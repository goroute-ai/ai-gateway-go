package drivers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/guardrails"
)

// GuardrailsAIDriver evaluates text against a Guardrails AI server (/guards/{guard_name}/validate),
// supporting validation_passed and validated_output re-asked/fixed output modifications.
type GuardrailsAIDriver struct {
	name           string
	id             string
	guardName      string
	endpoint       string
	apiKey         string
	numReasks      int
	explicitAction domain.GuardrailAction
	hasExplicitAct bool
	httpClient     *http.Client
}

// NewGuardrailsAIDriver constructs a Guardrails AI server driver.
func NewGuardrailsAIDriver(cfg guardrails.DriverConfig, httpClient *http.Client) (guardrails.Driver, error) {
	baseURL := configString(cfg, "base_url", "api_base", "endpoint")
	if baseURL == "" {
		return nil, fmt.Errorf("guardrails_ai driver requires base_url or endpoint")
	}
	guardName := configString(cfg, "guard_name", "guard")
	if guardName == "" {
		return nil, fmt.Errorf("guardrails_ai driver requires guard_name")
	}

	endpoint := fmt.Sprintf("%s/guards/%s/validate",
		strings.TrimRight(baseURL, "/"),
		url.PathEscape(guardName),
	)

	explicitAct := normalizeActionString(string(cfg.EffectiveAction))
	if explicitAct == "" {
		explicitAct = normalizeActionString(configString(cfg, "action", "default_action"))
	}

	return &GuardrailsAIDriver{
		name:           guardrailName(cfg, ProviderGuardrailsAI),
		id:             guardrailID(cfg),
		guardName:      guardName,
		endpoint:       endpoint,
		apiKey:         resolveSecretOrConfig(cfg, "api_key", "guardrails_api_key", "token"),
		numReasks:      configInt(cfg, 0, "num_reasks", "numReasks"),
		explicitAction: explicitAct,
		hasExplicitAct: explicitAct != "",
		httpClient:     resolveHTTPClient(httpClient),
	}, nil
}

func (d *GuardrailsAIDriver) Name() string {
	return d.name
}

func (d *GuardrailsAIDriver) SupportedHooks() []domain.GuardrailHook {
	return defaultTextHooks()
}

type guardrailsAIValidateRequest struct {
	LLMOutput string         `json:"llmOutput"`
	NumReasks int            `json:"numReasks,omitempty"`
	Metadata  map[string]any `json:"metadata,omitempty"`
}

type guardrailsAIValidateResponse struct {
	CallID              string `json:"callId"`
	RawLLMOutput        string `json:"rawLlmOutput"`
	RawLLMOutputSnake   string `json:"raw_llm_output"`
	ValidatedOutput     string `json:"validatedOutput"`
	ValidatedOutputSnk  string `json:"validated_output"`
	ValidationPassed    *bool  `json:"validationPassed"`
	ValidationPassedSnk *bool  `json:"validation_passed"`
	Error               string `json:"error"`
}

func (r guardrailsAIValidateResponse) passed() bool {
	if r.ValidationPassed != nil {
		return *r.ValidationPassed
	}
	if r.ValidationPassedSnk != nil {
		return *r.ValidationPassedSnk
	}
	return r.Error == ""
}

func (r guardrailsAIValidateResponse) outputText() string {
	if r.ValidatedOutput != "" {
		return r.ValidatedOutput
	}
	return r.ValidatedOutputSnk
}

func (d *GuardrailsAIDriver) Evaluate(ctx context.Context, input *domain.GuardrailEvalInput) (*domain.GuardrailEvalResult, error) {
	texts := extractTexts(input)
	if !hasNonEmptyText(texts) {
		return &domain.GuardrailEvalResult{
			Decision:          domain.GuardrailDecisionAllow,
			AppliedGuardrails: []string{d.name},
		}, nil
	}

	headers := map[string]string{}
	if d.apiKey != "" {
		headers["Authorization"] = "Bearer " + d.apiKey
		headers["x-api-key"] = d.apiKey
	}

	modified := make([]string, len(texts))
	copy(modified, texts)
	var violations []domain.GuardrailViolation
	hasFixedOutput := false

	for i, txt := range texts {
		if strings.TrimSpace(txt) == "" {
			continue
		}
		var meta map[string]any
		if input != nil && len(input.Metadata) > 0 {
			meta = input.Metadata
		}
		reqPayload := guardrailsAIValidateRequest{
			LLMOutput: txt,
			NumReasks: d.numReasks,
			Metadata:  meta,
		}

		status, body, err := doJSONRequest(ctx, d.httpClient, http.MethodPost, d.endpoint, headers, reqPayload, domain.ProviderType("guardrails_ai"))
		if err != nil {
			return nil, err
		}
		if status < 200 || status >= 300 {
			return nil, fmt.Errorf("guardrails_ai returned status %d: %s", status, strings.TrimSpace(string(body)))
		}

		var parsed guardrailsAIValidateResponse
		if err := json.Unmarshal(body, &parsed); err != nil {
			return nil, fmt.Errorf("decode guardrails_ai response: %w", err)
		}

		validated := parsed.outputText()
		if parsed.passed() {
			// Even if validation passed after auto-reask/fix, propagate changed validated_output if modified.
			if validated != "" && validated != txt {
				modified[i] = validated
				hasFixedOutput = true
			}
			continue
		}

		msg := parsed.Error
		if msg == "" {
			msg = fmt.Sprintf("Guardrails AI guard %q validation failed", d.guardName)
		}
		violations = append(violations, domain.GuardrailViolation{
			GuardrailName: d.name,
			GuardrailID:   d.id,
			Provider:      ProviderGuardrailsAI,
			Category:      "guard_validation",
			Rule:          d.guardName,
			Message:       msg,
		})

		if validated != "" && validated != txt {
			modified[i] = validated
			hasFixedOutput = true
		}
	}

	if len(violations) == 0 && !hasFixedOutput {
		return &domain.GuardrailEvalResult{
			Decision:          domain.GuardrailDecisionAllow,
			AppliedGuardrails: []string{d.name},
			UsageUnits:        int64(len(texts)),
		}, nil
	}

	decision := domain.GuardrailDecisionBlock
	switch {
	case d.hasExplicitAct && d.explicitAction == domain.GuardrailActionAudit:
		decision = domain.GuardrailDecisionFlag
	case hasFixedOutput && (!d.hasExplicitAct || d.explicitAction == domain.GuardrailActionRedact):
		decision = domain.GuardrailDecisionModify
	case d.hasExplicitAct && d.explicitAction == domain.GuardrailActionBlock:
		decision = domain.GuardrailDecisionBlock
	}

	for i := range violations {
		violations[i].Decision = decision
	}

	errMsg := ""
	if len(violations) > 0 {
		errMsg = violations[0].Message
	}

	res := &domain.GuardrailEvalResult{
		Decision:          decision,
		Violations:        violations,
		AppliedGuardrails: []string{d.name},
		UsageUnits:        int64(len(texts)),
		ErrorMessage:      errMsg,
	}
	if decision == domain.GuardrailDecisionModify {
		res.ModifiedTexts = modified
	}
	return res, nil
}
