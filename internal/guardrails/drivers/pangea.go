package drivers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/guardrails"
)

const defaultPangeaDomain = "aws.us.pangea.cloud"

// PangeaDriver evaluates prompts and responses using the Pangea AI Guard /v1/guard API.
type PangeaDriver struct {
	name           string
	id             string
	apiKey         string
	endpoint       string
	recipe         string
	debug          bool
	explicitAction domain.GuardrailAction
	hasExplicitAct bool
	httpClient     *http.Client
}

// NewPangeaDriver constructs a Pangea AI Guard driver.
func NewPangeaDriver(cfg guardrails.DriverConfig, httpClient *http.Client) (guardrails.Driver, error) {
	apiKey := resolveSecretOrConfig(cfg, "api_key", "pangea_token", "pangea_api_key", "token")
	if apiKey == "" {
		return nil, fmt.Errorf("pangea driver requires api_key or pangea_token")
	}

	baseURL := configString(cfg, "base_url", "api_base", "endpoint")
	if baseURL == "" {
		pangeaDomain := configString(cfg, "domain", "pangea_domain")
		if pangeaDomain == "" {
			pangeaDomain = defaultPangeaDomain
		}
		baseURL = fmt.Sprintf("https://ai-guard.%s", strings.TrimPrefix(pangeaDomain, "https://"))
	}
	endpoint := resolvePangeaURL(baseURL)

	explicitAct := normalizeActionString(string(cfg.EffectiveAction))
	if explicitAct == "" {
		explicitAct = normalizeActionString(configString(cfg, "action", "default_action"))
	}

	return &PangeaDriver{
		name:           guardrailName(cfg, ProviderPangea),
		id:             guardrailID(cfg),
		apiKey:         apiKey,
		endpoint:       endpoint,
		recipe:         configString(cfg, "recipe"),
		debug:          configBool(cfg, false, "debug"),
		explicitAction: explicitAct,
		hasExplicitAct: explicitAct != "",
		httpClient:     resolveHTTPClient(httpClient),
	}, nil
}

func resolvePangeaURL(baseURL string) string {
	trimmed := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if strings.HasSuffix(trimmed, "/v1/guard") {
		return trimmed
	}
	if strings.HasSuffix(trimmed, "/v1") {
		return trimmed + "/guard"
	}
	return trimmed + "/v1/guard"
}

func (d *PangeaDriver) Name() string {
	return d.name
}

func (d *PangeaDriver) SupportedHooks() []domain.GuardrailHook {
	return defaultTextHooks()
}

type pangeaMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type pangeaGuardRequest struct {
	Text      string          `json:"text,omitempty"`
	Messages  []pangeaMessage `json:"messages,omitempty"`
	Recipe    string          `json:"recipe,omitempty"`
	Debug     bool            `json:"debug,omitempty"`
	LogFields map[string]any  `json:"log_fields,omitempty"`
}

type pangeaGuardResponse struct {
	Status  string `json:"status"`
	Summary string `json:"summary"`
	Result  *struct {
		Blocked        bool                       `json:"blocked"`
		Transformed    bool                       `json:"transformed"`
		PromptText     string                     `json:"prompt_text"`
		PromptMessages []pangeaMessage            `json:"prompt_messages"`
		Detectors      map[string]json.RawMessage `json:"detectors"`
	} `json:"result"`
}

func (d *PangeaDriver) Evaluate(ctx context.Context, input *domain.GuardrailEvalInput) (*domain.GuardrailEvalResult, error) {
	reqPayload := pangeaGuardRequest{
		Recipe: d.recipe,
		Debug:  d.debug,
	}

	if input != nil && len(input.StructuredMessages) > 0 {
		for _, m := range input.StructuredMessages {
			txt := m.Content
			if txt == "" {
				var sb strings.Builder
				for _, p := range m.Parts {
					if p.Type == "text" {
						sb.WriteString(p.Text)
					}
				}
				txt = sb.String()
			}
			if txt != "" {
				role := m.Role
				if role == "" {
					role = "user"
				}
				reqPayload.Messages = append(reqPayload.Messages, pangeaMessage{
					Role:    role,
					Content: txt,
				})
			}
		}
	}
	if len(reqPayload.Messages) == 0 {
		reqPayload.Text = joinedNonEmptyText(extractTexts(input))
	}
	if strings.TrimSpace(reqPayload.Text) == "" && len(reqPayload.Messages) == 0 {
		return &domain.GuardrailEvalResult{
			Decision:          domain.GuardrailDecisionAllow,
			AppliedGuardrails: []string{d.name},
		}, nil
	}

	if input != nil && (input.RequestID != "" || input.OrgID != "" || input.Model != "") {
		reqPayload.LogFields = map[string]any{
			"source": "goroute",
		}
		if input.RequestID != "" {
			reqPayload.LogFields["request_id"] = input.RequestID
		}
		if input.OrgID != "" {
			reqPayload.LogFields["org_id"] = input.OrgID
		}
		if input.Model != "" {
			reqPayload.LogFields["model"] = input.Model
		}
	}

	headers := map[string]string{
		"Authorization": "Bearer " + d.apiKey,
	}
	status, body, err := doJSONRequest(ctx, d.httpClient, http.MethodPost, d.endpoint, headers, reqPayload, domain.ProviderType("pangea"))
	if err != nil {
		return nil, err
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("pangea returned status %d: %s", status, strings.TrimSpace(string(body)))
	}

	var parsed pangeaGuardResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("decode pangea response: %w", err)
	}
	if parsed.Result == nil {
		return &domain.GuardrailEvalResult{
			Decision:          domain.GuardrailDecisionAllow,
			AppliedGuardrails: []string{d.name},
			UsageUnits:        1,
		}, nil
	}

	violations := d.collectDetectorViolations(parsed.Result.Detectors)
	if !parsed.Result.Blocked && !parsed.Result.Transformed && len(violations) == 0 {
		return &domain.GuardrailEvalResult{
			Decision:          domain.GuardrailDecisionAllow,
			AppliedGuardrails: []string{d.name},
			UsageUnits:        1,
		}, nil
	}

	if len(violations) == 0 {
		msg := parsed.Summary
		if msg == "" {
			msg = "Pangea AI Guard intervened on content"
		}
		violations = []domain.GuardrailViolation{{
			GuardrailName: d.name,
			GuardrailID:   d.id,
			Provider:      ProviderPangea,
			Category:      "ai_guard",
			Rule:          "guard",
			Message:       msg,
		}}
	}

	decision := domain.GuardrailDecisionAllow
	switch {
	case d.hasExplicitAct && d.explicitAction == domain.GuardrailActionAudit:
		decision = domain.GuardrailDecisionFlag
	case parsed.Result.Blocked:
		decision = domain.GuardrailDecisionBlock
	case parsed.Result.Transformed && (!d.hasExplicitAct || d.explicitAction == domain.GuardrailActionRedact):
		decision = domain.GuardrailDecisionModify
	case d.hasExplicitAct && d.explicitAction == domain.GuardrailActionBlock:
		decision = domain.GuardrailDecisionBlock
	default:
		decision = domain.GuardrailDecisionFlag
	}

	for i := range violations {
		violations[i].Decision = decision
	}

	res := &domain.GuardrailEvalResult{
		Decision:          decision,
		Violations:        violations,
		AppliedGuardrails: []string{d.name},
		UsageUnits:        1,
		ErrorMessage:      violations[0].Message,
	}

	if decision == domain.GuardrailDecisionModify {
		if len(parsed.Result.PromptMessages) > 0 {
			modTexts := make([]string, len(parsed.Result.PromptMessages))
			for i, pm := range parsed.Result.PromptMessages {
				modTexts[i] = pm.Content
			}
			res.ModifiedTexts = modTexts
		} else if parsed.Result.PromptText != "" {
			res.ModifiedTexts = []string{parsed.Result.PromptText}
		}
	}
	return res, nil
}

func (d *PangeaDriver) collectDetectorViolations(detectors map[string]json.RawMessage) []domain.GuardrailViolation {
	if len(detectors) == 0 {
		return nil
	}
	keys := make([]string, 0, len(detectors))
	for k := range detectors {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var violations []domain.GuardrailViolation
	for _, k := range keys {
		var det struct {
			Detected bool `json:"detected"`
		}
		if json.Unmarshal(detectors[k], &det) == nil && det.Detected {
			violations = append(violations, domain.GuardrailViolation{
				GuardrailName: d.name,
				GuardrailID:   d.id,
				Provider:      ProviderPangea,
				Category:      k,
				Rule:          k,
				Message:       fmt.Sprintf("Pangea detector %q triggered", k),
			})
		}
	}
	return violations
}
