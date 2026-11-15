package drivers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/goroute-ai/ai-gateway-go/internal/adapter/vertex"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/guardrails"
)

// ModelArmorDriver evaluates prompts and model responses using Google Cloud Model Armor
// (:sanitizeUserPrompt / :sanitizeModelResponse) with Vertex/GCP service account or OAuth2 bearer auth.
type ModelArmorDriver struct {
	name           string
	id             string
	projectID      string
	location       string
	templateID     string
	baseURL        string
	tokenSource    *vertex.TokenSource
	explicitAction domain.GuardrailAction
	hasExplicitAct bool
	httpClient     *http.Client
}

// NewModelArmorDriver constructs a GCP Model Armor guardrail driver reusing internal/adapter/vertex auth.
func NewModelArmorDriver(cfg guardrails.DriverConfig, httpClient *http.Client) (guardrails.Driver, error) {
	client := resolveHTTPClient(httpClient)

	rawCred := resolveSecretOrConfig(cfg, "credentials", "service_account_json", "gcp_credentials", "bearer_token", "access_token", "api_key", "token")
	if rawCred == "" {
		return nil, fmt.Errorf("model_armor driver requires credentials or bearer_token")
	}

	ts, err := vertex.NewTokenSource(client, rawCred)
	if err != nil {
		return nil, fmt.Errorf("model_armor auth initialization failed: %w", err)
	}

	projectID := configString(cfg, "project_id", "gcp_project_id")
	if projectID == "" && strings.HasPrefix(strings.TrimSpace(rawCred), "{") {
		var sa vertex.ServiceAccountKey
		if json.Unmarshal([]byte(rawCred), &sa) == nil && sa.ProjectID != "" {
			projectID = sa.ProjectID
		}
	}
	if projectID == "" {
		return nil, fmt.Errorf("model_armor driver requires project_id")
	}

	templateID := configString(cfg, "template_id", "template")
	if templateID == "" {
		return nil, fmt.Errorf("model_armor driver requires template_id")
	}

	location := configString(cfg, "location", "region")
	if location == "" {
		location = "us-central1"
	}

	baseURL := configString(cfg, "base_url", "endpoint")
	if baseURL == "" {
		if strings.EqualFold(location, "global") {
			baseURL = "https://modelarmor.googleapis.com/v1"
		} else {
			baseURL = fmt.Sprintf("https://modelarmor.%s.rep.googleapis.com/v1", location)
		}
	}
	baseURL = strings.TrimRight(baseURL, "/")

	explicitAct := normalizeActionString(string(cfg.EffectiveAction))
	if explicitAct == "" {
		explicitAct = normalizeActionString(configString(cfg, "action", "default_action"))
	}

	return &ModelArmorDriver{
		name:           guardrailName(cfg, ProviderModelArmor),
		id:             guardrailID(cfg),
		projectID:      projectID,
		location:       location,
		templateID:     templateID,
		baseURL:        baseURL,
		tokenSource:    ts,
		explicitAction: explicitAct,
		hasExplicitAct: explicitAct != "",
		httpClient:     client,
	}, nil
}

func (d *ModelArmorDriver) Name() string {
	return d.name
}

func (d *ModelArmorDriver) SupportedHooks() []domain.GuardrailHook {
	return defaultTextHooks()
}

func (d *ModelArmorDriver) endpointForDirection(isOutput bool) string {
	method := "sanitizeUserPrompt"
	if isOutput {
		method = "sanitizeModelResponse"
	}
	return fmt.Sprintf("%s/projects/%s/locations/%s/templates/%s:%s",
		d.baseURL,
		url.PathEscape(d.projectID),
		url.PathEscape(d.location),
		url.PathEscape(d.templateID),
		method,
	)
}

type modelArmorPromptRequest struct {
	UserPromptData *modelArmorDataItem `json:"userPromptData,omitempty"`
}

type modelArmorResponseRequest struct {
	ModelResponseData *modelArmorDataItem `json:"modelResponseData,omitempty"`
}

type modelArmorDataItem struct {
	Text string `json:"text"`
}

type modelArmorAPIResponse struct {
	SanitizationResult struct {
		FilterMatchState string                     `json:"filterMatchState"`
		InvocationResult string                     `json:"invocationResult"`
		FilterResults    map[string]json.RawMessage `json:"filterResults"`
	} `json:"sanitizationResult"`
}

func (d *ModelArmorDriver) Evaluate(ctx context.Context, input *domain.GuardrailEvalInput) (*domain.GuardrailEvalResult, error) {
	texts := extractTexts(input)
	text := joinedNonEmptyText(texts)
	if strings.TrimSpace(text) == "" {
		return &domain.GuardrailEvalResult{
			Decision:          domain.GuardrailDecisionAllow,
			AppliedGuardrails: []string{d.name},
		}, nil
	}

	token, err := d.tokenSource.GetToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("model_armor oauth2 token: %w", err)
	}

	isOutput := isOutputDirection(input)
	endpoint := d.endpointForDirection(isOutput)
	var reqPayload any
	if isOutput {
		reqPayload = modelArmorResponseRequest{ModelResponseData: &modelArmorDataItem{Text: text}}
	} else {
		reqPayload = modelArmorPromptRequest{UserPromptData: &modelArmorDataItem{Text: text}}
	}

	headers := map[string]string{
		"Authorization": "Bearer " + token,
	}

	status, body, err := doJSONRequest(ctx, d.httpClient, http.MethodPost, endpoint, headers, reqPayload, domain.ProviderVertex)
	if err != nil {
		return nil, err
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("model_armor returned status %d: %s", status, strings.TrimSpace(string(body)))
	}

	var parsed modelArmorAPIResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("decode model_armor response: %w", err)
	}

	if !strings.EqualFold(parsed.SanitizationResult.FilterMatchState, "MATCH_FOUND") {
		return &domain.GuardrailEvalResult{
			Decision:          domain.GuardrailDecisionAllow,
			AppliedGuardrails: []string{d.name},
			UsageUnits:        1,
		}, nil
	}

	violations, deidentifiedText := d.parseFilterResults(parsed.SanitizationResult.FilterResults)
	if len(violations) == 0 {
		violations = []domain.GuardrailViolation{{
			GuardrailName: d.name,
			GuardrailID:   d.id,
			Provider:      ProviderModelArmor,
			Category:      "model_armor",
			Rule:          "match_found",
			Message:       "GCP Model Armor matched a configured safety filter",
		}}
	}

	decision := domain.GuardrailDecisionBlock
	if d.hasExplicitAct && d.explicitAction == domain.GuardrailActionAudit {
		decision = domain.GuardrailDecisionFlag
	} else if deidentifiedText != "" && (!d.hasExplicitAct || d.explicitAction == domain.GuardrailActionRedact) {
		decision = domain.GuardrailDecisionModify
	}

	res := &domain.GuardrailEvalResult{
		Decision:          decision,
		Violations:        violations,
		AppliedGuardrails: []string{d.name},
		UsageUnits:        1,
		ErrorMessage:      violations[0].Message,
	}
	if decision == domain.GuardrailDecisionModify && deidentifiedText != "" {
		res.ModifiedTexts = []string{deidentifiedText}
	}
	for i := range res.Violations {
		res.Violations[i].Decision = decision
	}
	return res, nil
}

func (d *ModelArmorDriver) parseFilterResults(rawResults map[string]json.RawMessage) ([]domain.GuardrailViolation, string) {
	if len(rawResults) == 0 {
		return nil, ""
	}
	keys := make([]string, 0, len(rawResults))
	for k := range rawResults {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var violations []domain.GuardrailViolation
	var deidentifiedText string

	for _, k := range keys {
		raw := rawResults[k]
		var obj map[string]any
		if json.Unmarshal(raw, &obj) != nil {
			continue
		}
		if sdpText := extractModelArmorSDPText(obj); sdpText != "" {
			deidentifiedText = sdpText
		}
		if containsMatchFound(obj) {
			violations = append(violations, domain.GuardrailViolation{
				GuardrailName: d.name,
				GuardrailID:   d.id,
				Provider:      ProviderModelArmor,
				Category:      k,
				Rule:          k,
				Message:       fmt.Sprintf("GCP Model Armor filter %q matched", k),
			})
		}
	}
	return violations, deidentifiedText
}

func containsMatchFound(v any) bool {
	switch x := v.(type) {
	case map[string]any:
		if ms, ok := x["matchState"].(string); ok && strings.EqualFold(ms, "MATCH_FOUND") {
			return true
		}
		for _, child := range x {
			if containsMatchFound(child) {
				return true
			}
		}
	case []any:
		for _, item := range x {
			if containsMatchFound(item) {
				return true
			}
		}
	}
	return false
}

func extractModelArmorSDPText(obj map[string]any) string {
	sdpRaw, ok := obj["sdpFilterResult"].(map[string]any)
	if !ok {
		sdpRaw = obj
	}
	deid, ok := sdpRaw["deidentifyResult"].(map[string]any)
	if !ok {
		return ""
	}
	if ms, _ := deid["matchState"].(string); ms != "" && !strings.EqualFold(ms, "MATCH_FOUND") {
		return ""
	}
	data, ok := deid["data"].(map[string]any)
	if !ok {
		return ""
	}
	txt, _ := data["text"].(string)
	return txt
}
