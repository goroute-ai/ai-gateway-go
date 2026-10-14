package drivers

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"strings"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/guardrails"
)

const defaultLakeraV2BaseURL = "https://api.lakera.ai"

// LakeraV2Driver evaluates prompts and assistant responses using the Lakera Guard /v2/guard API.
type LakeraV2Driver struct {
	name       string
	id         string
	apiKey     string
	endpoint   string
	projectID  string
	payload    bool
	breakdown  bool
	metadata   map[string]any
	action     domain.GuardrailAction
	httpClient *http.Client
}

// NewLakeraV2Driver constructs a Lakera Guard v2 driver.
func NewLakeraV2Driver(cfg guardrails.DriverConfig, httpClient *http.Client) (guardrails.Driver, error) {
	apiKey := resolveSecretOrConfig(cfg, "api_key", "lakera_api_key", "token")
	if apiKey == "" {
		return nil, fmt.Errorf("lakera_v2 driver requires api_key")
	}

	baseURL := configString(cfg, "base_url", "api_base", "endpoint")
	if baseURL == "" {
		baseURL = defaultLakeraV2BaseURL
	}
	endpoint := resolveLakeraV2URL(baseURL)

	return &LakeraV2Driver{
		name:       guardrailName(cfg, ProviderLakeraV2),
		id:         guardrailID(cfg),
		apiKey:     apiKey,
		endpoint:   endpoint,
		projectID:  configString(cfg, "project_id"),
		payload:    configBool(cfg, true, "payload"),
		breakdown:  configBool(cfg, true, "breakdown"),
		metadata:   configAnyMap(cfg, "metadata"),
		action:     effectiveAction(cfg, domain.GuardrailActionBlock),
		httpClient: resolveHTTPClient(httpClient),
	}, nil
}

func resolveLakeraV2URL(baseURL string) string {
	trimmed := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if strings.HasSuffix(trimmed, "/v2/guard") {
		return trimmed
	}
	if strings.HasSuffix(trimmed, "/v2") {
		return trimmed + "/guard"
	}
	return trimmed + "/v2/guard"
}

func (d *LakeraV2Driver) Name() string {
	return d.name
}

func (d *LakeraV2Driver) SupportedHooks() []domain.GuardrailHook {
	return defaultTextHooks()
}

type lakeraV2Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type lakeraV2Request struct {
	Messages  []lakeraV2Message `json:"messages"`
	ProjectID string            `json:"project_id,omitempty"`
	Payload   bool              `json:"payload,omitempty"`
	Breakdown bool              `json:"breakdown,omitempty"`
	Metadata  map[string]any    `json:"metadata,omitempty"`
}

type lakeraV2Response struct {
	Flagged   bool                `json:"flagged"`
	Breakdown []lakeraV2Breakdown `json:"breakdown"`
	Metadata  map[string]any      `json:"metadata"`
}

type lakeraV2Breakdown struct {
	ProjectID    string `json:"project_id"`
	PolicyID     string `json:"policy_id"`
	DetectorID   string `json:"detector_id"`
	DetectorType string `json:"detector_type"`
	Detected     bool   `json:"detected"`
}

func (d *LakeraV2Driver) Evaluate(ctx context.Context, input *domain.GuardrailEvalInput) (*domain.GuardrailEvalResult, error) {
	messages := buildLakeraMessages(input)
	if len(messages) == 0 {
		return &domain.GuardrailEvalResult{
			Decision:          domain.GuardrailDecisionAllow,
			AppliedGuardrails: []string{d.name},
		}, nil
	}

	meta := d.buildMetadata(input)
	reqPayload := lakeraV2Request{
		Messages:  messages,
		ProjectID: d.projectID,
		Payload:   d.payload,
		Breakdown: d.breakdown,
		Metadata:  meta,
	}

	headers := map[string]string{
		"Authorization": "Bearer " + d.apiKey,
	}
	status, body, err := doJSONRequest(ctx, d.httpClient, http.MethodPost, d.endpoint, headers, reqPayload, domain.ProviderType("lakera_v2"))
	if err != nil {
		return nil, err
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("lakera_v2 returned status %d: %s", status, strings.TrimSpace(string(body)))
	}

	var parsed lakeraV2Response
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("decode lakera_v2 response: %w", err)
	}

	var violations []domain.GuardrailViolation
	for _, b := range parsed.Breakdown {
		if !b.Detected {
			continue
		}
		rule := b.DetectorType
		if rule == "" {
			rule = b.DetectorID
		}
		violations = append(violations, domain.GuardrailViolation{
			GuardrailName: d.name,
			GuardrailID:   d.id,
			Provider:      ProviderLakeraV2,
			Category:      b.DetectorType,
			Rule:          rule,
			Message:       fmt.Sprintf("Lakera v2 detector %q flagged content", rule),
			Details: map[string]any{
				"detector_id": b.DetectorID,
				"policy_id":   b.PolicyID,
				"project_id":  b.ProjectID,
			},
		})
	}

	if parsed.Flagged && len(violations) == 0 {
		violations = append(violations, domain.GuardrailViolation{
			GuardrailName: d.name,
			GuardrailID:   d.id,
			Provider:      ProviderLakeraV2,
			Category:      "lakera_guard",
			Rule:          "flagged",
			Message:       "Lakera v2 flagged content",
		})
	}

	if len(violations) == 0 {
		return &domain.GuardrailEvalResult{
			Decision:          domain.GuardrailDecisionAllow,
			AppliedGuardrails: []string{d.name},
			UsageUnits:        1,
		}, nil
	}

	decision := domain.GuardrailDecisionBlock
	if d.action == domain.GuardrailActionAudit {
		decision = domain.GuardrailDecisionFlag
	}
	for i := range violations {
		violations[i].Decision = decision
		violations[i].Action = d.action
	}

	return &domain.GuardrailEvalResult{
		Decision:          decision,
		Violations:        violations,
		AppliedGuardrails: []string{d.name},
		UsageUnits:        1,
		ErrorMessage:      violations[0].Message,
	}, nil
}

func buildLakeraMessages(input *domain.GuardrailEvalInput) []lakeraV2Message {
	if input == nil {
		return nil
	}
	if len(input.StructuredMessages) > 0 {
		out := make([]lakeraV2Message, 0, len(input.StructuredMessages))
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
			if strings.TrimSpace(txt) == "" {
				continue
			}
			role := strings.TrimSpace(m.Role)
			if role == "" {
				role = "user"
			}
			out = append(out, lakeraV2Message{Role: role, Content: txt})
		}
		if len(out) > 0 {
			return out
		}
	}

	role := "user"
	if isOutputDirection(input) {
		role = "assistant"
	}
	var out []lakeraV2Message
	for _, t := range extractTexts(input) {
		if strings.TrimSpace(t) != "" {
			out = append(out, lakeraV2Message{Role: role, Content: t})
		}
	}
	return out
}

func (d *LakeraV2Driver) buildMetadata(input *domain.GuardrailEvalInput) map[string]any {
	meta := make(map[string]any)
	maps.Copy(meta, d.metadata)
	if input != nil {
		maps.Copy(meta, input.Metadata)
		if input.RequestID != "" {
			meta["request_id"] = input.RequestID
		}
		if input.OrgID != "" {
			meta["org_id"] = input.OrgID
		}
		if input.EndUserID != "" {
			meta["user_id"] = input.EndUserID
		}
		if input.Model != "" {
			meta["model"] = input.Model
		}
	}
	if len(meta) == 0 {
		return nil
	}
	return meta
}
