package drivers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/guardrails"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
)

const (
	// DriverNameGenericHTTP identifies the rich webhook guardrail driver.
	DriverNameGenericHTTP = "generic_http"

	maxGenericHTTPResponseBytes = 1 << 20
)

var defaultSafeRequestHeaders = map[string]struct{}{
	"content-type":       {},
	"user-agent":         {},
	"x-request-id":       {},
	"accept":             {},
	"accept-language":    {},
	"x-goroute-call-id":  {},
	"x-goroute-trace-id": {},
	"x-correlation-id":   {},
	"traceparent":        {},
}

var sensitiveRequestHeaders = map[string]struct{}{
	"authorization":       {},
	"x-api-key":           {},
	"api-key":             {},
	"cookie":              {},
	"set-cookie":          {},
	"proxy-authorization": {},
	"x-auth-token":        {},
	"x-admin-key":         {},
	"x-gateway-admin-key": {},
}

// GenericHTTPDriver evaluates guardrail checks against an external HTTP webhook
// endpoint using an SSRF-enforced HTTP client and structured request/response schemas.
type GenericHTTPDriver struct {
	guardrailName     string
	guardrailID       string
	url               string
	method            string
	timeout           time.Duration
	hooks             []domain.GuardrailHook
	headers           map[string]string
	allowedReqHeaders map[string]struct{}
	redactAuthHeaders bool
	client            *http.Client
}

// GenericHTTPRequest is the structured JSON payload dispatched to generic_http webhooks.
type GenericHTTPRequest struct {
	InputType          string                    `json:"input_type"`
	Direction          string                    `json:"direction,omitempty"`
	Hook               string                    `json:"hook,omitempty"`
	CallID             string                    `json:"call_id,omitempty"`
	RequestID          string                    `json:"request_id,omitempty"`
	TraceID            string                    `json:"trace_id,omitempty"`
	OrgID              string                    `json:"org_id,omitempty"`
	TeamID             string                    `json:"team_id,omitempty"`
	VirtualKeyID       string                    `json:"virtual_key_id,omitempty"`
	EndUserID          string                    `json:"end_user_id,omitempty"`
	Model              string                    `json:"model,omitempty"`
	Tags               []string                  `json:"tags,omitempty"`
	Content            string                    `json:"content,omitempty"`
	Texts              []string                  `json:"texts,omitempty"`
	StructuredMessages []domain.CanonicalMessage `json:"structured_messages,omitempty"`
	Images             []domain.ImageURL         `json:"images,omitempty"`
	RequestHeaders     map[string]string         `json:"request_headers,omitempty"`
	Metadata           map[string]any            `json:"metadata,omitempty"`
}

type genericHTTPWireResponse struct {
	Decision         string                    `json:"decision"`
	Action           string                    `json:"action"`
	Blocked          *bool                     `json:"blocked"`
	BlockedReason    string                    `json:"blocked_reason"`
	SanitizedText    *string                   `json:"sanitized_text"`
	ModifiedContent  *string                   `json:"modified_content"`
	ModifiedTexts    []string                  `json:"modified_texts"`
	Texts            []string                  `json:"texts"`
	ModifiedMessages []domain.CanonicalMessage `json:"modified_messages"`
	Violations       []json.RawMessage         `json:"violations"`
	Reason           string                    `json:"reason"`
	Message          string                    `json:"message"`
	Error            string                    `json:"error"`
}

// NewGenericHTTPDriver constructs a GenericHTTPDriver from cfg. When httpClient is nil,
// a strict SSRF-protected client is constructed via network.NewHTTPClient.
func NewGenericHTTPDriver(cfg guardrails.DriverConfig, httpClient *http.Client) (*GenericHTTPDriver, error) {
	cfgMap := cfg.EffectiveConfig
	if cfgMap == nil && cfg.Definition != nil {
		cfgMap = cfg.Definition.Config
	}

	rawURL := firstNonEmptyString(
		stringFromMap(cfgMap, "url"),
		stringFromMap(cfgMap, "api_base"),
		stringFromMap(cfgMap, "endpoint"),
		stringFromMap(cfg.DecryptedSecrets, "url"),
	)
	if rawURL == "" {
		return nil, fmt.Errorf("generic_http driver requires a non-empty url")
	}
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("generic_http invalid url %q: %w", rawURL, err)
	}
	scheme := strings.ToLower(parsedURL.Scheme)
	if (scheme != "http" && scheme != "https") || parsedURL.Host == "" {
		return nil, fmt.Errorf("generic_http url %q must use http or https with a host", rawURL)
	}

	method := strings.ToUpper(stringFromMap(cfgMap, "method"))
	if method == "" {
		method = http.MethodPost
	}

	if httpClient == nil {
		httpClient = network.NewHTTPClient(nil)
	}

	var guardrailName, guardrailID string
	var hooks []domain.GuardrailHook
	var timeout time.Duration
	if cfg.Definition != nil {
		guardrailName = cfg.Definition.Name
		guardrailID = cfg.Definition.ID
		if len(cfg.Definition.EventHooks) > 0 {
			hooks = slices.Clone(cfg.Definition.EventHooks)
		}
		if cfg.Definition.TimeoutMs > 0 {
			timeout = time.Duration(cfg.Definition.TimeoutMs) * time.Millisecond
		}
	}
	if guardrailName == "" {
		guardrailName = DriverNameGenericHTTP
	}
	if len(hooks) == 0 {
		hooks = hooksFromConfig(cfgMap)
	}
	if timeout <= 0 {
		if ms := intFromMap(cfgMap, "timeout_ms"); ms > 0 {
			timeout = time.Duration(ms) * time.Millisecond
		}
	}

	headers := resolveConfiguredHeaders(cfgMap, cfg.DecryptedSecrets)
	allowedHeaders := buildAllowedRequestHeaders(cfgMap)
	redactAuth := boolFromMap(cfgMap, "redact_auth_headers") || boolFromMap(cfgMap, "include_auth_presence")

	return &GenericHTTPDriver{
		guardrailName:     guardrailName,
		guardrailID:       guardrailID,
		url:               rawURL,
		method:            method,
		timeout:           timeout,
		hooks:             hooks,
		headers:           headers,
		allowedReqHeaders: allowedHeaders,
		redactAuthHeaders: redactAuth,
		client:            httpClient,
	}, nil
}

// Name returns the provider driver identifier ("generic_http").
func (d *GenericHTTPDriver) Name() string {
	return DriverNameGenericHTTP
}

// SupportedHooks returns the configured lifecycle hooks for this driver, or nil if unrestricted.
func (d *GenericHTTPDriver) SupportedHooks() []domain.GuardrailHook {
	if d == nil || len(d.hooks) == 0 {
		return nil
	}
	return slices.Clone(d.hooks)
}

// Evaluate dispatches the structured guardrail payload to the configured webhook and translates
// its response (allow, block, flag, modify, or legacy schema) into a GuardrailEvalResult.
func (d *GenericHTTPDriver) Evaluate(ctx context.Context, input *domain.GuardrailEvalInput) (*domain.GuardrailEvalResult, error) {
	if d == nil {
		return nil, fmt.Errorf("generic_http driver is nil")
	}
	if d.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, d.timeout)
		defer cancel()
	}

	payload := d.buildPayload(input)
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("generic_http %q marshal payload: %w", d.guardrailName, err)
	}

	req, err := http.NewRequestWithContext(ctx, d.method, d.url, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("generic_http %q build request: %w", d.guardrailName, err)
	}
	req.Header.Set("Content-Type", "application/json")
	if input != nil {
		if input.RequestID != "" {
			req.Header.Set("X-GoRoute-Call-ID", input.RequestID)
		}
		if input.TraceID != "" {
			req.Header.Set("X-GoRoute-Trace-ID", input.TraceID)
		}
	}
	for k, v := range d.headers {
		req.Header.Set(k, v)
	}

	resp, err := d.client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("generic_http %q request failed: %w", d.guardrailName, err)
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(io.LimitReader(resp.Body, maxGenericHTTPResponseBytes))
	if err != nil {
		return nil, fmt.Errorf("generic_http %q read response: %w", d.guardrailName, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("generic_http %q returned HTTP %d", d.guardrailName, resp.StatusCode)
	}

	return d.parseResponse(respBytes)
}

func (d *GenericHTTPDriver) buildPayload(input *domain.GuardrailEvalInput) GenericHTTPRequest {
	if input == nil {
		return GenericHTTPRequest{InputType: "request"}
	}

	inputType := "request"
	if strings.EqualFold(input.Direction, domain.GuardrailDirectionOutput) ||
		input.Hook == domain.GuardrailHookPostCall {
		inputType = "response"
	}

	content := ""
	if len(input.Texts) > 0 {
		content = strings.Join(input.Texts, "\n")
	}

	return GenericHTTPRequest{
		InputType:          inputType,
		Direction:          input.Direction,
		Hook:               string(input.Hook),
		CallID:             input.RequestID,
		RequestID:          input.RequestID,
		TraceID:            input.TraceID,
		OrgID:              input.OrgID,
		TeamID:             input.TeamID,
		VirtualKeyID:       input.VirtualKeyID,
		EndUserID:          input.EndUserID,
		Model:              input.Model,
		Tags:               slices.Clone(input.Tags),
		Content:            content,
		Texts:              slices.Clone(input.Texts),
		StructuredMessages: input.StructuredMessages,
		Images:             input.Images,
		RequestHeaders:     d.sanitizeIncomingHeaders(input.RequestHeaders),
		Metadata:           input.Metadata,
	}
}

func (d *GenericHTTPDriver) sanitizeIncomingHeaders(headers map[string]string) map[string]string {
	if len(headers) == 0 {
		return nil
	}
	out := make(map[string]string)
	for k, v := range headers {
		lk := strings.ToLower(strings.TrimSpace(k))
		if lk == "" || v == "" {
			continue
		}
		if _, sensitive := sensitiveRequestHeaders[lk]; sensitive {
			if d.redactAuthHeaders {
				out[lk] = "[present]"
			}
			continue
		}
		if _, allowed := d.allowedReqHeaders[lk]; allowed {
			out[lk] = v
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func (d *GenericHTTPDriver) parseResponse(respBytes []byte) (*domain.GuardrailEvalResult, error) {
	trimmed := bytes.TrimSpace(respBytes)
	if len(trimmed) == 0 {
		return &domain.GuardrailEvalResult{
			Decision:          domain.GuardrailDecisionAllow,
			AppliedGuardrails: []string{d.guardrailName},
		}, nil
	}

	var wire genericHTTPWireResponse
	if err := json.Unmarshal(trimmed, &wire); err != nil {
		return nil, fmt.Errorf("generic_http %q decode response: %w", d.guardrailName, err)
	}

	decision, err := d.resolveDecision(&wire)
	if err != nil {
		return nil, err
	}

	res := &domain.GuardrailEvalResult{
		Decision:          decision,
		AppliedGuardrails: []string{d.guardrailName},
	}

	if decision == domain.GuardrailDecisionModify {
		switch {
		case len(wire.ModifiedTexts) > 0:
			res.ModifiedTexts = wire.ModifiedTexts
		case len(wire.Texts) > 0:
			res.ModifiedTexts = wire.Texts
		case wire.ModifiedContent != nil:
			res.ModifiedTexts = []string{*wire.ModifiedContent}
		case wire.SanitizedText != nil:
			res.ModifiedTexts = []string{*wire.SanitizedText}
		}

		res.ModifiedMessages = wire.ModifiedMessages
	}

	res.Violations = d.parseViolations(wire.Violations, decision)

	reason := firstNonEmptyString(wire.BlockedReason, wire.Reason, wire.Message, wire.Error)
	if reason != "" {
		res.ErrorMessage = reason
		if (decision == domain.GuardrailDecisionBlock || decision == domain.GuardrailDecisionFlag) && len(res.Violations) == 0 {
			res.Violations = append(res.Violations, domain.GuardrailViolation{
				GuardrailName: d.guardrailName,
				GuardrailID:   d.guardrailID,
				Provider:      DriverNameGenericHTTP,
				Message:       reason,
				Decision:      decision,
			})
		}
	}

	return res, nil
}

func (d *GenericHTTPDriver) resolveDecision(wire *genericHTTPWireResponse) (domain.GuardrailDecision, error) {
	if wire.Blocked != nil && *wire.Blocked {
		return domain.GuardrailDecisionBlock, nil
	}
	hasModifications := wire.SanitizedText != nil ||
		wire.ModifiedContent != nil ||
		len(wire.ModifiedTexts) > 0 ||
		len(wire.Texts) > 0 ||
		len(wire.ModifiedMessages) > 0
	rawDecision := firstNonEmptyString(wire.Decision, wire.Action)
	if rawDecision != "" {
		switch strings.ToLower(strings.TrimSpace(rawDecision)) {
		case "allow", "pass", "ok", "none":
			return domain.GuardrailDecisionAllow, nil
		case "block", "blocked", "deny", "reject":
			return domain.GuardrailDecisionBlock, nil
		case "flag", "audit", "alert", "warn":
			return domain.GuardrailDecisionFlag, nil
		case "modify", "redact", "mask", "sanitize":
			return domain.GuardrailDecisionModify, nil
		case "guardrail_intervened":
			if hasModifications {
				return domain.GuardrailDecisionModify, nil
			}
			return domain.GuardrailDecisionBlock, nil
		default:
			return "", fmt.Errorf("generic_http %q returned unsupported decision %q", d.guardrailName, rawDecision)
		}
	}

	if wire.SanitizedText != nil ||
		wire.ModifiedContent != nil ||
		len(wire.ModifiedTexts) > 0 ||
		len(wire.ModifiedMessages) > 0 {
		return domain.GuardrailDecisionModify, nil
	}
	return domain.GuardrailDecisionAllow, nil
}

func (d *GenericHTTPDriver) parseViolations(raw []json.RawMessage, decision domain.GuardrailDecision) []domain.GuardrailViolation {
	if len(raw) == 0 {
		return nil
	}
	out := make([]domain.GuardrailViolation, 0, len(raw))
	for _, item := range raw {
		trimmed := bytes.TrimSpace(item)
		if len(trimmed) == 0 || bytes.Equal(trimmed, []byte("null")) {
			continue
		}
		if trimmed[0] == '"' {
			var label string
			if err := json.Unmarshal(trimmed, &label); err == nil && label != "" {
				out = append(out, domain.GuardrailViolation{
					GuardrailName: d.guardrailName,
					GuardrailID:   d.guardrailID,
					Provider:      DriverNameGenericHTTP,
					Rule:          label,
					Message:       label,
					Decision:      decision,
				})
			}
			continue
		}
		if trimmed[0] == '{' {
			var v domain.GuardrailViolation
			if err := json.Unmarshal(trimmed, &v); err == nil {
				if v.GuardrailName == "" {
					v.GuardrailName = d.guardrailName
				}
				if v.GuardrailID == "" {
					v.GuardrailID = d.guardrailID
				}
				if v.Provider == "" {
					v.Provider = DriverNameGenericHTTP
				}
				if v.Decision == "" {
					v.Decision = decision
				}
				if v.Message == "" {
					v.Message = firstNonEmptyString(v.Rule, v.Category)
				}
				out = append(out, v)
			}
		}
	}
	return out
}

func resolveConfiguredHeaders(cfgMap, secrets map[string]any) map[string]string {
	out := make(map[string]string)
	copyHeaderMap(out, cfgMap["headers"])
	copyHeaderMap(out, secrets["headers"])

	hasAuth := false
	for k := range out {
		if strings.EqualFold(k, "authorization") {
			hasAuth = true
			break
		}
	}
	if !hasAuth {
		token := firstNonEmptyString(
			stringFromMap(secrets, "bearer_token"),
			stringFromMap(secrets, "api_key"),
			stringFromMap(secrets, "token"),
			stringFromMap(secrets, "secret"),
			stringFromMap(cfgMap, "bearer_token"),
			stringFromMap(cfgMap, "api_key"),
			stringFromMap(cfgMap, "token"),
		)
		if token != "" {
			resolved := config.ResolveEnvValue(token)
			if resolved != "" {
				if strings.HasPrefix(strings.ToLower(resolved), "bearer ") {
					out["Authorization"] = resolved
				} else {
					out["Authorization"] = "Bearer " + resolved
				}
			}
		}
	}
	return out
}

func copyHeaderMap(dst map[string]string, raw any) {
	switch h := raw.(type) {
	case map[string]string:
		for k, v := range h {
			if strings.TrimSpace(k) != "" {
				dst[k] = config.ResolveEnvValue(v)
			}
		}
	case map[string]any:
		for k, v := range h {
			if strings.TrimSpace(k) != "" {
				if sv, ok := v.(string); ok {
					dst[k] = config.ResolveEnvValue(sv)
				}
			}
		}
	}
}

func buildAllowedRequestHeaders(cfgMap map[string]any) map[string]struct{} {
	allowed := make(map[string]struct{}, len(defaultSafeRequestHeaders))
	for k := range defaultSafeRequestHeaders {
		allowed[k] = struct{}{}
	}
	for _, key := range []string{"allowed_request_headers", "header_allowlist"} {
		for _, item := range stringSliceFromMap(cfgMap, key) {
			lk := strings.ToLower(strings.TrimSpace(item))
			if lk == "" {
				continue
			}
			if _, sensitive := sensitiveRequestHeaders[lk]; sensitive {
				continue
			}
			allowed[lk] = struct{}{}
		}
	}
	return allowed
}

func hooksFromConfig(cfgMap map[string]any) []domain.GuardrailHook {
	for _, key := range []string{"event_hooks", "supported_hooks"} {
		switch v := cfgMap[key].(type) {
		case []domain.GuardrailHook:
			if len(v) > 0 {
				return slices.Clone(v)
			}
		default:
			items := stringSliceFromMap(cfgMap, key)
			if len(items) > 0 {
				out := make([]domain.GuardrailHook, 0, len(items))
				for _, item := range items {
					h := domain.GuardrailHook(strings.TrimSpace(item))
					if h.IsValid() {
						out = append(out, h)
					}
				}
				return out
			}
		}
	}
	return nil
}

func stringFromMap(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	v, ok := m[key]
	if !ok || v == nil {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return ""
	}
	return strings.TrimSpace(s)
}

func boolFromMap(m map[string]any, key string) bool {
	if m == nil {
		return false
	}
	b, _ := m[key].(bool)
	return b
}

func intFromMap(m map[string]any, key string) int {
	if m == nil {
		return 0
	}
	switch v := m[key].(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	default:
		return 0
	}
}

func stringSliceFromMap(m map[string]any, key string) []string {
	if m == nil {
		return nil
	}
	switch v := m[key].(type) {
	case []string:
		return v
	case []any:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

func firstNonEmptyString(vals ...string) string {
	for _, v := range vals {
		if trimmed := strings.TrimSpace(v); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
