package drivers

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/goroute-ai/ai-gateway-go/internal/adapter"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/guardrails"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

const (
	ProviderOpenAIModeration   = "openai_moderation"
	ProviderPresidio           = "presidio"
	ProviderLakeraV2           = "lakera_v2"
	ProviderGuardrailsAI       = "guardrails_ai"
	ProviderPangea             = "pangea"
	ProviderLocalContentFilter = "local_content_filter"
	ProviderGenericHTTP        = DriverNameGenericHTTP
	ProviderCustomCode         = CustomCodeProvider
)

const defaultMaxGuardrailResponseBytes int64 = 4 << 20 // 4 MiB

// Constructor builds a guardrail Driver from resolved configuration and a shared HTTP client.
type Constructor func(cfg guardrails.DriverConfig, httpClient *http.Client) (guardrails.Driver, error)

// RegistryOption configures optional behavior on a Driver Registry.
type RegistryOption func(*Registry)

// WithHTTPClient overrides the default SSRF-enforced HTTP client used by network-backed drivers.
// Primarily useful for unit tests targeting httptest servers.
func WithHTTPClient(client *http.Client) RegistryOption {
	return func(r *Registry) {
		r.httpClient = client
	}
}

// WithNetworkPolicy configures the outbound SSRF policy used to construct the default HTTP client
// when WithHTTPClient is not provided.
func WithNetworkPolicy(policy *network.Policy) RegistryOption {
	return func(r *Registry) {
		r.networkPolicy = policy
	}
}

// WithSSRFPolicy is an alias for WithNetworkPolicy configuring the outbound SSRF policy for
// network-backed and custom_code drivers.
func WithSSRFPolicy(policy *network.Policy) RegistryOption {
	return WithNetworkPolicy(policy)
}

// WithChatExecutor configures the internal ChatExecutor used by llm_as_a_judge and decision_model.
func WithChatExecutor(executor ChatExecutor) RegistryOption {
	return func(r *Registry) {
		r.chatExecutor = executor
	}
}

// WithToolPolicyRepository configures the persistent ToolPolicyRepository used by tool_policy.
func WithToolPolicyRepository(repo storage.ToolPolicyRepository) RegistryOption {
	return func(r *Registry) {
		r.toolPolicyRepo = repo
	}
}

// WithMCPServerRegistry configures the repository used by mcp_security to resolve registered
// tenant MCPServer entries.
func WithMCPServerRegistry(repo storage.Repository) RegistryOption {
	return func(r *Registry) {
		r.mcpServerRepo = repo
	}
}

// Registry is a thread-safe catalog mapping guardrail provider names to driver constructors.
// Its Build method satisfies guardrails.DriverLookup and guardrails.DriverFactory directly.
type Registry struct {
	mu             sync.RWMutex
	constructors   map[string]Constructor
	httpClient     *http.Client
	networkPolicy  *network.Policy
	chatExecutor   ChatExecutor
	toolPolicyRepo storage.ToolPolicyRepository
	mcpServerRepo  storage.Repository
}

// NewRegistry creates a Registry pre-populated with all built-in cloud, OSS, local, governance,
// MCP, and model-based guardrail drivers.
// By default, network-backed drivers use network.NewHTTPClient enforcing strict outbound SSRF policy.
func NewRegistry(opts ...RegistryOption) *Registry {
	r := &Registry{
		constructors: make(map[string]Constructor, 19),
	}
	for _, opt := range opts {
		if opt != nil {
			opt(r)
		}
	}
	if r.httpClient == nil {
		r.httpClient = network.NewHTTPClient(r.networkPolicy)
	}

	// Wave 1: OpenAI moderation, OSS, and local content filters.
	r.Register(ProviderOpenAIModeration, NewOpenAIModerationDriver)
	r.Register(ProviderPresidio, NewPresidioDriver)
	r.Register(ProviderLakeraV2, NewLakeraV2Driver)
	r.Register(ProviderGuardrailsAI, NewGuardrailsAIDriver)
	r.Register(ProviderPangea, NewPangeaDriver)
	r.Register(ProviderLocalContentFilter, NewLocalContentFilterDriver)

	// Wave 2+3: Webhook, Starlark sandbox, tool governance, MCP security, and LLM judge/decision drivers.
	r.Register(DriverNameGenericHTTP, func(cfg guardrails.DriverConfig, httpClient *http.Client) (guardrails.Driver, error) {
		return NewGenericHTTPDriver(cfg, httpClient)
	})
	r.Register(CustomCodeProvider, func(cfg guardrails.DriverConfig, httpClient *http.Client) (guardrails.Driver, error) {
		return NewCustomCodeDriverWithPolicy(cfg, r.networkPolicy, httpClient)
	})
	r.Register(ProviderToolPermission, func(cfg guardrails.DriverConfig, _ *http.Client) (guardrails.Driver, error) {
		return NewToolPermissionDriver(cfg)
	})
	r.Register(ProviderToolPolicy, func(cfg guardrails.DriverConfig, _ *http.Client) (guardrails.Driver, error) {
		return NewToolPolicyDriver(cfg, r.toolPolicyRepo)
	})
	r.Register(ProviderCodeExecution, func(cfg guardrails.DriverConfig, _ *http.Client) (guardrails.Driver, error) {
		return NewCodeExecutionDriver(cfg)
	})
	r.Register(ProviderMCPSecurity, func(cfg guardrails.DriverConfig, _ *http.Client) (guardrails.Driver, error) {
		if r.mcpServerRepo != nil {
			return NewMCPSecurityDriver(cfg, r.mcpServerRepo)
		}
		return NewMCPSecurityDriver(cfg)
	})
	r.Register(ProviderMCPEndUserPermission, func(cfg guardrails.DriverConfig, _ *http.Client) (guardrails.Driver, error) {
		return NewMCPEndUserPermissionDriver(cfg)
	})
	r.Register(ProviderLLMJudge, func(cfg guardrails.DriverConfig, _ *http.Client) (guardrails.Driver, error) {
		return NewLLMJudgeDriver(cfg, r.chatExecutor)
	})
	r.Register(ProviderDecisionModel, func(cfg guardrails.DriverConfig, _ *http.Client) (guardrails.Driver, error) {
		return NewDecisionModelDriver(cfg, r.chatExecutor)
	})
	return r
}

// Register adds or replaces a Constructor for the given provider identifier (case-insensitive).
func (r *Registry) Register(provider string, ctor Constructor) {
	if r == nil || ctor == nil {
		return
	}
	key := normalizeProviderKey(provider)
	if key == "" {
		return
	}
	r.mu.Lock()
	r.constructors[key] = ctor
	r.mu.Unlock()
}

// Has reports whether a constructor is registered for provider.
func (r *Registry) Has(provider string) bool {
	if r == nil {
		return false
	}
	key := normalizeProviderKey(provider)
	r.mu.RLock()
	_, ok := r.constructors[key]
	r.mu.RUnlock()
	return ok
}

// Providers returns the sorted list of registered provider identifiers.
func (r *Registry) Providers() []string {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	out := make([]string, 0, len(r.constructors))
	for k := range r.constructors {
		out = append(out, k)
	}
	r.mu.RUnlock()
	sort.Strings(out)
	return out
}

// Build instantiates a guardrails.Driver for cfg.Definition.Provider.
// Its signature matches guardrails.DriverLookup and guardrails.DriverFactory.
func (r *Registry) Build(ctx context.Context, cfg guardrails.DriverConfig) (guardrails.Driver, error) {
	if r == nil {
		return nil, fmt.Errorf("guardrail driver registry is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if cfg.Definition == nil {
		return nil, fmt.Errorf("guardrail driver config missing definition")
	}
	key := normalizeProviderKey(cfg.Definition.Provider)
	if key == "" {
		return nil, fmt.Errorf("guardrail definition %q missing provider", cfg.Definition.Name)
	}

	r.mu.RLock()
	ctor, ok := r.constructors[key]
	client := r.httpClient
	r.mu.RUnlock()
	if !ok {
		return nil, fmt.Errorf("no guardrail driver constructor registered for provider %q", cfg.Definition.Provider)
	}
	return ctor(cfg, client)
}

func normalizeProviderKey(provider string) string {
	return strings.ToLower(strings.TrimSpace(provider))
}

func resolveHTTPClient(httpClient *http.Client) *http.Client {
	if httpClient != nil {
		return httpClient
	}
	return network.NewHTTPClient(nil)
}

// resolveSecretOrConfig inspects DecryptedSecrets first, then EffectiveConfig (and Definition.Config),
// returning the first non-empty trimmed string value matching any of keys.
func resolveSecretOrConfig(cfg guardrails.DriverConfig, keys ...string) string {
	for _, key := range keys {
		if v, ok := lookupStringCaseInsensitive(cfg.DecryptedSecrets, key); ok && v != "" {
			return v
		}
	}
	return configString(cfg, keys...)
}

func configMap(cfg guardrails.DriverConfig) map[string]any {
	if len(cfg.EffectiveConfig) > 0 {
		return cfg.EffectiveConfig
	}
	if cfg.Definition != nil && len(cfg.Definition.Config) > 0 {
		return cfg.Definition.Config
	}
	return nil
}

func lookupStringCaseInsensitive(m map[string]any, target string) (string, bool) {
	if len(m) == 0 || target == "" {
		return "", false
	}
	if raw, ok := m[target]; ok {
		if s := stringFromAny(raw); s != "" {
			return s, true
		}
	}
	lowerTarget := strings.ToLower(target)
	for k, raw := range m {
		if strings.ToLower(k) == lowerTarget {
			if s := stringFromAny(raw); s != "" {
				return s, true
			}
		}
	}
	return "", false
}

func lookupAnyCaseInsensitive(m map[string]any, target string) (any, bool) {
	if len(m) == 0 || target == "" {
		return nil, false
	}
	if raw, ok := m[target]; ok && raw != nil {
		return raw, true
	}
	lowerTarget := strings.ToLower(target)
	for k, raw := range m {
		if strings.ToLower(k) == lowerTarget && raw != nil {
			return raw, true
		}
	}
	return nil, false
}

func configString(cfg guardrails.DriverConfig, keys ...string) string {
	cm := configMap(cfg)
	for _, key := range keys {
		if v, ok := lookupStringCaseInsensitive(cm, key); ok && v != "" {
			return v
		}
	}
	return ""
}

func configBool(cfg guardrails.DriverConfig, defaultVal bool, keys ...string) bool {
	cm := configMap(cfg)
	for _, key := range keys {
		if raw, ok := lookupAnyCaseInsensitive(cm, key); ok {
			if b, ok := boolFromAny(raw); ok {
				return b
			}
		}
	}
	return defaultVal
}

func configInt(cfg guardrails.DriverConfig, defaultVal int, keys ...string) int {
	cm := configMap(cfg)
	for _, key := range keys {
		if raw, ok := lookupAnyCaseInsensitive(cm, key); ok {
			if n, ok := intFromAny(raw); ok {
				return n
			}
		}
	}
	return defaultVal
}

func configFloat(cfg guardrails.DriverConfig, defaultVal float64, keys ...string) float64 {
	cm := configMap(cfg)
	for _, key := range keys {
		if raw, ok := lookupAnyCaseInsensitive(cm, key); ok {
			if f, ok := floatFromAny(raw); ok {
				return f
			}
		}
	}
	return defaultVal
}

func configStringSlice(cfg guardrails.DriverConfig, keys ...string) []string {
	cm := configMap(cfg)
	for _, key := range keys {
		if raw, ok := lookupAnyCaseInsensitive(cm, key); ok {
			if sl := stringSliceFromAny(raw); len(sl) > 0 {
				return sl
			}
		}
	}
	return nil
}

func configFloatMap(cfg guardrails.DriverConfig, keys ...string) map[string]float64 {
	cm := configMap(cfg)
	for _, key := range keys {
		if raw, ok := lookupAnyCaseInsensitive(cm, key); ok {
			switch m := raw.(type) {
			case map[string]float64:
				out := make(map[string]float64, len(m))
				maps.Copy(out, m)
				return out
			case map[string]any:
				out := make(map[string]float64, len(m))
				for k, v := range m {
					if f, ok := floatFromAny(v); ok {
						out[k] = f
					}
				}
				return out
			case map[string]int:
				out := make(map[string]float64, len(m))
				for k, v := range m {
					out[k] = float64(v)
				}
				return out
			}
		}
	}
	return nil
}

func configAnyMap(cfg guardrails.DriverConfig, keys ...string) map[string]any {
	cm := configMap(cfg)
	for _, key := range keys {
		if raw, ok := lookupAnyCaseInsensitive(cm, key); ok {
			if m, ok := raw.(map[string]any); ok {
				out := make(map[string]any, len(m))
				maps.Copy(out, m)
				return out
			}
		}
	}
	return nil
}

func stringFromAny(v any) string {
	switch x := v.(type) {
	case string:
		return strings.TrimSpace(x)
	case []byte:
		return strings.TrimSpace(string(x))
	default:
		return ""
	}
}

func boolFromAny(v any) (bool, bool) {
	switch x := v.(type) {
	case bool:
		return x, true
	case string:
		b, err := strconv.ParseBool(strings.TrimSpace(x))
		return b, err == nil
	default:
		return false, false
	}
}

func intFromAny(v any) (int, bool) {
	switch x := v.(type) {
	case int:
		return x, true
	case int32:
		return int(x), true
	case int64:
		return int(x), true
	case float64:
		return int(x), true
	case float32:
		return int(x), true
	case json.Number:
		i, err := x.Int64()
		return int(i), err == nil
	case string:
		i, err := strconv.Atoi(strings.TrimSpace(x))
		return i, err == nil
	default:
		return 0, false
	}
}

func floatFromAny(v any) (float64, bool) {
	switch x := v.(type) {
	case float64:
		return x, true
	case float32:
		return float64(x), true
	case int:
		return float64(x), true
	case int64:
		return float64(x), true
	case json.Number:
		f, err := x.Float64()
		return f, err == nil
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(x), 64)
		return f, err == nil
	default:
		return 0, false
	}
}

func stringSliceFromAny(v any) []string {
	switch x := v.(type) {
	case []string:
		out := make([]string, 0, len(x))
		for _, item := range x {
			if s := strings.TrimSpace(item); s != "" {
				out = append(out, s)
			}
		}
		return out
	case []any:
		out := make([]string, 0, len(x))
		for _, item := range x {
			if s := stringFromAny(item); s != "" {
				out = append(out, s)
			}
		}
		return out
	case string:
		parts := strings.Split(x, ",")
		out := make([]string, 0, len(parts))
		for _, part := range parts {
			if s := strings.TrimSpace(part); s != "" {
				out = append(out, s)
			}
		}
		return out
	default:
		return nil
	}
}

func normalizeActionString(raw string) domain.GuardrailAction {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "block", "deny", "reject":
		return domain.GuardrailActionBlock
	case "redact", "mask", "anonymize", "modify", "transform":
		return domain.GuardrailActionRedact
	case "audit", "flag", "warn", "log":
		return domain.GuardrailActionAudit
	default:
		return ""
	}
}

func effectiveAction(cfg guardrails.DriverConfig, fallback domain.GuardrailAction) domain.GuardrailAction {
	if act := normalizeActionString(string(cfg.EffectiveAction)); act != "" {
		return act
	}
	if raw := configString(cfg, "action", "default_action"); raw != "" {
		if act := normalizeActionString(raw); act != "" {
			return act
		}
	}
	if fallback != "" {
		return fallback
	}
	return domain.GuardrailActionBlock
}

func guardrailName(cfg guardrails.DriverConfig, fallback string) string {
	if cfg.Definition != nil && strings.TrimSpace(cfg.Definition.Name) != "" {
		return cfg.Definition.Name
	}
	return fallback
}

func guardrailID(cfg guardrails.DriverConfig) string {
	if cfg.Definition != nil {
		return cfg.Definition.ID
	}
	return ""
}

func defaultTextHooks() []domain.GuardrailHook {
	return []domain.GuardrailHook{
		domain.GuardrailHookPreCall,
		domain.GuardrailHookDuringCall,
		domain.GuardrailHookPostCall,
		domain.GuardrailHookLoggingOnly,
	}
}

func extractTexts(input *domain.GuardrailEvalInput) []string {
	if input == nil {
		return nil
	}
	if len(input.Texts) > 0 {
		out := make([]string, len(input.Texts))
		copy(out, input.Texts)
		return out
	}
	if len(input.StructuredMessages) == 0 {
		return nil
	}
	out := make([]string, len(input.StructuredMessages))
	for i, msg := range input.StructuredMessages {
		if msg.Content != "" {
			out[i] = msg.Content
			continue
		}
		var sb strings.Builder
		for _, p := range msg.Parts {
			if p.Type == "text" {
				sb.WriteString(p.Text)
			}
		}
		out[i] = sb.String()
	}
	return out
}

func hasNonEmptyText(texts []string) bool {
	for _, t := range texts {
		if strings.TrimSpace(t) != "" {
			return true
		}
	}
	return false
}

func joinedNonEmptyText(texts []string) string {
	var parts []string
	for _, t := range texts {
		if t != "" {
			parts = append(parts, t)
		}
	}
	return strings.Join(parts, "\n")
}

func isOutputDirection(input *domain.GuardrailEvalInput) bool {
	if input == nil {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(input.Direction), domain.GuardrailDirectionOutput) {
		return true
	}
	switch input.Hook {
	case domain.GuardrailHookPostCall, domain.GuardrailHookPostMCPCall:
		return true
	default:
		return false
	}
}

func doJSONRequest(
	ctx context.Context,
	client *http.Client,
	method string,
	targetURL string,
	headers map[string]string,
	reqBody any,
	provider domain.ProviderType,
) (int, []byte, error) {
	var bodyReader io.Reader
	if reqBody != nil {
		raw, err := json.Marshal(reqBody)
		if err != nil {
			return 0, nil, fmt.Errorf("marshal %s request: %w", provider, err)
		}
		bodyReader = bytes.NewReader(raw)
	}

	req, err := http.NewRequestWithContext(ctx, method, targetURL, bodyReader)
	if err != nil {
		return 0, nil, fmt.Errorf("build %s request: %w", provider, err)
	}
	if reqBody != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	for k, v := range headers {
		if strings.TrimSpace(k) != "" && v != "" {
			req.Header.Set(k, v)
		}
	}

	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("%s request failed: %w", provider, err)
	}
	defer resp.Body.Close()

	respBytes, err := adapter.ReadBoundedBody(resp.Body, defaultMaxGuardrailResponseBytes, provider)
	if err != nil {
		return resp.StatusCode, nil, err
	}
	return resp.StatusCode, respBytes, nil
}
