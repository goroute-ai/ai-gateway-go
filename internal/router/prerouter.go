package router

import (
	"context"
	"errors"
	"math"
	"slices"
	"strings"
	"sync"

	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/ratelimit"
)

// Built-in pre-router mode names and virtual model aliases.
const (
	PreRouterModeHeuristic = "heuristic"
	PreRouterModeSemantic  = "semantic"
	PreRouterModeQuality   = "quality"
	PreRouterModeAdaptive  = "adaptive"

	VirtualAliasAuto      = "auto"
	VirtualAliasHeuristic = "router/heuristic"
	VirtualAliasSemantic  = "router/semantic"
	VirtualAliasQuality   = "router/quality"
	VirtualAliasAdaptive  = "router/adaptive"
)

// PreRouter selects a target model group alias for an incoming chat request
// before Stage 2 load balancing and failover run.
type PreRouter interface {
	Name() string
	Route(ctx context.Context, orgID string, req *domain.CanonicalChatRequest) (targetAlias string, reason string, score float64, err error)
}

// PreRouterRegistry manages named PreRouter implementations and maps virtual
// routing aliases (such as "auto" and "router/*") to them.
type PreRouterRegistry struct {
	mu          sync.RWMutex
	defaultMode string
	routers     map[string]PreRouter
	aliases     map[string]string
}

// NewPreRouterRegistry creates a PreRouterRegistry with built-in virtual alias
// mappings and a default mode for "auto" requests (defaulting to "heuristic").
func NewPreRouterRegistry(defaultMode string) *PreRouterRegistry {
	mode := normalizeModeName(defaultMode)
	if mode == "" {
		mode = PreRouterModeHeuristic
	}
	return &PreRouterRegistry{
		defaultMode: mode,
		routers:     make(map[string]PreRouter),
		aliases: map[string]string{
			VirtualAliasHeuristic: PreRouterModeHeuristic,
			VirtualAliasSemantic:  PreRouterModeSemantic,
			VirtualAliasQuality:   PreRouterModeQuality,
			VirtualAliasAdaptive:  PreRouterModeAdaptive,
		},
	}
}

// Register adds or replaces a named PreRouter in the registry.
func (r *PreRouterRegistry) Register(pr PreRouter) {
	if r == nil || pr == nil {
		return
	}
	name := normalizeModeName(pr.Name())
	if name == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.routers[name] = pr
}

// RegisterAlias maps a virtual model alias (e.g. "router/custom") to a named PreRouter.
func (r *PreRouterRegistry) RegisterAlias(virtualAlias, routerName string) {
	if r == nil {
		return
	}
	alias := strings.ToLower(strings.TrimSpace(virtualAlias))
	target := normalizeModeName(routerName)
	if alias == "" || target == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.aliases[alias] = target
}

// SetDefaultMode updates the PreRouter mode selected for "auto" requests.
func (r *PreRouterRegistry) SetDefaultMode(mode string) {
	if r == nil {
		return
	}
	norm := normalizeModeName(mode)
	if norm == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.defaultMode = norm
}

// DefaultMode returns the active mode name used for "auto" requests.
func (r *PreRouterRegistry) DefaultMode() string {
	if r == nil {
		return PreRouterModeHeuristic
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.defaultMode
}

// Get looks up a PreRouter by its registered mode name.
func (r *PreRouterRegistry) Get(name string) (PreRouter, bool) {
	if r == nil {
		return nil, false
	}
	norm := normalizeModeName(name)
	r.mu.RLock()
	defer r.mu.RUnlock()
	pr, ok := r.routers[norm]
	return pr, ok
}

// IsVirtualAlias reports whether requestedModel is "auto" or a registered virtual alias.
func (r *PreRouterRegistry) IsVirtualAlias(requestedModel string) bool {
	if r == nil {
		return false
	}
	key := strings.ToLower(strings.TrimSpace(requestedModel))
	if key == "" || key == VirtualAliasAuto {
		return true
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	_, ok := r.aliases[key]
	return ok
}

// ResolveAlias resolves a virtual model alias ("auto", "router/semantic", etc.)
// to its configured PreRouter. For "auto", if the configured defaultMode is not
// registered, it falls back to "heuristic" if available.
func (r *PreRouterRegistry) ResolveAlias(requestedModel string) (PreRouter, bool) {
	if r == nil {
		return nil, false
	}
	key := strings.ToLower(strings.TrimSpace(requestedModel))
	if key == "" {
		key = VirtualAliasAuto
	}

	r.mu.RLock()
	defer r.mu.RUnlock()

	if key == VirtualAliasAuto {
		if pr, ok := r.routers[r.defaultMode]; ok {
			return pr, true
		}
		if pr, ok := r.routers[PreRouterModeHeuristic]; ok {
			return pr, true
		}
		return nil, false
	}

	targetName, ok := r.aliases[key]
	if !ok {
		return nil, false
	}
	pr, ok := r.routers[targetName]
	return pr, ok
}

// Names returns the sorted names of all registered PreRouters.
func (r *PreRouterRegistry) Names() []string {
	if r == nil {
		return nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.routers))
	for k := range r.routers {
		names = append(names, k)
	}
	slices.Sort(names)
	return names
}

// Route resolves the PreRouter for req.Model (defaulting empty to "auto") and
// invokes it. If req.Model is not a recognized virtual alias with a registered
// PreRouter, matched is false.
func (r *PreRouterRegistry) Route(ctx context.Context, orgID string, req *domain.CanonicalChatRequest) (targetAlias string, reason string, score float64, matched bool, err error) {
	if r == nil || req == nil {
		return "", "", 0, false, nil
	}
	pr, ok := r.ResolveAlias(req.Model)
	if !ok {
		return "", "", 0, false, nil
	}
	alias, reason, score, err := pr.Route(ctx, orgID, req)
	return alias, reason, score, true, err
}

// HeuristicPreRouter implements PreRouter using GoRoute's deterministic
// rule + complexity scorer cascade.
type HeuristicPreRouter struct {
	cfg config.RouterConfig
	ir  *IntelligentRouter
}

// NewHeuristicPreRouter constructs a standalone HeuristicPreRouter from RouterConfig.
func NewHeuristicPreRouter(cfg config.RouterConfig) *HeuristicPreRouter {
	return &HeuristicPreRouter{cfg: normalizeRouterConfigDefaults(cfg)}
}

// NewHeuristicPreRouterWithRouter constructs a HeuristicPreRouter that delegates
// directly to an existing IntelligentRouter's prompt classifier.
func NewHeuristicPreRouterWithRouter(ir *IntelligentRouter) *HeuristicPreRouter {
	if ir == nil {
		return NewHeuristicPreRouter(config.RouterConfig{})
	}
	return &HeuristicPreRouter{
		cfg: normalizeRouterConfigDefaults(ir.cfg),
		ir:  ir,
	}
}

// Name returns "heuristic".
func (h *HeuristicPreRouter) Name() string {
	return PreRouterModeHeuristic
}

// Route classifies the prompt and selects the target fast or reasoning alias.
func (h *HeuristicPreRouter) Route(_ context.Context, _ string, req *domain.CanonicalChatRequest) (string, string, float64, error) {
	if req == nil {
		return "", "", 0, errors.New("request is required")
	}
	if h.ir != nil {
		alias, score, reason := h.ir.classifyPrompt(req)
		return alias, reason, score, nil
	}
	alias, score, reason := ClassifyPromptComplexity(h.cfg, req)
	return alias, reason, score, nil
}

// ClassifyPromptComplexity runs the deterministic Tier 1 rules and Tier 2
// multi-feature complexity scorer in < 0.2ms without calling an external LLM.
func ClassifyPromptComplexity(cfg config.RouterConfig, req *domain.CanonicalChatRequest) (targetAlias string, score float64, reason string) {
	cfg = normalizeRouterConfigDefaults(cfg)
	if req == nil {
		return cfg.DefaultFastAlias, 0, "heuristic:empty_request"
	}

	estTokens := ratelimit.EstimateRequestTokens(req)
	if estTokens >= cfg.LongContextTokens || strings.TrimSpace(req.ReasoningEffort) != "" {
		return cfg.DefaultReasoningAlias, 0.95, "rule:long_context_or_explicit_reasoning"
	}

	text := extractCombinedUserTextLower(req)

	lengthScore := math.Min(float64(estTokens)/1000.0, 1.0) * 0.25

	reasoningMarkers := []string{
		"step by step", "analyze", "architect", "prove", "theorem",
		"optimize", "trade-off", "design", "root cause", "debug",
		"concurrency", "distributed", "mathematical", "algorithm",
	}
	matchCount := 0
	for _, kw := range reasoningMarkers {
		if strings.Contains(text, kw) {
			matchCount++
		}
	}
	reasoningScore := math.Min(float64(matchCount)*0.22, 0.55)

	codeScore := 0.0
	if strings.Contains(text, "```") || strings.Contains(text, "func ") || strings.Contains(text, "select ") || strings.Contains(text, "class ") {
		codeScore = 0.30
	}

	turnScore := math.Min(float64(len(req.Messages))*0.03, 0.15)
	if len(req.Tools) > 0 {
		turnScore += 0.15
	}

	score = math.Min(lengthScore+reasoningScore+codeScore+turnScore, 1.0)
	if score >= cfg.ComplexityThreshold {
		return cfg.DefaultReasoningAlias, score, "heuristic:high_complexity"
	}
	return cfg.DefaultFastAlias, score, "heuristic:fast_simple_task"
}

func normalizeRouterConfigDefaults(cfg config.RouterConfig) config.RouterConfig {
	if cfg.DefaultFastAlias == "" {
		cfg.DefaultFastAlias = "fast"
	}
	if cfg.DefaultReasoningAlias == "" {
		cfg.DefaultReasoningAlias = "reasoning"
	}
	if cfg.DefaultCodingAlias == "" {
		cfg.DefaultCodingAlias = "coding"
	}
	if cfg.ComplexityThreshold <= 0 {
		cfg.ComplexityThreshold = 0.40
	}
	if cfg.LongContextTokens <= 0 {
		cfg.LongContextTokens = 32000
	}
	return cfg
}

func normalizeModeName(mode string) string {
	return strings.ToLower(strings.TrimSpace(mode))
}

func messageText(m domain.CanonicalMessage) string {
	if m.Content != "" {
		return m.Content
	}
	if len(m.Parts) == 0 {
		return ""
	}
	var b strings.Builder
	for _, p := range m.Parts {
		if (p.Type == "text" || p.Type == "input_text") && p.Text != "" {
			if b.Len() > 0 {
				b.WriteByte(' ')
			}
			b.WriteString(p.Text)
		}
	}
	return b.String()
}

func extractCombinedUserTextLower(req *domain.CanonicalChatRequest) string {
	if req == nil {
		return ""
	}
	var combined strings.Builder
	for _, m := range req.Messages {
		if strings.EqualFold(m.Role, "user") {
			if txt := messageText(m); txt != "" {
				combined.WriteString(strings.ToLower(txt))
				combined.WriteByte(' ')
			}
		}
	}
	return combined.String()
}

func extractLatestUserText(req *domain.CanonicalChatRequest) string {
	if req == nil {
		return ""
	}
	for i := len(req.Messages) - 1; i >= 0; i-- {
		if strings.EqualFold(req.Messages[i].Role, "user") {
			if txt := strings.TrimSpace(messageText(req.Messages[i])); txt != "" {
				return txt
			}
		}
	}
	return ""
}
