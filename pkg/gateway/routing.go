package gateway

import (
	"context"
	"fmt"
	"maps"
	"math"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/router"
	"github.com/goroute-ai/ai-gateway-go/internal/server"
)

// FallbackTarget specifies a fallback model group alias along with optional parameter overrides.
type FallbackTarget struct {
	Target    string         `json:"target" yaml:"target"`
	Overrides map[string]any `json:"overrides,omitempty" yaml:"overrides,omitempty"`
}

// RoutingCandidate describes an active deployment candidate evaluated by a custom RoutingPluginFunc.
type RoutingCandidate struct {
	DeploymentID   string   `json:"deployment_id"`
	DeploymentName string   `json:"deployment_name"`
	Provider       string   `json:"provider"`
	ModelName      string   `json:"model_name"`
	Region         string   `json:"region,omitempty"`
	Tags           []string `json:"tags,omitempty"`
	Priority       int      `json:"priority"`
	Weight         int      `json:"weight"`
}

// RoutingPluginContext carries per-request routing metadata and eligible candidates
// passed to a custom RoutingPluginFunc during Stage 2 deployment filtering.
type RoutingPluginContext struct {
	OrgID           string             `json:"org_id"`
	GroupAlias      string             `json:"group_alias"`
	RequestedModel  string             `json:"requested_model"`
	EstimatedTokens int                `json:"estimated_tokens"`
	Candidates      []RoutingCandidate `json:"candidates"`
}

// RoutingPluginFunc filters and optionally reorders candidate deployments for a request.
// It returns the ordered slice of allowed DeploymentID values (an empty slice rejects all
// candidates). Returning a non-nil error aborts routing for the request.
type RoutingPluginFunc func(ctx context.Context, rc RoutingPluginContext) ([]string, error)

// PreRouterFunc resolves a virtual model request (such as "auto" or "router/<name>")
// to a concrete model group alias before Stage 2 load balancing and failover run.
type PreRouterFunc func(ctx context.Context, orgID string, req ChatRequest) (targetAlias string, reason string, score float64, err error)

// RouterOptions configures embedded router defaults for pre-routing, fallbacks,
// mid-stream continuation, hedged requests, and session affinity.
type RouterOptions struct {
	PreRouterMode                  string
	DefaultFastAlias               string
	DefaultReasoningAlias          string
	DefaultCodingAlias             string
	ComplexityThreshold            float64
	LongContextTokens              int
	DefaultMaxRetries              int
	BaseRetryDelay                 time.Duration
	MaxRetryDelay                  time.Duration
	DefaultCooldown                time.Duration
	FailureWindow                  time.Duration
	FailureThreshold               int
	DefaultFallbacks               []FallbackTarget
	MaxFallbackDepth               int
	EnableMidStreamContinuation    bool
	MaxStreamContinuations         int
	HealthStalenessThreshold       time.Duration
	StrictCapacityFiltering        bool
	ProviderBudgets                map[string]int64
	SessionAffinityTTL             time.Duration
	SessionAffinityRepinOnFailover bool
	PromptCacheAffinity            bool
	CacheAwareRouting              bool
	HedgeDelayMs                   int
	MaxHedgeConcurrency            int
	LatencyTolerancePct            float64
	MaxHonoredRetryAfter           time.Duration
	DisableCooldowns               bool
	FallbackOnSaturation           bool
	DropUnsupportedParams          bool
	FallbackOnUnsupportedParams    bool
	AllowStrategyOverride          bool
	DebugRoutingHeaders            bool
	MaxParallelWaitMs              int
}

type routingPluginEntry struct {
	name string
	fn   RoutingPluginFunc
}

type preRouterEntry struct {
	name string
	fn   PreRouterFunc
}

type preRouterAliasEntry struct {
	virtualAlias string
	routerName   string
}

// WithRoutingPlugin registers a custom Stage 2 deployment filter/reorder plugin on the embedded gateway.
func WithRoutingPlugin(name string, fn RoutingPluginFunc) Option {
	return func(c *clientConfig) {
		c.routingPlugins = append(c.routingPlugins, routingPluginEntry{
			name: name,
			fn:   fn,
		})
	}
}

// WithPreRouter registers a custom Stage 1 PreRouter on the embedded gateway and binds
// the virtual alias "router/<name>" (or "<name>" if already prefixed with "router/") to it.
func WithPreRouter(name string, fn PreRouterFunc) Option {
	return func(c *clientConfig) {
		c.preRouters = append(c.preRouters, preRouterEntry{
			name: name,
			fn:   fn,
		})
	}
}

// WithPreRouterAlias binds a custom virtual model alias (e.g. "router/custom") to a named PreRouter.
func WithPreRouterAlias(virtualAlias, routerName string) Option {
	return func(c *clientConfig) {
		c.preRouterAliases = append(c.preRouterAliases, preRouterAliasEntry{
			virtualAlias: virtualAlias,
			routerName:   routerName,
		})
	}
}

// WithPreRouterMode sets the default PreRouter mode used when a request specifies model "auto".
func WithPreRouterMode(mode string) Option {
	return func(c *clientConfig) {
		c.routerMutations = append(c.routerMutations, func(r *config.RouterConfig) {
			if m := strings.TrimSpace(mode); m != "" {
				r.PreRouterMode = m
			}
		})
	}
}

// WithRouterConfig applies embedded router configuration defaults from RouterOptions.
func WithRouterConfig(rc RouterOptions) Option {
	return func(c *clientConfig) {
		c.routerMutations = append(c.routerMutations, func(r *config.RouterConfig) {
			if v := strings.TrimSpace(rc.PreRouterMode); v != "" {
				r.PreRouterMode = v
			}
			if v := strings.TrimSpace(rc.DefaultFastAlias); v != "" {
				r.DefaultFastAlias = v
			}
			if v := strings.TrimSpace(rc.DefaultReasoningAlias); v != "" {
				r.DefaultReasoningAlias = v
			}
			if v := strings.TrimSpace(rc.DefaultCodingAlias); v != "" {
				r.DefaultCodingAlias = v
			}
			if rc.ComplexityThreshold > 0 {
				r.ComplexityThreshold = rc.ComplexityThreshold
			}
			if rc.LongContextTokens > 0 {
				r.LongContextTokens = rc.LongContextTokens
			}
			if rc.DefaultMaxRetries > 0 {
				r.DefaultMaxRetries = rc.DefaultMaxRetries
			}
			if rc.BaseRetryDelay > 0 {
				r.BaseRetryDelay = rc.BaseRetryDelay
			}
			if rc.MaxRetryDelay > 0 {
				r.MaxRetryDelay = rc.MaxRetryDelay
			}
			if rc.DefaultCooldown > 0 {
				r.DefaultCooldown = rc.DefaultCooldown
			}
			if rc.FailureWindow > 0 {
				r.FailureWindow = rc.FailureWindow
			}
			if rc.FailureThreshold > 0 {
				r.FailureThreshold = rc.FailureThreshold
			}
			if len(rc.DefaultFallbacks) > 0 {
				r.DefaultFallbacks = convertFallbackTargets(rc.DefaultFallbacks)
			}
			if rc.MaxFallbackDepth > 0 {
				r.MaxFallbackDepth = rc.MaxFallbackDepth
			}
			if rc.EnableMidStreamContinuation {
				r.EnableMidStreamContinuation = true
			}
			if rc.MaxStreamContinuations > 0 {
				r.MaxStreamContinuations = rc.MaxStreamContinuations
			}
			if rc.HealthStalenessThreshold > 0 {
				r.HealthStalenessThreshold = rc.HealthStalenessThreshold
			}
			if rc.StrictCapacityFiltering {
				r.StrictCapacityFiltering = true
			}
			if len(rc.ProviderBudgets) > 0 {
				r.ProviderBudgets = maps.Clone(rc.ProviderBudgets)
			}
			if rc.SessionAffinityTTL > 0 {
				r.SessionAffinityTTL = rc.SessionAffinityTTL
			}
			if rc.SessionAffinityRepinOnFailover {
				r.SessionAffinityRepinOnFailover = true
			}
			if rc.PromptCacheAffinity {
				r.PromptCacheAffinity = true
			}
			if rc.CacheAwareRouting {
				r.CacheAwareRouting = true
			}
			if rc.HedgeDelayMs > 0 {
				r.HedgeDelayMs = rc.HedgeDelayMs
			}
			if rc.MaxHedgeConcurrency > 0 {
				r.MaxHedgeConcurrency = rc.MaxHedgeConcurrency
			}
			if rc.LatencyTolerancePct > 0 {
				r.LatencyTolerancePct = rc.LatencyTolerancePct
			}
			if rc.MaxHonoredRetryAfter > 0 {
				r.MaxHonoredRetryAfter = rc.MaxHonoredRetryAfter
			}
			if rc.DisableCooldowns {
				r.DisableCooldowns = true
			}
			if rc.FallbackOnSaturation {
				r.FallbackOnSaturation = true
			}
			if rc.DropUnsupportedParams {
				r.DropUnsupportedParams = true
			}
			if rc.FallbackOnUnsupportedParams {
				r.FallbackOnUnsupportedParams = true
			}
			if rc.AllowStrategyOverride {
				r.AllowStrategyOverride = true
			}
			if rc.DebugRoutingHeaders {
				r.DebugRoutingHeaders = true
			}
			if rc.MaxParallelWaitMs > 0 {
				r.Scheduler.MaxParallelWaitMs = rc.MaxParallelWaitMs
			}
		})
	}
}

// WithDefaultFallbacks sets global fallback model group aliases applied when a model group
// has no local fallbacks configured.
func WithDefaultFallbacks(aliases ...string) Option {
	return func(c *clientConfig) {
		cloned := slices.Clone(aliases)
		c.routerMutations = append(c.routerMutations, func(r *config.RouterConfig) {
			r.DefaultFallbacks = toDomainFallbackTargets(cloned)
		})
	}
}

// WithDefaultFallbackTargets sets global fallback targets (with optional parameter overrides)
// applied when a model group has no local fallbacks configured.
func WithDefaultFallbackTargets(targets ...FallbackTarget) Option {
	return func(c *clientConfig) {
		cloned := slices.Clone(targets)
		c.routerMutations = append(c.routerMutations, func(r *config.RouterConfig) {
			r.DefaultFallbacks = convertFallbackTargets(cloned)
		})
	}
}

// WithMidStreamContinuation enables or disables mid-stream SSE failover continuation
// and optionally configures the maximum number of continuation attempts per stream.
func WithMidStreamContinuation(enabled bool, maxContinuations int) Option {
	return func(c *clientConfig) {
		c.routerMutations = append(c.routerMutations, func(r *config.RouterConfig) {
			r.EnableMidStreamContinuation = enabled
			if maxContinuations > 0 {
				r.MaxStreamContinuations = maxContinuations
			}
		})
	}
}

// WithHedgeConfig configures default hedged-request stagger delay (ms) and max concurrency.
func WithHedgeConfig(hedgeDelayMs, maxConcurrency int) Option {
	return func(c *clientConfig) {
		c.routerMutations = append(c.routerMutations, func(r *config.RouterConfig) {
			if hedgeDelayMs > 0 {
				r.HedgeDelayMs = hedgeDelayMs
			}
			if maxConcurrency > 0 {
				r.MaxHedgeConcurrency = maxConcurrency
			}
		})
	}
}

// WithSessionAffinity configures session-affinity TTL and failover repinning behavior.
func WithSessionAffinity(ttl time.Duration, repinOnFailover bool) Option {
	return func(c *clientConfig) {
		c.routerMutations = append(c.routerMutations, func(r *config.RouterConfig) {
			if ttl > 0 {
				r.SessionAffinityTTL = ttl
			}
			r.SessionAffinityRepinOnFailover = repinOnFailover
		})
	}
}

// WithRoutingHints attaches per-request routing hints (region, tags, session affinity,
// preferred deployment, priority, and hedging) mapped to `goroute_extensions`.
func WithRoutingHints(hints RoutingHints) RequestOption {
	return func(r *domain.CanonicalChatRequest) {
		if r.GoRouteExtensions == nil {
			r.GoRouteExtensions = &domain.GoRouteExtensions{}
		}
		if v := strings.TrimSpace(hints.AllowedRegion); v != "" {
			r.GoRouteExtensions.AllowedRegion = v
		}
		if len(hints.Tags) > 0 {
			r.GoRouteExtensions.Tags = append(r.GoRouteExtensions.Tags, hints.Tags...)
		}
		if v := strings.TrimSpace(hints.SessionID); v != "" {
			r.GoRouteExtensions.SessionID = v
		}
		if v := strings.TrimSpace(hints.PreferredDeploymentID); v != "" {
			r.GoRouteExtensions.PreferredDeploymentID = v
		}
		if hints.Priority != 0 {
			r.GoRouteExtensions.Priority = hints.Priority
		}
		if hints.HedgeAfterMs > 0 {
			r.GoRouteExtensions.HedgeAfterMs = hints.HedgeAfterMs
		}
		if v := strings.TrimSpace(hints.RoutingStrategy); v != "" {
			r.GoRouteExtensions.RoutingStrategy = v
		}
		if hints.DropUnsupportedParams != nil {
			drop := *hints.DropUnsupportedParams
			r.GoRouteExtensions.DropUnsupportedParams = &drop
		}
	}
}

type sdkRoutingPluginAdapter struct {
	name string
	fn   RoutingPluginFunc
}

func (p *sdkRoutingPluginAdapter) Name() string {
	return p.name
}

func (p *sdkRoutingPluginAdapter) Filter(ctx context.Context, rc *router.RoutingContext) ([]*domain.Deployment, error) {
	if rc == nil || p.fn == nil {
		if rc == nil {
			return nil, nil
		}
		return rc.Candidates, nil
	}
	pubCtx := RoutingPluginContext{
		OrgID:           rc.OrgID,
		GroupAlias:      rc.GroupAlias,
		EstimatedTokens: rc.EstimatedTokens,
		Candidates:      make([]RoutingCandidate, 0, len(rc.Candidates)),
	}
	if rc.Request != nil {
		pubCtx.RequestedModel = rc.Request.Model
	}
	byID := make(map[string]*domain.Deployment, len(rc.Candidates))
	for _, dep := range rc.Candidates {
		if dep == nil {
			continue
		}
		byID[dep.ID] = dep
		cand := RoutingCandidate{
			DeploymentID:   dep.ID,
			DeploymentName: dep.DeploymentName,
			Region:         dep.Region,
			Tags:           slices.Clone(dep.Tags),
			Priority:       dep.Priority,
			Weight:         dep.Weight,
		}
		if dep.GlobalModel != nil {
			cand.Provider = string(dep.GlobalModel.Provider)
			cand.ModelName = dep.GlobalModel.ModelName
		}
		pubCtx.Candidates = append(pubCtx.Candidates, cand)
	}

	allowedIDs, err := p.fn(ctx, pubCtx)
	if err != nil {
		return nil, err
	}
	if len(allowedIDs) == 0 {
		return nil, nil
	}

	filtered := make([]*domain.Deployment, 0, len(allowedIDs))
	seen := make(map[string]struct{}, len(allowedIDs))
	for _, id := range allowedIDs {
		if _, dup := seen[id]; dup {
			continue
		}
		if dep, ok := byID[id]; ok {
			seen[id] = struct{}{}
			filtered = append(filtered, dep)
		}
	}
	return filtered, nil
}

type sdkPreRouterAdapter struct {
	name string
	fn   PreRouterFunc
}

func (p *sdkPreRouterAdapter) Name() string {
	return p.name
}

func (p *sdkPreRouterAdapter) Route(ctx context.Context, orgID string, req *domain.CanonicalChatRequest) (string, string, float64, error) {
	if p.fn == nil {
		return "", "", 0, fmt.Errorf("pre-router %q function is nil", p.name)
	}
	return p.fn(ctx, orgID, toSDKChatRequest(req))
}

func registerSDKRoutingHooks(
	gw *server.GatewayServer,
	plugins []routingPluginEntry,
	preRouters []preRouterEntry,
	aliases []preRouterAliasEntry,
) error {
	for _, entry := range plugins {
		cleanName := strings.TrimSpace(entry.name)
		if cleanName == "" {
			return fmt.Errorf("routing plugin name must not be empty")
		}
		if entry.fn == nil {
			return fmt.Errorf("routing plugin %q must not be nil", cleanName)
		}
		gw.AddRoutingPlugin(&sdkRoutingPluginAdapter{
			name: cleanName,
			fn:   entry.fn,
		})
	}

	for _, entry := range preRouters {
		cleanName := strings.TrimSpace(entry.name)
		if cleanName == "" {
			return fmt.Errorf("pre-router name must not be empty")
		}
		if entry.fn == nil {
			return fmt.Errorf("pre-router %q must not be nil", cleanName)
		}
		gw.RegisterPreRouter(&sdkPreRouterAdapter{
			name: cleanName,
			fn:   entry.fn,
		})
		if ir := gw.IntelligentRouter(); ir != nil && ir.PreRouters() != nil {
			norm := strings.ToLower(cleanName)
			if strings.HasPrefix(norm, "router/") {
				ir.PreRouters().RegisterAlias(norm, norm)
			} else {
				ir.PreRouters().RegisterAlias("router/"+norm, norm)
			}
		}
	}

	for _, alias := range aliases {
		vAlias := strings.TrimSpace(alias.virtualAlias)
		rName := strings.TrimSpace(alias.routerName)
		if vAlias == "" || rName == "" {
			return fmt.Errorf("pre-router alias and target router name must not be empty")
		}
		if ir := gw.IntelligentRouter(); ir != nil && ir.PreRouters() != nil {
			ir.PreRouters().RegisterAlias(vAlias, rName)
		}
	}

	return nil
}

func toDomainFallbackTargets(aliases []string) []domain.FallbackTarget {
	if len(aliases) == 0 {
		return nil
	}
	out := make([]domain.FallbackTarget, 0, len(aliases))
	for _, alias := range aliases {
		trimmed := strings.TrimSpace(alias)
		if trimmed == "" {
			continue
		}
		out = append(out, domain.FallbackTarget{GroupAliasOrID: trimmed})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func convertFallbackTargets(targets []FallbackTarget) []domain.FallbackTarget {
	if len(targets) == 0 {
		return nil
	}
	out := make([]domain.FallbackTarget, 0, len(targets))
	for _, t := range targets {
		trimmed := strings.TrimSpace(t.Target)
		if trimmed == "" {
			continue
		}
		out = append(out, domain.FallbackTarget{
			GroupAliasOrID: trimmed,
			Overrides:      maps.Clone(t.Overrides),
		})
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func toSDKChatRequest(req *domain.CanonicalChatRequest) ChatRequest {
	if req == nil {
		return ChatRequest{}
	}
	out := ChatRequest{
		Model:           req.Model,
		Temperature:     req.Temperature,
		TopP:            req.TopP,
		MaxTokens:       req.MaxTokens,
		Stop:            slices.Clone(req.Stop),
		Stream:          req.Stream,
		ReasoningEffort: req.ReasoningEffort,
		User:            req.User,
		Messages:        make([]Message, 0, len(req.Messages)),
	}
	for _, m := range req.Messages {
		sm := Message{
			Role:       m.Role,
			Content:    m.Content,
			Name:       m.Name,
			ToolCallID: m.ToolCallID,
		}
		for _, tc := range m.ToolCalls {
			sm.ToolCalls = append(sm.ToolCalls, ToolCall{
				ID:   tc.ID,
				Type: tc.Type,
				Function: FunctionCall{
					Name:      tc.Function.Name,
					Arguments: tc.Function.Arguments,
				},
			})
		}
		out.Messages = append(out.Messages, sm)
	}
	if req.GoRouteExtensions != nil {
		ext := req.GoRouteExtensions
		if ext.AllowedRegion != "" ||
			len(ext.Tags) > 0 ||
			ext.SessionID != "" ||
			ext.PreferredDeploymentID != "" ||
			ext.Priority != 0 ||
			ext.HedgeAfterMs > 0 ||
			ext.RoutingStrategy != "" ||
			ext.DropUnsupportedParams != nil {
			var dropPtr *bool
			if ext.DropUnsupportedParams != nil {
				drop := *ext.DropUnsupportedParams
				dropPtr = &drop
			}
			out.RoutingHints = &RoutingHints{
				AllowedRegion:         ext.AllowedRegion,
				Tags:                  slices.Clone(ext.Tags),
				SessionID:             ext.SessionID,
				PreferredDeploymentID: ext.PreferredDeploymentID,
				Priority:              ext.Priority,
				HedgeAfterMs:          ext.HedgeAfterMs,
				RoutingStrategy:       ext.RoutingStrategy,
				DropUnsupportedParams: dropPtr,
			}
		}
	}
	return out
}

func toDomainGoRouteExtensions(hints *RoutingHints) *domain.GoRouteExtensions {
	if hints == nil {
		return nil
	}
	var dropPtr *bool
	if hints.DropUnsupportedParams != nil {
		drop := *hints.DropUnsupportedParams
		dropPtr = &drop
	}
	return &domain.GoRouteExtensions{
		AllowedRegion:         strings.TrimSpace(hints.AllowedRegion),
		Tags:                  slices.Clone(hints.Tags),
		SessionID:             strings.TrimSpace(hints.SessionID),
		PreferredDeploymentID: strings.TrimSpace(hints.PreferredDeploymentID),
		Priority:              hints.Priority,
		HedgeAfterMs:          hints.HedgeAfterMs,
		RoutingStrategy:       strings.TrimSpace(hints.RoutingStrategy),
		DropUnsupportedParams: dropPtr,
	}
}

func populateChatResultFromHeaders(res *ChatResult, hdr http.Header) {
	if res == nil || hdr == nil {
		return
	}
	if v := strings.TrimSpace(hdr.Get("X-Gateway-Provider")); v != "" {
		res.Provider = v
	}
	if v := strings.TrimSpace(hdr.Get("X-Gateway-Model")); v != "" {
		res.Model = v
	}
	if v := strings.TrimSpace(hdr.Get("X-Gateway-Request-Id")); v != "" {
		res.RequestID = v
	}
	if v := strings.TrimSpace(hdr.Get("X-Gateway-Cache")); v != "" {
		res.CacheStatus = v
	}
	if v := strings.TrimSpace(hdr.Get("X-Gateway-Route-Reason")); v != "" {
		res.RouteReason = v
	}
	if strings.EqualFold(strings.TrimSpace(hdr.Get("X-Gateway-Fallback-Attempted")), "true") {
		res.FallbackAttempted = true
	}
	if v := strings.TrimSpace(hdr.Get("X-Gateway-Tier-Stepdowns")); v != "" {
		res.TierStepdowns = parseHeaderNonNegInt(v)
	}
	if strings.EqualFold(strings.TrimSpace(hdr.Get("X-Gateway-Stream-Continued")), "true") {
		res.StreamContinued = true
	}
	if v := strings.TrimSpace(hdr.Get("X-Gateway-Fallback-Reason")); v != "" {
		res.FallbackReason = v
	} else if (res.FallbackAttempted || res.TierStepdowns > 0) && res.RouteReason != "" {
		res.FallbackReason = res.RouteReason
	}
	if v := strings.TrimSpace(hdr.Get("X-Gateway-Cost-Micros")); v != "" {
		res.CostMicros = parseHeaderInt64(v)
	}
	if v := strings.TrimSpace(hdr.Get("X-Gateway-Routing-Micros")); v != "" {
		res.RoutingMicros = parseHeaderInt64(v)
	}
	if v := strings.TrimSpace(hdr.Get("X-Gateway-Retry-Count")); v != "" {
		res.RetryCount = parseHeaderNonNegInt(v)
	}
	if v := strings.TrimSpace(hdr.Get("X-Gateway-Dropped-Params")); v != "" {
		var dropped []string
		for _, part := range strings.Split(v, ",") {
			if p := strings.TrimSpace(part); p != "" {
				dropped = append(dropped, p)
			}
		}
		if len(dropped) > 0 {
			res.DroppedParams = dropped
		}
	}
	if v := strings.TrimSpace(hdr.Get("X-Gateway-Deployment-Id")); v != "" {
		res.WinningDeployment = v
	} else if res.WinningDeployment == "" {
		switch {
		case res.Model != "" && strings.Contains(res.Model, "/"):
			res.WinningDeployment = res.Model
		case res.Provider != "" && res.Model != "":
			res.WinningDeployment = res.Provider + "/" + res.Model
		case res.Model != "":
			res.WinningDeployment = res.Model
		case res.Provider != "":
			res.WinningDeployment = res.Provider
		}
	}
}

func parseHeaderNonNegInt(v string) int {
	n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
	if err != nil || n < 0 || n > math.MaxInt32 {
		return 0
	}
	return int(n)
}
