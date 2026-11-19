package router

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"math"
	"math/rand/v2"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/goroute-ai/ai-gateway-go/internal/adapter"
	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/health"
	"github.com/goroute-ai/ai-gateway-go/internal/logger"
	"github.com/goroute-ai/ai-gateway-go/internal/observability"
	"github.com/goroute-ai/ai-gateway-go/internal/ratelimit"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/redis/go-redis/v9"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// CircuitState represents the 3-state circuit breaker status for a deployment.
type CircuitState string

const (
	CircuitClosed    CircuitState = "closed"
	CircuitOpen      CircuitState = "open"
	CircuitHalfOpen  CircuitState = "half_open"
	maxFallbackDepth              = 16
)

type cooldownState struct {
	failures              int
	windowStart           time.Time
	cooldownUntil         time.Time
	tripped               bool
	halfOpenProbeInFlight bool
	probeToken            string
}

// ExecutionMeta captures telemetry about retries, fallbacks, TTFT, routing overhead, and the winning deployment.
type ExecutionMeta struct {
	RouteDecision     *RouteDecision
	WinningDeployment *domain.Deployment
	RetryCount        int
	FallbackAttempted bool
	TierStepdowns     int
	FallbackReason    string
	StreamContinued   bool
	LatencyMs         int64
	TTFTMs            int64
	RoutingMicros     int64
	DroppedParams     []string
	FallbackErrors    []string
}

// ReliabilityManager orchestrates Stage 1 Routing, Stage 2 Load Balancing,
// intra-group retries with full-jitter backoff, 3-state circuit breakers (Closed/Open/Half-Open),
// active health-probe awareness, and cross-provider fallback chains.
type ReliabilityManager struct {
	repo                 storage.Repository
	registry             *adapter.Registry
	intelligentRouter    *IntelligentRouter
	loadBalancer         *LoadBalancer
	vault                *auth.Vault
	rbac                 *auth.RBACEngine
	redis                *storage.RedisFabric
	healthMon            *health.Monitor
	collector            *observability.Collector
	tracer               trace.Tracer
	cfg                  config.RouterConfig
	mu                   sync.Mutex
	cooldowns            map[string]*cooldownState
	collabMu             sync.RWMutex
	plugins              []RoutingPlugin
	affinity             *AffinityStore
	depBudgets           *DeploymentBudgetTracker
	failureRates         *failureRateTracker
	scheduler            *PriorityScheduler
	priorityLimiter      *DynamicPriorityLimiter
	slotLimiter          *DeploymentSlotLimiter
	limiter              *ratelimit.Limiter
	dynamic429           bool
	fallbackQuotaChecker func(context.Context, *domain.IdentityContext, string, int) error
	filterPipeline       atomic.Pointer[FilterPipeline]
}

// NewReliabilityManager constructs the Stage 2 execution orchestrator coordinating filtering,
// priority tiers, retries, cooldown circuit breakers, hedged requests, and fallback chains.
func NewReliabilityManager(
	repo storage.Repository,
	registry *adapter.Registry,
	intelligentRouter *IntelligentRouter,
	loadBalancer *LoadBalancer,
	vault *auth.Vault,
	rbac *auth.RBACEngine,
	redisFabric *storage.RedisFabric,
	cfg config.RouterConfig,
) *ReliabilityManager {
	if cfg.DefaultMaxRetries < 0 {
		cfg.DefaultMaxRetries = 2
	}
	if cfg.BaseRetryDelay <= 0 {
		cfg.BaseRetryDelay = 25 * time.Millisecond
	}
	if cfg.MaxRetryDelay <= 0 {
		cfg.MaxRetryDelay = 1 * time.Second
	}
	if cfg.MaxHonoredRetryAfter <= 0 {
		cfg.MaxHonoredRetryAfter = 60 * time.Second
	}
	if cfg.DefaultCooldown <= 0 {
		cfg.DefaultCooldown = 60 * time.Second
	}
	if cfg.FailureWindow <= 0 {
		cfg.FailureWindow = 30 * time.Second
	}
	if cfg.FailureThreshold <= 0 {
		cfg.FailureThreshold = 3
	}
	if loadBalancer != nil {
		loadBalancer.SetLatencyTolerancePct(cfg.LatencyTolerancePct)
	}
	rm := &ReliabilityManager{
		repo:              repo,
		registry:          registry,
		intelligentRouter: intelligentRouter,
		loadBalancer:      loadBalancer,
		vault:             vault,
		rbac:              rbac,
		redis:             redisFabric,
		cfg:               cfg,
		cooldowns:         make(map[string]*cooldownState),
		failureRates:      newFailureRateTracker(redisFabric),
		slotLimiter:       NewDeploymentSlotLimiter(redisFabric, defaultDeploymentSlotTTLSec),
	}
	rm.rebuildFilterPipeline()
	return rm
}

// SetDeploymentSlotTTL configures the ZSET lease expiration TTL in seconds for per-deployment MaxParallelRequests slots.
func (rm *ReliabilityManager) SetDeploymentSlotTTL(ttlSec int) {
	if rm != nil && rm.slotLimiter != nil {
		rm.slotLimiter.SetTTL(ttlSec)
	}
}

// SetHealthMonitor attaches the active background HealthMonitor to ReliabilityManager.
func (rm *ReliabilityManager) SetHealthMonitor(hm *health.Monitor) {
	rm.healthMon = hm
	rm.rebuildFilterPipeline()
}

// SetCollector attaches the observability Collector to ReliabilityManager.
func (rm *ReliabilityManager) SetCollector(col *observability.Collector) {
	rm.collector = col
}

// SetTracer attaches an OpenTelemetry Tracer to ReliabilityManager for upstream client spans.
func (rm *ReliabilityManager) SetTracer(t trace.Tracer) {
	rm.tracer = t
}

// SetRoutingPlugins replaces the registered Stage 2 RoutingPlugins.
func (rm *ReliabilityManager) SetRoutingPlugins(plugins ...RoutingPlugin) {
	rm.collabMu.Lock()
	rm.plugins = nil
	for _, p := range plugins {
		if p != nil {
			rm.plugins = append(rm.plugins, p)
		}
	}
	rm.collabMu.Unlock()
	rm.rebuildFilterPipeline()
}

// AddRoutingPlugin appends a non-nil RoutingPlugin to Stage 2 filtering.
func (rm *ReliabilityManager) AddRoutingPlugin(p RoutingPlugin) {
	if p == nil {
		return
	}
	rm.collabMu.Lock()
	rm.plugins = append(rm.plugins, p)
	rm.collabMu.Unlock()
	rm.rebuildFilterPipeline()
}

// SetAffinityStore attaches the session/response/prompt-cache AffinityStore.
func (rm *ReliabilityManager) SetAffinityStore(a *AffinityStore) {
	rm.collabMu.Lock()
	defer rm.collabMu.Unlock()
	rm.affinity = a
}

// AffinityStore returns the configured AffinityStore, if any.
func (rm *ReliabilityManager) AffinityStore() *AffinityStore {
	if rm == nil {
		return nil
	}
	return rm.getAffinityStore()
}

// SetDeploymentBudgetTracker attaches the per-deployment/provider budget tracker.
func (rm *ReliabilityManager) SetDeploymentBudgetTracker(b *DeploymentBudgetTracker) {
	rm.collabMu.Lock()
	rm.depBudgets = b
	rm.collabMu.Unlock()
	rm.rebuildFilterPipeline()
}

// SetLimiter attaches the rate limiter and dynamic upstream 429 throttle flag.
func (rm *ReliabilityManager) SetLimiter(lim *ratelimit.Limiter, dynamic429 bool) {
	rm.collabMu.Lock()
	defer rm.collabMu.Unlock()
	rm.limiter = lim
	rm.dynamic429 = dynamic429
}

// SetFallbackQuotaChecker registers a hook that enforces per-model quota/budget rules on fallback hops.
func (rm *ReliabilityManager) SetFallbackQuotaChecker(fn func(context.Context, *domain.IdentityContext, string, int) error) {
	rm.collabMu.Lock()
	defer rm.collabMu.Unlock()
	rm.fallbackQuotaChecker = fn
}

func (rm *ReliabilityManager) authorizeFallbackHop(
	ctx context.Context,
	idCtx *domain.IdentityContext,
	fallbackAlias string,
	estTokens int,
) error {
	if idCtx == nil || strings.TrimSpace(fallbackAlias) == "" {
		return nil
	}
	if rm.rbac != nil {
		if err := rm.rbac.AuthorizeRequestedModel(idCtx, fallbackAlias); err != nil {
			return err
		}
	}
	rm.collabMu.RLock()
	checker := rm.fallbackQuotaChecker
	rm.collabMu.RUnlock()
	if checker != nil {
		if err := checker(ctx, idCtx, fallbackAlias, estTokens); err != nil {
			return err
		}
	}
	return nil
}

// SetScheduler attaches a bounded PriorityScheduler for request admission control.
func (rm *ReliabilityManager) SetScheduler(s *PriorityScheduler) {
	rm.collabMu.Lock()
	defer rm.collabMu.Unlock()
	rm.scheduler = s
}

// SetPriorityCapacityLimiter attaches a DynamicPriorityLimiter for saturation-aware
// priority capacity sharing and PTU team share enforcement.
func (rm *ReliabilityManager) SetPriorityCapacityLimiter(l *DynamicPriorityLimiter) {
	rm.collabMu.Lock()
	rm.priorityLimiter = l
	rm.collabMu.Unlock()
	rm.rebuildFilterPipeline()
}

func (rm *ReliabilityManager) rebuildFilterPipeline() {
	if rm == nil {
		return
	}
	rm.collabMu.RLock()
	plugins := make([]RoutingPlugin, len(rm.plugins))
	copy(plugins, rm.plugins)
	priorityLimiter := rm.priorityLimiter
	budgets := rm.depBudgets
	rm.collabMu.RUnlock()

	fp := NewFilterPipeline(rm.healthMon, rm.loadBalancer, rm.cfg, plugins...)
	fp.SetPriorityLimiter(priorityLimiter)
	fp.SetSlotLimiter(rm.slotLimiter)
	if budgets != nil {
		providerCaps := rm.cfg.ProviderBudgets
		fp.SetBudgetCheck(func(bCtx context.Context, bOrgID string, dep *domain.Deployment) bool {
			return budgets.IsWithinBudget(bCtx, bOrgID, dep, providerCaps)
		})
	}
	rm.filterPipeline.Store(fp)
}

func (rm *ReliabilityManager) getFilterPipeline() *FilterPipeline {
	if rm != nil {
		if fp := rm.filterPipeline.Load(); fp != nil {
			return fp
		}
		rm.rebuildFilterPipeline()
		return rm.filterPipeline.Load()
	}
	return NewFilterPipeline(nil, nil, config.RouterConfig{})
}

func (rm *ReliabilityManager) getAffinityStore() *AffinityStore {
	rm.collabMu.RLock()
	defer rm.collabMu.RUnlock()
	return rm.affinity
}

func (rm *ReliabilityManager) getScheduler() *PriorityScheduler {
	rm.collabMu.RLock()
	defer rm.collabMu.RUnlock()
	return rm.scheduler
}

func (rm *ReliabilityManager) getPriorityCapacityLimiter() *DynamicPriorityLimiter {
	rm.collabMu.RLock()
	defer rm.collabMu.RUnlock()
	return rm.priorityLimiter
}

func (rm *ReliabilityManager) acquireDynamicPriorityCapacityWithSignals(
	ctx context.Context,
	idCtx *domain.IdentityContext,
	group *domain.ModelGroup,
	req *domain.CanonicalChatRequest,
	deployments []*domain.Deployment,
	estTokens int,
	snap *SignalSnapshot,
) (func(int), error) {
	dpl := rm.getPriorityCapacityLimiter()
	if dpl == nil || !dpl.cfg.Enabled {
		return func(int) {}, nil
	}
	orgID := ""
	baseRPM, baseTPM := 0, 0
	if idCtx != nil {
		orgID = idCtx.OrgID
		baseRPM = idCtx.TeamRPMLimit
		if baseRPM <= 0 {
			baseRPM = idCtx.KeyRPMLimit
		}
		baseTPM = idCtx.TeamTPMLimit
		if baseTPM <= 0 {
			baseTPM = idCtx.KeyTPMLimit
		}
	}
	model := ""
	if group != nil {
		model = group.Alias
	}
	if model == "" && req != nil {
		model = req.Model
	}
	callerID := ResolveCallerID(idCtx)
	className, known := dpl.ResolvePriorityClassName(ctx, idCtx, req)

	var usedRPM, usedTPM, capRPM, capTPM int
	if rm.loadBalancer != nil {
		usedRPM, usedTPM, capRPM, capTPM = rm.loadBalancer.AggregateWindowUsageWithSignals(deployments, snap, time.Now())
	}
	if _, err := dpl.Admit(ctx, PriorityCapacityRequest{
		OrgID:           orgID,
		Model:           model,
		CallerID:        callerID,
		PriorityClass:   className,
		BaseRPM:         baseRPM,
		BaseTPM:         baseTPM,
		CapRPM:          capRPM,
		CapTPM:          capTPM,
		UsedRPM:         usedRPM,
		UsedTPM:         usedTPM,
		EstimatedTokens: estTokens,
		KnownClasses:    known,
	}); err != nil {
		return nil, err
	}
	return func(actualTokens int) {
		dpl.ReconcileTokens(ctx, orgID, model, callerID, estTokens, actualTokens)
	}, nil
}

func (rm *ReliabilityManager) acquireDeploymentPTU(
	ctx context.Context,
	idCtx *domain.IdentityContext,
	dep *domain.Deployment,
	estTokens int,
) (func(int), error) {
	dpl := rm.getPriorityCapacityLimiter()
	if dpl == nil || dpl.getPTURepo() == nil || idCtx == nil || idCtx.TeamID == "" || dep == nil {
		return func(int) {}, nil
	}
	res, err := dpl.AcquirePTUShare(ctx, idCtx.OrgID, dep.ID, idCtx.TeamID, estTokens)
	if err != nil {
		return nil, err
	}
	if res == nil || !res.HasShare {
		return func(int) {}, nil
	}
	return func(actualTokens int) {
		dpl.ReconcilePTUShare(ctx, idCtx.OrgID, dep.ID, idCtx.TeamID, estTokens, actualTokens)
	}, nil
}

func (rm *ReliabilityManager) tracerFor(ctx context.Context) trace.Tracer {
	if rm.tracer != nil {
		return rm.tracer
	}
	if span := trace.SpanFromContext(ctx); span.SpanContext().IsValid() {
		return span.TracerProvider().Tracer("github.com/goroute-ai/ai-gateway-go/router")
	}
	return otel.Tracer("github.com/goroute-ai/ai-gateway-go/router")
}

func (rm *ReliabilityManager) startGenAIClientSpan(ctx context.Context, operation string, dep *domain.Deployment) (context.Context, trace.Span) {
	var provider, model string
	if dep != nil && dep.GlobalModel != nil {
		provider = string(dep.GlobalModel.Provider)
		model = dep.GlobalModel.ModelName
	}
	attrs := []attribute.KeyValue{
		attribute.String("gen_ai.operation.name", operation),
	}
	if provider != "" {
		attrs = append(attrs, attribute.String("gen_ai.system", provider))
	}
	if model != "" {
		attrs = append(attrs, attribute.String("gen_ai.request.model", model))
	}
	return rm.tracerFor(ctx).Start(ctx, "gen_ai.client",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(attrs...),
	)
}

func finishGenAIClientSpan(span trace.Span, usage *domain.TokenUsage, err error) {
	if usage != nil {
		span.SetAttributes(
			attribute.Int("gen_ai.usage.input_tokens", usage.PromptTokens),
			attribute.Int("gen_ai.usage.output_tokens", usage.CompletionTokens),
			attribute.Int("gen_ai.usage.total_tokens", usage.TotalTokens),
		)
	}
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, err.Error())
	}
	span.End()
}

func withDeploymentTimeout(ctx context.Context, dep *domain.Deployment) (context.Context, context.CancelFunc) {
	if dep != nil && dep.TimeoutMs > 0 {
		return context.WithTimeout(ctx, time.Duration(dep.TimeoutMs)*time.Millisecond)
	}
	return ctx, func() {}
}

type cancelReadCloser struct {
	io.ReadCloser
	cancel    context.CancelFunc
	onClose   func()
	closeOnce sync.Once
}

func (c *cancelReadCloser) Close() error {
	err := c.ReadCloser.Close()
	c.closeOnce.Do(func() {
		if c.onClose != nil {
			c.onClose()
		}
		if c.cancel != nil {
			c.cancel()
		}
	})
	return err
}

func isBudgetConstrained(idCtx *domain.IdentityContext) bool {
	if idCtx == nil {
		return false
	}
	return idCtx.KeyMaxBudgetMicros > 0 || idCtx.TeamMaxBudgetMicros > 0 || idCtx.OrgMaxBudgetMicros > 0
}

func filterKnownPricing(deployments []*domain.Deployment) []*domain.Deployment {
	var known []*domain.Deployment
	for _, dep := range deployments {
		if dep != nil && dep.GlobalModel != nil {
			status := domain.ResolvePricingStatus(dep.GlobalModel)
			if status == domain.PricingStatusVerified || status == domain.PricingStatusCustom {
				known = append(known, dep)
			}
		}
	}
	return known
}

func filterByCapability(deployments []*domain.Deployment, check func(caps domain.ModelCapabilities) domain.CapabilityState) []*domain.Deployment {
	var candidates []*domain.Deployment
	for _, dep := range deployments {
		if dep == nil || dep.GlobalModel == nil {
			continue
		}
		caps := dep.GlobalModel.Capabilities
		if caps == (domain.ModelCapabilities{}) {
			caps = dep.GlobalModel.ResolveCapabilities()
		}
		if check(caps) != domain.CapabilityUnsupported {
			candidates = append(candidates, dep)
		}
	}
	return candidates
}

// ExecuteChat routes and executes a synchronous chat completion with automated retries and fallbacks.
func checkDeploymentOperation(adp adapter.ProviderAdapter, dep *domain.Deployment, op domain.OperationType) error {
	if opChk, ok := adp.(adapter.OperationSupportChecker); ok && !opChk.SupportsOperation(op) {
		return &domain.GatewayError{
			StatusCode: http.StatusNotImplemented,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       string(op) + "_not_supported",
			Message:    "Provider " + string(dep.GlobalModel.Provider) + " does not support " + string(op),
		}
	}
	if dep != nil && dep.GlobalModel != nil && len(dep.GlobalModel.SupportedOperations) > 0 && !dep.GlobalModel.SupportsOperation(op) {
		return &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "unsupported_operation",
			Message:    "Model " + dep.GlobalModel.ModelName + " does not support " + string(op),
		}
	}
	return nil
}

type queuedHop struct {
	group     *domain.ModelGroup
	overrides map[string]any
	reason    string
	depth     int
}

func (rm *ReliabilityManager) acquireSchedulerSlot(ctx context.Context, req *domain.CanonicalChatRequest) (func(), error) {
	sched := rm.getScheduler()
	if sched == nil {
		return func() {}, nil
	}
	reqPriority := 0
	if req != nil && req.GoRouteExtensions != nil {
		reqPriority = req.GoRouteExtensions.Priority
	}
	return sched.Acquire(ctx, reqPriority)
}

func (rm *ReliabilityManager) effectiveMaxFallbackDepth() int {
	if rm.cfg.MaxFallbackDepth > 0 {
		return rm.cfg.MaxFallbackDepth
	}
	return maxFallbackDepth
}

func extractPreviousResponseID(req *domain.CanonicalChatRequest) string {
	if req == nil {
		return ""
	}
	if req.ExtraParams != nil {
		if raw, ok := req.ExtraParams["previous_response_id"]; ok {
			if s, ok := raw.(string); ok && strings.TrimSpace(s) != "" {
				return strings.TrimSpace(s)
			}
		}
	}
	if req.Metadata != nil {
		if s := strings.TrimSpace(req.Metadata["previous_response_id"]); s != "" {
			return s
		}
	}
	return ""
}

func (rm *ReliabilityManager) affinityTTL(aff *AffinityStore) time.Duration {
	if rm.cfg.SessionAffinityTTL > 0 {
		return rm.cfg.SessionAffinityTTL
	}
	if aff != nil {
		return aff.DefaultTTL()
	}
	return 0
}

func (rm *ReliabilityManager) shouldRepinAffinity(aff *AffinityStore) bool {
	if aff != nil && aff.RepinOnFailover() {
		return true
	}
	return rm.cfg.SessionAffinityRepinOnFailover
}

func (rm *ReliabilityManager) pinAffinityOnSuccess(aff *AffinityStore, orgID, key, priorDepID, winningDepID string) {
	if aff == nil || key == "" || winningDepID == "" {
		return
	}
	if priorDepID == "" || (winningDepID != priorDepID && rm.shouldRepinAffinity(aff)) {
		aff.PinAsync(orgID, key, winningDepID, rm.affinityTTL(aff))
	}
}

func (rm *ReliabilityManager) releaseUnusedProbes(ctx context.Context, all, kept []*domain.Deployment) {
	if len(all) == 0 {
		return
	}
	keptSet := make(map[string]struct{}, len(kept))
	for _, d := range kept {
		if d != nil {
			keptSet[d.ID] = struct{}{}
		}
	}
	for _, d := range all {
		if d == nil || d.CircuitProbeToken == "" {
			continue
		}
		if _, ok := keptSet[d.ID]; !ok {
			rm.releaseHalfOpenProbe(ctx, d.ID, d.CircuitProbeToken)
			d.CircuitProbeToken = ""
		}
	}
}

func hasGroupFallbacks(group *domain.ModelGroup, defaultFallbacks []domain.FallbackTarget) bool {
	if len(defaultFallbacks) > 0 {
		return true
	}
	return group != nil && (len(group.FallbackGroupIDs) > 0 || len(group.FallbackTargets) > 0)
}

func groupMatchesTargetRef(ref string, mg *domain.ModelGroup) bool {
	if mg == nil {
		return false
	}
	ref = strings.TrimSpace(ref)
	return ref != "" && (ref == mg.ID || ref == mg.Alias)
}

func targetsContainGroup(targets []domain.FallbackTarget, mg *domain.ModelGroup) bool {
	for _, t := range targets {
		if groupMatchesTargetRef(t.GroupAliasOrID, mg) {
			return true
		}
	}
	return false
}

func idsContainGroup(ids []string, mg *domain.ModelGroup) bool {
	for _, id := range ids {
		if groupMatchesTargetRef(id, mg) {
			return true
		}
	}
	return false
}

func isDirectFallbackTarget(parent, child *domain.ModelGroup, defaultFallbacks []domain.FallbackTarget) bool {
	if parent == nil || child == nil {
		return false
	}
	return targetsContainGroup(parent.ContextWindowFallbacks, child) ||
		targetsContainGroup(parent.ContentPolicyFallbacks, child) ||
		targetsContainGroup(parent.SaturationFallbacks, child) ||
		targetsContainGroup(parent.FallbackTargets, child) ||
		idsContainGroup(parent.FallbackGroupIDs, child) ||
		targetsContainGroup(defaultFallbacks, child)
}

func fallbackReasonForHop(parent *domain.ModelGroup, hop FallbackHop, defaultFallbacks []domain.FallbackTarget) string {
	if hop.Category == CategoryContextWindow && parent != nil && len(parent.ContextWindowFallbacks) > 0 {
		return "context_window_fallback"
	}
	if hop.Category == CategoryContentPolicy && parent != nil && len(parent.ContentPolicyFallbacks) > 0 {
		return "content_policy_fallback"
	}
	if hop.Category == CategorySaturation && parent != nil && len(parent.SaturationFallbacks) > 0 {
		return "saturation_fallback"
	}
	if parent != nil && (targetsContainGroup(parent.FallbackTargets, hop.Group) || idsContainGroup(parent.FallbackGroupIDs, hop.Group)) {
		return "fallback_group"
	}
	if targetsContainGroup(defaultFallbacks, hop.Group) {
		return "default_fallback"
	}
	return "fallback_group"
}

func (rm *ReliabilityManager) isCooldownDisabled(group *domain.ModelGroup) bool {
	if rm != nil && rm.cfg.DisableCooldowns {
		return true
	}
	return group != nil && group.DisableCooldowns
}

func isPrioritySaturationErr(err error) bool {
	var gwErr *domain.GatewayError
	if !errors.As(err, &gwErr) || gwErr == nil {
		return false
	}
	return gwErr.StatusCode == http.StatusTooManyRequests &&
		(gwErr.Code == "priority_capacity_exceeded" || strings.Contains(gwErr.Code, "saturat"))
}

func saturationGatewayError() *domain.GatewayError {
	return &domain.GatewayError{
		StatusCode:    http.StatusTooManyRequests,
		Type:          domain.ErrorTypeRateLimit,
		Code:          "deployment_capacity_saturated",
		Message:       "All deployments in this model group have reached configured capacity or MaxParallelRequests limits",
		RetryAfterSec: 1,
		Retryable:     true,
	}
}

func setFallbackMetaReason(meta *ExecutionMeta, reason string) {
	if meta == nil || reason == "" {
		return
	}
	if meta.FallbackReason == "priority_tier_stepdown" && reason == "fallback_group" {
		return
	}
	meta.FallbackReason = reason
}

const maxRecordedFallbackErrors = 10

func appendFallbackError(meta *ExecutionMeta, groupAlias, depID string, err error) {
	if meta == nil || err == nil || len(meta.FallbackErrors) >= maxRecordedFallbackErrors {
		return
	}
	meta.FallbackErrors = append(meta.FallbackErrors, formatRedactedFallbackError(groupAlias, depID, err))
}

func (rm *ReliabilityManager) classifyErr(err error) FailureCategory {
	return classifyFailureCategoryWithOptions(err, rm != nil && rm.cfg.FallbackOnUnsupportedParams)
}

func (rm *ReliabilityManager) enqueueFallbacks(
	ctx context.Context,
	queue []queuedHop,
	current queuedHop,
	cat FailureCategory,
	maxDepth int,
	visited map[string]struct{},
) []queuedHop {
	if cat == CategoryNonRetryable || current.group == nil || current.depth >= maxDepth {
		return queue
	}
	var defaultFB []domain.FallbackTarget
	if current.depth == 0 {
		defaultFB = rm.cfg.DefaultFallbacks
	}
	hops := buildSpecializedFallbackChain(ctx, rm.repo, current.group, cat, defaultFB, maxDepth-current.depth, visited)
	if len(hops) == 0 {
		return queue
	}
	added := make([]queuedHop, 0, len(hops))
	for _, hop := range hops {
		hopDepth := current.depth + 2
		if isDirectFallbackTarget(current.group, hop.Group, defaultFB) {
			hopDepth = current.depth + 1
		}
		if hopDepth > maxDepth {
			hopDepth = maxDepth
		}
		added = append(added, queuedHop{
			group:     hop.Group,
			overrides: hop.Overrides,
			reason:    fallbackReasonForHop(current.group, hop, defaultFB),
			depth:     hopDepth,
		})
	}
	return append(added, queue...)
}

func filterOutDepIDs(all []*domain.Deployment, excluded map[string]struct{}) []*domain.Deployment {
	if len(excluded) == 0 {
		return all
	}
	var out []*domain.Deployment
	for _, d := range all {
		if _, skip := excluded[d.ID]; !skip {
			out = append(out, d)
		}
	}
	return out
}

func isZeroRetryPolicy(p domain.RetryPolicy) bool {
	return p == (domain.RetryPolicy{})
}

func (rm *ReliabilityManager) effectiveGroupRetryPolicy(group *domain.ModelGroup) domain.RetryPolicy {
	if (group == nil || group.RetryPolicy == nil) && isZeroRetryPolicy(rm.cfg.RetryPolicy) {
		maxRetries := 0
		if group != nil && group.MaxRetries > 0 {
			maxRetries = group.MaxRetries
		}
		cfgCopy := rm.cfg
		cfgCopy.DefaultMaxRetries = maxRetries
		return effectiveRetryPolicy(cfgCopy, group)
	}
	return effectiveRetryPolicy(rm.cfg, group)
}

func shouldHedgeGroup(group *domain.ModelGroup, req *domain.CanonicalChatRequest) bool {
	if group != nil && domain.NormalizeRoutingStrategy(group.RoutingStrategy) == domain.StrategyFastestResponse {
		return true
	}
	return req != nil && req.GoRouteExtensions != nil && req.GoRouteExtensions.HedgeAfterMs > 0
}

func (rm *ReliabilityManager) buildHedgeConfig(req *domain.CanonicalChatRequest) HedgeConfig {
	stagger := time.Duration(rm.cfg.HedgeDelayMs) * time.Millisecond
	if req != nil && req.GoRouteExtensions != nil && req.GoRouteExtensions.HedgeAfterMs > 0 {
		stagger = time.Duration(req.GoRouteExtensions.HedgeAfterMs) * time.Millisecond
	}
	if stagger < 0 {
		stagger = 0
	}
	return HedgeConfig{
		MaxConcurrency: rm.cfg.MaxHedgeConcurrency,
		StaggerDelay:   stagger,
	}
}

func prioritizeAffinityCandidate(candidates []*domain.Deployment, aff *AffinityStore, affinityDepID string) []*domain.Deployment {
	if aff == nil || affinityDepID == "" || len(candidates) <= 1 {
		return candidates
	}
	pinned, ok := aff.SelectOrPin(affinityDepID, candidates)
	if !ok || pinned == nil || candidates[0].ID == pinned.ID {
		return candidates
	}
	ordered := make([]*domain.Deployment, 0, len(candidates))
	ordered = append(ordered, pinned)
	for _, d := range candidates {
		if d != nil && d.ID != pinned.ID {
			ordered = append(ordered, d)
		}
	}
	return ordered
}

func isBanditRefusalResponse(resp *domain.CanonicalChatResponse) bool {
	if resp == nil {
		return false
	}
	for _, ch := range resp.Choices {
		reason := strings.ToLower(strings.TrimSpace(ch.FinishReason))
		if reason == "content_filter" || reason == "refusal" {
			return true
		}
	}
	return false
}

func (rm *ReliabilityManager) recordBanditOutcome(orgID string, decision *RouteDecision, success bool, latencyMs int64) {
	if decision == nil || decision.BanditBucket == "" || rm.intelligentRouter == nil {
		return
	}
	bandit := rm.intelligentRouter.Bandit()
	if bandit == nil {
		return
	}
	alias := strings.TrimSpace(decision.TargetGroupAlias)
	if alias == "" && decision.ModelGroup != nil {
		alias = decision.ModelGroup.Alias
	}
	if alias == "" {
		return
	}
	bandit.RecordOutcome(orgID, decision.BanditBucket, alias, success, latencyMs, false)
}

type commaGroupCandidatePool struct {
	groups        []*domain.ModelGroup
	candidates    []*domain.Deployment
	groupByDep    map[string]*domain.ModelGroup
	activeByGroup map[string]int
	skippedBudget bool
	lastErr       error
}

func (rm *ReliabilityManager) resolveCommaSeparatedCandidates(
	ctx context.Context,
	orgID string,
	req *domain.CanonicalChatRequest,
	aliases []string,
	estTokens int,
	isBudgeted bool,
	requirePrefill bool,
) (*commaGroupCandidatePool, error) {
	pool := &commaGroupCandidatePool{
		groupByDep:    make(map[string]*domain.ModelGroup),
		activeByGroup: make(map[string]int),
	}
	perGroup := make([][]*domain.Deployment, 0, len(aliases))
	seenDep := make(map[string]struct{})
	var firstResolveErr error

	for _, alias := range aliases {
		aliasReq := *req
		aliasReq.Model = alias
		dec, err := rm.intelligentRouter.ResolveGroup(ctx, orgID, &aliasReq)
		if err != nil {
			if firstResolveErr == nil {
				firstResolveErr = err
			}
			continue
		}
		if dec == nil || dec.ModelGroup == nil {
			continue
		}
		g := dec.ModelGroup
		pool.groups = append(pool.groups, g)
		deps, activeTotal, filterErr := rm.getEligibleDeploymentsForRequest(ctx, orgID, g, req, estTokens, nil, requirePrefill)
		pool.activeByGroup[g.ID] = activeTotal
		if filterErr != nil {
			pool.lastErr = filterErr
			if rm.classifyErr(filterErr) == CategoryNonRetryable {
				return nil, filterErr
			}
			continue
		}
		if isBudgeted && len(deps) > 0 {
			filtered := filterKnownPricing(deps)
			rm.releaseUnusedProbes(ctx, deps, filtered)
			if len(filtered) == 0 {
				pool.skippedBudget = true
				continue
			}
			deps = filtered
		}
		if len(deps) > 0 {
			perGroup = append(perGroup, deps)
		}
	}

	if len(pool.groups) == 0 {
		if firstResolveErr != nil {
			return nil, firstResolveErr
		}
		return nil, &domain.GatewayError{
			StatusCode: http.StatusNotFound,
			Type:       domain.ErrorTypeNotFound,
			Code:       "model_group_not_found",
			Message:    "No active model group configured for model or alias: " + req.Model,
		}
	}

	// Interleave candidates round-robin across resolved groups so K racers span distinct model aliases first.
	maxLen := 0
	for _, list := range perGroup {
		if len(list) > maxLen {
			maxLen = len(list)
		}
	}
	for idx := 0; idx < maxLen; idx++ {
		for gIdx, list := range perGroup {
			if idx >= len(list) {
				continue
			}
			d := list[idx]
			if d == nil {
				continue
			}
			if _, dup := seenDep[d.ID]; dup {
				continue
			}
			seenDep[d.ID] = struct{}{}
			pool.candidates = append(pool.candidates, d)
			// Find matching group by ModelGroupID fallback if needed.
			for _, g := range pool.groups {
				if g.ID == d.ModelGroupID {
					pool.groupByDep[d.ID] = g
					break
				}
			}
			if pool.groupByDep[d.ID] == nil && gIdx < len(pool.groups) {
				pool.groupByDep[d.ID] = pool.groups[gIdx]
			}
		}
	}

	return pool, nil
}

func (rm *ReliabilityManager) buildGroupChain(ctx context.Context, primary *domain.ModelGroup) []*domain.ModelGroup {
	if primary == nil {
		return nil
	}
	chain := []*domain.ModelGroup{primary}
	visited := map[string]struct{}{primary.ID: {}}
	var visit func(*domain.ModelGroup, int)
	visit = func(current *domain.ModelGroup, depth int) {
		if depth >= maxFallbackDepth {
			return
		}
		for _, fallbackID := range current.FallbackGroupIDs {
			fbGroup, err := rm.repo.GetModelGroupByID(ctx, fallbackID)
			if err != nil || fbGroup == nil {
				fbGroup, err = rm.repo.GetModelGroupByAlias(ctx, primary.OrgID, fallbackID)
			}
			if err != nil || fbGroup == nil || !fbGroup.IsActive || fbGroup.OrgID != primary.OrgID {
				continue
			}
			if _, ok := visited[fbGroup.ID]; ok {
				continue
			}
			visited[fbGroup.ID] = struct{}{}
			chain = append(chain, fbGroup)
			visit(fbGroup, depth+1)
		}
	}
	visit(primary, 0)
	return chain
}

func (rm *ReliabilityManager) getHealthyDeployments(ctx context.Context, orgID string, group *domain.ModelGroup) ([]*domain.Deployment, error) {
	all, err := rm.repo.ListDeploymentsByGroup(ctx, group.ID)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	eligible := make([]*domain.Deployment, 0, len(all))
	for _, d := range all {
		if d.Status != domain.DeploymentStatusActive || d.GlobalModel == nil {
			continue
		}
		// Credential lifecycle check: exclude deactivated or expired credentials
		if d.Credential != nil {
			if !d.Credential.IsActive {
				continue
			}
			if d.Credential.ExpiresAt != nil && !now.Before(*d.Credential.ExpiresAt) {
				continue
			}
		}
		// Active background health monitor check
		if rm.healthMon != nil && !rm.healthMon.IsHealthyWithMaxAge(d.ID, rm.cfg.HealthStalenessThreshold) {
			continue
		}
		if rm.rbac != nil && orgID != "" {
			if err := rm.rbac.AuthorizeDeployment(ctx, orgID, d); err != nil {
				continue
			}
		}
		eligible = append(eligible, d)
	}
	return rm.admitThroughCircuitBreakerForGroup(ctx, group, eligible), nil
}

func (rm *ReliabilityManager) getEligibleDeploymentsForRequest(
	ctx context.Context,
	orgID string,
	group *domain.ModelGroup,
	req *domain.CanonicalChatRequest,
	estTokens int,
	excludeDepIDs map[string]struct{},
	requirePrefill bool,
) ([]*domain.Deployment, int, error) {
	eligible, activeTotal, _, err := rm.getEligibleDeploymentsForRequestWithSignals(ctx, orgID, group, req, estTokens, excludeDepIDs, requirePrefill)
	return eligible, activeTotal, err
}

func (rm *ReliabilityManager) getEligibleDeploymentsForRequestWithSignals(
	ctx context.Context,
	orgID string,
	group *domain.ModelGroup,
	req *domain.CanonicalChatRequest,
	estTokens int,
	excludeDepIDs map[string]struct{},
	requirePrefill bool,
) ([]*domain.Deployment, int, *SignalSnapshot, error) {
	eligible, activeTotal, snap, _, err := rm.getEligibleDeploymentsDetailed(ctx, orgID, group, req, estTokens, excludeDepIDs, requirePrefill, 0, nil)
	return eligible, activeTotal, snap, err
}

func requestPriorityRank(idCtx *domain.IdentityContext, req *domain.CanonicalChatRequest) int {
	rank := 0
	if req != nil && req.GoRouteExtensions != nil && req.GoRouteExtensions.Priority > rank {
		rank = req.GoRouteExtensions.Priority
	}
	if idCtx != nil {
		if idCtx.KeyMinPriorityRank > rank {
			rank = idCtx.KeyMinPriorityRank
		}
		if idCtx.TeamMinPriorityRank > rank {
			rank = idCtx.TeamMinPriorityRank
		}
	}
	return rank
}

func (rm *ReliabilityManager) getEligibleDeploymentsDetailed(
	ctx context.Context,
	orgID string,
	group *domain.ModelGroup,
	req *domain.CanonicalChatRequest,
	estTokens int,
	excludeDepIDs map[string]struct{},
	requirePrefill bool,
	priorityRank int,
	preStageFilter func([]*domain.Deployment) []*domain.Deployment,
) ([]*domain.Deployment, int, *SignalSnapshot, bool, error) {
	if group == nil {
		return nil, 0, nil, false, nil
	}
	all, err := rm.repo.ListDeploymentsByGroup(ctx, group.ID)
	if err != nil {
		return nil, 0, nil, false, err
	}

	activeTotal := 0
	authorized := make([]*domain.Deployment, 0, len(all))
	for _, d := range all {
		if d == nil {
			continue
		}
		if d.Status == domain.DeploymentStatusActive && d.GlobalModel != nil {
			activeTotal++
		}
		if len(excludeDepIDs) > 0 {
			if _, excluded := excludeDepIDs[d.ID]; excluded {
				continue
			}
		}
		if rm.rbac != nil && orgID != "" {
			if err := rm.rbac.AuthorizeDeployment(ctx, orgID, d); err != nil {
				continue
			}
		}
		authorized = append(authorized, d)
	}
	if preStageFilter != nil && len(authorized) > 0 {
		authorized = preStageFilter(authorized)
	}
	if len(authorized) == 0 {
		return nil, activeTotal, nil, false, nil
	}

	var snap *SignalSnapshot
	if rm.loadBalancer != nil {
		snap = rm.loadBalancer.SnapshotSignals(authorized)
	}
	fp := rm.getFilterPipeline()
	eligible, saturated, err := fp.FilterEligibleDeploymentsForGroup(ctx, orgID, group.Alias, group.DropUnsupportedParams, req, authorized, estTokens, snap)
	if err != nil {
		return nil, activeTotal, snap, saturated, err
	}
	if len(eligible) == 0 && saturated && rm.slotLimiter != nil && rm.cfg.Scheduler.MaxParallelWaitMs > 0 && hasParallelLimits(authorized) {
		waitDur := time.Duration(rm.cfg.Scheduler.MaxParallelWaitMs) * time.Millisecond
		if rm.slotLimiter.WaitForAnySlot(ctx, authorized, priorityRank, waitDur) {
			if rm.loadBalancer != nil {
				snap = rm.loadBalancer.SnapshotSignals(authorized)
			}
			eligible, saturated, err = fp.FilterEligibleDeploymentsForGroup(ctx, orgID, group.Alias, group.DropUnsupportedParams, req, authorized, estTokens, snap)
			if err != nil {
				return nil, activeTotal, snap, saturated, err
			}
		}
	}
	if len(eligible) == 0 {
		return nil, activeTotal, snap, saturated, nil
	}

	if requirePrefill {
		prefillEligible := make([]*domain.Deployment, 0, len(eligible))
		for _, d := range eligible {
			if d.GlobalModel == nil || rm.registry == nil {
				continue
			}
			adp, adpErr := rm.registry.Get(d.GlobalModel.Provider)
			if adpErr != nil || !adapter.SupportsAssistantPrefill(adp) {
				continue
			}
			prefillEligible = append(prefillEligible, d)
		}
		eligible = prefillEligible
		if len(eligible) == 0 {
			return nil, activeTotal, snap, false, nil
		}
	}

	admitted := rm.admitThroughCircuitBreakerForGroup(ctx, group, eligible)
	return admitted, activeTotal, snap, false, nil
}

func (rm *ReliabilityManager) admitThroughCircuitBreakerForGroup(ctx context.Context, group *domain.ModelGroup, candidates []*domain.Deployment) []*domain.Deployment {
	if rm.isCooldownDisabled(group) {
		return candidates
	}
	return rm.admitThroughCircuitBreaker(ctx, candidates)
}

func (rm *ReliabilityManager) acquireDeploymentSlot(ctx context.Context, dep *domain.Deployment, priorityRank int, allowWait bool) (func(), bool) {
	if dep == nil || dep.MaxParallelRequests <= 0 || rm.slotLimiter == nil {
		return func() {}, true
	}
	if allowWait && rm.cfg.Scheduler.MaxParallelWaitMs > 0 {
		return rm.slotLimiter.AcquireWithWait(ctx, dep.ID, dep.MaxParallelRequests, priorityRank, time.Duration(rm.cfg.Scheduler.MaxParallelWaitMs)*time.Millisecond)
	}
	return rm.slotLimiter.AcquireDeploymentSlot(ctx, dep.ID, dep.MaxParallelRequests)
}

func (rm *ReliabilityManager) admitThroughCircuitBreaker(ctx context.Context, candidates []*domain.Deployment) []*domain.Deployment {
	if len(candidates) == 0 {
		return nil
	}
	var healthy []*domain.Deployment
	var probes []*domain.Deployment
	for _, d := range candidates {
		// 3-State Circuit Breaker check (CLOSED -> allowed, OPEN -> blocked, HALF_OPEN -> admits 1 trial request)
		allowed, probeToken := rm.allowDeploymentRequest(ctx, d.ID)
		if !allowed {
			continue
		}
		d.CircuitProbeToken = probeToken
		if probeToken != "" {
			probes = append(probes, d)
			continue
		}
		healthy = append(healthy, d)
	}
	if len(healthy) > 0 {
		for _, p := range probes {
			rm.releaseHalfOpenProbe(ctx, p.ID, p.CircuitProbeToken)
			p.CircuitProbeToken = ""
		}
		return healthy
	}
	if len(probes) > 0 {
		for _, p := range probes[1:] {
			rm.releaseHalfOpenProbe(ctx, p.ID, p.CircuitProbeToken)
			p.CircuitProbeToken = ""
		}
		return probes[:1]
	}
	return nil
}

func (rm *ReliabilityManager) hydrateCredential(dep *domain.Deployment) {
	if dep != nil && dep.Credential != nil && rm.vault != nil {
		if dec, err := rm.vault.DecryptCredential(dep.Credential); err == nil {
			dep.Credential.DecryptedAPIKey = dec
		}
	}
}

// GetCircuitState returns the 3-state circuit breaker status (Closed, Open, or Half-Open) for a deployment.
func (rm *ReliabilityManager) GetCircuitState(ctx context.Context, depID string) CircuitState {
	if rm.redis != nil && rm.redis.Client() != nil {
		res, err := rm.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
			state, err := rdb.Get(ctx, circuitStateKey(depID)).Result()
			if err == redis.Nil {
				return CircuitClosed, nil
			}
			if err != nil {
				return nil, err
			}
			if state != "open" {
				return CircuitClosed, nil
			}
			open, err := rdb.Exists(ctx, circuitCooldownKey(depID)).Result()
			if err != nil {
				return nil, err
			}
			if open > 0 {
				return CircuitOpen, nil
			}
			return CircuitHalfOpen, nil
		})
		if err == nil {
			if state, ok := res.(CircuitState); ok {
				return state
			}
		}
	}

	rm.mu.Lock()
	defer rm.mu.Unlock()
	st, ok := rm.cooldowns[depID]
	if !ok || !st.tripped {
		return CircuitClosed
	}
	if time.Now().Before(st.cooldownUntil) {
		return CircuitOpen
	}
	return CircuitHalfOpen
}

// IsInCooldown checks whether a deployment is currently in circuit-breaker OPEN state.
func (rm *ReliabilityManager) IsInCooldown(ctx context.Context, depID string) bool {
	return rm.GetCircuitState(ctx, depID) == CircuitOpen
}

// allowDeploymentRequest implements the 3-state circuit breaker admission logic:
// - CLOSED: allowed
// - OPEN: blocked
// - HALF_OPEN: admits exactly 1 trial recovery probe; blocks concurrent callers until the probe resolves.
func (rm *ReliabilityManager) allowDeploymentRequest(ctx context.Context, depID string) (bool, string) {
	if rm.redis != nil && rm.redis.Client() != nil {
		token := uuid.NewString()
		res, err := rm.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
			return allowCircuitProbeScript.Run(ctx, rdb, circuitKeys(depID), token, circuitProbeLeaseTTL.Milliseconds()).Int64()
		})
		if err == nil {
			if code, ok := res.(int64); ok {
				return code == 1 || code == 2, tokenIfProbe(code, token)
			}
		}
	}

	rm.mu.Lock()
	defer rm.mu.Unlock()
	st, ok := rm.cooldowns[depID]
	if !ok || !st.tripped {
		return true, ""
	}
	if time.Now().Before(st.cooldownUntil) {
		return false, ""
	}
	// Cooldown elapsed -> Circuit is HALF_OPEN; allow a single recovery probe
	if st.halfOpenProbeInFlight {
		return false, ""
	}
	st.halfOpenProbeInFlight = true
	st.probeToken = uuid.NewString()
	logger.InfoContext(ctx, "Circuit breaker entering HALF_OPEN probe state",
		slog.String("component", "circuit_breaker"),
		slog.String("deployment_id", depID),
	)
	return true, st.probeToken
}

type attemptErrorOutcome struct {
	terminalErr   error
	normalizedErr error
	stopTier      bool
	stopGroup     bool
	tripped       bool
}

func (rm *ReliabilityManager) handleAttemptErrorWithPolicy(
	ctx context.Context,
	dep *domain.Deployment,
	group *domain.ModelGroup,
	activeTotal int,
	err error,
	retryTracker *retryBudgetTracker,
	attempt int,
	hasUntriedSibling bool,
) attemptErrorOutcome {
	if errors.Is(err, context.Canceled) || errors.Is(ctx.Err(), context.Canceled) {
		return attemptErrorOutcome{terminalErr: err, normalizedErr: err, stopTier: true, stopGroup: true}
	}

	var gwErr *domain.GatewayError
	if !errors.As(err, &gwErr) {
		gwErr = &domain.GatewayError{
			StatusCode: http.StatusBadGateway,
			Type:       domain.ErrorTypeUpstream,
			Code:       "upstream_transport_error",
			Message:    err.Error(),
			Retryable:  true,
		}
	}

	cat := rm.classifyErr(gwErr)
	if cat == CategoryUnsupportedParam {
		if hasUntriedSibling {
			return attemptErrorOutcome{normalizedErr: gwErr, tripped: true}
		}
		return attemptErrorOutcome{normalizedErr: gwErr, stopTier: true, stopGroup: true}
	}
	if cat == CategoryNonRetryable {
		if isLocalGuardrailError(gwErr, true, strings.ToLower(strings.TrimSpace(gwErr.Code)), strings.ToLower(gwErr.Error())) {
			return attemptErrorOutcome{terminalErr: gwErr, normalizedErr: gwErr, stopTier: true, stopGroup: true}
		}
		if retryTracker == nil || !retryTracker.consumeErr(gwErr) {
			return attemptErrorOutcome{terminalErr: gwErr, normalizedErr: gwErr, stopTier: true, stopGroup: true}
		}
		if !hasUntriedSibling {
			sleepDur := CalculateBackoffWithMaxRetryAfter(attempt, gwErr.RetryAfterSec, rm.cfg.BaseRetryDelay, rm.cfg.MaxRetryDelay, rm.cfg.MaxHonoredRetryAfter)
			if sleepDur > 0 {
				timer := time.NewTimer(sleepDur)
				select {
				case <-ctx.Done():
					timer.Stop()
					return attemptErrorOutcome{terminalErr: ctx.Err(), normalizedErr: ctx.Err(), stopTier: true, stopGroup: true}
				case <-timer.C:
				}
			}
		}
		return attemptErrorOutcome{normalizedErr: gwErr}
	}

	if cat == CategoryContextWindow || cat == CategoryContentPolicy {
		return attemptErrorOutcome{normalizedErr: gwErr, stopTier: true, stopGroup: true}
	}

	tripped := rm.recordAttemptFailure(ctx, dep, group, activeTotal, gwErr)

	if gwErr.AuthFailure || cat == CategoryAuth {
		if retryTracker == nil || !retryTracker.consumeErr(gwErr) {
			return attemptErrorOutcome{normalizedErr: gwErr, stopTier: true, tripped: tripped}
		}
		return attemptErrorOutcome{normalizedErr: gwErr, tripped: tripped}
	}

	if retryTracker == nil || !retryTracker.consumeErr(gwErr) {
		return attemptErrorOutcome{normalizedErr: gwErr, stopTier: true, tripped: tripped}
	}

	// Zero-delay failover to an untried healthy sibling; sleep only when retrying the same deployment or none remain.
	if !hasUntriedSibling {
		sleepDur := CalculateBackoffWithMaxRetryAfter(attempt, gwErr.RetryAfterSec, rm.cfg.BaseRetryDelay, rm.cfg.MaxRetryDelay, rm.cfg.MaxHonoredRetryAfter)
		if sleepDur > 0 {
			timer := time.NewTimer(sleepDur)
			select {
			case <-ctx.Done():
				timer.Stop()
				return attemptErrorOutcome{terminalErr: ctx.Err(), normalizedErr: ctx.Err(), stopTier: true, stopGroup: true, tripped: tripped}
			case <-timer.C:
			}
		}
	}
	return attemptErrorOutcome{normalizedErr: gwErr, tripped: tripped}
}

func (rm *ReliabilityManager) recordAttemptFailure(
	ctx context.Context,
	dep *domain.Deployment,
	group *domain.ModelGroup,
	activeTotal int,
	err error,
) bool {
	if dep == nil || err == nil {
		return false
	}
	var gwErr *domain.GatewayError
	if !errors.As(err, &gwErr) {
		gwErr = &domain.GatewayError{
			StatusCode: http.StatusBadGateway,
			Type:       domain.ErrorTypeUpstream,
			Code:       "upstream_transport_error",
			Message:    err.Error(),
			Retryable:  true,
		}
	}

	cat := rm.classifyErr(gwErr)
	if rm.isCooldownDisabled(group) || cat == CategoryNonRetryable || cat == CategoryContextWindow || cat == CategoryContentPolicy || cat == CategoryUnsupportedParam {
		if dep.CircuitProbeToken != "" {
			rm.releaseHalfOpenProbe(ctx, dep.ID, dep.CircuitProbeToken)
			dep.CircuitProbeToken = ""
		}
		return false
	}

	var groupCooldownSec, groupThreshold int
	if group != nil {
		groupCooldownSec = group.CooldownSeconds
		groupThreshold = group.FailureThreshold
	}
	baseThreshold := groupThreshold
	if baseThreshold <= 0 {
		baseThreshold = rm.cfg.FailureThreshold
	}
	if baseThreshold <= 0 {
		baseThreshold = defaultFailureThreshold
	}

	cooldownPolicy := effectiveCooldownPolicy(rm.cfg, group)
	errClass := errorRetryClass(gwErr, activeTotal)
	cooldownDur := effectiveCooldownDuration(cooldownPolicy, groupCooldownSec, rm.cfg.DefaultCooldown, gwErr.RetryAfterSec)

	if gwErr.StatusCode == http.StatusTooManyRequests {
		rm.collabMu.RLock()
		lim := rm.limiter
		dyn429 := rm.dynamic429
		rm.collabMu.RUnlock()
		if dyn429 && lim != nil {
			if idCtx := auth.IdentityFromContext(ctx); idCtx != nil && (idCtx.OrgID != "" || idCtx.VirtualKeyID != "") {
				throttleDur := cooldownDur
				if gwErr.RetryAfterSec > 0 {
					throttleDur = time.Duration(gwErr.RetryAfterSec) * time.Second
				}
				if throttleDur <= 0 {
					throttleDur = 30 * time.Second
				}
				lim.MarkUpstream429Throttle(ctx, idCtx.OrgID, idCtx.VirtualKeyID, throttleDur)
			}
		}
	}

	var reqs, fails int
	if rm.failureRates != nil {
		reqs, fails = rm.failureRates.record(ctx, dep.ID, true)
	}

	if gwErr.AuthFailure || errClass == retryClassAuth {
		threshold := allowedFailsForClass(cooldownPolicy, baseThreshold, retryClassAuth)
		if threshold <= 1 {
			rm.tripCooldownDuration(ctx, dep.ID, cooldownDur)
			return true
		}
		return rm.recordFailureWithDuration(ctx, dep, threshold, cooldownDur)
	}

	hasFallbacks := hasGroupFallbacks(group, rm.cfg.DefaultFallbacks)
	rateProtected := isLoneDeploymentProtected(group, activeTotal, hasFallbacks, cooldownClassFailRate, cooldownPolicy)
	if !rateProtected && shouldTripByFailureRate(cooldownPolicy, reqs, fails) {
		rm.tripCooldownDuration(ctx, dep.ID, cooldownDur)
		return true
	}

	if isLoneDeploymentProtected(group, activeTotal, hasFallbacks, errClass, cooldownPolicy) {
		if dep.CircuitProbeToken != "" {
			rm.releaseHalfOpenProbe(ctx, dep.ID, dep.CircuitProbeToken)
			dep.CircuitProbeToken = ""
		}
		return false
	}

	threshold := allowedFailsForClass(cooldownPolicy, baseThreshold, errClass)
	return rm.recordFailureWithDuration(ctx, dep, threshold, cooldownDur)
}

func (rm *ReliabilityManager) recordFailure(ctx context.Context, dep *domain.Deployment, threshold, cooldownSec int) {
	if cooldownSec <= 0 {
		cooldownSec = int(rm.cfg.DefaultCooldown.Seconds())
	}
	if cooldownSec <= 0 {
		cooldownSec = 30
	}
	rm.recordFailureWithDuration(ctx, dep, threshold, time.Duration(cooldownSec)*time.Second)
}

func (rm *ReliabilityManager) recordFailureWithDuration(ctx context.Context, dep *domain.Deployment, threshold int, cooldownDur time.Duration) bool {
	if dep == nil {
		return false
	}
	depID := dep.ID
	if threshold <= 0 {
		threshold = rm.cfg.FailureThreshold
	}
	if threshold <= 0 {
		threshold = 3
	}
	if cooldownDur <= 0 {
		cooldownDur = rm.cfg.DefaultCooldown
	}
	if cooldownDur <= 0 {
		cooldownDur = 30 * time.Second
	}
	windowMs := rm.cfg.FailureWindow.Milliseconds()
	if windowMs <= 0 {
		windowMs = 60_000
	}

	if rm.redis != nil && rm.redis.Client() != nil {
		res, err := rm.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
			return recordCircuitFailureScript.Run(ctx, rdb, circuitKeys(depID), threshold, windowMs, cooldownDur.Milliseconds(), dep.CircuitProbeToken).Int64()
		})
		if err == nil {
			if code, ok := res.(int64); ok {
				if code == 1 || code == 2 {
					now := time.Now()
					rm.mu.Lock()
					st, ok := rm.cooldowns[depID]
					if !ok {
						st = &cooldownState{windowStart: now}
						rm.cooldowns[depID] = st
					}
					st.tripped = true
					st.halfOpenProbeInFlight = false
					st.probeToken = ""
					st.cooldownUntil = now.Add(cooldownDur)
					rm.mu.Unlock()
					logger.ErrorContext(ctx, "Circuit breaker tripped to OPEN",
						slog.String("component", "circuit_breaker"),
						slog.String("deployment_id", depID),
						slog.Duration("cooldown", cooldownDur),
					)
					return true
				}
				return false
			}
		}
	}

	now := time.Now()
	rm.mu.Lock()
	st, ok := rm.cooldowns[depID]
	// If failing during a HALF_OPEN probe, immediately re-trip to OPEN
	if ok && st.tripped && !now.Before(st.cooldownUntil) && dep.CircuitProbeToken != "" && st.probeToken == dep.CircuitProbeToken {
		st.halfOpenProbeInFlight = false
		st.probeToken = ""
		st.cooldownUntil = now.Add(cooldownDur)
		rm.mu.Unlock()
		rm.tripCooldownDuration(ctx, depID, cooldownDur)
		return true
	}
	if !ok || now.Sub(st.windowStart) > time.Duration(windowMs)*time.Millisecond {
		st = &cooldownState{windowStart: now}
		rm.cooldowns[depID] = st
	}
	st.failures++
	shouldTrip := st.failures >= threshold
	if shouldTrip {
		st.tripped = true
		st.halfOpenProbeInFlight = false
		st.cooldownUntil = now.Add(cooldownDur)
	}
	rm.mu.Unlock()

	if shouldTrip {
		rm.tripCooldownDuration(ctx, depID, cooldownDur)
		return true
	}
	rm.reopenHalfOpenDuration(ctx, depID, dep.CircuitProbeToken, cooldownDur)
	return false
}

func (rm *ReliabilityManager) tripCooldown(ctx context.Context, depID string, cooldownSec int) {
	if cooldownSec <= 0 {
		cooldownSec = int(rm.cfg.DefaultCooldown.Seconds())
	}
	rm.tripCooldownDuration(ctx, depID, time.Duration(cooldownSec)*time.Second)
}

func (rm *ReliabilityManager) tripCooldownDuration(ctx context.Context, depID string, dur time.Duration) {
	if dur <= 0 {
		dur = rm.cfg.DefaultCooldown
	}
	if dur <= 0 {
		dur = defaultCooldownDuration
	}
	rm.mu.Lock()
	st, ok := rm.cooldowns[depID]
	if !ok {
		st = &cooldownState{windowStart: time.Now()}
		rm.cooldowns[depID] = st
	}
	st.tripped = true
	st.halfOpenProbeInFlight = false
	st.probeToken = ""
	st.cooldownUntil = time.Now().Add(dur)
	rm.mu.Unlock()

	if rm.redis != nil && rm.redis.Client() != nil {
		_, _ = rm.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
			return tripCircuitScript.Run(ctx, rdb, circuitKeys(depID), dur.Milliseconds()).Result()
		})
	}

	logger.ErrorContext(ctx, "Circuit breaker tripped to OPEN",
		slog.String("component", "circuit_breaker"),
		slog.String("deployment_id", depID),
		slog.Duration("cooldown", dur),
	)
}

func (rm *ReliabilityManager) recordSuccess(ctx context.Context, dep *domain.Deployment) {
	if dep == nil {
		return
	}
	if rm.failureRates != nil {
		rm.failureRates.record(ctx, dep.ID, false)
	}
	depID := dep.ID
	rm.mu.Lock()
	st, ok := rm.cooldowns[depID]
	if ok && st.tripped && (dep.CircuitProbeToken == "" || (rm.redis == nil || rm.redis.Client() == nil) && dep.CircuitProbeToken != st.probeToken) {
		rm.mu.Unlock()
		return
	}
	if ok {
		if st.tripped {
			logger.Info("Circuit breaker reset to CLOSED",
				slog.String("component", "circuit_breaker"),
				slog.String("deployment_id", depID),
			)
		}
		delete(rm.cooldowns, depID)
	}
	rm.mu.Unlock()

	if rm.redis != nil && rm.redis.Client() != nil {
		_, _ = rm.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
			if dep.CircuitProbeToken != "" {
				return closeCircuitScript.Run(ctx, rdb, circuitKeys(depID), dep.CircuitProbeToken).Result()
			}
			return rdb.Del(ctx, circuitFailureKey(depID)).Result()
		})
	}
}

func (rm *ReliabilityManager) releaseHalfOpenProbe(ctx context.Context, depID, probeToken string) {
	if probeToken == "" {
		return
	}
	if rm.redis != nil && rm.redis.Client() != nil {
		_, _ = rm.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
			return rdb.Eval(ctx, "if redis.call('GET', KEYS[1]) == ARGV[1] then return redis.call('DEL', KEYS[1]) else return 0 end", []string{circuitProbeKey(depID)}, probeToken).Result()
		})
	}
	rm.mu.Lock()
	defer rm.mu.Unlock()
	if st, ok := rm.cooldowns[depID]; ok && st.probeToken == probeToken {
		st.halfOpenProbeInFlight = false
		st.probeToken = ""
	}
}

func (rm *ReliabilityManager) reopenHalfOpenDuration(ctx context.Context, depID, probeToken string, dur time.Duration) {
	if probeToken == "" || rm.redis == nil || rm.redis.Client() == nil {
		return
	}
	if dur <= 0 {
		dur = rm.cfg.DefaultCooldown
	}
	_, _ = rm.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
		return reopenHalfOpenScript.Run(ctx, rdb, circuitKeys(depID), dur.Milliseconds(), probeToken).Result()
	})
}

func tokenIfProbe(code int64, token string) string {
	if code == 2 {
		return token
	}
	return ""
}

func depHashTag(depID string) string {
	if depID == "" {
		depID = "default"
	}
	return "{dep:" + depID + "}"
}

func circuitKeys(depID string) []string {
	return []string{circuitStateKey(depID), circuitCooldownKey(depID), circuitProbeKey(depID), circuitFailureKey(depID)}
}

func circuitStateKey(depID string) string {
	return "gw:router:" + depHashTag(depID) + ":circuit"
}

func circuitCooldownKey(depID string) string {
	return "gw:router:" + depHashTag(depID) + ":cooldown"
}

func circuitProbeKey(depID string) string {
	return "gw:router:" + depHashTag(depID) + ":probe"
}

func circuitFailureKey(depID string) string {
	return "gw:router:" + depHashTag(depID) + ":failures"
}

func filterUntried(all []*domain.Deployment, tried []string) []*domain.Deployment {
	var out []*domain.Deployment
	for _, d := range all {
		if !slices.Contains(tried, d.ID) {
			out = append(out, d)
		}
	}
	return out
}

func requestEstimatedOutputTokens(req *domain.CanonicalChatRequest) int {
	if req != nil && req.MaxTokens != nil && *req.MaxTokens > 0 {
		return *req.MaxTokens
	}
	return 0
}

func isTimeoutErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	var gwErr *domain.GatewayError
	if errors.As(err, &gwErr) {
		return gwErr.StatusCode == http.StatusRequestTimeout ||
			gwErr.StatusCode == http.StatusGatewayTimeout ||
			strings.Contains(strings.ToLower(gwErr.Code), "timeout")
	}
	return false
}

// CalculateBackoff computes full-jitter exponential backoff or honors upstream Retry-After up to maxDelay.
func CalculateBackoff(attempt int, retryAfterSec int, baseDelay, maxDelay time.Duration) time.Duration {
	return CalculateBackoffWithMaxRetryAfter(attempt, retryAfterSec, baseDelay, maxDelay, maxDelay)
}

// CalculateBackoffWithMaxRetryAfter honors upstream Retry-After up to maxHonoredRetryAfter
// (even when maxHonoredRetryAfter exceeds maxDelay) and falls back to full-jitter exponential backoff.
func CalculateBackoffWithMaxRetryAfter(attempt int, retryAfterSec int, baseDelay, maxDelay, maxHonoredRetryAfter time.Duration) time.Duration {
	if retryAfterSec > 0 {
		ra := time.Duration(retryAfterSec) * time.Second
		honorCap := maxDelay
		if maxHonoredRetryAfter > 0 {
			honorCap = maxHonoredRetryAfter
		}
		if ra <= honorCap {
			return ra
		}
	}
	exp := float64(baseDelay) * math.Pow(2, float64(attempt))
	capped := math.Min(float64(maxDelay), exp)
	return time.Duration(rand.Float64() * capped)
}
