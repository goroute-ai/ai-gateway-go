package router

import (
	"context"
	"log/slog"
	"math"
	"math/rand/v2"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/adapter"
	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/health"
	"github.com/goroute-ai/ai-gateway-go/internal/logger"
	"github.com/goroute-ai/ai-gateway-go/internal/observability"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/redis/go-redis/v9"
)

// CircuitState represents the 3-state circuit breaker status for a deployment.
type CircuitState string

const (
	CircuitClosed   CircuitState = "closed"
	CircuitOpen     CircuitState = "open"
	CircuitHalfOpen CircuitState = "half_open"
)

type cooldownState struct {
	failures              int
	windowStart           time.Time
	cooldownUntil         time.Time
	tripped               bool
	halfOpenProbeInFlight bool
}

// ExecutionMeta captures telemetry about retries, fallbacks, TTFT, routing overhead, and the winning deployment.
type ExecutionMeta struct {
	RouteDecision     *RouteDecision
	WinningDeployment *domain.Deployment
	RetryCount        int
	FallbackAttempted bool
	LatencyMs         int64
	TTFTMs            int64
	RoutingMicros     int64
}

// ReliabilityManager orchestrates Stage 1 Routing, Stage 2 Load Balancing,
// intra-group retries with full-jitter backoff, 3-state circuit breakers (Closed/Open/Half-Open),
// active health-probe awareness, and cross-provider fallback chains.
type ReliabilityManager struct {
	repo              storage.Repository
	registry          *adapter.Registry
	intelligentRouter *IntelligentRouter
	loadBalancer      *LoadBalancer
	vault             *auth.Vault
	rbac              *auth.RBACEngine
	redis             *storage.RedisFabric
	healthMon         *health.Monitor
	collector         *observability.Collector
	cfg               config.RouterConfig
	mu                sync.Mutex
	cooldowns         map[string]*cooldownState
}

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
	if cfg.DefaultCooldown <= 0 {
		cfg.DefaultCooldown = 60 * time.Second
	}
	if cfg.FailureWindow <= 0 {
		cfg.FailureWindow = 30 * time.Second
	}
	if cfg.FailureThreshold <= 0 {
		cfg.FailureThreshold = 3
	}
	return &ReliabilityManager{
		repo:              repo,
		registry:          registry,
		intelligentRouter: intelligentRouter,
		loadBalancer:      loadBalancer,
		vault:             vault,
		rbac:              rbac,
		redis:             redisFabric,
		cfg:               cfg,
		cooldowns:         make(map[string]*cooldownState),
	}
}

// SetHealthMonitor attaches the active background HealthMonitor to ReliabilityManager.
func (rm *ReliabilityManager) SetHealthMonitor(hm *health.Monitor) {
	rm.healthMon = hm
}

// SetCollector attaches the observability Collector to ReliabilityManager.
func (rm *ReliabilityManager) SetCollector(col *observability.Collector) {
	rm.collector = col
}

// ExecuteChat routes and executes a synchronous chat completion with automated retries and fallbacks.
func (rm *ReliabilityManager) ExecuteChat(ctx context.Context, idCtx *domain.IdentityContext, req *domain.CanonicalChatRequest) (*domain.CanonicalChatResponse, *ExecutionMeta, error) {
	start := time.Now()
	orgID := ""
	if idCtx != nil {
		orgID = idCtx.OrgID
	}

	routeStart := time.Now()
	decision, err := rm.intelligentRouter.ResolveGroup(ctx, orgID, req)
	if err != nil {
		return nil, nil, err
	}

	meta := &ExecutionMeta{RouteDecision: decision}
	groupChain := rm.buildGroupChain(ctx, decision.ModelGroup)
	meta.RoutingMicros = time.Since(routeStart).Microseconds()
	if meta.RoutingMicros <= 0 {
		meta.RoutingMicros = 1
	}

	var lastErr error
	for groupIdx, group := range groupChain {
		if groupIdx > 0 {
			meta.FallbackAttempted = true
			logger.WarnContext(ctx, "Cross-provider fallback activated",
				slog.String("component", "router"),
				slog.String("primary_alias", groupChain[0].Alias),
				slog.String("fallback_alias", group.Alias),
				slog.String("requested_model", req.Model),
			)
		}

		deployments, err := rm.getHealthyDeployments(ctx, orgID, group)
		if err != nil || len(deployments) == 0 {
			continue
		}

		maxAttempts := group.MaxRetries + 1
		if maxAttempts < 1 {
			maxAttempts = 1
		}
		triedDepIDs := make([]string, 0, len(deployments))

		for attempt := 0; attempt < maxAttempts; attempt++ {
			candidates := filterUntried(deployments, triedDepIDs)
			if len(candidates) == 0 {
				candidates = deployments
			}
			dep := rm.loadBalancer.Select(group.RoutingStrategy, candidates)
			if dep == nil {
				break
			}
			triedDepIDs = append(triedDepIDs, dep.ID)

			if attempt > 0 {
				meta.RetryCount++
				logger.WarnContext(ctx, "Intra-group retry attempt triggered",
					slog.String("component", "router"),
					slog.Int("attempt", attempt),
					slog.Int("max_attempts", maxAttempts),
					slog.String("group_alias", group.Alias),
					slog.String("deployment_id", dep.ID),
					slog.String("model", dep.GlobalModel.ModelName),
				)
			}

			rm.hydrateCredential(dep)
			adp, err := rm.registry.Get(dep.GlobalModel.Provider)
			if err != nil {
				lastErr = err
				continue
			}

			reqCopy := *req
			reqCopy.ResolvedModel = dep.GlobalModel.ModelName

			depStart := time.Now()
			rm.loadBalancer.OnRequestStart(dep.ID)
			resp, err := adp.ChatCompletion(ctx, dep, &reqCopy)
			depLatency := time.Since(depStart).Milliseconds()

			if err == nil && resp != nil {
				rm.loadBalancer.OnRequestEnd(dep.ID, depLatency, resp.Usage.TotalTokens)
				rm.recordSuccess(dep.ID)
				if rm.collector != nil {
					rm.collector.RecordDeploymentAttempt(dep.ID, dep.DeploymentName, string(dep.GlobalModel.Provider), dep.GlobalModel.ModelName, depLatency, false)
				}
				meta.WinningDeployment = dep
				meta.LatencyMs = time.Since(start).Milliseconds()
				meta.TTFTMs = depLatency
				return resp, meta, nil
			}

			rm.loadBalancer.OnRequestEnd(dep.ID, 0, 0)
			if rm.collector != nil {
				rm.collector.RecordDeploymentAttempt(dep.ID, dep.DeploymentName, string(dep.GlobalModel.Provider), dep.GlobalModel.ModelName, depLatency, true)
			}
			lastErr = err

			gwErr, isGwErr := err.(*domain.GatewayError)
			if isGwErr {
				if gwErr.AuthFailure {
					// Immediately trip cooldown on upstream 401/403 and move to next deployment/fallback
					rm.tripCooldown(ctx, dep.ID, group.CooldownSeconds)
					continue
				}
				if !gwErr.Retryable {
					return nil, meta, gwErr
				}
				rm.recordFailure(ctx, dep.ID, group.FailureThreshold, group.CooldownSeconds)
				if attempt+1 < maxAttempts {
					sleepDur := CalculateBackoff(attempt, gwErr.RetryAfterSec, rm.cfg.BaseRetryDelay, rm.cfg.MaxRetryDelay)
					select {
					case <-ctx.Done():
						return nil, meta, ctx.Err()
					case <-time.After(sleepDur):
					}
				}
			}
		}
	}

	if lastErr == nil {
		lastErr = &domain.GatewayError{
			StatusCode: http.StatusServiceUnavailable,
			Type:       domain.ErrorTypeUpstream,
			Code:       "all_deployments_unavailable",
			Message:    "All primary and fallback model deployments are currently unavailable or in cooldown",
		}
	}
	return nil, meta, lastErr
}

// ExecuteStream routes and executes a streaming SSE chat completion.
// Retries and fallbacks happen transparently if an upstream fails BEFORE the first chunk is emitted.
func (rm *ReliabilityManager) ExecuteStream(ctx context.Context, idCtx *domain.IdentityContext, req *domain.CanonicalChatRequest, onChunk adapter.StreamChunkHandler) (*domain.TokenUsage, *ExecutionMeta, error) {
	start := time.Now()
	orgID := ""
	if idCtx != nil {
		orgID = idCtx.OrgID
	}

	decision, err := rm.intelligentRouter.ResolveGroup(ctx, orgID, req)
	if err != nil {
		return nil, nil, err
	}

	meta := &ExecutionMeta{RouteDecision: decision}
	groupChain := rm.buildGroupChain(ctx, decision.ModelGroup)

	var lastErr error
	for groupIdx, group := range groupChain {
		if groupIdx > 0 {
			meta.FallbackAttempted = true
			logger.WarnContext(ctx, "Cross-provider fallback activated",
				slog.String("component", "router"),
				slog.String("primary_alias", groupChain[0].Alias),
				slog.String("fallback_alias", group.Alias),
				slog.String("requested_model", req.Model),
			)
		}

		deployments, err := rm.getHealthyDeployments(ctx, orgID, group)
		if err != nil || len(deployments) == 0 {
			continue
		}

		maxAttempts := group.MaxRetries + 1
		if maxAttempts < 1 {
			maxAttempts = 1
		}
		triedDepIDs := make([]string, 0, len(deployments))

		for attempt := 0; attempt < maxAttempts; attempt++ {
			candidates := filterUntried(deployments, triedDepIDs)
			if len(candidates) == 0 {
				candidates = deployments
			}
			dep := rm.loadBalancer.Select(group.RoutingStrategy, candidates)
			if dep == nil {
				break
			}
			triedDepIDs = append(triedDepIDs, dep.ID)

			if attempt > 0 {
				meta.RetryCount++
				logger.WarnContext(ctx, "Intra-group retry attempt triggered",
					slog.String("component", "router"),
					slog.Int("attempt", attempt),
					slog.Int("max_attempts", maxAttempts),
					slog.String("group_alias", group.Alias),
					slog.String("deployment_id", dep.ID),
					slog.String("model", dep.GlobalModel.ModelName),
				)
			}

			rm.hydrateCredential(dep)
			adp, err := rm.registry.Get(dep.GlobalModel.Provider)
			if err != nil {
				lastErr = err
				continue
			}

			reqCopy := *req
			reqCopy.ResolvedModel = dep.GlobalModel.ModelName

			depStart := time.Now()
			firstChunkRecorded := false
			rm.loadBalancer.OnRequestStart(dep.ID)

			usage, err := adp.StreamChatCompletion(ctx, dep, &reqCopy, func(chunk *domain.CanonicalStreamChunk) error {
				if !firstChunkRecorded {
					firstChunkRecorded = true
					meta.TTFTMs = time.Since(depStart).Milliseconds()
				}
				return onChunk(chunk)
			})

			if err == nil {
				totalTok := 0
				if usage != nil {
					totalTok = usage.TotalTokens
				}
				rm.loadBalancer.OnRequestEnd(dep.ID, meta.TTFTMs, totalTok)
				rm.recordSuccess(dep.ID)
				meta.WinningDeployment = dep
				meta.LatencyMs = time.Since(start).Milliseconds()
				return usage, meta, nil
			}

			rm.loadBalancer.OnRequestEnd(dep.ID, 0, 0)
			lastErr = err

			// If bytes were already flushed to the client, we cannot retry on another deployment
			if firstChunkRecorded {
				return usage, meta, err
			}

			gwErr, isGwErr := err.(*domain.GatewayError)
			if isGwErr {
				if gwErr.AuthFailure {
					rm.tripCooldown(ctx, dep.ID, group.CooldownSeconds)
					continue
				}
				if !gwErr.Retryable {
					return nil, meta, gwErr
				}
				rm.recordFailure(ctx, dep.ID, group.FailureThreshold, group.CooldownSeconds)
			}
		}
	}

	if lastErr == nil {
		lastErr = &domain.GatewayError{
			StatusCode: http.StatusServiceUnavailable,
			Type:       domain.ErrorTypeUpstream,
			Code:       "all_deployments_unavailable",
			Message:    "All primary and fallback streaming deployments are unavailable",
		}
	}
	return nil, meta, lastErr
}

// ExecuteEmbeddings routes and executes a `/v1/embeddings` request with retries and fallbacks.
func (rm *ReliabilityManager) ExecuteEmbeddings(ctx context.Context, idCtx *domain.IdentityContext, req *domain.CanonicalEmbeddingRequest) (*domain.CanonicalEmbeddingResponse, *ExecutionMeta, error) {
	start := time.Now()
	orgID := ""
	if idCtx != nil {
		orgID = idCtx.OrgID
	}

	mg, err := rm.repo.GetModelGroupByAlias(ctx, orgID, req.Model)
	if err != nil {
		return nil, nil, &domain.GatewayError{
			StatusCode: http.StatusNotFound,
			Type:       domain.ErrorTypeNotFound,
			Code:       "embedding_model_not_found",
			Message:    "No active embedding model group configured for: " + req.Model,
		}
	}

	meta := &ExecutionMeta{
		RouteDecision: &RouteDecision{
			RequestedModel:   req.Model,
			TargetGroupAlias: mg.Alias,
			ModelGroup:       mg,
		},
	}

	deployments, err := rm.getHealthyDeployments(ctx, orgID, mg)
	if err != nil || len(deployments) == 0 {
		return nil, meta, &domain.GatewayError{
			StatusCode: http.StatusServiceUnavailable,
			Type:       domain.ErrorTypeUpstream,
			Code:       "no_healthy_embedding_deployments",
			Message:    "No healthy deployments available for embedding model " + req.Model,
		}
	}

	dep := rm.loadBalancer.Select(mg.RoutingStrategy, deployments)
	rm.hydrateCredential(dep)
	adp, err := rm.registry.Get(dep.GlobalModel.Provider)
	if err != nil {
		return nil, meta, err
	}
	reqCopy := *req
	reqCopy.ResolvedModel = dep.GlobalModel.ModelName
	resp, err := adp.Embeddings(ctx, dep, &reqCopy)
	if err != nil {
		return nil, meta, err
	}
	meta.WinningDeployment = dep
	meta.LatencyMs = time.Since(start).Milliseconds()
	return resp, meta, nil
}

func (rm *ReliabilityManager) buildGroupChain(ctx context.Context, primary *domain.ModelGroup) []*domain.ModelGroup {
	if primary == nil {
		return nil
	}
	chain := []*domain.ModelGroup{primary}
	for _, fbID := range primary.FallbackGroupIDs {
		if fbGroup, err := rm.repo.GetModelGroupByID(ctx, fbID); err == nil && fbGroup != nil && fbGroup.IsActive {
			chain = append(chain, fbGroup)
			continue
		}
		if fbGroup, err := rm.repo.GetModelGroupByAlias(ctx, primary.OrgID, fbID); err == nil && fbGroup != nil && fbGroup.IsActive {
			chain = append(chain, fbGroup)
		}
	}
	return chain
}

func (rm *ReliabilityManager) getHealthyDeployments(ctx context.Context, orgID string, group *domain.ModelGroup) ([]*domain.Deployment, error) {
	all, err := rm.repo.ListDeploymentsByGroup(ctx, group.ID)
	if err != nil {
		return nil, err
	}
	now := time.Now().UTC()
	var healthy []*domain.Deployment
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
		if rm.healthMon != nil && !rm.healthMon.IsHealthy(d.ID) {
			continue
		}
		// 3-State Circuit Breaker check (CLOSED -> allowed, OPEN -> blocked, HALF_OPEN -> admits 1 trial request)
		if !rm.allowDeploymentRequest(ctx, d.ID) {
			continue
		}
		if rm.rbac != nil && orgID != "" {
			if err := rm.rbac.AuthorizeDeployment(ctx, orgID, d); err != nil {
				continue
			}
		}
		healthy = append(healthy, d)
	}
	return healthy, nil
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
		res, err := rm.redis.Execute(func(rdb *redis.Client) (any, error) {
			return rdb.Exists(ctx, "gw:router:cooldown:"+depID).Result()
		})
		if err == nil {
			if cnt, ok := res.(int64); ok && cnt > 0 {
				return CircuitOpen
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
func (rm *ReliabilityManager) allowDeploymentRequest(ctx context.Context, depID string) bool {
	if rm.redis != nil && rm.redis.Client() != nil {
		res, err := rm.redis.Execute(func(rdb *redis.Client) (any, error) {
			return rdb.Exists(ctx, "gw:router:cooldown:"+depID).Result()
		})
		if err == nil {
			if cnt, ok := res.(int64); ok && cnt > 0 {
				return false
			}
		}
	}

	rm.mu.Lock()
	defer rm.mu.Unlock()
	st, ok := rm.cooldowns[depID]
	if !ok || !st.tripped {
		return true
	}
	if time.Now().Before(st.cooldownUntil) {
		return false
	}
	// Cooldown elapsed -> Circuit is HALF_OPEN; allow a single recovery probe
	if st.halfOpenProbeInFlight {
		return false
	}
	st.halfOpenProbeInFlight = true
	logger.InfoContext(ctx, "Circuit breaker entering HALF_OPEN probe state",
		slog.String("component", "circuit_breaker"),
		slog.String("deployment_id", depID),
	)
	return true
}

func (rm *ReliabilityManager) recordFailure(ctx context.Context, depID string, threshold, cooldownSec int) {
	if threshold <= 0 {
		threshold = rm.cfg.FailureThreshold
	}
	if cooldownSec <= 0 {
		cooldownSec = int(rm.cfg.DefaultCooldown.Seconds())
	}

	now := time.Now()
	rm.mu.Lock()
	st, ok := rm.cooldowns[depID]
	// If failing during a HALF_OPEN probe, immediately re-trip to OPEN
	if ok && st.tripped && !now.Before(st.cooldownUntil) {
		st.halfOpenProbeInFlight = false
		st.cooldownUntil = now.Add(time.Duration(cooldownSec) * time.Second)
		rm.mu.Unlock()
		rm.tripCooldown(ctx, depID, cooldownSec)
		return
	}
	if !ok || now.Sub(st.windowStart) > rm.cfg.FailureWindow {
		st = &cooldownState{windowStart: now}
		rm.cooldowns[depID] = st
	}
	st.failures++
	shouldTrip := st.failures >= threshold
	if shouldTrip {
		st.tripped = true
		st.halfOpenProbeInFlight = false
		st.cooldownUntil = now.Add(time.Duration(cooldownSec) * time.Second)
	}
	rm.mu.Unlock()

	if shouldTrip {
		rm.tripCooldown(ctx, depID, cooldownSec)
	}
}

func (rm *ReliabilityManager) tripCooldown(ctx context.Context, depID string, cooldownSec int) {
	if cooldownSec <= 0 {
		cooldownSec = int(rm.cfg.DefaultCooldown.Seconds())
	}
	dur := time.Duration(cooldownSec) * time.Second
	rm.mu.Lock()
	st, ok := rm.cooldowns[depID]
	if !ok {
		st = &cooldownState{windowStart: time.Now()}
		rm.cooldowns[depID] = st
	}
	st.tripped = true
	st.halfOpenProbeInFlight = false
	st.cooldownUntil = time.Now().Add(dur)
	rm.mu.Unlock()

	if rm.redis != nil && rm.redis.Client() != nil {
		_, _ = rm.redis.Execute(func(rdb *redis.Client) (any, error) {
			return rdb.Set(ctx, "gw:router:cooldown:"+depID, "open", dur).Result()
		})
	}

	logger.ErrorContext(ctx, "Circuit breaker tripped to OPEN",
		slog.String("component", "circuit_breaker"),
		slog.String("deployment_id", depID),
		slog.Duration("cooldown", dur),
	)
}

func (rm *ReliabilityManager) recordSuccess(depID string) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	if st, ok := rm.cooldowns[depID]; ok && st.tripped {
		logger.Info("Circuit breaker reset to CLOSED",
			slog.String("component", "circuit_breaker"),
			slog.String("deployment_id", depID),
		)
	}
	delete(rm.cooldowns, depID)
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

// CalculateBackoff computes full-jitter exponential backoff or honors upstream Retry-After.
func CalculateBackoff(attempt int, retryAfterSec int, baseDelay, maxDelay time.Duration) time.Duration {
	if retryAfterSec > 0 {
		ra := time.Duration(retryAfterSec) * time.Second
		if ra <= maxDelay {
			return ra
		}
	}
	exp := float64(baseDelay) * math.Pow(2, float64(attempt))
	capped := math.Min(float64(maxDelay), exp)
	return time.Duration(rand.Float64() * capped)
}
