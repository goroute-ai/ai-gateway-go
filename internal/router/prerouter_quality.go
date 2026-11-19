package router

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	catalog "github.com/goroute-ai/ai-gateway-go/internal/modelcatalog"
	"github.com/goroute-ai/ai-gateway-go/internal/ratelimit"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

// CacheHitCheckFn checks whether a request matches an exact response cache entry
// or warm prompt-cache affinity for an organization, returning the target alias
// when a hit is found.
type CacheHitCheckFn func(ctx context.Context, orgID string, req *domain.CanonicalChatRequest) (targetAlias string, hit bool)

type cachedQualityGroups struct {
	groups    []*domain.ModelGroup
	rev       uint64
	expiresAt time.Time
}

type cachedQualityDeps struct {
	deps      []*domain.Deployment
	rev       uint64
	expiresAt time.Time
}

type cachedQualityModel struct {
	model     *domain.GlobalModel
	rev       uint64
	expiresAt time.Time
}

// QualityPreRouter maps request complexity and explicit/keyword signals to a
// minimum model quality tier (1=economy, 2=standard, 3=frontier, 4=reasoning)
// and selects the cheapest eligible active ModelGroup/Deployment meeting that tier.
type QualityPreRouter struct {
	repo       storage.Repository
	cfg        config.RouterConfig
	cacheCheck CacheHitCheckFn

	cacheMu     sync.RWMutex
	groupsCache map[string]cachedQualityGroups
	depsCache   map[string]cachedQualityDeps
	modelsCache map[string]cachedQualityModel
}

// InvalidateCache clears cached group, deployment, and catalog lookups in response to mutations.
func (q *QualityPreRouter) InvalidateCache(ev storage.InvalidationEvent) {
	if q == nil {
		return
	}
	q.cacheMu.Lock()
	defer q.cacheMu.Unlock()
	if ev.OrgID != "" && q.groupsCache != nil {
		delete(q.groupsCache, ev.OrgID)
	} else if ev.EntityType == "" || ev.EntityType == "model_group" || ev.EntityType == "all" {
		q.groupsCache = nil
	}
	if ev.EntityID != "" && q.depsCache != nil {
		delete(q.depsCache, ev.EntityID)
	} else {
		q.depsCache = nil
	}
	q.modelsCache = nil
}

// NewQualityPreRouter constructs a QualityPreRouter backed by repo and RouterConfig.
// cacheCheck is optional and consulted when cfg.CacheAwareRouting is true.
func NewQualityPreRouter(repo storage.Repository, cfg config.RouterConfig, cacheCheck CacheHitCheckFn) *QualityPreRouter {
	return &QualityPreRouter{
		repo:       repo,
		cfg:        normalizeRouterConfigDefaults(cfg),
		cacheCheck: cacheCheck,
	}
}

// Name returns "quality".
func (q *QualityPreRouter) Name() string {
	return PreRouterModeQuality
}

// Route selects the target group alias for req. When CacheAwareRouting is enabled
// and cacheCheck reports a hit, that alias is returned before tier escalation.
func (q *QualityPreRouter) Route(ctx context.Context, orgID string, req *domain.CanonicalChatRequest) (string, string, float64, error) {
	if q == nil {
		return "fast", "quality:nil_router", 0, nil
	}
	if req == nil {
		return "", "", 0, errors.New("request is required")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	requiredTier, score, tierReason := DetermineRequiredQualityTier(q.cfg, req)

	// Cache-aware mode short-circuits before escalating to higher-tier models.
	if q.cfg.CacheAwareRouting && q.cacheCheck != nil {
		if cachedAlias, hit := q.cacheCheck(ctx, orgID, req); hit && strings.TrimSpace(cachedAlias) != "" {
			return strings.TrimSpace(cachedAlias), "quality:cache_hit", score, nil
		}
	}

	if q.repo == nil {
		return q.cfg.DefaultFastAlias, "quality:no_repo_fallback", score, nil
	}

	groups, err := q.listModelGroupsCached(ctx, orgID)
	if err != nil {
		return "", "", 0, fmt.Errorf("quality pre-router list model groups: %w", err)
	}

	estTokens := ratelimit.EstimateRequestTokens(req)
	requiresVision := hasVisionContent(req)
	requiresJSONSchema := req.ResponseFormat != nil && req.ResponseFormat.Type == "json_schema"

	var meetingTier *qualityCandidate
	var bestFallback *qualityCandidate
	var firstActiveAlias string
	hasDefaultFast := false

	for _, g := range groups {
		if g == nil || !g.IsActive {
			continue
		}
		lowerAlias := strings.ToLower(strings.TrimSpace(g.Alias))
		if lowerAlias == "" || lowerAlias == VirtualAliasAuto || strings.HasPrefix(lowerAlias, "router/") {
			continue
		}
		if firstActiveAlias == "" {
			firstActiveAlias = g.Alias
		}
		if g.Alias == q.cfg.DefaultFastAlias {
			hasDefaultFast = true
		}

		deps, depErr := q.listDeploymentsCached(ctx, g.ID)
		if depErr != nil || len(deps) == 0 {
			continue
		}

		for _, dep := range deps {
			if dep == nil || dep.Status != domain.DeploymentStatusActive {
				continue
			}
			if dep.Credential != nil && !dep.Credential.IsActive {
				continue
			}

			gm := q.resolveGlobalModel(ctx, dep)
			if !isChatDeploymentModelEligible(gm, req, estTokens, requiresVision, requiresJSONSchema) {
				continue
			}

			effTier := effectiveModelQualityTier(gm)
			cost := deploymentUnitCostMicros(gm)
			cand := qualityCandidate{
				alias:         g.Alias,
				effectiveTier: effTier,
				costMicros:    cost,
			}

			if effTier >= requiredTier {
				if meetingTier == nil || isBetterTierCandidate(cand, *meetingTier) {
					c := cand
					meetingTier = &c
				}
			} else {
				if bestFallback == nil || isBetterFallbackCandidate(cand, *bestFallback) {
					c := cand
					bestFallback = &c
				}
			}
		}
	}

	if meetingTier != nil {
		reason := fmt.Sprintf("quality:tier_%d_cost_optimized:%s", requiredTier, tierReason)
		return meetingTier.alias, reason, score, nil
	}
	if bestFallback != nil {
		reason := fmt.Sprintf("quality:tier_%d_best_available_tier_%d:%s", requiredTier, bestFallback.effectiveTier, tierReason)
		return bestFallback.alias, reason, score, nil
	}
	if hasDefaultFast {
		return q.cfg.DefaultFastAlias, "quality:fallback_default", score, nil
	}
	if firstActiveAlias != "" {
		return firstActiveAlias, "quality:fallback_active", score, nil
	}
	return q.cfg.DefaultFastAlias, "quality:no_active_groups", score, nil
}

// DetermineRequiredQualityTier maps a CanonicalChatRequest's complexity score S
// and keyword/parameter overrides to a minimum QualityTier in [1..4].
func DetermineRequiredQualityTier(cfg config.RouterConfig, req *domain.CanonicalChatRequest) (tier int, score float64, reason string) {
	cfg = normalizeRouterConfigDefaults(cfg)
	if req == nil {
		return catalog.QualityTierEconomy, 0, "empty_request"
	}

	_, score, _ = ClassifyPromptComplexity(cfg, req)
	estTokens := ratelimit.EstimateRequestTokens(req)
	text := extractCombinedUserTextLower(req)

	// Tier 4 (Reasoning): explicit reasoning_effort, reasoning/proof keywords, long context, or very high complexity.
	if strings.TrimSpace(req.ReasoningEffort) != "" ||
		estTokens >= cfg.LongContextTokens ||
		containsAnyKeyword(text, "reasoning", "prove", "theorem", "step by step", "step-by-step", "mathematical", "root cause", "formal proof") ||
		score >= 0.75 {
		return catalog.QualityTierReasoning, score, "reasoning_override"
	}

	// Tier 3 (Frontier): tool calls, code/architecture markers, structured JSON schema, or >= ComplexityThreshold.
	if len(req.Tools) > 0 ||
		(req.ResponseFormat != nil && req.ResponseFormat.Type == "json_schema") ||
		containsAnyKeyword(text, "```", "func ", "class ", "def ", "select ", "import ", "package ", "function ", "debug", "refactor", "architect", "algorithm") ||
		score >= cfg.ComplexityThreshold {
		return catalog.QualityTierFrontier, score, "code_tools_or_frontier_complexity"
	}

	// Tier 2 (Standard): multi-turn conversations, moderate length, or analytical/drafting tasks.
	if estTokens > 80 ||
		len(req.Messages) >= 3 ||
		score >= 0.15 ||
		containsAnyKeyword(text, "summarize", "explain", "compare", "analyze", "draft", "write", "design", "trade-off") {
		return catalog.QualityTierStandard, score, "standard_complexity"
	}

	// Tier 1 (Economy): short, simple prompts.
	return catalog.QualityTierEconomy, score, "short_simple_economy"
}

func (q *QualityPreRouter) repoRevision() uint64 {
	if rp, ok := q.repo.(storage.RoutingRevisionProvider); ok {
		return rp.RoutingRevision()
	}
	return 0
}

func (q *QualityPreRouter) listModelGroupsCached(ctx context.Context, orgID string) ([]*domain.ModelGroup, error) {
	now := time.Now()
	rev := q.repoRevision()
	q.cacheMu.RLock()
	if q.groupsCache != nil {
		if ent, ok := q.groupsCache[orgID]; ok && now.Before(ent.expiresAt) && (rev == 0 || ent.rev == rev) {
			q.cacheMu.RUnlock()
			return ent.groups, nil
		}
	}
	q.cacheMu.RUnlock()

	groups, err := q.repo.ListModelGroups(ctx, orgID)
	if err != nil {
		return nil, err
	}
	q.cacheMu.Lock()
	if q.groupsCache == nil {
		q.groupsCache = make(map[string]cachedQualityGroups)
	}
	q.groupsCache[orgID] = cachedQualityGroups{
		groups:    groups,
		rev:       rev,
		expiresAt: now.Add(defaultRoutingL1CacheTTL),
	}
	q.cacheMu.Unlock()
	return groups, nil
}

func (q *QualityPreRouter) listDeploymentsCached(ctx context.Context, groupID string) ([]*domain.Deployment, error) {
	now := time.Now()
	rev := q.repoRevision()
	q.cacheMu.RLock()
	if q.depsCache != nil {
		if ent, ok := q.depsCache[groupID]; ok && now.Before(ent.expiresAt) && (rev == 0 || ent.rev == rev) {
			q.cacheMu.RUnlock()
			return ent.deps, nil
		}
	}
	q.cacheMu.RUnlock()

	deps, err := q.repo.ListDeploymentsByGroup(ctx, groupID)
	if err != nil {
		return nil, err
	}
	q.cacheMu.Lock()
	if q.depsCache == nil {
		q.depsCache = make(map[string]cachedQualityDeps)
	}
	q.depsCache[groupID] = cachedQualityDeps{
		deps:      deps,
		rev:       rev,
		expiresAt: now.Add(defaultRoutingL1CacheTTL),
	}
	q.cacheMu.Unlock()
	return deps, nil
}

func (q *QualityPreRouter) resolveGlobalModel(ctx context.Context, dep *domain.Deployment) *domain.GlobalModel {
	if dep == nil {
		return nil
	}
	if dep.GlobalModel != nil {
		return dep.GlobalModel
	}
	if dep.GlobalModelID == "" {
		return nil
	}
	if q.repo != nil {
		now := time.Now()
		rev := q.repoRevision()
		q.cacheMu.RLock()
		if q.modelsCache != nil {
			if ent, ok := q.modelsCache[dep.GlobalModelID]; ok && now.Before(ent.expiresAt) && (rev == 0 || ent.rev == rev) {
				q.cacheMu.RUnlock()
				return ent.model
			}
		}
		q.cacheMu.RUnlock()
		if gm, err := q.repo.GetGlobalModel(ctx, dep.GlobalModelID); err == nil && gm != nil {
			q.cacheMu.Lock()
			if q.modelsCache == nil {
				q.modelsCache = make(map[string]cachedQualityModel)
			}
			q.modelsCache[dep.GlobalModelID] = cachedQualityModel{
				model:     gm,
				rev:       rev,
				expiresAt: now.Add(defaultRoutingL1CacheTTL),
			}
			q.cacheMu.Unlock()
			return gm
		}
	}
	if gm, ok := catalog.Lookup(dep.GlobalModelID); ok {
		return gm
	}
	return nil
}

func isChatDeploymentModelEligible(gm *domain.GlobalModel, req *domain.CanonicalChatRequest, estTokens int, requiresVision, requiresJSONSchema bool) bool {
	if gm == nil {
		return true
	}
	if gm.LifecycleStatus == domain.ModelStatusRetired {
		return false
	}
	if len(gm.SupportedOperations) > 0 && !gm.SupportsOperation(domain.OperationChat) {
		return false
	}
	if gm.SupportsEmbeddings && !gm.SupportsInference && len(gm.SupportedOperations) == 0 {
		return false
	}
	if gm.MaxInputTokens > 0 && estTokens > gm.MaxInputTokens {
		return false
	}
	caps := gm.ResolveCapabilities()
	if req.Stream && caps.Streaming == domain.CapabilityUnsupported {
		return false
	}
	if len(req.Tools) > 0 && caps.Tools == domain.CapabilityUnsupported {
		return false
	}
	if requiresVision && caps.Vision == domain.CapabilityUnsupported {
		return false
	}
	if requiresJSONSchema && caps.StructuredOutputs == domain.CapabilityUnsupported {
		return false
	}
	return true
}

func effectiveModelQualityTier(gm *domain.GlobalModel) int {
	if gm == nil {
		return catalog.QualityTierUnknown
	}
	if gm.QualityTier > 0 {
		return gm.QualityTier
	}
	return catalog.InferQualityTier(gm)
}

func deploymentUnitCostMicros(gm *domain.GlobalModel) int64 {
	if gm == nil {
		return math.MaxInt64
	}
	if gm.InputCostMicrosPer1M > math.MaxInt64-gm.OutputCostMicrosPer1M {
		return math.MaxInt64
	}
	return gm.InputCostMicrosPer1M + gm.OutputCostMicrosPer1M
}

type qualityCandidate struct {
	alias         string
	effectiveTier int
	costMicros    int64
}

func isBetterTierCandidate(cand, best qualityCandidate) bool {
	if cand.costMicros != best.costMicros {
		return cand.costMicros < best.costMicros
	}
	if cand.effectiveTier != best.effectiveTier {
		return cand.effectiveTier < best.effectiveTier
	}
	return cand.alias < best.alias
}

func isBetterFallbackCandidate(cand, best qualityCandidate) bool {
	if cand.effectiveTier != best.effectiveTier {
		return cand.effectiveTier > best.effectiveTier
	}
	if cand.costMicros != best.costMicros {
		return cand.costMicros < best.costMicros
	}
	return cand.alias < best.alias
}

func containsAnyKeyword(text string, keywords ...string) bool {
	for _, kw := range keywords {
		if strings.Contains(text, kw) {
			return true
		}
	}
	return false
}

func hasVisionContent(req *domain.CanonicalChatRequest) bool {
	if req == nil {
		return false
	}
	for _, m := range req.Messages {
		for _, p := range m.Parts {
			if p.Type == "image_url" || p.Type == "input_image" || p.ImageURL != nil {
				return true
			}
		}
	}
	return false
}
