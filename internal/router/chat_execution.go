package router

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/adapter"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/logger"
	"github.com/goroute-ai/ai-gateway-go/internal/ratelimit"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

type hedgedChatRaceResult struct {
	winner      *domain.Deployment
	resp        *domain.CanonicalChatResponse
	dropped     []string
	raceLatency int64
	err         error
}

type hedgedStreamRaceResult struct {
	winner                *domain.Deployment
	usage                 *domain.TokenUsage
	chunkUsageThisAttempt *domain.TokenUsage
	clientChunkErr        error
	dropped               []string
	raceLatency           int64
	err                   error
}

type groupHopOutcome[T any] struct {
	handled     bool
	result      T
	meta        *ExecutionMeta
	err         error
	stopAll     bool
	requeueSame bool
}

func extractExecutionOrgID(ctx context.Context, idCtx *domain.IdentityContext) (context.Context, string, bool) {
	orgID := ""
	if idCtx != nil {
		orgID = idCtx.OrgID
		if idCtx.TeamID != "" {
			ctx = WithCallerTeamID(ctx, idCtx.TeamID)
		}
	}
	return ctx, orgID, isBudgetConstrained(idCtx)
}

func initRouteDecisionMeta(decision *RouteDecision, routeStart time.Time) *ExecutionMeta {
	meta := &ExecutionMeta{RouteDecision: decision}
	meta.RoutingMicros = time.Since(routeStart).Microseconds()
	if meta.RoutingMicros <= 0 {
		meta.RoutingMicros = 1
	}
	return meta
}

func initHopQueue(primary *domain.ModelGroup, initialQueue []queuedHop) ([]queuedHop, map[string]struct{}) {
	visited := make(map[string]struct{})
	if key := groupVisitKey(primary); key != "" {
		visited[key] = struct{}{}
	}
	queue := initialQueue
	if len(queue) == 0 {
		return []queuedHop{{group: primary, depth: 0}}, visited
	}
	for _, h := range queue {
		if k := groupVisitKey(h.group); k != "" {
			visited[k] = struct{}{}
		}
	}
	return queue, visited
}

func unavailableChatError(isBudgeted, skippedDueToUnknownPricing bool, unavailableMsg string) error {
	if isBudgeted && skippedDueToUnknownPricing {
		return &domain.GatewayError{
			StatusCode: http.StatusForbidden,
			Type:       domain.ErrorTypePermission,
			Code:       "pricing_unknown_budget_restricted",
			Message:    "Request rejected: caller has strict budget enforcement enabled, but selected model deployment has unverified/unknown pricing",
		}
	}
	return &domain.GatewayError{
		StatusCode: http.StatusServiceUnavailable,
		Type:       domain.ErrorTypeUpstream,
		Code:       "all_deployments_unavailable",
		Message:    unavailableMsg,
	}
}

func (rm *ReliabilityManager) selectNextTierDeployment(
	tierIdx, attempt int,
	tierDeployments, allDeployments []*domain.Deployment,
	aff *AffinityStore,
	affinityDepID string,
	triedDepIDs []string,
	trippedDepIDs map[string]struct{},
	strategy domain.RoutingStrategy,
	snap *SignalSnapshot,
) *domain.Deployment {
	if tierIdx == 0 && attempt == 0 && affinityDepID != "" && aff != nil {
		if pinned, ok := aff.SelectOrPin(affinityDepID, allDeployments); ok {
			return pinned
		}
	}
	candidates := filterUntried(tierDeployments, triedDepIDs)
	if len(candidates) == 0 {
		candidates = filterOutDepIDs(tierDeployments, trippedDepIDs)
		if len(candidates) == 0 {
			return nil
		}
	}
	return rm.loadBalancer.SelectWithSignals(strategy, candidates, snap)
}

// ExecuteChat routes and executes a synchronous chat completion through intelligent routing,
// intra-group retries/hedging, circuit breakers, and cross-provider fallback chains.
func (rm *ReliabilityManager) ExecuteChat(ctx context.Context, idCtx *domain.IdentityContext, req *domain.CanonicalChatRequest) (*domain.CanonicalChatResponse, *ExecutionMeta, error) {
	if req != nil && req.Stream {
		ctx = network.WithStreamingRequest(ctx)
	}
	releaseSlot, schedErr := rm.acquireSchedulerSlot(ctx, req)
	if schedErr != nil {
		return nil, nil, schedErr
	}
	defer releaseSlot()

	start := time.Now()
	ctx, orgID, isBudgeted := extractExecutionOrgID(ctx, idCtx)
	estTokens := ratelimit.EstimateRequestTokens(req)

	var decision *RouteDecision
	var initialQueue []queuedHop
	var skippedDueToUnknownPricing bool
	var lastErr error

	routeStart := time.Now()
	if commaAliases := ParseCommaSeparatedModels(req.Model); len(commaAliases) >= 2 {
		var fastResp *domain.CanonicalChatResponse
		var fastMeta *ExecutionMeta
		var err error
		decision, initialQueue, skippedDueToUnknownPricing, lastErr, fastResp, fastMeta, err = rm.prepareCommaSeparatedChat(
			ctx, idCtx, req, commaAliases, orgID, estTokens, isBudgeted, start, routeStart,
		)
		if err != nil || fastResp != nil {
			return fastResp, fastMeta, err
		}
	} else {
		var err error
		decision, err = rm.intelligentRouter.ResolveGroup(ctx, orgID, req)
		if err != nil {
			return nil, nil, err
		}
	}

	meta := initRouteDecisionMeta(decision, routeStart)
	maxDepth := rm.effectiveMaxFallbackDepth()
	queue, visited := initHopQueue(decision.ModelGroup, initialQueue)
	aff := rm.getAffinityStore()

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		if current.group == nil {
			continue
		}

		hopOut := rm.executeChatGroupHop(
			ctx, idCtx, req, decision, meta, current,
			orgID, estTokens, isBudgeted, aff, start,
			&lastErr, &skippedDueToUnknownPricing,
		)
		if hopOut.handled {
			return hopOut.result, hopOut.meta, hopOut.err
		}
		if hopOut.stopAll {
			break
		}

		cat := rm.classifyErr(hopOut.err)
		if isPrioritySaturationErr(hopOut.err) {
			cat = CategorySaturation
		}
		queue = rm.enqueueFallbacks(ctx, queue, current, cat, maxDepth, visited)
	}

	if lastErr == nil {
		lastErr = unavailableChatError(isBudgeted, skippedDueToUnknownPricing, "All primary and fallback model deployments are currently unavailable or in cooldown")
	}
	rm.recordBanditOutcome(orgID, decision, false, time.Since(start).Milliseconds())
	return nil, meta, lastErr
}

func (rm *ReliabilityManager) prepareCommaSeparatedChat(
	ctx context.Context,
	idCtx *domain.IdentityContext,
	req *domain.CanonicalChatRequest,
	commaAliases []string,
	orgID string,
	estTokens int,
	isBudgeted bool,
	start, routeStart time.Time,
) (*RouteDecision, []queuedHop, bool, error, *domain.CanonicalChatResponse, *ExecutionMeta, error) {
	pool, poolErr := rm.resolveCommaSeparatedCandidates(ctx, orgID, req, commaAliases, estTokens, isBudgeted, false)
	if poolErr != nil {
		return nil, nil, false, nil, nil, nil, poolErr
	}
	skippedDueToUnknownPricing := pool.skippedBudget
	lastErr := pool.lastErr
	primary := pool.groups[0]
	decision := &RouteDecision{
		RequestedModel:   req.Model,
		TargetGroupAlias: primary.Alias,
		ModelGroup:       primary,
		Reason:           "hedged_race_winner",
	}
	meta := initRouteDecisionMeta(decision, routeStart)

	if len(pool.candidates) > 0 {
		res := rm.executeChatHedgeRace(ctx, idCtx, req, pool.candidates, meta, estTokens, func(dep *domain.Deployment) (*domain.ModelGroup, int) {
			depGroup := pool.groupByDep[dep.ID]
			if depGroup == nil {
				depGroup = primary
			}
			return depGroup, pool.activeByGroup[depGroup.ID]
		})
		if res.err == nil && res.resp != nil && res.winner != nil {
			rm.releaseUnusedProbes(ctx, pool.candidates, []*domain.Deployment{res.winner})
			if wg := pool.groupByDep[res.winner.ID]; wg != nil {
				meta.RouteDecision.TargetGroupAlias = wg.Alias
				meta.RouteDecision.ModelGroup = wg
			}
			meta.RouteDecision.Reason = "hedged_race_winner"
			meta.WinningDeployment = res.winner
			meta.DroppedParams = res.dropped
			meta.LatencyMs = time.Since(start).Milliseconds()
			return decision, nil, skippedDueToUnknownPricing, lastErr, res.resp, meta, nil
		}
		rm.releaseUnusedProbes(ctx, pool.candidates, nil)
		if res.err != nil {
			lastErr = res.err
		}
	}

	if lastErr != nil && rm.classifyErr(lastErr) == CategoryNonRetryable {
		return decision, nil, skippedDueToUnknownPricing, lastErr, nil, meta, lastErr
	}
	visited := make(map[string]struct{})
	if key := groupVisitKey(primary); key != "" {
		visited[key] = struct{}{}
	}
	initialQueue := rm.enqueueFallbacks(ctx, nil, queuedHop{group: primary, depth: 0}, rm.classifyErr(lastErr), rm.effectiveMaxFallbackDepth(), visited)
	if len(initialQueue) == 0 {
		if lastErr == nil {
			lastErr = unavailableChatError(isBudgeted, skippedDueToUnknownPricing, "All primary and fallback model deployments are currently unavailable or in cooldown")
		}
		return decision, nil, skippedDueToUnknownPricing, lastErr, nil, meta, lastErr
	}
	return decision, initialQueue, skippedDueToUnknownPricing, lastErr, nil, nil, nil
}

func (rm *ReliabilityManager) executeChatHedgeRace(
	ctx context.Context,
	idCtx *domain.IdentityContext,
	req *domain.CanonicalChatRequest,
	racers []*domain.Deployment,
	meta *ExecutionMeta,
	estTokens int,
	groupForDep func(dep *domain.Deployment) (*domain.ModelGroup, int),
) hedgedChatRaceResult {
	for _, r := range racers {
		rm.hydrateCredential(r)
	}
	raceStart := time.Now()
	var raceMetaMu sync.Mutex
	droppedByDep := make(map[string][]string, len(racers))

	winner, resp, raceErr := RaceChatAttempts(ctx, racers, rm.buildHedgeConfig(req), func(raceCtx context.Context, dep *domain.Deployment) (*domain.CanonicalChatResponse, error) {
		depGroup, activeTotal := groupForDep(dep)
		adp, adpErr := rm.registry.Get(dep.GlobalModel.Provider)
		if adpErr != nil {
			raceMetaMu.Lock()
			appendFallbackError(meta, depGroup.Alias, dep.ID, adpErr)
			raceMetaMu.Unlock()
			return nil, adpErr
		}
		if opErr := checkDeploymentOperation(adp, dep, domain.OperationChat); opErr != nil {
			raceMetaMu.Lock()
			appendFallbackError(meta, depGroup.Alias, dep.ID, opErr)
			raceMetaMu.Unlock()
			return nil, opErr
		}
		relSlot, slotOK := rm.acquireDeploymentSlot(raceCtx, dep, requestPriorityRank(idCtx, req), false)
		if !slotOK {
			satErr := saturationGatewayError()
			raceMetaMu.Lock()
			appendFallbackError(meta, depGroup.Alias, dep.ID, satErr)
			raceMetaMu.Unlock()
			return nil, satErr
		}
		defer relSlot()

		dropEnabled := resolveDropUnsupportedParams(rm.cfg.DropUnsupportedParams, depGroup, req)
		reqCopy, dropped := sanitizeRequestForDeployment(req, dep, dropEnabled)
		reqCopy.ResolvedModel = dep.GlobalModel.ModelName
		if len(dropped) > 0 {
			raceMetaMu.Lock()
			droppedByDep[dep.ID] = dropped
			raceMetaMu.Unlock()
		}

		estOut := requestEstimatedOutputTokens(&reqCopy)
		depStart := time.Now()
		rm.loadBalancer.OnRequestStartWithTokens(dep.ID, estTokens, estOut)
		capture := rm.shouldCaptureContent()
		spanCtx, span := rm.startGenAIClientSpan(raceCtx, "chat", dep, buildChatStartOpts(&reqCopy, capture))
		depCtx, depCancel := withDeploymentTimeout(spanCtx, dep)
		markProviderDispatch(depCtx, dep)
		r, callErr := adp.ChatCompletion(depCtx, dep, &reqCopy)
		depCancel()
		rm.finishGenAIClientSpanWithOpts(spanCtx, span, buildChatFinishOpts(r, meta.RetryCount, meta.FallbackAttempted, capture, callErr))
		depLatency := time.Since(depStart).Milliseconds()

		if callErr == nil && r != nil {
			rm.loadBalancer.OnRequestEndWithUsage(dep.ID, depLatency, 0, estTokens, estOut, r.Usage.PromptTokens, r.Usage.CompletionTokens)
			rm.recordSuccess(ctx, dep)
			if rm.collector != nil {
				rm.collector.RecordDeploymentAttempt(dep.ID, dep.DeploymentName, string(dep.GlobalModel.Provider), dep.GlobalModel.ModelName, depLatency, false)
			}
			return r, nil
		}

		rm.loadBalancer.OnRequestFailure(dep.ID, depLatency, isTimeoutErr(callErr), estTokens, estOut)
		if rm.collector != nil {
			rm.collector.RecordDeploymentAttempt(dep.ID, dep.DeploymentName, string(dep.GlobalModel.Provider), dep.GlobalModel.ModelName, depLatency, true)
		}
		if !errors.Is(callErr, context.Canceled) && raceCtx.Err() == nil {
			raceMetaMu.Lock()
			appendFallbackError(meta, depGroup.Alias, dep.ID, callErr)
			raceMetaMu.Unlock()
			rm.recordAttemptFailure(ctx, dep, depGroup, activeTotal, callErr)
		}
		return nil, callErr
	})

	var dropped []string
	if winner != nil {
		dropped = droppedByDep[winner.ID]
	}
	return hedgedChatRaceResult{
		winner:      winner,
		resp:        resp,
		dropped:     dropped,
		raceLatency: time.Since(raceStart).Milliseconds(),
		err:         raceErr,
	}
}

func (rm *ReliabilityManager) executeChatGroupHop(
	ctx context.Context,
	idCtx *domain.IdentityContext,
	req *domain.CanonicalChatRequest,
	decision *RouteDecision,
	meta *ExecutionMeta,
	current queuedHop,
	orgID string,
	estTokens int,
	isBudgeted bool,
	aff *AffinityStore,
	start time.Time,
	lastErr *error,
	skippedDueToUnknownPricing *bool,
) groupHopOutcome[*domain.CanonicalChatResponse] {
	group := current.group
	hopReq := req
	if len(current.overrides) > 0 {
		hopReq = applyFallbackOverrides(req, current.overrides)
	}
	if current.depth > 0 {
		if hopErr := rm.authorizeFallbackHop(ctx, idCtx, group.Alias, estTokens); hopErr != nil {
			*lastErr = hopErr
			logger.WarnContext(ctx, "Fallback model blocked by authorization or quota policy",
				slog.String("component", "router"),
				slog.String("primary_alias", decision.ModelGroup.Alias),
				slog.String("fallback_alias", group.Alias),
				slog.String("error", hopErr.Error()),
			)
			return groupHopOutcome[*domain.CanonicalChatResponse]{err: hopErr}
		}
		meta.FallbackAttempted = true
		setFallbackMetaReason(meta, current.reason)
		logger.WarnContext(ctx, "Cross-provider fallback activated",
			slog.String("component", "router"),
			slog.String("primary_alias", decision.ModelGroup.Alias),
			slog.String("fallback_alias", group.Alias),
			slog.String("fallback_reason", current.reason),
			slog.String("requested_model", req.Model),
		)
	}

	deployments, activeTotal, snap, stageSat, filterErr := rm.getEligibleDeploymentsDetailed(ctx, orgID, group, hopReq, estTokens, nil, false, requestPriorityRank(idCtx, hopReq), nil)
	if filterErr != nil {
		*lastErr = filterErr
		appendFallbackError(meta, group.Alias, "", filterErr)
		if rm.classifyErr(filterErr) == CategoryNonRetryable {
			rm.recordBanditOutcome(orgID, decision, false, time.Since(start).Milliseconds())
			return groupHopOutcome[*domain.CanonicalChatResponse]{handled: true, meta: meta, err: filterErr}
		}
		return groupHopOutcome[*domain.CanonicalChatResponse]{err: filterErr}
	}
	if len(deployments) == 0 {
		if stageSat {
			satErr := saturationGatewayError()
			*lastErr = satErr
			appendFallbackError(meta, group.Alias, "", satErr)
			if !rm.cfg.FallbackOnSaturation {
				rm.recordBanditOutcome(orgID, decision, false, time.Since(start).Milliseconds())
				return groupHopOutcome[*domain.CanonicalChatResponse]{handled: true, meta: meta, err: satErr}
			}
			return groupHopOutcome[*domain.CanonicalChatResponse]{err: satErr}
		}
		return groupHopOutcome[*domain.CanonicalChatResponse]{err: *lastErr}
	}

	if isBudgeted {
		filtered := filterKnownPricing(deployments)
		rm.releaseUnusedProbes(ctx, deployments, filtered)
		if len(filtered) == 0 {
			*skippedDueToUnknownPricing = true
			logger.WarnContext(ctx, "Skipping model group for budgeted caller: all deployments have unverified pricing",
				slog.String("component", "router"),
				slog.String("group_alias", group.Alias),
			)
			return groupHopOutcome[*domain.CanonicalChatResponse]{}
		}
		deployments = filtered
	}

	var affinityDepID, affinityKey string
	if aff != nil {
		affinityDepID, affinityKey = aff.Lookup(ctx, orgID, group.Alias, hopReq, extractPreviousResponseID(hopReq))
	}

	reconcilePriority, prioErr := rm.acquireDynamicPriorityCapacityWithSignals(ctx, idCtx, group, hopReq, deployments, estTokens, snap)
	if prioErr != nil {
		*lastErr = prioErr
		rm.releaseUnusedProbes(ctx, deployments, nil)
		if isPrioritySaturationErr(prioErr) && rm.cfg.FallbackOnSaturation {
			return groupHopOutcome[*domain.CanonicalChatResponse]{err: prioErr}
		}
		rm.recordBanditOutcome(orgID, decision, false, time.Since(start).Milliseconds())
		return groupHopOutcome[*domain.CanonicalChatResponse]{handled: true, meta: meta, err: prioErr}
	}

	tiers := partitionByPriority(deployments)
	retryPolicy := rm.effectiveGroupRetryPolicy(group)
	var groupErr error
	stopGroup := false

	for tierIdx, tierDeployments := range tiers {
		if tierIdx > 0 {
			recordTierStepdown(ctx, meta, group, tierIdx)
		}

		if shouldHedgeGroup(group, hopReq) {
			racers := tierDeployments
			if tierIdx == 0 {
				racers = prioritizeAffinityCandidate(tierDeployments, aff, affinityDepID)
			}
			res := rm.executeChatHedgeRace(ctx, idCtx, hopReq, racers, meta, estTokens, func(_ *domain.Deployment) (*domain.ModelGroup, int) {
				return group, activeTotal
			})
			if res.err == nil && res.resp != nil && res.winner != nil {
				reconcilePriority(res.resp.Usage.TotalTokens)
				rm.releaseUnusedProbes(ctx, deployments, []*domain.Deployment{res.winner})
				rm.pinAffinityOnSuccess(aff, orgID, affinityKey, affinityDepID, res.winner.ID)
				meta.RouteDecision.Reason = "hedged_race_winner"
				meta.WinningDeployment = res.winner
				meta.DroppedParams = res.dropped
				meta.LatencyMs = time.Since(start).Milliseconds()
				rm.recordBanditOutcome(orgID, decision, !meta.FallbackAttempted && !isBanditRefusalResponse(res.resp), res.raceLatency)
				return groupHopOutcome[*domain.CanonicalChatResponse]{handled: true, result: res.resp, meta: meta}
			}
			*lastErr = res.err
			groupErr = res.err
			if rm.classifyErr(res.err) == CategoryNonRetryable {
				rm.releaseUnusedProbes(ctx, deployments, nil)
				rm.recordBanditOutcome(orgID, decision, false, time.Since(start).Milliseconds())
				return groupHopOutcome[*domain.CanonicalChatResponse]{handled: true, meta: meta, err: res.err}
			}
			continue
		}

		tierOut := rm.executeChatTierSequential(
			ctx, idCtx, hopReq, group, decision, meta,
			tierIdx, tierDeployments, deployments, activeTotal,
			orgID, estTokens, retryPolicy, aff, affinityDepID, affinityKey,
			snap, reconcilePriority, start, lastErr, &groupErr,
		)
		if tierOut.handled {
			return tierOut
		}
		if tierOut.stopAll {
			stopGroup = true
		}
		if stopGroup {
			break
		}
	}

	rm.releaseUnusedProbes(ctx, deployments, nil)
	if isPrioritySaturationErr(groupErr) {
		if !rm.cfg.FallbackOnSaturation {
			rm.recordBanditOutcome(orgID, decision, false, time.Since(start).Milliseconds())
			return groupHopOutcome[*domain.CanonicalChatResponse]{handled: true, meta: meta, err: groupErr}
		}
		return groupHopOutcome[*domain.CanonicalChatResponse]{err: groupErr}
	}
	if rm.classifyErr(groupErr) == CategoryNonRetryable && groupErr != nil {
		rm.recordBanditOutcome(orgID, decision, false, time.Since(start).Milliseconds())
		return groupHopOutcome[*domain.CanonicalChatResponse]{handled: true, meta: meta, err: groupErr}
	}
	return groupHopOutcome[*domain.CanonicalChatResponse]{err: groupErr}
}

func (rm *ReliabilityManager) executeChatTierSequential(
	ctx context.Context,
	idCtx *domain.IdentityContext,
	hopReq *domain.CanonicalChatRequest,
	group *domain.ModelGroup,
	decision *RouteDecision,
	meta *ExecutionMeta,
	tierIdx int,
	tierDeployments, allDeployments []*domain.Deployment,
	activeTotal int,
	orgID string,
	estTokens int,
	retryPolicy domain.RetryPolicy,
	aff *AffinityStore,
	affinityDepID, affinityKey string,
	snap *SignalSnapshot,
	reconcilePriority func(int),
	start time.Time,
	lastErr, groupErr *error,
) groupHopOutcome[*domain.CanonicalChatResponse] {
	retryTracker := newRetryBudgetTracker(retryPolicy, len(tierDeployments))
	triedDepIDs := make([]string, 0, len(tierDeployments))
	trippedDepIDs := make(map[string]struct{})
	strategy := resolveEffectiveStrategy(group, hopReq, rm.cfg.AllowStrategyOverride)

	for attempt := 0; ; attempt++ {
		dep := rm.selectNextTierDeployment(tierIdx, attempt, tierDeployments, allDeployments, aff, affinityDepID, triedDepIDs, trippedDepIDs, strategy, snap)
		if dep == nil {
			break
		}
		triedDepIDs = append(triedDepIDs, dep.ID)

		if attempt > 0 {
			meta.RetryCount++
			logger.WarnContext(ctx, "Intra-group retry attempt triggered",
				slog.String("component", "router"),
				slog.Int("attempt", attempt),
				slog.String("group_alias", group.Alias),
				slog.String("deployment_id", dep.ID),
				slog.String("model", dep.GlobalModel.ModelName),
			)
		}

		rm.hydrateCredential(dep)
		adp, adpErr := rm.registry.Get(dep.GlobalModel.Provider)
		if adpErr != nil {
			*lastErr = adpErr
			*groupErr = adpErr
			appendFallbackError(meta, group.Alias, dep.ID, adpErr)
			trippedDepIDs[dep.ID] = struct{}{}
			if len(filterOutDepIDs(tierDeployments, trippedDepIDs)) == 0 {
				break
			}
			continue
		}
		if opErr := checkDeploymentOperation(adp, dep, domain.OperationChat); opErr != nil {
			*lastErr = opErr
			*groupErr = opErr
			appendFallbackError(meta, group.Alias, dep.ID, opErr)
			trippedDepIDs[dep.ID] = struct{}{}
			if len(filterOutDepIDs(tierDeployments, trippedDepIDs)) == 0 {
				break
			}
			continue
		}

		dropEnabled := resolveDropUnsupportedParams(rm.cfg.DropUnsupportedParams, group, hopReq)
		reqCopy, dropped := sanitizeRequestForDeployment(hopReq, dep, dropEnabled)
		reqCopy.ResolvedModel = dep.GlobalModel.ModelName

		reconcilePTU, ptuErr := rm.acquireDeploymentPTU(ctx, idCtx, dep, estTokens)
		if ptuErr != nil {
			*lastErr = ptuErr
			*groupErr = ptuErr
			appendFallbackError(meta, group.Alias, dep.ID, ptuErr)
			trippedDepIDs[dep.ID] = struct{}{}
			if len(filterOutDepIDs(tierDeployments, trippedDepIDs)) == 0 {
				break
			}
			continue
		}

		hasUntriedSibling := len(filterOutDepIDs(filterUntried(tierDeployments, triedDepIDs), trippedDepIDs)) > 0
		relSlot, slotOK := rm.acquireDeploymentSlot(ctx, dep, requestPriorityRank(idCtx, hopReq), !hasUntriedSibling)
		if !slotOK {
			satErr := saturationGatewayError()
			*lastErr = satErr
			*groupErr = satErr
			appendFallbackError(meta, group.Alias, dep.ID, satErr)
			trippedDepIDs[dep.ID] = struct{}{}
			if len(filterOutDepIDs(tierDeployments, trippedDepIDs)) == 0 {
				break
			}
			continue
		}

		estOut := requestEstimatedOutputTokens(&reqCopy)
		depStart := time.Now()
		rm.loadBalancer.OnRequestStartWithTokens(dep.ID, estTokens, estOut)
		capture := rm.shouldCaptureContent()
		spanCtx, span := rm.startGenAIClientSpan(ctx, "chat", dep, buildChatStartOpts(&reqCopy, capture))
		depCtx, depCancel := withDeploymentTimeout(spanCtx, dep)
		markProviderDispatch(depCtx, dep)
		resp, callErr := adp.ChatCompletion(depCtx, dep, &reqCopy)
		depCancel()
		relSlot()
		rm.finishGenAIClientSpanWithOpts(spanCtx, span, buildChatFinishOpts(resp, meta.RetryCount, meta.FallbackAttempted, capture, callErr))
		depLatency := time.Since(depStart).Milliseconds()

		if callErr == nil && resp != nil {
			reconcilePTU(resp.Usage.TotalTokens)
			reconcilePriority(resp.Usage.TotalTokens)
			rm.loadBalancer.OnRequestEndWithUsage(dep.ID, depLatency, 0, estTokens, estOut, resp.Usage.PromptTokens, resp.Usage.CompletionTokens)
			rm.recordSuccess(ctx, dep)
			rm.releaseUnusedProbes(ctx, allDeployments, []*domain.Deployment{dep})
			rm.pinAffinityOnSuccess(aff, orgID, affinityKey, affinityDepID, dep.ID)
			if rm.collector != nil {
				rm.collector.RecordDeploymentAttempt(dep.ID, dep.DeploymentName, string(dep.GlobalModel.Provider), dep.GlobalModel.ModelName, depLatency, false)
			}
			meta.WinningDeployment = dep
			meta.DroppedParams = dropped
			meta.LatencyMs = time.Since(start).Milliseconds()
			rm.recordBanditOutcome(orgID, decision, !meta.FallbackAttempted && !isBanditRefusalResponse(resp), depLatency)
			return groupHopOutcome[*domain.CanonicalChatResponse]{handled: true, result: resp, meta: meta}
		}

		rm.loadBalancer.OnRequestFailure(dep.ID, depLatency, isTimeoutErr(callErr), estTokens, estOut)
		if rm.collector != nil {
			rm.collector.RecordDeploymentAttempt(dep.ID, dep.DeploymentName, string(dep.GlobalModel.Provider), dep.GlobalModel.ModelName, depLatency, true)
		}
		out := rm.handleAttemptErrorWithPolicy(ctx, dep, group, activeTotal, callErr, retryTracker, attempt, hasUntriedSibling)
		*lastErr = out.normalizedErr
		*groupErr = out.normalizedErr
		appendFallbackError(meta, group.Alias, dep.ID, out.normalizedErr)
		if out.tripped {
			trippedDepIDs[dep.ID] = struct{}{}
		}
		if out.terminalErr != nil {
			rm.releaseUnusedProbes(ctx, allDeployments, []*domain.Deployment{dep})
			rm.recordBanditOutcome(orgID, decision, false, time.Since(start).Milliseconds())
			return groupHopOutcome[*domain.CanonicalChatResponse]{handled: true, meta: meta, err: out.terminalErr}
		}
		if out.stopGroup {
			return groupHopOutcome[*domain.CanonicalChatResponse]{stopAll: true}
		}
		if out.stopTier {
			break
		}
	}
	return groupHopOutcome[*domain.CanonicalChatResponse]{}
}

type streamExecutionState struct {
	acc                        *streamAccumulator
	failedDepIDs               map[string]struct{}
	continuationCount          int
	firstChunkSentToClient     bool
	partialUsage               *domain.TokenUsage
	lastErr                    error
	skippedDueToUnknownPricing bool
}

func mergePartialStreamUsage(acc *streamAccumulator, partialUsage, chunkUsage, raceOrCallUsage *domain.TokenUsage) *domain.TokenUsage {
	attemptUsage := chunkUsage
	if attemptUsage == nil && raceOrCallUsage != nil && (raceOrCallUsage.PromptTokens > 0 || raceOrCallUsage.CompletionTokens > 0 || raceOrCallUsage.TotalTokens > 0) {
		u := *raceOrCallUsage
		attemptUsage = &u
	}
	if attemptUsage == nil {
		return partialUsage
	}
	if partialUsage == nil {
		return attemptUsage
	}
	return acc.MergeUsage(partialUsage, attemptUsage)
}

// ExecuteStream routes and executes a streaming SSE chat completion.
// Retries, fallbacks, hedged racing, and (when enabled and safe) assistant-prefill mid-stream continuations
// happen transparently across eligible deployments.
func (rm *ReliabilityManager) ExecuteStream(
	ctx context.Context,
	idCtx *domain.IdentityContext,
	req *domain.CanonicalChatRequest,
	onChunk adapter.StreamChunkHandler,
	onSelected func(dep *domain.Deployment),
) (*domain.TokenUsage, *ExecutionMeta, error) {
	ctx = network.WithStreamingRequest(ctx)
	releaseSlot, schedErr := rm.acquireSchedulerSlot(ctx, req)
	if schedErr != nil {
		return nil, nil, schedErr
	}
	defer releaseSlot()

	start := time.Now()
	ctx, orgID, isBudgeted := extractExecutionOrgID(ctx, idCtx)
	state := &streamExecutionState{
		acc:          &streamAccumulator{},
		failedDepIDs: make(map[string]struct{}),
	}
	state.acc.ObserveRequest(req)

	var decision *RouteDecision
	var initialQueue []queuedHop

	routeStart := time.Now()
	if commaAliases := ParseCommaSeparatedModels(req.Model); len(commaAliases) >= 2 {
		var fastUsage *domain.TokenUsage
		var fastMeta *ExecutionMeta
		var err error
		decision, initialQueue, fastUsage, fastMeta, err = rm.prepareCommaSeparatedStream(
			ctx, idCtx, req, commaAliases, orgID, isBudgeted, start, routeStart, state, onChunk, onSelected,
		)
		if err != nil || fastUsage != nil || fastMeta != nil {
			return fastUsage, fastMeta, err
		}
	} else {
		var err error
		decision, err = rm.intelligentRouter.ResolveGroup(ctx, orgID, req)
		if err != nil {
			return nil, nil, err
		}
	}

	meta := initRouteDecisionMeta(decision, routeStart)
	maxDepth := rm.effectiveMaxFallbackDepth()
	queue, visited := initHopQueue(decision.ModelGroup, initialQueue)
	aff := rm.getAffinityStore()

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		if current.group == nil {
			continue
		}

		hopOut := rm.executeStreamGroupHop(
			ctx, idCtx, req, decision, meta, current,
			orgID, isBudgeted, aff, start, state, onChunk, onSelected,
		)
		if hopOut.handled {
			return hopOut.result, hopOut.meta, hopOut.err
		}
		if hopOut.requeueSame {
			queue = append([]queuedHop{current}, queue...)
			continue
		}

		cat := rm.classifyErr(hopOut.err)
		if isPrioritySaturationErr(hopOut.err) {
			cat = CategorySaturation
		}
		queue = rm.enqueueFallbacks(ctx, queue, current, cat, maxDepth, visited)
	}

	if state.firstChunkSentToClient {
		meta.LatencyMs = time.Since(start).Milliseconds()
		rm.recordBanditOutcome(orgID, decision, false, meta.LatencyMs)
		return state.acc.MergeUsage(state.partialUsage, nil), meta, state.lastErr
	}

	if state.lastErr == nil {
		state.lastErr = unavailableChatError(isBudgeted, state.skippedDueToUnknownPricing, "All primary and fallback streaming deployments are unavailable")
	}
	rm.recordBanditOutcome(orgID, decision, false, time.Since(start).Milliseconds())
	return nil, meta, state.lastErr
}

func (rm *ReliabilityManager) prepareCommaSeparatedStream(
	ctx context.Context,
	idCtx *domain.IdentityContext,
	req *domain.CanonicalChatRequest,
	commaAliases []string,
	orgID string,
	isBudgeted bool,
	start, routeStart time.Time,
	state *streamExecutionState,
	onChunk adapter.StreamChunkHandler,
	onSelected func(dep *domain.Deployment),
) (*RouteDecision, []queuedHop, *domain.TokenUsage, *ExecutionMeta, error) {
	estTokens := ratelimit.EstimateRequestTokens(req)
	pool, poolErr := rm.resolveCommaSeparatedCandidates(ctx, orgID, req, commaAliases, estTokens, isBudgeted, false)
	if poolErr != nil {
		return nil, nil, nil, nil, poolErr
	}
	state.skippedDueToUnknownPricing = pool.skippedBudget
	state.lastErr = pool.lastErr
	primary := pool.groups[0]
	decision := &RouteDecision{
		RequestedModel:   req.Model,
		TargetGroupAlias: primary.Alias,
		ModelGroup:       primary,
		Reason:           "hedged_race_winner",
	}
	meta := initRouteDecisionMeta(decision, routeStart)

	if len(pool.candidates) > 0 {
		res := rm.executeStreamHedgeRace(
			ctx, idCtx, req, pool.candidates, meta, estTokens, state, onChunk, onSelected,
			func(dep *domain.Deployment) (*domain.ModelGroup, int) {
				depGroup := pool.groupByDep[dep.ID]
				if depGroup == nil {
					depGroup = primary
				}
				return depGroup, pool.activeByGroup[depGroup.ID]
			},
		)
		if res.err == nil && res.winner != nil {
			rm.releaseUnusedProbes(ctx, pool.candidates, []*domain.Deployment{res.winner})
			if wg := pool.groupByDep[res.winner.ID]; wg != nil {
				meta.RouteDecision.TargetGroupAlias = wg.Alias
				meta.RouteDecision.ModelGroup = wg
			}
			meta.RouteDecision.Reason = "hedged_race_winner"
			meta.WinningDeployment = res.winner
			meta.DroppedParams = res.dropped
			meta.LatencyMs = time.Since(start).Milliseconds()
			return decision, nil, state.acc.MergeUsage(state.partialUsage, res.usage), meta, nil
		}
		rm.releaseUnusedProbes(ctx, pool.candidates, nil)
		if res.clientChunkErr != nil {
			meta.WinningDeployment = res.winner
			meta.LatencyMs = time.Since(start).Milliseconds()
			return decision, nil, state.acc.MergeUsage(state.partialUsage, res.usage), meta, res.err
		}
		if state.firstChunkSentToClient && res.winner != nil {
			state.failedDepIDs[res.winner.ID] = struct{}{}
			attemptUsage := res.chunkUsageThisAttempt
			if attemptUsage == nil && res.usage != nil && (res.usage.PromptTokens > 0 || res.usage.CompletionTokens > 0 || res.usage.TotalTokens > 0) {
				u := *res.usage
				attemptUsage = &u
			}
			state.partialUsage = attemptUsage
			meta.WinningDeployment = res.winner
			if !state.acc.CanContinue(rm.cfg, state.continuationCount, res.err) {
				meta.LatencyMs = time.Since(start).Milliseconds()
				return decision, nil, state.acc.MergeUsage(state.partialUsage, nil), meta, res.err
			}
			if _, ok := state.acc.BuildContinuationRequest(req); !ok {
				meta.LatencyMs = time.Since(start).Milliseconds()
				return decision, nil, state.acc.MergeUsage(state.partialUsage, nil), meta, nil
			}
			state.continuationCount++
		}
		if res.err != nil {
			state.lastErr = res.err
		}
	}

	if state.lastErr != nil && rm.classifyErr(state.lastErr) == CategoryNonRetryable {
		return decision, nil, nil, meta, state.lastErr
	}
	visited := make(map[string]struct{})
	if key := groupVisitKey(primary); key != "" {
		visited[key] = struct{}{}
	}
	var initialQueue []queuedHop
	if state.firstChunkSentToClient {
		initialQueue = append([]queuedHop{{group: primary, depth: 0}}, rm.enqueueFallbacks(ctx, nil, queuedHop{group: primary, depth: 0}, rm.classifyErr(state.lastErr), rm.effectiveMaxFallbackDepth(), visited)...)
	} else {
		initialQueue = rm.enqueueFallbacks(ctx, nil, queuedHop{group: primary, depth: 0}, rm.classifyErr(state.lastErr), rm.effectiveMaxFallbackDepth(), visited)
	}
	if len(initialQueue) == 0 {
		if state.firstChunkSentToClient {
			meta.LatencyMs = time.Since(start).Milliseconds()
			return decision, nil, state.acc.MergeUsage(state.partialUsage, nil), meta, state.lastErr
		}
		if state.lastErr == nil {
			state.lastErr = unavailableChatError(isBudgeted, state.skippedDueToUnknownPricing, "All primary and fallback streaming deployments are unavailable")
		}
		return decision, nil, nil, meta, state.lastErr
	}
	return decision, initialQueue, nil, nil, nil
}

func (rm *ReliabilityManager) executeStreamHedgeRace(
	ctx context.Context,
	idCtx *domain.IdentityContext,
	req *domain.CanonicalChatRequest,
	racers []*domain.Deployment,
	meta *ExecutionMeta,
	estTokens int,
	state *streamExecutionState,
	onChunk adapter.StreamChunkHandler,
	onSelected func(dep *domain.Deployment),
	groupForDep func(dep *domain.Deployment) (*domain.ModelGroup, int),
) hedgedStreamRaceResult {
	for _, r := range racers {
		rm.hydrateCredential(r)
	}
	raceStart := time.Now()
	var chunkUsageThisAttempt *domain.TokenUsage
	var clientChunkErr error
	var raceMetaMu sync.Mutex
	droppedByDep := make(map[string][]string, len(racers))

	wrappedOnSelected := func(dep *domain.Deployment) {
		if dep != nil {
			raceMetaMu.Lock()
			dropped := droppedByDep[dep.ID]
			raceMetaMu.Unlock()
			notifyDroppedParams(ctx, dropped)
		}
		if onSelected != nil {
			onSelected(dep)
		}
	}

	winner, raceUsage, raceErr := RaceStreamAttempts(ctx, racers, rm.buildHedgeConfig(req), func(racerCtx context.Context, dep *domain.Deployment, emit adapter.StreamChunkHandler) (*domain.TokenUsage, error) {
		depGroup, activeTotal := groupForDep(dep)
		adp, adpErr := rm.registry.Get(dep.GlobalModel.Provider)
		if adpErr != nil {
			raceMetaMu.Lock()
			appendFallbackError(meta, depGroup.Alias, dep.ID, adpErr)
			raceMetaMu.Unlock()
			return nil, adpErr
		}
		if opErr := checkDeploymentOperation(adp, dep, domain.OperationChat); opErr != nil {
			raceMetaMu.Lock()
			appendFallbackError(meta, depGroup.Alias, dep.ID, opErr)
			raceMetaMu.Unlock()
			return nil, opErr
		}
		relSlot, slotOK := rm.acquireDeploymentSlot(racerCtx, dep, requestPriorityRank(idCtx, req), false)
		if !slotOK {
			satErr := saturationGatewayError()
			raceMetaMu.Lock()
			appendFallbackError(meta, depGroup.Alias, dep.ID, satErr)
			raceMetaMu.Unlock()
			return nil, satErr
		}
		defer relSlot()

		dropEnabled := resolveDropUnsupportedParams(rm.cfg.DropUnsupportedParams, depGroup, req)
		reqCopy, dropped := sanitizeRequestForDeployment(req, dep, dropEnabled)
		reqCopy.ResolvedModel = dep.GlobalModel.ModelName
		if len(dropped) > 0 {
			raceMetaMu.Lock()
			droppedByDep[dep.ID] = dropped
			raceMetaMu.Unlock()
		}

		estOut := requestEstimatedOutputTokens(&reqCopy)
		depStart := time.Now()
		rm.loadBalancer.OnRequestStartWithTokens(dep.ID, estTokens, estOut)
		capture := rm.shouldCaptureContent()
		spanCtx, span := rm.startGenAIClientSpan(racerCtx, "chat", dep, buildChatStartOpts(&reqCopy, capture))
		depCtx, depCancel := withDeploymentTimeout(spanCtx, dep)
		markProviderDispatch(depCtx, dep)
		spanCap := streamSpanCapture{captureContent: capture}
		u, callErr := adp.StreamChatCompletion(depCtx, dep, &reqCopy, func(chunk *domain.CanonicalStreamChunk) error {
			recordGenAISpanFirstToken(spanCtx, span)
			spanCap.observeChunk(chunk)
			return emit(chunk)
		})
		depCancel()
		rm.finishGenAIClientSpanWithOpts(spanCtx, span, genAIClientFinishOpts{
			responseModel:     spanCap.responseModel,
			responseID:        spanCap.responseID,
			finishReasons:     spanCap.finishReasons,
			usage:             u,
			retryCount:        meta.RetryCount,
			fallbackAttempted: meta.FallbackAttempted,
			outputText:        spanCap.outputBuf.String(),
			err:               callErr,
		})
		depLatency := time.Since(depStart).Milliseconds()

		if callErr == nil {
			inTok, outTok := 0, 0
			if u != nil {
				inTok, outTok = u.PromptTokens, u.CompletionTokens
			}
			rm.loadBalancer.OnRequestEndWithUsage(dep.ID, depLatency, meta.TTFTMs, estTokens, estOut, inTok, outTok)
			rm.recordSuccess(ctx, dep)
			return u, nil
		}

		rm.loadBalancer.OnRequestFailure(dep.ID, depLatency, isTimeoutErr(callErr), estTokens, estOut)
		if !errors.Is(callErr, context.Canceled) && racerCtx.Err() == nil {
			raceMetaMu.Lock()
			appendFallbackError(meta, depGroup.Alias, dep.ID, callErr)
			raceMetaMu.Unlock()
			rm.recordAttemptFailure(ctx, dep, depGroup, activeTotal, callErr)
		}
		return u, callErr
	}, func(chunk *domain.CanonicalStreamChunk) error {
		if onChunk != nil {
			if cerr := onChunk(chunk); cerr != nil {
				clientChunkErr = cerr
				return cerr
			}
		}
		if !state.firstChunkSentToClient {
			state.firstChunkSentToClient = true
			meta.TTFTMs = time.Since(raceStart).Milliseconds()
		}
		if chunk != nil && chunk.Usage != nil {
			u := *chunk.Usage
			chunkUsageThisAttempt = &u
		}
		state.acc.ObserveChunk(chunk)
		return nil
	}, wrappedOnSelected)

	var dropped []string
	if winner != nil {
		dropped = droppedByDep[winner.ID]
	}
	return hedgedStreamRaceResult{
		winner:                winner,
		usage:                 raceUsage,
		chunkUsageThisAttempt: chunkUsageThisAttempt,
		clientChunkErr:        clientChunkErr,
		dropped:               dropped,
		raceLatency:           time.Since(raceStart).Milliseconds(),
		err:                   raceErr,
	}
}

func (rm *ReliabilityManager) streamErrorOutcome(
	state *streamExecutionState,
	meta *ExecutionMeta,
	orgID string,
	decision *RouteDecision,
	start time.Time,
	err error,
) groupHopOutcome[*domain.TokenUsage] {
	rm.recordBanditOutcome(orgID, decision, false, time.Since(start).Milliseconds())
	if state.firstChunkSentToClient {
		meta.LatencyMs = time.Since(start).Milliseconds()
		return groupHopOutcome[*domain.TokenUsage]{
			handled: true,
			result:  state.acc.MergeUsage(state.partialUsage, nil),
			meta:    meta,
			err:     err,
		}
	}
	return groupHopOutcome[*domain.TokenUsage]{handled: true, meta: meta, err: err}
}

func (rm *ReliabilityManager) executeStreamGroupHop(
	ctx context.Context,
	idCtx *domain.IdentityContext,
	req *domain.CanonicalChatRequest,
	decision *RouteDecision,
	meta *ExecutionMeta,
	current queuedHop,
	orgID string,
	isBudgeted bool,
	aff *AffinityStore,
	start time.Time,
	state *streamExecutionState,
	onChunk adapter.StreamChunkHandler,
	onSelected func(dep *domain.Deployment),
) groupHopOutcome[*domain.TokenUsage] {
	group := current.group
	hopBaseReq := req
	if len(current.overrides) > 0 {
		hopBaseReq = applyFallbackOverrides(req, current.overrides)
	}
	if current.depth > 0 {
		if hopErr := rm.authorizeFallbackHop(ctx, idCtx, group.Alias, ratelimit.EstimateRequestTokens(hopBaseReq)); hopErr != nil {
			state.lastErr = hopErr
			logger.WarnContext(ctx, "Streaming fallback model blocked by authorization or quota policy",
				slog.String("component", "router"),
				slog.String("primary_alias", decision.ModelGroup.Alias),
				slog.String("fallback_alias", group.Alias),
				slog.String("error", hopErr.Error()),
			)
			return groupHopOutcome[*domain.TokenUsage]{err: hopErr}
		}
		meta.FallbackAttempted = true
		setFallbackMetaReason(meta, current.reason)
		logger.WarnContext(ctx, "Cross-provider fallback activated",
			slog.String("component", "router"),
			slog.String("primary_alias", decision.ModelGroup.Alias),
			slog.String("fallback_alias", group.Alias),
			slog.String("fallback_reason", current.reason),
			slog.String("requested_model", req.Model),
		)
	}

	requirePrefill := state.firstChunkSentToClient
	attemptReq := hopBaseReq
	if requirePrefill {
		contReq, ok := state.acc.BuildContinuationRequest(hopBaseReq)
		if !ok {
			// Token cap reached after already emitted output: finish cleanly with merged usage.
			meta.LatencyMs = time.Since(start).Milliseconds()
			return groupHopOutcome[*domain.TokenUsage]{
				handled: true,
				result:  state.acc.MergeUsage(state.partialUsage, nil),
				meta:    meta,
			}
		}
		attemptReq = contReq
	}
	estTokens := ratelimit.EstimateRequestTokens(attemptReq)

	deployments, activeTotal, snap, stageSat, filterErr := rm.getEligibleDeploymentsDetailed(ctx, orgID, group, attemptReq, estTokens, state.failedDepIDs, requirePrefill, requestPriorityRank(idCtx, attemptReq), nil)
	if filterErr != nil {
		state.lastErr = filterErr
		appendFallbackError(meta, group.Alias, "", filterErr)
		if rm.classifyErr(filterErr) == CategoryNonRetryable {
			return rm.streamErrorOutcome(state, meta, orgID, decision, start, filterErr)
		}
		return groupHopOutcome[*domain.TokenUsage]{err: filterErr}
	}
	if len(deployments) == 0 {
		if stageSat {
			satErr := saturationGatewayError()
			state.lastErr = satErr
			appendFallbackError(meta, group.Alias, "", satErr)
			if !rm.cfg.FallbackOnSaturation {
				return rm.streamErrorOutcome(state, meta, orgID, decision, start, satErr)
			}
			return groupHopOutcome[*domain.TokenUsage]{err: satErr}
		}
		return groupHopOutcome[*domain.TokenUsage]{err: state.lastErr}
	}

	if isBudgeted {
		filtered := filterKnownPricing(deployments)
		rm.releaseUnusedProbes(ctx, deployments, filtered)
		if len(filtered) == 0 {
			state.skippedDueToUnknownPricing = true
			logger.WarnContext(ctx, "Skipping model group for budgeted caller: all deployments have unverified pricing",
				slog.String("component", "router"),
				slog.String("group_alias", group.Alias),
			)
			return groupHopOutcome[*domain.TokenUsage]{}
		}
		deployments = filtered
	}

	var affinityDepID, affinityKey string
	if aff != nil && !requirePrefill {
		affinityDepID, affinityKey = aff.Lookup(ctx, orgID, group.Alias, attemptReq, extractPreviousResponseID(attemptReq))
	}

	reconcilePriority, prioErr := rm.acquireDynamicPriorityCapacityWithSignals(ctx, idCtx, group, attemptReq, deployments, estTokens, snap)
	if prioErr != nil {
		state.lastErr = prioErr
		rm.releaseUnusedProbes(ctx, deployments, nil)
		if isPrioritySaturationErr(prioErr) && rm.cfg.FallbackOnSaturation {
			return groupHopOutcome[*domain.TokenUsage]{err: prioErr}
		}
		return rm.streamErrorOutcome(state, meta, orgID, decision, start, prioErr)
	}

	tiers := partitionByPriority(deployments)
	retryPolicy := rm.effectiveGroupRetryPolicy(group)
	var groupErr error
	continueSameGroup := false

	for tierIdx, tierDeployments := range tiers {
		if tierIdx > 0 {
			recordTierStepdown(ctx, meta, group, tierIdx)
		}

		if !state.firstChunkSentToClient && shouldHedgeGroup(group, hopBaseReq) {
			racers := tierDeployments
			if tierIdx == 0 {
				racers = prioritizeAffinityCandidate(tierDeployments, aff, affinityDepID)
			}
			res := rm.executeStreamHedgeRace(
				ctx, idCtx, attemptReq, racers, meta, estTokens, state, onChunk, onSelected,
				func(_ *domain.Deployment) (*domain.ModelGroup, int) {
					return group, activeTotal
				},
			)
			if res.err == nil && res.winner != nil {
				mergedUsage := state.acc.MergeUsage(state.partialUsage, res.usage)
				if mergedUsage != nil {
					reconcilePriority(mergedUsage.TotalTokens)
				}
				rm.releaseUnusedProbes(ctx, deployments, []*domain.Deployment{res.winner})
				rm.pinAffinityOnSuccess(aff, orgID, affinityKey, affinityDepID, res.winner.ID)
				meta.RouteDecision.Reason = "hedged_race_winner"
				meta.WinningDeployment = res.winner
				meta.DroppedParams = res.dropped
				meta.LatencyMs = time.Since(start).Milliseconds()
				rm.recordBanditOutcome(orgID, decision, !meta.FallbackAttempted, res.raceLatency)
				return groupHopOutcome[*domain.TokenUsage]{handled: true, result: mergedUsage, meta: meta}
			}
			if res.clientChunkErr != nil {
				rm.releaseUnusedProbes(ctx, deployments, nil)
				meta.WinningDeployment = res.winner
				meta.LatencyMs = time.Since(start).Milliseconds()
				rm.recordBanditOutcome(orgID, decision, false, meta.LatencyMs)
				return groupHopOutcome[*domain.TokenUsage]{
					handled: true,
					result:  state.acc.MergeUsage(state.partialUsage, res.usage),
					meta:    meta,
					err:     res.err,
				}
			}
			if state.firstChunkSentToClient && res.winner != nil {
				state.failedDepIDs[res.winner.ID] = struct{}{}
				state.partialUsage = mergePartialStreamUsage(state.acc, state.partialUsage, res.chunkUsageThisAttempt, res.usage)
				meta.WinningDeployment = res.winner
				if !state.acc.CanContinue(rm.cfg, state.continuationCount, res.err) {
					rm.releaseUnusedProbes(ctx, deployments, nil)
					meta.LatencyMs = time.Since(start).Milliseconds()
					rm.recordBanditOutcome(orgID, decision, false, meta.LatencyMs)
					return groupHopOutcome[*domain.TokenUsage]{
						handled: true,
						result:  state.acc.MergeUsage(state.partialUsage, nil),
						meta:    meta,
						err:     res.err,
					}
				}
				if _, ok := state.acc.BuildContinuationRequest(hopBaseReq); !ok {
					rm.releaseUnusedProbes(ctx, deployments, nil)
					meta.LatencyMs = time.Since(start).Milliseconds()
					rm.recordBanditOutcome(orgID, decision, !meta.FallbackAttempted, meta.LatencyMs)
					return groupHopOutcome[*domain.TokenUsage]{
						handled: true,
						result:  state.acc.MergeUsage(state.partialUsage, nil),
						meta:    meta,
					}
				}
				state.continuationCount++
				state.lastErr = res.err
				groupErr = res.err
				continueSameGroup = true
				break
			}
			state.lastErr = res.err
			groupErr = res.err
			if rm.classifyErr(res.err) == CategoryNonRetryable {
				rm.releaseUnusedProbes(ctx, deployments, nil)
				rm.recordBanditOutcome(orgID, decision, false, time.Since(start).Milliseconds())
				return groupHopOutcome[*domain.TokenUsage]{handled: true, meta: meta, err: res.err}
			}
			continue
		}

		tierOut := rm.executeStreamTierSequential(
			ctx, idCtx, hopBaseReq, attemptReq, requirePrefill, group, decision, meta,
			tierIdx, tierDeployments, deployments, activeTotal,
			orgID, estTokens, retryPolicy, aff, affinityDepID, affinityKey,
			snap, reconcilePriority, start, state, onChunk, onSelected, &groupErr,
		)
		if tierOut.handled {
			return tierOut
		}
		if tierOut.requeueSame {
			continueSameGroup = true
			break
		}
		if tierOut.stopAll {
			break
		}
	}

	rm.releaseUnusedProbes(ctx, deployments, nil)
	if continueSameGroup {
		return groupHopOutcome[*domain.TokenUsage]{requeueSame: true, err: groupErr}
	}
	if isPrioritySaturationErr(groupErr) {
		if !rm.cfg.FallbackOnSaturation {
			return rm.streamErrorOutcome(state, meta, orgID, decision, start, groupErr)
		}
		return groupHopOutcome[*domain.TokenUsage]{err: groupErr}
	}
	if rm.classifyErr(groupErr) == CategoryNonRetryable && groupErr != nil {
		return rm.streamErrorOutcome(state, meta, orgID, decision, start, groupErr)
	}
	return groupHopOutcome[*domain.TokenUsage]{err: groupErr}
}

func (rm *ReliabilityManager) executeStreamTierSequential(
	ctx context.Context,
	idCtx *domain.IdentityContext,
	hopBaseReq, attemptReq *domain.CanonicalChatRequest,
	requirePrefill bool,
	group *domain.ModelGroup,
	decision *RouteDecision,
	meta *ExecutionMeta,
	tierIdx int,
	tierDeployments, allDeployments []*domain.Deployment,
	activeTotal int,
	orgID string,
	estTokens int,
	retryPolicy domain.RetryPolicy,
	aff *AffinityStore,
	affinityDepID, affinityKey string,
	snap *SignalSnapshot,
	reconcilePriority func(int),
	start time.Time,
	state *streamExecutionState,
	onChunk adapter.StreamChunkHandler,
	onSelected func(dep *domain.Deployment),
	groupErr *error,
) groupHopOutcome[*domain.TokenUsage] {
	retryTracker := newRetryBudgetTracker(retryPolicy, len(tierDeployments))
	triedDepIDs := make([]string, 0, len(tierDeployments))
	trippedDepIDs := make(map[string]struct{})
	strategy := resolveEffectiveStrategy(group, attemptReq, rm.cfg.AllowStrategyOverride)

	for attempt := 0; ; attempt++ {
		dep := rm.selectNextTierDeployment(tierIdx, attempt, tierDeployments, allDeployments, aff, affinityDepID, triedDepIDs, trippedDepIDs, strategy, snap)
		if dep == nil {
			break
		}
		triedDepIDs = append(triedDepIDs, dep.ID)

		if attempt > 0 && !state.firstChunkSentToClient {
			meta.RetryCount++
			logger.WarnContext(ctx, "Intra-group retry attempt triggered",
				slog.String("component", "router"),
				slog.Int("attempt", attempt),
				slog.String("group_alias", group.Alias),
				slog.String("deployment_id", dep.ID),
				slog.String("model", dep.GlobalModel.ModelName),
			)
		}

		rm.hydrateCredential(dep)
		adp, adpErr := rm.registry.Get(dep.GlobalModel.Provider)
		if adpErr != nil {
			state.lastErr = adpErr
			*groupErr = adpErr
			appendFallbackError(meta, group.Alias, dep.ID, adpErr)
			trippedDepIDs[dep.ID] = struct{}{}
			if len(filterOutDepIDs(tierDeployments, trippedDepIDs)) == 0 {
				break
			}
			continue
		}
		if opErr := checkDeploymentOperation(adp, dep, domain.OperationChat); opErr != nil {
			state.lastErr = opErr
			*groupErr = opErr
			appendFallbackError(meta, group.Alias, dep.ID, opErr)
			trippedDepIDs[dep.ID] = struct{}{}
			if len(filterOutDepIDs(tierDeployments, trippedDepIDs)) == 0 {
				break
			}
			continue
		}

		dropEnabled := resolveDropUnsupportedParams(rm.cfg.DropUnsupportedParams, group, attemptReq)
		reqCopy, dropped := sanitizeRequestForDeployment(attemptReq, dep, dropEnabled)
		reqCopy.ResolvedModel = dep.GlobalModel.ModelName

		reconcilePTU, ptuErr := rm.acquireDeploymentPTU(ctx, idCtx, dep, estTokens)
		if ptuErr != nil {
			state.lastErr = ptuErr
			*groupErr = ptuErr
			appendFallbackError(meta, group.Alias, dep.ID, ptuErr)
			trippedDepIDs[dep.ID] = struct{}{}
			if len(filterOutDepIDs(tierDeployments, trippedDepIDs)) == 0 {
				break
			}
			continue
		}

		hasUntriedSibling := len(filterOutDepIDs(filterUntried(tierDeployments, triedDepIDs), trippedDepIDs)) > 0
		relSlot, slotOK := rm.acquireDeploymentSlot(ctx, dep, requestPriorityRank(idCtx, attemptReq), !hasUntriedSibling)
		if !slotOK {
			satErr := saturationGatewayError()
			state.lastErr = satErr
			*groupErr = satErr
			appendFallbackError(meta, group.Alias, dep.ID, satErr)
			trippedDepIDs[dep.ID] = struct{}{}
			if len(filterOutDepIDs(tierDeployments, trippedDepIDs)) == 0 {
				break
			}
			continue
		}

		if !state.firstChunkSentToClient {
			notifyDroppedParams(ctx, dropped)
			if onSelected != nil {
				onSelected(dep)
			}
		}

		estOut := requestEstimatedOutputTokens(&reqCopy)
		depStart := time.Now()
		attemptEmittedChunk := false
		var chunkUsageThisAttempt *domain.TokenUsage
		var clientChunkErr error
		rm.loadBalancer.OnRequestStartWithTokens(dep.ID, estTokens, estOut)

		capture := rm.shouldCaptureContent()
		spanCtx, span := rm.startGenAIClientSpan(ctx, "chat", dep, buildChatStartOpts(&reqCopy, capture))
		if requirePrefill {
			attrs := trace.WithAttributes(
				attribute.Int("continuation.attempt", state.continuationCount),
				attribute.String("deployment.id", dep.ID),
			)
			span.AddEvent("router.stream_continuation", attrs)
			if parentSpan := trace.SpanFromContext(ctx); parentSpan.SpanContext().IsValid() {
				parentSpan.AddEvent("router.stream_continuation", attrs)
			}
		}
		depCtx, depCancel := withDeploymentTimeout(spanCtx, dep)
		markProviderDispatch(depCtx, dep)
		spanCap := streamSpanCapture{captureContent: capture}
		usage, callErr := adp.StreamChatCompletion(depCtx, dep, &reqCopy, func(chunk *domain.CanonicalStreamChunk) error {
			if cerr := onChunk(chunk); cerr != nil {
				clientChunkErr = cerr
				return cerr
			}
			if !state.firstChunkSentToClient {
				state.firstChunkSentToClient = true
				meta.TTFTMs = time.Since(depStart).Milliseconds()
				recordGenAISpanFirstToken(spanCtx, span)
			}
			attemptEmittedChunk = true
			spanCap.observeChunk(chunk)
			if chunk != nil && chunk.Usage != nil {
				u := *chunk.Usage
				chunkUsageThisAttempt = &u
			}
			state.acc.ObserveChunk(chunk)
			return nil
		})
		depCancel()
		relSlot()
		rm.finishGenAIClientSpanWithOpts(spanCtx, span, genAIClientFinishOpts{
			responseModel:     spanCap.responseModel,
			responseID:        spanCap.responseID,
			finishReasons:     spanCap.finishReasons,
			usage:             usage,
			retryCount:        meta.RetryCount,
			fallbackAttempted: meta.FallbackAttempted,
			outputText:        spanCap.outputBuf.String(),
			err:               callErr,
		})
		depLatency := time.Since(depStart).Milliseconds()

		if callErr == nil {
			mergedUsage := state.acc.MergeUsage(state.partialUsage, usage)
			inTok, outTok, totalTok := 0, 0, 0
			if mergedUsage != nil {
				inTok = mergedUsage.PromptTokens
				outTok = mergedUsage.CompletionTokens
				totalTok = mergedUsage.TotalTokens
			}
			reconcilePTU(totalTok)
			reconcilePriority(totalTok)
			if state.continuationCount > 0 {
				meta.StreamContinued = true
			}
			rm.loadBalancer.OnRequestEndWithUsage(dep.ID, depLatency, meta.TTFTMs, estTokens, estOut, inTok, outTok)
			rm.recordSuccess(ctx, dep)
			rm.releaseUnusedProbes(ctx, allDeployments, []*domain.Deployment{dep})
			rm.pinAffinityOnSuccess(aff, orgID, affinityKey, affinityDepID, dep.ID)
			meta.WinningDeployment = dep
			meta.DroppedParams = dropped
			meta.LatencyMs = time.Since(start).Milliseconds()
			rm.recordBanditOutcome(orgID, decision, !meta.FallbackAttempted, depLatency)
			return groupHopOutcome[*domain.TokenUsage]{handled: true, result: mergedUsage, meta: meta}
		}

		rm.loadBalancer.OnRequestFailure(dep.ID, depLatency, isTimeoutErr(callErr), estTokens, estOut)
		appendFallbackError(meta, group.Alias, dep.ID, callErr)

		if clientChunkErr != nil {
			rm.releaseUnusedProbes(ctx, allDeployments, []*domain.Deployment{dep})
			meta.WinningDeployment = dep
			meta.LatencyMs = time.Since(start).Milliseconds()
			rm.recordBanditOutcome(orgID, decision, false, meta.LatencyMs)
			return groupHopOutcome[*domain.TokenUsage]{
				handled: true,
				result:  state.acc.MergeUsage(state.partialUsage, usage),
				meta:    meta,
				err:     callErr,
			}
		}

		if attemptEmittedChunk {
			if rm.collector != nil && dep.GlobalModel != nil {
				rm.collector.RecordDeploymentAttempt(dep.ID, dep.DeploymentName, string(dep.GlobalModel.Provider), dep.GlobalModel.ModelName, depLatency, false)
			}
			rm.recordAttemptFailure(ctx, dep, group, activeTotal, callErr)
			state.failedDepIDs[dep.ID] = struct{}{}
			state.partialUsage = mergePartialStreamUsage(state.acc, state.partialUsage, chunkUsageThisAttempt, usage)
			meta.WinningDeployment = dep

			if !state.acc.CanContinue(rm.cfg, state.continuationCount, callErr) {
				rm.releaseUnusedProbes(ctx, allDeployments, []*domain.Deployment{dep})
				meta.LatencyMs = time.Since(start).Milliseconds()
				rm.recordBanditOutcome(orgID, decision, false, meta.LatencyMs)
				return groupHopOutcome[*domain.TokenUsage]{
					handled: true,
					result:  state.acc.MergeUsage(state.partialUsage, nil),
					meta:    meta,
					err:     callErr,
				}
			}

			if _, ok := state.acc.BuildContinuationRequest(hopBaseReq); !ok {
				rm.releaseUnusedProbes(ctx, allDeployments, []*domain.Deployment{dep})
				meta.LatencyMs = time.Since(start).Milliseconds()
				rm.recordBanditOutcome(orgID, decision, !meta.FallbackAttempted, meta.LatencyMs)
				return groupHopOutcome[*domain.TokenUsage]{
					handled: true,
					result:  state.acc.MergeUsage(state.partialUsage, nil),
					meta:    meta,
				}
			}

			state.continuationCount++
			state.lastErr = callErr
			*groupErr = callErr
			// Re-enter the current group first so another prefill-capable deployment in the same group
			// is tried before falling back across groups.
			return groupHopOutcome[*domain.TokenUsage]{requeueSame: true}
		}

		if state.firstChunkSentToClient {
			// A continuation candidate failed before emitting any chunk; exclude it and continue searching.
			state.failedDepIDs[dep.ID] = struct{}{}
			trippedDepIDs[dep.ID] = struct{}{}
			hasUntriedSibling = len(filterOutDepIDs(filterUntried(tierDeployments, triedDepIDs), trippedDepIDs)) > 0
			out := rm.handleAttemptErrorWithPolicy(ctx, dep, group, activeTotal, callErr, retryTracker, attempt, hasUntriedSibling)
			state.lastErr = out.normalizedErr
			*groupErr = out.normalizedErr
			if out.terminalErr != nil {
				rm.releaseUnusedProbes(ctx, allDeployments, []*domain.Deployment{dep})
				meta.LatencyMs = time.Since(start).Milliseconds()
				rm.recordBanditOutcome(orgID, decision, false, meta.LatencyMs)
				return groupHopOutcome[*domain.TokenUsage]{
					handled: true,
					result:  state.acc.MergeUsage(state.partialUsage, nil),
					meta:    meta,
					err:     out.terminalErr,
				}
			}
			if out.stopGroup {
				return groupHopOutcome[*domain.TokenUsage]{stopAll: true}
			}
			if out.stopTier {
				break
			}
			continue
		}

		hasUntriedSibling = len(filterOutDepIDs(filterUntried(tierDeployments, triedDepIDs), trippedDepIDs)) > 0
		out := rm.handleAttemptErrorWithPolicy(ctx, dep, group, activeTotal, callErr, retryTracker, attempt, hasUntriedSibling)
		state.lastErr = out.normalizedErr
		*groupErr = out.normalizedErr
		if out.tripped {
			trippedDepIDs[dep.ID] = struct{}{}
		}
		if out.terminalErr != nil {
			rm.releaseUnusedProbes(ctx, allDeployments, []*domain.Deployment{dep})
			rm.recordBanditOutcome(orgID, decision, false, time.Since(start).Milliseconds())
			return groupHopOutcome[*domain.TokenUsage]{handled: true, meta: meta, err: out.terminalErr}
		}
		if out.stopGroup {
			return groupHopOutcome[*domain.TokenUsage]{stopAll: true}
		}
		if out.stopTier {
			break
		}
	}
	return groupHopOutcome[*domain.TokenUsage]{}
}

type streamSpanCapture struct {
	captureContent bool
	responseID     string
	responseModel  string
	finishReasons  []string
	outputBuf      strings.Builder
}

func (c *streamSpanCapture) observeChunk(chunk *domain.CanonicalStreamChunk) {
	if chunk == nil {
		return
	}
	if c.responseID == "" && chunk.ID != "" {
		c.responseID = chunk.ID
	}
	if c.responseModel == "" && chunk.Model != "" {
		c.responseModel = chunk.Model
	}
	for _, ch := range chunk.Choices {
		if ch.FinishReason != nil {
			if fr := strings.TrimSpace(*ch.FinishReason); fr != "" && !slices.Contains(c.finishReasons, fr) {
				c.finishReasons = append(c.finishReasons, fr)
			}
		}
		if c.captureContent && ch.Delta.Content != "" && c.outputBuf.Len() < 4096 {
			c.outputBuf.WriteString(ch.Delta.Content)
		}
	}
}
