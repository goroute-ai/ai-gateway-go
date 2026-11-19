package router

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/adapter"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/logger"
	"github.com/goroute-ai/ai-gateway-go/internal/ratelimit"
)

type nonChatStreamFinalizeFn func(inTokens, outTokens int, ttftMs int64, streamErr error)

type nonChatAttemptMetaKey struct{}

type nonChatAttemptMeta struct {
	group   *domain.ModelGroup
	dropped []string
}

type nonChatDispatchFn[T any] func(ctx context.Context, dep *domain.Deployment, overrides map[string]any, finalizeStream nonChatStreamFinalizeFn) (res T, inTokens, outTokens int, totalTokens int, ok bool, err error)

type nonChatSpec[T any] struct {
	OperationLabel                string
	RequestedModel                string
	NotFoundCode                  string
	NotFoundMessage               string
	UnavailableMessage            string
	RouterReq                     *domain.CanonicalChatRequest
	EstInputTokens                int
	EstOutputTokens               int
	CapabilityFilter              func([]*domain.Deployment) []*domain.Deployment
	HoldSlotAfterReturn           bool
	NonIdempotentNoRetryTransport bool
	OnSelected                    func(dep *domain.Deployment)
	Prepare                       func(adp adapter.ProviderAdapter, dep *domain.Deployment) (nonChatDispatchFn[T], error)
}

func estimateCharTokens(chars int) int {
	if chars <= 0 {
		return 0
	}
	t := chars / 4
	if t == 0 {
		t = 1
	}
	return t
}

func executeNonChat[T any](
	rm *ReliabilityManager,
	ctx context.Context,
	idCtx *domain.IdentityContext,
	spec nonChatSpec[T],
) (T, *ExecutionMeta, error) {
	var zero T
	releaseSched, schedErr := rm.acquireSchedulerSlot(ctx, spec.RouterReq)
	if schedErr != nil {
		return zero, nil, schedErr
	}
	defer releaseSched()

	start := time.Now()
	orgID := ""
	if idCtx != nil {
		orgID = idCtx.OrgID
		if idCtx.TeamID != "" {
			ctx = WithCallerTeamID(ctx, idCtx.TeamID)
		}
	}

	routeStart := time.Now()
	mg, err := rm.intelligentRouter.ResolveExplicitModel(ctx, orgID, spec.RequestedModel)
	if err != nil {
		return zero, nil, &domain.GatewayError{
			StatusCode: http.StatusNotFound,
			Type:       domain.ErrorTypeNotFound,
			Code:       spec.NotFoundCode,
			Message:    spec.NotFoundMessage,
		}
	}

	decision := &RouteDecision{
		RequestedModel:   spec.RequestedModel,
		TargetGroupAlias: mg.Alias,
		ModelGroup:       mg,
		Reason:           "explicit_model",
	}
	meta := &ExecutionMeta{
		RouteDecision: decision,
		RoutingMicros: time.Since(routeStart).Microseconds(),
	}
	if meta.RoutingMicros <= 0 {
		meta.RoutingMicros = 1
	}

	isBudgeted := isBudgetConstrained(idCtx)
	estTotal := spec.EstInputTokens + spec.EstOutputTokens
	maxDepth := rm.effectiveMaxFallbackDepth()
	visited := make(map[string]struct{})
	if key := groupVisitKey(mg); key != "" {
		visited[key] = struct{}{}
	}
	queue := []queuedHop{{group: mg, depth: 0}}

	var skippedDueToUnknownPricing bool
	var lastErr error
	prioRank := requestPriorityRank(idCtx, spec.RouterReq)

	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		group := current.group
		if group == nil {
			continue
		}

		if current.depth > 0 {
			if hopErr := rm.authorizeFallbackHop(ctx, idCtx, group.Alias, estTotal); hopErr != nil {
				lastErr = hopErr
				continue
			}
			meta.FallbackAttempted = true
			setFallbackMetaReason(meta, current.reason)
			logger.WarnContext(ctx, "Cross-provider fallback activated",
				slog.String("component", "router"),
				slog.String("operation", spec.OperationLabel),
				slog.String("primary_alias", mg.Alias),
				slog.String("fallback_alias", group.Alias),
				slog.String("fallback_reason", current.reason),
				slog.String("requested_model", spec.RequestedModel),
			)
		}

		deployments, activeTotal, snap, stageSat, filterErr := rm.getEligibleDeploymentsDetailed(
			ctx, orgID, group, spec.RouterReq, estTotal, nil, false, prioRank, spec.CapabilityFilter,
		)
		if filterErr != nil {
			lastErr = filterErr
			appendFallbackError(meta, group.Alias, "", filterErr)
			cat := rm.classifyErr(filterErr)
			if cat == CategoryNonRetryable {
				return zero, meta, filterErr
			}
			queue = rm.enqueueFallbacks(ctx, queue, current, cat, maxDepth, visited)
			continue
		}
		if len(deployments) == 0 {
			if stageSat {
				satErr := saturationGatewayError()
				lastErr = satErr
				appendFallbackError(meta, group.Alias, "", satErr)
				if !rm.cfg.FallbackOnSaturation {
					return zero, meta, satErr
				}
				queue = rm.enqueueFallbacks(ctx, queue, current, CategorySaturation, maxDepth, visited)
				continue
			}
			queue = rm.enqueueFallbacks(ctx, queue, current, rm.classifyErr(lastErr), maxDepth, visited)
			continue
		}

		if isBudgeted {
			filtered := filterKnownPricing(deployments)
			rm.releaseUnusedProbes(ctx, deployments, filtered)
			if len(filtered) == 0 {
				skippedDueToUnknownPricing = true
				queue = rm.enqueueFallbacks(ctx, queue, current, CategoryGeneral, maxDepth, visited)
				continue
			}
			deployments = filtered
		}

		reconcilePriority, prioErr := rm.acquireDynamicPriorityCapacityWithSignals(ctx, idCtx, group, spec.RouterReq, deployments, estTotal, snap)
		if prioErr != nil {
			lastErr = prioErr
			rm.releaseUnusedProbes(ctx, deployments, nil)
			if isPrioritySaturationErr(prioErr) && rm.cfg.FallbackOnSaturation {
				queue = rm.enqueueFallbacks(ctx, queue, current, CategorySaturation, maxDepth, visited)
				continue
			}
			return zero, meta, prioErr
		}

		tiers := partitionByPriority(deployments)
		retryPolicy := rm.effectiveGroupRetryPolicy(group)
		var groupErr error
		stopGroup := false

		for tierIdx, tierDeployments := range tiers {
			if tierIdx > 0 {
				recordTierStepdown(ctx, meta, group, tierIdx)
			}

			retryTracker := newRetryBudgetTracker(retryPolicy, len(tierDeployments))
			triedDepIDs := make([]string, 0, len(tierDeployments))
			trippedDepIDs := make(map[string]struct{})
			strategy := resolveEffectiveStrategy(group, spec.RouterReq, rm.cfg.AllowStrategyOverride)

			for attempt := 0; ; attempt++ {
				candidates := filterUntried(tierDeployments, triedDepIDs)
				if len(candidates) == 0 {
					candidates = filterOutDepIDs(tierDeployments, trippedDepIDs)
					if len(candidates) == 0 {
						break
					}
				}
				dep := rm.loadBalancer.SelectWithSignals(strategy, candidates, snap)
				if dep == nil {
					break
				}
				triedDepIDs = append(triedDepIDs, dep.ID)

				rm.hydrateCredential(dep)
				adp, adpErr := rm.registry.Get(dep.GlobalModel.Provider)
				if adpErr != nil {
					lastErr = adpErr
					groupErr = adpErr
					appendFallbackError(meta, group.Alias, dep.ID, adpErr)
					trippedDepIDs[dep.ID] = struct{}{}
					if len(filterOutDepIDs(tierDeployments, trippedDepIDs)) == 0 {
						break
					}
					continue
				}

				dispatch, prepErr := spec.Prepare(adp, dep)
				if prepErr != nil {
					lastErr = prepErr
					groupErr = prepErr
					appendFallbackError(meta, group.Alias, dep.ID, prepErr)
					trippedDepIDs[dep.ID] = struct{}{}
					if len(filterOutDepIDs(tierDeployments, trippedDepIDs)) == 0 {
						break
					}
					continue
				}

				reconcilePTU, ptuErr := rm.acquireDeploymentPTU(ctx, idCtx, dep, estTotal)
				if ptuErr != nil {
					lastErr = ptuErr
					groupErr = ptuErr
					appendFallbackError(meta, group.Alias, dep.ID, ptuErr)
					trippedDepIDs[dep.ID] = struct{}{}
					if len(filterOutDepIDs(tierDeployments, trippedDepIDs)) == 0 {
						break
					}
					continue
				}

				hasUntriedSibling := len(filterOutDepIDs(filterUntried(tierDeployments, triedDepIDs), trippedDepIDs)) > 0
				relSlot, slotOK := rm.acquireDeploymentSlot(ctx, dep, prioRank, !hasUntriedSibling)
				if !slotOK {
					satErr := saturationGatewayError()
					lastErr = satErr
					groupErr = satErr
					appendFallbackError(meta, group.Alias, dep.ID, satErr)
					trippedDepIDs[dep.ID] = struct{}{}
					if len(filterOutDepIDs(tierDeployments, trippedDepIDs)) == 0 {
						break
					}
					continue
				}

				if attempt > 0 {
					meta.RetryCount++
					logger.WarnContext(ctx, "Intra-group retry attempt triggered",
						slog.String("component", "router"),
						slog.String("operation", spec.OperationLabel),
						slog.Int("attempt", attempt),
						slog.String("group_alias", group.Alias),
						slog.String("deployment_id", dep.ID),
					)
				}

				depStart := time.Now()
				rm.loadBalancer.OnRequestStartWithTokens(dep.ID, spec.EstInputTokens, spec.EstOutputTokens)
				if spec.OnSelected != nil {
					spec.OnSelected(dep)
				}

				var settleOnce sync.Once
				settleSuccess := func(inTok, outTok, totalTok int, ttftMs int64, endLatencyMs int64) {
					settleOnce.Do(func() {
						if inTok == 0 && outTok == 0 && totalTok > 0 {
							inTok = totalTok
						}
						if totalTok == 0 {
							totalTok = inTok + outTok
						}
						reconcilePTU(totalTok)
						reconcilePriority(totalTok)
						rm.loadBalancer.OnRequestEndWithUsage(dep.ID, endLatencyMs, ttftMs, spec.EstInputTokens, spec.EstOutputTokens, inTok, outTok)
						rm.recordSuccess(context.WithoutCancel(ctx), dep)
						if rm.collector != nil {
							rm.collector.RecordDeploymentAttempt(dep.ID, dep.DeploymentName, string(dep.GlobalModel.Provider), dep.GlobalModel.ModelName, endLatencyMs, false)
						}
					})
				}
				finalizeStream := func(inTok, outTok int, ttftMs int64, streamErr error) {
					defer relSlot()
					endLatencyMs := time.Since(depStart).Milliseconds()
					if streamErr != nil && !errors.Is(streamErr, context.Canceled) {
						settleOnce.Do(func() {
							reconcilePTU(inTok + outTok)
							reconcilePriority(inTok + outTok)
							rm.loadBalancer.OnRequestFailure(dep.ID, endLatencyMs, isTimeoutErr(streamErr), spec.EstInputTokens, spec.EstOutputTokens)
							if rm.collector != nil {
								rm.collector.RecordDeploymentAttempt(dep.ID, dep.DeploymentName, string(dep.GlobalModel.Provider), dep.GlobalModel.ModelName, endLatencyMs, true)
							}
						})
						return
					}
					settleSuccess(inTok, outTok, inTok+outTok, ttftMs, endLatencyMs)
				}

				var attemptMeta *nonChatAttemptMeta
				if group != nil {
					attemptMeta = &nonChatAttemptMeta{group: group}
				}
				dispatchCtx := context.WithValue(ctx, nonChatAttemptMetaKey{}, attemptMeta)
				res, actualIn, actualOut, actualTotal, okRes, callErr := dispatch(dispatchCtx, dep, current.overrides, finalizeStream)
				if !spec.HoldSlotAfterReturn || callErr != nil || !okRes {
					relSlot()
				}
				depLatency := time.Since(depStart).Milliseconds()

				if callErr == nil && okRes {
					if !spec.HoldSlotAfterReturn {
						settleSuccess(actualIn, actualOut, actualTotal, 0, depLatency)
					}
					rm.releaseUnusedProbes(ctx, deployments, []*domain.Deployment{dep})
					meta.WinningDeployment = dep
					if attemptMeta != nil && len(attemptMeta.dropped) > 0 {
						meta.DroppedParams = append([]string(nil), attemptMeta.dropped...)
					}
					meta.LatencyMs = time.Since(start).Milliseconds()
					return res, meta, nil
				}

				if callErr == nil {
					callErr = &domain.GatewayError{
						StatusCode: http.StatusBadGateway,
						Type:       domain.ErrorTypeUpstream,
						Code:       "empty_upstream_response",
						Message:    "Upstream provider returned an empty response",
						Retryable:  true,
					}
				}
				rm.loadBalancer.OnRequestFailure(dep.ID, depLatency, isTimeoutErr(callErr), spec.EstInputTokens, spec.EstOutputTokens)
				if rm.collector != nil {
					rm.collector.RecordDeploymentAttempt(dep.ID, dep.DeploymentName, string(dep.GlobalModel.Provider), dep.GlobalModel.ModelName, depLatency, true)
				}

				if spec.NonIdempotentNoRetryTransport {
					if errors.Is(callErr, context.Canceled) || errors.Is(ctx.Err(), context.Canceled) {
						rm.releaseUnusedProbes(ctx, deployments, []*domain.Deployment{dep})
						return zero, meta, callErr
					}
					var gwErr *domain.GatewayError
					if !errors.As(callErr, &gwErr) {
						rm.releaseUnusedProbes(ctx, deployments, []*domain.Deployment{dep})
						return zero, meta, callErr
					}
					if !gwErr.Retryable && !gwErr.AuthFailure {
						rm.releaseUnusedProbes(ctx, deployments, []*domain.Deployment{dep})
						return zero, meta, gwErr
					}
				}

				hasUntriedSibling = len(filterOutDepIDs(filterUntried(tierDeployments, triedDepIDs), trippedDepIDs)) > 0
				out := rm.handleAttemptErrorWithPolicy(
					ctx, dep, group, activeTotal, callErr, retryTracker, attempt, hasUntriedSibling,
				)
				lastErr = out.normalizedErr
				groupErr = out.normalizedErr
				appendFallbackError(meta, group.Alias, dep.ID, out.normalizedErr)
				if out.tripped {
					trippedDepIDs[dep.ID] = struct{}{}
				}
				if out.terminalErr != nil {
					rm.releaseUnusedProbes(ctx, deployments, []*domain.Deployment{dep})
					return zero, meta, out.terminalErr
				}
				if out.stopGroup {
					stopGroup = true
					break
				}
				if out.stopTier {
					break
				}
			}
			if stopGroup {
				break
			}
		}

		rm.releaseUnusedProbes(ctx, deployments, nil)
		if isPrioritySaturationErr(groupErr) {
			if !rm.cfg.FallbackOnSaturation {
				return zero, meta, groupErr
			}
			queue = rm.enqueueFallbacks(ctx, queue, current, CategorySaturation, maxDepth, visited)
			continue
		}
		cat := rm.classifyErr(groupErr)
		if cat == CategoryNonRetryable && groupErr != nil {
			return zero, meta, groupErr
		}
		queue = rm.enqueueFallbacks(ctx, queue, current, cat, maxDepth, visited)
	}

	if lastErr == nil {
		if isBudgeted && skippedDueToUnknownPricing {
			lastErr = &domain.GatewayError{
				StatusCode: http.StatusForbidden,
				Type:       domain.ErrorTypePermission,
				Code:       "pricing_unknown_budget_restricted",
				Message:    "Request rejected: caller has strict budget enforcement enabled, but selected model deployment has unverified/unknown pricing",
			}
		} else {
			lastErr = &domain.GatewayError{
				StatusCode: http.StatusServiceUnavailable,
				Type:       domain.ErrorTypeUpstream,
				Code:       "all_deployments_unavailable",
				Message:    spec.UnavailableMessage,
			}
		}
	}
	return zero, meta, lastErr
}

// ExecuteEmbeddings routes and executes a `/v1/embeddings` request with retries and fallbacks.
func (rm *ReliabilityManager) ExecuteEmbeddings(ctx context.Context, idCtx *domain.IdentityContext, req *domain.CanonicalEmbeddingRequest) (*domain.CanonicalEmbeddingResponse, *ExecutionMeta, error) {
	chars := 0
	for _, s := range req.Input {
		chars += len(s)
	}
	return executeNonChat(rm, ctx, idCtx, nonChatSpec[*domain.CanonicalEmbeddingResponse]{
		OperationLabel:     "embeddings",
		RequestedModel:     req.Model,
		NotFoundCode:       "embedding_model_not_found",
		NotFoundMessage:    "No active embedding model group configured for: " + req.Model,
		UnavailableMessage: "All primary and fallback embedding deployments are currently unavailable or in cooldown",
		RouterReq: &domain.CanonicalChatRequest{
			RequestID:         req.RequestID,
			Model:             req.Model,
			User:              req.User,
			GoRouteExtensions: req.GoRouteExtensions,
		},
		EstInputTokens: estimateCharTokens(chars),
		CapabilityFilter: func(deps []*domain.Deployment) []*domain.Deployment {
			return filterByCapability(deps, func(caps domain.ModelCapabilities) domain.CapabilityState {
				return caps.Embeddings
			})
		},
		Prepare: func(adp adapter.ProviderAdapter, dep *domain.Deployment) (nonChatDispatchFn[*domain.CanonicalEmbeddingResponse], error) {
			if opErr := checkDeploymentOperation(adp, dep, domain.OperationEmbedding); opErr != nil {
				return nil, opErr
			}
			return func(callCtx context.Context, d *domain.Deployment, _ map[string]any, _ nonChatStreamFinalizeFn) (*domain.CanonicalEmbeddingResponse, int, int, int, bool, error) {
				reqCopy := *req
				reqCopy.ResolvedModel = d.GlobalModel.ModelName
				spanCtx, span := rm.startGenAIClientSpan(callCtx, "embeddings", d)
				depCtx, depCancel := withDeploymentTimeout(spanCtx, d)
				markProviderDispatch(depCtx, d)
				resp, callErr := adp.Embeddings(depCtx, d, &reqCopy)
				depCancel()
				var usage *domain.TokenUsage
				if resp != nil {
					usage = &resp.Usage
				}
				finishGenAIClientSpan(span, usage, callErr)
				if callErr != nil || resp == nil {
					return nil, 0, 0, 0, false, callErr
				}
				return resp, resp.Usage.PromptTokens, resp.Usage.CompletionTokens, resp.Usage.TotalTokens, true, nil
			}, nil
		},
	})
}

// ExecuteRerank routes and executes a `/v1/rerank` request across rerank-capable deployments.
func (rm *ReliabilityManager) ExecuteRerank(ctx context.Context, idCtx *domain.IdentityContext, req *domain.CanonicalRerankRequest) (*domain.CanonicalRerankResponse, *ExecutionMeta, error) {
	chars := len(req.Query)
	for _, doc := range req.Documents {
		chars += len(doc.Text)
	}
	return executeNonChat(rm, ctx, idCtx, nonChatSpec[*domain.CanonicalRerankResponse]{
		OperationLabel:     "rerank",
		RequestedModel:     req.Model,
		NotFoundCode:       "rerank_model_not_found",
		NotFoundMessage:    "No active rerank model group configured for: " + req.Model,
		UnavailableMessage: "All primary and fallback rerank deployments are currently unavailable or in cooldown",
		RouterReq: &domain.CanonicalChatRequest{
			RequestID:         req.RequestID,
			Model:             req.Model,
			GoRouteExtensions: req.GoRouteExtensions,
		},
		EstInputTokens: estimateCharTokens(chars),
		CapabilityFilter: func(deps []*domain.Deployment) []*domain.Deployment {
			return filterByCapability(deps, func(caps domain.ModelCapabilities) domain.CapabilityState {
				return caps.Rerank
			})
		},
		Prepare: func(adp adapter.ProviderAdapter, dep *domain.Deployment) (nonChatDispatchFn[*domain.CanonicalRerankResponse], error) {
			if opErr := checkDeploymentOperation(adp, dep, domain.OperationRerank); opErr != nil {
				return nil, opErr
			}
			rerankAdp, ok := adp.(adapter.RerankAdapter)
			if !ok {
				return nil, &domain.GatewayError{
					StatusCode: http.StatusNotImplemented,
					Type:       domain.ErrorTypeInvalidRequest,
					Code:       "rerank_not_supported",
					Message:    "Provider " + string(dep.GlobalModel.Provider) + " does not support reranking",
				}
			}
			return func(callCtx context.Context, d *domain.Deployment, _ map[string]any, _ nonChatStreamFinalizeFn) (*domain.CanonicalRerankResponse, int, int, int, bool, error) {
				reqCopy := *req
				reqCopy.ResolvedModel = d.GlobalModel.ModelName
				spanCtx, span := rm.startGenAIClientSpan(callCtx, "rerank", d)
				depCtx, depCancel := withDeploymentTimeout(spanCtx, d)
				resp, callErr := rerankAdp.Rerank(depCtx, d, &reqCopy)
				depCancel()
				var usage *domain.TokenUsage
				if resp != nil {
					usage = &domain.TokenUsage{TotalTokens: resp.Usage.TotalTokens}
				}
				finishGenAIClientSpan(span, usage, callErr)
				if callErr != nil || resp == nil {
					return nil, 0, 0, 0, false, callErr
				}
				return resp, resp.Usage.TotalTokens, 0, resp.Usage.TotalTokens, true, nil
			}, nil
		},
	})
}

// ExecuteModeration routes and executes a `/v1/moderations` request.
func (rm *ReliabilityManager) ExecuteModeration(ctx context.Context, idCtx *domain.IdentityContext, req *domain.CanonicalModerationRequest) (*domain.CanonicalModerationResponse, *ExecutionMeta, error) {
	chars := 0
	for _, s := range req.Input {
		chars += len(s)
	}
	return executeNonChat(rm, ctx, idCtx, nonChatSpec[*domain.CanonicalModerationResponse]{
		OperationLabel:     "moderation",
		RequestedModel:     req.Model,
		NotFoundCode:       "moderation_model_not_found",
		NotFoundMessage:    "No active moderation model group configured for: " + req.Model,
		UnavailableMessage: "All primary and fallback moderation deployments are currently unavailable or in cooldown",
		RouterReq: &domain.CanonicalChatRequest{
			RequestID:         req.RequestID,
			Model:             req.Model,
			GoRouteExtensions: req.GoRouteExtensions,
		},
		EstInputTokens: estimateCharTokens(chars),
		CapabilityFilter: func(deps []*domain.Deployment) []*domain.Deployment {
			return filterByCapability(deps, func(caps domain.ModelCapabilities) domain.CapabilityState {
				return caps.Moderation
			})
		},
		Prepare: func(adp adapter.ProviderAdapter, dep *domain.Deployment) (nonChatDispatchFn[*domain.CanonicalModerationResponse], error) {
			if opErr := checkDeploymentOperation(adp, dep, domain.OperationModeration); opErr != nil {
				return nil, opErr
			}
			modAdp, ok := adp.(adapter.ModerationAdapter)
			if !ok {
				return nil, &domain.GatewayError{
					StatusCode: http.StatusNotImplemented,
					Type:       domain.ErrorTypeInvalidRequest,
					Code:       "moderation_not_supported",
					Message:    "Provider " + string(dep.GlobalModel.Provider) + " does not support moderation",
				}
			}
			return func(callCtx context.Context, d *domain.Deployment, _ map[string]any, _ nonChatStreamFinalizeFn) (*domain.CanonicalModerationResponse, int, int, int, bool, error) {
				reqCopy := *req
				reqCopy.ResolvedModel = d.GlobalModel.ModelName
				spanCtx, span := rm.startGenAIClientSpan(callCtx, "moderation", d)
				depCtx, depCancel := withDeploymentTimeout(spanCtx, d)
				resp, callErr := modAdp.Moderate(depCtx, d, &reqCopy)
				depCancel()
				finishGenAIClientSpan(span, nil, callErr)
				if callErr != nil || resp == nil {
					return nil, 0, 0, 0, false, callErr
				}
				return resp, 0, 0, 0, true, nil
			}, nil
		},
	})
}

func completionRouterReq(req *domain.CanonicalCompletionRequest) (*domain.CanonicalChatRequest, int, int) {
	promptText := strings.Join(req.Prompt.Strings, "\n\n")
	estIn := ratelimit.EstimateRequestTokens(&domain.CanonicalChatRequest{
		Model:    req.Model,
		Messages: []domain.CanonicalMessage{{Role: "user", Content: promptText}},
	})
	estOut := 0
	if req.MaxTokens != nil && *req.MaxTokens > 0 {
		estOut = *req.MaxTokens
	}
	return &domain.CanonicalChatRequest{
		RequestID:         req.RequestID,
		Model:             req.Model,
		MaxTokens:         req.MaxTokens,
		Temperature:       req.Temperature,
		TopP:              req.TopP,
		Stream:            req.Stream,
		Stop:              req.Stop,
		User:              req.User,
		Metadata:          req.Metadata,
		GoRouteExtensions: req.GoRouteExtensions,
	}, estIn, estOut
}

// ExecuteCompletion routes and executes a legacy `/v1/completions` request, falling back to ChatCompletion promotion if needed.
func (rm *ReliabilityManager) ExecuteCompletion(ctx context.Context, idCtx *domain.IdentityContext, req *domain.CanonicalCompletionRequest) (*domain.CanonicalCompletionResponse, *ExecutionMeta, error) {
	routerReq, estIn, estOut := completionRouterReq(req)
	return executeNonChat(rm, ctx, idCtx, nonChatSpec[*domain.CanonicalCompletionResponse]{
		OperationLabel:     "completion",
		RequestedModel:     req.Model,
		NotFoundCode:       "completion_model_not_found",
		NotFoundMessage:    "No active model group configured for: " + req.Model,
		UnavailableMessage: "All primary and fallback completion deployments are currently unavailable or in cooldown",
		RouterReq:          routerReq,
		EstInputTokens:     estIn,
		EstOutputTokens:    estOut,
		Prepare: func(adp adapter.ProviderAdapter, dep *domain.Deployment) (nonChatDispatchFn[*domain.CanonicalCompletionResponse], error) {
			if opErr := checkDeploymentOperation(adp, dep, domain.OperationCompletion); opErr != nil {
				return nil, opErr
			}
			return func(callCtx context.Context, d *domain.Deployment, overrides map[string]any, _ nonChatStreamFinalizeFn) (*domain.CanonicalCompletionResponse, int, int, int, bool, error) {
				reqCopy := *req
				reqCopy.ResolvedModel = d.GlobalModel.ModelName

				var resp *domain.CanonicalCompletionResponse
				var callErr error
				if compAdp, ok := adp.(adapter.CompletionAdapter); ok {
					spanCtx, span := rm.startGenAIClientSpan(callCtx, "text_completion", d)
					depCtx, depCancel := withDeploymentTimeout(spanCtx, d)
					resp, callErr = compAdp.TextCompletion(depCtx, d, &reqCopy)
					depCancel()
					var usage *domain.TokenUsage
					if resp != nil {
						usage = &resp.Usage
					}
					finishGenAIClientSpan(span, usage, callErr)
				} else {
					promptText := strings.Join(req.Prompt.Strings, "\n\n")
					rawChatReq := applyFallbackOverrides(&domain.CanonicalChatRequest{
						RequestID:         req.RequestID,
						Model:             req.Model,
						ResolvedModel:     d.GlobalModel.ModelName,
						Messages:          []domain.CanonicalMessage{{Role: "user", Content: promptText}},
						MaxTokens:         req.MaxTokens,
						Temperature:       req.Temperature,
						TopP:              req.TopP,
						Stop:              req.Stop,
						User:              req.User,
						Metadata:          req.Metadata,
						GoRouteExtensions: req.GoRouteExtensions,
					}, overrides)
					am, _ := callCtx.Value(nonChatAttemptMetaKey{}).(*nonChatAttemptMeta)
					var depGroup *domain.ModelGroup
					if am != nil {
						depGroup = am.group
					}
					dropEnabled := resolveDropUnsupportedParams(rm.cfg.DropUnsupportedParams, depGroup, rawChatReq)
					chatReq, dropped := sanitizeRequestForDeployment(rawChatReq, d, dropEnabled)
					chatReq.ResolvedModel = d.GlobalModel.ModelName
					if len(dropped) > 0 {
						if am != nil {
							am.dropped = dropped
						}
						notifyDroppedParams(callCtx, dropped)
					}
					spanCtx, span := rm.startGenAIClientSpan(callCtx, "chat", d)
					depCtx, depCancel := withDeploymentTimeout(spanCtx, d)
					markProviderDispatch(depCtx, d)
					chatResp, cErr := adp.ChatCompletion(depCtx, d, &chatReq)
					depCancel()
					var usage *domain.TokenUsage
					if chatResp != nil {
						usage = &chatResp.Usage
					}
					finishGenAIClientSpan(span, usage, cErr)
					if cErr != nil {
						callErr = cErr
					} else if chatResp != nil {
						choices := make([]domain.CanonicalCompletionChoice, len(chatResp.Choices))
						for i, c := range chatResp.Choices {
							choices[i] = domain.CanonicalCompletionChoice{
								Index:        c.Index,
								Text:         c.Message.Content,
								FinishReason: c.FinishReason,
							}
						}
						resp = &domain.CanonicalCompletionResponse{
							ID:       chatResp.ID,
							Model:    chatResp.Model,
							Provider: chatResp.Provider,
							Choices:  choices,
							Usage:    chatResp.Usage,
						}
					}
				}
				if callErr != nil || resp == nil {
					return nil, 0, 0, 0, false, callErr
				}
				return resp, resp.Usage.PromptTokens, resp.Usage.CompletionTokens, resp.Usage.TotalTokens, true, nil
			}, nil
		},
	})
}

// ExecuteCompletionStream routes and executes a streaming legacy `/v1/completions` request.
func (rm *ReliabilityManager) ExecuteCompletionStream(ctx context.Context, idCtx *domain.IdentityContext, req *domain.CanonicalCompletionRequest) (<-chan domain.CanonicalStreamChunk, *ExecutionMeta, error) {
	return rm.ExecuteCompletionStreamWithCallback(ctx, idCtx, req, nil)
}

// ExecuteCompletionStreamWithCallback routes and executes a streaming legacy `/v1/completions` request, invoking onSelected before upstream dispatch.
func (rm *ReliabilityManager) ExecuteCompletionStreamWithCallback(ctx context.Context, idCtx *domain.IdentityContext, req *domain.CanonicalCompletionRequest, onSelected func(*domain.Deployment)) (<-chan domain.CanonicalStreamChunk, *ExecutionMeta, error) {
	routerReq, estIn, estOut := completionRouterReq(req)
	return executeNonChat(rm, ctx, idCtx, nonChatSpec[<-chan domain.CanonicalStreamChunk]{
		OperationLabel:      "completion_stream",
		RequestedModel:      req.Model,
		NotFoundCode:        "completion_model_not_found",
		NotFoundMessage:     "No active model group configured for: " + req.Model,
		UnavailableMessage:  "All primary and fallback completion deployments are currently unavailable or in cooldown",
		RouterReq:           routerReq,
		EstInputTokens:      estIn,
		EstOutputTokens:     estOut,
		HoldSlotAfterReturn: true,
		OnSelected:          onSelected,
		Prepare: func(adp adapter.ProviderAdapter, dep *domain.Deployment) (nonChatDispatchFn[<-chan domain.CanonicalStreamChunk], error) {
			if opErr := checkDeploymentOperation(adp, dep, domain.OperationCompletion); opErr != nil {
				return nil, opErr
			}
			streamCompAdp, ok := adp.(adapter.StreamingCompletionAdapter)
			if !ok {
				return nil, &domain.GatewayError{
					StatusCode: http.StatusBadRequest,
					Type:       domain.ErrorTypeInvalidRequest,
					Code:       "unsupported_capability",
					Message:    "Provider " + string(dep.GlobalModel.Provider) + " does not support streaming text completions",
					Provider:   dep.GlobalModel.Provider,
				}
			}
			return func(callCtx context.Context, d *domain.Deployment, _ map[string]any, finalizeStream nonChatStreamFinalizeFn) (<-chan domain.CanonicalStreamChunk, int, int, int, bool, error) {
				reqCopy := *req
				reqCopy.ResolvedModel = d.GlobalModel.ModelName
				spanCtx, span := rm.startGenAIClientSpan(callCtx, "text_completion", d)
				depCtx, depCancel := withDeploymentTimeout(spanCtx, d)
				streamStart := time.Now()
				ch, callErr := streamCompAdp.StreamTextCompletion(depCtx, d, &reqCopy)
				finishGenAIClientSpan(span, nil, callErr)
				if callErr != nil || ch == nil {
					depCancel()
					return nil, 0, 0, 0, false, callErr
				}
				outCh := make(chan domain.CanonicalStreamChunk, 16)
				go func() {
					var (
						lastIn   int
						lastOut  int
						ttftMs   int64
						gotChunk bool
					)
					defer close(outCh)
					defer func() {
						var streamErr error
						if err := depCtx.Err(); err != nil && !errors.Is(err, context.Canceled) {
							streamErr = err
						}
						depCancel()
						finalizeStream(lastIn, lastOut, ttftMs, streamErr)
					}()
					for {
						select {
						case chunk, open := <-ch:
							if !open {
								return
							}
							if !gotChunk {
								gotChunk = true
								ttftMs = time.Since(streamStart).Milliseconds()
							}
							if chunk.Usage != nil {
								if chunk.Usage.PromptTokens > 0 {
									lastIn = chunk.Usage.PromptTokens
								}
								if chunk.Usage.CompletionTokens > 0 {
									lastOut = chunk.Usage.CompletionTokens
								}
							}
							select {
							case outCh <- chunk:
							case <-depCtx.Done():
								return
							}
						case <-depCtx.Done():
							return
						}
					}
				}()
				return outCh, 0, 0, 0, true, nil
			}, nil
		},
	})
}

// ExecuteAudioTranscription routes and executes audio transcription or translation requests.
func (rm *ReliabilityManager) ExecuteAudioTranscription(ctx context.Context, idCtx *domain.IdentityContext, req *domain.CanonicalAudioTranscriptionRequest) (*domain.CanonicalAudioResponse, *ExecutionMeta, error) {
	return executeNonChat(rm, ctx, idCtx, nonChatSpec[*domain.CanonicalAudioResponse]{
		OperationLabel:     "audio_transcription",
		RequestedModel:     req.Model,
		NotFoundCode:       "audio_model_not_found",
		NotFoundMessage:    "No active model group configured for: " + req.Model,
		UnavailableMessage: "All primary and fallback audio transcription deployments are currently unavailable or in cooldown",
		RouterReq: &domain.CanonicalChatRequest{
			RequestID:         req.RequestID,
			Model:             req.Model,
			GoRouteExtensions: req.GoRouteExtensions,
		},
		EstInputTokens: estimateCharTokens(len(req.Prompt)),
		CapabilityFilter: func(deps []*domain.Deployment) []*domain.Deployment {
			return filterByCapability(deps, func(caps domain.ModelCapabilities) domain.CapabilityState {
				return caps.AudioSTT
			})
		},
		Prepare: func(adp adapter.ProviderAdapter, dep *domain.Deployment) (nonChatDispatchFn[*domain.CanonicalAudioResponse], error) {
			if opErr := checkDeploymentOperation(adp, dep, domain.OperationAudioSTT); opErr != nil {
				return nil, opErr
			}
			audioAdp, ok := adp.(adapter.AudioAdapter)
			if !ok {
				return nil, &domain.GatewayError{
					StatusCode: http.StatusNotImplemented,
					Type:       domain.ErrorTypeInvalidRequest,
					Code:       "audio_stt_not_supported",
					Message:    "Provider " + string(dep.GlobalModel.Provider) + " does not support audio transcription",
				}
			}
			return func(callCtx context.Context, d *domain.Deployment, _ map[string]any, _ nonChatStreamFinalizeFn) (*domain.CanonicalAudioResponse, int, int, int, bool, error) {
				reqCopy := *req
				reqCopy.ResolvedModel = d.GlobalModel.ModelName
				spanCtx, span := rm.startGenAIClientSpan(callCtx, "audio_transcription", d)
				depCtx, depCancel := withDeploymentTimeout(spanCtx, d)
				resp, callErr := audioAdp.TranscribeAudio(depCtx, d, &reqCopy)
				depCancel()
				finishGenAIClientSpan(span, nil, callErr)
				if callErr != nil || resp == nil {
					return nil, 0, 0, 0, false, callErr
				}
				return resp, 0, 0, 0, true, nil
			}, nil
		},
	})
}

type speechStreamResult struct {
	stream      io.ReadCloser
	contentType string
}

// ExecuteAudioSpeech routes and executes a text-to-speech request, returning an audio stream.
func (rm *ReliabilityManager) ExecuteAudioSpeech(ctx context.Context, idCtx *domain.IdentityContext, req *domain.CanonicalAudioSpeechRequest) (io.ReadCloser, string, *ExecutionMeta, error) {
	res, meta, err := executeNonChat(rm, ctx, idCtx, nonChatSpec[speechStreamResult]{
		OperationLabel:     "audio_speech",
		RequestedModel:     req.Model,
		NotFoundCode:       "speech_model_not_found",
		NotFoundMessage:    "No active model group configured for: " + req.Model,
		UnavailableMessage: "All primary and fallback speech deployments are currently unavailable or in cooldown",
		RouterReq: &domain.CanonicalChatRequest{
			RequestID:         req.RequestID,
			Model:             req.Model,
			GoRouteExtensions: req.GoRouteExtensions,
		},
		EstInputTokens:      estimateCharTokens(len(req.Input)),
		HoldSlotAfterReturn: true,
		CapabilityFilter: func(deps []*domain.Deployment) []*domain.Deployment {
			return filterByCapability(deps, func(caps domain.ModelCapabilities) domain.CapabilityState {
				return caps.AudioTTS
			})
		},
		Prepare: func(adp adapter.ProviderAdapter, dep *domain.Deployment) (nonChatDispatchFn[speechStreamResult], error) {
			if opErr := checkDeploymentOperation(adp, dep, domain.OperationAudioTTS); opErr != nil {
				return nil, opErr
			}
			audioAdp, ok := adp.(adapter.AudioAdapter)
			if !ok {
				return nil, &domain.GatewayError{
					StatusCode: http.StatusNotImplemented,
					Type:       domain.ErrorTypeInvalidRequest,
					Code:       "audio_tts_not_supported",
					Message:    "Provider " + string(dep.GlobalModel.Provider) + " does not support text-to-speech",
				}
			}
			return func(callCtx context.Context, d *domain.Deployment, _ map[string]any, finalizeStream nonChatStreamFinalizeFn) (speechStreamResult, int, int, int, bool, error) {
				reqCopy := *req
				reqCopy.ResolvedModel = d.GlobalModel.ModelName
				spanCtx, span := rm.startGenAIClientSpan(callCtx, "audio_speech", d)
				depCtx, depCancel := withDeploymentTimeout(spanCtx, d)
				stream, contentType, callErr := audioAdp.GenerateSpeech(depCtx, d, &reqCopy)
				finishGenAIClientSpan(span, nil, callErr)
				if callErr != nil || stream == nil {
					depCancel()
					return speechStreamResult{}, 0, 0, 0, false, callErr
				}
				return speechStreamResult{
					stream: &cancelReadCloser{
						ReadCloser: stream,
						cancel:     depCancel,
						onClose: func() {
							var streamErr error
							if err := depCtx.Err(); err != nil && !errors.Is(err, context.Canceled) {
								streamErr = err
							}
							finalizeStream(0, 0, 0, streamErr)
						},
					},
					contentType: contentType,
				}, 0, 0, 0, true, nil
			}, nil
		},
	})
	if err != nil {
		return nil, "", meta, err
	}
	return res.stream, res.contentType, meta, nil
}

// ExecuteImage routes and executes an image generation request with idempotency protection.
func (rm *ReliabilityManager) ExecuteImage(ctx context.Context, idCtx *domain.IdentityContext, req *domain.CanonicalImageRequest) (*domain.CanonicalImageResponse, *ExecutionMeta, error) {
	imgOp := domain.OperationImageGeneration
	if req.Operation == "edit" {
		imgOp = domain.OperationImageEdit
	} else if req.Operation == "variation" {
		imgOp = domain.OperationImageVariation
	}
	return executeNonChat(rm, ctx, idCtx, nonChatSpec[*domain.CanonicalImageResponse]{
		OperationLabel:     "image",
		RequestedModel:     req.Model,
		NotFoundCode:       "image_model_not_found",
		NotFoundMessage:    "No active model group configured for: " + req.Model,
		UnavailableMessage: "All primary and fallback image deployments are currently unavailable or in cooldown",
		RouterReq: &domain.CanonicalChatRequest{
			RequestID:         req.RequestID,
			Model:             req.Model,
			User:              req.User,
			GoRouteExtensions: req.GoRouteExtensions,
		},
		EstInputTokens:                estimateCharTokens(len(req.Prompt)),
		NonIdempotentNoRetryTransport: true,
		CapabilityFilter: func(deps []*domain.Deployment) []*domain.Deployment {
			return filterByCapability(deps, func(caps domain.ModelCapabilities) domain.CapabilityState {
				return caps.ImageGen
			})
		},
		Prepare: func(adp adapter.ProviderAdapter, dep *domain.Deployment) (nonChatDispatchFn[*domain.CanonicalImageResponse], error) {
			if opErr := checkDeploymentOperation(adp, dep, imgOp); opErr != nil {
				return nil, opErr
			}
			imgAdp, ok := adp.(adapter.ImageAdapter)
			if !ok {
				return nil, &domain.GatewayError{
					StatusCode: http.StatusNotImplemented,
					Type:       domain.ErrorTypeInvalidRequest,
					Code:       "image_gen_not_supported",
					Message:    "Provider " + string(dep.GlobalModel.Provider) + " does not support image generation",
				}
			}
			return func(callCtx context.Context, d *domain.Deployment, _ map[string]any, _ nonChatStreamFinalizeFn) (*domain.CanonicalImageResponse, int, int, int, bool, error) {
				reqCopy := *req
				reqCopy.ResolvedModel = d.GlobalModel.ModelName
				spanCtx, span := rm.startGenAIClientSpan(callCtx, "image_generation", d)
				depCtx, depCancel := withDeploymentTimeout(spanCtx, d)
				resp, callErr := imgAdp.GenerateImage(depCtx, d, &reqCopy)
				depCancel()
				finishGenAIClientSpan(span, nil, callErr)
				if callErr != nil || resp == nil {
					return nil, 0, 0, 0, false, callErr
				}
				return resp, 0, 0, 0, true, nil
			}, nil
		},
	})
}
