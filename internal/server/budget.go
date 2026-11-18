package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/finops"
	"github.com/goroute-ai/ai-gateway-go/internal/logger"
	"github.com/goroute-ai/ai-gateway-go/internal/router"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

const (
	defaultReservationLeaseRenewInterval = 15 * time.Minute
	defaultReservationLeaseTTLSec        = 3600
	defaultLeaseRenewCallTimeout         = 5 * time.Second
)

type budgetLookupStats struct {
	indexedLookups     atomic.Uint64
	catalogScans       atomic.Uint64
	budgetedChecks     atomic.Uint64
	pricingSummaries   atomic.Uint64
	leaseRenewals      atomic.Uint64
	leaseRenewInterval time.Duration
}

var errBudgetPricingUnverified = errors.New("budget model pricing is unverified")

func rejectBudgetedUnsupported(w http.ResponseWriter, id *domain.IdentityContext, stats ...*budgetLookupStats) bool {
	if !identityHasBudget(id) {
		return false
	}
	if len(stats) > 0 && stats[0] != nil {
		stats[0].budgetedChecks.Add(1)
	}
	domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: http.StatusServiceUnavailable, Type: domain.ErrorTypeBudgetExceeded, Code: "budget_estimate_unavailable", Message: "This modality has no safe pre-dispatch upper-bound cost estimator"})
	return true
}

func identityHasBudget(id *domain.IdentityContext) bool {
	return id != nil && (id.KeyMaxBudgetMicros > 0 || id.TeamMaxBudgetMicros > 0 || id.UserMaxBudgetMicros > 0 || id.OrgMaxBudgetMicros > 0)
}

func (s *GatewayServer) budgetModelCandidates(ctx context.Context, provider domain.ProviderType, model string) ([]*domain.GlobalModel, error) {
	_, bareModel, _ := config.ParseProviderModel(model)
	if bareModel != "" {
		if indexed, ok := s.repo.(storage.GlobalModelNameLookup); ok {
			if s.budgetStats != nil {
				s.budgetStats.indexedLookups.Add(1)
			}
			return indexed.ListGlobalModelsByName(ctx, provider, bareModel)
		}
	}
	if s.budgetStats != nil {
		s.budgetStats.catalogScans.Add(1)
	}
	return s.repo.ListGlobalModels(ctx)
}

// tokenBudgetUpperBound requires an unambiguous catalog model and prices the
// input plus the full caller/model output allowance at conservative rates.
// Aliases, unknown pricing, and unbounded outputs fail closed.
func (s *GatewayServer) tokenBudgetUpperBound(ctx context.Context, orgID, model string, inputTokens, requestedOutput int) (int64, error) {
	var match *domain.GlobalModel
	var catalogMax *domain.GlobalModel
	var sawUnverifiedMatch bool
	maxModel := func(dst **domain.GlobalModel, gm *domain.GlobalModel) {
		if *dst == nil {
			*dst = &domain.GlobalModel{PricingStatus: domain.PricingStatusVerified}
		}
		quoted := *dst
		if gm.InputCostMicrosPer1M > quoted.InputCostMicrosPer1M {
			quoted.InputCostMicrosPer1M = gm.InputCostMicrosPer1M
		}
		if gm.CachedInputCostMicrosPer1M > quoted.CachedInputCostMicrosPer1M {
			quoted.CachedInputCostMicrosPer1M = gm.CachedInputCostMicrosPer1M
		}
		if gm.CacheWriteCostMicrosPer1M > quoted.CacheWriteCostMicrosPer1M {
			quoted.CacheWriteCostMicrosPer1M = gm.CacheWriteCostMicrosPer1M
		}
		if gm.OutputCostMicrosPer1M > quoted.OutputCostMicrosPer1M {
			quoted.OutputCostMicrosPer1M = gm.OutputCostMicrosPer1M
		}
		if gm.ReasoningCostMicrosPer1M > quoted.ReasoningCostMicrosPer1M {
			quoted.ReasoningCostMicrosPer1M = gm.ReasoningCostMicrosPer1M
		}
		if gm.MaxOutputTokens > quoted.MaxOutputTokens {
			quoted.MaxOutputTokens = gm.MaxOutputTokens
		}
	}
	_, bareModel, canonicalID := config.ParseProviderModel(model)
	models, err := s.budgetModelCandidates(ctx, "", model)
	if err != nil {
		return 0, err
	}
	for _, gm := range models {
		if gm == nil {
			continue
		}
		isMatch := gm.ID == model || gm.ID == canonicalID || gm.ModelName == model || (bareModel != "" && gm.ModelName == bareModel)
		status := domain.ResolvePricingStatus(gm)
		if isMatch && status != domain.PricingStatusVerified && status != domain.PricingStatusCustom {
			sawUnverifiedMatch = true
		}
		if isMatch && (status == domain.PricingStatusVerified || status == domain.PricingStatusCustom) {
			maxModel(&match, gm)
		}
	}
	if match == nil {
		if sawUnverifiedMatch {
			return 0, errBudgetPricingUnverified
		}
		// Model-group aliases such as "auto" can route to any catalog model.
		// The maximum published text-token rates across the full catalog safely
		// bounds every known-priced deployment reachable through that alias.
		_, aliasErr := s.repo.GetModelGroupByAlias(ctx, orgID, model)
		if model != "auto" && aliasErr != nil {
			return 0, fmt.Errorf("no catalog pricing for model %q", model)
		}
		if summaryLookup, ok := s.repo.(storage.GlobalModelPricingSummaryLookup); ok {
			summary, summaryErr := summaryLookup.GetGlobalModelPricingSummary(ctx)
			if summaryErr != nil {
				return 0, summaryErr
			}
			if s.budgetStats != nil {
				s.budgetStats.pricingSummaries.Add(1)
				if summary.Rebuilt {
					s.budgetStats.catalogScans.Add(1)
				}
			}
			if summary.HasPricedModels {
				catalogMax = &domain.GlobalModel{
					PricingStatus:              domain.PricingStatusVerified,
					InputCostMicrosPer1M:       summary.InputCostMicrosPer1M,
					CachedInputCostMicrosPer1M: summary.CachedInputCostMicrosPer1M,
					CacheWriteCostMicrosPer1M:  summary.CacheWriteCostMicrosPer1M,
					OutputCostMicrosPer1M:      summary.OutputCostMicrosPer1M,
					ReasoningCostMicrosPer1M:   summary.ReasoningCostMicrosPer1M,
					MaxOutputTokens:            summary.MaxOutputTokens,
				}
			}
		} else {
			if s.budgetStats != nil {
				s.budgetStats.catalogScans.Add(1)
			}
			allModels, listErr := s.repo.ListGlobalModels(ctx)
			if listErr != nil {
				return 0, listErr
			}
			for _, gm := range allModels {
				if gm != nil && (domain.ResolvePricingStatus(gm) == domain.PricingStatusVerified || domain.ResolvePricingStatus(gm) == domain.PricingStatusCustom) {
					maxModel(&catalogMax, gm)
				}
			}
		}
		match = catalogMax
		if match == nil {
			return 0, fmt.Errorf("no known catalog pricing")
		}
	}
	maxOutput := requestedOutput
	if maxOutput == 0 {
		maxOutput = match.MaxOutputTokens
	}
	if requestedOutput < 0 {
		maxOutput = 0
	}
	if maxOutput <= 0 && requestedOutput >= 0 {
		return 0, fmt.Errorf("model %q has no enforceable maximum output", model)
	}
	bound, ok := finops.EstimateTokenCostUpperBound(match, inputTokens, maxOutput)
	if !ok {
		return 0, fmt.Errorf("model %q has unknown or incomplete pricing", model)
	}
	return bound, nil
}

func (s *GatewayServer) acquireRequestQuota(ctx context.Context, id *domain.IdentityContext, model string, inputTokens, requestedOutput int, requestID string) (func(int), error) {
	return s.acquireRequestQuotaWithBound(ctx, id, model, inputTokens, inputTokens, requestedOutput, requestID)
}

func (s *GatewayServer) reservationLeaseRenewInterval() time.Duration {
	if s != nil && s.budgetStats != nil && s.budgetStats.leaseRenewInterval > 0 {
		return s.budgetStats.leaseRenewInterval
	}
	return defaultReservationLeaseRenewInterval
}

// startReservationLeaseRenewer periodically extends active budget reservation
// leases while a budgeted request is in flight.
func (s *GatewayServer) startReservationLeaseRenewer(ctx context.Context, id *domain.IdentityContext, requestID string) func() {
	if s == nil || s.limiter == nil || !identityHasBudget(id) || requestID == "" {
		return func() {}
	}
	if ctx == nil {
		ctx = context.Background()
	}
	interval := s.reservationLeaseRenewInterval()
	leaseCtx, cancelLease := context.WithCancel(ctx)
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-leaseCtx.Done():
				return
			case <-ticker.C:
				renewCtx, cancelRenew := context.WithTimeout(leaseCtx, defaultLeaseRenewCallTimeout)
				err := s.limiter.RenewReservationLease(renewCtx, id, requestID, defaultReservationLeaseTTLSec)
				cancelRenew()
				if err != nil {
					if leaseCtx.Err() == nil {
						logger.Warn("Reservation lease renewal failed",
							slog.String("component", "budget"),
							slog.String("request_id", requestID),
							slog.String("error", err.Error()),
						)
					}
					continue
				}
				if s.budgetStats != nil {
					s.budgetStats.leaseRenewals.Add(1)
				}
			}
		}
	}()
	var stopOnce sync.Once
	return func() {
		stopOnce.Do(func() {
			cancelLease()
			wg.Wait()
		})
	}
}

func (s *GatewayServer) wrapBudgetRelease(ctx context.Context, id *domain.IdentityContext, requestID string, release func(int, int64)) func(actualTokens int, overrideCostMicros int64) {
	stopRenewer := s.startReservationLeaseRenewer(ctx, id, requestID)
	var once sync.Once
	return func(actualTokens int, overrideCostMicros int64) {
		once.Do(func() {
			stopRenewer()
			cost := int64(-2)
			if actualTokens < 0 {
				cost = -1
			} else if overrideCostMicros >= 0 {
				cost = overrideCostMicros
			}
			release(actualTokens, cost)
			if actualTokens >= 0 && overrideCostMicros >= 0 && s.spendWorker == nil && s.limiter != nil && id != nil {
				settleCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				defer cancel()
				_ = s.limiter.RecordSpendIncrementForUserEvent(settleCtx, "", requestID, id.VirtualKeyID, id.TeamID, id.UserID, id.OrgID, overrideCostMicros)
			}
		})
	}
}

func mergeVerifiedBudgetModel(match **domain.GlobalModel, sawUnverified *bool, gm *domain.GlobalModel) {
	if gm == nil {
		return
	}
	status := domain.ResolvePricingStatus(gm)
	if status != domain.PricingStatusVerified && status != domain.PricingStatusCustom {
		*sawUnverified = true
		return
	}
	if *match == nil {
		copyGM := *gm
		copyGM.ModalityPricingJSON = cloneModalityPricing(gm.ModalityPricingJSON)
		*match = &copyGM
		return
	}
	m := *match
	mergeModalityPricing(m, gm.ModalityPricingJSON)
	if gm.InputCostMicrosPer1M > m.InputCostMicrosPer1M {
		m.InputCostMicrosPer1M = gm.InputCostMicrosPer1M
	}
	if gm.CachedInputCostMicrosPer1M > m.CachedInputCostMicrosPer1M {
		m.CachedInputCostMicrosPer1M = gm.CachedInputCostMicrosPer1M
	}
	if gm.CacheWriteCostMicrosPer1M > m.CacheWriteCostMicrosPer1M {
		m.CacheWriteCostMicrosPer1M = gm.CacheWriteCostMicrosPer1M
	}
	if gm.OutputCostMicrosPer1M > m.OutputCostMicrosPer1M {
		m.OutputCostMicrosPer1M = gm.OutputCostMicrosPer1M
	}
	if gm.ReasoningCostMicrosPer1M > m.ReasoningCostMicrosPer1M {
		m.ReasoningCostMicrosPer1M = gm.ReasoningCostMicrosPer1M
	}
	if gm.ImageCostMicrosBase > m.ImageCostMicrosBase {
		m.ImageCostMicrosBase = gm.ImageCostMicrosBase
	}
	if gm.ImageCostMicrosHD > m.ImageCostMicrosHD {
		m.ImageCostMicrosHD = gm.ImageCostMicrosHD
	}
	if gm.AudioSTTCostMicrosPerSecond > m.AudioSTTCostMicrosPerSecond {
		m.AudioSTTCostMicrosPerSecond = gm.AudioSTTCostMicrosPerSecond
	}
	if gm.AudioTTSCostMicrosPer1KChars > m.AudioTTSCostMicrosPer1KChars {
		m.AudioTTSCostMicrosPer1KChars = gm.AudioTTSCostMicrosPer1KChars
	}
	if gm.RerankCostMicrosPerSearchUnit > m.RerankCostMicrosPerSearchUnit {
		m.RerankCostMicrosPerSearchUnit = gm.RerankCostMicrosPerSearchUnit
	}
	if gm.MaxOutputTokens > m.MaxOutputTokens {
		m.MaxOutputTokens = gm.MaxOutputTokens
	}
}

func (s *GatewayServer) resolveMatchedVerifiedModel(ctx context.Context, orgID, model string) (*domain.GlobalModel, bool, error) {
	_, bareModel, canonicalID := config.ParseProviderModel(model)
	qualifiedProvider := domain.ProviderType("")
	qualified := false
	if slash := strings.IndexByte(model, '/'); slash > 0 && config.IsKnownProviderAlias(model[:slash]) {
		qualifiedProvider = config.NormalizeProvider(model[:slash])
		qualified = true
	}
	lookupProvider := domain.ProviderType("")
	if qualified {
		lookupProvider = qualifiedProvider
	}
	models, err := s.budgetModelCandidates(ctx, lookupProvider, model)
	if err != nil {
		return nil, false, err
	}
	var match *domain.GlobalModel
	var sawUnverified bool
	for _, gm := range models {
		if gm == nil {
			continue
		}
		isMatch := false
		if qualified {
			isMatch = config.NormalizeProvider(string(gm.Provider)) == qualifiedProvider && (gm.ID == canonicalID || gm.ID == model || (bareModel != "" && gm.ModelName == bareModel))
		} else {
			isMatch = gm.ID == model || gm.ID == canonicalID || gm.ModelName == model || (bareModel != "" && gm.ModelName == bareModel)
		}
		if isMatch {
			mergeVerifiedBudgetModel(&match, &sawUnverified, gm)
		}
	}
	// Resolve model-group aliases (e.g. "prod-image", "prod-tts") to their underlying
	// active deployment models so budgeted modality requests compute true upper-bound costs.
	if match == nil && !sawUnverified && orgID != "" && s.repo != nil {
		if mg, mgErr := s.repo.GetModelGroupByAlias(ctx, orgID, model); mgErr == nil && mg != nil {
			if deps, depErr := s.repo.ListDeploymentsByGroup(ctx, mg.ID); depErr == nil {
				for _, dep := range deps {
					if dep == nil || dep.Status == domain.DeploymentStatusDisabled {
						continue
					}
					gm := dep.GlobalModel
					if gm == nil && dep.GlobalModelID != "" {
						gm, _ = s.repo.GetGlobalModel(ctx, dep.GlobalModelID)
					}
					mergeVerifiedBudgetModel(&match, &sawUnverified, gm)
				}
			}
		}
	}
	return match, sawUnverified, nil
}

func cloneModalityPricing(src map[string]any) map[string]any {
	if len(src) == 0 {
		return nil
	}
	dst := make(map[string]any, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func mergeModalityPricing(dst *domain.GlobalModel, src map[string]any) {
	if dst == nil || len(src) == 0 {
		return
	}
	if dst.ModalityPricingJSON == nil {
		dst.ModalityPricingJSON = make(map[string]any, len(src))
	}
	for key, value := range src {
		rate, ok := modalityRate(value)
		if !ok {
			continue
		}
		current, exists := modalityRate(dst.ModalityPricingJSON[key])
		if !exists || rate > current {
			dst.ModalityPricingJSON[key] = rate
		}
	}
}

func modalityRate(value any) (int64, bool) {
	switch v := value.(type) {
	case int:
		return int64(v), true
	case int64:
		return v, true
	case float64:
		if v < 0 || v >= float64(int64(^uint64(0)>>1)) {
			return 0, false
		}
		return int64(math.Ceil(v)), true
	default:
		return 0, false
	}
}

func (s *GatewayServer) acquireModalityBudget(ctx context.Context, id *domain.IdentityContext, model string, rateTokens int, requestID string, estimator func(*domain.GlobalModel) (int64, bool)) (func(int), error) {
	if !identityHasBudget(id) {
		return s.limiter.Acquire(ctx, id, rateTokens)
	}
	if s.budgetStats != nil {
		s.budgetStats.budgetedChecks.Add(1)
	}
	gm, sawUnverified, err := s.resolveMatchedVerifiedModel(ctx, id.OrgID, model)
	if err != nil || gm == nil {
		if sawUnverified {
			return nil, &domain.GatewayError{StatusCode: http.StatusForbidden, Type: domain.ErrorTypeBudgetExceeded, Code: "pricing_unknown_budget_restricted", Message: "Budgeted requests require known model pricing"}
		}
		return nil, &domain.GatewayError{StatusCode: http.StatusServiceUnavailable, Type: domain.ErrorTypeBudgetExceeded, Code: "budget_estimate_unavailable", Message: "A safe upper-bound cost could not be calculated before dispatch"}
	}
	reserve, ok := estimator(gm)
	if !ok {
		return nil, &domain.GatewayError{StatusCode: http.StatusServiceUnavailable, Type: domain.ErrorTypeBudgetExceeded, Code: "budget_estimate_unavailable", Message: "A safe upper-bound cost could not be calculated before dispatch"}
	}
	release, err := s.limiter.AcquireWithBudget(ctx, id, rateTokens, reserve, requestID)
	if err != nil {
		return nil, err
	}
	releaseWithCost := s.wrapBudgetRelease(ctx, id, requestID, release)
	return func(tokens int) {
		releaseWithCost(tokens, -2)
	}, nil
}

func (s *GatewayServer) acquireRequestQuotaWithBound(ctx context.Context, id *domain.IdentityContext, model string, rateTokens, budgetInputTokens, requestedOutput int, requestID string) (func(int), error) {
	releaseWithCost, err := s.acquireRequestQuotaWithCost(ctx, id, model, rateTokens, budgetInputTokens, requestedOutput, requestID)
	if err != nil {
		return nil, err
	}
	return func(tokens int) {
		releaseWithCost(tokens, -2)
	}, nil
}

func (s *GatewayServer) acquireRequestQuotaWithCost(ctx context.Context, id *domain.IdentityContext, model string, rateTokens, budgetInputTokens, requestedOutput int, requestID string) (func(actualTokens int, overrideCostMicros int64), error) {
	if !identityHasBudget(id) {
		release, err := s.limiter.Acquire(ctx, id, rateTokens)
		if err != nil {
			return nil, err
		}
		var once sync.Once
		return func(actualTokens int, _ int64) {
			once.Do(func() {
				release(actualTokens)
			})
		}, nil
	}
	if s.budgetStats != nil {
		s.budgetStats.budgetedChecks.Add(1)
	}
	reserve, err := s.tokenBudgetUpperBound(ctx, id.OrgID, model, budgetInputTokens, requestedOutput)
	if err != nil {
		if errors.Is(err, errBudgetPricingUnverified) {
			return nil, &domain.GatewayError{StatusCode: http.StatusForbidden, Type: domain.ErrorTypeBudgetExceeded, Code: "pricing_unknown_budget_restricted", Message: "Budgeted requests require known model pricing"}
		}
		return nil, &domain.GatewayError{StatusCode: 503, Type: domain.ErrorTypeBudgetExceeded, Code: "budget_estimate_unavailable", Message: "A safe upper-bound cost could not be calculated before dispatch"}
	}
	release, err := s.limiter.AcquireWithBudget(ctx, id, rateTokens, reserve, requestID)
	if err != nil {
		return nil, err
	}
	return s.wrapBudgetRelease(ctx, id, requestID, release), nil
}

func (s *GatewayServer) estimateInputCostMicros(orgID, model string, gm *domain.GlobalModel, inputTokens int) int64 {
	if inputTokens <= 0 {
		return 0
	}
	if gm != nil {
		if cost, ok := finops.EstimateTokenCostUpperBound(gm, inputTokens, 0); ok {
			return cost
		}
		if cost := finops.CalculateCostMicros(gm, domain.TokenUsage{PromptTokens: inputTokens, TotalTokens: inputTokens}); cost > 0 {
			return cost
		}
	}
	if s != nil && s.repo != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		if cost, err := s.tokenBudgetUpperBound(ctx, orgID, model, inputTokens, -1); err == nil && cost >= 0 {
			return cost
		}
	}
	return 0
}

type postDispatchSettlement struct {
	idCtx                  *domain.IdentityContext
	reqID                  string
	traceID                string
	endpoint               string
	modality               domain.ModalityType
	requestedModel         string
	estTokens              int
	isStream               bool
	actualTokensReconciled bool
	upstreamDispatched     bool
	meta                   *router.ExecutionMeta
	selectedDep            *domain.Deployment
	dispatchErr            error
	reqCtx                 context.Context
	releaseQuota           func(actualTokens int, overrideCostMicros int64)
}

func (s *GatewayServer) settleQuotaOnReturn(p *postDispatchSettlement) {
	if p == nil || p.releaseQuota == nil || p.actualTokensReconciled {
		return
	}
	if !p.upstreamDispatched {
		p.releaseQuota(-1, -1)
		return
	}
	var gm *domain.GlobalModel
	var depID string
	var provider domain.ProviderType
	var pricingVer int
	resolvedModel := p.requestedModel
	dep := p.selectedDep
	if p.meta != nil && p.meta.WinningDeployment != nil {
		dep = p.meta.WinningDeployment
	}
	if dep != nil {
		depID = dep.ID
		gm = dep.GlobalModel
		if gm != nil {
			provider = gm.Provider
			pricingVer = gm.PricingVersion
			if gm.ModelName != "" {
				resolvedModel = gm.ModelName
			}
		}
	}
	var orgID string
	if p.idCtx != nil {
		orgID = p.idCtx.OrgID
	}
	inputCostMicros := s.estimateInputCostMicros(orgID, p.requestedModel, gm, p.estTokens)
	p.releaseQuota(p.estTokens, inputCostMicros)

	if s != nil && s.spendWorker != nil && p.idCtx != nil {
		statusCode := http.StatusBadGateway
		if (p.reqCtx != nil && errors.Is(p.reqCtx.Err(), context.Canceled)) || errors.Is(p.dispatchErr, context.Canceled) {
			statusCode = 499
		} else if gwErr := (*domain.GatewayError)(nil); errors.As(p.dispatchErr, &gwErr) && gwErr.StatusCode > 0 {
			statusCode = gwErr.StatusCode
		}
		settleCtx := context.Background()
		if p.reqCtx != nil {
			settleCtx = context.WithoutCancel(p.reqCtx)
		}
		var cancel context.CancelFunc
		settleCtx, cancel = context.WithTimeout(settleCtx, 2*time.Second)
		defer cancel()

		var provenance string
		if gm != nil {
			provenance = gm.PricingProvenanceSource
		}
		var latMs, ttftMs int64
		var retries int
		var fb bool
		if p.meta != nil {
			latMs = p.meta.LatencyMs
			ttftMs = p.meta.TTFTMs
			retries = p.meta.RetryCount
			fb = p.meta.FallbackAttempted
		}
		_ = s.spendWorker.Record(settleCtx, domain.SpendEvent{
			RequestID:               p.reqID,
			TraceID:                 p.traceID,
			OrgID:                   p.idCtx.OrgID,
			TeamID:                  p.idCtx.TeamID,
			UserID:                  p.idCtx.UserID,
			VirtualKeyID:            p.idCtx.VirtualKeyID,
			Endpoint:                p.endpoint,
			Modality:                p.modality,
			RequestedModel:          p.requestedModel,
			ResolvedModel:           resolvedModel,
			Provider:                provider,
			DeploymentID:            depID,
			PricingVersion:          pricingVer,
			PricingStatus:           domain.ResolvePricingStatus(gm),
			PricingProvenanceSource: provenance,
			Usage: domain.TokenUsage{
				PromptTokens: p.estTokens,
				TotalTokens:  p.estTokens,
			},
			CostMicros:        inputCostMicros,
			LatencyMs:         latMs,
			TTFTMs:            ttftMs,
			StatusCode:        statusCode,
			IsStream:          p.isStream,
			FallbackAttempted: fb,
			RetryCount:        retries,
			CreatedAt:         time.Now().UTC(),
		})
	}
}
