package server

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/http"
	"strings"
	"sync/atomic"

	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/finops"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

type budgetLookupStats struct {
	indexedLookups   atomic.Uint64
	catalogScans     atomic.Uint64
	budgetedChecks   atomic.Uint64
	pricingSummaries atomic.Uint64
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
	return id != nil && (id.KeyMaxBudgetMicros > 0 || id.TeamMaxBudgetMicros > 0 || id.OrgMaxBudgetMicros > 0)
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
		if !isMatch {
			continue
		}
		status := domain.ResolvePricingStatus(gm)
		if status != domain.PricingStatusVerified && status != domain.PricingStatusCustom {
			sawUnverified = true
			continue
		}
		if match == nil {
			copyGM := *gm
			copyGM.ModalityPricingJSON = cloneModalityPricing(gm.ModalityPricingJSON)
			match = &copyGM
		} else {
			mergeModalityPricing(match, gm.ModalityPricingJSON)
			if gm.InputCostMicrosPer1M > match.InputCostMicrosPer1M {
				match.InputCostMicrosPer1M = gm.InputCostMicrosPer1M
			}
			if gm.CachedInputCostMicrosPer1M > match.CachedInputCostMicrosPer1M {
				match.CachedInputCostMicrosPer1M = gm.CachedInputCostMicrosPer1M
			}
			if gm.CacheWriteCostMicrosPer1M > match.CacheWriteCostMicrosPer1M {
				match.CacheWriteCostMicrosPer1M = gm.CacheWriteCostMicrosPer1M
			}
			if gm.OutputCostMicrosPer1M > match.OutputCostMicrosPer1M {
				match.OutputCostMicrosPer1M = gm.OutputCostMicrosPer1M
			}
			if gm.ReasoningCostMicrosPer1M > match.ReasoningCostMicrosPer1M {
				match.ReasoningCostMicrosPer1M = gm.ReasoningCostMicrosPer1M
			}
			if gm.ImageCostMicrosBase > match.ImageCostMicrosBase {
				match.ImageCostMicrosBase = gm.ImageCostMicrosBase
			}
			if gm.ImageCostMicrosHD > match.ImageCostMicrosHD {
				match.ImageCostMicrosHD = gm.ImageCostMicrosHD
			}
			if gm.AudioSTTCostMicrosPerSecond > match.AudioSTTCostMicrosPerSecond {
				match.AudioSTTCostMicrosPerSecond = gm.AudioSTTCostMicrosPerSecond
			}
			if gm.AudioTTSCostMicrosPer1KChars > match.AudioTTSCostMicrosPer1KChars {
				match.AudioTTSCostMicrosPer1KChars = gm.AudioTTSCostMicrosPer1KChars
			}
			if gm.RerankCostMicrosPerSearchUnit > match.RerankCostMicrosPerSearchUnit {
				match.RerankCostMicrosPerSearchUnit = gm.RerankCostMicrosPerSearchUnit
			}
			if gm.MaxOutputTokens > match.MaxOutputTokens {
				match.MaxOutputTokens = gm.MaxOutputTokens
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
	return func(tokens int) {
		cost := int64(-2)
		if tokens < 0 {
			cost = -1
		}
		release(tokens, cost)
	}, nil
}

func (s *GatewayServer) acquireRequestQuotaWithBound(ctx context.Context, id *domain.IdentityContext, model string, rateTokens, budgetInputTokens, requestedOutput int, requestID string) (func(int), error) {
	if !identityHasBudget(id) {
		return s.limiter.Acquire(ctx, id, rateTokens)
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
	return func(tokens int) {
		cost := int64(-2)
		if tokens < 0 {
			cost = -1
		}
		release(tokens, cost)
	}, nil
}
