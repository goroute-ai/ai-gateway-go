package server

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/finops"
)

func rejectBudgetedUnsupported(w http.ResponseWriter, id *domain.IdentityContext) bool {
	if !identityHasBudget(id) {
		return false
	}
	domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: http.StatusServiceUnavailable, Type: domain.ErrorTypeBudgetExceeded, Code: "budget_estimate_unavailable", Message: "This modality has no safe pre-dispatch upper-bound cost estimator"})
	return true
}

func identityHasBudget(id *domain.IdentityContext) bool {
	return id != nil && (id.KeyMaxBudgetMicros > 0 || id.TeamMaxBudgetMicros > 0 || id.OrgMaxBudgetMicros > 0)
}

// tokenBudgetUpperBound requires an unambiguous catalog model and prices the
// input plus the full caller/model output allowance at conservative rates.
// Aliases, unknown pricing, and unbounded outputs fail closed.
func (s *GatewayServer) tokenBudgetUpperBound(ctx context.Context, orgID, model string, inputTokens, requestedOutput int) (int64, error) {
	models, err := s.repo.ListGlobalModels(ctx)
	if err != nil {
		return 0, err
	}
	var match *domain.GlobalModel
	var catalogMax *domain.GlobalModel
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
	for _, gm := range models {
		if gm == nil || (domain.ResolvePricingStatus(gm) != domain.PricingStatusVerified && domain.ResolvePricingStatus(gm) != domain.PricingStatusCustom) {
			continue
		}
		maxModel(&catalogMax, gm)
		if gm.ID == model || gm.ModelName == model || gm.ID == "openai/"+model || gm.ID == "anthropic/"+model || gm.ID == "google/"+model {
			maxModel(&match, gm)
		}
	}
	if match == nil {
		// Model-group aliases such as "auto" can route to any catalog model.
		// The maximum published text-token rates across the full catalog safely
		// bounds every known-priced deployment reachable through that alias.
		_, aliasErr := s.repo.GetModelGroupByAlias(ctx, orgID, model)
		if model != "auto" && aliasErr != nil {
			return 0, fmt.Errorf("no catalog pricing for model %q", model)
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

func (s *GatewayServer) acquireRequestQuotaWithBound(ctx context.Context, id *domain.IdentityContext, model string, rateTokens, budgetInputTokens, requestedOutput int, requestID string) (func(int), error) {
	if !identityHasBudget(id) {
		return s.limiter.Acquire(ctx, id, rateTokens)
	}
	reserve, err := s.tokenBudgetUpperBound(ctx, id.OrgID, model, budgetInputTokens, requestedOutput)
	if err != nil {
		if models, listErr := s.repo.ListGlobalModels(ctx); listErr == nil {
			for _, gm := range models {
				if gm != nil && (gm.ID == model || gm.ModelName == model || strings.HasSuffix(gm.ID, "/"+model)) && domain.ResolvePricingStatus(gm) != domain.PricingStatusVerified && domain.ResolvePricingStatus(gm) != domain.PricingStatusCustom {
					return nil, &domain.GatewayError{StatusCode: http.StatusForbidden, Type: domain.ErrorTypeBudgetExceeded, Code: "pricing_unknown_budget_restricted", Message: "Budgeted requests require known model pricing"}
				}
			}
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
