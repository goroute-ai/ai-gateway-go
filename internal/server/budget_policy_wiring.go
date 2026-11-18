package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/finops"
)

const defaultBudgetExceededThrottlePct = 0.10

type budgetPolicyAcquisition struct {
	EffectiveModel  string
	ReleaseQuota    func(actualTokens int, overrideCostMicros int64)
	Throttled       bool
	FallbackApplied bool
}

func (s *GatewayServer) budgetExceededThrottlePct() float64 {
	if s != nil && s.cfg != nil && s.cfg.FinOps.BudgetExceededThrottlePct > 0 {
		return s.cfg.FinOps.BudgetExceededThrottlePct
	}
	return defaultBudgetExceededThrottlePct
}

func applyBudgetPolicyHeaders(w http.ResponseWriter, originalModel string, acq budgetPolicyAcquisition) {
	if w == nil {
		return
	}
	if acq.Throttled {
		w.Header().Set("X-Gateway-Budget-Throttled", "true")
	}
	if acq.FallbackApplied && acq.EffectiveModel != "" {
		w.Header().Set("X-Gateway-Budget-Fallback", acq.EffectiveModel)
		if originalModel != "" {
			w.Header().Set("X-Gateway-Original-Model", originalModel)
		}
	}
}

func isBudgetRejectionError(err error) bool {
	if err == nil {
		return false
	}
	var gwErr *domain.GatewayError
	if !errors.As(err, &gwErr) || gwErr == nil {
		return false
	}
	return gwErr.Type == domain.ErrorTypeBudgetExceeded
}

func markScopeBudgetExhausted(id *domain.IdentityContext, err error) (*domain.IdentityContext, bool) {
	if id == nil || err == nil {
		return id, false
	}
	var gwErr *domain.GatewayError
	if !errors.As(err, &gwErr) || gwErr == nil || gwErr.Type != domain.ErrorTypeBudgetExceeded {
		return id, false
	}
	clone := *id
	switch strings.ToLower(strings.TrimSpace(gwErr.Code)) {
	case "key_budget_exceeded":
		if !clone.KeyThrottleOnBudgetExceeded || clone.KeyMaxBudgetMicros <= 0 {
			return id, false
		}
		clone.KeySpentMicros = clone.KeyMaxBudgetMicros
		return &clone, true
	case "team_budget_exceeded":
		if !clone.TeamThrottleOnBudgetExceeded || clone.TeamMaxBudgetMicros <= 0 {
			return id, false
		}
		clone.TeamSpentMicros = clone.TeamMaxBudgetMicros
		return &clone, true
	case "user_budget_exceeded":
		if !clone.UserThrottleOnBudgetExceeded || clone.UserMaxBudgetMicros <= 0 {
			return id, false
		}
		clone.UserSpentMicros = clone.UserMaxBudgetMicros
		return &clone, true
	case "org_budget_exceeded":
		if !clone.OrgThrottleOnBudgetExceeded || clone.OrgMaxBudgetMicros <= 0 {
			return id, false
		}
		clone.OrgSpentMicros = clone.OrgMaxBudgetMicros
		return &clone, true
	default:
		return id, false
	}
}

func hasBudgetFallbacksForModel(id *domain.IdentityContext, model string) bool {
	if id == nil {
		return false
	}
	m := strings.TrimSpace(model)
	if m == "" {
		return false
	}
	return len(id.KeyBudgetFallbacks[m]) > 0 ||
		len(id.TeamBudgetFallbacks[m]) > 0 ||
		len(id.UserBudgetFallbacks[m]) > 0 ||
		len(id.OrgBudgetFallbacks[m]) > 0
}

func (s *GatewayServer) checkModelDeploymentBudget(ctx context.Context, orgID, model string) error {
	if s == nil || s.depBudgets == nil || s.repo == nil || strings.TrimSpace(orgID) == "" {
		return nil
	}
	var providerCaps map[string]int64
	if s.cfg != nil {
		providerCaps = s.cfg.Router.ProviderBudgets
	}

	mg, err := s.repo.GetModelGroupByAlias(ctx, orgID, model)
	if err == nil && mg != nil && mg.IsActive {
		deps, depErr := s.repo.ListDeploymentsByGroup(ctx, mg.ID)
		if depErr == nil && len(deps) > 0 {
			activeCount := 0
			withinBudgetCount := 0
			for _, dep := range deps {
				if dep == nil || dep.Status == domain.DeploymentStatusDisabled {
					continue
				}
				activeCount++
				if s.depBudgets.IsWithinBudget(ctx, orgID, dep, providerCaps) {
					withinBudgetCount++
				}
			}
			if activeCount > 0 && withinBudgetCount == 0 {
				return &domain.GatewayError{
					StatusCode:    http.StatusTooManyRequests,
					Type:          domain.ErrorTypeBudgetExceeded,
					Code:          "model_budget_exceeded",
					Message:       fmt.Sprintf("All deployments for model %q exceeded configured deployment or provider budget", model),
					RetryAfterSec: 60,
				}
			}
		}
		return nil
	}

	if len(providerCaps) > 0 {
		provider, _, _ := config.ParseProviderModel(model)
		if provider != "" {
			syntheticDep := &domain.Deployment{
				GlobalModelID: model,
				GlobalModel:   &domain.GlobalModel{Provider: provider},
			}
			if !s.depBudgets.IsWithinBudget(ctx, orgID, syntheticDep, providerCaps) {
				return &domain.GatewayError{
					StatusCode:    http.StatusTooManyRequests,
					Type:          domain.ErrorTypeBudgetExceeded,
					Code:          "model_budget_exceeded",
					Message:       fmt.Sprintf("Provider budget exceeded for model %q", model),
					RetryAfterSec: 60,
				}
			}
		}
	}
	return nil
}

func (s *GatewayServer) acquireQuotaWithoutThrottle(ctx context.Context, id *domain.IdentityContext, model string, rateTokens, budgetInputTokens, requestedOutput int, requestID string) (func(actualTokens int, overrideCostMicros int64), error) {
	if s == nil {
		return func(int, int64) {}, nil
	}
	if !identityHasBudget(id) {
		if s.limiter == nil {
			return func(int, int64) {}, nil
		}
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
		return nil, &domain.GatewayError{StatusCode: http.StatusServiceUnavailable, Type: domain.ErrorTypeBudgetExceeded, Code: "budget_estimate_unavailable", Message: "A safe upper-bound cost could not be calculated before dispatch"}
	}
	if s.limiter == nil {
		return func(int, int64) {}, nil
	}
	release, err := s.limiter.AcquireWithBudget(ctx, id, rateTokens, reserve, requestID)
	if err != nil {
		return nil, err
	}
	return s.wrapBudgetRelease(ctx, id, requestID, release), nil
}

func (s *GatewayServer) acquireQuotaWithThrottle(ctx context.Context, id *domain.IdentityContext, model string, rateTokens, budgetInputTokens, requestedOutput int, requestID string) (func(actualTokens int, overrideCostMicros int64), bool, error) {
	pct := s.budgetExceededThrottlePct()
	currID := id
	throttled := false

	for attempt := 0; attempt < 5; attempt++ {
		effID, applied := finops.ApplyBudgetThrottle(currID, pct)
		if applied {
			throttled = true
		}
		release, err := s.acquireQuotaWithoutThrottle(ctx, effID, model, rateTokens, budgetInputTokens, requestedOutput, requestID)
		if err == nil {
			return release, throttled, nil
		}
		nextID, canThrottle := markScopeBudgetExhausted(currID, err)
		if !canThrottle {
			return nil, throttled, err
		}
		currID = nextID
	}
	return nil, throttled, &domain.GatewayError{
		StatusCode: http.StatusTooManyRequests,
		Type:       domain.ErrorTypeBudgetExceeded,
		Code:       "budget_exceeded",
		Message:    "Configured budget exceeded across multiple scopes",
	}
}

func (s *GatewayServer) acquireModalityQuotaWithThrottle(ctx context.Context, id *domain.IdentityContext, model string, rateTokens int, requestID string, estimator func(*domain.GlobalModel) (int64, bool)) (func(int), bool, error) {
	if s == nil {
		return func(int) {}, false, nil
	}
	pct := s.budgetExceededThrottlePct()
	currID := id
	throttled := false

	for attempt := 0; attempt < 5; attempt++ {
		effID, applied := finops.ApplyBudgetThrottle(currID, pct)
		if applied {
			throttled = true
		}
		if !identityHasBudget(effID) {
			if s.limiter == nil {
				return func(int) {}, throttled, nil
			}
			release, err := s.limiter.Acquire(ctx, effID, rateTokens)
			if err == nil {
				return release, throttled, nil
			}
			return nil, throttled, err
		}
		if s.budgetStats != nil {
			s.budgetStats.budgetedChecks.Add(1)
		}
		gm, sawUnverified, err := s.resolveMatchedVerifiedModel(ctx, effID.OrgID, model)
		if err != nil || gm == nil {
			if sawUnverified {
				return nil, throttled, &domain.GatewayError{StatusCode: http.StatusForbidden, Type: domain.ErrorTypeBudgetExceeded, Code: "pricing_unknown_budget_restricted", Message: "Budgeted requests require known model pricing"}
			}
			return nil, throttled, &domain.GatewayError{StatusCode: http.StatusServiceUnavailable, Type: domain.ErrorTypeBudgetExceeded, Code: "budget_estimate_unavailable", Message: "A safe upper-bound cost could not be calculated before dispatch"}
		}
		reserve, ok := estimator(gm)
		if !ok {
			return nil, throttled, &domain.GatewayError{StatusCode: http.StatusServiceUnavailable, Type: domain.ErrorTypeBudgetExceeded, Code: "budget_estimate_unavailable", Message: "A safe upper-bound cost could not be calculated before dispatch"}
		}
		if s.limiter == nil {
			return func(int) {}, throttled, nil
		}
		release, err := s.limiter.AcquireWithBudget(ctx, effID, rateTokens, reserve, requestID)
		if err == nil {
			releaseWithCost := s.wrapBudgetRelease(ctx, effID, requestID, release)
			return func(tokens int) {
				releaseWithCost(tokens, -2)
			}, throttled, nil
		}
		nextID, canThrottle := markScopeBudgetExhausted(currID, err)
		if !canThrottle {
			return nil, throttled, err
		}
		currID = nextID
	}
	return nil, throttled, &domain.GatewayError{
		StatusCode: http.StatusTooManyRequests,
		Type:       domain.ErrorTypeBudgetExceeded,
		Code:       "budget_exceeded",
		Message:    "Configured budget exceeded across multiple scopes",
	}
}

func (s *GatewayServer) acquireQuotaWithBudgetPolicy(
	ctx context.Context,
	id *domain.IdentityContext,
	requestedModel string,
	rateTokens, budgetInputTokens, requestedOutput int,
	requestID string,
) (budgetPolicyAcquisition, error) {
	hasFallbacks := hasBudgetFallbacksForModel(id, requestedModel)

	if hasFallbacks {
		orgID := ""
		if id != nil {
			orgID = id.OrgID
		}
		depErr := s.checkModelDeploymentBudget(ctx, orgID, requestedModel)
		if depErr == nil {
			release, err := s.acquireQuotaWithoutThrottle(ctx, id, requestedModel, rateTokens, budgetInputTokens, requestedOutput, requestID)
			if err == nil {
				return budgetPolicyAcquisition{
					EffectiveModel: requestedModel,
					ReleaseQuota:   release,
				}, nil
			}
			if !isBudgetRejectionError(err) {
				return budgetPolicyAcquisition{}, err
			}
		}

		var winningRelease func(int, int64)
		if fbModel, ok := finops.ResolveBudgetFallbackModel(ctx, id, requestedModel, func(checkCtx context.Context, candidate string) error {
			if s.rbac != nil {
				if err := s.rbac.AuthorizeRequestedModel(id, candidate); err != nil {
					return err
				}
			}
			if err := s.checkModelDeploymentBudget(checkCtx, orgID, candidate); err != nil {
				return err
			}
			rel, err := s.acquireQuotaWithoutThrottle(checkCtx, id, candidate, rateTokens, budgetInputTokens, requestedOutput, requestID)
			if err != nil {
				return err
			}
			winningRelease = rel
			return nil
		}); ok {
			return budgetPolicyAcquisition{
				EffectiveModel:  fbModel,
				ReleaseQuota:    winningRelease,
				FallbackApplied: true,
			}, nil
		}
	}

	release, throttled, err := s.acquireQuotaWithThrottle(ctx, id, requestedModel, rateTokens, budgetInputTokens, requestedOutput, requestID)
	if err != nil {
		return budgetPolicyAcquisition{}, err
	}
	return budgetPolicyAcquisition{
		EffectiveModel: requestedModel,
		ReleaseQuota:   release,
		Throttled:      throttled,
	}, nil
}
