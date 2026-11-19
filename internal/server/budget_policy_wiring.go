package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/finops"
	"github.com/goroute-ai/ai-gateway-go/internal/ratelimit"
)

const defaultBudgetExceededThrottlePct = 0.10

type budgetPolicyAcquisition struct {
	EffectiveModel  string
	ReleaseQuota    func(actualTokens int, overrideCostMicros int64)
	ReleaseUsage    func(actualInput, actualOutput int, overrideCostMicros int64)
	RateLimitMeta   *domain.RateLimitHeaderMetadata
	Throttled       bool
	FallbackApplied bool
}

func legacyReleaseFromUsage(releaseUsage func(actualInput, actualOutput int, overrideCostMicros int64)) func(actualTokens int, overrideCostMicros int64) {
	if releaseUsage == nil {
		return nil
	}
	return func(actualTokens int, overrideCostMicros int64) {
		if actualTokens < 0 {
			releaseUsage(-1, -1, -1)
			return
		}
		releaseUsage(actualTokens, 0, overrideCostMicros)
	}
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
	domain.WriteRateLimitHeaders(w, acq.RateLimitMeta)
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

func (s *GatewayServer) checkDynamicUpstream429(ctx context.Context, id *domain.IdentityContext) error {
	if s != nil && s.limiter != nil && s.cfg != nil && s.cfg.RateLimit.DynamicOnUpstream429 && id != nil && id.VirtualKeyID != "" {
		if sec, throttled := s.limiter.CheckUpstream429Throttle(ctx, id.OrgID, id.VirtualKeyID); throttled {
			return &domain.GatewayError{
				StatusCode:    http.StatusTooManyRequests,
				Type:          domain.ErrorTypeRateLimit,
				Code:          "upstream_429_dynamic_throttle",
				Message:       "Key temporarily throttled after upstream 429 rate-limit signals",
				RetryAfterSec: sec,
				RateLimitMeta: &domain.RateLimitHeaderMetadata{
					Scope:     "key",
					LimitType: "upstream_429",
					ResetAt:   time.Now().UTC().Add(time.Duration(sec) * time.Second).Format(time.RFC3339),
				},
			}
		}
	}
	return nil
}

func (s *GatewayServer) acquireQuotaWithoutThrottle(ctx context.Context, id *domain.IdentityContext, model string, rateTokens, budgetInputTokens, requestedOutput int, requestID string) (func(actualInput, actualOutput int, overrideCostMicros int64), *domain.RateLimitHeaderMetadata, error) {
	return s.acquireQuotaUsingEstimator(ctx, id, model, rateTokens, requestedOutput, requestID, s.textBudgetEstimator(model, budgetInputTokens, requestedOutput))
}

type requestBudgetEstimator func(ctx context.Context, orgID string) (int64, error)

func (s *GatewayServer) textBudgetEstimator(model string, budgetInputTokens, requestedOutput int) requestBudgetEstimator {
	return func(ctx context.Context, orgID string) (int64, error) {
		return s.tokenBudgetUpperBound(ctx, orgID, model, budgetInputTokens, requestedOutput)
	}
}

func (s *GatewayServer) acquireQuotaUsingEstimator(ctx context.Context, id *domain.IdentityContext, model string, rateTokens, requestedOutput int, requestID string, estimate requestBudgetEstimator) (func(int, int, int64), *domain.RateLimitHeaderMetadata, error) {
	if s == nil {
		return func(int, int, int64) {}, nil, nil
	}
	if err := s.checkDynamicUpstream429(ctx, id); err != nil {
		return nil, nil, err
	}
	now := s.nowUTC()
	effID := applyEffectiveTempBudgets(id, now)
	extDescriptors, descErr := s.buildExtendedQuotaDescriptors(ctx, effID, model, now)
	if descErr != nil {
		return nil, nil, descriptorLookupError(descErr)
	}

	legacyHasBudget := hasLegacyBudget(effID)
	extHasBudget := descriptorsHaveBudget(extDescriptors)
	needsBudget := legacyHasBudget || extHasBudget

	var reserve int64
	if needsBudget {
		if s.budgetStats != nil {
			s.budgetStats.budgetedChecks.Add(1)
		}
		orgID := ""
		if effID != nil {
			orgID = effID.OrgID
		}
		var err error
		reserve, err = estimate(ctx, orgID)
		if err != nil {
			return nil, nil, requestBudgetEstimateError(err)
		}
	}
	if s.limiter == nil {
		return func(int, int, int64) {}, nil, nil
	}

	var legacyRawRel func(actualTokens int, overrideCostMicros int64)
	var legacyRollback func()
	var meta *domain.RateLimitHeaderMetadata
	if legacyHasBudget {
		rel, rb, m, err := s.limiter.AcquireWithBudgetAndRollbackWithMeta(ctx, effID, rateTokens, reserve, requestID)
		if err != nil {
			return nil, nil, err
		}
		legacyRawRel = rel
		legacyRollback = rb
		meta = m
	} else {
		rel, rb, m, err := s.limiter.AcquireWithRollbackWithMeta(ctx, effID, rateTokens)
		if err != nil {
			return nil, nil, err
		}
		legacyRollback = rb
		meta = m
		legacyRawRel = func(actualTokens int, _ int64) {
			rel(actualTokens)
		}
	}

	var descRel func(actualInput, actualOutput int, actualCostMicros int64)
	if len(extDescriptors) > 0 {
		estInput := rateTokens
		if estInput < 0 {
			estInput = 0
		}
		estOutput := requestedOutput
		if estOutput < 0 {
			estOutput = 0
		}
		orgID := ""
		if effID != nil {
			orgID = effID.OrgID
		}
		var descMeta *domain.RateLimitHeaderMetadata
		var err error
		descRel, descMeta, err = s.reserveExtendedQuotaWithMeta(ctx, orgID, requestID, estInput, estOutput, reserve, extDescriptors)
		if err != nil {
			if legacyRollback != nil {
				legacyRollback()
			}
			return nil, nil, err
		}
		meta = ratelimit.MergeRateLimitMetadata(meta, descMeta)
	}

	stopRenewer := s.startReservationLeaseRenewerWithDescriptors(ctx, effID, extDescriptors, requestID)
	var legacyRel func(actualTokens int, overrideCostMicros int64)
	if legacyHasBudget {
		legacyRel = s.wrapBudgetReleaseWithRenewer(effID, requestID, stopRenewer, legacyRawRel)
	} else {
		var legacyOnce sync.Once
		legacyRel = func(actualTokens int, _ int64) {
			legacyOnce.Do(func() {
				stopRenewer()
				legacyRawRel(actualTokens, 0)
			})
		}
	}

	var once sync.Once
	return func(actualInput, actualOutput int, overrideCostMicros int64) {
		once.Do(func() {
			stopRenewer()
			if actualInput < 0 {
				if legacyRel != nil {
					legacyRel(-1, -1)
				}
				if descRel != nil {
					descRel(-1, -1, -1)
				}
				return
			}
			if actualOutput < 0 {
				actualOutput = 0
			}
			totalTokens := actualInput + actualOutput
			if legacyRel != nil {
				legacyCost := overrideCostMicros
				if s.spendWorker != nil && overrideCostMicros >= 0 {
					legacyCost = -2
				}
				legacyRel(totalTokens, legacyCost)
			}
			if descRel != nil {
				descCost := overrideCostMicros
				if descCost < 0 {
					descCost = 0
				}
				descRel(actualInput, actualOutput, descCost)
			}
			if s.spendWorker == nil && overrideCostMicros > 0 {
				s.incrementBudgetWindowSpendBestEffort(ctx, effID, overrideCostMicros)
			}
		})
	}, meta, nil
}

func (s *GatewayServer) acquireQuotaWithThrottle(ctx context.Context, id *domain.IdentityContext, model string, rateTokens, budgetInputTokens, requestedOutput int, requestID string) (func(actualInput, actualOutput int, overrideCostMicros int64), *domain.RateLimitHeaderMetadata, bool, error) {
	return s.acquireQuotaWithThrottleUsingEstimator(ctx, id, model, rateTokens, requestedOutput, requestID, s.textBudgetEstimator(model, budgetInputTokens, requestedOutput))
}

func (s *GatewayServer) acquireQuotaWithThrottleUsingEstimator(ctx context.Context, id *domain.IdentityContext, model string, rateTokens, requestedOutput int, requestID string, estimate requestBudgetEstimator) (func(int, int, int64), *domain.RateLimitHeaderMetadata, bool, error) {
	pct := s.budgetExceededThrottlePct()
	currID := applyEffectiveTempBudgets(id, s.nowUTC())
	throttled := false

	for attempt := 0; attempt < 5; attempt++ {
		effID, applied := finops.ApplyBudgetThrottle(currID, pct)
		if applied {
			throttled = true
		}
		release, meta, err := s.acquireQuotaUsingEstimator(ctx, effID, model, rateTokens, requestedOutput, requestID, estimate)
		if err == nil {
			return release, meta, throttled, nil
		}
		nextID, canThrottle := markScopeBudgetExhausted(currID, err)
		if !canThrottle {
			return nil, nil, throttled, err
		}
		currID = nextID
	}
	return nil, nil, throttled, &domain.GatewayError{
		StatusCode: http.StatusTooManyRequests,
		Type:       domain.ErrorTypeBudgetExceeded,
		Code:       "budget_exceeded",
		Message:    "Configured budget exceeded across multiple scopes",
	}
}

func descriptorLookupError(err error) error {
	var gwErr *domain.GatewayError
	if errors.As(err, &gwErr) {
		return gwErr
	}
	return &domain.GatewayError{
		StatusCode:    http.StatusServiceUnavailable,
		Type:          domain.ErrorTypeRateLimit,
		Code:          "quota_policy_unavailable",
		Message:       "Unable to evaluate configured quota policies",
		RetryAfterSec: 5,
	}
}

func modalityResponseStatus(err error) int {
	if err == nil {
		return http.StatusOK
	}
	var gwErr *domain.GatewayError
	if errors.As(err, &gwErr) {
		return gwErr.StatusCode
	}
	return http.StatusInternalServerError
}

func requestBudgetEstimateError(err error) error {
	if errors.Is(err, errBudgetPricingUnverified) {
		return &domain.GatewayError{StatusCode: http.StatusForbidden, Type: domain.ErrorTypeBudgetExceeded, Code: "pricing_unknown_budget_restricted", Message: "Budgeted requests require known model pricing"}
	}
	return &domain.GatewayError{StatusCode: http.StatusServiceUnavailable, Type: domain.ErrorTypeBudgetExceeded, Code: "budget_estimate_unavailable", Message: "A safe upper-bound cost could not be calculated before dispatch"}
}

// reserveExtendedQuota shares an event ID between rolling spend settlement and the durable outbox.
func (s *GatewayServer) reserveExtendedQuota(ctx context.Context, orgID, requestID string, input, output int, reserve int64, descriptors []domain.RateLimitDescriptor) (func(int, int, int64), error) {
	rel, _, err := s.reserveExtendedQuotaWithMeta(ctx, orgID, requestID, input, output, reserve, descriptors)
	return rel, err
}

// reserveExtendedQuotaWithMeta shares an event ID between rolling spend settlement and the durable outbox
// while returning tightest-scope rate-limit header metadata.
func (s *GatewayServer) reserveExtendedQuotaWithMeta(ctx context.Context, orgID, requestID string, input, output int, reserve int64, descriptors []domain.RateLimitDescriptor) (func(int, int, int64), *domain.RateLimitHeaderMetadata, error) {
	state := requestQuotaStateFromContext(ctx)
	var settlementID string
	if state != nil {
		for _, d := range descriptors {
			if d.WindowType == domain.BudgetWindowRolling24h && d.MaxBudgetMicros > 0 {
				settlementID = uuid.NewString()
				break
			}
		}
	}
	release, meta, err := s.limiter.AcquireDescriptorsWithSettlementIDAndMeta(ctx, orgID, requestID, settlementID, input, output, reserve, descriptors)
	if err == nil && settlementID != "" {
		state.SettlementID = settlementID
		state.SettlementRequestID = requestID
	}
	if err != nil || settlementID == "" {
		return release, meta, err
	}
	return func(input, output int, cost int64) {
		if cost >= 0 {
			state.SettlementAt = s.nowUTC()
		}
		release(input, output, cost)
	}, meta, nil
}

func (s *GatewayServer) acquireModalityQuotaWithThrottle(ctx context.Context, id *domain.IdentityContext, model string, rateTokens int, requestID string, estimator func(*domain.GlobalModel) (int64, bool)) (func(int, int64), *domain.RateLimitHeaderMetadata, bool, error) {
	estimate := func(ctx context.Context, orgID string) (int64, error) {
		if estimator == nil {
			return 0, errors.New("no safe upper-bound estimator for this modality")
		}
		gm, sawUnverified, err := s.resolveMatchedVerifiedModel(ctx, orgID, model)
		if err != nil || gm == nil {
			if sawUnverified {
				return 0, errBudgetPricingUnverified
			}
			return 0, errors.New("verified model pricing unavailable")
		}
		reserve, ok := estimator(gm)
		if !ok {
			return 0, errors.New("modality cost estimate unavailable")
		}
		// A free, verified modality still needs a positive reservation to exercise
		// the budget admission path. Reconciliation records the actual zero cost.
		return max(1, reserve), nil
	}
	release, meta, throttled, err := s.acquireQuotaWithThrottleUsingEstimator(ctx, id, model, rateTokens, 0, requestID, estimate)
	if err != nil {
		return nil, meta, throttled, err
	}
	return func(tokens int, cost int64) { release(tokens, 0, cost) }, meta, throttled, nil
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
			release, meta, err := s.acquireQuotaWithoutThrottle(ctx, id, requestedModel, rateTokens, budgetInputTokens, requestedOutput, requestID)
			if err == nil {
				return budgetPolicyAcquisition{
					EffectiveModel: requestedModel,
					ReleaseQuota:   legacyReleaseFromUsage(release),
					ReleaseUsage:   release,
					RateLimitMeta:  meta,
				}, nil
			}
			if !isBudgetRejectionError(err) {
				return budgetPolicyAcquisition{}, err
			}
		}

		var winningRelease func(int, int, int64)
		var winningMeta *domain.RateLimitHeaderMetadata
		if fbModel, ok := finops.ResolveBudgetFallbackModel(ctx, id, requestedModel, func(checkCtx context.Context, candidate string) error {
			if s.rbac != nil {
				if err := s.rbac.AuthorizeRequestedModel(id, candidate); err != nil {
					return err
				}
			}
			if err := s.checkModelDeploymentBudget(checkCtx, orgID, candidate); err != nil {
				return err
			}
			rel, m, err := s.acquireQuotaWithoutThrottle(checkCtx, id, candidate, rateTokens, budgetInputTokens, requestedOutput, requestID)
			if err != nil {
				return err
			}
			winningRelease = rel
			winningMeta = m
			return nil
		}); ok {
			return budgetPolicyAcquisition{
				EffectiveModel:  fbModel,
				ReleaseQuota:    legacyReleaseFromUsage(winningRelease),
				ReleaseUsage:    winningRelease,
				RateLimitMeta:   winningMeta,
				FallbackApplied: true,
			}, nil
		}
	}

	release, meta, throttled, err := s.acquireQuotaWithThrottle(ctx, id, requestedModel, rateTokens, budgetInputTokens, requestedOutput, requestID)
	if err != nil {
		return budgetPolicyAcquisition{}, err
	}
	return budgetPolicyAcquisition{
		EffectiveModel: requestedModel,
		ReleaseQuota:   legacyReleaseFromUsage(release),
		ReleaseUsage:   release,
		RateLimitMeta:  meta,
		Throttled:      throttled,
	}, nil
}
