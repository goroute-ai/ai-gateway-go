package ratelimit

import (
	"context"
	_ "embed"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/redis/go-redis/v9"
)

//go:embed scripts/check_and_increment.lua
var checkAndIncrementLua string

//go:embed scripts/reconcile.lua
var reconcileLua string

//go:embed scripts/record_spend.lua
var recordSpendLua string

//go:embed scripts/reset_budget_spend.lua
var resetBudgetSpendLua string

//go:embed scripts/renew_reservation.lua
var renewReservationLua string

// Limiter enforces RPM, TPM, Concurrency, and Budget limits across Virtual Key, Team, and Organization scopes.
// Uses atomic Redis Lua scripts; configured quotas fail closed when Redis is unavailable.
type Limiter struct {
	redis          *storage.RedisFabric
	checkScript    *redis.Script
	reconcileScr   *redis.Script
	spendScr       *redis.Script
	resetBudgetScr *redis.Script
	renewScr       *redis.Script
	windowSec      int
	concTTLSec     int
}

func NewLimiter(redisFabric *storage.RedisFabric, windowSec, concTTLSec int) *Limiter {
	if windowSec <= 0 {
		windowSec = 60
	}
	if concTTLSec <= 0 {
		concTTLSec = 300
	}
	return &Limiter{
		redis:          redisFabric,
		checkScript:    redis.NewScript(checkAndIncrementLua),
		reconcileScr:   redis.NewScript(reconcileLua),
		spendScr:       redis.NewScript(recordSpendLua),
		resetBudgetScr: redis.NewScript(resetBudgetSpendLua),
		renewScr:       redis.NewScript(renewReservationLua),
		windowSec:      windowSec,
		concTTLSec:     concTTLSec,
	}
}

// Acquire checks rate limits and, for backward compatibility, only admits requests
// without an enforced budget. Budgeted requests must use AcquireWithBudget so the
// maximum spend is reserved atomically before dispatch.
// Returns a release function that MUST be called after the request finishes to decrement concurrency and reconcile token deltas.
func (l *Limiter) Acquire(ctx context.Context, idCtx *domain.IdentityContext, estimatedTokens int) (func(actualTokens int), error) {
	release, err := l.acquire(ctx, idCtx, estimatedTokens, 0, "")
	if err != nil {
		return nil, err
	}
	return func(actualTokens int) { release(actualTokens, 0) }, nil
}

// AcquireWithBudget atomically reserves a conservative upper-bound cost in
// micro-dollars alongside rate-limit admission. Call release with actual usage
// and cost after dispatch; a negative token count releases the reservation
// without charging spend.
func (l *Limiter) AcquireWithBudget(ctx context.Context, idCtx *domain.IdentityContext, estimatedTokens int, reserveMicros int64, requestID string) (func(actualTokens int, actualCostMicros int64), error) {
	if reserveMicros < 0 || requestID == "" {
		return nil, fmt.Errorf("budget reservation requires a non-negative amount and request ID")
	}
	return l.acquire(ctx, idCtx, estimatedTokens, reserveMicros, requestID)
}

func orgHashTag(orgID string) string {
	if orgID == "" {
		orgID = "default"
	}
	return "{org:" + orgID + "}"
}

func acquireKeys(idCtx *domain.IdentityContext, nowMin int64) []string {
	tag := orgHashTag(idCtx.OrgID)
	return []string{
		fmt.Sprintf("gw:rl:%s:rpm:key:%s:%d", tag, idCtx.VirtualKeyID, nowMin),
		fmt.Sprintf("gw:rl:%s:tpm:key:%s:%d", tag, idCtx.VirtualKeyID, nowMin),
		fmt.Sprintf("gw:rl:%s:conc:%s", tag, idCtx.VirtualKeyID),
		fmt.Sprintf("gw:spend:%s:key:%s", tag, idCtx.VirtualKeyID),
		fmt.Sprintf("gw:rl:%s:rpm:team:%s:%d", tag, idCtx.TeamID, nowMin),
		fmt.Sprintf("gw:rl:%s:tpm:team:%s:%d", tag, idCtx.TeamID, nowMin),
		fmt.Sprintf("gw:spend:%s:team:%s", tag, idCtx.TeamID),
		fmt.Sprintf("gw:rl:%s:rpm:org:%s:%d", tag, idCtx.OrgID, nowMin),
		fmt.Sprintf("gw:rl:%s:tpm:org:%s:%d", tag, idCtx.OrgID, nowMin),
		fmt.Sprintf("gw:spend:%s:org:%s", tag, idCtx.OrgID),
		fmt.Sprintf("gw:budget:%s:reservations:key:%s", tag, idCtx.VirtualKeyID),
		fmt.Sprintf("gw:budget:%s:reservations:team:%s", tag, idCtx.TeamID),
		fmt.Sprintf("gw:budget:%s:reservations:org:%s", tag, idCtx.OrgID),
	}
}

func reconcileKeys(keys []string) []string {
	return []string{
		keys[2],  // key_conc
		keys[1],  // key_tpm
		keys[5],  // team_tpm
		keys[8],  // org_tpm
		keys[10], // key_reservations
		keys[11], // team_reservations
		keys[12], // org_reservations
		keys[3],  // key_spend
		keys[6],  // team_spend
		keys[9],  // org_spend
	}
}

func spendKeys(keyID, teamID, orgID string) []string {
	tag := orgHashTag(orgID)
	return []string{
		fmt.Sprintf("gw:spend:%s:key:%s", tag, keyID),
		fmt.Sprintf("gw:spend:%s:team:%s", tag, teamID),
		fmt.Sprintf("gw:spend:%s:org:%s", tag, orgID),
		fmt.Sprintf("gw:budget:%s:reservations:key:%s", tag, keyID),
		fmt.Sprintf("gw:budget:%s:reservations:team:%s", tag, teamID),
		fmt.Sprintf("gw:budget:%s:reservations:org:%s", tag, orgID),
	}
}

func (l *Limiter) acquire(ctx context.Context, idCtx *domain.IdentityContext, estimatedTokens int, reserveMicros int64, requestID string) (func(int, int64), error) {
	if idCtx == nil {
		return func(int, int64) {}, nil
	}
	if estimatedTokens < 1 {
		estimatedTokens = 1
	}

	nowMin := time.Now().Unix() / 60

	// Try Redis Atomic Lua script first if Redis is configured
	if l.redis != nil && l.redis.Client() != nil {
		keys := acquireKeys(idCtx, nowMin)
		argv := []any{
			idCtx.KeyRPMLimit, idCtx.KeyTPMLimit, idCtx.KeyMaxConcurrent, idCtx.KeyMaxBudgetMicros,
			idCtx.TeamRPMLimit, idCtx.TeamTPMLimit, idCtx.TeamMaxBudgetMicros,
			idCtx.OrgRPMLimit, idCtx.OrgTPMLimit, idCtx.OrgMaxBudgetMicros,
			estimatedTokens, l.windowSec * 2, l.concTTLSec, reserveMicros, requestID, 3600,
		}

		res, err := l.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
			return l.checkScript.Run(ctx, rdb, keys, argv...).Slice()
		})
		if err == nil {
			if slice, ok := res.([]any); ok && len(slice) >= 2 {
				allowed, _ := slice[0].(int64)
				reason, _ := slice[1].(string)
				if allowed == 0 {
					return nil, toQuotaError(reason)
				}
				return func(actualTokens int, actualCostMicros int64) {
					delta := actualTokens - estimatedTokens
					resKeys := reconcileKeys(keys)
					settle := []any{delta, l.windowSec * 2, requestID, actualCostMicros, reserveMicros}
					if actualTokens < 0 {
						settle[3] = int64(-1)
					} else {
						// Successful requests settle the reservation with their SpendEvent,
						// which atomically swaps reserved cost for actual spend.
						settle[3] = int64(-2)
					}
					_, _ = l.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
						return l.reconcileScr.Run(context.Background(), rdb, resKeys, settle...).Result()
					})
				}, nil
			}
		}
	}

	if hasConfiguredLimits(idCtx) {
		return nil, limiterUnavailableError()
	}
	return func(int, int64) {}, nil
}

func hasConfiguredLimits(idCtx *domain.IdentityContext) bool {
	return idCtx != nil && (idCtx.KeyRPMLimit > 0 || idCtx.KeyTPMLimit > 0 || idCtx.KeyMaxConcurrent > 0 || idCtx.KeyMaxBudgetMicros > 0 ||
		idCtx.TeamRPMLimit > 0 || idCtx.TeamTPMLimit > 0 || idCtx.TeamMaxBudgetMicros > 0 ||
		idCtx.OrgRPMLimit > 0 || idCtx.OrgTPMLimit > 0 || idCtx.OrgMaxBudgetMicros > 0)
}

func limiterUnavailableError() *domain.GatewayError {
	return &domain.GatewayError{StatusCode: http.StatusServiceUnavailable, Type: domain.ErrorTypeRateLimit, Code: "rate_limiter_unavailable", Message: "Distributed rate limiter is unavailable; request rejected to preserve configured quotas", RetryAfterSec: 5}
}

func hasBudget(idCtx *domain.IdentityContext) bool {
	return idCtx != nil && (idCtx.KeyMaxBudgetMicros > 0 || idCtx.TeamMaxBudgetMicros > 0 || idCtx.OrgMaxBudgetMicros > 0)
}

func budgetUnavailableError() *domain.GatewayError {
	return &domain.GatewayError{StatusCode: http.StatusServiceUnavailable, Type: domain.ErrorTypeBudgetExceeded, Code: "budget_reservation_unavailable", Message: "A safe distributed budget reservation could not be made before dispatch", RetryAfterSec: 5}
}

// RecordSpendIncrement updates real-time spend counters in Redis so subsequent admissions observe completed spend.
func (l *Limiter) RecordSpendIncrement(ctx context.Context, keyID, teamID, orgID string, costMicros int64) {
	_ = l.RecordSpendIncrementForEvent(ctx, "", "", keyID, teamID, orgID, costMicros)
}

// RecordSpendIncrementForRequest atomically replaces a matching request's
// outstanding reservations with its actual cost and updates all spend scopes.
func (l *Limiter) RecordSpendIncrementForRequest(ctx context.Context, requestID, keyID, teamID, orgID string, costMicros int64) error {
	return l.RecordSpendIncrementForEvent(ctx, "", requestID, keyID, teamID, orgID, costMicros)
}

// RecordSpendIncrementForEvent idempotently applies spend for eventID (falling back to requestID)
// and atomically removes any matching request reservations across all scopes.
func (l *Limiter) RecordSpendIncrementForEvent(ctx context.Context, eventID, requestID, keyID, teamID, orgID string, costMicros int64) error {
	if costMicros <= 0 && requestID == "" {
		return nil
	}
	if l.redis == nil || l.redis.Client() == nil {
		return nil
	}
	effectiveEventID := eventID
	if effectiveEventID == "" {
		effectiveEventID = requestID
	}
	keys := spendKeys(keyID, teamID, orgID)
	if effectiveEventID != "" {
		tag := orgHashTag(orgID)
		keys = append(keys, fmt.Sprintf("gw:spend:applied:%s:%s", tag, effectiveEventID))
	}
	_, err := l.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
		return l.spendScr.Run(ctx, rdb, keys, requestID, costMicros, effectiveEventID).Result()
	})
	return err
}

// RenewReservationLease extends the expiration of active budget reservations
// matching requestID across key, team, and org reservation sorted sets.
func (l *Limiter) RenewReservationLease(ctx context.Context, idCtx *domain.IdentityContext, requestID string, ttlSec int) error {
	if idCtx == nil || requestID == "" {
		return nil
	}
	if ttlSec <= 0 {
		ttlSec = 3600
	}
	if l.redis == nil || l.redis.Client() == nil {
		if hasBudget(idCtx) {
			return limiterUnavailableError()
		}
		return nil
	}
	tag := orgHashTag(idCtx.OrgID)
	keys := []string{
		fmt.Sprintf("gw:budget:%s:reservations:key:%s", tag, idCtx.VirtualKeyID),
		fmt.Sprintf("gw:budget:%s:reservations:team:%s", tag, idCtx.TeamID),
		fmt.Sprintf("gw:budget:%s:reservations:org:%s", tag, idCtx.OrgID),
	}
	_, err := l.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
		return l.renewScr.Run(ctx, rdb, keys, requestID, ttlSec).Result()
	})
	return err
}

// ResetSpendCounters deletes live Redis spend counters for the given entity IDs
// after their budget reset period rolls over.
func (l *Limiter) ResetSpendCounters(ctx context.Context, events []storage.BudgetResetEvent) error {
	if l == nil || l.redis == nil || l.redis.Client() == nil {
		return nil
	}
	if len(events) == 0 {
		return nil
	}
	_, err := l.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
		for _, event := range events {
			if event.ID == "" || event.EntityID == "" || event.OrgID == "" {
				return nil, fmt.Errorf("invalid budget reset event")
			}
			scope := event.Scope
			if scope != "org" && scope != "team" && scope != "key" {
				return nil, fmt.Errorf("invalid budget reset scope %q", scope)
			}
			tag := orgHashTag(event.OrgID)
			spendKey := fmt.Sprintf("gw:spend:%s:%s:%s", tag, scope, event.EntityID)
			markerKey := fmt.Sprintf("gw:spend-reset:%s:%s:%s:%s", tag, scope, event.EntityID, event.ID)
			if _, err := l.resetBudgetScr.Run(ctx, rdb, []string{spendKey, markerKey}, event.ID, 7776000).Result(); err != nil {
				return nil, err
			}
		}
		return nil, nil
	})
	return err
}

func toQuotaError(code string) *domain.GatewayError {
	if code == "BUDGET_ESTIMATE_REQUIRED" {
		return budgetUnavailableError()
	}
	if strings.Contains(code, "BUDGET") {
		return &domain.GatewayError{
			StatusCode:    http.StatusTooManyRequests,
			Type:          domain.ErrorTypeBudgetExceeded,
			Code:          strings.ToLower(code),
			Message:       fmt.Sprintf("Configured financial spend budget exceeded (%s)", code),
			RetryAfterSec: 60,
		}
	}
	return &domain.GatewayError{
		StatusCode:    http.StatusTooManyRequests,
		Type:          domain.ErrorTypeRateLimit,
		Code:          strings.ToLower(code),
		Message:       fmt.Sprintf("Rate limit or quota exceeded (%s)", code),
		RetryAfterSec: 15,
	}
}
