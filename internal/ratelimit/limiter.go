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

// Limiter enforces RPM, TPM, Concurrency, and Budget limits across Virtual Key, Team, and Organization scopes.
// Uses atomic Redis Lua scripts; configured quotas fail closed when Redis is unavailable.
type Limiter struct {
	redis        *storage.RedisFabric
	checkScript  *redis.Script
	reconcileScr *redis.Script
	spendScr     *redis.Script
	windowSec    int
	concTTLSec   int
}

func NewLimiter(redisFabric *storage.RedisFabric, windowSec, concTTLSec int) *Limiter {
	if windowSec <= 0 {
		windowSec = 60
	}
	if concTTLSec <= 0 {
		concTTLSec = 300
	}
	return &Limiter{
		redis:        redisFabric,
		checkScript:  redis.NewScript(checkAndIncrementLua),
		reconcileScr: redis.NewScript(reconcileLua),
		spendScr:     redis.NewScript(recordSpendLua),
		windowSec:    windowSec,
		concTTLSec:   concTTLSec,
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
		keys := []string{
			fmt.Sprintf("gw:rl:rpm:key:%s:%d", idCtx.VirtualKeyID, nowMin),
			fmt.Sprintf("gw:rl:tpm:key:%s:%d", idCtx.VirtualKeyID, nowMin),
			fmt.Sprintf("gw:rl:conc:%s", idCtx.VirtualKeyID),
			fmt.Sprintf("gw:spend:key:%s", idCtx.VirtualKeyID),
			fmt.Sprintf("gw:rl:rpm:team:%s:%d", idCtx.TeamID, nowMin),
			fmt.Sprintf("gw:rl:tpm:team:%s:%d", idCtx.TeamID, nowMin),
			fmt.Sprintf("gw:spend:team:%s", idCtx.TeamID),
			fmt.Sprintf("gw:rl:rpm:org:%s:%d", idCtx.OrgID, nowMin),
			fmt.Sprintf("gw:rl:tpm:org:%s:%d", idCtx.OrgID, nowMin),
			fmt.Sprintf("gw:spend:org:%s", idCtx.OrgID),
			fmt.Sprintf("gw:budget:reservations:key:%s", idCtx.VirtualKeyID),
			fmt.Sprintf("gw:budget:reservations:team:%s", idCtx.TeamID),
			fmt.Sprintf("gw:budget:reservations:org:%s", idCtx.OrgID),
		}
		argv := []any{
			idCtx.KeyRPMLimit, idCtx.KeyTPMLimit, idCtx.KeyMaxConcurrent, idCtx.KeyMaxBudgetMicros,
			idCtx.TeamRPMLimit, idCtx.TeamTPMLimit, idCtx.TeamMaxBudgetMicros,
			idCtx.OrgRPMLimit, idCtx.OrgTPMLimit, idCtx.OrgMaxBudgetMicros,
			estimatedTokens, l.windowSec * 2, l.concTTLSec, reserveMicros, requestID, 3600,
		}

		res, err := l.redis.Execute(func(rdb *redis.Client) (any, error) {
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
					recKeys := []string{
						keys[2], // key_conc
						keys[1], // key_tpm
						keys[5], // team_tpm
						keys[8], // org_tpm
					}
					resKeys := append(recKeys, keys[10], keys[11], keys[12], keys[3], keys[6], keys[9])
					settle := []any{delta, l.windowSec * 2, requestID, actualCostMicros, reserveMicros}
					if actualTokens < 0 {
						settle[3] = int64(-1)
					} else {
						// Successful requests settle the reservation with their SpendEvent,
						// which atomically swaps reserved cost for actual spend.
						settle[3] = int64(-2)
					}
					_, _ = l.redis.Execute(func(rdb *redis.Client) (any, error) {
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
	l.RecordSpendIncrementForRequest(ctx, "", keyID, teamID, orgID, costMicros)
}

// RecordSpendIncrementForRequest atomically replaces a matching request's
// outstanding reservations with its actual cost and updates all spend scopes.
func (l *Limiter) RecordSpendIncrementForRequest(ctx context.Context, requestID, keyID, teamID, orgID string, costMicros int64) {
	if costMicros <= 0 {
		if requestID == "" {
			return
		}
	}

	if l.redis != nil && l.redis.Client() != nil {
		_, _ = l.redis.Execute(func(rdb *redis.Client) (any, error) {
			keys := []string{
				"gw:spend:key:" + keyID, "gw:spend:team:" + teamID, "gw:spend:org:" + orgID,
				"gw:budget:reservations:key:" + keyID, "gw:budget:reservations:team:" + teamID, "gw:budget:reservations:org:" + orgID,
			}
			return l.spendScr.Run(ctx, rdb, keys, requestID, costMicros).Result()
		})
	}
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
