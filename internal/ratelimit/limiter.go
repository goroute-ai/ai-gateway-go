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

// Limiter enforces RPM, TPM, Concurrency, and Budget limits across Virtual Key, Team, and Organization scopes.
// It requires Redis for any request with configured limits so every replica shares the same counters.
type Limiter struct {
	redis        *storage.RedisFabric
	checkScript  *redis.Script
	reconcileScr *redis.Script
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
		windowSec:    windowSec,
		concTTLSec:   concTTLSec,
	}
}

// Acquire checks budgets and rate limits and increments pre-flight counters.
// Returns a release function that MUST be called after the request finishes to decrement concurrency and reconcile token deltas.
func (l *Limiter) Acquire(ctx context.Context, idCtx *domain.IdentityContext, estimatedTokens int) (func(actualTokens int), error) {
	if idCtx == nil {
		return func(int) {}, nil
	}
	if !hasConfiguredLimits(idCtx) {
		return func(int) {}, nil
	}
	if l.redis == nil || l.redis.Client() == nil {
		return nil, limiterUnavailableError()
	}
	if estimatedTokens < 1 {
		estimatedTokens = 1
	}

	nowMin := time.Now().Unix() / 60
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
	}
	argv := []any{
		idCtx.KeyRPMLimit, idCtx.KeyTPMLimit, idCtx.KeyMaxConcurrent, idCtx.KeyMaxBudgetMicros,
		idCtx.TeamRPMLimit, idCtx.TeamTPMLimit, idCtx.TeamMaxBudgetMicros,
		idCtx.OrgRPMLimit, idCtx.OrgTPMLimit, idCtx.OrgMaxBudgetMicros,
		estimatedTokens, l.windowSec * 2, l.concTTLSec,
	}

	res, err := l.redis.Execute(func(rdb *redis.Client) (any, error) {
		return l.checkScript.Run(ctx, rdb, keys, argv...).Slice()
	})
	if err != nil {
		return nil, limiterUnavailableError()
	}
	slice, ok := res.([]any)
	if !ok || len(slice) < 2 {
		return nil, limiterUnavailableError()
	}
	allowed, ok := slice[0].(int64)
	if !ok {
		return nil, limiterUnavailableError()
	}
	if allowed == 0 {
		reason, _ := slice[1].(string)
		return nil, toQuotaError(reason)
	}
	if allowed != 1 {
		return nil, limiterUnavailableError()
	}

	return func(actualTokens int) {
		delta := actualTokens - estimatedTokens
		recKeys := []string{keys[2], keys[1], keys[5], keys[8]}
		_, _ = l.redis.Execute(func(rdb *redis.Client) (any, error) {
			return l.reconcileScr.Run(context.Background(), rdb, recKeys, delta, l.windowSec*2).Result()
		})
	}, nil
}

func hasConfiguredLimits(idCtx *domain.IdentityContext) bool {
	return idCtx.KeyRPMLimit > 0 || idCtx.KeyTPMLimit > 0 || idCtx.KeyMaxConcurrent > 0 || idCtx.KeyMaxBudgetMicros > 0 ||
		idCtx.TeamRPMLimit > 0 || idCtx.TeamTPMLimit > 0 || idCtx.TeamMaxBudgetMicros > 0 ||
		idCtx.OrgRPMLimit > 0 || idCtx.OrgTPMLimit > 0 || idCtx.OrgMaxBudgetMicros > 0
}

func limiterUnavailableError() *domain.GatewayError {
	return &domain.GatewayError{
		StatusCode:    http.StatusServiceUnavailable,
		Type:          domain.ErrorTypeRateLimit,
		Code:          "rate_limiter_unavailable",
		Message:       "Distributed rate limiter is unavailable; request rejected to preserve configured quotas",
		RetryAfterSec: 5,
	}
}

// RecordSpendIncrement updates real-time spend counters in Redis so subsequent admissions observe completed spend.
func (l *Limiter) RecordSpendIncrement(ctx context.Context, keyID, teamID, orgID string, costMicros int64) {
	if costMicros <= 0 {
		return
	}

	if l.redis != nil && l.redis.Client() != nil {
		_, _ = l.redis.Execute(func(rdb *redis.Client) (any, error) {
			pipe := rdb.Pipeline()
			if keyID != "" {
				pipe.IncrBy(ctx, "gw:spend:key:"+keyID, costMicros)
			}
			if teamID != "" {
				pipe.IncrBy(ctx, "gw:spend:team:"+teamID, costMicros)
			}
			if orgID != "" {
				pipe.IncrBy(ctx, "gw:spend:org:"+orgID, costMicros)
			}
			return pipe.Exec(ctx)
		})
	}
}

func toQuotaError(code string) *domain.GatewayError {
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
