package ratelimit

import (
	"context"
	_ "embed"
	"fmt"
	"net/http"
	"strings"
	"sync"
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

// FallbackMode governs how the rate limiter behaves when Redis is unreachable or unconfigured.
type FallbackMode string

const (
	// FallbackLocalDividedByReplicas divides configured RPM/TPM limits by ExpectedPodCount
	// (`max(1, limit / expectedPods)`) so total cluster traffic never overshoots tenant quotas during a Redis outage.
	FallbackLocalDividedByReplicas FallbackMode = "local_divided_by_replicas"
	// FallbackLocalPerPod enforces the full limit locally per pod (trades strict global cap for maximum availability).
	FallbackLocalPerPod FallbackMode = "local_per_pod"
	// FallbackFailClosed rejects requests with HTTP 503 when distributed Redis state is unreachable.
	FallbackFailClosed FallbackMode = "fail_closed"
)

type localWindow struct {
	epochMin   int64
	rpm        int
	tpm        int
	concurrent int
}

// Limiter enforces RPM, TPM, Concurrency, and Budget limits across Virtual Key, Team, and Organization scopes.
// Uses atomic Redis Lua scripts when Redis is available, and falls back according to FallbackMode when Redis is unavailable.
type Limiter struct {
	redis            *storage.RedisFabric
	checkScript      *redis.Script
	reconcileScr     *redis.Script
	spendScr         *redis.Script
	windowSec        int
	concTTLSec       int
	fallbackMode     FallbackMode
	expectedPodCount int
	mu               sync.Mutex
	localCounters    map[string]*localWindow
	localSpend       map[string]int64
}

func NewLimiter(redisFabric *storage.RedisFabric, windowSec, concTTLSec int) *Limiter {
	if windowSec <= 0 {
		windowSec = 60
	}
	if concTTLSec <= 0 {
		concTTLSec = 300
	}
	return &Limiter{
		redis:            redisFabric,
		checkScript:      redis.NewScript(checkAndIncrementLua),
		reconcileScr:     redis.NewScript(reconcileLua),
		spendScr:         redis.NewScript(recordSpendLua),
		windowSec:        windowSec,
		concTTLSec:       concTTLSec,
		fallbackMode:     FallbackLocalDividedByReplicas,
		expectedPodCount: 1,
		localCounters:    make(map[string]*localWindow),
		localSpend:       make(map[string]int64),
	}
}

// SetFallbackPolicy configures the distributed rate-limit fallback strategy and expected replica count.
func (l *Limiter) SetFallbackPolicy(mode FallbackMode, expectedPods int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if mode != "" {
		l.fallbackMode = mode
	}
	if expectedPods < 1 {
		expectedPods = 1
	}
	l.expectedPodCount = expectedPods
}

// FallbackPolicy returns the active fallback mode and expected pod count.
func (l *Limiter) FallbackPolicy() (FallbackMode, int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.fallbackMode, l.expectedPodCount
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

	// Fallback: In-Process Atomic Check & Increment governed by FallbackMode
	if hasBudget(idCtx) {
		return nil, budgetUnavailableError()
	}
	release, err := l.acquireLocal(idCtx, estimatedTokens, nowMin)
	if err != nil {
		return nil, err
	}
	return func(tokens int, _ int64) { release(tokens) }, nil
}

func hasBudget(idCtx *domain.IdentityContext) bool {
	return idCtx != nil && (idCtx.KeyMaxBudgetMicros > 0 || idCtx.TeamMaxBudgetMicros > 0 || idCtx.OrgMaxBudgetMicros > 0)
}

func budgetUnavailableError() *domain.GatewayError {
	return &domain.GatewayError{StatusCode: http.StatusServiceUnavailable, Type: domain.ErrorTypeBudgetExceeded, Code: "budget_reservation_unavailable", Message: "A safe distributed budget reservation could not be made before dispatch", RetryAfterSec: 5}
}

func (l *Limiter) scaleLimit(limit int) int {
	if limit <= 0 {
		return 0
	}
	if l.fallbackMode == FallbackLocalDividedByReplicas && l.expectedPodCount > 1 {
		scaled := limit / l.expectedPodCount
		if scaled < 1 {
			return 1
		}
		return scaled
	}
	return limit
}

func (l *Limiter) acquireLocal(idCtx *domain.IdentityContext, estimatedTokens int, nowMin int64) (func(actualTokens int), error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.fallbackMode == FallbackFailClosed {
		return nil, &domain.GatewayError{
			StatusCode:    http.StatusServiceUnavailable,
			Type:          domain.ErrorTypeRateLimit,
			Code:          "rate_limiter_unavailable",
			Message:       "Distributed rate limiter (Redis) is unreachable and fallback mode is fail_closed",
			RetryAfterSec: 5,
		}
	}

	// 1. Check Budgets (combining persisted spend + real-time local spend delta)
	keySpend := idCtx.KeySpentMicros + l.localSpend["key:"+idCtx.VirtualKeyID]
	if idCtx.KeyMaxBudgetMicros > 0 && keySpend >= idCtx.KeyMaxBudgetMicros {
		return nil, toQuotaError("KEY_BUDGET_EXCEEDED")
	}
	if idCtx.TeamID != "" {
		teamSpend := idCtx.TeamSpentMicros + l.localSpend["team:"+idCtx.TeamID]
		if idCtx.TeamMaxBudgetMicros > 0 && teamSpend >= idCtx.TeamMaxBudgetMicros {
			return nil, toQuotaError("TEAM_BUDGET_EXCEEDED")
		}
	}
	orgSpend := idCtx.OrgSpentMicros + l.localSpend["org:"+idCtx.OrgID]
	if idCtx.OrgMaxBudgetMicros > 0 && orgSpend >= idCtx.OrgMaxBudgetMicros {
		return nil, toQuotaError("ORG_BUDGET_EXCEEDED")
	}

	getWin := func(scopeKey string) *localWindow {
		w, ok := l.localCounters[scopeKey]
		if !ok || w.epochMin != nowMin {
			prevConc := 0
			if ok {
				prevConc = w.concurrent
			}
			w = &localWindow{epochMin: nowMin, concurrent: prevConc}
			l.localCounters[scopeKey] = w
		}
		return w
	}

	keyRPM := l.scaleLimit(idCtx.KeyRPMLimit)
	keyTPM := l.scaleLimit(idCtx.KeyTPMLimit)
	keyConc := l.scaleLimit(idCtx.KeyMaxConcurrent)

	kw := getWin("key:" + idCtx.VirtualKeyID)
	if keyRPM > 0 && kw.rpm+1 > keyRPM {
		return nil, toQuotaError("KEY_RPM_EXCEEDED")
	}
	if keyTPM > 0 && kw.tpm+estimatedTokens > keyTPM {
		return nil, toQuotaError("KEY_TPM_EXCEEDED")
	}
	if keyConc > 0 && kw.concurrent+1 > keyConc {
		return nil, toQuotaError("KEY_CONCURRENCY_EXCEEDED")
	}

	var tw *localWindow
	if idCtx.TeamID != "" {
		teamRPM := l.scaleLimit(idCtx.TeamRPMLimit)
		teamTPM := l.scaleLimit(idCtx.TeamTPMLimit)
		tw = getWin("team:" + idCtx.TeamID)
		if teamRPM > 0 && tw.rpm+1 > teamRPM {
			return nil, toQuotaError("TEAM_RPM_EXCEEDED")
		}
		if teamTPM > 0 && tw.tpm+estimatedTokens > teamTPM {
			return nil, toQuotaError("TEAM_TPM_EXCEEDED")
		}
	}

	orgRPM := l.scaleLimit(idCtx.OrgRPMLimit)
	orgTPM := l.scaleLimit(idCtx.OrgTPMLimit)
	ow := getWin("org:" + idCtx.OrgID)
	if orgRPM > 0 && ow.rpm+1 > orgRPM {
		return nil, toQuotaError("ORG_RPM_EXCEEDED")
	}
	if orgTPM > 0 && ow.tpm+estimatedTokens > orgTPM {
		return nil, toQuotaError("ORG_TPM_EXCEEDED")
	}

	// Mutate counters
	kw.rpm++
	kw.tpm += estimatedTokens
	kw.concurrent++
	if tw != nil {
		tw.rpm++
		tw.tpm += estimatedTokens
	}
	ow.rpm++
	ow.tpm += estimatedTokens

	return func(actualTokens int) {
		l.mu.Lock()
		defer l.mu.Unlock()
		if kw.concurrent > 0 {
			kw.concurrent--
		}
		if actualTokens > 0 {
			delta := actualTokens - estimatedTokens
			kw.tpm += delta
			if tw != nil {
				tw.tpm += delta
			}
			ow.tpm += delta
		}
	}, nil
}

// RecordSpendIncrement updates real-time spend counters in Redis and local memory so concurrent calls immediately enforce budgets.
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
	l.mu.Lock()
	if keyID != "" {
		l.localSpend["key:"+keyID] += costMicros
	}
	if teamID != "" {
		l.localSpend["team:"+teamID] += costMicros
	}
	if orgID != "" {
		l.localSpend["org:"+orgID] += costMicros
	}
	l.mu.Unlock()

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
