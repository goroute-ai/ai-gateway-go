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

//go:embed scripts/check_and_increment_global.lua
var checkAndIncrementGlobalLua string

//go:embed scripts/reconcile.lua
var reconcileLua string

//go:embed scripts/reconcile_global.lua
var reconcileGlobalLua string

//go:embed scripts/rollback_acquire.lua
var rollbackAcquireLua string

//go:embed scripts/record_spend.lua
var recordSpendLua string

//go:embed scripts/reset_budget_spend.lua
var resetBudgetSpendLua string

//go:embed scripts/renew_reservation.lua
var renewReservationLua string

// SpendIncrementEvent describes a single spend settlement for batched Redis pipelining.
type SpendIncrementEvent struct {
	EventID      string
	RequestID    string
	VirtualKeyID string
	TeamID       string
	UserID       string
	OrgID        string
	CostMicros   int64
}

// Limiter enforces RPM, TPM, Concurrency, and Budget limits across Virtual Key, Team, User, Organization, and Global scopes.
// Uses atomic Redis Lua scripts; configured quotas fail closed when Redis is unavailable.
type Limiter struct {
	redis              *storage.RedisFabric
	checkScript        *redis.Script
	checkGlobalScript  *redis.Script
	reconcileScr       *redis.Script
	reconcileGlobalScr *redis.Script
	rollbackScr        *redis.Script
	spendScr           *redis.Script
	resetBudgetScr     *redis.Script
	renewScr           *redis.Script
	windowSec          int
	concTTLSec         int

	mu            sync.RWMutex
	globalRPM     int
	globalTPM     int
	globalMaxConc int
}

func NewLimiter(redisFabric *storage.RedisFabric, windowSec, concTTLSec int) *Limiter {
	if windowSec <= 0 {
		windowSec = 60
	}
	if concTTLSec <= 0 {
		concTTLSec = 300
	}
	return &Limiter{
		redis:              redisFabric,
		checkScript:        redis.NewScript(checkAndIncrementLua),
		checkGlobalScript:  redis.NewScript(checkAndIncrementGlobalLua),
		reconcileScr:       redis.NewScript(reconcileLua),
		reconcileGlobalScr: redis.NewScript(reconcileGlobalLua),
		rollbackScr:        redis.NewScript(rollbackAcquireLua),
		spendScr:           redis.NewScript(recordSpendLua),
		resetBudgetScr:     redis.NewScript(resetBudgetSpendLua),
		renewScr:           redis.NewScript(renewReservationLua),
		windowSec:          windowSec,
		concTTLSec:         concTTLSec,
	}
}

// SetGlobalLimits configures gateway-wide RPM, TPM, and concurrency caps.
// Non-positive values disable the corresponding global limit.
func (l *Limiter) SetGlobalLimits(rpm, tpm, maxConcurrent int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.globalRPM = rpm
	l.globalTPM = tpm
	l.globalMaxConc = maxConcurrent
}

func (l *Limiter) globalLimits() (rpm, tpm, maxConc int) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.globalRPM, l.globalTPM, l.globalMaxConc
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

func reservationTuple(base string) (string, string, string) {
	return base, base + ":sum", base + ":amounts"
}

func acquireKeys(idCtx *domain.IdentityContext, nowMin int64) []string {
	tag := orgHashTag(idCtx.OrgID)
	keyResZ, keyResS, keyResA := reservationTuple(fmt.Sprintf("gw:budget:%s:reservations:key:%s", tag, idCtx.VirtualKeyID))
	teamResZ, teamResS, teamResA := reservationTuple(fmt.Sprintf("gw:budget:%s:reservations:team:%s", tag, idCtx.TeamID))
	userResZ, userResS, userResA := reservationTuple(fmt.Sprintf("gw:budget:%s:reservations:user:%s", tag, idCtx.UserID))
	orgResZ, orgResS, orgResA := reservationTuple(fmt.Sprintf("gw:budget:%s:reservations:org:%s", tag, idCtx.OrgID))

	return []string{
		fmt.Sprintf("gw:rl:%s:rpm:key:%s:%d", tag, idCtx.VirtualKeyID, nowMin),
		fmt.Sprintf("gw:rl:%s:tpm:key:%s:%d", tag, idCtx.VirtualKeyID, nowMin),
		fmt.Sprintf("gw:rl:%s:conc:%s", tag, idCtx.VirtualKeyID),
		fmt.Sprintf("gw:spend:%s:key:%s", tag, idCtx.VirtualKeyID),
		fmt.Sprintf("gw:rl:%s:rpm:team:%s:%d", tag, idCtx.TeamID, nowMin),
		fmt.Sprintf("gw:rl:%s:tpm:team:%s:%d", tag, idCtx.TeamID, nowMin),
		fmt.Sprintf("gw:spend:%s:team:%s", tag, idCtx.TeamID),
		fmt.Sprintf("gw:rl:%s:rpm:user:%s:%d", tag, idCtx.UserID, nowMin),
		fmt.Sprintf("gw:rl:%s:tpm:user:%s:%d", tag, idCtx.UserID, nowMin),
		fmt.Sprintf("gw:rl:%s:conc:user:%s", tag, idCtx.UserID),
		fmt.Sprintf("gw:spend:%s:user:%s", tag, idCtx.UserID),
		fmt.Sprintf("gw:rl:%s:rpm:org:%s:%d", tag, idCtx.OrgID, nowMin),
		fmt.Sprintf("gw:rl:%s:tpm:org:%s:%d", tag, idCtx.OrgID, nowMin),
		fmt.Sprintf("gw:spend:%s:org:%s", tag, idCtx.OrgID),
		keyResZ, keyResS, keyResA,
		teamResZ, teamResS, teamResA,
		userResZ, userResS, userResA,
		orgResZ, orgResS, orgResA,
	}
}

func globalAcquireKeys(nowMin int64) []string {
	return []string{
		fmt.Sprintf("gw:rl:{global}:rpm:%d", nowMin),
		fmt.Sprintf("gw:rl:{global}:tpm:%d", nowMin),
		"gw:rl:{global}:conc",
	}
}

func reconcileKeys(keys []string) []string {
	return []string{
		keys[2],                      // key_conc
		keys[9],                      // user_conc
		keys[1],                      // key_tpm
		keys[5],                      // team_tpm
		keys[8],                      // user_tpm
		keys[12],                     // org_tpm
		keys[14], keys[15], keys[16], // key_res
		keys[17], keys[18], keys[19], // team_res
		keys[20], keys[21], keys[22], // user_res
		keys[23], keys[24], keys[25], // org_res
		keys[3],  // key_spend
		keys[6],  // team_spend
		keys[10], // user_spend
		keys[13], // org_spend
	}
}

func rollbackKeys(keys []string) []string {
	return []string{
		keys[0], keys[1], keys[2], // key rpm, tpm, conc
		keys[4], keys[5], // team rpm, tpm
		keys[7], keys[8], keys[9], // user rpm, tpm, conc
		keys[11], keys[12], // org rpm, tpm
		keys[14], keys[15], keys[16], // key_res
		keys[17], keys[18], keys[19], // team_res
		keys[20], keys[21], keys[22], // user_res
		keys[23], keys[24], keys[25], // org_res
	}
}

func spendKeys(keyID, teamID, userID, orgID string) []string {
	tag := orgHashTag(orgID)
	keyResZ, keyResS, keyResA := reservationTuple(fmt.Sprintf("gw:budget:%s:reservations:key:%s", tag, keyID))
	teamResZ, teamResS, teamResA := reservationTuple(fmt.Sprintf("gw:budget:%s:reservations:team:%s", tag, teamID))
	userResZ, userResS, userResA := reservationTuple(fmt.Sprintf("gw:budget:%s:reservations:user:%s", tag, userID))
	orgResZ, orgResS, orgResA := reservationTuple(fmt.Sprintf("gw:budget:%s:reservations:org:%s", tag, orgID))

	return []string{
		fmt.Sprintf("gw:spend:%s:key:%s", tag, keyID),
		fmt.Sprintf("gw:spend:%s:team:%s", tag, teamID),
		fmt.Sprintf("gw:spend:%s:user:%s", tag, userID),
		fmt.Sprintf("gw:spend:%s:org:%s", tag, orgID),
		keyResZ, keyResS, keyResA,
		teamResZ, teamResS, teamResA,
		userResZ, userResS, userResA,
		orgResZ, orgResS, orgResA,
	}
}

func (l *Limiter) acquire(ctx context.Context, idCtx *domain.IdentityContext, estimatedTokens int, reserveMicros int64, requestID string) (func(int, int64), error) {
	if idCtx == nil {
		return func(int, int64) {}, nil
	}
	if estimatedTokens < 1 {
		estimatedTokens = 1
	}

	gRPM, gTPM, gConc := l.globalLimits()
	hasGlobal := gRPM > 0 || gTPM > 0 || gConc > 0
	nowMin := time.Now().Unix() / 60

	// Try Redis Atomic Lua script first if Redis is configured
	if l.redis != nil && l.redis.Client() != nil {
		keys := acquireKeys(idCtx, nowMin)
		argv := []any{
			idCtx.KeyRPMLimit, idCtx.KeyTPMLimit, idCtx.KeyMaxConcurrent, idCtx.KeyMaxBudgetMicros,
			idCtx.TeamRPMLimit, idCtx.TeamTPMLimit, idCtx.TeamMaxBudgetMicros,
			idCtx.UserRPMLimit, idCtx.UserTPMLimit, idCtx.UserMaxConcurrent, idCtx.UserMaxBudgetMicros,
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

				gKeys := globalAcquireKeys(nowMin)
				if hasGlobal {
					gRes, gErr := l.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
						return l.checkGlobalScript.Run(ctx, rdb, gKeys, gRPM, gTPM, gConc, estimatedTokens, l.windowSec*2, l.concTTLSec).Slice()
					})
					rollbackOrg := func() {
						rbKeys := rollbackKeys(keys)
						rbArgv := []any{
							estimatedTokens, requestID,
							idCtx.TeamRPMLimit, idCtx.TeamTPMLimit,
							idCtx.UserRPMLimit, idCtx.UserTPMLimit, idCtx.UserMaxConcurrent,
							idCtx.OrgRPMLimit, idCtx.OrgTPMLimit,
						}
						_, _ = l.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
							return l.rollbackScr.Run(context.Background(), rdb, rbKeys, rbArgv...).Result()
						})
					}
					if gErr != nil {
						rollbackOrg()
						return nil, limiterUnavailableError()
					}
					if gSlice, ok := gRes.([]any); ok && len(gSlice) >= 2 {
						gAllowed, _ := gSlice[0].(int64)
						gReason, _ := gSlice[1].(string)
						if gAllowed == 0 {
							rollbackOrg()
							return nil, toQuotaError(gReason)
						}
					} else {
						rollbackOrg()
						return nil, limiterUnavailableError()
					}
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
					if hasGlobal {
						_, _ = l.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
							return l.reconcileGlobalScr.Run(context.Background(), rdb, []string{gKeys[2], gKeys[1]}, delta, l.windowSec*2, gTPM, gConc).Result()
						})
					}
				}, nil
			}
		}
	}

	if hasConfiguredLimits(idCtx) || hasGlobal {
		return nil, limiterUnavailableError()
	}
	return func(int, int64) {}, nil
}

func hasConfiguredLimits(idCtx *domain.IdentityContext) bool {
	return idCtx != nil && (idCtx.KeyRPMLimit > 0 || idCtx.KeyTPMLimit > 0 || idCtx.KeyMaxConcurrent > 0 || idCtx.KeyMaxBudgetMicros > 0 ||
		idCtx.TeamRPMLimit > 0 || idCtx.TeamTPMLimit > 0 || idCtx.TeamMaxBudgetMicros > 0 ||
		idCtx.UserRPMLimit > 0 || idCtx.UserTPMLimit > 0 || idCtx.UserMaxConcurrent > 0 || idCtx.UserMaxBudgetMicros > 0 ||
		idCtx.OrgRPMLimit > 0 || idCtx.OrgTPMLimit > 0 || idCtx.OrgMaxBudgetMicros > 0)
}

func limiterUnavailableError() *domain.GatewayError {
	return &domain.GatewayError{StatusCode: http.StatusServiceUnavailable, Type: domain.ErrorTypeRateLimit, Code: "rate_limiter_unavailable", Message: "Distributed rate limiter is unavailable; request rejected to preserve configured quotas", RetryAfterSec: 5}
}

func hasBudget(idCtx *domain.IdentityContext) bool {
	return idCtx != nil && (idCtx.KeyMaxBudgetMicros > 0 || idCtx.TeamMaxBudgetMicros > 0 || idCtx.UserMaxBudgetMicros > 0 || idCtx.OrgMaxBudgetMicros > 0)
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
// and atomically removes any matching request reservations across key, team, and org scopes.
func (l *Limiter) RecordSpendIncrementForEvent(ctx context.Context, eventID, requestID, keyID, teamID, orgID string, costMicros int64) error {
	return l.RecordSpendIncrementForUserEvent(ctx, eventID, requestID, keyID, teamID, "", orgID, costMicros)
}

// RecordSpendIncrementForUserEvent idempotently applies spend for eventID (falling back to requestID)
// and atomically removes any matching request reservations across key, team, user, and org scopes.
func (l *Limiter) RecordSpendIncrementForUserEvent(ctx context.Context, eventID, requestID, keyID, teamID, userID, orgID string, costMicros int64) error {
	if costMicros <= 0 && requestID == "" {
		return nil
	}
	if l.redis == nil || l.redis.Client() == nil {
		return nil
	}
	keys, argv := buildSpendEventArgs(SpendIncrementEvent{
		EventID:      eventID,
		RequestID:    requestID,
		VirtualKeyID: keyID,
		TeamID:       teamID,
		UserID:       userID,
		OrgID:        orgID,
		CostMicros:   costMicros,
	})
	_, err := l.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
		return l.spendScr.Run(ctx, rdb, keys, argv...).Result()
	})
	return err
}

func buildSpendEventArgs(ev SpendIncrementEvent) ([]string, []any) {
	effectiveEventID := ev.EventID
	if effectiveEventID == "" {
		effectiveEventID = ev.RequestID
	}
	keys := spendKeys(ev.VirtualKeyID, ev.TeamID, ev.UserID, ev.OrgID)
	if effectiveEventID != "" {
		tag := orgHashTag(ev.OrgID)
		keys = append(keys, fmt.Sprintf("gw:spend:applied:%s:%s", tag, effectiveEventID))
	}
	return keys, []any{ev.RequestID, ev.CostMicros, effectiveEventID}
}

// RecordSpendIncrementsBatch pipelines multiple spend settlement scripts over Redis
// and returns a per-event error slice matching the input order.
func (l *Limiter) RecordSpendIncrementsBatch(ctx context.Context, events []SpendIncrementEvent) []error {
	errs := make([]error, len(events))
	if len(events) == 0 || l == nil || l.redis == nil || l.redis.Client() == nil {
		return errs
	}
	_, execErr := l.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
		if err := l.spendScr.Load(ctx, rdb).Err(); err != nil {
			return nil, err
		}
		cmds := make([]*redis.Cmd, len(events))
		_, pipeErr := rdb.Pipelined(ctx, func(pipe redis.Pipeliner) error {
			for i, ev := range events {
				if ev.CostMicros <= 0 && ev.RequestID == "" {
					continue
				}
				keys, argv := buildSpendEventArgs(ev)
				cmds[i] = l.spendScr.EvalSha(ctx, pipe, keys, argv...)
			}
			return nil
		})
		for i, cmd := range cmds {
			if cmd == nil {
				continue
			}
			if err := cmd.Err(); err != nil {
				if strings.Contains(err.Error(), "NOSCRIPT") {
					keys, argv := buildSpendEventArgs(events[i])
					errs[i] = l.spendScr.Run(ctx, rdb, keys, argv...).Err()
					continue
				}
				errs[i] = err
			} else if pipeErr != nil {
				errs[i] = pipeErr
			}
		}
		return nil, pipeErr
	})
	if execErr != nil {
		for i, ev := range events {
			if (ev.CostMicros > 0 || ev.RequestID != "") && errs[i] == nil {
				errs[i] = execErr
			}
		}
	}
	return errs
}

// RenewReservationLease extends the expiration of active budget reservations
// matching requestID across key, team, user, and org reservation sorted sets.
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
	keyResZ, keyResS, keyResA := reservationTuple(fmt.Sprintf("gw:budget:%s:reservations:key:%s", tag, idCtx.VirtualKeyID))
	teamResZ, teamResS, teamResA := reservationTuple(fmt.Sprintf("gw:budget:%s:reservations:team:%s", tag, idCtx.TeamID))
	userResZ, userResS, userResA := reservationTuple(fmt.Sprintf("gw:budget:%s:reservations:user:%s", tag, idCtx.UserID))
	orgResZ, orgResS, orgResA := reservationTuple(fmt.Sprintf("gw:budget:%s:reservations:org:%s", tag, idCtx.OrgID))
	keys := []string{
		keyResZ, keyResS, keyResA,
		teamResZ, teamResS, teamResA,
		userResZ, userResS, userResA,
		orgResZ, orgResS, orgResA,
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
			if scope != "org" && scope != "team" && scope != "user" && scope != "key" {
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
