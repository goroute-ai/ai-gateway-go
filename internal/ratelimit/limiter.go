package ratelimit

import (
	"context"
	_ "embed"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
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

//go:embed scripts/rollback_global.lua
var rollbackGlobalLua string

//go:embed scripts/record_spend.lua
var recordSpendLua string

//go:embed scripts/reset_budget_spend.lua
var resetBudgetSpendLua string

//go:embed scripts/renew_reservation.lua
var renewReservationLua string

//go:embed scripts/check_budget_available.lua
var checkBudgetAvailableLua string

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

// RollingWindowSpendLoader restores timestamped trailing-24h spend entries and
// active migration holds from durable storage when a rolling_24h counter is cold.
type RollingWindowSpendLoader func(ctx context.Context, orgID string, descriptor domain.RateLimitDescriptor, now time.Time) ([]domain.RollingSpendEntry, error)

// Limiter enforces RPM, TPM, Concurrency, and Budget limits across Virtual Key, Team, User, Organization, and Global scopes.
// Uses atomic Redis Lua scripts; configured quotas fail closed when Redis is unavailable.
type Limiter struct {
	redis                   *storage.RedisFabric
	checkScript             *redis.Script
	checkGlobalScript       *redis.Script
	reconcileScr            *redis.Script
	reconcileGlobalScr      *redis.Script
	rollbackScr             *redis.Script
	rollbackGlobalScr       *redis.Script
	spendScr                *redis.Script
	resetBudgetScr          *redis.Script
	renewScr                *redis.Script
	budgetAvailScr          *redis.Script
	batchAcquireScr         *redis.Script
	batchReleaseScr         *redis.Script
	checkDescriptorsScr     *redis.Script
	reconcileDescriptorsScr *redis.Script
	renewDescriptorsScr     *redis.Script
	windowSec               int
	concTTLSec              int
	nowFunc                 func() time.Time

	mu                      sync.RWMutex
	enabled                 bool
	fallbackToLocalOnOutage bool
	defaultEstimatedTPM     int
	redisTimeout            time.Duration
	globalRPM               int
	globalTPM               int
	globalMaxConc           int
	rollingLoader           RollingWindowSpendLoader

	localMu               sync.Mutex
	localWindowMin        int64
	localRPM              map[string]int
	localTPM              map[string]int
	localConc             map[string]int
	localSpent            map[string]int64
	localReservations     map[string]map[string]int64
	localBatchSum         map[string]int64
	localBatchHolds       map[string]localBatchHold
	localDescWindowMin    int64
	localDescDay          string
	localDescRPM          map[string]int
	localDescTPM          map[string]int
	localDescITPM         map[string]int
	localDescOTPM         map[string]int
	localDescTPD          map[string]int64
	localDescRPD          map[string]int64
	localDescConc         map[string]int
	localDescIter         map[string]localIterCounter
	localDescSpent        map[string]int64
	localDescReservations map[string]map[string]localReservationEntry
	localDescRolling      map[string]localRollingWindow
}

func NewLimiter(redisFabric *storage.RedisFabric, windowSec, concTTLSec int) *Limiter {
	if windowSec <= 0 {
		windowSec = 60
	}
	if concTTLSec <= 0 {
		concTTLSec = 300
	}
	return &Limiter{
		redis:                   redisFabric,
		checkScript:             redis.NewScript(checkAndIncrementLua),
		checkGlobalScript:       redis.NewScript(checkAndIncrementGlobalLua),
		reconcileScr:            redis.NewScript(reconcileLua),
		reconcileGlobalScr:      redis.NewScript(reconcileGlobalLua),
		rollbackScr:             redis.NewScript(rollbackAcquireLua),
		rollbackGlobalScr:       redis.NewScript(rollbackGlobalLua),
		spendScr:                redis.NewScript(recordSpendLua),
		resetBudgetScr:          redis.NewScript(resetBudgetSpendLua),
		renewScr:                redis.NewScript(renewReservationLua),
		budgetAvailScr:          redis.NewScript(checkBudgetAvailableLua),
		batchAcquireScr:         redis.NewScript(batchEnqueuedAcquireLua),
		batchReleaseScr:         redis.NewScript(batchEnqueuedReleaseLua),
		checkDescriptorsScr:     redis.NewScript(checkDescriptorsLua),
		reconcileDescriptorsScr: redis.NewScript(reconcileDescriptorsLua),
		renewDescriptorsScr:     redis.NewScript(renewDescriptorsLua),
		windowSec:               windowSec,
		concTTLSec:              concTTLSec,
		enabled:                 true,
		localRPM:                make(map[string]int),
		localTPM:                make(map[string]int),
		localConc:               make(map[string]int),
		localSpent:              make(map[string]int64),
		localReservations:       make(map[string]map[string]int64),
		localBatchSum:           make(map[string]int64),
		localBatchHolds:         make(map[string]localBatchHold),
		localDescRPM:            make(map[string]int),
		localDescTPM:            make(map[string]int),
		localDescITPM:           make(map[string]int),
		localDescOTPM:           make(map[string]int),
		localDescTPD:            make(map[string]int64),
		localDescRPD:            make(map[string]int64),
		localDescConc:           make(map[string]int),
		localDescIter:           make(map[string]localIterCounter),
		localDescSpent:          make(map[string]int64),
		localDescReservations:   make(map[string]map[string]localReservationEntry),
		localDescRolling:        make(map[string]localRollingWindow),
	}
}

// SetFallbackToLocalOnOutage enables or disables degraded in-memory rate-limit
// and budget enforcement when Redis is unavailable.
func (l *Limiter) SetFallbackToLocalOnOutage(fallback bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.fallbackToLocalOnOutage = fallback
}

// SetRollingWindowLoader configures the durable repository loader used to restore
// timestamped trailing-24h spend history on cold rolling_24h quota counters.
func (l *Limiter) SetRollingWindowLoader(loader RollingWindowSpendLoader) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.rollingLoader = loader
}

// SetNowFunc overrides the wall-clock source used by the limiter (primarily for deterministic tests).
func (l *Limiter) SetNowFunc(fn func() time.Time) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.nowFunc = fn
}

// SetEnabled enables or disables rate limiting enforcement.
// When disabled, Acquire and AcquireWithBudget bypass Redis checks and admit requests.
func (l *Limiter) SetEnabled(enabled bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.enabled = enabled
}

// SetDefaultEstimatedTPM sets the fallback token estimate used when a caller passes <= 0.
func (l *Limiter) SetDefaultEstimatedTPM(tokens int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.defaultEstimatedTPM = tokens
}

// SetRedisTimeout sets the per-call timeout applied to Redis Lua script executions.
func (l *Limiter) SetRedisTimeout(timeout time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.redisTimeout = timeout
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

func (l *Limiter) configSnapshot() (enabled, fallbackLocal bool, defaultEstTPM, gRPM, gTPM, gConc int) {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.enabled, l.fallbackToLocalOnOutage, l.defaultEstimatedTPM, l.globalRPM, l.globalTPM, l.globalMaxConc
}

func (l *Limiter) withRedisTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	l.mu.RLock()
	timeout := l.redisTimeout
	l.mu.RUnlock()
	if timeout <= 0 {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, timeout)
}

// Acquire checks rate limits and, for backward compatibility, only admits requests
// without an enforced budget. Budgeted requests must use AcquireWithBudget so the
// maximum spend is reserved atomically before dispatch.
// Returns a release function that MUST be called after the request finishes to decrement concurrency and reconcile token deltas.
func (l *Limiter) Acquire(ctx context.Context, idCtx *domain.IdentityContext, estimatedTokens int) (func(actualTokens int), error) {
	rel, _, err := l.AcquireWithMeta(ctx, idCtx, estimatedTokens)
	return rel, err
}

// AcquireWithMeta enforces rate limits without budget reservation and returns tightest-scope
// rate-limit header metadata for emission on inference responses.
func (l *Limiter) AcquireWithMeta(ctx context.Context, idCtx *domain.IdentityContext, estimatedTokens int) (func(actualTokens int), *domain.RateLimitHeaderMetadata, error) {
	release, _, meta, err := l.acquireInternal(ctx, idCtx, estimatedTokens, 0, "")
	if err != nil {
		return nil, nil, err
	}
	return func(actualTokens int) { release(actualTokens, 0) }, meta, nil
}

// AcquireWithRollback behaves like Acquire and additionally returns an undo hook
// that reverts RPM, TPM, and concurrency increments if a downstream quota step rejects.
func (l *Limiter) AcquireWithRollback(ctx context.Context, idCtx *domain.IdentityContext, estimatedTokens int) (func(actualTokens int), func(), error) {
	release, rollback, _, err := l.AcquireWithRollbackWithMeta(ctx, idCtx, estimatedTokens)
	return release, rollback, err
}

// AcquireWithRollbackWithMeta behaves like AcquireWithRollback and also returns tightest-scope
// rate-limit header metadata for emission on 2xx inference responses.
func (l *Limiter) AcquireWithRollbackWithMeta(ctx context.Context, idCtx *domain.IdentityContext, estimatedTokens int) (func(actualTokens int), func(), *domain.RateLimitHeaderMetadata, error) {
	release, rollback, meta, err := l.acquireInternal(ctx, idCtx, estimatedTokens, 0, "")
	if err != nil {
		return nil, nil, nil, err
	}
	return func(actualTokens int) { release(actualTokens, 0) }, rollback, meta, nil
}

// AcquireSession enforces rate/concurrency limits and verifies that any configured
// budget still has remaining headroom before opening a long-lived session (e.g. Realtime WS),
// without holding a synthetic budget reservation across idle session lifetime.
func (l *Limiter) AcquireSession(ctx context.Context, idCtx *domain.IdentityContext) (func(), error) {
	rel, _, err := l.AcquireSessionWithMeta(ctx, idCtx)
	return rel, err
}

// AcquireSessionWithMeta behaves like AcquireSession and also returns rate-limit header metadata.
func (l *Limiter) AcquireSessionWithMeta(ctx context.Context, idCtx *domain.IdentityContext) (func(), *domain.RateLimitHeaderMetadata, error) {
	if l == nil || idCtx == nil {
		return func() {}, nil, nil
	}
	if !hasBudget(idCtx) {
		release, meta, err := l.AcquireWithMeta(ctx, idCtx, 1)
		if err != nil {
			return nil, nil, err
		}
		return func() { release(1) }, meta, nil
	}
	enabled, fallbackLocal, _, _, _, _ := l.configSnapshot()
	if !enabled {
		return func() {}, nil, nil
	}
	if err := l.checkBudgetHeadroom(ctx, idCtx, fallbackLocal); err != nil {
		return nil, nil, err
	}
	rateOnly := *idCtx
	rateOnly.KeyMaxBudgetMicros = 0
	rateOnly.TeamMaxBudgetMicros = 0
	rateOnly.UserMaxBudgetMicros = 0
	rateOnly.OrgMaxBudgetMicros = 0
	release, meta, err := l.AcquireWithMeta(ctx, &rateOnly, 1)
	if err != nil {
		return nil, nil, err
	}
	return func() { release(1) }, meta, nil
}

// CheckBudgetReserve verifies whether idCtx has sufficient remaining Key/Team/User/Org
// budget headroom to afford reserveMicros (replacing any active reservation already held by requestID).
func (l *Limiter) CheckBudgetReserve(ctx context.Context, idCtx *domain.IdentityContext, reserveMicros int64, requestID string) error {
	if l == nil || idCtx == nil || reserveMicros <= 0 {
		return nil
	}
	enabled, fallbackLocal, _, _, _, _ := l.configSnapshot()
	if !enabled {
		return nil
	}
	if !hasBudget(idCtx) {
		return nil
	}
	return l.checkBudgetHeadroomWithReserve(ctx, idCtx, fallbackLocal, reserveMicros, requestID)
}

func (l *Limiter) checkBudgetHeadroom(ctx context.Context, idCtx *domain.IdentityContext, fallbackLocal bool) error {
	return l.checkBudgetHeadroomWithReserve(ctx, idCtx, fallbackLocal, 0, "")
}

func (l *Limiter) checkBudgetHeadroomWithReserve(ctx context.Context, idCtx *domain.IdentityContext, fallbackLocal bool, reserveMicros int64, requestID string) error {
	if l.redis != nil && l.redis.Client() != nil {
		keys := spendKeys(idCtx.VirtualKeyID, idCtx.TeamID, idCtx.UserID, idCtx.OrgID)
		argv := []any{
			idCtx.KeyMaxBudgetMicros, idCtx.KeySpentMicros,
			idCtx.TeamMaxBudgetMicros, idCtx.TeamSpentMicros,
			idCtx.UserMaxBudgetMicros, idCtx.UserSpentMicros,
			idCtx.OrgMaxBudgetMicros, idCtx.OrgSpentMicros,
			reserveMicros, requestID,
		}
		res, err := l.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
			rCtx, cancel := l.withRedisTimeout(ctx)
			defer cancel()
			return l.budgetAvailScr.Run(rCtx, rdb, keys, argv...).Slice()
		})
		if err == nil {
			if slice, ok := res.([]any); ok && len(slice) >= 2 {
				allowed, _ := slice[0].(int64)
				reason, _ := slice[1].(string)
				if allowed == 0 {
					return toQuotaError(reason)
				}
				return nil
			}
		}
		if !fallbackLocal {
			return limiterUnavailableError()
		}
	}

	if !fallbackLocal {
		return limiterUnavailableError()
	}

	l.localMu.Lock()
	defer l.localMu.Unlock()
	scopes := []struct {
		key     string
		maxB    int64
		dbFloor int64
		errCode string
	}{
		{key: "key:" + idCtx.VirtualKeyID, maxB: idCtx.KeyMaxBudgetMicros, dbFloor: idCtx.KeySpentMicros, errCode: "KEY_BUDGET_EXCEEDED"},
		{key: "team:" + idCtx.TeamID, maxB: idCtx.TeamMaxBudgetMicros, dbFloor: idCtx.TeamSpentMicros, errCode: "TEAM_BUDGET_EXCEEDED"},
		{key: "user:" + idCtx.UserID, maxB: idCtx.UserMaxBudgetMicros, dbFloor: idCtx.UserSpentMicros, errCode: "USER_BUDGET_EXCEEDED"},
		{key: "org:" + idCtx.OrgID, maxB: idCtx.OrgMaxBudgetMicros, dbFloor: idCtx.OrgSpentMicros, errCode: "ORG_BUDGET_EXCEEDED"},
	}
	for _, sc := range scopes {
		if sc.dbFloor > l.localSpent[sc.key] {
			l.localSpent[sc.key] = sc.dbFloor
		}
		if sc.maxB > 0 {
			var reserved int64
			for reqKey, amt := range l.localReservations[sc.key] {
				if requestID != "" && reqKey == requestID {
					continue
				}
				reserved += amt
			}
			if reserveMicros > 0 {
				if l.localSpent[sc.key]+reserved+reserveMicros > sc.maxB {
					return toQuotaError(sc.errCode)
				}
			} else if l.localSpent[sc.key]+reserved >= sc.maxB {
				return toQuotaError(sc.errCode)
			}
		}
	}
	return nil
}

// AcquireWithBudget atomically reserves a conservative upper-bound cost in
// micro-dollars alongside rate-limit admission. Call release with actual usage
// and cost after dispatch; a negative token count releases the reservation
// without charging spend.
func (l *Limiter) AcquireWithBudget(ctx context.Context, idCtx *domain.IdentityContext, estimatedTokens int, reserveMicros int64, requestID string) (func(actualTokens int, actualCostMicros int64), error) {
	rel, _, err := l.AcquireWithBudgetAndMeta(ctx, idCtx, estimatedTokens, reserveMicros, requestID)
	return rel, err
}

// AcquireWithBudgetAndMeta behaves like AcquireWithBudget and additionally returns tightest-scope
// rate-limit telemetry headers for emission on 2xx responses.
func (l *Limiter) AcquireWithBudgetAndMeta(ctx context.Context, idCtx *domain.IdentityContext, estimatedTokens int, reserveMicros int64, requestID string) (func(actualTokens int, actualCostMicros int64), *domain.RateLimitHeaderMetadata, error) {
	if reserveMicros < 0 || requestID == "" {
		return nil, nil, fmt.Errorf("budget reservation requires a non-negative amount and request ID")
	}
	release, _, meta, err := l.acquireInternal(ctx, idCtx, estimatedTokens, reserveMicros, requestID)
	return release, meta, err
}

// AcquireWithBudgetAndRollback behaves like AcquireWithBudget and additionally
// returns an undo hook that reverts RPM, TPM, concurrency, and budget reservations
// if a downstream quota step rejects before dispatch.
func (l *Limiter) AcquireWithBudgetAndRollback(ctx context.Context, idCtx *domain.IdentityContext, estimatedTokens int, reserveMicros int64, requestID string) (func(actualTokens int, actualCostMicros int64), func(), error) {
	if reserveMicros < 0 || requestID == "" {
		return nil, nil, fmt.Errorf("budget reservation requires a non-negative amount and request ID")
	}
	release, rollback, _, err := l.acquireInternal(ctx, idCtx, estimatedTokens, reserveMicros, requestID)
	return release, rollback, err
}

// AcquireWithBudgetAndRollbackWithMeta combines rollback hooks with 2xx rate-limit header metadata.
func (l *Limiter) AcquireWithBudgetAndRollbackWithMeta(ctx context.Context, idCtx *domain.IdentityContext, estimatedTokens int, reserveMicros int64, requestID string) (func(actualTokens int, actualCostMicros int64), func(), *domain.RateLimitHeaderMetadata, error) {
	if reserveMicros < 0 || requestID == "" {
		return nil, nil, nil, fmt.Errorf("budget reservation requires a non-negative amount and request ID")
	}
	return l.acquireInternal(ctx, idCtx, estimatedTokens, reserveMicros, requestID)
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
		fmt.Sprintf("gw:rl:%s:zconc:%s", tag, idCtx.VirtualKeyID),
		fmt.Sprintf("gw:spend:%s:key:%s", tag, idCtx.VirtualKeyID),
		fmt.Sprintf("gw:rl:%s:rpm:team:%s:%d", tag, idCtx.TeamID, nowMin),
		fmt.Sprintf("gw:rl:%s:tpm:team:%s:%d", tag, idCtx.TeamID, nowMin),
		fmt.Sprintf("gw:rl:%s:zconc:team:%s", tag, idCtx.TeamID),
		fmt.Sprintf("gw:spend:%s:team:%s", tag, idCtx.TeamID),
		fmt.Sprintf("gw:rl:%s:rpm:user:%s:%d", tag, idCtx.UserID, nowMin),
		fmt.Sprintf("gw:rl:%s:tpm:user:%s:%d", tag, idCtx.UserID, nowMin),
		fmt.Sprintf("gw:rl:%s:zconc:user:%s", tag, idCtx.UserID),
		fmt.Sprintf("gw:spend:%s:user:%s", tag, idCtx.UserID),
		fmt.Sprintf("gw:rl:%s:rpm:org:%s:%d", tag, idCtx.OrgID, nowMin),
		fmt.Sprintf("gw:rl:%s:tpm:org:%s:%d", tag, idCtx.OrgID, nowMin),
		fmt.Sprintf("gw:rl:%s:zconc:org:%s", tag, idCtx.OrgID),
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
		"gw:rl:{global}:zconc",
	}
}

func reconcileKeys(keys []string) []string {
	return []string{
		keys[2],                      // key_conc
		keys[6],                      // team_conc
		keys[10],                     // user_conc
		keys[14],                     // org_conc
		keys[1],                      // key_tpm
		keys[5],                      // team_tpm
		keys[9],                      // user_tpm
		keys[13],                     // org_tpm
		keys[16], keys[17], keys[18], // key_res
		keys[19], keys[20], keys[21], // team_res
		keys[22], keys[23], keys[24], // user_res
		keys[25], keys[26], keys[27], // org_res
		keys[3],  // key_spend
		keys[7],  // team_spend
		keys[11], // user_spend
		keys[15], // org_spend
	}
}

func rollbackKeys(keys []string) []string {
	return []string{
		keys[0], keys[1], keys[2], // key rpm, tpm, conc
		keys[4], keys[5], keys[6], // team rpm, tpm, conc
		keys[8], keys[9], keys[10], // user rpm, tpm, conc
		keys[12], keys[13], keys[14], // org rpm, tpm, conc
		keys[16], keys[17], keys[18], // key_res
		keys[19], keys[20], keys[21], // team_res
		keys[22], keys[23], keys[24], // user_res
		keys[25], keys[26], keys[27], // org_res
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

func (l *Limiter) acquireInternal(ctx context.Context, idCtx *domain.IdentityContext, estimatedTokens int, reserveMicros int64, requestID string) (func(int, int64), func(), *domain.RateLimitHeaderMetadata, error) {
	enabled, fallbackLocal, defaultEstTPM, gRPM, gTPM, gConc := l.configSnapshot()
	if !enabled || idCtx == nil {
		return func(int, int64) {}, func() {}, nil, nil
	}
	if estimatedTokens <= 0 {
		if defaultEstTPM > 0 {
			estimatedTokens = defaultEstTPM
		} else {
			estimatedTokens = 1
		}
	}
	slotID := requestID
	if slotID == "" && reserveMicros == 0 {
		slotID = uuid.NewString()
	}

	hasGlobal := gRPM > 0 || gTPM > 0 || gConc > 0
	now := l.nowUTC()
	nowMin := now.Unix() / 60

	// Try Redis Atomic Lua script first if Redis is configured
	if l.redis != nil && l.redis.Client() != nil {
		keys := acquireKeys(idCtx, nowMin)
		argv := []any{
			idCtx.KeyRPMLimit, idCtx.KeyTPMLimit, idCtx.KeyMaxConcurrent, idCtx.KeyMaxBudgetMicros, idCtx.KeySpentMicros,
			idCtx.TeamRPMLimit, idCtx.TeamTPMLimit, idCtx.TeamMaxConcurrent, idCtx.TeamMaxBudgetMicros, idCtx.TeamSpentMicros,
			idCtx.UserRPMLimit, idCtx.UserTPMLimit, idCtx.UserMaxConcurrent, idCtx.UserMaxBudgetMicros, idCtx.UserSpentMicros,
			idCtx.OrgRPMLimit, idCtx.OrgTPMLimit, idCtx.OrgMaxConcurrent, idCtx.OrgMaxBudgetMicros, idCtx.OrgSpentMicros,
			estimatedTokens, l.windowSec * 2, l.concTTLSec, reserveMicros, slotID, 3600,
		}

		res, err := l.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
			rCtx, cancel := l.withRedisTimeout(ctx)
			defer cancel()
			return l.checkScript.Run(rCtx, rdb, keys, argv...).Slice()
		})
		if err == nil {
			if slice, ok := res.([]any); ok && len(slice) >= 2 {
				allowed, _ := slice[0].(int64)
				reason, _ := slice[1].(string)
				if allowed == 0 {
					return nil, nil, nil, parseLuaDenyError(reason, slice, now)
				}
				meta := parseLuaAllowMeta(slice)

				gKeys := globalAcquireKeys(nowMin)
				rollbackOrg := func() {
					rbKeys := rollbackKeys(keys)
					rbArgv := []any{
						estimatedTokens, slotID,
						idCtx.TeamRPMLimit, idCtx.TeamTPMLimit, idCtx.TeamMaxConcurrent,
						idCtx.UserRPMLimit, idCtx.UserTPMLimit, idCtx.UserMaxConcurrent,
						idCtx.OrgRPMLimit, idCtx.OrgTPMLimit, idCtx.OrgMaxConcurrent,
					}
					_, _ = l.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
						rCtx, cancel := l.withRedisTimeout(context.Background())
						defer cancel()
						return l.rollbackScr.Run(rCtx, rdb, rbKeys, rbArgv...).Result()
					})
				}
				if hasGlobal {
					gRes, gErr := l.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
						rCtx, cancel := l.withRedisTimeout(ctx)
						defer cancel()
						return l.checkGlobalScript.Run(rCtx, rdb, gKeys, gRPM, gTPM, gConc, estimatedTokens, l.windowSec*2, l.concTTLSec, slotID).Slice()
					})
					if gErr != nil {
						rollbackOrg()
						if fallbackLocal {
							return l.acquireLocal(idCtx, estimatedTokens, reserveMicros, slotID, nowMin, gRPM, gTPM, gConc)
						}
						return nil, nil, nil, limiterUnavailableError()
					}
					if gSlice, ok := gRes.([]any); ok && len(gSlice) >= 2 {
						gAllowed, _ := gSlice[0].(int64)
						gReason, _ := gSlice[1].(string)
						if gAllowed == 0 {
							rollbackOrg()
							return nil, nil, nil, parseLuaDenyError(gReason, gSlice, now)
						}
						meta = MergeRateLimitMetadata(meta, parseLuaAllowMeta(gSlice))
					} else {
						rollbackOrg()
						if fallbackLocal {
							return l.acquireLocal(idCtx, estimatedTokens, reserveMicros, slotID, nowMin, gRPM, gTPM, gConc)
						}
						return nil, nil, nil, limiterUnavailableError()
					}
				}

				var settledOrRolledBack sync.Once
				rollbackAll := func() {
					settledOrRolledBack.Do(func() {
						rollbackOrg()
						if hasGlobal {
							_, _ = l.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
								rCtx, cancel := l.withRedisTimeout(context.Background())
								defer cancel()
								return l.rollbackGlobalScr.Run(rCtx, rdb, gKeys, gRPM, gTPM, gConc, estimatedTokens, slotID).Result()
							})
						}
					})
				}
				return func(actualTokens int, actualCostMicros int64) {
					settledOrRolledBack.Do(func() {
						delta := actualTokens - estimatedTokens
						resKeys := reconcileKeys(keys)
						settle := []any{delta, l.windowSec * 2, slotID, actualCostMicros, reserveMicros}
						if actualTokens < 0 {
							settle[3] = int64(-1)
						} else if reserveMicros > 0 {
							// Successful budgeted requests settle the reservation with their SpendEvent,
							// which atomically swaps reserved cost for actual spend.
							settle[3] = int64(-2)
						}
						_, _ = l.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
							rCtx, cancel := l.withRedisTimeout(context.Background())
							defer cancel()
							return l.reconcileScr.Run(rCtx, rdb, resKeys, settle...).Result()
						})
						if hasGlobal {
							_, _ = l.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
								rCtx, cancel := l.withRedisTimeout(context.Background())
								defer cancel()
								return l.reconcileGlobalScr.Run(rCtx, rdb, []string{gKeys[2], gKeys[1]}, delta, l.windowSec*2, gTPM, gConc, slotID).Result()
							})
						}
					})
				}, rollbackAll, meta, nil
			}
		}
	}

	if fallbackLocal {
		return l.acquireLocal(idCtx, estimatedTokens, reserveMicros, slotID, nowMin, gRPM, gTPM, gConc)
	}
	if hasConfiguredLimits(idCtx) || hasGlobal {
		return nil, nil, nil, limiterUnavailableError()
	}
	return func(int, int64) {}, func() {}, nil, nil
}

func (l *Limiter) acquireLocal(idCtx *domain.IdentityContext, estimatedTokens int, reserveMicros int64, requestID string, nowMin int64, gRPM, gTPM, gConc int) (func(int, int64), func(), *domain.RateLimitHeaderMetadata, error) {
	l.localMu.Lock()
	defer l.localMu.Unlock()

	if l.localWindowMin != nowMin {
		l.localWindowMin = nowMin
		clear(l.localRPM)
		clear(l.localTPM)
	}

	type budgetScope struct {
		key     string
		maxB    int64
		dbFloor int64
		errCode string
	}
	bScopes := []budgetScope{
		{key: "key:" + idCtx.VirtualKeyID, maxB: idCtx.KeyMaxBudgetMicros, dbFloor: idCtx.KeySpentMicros, errCode: "KEY_BUDGET_EXCEEDED"},
		{key: "team:" + idCtx.TeamID, maxB: idCtx.TeamMaxBudgetMicros, dbFloor: idCtx.TeamSpentMicros, errCode: "TEAM_BUDGET_EXCEEDED"},
		{key: "user:" + idCtx.UserID, maxB: idCtx.UserMaxBudgetMicros, dbFloor: idCtx.UserSpentMicros, errCode: "USER_BUDGET_EXCEEDED"},
		{key: "org:" + idCtx.OrgID, maxB: idCtx.OrgMaxBudgetMicros, dbFloor: idCtx.OrgSpentMicros, errCode: "ORG_BUDGET_EXCEEDED"},
	}
	for _, bs := range bScopes {
		if bs.dbFloor > l.localSpent[bs.key] {
			l.localSpent[bs.key] = bs.dbFloor
		}
		if bs.maxB > 0 {
			if reserveMicros <= 0 || requestID == "" {
				return nil, nil, nil, toQuotaError("BUDGET_ESTIMATE_REQUIRED")
			}
			resMap := l.localReservations[bs.key]
			if resMap != nil {
				if _, exists := resMap[requestID]; exists {
					return nil, nil, nil, toQuotaError("BUDGET_RESERVATION_CONFLICT")
				}
			}
			var reserved int64
			for _, amt := range resMap {
				reserved += amt
			}
			if l.localSpent[bs.key]+reserved+reserveMicros > bs.maxB {
				return nil, nil, nil, toQuotaError(bs.errCode)
			}
		}
	}

	type quotaCheck struct {
		bucket  map[string]int
		key     string
		delta   int
		limit   int
		errCode string
	}
	checks := []quotaCheck{
		{l.localRPM, "key:" + idCtx.VirtualKeyID, 1, idCtx.KeyRPMLimit, "KEY_RPM_EXCEEDED"},
		{l.localTPM, "key:" + idCtx.VirtualKeyID, estimatedTokens, idCtx.KeyTPMLimit, "KEY_TPM_EXCEEDED"},
		{l.localConc, "key:" + idCtx.VirtualKeyID, 1, idCtx.KeyMaxConcurrent, "KEY_CONCURRENCY_EXCEEDED"},
		{l.localRPM, "team:" + idCtx.TeamID, 1, idCtx.TeamRPMLimit, "TEAM_RPM_EXCEEDED"},
		{l.localTPM, "team:" + idCtx.TeamID, estimatedTokens, idCtx.TeamTPMLimit, "TEAM_TPM_EXCEEDED"},
		{l.localConc, "team:" + idCtx.TeamID, 1, idCtx.TeamMaxConcurrent, "TEAM_CONCURRENCY_EXCEEDED"},
		{l.localRPM, "user:" + idCtx.UserID, 1, idCtx.UserRPMLimit, "USER_RPM_EXCEEDED"},
		{l.localTPM, "user:" + idCtx.UserID, estimatedTokens, idCtx.UserTPMLimit, "USER_TPM_EXCEEDED"},
		{l.localConc, "user:" + idCtx.UserID, 1, idCtx.UserMaxConcurrent, "USER_CONCURRENCY_EXCEEDED"},
		{l.localRPM, "org:" + idCtx.OrgID, 1, idCtx.OrgRPMLimit, "ORG_RPM_EXCEEDED"},
		{l.localTPM, "org:" + idCtx.OrgID, estimatedTokens, idCtx.OrgTPMLimit, "ORG_TPM_EXCEEDED"},
		{l.localConc, "org:" + idCtx.OrgID, 1, idCtx.OrgMaxConcurrent, "ORG_CONCURRENCY_EXCEEDED"},
		{l.localRPM, "global", 1, gRPM, "GLOBAL_RPM_EXCEEDED"},
		{l.localTPM, "global", estimatedTokens, gTPM, "GLOBAL_TPM_EXCEEDED"},
		{l.localConc, "global", 1, gConc, "GLOBAL_CONCURRENCY_EXCEEDED"},
	}
	now := l.nowUTC()
	retryMin := int(60 - (now.Unix() % 60))
	if retryMin <= 0 {
		retryMin = 60
	}
	for _, qc := range checks {
		if qc.limit > 0 && qc.bucket[qc.key]+qc.delta > qc.limit {
			return nil, nil, nil, buildQuotaDenyError(qc.errCode, int64(qc.bucket[qc.key]), int64(qc.limit), int64(retryMin), now)
		}
	}

	l.localRPM["key:"+idCtx.VirtualKeyID]++
	l.localTPM["key:"+idCtx.VirtualKeyID] += estimatedTokens
	l.localConc["key:"+idCtx.VirtualKeyID]++
	if idCtx.TeamRPMLimit > 0 {
		l.localRPM["team:"+idCtx.TeamID]++
	}
	if idCtx.TeamTPMLimit > 0 {
		l.localTPM["team:"+idCtx.TeamID] += estimatedTokens
	}
	if idCtx.TeamMaxConcurrent > 0 {
		l.localConc["team:"+idCtx.TeamID]++
	}
	if idCtx.UserRPMLimit > 0 {
		l.localRPM["user:"+idCtx.UserID]++
	}
	if idCtx.UserTPMLimit > 0 {
		l.localTPM["user:"+idCtx.UserID] += estimatedTokens
	}
	if idCtx.UserMaxConcurrent > 0 {
		l.localConc["user:"+idCtx.UserID]++
	}
	if idCtx.OrgRPMLimit > 0 {
		l.localRPM["org:"+idCtx.OrgID]++
	}
	if idCtx.OrgTPMLimit > 0 {
		l.localTPM["org:"+idCtx.OrgID] += estimatedTokens
	}
	if idCtx.OrgMaxConcurrent > 0 {
		l.localConc["org:"+idCtx.OrgID]++
	}
	if gRPM > 0 {
		l.localRPM["global"]++
	}
	if gTPM > 0 {
		l.localTPM["global"] += estimatedTokens
	}
	if gConc > 0 {
		l.localConc["global"]++
	}

	var meta domain.RateLimitHeaderMetadata
	for _, qc := range checks {
		if qc.limit <= 0 {
			continue
		}
		rem := qc.limit - qc.bucket[qc.key]
		if rem < 0 {
			rem = 0
		}
		if strings.HasSuffix(qc.errCode, "_RPM_EXCEEDED") {
			if meta.LimitRequests == 0 || rem < meta.RemainingRequests {
				meta.LimitRequests = qc.limit
				meta.RemainingRequests = rem
				meta.ResetRequestsSeconds = retryMin
			}
		} else if strings.HasSuffix(qc.errCode, "_TPM_EXCEEDED") {
			if meta.LimitTokens == 0 || rem < meta.RemainingTokens {
				meta.LimitTokens = qc.limit
				meta.RemainingTokens = rem
				meta.ResetTokensSeconds = retryMin
			}
		}
	}

	if reserveMicros > 0 && requestID != "" {
		for _, bs := range bScopes {
			if bs.maxB > 0 {
				if l.localReservations[bs.key] == nil {
					l.localReservations[bs.key] = make(map[string]int64)
				}
				l.localReservations[bs.key][requestID] = reserveMicros
			}
		}
	}

	var once sync.Once
	rollbackLocal := func() {
		once.Do(func() {
			l.localMu.Lock()
			defer l.localMu.Unlock()

			decrInt := func(m map[string]int, k string, delta int) {
				if m[k] >= delta {
					m[k] -= delta
				} else {
					m[k] = 0
				}
			}
			decrInt(l.localConc, "key:"+idCtx.VirtualKeyID, 1)
			if idCtx.TeamMaxConcurrent > 0 {
				decrInt(l.localConc, "team:"+idCtx.TeamID, 1)
			}
			if idCtx.UserMaxConcurrent > 0 {
				decrInt(l.localConc, "user:"+idCtx.UserID, 1)
			}
			if idCtx.OrgMaxConcurrent > 0 {
				decrInt(l.localConc, "org:"+idCtx.OrgID, 1)
			}
			if gConc > 0 {
				decrInt(l.localConc, "global", 1)
			}

			if l.localWindowMin == nowMin {
				decrInt(l.localRPM, "key:"+idCtx.VirtualKeyID, 1)
				decrInt(l.localTPM, "key:"+idCtx.VirtualKeyID, estimatedTokens)
				if idCtx.TeamRPMLimit > 0 {
					decrInt(l.localRPM, "team:"+idCtx.TeamID, 1)
				}
				if idCtx.TeamTPMLimit > 0 {
					decrInt(l.localTPM, "team:"+idCtx.TeamID, estimatedTokens)
				}
				if idCtx.UserRPMLimit > 0 {
					decrInt(l.localRPM, "user:"+idCtx.UserID, 1)
				}
				if idCtx.UserTPMLimit > 0 {
					decrInt(l.localTPM, "user:"+idCtx.UserID, estimatedTokens)
				}
				if idCtx.OrgRPMLimit > 0 {
					decrInt(l.localRPM, "org:"+idCtx.OrgID, 1)
				}
				if idCtx.OrgTPMLimit > 0 {
					decrInt(l.localTPM, "org:"+idCtx.OrgID, estimatedTokens)
				}
				if gRPM > 0 {
					decrInt(l.localRPM, "global", 1)
				}
				if gTPM > 0 {
					decrInt(l.localTPM, "global", estimatedTokens)
				}
			}

			if requestID != "" {
				for _, bs := range bScopes {
					if resMap := l.localReservations[bs.key]; resMap != nil {
						delete(resMap, requestID)
					}
				}
			}
		})
	}

	return func(actualTokens int, actualCostMicros int64) {
		once.Do(func() {
			l.localMu.Lock()
			defer l.localMu.Unlock()

			for _, ck := range []string{
				"key:" + idCtx.VirtualKeyID,
				"team:" + idCtx.TeamID,
				"user:" + idCtx.UserID,
				"org:" + idCtx.OrgID,
				"global",
			} {
				if l.localConc[ck] > 0 {
					l.localConc[ck]--
				}
			}

			if l.localWindowMin == nowMin && actualTokens >= 0 {
				delta := actualTokens - estimatedTokens
				for _, tk := range []string{
					"key:" + idCtx.VirtualKeyID,
					"team:" + idCtx.TeamID,
					"user:" + idCtx.UserID,
					"org:" + idCtx.OrgID,
					"global",
				} {
					if _, ok := l.localTPM[tk]; ok {
						v := l.localTPM[tk] + delta
						if v < 0 {
							v = 0
						}
						l.localTPM[tk] = v
					}
				}
			}

			if requestID != "" {
				for _, bs := range bScopes {
					if resMap := l.localReservations[bs.key]; resMap != nil {
						delete(resMap, requestID)
					}
					if actualTokens >= 0 && actualCostMicros > 0 {
						l.localSpent[bs.key] += actualCostMicros
					}
				}
			}
		})
	}, rollbackLocal, &meta, nil
}

func hasConfiguredLimits(idCtx *domain.IdentityContext) bool {
	return idCtx != nil && (idCtx.KeyRPMLimit > 0 || idCtx.KeyTPMLimit > 0 || idCtx.KeyMaxConcurrent > 0 || idCtx.KeyMaxBudgetMicros > 0 ||
		idCtx.TeamRPMLimit > 0 || idCtx.TeamTPMLimit > 0 || idCtx.TeamMaxConcurrent > 0 || idCtx.TeamMaxBudgetMicros > 0 ||
		idCtx.UserRPMLimit > 0 || idCtx.UserTPMLimit > 0 || idCtx.UserMaxConcurrent > 0 || idCtx.UserMaxBudgetMicros > 0 ||
		idCtx.OrgRPMLimit > 0 || idCtx.OrgTPMLimit > 0 || idCtx.OrgMaxConcurrent > 0 || idCtx.OrgMaxBudgetMicros > 0)
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
		rCtx, cancel := l.withRedisTimeout(ctx)
		defer cancel()
		return l.spendScr.Run(rCtx, rdb, keys, argv...).Result()
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
		rCtx, cancel := l.withRedisTimeout(ctx)
		defer cancel()
		if err := l.spendScr.Load(rCtx, rdb).Err(); err != nil {
			return nil, err
		}
		cmds := make([]*redis.Cmd, len(events))
		_, pipeErr := rdb.Pipelined(rCtx, func(pipe redis.Pipeliner) error {
			for i, ev := range events {
				if ev.CostMicros <= 0 && ev.RequestID == "" {
					continue
				}
				keys, argv := buildSpendEventArgs(ev)
				cmds[i] = l.spendScr.EvalSha(rCtx, pipe, keys, argv...)
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
					errs[i] = l.spendScr.Run(rCtx, rdb, keys, argv...).Err()
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
		rCtx, cancel := l.withRedisTimeout(ctx)
		defer cancel()
		return l.renewScr.Run(rCtx, rdb, keys, requestID, ttlSec).Result()
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
			if _, err := func() (any, error) {
				rCtx, cancel := l.withRedisTimeout(ctx)
				defer cancel()
				return l.resetBudgetScr.Run(rCtx, rdb, []string{spendKey, markerKey}, event.ID, 7776000).Result()
			}(); err != nil {
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

// MergeRateLimitMetadata combines two RateLimitHeaderMetadata values, retaining the tightest
// remaining request and token windows across multiple quota passes.
func MergeRateLimitMetadata(a, b *domain.RateLimitHeaderMetadata) *domain.RateLimitHeaderMetadata {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	out := *a
	if b.LimitRequests > 0 && (out.LimitRequests == 0 || b.RemainingRequests < out.RemainingRequests) {
		out.LimitRequests = b.LimitRequests
		out.RemainingRequests = b.RemainingRequests
		out.ResetRequestsSeconds = b.ResetRequestsSeconds
	}
	if b.LimitTokens > 0 && (out.LimitTokens == 0 || b.RemainingTokens < out.RemainingTokens) {
		out.LimitTokens = b.LimitTokens
		out.RemainingTokens = b.RemainingTokens
		out.ResetTokensSeconds = b.ResetTokensSeconds
	}
	return &out
}

// ClearEntitySpend directly clears Redis and local live spend counters when an operator resets spend.
func (l *Limiter) ClearEntitySpend(ctx context.Context, scope storage.EntitySpendScope, orgID, entityID, secondaryID string) error {
	if l == nil || orgID == "" || entityID == "" {
		return nil
	}
	tag := orgHashTag(orgID)
	var keys []string
	switch scope {
	case storage.EntitySpendScopeKey:
		keys = []string{
			fmt.Sprintf("gw:spend:%s:key:%s", tag, entityID),
			fmt.Sprintf("gw:dq:%s:spend:key:%s", tag, entityID),
		}
		l.localMu.Lock()
		delete(l.localSpent, "key:"+entityID)
		delete(l.localDescSpent, tag+":key:"+entityID)
		l.localMu.Unlock()
	case storage.EntitySpendScopeTeamMember:
		scopeID := entityID + ":" + secondaryID
		keys = []string{
			fmt.Sprintf("gw:dq:%s:spend:team_member:%s", tag, scopeID),
		}
		l.localMu.Lock()
		delete(l.localDescSpent, tag+":team_member:"+scopeID)
		l.localMu.Unlock()
	default:
		return fmt.Errorf("unsupported spend scope %q", scope)
	}
	if len(keys) == 0 || l.redis == nil || l.redis.Client() == nil {
		return nil
	}
	_, err := l.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
		rCtx, cancel := l.withRedisTimeout(ctx)
		defer cancel()
		return rdb.Del(rCtx, keys...).Result()
	})
	return err
}

// MarkUpstream429Throttle sets a brief org/key-scoped soft throttle hint when upstream providers return 429.
func (l *Limiter) MarkUpstream429Throttle(ctx context.Context, orgID, keyID string, cooldown time.Duration) {
	if l == nil || l.redis == nil || l.redis.Client() == nil || orgID == "" || keyID == "" {
		return
	}
	if cooldown <= 0 {
		cooldown = 2 * time.Second
	}
	if cooldown > 15*time.Second {
		cooldown = 15 * time.Second
	}
	k := fmt.Sprintf("gw:rl:%s:dyn_throttle:%s", orgHashTag(orgID), keyID)
	_, _ = l.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
		rCtx, cancel := l.withRedisTimeout(ctx)
		defer cancel()
		return rdb.Set(rCtx, k, "1", cooldown).Result()
	})
}

// CheckUpstream429Throttle returns (retryAfterSec, true) if the key is temporarily in dynamic 429 cooldown.
func (l *Limiter) CheckUpstream429Throttle(ctx context.Context, orgID, keyID string) (int, bool) {
	if l == nil || l.redis == nil || l.redis.Client() == nil || orgID == "" || keyID == "" {
		return 0, false
	}
	k := fmt.Sprintf("gw:rl:%s:dyn_throttle:%s", orgHashTag(orgID), keyID)
	res, err := l.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
		rCtx, cancel := l.withRedisTimeout(ctx)
		defer cancel()
		return rdb.TTL(rCtx, k).Result()
	})
	if err != nil {
		return 0, false
	}
	ttl, ok := res.(time.Duration)
	if !ok || ttl <= 0 {
		return 0, false
	}
	sec := int(ttl.Seconds())
	if sec <= 0 {
		sec = 1
	}
	return sec, true
}

func parseLuaAllowMeta(slice []any) *domain.RateLimitHeaderMetadata {
	if len(slice) < 8 {
		return nil
	}
	limReq, _ := slice[2].(int64)
	remReq, _ := slice[3].(int64)
	resReq, _ := slice[4].(int64)
	limTok, _ := slice[5].(int64)
	remTok, _ := slice[6].(int64)
	resTok, _ := slice[7].(int64)
	if limReq <= 0 && limTok <= 0 {
		return nil
	}
	return &domain.RateLimitHeaderMetadata{
		LimitRequests:        int(limReq),
		RemainingRequests:    int(remReq),
		ResetRequestsSeconds: int(resReq),
		LimitTokens:          int(limTok),
		RemainingTokens:      int(remTok),
		ResetTokensSeconds:   int(resTok),
	}
}

func parseLuaDenyError(code string, slice []any, now time.Time) *domain.GatewayError {
	var cur, lim, retryAfter int64
	if len(slice) >= 3 {
		cur, _ = slice[2].(int64)
	}
	if len(slice) >= 4 {
		lim, _ = slice[3].(int64)
	}
	if len(slice) >= 5 {
		retryAfter, _ = slice[4].(int64)
	}
	return buildQuotaDenyError(code, cur, lim, retryAfter, now)
}

func buildQuotaDenyError(code string, current, limit, retryAfter int64, now time.Time) *domain.GatewayError {
	gwErr := toQuotaError(code)
	if retryAfter > 0 {
		gwErr.RetryAfterSec = int(retryAfter)
	}
	if code == "BUDGET_ESTIMATE_REQUIRED" {
		return gwErr
	}
	scope, limitType := parseScopeAndLimitType(code)
	resetSec := gwErr.RetryAfterSec
	meta := &domain.RateLimitHeaderMetadata{
		Scope:     scope,
		LimitType: limitType,
		ResetAt:   now.UTC().Add(time.Duration(resetSec) * time.Second).Format(time.RFC3339),
	}
	rem := int(limit - current)
	if rem < 0 {
		rem = 0
	}
	switch limitType {
	case "rpm", "rpd":
		meta.LimitRequests = int(limit)
		meta.RemainingRequests = rem
		meta.ResetRequestsSeconds = resetSec
	case "tpm", "itpm", "otpm", "tpd":
		meta.LimitTokens = int(limit)
		meta.RemainingTokens = rem
		meta.ResetTokensSeconds = resetSec
	}
	gwErr.RateLimitMeta = meta
	return gwErr
}

func parseScopeAndLimitType(code string) (string, string) {
	upper := strings.ToUpper(strings.TrimSpace(code))
	suffixes := []struct {
		suffix string
		typ    string
	}{
		{"_RPM_EXCEEDED", "rpm"},
		{"_RPD_EXCEEDED", "rpd"},
		{"_TPM_EXCEEDED", "tpm"},
		{"_ITPM_EXCEEDED", "itpm"},
		{"_OTPM_EXCEEDED", "otpm"},
		{"_TPD_EXCEEDED", "tpd"},
		{"_CONCURRENCY_EXCEEDED", "concurrency"},
		{"_ITERATIONS_EXCEEDED", "iterations"},
		{"_BUDGET_EXCEEDED", "budget"},
	}
	for _, s := range suffixes {
		if strings.HasSuffix(upper, s.suffix) {
			scope := strings.ToLower(strings.TrimSuffix(upper, s.suffix))
			return scope, s.typ
		}
	}
	return "", ""
}
