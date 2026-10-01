package ratelimit

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/redis/go-redis/v9"
)

//go:embed scripts/check_descriptors.lua
var checkDescriptorsLua string

//go:embed scripts/reconcile_descriptors.lua
var reconcileDescriptorsLua string

//go:embed scripts/renew_descriptors.lua
var renewDescriptorsLua string

const (
	defaultDescriptorTPDTTLSec         = 86400 * 2
	defaultDescriptorIterationTTLSec   = 3600
	defaultDescriptorReservationTTLSec = 3600
	rolling24hWindowMs                 = int64(86_400_000)
)

type localIterCounter struct {
	count     int
	expiresAt time.Time
}

type localReservationEntry struct {
	amount    int64
	expiresAt time.Time
}

type localRollingSpendEntry struct {
	id     string
	tsMs   int64
	amount int64
}

// descriptorKeySet holds all Redis Cluster slot-aligned keys for a single descriptor.
type descriptorKeySet struct {
	rpm        string
	rpd        string
	tpm        string
	itpm       string
	otpm       string
	tpd        string
	conc       string
	iter       string
	spend      string
	resZSet    string
	resSum     string
	resAmounts string
	r24hZSet   string
}

func descriptorEntityKey(d domain.RateLimitDescriptor) string {
	scope := strings.ToLower(strings.TrimSpace(string(d.ScopeType)))
	scopeID := strings.TrimSpace(d.ScopeID)
	modelPattern := strings.TrimSpace(d.ModelPattern)
	base := fmt.Sprintf("%s:%s", scope, scopeID)
	if modelPattern != "" && modelPattern != "*" {
		base = fmt.Sprintf("%s:model:%s", base, modelPattern)
	}
	if wt := strings.ToLower(strings.TrimSpace(string(d.WindowType))); wt != "" {
		base = fmt.Sprintf("%s:win:%s", base, wt)
	}
	return base
}

func buildDescriptorKeySet(orgID string, d domain.RateLimitDescriptor, nowMin int64, utcDay string) descriptorKeySet {
	tag := orgHashTag(orgID)
	entity := descriptorEntityKey(d)
	resBase := fmt.Sprintf("gw:dq:%s:res:%s", tag, entity)
	resZ, resS, resA := reservationTuple(resBase)
	return descriptorKeySet{
		rpm:        fmt.Sprintf("gw:dq:%s:rpm:%s:%d", tag, entity, nowMin),
		rpd:        fmt.Sprintf("gw:dq:%s:rpd:%s:%s", tag, entity, utcDay),
		tpm:        fmt.Sprintf("gw:dq:%s:tpm:%s:%d", tag, entity, nowMin),
		itpm:       fmt.Sprintf("gw:dq:%s:itpm:%s:%d", tag, entity, nowMin),
		otpm:       fmt.Sprintf("gw:dq:%s:otpm:%s:%d", tag, entity, nowMin),
		tpd:        fmt.Sprintf("gw:dq:%s:tpd:%s:%s", tag, entity, utcDay),
		conc:       fmt.Sprintf("gw:dq:%s:zconc:%s", tag, entity),
		iter:       fmt.Sprintf("gw:dq:%s:iter:%s", tag, entity),
		spend:      fmt.Sprintf("gw:dq:%s:spend:%s", tag, entity),
		resZSet:    resZ,
		resSum:     resS,
		resAmounts: resA,
		r24hZSet:   fmt.Sprintf("gw:dq:%s:r24h:%s", tag, entity),
	}
}

func descriptorCheckKeys(orgID string, descriptors []domain.RateLimitDescriptor, now time.Time) []string {
	nowUTC := now.UTC()
	nowMin := nowUTC.Unix() / 60
	utcDay := nowUTC.Format("20060102")
	keys := make([]string, 0, len(descriptors)*13)
	for _, d := range descriptors {
		ks := buildDescriptorKeySet(orgID, d, nowMin, utcDay)
		keys = append(keys,
			ks.rpm,
			ks.tpm,
			ks.itpm,
			ks.otpm,
			ks.tpd,
			ks.conc,
			ks.iter,
			ks.spend,
			ks.resZSet,
			ks.resSum,
			ks.resAmounts,
			ks.r24hZSet,
			ks.rpd,
		)
	}
	return keys
}

func descriptorReconcileKeys(orgID string, descriptors []domain.RateLimitDescriptor, now time.Time) []string {
	nowUTC := now.UTC()
	nowMin := nowUTC.Unix() / 60
	utcDay := nowUTC.Format("20060102")
	keys := make([]string, 0, len(descriptors)*10)
	for _, d := range descriptors {
		ks := buildDescriptorKeySet(orgID, d, nowMin, utcDay)
		keys = append(keys,
			ks.tpm,
			ks.itpm,
			ks.otpm,
			ks.tpd,
			ks.conc,
			ks.spend,
			ks.resZSet,
			ks.resSum,
			ks.resAmounts,
			ks.r24hZSet,
		)
	}
	return keys
}

func normalizeDescriptors(orgID string, descriptors []domain.RateLimitDescriptor) ([]domain.RateLimitDescriptor, error) {
	if len(descriptors) == 0 {
		return nil, nil
	}
	active := make([]domain.RateLimitDescriptor, 0, len(descriptors))
	for i, d := range descriptors {
		if !d.HasLimits() {
			continue
		}
		d.ScopeType = domain.QuotaScopeType(strings.ToLower(strings.TrimSpace(string(d.ScopeType))))
		if d.ScopeType == "" {
			return nil, fmt.Errorf("descriptor[%d] scope_type is required", i)
		}
		d.ScopeID = strings.TrimSpace(d.ScopeID)
		if d.ScopeID == "" && d.ScopeType == domain.QuotaScopeOrg && strings.TrimSpace(orgID) != "" {
			d.ScopeID = strings.TrimSpace(orgID)
		}
		if d.ScopeID == "" {
			return nil, fmt.Errorf("descriptor[%d] scope_id is required", i)
		}
		d.ModelPattern = strings.TrimSpace(d.ModelPattern)
		if d.ModelPattern == "" {
			d.ModelPattern = "*"
		}
		active = append(active, d)
	}
	return active, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func (l *Limiter) nowUTC() time.Time {
	if l == nil {
		return time.Now().UTC()
	}
	l.mu.RLock()
	fn := l.nowFunc
	l.mu.RUnlock()
	if fn != nil {
		return fn().UTC()
	}
	return time.Now().UTC()
}

func (l *Limiter) rollingWindowLoader() RollingWindowSpendLoader {
	if l == nil {
		return nil
	}
	l.mu.RLock()
	loader := l.rollingLoader
	l.mu.RUnlock()
	return loader
}

func quotaPolicyUnavailableError() *domain.GatewayError {
	return &domain.GatewayError{
		StatusCode:    http.StatusServiceUnavailable,
		Type:          domain.ErrorTypeRateLimit,
		Code:          "quota_policy_unavailable",
		Message:       "Unable to evaluate configured quota policies",
		RetryAfterSec: 5,
	}
}

func buildCheckDescriptorArgv(
	estInput int,
	estOutput int,
	reserveMicros int64,
	reqID string,
	windowTTL int,
	concTTL int,
	now time.Time,
	active []domain.RateLimitDescriptor,
) []any {
	nowMs := now.UTC().UnixMilli()
	argv := make([]any, 0, 10+len(active)*14)
	argv = append(argv,
		len(active),
		estInput,
		estOutput,
		reserveMicros,
		reqID,
		windowTTL,
		defaultDescriptorTPDTTLSec,
		concTTL,
		defaultDescriptorReservationTTLSec,
		nowMs,
	)
	var trailingInit []any
	for _, d := range active {
		isRolling := d.WindowType == domain.BudgetWindowRolling24h
		hasInit := isRolling && d.RollingHistoryLoaded
		argv = append(argv,
			strings.ToUpper(string(d.ScopeType)),
			d.RPMLimit,
			d.TPMLimit,
			d.ITPMLimit,
			d.OTPMLimit,
			d.TPDLimit,
			d.MaxConcurrent,
			d.MaxIterations,
			descriptorIterTTL(d),
			d.MaxBudgetMicros,
			d.SpentFloorMicros,
			boolToInt(isRolling),
			boolToInt(hasInit),
			d.RPDLimit,
		)
		if hasInit {
			trailingInit = append(trailingInit, len(d.RollingEntries))
			for _, entry := range d.RollingEntries {
				eid := entry.ID
				if eid == "" {
					eid = "db"
				}
				trailingInit = append(trailingInit, eid, entry.TimestampMs, entry.AmountMicros)
			}
		}
	}
	if len(trailingInit) > 0 {
		argv = append(argv, trailingInit...)
	}
	return argv
}

func populateColdRollingDescriptors(
	ctx context.Context,
	loader RollingWindowSpendLoader,
	orgID string,
	descriptors []domain.RateLimitDescriptor,
	indices []int,
	now time.Time,
) error {
	nowMs := now.UTC().UnixMilli()
	for _, idx := range indices {
		d := &descriptors[idx]
		if d.WindowType != domain.BudgetWindowRolling24h || d.RollingHistoryLoaded {
			continue
		}
		if loader == nil {
			if d.SpentFloorMicros > 0 {
				d.RollingEntries = []domain.RollingSpendEntry{{
					ID:           "seed",
					TimestampMs:  nowMs,
					AmountMicros: d.SpentFloorMicros,
				}}
			}
			d.RollingHistoryLoaded = true
			continue
		}
		entries, err := loader(ctx, orgID, *d, now)
		if err != nil {
			return quotaPolicyUnavailableError()
		}
		d.RollingEntries = entries
		d.RollingHistoryLoaded = true
	}
	return nil
}

func descriptorIterTTL(d domain.RateLimitDescriptor) int {
	if d.WindowTTLSec > 0 {
		return d.WindowTTLSec
	}
	return defaultDescriptorIterationTTLSec
}

func toDescriptorQuotaError(code string, current, limit, retryAfter int64) *domain.GatewayError {
	gwErr := buildQuotaDenyError(code, current, limit, retryAfter, time.Now().UTC())
	if code != "BUDGET_ESTIMATE_REQUIRED" && limit > 0 {
		if strings.Contains(code, "BUDGET") {
			gwErr.Message = fmt.Sprintf("Configured financial spend budget exceeded (%s: current=%d, limit=%d)", code, current, limit)
		} else {
			gwErr.Message = fmt.Sprintf("Rate limit or quota exceeded (%s: current=%d, limit=%d)", code, current, limit)
		}
	}
	return gwErr
}

// AcquireDescriptors atomically evaluates all configured quota descriptors for an
// organization in a single all-or-nothing operation.
func (l *Limiter) AcquireDescriptors(
	ctx context.Context,
	orgID string,
	reqID string,
	estInput int,
	estOutput int,
	reserveMicros int64,
	descriptors []domain.RateLimitDescriptor,
) (func(actualInput, actualOutput int, actualCostMicros int64), error) {
	return l.AcquireDescriptorsWithSettlementID(ctx, orgID, reqID, "", estInput, estOutput, reserveMicros, descriptors)
}

// AcquireDescriptorsWithSettlementID shares a spend event ID with durable quota history.
func (l *Limiter) AcquireDescriptorsWithSettlementID(
	ctx context.Context,
	orgID string,
	reqID string,
	settlementID string,
	estInput int,
	estOutput int,
	reserveMicros int64,
	descriptors []domain.RateLimitDescriptor,
) (func(actualInput, actualOutput int, actualCostMicros int64), error) {
	rel, _, err := l.AcquireDescriptorsWithSettlementIDAndMeta(ctx, orgID, reqID, settlementID, estInput, estOutput, reserveMicros, descriptors)
	return rel, err
}

// AcquireDescriptorsWithMeta behaves like AcquireDescriptors and also returns tightest-scope
// rate-limit telemetry headers for emission on 2xx responses.
func (l *Limiter) AcquireDescriptorsWithMeta(
	ctx context.Context,
	orgID string,
	reqID string,
	estInput int,
	estOutput int,
	reserveMicros int64,
	descriptors []domain.RateLimitDescriptor,
) (func(actualInput, actualOutput int, actualCostMicros int64), *domain.RateLimitHeaderMetadata, error) {
	return l.AcquireDescriptorsWithSettlementIDAndMeta(ctx, orgID, reqID, "", estInput, estOutput, reserveMicros, descriptors)
}

// AcquireDescriptorsWithSettlementIDAndMeta combines shared settlement IDs with 2xx rate-limit header metadata.
func (l *Limiter) AcquireDescriptorsWithSettlementIDAndMeta(
	ctx context.Context,
	orgID string,
	reqID string,
	settlementID string,
	estInput int,
	estOutput int,
	reserveMicros int64,
	descriptors []domain.RateLimitDescriptor,
) (func(actualInput, actualOutput int, actualCostMicros int64), *domain.RateLimitHeaderMetadata, error) {
	noop := func(int, int, int64) {}
	if l == nil {
		return noop, nil, nil
	}
	enabled, fallbackLocal, _, _, _, _ := l.configSnapshot()
	if !enabled {
		return noop, nil, nil
	}
	if reserveMicros < 0 {
		return nil, nil, fmt.Errorf("budget reservation requires a non-negative amount")
	}
	if estInput < 0 {
		estInput = 0
	}
	if estOutput < 0 {
		estOutput = 0
	}

	active, err := normalizeDescriptors(orgID, descriptors)
	if err != nil {
		return nil, nil, err
	}
	if len(active) == 0 {
		return noop, nil, nil
	}

	slotID := reqID
	if slotID == "" && reserveMicros == 0 {
		slotID = uuid.NewString()
	}

	rollingID := "s:" + reqID
	if settlementID != "" {
		rollingID = "db:" + settlementID
	}
	now := l.nowUTC()
	windowTTL := l.windowSec * 2
	if windowTTL <= 0 {
		windowTTL = 120
	}
	concTTL := l.concTTLSec
	if concTTL <= 0 {
		concTTL = 300
	}

	if l.redis != nil && l.redis.Client() != nil {
		keys := descriptorCheckKeys(orgID, active, now)
		// Last key stores a per-attempt admission receipt so Redis retries do not double-admit.
		keys = append(keys, "")
		loader := l.rollingWindowLoader()
		var rollingIndices []int
		for i, d := range active {
			if d.WindowType == domain.BudgetWindowRolling24h && d.MaxBudgetMicros > 0 {
				rollingIndices = append(rollingIndices, i)
			}
		}

		for attempt := 0; attempt < 2; attempt++ {
			keys[len(keys)-1] = "gw:quota:" + orgHashTag(orgID) + ":admission:" + uuid.NewString()
			argv := buildCheckDescriptorArgv(estInput, estOutput, reserveMicros, slotID, windowTTL, concTTL, now, active)

			res, execErr := l.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
				rCtx, cancel := l.withRedisTimeout(ctx)
				defer cancel()
				return l.checkDescriptorsScr.Run(rCtx, rdb, keys, argv...).Slice()
			})
			if execErr != nil {
				break
			}
			slice, ok := res.([]any)
			if !ok || len(slice) < 2 {
				break
			}
			allowed, _ := slice[0].(int64)
			reason, _ := slice[1].(string)
			if allowed == 0 {
				if reason == "ROLLING_WINDOW_COLD" && attempt == 0 && len(rollingIndices) > 0 {
					if loadErr := populateColdRollingDescriptors(ctx, loader, orgID, active, rollingIndices, now); loadErr != nil {
						return nil, nil, loadErr
					}
					continue
				}
				var current, limit, retryAfter int64
				if len(slice) >= 3 {
					current, _ = slice[2].(int64)
				}
				if len(slice) >= 4 {
					limit, _ = slice[3].(int64)
				}
				if len(slice) >= 5 {
					retryAfter, _ = slice[4].(int64)
				}
				return nil, nil, toDescriptorQuotaError(reason, current, limit, retryAfter)
			}
			meta := parseLuaAllowMeta(slice)

			recKeys := descriptorReconcileKeys(orgID, active, now)
			flags := make([]any, 0, len(active)*7)
			for _, d := range active {
				flags = append(flags,
					boolToInt(d.TPMLimit > 0),
					boolToInt(d.ITPMLimit > 0),
					boolToInt(d.OTPMLimit > 0),
					boolToInt(d.TPDLimit > 0),
					boolToInt(d.MaxConcurrent > 0),
					boolToInt(d.MaxBudgetMicros > 0),
					boolToInt(d.WindowType == domain.BudgetWindowRolling24h),
				)
			}

			var once sync.Once
			return func(actualInput, actualOutput int, actualCostMicros int64) {
				once.Do(func() {
					if actualInput < 0 {
						actualInput = 0
					}
					if actualOutput < 0 {
						actualOutput = 0
					}
					inputDelta := actualInput - estInput
					outputDelta := actualOutput - estOutput
					totalDelta := (actualInput + actualOutput) - (estInput + estOutput)

					recArgv := make([]any, 0, 10+len(flags))
					recArgv = append(recArgv,
						len(active),
						inputDelta,
						outputDelta,
						totalDelta,
						windowTTL,
						defaultDescriptorTPDTTLSec,
						slotID,
						actualCostMicros,
						l.nowUTC().UnixMilli(),
						rollingID,
					)
					recArgv = append(recArgv, flags...)

					_, _ = l.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
						rCtx, cancel := l.withRedisTimeout(context.Background())
						defer cancel()
						return l.reconcileDescriptorsScr.Run(rCtx, rdb, recKeys, recArgv...).Result()
					})
				})
			}, meta, nil
		}

		if !fallbackLocal {
			return nil, nil, limiterUnavailableError()
		}
	}

	if !fallbackLocal {
		return nil, nil, limiterUnavailableError()
	}

	return l.acquireDescriptorsLocal(ctx, orgID, reqID, rollingID, estInput, estOutput, reserveMicros, active, now)
}

func (l *Limiter) ensureLocalDescMapsLocked() {
	if l.localDescRPM == nil {
		l.localDescRPM = make(map[string]int)
	}
	if l.localDescTPM == nil {
		l.localDescTPM = make(map[string]int)
	}
	if l.localDescITPM == nil {
		l.localDescITPM = make(map[string]int)
	}
	if l.localDescOTPM == nil {
		l.localDescOTPM = make(map[string]int)
	}
	if l.localDescTPD == nil {
		l.localDescTPD = make(map[string]int64)
	}
	if l.localDescRPD == nil {
		l.localDescRPD = make(map[string]int64)
	}
	if l.localDescConc == nil {
		l.localDescConc = make(map[string]int)
	}
	if l.localDescIter == nil {
		l.localDescIter = make(map[string]localIterCounter)
	}
	if l.localDescSpent == nil {
		l.localDescSpent = make(map[string]int64)
	}
	if l.localDescReservations == nil {
		l.localDescReservations = make(map[string]map[string]localReservationEntry)
	}
	if l.localDescRolling == nil {
		l.localDescRolling = make(map[string]localRollingWindow)
	}
}

type localRollingWindow struct {
	initialized bool
	entries     []localRollingSpendEntry
}

func mergeLocalRollingHistory(entries []localRollingSpendEntry, history []domain.RollingSpendEntry, cutoffMs int64) []localRollingSpendEntry {
	restored := make(map[string]struct{}, len(history))
	merged := make([]localRollingSpendEntry, 0, len(entries)+len(history))
	for _, entry := range history {
		if entry.TimestampMs <= cutoffMs || entry.AmountMicros <= 0 {
			continue
		}
		if _, exists := restored[entry.ID]; !exists {
			restored[entry.ID] = struct{}{}
			merged = append(merged, localRollingSpendEntry{entry.ID, entry.TimestampMs, entry.AmountMicros})
		}
	}
	for _, entry := range entries {
		if _, exists := restored[entry.id]; !exists {
			merged = append(merged, entry)
		}
	}
	return merged
}

func pruneLocalRollingEntries(entries []localRollingSpendEntry, cutoffMs int64) ([]localRollingSpendEntry, int64) {
	if len(entries) == 0 {
		return entries, 0
	}
	pruned := make([]localRollingSpendEntry, 0, len(entries))
	var sum int64
	for _, entry := range entries {
		if entry.tsMs > cutoffMs && entry.amount > 0 {
			pruned = append(pruned, entry)
			sum += entry.amount
		}
	}
	return pruned, sum
}

func (l *Limiter) acquireDescriptorsLocal(
	ctx context.Context,
	orgID string,
	reqID string,
	rollingID string,
	estInput int,
	estOutput int,
	reserveMicros int64,
	descriptors []domain.RateLimitDescriptor,
	now time.Time,
) (func(actualInput, actualOutput int, actualCostMicros int64), *domain.RateLimitHeaderMetadata, error) {
	tag := orgHashTag(orgID)
	localKeys := make([]string, len(descriptors))
	for i, d := range descriptors {
		localKeys[i] = tag + ":" + descriptorEntityKey(d)
	}

	loader := l.rollingWindowLoader()
	var coldIndices []int
	l.localMu.Lock()
	l.ensureLocalDescMapsLocked()
	for i, d := range descriptors {
		if d.MaxBudgetMicros > 0 && d.WindowType == domain.BudgetWindowRolling24h && !d.RollingHistoryLoaded {
			if !l.localDescRolling[localKeys[i]].initialized {
				coldIndices = append(coldIndices, i)
			}
		}
	}
	l.localMu.Unlock()

	if len(coldIndices) > 0 {
		if err := populateColdRollingDescriptors(ctx, loader, orgID, descriptors, coldIndices, now); err != nil {
			return nil, nil, err
		}
	}
	l.localMu.Lock()
	defer l.localMu.Unlock()

	l.ensureLocalDescMapsLocked()

	nowUTC := now.UTC()
	nowMs := nowUTC.UnixMilli()
	cutoffMs := nowMs - rolling24hWindowMs
	nowSec := nowUTC.Unix()
	nowMin := nowSec / 60
	utcDay := nowUTC.Format("20060102")
	estTotal := estInput + estOutput

	retryMin := 60 - (nowSec % 60)
	if retryMin <= 0 {
		retryMin = 60
	}
	retryDay := 86400 - (nowSec % 86400)
	if retryDay <= 0 {
		retryDay = 86400
	}

	if l.localDescWindowMin != nowMin {
		l.localDescWindowMin = nowMin
		clear(l.localDescRPM)
		clear(l.localDescTPM)
		clear(l.localDescITPM)
		clear(l.localDescOTPM)
	}
	if l.localDescDay != utcDay {
		l.localDescDay = utcDay
		clear(l.localDescTPD)
		clear(l.localDescRPD)
	}

	// Phase 1: Pure read-only validation across all descriptors.
	pendingRolling := make(map[string]localRollingWindow)
	pendingRPM := make(map[string]int)
	pendingTPM := make(map[string]int)
	pendingITPM := make(map[string]int)
	pendingOTPM := make(map[string]int)
	pendingTPD := make(map[string]int64)
	pendingRPD := make(map[string]int64)
	pendingConc := make(map[string]int)
	pendingIter := make(map[string]int)
	pendingRes := make(map[string]bool)

	for i, d := range descriptors {
		lk := localKeys[i]
		scope := strings.ToUpper(string(d.ScopeType))

		if d.RPMLimit > 0 {
			cur := l.localDescRPM[lk] + pendingRPM[lk]
			if cur+1 > d.RPMLimit {
				return nil, nil, toDescriptorQuotaError(scope+"_RPM_EXCEEDED", int64(cur), int64(d.RPMLimit), retryMin)
			}
			pendingRPM[lk]++
		}

		if d.TPMLimit > 0 {
			cur := l.localDescTPM[lk] + pendingTPM[lk]
			if cur+estTotal > d.TPMLimit || (estTotal == 0 && cur >= d.TPMLimit) {
				return nil, nil, toDescriptorQuotaError(scope+"_TPM_EXCEEDED", int64(cur), int64(d.TPMLimit), retryMin)
			}
			pendingTPM[lk] += estTotal
		}

		if d.ITPMLimit > 0 {
			cur := l.localDescITPM[lk] + pendingITPM[lk]
			if cur+estInput > d.ITPMLimit || (estInput == 0 && cur >= d.ITPMLimit) {
				return nil, nil, toDescriptorQuotaError(scope+"_ITPM_EXCEEDED", int64(cur), int64(d.ITPMLimit), retryMin)
			}
			pendingITPM[lk] += estInput
		}

		if d.OTPMLimit > 0 {
			cur := l.localDescOTPM[lk] + pendingOTPM[lk]
			if cur+estOutput > d.OTPMLimit || (estOutput == 0 && cur >= d.OTPMLimit) {
				return nil, nil, toDescriptorQuotaError(scope+"_OTPM_EXCEEDED", int64(cur), int64(d.OTPMLimit), retryMin)
			}
			pendingOTPM[lk] += estOutput
		}

		if d.TPDLimit > 0 {
			cur := l.localDescTPD[lk] + pendingTPD[lk]
			if cur+int64(estTotal) > d.TPDLimit || (estTotal == 0 && cur >= d.TPDLimit) {
				return nil, nil, toDescriptorQuotaError(scope+"_TPD_EXCEEDED", cur, d.TPDLimit, retryDay)
			}
			pendingTPD[lk] += int64(estTotal)
		}

		if d.RPDLimit > 0 {
			cur := l.localDescRPD[lk] + pendingRPD[lk]
			if cur+1 > d.RPDLimit {
				return nil, nil, toDescriptorQuotaError(scope+"_RPD_EXCEEDED", cur, d.RPDLimit, retryDay)
			}
			pendingRPD[lk]++
		}

		if d.MaxConcurrent > 0 {
			cur := l.localDescConc[lk] + pendingConc[lk]
			if cur+1 > d.MaxConcurrent {
				return nil, nil, toDescriptorQuotaError(scope+"_CONCURRENCY_EXCEEDED", int64(cur), int64(d.MaxConcurrent), 5)
			}
			pendingConc[lk]++
		}

		if d.MaxIterations > 0 {
			var cur int
			retryIter := int64(descriptorIterTTL(d))
			if entry, ok := l.localDescIter[lk]; ok && nowUTC.Before(entry.expiresAt) {
				cur = entry.count
				if rem := int64(entry.expiresAt.Sub(nowUTC).Seconds()); rem > 0 {
					retryIter = rem
				}
			}
			cur += pendingIter[lk]
			if cur+1 > d.MaxIterations {
				return nil, nil, toDescriptorQuotaError(scope+"_ITERATIONS_EXCEEDED", int64(cur), int64(d.MaxIterations), retryIter)
			}
			pendingIter[lk]++
		}

		if d.MaxBudgetMicros > 0 {
			var curSpent int64
			if d.WindowType == domain.BudgetWindowRolling24h {
				window := l.localDescRolling[lk]
				entries := window.entries
				if !window.initialized {
					if !d.RollingHistoryLoaded {
						return nil, nil, quotaPolicyUnavailableError()
					}
					entries = mergeLocalRollingHistory(entries, d.RollingEntries, cutoffMs)
				}
				pruned, sum := pruneLocalRollingEntries(entries, cutoffMs)
				pendingRolling[lk] = localRollingWindow{initialized: true, entries: pruned}
				curSpent = sum
			} else {
				curSpent = l.localDescSpent[lk]
				if d.SpentFloorMicros > curSpent {
					curSpent = d.SpentFloorMicros
				}
			}
			if reserveMicros <= 0 || reqID == "" {
				return nil, nil, toDescriptorQuotaError("BUDGET_ESTIMATE_REQUIRED", curSpent, d.MaxBudgetMicros, 5)
			}
			if pendingRes[lk] {
				return nil, nil, toDescriptorQuotaError("BUDGET_RESERVATION_CONFLICT", curSpent, d.MaxBudgetMicros, 5)
			}
			var activeReserved int64
			if resMap := l.localDescReservations[lk]; resMap != nil {
				for rid, entry := range resMap {
					if !nowUTC.Before(entry.expiresAt) {
						continue
					}
					if rid == reqID {
						return nil, nil, toDescriptorQuotaError("BUDGET_RESERVATION_CONFLICT", curSpent, d.MaxBudgetMicros, 5)
					}
					activeReserved += entry.amount
				}
			}
			if curSpent+activeReserved+reserveMicros > d.MaxBudgetMicros {
				return nil, nil, toDescriptorQuotaError(scope+"_BUDGET_EXCEEDED", curSpent+activeReserved, d.MaxBudgetMicros, 60)
			}
			pendingRes[lk] = true
		}
	}

	// Phase 2: All descriptors admitted; apply mutations atomically under lock.
	var meta domain.RateLimitHeaderMetadata
	resExpiry := nowUTC.Add(defaultDescriptorReservationTTLSec * time.Second)
	for i, d := range descriptors {
		lk := localKeys[i]
		if d.RPMLimit > 0 {
			l.localDescRPM[lk]++
			rem := d.RPMLimit - l.localDescRPM[lk]
			if rem < 0 {
				rem = 0
			}
			if meta.LimitRequests == 0 || rem < meta.RemainingRequests {
				meta.LimitRequests = d.RPMLimit
				meta.RemainingRequests = rem
				meta.ResetRequestsSeconds = int(retryMin)
			}
		}
		if d.TPMLimit > 0 && estTotal > 0 {
			l.localDescTPM[lk] += estTotal
			rem := d.TPMLimit - l.localDescTPM[lk]
			if rem < 0 {
				rem = 0
			}
			if meta.LimitTokens == 0 || rem < meta.RemainingTokens {
				meta.LimitTokens = d.TPMLimit
				meta.RemainingTokens = rem
				meta.ResetTokensSeconds = int(retryMin)
			}
		}
		if d.ITPMLimit > 0 && estInput > 0 {
			l.localDescITPM[lk] += estInput
		}
		if d.OTPMLimit > 0 && estOutput > 0 {
			l.localDescOTPM[lk] += estOutput
		}
		if d.TPDLimit > 0 && estTotal > 0 {
			l.localDescTPD[lk] += int64(estTotal)
		}
		if d.RPDLimit > 0 {
			l.localDescRPD[lk]++
		}
		if d.MaxConcurrent > 0 {
			l.localDescConc[lk]++
		}
		if d.MaxIterations > 0 {
			entry, ok := l.localDescIter[lk]
			if !ok || !nowUTC.Before(entry.expiresAt) {
				entry = localIterCounter{
					count:     0,
					expiresAt: nowUTC.Add(time.Duration(descriptorIterTTL(d)) * time.Second),
				}
			}
			entry.count++
			l.localDescIter[lk] = entry
		}
		if d.MaxBudgetMicros > 0 {
			if d.WindowType == domain.BudgetWindowRolling24h {
				l.localDescRolling[lk] = pendingRolling[lk]
			} else if d.SpentFloorMicros > l.localDescSpent[lk] {
				l.localDescSpent[lk] = d.SpentFloorMicros
			}
			resMap := l.localDescReservations[lk]
			if resMap == nil {
				resMap = make(map[string]localReservationEntry)
				l.localDescReservations[lk] = resMap
			} else {
				for rid, entry := range resMap {
					if !nowUTC.Before(entry.expiresAt) {
						delete(resMap, rid)
					}
				}
			}
			if reserveMicros > 0 && reqID != "" {
				resMap[reqID] = localReservationEntry{
					amount:    reserveMicros,
					expiresAt: resExpiry,
				}
			}
		}
	}

	var once sync.Once
	return func(actualInput, actualOutput int, actualCostMicros int64) {
		once.Do(func() {
			if actualInput < 0 {
				actualInput = 0
			}
			if actualOutput < 0 {
				actualOutput = 0
			}
			inputDelta := actualInput - estInput
			outputDelta := actualOutput - estOutput
			totalDelta := (actualInput + actualOutput) - estTotal

			l.localMu.Lock()
			defer l.localMu.Unlock()

			for i, d := range descriptors {
				lk := localKeys[i]
				if d.MaxConcurrent > 0 && l.localDescConc[lk] > 0 {
					l.localDescConc[lk]--
				}
				if l.localDescWindowMin == nowMin {
					if d.TPMLimit > 0 && totalDelta != 0 {
						v := l.localDescTPM[lk] + totalDelta
						if v < 0 {
							v = 0
						}
						l.localDescTPM[lk] = v
					}
					if d.ITPMLimit > 0 && inputDelta != 0 {
						v := l.localDescITPM[lk] + inputDelta
						if v < 0 {
							v = 0
						}
						l.localDescITPM[lk] = v
					}
					if d.OTPMLimit > 0 && outputDelta != 0 {
						v := l.localDescOTPM[lk] + outputDelta
						if v < 0 {
							v = 0
						}
						l.localDescOTPM[lk] = v
					}
				}
				if l.localDescDay == utcDay && d.TPDLimit > 0 && totalDelta != 0 {
					v := l.localDescTPD[lk] + int64(totalDelta)
					if v < 0 {
						v = 0
					}
					l.localDescTPD[lk] = v
				}
				if d.MaxBudgetMicros > 0 && reqID != "" && actualCostMicros != -2 {
					if resMap := l.localDescReservations[lk]; resMap != nil {
						if _, existed := resMap[reqID]; existed {
							delete(resMap, reqID)
							if actualCostMicros > 0 {
								if d.WindowType == domain.BudgetWindowRolling24h {
									window := l.localDescRolling[lk]
									existing := slices.ContainsFunc(window.entries, func(entry localRollingSpendEntry) bool {
										return strings.HasPrefix(rollingID, "db:") && entry.id == rollingID
									})
									if !existing {
										window.entries = append(window.entries, localRollingSpendEntry{
											id:     rollingID,
											tsMs:   l.nowUTC().UTC().UnixMilli(),
											amount: actualCostMicros,
										})
										l.localDescRolling[lk] = window
									}
								} else {
									l.localDescSpent[lk] += actualCostMicros
								}
							}
						}
					}
				}
			}
		})
	}, &meta, nil
}

// ResetBudgetWindowSpend clears live Redis and local descriptor spend counters
// for expired multi-window budget limits that have been reset in durable storage.
func (l *Limiter) ResetBudgetWindowSpend(ctx context.Context, windows []*domain.BudgetWindowLimit) error {
	if l == nil || len(windows) == 0 {
		return nil
	}
	now := l.nowUTC()
	nowMin := now.Unix() / 60
	utcDay := now.Format("20060102")

	var redisKeys []string
	l.localMu.Lock()
	for _, w := range windows {
		if w == nil || w.OrgID == "" || w.ScopeID == "" || w.WindowType == "" {
			continue
		}
		desc := w.ToDescriptor()
		lk := orgHashTag(w.OrgID) + ":" + descriptorEntityKey(desc)
		delete(l.localDescSpent, lk)
		delete(l.localDescRolling, lk)
		ks := buildDescriptorKeySet(w.OrgID, desc, nowMin, utcDay)
		redisKeys = append(redisKeys, ks.spend, ks.r24hZSet)
	}
	l.localMu.Unlock()

	if len(redisKeys) == 0 || l.redis == nil || l.redis.Client() == nil {
		return nil
	}
	_, err := l.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
		rCtx, cancel := l.withRedisTimeout(ctx)
		defer cancel()
		return rdb.Del(rCtx, redisKeys...).Result()
	})
	return err
}

// RenewDescriptorLeases extends active budget reservation leases for all budgeted
// descriptors matching requestID in both Redis and local fallback tracking.
func (l *Limiter) RenewDescriptorLeases(
	ctx context.Context,
	orgID string,
	descriptors []domain.RateLimitDescriptor,
	requestID string,
	ttlSec int,
) error {
	if l == nil || requestID == "" || len(descriptors) == 0 {
		return nil
	}
	if ttlSec <= 0 {
		ttlSec = defaultDescriptorReservationTTLSec
	}
	active, err := normalizeDescriptors(orgID, descriptors)
	if err != nil {
		return err
	}
	var budgeted []domain.RateLimitDescriptor
	for _, d := range active {
		if d.MaxBudgetMicros > 0 {
			budgeted = append(budgeted, d)
		}
	}
	if len(budgeted) == 0 {
		return nil
	}

	now := l.nowUTC()
	newExpiry := now.Add(time.Duration(ttlSec) * time.Second)
	tag := orgHashTag(orgID)
	l.localMu.Lock()
	for _, d := range budgeted {
		lk := tag + ":" + descriptorEntityKey(d)
		if resMap := l.localDescReservations[lk]; resMap != nil {
			if entry, ok := resMap[requestID]; ok {
				entry.expiresAt = newExpiry
				resMap[requestID] = entry
			}
		}
	}
	l.localMu.Unlock()

	if l.redis == nil || l.redis.Client() == nil {
		return nil
	}
	nowMin := now.Unix() / 60
	utcDay := now.Format("20060102")
	keys := make([]string, 0, len(budgeted)*3)
	for _, d := range budgeted {
		ks := buildDescriptorKeySet(orgID, d, nowMin, utcDay)
		keys = append(keys, ks.resZSet, ks.resSum, ks.resAmounts)
	}
	_, execErr := l.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
		rCtx, cancel := l.withRedisTimeout(ctx)
		defer cancel()
		return l.renewDescriptorsScr.Run(rCtx, rdb, keys, len(budgeted), requestID, ttlSec).Result()
	})
	return execErr
}

// CheckDescriptorBudgetReserve verifies whether active budgeted descriptors can afford reserveMicros
// without deducting or holding duplicate quota on fallback hops.
func (l *Limiter) CheckDescriptorBudgetReserve(
	ctx context.Context,
	orgID string,
	descriptors []domain.RateLimitDescriptor,
	reserveMicros int64,
	requestID string,
) error {
	if l == nil || reserveMicros <= 0 || len(descriptors) == 0 {
		return nil
	}
	enabled, fallbackLocal, _, _, _, _ := l.configSnapshot()
	if !enabled {
		return nil
	}
	active, err := normalizeDescriptors(orgID, descriptors)
	if err != nil {
		return err
	}
	var budgeted []domain.RateLimitDescriptor
	for _, d := range active {
		if d.MaxBudgetMicros > 0 {
			budgeted = append(budgeted, d)
		}
	}
	if len(budgeted) == 0 {
		return nil
	}
	now := l.nowUTC()
	nowMin := now.Unix() / 60
	utcDay := now.Format("20060102")
	tag := orgHashTag(orgID)

	if l.redis != nil && l.redis.Client() != nil {
		res, execErr := l.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
			rCtx, cancel := l.withRedisTimeout(ctx)
			defer cancel()
			pipe := rdb.Pipeline()
			type cmds struct {
				spend  *redis.StringCmd
				resSum *redis.StringCmd
				reqRes *redis.StringCmd
				desc   domain.RateLimitDescriptor
			}
			entries := make([]cmds, 0, len(budgeted))
			for _, d := range budgeted {
				ks := buildDescriptorKeySet(orgID, d, nowMin, utcDay)
				c := cmds{
					spend:  pipe.Get(rCtx, ks.spend),
					resSum: pipe.Get(rCtx, ks.resSum),
					desc:   d,
				}
				if requestID != "" {
					c.reqRes = pipe.HGet(rCtx, ks.resAmounts, requestID)
				}
				entries = append(entries, c)
			}
			if _, pErr := pipe.Exec(rCtx); pErr != nil && !errors.Is(pErr, redis.Nil) {
				return nil, pErr
			}
			for _, e := range entries {
				spent := e.desc.SpentFloorMicros
				if val, err := e.spend.Int64(); err == nil && val > spent {
					spent = val
				}
				var resSum int64
				if val, err := e.resSum.Int64(); err == nil && val > 0 {
					resSum = val
				}
				var reqRes int64
				if e.reqRes != nil {
					if val, err := e.reqRes.Int64(); err == nil && val > 0 {
						reqRes = val
					}
				}
				otherRes := resSum - reqRes
				if otherRes < 0 {
					otherRes = 0
				}
				if spent+otherRes+reserveMicros > e.desc.MaxBudgetMicros {
					scope := strings.ToUpper(string(e.desc.ScopeType))
					return toQuotaError(scope + "_BUDGET_EXCEEDED"), nil
				}
			}
			return nil, nil
		})
		if execErr == nil {
			if qErr, ok := res.(error); ok && qErr != nil {
				return qErr
			}
			return nil
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
	for _, d := range budgeted {
		lk := tag + ":" + descriptorEntityKey(d)
		spent := d.SpentFloorMicros
		if localVal := l.localDescSpent[lk]; localVal > spent {
			spent = localVal
		}
		var otherRes int64
		for rk, entry := range l.localDescReservations[lk] {
			if rk == requestID {
				continue
			}
			if !entry.expiresAt.After(now) {
				continue
			}
			otherRes += entry.amount
		}
		if spent+otherRes+reserveMicros > d.MaxBudgetMicros {
			return toQuotaError(strings.ToUpper(string(d.ScopeType)) + "_BUDGET_EXCEEDED")
		}
	}
	return nil
}
