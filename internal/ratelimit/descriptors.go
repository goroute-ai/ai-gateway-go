package ratelimit

import (
	"context"
	_ "embed"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/redis/go-redis/v9"
)

//go:embed scripts/check_descriptors.lua
var checkDescriptorsLua string

//go:embed scripts/reconcile_descriptors.lua
var reconcileDescriptorsLua string

const (
	defaultDescriptorTPDTTLSec         = 86400 * 2
	defaultDescriptorIterationTTLSec   = 3600
	defaultDescriptorReservationTTLSec = 3600
)

type localIterCounter struct {
	count     int
	expiresAt time.Time
}

type localReservationEntry struct {
	amount    int64
	expiresAt time.Time
}

// descriptorKeySet holds all Redis Cluster slot-aligned keys for a single descriptor.
type descriptorKeySet struct {
	rpm        string
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
}

func descriptorEntityKey(d domain.RateLimitDescriptor) string {
	scope := strings.ToLower(strings.TrimSpace(string(d.ScopeType)))
	scopeID := strings.TrimSpace(d.ScopeID)
	modelPattern := strings.TrimSpace(d.ModelPattern)
	if modelPattern == "" || modelPattern == "*" {
		return fmt.Sprintf("%s:%s", scope, scopeID)
	}
	return fmt.Sprintf("%s:%s:model:%s", scope, scopeID, modelPattern)
}

func buildDescriptorKeySet(orgID string, d domain.RateLimitDescriptor, nowMin int64, utcDay string) descriptorKeySet {
	tag := orgHashTag(orgID)
	entity := descriptorEntityKey(d)
	resBase := fmt.Sprintf("gw:dq:%s:res:%s", tag, entity)
	resZ, resS, resA := reservationTuple(resBase)
	return descriptorKeySet{
		rpm:        fmt.Sprintf("gw:dq:%s:rpm:%s:%d", tag, entity, nowMin),
		tpm:        fmt.Sprintf("gw:dq:%s:tpm:%s:%d", tag, entity, nowMin),
		itpm:       fmt.Sprintf("gw:dq:%s:itpm:%s:%d", tag, entity, nowMin),
		otpm:       fmt.Sprintf("gw:dq:%s:otpm:%s:%d", tag, entity, nowMin),
		tpd:        fmt.Sprintf("gw:dq:%s:tpd:%s:%s", tag, entity, utcDay),
		conc:       fmt.Sprintf("gw:dq:%s:conc:%s", tag, entity),
		iter:       fmt.Sprintf("gw:dq:%s:iter:%s", tag, entity),
		spend:      fmt.Sprintf("gw:dq:%s:spend:%s", tag, entity),
		resZSet:    resZ,
		resSum:     resS,
		resAmounts: resA,
	}
}

func descriptorCheckKeys(orgID string, descriptors []domain.RateLimitDescriptor, now time.Time) []string {
	nowUTC := now.UTC()
	nowMin := nowUTC.Unix() / 60
	utcDay := nowUTC.Format("20060102")
	keys := make([]string, 0, len(descriptors)*11)
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
		)
	}
	return keys
}

func descriptorReconcileKeys(orgID string, descriptors []domain.RateLimitDescriptor, now time.Time) []string {
	nowUTC := now.UTC()
	nowMin := nowUTC.Unix() / 60
	utcDay := nowUTC.Format("20060102")
	keys := make([]string, 0, len(descriptors)*9)
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
	if l != nil && l.nowFunc != nil {
		return l.nowFunc().UTC()
	}
	return time.Now().UTC()
}

func descriptorIterTTL(d domain.RateLimitDescriptor) int {
	if d.WindowTTLSec > 0 {
		return d.WindowTTLSec
	}
	return defaultDescriptorIterationTTLSec
}

func toDescriptorQuotaError(code string, current, limit, retryAfter int64) *domain.GatewayError {
	gwErr := toQuotaError(code)
	if retryAfter > 0 {
		gwErr.RetryAfterSec = int(retryAfter)
	}
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
// organization in a single all-or-nothing operation. If any descriptor exceeds a
// configured limit, no counters or budget reservations are mutated across any
// descriptor.
//
// The returned release function MUST be called once after request completion or
// failure to reconcile input/output/total/daily token deltas, release concurrency,
// and settle or refund budget reservations:
//   - actualCostMicros >= 0: removes reservation and charges actualCostMicros to spend
//   - actualCostMicros == -1: refunds reservation without charging spend
//   - actualCostMicros == -2: leaves reservation intact for asynchronous outbox settlement
func (l *Limiter) AcquireDescriptors(
	ctx context.Context,
	orgID string,
	reqID string,
	estInput int,
	estOutput int,
	reserveMicros int64,
	descriptors []domain.RateLimitDescriptor,
) (func(actualInput, actualOutput int, actualCostMicros int64), error) {
	noop := func(int, int, int64) {}
	if l == nil {
		return noop, nil
	}
	enabled, fallbackLocal, _, _, _, _ := l.configSnapshot()
	if !enabled {
		return noop, nil
	}
	if reserveMicros < 0 {
		return nil, fmt.Errorf("budget reservation requires a non-negative amount")
	}
	if estInput < 0 {
		estInput = 0
	}
	if estOutput < 0 {
		estOutput = 0
	}

	active, err := normalizeDescriptors(orgID, descriptors)
	if err != nil {
		return nil, err
	}
	if len(active) == 0 {
		return noop, nil
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
		argv := make([]any, 0, 9+len(active)*11)
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
		)
		for _, d := range active {
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
			)
		}

		res, execErr := l.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
			rCtx, cancel := l.withRedisTimeout(ctx)
			defer cancel()
			return l.checkDescriptorsScr.Run(rCtx, rdb, keys, argv...).Slice()
		})
		if execErr == nil {
			if slice, ok := res.([]any); ok && len(slice) >= 2 {
				allowed, _ := slice[0].(int64)
				reason, _ := slice[1].(string)
				if allowed == 0 {
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
					return nil, toDescriptorQuotaError(reason, current, limit, retryAfter)
				}

				recKeys := descriptorReconcileKeys(orgID, active, now)
				flags := make([]any, 0, len(active)*6)
				for _, d := range active {
					flags = append(flags,
						boolToInt(d.TPMLimit > 0),
						boolToInt(d.ITPMLimit > 0),
						boolToInt(d.OTPMLimit > 0),
						boolToInt(d.TPDLimit > 0),
						boolToInt(d.MaxConcurrent > 0),
						boolToInt(d.MaxBudgetMicros > 0),
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

						recArgv := make([]any, 0, 8+len(flags))
						recArgv = append(recArgv,
							len(active),
							inputDelta,
							outputDelta,
							totalDelta,
							windowTTL,
							defaultDescriptorTPDTTLSec,
							reqID,
							actualCostMicros,
						)
						recArgv = append(recArgv, flags...)

						_, _ = l.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
							rCtx, cancel := l.withRedisTimeout(context.Background())
							defer cancel()
							return l.reconcileDescriptorsScr.Run(rCtx, rdb, recKeys, recArgv...).Result()
						})
					})
				}, nil
			}
		}

		if !fallbackLocal {
			return nil, limiterUnavailableError()
		}
	}

	if !fallbackLocal {
		return nil, limiterUnavailableError()
	}

	return l.acquireDescriptorsLocal(orgID, reqID, estInput, estOutput, reserveMicros, active, now)
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
}

func (l *Limiter) acquireDescriptorsLocal(
	orgID string,
	reqID string,
	estInput int,
	estOutput int,
	reserveMicros int64,
	descriptors []domain.RateLimitDescriptor,
	now time.Time,
) (func(actualInput, actualOutput int, actualCostMicros int64), error) {
	l.localMu.Lock()
	defer l.localMu.Unlock()

	l.ensureLocalDescMapsLocked()

	nowUTC := now.UTC()
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
	}

	tag := orgHashTag(orgID)
	localKeys := make([]string, len(descriptors))
	for i, d := range descriptors {
		localKeys[i] = tag + ":" + descriptorEntityKey(d)
	}

	// Phase 1: Pure read-only validation across all descriptors.
	pendingRPM := make(map[string]int)
	pendingTPM := make(map[string]int)
	pendingITPM := make(map[string]int)
	pendingOTPM := make(map[string]int)
	pendingTPD := make(map[string]int64)
	pendingConc := make(map[string]int)
	pendingIter := make(map[string]int)
	pendingRes := make(map[string]bool)

	for i, d := range descriptors {
		lk := localKeys[i]
		scope := strings.ToUpper(string(d.ScopeType))

		if d.RPMLimit > 0 {
			cur := l.localDescRPM[lk] + pendingRPM[lk]
			if cur+1 > d.RPMLimit {
				return nil, toDescriptorQuotaError(scope+"_RPM_EXCEEDED", int64(cur), int64(d.RPMLimit), retryMin)
			}
			pendingRPM[lk]++
		}

		if d.TPMLimit > 0 {
			cur := l.localDescTPM[lk] + pendingTPM[lk]
			if cur+estTotal > d.TPMLimit {
				return nil, toDescriptorQuotaError(scope+"_TPM_EXCEEDED", int64(cur), int64(d.TPMLimit), retryMin)
			}
			pendingTPM[lk] += estTotal
		}

		if d.ITPMLimit > 0 {
			cur := l.localDescITPM[lk] + pendingITPM[lk]
			if cur+estInput > d.ITPMLimit {
				return nil, toDescriptorQuotaError(scope+"_ITPM_EXCEEDED", int64(cur), int64(d.ITPMLimit), retryMin)
			}
			pendingITPM[lk] += estInput
		}

		if d.OTPMLimit > 0 {
			cur := l.localDescOTPM[lk] + pendingOTPM[lk]
			if cur+estOutput > d.OTPMLimit {
				return nil, toDescriptorQuotaError(scope+"_OTPM_EXCEEDED", int64(cur), int64(d.OTPMLimit), retryMin)
			}
			pendingOTPM[lk] += estOutput
		}

		if d.TPDLimit > 0 {
			cur := l.localDescTPD[lk] + pendingTPD[lk]
			if cur+int64(estTotal) > d.TPDLimit {
				return nil, toDescriptorQuotaError(scope+"_TPD_EXCEEDED", cur, d.TPDLimit, retryDay)
			}
			pendingTPD[lk] += int64(estTotal)
		}

		if d.MaxConcurrent > 0 {
			cur := l.localDescConc[lk] + pendingConc[lk]
			if cur+1 > d.MaxConcurrent {
				return nil, toDescriptorQuotaError(scope+"_CONCURRENCY_EXCEEDED", int64(cur), int64(d.MaxConcurrent), 5)
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
				return nil, toDescriptorQuotaError(scope+"_ITERATIONS_EXCEEDED", int64(cur), int64(d.MaxIterations), retryIter)
			}
			pendingIter[lk]++
		}

		if d.MaxBudgetMicros > 0 {
			curSpent := l.localDescSpent[lk]
			if d.SpentFloorMicros > curSpent {
				curSpent = d.SpentFloorMicros
			}
			if reserveMicros <= 0 || reqID == "" {
				return nil, toDescriptorQuotaError("BUDGET_ESTIMATE_REQUIRED", curSpent, d.MaxBudgetMicros, 5)
			}
			if pendingRes[lk] {
				return nil, toDescriptorQuotaError("BUDGET_RESERVATION_CONFLICT", curSpent, d.MaxBudgetMicros, 5)
			}
			var activeReserved int64
			if resMap := l.localDescReservations[lk]; resMap != nil {
				for rid, entry := range resMap {
					if !nowUTC.Before(entry.expiresAt) {
						continue
					}
					if rid == reqID {
						return nil, toDescriptorQuotaError("BUDGET_RESERVATION_CONFLICT", curSpent, d.MaxBudgetMicros, 5)
					}
					activeReserved += entry.amount
				}
			}
			if curSpent+activeReserved+reserveMicros > d.MaxBudgetMicros {
				return nil, toDescriptorQuotaError(scope+"_BUDGET_EXCEEDED", curSpent+activeReserved, d.MaxBudgetMicros, 60)
			}
			pendingRes[lk] = true
		}
	}

	// Phase 2: All descriptors admitted; apply mutations atomically under lock.
	resExpiry := nowUTC.Add(defaultDescriptorReservationTTLSec * time.Second)
	for i, d := range descriptors {
		lk := localKeys[i]
		if d.RPMLimit > 0 {
			l.localDescRPM[lk]++
		}
		if d.TPMLimit > 0 && estTotal > 0 {
			l.localDescTPM[lk] += estTotal
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
			if d.SpentFloorMicros > l.localDescSpent[lk] {
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
								l.localDescSpent[lk] += actualCostMicros
							}
						}
					}
				}
			}
		})
	}, nil
}
