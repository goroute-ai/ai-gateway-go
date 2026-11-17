package router

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/observability"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/redis/go-redis/v9"
)

const (
	defaultBudgetRedisTimeout = 50 * time.Millisecond
	defaultBudgetLocalCap     = 16384
	dailyBudgetTTLSeconds     = int64(48 * 3600)
	monthlyBudgetTTLSeconds   = int64(35 * 24 * 3600)
)

var recordDeploymentBudgetScript = redis.NewScript(`
local cost = tonumber(ARGV[1]) or 0
if cost <= 0 then
	return {}
end
local results = {}
for i = 1, #KEYS do
	local updated = redis.call("INCRBY", KEYS[i], cost)
	local ttlSec = tonumber(ARGV[i + 1]) or 0
	if ttlSec > 0 and redis.call("TTL", KEYS[i]) < 0 then
		redis.call("EXPIRE", KEYS[i], ttlSec)
	end
	results[i] = updated
end
return results
`)

// DeploymentBudgetConfig configures per-deployment and per-provider budget tracking.
type DeploymentBudgetConfig struct {
	RedisTimeout time.Duration
	MaxLocalKeys int
}

// DeploymentBudgetTracker enforces per-deployment and per-provider spend limits
// using atomic Redis counters aligned by {org:<orgID>} cluster hash-tags, with
// a process-local atomic fallback when Redis is nil or degraded.
type DeploymentBudgetTracker struct {
	redis     *storage.RedisFabric
	cfg       DeploymentBudgetConfig
	collector atomic.Pointer[observability.Collector]
	nowFn     func() time.Time

	localMu    sync.RWMutex
	localSpend map[string]*atomic.Int64
	depPeriods map[string]string
}

// NewDeploymentBudgetTracker constructs a DeploymentBudgetTracker with optional Redis backing.
func NewDeploymentBudgetTracker(redisFabric *storage.RedisFabric, cfg ...DeploymentBudgetConfig) *DeploymentBudgetTracker {
	var c DeploymentBudgetConfig
	if len(cfg) > 0 {
		c = cfg[0]
	}
	if c.RedisTimeout <= 0 {
		c.RedisTimeout = defaultBudgetRedisTimeout
	}
	if c.MaxLocalKeys <= 0 {
		c.MaxLocalKeys = defaultBudgetLocalCap
	}
	return &DeploymentBudgetTracker{
		redis:      redisFabric,
		cfg:        c,
		nowFn:      time.Now,
		localSpend: make(map[string]*atomic.Int64),
		depPeriods: make(map[string]string),
	}
}

// SetCollector attaches an observability collector for reporting Redis degradation.
func (t *DeploymentBudgetTracker) SetCollector(collector *observability.Collector) {
	if t == nil {
		return
	}
	t.collector.Store(collector)
}

// DeploymentBudgetKey returns the Redis Cluster slot-aligned spend key for a deployment period.
func DeploymentBudgetKey(orgID, depID, period string) string {
	return fmt.Sprintf("gw:budget:%s:dep:%s:%s", orgClusterHashTag(orgID), depID, period)
}

// ProviderBudgetKey returns the Redis Cluster slot-aligned spend key for a provider period.
func ProviderBudgetKey(orgID, provider, period string) string {
	return fmt.Sprintf("gw:budget:%s:prov:%s:%s", orgClusterHashTag(orgID), provider, period)
}

// PeriodBucket normalizes a budget reset period ("daily", "monthly", "never", or
// an explicit bucket identifier) into a concrete bucket key and Redis TTL in seconds.
func PeriodBucket(period string, at time.Time) (bucket string, ttlSeconds int64) {
	normalized := strings.ToLower(strings.TrimSpace(period))
	switch normalized {
	case "", string(domain.BudgetResetMonthly):
		return at.UTC().Format("2006-01"), monthlyBudgetTTLSeconds
	case string(domain.BudgetResetDaily):
		return at.UTC().Format("2006-01-02"), dailyBudgetTTLSeconds
	case string(domain.BudgetResetNever):
		return "never", 0
	default:
		return strings.TrimSpace(period), 0
	}
}

func deploymentProviderName(dep *domain.Deployment) string {
	if dep == nil {
		return ""
	}
	if dep.GlobalModel != nil && dep.GlobalModel.Provider != "" {
		return string(dep.GlobalModel.Provider)
	}
	if dep.Credential != nil && dep.Credential.Provider != "" {
		return string(dep.Credential.Provider)
	}
	if idx := strings.IndexByte(dep.GlobalModelID, '/'); idx > 0 {
		return dep.GlobalModelID[:idx]
	}
	return ""
}

// IsWithinBudget reports whether dep is within both its deployment-level spend
// cap (dep.MaxBudgetMicros) and its provider-level spend cap in providerCaps.
func (t *DeploymentBudgetTracker) IsWithinBudget(ctx context.Context, orgID string, dep *domain.Deployment, providerCaps map[string]int64) bool {
	if dep == nil {
		return false
	}
	if t == nil {
		return true
	}

	depCap := dep.MaxBudgetMicros
	provider := deploymentProviderName(dep)
	var provCap int64
	if provider != "" && len(providerCaps) > 0 {
		provCap = providerCaps[provider]
		if provCap == 0 {
			provCap = providerCaps[strings.ToLower(provider)]
		}
	}

	if dep.ID != "" && strings.TrimSpace(dep.BudgetResetPeriod) != "" {
		t.rememberDepPeriod(dep.ID, dep.BudgetResetPeriod)
	}

	// Fast-path when neither deployment nor provider cap is active.
	if depCap <= 0 && provCap <= 0 {
		return true
	}

	now := t.nowFn()
	var keys []string
	var caps []int64
	if depCap > 0 && dep.ID != "" {
		depBucket, _ := PeriodBucket(dep.BudgetResetPeriod, now)
		keys = append(keys, DeploymentBudgetKey(orgID, dep.ID, depBucket))
		caps = append(caps, depCap)
	}
	if provCap > 0 && provider != "" {
		provBucket, _ := PeriodBucket("", now)
		keys = append(keys, ProviderBudgetKey(orgID, provider, provBucket))
		caps = append(caps, provCap)
	}
	if len(keys) == 0 {
		return true
	}

	spentVals, ok := t.readRedisSpend(ctx, keys)
	if !ok {
		for i, k := range keys {
			if t.getLocalSpend(k) >= caps[i] {
				return false
			}
		}
		return true
	}

	for i, spent := range spentVals {
		if spent >= caps[i] {
			return false
		}
	}
	return true
}

// RecordSpend atomically increments deployment and/or provider spend counters
// in Redis (and syncs/falls back to process-local atomic counters).
func (t *DeploymentBudgetTracker) RecordSpend(ctx context.Context, orgID, depID, provider, period string, costMicros int64) {
	if t == nil || costMicros <= 0 {
		return
	}
	depID = strings.TrimSpace(depID)
	provider = strings.TrimSpace(provider)
	if depID == "" && provider == "" {
		return
	}

	now := t.nowFn()
	var keys []string
	var args []any
	args = append(args, costMicros)

	if depID != "" {
		depPeriod := strings.TrimSpace(period)
		if depPeriod == "" {
			depPeriod = t.lookupDepPeriod(depID)
		}
		depBucket, depTTL := PeriodBucket(depPeriod, now)
		keys = append(keys, DeploymentBudgetKey(orgID, depID, depBucket))
		args = append(args, depTTL)
	}
	if provider != "" {
		provBucket, provTTL := PeriodBucket(period, now)
		keys = append(keys, ProviderBudgetKey(orgID, provider, provBucket))
		args = append(args, provTTL)
	}

	if t.redis == nil || t.redis.Client() == nil {
		for _, k := range keys {
			t.addLocalSpend(k, costMicros)
		}
		return
	}

	if ctx == nil {
		ctx = context.Background()
	}
	rCtx, cancel := context.WithTimeout(ctx, t.cfg.RedisTimeout)
	defer cancel()

	res, err := t.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
		return recordDeploymentBudgetScript.Run(rCtx, rdb, keys, args...).Result()
	})
	if err != nil {
		t.recordDegraded()
		for _, k := range keys {
			t.addLocalSpend(k, costMicros)
		}
		return
	}

	if vals, ok := res.([]any); ok {
		for i, k := range keys {
			if i < len(vals) {
				if updated, ok := parseRedisInt64(vals[i]); ok {
					t.syncLocalSpend(k, updated)
					continue
				}
			}
			t.addLocalSpend(k, costMicros)
		}
		return
	}
	for _, k := range keys {
		t.addLocalSpend(k, costMicros)
	}
}

func (t *DeploymentBudgetTracker) readRedisSpend(ctx context.Context, keys []string) ([]int64, bool) {
	if t.redis == nil || t.redis.Client() == nil {
		return nil, false
	}
	if ctx == nil {
		ctx = context.Background()
	}
	rCtx, cancel := context.WithTimeout(ctx, t.cfg.RedisTimeout)
	defer cancel()

	res, err := t.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
		pipe := rdb.Pipeline()
		cmds := make([]*redis.StringCmd, len(keys))
		for i, k := range keys {
			cmds[i] = pipe.Get(rCtx, k)
		}
		_, execErr := pipe.Exec(rCtx)
		if execErr != nil && !errors.Is(execErr, redis.Nil) {
			return nil, execErr
		}
		out := make([]int64, len(keys))
		for i, cmd := range cmds {
			valStr, cmdErr := cmd.Result()
			if errors.Is(cmdErr, redis.Nil) {
				out[i] = 0
				continue
			}
			if cmdErr != nil {
				return nil, cmdErr
			}
			parsed, parseErr := strconv.ParseInt(valStr, 10, 64)
			if parseErr != nil {
				return nil, parseErr
			}
			out[i] = parsed
		}
		return out, nil
	})
	if err != nil {
		t.recordDegraded()
		return nil, false
	}
	vals, ok := res.([]int64)
	if !ok {
		return nil, false
	}
	for i, k := range keys {
		t.syncLocalSpend(k, vals[i])
	}
	return vals, true
}

func (t *DeploymentBudgetTracker) getOrCreateCounter(key string) *atomic.Int64 {
	t.localMu.RLock()
	counter, ok := t.localSpend[key]
	t.localMu.RUnlock()
	if ok {
		return counter
	}

	t.localMu.Lock()
	defer t.localMu.Unlock()
	if counter, ok := t.localSpend[key]; ok {
		return counter
	}
	if len(t.localSpend) >= t.cfg.MaxLocalKeys {
		// Evict one arbitrary entry to keep memory bounded under high-cardinality keys.
		for k := range t.localSpend {
			delete(t.localSpend, k)
			break
		}
	}
	counter = &atomic.Int64{}
	t.localSpend[key] = counter
	return counter
}

func (t *DeploymentBudgetTracker) addLocalSpend(key string, delta int64) {
	t.getOrCreateCounter(key).Add(delta)
}

func (t *DeploymentBudgetTracker) syncLocalSpend(key string, redisVal int64) {
	counter := t.getOrCreateCounter(key)
	for {
		cur := counter.Load()
		if redisVal <= cur {
			return
		}
		if counter.CompareAndSwap(cur, redisVal) {
			return
		}
	}
}

func (t *DeploymentBudgetTracker) getLocalSpend(key string) int64 {
	t.localMu.RLock()
	counter, ok := t.localSpend[key]
	t.localMu.RUnlock()
	if !ok {
		return 0
	}
	return counter.Load()
}

func (t *DeploymentBudgetTracker) rememberDepPeriod(depID, period string) {
	t.localMu.RLock()
	cur, ok := t.depPeriods[depID]
	t.localMu.RUnlock()
	if ok && cur == period {
		return
	}
	t.localMu.Lock()
	if len(t.depPeriods) >= t.cfg.MaxLocalKeys {
		for k := range t.depPeriods {
			delete(t.depPeriods, k)
			break
		}
	}
	t.depPeriods[depID] = period
	t.localMu.Unlock()
}

func (t *DeploymentBudgetTracker) lookupDepPeriod(depID string) string {
	t.localMu.RLock()
	period := t.depPeriods[depID]
	t.localMu.RUnlock()
	return period
}

func (t *DeploymentBudgetTracker) recordDegraded() {
	if c := t.collector.Load(); c != nil {
		c.RecordRoutingSignalDegraded()
	}
}

func parseRedisInt64(v any) (int64, bool) {
	switch x := v.(type) {
	case int64:
		return x, true
	case int:
		return int64(x), true
	case string:
		n, err := strconv.ParseInt(x, 10, 64)
		return n, err == nil
	default:
		return 0, false
	}
}
