package router

import (
	"context"
	_ "embed"
	"math/rand/v2"
	"strconv"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/redis/go-redis/v9"
)

//go:embed scripts/acquire_deployment_slot.lua
var acquireDeploymentSlotLua string

//go:embed scripts/release_deployment_slot.lua
var releaseDeploymentSlotLua string

var (
	acquireDeploymentSlotScript = redis.NewScript(acquireDeploymentSlotLua)
	releaseDeploymentSlotScript = redis.NewScript(releaseDeploymentSlotLua)
)

const defaultDeploymentSlotTTLSec = 300

func deploymentSlotKey(depID string) string {
	return "gw:router:dep_slots:" + depID
}

// DeploymentSlotLimiter enforces per-deployment MaxParallelRequests using self-healing
// Redis ZSET leases with a thread-safe in-memory fallback when Redis is unavailable.
type DeploymentSlotLimiter struct {
	redis      *storage.RedisFabric
	ttlSec     int
	now        func() time.Time
	mu         sync.Mutex
	localSlots map[string]map[string]time.Time
}

// NewDeploymentSlotLimiter constructs a DeploymentSlotLimiter with ttlSec lease expiry.
func NewDeploymentSlotLimiter(redisFabric *storage.RedisFabric, ttlSec int) *DeploymentSlotLimiter {
	if ttlSec <= 0 {
		ttlSec = defaultDeploymentSlotTTLSec
	}
	return &DeploymentSlotLimiter{
		redis:      redisFabric,
		ttlSec:     ttlSec,
		now:        time.Now,
		localSlots: make(map[string]map[string]time.Time),
	}
}

// SetTTL updates the lease expiration duration in seconds.
func (l *DeploymentSlotLimiter) SetTTL(ttlSec int) {
	if l == nil || ttlSec <= 0 {
		return
	}
	l.mu.Lock()
	l.ttlSec = ttlSec
	l.mu.Unlock()
}

func (l *DeploymentSlotLimiter) currentNow() time.Time {
	if l != nil && l.now != nil {
		return l.now()
	}
	return time.Now()
}

func (l *DeploymentSlotLimiter) currentTTLSec() int {
	if l == nil {
		return defaultDeploymentSlotTTLSec
	}
	l.mu.Lock()
	ttl := l.ttlSec
	l.mu.Unlock()
	if ttl <= 0 {
		return defaultDeploymentSlotTTLSec
	}
	return ttl
}

// AcquireDeploymentSlot attempts an immediate atomic concurrency lease for depID up to maxParallel.
// When maxParallel <= 0, it returns a no-op release func and true.
func (l *DeploymentSlotLimiter) AcquireDeploymentSlot(ctx context.Context, depID string, maxParallel int) (func(), bool) {
	noop := func() {}
	if l == nil || depID == "" || maxParallel <= 0 {
		return noop, true
	}

	slotID := uuid.NewString()
	now := l.currentNow()
	ttlSec := l.currentTTLSec()

	if l.redis != nil && l.redis.Client() != nil {
		key := deploymentSlotKey(depID)
		res, err := l.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
			rCtx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
			defer cancel()
			if ctx != nil && ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return acquireDeploymentSlotScript.Run(rCtx, rdb, []string{key}, now.Unix(), ttlSec, maxParallel, slotID).Slice()
		})
		if err == nil {
			if slice, ok := res.([]any); ok && len(slice) >= 1 {
				allowed, _ := slice[0].(int64)
				if allowed != 1 {
					return noop, false
				}
				var once sync.Once
				return func() {
					once.Do(func() {
						relCtx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
						defer cancel()
						_, _ = l.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
							return releaseDeploymentSlotScript.Run(relCtx, rdb, []string{key}, slotID).Result()
						})
					})
				}, true
			}
		}
		if ctx != nil && ctx.Err() != nil {
			return noop, false
		}
	}

	return l.tryAcquireLocal(depID, maxParallel, slotID, now, ttlSec)
}

func (l *DeploymentSlotLimiter) tryAcquireLocal(depID string, maxParallel int, slotID string, now time.Time, ttlSec int) (func(), bool) {
	noop := func() {}
	l.mu.Lock()
	slots := l.localSlots[depID]
	for k, exp := range slots {
		if !now.Before(exp) {
			delete(slots, k)
		}
	}
	if len(slots) >= maxParallel {
		l.mu.Unlock()
		return noop, false
	}
	if slots == nil {
		slots = make(map[string]time.Time)
		l.localSlots[depID] = slots
	}
	slots[slotID] = now.Add(time.Duration(ttlSec) * time.Second)
	l.mu.Unlock()

	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			if cur := l.localSlots[depID]; cur != nil {
				delete(cur, slotID)
				if len(cur) == 0 {
					delete(l.localSlots, depID)
				}
			}
			l.mu.Unlock()
		})
	}, true
}

// AcquireWithWait attempts AcquireDeploymentSlot immediately, and if maxWait > 0 waits with
// short priority-biased polling until a slot frees, maxWait elapses, or ctx cancels.
func (l *DeploymentSlotLimiter) AcquireWithWait(ctx context.Context, depID string, maxParallel, priorityRank int, maxWait time.Duration) (func(), bool) {
	rel, ok := l.AcquireDeploymentSlot(ctx, depID, maxParallel)
	if ok || maxWait <= 0 {
		return rel, ok
	}
	if ctx == nil {
		ctx = context.Background()
	}
	deadline := l.currentNow().Add(maxWait)
	for {
		rem := deadline.Sub(l.currentNow())
		if rem <= 0 {
			return func() {}, false
		}
		waitStep := parallelWaitPollInterval(priorityRank, rem)
		timer := time.NewTimer(waitStep)
		select {
		case <-ctx.Done():
			timer.Stop()
			return func() {}, false
		case <-timer.C:
		}
		if rel, ok := l.AcquireDeploymentSlot(ctx, depID, maxParallel); ok {
			return rel, true
		}
	}
}

// WaitForAnySlot waits up to maxWait until at least one deployment in deps with MaxParallelRequests > 0
// has an available slot, giving lower priorityRank (higher importance) shorter poll delays.
func (l *DeploymentSlotLimiter) WaitForAnySlot(ctx context.Context, deps []*domain.Deployment, priorityRank int, maxWait time.Duration) bool {
	if l == nil || maxWait <= 0 || len(deps) == 0 {
		return false
	}
	if ctx == nil {
		ctx = context.Background()
	}
	deadline := l.currentNow().Add(maxWait)
	for {
		counts := l.ActiveCounts(ctx, deps)
		for _, d := range deps {
			if d == nil {
				continue
			}
			if d.MaxParallelRequests <= 0 || counts[d.ID] < d.MaxParallelRequests {
				return true
			}
		}
		rem := deadline.Sub(l.currentNow())
		if rem <= 0 {
			return false
		}
		waitStep := parallelWaitPollInterval(priorityRank, rem)
		timer := time.NewTimer(waitStep)
		select {
		case <-ctx.Done():
			timer.Stop()
			return false
		case <-timer.C:
		}
	}
}

func parallelWaitPollInterval(priorityRank int, rem time.Duration) time.Duration {
	if priorityRank < 0 {
		priorityRank = 0
	}
	baseMs := 4 + min(priorityRank, 20)
	step := time.Duration(baseMs+rand.IntN(5)) * time.Millisecond
	if step > rem {
		return rem
	}
	return step
}

// ActiveCounts returns current non-expired concurrency slot counts for all candidates with MaxParallelRequests > 0.
func (l *DeploymentSlotLimiter) ActiveCounts(ctx context.Context, deps []*domain.Deployment) map[string]int {
	if l == nil || len(deps) == 0 {
		return nil
	}
	var cappedIDs []string
	for _, d := range deps {
		if d != nil && d.MaxParallelRequests > 0 {
			cappedIDs = append(cappedIDs, d.ID)
		}
	}
	if len(cappedIDs) == 0 {
		return nil
	}

	now := l.currentNow()
	if l.redis != nil && l.redis.Client() != nil {
		if ctx == nil {
			ctx = context.Background()
		}
		counts := make(map[string]int, len(cappedIDs))
		rCtx, cancel := context.WithTimeout(ctx, 150*time.Millisecond)
		defer cancel()
		cmds := make([]*redis.IntCmd, len(cappedIDs))
		_, err := l.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
			pipe := rdb.Pipeline()
			maxScore := strconv.FormatInt(now.Unix(), 10)
			for i, id := range cappedIDs {
				k := deploymentSlotKey(id)
				pipe.ZRemRangeByScore(rCtx, k, "-inf", maxScore)
				cmds[i] = pipe.ZCard(rCtx, k)
			}
			_, perr := pipe.Exec(rCtx)
			return nil, perr
		})
		if err == nil {
			for i, id := range cappedIDs {
				if v, cerr := cmds[i].Result(); cerr == nil {
					counts[id] = int(v)
				}
			}
			return counts
		}
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	counts := make(map[string]int, len(cappedIDs))
	for _, id := range cappedIDs {
		slots := l.localSlots[id]
		if len(slots) == 0 {
			continue
		}
		active := 0
		for k, exp := range slots {
			if !now.Before(exp) {
				delete(slots, k)
				continue
			}
			active++
		}
		if len(slots) == 0 {
			delete(l.localSlots, id)
		}
		counts[id] = active
	}
	return counts
}
