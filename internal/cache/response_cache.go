package cache

import (
	"container/list"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/redis/go-redis/v9"
)

type cacheEpochs struct {
	Global       int64 `json:"global"`
	Organization int64 `json:"organization"`
	Model        int64 `json:"model"`
}

type cacheEntry struct {
	Response  *domain.CanonicalChatResponse `json:"response"`
	OrgID     string                        `json:"org_id"`
	Model     string                        `json:"model"`
	Epochs    cacheEpochs                   `json:"epochs"`
	ExpiresAt time.Time                     `json:"expires_at"`
}

// ResponseCache provides tenant-isolated exact-match response caching. Every hit validates
// shared invalidation epochs before returning either an L1 or Redis entry.
type ResponseCache struct {
	enabled bool
	ttl     time.Duration
	redis   *storage.RedisFabric
	l1      boundedL1

	epochMu     sync.RWMutex
	globalEpoch int64
	orgEpochs   map[string]int64
	modelEpochs map[string]int64
	revision    int64
	l1Hits      atomic.Uint64
	l1Misses    atomic.Uint64
	l2Hits      atomic.Uint64
	epochChecks atomic.Uint64
	epochNanos  atomic.Uint64
}

type MetricsSnapshot struct {
	L1Hits      uint64
	L1Misses    uint64
	L2Hits      uint64
	EpochChecks uint64
	EpochNanos  uint64
}

const defaultL1Capacity = 4096

type l1Item struct {
	key   string
	entry cacheEntry
}

// boundedL1 is a process-local LRU. TTL-only deletion would retain expired
// entries forever when callers continuously use unique keys.
type boundedL1 struct {
	mu       sync.Mutex
	capacity int
	items    map[string]*list.Element
	order    *list.List
	evicted  uint64
}

func newBoundedL1(capacity int) boundedL1 {
	if capacity <= 0 {
		capacity = defaultL1Capacity
	}
	return boundedL1{capacity: capacity, items: make(map[string]*list.Element, capacity), order: list.New()}
}

func (l *boundedL1) load(key string) (cacheEntry, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	elem, ok := l.items[key]
	if !ok {
		return cacheEntry{}, false
	}
	l.order.MoveToFront(elem)
	return elem.Value.(l1Item).entry, true
}

func (l *boundedL1) store(key string, entry cacheEntry) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if elem, ok := l.items[key]; ok {
		elem.Value = l1Item{key: key, entry: entry}
		l.order.MoveToFront(elem)
		return
	}
	if len(l.items) >= l.capacity {
		oldest := l.order.Back()
		if oldest != nil {
			delete(l.items, oldest.Value.(l1Item).key)
			l.order.Remove(oldest)
			l.evicted++
		}
	}
	l.items[key] = l.order.PushFront(l1Item{key: key, entry: entry})
}

func (l *boundedL1) delete(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if elem, ok := l.items[key]; ok {
		delete(l.items, key)
		l.order.Remove(elem)
	}
}

func (l *boundedL1) purge(orgID, model string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	purged := 0
	for elem := l.order.Back(); elem != nil; {
		prev := elem.Prev()
		item := elem.Value.(l1Item)
		matchScope := orgID == "" && model == ""
		if matchScope || (orgID != "" && item.entry.OrgID == orgID) || (model != "" && item.entry.Model == model) {
			delete(l.items, item.key)
			l.order.Remove(elem)
			purged++
		}
		elem = prev
	}
	return purged
}

func (l *boundedL1) stats() (size, capacity int, evicted uint64) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.items), l.capacity, l.evicted
}

func NewResponseCache(enabled bool, ttl time.Duration, redisFabric *storage.RedisFabric) *ResponseCache {
	return NewResponseCacheWithL1Capacity(enabled, ttl, defaultL1Capacity, redisFabric)
}

func NewResponseCacheWithL1Capacity(enabled bool, ttl time.Duration, maxL1Entries int, redisFabric *storage.RedisFabric) *ResponseCache {
	if ttl <= 0 {
		ttl = time.Hour
	}
	return &ResponseCache{
		enabled:     enabled,
		ttl:         ttl,
		redis:       redisFabric,
		l1:          newBoundedL1(maxL1Entries),
		orgEpochs:   make(map[string]int64),
		modelEpochs: make(map[string]int64),
	}
}

// IsCacheable reports whether a ChatCompletion request is eligible for exact-match caching.
func (c *ResponseCache) IsCacheable(req *domain.CanonicalChatRequest, cacheControlHeader string) bool {
	if !c.enabled || req == nil || req.Stream {
		return false
	}
	if cacheControlHeader == "no-cache" || cacheControlHeader == "bypass" {
		return false
	}
	if cacheControlHeader == "enabled" || cacheControlHeader == "force" {
		return true
	}
	return req.Temperature != nil && *req.Temperature == 0
}

// ComputeKey generates a collision-resistant SHA-256 cache key scoped to the organization and request.
func (c *ResponseCache) ComputeKey(orgID string, req *domain.CanonicalChatRequest) string {
	type keyPayload struct {
		OrgID   string                       `json:"org_id"`
		Request *domain.CanonicalChatRequest `json:"request"`
	}
	if req == nil {
		return ""
	}
	// RequestID is per-call observability metadata. Stream requests are not
	// cacheable, so omitting it avoids irrelevant key differences. All other
	// canonical fields participate, including provider and modality extensions.
	canonical := *req
	canonical.RequestID = ""
	canonical.Stream = false
	h := sha256.New()
	if err := json.NewEncoder(h).Encode(keyPayload{OrgID: orgID, Request: &canonical}); err != nil {
		// An unencodable extension value must disable caching, never collapse to
		// the same empty-payload digest as another request.
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

func (c *ResponseCache) Get(ctx context.Context, key string) (*domain.CanonicalChatResponse, bool) {
	now := time.Now()
	if entry, ok := c.l1.load(key); ok {
		if now.Before(entry.ExpiresAt) {
			current, err := c.currentEpochs(ctx, entry.OrgID, entry.Model)
			if err != nil {
				c.l1Misses.Add(1)
				return nil, false
			}
			if current == entry.Epochs {
				c.l1Hits.Add(1)
				return cloneResponse(entry.Response), true
			}
		}
		c.l1.delete(key)
	}
	c.l1Misses.Add(1)

	if c.redis == nil || c.redis.Client() == nil {
		return nil, false
	}
	res, err := c.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
		return rdb.Get(ctx, "gw:cache:resp:"+key).Result()
	})
	if err != nil {
		return nil, false
	}
	raw, ok := res.(string)
	if !ok || raw == "" {
		return nil, false
	}
	var entry cacheEntry
	if json.Unmarshal([]byte(raw), &entry) != nil || entry.Response == nil {
		return nil, false
	}
	if !now.Before(entry.ExpiresAt) {
		return nil, false
	}
	current, err := c.currentEpochs(ctx, entry.OrgID, entry.Model)
	if err != nil || current != entry.Epochs {
		return nil, false
	}
	c.l2Hits.Add(1)
	c.l1.store(key, entry)
	return cloneResponse(entry.Response), true
}

func (c *ResponseCache) Set(ctx context.Context, key string, resp *domain.CanonicalChatResponse) {
	c.SetWithMeta(ctx, key, "", resp)
}

func (c *ResponseCache) SetWithMeta(ctx context.Context, key, orgID string, resp *domain.CanonicalChatResponse) {
	if resp == nil {
		return
	}
	model := resp.Model
	epochs, err := c.currentEpochs(ctx, orgID, model)
	if err != nil {
		return
	}
	entry := cacheEntry{
		Response:  cloneResponse(resp),
		OrgID:     orgID,
		Model:     model,
		Epochs:    epochs,
		ExpiresAt: time.Now().Add(c.ttl),
	}
	if c.redis != nil && c.redis.Client() != nil {
		b, err := json.Marshal(entry)
		if err != nil {
			return
		}
		if _, err := c.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
			return rdb.Set(ctx, "gw:cache:resp:"+key, b, c.ttl).Result()
		}); err != nil {
			return
		}
	}
	c.l1.store(key, entry)
}

// Invalidate advances shared global, organization, and/or model epochs and removes matching local entries.
// The returned revision is monotonic across all invalidation operations.
func (c *ResponseCache) Invalidate(ctx context.Context, orgID, model string) (int, int64, error) {
	var revision int64
	if c.redis != nil && c.redis.Client() != nil {
		keys := []string{cacheRevisionKey()}
		if orgID == "" && model == "" {
			keys = append(keys, cacheGlobalEpochKey())
		} else {
			if orgID != "" {
				keys = append(keys, cacheOrgEpochKey(orgID))
			}
			if model != "" {
				keys = append(keys, cacheModelEpochKey(model))
			}
		}
		res, err := c.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
			return invalidateCacheEpochsScript.Run(ctx, rdb, keys).Int64()
		})
		if err != nil {
			return 0, 0, err
		}
		var ok bool
		revision, ok = res.(int64)
		if !ok {
			return 0, 0, fmt.Errorf("cache invalidation returned unexpected revision")
		}
	} else {
		c.epochMu.Lock()
		c.revision++
		revision = c.revision
		if orgID == "" && model == "" {
			c.globalEpoch++
		} else {
			if orgID != "" {
				c.orgEpochs[orgID]++
			}
			if model != "" {
				c.modelEpochs[model]++
			}
		}
		c.epochMu.Unlock()
	}

	purged := c.l1.purge(orgID, model)
	return purged, revision, nil
}

// L1Stats returns the current bounded process-local entry count and lifetime
// eviction count for operator diagnostics.
func (c *ResponseCache) L1Stats() (size, capacity int, evicted uint64) {
	if c == nil {
		return 0, 0, 0
	}
	return c.l1.stats()
}

// Metrics returns cumulative cache-hit and shared-epoch lookup measurements.
func (c *ResponseCache) Metrics() MetricsSnapshot {
	if c == nil {
		return MetricsSnapshot{}
	}
	return MetricsSnapshot{
		L1Hits:      c.l1Hits.Load(),
		L1Misses:    c.l1Misses.Load(),
		L2Hits:      c.l2Hits.Load(),
		EpochChecks: c.epochChecks.Load(),
		EpochNanos:  c.epochNanos.Load(),
	}
}

func (c *ResponseCache) currentEpochs(ctx context.Context, orgID, model string) (cacheEpochs, error) {
	started := time.Now()
	defer func() {
		c.epochChecks.Add(1)
		c.epochNanos.Add(uint64(time.Since(started)))
	}()
	if c.redis == nil || c.redis.Client() == nil {
		c.epochMu.RLock()
		defer c.epochMu.RUnlock()
		return cacheEpochs{Global: c.globalEpoch, Organization: c.orgEpochs[orgID], Model: c.modelEpochs[model]}, nil
	}
	keys := []string{cacheGlobalEpochKey(), cacheOrgEpochKey(orgID), cacheModelEpochKey(model)}
	res, err := c.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
		return rdb.MGet(ctx, keys...).Result()
	})
	if err != nil {
		return cacheEpochs{}, err
	}
	values, ok := res.([]any)
	if !ok || len(values) != len(keys) {
		return cacheEpochs{}, fmt.Errorf("cache epoch lookup returned unexpected values")
	}
	parsed := make([]int64, len(values))
	for i, value := range values {
		if value == nil {
			continue
		}
		text, ok := value.(string)
		if !ok {
			return cacheEpochs{}, fmt.Errorf("cache epoch %d has unexpected type %T", i, value)
		}
		parsed[i], err = strconv.ParseInt(text, 10, 64)
		if err != nil {
			return cacheEpochs{}, fmt.Errorf("parse cache epoch %d: %w", i, err)
		}
	}
	return cacheEpochs{Global: parsed[0], Organization: parsed[1], Model: parsed[2]}, nil
}

func cloneResponse(resp *domain.CanonicalChatResponse) *domain.CanonicalChatResponse {
	if resp == nil {
		return nil
	}
	cp := *resp
	return &cp
}

func cacheGlobalEpochKey() string { return "gw:cache:{epochs}:global" }
func cacheRevisionKey() string    { return "gw:cache:{epochs}:revision" }

func cacheOrgEpochKey(orgID string) string {
	return fmt.Sprintf("gw:cache:{epochs}:org:%x", sha256.Sum256([]byte(orgID)))
}

func cacheModelEpochKey(model string) string {
	return fmt.Sprintf("gw:cache:{epochs}:model:%x", sha256.Sum256([]byte(model)))
}
