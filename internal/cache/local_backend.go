package cache

import (
	"container/list"
	"context"
	"sync"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/config"
)

const (
	defaultLocalMaxEntries   = 4096
	defaultLocalMaxItemBytes = 1 << 20 // 1 MiB
)

type localEntry struct {
	storageKey string
	value      []byte
	meta       EntryMeta
	expiresAt  time.Time
}

// LocalBackend is a bounded, process-local in-memory LRU cache with TTL expiration
// and a per-entry payload size cap.
type LocalBackend struct {
	mu           sync.Mutex
	capacity     int
	maxItemBytes int
	items        map[string]*list.Element
	order        *list.List
	evictions    uint64
	nowFn        func() time.Time
}

// NewLocalBackend constructs a bounded in-memory LRU Backend.
func NewLocalBackend(maxEntries, maxItemBytes int) *LocalBackend {
	if maxEntries <= 0 {
		maxEntries = defaultLocalMaxEntries
	}
	if maxItemBytes <= 0 {
		maxItemBytes = defaultLocalMaxItemBytes
	}
	return &LocalBackend{
		capacity:     maxEntries,
		maxItemBytes: maxItemBytes,
		items:        make(map[string]*list.Element, min(maxEntries, 256)),
		order:        list.New(),
		nowFn:        time.Now,
	}
}

// Type returns "local".
func (b *LocalBackend) Type() string { return config.CacheTypeLocal }

func localStorageKey(orgID, key string) string {
	return orgTag(orgID) + ":" + key
}

// Get retrieves an unexpired cached payload from memory and promotes it to MRU.
func (b *LocalBackend) Get(_ context.Context, orgID, key string) ([]byte, bool, error) {
	if b == nil || key == "" {
		return nil, false, nil
	}
	sk := localStorageKey(orgID, key)
	now := b.nowFn()

	b.mu.Lock()
	defer b.mu.Unlock()
	elem, ok := b.items[sk]
	if !ok {
		return nil, false, nil
	}
	entry := elem.Value.(*localEntry)
	if !now.Before(entry.expiresAt) {
		delete(b.items, sk)
		b.order.Remove(elem)
		return nil, false, nil
	}
	b.order.MoveToFront(elem)
	cp := make([]byte, len(entry.value))
	copy(cp, entry.value)
	return cp, true, nil
}

// Set stores a payload in the bounded in-memory LRU if within maxItemBytes.
func (b *LocalBackend) Set(_ context.Context, orgID, key string, value []byte, meta EntryMeta, ttl time.Duration) error {
	if b == nil || key == "" || len(value) == 0 || ttl <= 0 {
		return nil
	}
	if b.maxItemBytes > 0 && len(value) > b.maxItemBytes {
		return nil
	}
	sk := localStorageKey(orgID, key)
	now := b.nowFn()
	cp := make([]byte, len(value))
	copy(cp, value)

	b.mu.Lock()
	defer b.mu.Unlock()

	if elem, ok := b.items[sk]; ok {
		entry := elem.Value.(*localEntry)
		entry.value = cp
		entry.meta = meta
		entry.expiresAt = now.Add(ttl)
		b.order.MoveToFront(elem)
		return nil
	}

	// Prune any expired entries at the LRU tail before evicting live entries.
	for elem := b.order.Back(); elem != nil; {
		entry := elem.Value.(*localEntry)
		if now.Before(entry.expiresAt) {
			break
		}
		prev := elem.Prev()
		delete(b.items, entry.storageKey)
		b.order.Remove(elem)
		elem = prev
	}

	for len(b.items) >= b.capacity {
		oldest := b.order.Back()
		if oldest == nil {
			break
		}
		entry := oldest.Value.(*localEntry)
		delete(b.items, entry.storageKey)
		b.order.Remove(oldest)
		b.evictions++
	}

	b.items[sk] = b.order.PushFront(&localEntry{
		storageKey: sk,
		value:      cp,
		meta:       meta,
		expiresAt:  now.Add(ttl),
	})
	return nil
}

// Invalidate removes entries matching orgID (when non-empty) and model (when non-empty).
// When both are empty, all entries are purged.
func (b *LocalBackend) Invalidate(_ context.Context, orgID, model string) (int, error) {
	if b == nil {
		return 0, nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()

	purged := 0
	for elem := b.order.Back(); elem != nil; {
		prev := elem.Prev()
		entry := elem.Value.(*localEntry)
		matchOrg := orgID == "" || entry.meta.OrgID == orgID
		matchModel := model == "" || entry.meta.Model == model || entry.meta.RequestedModel == model
		if matchOrg && matchModel {
			delete(b.items, entry.storageKey)
			b.order.Remove(elem)
			purged++
		}
		elem = prev
	}
	return purged, nil
}

// Stats returns current entry count, capacity, and lifetime eviction count.
func (b *LocalBackend) Stats() BackendStats {
	if b == nil {
		return BackendStats{}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return BackendStats{
		Entries:   len(b.items),
		Capacity:  b.capacity,
		Evictions: b.evictions,
	}
}
