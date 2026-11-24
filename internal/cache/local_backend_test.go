package cache

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLocalBackend_BasicGetSetTTLAndEviction(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	b := NewLocalBackend(2, 1024)
	b.nowFn = func() time.Time { return now }

	ctx := context.Background()
	require.NoError(t, b.Set(ctx, "org-1", "k1", []byte(`{"v":1}`), EntryMeta{OrgID: "org-1", Model: "m1"}, 10*time.Second))
	require.NoError(t, b.Set(ctx, "org-1", "k2", []byte(`{"v":2}`), EntryMeta{OrgID: "org-1", Model: "m2"}, 10*time.Second))

	// Touch k1 so k2 becomes LRU.
	val, hit, err := b.Get(ctx, "org-1", "k1")
	require.NoError(t, err)
	require.True(t, hit)
	assert.Equal(t, `{"v":1}`, string(val))

	// Inserting k3 evicts k2 (LRU).
	require.NoError(t, b.Set(ctx, "org-1", "k3", []byte(`{"v":3}`), EntryMeta{OrgID: "org-1", Model: "m1"}, 10*time.Second))

	_, hit, _ = b.Get(ctx, "org-1", "k2")
	assert.False(t, hit, "k2 should have been evicted as LRU")
	_, hit, _ = b.Get(ctx, "org-1", "k1")
	assert.True(t, hit)
	_, hit, _ = b.Get(ctx, "org-1", "k3")
	assert.True(t, hit)

	stats := b.Stats()
	assert.Equal(t, 2, stats.Entries)
	assert.Equal(t, 2, stats.Capacity)
	assert.Equal(t, uint64(1), stats.Evictions)

	// Advance clock past TTL -> lazy expiration.
	now = now.Add(11 * time.Second)
	_, hit, _ = b.Get(ctx, "org-1", "k1")
	assert.False(t, hit)
}

func TestLocalBackend_MaxItemBytesGuard(t *testing.T) {
	b := NewLocalBackend(16, 10)
	ctx := context.Background()

	require.NoError(t, b.Set(ctx, "org-1", "oversized", []byte("0123456789_extra"), EntryMeta{OrgID: "org-1", Model: "m1"}, time.Minute))
	_, hit, err := b.Get(ctx, "org-1", "oversized")
	require.NoError(t, err)
	assert.False(t, hit, "oversized entry must not be stored")
	assert.Equal(t, 0, b.Stats().Entries)
}

func TestLocalBackend_ScopedInvalidation(t *testing.T) {
	b := NewLocalBackend(16, 1024)
	ctx := context.Background()

	require.NoError(t, b.Set(ctx, "org-a", "k1", []byte("1"), EntryMeta{OrgID: "org-a", Model: "gpt-4o"}, time.Minute))
	require.NoError(t, b.Set(ctx, "org-a", "k2", []byte("2"), EntryMeta{OrgID: "org-a", Model: "claude-sonnet"}, time.Minute))
	require.NoError(t, b.Set(ctx, "org-b", "k3", []byte("3"), EntryMeta{OrgID: "org-b", Model: "gpt-4o"}, time.Minute))

	// Invalidate (org-a, gpt-4o) -> only k1 should be purged (AND semantics, not OR).
	purged, err := b.Invalidate(ctx, "org-a", "gpt-4o")
	require.NoError(t, err)
	assert.Equal(t, 1, purged)

	_, hit, _ := b.Get(ctx, "org-a", "k1")
	assert.False(t, hit)
	_, hit, _ = b.Get(ctx, "org-a", "k2")
	assert.True(t, hit, "other model in org-a must remain")
	_, hit, _ = b.Get(ctx, "org-b", "k3")
	assert.True(t, hit, "same model in org-b must remain")

	// Model-only invalidation across all orgs.
	purged, err = b.Invalidate(ctx, "", "gpt-4o")
	require.NoError(t, err)
	assert.Equal(t, 1, purged)

	// Global invalidation clears remaining entries.
	purged, err = b.Invalidate(ctx, "", "")
	require.NoError(t, err)
	assert.Equal(t, 1, purged)
	assert.Equal(t, 0, b.Stats().Entries)
}

func TestLocalBackend_ConcurrentRaceSafety(t *testing.T) {
	b := NewLocalBackend(64, 4096)
	ctx := context.Background()

	var wg sync.WaitGroup
	for g := range 12 {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := range 100 {
				k := fmt.Sprintf("key-%d-%d", id%4, i%20)
				_ = b.Set(ctx, "org-1", k, []byte(`{"ok":true}`), EntryMeta{OrgID: "org-1", Model: "m1"}, time.Minute)
				val, hit, _ := b.Get(ctx, "org-1", k)
				if hit && len(val) > 0 {
					val[0] = 'X' // Mutate returned copy to verify isolation.
				}
				if i%37 == 0 {
					_, _ = b.Invalidate(ctx, "org-1", "m1")
				}
			}
		}(g)
	}
	wg.Wait()
}
