package router

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/observability"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

func testCRC16ClusterSlot(key string) uint16 {
	hashKey := key
	if s := strings.IndexByte(key, '{'); s >= 0 {
		if e := strings.IndexByte(key[s+1:], '}'); e > 0 {
			hashKey = key[s+1 : s+1+e]
		}
	}
	var crc uint16
	for i := 0; i < len(hashKey); i++ {
		crc ^= uint16(hashKey[i]) << 8
		for b := 0; b < 8; b++ {
			if crc&0x8000 != 0 {
				crc = (crc << 1) ^ 0x1021
			} else {
				crc <<= 1
			}
		}
	}
	return crc % 16384
}

func TestAffinityKeysAlignToOrgClusterSlot(t *testing.T) {
	for _, orgID := range []string{"org_alpha", ""} {
		kResp := ResponseAffinityKey(orgID, "resp_123")
		kSess := SessionAffinityKey(orgID, "sess_456")
		kPCache := PromptCacheAffinityKey(orgID, "fast", "deadbeef")

		wantTag := "{org:" + orgID + "}"
		if orgID == "" {
			wantTag = "{org:default}"
		}
		for _, k := range []string{kResp, kSess, kPCache} {
			if !strings.Contains(k, wantTag) {
				t.Fatalf("key %q missing hash tag %q", k, wantTag)
			}
		}
		slot := testCRC16ClusterSlot(kResp)
		if testCRC16ClusterSlot(kSess) != slot || testCRC16ClusterSlot(kPCache) != slot {
			t.Fatalf("affinity keys do not share Redis Cluster slot: resp=%d sess=%d pcache=%d",
				slot, testCRC16ClusterSlot(kSess), testCRC16ClusterSlot(kPCache))
		}
	}
}

func TestAffinityStore_PrecedenceAndSelectOrPin(t *testing.T) {
	store := NewAffinityStore(nil, AffinityConfig{
		DefaultTTL:                10 * time.Minute,
		RepinOnFailover:           true,
		PromptCacheAffinity:       true,
		PromptCachePrefixMessages: 2,
	})
	ctx := context.Background()

	req := &domain.CanonicalChatRequest{
		Model: "fast",
		Messages: []domain.CanonicalMessage{
			{Role: "system", Content: "You are concise."},
			{Role: "user", Content: "Explain affinity."},
		},
		GoRouteExtensions: &domain.GoRouteExtensions{
			SessionID:             "sess-1",
			PreferredDeploymentID: "dep-preferred",
		},
	}

	respKey := ResponseAffinityKey("org-1", "resp-1")
	sessKey := SessionAffinityKey("org-1", "sess-1")
	pcacheKey := PromptCacheAffinityKey("org-1", "fast", ComputePromptPrefixHash(req, 2))

	store.PinAsync("org-1", pcacheKey, "dep-pcache", time.Minute)
	store.PinAsync("org-1", sessKey, "dep-sess", time.Minute)
	store.PinAsync("org-1", respKey, "dep-resp", time.Minute)

	// 1. PreferredDeploymentID wins over respID, sessionID, and pcache.
	depID, key := store.Lookup(ctx, "org-1", "fast", req, "resp-1")
	if depID != "dep-preferred" || key != respKey {
		t.Fatalf("expected (dep-preferred, %s), got (%s, %s)", respKey, depID, key)
	}

	// 2. Without PreferredDeploymentID, respID wins over sessionID and pcache.
	req.GoRouteExtensions.PreferredDeploymentID = ""
	depID, key = store.Lookup(ctx, "org-1", "fast", req, "resp-1")
	if depID != "dep-resp" || key != respKey {
		t.Fatalf("expected (dep-resp, %s), got (%s, %s)", respKey, depID, key)
	}

	// 3. Without prevRespID, sessionID wins over pcache.
	depID, key = store.Lookup(ctx, "org-1", "fast", req, "")
	if depID != "dep-sess" || key != sessKey {
		t.Fatalf("expected (dep-sess, %s), got (%s, %s)", sessKey, depID, key)
	}

	// 4. Without sessionID, pcache applies.
	req.GoRouteExtensions.SessionID = ""
	depID, key = store.Lookup(ctx, "org-1", "fast", req, "")
	if depID != "dep-pcache" || key != pcacheKey {
		t.Fatalf("expected (dep-pcache, %s), got (%s, %s)", pcacheKey, depID, key)
	}

	// SelectOrPin matches healthy candidate and fails cleanly when absent.
	c1 := &domain.Deployment{ID: "dep-pcache"}
	c2 := &domain.Deployment{ID: "dep-other"}
	picked, ok := store.SelectOrPin("dep-pcache", []*domain.Deployment{c2, c1})
	if !ok || picked != c1 {
		t.Fatalf("expected SelectOrPin to find dep-pcache, got (%v, %v)", picked, ok)
	}
	if picked, ok := store.SelectOrPin("dep-missing", []*domain.Deployment{c2, c1}); ok || picked != nil {
		t.Fatalf("expected SelectOrPin miss to return (nil, false), got (%v, %v)", picked, ok)
	}

	// Failover re-pinning overwrites local entry synchronously.
	store.PinAsync("org-1", key, "dep-other", time.Minute)
	depID, _ = store.Lookup(ctx, "org-1", "fast", req, "")
	if depID != "dep-other" {
		t.Fatalf("expected re-pinned dep-other, got %q", depID)
	}
}

func TestAffinityStore_LRUEvictionAndExpiry(t *testing.T) {
	now := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	store := NewAffinityStore(nil, AffinityConfig{
		MaxLocalEntries: 2,
		DefaultTTL:      5 * time.Minute,
	})
	store.nowFn = func() time.Time { return now }

	k1 := SessionAffinityKey("org-1", "s1")
	k2 := SessionAffinityKey("org-1", "s2")
	k3 := SessionAffinityKey("org-1", "s3")

	store.PinAsync("org-1", k1, "dep-1", 5*time.Minute)
	store.PinAsync("org-1", k2, "dep-2", 5*time.Minute)

	// Access k1 so k2 becomes least-recently-used.
	req1 := &domain.CanonicalChatRequest{GoRouteExtensions: &domain.GoRouteExtensions{SessionID: "s1"}}
	if dep, _ := store.Lookup(context.Background(), "org-1", "fast", req1, ""); dep != "dep-1" {
		t.Fatalf("expected dep-1, got %q", dep)
	}

	// Inserting k3 must evict k2 while preserving k1.
	store.PinAsync("org-1", k3, "dep-3", 5*time.Minute)
	if store.lru.len() != 2 {
		t.Fatalf("expected LRU len=2, got %d", store.lru.len())
	}
	req2 := &domain.CanonicalChatRequest{GoRouteExtensions: &domain.GoRouteExtensions{SessionID: "s2"}}
	if dep, _ := store.Lookup(context.Background(), "org-1", "fast", req2, ""); dep != "" {
		t.Fatalf("expected evicted k2 to miss, got %q", dep)
	}
	if dep, _ := store.Lookup(context.Background(), "org-1", "fast", req1, ""); dep != "dep-1" {
		t.Fatalf("expected k1 to remain in LRU, got %q", dep)
	}

	// Advance clock past TTL -> entry expires on lookup.
	now = now.Add(6 * time.Minute)
	if dep, _ := store.Lookup(context.Background(), "org-1", "fast", req1, ""); dep != "" {
		t.Fatalf("expected expired k1 to miss, got %q", dep)
	}
}

func TestAffinityStore_PromptCachePrefixStabilityAndDisabled(t *testing.T) {
	reqTurn1 := &domain.CanonicalChatRequest{
		Messages: []domain.CanonicalMessage{
			{Role: "system", Content: "System instructions"},
			{Role: "user", Content: "First question"},
		},
	}
	reqTurn2 := &domain.CanonicalChatRequest{
		Messages: []domain.CanonicalMessage{
			{Role: "system", Content: "System instructions"},
			{Role: "user", Content: "First question"},
			{Role: "assistant", Content: "First answer"},
			{Role: "user", Content: "Follow-up question"},
		},
	}

	h1 := ComputePromptPrefixHash(reqTurn1, 2)
	h2 := ComputePromptPrefixHash(reqTurn2, 2)
	if h1 == "" || h1 != h2 {
		t.Fatalf("expected identical prompt prefix hash across turns, got %q vs %q", h1, h2)
	}

	disabled := NewAffinityStoreFromRouterConfig(nil, config.RouterConfig{PromptCacheAffinity: false})
	if dep, key := disabled.Lookup(context.Background(), "org-1", "fast", reqTurn1, ""); dep != "" || key != "" {
		t.Fatalf("expected empty lookup when prompt cache affinity is disabled, got (%q, %q)", dep, key)
	}
}

func TestAffinityStore_MiniredisCrossPodAndDegradation(t *testing.T) {
	mr := miniredis.RunT(t)
	fabric := storage.NewRedisFabric(mr.Addr(), "", 0)
	t.Cleanup(func() { _ = fabric.Client().Close() })

	col := observability.NewCollector()
	podA := NewAffinityStoreFromRouterConfig(fabric, config.RouterConfig{
		SessionAffinityTTL:             15 * time.Minute,
		SessionAffinityRepinOnFailover: true,
		PromptCacheAffinity:            true,
	})
	podA.SetCollector(col)
	podB := NewAffinityStoreFromRouterConfig(fabric, config.RouterConfig{
		SessionAffinityTTL:             15 * time.Minute,
		SessionAffinityRepinOnFailover: true,
		PromptCacheAffinity:            true,
	})
	podB.SetCollector(col)

	ctx := context.Background()
	req := &domain.CanonicalChatRequest{
		GoRouteExtensions: &domain.GoRouteExtensions{SessionID: "sess-cross-pod"},
	}

	// Miss on Pod A returns the key so caller can pin the chosen deployment.
	depID, key := podA.Lookup(ctx, "org-1", "fast", req, "")
	if depID != "" || key != SessionAffinityKey("org-1", "sess-cross-pod") {
		t.Fatalf("unexpected initial lookup: depID=%q key=%q", depID, key)
	}

	podA.PinAsync("org-1", key, "dep-primary", 15*time.Minute)
	if err := podA.Wait(ctx); err != nil {
		t.Fatalf("Wait failed: %v", err)
	}

	gotRedis, err := mr.Get(key)
	if err != nil || gotRedis != "dep-primary" {
		t.Fatalf("expected Redis key %q=dep-primary, got %q (err=%v)", key, gotRedis, err)
	}

	// Pod B (cold local LRU) reads from Redis and backfills its local LRU.
	depID, gotKey := podB.Lookup(ctx, "org-1", "fast", req, "")
	if depID != "dep-primary" || gotKey != key {
		t.Fatalf("expected Pod B to resolve dep-primary from Redis, got (%q, %q)", depID, gotKey)
	}

	// Close Redis -> Pod B still hits its backfilled local LRU; uncached key degrades cleanly.
	mr.Close()
	depID, _ = podB.Lookup(ctx, "org-1", "fast", req, "")
	if depID != "dep-primary" {
		t.Fatalf("expected Pod B local LRU hit after Redis close, got %q", depID)
	}

	reqMiss := &domain.CanonicalChatRequest{
		GoRouteExtensions: &domain.GoRouteExtensions{SessionID: "sess-uncached"},
	}
	depID, missKey := podB.Lookup(ctx, "org-1", "fast", reqMiss, "")
	if depID != "" || missKey != SessionAffinityKey("org-1", "sess-uncached") {
		t.Fatalf("unexpected degraded lookup result: depID=%q key=%q", depID, missKey)
	}
	if snap := col.Snapshot(); snap.RoutingSignalDegradedTotal == 0 {
		t.Fatalf("expected RoutingSignalDegradedTotal > 0 after Redis outage, got 0")
	}

	// PinAsync still works locally during Redis outage without panicking.
	podB.PinAsync("org-1", missKey, "dep-fallback", 5*time.Minute)
	_ = podB.Wait(ctx)
	if depID, _ := podB.Lookup(ctx, "org-1", "fast", reqMiss, ""); depID != "dep-fallback" {
		t.Fatalf("expected local LRU hit during Redis outage, got %q", depID)
	}
}

func TestAffinityStore_ConcurrentRace(t *testing.T) {
	mr := miniredis.RunT(t)
	fabric := storage.NewRedisFabric(mr.Addr(), "", 0)
	t.Cleanup(func() { _ = fabric.Client().Close() })

	store := NewAffinityStore(fabric, AffinityConfig{
		MaxLocalEntries:     64,
		DefaultTTL:          time.Minute,
		PromptCacheAffinity: true,
	})
	ctx := context.Background()
	candidates := []*domain.Deployment{{ID: "dep-1"}, {ID: "dep-2"}}

	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				req := &domain.CanonicalChatRequest{
					GoRouteExtensions: &domain.GoRouteExtensions{
						SessionID: fmt.Sprintf("sess-%d", (id+i)%10),
					},
					Messages: []domain.CanonicalMessage{{Role: "user", Content: fmt.Sprintf("msg-%d", i%5)}},
				}
				depID, key := store.Lookup(ctx, "org-race", "fast", req, "")
				if _, ok := store.SelectOrPin(depID, candidates); !ok && key != "" {
					store.PinAsync("org-race", key, candidates[i%2].ID, time.Minute)
				}
			}
		}(g)
	}
	wg.Wait()
	if err := store.Wait(ctx); err != nil {
		t.Fatalf("Wait failed: %v", err)
	}
}
