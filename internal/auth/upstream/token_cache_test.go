package upstream_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/goroute-ai/ai-gateway-go/internal/auth/upstream"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

func TestDistributedTokenCache_SingleflightAndL1(t *testing.T) {
	cache := upstream.NewDistributedTokenCache(nil, upstream.DistributedTokenCacheConfig{})

	var calls atomic.Int32
	const workers = 16
	var wg sync.WaitGroup
	wg.Add(workers)

	results := make([]string, workers)
	errs := make([]error, workers)

	for i := 0; i < workers; i++ {
		go func(idx int) {
			defer wg.Done()
			tok, err := cache.GetOrRefresh(context.Background(), "key-singleflight", func(ctx context.Context) (string, time.Duration, error) {
				calls.Add(1)
				time.Sleep(30 * time.Millisecond)
				return "tok-sf-123", 10 * time.Minute, nil
			})
			results[idx] = tok
			errs[idx] = err
		}(i)
	}
	wg.Wait()

	if calls.Load() != 1 {
		t.Fatalf("expected 1 refresh call under singleflight, got %d", calls.Load())
	}
	for i := 0; i < workers; i++ {
		if errs[i] != nil {
			t.Fatalf("worker %d failed: %v", i, errs[i])
		}
		if results[i] != "tok-sf-123" {
			t.Fatalf("worker %d got unexpected token %q", i, results[i])
		}
	}

	// Subsequent call hits L1 without refreshing.
	tok, err := cache.GetOrRefresh(context.Background(), "key-singleflight", func(ctx context.Context) (string, time.Duration, error) {
		calls.Add(1)
		return "tok-should-not-happen", 10 * time.Minute, nil
	})
	if err != nil {
		t.Fatalf("L1 hit failed: %v", err)
	}
	if tok != "tok-sf-123" || calls.Load() != 1 {
		t.Fatalf("expected cached token on L1 hit, got %q (calls=%d)", tok, calls.Load())
	}
}

func TestDistributedTokenCache_MultiPodRedisLockPreventsStampede(t *testing.T) {
	mr := miniredis.RunT(t)
	fabricA := storage.NewRedisFabric(mr.Addr(), "", 0)
	fabricB := storage.NewRedisFabric(mr.Addr(), "", 0)
	t.Cleanup(func() {
		_ = fabricA.Client().Close()
		_ = fabricB.Client().Close()
	})

	podA := upstream.NewDistributedTokenCache(fabricA, upstream.DistributedTokenCacheConfig{
		EncryptionKey:    "gateway-token-cache-test-key",
		LockTTL:          10 * time.Second,
		LockWaitTimeout:  2 * time.Second,
		LockPollInterval: 10 * time.Millisecond,
	})
	podB := upstream.NewDistributedTokenCache(fabricB, upstream.DistributedTokenCacheConfig{
		EncryptionKey:    "gateway-token-cache-test-key",
		LockTTL:          10 * time.Second,
		LockWaitTimeout:  2 * time.Second,
		LockPollInterval: 10 * time.Millisecond,
	})

	var refreshCalls atomic.Int32
	refreshFn := func(ctx context.Context) (string, time.Duration, error) {
		refreshCalls.Add(1)
		time.Sleep(80 * time.Millisecond)
		return "shared-pod-token", 5 * time.Minute, nil
	}

	// Launch concurrent refreshes on Pod A and Pod B (cold L1 and L2).
	var wg sync.WaitGroup
	wg.Add(2)
	var tokA, tokB string
	var errA, errB error

	go func() {
		defer wg.Done()
		tokA, errA = podA.GetOrRefresh(context.Background(), "multi-pod-key", refreshFn)
	}()
	go func() {
		defer wg.Done()
		// Slight stagger or simultaneous race: both miss L1/L2, one wins NX lock, other polls L2.
		tokB, errB = podB.GetOrRefresh(context.Background(), "multi-pod-key", refreshFn)
	}()
	wg.Wait()

	if errA != nil || errB != nil {
		t.Fatalf("unexpected errors: podA=%v, podB=%v", errA, errB)
	}
	if tokA != "shared-pod-token" || tokB != "shared-pod-token" {
		t.Fatalf("unexpected tokens: podA=%q, podB=%q", tokA, tokB)
	}
	if refreshCalls.Load() != 1 {
		t.Fatalf("expected exactly 1 upstream refresh across both pods, got %d", refreshCalls.Load())
	}

	// Verify no stale lock keys remain in miniredis after Lua release.
	for _, k := range mr.Keys() {
		if len(k) > len("gw:upstream_token:lock:") && k[:len("gw:upstream_token:lock:")] == "gw:upstream_token:lock:" {
			t.Fatalf("expected lock key %q to be released via Lua script", k)
		}
	}

	// Verify Redis does not store plaintext token and Pod C reads encrypted L2.
	for _, k := range mr.Keys() {
		if v, err := mr.Get(k); err == nil && strings.Contains(v, "shared-pod-token") {
			t.Fatalf("expected encrypted L2 cache value in %q, found plaintext", k)
		}
	}
	podC := upstream.NewDistributedTokenCache(fabricB, upstream.DistributedTokenCacheConfig{
		EncryptionKey: "gateway-token-cache-test-key",
	})
	tokC, err := podC.GetOrRefresh(context.Background(), "multi-pod-key", func(ctx context.Context) (string, time.Duration, error) {
		refreshCalls.Add(1)
		return "should-not-refresh", 5 * time.Minute, nil
	})
	if err != nil {
		t.Fatalf("podC L2 read failed: %v", err)
	}
	if tokC != "shared-pod-token" || refreshCalls.Load() != 1 {
		t.Fatalf("expected Pod C to hit L2, got %q (calls=%d)", tokC, refreshCalls.Load())
	}
}

func TestDistributedTokenCache_EarlyRefreshAndInvalidate(t *testing.T) {
	mr := miniredis.RunT(t)
	fabric := storage.NewRedisFabric(mr.Addr(), "", 0)
	t.Cleanup(func() { _ = fabric.Client().Close() })

	var nowMu sync.Mutex
	curNow := time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC)
	nowFn := func() time.Time {
		nowMu.Lock()
		defer nowMu.Unlock()
		return curNow
	}

	cache := upstream.NewDistributedTokenCache(fabric, upstream.DistributedTokenCacheConfig{
		EncryptionKey:    "gateway-token-cache-test-key",
		EarlyRefreshSkew: 30 * time.Second,
		Now:              nowFn,
	})

	var seq atomic.Int32
	refreshFn := func(ctx context.Context) (string, time.Duration, error) {
		n := seq.Add(1)
		return "tok-v" + string('0'+n), 120 * time.Second, nil
	}

	t1, err := cache.GetOrRefresh(context.Background(), "exp-key", refreshFn)
	if err != nil || t1 != "tok-v1" {
		t.Fatalf("expected tok-v1, got %q (err=%v)", t1, err)
	}

	// Advance 95s -> inside 30s early refresh window before 120s expiry.
	nowMu.Lock()
	curNow = curNow.Add(95 * time.Second)
	nowMu.Unlock()

	t2, err := cache.GetOrRefresh(context.Background(), "exp-key", refreshFn)
	if err != nil || t2 != "tok-v2" {
		t.Fatalf("expected early refresh to tok-v2, got %q (err=%v)", t2, err)
	}

	// Invalidate clears L1 + L2 and forces refresh on next call.
	cache.Invalidate(context.Background(), "exp-key")
	t3, err := cache.GetOrRefresh(context.Background(), "exp-key", refreshFn)
	if err != nil || t3 != "tok-v3" {
		t.Fatalf("expected tok-v3 after invalidate, got %q (err=%v)", t3, err)
	}
}

func TestDistributedTokenCache_GracefulRedisFailure(t *testing.T) {
	mr := miniredis.RunT(t)
	fabric := storage.NewRedisFabric(mr.Addr(), "", 0)
	mr.Close() // Simulate Redis outage

	cache := upstream.NewDistributedTokenCache(fabric, upstream.DistributedTokenCacheConfig{
		EncryptionKey: "gateway-token-cache-test-key",
	})

	tok, err := cache.GetOrRefresh(context.Background(), "degraded-key", func(ctx context.Context) (string, time.Duration, error) {
		return "degraded-ok-token", 5 * time.Minute, nil
	})
	if err != nil {
		t.Fatalf("expected graceful fallback when Redis is unavailable, got %v", err)
	}
	if tok != "degraded-ok-token" {
		t.Fatalf("unexpected token: %q", tok)
	}
}

func TestUpstreamStrategies_SharedDistributedTokenCacheAcrossPods(t *testing.T) {
	mr := miniredis.RunT(t)
	fabric := storage.NewRedisFabric(mr.Addr(), "", 0)
	t.Cleanup(func() { _ = fabric.Client().Close() })

	netPolicy := &network.Policy{
		AllowPrivateNetworks: true,
		AllowInsecureHTTP:    true,
	}

	t.Run("OAuth2Strategy shares L2 across instances", func(t *testing.T) {
		var calls atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "oauth2-shared-tok",
				"expires_in":   600,
			})
		}))
		defer srv.Close()

		c1 := upstream.NewDistributedTokenCache(fabric, upstream.DistributedTokenCacheConfig{EncryptionKey: "gateway-token-cache-test-key"})
		c2 := upstream.NewDistributedTokenCache(fabric, upstream.DistributedTokenCacheConfig{EncryptionKey: "gateway-token-cache-test-key"})
		s1 := upstream.NewOAuth2StrategyWithCache(srv.URL, "cid", "csec", []string{"read"}, netPolicy, c1)
		s2 := upstream.NewOAuth2StrategyWithCache(srv.URL, "cid", "csec", []string{"read"}, netPolicy, c2)

		req1, _ := http.NewRequest(http.MethodGet, "https://api.example.com", nil)
		if err := s1.Apply(context.Background(), req1, nil); err != nil {
			t.Fatalf("s1 apply failed: %v", err)
		}
		req2, _ := http.NewRequest(http.MethodGet, "https://api.example.com", nil)
		if err := s2.Apply(context.Background(), req2, nil); err != nil {
			t.Fatalf("s2 apply failed: %v", err)
		}
		if calls.Load() != 1 {
			t.Fatalf("expected 1 IdP call across two pods, got %d", calls.Load())
		}
		if req2.Header.Get("Authorization") != "Bearer oauth2-shared-tok" {
			t.Fatalf("unexpected auth header on pod 2: %q", req2.Header.Get("Authorization"))
		}

		// Tenant/server scoping must isolate tokens across CallingOrgID/ServerID.
		reqOtherOrg, _ := http.NewRequest(http.MethodGet, "https://api.example.com", nil)
		if err := s2.Apply(context.Background(), reqOtherOrg, &upstream.UpstreamAuthContext{
			CallingOrgID: "org-other",
			ServerID:     "srv-2",
		}); err != nil {
			t.Fatalf("s2 apply(org-other) failed: %v", err)
		}
		if calls.Load() != 2 {
			t.Fatalf("expected second IdP call for distinct tenant/server scope, got %d", calls.Load())
		}

		// Empty EncryptionKey disables Redis L2 sharing (no plaintext Redis leak).
		noKeyMr := miniredis.RunT(t)
		noKeyFabric := storage.NewRedisFabric(noKeyMr.Addr(), "", 0)
		defer func() { _ = noKeyFabric.Client().Close() }()
		cNoKey := upstream.NewDistributedTokenCache(noKeyFabric, upstream.DistributedTokenCacheConfig{})
		sNoKey := upstream.NewOAuth2StrategyWithCache(srv.URL, "cid", "csec", []string{"read"}, netPolicy, cNoKey)
		reqNoKey, _ := http.NewRequest(http.MethodGet, "https://api.example.com", nil)
		if err := sNoKey.Apply(context.Background(), reqNoKey, nil); err != nil {
			t.Fatalf("sNoKey apply failed: %v", err)
		}
		if len(noKeyMr.Keys()) != 0 {
			t.Fatalf("expected empty Redis when EncryptionKey is unset, got keys %v", noKeyMr.Keys())
		}
	})

	t.Run("TokenExchangeStrategy shares L2 across instances", func(t *testing.T) {
		var calls atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "rfc8693-shared-tok",
				"expires_in":   600,
			})
		}))
		defer srv.Close()

		c1 := upstream.NewDistributedTokenCache(fabric, upstream.DistributedTokenCacheConfig{EncryptionKey: "gateway-token-cache-test-key"})
		c2 := upstream.NewDistributedTokenCache(fabric, upstream.DistributedTokenCacheConfig{EncryptionKey: "gateway-token-cache-test-key"})

		s1, err := upstream.NewTokenExchangeStrategy(upstream.TokenExchangeConfig{
			TokenEndpoint: srv.URL,
			ClientID:      "gw",
			ClientSecret:  "sec",
			Resource:      "https://mcp.internal/tools",
			NetPolicy:     netPolicy,
			TokenCache:    c1,
		})
		if err != nil {
			t.Fatalf("s1 init: %v", err)
		}
		s2, err := upstream.NewTokenExchangeStrategy(upstream.TokenExchangeConfig{
			TokenEndpoint: srv.URL,
			ClientID:      "gw",
			ClientSecret:  "sec",
			Resource:      "https://mcp.internal/tools",
			NetPolicy:     netPolicy,
			TokenCache:    c2,
		})
		if err != nil {
			t.Fatalf("s2 init: %v", err)
		}

		authCtx := &upstream.UpstreamAuthContext{DelegatedToken: "sub-tok-abc"}
		req1, _ := http.NewRequest(http.MethodGet, "https://mcp.internal/tools", nil)
		if err := s1.Apply(context.Background(), req1, authCtx); err != nil {
			t.Fatalf("s1 apply: %v", err)
		}
		req2, _ := http.NewRequest(http.MethodGet, "https://mcp.internal/tools", nil)
		if err := s2.Apply(context.Background(), req2, authCtx); err != nil {
			t.Fatalf("s2 apply: %v", err)
		}
		if calls.Load() != 1 {
			t.Fatalf("expected 1 RFC8693 call across two pods, got %d", calls.Load())
		}
		if req2.Header.Get("Authorization") != "Bearer rfc8693-shared-tok" {
			t.Fatalf("unexpected auth header on pod 2: %q", req2.Header.Get("Authorization"))
		}
	})

	t.Run("OktaIDJAGStrategy shares L2 across instances", func(t *testing.T) {
		var calls atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"access_token": "okta-shared-tok",
				"expires_in":   600,
			})
		}))
		defer srv.Close()

		c1 := upstream.NewDistributedTokenCache(fabric, upstream.DistributedTokenCacheConfig{EncryptionKey: "gateway-token-cache-test-key"})
		c2 := upstream.NewDistributedTokenCache(fabric, upstream.DistributedTokenCacheConfig{EncryptionKey: "gateway-token-cache-test-key"})

		s1, err := upstream.NewOktaIDJAGStrategy(upstream.OktaIDJAGConfig{
			TokenEndpoint: srv.URL,
			ClientID:      "cid",
			Audience:      "aud",
			SigningKey:    "hmac-signing-key",
			NetPolicy:     netPolicy,
			TokenCache:    c1,
		})
		if err != nil {
			t.Fatalf("s1 init: %v", err)
		}
		s2, err := upstream.NewOktaIDJAGStrategy(upstream.OktaIDJAGConfig{
			TokenEndpoint: srv.URL,
			ClientID:      "cid",
			Audience:      "aud",
			SigningKey:    "hmac-signing-key",
			NetPolicy:     netPolicy,
			TokenCache:    c2,
		})
		if err != nil {
			t.Fatalf("s2 init: %v", err)
		}

		authCtx := &upstream.UpstreamAuthContext{CallingUserID: "usr_1"}
		req1, _ := http.NewRequest(http.MethodGet, "https://api.example.com", nil)
		if err := s1.Apply(context.Background(), req1, authCtx); err != nil {
			t.Fatalf("s1 apply: %v", err)
		}
		req2, _ := http.NewRequest(http.MethodGet, "https://api.example.com", nil)
		if err := s2.Apply(context.Background(), req2, authCtx); err != nil {
			t.Fatalf("s2 apply: %v", err)
		}
		if calls.Load() != 1 {
			t.Fatalf("expected 1 Okta ID-JAG call across two pods, got %d", calls.Load())
		}
		if req2.Header.Get("Authorization") != "Bearer okta-shared-tok" {
			t.Fatalf("unexpected auth header on pod 2: %q", req2.Header.Get("Authorization"))
		}
	})
}
