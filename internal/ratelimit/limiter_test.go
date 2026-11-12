package ratelimit_test

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/goroute-ai/ai-gateway-go/internal/cache"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/ratelimit"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

func TestRateLimiterRPMTPMConcurrencyBudgetAndResponseCache(t *testing.T) {
	ctx := context.Background()
	limiter := ratelimit.NewLimiter(nil, 60, 300)

	idCtx := &domain.IdentityContext{
		VirtualKeyID:     "vk-1",
		OrgID:            "org-1",
		KeyRPMLimit:      2,
		KeyTPMLimit:      100,
		KeyMaxConcurrent: 1,
	}

	req := &domain.CanonicalChatRequest{
		Model:    "gpt-4.1",
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "Hello world"}},
	}
	est := ratelimit.EstimateRequestTokens(req)
	if est <= 0 {
		t.Fatalf("expected positive token estimate, got %d", est)
	}

	// Verify model-specific tokenizer profiles
	if prof := ratelimit.ResolveTokenizerProfile("gpt-4.1"); prof != ratelimit.ProfileO200K {
		t.Fatalf("expected o200k_base for gpt-4.1, got %s", prof)
	}
	if prof := ratelimit.ResolveTokenizerProfile("claude-sonnet-4-20250514"); prof != ratelimit.ProfileClaudeBPE {
		t.Fatalf("expected claude_bpe for claude-sonnet-4, got %s", prof)
	}
	if prof := ratelimit.ResolveTokenizerProfile("gemini-2.5-flash"); prof != ratelimit.ProfileGeminiSP {
		t.Fatalf("expected gemini_sp for gemini-2.5-flash, got %s", prof)
	}

	// 1. Acquire #1 succeeds
	release1, err := limiter.Acquire(ctx, idCtx, 30)
	if err != nil {
		t.Fatalf("acquire #1 failed: %v", err)
	}

	// 2. While #1 is still in-flight, KeyMaxConcurrent=1 blocks a concurrent request
	if _, err := limiter.Acquire(ctx, idCtx, 10); err == nil {
		t.Fatalf("expected concurrency limit (1) to block second concurrent request")
	}

	// Release #1
	release1(25)

	// 3. Acquire #2 now succeeds, but a request exceeding TPM (100) is blocked
	if _, err := limiter.Acquire(ctx, idCtx, 90); err == nil {
		t.Fatalf("expected TPM limit (100) to block 25 + 90 = 115 tokens")
	}

	release2, err := limiter.Acquire(ctx, idCtx, 20)
	if err != nil {
		t.Fatalf("acquire #2 failed: %v", err)
	}
	release2(20)

	// 4. Acquire #3 exceeds RPM limit (2)
	if _, err := limiter.Acquire(ctx, idCtx, 5); err == nil {
		t.Fatalf("expected RPM limit (2) to block 3rd request in same minute")
	}

	// 5. Budget Exceeded test
	overBudgetCtx := &domain.IdentityContext{
		VirtualKeyID:       "vk-budget",
		OrgID:              "org-1",
		KeyMaxBudgetMicros: 1000,
		KeySpentMicros:     1000,
	}
	if _, err := limiter.Acquire(ctx, overBudgetCtx, 5); err == nil {
		t.Fatalf("expected budget exceeded error")
	}

	// 6. Test Distributed Fallback Modes (local_divided_by_replicas & fail_closed)
	scaledLimiter := ratelimit.NewLimiter(nil, 60, 300)
	scaledLimiter.SetFallbackPolicy(ratelimit.FallbackLocalDividedByReplicas, 4) // 4 pods -> RPM=8 becomes 2 per pod
	podCtx := &domain.IdentityContext{
		VirtualKeyID: "vk-pod",
		OrgID:        "org-1",
		KeyRPMLimit:  8,
	}
	r1, err := scaledLimiter.Acquire(ctx, podCtx, 1)
	if err != nil {
		t.Fatalf("pod acquire #1 failed: %v", err)
	}
	r1(1)
	r2, err := scaledLimiter.Acquire(ctx, podCtx, 1)
	if err != nil {
		t.Fatalf("pod acquire #2 failed: %v", err)
	}
	r2(1)
	if _, err := scaledLimiter.Acquire(ctx, podCtx, 1); err == nil {
		t.Fatalf("expected scaled per-pod limit (8/4 = 2 RPM) to block 3rd request")
	}

	scaledLimiter.SetFallbackPolicy(ratelimit.FallbackFailClosed, 4)
	if _, err := scaledLimiter.Acquire(ctx, podCtx, 1); err == nil {
		t.Fatalf("expected fail_closed fallback mode to reject request when Redis is absent")
	}

	// 7. Test Exact-Match Response Cache + Safe Cache Invalidation
	rc := cache.NewResponseCache(true, time.Minute, nil)
	zero := 0.0
	req.Temperature = &zero
	if !rc.IsCacheable(req, "") {
		t.Fatalf("expected temperature=0 request to be cacheable")
	}
	ck := rc.ComputeKey("org-1", req)
	rc.SetWithMeta(ctx, ck, "org-1", &domain.CanonicalChatResponse{ID: "cached-1", Model: "gpt-4.1"})
	got, hit := rc.Get(ctx, ck)
	if !hit || got.ID != "cached-1" {
		t.Fatalf("expected cache hit for key %s", ck)
	}

	purged, _ := rc.Invalidate(ctx, "org-1", "")
	if purged != 1 {
		t.Fatalf("expected 1 purged cache entry for org-1, got %d", purged)
	}
	if _, hitAfter := rc.Get(ctx, ck); hitAfter {
		t.Fatalf("expected cache miss after org invalidation")
	}
}

func TestBudgetReservationsAreAtomicAcrossLimiterInstances(t *testing.T) {
	mr := miniredis.RunT(t)
	redisFabric := storage.NewRedisFabric(mr.Addr(), "", 0)
	t.Cleanup(func() { _ = redisFabric.Client().Close() })
	first := ratelimit.NewLimiter(redisFabric, 60, 300)
	second := ratelimit.NewLimiter(redisFabric, 60, 300)
	identity := &domain.IdentityContext{VirtualKeyID: "budget-key", OrgID: "budget-org", KeyMaxBudgetMicros: 100}

	r1, err := first.AcquireWithBudget(context.Background(), identity, 10, 60, "request-1")
	if err != nil {
		t.Fatalf("first reservation: %v", err)
	}
	if _, err := second.AcquireWithBudget(context.Background(), identity, 10, 60, "request-2"); err == nil {
		t.Fatal("expected concurrent reservation to be rejected when total upper bounds exceed budget")
	}
	r1(-1, 0) // failed request releases its reservation
	if members, _ := mr.ZMembers("gw:budget:reservations:key:budget-key"); len(members) != 0 {
		t.Fatalf("reservation should be released, remain: %v", members)
	}
	r2, err := second.AcquireWithBudget(context.Background(), identity, 10, 60, "request-3")
	if err != nil {
		t.Fatalf("reservation after release: %v", err)
	}
	r2(10, -2)
	second.RecordSpendIncrementForRequest(context.Background(), "request-3", "budget-key", "", "budget-org", 45)
	if got, _ := mr.Get("gw:spend:key:budget-key"); got != "45" {
		t.Fatalf("actual spend = %q, want 45", got)
	}

	// Concurrent calls on independent limiter instances must not oversubscribe.
	identity.KeyMaxBudgetMicros = 100
	var wg sync.WaitGroup
	var admitted atomic.Int32
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			lim := first
			if i%2 == 1 {
				lim = second
			}
			if _, err := lim.AcquireWithBudget(context.Background(), identity, 1, 30, fmt.Sprintf("concurrent-%d", i)); err == nil {
				admitted.Add(1)
			}
		}(i)
	}
	wg.Wait()
	if got := admitted.Load(); got != 1 {
		t.Fatalf("admitted %d concurrent reservations, want 1 after 45 micros spent", got)
	}
}
