package ratelimit

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

func TestBatchEnqueuedTokens_RedisMultiScopeAcquireAndRelease(t *testing.T) {
	mr := miniredis.RunT(t)
	redisFabric := storage.NewRedisFabric(mr.Addr(), "", 0)
	t.Cleanup(func() { _ = redisFabric.Client().Close() })
	limiter := NewLimiter(redisFabric, 60, 300)
	ctx := context.Background()

	idA := &domain.IdentityContext{
		VirtualKeyID:                "vk-batch-a",
		TeamID:                      "team-batch-1",
		UserID:                      "user-batch-a",
		OrgID:                       "org-batch-1",
		KeyBatchEnqueuedTokenLimit:  1000,
		TeamBatchEnqueuedTokenLimit: 1500,
		UserBatchEnqueuedTokenLimit: 1500,
		OrgBatchEnqueuedTokenLimit:  2000,
	}

	// Acquire batch-1 (800 tokens)
	if err := limiter.AcquireBatchEnqueuedTokens(ctx, idA, "batch-1", 800); err != nil {
		t.Fatalf("AcquireBatchEnqueuedTokens(batch-1): %v", err)
	}

	// Verify slot-aligned Redis keys exist with expected sums.
	for _, sumKey := range []string{
		"gw:batch:{org:org-batch-1}:enqueued:key:vk-batch-a:sum",
		"gw:batch:{org:org-batch-1}:enqueued:team:team-batch-1:sum",
		"gw:batch:{org:org-batch-1}:enqueued:user:user-batch-a:sum",
		"gw:batch:{org:org-batch-1}:enqueued:org:org-batch-1:sum",
	} {
		got, err := mr.Get(sumKey)
		if err != nil || got != "800" {
			t.Fatalf("key %s = %q (err=%v), want 800", sumKey, got, err)
		}
	}

	// Second batch for same key (300 tokens) exceeds key limit (800+300 > 1000) and must not mutate team/user/org sums.
	err := limiter.AcquireBatchEnqueuedTokens(ctx, idA, "batch-2", 300)
	var gwErr *domain.GatewayError
	if !errors.As(err, &gwErr) || gwErr.StatusCode != http.StatusTooManyRequests || gwErr.Code != "key_batch_enqueued_tokens_exceeded" {
		t.Fatalf("expected 429 key_batch_enqueued_tokens_exceeded, got %v", err)
	}
	if got, _ := mr.Get("gw:batch:{org:org-batch-1}:enqueued:org:org-batch-1:sum"); got != "800" {
		t.Fatalf("org sum mutated on rejected acquire: got %q, want 800", got)
	}

	// Another key in same team/org hits team limit (800+800 > 1500).
	idB := &domain.IdentityContext{
		VirtualKeyID:                "vk-batch-b",
		TeamID:                      "team-batch-1",
		UserID:                      "user-batch-b",
		OrgID:                       "org-batch-1",
		KeyBatchEnqueuedTokenLimit:  1000,
		TeamBatchEnqueuedTokenLimit: 1500,
		UserBatchEnqueuedTokenLimit: 1500,
		OrgBatchEnqueuedTokenLimit:  2000,
	}
	err = limiter.AcquireBatchEnqueuedTokens(ctx, idB, "batch-b1", 800)
	if !errors.As(err, &gwErr) || gwErr.Code != "team_batch_enqueued_tokens_exceeded" {
		t.Fatalf("expected team_batch_enqueued_tokens_exceeded, got %v", err)
	}

	// Release batch-1 via an org admin identity (different key/user) using stored meta key.
	adminCaller := &domain.IdentityContext{
		VirtualKeyID: "vk-admin",
		OrgID:        "org-batch-1",
	}
	if err := limiter.ReleaseBatchEnqueuedTokens(ctx, adminCaller, "batch-1"); err != nil {
		t.Fatalf("ReleaseBatchEnqueuedTokens: %v", err)
	}
	// Idempotent second release must succeed without underflowing.
	if err := limiter.ReleaseBatchEnqueuedTokens(ctx, idA, "batch-1"); err != nil {
		t.Fatalf("ReleaseBatchEnqueuedTokens (idempotent): %v", err)
	}

	for _, sumKey := range []string{
		"gw:batch:{org:org-batch-1}:enqueued:key:vk-batch-a:sum",
		"gw:batch:{org:org-batch-1}:enqueued:team:team-batch-1:sum",
		"gw:batch:{org:org-batch-1}:enqueued:user:user-batch-a:sum",
		"gw:batch:{org:org-batch-1}:enqueued:org:org-batch-1:sum",
	} {
		got, err := mr.Get(sumKey)
		if err != nil || got != "0" {
			t.Fatalf("after release key %s = %q (err=%v), want 0", sumKey, got, err)
		}
	}

	// Re-acquire after release succeeds.
	if err := limiter.AcquireBatchEnqueuedTokens(ctx, idA, "batch-3", 900); err != nil {
		t.Fatalf("re-acquire after release failed: %v", err)
	}
}

func TestBatchEnqueuedTokens_LocalFallbackAndFailClosed(t *testing.T) {
	ctx := context.Background()
	id := &domain.IdentityContext{
		VirtualKeyID:                "vk-local",
		TeamID:                      "team-local",
		UserID:                      "user-local",
		OrgID:                       "org-local",
		KeyBatchEnqueuedTokenLimit:  500,
		OrgBatchEnqueuedTokenLimit:  1000,
		UserBatchEnqueuedTokenLimit: 600,
	}

	// Fail closed when Redis is nil and fallbackLocal is false.
	failClosedLimiter := NewLimiter(nil, 60, 300)
	err := failClosedLimiter.AcquireBatchEnqueuedTokens(ctx, id, "batch-fc", 100)
	var gwErr *domain.GatewayError
	if !errors.As(err, &gwErr) || gwErr.StatusCode != http.StatusServiceUnavailable || gwErr.Code != "rate_limiter_unavailable" {
		t.Fatalf("expected 503 rate_limiter_unavailable, got %v", err)
	}

	// Enforce in-memory when fallbackLocal is enabled.
	localLimiter := NewLimiter(nil, 60, 300)
	localLimiter.SetFallbackToLocalOnOutage(true)

	if err := localLimiter.AcquireBatchEnqueuedTokens(ctx, id, "batch-l1", 400); err != nil {
		t.Fatalf("local acquire 1: %v", err)
	}
	err = localLimiter.AcquireBatchEnqueuedTokens(ctx, id, "batch-l2", 200)
	if !errors.As(err, &gwErr) || gwErr.StatusCode != http.StatusTooManyRequests || gwErr.Code != "key_batch_enqueued_tokens_exceeded" {
		t.Fatalf("expected 429 key_batch_enqueued_tokens_exceeded, got %v", err)
	}
	if err := localLimiter.ReleaseBatchEnqueuedTokens(ctx, &domain.IdentityContext{OrgID: "org-local"}, "batch-l1"); err != nil {
		t.Fatalf("local release: %v", err)
	}
	if err := localLimiter.AcquireBatchEnqueuedTokens(ctx, id, "batch-l2", 500); err != nil {
		t.Fatalf("local re-acquire after release failed: %v", err)
	}
}

func TestAcquireSession_BudgetAndRateLimits(t *testing.T) {
	mr := miniredis.RunT(t)
	redisFabric := storage.NewRedisFabric(mr.Addr(), "", 0)
	t.Cleanup(func() { _ = redisFabric.Client().Close() })
	limiter := NewLimiter(redisFabric, 60, 300)
	ctx := context.Background()

	id := &domain.IdentityContext{
		VirtualKeyID:       "vk-ws",
		OrgID:              "org-ws",
		KeyMaxConcurrent:   1,
		KeyMaxBudgetMicros: 100,
	}

	relSession, err := limiter.AcquireSession(ctx, id)
	if err != nil {
		t.Fatalf("first AcquireSession failed: %v", err)
	}

	// Second concurrent session is rejected by KeyMaxConcurrent=1.
	_, err = limiter.AcquireSession(ctx, id)
	var gwErr *domain.GatewayError
	if !errors.As(err, &gwErr) || gwErr.Code != "key_concurrency_exceeded" {
		t.Fatalf("expected key_concurrency_exceeded, got %v", err)
	}

	// Full 100 micro-dollar budget must still be available for a turn inside the open session
	// (with concurrency checked at session level rather than double-counted per turn).
	turnID := *id
	turnID.KeyMaxConcurrent = 0
	relTurn, err := limiter.AcquireWithBudget(ctx, &turnID, 10, 100, "turn-1")
	if err != nil {
		t.Fatalf("AcquireWithBudget inside open session failed: %v", err)
	}
	relTurn(10, 100)
	if err := limiter.RecordSpendIncrementForUserEvent(ctx, "ev-ws-1", "turn-1", id.VirtualKeyID, "", "", id.OrgID, 100); err != nil {
		t.Fatalf("RecordSpendIncrementForUserEvent: %v", err)
	}

	relSession()

	// Exhausted budget rejects new session upgrade with 429 key_budget_exceeded.
	_, err = limiter.AcquireSession(ctx, id)
	if !errors.As(err, &gwErr) || gwErr.StatusCode != http.StatusTooManyRequests || gwErr.Code != "key_budget_exceeded" {
		t.Fatalf("expected 429 key_budget_exceeded on exhausted session upgrade, got %v", err)
	}
}
