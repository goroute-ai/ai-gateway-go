package server_test

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/ratelimit"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

func TestBudgetImmediateIdempotentSettlementAndConcurrentBurst(t *testing.T) {
	mr := miniredis.RunT(t)
	rf := storage.NewRedisFabric(mr.Addr(), "", 0)
	if c := rf.Client(); c != nil {
		defer c.Close()
	}

	limiter := ratelimit.NewLimiter(rf, 60, 300)
	ctx := context.Background()

	idCtx := &domain.IdentityContext{
		OrgID:              "org-burst",
		TeamID:             "team-burst",
		UserID:             "usr-burst",
		VirtualKeyID:       "vk-burst",
		KeyMaxBudgetMicros: 50,
	}

	t.Run("ImmediateIdempotentSettlement settles instantly with zero double count on SpendWorker replay", func(t *testing.T) {
		// Request 1 reserves 40 µ$ (upper bound), finishes with actual cost 35 µ$ using shared settlementID.
		rel1, _, _, err := limiter.AcquireWithBudgetAndSettlementIDWithMeta(ctx, idCtx, 100, 40, "req-1", "evt-1")
		if err != nil {
			t.Fatalf("acquire req-1: %v", err)
		}
		// Immediately settle at 35 µ$ (no sleep, no waiting for SpendWorker!).
		rel1(100, 35)

		// Now 15 µ$ remain immediately! Request 2 needing 15 µ$ MUST succeed immediately (no stale 40 µ$ lockout).
		rel2, _, _, err := limiter.AcquireWithBudgetAndSettlementIDWithMeta(ctx, idCtx, 50, 15, "req-2", "evt-2")
		if err != nil {
			t.Fatalf("expected req-2 (15 µ$) to pass immediately after req-1 settled to 35 µ$, got: %v", err)
		}
		rel2(50, 15)

		// Budget is now 35 + 15 = 50 µ$ (exact limit). Next request needing 1 µ$ MUST fail immediately with 429!
		if _, _, _, err := limiter.AcquireWithBudgetAndSettlementIDWithMeta(ctx, idCtx, 10, 1, "req-3", "evt-3"); err == nil {
			t.Fatalf("expected immediate budget_exceeded after 50/50 µ$ settled")
		}

		// Simulate SpendWorker flushing evt-1 & evt-2 200ms later: MUST be an idempotent no-op in Redis (zero double-count)!
		errs := limiter.RecordSpendIncrementsBatch(ctx, []ratelimit.SpendIncrementEvent{
			{EventID: "evt-1", RequestID: "req-1", VirtualKeyID: "vk-burst", TeamID: "team-burst", UserID: "usr-burst", OrgID: "org-burst", CostMicros: 35},
			{EventID: "evt-2", RequestID: "req-2", VirtualKeyID: "vk-burst", TeamID: "team-burst", UserID: "usr-burst", OrgID: "org-burst", CostMicros: 15},
		})
		for i, e := range errs {
			if e != nil {
				t.Fatalf("RecordSpendIncrementsBatch[%d]: %v", i, e)
			}
		}

		// Verify Redis key spend counter equals exact 50 µ$ (NOT 100 µ$!).
		spendVal, err := mr.Get("gw:spend:{org:org-burst}:key:vk-burst")
		if err != nil {
			t.Fatalf("read redis spend key: %v", err)
		}
		if spendVal != "50" {
			t.Fatalf("expected exact 50 µ$ in Redis (zero double-count), got %q", spendVal)
		}
	})

	t.Run("CrashRecoveryFallback settles reservation if reconcile never ran", func(t *testing.T) {
		crashID := &domain.IdentityContext{
			OrgID:              "org-burst",
			TeamID:             "team-burst",
			UserID:             "usr-burst",
			VirtualKeyID:       "vk-crash",
			KeyMaxBudgetMicros: 100,
		}
		// Acquire reservation of 60 µ$ and simulate process crash before reconcile closure runs.
		_, _, _, err := limiter.AcquireWithBudgetAndSettlementIDWithMeta(ctx, crashID, 100, 60, "req-crash-1", "evt-crash-1")
		if err != nil {
			t.Fatalf("acquire crash req: %v", err)
		}
		// Durable SpendWorker/outbox replay settles the crashed request exactly once at 25 µ$.
		errs := limiter.RecordSpendIncrementsBatch(ctx, []ratelimit.SpendIncrementEvent{
			{EventID: "evt-crash-1", RequestID: "req-crash-1", VirtualKeyID: "vk-crash", TeamID: "team-burst", UserID: "usr-burst", OrgID: "org-burst", CostMicros: 25},
		})
		if len(errs) != 1 || errs[0] != nil {
			t.Fatalf("crash recovery batch err: %v", errs)
		}
		spendVal, err := mr.Get("gw:spend:{org:org-burst}:key:vk-crash")
		if err != nil || spendVal != "25" {
			t.Fatalf("expected crash recovery spend 25, got %q (err=%v)", spendVal, err)
		}
		resSum, _ := mr.Get("gw:budget:{org:org-burst}:reservations:key:vk-crash:sum")
		if resSum != "0" {
			t.Fatalf("expected reservation sum cleared to 0, got %q", resSum)
		}
	})

	t.Run("ConcurrentBurst respects strict budget conservation under -race", func(t *testing.T) {
		burstID := &domain.IdentityContext{
			OrgID:              "org-burst",
			TeamID:             "team-burst",
			UserID:             "usr-burst",
			VirtualKeyID:       "vk-concurrent",
			KeyMaxBudgetMicros: 50,
		}
		const workers = 20
		const perReqCost = int64(10)
		var admitted atomic.Int64
		var rejected atomic.Int64

		startCh := make(chan struct{})
		var wg sync.WaitGroup
		for i := 0; i < workers; i++ {
			wg.Add(1)
			go func(idx int) {
				defer wg.Done()
				<-startCh
				reqID := "burst-req-" + string(rune('a'+idx))
				evtID := "burst-evt-" + string(rune('a'+idx))
				rel, _, _, err := limiter.AcquireWithBudgetAndSettlementIDWithMeta(ctx, burstID, 50, perReqCost, reqID, evtID)
				if err != nil {
					rejected.Add(1)
					return
				}
				admitted.Add(1)
				rel(50, perReqCost)
				_ = limiter.RecordSpendIncrementsBatch(ctx, []ratelimit.SpendIncrementEvent{
					{EventID: evtID, RequestID: reqID, VirtualKeyID: "vk-concurrent", TeamID: "team-burst", UserID: "usr-burst", OrgID: "org-burst", CostMicros: perReqCost},
				})
			}(i)
		}
		close(startCh)
		wg.Wait()

		if admitted.Load() != 5 {
			t.Fatalf("expected exact 5 requests admitted (5 * 10 µ$ = 50 µ$), got admitted=%d rejected=%d", admitted.Load(), rejected.Load())
		}
		if rejected.Load() != workers-5 {
			t.Fatalf("expected %d requests rejected, got %d", workers-5, rejected.Load())
		}
		spendVal, err := mr.Get("gw:spend:{org:org-burst}:key:vk-concurrent")
		if err != nil || spendVal != "50" {
			t.Fatalf("expected exact 50 µ$ settled in Redis, got %q (err=%v)", spendVal, err)
		}
	})
}
