package ratelimit

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

func TestLimiter_AcquireWithRollback_RevertsLegacyAndGlobalOnDescriptorReject(t *testing.T) {
	runCase := func(t *testing.T, redisMode bool) {
		ctx := context.Background()
		var mr *miniredis.Miniredis
		var rf *storage.RedisFabric
		if redisMode {
			mr = miniredis.RunT(t)
			rf = storage.NewRedisFabric(mr.Addr(), "", 0)
			defer func() { _ = rf.Client().Close() }()
		}
		lim := NewLimiter(rf, 60, 60)
		if !redisMode {
			lim.SetFallbackToLocalOnOutage(true)
		}
		lim.SetGlobalLimits(1, 100, 1)

		idCtx := &domain.IdentityContext{
			VirtualKeyID:       "vk-rb",
			OrgID:              "org-rb",
			TeamID:             "team-rb",
			UserID:             "user-rb",
			KeyRPMLimit:        1,
			KeyTPMLimit:        100,
			KeyMaxConcurrent:   1,
			KeyMaxBudgetMicros: 1000,
			OrgRPMLimit:        1,
			OrgTPMLimit:        100,
			OrgMaxConcurrent:   1,
			OrgMaxBudgetMicros: 1000,
		}

		// Step 1 succeeds with RPM=1, TPM=50, Conc=1, Budget=400.
		rel, rb, err := lim.AcquireWithBudgetAndRollback(ctx, idCtx, 50, 400, "req-step1")
		if err != nil {
			t.Fatalf("AcquireWithBudgetAndRollback: %v", err)
		}
		// Simulate step 2 descriptor rejection and invoke rollback.
		rb()
		// Subsequent release call after rollback is a safe no-op.
		rel(-1, -1)

		// A fresh request hitting the exact RPM=1 / Conc=1 / Global=1 / Budget ceiling must succeed.
		rel2, rb2, err := lim.AcquireWithBudgetAndRollback(ctx, idCtx, 50, 900, "req-step2")
		if err != nil {
			t.Fatalf("expected zero leaked quota after rollback, got %v", err)
		}
		_ = rb2
		rel2(50, 100)
	}

	t.Run("redis", func(t *testing.T) { runCase(t, true) })
	t.Run("local_fallback", func(t *testing.T) { runCase(t, false) })
}

func TestLimiter_RenewDescriptorLeases_ExtendsScoreAndLocalExpiry(t *testing.T) {
	ctx := context.Background()
	mr := miniredis.RunT(t)
	rf := storage.NewRedisFabric(mr.Addr(), "", 0)
	defer func() { _ = rf.Client().Close() }()

	lim := NewLimiter(rf, 60, 60)
	desc := domain.RateLimitDescriptor{
		ScopeType:       domain.QuotaScopeProject,
		ScopeID:         "proj-lease",
		MaxBudgetMicros: 1000,
	}
	rel, err := lim.AcquireDescriptors(ctx, "org-lease", "req-long-1", 10, 10, 700, []domain.RateLimitDescriptor{desc})
	if err != nil {
		t.Fatalf("AcquireDescriptors: %v", err)
	}
	defer rel(-1, -1, -1)

	ks := buildDescriptorKeySet("org-lease", desc, time.Now().UTC().Unix()/60, time.Now().UTC().Format("20060102"))
	initialScore, err := mr.ZScore(ks.resZSet, "req-long-1")
	if err != nil {
		t.Fatalf("ZScore initial: %v", err)
	}

	if err := lim.RenewDescriptorLeases(ctx, "org-lease", []domain.RateLimitDescriptor{desc}, "req-long-1", 7200); err != nil {
		t.Fatalf("RenewDescriptorLeases: %v", err)
	}
	renewedScore, err := mr.ZScore(ks.resZSet, "req-long-1")
	if err != nil {
		t.Fatalf("ZScore renewed: %v", err)
	}
	if renewedScore <= initialScore {
		t.Fatalf("expected renewed ZSET score %v > initial %v", renewedScore, initialScore)
	}

	// Verify duplicate request_id with a distinct AcquireDescriptors call still conflicts
	// (receipt is per-Redis-attempt, not per-requestID).
	if _, err := lim.AcquireDescriptors(ctx, "org-lease", "req-long-1", 10, 10, 700, []domain.RateLimitDescriptor{desc}); err == nil {
		t.Fatal("expected distinct AcquireDescriptors call with same requestID to be rejected")
	}
}

func TestLimiter_Rolling24hWindow_SlidingExpiration(t *testing.T) {
	ctx := context.Background()
	runCase := func(t *testing.T, withRedis bool) {
		var lim *Limiter
		if withRedis {
			mr := miniredis.RunT(t)
			rf := storage.NewRedisFabric(mr.Addr(), "", 0)
			defer func() { _ = rf.Client().Close() }()
			lim = NewLimiter(rf, 60, 60)
		} else {
			lim = NewLimiter(nil, 60, 60)
			lim.SetFallbackToLocalOnOutage(true)
		}

		curTime := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
		lim.nowFunc = func() time.Time { return curTime }

		desc := domain.RateLimitDescriptor{
			ScopeType:       domain.QuotaScopeKey,
			ScopeID:         "vk-roll",
			WindowType:      domain.BudgetWindowRolling24h,
			MaxBudgetMicros: 1000,
		}

		// Request 1 at t=0 settles 700 micros.
		rel1, err := lim.AcquireDescriptors(ctx, "org-roll", "req-r1", 10, 10, 700, []domain.RateLimitDescriptor{desc})
		if err != nil {
			t.Fatalf("req-r1: %v", err)
		}
		rel1(10, 10, 700)

		// At t=+12h, 700 is still active; a 400-micro reservation (total 1100 > 1000) must reject.
		curTime = curTime.Add(12 * time.Hour)
		if _, err := lim.AcquireDescriptors(ctx, "org-roll", "req-r2", 10, 10, 400, []domain.RateLimitDescriptor{desc}); err == nil {
			t.Fatal("expected rejection at +12h while 700 micros remain in rolling window")
		}

		// A 250-micro request at t=+12h succeeds (700 + 250 = 950 <= 1000).
		rel3, err := lim.AcquireDescriptors(ctx, "org-roll", "req-r3", 10, 10, 250, []domain.RateLimitDescriptor{desc})
		if err != nil {
			t.Fatalf("req-r3 at +12h: %v", err)
		}
		rel3(10, 10, 250)

		// At t=+24h+1m from t=0, req-r1 (700) has aged out while req-r3 (250) stays active.
		curTime = curTime.Add(12*time.Hour + time.Minute)
		rel4, err := lim.AcquireDescriptors(ctx, "org-roll", "req-r4", 10, 10, 700, []domain.RateLimitDescriptor{desc})
		if err != nil {
			t.Fatalf("expected req-r4 to succeed after req-r1 aged out (250 active + 700 <= 1000), got: %v", err)
		}
		rel4(10, 10, 700)
	}

	t.Run("redis", func(t *testing.T) { runCase(t, true) })
	t.Run("local_fallback", func(t *testing.T) { runCase(t, false) })
}

func TestLimiter_Rolling24hColdRecovery_HoldConcurrentAndFailClosed(t *testing.T) {
	ctx := context.Background()
	t0 := time.Date(2026, 11, 18, 12, 0, 0, 500_000_000, time.UTC)

	t.Run("cold_restore_surviving_reservations_and_subsecond_expiry", func(t *testing.T) {
		runMode := func(t *testing.T, withRedis bool) {
			var curTime = t0
			var mu sync.Mutex
			clock := func() time.Time {
				mu.Lock()
				defer mu.Unlock()
				return curTime
			}
			setClock := func(ts time.Time) {
				mu.Lock()
				curTime = ts
				mu.Unlock()
			}

			var lim *Limiter
			var mr *miniredis.Miniredis
			if withRedis {
				mr = miniredis.RunT(t)
				rf := storage.NewRedisFabric(mr.Addr(), "", 0)
				defer func() { _ = rf.Client().Close() }()
				lim = NewLimiter(rf, 60, 60)
			} else {
				lim = NewLimiter(nil, 60, 60)
				lim.SetFallbackToLocalOnOutage(true)
			}
			lim.SetNowFunc(clock)

			// Seed repository history with:
			//   - db:c1 (400) recorded at t0 - 20h (expires at t0 + 4h)
			//   - db:c2 (300) recorded at t0 - 10h + 250ms (expires at t0 + 14h + 250ms)
			//   - hold:bw1 (200) expiring at t0 + 6h
			var loaderCalls atomic.Int32
			lim.SetRollingWindowLoader(func(_ context.Context, _ string, _ domain.RateLimitDescriptor, _ time.Time) ([]domain.RollingSpendEntry, error) {
				loaderCalls.Add(1)
				return []domain.RollingSpendEntry{
					{ID: "db:c1", TimestampMs: t0.Add(-20 * time.Hour).UnixMilli(), AmountMicros: 400},
					{ID: "db:c2", TimestampMs: t0.Add(-10*time.Hour + 250*time.Millisecond).UnixMilli(), AmountMicros: 300},
					{ID: "hold:bw1", TimestampMs: t0.Add(6*time.Hour - 24*time.Hour).UnixMilli(), AmountMicros: 200},
				}, nil
			})

			desc := domain.RateLimitDescriptor{
				ScopeType:       domain.QuotaScopeKey,
				ScopeID:         "vk-rec",
				WindowType:      domain.BudgetWindowRolling24h,
				MaxBudgetMicros: 1200,
			}

			// Initial cold load restores 400 + 300 + 200 = 900. Reserve 200 (1100 <= 1200) succeeds.
			rel1, err := lim.AcquireDescriptors(ctx, "org-rec", "req-surv", 10, 10, 200, []domain.RateLimitDescriptor{desc})
			if err != nil {
				t.Fatalf("req-surv: %v", err)
			}
			if loaderCalls.Load() != 1 {
				t.Fatalf("expected 1 loader call on cold init, got %d", loaderCalls.Load())
			}

			// Simulate losing ONLY r24hZSet (while an init/spend marker or res_* survives).
			if withRedis {
				ks := buildDescriptorKeySet("org-rec", desc, curTime.Unix()/60, curTime.Format("20060102"))
				mr.Set(ks.spend, "1")
				mr.Del(ks.r24hZSet)
			} else {
				lim.localMu.Lock()
				delete(lim.localDescRolling, orgHashTag("org-rec")+":"+descriptorEntityKey(desc))
				lim.localMu.Unlock()
			}

			// Warm/cold re-recovery must still count surviving reservation (200) separately from restored spend (900):
			// 900 + 200 + 150 = 1250 > 1200 must reject; 900 + 200 + 100 = 1200 must admit!
			if _, err := lim.AcquireDescriptors(ctx, "org-rec", "req-over-res", 10, 10, 150, []domain.RateLimitDescriptor{desc}); err == nil {
				t.Fatal("expected surviving reservation + restored spend to reject over cap")
			}
			rel2, err := lim.AcquireDescriptors(ctx, "org-rec", "req-exact", 10, 10, 100, []domain.RateLimitDescriptor{desc})
			if err != nil {
				t.Fatalf("expected surviving reservation + restored spend exact fit: %v", err)
			}
			rel2(-1, -1, -1)
			rel1(-1, -1, -1)

			// Advance to t0 + 4h: db:c1 (400) expires cleanly, leaving 300 + 200 = 500 -> room for 700.
			setClock(t0.Add(4 * time.Hour))
			rel3, err := lim.AcquireDescriptors(ctx, "org-rec", "req-after-c1", 10, 10, 700, []domain.RateLimitDescriptor{desc})
			if err != nil {
				t.Fatalf("expected db:c1 expiry at +4h to free 400 (500+700<=1200): %v", err)
			}
			rel3(-1, -1, -1)

			// Advance to t0 + 6h: hold:bw1 (200) expires at its original RollingHoldExpiresAt, leaving only db:c2 (300).
			setClock(t0.Add(6 * time.Hour))
			rel4, err := lim.AcquireDescriptors(ctx, "org-rec", "req-after-hold", 10, 10, 900, []domain.RateLimitDescriptor{desc})
			if err != nil {
				t.Fatalf("expected migration hold expiry at +6h to leave only 300: %v", err)
			}
			rel4(-1, -1, -1)

			// At t0 + 14h + 100ms (150ms BEFORE db:c2 expires), db:c2 (300) still counts.
			setClock(t0.Add(14*time.Hour + 100*time.Millisecond))
			if _, err := lim.AcquireDescriptors(ctx, "org-rec", "req-before-c2-ms", 10, 10, 950, []domain.RateLimitDescriptor{desc}); err == nil {
				t.Fatal("expected db:c2 to remain active 150ms before millisecond expiry")
			}

			// At t0 + 14h + 250ms, db:c2 expires at exact millisecond boundary -> full 1200 available.
			setClock(t0.Add(14*time.Hour + 250*time.Millisecond))
			rel5, err := lim.AcquireDescriptors(ctx, "org-rec", "req-at-c2-ms", 10, 10, 1200, []domain.RateLimitDescriptor{desc})
			if err != nil {
				t.Fatalf("expected db:c2 expiry at exact millisecond boundary: %v", err)
			}
			rel5(-1, -1, -1)
		}

		t.Run("redis", func(t *testing.T) { runMode(t, true) })
		t.Run("local_fallback", func(t *testing.T) { runMode(t, false) })
	})

	t.Run("concurrent_cold_init_is_idempotent_and_shared", func(t *testing.T) {
		mr := miniredis.RunT(t)
		rfA := storage.NewRedisFabric(mr.Addr(), "", 0)
		rfB := storage.NewRedisFabric(mr.Addr(), "", 0)
		defer func() {
			_ = rfA.Client().Close()
			_ = rfB.Client().Close()
		}()

		loader := func(_ context.Context, _ string, _ domain.RateLimitDescriptor, _ time.Time) ([]domain.RollingSpendEntry, error) {
			return []domain.RollingSpendEntry{
				{ID: "db:hist", TimestampMs: t0.Add(-2 * time.Hour).UnixMilli(), AmountMicros: 700},
			}, nil
		}
		limA := NewLimiter(rfA, 60, 60)
		limB := NewLimiter(rfB, 60, 60)
		limA.SetNowFunc(func() time.Time { return t0 })
		limB.SetNowFunc(func() time.Time { return t0 })
		limA.SetRollingWindowLoader(loader)
		limB.SetRollingWindowLoader(loader)

		desc := domain.RateLimitDescriptor{
			ScopeType:       domain.QuotaScopeKey,
			ScopeID:         "vk-conc",
			WindowType:      domain.BudgetWindowRolling24h,
			MaxBudgetMicros: 1000,
		}

		// With 700 persisted and max 1000, two simultaneous requests reserving 200 each total 1100 > 1000:
		// strictly 1 must be admitted and 1 rejected!
		start := make(chan struct{})
		var okCount, rejectCount atomic.Int32
		var wg sync.WaitGroup
		for i, lim := range []*Limiter{limA, limB} {
			wg.Add(1)
			go func(idx int, l *Limiter) {
				defer wg.Done()
				<-start
				reqID := "req-conc-a"
				if idx == 1 {
					reqID = "req-conc-b"
				}
				rel, err := l.AcquireDescriptors(ctx, "org-conc", reqID, 10, 10, 200, []domain.RateLimitDescriptor{desc})
				if err == nil {
					okCount.Add(1)
					rel(10, 10, 200)
				} else {
					rejectCount.Add(1)
				}
			}(i, lim)
		}
		close(start)
		wg.Wait()
		if okCount.Load() != 1 || rejectCount.Load() != 1 {
			t.Fatalf("expected 1 admitted and 1 rejected on concurrent cold init, got ok=%d reject=%d", okCount.Load(), rejectCount.Load())
		}
	})

	t.Run("loader_error_returns_quota_policy_unavailable", func(t *testing.T) {
		for _, withRedis := range []bool{true, false} {
			var lim *Limiter
			if withRedis {
				mr := miniredis.RunT(t)
				rf := storage.NewRedisFabric(mr.Addr(), "", 0)
				defer func() { _ = rf.Client().Close() }()
				lim = NewLimiter(rf, 60, 60)
			} else {
				lim = NewLimiter(nil, 60, 60)
				lim.SetFallbackToLocalOnOutage(true)
			}
			lim.SetRollingWindowLoader(func(_ context.Context, _ string, _ domain.RateLimitDescriptor, _ time.Time) ([]domain.RollingSpendEntry, error) {
				return nil, errors.New("postgres down")
			})
			_, err := lim.AcquireDescriptors(ctx, "org-err", "req-err", 10, 10, 100, []domain.RateLimitDescriptor{{
				ScopeType:       domain.QuotaScopeKey,
				ScopeID:         "vk-err",
				WindowType:      domain.BudgetWindowRolling24h,
				MaxBudgetMicros: 500,
			}})
			var gwErr *domain.GatewayError
			if !errors.As(err, &gwErr) || gwErr.StatusCode != http.StatusServiceUnavailable || gwErr.Code != "quota_policy_unavailable" {
				t.Fatalf("withRedis=%v: expected 503 quota_policy_unavailable, got %v", withRedis, err)
			}
		}
	})
}

func TestRollingColdRecoveryCountsRedisAndDurableSettlementOnce(t *testing.T) {
	run := func(t *testing.T, redisMode bool) {
		var mr *miniredis.Miniredis
		var redisFabric *storage.RedisFabric
		if redisMode {
			mr = miniredis.RunT(t)
			redisFabric = storage.NewRedisFabric(mr.Addr(), "", 0)
			t.Cleanup(func() { _ = redisFabric.Client().Close() })
		}
		lim := NewLimiter(redisFabric, 60, 60)
		lim.SetFallbackToLocalOnOutage(!redisMode)
		now := time.Date(2026, 11, 19, 6, 0, 0, 0, time.UTC)
		lim.SetNowFunc(func() time.Time { return now })
		desc := domain.RateLimitDescriptor{
			ScopeType: domain.QuotaScopeKey, ScopeID: "vk-overlap",
			WindowType: domain.BudgetWindowRolling24h, MaxBudgetMicros: 1000,
		}
		var history []domain.RollingSpendEntry
		lim.SetRollingWindowLoader(func(context.Context, string, domain.RateLimitDescriptor, time.Time) ([]domain.RollingSpendEntry, error) {
			return history, nil
		})

		release, err := lim.AcquireDescriptorsWithSettlementID(t.Context(), "org-overlap", "request-one", "event-one", 10, 10, 400, []domain.RateLimitDescriptor{desc})
		if err != nil {
			t.Fatal(err)
		}
		if redisMode {
			key := buildDescriptorKeySet("org-overlap", desc, now.Unix()/60, now.Format("20060102"))
			mr.Del(key.r24hZSet)
		} else {
			lim.localMu.Lock()
			delete(lim.localDescRolling, orgHashTag("org-overlap")+":"+descriptorEntityKey(desc))
			lim.localMu.Unlock()
		}
		// The reservation survived eviction. Settlement reaches both stores before the next admission.
		release(10, 10, 400)
		history = []domain.RollingSpendEntry{{ID: "db:event-one", TimestampMs: now.UnixMilli(), AmountMicros: 400}}

		next, err := lim.AcquireDescriptorsWithSettlementID(t.Context(), "org-overlap", "request-two", "event-two", 10, 10, 600, []domain.RateLimitDescriptor{desc})
		if err != nil {
			t.Fatalf("the recovered 400-micro charge leaves room for 600: %v", err)
		}
		if _, err := lim.AcquireDescriptors(t.Context(), "org-overlap", "request-three", 10, 10, 1, []domain.RateLimitDescriptor{desc}); err == nil {
			t.Fatal("admission must count both the recovered charge and the live reservation")
		}
		next(-1, -1, -1)
	}
	t.Run("redis", func(t *testing.T) { run(t, true) })
	t.Run("memory", func(t *testing.T) { run(t, false) })
}
