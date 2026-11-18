package ratelimit

import (
	"context"
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
