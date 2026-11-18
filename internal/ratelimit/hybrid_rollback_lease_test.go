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
