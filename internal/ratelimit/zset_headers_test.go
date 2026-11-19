package ratelimit

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

func TestZSETConcurrency_CrashSelfHealsUnderSteadyTraffic(t *testing.T) {
	mr := miniredis.RunT(t)
	rf := storage.NewRedisFabric(mr.Addr(), "", 0)
	t.Cleanup(func() { _ = rf.Client().Close() })

	baseNow := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	mr.SetTime(baseNow)

	// 2-second concurrency slot lease.
	limiter := NewLimiter(rf, 60, 2)
	limiter.nowFunc = func() time.Time { return baseNow }
	ctx := context.Background()

	idCtx := &domain.IdentityContext{
		VirtualKeyID:     "vk-zset",
		OrgID:            "org-zset",
		KeyMaxConcurrent: 2,
	}

	// Simulate pod A acquiring slot #1 and crashing without calling release.
	if _, _, err := limiter.AcquireWithBudgetAndMeta(ctx, idCtx, 10, 0, "req-crashed-pod"); err != nil {
		t.Fatalf("acquire crashed slot: %v", err)
	}

	// Pod B handles healthy traffic on slot #2 continuously while advancing 1s.
	mr.SetTime(baseNow.Add(1 * time.Second))
	mr.FastForward(1 * time.Second)
	relHealthy, _, err := limiter.AcquireWithBudgetAndMeta(ctx, idCtx, 10, 0, "req-healthy-1")
	if err != nil {
		t.Fatalf("healthy slot #2 acquire: %v", err)
	}
	// While both slots are active, a 3rd concurrent request fails with key_concurrency_exceeded.
	if _, _, err := limiter.AcquireWithBudgetAndMeta(ctx, idCtx, 10, 0, "req-blocked"); err == nil {
		t.Fatal("expected concurrency_exceeded while 2 slots held")
	} else {
		var gwErr *domain.GatewayError
		if !errors.As(err, &gwErr) || gwErr.RateLimitMeta == nil || gwErr.RateLimitMeta.LimitType != "concurrency" || gwErr.RateLimitMeta.Scope != "key" {
			t.Fatalf("unexpected concurrency error metadata: %+v", gwErr)
		}
	}
	relHealthy(10, 0)

	// Advance past the 2-second crash TTL. Even under healthy traffic,
	// ZREMRANGEBYSCORE purges req-crashed-pod so both slots are free again!
	mr.SetTime(baseNow.Add(4 * time.Second))
	mr.FastForward(3 * time.Second)
	relA, _, err := limiter.AcquireWithBudgetAndMeta(ctx, idCtx, 10, 0, "req-recovered-1")
	if err != nil {
		t.Fatalf("expected recovered slot #1 after leaked TTL expiry, got %v", err)
	}
	relB, _, err := limiter.AcquireWithBudgetAndMeta(ctx, idCtx, 10, 0, "req-recovered-2")
	if err != nil {
		t.Fatalf("expected recovered slot #2 after leaked TTL expiry, got %v", err)
	}
	relA(10, 0)
	relB(10, 0)

	if members, _ := mr.ZMembers("gw:rl:{org:org-zset}:zconc:vk-zset"); len(members) != 0 {
		t.Fatalf("expected 0 active ZSET slots after release, got %v", members)
	}
}

func TestRateLimitHeaderMetadata_TightestAllowAndDeny(t *testing.T) {
	mr := miniredis.RunT(t)
	rf := storage.NewRedisFabric(mr.Addr(), "", 0)
	t.Cleanup(func() { _ = rf.Client().Close() })

	limiter := NewLimiter(rf, 60, 30)
	ctx := context.Background()

	idCtx := &domain.IdentityContext{
		VirtualKeyID: "vk-hdr",
		TeamID:       "team-hdr",
		OrgID:        "org-hdr",
		KeyRPMLimit:  2,
		KeyTPMLimit:  1000,
		TeamRPMLimit: 100,
		TeamTPMLimit: 50000,
	}

	rel1, meta1, err := limiter.AcquireWithBudgetAndMeta(ctx, idCtx, 250, 0, "req-h1")
	if err != nil {
		t.Fatalf("acquire #1: %v", err)
	}
	defer rel1(250, 0)
	if meta1 == nil || meta1.LimitRequests != 2 || meta1.RemainingRequests != 1 || meta1.LimitTokens != 1000 || meta1.RemainingTokens != 750 || meta1.ResetRequestsSeconds <= 0 {
		t.Fatalf("unexpected tightest allow metadata #1: %+v", meta1)
	}

	// Descriptor limit narrower than Key limit merges cleanly via MergeRateLimitMetadata
	relD, metaD, err := limiter.AcquireDescriptorsWithMeta(ctx, "org-hdr", "req-h1", 200, 50, 0, []domain.RateLimitDescriptor{
		{
			ScopeType:    domain.QuotaScopeModelPerKey,
			ScopeID:      "vk-hdr",
			ModelPattern: "gpt-4.1",
			RPMLimit:     1,
			TPMLimit:     500,
		},
	})
	if err != nil {
		t.Fatalf("AcquireDescriptorsWithMeta: %v", err)
	}
	defer relD(200, 50, 0)
	merged := MergeRateLimitMetadata(meta1, metaD)
	if merged.LimitRequests != 1 || merged.RemainingRequests != 0 || merged.LimitTokens != 500 || merged.RemainingTokens != 250 {
		t.Fatalf("unexpected merged metadata: %+v", merged)
	}

	// Second descriptor call hits model_per_key RPM limit and populates 429 diagnostic headers.
	_, _, err = limiter.AcquireDescriptorsWithMeta(ctx, "org-hdr", "req-h2", 10, 10, 0, []domain.RateLimitDescriptor{
		{
			ScopeType:    domain.QuotaScopeModelPerKey,
			ScopeID:      "vk-hdr",
			ModelPattern: "gpt-4.1",
			RPMLimit:     1,
		},
	})
	var gwErr *domain.GatewayError
	if !errors.As(err, &gwErr) || gwErr.RateLimitMeta == nil {
		t.Fatalf("expected 429 GatewayError with RateLimitMeta, got %v", err)
	}
	if gwErr.RateLimitMeta.Scope != "model_per_key" || gwErr.RateLimitMeta.LimitType != "rpm" || gwErr.RateLimitMeta.LimitRequests != 1 || gwErr.RateLimitMeta.RemainingRequests != 0 || gwErr.RateLimitMeta.ResetAt == "" {
		t.Fatalf("unexpected 429 RateLimitMeta: %+v", gwErr.RateLimitMeta)
	}
}

func TestClearEntitySpend_And_DynamicUpstream429Throttle(t *testing.T) {
	mr := miniredis.RunT(t)
	rf := storage.NewRedisFabric(mr.Addr(), "", 0)
	t.Cleanup(func() { _ = rf.Client().Close() })

	limiter := NewLimiter(rf, 60, 30)
	ctx := context.Background()

	_ = mr.Set("gw:spend:{org:org-clr}:key:vk-clr", "500000")
	_ = mr.Set("gw:dq:{org:org-clr}:spend:team_member:team-clr:usr-clr", "250000")

	if err := limiter.ClearEntitySpend(ctx, storage.EntitySpendScopeKey, "org-clr", "vk-clr", ""); err != nil {
		t.Fatalf("ClearEntitySpend key: %v", err)
	}
	if mr.Exists("gw:spend:{org:org-clr}:key:vk-clr") {
		t.Fatal("expected key spend counter deleted from Redis")
	}

	if err := limiter.ClearEntitySpend(ctx, storage.EntitySpendScopeTeamMember, "org-clr", "team-clr", "usr-clr"); err != nil {
		t.Fatalf("ClearEntitySpend team_member: %v", err)
	}
	if mr.Exists("gw:dq:{org:org-clr}:spend:team_member:team-clr:usr-clr") {
		t.Fatal("expected team_member spend counter deleted from Redis")
	}

	limiter.MarkUpstream429Throttle(ctx, "org-clr", "vk-clr", 3*time.Second)
	sec, ok := limiter.CheckUpstream429Throttle(ctx, "org-clr", "vk-clr")
	if !ok || sec <= 0 {
		t.Fatalf("expected active dynamic 429 throttle, got sec=%d ok=%v", sec, ok)
	}
}

func TestReconcileDescriptors_ExpiredMinuteBucketGuard_And_AcquireSessionWithMeta(t *testing.T) {
	mr := miniredis.RunT(t)
	rf := storage.NewRedisFabric(mr.Addr(), "", 0)
	t.Cleanup(func() { _ = rf.Client().Close() })

	baseTime := time.Date(2026, 11, 19, 12, 0, 58, 0, time.UTC)
	mr.SetTime(baseTime)
	limiter := NewLimiter(rf, 60, 30)
	limiter.nowFunc = func() time.Time { return baseTime }
	ctx := context.Background()

	id := &domain.IdentityContext{
		OrgID:        "org-sess-hdr",
		VirtualKeyID: "vk-sess-hdr",
		KeyRPMLimit:  20,
	}
	relSess, meta, err := limiter.AcquireSessionWithMeta(ctx, id)
	if err != nil {
		t.Fatalf("AcquireSessionWithMeta: %v", err)
	}
	if meta == nil || meta.LimitRequests != 20 || meta.RemainingRequests != 19 {
		t.Fatalf("unexpected session rate-limit meta: %+v", meta)
	}
	relSess()

	desc := []domain.RateLimitDescriptor{{
		ScopeType: domain.QuotaScopeKey,
		ScopeID:   "vk-roll",
		RPMLimit:  10,
		TPMLimit:  5000,
	}}
	relDesc, dMeta, err := limiter.AcquireDescriptorsWithMeta(ctx, "org-sess-hdr", "req-roll", 200, 0, 0, desc)
	if err != nil || dMeta == nil {
		t.Fatalf("AcquireDescriptorsWithMeta: %v", err)
	}
	// Simulate the minute bucket key having expired before post-dispatch settlement runs.
	bucketKeys := descriptorReconcileKeys("org-sess-hdr", desc, baseTime)
	mr.Del(bucketKeys[0])
	relDesc(50, 0, 0) // delta = -150 against expired tpm key
	if mr.Exists(bucketKeys[0]) {
		t.Fatalf("expected expired minute tpm key %s not to be recreated on negative delta", bucketKeys[0])
	}
}
