package router

import (
	"context"
	"errors"
	"math"
	"net/http"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

func TestComputeSaturation(t *testing.T) {
	if got := ComputeSaturation(0, 0, 0, 0); got != 0 {
		t.Fatalf("ComputeSaturation(0,0,0,0) = %v, want 0", got)
	}
	if got := ComputeSaturation(40, 100, 750, 1000); math.Abs(got-0.75) > 1e-9 {
		t.Fatalf("ComputeSaturation = %v, want 0.75", got)
	}
	if got := ComputeSaturation(90, 100, 200, 1000); math.Abs(got-0.90) > 1e-9 {
		t.Fatalf("ComputeSaturation = %v, want 0.90", got)
	}
}

func TestActiveTenantRegistry_SlidingTTLExpiry_RedisAndMemory(t *testing.T) {
	run := func(t *testing.T, reg *ActiveTenantRegistry, mr *miniredis.Miniredis) {
		t.Helper()
		ctx := context.Background()
		now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
		reg.SetNowFunc(func() time.Time { return now })

		total, byClass, err := reg.Register(ctx, "org-1", "gpt-4.1", "team:a", "high")
		if err != nil {
			t.Fatalf("Register team:a: %v", err)
		}
		if total != 1 || byClass["high"] != 1 {
			t.Fatalf("after team:a total=%d byClass=%v, want total=1 high=1", total, byClass)
		}

		// Advance 20s and register team:b (low) and team:c (high).
		now = now.Add(20 * time.Second)
		total, byClass, err = reg.Register(ctx, "org-1", "gpt-4.1", "team:b", "low")
		if err != nil {
			t.Fatalf("Register team:b: %v", err)
		}
		total, byClass, err = reg.Register(ctx, "org-1", "gpt-4.1", "team:c", "high")
		if err != nil {
			t.Fatalf("Register team:c: %v", err)
		}
		if total != 3 || byClass["high"] != 2 || byClass["low"] != 1 {
			t.Fatalf("after 3 callers total=%d byClass=%v", total, byClass)
		}

		if mr != nil {
			zkey := ActiveCallersKey("org-1", "gpt-4.1")
			members, err := mr.ZMembers(zkey)
			if err != nil {
				t.Fatalf("miniredis ZMembers(%q): %v", zkey, err)
			}
			if len(members) != 3 {
				t.Fatalf("expected 3 members in Redis ZSET %q, got %v", zkey, members)
			}
		}

		// Advance 15s (t+35s): team:a (lastSeen=t+0) has expired under 30s TTL; team:b & team:c (t+20) remain.
		now = now.Add(15 * time.Second)
		total, byClass, err = reg.ActiveCounts(ctx, "org-1", "gpt-4.1")
		if err != nil {
			t.Fatalf("ActiveCounts at t+35s: %v", err)
		}
		if total != 2 || byClass["high"] != 1 || byClass["low"] != 1 {
			t.Fatalf("at t+35s total=%d byClass=%v, want total=2 high=1 low=1", total, byClass)
		}

		// Refresh team:b at t+35s, then advance to t+55s -> team:c expires, team:b stays active.
		total, byClass, err = reg.Register(ctx, "org-1", "gpt-4.1", "team:b", "low")
		if err != nil {
			t.Fatalf("refresh team:b: %v", err)
		}
		now = now.Add(20 * time.Second)
		total, byClass, err = reg.ActiveCounts(ctx, "org-1", "gpt-4.1")
		if err != nil {
			t.Fatalf("ActiveCounts at t+55s: %v", err)
		}
		if total != 1 || byClass["low"] != 1 || byClass["high"] != 0 {
			t.Fatalf("at t+55s total=%d byClass=%v, want total=1 low=1", total, byClass)
		}

		// Advance past TTL -> all expired.
		now = now.Add(35 * time.Second)
		count, err := reg.ActiveCallerCount(ctx, "org-1", "gpt-4.1")
		if err != nil {
			t.Fatalf("ActiveCallerCount after full expiry: %v", err)
		}
		if count != 0 {
			t.Fatalf("expected 0 active callers after full expiry, got %d", count)
		}
	}

	t.Run("redis_miniredis", func(t *testing.T) {
		mr := miniredis.RunT(t)
		fabric := storage.NewRedisFabric(mr.Addr(), "", 0)
		t.Cleanup(func() { _ = fabric.Client().Close() })
		reg := NewActiveTenantRegistry(fabric, 30*time.Second)
		run(t, reg, mr)
	})

	t.Run("memory_fallback", func(t *testing.T) {
		reg := NewActiveTenantRegistry(nil, 30*time.Second)
		run(t, reg, nil)
	})
}

func TestDynamicPriorityLimiter_GenerousAndStrictModes(t *testing.T) {
	ctx := context.Background()
	mem := storage.NewMemoryRepository()
	orgID := "org-dyn-1"
	if err := mem.CreateOrganization(ctx, &domain.Organization{ID: orgID, Name: "Dyn Org", Slug: "dyn-org", IsActive: true}); err != nil {
		t.Fatalf("CreateOrganization: %v", err)
	}
	if err := mem.UpsertPriorityClass(ctx, &domain.PriorityClass{
		OrgID:             orgID,
		Name:              "critical",
		Weight:            3.0,
		PriorityRank:      0,
		MaxBorrowMultiple: 2.5,
	}); err != nil {
		t.Fatalf("UpsertPriorityClass critical: %v", err)
	}
	if err := mem.UpsertPriorityClass(ctx, &domain.PriorityClass{
		OrgID:             orgID,
		Name:              "standard",
		Weight:            1.0,
		PriorityRank:      5,
		MaxBorrowMultiple: 2.0,
	}); err != nil {
		t.Fatalf("UpsertPriorityClass standard: %v", err)
	}

	mr := miniredis.RunT(t)
	fabric := storage.NewRedisFabric(mr.Addr(), "", 0)
	t.Cleanup(func() { _ = fabric.Client().Close() })

	now := time.Date(2026, 11, 18, 13, 0, 0, 0, time.UTC)
	limiter := NewDynamicPriorityLimiter(fabric, mem, DynamicPriorityConfig{
		Enabled:             true,
		SaturationThreshold: 0.80,
		ActiveCallerTTL:     60 * time.Second,
		WindowDuration:      60 * time.Second,
	})
	limiter.SetNowFunc(func() time.Time { return now })

	// 1. Generous Mode (saturation = 0.50 < 0.80):
	// standard caller has BaseRPM=3, MaxBorrowMultiple=2.0, CapRPM=100 -> effective RPM = min(100, 3*2.0) = 6.
	for i := 0; i < 6; i++ {
		al, err := limiter.Admit(ctx, PriorityCapacityRequest{
			OrgID:           orgID,
			Model:           "gpt-4.1",
			CallerID:        "team:std-1",
			PriorityClass:   "standard",
			BaseRPM:         3,
			BaseTPM:         1000,
			CapRPM:          100,
			CapTPM:          100000,
			UsedRPM:         50, // 50% < 80%
			UsedTPM:         20000,
			EstimatedTokens: 100,
		})
		if err != nil {
			t.Fatalf("generous Admit #%d unexpected error: %v", i+1, err)
		}
		if al.Mode != CapacityModeGenerous || al.EffectiveRPM != 6 || al.EffectiveTPM != 2000 {
			t.Fatalf("unexpected generous allowance: %+v", al)
		}
	}
	// 7th request exceeds borrowed limit (6 RPM) -> 429 priority_capacity_exceeded.
	_, err := limiter.Admit(ctx, PriorityCapacityRequest{
		OrgID:           orgID,
		Model:           "gpt-4.1",
		CallerID:        "team:std-1",
		PriorityClass:   "standard",
		BaseRPM:         3,
		BaseTPM:         1000,
		CapRPM:          100,
		CapTPM:          100000,
		UsedRPM:         50,
		UsedTPM:         20000,
		EstimatedTokens: 100,
	})
	var gwErr *domain.GatewayError
	if !errors.As(err, &gwErr) || gwErr.StatusCode != http.StatusTooManyRequests || gwErr.Code != "priority_capacity_exceeded" {
		t.Fatalf("expected 429 priority_capacity_exceeded on 7th generous call, got %v", err)
	}

	// Generous cap is bounded by model capacity when baseLimit * maxBorrowMultiple > modelCapacity.
	alCapped, err := limiter.EvaluateAllowance(ctx, PriorityCapacityRequest{
		OrgID:         orgID,
		Model:         "gpt-4.1",
		CallerID:      "team:crit-1",
		PriorityClass: "critical",
		BaseRPM:       60, // 60 * 2.5 = 150, capped to CapRPM=100
		CapRPM:        100,
		UsedRPM:       79, // 79% < 80%
	})
	if err != nil {
		t.Fatalf("EvaluateAllowance generous cap: %v", err)
	}
	if alCapped.Mode != CapacityModeGenerous || alCapped.EffectiveRPM != 100 {
		t.Fatalf("expected generous EffectiveRPM capped at 100, got %+v", alCapped)
	}

	// 2. Strict Mode (saturation = 0.85 >= 0.80):
	// Advance to a fresh minute window and register:
	// - 2 active callers in "critical" (weight=3.0)
	// - 1 active caller in "standard" (weight=1.0)
	// Total active class weight = 3.0 + 1.0 = 4.0.
	// Critical normalized weight = 3/4 = 0.75 -> class RPM = 75 -> 2 critical callers => 37 RPM each!
	// Standard normalized weight = 1/4 = 0.25 -> class RPM = 25 -> 1 standard caller => 25 RPM!
	now = now.Add(2 * time.Minute)
	if _, _, err := limiter.Registry().Register(ctx, orgID, "gpt-4.1-strict", "team:crit-1", "critical"); err != nil {
		t.Fatalf("Register crit-1: %v", err)
	}
	if _, _, err := limiter.Registry().Register(ctx, orgID, "gpt-4.1-strict", "team:crit-2", "critical"); err != nil {
		t.Fatalf("Register crit-2: %v", err)
	}
	if _, _, err := limiter.Registry().Register(ctx, orgID, "gpt-4.1-strict", "team:std-1", "standard"); err != nil {
		t.Fatalf("Register std-1: %v", err)
	}

	alCrit, err := limiter.EvaluateAllowance(ctx, PriorityCapacityRequest{
		OrgID:         orgID,
		Model:         "gpt-4.1-strict",
		CallerID:      "team:crit-1",
		PriorityClass: "critical",
		CapRPM:        100,
		CapTPM:        10000,
		UsedRPM:       85, // 85% >= 80%
		UsedTPM:       1000,
	})
	if err != nil {
		t.Fatalf("EvaluateAllowance strict critical: %v", err)
	}
	if alCrit.Mode != CapacityModeStrict || math.Abs(alCrit.NormalizedWeight-0.75) > 1e-9 || alCrit.ActiveCallersInClass != 2 || alCrit.EffectiveRPM != 37 || alCrit.EffectiveTPM != 3750 {
		t.Fatalf("unexpected strict critical allowance: %+v", alCrit)
	}

	alStd, err := limiter.EvaluateAllowance(ctx, PriorityCapacityRequest{
		OrgID:         orgID,
		Model:         "gpt-4.1-strict",
		CallerID:      "team:std-1",
		PriorityClass: "standard",
		CapRPM:        100,
		CapTPM:        10000,
		UsedRPM:       40,
		UsedTPM:       8000, // TPM saturation = 0.80 >= 0.80 triggers Strict Mode
	})
	if err != nil {
		t.Fatalf("EvaluateAllowance strict standard: %v", err)
	}
	if alStd.Mode != CapacityModeStrict || math.Abs(alStd.NormalizedWeight-0.25) > 1e-9 || alStd.ActiveCallersInClass != 1 || alStd.EffectiveRPM != 25 || alStd.EffectiveTPM != 2500 {
		t.Fatalf("unexpected strict standard allowance: %+v", alStd)
	}

	// Verify Strict Mode enforcement rejects after reaching EffectiveRPM on a small capacity model.
	for i := 0; i < 2; i++ {
		if _, err := limiter.Admit(ctx, PriorityCapacityRequest{
			OrgID:           orgID,
			Model:           "gpt-4.1-tiny",
			CallerID:        "team:std-only",
			PriorityClass:   "standard",
			CapRPM:          2,
			UsedRPM:         2, // 100% saturated; 1 active class -> share=2
			EstimatedTokens: 10,
		}); err != nil {
			t.Fatalf("strict tiny Admit #%d failed: %v", i+1, err)
		}
	}
	_, err = limiter.Admit(ctx, PriorityCapacityRequest{
		OrgID:           orgID,
		Model:           "gpt-4.1-tiny",
		CallerID:        "team:std-only",
		PriorityClass:   "standard",
		CapRPM:          2,
		UsedRPM:         2,
		EstimatedTokens: 10,
	})
	if !errors.As(err, &gwErr) || gwErr.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429 when strict share exhausted, got %v", err)
	}
}

func TestPTUShareEnforcement_RedisAndFilterPipeline(t *testing.T) {
	ctx := context.Background()
	mem := storage.NewMemoryRepository()
	orgID := "org-ptu-router"
	_ = mem.CreateOrganization(ctx, &domain.Organization{ID: orgID, Name: "PTU", Slug: "ptu", IsActive: true})
	_ = mem.CreateTeam(ctx, &domain.Team{ID: "team-reserved", OrgID: orgID, Name: "Reserved", IsActive: true})
	_ = mem.CreateTeam(ctx, &domain.Team{ID: "team-shared", OrgID: orgID, Name: "Shared", IsActive: true})

	// dep-ptu has 100 RPM capacity, with 80 RPM dedicated to team-reserved (leaving 20 RPM unreserved).
	if err := mem.UpsertDeploymentPTUShare(ctx, &domain.DeploymentPTUShare{
		OrgID:        orgID,
		DeploymentID: "dep-ptu",
		TeamID:       "team-reserved",
		ReservedRPM:  2,
		ReservedTPM:  500,
	}); err != nil {
		t.Fatalf("UpsertDeploymentPTUShare: %v", err)
	}

	mr := miniredis.RunT(t)
	fabric := storage.NewRedisFabric(mr.Addr(), "", 0)
	t.Cleanup(func() { _ = fabric.Client().Close() })

	now := time.Date(2026, 11, 18, 14, 0, 0, 0, time.UTC)
	limiter := NewDynamicPriorityLimiter(fabric, mem)
	limiter.SetNowFunc(func() time.Time { return now })

	// 1. team-reserved gets 2 RPM / 500 TPM via gw:ptu:{org:<orgID>}:dep:<depID>:team:<teamID>:...
	res1, err := limiter.AcquirePTUShare(ctx, orgID, "dep-ptu", "team-reserved", 200)
	if err != nil || !res1.HasShare || !res1.Allowed || res1.UsedRPM != 1 || res1.UsedTPM != 200 {
		t.Fatalf("first AcquirePTUShare = %+v, err=%v", res1, err)
	}
	res2, err := limiter.AcquirePTUShare(ctx, orgID, "dep-ptu", "team-reserved", 200)
	if err != nil || !res2.Allowed || res2.UsedRPM != 2 || res2.UsedTPM != 400 {
		t.Fatalf("second AcquirePTUShare = %+v, err=%v", res2, err)
	}

	bucket := now.Unix() / 60
	rpmKey := PTUTeamRPMKey(orgID, "dep-ptu", "team-reserved", bucket)
	if got, err := mr.Get(rpmKey); err != nil || got != "2" {
		t.Fatalf("expected Redis PTU key %q=2, got %q (err=%v)", rpmKey, got, err)
	}

	// 3rd request exceeds ReservedRPM=2 -> 429 ptu_share_exceeded
	_, err = limiter.AcquirePTUShare(ctx, orgID, "dep-ptu", "team-reserved", 50)
	var gwErr *domain.GatewayError
	if !errors.As(err, &gwErr) || gwErr.StatusCode != http.StatusTooManyRequests || gwErr.Code != "ptu_share_exceeded" {
		t.Fatalf("expected 429 ptu_share_exceeded, got %v", err)
	}

	// Reconcile tokens down by 150 (from 400 -> 250) and test TPM limit on next window.
	limiter.ReconcilePTUShare(ctx, orgID, "dep-ptu", "team-reserved", 200, 50)
	tpmKey := PTUTeamTPMKey(orgID, "dep-ptu", "team-reserved", bucket)
	if got, err := mr.Get(tpmKey); err != nil || got != "250" {
		t.Fatalf("expected reconciled Redis PTU TPM key %q=250, got %q (err=%v)", tpmKey, got, err)
	}

	// Next window: TPM exceeding ReservedTPM=500 is rejected.
	now = now.Add(time.Minute)
	if _, err := limiter.AcquirePTUShare(ctx, orgID, "dep-ptu", "team-reserved", 350); err != nil {
		t.Fatalf("AcquirePTUShare 350 tokens: %v", err)
	}
	_, err = limiter.AcquirePTUShare(ctx, orgID, "dep-ptu", "team-reserved", 200)
	if !errors.As(err, &gwErr) || gwErr.Code != "ptu_share_exceeded" {
		t.Fatalf("expected 429 ptu_share_exceeded on TPM overflow, got %v", err)
	}

	// 2. team-shared has NO share on dep-ptu; verify FilterPipeline protects reserved slice.
	// Suppose dep-ptu has RPMCapacity=10 and team-reserved holds ReservedRPM=8 (2 unreserved for others).
	if err := mem.UpsertDeploymentPTUShare(ctx, &domain.DeploymentPTUShare{
		OrgID:        orgID,
		DeploymentID: "dep-ptu",
		TeamID:       "team-reserved",
		ReservedRPM:  8,
		ReservedTPM:  8000,
	}); err != nil {
		t.Fatalf("update PTU share: %v", err)
	}
	lb := NewLoadBalancer()
	depPTU := &domain.Deployment{
		ID:          "dep-ptu",
		Status:      domain.DeploymentStatusActive,
		RPMCapacity: 10,
		TPMCapacity: 10000,
		GlobalModel: &domain.GlobalModel{
			ID:                "openai/gpt-4.1",
			Provider:          domain.ProviderOpenAI,
			ModelName:         "gpt-4.1",
			SupportsInference: true,
		},
	}
	depShared := &domain.Deployment{
		ID:          "dep-payg",
		Status:      domain.DeploymentStatusActive,
		RPMCapacity: 100,
		TPMCapacity: 100000,
		GlobalModel: depPTU.GlobalModel,
	}
	// Simulate 2 RPM already consumed on dep-ptu (all unreserved capacity for non-owners is now used).
	lb.OnRequestStart(depPTU.ID)
	lb.OnRequestEnd(depPTU.ID, 10, 100)
	lb.OnRequestStart(depPTU.ID)
	lb.OnRequestEnd(depPTU.ID, 10, 100)

	fp := NewFilterPipeline(nil, lb, config.RouterConfig{})
	fp.SetPriorityLimiter(limiter)

	// team-shared cannot consume team-reserved's 8 reserved RPM on dep-ptu.
	eligibleShared, err := fp.FilterEligibleDeployments(WithCallerTeamID(ctx, "team-shared"), orgID, "gpt-4.1", nil, []*domain.Deployment{depPTU, depShared}, 100)
	if err != nil {
		t.Fatalf("FilterEligibleDeployments shared: %v", err)
	}
	if len(eligibleShared) != 1 || eligibleShared[0].ID != "dep-payg" {
		t.Fatalf("expected dep-ptu excluded for team-shared once unreserved capacity used, got %+v", eligibleShared)
	}

	// team-reserved CAN still use dep-ptu.
	eligibleReserved, err := fp.FilterEligibleDeployments(WithCallerTeamID(ctx, "team-reserved"), orgID, "gpt-4.1", nil, []*domain.Deployment{depPTU, depShared}, 100)
	if err != nil {
		t.Fatalf("FilterEligibleDeployments reserved: %v", err)
	}
	if len(eligibleReserved) != 2 {
		t.Fatalf("expected dep-ptu available for team-reserved, got %d candidates", len(eligibleReserved))
	}
}

func TestDynamicPriorityLimiter_MemoryFallbackAndReconcile(t *testing.T) {
	ctx := context.Background()
	mem := storage.NewMemoryRepository()
	orgID := "org-mem-1"
	_ = mem.CreateOrganization(ctx, &domain.Organization{ID: orgID, Name: "Mem Org", Slug: "mem-org", IsActive: true})
	_ = mem.UpsertPriorityClass(ctx, &domain.PriorityClass{
		OrgID:             orgID,
		Name:              "gold",
		Weight:            2.0,
		PriorityRank:      1,
		MaxBorrowMultiple: 2.0,
	})
	_ = mem.UpsertDeploymentPTUShare(ctx, &domain.DeploymentPTUShare{
		OrgID:        orgID,
		DeploymentID: "dep-mem",
		TeamID:       "team-mem",
		ReservedRPM:  2,
		ReservedTPM:  200,
	})

	now := time.Date(2026, 11, 18, 15, 0, 0, 0, time.UTC)
	limiter := NewDynamicPriorityLimiter(nil, mem, DynamicPriorityConfig{
		Enabled:             true,
		SaturationThreshold: 0.80,
		ActiveCallerTTL:     60 * time.Second,
		WindowDuration:      60 * time.Second,
	})
	limiter.SetNowFunc(func() time.Time { return now })

	// Memory fallback: generous mode allows borrowing up to 2x baseTPM (100 * 2 = 200)
	al, err := limiter.Admit(ctx, PriorityCapacityRequest{
		OrgID:           orgID,
		Model:           "gpt-4.1",
		CallerID:        "team:team-mem",
		PriorityClass:   "gold",
		BaseRPM:         2,
		BaseTPM:         100,
		CapRPM:          100,
		CapTPM:          10000,
		UsedRPM:         10,
		UsedTPM:         500,
		EstimatedTokens: 150,
	})
	if err != nil || !al.Allowed || al.UsedCallerTPM != 150 {
		t.Fatalf("expected memory fallback Admit success, got %+v err=%v", al, err)
	}
	// Reconcile actual tokens down from 150 -> 50, so another 150-token call succeeds within 200 TPM.
	limiter.ReconcileTokens(ctx, orgID, "gpt-4.1", "team:team-mem", 150, 50)
	al2, err := limiter.Admit(ctx, PriorityCapacityRequest{
		OrgID:           orgID,
		Model:           "gpt-4.1",
		CallerID:        "team:team-mem",
		PriorityClass:   "gold",
		BaseRPM:         2,
		BaseTPM:         100,
		CapRPM:          100,
		CapTPM:          10000,
		UsedRPM:         10,
		UsedTPM:         500,
		EstimatedTokens: 150,
	})
	if err != nil || !al2.Allowed || al2.UsedCallerTPM != 200 {
		t.Fatalf("expected reconciled memory fallback Admit success, got %+v err=%v", al2, err)
	}

	// Memory fallback PTU share enforcement
	if _, err := limiter.AcquirePTUShare(ctx, orgID, "dep-mem", "team-mem", 100); err != nil {
		t.Fatalf("memory AcquirePTUShare #1: %v", err)
	}
	if _, err := limiter.AcquirePTUShare(ctx, orgID, "dep-mem", "team-mem", 150); err == nil {
		t.Fatal("expected memory AcquirePTUShare #2 to fail on TPM > 200")
	}
}
