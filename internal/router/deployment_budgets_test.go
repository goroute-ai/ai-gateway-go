package router

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/observability"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

func TestDeploymentBudgetKeysAlignToOrgClusterSlot(t *testing.T) {
	for _, orgID := range []string{"org_acme", ""} {
		depKey := DeploymentBudgetKey(orgID, "dep_1", "2026-11")
		provKey := ProviderBudgetKey(orgID, "openai", "2026-11")
		wantTag := "{org:" + orgID + "}"
		if orgID == "" {
			wantTag = "{org:default}"
		}
		if !strings.Contains(depKey, wantTag) || !strings.Contains(provKey, wantTag) {
			t.Fatalf("budget keys missing hash tag %q: dep=%q prov=%q", wantTag, depKey, provKey)
		}
		if testCRC16ClusterSlot(depKey) != testCRC16ClusterSlot(provKey) {
			t.Fatalf("budget keys mapped to different Redis Cluster slots: dep=%d prov=%d",
				testCRC16ClusterSlot(depKey), testCRC16ClusterSlot(provKey))
		}
	}
}

func TestDeploymentBudgetTracker_LocalFallbackAndPeriods(t *testing.T) {
	now := time.Date(2026, 11, 17, 15, 0, 0, 0, time.UTC)
	tracker := NewDeploymentBudgetTracker(nil)
	tracker.nowFn = func() time.Time { return now }
	ctx := context.Background()

	dailyDep := &domain.Deployment{
		ID:                "dep-daily",
		MaxBudgetMicros:   1000,
		BudgetResetPeriod: "daily",
		GlobalModel:       &domain.GlobalModel{Provider: domain.ProviderOpenAI},
	}
	neverDep := &domain.Deployment{
		ID:                "dep-never",
		MaxBudgetMicros:   500,
		BudgetResetPeriod: "never",
		GlobalModel:       &domain.GlobalModel{Provider: domain.ProviderAnthropic},
	}

	if !tracker.IsWithinBudget(ctx, "org-1", dailyDep, nil) {
		t.Fatal("expected fresh daily deployment to be within budget")
	}

	// Spend 600 -> still within 1000.
	tracker.RecordSpend(ctx, "org-1", dailyDep.ID, "openai", "daily", 600)
	if !tracker.IsWithinBudget(ctx, "org-1", dailyDep, nil) {
		t.Fatal("expected 600 < 1000 to be within budget")
	}

	// Spend 400 more -> exact 1000 cap is exhausted.
	tracker.RecordSpend(ctx, "org-1", dailyDep.ID, "openai", "daily", 400)
	if tracker.IsWithinBudget(ctx, "org-1", dailyDep, nil) {
		t.Fatal("expected 1000 == 1000 to be over/exhausted budget")
	}

	// Never-reset deployment exhausted across day/month boundaries.
	tracker.RecordSpend(ctx, "org-1", neverDep.ID, "anthropic", "never", 550)
	if tracker.IsWithinBudget(ctx, "org-1", neverDep, nil) {
		t.Fatal("expected never-reset deployment at 550 > 500 to be over budget")
	}

	// Advance to next day: daily budget resets, never-reset remains exhausted.
	now = now.Add(24 * time.Hour)
	if !tracker.IsWithinBudget(ctx, "org-1", dailyDep, nil) {
		t.Fatal("expected daily deployment budget to reset on next UTC day")
	}
	if tracker.IsWithinBudget(ctx, "org-1", neverDep, nil) {
		t.Fatal("expected never-reset deployment to remain exhausted across days")
	}
}

func TestDeploymentBudgetTracker_MiniredisAndProviderCaps(t *testing.T) {
	mr := miniredis.RunT(t)
	fabric := storage.NewRedisFabric(mr.Addr(), "", 0)
	t.Cleanup(func() { _ = fabric.Client().Close() })

	now := time.Date(2026, 11, 17, 15, 0, 0, 0, time.UTC)
	col := observability.NewCollector()
	tracker := NewDeploymentBudgetTracker(fabric)
	tracker.SetCollector(col)
	tracker.nowFn = func() time.Time { return now }
	ctx := context.Background()

	providerCaps := map[string]int64{
		"openai": 2000,
	}
	dep1 := &domain.Deployment{
		ID:                "dep-oai-1",
		MaxBudgetMicros:   5000, // higher than provider cap
		BudgetResetPeriod: "monthly",
		GlobalModel:       &domain.GlobalModel{Provider: domain.ProviderOpenAI},
	}
	dep2 := &domain.Deployment{
		ID:                "dep-oai-2",
		MaxBudgetMicros:   0, // unlimited deployment, capped by providerCaps
		BudgetResetPeriod: "monthly",
		Credential:        &domain.ProviderCredential{Provider: domain.ProviderOpenAI},
	}
	depOtherOrg := &domain.Deployment{
		ID:            "dep-oai-2",
		GlobalModelID: "openai/gpt-4.1",
	}

	tracker.RecordSpend(ctx, "org-1", dep1.ID, "openai", "", 1200)
	tracker.RecordSpend(ctx, "org-1", dep2.ID, "openai", "", 800)

	// Verify exact Redis keys and TTLs in miniredis.
	provKey := ProviderBudgetKey("org-1", "openai", "2026-11")
	gotProv, err := mr.Get(provKey)
	if err != nil || gotProv != "2000" {
		t.Fatalf("expected Redis %q=2000, got %q (err=%v)", provKey, gotProv, err)
	}
	if ttl := mr.TTL(provKey); ttl <= 0 {
		t.Fatalf("expected positive TTL on monthly budget key, got %v", ttl)
	}

	// org-1 openai provider budget is 2000/2000 -> both dep1 and dep2 are blocked.
	if tracker.IsWithinBudget(ctx, "org-1", dep1, providerCaps) {
		t.Fatal("expected dep1 to be blocked by provider cap")
	}
	if tracker.IsWithinBudget(ctx, "org-1", dep2, providerCaps) {
		t.Fatal("expected dep2 to be blocked by provider cap")
	}
	// org-2 is isolated and still within budget.
	if !tracker.IsWithinBudget(ctx, "org-2", depOtherOrg, providerCaps) {
		t.Fatal("expected org-2 to remain within provider cap")
	}

	// Simulate Redis outage: fallback retains synced 2000 spend and records degradation.
	mr.Close()
	if tracker.IsWithinBudget(ctx, "org-1", dep2, providerCaps) {
		t.Fatal("expected degraded fallback to preserve synced provider spend and block dep2")
	}
	if snap := col.Snapshot(); snap.RoutingSignalDegradedTotal == 0 {
		t.Fatal("expected RoutingSignalDegradedTotal > 0 after Redis outage")
	}

	// Further degraded spend accrues locally for org-2.
	tracker.RecordSpend(ctx, "org-2", depOtherOrg.ID, "openai", "", 2100)
	if tracker.IsWithinBudget(ctx, "org-2", depOtherOrg, providerCaps) {
		t.Fatal("expected org-2 local fallback counter to block after exceeding 2000")
	}
}

func TestDeploymentBudgetTracker_DailyPeriodHintFromIsWithinBudget(t *testing.T) {
	mr := miniredis.RunT(t)
	fabric := storage.NewRedisFabric(mr.Addr(), "", 0)
	t.Cleanup(func() { _ = fabric.Client().Close() })

	now := time.Date(2026, 11, 17, 15, 0, 0, 0, time.UTC)
	tracker := NewDeploymentBudgetTracker(fabric)
	tracker.nowFn = func() time.Time { return now }
	ctx := context.Background()

	dep := &domain.Deployment{
		ID:                "dep-daily-hint",
		MaxBudgetMicros:   500,
		BudgetResetPeriod: "daily",
		GlobalModel:       &domain.GlobalModel{Provider: domain.ProviderOpenAI},
	}

	// Routing checks IsWithinBudget before execution.
	if !tracker.IsWithinBudget(ctx, "org-1", dep, nil) {
		t.Fatal("expected within budget initially")
	}
	// FinOps SpendWorker settles with empty period string.
	tracker.RecordSpend(ctx, "org-1", dep.ID, "openai", "", 600)

	if tracker.IsWithinBudget(ctx, "org-1", dep, nil) {
		t.Fatal("expected daily deployment to be blocked after SpendWorker settlement")
	}
}

func TestDeploymentBudgetTracker_ConcurrentRace(t *testing.T) {
	mr := miniredis.RunT(t)
	fabric := storage.NewRedisFabric(mr.Addr(), "", 0)
	t.Cleanup(func() { _ = fabric.Client().Close() })

	tracker := NewDeploymentBudgetTracker(fabric)
	ctx := context.Background()
	dep := &domain.Deployment{
		ID:                "dep-race",
		MaxBudgetMicros:   100_000,
		BudgetResetPeriod: "monthly",
		GlobalModel:       &domain.GlobalModel{Provider: domain.ProviderOpenAI},
	}
	caps := map[string]int64{"openai": 500_000}

	var wg sync.WaitGroup
	for g := 0; g < 16; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 20; i++ {
				_ = tracker.IsWithinBudget(ctx, "org-race", dep, caps)
				tracker.RecordSpend(ctx, "org-race", dep.ID, "openai", "monthly", 50)
			}
		}()
	}
	wg.Wait()

	expected := int64(16 * 20 * 50)
	bucket, _ := PeriodBucket("monthly", time.Now())
	gotKey := DeploymentBudgetKey("org-race", dep.ID, bucket)
	val, err := mr.Get(gotKey)
	if err != nil {
		t.Fatalf("missing Redis key %q: %v", gotKey, err)
	}
	if val != "16000" {
		t.Fatalf("expected atomic Redis spend=%d, got %s", expected, val)
	}
}
