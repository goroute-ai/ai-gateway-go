package finops_test

import (
	"context"
	"sync"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/finops"
	"github.com/goroute-ai/ai-gateway-go/internal/ratelimit"
	"github.com/goroute-ai/ai-gateway-go/internal/router"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

type recordedDeploymentSpend struct {
	orgID      string
	depID      string
	provider   string
	period     string
	costMicros int64
}

type mockDeploymentSpendHook struct {
	mu    sync.Mutex
	calls []recordedDeploymentSpend
}

func (m *mockDeploymentSpendHook) RecordSpend(_ context.Context, orgID, depID, provider, period string, costMicros int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = append(m.calls, recordedDeploymentSpend{
		orgID:      orgID,
		depID:      depID,
		provider:   provider,
		period:     period,
		costMicros: costMicros,
	})
}

func TestSpendWorker_DeploymentSpendHookInvocation(t *testing.T) {
	repo := storage.NewMemoryRepository()
	sw := finops.NewSpendWorker(repo, nil, config.FinOpsConfig{})
	hook := &mockDeploymentSpendHook{}
	sw.SetDeploymentBudgetHook(hook)

	ctx := context.Background()

	// Skips hook when neither DeploymentID nor Provider is set.
	if err := sw.Record(ctx, domain.SpendEvent{
		ID:         "ev-empty",
		RequestID:  "req-empty",
		OrgID:      "org-1",
		CostMicros: 500,
	}); err != nil {
		t.Fatalf("Record ev-empty: %v", err)
	}
	if len(hook.calls) != 0 {
		t.Fatalf("expected 0 hook calls when dep and provider are empty, got %d", len(hook.calls))
	}

	// Fires when DeploymentID is set, clamping negative cost to 0.
	if err := sw.Record(ctx, domain.SpendEvent{
		ID:           "ev-dep",
		RequestID:    "req-dep",
		OrgID:        "org-1",
		DeploymentID: "dep-1",
		CostMicros:   -25,
	}); err != nil {
		t.Fatalf("Record ev-dep: %v", err)
	}
	// Fires when Provider is set without DeploymentID.
	if err := sw.Record(ctx, domain.SpendEvent{
		ID:         "ev-prov",
		RequestID:  "req-prov",
		OrgID:      "org-1",
		Provider:   domain.ProviderAnthropic,
		CostMicros: 750,
	}); err != nil {
		t.Fatalf("Record ev-prov: %v", err)
	}

	if len(hook.calls) != 2 {
		t.Fatalf("expected 2 hook calls, got %d", len(hook.calls))
	}
	if hook.calls[0].depID != "dep-1" || hook.calls[0].costMicros != 0 {
		t.Fatalf("unexpected first hook call: %+v", hook.calls[0])
	}
	if hook.calls[1].provider != "anthropic" || hook.calls[1].costMicros != 750 {
		t.Fatalf("unexpected second hook call: %+v", hook.calls[1])
	}
}

func TestSpendWorker_SettlesDeploymentBudgetTrackerAlongsideLimiter(t *testing.T) {
	mr := miniredis.RunT(t)
	fabric := storage.NewRedisFabric(mr.Addr(), "", 0)
	t.Cleanup(func() { _ = fabric.Client().Close() })

	repo := storage.NewMemoryRepository()
	limiter := ratelimit.NewLimiter(fabric, 60, 300)
	tracker := router.NewDeploymentBudgetTracker(fabric)

	sw := finops.NewSpendWorker(repo, limiter, config.FinOpsConfig{})
	sw.SetDeploymentSpendRecorder(tracker)

	ctx := context.Background()
	dep := &domain.Deployment{
		ID:                "dep-oai-budget",
		MaxBudgetMicros:   1000,
		BudgetResetPeriod: "monthly",
		GlobalModel:       &domain.GlobalModel{Provider: domain.ProviderOpenAI},
	}
	provCaps := map[string]int64{"openai": 1500}

	if !tracker.IsWithinBudget(ctx, "org-finops", dep, provCaps) {
		t.Fatal("expected deployment within budget initially")
	}

	if err := sw.Record(ctx, domain.SpendEvent{
		ID:           "ev-settled-1",
		RequestID:    "req-settled-1",
		OrgID:        "org-finops",
		VirtualKeyID: "vk-1",
		DeploymentID: dep.ID,
		Provider:     domain.ProviderOpenAI,
		CostMicros:   1100,
		StatusCode:   200,
	}); err != nil {
		t.Fatalf("SpendWorker.Record: %v", err)
	}

	if tracker.IsWithinBudget(ctx, "org-finops", dep, provCaps) {
		t.Fatal("expected deployment budget to be exhausted after SpendWorker.Record settled 1100 > 1000")
	}

	// Second deployment for same provider sees 1100/1500 spent; another 400 exhausts provider cap.
	dep2 := &domain.Deployment{
		ID:                "dep-oai-2",
		MaxBudgetMicros:   5000,
		BudgetResetPeriod: "monthly",
		GlobalModel:       &domain.GlobalModel{Provider: domain.ProviderOpenAI},
	}
	if !tracker.IsWithinBudget(ctx, "org-finops", dep2, provCaps) {
		t.Fatal("expected dep2 within provider cap at 1100/1500")
	}
	if err := sw.Record(ctx, domain.SpendEvent{
		ID:           "ev-settled-2",
		RequestID:    "req-settled-2",
		OrgID:        "org-finops",
		VirtualKeyID: "vk-1",
		DeploymentID: dep2.ID,
		Provider:     domain.ProviderOpenAI,
		CostMicros:   400,
		StatusCode:   200,
	}); err != nil {
		t.Fatalf("SpendWorker.Record 2: %v", err)
	}
	if tracker.IsWithinBudget(ctx, "org-finops", dep2, provCaps) {
		t.Fatal("expected provider cap to be exhausted at 1500/1500")
	}
}
