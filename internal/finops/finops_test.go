package finops_test

import (
	"context"
	"errors"
	"github.com/alicebob/miniredis/v2"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/finops"
	"github.com/goroute-ai/ai-gateway-go/internal/observability"
	"github.com/goroute-ai/ai-gateway-go/internal/ratelimit"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"net"
	"testing"
	"time"
)

type failingOutboxRepository struct {
	storage.Repository
	err error
}

func (r failingOutboxRepository) EnqueueSpendEvent(context.Context, domain.SpendEvent) error {
	return r.err
}

func TestCostCalculatorAndAsyncSpendWorker(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()

	gm, err := repo.GetGlobalModel(ctx, "openai/gpt-4.1")
	if err != nil {
		t.Fatalf("get global model: %v", err)
	}

	// GPT-4.1: Input = $2/1M (2,000,000 micros), Output = $8/1M (8,000,000 micros)
	// 1,000 prompt tokens ($0.002 = 2,000 micros) + 500 completion tokens ($0.004 = 4,000 micros) = 6,000 micros
	cost := finops.CalculateCostMicros(gm, domain.TokenUsage{
		PromptTokens:     1000,
		CompletionTokens: 500,
		TotalTokens:      1500,
	})
	if cost != 6000 {
		t.Fatalf("expected 6000 micro-dollars, got %d", cost)
	}

	org := &domain.Organization{Name: "FinOps Org", Slug: "finops", IsActive: true}
	_ = repo.CreateOrganization(ctx, org)
	team := &domain.Team{OrgID: org.ID, Name: "Platform Team", IsActive: true}
	_ = repo.CreateTeam(ctx, team)
	vk := &domain.VirtualKey{OrgID: org.ID, TeamID: team.ID, Name: "app-key", KeyHash: "hash123", IsActive: true}
	_ = repo.CreateVirtualKey(ctx, vk)

	sw := finops.NewSpendWorker(repo, nil, config.FinOpsConfig{
		ChannelBufferSize: 128,
		BatchSize:         10,
		FlushInterval:     20 * time.Millisecond,
	})
	sw.Start(ctx)

	if err := sw.Record(ctx, domain.SpendEvent{
		RequestID:      "req-1",
		OrgID:          org.ID,
		TeamID:         team.ID,
		VirtualKeyID:   vk.ID,
		Endpoint:       "/v1/chat/completions",
		RequestedModel: "gpt-4.1",
		ResolvedModel:  "gpt-4.1",
		Provider:       domain.ProviderOpenAI,
		Usage:          domain.TokenUsage{PromptTokens: 1000, CompletionTokens: 500, TotalTokens: 1500},
		CostMicros:     cost,
		StatusCode:     200,
	}); err != nil {
		t.Fatalf("record spend event: %v", err)
	}

	sw.Stop(ctx)

	summary, err := repo.GetSpendSummary(ctx, org.ID)
	if err != nil || summary.TotalCostMicros != 6000 || summary.TotalRequests != 1 {
		t.Fatalf("unexpected spend summary: %+v (err=%v)", summary, err)
	}
	updatedOrg, _ := repo.GetOrganization(ctx, org.ID)
	if updatedOrg.SpentMicros != 6000 {
		t.Fatalf("expected org spent_micros=6000, got %d", updatedOrg.SpentMicros)
	}
}

func TestSpendOutboxSurvivesWorkerRestartAndDuplicateDelivery(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	ev := domain.SpendEvent{ID: "stable-spend-id", RequestID: "request-1", CostMicros: 42, StatusCode: 200}
	first := finops.NewSpendWorker(repo, nil, config.FinOpsConfig{})
	if err := first.Record(ctx, ev); err != nil {
		t.Fatal(err)
	}
	// No worker has delivered the row yet. A new worker represents a restarted process.
	restarted := finops.NewSpendWorker(repo, nil, config.FinOpsConfig{})
	if err := restarted.FlushNow(ctx); err != nil {
		t.Fatal(err)
	}
	// Simulate the worker committing to the ledger but crashing before outbox ack.
	if err := repo.RecordSpendBatch(ctx, []domain.SpendEvent{ev}); err != nil {
		t.Fatal(err)
	}
	// Re-enqueueing the same stable ID and delivering it again must not double-count.
	if err := restarted.Record(ctx, ev); err != nil {
		t.Fatal(err)
	}
	if err := restarted.FlushNow(ctx); err != nil {
		t.Fatal(err)
	}
	summary, err := repo.GetSpendSummary(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if summary.TotalRequests != 1 || summary.TotalCostMicros != 42 {
		t.Fatalf("duplicate delivery changed ledger: %+v", summary)
	}
}

func TestSpendOutboxRetryAndDeadLetterState(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	if err := repo.EnqueueSpendEvent(ctx, domain.SpendEvent{ID: "retry-id"}); err != nil {
		t.Fatal(err)
	}
	claimed, err := repo.ClaimSpendEvents(ctx, 1, time.Minute)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("claim: events=%d err=%v", len(claimed), err)
	}
	if err := repo.RetrySpendEvent(ctx, "retry-id", context.DeadlineExceeded, time.Now().Add(-time.Second), 2); err != nil {
		t.Fatal(err)
	}
	claimed, err = repo.ClaimSpendEvents(ctx, 1, time.Minute)
	if err != nil || len(claimed) != 1 {
		t.Fatalf("retry claim: events=%d err=%v", len(claimed), err)
	}
	if err := repo.RetrySpendEvent(ctx, "retry-id", context.DeadlineExceeded, time.Now(), 2); err != nil {
		t.Fatal(err)
	}
	claimed, err = repo.ClaimSpendEvents(ctx, 1, time.Minute)
	if err != nil || len(claimed) != 0 {
		t.Fatalf("dead-letter event was claimable: events=%d err=%v", len(claimed), err)
	}
}

func TestRecordReturnsPersistenceFailure(t *testing.T) {
	want := errors.New("database unavailable")
	worker := finops.NewSpendWorker(failingOutboxRepository{Repository: storage.NewMemoryRepository(), err: want}, nil, config.FinOpsConfig{})
	if err := worker.Record(context.Background(), domain.SpendEvent{RequestID: "request-1"}); !errors.Is(err, want) {
		t.Fatalf("Record error = %v, want %v", err, want)
	}
}

func TestSpendWorkerResetExpiredBudgetsClearsRedisAndAdvancesPeriod(t *testing.T) {
	ctx := context.Background()
	mr := miniredis.RunT(t)
	redisFabric := storage.NewRedisFabric(mr.Addr(), "", 0)
	t.Cleanup(func() { _ = redisFabric.Client().Close() })
	limiter := ratelimit.NewLimiter(redisFabric, 60, 300)

	repo := storage.NewMemoryRepository()
	now := time.Date(2026, 5, 10, 12, 0, 0, 0, time.UTC)
	expired := now.Add(-time.Minute)

	org := &domain.Organization{
		ID:                "org-sw-reset",
		Name:              "SW Org",
		Slug:              "sw-org",
		MaxBudgetMicros:   500,
		SpentMicros:       500,
		BudgetResetPeriod: domain.BudgetResetDaily,
		BudgetResetAt:     &expired,
		IsActive:          true,
	}
	team := &domain.Team{
		ID:                "team-sw-reset",
		OrgID:             org.ID,
		Name:              "SW Team",
		MaxBudgetMicros:   500,
		SpentMicros:       500,
		BudgetResetPeriod: domain.BudgetResetMonthly,
		BudgetResetAt:     &expired,
		IsActive:          true,
	}
	vk := &domain.VirtualKey{
		ID:                "vk-sw-reset",
		OrgID:             org.ID,
		TeamID:            team.ID,
		Name:              "SW Key",
		KeyHash:           "hash-sw-reset",
		MaxBudgetMicros:   500,
		SpentMicros:       500,
		BudgetResetPeriod: domain.BudgetResetDaily,
		BudgetResetAt:     &expired,
		IsActive:          true,
	}
	_ = repo.CreateOrganization(ctx, org)
	_ = repo.CreateTeam(ctx, team)
	_ = repo.CreateVirtualKey(ctx, vk)

	limiter.RecordSpendIncrement(ctx, vk.ID, team.ID, org.ID, 500)
	idCtx := &domain.IdentityContext{
		VirtualKeyID:        vk.ID,
		TeamID:              team.ID,
		OrgID:               org.ID,
		KeyMaxBudgetMicros:  500,
		TeamMaxBudgetMicros: 500,
		OrgMaxBudgetMicros:  500,
	}
	if _, err := limiter.AcquireWithBudget(ctx, idCtx, 1, 50, "req-exhausted"); err == nil {
		t.Fatal("expected request to be rejected while budget is exhausted")
	}

	sw := finops.NewSpendWorker(repo, limiter, config.FinOpsConfig{})
	count, err := sw.ResetExpiredBudgetsNow(ctx, now)
	if err != nil {
		t.Fatalf("ResetExpiredBudgetsNow: %v", err)
	}
	if count != 3 {
		t.Fatalf("expected 3 reset entities, got %d", count)
	}

	gotOrg, _ := repo.GetOrganization(ctx, org.ID)
	if gotOrg.SpentMicros != 0 || gotOrg.BudgetResetAt == nil || !gotOrg.BudgetResetAt.Equal(now.Add(24*time.Hour)) {
		t.Fatalf("org not properly reset: %+v", gotOrg)
	}
	gotTeam, _ := repo.GetTeam(ctx, team.ID)
	if gotTeam.SpentMicros != 0 || gotTeam.BudgetResetAt == nil || !gotTeam.BudgetResetAt.Equal(now.AddDate(0, 1, 0)) {
		t.Fatalf("team not properly reset: %+v", gotTeam)
	}
	gotVK, _ := repo.GetVirtualKeyByID(ctx, vk.ID)
	if gotVK.SpentMicros != 0 || gotVK.BudgetResetAt == nil || !gotVK.BudgetResetAt.Equal(now.Add(24*time.Hour)) {
		t.Fatalf("vk not properly reset: %+v", gotVK)
	}

	for _, key := range []string{"gw:spend:{org:org-sw-reset}:org:org-sw-reset", "gw:spend:{org:org-sw-reset}:team:team-sw-reset", "gw:spend:{org:org-sw-reset}:key:vk-sw-reset"} {
		if mr.Exists(key) {
			t.Fatalf("expected Redis key %q to be deleted", key)
		}
	}
	if pending, err := repo.ListPendingBudgetResets(ctx, 10); err != nil || len(pending) != 0 {
		t.Fatalf("expected delivered budget-reset outbox to be empty, pending=%v err=%v", pending, err)
	}

	release, err := limiter.AcquireWithBudget(ctx, idCtx, 1, 50, "req-reset-ok")
	if err != nil {
		t.Fatalf("expected request to be admitted after budget reset, got %v", err)
	}
	release(1, 50)
}

func TestSpendWorkerRetriesRedisAndRecordsDriftMetric(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()

	// Create a closed port to simulate an unreachable Redis instance.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadAddr := ln.Addr().String()
	_ = ln.Close()

	deadFabric := storage.NewRedisFabric(deadAddr, "", 0)
	t.Cleanup(func() { _ = deadFabric.Client().Close() })
	deadLimiter := ratelimit.NewLimiter(deadFabric, 60, 300)
	collector := observability.NewCollector()

	sw := finops.NewSpendWorker(repo, deadLimiter, config.FinOpsConfig{BatchSize: 10})
	sw.SetCollector(collector)

	ev := domain.SpendEvent{
		ID:           "ev-redis-retry-1",
		RequestID:    "req-redis-retry-1",
		VirtualKeyID: "vk-retry",
		OrgID:        "org-retry",
		CostMicros:   120,
		StatusCode:   200,
	}
	if err := sw.Record(ctx, ev); err != nil {
		t.Fatalf("Record failed: %v", err)
	}
	// First flush fails on Redis and schedules retry rather than marking delivered.
	if err := sw.FlushNow(ctx); err == nil {
		t.Fatal("expected FlushNow to return error when Redis is unreachable")
	}

	// Simulate recovery with a live Redis instance: outbox retry succeeds without double-counting SQL.
	mr := miniredis.RunT(t)
	liveFabric := storage.NewRedisFabric(mr.Addr(), "", 0)
	t.Cleanup(func() { _ = liveFabric.Client().Close() })
	liveLimiter := ratelimit.NewLimiter(liveFabric, 60, 300)

	// Re-enqueue / claim via a fresh event at attempt 12 to also verify drift metric on exhaustion,
	// and verify live retry on a recovered worker after retry backoff.
	if err := repo.RetrySpendEvent(ctx, ev.ID, errors.New("retry now"), time.Now().Add(-time.Second), 12); err != nil {
		t.Fatal(err)
	}
	recovered := finops.NewSpendWorker(repo, liveLimiter, config.FinOpsConfig{BatchSize: 10})
	if err := recovered.FlushNow(ctx); err != nil {
		t.Fatalf("recovered FlushNow failed: %v", err)
	}
	if got, _ := mr.Get("gw:spend:key:vk-retry"); got != "120" {
		t.Fatalf("gw:spend:key:vk-retry = %q, want 120", got)
	}
	summary, err := repo.GetSpendSummary(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	if summary.TotalRequests != 1 || summary.TotalCostMicros != 120 {
		t.Fatalf("unexpected SQL summary after retry: %+v", summary)
	}

	// Verify dead-lettered Redis failure increments SpendRedisDriftTotal.
	driftEv := domain.SpendEvent{
		ID:           "ev-redis-drift-1",
		RequestID:    "req-redis-drift-1",
		VirtualKeyID: "vk-drift",
		OrgID:        "org-drift",
		CostMicros:   50,
		StatusCode:   200,
	}
	if err := repo.EnqueueSpendEvent(ctx, driftEv); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 11; i++ {
		claimed, claimErr := repo.ClaimSpendEvents(ctx, 1, time.Minute)
		if claimErr != nil || len(claimed) != 1 {
			t.Fatalf("attempt %d claim: len=%d err=%v", i+1, len(claimed), claimErr)
		}
		if retryErr := repo.RetrySpendEvent(ctx, driftEv.ID, errors.New("still down"), time.Now().Add(-time.Second), 12); retryErr != nil {
			t.Fatal(retryErr)
		}
	}
	// 12th attempt via FlushNow moves to dead-letter and increments drift metric.
	if err := sw.FlushNow(ctx); err == nil {
		t.Fatal("expected FlushNow error on 12th attempt")
	}
	if got := collector.Snapshot().SpendRedisDriftTotal; got != 1 {
		t.Fatalf("SpendRedisDriftTotal = %d, want 1", got)
	}
}
