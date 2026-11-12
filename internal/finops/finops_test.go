package finops_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/finops"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
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
