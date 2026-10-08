package finops_test

import (
	"context"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/finops"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

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

	sw.Enqueue(domain.SpendEvent{
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
	})

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
