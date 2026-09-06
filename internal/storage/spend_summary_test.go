package storage

import (
	"context"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

func TestSpendSummarySeparatesUnpricedUsage(t *testing.T) {
	repo := NewMemoryRepository()
	events := []domain.SpendEvent{
		{ID: "unknown", PricingStatus: domain.PricingStatusUnknown, Usage: domain.TokenUsage{TotalTokens: 17}},
		{ID: "unrecorded", PricingStatus: domain.PricingStatusUnrecorded, Usage: domain.TokenUsage{TotalTokens: 8}},
		{ID: "known-zero", PricingStatus: domain.PricingStatusVerified, Usage: domain.TokenUsage{TotalTokens: 5}},
		{ID: "known-cost", PricingStatus: domain.PricingStatusCustom, Usage: domain.TokenUsage{TotalTokens: 10}, CostMicros: 200},
	}
	if err := repo.RecordSpendBatch(context.Background(), events); err != nil {
		t.Fatalf("record spend events: %v", err)
	}

	summary, err := repo.GetSpendSummary(context.Background(), "")
	if err != nil {
		t.Fatalf("get spend summary: %v", err)
	}
	if summary.TotalRequests != 4 || summary.TotalTokens != 40 || summary.TotalCostMicros != 200 {
		t.Fatalf("unexpected totals: %+v", summary)
	}
	if summary.UnpricedRequests != 2 || summary.UnpricedTokens != 25 {
		t.Fatalf("expected only unknown/unrecorded usage to be unpriced, got %+v", summary)
	}
}
