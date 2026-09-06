package storage

import (
	"context"
	"fmt"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

func TestMemoryRepositoryListGlobalModelsByNameIndexTracksUpserts(t *testing.T) {
	repo := NewMemoryRepository()
	ctx := context.Background()
	model := &domain.GlobalModel{ID: "test-provider/indexed-model", Provider: domain.ProviderOpenAI, ModelName: "indexed-model"}
	if err := repo.UpsertGlobalModel(ctx, model); err != nil {
		t.Fatal(err)
	}

	got, err := repo.ListGlobalModelsByName(ctx, domain.ProviderOpenAI, "indexed-model")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != model.ID {
		t.Fatalf("provider-filtered indexed lookup = %#v", got)
	}

	all, err := repo.ListGlobalModelsByName(ctx, "", "indexed-model")
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 1 || all[0].ID != model.ID {
		t.Fatalf("cross-provider indexed lookup = %#v", all)
	}

	model.ModelName = "renamed-model"
	if err := repo.UpsertGlobalModel(ctx, model); err != nil {
		t.Fatal(err)
	}
	old, err := repo.ListGlobalModelsByName(ctx, "", "indexed-model")
	if err != nil {
		t.Fatal(err)
	}
	if len(old) != 0 {
		t.Fatalf("old name index retained stale entries: %#v", old)
	}
	newName, err := repo.ListGlobalModelsByName(ctx, domain.ProviderOpenAI, "renamed-model")
	if err != nil {
		t.Fatal(err)
	}
	if len(newName) != 1 || newName[0].ID != model.ID {
		t.Fatalf("updated name index = %#v", newName)
	}
}

func TestMemoryRepositoryPricingSummaryIsCachedAndInvalidated(t *testing.T) {
	repo := NewMemoryRepository()
	ctx := context.Background()
	first, err := repo.GetGlobalModelPricingSummary(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !first.HasPricedModels || !first.Rebuilt || first.CatalogSize == 0 {
		t.Fatalf("initial pricing summary = %+v", first)
	}
	second, err := repo.GetGlobalModelPricingSummary(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if second.Rebuilt || repo.PricingSummaryRebuilds() != 1 {
		t.Fatalf("cached summary should not rebuild: summary=%+v rebuilds=%d", second, repo.PricingSummaryRebuilds())
	}

	if err := repo.UpsertGlobalModel(ctx, &domain.GlobalModel{
		ID: "openai/summary-invalidation-model", Provider: domain.ProviderOpenAI, ModelName: "summary-invalidation-model",
		PricingStatus: domain.PricingStatusVerified, InputCostMicrosPer1M: 999999999, OutputCostMicrosPer1M: 888888888, MaxOutputTokens: 12345,
	}); err != nil {
		t.Fatal(err)
	}
	updated, err := repo.GetGlobalModelPricingSummary(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if !updated.Rebuilt || updated.InputCostMicrosPer1M != 999999999 || updated.OutputCostMicrosPer1M != 888888888 || updated.MaxOutputTokens < 12345 {
		t.Fatalf("pricing summary did not reflect catalog update: %+v", updated)
	}
}

func BenchmarkMemoryRepositoryGlobalModelLookup(b *testing.B) {
	repo := NewMemoryRepository()
	ctx := context.Background()
	for i := 0; i < 5500; i++ {
		modelName := fmt.Sprintf("synthetic-model-%04d", i)
		if err := repo.UpsertGlobalModel(ctx, &domain.GlobalModel{
			ID:        "benchmark/" + modelName,
			Provider:  domain.ProviderOpenAI,
			ModelName: modelName,
		}); err != nil {
			b.Fatal(err)
		}
	}
	b.Run("full_catalog", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := repo.ListGlobalModels(ctx); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("indexed_name", func(b *testing.B) {
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			if _, err := repo.ListGlobalModelsByName(ctx, domain.ProviderOpenAI, "synthetic-model-5499"); err != nil {
				b.Fatal(err)
			}
		}
	})
}
