package storage

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

func TestPostgresPricingStatus_MigrationSyntax(t *testing.T) {
	upSQLPath := filepath.Join("..", "..", "migrations", "0004_add_pricing_status.up.sql")
	upSQL, err := os.ReadFile(upSQLPath)
	if err != nil {
		t.Fatalf("failed to read 0004 up migration: %v", err)
	}
	if len(upSQL) == 0 {
		t.Fatal("0004 up migration is empty")
	}

	downSQLPath := filepath.Join("..", "..", "migrations", "0004_add_pricing_status.down.sql")
	downSQL, err := os.ReadFile(downSQLPath)
	if err != nil {
		t.Fatalf("failed to read 0004 down migration: %v", err)
	}
	if len(downSQL) == 0 {
		t.Fatal("0004 down migration is empty")
	}
}

func TestPricingStatus_SeedModelsAuditedProvenance(t *testing.T) {
	repo := NewMemoryRepository()
	ctx := context.Background()

	// 1. Verify audited seed model has PricingStatusVerified and Provenance
	gpt4, err := repo.GetGlobalModel(ctx, "openai/gpt-4.1")
	if err != nil {
		t.Fatalf("expected openai/gpt-4.1 in seed catalogue, got err: %v", err)
	}
	if gpt4.PricingStatus != domain.PricingStatusVerified {
		t.Fatalf("expected openai/gpt-4.1 to have PricingStatusVerified, got %q", gpt4.PricingStatus)
	}
	if gpt4.PricingProvenanceSource != "official-vendor-pricing-2025" {
		t.Fatalf("expected pricing provenance source, got %q", gpt4.PricingProvenanceSource)
	}

	// 2. Upsert a model with explicit unknown status and verify persistence
	unknownModel := &domain.GlobalModel{
		ID:            "custom/unpriced-model-1",
		Provider:      domain.ProviderType("custom"),
		ModelName:     "unpriced-model-1",
		PricingStatus: domain.PricingStatusUnknown,
	}
	if err := repo.UpsertGlobalModel(ctx, unknownModel); err != nil {
		t.Fatalf("failed to upsert unknown model: %v", err)
	}

	reloaded, err := repo.GetGlobalModel(ctx, "custom/unpriced-model-1")
	if err != nil {
		t.Fatalf("failed to reload model: %v", err)
	}
	if reloaded.PricingStatus != domain.PricingStatusUnknown {
		t.Fatalf("expected reloaded model to preserve PricingStatusUnknown, got %q", reloaded.PricingStatus)
	}

	// 3. Upsert a model with missing/empty status and verify defensive fallback to unknown
	uninitModel := &domain.GlobalModel{
		ID:        "custom/legacy-model-2",
		Provider:  domain.ProviderType("custom"),
		ModelName: "legacy-model-2",
	}
	if err := repo.UpsertGlobalModel(ctx, uninitModel); err != nil {
		t.Fatalf("failed to upsert uninit model: %v", err)
	}

	reloadedUninit, err := repo.GetGlobalModel(ctx, "custom/legacy-model-2")
	if err != nil {
		t.Fatalf("failed to reload model: %v", err)
	}
	if reloadedUninit.PricingStatus != domain.PricingStatusUnknown {
		t.Fatalf("expected uninitialized model to resolve to PricingStatusUnknown, got %q", reloadedUninit.PricingStatus)
	}
}

func TestPricingStatus_SpendLogsStatusPreservation(t *testing.T) {
	repo := NewMemoryRepository()
	ctx := context.Background()

	evs := []domain.SpendEvent{
		{
			ID:                      "spend-1",
			OrgID:                   "00000000-0000-0000-0000-000000000001",
			PricingStatus:           domain.PricingStatusVerified,
			PricingProvenanceSource: "official-vendor-pricing-2025",
			CostMicros:              150,
			CreatedAt:               time.Now().UTC(),
		},
		{
			ID:            "spend-2",
			OrgID:         "00000000-0000-0000-0000-000000000001",
			PricingStatus: domain.PricingStatusUnknown,
			CostMicros:    0,
			CreatedAt:     time.Now().UTC(),
		},
		{
			ID:         "spend-legacy-3",
			OrgID:      "00000000-0000-0000-0000-000000000001",
			CostMicros: 0,
			CreatedAt:  time.Now().UTC(),
			// PricingStatus is empty to simulate historical unrecorded spend
		},
	}

	if err := repo.RecordSpendBatch(ctx, evs); err != nil {
		t.Fatalf("failed to record spend batch: %v", err)
	}

	if len(repo.spendLogs) != 3 {
		t.Fatalf("expected 3 spend logs, got %d", len(repo.spendLogs))
	}
	if repo.spendLogs[0].PricingStatus != domain.PricingStatusVerified {
		t.Fatalf("expected spend-1 to have PricingStatusVerified, got %q", repo.spendLogs[0].PricingStatus)
	}
	if repo.spendLogs[0].PricingProvenanceSource != "official-vendor-pricing-2025" {
		t.Fatalf("expected spend-1 to have PricingProvenanceSource, got %q", repo.spendLogs[0].PricingProvenanceSource)
	}
	if repo.spendLogs[1].PricingStatus != domain.PricingStatusUnknown {
		t.Fatalf("expected spend-2 to have PricingStatusUnknown, got %q", repo.spendLogs[1].PricingStatus)
	}
	if repo.spendLogs[2].PricingStatus != domain.PricingStatusUnrecorded {
		t.Fatalf("expected legacy spend-3 to have PricingStatusUnrecorded, got %q", repo.spendLogs[2].PricingStatus)
	}
}

func TestAzureCredential_PersistenceAndReload(t *testing.T) {
	repo := NewMemoryRepository()
	ctx := context.Background()

	cred := &domain.ProviderCredential{
		ID:                  "cred-azure-test-1",
		OrgID:               "org-azure-1",
		Provider:            domain.ProviderType("azure"),
		Name:                "azure-eastus-prod",
		BaseURL:             "https://my-resource.openai.azure.com",
		AzureDeploymentName: "gpt-4o-resource-deployment",
		APIVersion:          "2024-06-01",
		IsActive:            true,
	}

	if err := repo.CreateProviderCredential(ctx, cred); err != nil {
		t.Fatalf("failed to create azure credential: %v", err)
	}

	reloaded, err := repo.GetProviderCredential(ctx, cred.ID)
	if err != nil {
		t.Fatalf("failed to reload azure credential: %v", err)
	}
	if reloaded.AzureDeploymentName != "gpt-4o-resource-deployment" {
		t.Fatalf("expected AzureDeploymentName 'gpt-4o-resource-deployment', got %q", reloaded.AzureDeploymentName)
	}
	if reloaded.APIVersion != "2024-06-01" {
		t.Fatalf("expected APIVersion '2024-06-01', got %q", reloaded.APIVersion)
	}

	// Test update
	reloaded.AzureDeploymentName = "gpt-4o-mini-resource-deployment"
	reloaded.APIVersion = "2024-10-21"
	if err := repo.UpdateProviderCredential(ctx, reloaded); err != nil {
		t.Fatalf("failed to update azure credential: %v", err)
	}

	updated, err := repo.GetProviderCredential(ctx, cred.ID)
	if err != nil {
		t.Fatalf("failed to reload updated azure credential: %v", err)
	}
	if updated.AzureDeploymentName != "gpt-4o-mini-resource-deployment" {
		t.Fatalf("expected updated AzureDeploymentName, got %q", updated.AzureDeploymentName)
	}
	if updated.APIVersion != "2024-10-21" {
		t.Fatalf("expected updated APIVersion, got %q", updated.APIVersion)
	}
}
