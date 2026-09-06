package storage

import (
	"context"
	"errors"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

func TestQuotaPolicyRepository_MemoryCRUDAndSpend(t *testing.T) {
	ctx := context.Background()
	repo := NewMemoryRepository()

	// Validate invalid scope rejected.
	err := repo.UpsertQuotaPolicy(ctx, &domain.QuotaPolicy{
		OrgID:     "org-1",
		ScopeType: domain.QuotaScopeType("unknown_scope"),
		ScopeID:   "s1",
		IsActive:  true,
	})
	if err == nil {
		t.Fatal("expected error for invalid scope_type")
	}

	// Upsert with defaults (empty model_pattern -> "*", empty reset period -> "monthly").
	p1 := &domain.QuotaPolicy{
		OrgID:           "org-1",
		ScopeType:       domain.QuotaScopeEndUser,
		ScopeID:         "eu-100",
		RPMLimit:        60,
		TPMLimit:        100000,
		ITPMLimit:       60000,
		OTPMLimit:       40000,
		TPDLimit:        1000000,
		MaxConcurrent:   5,
		MaxBudgetMicros: 5_000_000,
		MaxIterations:   25,
		WindowTTLSec:    1800,
		IsActive:        true,
	}
	if err := repo.UpsertQuotaPolicy(ctx, p1); err != nil {
		t.Fatalf("UpsertQuotaPolicy p1: %v", err)
	}
	if p1.ID == "" || p1.ModelPattern != "*" || p1.BudgetResetPeriod != domain.BudgetResetMonthly || p1.BudgetResetAt == nil {
		t.Fatalf("unexpected normalized p1: %+v", p1)
	}

	// Increment spend durably.
	if err := repo.IncrementQuotaPolicySpend(ctx, p1.ID, 125_000); err != nil {
		t.Fatalf("IncrementQuotaPolicySpend: %v", err)
	}
	got, err := repo.GetQuotaPolicy(ctx, p1.ID)
	if err != nil {
		t.Fatalf("GetQuotaPolicy: %v", err)
	}
	if got.SpentMicros != 125_000 {
		t.Fatalf("SpentMicros = %d, want 125000", got.SpentMicros)
	}

	// Upserting same (org, scope_type, scope_id, model_pattern) updates limits in place
	// while preserving ID and accumulated SpentMicros.
	origID := p1.ID
	p1Update := &domain.QuotaPolicy{
		OrgID:           "org-1",
		ScopeType:       domain.QuotaScopeEndUser,
		ScopeID:         "eu-100",
		ModelPattern:    "*",
		RPMLimit:        120,
		MaxBudgetMicros: 10_000_000,
		IsActive:        true,
	}
	if err := repo.UpsertQuotaPolicy(ctx, p1Update); err != nil {
		t.Fatalf("UpsertQuotaPolicy update: %v", err)
	}
	if p1Update.ID != origID {
		t.Fatalf("upsert changed ID from %q to %q", origID, p1Update.ID)
	}
	if p1Update.SpentMicros != 125_000 {
		t.Fatalf("upsert wiped SpentMicros: got %d, want 125000", p1Update.SpentMicros)
	}

	// Compile to descriptor and verify fields.
	desc := p1Update.ToDescriptor()
	if desc.PolicyID != origID || desc.RPMLimit != 120 || desc.SpentFloorMicros != 125_000 || !desc.HasLimits() {
		t.Fatalf("unexpected compiled descriptor: %+v", desc)
	}

	// Add second policy (inactive, specific model pattern) and third policy (different org).
	p2 := &domain.QuotaPolicy{
		OrgID:        "org-1",
		ScopeType:    domain.QuotaScopeModelPerKey,
		ScopeID:      "vk-1",
		ModelPattern: "gpt-4.1",
		ITPMLimit:    5000,
		IsActive:     false,
	}
	if err := repo.UpsertQuotaPolicy(ctx, p2); err != nil {
		t.Fatalf("UpsertQuotaPolicy p2: %v", err)
	}
	p3 := &domain.QuotaPolicy{
		OrgID:     "org-2",
		ScopeType: domain.QuotaScopeOrg,
		ScopeID:   "org-2",
		RPMLimit:  10,
		IsActive:  true,
	}
	if err := repo.UpsertQuotaPolicy(ctx, p3); err != nil {
		t.Fatalf("UpsertQuotaPolicy p3: %v", err)
	}

	// Duplicate ID with different tuple returns ErrConflict.
	dupIDErr := repo.UpsertQuotaPolicy(ctx, &domain.QuotaPolicy{
		ID:        p2.ID,
		OrgID:     "org-1",
		ScopeType: domain.QuotaScopeTag,
		ScopeID:   "prod",
		IsActive:  true,
	})
	if !errors.Is(dupIDErr, ErrConflict) {
		t.Fatalf("expected ErrConflict for duplicate ID with different tuple, got %v", dupIDErr)
	}

	// List filtering.
	org1All, err := repo.ListQuotaPolicies(ctx, QuotaPolicyFilter{OrgID: "org-1"})
	if err != nil || len(org1All) != 2 {
		t.Fatalf("ListQuotaPolicies org-1 all = %d (err=%v), want 2", len(org1All), err)
	}
	org1Active, err := repo.ListQuotaPolicies(ctx, QuotaPolicyFilter{OrgID: "org-1", ActiveOnly: true})
	if err != nil || len(org1Active) != 1 || org1Active[0].ID != origID {
		t.Fatalf("ListQuotaPolicies org-1 active = %+v (err=%v), want [%s]", org1Active, err, origID)
	}
	byModel, err := repo.ListQuotaPolicies(ctx, QuotaPolicyFilter{OrgID: "org-1", ScopeType: domain.QuotaScopeModelPerKey, ModelPattern: "gpt-4.1"})
	if err != nil || len(byModel) != 1 || byModel[0].ID != p2.ID {
		t.Fatalf("ListQuotaPolicies by model = %+v (err=%v), want [%s]", byModel, err, p2.ID)
	}

	// Delete and verify ErrNotFound.
	if err := repo.DeleteQuotaPolicy(ctx, p2.ID); err != nil {
		t.Fatalf("DeleteQuotaPolicy: %v", err)
	}
	if _, err := repo.GetQuotaPolicy(ctx, p2.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound after delete, got %v", err)
	}
	if err := repo.IncrementQuotaPolicySpend(ctx, p2.ID, 10); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound on spend increment after delete, got %v", err)
	}
	if err := repo.IncrementQuotaPolicySpend(ctx, origID, -5); err == nil {
		t.Fatal("expected error for negative deltaMicros")
	}

	// Verify PostgresRepository with nil pool cleanly delegates to in-memory store.
	pgNil := &PostgresRepository{mem: NewMemoryRepository()}
	var qRepo QuotaPolicyRepository = pgNil
	pNil := &domain.QuotaPolicy{
		OrgID:     "org-pg-nil",
		ScopeType: domain.QuotaScopeMCPServer,
		ScopeID:   "mcp-github",
		RPMLimit:  30,
		IsActive:  true,
	}
	if err := qRepo.UpsertQuotaPolicy(ctx, pNil); err != nil {
		t.Fatalf("pgNil UpsertQuotaPolicy: %v", err)
	}
	if err := qRepo.IncrementQuotaPolicySpend(ctx, pNil.ID, 500); err != nil {
		t.Fatalf("pgNil IncrementQuotaPolicySpend: %v", err)
	}
	gotNil, err := qRepo.GetQuotaPolicy(ctx, pNil.ID)
	if err != nil || gotNil.SpentMicros != 500 {
		t.Fatalf("pgNil GetQuotaPolicy = %+v (err=%v), want spent=500", gotNil, err)
	}
}
