package storage_test

import (
	"context"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

func TestMemoryResetExpiredBudgetsWithIDs(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	now := time.Date(2026, 5, 10, 12, 0, 0, 0, time.UTC)
	expired := now.Add(-time.Minute)
	future := now.Add(2 * time.Hour)

	orgExpired := &domain.Organization{
		ID:                "org-expired",
		Name:              "Expired Org",
		Slug:              "expired-org",
		MaxBudgetMicros:   1000,
		SpentMicros:       900,
		BudgetResetPeriod: domain.BudgetResetDaily,
		BudgetResetAt:     &expired,
		IsActive:          true,
	}
	orgNever := &domain.Organization{
		ID:                "org-never",
		Name:              "Never Org",
		Slug:              "never-org",
		MaxBudgetMicros:   1000,
		SpentMicros:       500,
		BudgetResetPeriod: domain.BudgetResetNever,
		BudgetResetAt:     &expired,
		IsActive:          true,
	}
	teamExpired := &domain.Team{
		ID:                "team-expired",
		OrgID:             orgExpired.ID,
		Name:              "Expired Team",
		MaxBudgetMicros:   1000,
		SpentMicros:       750,
		BudgetResetPeriod: domain.BudgetResetMonthly,
		BudgetResetAt:     &expired,
		IsActive:          true,
	}
	teamFuture := &domain.Team{
		ID:                "team-future",
		OrgID:             orgExpired.ID,
		Name:              "Future Team",
		MaxBudgetMicros:   1000,
		SpentMicros:       300,
		BudgetResetPeriod: domain.BudgetResetDaily,
		BudgetResetAt:     &future,
		IsActive:          true,
	}
	vkExpired := &domain.VirtualKey{
		ID:                "vk-expired",
		OrgID:             orgExpired.ID,
		TeamID:            teamExpired.ID,
		Name:              "Expired Key",
		KeyHash:           "hash-expired",
		MaxBudgetMicros:   1000,
		SpentMicros:       800,
		BudgetResetPeriod: domain.BudgetResetDaily,
		BudgetResetAt:     &expired,
		IsActive:          true,
	}

	for _, err := range []error{
		repo.CreateOrganization(ctx, orgExpired),
		repo.CreateOrganization(ctx, orgNever),
		repo.CreateTeam(ctx, teamExpired),
		repo.CreateTeam(ctx, teamFuture),
		repo.CreateVirtualKey(ctx, vkExpired),
	} {
		if err != nil {
			t.Fatalf("seed entity: %v", err)
		}
	}

	res, err := repo.ResetExpiredBudgetsWithIDs(ctx, now)
	if err != nil {
		t.Fatalf("ResetExpiredBudgetsWithIDs: %v", err)
	}
	if res.Total() != 3 {
		t.Fatalf("expected 3 reset entities, got %d (%+v)", res.Total(), res)
	}
	if len(res.OrgIDs) != 1 || res.OrgIDs[0] != "org-expired" {
		t.Fatalf("unexpected OrgIDs: %v", res.OrgIDs)
	}
	if len(res.TeamIDs) != 1 || res.TeamIDs[0] != "team-expired" {
		t.Fatalf("unexpected TeamIDs: %v", res.TeamIDs)
	}
	if len(res.VirtualKeyIDs) != 1 || res.VirtualKeyIDs[0] != "vk-expired" {
		t.Fatalf("unexpected VirtualKeyIDs: %v", res.VirtualKeyIDs)
	}

	gotOrg, _ := repo.GetOrganization(ctx, "org-expired")
	if gotOrg.SpentMicros != 0 {
		t.Fatalf("expected org spent_micros=0, got %d", gotOrg.SpentMicros)
	}
	if gotOrg.BudgetResetAt == nil || !gotOrg.BudgetResetAt.Equal(now.Add(24*time.Hour)) {
		t.Fatalf("expected daily org budget_reset_at=%v, got %v", now.Add(24*time.Hour), gotOrg.BudgetResetAt)
	}

	gotOrgNever, _ := repo.GetOrganization(ctx, "org-never")
	if gotOrgNever.SpentMicros != 500 {
		t.Fatalf("expected never-reset org spent_micros=500, got %d", gotOrgNever.SpentMicros)
	}

	gotTeam, _ := repo.GetTeam(ctx, "team-expired")
	if gotTeam.SpentMicros != 0 {
		t.Fatalf("expected team spent_micros=0, got %d", gotTeam.SpentMicros)
	}
	if gotTeam.BudgetResetAt == nil || !gotTeam.BudgetResetAt.Equal(now.AddDate(0, 1, 0)) {
		t.Fatalf("expected monthly team budget_reset_at=%v, got %v", now.AddDate(0, 1, 0), gotTeam.BudgetResetAt)
	}

	gotTeamFuture, _ := repo.GetTeam(ctx, "team-future")
	if gotTeamFuture.SpentMicros != 300 {
		t.Fatalf("expected future team spent_micros=300, got %d", gotTeamFuture.SpentMicros)
	}

	gotVK, _ := repo.GetVirtualKeyByID(ctx, "vk-expired")
	if gotVK.SpentMicros != 0 {
		t.Fatalf("expected vk spent_micros=0, got %d", gotVK.SpentMicros)
	}

	// Re-running a minute later must not reset again because budget_reset_at was advanced.
	again, err := repo.ResetExpiredBudgets(ctx, now.Add(time.Minute))
	if err != nil {
		t.Fatalf("second ResetExpiredBudgets: %v", err)
	}
	if again != 0 {
		t.Fatalf("expected 0 resets on immediate follow-up cycle, got %d", again)
	}
}
