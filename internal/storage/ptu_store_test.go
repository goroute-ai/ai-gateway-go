package storage

import (
	"context"
	"errors"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

func TestPTUShareRepository_MemoryAndPostgresNilPool(t *testing.T) {
	ctx := context.Background()

	runSuite := func(t *testing.T, repo PTUShareRepository, setupRepo Repository, deleteRepo Repository) {
		t.Helper()

		org := &domain.Organization{ID: "org-ptu-1", Name: "PTU Org", Slug: "ptu-org", IsActive: true}
		if err := setupRepo.CreateOrganization(ctx, org); err != nil {
			t.Fatalf("CreateOrganization: %v", err)
		}
		team1 := &domain.Team{ID: "team-ptu-1", OrgID: org.ID, Name: "Team One", IsActive: true}
		team2 := &domain.Team{ID: "team-ptu-2", OrgID: org.ID, Name: "Team Two", IsActive: true}
		if err := setupRepo.CreateTeam(ctx, team1); err != nil {
			t.Fatalf("CreateTeam 1: %v", err)
		}
		if err := setupRepo.CreateTeam(ctx, team2); err != nil {
			t.Fatalf("CreateTeam 2: %v", err)
		}

		// Validation checks
		if err := repo.UpsertDeploymentPTUShare(ctx, &domain.DeploymentPTUShare{
			OrgID:        org.ID,
			DeploymentID: "dep-1",
			TeamID:       team1.ID,
			ReservedRPM:  -1,
		}); err == nil {
			t.Fatal("expected error for negative reserved_rpm")
		}

		// Insert two PTU shares on dep-1
		s1 := &domain.DeploymentPTUShare{
			OrgID:        org.ID,
			DeploymentID: "dep-1",
			TeamID:       team1.ID,
			ReservedRPM:  60,
			ReservedTPM:  60000,
		}
		if err := repo.UpsertDeploymentPTUShare(ctx, s1); err != nil {
			t.Fatalf("UpsertDeploymentPTUShare s1: %v", err)
		}
		if s1.ID == "" {
			t.Fatal("expected generated ID on s1")
		}
		origID := s1.ID

		// Upsert same (deployment_id, team_id) updates in place and keeps ID
		s1Update := &domain.DeploymentPTUShare{
			OrgID:        org.ID,
			DeploymentID: "dep-1",
			TeamID:       team1.ID,
			ReservedRPM:  80,
			ReservedTPM:  80000,
		}
		if err := repo.UpsertDeploymentPTUShare(ctx, s1Update); err != nil {
			t.Fatalf("UpsertDeploymentPTUShare update: %v", err)
		}
		if s1Update.ID != origID {
			t.Fatalf("expected preserved ID %q on upsert, got %q", origID, s1Update.ID)
		}

		s2 := &domain.DeploymentPTUShare{
			OrgID:        org.ID,
			DeploymentID: "dep-1",
			TeamID:       team2.ID,
			ReservedRPM:  20,
			ReservedTPM:  20000,
		}
		if err := repo.UpsertDeploymentPTUShare(ctx, s2); err != nil {
			t.Fatalf("UpsertDeploymentPTUShare s2: %v", err)
		}

		list, err := repo.ListDeploymentPTUShares(ctx, "dep-1")
		if err != nil {
			t.Fatalf("ListDeploymentPTUShares: %v", err)
		}
		if len(list) != 2 {
			t.Fatalf("expected 2 PTU shares, got %d", len(list))
		}
		if list[0].TeamID != team1.ID || list[0].ReservedRPM != 80 {
			t.Fatalf("unexpected first share: %+v", list[0])
		}

		has1, err := repo.HasTeamPTUShares(ctx, team1.ID)
		if err != nil || !has1 {
			t.Fatalf("HasTeamPTUShares(team1) = %v, err=%v; want true", has1, err)
		}

		// DeleteTeam must fail while team1 holds an active PTU share.
		err = deleteRepo.DeleteTeam(ctx, team1.ID)
		if !errors.Is(err, ErrTeamHasActivePTUShares) {
			t.Fatalf("DeleteTeam with active PTU share err = %v, want ErrTeamHasActivePTUShares", err)
		}

		// Delete share for team1, verify HasTeamPTUShares is false and DeleteTeam succeeds.
		if err := repo.DeleteDeploymentPTUShare(ctx, "dep-1", team1.ID); err != nil {
			t.Fatalf("DeleteDeploymentPTUShare: %v", err)
		}
		if err := repo.DeleteDeploymentPTUShare(ctx, "dep-1", team1.ID); !errors.Is(err, ErrNotFound) {
			t.Fatalf("expected ErrNotFound on second delete, got %v", err)
		}
		has1After, err := repo.HasTeamPTUShares(ctx, team1.ID)
		if err != nil || has1After {
			t.Fatalf("HasTeamPTUShares(team1) after delete = %v, err=%v; want false", has1After, err)
		}
		if err := deleteRepo.DeleteTeam(ctx, team1.ID); err != nil {
			t.Fatalf("DeleteTeam after removing PTU share: %v", err)
		}

		// Priority classes CRUD + sorting + defaults
		pcLow := &domain.PriorityClass{
			OrgID:        org.ID,
			Name:         "batch",
			Weight:       1.0,
			PriorityRank: 10,
		}
		pcHigh := &domain.PriorityClass{
			OrgID:             org.ID,
			Name:              "critical",
			Weight:            5.0,
			PriorityRank:      0,
			MaxBorrowMultiple: 3.0,
		}
		if err := repo.UpsertPriorityClass(ctx, pcLow); err != nil {
			t.Fatalf("UpsertPriorityClass low: %v", err)
		}
		if pcLow.MaxBorrowMultiple != 2.0 {
			t.Fatalf("expected default MaxBorrowMultiple 2.0, got %v", pcLow.MaxBorrowMultiple)
		}
		if err := repo.UpsertPriorityClass(ctx, pcHigh); err != nil {
			t.Fatalf("UpsertPriorityClass high: %v", err)
		}
		classes, err := repo.ListPriorityClasses(ctx, org.ID)
		if err != nil {
			t.Fatalf("ListPriorityClasses: %v", err)
		}
		if len(classes) != 2 || classes[0].Name != "critical" || classes[1].Name != "batch" {
			t.Fatalf("unexpected priority classes order/content: %+v", classes)
		}
	}

	t.Run("memory", func(t *testing.T) {
		mem := NewMemoryRepository()
		runSuite(t, mem, mem, mem)
	})

	t.Run("postgres_nil_pool", func(t *testing.T) {
		mem := NewMemoryRepository()
		pg := &PostgresRepository{mem: mem}
		runSuite(t, pg, mem, pg)
	})
}
