package storage

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/jackc/pgx/v5"
)

func TestProjectAndMembershipRepository_MemoryCRUDAndVirtualKeyBinding(t *testing.T) {
	ctx := context.Background()
	repo := NewMemoryRepository()

	org := &domain.Organization{ID: "org-pm", Name: "PM Org", Slug: "pm-org", IsActive: true}
	if err := repo.CreateOrganization(ctx, org); err != nil {
		t.Fatalf("CreateOrganization: %v", err)
	}
	teamA := &domain.Team{ID: "team-a", OrgID: org.ID, Name: "Team A", IsActive: true}
	teamB := &domain.Team{ID: "team-b", OrgID: org.ID, Name: "Team B", IsActive: true}
	if err := repo.CreateTeam(ctx, teamA); err != nil {
		t.Fatalf("CreateTeam A: %v", err)
	}
	if err := repo.CreateTeam(ctx, teamB); err != nil {
		t.Fatalf("CreateTeam B: %v", err)
	}
	user := &domain.User{ID: "usr-1", OrgID: org.ID, Email: "u1@pm.example", Name: "User 1", Role: domain.RoleDeveloper, IsActive: true}
	if err := repo.CreateUser(ctx, user); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	// M:N Team Memberships for same user across Team A and Team B
	mA := &domain.TeamMembership{
		OrgID:           org.ID,
		TeamID:          teamA.ID,
		UserID:          user.ID,
		Role:            domain.RoleDeveloper,
		MaxBudgetMicros: 1_000_000,
		RPMLimit:        20,
		TPMLimit:        5000,
		AllowedModels:   []string{"gpt-4.1"},
	}
	if err := repo.UpsertTeamMembership(ctx, mA); err != nil {
		t.Fatalf("UpsertTeamMembership A: %v", err)
	}
	mB := &domain.TeamMembership{
		OrgID:           org.ID,
		TeamID:          teamB.ID,
		UserID:          user.ID,
		Role:            domain.RoleTeamAdmin,
		MaxBudgetMicros: 2_000_000,
		RPMLimit:        40,
		TPMLimit:        10000,
		AllowedModels:   []string{"gpt-4.1-mini"},
	}
	if err := repo.UpsertTeamMembership(ctx, mB); err != nil {
		t.Fatalf("UpsertTeamMembership B: %v", err)
	}

	gotA, err := repo.GetTeamMembership(ctx, teamA.ID, user.ID)
	if err != nil {
		t.Fatalf("GetTeamMembership A: %v", err)
	}
	if gotA.Role != domain.RoleDeveloper || gotA.RPMLimit != 20 || len(gotA.AllowedModels) != 1 || gotA.AllowedModels[0] != "gpt-4.1" {
		t.Fatalf("unexpected membership A: %+v", gotA)
	}

	// Upsert preserves ID, CreatedAt, and max(spent_micros)
	gotA.SpentMicros = 500
	if err := repo.UpsertTeamMembership(ctx, gotA); err != nil {
		t.Fatalf("UpsertTeamMembership A spend: %v", err)
	}
	mAUpdate := &domain.TeamMembership{
		OrgID:           org.ID,
		TeamID:          teamA.ID,
		UserID:          user.ID,
		Role:            domain.RoleTeamAdmin,
		MaxBudgetMicros: 1_500_000,
		SpentMicros:     100, // lower than existing 500 -> must preserve 500
		RPMLimit:        30,
	}
	if err := repo.UpsertTeamMembership(ctx, mAUpdate); err != nil {
		t.Fatalf("UpsertTeamMembership A update: %v", err)
	}
	if mAUpdate.ID != gotA.ID || mAUpdate.SpentMicros != 500 || mAUpdate.Role != domain.RoleTeamAdmin {
		t.Fatalf("expected upsert to preserve ID/SpentMicros and update role, got %+v", mAUpdate)
	}

	byUser, err := repo.ListTeamMemberships(ctx, org.ID, "", user.ID)
	if err != nil || len(byUser) != 2 {
		t.Fatalf("ListTeamMemberships by user: len=%d err=%v", len(byUser), err)
	}
	byTeamB, err := repo.ListTeamMemberships(ctx, org.ID, teamB.ID, "")
	if err != nil || len(byTeamB) != 1 || byTeamB[0].TeamID != teamB.ID {
		t.Fatalf("ListTeamMemberships by team B: %+v err=%v", byTeamB, err)
	}

	if err := repo.DeleteTeamMembership(ctx, teamB.ID, user.ID); err != nil {
		t.Fatalf("DeleteTeamMembership B: %v", err)
	}
	if _, err := repo.GetTeamMembership(ctx, teamB.ID, user.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound after DeleteTeamMembership, got %v", err)
	}

	// Projects CRUD + uniqueness + VirtualKey.ProjectID binding
	proj := &domain.Project{
		ID:                       "proj-alpha",
		OrgID:                    org.ID,
		TeamID:                   teamA.ID,
		Name:                     "Alpha",
		Description:              "Alpha workload",
		MaxBudgetMicros:          5_000_000,
		RPMLimit:                 100,
		TPMLimit:                 50_000,
		AllowedModels:            []string{"gpt-4.1"},
		EnforceProjectModelQuota: true,
		IsActive:                 true,
	}
	if err := repo.CreateProject(ctx, proj); err != nil {
		t.Fatalf("CreateProject: %v", err)
	}
	dupErr := repo.CreateProject(ctx, &domain.Project{
		OrgID:    org.ID,
		TeamID:   teamA.ID,
		Name:     "Alpha",
		IsActive: true,
	})
	if !errors.Is(dupErr, ErrConflict) {
		t.Fatalf("expected ErrConflict on duplicate (team_id, name), got %v", dupErr)
	}

	gotProj, err := repo.GetProject(ctx, proj.ID)
	if err != nil {
		t.Fatalf("GetProject: %v", err)
	}
	if !gotProj.EnforceProjectModelQuota || gotProj.RPMLimit != 100 || gotProj.Description != "Alpha workload" {
		t.Fatalf("unexpected GetProject: %+v", gotProj)
	}

	gotProj.Description = "Updated Alpha"
	gotProj.EnforceProjectModelQuota = false
	if err := repo.UpdateProject(ctx, gotProj); err != nil {
		t.Fatalf("UpdateProject: %v", err)
	}
	listed, err := repo.ListProjects(ctx, org.ID, teamA.ID)
	if err != nil || len(listed) != 1 || listed[0].Description != "Updated Alpha" || listed[0].EnforceProjectModelQuota {
		t.Fatalf("ListProjects: %+v err=%v", listed, err)
	}

	vk := &domain.VirtualKey{
		ID:        "vk-proj-1",
		KeyPrefix: "sk-gw-11111111",
		KeyHash:   "1111111111111111111111111111111111111111111111111111111111111111",
		Name:      "alpha-key",
		OrgID:     org.ID,
		TeamID:    teamA.ID,
		ProjectID: proj.ID,
		UserID:    user.ID,
		Role:      domain.RoleDeveloper,
		IsActive:  true,
	}
	if err := repo.CreateVirtualKey(ctx, vk); err != nil {
		t.Fatalf("CreateVirtualKey: %v", err)
	}
	gotVK, err := repo.GetVirtualKeyByID(ctx, vk.ID)
	if err != nil || gotVK.ProjectID != proj.ID {
		t.Fatalf("GetVirtualKeyByID ProjectID: got=%+v err=%v", gotVK, err)
	}

	// Deleting project clears virtual_keys.project_id (matching ON DELETE SET NULL)
	if err := repo.DeleteProject(ctx, proj.ID); err != nil {
		t.Fatalf("DeleteProject: %v", err)
	}
	if _, err := repo.GetProject(ctx, proj.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound after DeleteProject, got %v", err)
	}
	gotVKAfterDel, err := repo.GetVirtualKeyByID(ctx, vk.ID)
	if err != nil || gotVKAfterDel.ProjectID != "" {
		t.Fatalf("expected VirtualKey.ProjectID to be cleared on DeleteProject, got=%+v err=%v", gotVKAfterDel, err)
	}

	// DeleteTeam cascades memberships and projects
	proj2 := &domain.Project{ID: "proj-cascade", OrgID: org.ID, TeamID: teamA.ID, Name: "Cascade", IsActive: true}
	if err := repo.CreateProject(ctx, proj2); err != nil {
		t.Fatalf("CreateProject proj2: %v", err)
	}
	if err := repo.DeleteTeam(ctx, teamA.ID); err != nil {
		t.Fatalf("DeleteTeam A: %v", err)
	}
	if ms, _ := repo.ListTeamMemberships(ctx, org.ID, teamA.ID, ""); len(ms) != 0 {
		t.Fatalf("expected team memberships cascaded on DeleteTeam, got %d", len(ms))
	}
	if ps, _ := repo.ListProjects(ctx, org.ID, teamA.ID); len(ps) != 0 {
		t.Fatalf("expected projects cascaded on DeleteTeam, got %d", len(ps))
	}
}

func TestProjectAndMembershipRepository_PostgresNilPoolFallbackAndScanners(t *testing.T) {
	ctx := context.Background()
	pgNil := &PostgresRepository{mem: NewMemoryRepository()}
	var pmRepo ProjectAndMembershipRepository = pgNil

	m := &domain.TeamMembership{
		OrgID:         "org-1",
		TeamID:        "team-1",
		UserID:        "user-1",
		Role:          domain.RoleDeveloper,
		AllowedModels: []string{"gpt-4.1"},
	}
	if err := pmRepo.UpsertTeamMembership(ctx, m); err != nil {
		t.Fatalf("pgNil UpsertTeamMembership: %v", err)
	}
	if got, err := pmRepo.GetTeamMembership(ctx, "team-1", "user-1"); err != nil || got.ID != m.ID {
		t.Fatalf("pgNil GetTeamMembership: got=%+v err=%v", got, err)
	}
	proj := &domain.Project{
		ID:                       "proj-pgnil",
		OrgID:                    "org-1",
		TeamID:                   "team-1",
		Name:                     "PG Nil Project",
		EnforceProjectModelQuota: true,
		IsActive:                 true,
	}
	if err := pmRepo.CreateProject(ctx, proj); err != nil {
		t.Fatalf("pgNil CreateProject: %v", err)
	}
	if gotP, err := pmRepo.GetProject(ctx, proj.ID); err != nil || !gotP.EnforceProjectModelQuota {
		t.Fatalf("pgNil GetProject: got=%+v err=%v", gotP, err)
	}

	now := time.Now().UTC()
	scannedM, err := scanTeamMembership(&fakeTeamScanner{
		values: []any{
			"tm-1", "org-1", "team-1", "user-1", "team_admin",
			int64(1000), int64(250), 30, 5000, []string{"gpt-4.1"}, now, now,
		},
	})
	if err != nil {
		t.Fatalf("scanTeamMembership: %v", err)
	}
	if scannedM.Role != domain.RoleTeamAdmin || scannedM.RPMLimit != 30 || scannedM.SpentMicros != 250 {
		t.Fatalf("unexpected scanned TeamMembership: %+v", scannedM)
	}

	scannedP, err := scanProject(&fakeTeamScanner{
		values: []any{
			"proj-1", "org-1", "team-1", "Prod", "Production API",
			int64(9000), int64(100), 60, 12000, []string{"gpt-4.1-mini"}, true, true, now, now,
		},
	})
	if err != nil {
		t.Fatalf("scanProject: %v", err)
	}
	if !scannedP.EnforceProjectModelQuota || scannedP.Name != "Prod" || len(scannedP.AllowedModels) != 1 {
		t.Fatalf("unexpected scanned Project: %+v", scannedP)
	}

	if _, err := scanProject(&fakeTeamScanner{err: pgx.ErrNoRows}); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("expected pgx.ErrNoRows, got %v", err)
	}
}
