package storage

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/jackc/pgx/v5"
)

type fakeTeamScanner struct {
	values []any
	err    error
}

func (f *fakeTeamScanner) Scan(dest ...any) error {
	if f.err != nil {
		return f.err
	}
	if len(dest) != len(f.values) {
		return errors.New("column count mismatch")
	}
	for i := range dest {
		switch d := dest[i].(type) {
		case *string:
			*d = f.values[i].(string)
		case *int64:
			*d = f.values[i].(int64)
		case *int:
			*d = f.values[i].(int)
		case *bool:
			*d = f.values[i].(bool)
		case *time.Time:
			*d = f.values[i].(time.Time)
		case **time.Time:
			if f.values[i] == nil {
				*d = nil
			} else {
				*d = f.values[i].(*time.Time)
			}
		case *[]string:
			if f.values[i] == nil {
				*d = nil
			} else {
				*d = f.values[i].([]string)
			}
		default:
			return errors.New("unsupported scan destination")
		}
	}
	return nil
}

func TestScanTeam_ThreeStateAllowlists(t *testing.T) {
	now := time.Now().UTC()

	t.Run("NULL columns map to nil slices (inherit)", func(t *testing.T) {
		scanner := &fakeTeamScanner{
			values: []any{
				"team-1", "org-1", "eng", int64(1000), int64(100), "monthly", nil,
				10, 1000, 5, []string{"gpt-4.1"}, nil, nil, nil,
				true, now, now,
			},
		}
		team, err := scanTeam(scanner)
		if err != nil {
			t.Fatalf("scanTeam failed: %v", err)
		}
		if team.MaxConcurrentRequests != 5 {
			t.Fatalf("expected MaxConcurrentRequests=5, got %d", team.MaxConcurrentRequests)
		}
		if team.AllowedMCPServers != nil || team.AllowedA2AAgents != nil || team.AllowedClientApps != nil {
			t.Fatalf("expected nil slices for NULL columns, got mcp=%#v a2a=%#v apps=%#v",
				team.AllowedMCPServers, team.AllowedA2AAgents, team.AllowedClientApps)
		}
	})

	t.Run("Empty array {} maps to non-nil empty slices (DenyAll)", func(t *testing.T) {
		scanner := &fakeTeamScanner{
			values: []any{
				"team-2", "org-1", "sec", int64(0), int64(0), "monthly", nil,
				0, 0, 0, []string{}, []string{}, []string{}, []string{},
				true, now, now,
			},
		}
		team, err := scanTeam(scanner)
		if err != nil {
			t.Fatalf("scanTeam failed: %v", err)
		}
		if team.AllowedMCPServers == nil || len(team.AllowedMCPServers) != 0 {
			t.Fatalf("expected non-nil empty AllowedMCPServers, got %#v", team.AllowedMCPServers)
		}
		if team.AllowedA2AAgents == nil || len(team.AllowedA2AAgents) != 0 {
			t.Fatalf("expected non-nil empty AllowedA2AAgents, got %#v", team.AllowedA2AAgents)
		}
		if team.AllowedClientApps == nil || len(team.AllowedClientApps) != 0 {
			t.Fatalf("expected non-nil empty AllowedClientApps, got %#v", team.AllowedClientApps)
		}
	})

	t.Run("Populated allowlists map to exact entries", func(t *testing.T) {
		scanner := &fakeTeamScanner{
			values: []any{
				"team-3", "org-1", "ml", int64(5000), int64(0), "weekly", nil,
				20, 2000, 12, []string{"gpt-4.1"}, []string{"mcp-1"}, []string{"agent-1", "agent-2"}, []string{"cursor"},
				true, now, now,
			},
		}
		team, err := scanTeam(scanner)
		if err != nil {
			t.Fatalf("scanTeam failed: %v", err)
		}
		if len(team.AllowedMCPServers) != 1 || team.AllowedMCPServers[0] != "mcp-1" {
			t.Fatalf("unexpected AllowedMCPServers: %#v", team.AllowedMCPServers)
		}
		if len(team.AllowedA2AAgents) != 2 || team.AllowedA2AAgents[1] != "agent-2" {
			t.Fatalf("unexpected AllowedA2AAgents: %#v", team.AllowedA2AAgents)
		}
		if len(team.AllowedClientApps) != 1 || team.AllowedClientApps[0] != "cursor" {
			t.Fatalf("unexpected AllowedClientApps: %#v", team.AllowedClientApps)
		}
	})

	t.Run("Propagates pgx.ErrNoRows", func(t *testing.T) {
		scanner := &fakeTeamScanner{err: pgx.ErrNoRows}
		_, err := scanTeam(scanner)
		if !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("expected pgx.ErrNoRows, got %v", err)
		}
	})
}

func TestMemoryRepository_TeamThreeStateAndNotFound(t *testing.T) {
	ctx := context.Background()
	repo := NewMemoryRepository()

	org := &domain.Organization{
		ID:                    "org-1",
		Name:                  "Acme",
		Slug:                  "acme",
		MaxConcurrentRequests: 25,
		IsActive:              true,
	}
	if err := repo.CreateOrganization(ctx, org); err != nil {
		t.Fatalf("CreateOrganization: %v", err)
	}
	gotOrg, err := repo.GetOrganization(ctx, org.ID)
	if err != nil || gotOrg.MaxConcurrentRequests != 25 {
		t.Fatalf("GetOrganization MaxConcurrentRequests: got=%+v err=%v", gotOrg, err)
	}

	team := &domain.Team{
		ID:                    "team-mem-1",
		OrgID:                 "org-1",
		Name:                  "platform",
		MaxConcurrentRequests: 8,
		AllowedMCPServers:     nil,        // Inherit
		AllowedA2AAgents:      []string{}, // DenyAll
		AllowedClientApps:     []string{"cli"},
		IsActive:              true,
	}
	if err := repo.CreateTeam(ctx, team); err != nil {
		t.Fatalf("CreateTeam: %v", err)
	}

	got, err := repo.GetTeam(ctx, team.ID)
	if err != nil {
		t.Fatalf("GetTeam: %v", err)
	}
	if got.MaxConcurrentRequests != 8 {
		t.Fatalf("expected team MaxConcurrentRequests=8, got %d", got.MaxConcurrentRequests)
	}
	if got.AllowedMCPServers != nil {
		t.Fatalf("expected nil AllowedMCPServers, got %#v", got.AllowedMCPServers)
	}
	if got.AllowedA2AAgents == nil || len(got.AllowedA2AAgents) != 0 {
		t.Fatalf("expected non-nil empty AllowedA2AAgents, got %#v", got.AllowedA2AAgents)
	}
	if len(got.AllowedClientApps) != 1 || got.AllowedClientApps[0] != "cli" {
		t.Fatalf("expected [cli] AllowedClientApps, got %#v", got.AllowedClientApps)
	}

	teams, err := repo.ListTeams(ctx, "org-1")
	if err != nil || len(teams) != 1 {
		t.Fatalf("ListTeams: len=%d err=%v", len(teams), err)
	}
	if teams[0].AllowedMCPServers != nil || teams[0].AllowedA2AAgents == nil || len(teams[0].AllowedA2AAgents) != 0 {
		t.Fatalf("ListTeams did not preserve 3-state allowlists: %+v", teams[0])
	}

	_, err = repo.GetTeam(ctx, "does-not-exist")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestMemoryRepository_UpdateAndDeleteTeamUserVirtualKey(t *testing.T) {
	ctx := context.Background()
	repo := NewMemoryRepository()

	org := &domain.Organization{ID: "org-crud", Name: "CRUD Org", Slug: "crud-org", IsActive: true}
	if err := repo.CreateOrganization(ctx, org); err != nil {
		t.Fatalf("CreateOrganization: %v", err)
	}

	// Team Update & Delete
	team := &domain.Team{
		ID:       "team-crud",
		OrgID:    org.ID,
		Name:     "initial-team",
		RPMLimit: 10,
		IsActive: true,
	}
	if err := repo.CreateTeam(ctx, team); err != nil {
		t.Fatalf("CreateTeam: %v", err)
	}
	team.Name = "updated-team"
	team.RPMLimit = 50
	if err := repo.UpdateTeam(ctx, team); err != nil {
		t.Fatalf("UpdateTeam: %v", err)
	}
	gotTeam, err := repo.GetTeam(ctx, team.ID)
	if err != nil || gotTeam.Name != "updated-team" || gotTeam.RPMLimit != 50 {
		t.Fatalf("GetTeam after UpdateTeam: got=%+v err=%v", gotTeam, err)
	}
	if err := repo.DeleteTeam(ctx, team.ID); err != nil {
		t.Fatalf("DeleteTeam: %v", err)
	}
	if _, err := repo.GetTeam(ctx, team.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound after DeleteTeam, got %v", err)
	}
	if err := repo.DeleteTeam(ctx, team.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound on second DeleteTeam, got %v", err)
	}

	// User Update & Delete
	user := &domain.User{
		ID:       "user-crud",
		OrgID:    org.ID,
		Email:    "dev@acme.io",
		Name:     "Dev One",
		Role:     domain.RoleDeveloper,
		RPMLimit: 20,
		IsActive: true,
	}
	if err := repo.CreateUser(ctx, user); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	user.Name = "Dev Updated"
	user.Role = domain.RoleTeamAdmin
	user.RPMLimit = 100
	if err := repo.UpdateUser(ctx, user); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
	gotUser, err := repo.GetUser(ctx, user.ID)
	if err != nil || gotUser.Name != "Dev Updated" || gotUser.Role != domain.RoleTeamAdmin || gotUser.RPMLimit != 100 {
		t.Fatalf("GetUser after UpdateUser: got=%+v err=%v", gotUser, err)
	}
	if err := repo.DeleteUser(ctx, user.ID); err != nil {
		t.Fatalf("DeleteUser: %v", err)
	}
	if _, err := repo.GetUser(ctx, user.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound after DeleteUser, got %v", err)
	}

	// VirtualKey Update (including hash rotation)
	vk := &domain.VirtualKey{
		ID:        "vk-crud",
		OrgID:     org.ID,
		Name:      "key-1",
		KeyPrefix: "sk-gw-11111111",
		KeyHash:   "hash-old",
		RPMLimit:  30,
		IsActive:  true,
	}
	if err := repo.CreateVirtualKey(ctx, vk); err != nil {
		t.Fatalf("CreateVirtualKey: %v", err)
	}
	vk.Name = "key-1-rotated"
	vk.KeyPrefix = "sk-gw-22222222"
	vk.KeyHash = "hash-new"
	vk.RPMLimit = 60
	if err := repo.UpdateVirtualKey(ctx, vk); err != nil {
		t.Fatalf("UpdateVirtualKey: %v", err)
	}
	if _, err := repo.GetVirtualKeyByHash(ctx, "hash-old"); err == nil {
		t.Fatal("expected old key hash to be removed after UpdateVirtualKey")
	}
	gotVK, err := repo.GetVirtualKeyByHash(ctx, "hash-new")
	if err != nil || gotVK.Name != "key-1-rotated" || gotVK.KeyPrefix != "sk-gw-22222222" || gotVK.RPMLimit != 60 {
		t.Fatalf("GetVirtualKeyByHash(hash-new): got=%+v err=%v", gotVK, err)
	}
}
