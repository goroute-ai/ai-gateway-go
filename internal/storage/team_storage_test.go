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
				10, 1000, []string{"gpt-4.1"}, nil, nil, nil,
				true, now, now,
			},
		}
		team, err := scanTeam(scanner)
		if err != nil {
			t.Fatalf("scanTeam failed: %v", err)
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
				0, 0, []string{}, []string{}, []string{}, []string{},
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
				20, 2000, []string{"gpt-4.1"}, []string{"mcp-1"}, []string{"agent-1", "agent-2"}, []string{"cursor"},
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

	team := &domain.Team{
		ID:                "team-mem-1",
		OrgID:             "org-1",
		Name:              "platform",
		AllowedMCPServers: nil,        // Inherit
		AllowedA2AAgents:  []string{}, // DenyAll
		AllowedClientApps: []string{"cli"},
		IsActive:          true,
	}
	if err := repo.CreateTeam(ctx, team); err != nil {
		t.Fatalf("CreateTeam: %v", err)
	}

	got, err := repo.GetTeam(ctx, team.ID)
	if err != nil {
		t.Fatalf("GetTeam: %v", err)
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
