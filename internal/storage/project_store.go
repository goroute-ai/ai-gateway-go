package storage

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

// ProjectAndMembershipRepository is an optional Repository extension for managing
// M:N team memberships and team-scoped projects.
type ProjectAndMembershipRepository interface {
	UpsertTeamMembership(ctx context.Context, membership *domain.TeamMembership) error
	GetTeamMembership(ctx context.Context, teamID, userID string) (*domain.TeamMembership, error)
	ListTeamMemberships(ctx context.Context, orgID, teamID, userID string) ([]*domain.TeamMembership, error)
	DeleteTeamMembership(ctx context.Context, teamID, userID string) error

	CreateProject(ctx context.Context, project *domain.Project) error
	GetProject(ctx context.Context, id string) (*domain.Project, error)
	ListProjects(ctx context.Context, orgID, teamID string) ([]*domain.Project, error)
	UpdateProject(ctx context.Context, project *domain.Project) error
	DeleteProject(ctx context.Context, id string) error
}

var (
	_ ProjectAndMembershipRepository = (*MemoryRepository)(nil)
	_ ProjectAndMembershipRepository = (*PostgresRepository)(nil)
)

func teamMembershipTupleKey(teamID, userID string) string {
	return strings.TrimSpace(teamID) + "\x00" + strings.TrimSpace(userID)
}

func projectNameTupleKey(teamID, name string) string {
	return strings.TrimSpace(teamID) + "\x00" + strings.TrimSpace(name)
}

func normalizeTeamMembership(m *domain.TeamMembership) error {
	if m == nil {
		return fmt.Errorf("team membership is required")
	}
	m.ID = strings.TrimSpace(m.ID)
	m.OrgID = strings.TrimSpace(m.OrgID)
	m.TeamID = strings.TrimSpace(m.TeamID)
	m.UserID = strings.TrimSpace(m.UserID)
	if m.OrgID == "" || m.TeamID == "" || m.UserID == "" {
		return fmt.Errorf("org_id, team_id, and user_id are required for team membership")
	}
	if m.Role == "" {
		m.Role = domain.RoleDeveloper
	}
	if m.MaxBudgetMicros < 0 || m.SpentMicros < 0 || m.RPMLimit < 0 || m.TPMLimit < 0 {
		return fmt.Errorf("team membership budgets and rate limits must be non-negative")
	}
	if m.AllowedModels == nil {
		m.AllowedModels = []string{}
	}
	return nil
}

func normalizeProject(p *domain.Project) error {
	if p == nil {
		return fmt.Errorf("project is required")
	}
	p.ID = strings.TrimSpace(p.ID)
	p.OrgID = strings.TrimSpace(p.OrgID)
	p.TeamID = strings.TrimSpace(p.TeamID)
	p.Name = strings.TrimSpace(p.Name)
	if p.OrgID == "" || p.TeamID == "" || p.Name == "" {
		return fmt.Errorf("org_id, team_id, and name are required for project")
	}
	if p.MaxBudgetMicros < 0 || p.SpentMicros < 0 || p.RPMLimit < 0 || p.TPMLimit < 0 {
		return fmt.Errorf("project budgets and rate limits must be non-negative")
	}
	if p.AllowedModels == nil {
		p.AllowedModels = []string{}
	}
	return nil
}

func cloneTeamMembership(m *domain.TeamMembership) *domain.TeamMembership {
	if m == nil {
		return nil
	}
	cp := *m
	if m.AllowedModels != nil {
		cp.AllowedModels = slices.Clone(m.AllowedModels)
	} else {
		cp.AllowedModels = []string{}
	}
	return &cp
}

func cloneProject(p *domain.Project) *domain.Project {
	if p == nil {
		return nil
	}
	cp := *p
	if p.AllowedModels != nil {
		cp.AllowedModels = slices.Clone(p.AllowedModels)
	} else {
		cp.AllowedModels = []string{}
	}
	return &cp
}

func sortTeamMemberships(list []*domain.TeamMembership) {
	sort.Slice(list, func(i, j int) bool {
		if !list[i].CreatedAt.Equal(list[j].CreatedAt) {
			return list[i].CreatedAt.Before(list[j].CreatedAt)
		}
		return list[i].ID < list[j].ID
	})
}

func sortProjects(list []*domain.Project) {
	sort.Slice(list, func(i, j int) bool {
		if !list[i].CreatedAt.Equal(list[j].CreatedAt) {
			return list[i].CreatedAt.Before(list[j].CreatedAt)
		}
		return list[i].ID < list[j].ID
	})
}
