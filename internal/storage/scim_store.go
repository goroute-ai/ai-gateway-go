package storage

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// SCIMRepository is an optional Repository extension supporting SCIM v2
// user/group lookup and per-user virtual key enumeration for immediate revocation.
type SCIMRepository interface {
	UpdateSCIMGroup(ctx context.Context, group *domain.Team, memberIDs []string, replace bool) error
	GetUserBySCIMExternalID(ctx context.Context, orgID, externalID string) (*domain.User, error)
	GetTeamByName(ctx context.Context, orgID, name string) (*domain.Team, error)
	ListVirtualKeysByUserID(ctx context.Context, orgID, userID string) ([]*domain.VirtualKey, error)
}

var (
	_ SCIMRepository = (*MemoryRepository)(nil)
	_ SCIMRepository = (*PostgresRepository)(nil)
)

// UpdateSCIMGroup atomically updates a group's name and, when replace is true,
// its memberships inside a single tenant-scoped unit of work guarded by optimistic
// concurrency on group.UpdatedAt.
func (r *MemoryRepository) UpdateSCIMGroup(_ context.Context, group *domain.Team, memberIDs []string, replace bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if group == nil {
		return ErrNotFound
	}
	team := r.teams[group.ID]
	if team == nil || team.OrgID != group.OrgID {
		return ErrNotFound
	}
	if !team.UpdatedAt.Equal(group.UpdatedAt) {
		return ErrConflict
	}
	for _, other := range r.teams {
		if other.ID != team.ID && other.OrgID == team.OrgID && other.Name == group.Name {
			return ErrConflict
		}
	}
	desired := make(map[string]*domain.User, len(memberIDs))
	if replace {
		for _, id := range memberIDs {
			user := r.users[id]
			if user == nil || user.OrgID != team.OrgID {
				return ErrNotFound
			}
			desired[id] = user
		}
	}

	now := time.Now().UTC()
	if replace {
		for id, membership := range r.teamMemberships {
			if membership.TeamID == team.ID && desired[membership.UserID] == nil {
				delete(r.teamMemberships, id)
				delete(r.teamMembershipsByTuple, teamMembershipTupleKey(team.ID, membership.UserID))
			}
		}
		for id, user := range r.users {
			if user.OrgID == team.OrgID && user.TeamID == team.ID && desired[id] == nil {
				user.TeamID = ""
				for _, membership := range r.teamMemberships {
					if membership.OrgID == team.OrgID && membership.UserID == id && (user.TeamID == "" || membership.TeamID < user.TeamID) {
						user.TeamID = membership.TeamID
					}
				}
				user.UpdatedAt = now
			}
		}
		for id, user := range desired {
			tuple := teamMembershipTupleKey(team.ID, id)
			if r.teamMembershipsByTuple[tuple] == "" {
				membership := &domain.TeamMembership{
					ID: uuid.NewString(), OrgID: team.OrgID, TeamID: team.ID, UserID: id,
					Role: user.Role, CreatedAt: now, UpdatedAt: now,
				}
				if membership.Role == "" {
					membership.Role = domain.RoleDeveloper
				}
				r.teamMemberships[membership.ID] = membership
				r.teamMembershipsByTuple[tuple] = membership.ID
			}
			if user.TeamID == "" {
				user.TeamID, user.UpdatedAt = team.ID, now
			}
		}
	}
	team.Name, team.UpdatedAt = group.Name, now
	*group = *team
	return nil
}

func (p *PostgresRepository) UpdateSCIMGroup(ctx context.Context, group *domain.Team, memberIDs []string, replace bool) error {
	if p.pool == nil {
		return p.mem.UpdateSCIMGroup(ctx, group, memberIDs, replace)
	}
	if group == nil {
		return ErrNotFound
	}
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)
	tag, err := tx.Exec(ctx, `
		UPDATE teams SET name = $4, updated_at = NOW()
		WHERE id = $1 AND org_id = $2 AND updated_at = $3`,
		group.ID, group.OrgID, group.UpdatedAt, group.Name)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return ErrConflict
		}
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrConflict
	}
	if replace {
		seen := make(map[string]struct{}, len(memberIDs))
		uniqueIDs := make([]string, 0, len(memberIDs))
		for _, id := range memberIDs {
			if id == "" {
				continue
			}
			if _, ok := seen[id]; ok {
				continue
			}
			seen[id] = struct{}{}
			uniqueIDs = append(uniqueIDs, id)
		}
		sort.Strings(uniqueIDs)
		for _, id := range uniqueIDs {
			var role string
			if err := tx.QueryRow(ctx, `SELECT role FROM users WHERE id = $1 AND org_id = $2 FOR UPDATE`, id, group.OrgID).Scan(&role); err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					return ErrNotFound
				}
				return err
			}
			if role == "" {
				role = string(domain.RoleDeveloper)
			}
			if _, err := tx.Exec(ctx, `
				INSERT INTO team_memberships (id, org_id, team_id, user_id, role)
				VALUES ($1, $2, $3, $4, $5) ON CONFLICT (team_id, user_id) DO NOTHING`,
				uuid.NewString(), group.OrgID, group.ID, id, role); err != nil {
				return err
			}
		}
		if _, err := tx.Exec(ctx, `
			DELETE FROM team_memberships WHERE org_id = $1 AND team_id = $2 AND NOT (user_id = ANY($3))`,
			group.OrgID, group.ID, uniqueIDs); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			UPDATE users u SET team_id = (
				SELECT m.team_id FROM team_memberships m WHERE m.org_id = u.org_id AND m.user_id = u.id
				ORDER BY m.team_id LIMIT 1
			), updated_at = NOW()
			WHERE u.org_id = $1 AND u.team_id = $2 AND NOT (u.id = ANY($3))`,
			group.OrgID, group.ID, uniqueIDs); err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			UPDATE users SET team_id = $2, updated_at = NOW()
			WHERE org_id = $1 AND team_id IS NULL AND id = ANY($3)`,
			group.OrgID, group.ID, uniqueIDs); err != nil {
			return err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	updated, err := p.GetTeam(ctx, group.ID)
	if err == nil && updated != nil {
		*group = *updated
	}
	return nil
}
