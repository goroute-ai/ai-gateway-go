package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func marshalStringMapJSON(m map[string]string) []byte {
	if len(m) == 0 {
		return []byte("{}")
	}
	b, err := json.Marshal(m)
	if err != nil {
		return []byte("{}")
	}
	return b
}

func unmarshalStringMapJSON(raw []byte) map[string]string {
	if len(raw) == 0 {
		return nil
	}
	var out map[string]string
	if err := json.Unmarshal(raw, &out); err != nil || len(out) == 0 {
		return nil
	}
	return out
}

const endUserSelectCols = `id, org_id, end_user_id, alias, max_budget_micros, spent_micros, budget_reset_period, budget_reset_at, rpm_limit, tpm_limit, itpm_limit, otpm_limit, tpd_limit, max_concurrent, COALESCE(allowed_models, '{}'), is_active, COALESCE(metadata, '{}'::jsonb), created_at, updated_at`

func scanEndUser(row rowScanner) (*domain.EndUser, error) {
	var eu domain.EndUser
	var period string
	var rawMeta []byte
	if err := row.Scan(
		&eu.ID, &eu.OrgID, &eu.EndUserID, &eu.Alias,
		&eu.MaxBudgetMicros, &eu.SpentMicros, &period, &eu.BudgetResetAt,
		&eu.RPMLimit, &eu.TPMLimit, &eu.ITPMLimit, &eu.OTPMLimit, &eu.TPDLimit, &eu.MaxConcurrent,
		&eu.AllowedModels, &eu.IsActive, &rawMeta, &eu.CreatedAt, &eu.UpdatedAt,
	); err != nil {
		return nil, err
	}
	eu.BudgetResetPeriod = domain.BudgetResetPeriod(period)
	eu.Metadata = unmarshalStringMapJSON(rawMeta)
	return &eu, nil
}

func (p *PostgresRepository) syncEndUserMem(eu *domain.EndUser) {
	if p == nil || p.mem == nil || eu == nil {
		return
	}
	p.mem.mu.Lock()
	tupleKey := endUserTupleKey(eu.OrgID, eu.EndUserID)
	if oldID, ok := p.mem.endUsersByTuple[tupleKey]; ok && oldID != eu.ID {
		delete(p.mem.endUsers, oldID)
	}
	if existing, ok := p.mem.endUsers[eu.ID]; ok {
		delete(p.mem.endUsersByTuple, endUserTupleKey(existing.OrgID, existing.EndUserID))
	}
	cp := eu.Clone()
	p.mem.endUsers[cp.ID] = cp
	p.mem.endUsersByTuple[tupleKey] = cp.ID
	p.mem.mu.Unlock()
}

func (p *PostgresRepository) UpsertEndUser(ctx context.Context, eu *domain.EndUser) error {
	if p.pool == nil {
		return p.mem.UpsertEndUser(ctx, eu)
	}
	now := time.Now().UTC()
	if err := normalizeEndUser(eu, now); err != nil {
		return err
	}
	if eu.ID == "" {
		eu.ID = uuid.NewString()
	}
	allowedModels := eu.AllowedModels
	if allowedModels == nil {
		allowedModels = []string{}
	}
	const q = `
		INSERT INTO end_users (
			id, org_id, end_user_id, alias, max_budget_micros, spent_micros,
			budget_reset_period, budget_reset_at, rpm_limit, tpm_limit, itpm_limit,
			otpm_limit, tpd_limit, max_concurrent, allowed_models, is_active, metadata
		) VALUES (
			$1, $2, $3, $4, $5, $6,
			$7, $8, $9, $10, $11,
			$12, $13, $14, $15, $16, $17
		)
		ON CONFLICT (org_id, end_user_id) DO UPDATE SET
			alias = EXCLUDED.alias,
			max_budget_micros = EXCLUDED.max_budget_micros,
			spent_micros = GREATEST(end_users.spent_micros, EXCLUDED.spent_micros),
			budget_reset_period = EXCLUDED.budget_reset_period,
			budget_reset_at = EXCLUDED.budget_reset_at,
			rpm_limit = EXCLUDED.rpm_limit,
			tpm_limit = EXCLUDED.tpm_limit,
			itpm_limit = EXCLUDED.itpm_limit,
			otpm_limit = EXCLUDED.otpm_limit,
			tpd_limit = EXCLUDED.tpd_limit,
			max_concurrent = EXCLUDED.max_concurrent,
			allowed_models = EXCLUDED.allowed_models,
			is_active = EXCLUDED.is_active,
			metadata = EXCLUDED.metadata,
			updated_at = NOW()
		RETURNING id, spent_micros, created_at, updated_at`
	if err := p.pool.QueryRow(ctx, q,
		eu.ID, eu.OrgID, eu.EndUserID, eu.Alias, eu.MaxBudgetMicros, eu.SpentMicros,
		string(eu.BudgetResetPeriod), eu.BudgetResetAt, eu.RPMLimit, eu.TPMLimit, eu.ITPMLimit,
		eu.OTPMLimit, eu.TPDLimit, eu.MaxConcurrent, allowedModels, eu.IsActive, marshalStringMapJSON(eu.Metadata),
	).Scan(&eu.ID, &eu.SpentMicros, &eu.CreatedAt, &eu.UpdatedAt); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return fmt.Errorf("end_user conflict: %w", ErrConflict)
		}
		return err
	}
	p.syncEndUserMem(eu)
	return nil
}

func (p *PostgresRepository) GetOrCreateEndUser(ctx context.Context, orgID, endUserID string) (*domain.EndUser, error) {
	if p.pool == nil {
		return p.mem.GetOrCreateEndUser(ctx, orgID, endUserID)
	}
	orgID = strings.TrimSpace(orgID)
	endUserID = strings.TrimSpace(endUserID)
	if orgID == "" || endUserID == "" {
		return nil, fmt.Errorf("org_id and end_user_id are required")
	}

	eu, err := scanEndUser(p.pool.QueryRow(ctx,
		`SELECT `+endUserSelectCols+` FROM end_users WHERE org_id = $1 AND end_user_id = $2`,
		orgID, endUserID,
	))
	if err == nil {
		p.syncEndUserMem(eu)
		return eu, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, err
	}

	now := time.Now().UTC()
	fresh := &domain.EndUser{
		ID:        uuid.NewString(),
		OrgID:     orgID,
		EndUserID: endUserID,
		IsActive:  true,
	}
	if normErr := normalizeEndUser(fresh, now); normErr != nil {
		return nil, normErr
	}
	const insQ = `
		INSERT INTO end_users (
			id, org_id, end_user_id, alias, max_budget_micros, spent_micros,
			budget_reset_period, budget_reset_at, is_active
		) VALUES ($1, $2, $3, '', 0, 0, $4, $5, TRUE)
		ON CONFLICT (org_id, end_user_id) DO NOTHING`
	if _, execErr := p.pool.Exec(ctx, insQ, fresh.ID, fresh.OrgID, fresh.EndUserID, string(fresh.BudgetResetPeriod), fresh.BudgetResetAt); execErr != nil {
		return nil, execErr
	}
	eu, err = scanEndUser(p.pool.QueryRow(ctx,
		`SELECT `+endUserSelectCols+` FROM end_users WHERE org_id = $1 AND end_user_id = $2`,
		orgID, endUserID,
	))
	if err != nil {
		return nil, err
	}
	p.syncEndUserMem(eu)
	return eu, nil
}

func (p *PostgresRepository) GetEndUser(ctx context.Context, id string) (*domain.EndUser, error) {
	if p.pool == nil {
		return p.mem.GetEndUser(ctx, id)
	}
	eu, err := scanEndUser(p.pool.QueryRow(ctx, `SELECT `+endUserSelectCols+` FROM end_users WHERE id = $1`, strings.TrimSpace(id)))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("end_user %q %w", id, ErrNotFound)
		}
		return nil, err
	}
	p.syncEndUserMem(eu)
	return eu, nil
}

func (p *PostgresRepository) GetEndUserByExternalID(ctx context.Context, orgID, endUserID string) (*domain.EndUser, error) {
	if p.pool == nil {
		return p.mem.GetEndUserByExternalID(ctx, orgID, endUserID)
	}
	eu, err := scanEndUser(p.pool.QueryRow(ctx,
		`SELECT `+endUserSelectCols+` FROM end_users WHERE org_id = $1 AND end_user_id = $2`,
		strings.TrimSpace(orgID), strings.TrimSpace(endUserID),
	))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("end_user (%s, %s) %w", orgID, endUserID, ErrNotFound)
		}
		return nil, err
	}
	p.syncEndUserMem(eu)
	return eu, nil
}

func (p *PostgresRepository) ListEndUsers(ctx context.Context, filter EndUserFilter) ([]*domain.EndUser, error) {
	if p.pool == nil {
		return p.mem.ListEndUsers(ctx, filter)
	}
	var conds []string
	var args []any
	addCond := func(col string, val any) {
		args = append(args, val)
		conds = append(conds, fmt.Sprintf("%s = $%d", col, len(args)))
	}
	if v := strings.TrimSpace(filter.OrgID); v != "" {
		addCond("org_id", v)
	}
	if v := strings.TrimSpace(filter.EndUserID); v != "" {
		addCond("end_user_id", v)
	}
	if filter.ActiveOnly {
		conds = append(conds, "is_active = TRUE")
	}
	q := `SELECT ` + endUserSelectCols + ` FROM end_users`
	if len(conds) > 0 {
		q += ` WHERE ` + strings.Join(conds, " AND ")
	}
	q += ` ORDER BY org_id ASC, end_user_id ASC, id ASC`

	rows, err := p.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*domain.EndUser
	for rows.Next() {
		eu, scanErr := scanEndUser(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, eu)
	}
	return out, rows.Err()
}

func (p *PostgresRepository) DeleteEndUser(ctx context.Context, id string) error {
	if p.pool == nil {
		return p.mem.DeleteEndUser(ctx, id)
	}
	tag, err := p.pool.Exec(ctx, `DELETE FROM end_users WHERE id = $1`, strings.TrimSpace(id))
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("end_user %q %w", id, ErrNotFound)
	}
	_ = p.mem.DeleteEndUser(ctx, id)
	return nil
}

func (p *PostgresRepository) IncrementEndUserSpend(ctx context.Context, orgID, endUserID string, deltaMicros int64) error {
	orgID = strings.TrimSpace(orgID)
	endUserID = strings.TrimSpace(endUserID)
	if orgID == "" || endUserID == "" {
		return fmt.Errorf("org_id and end_user_id are required")
	}
	if deltaMicros < 0 {
		return fmt.Errorf("delta_micros must be non-negative")
	}
	if p.pool == nil {
		return p.mem.IncrementEndUserSpend(ctx, orgID, endUserID, deltaMicros)
	}
	tag, err := p.pool.Exec(ctx,
		`UPDATE end_users SET spent_micros = spent_micros + $3, updated_at = NOW() WHERE org_id = $1 AND end_user_id = $2`,
		orgID, endUserID, deltaMicros,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("end_user (%s, %s) %w", orgID, endUserID, ErrNotFound)
	}
	_ = p.mem.IncrementEndUserSpend(ctx, orgID, endUserID, deltaMicros)
	return nil
}

const tagSelectCols = `id, org_id, tag, description, max_budget_micros, spent_micros, budget_reset_period, budget_reset_at, rpm_limit, tpm_limit, itpm_limit, otpm_limit, tpd_limit, max_concurrent, COALESCE(allowed_models, '{}'), is_active, COALESCE(metadata, '{}'::jsonb), created_at, updated_at`

func scanTag(row rowScanner) (*domain.Tag, error) {
	var t domain.Tag
	var period string
	var rawMeta []byte
	if err := row.Scan(
		&t.ID, &t.OrgID, &t.Tag, &t.Description,
		&t.MaxBudgetMicros, &t.SpentMicros, &period, &t.BudgetResetAt,
		&t.RPMLimit, &t.TPMLimit, &t.ITPMLimit, &t.OTPMLimit, &t.TPDLimit, &t.MaxConcurrent,
		&t.AllowedModels, &t.IsActive, &rawMeta, &t.CreatedAt, &t.UpdatedAt,
	); err != nil {
		return nil, err
	}
	t.BudgetResetPeriod = domain.BudgetResetPeriod(period)
	t.Metadata = unmarshalStringMapJSON(rawMeta)
	return &t, nil
}

func (p *PostgresRepository) syncTagMem(t *domain.Tag) {
	if p == nil || p.mem == nil || t == nil {
		return
	}
	p.mem.mu.Lock()
	tupleKey := tagTupleKey(t.OrgID, t.Tag)
	if oldID, ok := p.mem.tagsByTuple[tupleKey]; ok && oldID != t.ID {
		delete(p.mem.tags, oldID)
	}
	if existing, ok := p.mem.tags[t.ID]; ok {
		delete(p.mem.tagsByTuple, tagTupleKey(existing.OrgID, existing.Tag))
	}
	cp := t.Clone()
	p.mem.tags[cp.ID] = cp
	p.mem.tagsByTuple[tupleKey] = cp.ID
	p.mem.mu.Unlock()
}

func (p *PostgresRepository) UpsertTag(ctx context.Context, tag *domain.Tag) error {
	if p.pool == nil {
		return p.mem.UpsertTag(ctx, tag)
	}
	now := time.Now().UTC()
	if err := normalizeTag(tag, now); err != nil {
		return err
	}
	if tag.ID == "" {
		tag.ID = uuid.NewString()
	}
	allowedModels := tag.AllowedModels
	if allowedModels == nil {
		allowedModels = []string{}
	}
	const q = `
		INSERT INTO tags (
			id, org_id, tag, description, max_budget_micros, spent_micros,
			budget_reset_period, budget_reset_at, rpm_limit, tpm_limit, itpm_limit,
			otpm_limit, tpd_limit, max_concurrent, allowed_models, is_active, metadata
		) VALUES (
			$1, $2, $3, $4, $5, $6,
			$7, $8, $9, $10, $11,
			$12, $13, $14, $15, $16, $17
		)
		ON CONFLICT (org_id, tag) DO UPDATE SET
			description = EXCLUDED.description,
			max_budget_micros = EXCLUDED.max_budget_micros,
			spent_micros = GREATEST(tags.spent_micros, EXCLUDED.spent_micros),
			budget_reset_period = EXCLUDED.budget_reset_period,
			budget_reset_at = EXCLUDED.budget_reset_at,
			rpm_limit = EXCLUDED.rpm_limit,
			tpm_limit = EXCLUDED.tpm_limit,
			itpm_limit = EXCLUDED.itpm_limit,
			otpm_limit = EXCLUDED.otpm_limit,
			tpd_limit = EXCLUDED.tpd_limit,
			max_concurrent = EXCLUDED.max_concurrent,
			allowed_models = EXCLUDED.allowed_models,
			is_active = EXCLUDED.is_active,
			metadata = EXCLUDED.metadata,
			updated_at = NOW()
		RETURNING id, spent_micros, created_at, updated_at`
	if err := p.pool.QueryRow(ctx, q,
		tag.ID, tag.OrgID, tag.Tag, tag.Description, tag.MaxBudgetMicros, tag.SpentMicros,
		string(tag.BudgetResetPeriod), tag.BudgetResetAt, tag.RPMLimit, tag.TPMLimit, tag.ITPMLimit,
		tag.OTPMLimit, tag.TPDLimit, tag.MaxConcurrent, allowedModels, tag.IsActive, marshalStringMapJSON(tag.Metadata),
	).Scan(&tag.ID, &tag.SpentMicros, &tag.CreatedAt, &tag.UpdatedAt); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return fmt.Errorf("tag conflict: %w", ErrConflict)
		}
		return err
	}
	p.syncTagMem(tag)
	return nil
}

func (p *PostgresRepository) GetTag(ctx context.Context, id string) (*domain.Tag, error) {
	if p.pool == nil {
		return p.mem.GetTag(ctx, id)
	}
	t, err := scanTag(p.pool.QueryRow(ctx, `SELECT `+tagSelectCols+` FROM tags WHERE id = $1`, strings.TrimSpace(id)))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("tag %q %w", id, ErrNotFound)
		}
		return nil, err
	}
	p.syncTagMem(t)
	return t, nil
}

func (p *PostgresRepository) GetTagByName(ctx context.Context, orgID, tagName string) (*domain.Tag, error) {
	if p.pool == nil {
		return p.mem.GetTagByName(ctx, orgID, tagName)
	}
	t, err := scanTag(p.pool.QueryRow(ctx,
		`SELECT `+tagSelectCols+` FROM tags WHERE org_id = $1 AND tag = $2`,
		strings.TrimSpace(orgID), strings.TrimSpace(tagName),
	))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("tag (%s, %s) %w", orgID, tagName, ErrNotFound)
		}
		return nil, err
	}
	p.syncTagMem(t)
	return t, nil
}

func (p *PostgresRepository) ListTags(ctx context.Context, filter TagFilter) ([]*domain.Tag, error) {
	if p.pool == nil {
		return p.mem.ListTags(ctx, filter)
	}
	var conds []string
	var args []any
	addCond := func(col string, val any) {
		args = append(args, val)
		conds = append(conds, fmt.Sprintf("%s = $%d", col, len(args)))
	}
	if v := strings.TrimSpace(filter.OrgID); v != "" {
		addCond("org_id", v)
	}
	if v := strings.TrimSpace(filter.Tag); v != "" {
		addCond("tag", v)
	}
	if filter.ActiveOnly {
		conds = append(conds, "is_active = TRUE")
	}
	q := `SELECT ` + tagSelectCols + ` FROM tags`
	if len(conds) > 0 {
		q += ` WHERE ` + strings.Join(conds, " AND ")
	}
	q += ` ORDER BY org_id ASC, tag ASC, id ASC`

	rows, err := p.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*domain.Tag
	for rows.Next() {
		t, scanErr := scanTag(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, t)
	}
	return out, rows.Err()
}

func (p *PostgresRepository) DeleteTag(ctx context.Context, id string) error {
	if p.pool == nil {
		return p.mem.DeleteTag(ctx, id)
	}
	tag, err := p.pool.Exec(ctx, `DELETE FROM tags WHERE id = $1`, strings.TrimSpace(id))
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("tag %q %w", id, ErrNotFound)
	}
	_ = p.mem.DeleteTag(ctx, id)
	return nil
}

func (p *PostgresRepository) IncrementTagSpend(ctx context.Context, orgID, tagName string, deltaMicros int64) error {
	orgID = strings.TrimSpace(orgID)
	tagName = strings.TrimSpace(tagName)
	if orgID == "" || tagName == "" {
		return fmt.Errorf("org_id and tag are required")
	}
	if deltaMicros < 0 {
		return fmt.Errorf("delta_micros must be non-negative")
	}
	if p.pool == nil {
		return p.mem.IncrementTagSpend(ctx, orgID, tagName, deltaMicros)
	}
	tag, err := p.pool.Exec(ctx,
		`UPDATE tags SET spent_micros = spent_micros + $3, updated_at = NOW() WHERE org_id = $1 AND tag = $2`,
		orgID, tagName, deltaMicros,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("tag (%s, %s) %w", orgID, tagName, ErrNotFound)
	}
	_ = p.mem.IncrementTagSpend(ctx, orgID, tagName, deltaMicros)
	return nil
}

const modelAccessGroupSelectCols = `id, org_id, name, description, max_budget_micros, spent_micros, budget_reset_period, budget_reset_at, rpm_limit, tpm_limit, itpm_limit, otpm_limit, tpd_limit, max_concurrent, COALESCE(allowed_mcp_servers, '{}'), COALESCE(allowed_mcp_tools, '{}'), COALESCE(allowed_a2a_agents, '{}'), is_active, COALESCE(metadata, '{}'::jsonb), created_at, updated_at`
const modelAccessGroupMemberSelectCols = `id, org_id, group_id, member_type, member_id, created_at`

func scanModelAccessGroup(row rowScanner) (*domain.ModelAccessGroup, error) {
	var g domain.ModelAccessGroup
	var period string
	var rawMeta []byte
	if err := row.Scan(
		&g.ID, &g.OrgID, &g.Name, &g.Description,
		&g.MaxBudgetMicros, &g.SpentMicros, &period, &g.BudgetResetAt,
		&g.RPMLimit, &g.TPMLimit, &g.ITPMLimit, &g.OTPMLimit, &g.TPDLimit, &g.MaxConcurrent,
		&g.AllowedMCPServers, &g.AllowedMCPTools, &g.AllowedA2AAgents,
		&g.IsActive, &rawMeta, &g.CreatedAt, &g.UpdatedAt,
	); err != nil {
		return nil, err
	}
	g.BudgetResetPeriod = domain.BudgetResetPeriod(period)
	g.Metadata = unmarshalStringMapJSON(rawMeta)
	return &g, nil
}

func scanModelAccessGroupMember(row rowScanner) (*domain.ModelAccessGroupMember, error) {
	var m domain.ModelAccessGroupMember
	var memberType string
	if err := row.Scan(&m.ID, &m.OrgID, &m.GroupID, &memberType, &m.MemberID, &m.CreatedAt); err != nil {
		return nil, err
	}
	m.MemberType = domain.ModelAccessGroupMemberType(memberType)
	return &m, nil
}

func (p *PostgresRepository) syncModelAccessGroupMem(g *domain.ModelAccessGroup) {
	if p == nil || p.mem == nil || g == nil {
		return
	}
	p.mem.mu.Lock()
	tupleKey := modelAccessGroupTupleKey(g.OrgID, g.Name)
	if oldID, ok := p.mem.modelAccessGroupsByTuple[tupleKey]; ok && oldID != g.ID {
		delete(p.mem.modelAccessGroups, oldID)
	}
	if existing, ok := p.mem.modelAccessGroups[g.ID]; ok {
		delete(p.mem.modelAccessGroupsByTuple, modelAccessGroupTupleKey(existing.OrgID, existing.Name))
	}
	cp := g.Clone()
	cp.Members = nil
	p.mem.modelAccessGroups[cp.ID] = cp
	p.mem.modelAccessGroupsByTuple[tupleKey] = cp.ID
	p.mem.mu.Unlock()
}

func (p *PostgresRepository) syncModelAccessGroupMemberMem(m *domain.ModelAccessGroupMember) {
	if p == nil || p.mem == nil || m == nil {
		return
	}
	p.mem.mu.Lock()
	tupleKey := modelAccessGroupMemberTupleKey(m.GroupID, m.MemberType, m.MemberID)
	if oldID, ok := p.mem.modelAccessGroupMembersByTuple[tupleKey]; ok && oldID != m.ID {
		delete(p.mem.modelAccessGroupMembers, oldID)
	}
	cp := m.Clone()
	p.mem.modelAccessGroupMembers[cp.ID] = cp
	p.mem.modelAccessGroupMembersByTuple[tupleKey] = cp.ID
	p.mem.mu.Unlock()
}

func (p *PostgresRepository) UpsertModelAccessGroup(ctx context.Context, group *domain.ModelAccessGroup) error {
	if p.pool == nil {
		return p.mem.UpsertModelAccessGroup(ctx, group)
	}
	now := time.Now().UTC()
	if err := normalizeModelAccessGroup(group, now); err != nil {
		return err
	}
	if group.ID == "" {
		group.ID = uuid.NewString()
	}
	allowedMCPServers := group.AllowedMCPServers
	if allowedMCPServers == nil {
		allowedMCPServers = []string{}
	}
	allowedMCPTools := group.AllowedMCPTools
	if allowedMCPTools == nil {
		allowedMCPTools = []string{}
	}
	allowedA2AAgents := group.AllowedA2AAgents
	if allowedA2AAgents == nil {
		allowedA2AAgents = []string{}
	}
	const q = `
		INSERT INTO model_access_groups (
			id, org_id, name, description, max_budget_micros, spent_micros,
			budget_reset_period, budget_reset_at, rpm_limit, tpm_limit, itpm_limit,
			otpm_limit, tpd_limit, max_concurrent, allowed_mcp_servers, allowed_mcp_tools, allowed_a2a_agents, is_active, metadata
		) VALUES (
			$1, $2, $3, $4, $5, $6,
			$7, $8, $9, $10, $11,
			$12, $13, $14, $15, $16, $17, $18, $19
		)
		ON CONFLICT (org_id, name) DO UPDATE SET
			description = EXCLUDED.description,
			max_budget_micros = EXCLUDED.max_budget_micros,
			spent_micros = GREATEST(model_access_groups.spent_micros, EXCLUDED.spent_micros),
			budget_reset_period = EXCLUDED.budget_reset_period,
			budget_reset_at = EXCLUDED.budget_reset_at,
			rpm_limit = EXCLUDED.rpm_limit,
			tpm_limit = EXCLUDED.tpm_limit,
			itpm_limit = EXCLUDED.itpm_limit,
			otpm_limit = EXCLUDED.otpm_limit,
			tpd_limit = EXCLUDED.tpd_limit,
			max_concurrent = EXCLUDED.max_concurrent,
			allowed_mcp_servers = EXCLUDED.allowed_mcp_servers,
			allowed_mcp_tools = EXCLUDED.allowed_mcp_tools,
			allowed_a2a_agents = EXCLUDED.allowed_a2a_agents,
			is_active = EXCLUDED.is_active,
			metadata = EXCLUDED.metadata,
			updated_at = NOW()
		RETURNING id, spent_micros, created_at, updated_at`
	if err := p.pool.QueryRow(ctx, q,
		group.ID, group.OrgID, group.Name, group.Description, group.MaxBudgetMicros, group.SpentMicros,
		string(group.BudgetResetPeriod), group.BudgetResetAt, group.RPMLimit, group.TPMLimit, group.ITPMLimit,
		group.OTPMLimit, group.TPDLimit, group.MaxConcurrent, allowedMCPServers, allowedMCPTools, allowedA2AAgents, group.IsActive, marshalStringMapJSON(group.Metadata),
	).Scan(&group.ID, &group.SpentMicros, &group.CreatedAt, &group.UpdatedAt); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return fmt.Errorf("model_access_group conflict: %w", ErrConflict)
		}
		return err
	}
	p.syncModelAccessGroupMem(group)
	members, err := p.ListModelAccessGroupMembers(ctx, group.ID)
	if err == nil {
		group.Members = members
	}
	return nil
}

func (p *PostgresRepository) GetModelAccessGroup(ctx context.Context, id string) (*domain.ModelAccessGroup, error) {
	if p.pool == nil {
		return p.mem.GetModelAccessGroup(ctx, id)
	}
	g, err := scanModelAccessGroup(p.pool.QueryRow(ctx,
		`SELECT `+modelAccessGroupSelectCols+` FROM model_access_groups WHERE id = $1`,
		strings.TrimSpace(id),
	))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("model_access_group %q %w", id, ErrNotFound)
		}
		return nil, err
	}
	p.syncModelAccessGroupMem(g)
	members, err := p.ListModelAccessGroupMembers(ctx, g.ID)
	if err != nil {
		return nil, err
	}
	g.Members = members
	return g, nil
}

func (p *PostgresRepository) GetModelAccessGroupByName(ctx context.Context, orgID, name string) (*domain.ModelAccessGroup, error) {
	if p.pool == nil {
		return p.mem.GetModelAccessGroupByName(ctx, orgID, name)
	}
	g, err := scanModelAccessGroup(p.pool.QueryRow(ctx,
		`SELECT `+modelAccessGroupSelectCols+` FROM model_access_groups WHERE org_id = $1 AND name = $2`,
		strings.TrimSpace(orgID), strings.TrimSpace(name),
	))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("model_access_group (%s, %s) %w", orgID, name, ErrNotFound)
		}
		return nil, err
	}
	p.syncModelAccessGroupMem(g)
	members, err := p.ListModelAccessGroupMembers(ctx, g.ID)
	if err != nil {
		return nil, err
	}
	g.Members = members
	return g, nil
}

func (p *PostgresRepository) ListModelAccessGroups(ctx context.Context, filter ModelAccessGroupFilter) ([]*domain.ModelAccessGroup, error) {
	if p.pool == nil {
		return p.mem.ListModelAccessGroups(ctx, filter)
	}
	var conds []string
	var args []any
	addCond := func(col string, val any) {
		args = append(args, val)
		conds = append(conds, fmt.Sprintf("%s = $%d", col, len(args)))
	}
	if v := strings.TrimSpace(filter.OrgID); v != "" {
		addCond("org_id", v)
	}
	if v := strings.TrimSpace(filter.Name); v != "" {
		addCond("name", v)
	}
	if filter.ActiveOnly {
		conds = append(conds, "is_active = TRUE")
	}
	q := `SELECT ` + modelAccessGroupSelectCols + ` FROM model_access_groups`
	if len(conds) > 0 {
		q += ` WHERE ` + strings.Join(conds, " AND ")
	}
	q += ` ORDER BY org_id ASC, name ASC, id ASC`

	rows, err := p.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*domain.ModelAccessGroup
	byID := make(map[string]*domain.ModelAccessGroup)
	for rows.Next() {
		g, scanErr := scanModelAccessGroup(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, g)
		byID[g.ID] = g
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) > 0 && strings.TrimSpace(filter.OrgID) != "" {
		members, memErr := p.ListModelAccessGroupMembersByOrg(ctx, filter.OrgID)
		if memErr != nil {
			return nil, memErr
		}
		for _, m := range members {
			if g, ok := byID[m.GroupID]; ok {
				g.Members = append(g.Members, m)
			}
		}
	} else {
		for _, g := range out {
			members, memErr := p.ListModelAccessGroupMembers(ctx, g.ID)
			if memErr != nil {
				return nil, memErr
			}
			g.Members = members
		}
	}
	return out, nil
}

func (p *PostgresRepository) DeleteModelAccessGroup(ctx context.Context, id string) error {
	if p.pool == nil {
		return p.mem.DeleteModelAccessGroup(ctx, id)
	}
	tag, err := p.pool.Exec(ctx, `DELETE FROM model_access_groups WHERE id = $1`, strings.TrimSpace(id))
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("model_access_group %q %w", id, ErrNotFound)
	}
	_ = p.mem.DeleteModelAccessGroup(ctx, id)
	return nil
}

func (p *PostgresRepository) IncrementModelAccessGroupSpend(ctx context.Context, groupID string, deltaMicros int64) error {
	groupID = strings.TrimSpace(groupID)
	if groupID == "" {
		return fmt.Errorf("group_id is required")
	}
	if deltaMicros < 0 {
		return fmt.Errorf("delta_micros must be non-negative")
	}
	if p.pool == nil {
		return p.mem.IncrementModelAccessGroupSpend(ctx, groupID, deltaMicros)
	}
	tag, err := p.pool.Exec(ctx,
		`UPDATE model_access_groups SET spent_micros = spent_micros + $2, updated_at = NOW() WHERE id = $1`,
		groupID, deltaMicros,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("model_access_group %q %w", groupID, ErrNotFound)
	}
	_ = p.mem.IncrementModelAccessGroupSpend(ctx, groupID, deltaMicros)
	return nil
}

func (p *PostgresRepository) AddModelAccessGroupMember(ctx context.Context, member *domain.ModelAccessGroupMember) error {
	if p.pool == nil {
		return p.mem.AddModelAccessGroupMember(ctx, member)
	}
	if err := normalizeModelAccessGroupMember(member); err != nil {
		return err
	}
	if member.ID == "" {
		member.ID = uuid.NewString()
	}
	const q = `
		INSERT INTO model_access_group_members (id, org_id, group_id, member_type, member_id)
		VALUES ($1, $2, $3, $4, $5)
		ON CONFLICT (group_id, member_type, member_id) DO UPDATE SET
			member_id = EXCLUDED.member_id
		RETURNING id, created_at`
	if err := p.pool.QueryRow(ctx, q,
		member.ID, member.OrgID, member.GroupID, string(member.MemberType), member.MemberID,
	).Scan(&member.ID, &member.CreatedAt); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23503" {
			return fmt.Errorf("model_access_group %q %w", member.GroupID, ErrNotFound)
		}
		return err
	}
	p.syncModelAccessGroupMemberMem(member)
	return nil
}

func (p *PostgresRepository) ListModelAccessGroupMembers(ctx context.Context, groupID string) ([]*domain.ModelAccessGroupMember, error) {
	if p.pool == nil {
		return p.mem.ListModelAccessGroupMembers(ctx, groupID)
	}
	rows, err := p.pool.Query(ctx,
		`SELECT `+modelAccessGroupMemberSelectCols+` FROM model_access_group_members WHERE group_id = $1 ORDER BY member_type ASC, member_id ASC, id ASC`,
		strings.TrimSpace(groupID),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*domain.ModelAccessGroupMember
	for rows.Next() {
		m, scanErr := scanModelAccessGroupMember(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (p *PostgresRepository) ListModelAccessGroupMembersByOrg(ctx context.Context, orgID string) ([]*domain.ModelAccessGroupMember, error) {
	if p.pool == nil {
		return p.mem.ListModelAccessGroupMembersByOrg(ctx, orgID)
	}
	rows, err := p.pool.Query(ctx,
		`SELECT `+modelAccessGroupMemberSelectCols+` FROM model_access_group_members WHERE org_id = $1 ORDER BY group_id ASC, member_type ASC, member_id ASC, id ASC`,
		strings.TrimSpace(orgID),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*domain.ModelAccessGroupMember
	for rows.Next() {
		m, scanErr := scanModelAccessGroupMember(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (p *PostgresRepository) RemoveModelAccessGroupMember(ctx context.Context, groupID, memberRowID string) error {
	if p.pool == nil {
		return p.mem.RemoveModelAccessGroupMember(ctx, groupID, memberRowID)
	}
	tag, err := p.pool.Exec(ctx,
		`DELETE FROM model_access_group_members WHERE group_id = $1 AND id = $2`,
		strings.TrimSpace(groupID), strings.TrimSpace(memberRowID),
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("model_access_group_member %q %w", memberRowID, ErrNotFound)
	}
	_ = p.mem.RemoveModelAccessGroupMember(ctx, groupID, memberRowID)
	return nil
}

func (p *PostgresRepository) RemoveModelAccessGroupMemberByTuple(ctx context.Context, groupID string, memberType domain.ModelAccessGroupMemberType, memberID string) error {
	if p.pool == nil {
		return p.mem.RemoveModelAccessGroupMemberByTuple(ctx, groupID, memberType, memberID)
	}
	tag, err := p.pool.Exec(ctx,
		`DELETE FROM model_access_group_members WHERE group_id = $1 AND member_type = $2 AND member_id = $3`,
		strings.TrimSpace(groupID), strings.ToLower(strings.TrimSpace(string(memberType))), strings.TrimSpace(memberID),
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("model_access_group_member (%s, %s, %s) %w", groupID, memberType, memberID, ErrNotFound)
	}
	_ = p.mem.RemoveModelAccessGroupMemberByTuple(ctx, groupID, memberType, memberID)
	return nil
}
