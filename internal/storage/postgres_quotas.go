package storage

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

const quotaPolicySelectCols = `id, org_id, scope_type, scope_id, model_pattern, rpm_limit, rpd_limit, tpm_limit, itpm_limit, otpm_limit, tpd_limit, max_concurrent, max_budget_micros, spent_micros, budget_reset_period, budget_reset_at, max_iterations, window_ttl_sec, is_active, created_at, updated_at`

func scanQuotaPolicy(row rowScanner) (*domain.QuotaPolicy, error) {
	var qp domain.QuotaPolicy
	var scopeType, period string
	if err := row.Scan(
		&qp.ID, &qp.OrgID, &scopeType, &qp.ScopeID, &qp.ModelPattern,
		&qp.RPMLimit, &qp.RPDLimit, &qp.TPMLimit, &qp.ITPMLimit, &qp.OTPMLimit, &qp.TPDLimit,
		&qp.MaxConcurrent, &qp.MaxBudgetMicros, &qp.SpentMicros,
		&period, &qp.BudgetResetAt, &qp.MaxIterations, &qp.WindowTTLSec,
		&qp.IsActive, &qp.CreatedAt, &qp.UpdatedAt,
	); err != nil {
		return nil, err
	}
	qp.ScopeType = domain.QuotaScopeType(scopeType)
	qp.BudgetResetPeriod = domain.BudgetResetPeriod(period)
	return &qp, nil
}

func (p *PostgresRepository) syncQuotaPolicyMem(policy *domain.QuotaPolicy) {
	if p == nil || p.mem == nil || policy == nil {
		return
	}
	p.mem.mu.Lock()
	tupleKey := quotaPolicyTupleKey(policy.OrgID, policy.ScopeType, policy.ScopeID, policy.ModelPattern)
	if oldID, ok := p.mem.quotaPoliciesByTuple[tupleKey]; ok && oldID != policy.ID {
		delete(p.mem.quotaPolicies, oldID)
	}
	if existing, ok := p.mem.quotaPolicies[policy.ID]; ok {
		delete(p.mem.quotaPoliciesByTuple, quotaPolicyTupleKey(existing.OrgID, existing.ScopeType, existing.ScopeID, existing.ModelPattern))
	}
	cp := policy.Clone()
	p.mem.quotaPolicies[cp.ID] = cp
	p.mem.quotaPoliciesByTuple[tupleKey] = cp.ID
	p.mem.mu.Unlock()
}

func (p *PostgresRepository) UpsertQuotaPolicy(ctx context.Context, policy *domain.QuotaPolicy) error {
	if p.pool == nil {
		return p.mem.UpsertQuotaPolicy(ctx, policy)
	}
	now := time.Now().UTC()
	if err := normalizeQuotaPolicy(policy, now); err != nil {
		return err
	}
	if policy.ID == "" {
		policy.ID = uuid.NewString()
	}
	const q = `
		INSERT INTO quota_policies (
			id, org_id, scope_type, scope_id, model_pattern,
			rpm_limit, rpd_limit, tpm_limit, itpm_limit, otpm_limit, tpd_limit,
			max_concurrent, max_budget_micros, spent_micros,
			budget_reset_period, budget_reset_at, max_iterations,
			window_ttl_sec, is_active
		) VALUES (
			$1, $2, $3, $4, $5,
			$6, $7, $8, $9, $10, $11,
			$12, $13, $14,
			$15, $16, $17,
			$18, $19
		)
		ON CONFLICT (org_id, scope_type, scope_id, model_pattern) DO UPDATE SET
			rpm_limit = EXCLUDED.rpm_limit,
			rpd_limit = EXCLUDED.rpd_limit,
			tpm_limit = EXCLUDED.tpm_limit,
			itpm_limit = EXCLUDED.itpm_limit,
			otpm_limit = EXCLUDED.otpm_limit,
			tpd_limit = EXCLUDED.tpd_limit,
			max_concurrent = EXCLUDED.max_concurrent,
			max_budget_micros = EXCLUDED.max_budget_micros,
			spent_micros = GREATEST(quota_policies.spent_micros, EXCLUDED.spent_micros),
			budget_reset_period = EXCLUDED.budget_reset_period,
			budget_reset_at = EXCLUDED.budget_reset_at,
			max_iterations = EXCLUDED.max_iterations,
			window_ttl_sec = EXCLUDED.window_ttl_sec,
			is_active = EXCLUDED.is_active,
			updated_at = NOW()
		RETURNING id, spent_micros, created_at, updated_at`

	if err := p.pool.QueryRow(ctx, q,
		policy.ID, policy.OrgID, string(policy.ScopeType), policy.ScopeID, policy.ModelPattern,
		policy.RPMLimit, policy.RPDLimit, policy.TPMLimit, policy.ITPMLimit, policy.OTPMLimit, policy.TPDLimit,
		policy.MaxConcurrent, policy.MaxBudgetMicros, policy.SpentMicros,
		string(policy.BudgetResetPeriod), policy.BudgetResetAt, policy.MaxIterations,
		policy.WindowTTLSec, policy.IsActive,
	).Scan(&policy.ID, &policy.SpentMicros, &policy.CreatedAt, &policy.UpdatedAt); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return fmt.Errorf("quota policy conflict: %w", ErrConflict)
		}
		return err
	}
	p.syncQuotaPolicyMem(policy)
	return nil
}

func (p *PostgresRepository) GetQuotaPolicy(ctx context.Context, id string) (*domain.QuotaPolicy, error) {
	if p.pool == nil {
		return p.mem.GetQuotaPolicy(ctx, id)
	}
	qp, err := scanQuotaPolicy(p.pool.QueryRow(ctx,
		`SELECT `+quotaPolicySelectCols+` FROM quota_policies WHERE id = $1`, id,
	))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("quota policy %q %w", id, ErrNotFound)
		}
		return nil, err
	}
	return qp, nil
}

func (p *PostgresRepository) ListQuotaPolicies(ctx context.Context, filter QuotaPolicyFilter) ([]*domain.QuotaPolicy, error) {
	if p.pool == nil {
		return p.mem.ListQuotaPolicies(ctx, filter)
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
	if v := strings.ToLower(strings.TrimSpace(string(filter.ScopeType))); v != "" {
		addCond("scope_type", v)
	}
	if v := strings.TrimSpace(filter.ScopeID); v != "" {
		addCond("scope_id", v)
	}
	if v := strings.TrimSpace(filter.ModelPattern); v != "" {
		addCond("model_pattern", v)
	}
	if filter.ActiveOnly {
		conds = append(conds, "is_active = TRUE")
	}

	q := `SELECT ` + quotaPolicySelectCols + ` FROM quota_policies`
	if len(conds) > 0 {
		q += ` WHERE ` + strings.Join(conds, " AND ")
	}
	q += ` ORDER BY org_id ASC, scope_type ASC, scope_id ASC, model_pattern ASC, id ASC`

	rows, err := p.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*domain.QuotaPolicy
	for rows.Next() {
		qp, scanErr := scanQuotaPolicy(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, qp)
	}
	return out, rows.Err()
}

func (p *PostgresRepository) DeleteQuotaPolicy(ctx context.Context, id string) error {
	if p.pool == nil {
		return p.mem.DeleteQuotaPolicy(ctx, id)
	}
	tag, err := p.pool.Exec(ctx, `DELETE FROM quota_policies WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("quota policy %q %w", id, ErrNotFound)
	}
	_ = p.mem.DeleteQuotaPolicy(ctx, id)
	return nil
}

func (p *PostgresRepository) IncrementQuotaPolicySpend(ctx context.Context, id string, deltaMicros int64) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return fmt.Errorf("quota policy id is required")
	}
	if deltaMicros < 0 {
		return fmt.Errorf("delta_micros must be non-negative")
	}
	if p.pool == nil {
		return p.mem.IncrementQuotaPolicySpend(ctx, id, deltaMicros)
	}
	tag, err := p.pool.Exec(ctx,
		`UPDATE quota_policies SET spent_micros = spent_micros + $2, updated_at = NOW() WHERE id = $1`,
		id, deltaMicros,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("quota policy %q %w", id, ErrNotFound)
	}
	_ = p.mem.IncrementQuotaPolicySpend(ctx, id, deltaMicros)
	return nil
}

const ptuShareSelectCols = `id, org_id, deployment_id, team_id, reserved_rpm, reserved_tpm, created_at, updated_at`

func scanPTUShare(row rowScanner) (*domain.DeploymentPTUShare, error) {
	var s domain.DeploymentPTUShare
	if err := row.Scan(
		&s.ID, &s.OrgID, &s.DeploymentID, &s.TeamID,
		&s.ReservedRPM, &s.ReservedTPM, &s.CreatedAt, &s.UpdatedAt,
	); err != nil {
		return nil, err
	}
	return &s, nil
}

func (p *PostgresRepository) syncPTUShareMem(share *domain.DeploymentPTUShare) {
	if p == nil || p.mem == nil || share == nil {
		return
	}
	p.mem.mu.Lock()
	tupleKey := ptuShareTupleKey(share.DeploymentID, share.TeamID)
	if oldID, ok := p.mem.ptuSharesByTuple[tupleKey]; ok && oldID != share.ID {
		delete(p.mem.ptuShares, oldID)
	}
	if existing, ok := p.mem.ptuShares[share.ID]; ok {
		delete(p.mem.ptuSharesByTuple, ptuShareTupleKey(existing.DeploymentID, existing.TeamID))
	}
	cp := share.Clone()
	p.mem.ptuShares[cp.ID] = cp
	p.mem.ptuSharesByTuple[tupleKey] = cp.ID
	p.mem.mu.Unlock()
}

func (p *PostgresRepository) UpsertDeploymentPTUShare(ctx context.Context, share *domain.DeploymentPTUShare) error {
	if p.pool == nil {
		return p.mem.UpsertDeploymentPTUShare(ctx, share)
	}
	now := time.Now().UTC()
	if err := normalizePTUShare(share, now); err != nil {
		return err
	}
	if share.ID == "" {
		share.ID = uuid.NewString()
	}
	const q = `
		INSERT INTO deployment_ptu_shares (
			id, org_id, deployment_id, team_id, reserved_rpm, reserved_tpm
		) VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (deployment_id, team_id) DO UPDATE SET
			reserved_rpm = EXCLUDED.reserved_rpm,
			reserved_tpm = EXCLUDED.reserved_tpm,
			updated_at = NOW()
		RETURNING id, created_at, updated_at`
	if err := p.pool.QueryRow(ctx, q,
		share.ID, share.OrgID, share.DeploymentID, share.TeamID,
		share.ReservedRPM, share.ReservedTPM,
	).Scan(&share.ID, &share.CreatedAt, &share.UpdatedAt); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return fmt.Errorf("deployment PTU share conflict: %w", ErrConflict)
		}
		return err
	}
	p.syncPTUShareMem(share)
	return nil
}

func (p *PostgresRepository) ListDeploymentPTUShares(ctx context.Context, deploymentID string) ([]*domain.DeploymentPTUShare, error) {
	if p.pool == nil {
		return p.mem.ListDeploymentPTUShares(ctx, deploymentID)
	}
	deploymentID = strings.TrimSpace(deploymentID)
	q := `SELECT ` + ptuShareSelectCols + ` FROM deployment_ptu_shares`
	var args []any
	if deploymentID != "" {
		args = append(args, deploymentID)
		q += ` WHERE deployment_id = $1`
	}
	q += ` ORDER BY deployment_id ASC, team_id ASC, id ASC`

	rows, err := p.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*domain.DeploymentPTUShare
	for rows.Next() {
		s, scanErr := scanPTUShare(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (p *PostgresRepository) DeleteDeploymentPTUShare(ctx context.Context, deploymentID, teamID string) error {
	if p.pool == nil {
		return p.mem.DeleteDeploymentPTUShare(ctx, deploymentID, teamID)
	}
	deploymentID = strings.TrimSpace(deploymentID)
	teamID = strings.TrimSpace(teamID)
	tag, err := p.pool.Exec(ctx,
		`DELETE FROM deployment_ptu_shares WHERE deployment_id = $1 AND team_id = $2`,
		deploymentID, teamID,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("deployment PTU share (%s, %s) %w", deploymentID, teamID, ErrNotFound)
	}
	_ = p.mem.DeleteDeploymentPTUShare(ctx, deploymentID, teamID)
	return nil
}

func (p *PostgresRepository) HasTeamPTUShares(ctx context.Context, teamID string) (bool, error) {
	if p.pool == nil {
		return p.mem.HasTeamPTUShares(ctx, teamID)
	}
	teamID = strings.TrimSpace(teamID)
	if teamID == "" {
		return false, nil
	}
	var exists bool
	if err := p.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM deployment_ptu_shares WHERE team_id = $1)`,
		teamID,
	).Scan(&exists); err != nil {
		return false, err
	}
	return exists, nil
}

const budgetWindowSelectCols = `id, org_id, scope_type, scope_id, window_type, max_budget_micros, spent_micros, window_reset_at, rolling_hold_micros, rolling_hold_expires_at, created_at, updated_at`

func scanBudgetWindowLimit(row rowScanner) (*domain.BudgetWindowLimit, error) {
	var bw domain.BudgetWindowLimit
	var scopeType, windowType string
	if err := row.Scan(
		&bw.ID, &bw.OrgID, &scopeType, &bw.ScopeID, &windowType,
		&bw.MaxBudgetMicros, &bw.SpentMicros, &bw.WindowResetAt,
		&bw.RollingHoldMicros, &bw.RollingHoldExpiresAt,
		&bw.CreatedAt, &bw.UpdatedAt,
	); err != nil {
		return nil, err
	}
	bw.ScopeType = domain.QuotaScopeType(scopeType)
	bw.WindowType = domain.BudgetWindowType(windowType)
	return &bw, nil
}

func (p *PostgresRepository) syncBudgetWindowMem(bw *domain.BudgetWindowLimit) {
	if p == nil || p.mem == nil || bw == nil {
		return
	}
	tupleKey := budgetWindowTupleKey(bw.OrgID, bw.ScopeType, bw.ScopeID, bw.WindowType)
	p.mem.mu.Lock()
	if existingID, ok := p.mem.budgetWindowsByTuple[tupleKey]; ok && existingID != bw.ID {
		delete(p.mem.budgetWindows, existingID)
	}
	cp := bw.Clone()
	p.mem.budgetWindows[cp.ID] = cp
	p.mem.budgetWindowsByTuple[tupleKey] = cp.ID
	p.mem.mu.Unlock()
}

func (p *PostgresRepository) UpsertBudgetWindowLimit(ctx context.Context, limit *domain.BudgetWindowLimit) error {
	if p.pool == nil {
		return p.mem.UpsertBudgetWindowLimit(ctx, limit)
	}
	now := time.Now().UTC()
	hasExplicitReset := limit != nil && !limit.WindowResetAt.IsZero()
	if err := normalizeBudgetWindowLimit(limit, now); err != nil {
		return err
	}
	if limit.ID == "" {
		limit.ID = uuid.NewString()
	}
	const q = `
		INSERT INTO budget_window_limits (
			id, org_id, scope_type, scope_id, window_type,
			max_budget_micros, spent_micros, window_reset_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (org_id, scope_type, scope_id, window_type) DO UPDATE SET
			max_budget_micros = EXCLUDED.max_budget_micros,
			spent_micros = GREATEST(budget_window_limits.spent_micros, EXCLUDED.spent_micros),
			window_reset_at = CASE WHEN $9 THEN EXCLUDED.window_reset_at ELSE budget_window_limits.window_reset_at END,
			updated_at = NOW()
		RETURNING id, spent_micros, window_reset_at, created_at, updated_at`

	if err := p.pool.QueryRow(ctx, q,
		limit.ID, limit.OrgID, string(limit.ScopeType), limit.ScopeID, string(limit.WindowType),
		limit.MaxBudgetMicros, limit.SpentMicros, limit.WindowResetAt, hasExplicitReset,
	).Scan(&limit.ID, &limit.SpentMicros, &limit.WindowResetAt, &limit.CreatedAt, &limit.UpdatedAt); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return fmt.Errorf("budget window limit conflict: %w", ErrConflict)
		}
		return err
	}
	p.syncBudgetWindowMem(limit)
	return nil
}

func (p *PostgresRepository) ListBudgetWindowLimits(ctx context.Context, filter BudgetWindowFilter) ([]*domain.BudgetWindowLimit, error) {
	if p.pool == nil {
		return p.mem.ListBudgetWindowLimits(ctx, filter)
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
	if v := strings.ToLower(strings.TrimSpace(string(filter.ScopeType))); v != "" {
		addCond("scope_type", v)
	}
	if v := strings.TrimSpace(filter.ScopeID); v != "" {
		addCond("scope_id", v)
	}
	if v := strings.ToLower(strings.TrimSpace(string(filter.WindowType))); v != "" {
		addCond("window_type", v)
	}

	q := `SELECT ` + budgetWindowSelectCols + ` FROM budget_window_limits`
	if len(conds) > 0 {
		q += ` WHERE ` + strings.Join(conds, " AND ")
	}
	q += ` ORDER BY org_id ASC, scope_type ASC, scope_id ASC, window_type ASC, id ASC`

	rows, err := p.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*domain.BudgetWindowLimit
	for rows.Next() {
		bw, scanErr := scanBudgetWindowLimit(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, bw)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if filter.SkipRollingSpend {
		return out, nil
	}
	now := time.Now().UTC()
	cutoff := now.Add(-24 * time.Hour)
	for _, bw := range out {
		if bw.WindowType != domain.BudgetWindowRolling24h {
			continue
		}
		recentSum, rErr := p.postgresRollingWindowSpend(ctx, bw, cutoff)
		if rErr != nil {
			return nil, rErr
		}
		if bw.RollingHoldExpiresAt != nil && now.Before(bw.RollingHoldExpiresAt.UTC()) && bw.RollingHoldMicros > 0 {
			recentSum += bw.RollingHoldMicros
		}
		bw.SpentMicros = recentSum
	}
	return out, nil
}

func rollingSpendScopeFilter(orgID string, scopeType domain.QuotaScopeType, scopeID string, nextArg int) (string, []any, bool) {
	switch scopeType {
	case domain.QuotaScopeOrg:
		return fmt.Sprintf("org_id = $%d", nextArg), []any{orgID}, true
	case domain.QuotaScopeTeam:
		return fmt.Sprintf("org_id = $%d AND team_id = $%d", nextArg, nextArg+1), []any{orgID, scopeID}, true
	case domain.QuotaScopeUser:
		return fmt.Sprintf("org_id = $%d AND user_id = $%d", nextArg, nextArg+1), []any{orgID, scopeID}, true
	case domain.QuotaScopeKey:
		return fmt.Sprintf("org_id = $%d AND virtual_key_id = $%d", nextArg, nextArg+1), []any{orgID, scopeID}, true
	case domain.QuotaScopeTeamMember:
		teamID, userID, ok := strings.Cut(scopeID, ":")
		if !ok || teamID == "" || userID == "" {
			return "", nil, false
		}
		return fmt.Sprintf("org_id = $%d AND team_id = $%d AND user_id = $%d", nextArg, nextArg+1, nextArg+2), []any{orgID, teamID, userID}, true
	case domain.QuotaScopeProject:
		return fmt.Sprintf("org_id = $%d AND project_id = $%d", nextArg, nextArg+1), []any{orgID, scopeID}, true
	case domain.QuotaScopeEndUser:
		return fmt.Sprintf("org_id = $%d AND end_user_id = $%d", nextArg, nextArg+1), []any{orgID, scopeID}, true
	case domain.QuotaScopeTag:
		return fmt.Sprintf("org_id = $%d AND $%d = ANY(tags)", nextArg, nextArg+1), []any{orgID, scopeID}, true
	case domain.QuotaScopeModelAccessGroup:
		return fmt.Sprintf("org_id = $%d AND $%d = ANY(model_access_group_ids)", nextArg, nextArg+1), []any{orgID, scopeID}, true
	default:
		return "", nil, false
	}
}

func (p *PostgresRepository) postgresRollingWindowSpend(ctx context.Context, bw *domain.BudgetWindowLimit, cutoff time.Time) (int64, error) {
	if p == nil || p.pool == nil || bw == nil {
		return 0, nil
	}
	condSQL, scopeArgs, ok := rollingSpendScopeFilter(bw.OrgID, bw.ScopeType, bw.ScopeID, 2)
	if !ok {
		return 0, nil
	}
	var sum int64
	q := `SELECT COALESCE(SUM(cost_micros), 0) FROM spend_logs WHERE created_at > $1 AND ` + condSQL
	args := append([]any{cutoff}, scopeArgs...)
	if err := p.pool.QueryRow(ctx, q, args...).Scan(&sum); err != nil {
		return 0, err
	}
	return sum, nil
}

func (p *PostgresRepository) ListRollingWindowHistory(ctx context.Context, orgID string, scopeType domain.QuotaScopeType, scopeID string, now time.Time) ([]domain.RollingSpendEntry, error) {
	orgID = strings.TrimSpace(orgID)
	scopeType = domain.QuotaScopeType(strings.ToLower(strings.TrimSpace(string(scopeType))))
	scopeID = strings.TrimSpace(scopeID)
	if orgID == "" || scopeID == "" || !scopeType.IsValid() {
		return nil, nil
	}
	nowUTC := now.UTC()
	if nowUTC.IsZero() {
		nowUTC = time.Now().UTC()
	}
	if p == nil || p.pool == nil {
		return p.mem.ListRollingWindowHistory(ctx, orgID, scopeType, scopeID, nowUTC)
	}

	condSQL, scopeArgs, ok := rollingSpendScopeFilter(orgID, scopeType, scopeID, 2)
	if !ok {
		return nil, nil
	}
	cutoff := nowUTC.Add(-24 * time.Hour)
	q := `SELECT id, created_at, cost_micros FROM spend_logs WHERE created_at > $1 AND cost_micros > 0 AND ` + condSQL + ` ORDER BY created_at ASC, id ASC`
	args := append([]any{cutoff}, scopeArgs...)

	rows, err := p.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []domain.RollingSpendEntry
	for rows.Next() {
		var id string
		var createdAt time.Time
		var costMicros int64
		if scanErr := rows.Scan(&id, &createdAt, &costMicros); scanErr != nil {
			return nil, scanErr
		}
		if costMicros <= 0 {
			continue
		}
		out = append(out, domain.RollingSpendEntry{
			ID:           "db:" + id,
			TimestampMs:  createdAt.UTC().UnixMilli(),
			AmountMicros: costMicros,
		})
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	var bwID string
	var holdMicros int64
	var holdExp *time.Time
	holdErr := p.pool.QueryRow(ctx,
		`SELECT id, rolling_hold_micros, rolling_hold_expires_at
		 FROM budget_window_limits
		 WHERE org_id = $1 AND scope_type = $2 AND scope_id = $3 AND window_type = 'rolling_24h'`,
		orgID, string(scopeType), scopeID,
	).Scan(&bwID, &holdMicros, &holdExp)
	if holdErr != nil && !errors.Is(holdErr, pgx.ErrNoRows) {
		return nil, holdErr
	}
	if holdErr == nil && holdMicros > 0 && holdExp != nil && holdExp.UTC().After(nowUTC) {
		out = append(out, domain.RollingSpendEntry{
			ID:           "hold:" + bwID,
			TimestampMs:  holdExp.UTC().Add(-24 * time.Hour).UnixMilli(),
			AmountMicros: holdMicros,
		})
	}
	return out, nil
}

func (p *PostgresRepository) IncrementBudgetWindowSpend(ctx context.Context, orgID string, scopeType domain.QuotaScopeType, scopeID string, deltaMicros int64) error {
	orgID = strings.TrimSpace(orgID)
	scopeType = domain.QuotaScopeType(strings.ToLower(strings.TrimSpace(string(scopeType))))
	scopeID = strings.TrimSpace(scopeID)
	if orgID == "" || !scopeType.IsValid() || scopeID == "" {
		return fmt.Errorf("org_id, valid scope_type, and scope_id are required")
	}
	if deltaMicros < 0 {
		return fmt.Errorf("delta_micros must be non-negative")
	}
	if deltaMicros == 0 {
		return nil
	}
	if p.pool == nil {
		return p.mem.IncrementBudgetWindowSpend(ctx, orgID, scopeType, scopeID, deltaMicros)
	}
	now := time.Now().UTC()
	expiresAt := now.Add(24 * time.Hour)
	if _, err := p.pool.Exec(ctx,
		`UPDATE budget_window_limits
		 SET spent_micros = CASE WHEN window_type = 'rolling_24h' THEN spent_micros ELSE spent_micros + $4 END,
		     rolling_hold_micros = CASE
		         WHEN window_type <> 'rolling_24h' THEN rolling_hold_micros
		         WHEN rolling_hold_expires_at IS NULL OR rolling_hold_expires_at <= $5 THEN $4
		         ELSE rolling_hold_micros + $4
		     END,
		     rolling_hold_expires_at = CASE WHEN window_type = 'rolling_24h' THEN $6 ELSE rolling_hold_expires_at END,
		     updated_at = NOW()
		 WHERE org_id = $1 AND scope_type = $2 AND scope_id = $3`,
		orgID, string(scopeType), scopeID, deltaMicros, now, expiresAt,
	); err != nil {
		return err
	}
	_ = p.mem.IncrementBudgetWindowSpend(ctx, orgID, scopeType, scopeID, deltaMicros)
	return nil
}

func (p *PostgresRepository) ResetExpiredBudgetWindows(ctx context.Context, now time.Time) (int, error) {
	reset, err := p.ResetExpiredBudgetWindowsWithResults(ctx, now)
	return len(reset), err
}

func (p *PostgresRepository) ResetExpiredBudgetWindowsWithResults(ctx context.Context, now time.Time) ([]*domain.BudgetWindowLimit, error) {
	if p.pool == nil {
		return p.mem.ResetExpiredBudgetWindowsWithResults(ctx, now)
	}
	nowUTC := now.UTC()
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin reset budget windows tx: %w", err)
	}
	defer tx.Rollback(ctx)

	rows, err := tx.Query(ctx,
		`SELECT `+budgetWindowSelectCols+` FROM budget_window_limits WHERE window_type <> 'rolling_24h' AND window_reset_at <= $1 FOR UPDATE`,
		nowUTC,
	)
	if err != nil {
		return nil, err
	}
	var expired []*domain.BudgetWindowLimit
	for rows.Next() {
		bw, scanErr := scanBudgetWindowLimit(rows)
		if scanErr != nil {
			rows.Close()
			return nil, scanErr
		}
		expired = append(expired, bw)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()

	for _, bw := range expired {
		nextReset := advanceBudgetWindowResetAt(bw.WindowType, bw.WindowResetAt, nowUTC)
		if _, err := tx.Exec(ctx,
			`UPDATE budget_window_limits SET spent_micros = 0, window_reset_at = $2, updated_at = NOW() WHERE id = $1`,
			bw.ID, nextReset,
		); err != nil {
			return nil, err
		}
		bw.SpentMicros = 0
		bw.WindowResetAt = nextReset
		bw.UpdatedAt = nowUTC
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit reset budget windows tx: %w", err)
	}
	for _, bw := range expired {
		p.syncBudgetWindowMem(bw)
	}
	sortBudgetWindowLimits(expired)
	return expired, nil
}

func (p *PostgresRepository) SetTempBudgetBoost(ctx context.Context, scopeType domain.QuotaScopeType, scopeID string, increaseMicros int64, expiresAt *time.Time) error {
	scopeType = domain.QuotaScopeType(strings.ToLower(strings.TrimSpace(string(scopeType))))
	scopeID = strings.TrimSpace(scopeID)
	if scopeID == "" {
		return fmt.Errorf("scope_id is required")
	}
	if increaseMicros < 0 {
		return fmt.Errorf("temp_budget_increase_micros must be non-negative")
	}
	if p.pool == nil {
		return p.mem.SetTempBudgetBoost(ctx, scopeType, scopeID, increaseMicros, expiresAt)
	}
	var table string
	switch scopeType {
	case domain.QuotaScopeKey:
		table = "virtual_keys"
	case domain.QuotaScopeTeam:
		table = "teams"
	case domain.QuotaScopeUser:
		table = "users"
	case domain.QuotaScopeOrg:
		table = "organizations"
	default:
		return fmt.Errorf("unsupported temp budget scope_type %q", scopeType)
	}
	var exp *time.Time
	if expiresAt != nil {
		u := expiresAt.UTC()
		exp = &u
	}
	tag, err := p.pool.Exec(ctx,
		`UPDATE `+table+` SET temp_budget_increase_micros = $2, temp_budget_expires_at = $3, updated_at = NOW() WHERE id = $1`,
		scopeID, increaseMicros, exp,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("%s %q %w", scopeType, scopeID, ErrNotFound)
	}
	_ = p.mem.SetTempBudgetBoost(ctx, scopeType, scopeID, increaseMicros, exp)
	return nil
}

const priorityClassSelectCols = `id, org_id, name, weight, priority_rank, max_borrow_multiple, created_at`

func scanPriorityClass(row rowScanner) (*domain.PriorityClass, error) {
	var pc domain.PriorityClass
	if err := row.Scan(
		&pc.ID, &pc.OrgID, &pc.Name, &pc.Weight,
		&pc.PriorityRank, &pc.MaxBorrowMultiple, &pc.CreatedAt,
	); err != nil {
		return nil, err
	}
	return &pc, nil
}

func (p *PostgresRepository) syncPriorityClassMem(pc *domain.PriorityClass) {
	if p == nil || p.mem == nil || pc == nil {
		return
	}
	p.mem.mu.Lock()
	tupleKey := priorityClassTupleKey(pc.OrgID, pc.Name)
	if oldID, ok := p.mem.priorityClassesByTuple[tupleKey]; ok && oldID != pc.ID {
		delete(p.mem.priorityClasses, oldID)
	}
	if existing, ok := p.mem.priorityClasses[pc.ID]; ok {
		delete(p.mem.priorityClassesByTuple, priorityClassTupleKey(existing.OrgID, existing.Name))
	}
	cp := pc.Clone()
	p.mem.priorityClasses[cp.ID] = cp
	p.mem.priorityClassesByTuple[tupleKey] = cp.ID
	p.mem.mu.Unlock()
}

func (p *PostgresRepository) UpsertPriorityClass(ctx context.Context, pc *domain.PriorityClass) error {
	if p.pool == nil {
		return p.mem.UpsertPriorityClass(ctx, pc)
	}
	now := time.Now().UTC()
	if err := normalizePriorityClass(pc, now); err != nil {
		return err
	}
	if pc.ID == "" {
		pc.ID = uuid.NewString()
	}
	const q = `
		INSERT INTO priority_classes (
			id, org_id, name, weight, priority_rank, max_borrow_multiple
		) VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (org_id, name) DO UPDATE SET
			weight = EXCLUDED.weight,
			priority_rank = EXCLUDED.priority_rank,
			max_borrow_multiple = EXCLUDED.max_borrow_multiple
		RETURNING id, created_at`
	if err := p.pool.QueryRow(ctx, q,
		pc.ID, pc.OrgID, pc.Name, pc.Weight, pc.PriorityRank, pc.MaxBorrowMultiple,
	).Scan(&pc.ID, &pc.CreatedAt); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return fmt.Errorf("priority class conflict: %w", ErrConflict)
		}
		return err
	}
	p.syncPriorityClassMem(pc)
	return nil
}

func (p *PostgresRepository) ListPriorityClasses(ctx context.Context, orgID string) ([]*domain.PriorityClass, error) {
	if p.pool == nil {
		return p.mem.ListPriorityClasses(ctx, orgID)
	}
	orgID = strings.TrimSpace(orgID)
	q := `SELECT ` + priorityClassSelectCols + ` FROM priority_classes`
	var args []any
	if orgID != "" {
		args = append(args, orgID)
		q += ` WHERE org_id = $1`
	}
	q += ` ORDER BY priority_rank ASC, name ASC, id ASC`

	rows, err := p.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*domain.PriorityClass
	for rows.Next() {
		pc, scanErr := scanPriorityClass(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, pc)
	}
	return out, rows.Err()
}
