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

const accessGroupRuleSelectCols = `id, org_id, name, attribute, operator, value, COALESCE(allowed_models, '{}'), COALESCE(allowed_mcp_servers, '{}'), COALESCE(allowed_mcp_tools, '{}'), COALESCE(allowed_a2a_agents, '{}'), COALESCE(access_group_id, ''), priority, is_active, created_at, updated_at`

func scanAccessGroupRule(row rowScanner) (*domain.AccessGroupRule, error) {
	var r domain.AccessGroupRule
	var op string
	if err := row.Scan(
		&r.ID, &r.OrgID, &r.Name, &r.Attribute, &op, &r.Value,
		&r.AllowedModels, &r.AllowedMCPServers, &r.AllowedMCPTools, &r.AllowedA2AAgents,
		&r.AccessGroupID, &r.Priority, &r.IsActive, &r.CreatedAt, &r.UpdatedAt,
	); err != nil {
		return nil, err
	}
	r.Operator = domain.AccessRuleOperator(op)
	if r.AllowedModels == nil {
		r.AllowedModels = []string{}
	}
	if r.AllowedMCPServers == nil {
		r.AllowedMCPServers = []string{}
	}
	if r.AllowedMCPTools == nil {
		r.AllowedMCPTools = []string{}
	}
	if r.AllowedA2AAgents == nil {
		r.AllowedA2AAgents = []string{}
	}
	return &r, nil
}

func (p *PostgresRepository) CreateAccessGroupRule(ctx context.Context, rule *domain.AccessGroupRule) error {
	if rule == nil {
		return fmt.Errorf("access group rule is required")
	}
	if strings.TrimSpace(rule.OrgID) == "" ||
		strings.TrimSpace(rule.Name) == "" ||
		strings.TrimSpace(rule.Attribute) == "" ||
		strings.TrimSpace(string(rule.Operator)) == "" ||
		strings.TrimSpace(rule.Value) == "" {
		return fmt.Errorf("org_id, name, attribute, operator, and value are required")
	}
	if p.pool == nil {
		return p.mem.CreateAccessGroupRule(ctx, rule)
	}
	if rule.ID == "" {
		rule.ID = uuid.NewString()
	}
	allowedModels := rule.AllowedModels
	if allowedModels == nil {
		allowedModels = []string{}
	}
	allowedMCPServers := rule.AllowedMCPServers
	if allowedMCPServers == nil {
		allowedMCPServers = []string{}
	}
	allowedMCPTools := rule.AllowedMCPTools
	if allowedMCPTools == nil {
		allowedMCPTools = []string{}
	}
	allowedA2AAgents := rule.AllowedA2AAgents
	if allowedA2AAgents == nil {
		allowedA2AAgents = []string{}
	}
	const q = `
		INSERT INTO access_group_rules (id, org_id, name, attribute, operator, value, allowed_models, allowed_mcp_servers, allowed_mcp_tools, allowed_a2a_agents, access_group_id, priority, is_active)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
		RETURNING created_at, updated_at`
	if err := p.pool.QueryRow(ctx, q,
		rule.ID, rule.OrgID, rule.Name, rule.Attribute, string(rule.Operator), rule.Value,
		allowedModels, allowedMCPServers, allowedMCPTools, allowedA2AAgents, rule.AccessGroupID, rule.Priority, rule.IsActive,
	).Scan(&rule.CreatedAt, &rule.UpdatedAt); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return fmt.Errorf("access group rule already exists: %w", ErrConflict)
		}
		return err
	}
	rule.AllowedModels = allowedModels
	rule.AllowedMCPServers = allowedMCPServers
	rule.AllowedMCPTools = allowedMCPTools
	rule.AllowedA2AAgents = allowedA2AAgents
	_ = p.mem.CreateAccessGroupRule(ctx, rule)
	return nil
}

func (p *PostgresRepository) GetAccessGroupRule(ctx context.Context, id string) (*domain.AccessGroupRule, error) {
	if p.pool == nil {
		return p.mem.GetAccessGroupRule(ctx, id)
	}
	r, err := scanAccessGroupRule(p.pool.QueryRow(ctx, `SELECT `+accessGroupRuleSelectCols+` FROM access_group_rules WHERE id = $1`, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("access group rule %q %w", id, ErrNotFound)
		}
		return nil, err
	}
	return r, nil
}

func (p *PostgresRepository) ListAccessGroupRules(ctx context.Context, orgID string, activeOnly bool) ([]*domain.AccessGroupRule, error) {
	if p.pool == nil {
		return p.mem.ListAccessGroupRules(ctx, orgID, activeOnly)
	}
	var (
		clauses []string
		args    []any
	)
	if orgID != "" {
		args = append(args, orgID)
		clauses = append(clauses, fmt.Sprintf("org_id = $%d", len(args)))
	}
	if activeOnly {
		clauses = append(clauses, "is_active = TRUE")
	}
	q := `SELECT ` + accessGroupRuleSelectCols + ` FROM access_group_rules`
	if len(clauses) > 0 {
		q += ` WHERE ` + strings.Join(clauses, " AND ")
	}
	q += ` ORDER BY priority DESC, created_at ASC, id ASC`

	rows, err := p.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*domain.AccessGroupRule
	for rows.Next() {
		r, scanErr := scanAccessGroupRule(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (p *PostgresRepository) DeleteAccessGroupRule(ctx context.Context, id string) error {
	if p.pool == nil {
		return p.mem.DeleteAccessGroupRule(ctx, id)
	}
	tag, err := p.pool.Exec(ctx, `DELETE FROM access_group_rules WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("access group rule %q %w", id, ErrNotFound)
	}
	_ = p.mem.DeleteAccessGroupRule(ctx, id)
	return nil
}

const virtualKeySelectCols = `id, key_prefix, key_hash, name, org_id, COALESCE(team_id, ''), COALESCE(user_id, ''), role, allowed_models, COALESCE(allowed_deployments, '{}'), allowed_endpoints, allowed_mcp_servers, allowed_mcp_tools, allowed_mcp_toolsets, allowed_a2a_agents, allowed_client_apps, max_budget_micros, temp_budget_increase_micros, temp_budget_expires_at, soft_budget_micros, throttle_on_budget_exceeded, COALESCE(budget_fallbacks, '{}'::jsonb), spent_micros, budget_reset_period, budget_reset_at, rpm_limit, tpm_limit, mcp_rpm_limit, max_concurrent_requests, batch_enqueued_token_limit, max_iterations, max_budget_per_session_micros, expires_at, is_active, rotation_interval_sec, key_rotation_at, COALESCE(staged_key_hash, ''), COALESCE(staged_key_prefix, ''), COALESCE(staged_encrypted_raw_key, ''), COALESCE(staged_key_dek, ''), staged_created_at, last_rotated_at, rotation_count, revoked_at, COALESCE(revoked_by, ''), COALESCE(expiry_alert_sent_days, '{}'), COALESCE(NULLIF(key_type, ''), 'default'), COALESCE(project_id, ''), can_impersonate, min_priority_rank, COALESCE(allowed_routing_tags, '{}'), COALESCE(tags, '{}'), COALESCE(metadata, '{}'::jsonb)`

const virtualKeySelectColsAliased = `vk.id, vk.key_prefix, vk.key_hash, vk.name, vk.org_id, COALESCE(vk.team_id, ''), COALESCE(vk.user_id, ''), vk.role, vk.allowed_models, COALESCE(vk.allowed_deployments, '{}'), vk.allowed_endpoints, vk.allowed_mcp_servers, vk.allowed_mcp_tools, vk.allowed_mcp_toolsets, vk.allowed_a2a_agents, vk.allowed_client_apps, vk.max_budget_micros, vk.temp_budget_increase_micros, vk.temp_budget_expires_at, vk.soft_budget_micros, vk.throttle_on_budget_exceeded, COALESCE(vk.budget_fallbacks, '{}'::jsonb), vk.spent_micros, vk.budget_reset_period, vk.budget_reset_at, vk.rpm_limit, vk.tpm_limit, vk.mcp_rpm_limit, vk.max_concurrent_requests, vk.batch_enqueued_token_limit, vk.max_iterations, vk.max_budget_per_session_micros, vk.expires_at, vk.is_active, vk.rotation_interval_sec, vk.key_rotation_at, COALESCE(vk.staged_key_hash, ''), COALESCE(vk.staged_key_prefix, ''), COALESCE(vk.staged_encrypted_raw_key, ''), COALESCE(vk.staged_key_dek, ''), vk.staged_created_at, vk.last_rotated_at, vk.rotation_count, vk.revoked_at, COALESCE(vk.revoked_by, ''), COALESCE(vk.expiry_alert_sent_days, '{}'), COALESCE(NULLIF(vk.key_type, ''), 'default'), COALESCE(vk.project_id, ''), vk.can_impersonate, vk.min_priority_rank, COALESCE(vk.allowed_routing_tags, '{}'), COALESCE(vk.tags, '{}'), COALESCE(vk.metadata, '{}'::jsonb)`

func scanVirtualKey(row rowScanner) (*domain.VirtualKey, error) {
	var k domain.VirtualKey
	var role, period, keyType string
	var rawFallbacks, rawMeta []byte
	var sentDays []int32
	if err := row.Scan(
		&k.ID, &k.KeyPrefix, &k.KeyHash, &k.Name, &k.OrgID, &k.TeamID, &k.UserID, &role,
		&k.AllowedModels, &k.AllowedDeployments, &k.AllowedEndpoints,
		&k.AllowedMCPServers, &k.AllowedMCPTools, &k.AllowedMCPToolsets, &k.AllowedA2AAgents, &k.AllowedClientApps,
		&k.MaxBudgetMicros, &k.TempBudgetIncreaseMicros, &k.TempBudgetExpiresAt, &k.SoftBudgetMicros, &k.ThrottleOnBudgetExceeded, &rawFallbacks, &k.SpentMicros, &period, &k.BudgetResetAt,
		&k.RPMLimit, &k.TPMLimit, &k.MCPRPMLimit, &k.MaxConcurrentRequests, &k.BatchEnqueuedTokenLimit, &k.MaxIterations, &k.MaxBudgetPerSessionMicros, &k.ExpiresAt, &k.IsActive,
		&k.RotationIntervalSec, &k.KeyRotationAt, &k.StagedKeyHash, &k.StagedKeyPrefix, &k.StagedEncryptedRawKey, &k.StagedKeyDEK, &k.StagedCreatedAt,
		&k.LastRotatedAt, &k.RotationCount, &k.RevokedAt, &k.RevokedBy, &sentDays,
		&keyType, &k.ProjectID, &k.CanImpersonate, &k.MinPriorityRank, &k.AllowedRoutingTags, &k.Tags, &rawMeta,
	); err != nil {
		return nil, err
	}
	k.Role = domain.Role(role)
	k.BudgetResetPeriod = domain.BudgetResetPeriod(period)
	k.BudgetFallbacks = unmarshalBudgetFallbacks(rawFallbacks)
	k.Metadata = unmarshalStringMapJSON(rawMeta)
	k.ExpiryAlertSentDays = int32sToInts(sentDays)
	k.KeyType = domain.KeyType(keyType)
	if k.KeyType == "" {
		k.KeyType = domain.KeyTypeDefault
	}
	return &k, nil
}

func scanDeprecatedVirtualKey(row rowScanner) (*domain.VirtualKey, time.Time, error) {
	var k domain.VirtualKey
	var role, period, keyType string
	var rawFallbacks, rawMeta []byte
	var sentDays []int32
	var revokeAt time.Time
	if err := row.Scan(
		&k.ID, &k.KeyPrefix, &k.KeyHash, &k.Name, &k.OrgID, &k.TeamID, &k.UserID, &role,
		&k.AllowedModels, &k.AllowedDeployments, &k.AllowedEndpoints,
		&k.AllowedMCPServers, &k.AllowedMCPTools, &k.AllowedMCPToolsets, &k.AllowedA2AAgents, &k.AllowedClientApps,
		&k.MaxBudgetMicros, &k.TempBudgetIncreaseMicros, &k.TempBudgetExpiresAt, &k.SoftBudgetMicros, &k.ThrottleOnBudgetExceeded, &rawFallbacks, &k.SpentMicros, &period, &k.BudgetResetAt,
		&k.RPMLimit, &k.TPMLimit, &k.MCPRPMLimit, &k.MaxConcurrentRequests, &k.BatchEnqueuedTokenLimit, &k.MaxIterations, &k.MaxBudgetPerSessionMicros, &k.ExpiresAt, &k.IsActive,
		&k.RotationIntervalSec, &k.KeyRotationAt, &k.StagedKeyHash, &k.StagedKeyPrefix, &k.StagedEncryptedRawKey, &k.StagedKeyDEK, &k.StagedCreatedAt,
		&k.LastRotatedAt, &k.RotationCount, &k.RevokedAt, &k.RevokedBy, &sentDays,
		&keyType, &k.ProjectID, &k.CanImpersonate, &k.MinPriorityRank, &k.AllowedRoutingTags, &k.Tags, &rawMeta,
		&revokeAt,
	); err != nil {
		return nil, time.Time{}, err
	}
	k.Role = domain.Role(role)
	k.BudgetResetPeriod = domain.BudgetResetPeriod(period)
	k.BudgetFallbacks = unmarshalBudgetFallbacks(rawFallbacks)
	k.Metadata = unmarshalStringMapJSON(rawMeta)
	k.ExpiryAlertSentDays = int32sToInts(sentDays)
	k.KeyType = domain.KeyType(keyType)
	if k.KeyType == "" {
		k.KeyType = domain.KeyTypeDefault
	}
	return &k, revokeAt.UTC(), nil
}

func (p *PostgresRepository) CreateVirtualKey(ctx context.Context, vk *domain.VirtualKey) error {
	if vk.ID == "" {
		vk.ID = uuid.NewString()
	}
	if vk.AllowedModels == nil {
		vk.AllowedModels = []string{}
	}
	allowedDeployments := vk.AllowedDeployments
	if allowedDeployments == nil {
		allowedDeployments = []string{}
	}
	if vk.AllowedEndpoints == nil {
		vk.AllowedEndpoints = append([]string(nil), domain.DefaultAllowedEndpoints...)
	}
	tags := vk.Tags
	if tags == nil {
		tags = []string{}
	}
	routingTags := vk.AllowedRoutingTags
	if routingTags == nil {
		routingTags = []string{}
	}
	if vk.Role == "" {
		vk.Role = domain.RoleServiceAccount
	}
	if vk.KeyType == "" {
		vk.KeyType = domain.KeyTypeDefault
	}
	vk.BudgetResetPeriod, vk.BudgetResetAt = resolveBudgetResetSchedule(vk.BudgetResetPeriod, vk.BudgetResetAt, time.Now().UTC())
	if p.pool == nil {
		return p.mem.CreateVirtualKey(ctx, vk)
	}
	const q = `
		INSERT INTO virtual_keys (
			id, key_prefix, key_hash, name, org_id, team_id, user_id, role, allowed_models, allowed_deployments, allowed_endpoints,
			allowed_mcp_servers, allowed_mcp_tools, allowed_mcp_toolsets, allowed_a2a_agents, allowed_client_apps,
			max_budget_micros, temp_budget_increase_micros, temp_budget_expires_at, soft_budget_micros, throttle_on_budget_exceeded, budget_fallbacks, spent_micros, budget_reset_period, budget_reset_at,
			rpm_limit, tpm_limit, mcp_rpm_limit, max_concurrent_requests, batch_enqueued_token_limit, max_iterations, max_budget_per_session_micros, expires_at, is_active,
			rotation_interval_sec, key_rotation_at,
			staged_key_hash, staged_key_prefix, staged_encrypted_raw_key, staged_key_dek, staged_created_at,
			key_type, project_id, can_impersonate, min_priority_rank, allowed_routing_tags, tags, metadata
		) VALUES ($1,$2,$3,$4,$5,NULLIF($6,''),NULLIF($7,''),$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32,$33,$34,$35,$36,NULLIF($37,''),NULLIF($38,''),NULLIF($39,''),NULLIF($40,''),$41,$42,NULLIF($43,''),$44,$45,$46,$47,$48)`
	if _, err := p.pool.Exec(ctx, q,
		vk.ID, vk.KeyPrefix, vk.KeyHash, vk.Name, vk.OrgID, vk.TeamID, vk.UserID, string(vk.Role),
		vk.AllowedModels, allowedDeployments, vk.AllowedEndpoints,
		vk.AllowedMCPServers, vk.AllowedMCPTools, vk.AllowedMCPToolsets, vk.AllowedA2AAgents, vk.AllowedClientApps,
		vk.MaxBudgetMicros, vk.TempBudgetIncreaseMicros, vk.TempBudgetExpiresAt, vk.SoftBudgetMicros, vk.ThrottleOnBudgetExceeded, marshalBudgetFallbacks(vk.BudgetFallbacks), vk.SpentMicros, string(vk.BudgetResetPeriod), vk.BudgetResetAt,
		vk.RPMLimit, vk.TPMLimit, vk.MCPRPMLimit, vk.MaxConcurrentRequests, vk.BatchEnqueuedTokenLimit, vk.MaxIterations, vk.MaxBudgetPerSessionMicros, vk.ExpiresAt, vk.IsActive,
		vk.RotationIntervalSec, vk.KeyRotationAt,
		vk.StagedKeyHash, vk.StagedKeyPrefix, vk.StagedEncryptedRawKey, vk.StagedKeyDEK, vk.StagedCreatedAt,
		string(vk.KeyType), vk.ProjectID, vk.CanImpersonate, vk.MinPriorityRank, routingTags, tags, marshalStringMapJSON(vk.Metadata),
	); err != nil {
		return err
	}
	return p.mem.CreateVirtualKey(ctx, vk)
}

func (p *PostgresRepository) UpdateVirtualKey(ctx context.Context, vk *domain.VirtualKey) error {
	if vk == nil || vk.ID == "" {
		return fmt.Errorf("virtual key id is required")
	}
	if vk.AllowedModels == nil {
		vk.AllowedModels = []string{}
	}
	allowedDeployments := vk.AllowedDeployments
	if allowedDeployments == nil {
		allowedDeployments = []string{}
	}
	if vk.AllowedEndpoints == nil {
		vk.AllowedEndpoints = append([]string(nil), domain.DefaultAllowedEndpoints...)
	}
	tags := vk.Tags
	if tags == nil {
		tags = []string{}
	}
	routingTags := vk.AllowedRoutingTags
	if routingTags == nil {
		routingTags = []string{}
	}
	if vk.Role == "" {
		vk.Role = domain.RoleServiceAccount
	}
	vk.BudgetResetPeriod, vk.BudgetResetAt = resolveBudgetResetSchedule(vk.BudgetResetPeriod, vk.BudgetResetAt, time.Now().UTC())
	const q = `
		UPDATE virtual_keys SET
			key_prefix = COALESCE(NULLIF($2, ''), key_prefix),
			key_hash = COALESCE(NULLIF($3, ''), key_hash),
			name = $4,
			team_id = NULLIF($5, ''),
			user_id = NULLIF($6, ''),
			role = $7,
			allowed_models = $8,
			allowed_deployments = $9,
			allowed_endpoints = $10,
			allowed_mcp_servers = $11,
			allowed_mcp_tools = $12,
			allowed_mcp_toolsets = $13,
			allowed_a2a_agents = $14,
			allowed_client_apps = $15,
			max_budget_micros = $16,
			temp_budget_increase_micros = $17,
			temp_budget_expires_at = $18,
			soft_budget_micros = $19,
			throttle_on_budget_exceeded = $20,
			budget_fallbacks = $21,
			spent_micros = $22,
			budget_reset_period = $23,
			budget_reset_at = $24,
			rpm_limit = $25,
			tpm_limit = $26,
			mcp_rpm_limit = $27,
			max_concurrent_requests = $28,
			batch_enqueued_token_limit = $29,
			max_iterations = $30,
			max_budget_per_session_micros = $31,
			expires_at = $32,
			is_active = $33,
			rotation_interval_sec = $34,
			key_rotation_at = $35,
			staged_key_hash = NULLIF($36, ''),
			staged_key_prefix = NULLIF($37, ''),
			staged_encrypted_raw_key = NULLIF($38, ''),
			staged_key_dek = NULLIF($39, ''),
			staged_created_at = $40,
			key_type = COALESCE(NULLIF($41, ''), key_type),
			project_id = NULLIF($42, ''),
			can_impersonate = $43,
			min_priority_rank = $44,
			allowed_routing_tags = $45,
			tags = $46,
			metadata = $47,
			updated_at = NOW()
		WHERE id = $1`
	if p.pool != nil {
		tag, err := p.pool.Exec(ctx, q,
			vk.ID, vk.KeyPrefix, vk.KeyHash, vk.Name, vk.TeamID, vk.UserID, string(vk.Role),
			vk.AllowedModels, allowedDeployments, vk.AllowedEndpoints,
			vk.AllowedMCPServers, vk.AllowedMCPTools, vk.AllowedMCPToolsets, vk.AllowedA2AAgents, vk.AllowedClientApps,
			vk.MaxBudgetMicros, vk.TempBudgetIncreaseMicros, vk.TempBudgetExpiresAt, vk.SoftBudgetMicros, vk.ThrottleOnBudgetExceeded, marshalBudgetFallbacks(vk.BudgetFallbacks), vk.SpentMicros, string(vk.BudgetResetPeriod), vk.BudgetResetAt,
			vk.RPMLimit, vk.TPMLimit, vk.MCPRPMLimit, vk.MaxConcurrentRequests, vk.BatchEnqueuedTokenLimit, vk.MaxIterations, vk.MaxBudgetPerSessionMicros, vk.ExpiresAt, vk.IsActive,
			vk.RotationIntervalSec, vk.KeyRotationAt, vk.StagedKeyHash, vk.StagedKeyPrefix, vk.StagedEncryptedRawKey, vk.StagedKeyDEK, vk.StagedCreatedAt, string(vk.KeyType), vk.ProjectID, vk.CanImpersonate, vk.MinPriorityRank, routingTags, tags, marshalStringMapJSON(vk.Metadata),
		)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("virtual key %q %w", vk.ID, ErrNotFound)
		}
	}
	if err := p.mem.UpdateVirtualKey(ctx, vk); err != nil {
		if p.pool == nil {
			return err
		}
		_ = p.mem.CreateVirtualKey(ctx, vk)
	}
	return nil
}

func (p *PostgresRepository) GetVirtualKeyByHash(ctx context.Context, keyHash string) (*domain.VirtualKey, error) {
	if p.pool == nil {
		return p.mem.GetVirtualKeyByHash(ctx, keyHash)
	}
	k, err := scanVirtualKey(p.pool.QueryRow(ctx, `SELECT `+virtualKeySelectCols+` FROM virtual_keys WHERE key_hash = $1`, keyHash))
	if err != nil {
		return nil, fmt.Errorf("virtual key not found: %w", err)
	}
	return k, nil
}

func (p *PostgresRepository) GetVirtualKeyByID(ctx context.Context, id string) (*domain.VirtualKey, error) {
	if p.pool == nil {
		return p.mem.GetVirtualKeyByID(ctx, id)
	}
	k, err := scanVirtualKey(p.pool.QueryRow(ctx, `SELECT `+virtualKeySelectCols+` FROM virtual_keys WHERE id = $1`, id))
	if err != nil {
		return nil, fmt.Errorf("virtual key not found: %w", err)
	}
	return k, nil
}

func (p *PostgresRepository) ListVirtualKeys(ctx context.Context, orgID string) ([]*domain.VirtualKey, error) {
	if p.pool == nil {
		return p.mem.ListVirtualKeys(ctx, orgID)
	}
	rows, err := p.pool.Query(ctx, `SELECT `+virtualKeySelectCols+` FROM virtual_keys WHERE org_id = $1 ORDER BY created_at DESC`, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []*domain.VirtualKey
	for rows.Next() {
		k, err := scanVirtualKey(rows)
		if err != nil {
			return nil, err
		}
		list = append(list, k)
	}
	return list, rows.Err()
}

func (p *PostgresRepository) ListVirtualKeysByUserID(ctx context.Context, orgID, userID string) ([]*domain.VirtualKey, error) {
	orgID = strings.TrimSpace(orgID)
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return nil, nil
	}
	if p.pool == nil {
		return p.mem.ListVirtualKeysByUserID(ctx, orgID, userID)
	}
	var (
		rows pgx.Rows
		err  error
	)
	if orgID != "" {
		rows, err = p.pool.Query(ctx, `SELECT `+virtualKeySelectCols+` FROM virtual_keys WHERE org_id = $1 AND user_id = $2 ORDER BY created_at DESC`, orgID, userID)
	} else {
		rows, err = p.pool.Query(ctx, `SELECT `+virtualKeySelectCols+` FROM virtual_keys WHERE user_id = $1 ORDER BY created_at DESC`, userID)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []*domain.VirtualKey
	for rows.Next() {
		k, err := scanVirtualKey(rows)
		if err != nil {
			return nil, err
		}
		list = append(list, k)
	}
	return list, rows.Err()
}

func (p *PostgresRepository) RevokeVirtualKey(ctx context.Context, id string) error {
	return p.RevokeVirtualKeyWithActor(ctx, id, "")
}

func (p *PostgresRepository) RevokeVirtualKeyWithActor(ctx context.Context, id, revokedBy string) error {
	if p.pool == nil {
		return p.mem.RevokeVirtualKeyWithActor(ctx, id, revokedBy)
	}
	var keyHash, orgID string
	err := p.pool.QueryRow(ctx,
		`UPDATE virtual_keys SET is_active = FALSE, revoked_at = COALESCE(revoked_at, NOW()), revoked_by = $2, updated_at = NOW() WHERE id = $1 RETURNING key_hash, org_id`,
		id, strings.TrimSpace(revokedBy),
	).Scan(&keyHash, &orgID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("virtual key %q %w", id, ErrNotFound)
		}
		return err
	}
	_ = p.mem.RevokeVirtualKeyWithActor(ctx, id, revokedBy)
	return nil
}

func (p *PostgresRepository) UnblockVirtualKey(ctx context.Context, id string) error {
	if p.pool == nil {
		return p.mem.UnblockVirtualKey(ctx, id)
	}
	tag, err := p.pool.Exec(ctx,
		`UPDATE virtual_keys SET is_active = TRUE, revoked_at = NULL, revoked_by = '', updated_at = NOW() WHERE id = $1`,
		id,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("virtual key %q %w", id, ErrNotFound)
	}
	_ = p.mem.UnblockVirtualKey(ctx, id)
	return nil
}

func (p *PostgresRepository) GetVirtualKeyAuthBundleByHash(ctx context.Context, keyHash string, now time.Time) (*VirtualKeyAuthBundle, error) {
	keyHash = strings.TrimSpace(keyHash)
	if keyHash == "" {
		return nil, fmt.Errorf("virtual key %w", ErrNotFound)
	}
	if p.pool == nil {
		return p.mem.GetVirtualKeyAuthBundleByHash(ctx, keyHash, now)
	}
	const q = `
		WITH matched AS (
			SELECT id AS vk_id, FALSE AS is_deprecated, NULL::timestamptz AS revoke_at
			FROM virtual_keys
			WHERE key_hash = $1
			UNION ALL
			SELECT d.virtual_key_id AS vk_id, TRUE AS is_deprecated, d.revoke_at
			FROM virtual_key_deprecated_hashes d
			WHERE d.key_hash = $1
			  AND d.revoke_at > $2
			  AND NOT EXISTS (SELECT 1 FROM virtual_keys WHERE key_hash = $1)
			LIMIT 1
		)
		SELECT
			` + virtualKeySelectColsAliased + `,
			m.is_deprecated,
			m.revoke_at,
			(o.id IS NOT NULL) AS has_org,
			COALESCE(o.id, ''), COALESCE(o.name, ''), COALESCE(o.slug, ''),
			COALESCE(o.max_budget_micros, 0), COALESCE(o.temp_budget_increase_micros, 0), o.temp_budget_expires_at,
			COALESCE(NULLIF(o.self_serve_budget_policy, ''), 'disabled'),
			COALESCE(o.soft_budget_micros, 0), COALESCE(o.throttle_on_budget_exceeded, FALSE), COALESCE(o.budget_fallbacks, '{}'::jsonb),
			COALESCE(o.spent_micros, 0), COALESCE(NULLIF(o.budget_reset_period, ''), 'monthly'), o.budget_reset_at,
			COALESCE(o.rpm_limit, 0), COALESCE(o.tpm_limit, 0), COALESCE(o.max_concurrent_requests, 0),
			COALESCE(o.batch_enqueued_token_limit, 0), COALESCE(o.max_iterations, 0), COALESCE(o.max_budget_per_session_micros, 0),
			COALESCE(o.enforce_guaranteed_throughput, FALSE), COALESCE(o.developer_self_serve_keys, FALSE),
			COALESCE(o.key_expiry_alert_days, '{7,1}'), COALESCE(o.lifecycle_webhook_url, ''), COALESCE(o.is_active, FALSE),
			(t.id IS NOT NULL) AS has_team,
			COALESCE(t.id, ''), COALESCE(t.org_id, ''), COALESCE(t.name, ''),
			COALESCE(t.max_budget_micros, 0), COALESCE(t.temp_budget_increase_micros, 0), t.temp_budget_expires_at,
			COALESCE(t.soft_budget_micros, 0), COALESCE(t.throttle_on_budget_exceeded, FALSE), COALESCE(t.budget_fallbacks, '{}'::jsonb),
			COALESCE(t.spent_micros, 0), COALESCE(NULLIF(t.budget_reset_period, ''), 'monthly'), t.budget_reset_at,
			COALESCE(t.rpm_limit, 0), COALESCE(t.tpm_limit, 0), COALESCE(t.mcp_rpm_limit, 0), COALESCE(t.max_concurrent_requests, 0),
			COALESCE(t.batch_enqueued_token_limit, 0), COALESCE(t.max_iterations, 0), COALESCE(t.max_budget_per_session_micros, 0),
			COALESCE(t.enforce_guaranteed_throughput, FALSE), COALESCE(t.default_member_max_budget_micros, 0),
			COALESCE(t.default_member_rpm_limit, 0), COALESCE(t.default_member_tpm_limit, 0),
			COALESCE(t.default_member_allowed_models, '{}'), COALESCE(t.team_member_permissions, '{}'),
			COALESCE(t.allowed_models, '{}'), COALESCE(t.allowed_deployments, '{}'), t.allowed_mcp_servers, t.allowed_mcp_tools, t.allowed_mcp_toolsets, t.allowed_a2a_agents, t.allowed_client_apps,
			COALESCE(t.min_priority_rank, 0), COALESCE(t.allowed_routing_tags, '{}'),
			COALESCE(t.is_active, FALSE),
			(pr.id IS NOT NULL) AS has_project,
			COALESCE(pr.id, ''), COALESCE(pr.org_id, ''), COALESCE(pr.team_id, ''), COALESCE(pr.name, ''), COALESCE(pr.description, ''),
			COALESCE(pr.max_budget_micros, 0), COALESCE(pr.spent_micros, 0), COALESCE(pr.rpm_limit, 0), COALESCE(pr.tpm_limit, 0),
			COALESCE(pr.allowed_models, '{}'), COALESCE(pr.allowed_deployments, '{}'), COALESCE(pr.allowed_routing_tags, '{}'),
			pr.allowed_mcp_servers, pr.allowed_mcp_tools, pr.allowed_mcp_toolsets, pr.allowed_a2a_agents,
			COALESCE(pr.enforce_project_model_quota, FALSE), COALESCE(pr.is_active, FALSE),
			(u.id IS NOT NULL) AS has_user,
			COALESCE(u.id, ''), COALESCE(u.org_id, ''), COALESCE(u.team_id, ''), COALESCE(u.email, ''), COALESCE(u.name, ''), COALESCE(u.role, ''),
			COALESCE(u.oidc_subject, ''), COALESCE(u.scim_external_id, ''), COALESCE(u.scim_active, TRUE),
			COALESCE(u.max_budget_micros, 0), COALESCE(u.temp_budget_increase_micros, 0), u.temp_budget_expires_at,
			COALESCE(u.soft_budget_micros, 0), COALESCE(u.throttle_on_budget_exceeded, FALSE), COALESCE(u.budget_fallbacks, '{}'::jsonb),
			COALESCE(u.spent_micros, 0), COALESCE(NULLIF(u.budget_reset_period, ''), 'monthly'), u.budget_reset_at,
			COALESCE(u.rpm_limit, 0), COALESCE(u.tpm_limit, 0), COALESCE(u.max_concurrent_requests, 0), COALESCE(u.batch_enqueued_token_limit, 0),
			COALESCE(u.is_active, FALSE),
			(tm.id IS NOT NULL) AS has_tm,
			COALESCE(tm.id, ''), COALESCE(tm.org_id, ''), COALESCE(tm.team_id, ''), COALESCE(tm.user_id, ''), COALESCE(tm.role, ''),
			COALESCE(tm.max_budget_micros, 0), COALESCE(tm.spent_micros, 0), COALESCE(tm.rpm_limit, 0), COALESCE(tm.tpm_limit, 0), COALESCE(tm.allowed_models, '{}')
		FROM matched m
		JOIN virtual_keys vk ON vk.id = m.vk_id
		LEFT JOIN organizations o ON o.id = vk.org_id
		LEFT JOIN teams t ON t.id = vk.team_id
		LEFT JOIN projects pr ON pr.id = vk.project_id
		LEFT JOIN users u ON u.id = vk.user_id
		LEFT JOIN team_memberships tm ON tm.team_id = vk.team_id AND tm.user_id = vk.user_id`

	var (
		k                         domain.VirtualKey
		vkRole, vkPeriod, keyType string
		vkFallbacks, vkMeta       []byte
		vkSentDays                []int32
		deprecated                bool
		revokeAt                  *time.Time

		hasOrg              bool
		o                   domain.Organization
		oPeriod, oSelfServe string
		oFallbacks          []byte
		oAlertDays          []int32

		hasTeam    bool
		t          domain.Team
		tPeriod    string
		tFallbacks []byte

		hasProj bool
		pr      domain.Project

		hasUser        bool
		u              domain.User
		uRole, uPeriod string
		uFallbacks     []byte

		hasTM  bool
		tm     domain.TeamMembership
		tmRole string
	)

	err := p.pool.QueryRow(ctx, q, keyHash, now.UTC()).Scan(
		&k.ID, &k.KeyPrefix, &k.KeyHash, &k.Name, &k.OrgID, &k.TeamID, &k.UserID, &vkRole,
		&k.AllowedModels, &k.AllowedDeployments, &k.AllowedEndpoints,
		&k.AllowedMCPServers, &k.AllowedMCPTools, &k.AllowedMCPToolsets, &k.AllowedA2AAgents, &k.AllowedClientApps,
		&k.MaxBudgetMicros, &k.TempBudgetIncreaseMicros, &k.TempBudgetExpiresAt, &k.SoftBudgetMicros, &k.ThrottleOnBudgetExceeded, &vkFallbacks, &k.SpentMicros, &vkPeriod, &k.BudgetResetAt,
		&k.RPMLimit, &k.TPMLimit, &k.MCPRPMLimit, &k.MaxConcurrentRequests, &k.BatchEnqueuedTokenLimit, &k.MaxIterations, &k.MaxBudgetPerSessionMicros, &k.ExpiresAt, &k.IsActive,
		&k.RotationIntervalSec, &k.KeyRotationAt, &k.StagedKeyHash, &k.StagedKeyPrefix, &k.StagedEncryptedRawKey, &k.StagedKeyDEK, &k.StagedCreatedAt,
		&k.LastRotatedAt, &k.RotationCount, &k.RevokedAt, &k.RevokedBy, &vkSentDays,
		&keyType, &k.ProjectID, &k.CanImpersonate, &k.MinPriorityRank, &k.AllowedRoutingTags, &k.Tags, &vkMeta,
		&deprecated, &revokeAt,
		&hasOrg,
		&o.ID, &o.Name, &o.Slug, &o.MaxBudgetMicros, &o.TempBudgetIncreaseMicros, &o.TempBudgetExpiresAt, &oSelfServe,
		&o.SoftBudgetMicros, &o.ThrottleOnBudgetExceeded, &oFallbacks, &o.SpentMicros, &oPeriod, &o.BudgetResetAt,
		&o.RPMLimit, &o.TPMLimit, &o.MaxConcurrentRequests, &o.BatchEnqueuedTokenLimit, &o.MaxIterations, &o.MaxBudgetPerSessionMicros,
		&o.EnforceGuaranteedThroughput, &o.DeveloperSelfServeKeys, &oAlertDays, &o.LifecycleWebhookURL, &o.IsActive,
		&hasTeam,
		&t.ID, &t.OrgID, &t.Name, &t.MaxBudgetMicros, &t.TempBudgetIncreaseMicros, &t.TempBudgetExpiresAt,
		&t.SoftBudgetMicros, &t.ThrottleOnBudgetExceeded, &tFallbacks, &t.SpentMicros, &tPeriod, &t.BudgetResetAt,
		&t.RPMLimit, &t.TPMLimit, &t.MCPRPMLimit, &t.MaxConcurrentRequests, &t.BatchEnqueuedTokenLimit, &t.MaxIterations, &t.MaxBudgetPerSessionMicros,
		&t.EnforceGuaranteedThroughput, &t.DefaultMemberMaxBudgetMicros, &t.DefaultMemberRPMLimit, &t.DefaultMemberTPMLimit,
		&t.DefaultMemberAllowedModels, &t.TeamMemberPermissions,
		&t.AllowedModels, &t.AllowedDeployments, &t.AllowedMCPServers, &t.AllowedMCPTools, &t.AllowedMCPToolsets, &t.AllowedA2AAgents, &t.AllowedClientApps,
		&t.MinPriorityRank, &t.AllowedRoutingTags, &t.IsActive,
		&hasProj,
		&pr.ID, &pr.OrgID, &pr.TeamID, &pr.Name, &pr.Description, &pr.MaxBudgetMicros, &pr.SpentMicros, &pr.RPMLimit, &pr.TPMLimit,
		&pr.AllowedModels, &pr.AllowedDeployments, &pr.AllowedRoutingTags,
		&pr.AllowedMCPServers, &pr.AllowedMCPTools, &pr.AllowedMCPToolsets, &pr.AllowedA2AAgents,
		&pr.EnforceProjectModelQuota, &pr.IsActive,
		&hasUser,
		&u.ID, &u.OrgID, &u.TeamID, &u.Email, &u.Name, &uRole, &u.OIDCSubject, &u.SCIMExternalID, &u.SCIMActive,
		&u.MaxBudgetMicros, &u.TempBudgetIncreaseMicros, &u.TempBudgetExpiresAt,
		&u.SoftBudgetMicros, &u.ThrottleOnBudgetExceeded, &uFallbacks, &u.SpentMicros, &uPeriod, &u.BudgetResetAt,
		&u.RPMLimit, &u.TPMLimit, &u.MaxConcurrentRequests, &u.BatchEnqueuedTokenLimit, &u.IsActive,
		&hasTM,
		&tm.ID, &tm.OrgID, &tm.TeamID, &tm.UserID, &tmRole, &tm.MaxBudgetMicros, &tm.SpentMicros, &tm.RPMLimit, &tm.TPMLimit, &tm.AllowedModels,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("virtual key %w", ErrNotFound)
		}
		return nil, err
	}

	k.Role = domain.Role(vkRole)
	k.BudgetResetPeriod = domain.BudgetResetPeriod(vkPeriod)
	k.BudgetFallbacks = unmarshalBudgetFallbacks(vkFallbacks)
	k.Metadata = unmarshalStringMapJSON(vkMeta)
	k.ExpiryAlertSentDays = int32sToInts(vkSentDays)
	k.KeyType = domain.KeyType(keyType)
	if k.KeyType == "" {
		k.KeyType = domain.KeyTypeDefault
	}

	bundle := &VirtualKeyAuthBundle{
		Key:        &k,
		Deprecated: deprecated,
	}
	if revokeAt != nil {
		bundle.DeprecatedKeyRevokeAt = revokeAt.UTC()
	}
	if hasOrg {
		o.BudgetResetPeriod = domain.BudgetResetPeriod(oPeriod)
		o.SelfServeBudgetPolicy = domain.SelfServeBudgetPolicy(oSelfServe)
		o.BudgetFallbacks = unmarshalBudgetFallbacks(oFallbacks)
		o.KeyExpiryAlertDays = int32sToInts(oAlertDays)
		bundle.Org = &o
	}
	if hasTeam {
		t.BudgetResetPeriod = domain.BudgetResetPeriod(tPeriod)
		t.BudgetFallbacks = unmarshalBudgetFallbacks(tFallbacks)
		bundle.Team = &t
	}
	if hasProj {
		bundle.Project = &pr
	}
	if hasUser {
		u.Role = domain.Role(uRole)
		u.BudgetResetPeriod = domain.BudgetResetPeriod(uPeriod)
		u.BudgetFallbacks = unmarshalBudgetFallbacks(uFallbacks)
		bundle.User = &u
	}
	if hasTM {
		tm.Role = domain.Role(tmRole)
		bundle.TeamMembership = &tm
	}
	return bundle, nil
}

func (p *PostgresRepository) ListVirtualKeysFiltered(ctx context.Context, filter VirtualKeyFilter) ([]*domain.VirtualKey, int, error) {
	if p.pool == nil {
		return p.mem.ListVirtualKeysFiltered(ctx, filter)
	}
	var conds []string
	var args []any
	addEq := func(col, val string) {
		if v := strings.TrimSpace(val); v != "" {
			args = append(args, v)
			conds = append(conds, fmt.Sprintf("%s = $%d", col, len(args)))
		}
	}
	addEq("org_id", filter.OrgID)
	addEq("team_id", filter.TeamID)
	addEq("user_id", filter.UserID)
	addEq("project_id", filter.ProjectID)
	switch strings.ToLower(strings.TrimSpace(filter.Status)) {
	case "active":
		conds = append(conds, "is_active = TRUE AND (expires_at IS NULL OR expires_at > NOW())")
	case "revoked":
		conds = append(conds, "is_active = FALSE")
	case "expired":
		conds = append(conds, "expires_at IS NOT NULL AND expires_at <= NOW()")
	}
	if qStr := strings.TrimSpace(filter.Search); qStr != "" {
		args = append(args, "%"+qStr+"%")
		conds = append(conds, fmt.Sprintf("(id ILIKE $%d OR key_prefix ILIKE $%d OR name ILIKE $%d)", len(args), len(args), len(args)))
	}
	where := ""
	if len(conds) > 0 {
		where = " WHERE " + strings.Join(conds, " AND ")
	}
	var total int
	if err := p.pool.QueryRow(ctx, `SELECT COUNT(*) FROM virtual_keys`+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	q := `SELECT ` + virtualKeySelectCols + ` FROM virtual_keys` + where + ` ORDER BY created_at DESC, id ASC`
	if filter.Limit > 0 {
		args = append(args, filter.Limit)
		q += fmt.Sprintf(" LIMIT $%d", len(args))
	}
	if filter.Offset > 0 {
		args = append(args, filter.Offset)
		q += fmt.Sprintf(" OFFSET $%d", len(args))
	}
	rows, err := p.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var list []*domain.VirtualKey
	for rows.Next() {
		k, scanErr := scanVirtualKey(rows)
		if scanErr != nil {
			return nil, 0, scanErr
		}
		list = append(list, k)
	}
	return list, total, rows.Err()
}

func (p *PostgresRepository) BulkUpdateVirtualKeys(ctx context.Context, orgID string, ids []string, patch VirtualKeyBulkPatch) ([]*domain.VirtualKey, error) {
	if p.pool == nil {
		return p.mem.BulkUpdateVirtualKeys(ctx, orgID, ids, patch)
	}
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var updated []*domain.VirtualKey
	for _, id := range ids {
		var sets []string
		args := []any{id}
		addSet := func(expr string, val any) {
			args = append(args, val)
			sets = append(sets, fmt.Sprintf("%s = $%d", expr, len(args)))
		}
		if patch.IsActive != nil {
			addSet("is_active", *patch.IsActive)
			if !*patch.IsActive {
				sets = append(sets, "revoked_at = COALESCE(revoked_at, NOW())")
				addSet("revoked_by", strings.TrimSpace(patch.RevokedBy))
			} else {
				sets = append(sets, "revoked_at = NULL", "revoked_by = ''")
			}
		}
		if patch.MaxBudgetMicros != nil {
			addSet("max_budget_micros", *patch.MaxBudgetMicros)
		}
		if patch.RPMLimit != nil {
			addSet("rpm_limit", *patch.RPMLimit)
		}
		if patch.TPMLimit != nil {
			addSet("tpm_limit", *patch.TPMLimit)
		}
		if patch.AllowedModels != nil {
			addSet("allowed_models", patch.AllowedModels)
		}
		sets = append(sets, "updated_at = NOW()")
		where := "id = $1"
		if strings.TrimSpace(orgID) != "" {
			args = append(args, strings.TrimSpace(orgID))
			where += fmt.Sprintf(" AND org_id = $%d", len(args))
		}
		q := `UPDATE virtual_keys SET ` + strings.Join(sets, ", ") + ` WHERE ` + where + ` RETURNING ` + virtualKeySelectCols
		k, scanErr := scanVirtualKey(tx.QueryRow(ctx, q, args...))
		if scanErr != nil {
			if errors.Is(scanErr, pgx.ErrNoRows) {
				return nil, fmt.Errorf("virtual key %q %w", id, ErrNotFound)
			}
			return nil, scanErr
		}
		if patch.IsActive != nil && !*patch.IsActive {
			if _, delErr := tx.Exec(ctx, `DELETE FROM virtual_key_deprecated_hashes WHERE virtual_key_id = $1`, k.ID); delErr != nil {
				return nil, delErr
			}
		}
		updated = append(updated, k)
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	_, _ = p.mem.BulkUpdateVirtualKeys(ctx, orgID, ids, patch)
	return updated, nil
}

func (p *PostgresRepository) ResetEntitySpend(ctx context.Context, scope EntitySpendScope, orgID, entityID, secondaryID string) error {
	if p.pool == nil {
		return p.mem.ResetEntitySpend(ctx, scope, orgID, entityID, secondaryID)
	}
	switch scope {
	case EntitySpendScopeKey:
		tag, err := p.pool.Exec(ctx, `UPDATE virtual_keys SET spent_micros = 0, updated_at = NOW() WHERE id = $1 AND ($2 = '' OR org_id = $2)`, entityID, strings.TrimSpace(orgID))
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("virtual key %q %w", entityID, ErrNotFound)
		}
	case EntitySpendScopeTeamMember:
		tag, err := p.pool.Exec(ctx, `UPDATE team_memberships SET spent_micros = 0, updated_at = NOW() WHERE team_id = $1 AND user_id = $2 AND ($3 = '' OR org_id = $3)`, entityID, secondaryID, strings.TrimSpace(orgID))
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("team membership (%q, %q) %w", entityID, secondaryID, ErrNotFound)
		}
	default:
		return fmt.Errorf("unsupported spend reset scope %q", scope)
	}
	_ = p.mem.ResetEntitySpend(ctx, scope, orgID, entityID, secondaryID)
	return nil
}

func (p *PostgresRepository) SumChildKeyThroughput(ctx context.Context, orgID, teamID, excludeKeyID string) (int, int, error) {
	if p.pool == nil {
		return p.mem.SumChildKeyThroughput(ctx, orgID, teamID, excludeKeyID)
	}
	var rpmSum, tpmSum int
	var q string
	var args []any
	if strings.TrimSpace(teamID) != "" {
		q = `SELECT COALESCE(SUM(rpm_limit), 0), COALESCE(SUM(tpm_limit), 0) FROM virtual_keys WHERE org_id = $1 AND team_id = $2 AND is_active = TRUE AND ($3 = '' OR id <> $3)`
		args = []any{orgID, teamID, excludeKeyID}
	} else {
		q = `SELECT COALESCE(SUM(rpm_limit), 0), COALESCE(SUM(tpm_limit), 0) FROM virtual_keys WHERE org_id = $1 AND is_active = TRUE AND ($2 = '' OR id <> $2)`
		args = []any{orgID, excludeKeyID}
	}
	if err := p.pool.QueryRow(ctx, q, args...).Scan(&rpmSum, &tpmSum); err != nil {
		return 0, 0, err
	}
	return rpmSum, tpmSum, nil
}

func (p *PostgresRepository) ListVirtualKeysExpiringBefore(ctx context.Context, cutoff time.Time, limit int) ([]*domain.VirtualKey, error) {
	if p.pool == nil {
		return p.mem.ListVirtualKeysExpiringBefore(ctx, cutoff, limit)
	}
	if limit <= 0 {
		limit = 200
	}
	const q = `
		SELECT ` + virtualKeySelectCols + `
		FROM virtual_keys
		WHERE is_active = TRUE
		  AND expires_at IS NOT NULL
		  AND expires_at > NOW()
		  AND expires_at <= $1
		ORDER BY expires_at ASC, id ASC
		LIMIT $2`
	rows, err := p.pool.Query(ctx, q, cutoff.UTC(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []*domain.VirtualKey
	for rows.Next() {
		k, scanErr := scanVirtualKey(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		list = append(list, k)
	}
	return list, rows.Err()
}

func (p *PostgresRepository) MarkVirtualKeyExpiryAlertSent(ctx context.Context, keyID string, alertDay int) error {
	if p.pool == nil {
		return p.mem.MarkVirtualKeyExpiryAlertSent(ctx, keyID, alertDay)
	}
	const q = `
		UPDATE virtual_keys
		SET expiry_alert_sent_days = CASE
			WHEN $2 = ANY(COALESCE(expiry_alert_sent_days, '{}')) THEN COALESCE(expiry_alert_sent_days, '{}')
			ELSE array_append(COALESCE(expiry_alert_sent_days, '{}'), $2)
		END
		WHERE id = $1`
	tag, err := p.pool.Exec(ctx, q, keyID, int32(alertDay))
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("virtual key %q %w", keyID, ErrNotFound)
	}
	_ = p.mem.MarkVirtualKeyExpiryAlertSent(ctx, keyID, alertDay)
	return nil
}

func (p *PostgresRepository) MarkVirtualKeyRotated(ctx context.Context, keyID string, rotatedAt time.Time) error {
	if p.pool == nil {
		return p.mem.MarkVirtualKeyRotated(ctx, keyID, rotatedAt)
	}
	ts := rotatedAt.UTC()
	tag, err := p.pool.Exec(ctx, `UPDATE virtual_keys SET last_rotated_at = $2, rotation_count = rotation_count + 1, updated_at = $2 WHERE id = $1`, keyID, ts)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("virtual key %q %w", keyID, ErrNotFound)
	}
	_ = p.mem.MarkVirtualKeyRotated(ctx, keyID, ts)
	return nil
}

func (p *PostgresRepository) AddDeprecatedVirtualKeyHash(ctx context.Context, keyHash, virtualKeyID string, revokeAt time.Time) error {
	keyHash = strings.TrimSpace(keyHash)
	virtualKeyID = strings.TrimSpace(virtualKeyID)
	if keyHash == "" || virtualKeyID == "" {
		return fmt.Errorf("key_hash and virtual_key_id are required")
	}
	revUTC := revokeAt.UTC()
	if p.pool == nil {
		return p.mem.AddDeprecatedVirtualKeyHash(ctx, keyHash, virtualKeyID, revUTC)
	}
	const q = `
		INSERT INTO virtual_key_deprecated_hashes (key_hash, virtual_key_id, revoke_at, created_at)
		VALUES ($1, $2, $3, NOW())
		ON CONFLICT (key_hash) DO UPDATE SET
			virtual_key_id = EXCLUDED.virtual_key_id,
			revoke_at = EXCLUDED.revoke_at`
	if _, err := p.pool.Exec(ctx, q, keyHash, virtualKeyID, revUTC); err != nil {
		return err
	}
	_ = p.mem.AddDeprecatedVirtualKeyHash(ctx, keyHash, virtualKeyID, revUTC)
	return nil
}

func (p *PostgresRepository) GetActiveDeprecatedVirtualKey(ctx context.Context, keyHash string, now time.Time) (*domain.VirtualKey, time.Time, error) {
	keyHash = strings.TrimSpace(keyHash)
	if keyHash == "" {
		return nil, time.Time{}, fmt.Errorf("deprecated virtual key %w", ErrNotFound)
	}
	nowUTC := now.UTC()
	if p.pool == nil {
		return p.mem.GetActiveDeprecatedVirtualKey(ctx, keyHash, nowUTC)
	}
	const q = `
		SELECT ` + virtualKeySelectColsAliased + `, d.revoke_at
		FROM virtual_key_deprecated_hashes d
		JOIN virtual_keys vk ON vk.id = d.virtual_key_id
		WHERE d.key_hash = $1 AND d.revoke_at > $2`
	vk, revokeAt, err := scanDeprecatedVirtualKey(p.pool.QueryRow(ctx, q, keyHash, nowUTC))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, time.Time{}, fmt.Errorf("deprecated virtual key %w", ErrNotFound)
		}
		return nil, time.Time{}, err
	}
	return vk, revokeAt, nil
}

func (p *PostgresRepository) DeleteExpiredDeprecatedVirtualKeyHashes(ctx context.Context, now time.Time) (int64, error) {
	nowUTC := now.UTC()
	if p.pool == nil {
		return p.mem.DeleteExpiredDeprecatedVirtualKeyHashes(ctx, nowUTC)
	}
	tag, err := p.pool.Exec(ctx, `DELETE FROM virtual_key_deprecated_hashes WHERE revoke_at <= $1`, nowUTC)
	if err != nil {
		return 0, err
	}
	_, _ = p.mem.DeleteExpiredDeprecatedVirtualKeyHashes(ctx, nowUTC)
	return tag.RowsAffected(), nil
}

func (p *PostgresRepository) ListDeprecatedVirtualKeyHashesByKeyID(ctx context.Context, virtualKeyID string) ([]string, error) {
	virtualKeyID = strings.TrimSpace(virtualKeyID)
	if virtualKeyID == "" {
		return nil, nil
	}
	if p.pool == nil {
		return p.mem.ListDeprecatedVirtualKeyHashesByKeyID(ctx, virtualKeyID)
	}
	rows, err := p.pool.Query(ctx, `SELECT TRIM(key_hash) FROM virtual_key_deprecated_hashes WHERE virtual_key_id = $1 ORDER BY key_hash ASC`, virtualKeyID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var hashes []string
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			return nil, err
		}
		if h != "" {
			hashes = append(hashes, h)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return hashes, nil
}

func (p *PostgresRepository) DeleteDeprecatedVirtualKeyHashesByKeyID(ctx context.Context, virtualKeyID string) ([]string, error) {
	virtualKeyID = strings.TrimSpace(virtualKeyID)
	if virtualKeyID == "" {
		return nil, nil
	}
	if p.pool == nil {
		return p.mem.DeleteDeprecatedVirtualKeyHashesByKeyID(ctx, virtualKeyID)
	}
	rows, err := p.pool.Query(ctx, `DELETE FROM virtual_key_deprecated_hashes WHERE virtual_key_id = $1 RETURNING TRIM(key_hash)`, virtualKeyID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var hashes []string
	for rows.Next() {
		var h string
		if err := rows.Scan(&h); err != nil {
			return nil, err
		}
		if h != "" {
			hashes = append(hashes, h)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	_, _ = p.mem.DeleteDeprecatedVirtualKeyHashesByKeyID(ctx, virtualKeyID)
	return hashes, nil
}

func (p *PostgresRepository) ListVirtualKeysDueForRotation(ctx context.Context, now time.Time, limit int) ([]*domain.VirtualKey, error) {
	nowUTC := now.UTC()
	if p.pool == nil {
		return p.mem.ListVirtualKeysDueForRotation(ctx, nowUTC, limit)
	}
	if limit <= 0 {
		limit = 100
	}
	const q = `
		SELECT ` + virtualKeySelectCols + `
		FROM virtual_keys
		WHERE is_active = TRUE
		  AND rotation_interval_sec > 0
		  AND key_rotation_at IS NOT NULL
		  AND key_rotation_at <= $1
		  AND (expires_at IS NULL OR expires_at > $1)
		ORDER BY key_rotation_at ASC, id ASC
		LIMIT $2`
	rows, err := p.pool.Query(ctx, q, nowUTC, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []*domain.VirtualKey
	for rows.Next() {
		k, err := scanVirtualKey(rows)
		if err != nil {
			return nil, err
		}
		list = append(list, k)
	}
	return list, rows.Err()
}
