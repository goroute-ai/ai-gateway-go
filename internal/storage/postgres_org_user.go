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

const orgSelectCols = `id, name, slug, max_budget_micros, temp_budget_increase_micros, temp_budget_expires_at, COALESCE(NULLIF(self_serve_budget_policy, ''), 'disabled'), soft_budget_micros, throttle_on_budget_exceeded, COALESCE(budget_fallbacks, '{}'::jsonb), spent_micros, budget_reset_period, budget_reset_at, rpm_limit, tpm_limit, max_concurrent_requests, batch_enqueued_token_limit, max_iterations, max_budget_per_session_micros, enforce_guaranteed_throughput, developer_self_serve_keys, COALESCE(key_expiry_alert_days, '{7,1}'), COALESCE(lifecycle_webhook_url, ''), is_active`

func scanOrganization(row rowScanner) (*domain.Organization, error) {
	var o domain.Organization
	var period, selfServePolicy string
	var rawFallbacks []byte
	var alertDays []int32
	if err := row.Scan(
		&o.ID, &o.Name, &o.Slug, &o.MaxBudgetMicros, &o.TempBudgetIncreaseMicros, &o.TempBudgetExpiresAt, &selfServePolicy, &o.SoftBudgetMicros, &o.ThrottleOnBudgetExceeded, &rawFallbacks, &o.SpentMicros, &period, &o.BudgetResetAt, &o.RPMLimit, &o.TPMLimit, &o.MaxConcurrentRequests, &o.BatchEnqueuedTokenLimit, &o.MaxIterations, &o.MaxBudgetPerSessionMicros, &o.EnforceGuaranteedThroughput, &o.DeveloperSelfServeKeys, &alertDays, &o.LifecycleWebhookURL, &o.IsActive,
	); err != nil {
		return nil, err
	}
	o.BudgetResetPeriod = domain.BudgetResetPeriod(period)
	o.SelfServeBudgetPolicy = domain.SelfServeBudgetPolicy(selfServePolicy)
	o.BudgetFallbacks = unmarshalBudgetFallbacks(rawFallbacks)
	o.KeyExpiryAlertDays = int32sToInts(alertDays)
	return &o, nil
}

func (p *PostgresRepository) CreateOrganization(ctx context.Context, org *domain.Organization) error {
	if org.ID == "" {
		org.ID = uuid.NewString()
	}
	if org.SelfServeBudgetPolicy == "" {
		org.SelfServeBudgetPolicy = domain.SelfServeBudgetDisabled
	} else {
		pol := domain.SelfServeBudgetPolicy(strings.ToLower(strings.TrimSpace(string(org.SelfServeBudgetPolicy))))
		if !pol.IsValid() {
			return fmt.Errorf("invalid self_serve_budget_policy %q", org.SelfServeBudgetPolicy)
		}
		org.SelfServeBudgetPolicy = pol
	}
	alertDays := org.KeyExpiryAlertDays
	if alertDays == nil {
		alertDays = []int{7, 1}
		org.KeyExpiryAlertDays = alertDays
	}
	org.BudgetResetPeriod, org.BudgetResetAt = resolveBudgetResetSchedule(org.BudgetResetPeriod, org.BudgetResetAt, time.Now().UTC())
	if p.pool == nil {
		return p.mem.CreateOrganization(ctx, org)
	}
	const q = `
		INSERT INTO organizations (id, name, slug, max_budget_micros, temp_budget_increase_micros, temp_budget_expires_at, self_serve_budget_policy, soft_budget_micros, throttle_on_budget_exceeded, budget_fallbacks, spent_micros, budget_reset_period, budget_reset_at, rpm_limit, tpm_limit, max_concurrent_requests, batch_enqueued_token_limit, max_iterations, max_budget_per_session_micros, enforce_guaranteed_throughput, developer_self_serve_keys, key_expiry_alert_days, lifecycle_webhook_url, is_active)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24)`
	if _, err := p.pool.Exec(ctx, q, org.ID, org.Name, org.Slug, org.MaxBudgetMicros, org.TempBudgetIncreaseMicros, org.TempBudgetExpiresAt, string(org.SelfServeBudgetPolicy), org.SoftBudgetMicros, org.ThrottleOnBudgetExceeded, marshalBudgetFallbacks(org.BudgetFallbacks), org.SpentMicros, string(org.BudgetResetPeriod), org.BudgetResetAt, org.RPMLimit, org.TPMLimit, org.MaxConcurrentRequests, org.BatchEnqueuedTokenLimit, org.MaxIterations, org.MaxBudgetPerSessionMicros, org.EnforceGuaranteedThroughput, org.DeveloperSelfServeKeys, intsToInt32(alertDays), org.LifecycleWebhookURL, org.IsActive); err != nil {
		return err
	}
	return p.mem.CreateOrganization(ctx, org)
}

func (p *PostgresRepository) UpdateOrganization(ctx context.Context, org *domain.Organization) error {
	if org == nil || org.ID == "" {
		return fmt.Errorf("organization id is required")
	}
	if org.SelfServeBudgetPolicy == "" {
		org.SelfServeBudgetPolicy = domain.SelfServeBudgetDisabled
	} else {
		pol := domain.SelfServeBudgetPolicy(strings.ToLower(strings.TrimSpace(string(org.SelfServeBudgetPolicy))))
		if !pol.IsValid() {
			return fmt.Errorf("invalid self_serve_budget_policy %q", org.SelfServeBudgetPolicy)
		}
		org.SelfServeBudgetPolicy = pol
	}
	alertDays := org.KeyExpiryAlertDays
	if alertDays == nil {
		alertDays = []int{7, 1}
		org.KeyExpiryAlertDays = alertDays
	}
	org.BudgetResetPeriod, org.BudgetResetAt = resolveBudgetResetSchedule(org.BudgetResetPeriod, org.BudgetResetAt, time.Now().UTC())
	if p.pool != nil {
		const q = `
			UPDATE organizations SET
				name = $2,
				slug = COALESCE(NULLIF($3, ''), slug),
				max_budget_micros = $4,
				temp_budget_increase_micros = $5,
				temp_budget_expires_at = $6,
				self_serve_budget_policy = $7,
				soft_budget_micros = $8,
				throttle_on_budget_exceeded = $9,
				budget_fallbacks = $10,
				spent_micros = $11,
				budget_reset_period = $12,
				budget_reset_at = $13,
				rpm_limit = $14,
				tpm_limit = $15,
				max_concurrent_requests = $16,
				batch_enqueued_token_limit = $17,
				max_iterations = $18,
				max_budget_per_session_micros = $19,
				enforce_guaranteed_throughput = $20,
				developer_self_serve_keys = $21,
				key_expiry_alert_days = $22,
				lifecycle_webhook_url = $23,
				is_active = $24,
				updated_at = NOW()
			WHERE id = $1`
		tag, err := p.pool.Exec(ctx, q,
			org.ID, org.Name, org.Slug, org.MaxBudgetMicros, org.TempBudgetIncreaseMicros, org.TempBudgetExpiresAt,
			string(org.SelfServeBudgetPolicy), org.SoftBudgetMicros, org.ThrottleOnBudgetExceeded, marshalBudgetFallbacks(org.BudgetFallbacks),
			org.SpentMicros, string(org.BudgetResetPeriod), org.BudgetResetAt, org.RPMLimit, org.TPMLimit,
			org.MaxConcurrentRequests, org.BatchEnqueuedTokenLimit, org.MaxIterations, org.MaxBudgetPerSessionMicros,
			org.EnforceGuaranteedThroughput, org.DeveloperSelfServeKeys, intsToInt32(alertDays), org.LifecycleWebhookURL, org.IsActive,
		)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("organization %q %w", org.ID, ErrNotFound)
		}
	}
	if err := p.mem.UpdateOrganization(ctx, org); err != nil {
		if p.pool == nil {
			return err
		}
		_ = p.mem.CreateOrganization(ctx, org)
	}
	return nil
}

func (p *PostgresRepository) GetOrganization(ctx context.Context, id string) (*domain.Organization, error) {
	if p.pool == nil {
		return p.mem.GetOrganization(ctx, id)
	}
	const q = `SELECT ` + orgSelectCols + ` FROM organizations WHERE id = $1`
	o, err := scanOrganization(p.pool.QueryRow(ctx, q, id))
	if err != nil {
		return nil, fmt.Errorf("organization not found: %w", err)
	}
	_ = p.mem.CreateOrganization(ctx, o)
	return o, nil
}

func (p *PostgresRepository) ListOrganizations(ctx context.Context) ([]*domain.Organization, error) {
	if p.pool == nil {
		return p.mem.ListOrganizations(ctx)
	}
	const q = `SELECT ` + orgSelectCols + ` FROM organizations ORDER BY name ASC`
	rows, err := p.pool.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*domain.Organization
	for rows.Next() {
		o, err := scanOrganization(rows)
		if err != nil {
			return nil, err
		}
		_ = p.mem.CreateOrganization(ctx, o)
		out = append(out, o)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (p *PostgresRepository) SetOrgProviderSubscription(ctx context.Context, sub *domain.OrgProviderSubscription) error {
	const q = `
		INSERT INTO org_provider_subscriptions (org_id, provider, is_enabled, auto_enable_new, subscribed_at)
		VALUES ($1,$2,$3,$4,NOW())
		ON CONFLICT (org_id, provider) DO UPDATE SET is_enabled = EXCLUDED.is_enabled, auto_enable_new = EXCLUDED.auto_enable_new`
	if _, err := p.pool.Exec(ctx, q, sub.OrgID, string(sub.Provider), sub.IsEnabled, sub.AutoEnableNew); err != nil {
		return err
	}
	return p.mem.SetOrgProviderSubscription(ctx, sub)
}

func (p *PostgresRepository) GetOrgProviderSubscriptions(ctx context.Context, orgID string) ([]*domain.OrgProviderSubscription, error) {
	if p.pool == nil {
		return p.mem.GetOrgProviderSubscriptions(ctx, orgID)
	}
	value, err := p.coalesceLookup(ctx, "subscriptions:"+orgID, func(lookupCtx context.Context) (any, error) {
		p.subscriptionQueries.Add(1)
		const q = `SELECT org_id, provider, is_enabled, auto_enable_new, subscribed_at FROM org_provider_subscriptions WHERE org_id = $1`
		rows, queryErr := p.pool.Query(lookupCtx, q, orgID)
		if queryErr != nil {
			return nil, queryErr
		}
		defer rows.Close()
		var out []*domain.OrgProviderSubscription
		for rows.Next() {
			var s domain.OrgProviderSubscription
			var prov string
			if scanErr := rows.Scan(&s.OrgID, &prov, &s.IsEnabled, &s.AutoEnableNew, &s.SubscribedAt); scanErr != nil {
				return nil, scanErr
			}
			s.Provider = domain.ProviderType(prov)
			if p.mem != nil {
				_ = p.mem.SetOrgProviderSubscription(lookupCtx, &s)
			}
			out = append(out, &s)
		}
		if rowsErr := rows.Err(); rowsErr != nil {
			return nil, rowsErr
		}
		if len(out) == 0 {
			p.emptySubscriptionQueries.Add(1)
		}
		return out, nil
	})
	if err != nil {
		return nil, err
	}
	result, _ := value.([]*domain.OrgProviderSubscription)
	return result, nil
}

func (p *PostgresRepository) SetOrgModelPolicy(ctx context.Context, pol *domain.OrgModelPolicy) error {
	const q = `
		INSERT INTO org_model_policies (org_id, global_model_id, is_enabled, approved_by, approved_at)
		VALUES ($1,$2,$3,$4,NOW())
		ON CONFLICT (org_id, global_model_id) DO UPDATE SET is_enabled = EXCLUDED.is_enabled`
	if _, err := p.pool.Exec(ctx, q, pol.OrgID, pol.GlobalModelID, pol.IsEnabled, pol.ApprovedBy); err != nil {
		return err
	}
	return p.mem.SetOrgModelPolicy(ctx, pol)
}

func (p *PostgresRepository) GetOrgModelPolicies(ctx context.Context, orgID string) ([]*domain.OrgModelPolicy, error) {
	if p.pool == nil {
		return p.mem.GetOrgModelPolicies(ctx, orgID)
	}
	const q = `SELECT org_id, global_model_id, is_enabled, approved_by, approved_at FROM org_model_policies WHERE org_id = $1`
	rows, err := p.pool.Query(ctx, q, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*domain.OrgModelPolicy
	for rows.Next() {
		var pol domain.OrgModelPolicy
		if err := rows.Scan(&pol.OrgID, &pol.GlobalModelID, &pol.IsEnabled, &pol.ApprovedBy, &pol.ApprovedAt); err != nil {
			return nil, err
		}
		_ = p.mem.SetOrgModelPolicy(ctx, &pol)
		out = append(out, &pol)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

type rowScanner interface {
	Scan(dest ...any) error
}

const teamSelectCols = `id, org_id, name, max_budget_micros, temp_budget_increase_micros, temp_budget_expires_at, soft_budget_micros, throttle_on_budget_exceeded, COALESCE(budget_fallbacks, '{}'::jsonb), spent_micros, budget_reset_period, budget_reset_at, rpm_limit, tpm_limit, mcp_rpm_limit, max_concurrent_requests, batch_enqueued_token_limit, max_iterations, max_budget_per_session_micros, enforce_guaranteed_throughput, default_member_max_budget_micros, default_member_rpm_limit, default_member_tpm_limit, COALESCE(default_member_allowed_models, '{}'), COALESCE(team_member_permissions, '{}'), allowed_models, allowed_mcp_servers, allowed_a2a_agents, allowed_client_apps, min_priority_rank, COALESCE(allowed_routing_tags, '{}'), is_active, created_at, updated_at`

func scanTeam(row rowScanner) (*domain.Team, error) {
	var t domain.Team
	var period string
	var rawFallbacks []byte
	if err := row.Scan(
		&t.ID, &t.OrgID, &t.Name, &t.MaxBudgetMicros, &t.TempBudgetIncreaseMicros, &t.TempBudgetExpiresAt, &t.SoftBudgetMicros, &t.ThrottleOnBudgetExceeded, &rawFallbacks, &t.SpentMicros, &period, &t.BudgetResetAt,
		&t.RPMLimit, &t.TPMLimit, &t.MCPRPMLimit, &t.MaxConcurrentRequests, &t.BatchEnqueuedTokenLimit, &t.MaxIterations, &t.MaxBudgetPerSessionMicros,
		&t.EnforceGuaranteedThroughput, &t.DefaultMemberMaxBudgetMicros, &t.DefaultMemberRPMLimit, &t.DefaultMemberTPMLimit, &t.DefaultMemberAllowedModels, &t.TeamMemberPermissions,
		&t.AllowedModels, &t.AllowedMCPServers, &t.AllowedA2AAgents, &t.AllowedClientApps,
		&t.MinPriorityRank, &t.AllowedRoutingTags,
		&t.IsActive, &t.CreatedAt, &t.UpdatedAt,
	); err != nil {
		return nil, err
	}
	t.BudgetResetPeriod = domain.BudgetResetPeriod(period)
	t.BudgetFallbacks = unmarshalBudgetFallbacks(rawFallbacks)
	return &t, nil
}

func (p *PostgresRepository) CreateTeam(ctx context.Context, team *domain.Team) error {
	if team.ID == "" {
		team.ID = uuid.NewString()
	}
	team.BudgetResetPeriod, team.BudgetResetAt = resolveBudgetResetSchedule(team.BudgetResetPeriod, team.BudgetResetAt, time.Now().UTC())
	allowedModels := team.AllowedModels
	if allowedModels == nil {
		allowedModels = []string{}
	}
	defaultMemberAllowedModels := team.DefaultMemberAllowedModels
	if defaultMemberAllowedModels == nil {
		defaultMemberAllowedModels = []string{}
	}
	teamMemberPermissions := team.TeamMemberPermissions
	if teamMemberPermissions == nil {
		teamMemberPermissions = []string{}
	}
	allowedRoutingTags := team.AllowedRoutingTags
	if allowedRoutingTags == nil {
		allowedRoutingTags = []string{}
	}
	if p.pool == nil {
		return p.mem.CreateTeam(ctx, team)
	}
	const q = `
		INSERT INTO teams (
			id, org_id, name, max_budget_micros, temp_budget_increase_micros, temp_budget_expires_at, soft_budget_micros, throttle_on_budget_exceeded, budget_fallbacks, spent_micros, budget_reset_period, budget_reset_at,
			rpm_limit, tpm_limit, mcp_rpm_limit, max_concurrent_requests, batch_enqueued_token_limit, max_iterations, max_budget_per_session_micros,
			enforce_guaranteed_throughput, default_member_max_budget_micros, default_member_rpm_limit, default_member_tpm_limit, default_member_allowed_models, team_member_permissions,
			allowed_models, allowed_mcp_servers, allowed_a2a_agents, allowed_client_apps, min_priority_rank, allowed_routing_tags, is_active
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26,$27,$28,$29,$30,$31,$32)`
	if _, err := p.pool.Exec(ctx, q,
		team.ID, team.OrgID, team.Name, team.MaxBudgetMicros, team.TempBudgetIncreaseMicros, team.TempBudgetExpiresAt, team.SoftBudgetMicros, team.ThrottleOnBudgetExceeded, marshalBudgetFallbacks(team.BudgetFallbacks), team.SpentMicros, string(team.BudgetResetPeriod), team.BudgetResetAt,
		team.RPMLimit, team.TPMLimit, team.MCPRPMLimit, team.MaxConcurrentRequests, team.BatchEnqueuedTokenLimit, team.MaxIterations, team.MaxBudgetPerSessionMicros,
		team.EnforceGuaranteedThroughput, team.DefaultMemberMaxBudgetMicros, team.DefaultMemberRPMLimit, team.DefaultMemberTPMLimit, defaultMemberAllowedModels, teamMemberPermissions,
		allowedModels, team.AllowedMCPServers, team.AllowedA2AAgents, team.AllowedClientApps, team.MinPriorityRank, allowedRoutingTags, team.IsActive,
	); err != nil {
		return err
	}
	return p.mem.CreateTeam(ctx, team)
}

func (p *PostgresRepository) UpdateTeam(ctx context.Context, team *domain.Team) error {
	if team == nil || team.ID == "" {
		return fmt.Errorf("team id is required")
	}
	team.BudgetResetPeriod, team.BudgetResetAt = resolveBudgetResetSchedule(team.BudgetResetPeriod, team.BudgetResetAt, time.Now().UTC())
	allowedModels := team.AllowedModels
	if allowedModels == nil {
		allowedModels = []string{}
	}
	defaultMemberAllowedModels := team.DefaultMemberAllowedModels
	if defaultMemberAllowedModels == nil {
		defaultMemberAllowedModels = []string{}
	}
	teamMemberPermissions := team.TeamMemberPermissions
	if teamMemberPermissions == nil {
		teamMemberPermissions = []string{}
	}
	allowedRoutingTags := team.AllowedRoutingTags
	if allowedRoutingTags == nil {
		allowedRoutingTags = []string{}
	}
	const q = `
		UPDATE teams SET
			name = $2, max_budget_micros = $3, temp_budget_increase_micros = $4, temp_budget_expires_at = $5,
			soft_budget_micros = $6, throttle_on_budget_exceeded = $7, budget_fallbacks = $8,
			spent_micros = $9, budget_reset_period = $10, budget_reset_at = $11,
			rpm_limit = $12, tpm_limit = $13, mcp_rpm_limit = $14, max_concurrent_requests = $15, batch_enqueued_token_limit = $16,
			max_iterations = $17, max_budget_per_session_micros = $18,
			enforce_guaranteed_throughput = $19, default_member_max_budget_micros = $20, default_member_rpm_limit = $21, default_member_tpm_limit = $22, default_member_allowed_models = $23, team_member_permissions = $24,
			allowed_models = $25, allowed_mcp_servers = $26, allowed_a2a_agents = $27, allowed_client_apps = $28, min_priority_rank = $29, allowed_routing_tags = $30, is_active = $31,
			updated_at = NOW()
		WHERE id = $1`
	if p.pool != nil {
		tag, err := p.pool.Exec(ctx, q,
			team.ID, team.Name, team.MaxBudgetMicros, team.TempBudgetIncreaseMicros, team.TempBudgetExpiresAt,
			team.SoftBudgetMicros, team.ThrottleOnBudgetExceeded, marshalBudgetFallbacks(team.BudgetFallbacks),
			team.SpentMicros, string(team.BudgetResetPeriod), team.BudgetResetAt,
			team.RPMLimit, team.TPMLimit, team.MCPRPMLimit, team.MaxConcurrentRequests, team.BatchEnqueuedTokenLimit,
			team.MaxIterations, team.MaxBudgetPerSessionMicros,
			team.EnforceGuaranteedThroughput, team.DefaultMemberMaxBudgetMicros, team.DefaultMemberRPMLimit, team.DefaultMemberTPMLimit, defaultMemberAllowedModels, teamMemberPermissions,
			allowedModels, team.AllowedMCPServers, team.AllowedA2AAgents, team.AllowedClientApps, team.MinPriorityRank, allowedRoutingTags, team.IsActive,
		)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("team %q %w", team.ID, ErrNotFound)
		}
	}
	if err := p.mem.UpdateTeam(ctx, team); err != nil {
		if p.pool == nil {
			return err
		}
		_ = p.mem.CreateTeam(ctx, team)
	}
	return nil
}

func (p *PostgresRepository) GetTeam(ctx context.Context, id string) (*domain.Team, error) {
	if p.pool == nil {
		return p.mem.GetTeam(ctx, id)
	}
	const q = `SELECT ` + teamSelectCols + ` FROM teams WHERE id = $1`
	t, err := scanTeam(p.pool.QueryRow(ctx, q, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("team %q %w", id, ErrNotFound)
		}
		return nil, err
	}
	cp := cloneTeam(t)
	_ = p.mem.CreateTeam(ctx, cp)
	return t, nil
}

func (p *PostgresRepository) GetTeamByName(ctx context.Context, orgID, name string) (*domain.Team, error) {
	orgID = strings.TrimSpace(orgID)
	name = strings.TrimSpace(name)
	if orgID == "" || name == "" {
		return nil, fmt.Errorf("team with org_id %q and name %q %w", orgID, name, ErrNotFound)
	}
	if p.pool == nil {
		return p.mem.GetTeamByName(ctx, orgID, name)
	}
	const q = `SELECT ` + teamSelectCols + ` FROM teams WHERE org_id = $1 AND name = $2 LIMIT 1`
	t, err := scanTeam(p.pool.QueryRow(ctx, q, orgID, name))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("team with org_id %q and name %q %w", orgID, name, ErrNotFound)
		}
		return nil, err
	}
	cp := cloneTeam(t)
	_ = p.mem.CreateTeam(ctx, cp)
	return t, nil
}

func (p *PostgresRepository) ListTeams(ctx context.Context, orgID string) ([]*domain.Team, error) {
	const q = `SELECT ` + teamSelectCols + ` FROM teams WHERE org_id = $1 ORDER BY created_at ASC`
	rows, err := p.pool.Query(ctx, q, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var teams []*domain.Team
	for rows.Next() {
		t, err := scanTeam(rows)
		if err != nil {
			return nil, err
		}
		teams = append(teams, t)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return teams, nil
}

func (p *PostgresRepository) DeleteTeam(ctx context.Context, id string) error {
	if p.pool != nil {
		tag, err := p.pool.Exec(ctx, `DELETE FROM teams WHERE id = $1`, id)
		if err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23503" {
				if hasPTU, checkErr := p.HasTeamPTUShares(ctx, id); checkErr == nil && hasPTU {
					return fmt.Errorf("team %q cannot be deleted while it holds active PTU shares: %w", id, ErrTeamHasActivePTUShares)
				}
			}
			return err
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("team %q %w", id, ErrNotFound)
		}
		_ = p.mem.DeleteTeam(ctx, id)
		return nil
	}
	return p.mem.DeleteTeam(ctx, id)
}

const teamMembershipSelectCols = `id, org_id, team_id, user_id, role, max_budget_micros, spent_micros, rpm_limit, tpm_limit, COALESCE(allowed_models, '{}'), created_at, updated_at`

func scanTeamMembership(row rowScanner) (*domain.TeamMembership, error) {
	var m domain.TeamMembership
	var role string
	if err := row.Scan(
		&m.ID, &m.OrgID, &m.TeamID, &m.UserID, &role,
		&m.MaxBudgetMicros, &m.SpentMicros, &m.RPMLimit, &m.TPMLimit,
		&m.AllowedModels, &m.CreatedAt, &m.UpdatedAt,
	); err != nil {
		return nil, err
	}
	m.Role = domain.Role(role)
	if m.AllowedModels == nil {
		m.AllowedModels = []string{}
	}
	return &m, nil
}

func (p *PostgresRepository) UpsertTeamMembership(ctx context.Context, m *domain.TeamMembership) error {
	if err := normalizeTeamMembership(m); err != nil {
		return err
	}
	if p.pool == nil {
		return p.mem.UpsertTeamMembership(ctx, m)
	}
	if m.ID == "" {
		m.ID = uuid.NewString()
	}
	const q = `
		INSERT INTO team_memberships (
			id, org_id, team_id, user_id, role,
			max_budget_micros, spent_micros, rpm_limit, tpm_limit, allowed_models
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (team_id, user_id) DO UPDATE SET
			org_id = EXCLUDED.org_id,
			role = EXCLUDED.role,
			max_budget_micros = EXCLUDED.max_budget_micros,
			spent_micros = GREATEST(team_memberships.spent_micros, EXCLUDED.spent_micros),
			rpm_limit = EXCLUDED.rpm_limit,
			tpm_limit = EXCLUDED.tpm_limit,
			allowed_models = EXCLUDED.allowed_models,
			updated_at = NOW()
		RETURNING id, spent_micros, created_at, updated_at`
	if err := p.pool.QueryRow(ctx, q,
		m.ID, m.OrgID, m.TeamID, m.UserID, string(m.Role),
		m.MaxBudgetMicros, m.SpentMicros, m.RPMLimit, m.TPMLimit, m.AllowedModels,
	).Scan(&m.ID, &m.SpentMicros, &m.CreatedAt, &m.UpdatedAt); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return fmt.Errorf("team membership conflict: %w", ErrConflict)
		}
		return err
	}
	_ = p.mem.UpsertTeamMembership(ctx, m)
	return nil
}

func (p *PostgresRepository) GetTeamMembership(ctx context.Context, teamID, userID string) (*domain.TeamMembership, error) {
	if p.pool == nil {
		return p.mem.GetTeamMembership(ctx, teamID, userID)
	}
	m, err := scanTeamMembership(p.pool.QueryRow(ctx,
		`SELECT `+teamMembershipSelectCols+` FROM team_memberships WHERE team_id = $1 AND user_id = $2`,
		strings.TrimSpace(teamID), strings.TrimSpace(userID),
	))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("team membership (%q, %q) %w", teamID, userID, ErrNotFound)
		}
		return nil, err
	}
	return m, nil
}

func (p *PostgresRepository) ListTeamMemberships(ctx context.Context, orgID, teamID, userID string) ([]*domain.TeamMembership, error) {
	if p.pool == nil {
		return p.mem.ListTeamMemberships(ctx, orgID, teamID, userID)
	}
	var conds []string
	var args []any
	addCond := func(col, val string) {
		if v := strings.TrimSpace(val); v != "" {
			args = append(args, v)
			conds = append(conds, fmt.Sprintf("%s = $%d", col, len(args)))
		}
	}
	addCond("org_id", orgID)
	addCond("team_id", teamID)
	addCond("user_id", userID)

	q := `SELECT ` + teamMembershipSelectCols + ` FROM team_memberships`
	if len(conds) > 0 {
		q += ` WHERE ` + strings.Join(conds, " AND ")
	}
	q += ` ORDER BY created_at ASC, id ASC`

	rows, err := p.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*domain.TeamMembership
	for rows.Next() {
		m, scanErr := scanTeamMembership(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (p *PostgresRepository) DeleteTeamMembership(ctx context.Context, teamID, userID string) error {
	if p.pool == nil {
		return p.mem.DeleteTeamMembership(ctx, teamID, userID)
	}
	tag, err := p.pool.Exec(ctx,
		`DELETE FROM team_memberships WHERE team_id = $1 AND user_id = $2`,
		strings.TrimSpace(teamID), strings.TrimSpace(userID),
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("team membership (%q, %q) %w", teamID, userID, ErrNotFound)
	}
	_ = p.mem.DeleteTeamMembership(ctx, teamID, userID)
	return nil
}

func (p *PostgresRepository) BulkSyncTeamMemberships(ctx context.Context, orgID, teamID string, upserts []*domain.TeamMembership, removeUserIDs []string) ([]*domain.TeamMembership, int, error) {
	if p.pool == nil {
		return p.mem.BulkSyncTeamMemberships(ctx, orgID, teamID, upserts, removeUserIDs)
	}
	orgID = strings.TrimSpace(orgID)
	teamID = strings.TrimSpace(teamID)

	tx, err := p.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	const upsertQ = `
		INSERT INTO team_memberships (
			id, org_id, team_id, user_id, role,
			max_budget_micros, spent_micros, rpm_limit, tpm_limit, allowed_models
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		ON CONFLICT (team_id, user_id) DO UPDATE SET
			org_id = EXCLUDED.org_id,
			role = EXCLUDED.role,
			max_budget_micros = EXCLUDED.max_budget_micros,
			spent_micros = GREATEST(team_memberships.spent_micros, EXCLUDED.spent_micros),
			rpm_limit = EXCLUDED.rpm_limit,
			tpm_limit = EXCLUDED.tpm_limit,
			allowed_models = EXCLUDED.allowed_models,
			updated_at = NOW()
		RETURNING id, spent_micros, created_at, updated_at`

	results := make([]*domain.TeamMembership, 0, len(upserts))
	for _, entry := range upserts {
		if entry == nil {
			continue
		}
		cp := *entry
		cp.OrgID = orgID
		cp.TeamID = teamID
		if err := normalizeTeamMembership(&cp); err != nil {
			return nil, 0, err
		}
		if cp.ID == "" {
			cp.ID = uuid.NewString()
		}
		if err := tx.QueryRow(ctx, upsertQ,
			cp.ID, cp.OrgID, cp.TeamID, cp.UserID, string(cp.Role),
			cp.MaxBudgetMicros, cp.SpentMicros, cp.RPMLimit, cp.TPMLimit, cp.AllowedModels,
		).Scan(&cp.ID, &cp.SpentMicros, &cp.CreatedAt, &cp.UpdatedAt); err != nil {
			var pgErr *pgconn.PgError
			if errors.As(err, &pgErr) && pgErr.Code == "23505" {
				return nil, 0, fmt.Errorf("team membership conflict: %w", ErrConflict)
			}
			return nil, 0, err
		}
		results = append(results, &cp)
	}

	cleanedRemovals := make([]string, 0, len(removeUserIDs))
	for _, rawUID := range removeUserIDs {
		if uid := strings.TrimSpace(rawUID); uid != "" {
			cleanedRemovals = append(cleanedRemovals, uid)
		}
	}
	var removed int
	if len(cleanedRemovals) > 0 {
		tag, err := tx.Exec(ctx, `DELETE FROM team_memberships WHERE team_id = $1 AND user_id = ANY($2)`, teamID, cleanedRemovals)
		if err != nil {
			return nil, 0, err
		}
		removed = int(tag.RowsAffected())
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, 0, err
	}
	_, _, _ = p.mem.BulkSyncTeamMemberships(ctx, orgID, teamID, results, cleanedRemovals)
	return results, removed, nil
}

func (p *PostgresRepository) RotateKEKsTransactionally(ctx context.Context, rewrap func(batch KEKRotationBatch) (KEKRotationBatch, error)) (KEKRotationSummary, error) {
	if p.pool == nil {
		return p.mem.RotateKEKsTransactionally(ctx, rewrap)
	}
	var summary KEKRotationSummary
	if rewrap == nil {
		return summary, fmt.Errorf("rewrap callback is required")
	}

	tx, err := p.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return summary, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var batch KEKRotationBatch

	credRows, err := tx.Query(ctx, `SELECT `+providerCredentialSelectCols+` FROM provider_credentials WHERE length(encrypted_dek) > 0 ORDER BY id ASC FOR UPDATE`)
	if err != nil {
		return summary, err
	}
	for credRows.Next() {
		c, sErr := scanProviderCredential(credRows)
		if sErr != nil {
			credRows.Close()
			return summary, sErr
		}
		batch.Credentials = append(batch.Credentials, c)
	}
	if rErr := credRows.Err(); rErr != nil {
		credRows.Close()
		return summary, rErr
	}
	credRows.Close()

	mcpRows, err := tx.Query(ctx, `
		SELECT id, org_id, name, slug, protocol_version, transport_type, endpoint_url,
		       config_version, auth_type, encrypted_auth_secret, encrypted_auth_dek,
		       static_headers, oauth2_endpoint, oauth2_client_id, oauth2_scopes,
		       pinned_tool_hash, rpm_limit, is_active, created_at, updated_at
		FROM mcp_servers WHERE encrypted_auth_dek <> '' ORDER BY id ASC FOR UPDATE`)
	if err != nil {
		return summary, err
	}
	for mcpRows.Next() {
		var s domain.MCPServer
		var headersJSON []byte
		if sErr := mcpRows.Scan(
			&s.ID, &s.OrgID, &s.Name, &s.Slug, &s.ProtocolVersion, &s.TransportType, &s.EndpointURL,
			&s.ConfigVersion, &s.AuthType, &s.EncryptedAuthSecret, &s.EncryptedAuthDEK,
			&headersJSON, &s.OAuth2Endpoint, &s.OAuth2ClientID, &s.OAuth2Scopes,
			&s.PinnedToolHash, &s.RPMLimit, &s.IsActive, &s.CreatedAt, &s.UpdatedAt,
		); sErr != nil {
			mcpRows.Close()
			return summary, sErr
		}
		if len(headersJSON) > 0 {
			_ = json.Unmarshal(headersJSON, &s.StaticHeaders)
		}
		batch.MCPServers = append(batch.MCPServers, &s)
	}
	if rErr := mcpRows.Err(); rErr != nil {
		mcpRows.Close()
		return summary, rErr
	}
	mcpRows.Close()

	a2aRows, err := tx.Query(ctx, `
		SELECT id, org_id, name, slug, endpoint_url, agent_card_url, agent_card_json,
		       task_visibility_mode, auth_type, encrypted_auth_secret, encrypted_auth_dek,
		       max_task_iterations, max_task_budget_micros, is_active, is_killed,
		       created_at, updated_at
		FROM a2a_agents WHERE encrypted_auth_dek <> '' ORDER BY id ASC FOR UPDATE`)
	if err != nil {
		return summary, err
	}
	for a2aRows.Next() {
		var a domain.A2AAgent
		if sErr := a2aRows.Scan(
			&a.ID, &a.OrgID, &a.Name, &a.Slug, &a.EndpointURL, &a.AgentCardURL, &a.AgentCardJSON,
			&a.TaskVisibilityMode, &a.AuthType, &a.EncryptedAuthSecret, &a.EncryptedAuthDEK,
			&a.MaxTaskIterations, &a.MaxTaskBudgetMicros, &a.IsActive, &a.IsKilled,
			&a.CreatedAt, &a.UpdatedAt,
		); sErr != nil {
			a2aRows.Close()
			return summary, sErr
		}
		batch.A2AAgents = append(batch.A2AAgents, &a)
	}
	if rErr := a2aRows.Err(); rErr != nil {
		a2aRows.Close()
		return summary, rErr
	}
	a2aRows.Close()

	grRows, err := tx.Query(ctx, `SELECT `+guardrailDefinitionSelectCols+` FROM guardrail_definitions WHERE encrypted_dek <> '' ORDER BY id ASC FOR UPDATE`)
	if err != nil {
		return summary, err
	}
	for grRows.Next() {
		gd, sErr := scanGuardrailDefinition(grRows)
		if sErr != nil {
			grRows.Close()
			return summary, sErr
		}
		batch.Guardrails = append(batch.Guardrails, gd)
	}
	if rErr := grRows.Err(); rErr != nil {
		grRows.Close()
		return summary, rErr
	}
	grRows.Close()

	vkRows, err := tx.Query(ctx, `SELECT `+virtualKeySelectCols+` FROM virtual_keys WHERE COALESCE(staged_key_dek, '') <> '' ORDER BY id ASC FOR UPDATE`)
	if err != nil {
		return summary, err
	}
	for vkRows.Next() {
		vk, sErr := scanVirtualKey(vkRows)
		if sErr != nil {
			vkRows.Close()
			return summary, sErr
		}
		batch.StagedVirtualKeys = append(batch.StagedVirtualKeys, vk)
	}
	if rErr := vkRows.Err(); rErr != nil {
		vkRows.Close()
		return summary, rErr
	}
	vkRows.Close()

	updated, err := rewrap(batch)
	if err != nil {
		return summary, err
	}

	for _, c := range updated.Credentials {
		if c == nil || c.ID == "" {
			continue
		}
		kv := c.KeyVersion
		if kv <= 0 {
			kv = 1
		}
		if _, err := tx.Exec(ctx, `
			UPDATE provider_credentials
			SET encrypted_dek = $2, dek_nonce = $3, key_version = $4, last_rotated_at = $5, updated_at = NOW()
			WHERE id = $1`,
			c.ID, c.EncryptedDEK, c.DEKNonce, kv, c.LastRotatedAt,
		); err != nil {
			return summary, err
		}
		summary.CredentialsRewrapped++
	}
	for _, s := range updated.MCPServers {
		if s == nil || s.ID == "" {
			continue
		}
		if _, err := tx.Exec(ctx, `
			UPDATE mcp_servers
			SET encrypted_auth_dek = $2, config_version = config_version + 1, updated_at = NOW()
			WHERE id = $1`,
			s.ID, s.EncryptedAuthDEK,
		); err != nil {
			return summary, err
		}
		summary.MCPServersRewrapped++
	}
	for _, a := range updated.A2AAgents {
		if a == nil || a.ID == "" {
			continue
		}
		if _, err := tx.Exec(ctx, `
			UPDATE a2a_agents
			SET encrypted_auth_dek = $2, updated_at = NOW()
			WHERE id = $1`,
			a.ID, a.EncryptedAuthDEK,
		); err != nil {
			return summary, err
		}
		summary.A2AAgentsRewrapped++
	}
	for _, g := range updated.Guardrails {
		if g == nil || g.ID == "" {
			continue
		}
		if _, err := tx.Exec(ctx, `
			UPDATE guardrail_definitions
			SET encrypted_dek = $2, updated_at = NOW()
			WHERE id = $1`,
			g.ID, g.EncryptedDEK,
		); err != nil {
			return summary, err
		}
		summary.GuardrailsRewrapped++
	}
	for _, vk := range updated.StagedVirtualKeys {
		if vk == nil || vk.ID == "" {
			continue
		}
		if _, err := tx.Exec(ctx, `
			UPDATE virtual_keys
			SET staged_key_dek = $2, updated_at = NOW()
			WHERE id = $1`,
			vk.ID, vk.StagedKeyDEK,
		); err != nil {
			return summary, err
		}
		summary.StagedVirtualKeysRewrapped++
	}

	if err := tx.Commit(ctx); err != nil {
		return summary, err
	}
	for _, vk := range updated.StagedVirtualKeys {
		if vk != nil {
			_ = p.mem.UpdateVirtualKey(ctx, vk)
		}
	}
	for _, c := range updated.Credentials {
		if c != nil {
			if err := p.mem.UpdateProviderCredential(ctx, c); err != nil {
				_ = p.mem.CreateProviderCredential(ctx, c)
			}
		}
	}
	for _, s := range updated.MCPServers {
		if s != nil {
			if err := p.mem.UpdateMCPServer(ctx, s); err != nil {
				_ = p.mem.CreateMCPServer(ctx, s)
			}
		}
	}
	for _, a := range updated.A2AAgents {
		if a != nil {
			if err := p.mem.UpdateA2AAgent(ctx, a); err != nil {
				_ = p.mem.CreateA2AAgent(ctx, a)
			}
		}
	}
	for _, g := range updated.Guardrails {
		if g != nil {
			if err := p.mem.UpdateGuardrailDefinition(ctx, g); err != nil {
				_ = p.mem.CreateGuardrailDefinition(ctx, g)
			}
		}
	}
	return summary, nil
}

const projectSelectCols = `id, org_id, team_id, name, description, max_budget_micros, spent_micros, rpm_limit, tpm_limit, COALESCE(allowed_models, '{}'), enforce_project_model_quota, is_active, created_at, updated_at`

func scanProject(row rowScanner) (*domain.Project, error) {
	var pr domain.Project
	if err := row.Scan(
		&pr.ID, &pr.OrgID, &pr.TeamID, &pr.Name, &pr.Description,
		&pr.MaxBudgetMicros, &pr.SpentMicros, &pr.RPMLimit, &pr.TPMLimit,
		&pr.AllowedModels, &pr.EnforceProjectModelQuota, &pr.IsActive,
		&pr.CreatedAt, &pr.UpdatedAt,
	); err != nil {
		return nil, err
	}
	if pr.AllowedModels == nil {
		pr.AllowedModels = []string{}
	}
	return &pr, nil
}

func (p *PostgresRepository) CreateProject(ctx context.Context, pr *domain.Project) error {
	if err := normalizeProject(pr); err != nil {
		return err
	}
	if p.pool == nil {
		return p.mem.CreateProject(ctx, pr)
	}
	if pr.ID == "" {
		pr.ID = uuid.NewString()
	}
	const q = `
		INSERT INTO projects (
			id, org_id, team_id, name, description,
			max_budget_micros, spent_micros, rpm_limit, tpm_limit,
			allowed_models, enforce_project_model_quota, is_active
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
		RETURNING created_at, updated_at`
	if err := p.pool.QueryRow(ctx, q,
		pr.ID, pr.OrgID, pr.TeamID, pr.Name, pr.Description,
		pr.MaxBudgetMicros, pr.SpentMicros, pr.RPMLimit, pr.TPMLimit,
		pr.AllowedModels, pr.EnforceProjectModelQuota, pr.IsActive,
	).Scan(&pr.CreatedAt, &pr.UpdatedAt); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return fmt.Errorf("project already exists: %w", ErrConflict)
		}
		return err
	}
	_ = p.mem.CreateProject(ctx, pr)
	return nil
}

func (p *PostgresRepository) GetProject(ctx context.Context, id string) (*domain.Project, error) {
	if p.pool == nil {
		return p.mem.GetProject(ctx, id)
	}
	pr, err := scanProject(p.pool.QueryRow(ctx,
		`SELECT `+projectSelectCols+` FROM projects WHERE id = $1`,
		strings.TrimSpace(id),
	))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("project %q %w", id, ErrNotFound)
		}
		return nil, err
	}
	return pr, nil
}

func (p *PostgresRepository) ListProjects(ctx context.Context, orgID, teamID string) ([]*domain.Project, error) {
	if p.pool == nil {
		return p.mem.ListProjects(ctx, orgID, teamID)
	}
	var conds []string
	var args []any
	addCond := func(col, val string) {
		if v := strings.TrimSpace(val); v != "" {
			args = append(args, v)
			conds = append(conds, fmt.Sprintf("%s = $%d", col, len(args)))
		}
	}
	addCond("org_id", orgID)
	addCond("team_id", teamID)

	q := `SELECT ` + projectSelectCols + ` FROM projects`
	if len(conds) > 0 {
		q += ` WHERE ` + strings.Join(conds, " AND ")
	}
	q += ` ORDER BY created_at ASC, id ASC`

	rows, err := p.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*domain.Project
	for rows.Next() {
		pr, scanErr := scanProject(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, pr)
	}
	return out, rows.Err()
}

func (p *PostgresRepository) UpdateProject(ctx context.Context, pr *domain.Project) error {
	if err := normalizeProject(pr); err != nil {
		return err
	}
	if pr.ID == "" {
		return fmt.Errorf("project id is required")
	}
	if p.pool == nil {
		return p.mem.UpdateProject(ctx, pr)
	}
	const q = `
		UPDATE projects SET
			team_id = $2,
			name = $3,
			description = $4,
			max_budget_micros = $5,
			spent_micros = $6,
			rpm_limit = $7,
			tpm_limit = $8,
			allowed_models = $9,
			enforce_project_model_quota = $10,
			is_active = $11,
			updated_at = NOW()
		WHERE id = $1
		RETURNING created_at, updated_at`
	if err := p.pool.QueryRow(ctx, q,
		pr.ID, pr.TeamID, pr.Name, pr.Description,
		pr.MaxBudgetMicros, pr.SpentMicros, pr.RPMLimit, pr.TPMLimit,
		pr.AllowedModels, pr.EnforceProjectModelQuota, pr.IsActive,
	).Scan(&pr.CreatedAt, &pr.UpdatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("project %q %w", pr.ID, ErrNotFound)
		}
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return fmt.Errorf("project conflict: %w", ErrConflict)
		}
		return err
	}
	if err := p.mem.UpdateProject(ctx, pr); err != nil {
		_ = p.mem.CreateProject(ctx, pr)
	}
	return nil
}

func (p *PostgresRepository) DeleteProject(ctx context.Context, id string) error {
	if p.pool == nil {
		return p.mem.DeleteProject(ctx, id)
	}
	tag, err := p.pool.Exec(ctx, `DELETE FROM projects WHERE id = $1`, strings.TrimSpace(id))
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("project %q %w", id, ErrNotFound)
	}
	_ = p.mem.DeleteProject(ctx, id)
	return nil
}

const userSelectCols = `id, org_id, COALESCE(team_id, ''), email, name, role, COALESCE(oidc_subject, ''), oidc_issuer, COALESCE(scim_external_id, ''), scim_active, max_budget_micros, temp_budget_increase_micros, temp_budget_expires_at, soft_budget_micros, throttle_on_budget_exceeded, COALESCE(budget_fallbacks, '{}'::jsonb), spent_micros, budget_reset_period, budget_reset_at, rpm_limit, tpm_limit, max_concurrent_requests, batch_enqueued_token_limit, is_active, created_at, updated_at`

func scanUser(row rowScanner) (*domain.User, error) {
	var u domain.User
	var role, period string
	var rawFallbacks []byte
	if err := row.Scan(
		&u.ID, &u.OrgID, &u.TeamID, &u.Email, &u.Name, &role, &u.OIDCSubject, &u.OIDCIssuer, &u.SCIMExternalID, &u.SCIMActive,
		&u.MaxBudgetMicros, &u.TempBudgetIncreaseMicros, &u.TempBudgetExpiresAt, &u.SoftBudgetMicros, &u.ThrottleOnBudgetExceeded, &rawFallbacks, &u.SpentMicros, &period, &u.BudgetResetAt,
		&u.RPMLimit, &u.TPMLimit, &u.MaxConcurrentRequests, &u.BatchEnqueuedTokenLimit, &u.IsActive, &u.CreatedAt, &u.UpdatedAt,
	); err != nil {
		return nil, err
	}
	u.Role = domain.Role(role)
	u.BudgetResetPeriod = domain.BudgetResetPeriod(period)
	u.BudgetFallbacks = unmarshalBudgetFallbacks(rawFallbacks)
	return &u, nil
}

func (p *PostgresRepository) CreateUser(ctx context.Context, user *domain.User) error {
	if user.ID == "" {
		user.ID = uuid.NewString()
	}
	if user.IsActive && strings.TrimSpace(user.SCIMExternalID) == "" {
		user.SCIMActive = true
	}
	user.BudgetResetPeriod, user.BudgetResetAt = resolveBudgetResetSchedule(user.BudgetResetPeriod, user.BudgetResetAt, time.Now().UTC())
	if p.pool == nil {
		return p.mem.CreateUser(ctx, user)
	}
	const q = `
		INSERT INTO users (
			id, org_id, team_id, email, name, role, oidc_subject, oidc_issuer, scim_external_id, scim_active,
			max_budget_micros, temp_budget_increase_micros, temp_budget_expires_at, soft_budget_micros, throttle_on_budget_exceeded, budget_fallbacks, spent_micros, budget_reset_period, budget_reset_at,
			rpm_limit, tpm_limit, max_concurrent_requests, batch_enqueued_token_limit, is_active
		) VALUES ($1,$2,NULLIF($3,''),$4,$5,$6,NULLIF($7,''),$8,NULLIF($9,''),$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24)`
	if _, err := p.pool.Exec(ctx, q,
		user.ID, user.OrgID, user.TeamID, user.Email, user.Name, string(user.Role), user.OIDCSubject, user.OIDCIssuer, user.SCIMExternalID, user.SCIMActive,
		user.MaxBudgetMicros, user.TempBudgetIncreaseMicros, user.TempBudgetExpiresAt, user.SoftBudgetMicros, user.ThrottleOnBudgetExceeded, marshalBudgetFallbacks(user.BudgetFallbacks), user.SpentMicros, string(user.BudgetResetPeriod), user.BudgetResetAt,
		user.RPMLimit, user.TPMLimit, user.MaxConcurrentRequests, user.BatchEnqueuedTokenLimit, user.IsActive,
	); err != nil {
		return err
	}
	return p.mem.CreateUser(ctx, user)
}

func (p *PostgresRepository) UpdateUser(ctx context.Context, user *domain.User) error {
	if user == nil || user.ID == "" {
		return fmt.Errorf("user id is required")
	}
	user.BudgetResetPeriod, user.BudgetResetAt = resolveBudgetResetSchedule(user.BudgetResetPeriod, user.BudgetResetAt, time.Now().UTC())
	const q = `
		UPDATE users SET
			team_id = NULLIF($2,''), email = $3, name = $4, role = $5, oidc_subject = NULLIF($6,''), oidc_issuer = $7,
			scim_external_id = NULLIF($8,''), scim_active = $9,
			max_budget_micros = $10, temp_budget_increase_micros = $11, temp_budget_expires_at = $12,
			soft_budget_micros = $13, throttle_on_budget_exceeded = $14, budget_fallbacks = $15,
			spent_micros = $16, budget_reset_period = $17, budget_reset_at = $18,
			rpm_limit = $19, tpm_limit = $20, max_concurrent_requests = $21, batch_enqueued_token_limit = $22, is_active = $23,
			updated_at = NOW()
		WHERE id = $1`
	if p.pool != nil {
		tag, err := p.pool.Exec(ctx, q,
			user.ID, user.TeamID, user.Email, user.Name, string(user.Role), user.OIDCSubject, user.OIDCIssuer,
			user.SCIMExternalID, user.SCIMActive,
			user.MaxBudgetMicros, user.TempBudgetIncreaseMicros, user.TempBudgetExpiresAt,
			user.SoftBudgetMicros, user.ThrottleOnBudgetExceeded, marshalBudgetFallbacks(user.BudgetFallbacks),
			user.SpentMicros, string(user.BudgetResetPeriod), user.BudgetResetAt,
			user.RPMLimit, user.TPMLimit, user.MaxConcurrentRequests, user.BatchEnqueuedTokenLimit, user.IsActive,
		)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("user %q %w", user.ID, ErrNotFound)
		}
	}
	if err := p.mem.UpdateUser(ctx, user); err != nil {
		if p.pool == nil {
			return err
		}
		_ = p.mem.CreateUser(ctx, user)
	}
	return nil
}

func (p *PostgresRepository) GetUser(ctx context.Context, id string) (*domain.User, error) {
	if u, err := p.mem.GetUser(ctx, id); err == nil && u != nil {
		return u, nil
	}
	u, err := scanUser(p.pool.QueryRow(ctx, `SELECT `+userSelectCols+` FROM users WHERE id = $1`, id))
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}
	_ = p.mem.CreateUser(ctx, u)
	return u, nil
}

func (p *PostgresRepository) GetUserByOIDCSubject(ctx context.Context, subject string) (*domain.User, error) {
	if subject == "" {
		return nil, fmt.Errorf("user with oidc_subject %q not found", subject)
	}
	u, err := scanUser(p.pool.QueryRow(ctx, `SELECT `+userSelectCols+` FROM users WHERE oidc_subject = $1 LIMIT 1`, subject))
	if err != nil {
		return p.mem.GetUserByOIDCSubject(ctx, subject)
	}
	return u, nil
}

func (p *PostgresRepository) ListUsers(ctx context.Context, orgID string) ([]*domain.User, error) {
	rows, err := p.pool.Query(ctx, `SELECT `+userSelectCols+` FROM users WHERE org_id = $1 ORDER BY created_at ASC`, orgID)
	if err != nil {
		return p.mem.ListUsers(ctx, orgID)
	}
	defer rows.Close()

	var users []*domain.User
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	if len(users) == 0 {
		return p.mem.ListUsers(ctx, orgID)
	}
	return users, rows.Err()
}

func (p *PostgresRepository) DeleteUser(ctx context.Context, id string) error {
	if p.pool != nil {
		tag, err := p.pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, id)
		if err != nil {
			return err
		}
		if tag.RowsAffected() == 0 {
			return fmt.Errorf("user %q %w", id, ErrNotFound)
		}
	}
	if err := p.mem.DeleteUser(ctx, id); err != nil && p.pool == nil {
		return err
	}
	return nil
}

func (p *PostgresRepository) GetUserByOrgAndOIDCSubject(ctx context.Context, orgID, subject string) (*domain.User, error) {
	return p.GetUserByOIDCIdentity(ctx, orgID, "", subject)
}

func (p *PostgresRepository) GetUserByOIDCIdentity(ctx context.Context, orgID, issuer, subject string) (*domain.User, error) {
	if subject == "" || (orgID == "" && issuer != "") {
		return nil, fmt.Errorf("user with org_id %q issuer %q and oidc_subject %q %w", orgID, issuer, subject, ErrNotFound)
	}
	if p.pool == nil {
		return p.mem.GetUserByOIDCIdentity(ctx, orgID, issuer, subject)
	}
	query := `SELECT ` + userSelectCols + ` FROM users WHERE oidc_subject = $1 AND oidc_issuer = $2`
	args := []any{subject, issuer}
	if orgID != "" {
		query += ` AND org_id = $3`
		args = append(args, orgID)
	}
	rows, err := p.pool.Query(ctx, query+` LIMIT 2`, args...)
	if err != nil {
		return nil, err
	}
	users, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (*domain.User, error) { return scanUser(row) })
	if err != nil {
		return nil, err
	}
	switch len(users) {
	case 0:
		return nil, fmt.Errorf("user with org_id %q issuer %q and oidc_subject %q %w", orgID, issuer, subject, ErrNotFound)
	case 1:
		return users[0], nil
	default:
		return nil, fmt.Errorf("multiple users share oidc identity: %w", ErrConflict)
	}
}

func (p *PostgresRepository) GetUserByEmail(ctx context.Context, email string) (*domain.User, error) {
	email = strings.TrimSpace(email)
	if email == "" {
		return nil, fmt.Errorf("user with email %q %w", email, ErrNotFound)
	}
	if p.pool == nil {
		return p.mem.GetUserByEmail(ctx, email)
	}
	u, err := scanUser(p.pool.QueryRow(ctx, `SELECT `+userSelectCols+` FROM users WHERE LOWER(email) = LOWER($1) LIMIT 1`, email))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("user with email %q %w", email, ErrNotFound)
		}
		return nil, err
	}
	_ = p.mem.CreateUser(ctx, u)
	return u, nil
}

func (p *PostgresRepository) GetUserBySCIMExternalID(ctx context.Context, orgID, externalID string) (*domain.User, error) {
	orgID = strings.TrimSpace(orgID)
	externalID = strings.TrimSpace(externalID)
	if orgID == "" || externalID == "" {
		return nil, fmt.Errorf("user with org_id %q and scim_external_id %q %w", orgID, externalID, ErrNotFound)
	}
	if p.pool == nil {
		return p.mem.GetUserBySCIMExternalID(ctx, orgID, externalID)
	}
	u, err := scanUser(p.pool.QueryRow(ctx, `SELECT `+userSelectCols+` FROM users WHERE org_id = $1 AND scim_external_id = $2 LIMIT 1`, orgID, externalID))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("user with org_id %q and scim_external_id %q %w", orgID, externalID, ErrNotFound)
		}
		return nil, err
	}
	_ = p.mem.CreateUser(ctx, u)
	return u, nil
}

func (p *PostgresRepository) GetOrCreateUserByOIDCSubject(ctx context.Context, user *domain.User) (*domain.User, bool, error) {
	if user == nil || strings.TrimSpace(user.OrgID) == "" {
		return nil, false, fmt.Errorf("org_id is required to provision user")
	}
	if p.pool == nil {
		return p.mem.GetOrCreateUserByOIDCSubject(ctx, user)
	}

	cp := *user
	if cp.ID == "" {
		cp.ID = uuid.NewString()
	}
	if cp.IsActive && strings.TrimSpace(cp.SCIMExternalID) == "" {
		cp.SCIMActive = true
	}
	now := time.Now().UTC()
	cp.BudgetResetPeriod, cp.BudgetResetAt = resolveBudgetResetSchedule(cp.BudgetResetPeriod, cp.BudgetResetAt, now)

	const q = `
		INSERT INTO users (
			id, org_id, team_id, email, name, role, oidc_subject, oidc_issuer, scim_external_id, scim_active,
			max_budget_micros, soft_budget_micros, throttle_on_budget_exceeded, budget_fallbacks, spent_micros, budget_reset_period, budget_reset_at,
			rpm_limit, tpm_limit, max_concurrent_requests, batch_enqueued_token_limit, is_active
		) VALUES ($1,$2,NULLIF($3,''),$4,$5,$6,NULLIF($7,''),$8,NULLIF($9,''),$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22)
		ON CONFLICT DO NOTHING`
	tag, err := p.pool.Exec(ctx, q,
		cp.ID, cp.OrgID, cp.TeamID, cp.Email, cp.Name, string(cp.Role), cp.OIDCSubject, cp.OIDCIssuer, cp.SCIMExternalID, cp.SCIMActive,
		cp.MaxBudgetMicros, cp.SoftBudgetMicros, cp.ThrottleOnBudgetExceeded, marshalBudgetFallbacks(cp.BudgetFallbacks), cp.SpentMicros, string(cp.BudgetResetPeriod), cp.BudgetResetAt,
		cp.RPMLimit, cp.TPMLimit, cp.MaxConcurrentRequests, cp.BatchEnqueuedTokenLimit, cp.IsActive,
	)
	if err != nil {
		return nil, false, err
	}
	if tag.RowsAffected() > 0 {
		created, getErr := p.GetUser(ctx, cp.ID)
		if getErr == nil && created != nil {
			return created, true, nil
		}
		_ = p.mem.CreateUser(ctx, &cp)
		return &cp, true, nil
	}

	// Concurrent creation or pre-existing user: re-read deterministically by (org_id, oidc_issuer, oidc_subject), then email.
	if cp.OIDCSubject != "" {
		existing, err := p.GetUserByOIDCIdentity(ctx, cp.OrgID, cp.OIDCIssuer, cp.OIDCSubject)
		if err == nil && existing != nil {
			return existing, false, nil
		}
		if err != nil && !errors.Is(err, ErrNotFound) {
			return nil, false, err
		}
	}
	if cp.Email != "" {
		existing, err := p.GetUserByEmail(ctx, cp.Email)
		if err == nil && existing != nil {
			if existing.OrgID != cp.OrgID {
				return nil, false, fmt.Errorf("email %q already belongs to another organization: %w", cp.Email, ErrConflict)
			}
			if existing.OIDCIssuer != "" || cp.OIDCIssuer != "" || (existing.OIDCSubject != "" && cp.OIDCSubject != "" && existing.OIDCSubject != cp.OIDCSubject) {
				return nil, false, fmt.Errorf("email %q is bound to another OIDC identity: %w", cp.Email, ErrConflict)
			}
			return existing, false, nil
		}
		if err != nil && !errors.Is(err, ErrNotFound) {
			return nil, false, err
		}
	}
	return nil, false, fmt.Errorf("failed to resolve or provision user for org %q", cp.OrgID)
}

const jwtKeyMappingSelectCols = `id, org_id, issuer, claim_name, claim_value, virtual_key_id, created_at`

func scanJWTKeyMapping(row rowScanner) (*domain.JWTKeyMapping, error) {
	var m domain.JWTKeyMapping
	if err := row.Scan(&m.ID, &m.OrgID, &m.Issuer, &m.ClaimName, &m.ClaimValue, &m.VirtualKeyID, &m.CreatedAt); err != nil {
		return nil, err
	}
	return &m, nil
}

func (p *PostgresRepository) CreateJWTKeyMapping(ctx context.Context, mapping *domain.JWTKeyMapping) error {
	if mapping == nil {
		return fmt.Errorf("jwt key mapping is required")
	}
	if strings.TrimSpace(mapping.OrgID) == "" ||
		strings.TrimSpace(mapping.Issuer) == "" ||
		strings.TrimSpace(mapping.ClaimName) == "" ||
		strings.TrimSpace(mapping.ClaimValue) == "" ||
		strings.TrimSpace(mapping.VirtualKeyID) == "" {
		return fmt.Errorf("org_id, issuer, claim_name, claim_value, and virtual_key_id are required")
	}
	if p.pool == nil {
		return p.mem.CreateJWTKeyMapping(ctx, mapping)
	}
	if mapping.ID == "" {
		mapping.ID = uuid.NewString()
	}
	const q = `
		INSERT INTO jwt_key_mappings (id, org_id, issuer, claim_name, claim_value, virtual_key_id)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING created_at`
	if err := p.pool.QueryRow(ctx, q,
		mapping.ID, mapping.OrgID, mapping.Issuer, mapping.ClaimName, mapping.ClaimValue, mapping.VirtualKeyID,
	).Scan(&mapping.CreatedAt); err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return fmt.Errorf("jwt key mapping already exists: %w", ErrConflict)
		}
		return err
	}
	_ = p.mem.CreateJWTKeyMapping(ctx, mapping)
	return nil
}

func (p *PostgresRepository) GetJWTKeyMapping(ctx context.Context, id string) (*domain.JWTKeyMapping, error) {
	if p.pool == nil {
		return p.mem.GetJWTKeyMapping(ctx, id)
	}
	m, err := scanJWTKeyMapping(p.pool.QueryRow(ctx, `SELECT `+jwtKeyMappingSelectCols+` FROM jwt_key_mappings WHERE id = $1`, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("jwt key mapping %q %w", id, ErrNotFound)
		}
		return nil, err
	}
	return m, nil
}

func (p *PostgresRepository) ListJWTKeyMappings(ctx context.Context, orgID string) ([]*domain.JWTKeyMapping, error) {
	if p.pool == nil {
		return p.mem.ListJWTKeyMappings(ctx, orgID)
	}
	var (
		rows pgx.Rows
		err  error
	)
	if orgID != "" {
		rows, err = p.pool.Query(ctx, `SELECT `+jwtKeyMappingSelectCols+` FROM jwt_key_mappings WHERE org_id = $1 ORDER BY created_at ASC, id ASC`, orgID)
	} else {
		rows, err = p.pool.Query(ctx, `SELECT `+jwtKeyMappingSelectCols+` FROM jwt_key_mappings ORDER BY created_at ASC, id ASC`)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*domain.JWTKeyMapping
	for rows.Next() {
		m, scanErr := scanJWTKeyMapping(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func (p *PostgresRepository) DeleteJWTKeyMapping(ctx context.Context, id string) error {
	if p.pool == nil {
		return p.mem.DeleteJWTKeyMapping(ctx, id)
	}
	tag, err := p.pool.Exec(ctx, `DELETE FROM jwt_key_mappings WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("jwt key mapping %q %w", id, ErrNotFound)
	}
	_ = p.mem.DeleteJWTKeyMapping(ctx, id)
	return nil
}

func (p *PostgresRepository) ResolveJWTKeyMapping(ctx context.Context, issuer, claimName, claimValue string) (*domain.JWTKeyMapping, error) {
	if p.pool == nil {
		return p.mem.ResolveJWTKeyMapping(ctx, issuer, claimName, claimValue)
	}
	m, err := scanJWTKeyMapping(p.pool.QueryRow(ctx,
		`SELECT `+jwtKeyMappingSelectCols+` FROM jwt_key_mappings WHERE issuer = $1 AND claim_name = $2 AND claim_value = $3 LIMIT 1`,
		issuer, claimName, claimValue,
	))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("jwt key mapping %w", ErrNotFound)
		}
		return nil, err
	}
	return m, nil
}

func (p *PostgresRepository) UpsertUserPassword(ctx context.Context, userID, passwordHash string, resetRequired bool) error {
	userID = strings.TrimSpace(userID)
	passwordHash = strings.TrimSpace(passwordHash)
	if userID == "" {
		return fmt.Errorf("user_id is required")
	}
	if passwordHash == "" {
		return fmt.Errorf("password_hash is required")
	}
	if p.pool == nil {
		return p.mem.UpsertUserPassword(ctx, userID, passwordHash, resetRequired)
	}
	const q = `
		INSERT INTO user_credentials (user_id, password_hash, password_reset_required, failed_attempts, locked_until, updated_at)
		VALUES ($1, $2, $3, 0, NULL, NOW())
		ON CONFLICT (user_id) DO UPDATE SET
			password_hash = EXCLUDED.password_hash,
			password_reset_required = EXCLUDED.password_reset_required,
			failed_attempts = 0,
			locked_until = NULL,
			updated_at = NOW()`
	if _, err := p.pool.Exec(ctx, q, userID, passwordHash, resetRequired); err != nil {
		return err
	}
	if p.mem != nil {
		_ = p.mem.UpsertUserPassword(ctx, userID, passwordHash, resetRequired)
	}
	return nil
}

func (p *PostgresRepository) GetUserCredential(ctx context.Context, userID string) (*domain.UserCredential, error) {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return nil, fmt.Errorf("user credential for %q %w", userID, ErrNotFound)
	}
	if p.pool == nil {
		return p.mem.GetUserCredential(ctx, userID)
	}
	const q = `
		SELECT user_id, password_hash, password_reset_required, failed_attempts, locked_until, updated_at
		FROM user_credentials
		WHERE user_id = $1`
	var cred domain.UserCredential
	if err := p.pool.QueryRow(ctx, q, userID).Scan(
		&cred.UserID,
		&cred.PasswordHash,
		&cred.PasswordResetRequired,
		&cred.FailedAttempts,
		&cred.LockedUntil,
		&cred.UpdatedAt,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("user credential for %q %w", userID, ErrNotFound)
		}
		return nil, err
	}
	return &cred, nil
}

func (p *PostgresRepository) UpdateUserLoginFailure(ctx context.Context, userID string, failedAttempts int, lockedUntil *time.Time) error {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return fmt.Errorf("user_id is required")
	}
	if p.pool == nil {
		return p.mem.UpdateUserLoginFailure(ctx, userID, failedAttempts, lockedUntil)
	}
	const q = `
		UPDATE user_credentials
		SET failed_attempts = $2, locked_until = $3, updated_at = NOW()
		WHERE user_id = $1`
	tag, err := p.pool.Exec(ctx, q, userID, failedAttempts, lockedUntil)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("user credential for %q %w", userID, ErrNotFound)
	}
	if p.mem != nil {
		_ = p.mem.UpdateUserLoginFailure(ctx, userID, failedAttempts, lockedUntil)
	}
	return nil
}

func (p *PostgresRepository) CreateOperatorSession(ctx context.Context, session *domain.OperatorSession) error {
	if session == nil {
		return fmt.Errorf("operator session is required")
	}
	if strings.TrimSpace(session.UserID) == "" ||
		strings.TrimSpace(session.OrgID) == "" ||
		strings.TrimSpace(session.Role) == "" ||
		strings.TrimSpace(session.CSRFToken) == "" ||
		session.ExpiresAt.IsZero() {
		return fmt.Errorf("user_id, org_id, role, csrf_token, and expires_at are required")
	}
	if p.pool == nil {
		return p.mem.CreateOperatorSession(ctx, session)
	}
	if strings.TrimSpace(session.ID) == "" {
		session.ID = uuid.NewString()
	}
	if session.CreatedAt.IsZero() {
		session.CreatedAt = time.Now().UTC()
	}
	const q = `
		INSERT INTO operator_sessions (id, user_id, org_id, role, csrf_token, expires_at, revoked_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`
	if _, err := p.pool.Exec(ctx, q,
		session.ID,
		session.UserID,
		session.OrgID,
		session.Role,
		session.CSRFToken,
		session.ExpiresAt.UTC(),
		session.RevokedAt,
		session.CreatedAt.UTC(),
	); err != nil {
		return err
	}
	if p.mem != nil {
		_ = p.mem.CreateOperatorSession(ctx, session)
	}
	return nil
}

func (p *PostgresRepository) GetOperatorSession(ctx context.Context, id string) (*domain.OperatorSession, error) {
	id = strings.TrimSpace(id)
	if id == "" {
		return nil, fmt.Errorf("operator session %q %w", id, ErrNotFound)
	}
	if p.pool == nil {
		return p.mem.GetOperatorSession(ctx, id)
	}
	const q = `
		SELECT id, user_id, org_id, role, csrf_token, expires_at, revoked_at, created_at
		FROM operator_sessions
		WHERE id = $1`
	var sess domain.OperatorSession
	if err := p.pool.QueryRow(ctx, q, id).Scan(
		&sess.ID,
		&sess.UserID,
		&sess.OrgID,
		&sess.Role,
		&sess.CSRFToken,
		&sess.ExpiresAt,
		&sess.RevokedAt,
		&sess.CreatedAt,
	); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("operator session %q %w", id, ErrNotFound)
		}
		return nil, err
	}
	return &sess, nil
}

func (p *PostgresRepository) RevokeOperatorSession(ctx context.Context, id string, revokedAt time.Time) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return fmt.Errorf("operator session id is required")
	}
	if revokedAt.IsZero() {
		revokedAt = time.Now().UTC()
	} else {
		revokedAt = revokedAt.UTC()
	}
	if p.pool == nil {
		return p.mem.RevokeOperatorSession(ctx, id, revokedAt)
	}
	const q = `
		UPDATE operator_sessions
		SET revoked_at = COALESCE(revoked_at, $2)
		WHERE id = $1`
	tag, err := p.pool.Exec(ctx, q, id, revokedAt)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("operator session %q %w", id, ErrNotFound)
	}
	if p.mem != nil {
		_ = p.mem.RevokeOperatorSession(ctx, id, revokedAt)
	}
	return nil
}

func (p *PostgresRepository) RevokeAllUserSessions(ctx context.Context, userID string, revokedAt time.Time) error {
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return fmt.Errorf("user_id is required")
	}
	if revokedAt.IsZero() {
		revokedAt = time.Now().UTC()
	} else {
		revokedAt = revokedAt.UTC()
	}
	if p.pool == nil {
		return p.mem.RevokeAllUserSessions(ctx, userID, revokedAt)
	}
	const q = `
		UPDATE operator_sessions
		SET revoked_at = $2
		WHERE user_id = $1 AND revoked_at IS NULL`
	if _, err := p.pool.Exec(ctx, q, userID, revokedAt); err != nil {
		return err
	}
	if p.mem != nil {
		_ = p.mem.RevokeAllUserSessions(ctx, userID, revokedAt)
	}
	return nil
}
