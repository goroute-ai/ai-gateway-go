package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// NewPostgresPool creates a configured pgxpool.Pool for PostgreSQL 16+ persistence.
func NewPostgresPool(ctx context.Context, dsn string) (*pgxpool.Pool, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, fmt.Errorf("parse postgres dsn: %w", err)
	}
	cfg.MaxConns = 32
	cfg.MinConns = 4
	cfg.MaxConnLifetime = 30 * time.Minute
	cfg.MaxConnIdleTime = 5 * time.Minute

	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, fmt.Errorf("create postgres pool: %w", err)
	}
	pingCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := pool.Ping(pingCtx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping postgres: %w", err)
	}
	return pool, nil
}

// RunMigrations executes a single SQL schema migration file on the PostgreSQL pool.
func RunMigrations(ctx context.Context, pool *pgxpool.Pool, migrationFilePath string) error {
	sqlBytes, err := os.ReadFile(migrationFilePath)
	if err != nil {
		return fmt.Errorf("read migration file %s: %w", migrationFilePath, err)
	}
	if _, err := pool.Exec(ctx, string(sqlBytes)); err != nil {
		return fmt.Errorf("execute migration %s: %w", migrationFilePath, err)
	}
	return nil
}

// RunMigrationsDir executes all *.up.sql migration files in dir in alphabetical order.
func RunMigrationsDir(ctx context.Context, pool *pgxpool.Pool, dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read migrations dir %s: %w", dir, err)
	}
	var upFiles []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".up.sql") {
			upFiles = append(upFiles, filepath.Join(dir, e.Name()))
		}
	}
	sort.Strings(upFiles)
	for _, file := range upFiles {
		if err := RunMigrations(ctx, pool, file); err != nil {
			return err
		}
	}
	return nil
}

// PostgresRepository implements Repository backed by PostgreSQL 16+ with a synchronized write-through
// in-memory projection for ultra-fast relational joins on deployments and global models.
type PostgresRepository struct {
	pool *pgxpool.Pool
	mem  *MemoryRepository
}

func NewPostgresRepository(ctx context.Context, pool *pgxpool.Pool) (*PostgresRepository, error) {
	pr := &PostgresRepository{
		pool: pool,
		mem:  NewMemoryRepository(),
	}
	// Seed default global catalogue into PostgreSQL
	models, _ := pr.mem.ListGlobalModels(ctx)
	for _, m := range models {
		_ = pr.UpsertGlobalModel(ctx, m)
	}
	return pr, nil
}

// Ping verifies PostgreSQL database pool connectivity.
func (p *PostgresRepository) Ping(ctx context.Context) error {
	if p.pool == nil {
		return fmt.Errorf("postgres pool is uninitialized")
	}
	return p.pool.Ping(ctx)
}

func (p *PostgresRepository) UpsertGlobalModel(ctx context.Context, m *domain.GlobalModel) error {
	if err := p.mem.UpsertGlobalModel(ctx, m); err != nil {
		return err
	}
	capsJSON, _ := json.Marshal(m.ResolveCapabilities())
	if len(capsJSON) == 0 {
		capsJSON = []byte("{}")
	}
	const q = `
		INSERT INTO global_models (
			id, provider, model_name, display_name, max_input_tokens, max_output_tokens,
			supports_streaming, supports_tools, supports_vision, supports_reasoning, supports_embeddings,
			input_cost_micros_per_1m, output_cost_micros_per_1m, cached_input_cost_micros_per_1m,
			reasoning_cost_micros_per_1m, pricing_version, pricing_status, pricing_provenance_source,
			pricing_effective_date, lifecycle_status, capabilities, supports_inference, discovered_at, updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,NOW(),NOW())
		ON CONFLICT (id) DO UPDATE SET
			display_name = EXCLUDED.display_name,
			input_cost_micros_per_1m = EXCLUDED.input_cost_micros_per_1m,
			output_cost_micros_per_1m = EXCLUDED.output_cost_micros_per_1m,
			pricing_version = EXCLUDED.pricing_version,
			pricing_status = EXCLUDED.pricing_status,
			pricing_provenance_source = EXCLUDED.pricing_provenance_source,
			pricing_effective_date = EXCLUDED.pricing_effective_date,
			lifecycle_status = EXCLUDED.lifecycle_status,
			capabilities = EXCLUDED.capabilities,
			supports_inference = EXCLUDED.supports_inference,
			updated_at = NOW()`
	pv := m.PricingVersion
	if pv <= 0 {
		pv = 1
	}
	pricingStatus := string(domain.ResolvePricingStatus(m))
	_, err := p.pool.Exec(ctx, q,
		m.ID, string(m.Provider), m.ModelName, m.DisplayName, m.MaxInputTokens, m.MaxOutputTokens,
		m.SupportsStreaming, m.SupportsTools, m.SupportsVision, m.SupportsReasoning, m.SupportsEmbeddings,
		m.InputCostMicrosPer1M, m.OutputCostMicrosPer1M, m.CachedInputCostMicrosPer1M,
		m.ReasoningCostMicrosPer1M, pv, pricingStatus, m.PricingProvenanceSource,
		m.PricingEffectiveDate, string(m.LifecycleStatus), capsJSON, m.SupportsInference,
	)
	return err
}

func (p *PostgresRepository) GetGlobalModel(ctx context.Context, id string) (*domain.GlobalModel, error) {
	if gm, err := p.mem.GetGlobalModel(ctx, id); err == nil && gm != nil {
		return gm, nil
	}
	const q = `SELECT id, provider, model_name, display_name, max_input_tokens, max_output_tokens, supports_streaming, supports_tools, supports_vision, supports_reasoning, supports_embeddings, input_cost_micros_per_1m, output_cost_micros_per_1m, cached_input_cost_micros_per_1m, reasoning_cost_micros_per_1m, pricing_version, COALESCE(pricing_status, 'unknown'), COALESCE(pricing_provenance_source, ''), COALESCE(pricing_effective_date, ''), lifecycle_status, COALESCE(capabilities, '{}'::jsonb), supports_inference FROM global_models WHERE id = $1`
	var m domain.GlobalModel
	var prov, status, pricingStatus string
	var rawCaps []byte
	if err := p.pool.QueryRow(ctx, q, id).Scan(
		&m.ID, &prov, &m.ModelName, &m.DisplayName, &m.MaxInputTokens, &m.MaxOutputTokens,
		&m.SupportsStreaming, &m.SupportsTools, &m.SupportsVision, &m.SupportsReasoning, &m.SupportsEmbeddings,
		&m.InputCostMicrosPer1M, &m.OutputCostMicrosPer1M, &m.CachedInputCostMicrosPer1M,
		&m.ReasoningCostMicrosPer1M, &m.PricingVersion, &pricingStatus, &m.PricingProvenanceSource,
		&m.PricingEffectiveDate, &status, &rawCaps, &m.SupportsInference,
	); err != nil {
		return nil, fmt.Errorf("global model not found: %w", err)
	}
	m.Provider = domain.ProviderType(prov)
	m.PricingStatus = domain.PricingStatus(pricingStatus)
	m.LifecycleStatus = domain.ModelLifecycleStatus(status)
	if len(rawCaps) > 0 {
		_ = json.Unmarshal(rawCaps, &m.Capabilities)
	}
	_ = p.mem.UpsertGlobalModel(ctx, &m)
	return &m, nil
}

func (p *PostgresRepository) ListGlobalModels(ctx context.Context) ([]*domain.GlobalModel, error) {
	return p.mem.ListGlobalModels(ctx)
}

func (p *PostgresRepository) UpdateModelPricing(ctx context.Context, modelID string, inputMicros, outputMicros, cachedMicros, reasoningMicros int64, status domain.PricingStatus, provenance, effectiveDate, changedBy string) (*domain.GlobalModel, error) {
	gm, err := p.mem.UpdateModelPricing(ctx, modelID, inputMicros, outputMicros, cachedMicros, reasoningMicros, status, provenance, effectiveDate, changedBy)
	if err != nil {
		return nil, err
	}
	_, _ = p.pool.Exec(ctx, `
		UPDATE global_models SET
			pricing_version = $2,
			input_cost_micros_per_1m = $3,
			output_cost_micros_per_1m = $4,
			cached_input_cost_micros_per_1m = $5,
			reasoning_cost_micros_per_1m = $6,
			pricing_status = $7,
			pricing_provenance_source = $8,
			pricing_effective_date = $9,
			updated_at = NOW()
		WHERE id = $1`,
		gm.ID, gm.PricingVersion, gm.InputCostMicrosPer1M, gm.OutputCostMicrosPer1M, gm.CachedInputCostMicrosPer1M, gm.ReasoningCostMicrosPer1M,
		string(gm.PricingStatus), gm.PricingProvenanceSource, gm.PricingEffectiveDate,
	)
	histID := uuid.NewString()
	_, _ = p.pool.Exec(ctx, `
		INSERT INTO model_pricing_history (
			id, global_model_id, pricing_version, input_cost_micros_per_1m, output_cost_micros_per_1m,
			cached_input_cost_micros_per_1m, reasoning_cost_micros_per_1m, pricing_status, pricing_provenance_source, changed_by, effective_from
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,NOW())`,
		histID, gm.ID, gm.PricingVersion, gm.InputCostMicrosPer1M, gm.OutputCostMicrosPer1M,
		gm.CachedInputCostMicrosPer1M, gm.ReasoningCostMicrosPer1M, string(gm.PricingStatus), gm.PricingProvenanceSource, changedBy,
	)
	return gm, nil
}

func (p *PostgresRepository) ListModelPricingHistory(ctx context.Context, modelID string) ([]*domain.ModelPricingHistory, error) {
	return p.mem.ListModelPricingHistory(ctx, modelID)
}

func (p *PostgresRepository) CreateOrganization(ctx context.Context, org *domain.Organization) error {
	if org.ID == "" {
		org.ID = uuid.NewString()
	}
	const q = `
		INSERT INTO organizations (id, name, slug, max_budget_micros, spent_micros, budget_reset_period, rpm_limit, tpm_limit, is_active)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`
	if _, err := p.pool.Exec(ctx, q, org.ID, org.Name, org.Slug, org.MaxBudgetMicros, org.SpentMicros, string(org.BudgetResetPeriod), org.RPMLimit, org.TPMLimit, org.IsActive); err != nil {
		return err
	}
	return p.mem.CreateOrganization(ctx, org)
}

func (p *PostgresRepository) GetOrganization(ctx context.Context, id string) (*domain.Organization, error) {
	if org, err := p.mem.GetOrganization(ctx, id); err == nil && org != nil {
		return org, nil
	}
	const q = `SELECT id, name, slug, max_budget_micros, spent_micros, budget_reset_period, rpm_limit, tpm_limit, is_active FROM organizations WHERE id = $1`
	var o domain.Organization
	var period string
	if err := p.pool.QueryRow(ctx, q, id).Scan(
		&o.ID, &o.Name, &o.Slug, &o.MaxBudgetMicros, &o.SpentMicros, &period, &o.RPMLimit, &o.TPMLimit, &o.IsActive,
	); err != nil {
		return nil, fmt.Errorf("organization not found: %w", err)
	}
	o.BudgetResetPeriod = domain.BudgetResetPeriod(period)
	_ = p.mem.CreateOrganization(ctx, &o)
	return &o, nil
}

func (p *PostgresRepository) ListOrganizations(ctx context.Context) ([]*domain.Organization, error) {
	return p.mem.ListOrganizations(ctx)
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
	subs, err := p.mem.GetOrgProviderSubscriptions(ctx, orgID)
	if err == nil && len(subs) > 0 {
		return subs, nil
	}
	const q = `SELECT org_id, provider, is_enabled, auto_enable_new, subscribed_at FROM org_provider_subscriptions WHERE org_id = $1`
	rows, err := p.pool.Query(ctx, q, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var s domain.OrgProviderSubscription
		var prov string
		if err := rows.Scan(&s.OrgID, &prov, &s.IsEnabled, &s.AutoEnableNew, &s.SubscribedAt); err == nil {
			s.Provider = domain.ProviderType(prov)
			_ = p.mem.SetOrgProviderSubscription(ctx, &s)
		}
	}
	return p.mem.GetOrgProviderSubscriptions(ctx, orgID)
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
	pols, err := p.mem.GetOrgModelPolicies(ctx, orgID)
	if err == nil && len(pols) > 0 {
		return pols, nil
	}
	const q = `SELECT org_id, global_model_id, is_enabled, approved_by, approved_at FROM org_model_policies WHERE org_id = $1`
	rows, err := p.pool.Query(ctx, q, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var pol domain.OrgModelPolicy
		if err := rows.Scan(&pol.OrgID, &pol.GlobalModelID, &pol.IsEnabled, &pol.ApprovedBy, &pol.ApprovedAt); err == nil {
			_ = p.mem.SetOrgModelPolicy(ctx, &pol)
		}
	}
	return p.mem.GetOrgModelPolicies(ctx, orgID)
}

func (p *PostgresRepository) CreateTeam(ctx context.Context, team *domain.Team) error {
	if team.ID == "" {
		team.ID = uuid.NewString()
	}
	const q = `
		INSERT INTO teams (id, org_id, name, max_budget_micros, spent_micros, rpm_limit, tpm_limit, allowed_models, is_active)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`
	if _, err := p.pool.Exec(ctx, q, team.ID, team.OrgID, team.Name, team.MaxBudgetMicros, team.SpentMicros, team.RPMLimit, team.TPMLimit, team.AllowedModels, team.IsActive); err != nil {
		return err
	}
	return p.mem.CreateTeam(ctx, team)
}

func (p *PostgresRepository) GetTeam(ctx context.Context, id string) (*domain.Team, error) {
	row := p.pool.QueryRow(ctx, `
		SELECT id, org_id, name, max_budget_micros, spent_micros, budget_reset_period, budget_reset_at, rpm_limit, tpm_limit, allowed_models, is_active, created_at, updated_at
		FROM teams WHERE id = $1`, id)
	var t domain.Team
	var period string
	if err := row.Scan(
		&t.ID, &t.OrgID, &t.Name, &t.MaxBudgetMicros, &t.SpentMicros, &period, &t.BudgetResetAt,
		&t.RPMLimit, &t.TPMLimit, &t.AllowedModels, &t.IsActive, &t.CreatedAt, &t.UpdatedAt,
	); err != nil {
		return p.mem.GetTeam(ctx, id)
	}
	t.BudgetResetPeriod = domain.BudgetResetPeriod(period)
	_ = p.mem.CreateTeam(ctx, &t)
	return &t, nil
}

func (p *PostgresRepository) ListTeams(ctx context.Context, orgID string) ([]*domain.Team, error) {
	rows, err := p.pool.Query(ctx, `
		SELECT id, org_id, name, max_budget_micros, spent_micros, budget_reset_period, budget_reset_at, rpm_limit, tpm_limit, allowed_models, is_active, created_at, updated_at
		FROM teams WHERE org_id = $1 ORDER BY created_at ASC`, orgID)
	if err != nil {
		return p.mem.ListTeams(ctx, orgID)
	}
	defer rows.Close()

	var teams []*domain.Team
	for rows.Next() {
		var t domain.Team
		var period string
		if err := rows.Scan(
			&t.ID, &t.OrgID, &t.Name, &t.MaxBudgetMicros, &t.SpentMicros, &period, &t.BudgetResetAt,
			&t.RPMLimit, &t.TPMLimit, &t.AllowedModels, &t.IsActive, &t.CreatedAt, &t.UpdatedAt,
		); err != nil {
			return nil, err
		}
		t.BudgetResetPeriod = domain.BudgetResetPeriod(period)
		teams = append(teams, &t)
	}
	if len(teams) == 0 {
		return p.mem.ListTeams(ctx, orgID)
	}
	return teams, rows.Err()
}

func (p *PostgresRepository) CreateUser(ctx context.Context, user *domain.User) error {
	if user.ID == "" {
		user.ID = uuid.NewString()
	}
	const q = `INSERT INTO users (id, org_id, email, name, role, is_active) VALUES ($1,$2,$3,$4,$5,$6)`
	if _, err := p.pool.Exec(ctx, q, user.ID, user.OrgID, user.Email, user.Name, string(user.Role), user.IsActive); err != nil {
		return err
	}
	return p.mem.CreateUser(ctx, user)
}

func (p *PostgresRepository) ListUsers(ctx context.Context, orgID string) ([]*domain.User, error) {
	rows, err := p.pool.Query(ctx, `
		SELECT id, org_id, COALESCE(team_id, ''), email, name, role, COALESCE(oidc_subject, ''), is_active, created_at, updated_at
		FROM users WHERE org_id = $1 ORDER BY created_at ASC`, orgID)
	if err != nil {
		return p.mem.ListUsers(ctx, orgID)
	}
	defer rows.Close()

	var users []*domain.User
	for rows.Next() {
		var u domain.User
		var role string
		if err := rows.Scan(
			&u.ID, &u.OrgID, &u.TeamID, &u.Email, &u.Name, &role, &u.OIDCSubject, &u.IsActive, &u.CreatedAt, &u.UpdatedAt,
		); err != nil {
			return nil, err
		}
		u.Role = domain.Role(role)
		users = append(users, &u)
	}
	if len(users) == 0 {
		return p.mem.ListUsers(ctx, orgID)
	}
	return users, rows.Err()
}

func (p *PostgresRepository) CreateVirtualKey(ctx context.Context, vk *domain.VirtualKey) error {
	if vk.ID == "" {
		vk.ID = uuid.NewString()
	}
	if vk.AllowedModels == nil {
		vk.AllowedModels = []string{}
	}
	if vk.AllowedEndpoints == nil {
		vk.AllowedEndpoints = append([]string(nil), domain.DefaultAllowedEndpoints...)
	}
	if vk.Role == "" {
		vk.Role = domain.RoleServiceAccount
	}
	const q = `
		INSERT INTO virtual_keys (
			id, key_prefix, key_hash, name, org_id, role, allowed_models, allowed_endpoints,
			allowed_mcp_servers, allowed_a2a_agents, allowed_client_apps,
			max_budget_micros, spent_micros, rpm_limit, tpm_limit, max_concurrent_requests, expires_at, is_active
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`
	if _, err := p.pool.Exec(ctx, q,
		vk.ID, vk.KeyPrefix, vk.KeyHash, vk.Name, vk.OrgID, string(vk.Role), vk.AllowedModels, vk.AllowedEndpoints,
		vk.AllowedMCPServers, vk.AllowedA2AAgents, vk.AllowedClientApps,
		vk.MaxBudgetMicros, vk.SpentMicros, vk.RPMLimit, vk.TPMLimit, vk.MaxConcurrentRequests, vk.ExpiresAt, vk.IsActive,
	); err != nil {
		return err
	}
	return p.mem.CreateVirtualKey(ctx, vk)
}

func (p *PostgresRepository) GetVirtualKeyByHash(ctx context.Context, keyHash string) (*domain.VirtualKey, error) {
	const q = `SELECT id, key_prefix, key_hash, name, org_id, role, allowed_models, allowed_endpoints, allowed_mcp_servers, allowed_a2a_agents, allowed_client_apps, max_budget_micros, spent_micros, rpm_limit, tpm_limit, max_concurrent_requests, expires_at, is_active FROM virtual_keys WHERE key_hash = $1`
	var k domain.VirtualKey
	var role string
	if err := p.pool.QueryRow(ctx, q, keyHash).Scan(
		&k.ID, &k.KeyPrefix, &k.KeyHash, &k.Name, &k.OrgID, &role, &k.AllowedModels, &k.AllowedEndpoints,
		&k.AllowedMCPServers, &k.AllowedA2AAgents, &k.AllowedClientApps,
		&k.MaxBudgetMicros, &k.SpentMicros, &k.RPMLimit, &k.TPMLimit, &k.MaxConcurrentRequests, &k.ExpiresAt, &k.IsActive,
	); err != nil {
		return nil, fmt.Errorf("virtual key not found: %w", err)
	}
	k.Role = domain.Role(role)
	return &k, nil
}

func (p *PostgresRepository) GetVirtualKeyByID(ctx context.Context, id string) (*domain.VirtualKey, error) {
	const q = `SELECT id, key_prefix, key_hash, name, org_id, role, allowed_models, allowed_endpoints, allowed_mcp_servers, allowed_a2a_agents, allowed_client_apps, max_budget_micros, spent_micros, rpm_limit, tpm_limit, max_concurrent_requests, expires_at, is_active FROM virtual_keys WHERE id = $1`
	var k domain.VirtualKey
	var role string
	if err := p.pool.QueryRow(ctx, q, id).Scan(
		&k.ID, &k.KeyPrefix, &k.KeyHash, &k.Name, &k.OrgID, &role, &k.AllowedModels, &k.AllowedEndpoints,
		&k.AllowedMCPServers, &k.AllowedA2AAgents, &k.AllowedClientApps,
		&k.MaxBudgetMicros, &k.SpentMicros, &k.RPMLimit, &k.TPMLimit, &k.MaxConcurrentRequests, &k.ExpiresAt, &k.IsActive,
	); err != nil {
		return nil, fmt.Errorf("virtual key not found: %w", err)
	}
	k.Role = domain.Role(role)
	return &k, nil
}

func (p *PostgresRepository) ListVirtualKeys(ctx context.Context, orgID string) ([]*domain.VirtualKey, error) {
	const q = `SELECT id, key_prefix, key_hash, name, org_id, role, allowed_models, allowed_endpoints, allowed_mcp_servers, allowed_a2a_agents, allowed_client_apps, max_budget_micros, spent_micros, rpm_limit, tpm_limit, max_concurrent_requests, expires_at, is_active FROM virtual_keys WHERE org_id = $1 ORDER BY created_at DESC`
	rows, err := p.pool.Query(ctx, q, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var list []*domain.VirtualKey
	for rows.Next() {
		var k domain.VirtualKey
		var role string
		if err := rows.Scan(
			&k.ID, &k.KeyPrefix, &k.KeyHash, &k.Name, &k.OrgID, &role, &k.AllowedModels, &k.AllowedEndpoints,
			&k.AllowedMCPServers, &k.AllowedA2AAgents, &k.AllowedClientApps,
			&k.MaxBudgetMicros, &k.SpentMicros, &k.RPMLimit, &k.TPMLimit, &k.MaxConcurrentRequests, &k.ExpiresAt, &k.IsActive,
		); err != nil {
			return nil, err
		}
		k.Role = domain.Role(role)
		list = append(list, &k)
	}
	return list, nil
}

func (p *PostgresRepository) RevokeVirtualKey(ctx context.Context, id string) error {
	var keyHash, orgID string
	err := p.pool.QueryRow(ctx, `UPDATE virtual_keys SET is_active = FALSE, updated_at = NOW() WHERE id = $1 RETURNING key_hash, org_id`, id).Scan(&keyHash, &orgID)
	if err != nil {
		return err
	}
	return p.mem.RevokeVirtualKey(ctx, id)
}

func (p *PostgresRepository) CreateProviderCredential(ctx context.Context, cred *domain.ProviderCredential) error {
	if cred.ID == "" {
		cred.ID = uuid.NewString()
	}
	const q = `
		INSERT INTO provider_credentials (
			id, org_id, provider, name, base_url, azure_deployment_name, api_version,
			encrypted_api_key, data_nonce, encrypted_dek, dek_nonce, key_version,
			expires_at, last_rotated_at, last_validated_at, is_active
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)
		ON CONFLICT (org_id, name) DO UPDATE SET
			encrypted_api_key = EXCLUDED.encrypted_api_key,
			data_nonce = EXCLUDED.data_nonce,
			encrypted_dek = EXCLUDED.encrypted_dek,
			dek_nonce = EXCLUDED.dek_nonce,
			base_url = EXCLUDED.base_url,
			azure_deployment_name = EXCLUDED.azure_deployment_name,
			api_version = EXCLUDED.api_version,
			updated_at = NOW()
		RETURNING id`
	kv := cred.KeyVersion
	if kv <= 0 {
		kv = 1
	}
	if err := p.pool.QueryRow(ctx, q,
		cred.ID, cred.OrgID, string(cred.Provider), cred.Name, cred.BaseURL,
		cred.AzureDeploymentName, cred.APIVersion,
		cred.EncryptedAPIKey, cred.DataNonce, cred.EncryptedDEK, cred.DEKNonce,
		kv, cred.ExpiresAt, cred.LastRotatedAt, cred.LastValidatedAt, cred.IsActive,
	).Scan(&cred.ID); err != nil {
		return err
	}
	return p.mem.CreateProviderCredential(ctx, cred)
}

func (p *PostgresRepository) GetProviderCredential(ctx context.Context, id string) (*domain.ProviderCredential, error) {
	if cred, err := p.mem.GetProviderCredential(ctx, id); err == nil && cred != nil {
		return cred, nil
	}
	const q = `SELECT id, org_id, provider, name, base_url, COALESCE(azure_deployment_name, ''), COALESCE(api_version, ''), encrypted_api_key, data_nonce, encrypted_dek, dek_nonce, key_version, expires_at, last_rotated_at, last_validated_at, is_active FROM provider_credentials WHERE id = $1`
	var c domain.ProviderCredential
	var prov string
	if err := p.pool.QueryRow(ctx, q, id).Scan(
		&c.ID, &c.OrgID, &prov, &c.Name, &c.BaseURL, &c.AzureDeploymentName, &c.APIVersion,
		&c.EncryptedAPIKey, &c.DataNonce, &c.EncryptedDEK, &c.DEKNonce,
		&c.KeyVersion, &c.ExpiresAt, &c.LastRotatedAt, &c.LastValidatedAt, &c.IsActive,
	); err != nil {
		return nil, fmt.Errorf("credential not found: %w", err)
	}
	c.Provider = domain.ProviderType(prov)
	_ = p.mem.CreateProviderCredential(ctx, &c)
	return &c, nil
}

func (p *PostgresRepository) UpdateProviderCredential(ctx context.Context, cred *domain.ProviderCredential) error {
	if err := p.mem.UpdateProviderCredential(ctx, cred); err != nil {
		return err
	}
	kv := cred.KeyVersion
	if kv <= 0 {
		kv = 1
	}
	_, _ = p.pool.Exec(ctx, `
		UPDATE provider_credentials SET
			azure_deployment_name = $2,
			api_version = $3,
			encrypted_api_key = $4,
			data_nonce = $5,
			encrypted_dek = $6,
			dek_nonce = $7,
			key_version = $8,
			expires_at = $9,
			last_rotated_at = $10,
			last_validated_at = $11,
			is_active = $12,
			updated_at = NOW()
		WHERE id = $1`,
		cred.ID, cred.AzureDeploymentName, cred.APIVersion,
		cred.EncryptedAPIKey, cred.DataNonce, cred.EncryptedDEK, cred.DEKNonce,
		kv, cred.ExpiresAt, cred.LastRotatedAt, cred.LastValidatedAt, cred.IsActive,
	)
	return nil
}

func (p *PostgresRepository) ListProviderCredentials(ctx context.Context, orgID string) ([]*domain.ProviderCredential, error) {
	return p.mem.ListProviderCredentials(ctx, orgID)
}

func (p *PostgresRepository) CreateModelGroup(ctx context.Context, mg *domain.ModelGroup) error {
	if mg.ID == "" {
		mg.ID = uuid.NewString()
	}
	fbs := mg.FallbackGroupIDs
	if fbs == nil {
		fbs = []string{}
	}
	const q = `
		INSERT INTO model_groups (id, org_id, alias, description, routing_strategy, fallback_group_ids, max_retries, cooldown_seconds, failure_threshold, is_active)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)
		ON CONFLICT (org_id, alias) DO UPDATE SET
			routing_strategy = EXCLUDED.routing_strategy,
			fallback_group_ids = EXCLUDED.fallback_group_ids,
			updated_at = NOW()
		RETURNING id`
	if err := p.pool.QueryRow(ctx, q, mg.ID, mg.OrgID, mg.Alias, mg.Description, string(mg.RoutingStrategy), fbs, mg.MaxRetries, mg.CooldownSeconds, mg.FailureThreshold, mg.IsActive).Scan(&mg.ID); err != nil {
		return err
	}
	return p.mem.CreateModelGroup(ctx, mg)
}

func (p *PostgresRepository) GetModelGroupByAlias(ctx context.Context, orgID, alias string) (*domain.ModelGroup, error) {
	if mg, err := p.mem.GetModelGroupByAlias(ctx, orgID, alias); err == nil && mg != nil {
		return mg, nil
	}
	const q = `SELECT id, org_id, alias, description, routing_strategy, fallback_group_ids, max_retries, cooldown_seconds, failure_threshold, is_active FROM model_groups WHERE org_id = $1 AND alias = $2`
	var g domain.ModelGroup
	var strat string
	var fbs []string
	if err := p.pool.QueryRow(ctx, q, orgID, alias).Scan(
		&g.ID, &g.OrgID, &g.Alias, &g.Description, &strat, &fbs, &g.MaxRetries, &g.CooldownSeconds, &g.FailureThreshold, &g.IsActive,
	); err != nil {
		return nil, fmt.Errorf("model group not found: %w", err)
	}
	g.RoutingStrategy = domain.RoutingStrategy(strat)
	g.FallbackGroupIDs = fbs
	_ = p.mem.CreateModelGroup(ctx, &g)
	return &g, nil
}

func (p *PostgresRepository) GetModelGroupByID(ctx context.Context, id string) (*domain.ModelGroup, error) {
	if mg, err := p.mem.GetModelGroupByID(ctx, id); err == nil && mg != nil {
		return mg, nil
	}
	const q = `SELECT id, org_id, alias, description, routing_strategy, fallback_group_ids, max_retries, cooldown_seconds, failure_threshold, is_active FROM model_groups WHERE id = $1`
	var g domain.ModelGroup
	var strat string
	var fbs []string
	if err := p.pool.QueryRow(ctx, q, id).Scan(
		&g.ID, &g.OrgID, &g.Alias, &g.Description, &strat, &fbs, &g.MaxRetries, &g.CooldownSeconds, &g.FailureThreshold, &g.IsActive,
	); err != nil {
		return nil, fmt.Errorf("model group not found: %w", err)
	}
	g.RoutingStrategy = domain.RoutingStrategy(strat)
	g.FallbackGroupIDs = fbs
	_ = p.mem.CreateModelGroup(ctx, &g)
	return &g, nil
}

func (p *PostgresRepository) ListModelGroups(ctx context.Context, orgID string) ([]*domain.ModelGroup, error) {
	return p.mem.ListModelGroups(ctx, orgID)
}

func (p *PostgresRepository) CreateDeployment(ctx context.Context, dep *domain.Deployment) error {
	if dep.ID == "" {
		dep.ID = uuid.NewString()
	}
	if dep.Status == "" {
		dep.Status = domain.DeploymentStatusActive
	}
	if dep.Weight <= 0 {
		dep.Weight = 100
	}
	const q = `
		INSERT INTO model_deployments (id, model_group_id, global_model_id, credential_id, deployment_name, region, weight, rpm_capacity, tpm_capacity, timeout_ms, priority, status)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`
	if _, err := p.pool.Exec(ctx, q, dep.ID, dep.ModelGroupID, dep.GlobalModelID, dep.CredentialID, dep.DeploymentName, dep.Region, dep.Weight, dep.RPMCapacity, dep.TPMCapacity, dep.TimeoutMs, dep.Priority, string(dep.Status)); err != nil {
		return err
	}
	if dep.GlobalModel == nil && dep.GlobalModelID != "" {
		dep.GlobalModel, _ = p.GetGlobalModel(ctx, dep.GlobalModelID)
	}
	if dep.Credential == nil && dep.CredentialID != "" {
		dep.Credential, _ = p.GetProviderCredential(ctx, dep.CredentialID)
	}
	return p.mem.CreateDeployment(ctx, dep)
}

func (p *PostgresRepository) ListDeploymentsByGroup(ctx context.Context, groupID string) ([]*domain.Deployment, error) {
	deps, err := p.mem.ListDeploymentsByGroup(ctx, groupID)
	if err == nil && len(deps) > 0 {
		return deps, nil
	}
	const q = `SELECT id, model_group_id, global_model_id, credential_id, deployment_name, region, weight, rpm_capacity, tpm_capacity, timeout_ms, priority, status FROM model_deployments WHERE model_group_id = $1`
	rows, err := p.pool.Query(ctx, q, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var d domain.Deployment
		var status string
		if err := rows.Scan(&d.ID, &d.ModelGroupID, &d.GlobalModelID, &d.CredentialID, &d.DeploymentName, &d.Region, &d.Weight, &d.RPMCapacity, &d.TPMCapacity, &d.TimeoutMs, &d.Priority, &status); err != nil {
			continue
		}
		if status == "" {
			d.Status = domain.DeploymentStatusActive
		} else {
			d.Status = domain.DeploymentStatus(status)
		}
		// Hydrate credential if needed
		_, _ = p.GetProviderCredential(ctx, d.CredentialID)
		// Hydrate global model if needed
		_, _ = p.GetGlobalModel(ctx, d.GlobalModelID)
		_ = p.mem.CreateDeployment(ctx, &d)
	}
	return p.mem.ListDeploymentsByGroup(ctx, groupID)
}

func (p *PostgresRepository) ListAllDeployments(ctx context.Context) ([]*domain.Deployment, error) {
	deps, err := p.mem.ListAllDeployments(ctx)
	if err == nil && len(deps) > 0 {
		return deps, nil
	}
	const q = `SELECT id, model_group_id, global_model_id, credential_id, deployment_name, region, weight, rpm_capacity, tpm_capacity, timeout_ms, priority, status FROM model_deployments`
	rows, err := p.pool.Query(ctx, q)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var d domain.Deployment
		var status string
		if err := rows.Scan(&d.ID, &d.ModelGroupID, &d.GlobalModelID, &d.CredentialID, &d.DeploymentName, &d.Region, &d.Weight, &d.RPMCapacity, &d.TPMCapacity, &d.TimeoutMs, &d.Priority, &status); err != nil {
			continue
		}
		if status == "" {
			d.Status = domain.DeploymentStatusActive
		} else {
			d.Status = domain.DeploymentStatus(status)
		}
		_, _ = p.GetProviderCredential(ctx, d.CredentialID)
		_, _ = p.GetGlobalModel(ctx, d.GlobalModelID)
		_ = p.mem.CreateDeployment(ctx, &d)
	}
	return p.mem.ListAllDeployments(ctx)
}

func (p *PostgresRepository) SetGuardrailPolicy(ctx context.Context, pol *domain.GuardrailPolicy) error {
	if err := p.mem.SetGuardrailPolicy(ctx, pol); err != nil {
		return err
	}
	const q = `
		INSERT INTO guardrail_policies (
			org_id, enable_prompt_injection, prompt_injection_action,
			enable_pii_detection, pii_action, enable_secret_detection,
			secret_action, blocked_keywords, redact_output_pii, updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,NOW())
		ON CONFLICT (org_id) DO UPDATE SET
			enable_prompt_injection = EXCLUDED.enable_prompt_injection,
			prompt_injection_action = EXCLUDED.prompt_injection_action,
			enable_pii_detection = EXCLUDED.enable_pii_detection,
			pii_action = EXCLUDED.pii_action,
			enable_secret_detection = EXCLUDED.enable_secret_detection,
			secret_action = EXCLUDED.secret_action,
			blocked_keywords = EXCLUDED.blocked_keywords,
			redact_output_pii = EXCLUDED.redact_output_pii,
			updated_at = NOW()`
	act := pol.PromptInjectionAction
	if act == "" {
		act = domain.GuardrailActionBlock
	}
	piiAct := pol.PIIAction
	if piiAct == "" {
		piiAct = domain.GuardrailActionRedact
	}
	secAct := pol.SecretAction
	if secAct == "" {
		secAct = domain.GuardrailActionRedact
	}
	_, err := p.pool.Exec(ctx, q,
		pol.OrgID, pol.EnablePromptInjection, string(act),
		pol.EnablePIIDetection, string(piiAct), pol.EnableSecretDetection,
		string(secAct), pol.BlockedKeywords, pol.RedactOutputPII,
	)
	return err
}

func (p *PostgresRepository) GetGuardrailPolicy(ctx context.Context, orgID string) (*domain.GuardrailPolicy, error) {
	if pol, err := p.mem.GetGuardrailPolicy(ctx, orgID); err == nil && pol != nil {
		return pol, nil
	}
	const q = `SELECT org_id, enable_prompt_injection, prompt_injection_action, enable_pii_detection, pii_action, enable_secret_detection, secret_action, blocked_keywords, redact_output_pii FROM guardrail_policies WHERE org_id = $1`
	var pol domain.GuardrailPolicy
	var injAct, piiAct, secAct string
	if err := p.pool.QueryRow(ctx, q, orgID).Scan(
		&pol.OrgID, &pol.EnablePromptInjection, &injAct, &pol.EnablePIIDetection, &piiAct,
		&pol.EnableSecretDetection, &secAct, &pol.BlockedKeywords, &pol.RedactOutputPII,
	); err != nil {
		if err == pgx.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}
	pol.PromptInjectionAction = domain.GuardrailAction(injAct)
	pol.PIIAction = domain.GuardrailAction(piiAct)
	pol.SecretAction = domain.GuardrailAction(secAct)
	_ = p.mem.SetGuardrailPolicy(ctx, &pol)
	return &pol, nil
}

func (p *PostgresRepository) UpdateDeploymentStatus(ctx context.Context, depID string, status domain.DeploymentStatus) error {
	if _, err := p.pool.Exec(ctx, `UPDATE model_deployments SET status = $2, updated_at = NOW() WHERE id = $1`, depID, string(status)); err != nil {
		return err
	}
	return p.mem.UpdateDeploymentStatus(ctx, depID, status)
}

func (p *PostgresRepository) RecordSpendBatch(ctx context.Context, events []domain.SpendEvent) error {
	if err := p.mem.RecordSpendBatch(ctx, events); err != nil {
		return err
	}
	if len(events) == 0 {
		return nil
	}
	const q = `
		INSERT INTO spend_logs (
			id, request_id, trace_id, org_id, endpoint, modality, modality_units, requested_model, resolved_model, provider,
			prompt_tokens, completion_tokens, cached_tokens, reasoning_tokens, total_tokens,
			cost_micros, pricing_version, pricing_status, pricing_provenance_source, latency_ms, ttft_ms, status_code, is_stream, cache_hit, fallback_attempted, retry_count
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19,$20,$21,$22,$23,$24,$25,$26)`
	batch := &pgx.Batch{}
	for _, ev := range events {
		id := ev.ID
		if id == "" {
			id = uuid.NewString()
		}
		pv := ev.PricingVersion
		if pv <= 0 {
			pv = 1
		}
		pricingStatus := string(ev.PricingStatus)
		if pricingStatus == "" {
			pricingStatus = string(domain.PricingStatusUnrecorded)
		}
		orgID := ev.OrgID
		if _, err := uuid.Parse(orgID); err != nil {
			orgID = "00000000-0000-0000-0000-000000000000"
		}
		modality := string(ev.Modality)
		if modality == "" {
			modality = string(domain.ModalityChat)
		}
		modUnitsJSON, _ := json.Marshal(ev.ModalityUnits)
		if len(ev.ModalityUnits) == 0 {
			modUnitsJSON = []byte("{}")
		}
		batch.Queue(q,
			id, ev.RequestID, ev.TraceID, orgID, ev.Endpoint, modality, modUnitsJSON, ev.RequestedModel, ev.ResolvedModel, string(ev.Provider),
			ev.Usage.PromptTokens, ev.Usage.CompletionTokens, ev.Usage.CachedPromptTokens, ev.Usage.ReasoningTokens, ev.Usage.TotalTokens,
			ev.CostMicros, pv, pricingStatus, ev.PricingProvenanceSource, ev.LatencyMs, ev.TTFTMs, ev.StatusCode, ev.IsStream, ev.CacheHit, ev.FallbackAttempted, ev.RetryCount,
		)
	}
	br := p.pool.SendBatch(ctx, batch)
	defer br.Close()
	for range events {
		if _, err := br.Exec(); err != nil {
			return fmt.Errorf("execute spend batch: %w", err)
		}
	}
	return nil
}

func (p *PostgresRepository) GetSpendSummary(ctx context.Context, orgID string) (*SpendSummary, error) {
	sum := &SpendSummary{
		SpendByProvider:   make(map[string]int64),
		SpendByModel:      make(map[string]int64),
		SpendByTeam:       make(map[string]int64),
		SpendByVirtualKey: make(map[string]int64),
	}
	var whereClause string
	var args []any
	if orgID != "" {
		whereClause = "WHERE org_id = $1"
		args = append(args, orgID)
	}

	qTotals := `SELECT COUNT(*), COALESCE(SUM(total_tokens), 0), COALESCE(SUM(cost_micros), 0),
		COUNT(*) FILTER (WHERE pricing_status IN ('unknown', 'unrecorded')),
		COALESCE(SUM(total_tokens) FILTER (WHERE pricing_status IN ('unknown', 'unrecorded')), 0)
		FROM spend_logs ` + whereClause
	if err := p.pool.QueryRow(ctx, qTotals, args...).Scan(&sum.TotalRequests, &sum.TotalTokens, &sum.TotalCostMicros, &sum.UnpricedRequests, &sum.UnpricedTokens); err != nil {
		return p.mem.GetSpendSummary(ctx, orgID)
	}
	sum.TotalCostUSD = float64(sum.TotalCostMicros) / 1_000_000.0

	qProviders := `SELECT provider, COALESCE(SUM(cost_micros), 0) FROM spend_logs ` + whereClause + ` GROUP BY provider`
	if rows, err := p.pool.Query(ctx, qProviders, args...); err == nil {
		defer rows.Close()
		for rows.Next() {
			var prov string
			var cost int64
			if err := rows.Scan(&prov, &cost); err == nil {
				sum.SpendByProvider[prov] = cost
			}
		}
	}

	qModels := `SELECT resolved_model, COALESCE(SUM(cost_micros), 0) FROM spend_logs ` + whereClause + ` GROUP BY resolved_model`
	if rows, err := p.pool.Query(ctx, qModels, args...); err == nil {
		defer rows.Close()
		for rows.Next() {
			var model string
			var cost int64
			if err := rows.Scan(&model, &cost); err == nil {
				sum.SpendByModel[model] = cost
			}
		}
	}

	return sum, nil
}

func (p *PostgresRepository) ListSpendLogs(ctx context.Context, orgID string, limit int) ([]domain.SpendEvent, error) {
	if limit <= 0 {
		limit = 100
	}
	var q string
	var args []any
	if orgID != "" {
		q = `
			SELECT id, request_id, trace_id, org_id, endpoint, requested_model, resolved_model, provider,
				prompt_tokens, completion_tokens, cached_tokens, reasoning_tokens, total_tokens,
				cost_micros, pricing_version, latency_ms, ttft_ms, status_code, is_stream, cache_hit, fallback_attempted, retry_count, created_at
			FROM spend_logs WHERE org_id = $1 ORDER BY created_at DESC LIMIT $2`
		args = []any{orgID, limit}
	} else {
		q = `
			SELECT id, request_id, trace_id, org_id, endpoint, requested_model, resolved_model, provider,
				prompt_tokens, completion_tokens, cached_tokens, reasoning_tokens, total_tokens,
				cost_micros, pricing_version, latency_ms, ttft_ms, status_code, is_stream, cache_hit, fallback_attempted, retry_count, created_at
			FROM spend_logs ORDER BY created_at DESC LIMIT $1`
		args = []any{limit}
	}

	rows, err := p.pool.Query(ctx, q, args...)
	if err != nil {
		return p.mem.ListSpendLogs(ctx, orgID, limit)
	}
	defer rows.Close()

	var out []domain.SpendEvent
	for rows.Next() {
		var ev domain.SpendEvent
		var prov string
		if err := rows.Scan(
			&ev.ID, &ev.RequestID, &ev.TraceID, &ev.OrgID, &ev.Endpoint, &ev.RequestedModel, &ev.ResolvedModel, &prov,
			&ev.Usage.PromptTokens, &ev.Usage.CompletionTokens, &ev.Usage.CachedPromptTokens, &ev.Usage.ReasoningTokens, &ev.Usage.TotalTokens,
			&ev.CostMicros, &ev.PricingVersion, &ev.LatencyMs, &ev.TTFTMs, &ev.StatusCode, &ev.IsStream, &ev.CacheHit, &ev.FallbackAttempted, &ev.RetryCount, &ev.CreatedAt,
		); err != nil {
			return nil, err
		}
		ev.Provider = domain.ProviderType(prov)
		out = append(out, ev)
	}
	if len(out) == 0 {
		return p.mem.ListSpendLogs(ctx, orgID, limit)
	}
	return out, rows.Err()
}

func (p *PostgresRepository) ResetExpiredBudgets(ctx context.Context, now time.Time) (int, error) {
	tag1, err1 := p.pool.Exec(ctx, `UPDATE teams SET spent_micros = 0, budget_reset_at = $1 WHERE budget_reset_at IS NOT NULL AND budget_reset_at <= $1`, now)
	tag2, err2 := p.pool.Exec(ctx, `UPDATE virtual_keys SET spent_micros = 0, budget_reset_at = $1 WHERE budget_reset_at IS NOT NULL AND budget_reset_at <= $1`, now)
	var total int64
	if err1 == nil {
		total += tag1.RowsAffected()
	}
	if err2 == nil {
		total += tag2.RowsAffected()
	}
	memCount, _ := p.mem.ResetExpiredBudgets(ctx, now)
	if total == 0 {
		return memCount, nil
	}
	return int(total), nil
}

func (p *PostgresRepository) RecordAuditLog(ctx context.Context, log *domain.AuditLog) error {
	if log.ID == "" {
		log.ID = uuid.NewString()
	}
	var orgUUID *uuid.UUID
	if u, err := uuid.Parse(log.OrgID); err == nil {
		orgUUID = &u
	}
	detailsJSON, _ := json.Marshal(log.Details)
	if _, err := p.pool.Exec(ctx, `INSERT INTO audit_logs (id, org_id, actor_id, action, resource, resource_id, details) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		log.ID, orgUUID, log.ActorID, log.Action, log.Resource, log.ResourceID, detailsJSON,
	); err != nil {
		return fmt.Errorf("insert audit log: %w", err)
	}
	return p.mem.RecordAuditLog(ctx, log)
}

func (p *PostgresRepository) ListAuditLogs(ctx context.Context, orgID string, limit int) ([]*domain.AuditLog, error) {
	if limit <= 0 {
		limit = 100
	}
	var q string
	var args []any
	if orgID != "" {
		q = `SELECT id, COALESCE(org_id::text, ''), actor_id, action, resource, resource_id, details, created_at FROM audit_logs WHERE org_id = $1::uuid ORDER BY created_at DESC LIMIT $2`
		args = []any{orgID, limit}
	} else {
		q = `SELECT id, COALESCE(org_id::text, ''), actor_id, action, resource, resource_id, details, created_at FROM audit_logs ORDER BY created_at DESC LIMIT $1`
		args = []any{limit}
	}
	rows, err := p.pool.Query(ctx, q, args...)
	if err != nil {
		return p.mem.ListAuditLogs(ctx, orgID, limit)
	}
	defer rows.Close()

	var logs []*domain.AuditLog
	for rows.Next() {
		var a domain.AuditLog
		var detailsJSON []byte
		if err := rows.Scan(&a.ID, &a.OrgID, &a.ActorID, &a.Action, &a.Resource, &a.ResourceID, &detailsJSON, &a.CreatedAt); err != nil {
			return nil, err
		}
		if len(detailsJSON) > 0 {
			_ = json.Unmarshal(detailsJSON, &a.Details)
		}
		logs = append(logs, &a)
	}
	if len(logs) == 0 {
		return p.mem.ListAuditLogs(ctx, orgID, limit)
	}
	return logs, rows.Err()
}

// -----------------------------------------------------------------------------
// MCP: Servers, Tools, Toolsets & BYOK Credentials
// -----------------------------------------------------------------------------

func (p *PostgresRepository) CreateMCPServer(ctx context.Context, server *domain.MCPServer) error {
	if server.ID == "" {
		server.ID = uuid.NewString()
	}
	headersJSON, _ := json.Marshal(server.StaticHeaders)
	const q = `
		INSERT INTO mcp_servers (
			id, org_id, name, slug, protocol_version, transport_type, endpoint_url,
			config_version, auth_type, encrypted_auth_secret, encrypted_auth_dek,
			static_headers, oauth2_endpoint, oauth2_client_id, oauth2_scopes,
			pinned_tool_hash, is_active
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`
	if _, err := p.pool.Exec(ctx, q,
		server.ID, server.OrgID, server.Name, server.Slug, server.ProtocolVersion, server.TransportType, server.EndpointURL,
		server.ConfigVersion, server.AuthType, server.EncryptedAuthSecret, server.EncryptedAuthDEK,
		headersJSON, server.OAuth2Endpoint, server.OAuth2ClientID, server.OAuth2Scopes,
		server.PinnedToolHash, server.IsActive,
	); err != nil {
		return err
	}
	return p.mem.CreateMCPServer(ctx, server)
}

func (p *PostgresRepository) UpdateMCPServer(ctx context.Context, server *domain.MCPServer) error {
	headersJSON, _ := json.Marshal(server.StaticHeaders)
	const q = `
		UPDATE mcp_servers SET
			name = $2, slug = $3, protocol_version = $4, transport_type = $5, endpoint_url = $6,
			config_version = config_version + 1, auth_type = $7, encrypted_auth_secret = $8, encrypted_auth_dek = $9,
			static_headers = $10, oauth2_endpoint = $11, oauth2_client_id = $12, oauth2_scopes = $13,
			pinned_tool_hash = $14, is_active = $15, updated_at = NOW()
		WHERE id = $1 RETURNING config_version`
	var newVersion int64
	if err := p.pool.QueryRow(ctx, q,
		server.ID, server.Name, server.Slug, server.ProtocolVersion, server.TransportType, server.EndpointURL,
		server.AuthType, server.EncryptedAuthSecret, server.EncryptedAuthDEK,
		headersJSON, server.OAuth2Endpoint, server.OAuth2ClientID, server.OAuth2Scopes,
		server.PinnedToolHash, server.IsActive,
	).Scan(&newVersion); err != nil {
		return err
	}
	server.ConfigVersion = newVersion
	return p.mem.UpdateMCPServer(ctx, server)
}

func (p *PostgresRepository) GetMCPServer(ctx context.Context, id string) (*domain.MCPServer, error) {
	if s, err := p.mem.GetMCPServer(ctx, id); err == nil && s != nil {
		return s, nil
	}
	const q = `
		SELECT id, org_id, name, slug, protocol_version, transport_type, endpoint_url,
		       config_version, auth_type, encrypted_auth_secret, encrypted_auth_dek,
		       static_headers, oauth2_endpoint, oauth2_client_id, oauth2_scopes,
		       pinned_tool_hash, is_active, created_at, updated_at
		FROM mcp_servers WHERE id = $1`
	var s domain.MCPServer
	var headersJSON []byte
	if err := p.pool.QueryRow(ctx, q, id).Scan(
		&s.ID, &s.OrgID, &s.Name, &s.Slug, &s.ProtocolVersion, &s.TransportType, &s.EndpointURL,
		&s.ConfigVersion, &s.AuthType, &s.EncryptedAuthSecret, &s.EncryptedAuthDEK,
		&headersJSON, &s.OAuth2Endpoint, &s.OAuth2ClientID, &s.OAuth2Scopes,
		&s.PinnedToolHash, &s.IsActive, &s.CreatedAt, &s.UpdatedAt,
	); err != nil {
		return nil, fmt.Errorf("mcp server %s not found: %w", id, err)
	}
	if len(headersJSON) > 0 {
		_ = json.Unmarshal(headersJSON, &s.StaticHeaders)
	}
	_ = p.mem.CreateMCPServer(ctx, &s)
	return &s, nil
}

func (p *PostgresRepository) GetMCPServerBySlug(ctx context.Context, orgID, slug string) (*domain.MCPServer, error) {
	if s, err := p.mem.GetMCPServerBySlug(ctx, orgID, slug); err == nil && s != nil {
		return s, nil
	}
	const q = `
		SELECT id, org_id, name, slug, protocol_version, transport_type, endpoint_url,
		       config_version, auth_type, encrypted_auth_secret, encrypted_auth_dek,
		       static_headers, oauth2_endpoint, oauth2_client_id, oauth2_scopes,
		       pinned_tool_hash, is_active, created_at, updated_at
		FROM mcp_servers WHERE (org_id = $1 OR $1 = '') AND slug = $2 LIMIT 1`
	var s domain.MCPServer
	var headersJSON []byte
	if err := p.pool.QueryRow(ctx, q, orgID, slug).Scan(
		&s.ID, &s.OrgID, &s.Name, &s.Slug, &s.ProtocolVersion, &s.TransportType, &s.EndpointURL,
		&s.ConfigVersion, &s.AuthType, &s.EncryptedAuthSecret, &s.EncryptedAuthDEK,
		&headersJSON, &s.OAuth2Endpoint, &s.OAuth2ClientID, &s.OAuth2Scopes,
		&s.PinnedToolHash, &s.IsActive, &s.CreatedAt, &s.UpdatedAt,
	); err != nil {
		return nil, fmt.Errorf("mcp server %q not found: %w", slug, err)
	}
	if len(headersJSON) > 0 {
		_ = json.Unmarshal(headersJSON, &s.StaticHeaders)
	}
	_ = p.mem.CreateMCPServer(ctx, &s)
	return &s, nil
}

func (p *PostgresRepository) ListMCPServers(ctx context.Context, orgID string) ([]*domain.MCPServer, error) {
	const q = `
		SELECT id, org_id, name, slug, protocol_version, transport_type, endpoint_url,
		       config_version, auth_type, encrypted_auth_secret, encrypted_auth_dek,
		       static_headers, oauth2_endpoint, oauth2_client_id, oauth2_scopes,
		       pinned_tool_hash, is_active, created_at, updated_at
		FROM mcp_servers WHERE org_id = $1 OR $1 = '' ORDER BY name ASC`
	rows, err := p.pool.Query(ctx, q, orgID)
	if err != nil {
		return p.mem.ListMCPServers(ctx, orgID)
	}
	defer rows.Close()

	var out []*domain.MCPServer
	for rows.Next() {
		var s domain.MCPServer
		var headersJSON []byte
		if err := rows.Scan(
			&s.ID, &s.OrgID, &s.Name, &s.Slug, &s.ProtocolVersion, &s.TransportType, &s.EndpointURL,
			&s.ConfigVersion, &s.AuthType, &s.EncryptedAuthSecret, &s.EncryptedAuthDEK,
			&headersJSON, &s.OAuth2Endpoint, &s.OAuth2ClientID, &s.OAuth2Scopes,
			&s.PinnedToolHash, &s.IsActive, &s.CreatedAt, &s.UpdatedAt,
		); err == nil {
			if len(headersJSON) > 0 {
				_ = json.Unmarshal(headersJSON, &s.StaticHeaders)
			}
			out = append(out, &s)
		}
	}
	return out, nil
}

func (p *PostgresRepository) DeleteMCPServer(ctx context.Context, id string) error {
	_, err := p.pool.Exec(ctx, `DELETE FROM mcp_servers WHERE id = $1`, id)
	_ = p.mem.DeleteMCPServer(ctx, id)
	return err
}

func (p *PostgresRepository) UpsertMCPTools(ctx context.Context, serverID, orgID string, tools []*domain.MCPTool) error {
	for _, t := range tools {
		if t.ID == "" {
			t.ID = uuid.NewString()
		}
		schemaJSON, _ := json.Marshal(t.InputSchema)
		const q = `
			INSERT INTO mcp_tools (id, server_id, org_id, name, description, input_schema, tool_def_hash, cost_per_call_micros, is_active, updated_at)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())
			ON CONFLICT (server_id, name) DO UPDATE SET
				description = EXCLUDED.description,
				input_schema = EXCLUDED.input_schema,
				tool_def_hash = EXCLUDED.tool_def_hash,
				cost_per_call_micros = EXCLUDED.cost_per_call_micros,
				is_active = EXCLUDED.is_active,
				updated_at = NOW()`
		_, err := p.pool.Exec(ctx, q, t.ID, serverID, orgID, t.Name, t.Description, schemaJSON, t.ToolDefHash, t.CostPerCallMicros, t.IsActive)
		if err != nil {
			return err
		}
	}
	return p.mem.UpsertMCPTools(ctx, serverID, orgID, tools)
}

func (p *PostgresRepository) ListMCPTools(ctx context.Context, serverID string) ([]*domain.MCPTool, error) {
	const q = `SELECT id, server_id, org_id, name, description, input_schema, tool_def_hash, cost_per_call_micros, is_active, created_at, updated_at FROM mcp_tools WHERE server_id = $1 AND is_active = TRUE ORDER BY name ASC`
	rows, err := p.pool.Query(ctx, q, serverID)
	if err != nil {
		return p.mem.ListMCPTools(ctx, serverID)
	}
	defer rows.Close()

	var out []*domain.MCPTool
	for rows.Next() {
		var t domain.MCPTool
		var schemaJSON []byte
		if err := rows.Scan(&t.ID, &t.ServerID, &t.OrgID, &t.Name, &t.Description, &schemaJSON, &t.ToolDefHash, &t.CostPerCallMicros, &t.IsActive, &t.CreatedAt, &t.UpdatedAt); err == nil {
			if len(schemaJSON) > 0 {
				_ = json.Unmarshal(schemaJSON, &t.InputSchema)
			}
			out = append(out, &t)
		}
	}
	return out, nil
}

func (p *PostgresRepository) GetMCPTool(ctx context.Context, id string) (*domain.MCPTool, error) {
	if t, err := p.mem.GetMCPTool(ctx, id); err == nil && t != nil {
		return t, nil
	}
	const q = `SELECT id, server_id, org_id, name, description, input_schema, tool_def_hash, cost_per_call_micros, is_active, created_at, updated_at FROM mcp_tools WHERE id = $1`
	var t domain.MCPTool
	var schemaJSON []byte
	if err := p.pool.QueryRow(ctx, q, id).Scan(&t.ID, &t.ServerID, &t.OrgID, &t.Name, &t.Description, &schemaJSON, &t.ToolDefHash, &t.CostPerCallMicros, &t.IsActive, &t.CreatedAt, &t.UpdatedAt); err != nil {
		return nil, fmt.Errorf("mcp tool %s not found: %w", id, err)
	}
	if len(schemaJSON) > 0 {
		_ = json.Unmarshal(schemaJSON, &t.InputSchema)
	}
	return &t, nil
}

func (p *PostgresRepository) CreateMCPToolset(ctx context.Context, toolset *domain.MCPToolset) error {
	if toolset.ID == "" {
		toolset.ID = uuid.NewString()
	}
	const q = `INSERT INTO mcp_toolsets (id, org_id, name, slug, tool_ids, is_active) VALUES ($1,$2,$3,$4,$5,$6)`
	if _, err := p.pool.Exec(ctx, q, toolset.ID, toolset.OrgID, toolset.Name, toolset.Slug, toolset.ToolIDs, toolset.IsActive); err != nil {
		return err
	}
	return p.mem.CreateMCPToolset(ctx, toolset)
}

func (p *PostgresRepository) GetMCPToolsetBySlug(ctx context.Context, orgID, slug string) (*domain.MCPToolset, error) {
	if ts, err := p.mem.GetMCPToolsetBySlug(ctx, orgID, slug); err == nil && ts != nil {
		return ts, nil
	}
	const q = `SELECT id, org_id, name, slug, tool_ids, is_active, created_at, updated_at FROM mcp_toolsets WHERE (org_id = $1 OR $1 = '') AND slug = $2 LIMIT 1`
	var ts domain.MCPToolset
	if err := p.pool.QueryRow(ctx, q, orgID, slug).Scan(&ts.ID, &ts.OrgID, &ts.Name, &ts.Slug, &ts.ToolIDs, &ts.IsActive, &ts.CreatedAt, &ts.UpdatedAt); err != nil {
		return nil, fmt.Errorf("mcp toolset %q not found: %w", slug, err)
	}
	_ = p.mem.CreateMCPToolset(ctx, &ts)
	return &ts, nil
}

func (p *PostgresRepository) ListMCPToolsets(ctx context.Context, orgID string) ([]*domain.MCPToolset, error) {
	const q = `SELECT id, org_id, name, slug, tool_ids, is_active, created_at, updated_at FROM mcp_toolsets WHERE org_id = $1 OR $1 = ''`
	rows, err := p.pool.Query(ctx, q, orgID)
	if err != nil {
		return p.mem.ListMCPToolsets(ctx, orgID)
	}
	defer rows.Close()

	var out []*domain.MCPToolset
	for rows.Next() {
		var ts domain.MCPToolset
		if err := rows.Scan(&ts.ID, &ts.OrgID, &ts.Name, &ts.Slug, &ts.ToolIDs, &ts.IsActive, &ts.CreatedAt, &ts.UpdatedAt); err == nil {
			out = append(out, &ts)
		}
	}
	return out, nil
}

func (p *PostgresRepository) SetMCPUserCredential(ctx context.Context, cred *domain.MCPUserCredential) error {
	if cred.ID == "" {
		cred.ID = uuid.NewString()
	}
	const q = `
		INSERT INTO mcp_user_credentials (id, server_id, user_id, org_id, encrypted_token, encrypted_dek, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, NOW())
		ON CONFLICT (server_id, user_id) DO UPDATE SET
			encrypted_token = EXCLUDED.encrypted_token,
			encrypted_dek = EXCLUDED.encrypted_dek,
			updated_at = NOW()`
	if _, err := p.pool.Exec(ctx, q, cred.ID, cred.ServerID, cred.UserID, cred.OrgID, cred.EncryptedToken, cred.EncryptedDEK); err != nil {
		return err
	}
	return p.mem.SetMCPUserCredential(ctx, cred)
}

func (p *PostgresRepository) GetMCPUserCredential(ctx context.Context, serverID, userID string) (*domain.MCPUserCredential, error) {
	if c, err := p.mem.GetMCPUserCredential(ctx, serverID, userID); err == nil && c != nil {
		return c, nil
	}
	const q = `SELECT id, server_id, user_id, org_id, encrypted_token, encrypted_dek, created_at, updated_at FROM mcp_user_credentials WHERE server_id = $1 AND user_id = $2`
	var c domain.MCPUserCredential
	if err := p.pool.QueryRow(ctx, q, serverID, userID).Scan(&c.ID, &c.ServerID, &c.UserID, &c.OrgID, &c.EncryptedToken, &c.EncryptedDEK, &c.CreatedAt, &c.UpdatedAt); err != nil {
		return nil, fmt.Errorf("credential for server %s user %s not found: %w", serverID, userID, err)
	}
	_ = p.mem.SetMCPUserCredential(ctx, &c)
	return &c, nil
}

// -----------------------------------------------------------------------------
// A2A: Agents, Tasks, Events, Publications & Outbox
// -----------------------------------------------------------------------------

func (p *PostgresRepository) CreateA2AAgent(ctx context.Context, agent *domain.A2AAgent) error {
	if agent.ID == "" {
		agent.ID = uuid.NewString()
	}
	const q = `
		INSERT INTO a2a_agents (
			id, org_id, name, slug, endpoint_url, agent_card_url, agent_card_json,
			task_visibility_mode, auth_type, encrypted_auth_secret, encrypted_auth_dek,
			max_task_iterations, max_task_budget_micros, is_active, is_killed
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`
	if _, err := p.pool.Exec(ctx, q,
		agent.ID, agent.OrgID, agent.Name, agent.Slug, agent.EndpointURL, agent.AgentCardURL, agent.AgentCardJSON,
		agent.TaskVisibilityMode, agent.AuthType, agent.EncryptedAuthSecret, agent.EncryptedAuthDEK,
		agent.MaxTaskIterations, agent.MaxTaskBudgetMicros, agent.IsActive, agent.IsKilled,
	); err != nil {
		return err
	}
	return p.mem.CreateA2AAgent(ctx, agent)
}

func (p *PostgresRepository) UpdateA2AAgent(ctx context.Context, agent *domain.A2AAgent) error {
	const q = `
		UPDATE a2a_agents SET
			name = $2, slug = $3, endpoint_url = $4, agent_card_url = $5, agent_card_json = $6,
			task_visibility_mode = $7, auth_type = $8, encrypted_auth_secret = $9, encrypted_auth_dek = $10,
			max_task_iterations = $11, max_task_budget_micros = $12, is_active = $13, is_killed = $14,
			updated_at = NOW()
		WHERE id = $1`
	if _, err := p.pool.Exec(ctx, q,
		agent.ID, agent.Name, agent.Slug, agent.EndpointURL, agent.AgentCardURL, agent.AgentCardJSON,
		agent.TaskVisibilityMode, agent.AuthType, agent.EncryptedAuthSecret, agent.EncryptedAuthDEK,
		agent.MaxTaskIterations, agent.MaxTaskBudgetMicros, agent.IsActive, agent.IsKilled,
	); err != nil {
		return err
	}
	return p.mem.UpdateA2AAgent(ctx, agent)
}

func (p *PostgresRepository) GetA2AAgent(ctx context.Context, id string) (*domain.A2AAgent, error) {
	if a, err := p.mem.GetA2AAgent(ctx, id); err == nil && a != nil {
		return a, nil
	}
	const q = `
		SELECT id, org_id, name, slug, endpoint_url, agent_card_url, agent_card_json,
		       task_visibility_mode, auth_type, encrypted_auth_secret, encrypted_auth_dek,
		       max_task_iterations, max_task_budget_micros, is_active, is_killed,
		       created_at, updated_at
		FROM a2a_agents WHERE id = $1`
	var a domain.A2AAgent
	if err := p.pool.QueryRow(ctx, q, id).Scan(
		&a.ID, &a.OrgID, &a.Name, &a.Slug, &a.EndpointURL, &a.AgentCardURL, &a.AgentCardJSON,
		&a.TaskVisibilityMode, &a.AuthType, &a.EncryptedAuthSecret, &a.EncryptedAuthDEK,
		&a.MaxTaskIterations, &a.MaxTaskBudgetMicros, &a.IsActive, &a.IsKilled,
		&a.CreatedAt, &a.UpdatedAt,
	); err != nil {
		return nil, fmt.Errorf("a2a agent %s not found: %w", id, err)
	}
	_ = p.mem.CreateA2AAgent(ctx, &a)
	return &a, nil
}

func (p *PostgresRepository) GetA2AAgentBySlug(ctx context.Context, orgID, slug string) (*domain.A2AAgent, error) {
	if a, err := p.mem.GetA2AAgentBySlug(ctx, orgID, slug); err == nil && a != nil {
		return a, nil
	}
	const q = `
		SELECT id, org_id, name, slug, endpoint_url, agent_card_url, agent_card_json,
		       task_visibility_mode, auth_type, encrypted_auth_secret, encrypted_auth_dek,
		       max_task_iterations, max_task_budget_micros, is_active, is_killed,
		       created_at, updated_at
		FROM a2a_agents WHERE (org_id = $1 OR $1 = '') AND slug = $2 LIMIT 1`
	var a domain.A2AAgent
	if err := p.pool.QueryRow(ctx, q, orgID, slug).Scan(
		&a.ID, &a.OrgID, &a.Name, &a.Slug, &a.EndpointURL, &a.AgentCardURL, &a.AgentCardJSON,
		&a.TaskVisibilityMode, &a.AuthType, &a.EncryptedAuthSecret, &a.EncryptedAuthDEK,
		&a.MaxTaskIterations, &a.MaxTaskBudgetMicros, &a.IsActive, &a.IsKilled,
		&a.CreatedAt, &a.UpdatedAt,
	); err != nil {
		return nil, fmt.Errorf("a2a agent %q not found: %w", slug, err)
	}
	_ = p.mem.CreateA2AAgent(ctx, &a)
	return &a, nil
}

func (p *PostgresRepository) ListA2AAgents(ctx context.Context, orgID string) ([]*domain.A2AAgent, error) {
	const q = `
		SELECT id, org_id, name, slug, endpoint_url, agent_card_url, agent_card_json,
		       task_visibility_mode, auth_type, encrypted_auth_secret, encrypted_auth_dek,
		       max_task_iterations, max_task_budget_micros, is_active, is_killed,
		       created_at, updated_at
		FROM a2a_agents WHERE org_id = $1 OR $1 = '' ORDER BY name ASC`
	rows, err := p.pool.Query(ctx, q, orgID)
	if err != nil {
		return p.mem.ListA2AAgents(ctx, orgID)
	}
	defer rows.Close()

	var out []*domain.A2AAgent
	for rows.Next() {
		var a domain.A2AAgent
		if err := rows.Scan(
			&a.ID, &a.OrgID, &a.Name, &a.Slug, &a.EndpointURL, &a.AgentCardURL, &a.AgentCardJSON,
			&a.TaskVisibilityMode, &a.AuthType, &a.EncryptedAuthSecret, &a.EncryptedAuthDEK,
			&a.MaxTaskIterations, &a.MaxTaskBudgetMicros, &a.IsActive, &a.IsKilled,
			&a.CreatedAt, &a.UpdatedAt,
		); err == nil {
			out = append(out, &a)
		}
	}
	return out, nil
}

func (p *PostgresRepository) SetA2AAgentKillSwitch(ctx context.Context, id string, killed bool) error {
	_, err := p.pool.Exec(ctx, `UPDATE a2a_agents SET is_killed = $2, updated_at = NOW() WHERE id = $1`, id, killed)
	_ = p.mem.SetA2AAgentKillSwitch(ctx, id, killed)
	return err
}

func (p *PostgresRepository) CreateA2ATask(ctx context.Context, task *domain.A2ATask) error {
	if task.ID == "" {
		task.ID = uuid.NewString()
	}
	const q = `
		INSERT INTO a2a_tasks (
			id, agent_id, org_id, team_id, virtual_key_id, user_id, client_task_id,
			state, last_event_seq, input_message_json, output_message_json, total_cost_micros
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`
	if _, err := p.pool.Exec(ctx, q,
		task.ID, task.AgentID, task.OrgID, task.TeamID, task.VirtualKeyID, task.UserID, task.ClientTaskID,
		task.State, task.LastEventSeq, task.InputMessageJSON, task.OutputMessageJSON, task.TotalCostMicros,
	); err != nil {
		return err
	}
	return p.mem.CreateA2ATask(ctx, task)
}

func (p *PostgresRepository) UpdateA2ATaskState(ctx context.Context, taskID, state string, outputJSON string, costMicros int64) error {
	var completedAt *time.Time
	if state == domain.A2ATaskStateCompleted || state == domain.A2ATaskStateFailed || state == domain.A2ATaskStateCanceled {
		now := time.Now().UTC()
		completedAt = &now
	}
	const q = `
		UPDATE a2a_tasks SET
			state = $2,
			output_message_json = CASE WHEN $3 <> '' THEN $3 ELSE output_message_json END,
			total_cost_micros = total_cost_micros + $4,
			completed_at = COALESCE($5, completed_at),
			updated_at = NOW()
		WHERE id = $1`
	if _, err := p.pool.Exec(ctx, q, taskID, state, outputJSON, costMicros, completedAt); err != nil {
		return err
	}
	return p.mem.UpdateA2ATaskState(ctx, taskID, state, outputJSON, costMicros)
}

func (p *PostgresRepository) GetA2ATask(ctx context.Context, id string) (*domain.A2ATask, error) {
	if t, err := p.mem.GetA2ATask(ctx, id); err == nil && t != nil {
		return t, nil
	}
	const q = `
		SELECT id, agent_id, org_id, team_id, virtual_key_id, user_id, client_task_id,
		       state, last_event_seq, input_message_json, output_message_json, total_cost_micros,
		       created_at, updated_at, completed_at
		FROM a2a_tasks WHERE id = $1`
	var t domain.A2ATask
	if err := p.pool.QueryRow(ctx, q, id).Scan(
		&t.ID, &t.AgentID, &t.OrgID, &t.TeamID, &t.VirtualKeyID, &t.UserID, &t.ClientTaskID,
		&t.State, &t.LastEventSeq, &t.InputMessageJSON, &t.OutputMessageJSON, &t.TotalCostMicros,
		&t.CreatedAt, &t.UpdatedAt, &t.CompletedAt,
	); err != nil {
		return nil, fmt.Errorf("a2a task %s not found: %w", id, err)
	}
	_ = p.mem.CreateA2ATask(ctx, &t)
	return &t, nil
}

func (p *PostgresRepository) ListA2ATasks(ctx context.Context, agentID, virtualKeyID string, limit int) ([]*domain.A2ATask, error) {
	if limit <= 0 {
		limit = 50
	}
	const q = `
		SELECT id, agent_id, org_id, team_id, virtual_key_id, user_id, client_task_id,
		       state, last_event_seq, input_message_json, output_message_json, total_cost_micros,
		       created_at, updated_at, completed_at
		FROM a2a_tasks
		WHERE (agent_id = $1 OR $1 = '') AND (virtual_key_id = $2 OR $2 = '')
		ORDER BY created_at DESC LIMIT $3`
	rows, err := p.pool.Query(ctx, q, agentID, virtualKeyID, limit)
	if err != nil {
		return p.mem.ListA2ATasks(ctx, agentID, virtualKeyID, limit)
	}
	defer rows.Close()

	var out []*domain.A2ATask
	for rows.Next() {
		var t domain.A2ATask
		if err := rows.Scan(
			&t.ID, &t.AgentID, &t.OrgID, &t.TeamID, &t.VirtualKeyID, &t.UserID, &t.ClientTaskID,
			&t.State, &t.LastEventSeq, &t.InputMessageJSON, &t.OutputMessageJSON, &t.TotalCostMicros,
			&t.CreatedAt, &t.UpdatedAt, &t.CompletedAt,
		); err == nil {
			out = append(out, &t)
		}
	}
	return out, nil
}

func (p *PostgresRepository) AppendA2ATaskEvent(ctx context.Context, taskID, eventType, payloadJSON string) (*domain.A2ATaskEvent, error) {
	tx, err := p.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("begin task event tx: %w", err)
	}
	defer tx.Rollback(ctx)

	// Atomic sequence increment with row lock on task:
	var nextSeq int64
	err = tx.QueryRow(ctx, `
		UPDATE a2a_tasks 
		SET last_event_seq = last_event_seq + 1, updated_at = NOW() 
		WHERE id = $1 
		RETURNING last_event_seq
	`, taskID).Scan(&nextSeq)
	if err != nil {
		return nil, fmt.Errorf("increment task event sequence: %w", err)
	}

	eventID := uuid.NewString()
	now := time.Now().UTC()
	_, err = tx.Exec(ctx, `
		INSERT INTO a2a_task_events (id, task_id, event_seq, event_type, payload_json, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`, eventID, taskID, nextSeq, eventType, payloadJSON, now)
	if err != nil {
		return nil, fmt.Errorf("insert a2a task event: %w", err)
	}

	// Insert into stream publications for background Redis Pub/Sub broadcast
	pubID := uuid.NewString()
	_, err = tx.Exec(ctx, `
		INSERT INTO a2a_stream_publications (id, task_id, event_seq, payload_json, published, created_at)
		VALUES ($1, $2, $3, $4, FALSE, $5)
	`, pubID, taskID, nextSeq, payloadJSON, now)
	if err != nil {
		return nil, fmt.Errorf("insert a2a stream publication: %w", err)
	}

	// Enqueue webhook notification if push config is registered for this task
	var targetURL string
	_ = tx.QueryRow(ctx, `SELECT target_url FROM a2a_push_notification_configs WHERE task_id = $1`, taskID).Scan(&targetURL)
	if targetURL != "" {
		outboxID := uuid.NewString()
		_, _ = tx.Exec(ctx, `
			INSERT INTO a2a_outbox_events (id, task_id, event_type, target_url, payload_json, status, created_at)
			VALUES ($1, $2, $3, $4, $5, 'pending', $6)
		`, outboxID, taskID, eventType, targetURL, payloadJSON, now)
	}

	if err := tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("commit task event tx: %w", err)
	}

	event := &domain.A2ATaskEvent{
		ID:          eventID,
		TaskID:      taskID,
		EventSeq:    nextSeq,
		EventType:   eventType,
		PayloadJSON: payloadJSON,
		CreatedAt:   now,
	}
	_, _ = p.mem.AppendA2ATaskEvent(ctx, taskID, eventType, payloadJSON)
	return event, nil
}

func (p *PostgresRepository) ListA2ATaskEvents(ctx context.Context, taskID string, afterSeq int64, limit int) ([]*domain.A2ATaskEvent, error) {
	if limit <= 0 {
		limit = 100
	}
	const q = `
		SELECT id, task_id, event_seq, event_type, payload_json, created_at
		FROM a2a_task_events
		WHERE task_id = $1 AND event_seq > $2
		ORDER BY event_seq ASC LIMIT $3`
	rows, err := p.pool.Query(ctx, q, taskID, afterSeq, limit)
	if err != nil {
		return p.mem.ListA2ATaskEvents(ctx, taskID, afterSeq, limit)
	}
	defer rows.Close()

	var out []*domain.A2ATaskEvent
	for rows.Next() {
		var e domain.A2ATaskEvent
		if err := rows.Scan(&e.ID, &e.TaskID, &e.EventSeq, &e.EventType, &e.PayloadJSON, &e.CreatedAt); err == nil {
			out = append(out, &e)
		}
	}
	return out, nil
}

func (p *PostgresRepository) ClaimPendingA2AStreamPublications(ctx context.Context, batchSize int) ([]*domain.A2AStreamPublication, error) {
	if batchSize <= 0 {
		batchSize = 50
	}
	const q = `
		UPDATE a2a_stream_publications SET
			attempt_count = attempt_count + 1,
			next_attempt_at = NOW() + INTERVAL '5 seconds'
		WHERE id IN (
			SELECT id FROM a2a_stream_publications
			WHERE NOT published AND next_attempt_at <= NOW()
			ORDER BY next_attempt_at ASC
			LIMIT $1
			FOR UPDATE SKIP LOCKED
		)
		RETURNING id, task_id, event_seq, payload_json, published, attempt_count, next_attempt_at, created_at`
	rows, err := p.pool.Query(ctx, q, batchSize)
	if err != nil {
		return p.mem.ClaimPendingA2AStreamPublications(ctx, batchSize)
	}
	defer rows.Close()

	var out []*domain.A2AStreamPublication
	for rows.Next() {
		var pub domain.A2AStreamPublication
		if err := rows.Scan(&pub.ID, &pub.TaskID, &pub.EventSeq, &pub.PayloadJSON, &pub.Published, &pub.AttemptCount, &pub.NextAttemptAt, &pub.CreatedAt); err == nil {
			out = append(out, &pub)
		}
	}
	return out, nil
}

func (p *PostgresRepository) MarkA2AStreamPublicationSuccess(ctx context.Context, id string) error {
	_, err := p.pool.Exec(ctx, `UPDATE a2a_stream_publications SET published = TRUE WHERE id = $1`, id)
	_ = p.mem.MarkA2AStreamPublicationSuccess(ctx, id)
	return err
}

func (p *PostgresRepository) CreateA2AOutboxEvent(ctx context.Context, event *domain.A2AOutboxEvent) error {
	if event.ID == "" {
		event.ID = uuid.NewString()
	}
	const q = `
		INSERT INTO a2a_outbox_events (id, task_id, event_type, target_url, payload_json, status)
		VALUES ($1, $2, $3, $4, $5, $6)`
	if _, err := p.pool.Exec(ctx, q, event.ID, event.TaskID, event.EventType, event.TargetURL, event.PayloadJSON, event.Status); err != nil {
		return err
	}
	return p.mem.CreateA2AOutboxEvent(ctx, event)
}

func (p *PostgresRepository) ClaimPendingA2AOutboxEvents(ctx context.Context, batchSize int) ([]*domain.A2AOutboxEvent, error) {
	if batchSize <= 0 {
		batchSize = 25
	}
	const q = `
		UPDATE a2a_outbox_events SET
			attempt_count = attempt_count + 1,
			next_attempt_at = NOW() + INTERVAL '10 seconds'
		WHERE id IN (
			SELECT id FROM a2a_outbox_events
			WHERE status = 'pending' AND next_attempt_at <= NOW()
			ORDER BY next_attempt_at ASC
			LIMIT $1
			FOR UPDATE SKIP LOCKED
		)
		RETURNING id, task_id, event_type, target_url, payload_json, status, attempt_count, next_attempt_at, created_at`
	rows, err := p.pool.Query(ctx, q, batchSize)
	if err != nil {
		return p.mem.ClaimPendingA2AOutboxEvents(ctx, batchSize)
	}
	defer rows.Close()

	var out []*domain.A2AOutboxEvent
	for rows.Next() {
		var o domain.A2AOutboxEvent
		if err := rows.Scan(&o.ID, &o.TaskID, &o.EventType, &o.TargetURL, &o.PayloadJSON, &o.Status, &o.AttemptCount, &o.NextAttemptAt, &o.CreatedAt); err == nil {
			out = append(out, &o)
		}
	}
	return out, nil
}

func (p *PostgresRepository) UpdateA2AOutboxEventStatus(ctx context.Context, id, status string) error {
	_, err := p.pool.Exec(ctx, `UPDATE a2a_outbox_events SET status = $2 WHERE id = $1`, id, status)
	_ = p.mem.UpdateA2AOutboxEventStatus(ctx, id, status)
	return err
}

func (p *PostgresRepository) GetA2AOutboxEvent(ctx context.Context, id string) (*domain.A2AOutboxEvent, error) {
	if ev, err := p.mem.GetA2AOutboxEvent(ctx, id); err == nil && ev != nil {
		return ev, nil
	}
	const q = `SELECT id, task_id, event_type, target_url, payload_json, status, attempt_count, next_attempt_at, created_at FROM a2a_outbox_events WHERE id = $1`
	var o domain.A2AOutboxEvent
	if err := p.pool.QueryRow(ctx, q, id).Scan(&o.ID, &o.TaskID, &o.EventType, &o.TargetURL, &o.PayloadJSON, &o.Status, &o.AttemptCount, &o.NextAttemptAt, &o.CreatedAt); err != nil {
		return nil, fmt.Errorf("outbox event %s not found: %w", id, err)
	}
	return &o, nil
}

func (p *PostgresRepository) SetA2APushNotificationConfig(ctx context.Context, cfg *domain.A2APushNotificationConfig) error {
	if cfg.ID == "" {
		cfg.ID = uuid.NewString()
	}
	const q = `
		INSERT INTO a2a_push_notification_configs (id, task_id, target_url, auth_token)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (task_id) DO UPDATE SET
			target_url = EXCLUDED.target_url,
			auth_token = EXCLUDED.auth_token`
	if _, err := p.pool.Exec(ctx, q, cfg.ID, cfg.TaskID, cfg.TargetURL, cfg.AuthToken); err != nil {
		return err
	}
	return p.mem.SetA2APushNotificationConfig(ctx, cfg)
}

func (p *PostgresRepository) GetA2APushNotificationConfig(ctx context.Context, taskID string) (*domain.A2APushNotificationConfig, error) {
	if c, err := p.mem.GetA2APushNotificationConfig(ctx, taskID); err == nil && c != nil {
		return c, nil
	}
	const q = `SELECT id, task_id, target_url, auth_token, created_at FROM a2a_push_notification_configs WHERE task_id = $1`
	var cfg domain.A2APushNotificationConfig
	if err := p.pool.QueryRow(ctx, q, taskID).Scan(&cfg.ID, &cfg.TaskID, &cfg.TargetURL, &cfg.AuthToken, &cfg.CreatedAt); err != nil {
		return nil, fmt.Errorf("push notification config for task %s not found: %w", taskID, err)
	}
	_ = p.mem.SetA2APushNotificationConfig(ctx, &cfg)
	return &cfg, nil
}

// Files Management

func (p *PostgresRepository) CreateFile(ctx context.Context, file *domain.CanonicalFile) error {
	if file.ID == "" {
		file.ID = uuid.NewString()
	}
	if file.CreatedAt.IsZero() {
		file.CreatedAt = time.Now().UTC()
	}
	const q = `
		INSERT INTO files (id, org_id, team_id, user_id, bytes, created_at, filename, purpose, status, content_sha256, storage_path, upstream_provider, upstream_id, expires_at)
		VALUES ($1, $2, NULLIF($3, '')::uuid, NULLIF($4, '')::uuid, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`
	_, err := p.pool.Exec(ctx, q, file.ID, file.OrgID, file.TeamID, file.UserID, file.Bytes, file.CreatedAt, file.Filename, file.Purpose, file.Status, file.ContentSHA256, file.StoragePath, file.UpstreamProvider, file.UpstreamID, file.ExpiresAt)
	if err != nil {
		return err
	}
	return p.mem.CreateFile(ctx, file)
}

func (p *PostgresRepository) GetFile(ctx context.Context, orgID, fileID string) (*domain.CanonicalFile, error) {
	if f, err := p.mem.GetFile(ctx, orgID, fileID); err == nil && f != nil {
		return f, nil
	}
	const q = `
		SELECT id, org_id, COALESCE(team_id::text, ''), COALESCE(user_id::text, ''), bytes, created_at, filename, purpose, status, content_sha256, storage_path, COALESCE(upstream_provider, ''), COALESCE(upstream_id, ''), expires_at
		FROM files WHERE id = $1 AND ($2 = '' OR org_id = $2::uuid)`
	var f domain.CanonicalFile
	if err := p.pool.QueryRow(ctx, q, fileID, orgID).Scan(
		&f.ID, &f.OrgID, &f.TeamID, &f.UserID, &f.Bytes, &f.CreatedAt, &f.Filename, &f.Purpose, &f.Status, &f.ContentSHA256, &f.StoragePath, &f.UpstreamProvider, &f.UpstreamID, &f.ExpiresAt,
	); err != nil {
		return nil, fmt.Errorf("file %s not found: %w", fileID, err)
	}
	_ = p.mem.CreateFile(ctx, &f)
	return &f, nil
}

func (p *PostgresRepository) ListFiles(ctx context.Context, orgID string, purpose string) ([]*domain.CanonicalFile, error) {
	const q = `
		SELECT id, org_id, COALESCE(team_id::text, ''), COALESCE(user_id::text, ''), bytes, created_at, filename, purpose, status, content_sha256, storage_path, COALESCE(upstream_provider, ''), COALESCE(upstream_id, ''), expires_at
		FROM files WHERE ($1 = '' OR org_id = $1::uuid) AND ($2 = '' OR purpose = $2)
		ORDER BY created_at DESC`
	rows, err := p.pool.Query(ctx, q, orgID, purpose)
	if err != nil {
		return p.mem.ListFiles(ctx, orgID, purpose)
	}
	defer rows.Close()
	var out []*domain.CanonicalFile
	for rows.Next() {
		var f domain.CanonicalFile
		if err := rows.Scan(
			&f.ID, &f.OrgID, &f.TeamID, &f.UserID, &f.Bytes, &f.CreatedAt, &f.Filename, &f.Purpose, &f.Status, &f.ContentSHA256, &f.StoragePath, &f.UpstreamProvider, &f.UpstreamID, &f.ExpiresAt,
		); err == nil {
			out = append(out, &f)
			_ = p.mem.CreateFile(ctx, &f)
		}
	}
	return out, nil
}

func (p *PostgresRepository) DeleteFile(ctx context.Context, orgID, fileID string) error {
	const q = `DELETE FROM files WHERE id = $1 AND ($2 = '' OR org_id = $2::uuid)`
	if _, err := p.pool.Exec(ctx, q, fileID, orgID); err != nil {
		return err
	}
	return p.mem.DeleteFile(ctx, orgID, fileID)
}

// Batches Management

func (p *PostgresRepository) CreateBatch(ctx context.Context, batch *domain.CanonicalBatch) error {
	if batch.ID == "" {
		batch.ID = uuid.NewString()
	}
	if batch.CreatedAt.IsZero() {
		batch.CreatedAt = time.Now().UTC()
	}
	metaJSON, _ := json.Marshal(batch.Metadata)
	countsJSON, _ := json.Marshal(batch.RequestCounts)
	const q = `
		INSERT INTO batches (id, org_id, team_id, input_file_id, output_file_id, error_file_id, endpoint, status, completion_window, created_at, completed_at, metadata, request_counts, upstream_provider, upstream_id)
		VALUES ($1, $2, NULLIF($3, '')::uuid, $4, NULLIF($5, ''), NULLIF($6, ''), $7, $8, $9, $10, $11, $12, $13, $14, $15)`
	_, err := p.pool.Exec(ctx, q, batch.ID, batch.OrgID, batch.TeamID, batch.InputFileID, batch.OutputFileID, batch.ErrorFileID, batch.Endpoint, batch.Status, batch.CompletionWindow, batch.CreatedAt, batch.CompletedAt, metaJSON, countsJSON, batch.UpstreamProvider, batch.UpstreamID)
	if err != nil {
		return err
	}
	return p.mem.CreateBatch(ctx, batch)
}

func (p *PostgresRepository) GetBatch(ctx context.Context, orgID, batchID string) (*domain.CanonicalBatch, error) {
	if b, err := p.mem.GetBatch(ctx, orgID, batchID); err == nil && b != nil {
		return b, nil
	}
	const q = `
		SELECT id, org_id, COALESCE(team_id::text, ''), input_file_id, COALESCE(output_file_id, ''), COALESCE(error_file_id, ''), endpoint, status, completion_window, created_at, completed_at, metadata, request_counts, COALESCE(upstream_provider, ''), COALESCE(upstream_id, '')
		FROM batches WHERE id = $1 AND ($2 = '' OR org_id = $2::uuid)`
	var b domain.CanonicalBatch
	var metaJSON, countsJSON []byte
	if err := p.pool.QueryRow(ctx, q, batchID, orgID).Scan(
		&b.ID, &b.OrgID, &b.TeamID, &b.InputFileID, &b.OutputFileID, &b.ErrorFileID, &b.Endpoint, &b.Status, &b.CompletionWindow, &b.CreatedAt, &b.CompletedAt, &metaJSON, &countsJSON, &b.UpstreamProvider, &b.UpstreamID,
	); err != nil {
		return nil, fmt.Errorf("batch %s not found: %w", batchID, err)
	}
	_ = json.Unmarshal(metaJSON, &b.Metadata)
	_ = json.Unmarshal(countsJSON, &b.RequestCounts)
	_ = p.mem.CreateBatch(ctx, &b)
	return &b, nil
}

func (p *PostgresRepository) ListBatches(ctx context.Context, orgID string, limit int) ([]*domain.CanonicalBatch, error) {
	if limit <= 0 {
		limit = 50
	}
	const q = `
		SELECT id, org_id, COALESCE(team_id::text, ''), input_file_id, COALESCE(output_file_id, ''), COALESCE(error_file_id, ''), endpoint, status, completion_window, created_at, completed_at, metadata, request_counts, COALESCE(upstream_provider, ''), COALESCE(upstream_id, '')
		FROM batches WHERE ($1 = '' OR org_id = $1::uuid)
		ORDER BY created_at DESC LIMIT $2`
	rows, err := p.pool.Query(ctx, q, orgID, limit)
	if err != nil {
		return p.mem.ListBatches(ctx, orgID, limit)
	}
	defer rows.Close()
	var out []*domain.CanonicalBatch
	for rows.Next() {
		var b domain.CanonicalBatch
		var metaJSON, countsJSON []byte
		if err := rows.Scan(
			&b.ID, &b.OrgID, &b.TeamID, &b.InputFileID, &b.OutputFileID, &b.ErrorFileID, &b.Endpoint, &b.Status, &b.CompletionWindow, &b.CreatedAt, &b.CompletedAt, &metaJSON, &countsJSON, &b.UpstreamProvider, &b.UpstreamID,
		); err == nil {
			_ = json.Unmarshal(metaJSON, &b.Metadata)
			_ = json.Unmarshal(countsJSON, &b.RequestCounts)
			out = append(out, &b)
			_ = p.mem.CreateBatch(ctx, &b)
		}
	}
	return out, nil
}

func (p *PostgresRepository) UpdateBatchStatus(ctx context.Context, batchID string, status string, outputFileID string, counts domain.BatchCounts, completedAt *time.Time) error {
	countsJSON, _ := json.Marshal(counts)
	const q = `UPDATE batches SET status = $1, output_file_id = COALESCE(NULLIF($2, ''), output_file_id), request_counts = $3, completed_at = $4 WHERE id = $5`
	if _, err := p.pool.Exec(ctx, q, status, outputFileID, countsJSON, completedAt, batchID); err != nil {
		return err
	}
	return p.mem.UpdateBatchStatus(ctx, batchID, status, outputFileID, counts, completedAt)
}
