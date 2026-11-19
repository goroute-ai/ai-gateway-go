package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func (p *PostgresRepository) CreateProviderCredential(ctx context.Context, cred *domain.ProviderCredential) error {
	if p.pool == nil {
		return p.mem.CreateProviderCredential(ctx, cred)
	}
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

const providerCredentialSelectCols = `id, org_id, provider, name, base_url, COALESCE(azure_deployment_name, ''), COALESCE(api_version, ''), encrypted_api_key, data_nonce, encrypted_dek, dek_nonce, key_version, expires_at, last_rotated_at, last_validated_at, is_active`

func scanProviderCredential(row rowScanner) (*domain.ProviderCredential, error) {
	var c domain.ProviderCredential
	var prov string
	if err := row.Scan(
		&c.ID, &c.OrgID, &prov, &c.Name, &c.BaseURL, &c.AzureDeploymentName, &c.APIVersion,
		&c.EncryptedAPIKey, &c.DataNonce, &c.EncryptedDEK, &c.DEKNonce,
		&c.KeyVersion, &c.ExpiresAt, &c.LastRotatedAt, &c.LastValidatedAt, &c.IsActive,
	); err != nil {
		return nil, err
	}
	c.Provider = domain.ProviderType(prov)
	return &c, nil
}

func (p *PostgresRepository) GetProviderCredential(ctx context.Context, id string) (*domain.ProviderCredential, error) {
	if p.pool == nil {
		return p.mem.GetProviderCredential(ctx, id)
	}
	const q = `SELECT ` + providerCredentialSelectCols + ` FROM provider_credentials WHERE id = $1`
	c, err := scanProviderCredential(p.pool.QueryRow(ctx, q, id))
	if err != nil {
		return nil, fmt.Errorf("credential not found: %w", err)
	}
	_ = p.mem.CreateProviderCredential(ctx, c)
	return c, nil
}

func (p *PostgresRepository) hydrateProviderCredentials(ctx context.Context, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
	const q = `SELECT ` + providerCredentialSelectCols + ` FROM provider_credentials WHERE id = ANY($1)`
	rows, err := p.pool.Query(ctx, q, ids)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		c, err := scanProviderCredential(rows)
		if err != nil {
			return err
		}
		_ = p.mem.CreateProviderCredential(ctx, c)
	}
	return rows.Err()
}

func (p *PostgresRepository) UpdateProviderCredential(ctx context.Context, cred *domain.ProviderCredential) error {
	if p.pool == nil {
		return p.mem.UpdateProviderCredential(ctx, cred)
	}
	kv := cred.KeyVersion
	if kv <= 0 {
		kv = 1
	}
	if _, err := p.pool.Exec(ctx, `
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
	); err != nil {
		return err
	}
	if err := p.mem.UpdateProviderCredential(ctx, cred); err != nil {
		_ = p.mem.CreateProviderCredential(ctx, cred)
	}
	return nil
}

func (p *PostgresRepository) ListProviderCredentials(ctx context.Context, orgID string) ([]*domain.ProviderCredential, error) {
	if p.pool == nil {
		return p.mem.ListProviderCredentials(ctx, orgID)
	}
	const q = `SELECT ` + providerCredentialSelectCols + ` FROM provider_credentials WHERE ($1 = '' OR org_id = $1) ORDER BY name ASC`
	rows, err := p.pool.Query(ctx, q, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*domain.ProviderCredential
	for rows.Next() {
		c, err := scanProviderCredential(rows)
		if err != nil {
			return nil, err
		}
		_ = p.mem.CreateProviderCredential(ctx, c)
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func isJSONObjectNonEmpty(raw []byte) bool {
	trimmed := strings.TrimSpace(string(raw))
	return trimmed != "" && trimmed != "{}" && trimmed != "null"
}

const modelGroupSelectCols = `id, org_id, alias, description, routing_strategy, fallback_group_ids, COALESCE(context_window_fallbacks, '[]'::jsonb), COALESCE(content_policy_fallbacks, '[]'::jsonb), COALESCE(fallback_targets, '[]'::jsonb), COALESCE(saturation_fallbacks, '[]'::jsonb), drop_unsupported_params, disable_cooldowns, COALESCE(retry_policy, '{}'::jsonb), COALESCE(cooldown_policy, '{}'::jsonb), max_retries, cooldown_seconds, failure_threshold, is_active`

func scanModelGroup(row rowScanner) (*domain.ModelGroup, error) {
	var g domain.ModelGroup
	var strat string
	var fbs []string
	var rawCtxFbs, rawContentFbs, rawTargets, rawSatFbs, rawRetry, rawCooldown []byte
	if err := row.Scan(
		&g.ID, &g.OrgID, &g.Alias, &g.Description, &strat, &fbs,
		&rawCtxFbs, &rawContentFbs, &rawTargets, &rawSatFbs, &g.DropUnsupportedParams, &g.DisableCooldowns, &rawRetry, &rawCooldown,
		&g.MaxRetries, &g.CooldownSeconds, &g.FailureThreshold, &g.IsActive,
	); err != nil {
		return nil, err
	}
	g.RoutingStrategy = domain.RoutingStrategy(strat)
	g.FallbackGroupIDs = fbs
	if g.FallbackGroupIDs == nil {
		g.FallbackGroupIDs = []string{}
	}
	if len(rawCtxFbs) > 0 {
		_ = json.Unmarshal(rawCtxFbs, &g.ContextWindowFallbacks)
	}
	if len(rawContentFbs) > 0 {
		_ = json.Unmarshal(rawContentFbs, &g.ContentPolicyFallbacks)
	}
	if len(rawTargets) > 0 {
		_ = json.Unmarshal(rawTargets, &g.FallbackTargets)
	}
	if len(rawSatFbs) > 0 {
		_ = json.Unmarshal(rawSatFbs, &g.SaturationFallbacks)
	}
	if isJSONObjectNonEmpty(rawRetry) {
		var rp domain.RetryPolicy
		if err := json.Unmarshal(rawRetry, &rp); err == nil {
			g.RetryPolicy = &rp
		}
	}
	if isJSONObjectNonEmpty(rawCooldown) {
		var cp domain.CooldownPolicy
		if err := json.Unmarshal(rawCooldown, &cp); err == nil {
			g.CooldownPolicy = &cp
		}
	}
	return &g, nil
}

func (p *PostgresRepository) CreateModelGroup(ctx context.Context, mg *domain.ModelGroup) error {
	if mg.ID == "" {
		mg.ID = uuid.NewString()
	}
	if p.pool == nil {
		return p.mem.CreateModelGroup(ctx, mg)
	}
	fbs := mg.FallbackGroupIDs
	if fbs == nil {
		fbs = []string{}
	}
	ctxFbsJSON, err := marshalJSONOrDefault(mg.ContextWindowFallbacks, "[]")
	if err != nil {
		return fmt.Errorf("marshal context_window_fallbacks: %w", err)
	}
	contentFbsJSON, err := marshalJSONOrDefault(mg.ContentPolicyFallbacks, "[]")
	if err != nil {
		return fmt.Errorf("marshal content_policy_fallbacks: %w", err)
	}
	targetsJSON, err := marshalJSONOrDefault(mg.FallbackTargets, "[]")
	if err != nil {
		return fmt.Errorf("marshal fallback_targets: %w", err)
	}
	satFbsJSON, err := marshalJSONOrDefault(mg.SaturationFallbacks, "[]")
	if err != nil {
		return fmt.Errorf("marshal saturation_fallbacks: %w", err)
	}
	retryJSON, err := marshalJSONOrDefault(mg.RetryPolicy, "{}")
	if err != nil {
		return fmt.Errorf("marshal retry_policy: %w", err)
	}
	cooldownJSON, err := marshalJSONOrDefault(mg.CooldownPolicy, "{}")
	if err != nil {
		return fmt.Errorf("marshal cooldown_policy: %w", err)
	}
	const q = `
		INSERT INTO model_groups (
			id, org_id, alias, description, routing_strategy, fallback_group_ids,
			context_window_fallbacks, content_policy_fallbacks, fallback_targets,
			saturation_fallbacks, drop_unsupported_params, disable_cooldowns,
			retry_policy, cooldown_policy, max_retries, cooldown_seconds, failure_threshold, is_active
		)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)
		ON CONFLICT (org_id, alias) DO UPDATE SET
			routing_strategy = EXCLUDED.routing_strategy,
			fallback_group_ids = EXCLUDED.fallback_group_ids,
			context_window_fallbacks = EXCLUDED.context_window_fallbacks,
			content_policy_fallbacks = EXCLUDED.content_policy_fallbacks,
			fallback_targets = EXCLUDED.fallback_targets,
			saturation_fallbacks = EXCLUDED.saturation_fallbacks,
			drop_unsupported_params = EXCLUDED.drop_unsupported_params,
			disable_cooldowns = EXCLUDED.disable_cooldowns,
			retry_policy = EXCLUDED.retry_policy,
			cooldown_policy = EXCLUDED.cooldown_policy,
			updated_at = NOW()
		RETURNING id`
	if err := p.pool.QueryRow(ctx, q,
		mg.ID, mg.OrgID, mg.Alias, mg.Description, string(mg.RoutingStrategy), fbs,
		ctxFbsJSON, contentFbsJSON, targetsJSON,
		satFbsJSON, mg.DropUnsupportedParams, mg.DisableCooldowns,
		retryJSON, cooldownJSON,
		mg.MaxRetries, mg.CooldownSeconds, mg.FailureThreshold, mg.IsActive,
	).Scan(&mg.ID); err != nil {
		return err
	}
	return p.mem.CreateModelGroup(ctx, mg)
}

func (p *PostgresRepository) GetModelGroupByAlias(ctx context.Context, orgID, alias string) (*domain.ModelGroup, error) {
	if p.pool == nil {
		return p.mem.GetModelGroupByAlias(ctx, orgID, alias)
	}
	const q = `SELECT ` + modelGroupSelectCols + ` FROM model_groups WHERE org_id = $1 AND alias = $2`
	g, err := scanModelGroup(p.pool.QueryRow(ctx, q, orgID, alias))
	if err != nil {
		return nil, fmt.Errorf("model group not found: %w", err)
	}
	_ = p.mem.CreateModelGroup(ctx, g)
	return g, nil
}

func (p *PostgresRepository) GetModelGroupByID(ctx context.Context, id string) (*domain.ModelGroup, error) {
	if p.pool == nil {
		return p.mem.GetModelGroupByID(ctx, id)
	}
	const q = `SELECT ` + modelGroupSelectCols + ` FROM model_groups WHERE id = $1`
	g, err := scanModelGroup(p.pool.QueryRow(ctx, q, id))
	if err != nil {
		return nil, fmt.Errorf("model group not found: %w", err)
	}
	_ = p.mem.CreateModelGroup(ctx, g)
	return g, nil
}

func (p *PostgresRepository) ListModelGroups(ctx context.Context, orgID string) ([]*domain.ModelGroup, error) {
	if p.pool == nil {
		return p.mem.ListModelGroups(ctx, orgID)
	}
	const q = `SELECT ` + modelGroupSelectCols + ` FROM model_groups WHERE ($1 = '' OR org_id = $1) ORDER BY alias ASC`
	rows, err := p.pool.Query(ctx, q, orgID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*domain.ModelGroup
	for rows.Next() {
		g, err := scanModelGroup(rows)
		if err != nil {
			return nil, err
		}
		_ = p.mem.CreateModelGroup(ctx, g)
		out = append(out, g)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (p *PostgresRepository) UpdateModelGroup(ctx context.Context, mg *domain.ModelGroup) error {
	if mg == nil || strings.TrimSpace(mg.ID) == "" {
		return fmt.Errorf("model group id is required")
	}
	if p.pool == nil {
		return p.mem.UpdateModelGroup(ctx, mg)
	}
	fbs := mg.FallbackGroupIDs
	if fbs == nil {
		fbs = []string{}
	}
	ctxFbsJSON, err := marshalJSONOrDefault(mg.ContextWindowFallbacks, "[]")
	if err != nil {
		return fmt.Errorf("marshal context_window_fallbacks: %w", err)
	}
	contentFbsJSON, err := marshalJSONOrDefault(mg.ContentPolicyFallbacks, "[]")
	if err != nil {
		return fmt.Errorf("marshal content_policy_fallbacks: %w", err)
	}
	targetsJSON, err := marshalJSONOrDefault(mg.FallbackTargets, "[]")
	if err != nil {
		return fmt.Errorf("marshal fallback_targets: %w", err)
	}
	satFbsJSON, err := marshalJSONOrDefault(mg.SaturationFallbacks, "[]")
	if err != nil {
		return fmt.Errorf("marshal saturation_fallbacks: %w", err)
	}
	retryJSON, err := marshalJSONOrDefault(mg.RetryPolicy, "{}")
	if err != nil {
		return fmt.Errorf("marshal retry_policy: %w", err)
	}
	cooldownJSON, err := marshalJSONOrDefault(mg.CooldownPolicy, "{}")
	if err != nil {
		return fmt.Errorf("marshal cooldown_policy: %w", err)
	}
	if mg.RoutingStrategy == "" {
		mg.RoutingStrategy = domain.StrategyWeightedShuffle
	}
	const q = `
		UPDATE model_groups SET
			alias = $2,
			description = $3,
			routing_strategy = $4,
			fallback_group_ids = $5,
			context_window_fallbacks = $6,
			content_policy_fallbacks = $7,
			fallback_targets = $8,
			saturation_fallbacks = $9,
			drop_unsupported_params = $10,
			disable_cooldowns = $11,
			retry_policy = $12,
			cooldown_policy = $13,
			max_retries = $14,
			cooldown_seconds = $15,
			failure_threshold = $16,
			is_active = $17,
			updated_at = NOW()
		WHERE id = $1
		RETURNING updated_at`
	if err := p.pool.QueryRow(ctx, q,
		mg.ID, mg.Alias, mg.Description, string(mg.RoutingStrategy), fbs,
		ctxFbsJSON, contentFbsJSON, targetsJSON, satFbsJSON, mg.DropUnsupportedParams, mg.DisableCooldowns,
		retryJSON, cooldownJSON, mg.MaxRetries, mg.CooldownSeconds, mg.FailureThreshold, mg.IsActive,
	).Scan(&mg.UpdatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("model group %q %w", mg.ID, ErrNotFound)
		}
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return fmt.Errorf("model group alias %q already exists in organization: %w", mg.Alias, ErrConflict)
		}
		return err
	}
	if err := p.mem.UpdateModelGroup(ctx, mg); err != nil && errors.Is(err, ErrNotFound) {
		_ = p.mem.CreateModelGroup(ctx, mg)
	}
	return nil
}

func (p *PostgresRepository) DeleteModelGroup(ctx context.Context, id string) error {
	if p.pool == nil {
		return p.mem.DeleteModelGroup(ctx, id)
	}
	tag, err := p.pool.Exec(ctx, `DELETE FROM model_groups WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("model group %q %w", id, ErrNotFound)
	}
	_ = p.mem.DeleteModelGroup(ctx, id)
	return nil
}

const deploymentSelectCols = `id, model_group_id, global_model_id, credential_id, deployment_name, region, weight, rpm_capacity, tpm_capacity, itpm_capacity, otpm_capacity, max_parallel_requests, timeout_ms, priority, status, COALESCE(tags, '{}'), max_budget_micros, COALESCE(budget_reset_period, 'monthly')`

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
	if p.pool == nil {
		return p.mem.CreateDeployment(ctx, dep)
	}
	resetPeriod := dep.BudgetResetPeriod
	if resetPeriod == "" {
		resetPeriod = string(domain.BudgetResetMonthly)
	}
	tags := dep.Tags
	if tags == nil {
		tags = []string{}
	}
	const q = `
		INSERT INTO model_deployments (id, model_group_id, global_model_id, credential_id, deployment_name, region, weight, rpm_capacity, tpm_capacity, itpm_capacity, otpm_capacity, max_parallel_requests, timeout_ms, priority, status, tags, max_budget_micros, budget_reset_period)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`
	if _, err := p.pool.Exec(ctx, q, dep.ID, dep.ModelGroupID, dep.GlobalModelID, dep.CredentialID, dep.DeploymentName, dep.Region, dep.Weight, dep.RPMCapacity, dep.TPMCapacity, dep.ITPMCapacity, dep.OTPMCapacity, dep.MaxParallelRequests, dep.TimeoutMs, dep.Priority, string(dep.Status), tags, dep.MaxBudgetMicros, resetPeriod); err != nil {
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

func (p *PostgresRepository) GetDeployment(ctx context.Context, id string) (*domain.Deployment, error) {
	if p.pool == nil {
		return p.mem.GetDeployment(ctx, id)
	}
	const q = `SELECT ` + deploymentSelectCols + ` FROM model_deployments WHERE id = $1`
	deps, err := p.loadAndHydrateDeployments(ctx, q, id)
	if err != nil {
		return nil, err
	}
	if len(deps) == 0 {
		return nil, fmt.Errorf("deployment %q %w", id, ErrNotFound)
	}
	return deps[0], nil
}

func (p *PostgresRepository) UpdateDeployment(ctx context.Context, dep *domain.Deployment) error {
	if dep == nil || strings.TrimSpace(dep.ID) == "" {
		return fmt.Errorf("deployment id is required")
	}
	if dep.Status == "" {
		dep.Status = domain.DeploymentStatusActive
	}
	if dep.Weight <= 0 {
		dep.Weight = 100
	}
	if p.pool == nil {
		return p.mem.UpdateDeployment(ctx, dep)
	}
	resetPeriod := dep.BudgetResetPeriod
	if resetPeriod == "" {
		resetPeriod = string(domain.BudgetResetMonthly)
	}
	tags := dep.Tags
	if tags == nil {
		tags = []string{}
	}
	const q = `
		UPDATE model_deployments SET
			deployment_name = $2,
			region = $3,
			weight = $4,
			rpm_capacity = $5,
			tpm_capacity = $6,
			itpm_capacity = $7,
			otpm_capacity = $8,
			max_parallel_requests = $9,
			timeout_ms = $10,
			priority = $11,
			status = $12,
			tags = $13,
			max_budget_micros = $14,
			budget_reset_period = $15,
			updated_at = NOW()
		WHERE id = $1
		RETURNING updated_at`
	if err := p.pool.QueryRow(ctx, q,
		dep.ID, dep.DeploymentName, dep.Region, dep.Weight,
		dep.RPMCapacity, dep.TPMCapacity, dep.ITPMCapacity, dep.OTPMCapacity, dep.MaxParallelRequests,
		dep.TimeoutMs, dep.Priority, string(dep.Status), tags, dep.MaxBudgetMicros, resetPeriod,
	).Scan(&dep.UpdatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("deployment %q %w", dep.ID, ErrNotFound)
		}
		return err
	}
	if dep.GlobalModel == nil && dep.GlobalModelID != "" {
		dep.GlobalModel, _ = p.GetGlobalModel(ctx, dep.GlobalModelID)
	}
	if dep.Credential == nil && dep.CredentialID != "" {
		dep.Credential, _ = p.GetProviderCredential(ctx, dep.CredentialID)
	}
	if err := p.mem.UpdateDeployment(ctx, dep); err != nil && errors.Is(err, ErrNotFound) {
		_ = p.mem.CreateDeployment(ctx, dep)
	}
	return nil
}

func (p *PostgresRepository) DeleteDeployment(ctx context.Context, id string) error {
	if p.pool == nil {
		return p.mem.DeleteDeployment(ctx, id)
	}
	tag, err := p.pool.Exec(ctx, `DELETE FROM model_deployments WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("deployment %q %w", id, ErrNotFound)
	}
	_ = p.mem.DeleteDeployment(ctx, id)
	return nil
}

func (p *PostgresRepository) loadAndHydrateDeployments(ctx context.Context, q string, args ...any) ([]*domain.Deployment, error) {
	rows, err := p.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	var deps []*domain.Deployment
	credSeen := make(map[string]struct{})
	modelSeen := make(map[string]struct{})
	var credIDs, modelIDs []string
	for rows.Next() {
		var d domain.Deployment
		var status string
		if err := rows.Scan(&d.ID, &d.ModelGroupID, &d.GlobalModelID, &d.CredentialID, &d.DeploymentName, &d.Region, &d.Weight, &d.RPMCapacity, &d.TPMCapacity, &d.ITPMCapacity, &d.OTPMCapacity, &d.MaxParallelRequests, &d.TimeoutMs, &d.Priority, &status, &d.Tags, &d.MaxBudgetMicros, &d.BudgetResetPeriod); err != nil {
			continue
		}
		if d.Tags == nil {
			d.Tags = []string{}
		}
		if status == "" {
			d.Status = domain.DeploymentStatusActive
		} else {
			d.Status = domain.DeploymentStatus(status)
		}
		if d.CredentialID != "" {
			if _, ok := credSeen[d.CredentialID]; !ok {
				credSeen[d.CredentialID] = struct{}{}
				credIDs = append(credIDs, d.CredentialID)
			}
		}
		if d.GlobalModelID != "" {
			if _, ok := modelSeen[d.GlobalModelID]; !ok {
				modelSeen[d.GlobalModelID] = struct{}{}
				modelIDs = append(modelIDs, d.GlobalModelID)
			}
		}
		deps = append(deps, &d)
	}
	rowsErr := rows.Err()
	// Close rows before issuing batch hydration queries to prevent pool exhaustion/deadlocks.
	rows.Close()
	if rowsErr != nil {
		return nil, rowsErr
	}

	if len(credIDs) > 0 {
		_ = p.hydrateProviderCredentials(ctx, credIDs)
	}
	if len(modelIDs) > 0 {
		_ = p.hydrateGlobalModels(ctx, modelIDs)
	}
	for _, d := range deps {
		if d.CredentialID != "" {
			if c, err := p.mem.GetProviderCredential(ctx, d.CredentialID); err == nil {
				d.Credential = c
			}
		}
		if d.GlobalModelID != "" {
			if gm, err := p.mem.GetGlobalModel(ctx, d.GlobalModelID); err == nil {
				d.GlobalModel = gm
			}
		}
		_ = p.mem.CreateDeployment(ctx, d)
	}
	return deps, nil
}

func (p *PostgresRepository) ListDeploymentsByGroup(ctx context.Context, groupID string) ([]*domain.Deployment, error) {
	if p.pool == nil {
		return p.mem.ListDeploymentsByGroup(ctx, groupID)
	}
	const q = `SELECT ` + deploymentSelectCols + ` FROM model_deployments WHERE model_group_id = $1`
	return p.loadAndHydrateDeployments(ctx, q, groupID)
}

func (p *PostgresRepository) ListAllDeployments(ctx context.Context) ([]*domain.Deployment, error) {
	if p.pool == nil {
		return p.mem.ListAllDeployments(ctx)
	}
	const q = `SELECT ` + deploymentSelectCols + ` FROM model_deployments`
	return p.loadAndHydrateDeployments(ctx, q)
}

func (p *PostgresRepository) UpdateDeploymentStatus(ctx context.Context, depID string, status domain.DeploymentStatus) error {
	if p.pool == nil {
		return p.mem.UpdateDeploymentStatus(ctx, depID, status)
	}
	if _, err := p.pool.Exec(ctx, `UPDATE model_deployments SET status = $2, updated_at = NOW() WHERE id = $1`, depID, string(status)); err != nil {
		return err
	}
	_ = p.mem.UpdateDeploymentStatus(ctx, depID, status)
	return nil
}
