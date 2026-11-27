package storage

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/jackc/pgx/v5"
)

func (p *PostgresRepository) SetGuardrailPolicy(ctx context.Context, pol *domain.GuardrailPolicy) error {
	if err := p.mem.SetGuardrailPolicy(ctx, pol); err != nil {
		return err
	}
	if p.pool == nil {
		return nil
	}
	const q = `
		INSERT INTO guardrail_policies (
			org_id, mode, scan_all_roles, enable_prompt_injection, prompt_injection_action,
			enable_pii_detection, pii_action, enable_secret_detection,
			secret_action, blocked_keywords, blocked_patterns, redact_output_pii,
			enable_toxicity_filter, toxicity_action, toxicity_threshold,
			enabled_content_categories, content_exceptions, updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,NOW())
		ON CONFLICT (org_id) DO UPDATE SET
			mode = EXCLUDED.mode,
			scan_all_roles = EXCLUDED.scan_all_roles,
			enable_prompt_injection = EXCLUDED.enable_prompt_injection,
			prompt_injection_action = EXCLUDED.prompt_injection_action,
			enable_pii_detection = EXCLUDED.enable_pii_detection,
			pii_action = EXCLUDED.pii_action,
			enable_secret_detection = EXCLUDED.enable_secret_detection,
			secret_action = EXCLUDED.secret_action,
			blocked_keywords = EXCLUDED.blocked_keywords,
			blocked_patterns = EXCLUDED.blocked_patterns,
			redact_output_pii = EXCLUDED.redact_output_pii,
			enable_toxicity_filter = EXCLUDED.enable_toxicity_filter,
			toxicity_action = EXCLUDED.toxicity_action,
			toxicity_threshold = EXCLUDED.toxicity_threshold,
			enabled_content_categories = EXCLUDED.enabled_content_categories,
			content_exceptions = EXCLUDED.content_exceptions,
			updated_at = NOW()`
	mode := pol.EffectiveMode()
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
	toxAct := pol.ToxicityAction
	if toxAct == "" {
		toxAct = domain.GuardrailActionBlock
	}
	toxThreshold := pol.ToxicityThreshold
	if toxThreshold == "" {
		toxThreshold = "medium"
	}
	blockedKeywords := pol.BlockedKeywords
	if blockedKeywords == nil {
		blockedKeywords = []string{}
	}
	blockedPatterns := pol.BlockedPatterns
	if blockedPatterns == nil {
		blockedPatterns = []string{}
	}
	enabledContentCategories := pol.EnabledContentCategories
	if enabledContentCategories == nil {
		enabledContentCategories = []string{}
	}
	contentExceptions := pol.ContentExceptions
	if contentExceptions == nil {
		contentExceptions = []string{}
	}
	_, err := p.pool.Exec(ctx, q,
		pol.OrgID, string(mode), pol.ScanAllRoles, pol.EnablePromptInjection, string(act),
		pol.EnablePIIDetection, string(piiAct), pol.EnableSecretDetection,
		string(secAct), blockedKeywords, blockedPatterns, pol.RedactOutputPII,
		pol.EnableToxicityFilter, string(toxAct), toxThreshold,
		enabledContentCategories, contentExceptions,
	)
	return err
}

func (p *PostgresRepository) GetGuardrailPolicy(ctx context.Context, orgID string) (*domain.GuardrailPolicy, error) {
	if p.pool == nil {
		return p.mem.GetGuardrailPolicy(ctx, orgID)
	}
	value, err := p.coalesceLookup(ctx, "guardrail:"+orgID, func(lookupCtx context.Context) (any, error) {
		p.guardrailQueries.Add(1)
		const q = `SELECT org_id, mode, scan_all_roles, enable_prompt_injection, prompt_injection_action, enable_pii_detection, pii_action, enable_secret_detection, secret_action, blocked_keywords, blocked_patterns, redact_output_pii, enable_toxicity_filter, toxicity_action, toxicity_threshold, enabled_content_categories, content_exceptions FROM guardrail_policies WHERE org_id = $1`
		var pol domain.GuardrailPolicy
		var modeStr, injAct, piiAct, secAct, toxAct string
		if scanErr := p.pool.QueryRow(lookupCtx, q, orgID).Scan(
			&pol.OrgID, &modeStr, &pol.ScanAllRoles, &pol.EnablePromptInjection, &injAct, &pol.EnablePIIDetection, &piiAct,
			&pol.EnableSecretDetection, &secAct, &pol.BlockedKeywords, &pol.BlockedPatterns, &pol.RedactOutputPII,
			&pol.EnableToxicityFilter, &toxAct, &pol.ToxicityThreshold, &pol.EnabledContentCategories, &pol.ContentExceptions,
		); scanErr != nil {
			if errors.Is(scanErr, pgx.ErrNoRows) {
				p.missingGuardrailQueries.Add(1)
				return (*domain.GuardrailPolicy)(nil), nil
			}
			return nil, scanErr
		}
		pol.Mode = domain.GuardrailMode(modeStr)
		pol.PromptInjectionAction = domain.GuardrailAction(injAct)
		pol.PIIAction = domain.GuardrailAction(piiAct)
		pol.SecretAction = domain.GuardrailAction(secAct)
		pol.ToxicityAction = domain.GuardrailAction(toxAct)
		if pol.BlockedKeywords == nil {
			pol.BlockedKeywords = []string{}
		}
		if pol.BlockedPatterns == nil {
			pol.BlockedPatterns = []string{}
		}
		if pol.EnabledContentCategories == nil {
			pol.EnabledContentCategories = []string{}
		}
		if pol.ContentExceptions == nil {
			pol.ContentExceptions = []string{}
		}
		if p.mem != nil {
			_ = p.mem.SetGuardrailPolicy(lookupCtx, &pol)
		}
		return &pol, nil
	})
	if err != nil {
		return nil, err
	}
	result, _ := value.(*domain.GuardrailPolicy)
	return result, nil
}

// -----------------------------------------------------------------------------
// External Guardrail Definitions Registry
// -----------------------------------------------------------------------------

func marshalJSONOrDefault(v any, fallback string) ([]byte, error) {
	if v == nil {
		return []byte(fallback), nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	if len(b) == 0 || string(b) == "null" {
		return []byte(fallback), nil
	}
	return b, nil
}

func marshalGuardrailDefinitionPayloads(def *domain.GuardrailDefinition) (hooksJSON, configJSON []byte, err error) {
	hooksJSON, err = marshalJSONOrDefault(def.EventHooks, "[]")
	if err != nil {
		return nil, nil, fmt.Errorf("marshal guardrail hooks: %w", err)
	}
	configJSON, err = marshalJSONOrDefault(def.Config, "{}")
	if err != nil {
		return nil, nil, fmt.Errorf("marshal guardrail config: %w", err)
	}
	return hooksJSON, configJSON, nil
}

const guardrailDefinitionSelectCols = `id, org_id, name, provider, hooks, enabled, timeout_ms, fail_open, precedence, config, encrypted_secrets, encrypted_dek, created_at, updated_at`

func scanGuardrailDefinition(row rowScanner) (*domain.GuardrailDefinition, error) {
	var def domain.GuardrailDefinition
	var hooksJSON, configJSON []byte
	if err := row.Scan(
		&def.ID, &def.OrgID, &def.Name, &def.Provider,
		&hooksJSON, &def.Enabled, &def.TimeoutMs, &def.FailOpen, &def.Precedence,
		&configJSON, &def.EncryptedSecrets, &def.EncryptedDEK,
		&def.CreatedAt, &def.UpdatedAt,
	); err != nil {
		return nil, err
	}
	if len(hooksJSON) > 0 && string(hooksJSON) != "[]" && string(hooksJSON) != "null" {
		if err := json.Unmarshal(hooksJSON, &def.EventHooks); err != nil {
			return nil, fmt.Errorf("unmarshal guardrail hooks: %w", err)
		}
	}
	if len(configJSON) > 0 && string(configJSON) != "{}" && string(configJSON) != "null" {
		if err := json.Unmarshal(configJSON, &def.Config); err != nil {
			return nil, fmt.Errorf("unmarshal guardrail config: %w", err)
		}
	}
	return &def, nil
}

func (p *PostgresRepository) syncGuardrailDefinitionMem(def *domain.GuardrailDefinition) {
	if p.mem == nil || def == nil {
		return
	}
	p.mem.mu.Lock()
	p.mem.guardrailDefs[def.ID] = cloneGuardrailDefinition(def)
	p.mem.mu.Unlock()
}

func (p *PostgresRepository) CreateGuardrailDefinition(ctx context.Context, def *domain.GuardrailDefinition) error {
	if p.pool == nil {
		return p.mem.CreateGuardrailDefinition(ctx, def)
	}
	if err := normalizeGuardrailDefinition(def); err != nil {
		return err
	}
	if def.ID == "" {
		def.ID = uuid.NewString()
	}
	hooksJSON, configJSON, err := marshalGuardrailDefinitionPayloads(def)
	if err != nil {
		return err
	}
	const q = `
		INSERT INTO guardrail_definitions (
			id, org_id, name, provider, hooks, enabled, timeout_ms, fail_open,
			precedence, config, encrypted_secrets, encrypted_dek
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
		RETURNING created_at, updated_at`
	if err := p.pool.QueryRow(ctx, q,
		def.ID, def.OrgID, def.Name, def.Provider,
		hooksJSON, def.Enabled, def.TimeoutMs, def.FailOpen,
		def.Precedence, configJSON, def.EncryptedSecrets, def.EncryptedDEK,
	).Scan(&def.CreatedAt, &def.UpdatedAt); err != nil {
		return err
	}
	p.syncGuardrailDefinitionMem(def)
	return nil
}

func (p *PostgresRepository) GetGuardrailDefinition(ctx context.Context, id string) (*domain.GuardrailDefinition, error) {
	if p.pool == nil {
		return p.mem.GetGuardrailDefinition(ctx, id)
	}
	const q = `SELECT ` + guardrailDefinitionSelectCols + ` FROM guardrail_definitions WHERE id = $1`
	def, err := scanGuardrailDefinition(p.pool.QueryRow(ctx, q, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("guardrail definition %q %w", id, ErrNotFound)
		}
		return nil, err
	}
	p.syncGuardrailDefinitionMem(def)
	return def, nil
}

func (p *PostgresRepository) ListGuardrailDefinitions(ctx context.Context, orgID string, onlyEnabled bool) ([]*domain.GuardrailDefinition, error) {
	if p.pool == nil {
		return p.mem.ListGuardrailDefinitions(ctx, orgID, onlyEnabled)
	}
	const q = `
		SELECT ` + guardrailDefinitionSelectCols + `
		FROM guardrail_definitions
		WHERE ($1 = '' OR org_id = $1)
		  AND (NOT $2 OR enabled = TRUE)
		ORDER BY precedence ASC, created_at ASC, id ASC`
	rows, err := p.pool.Query(ctx, q, orgID, onlyEnabled)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*domain.GuardrailDefinition
	for rows.Next() {
		def, err := scanGuardrailDefinition(rows)
		if err != nil {
			return nil, err
		}
		p.syncGuardrailDefinitionMem(def)
		out = append(out, def)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (p *PostgresRepository) UpdateGuardrailDefinition(ctx context.Context, def *domain.GuardrailDefinition) error {
	if p.pool == nil {
		return p.mem.UpdateGuardrailDefinition(ctx, def)
	}
	if def == nil || def.ID == "" {
		return fmt.Errorf("guardrail definition id is required")
	}
	if err := normalizeGuardrailDefinition(def); err != nil {
		return err
	}
	hooksJSON, configJSON, err := marshalGuardrailDefinitionPayloads(def)
	if err != nil {
		return err
	}
	const q = `
		UPDATE guardrail_definitions SET
			name = $3,
			provider = $4,
			hooks = $5,
			enabled = $6,
			timeout_ms = $7,
			fail_open = $8,
			precedence = $9,
			config = $10,
			encrypted_secrets = CASE WHEN $11 <> '' OR $12 <> '' THEN $11 ELSE encrypted_secrets END,
			encrypted_dek = CASE WHEN $11 <> '' OR $12 <> '' THEN $12 ELSE encrypted_dek END,
			updated_at = NOW()
		WHERE id = $1 AND org_id = $2
		RETURNING created_at, updated_at, encrypted_secrets, encrypted_dek`
	var encSecrets, encDEK string
	if err := p.pool.QueryRow(ctx, q,
		def.ID, def.OrgID, def.Name, def.Provider,
		hooksJSON, def.Enabled, def.TimeoutMs, def.FailOpen,
		def.Precedence, configJSON, def.EncryptedSecrets, def.EncryptedDEK,
	).Scan(&def.CreatedAt, &def.UpdatedAt, &encSecrets, &encDEK); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("guardrail definition %q %w", def.ID, ErrNotFound)
		}
		return err
	}
	stored := cloneGuardrailDefinition(def)
	stored.EncryptedSecrets = encSecrets
	stored.EncryptedDEK = encDEK
	p.syncGuardrailDefinitionMem(stored)
	return nil
}

func (p *PostgresRepository) DeleteGuardrailDefinition(ctx context.Context, id string) error {
	if p.pool == nil {
		return p.mem.DeleteGuardrailDefinition(ctx, id)
	}
	tag, err := p.pool.Exec(ctx, `DELETE FROM guardrail_definitions WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("guardrail definition %q %w", id, ErrNotFound)
	}
	if p.mem != nil {
		_ = p.mem.DeleteGuardrailDefinition(ctx, id)
	}
	return nil
}

func (p *PostgresRepository) RotateGuardrailSecrets(ctx context.Context, orgID, id, encryptedSecrets, encryptedDEK string) error {
	if id == "" {
		return fmt.Errorf("guardrail definition id is required")
	}
	if p.pool == nil {
		return p.mem.RotateGuardrailSecrets(ctx, orgID, id, encryptedSecrets, encryptedDEK)
	}
	tag, err := p.pool.Exec(ctx, `
		UPDATE guardrail_definitions
		SET encrypted_secrets = $3, encrypted_dek = $4, updated_at = NOW()
		WHERE id = $1 AND ($2 = '' OR org_id = $2)`,
		id, orgID, encryptedSecrets, encryptedDEK,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("guardrail definition %q %w", id, ErrNotFound)
	}
	if p.mem != nil {
		_ = p.mem.RotateGuardrailSecrets(ctx, orgID, id, encryptedSecrets, encryptedDEK)
	}
	return nil
}
