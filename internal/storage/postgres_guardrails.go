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
			secret_action, blocked_keywords, redact_output_pii,
			enable_toxicity_filter, toxicity_action, toxicity_threshold,
			enabled_content_categories, content_exceptions, sensitive_route_target, updated_at
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
			redact_output_pii = EXCLUDED.redact_output_pii,
			enable_toxicity_filter = EXCLUDED.enable_toxicity_filter,
			toxicity_action = EXCLUDED.toxicity_action,
			toxicity_threshold = EXCLUDED.toxicity_threshold,
			enabled_content_categories = EXCLUDED.enabled_content_categories,
			content_exceptions = EXCLUDED.content_exceptions,
			sensitive_route_target = EXCLUDED.sensitive_route_target,
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
		string(secAct), blockedKeywords, pol.RedactOutputPII,
		pol.EnableToxicityFilter, string(toxAct), toxThreshold,
		enabledContentCategories, contentExceptions, strings.TrimSpace(pol.SensitiveRouteTarget),
	)
	return err
}

func (p *PostgresRepository) GetGuardrailPolicy(ctx context.Context, orgID string) (*domain.GuardrailPolicy, error) {
	if p.pool == nil {
		return p.mem.GetGuardrailPolicy(ctx, orgID)
	}
	value, err := p.coalesceLookup(ctx, "guardrail:"+orgID, func(lookupCtx context.Context) (any, error) {
		p.guardrailQueries.Add(1)
		const q = `SELECT org_id, mode, scan_all_roles, enable_prompt_injection, prompt_injection_action, enable_pii_detection, pii_action, enable_secret_detection, secret_action, blocked_keywords, redact_output_pii, enable_toxicity_filter, toxicity_action, toxicity_threshold, enabled_content_categories, content_exceptions, COALESCE(sensitive_route_target, '') FROM guardrail_policies WHERE org_id = $1`
		var pol domain.GuardrailPolicy
		var modeStr, injAct, piiAct, secAct, toxAct string
		if scanErr := p.pool.QueryRow(lookupCtx, q, orgID).Scan(
			&pol.OrgID, &modeStr, &pol.ScanAllRoles, &pol.EnablePromptInjection, &injAct, &pol.EnablePIIDetection, &piiAct,
			&pol.EnableSecretDetection, &secAct, &pol.BlockedKeywords, &pol.RedactOutputPII,
			&pol.EnableToxicityFilter, &toxAct, &pol.ToxicityThreshold, &pol.EnabledContentCategories, &pol.ContentExceptions, &pol.SensitiveRouteTarget,
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
// Guardrail Definitions Registry & Hierarchical Bindings
// -----------------------------------------------------------------------------

type guardrailStreamScopeJSON struct {
	Scope  domain.StreamScope       `json:"scope,omitempty"`
	ByHook domain.StreamScopeByHook `json:"by_hook,omitempty"`
}

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

func marshalGuardrailDefinitionPayloads(def *domain.GuardrailDefinition) (hooksJSON, streamScopeJSON, modeRuleJSON, rolesJSON, configJSON, infoJSON []byte, err error) {
	hooksJSON, err = marshalJSONOrDefault(def.EventHooks, "[]")
	if err != nil {
		return nil, nil, nil, nil, nil, nil, fmt.Errorf("marshal guardrail hooks: %w", err)
	}
	streamScopeJSON, err = json.Marshal(guardrailStreamScopeJSON{
		Scope:  def.StreamScope,
		ByHook: def.StreamScopeByHook,
	})
	if err != nil {
		return nil, nil, nil, nil, nil, nil, fmt.Errorf("marshal guardrail stream_scope: %w", err)
	}
	modeRuleJSON, err = marshalJSONOrDefault(def.ModeRule, "{}")
	if err != nil {
		return nil, nil, nil, nil, nil, nil, fmt.Errorf("marshal guardrail mode_rule: %w", err)
	}
	rolesJSON, err = marshalJSONOrDefault(def.EnabledRoles, "[]")
	if err != nil {
		return nil, nil, nil, nil, nil, nil, fmt.Errorf("marshal guardrail enabled_roles: %w", err)
	}
	configJSON, err = marshalJSONOrDefault(def.Config, "{}")
	if err != nil {
		return nil, nil, nil, nil, nil, nil, fmt.Errorf("marshal guardrail config: %w", err)
	}
	infoJSON, err = marshalJSONOrDefault(def.GuardrailInfo, "{}")
	if err != nil {
		return nil, nil, nil, nil, nil, nil, fmt.Errorf("marshal guardrail info: %w", err)
	}
	return hooksJSON, streamScopeJSON, modeRuleJSON, rolesJSON, configJSON, infoJSON, nil
}

const guardrailDefinitionSelectCols = `id, org_id, name, provider, hooks, stream_scope, mode_rule, default_on, enabled_roles, timeout_ms, fail_open, precedence, config, encrypted_secrets, encrypted_dek, status, COALESCE(sensitive_route_target, ''), guardrail_info, weight, created_at, updated_at`

func scanGuardrailDefinition(row rowScanner) (*domain.GuardrailDefinition, error) {
	var def domain.GuardrailDefinition
	var statusStr string
	var hooksJSON, streamScopeJSON, modeRuleJSON, rolesJSON, configJSON, infoJSON []byte
	if err := row.Scan(
		&def.ID, &def.OrgID, &def.Name, &def.Provider,
		&hooksJSON, &streamScopeJSON, &modeRuleJSON,
		&def.DefaultOn, &rolesJSON, &def.TimeoutMs, &def.FailOpen, &def.Precedence,
		&configJSON, &def.EncryptedSecrets, &def.EncryptedDEK, &statusStr, &def.SensitiveRouteTarget, &infoJSON, &def.Weight,
		&def.CreatedAt, &def.UpdatedAt,
	); err != nil {
		return nil, err
	}
	def.Status = domain.GuardrailStatus(statusStr)

	if len(hooksJSON) > 0 && string(hooksJSON) != "[]" && string(hooksJSON) != "null" {
		if err := json.Unmarshal(hooksJSON, &def.EventHooks); err != nil {
			return nil, fmt.Errorf("unmarshal guardrail hooks: %w", err)
		}
	}
	if len(streamScopeJSON) > 0 && string(streamScopeJSON) != "{}" && string(streamScopeJSON) != "null" {
		trimmed := strings.TrimSpace(string(streamScopeJSON))
		if strings.HasPrefix(trimmed, `"`) {
			var scope domain.StreamScope
			if err := json.Unmarshal(streamScopeJSON, &scope); err != nil {
				return nil, fmt.Errorf("unmarshal guardrail stream_scope: %w", err)
			}
			def.StreamScope = scope
		} else {
			var ss guardrailStreamScopeJSON
			if err := json.Unmarshal(streamScopeJSON, &ss); err != nil {
				return nil, fmt.Errorf("unmarshal guardrail stream_scope: %w", err)
			}
			if ss.Scope != "" || len(ss.ByHook) > 0 {
				def.StreamScope = ss.Scope
				def.StreamScopeByHook = ss.ByHook
			} else {
				var byHook domain.StreamScopeByHook
				if err := json.Unmarshal(streamScopeJSON, &byHook); err == nil && len(byHook) > 0 {
					def.StreamScopeByHook = byHook
				}
			}
		}
	}
	if len(modeRuleJSON) > 0 && string(modeRuleJSON) != "{}" && string(modeRuleJSON) != "null" {
		var mr domain.GuardrailModeRule
		if err := json.Unmarshal(modeRuleJSON, &mr); err != nil {
			return nil, fmt.Errorf("unmarshal guardrail mode_rule: %w", err)
		}
		if len(mr.Tags) > 0 || len(mr.Default) > 0 {
			def.ModeRule = &mr
		}
	}
	if len(rolesJSON) > 0 && string(rolesJSON) != "[]" && string(rolesJSON) != "null" {
		if err := json.Unmarshal(rolesJSON, &def.EnabledRoles); err != nil {
			return nil, fmt.Errorf("unmarshal guardrail enabled_roles: %w", err)
		}
	}
	if len(configJSON) > 0 && string(configJSON) != "{}" && string(configJSON) != "null" {
		if err := json.Unmarshal(configJSON, &def.Config); err != nil {
			return nil, fmt.Errorf("unmarshal guardrail config: %w", err)
		}
	}
	if len(infoJSON) > 0 && string(infoJSON) != "{}" && string(infoJSON) != "null" {
		if err := json.Unmarshal(infoJSON, &def.GuardrailInfo); err != nil {
			return nil, fmt.Errorf("unmarshal guardrail info: %w", err)
		}
	}
	return &def, nil
}

const guardrailBindingSelectCols = `id, org_id, guardrail_id, guardrail_name, COALESCE(team_id, ''), COALESCE(virtual_key_id, ''), COALESCE(end_user_id, ''), COALESCE(model_group_id, ''), COALESCE(tag, ''), overrides, is_locked, created_at, updated_at`

func scanGuardrailBinding(row rowScanner) (*domain.GuardrailBinding, error) {
	var b domain.GuardrailBinding
	var overridesJSON []byte
	if err := row.Scan(
		&b.ID, &b.OrgID, &b.GuardrailID, &b.GuardrailName,
		&b.TeamID, &b.VirtualKeyID, &b.EndUserID, &b.ModelGroupID, &b.Tag,
		&overridesJSON, &b.IsLocked, &b.CreatedAt, &b.UpdatedAt,
	); err != nil {
		return nil, err
	}
	if len(overridesJSON) > 0 && string(overridesJSON) != "{}" && string(overridesJSON) != "null" {
		if err := json.Unmarshal(overridesJSON, &b.ParamOverrides); err != nil {
			return nil, fmt.Errorf("unmarshal guardrail binding overrides: %w", err)
		}
	}
	return &b, nil
}

func (p *PostgresRepository) syncGuardrailDefinitionMem(def *domain.GuardrailDefinition) {
	if p.mem == nil || def == nil {
		return
	}
	p.mem.mu.Lock()
	p.mem.guardrailDefs[def.ID] = cloneGuardrailDefinition(def)
	p.mem.mu.Unlock()
}

func (p *PostgresRepository) syncGuardrailBindingMem(b *domain.GuardrailBinding) {
	if p.mem == nil || b == nil {
		return
	}
	p.mem.mu.Lock()
	p.mem.guardrailBindings[b.ID] = cloneGuardrailBinding(b)
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
	hooksJSON, streamScopeJSON, modeRuleJSON, rolesJSON, configJSON, infoJSON, err := marshalGuardrailDefinitionPayloads(def)
	if err != nil {
		return err
	}
	const q = `
		INSERT INTO guardrail_definitions (
			id, org_id, name, provider, hooks, stream_scope, mode_rule,
			default_on, enabled_roles, timeout_ms, fail_open, precedence,
			config, encrypted_secrets, encrypted_dek, status, sensitive_route_target, guardrail_info, weight
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18,$19)
		RETURNING created_at, updated_at`
	if err := p.pool.QueryRow(ctx, q,
		def.ID, def.OrgID, def.Name, def.Provider,
		hooksJSON, streamScopeJSON, modeRuleJSON,
		def.DefaultOn, rolesJSON, def.TimeoutMs, def.FailOpen, def.Precedence,
		configJSON, def.EncryptedSecrets, def.EncryptedDEK, string(def.Status), strings.TrimSpace(def.SensitiveRouteTarget), infoJSON, def.Weight,
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

func (p *PostgresRepository) ListGuardrailDefinitions(ctx context.Context, orgID string, status domain.GuardrailStatus, name string) ([]*domain.GuardrailDefinition, error) {
	if p.pool == nil {
		return p.mem.ListGuardrailDefinitions(ctx, orgID, status, name)
	}
	const q = `
		SELECT ` + guardrailDefinitionSelectCols + `
		FROM guardrail_definitions
		WHERE ($1 = '' OR org_id = $1)
		  AND ($2 = '' OR status = $2)
		  AND ($3 = '' OR name = $3)
		ORDER BY precedence ASC, created_at ASC, id ASC`
	rows, err := p.pool.Query(ctx, q, orgID, string(status), name)
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
	hooksJSON, streamScopeJSON, modeRuleJSON, rolesJSON, configJSON, infoJSON, err := marshalGuardrailDefinitionPayloads(def)
	if err != nil {
		return err
	}
	const q = `
		UPDATE guardrail_definitions SET
			name = $3,
			provider = $4,
			hooks = $5,
			stream_scope = $6,
			mode_rule = $7,
			default_on = $8,
			enabled_roles = $9,
			timeout_ms = $10,
			fail_open = $11,
			precedence = $12,
			config = $13,
			encrypted_secrets = CASE WHEN $14 <> '' OR $15 <> '' THEN $14 ELSE encrypted_secrets END,
			encrypted_dek = CASE WHEN $14 <> '' OR $15 <> '' THEN $15 ELSE encrypted_dek END,
			status = $16,
			sensitive_route_target = $17,
			guardrail_info = $18,
			weight = $19,
			updated_at = NOW()
		WHERE id = $1 AND org_id = $2
		RETURNING created_at, updated_at, encrypted_secrets, encrypted_dek`
	var encSecrets, encDEK string
	if err := p.pool.QueryRow(ctx, q,
		def.ID, def.OrgID, def.Name, def.Provider,
		hooksJSON, streamScopeJSON, modeRuleJSON,
		def.DefaultOn, rolesJSON, def.TimeoutMs, def.FailOpen, def.Precedence,
		configJSON, def.EncryptedSecrets, def.EncryptedDEK, string(def.Status), strings.TrimSpace(def.SensitiveRouteTarget), infoJSON, def.Weight,
	).Scan(&def.CreatedAt, &def.UpdatedAt, &encSecrets, &encDEK); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("guardrail definition %q %w", def.ID, ErrNotFound)
		}
		return err
	}
	if _, err := p.pool.Exec(ctx,
		`UPDATE guardrail_bindings SET guardrail_name = $2, updated_at = NOW() WHERE guardrail_id = $1 AND guardrail_name <> $2`,
		def.ID, def.Name,
	); err != nil {
		return err
	}
	stored := cloneGuardrailDefinition(def)
	stored.EncryptedSecrets = encSecrets
	stored.EncryptedDEK = encDEK
	p.syncGuardrailDefinitionMem(stored)
	if p.mem != nil {
		p.mem.mu.Lock()
		for _, b := range p.mem.guardrailBindings {
			if b.GuardrailID == def.ID {
				b.GuardrailName = def.Name
			}
		}
		p.mem.mu.Unlock()
	}
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

func (p *PostgresRepository) CreateGuardrailBinding(ctx context.Context, binding *domain.GuardrailBinding) error {
	if p.pool == nil {
		return p.mem.CreateGuardrailBinding(ctx, binding)
	}
	if binding == nil {
		return fmt.Errorf("guardrail binding is required")
	}
	if binding.OrgID == "" {
		return fmt.Errorf("org_id is required for guardrail binding")
	}
	if binding.GuardrailID == "" {
		return fmt.Errorf("guardrail_id is required for guardrail binding")
	}
	var defName string
	if err := p.pool.QueryRow(ctx, `SELECT name FROM guardrail_definitions WHERE id = $1 AND org_id = $2`, binding.GuardrailID, binding.OrgID).Scan(&defName); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("guardrail definition %q %w", binding.GuardrailID, ErrNotFound)
		}
		return err
	}
	if binding.GuardrailName == "" {
		binding.GuardrailName = defName
	}
	if binding.ID == "" {
		binding.ID = uuid.NewString()
	}
	overridesJSON, err := marshalJSONOrDefault(binding.ParamOverrides, "{}")
	if err != nil {
		return fmt.Errorf("marshal guardrail binding overrides: %w", err)
	}
	const q = `
		INSERT INTO guardrail_bindings (
			id, org_id, guardrail_id, guardrail_name,
			team_id, virtual_key_id, end_user_id, model_group_id, tag,
			overrides, is_locked
		) VALUES (
			$1, $2, $3, $4,
			NULLIF($5, ''), NULLIF($6, ''), NULLIF($7, ''), NULLIF($8, ''), NULLIF($9, ''),
			$10, $11
		)
		RETURNING created_at, updated_at`
	if err := p.pool.QueryRow(ctx, q,
		binding.ID, binding.OrgID, binding.GuardrailID, binding.GuardrailName,
		binding.TeamID, binding.VirtualKeyID, binding.EndUserID, binding.ModelGroupID, binding.Tag,
		overridesJSON, binding.IsLocked,
	).Scan(&binding.CreatedAt, &binding.UpdatedAt); err != nil {
		return err
	}
	p.syncGuardrailBindingMem(binding)
	return nil
}

func (p *PostgresRepository) GetGuardrailBinding(ctx context.Context, id string) (*domain.GuardrailBinding, error) {
	if p.pool == nil {
		return p.mem.GetGuardrailBinding(ctx, id)
	}
	const q = `SELECT ` + guardrailBindingSelectCols + ` FROM guardrail_bindings WHERE id = $1`
	b, err := scanGuardrailBinding(p.pool.QueryRow(ctx, q, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, fmt.Errorf("guardrail binding %q %w", id, ErrNotFound)
		}
		return nil, err
	}
	p.syncGuardrailBindingMem(b)
	return b, nil
}

func (p *PostgresRepository) ListGuardrailBindings(ctx context.Context, filter GuardrailBindingFilter) ([]*domain.GuardrailBinding, error) {
	if p.pool == nil {
		return p.mem.ListGuardrailBindings(ctx, filter)
	}
	const q = `
		SELECT ` + guardrailBindingSelectCols + `
		FROM guardrail_bindings
		WHERE ($1 = '' OR org_id = $1)
		  AND ($2 = '' OR guardrail_id = $2)
		  AND ($3 = '' OR guardrail_name = $3)
		  AND ($4 = '' OR team_id = $4)
		  AND ($5 = '' OR virtual_key_id = $5)
		  AND ($6 = '' OR end_user_id = $6)
		  AND ($7 = '' OR model_group_id = $7)
		  AND ($8 = '' OR tag = $8)
		ORDER BY created_at ASC, id ASC`
	rows, err := p.pool.Query(ctx, q,
		filter.OrgID, filter.GuardrailID, filter.GuardrailName,
		filter.TeamID, filter.VirtualKeyID, filter.EndUserID, filter.ModelGroupID, filter.Tag,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*domain.GuardrailBinding
	for rows.Next() {
		b, err := scanGuardrailBinding(rows)
		if err != nil {
			return nil, err
		}
		p.syncGuardrailBindingMem(b)
		out = append(out, b)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (p *PostgresRepository) UpdateGuardrailBinding(ctx context.Context, binding *domain.GuardrailBinding) error {
	if p.pool == nil {
		return p.mem.UpdateGuardrailBinding(ctx, binding)
	}
	if binding == nil || binding.ID == "" {
		return fmt.Errorf("guardrail binding id is required")
	}
	if binding.OrgID == "" {
		return fmt.Errorf("org_id is required for guardrail binding")
	}
	if binding.GuardrailID == "" {
		return fmt.Errorf("guardrail_id is required for guardrail binding")
	}
	var defName string
	if err := p.pool.QueryRow(ctx, `SELECT name FROM guardrail_definitions WHERE id = $1 AND org_id = $2`, binding.GuardrailID, binding.OrgID).Scan(&defName); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("guardrail definition %q %w", binding.GuardrailID, ErrNotFound)
		}
		return err
	}
	if binding.GuardrailName == "" {
		binding.GuardrailName = defName
	}
	overridesJSON, err := marshalJSONOrDefault(binding.ParamOverrides, "{}")
	if err != nil {
		return fmt.Errorf("marshal guardrail binding overrides: %w", err)
	}
	const q = `
		UPDATE guardrail_bindings SET
			guardrail_id = $3,
			guardrail_name = $4,
			team_id = NULLIF($5, ''),
			virtual_key_id = NULLIF($6, ''),
			end_user_id = NULLIF($7, ''),
			model_group_id = NULLIF($8, ''),
			tag = NULLIF($9, ''),
			overrides = $10,
			is_locked = $11,
			updated_at = NOW()
		WHERE id = $1 AND org_id = $2
		RETURNING created_at, updated_at`
	if err := p.pool.QueryRow(ctx, q,
		binding.ID, binding.OrgID, binding.GuardrailID, binding.GuardrailName,
		binding.TeamID, binding.VirtualKeyID, binding.EndUserID, binding.ModelGroupID, binding.Tag,
		overridesJSON, binding.IsLocked,
	).Scan(&binding.CreatedAt, &binding.UpdatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("guardrail binding %q %w", binding.ID, ErrNotFound)
		}
		return err
	}
	p.syncGuardrailBindingMem(binding)
	return nil
}

func (p *PostgresRepository) DeleteGuardrailBinding(ctx context.Context, id string) error {
	if p.pool == nil {
		return p.mem.DeleteGuardrailBinding(ctx, id)
	}
	tag, err := p.pool.Exec(ctx, `DELETE FROM guardrail_bindings WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("guardrail binding %q %w", id, ErrNotFound)
	}
	if p.mem != nil {
		_ = p.mem.DeleteGuardrailBinding(ctx, id)
	}
	return nil
}

func (p *PostgresRepository) ListEffectiveGuardrailsForOrg(ctx context.Context, orgID string) (*EffectiveGuardrails, error) {
	if p.pool == nil {
		return p.mem.ListEffectiveGuardrailsForOrg(ctx, orgID)
	}
	value, err := p.coalesceLookup(ctx, "effective_guardrails:"+orgID, func(lookupCtx context.Context) (any, error) {
		const defsQ = `
			SELECT ` + guardrailDefinitionSelectCols + `
			FROM guardrail_definitions
			WHERE org_id = $1 AND status = $2
			ORDER BY precedence ASC, created_at ASC, id ASC`
		defRows, err := p.pool.Query(lookupCtx, defsQ, orgID, string(domain.GuardrailStatusActive))
		if err != nil {
			return nil, err
		}
		defer defRows.Close()

		var defs []*domain.GuardrailDefinition
		for defRows.Next() {
			def, err := scanGuardrailDefinition(defRows)
			if err != nil {
				return nil, err
			}
			p.syncGuardrailDefinitionMem(def)
			defs = append(defs, def)
		}
		if err := defRows.Err(); err != nil {
			return nil, err
		}

		const bindQ = `
			SELECT b.id, b.org_id, b.guardrail_id, b.guardrail_name,
			       COALESCE(b.team_id, ''), COALESCE(b.virtual_key_id, ''), COALESCE(b.end_user_id, ''), COALESCE(b.model_group_id, ''), COALESCE(b.tag, ''),
			       b.overrides, b.is_locked, b.created_at, b.updated_at
			FROM guardrail_bindings b
			INNER JOIN guardrail_definitions d ON d.id = b.guardrail_id
			WHERE b.org_id = $1 AND d.org_id = $1 AND d.status = $2
			ORDER BY b.created_at ASC, b.id ASC`
		bindRows, err := p.pool.Query(lookupCtx, bindQ, orgID, string(domain.GuardrailStatusActive))
		if err != nil {
			return nil, err
		}
		defer bindRows.Close()

		var bindings []*domain.GuardrailBinding
		for bindRows.Next() {
			b, err := scanGuardrailBinding(bindRows)
			if err != nil {
				return nil, err
			}
			p.syncGuardrailBindingMem(b)
			bindings = append(bindings, b)
		}
		if err := bindRows.Err(); err != nil {
			return nil, err
		}

		return &EffectiveGuardrails{
			Definitions: defs,
			Bindings:    bindings,
		}, nil
	})
	if err != nil {
		return nil, err
	}
	eff, _ := value.(*EffectiveGuardrails)
	if eff == nil {
		return &EffectiveGuardrails{}, nil
	}
	cloned := &EffectiveGuardrails{
		Definitions: make([]*domain.GuardrailDefinition, len(eff.Definitions)),
		Bindings:    make([]*domain.GuardrailBinding, len(eff.Bindings)),
	}
	for i, d := range eff.Definitions {
		cloned.Definitions[i] = cloneGuardrailDefinition(d)
	}
	for i, b := range eff.Bindings {
		cloned.Bindings[i] = cloneGuardrailBinding(b)
	}
	return cloned, nil
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
