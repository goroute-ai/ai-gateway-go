package storage

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"time"

	"github.com/google/uuid"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

func (r *MemoryRepository) SetGuardrailPolicy(ctx context.Context, pol *domain.GuardrailPolicy) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if pol == nil || pol.OrgID == "" {
		return fmt.Errorf("org_id is required for guardrail policy")
	}
	pol.UpdatedAt = time.Now().UTC()
	cp := *pol
	if pol.BlockedKeywords != nil {
		cp.BlockedKeywords = slices.Clone(pol.BlockedKeywords)
	}
	if pol.BlockedPatterns != nil {
		cp.BlockedPatterns = slices.Clone(pol.BlockedPatterns)
	}
	if pol.EnabledContentCategories != nil {
		cp.EnabledContentCategories = slices.Clone(pol.EnabledContentCategories)
	}
	if pol.ContentExceptions != nil {
		cp.ContentExceptions = slices.Clone(pol.ContentExceptions)
	}
	r.guardrails[pol.OrgID] = &cp
	return nil
}

func (r *MemoryRepository) GetGuardrailPolicy(ctx context.Context, orgID string) (*domain.GuardrailPolicy, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	pol, ok := r.guardrails[orgID]
	if !ok {
		return nil, nil
	}
	cp := *pol
	if pol.BlockedKeywords != nil {
		cp.BlockedKeywords = slices.Clone(pol.BlockedKeywords)
	}
	if pol.BlockedPatterns != nil {
		cp.BlockedPatterns = slices.Clone(pol.BlockedPatterns)
	}
	if pol.EnabledContentCategories != nil {
		cp.EnabledContentCategories = slices.Clone(pol.EnabledContentCategories)
	}
	if pol.ContentExceptions != nil {
		cp.ContentExceptions = slices.Clone(pol.ContentExceptions)
	}
	return &cp, nil
}

// -----------------------------------------------------------------------------
// External Guardrail Definitions Registry
// -----------------------------------------------------------------------------

func cloneAnyValue(v any) any {
	switch tv := v.(type) {
	case map[string]any:
		return cloneAnyMap(tv)
	case []any:
		return cloneAnySlice(tv)
	case []string:
		return slices.Clone(tv)
	default:
		return v
	}
}

func cloneAnySlice(src []any) []any {
	if src == nil {
		return nil
	}
	dst := make([]any, len(src))
	for i, v := range src {
		dst[i] = cloneAnyValue(v)
	}
	return dst
}

func cloneAnyMap(src map[string]any) map[string]any {
	if src == nil {
		return nil
	}
	dst := make(map[string]any, len(src))
	for k, v := range src {
		dst[k] = cloneAnyValue(v)
	}
	return dst
}

func cloneGuardrailDefinition(def *domain.GuardrailDefinition) *domain.GuardrailDefinition {
	if def == nil {
		return nil
	}
	cp := *def
	if def.EventHooks != nil {
		cp.EventHooks = slices.Clone(def.EventHooks)
	}
	cp.Config = cloneAnyMap(def.Config)
	return &cp
}

func normalizeGuardrailDefinition(def *domain.GuardrailDefinition) error {
	if def == nil {
		return fmt.Errorf("guardrail definition is required")
	}
	if def.OrgID == "" {
		return fmt.Errorf("org_id is required for guardrail definition")
	}
	if def.Name == "" {
		return fmt.Errorf("name is required for guardrail definition")
	}
	if def.Provider == "" {
		return fmt.Errorf("provider is required for guardrail definition")
	}
	for _, hook := range def.EventHooks {
		if !hook.IsValid() {
			return fmt.Errorf("invalid guardrail hook %q", hook)
		}
	}
	if def.TimeoutMs < 0 {
		def.TimeoutMs = 0
	}
	return nil
}

func sortGuardrailDefinitions(defs []*domain.GuardrailDefinition) {
	sort.Slice(defs, func(i, j int) bool {
		if defs[i].Precedence != defs[j].Precedence {
			return defs[i].Precedence < defs[j].Precedence
		}
		if !defs[i].CreatedAt.Equal(defs[j].CreatedAt) {
			return defs[i].CreatedAt.Before(defs[j].CreatedAt)
		}
		return defs[i].ID < defs[j].ID
	})
}

func (r *MemoryRepository) CreateGuardrailDefinition(ctx context.Context, def *domain.GuardrailDefinition) error {
	if err := normalizeGuardrailDefinition(def); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if def.ID == "" {
		def.ID = uuid.NewString()
	}
	now := time.Now().UTC()
	if def.CreatedAt.IsZero() {
		def.CreatedAt = now
	}
	if def.UpdatedAt.IsZero() {
		def.UpdatedAt = now
	}
	r.guardrailDefs[def.ID] = cloneGuardrailDefinition(def)
	return nil
}

func (r *MemoryRepository) GetGuardrailDefinition(ctx context.Context, id string) (*domain.GuardrailDefinition, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	def, ok := r.guardrailDefs[id]
	if !ok {
		return nil, fmt.Errorf("guardrail definition %q %w", id, ErrNotFound)
	}
	return cloneGuardrailDefinition(def), nil
}

func (r *MemoryRepository) ListGuardrailDefinitions(ctx context.Context, orgID string, onlyEnabled bool) ([]*domain.GuardrailDefinition, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []*domain.GuardrailDefinition
	for _, def := range r.guardrailDefs {
		if orgID != "" && def.OrgID != orgID {
			continue
		}
		if onlyEnabled && !def.Enabled {
			continue
		}
		out = append(out, cloneGuardrailDefinition(def))
	}
	sortGuardrailDefinitions(out)
	return out, nil
}

func (r *MemoryRepository) UpdateGuardrailDefinition(ctx context.Context, def *domain.GuardrailDefinition) error {
	if def == nil || def.ID == "" {
		return fmt.Errorf("guardrail definition id is required")
	}
	if err := normalizeGuardrailDefinition(def); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	existing, ok := r.guardrailDefs[def.ID]
	if !ok || existing.OrgID != def.OrgID {
		return fmt.Errorf("guardrail definition %q %w", def.ID, ErrNotFound)
	}
	def.CreatedAt = existing.CreatedAt
	def.UpdatedAt = time.Now().UTC()
	cp := cloneGuardrailDefinition(def)
	if cp.EncryptedSecrets == "" && cp.EncryptedDEK == "" {
		cp.EncryptedSecrets = existing.EncryptedSecrets
		cp.EncryptedDEK = existing.EncryptedDEK
	}
	r.guardrailDefs[def.ID] = cp
	return nil
}

func (r *MemoryRepository) DeleteGuardrailDefinition(ctx context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.guardrailDefs[id]; !ok {
		return fmt.Errorf("guardrail definition %q %w", id, ErrNotFound)
	}
	delete(r.guardrailDefs, id)
	return nil
}

func (r *MemoryRepository) RotateGuardrailSecrets(ctx context.Context, orgID, id, encryptedSecrets, encryptedDEK string) error {
	if id == "" {
		return fmt.Errorf("guardrail definition id is required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	def, ok := r.guardrailDefs[id]
	if !ok || (orgID != "" && def.OrgID != orgID) {
		return fmt.Errorf("guardrail definition %q %w", id, ErrNotFound)
	}
	def.EncryptedSecrets = encryptedSecrets
	def.EncryptedDEK = encryptedDEK
	def.UpdatedAt = time.Now().UTC()
	return nil
}
