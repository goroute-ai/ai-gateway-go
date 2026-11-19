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
	return &cp, nil
}

// -----------------------------------------------------------------------------
// Guardrail Definitions Registry & Hierarchical Bindings
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
	if def.StreamScopeByHook != nil {
		cp.StreamScopeByHook = make(domain.StreamScopeByHook, len(def.StreamScopeByHook))
		for k, v := range def.StreamScopeByHook {
			cp.StreamScopeByHook[k] = v
		}
	}
	if def.ModeRule != nil {
		mr := &domain.GuardrailModeRule{}
		if def.ModeRule.Default != nil {
			mr.Default = slices.Clone(def.ModeRule.Default)
		}
		if def.ModeRule.Tags != nil {
			mr.Tags = make(map[string][]domain.GuardrailHook, len(def.ModeRule.Tags))
			for tag, hooks := range def.ModeRule.Tags {
				mr.Tags[tag] = slices.Clone(hooks)
			}
		}
		cp.ModeRule = mr
	}
	if def.EnabledRoles != nil {
		cp.EnabledRoles = slices.Clone(def.EnabledRoles)
	}
	cp.Config = cloneAnyMap(def.Config)
	cp.GuardrailInfo = cloneAnyMap(def.GuardrailInfo)
	return &cp
}

func cloneGuardrailBinding(b *domain.GuardrailBinding) *domain.GuardrailBinding {
	if b == nil {
		return nil
	}
	cp := *b
	cp.ParamOverrides = cloneAnyMap(b.ParamOverrides)
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
	if def.Status == "" {
		def.Status = domain.GuardrailStatusActive
	} else if !def.Status.IsValid() {
		return fmt.Errorf("invalid guardrail status %q", def.Status)
	}
	if def.StreamScope == "" {
		def.StreamScope = domain.StreamScopeBoth
	} else if !def.StreamScope.IsValid() {
		return fmt.Errorf("invalid stream_scope %q", def.StreamScope)
	}
	for hook, scope := range def.StreamScopeByHook {
		if !hook.IsValid() {
			return fmt.Errorf("invalid guardrail hook %q", hook)
		}
		if scope != "" && !scope.IsValid() {
			return fmt.Errorf("invalid stream_scope %q for hook %q", scope, hook)
		}
	}
	for _, hook := range def.EventHooks {
		if !hook.IsValid() {
			return fmt.Errorf("invalid guardrail hook %q", hook)
		}
	}
	if def.TimeoutMs < 0 {
		def.TimeoutMs = 0
	}
	if def.Weight <= 0 {
		def.Weight = 1
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

func sortGuardrailBindings(bindings []*domain.GuardrailBinding) {
	sort.Slice(bindings, func(i, j int) bool {
		if !bindings[i].CreatedAt.Equal(bindings[j].CreatedAt) {
			return bindings[i].CreatedAt.Before(bindings[j].CreatedAt)
		}
		return bindings[i].ID < bindings[j].ID
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

func (r *MemoryRepository) ListGuardrailDefinitions(ctx context.Context, orgID string, status domain.GuardrailStatus, name string) ([]*domain.GuardrailDefinition, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []*domain.GuardrailDefinition
	for _, def := range r.guardrailDefs {
		if orgID != "" && def.OrgID != orgID {
			continue
		}
		if status != "" && def.Status != status {
			continue
		}
		if name != "" && def.Name != name {
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
	if def.Name != existing.Name {
		for _, b := range r.guardrailBindings {
			if b.GuardrailID == def.ID {
				b.GuardrailName = def.Name
			}
		}
	}
	return nil
}

func (r *MemoryRepository) DeleteGuardrailDefinition(ctx context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.guardrailDefs[id]; !ok {
		return fmt.Errorf("guardrail definition %q %w", id, ErrNotFound)
	}
	delete(r.guardrailDefs, id)
	for bid, b := range r.guardrailBindings {
		if b.GuardrailID == id {
			delete(r.guardrailBindings, bid)
		}
	}
	return nil
}

func (r *MemoryRepository) CreateGuardrailBinding(ctx context.Context, binding *domain.GuardrailBinding) error {
	if binding == nil {
		return fmt.Errorf("guardrail binding is required")
	}
	if binding.OrgID == "" {
		return fmt.Errorf("org_id is required for guardrail binding")
	}
	if binding.GuardrailID == "" {
		return fmt.Errorf("guardrail_id is required for guardrail binding")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	def, ok := r.guardrailDefs[binding.GuardrailID]
	if !ok || def.OrgID != binding.OrgID {
		return fmt.Errorf("guardrail definition %q %w", binding.GuardrailID, ErrNotFound)
	}
	if binding.GuardrailName == "" {
		binding.GuardrailName = def.Name
	}
	if binding.ID == "" {
		binding.ID = uuid.NewString()
	}
	now := time.Now().UTC()
	if binding.CreatedAt.IsZero() {
		binding.CreatedAt = now
	}
	if binding.UpdatedAt.IsZero() {
		binding.UpdatedAt = now
	}
	r.guardrailBindings[binding.ID] = cloneGuardrailBinding(binding)
	return nil
}

func (r *MemoryRepository) GetGuardrailBinding(ctx context.Context, id string) (*domain.GuardrailBinding, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	b, ok := r.guardrailBindings[id]
	if !ok {
		return nil, fmt.Errorf("guardrail binding %q %w", id, ErrNotFound)
	}
	return cloneGuardrailBinding(b), nil
}

func matchesGuardrailBindingFilter(b *domain.GuardrailBinding, filter GuardrailBindingFilter) bool {
	if filter.OrgID != "" && b.OrgID != filter.OrgID {
		return false
	}
	if filter.GuardrailID != "" && b.GuardrailID != filter.GuardrailID {
		return false
	}
	if filter.GuardrailName != "" && b.GuardrailName != filter.GuardrailName {
		return false
	}
	if filter.TeamID != "" && b.TeamID != filter.TeamID {
		return false
	}
	if filter.VirtualKeyID != "" && b.VirtualKeyID != filter.VirtualKeyID {
		return false
	}
	if filter.EndUserID != "" && b.EndUserID != filter.EndUserID {
		return false
	}
	if filter.ModelGroupID != "" && b.ModelGroupID != filter.ModelGroupID {
		return false
	}
	if filter.Tag != "" && b.Tag != filter.Tag {
		return false
	}
	return true
}

func (r *MemoryRepository) ListGuardrailBindings(ctx context.Context, filter GuardrailBindingFilter) ([]*domain.GuardrailBinding, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []*domain.GuardrailBinding
	for _, b := range r.guardrailBindings {
		if matchesGuardrailBindingFilter(b, filter) {
			out = append(out, cloneGuardrailBinding(b))
		}
	}
	sortGuardrailBindings(out)
	return out, nil
}

func (r *MemoryRepository) UpdateGuardrailBinding(ctx context.Context, binding *domain.GuardrailBinding) error {
	if binding == nil || binding.ID == "" {
		return fmt.Errorf("guardrail binding id is required")
	}
	if binding.OrgID == "" {
		return fmt.Errorf("org_id is required for guardrail binding")
	}
	if binding.GuardrailID == "" {
		return fmt.Errorf("guardrail_id is required for guardrail binding")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	existing, ok := r.guardrailBindings[binding.ID]
	if !ok || existing.OrgID != binding.OrgID {
		return fmt.Errorf("guardrail binding %q %w", binding.ID, ErrNotFound)
	}
	def, ok := r.guardrailDefs[binding.GuardrailID]
	if !ok || def.OrgID != binding.OrgID {
		return fmt.Errorf("guardrail definition %q %w", binding.GuardrailID, ErrNotFound)
	}
	if binding.GuardrailName == "" {
		binding.GuardrailName = def.Name
	}
	binding.CreatedAt = existing.CreatedAt
	binding.UpdatedAt = time.Now().UTC()
	r.guardrailBindings[binding.ID] = cloneGuardrailBinding(binding)
	return nil
}

func (r *MemoryRepository) DeleteGuardrailBinding(ctx context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.guardrailBindings[id]; !ok {
		return fmt.Errorf("guardrail binding %q %w", id, ErrNotFound)
	}
	delete(r.guardrailBindings, id)
	return nil
}

func (r *MemoryRepository) ListEffectiveGuardrailsForOrg(ctx context.Context, orgID string) (*EffectiveGuardrails, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	activeIDs := make(map[string]struct{})
	var defs []*domain.GuardrailDefinition
	for _, def := range r.guardrailDefs {
		if def.OrgID == orgID && def.Status == domain.GuardrailStatusActive {
			activeIDs[def.ID] = struct{}{}
			defs = append(defs, cloneGuardrailDefinition(def))
		}
	}
	sortGuardrailDefinitions(defs)

	var bindings []*domain.GuardrailBinding
	for _, b := range r.guardrailBindings {
		if b.OrgID == orgID {
			if _, ok := activeIDs[b.GuardrailID]; ok {
				bindings = append(bindings, cloneGuardrailBinding(b))
			}
		}
	}
	sortGuardrailBindings(bindings)

	return &EffectiveGuardrails{
		Definitions: defs,
		Bindings:    bindings,
	}, nil
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
