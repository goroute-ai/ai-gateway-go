package storage

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

func (r *MemoryRepository) CreateProviderCredential(ctx context.Context, cred *domain.ProviderCredential) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if cred.ID == "" {
		cred.ID = uuid.NewString()
	}
	if cred.KeyVersion <= 0 {
		cred.KeyVersion = 1
	}
	now := time.Now().UTC()
	cred.CreatedAt = now
	cred.UpdatedAt = now
	cp := *cred
	cp.DecryptedAPIKey = "" // Never store plaintext key in repository
	r.credentials[cp.ID] = &cp
	r.routingRev.Add(1)
	return nil
}

func (r *MemoryRepository) UpdateProviderCredential(ctx context.Context, cred *domain.ProviderCredential) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if cred == nil || cred.ID == "" {
		return fmt.Errorf("credential id is required")
	}
	if _, ok := r.credentials[cred.ID]; !ok {
		return fmt.Errorf("provider credential %q not found", cred.ID)
	}
	cred.UpdatedAt = time.Now().UTC()
	cp := *cred
	cp.DecryptedAPIKey = ""
	r.credentials[cp.ID] = &cp
	r.routingRev.Add(1)
	return nil
}

func (r *MemoryRepository) GetProviderCredential(ctx context.Context, id string) (*domain.ProviderCredential, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.credentials[id]
	if !ok {
		return nil, fmt.Errorf("provider credential %q not found", id)
	}
	cp := *c
	return &cp, nil
}

func (r *MemoryRepository) ListProviderCredentials(ctx context.Context, orgID string) ([]*domain.ProviderCredential, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []*domain.ProviderCredential
	for _, c := range r.credentials {
		if orgID == "" || c.OrgID == orgID {
			cp := *c
			out = append(out, &cp)
		}
	}
	return out, nil
}

func cloneFallbackTargets(src []domain.FallbackTarget) []domain.FallbackTarget {
	if src == nil {
		return nil
	}
	out := make([]domain.FallbackTarget, len(src))
	for i, ft := range src {
		out[i] = ft
		if ft.Overrides != nil {
			out[i].Overrides = maps.Clone(ft.Overrides)
		}
	}
	return out
}

func cloneModelGroup(mg *domain.ModelGroup) *domain.ModelGroup {
	if mg == nil {
		return nil
	}
	cp := *mg
	if mg.FallbackGroupIDs != nil {
		cp.FallbackGroupIDs = slices.Clone(mg.FallbackGroupIDs)
	}
	cp.ContextWindowFallbacks = cloneFallbackTargets(mg.ContextWindowFallbacks)
	cp.ContentPolicyFallbacks = cloneFallbackTargets(mg.ContentPolicyFallbacks)
	cp.FallbackTargets = cloneFallbackTargets(mg.FallbackTargets)
	cp.SaturationFallbacks = cloneFallbackTargets(mg.SaturationFallbacks)
	if mg.RetryPolicy != nil {
		rp := *mg.RetryPolicy
		cp.RetryPolicy = &rp
	}
	if mg.CooldownPolicy != nil {
		cd := *mg.CooldownPolicy
		if mg.CooldownPolicy.AllowedFails != nil {
			cd.AllowedFails = maps.Clone(mg.CooldownPolicy.AllowedFails)
		}
		cp.CooldownPolicy = &cd
	}
	return &cp
}

func cloneDeployment(d *domain.Deployment) *domain.Deployment {
	if d == nil {
		return nil
	}
	cp := *d
	if d.Tags != nil {
		cp.Tags = slices.Clone(d.Tags)
	}
	return &cp
}

func (r *MemoryRepository) CreateModelGroup(ctx context.Context, mg *domain.ModelGroup) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if mg.ID == "" {
		mg.ID = uuid.NewString()
	}
	if mg.RoutingStrategy == "" {
		mg.RoutingStrategy = domain.StrategyWeightedShuffle
	}
	now := time.Now().UTC()
	mg.CreatedAt = now
	mg.UpdatedAt = now
	cp := cloneModelGroup(mg)
	r.groupsByID[cp.ID] = cp
	r.routingRev.Add(1)
	return nil
}

func (r *MemoryRepository) GetModelGroupByAlias(ctx context.Context, orgID, alias string) (*domain.ModelGroup, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, mg := range r.groupsByID {
		if mg.OrgID == orgID && mg.Alias == alias && mg.IsActive {
			return cloneModelGroup(mg), nil
		}
	}
	return nil, fmt.Errorf("model group %q not found for org %q", alias, orgID)
}

func (r *MemoryRepository) GetModelGroupByID(ctx context.Context, id string) (*domain.ModelGroup, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	mg, ok := r.groupsByID[id]
	if !ok {
		return nil, fmt.Errorf("model group %q not found", id)
	}
	return cloneModelGroup(mg), nil
}

func (r *MemoryRepository) ListModelGroups(ctx context.Context, orgID string) ([]*domain.ModelGroup, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []*domain.ModelGroup
	for _, mg := range r.groupsByID {
		if orgID == "" || mg.OrgID == orgID {
			out = append(out, cloneModelGroup(mg))
		}
	}
	return out, nil
}

func (r *MemoryRepository) UpdateModelGroup(ctx context.Context, mg *domain.ModelGroup) error {
	if mg == nil || strings.TrimSpace(mg.ID) == "" {
		return fmt.Errorf("model group id is required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	existing, ok := r.groupsByID[mg.ID]
	if !ok {
		return fmt.Errorf("model group %q %w", mg.ID, ErrNotFound)
	}
	if mg.OrgID == "" {
		mg.OrgID = existing.OrgID
	}
	for id, other := range r.groupsByID {
		if id != mg.ID && other.OrgID == mg.OrgID && other.Alias == mg.Alias {
			return fmt.Errorf("model group alias %q already exists in organization: %w", mg.Alias, ErrConflict)
		}
	}
	if mg.RoutingStrategy == "" {
		mg.RoutingStrategy = domain.StrategyWeightedShuffle
	}
	if mg.CreatedAt.IsZero() {
		mg.CreatedAt = existing.CreatedAt
	}
	mg.UpdatedAt = time.Now().UTC()
	r.groupsByID[mg.ID] = cloneModelGroup(mg)
	r.routingRev.Add(1)
	return nil
}

func (r *MemoryRepository) DeleteModelGroup(ctx context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.groupsByID[id]; !ok {
		return fmt.Errorf("model group %q %w", id, ErrNotFound)
	}
	delete(r.groupsByID, id)
	for depID, dep := range r.deployments {
		if dep != nil && dep.ModelGroupID == id {
			delete(r.deployments, depID)
		}
	}
	r.routingRev.Add(1)
	return nil
}

func (r *MemoryRepository) CreateDeployment(ctx context.Context, dep *domain.Deployment) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if dep.ID == "" {
		dep.ID = uuid.NewString()
	}
	if dep.Status == "" {
		dep.Status = domain.DeploymentStatusActive
	}
	if dep.Weight <= 0 {
		dep.Weight = 100
	}
	now := time.Now().UTC()
	dep.CreatedAt = now
	dep.UpdatedAt = now
	cp := cloneDeployment(dep)
	r.deployments[cp.ID] = cp
	r.routingRev.Add(1)
	return nil
}

func (r *MemoryRepository) GetDeployment(ctx context.Context, id string) (*domain.Deployment, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	d, ok := r.deployments[id]
	if !ok {
		return nil, fmt.Errorf("deployment %q %w", id, ErrNotFound)
	}
	cp := cloneDeployment(d)
	if gm, ok := r.globalModels[cp.GlobalModelID]; ok {
		cp.GlobalModel = cloneGlobalModel(gm)
	}
	if cred, ok := r.credentials[cp.CredentialID]; ok {
		credCopy := *cred
		cp.Credential = &credCopy
	}
	return cp, nil
}

func (r *MemoryRepository) UpdateDeployment(ctx context.Context, dep *domain.Deployment) error {
	if dep == nil || strings.TrimSpace(dep.ID) == "" {
		return fmt.Errorf("deployment id is required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	existing, ok := r.deployments[dep.ID]
	if !ok {
		return fmt.Errorf("deployment %q %w", dep.ID, ErrNotFound)
	}
	if dep.ModelGroupID == "" {
		dep.ModelGroupID = existing.ModelGroupID
	}
	if dep.GlobalModelID == "" {
		dep.GlobalModelID = existing.GlobalModelID
	}
	if dep.CredentialID == "" {
		dep.CredentialID = existing.CredentialID
	}
	if dep.Status == "" {
		dep.Status = existing.Status
	}
	if dep.Weight <= 0 {
		dep.Weight = 100
	}
	if dep.CreatedAt.IsZero() {
		dep.CreatedAt = existing.CreatedAt
	}
	dep.UpdatedAt = time.Now().UTC()
	cp := cloneDeployment(dep)
	if gm, ok := r.globalModels[cp.GlobalModelID]; ok {
		cp.GlobalModel = cloneGlobalModel(gm)
		dep.GlobalModel = cloneGlobalModel(gm)
	}
	if cred, ok := r.credentials[cp.CredentialID]; ok {
		credCopy := *cred
		cp.Credential = &credCopy
		credCopy2 := *cred
		dep.Credential = &credCopy2
	}
	r.deployments[dep.ID] = cp
	r.routingRev.Add(1)
	return nil
}

func (r *MemoryRepository) DeleteDeployment(ctx context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.deployments[id]; !ok {
		return fmt.Errorf("deployment %q %w", id, ErrNotFound)
	}
	delete(r.deployments, id)
	r.routingRev.Add(1)
	return nil
}

func (r *MemoryRepository) ListDeploymentsByGroup(ctx context.Context, groupID string) ([]*domain.Deployment, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []*domain.Deployment
	for _, d := range r.deployments {
		if d.ModelGroupID == groupID {
			cp := cloneDeployment(d)
			if gm, ok := r.globalModels[cp.GlobalModelID]; ok {
				cp.GlobalModel = cloneGlobalModel(gm)
			}
			if cred, ok := r.credentials[cp.CredentialID]; ok {
				credCopy := *cred
				cp.Credential = &credCopy
			}
			out = append(out, cp)
		}
	}
	return out, nil
}

func (r *MemoryRepository) ListAllDeployments(ctx context.Context) ([]*domain.Deployment, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []*domain.Deployment
	for _, d := range r.deployments {
		cp := cloneDeployment(d)
		if gm, ok := r.globalModels[cp.GlobalModelID]; ok {
			cp.GlobalModel = cloneGlobalModel(gm)
		}
		if cred, ok := r.credentials[cp.CredentialID]; ok {
			credCopy := *cred
			cp.Credential = &credCopy
		}
		out = append(out, cp)
	}
	return out, nil
}

func (r *MemoryRepository) UpdateDeploymentStatus(ctx context.Context, depID string, status domain.DeploymentStatus) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	dep, ok := r.deployments[depID]
	if !ok {
		return fmt.Errorf("deployment %q not found", depID)
	}
	dep.Status = status
	dep.UpdatedAt = time.Now().UTC()
	r.routingRev.Add(1)
	return nil
}
