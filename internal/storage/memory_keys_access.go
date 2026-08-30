package storage

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

func cloneAccessGroupRule(rule *domain.AccessGroupRule) *domain.AccessGroupRule {
	if rule == nil {
		return nil
	}
	cp := *rule
	if rule.AllowedModels != nil {
		cp.AllowedModels = slices.Clone(rule.AllowedModels)
	} else {
		cp.AllowedModels = []string{}
	}
	if rule.AllowedMCPServers != nil {
		cp.AllowedMCPServers = slices.Clone(rule.AllowedMCPServers)
	} else {
		cp.AllowedMCPServers = []string{}
	}
	if rule.AllowedMCPTools != nil {
		cp.AllowedMCPTools = slices.Clone(rule.AllowedMCPTools)
	} else {
		cp.AllowedMCPTools = []string{}
	}
	if rule.AllowedA2AAgents != nil {
		cp.AllowedA2AAgents = slices.Clone(rule.AllowedA2AAgents)
	} else {
		cp.AllowedA2AAgents = []string{}
	}
	return &cp
}

func (r *MemoryRepository) CreateAccessGroupRule(ctx context.Context, rule *domain.AccessGroupRule) error {
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
	r.mu.Lock()
	defer r.mu.Unlock()
	if rule.ID == "" {
		rule.ID = uuid.NewString()
	}
	if _, exists := r.accessGroupRules[rule.ID]; exists {
		return fmt.Errorf("access group rule %q already exists: %w", rule.ID, ErrConflict)
	}
	now := time.Now().UTC()
	if rule.CreatedAt.IsZero() {
		rule.CreatedAt = now
	}
	if rule.UpdatedAt.IsZero() {
		rule.UpdatedAt = rule.CreatedAt
	}
	if rule.AllowedModels == nil {
		rule.AllowedModels = []string{}
	}
	r.accessGroupRules[rule.ID] = cloneAccessGroupRule(rule)
	return nil
}

func (r *MemoryRepository) GetAccessGroupRule(ctx context.Context, id string) (*domain.AccessGroupRule, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	rule, ok := r.accessGroupRules[id]
	if !ok {
		return nil, fmt.Errorf("access group rule %q %w", id, ErrNotFound)
	}
	return cloneAccessGroupRule(rule), nil
}

func (r *MemoryRepository) ListAccessGroupRules(ctx context.Context, orgID string, activeOnly bool) ([]*domain.AccessGroupRule, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []*domain.AccessGroupRule
	for _, rule := range r.accessGroupRules {
		if orgID != "" && rule.OrgID != orgID {
			continue
		}
		if activeOnly && !rule.IsActive {
			continue
		}
		out = append(out, cloneAccessGroupRule(rule))
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Priority != out[j].Priority {
			return out[i].Priority > out[j].Priority
		}
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.Before(out[j].CreatedAt)
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

func (r *MemoryRepository) DeleteAccessGroupRule(ctx context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.accessGroupRules[id]; !ok {
		return fmt.Errorf("access group rule %q %w", id, ErrNotFound)
	}
	delete(r.accessGroupRules, id)
	return nil
}

func cloneVirtualKey(vk *domain.VirtualKey) *domain.VirtualKey {
	if vk == nil {
		return nil
	}
	cp := *vk
	cp.RawKey = ""
	cp.BudgetFallbacks = domain.CloneBudgetFallbacks(vk.BudgetFallbacks)
	cp.AllowedModels = slices.Clone(vk.AllowedModels)
	cp.AllowedDeployments = slices.Clone(vk.AllowedDeployments)
	cp.AllowedEndpoints = slices.Clone(vk.AllowedEndpoints)
	cp.AllowedMCPServers = slices.Clone(vk.AllowedMCPServers)
	cp.AllowedMCPTools = slices.Clone(vk.AllowedMCPTools)
	cp.AllowedMCPToolsets = slices.Clone(vk.AllowedMCPToolsets)
	cp.AllowedA2AAgents = slices.Clone(vk.AllowedA2AAgents)
	cp.AllowedClientApps = slices.Clone(vk.AllowedClientApps)
	cp.AllowedRoutingTags = slices.Clone(vk.AllowedRoutingTags)
	cp.Tags = slices.Clone(vk.Tags)
	cp.ExpiryAlertSentDays = slices.Clone(vk.ExpiryAlertSentDays)
	cp.BudgetResetAt = cloneTimePtr(vk.BudgetResetAt)
	cp.TempBudgetExpiresAt = cloneTimePtr(vk.TempBudgetExpiresAt)
	cp.KeyRotationAt = cloneTimePtr(vk.KeyRotationAt)
	cp.StagedCreatedAt = cloneTimePtr(vk.StagedCreatedAt)
	cp.LastRotatedAt = cloneTimePtr(vk.LastRotatedAt)
	cp.ExpiresAt = cloneTimePtr(vk.ExpiresAt)
	cp.RevokedAt = cloneTimePtr(vk.RevokedAt)
	if len(vk.Metadata) > 0 {
		cp.Metadata = make(map[string]string, len(vk.Metadata))
		for k, v := range vk.Metadata {
			cp.Metadata[k] = v
		}
	}
	return &cp
}

func (r *MemoryRepository) CreateVirtualKey(ctx context.Context, vk *domain.VirtualKey) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if vk.ID == "" {
		vk.ID = uuid.NewString()
	}
	if vk.KeyType == "" {
		vk.KeyType = domain.KeyTypeDefault
	}
	now := time.Now().UTC()
	vk.BudgetResetPeriod, vk.BudgetResetAt = resolveBudgetResetSchedule(vk.BudgetResetPeriod, vk.BudgetResetAt, now)
	vk.CreatedAt = now
	vk.UpdatedAt = now
	cp := cloneVirtualKey(vk)
	r.keysByID[cp.ID] = cp
	r.keysByHash[cp.KeyHash] = cp
	return nil
}

func (r *MemoryRepository) UpdateVirtualKey(ctx context.Context, vk *domain.VirtualKey) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if vk == nil || vk.ID == "" {
		return fmt.Errorf("virtual key id is required")
	}
	existing, ok := r.keysByID[vk.ID]
	if !ok {
		return fmt.Errorf("virtual key %q %w", vk.ID, ErrNotFound)
	}
	now := time.Now().UTC()
	if vk.OrgID == "" {
		vk.OrgID = existing.OrgID
	}
	if vk.KeyHash == "" {
		vk.KeyHash = existing.KeyHash
	}
	if vk.KeyPrefix == "" {
		vk.KeyPrefix = existing.KeyPrefix
	}
	if vk.KeyType == "" {
		if existing.KeyType != "" {
			vk.KeyType = existing.KeyType
		} else {
			vk.KeyType = domain.KeyTypeDefault
		}
	}
	if vk.CreatedAt.IsZero() {
		vk.CreatedAt = existing.CreatedAt
	}
	if existing.KeyHash != "" && existing.KeyHash != vk.KeyHash {
		delete(r.keysByHash, existing.KeyHash)
	}
	vk.BudgetResetPeriod, vk.BudgetResetAt = resolveBudgetResetSchedule(vk.BudgetResetPeriod, vk.BudgetResetAt, now)
	vk.UpdatedAt = now
	cp := cloneVirtualKey(vk)
	r.keysByID[cp.ID] = cp
	r.keysByHash[cp.KeyHash] = cp
	return nil
}

func (r *MemoryRepository) GetVirtualKeyByHash(ctx context.Context, keyHash string) (*domain.VirtualKey, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	vk, ok := r.keysByHash[keyHash]
	if !ok {
		return nil, fmt.Errorf("virtual key not found")
	}
	return cloneVirtualKey(vk), nil
}

func (r *MemoryRepository) GetVirtualKeyByID(ctx context.Context, id string) (*domain.VirtualKey, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	vk, ok := r.keysByID[id]
	if !ok {
		return nil, fmt.Errorf("virtual key %q not found", id)
	}
	return cloneVirtualKey(vk), nil
}

func (r *MemoryRepository) ListVirtualKeys(ctx context.Context, orgID string) ([]*domain.VirtualKey, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []*domain.VirtualKey
	for _, vk := range r.keysByID {
		if orgID == "" || vk.OrgID == orgID {
			out = append(out, cloneVirtualKey(vk))
		}
	}
	return out, nil
}

func (r *MemoryRepository) ListVirtualKeysByUserID(ctx context.Context, orgID, userID string) ([]*domain.VirtualKey, error) {
	orgID = strings.TrimSpace(orgID)
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return nil, nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []*domain.VirtualKey
	for _, vk := range r.keysByID {
		if (orgID == "" || vk.OrgID == orgID) && vk.UserID == userID {
			out = append(out, cloneVirtualKey(vk))
		}
	}
	return out, nil
}

func (r *MemoryRepository) RevokeVirtualKey(ctx context.Context, id string) error {
	return r.RevokeVirtualKeyWithActor(ctx, id, "")
}

func (r *MemoryRepository) RevokeVirtualKeyWithActor(_ context.Context, id, revokedBy string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	vk, ok := r.keysByID[id]
	if !ok {
		return fmt.Errorf("virtual key %q %w", id, ErrNotFound)
	}
	now := time.Now().UTC()
	vk.IsActive = false
	vk.RevokedAt = &now
	vk.RevokedBy = strings.TrimSpace(revokedBy)
	vk.UpdatedAt = now
	return nil
}

func (r *MemoryRepository) UnblockVirtualKey(_ context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	vk, ok := r.keysByID[id]
	if !ok {
		return fmt.Errorf("virtual key %q %w", id, ErrNotFound)
	}
	vk.IsActive = true
	vk.RevokedAt = nil
	vk.RevokedBy = ""
	vk.UpdatedAt = time.Now().UTC()
	return nil
}

func (r *MemoryRepository) GetVirtualKeyAuthBundleByHash(_ context.Context, keyHash string, now time.Time) (*VirtualKeyAuthBundle, error) {
	keyHash = strings.TrimSpace(keyHash)
	if keyHash == "" {
		return nil, fmt.Errorf("virtual key %w", ErrNotFound)
	}
	nowUTC := now.UTC()
	r.mu.RLock()
	defer r.mu.RUnlock()

	var (
		vk         *domain.VirtualKey
		deprecated bool
		revokeAt   time.Time
	)
	if found, ok := r.keysByHash[keyHash]; ok && found != nil {
		vk = found
	} else if entry, ok := r.deprecatedKeyHashes[keyHash]; ok && entry != nil && nowUTC.Before(entry.revokeAt) {
		if target, exists := r.keysByID[entry.virtualKeyID]; exists && target != nil {
			vk = target
			deprecated = true
			revokeAt = entry.revokeAt
		}
	}
	if vk == nil {
		return nil, fmt.Errorf("virtual key %w", ErrNotFound)
	}

	bundle := &VirtualKeyAuthBundle{
		Key:                   cloneVirtualKey(vk),
		Deprecated:            deprecated,
		DeprecatedKeyRevokeAt: revokeAt,
	}
	if org, ok := r.orgs[vk.OrgID]; ok && org != nil {
		bundle.Org = cloneOrganization(org)
	}
	if vk.TeamID != "" {
		if team, ok := r.teams[vk.TeamID]; ok && team != nil {
			bundle.Team = cloneTeam(team)
		}
	}
	if vk.ProjectID != "" {
		if proj, ok := r.projects[vk.ProjectID]; ok && proj != nil {
			bundle.Project = cloneProject(proj)
		}
	}
	if vk.UserID != "" {
		if user, ok := r.users[vk.UserID]; ok && user != nil {
			bundle.User = cloneUser(user)
		}
		if vk.TeamID != "" {
			if tmID, ok := r.teamMembershipsByTuple[teamMembershipTupleKey(vk.TeamID, vk.UserID)]; ok {
				if tm, exists := r.teamMemberships[tmID]; exists && tm != nil {
					bundle.TeamMembership = cloneTeamMembership(tm)
				}
			}
		}
	}
	return bundle, nil
}

func (r *MemoryRepository) ListVirtualKeysFiltered(_ context.Context, filter VirtualKeyFilter) ([]*domain.VirtualKey, int, error) {
	nowUTC := time.Now().UTC()
	statusFilter := strings.ToLower(strings.TrimSpace(filter.Status))
	search := strings.ToLower(strings.TrimSpace(filter.Search))

	r.mu.RLock()
	defer r.mu.RUnlock()

	matched := make([]*domain.VirtualKey, 0)
	for _, vk := range r.keysByID {
		if vk == nil {
			continue
		}
		if filter.OrgID != "" && vk.OrgID != filter.OrgID {
			continue
		}
		if filter.TeamID != "" && vk.TeamID != filter.TeamID {
			continue
		}
		if filter.UserID != "" && vk.UserID != filter.UserID {
			continue
		}
		if filter.ProjectID != "" && vk.ProjectID != filter.ProjectID {
			continue
		}
		expired := vk.ExpiresAt != nil && !nowUTC.Before(vk.ExpiresAt.UTC())
		switch statusFilter {
		case "active":
			if !vk.IsActive || expired {
				continue
			}
		case "revoked":
			if vk.IsActive {
				continue
			}
		case "expired":
			if !expired {
				continue
			}
		}
		if search != "" {
			if !strings.Contains(strings.ToLower(vk.ID), search) &&
				!strings.Contains(strings.ToLower(vk.KeyPrefix), search) &&
				!strings.Contains(strings.ToLower(vk.Name), search) {
				continue
			}
		}
		matched = append(matched, cloneVirtualKey(vk))
	}
	sort.Slice(matched, func(i, j int) bool {
		if !matched[i].CreatedAt.Equal(matched[j].CreatedAt) {
			return matched[i].CreatedAt.After(matched[j].CreatedAt)
		}
		return matched[i].ID < matched[j].ID
	})
	total := len(matched)
	offset := filter.Offset
	if offset < 0 {
		offset = 0
	}
	if offset >= total {
		return []*domain.VirtualKey{}, total, nil
	}
	end := total
	if filter.Limit > 0 && offset+filter.Limit < end {
		end = offset + filter.Limit
	}
	return matched[offset:end], total, nil
}

func (r *MemoryRepository) BulkUpdateVirtualKeys(_ context.Context, orgID string, ids []string, patch VirtualKeyBulkPatch) ([]*domain.VirtualKey, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now().UTC()
	var updated []*domain.VirtualKey
	for _, id := range ids {
		vk, ok := r.keysByID[id]
		if !ok || vk == nil {
			return nil, fmt.Errorf("virtual key %q %w", id, ErrNotFound)
		}
		if orgID != "" && vk.OrgID != orgID {
			return nil, fmt.Errorf("virtual key %q %w", id, ErrNotFound)
		}
		if patch.IsActive != nil {
			vk.IsActive = *patch.IsActive
			if !vk.IsActive {
				t := now
				vk.RevokedAt = &t
				vk.RevokedBy = strings.TrimSpace(patch.RevokedBy)
				for h, entry := range r.deprecatedKeyHashes {
					if entry != nil && entry.virtualKeyID == vk.ID {
						delete(r.deprecatedKeyHashes, h)
					}
				}
			} else {
				vk.RevokedAt = nil
				vk.RevokedBy = ""
			}
		}
		if patch.MaxBudgetMicros != nil {
			vk.MaxBudgetMicros = *patch.MaxBudgetMicros
		}
		if patch.RPMLimit != nil {
			vk.RPMLimit = *patch.RPMLimit
		}
		if patch.TPMLimit != nil {
			vk.TPMLimit = *patch.TPMLimit
		}
		if patch.AllowedModels != nil {
			vk.AllowedModels = slices.Clone(patch.AllowedModels)
		}
		vk.UpdatedAt = now
		updated = append(updated, cloneVirtualKey(vk))
	}
	return updated, nil
}

func (r *MemoryRepository) ResetEntitySpend(_ context.Context, scope EntitySpendScope, orgID, entityID, secondaryID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	now := time.Now().UTC()
	switch scope {
	case EntitySpendScopeKey:
		vk, ok := r.keysByID[entityID]
		if !ok || vk == nil || (orgID != "" && vk.OrgID != orgID) {
			return fmt.Errorf("virtual key %q %w", entityID, ErrNotFound)
		}
		vk.SpentMicros = 0
		vk.UpdatedAt = now
		return nil
	case EntitySpendScopeTeamMember:
		id, ok := r.teamMembershipsByTuple[teamMembershipTupleKey(entityID, secondaryID)]
		if !ok {
			return fmt.Errorf("team membership (%q, %q) %w", entityID, secondaryID, ErrNotFound)
		}
		m, ok := r.teamMemberships[id]
		if !ok || m == nil || (orgID != "" && m.OrgID != orgID) {
			return fmt.Errorf("team membership (%q, %q) %w", entityID, secondaryID, ErrNotFound)
		}
		m.SpentMicros = 0
		m.UpdatedAt = now
		return nil
	default:
		return fmt.Errorf("unsupported spend reset scope %q", scope)
	}
}

func (r *MemoryRepository) SumChildKeyThroughput(_ context.Context, orgID, teamID, excludeKeyID string) (int, int, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	var rpmSum, tpmSum int
	for _, vk := range r.keysByID {
		if vk == nil || !vk.IsActive {
			continue
		}
		if excludeKeyID != "" && vk.ID == excludeKeyID {
			continue
		}
		if orgID != "" && vk.OrgID != orgID {
			continue
		}
		if teamID != "" {
			if vk.TeamID != teamID {
				continue
			}
		}
		rpmSum += vk.RPMLimit
		tpmSum += vk.TPMLimit
	}
	return rpmSum, tpmSum, nil
}

func (r *MemoryRepository) ListVirtualKeysExpiringBefore(_ context.Context, cutoff time.Time, limit int) ([]*domain.VirtualKey, error) {
	cutoffUTC := cutoff.UTC()
	nowUTC := time.Now().UTC()
	r.mu.RLock()
	defer r.mu.RUnlock()
	var out []*domain.VirtualKey
	for _, vk := range r.keysByID {
		if vk == nil || !vk.IsActive || vk.ExpiresAt == nil {
			continue
		}
		expUTC := vk.ExpiresAt.UTC()
		if expUTC.After(nowUTC) && !expUTC.After(cutoffUTC) {
			out = append(out, cloneVirtualKey(vk))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].ExpiresAt.Before(*out[j].ExpiresAt)
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (r *MemoryRepository) MarkVirtualKeyExpiryAlertSent(_ context.Context, keyID string, alertDay int) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	vk, ok := r.keysByID[keyID]
	if !ok || vk == nil {
		return fmt.Errorf("virtual key %q %w", keyID, ErrNotFound)
	}
	if !slices.Contains(vk.ExpiryAlertSentDays, alertDay) {
		vk.ExpiryAlertSentDays = append(vk.ExpiryAlertSentDays, alertDay)
	}
	return nil
}

func (r *MemoryRepository) MarkVirtualKeyRotated(_ context.Context, keyID string, rotatedAt time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	vk, ok := r.keysByID[keyID]
	if !ok || vk == nil {
		return fmt.Errorf("virtual key %q %w", keyID, ErrNotFound)
	}
	ts := rotatedAt.UTC()
	vk.LastRotatedAt = &ts
	vk.RotationCount++
	vk.UpdatedAt = ts
	return nil
}

func (r *MemoryRepository) AddDeprecatedVirtualKeyHash(ctx context.Context, keyHash, virtualKeyID string, revokeAt time.Time) error {
	keyHash = strings.TrimSpace(keyHash)
	virtualKeyID = strings.TrimSpace(virtualKeyID)
	if keyHash == "" || virtualKeyID == "" {
		return fmt.Errorf("key_hash and virtual_key_id are required")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.keysByID[virtualKeyID]; !ok {
		return fmt.Errorf("virtual key %q %w", virtualKeyID, ErrNotFound)
	}
	if r.deprecatedKeyHashes == nil {
		r.deprecatedKeyHashes = make(map[string]*deprecatedKeyHashEntry)
	}
	r.deprecatedKeyHashes[keyHash] = &deprecatedKeyHashEntry{
		keyHash:      keyHash,
		virtualKeyID: virtualKeyID,
		revokeAt:     revokeAt.UTC(),
		createdAt:    time.Now().UTC(),
	}
	return nil
}

func (r *MemoryRepository) GetActiveDeprecatedVirtualKey(ctx context.Context, keyHash string, now time.Time) (*domain.VirtualKey, time.Time, error) {
	keyHash = strings.TrimSpace(keyHash)
	if keyHash == "" {
		return nil, time.Time{}, fmt.Errorf("deprecated virtual key %w", ErrNotFound)
	}
	nowUTC := now.UTC()
	r.mu.RLock()
	defer r.mu.RUnlock()
	entry, ok := r.deprecatedKeyHashes[keyHash]
	if !ok || entry == nil || !nowUTC.Before(entry.revokeAt) {
		return nil, time.Time{}, fmt.Errorf("deprecated virtual key %w", ErrNotFound)
	}
	vk, ok := r.keysByID[entry.virtualKeyID]
	if !ok || vk == nil {
		return nil, time.Time{}, fmt.Errorf("deprecated virtual key %w", ErrNotFound)
	}
	return cloneVirtualKey(vk), entry.revokeAt, nil
}

func (r *MemoryRepository) DeleteExpiredDeprecatedVirtualKeyHashes(ctx context.Context, now time.Time) (int64, error) {
	nowUTC := now.UTC()
	r.mu.Lock()
	defer r.mu.Unlock()
	var deleted int64
	for h, entry := range r.deprecatedKeyHashes {
		if entry == nil || !nowUTC.Before(entry.revokeAt) {
			delete(r.deprecatedKeyHashes, h)
			deleted++
		}
	}
	return deleted, nil
}

func (r *MemoryRepository) ListDeprecatedVirtualKeyHashesByKeyID(_ context.Context, virtualKeyID string) ([]string, error) {
	virtualKeyID = strings.TrimSpace(virtualKeyID)
	if virtualKeyID == "" {
		return nil, nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	var hashes []string
	for h, entry := range r.deprecatedKeyHashes {
		if entry != nil && entry.virtualKeyID == virtualKeyID {
			hashes = append(hashes, h)
		}
	}
	sort.Strings(hashes)
	return hashes, nil
}

func (r *MemoryRepository) DeleteDeprecatedVirtualKeyHashesByKeyID(ctx context.Context, virtualKeyID string) ([]string, error) {
	virtualKeyID = strings.TrimSpace(virtualKeyID)
	if virtualKeyID == "" {
		return nil, nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	var hashes []string
	for h, entry := range r.deprecatedKeyHashes {
		if entry != nil && entry.virtualKeyID == virtualKeyID {
			hashes = append(hashes, h)
			delete(r.deprecatedKeyHashes, h)
		}
	}
	sort.Strings(hashes)
	return hashes, nil
}

func (r *MemoryRepository) ListVirtualKeysDueForRotation(ctx context.Context, now time.Time, limit int) ([]*domain.VirtualKey, error) {
	nowUTC := now.UTC()
	r.mu.RLock()
	defer r.mu.RUnlock()
	var due []*domain.VirtualKey
	for _, vk := range r.keysByID {
		if vk == nil || !vk.IsActive {
			continue
		}
		if vk.ExpiresAt != nil && !nowUTC.Before(*vk.ExpiresAt) {
			continue
		}
		if vk.RotationIntervalSec <= 0 || vk.KeyRotationAt == nil {
			continue
		}
		if !vk.KeyRotationAt.UTC().After(nowUTC) {
			due = append(due, cloneVirtualKey(vk))
		}
	}
	sort.Slice(due, func(i, j int) bool {
		ti, tj := due[i].KeyRotationAt.UTC(), due[j].KeyRotationAt.UTC()
		if !ti.Equal(tj) {
			return ti.Before(tj)
		}
		return due[i].ID < due[j].ID
	})
	if limit > 0 && len(due) > limit {
		due = due[:limit]
	}
	return due, nil
}
