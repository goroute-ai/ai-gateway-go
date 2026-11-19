package storage

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

func (r *MemoryRepository) UpsertQuotaPolicy(_ context.Context, policy *domain.QuotaPolicy) error {
	now := time.Now().UTC()
	if err := normalizeQuotaPolicy(policy, now); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	tupleKey := quotaPolicyTupleKey(policy.OrgID, policy.ScopeType, policy.ScopeID, policy.ModelPattern)
	if existingID, ok := r.quotaPoliciesByTuple[tupleKey]; ok {
		existing := r.quotaPolicies[existingID]
		policy.ID = existing.ID
		policy.CreatedAt = existing.CreatedAt
		if existing.SpentMicros > policy.SpentMicros {
			policy.SpentMicros = existing.SpentMicros
		}
		policy.UpdatedAt = now
		r.quotaPolicies[existing.ID] = policy.Clone()
		return nil
	}

	if policy.ID == "" {
		policy.ID = uuid.NewString()
	} else if _, exists := r.quotaPolicies[policy.ID]; exists {
		return fmt.Errorf("quota policy %q already exists: %w", policy.ID, ErrConflict)
	}
	if policy.CreatedAt.IsZero() {
		policy.CreatedAt = now
	}
	policy.UpdatedAt = now
	r.quotaPolicies[policy.ID] = policy.Clone()
	r.quotaPoliciesByTuple[tupleKey] = policy.ID
	return nil
}

func (r *MemoryRepository) GetQuotaPolicy(_ context.Context, id string) (*domain.QuotaPolicy, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	p, ok := r.quotaPolicies[id]
	if !ok {
		return nil, fmt.Errorf("quota policy %q %w", id, ErrNotFound)
	}
	return p.Clone(), nil
}

func (r *MemoryRepository) ListQuotaPolicies(_ context.Context, filter QuotaPolicyFilter) ([]*domain.QuotaPolicy, error) {
	orgID := strings.TrimSpace(filter.OrgID)
	scopeType := domain.QuotaScopeType(strings.ToLower(strings.TrimSpace(string(filter.ScopeType))))
	scopeID := strings.TrimSpace(filter.ScopeID)
	modelPattern := strings.TrimSpace(filter.ModelPattern)

	r.mu.RLock()
	defer r.mu.RUnlock()

	var out []*domain.QuotaPolicy
	for _, p := range r.quotaPolicies {
		if orgID != "" && p.OrgID != orgID {
			continue
		}
		if scopeType != "" && p.ScopeType != scopeType {
			continue
		}
		if scopeID != "" && p.ScopeID != scopeID {
			continue
		}
		if modelPattern != "" && p.ModelPattern != modelPattern {
			continue
		}
		if filter.ActiveOnly && !p.IsActive {
			continue
		}
		out = append(out, p.Clone())
	}
	sortQuotaPolicies(out)
	return out, nil
}

func (r *MemoryRepository) DeleteQuotaPolicy(_ context.Context, id string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	p, ok := r.quotaPolicies[id]
	if !ok {
		return fmt.Errorf("quota policy %q %w", id, ErrNotFound)
	}
	delete(r.quotaPoliciesByTuple, quotaPolicyTupleKey(p.OrgID, p.ScopeType, p.ScopeID, p.ModelPattern))
	delete(r.quotaPolicies, id)
	return nil
}

func (r *MemoryRepository) IncrementQuotaPolicySpend(_ context.Context, id string, deltaMicros int64) error {
	id = strings.TrimSpace(id)
	if id == "" {
		return fmt.Errorf("quota policy id is required")
	}
	if deltaMicros < 0 {
		return fmt.Errorf("delta_micros must be non-negative")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	p, ok := r.quotaPolicies[id]
	if !ok {
		return fmt.Errorf("quota policy %q %w", id, ErrNotFound)
	}
	p.SpentMicros += deltaMicros
	p.UpdatedAt = time.Now().UTC()
	return nil
}

func (r *MemoryRepository) UpsertDeploymentPTUShare(_ context.Context, share *domain.DeploymentPTUShare) error {
	now := time.Now().UTC()
	if err := normalizePTUShare(share, now); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	tupleKey := ptuShareTupleKey(share.DeploymentID, share.TeamID)
	if existingID, ok := r.ptuSharesByTuple[tupleKey]; ok {
		existing := r.ptuShares[existingID]
		share.ID = existing.ID
		share.CreatedAt = existing.CreatedAt
		share.UpdatedAt = now
		r.ptuShares[existing.ID] = share.Clone()
		r.routingRev.Add(1)
		return nil
	}

	if share.ID == "" {
		share.ID = uuid.NewString()
	} else if _, exists := r.ptuShares[share.ID]; exists {
		return fmt.Errorf("deployment PTU share %q already exists: %w", share.ID, ErrConflict)
	}
	r.ptuShares[share.ID] = share.Clone()
	r.ptuSharesByTuple[tupleKey] = share.ID
	r.routingRev.Add(1)
	return nil
}

func (r *MemoryRepository) ListDeploymentPTUShares(_ context.Context, deploymentID string) ([]*domain.DeploymentPTUShare, error) {
	deploymentID = strings.TrimSpace(deploymentID)
	r.mu.RLock()
	defer r.mu.RUnlock()

	var out []*domain.DeploymentPTUShare
	for _, s := range r.ptuShares {
		if deploymentID != "" && s.DeploymentID != deploymentID {
			continue
		}
		out = append(out, s.Clone())
	}
	sortPTUShares(out)
	return out, nil
}

func (r *MemoryRepository) DeleteDeploymentPTUShare(_ context.Context, deploymentID, teamID string) error {
	deploymentID = strings.TrimSpace(deploymentID)
	teamID = strings.TrimSpace(teamID)
	r.mu.Lock()
	defer r.mu.Unlock()

	tupleKey := ptuShareTupleKey(deploymentID, teamID)
	id, ok := r.ptuSharesByTuple[tupleKey]
	if !ok {
		return fmt.Errorf("deployment PTU share (%s, %s) %w", deploymentID, teamID, ErrNotFound)
	}
	delete(r.ptuSharesByTuple, tupleKey)
	delete(r.ptuShares, id)
	r.routingRev.Add(1)
	return nil
}

func (r *MemoryRepository) HasTeamPTUShares(_ context.Context, teamID string) (bool, error) {
	teamID = strings.TrimSpace(teamID)
	if teamID == "" {
		return false, nil
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	for _, s := range r.ptuShares {
		if s != nil && s.TeamID == teamID {
			return true, nil
		}
	}
	return false, nil
}

func (r *MemoryRepository) UpsertPriorityClass(_ context.Context, pc *domain.PriorityClass) error {
	now := time.Now().UTC()
	if err := normalizePriorityClass(pc, now); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	tupleKey := priorityClassTupleKey(pc.OrgID, pc.Name)
	if existingID, ok := r.priorityClassesByTuple[tupleKey]; ok {
		existing := r.priorityClasses[existingID]
		pc.ID = existing.ID
		pc.CreatedAt = existing.CreatedAt
		r.priorityClasses[existing.ID] = pc.Clone()
		r.routingRev.Add(1)
		return nil
	}

	if pc.ID == "" {
		pc.ID = uuid.NewString()
	} else if _, exists := r.priorityClasses[pc.ID]; exists {
		return fmt.Errorf("priority class %q already exists: %w", pc.ID, ErrConflict)
	}
	r.priorityClasses[pc.ID] = pc.Clone()
	r.priorityClassesByTuple[tupleKey] = pc.ID
	r.routingRev.Add(1)
	return nil
}

func (r *MemoryRepository) ListPriorityClasses(_ context.Context, orgID string) ([]*domain.PriorityClass, error) {
	orgID = strings.TrimSpace(orgID)
	r.mu.RLock()
	defer r.mu.RUnlock()

	var out []*domain.PriorityClass
	for _, pc := range r.priorityClasses {
		if orgID != "" && pc.OrgID != orgID {
			continue
		}
		out = append(out, pc.Clone())
	}
	sortPriorityClasses(out)
	return out, nil
}

func (r *MemoryRepository) UpsertBudgetWindowLimit(_ context.Context, limit *domain.BudgetWindowLimit) error {
	now := time.Now().UTC()
	hasExplicitReset := limit != nil && !limit.WindowResetAt.IsZero()
	if err := normalizeBudgetWindowLimit(limit, now); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()

	tupleKey := budgetWindowTupleKey(limit.OrgID, limit.ScopeType, limit.ScopeID, limit.WindowType)
	if existingID, ok := r.budgetWindowsByTuple[tupleKey]; ok {
		existing := r.budgetWindows[existingID]
		limit.ID = existing.ID
		limit.CreatedAt = existing.CreatedAt
		if existing.SpentMicros > limit.SpentMicros {
			limit.SpentMicros = existing.SpentMicros
		}
		if !hasExplicitReset {
			limit.WindowResetAt = existing.WindowResetAt
		}
		limit.UpdatedAt = now
		r.budgetWindows[existing.ID] = limit.Clone()
		return nil
	}

	if limit.ID == "" {
		limit.ID = uuid.NewString()
	} else if _, exists := r.budgetWindows[limit.ID]; exists {
		return fmt.Errorf("budget window limit %q already exists: %w", limit.ID, ErrConflict)
	}
	if limit.CreatedAt.IsZero() {
		limit.CreatedAt = now
	}
	limit.UpdatedAt = now
	r.budgetWindows[limit.ID] = limit.Clone()
	r.budgetWindowsByTuple[tupleKey] = limit.ID
	return nil
}

func (r *MemoryRepository) ListBudgetWindowLimits(_ context.Context, filter BudgetWindowFilter) ([]*domain.BudgetWindowLimit, error) {
	orgID := strings.TrimSpace(filter.OrgID)
	scopeType := domain.QuotaScopeType(strings.ToLower(strings.TrimSpace(string(filter.ScopeType))))
	scopeID := strings.TrimSpace(filter.ScopeID)
	windowType := domain.BudgetWindowType(strings.ToLower(strings.TrimSpace(string(filter.WindowType))))

	r.mu.RLock()
	defer r.mu.RUnlock()

	now := time.Now().UTC()
	cutoff := now.Add(-24 * time.Hour)
	var out []*domain.BudgetWindowLimit
	for _, bw := range r.budgetWindows {
		if orgID != "" && bw.OrgID != orgID {
			continue
		}
		if scopeType != "" && bw.ScopeType != scopeType {
			continue
		}
		if scopeID != "" && bw.ScopeID != scopeID {
			continue
		}
		if windowType != "" && bw.WindowType != windowType {
			continue
		}
		cp := bw.Clone()
		if !filter.SkipRollingSpend && cp.WindowType == domain.BudgetWindowRolling24h {
			recent := r.rollingWindowSpendLocked(cp, cutoff)
			if cp.RollingHoldExpiresAt != nil && now.Before(cp.RollingHoldExpiresAt.UTC()) && cp.RollingHoldMicros > 0 {
				recent += cp.RollingHoldMicros
			}
			cp.SpentMicros = recent
		}
		out = append(out, cp)
	}
	sortBudgetWindowLimits(out)
	return out, nil
}

func (r *MemoryRepository) matchesRollingSpendEventLocked(ev domain.SpendEvent, orgID string, scopeType domain.QuotaScopeType, scopeID string) bool {
	if ev.OrgID != orgID || ev.CostMicros <= 0 {
		return false
	}
	switch scopeType {
	case domain.QuotaScopeOrg:
		return true
	case domain.QuotaScopeTeam:
		return ev.TeamID == scopeID
	case domain.QuotaScopeUser:
		return ev.UserID == scopeID
	case domain.QuotaScopeKey:
		return ev.VirtualKeyID == scopeID
	case domain.QuotaScopeTeamMember:
		return ev.TeamID != "" && ev.UserID != "" && ev.TeamID+":"+ev.UserID == scopeID
	case domain.QuotaScopeProject:
		projID := strings.TrimSpace(ev.ProjectID)
		if projID == "" {
			if vk, ok := r.keysByID[ev.VirtualKeyID]; ok {
				projID = strings.TrimSpace(vk.ProjectID)
			}
		}
		return projID != "" && projID == scopeID
	case domain.QuotaScopeEndUser:
		return ev.EndUserID == scopeID
	case domain.QuotaScopeTag:
		for _, t := range ev.Tags {
			if strings.TrimSpace(t) == scopeID {
				return true
			}
		}
		return false
	case domain.QuotaScopeModelAccessGroup:
		for _, magID := range ev.ModelAccessGroupIDs {
			if strings.TrimSpace(magID) == scopeID {
				return true
			}
		}
		return false
	default:
		return false
	}
}

func (r *MemoryRepository) rollingWindowSpendLocked(bw *domain.BudgetWindowLimit, cutoff time.Time) int64 {
	if bw == nil {
		return 0
	}
	var sum int64
	for _, ev := range r.spendLogs {
		if !ev.CreatedAt.UTC().After(cutoff) {
			continue
		}
		if r.matchesRollingSpendEventLocked(ev, bw.OrgID, bw.ScopeType, bw.ScopeID) {
			sum += ev.CostMicros
		}
	}
	return sum
}

func (r *MemoryRepository) ListRollingWindowHistory(_ context.Context, orgID string, scopeType domain.QuotaScopeType, scopeID string, now time.Time) ([]domain.RollingSpendEntry, error) {
	orgID = strings.TrimSpace(orgID)
	scopeType = domain.QuotaScopeType(strings.ToLower(strings.TrimSpace(string(scopeType))))
	scopeID = strings.TrimSpace(scopeID)
	if orgID == "" || scopeID == "" || !scopeType.IsValid() {
		return nil, nil
	}
	nowUTC := now.UTC()
	if nowUTC.IsZero() {
		nowUTC = time.Now().UTC()
	}
	cutoff := nowUTC.Add(-24 * time.Hour)

	r.mu.RLock()
	defer r.mu.RUnlock()

	var out []domain.RollingSpendEntry
	for _, ev := range r.spendLogs {
		if !ev.CreatedAt.UTC().After(cutoff) {
			continue
		}
		if r.matchesRollingSpendEventLocked(ev, orgID, scopeType, scopeID) {
			out = append(out, domain.RollingSpendEntry{
				ID:           "db:" + ev.ID,
				TimestampMs:  ev.CreatedAt.UTC().UnixMilli(),
				AmountMicros: ev.CostMicros,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].TimestampMs != out[j].TimestampMs {
			return out[i].TimestampMs < out[j].TimestampMs
		}
		return out[i].ID < out[j].ID
	})

	if bwID, ok := r.budgetWindowsByTuple[budgetWindowTupleKey(orgID, scopeType, scopeID, domain.BudgetWindowRolling24h)]; ok {
		if bw := r.budgetWindows[bwID]; bw != nil && bw.RollingHoldMicros > 0 && bw.RollingHoldExpiresAt != nil && bw.RollingHoldExpiresAt.UTC().After(nowUTC) {
			out = append(out, domain.RollingSpendEntry{
				ID:           "hold:" + bw.ID,
				TimestampMs:  bw.RollingHoldExpiresAt.UTC().Add(-24 * time.Hour).UnixMilli(),
				AmountMicros: bw.RollingHoldMicros,
			})
		}
	}
	return out, nil
}

func (r *MemoryRepository) incrementBudgetWindowSpendLocked(orgID string, scopeType domain.QuotaScopeType, scopeID string, deltaMicros int64, now time.Time, includeRollingHold bool) {
	if orgID == "" || scopeID == "" || deltaMicros <= 0 {
		return
	}
	nowUTC := now.UTC()
	for _, bw := range r.budgetWindows {
		if bw.OrgID == orgID && bw.ScopeType == scopeType && bw.ScopeID == scopeID {
			if bw.WindowType == domain.BudgetWindowRolling24h {
				if includeRollingHold {
					if bw.RollingHoldExpiresAt == nil || !nowUTC.Before(bw.RollingHoldExpiresAt.UTC()) {
						bw.RollingHoldMicros = deltaMicros
					} else {
						bw.RollingHoldMicros += deltaMicros
					}
					exp := nowUTC.Add(24 * time.Hour)
					bw.RollingHoldExpiresAt = &exp
					bw.UpdatedAt = nowUTC
				}
				continue
			}
			bw.SpentMicros += deltaMicros
			bw.UpdatedAt = nowUTC
		}
	}
}

func (r *MemoryRepository) IncrementBudgetWindowSpend(_ context.Context, orgID string, scopeType domain.QuotaScopeType, scopeID string, deltaMicros int64) error {
	orgID = strings.TrimSpace(orgID)
	scopeType = domain.QuotaScopeType(strings.ToLower(strings.TrimSpace(string(scopeType))))
	scopeID = strings.TrimSpace(scopeID)
	if orgID == "" || !scopeType.IsValid() || scopeID == "" {
		return fmt.Errorf("org_id, valid scope_type, and scope_id are required")
	}
	if deltaMicros < 0 {
		return fmt.Errorf("delta_micros must be non-negative")
	}
	if deltaMicros == 0 {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.incrementBudgetWindowSpendLocked(orgID, scopeType, scopeID, deltaMicros, time.Now().UTC(), true)
	return nil
}

func (r *MemoryRepository) ResetExpiredBudgetWindows(ctx context.Context, now time.Time) (int, error) {
	reset, err := r.ResetExpiredBudgetWindowsWithResults(ctx, now)
	return len(reset), err
}

func (r *MemoryRepository) ResetExpiredBudgetWindowsWithResults(_ context.Context, now time.Time) ([]*domain.BudgetWindowLimit, error) {
	nowUTC := now.UTC()
	r.mu.Lock()
	defer r.mu.Unlock()

	var reset []*domain.BudgetWindowLimit
	for _, bw := range r.budgetWindows {
		if bw.WindowType == domain.BudgetWindowRolling24h {
			continue
		}
		if !nowUTC.Before(bw.WindowResetAt) {
			bw.SpentMicros = 0
			bw.WindowResetAt = advanceBudgetWindowResetAt(bw.WindowType, bw.WindowResetAt, nowUTC)
			bw.UpdatedAt = nowUTC
			reset = append(reset, bw.Clone())
		}
	}
	sortBudgetWindowLimits(reset)
	return reset, nil
}

func (r *MemoryRepository) SetTempBudgetBoost(_ context.Context, scopeType domain.QuotaScopeType, scopeID string, increaseMicros int64, expiresAt *time.Time) error {
	scopeType = domain.QuotaScopeType(strings.ToLower(strings.TrimSpace(string(scopeType))))
	scopeID = strings.TrimSpace(scopeID)
	if scopeID == "" {
		return fmt.Errorf("scope_id is required")
	}
	if increaseMicros < 0 {
		return fmt.Errorf("temp_budget_increase_micros must be non-negative")
	}
	now := time.Now().UTC()
	exp := cloneTimePtr(expiresAt)
	if exp != nil {
		u := exp.UTC()
		exp = &u
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	switch scopeType {
	case domain.QuotaScopeKey:
		vk, ok := r.keysByID[scopeID]
		if !ok {
			return fmt.Errorf("virtual key %q %w", scopeID, ErrNotFound)
		}
		vk.TempBudgetIncreaseMicros = increaseMicros
		vk.TempBudgetExpiresAt = exp
		vk.UpdatedAt = now
	case domain.QuotaScopeTeam:
		t, ok := r.teams[scopeID]
		if !ok {
			return fmt.Errorf("team %q %w", scopeID, ErrNotFound)
		}
		t.TempBudgetIncreaseMicros = increaseMicros
		t.TempBudgetExpiresAt = exp
		t.UpdatedAt = now
	case domain.QuotaScopeUser:
		u, ok := r.users[scopeID]
		if !ok {
			return fmt.Errorf("user %q %w", scopeID, ErrNotFound)
		}
		u.TempBudgetIncreaseMicros = increaseMicros
		u.TempBudgetExpiresAt = exp
		u.UpdatedAt = now
	case domain.QuotaScopeOrg:
		o, ok := r.orgs[scopeID]
		if !ok {
			return fmt.Errorf("organization %q %w", scopeID, ErrNotFound)
		}
		o.TempBudgetIncreaseMicros = increaseMicros
		o.TempBudgetExpiresAt = exp
		o.UpdatedAt = now
	default:
		return fmt.Errorf("unsupported temp budget scope_type %q", scopeType)
	}
	return nil
}
