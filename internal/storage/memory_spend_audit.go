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

func (r *MemoryRepository) EnqueueSpendEvent(ctx context.Context, ev domain.SpendEvent) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if ev.ID == "" {
		ev.ID = uuid.NewString()
	}
	if ev.CreatedAt.IsZero() {
		ev.CreatedAt = time.Now().UTC()
	}
	if ev.PricingStatus == "" {
		ev.PricingStatus = domain.PricingStatusUnrecorded
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, delivered := r.spendLogIDs[ev.ID]; !delivered {
		if _, exists := r.spendOutbox[ev.ID]; !exists {
			r.spendOutbox[ev.ID] = &spendOutboxEntry{event: ev, status: "pending", nextAttempt: time.Now().UTC()}
		}
	}
	return nil
}

func (r *MemoryRepository) ClaimSpendEvents(ctx context.Context, limit int, lease time.Duration) ([]domain.SpendEvent, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if limit <= 0 {
		limit = 100
	}
	if lease <= 0 {
		lease = time.Minute
	}
	now := time.Now().UTC()
	r.mu.Lock()
	defer r.mu.Unlock()
	ids := make([]string, 0, len(r.spendOutbox))
	for id, e := range r.spendOutbox {
		if e.status == "pending" && !e.nextAttempt.After(now) || e.status == "processing" && e.lockedAt.Add(lease).Before(now) {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	if len(ids) > limit {
		ids = ids[:limit]
	}
	out := make([]domain.SpendEvent, 0, len(ids))
	for _, id := range ids {
		e := r.spendOutbox[id]
		e.status = "processing"
		e.lockedAt = now
		e.attempts++
		ev := e.event
		ev.OutboxAttempt = e.attempts
		out = append(out, ev)
	}
	return out, nil
}

func (r *MemoryRepository) MarkSpendEventDelivered(ctx context.Context, id string) error {
	return r.MarkSpendEventsDelivered(ctx, []string{id})
}

func (r *MemoryRepository) MarkSpendEventsDelivered(ctx context.Context, ids []string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, id := range ids {
		delete(r.spendOutbox, id)
	}
	return nil
}

func (r *MemoryRepository) CountPendingSpendEvents(ctx context.Context) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	var count int64
	for _, e := range r.spendOutbox {
		if e.status == "pending" || e.status == "processing" {
			count++
		}
	}
	return count, nil
}

func (r *MemoryRepository) PruneDeliveredSpendEvents(ctx context.Context, _ time.Time, _ int) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	// MemoryRepository deletes delivered events immediately upon acknowledgement.
	return 0, nil
}

func (r *MemoryRepository) RetrySpendEvent(ctx context.Context, id string, cause error, retryAt time.Time, maxAttempts int) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if e := r.spendOutbox[id]; e != nil {
		if maxAttempts > 0 && e.attempts >= maxAttempts {
			e.status = "dead_letter"
		} else {
			e.status = "pending"
			e.nextAttempt = retryAt
		}
		e.lockedAt = time.Time{}
		if cause != nil {
			e.lastError = cause.Error()
		}
	}
	return nil
}

func (r *MemoryRepository) RecordSpendBatch(ctx context.Context, events []domain.SpendEvent) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, ev := range events {
		if ev.ID == "" {
			ev.ID = uuid.NewString()
		}
		if ev.CreatedAt.IsZero() {
			ev.CreatedAt = time.Now().UTC()
		}
		if ev.PricingStatus == "" {
			ev.PricingStatus = domain.PricingStatusUnrecorded
		}
		if _, exists := r.spendLogIDs[ev.ID]; exists {
			continue
		}
		projectID := strings.TrimSpace(ev.ProjectID)
		if vk, ok := r.keysByID[ev.VirtualKeyID]; ok {
			vk.SpentMicros += ev.CostMicros
			if projectID == "" {
				projectID = strings.TrimSpace(vk.ProjectID)
			}
		}
		ev.ProjectID = projectID
		r.spendLogIDs[ev.ID] = struct{}{}
		r.spendLogs = append(r.spendLogs, ev)

		if ev.TeamID != "" {
			if t, ok := r.teams[ev.TeamID]; ok {
				t.SpentMicros += ev.CostMicros
			}
		}
		if ev.UserID != "" {
			if u, ok := r.users[ev.UserID]; ok {
				u.SpentMicros += ev.CostMicros
			}
		}
		if ev.OrgID != "" {
			if o, ok := r.orgs[ev.OrgID]; ok {
				o.SpentMicros += ev.CostMicros
			}
		}
		if projectID != "" {
			if p, ok := r.projects[projectID]; ok {
				p.SpentMicros += ev.CostMicros
				p.UpdatedAt = ev.CreatedAt
			}
		}
		if ev.TeamID != "" && ev.UserID != "" {
			if mID, ok := r.teamMembershipsByTuple[teamMembershipTupleKey(ev.TeamID, ev.UserID)]; ok {
				if m, exists := r.teamMemberships[mID]; exists {
					m.SpentMicros += ev.CostMicros
					m.UpdatedAt = ev.CreatedAt
				}
			}
		}
		seenPolicies := make(map[string]struct{}, len(ev.MatchedQuotaPolicyIDs))
		for _, qpID := range ev.MatchedQuotaPolicyIDs {
			qpID = strings.TrimSpace(qpID)
			if qpID == "" {
				continue
			}
			if _, dup := seenPolicies[qpID]; dup {
				continue
			}
			seenPolicies[qpID] = struct{}{}
			if qp, ok := r.quotaPolicies[qpID]; ok {
				qp.SpentMicros += ev.CostMicros
				qp.UpdatedAt = ev.CreatedAt
			}
		}
		if ev.CostMicros > 0 && ev.OrgID != "" {
			r.incrementBudgetWindowSpendLocked(ev.OrgID, domain.QuotaScopeOrg, ev.OrgID, ev.CostMicros, ev.CreatedAt, false)
			if ev.TeamID != "" {
				r.incrementBudgetWindowSpendLocked(ev.OrgID, domain.QuotaScopeTeam, ev.TeamID, ev.CostMicros, ev.CreatedAt, false)
			}
			if ev.UserID != "" {
				r.incrementBudgetWindowSpendLocked(ev.OrgID, domain.QuotaScopeUser, ev.UserID, ev.CostMicros, ev.CreatedAt, false)
			}
			if ev.VirtualKeyID != "" {
				r.incrementBudgetWindowSpendLocked(ev.OrgID, domain.QuotaScopeKey, ev.VirtualKeyID, ev.CostMicros, ev.CreatedAt, false)
			}
			if projectID != "" {
				r.incrementBudgetWindowSpendLocked(ev.OrgID, domain.QuotaScopeProject, projectID, ev.CostMicros, ev.CreatedAt, false)
			}
			if ev.TeamID != "" && ev.UserID != "" {
				r.incrementBudgetWindowSpendLocked(ev.OrgID, domain.QuotaScopeTeamMember, ev.TeamID+":"+ev.UserID, ev.CostMicros, ev.CreatedAt, false)
			}
			if ev.EndUserID != "" {
				if euID, ok := r.endUsersByTuple[endUserTupleKey(ev.OrgID, ev.EndUserID)]; ok {
					if eu, exists := r.endUsers[euID]; exists {
						eu.SpentMicros += ev.CostMicros
						eu.UpdatedAt = ev.CreatedAt
					}
				}
				r.incrementBudgetWindowSpendLocked(ev.OrgID, domain.QuotaScopeEndUser, ev.EndUserID, ev.CostMicros, ev.CreatedAt, false)
			}
			for _, tagName := range ev.Tags {
				tagName = strings.TrimSpace(tagName)
				if tagName == "" {
					continue
				}
				if tID, ok := r.tagsByTuple[tagTupleKey(ev.OrgID, tagName)]; ok {
					if t, exists := r.tags[tID]; exists {
						t.SpentMicros += ev.CostMicros
						t.UpdatedAt = ev.CreatedAt
					}
				}
				r.incrementBudgetWindowSpendLocked(ev.OrgID, domain.QuotaScopeTag, tagName, ev.CostMicros, ev.CreatedAt, false)
			}
			seenMAGs := make(map[string]struct{}, len(ev.ModelAccessGroupIDs))
			for _, magID := range ev.ModelAccessGroupIDs {
				magID = strings.TrimSpace(magID)
				if magID == "" {
					continue
				}
				if _, dup := seenMAGs[magID]; dup {
					continue
				}
				seenMAGs[magID] = struct{}{}
				if g, exists := r.modelAccessGroups[magID]; exists && g.OrgID == ev.OrgID {
					g.SpentMicros += ev.CostMicros
					g.UpdatedAt = ev.CreatedAt
				}
				r.incrementBudgetWindowSpendLocked(ev.OrgID, domain.QuotaScopeModelAccessGroup, magID, ev.CostMicros, ev.CreatedAt, false)
			}
		}
	}
	return nil
}

func (r *MemoryRepository) GetSpendSummary(ctx context.Context, orgID string) (*SpendSummary, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	sum := &SpendSummary{
		SpendByProvider:   make(map[string]int64),
		SpendByModel:      make(map[string]int64),
		SpendByTeam:       make(map[string]int64),
		SpendByUser:       make(map[string]int64),
		SpendByVirtualKey: make(map[string]int64),
	}
	for _, ev := range r.spendLogs {
		if orgID != "" && ev.OrgID != orgID {
			continue
		}
		sum.TotalRequests++
		sum.TotalTokens += int64(ev.Usage.TotalTokens)
		sum.TotalCostMicros += ev.CostMicros
		if ev.PricingStatus == domain.PricingStatusUnknown || ev.PricingStatus == domain.PricingStatusUnrecorded {
			sum.UnpricedRequests++
			sum.UnpricedTokens += int64(ev.Usage.TotalTokens)
		}
		sum.SpendByProvider[string(ev.Provider)] += ev.CostMicros
		sum.SpendByModel[ev.ResolvedModel] += ev.CostMicros
		if ev.TeamID != "" {
			sum.SpendByTeam[ev.TeamID] += ev.CostMicros
		}
		if ev.UserID != "" {
			sum.SpendByUser[ev.UserID] += ev.CostMicros
		}
		if ev.VirtualKeyID != "" {
			sum.SpendByVirtualKey[ev.VirtualKeyID] += ev.CostMicros
		}
	}
	sum.TotalCostUSD = float64(sum.TotalCostMicros) / 1_000_000.0
	return sum, nil
}

func (r *MemoryRepository) ListSpendLogs(ctx context.Context, orgID string, limit int) ([]domain.SpendEvent, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if limit <= 0 {
		limit = 100
	}
	var out []domain.SpendEvent
	for i := len(r.spendLogs) - 1; i >= 0 && len(out) < limit; i-- {
		ev := r.spendLogs[i]
		if orgID == "" || ev.OrgID == orgID {
			out = append(out, ev)
		}
	}
	return out, nil
}

func (r *MemoryRepository) GetTeamSpendSummary(ctx context.Context, orgID, teamID string) (*SpendSummary, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	sum := &SpendSummary{
		SpendByProvider:   make(map[string]int64),
		SpendByModel:      make(map[string]int64),
		SpendByTeam:       make(map[string]int64),
		SpendByUser:       make(map[string]int64),
		SpendByVirtualKey: make(map[string]int64),
	}
	for _, ev := range r.spendLogs {
		if orgID != "" && ev.OrgID != orgID {
			continue
		}
		if ev.TeamID != teamID {
			continue
		}
		sum.TotalRequests++
		sum.TotalTokens += int64(ev.Usage.TotalTokens)
		sum.TotalCostMicros += ev.CostMicros
		if ev.PricingStatus == domain.PricingStatusUnknown || ev.PricingStatus == domain.PricingStatusUnrecorded {
			sum.UnpricedRequests++
			sum.UnpricedTokens += int64(ev.Usage.TotalTokens)
		}
		sum.SpendByProvider[string(ev.Provider)] += ev.CostMicros
		sum.SpendByModel[ev.ResolvedModel] += ev.CostMicros
		if ev.TeamID != "" {
			sum.SpendByTeam[ev.TeamID] += ev.CostMicros
		}
		if ev.UserID != "" {
			sum.SpendByUser[ev.UserID] += ev.CostMicros
		}
		if ev.VirtualKeyID != "" {
			sum.SpendByVirtualKey[ev.VirtualKeyID] += ev.CostMicros
		}
	}
	sum.TotalCostUSD = float64(sum.TotalCostMicros) / 1_000_000.0
	return sum, nil
}

func (r *MemoryRepository) ListTeamSpendLogs(ctx context.Context, orgID, teamID string, limit int) ([]domain.SpendEvent, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if limit <= 0 {
		limit = 100
	}
	out := make([]domain.SpendEvent, 0)
	for i := len(r.spendLogs) - 1; i >= 0 && len(out) < limit; i-- {
		ev := r.spendLogs[i]
		if (orgID == "" || ev.OrgID == orgID) && ev.TeamID == teamID {
			out = append(out, ev)
		}
	}
	return out, nil
}

func (r *MemoryRepository) ResetExpiredBudgets(ctx context.Context, now time.Time) (int, error) {
	res, err := r.ResetExpiredBudgetsWithIDs(ctx, now)
	return res.Total(), err
}

func (r *MemoryRepository) ResetExpiredBudgetsWithIDs(ctx context.Context, now time.Time) (BudgetResetResult, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	var res BudgetResetResult

	for _, o := range r.orgs {
		if o.BudgetResetAt != nil && !now.Before(*o.BudgetResetAt) &&
			(o.BudgetResetPeriod == domain.BudgetResetDaily || o.BudgetResetPeriod == domain.BudgetResetMonthly) {
			o.SpentMicros = 0
			o.BudgetResetAt = advanceBudgetResetAt(o.BudgetResetPeriod, o.BudgetResetAt)
			res.OrgIDs = append(res.OrgIDs, o.ID)
			event := BudgetResetEvent{ID: uuid.NewString(), Scope: "org", EntityID: o.ID, OrgID: o.ID, ResetAt: now.UTC()}
			res.Events = append(res.Events, event)
			r.budgetResetOutbox[event.ID] = event
		}
	}
	for _, t := range r.teams {
		if t.BudgetResetAt != nil && !now.Before(*t.BudgetResetAt) &&
			(t.BudgetResetPeriod == domain.BudgetResetDaily || t.BudgetResetPeriod == domain.BudgetResetMonthly) {
			t.SpentMicros = 0
			t.BudgetResetAt = advanceBudgetResetAt(t.BudgetResetPeriod, t.BudgetResetAt)
			res.TeamIDs = append(res.TeamIDs, t.ID)
			event := BudgetResetEvent{ID: uuid.NewString(), Scope: "team", EntityID: t.ID, OrgID: t.OrgID, ResetAt: now.UTC()}
			res.Events = append(res.Events, event)
			r.budgetResetOutbox[event.ID] = event
		}
	}
	for _, u := range r.users {
		if u.BudgetResetAt != nil && !now.Before(*u.BudgetResetAt) &&
			(u.BudgetResetPeriod == domain.BudgetResetDaily || u.BudgetResetPeriod == domain.BudgetResetMonthly) {
			u.SpentMicros = 0
			u.BudgetResetAt = advanceBudgetResetAt(u.BudgetResetPeriod, u.BudgetResetAt)
			res.UserIDs = append(res.UserIDs, u.ID)
			event := BudgetResetEvent{ID: uuid.NewString(), Scope: "user", EntityID: u.ID, OrgID: u.OrgID, ResetAt: now.UTC()}
			res.Events = append(res.Events, event)
			r.budgetResetOutbox[event.ID] = event
		}
	}
	for _, vk := range r.keysByID {
		if vk.BudgetResetAt != nil && !now.Before(*vk.BudgetResetAt) &&
			(vk.BudgetResetPeriod == domain.BudgetResetDaily || vk.BudgetResetPeriod == domain.BudgetResetMonthly) {
			vk.SpentMicros = 0
			vk.BudgetResetAt = advanceBudgetResetAt(vk.BudgetResetPeriod, vk.BudgetResetAt)
			res.VirtualKeyIDs = append(res.VirtualKeyIDs, vk.ID)
			event := BudgetResetEvent{ID: uuid.NewString(), Scope: "key", EntityID: vk.ID, OrgID: vk.OrgID, ResetAt: now.UTC()}
			res.Events = append(res.Events, event)
			r.budgetResetOutbox[event.ID] = event
		}
	}
	return res, nil
}

func (r *MemoryRepository) ListPendingBudgetResets(ctx context.Context, limit int) ([]BudgetResetEvent, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if limit <= 0 {
		limit = 250
	}
	out := make([]BudgetResetEvent, 0, min(limit, len(r.budgetResetOutbox)))
	for _, ev := range r.budgetResetOutbox {
		out = append(out, ev)
		if len(out) >= limit {
			break
		}
	}
	return out, nil
}

func (r *MemoryRepository) MarkBudgetResetsDelivered(ctx context.Context, ids []string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, id := range ids {
		delete(r.budgetResetOutbox, id)
	}
	return nil
}

// SetAuditLogObserver registers a synchronous callback invoked after each RecordAuditLog write.
func (r *MemoryRepository) SetAuditLogObserver(fn func(*domain.AuditLog)) {
	r.mu.Lock()
	r.auditObserver = fn
	r.mu.Unlock()
}

func (r *MemoryRepository) RecordAuditLog(ctx context.Context, log *domain.AuditLog) error {
	r.mu.Lock()
	if log.ID == "" {
		log.ID = uuid.NewString()
	}
	if log.CreatedAt.IsZero() {
		log.CreatedAt = time.Now().UTC()
	}
	cp := *log
	cp.Details = cloneAnyMap(log.Details)
	cp.BeforeValue = cloneAnyMap(log.BeforeValue)
	cp.AfterValue = cloneAnyMap(log.AfterValue)
	r.auditLogs = append(r.auditLogs, &cp)
	obs := r.auditObserver
	r.mu.Unlock()
	if obs != nil {
		obs(&cp)
	}
	return nil
}

func (r *MemoryRepository) ListAuditLogs(ctx context.Context, orgID string, limit int) ([]*domain.AuditLog, error) {
	logs, _, err := r.ListAuditLogsFiltered(ctx, domain.AuditLogFilter{
		OrgID: orgID,
		Limit: limit,
	})
	return logs, err
}

func (r *MemoryRepository) ListAuditLogsFiltered(_ context.Context, filter domain.AuditLogFilter) ([]*domain.AuditLog, string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	limit := filter.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 200 {
		limit = 200
	}

	var cursorTime time.Time
	var cursorID string
	hasCursor := false
	if strings.TrimSpace(filter.Cursor) != "" {
		ct, cid, err := decodeAuditLogCursor(filter.Cursor)
		if err != nil {
			return nil, "", fmt.Errorf("invalid audit log cursor: %w", err)
		}
		cursorTime = ct
		cursorID = cid
		hasCursor = true
	}

	orgID := strings.TrimSpace(filter.OrgID)
	actorID := strings.TrimSpace(filter.ActorID)
	action := strings.TrimSpace(filter.Action)
	resource := strings.TrimSpace(filter.Resource)
	resourceID := strings.TrimSpace(filter.ResourceID)

	matched := make([]*domain.AuditLog, 0, len(r.auditLogs))
	for _, l := range r.auditLogs {
		if orgID != "" && l.OrgID != orgID {
			continue
		}
		if actorID != "" && l.ActorID != actorID {
			continue
		}
		if action != "" && l.Action != action {
			continue
		}
		if resource != "" && l.Resource != resource {
			continue
		}
		if resourceID != "" && l.ResourceID != resourceID {
			continue
		}
		if filter.Since != nil && l.CreatedAt.Before(*filter.Since) {
			continue
		}
		if filter.Until != nil && l.CreatedAt.After(*filter.Until) {
			continue
		}
		if hasCursor {
			if l.CreatedAt.After(cursorTime) || (l.CreatedAt.Equal(cursorTime) && l.ID >= cursorID) {
				continue
			}
		}
		cp := *l
		cp.Details = cloneAnyMap(l.Details)
		cp.BeforeValue = cloneAnyMap(l.BeforeValue)
		cp.AfterValue = cloneAnyMap(l.AfterValue)
		matched = append(matched, &cp)
	}

	sort.Slice(matched, func(i, j int) bool {
		if !matched[i].CreatedAt.Equal(matched[j].CreatedAt) {
			return matched[i].CreatedAt.After(matched[j].CreatedAt)
		}
		return matched[i].ID > matched[j].ID
	})

	var nextCursor string
	if len(matched) > limit {
		matched = matched[:limit]
		last := matched[len(matched)-1]
		nextCursor = encodeAuditLogCursor(last.CreatedAt, last.ID)
	}
	return matched, nextCursor, nil
}
