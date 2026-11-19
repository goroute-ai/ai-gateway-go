package storage

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

// QuotaPolicyFilter filters quota policy queries. Empty fields match all values.
type QuotaPolicyFilter struct {
	OrgID        string
	ScopeType    domain.QuotaScopeType
	ScopeID      string
	ModelPattern string
	ActiveOnly   bool
}

// QuotaPolicyRepository is an optional Repository extension for managing
// polymorphic descriptor quota policies and durable spend accounting.
type QuotaPolicyRepository interface {
	UpsertQuotaPolicy(ctx context.Context, policy *domain.QuotaPolicy) error
	GetQuotaPolicy(ctx context.Context, id string) (*domain.QuotaPolicy, error)
	ListQuotaPolicies(ctx context.Context, filter QuotaPolicyFilter) ([]*domain.QuotaPolicy, error)
	DeleteQuotaPolicy(ctx context.Context, id string) error
	IncrementQuotaPolicySpend(ctx context.Context, id string, deltaMicros int64) error
}

var (
	_ QuotaPolicyRepository       = (*MemoryRepository)(nil)
	_ QuotaPolicyRepository       = (*PostgresRepository)(nil)
	_ BudgetWindowRepository      = (*MemoryRepository)(nil)
	_ BudgetWindowRepository      = (*PostgresRepository)(nil)
	_ BudgetWindowResetRepository = (*MemoryRepository)(nil)
	_ BudgetWindowResetRepository = (*PostgresRepository)(nil)
	_ TempBudgetRepository        = (*MemoryRepository)(nil)
	_ TempBudgetRepository        = (*PostgresRepository)(nil)
	_ EndUserRepository           = (*MemoryRepository)(nil)
	_ EndUserRepository           = (*PostgresRepository)(nil)
	_ TagRepository               = (*MemoryRepository)(nil)
	_ TagRepository               = (*PostgresRepository)(nil)
	_ ModelAccessGroupRepository  = (*MemoryRepository)(nil)
	_ ModelAccessGroupRepository  = (*PostgresRepository)(nil)
)

// EndUserFilter filters end-user queries. Empty fields match all values.
type EndUserFilter struct {
	OrgID      string
	EndUserID  string
	ActiveOnly bool
}

// EndUserRepository manages org-scoped end users, per-end-user budgets/rate limits, and spend.
type EndUserRepository interface {
	UpsertEndUser(ctx context.Context, eu *domain.EndUser) error
	GetOrCreateEndUser(ctx context.Context, orgID, endUserID string) (*domain.EndUser, error)
	GetEndUser(ctx context.Context, id string) (*domain.EndUser, error)
	GetEndUserByExternalID(ctx context.Context, orgID, endUserID string) (*domain.EndUser, error)
	ListEndUsers(ctx context.Context, filter EndUserFilter) ([]*domain.EndUser, error)
	DeleteEndUser(ctx context.Context, id string) error
	IncrementEndUserSpend(ctx context.Context, orgID, endUserID string, deltaMicros int64) error
}

// TagFilter filters tag quota queries. Empty fields match all values.
type TagFilter struct {
	OrgID      string
	Tag        string
	ActiveOnly bool
}

// TagRepository manages org-scoped tag quotas, budgets, and spend attribution.
type TagRepository interface {
	UpsertTag(ctx context.Context, tag *domain.Tag) error
	GetTag(ctx context.Context, id string) (*domain.Tag, error)
	GetTagByName(ctx context.Context, orgID, tag string) (*domain.Tag, error)
	ListTags(ctx context.Context, filter TagFilter) ([]*domain.Tag, error)
	DeleteTag(ctx context.Context, id string) error
	IncrementTagSpend(ctx context.Context, orgID, tag string, deltaMicros int64) error
}

// ModelAccessGroupFilter filters model access group queries. Empty fields match all values.
type ModelAccessGroupFilter struct {
	OrgID      string
	Name       string
	ActiveOnly bool
}

// ModelAccessGroupRepository manages shared model access groups and their model/principal memberships.
type ModelAccessGroupRepository interface {
	UpsertModelAccessGroup(ctx context.Context, group *domain.ModelAccessGroup) error
	GetModelAccessGroup(ctx context.Context, id string) (*domain.ModelAccessGroup, error)
	GetModelAccessGroupByName(ctx context.Context, orgID, name string) (*domain.ModelAccessGroup, error)
	ListModelAccessGroups(ctx context.Context, filter ModelAccessGroupFilter) ([]*domain.ModelAccessGroup, error)
	DeleteModelAccessGroup(ctx context.Context, id string) error
	IncrementModelAccessGroupSpend(ctx context.Context, groupID string, deltaMicros int64) error

	AddModelAccessGroupMember(ctx context.Context, member *domain.ModelAccessGroupMember) error
	ListModelAccessGroupMembers(ctx context.Context, groupID string) ([]*domain.ModelAccessGroupMember, error)
	ListModelAccessGroupMembersByOrg(ctx context.Context, orgID string) ([]*domain.ModelAccessGroupMember, error)
	RemoveModelAccessGroupMember(ctx context.Context, groupID, memberRowID string) error
	RemoveModelAccessGroupMemberByTuple(ctx context.Context, groupID string, memberType domain.ModelAccessGroupMemberType, memberID string) error
}

// BudgetWindowFilter filters multi-window budget queries. Empty fields match all values.
type BudgetWindowFilter struct {
	OrgID      string
	ScopeType  domain.QuotaScopeType
	ScopeID    string
	WindowType domain.BudgetWindowType
	// SkipRollingSpend returns rolling window definitions without aggregating historical spend.
	SkipRollingSpend bool
}

// BudgetWindowRepository is an optional Repository extension for managing
// multi-window budget caps (daily, weekly, monthly, rolling_24h).
type BudgetWindowRepository interface {
	UpsertBudgetWindowLimit(ctx context.Context, limit *domain.BudgetWindowLimit) error
	ListBudgetWindowLimits(ctx context.Context, filter BudgetWindowFilter) ([]*domain.BudgetWindowLimit, error)
	IncrementBudgetWindowSpend(ctx context.Context, orgID string, scopeType domain.QuotaScopeType, scopeID string, deltaMicros int64) error
	ResetExpiredBudgetWindows(ctx context.Context, now time.Time) (int, error)
}

// BudgetWindowResetRepository returns the reset windows so callers can also clear
// the corresponding Redis spend counters.
type BudgetWindowResetRepository interface {
	ResetExpiredBudgetWindowsWithResults(ctx context.Context, now time.Time) ([]*domain.BudgetWindowLimit, error)
}

// RollingSpendHistoryRepository restores timestamped spend entries and active
// migration holds within the trailing 24 hours for cold rolling_24h quota recovery.
type RollingSpendHistoryRepository interface {
	ListRollingWindowHistory(ctx context.Context, orgID string, scopeType domain.QuotaScopeType, scopeID string, now time.Time) ([]domain.RollingSpendEntry, error)
}

// TempBudgetRepository persists temporary budget boosts with expirations across
// virtual_keys, teams, users, and organizations.
type TempBudgetRepository interface {
	SetTempBudgetBoost(ctx context.Context, scopeType domain.QuotaScopeType, scopeID string, increaseMicros int64, expiresAt *time.Time) error
}

func quotaPolicyTupleKey(orgID string, scopeType domain.QuotaScopeType, scopeID, modelPattern string) string {
	return orgID + "\x00" + string(scopeType) + "\x00" + scopeID + "\x00" + modelPattern
}

func normalizeQuotaPolicy(policy *domain.QuotaPolicy, now time.Time) error {
	if policy == nil {
		return fmt.Errorf("quota policy is required")
	}
	policy.OrgID = strings.TrimSpace(policy.OrgID)
	if policy.OrgID == "" {
		return fmt.Errorf("org_id is required for quota policy")
	}
	policy.ScopeType = domain.QuotaScopeType(strings.ToLower(strings.TrimSpace(string(policy.ScopeType))))
	if !policy.ScopeType.IsValid() {
		return fmt.Errorf("invalid quota scope_type %q", policy.ScopeType)
	}
	policy.ScopeID = strings.TrimSpace(policy.ScopeID)
	if policy.ScopeID == "" {
		return fmt.Errorf("scope_id is required for quota policy")
	}
	policy.ModelPattern = strings.TrimSpace(policy.ModelPattern)
	if policy.ModelPattern == "" {
		policy.ModelPattern = "*"
	}
	if policy.RPMLimit < 0 || policy.RPDLimit < 0 || policy.TPMLimit < 0 || policy.ITPMLimit < 0 || policy.OTPMLimit < 0 ||
		policy.TPDLimit < 0 || policy.MaxConcurrent < 0 || policy.MaxBudgetMicros < 0 ||
		policy.SpentMicros < 0 || policy.MaxIterations < 0 || policy.WindowTTLSec < 0 {
		return fmt.Errorf("quota policy limits and counters must be non-negative")
	}
	period := domain.BudgetResetPeriod(strings.ToLower(strings.TrimSpace(string(policy.BudgetResetPeriod))))
	if period == "" {
		period = domain.BudgetResetMonthly
	}
	switch period {
	case domain.BudgetResetDaily, domain.BudgetResetMonthly, domain.BudgetResetNever:
	default:
		return fmt.Errorf("invalid budget_reset_period %q", policy.BudgetResetPeriod)
	}
	policy.BudgetResetPeriod, policy.BudgetResetAt = resolveBudgetResetSchedule(period, policy.BudgetResetAt, now)
	return nil
}

func sortQuotaPolicies(list []*domain.QuotaPolicy) {
	sort.Slice(list, func(i, j int) bool {
		if list[i].OrgID != list[j].OrgID {
			return list[i].OrgID < list[j].OrgID
		}
		if list[i].ScopeType != list[j].ScopeType {
			return list[i].ScopeType < list[j].ScopeType
		}
		if list[i].ScopeID != list[j].ScopeID {
			return list[i].ScopeID < list[j].ScopeID
		}
		if list[i].ModelPattern != list[j].ModelPattern {
			return list[i].ModelPattern < list[j].ModelPattern
		}
		return list[i].ID < list[j].ID
	})
}

func budgetWindowTupleKey(orgID string, scopeType domain.QuotaScopeType, scopeID string, windowType domain.BudgetWindowType) string {
	return orgID + "\x00" + string(scopeType) + "\x00" + scopeID + "\x00" + string(windowType)
}

func defaultBudgetWindowResetAt(windowType domain.BudgetWindowType, now time.Time) time.Time {
	t := now.UTC()
	switch windowType {
	case domain.BudgetWindowDaily, domain.BudgetWindowRolling24h:
		return t.Add(24 * time.Hour)
	case domain.BudgetWindowWeekly:
		return t.AddDate(0, 0, 7)
	case domain.BudgetWindowMonthly:
		return t.AddDate(0, 1, 0)
	default:
		return t.Add(24 * time.Hour)
	}
}

func advanceBudgetWindowResetAt(windowType domain.BudgetWindowType, currentResetAt, now time.Time) time.Time {
	nowUTC := now.UTC()
	if windowType == domain.BudgetWindowRolling24h {
		return nowUTC.Add(24 * time.Hour)
	}
	next := currentResetAt.UTC()
	if next.IsZero() {
		return defaultBudgetWindowResetAt(windowType, nowUTC)
	}
	for !next.After(nowUTC) {
		switch windowType {
		case domain.BudgetWindowDaily:
			next = next.Add(24 * time.Hour)
		case domain.BudgetWindowWeekly:
			next = next.AddDate(0, 0, 7)
		case domain.BudgetWindowMonthly:
			next = next.AddDate(0, 1, 0)
		default:
			next = next.Add(24 * time.Hour)
		}
	}
	return next
}

func normalizeBudgetWindowLimit(limit *domain.BudgetWindowLimit, now time.Time) error {
	if limit == nil {
		return fmt.Errorf("budget window limit is required")
	}
	limit.OrgID = strings.TrimSpace(limit.OrgID)
	if limit.OrgID == "" {
		return fmt.Errorf("org_id is required for budget window limit")
	}
	limit.ScopeType = domain.QuotaScopeType(strings.ToLower(strings.TrimSpace(string(limit.ScopeType))))
	if !limit.ScopeType.IsValid() {
		return fmt.Errorf("invalid budget window scope_type %q", limit.ScopeType)
	}
	limit.ScopeID = strings.TrimSpace(limit.ScopeID)
	if limit.ScopeID == "" {
		return fmt.Errorf("scope_id is required for budget window limit")
	}
	limit.WindowType = domain.BudgetWindowType(strings.ToLower(strings.TrimSpace(string(limit.WindowType))))
	if !limit.WindowType.IsValid() {
		return fmt.Errorf("invalid window_type %q", limit.WindowType)
	}
	if limit.MaxBudgetMicros < 0 || limit.SpentMicros < 0 {
		return fmt.Errorf("budget window limits and counters must be non-negative")
	}
	if limit.WindowResetAt.IsZero() {
		limit.WindowResetAt = defaultBudgetWindowResetAt(limit.WindowType, now)
	} else {
		limit.WindowResetAt = limit.WindowResetAt.UTC()
	}
	return nil
}

func sortBudgetWindowLimits(list []*domain.BudgetWindowLimit) {
	sort.Slice(list, func(i, j int) bool {
		if list[i].OrgID != list[j].OrgID {
			return list[i].OrgID < list[j].OrgID
		}
		if list[i].ScopeType != list[j].ScopeType {
			return list[i].ScopeType < list[j].ScopeType
		}
		if list[i].ScopeID != list[j].ScopeID {
			return list[i].ScopeID < list[j].ScopeID
		}
		if list[i].WindowType != list[j].WindowType {
			return list[i].WindowType < list[j].WindowType
		}
		return list[i].ID < list[j].ID
	})
}

func endUserTupleKey(orgID, endUserID string) string {
	return orgID + "\x00" + endUserID
}

func tagTupleKey(orgID, tag string) string {
	return orgID + "\x00" + tag
}

func modelAccessGroupTupleKey(orgID, name string) string {
	return orgID + "\x00" + name
}

func modelAccessGroupMemberTupleKey(groupID string, memberType domain.ModelAccessGroupMemberType, memberID string) string {
	return groupID + "\x00" + string(memberType) + "\x00" + memberID
}

func normalizeEndUser(eu *domain.EndUser, now time.Time) error {
	if eu == nil {
		return fmt.Errorf("end_user is required")
	}
	eu.OrgID = strings.TrimSpace(eu.OrgID)
	if eu.OrgID == "" {
		return fmt.Errorf("org_id is required for end_user")
	}
	eu.EndUserID = strings.TrimSpace(eu.EndUserID)
	if eu.EndUserID == "" {
		return fmt.Errorf("end_user_id is required")
	}
	eu.Alias = strings.TrimSpace(eu.Alias)
	if eu.RPMLimit < 0 || eu.TPMLimit < 0 || eu.ITPMLimit < 0 || eu.OTPMLimit < 0 ||
		eu.TPDLimit < 0 || eu.MaxConcurrent < 0 || eu.MaxBudgetMicros < 0 || eu.SpentMicros < 0 {
		return fmt.Errorf("end_user limits and counters must be non-negative")
	}
	period := domain.BudgetResetPeriod(strings.ToLower(strings.TrimSpace(string(eu.BudgetResetPeriod))))
	if period == "" {
		period = domain.BudgetResetMonthly
	}
	switch period {
	case domain.BudgetResetDaily, domain.BudgetResetMonthly, domain.BudgetResetNever:
	default:
		return fmt.Errorf("invalid budget_reset_period %q", eu.BudgetResetPeriod)
	}
	eu.BudgetResetPeriod, eu.BudgetResetAt = resolveBudgetResetSchedule(period, eu.BudgetResetAt, now)
	return nil
}

func normalizeTag(tag *domain.Tag, now time.Time) error {
	if tag == nil {
		return fmt.Errorf("tag is required")
	}
	tag.OrgID = strings.TrimSpace(tag.OrgID)
	if tag.OrgID == "" {
		return fmt.Errorf("org_id is required for tag")
	}
	tag.Tag = strings.TrimSpace(tag.Tag)
	if tag.Tag == "" {
		return fmt.Errorf("tag is required")
	}
	tag.Description = strings.TrimSpace(tag.Description)
	if tag.RPMLimit < 0 || tag.TPMLimit < 0 || tag.ITPMLimit < 0 || tag.OTPMLimit < 0 ||
		tag.TPDLimit < 0 || tag.MaxConcurrent < 0 || tag.MaxBudgetMicros < 0 || tag.SpentMicros < 0 {
		return fmt.Errorf("tag limits and counters must be non-negative")
	}
	period := domain.BudgetResetPeriod(strings.ToLower(strings.TrimSpace(string(tag.BudgetResetPeriod))))
	if period == "" {
		period = domain.BudgetResetMonthly
	}
	switch period {
	case domain.BudgetResetDaily, domain.BudgetResetMonthly, domain.BudgetResetNever:
	default:
		return fmt.Errorf("invalid budget_reset_period %q", tag.BudgetResetPeriod)
	}
	tag.BudgetResetPeriod, tag.BudgetResetAt = resolveBudgetResetSchedule(period, tag.BudgetResetAt, now)
	return nil
}

func normalizeModelAccessGroup(g *domain.ModelAccessGroup, now time.Time) error {
	if g == nil {
		return fmt.Errorf("model_access_group is required")
	}
	g.OrgID = strings.TrimSpace(g.OrgID)
	if g.OrgID == "" {
		return fmt.Errorf("org_id is required for model_access_group")
	}
	g.Name = strings.TrimSpace(g.Name)
	if g.Name == "" {
		return fmt.Errorf("name is required for model_access_group")
	}
	g.Description = strings.TrimSpace(g.Description)
	if g.RPMLimit < 0 || g.TPMLimit < 0 || g.ITPMLimit < 0 || g.OTPMLimit < 0 ||
		g.TPDLimit < 0 || g.MaxConcurrent < 0 || g.MaxBudgetMicros < 0 || g.SpentMicros < 0 {
		return fmt.Errorf("model_access_group limits and counters must be non-negative")
	}
	period := domain.BudgetResetPeriod(strings.ToLower(strings.TrimSpace(string(g.BudgetResetPeriod))))
	if period == "" {
		period = domain.BudgetResetMonthly
	}
	switch period {
	case domain.BudgetResetDaily, domain.BudgetResetMonthly, domain.BudgetResetNever:
	default:
		return fmt.Errorf("invalid budget_reset_period %q", g.BudgetResetPeriod)
	}
	g.BudgetResetPeriod, g.BudgetResetAt = resolveBudgetResetSchedule(period, g.BudgetResetAt, now)
	return nil
}

func normalizeModelAccessGroupMember(m *domain.ModelAccessGroupMember) error {
	if m == nil {
		return fmt.Errorf("model_access_group_member is required")
	}
	m.OrgID = strings.TrimSpace(m.OrgID)
	if m.OrgID == "" {
		return fmt.Errorf("org_id is required for model_access_group_member")
	}
	m.GroupID = strings.TrimSpace(m.GroupID)
	if m.GroupID == "" {
		return fmt.Errorf("group_id is required for model_access_group_member")
	}
	m.MemberType = domain.ModelAccessGroupMemberType(strings.ToLower(strings.TrimSpace(string(m.MemberType))))
	if !m.MemberType.IsValid() {
		return fmt.Errorf("invalid member_type %q", m.MemberType)
	}
	m.MemberID = strings.TrimSpace(m.MemberID)
	if m.MemberID == "" {
		return fmt.Errorf("member_id is required for model_access_group_member")
	}
	return nil
}

func sortEndUsers(list []*domain.EndUser) {
	sort.Slice(list, func(i, j int) bool {
		if list[i].OrgID != list[j].OrgID {
			return list[i].OrgID < list[j].OrgID
		}
		if list[i].EndUserID != list[j].EndUserID {
			return list[i].EndUserID < list[j].EndUserID
		}
		return list[i].ID < list[j].ID
	})
}

func sortTags(list []*domain.Tag) {
	sort.Slice(list, func(i, j int) bool {
		if list[i].OrgID != list[j].OrgID {
			return list[i].OrgID < list[j].OrgID
		}
		if list[i].Tag != list[j].Tag {
			return list[i].Tag < list[j].Tag
		}
		return list[i].ID < list[j].ID
	})
}

func sortModelAccessGroups(list []*domain.ModelAccessGroup) {
	sort.Slice(list, func(i, j int) bool {
		if list[i].OrgID != list[j].OrgID {
			return list[i].OrgID < list[j].OrgID
		}
		if list[i].Name != list[j].Name {
			return list[i].Name < list[j].Name
		}
		return list[i].ID < list[j].ID
	})
}

func sortModelAccessGroupMembers(list []*domain.ModelAccessGroupMember) {
	sort.Slice(list, func(i, j int) bool {
		if list[i].GroupID != list[j].GroupID {
			return list[i].GroupID < list[j].GroupID
		}
		if list[i].MemberType != list[j].MemberType {
			return list[i].MemberType < list[j].MemberType
		}
		if list[i].MemberID != list[j].MemberID {
			return list[i].MemberID < list[j].MemberID
		}
		return list[i].ID < list[j].ID
	})
}
