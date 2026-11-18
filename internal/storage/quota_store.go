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
)

// BudgetWindowFilter filters multi-window budget queries. Empty fields match all values.
type BudgetWindowFilter struct {
	OrgID      string
	ScopeType  domain.QuotaScopeType
	ScopeID    string
	WindowType domain.BudgetWindowType
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
	if policy.RPMLimit < 0 || policy.TPMLimit < 0 || policy.ITPMLimit < 0 || policy.OTPMLimit < 0 ||
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
