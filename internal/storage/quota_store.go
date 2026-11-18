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
	_ QuotaPolicyRepository = (*MemoryRepository)(nil)
	_ QuotaPolicyRepository = (*PostgresRepository)(nil)
)

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
