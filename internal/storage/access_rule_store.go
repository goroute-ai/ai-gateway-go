package storage

import (
	"context"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

// AccessRuleRepository is an optional Repository extension for managing organization-scoped
// dynamic attribute-based access group rules.
type AccessRuleRepository interface {
	CreateAccessGroupRule(ctx context.Context, rule *domain.AccessGroupRule) error
	GetAccessGroupRule(ctx context.Context, id string) (*domain.AccessGroupRule, error)
	ListAccessGroupRules(ctx context.Context, orgID string, activeOnly bool) ([]*domain.AccessGroupRule, error)
	DeleteAccessGroupRule(ctx context.Context, id string) error
}

var (
	_ AccessRuleRepository = (*MemoryRepository)(nil)
	_ AccessRuleRepository = (*PostgresRepository)(nil)
	_ TeamSpendRepository  = (*MemoryRepository)(nil)
	_ TeamSpendRepository  = (*PostgresRepository)(nil)
)
