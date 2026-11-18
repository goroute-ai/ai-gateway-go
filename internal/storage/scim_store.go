package storage

import (
	"context"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

// SCIMRepository is an optional Repository extension supporting SCIM v2
// user/group lookup and per-user virtual key enumeration for immediate revocation.
type SCIMRepository interface {
	GetUserBySCIMExternalID(ctx context.Context, orgID, externalID string) (*domain.User, error)
	GetTeamByName(ctx context.Context, orgID, name string) (*domain.Team, error)
	ListVirtualKeysByUserID(ctx context.Context, orgID, userID string) ([]*domain.VirtualKey, error)
}

var (
	_ SCIMRepository = (*MemoryRepository)(nil)
	_ SCIMRepository = (*PostgresRepository)(nil)
)
