package storage

import (
	"context"
	"errors"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

// ErrConflict is returned when creating or provisioning a record violates a uniqueness constraint.
var ErrConflict = errors.New("conflict")

// JWTMappingRepository is an optional Repository extension for managing JWT claim-to-virtual-key mappings.
type JWTMappingRepository interface {
	CreateJWTKeyMapping(ctx context.Context, mapping *domain.JWTKeyMapping) error
	ListJWTKeyMappings(ctx context.Context, orgID string) ([]*domain.JWTKeyMapping, error)
	DeleteJWTKeyMapping(ctx context.Context, id string) error
	ResolveJWTKeyMapping(ctx context.Context, issuer, claimName, claimValue string) (*domain.JWTKeyMapping, error)
}

// JWTMappingLookupRepository is an optional Repository extension for direct JWT mapping lookup by ID.
type JWTMappingLookupRepository interface {
	GetJWTKeyMapping(ctx context.Context, id string) (*domain.JWTKeyMapping, error)
}

// OIDCUserRepository is an optional Repository extension for tenant-scoped OIDC user lookup and race-safe JIT provisioning.
type OIDCUserRepository interface {
	GetUserByOIDCIdentity(ctx context.Context, orgID, issuer, subject string) (*domain.User, error)
	GetUserByOrgAndOIDCSubject(ctx context.Context, orgID, subject string) (*domain.User, error)
	GetUserByEmail(ctx context.Context, email string) (*domain.User, error)
	GetOrCreateUserByOIDCSubject(ctx context.Context, user *domain.User) (*domain.User, bool, error)
}
