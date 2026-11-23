package storage

import (
	"context"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

// OperatorSession aliases domain.OperatorSession for storage callers.
type OperatorSession = domain.OperatorSession

// OperatorSessionRepository is an optional Repository extension for managing
// revocable Control Plane operator sessions.
type OperatorSessionRepository interface {
	CreateOperatorSession(ctx context.Context, session *domain.OperatorSession) error
	GetOperatorSession(ctx context.Context, id string) (*domain.OperatorSession, error)
	RevokeOperatorSession(ctx context.Context, id string, revokedAt time.Time) error
	RevokeAllUserSessions(ctx context.Context, userID string, revokedAt time.Time) error
}

// OperatorSessionRevocationListRepository is an optional extension that returns all
// newly revoked session IDs so distributed caches (Redis/PubSub) can evict them across replicas.
type OperatorSessionRevocationListRepository interface {
	RevokeAllUserSessionsReturningIDs(ctx context.Context, userID string, revokedAt time.Time) ([]string, error)
}

var (
	_ OperatorSessionRepository               = (*MemoryRepository)(nil)
	_ OperatorSessionRepository               = (*PostgresRepository)(nil)
	_ OperatorSessionRevocationListRepository = (*MemoryRepository)(nil)
	_ OperatorSessionRevocationListRepository = (*PostgresRepository)(nil)
)
