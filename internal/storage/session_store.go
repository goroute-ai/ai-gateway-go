package storage

import (
	"context"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

// UserCredential aliases domain.UserCredential for storage callers.
type UserCredential = domain.UserCredential

// OperatorSession aliases domain.OperatorSession for storage callers.
type OperatorSession = domain.OperatorSession

// OperatorSessionRepository is an optional Repository extension for managing
// user password credentials and revocable Control Plane operator sessions.
type OperatorSessionRepository interface {
	UpsertUserPassword(ctx context.Context, userID, passwordHash string, resetRequired bool) error
	GetUserCredential(ctx context.Context, userID string) (*domain.UserCredential, error)
	CreateOperatorSession(ctx context.Context, session *domain.OperatorSession) error
	GetOperatorSession(ctx context.Context, id string) (*domain.OperatorSession, error)
	RevokeOperatorSession(ctx context.Context, id string, revokedAt time.Time) error
	RevokeAllUserSessions(ctx context.Context, userID string, revokedAt time.Time) error
}

var (
	_ OperatorSessionRepository = (*MemoryRepository)(nil)
	_ OperatorSessionRepository = (*PostgresRepository)(nil)
)
