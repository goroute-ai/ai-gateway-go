package storage

import (
	"context"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

// KeyRotationRepository is an optional Repository extension for managing deprecated
// virtual key hashes during dual-active rotation grace windows and querying keys due
// for scheduled automatic rotation.
type KeyRotationRepository interface {
	AddDeprecatedVirtualKeyHash(ctx context.Context, keyHash, virtualKeyID string, revokeAt time.Time) error
	GetActiveDeprecatedVirtualKey(ctx context.Context, keyHash string, now time.Time) (*domain.VirtualKey, time.Time, error)
	DeleteExpiredDeprecatedVirtualKeyHashes(ctx context.Context, now time.Time) (int64, error)
	ListVirtualKeysDueForRotation(ctx context.Context, now time.Time, limit int) ([]*domain.VirtualKey, error)
}

// DeprecatedKeyRevocationRepository is an optional Repository extension that deletes
// all deprecated grace hashes belonging to a virtual key when the key is explicitly revoked,
// returning the deleted key hashes so callers can evict them from L1/L2 caches immediately.
type DeprecatedKeyRevocationRepository interface {
	DeleteDeprecatedVirtualKeyHashesByKeyID(ctx context.Context, virtualKeyID string) ([]string, error)
}

var (
	_ KeyRotationRepository             = (*MemoryRepository)(nil)
	_ KeyRotationRepository             = (*PostgresRepository)(nil)
	_ DeprecatedKeyRevocationRepository = (*MemoryRepository)(nil)
	_ DeprecatedKeyRevocationRepository = (*PostgresRepository)(nil)
)
