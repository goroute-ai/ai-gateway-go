package storage

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/jackc/pgx/v5"
)

func TestScanVirtualKey_AndDeprecatedKeyFields(t *testing.T) {
	now := time.Now().UTC().Truncate(time.Second)
	rotAt := now.Add(24 * time.Hour)
	expAt := now.Add(48 * time.Hour)
	revokeAt := now.Add(15 * time.Minute)

	baseValues := []any{
		"vk-1", "sk-gw-12345678", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"prod-key", "org-1", "team-1", "user-1", "service_account",
		[]string{"gpt-4.1"}, []string{"/v1/*"}, []string{}, []string{}, []string{},
		int64(10_000_000), int64(2_000_000), &expAt, int64(5_000_000), true, []byte(`{"gpt-4.1":["gpt-4.1-mini"]}`),
		int64(1000), "monthly", nil,
		60, 10000, 10, int64(50000), &expAt, true,
		int64(86400), &rotAt, "llm_api", "proj-1", false,
	}

	vk, err := scanVirtualKey(&fakeTeamScanner{values: baseValues})
	if err != nil {
		t.Fatalf("scanVirtualKey: %v", err)
	}
	if vk.ProjectID != "proj-1" {
		t.Fatalf("ProjectID = %q, want %q", vk.ProjectID, "proj-1")
	}
	if vk.KeyType != domain.KeyTypeLLMAPI {
		t.Fatalf("KeyType = %q, want %q", vk.KeyType, domain.KeyTypeLLMAPI)
	}
	if vk.RotationIntervalSec != 86400 {
		t.Fatalf("RotationIntervalSec = %d, want 86400", vk.RotationIntervalSec)
	}
	if vk.KeyRotationAt == nil || !vk.KeyRotationAt.Equal(rotAt) {
		t.Fatalf("KeyRotationAt = %v, want %v", vk.KeyRotationAt, rotAt)
	}

	depValues := append(append([]any(nil), baseValues...), revokeAt)
	depVK, gotRevokeAt, err := scanDeprecatedVirtualKey(&fakeTeamScanner{values: depValues})
	if err != nil {
		t.Fatalf("scanDeprecatedVirtualKey: %v", err)
	}
	if depVK.ID != "vk-1" || depVK.KeyType != domain.KeyTypeLLMAPI {
		t.Fatalf("unexpected deprecated virtual key: %+v", depVK)
	}
	if !gotRevokeAt.Equal(revokeAt) {
		t.Fatalf("revokeAt = %v, want %v", gotRevokeAt, revokeAt)
	}

	if _, _, err := scanDeprecatedVirtualKey(&fakeTeamScanner{err: pgx.ErrNoRows}); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("expected pgx.ErrNoRows, got %v", err)
	}
}

func TestKeyRotationRepository_MemoryAndPostgresFallback(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name string
		new  func() interface {
			Repository
			KeyRotationRepository
			DeprecatedKeyRevocationRepository
		}
	}{
		{
			name: "MemoryRepository",
			new: func() interface {
				Repository
				KeyRotationRepository
				DeprecatedKeyRevocationRepository
			} {
				return NewMemoryRepository()
			},
		},
		{
			name: "PostgresRepository_PoolNilFallback",
			new: func() interface {
				Repository
				KeyRotationRepository
				DeprecatedKeyRevocationRepository
			} {
				return &PostgresRepository{mem: NewMemoryRepository()}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			repo := tc.new()
			now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)

			due1At := now.Add(-2 * time.Minute)
			due2At := now.Add(-1 * time.Minute)
			futureAt := now.Add(10 * time.Minute)
			expiredAt := now.Add(-1 * time.Second)

			keys := []*domain.VirtualKey{
				{
					ID:                  "vk-due-2",
					OrgID:               "org-rot",
					Name:                "due-2",
					KeyPrefix:           "sk-gw-22222222",
					KeyHash:             "2222222222222222222222222222222222222222222222222222222222222222",
					KeyType:             domain.KeyTypeLLMAPI,
					RotationIntervalSec: 3600,
					KeyRotationAt:       &due2At,
					IsActive:            true,
				},
				{
					ID:                  "vk-due-1",
					OrgID:               "org-rot",
					Name:                "due-1",
					KeyPrefix:           "sk-gw-11111111",
					KeyHash:             "1111111111111111111111111111111111111111111111111111111111111111",
					KeyType:             domain.KeyTypeManagement,
					RotationIntervalSec: 600,
					KeyRotationAt:       &due1At,
					IsActive:            true,
				},
				{
					ID:                  "vk-future",
					OrgID:               "org-rot",
					Name:                "future",
					KeyPrefix:           "sk-gw-33333333",
					KeyHash:             "3333333333333333333333333333333333333333333333333333333333333333",
					RotationIntervalSec: 3600,
					KeyRotationAt:       &futureAt,
					IsActive:            true,
				},
				{
					ID:                  "vk-inactive",
					OrgID:               "org-rot",
					Name:                "inactive",
					KeyPrefix:           "sk-gw-44444444",
					KeyHash:             "4444444444444444444444444444444444444444444444444444444444444444",
					RotationIntervalSec: 600,
					KeyRotationAt:       &due1At,
					IsActive:            false,
				},
				{
					ID:                  "vk-expired",
					OrgID:               "org-rot",
					Name:                "expired",
					KeyPrefix:           "sk-gw-55555555",
					KeyHash:             "5555555555555555555555555555555555555555555555555555555555555555",
					RotationIntervalSec: 600,
					KeyRotationAt:       &due1At,
					ExpiresAt:           &expiredAt,
					IsActive:            true,
				},
			}
			for _, k := range keys {
				if err := repo.CreateVirtualKey(ctx, k); err != nil {
					t.Fatalf("CreateVirtualKey(%s): %v", k.ID, err)
				}
			}

			// ListVirtualKeysDueForRotation returns only active, non-expired, due keys ordered by KeyRotationAt ASC
			due, err := repo.ListVirtualKeysDueForRotation(ctx, now, 10)
			if err != nil {
				t.Fatalf("ListVirtualKeysDueForRotation: %v", err)
			}
			if len(due) != 2 || due[0].ID != "vk-due-1" || due[1].ID != "vk-due-2" {
				t.Fatalf("unexpected due keys: %+v", due)
			}
			if due[0].KeyType != domain.KeyTypeManagement || due[1].KeyType != domain.KeyTypeLLMAPI {
				t.Fatalf("expected key_type preserved, got %q and %q", due[0].KeyType, due[1].KeyType)
			}

			// Limit is respected
			limited, err := repo.ListVirtualKeysDueForRotation(ctx, now, 1)
			if err != nil || len(limited) != 1 || limited[0].ID != "vk-due-1" {
				t.Fatalf("ListVirtualKeysDueForRotation(limit=1): got=%+v err=%v", limited, err)
			}

			// Missing virtual key rejects AddDeprecatedVirtualKeyHash
			if err := repo.AddDeprecatedVirtualKeyHash(ctx, "deadhash", "missing-id", now.Add(time.Minute)); !errors.Is(err, ErrNotFound) {
				t.Fatalf("expected ErrNotFound for missing virtual key, got %v", err)
			}

			// Add active and expired deprecated hashes
			activeHash := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			expiredHash := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
			revokeActive := now.Add(5 * time.Minute)
			revokeExpired := now.Add(-1 * time.Second)

			if err := repo.AddDeprecatedVirtualKeyHash(ctx, activeHash, "vk-due-1", revokeActive); err != nil {
				t.Fatalf("AddDeprecatedVirtualKeyHash(active): %v", err)
			}
			if err := repo.AddDeprecatedVirtualKeyHash(ctx, expiredHash, "vk-due-2", revokeExpired); err != nil {
				t.Fatalf("AddDeprecatedVirtualKeyHash(expired): %v", err)
			}

			// Active deprecated hash resolves before revoke_at
			gotVK, gotRevoke, err := repo.GetActiveDeprecatedVirtualKey(ctx, activeHash, now)
			if err != nil {
				t.Fatalf("GetActiveDeprecatedVirtualKey(active): %v", err)
			}
			if gotVK.ID != "vk-due-1" || !gotRevoke.Equal(revokeActive) {
				t.Fatalf("unexpected active deprecated lookup: vk=%+v revoke=%v", gotVK, gotRevoke)
			}

			// Active deprecated hash rejected at exact revoke_at
			if _, _, err := repo.GetActiveDeprecatedVirtualKey(ctx, activeHash, revokeActive); !errors.Is(err, ErrNotFound) {
				t.Fatalf("expected ErrNotFound at exact revoke_at, got %v", err)
			}

			// Expired deprecated hash rejected immediately
			if _, _, err := repo.GetActiveDeprecatedVirtualKey(ctx, expiredHash, now); !errors.Is(err, ErrNotFound) {
				t.Fatalf("expected ErrNotFound for expired hash, got %v", err)
			}

			// DeleteExpiredDeprecatedVirtualKeyHashes purges only expired row
			deleted, err := repo.DeleteExpiredDeprecatedVirtualKeyHashes(ctx, now)
			if err != nil || deleted != 1 {
				t.Fatalf("DeleteExpiredDeprecatedVirtualKeyHashes: deleted=%d err=%v", deleted, err)
			}

			// Active hash still present until deleted by key ID
			if _, _, err := repo.GetActiveDeprecatedVirtualKey(ctx, activeHash, now); err != nil {
				t.Fatalf("expected activeHash to survive expired purge: %v", err)
			}
			revokedHashes, err := repo.DeleteDeprecatedVirtualKeyHashesByKeyID(ctx, "vk-due-1")
			if err != nil || len(revokedHashes) != 1 || revokedHashes[0] != activeHash {
				t.Fatalf("DeleteDeprecatedVirtualKeyHashesByKeyID: got=%v err=%v", revokedHashes, err)
			}
			if _, _, err := repo.GetActiveDeprecatedVirtualKey(ctx, activeHash, now); !errors.Is(err, ErrNotFound) {
				t.Fatalf("expected ErrNotFound after DeleteDeprecatedVirtualKeyHashesByKeyID, got %v", err)
			}
		})
	}
}
