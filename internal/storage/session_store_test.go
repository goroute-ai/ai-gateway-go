package storage

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

func TestMemoryRepository_OperatorSessionAndCredentials(t *testing.T) {
	ctx := context.Background()
	repo := NewMemoryRepository()

	if err := repo.CreateOrganization(ctx, &domain.Organization{
		ID:       "org-sess-test",
		Name:     "Session Org",
		Slug:     "session-org",
		IsActive: true,
	}); err != nil {
		t.Fatalf("CreateOrganization: %v", err)
	}
	if err := repo.CreateUser(ctx, &domain.User{
		ID:       "usr-sess-1",
		OrgID:    "org-sess-test",
		Email:    "sess@example.com",
		Name:     "Session User",
		Role:     domain.RoleOrgAdmin,
		IsActive: true,
	}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	if err := repo.UpsertUserPassword(ctx, "usr-sess-1", "scrypt:32768:8:1:aa:bb", true); err != nil {
		t.Fatalf("UpsertUserPassword: %v", err)
	}
	cred, err := repo.GetUserCredential(ctx, "usr-sess-1")
	if err != nil {
		t.Fatalf("GetUserCredential: %v", err)
	}
	if cred.PasswordHash != "scrypt:32768:8:1:aa:bb" || !cred.PasswordResetRequired {
		t.Fatalf("unexpected credential: %+v", cred)
	}

	exp := time.Now().UTC().Add(time.Hour)
	s1 := &domain.OperatorSession{
		ID:        "jti-1",
		UserID:    "usr-sess-1",
		OrgID:     "org-sess-test",
		Role:      string(domain.OperatorRoleOrgAdmin),
		CSRFToken: "csrf-1",
		ExpiresAt: exp,
	}
	s2 := &domain.OperatorSession{
		ID:        "jti-2",
		UserID:    "usr-sess-1",
		OrgID:     "org-sess-test",
		Role:      string(domain.OperatorRoleOrgAdmin),
		CSRFToken: "csrf-2",
		ExpiresAt: exp,
	}
	if err := repo.CreateOperatorSession(ctx, s1); err != nil {
		t.Fatalf("CreateOperatorSession s1: %v", err)
	}
	if err := repo.CreateOperatorSession(ctx, s2); err != nil {
		t.Fatalf("CreateOperatorSession s2: %v", err)
	}

	got1, err := repo.GetOperatorSession(ctx, "jti-1")
	if err != nil || got1.CSRFToken != "csrf-1" || got1.RevokedAt != nil {
		t.Fatalf("GetOperatorSession jti-1: got=%+v err=%v", got1, err)
	}

	if err := repo.RevokeOperatorSession(ctx, "jti-1", time.Now().UTC()); err != nil {
		t.Fatalf("RevokeOperatorSession jti-1: %v", err)
	}
	got1After, err := repo.GetOperatorSession(ctx, "jti-1")
	if err != nil || got1After.RevokedAt == nil {
		t.Fatalf("expected jti-1 revoked_at to be set, got=%+v err=%v", got1After, err)
	}
	got2Before, err := repo.GetOperatorSession(ctx, "jti-2")
	if err != nil || got2Before.RevokedAt != nil {
		t.Fatalf("expected jti-2 still active, got=%+v err=%v", got2Before, err)
	}

	if err := repo.RevokeAllUserSessions(ctx, "usr-sess-1", time.Now().UTC()); err != nil {
		t.Fatalf("RevokeAllUserSessions: %v", err)
	}
	got2After, err := repo.GetOperatorSession(ctx, "jti-2")
	if err != nil || got2After.RevokedAt == nil {
		t.Fatalf("expected jti-2 revoked_at after RevokeAllUserSessions, got=%+v err=%v", got2After, err)
	}

	if _, err := repo.GetOperatorSession(ctx, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound for missing session, got %v", err)
	}
}
