package auth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

func TestSessionManager_IssueVerifyRevokeAndMiddlewareCSRF(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis.Run: %v", err)
	}
	defer mr.Close()

	redisFabric := storage.NewRedisFabric(mr.Addr(), "", 0)
	defer func() { _ = redisFabric.Client().Close() }()

	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	if err := repo.CreateOrganization(ctx, &domain.Organization{
		ID:       "org-1",
		Name:     "Org One",
		Slug:     "org-one",
		IsActive: true,
	}); err != nil {
		t.Fatalf("CreateOrganization: %v", err)
	}
	if err := repo.CreateUser(ctx, &domain.User{
		ID:       "user-1",
		OrgID:    "org-1",
		Email:    "admin@org1.com",
		Name:     "Admin",
		Role:     domain.RoleOrgAdmin,
		IsActive: true,
	}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
	sm := auth.NewSessionManager(repo, redisFabric, []byte("test-session-secret-0123456789abcdef"), time.Hour)
	sm.SetNowFunc(func() time.Time { return now })

	svc := auth.NewService(repo, redisFabric, "sk-gw-master-admin-test", 15*time.Second, 5*time.Minute)
	svc.SetSessionManager(sm)

	issued, err := sm.IssueSessionWithProvider(ctx, "user-1", "org-1", "", "keycloak", domain.OperatorRoleOrgAdmin)
	if err != nil {
		t.Fatalf("IssueSessionWithProvider: %v", err)
	}
	if issued.Token == "" || issued.CSRFToken == "" {
		t.Fatalf("expected non-empty token and csrf_token")
	}

	claims, sess, err := sm.VerifySession(ctx, issued.Token)
	if err != nil {
		t.Fatalf("VerifySession: %v", err)
	}
	if !claims.Audience.Contains(auth.SESSION_AUDIENCE) {
		t.Fatalf("expected audience %q, got %v", auth.SESSION_AUDIENCE, claims.Audience)
	}
	if claims.ProviderID != "keycloak" || sess.ProviderID != "keycloak" {
		t.Fatalf("expected provider_id=keycloak, got claim=%q sess=%q", claims.ProviderID, sess.ProviderID)
	}
	if sess.ID != claims.JTI || sess.UserID != "user-1" {
		t.Fatalf("unexpected session metadata: %+v", sess)
	}

	// Tampered token must fail signature check.
	if _, _, err := sm.VerifySession(ctx, issued.Token+"x"); err == nil {
		t.Fatalf("expected tampered session JWT to fail verification")
	}

	handler := auth.AdminControlPlaneMiddleware(svc)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		op := auth.OperatorFromContext(r.Context())
		if op == nil || op.ActorID != "user-1" || op.AuthMethod != "session" {
			t.Fatalf("unexpected operator context: %+v", op)
		}
		w.WriteHeader(http.StatusOK)
	}))

	// 1. Cookie GET without CSRF succeeds.
	reqGet := httptest.NewRequest(http.MethodGet, "/admin/v1/keys", nil)
	reqGet.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: issued.Token})
	recGet := httptest.NewRecorder()
	handler.ServeHTTP(recGet, reqGet)
	if recGet.Code != http.StatusOK {
		t.Fatalf("cookie GET status = %d, want 200", recGet.Code)
	}

	// 2. Cookie POST without X-CSRF-Token returns 403.
	reqPostNoCSRF := httptest.NewRequest(http.MethodPost, "/admin/v1/keys", nil)
	reqPostNoCSRF.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: issued.Token})
	recPostNoCSRF := httptest.NewRecorder()
	handler.ServeHTTP(recPostNoCSRF, reqPostNoCSRF)
	if recPostNoCSRF.Code != http.StatusForbidden {
		t.Fatalf("cookie POST without CSRF status = %d, want 403", recPostNoCSRF.Code)
	}

	// 3. Cookie POST with valid X-CSRF-Token succeeds.
	reqPostCSRF := httptest.NewRequest(http.MethodPost, "/admin/v1/keys", nil)
	reqPostCSRF.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: issued.Token})
	reqPostCSRF.Header.Set(auth.CSRFHeaderName, issued.CSRFToken)
	recPostCSRF := httptest.NewRecorder()
	handler.ServeHTTP(recPostCSRF, reqPostCSRF)
	if recPostCSRF.Code != http.StatusOK {
		t.Fatalf("cookie POST with CSRF status = %d, want 200", recPostCSRF.Code)
	}

	// 4. Bearer session token POST succeeds without CSRF header.
	reqBearer := httptest.NewRequest(http.MethodPost, "/admin/v1/keys", nil)
	reqBearer.Header.Set("Authorization", "Bearer "+issued.Token)
	recBearer := httptest.NewRecorder()
	handler.ServeHTTP(recBearer, reqBearer)
	if recBearer.Code != http.StatusOK {
		t.Fatalf("bearer session POST status = %d, want 200", recBearer.Code)
	}

	// 5. Revoke session -> replayed cookie and bearer both fail with 401.
	if err := sm.RevokeSession(ctx, issued.Session.ID, issued.ExpiresAt); err != nil {
		t.Fatalf("RevokeSession: %v", err)
	}
	recRevoked := httptest.NewRecorder()
	handler.ServeHTTP(recRevoked, reqGet)
	if recRevoked.Code != http.StatusUnauthorized {
		t.Fatalf("revoked cookie replay status = %d, want 401", recRevoked.Code)
	}
	recRevokedBearer := httptest.NewRecorder()
	handler.ServeHTTP(recRevokedBearer, reqBearer)
	if recRevokedBearer.Code != http.StatusUnauthorized {
		t.Fatalf("revoked bearer replay status = %d, want 401", recRevokedBearer.Code)
	}

	// 6. Expired session fails with 401.
	issued2, err := sm.IssueSession(ctx, "user-1", "org-1", "", domain.OperatorRoleOrgAdmin)
	if err != nil {
		t.Fatalf("IssueSession 2: %v", err)
	}
	now = now.Add(2 * time.Hour)
	if _, _, err := sm.VerifySession(ctx, issued2.Token); err == nil {
		t.Fatalf("expected expired session token to fail")
	}
}
