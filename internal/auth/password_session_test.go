package auth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

func TestPasswordScrypt_HashAndVerify(t *testing.T) {
	hash1, err := auth.HashPasswordScrypt("correct-horse-battery-staple")
	if err != nil {
		t.Fatalf("HashPasswordScrypt: %v", err)
	}
	hash2, err := auth.HashPasswordScrypt("correct-horse-battery-staple")
	if err != nil {
		t.Fatalf("HashPasswordScrypt 2: %v", err)
	}
	if hash1 == hash2 {
		t.Fatalf("expected unique salts per hash call")
	}
	if !strings.HasPrefix(hash1, "scrypt:32768:8:1:") {
		t.Fatalf("expected scrypt:32768:8:1: prefix, got %q", hash1)
	}
	if parts := strings.Split(hash1, ":"); len(parts) != 6 {
		t.Fatalf("expected 6 colon-separated scrypt parts, got %d (%q)", len(parts), hash1)
	}

	ok, upgrade := auth.VerifyPassword("correct-horse-battery-staple", hash1)
	if !ok || upgrade {
		t.Fatalf("VerifyPassword valid = (%v, %v), want (true, false)", ok, upgrade)
	}

	ok, upgrade = auth.VerifyPassword("wrong-password", hash1)
	if ok || upgrade {
		t.Fatalf("VerifyPassword wrong = (%v, %v), want (false, false)", ok, upgrade)
	}

	ok, upgrade = auth.VerifyPassword("", hash1)
	if ok || upgrade {
		t.Fatalf("VerifyPassword empty = (%v, %v), want (false, false)", ok, upgrade)
	}
}

func TestPasswordVerify_LegacyUpgradeSignals(t *testing.T) {
	lowerCostHash, err := auth.HashPasswordScryptWithCost("legacy-secret-123", 1024, 8, 1)
	if err != nil {
		t.Fatalf("HashPasswordScryptWithCost: %v", err)
	}
	if !strings.HasPrefix(lowerCostHash, "scrypt:1024:8:1:") {
		t.Fatalf("expected scrypt:1024:8:1: prefix, got %q", lowerCostHash)
	}

	ok, upgrade := auth.VerifyPassword("legacy-secret-123", lowerCostHash)
	if !ok || !upgrade {
		t.Fatalf("VerifyPassword lower-cost scrypt = (%v, %v), want (true, true)", ok, upgrade)
	}

	ok, upgrade = auth.VerifyPassword("wrong", lowerCostHash)
	if ok || upgrade {
		t.Fatalf("VerifyPassword lower-cost wrong = (%v, %v), want (false, false)", ok, upgrade)
	}
}

func TestLoginThrottle_LockoutAfter5Failures_MemoryAndRedis(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis.Run: %v", err)
	}
	defer mr.Close()

	redisFabric := storage.NewRedisFabric(mr.Addr(), "", 0)
	defer func() { _ = redisFabric.Client().Close() }()

	for _, tc := range []struct {
		name  string
		redis *storage.RedisFabric
	}{
		{name: "memory_fallback", redis: nil},
		{name: "redis_backed", redis: redisFabric},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
			throttle := auth.NewLoginThrottle(tc.redis)
			throttle.SetNowFunc(func() time.Time { return now })

			email := "alice@example.com"
			ip := "192.0.2.10"

			for i := 1; i <= 4; i++ {
				if err := throttle.Check(ctx, email, ip); err != nil {
					t.Fatalf("attempt %d unexpectedly blocked: %v", i, err)
				}
				att, locked, _ := throttle.RecordFailure(ctx, email, ip)
				if att != i || locked {
					t.Fatalf("attempt %d: got (att=%d, locked=%v), want (%d, false)", i, att, locked, i)
				}
			}

			// 5th consecutive failure locks for 300s.
			att, locked, retryAfter := throttle.RecordFailure(ctx, email, ip)
			if att != 5 || !locked || retryAfter != 300*time.Second {
				t.Fatalf("5th failure: got (att=%d, locked=%v, retry=%v), want (5, true, 300s)", att, locked, retryAfter)
			}

			if err := throttle.Check(ctx, email, ip); err == nil {
				t.Fatalf("expected Check to reject locked (email, ip)")
			}

			// Different IP or different email must not be locked.
			if err := throttle.Check(ctx, email, "192.0.2.11"); err != nil {
				t.Fatalf("different IP should not be locked: %v", err)
			}
			if err := throttle.Check(ctx, "bob@example.com", ip); err != nil {
				t.Fatalf("different email should not be locked: %v", err)
			}

			// Advance past 300s lockout (and fast-forward miniredis TTL).
			now = now.Add(301 * time.Second)
			if tc.redis != nil {
				mr.FastForward(301 * time.Second)
			}
			if err := throttle.Check(ctx, email, ip); err != nil {
				t.Fatalf("expected lockout to expire after 301s: %v", err)
			}

			// RecordSuccess clears failure counter.
			throttle.RecordFailure(ctx, email, ip)
			throttle.RecordSuccess(ctx, email, ip)
			for i := 1; i <= 4; i++ {
				_, locked, _ := throttle.RecordFailure(ctx, email, ip)
				if locked {
					t.Fatalf("expected failure counter reset after RecordSuccess (failed on attempt %d)", i)
				}
			}
		})
	}
}

func TestScreenPasswordBreach_KAnonymity(t *testing.T) {
	// Standard 40-char uppercase hex digest test vector (prefix 5BAA6 + 35-char suffix).
	breachedDigest := "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"
	prefix := breachedDigest[:5]
	suffix := breachedDigest[5:]

	var seenPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenPath = r.URL.Path
		if r.URL.Path != "/range/"+prefix {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte("00000000000000000000000000000000000:0\n" + suffix + ":42\n"))
	}))
	defer srv.Close()

	// Strict SSRF policy (private networks blocked) must reject loopback test server.
	strictPolicy, err := network.NewPolicy(config.OutboundSSRFConfig{})
	if err != nil {
		t.Fatalf("NewPolicy strict: %v", err)
	}
	strictClient := auth.NewHIBPRangeClient(srv.URL+"/range", strictPolicy)
	if _, err := strictClient.CheckDigest(context.Background(), breachedDigest); err == nil {
		t.Fatalf("expected strict network.Policy to block loopback HIBP test server")
	}

	// Dev/test policy allows httptest.Server and verifies only 5-char hex prefix is transmitted.
	allowPolicy, err := network.NewPolicy(config.OutboundSSRFConfig{
		AllowPrivateNetworks: true,
		AllowInsecureHTTP:    true,
	})
	if err != nil {
		t.Fatalf("NewPolicy allow: %v", err)
	}

	client := auth.NewHIBPRangeClient(srv.URL+"/range", allowPolicy)
	breached, err := client.CheckDigest(context.Background(), breachedDigest)
	if err != nil {
		t.Fatalf("CheckDigest breached: %v", err)
	}
	if !breached {
		t.Fatalf("expected breached=true for matched suffix")
	}
	if seenPath != "/range/"+prefix {
		t.Fatalf("expected request path /range/%s, got %q", prefix, seenPath)
	}
	if strings.Contains(seenPath, suffix) {
		t.Fatalf("full 35-char suffix leaked in URL path %q", seenPath)
	}

	// Invalid digest length must be rejected before making any network call.
	if _, err := client.CheckDigest(context.Background(), "not-a-valid-40-char-hex"); err == nil {
		t.Fatalf("expected validation error for malformed hex digest")
	}

	cleanDigest := "ABCDEF1234567890ABCDEF1234567890ABCDEF12"
	cleanPrefix := cleanDigest[:5]
	cleanSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/range/"+cleanPrefix {
			_, _ = w.Write([]byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA:5\n"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer cleanSrv.Close()

	cleanClient := auth.NewHIBPRangeClient(cleanSrv.URL+"/range", allowPolicy)
	breached, err = cleanClient.CheckDigest(context.Background(), cleanDigest)
	if err != nil {
		t.Fatalf("CheckDigest clean: %v", err)
	}
	if breached {
		t.Fatalf("expected breached=false for non-matching suffix")
	}
}

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

	issued, err := sm.IssueSession(ctx, "user-1", "org-1", "", domain.OperatorRoleOrgAdmin)
	if err != nil {
		t.Fatalf("IssueSession: %v", err)
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
