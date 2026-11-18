package server_test

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/server"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

func newSSOTestServer(t *testing.T, mutator func(*config.Config)) (*server.GatewayServer, *storage.MemoryRepository, *config.Config) {
	t.Helper()
	cfg := config.Default()
	cfg.Server.Environment = "test"
	cfg.Auth.MasterAdminKey = "sk-gw-sso-master-admin-key-12345"
	cfg.Auth.SessionSecret = "sso-session-test-secret-0123456789abcdef"
	cfg.Discovery.Enabled = false
	if mutator != nil {
		mutator(cfg)
	}

	repo := storage.NewMemoryRepository()
	if err := repo.CreateOrganization(context.Background(), &domain.Organization{
		ID:       "org-sso",
		Name:     "SSO Org",
		Slug:     "sso-org",
		IsActive: true,
	}); err != nil {
		t.Fatalf("CreateOrganization: %v", err)
	}

	srv, err := server.New(cfg, repo, nil, nil)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	return srv, repo, cfg
}

func doJSONReq(t *testing.T, h http.Handler, method, path string, body any, headers map[string]string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		if err := json.NewEncoder(&buf).Encode(body); err != nil {
			t.Fatalf("encode body: %v", err)
		}
	}
	req := httptest.NewRequest(method, path, &buf)
	req.RemoteAddr = "127.0.0.1:45678"
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	for _, c := range cookies {
		if c != nil {
			req.AddCookie(c)
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func findCookie(rec *httptest.ResponseRecorder, name string) *http.Cookie {
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

func TestAuthSSO_LoginCookieCSRFAdminAndLogoutRevocation(t *testing.T) {
	srv, repo, cfg := newSSOTestServer(t, nil)
	ctx := context.Background()

	user := &domain.User{
		ID:       "usr-sso-admin",
		OrgID:    "org-sso",
		Email:    "operator@sso.example.com",
		Name:     "SSO Operator",
		Role:     domain.RoleOrgAdmin,
		IsActive: true,
	}
	if err := repo.CreateUser(ctx, user); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	// Admin sets initial password for the user via POST /auth/password.
	setPassRec := doJSONReq(t, srv.Handler(), http.MethodPost, "/auth/password", map[string]any{
		"user_id":      user.ID,
		"new_password": "StrongOperatorPassword!1",
	}, map[string]string{
		"Authorization": "Bearer " + cfg.Auth.MasterAdminKey,
	})
	if setPassRec.Code != http.StatusOK {
		t.Fatalf("POST /auth/password status = %d, body = %s", setPassRec.Code, setPassRec.Body.String())
	}

	// Login via POST /auth/login.
	loginRec := doJSONReq(t, srv.Handler(), http.MethodPost, "/auth/login", map[string]any{
		"email":    user.Email,
		"password": "StrongOperatorPassword!1",
	}, nil)
	if loginRec.Code != http.StatusOK {
		t.Fatalf("POST /auth/login status = %d, body = %s", loginRec.Code, loginRec.Body.String())
	}

	var loginBody struct {
		Token     string `json:"token"`
		CSRFToken string `json:"csrf_token"`
		Operator  struct {
			ActorID    string `json:"actor_id"`
			Role       string `json:"role"`
			OrgID      string `json:"org_id"`
			AuthMethod string `json:"auth_method"`
			SessionID  string `json:"session_id"`
		} `json:"operator"`
	}
	if err := json.Unmarshal(loginRec.Body.Bytes(), &loginBody); err != nil {
		t.Fatalf("decode login response: %v", err)
	}
	if loginBody.Token == "" || loginBody.CSRFToken == "" || loginBody.Operator.SessionID == "" {
		t.Fatalf("expected token, csrf_token, and session_id in login response, got %+v", loginBody)
	}
	if loginBody.Operator.ActorID != user.ID || loginBody.Operator.OrgID != "org-sso" || loginBody.Operator.AuthMethod != "session" {
		t.Fatalf("unexpected operator in login response: %+v", loginBody.Operator)
	}

	sessCookie := findCookie(loginRec, auth.SessionCookieName)
	if sessCookie == nil {
		t.Fatalf("expected %s cookie to be set", auth.SessionCookieName)
	}
	if !sessCookie.HttpOnly || !sessCookie.Secure || sessCookie.SameSite != http.SameSiteLaxMode {
		t.Fatalf("expected HttpOnly; Secure; SameSite=Lax cookie, got %+v", sessCookie)
	}

	// GET /auth/me with cookie succeeds without CSRF header.
	meRec := doJSONReq(t, srv.Handler(), http.MethodGet, "/auth/me", nil, nil, sessCookie)
	if meRec.Code != http.StatusOK {
		t.Fatalf("GET /auth/me (cookie) status = %d, body = %s", meRec.Code, meRec.Body.String())
	}

	// Mutating /admin/v1/* with cookie and NO X-CSRF-Token fails with 403.
	noCSRFRec := doJSONReq(t, srv.Handler(), http.MethodPost, "/admin/v1/teams", map[string]any{
		"org_id": "org-sso",
		"name":   "Team Denied",
	}, nil, sessCookie)
	if noCSRFRec.Code != http.StatusForbidden {
		t.Fatalf("POST /admin/v1/teams without CSRF status = %d, want 403 (%s)", noCSRFRec.Code, noCSRFRec.Body.String())
	}

	// Mutating /admin/v1/* with cookie and wrong X-CSRF-Token fails with 403.
	badCSRFRec := doJSONReq(t, srv.Handler(), http.MethodPost, "/admin/v1/teams", map[string]any{
		"org_id": "org-sso",
		"name":   "Team Denied 2",
	}, map[string]string{
		auth.CSRFHeaderName: "wrong-csrf-token",
	}, sessCookie)
	if badCSRFRec.Code != http.StatusForbidden {
		t.Fatalf("POST /admin/v1/teams with wrong CSRF status = %d, want 403 (%s)", badCSRFRec.Code, badCSRFRec.Body.String())
	}

	// Mutating /admin/v1/* with cookie and valid X-CSRF-Token succeeds.
	okCSRFRec := doJSONReq(t, srv.Handler(), http.MethodPost, "/admin/v1/teams", map[string]any{
		"org_id": "org-sso",
		"name":   "Team Allowed Cookie",
	}, map[string]string{
		auth.CSRFHeaderName: loginBody.CSRFToken,
	}, sessCookie)
	if okCSRFRec.Code != http.StatusCreated {
		t.Fatalf("POST /admin/v1/teams with valid CSRF status = %d, want 201 (%s)", okCSRFRec.Code, okCSRFRec.Body.String())
	}

	// Mutating /admin/v1/* with Authorization: Bearer <session_jwt> succeeds without CSRF header.
	bearerRec := doJSONReq(t, srv.Handler(), http.MethodPost, "/admin/v1/teams", map[string]any{
		"org_id": "org-sso",
		"name":   "Team Allowed Bearer",
	}, map[string]string{
		"Authorization": "Bearer " + loginBody.Token,
	})
	if bearerRec.Code != http.StatusCreated {
		t.Fatalf("POST /admin/v1/teams with Bearer session JWT status = %d, want 201 (%s)", bearerRec.Code, bearerRec.Body.String())
	}

	// Logout revokes session jti and clears cookie.
	logoutRec := doJSONReq(t, srv.Handler(), http.MethodPost, "/auth/logout", nil, map[string]string{
		auth.CSRFHeaderName: loginBody.CSRFToken,
	}, sessCookie)
	if logoutRec.Code != http.StatusOK {
		t.Fatalf("POST /auth/logout status = %d, body = %s", logoutRec.Code, logoutRec.Body.String())
	}
	cleared := findCookie(logoutRec, auth.SessionCookieName)
	if cleared == nil || cleared.MaxAge != -1 {
		t.Fatalf("expected cleared cookie MaxAge=-1, got %+v", cleared)
	}

	// Replayed session cookie and Bearer token must both fail with 401.
	replayCookieRec := doJSONReq(t, srv.Handler(), http.MethodGet, "/auth/me", nil, nil, sessCookie)
	if replayCookieRec.Code != http.StatusUnauthorized {
		t.Fatalf("replayed cookie GET /auth/me status = %d, want 401", replayCookieRec.Code)
	}
	replayAdminRec := doJSONReq(t, srv.Handler(), http.MethodGet, "/admin/v1/teams?org_id=org-sso", nil, map[string]string{
		"Authorization": "Bearer " + loginBody.Token,
	})
	if replayAdminRec.Code != http.StatusUnauthorized {
		t.Fatalf("replayed bearer GET /admin/v1/teams status = %d, want 401", replayAdminRec.Code)
	}
}

func TestAuthSSO_UIAdminCredentialsAndThrottleAndLegacyUpgrade(t *testing.T) {
	srv, repo, _ := newSSOTestServer(t, func(c *config.Config) {
		c.Auth.UIUsername = "admin"
		c.Auth.UIPassword = "super-ui-password-123"
		c.Auth.DefaultOrgID = "org-sso"
	})
	ctx := context.Background()

	// 1. UIUsername/UIPassword login works and returns platform_admin session.
	uiLoginRec := doJSONReq(t, srv.Handler(), http.MethodPost, "/auth/login", map[string]any{
		"username": "admin",
		"password": "super-ui-password-123",
	}, nil)
	if uiLoginRec.Code != http.StatusOK {
		t.Fatalf("UI admin login status = %d, body = %s", uiLoginRec.Code, uiLoginRec.Body.String())
	}
	uiCookie := findCookie(uiLoginRec, auth.SessionCookieName)
	uiMeRec := doJSONReq(t, srv.Handler(), http.MethodGet, "/auth/me", nil, nil, uiCookie)
	if uiMeRec.Code != http.StatusOK || !strings.Contains(uiMeRec.Body.String(), `"platform_admin"`) {
		t.Fatalf("UI admin /auth/me unexpected response: %d %s", uiMeRec.Code, uiMeRec.Body.String())
	}

	// 2. Lower-cost scrypt password hash + 5-attempt lockout throttle + transparent scrypt cost upgrade.
	user := &domain.User{
		ID:       "usr-legacy",
		OrgID:    "org-sso",
		Email:    "legacy@sso.example.com",
		Name:     "Legacy User",
		Role:     domain.RoleOrgAdmin,
		IsActive: true,
	}
	if err := repo.CreateUser(ctx, user); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	legacyHash, err := auth.HashPasswordScryptWithCost("LegacyPass!999", 1024, 8, 1)
	if err != nil {
		t.Fatalf("HashPasswordScryptWithCost: %v", err)
	}
	if err := repo.UpsertUserPassword(ctx, user.ID, legacyHash, false); err != nil {
		t.Fatalf("UpsertUserPassword: %v", err)
	}

	now := time.Date(2026, 11, 18, 14, 0, 0, 0, time.UTC)
	srv.LoginThrottle().SetNowFunc(func() time.Time { return now })

	for i := 1; i <= 5; i++ {
		rec := doJSONReq(t, srv.Handler(), http.MethodPost, "/auth/login", map[string]any{
			"email":    user.Email,
			"password": "wrong-password",
		}, nil)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("bad login %d status = %d, want 401", i, rec.Code)
		}
	}

	// 6th attempt (even with correct password!) is throttled with 429.
	throttledRec := doJSONReq(t, srv.Handler(), http.MethodPost, "/auth/login", map[string]any{
		"email":    user.Email,
		"password": "LegacyPass!999",
	}, nil)
	if throttledRec.Code != http.StatusTooManyRequests {
		t.Fatalf("6th attempt status = %d, want 429 (%s)", throttledRec.Code, throttledRec.Body.String())
	}

	// Advance clock past 300s lockout and login with correct legacy password.
	now = now.Add(301 * time.Second)
	okRec := doJSONReq(t, srv.Handler(), http.MethodPost, "/auth/login", map[string]any{
		"email":    user.Email,
		"password": "LegacyPass!999",
	}, nil)
	if okRec.Code != http.StatusOK {
		t.Fatalf("post-lockout login status = %d, body = %s", okRec.Code, okRec.Body.String())
	}

	// Verify stored password hash was transparently upgraded from sha256: to scrypt:32768:8:1:.
	cred, err := repo.GetUserCredential(ctx, user.ID)
	if err != nil {
		t.Fatalf("GetUserCredential: %v", err)
	}
	if !strings.HasPrefix(cred.PasswordHash, "scrypt:32768:8:1:") {
		t.Fatalf("expected upgraded scrypt hash, got %q", cred.PasswordHash)
	}
}

func TestAuthSSO_HIBPBreachScreeningAndPasswordRotation(t *testing.T) {
	breachedPass := "CompromisedPass!2026"
	breachedDigest := fmt.Sprintf("%X", sha1.Sum([]byte(breachedPass)))
	prefix := breachedDigest[:5]
	suffix := breachedDigest[5:]

	hibpSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/range/"+prefix {
			_, _ = w.Write([]byte(suffix + ":1337\n"))
			return
		}
		_, _ = w.Write([]byte("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:1\n"))
	}))
	defer hibpSrv.Close()

	srv, repo, _ := newSSOTestServer(t, func(c *config.Config) {
		c.Auth.EnableHIBPCheck = true
		c.Auth.HIBPBaseURL = hibpSrv.URL
		c.Security.Network.OutboundSSRF.AllowPrivateNetworks = true
		c.Security.Network.OutboundSSRF.AllowInsecureHTTP = true
	})
	ctx := context.Background()

	user := &domain.User{
		ID:       "usr-hibp",
		OrgID:    "org-sso",
		Email:    "hibp@sso.example.com",
		Name:     "HIBP User",
		Role:     domain.RoleOrgAdmin,
		IsActive: true,
	}
	if err := repo.CreateUser(ctx, user); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	hash, err := auth.HashPasswordScrypt(breachedPass)
	if err != nil {
		t.Fatalf("HashPasswordScrypt: %v", err)
	}
	if err := repo.UpsertUserPassword(ctx, user.ID, hash, false); err != nil {
		t.Fatalf("UpsertUserPassword: %v", err)
	}

	// Logging in with a breached password is rejected server-side before issuing a session,
	// regardless of any client-supplied password_sha1 value.
	for _, fields := range []map[string]any{
		{"email": user.Email, "password": breachedPass},
		{"email": user.Email, "password": breachedPass, "password_sha1": strings.Repeat("A", 40)},
	} {
		loginRec := doJSONReq(t, srv.Handler(), http.MethodPost, "/auth/login", fields, nil)
		if loginRec.Code != http.StatusForbidden || len(loginRec.Result().Cookies()) != 0 {
			t.Fatalf("expected 403 breached_password rejection without a cookie, got %d (%s)", loginRec.Code, loginRec.Body.String())
		}
	}

	session, err := srv.SessionManager().IssueSession(ctx, user.ID, user.OrgID, user.TeamID, domain.OperatorRoleOrgAdmin)
	if err != nil {
		t.Fatalf("IssueSession: %v", err)
	}

	// Rotating to a breached password via POST /auth/password is rejected with 400.
	badRotateRec := doJSONReq(t, srv.Handler(), http.MethodPost, "/auth/password", map[string]any{
		"current_password": breachedPass,
		"new_password":     breachedPass,
	}, map[string]string{
		"Authorization": "Bearer " + session.Token,
	})
	if badRotateRec.Code != http.StatusBadRequest || !strings.Contains(badRotateRec.Body.String(), "breached_password") {
		t.Fatalf("expected 400 breached_password on rotation, got %d (%s)", badRotateRec.Code, badRotateRec.Body.String())
	}

	// Rotating to a clean password succeeds and revokes prior sessions.
	okRotateRec := doJSONReq(t, srv.Handler(), http.MethodPost, "/auth/password", map[string]any{
		"current_password": breachedPass,
		"new_password":     "FreshUnbreachedPass!987",
	}, map[string]string{
		"Authorization": "Bearer " + session.Token,
	})
	if okRotateRec.Code != http.StatusOK {
		t.Fatalf("expected 200 on password rotation, got %d (%s)", okRotateRec.Code, okRotateRec.Body.String())
	}

	// Old session token must be rejected with 401 after password rotation.
	oldMeRec := doJSONReq(t, srv.Handler(), http.MethodGet, "/auth/me", nil, map[string]string{
		"Authorization": "Bearer " + session.Token,
	})
	if oldMeRec.Code != http.StatusUnauthorized {
		t.Fatalf("expected old session token to be revoked after password rotation, got %d", oldMeRec.Code)
	}

	// Login with new password succeeds with password_reset_required = false.
	newLoginRec := doJSONReq(t, srv.Handler(), http.MethodPost, "/auth/login", map[string]any{
		"email":    user.Email,
		"password": "FreshUnbreachedPass!987",
	}, nil)
	if newLoginRec.Code != http.StatusOK {
		t.Fatalf("new login status = %d, body = %s", newLoginRec.Code, newLoginRec.Body.String())
	}
	var newLoginResp struct {
		PasswordResetRequired bool `json:"password_reset_required"`
	}
	if err := json.Unmarshal(newLoginRec.Body.Bytes(), &newLoginResp); err != nil {
		t.Fatalf("decode newLoginResp: %v", err)
	}
	if newLoginResp.PasswordResetRequired {
		t.Fatalf("expected password_reset_required=false after rotation")
	}

	// HIBP outage preserves login availability (fail-open with warning).
	hibpDownSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer hibpDownSrv.Close()
	downSrv, downRepo, _ := newSSOTestServer(t, func(c *config.Config) {
		c.Auth.EnableHIBPCheck = true
		c.Auth.HIBPBaseURL = hibpDownSrv.URL
		c.Security.Network.OutboundSSRF.AllowPrivateNetworks = true
		c.Security.Network.OutboundSSRF.AllowInsecureHTTP = true
	})
	downUser := &domain.User{
		ID:       "usr-hibp-down",
		OrgID:    "org-sso",
		Email:    "hibp-down@sso.example.com",
		Name:     "HIBP Down User",
		Role:     domain.RoleOrgAdmin,
		IsActive: true,
	}
	if err := downRepo.CreateUser(ctx, downUser); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	downHash, _ := auth.HashPasswordScrypt("FreshUnbreachedPass!987")
	if err := downRepo.UpsertUserPassword(ctx, downUser.ID, downHash, false); err != nil {
		t.Fatalf("UpsertUserPassword: %v", err)
	}
	downLoginRec := doJSONReq(t, downSrv.Handler(), http.MethodPost, "/auth/login", map[string]any{
		"email":    downUser.Email,
		"password": "FreshUnbreachedPass!987",
	}, nil)
	if downLoginRec.Code != http.StatusOK {
		t.Fatalf("expected HIBP service outage to fail open on login, got %d (%s)", downLoginRec.Code, downLoginRec.Body.String())
	}
}
