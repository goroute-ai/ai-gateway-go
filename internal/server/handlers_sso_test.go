package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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

func TestAuthSSO_SessionCookieCSRF_RPInitiatedLogout_AndLegacyRoutesRemoved(t *testing.T) {
	idp := newServerTestOIDCIssuer(t)
	srv, repo, _ := newSSOTestServer(t, func(c *config.Config) {
		c.Security.Network.OutboundSSRF.AllowLoopbackHTTP = true
		c.Auth.SSOProviders = []config.SSOProviderConfig{{
			ID:           "keycloak",
			Type:         "oidc",
			ClientID:     "goroute-gateway",
			ClientSecret: "kc-secret",
			Issuer:       idp.Issuer(),
			DiscoveryURL: idp.DiscoveryURL(),
		}}
	})
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

	// Legacy password endpoints are removed in OIDC-only mode.
	for _, removed := range []string{"/auth/login", "/auth/password"} {
		rec := doJSONReq(t, srv.Handler(), http.MethodPost, removed, map[string]any{}, nil)
		if rec.Code != http.StatusNotFound && rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("expected removed endpoint %s to return 404/405, got %d", removed, rec.Code)
		}
	}

	// Issue a provider-bound OIDC operator session cleanly.
	issued, err := srv.SessionManager().IssueSessionWithProvider(ctx, user.ID, user.OrgID, user.TeamID, "keycloak", domain.OperatorRoleOrgAdmin)
	if err != nil {
		t.Fatalf("IssueSessionWithProvider: %v", err)
	}
	sessCookie := &http.Cookie{Name: auth.SessionCookieName, Value: issued.Token}

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
		auth.CSRFHeaderName: issued.CSRFToken,
	}, sessCookie)
	if okCSRFRec.Code != http.StatusCreated {
		t.Fatalf("POST /admin/v1/teams with valid CSRF status = %d, want 201 (%s)", okCSRFRec.Code, okCSRFRec.Body.String())
	}

	// Mutating /admin/v1/* with Authorization: Bearer <session_jwt> succeeds without CSRF header.
	bearerRec := doJSONReq(t, srv.Handler(), http.MethodPost, "/admin/v1/teams", map[string]any{
		"org_id": "org-sso",
		"name":   "Team Allowed Bearer",
	}, map[string]string{
		"Authorization": "Bearer " + issued.Token,
	})
	if bearerRec.Code != http.StatusCreated {
		t.Fatalf("POST /admin/v1/teams with Bearer session JWT status = %d, want 201 (%s)", bearerRec.Code, bearerRec.Body.String())
	}

	// Logout revokes session jti, clears cookie, and returns RP-Initiated Logout end_session_url.
	logoutRec := doJSONReq(t, srv.Handler(), http.MethodPost, "/auth/logout", nil, map[string]string{
		auth.CSRFHeaderName: issued.CSRFToken,
	}, sessCookie)
	if logoutRec.Code != http.StatusOK {
		t.Fatalf("POST /auth/logout status = %d, body = %s", logoutRec.Code, logoutRec.Body.String())
	}
	var logoutResp struct {
		Status        string `json:"status"`
		EndSessionURL string `json:"end_session_url"`
	}
	if err := json.Unmarshal(logoutRec.Body.Bytes(), &logoutResp); err != nil {
		t.Fatalf("decode logout response: %v", err)
	}
	if !strings.HasPrefix(logoutResp.EndSessionURL, idp.Issuer()+"/protocol/openid-connect/logout") ||
		!strings.Contains(logoutResp.EndSessionURL, "post_logout_redirect_uri=") ||
		!strings.Contains(logoutResp.EndSessionURL, "%2Fui%2F") {
		t.Fatalf("expected OIDC end_session_url targeting /ui/ in logout response, got %+v", logoutResp)
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
		"Authorization": "Bearer " + issued.Token,
	})
	if replayAdminRec.Code != http.StatusUnauthorized {
		t.Fatalf("replayed bearer GET /admin/v1/teams status = %d, want 401", replayAdminRec.Code)
	}
}
