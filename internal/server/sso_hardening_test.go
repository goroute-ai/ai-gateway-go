package server_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/server"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

func TestServer_SSOHardening_PublicBaseURL_ViewerCLIBlock_RateLimit_CORS_AndRevocation(t *testing.T) {
	ctx := context.Background()
	idp := newMockOIDCIdP(t)

	repo := storage.NewMemoryRepository()
	_ = repo.CreateOrganization(ctx, &domain.Organization{ID: "org_a", Name: "Org A", Slug: "org-a", IsActive: true})
	_ = repo.CreateUser(ctx, &domain.User{
		ID:          "u_viewer",
		OrgID:       "org_a",
		Email:       "viewer@orga.local",
		Name:        "Org Viewer",
		Role:        domain.RoleOrgViewer,
		OIDCIssuer:  idp.srv.URL,
		OIDCSubject: "sub-viewer",
		IsActive:    true,
		SCIMActive:  true,
	})
	_ = repo.CreateUser(ctx, &domain.User{
		ID:             "u_scim_off",
		OrgID:          "org_a",
		Email:          "deprov@orga.local",
		Name:           "Deprovisioned",
		Role:           domain.RoleOrgAdmin,
		OIDCIssuer:     idp.srv.URL,
		OIDCSubject:    "sub-scim-off",
		SCIMExternalID: "scim-ext-off",
		IsActive:       true,
		SCIMActive:     false,
	})
	_ = repo.CreateUser(ctx, &domain.User{
		ID:          "u_admin",
		OrgID:       "org_a",
		Email:       "admin@orga.local",
		Name:        "Org Admin",
		Role:        domain.RoleOrgAdmin,
		OIDCIssuer:  idp.srv.URL,
		OIDCSubject: "sub-admin",
		IsActive:    true,
		SCIMActive:  true,
	})

	cfg := config.Default()
	cfg.Server.Environment = "test"
	cfg.Server.PublicBaseURL = "https://gateway.canonical.example"
	cfg.Server.CORSAllowedOrigins = []string{"https://console.canonical.example"}
	cfg.Server.CORSAllowCredentials = true
	cfg.Auth.SessionSecret = "hardening-session-secret-0123456789abcdef"
	cfg.Auth.DefaultOrgID = "org_a"
	cfg.Auth.AuthStartRateLimitPerMin = 4
	cfg.Auth.Introspection = config.IntrospectionConfig{
		Issuer:       idp.srv.URL,
		ClientID:     "introspect-cid",
		ClientSecret: "super-secret-introspect-value",
		Mode:         "introspect",
	}
	cfg.Security.Network.OutboundSSRF.AllowLoopbackHTTP = true
	cfg.Auth.SSOProviders = []config.SSOProviderConfig{{
		ID:                  "keycloak",
		Type:                "oidc",
		ClientID:            "goroute-gateway",
		ClientSecret:        "sso-secret-val",
		Issuer:              idp.srv.URL,
		AllowedEmailDomains: []string{"orga.local"},
		AutoRegister:        true,
		DefaultOrgID:        "org_a",
		DefaultRole:         "org_viewer",
	}}

	srv, err := server.New(cfg, repo, nil, nil)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}

	// 1. CORS OPTIONS preflight must allow X-CSRF-Token header
	corsReq := httptest.NewRequest(http.MethodOptions, "/admin/v1/keys", nil)
	corsReq.Header.Set("Origin", "https://console.canonical.example")
	corsReq.Header.Set("Access-Control-Request-Method", "POST")
	corsRec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(corsRec, corsReq)
	if corsRec.Code != http.StatusNoContent {
		t.Fatalf("CORS preflight status = %d, want 204", corsRec.Code)
	}
	if !strings.Contains(corsRec.Header().Get("Access-Control-Allow-Headers"), "X-CSRF-Token") {
		t.Fatalf("expected X-CSRF-Token in Access-Control-Allow-Headers, got %q", corsRec.Header().Get("Access-Control-Allow-Headers"))
	}

	// 2. Host spoofing on /auth/cli/start must honor canonical Server.PublicBaseURL
	cliStartReq := httptest.NewRequest(http.MethodPost, "/auth/cli/start", strings.NewReader(`{"provider":"keycloak"}`))
	cliStartReq.Host = "evil.attacker.example"
	cliStartReq.RemoteAddr = "10.20.30.10:12345"
	cliStartReq.Header.Set("Content-Type", "application/json")
	cliStartRec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(cliStartRec, cliStartReq)
	if cliStartRec.Code != http.StatusOK {
		t.Fatalf("POST /auth/cli/start status = %d, body = %s", cliStartRec.Code, cliStartRec.Body.String())
	}
	var startResp struct {
		LoginID         string `json:"login_id"`
		VerificationURL string `json:"verification_url"`
	}
	_ = json.Unmarshal(cliStartRec.Body.Bytes(), &startResp)
	if !strings.HasPrefix(startResp.VerificationURL, "https://gateway.canonical.example/ui/cli?") {
		t.Fatalf("expected canonical public_base_url in verification_url, got %q", startResp.VerificationURL)
	}

	// 3. org_viewer must be rejected (403) on POST /auth/cli/complete/{login_id}
	viewerSess, err := srv.SessionManager().IssueSessionWithProvider(ctx, "u_viewer", "org_a", "", "keycloak", domain.OperatorRoleOrgViewer)
	if err != nil {
		t.Fatalf("IssueSessionWithProvider(viewer): %v", err)
	}
	viewerCompleteReq := httptest.NewRequest(http.MethodPost, "/auth/cli/complete/"+startResp.LoginID, strings.NewReader(`{"org_id":"org_a"}`))
	viewerCompleteReq.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: viewerSess.Token})
	viewerCompleteReq.Header.Set(auth.CSRFHeaderName, viewerSess.CSRFToken)
	viewerCompleteReq.Header.Set("Content-Type", "application/json")
	viewerCompleteRec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(viewerCompleteRec, viewerCompleteReq)
	if viewerCompleteRec.Code != http.StatusForbidden {
		t.Fatalf("expected org_viewer to receive 403 on /auth/cli/complete, got %d (%s)", viewerCompleteRec.Code, viewerCompleteRec.Body.String())
	}

	// 3b. org_viewer must also be rejected (403) when completing cli_login_id via SSO callback
	idp.mu.Lock()
	idp.nextSub = "sub-viewer"
	idp.nextEmail = "viewer@orga.local"
	idp.nextName = "Org Viewer"
	idp.mu.Unlock()
	viewerLoginRec := httptest.NewRequest(http.MethodGet, "/auth/sso/keycloak/login?format=json&cli_login_id="+url.QueryEscape(startResp.LoginID), nil)
	viewerLoginRec.RemoteAddr = "10.20.30.12:12345"
	viewerLoginRes := httptest.NewRecorder()
	srv.Handler().ServeHTTP(viewerLoginRes, viewerLoginRec)
	if viewerLoginRes.Code != http.StatusOK {
		t.Fatalf("GET /auth/sso/keycloak/login (viewer cli_login_id) = %d (%s)", viewerLoginRes.Code, viewerLoginRes.Body.String())
	}
	if cc := viewerLoginRes.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("expected Cache-Control=no-store on /auth/* response, got %q", cc)
	}
	var viewerLoginBody struct {
		AuthorizationURL string `json:"authorization_url"`
	}
	_ = json.Unmarshal(viewerLoginRes.Body.Bytes(), &viewerLoginBody)
	vAuthClient := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	vIDPResp, err := vAuthClient.Get(viewerLoginBody.AuthorizationURL)
	if err != nil {
		t.Fatalf("IdP authorize viewer cli_login_id: %v", err)
	}
	_ = vIDPResp.Body.Close()
	vCBURL, _ := url.Parse(vIDPResp.Header.Get("Location"))
	vCBReq := httptest.NewRequest(http.MethodGet, vCBURL.RequestURI(), nil)
	vCBRec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(vCBRec, vCBReq)
	if vCBRec.Code != http.StatusForbidden {
		t.Fatalf("expected org_viewer to receive 403 on linked cli_login_id SSO callback, got %d (%s)", vCBRec.Code, vCBRec.Body.String())
	}

	// 4. SCIM-deprovisioned user must be blocked on SSO browser callback
	idp.mu.Lock()
	idp.nextSub = "sub-scim-off"
	idp.nextEmail = "deprov@orga.local"
	idp.nextName = "Deprovisioned"
	idp.mu.Unlock()

	loginReq := httptest.NewRequest(http.MethodGet, "/auth/sso/keycloak/login?format=json", nil)
	loginReq.RemoteAddr = "10.20.30.11:12345"
	loginRec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(loginRec, loginReq)
	if loginRec.Code != http.StatusOK {
		t.Fatalf("GET /auth/sso/keycloak/login status = %d, body = %s", loginRec.Code, loginRec.Body.String())
	}
	var loginBody struct {
		AuthorizationURL string `json:"authorization_url"`
	}
	_ = json.Unmarshal(loginRec.Body.Bytes(), &loginBody)
	parsedAuth, _ := url.Parse(loginBody.AuthorizationURL)
	if parsedAuth.Query().Get("redirect_uri") != "https://gateway.canonical.example/auth/sso/keycloak/callback" {
		t.Fatalf("expected canonical redirect_uri, got %q", parsedAuth.Query().Get("redirect_uri"))
	}
	// Simulate IdP authorization redirect
	authClient := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	idpResp, err := authClient.Get(loginBody.AuthorizationURL)
	if err != nil {
		t.Fatalf("IdP authorize: %v", err)
	}
	_ = idpResp.Body.Close()
	cbURL, _ := url.Parse(idpResp.Header.Get("Location"))
	cbReq := httptest.NewRequest(http.MethodGet, cbURL.RequestURI(), nil)
	cbRec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(cbRec, cbReq)
	if cbRec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 scim_deprovisioned on SSO callback, got %d (%s)", cbRec.Code, cbRec.Body.String())
	}

	// 5. Admin deactivation immediately revokes operator sessions
	adminSess, err := srv.SessionManager().IssueSessionWithOIDC(ctx, "u_admin", "org_a", "", "keycloak", "id-token-for-logout", domain.OperatorRoleOrgAdmin)
	if err != nil {
		t.Fatalf("IssueSessionWithOIDC: %v", err)
	}
	// Deactivate u_admin via Control Plane PUT /admin/v1/users/u_admin
	deactRec := doJSONReq(t, srv.Handler(), http.MethodPut, "/admin/v1/users/u_admin", map[string]any{
		"is_active": false,
	}, map[string]string{
		"Authorization": "Bearer " + cfg.Auth.MasterAdminKey,
	})
	if deactRec.Code != http.StatusOK {
		t.Fatalf("PUT /admin/v1/users/u_admin status = %d (%s)", deactRec.Code, deactRec.Body.String())
	}
	meReq := httptest.NewRequest(http.MethodGet, "/auth/me", nil)
	meReq.AddCookie(&http.Cookie{Name: auth.SessionCookieName, Value: adminSess.Token})
	meRec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(meRec, meReq)
	if meRec.Code != http.StatusUnauthorized && meRec.Code != http.StatusForbidden {
		t.Fatalf("expected deactivated admin session to be rejected, got %d", meRec.Code)
	}

	// 6. Per-IP rate limiting on /auth/cli/start (limit = 4/min for IP 10.20.30.10; 1 already sent)
	var hit429 bool
	for i := 0; i < 5; i++ {
		rlReq := httptest.NewRequest(http.MethodPost, "/auth/cli/start", strings.NewReader(`{}`))
		rlReq.RemoteAddr = "10.20.30.10:22222"
		rlReq.Header.Set("Content-Type", "application/json")
		rlRec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rlRec, rlReq)
		if rlRec.Code == http.StatusTooManyRequests {
			hit429 = true
			break
		}
	}
	if !hit429 {
		t.Fatal("expected per-IP rate limiter to return 429 after exceeding auth_start_rate_limit_per_min")
	}

	// 7. GET /admin/v1/config exposes redacted introspection.client_secret and public_base_url
	cfgRec := doJSONReq(t, srv.Handler(), http.MethodGet, "/admin/v1/config", nil, map[string]string{
		"Authorization": "Bearer " + cfg.Auth.MasterAdminKey,
	})
	if cfgRec.Code != http.StatusOK {
		t.Fatalf("GET /admin/v1/config status = %d", cfgRec.Code)
	}
	if cc := cfgRec.Header().Get("Cache-Control"); cc != "no-store" {
		t.Fatalf("expected Cache-Control=no-store on /admin/v1/* response, got %q", cc)
	}
	if strings.Contains(cfgRec.Body.String(), "super-secret-introspect-value") {
		t.Fatal("introspection client_secret leaked in /admin/v1/config")
	}
	if !strings.Contains(cfgRec.Body.String(), "https://gateway.canonical.example") {
		t.Fatal("expected public_base_url in /admin/v1/config")
	}

	// 8. SEC-02: Sanitized browser redirect vs JSON on OIDC callback errors (never reflecting error_description)
	htmlCbReq := httptest.NewRequest(http.MethodGet, "/auth/sso/keycloak/callback?error=access_denied&error_description=%3Cscript%3Ealert(1)%3C/script%3E", nil)
	htmlCbReq.Header.Set("Accept", "text/html,application/xhtml+xml")
	htmlCbRec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(htmlCbRec, htmlCbReq)
	if htmlCbRec.Code != http.StatusFound {
		t.Fatalf("expected 302 redirect for browser OIDC callback error, got %d", htmlCbRec.Code)
	}
	if loc := htmlCbRec.Header().Get("Location"); loc != "/ui/?auth_error=access_denied" {
		t.Fatalf("expected sanitized Location=/ui/?auth_error=access_denied, got %q", loc)
	}

	unknownHtmlReq := httptest.NewRequest(http.MethodGet, "/auth/sso/keycloak/callback?error=custom_untrusted_code", nil)
	unknownHtmlReq.Header.Set("Accept", "text/html")
	unknownHtmlRec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(unknownHtmlRec, unknownHtmlReq)
	if unknownHtmlRec.Code != http.StatusFound || unknownHtmlRec.Header().Get("Location") != "/ui/?auth_error=sso_provider_error" {
		t.Fatalf("expected unknown error code to map to /ui/?auth_error=sso_provider_error, got %d %q", unknownHtmlRec.Code, unknownHtmlRec.Header().Get("Location"))
	}

	jsonCbReq := httptest.NewRequest(http.MethodGet, "/auth/sso/keycloak/callback?error=access_denied&error_description=leaked_secret_desc", nil)
	jsonCbReq.Header.Set("Accept", "application/json")
	jsonCbRec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(jsonCbRec, jsonCbReq)
	if jsonCbRec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for JSON OIDC callback error, got %d", jsonCbRec.Code)
	}
	if strings.Contains(jsonCbRec.Body.String(), "leaked_secret_desc") {
		t.Fatalf("JSON callback error must not reflect untrusted error_description: %s", jsonCbRec.Body.String())
	}

	// 9. SEC-03: org_admin cannot mutate, delete, rotate, revoke, or block existing platform_admin users or keys
	platUser := &domain.User{
		ID:          "user-plat-target",
		OrgID:       "org_a",
		Email:       "plat-target@orga.local",
		Role:        domain.RolePlatformAdmin,
		OIDCIssuer:  idp.srv.URL,
		OIDCSubject: "sub-plat-target",
		SCIMActive:  true,
		IsActive:    true,
	}
	if err := repo.CreateUser(ctx, platUser); err != nil {
		t.Fatalf("CreateUser platform_admin: %v", err)
	}
	orgAdminActor := &domain.User{
		ID:         "u_org_admin_actor",
		OrgID:      "org_a",
		Email:      "orgadmin2@orga.local",
		Role:       domain.RoleOrgAdmin,
		SCIMActive: true,
		IsActive:   true,
	}
	if err := repo.CreateUser(ctx, orgAdminActor); err != nil {
		t.Fatalf("CreateUser org_admin: %v", err)
	}
	orgAdminSess, err := srv.SessionManager().IssueSessionWithOIDC(ctx, orgAdminActor.ID, "org_a", "", "keycloak", "id-tok", domain.OperatorRoleOrgAdmin)
	if err != nil {
		t.Fatalf("IssueSessionWithOIDC org_admin: %v", err)
	}
	orgAdminHeaders := map[string]string{
		"Authorization": "Bearer " + orgAdminSess.Token,
		"X-CSRF-Token":  orgAdminSess.CSRFToken,
	}

	masterHeaders := map[string]string{"Authorization": "Bearer " + cfg.Auth.MasterAdminKey}
	issuePlatKeyRec := doJSONReq(t, srv.Handler(), http.MethodPost, "/admin/v1/keys", map[string]any{
		"org_id":  "org_a",
		"user_id": platUser.ID,
		"name":    "plat-admin-key",
		"role":    "platform_admin",
	}, masterHeaders)
	if issuePlatKeyRec.Code != http.StatusCreated {
		t.Fatalf("issue platform_admin key status = %d: %s", issuePlatKeyRec.Code, issuePlatKeyRec.Body.String())
	}
	var platKeyResp struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(issuePlatKeyRec.Body.Bytes(), &platKeyResp)
	if platKeyResp.ID == "" {
		t.Fatalf("expected issued platform_admin key ID in %s", issuePlatKeyRec.Body.String())
	}

	// org_admin attempting to hijack platform_admin user's oidc_subject -> 403
	hijackRec := doJSONReq(t, srv.Handler(), http.MethodPut, "/admin/v1/users/"+platUser.ID, map[string]any{
		"org_id":       "org_a",
		"oidc_subject": "hijacked-sub",
	}, orgAdminHeaders)
	if hijackRec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 when org_admin updates platform_admin user, got %d: %s", hijackRec.Code, hijackRec.Body.String())
	}

	// org_admin attempting to delete platform_admin user -> 403
	delPlatUserRec := doJSONReq(t, srv.Handler(), http.MethodDelete, "/admin/v1/users/"+platUser.ID+"?org_id=org_a", nil, orgAdminHeaders)
	if delPlatUserRec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 when org_admin deletes platform_admin user, got %d: %s", delPlatUserRec.Code, delPlatUserRec.Body.String())
	}

	// org_admin attempting to update, rotate, block, or revoke platform_admin virtual key -> 403
	for _, tc := range []struct {
		method string
		path   string
		body   any
	}{
		{http.MethodPut, "/admin/v1/keys/" + platKeyResp.ID, map[string]any{"org_id": "org_a", "name": "hijacked"}},
		{http.MethodPost, "/admin/v1/keys/" + platKeyResp.ID + "/rotate", map[string]any{"org_id": "org_a"}},
		{http.MethodPost, "/admin/v1/keys/" + platKeyResp.ID + "/block", map[string]any{"reason": "attempt"}},
		{http.MethodPost, "/admin/v1/keys/" + platKeyResp.ID + "/revoke", nil},
		{http.MethodPost, "/admin/v1/keys/bulk-update", map[string]any{"org_id": "org_a", "key_ids": []string{platKeyResp.ID}, "rpm_limit": 10}},
	} {
		rec := doJSONReq(t, srv.Handler(), tc.method, tc.path, tc.body, orgAdminHeaders)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("expected 403 when org_admin calls %s %s on platform_admin key, got %d: %s", tc.method, tc.path, rec.Code, rec.Body.String())
		}
	}
}
