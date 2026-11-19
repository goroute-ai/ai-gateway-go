package server_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/auth/upstream"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/server"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

type mockOIDCAuthCode struct {
	CodeChallenge       string
	CodeChallengeMethod string
	Nonce               string
	RedirectURI         string
	ClientID            string
	Sub                 string
	Email               string
	Name                string
	OverrideNonce       string
	OverrideAud         string
}

type mockOIDCIdP struct {
	t       *testing.T
	privKey *rsa.PrivateKey
	kid     string
	srv     *httptest.Server

	mu            sync.Mutex
	codes         map[string]mockOIDCAuthCode
	nextSub       string
	nextEmail     string
	nextName      string
	overrideNonce string
	overrideAud   string
}

func newMockOIDCIdP(t *testing.T) *mockOIDCIdP {
	t.Helper()
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	m := &mockOIDCIdP{
		t:         t,
		privKey:   privKey,
		kid:       "mock-idp-key-1",
		codes:     make(map[string]mockOIDCAuthCode),
		nextSub:   "oidc-user-1",
		nextEmail: "alice@trusted.example.com",
		nextName:  "Alice Trusted",
	}
	m.srv = httptest.NewServer(http.HandlerFunc(m.handle))
	t.Cleanup(m.srv.Close)
	return m
}

func (m *mockOIDCIdP) URL() string {
	return m.srv.URL
}

func (m *mockOIDCIdP) setNextIdentity(sub, email, name string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.nextSub = sub
	m.nextEmail = email
	m.nextName = name
}

func (m *mockOIDCIdP) setOverrides(nonce, aud string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.overrideNonce = nonce
	m.overrideAud = aud
}

func (m *mockOIDCIdP) handle(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/.well-known/openid-configuration":
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 m.srv.URL,
			"authorization_endpoint": m.srv.URL + "/authorize",
			"token_endpoint":         m.srv.URL + "/token",
			"jwks_uri":               m.srv.URL + "/jwks",
		})
	case "/jwks":
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"keys": []map[string]any{{
				"kty": "RSA",
				"kid": m.kid,
				"use": "sig",
				"alg": "RS256",
				"n":   base64.RawURLEncoding.EncodeToString(m.privKey.N.Bytes()),
				"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(m.privKey.E)).Bytes()),
			}},
		})
	case "/authorize":
		q := r.URL.Query()
		if q.Get("response_type") != "code" {
			http.Error(w, "unsupported response_type", http.StatusBadRequest)
			return
		}
		if q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
			http.Error(w, "missing PKCE S256 challenge", http.StatusBadRequest)
			return
		}
		code := "code-" + q.Get("state")
		m.mu.Lock()
		m.codes[code] = mockOIDCAuthCode{
			CodeChallenge:       q.Get("code_challenge"),
			CodeChallengeMethod: q.Get("code_challenge_method"),
			Nonce:               q.Get("nonce"),
			RedirectURI:         q.Get("redirect_uri"),
			ClientID:            q.Get("client_id"),
			Sub:                 m.nextSub,
			Email:               m.nextEmail,
			Name:                m.nextName,
			OverrideNonce:       m.overrideNonce,
			OverrideAud:         m.overrideAud,
		}
		m.mu.Unlock()

		redir, err := url.Parse(q.Get("redirect_uri"))
		if err != nil {
			http.Error(w, "invalid redirect_uri", http.StatusBadRequest)
			return
		}
		rq := redir.Query()
		rq.Set("code", code)
		rq.Set("state", q.Get("state"))
		redir.RawQuery = rq.Encode()
		http.Redirect(w, r, redir.String(), http.StatusFound)
	case "/token":
		_ = r.ParseForm()
		if r.FormValue("grant_type") != "authorization_code" {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "unsupported_grant_type"})
			return
		}
		code := r.FormValue("code")
		m.mu.Lock()
		entry, ok := m.codes[code]
		if ok {
			delete(m.codes, code)
		}
		m.mu.Unlock()
		if !ok {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant", "error_description": "unknown code"})
			return
		}
		if r.FormValue("client_id") != entry.ClientID || r.FormValue("redirect_uri") != entry.RedirectURI {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant", "error_description": "client_id or redirect_uri mismatch"})
			return
		}
		if !upstream.ValidatePKCE(r.FormValue("code_verifier"), entry.CodeChallenge, entry.CodeChallengeMethod) {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant", "error_description": "PKCE verification failed"})
			return
		}
		nonce := entry.Nonce
		if entry.OverrideNonce != "" {
			nonce = entry.OverrideNonce
		}
		aud := entry.ClientID
		if entry.OverrideAud != "" {
			aud = entry.OverrideAud
		}
		now := time.Now().UTC()
		idToken := signTestRS256JWT(m.t, m.privKey, m.kid, map[string]any{
			"iss":   m.srv.URL,
			"sub":   entry.Sub,
			"aud":   aud,
			"nonce": nonce,
			"email": entry.Email,
			"name":  entry.Name,
			"iat":   now.Unix(),
			"exp":   now.Add(10 * time.Minute).Unix(),
		})
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token_type":   "Bearer",
			"access_token": "mock-access-token",
			"id_token":     idToken,
			"expires_in":   600,
		})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

func runMockIdPAuthorize(t *testing.T, authURL string) (code, state string) {
	t.Helper()
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Get(authURL)
	if err != nil {
		t.Fatalf("GET IdP authorize: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("expected 302 from IdP authorize, got %d", resp.StatusCode)
	}
	loc, err := url.Parse(resp.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse IdP redirect location: %v", err)
	}
	return loc.Query().Get("code"), loc.Query().Get("state")
}

func newOIDCSSOTestServer(t *testing.T, idp *mockOIDCIdP, mutator func(*config.Config)) (*server.GatewayServer, *config.Config) {
	t.Helper()
	srv, _, cfg := newSSOTestServer(t, func(c *config.Config) {
		c.Security.Network.OutboundSSRF.AllowPrivateNetworks = true
		c.Security.Network.OutboundSSRF.AllowInsecureHTTP = true
		c.Auth.DefaultOrgID = "org-sso"
		c.Auth.SSOProviders = []config.SSOProviderConfig{
			{
				ID:                  "oidc",
				Name:                "oidc",
				Type:                "oidc",
				DisplayName:         "Corporate OIDC",
				ClientID:            "gw-oidc-client",
				ClientSecret:        "super-secret-oidc-client-secret",
				Issuer:              idp.URL(),
				DiscoveryURL:        idp.URL() + "/.well-known/openid-configuration",
				Scopes:              []string{"openid", "email", "profile"},
				AllowedEmailDomains: []string{"trusted.example.com"},
				AutoRegister:        true,
				DefaultOrgID:        "org-sso",
				DefaultRole:         "org_admin",
			},
			{
				ID:           "google",
				DisplayName:  "Google Workspace",
				ClientID:     "google-client-id",
				ClientSecret: "google-secret-value-never-expose",
				AutoRegister: true,
				DefaultOrgID: "org-sso",
			},
		}
		if mutator != nil {
			mutator(c)
		}
	})
	return srv, cfg
}

func TestAuthSSO_OIDCProvidersRedactionAndLoginRedirects(t *testing.T) {
	idp := newMockOIDCIdP(t)
	srv, cfg := newOIDCSSOTestServer(t, idp, nil)

	// 1. GET /auth/sso/providers is public and never exposes client_secret.
	provRec := doJSONReq(t, srv.Handler(), http.MethodGet, "/auth/sso/providers", nil, nil)
	if provRec.Code != http.StatusOK {
		t.Fatalf("GET /auth/sso/providers status = %d, body = %s", provRec.Code, provRec.Body.String())
	}
	if strings.Contains(provRec.Body.String(), "super-secret-oidc-client-secret") ||
		strings.Contains(provRec.Body.String(), "google-secret-value-never-expose") {
		t.Fatalf("GET /auth/sso/providers leaked client_secret: %s", provRec.Body.String())
	}
	var provResp struct {
		Providers []auth.SSOProviderPublicInfo `json:"providers"`
	}
	if err := json.Unmarshal(provRec.Body.Bytes(), &provResp); err != nil {
		t.Fatalf("decode providers: %v", err)
	}
	if len(provResp.Providers) != 2 || provResp.Providers[0].ID != "oidc" || provResp.Providers[1].ID != "google" {
		t.Fatalf("unexpected providers list: %+v", provResp.Providers)
	}

	// 2. GET /admin/v1/config redacts sso_providers client_secret.
	cfgRec := doJSONReq(t, srv.Handler(), http.MethodGet, "/admin/v1/config", nil, map[string]string{
		"Authorization": "Bearer " + cfg.Auth.MasterAdminKey,
	})
	if cfgRec.Code != http.StatusOK {
		t.Fatalf("GET /admin/v1/config status = %d, body = %s", cfgRec.Code, cfgRec.Body.String())
	}
	if strings.Contains(cfgRec.Body.String(), "super-secret-oidc-client-secret") ||
		strings.Contains(cfgRec.Body.String(), "google-secret-value-never-expose") {
		t.Fatalf("GET /admin/v1/config leaked SSO client_secret: %s", cfgRec.Body.String())
	}
	if !strings.Contains(cfgRec.Body.String(), `"client_secret":"[REDACTED]"`) {
		t.Fatalf("expected redacted client_secret in /admin/v1/config: %s", cfgRec.Body.String())
	}

	// 3. GET /auth/sso/{provider}/login returns 302 by default and JSON when Accept: application/json.
	redirRec := doJSONReq(t, srv.Handler(), http.MethodGet, "/auth/sso/oidc/login", nil, nil)
	if redirRec.Code != http.StatusFound {
		t.Fatalf("GET /auth/sso/oidc/login status = %d, want 302 (%s)", redirRec.Code, redirRec.Body.String())
	}
	loc := redirRec.Header().Get("Location")
	if !strings.HasPrefix(loc, idp.URL()+"/authorize?") || !strings.Contains(loc, "code_challenge_method=S256") {
		t.Fatalf("unexpected redirect location: %q", loc)
	}

	jsonRec := doJSONReq(t, srv.Handler(), http.MethodGet, "/auth/sso/oidc/login", nil, map[string]string{
		"Accept": "application/json",
	})
	if jsonRec.Code != http.StatusOK {
		t.Fatalf("GET /auth/sso/oidc/login (JSON) status = %d, body = %s", jsonRec.Code, jsonRec.Body.String())
	}
	var loginURLResp struct {
		AuthorizationURL string `json:"authorization_url"`
		State            string `json:"state"`
	}
	if err := json.Unmarshal(jsonRec.Body.Bytes(), &loginURLResp); err != nil {
		t.Fatalf("decode loginURLResp: %v", err)
	}
	if loginURLResp.AuthorizationURL == "" || loginURLResp.State == "" {
		t.Fatalf("expected authorization_url and state, got %+v", loginURLResp)
	}

	// 4. Open-redirect redirect_after values must be rejected.
	for _, badRedirect := range []string{"https://evil.example.com", "//evil.example.com", "/\\evil.example.com"} {
		badRec := doJSONReq(t, srv.Handler(), http.MethodGet, "/auth/sso/oidc/login?redirect_after="+url.QueryEscape(badRedirect), nil, nil)
		if badRec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400 for bad redirect_after %q, got %d", badRedirect, badRec.Code)
		}
	}
}

func TestAuthSSO_OIDCCallback_PKCE_JITProvision_Session_And_SecurityChecks(t *testing.T) {
	idp := newMockOIDCIdP(t)
	srv, _ := newOIDCSSOTestServer(t, idp, nil)

	// 1. Happy path: PKCE S256 + nonce validation + JIT user creation + operator session issuance.
	loginRec := doJSONReq(t, srv.Handler(), http.MethodGet, "/auth/sso/oidc/login?format=json", nil, nil)
	if loginRec.Code != http.StatusOK {
		t.Fatalf("login status = %d, body = %s", loginRec.Code, loginRec.Body.String())
	}
	var startResp struct {
		AuthorizationURL string `json:"authorization_url"`
		State            string `json:"state"`
	}
	_ = json.Unmarshal(loginRec.Body.Bytes(), &startResp)

	code, state := runMockIdPAuthorize(t, startResp.AuthorizationURL)
	cbRec := doJSONReq(t, srv.Handler(), http.MethodGet, "/auth/sso/oidc/callback?code="+url.QueryEscape(code)+"&state="+url.QueryEscape(state), nil, nil)
	if cbRec.Code != http.StatusOK {
		t.Fatalf("callback status = %d, body = %s", cbRec.Code, cbRec.Body.String())
	}

	var cbResp struct {
		Token     string `json:"token"`
		CSRFToken string `json:"csrf_token"`
		Provider  string `json:"provider"`
		Operator  struct {
			ActorID    string `json:"actor_id"`
			Role       string `json:"role"`
			OrgID      string `json:"org_id"`
			AuthMethod string `json:"auth_method"`
			SessionID  string `json:"session_id"`
		} `json:"operator"`
		User domain.User `json:"user"`
	}
	if err := json.Unmarshal(cbRec.Body.Bytes(), &cbResp); err != nil {
		t.Fatalf("decode callback resp: %v", err)
	}
	if cbResp.Token == "" || cbResp.CSRFToken == "" || cbResp.Provider != "oidc" {
		t.Fatalf("unexpected callback resp: %+v", cbResp)
	}
	if cbResp.User.Email != "alice@trusted.example.com" || cbResp.User.OIDCSubject != "oidc-user-1" {
		t.Fatalf("unexpected JIT user: %+v", cbResp.User)
	}
	if cbResp.Operator.Role != "org_admin" || cbResp.Operator.OrgID != "org-sso" || cbResp.Operator.AuthMethod != "session" {
		t.Fatalf("unexpected operator: %+v", cbResp.Operator)
	}

	sessCookie := findCookie(cbRec, auth.SessionCookieName)
	if sessCookie == nil {
		t.Fatalf("expected %s cookie on SSO callback", auth.SessionCookieName)
	}
	meRec := doJSONReq(t, srv.Handler(), http.MethodGet, "/auth/me", nil, nil, sessCookie)
	if meRec.Code != http.StatusOK || !strings.Contains(meRec.Body.String(), "alice@trusted.example.com") {
		t.Fatalf("GET /auth/me with SSO cookie failed: %d %s", meRec.Code, meRec.Body.String())
	}

	// 2. State replay rejection: replaying the same (code, state) must fail with 401.
	replayRec := doJSONReq(t, srv.Handler(), http.MethodGet, "/auth/sso/oidc/callback?code="+url.QueryEscape(code)+"&state="+url.QueryEscape(state), nil, nil)
	if replayRec.Code != http.StatusUnauthorized {
		t.Fatalf("state replay status = %d, want 401 (%s)", replayRec.Code, replayRec.Body.String())
	}

	// 3. Nonce mismatch rejection.
	loginNonceRec := doJSONReq(t, srv.Handler(), http.MethodGet, "/auth/sso/oidc/login?format=json", nil, nil)
	var startNonce struct {
		AuthorizationURL string `json:"authorization_url"`
	}
	_ = json.Unmarshal(loginNonceRec.Body.Bytes(), &startNonce)
	idp.setOverrides("wrong-nonce-value", "")
	badNonceCode, badNonceState := runMockIdPAuthorize(t, startNonce.AuthorizationURL)
	idp.setOverrides("", "")
	badNonceCB := doJSONReq(t, srv.Handler(), http.MethodGet, "/auth/sso/oidc/callback?code="+url.QueryEscape(badNonceCode)+"&state="+url.QueryEscape(badNonceState), nil, nil)
	if badNonceCB.Code != http.StatusUnauthorized || !strings.Contains(badNonceCB.Body.String(), "invalid_sso_nonce") {
		t.Fatalf("expected 401 invalid_sso_nonce, got %d (%s)", badNonceCB.Code, badNonceCB.Body.String())
	}

	// 4. Disallowed email domain rejection.
	idp.setNextIdentity("oidc-evil-user", "mallory@untrusted.example.org", "Mallory Untrusted")
	loginDomainRec := doJSONReq(t, srv.Handler(), http.MethodGet, "/auth/sso/oidc/login?format=json", nil, nil)
	var startDomain struct {
		AuthorizationURL string `json:"authorization_url"`
	}
	_ = json.Unmarshal(loginDomainRec.Body.Bytes(), &startDomain)
	badDomainCode, badDomainState := runMockIdPAuthorize(t, startDomain.AuthorizationURL)
	badDomainCB := doJSONReq(t, srv.Handler(), http.MethodGet, "/auth/sso/oidc/callback?code="+url.QueryEscape(badDomainCode)+"&state="+url.QueryEscape(badDomainState), nil, nil)
	if badDomainCB.Code != http.StatusForbidden || !strings.Contains(badDomainCB.Body.String(), "email_domain_not_allowed") {
		t.Fatalf("expected 403 email_domain_not_allowed, got %d (%s)", badDomainCB.Code, badDomainCB.Body.String())
	}
	if findCookie(badDomainCB, auth.SessionCookieName) != nil {
		t.Fatalf("session cookie must not be set on rejected email domain")
	}
}

func TestAuthSSO_CLIFlow_StartCompletePoll_RateLimitAndSingleUse(t *testing.T) {
	idp := newMockOIDCIdP(t)
	srv, cfg := newOIDCSSOTestServer(t, idp, nil)
	ctx := context.Background()

	// Create a team in org-sso so CLI completion can scope the minted Virtual Key to org+team.
	team := &domain.Team{
		ID:       "team-cli",
		OrgID:    "org-sso",
		Name:     "CLI Team",
		IsActive: true,
	}
	if err := srv.AuthService().Repo().CreateTeam(ctx, team); err != nil {
		t.Fatalf("CreateTeam: %v", err)
	}

	now := time.Date(2026, 11, 18, 16, 0, 0, 0, time.UTC)
	srv.CLILoginStore().SetNowFunc(func() time.Time { return now })
	srv.CLILoginStore().SetPollInterval(5 * time.Second)

	// 1. CLI calls POST /auth/cli/start.
	startRec := doJSONReq(t, srv.Handler(), http.MethodPost, "/auth/cli/start", map[string]any{
		"provider": "oidc",
	}, nil)
	if startRec.Code != http.StatusOK {
		t.Fatalf("POST /auth/cli/start status = %d, body = %s", startRec.Code, startRec.Body.String())
	}
	var startResp struct {
		LoginID         string `json:"login_id"`
		UserCode        string `json:"user_code"`
		VerificationURL string `json:"verification_url"`
		ExpiresIn       int    `json:"expires_in"`
		Interval        int    `json:"interval"`
	}
	if err := json.Unmarshal(startRec.Body.Bytes(), &startResp); err != nil {
		t.Fatalf("decode startResp: %v", err)
	}
	if startResp.LoginID == "" || startResp.UserCode == "" || startResp.VerificationURL == "" || startResp.ExpiresIn <= 0 {
		t.Fatalf("unexpected CLI start response: %+v", startResp)
	}

	// 2. CLI polls while pending -> 202 Accepted.
	pollPending := doJSONReq(t, srv.Handler(), http.MethodGet, "/auth/cli/poll/"+startResp.LoginID, nil, nil)
	if pollPending.Code != http.StatusAccepted || !strings.Contains(pollPending.Body.String(), `"pending"`) {
		t.Fatalf("expected 202 pending, got %d (%s)", pollPending.Code, pollPending.Body.String())
	}

	// 3. Immediate second poll enforces rate limit -> 429 Too Many Requests.
	pollFast := doJSONReq(t, srv.Handler(), http.MethodGet, "/auth/cli/poll/"+startResp.LoginID, nil, nil)
	if pollFast.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 on rapid CLI poll, got %d (%s)", pollFast.Code, pollFast.Body.String())
	}
	if pollFast.Header().Get("Retry-After") == "" {
		t.Fatalf("expected Retry-After header on 429 CLI poll")
	}

	// 4. Operator authenticates via OIDC SSO to get a session cookie + CSRF token.
	ssoLoginRec := doJSONReq(t, srv.Handler(), http.MethodGet, "/auth/sso/oidc/login?format=json", nil, nil)
	var ssoStart struct {
		AuthorizationURL string `json:"authorization_url"`
	}
	_ = json.Unmarshal(ssoLoginRec.Body.Bytes(), &ssoStart)
	code, state := runMockIdPAuthorize(t, ssoStart.AuthorizationURL)
	cbRec := doJSONReq(t, srv.Handler(), http.MethodGet, "/auth/sso/oidc/callback?code="+url.QueryEscape(code)+"&state="+url.QueryEscape(state), nil, nil)
	if cbRec.Code != http.StatusOK {
		t.Fatalf("SSO callback status = %d, body = %s", cbRec.Code, cbRec.Body.String())
	}
	var cbResp struct {
		CSRFToken string `json:"csrf_token"`
	}
	_ = json.Unmarshal(cbRec.Body.Bytes(), &cbResp)
	sessCookie := findCookie(cbRec, auth.SessionCookieName)

	// Unauthenticated POST /auth/cli/complete/{login_id} must fail with 401.
	unauthComplete := doJSONReq(t, srv.Handler(), http.MethodPost, "/auth/cli/complete/"+startResp.LoginID, map[string]any{
		"org_id":  "org-sso",
		"team_id": "team-cli",
	}, nil)
	if unauthComplete.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 on unauthenticated cli complete, got %d", unauthComplete.Code)
	}

	// Cookie-authenticated POST /auth/cli/complete/{login_id} without CSRF must fail with 403.
	noCSRFComplete := doJSONReq(t, srv.Handler(), http.MethodPost, "/auth/cli/complete/"+startResp.LoginID, map[string]any{
		"org_id":  "org-sso",
		"team_id": "team-cli",
	}, nil, sessCookie)
	if noCSRFComplete.Code != http.StatusForbidden {
		t.Fatalf("expected 403 without CSRF on cli complete, got %d", noCSRFComplete.Code)
	}

	// Authenticated operator approves CLI login with org_id and team_id.
	completeRec := doJSONReq(t, srv.Handler(), http.MethodPost, "/auth/cli/complete/"+startResp.LoginID, map[string]any{
		"org_id":  "org-sso",
		"team_id": "team-cli",
	}, map[string]string{
		auth.CSRFHeaderName: cbResp.CSRFToken,
	}, sessCookie)
	if completeRec.Code != http.StatusOK {
		t.Fatalf("POST /auth/cli/complete status = %d, body = %s", completeRec.Code, completeRec.Body.String())
	}
	if strings.Contains(completeRec.Body.String(), "raw_key") {
		t.Fatalf("complete response must not expose raw_key directly: %s", completeRec.Body.String())
	}

	// 5. Advance clock past poll interval; CLI picks up the minted Virtual Key once.
	now = now.Add(6 * time.Second)
	pollDone := doJSONReq(t, srv.Handler(), http.MethodGet, "/auth/cli/poll/"+startResp.LoginID, nil, nil)
	if pollDone.Code != http.StatusOK {
		t.Fatalf("expected 200 on completed CLI poll, got %d (%s)", pollDone.Code, pollDone.Body.String())
	}
	var pollResp struct {
		Status     string `json:"status"`
		APIKey     string `json:"api_key"`
		VirtualKey string `json:"virtual_key"`
		KeyPrefix  string `json:"key_prefix"`
		OrgID      string `json:"org_id"`
		TeamID     string `json:"team_id"`
	}
	if err := json.Unmarshal(pollDone.Body.Bytes(), &pollResp); err != nil {
		t.Fatalf("decode pollResp: %v", err)
	}
	if pollResp.Status != "completed" || !strings.HasPrefix(pollResp.APIKey, "sk-gw-") || pollResp.APIKey != pollResp.VirtualKey {
		t.Fatalf("unexpected completed CLI poll response: %+v", pollResp)
	}
	if pollResp.OrgID != "org-sso" || pollResp.TeamID != "team-cli" {
		t.Fatalf("unexpected CLI key scope: %+v", pollResp)
	}

	// Verify the minted Virtual Key authenticates Data Plane requests (and NOT Control Plane admin requests).
	modelsRec := doJSONReq(t, srv.Handler(), http.MethodGet, "/v1/models", nil, map[string]string{
		"Authorization": "Bearer " + pollResp.APIKey,
	})
	if modelsRec.Code != http.StatusOK {
		t.Fatalf("GET /v1/models with CLI virtual key status = %d, body = %s", modelsRec.Code, modelsRec.Body.String())
	}
	adminRec := doJSONReq(t, srv.Handler(), http.MethodGet, "/admin/v1/config", nil, map[string]string{
		"Authorization": "Bearer " + pollResp.APIKey,
	})
	if adminRec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 using llm_api CLI virtual key on /admin/v1/config, got %d (master=%s)", adminRec.Code, cfg.Auth.MasterAdminKey)
	}

	// 6. Second poll immediately after pickup must fail (deleted immediately after retrieval).
	pollReplay := doJSONReq(t, srv.Handler(), http.MethodGet, "/auth/cli/poll/"+startResp.LoginID, nil, nil)
	if pollReplay.Code != http.StatusNotFound {
		t.Fatalf("expected 404 on second poll after single-use pickup, got %d (%s)", pollReplay.Code, pollReplay.Body.String())
	}
}

func TestAuthSSO_LinkedCLILoginViaSSOCallback(t *testing.T) {
	idp := newMockOIDCIdP(t)
	srv, _ := newOIDCSSOTestServer(t, idp, nil)

	startRec := doJSONReq(t, srv.Handler(), http.MethodPost, "/auth/cli/start", nil, nil)
	if startRec.Code != http.StatusOK {
		t.Fatalf("POST /auth/cli/start status = %d, body = %s", startRec.Code, startRec.Body.String())
	}
	var startResp struct {
		LoginID string `json:"login_id"`
	}
	_ = json.Unmarshal(startRec.Body.Bytes(), &startResp)

	// Start SSO login linked to cli_login_id.
	loginRec := doJSONReq(t, srv.Handler(), http.MethodGet, "/auth/sso/oidc/login?format=json&cli_login_id="+url.QueryEscape(startResp.LoginID), nil, nil)
	if loginRec.Code != http.StatusOK {
		t.Fatalf("GET /auth/sso/oidc/login with cli_login_id status = %d, body = %s", loginRec.Code, loginRec.Body.String())
	}
	var loginResp struct {
		AuthorizationURL string `json:"authorization_url"`
	}
	_ = json.Unmarshal(loginRec.Body.Bytes(), &loginResp)

	code, state := runMockIdPAuthorize(t, loginResp.AuthorizationURL)
	cbRec := doJSONReq(t, srv.Handler(), http.MethodGet, "/auth/sso/oidc/callback?code="+url.QueryEscape(code)+"&state="+url.QueryEscape(state), nil, nil)
	if cbRec.Code != http.StatusOK || !strings.Contains(cbRec.Body.String(), `"cli_status":"completed"`) {
		t.Fatalf("expected linked CLI completion on callback, got %d (%s)", cbRec.Code, cbRec.Body.String())
	}

	pollRec := doJSONReq(t, srv.Handler(), http.MethodGet, "/auth/cli/poll/"+startResp.LoginID, nil, nil)
	if pollRec.Code != http.StatusOK || !strings.Contains(pollRec.Body.String(), `"sk-gw-`) {
		t.Fatalf("expected minted Virtual Key on CLI poll after linked SSO callback, got %d (%s)", pollRec.Code, pollRec.Body.String())
	}
}

func TestAuthSSO_MultiIssuerCollisionLegacyFallbackAndNoEmailLinking(t *testing.T) {
	ctx := context.Background()
	idpA := newMockOIDCIdP(t)
	idpB := newMockOIDCIdP(t)

	// Configure two trusted OIDC providers without AutoRegister first to verify
	// unambiguous issuer isolation, no auto email linking, and multi-issuer legacy rejection.
	srv, repo, cfg := newSSOTestServer(t, func(c *config.Config) {
		c.Security.Network.OutboundSSRF.AllowPrivateNetworks = true
		c.Security.Network.OutboundSSRF.AllowInsecureHTTP = true
		c.Auth.DefaultOrgID = "org-sso"
		c.Auth.SSOProviders = []config.SSOProviderConfig{
			{
				ID:                  "idp-a",
				Name:                "idp-a",
				Type:                "oidc",
				DisplayName:         "IdP A",
				ClientID:            "client-a",
				ClientSecret:        "secret-a-0123456789abcdef",
				Issuer:              idpA.URL(),
				DiscoveryURL:        idpA.URL() + "/.well-known/openid-configuration",
				Scopes:              []string{"openid", "email", "profile"},
				AllowedEmailDomains: []string{"trusted.example.com"},
				AutoRegister:        false,
				DefaultOrgID:        "org-sso",
			},
			{
				ID:                  "idp-b",
				Name:                "idp-b",
				Type:                "oidc",
				DisplayName:         "IdP B",
				ClientID:            "client-b",
				ClientSecret:        "secret-b-0123456789abcdef",
				Issuer:              idpB.URL(),
				DiscoveryURL:        idpB.URL() + "/.well-known/openid-configuration",
				Scopes:              []string{"openid", "email", "profile"},
				AllowedEmailDomains: []string{"trusted.example.com"},
				AutoRegister:        false,
				DefaultOrgID:        "org-sso",
			},
		}
	})

	_ = repo.CreateUser(ctx, &domain.User{
		ID:          "usr-idp-a",
		OrgID:       "org-sso",
		Email:       "shared-a@trusted.example.com",
		Name:        "User A",
		Role:        domain.RoleOrgAdmin,
		OIDCIssuer:  idpA.URL(),
		OIDCSubject: "shared-sub",
		IsActive:    true,
	})
	_ = repo.CreateUser(ctx, &domain.User{
		ID:          "usr-idp-b",
		OrgID:       "org-sso",
		Email:       "shared-b@trusted.example.com",
		Name:        "User B",
		Role:        domain.RoleOrgAdmin,
		OIDCIssuer:  idpB.URL(),
		OIDCSubject: "shared-sub",
		IsActive:    true,
	})
	_ = repo.CreateUser(ctx, &domain.User{
		ID:       "usr-email-only",
		OrgID:    "org-sso",
		Email:    "emailonly@trusted.example.com",
		Name:     "Email Only",
		Role:     domain.RoleOrgAdmin,
		IsActive: true,
	})
	_ = repo.CreateUser(ctx, &domain.User{
		ID:          "usr-legacy",
		OrgID:       "org-sso",
		Email:       "legacy@trusted.example.com",
		Name:        "Legacy Unbound",
		Role:        domain.RoleOrgAdmin,
		OIDCSubject: "legacy-sub",
		IsActive:    true,
	})

	oidcCallbackFor := func(targetSrv *server.GatewayServer, prov string, idp *mockOIDCIdP, sub, email string) *httptest.ResponseRecorder {
		idp.mu.Lock()
		idp.nextSub = sub
		idp.nextEmail = email
		idp.mu.Unlock()
		loginRec := doJSONReq(t, targetSrv.Handler(), http.MethodGet, "/auth/sso/"+prov+"/login?format=json", nil, nil)
		if loginRec.Code != http.StatusOK {
			t.Fatalf("GET /auth/sso/%s/login failed: %d (%s)", prov, loginRec.Code, loginRec.Body.String())
		}
		var loginResp struct {
			AuthorizationURL string `json:"authorization_url"`
		}
		_ = json.Unmarshal(loginRec.Body.Bytes(), &loginResp)
		code, state := runMockIdPAuthorize(t, loginResp.AuthorizationURL)
		return doJSONReq(t, targetSrv.Handler(), http.MethodGet, "/auth/sso/"+prov+"/callback?code="+url.QueryEscape(code)+"&state="+url.QueryEscape(state), nil, nil)
	}

	// 1. Colliding sub across two issuers resolves strictly to each issuer's bound user.
	cbA := oidcCallbackFor(srv, "idp-a", idpA, "shared-sub", "shared-a@trusted.example.com")
	if cbA.Code != http.StatusOK || !strings.Contains(cbA.Body.String(), `"usr-idp-a"`) {
		t.Fatalf("expected IdP A callback to resolve usr-idp-a, got %d (%s)", cbA.Code, cbA.Body.String())
	}
	cbB := oidcCallbackFor(srv, "idp-b", idpB, "shared-sub", "shared-b@trusted.example.com")
	if cbB.Code != http.StatusOK || !strings.Contains(cbB.Body.String(), `"usr-idp-b"`) {
		t.Fatalf("expected IdP B callback to resolve usr-idp-b, got %d (%s)", cbB.Code, cbB.Body.String())
	}

	// 2. Email match without matching (org, issuer, sub) must NOT auto-link existing user.
	cbEmail := oidcCallbackFor(srv, "idp-a", idpA, "unlinked-sub", "emailonly@trusted.example.com")
	if cbEmail.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 when email matches unbound user (no auto email linking), got %d (%s)", cbEmail.Code, cbEmail.Body.String())
	}

	// 3. Multi-issuer tenant refuses legacy subject-only binding without explicit oidc_issuer.
	cbLegacy := oidcCallbackFor(srv, "idp-a", idpA, "legacy-sub", "legacy@trusted.example.com")
	if cbLegacy.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for legacy unbound subject under multi-issuer config, got %d (%s)", cbLegacy.Code, cbLegacy.Body.String())
	}

	// 4. Administrator explicitly binds oidc_issuer via PUT /admin/v1/users/{id}, unblocking login.
	bindRec := doJSONReq(t, srv.Handler(), http.MethodPut, "/admin/v1/users/usr-legacy", map[string]any{
		"oidc_issuer": idpA.URL(),
	}, map[string]string{"Authorization": "Bearer " + cfg.Auth.MasterAdminKey})
	if bindRec.Code != http.StatusOK {
		t.Fatalf("PUT /admin/v1/users/usr-legacy failed: %d (%s)", bindRec.Code, bindRec.Body.String())
	}
	cbLegacyBound := oidcCallbackFor(srv, "idp-a", idpA, "legacy-sub", "legacy@trusted.example.com")
	if cbLegacyBound.Code != http.StatusOK || !strings.Contains(cbLegacyBound.Body.String(), `"usr-legacy"`) {
		t.Fatalf("expected bound legacy user login to succeed, got %d (%s)", cbLegacyBound.Code, cbLegacyBound.Body.String())
	}

	// 5. Single-issuer tenant preserves unambiguous legacy subject-only binding automatically.
	idpSingle := newMockOIDCIdP(t)
	singleSrv, singleRepo, _ := newSSOTestServer(t, func(c *config.Config) {
		c.Security.Network.OutboundSSRF.AllowPrivateNetworks = true
		c.Security.Network.OutboundSSRF.AllowInsecureHTTP = true
		c.Auth.DefaultOrgID = "org-sso"
		c.Auth.SSOProviders = []config.SSOProviderConfig{
			{
				ID:           "idp-only",
				Name:         "idp-only",
				Type:         "oidc",
				DisplayName:  "Single IdP",
				ClientID:     "client-only",
				ClientSecret: "secret-only-0123456789abcdef",
				Issuer:       idpSingle.URL(),
				DiscoveryURL: idpSingle.URL() + "/.well-known/openid-configuration",
				Scopes:       []string{"openid", "email"},
				DefaultOrgID: "org-sso",
			},
		}
	})
	_ = singleRepo.CreateUser(ctx, &domain.User{
		ID:          "usr-single-legacy",
		OrgID:       "org-sso",
		Email:       "single-legacy@trusted.example.com",
		Name:        "Single Legacy",
		Role:        domain.RoleOrgAdmin,
		OIDCSubject: "single-legacy-sub",
		IsActive:    true,
	})
	cbSingle := oidcCallbackFor(singleSrv, "idp-only", idpSingle, "single-legacy-sub", "single-legacy@trusted.example.com")
	if cbSingle.Code != http.StatusOK || !strings.Contains(cbSingle.Body.String(), `"usr-single-legacy"`) {
		t.Fatalf("expected unambiguous single-issuer legacy user login to succeed, got %d (%s)", cbSingle.Code, cbSingle.Body.String())
	}
	if _, err := singleRepo.GetUser(ctx, "usr-single-legacy"); err != nil {
		t.Fatalf("sanity check: %v", err)
	}
	_ = storage.ErrNotFound
}
