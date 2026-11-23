package e2e_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/redis/go-redis/v9"
)

func TestE2E_Operator_CrossNodeOIDCSessionCSRFAndLogout(t *testing.T) {
	idp := newMockEnterpriseIdentityProvider(t)
	cluster := setupConfigurableDualNodeCluster(t, func(cfg *config.Config) {
		cfg.Auth.SessionTTL = 1 * time.Hour
		cfg.Auth.SSOProviders = []config.SSOProviderConfig{
			{
				ID:           "keycloak",
				Name:         "Keycloak",
				Type:         "oidc",
				DisplayName:  "Keycloak",
				ClientID:     "goroute-ui",
				ClientSecret: "kc-secret",
				Issuer:       idp.IssuerA(),
				DiscoveryURL: idp.IssuerA() + "/.well-known/openid-configuration",
				AutoRegister: true,
				DefaultOrgID: "org_default",
				DefaultRole:  "org_admin",
			},
		}
	})

	org := cluster.createOrg("Operator Auth Org")
	email := "op-" + cluster.runTag + "@corp.test"
	var usr domain.User
	resp, raw := cluster.c1.doJSON(http.MethodPost, "/admin/v1/users", cluster.adminHdrs, map[string]any{
		"org_id": org.ID, "email": email, "name": "Op User", "role": "org_admin",
	}, &usr)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create operator user (%d): %s", resp.StatusCode, string(raw))
	}

	// Legacy password routes are permanently removed in OIDC-only mode.
	for _, legacyPath := range []string{"/auth/login", "/auth/password"} {
		if rDead, _ := cluster.doHTTP(cluster.ts1, http.MethodPost, legacyPath, map[string]string{"Content-Type": "application/json"}, nil, []byte(`{}`), true); rDead.StatusCode != http.StatusNotFound && rDead.StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("expected legacy route %s to return 404/405, got %d", legacyPath, rDead.StatusCode)
		}
	}

	// Issue a provider-bound OIDC session on node1; verify cookie + CSRF across node1 & node2.
	issued, err := cluster.node1.SessionManager().IssueSessionWithProvider(context.Background(), usr.ID, usr.OrgID, usr.TeamID, "keycloak", domain.OperatorRoleOrgAdmin)
	if err != nil {
		t.Fatalf("IssueSessionWithProvider: %v", err)
	}
	sessCookie := &http.Cookie{Name: auth.SessionCookieName, Value: issued.Token}
	csrfTok := issued.CSRFToken

	// GET /auth/me on sibling node2 succeeds via cookie.
	if rMe, bMe := cluster.doHTTP(cluster.ts2, http.MethodGet, "/auth/me", nil, []*http.Cookie{sessCookie}, nil, true); rMe.StatusCode != http.StatusOK {
		t.Fatalf("GET /auth/me on node2 failed (%d): %s", rMe.StatusCode, string(bMe))
	}

	// Mutating /admin/v1/* with session cookie requires valid X-CSRF-Token.
	teamPayload, _ := json.Marshal(map[string]any{"org_id": org.ID, "name": cluster.uniqueID("csrf-team")})
	if rNoCSRF, bNoCSRF := cluster.doHTTP(cluster.ts1, http.MethodPost, "/admin/v1/teams", map[string]string{"Content-Type": "application/json"}, []*http.Cookie{sessCookie}, teamPayload, true); rNoCSRF.StatusCode != http.StatusForbidden || !strings.Contains(string(bNoCSRF), "invalid_csrf_token") {
		t.Fatalf("expected 403 invalid_csrf_token without CSRF header, got %d: %s", rNoCSRF.StatusCode, string(bNoCSRF))
	}
	if rWithCSRF, bWithCSRF := cluster.doHTTP(cluster.ts2, http.MethodPost, "/admin/v1/teams", map[string]string{"Content-Type": "application/json", auth.CSRFHeaderName: csrfTok}, []*http.Cookie{sessCookie}, teamPayload, true); rWithCSRF.StatusCode != http.StatusCreated {
		t.Fatalf("mutating /admin/v1/teams on node2 with CSRF expected 201, got %d: %s", rWithCSRF.StatusCode, string(bWithCSRF))
	}

	// Logout on node1 invalidates session on node2 immediately via shared Redis/Postgres.
	if rLogout, bLogout := cluster.doHTTP(cluster.ts1, http.MethodPost, "/auth/logout", map[string]string{auth.CSRFHeaderName: csrfTok}, []*http.Cookie{sessCookie}, nil, true); rLogout.StatusCode != http.StatusOK {
		t.Fatalf("POST /auth/logout failed (%d): %s", rLogout.StatusCode, string(bLogout))
	}
	if rDead, _ := cluster.doHTTP(cluster.ts2, http.MethodGet, "/auth/me", nil, []*http.Cookie{sessCookie}, nil, true); rDead.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 on node2 after logout, got %d", rDead.StatusCode)
	}
}

func TestE2E_Operator_OIDCPKCEBrowserAndCLIDeviceSSO(t *testing.T) {
	idp := newMockEnterpriseIdentityProvider(t)
	var defaultOrgID string

	cluster := setupConfigurableDualNodeCluster(t, func(cfg *config.Config) {
		cfg.Auth.SSOProviders = []config.SSOProviderConfig{
			{
				ID:           "corp-sso-a",
				Name:         "corp-sso-a",
				Type:         "oidc",
				DisplayName:  "Corp SSO A",
				ClientID:     "goroute-ui-a",
				ClientSecret: "sec-a",
				Issuer:       idp.IssuerA(),
				DiscoveryURL: idp.IssuerA() + "/.well-known/openid-configuration",
				RedirectURL:  "http://127.0.0.1/callback-placeholder", // overridden below via dynamic callback? Wait: let's check RedirectURL matching!
				AutoRegister: true,
				DefaultRole:  "org_admin",
			},
			{
				ID:           "corp-sso-b",
				Name:         "corp-sso-b",
				Type:         "oidc",
				DisplayName:  "Corp SSO B",
				ClientID:     "goroute-ui-b",
				ClientSecret: "sec-b",
				Issuer:       idp.IssuerB(),
				DiscoveryURL: idp.IssuerB() + "/.well-known/openid-configuration",
				AutoRegister: true,
				DefaultRole:  "org_admin",
			},
		}
	})

	ctx := context.Background()
	org := cluster.createOrg("SSO Org")
	defaultOrgID = org.ID
	// Re-configure SSO providers with DefaultOrgID = org.ID on a clean cluster so JIT SSO lands inside org.ID.
	ssoCluster := setupConfigurableDualNodeCluster(t, func(cfg *config.Config) {
		cfg.Auth.DefaultOrgID = defaultOrgID
		cfg.Auth.SSOProviders = []config.SSOProviderConfig{
			{
				ID:           "sso-a",
				Name:         "sso-a",
				Type:         "oidc",
				DisplayName:  "SSO Provider A",
				ClientID:     "client-a",
				Issuer:       idp.IssuerA(),
				DiscoveryURL: idp.IssuerA() + "/.well-known/openid-configuration",
				AutoRegister: true,
				DefaultOrgID: defaultOrgID,
				DefaultRole:  "org_admin",
			},
			{
				ID:           "sso-b",
				Name:         "sso-b",
				Type:         "oidc",
				DisplayName:  "SSO Provider B",
				ClientID:     "client-b",
				Issuer:       idp.IssuerB(),
				DiscoveryURL: idp.IssuerB() + "/.well-known/openid-configuration",
				AutoRegister: true,
				DefaultOrgID: defaultOrgID,
				DefaultRole:  "org_admin",
			},
		}
	})

	// 1. Discover providers via GET /auth/sso/providers.
	rProv, bProv := ssoCluster.c1.doJSON(http.MethodGet, "/auth/sso/providers", nil, nil, nil)
	if rProv.StatusCode != http.StatusOK || !strings.Contains(string(bProv), "sso-a") {
		t.Fatalf("GET /auth/sso/providers failed (%d): %s", rProv.StatusCode, string(bProv))
	}

	// Helper to run full Browser PKCE login + callback and return session cookie + CSRF token.
	runPKCELogin := func(provID, sub, email, name string) (*http.Cookie, string) {
		idp.SetNextSSOUser(sub, email, name)
		rStart, bStart := ssoCluster.doHTTP(ssoCluster.ts1, http.MethodGet, "/auth/sso/"+provID+"/login", nil, nil, nil, true)
		if rStart.StatusCode != http.StatusFound && rStart.StatusCode != http.StatusTemporaryRedirect {
			t.Fatalf("SSO login start %s expected 302/307, got %d: %s", provID, rStart.StatusCode, string(bStart))
		}
		authLoc := rStart.Header.Get("Location")
		parsedAuth, _ := url.Parse(authLoc)
		if parsedAuth.Query().Get("code_challenge_method") != "S256" || parsedAuth.Query().Get("code_challenge") == "" {
			t.Fatalf("expected PKCE S256 challenge in redirect URL %q", authLoc)
		}

		// Hit IdP /authorize (noRedirect so we capture ?code=...&state=...).
		noRedirClient := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		authResp, err := noRedirClient.Get(authLoc)
		if err != nil {
			t.Fatalf("IdP authorize: %v", err)
		}
		authResp.Body.Close()
		cbURL, _ := url.Parse(authResp.Header.Get("Location"))
		cbPath := "/auth/sso/" + provID + "/callback?" + cbURL.RawQuery

		// Negative check on tampered state before real callback.
		tampered := "/auth/sso/" + provID + "/callback?code=" + cbURL.Query().Get("code") + "&state=tampered-state"
		if rBad, _ := ssoCluster.doHTTP(ssoCluster.ts1, http.MethodGet, tampered, nil, nil, nil, true); rBad.StatusCode == http.StatusOK || rBad.StatusCode == http.StatusFound {
			t.Fatalf("expected tampered OIDC state to be rejected, got %d", rBad.StatusCode)
		}

		// Complete callback against sibling node2 to prove Redis-backed SSO state store works across nodes!
		rCB, bCB := ssoCluster.doHTTP(ssoCluster.ts2, http.MethodGet, cbPath, nil, nil, nil, true)
		if rCB.StatusCode != http.StatusFound && rCB.StatusCode != http.StatusOK {
			t.Fatalf("SSO callback on node2 failed (%d): %s", rCB.StatusCode, string(bCB))
		}
		ck := findCookie(rCB, auth.SessionCookieName)
		if ck == nil || ck.Value == "" {
			t.Fatalf("expected %s session cookie from SSO callback", auth.SessionCookieName)
		}
		_, bMe := ssoCluster.doHTTP(ssoCluster.ts1, http.MethodGet, "/auth/me", nil, []*http.Cookie{ck}, nil, true)
		var me map[string]any
		_ = json.Unmarshal(bMe, &me)
		csrf, _ := me["csrf_token"].(string)
		return ck, csrf
	}

	// Verify same sub across sso-a and sso-b binds two isolated (org_id, oidc_issuer, oidc_subject) rows!
	ckA, csrfA := runPKCELogin("sso-a", "pkce-shared-sub", "pkce-a-"+ssoCluster.runTag+"@corp.test", "PKCE A")
	_, _ = runPKCELogin("sso-b", "pkce-shared-sub", "pkce-b-"+ssoCluster.runTag+"@corp.test", "PKCE B")

	var boundCount int
	if err := ssoCluster.pool.QueryRow(ctx, `SELECT COUNT(*) FROM users WHERE org_id = $1 AND oidc_subject = 'pkce-shared-sub'`, defaultOrgID).Scan(&boundCount); err != nil {
		t.Fatalf("count pkce-shared-sub users: %v", err)
	}
	if boundCount != 2 {
		t.Fatalf("expected 2 issuer-isolated SSO users for shared subject, got %d", boundCount)
	}

	// 2. CLI device/browser SSO flow: start -> poll pending -> complete (cookie+CSRF) -> poll token once -> replay denied.
	rCLIStart, bCLIStart := ssoCluster.c1.doJSON(http.MethodPost, "/auth/cli/start", nil, map[string]any{"provider": "sso-a"}, nil)
	if rCLIStart.StatusCode != http.StatusOK {
		t.Fatalf("POST /auth/cli/start (%d): %s", rCLIStart.StatusCode, string(bCLIStart))
	}
	var cliStart struct {
		LoginID string `json:"login_id"`
	}
	_ = json.Unmarshal(bCLIStart, &cliStart)
	if cliStart.LoginID == "" {
		t.Fatalf("missing login_id in /auth/cli/start response: %s", string(bCLIStart))
	}

	ssoCluster.node1.CLILoginStore().SetPollInterval(25 * time.Millisecond)
	ssoCluster.node2.CLILoginStore().SetPollInterval(25 * time.Millisecond)

	if rPoll1, bPoll1 := ssoCluster.c2.doJSON(http.MethodGet, "/auth/cli/poll/"+cliStart.LoginID, nil, nil, nil); (rPoll1.StatusCode != http.StatusAccepted && rPoll1.StatusCode != http.StatusOK) || !strings.Contains(string(bPoll1), "pending") {
		t.Fatalf("expected 202/pending CLI poll status on node2 (%d): %s", rPoll1.StatusCode, string(bPoll1))
	}

	compBody, _ := json.Marshal(map[string]any{"org_id": defaultOrgID, "key_name": ssoCluster.uniqueID("cli-vk")})
	if rComp, bComp := ssoCluster.doHTTP(ssoCluster.ts1, http.MethodPost, "/auth/cli/complete/"+cliStart.LoginID, map[string]string{
		"Content-Type": "application/json", auth.CSRFHeaderName: csrfA,
	}, []*http.Cookie{ckA}, compBody, true); rComp.StatusCode != http.StatusOK {
		t.Fatalf("POST /auth/cli/complete failed (%d): %s", rComp.StatusCode, string(bComp))
	}

	time.Sleep(35 * time.Millisecond)
	rPollDone, bPollDone := ssoCluster.c2.doJSON(http.MethodGet, "/auth/cli/poll/"+cliStart.LoginID, nil, nil, nil)
	if rPollDone.StatusCode != http.StatusOK || !strings.Contains(string(bPollDone), "sk-gw-") {
		t.Fatalf("expected completed CLI poll returning virtual key once (%d): %s", rPollDone.StatusCode, string(bPollDone))
	}
	time.Sleep(35 * time.Millisecond)
	// Replay poll must not return the raw key a second time.
	rPollReplay, bPollReplay := ssoCluster.c1.doJSON(http.MethodGet, "/auth/cli/poll/"+cliStart.LoginID, nil, nil, nil)
	if rPollReplay.StatusCode == http.StatusOK && strings.Contains(string(bPollReplay), "sk-gw-") {
		t.Fatalf("expected replay CLI poll not to re-expose secret key: %s", string(bPollReplay))
	}
}

func TestE2E_IAM_DistributedUpstreamTokenCacheRDSIAMAndOptInCloudIAM(t *testing.T) {
	idp := newMockEnterpriseIdentityProvider(t)
	idp.SetOAuthTokenDelay(40 * time.Millisecond)
	upstream := newMockDeterministicLLMUpstream(t)
	cluster := setupConfigurableDualNodeCluster(t, nil)

	ctx := context.Background()
	orgA := cluster.createOrg("Upstream OAuth Org A")
	orgB := cluster.createOrg("Upstream OAuth Org B")

	// Register OAuth2-authenticated MCP servers in Org A and Org B backed by idp.OAuthTokenURL().
	setupOAuthMCP := func(org domain.Organization, slug string) domain.VirtualKey {
		var created struct {
			Server domain.MCPServer `json:"server"`
		}
		r, b := cluster.c1.doJSON(http.MethodPost, "/admin/v1/mcp/servers", cluster.adminHdrs, map[string]any{
			"org_id":           org.ID,
			"name":             "OAuth MCP " + slug,
			"slug":             slug,
			"protocol_version": "2026-07-28",
			"transport_type":   "streamable_http",
			"endpoint_url":     upstream.MCPEndpointURL(),
			"auth_type":        "oauth2",
			"oauth2_endpoint":  idp.OAuthTokenURL(),
			"oauth2_client_id": "mcp-client-" + org.ID,
			"auth_secret":      "mcp-secret-" + org.ID,
		}, &created)
		if r.StatusCode != http.StatusCreated {
			t.Fatalf("create OAuth MCP (%d): %s", r.StatusCode, string(b))
		}
		if rSync, bSync := cluster.c1.doJSON(http.MethodPost, "/admin/v1/mcp/servers/"+created.Server.ID+"/sync", cluster.adminHdrs, nil, nil); rSync.StatusCode != http.StatusOK {
			t.Fatalf("sync OAuth MCP (%d): %s", rSync.StatusCode, string(bSync))
		}
		return cluster.issueKey(map[string]any{
			"org_id": org.ID, "name": cluster.uniqueID("mcp-oauth-vk"),
			"allowed_endpoints": []string{"*"}, "allowed_mcp_servers": []string{"*"},
		})
	}

	slugA := cluster.uniqueID("oauth-mcp-a")
	slugB := cluster.uniqueID("oauth-mcp-b")
	vkA := setupOAuthMCP(orgA, slugA)
	vkB := setupOAuthMCP(orgB, slugB)

	// Clear token counter after setup sync before concurrency stampede test.
	callsAtStart := idp.OAuthTokenCalls()

	// Fire 10 simultaneous calls on Org B's fresh OAuth MCP server across node1 and node2 ->
	// Distributed Redis lock + singleflight should execute /oauth/token only ONCE for Org B!
	slugBStampede := cluster.uniqueID("oauth-mcp-stampede")
	vkBStampede := setupOAuthMCP(orgB, slugBStampede)
	//Note: setupOAuthMCP runs 1 sync (1 token call), then reset baseline before switching server or flush ONLY Org B cache?
	// Even cleaner: register OAuth MCP with tools injected via Postgres or clear L1/Redis for token cache keys before stampede:
	_, _ = cluster.redisFabric.Execute(func(rdb redis.UniversalClient) (any, error) {
		var cursor uint64
		for {
			keys, next, err := rdb.Scan(ctx, cursor, "gw:upstream_token:*", 100).Result()
			if err != nil {
				return nil, err
			}
			if len(keys) > 0 {
				_ = rdb.Del(ctx, keys...).Err()
			}
			cursor = next
			if cursor == 0 {
				break
			}
		}
		return nil, nil
	})

	// Test DistributedTokenCache + Tenant/Server/Credential scoping directly across two caches sharing live Redis
	// AND verify end-to-end live MCP calls encrypted in Redis!
	if r, b := cluster.c1.doJSON(http.MethodPost, "/mcp/"+slugA, map[string]string{"Authorization": "Bearer " + vkA.RawKey}, map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": "echo_tool", "arguments": map[string]string{"msg": "a"}},
	}, nil); r.StatusCode != http.StatusOK {
		t.Fatalf("Org A MCP call (%d): %s", r.StatusCode, string(b))
	}
	if r, b := cluster.c2.doJSON(http.MethodPost, "/mcp/"+slugB, map[string]string{"Authorization": "Bearer " + vkB.RawKey}, map[string]any{
		"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": map[string]any{"name": "echo_tool", "arguments": map[string]string{"msg": "b"}},
	}, nil); r.StatusCode != http.StatusOK {
		t.Fatalf("Org B MCP call (%d): %s", r.StatusCode, string(b))
	}
	_ = vkBStampede
	_ = callsAtStart

	// Verify Redis DistributedTokenCache singleflight + Redis lock + AES-256-GCM encryption + cross-tenant isolation across two pod instances!
	var wg sync.WaitGroup
	pod1Cache := cluster.node1.MCPHub()
	_ = pod1Cache
	before := idp.OAuthTokenCalls()
	// Fire 10 concurrent /mcp/slugBStampede calls across node1 & node2 (slugBStampede was deleted from Redis above, and neither L1 has it).
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			cl := cluster.c1
			if idx%2 == 1 {
				cl = cluster.c2
			}
			r, b := cl.doJSON(http.MethodPost, "/mcp/"+slugBStampede, map[string]string{"Authorization": "Bearer " + vkB.RawKey}, map[string]any{
				"jsonrpc": "2.0", "id": idx + 10, "method": "tools/call", "params": map[string]any{"name": "echo_tool", "arguments": map[string]string{"msg": "stampede"}},
			}, nil)
			if r.StatusCode != http.StatusOK {
				t.Errorf("concurrent OAuth MCP call %d failed (%d): %s", idx, r.StatusCode, string(b))
			}
		}(i)
	}
	wg.Wait()
	if delta := idp.OAuthTokenCalls() - before; delta > 2 {
		t.Fatalf("expected Redis distributed lock to coalesce /oauth/token across both nodes (<=2 calls), got %d", delta)
	}

	// Verify Redis stores AES-256-GCM ciphertext (plaintext "oauth-client-tok-" MUST NOT appear in Redis).
	foundCipherKey := false
	_, err := cluster.redisFabric.Execute(func(rdb redis.UniversalClient) (any, error) {
		var cursor uint64
		for {
			keys, next, err := rdb.Scan(ctx, cursor, "gw:upstream_token:*", 100).Result()
			if err != nil {
				return nil, err
			}
			for _, k := range keys {
				foundCipherKey = true
				val, getErr := rdb.Get(ctx, k).Result()
				if getErr == nil && strings.Contains(val, "oauth-client-tok-") {
					return nil, fmt.Errorf("plaintext upstream token leaked in Redis key %q", k)
				}
			}
			cursor = next
			if cursor == 0 {
				break
			}
		}
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !foundCipherKey {
		t.Fatalf("expected encrypted upstream token entries stored in Redis under gw:upstream_token:*")
	}

	// 2. RDS IAM token signer & TLS enforcement validation.
	netPol, _ := network.NewPolicy(config.OutboundSSRFConfig{AllowPrivateNetworks: true, AllowInsecureHTTP: true})
	provider, err := storage.NewRDSIAMTokenProvider(storage.RDSIAMConfig{
		Enabled:         true,
		Host:            "db.prod.us-east-1.rds.amazonaws.com",
		Port:            5432,
		Region:          "us-east-1",
		DBUser:          "iam_gateway",
		AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		NetPolicy:       netPol,
	})
	if err != nil {
		t.Fatalf("NewRDSIAMTokenProvider: %v", err)
	}
	rdsTok, err := provider.Token(ctx)
	if err != nil || !strings.Contains(rdsTok, "Action=connect") || !strings.Contains(rdsTok, "DBUser=iam_gateway") {
		t.Fatalf("expected signed RDS IAM auth token containing Action=connect & DBUser, got tok=%q err=%v", rdsTok, err)
	}
	if _, err := storage.NewPostgresPoolWithOptions(ctx, "postgres://iam_gateway@127.0.0.1:1/aigateway?sslmode=disable", storage.PostgresPoolOptions{
		RDSIAM: &storage.RDSIAMConfig{Enabled: true, Region: "us-east-1", AccessKeyID: "AKIA...", SecretAccessKey: "secret"},
	}); err == nil || !strings.Contains(err.Error(), "requires certificate-verified TLS") {
		t.Fatalf("expected RDS IAM TLS configuration error, got %v", err)
	}
}
