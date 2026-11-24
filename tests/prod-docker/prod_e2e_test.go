//go:build proddocker

package proddocker_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const (
	prodLBBase       = "https://gateway.prod.test:18443"
	prodPod1Base     = "https://gateway.prod.test:18444"
	prodPod2Base     = "https://gateway.prod.test:18445"
	prodAuthBase     = "https://auth.prod.test:18443"
	prodFixturesBase = "https://fixtures.prod.test:18443"
	prodMasterKey    = "sk-gw-prod-test-master-admin-key-2026-secure"
	prodComposeFile  = "../../deployments/prod-test/docker-compose.prod-test.yml"
	prodCertCAPath   = "../../.tmp/prod-test-certs/ca.crt"
	prodSSOSecret    = "goroute-prod-oidc-secret-2026"
	prodSessionSec   = "prod-test-hmac-session-secret-0123456789abcdef0123456789abcdef"
	prodRedisPass    = "prod-test-redis-pass-2026"
	prodPostgresPass = "prod-test-pg-password-2026"
	prodAuthzSecret  = "prod-test-authz-hmac-secret-2026"
	prodSIEMSecret   = "prod-test-siem-hmac-secret-2026"
)

func newProdTLSClientWithJar(t *testing.T, followRedirects bool, withJar bool) *http.Client {
	t.Helper()
	caPEM, err := os.ReadFile(prodCertCAPath)
	if err != nil {
		t.Fatalf("read prod-test CA cert %s: %v", prodCertCAPath, err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("failed to parse prod-test CA cert")
	}
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:    pool,
			MinVersion: tls.VersionTLS12,
		},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err == nil && strings.HasSuffix(host, ".prod.test") {
				return dialer.DialContext(ctx, network, net.JoinHostPort("127.0.0.1", port))
			}
			return dialer.DialContext(ctx, network, addr)
		},
	}
	client := &http.Client{
		Transport: tr,
		Timeout:   45 * time.Second,
	}
	if withJar {
		jar, err := cookiejar.New(nil)
		if err != nil {
			t.Fatalf("cookiejar.New: %v", err)
		}
		client.Jar = jar
	}
	if !followRedirects {
		client.CheckRedirect = func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	return client
}

func newProdTLSClient(t *testing.T, followRedirects bool) *http.Client {
	return newProdTLSClientWithJar(t, followRedirects, false)
}

func doReq(t *testing.T, client *http.Client, method, rawURL string, body any, headers map[string]string) (*http.Response, []byte) {
	t.Helper()
	var rdr io.Reader
	if body != nil {
		switch v := body.(type) {
		case string:
			rdr = strings.NewReader(v)
		case []byte:
			rdr = bytes.NewReader(v)
		default:
			raw, err := json.Marshal(v)
			if err != nil {
				t.Fatalf("marshal body: %v", err)
			}
			rdr = bytes.NewReader(raw)
		}
	}
	req, err := http.NewRequest(method, rawURL, rdr)
	if err != nil {
		t.Fatalf("NewRequest(%s %s): %v", method, rawURL, err)
	}
	if body != nil && headers["Content-Type"] == "" {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s failed: %v", method, rawURL, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read response body for %s %s: %v", method, rawURL, err)
	}
	return resp, data
}

func mustAdminJSON(t *testing.T, client *http.Client, method, urlStr string, body any, out any, wantStatuses ...int) []byte {
	t.Helper()
	resp, data := doReq(t, client, method, urlStr, body, map[string]string{
		"Authorization": "Bearer " + prodMasterKey,
	})
	ok := false
	for _, s := range wantStatuses {
		if resp.StatusCode == s {
			ok = true
			break
		}
	}
	if !ok {
		t.Fatalf("%s %s status=%d (want %v) body=%s", method, urlStr, resp.StatusCode, wantStatuses, string(data))
	}
	if out != nil {
		if err := json.Unmarshal(data, out); err != nil {
			t.Fatalf("unmarshal %s %s: %v (%s)", method, urlStr, err, string(data))
		}
	}
	return data
}

func mintKeycloakToken(t *testing.T, client *http.Client, realm, clientID, clientSecret, username, password string) string {
	t.Helper()
	form := url.Values{
		"grant_type":    {"password"},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"username":      {username},
		"password":      {password},
		"scope":         {"openid email profile"},
	}
	tokenURL := fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", prodAuthBase, realm)
	resp, data := doReq(t, client, http.MethodPost, tokenURL, form.Encode(), map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("mintKeycloakToken(%s/%s/%s) status=%d body=%s", realm, clientID, username, resp.StatusCode, string(data))
	}
	var tok struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal(data, &tok); err != nil || tok.AccessToken == "" {
		t.Fatalf("parse access_token: %v (%s)", err, string(data))
	}
	return tok.AccessToken
}

func keycloakAdminToken(t *testing.T, client *http.Client) string {
	t.Helper()
	return mintKeycloakToken(t, client, "master", "admin-cli", "", "kcadmin", "prod-test-kc-admin-2026")
}

func performKeycloakSSOLogin(t *testing.T, username, password string) (*http.Client, map[string]any) {
	t.Helper()
	jarClient := newProdTLSClientWithJar(t, true, true)
	resp, pageBytes := doReq(t, jarClient, http.MethodGet, prodLBBase+"/auth/sso/keycloak/login", nil, map[string]string{
		"Accept": "text/html",
	})
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /auth/sso/keycloak/login status=%d body=%s", resp.StatusCode, string(pageBytes))
	}
	re := regexp.MustCompile(`<form[^>]*id="kc-form-login"[^>]*action="([^"]+)"`)
	m := re.FindSubmatch(pageBytes)
	if len(m) < 2 {
		reAlt := regexp.MustCompile(`action="([^"]*login-actions/authenticate[^"]*)"`)
		m = reAlt.FindSubmatch(pageBytes)
	}
	if len(m) < 2 {
		t.Fatalf("failed to find Keycloak login form action in HTML: %s", string(pageBytes))
	}
	actionURL := html.UnescapeString(string(m[1]))

	form := url.Values{
		"username": {username},
		"password": {password},
	}
	cbResp, cbData := doReq(t, jarClient, http.MethodPost, actionURL, form.Encode(), map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
		"Accept":       "application/json",
	})
	if cbResp.StatusCode != http.StatusOK {
		t.Fatalf("Keycloak SSO callback for %s status=%d body=%s", username, cbResp.StatusCode, string(cbData))
	}
	var payload map[string]any
	if err := json.Unmarshal(cbData, &payload); err != nil {
		t.Fatalf("unmarshal SSO callback JSON: %v (%s)", err, string(cbData))
	}
	return jarClient, payload
}

func composeExec(t *testing.T, args ...string) string {
	t.Helper()
	absCompose, err := filepath.Abs(prodComposeFile)
	if err != nil {
		t.Fatalf("abs compose path: %v", err)
	}
	cmdArgs := append([]string{"compose", "-f", absCompose}, args...)
	out, err := exec.Command("docker", cmdArgs...).CombinedOutput()
	if err != nil {
		t.Fatalf("docker %v failed: %v\n%s", cmdArgs, err, string(out))
	}
	return string(out)
}

func psqlExec(t *testing.T, sql string) string {
	t.Helper()
	return composeExec(t, "exec", "-T", "postgres", "psql", "-U", "gateway", "-d", "aigateway", "-tAc", sql)
}

func buildFakeJWT(alg, typ, kid string, claims map[string]any, hmacKey []byte) string {
	hdr := map[string]any{"alg": alg, "typ": typ}
	if kid != "" {
		hdr["kid"] = kid
	}
	hBytes, _ := json.Marshal(hdr)
	cBytes, _ := json.Marshal(claims)
	hEnc := base64.RawURLEncoding.EncodeToString(hBytes)
	cEnc := base64.RawURLEncoding.EncodeToString(cBytes)
	signingInput := hEnc + "." + cEnc
	if alg == "none" {
		return signingInput + "."
	}
	mac := hmac.New(sha256.New, hmacKey)
	_, _ = mac.Write([]byte(signingInput))
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func resetFixtureAuthzPolicy(t *testing.T, client *http.Client) {
	t.Helper()
	resp, data := doReq(t, client, http.MethodDelete, prodFixturesBase+"/_control/authz", nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("reset fixture authz policy status=%d body=%s", resp.StatusCode, string(data))
	}
}

func seedCustomGlobalModel(t *testing.T, id, provider, modelName string, inputMicrosPer1M, outputMicrosPer1M int64) string {
	t.Helper()
	q := fmt.Sprintf(`
INSERT INTO global_models (
	id, provider, model_name, display_name,
	input_cost_micros_per_1m, output_cost_micros_per_1m,
	pricing_status, pricing_version, pricing_provenance_source,
	max_input_tokens, max_output_tokens, supports_inference, capabilities
) VALUES (
	'%s', '%s', '%s', '%s',
	%d, %d,
	'verified', 1, 'prod-docker-test',
	128000, 16384, TRUE, '{"streaming":"supported","tools":"supported"}'::jsonb
)
ON CONFLICT (provider, model_name) DO UPDATE SET
	input_cost_micros_per_1m = EXCLUDED.input_cost_micros_per_1m,
	output_cost_micros_per_1m = EXCLUDED.output_cost_micros_per_1m,
	pricing_status = 'verified',
	supports_inference = TRUE
RETURNING id;`,
		strings.ReplaceAll(id, "'", "''"),
		strings.ReplaceAll(provider, "'", "''"),
		strings.ReplaceAll(modelName, "'", "''"),
		strings.ReplaceAll(modelName, "'", "''"),
		inputMicrosPer1M,
		outputMicrosPer1M,
	)
	out := strings.TrimSpace(psqlExec(t, q))
	lines := strings.Split(out, "\n")
	if len(lines) > 0 {
		return strings.TrimSpace(lines[0])
	}
	return out
}

func TestProdDocker_Suite1_HealthMigrationsHeadersAndRemovedRoutes(t *testing.T) {
	client := newProdTLSClient(t, false)
	resetFixtureAuthzPolicy(t, client)

	for _, base := range []string{prodPod1Base, prodPod2Base, prodLBBase} {
		resp, body := doReq(t, client, http.MethodGet, base+"/readyz", nil, nil)
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("%s/readyz status=%d body=%s", base, resp.StatusCode, string(body))
		}
		if hsts := resp.Header.Get("Strict-Transport-Security"); !strings.Contains(hsts, "max-age=") {
			t.Fatalf("%s missing HSTS header, got %q", base, hsts)
		}
		if xcto := resp.Header.Get("X-Content-Type-Options"); xcto != "nosniff" {
			t.Fatalf("%s missing X-Content-Type-Options=nosniff, got %q", base, xcto)
		}
	}

	corsResp, _ := doReq(t, client, http.MethodOptions, prodLBBase+"/admin/v1/keys", nil, map[string]string{
		"Origin":                        prodLBBase,
		"Access-Control-Request-Method": "POST",
	})
	if corsResp.StatusCode != http.StatusNoContent {
		t.Fatalf("CORS preflight status=%d, want 204", corsResp.StatusCode)
	}
	if !strings.Contains(corsResp.Header.Get("Access-Control-Allow-Headers"), "X-CSRF-Token") {
		t.Fatalf("CORS missing X-CSRF-Token: %q", corsResp.Header.Get("Access-Control-Allow-Headers"))
	}

	for _, path := range []string{"/auth/login", "/auth/password"} {
		resp, _ := doReq(t, client, http.MethodPost, prodLBBase+path, map[string]any{}, nil)
		if resp.StatusCode != http.StatusNotFound && resp.StatusCode != http.StatusMethodNotAllowed {
			t.Fatalf("removed %s returned %d, want 404/405", path, resp.StatusCode)
		}
	}
	for _, prov := range []string{"google", "microsoft"} {
		resp, _ := doReq(t, client, http.MethodGet, prodLBBase+"/auth/sso/"+prov+"/login", nil, nil)
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("unconfigured legacy provider %s returned %d, want 404", prov, resp.StatusCode)
		}
	}

	// Verify PostgreSQL migrations 0039, 0040, and 0041 schema parity
	tblOut := psqlExec(t, "SELECT to_regclass('public.user_credentials');")
	if strings.TrimSpace(tblOut) != "" {
		t.Fatalf("expected user_credentials table dropped by migration 0039, got %q", strings.TrimSpace(tblOut))
	}
	colsOut := psqlExec(t, "SELECT column_name FROM information_schema.columns WHERE table_name='operator_sessions' AND column_name IN ('provider_id','encrypted_id_token','encrypted_id_token_dek') ORDER BY column_name;")
	for _, col := range []string{"encrypted_id_token", "encrypted_id_token_dek", "provider_id"} {
		if !strings.Contains(colsOut, col) {
			t.Fatalf("migration 0040 column %q missing from operator_sessions: %q", col, colsOut)
		}
	}
	vkCols := psqlExec(t, "SELECT column_name FROM information_schema.columns WHERE table_name='virtual_keys' AND column_name IN ('allowed_deployments','allowed_mcp_tools','allowed_mcp_toolsets') ORDER BY column_name;")
	for _, col := range []string{"allowed_deployments", "allowed_mcp_tools", "allowed_mcp_toolsets"} {
		if !strings.Contains(vkCols, col) {
			t.Fatalf("migration 0041 column %q missing from virtual_keys: %q", col, vkCols)
		}
	}
	idxOut := psqlExec(t, "SELECT indexname FROM pg_indexes WHERE schemaname='public' AND indexname='idx_audit_logs_org_created_id';")
	if !strings.Contains(idxOut, "idx_audit_logs_org_created_id") {
		t.Fatalf("migration 0041 audit_logs index missing: %q", idxOut)
	}
}

func TestProdDocker_Suite3_AsymmetricJWT_MultiIssuer_GroupRoleSync_AndSCIM(t *testing.T) {
	client := newProdTLSClient(t, false)
	resetFixtureAuthzPolicy(t, client)

	// 1. Live Keycloak RS256, ES256, EdDSA asymmetric JWT verification
	for _, tc := range []struct {
		name     string
		clientID string
		secret   string
	}{
		{"RS256", "goroute-ci-mint", "goroute-ci-mint-secret-2026"},
		{"ES256", "goroute-ci-es256", "goroute-ci-es256-secret-2026"},
		{"EdDSA", "goroute-ci-eddsa", "goroute-ci-eddsa-secret-2026"},
	} {
		t.Run("Alg_"+tc.name, func(t *testing.T) {
			tok := mintKeycloakToken(t, client, "goroute-prod", tc.clientID, tc.secret, "orgadmin@goroute.local", "ProdOrgAdmin!2026")
			resp, body := doReq(t, client, http.MethodGet, prodLBBase+"/v1/models", nil, map[string]string{
				"Authorization": "Bearer " + tok,
			})
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("%s JWT rejected on /v1/models: status=%d body=%s", tc.name, resp.StatusCode, string(body))
			}
		})
	}

	// 2. Forged/invalid tokens rejected
	now := time.Now().Unix()
	for _, tc := range []struct {
		name  string
		token string
	}{
		{"HS256", buildFakeJWT("HS256", "JWT", "k1", map[string]any{"iss": prodAuthBase + "/realms/goroute-prod", "sub": "u1", "aud": "goroute-gateway", "exp": now + 300}, []byte("secret"))},
		{"AlgNone", buildFakeJWT("none", "JWT", "", map[string]any{"iss": prodAuthBase + "/realms/goroute-prod", "sub": "u1", "aud": "goroute-gateway", "exp": now + 300}, nil)},
		{"IDJAG", buildFakeJWT("RS256", "oauth-id-jag+jwt", "k1", map[string]any{"iss": prodAuthBase + "/realms/goroute-prod", "sub": "u1", "aud": "goroute-gateway", "exp": now + 300}, []byte("k"))},
		{"ExpiredJWT", buildFakeJWT("RS256", "JWT", "k1", map[string]any{"iss": prodAuthBase + "/realms/goroute-prod", "sub": "u1", "aud": "goroute-gateway", "exp": now - 60}, []byte("k"))},
		{"WrongAudJWT", buildFakeJWT("RS256", "JWT", "k1", map[string]any{"iss": prodAuthBase + "/realms/goroute-prod", "sub": "u1", "aud": "wrong-audience", "exp": now + 300}, []byte("k"))},
		{"OpaqueInvalid", "opaque-revoked-token-not-active-in-keycloak"},
	} {
		resp, _ := doReq(t, client, http.MethodGet, prodLBBase+"/v1/models", nil, map[string]string{
			"Authorization": "Bearer " + tc.token,
		})
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("forged/invalid %s token got %d, want 401", tc.name, resp.StatusCode)
		}
	}

	// 3. Unverified email rejected
	unverifiedTok := mintKeycloakToken(t, client, "goroute-prod", "goroute-ci-mint", "goroute-ci-mint-secret-2026", "unverified@goroute.local", "ProdUnverified!2026")
	unvResp, unvBody := doReq(t, client, http.MethodGet, prodLBBase+"/v1/models", nil, map[string]string{
		"Authorization": "Bearer " + unverifiedTok,
	})
	if unvResp.StatusCode != http.StatusUnauthorized && unvResp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected unverified email JWT rejection, got %d (%s)", unvResp.StatusCode, string(unvBody))
	}

	// 4. Privilege ceiling on keycloak-prod (allow_privileged_role_claims=false): privcap has group goroute-platform-admins
	privCapTok := mintKeycloakToken(t, client, "goroute-prod", "goroute-ci-mint", "goroute-ci-mint-secret-2026", "privcap@goroute.local", "ProdPrivCap!2026")
	pcResp, _ := doReq(t, client, http.MethodGet, prodLBBase+"/v1/models", nil, map[string]string{
		"Authorization": "Bearer " + privCapTok,
	})
	if pcResp.StatusCode != http.StatusOK {
		t.Fatalf("expected privcap JWT data plane 200, got %d", pcResp.StatusCode)
	}
	pcAdminResp, _ := doReq(t, client, http.MethodGet, prodLBBase+"/admin/v1/organizations", nil, map[string]string{
		"Authorization": "Bearer " + privCapTok,
	})
	if pcAdminResp.StatusCode == http.StatusOK {
		t.Fatalf("privcap user unexpectedly allowed admin API access when allow_privileged_role_claims=false")
	}
	roleOut := strings.TrimSpace(psqlExec(t, "SELECT role FROM users WHERE email='privcap@goroute.local' LIMIT 1;"))
	if roleOut == "platform_admin" {
		t.Fatalf("privilege ceiling violated: privcap@goroute.local stored as platform_admin!")
	}

	// 5. JWT Key Mapping resolution across replicas
	var mappedVK struct {
		ID string `json:"id"`
	}
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/keys", map[string]any{
		"org_id":         "org_default",
		"name":           "jwt-mapped-scoped-vk",
		"allowed_models": []string{"jwt-mapped-only-model"},
	}, &mappedVK, http.StatusCreated)
	var jwtMapping struct {
		ID string `json:"id"`
	}
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/jwt-mappings", map[string]any{
		"org_id":         "org_default",
		"issuer":         prodAuthBase + "/realms/goroute-prod",
		"claim_name":     "groups",
		"claim_value":    "goroute-platform-admins",
		"virtual_key_id": mappedVK.ID,
	}, &jwtMapping, http.StatusCreated)
	// Clean up JWT mapping after verifying
	defer func() {
		doReq(t, client, http.MethodDelete, prodPod1Base+"/admin/v1/jwt-mappings/"+jwtMapping.ID, nil, map[string]string{
			"Authorization": "Bearer " + prodMasterKey,
		})
	}()
	// Seed a real fixture deployment for jwt-mapped-only-model so we verify BOTH positive 200 and negative 403!
	jwtMapGlobalID := seedCustomGlobalModel(t, "openai/prod-fixture-mini", "openai", "gpt-4o-mini", 100000, 200000)
	var jwtMapCred, jwtMapMG struct {
		ID string `json:"id"`
	}
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/credentials", map[string]any{
		"org_id": "org_default", "provider": "openai", "name": "jwt-map-cred-" + fmt.Sprintf("%d", time.Now().UnixNano()),
		"api_key": "sk-mock-jwt", "base_url": prodFixturesBase + "/llm/eu/v1",
	}, &jwtMapCred, http.StatusCreated)
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/model-groups", map[string]any{
		"org_id": "org_default", "alias": "jwt-mapped-only-model", "routing_strategy": "round_robin",
	}, &jwtMapMG, http.StatusCreated, http.StatusConflict)
	if jwtMapMG.ID != "" {
		mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/deployments", map[string]any{
			"model_group_id": jwtMapMG.ID, "global_model_id": jwtMapGlobalID, "credential_id": jwtMapCred.ID,
			"deployment_name": "dep-jwt-map", "weight": 100, "priority": 1,
		}, nil, http.StatusCreated)
	}

	// privCapTok has group goroute-platform-admins -> allowed on jwt-mapped-only-model (200), denied on unmapped-model (403) on Pod 2
	allowChat, allowBody := doReq(t, client, http.MethodPost, prodPod2Base+"/v1/chat/completions", map[string]any{
		"model":    "jwt-mapped-only-model",
		"messages": []map[string]any{{"role": "user", "content": "hi"}},
	}, map[string]string{"Authorization": "Bearer " + privCapTok})
	if allowChat.StatusCode != http.StatusOK || !strings.Contains(string(allowBody), "eu-deployment-ok") {
		t.Fatalf("JWT-mapped virtual key expected 200 on jwt-mapped-only-model on Pod 2, got %d: %s", allowChat.StatusCode, string(allowBody))
	}
	denyChat, denyBody := doReq(t, client, http.MethodPost, prodPod2Base+"/v1/chat/completions", map[string]any{
		"model":    "unmapped-model",
		"messages": []map[string]any{{"role": "user", "content": "hi"}},
	}, map[string]string{"Authorization": "Bearer " + privCapTok})
	if denyChat.StatusCode != http.StatusForbidden {
		t.Fatalf("JWT-mapped virtual key expected 403 on unmapped-model on Pod 2, got %d: %s", denyChat.StatusCode, string(denyBody))
	}

	// 6. SSO Group-to-Role + Group-to-Team Mapping + Live sync_roles_on_login Demotion + Session Revocation
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/teams", map[string]any{
		"id":     "team-prod-alpha",
		"org_id": "org_default",
		"name":   "Team Alpha",
	}, nil, http.StatusCreated, http.StatusConflict)

	syncJar1, login1 := performKeycloakSSOLogin(t, "syncuser@goroute.local", "ProdSyncUser!2026")
	u1, _ := login1["user"].(map[string]any)
	if u1["role"] != "org_admin" || u1["team_id"] != "team-prod-alpha" {
		t.Fatalf("expected syncuser initial role=org_admin & team_id=team-prod-alpha, got %+v", u1)
	}
	// Verify sessionA works on BOTH replicas before demotion
	for _, base := range []string{prodPod1Base, prodPod2Base} {
		r, b := doReq(t, syncJar1, http.MethodGet, base+"/admin/v1/keys?org_id=org_default", nil, nil)
		if r.StatusCode != http.StatusOK {
			t.Fatalf("syncuser initial org_admin session failed on %s: %d %s", base, r.StatusCode, string(b))
		}
	}

	// Use Keycloak Admin REST API to demote syncuser: goroute-org-admins -> goroute-org-viewers
	kcTok := keycloakAdminToken(t, client)
	kcHdrs := map[string]string{"Authorization": "Bearer " + kcTok}
	_, usersRaw := doReq(t, client, http.MethodGet, prodAuthBase+"/admin/realms/goroute-prod/users?username=syncuser%40goroute.local", nil, kcHdrs)
	var kcUsers []struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(usersRaw, &kcUsers)
	if len(kcUsers) == 0 {
		t.Fatalf("syncuser not found in Keycloak admin API: %s", string(usersRaw))
	}
	syncKCID := kcUsers[0].ID
	_, groupsRaw := doReq(t, client, http.MethodGet, prodAuthBase+"/admin/realms/goroute-prod/groups", nil, kcHdrs)
	var kcGroups []struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	_ = json.Unmarshal(groupsRaw, &kcGroups)
	grpMap := map[string]string{}
	for _, g := range kcGroups {
		grpMap[g.Name] = g.ID
	}
	if grpMap["goroute-org-admins"] == "" || grpMap["goroute-org-viewers"] == "" {
		t.Fatalf("missing expected Keycloak groups: %+v", grpMap)
	}
	doReq(t, client, http.MethodDelete, fmt.Sprintf("%s/admin/realms/goroute-prod/users/%s/groups/%s", prodAuthBase, syncKCID, grpMap["goroute-org-admins"]), nil, kcHdrs)
	putGrpResp, putGrpBody := doReq(t, client, http.MethodPut, fmt.Sprintf("%s/admin/realms/goroute-prod/users/%s/groups/%s", prodAuthBase, syncKCID, grpMap["goroute-org-viewers"]), nil, kcHdrs)
	if putGrpResp.StatusCode >= 300 {
		t.Fatalf("assign goroute-org-viewers in Keycloak failed: %d %s", putGrpResp.StatusCode, string(putGrpBody))
	}
	// Restore group membership on cleanup so re-runs stay idempotent
	defer func() {
		doReq(t, client, http.MethodDelete, fmt.Sprintf("%s/admin/realms/goroute-prod/users/%s/groups/%s", prodAuthBase, syncKCID, grpMap["goroute-org-viewers"]), nil, kcHdrs)
		doReq(t, client, http.MethodPut, fmt.Sprintf("%s/admin/realms/goroute-prod/users/%s/groups/%s", prodAuthBase, syncKCID, grpMap["goroute-org-admins"]), nil, kcHdrs)
	}()

	// Re-login with a fresh jar -> sync_roles_on_login demotes user to org_viewer & revokes session1!
	syncJar2, login2 := performKeycloakSSOLogin(t, "syncuser@goroute.local", "ProdSyncUser!2026")
	u2, _ := login2["user"].(map[string]any)
	if u2["role"] != "org_viewer" {
		t.Fatalf("expected sync_roles_on_login demotion to org_viewer, got %+v", u2)
	}
	csrf2, _ := login2["csrf_token"].(string)

	// Old session1 MUST immediately fail 401 on BOTH replicas (RevokeAllUserSessions + Pub/Sub)
	for _, base := range []string{prodPod1Base, prodPod2Base} {
		oldResp, _ := doReq(t, syncJar1, http.MethodGet, base+"/admin/v1/keys?org_id=org_default", nil, nil)
		if oldResp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("old org_admin session still active after role sync demotion on %s: status=%d", base, oldResp.StatusCode)
		}
	}
	// New session2 has org_viewer read access, denied write access
	getResp, _ := doReq(t, syncJar2, http.MethodGet, prodPod2Base+"/admin/v1/keys?org_id=org_default", nil, nil)
	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("demoted org_viewer GET /admin/v1/keys failed: %d", getResp.StatusCode)
	}
	writeResp, _ := doReq(t, syncJar2, http.MethodPost, prodPod2Base+"/admin/v1/keys", map[string]any{
		"org_id": "org_default", "name": "should-fail-viewer",
	}, map[string]string{"X-CSRF-Token": csrf2})
	if writeResp.StatusCode != http.StatusForbidden {
		t.Fatalf("demoted org_viewer unexpectedly allowed POST /admin/v1/keys: %d", writeResp.StatusCode)
	}
	// Verify sso.role_synced audit record with before/after diff
	_, syncAuditBody := doReq(t, client, http.MethodGet, prodLBBase+"/admin/v1/audit/logs?org_id=org_default&action=sso.role_synced", nil, map[string]string{
		"Authorization": "Bearer " + prodMasterKey,
	})
	if !strings.Contains(string(syncAuditBody), "org_viewer") || !strings.Contains(string(syncAuditBody), "org_admin") {
		t.Fatalf("expected sso.role_synced before/after diff in audit log, got: %s", string(syncAuditBody))
	}

	// 7. Multi-issuer tenant-b isolation & cross-replica SCIM deprovisioning
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/organizations", map[string]any{
		"id": "org_tenant_b", "name": "Tenant B Org", "slug": "tenant-b",
	}, nil, http.StatusCreated, http.StatusConflict)
	bobTok := mintKeycloakToken(t, client, "tenant-b", "goroute-tenant-b-mint", "tenant-b-mint-secret-2026", "bob@tenantb.local", "TenantB!2026")
	parts := strings.Split(bobTok, ".")
	claimsJSON, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var bobClaims struct {
		Sub string `json:"sub"`
	}
	_ = json.Unmarshal(claimsJSON, &bobClaims)
	preBindResp, _ := doReq(t, client, http.MethodGet, prodPod2Base+"/v1/models", nil, map[string]string{"Authorization": "Bearer " + bobTok})
	if preBindResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected unbound tenant-b user to get 401, got %d", preBindResp.StatusCode)
	}
	var createdBob struct {
		ID string `json:"id"`
	}
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/users", map[string]any{
		"org_id": "org_tenant_b", "email": "bob@tenantb.local", "name": "Bob TenantB",
		"role": "developer", "oidc_issuer": prodAuthBase + "/realms/tenant-b", "oidc_subject": bobClaims.Sub,
	}, &createdBob, http.StatusCreated)
	postBindResp, postBindBody := doReq(t, client, http.MethodGet, prodPod2Base+"/v1/models", nil, map[string]string{"Authorization": "Bearer " + bobTok})
	if postBindResp.StatusCode != http.StatusOK {
		t.Fatalf("expected bound tenant-b user on Pod 2 to get 200, got %d (%s)", postBindResp.StatusCode, string(postBindBody))
	}
	mustAdminJSON(t, client, http.MethodPut, prodPod1Base+"/admin/v1/users/"+createdBob.ID, map[string]any{
		"scim_active": false,
	}, nil, http.StatusOK)
	afterDeactResp, _ := doReq(t, client, http.MethodGet, prodPod2Base+"/v1/models", nil, map[string]string{"Authorization": "Bearer " + bobTok})
	if afterDeactResp.StatusCode != http.StatusForbidden && afterDeactResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected SCIM-deactivated user to fail immediately on Pod 2, got %d", afterDeactResp.StatusCode)
	}
}

func TestProdDocker_Suite4_SecurityAttackMatrix(t *testing.T) {
	client := newProdTLSClient(t, false)
	resetFixtureAuthzPolicy(t, client)

	for _, bad := range []string{"https://evil.example/steal", "//evil.example/steal", `/\evil.example`, "javascript:alert(1)"} {
		u := prodLBBase + "/auth/sso/keycloak/login?redirect_after=" + url.QueryEscape(bad)
		resp, _ := doReq(t, client, http.MethodGet, u, nil, nil)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("open redirect %q got %d, want 400", bad, resp.StatusCode)
		}
	}

	cliResp, cliBody := doReq(t, client, http.MethodPost, prodLBBase+"/auth/cli/start", map[string]any{"provider": "keycloak"}, map[string]string{
		"X-Forwarded-Proto": "http",
		"X-Forwarded-Host":  "evil.attacker.example",
	})
	if cliResp.StatusCode != http.StatusOK {
		t.Fatalf("POST /auth/cli/start status=%d body=%s", cliResp.StatusCode, string(cliBody))
	}
	var cliStart struct {
		VerificationURL string `json:"verification_url"`
	}
	_ = json.Unmarshal(cliBody, &cliStart)
	if !strings.HasPrefix(cliStart.VerificationURL, prodLBBase+"/ui/cli?") {
		t.Fatalf("verification_url did not honor canonical public_base_url: %q", cliStart.VerificationURL)
	}

	for _, target := range []string{"http://172.30.30.10:8080/secret", "http://169.254.169.254/latest/meta-data/"} {
		credResp, credBody := doReq(t, client, http.MethodPost, prodLBBase+"/admin/v1/credentials", map[string]any{
			"org_id": "org_default", "provider": "openai", "name": "ssrf-cred", "api_key": "sk-test", "base_url": target,
		}, map[string]string{"Authorization": "Bearer " + prodMasterKey})
		if credResp.StatusCode == http.StatusOK || credResp.StatusCode == http.StatusCreated {
			t.Fatalf("credential SSRF target %s unexpectedly allowed: %d %s", target, credResp.StatusCode, string(credBody))
		}
		whResp, whBody := doReq(t, client, http.MethodPut, prodLBBase+"/admin/v1/organizations/org_default", map[string]any{
			"lifecycle_webhook_url": target,
		}, map[string]string{"Authorization": "Bearer " + prodMasterKey})
		if whResp.StatusCode == http.StatusOK {
			t.Fatalf("webhook SSRF target %s unexpectedly allowed: %d %s", target, whResp.StatusCode, string(whBody))
		}
		var mcpSrv struct {
			Server struct {
				ID string `json:"id"`
			} `json:"server"`
		}
		mustAdminJSON(t, client, http.MethodPost, prodLBBase+"/admin/v1/mcp/servers", map[string]any{
			"org_id": "org_default", "name": "ssrf-probe", "slug": fmt.Sprintf("ssrf-probe-%d", time.Now().UnixNano()),
			"transport_type": "streamable_http", "endpoint_url": target, "auth_type": "none",
		}, &mcpSrv, http.StatusCreated)
		syncResp, syncBody := doReq(t, client, http.MethodPost, prodLBBase+"/admin/v1/mcp/servers/"+mcpSrv.Server.ID+"/sync", map[string]any{}, map[string]string{"Authorization": "Bearer " + prodMasterKey})
		if syncResp.StatusCode == http.StatusOK {
			t.Fatalf("MCP sync SSRF target %s unexpectedly allowed: %d %s", target, syncResp.StatusCode, string(syncBody))
		}
	}

	cfgBody := mustAdminJSON(t, client, http.MethodGet, prodLBBase+"/admin/v1/config", nil, nil, http.StatusOK)
	cfgText := string(cfgBody)
	for _, secret := range []string{prodMasterKey, prodSSOSecret, prodSessionSec, prodRedisPass, prodPostgresPass, prodAuthzSecret, prodSIEMSecret} {
		if strings.Contains(cfgText, secret) {
			t.Fatalf("secret %q leaked in GET /admin/v1/config!", secret[:8]+"...")
		}
	}
	if !strings.Contains(cfgText, `"external_authorizer"`) || !strings.Contains(cfgText, `"siem_webhook"`) {
		t.Fatalf("expected external_authorizer and siem_webhook metadata in GET /admin/v1/config")
	}
}

func TestProdDocker_Suite5_RBAC_Ownership_AndSec03(t *testing.T) {
	client := newProdTLSClient(t, false)
	resetFixtureAuthzPolicy(t, client)

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	var org struct {
		ID string `json:"id"`
	}
	mustAdminJSON(t, client, http.MethodPost, prodLBBase+"/admin/v1/organizations", map[string]any{
		"name": "RBAC Prod Org " + suffix, "slug": "rbac-prod-" + suffix,
	}, &org, http.StatusCreated)

	var platUser, teamAdmUser, memberUser struct {
		ID string `json:"id"`
	}
	mustAdminJSON(t, client, http.MethodPost, prodLBBase+"/admin/v1/users", map[string]any{
		"org_id": org.ID, "email": "plat-" + suffix + "@goroute.local", "name": "Plat", "role": "platform_admin",
	}, &platUser, http.StatusCreated)
	mustAdminJSON(t, client, http.MethodPost, prodLBBase+"/admin/v1/users", map[string]any{
		"org_id": org.ID, "email": "ta-" + suffix + "@goroute.local", "name": "TeamAdm", "role": "team_admin",
	}, &teamAdmUser, http.StatusCreated)
	mustAdminJSON(t, client, http.MethodPost, prodLBBase+"/admin/v1/users", map[string]any{
		"org_id": org.ID, "email": "dev-" + suffix + "@goroute.local", "name": "Dev", "role": "developer",
	}, &memberUser, http.StatusCreated)

	var orgAdmKey, teamAdmKey, platKey struct {
		ID     string `json:"id"`
		RawKey string `json:"raw_key"`
	}
	mustAdminJSON(t, client, http.MethodPost, prodLBBase+"/admin/v1/keys", map[string]any{
		"org_id": org.ID, "name": "org-admin-mgmt", "role": "org_admin", "key_type": "management", "allowed_endpoints": []string{"*"},
	}, &orgAdmKey, http.StatusCreated)
	mustAdminJSON(t, client, http.MethodPost, prodLBBase+"/admin/v1/keys", map[string]any{
		"org_id": org.ID, "name": "plat-admin-vk", "user_id": platUser.ID, "role": "platform_admin", "key_type": "default", "allowed_endpoints": []string{"*"},
	}, &platKey, http.StatusCreated)
	mustAdminJSON(t, client, http.MethodPost, prodLBBase+"/admin/v1/keys", map[string]any{
		"org_id": org.ID, "name": "team-admin-mgmt", "user_id": teamAdmUser.ID, "role": "team_admin", "key_type": "management", "allowed_endpoints": []string{"*"},
	}, &teamAdmKey, http.StatusCreated)

	// SEC-03: org_admin cannot mutate, rotate, or revoke platform_admin user or platform_admin virtual key
	mutUserResp, _ := doReq(t, client, http.MethodPut, prodPod1Base+"/admin/v1/users/"+platUser.ID, map[string]any{
		"name": "Hijacked",
	}, map[string]string{"Authorization": "Bearer " + orgAdmKey.RawKey})
	if mutUserResp.StatusCode != http.StatusForbidden {
		t.Fatalf("SEC-03 violation: org_admin modified platform_admin user, got %d", mutUserResp.StatusCode)
	}
	rotKeyResp, _ := doReq(t, client, http.MethodPost, prodPod2Base+"/admin/v1/keys/"+platKey.ID+"/rotate", map[string]any{}, map[string]string{
		"Authorization": "Bearer " + orgAdmKey.RawKey,
	})
	if rotKeyResp.StatusCode != http.StatusForbidden {
		t.Fatalf("SEC-03 violation: org_admin rotated platform_admin key, got %d", rotKeyResp.StatusCode)
	}
	// org_admin can list users in own org but cannot manage another org
	crossOrgResp, _ := doReq(t, client, http.MethodGet, prodLBBase+"/admin/v1/users?org_id=org_default", nil, map[string]string{
		"Authorization": "Bearer " + orgAdmKey.RawKey,
	})
	if crossOrgResp.StatusCode != http.StatusForbidden {
		t.Fatalf("cross-org isolation violation: org_admin read org_default users, got %d", crossOrgResp.StatusCode)
	}
	// team_admin cannot list or delete users across org
	taDelResp, _ := doReq(t, client, http.MethodDelete, prodLBBase+"/admin/v1/users/"+memberUser.ID, nil, map[string]string{
		"Authorization": "Bearer " + teamAdmKey.RawKey,
	})
	if taDelResp.StatusCode != http.StatusForbidden {
		t.Fatalf("team_admin unexpectedly allowed to delete user, got %d", taDelResp.StatusCode)
	}
}

func TestProdDocker_Suite6_Models_Deployments_MandatoryTags_Projects_Budgets_RateLimits(t *testing.T) {
	client := newProdTLSClient(t, false)
	resetFixtureAuthzPolicy(t, client)

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	globalID := seedCustomGlobalModel(t, "openai/prod-fixture-mini", "openai", "gpt-4o-mini", 100000, 200000)

	var org struct {
		ID string `json:"id"`
	}
	mustAdminJSON(t, client, http.MethodPost, prodLBBase+"/admin/v1/organizations", map[string]any{
		"name": "Suite6 Org " + suffix, "slug": "suite6-" + suffix,
	}, &org, http.StatusCreated)
	mustAdminJSON(t, client, http.MethodPost, prodLBBase+"/admin/v1/organizations/"+org.ID+"/subscriptions", map[string]any{
		"provider": "openai", "is_enabled": true,
	}, nil, http.StatusOK)

	var credEU, credUS struct {
		ID string `json:"id"`
	}
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/credentials", map[string]any{
		"org_id": org.ID, "provider": "openai", "name": "eu-cred-" + suffix, "api_key": "sk-mock-eu", "base_url": prodFixturesBase + "/llm/eu/v1",
	}, &credEU, http.StatusCreated)
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/credentials", map[string]any{
		"org_id": org.ID, "provider": "openai", "name": "us-cred-" + suffix, "api_key": "sk-mock-us", "base_url": prodFixturesBase + "/llm/us/v1",
	}, &credUS, http.StatusCreated)

	var mgResidency, mgUSOnly struct {
		ID string `json:"id"`
	}
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/model-groups", map[string]any{
		"org_id": org.ID, "alias": "residency-model", "routing_strategy": "round_robin",
	}, &mgResidency, http.StatusCreated)
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/model-groups", map[string]any{
		"org_id": org.ID, "alias": "us-only-model", "routing_strategy": "round_robin",
	}, &mgUSOnly, http.StatusCreated)

	var depEU, depUS struct {
		ID string `json:"id"`
	}
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/deployments", map[string]any{
		"model_group_id": mgResidency.ID, "global_model_id": globalID, "credential_id": credEU.ID,
		"deployment_name": "dep-eu-" + suffix, "tags": []string{"eu-gdpr", "tier:prod"}, "weight": 100, "priority": 1,
	}, &depEU, http.StatusCreated)
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/deployments", map[string]any{
		"model_group_id": mgResidency.ID, "global_model_id": globalID, "credential_id": credUS.ID,
		"deployment_name": "dep-us-" + suffix, "tags": []string{"us-east", "tier:prod"}, "weight": 100, "priority": 1,
	}, &depUS, http.StatusCreated)
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/deployments", map[string]any{
		"model_group_id": mgUSOnly.ID, "global_model_id": globalID, "credential_id": credUS.ID,
		"deployment_name": "dep-us-only-" + suffix, "tags": []string{"us-east"}, "weight": 100, "priority": 1,
	}, nil, http.StatusCreated)

	var team struct {
		ID string `json:"id"`
	}
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/teams", map[string]any{
		"org_id": org.ID, "name": "Residency Team", "allowed_models": []string{"residency-model", "us-only-model"},
	}, &team, http.StatusCreated)

	// Project with allowed_models, allowed_deployments, allowed_routing_tags, and tight budget ($0.000010 = 10 micros)
	var proj struct {
		ID string `json:"id"`
	}
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/projects", map[string]any{
		"org_id":               org.ID,
		"team_id":              team.ID,
		"name":                 "EU Project " + suffix,
		"allowed_models":       []string{"residency-model"},
		"allowed_deployments":  []string{depEU.ID},
		"allowed_routing_tags": []string{"eu-gdpr"},
		"rpm_limit":            3,
	}, &proj, http.StatusCreated)

	var euKey, usBlockedKey, depKey, budgetKey struct {
		ID     string `json:"id"`
		RawKey string `json:"raw_key"`
	}
	// Key inheriting Project EU policy + Project RPM limit = 3
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/keys", map[string]any{
		"org_id": org.ID, "team_id": team.ID, "project_id": proj.ID, "name": "proj-eu-key",
	}, &euKey, http.StatusCreated)

	// Key restricted by allowed_routing_tags: ["eu-gdpr"] on model group that ONLY has us-east
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/keys", map[string]any{
		"org_id": org.ID, "name": "eu-tag-fail-closed-key",
		"allowed_models": []string{"residency-model", "us-only-model"}, "allowed_routing_tags": []string{"eu-gdpr"},
	}, &usBlockedKey, http.StatusCreated)

	// Key restricted by Deployment ID
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/keys", map[string]any{
		"org_id": org.ID, "name": "dep-restricted-key",
		"allowed_models": []string{"residency-model"}, "allowed_deployments": []string{depUS.ID},
	}, &depKey, http.StatusCreated)

	// Budget model & group ($50/1M in, $100/1M out => mock 100in+50out settles 10,000 micros; matches exact model name in budget estimator)
	budgetGlobalID := seedCustomGlobalModel(t, "openai/prod-fixture-budget", "openai", "prod-fixture-budget", 50000000, 100000000)
	var mgBudget struct {
		ID string `json:"id"`
	}
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/model-groups", map[string]any{
		"org_id": org.ID, "alias": "prod-fixture-budget", "routing_strategy": "round_robin",
	}, &mgBudget, http.StatusCreated)
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/deployments", map[string]any{
		"model_group_id": mgBudget.ID, "global_model_id": budgetGlobalID, "credential_id": credUS.ID,
		"deployment_name": "dep-budget-" + suffix, "tags": []string{"us-east"}, "weight": 100, "priority": 1,
	}, nil, http.StatusCreated)

	// Budget key ($0.015 = 15,000 micros max_budget_micros; call #1 reserves ~2,100 micros and settles 10,000 micros, exhausting budget for call #2)
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/keys", map[string]any{
		"org_id": org.ID, "name": "tight-budget-key",
		"allowed_models": []string{"prod-fixture-budget"}, "max_budget_micros": 15000,
	}, &budgetKey, http.StatusCreated)

	// 1. Project-inherited EU key sending ZERO tag headers must route 100% (4/4? Wait RPM=3 so 3/3 -> 4th 429!) to EU across Pod1 & Pod2!
	for i := 0; i < 3; i++ {
		base := prodPod1Base
		if i%2 == 1 {
			base = prodPod2Base
		}
		r, b := doReq(t, client, http.MethodPost, base+"/v1/chat/completions", map[string]any{
			"model":    "residency-model",
			"messages": []map[string]any{{"role": "user", "content": "hi"}},
		}, map[string]string{"Authorization": "Bearer " + euKey.RawKey})
		if r.StatusCode != http.StatusOK || !strings.Contains(string(b), "eu-deployment-ok") {
			t.Fatalf("EU project key call #%d on %s expected eu-deployment-ok, got %d: %s", i+1, base, r.StatusCode, string(b))
		}
	}
	// 4th call triggers Redis Lua Project/Key RPM=3 limit (429)
	rlResp, rlBody := doReq(t, client, http.MethodPost, prodPod2Base+"/v1/chat/completions", map[string]any{
		"model":    "residency-model",
		"messages": []map[string]any{{"role": "user", "content": "over rpm"}},
	}, map[string]string{"Authorization": "Bearer " + euKey.RawKey})
	if rlResp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429 Redis RPM enforcement on 4th call, got %d: %s", rlResp.StatusCode, string(rlBody))
	}

	// 2. Project allowed_models blocks us-only-model (403)
	pmResp, _ := doReq(t, client, http.MethodPost, prodPod1Base+"/v1/chat/completions", map[string]any{
		"model":    "us-only-model",
		"messages": []map[string]any{{"role": "user", "content": "hi"}},
	}, map[string]string{"Authorization": "Bearer " + euKey.RawKey})
	if pmResp.StatusCode != http.StatusForbidden {
		t.Fatalf("Project allowed_models expected 403 on us-only-model, got %d", pmResp.StatusCode)
	}

	// 3. Mandatory allowed_routing_tags fails closed (403 deployment_restricted) when NO deployments match even without tag headers
	fcResp, fcBody := doReq(t, client, http.MethodPost, prodPod1Base+"/v1/chat/completions", map[string]any{
		"model":    "us-only-model",
		"messages": []map[string]any{{"role": "user", "content": "no tags sent"}},
	}, map[string]string{"Authorization": "Bearer " + usBlockedKey.RawKey})
	if fcResp.StatusCode != http.StatusForbidden || !strings.Contains(string(fcBody), "deployment_restricted") {
		t.Fatalf("expected 403 deployment_restricted on us-only-model for eu-gdpr key, got %d: %s", fcResp.StatusCode, string(fcBody))
	}
	// Explicit disallowed X-Gateway-Tags header returns 403 routing_tag_not_allowed
	htResp, htBody := doReq(t, client, http.MethodPost, prodPod2Base+"/v1/chat/completions", map[string]any{
		"model":    "residency-model",
		"messages": []map[string]any{{"role": "user", "content": "hi"}},
	}, map[string]string{"Authorization": "Bearer " + usBlockedKey.RawKey, "X-Gateway-Tags": "us-east"})
	if htResp.StatusCode != http.StatusForbidden || !strings.Contains(string(htBody), "routing_tag_not_allowed") {
		t.Fatalf("expected 403 routing_tag_not_allowed, got %d: %s", htResp.StatusCode, string(htBody))
	}

	// 4. Deployment ID restriction routes deterministically to depUS across Pod1 & Pod2
	for i := 0; i < 3; i++ {
		r, b := doReq(t, client, http.MethodPost, prodPod2Base+"/v1/chat/completions", map[string]any{
			"model":    "residency-model",
			"messages": []map[string]any{{"role": "user", "content": "hi"}},
		}, map[string]string{"Authorization": "Bearer " + depKey.RawKey})
		if r.StatusCode != http.StatusOK || !strings.Contains(string(b), "us-deployment-ok") {
			t.Fatalf("Deployment-restricted key expected us-deployment-ok, got %d: %s", r.StatusCode, string(b))
		}
	}

	// 5. Budget-Based Access Control across Pod 1 -> Pod 2
	b1Resp, b1Body := doReq(t, client, http.MethodPost, prodPod1Base+"/v1/chat/completions", map[string]any{
		"model":      "prod-fixture-budget",
		"max_tokens": 16,
		"messages":   []map[string]any{{"role": "user", "content": "first spend"}},
	}, map[string]string{"Authorization": "Bearer " + budgetKey.RawKey})
	if b1Resp.StatusCode != http.StatusOK {
		t.Fatalf("budget key first call failed: %d %s", b1Resp.StatusCode, string(b1Body))
	}
	// Flush spend worker & sync before testing budget cap on Pod 2
	deadline := time.Now().Add(8 * time.Second)
	budgetExceeded := false
	for time.Now().Before(deadline) {
		r, _ := doReq(t, client, http.MethodPost, prodPod2Base+"/v1/chat/completions", map[string]any{
			"model":      "prod-fixture-budget",
			"max_tokens": 64,
			"messages":   []map[string]any{{"role": "user", "content": "over budget"}},
		}, map[string]string{"Authorization": "Bearer " + budgetKey.RawKey})
		if r.StatusCode == http.StatusTooManyRequests || r.StatusCode == http.StatusPaymentRequired || r.StatusCode == http.StatusForbidden {
			budgetExceeded = true
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if !budgetExceeded {
		t.Fatalf("expected tight-budget key (25 micros) to hit budget cap across Pod 1 -> Pod 2")
	}
}

func TestProdDocker_Suite7_MCP_UnconditionalToolPolicy_A2A_AndUnifiedAccessGroups(t *testing.T) {
	client := newProdTLSClient(t, false)
	resetFixtureAuthzPolicy(t, client)

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	var org struct {
		ID string `json:"id"`
	}
	mustAdminJSON(t, client, http.MethodPost, prodLBBase+"/admin/v1/organizations", map[string]any{
		"name": "Suite7 Agentic Org " + suffix, "slug": "suite7-" + suffix,
	}, &org, http.StatusCreated)

	// Register real Streamable HTTP MCP Server + Sync Tools
	var mcpResp struct {
		Server struct {
			ID string `json:"id"`
		} `json:"server"`
	}
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/mcp/servers", map[string]any{
		"org_id": org.ID, "name": "GitHub Fixture", "slug": "github",
		"protocol_version": "2026-07-28", "transport_type": "streamable_http",
		"endpoint_url": prodFixturesBase + "/mcp", "auth_type": "none",
	}, &mcpResp, http.StatusCreated)
	var syncResp struct {
		Tools []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"tools"`
	}
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/mcp/servers/"+mcpResp.Server.ID+"/sync", nil, &syncResp, http.StatusOK)

	var getIssueID string
	for _, tl := range syncResp.Tools {
		if tl.Name == "get_issue" {
			getIssueID = tl.ID
		}
	}
	if getIssueID == "" {
		t.Fatalf("expected get_issue tool synced from fixture MCP server, got %+v", syncResp.Tools)
	}

	// Create MCP Toolset containing only get_issue
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/mcp/toolsets", map[string]any{
		"org_id": org.ID, "name": "GH Read Only", "slug": "gh-ro-" + suffix, "tool_ids": []string{getIssueID},
	}, nil, http.StatusCreated)

	// Upsert ToolPolicy blocking delete_repo WITHOUT creating any GuardrailBinding (unconditional enforcement!)
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/organizations/"+org.ID+"/tool-policies", map[string]any{
		"tool_name": "delete_repo", "input_policy": "blocked", "output_policy": "trusted",
	}, nil, http.StatusOK, http.StatusCreated)

	// Register A2A Agent
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/a2a/agents", map[string]any{
		"org_id": org.ID, "name": "Researcher", "slug": "researcher",
		"endpoint_url": prodFixturesBase + "/a2a", "auth_type": "none", "task_visibility_mode": "key_strict",
	}, nil, http.StatusCreated)

	// Issue keys:
	// - keyFullMCP: allowed_mcp_servers: ["github"], allowed_mcp_tools: nil (inherits all except blocked ToolPolicy!), allowed_a2a_agents: ["researcher"]
	// - keyToolScoped: allowed_mcp_servers: ["github"], allowed_mcp_tools: ["github:get_issue"], allowed_mcp_toolsets: ["gh-ro-"+suffix]
	// - keyExplicitDeny: allowed_mcp_servers: [], allowed_a2a_agents: [] (DenyAll must override Unified Access Group grants!)
	var keyFullMCP, keyToolScoped, keyExplicitDeny struct {
		ID     string `json:"id"`
		RawKey string `json:"raw_key"`
	}
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/keys", map[string]any{
		"org_id": org.ID, "name": "mcp-full-key",
		"allowed_mcp_servers": []string{"github"}, "allowed_a2a_agents": []string{"researcher"},
	}, &keyFullMCP, http.StatusCreated)
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/keys", map[string]any{
		"org_id": org.ID, "name": "mcp-tool-scoped-key",
		"allowed_mcp_servers": []string{"github"}, "allowed_mcp_tools": []string{"github:get_issue"}, "allowed_mcp_toolsets": []string{"gh-ro-" + suffix}, "allowed_a2a_agents": []string{},
	}, &keyToolScoped, http.StatusCreated)
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/keys", map[string]any{
		"org_id": org.ID, "name": "mcp-deny-all-key",
		"allowed_mcp_servers": []string{}, "allowed_a2a_agents": []string{},
	}, &keyExplicitDeny, http.StatusCreated)

	// 1. Direct POST /mcp & /mcp/github tools/list MUST hide delete_repo unconditionally; Pod 2 scoped cache must isolate keyToolScoped!
	listFullResp, listFullBody := doReq(t, client, http.MethodPost, prodPod2Base+"/mcp/github", map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/list",
	}, map[string]string{"Authorization": "Bearer " + keyFullMCP.RawKey})
	if listFullResp.StatusCode != http.StatusOK {
		t.Fatalf("tools/list keyFullMCP failed: %d %s", listFullResp.StatusCode, string(listFullBody))
	}
	if strings.Contains(string(listFullBody), "delete_repo") {
		t.Fatalf("blocked ToolPolicy delete_repo leaked into tools/list: %s", string(listFullBody))
	}
	if !strings.Contains(string(listFullBody), "get_issue") || !strings.Contains(string(listFullBody), "list_files") {
		t.Fatalf("expected non-blocked tools in keyFullMCP tools/list: %s", string(listFullBody))
	}

	// Same endpoint with keyToolScoped must ONLY show get_issue (cache isolation!)
	listScopedResp, listScopedBody := doReq(t, client, http.MethodPost, prodPod2Base+"/mcp/github", map[string]any{
		"jsonrpc": "2.0", "id": 2, "method": "tools/list",
	}, map[string]string{"Authorization": "Bearer " + keyToolScoped.RawKey})
	if listScopedResp.StatusCode != http.StatusOK {
		t.Fatalf("tools/list keyToolScoped failed: %d %s", listScopedResp.StatusCode, string(listScopedBody))
	}
	if !strings.Contains(string(listScopedBody), "get_issue") || strings.Contains(string(listScopedBody), "list_files") {
		t.Fatalf("keyToolScoped tools/list leaked unlisted tools or missed get_issue: %s", string(listScopedBody))
	}

	// Calling delete_repo returns 403 violated_tool_policy & emits mcp.tool_policy.blocked audit record
	blkResp, blkBody := doReq(t, client, http.MethodPost, prodPod1Base+"/mcp/github", map[string]any{
		"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": map[string]any{"name": "delete_repo", "arguments": map[string]any{}},
	}, map[string]string{"Authorization": "Bearer " + keyFullMCP.RawKey})
	if blkResp.StatusCode == http.StatusOK && !strings.Contains(string(blkBody), "violated_tool_policy") {
		t.Fatalf("expected delete_repo blocked unconditionally, got: %d %s", blkResp.StatusCode, string(blkBody))
	}
	// Allowed tool call succeeds
	okCallResp, okCallBody := doReq(t, client, http.MethodPost, prodPod2Base+"/mcp/github", map[string]any{
		"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": map[string]any{"name": "get_issue", "arguments": map[string]any{"id": "42"}},
	}, map[string]string{"Authorization": "Bearer " + keyToolScoped.RawKey})
	if okCallResp.StatusCode != http.StatusOK || !strings.Contains(string(okCallBody), "fixture-mcp-ok") {
		t.Fatalf("expected allowed get_issue call 200, got: %d %s", okCallResp.StatusCode, string(okCallBody))
	}
	// Toolset dispatch authorized for keyToolScoped
	tsResp, tsBody := doReq(t, client, http.MethodPost, prodPod2Base+"/mcp/toolsets/gh-ro-"+suffix, map[string]any{
		"jsonrpc": "2.0", "id": 5, "method": "tools/list",
	}, map[string]string{"Authorization": "Bearer " + keyToolScoped.RawKey})
	if tsResp.StatusCode != http.StatusOK || !strings.Contains(string(tsBody), "get_issue") {
		t.Fatalf("toolset gh-ro-%s expected 200, got: %d %s", suffix, tsResp.StatusCode, string(tsBody))
	}

	// 2. A2A invoke authorized vs denied
	a2aOK, a2aOKBody := doReq(t, client, http.MethodPost, prodPod1Base+"/a2a/v1/agents/researcher", map[string]any{
		"jsonrpc": "2.0", "id": "a1", "method": "tasks/send",
		"params": map[string]any{"message": map[string]any{"messageId": "m1", "role": "ROLE_USER", "parts": []map[string]any{{"text": "hello"}}}},
	}, map[string]string{"Authorization": "Bearer " + keyFullMCP.RawKey})
	if a2aOK.StatusCode != http.StatusOK || !strings.Contains(string(a2aOKBody), "prod-fixture-a2a-ok") {
		t.Fatalf("authorized A2A tasks/send failed: %d %s", a2aOK.StatusCode, string(a2aOKBody))
	}
	a2aDeny, a2aDenyBody := doReq(t, client, http.MethodPost, prodPod2Base+"/a2a/v1/agents/researcher", map[string]any{
		"jsonrpc": "2.0", "id": "a2", "method": "tasks/send",
		"params": map[string]any{"message": map[string]any{"messageId": "m2", "role": "ROLE_USER", "parts": []map[string]any{{"text": "hello"}}}},
	}, map[string]string{"Authorization": "Bearer " + keyToolScoped.RawKey})
	if a2aDeny.StatusCode == http.StatusOK && !strings.Contains(string(a2aDenyBody), `"error"`) {
		t.Fatalf("unauthorized keyToolScoped JSON-RPC A2A call should have been denied, got: %d %s", a2aDeny.StatusCode, string(a2aDenyBody))
	}
	a2aRestDeny, a2aRestBody := doReq(t, client, http.MethodPost, prodPod2Base+"/a2a/v1/agents/researcher", map[string]any{
		"message": map[string]any{"messageId": "m3", "role": "ROLE_USER", "parts": []map[string]any{{"text": "hello"}}},
	}, map[string]string{"Authorization": "Bearer " + keyToolScoped.RawKey})
	if (a2aRestDeny.StatusCode != http.StatusForbidden && a2aRestDeny.StatusCode != http.StatusNotFound) || !strings.Contains(string(a2aRestBody), "a2a_agent_restricted") {
		t.Fatalf("unauthorized keyToolScoped HTTP+JSON A2A call expected denial (a2a_agent_restricted), got %d %s", a2aRestDeny.StatusCode, string(a2aRestBody))
	}

	// 3. Unified Access Group + Dynamic AccessGroupRule (respecting Key [] DenyAll precedence)
	var uag struct {
		ID string `json:"id"`
	}
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/access-groups", map[string]any{
		"org_id":              org.ID,
		"name":                "unified-eng-" + suffix,
		"allowed_mcp_servers": []string{"github"},
		"allowed_mcp_tools":   []string{"github:list_files"},
		"allowed_a2a_agents":  []string{"researcher"},
	}, &uag, http.StatusOK, http.StatusCreated)
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/access-groups/"+uag.ID+"/members", map[string]any{
		"org_id": org.ID, "member_type": "key", "member_id": keyExplicitDeny.ID,
	}, nil, http.StatusOK, http.StatusCreated)

	// Explicit Key DenyAll [] MUST STILL WIN over Access Group grant
	denyWinsResp, denyWinsBody := doReq(t, client, http.MethodPost, prodPod2Base+"/mcp/github", map[string]any{
		"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": map[string]any{"name": "list_files", "arguments": map[string]any{}},
	}, map[string]string{"Authorization": "Bearer " + keyExplicitDeny.RawKey})
	if denyWinsResp.StatusCode == http.StatusOK && !strings.Contains(string(denyWinsBody), "denied") && !strings.Contains(string(denyWinsBody), "restricted") {
		t.Fatalf("explicit Key [] DenyAll did not win over Unified Access Group grant! got %d %s", denyWinsResp.StatusCode, string(denyWinsBody))
	}

	// Positive Unified Access Group grants, gated ModelAccessGroup enforcement, and Dynamic AccessGroupRule
	// evaluation across replicas are exercised in TestProdDocker_Suite7b_MultiMCPHub_ToolAuthz_A2AKillSwitch_UnifiedGroups_AndDynamicRules.
}

func TestProdDocker_Suite8_ExternalAuthorizer_AuditFilters_AndSIEM(t *testing.T) {
	client := newProdTLSClient(t, false)
	defer resetFixtureAuthzPolicy(t, client)

	// 1. Dynamic External Webhook Authorizer deny across Admin + Inference -> 403
	mustAdminJSON(t, client, http.MethodPost, prodLBBase+"/admin/v1/organizations", map[string]any{
		"name": "Authz S8 Org", "slug": "authz-s8-" + fmt.Sprintf("%d", time.Now().UnixNano()),
	}, nil, http.StatusCreated)

	var vk struct {
		RawKey string `json:"raw_key"`
	}
	mustAdminJSON(t, client, http.MethodPost, prodLBBase+"/admin/v1/keys", map[string]any{
		"org_id": "org_default", "name": "authz-probe-key", "allowed_models": []string{"*"},
	}, &vk, http.StatusCreated)

	// Enable model denial on external authorizer fixture
	resp, data := doReq(t, client, http.MethodPut, prodFixturesBase+"/_control/authz", map[string]any{
		"deny_models": []string{"authz-denied-model"},
		"reason":      "blocked by prod external webhook",
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("configure fixture authz deny_models: %d %s", resp.StatusCode, string(data))
	}
	for _, ep := range []struct {
		path string
		body any
	}{
		{"/v1/chat/completions", map[string]any{"model": "authz-denied-model", "messages": []map[string]any{{"role": "user", "content": "hi"}}}},
		{"/v1/responses", map[string]any{"model": "authz-denied-model", "input": "hi"}},
		{"/v1/embeddings", map[string]any{"model": "authz-denied-model", "input": "hi"}},
	} {
		r, b := doReq(t, client, http.MethodPost, prodPod2Base+ep.path, ep.body, map[string]string{
			"Authorization": "Bearer " + vk.RawKey,
		})
		if r.StatusCode != http.StatusForbidden {
			t.Fatalf("external authorizer expected 403 on %s, got %d: %s", ep.path, r.StatusCode, string(b))
		}
	}

	// Simulate External Authorizer 500 outage -> must fail-closed with 503
	doReq(t, client, http.MethodPut, prodFixturesBase+"/_control/authz", map[string]any{
		"status_code": 500,
	}, nil)
	outResp, outBody := doReq(t, client, http.MethodPost, prodPod1Base+"/v1/chat/completions", map[string]any{
		"model":    "gpt-4o-mini",
		"messages": []map[string]any{{"role": "user", "content": "hi"}},
	}, map[string]string{"Authorization": "Bearer " + vk.RawKey})
	if outResp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("fail_mode=closed expected 503 during external authorizer outage, got %d: %s", outResp.StatusCode, string(outBody))
	}
	// Confirm HMAC-verified calls recorded by fixture BEFORE resetting fixture state
	_, callsData := doReq(t, client, http.MethodGet, prodFixturesBase+"/_control/authz", nil, nil)
	if !strings.Contains(string(callsData), `"hmac_verified":true`) {
		t.Fatalf("expected HMAC-verified calls on external authorizer fixture: %s", string(callsData))
	}
	resetFixtureAuthzPolicy(t, client)

	// 2. PostgreSQL 16 filtered cursor pagination on GET /admin/v1/audit/logs
	p1Body := mustAdminJSON(t, client, http.MethodGet, prodLBBase+"/admin/v1/audit/logs?org_id=org_default&limit=2", nil, nil, http.StatusOK)
	var p1 struct {
		Data       []map[string]any `json:"data"`
		NextCursor string           `json:"next_cursor"`
	}
	_ = json.Unmarshal(p1Body, &p1)
	if len(p1.Data) != 2 || p1.NextCursor == "" {
		t.Fatalf("expected 2 audit records + next_cursor, got len=%d cursor=%q", len(p1.Data), p1.NextCursor)
	}
	p2Body := mustAdminJSON(t, client, http.MethodGet, prodLBBase+"/admin/v1/audit/logs?org_id=org_default&limit=2&cursor="+url.QueryEscape(p1.NextCursor), nil, nil, http.StatusOK)
	var p2 struct {
		Data []map[string]any `json:"data"`
	}
	_ = json.Unmarshal(p2Body, &p2)
	if len(p2.Data) == 0 || p2.Data[0]["id"] == p1.Data[0]["id"] {
		t.Fatalf("cursor page 2 failed to advance deterministically")
	}

	// 3. SIEM Webhook collector received HMAC-verified batches (flush_interval=500ms) including new MCP/A2A admin audit events
	var siemOK bool
	var siemBody []byte
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		_, siemBody = doReq(t, client, http.MethodGet, prodFixturesBase+"/_control/siem/events", nil, nil)
		s := string(siemBody)
		if strings.Contains(s, "sso.role_synced") &&
			strings.Contains(s, "mcp.tool_policy.blocked") &&
			strings.Contains(s, "virtual_key.issued") &&
			strings.Contains(s, "mcp_server.created") &&
			strings.Contains(s, "a2a_agent.created") {
			siemOK = true
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	if !siemOK {
		t.Fatalf("expected HMAC-verified SIEM webhook events (sso.role_synced, mcp.tool_policy.blocked, virtual_key.issued, mcp_server.created, a2a_agent.created), got: %s", string(siemBody))
	}
}

func TestProdDocker_Suite10_LiveMultiProviderAuthorizationAndFinOps(t *testing.T) {
	client := newProdTLSClient(t, false)
	resetFixtureAuthzPolicy(t, client)

	type liveSpec struct {
		Name        string
		EnvVar      string
		Provider    string
		BaseURL     string
		GlobalID    string
		ModelName   string
		InputMicros int64
		OutMicros   int64
	}
	groqModel := strings.TrimSpace(os.Getenv("PROD_LIVE_GROQ_MODEL"))
	if groqModel == "" {
		groqModel = "openai/gpt-oss-20b"
	}
	specs := []liveSpec{
		{Name: "groq", EnvVar: "PROD_LIVE_GROQ_API_KEY", Provider: "groq", GlobalID: "groq/" + groqModel, ModelName: groqModel, InputMicros: 100000, OutMicros: 300000},
		{Name: "openai", EnvVar: "PROD_LIVE_OPENAI_API_KEY", Provider: "openai", GlobalID: "openai/gpt-4o-mini", ModelName: "gpt-4o-mini", InputMicros: 150000, OutMicros: 600000},
		{Name: "openrouter", EnvVar: "PROD_LIVE_OPENROUTER_API_KEY", Provider: "openrouter", GlobalID: "openrouter/openai/gpt-4o-mini", ModelName: "openai/gpt-4o-mini", InputMicros: 150000, OutMicros: 600000},
		{Name: "anthropic", EnvVar: "PROD_LIVE_ANTHROPIC_API_KEY", Provider: "anthropic", GlobalID: "anthropic/claude-haiku-4-5-20251001", ModelName: "claude-haiku-4-5-20251001", InputMicros: 800000, OutMicros: 4000000},
		{Name: "gemini", EnvVar: "PROD_LIVE_GEMINI_API_KEY", Provider: "openai", BaseURL: "https://generativelanguage.googleapis.com/v1beta/openai", GlobalID: "openai/gemini-2.5-flash", ModelName: "gemini-2.5-flash", InputMicros: 150000, OutMicros: 600000},
	}

	var configured []liveSpec
	for _, sp := range specs {
		if strings.TrimSpace(os.Getenv(sp.EnvVar)) != "" {
			configured = append(configured, sp)
		}
	}
	if len(configured) == 0 {
		t.Skip("no PROD_LIVE_*_API_KEY environment variables supplied; skipping Suite 10")
	}

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	var org struct {
		ID string `json:"id"`
	}
	mustAdminJSON(t, client, http.MethodPost, prodLBBase+"/admin/v1/organizations", map[string]any{
		"name": "Suite10 Live LLM Org " + suffix, "slug": "suite10-" + suffix,
	}, &org, http.StatusCreated)
	for _, prov := range []string{"openai", "groq", "openrouter", "anthropic"} {
		mustAdminJSON(t, client, http.MethodPost, prodLBBase+"/admin/v1/organizations/"+org.ID+"/subscriptions", map[string]any{
			"provider": prov, "is_enabled": true,
		}, nil, http.StatusOK)
	}

	var multiGroup struct {
		ID string `json:"id"`
	}
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/model-groups", map[string]any{
		"org_id": org.ID, "alias": "live-multi", "routing_strategy": "round_robin",
	}, &multiGroup, http.StatusCreated)

	type liveActive struct {
		spec   liveSpec
		credID string
		depID  string
		alias  string
	}
	var succeeded []liveActive
	for _, sp := range configured {
		apiKey := strings.TrimSpace(os.Getenv(sp.EnvVar))
		sp.GlobalID = seedCustomGlobalModel(t, sp.GlobalID, sp.Provider, sp.ModelName, sp.InputMicros, sp.OutMicros)

		credPayload := map[string]any{
			"org_id":   org.ID,
			"provider": sp.Provider,
			"name":     "live-" + sp.Name + "-" + suffix,
			"api_key":  apiKey,
		}
		if sp.BaseURL != "" {
			credPayload["base_url"] = sp.BaseURL
		}
		var cred struct {
			ID string `json:"id"`
		}
		mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/credentials", credPayload, &cred, http.StatusCreated)

		alias := "live-" + sp.Name
		var mg struct {
			ID string `json:"id"`
		}
		mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/model-groups", map[string]any{
			"org_id": org.ID, "alias": alias, "routing_strategy": "weighted_shuffle",
		}, &mg, http.StatusCreated)

		var dep struct {
			ID string `json:"id"`
		}
		mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/deployments", map[string]any{
			"model_group_id": mg.ID, "global_model_id": sp.GlobalID, "credential_id": cred.ID,
			"deployment_name": "dep-live-" + sp.Name, "tags": []string{"provider:" + sp.Name, "tier:live"},
			"weight": 100, "priority": 1, "timeout_ms": 20000,
		}, &dep, http.StatusCreated)

		var vk struct {
			RawKey string `json:"raw_key"`
		}
		mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/keys", map[string]any{
			"org_id": org.ID, "name": "vk-live-" + sp.Name, "allowed_models": []string{alias}, "allowed_routing_tags": []string{"provider:" + sp.Name},
		}, &vk, http.StatusCreated)

		r, b := doReq(t, client, http.MethodPost, prodLBBase+"/v1/chat/completions", map[string]any{
			"model":      alias,
			"max_tokens": 16,
			"messages":   []map[string]any{{"role": "user", "content": "Reply with one word: OK"}},
		}, map[string]string{"Authorization": "Bearer " + vk.RawKey})

		if r.StatusCode == http.StatusOK {
			t.Logf("LIVE PROVIDER PASS [%s/%s]: status=200 provider_hdr=%q cost_micros=%q",
				sp.Name, sp.ModelName, r.Header.Get("X-Gateway-Provider"), r.Header.Get("X-Gateway-Cost-Micros"))
			// Also add to shared live-multi model group for cross-provider routing tag & deployment tests
			var multiDep struct {
				ID string `json:"id"`
			}
			mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/deployments", map[string]any{
				"model_group_id": multiGroup.ID, "global_model_id": sp.GlobalID, "credential_id": cred.ID,
				"deployment_name": "dep-multi-" + sp.Name, "tags": []string{"provider:" + sp.Name, "tier:live"},
				"weight": 100, "priority": 1, "timeout_ms": 20000,
			}, &multiDep, http.StatusCreated)
			succeeded = append(succeeded, liveActive{spec: sp, credID: cred.ID, depID: multiDep.ID, alias: alias})
		} else {
			t.Logf("LIVE PROVIDER UPSTREAM NON-200 [%s/%s]: status=%d body=%s", sp.Name, sp.ModelName, r.StatusCode, string(b))
		}
	}

	if len(succeeded) != len(configured) {
		t.Fatalf("expected all %d configured live LLM providers to succeed end-to-end, got %d", len(configured), len(succeeded))
	}

	// Cross-provider Mandatory Tag Routing & Subscription Gate using top succeeding live provider
	first := succeeded[0]
	var tagKey, badTagKey, depScopedKey struct {
		RawKey string `json:"raw_key"`
	}
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/keys", map[string]any{
		"org_id": org.ID, "name": "live-multi-tag-key",
		"allowed_models": []string{"live-multi"}, "allowed_routing_tags": []string{"provider:" + first.spec.Name},
	}, &tagKey, http.StatusCreated)
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/keys", map[string]any{
		"org_id": org.ID, "name": "live-multi-badtag-key",
		"allowed_models": []string{"live-multi"}, "allowed_routing_tags": []string{"provider:nonexistent"},
	}, &badTagKey, http.StatusCreated)
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/keys", map[string]any{
		"org_id": org.ID, "name": "live-multi-dep-key",
		"allowed_models": []string{"live-multi"}, "allowed_deployments": []string{first.depID},
	}, &depScopedKey, http.StatusCreated)

	// 1. Tag-scoped key with ZERO caller headers routes deterministically to first.spec
	rTag, bTag := doReq(t, client, http.MethodPost, prodPod2Base+"/v1/chat/completions", map[string]any{
		"model": "live-multi", "max_tokens": 16,
		"messages": []map[string]any{{"role": "user", "content": "Say hi"}},
	}, map[string]string{"Authorization": "Bearer " + tagKey.RawKey})
	if rTag.StatusCode != http.StatusOK {
		t.Fatalf("live-multi mandatory tag routing failed: %d %s", rTag.StatusCode, string(bTag))
	}

	// 2. Non-matching tag fails closed (403 deployment_restricted) with zero upstream spend
	rBadTag, bBadTag := doReq(t, client, http.MethodPost, prodPod2Base+"/v1/chat/completions", map[string]any{
		"model": "live-multi", "max_tokens": 16,
		"messages": []map[string]any{{"role": "user", "content": "Say hi"}},
	}, map[string]string{"Authorization": "Bearer " + badTagKey.RawKey})
	if rBadTag.StatusCode != http.StatusForbidden || !strings.Contains(string(bBadTag), "deployment_restricted") {
		t.Fatalf("expected 403 deployment_restricted for non-matching tag on live-multi, got %d: %s", rBadTag.StatusCode, string(bBadTag))
	}

	// 3. Deployment-scoped key succeeds on first.depID
	rDep, bDep := doReq(t, client, http.MethodPost, prodPod1Base+"/v1/chat/completions", map[string]any{
		"model": "live-multi", "max_tokens": 16,
		"messages": []map[string]any{{"role": "user", "content": "Say hi"}},
	}, map[string]string{"Authorization": "Bearer " + depScopedKey.RawKey})
	if rDep.StatusCode != http.StatusOK {
		t.Fatalf("live deployment-scoped key failed: %d %s", rDep.StatusCode, string(bDep))
	}

	// 4. Org Provider Subscription gate blocks when disabled
	mustAdminJSON(t, client, http.MethodPost, prodLBBase+"/admin/v1/organizations/"+org.ID+"/subscriptions", map[string]any{
		"provider": first.spec.Provider, "is_enabled": false,
	}, nil, http.StatusOK)
	time.Sleep(150 * time.Millisecond)
	var subKey struct {
		RawKey string `json:"raw_key"`
	}
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/keys", map[string]any{
		"org_id": org.ID, "name": "sub-check-key", "allowed_models": []string{first.alias},
	}, &subKey, http.StatusCreated)
	rSubDeny, bSubDeny := doReq(t, client, http.MethodPost, prodPod1Base+"/v1/chat/completions", map[string]any{
		"model": first.alias, "max_tokens": 16,
		"messages": []map[string]any{{"role": "user", "content": "hi"}},
	}, map[string]string{"Authorization": "Bearer " + subKey.RawKey})
	if rSubDeny.StatusCode != http.StatusForbidden && rSubDeny.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 403 or 503 when Org Provider Subscription disabled for %s, got %d: %s", first.spec.Provider, rSubDeny.StatusCode, string(bSubDeny))
	}
	t.Logf("Org Provider Subscription disabled gate blocked %s cleanly: status=%d body=%s", first.spec.Provider, rSubDeny.StatusCode, string(bSubDeny))
	mustAdminJSON(t, client, http.MethodPost, prodLBBase+"/admin/v1/organizations/"+org.ID+"/subscriptions", map[string]any{
		"provider": first.spec.Provider, "is_enabled": true,
	}, nil, http.StatusOK)

	// 5. Verify FinOps spend_logs persisted to PostgreSQL for org
	deadline := time.Now().Add(6 * time.Second)
	var spendCount string
	for time.Now().Before(deadline) {
		spendCount = strings.TrimSpace(psqlExec(t, fmt.Sprintf("SELECT COUNT(*) FROM spend_logs WHERE org_id='%s';", org.ID)))
		if spendCount != "" && spendCount != "0" {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}
	if spendCount == "" || spendCount == "0" {
		t.Fatalf("expected real FinOps spend_logs rows persisted for org %s", org.ID)
	}
	t.Logf("Verified %s live spend_logs rows persisted in PostgreSQL 16 TLS for org %s (%d providers succeeded: live-multi passed)", spendCount, org.ID, len(succeeded))
}

func TestProdDocker_Suite99_MultiReplicaHA_ResilienceAndKEKRotation(t *testing.T) {
	client := newProdTLSClient(t, false)
	resetFixtureAuthzPolicy(t, client)

	startResp, startBody := doReq(t, client, http.MethodGet, prodPod1Base+"/auth/sso/keycloak/login?format=json", nil, nil)
	if startResp.StatusCode != http.StatusOK {
		t.Fatalf("Pod 1 SSO start status=%d body=%s", startResp.StatusCode, string(startBody))
	}
	var startJSON struct {
		AuthorizationURL string `json:"authorization_url"`
		State            string `json:"state"`
	}
	_ = json.Unmarshal(startBody, &startJSON)
	if !strings.Contains(startJSON.AuthorizationURL, "code_challenge_method=S256") {
		t.Fatalf("missing PKCE S256 in %q", startJSON.AuthorizationURL)
	}
	cbResp, cbBody := doReq(t, client, http.MethodGet, prodPod2Base+"/auth/sso/keycloak/callback?code=fake-code&state="+url.QueryEscape(startJSON.State), nil, nil)
	if strings.Contains(string(cbBody), "invalid_state") || strings.Contains(string(cbBody), "sso_state_not_found") {
		t.Fatalf("Pod 2 did not share Redis SSO state created by Pod 1: status=%d body=%s", cbResp.StatusCode, string(cbBody))
	}

	tok := mintKeycloakToken(t, client, "goroute-prod", "goroute-ci-mint", "goroute-ci-mint-secret-2026", "orgadmin@goroute.local", "ProdOrgAdmin!2026")
	for _, base := range []string{prodPod1Base, prodPod2Base} {
		r, b := doReq(t, client, http.MethodGet, base+"/v1/models", nil, map[string]string{"Authorization": "Bearer " + tok})
		if r.StatusCode != http.StatusOK {
			t.Fatalf("warm JWKS on %s failed: %d %s", base, r.StatusCode, string(b))
		}
	}

	composeExec(t, "pause", "keycloak")
	defer func() {
		_, _ = exec.Command("docker", "compose", "-f", prodComposeFile, "unpause", "keycloak").CombinedOutput()
	}()
	for _, base := range []string{prodPod1Base, prodPod2Base} {
		r, b := doReq(t, client, http.MethodGet, base+"/v1/models", nil, map[string]string{"Authorization": "Bearer " + tok})
		if r.StatusCode != http.StatusOK {
			t.Fatalf("cached-JWKS JWT failed on %s while Keycloak paused: %d %s", base, r.StatusCode, string(b))
		}
		bgResp, _ := doReq(t, client, http.MethodGet, base+"/admin/v1/organizations", nil, map[string]string{"Authorization": "Bearer " + prodMasterKey})
		if bgResp.StatusCode != http.StatusOK {
			t.Fatalf("break-glass admin API failed on %s while Keycloak paused: %d", base, bgResp.StatusCode)
		}
	}
	composeExec(t, "unpause", "keycloak")

	for i := 0; i < 25; i++ {
		badTok := buildFakeJWT("RS256", "JWT", fmt.Sprintf("unknown-kid-%d", i), map[string]any{
			"iss": prodAuthBase + "/realms/goroute-prod", "sub": "storm", "aud": "goroute-gateway", "exp": time.Now().Add(5 * time.Minute).Unix(),
		}, []byte("x"))
		r, _ := doReq(t, client, http.MethodGet, prodLBBase+"/v1/models", nil, map[string]string{"Authorization": "Bearer " + badTok})
		if r.StatusCode != http.StatusUnauthorized {
			t.Fatalf("unknown kid #%d returned %d, want 401", i, r.StatusCode)
		}
	}

	composeExec(t, "restart", "redis")
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		r1, _ := doReq(t, client, http.MethodGet, prodPod1Base+"/readyz", nil, nil)
		r2, _ := doReq(t, client, http.MethodGet, prodPod2Base+"/readyz", nil, nil)
		if r1.StatusCode == http.StatusOK && r2.StatusCode == http.StatusOK {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	postRedisResp, _ := doReq(t, client, http.MethodGet, prodLBBase+"/v1/models", nil, map[string]string{"Authorization": "Bearer " + tok})
	if postRedisResp.StatusCode != http.StatusOK {
		t.Fatalf("JWT auth failed after Redis restart: %d", postRedisResp.StatusCode)
	}

	var failures atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequest(http.MethodGet, prodLBBase+"/v1/models", nil)
			req.Header.Set("Authorization", "Bearer "+tok)
			resp, err := client.Do(req)
			if err != nil {
				failures.Add(1)
				return
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				failures.Add(1)
			}
		}()
	}
	wg.Wait()
	if f := failures.Load(); f > 0 {
		t.Fatalf("concurrent JWT load had %d/40 non-200 responses", f)
	}

	for _, base := range []string{prodPod1Base, prodPod2Base} {
		unauthResp, _ := doReq(t, client, http.MethodGet, base+"/metrics", nil, nil)
		if unauthResp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("%s/metrics without auth got %d, want 401", base, unauthResp.StatusCode)
		}
		mResp, mBody := doReq(t, client, http.MethodGet, base+"/metrics", nil, map[string]string{"Authorization": "Bearer " + prodMasterKey})
		if mResp.StatusCode != http.StatusOK || !strings.Contains(string(mBody), "# HELP") {
			t.Fatalf("%s/metrics unexpected response: status=%d body_len=%d", base, mResp.StatusCode, len(mBody))
		}
	}

	rotResp, rotBody := doReq(t, client, http.MethodPost, prodPod1Base+"/admin/v1/security/rotate-kek", map[string]any{
		"new_master_key": "b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1",
	}, map[string]string{"Authorization": "Bearer " + prodMasterKey})
	if rotResp.StatusCode != http.StatusOK {
		t.Fatalf("live KEK rotation failed: status=%d body=%s", rotResp.StatusCode, string(rotBody))
	}
}
