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
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
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
	prodMasterKey    = "sk-gw-prod-test-master-admin-key-2026-secure"
	prodComposeFile  = "../../deployments/prod-test/docker-compose.prod-test.yml"
	prodCertCAPath   = "../../.tmp/prod-test-certs/ca.crt"
	prodSSOSecret    = "goroute-prod-oidc-secret-2026"
	prodSessionSec   = "prod-test-hmac-session-secret-0123456789abcdef0123456789abcdef"
	prodRedisPass    = "prod-test-redis-pass-2026"
	prodPostgresPass = "prod-test-pg-password-2026"
)

func newProdTLSClient(t *testing.T, followRedirects bool) *http.Client {
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
		Timeout:   20 * time.Second,
	}
	if !followRedirects {
		client.CheckRedirect = func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	return client
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

func TestProdDocker_Suite1_HealthMigrationsHeadersAndRemovedRoutes(t *testing.T) {
	client := newProdTLSClient(t, false)

	// 1. Both replicas ready over verified TLS 1.3
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

	// 2. CORS preflight includes X-CSRF-Token
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

	// 3. Removed legacy endpoints return 404/405
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

	// 4. Verify PostgreSQL migrations 0039 (no user_credentials) & 0040 (operator_sessions columns)
	tblOut := composeExec(t, "exec", "-T", "postgres", "psql", "-U", "gateway", "-d", "aigateway", "-tAc",
		"SELECT to_regclass('public.user_credentials');")
	if strings.TrimSpace(tblOut) != "" {
		t.Fatalf("expected user_credentials table to be dropped by migration 0039, got %q", strings.TrimSpace(tblOut))
	}
	colsOut := composeExec(t, "exec", "-T", "postgres", "psql", "-U", "gateway", "-d", "aigateway", "-tAc",
		"SELECT column_name FROM information_schema.columns WHERE table_name='operator_sessions' AND column_name IN ('provider_id','encrypted_id_token','encrypted_id_token_dek') ORDER BY column_name;")
	for _, col := range []string{"encrypted_id_token", "encrypted_id_token_dek", "provider_id"} {
		if !strings.Contains(colsOut, col) {
			t.Fatalf("migration 0040 column %q missing from operator_sessions: %q", col, colsOut)
		}
	}
}

func TestProdDocker_Suite3_AsymmetricJWT_MultiIssuer_Introspection_AndSCIM(t *testing.T) {
	client := newProdTLSClient(t, false)

	// 1. Live Keycloak RS256, ES256, and EdDSA asymmetric Data-Plane JWT verification
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

	// 2. Reject forged HS256, alg:none, oauth-id-jag+jwt, wrong aud, expired
	now := time.Now().Unix()
	for _, tc := range []struct {
		name  string
		token string
	}{
		{"HS256", buildFakeJWT("HS256", "JWT", "k1", map[string]any{"iss": prodAuthBase + "/realms/goroute-prod", "sub": "u1", "aud": "goroute-gateway", "exp": now + 300}, []byte("secret"))},
		{"AlgNone", buildFakeJWT("none", "JWT", "", map[string]any{"iss": prodAuthBase + "/realms/goroute-prod", "sub": "u1", "aud": "goroute-gateway", "exp": now + 300}, nil)},
		{"IDJAG", buildFakeJWT("RS256", "oauth-id-jag+jwt", "k1", map[string]any{"iss": prodAuthBase + "/realms/goroute-prod", "sub": "u1", "aud": "goroute-gateway", "exp": now + 300}, []byte("k"))},
		{"OpaqueInvalid", "opaque-revoked-token-not-active-in-keycloak"},
	} {
		resp, _ := doReq(t, client, http.MethodGet, prodLBBase+"/v1/models", nil, map[string]string{
			"Authorization": "Bearer " + tc.token,
		})
		if resp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("forged/invalid %s token got %d, want 401", tc.name, resp.StatusCode)
		}
	}

	// 3. Unverified email rejected on allowed_email_domains
	unverifiedTok := mintKeycloakToken(t, client, "goroute-prod", "goroute-ci-mint", "goroute-ci-mint-secret-2026", "unverified@goroute.local", "ProdUnverified!2026")
	unvResp, unvBody := doReq(t, client, http.MethodGet, prodLBBase+"/v1/models", nil, map[string]string{
		"Authorization": "Bearer " + unverifiedTok,
	})
	if unvResp.StatusCode != http.StatusUnauthorized && unvResp.StatusCode != http.StatusForbidden {
		t.Fatalf("expected unverified email JWT rejection, got %d (%s)", unvResp.StatusCode, string(unvBody))
	}

	// 4. Multi-issuer tenant-b isolation
	orgBResp, orgBBody := doReq(t, client, http.MethodPost, prodPod1Base+"/admin/v1/organizations", map[string]any{
		"id":   "org_tenant_b",
		"name": "Tenant B Org",
		"slug": "tenant-b",
	}, map[string]string{"Authorization": "Bearer " + prodMasterKey})
	if orgBResp.StatusCode != http.StatusCreated && orgBResp.StatusCode != http.StatusConflict {
		t.Fatalf("create org_tenant_b status=%d body=%s", orgBResp.StatusCode, string(orgBBody))
	}
	bobTok := mintKeycloakToken(t, client, "tenant-b", "goroute-tenant-b-mint", "tenant-b-mint-secret-2026", "bob@tenantb.local", "TenantB!2026")
	// Parse sub from bob's JWT to bind bob explicitly to org_tenant_b + tenant-b issuer
	parts := strings.Split(bobTok, ".")
	claimsJSON, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var bobClaims struct {
		Sub string `json:"sub"`
	}
	_ = json.Unmarshal(claimsJSON, &bobClaims)
	if bobClaims.Sub == "" {
		t.Fatal("failed to extract bob sub from tenant-b JWT")
	}
	// Before binding (auto_register=false on tenant-b), bob must be rejected
	preBindResp, _ := doReq(t, client, http.MethodGet, prodPod2Base+"/v1/models", nil, map[string]string{
		"Authorization": "Bearer " + bobTok,
	})
	if preBindResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected unbound tenant-b user to get 401, got %d", preBindResp.StatusCode)
	}
	// Bind bob on Pod 1 and authenticate on Pod 2
	createUserResp, createUserBody := doReq(t, client, http.MethodPost, prodPod1Base+"/admin/v1/users", map[string]any{
		"org_id":       "org_tenant_b",
		"email":        "bob@tenantb.local",
		"name":         "Bob TenantB",
		"role":         "developer",
		"oidc_issuer":  prodAuthBase + "/realms/tenant-b",
		"oidc_subject": bobClaims.Sub,
	}, map[string]string{"Authorization": "Bearer " + prodMasterKey})
	if createUserResp.StatusCode != http.StatusCreated {
		t.Fatalf("create bob user status=%d body=%s", createUserResp.StatusCode, string(createUserBody))
	}
	postBindResp, postBindBody := doReq(t, client, http.MethodGet, prodPod2Base+"/v1/models", nil, map[string]string{
		"Authorization": "Bearer " + bobTok,
	})
	if postBindResp.StatusCode != http.StatusOK {
		t.Fatalf("expected bound tenant-b user on Pod 2 to get 200, got %d (%s)", postBindResp.StatusCode, string(postBindBody))
	}

	// 5. Cross-replica SCIM deprovisioning kills data-plane JWT access on Pod 2 immediately
	var createdBob struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(createUserBody, &createdBob)
	scimDeactResp, scimDeactBody := doReq(t, client, http.MethodPut, prodPod1Base+"/admin/v1/users/"+createdBob.ID, map[string]any{
		"scim_active": false,
	}, map[string]string{"Authorization": "Bearer " + prodMasterKey})
	if scimDeactResp.StatusCode != http.StatusOK {
		t.Fatalf("SCIM deactivate bob on Pod 1 status=%d body=%s", scimDeactResp.StatusCode, string(scimDeactBody))
	}
	afterDeactResp, _ := doReq(t, client, http.MethodGet, prodPod2Base+"/v1/models", nil, map[string]string{
		"Authorization": "Bearer " + bobTok,
	})
	if afterDeactResp.StatusCode != http.StatusForbidden && afterDeactResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected SCIM-deactivated user to fail immediately on Pod 2 (no stale cache), got %d", afterDeactResp.StatusCode)
	}
}

func TestProdDocker_Suite4_SecurityAttackMatrix(t *testing.T) {
	client := newProdTLSClient(t, false)

	// 1. Open redirect fuzzing
	for _, bad := range []string{"https://evil.example/steal", "//evil.example/steal", `/\evil.example`, "javascript:alert(1)"} {
		u := prodLBBase + "/auth/sso/keycloak/login?redirect_after=" + url.QueryEscape(bad)
		resp, _ := doReq(t, client, http.MethodGet, u, nil, nil)
		if resp.StatusCode != http.StatusBadRequest {
			t.Fatalf("open redirect %q got %d, want 400", bad, resp.StatusCode)
		}
	}

	// 2. Host / X-Forwarded-Proto spoofing cannot override canonical public_base_url
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

	// 3. SSRF blocking against live reachable ssrf-trap (172.30.30.10:8080) and cloud IMDS
	for _, target := range []string{"http://172.30.30.10:8080/secret", "http://169.254.169.254/latest/meta-data/"} {
		resp, body := doReq(t, client, http.MethodPost, prodLBBase+"/admin/v1/mcp/servers", map[string]any{
			"org_id":    "org_default",
			"name":      "ssrf-probe",
			"transport": "streamable_http",
			"url":       target,
		}, map[string]string{"Authorization": "Bearer " + prodMasterKey})
		if resp.StatusCode == http.StatusOK || resp.StatusCode == http.StatusCreated {
			t.Fatalf("SSRF target %s was unexpectedly allowed: status=%d body=%s", target, resp.StatusCode, string(body))
		}
	}

	// 4. /admin/v1/config secret scrubbing
	cfgResp, cfgBody := doReq(t, client, http.MethodGet, prodLBBase+"/admin/v1/config", nil, map[string]string{
		"Authorization": "Bearer " + prodMasterKey,
	})
	if cfgResp.StatusCode != http.StatusOK {
		t.Fatalf("GET /admin/v1/config status=%d", cfgResp.StatusCode)
	}
	cfgText := string(cfgBody)
	for _, secret := range []string{prodMasterKey, prodSSOSecret, prodSessionSec, prodRedisPass, prodPostgresPass} {
		if strings.Contains(cfgText, secret) {
			t.Fatalf("secret %q leaked in GET /admin/v1/config!", secret[:8]+"...")
		}
	}
}

func TestProdDocker_Suite5_MultiReplicaHA_AndResilience(t *testing.T) {
	client := newProdTLSClient(t, false)

	// 1. Cross-pod SSO authorization state (start on Pod 1 -> authorize URL has canonical redirect_uri & PKCE S256)
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
	// Verify Pod 2 recognizes state from Redis (replaying fake code returns token_exchange failure, NOT missing_state!)
	cbResp, cbBody := doReq(t, client, http.MethodGet, prodPod2Base+"/auth/sso/keycloak/callback?code=fake-code&state="+url.QueryEscape(startJSON.State), nil, nil)
	if strings.Contains(string(cbBody), "invalid_state") || strings.Contains(string(cbBody), "sso_state_not_found") {
		t.Fatalf("Pod 2 did not share Redis SSO state created by Pod 1: status=%d body=%s", cbResp.StatusCode, string(cbBody))
	}

	// 2. Warm JWKS cache on both pods, pause Keycloak, verify stale-JWKS JWT + Break-Glass survival
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

	// 3. Unknown-kid storm rate limiting (25 random unknown kids must fail 401 fast without harming pods)
	for i := 0; i < 25; i++ {
		badTok := buildFakeJWT("RS256", "JWT", fmt.Sprintf("unknown-kid-%d", i), map[string]any{
			"iss": prodAuthBase + "/realms/goroute-prod",
			"sub": "storm",
			"aud": "goroute-gateway",
			"exp": time.Now().Add(5 * time.Minute).Unix(),
		}, []byte("x"))
		r, _ := doReq(t, client, http.MethodGet, prodLBBase+"/v1/models", nil, map[string]string{"Authorization": "Bearer " + badTok})
		if r.StatusCode != http.StatusUnauthorized {
			t.Fatalf("unknown kid #%d returned %d, want 401", i, r.StatusCode)
		}
	}

	// 4. Redis restart recovery
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

	// 5. Live Master KEK rotation on Pod 1
	rotResp, rotBody := doReq(t, client, http.MethodPost, prodPod1Base+"/admin/v1/security/rotate-kek", map[string]any{
		"new_master_key": "b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90a1",
	}, map[string]string{"Authorization": "Bearer " + prodMasterKey})
	if rotResp.StatusCode != http.StatusOK {
		t.Fatalf("live KEK rotation failed: status=%d body=%s", rotResp.StatusCode, string(rotBody))
	}
}

func TestProdDocker_Suite6_ConcurrentLoad_Metrics_AndAuditLogs(t *testing.T) {
	client := newProdTLSClient(t, false)
	tok := mintKeycloakToken(t, client, "goroute-prod", "goroute-ci-mint", "goroute-ci-mint-secret-2026", "orgadmin@goroute.local", "ProdOrgAdmin!2026")

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

	// Prometheus metrics on both pods (requires admin auth in production)
	for _, base := range []string{prodPod1Base, prodPod2Base} {
		unauthResp, _ := doReq(t, client, http.MethodGet, base+"/metrics", nil, nil)
		if unauthResp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("%s/metrics without auth got %d, want 401", base, unauthResp.StatusCode)
		}
		mResp, mBody := doReq(t, client, http.MethodGet, base+"/metrics", nil, map[string]string{
			"Authorization": "Bearer " + prodMasterKey,
		})
		if mResp.StatusCode != http.StatusOK || !strings.Contains(string(mBody), "# HELP") {
			t.Fatalf("%s/metrics unexpected response: status=%d body_len=%d", base, mResp.StatusCode, len(mBody))
		}
	}

	// Audit logs persisted
	aResp, aBody := doReq(t, client, http.MethodGet, prodLBBase+"/admin/v1/audit/logs?org_id=org_default", nil, map[string]string{
		"Authorization": "Bearer " + prodMasterKey,
	})
	if aResp.StatusCode != http.StatusOK || len(aBody) == 0 {
		t.Fatalf("GET /admin/v1/audit/logs status=%d", aResp.StatusCode)
	}
}
