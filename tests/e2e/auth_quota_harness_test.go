package e2e_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/auth/upstream"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/server"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/redis/go-redis/v9"
)

const (
	e2eMasterAdminKey      = "sk-gw-e2e-master-admin-key"
	e2eMasterEncryptionKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	e2eSessionSecret       = "e2e-session-secret-0123456789abcdef0123456789abcdef"
)

type dualNodeTestCluster struct {
	t           *testing.T
	ts1         *httptest.Server
	ts2         *httptest.Server
	node1       *server.GatewayServer
	node2       *server.GatewayServer
	c1          *httpClientHelper
	c2          *httpClientHelper
	pgRepo      *storage.PostgresRepository
	pool        *pgxpool.Pool
	redisFabric *storage.RedisFabric
	adminHdrs   map[string]string

	clockMu sync.Mutex
	curTime time.Time
	idSeq   atomic.Int64
	runTag  string
}

func liveE2EPostgresDSN() string {
	return getEnvOrDefault("GATEWAY_POSTGRES_DSN", "postgres://gateway:gateway@localhost:15432/aigateway_test?sslmode=disable")
}

func liveE2ERedisAddr() string {
	return getEnvOrDefault("GATEWAY_REDIS_ADDR", "localhost:16379")
}

// setupConfigurableDualNodeCluster boots two sibling GatewayServer HTTP servers sharing
// live PostgreSQL 16 and Redis 7 state with optional configuration mutation before startup.
func setupConfigurableDualNodeCluster(t *testing.T, mutateCfg func(cfg *config.Config)) *dualNodeTestCluster {
	t.Helper()
	ctx := context.Background()

	pgDSN := liveE2EPostgresDSN()
	redisAddr := liveE2ERedisAddr()

	pool, err := storage.NewPostgresPool(ctx, pgDSN)
	if err != nil {
		if os.Getenv("GATEWAY_REQUIRE_LIVE_DEPS") == "1" {
			t.Fatalf("GATEWAY_REQUIRE_LIVE_DEPS=1 set, cannot connect to PostgreSQL: %v", err)
		}
		t.Skipf("skipping live E2E test: cannot connect to PostgreSQL: %v", err)
	}

	if err := storage.RunMigrationsDir(ctx, pool, "../../migrations"); err != nil {
		pool.Close()
		t.Fatalf("RunMigrationsDir: %v", err)
	}

	pgRepo, err := storage.NewPostgresRepository(ctx, pool)
	if err != nil {
		pool.Close()
		t.Fatalf("NewPostgresRepository: %v", err)
	}

	redisFabric := storage.NewRedisFabric(redisAddr, "", 0)
	if _, err := redisFabric.Execute(func(rdb redis.UniversalClient) (any, error) {
		return rdb.Ping(ctx).Result()
	}); err != nil {
		pool.Close()
		if os.Getenv("GATEWAY_REQUIRE_LIVE_DEPS") == "1" {
			t.Fatalf("GATEWAY_REQUIRE_LIVE_DEPS=1 set, cannot ping Redis: %v", err)
		}
		t.Skipf("skipping live E2E test: cannot ping Redis: %v", err)
	}

	buildCfg := func(nodeIdx int) *config.Config {
		cfg := config.Default()
		cfg.Server.Environment = "test"
		cfg.Discovery.Enabled = false
		cfg.Auth.MasterAdminKey = e2eMasterAdminKey
		cfg.Auth.MasterEncryptionKey = e2eMasterEncryptionKey
		cfg.Auth.SessionSecret = e2eSessionSecret
		cfg.Auth.SessionTTL = 1 * time.Hour
		cfg.Security.Network.OutboundSSRF.AllowPrivateNetworks = true
		cfg.Security.Network.OutboundSSRF.AllowInsecureHTTP = true
		cfg.MCP.Enabled = true
		cfg.MCP.EnableSessionCompat2025 = true
		cfg.A2A.Enabled = true
		cfg.A2A.EnableJSONRPC = true
		cfg.A2A.EnableHTTPJSON = true
		cfg.A2A.SigningKeyID = fmt.Sprintf("gw-e2e-key-%d", nodeIdx)
		cfg.Cache.Enabled = true
		cfg.Cache.DefaultTTL = 10 * time.Minute
		cfg.FinOps.FlushInterval = 25 * time.Millisecond
		cfg.FinOps.BatchSize = 1
		if mutateCfg != nil {
			mutateCfg(cfg)
		}
		return cfg
	}

	cfg1 := buildCfg(1)
	cfg2 := buildCfg(2)

	node1, err := server.New(cfg1, pgRepo, redisFabric, nil)
	if err != nil {
		pool.Close()
		t.Fatalf("server.New(node1): %v", err)
	}
	node1.StartWorkers(ctx)
	ts1 := httptest.NewServer(node1.Handler())

	node2, err := server.New(cfg2, pgRepo, redisFabric, nil)
	if err != nil {
		ts1.Close()
		node1.Shutdown(ctx)
		pool.Close()
		t.Fatalf("server.New(node2): %v", err)
	}
	node2.StartWorkers(ctx)
	ts2 := httptest.NewServer(node2.Handler())

	c := &dualNodeTestCluster{
		t:           t,
		ts1:         ts1,
		ts2:         ts2,
		node1:       node1,
		node2:       node2,
		c1:          &httpClientHelper{t: t, ts: ts1},
		c2:          &httpClientHelper{t: t, ts: ts2},
		pgRepo:      pgRepo,
		pool:        pool,
		redisFabric: redisFabric,
		adminHdrs:   map[string]string{"Authorization": "Bearer " + e2eMasterAdminKey},
		runTag:      fmt.Sprintf("%d", time.Now().UnixNano()),
	}

	t.Cleanup(func() {
		ts1.Close()
		ts2.Close()
		node1.Shutdown(context.Background())
		node2.Shutdown(context.Background())
		pool.Close()
	})

	return c
}

func (c *dualNodeTestCluster) uniqueID(prefix string) string {
	n := c.idSeq.Add(1)
	return fmt.Sprintf("%s-%s-%d", prefix, c.runTag, n)
}

func (c *dualNodeTestCluster) setClock(ts time.Time) {
	c.clockMu.Lock()
	c.curTime = ts.UTC()
	c.clockMu.Unlock()
	clock := func() time.Time {
		c.clockMu.Lock()
		defer c.clockMu.Unlock()
		return c.curTime
	}
	c.node1.SetNowFunc(clock)
	c.node2.SetNowFunc(clock)
	if c.node1.AuthService() != nil {
		c.node1.AuthService().SetNowFunc(clock)
	}
	if c.node2.AuthService() != nil {
		c.node2.AuthService().SetNowFunc(clock)
	}
}

func (c *dualNodeTestCluster) createOrg(name string) domain.Organization {
	c.t.Helper()
	var org domain.Organization
	slug := c.uniqueID("org")
	resp, raw := c.c1.doJSON(http.MethodPost, "/admin/v1/organizations", c.adminHdrs, map[string]any{
		"name": name,
		"slug": slug,
	}, &org)
	if resp.StatusCode != http.StatusCreated {
		c.t.Fatalf("create org %q (%d): %s", name, resp.StatusCode, string(raw))
	}
	return org
}

func (c *dualNodeTestCluster) issueKey(payload map[string]any) domain.VirtualKey {
	c.t.Helper()
	var vk domain.VirtualKey
	resp, raw := c.c1.doJSON(http.MethodPost, "/admin/v1/keys", c.adminHdrs, payload, &vk)
	if resp.StatusCode != http.StatusCreated {
		c.t.Fatalf("issue key (%d): %s", resp.StatusCode, string(raw))
	}
	if vk.RawKey == "" {
		c.t.Fatalf("expected non-empty RawKey in create key response")
	}
	return vk
}

// seedOpenAIModel registers an active GlobalModel, ProviderCredential, ModelGroup, and Deployment.
func (c *dualNodeTestCluster) seedOpenAIModel(ctx context.Context, orgID, alias, baseURL string, inputMicrosPer1M, outputMicrosPer1M int64, rpmLimit, tpmLimit int) (credID, mgID, depID string) {
	c.t.Helper()
	gmID := "openai/" + alias
	err := c.pgRepo.UpsertGlobalModel(ctx, &domain.GlobalModel{
		ID:                    gmID,
		Provider:              domain.ProviderOpenAI,
		ModelName:             alias,
		DisplayName:           alias,
		SupportsInference:     true,
		LifecycleStatus:       domain.ModelStatusActive,
		PricingStatus:         domain.PricingStatusVerified,
		InputCostMicrosPer1M:  inputMicrosPer1M,
		OutputCostMicrosPer1M: outputMicrosPer1M,
		MaxOutputTokens:       4096,
		SupportedOperations:   []domain.OperationType{domain.OperationChat, domain.OperationResponses},
	})
	if err != nil {
		c.t.Fatalf("UpsertGlobalModel(%s): %v", gmID, err)
	}

	var credResp, grpResp, depResp map[string]any
	resp, raw := c.c1.doJSON(http.MethodPost, "/admin/v1/credentials", c.adminHdrs, map[string]any{
		"org_id":   orgID,
		"provider": "openai",
		"name":     c.uniqueID("cred"),
		"api_key":  "sk-mock-upstream-key",
		"base_url": baseURL,
	}, &credResp)
	if resp.StatusCode != http.StatusCreated {
		c.t.Fatalf("create credential (%d): %s", resp.StatusCode, string(raw))
	}
	credID, _ = credResp["id"].(string)

	resp, raw = c.c1.doJSON(http.MethodPost, "/admin/v1/model-groups", c.adminHdrs, map[string]any{
		"org_id":           orgID,
		"alias":            alias,
		"routing_strategy": "weighted_shuffle",
	}, &grpResp)
	if resp.StatusCode != http.StatusCreated {
		c.t.Fatalf("create model group %q (%d): %s", alias, resp.StatusCode, string(raw))
	}
	mgID, _ = grpResp["id"].(string)

	depPayload := map[string]any{
		"model_group_id":  mgID,
		"global_model_id": gmID,
		"credential_id":   credID,
		"deployment_name": c.uniqueID("dep"),
		"weight":          1,
	}
	if rpmLimit > 0 {
		depPayload["rpm_limit"] = rpmLimit
	}
	if tpmLimit > 0 {
		depPayload["tpm_limit"] = tpmLimit
	}
	resp, raw = c.c1.doJSON(http.MethodPost, "/admin/v1/deployments", c.adminHdrs, depPayload, &depResp)
	if resp.StatusCode != http.StatusCreated {
		c.t.Fatalf("create deployment (%d): %s", resp.StatusCode, string(raw))
	}
	depID, _ = depResp["id"].(string)
	return credID, mgID, depID
}

// doHTTP performs a flexible HTTP request preserving redirects (if noRedirect) and returning status + raw bytes.
func (c *dualNodeTestCluster) doHTTP(ts *httptest.Server, method, path string, headers map[string]string, cookies []*http.Cookie, body []byte, noRedirect bool) (*http.Response, []byte) {
	c.t.Helper()
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequest(method, ts.URL+path, rdr)
	if err != nil {
		c.t.Fatalf("new request %s %s: %v", method, path, err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	for _, ck := range cookies {
		req.AddCookie(ck)
	}
	client := &http.Client{Timeout: 10 * time.Second}
	if noRedirect {
		client.CheckRedirect = func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		c.t.Fatalf("do request %s %s: %v", method, path, err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, raw
}

// waitForCondition polls checkFn every 25ms until it returns true or timeout expires.
func (c *dualNodeTestCluster) waitForCondition(timeout time.Duration, desc string, checkFn func() bool) {
	c.t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if checkFn() {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	c.t.Fatalf("timed out after %v waiting for: %s", timeout, desc)
}

// -----------------------------------------------------------------------------
// mockEnterpriseIdentityProvider: Dual OIDC Issuers, Multi-Alg JWKS, PKCE,
// RFC 7662 Introspection, UserInfo, and OAuth2 Client Credentials
// -----------------------------------------------------------------------------

type mockAuthCodeEntry struct {
	Challenge string
	Method    string
	Nonce     string
	Redirect  string
	ClientID  string
	Sub       string
	Email     string
	Name      string
}

type mockIntrospectRecord struct {
	Active bool
	Claims map[string]any
}

type mockEnterpriseIdentityProvider struct {
	t        *testing.T
	srv      *httptest.Server
	rsaPrivA *rsa.PrivateKey
	rsaPrivB *rsa.PrivateKey
	rsaRotA  *rsa.PrivateKey
	ec256    *ecdsa.PrivateKey
	ec384    *ecdsa.PrivateKey
	edPriv   ed25519.PrivateKey
	edPub    ed25519.PublicKey
	hsSecret []byte

	mu               sync.Mutex
	kidA             string
	rotatedA         bool
	jwksOutage       bool
	nextSub          string
	nextEmail        string
	nextName         string
	codes            map[string]mockAuthCodeEntry
	introspectTokens map[string]mockIntrospectRecord
	userinfoTokens   map[string]map[string]any
	oauthTokenDelay  time.Duration

	introspectCalls atomic.Int32
	oauthTokenCalls atomic.Int32
}

func newMockEnterpriseIdentityProvider(t *testing.T) *mockEnterpriseIdentityProvider {
	t.Helper()
	rsaA, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsaA: %v", err)
	}
	rsaB, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsaB: %v", err)
	}
	rsaRot, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsaRot: %v", err)
	}
	ec256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("ec256: %v", err)
	}
	ec384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatalf("ec384: %v", err)
	}
	edPub, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519: %v", err)
	}

	m := &mockEnterpriseIdentityProvider{
		t:                t,
		rsaPrivA:         rsaA,
		rsaPrivB:         rsaB,
		rsaRotA:          rsaRot,
		ec256:            ec256,
		ec384:            ec384,
		edPriv:           edPriv,
		edPub:            edPub,
		hsSecret:         []byte("e2e-hs256-shared-secret-key-0123456789"),
		kidA:             "kid-a-1",
		nextSub:          "sso-user-1",
		nextEmail:        "sso-user-1@corp.example",
		nextName:         "SSO User One",
		codes:            make(map[string]mockAuthCodeEntry),
		introspectTokens: make(map[string]mockIntrospectRecord),
		userinfoTokens:   make(map[string]map[string]any),
	}
	m.srv = httptest.NewServer(http.HandlerFunc(m.handle))
	t.Cleanup(m.srv.Close)
	return m
}

func (m *mockEnterpriseIdentityProvider) BaseURL() string { return m.srv.URL }
func (m *mockEnterpriseIdentityProvider) IssuerA() string { return m.srv.URL + "/issuer-a" }
func (m *mockEnterpriseIdentityProvider) IssuerB() string { return m.srv.URL + "/issuer-b" }
func (m *mockEnterpriseIdentityProvider) IntrospectURL() string {
	return m.srv.URL + "/introspect"
}
func (m *mockEnterpriseIdentityProvider) UserInfoURL() string {
	return m.srv.URL + "/userinfo"
}
func (m *mockEnterpriseIdentityProvider) OAuthTokenURL() string {
	return m.srv.URL + "/oauth/token"
}
func (m *mockEnterpriseIdentityProvider) HSSecret() string { return string(m.hsSecret) }

func (m *mockEnterpriseIdentityProvider) SetJWKSOutage(outage bool) {
	m.mu.Lock()
	m.jwksOutage = outage
	m.mu.Unlock()
}

func (m *mockEnterpriseIdentityProvider) RotateKeyA(newKid string) {
	m.mu.Lock()
	m.kidA = newKid
	m.rotatedA = true
	m.mu.Unlock()
}

func (m *mockEnterpriseIdentityProvider) SetNextSSOUser(sub, email, name string) {
	m.mu.Lock()
	m.nextSub = sub
	m.nextEmail = email
	m.nextName = name
	m.mu.Unlock()
}

func (m *mockEnterpriseIdentityProvider) SetIntrospectToken(tok string, active bool, claims map[string]any) {
	m.mu.Lock()
	m.introspectTokens[tok] = mockIntrospectRecord{Active: active, Claims: claims}
	m.mu.Unlock()
}

func (m *mockEnterpriseIdentityProvider) SetUserInfoToken(tok string, claims map[string]any) {
	m.mu.Lock()
	m.userinfoTokens[tok] = claims
	m.mu.Unlock()
}

func (m *mockEnterpriseIdentityProvider) SetOAuthTokenDelay(d time.Duration) {
	m.mu.Lock()
	m.oauthTokenDelay = d
	m.mu.Unlock()
}

func (m *mockEnterpriseIdentityProvider) IntrospectCalls() int32 {
	return m.introspectCalls.Load()
}
func (m *mockEnterpriseIdentityProvider) OAuthTokenCalls() int32 {
	return m.oauthTokenCalls.Load()
}

func (m *mockEnterpriseIdentityProvider) SignJWT(alg, kid, typ string, claims map[string]any) string {
	m.t.Helper()
	if typ == "" {
		typ = "JWT"
	}
	hdr := map[string]string{"alg": alg, "typ": typ}
	if kid != "" {
		hdr["kid"] = kid
	}
	hdrBytes, _ := json.Marshal(hdr)
	claimsBytes, _ := json.Marshal(claims)
	signingInput := base64.RawURLEncoding.EncodeToString(hdrBytes) + "." + base64.RawURLEncoding.EncodeToString(claimsBytes)

	var sig []byte
	var err error
	switch alg {
	case "RS256":
		priv := m.rsaPrivA
		if kid == "kid-b-1" {
			priv = m.rsaPrivB
		} else {
			m.mu.Lock()
			if m.rotatedA && kid == m.kidA {
				priv = m.rsaRotA
			}
			m.mu.Unlock()
		}
		h := sha256.Sum256([]byte(signingInput))
		sig, err = rsa.SignPKCS1v15(rand.Reader, priv, crypto.SHA256, h[:])
	case "RS384":
		h := sha512.Sum384([]byte(signingInput))
		sig, err = rsa.SignPKCS1v15(rand.Reader, m.rsaPrivA, crypto.SHA384, h[:])
	case "RS512":
		h := sha512.Sum512([]byte(signingInput))
		sig, err = rsa.SignPKCS1v15(rand.Reader, m.rsaPrivA, crypto.SHA512, h[:])
	case "PS256":
		h := sha256.Sum256([]byte(signingInput))
		sig, err = rsa.SignPSS(rand.Reader, m.rsaPrivA, crypto.SHA256, h[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	case "ES256":
		h := sha256.Sum256([]byte(signingInput))
		sig, err = ecdsaRawSig(m.ec256, h[:], 32)
	case "ES384":
		h := sha512.Sum384([]byte(signingInput))
		sig, err = ecdsaRawSig(m.ec384, h[:], 48)
	case "EdDSA":
		sig = ed25519.Sign(m.edPriv, []byte(signingInput))
	case "HS256":
		mac := hmac.New(sha256.New, m.hsSecret)
		_, _ = mac.Write([]byte(signingInput))
		sig = mac.Sum(nil)
	default:
		m.t.Fatalf("unsupported test JWT alg: %s", alg)
	}
	if err != nil {
		m.t.Fatalf("sign %s JWT: %v", alg, err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

func ecdsaRawSig(priv *ecdsa.PrivateKey, digest []byte, coordSize int) ([]byte, error) {
	r, s, err := ecdsa.Sign(rand.Reader, priv, digest)
	if err != nil {
		return nil, err
	}
	sig := make([]byte, coordSize*2)
	rb, sb := r.Bytes(), s.Bytes()
	copy(sig[coordSize-len(rb):coordSize], rb)
	copy(sig[coordSize*2-len(sb):coordSize*2], sb)
	return sig, nil
}

func jwkRSA(kid, alg string, pub *rsa.PublicKey) map[string]any {
	return map[string]any{
		"kty": "RSA", "kid": kid, "use": "sig", "alg": alg,
		"n": base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
		"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
	}
}

func jwkEC(kid, alg, crv string, pub *ecdsa.PublicKey, coordSize int) map[string]any {
	xb, yb := make([]byte, coordSize), make([]byte, coordSize)
	px, py := pub.X.Bytes(), pub.Y.Bytes()
	copy(xb[coordSize-len(px):], px)
	copy(yb[coordSize-len(py):], py)
	return map[string]any{
		"kty": "EC", "kid": kid, "use": "sig", "alg": alg, "crv": crv,
		"x": base64.RawURLEncoding.EncodeToString(xb),
		"y": base64.RawURLEncoding.EncodeToString(yb),
	}
}

func jwkEd(kid string, pub ed25519.PublicKey) map[string]any {
	return map[string]any{
		"kty": "OKP", "kid": kid, "use": "sig", "alg": "EdDSA", "crv": "Ed25519",
		"x": base64.RawURLEncoding.EncodeToString(pub),
	}
}

func (m *mockEnterpriseIdentityProvider) handle(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/issuer-a/.well-known/openid-configuration", "/issuer-b/.well-known/openid-configuration":
		prefix := "/issuer-a"
		if strings.HasPrefix(r.URL.Path, "/issuer-b") {
			prefix = "/issuer-b"
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer":                 m.srv.URL + prefix,
			"authorization_endpoint": m.srv.URL + prefix + "/authorize",
			"token_endpoint":         m.srv.URL + prefix + "/token",
			"jwks_uri":               m.srv.URL + prefix + "/jwks",
			"userinfo_endpoint":      m.srv.URL + prefix + "/userinfo",
		})
	case "/issuer-a/jwks", "/issuer-b/jwks":
		m.mu.Lock()
		outage := m.jwksOutage
		kidA := m.kidA
		rotated := m.rotatedA
		m.mu.Unlock()
		if outage {
			http.Error(w, "jwks unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		if strings.HasPrefix(r.URL.Path, "/issuer-b") {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"keys": []map[string]any{
					jwkRSA("kid-b-1", "RS256", &m.rsaPrivB.PublicKey),
				},
			})
			return
		}
		keys := []map[string]any{
			jwkRSA("kid-a-1", "RS256", &m.rsaPrivA.PublicKey),
			jwkRSA("kid-a-rs384", "RS384", &m.rsaPrivA.PublicKey),
			jwkRSA("kid-a-rs512", "RS512", &m.rsaPrivA.PublicKey),
			jwkRSA("kid-a-ps256", "PS256", &m.rsaPrivA.PublicKey),
			jwkEC("kid-a-es256", "ES256", "P-256", &m.ec256.PublicKey, 32),
			jwkEC("kid-a-es384", "ES384", "P-384", &m.ec384.PublicKey, 48),
			jwkEd("kid-a-eddsa", m.edPub),
		}
		if rotated {
			keys = append(keys, jwkRSA(kidA, "RS256", &m.rsaRotA.PublicKey))
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": keys})
	case "/issuer-a/authorize", "/issuer-b/authorize":
		q := r.URL.Query()
		if q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
			http.Error(w, "invalid authorize request", http.StatusBadRequest)
			return
		}
		code := "authcode-" + q.Get("state")
		m.mu.Lock()
		m.codes[code] = mockAuthCodeEntry{
			Challenge: q.Get("code_challenge"),
			Method:    q.Get("code_challenge_method"),
			Nonce:     q.Get("nonce"),
			Redirect:  q.Get("redirect_uri"),
			ClientID:  q.Get("client_id"),
			Sub:       m.nextSub,
			Email:     m.nextEmail,
			Name:      m.nextName,
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
	case "/issuer-a/token", "/issuer-b/token":
		_ = r.ParseForm()
		if r.FormValue("grant_type") != "authorization_code" {
			http.Error(w, "unsupported_grant_type", http.StatusBadRequest)
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
			http.Error(w, "invalid_grant", http.StatusBadRequest)
			return
		}
		if r.FormValue("client_id") != entry.ClientID || r.FormValue("redirect_uri") != entry.Redirect {
			http.Error(w, "client_id or redirect_uri mismatch", http.StatusBadRequest)
			return
		}
		if !upstream.ValidatePKCE(r.FormValue("code_verifier"), entry.Challenge, entry.Method) {
			http.Error(w, "PKCE verification failed", http.StatusBadRequest)
			return
		}
		iss := m.IssuerA()
		kid := "kid-a-1"
		if strings.HasPrefix(r.URL.Path, "/issuer-b") {
			iss = m.IssuerB()
			kid = "kid-b-1"
		}
		now := time.Now().UTC()
		idTok := m.SignJWT("RS256", kid, "JWT", map[string]any{
			"iss": iss, "sub": entry.Sub, "aud": entry.ClientID, "nonce": entry.Nonce,
			"email": entry.Email, "name": entry.Name,
			"iat": now.Unix(), "exp": now.Add(10 * time.Minute).Unix(),
		})
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token_type":   "Bearer",
			"access_token": "oidc-access-" + entry.Sub,
			"id_token":     idTok,
			"expires_in":   600,
		})
	case "/introspect":
		m.introspectCalls.Add(1)
		_ = r.ParseForm()
		tok := r.FormValue("token")
		m.mu.Lock()
		rec, ok := m.introspectTokens[tok]
		m.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		if !ok || !rec.Active {
			_ = json.NewEncoder(w).Encode(map[string]any{"active": false})
			return
		}
		payload := map[string]any{"active": true}
		for k, v := range rec.Claims {
			payload[k] = v
		}
		_ = json.NewEncoder(w).Encode(payload)
	case "/userinfo", "/issuer-a/userinfo", "/issuer-b/userinfo":
		m.introspectCalls.Add(1)
		tok := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		m.mu.Lock()
		claims, ok := m.userinfoTokens[tok]
		m.mu.Unlock()
		if !ok {
			http.Error(w, "invalid_token", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(claims)
	case "/oauth/token":
		callIdx := m.oauthTokenCalls.Add(1)
		m.mu.Lock()
		delay := m.oauthTokenDelay
		m.mu.Unlock()
		if delay > 0 {
			time.Sleep(delay)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"token_type":   "Bearer",
			"access_token": fmt.Sprintf("oauth-client-tok-%d", callIdx),
			"expires_in":   300,
		})
	default:
		http.NotFound(w, r)
	}
}

// -----------------------------------------------------------------------------
// mockSecurityAndWebhookSink: Soft-Budget webhooks and HTTPS Key Rotation
// Delivery receiver
// -----------------------------------------------------------------------------

type recordedRotationDelivery struct {
	OrgID  string `json:"org_id"`
	KeyID  string `json:"key_id"`
	RawKey string `json:"raw_key"`
}

type mockSecurityAndWebhookSink struct {
	t       *testing.T
	httpSrv *httptest.Server
	tlsSrv  *httptest.Server

	mu                 sync.Mutex
	softBudgetEvents   []map[string]any
	rotationDeliveries []recordedRotationDelivery
	rotationFailures   int
	rotationToken      string
}

func newMockSecurityAndWebhookSink(t *testing.T, rotationToken string) *mockSecurityAndWebhookSink {
	t.Helper()
	s := &mockSecurityAndWebhookSink{
		t:             t,
		rotationToken: rotationToken,
	}
	s.httpSrv = httptest.NewServer(http.HandlerFunc(s.handleHTTP))
	s.tlsSrv = httptest.NewTLSServer(http.HandlerFunc(s.handleTLS))
	t.Cleanup(func() {
		s.httpSrv.Close()
		s.tlsSrv.Close()
	})
	return s
}

func (s *mockSecurityAndWebhookSink) SoftBudgetWebhookURL() string {
	return s.httpSrv.URL + "/webhooks/soft-budget"
}
func (s *mockSecurityAndWebhookSink) RotationHTTPSURL() string {
	return s.tlsSrv.URL + "/webhooks/key-rotation"
}
func (s *mockSecurityAndWebhookSink) SetRotationFailuresRemaining(n int) {
	s.mu.Lock()
	s.rotationFailures = n
	s.mu.Unlock()
}
func (s *mockSecurityAndWebhookSink) SoftBudgetEvents() []map[string]any {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]map[string]any(nil), s.softBudgetEvents...)
}
func (s *mockSecurityAndWebhookSink) RotationDeliveries() []recordedRotationDelivery {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]recordedRotationDelivery(nil), s.rotationDeliveries...)
}

// HTTPSRotationDeliverFunc exercises real HTTPS TLS mutual request/response delivery
// against tlsSrv while tracking attempts and honoring transient failures.
func (s *mockSecurityAndWebhookSink) HTTPSRotationDeliverFunc() func(ctx context.Context, orgID, keyID, replacement string) error {
	client := s.tlsSrv.Client()
	return func(ctx context.Context, orgID, keyID, replacement string) error {
		body, _ := json.Marshal(recordedRotationDelivery{OrgID: orgID, KeyID: keyID, RawKey: replacement})
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.RotationHTTPSURL(), bytes.NewReader(body))
		if err != nil {
			return err
		}
		req.Header.Set("Authorization", "Bearer "+s.rotationToken)
		req.Header.Set("Content-Type", "application/json")
		resp, err := client.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return fmt.Errorf("rotation delivery rejected with HTTP %d", resp.StatusCode)
		}
		return nil
	}
}

func (s *mockSecurityAndWebhookSink) handleHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/webhooks/soft-budget":
		raw, _ := io.ReadAll(r.Body)
		var ev map[string]any
		_ = json.Unmarshal(raw, &ev)
		s.mu.Lock()
		s.softBudgetEvents = append(s.softBudgetEvents, ev)
		s.mu.Unlock()
		w.WriteHeader(http.StatusOK)
	default:
		http.NotFound(w, r)
	}
}

func (s *mockSecurityAndWebhookSink) handleTLS(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/webhooks/key-rotation" {
		http.NotFound(w, r)
		return
	}
	if s.rotationToken != "" && r.Header.Get("Authorization") != "Bearer "+s.rotationToken {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	raw, _ := io.ReadAll(r.Body)
	var del recordedRotationDelivery
	_ = json.Unmarshal(raw, &del)

	s.mu.Lock()
	s.rotationDeliveries = append(s.rotationDeliveries, del)
	fail := false
	if s.rotationFailures > 0 {
		s.rotationFailures--
		fail = true
	}
	s.mu.Unlock()

	if fail {
		http.Error(w, "vault receiver busy", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = io.WriteString(w, `{"status":"acked"}`)
}

// -----------------------------------------------------------------------------
// mockDeterministicLLMUpstream: Chat, Stream, Anthropic, MCP, A2A
// -----------------------------------------------------------------------------

type mockDeterministicLLMUpstream struct {
	srv *httptest.Server

	mu                sync.Mutex
	promptTokens      int
	completionTokens  int
	streamChunkDelay  time.Duration
	streamChunks      int
	chatCallsByModel  map[string]int
	mcpCalls          int
	lastMCPAuthHeader string
	a2aCalls          int
	streamCanceled    atomic.Bool
}

func newMockDeterministicLLMUpstream(t *testing.T) *mockDeterministicLLMUpstream {
	t.Helper()
	m := &mockDeterministicLLMUpstream{
		promptTokens:     1000,
		completionTokens: 500,
		streamChunks:     3,
		chatCallsByModel: make(map[string]int),
	}
	m.srv = httptest.NewServer(http.HandlerFunc(m.handle))
	t.Cleanup(m.srv.Close)
	return m
}

func (m *mockDeterministicLLMUpstream) OpenAIBaseURL() string { return m.srv.URL + "/v1" }
func (m *mockDeterministicLLMUpstream) AnthropicBaseURL() string {
	return m.srv.URL
}
func (m *mockDeterministicLLMUpstream) MCPEndpointURL() string { return m.srv.URL + "/mcp" }
func (m *mockDeterministicLLMUpstream) A2AEndpointURL() string { return m.srv.URL + "/a2a" }

func (m *mockDeterministicLLMUpstream) SetUsage(promptToks, completionToks int) {
	m.mu.Lock()
	m.promptTokens = promptToks
	m.completionTokens = completionToks
	m.mu.Unlock()
}

func (m *mockDeterministicLLMUpstream) SetStreamProfile(chunks int, delay time.Duration) {
	m.mu.Lock()
	m.streamChunks = chunks
	m.streamChunkDelay = delay
	m.mu.Unlock()
}

func (m *mockDeterministicLLMUpstream) ChatCalls(model string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	if model == "" {
		total := 0
		for _, v := range m.chatCallsByModel {
			total += v
		}
		return total
	}
	return m.chatCallsByModel[model]
}

func (m *mockDeterministicLLMUpstream) MCPCalls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.mcpCalls
}

func (m *mockDeterministicLLMUpstream) LastMCPAuthHeader() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.lastMCPAuthHeader
}

func (m *mockDeterministicLLMUpstream) handle(w http.ResponseWriter, r *http.Request) {
	switch {
	case strings.HasSuffix(r.URL.Path, "/chat/completions"):
		raw, _ := io.ReadAll(r.Body)
		var req struct {
			Model  string `json:"model"`
			Stream bool   `json:"stream"`
		}
		_ = json.Unmarshal(raw, &req)
		if req.Model == "" {
			req.Model = "default"
		}
		m.mu.Lock()
		m.chatCallsByModel[req.Model]++
		pt := m.promptTokens
		ct := m.completionTokens
		chunks := m.streamChunks
		delay := m.streamChunkDelay
		m.mu.Unlock()

		if req.Stream {
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Cache-Control", "no-cache")
			fl, _ := w.(http.Flusher)
			for i := 0; i < chunks; i++ {
				if delay > 0 {
					select {
					case <-r.Context().Done():
						m.streamCanceled.Store(true)
						return
					case <-time.After(delay):
					}
				}
				chunk := fmt.Sprintf(`{"id":"chatcmpl-stream","object":"chat.completion.chunk","model":%q,"choices":[{"index":0,"delta":{"content":"part-%d "}}]}`, req.Model, i)
				_, _ = fmt.Fprintf(w, "data: %s\n\n", chunk)
				if fl != nil {
					fl.Flush()
				}
			}
			finalChunk := fmt.Sprintf(`{"id":"chatcmpl-stream","object":"chat.completion.chunk","model":%q,"choices":[{"index":0,"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":%d,"completion_tokens":%d,"total_tokens":%d}}`, req.Model, pt, ct, pt+ct)
			_, _ = fmt.Fprintf(w, "data: %s\n\ndata: [DONE]\n\n", finalChunk)
			if fl != nil {
				fl.Flush()
			}
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":      "chatcmpl-det",
			"object":  "chat.completion",
			"created": time.Now().Unix(),
			"model":   req.Model,
			"choices": []map[string]any{
				{"index": 0, "message": map[string]any{"role": "assistant", "content": "ok"}, "finish_reason": "stop"},
			},
			"usage": map[string]any{
				"prompt_tokens":     pt,
				"completion_tokens": ct,
				"total_tokens":      pt + ct,
			},
		})
	case strings.HasSuffix(r.URL.Path, "/v1/messages"):
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": "msg_det", "type": "message", "role": "assistant",
			"model":   "claude-sonnet-4-5",
			"content": []map[string]any{{"type": "text", "text": "anthropic ok"}},
			"usage":   map[string]any{"input_tokens": 100, "output_tokens": 50},
		})
	case r.URL.Path == "/mcp":
		raw, _ := io.ReadAll(r.Body)
		var rpc struct {
			JSONRPC string `json:"jsonrpc"`
			ID      any    `json:"id"`
			Method  string `json:"method"`
		}
		_ = json.Unmarshal(raw, &rpc)
		m.mu.Lock()
		if rpc.Method == "tools/call" {
			m.mcpCalls++
		}
		if authHdr := r.Header.Get("Authorization"); authHdr != "" {
			m.lastMCPAuthHeader = authHdr
		}
		m.mu.Unlock()

		var result any
		switch rpc.Method {
		case "initialize":
			result = map[string]any{
				"protocolVersion": "2026-07-28",
				"capabilities":    map[string]any{"tools": map[string]any{}},
				"serverInfo":      map[string]any{"name": "mock-mcp", "version": "1.0.0"},
			}
		case "tools/list":
			result = map[string]any{
				"tools": []map[string]any{
					{
						"name":        "echo_tool",
						"description": "Echoes input message",
						"inputSchema": map[string]any{"type": "object", "properties": map[string]any{"msg": map[string]any{"type": "string"}}},
					},
				},
			}
		case "tools/call":
			result = map[string]any{
				"content": []map[string]any{{"type": "text", "text": "echoed"}},
			}
		default:
			result = map[string]any{}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      rpc.ID,
			"result":  result,
		})
	case strings.HasPrefix(r.URL.Path, "/a2a"):
		m.mu.Lock()
		m.a2aCalls++
		m.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":     "task-e2e-1",
			"status": map[string]any{"state": "completed"},
			"artifacts": []map[string]any{
				{"parts": []map[string]any{{"text": "a2a ok"}}},
			},
		})
	default:
		http.NotFound(w, r)
	}
}

func findCookie(resp *http.Response, name string) *http.Cookie {
	for _, ck := range resp.Cookies() {
		if ck.Name == name {
			return ck
		}
	}
	return nil
}
