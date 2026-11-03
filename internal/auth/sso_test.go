package auth_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/auth/upstream"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

func TestSSOStateStore_MemoryAndRedis_SingleUseAndExpiry(t *testing.T) {
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
			store := auth.NewSSOStateStore(tc.redis)
			store.SetNowFunc(func() time.Time { return now })

			err := store.Save(ctx, &auth.SSOAuthState{
				State:        "state-abc",
				Provider:     "keycloak",
				CodeVerifier: "verifier-123",
				Nonce:        "nonce-456",
				CLILoginID:   "cli-789",
			})
			if err != nil {
				t.Fatalf("Save: %v", err)
			}

			got, err := store.Consume(ctx, "state-abc")
			if err != nil {
				t.Fatalf("Consume: %v", err)
			}
			if got.Provider != "keycloak" || got.CodeVerifier != "verifier-123" || got.Nonce != "nonce-456" || got.CLILoginID != "cli-789" {
				t.Fatalf("unexpected consumed state: %+v", got)
			}

			// Replay must fail.
			if _, err := store.Consume(ctx, "state-abc"); !errors.Is(err, auth.ErrSSOStateNotFound) {
				t.Fatalf("expected ErrSSOStateNotFound on replay, got %v", err)
			}

			// Expired state must be rejected.
			if err := store.Save(ctx, &auth.SSOAuthState{
				State:        "state-expired",
				Provider:     "oidc",
				CodeVerifier: "v",
				Nonce:        "n",
			}); err != nil {
				t.Fatalf("Save expired test: %v", err)
			}
			now = now.Add(auth.DefaultSSOStateTTL + time.Second)
			if _, err := store.Consume(ctx, "state-expired"); !errors.Is(err, auth.ErrSSOStateNotFound) {
				t.Fatalf("expected ErrSSOStateNotFound after expiry, got %v", err)
			}
		})
	}
}

func TestCLILoginStore_MemoryAndRedis_EncryptedAndRateLimited(t *testing.T) {
	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis.Run: %v", err)
	}
	defer mr.Close()

	redisFabric := storage.NewRedisFabric(mr.Addr(), "", 0)
	defer func() { _ = redisFabric.Client().Close() }()

	vault, err := auth.NewVault("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("NewVault: %v", err)
	}

	for _, tc := range []struct {
		name    string
		redis   *storage.RedisFabric
		isRedis bool
	}{
		{name: "memory_fallback", redis: nil},
		{name: "redis_backed", redis: redisFabric, isRedis: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			now := time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC)
			store := auth.NewCLILoginStore(tc.redis, vault)
			store.SetNowFunc(func() time.Time { return now })
			store.SetPollInterval(5 * time.Second)

			sess, err := store.Start(ctx, "keycloak")
			if err != nil {
				t.Fatalf("Start: %v", err)
			}
			if sess.LoginID == "" || sess.UserCode == "" {
				t.Fatalf("expected non-empty login_id and user_code, got %+v", sess)
			}

			// First poll while pending returns pending status.
			p1, err := store.Poll(ctx, sess.LoginID)
			if err != nil {
				t.Fatalf("Poll 1: %v", err)
			}
			if p1.Status != auth.CLILoginStatusPending {
				t.Fatalf("expected pending, got %s", p1.Status)
			}

			// Immediate second poll is rate-limited.
			if _, err := store.Poll(ctx, sess.LoginID); !errors.Is(err, auth.ErrCLIPollRateLimited) {
				t.Fatalf("expected ErrCLIPollRateLimited on fast poll, got %v", err)
			}

			// Advance past poll interval.
			now = now.Add(6 * time.Second)
			if tc.isRedis {
				mr.FastForward(6 * time.Second)
			}

			rawSecretKey := "sk-gw-cli-test-secret-00112233445566778899"
			if _, err := store.Complete(ctx, sess.LoginID, "org-1", "team-1", "usr-1", "vk-1", "sk-gw-cli", rawSecretKey); err != nil {
				t.Fatalf("Complete: %v", err)
			}

			if tc.isRedis {
				rawVal, getErr := mr.Get("gw:cli:login:" + sess.LoginID)
				if getErr != nil {
					t.Fatalf("miniredis Get: %v", getErr)
				}
				if strings.Contains(rawVal, rawSecretKey) {
					t.Fatalf("raw virtual key must be encrypted in Redis, found plaintext in %s", rawVal)
				}
			}

			// Single-use pickup returns decrypted key once.
			p2, err := store.Poll(ctx, sess.LoginID)
			if err != nil {
				t.Fatalf("Poll 2: %v", err)
			}
			if p2.Status != auth.CLILoginStatusCompleted || p2.APIKey != rawSecretKey {
				t.Fatalf("unexpected completed poll result: %+v", p2)
			}

			// Subsequent poll must fail because session was deleted immediately.
			if _, err := store.Poll(ctx, sess.LoginID); !errors.Is(err, auth.ErrCLILoginNotFound) {
				t.Fatalf("expected ErrCLILoginNotFound after single-use pickup, got %v", err)
			}
		})
	}
}

func TestSSOProviderManager_RejectsLegacyProviderTypes(t *testing.T) {
	netPolicy, err := network.NewPolicy(config.OutboundSSRFConfig{AllowLoopbackHTTP: true})
	if err != nil {
		t.Fatalf("network.NewPolicy: %v", err)
	}
	for _, legacyType := range []string{"google", "microsoft", "entra", "azure_ad", "okta_id_jag"} {
		if _, err := auth.NewSSOProviderManager([]auth.SSOProviderConfig{{
			ID:       "legacy",
			Type:     legacyType,
			ClientID: "cid",
			Issuer:   "https://idp.example.com",
		}}, netPolicy); err == nil {
			t.Fatalf("expected provider type %q to be rejected", legacyType)
		}
	}
}

func TestSSOProviderManager_OIDCDiscovery_PKCE_ATHash_UserInfo_AndLogout(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}

	var idpURL string
	var expectedChallenge string
	var accessToken = "kc-access-token-abc123"
	var overrideATHash string
	var userinfoSubOverride string
	var revokeCalls atomic.Int32

	sum := sha256.Sum256([]byte(accessToken))
	validATHash := base64.RawURLEncoding.EncodeToString(sum[:16])

	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/realms/goroute/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer":                           idpURL + "/realms/goroute",
				"authorization_endpoint":           idpURL + "/realms/goroute/protocol/openid-connect/auth",
				"token_endpoint":                   idpURL + "/realms/goroute/protocol/openid-connect/token",
				"userinfo_endpoint":                idpURL + "/realms/goroute/protocol/openid-connect/userinfo",
				"end_session_endpoint":             idpURL + "/realms/goroute/protocol/openid-connect/logout",
				"revocation_endpoint":              idpURL + "/realms/goroute/protocol/openid-connect/revoke",
				"jwks_uri":                         idpURL + "/realms/goroute/protocol/openid-connect/certs",
				"code_challenge_methods_supported": []string{"S256"},
			})
		case "/realms/goroute/protocol/openid-connect/certs":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"keys": []map[string]any{{
					"kty":     "RSA",
					"kid":     "kc-key-1",
					"use":     "sig",
					"key_ops": []string{"verify"},
					"n":       base64.RawURLEncoding.EncodeToString(privKey.N.Bytes()),
					"e":       base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privKey.E)).Bytes()),
				}},
			})
		case "/realms/goroute/protocol/openid-connect/token":
			_ = r.ParseForm()
			verifier := r.FormValue("code_verifier")
			if !upstream.ValidatePKCE(verifier, expectedChallenge, "S256") {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
				return
			}
			now := time.Now().UTC()
			atHash := validATHash
			if overrideATHash != "" {
				atHash = overrideATHash
			}
			// Intentionally omit email/name from ID Token to exercise UserInfo hydration.
			idTok := signRS256JWT(t, privKey, "kc-key-1", map[string]any{
				"iss":     idpURL + "/realms/goroute",
				"sub":     "kc-sub-1",
				"aud":     "goroute-gateway",
				"nonce":   r.FormValue("code"),
				"at_hash": atHash,
				"iat":     now.Unix(),
				"exp":     now.Add(5 * time.Minute).Unix(),
			})
			_ = json.NewEncoder(w).Encode(map[string]any{
				"token_type":   "Bearer",
				"access_token": accessToken,
				"id_token":     idTok,
			})
		case "/realms/goroute/protocol/openid-connect/userinfo":
			sub := "kc-sub-1"
			if userinfoSubOverride != "" {
				sub = userinfoSubOverride
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"sub":            sub,
				"email":          "alice@goroute.local",
				"email_verified": true,
				"name":           "Alice Keycloak",
				"org_id":         "org_from_userinfo",
				"role":           "org_admin",
				"team_ids":       []string{"team_userinfo"},
			})
		case "/realms/goroute/protocol/openid-connect/revoke":
			revokeCalls.Add(1)
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer idp.Close()
	idpURL = idp.URL

	netPolicy, err := network.NewPolicy(config.OutboundSSRFConfig{
		AllowLoopbackHTTP: true,
	})
	if err != nil {
		t.Fatalf("network.NewPolicy: %v", err)
	}

	mgr, err := auth.NewSSOProviderManager([]auth.SSOProviderConfig{
		{
			ID:                  "keycloak",
			Type:                "oidc",
			ClientID:            "goroute-gateway",
			ClientSecret:        "gw-secret",
			Issuer:              idp.URL + "/realms/goroute",
			AllowedEmailDomains: []string{"goroute.local"},
		},
	}, netPolicy)
	if err != nil {
		t.Fatalf("NewSSOProviderManager: %v", err)
	}

	stateStore := auth.NewSSOStateStore(nil)
	authURL, state, err := mgr.BuildAuthorizationURL(context.Background(), "keycloak", "http://localhost:8080/auth/sso/keycloak/callback", "", "", stateStore)
	if err != nil {
		t.Fatalf("BuildAuthorizationURL: %v", err)
	}
	expectedChallenge = extractURLParam(t, authURL, "code_challenge")
	st, err := stateStore.Consume(context.Background(), state)
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}

	// 1. Valid exchange with at_hash verification + UserInfo hydration.
	claims, err := mgr.ExchangeAndVerify(context.Background(), "keycloak", st.Nonce, st.RedirectURI, st.CodeVerifier, st.Nonce)
	if err != nil {
		t.Fatalf("ExchangeAndVerify: %v", err)
	}
	if claims.Email != "alice@goroute.local" || claims.DisplayName != "Alice Keycloak" || !claims.EmailVerified {
		t.Fatalf("unexpected OIDC claims: %+v", claims)
	}
	if claims.OrgID != "org_from_userinfo" || claims.Role != "org_admin" || len(claims.TeamIDs) != 1 || claims.TeamIDs[0] != "team_userinfo" {
		t.Fatalf("expected default org_id/role/team_ids hydrated from userinfo, got %+v", claims)
	}
	if claims.RawIDToken == "" {
		t.Fatal("expected RawIDToken populated on verified SSOIDTokenClaims for encrypted id_token_hint")
	}

	// 2. Mismatched at_hash must fail.
	overrideATHash = "bad-at-hash-value"
	if _, err := mgr.ExchangeAndVerify(context.Background(), "keycloak", st.Nonce, st.RedirectURI, st.CodeVerifier, st.Nonce); err == nil {
		t.Fatalf("expected invalid at_hash to fail verification")
	}
	overrideATHash = ""

	// 3. Mismatched UserInfo sub must fail (sub substitution protection).
	userinfoSubOverride = "evil-other-sub"
	if _, err := mgr.ExchangeAndVerify(context.Background(), "keycloak", st.Nonce, st.RedirectURI, st.CodeVerifier, st.Nonce); err == nil {
		t.Fatalf("expected userinfo sub mismatch to fail verification")
	}
	userinfoSubOverride = ""

	// 4. RP-Initiated Logout constructs end_session_endpoint URL.
	endSessionURL, err := mgr.BuildEndSessionURL(context.Background(), "keycloak", "id-tok-hint", "http://localhost:8080/")
	if err != nil {
		t.Fatalf("BuildEndSessionURL: %v", err)
	}
	parsedEnd, err := url.Parse(endSessionURL)
	if err != nil || !strings.HasSuffix(parsedEnd.Path, "/protocol/openid-connect/logout") {
		t.Fatalf("unexpected end_session_url: %q (%v)", endSessionURL, err)
	}
	if parsedEnd.Query().Get("post_logout_redirect_uri") != "http://localhost:8080/" {
		t.Fatalf("missing post_logout_redirect_uri in %q", endSessionURL)
	}

	// 5. RFC 7009 token revocation hits revocation_endpoint.
	if err := mgr.RevokeToken(context.Background(), "keycloak", accessToken, "access_token"); err != nil {
		t.Fatalf("RevokeToken: %v", err)
	}
	if revokeCalls.Load() != 1 {
		t.Fatalf("expected 1 revocation call, got %d", revokeCalls.Load())
	}
}

func TestOIDC_RFC8414MetadataFallback(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}
	var srvURL string
	var rfc8414Hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/tenant/.well-known/openid-configuration":
			w.WriteHeader(http.StatusNotFound)
		case "/.well-known/oauth-authorization-server/tenant":
			rfc8414Hits.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer":                 srvURL + "/tenant",
				"authorization_endpoint": srvURL + "/tenant/authorize",
				"token_endpoint":         srvURL + "/tenant/token",
				"jwks_uri":               srvURL + "/tenant/jwks",
			})
		case "/tenant/jwks":
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"keys": []map[string]any{{
					"kty":     "RSA",
					"kid":     "k1",
					"use":     "sig",
					"key_ops": []string{"verify"},
					"n":       base64.RawURLEncoding.EncodeToString(privKey.N.Bytes()),
					"e":       base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privKey.E)).Bytes()),
				}},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	srvURL = srv.URL

	netPolicy, _ := network.NewPolicy(config.OutboundSSRFConfig{AllowLoopbackHTTP: true})
	mgr, err := auth.NewSSOProviderManager([]auth.SSOProviderConfig{{
		ID:       "rfc8414",
		Type:     "oidc",
		ClientID: "cid",
		Issuer:   srv.URL + "/tenant",
	}}, netPolicy)
	if err != nil {
		t.Fatalf("NewSSOProviderManager: %v", err)
	}
	stateStore := auth.NewSSOStateStore(nil)
	authURL, _, err := mgr.BuildAuthorizationURL(context.Background(), "rfc8414", "http://localhost/cb", "", "", stateStore)
	if err != nil {
		t.Fatalf("BuildAuthorizationURL with RFC 8414 fallback: %v", err)
	}
	if !strings.HasPrefix(authURL, srvURL+"/tenant/authorize?") {
		t.Fatalf("unexpected authorization_url: %s", authURL)
	}
	if rfc8414Hits.Load() != 1 {
		t.Fatalf("expected 1 hit to RFC 8414 fallback endpoint, got %d", rfc8414Hits.Load())
	}
}

func extractURLParam(t *testing.T, rawURL, key string) string {
	t.Helper()
	idx := strings.Index(rawURL, "?")
	if idx < 0 {
		t.Fatalf("url missing query: %s", rawURL)
	}
	for _, pair := range strings.Split(rawURL[idx+1:], "&") {
		kv := strings.SplitN(pair, "=", 2)
		if len(kv) == 2 && kv[0] == key {
			return kv[1]
		}
	}
	return ""
}
