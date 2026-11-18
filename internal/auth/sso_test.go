package auth_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
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
				Provider:     "google",
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
			if got.Provider != "google" || got.CodeVerifier != "verifier-123" || got.Nonce != "nonce-456" || got.CLILoginID != "cli-789" {
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

			sess, err := store.Start(ctx, "google")
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

func TestSSOProviderManager_MicrosoftTemplatedIssuerAndPreferredUsername(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa.GenerateKey: %v", err)
	}

	var idpURL string
	var expectedChallenge string
	tenantGUID := "11111111-2222-3333-4444-555555555555"

	idp := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"issuer":                 "https://login.microsoftonline.com/{tenantid}/v2.0",
				"authorization_endpoint": idpURL + "/authorize",
				"token_endpoint":         idpURL + "/token",
				"jwks_uri":               idpURL + "/jwks",
			})
		case "/jwks":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"keys": []map[string]any{{
					"kty": "RSA",
					"kid": "ms-key-1",
					"use": "sig",
					"alg": "RS256",
					"n":   base64.RawURLEncoding.EncodeToString(privKey.N.Bytes()),
					"e":   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(privKey.E)).Bytes()),
				}},
			})
		case "/token":
			_ = r.ParseForm()
			verifier := r.FormValue("code_verifier")
			if !upstream.ValidatePKCE(verifier, expectedChallenge, "S256") {
				w.WriteHeader(http.StatusBadRequest)
				_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
				return
			}
			now := time.Now().UTC()
			idTok := signRS256JWT(t, privKey, "ms-key-1", map[string]any{
				"iss":                "https://login.microsoftonline.com/" + tenantGUID + "/v2.0",
				"sub":                "ms-sub-1",
				"aud":                "ms-client-id",
				"tid":                tenantGUID,
				"nonce":              r.FormValue("code"), // test passes nonce via code lookup below
				"preferred_username": "alice@contoso.com",
				"name":               "Alice Contoso",
				"iat":                now.Unix(),
				"exp":                now.Add(5 * time.Minute).Unix(),
			})
			_ = json.NewEncoder(w).Encode(map[string]any{
				"token_type":   "Bearer",
				"access_token": "ms-access",
				"id_token":     idTok,
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer idp.Close()
	idpURL = idp.URL

	netPolicy, err := network.NewPolicy(config.OutboundSSRFConfig{
		AllowPrivateNetworks: true,
		AllowInsecureHTTP:    true,
	})
	if err != nil {
		t.Fatalf("network.NewPolicy: %v", err)
	}

	mgr, err := auth.NewSSOProviderManager([]auth.SSOProviderConfig{
		{
			ID:                  "microsoft",
			Type:                "microsoft",
			TenantID:            "common",
			ClientID:            "ms-client-id",
			ClientSecret:        "ms-client-secret",
			DiscoveryURL:        idp.URL + "/.well-known/openid-configuration",
			AllowedEmailDomains: []string{"contoso.com"},
		},
	}, netPolicy)
	if err != nil {
		t.Fatalf("NewSSOProviderManager: %v", err)
	}

	stateStore := auth.NewSSOStateStore(nil)
	authURL, state, err := mgr.BuildAuthorizationURL(context.Background(), "microsoft", "http://localhost/auth/sso/microsoft/callback", "", "", stateStore)
	if err != nil {
		t.Fatalf("BuildAuthorizationURL: %v", err)
	}
	expectedChallenge = extractURLParam(t, authURL, "code_challenge")
	st, err := stateStore.Consume(context.Background(), state)
	if err != nil {
		t.Fatalf("Consume: %v", err)
	}

	// Pass st.Nonce as the code so the mock token handler embeds it cleanly.
	claims, err := mgr.ExchangeAndVerify(context.Background(), "microsoft", st.Nonce, st.RedirectURI, st.CodeVerifier, st.Nonce)
	if err != nil {
		t.Fatalf("ExchangeAndVerify: %v", err)
	}
	if claims.Email != "alice@contoso.com" || claims.DisplayName != "Alice Contoso" {
		t.Fatalf("unexpected Microsoft claims: %+v", claims)
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
