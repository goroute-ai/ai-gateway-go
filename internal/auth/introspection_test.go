package auth_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

func TestOAuthIntrospector_ModeSelection(t *testing.T) {
	cases := []struct {
		name     string
		cfg      auth.IntrospectionConfig
		wantMode string
		wantErr  bool
	}{
		{
			name: "auto uses introspect when endpoint contains introspect",
			cfg: auth.IntrospectionConfig{
				TokenInfoEndpoint: "https://idp.example.com/oauth2/introspect",
			},
			wantMode: auth.IntrospectionModeIntrospect,
		},
		{
			name: "auto uses introspect when client id is set",
			cfg: auth.IntrospectionConfig{
				TokenInfoEndpoint: "https://idp.example.com/tokeninfo",
				ClientID:          "gw-client",
			},
			wantMode: auth.IntrospectionModeIntrospect,
		},
		{
			name: "auto uses userinfo otherwise",
			cfg: auth.IntrospectionConfig{
				TokenInfoEndpoint: "https://idp.example.com/userinfo",
			},
			wantMode: auth.IntrospectionModeUserInfo,
		},
		{
			name: "explicit introspect overrides userinfo path",
			cfg: auth.IntrospectionConfig{
				TokenInfoEndpoint: "https://idp.example.com/userinfo",
				Mode:              auth.IntrospectionModeIntrospect,
			},
			wantMode: auth.IntrospectionModeIntrospect,
		},
		{
			name: "explicit userinfo overrides introspect path and client id",
			cfg: auth.IntrospectionConfig{
				TokenInfoEndpoint: "https://idp.example.com/introspect",
				ClientID:          "gw-client",
				Mode:              auth.IntrospectionModeUserInfo,
			},
			wantMode: auth.IntrospectionModeUserInfo,
		},
		{
			name: "invalid mode returns error",
			cfg: auth.IntrospectionConfig{
				TokenInfoEndpoint: "https://idp.example.com/introspect",
				Mode:              "unsupported",
			},
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ins := auth.NewOAuthIntrospector(tc.cfg)
			got, err := ins.ResolvedMode()
			if tc.wantErr {
				if err == nil {
					t.Fatalf("expected error, got mode %q", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.wantMode {
				t.Fatalf("got mode %q, want %q", got, tc.wantMode)
			}
		})
	}
}

func TestOAuthIntrospector_RFC7662_ConfidentialAndPublicClients(t *testing.T) {
	ctx := context.Background()
	exp := time.Now().UTC().Add(5 * time.Minute).Unix()

	t.Run("confidential client uses HTTP Basic auth and extracts custom claims", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				t.Fatalf("expected POST, got %s", r.Method)
			}
			if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "application/x-www-form-urlencoded") {
				t.Fatalf("unexpected content-type %q", ct)
			}
			cid, csec, ok := r.BasicAuth()
			if !ok || cid != "client-123" || csec != "secret-xyz" {
				t.Fatalf("unexpected basic auth: ok=%v cid=%q csec=%q", ok, cid, csec)
			}
			if err := r.ParseForm(); err != nil {
				t.Fatalf("parse form: %v", err)
			}
			if got := r.PostForm.Get("token"); got != "opaque-token-1" {
				t.Fatalf("unexpected token %q", got)
			}
			if r.PostForm.Has("client_id") {
				t.Fatalf("confidential client should not duplicate client_id in form body")
			}

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"active":       true,
				"sub":          "sub-123",
				"uid":          "user-456",
				"mail":         "alice@example.com",
				"roles":        []string{"org_admin", "developer"},
				"tenant_org":   "org_acme",
				"tenant_team":  "team_platform",
				"scope":        "openid profile email",
				"client_id":    "client-123",
				"token_type":   "Bearer",
				"username":     "alice",
				"iss":          "https://idp.example.com",
				"aud":          []string{"ai-gateway"},
				"exp":          exp,
				"groups":       []string{"engineering", "admins"},
				"custom_claim": "val",
			})
		}))
		defer srv.Close()

		ins := auth.NewOAuthIntrospector(auth.IntrospectionConfig{
			TokenInfoEndpoint: srv.URL + "/oauth2/introspect",
			ClientID:          "client-123",
			ClientSecret:      "secret-xyz",
			UserIDField:       "uid",
			EmailField:        "mail",
			RoleField:         "roles",
			OrgIDField:        "tenant_org",
			TeamIDField:       "tenant_team",
			HTTPClient:        srv.Client(),
		})

		res, err := ins.Introspect(ctx, "opaque-token-1")
		if err != nil {
			t.Fatalf("Introspect failed: %v", err)
		}
		if !res.Active || res.Subject != "sub-123" || res.UserID != "user-456" {
			t.Fatalf("unexpected identity fields: %+v", res)
		}
		if res.Email != "alice@example.com" || res.Role != "org_admin" || res.OrgID != "org_acme" || res.TeamID != "team_platform" {
			t.Fatalf("unexpected mapped claims: %+v", res)
		}
		if res.Scope != "openid profile email" || res.ExpiresAt != exp || len(res.Groups) != 2 {
			t.Fatalf("unexpected metadata: %+v", res)
		}
		if !res.Audience.Contains("ai-gateway") {
			t.Fatalf("expected audience ai-gateway, got %v", res.Audience)
		}
	})

	t.Run("public client sends client_id in form body without Basic auth", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if _, _, ok := r.BasicAuth(); ok {
				t.Fatalf("public client must not send Basic auth")
			}
			if err := r.ParseForm(); err != nil {
				t.Fatalf("parse form: %v", err)
			}
			if r.PostForm.Get("token") != "public-tok" || r.PostForm.Get("client_id") != "public-cli" {
				t.Fatalf("unexpected form values: %v", r.PostForm)
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"active": true,
				"sub":    "public-user",
				"exp":    exp,
			})
		}))
		defer srv.Close()

		ins := auth.NewOAuthIntrospector(auth.IntrospectionConfig{
			TokenInfoEndpoint: srv.URL + "/tokeninfo",
			ClientID:          "public-cli",
			HTTPClient:        srv.Client(),
		})
		res, err := ins.Introspect(ctx, "public-tok")
		if err != nil {
			t.Fatalf("Introspect public client failed: %v", err)
		}
		if res.UserID != "public-user" || res.Subject != "public-user" {
			t.Fatalf("unexpected result: %+v", res)
		}
	})
}

func TestOAuthIntrospector_RFC7662_InactiveAndExpiredRejected(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name    string
		payload map[string]any
		code    string
	}{
		{
			name:    "active false rejected",
			payload: map[string]any{"active": false, "sub": "user-1"},
			code:    "invalid_token",
		},
		{
			name:    "missing active claim rejected",
			payload: map[string]any{"sub": "user-1"},
			code:    "invalid_token",
		},
		{
			name:    "non-boolean active claim rejected",
			payload: map[string]any{"active": "true", "sub": "user-1"},
			code:    "invalid_token",
		},
		{
			name: "expired token rejected",
			payload: map[string]any{
				"active": true,
				"sub":    "user-1",
				"exp":    time.Now().UTC().Add(-10 * time.Second).Unix(),
			},
			code: "token_expired",
		},
		{
			name: "not-yet-valid nbf token rejected",
			payload: map[string]any{
				"active": true,
				"sub":    "user-1",
				"nbf":    time.Now().UTC().Add(60 * time.Second).Unix(),
				"exp":    time.Now().UTC().Add(120 * time.Second).Unix(),
			},
			code: "invalid_token",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var hits atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(tc.payload)
			}))
			defer srv.Close()

			mr := miniredis.RunT(t)
			rf := storage.NewRedisFabric(mr.Addr(), "", 0)
			t.Cleanup(func() { _ = rf.Client().Close() })

			ins := auth.NewOAuthIntrospector(auth.IntrospectionConfig{
				TokenInfoEndpoint: srv.URL + "/introspect",
				ClientID:          "cid",
				ClientSecret:      "csec",
				HTTPClient:        srv.Client(),
				Redis:             rf,
			})

			_, err := ins.Introspect(ctx, "bad-token")
			var gwErr *domain.GatewayError
			if !errors.As(err, &gwErr) {
				t.Fatalf("expected *domain.GatewayError, got %v", err)
			}
			if gwErr.StatusCode != http.StatusUnauthorized || gwErr.Code != tc.code {
				t.Fatalf("got status=%d code=%q, want 401 %q", gwErr.StatusCode, gwErr.Code, tc.code)
			}

			// Negative responses must never be cached.
			_, err = ins.Introspect(ctx, "bad-token")
			if err == nil {
				t.Fatalf("expected second call to also fail")
			}
			if hits.Load() != 2 {
				t.Fatalf("expected 2 upstream calls (no caching of rejected tokens), got %d", hits.Load())
			}
			if len(mr.Keys()) != 0 {
				t.Fatalf("expected no redis keys for rejected token, got %v", mr.Keys())
			}
		})
	}
}

func TestOAuthIntrospector_UserInfoGET(t *testing.T) {
	ctx := context.Background()

	t.Run("valid userinfo GET extracts claims", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodGet {
				t.Fatalf("expected GET, got %s", r.Method)
			}
			if got := r.Header.Get("Authorization"); got != "Bearer userinfo-opaque-token" {
				t.Fatalf("unexpected Authorization header %q", got)
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"sub":     "oidc-user-99",
				"email":   "bob@example.com",
				"role":    "developer",
				"org_id":  "org_beta",
				"team_id": "team_ai",
				"groups":  []string{"eng"},
			})
		}))
		defer srv.Close()

		ins := auth.NewOAuthIntrospector(auth.IntrospectionConfig{
			TokenInfoEndpoint: srv.URL + "/oauth2/userinfo",
			HTTPClient:        srv.Client(),
		})

		res, err := ins.Introspect(ctx, "userinfo-opaque-token")
		if err != nil {
			t.Fatalf("UserInfo Introspect failed: %v", err)
		}
		if !res.Active || res.Subject != "oidc-user-99" || res.UserID != "oidc-user-99" {
			t.Fatalf("unexpected identity: %+v", res)
		}
		if res.Email != "bob@example.com" || res.Role != "developer" || res.OrgID != "org_beta" || res.TeamID != "team_ai" {
			t.Fatalf("unexpected claims: %+v", res)
		}
	})

	t.Run("userinfo missing subject fails closed with 401", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"email": "nosub@example.com"})
		}))
		defer srv.Close()

		ins := auth.NewOAuthIntrospector(auth.IntrospectionConfig{
			TokenInfoEndpoint: srv.URL + "/userinfo",
			HTTPClient:        srv.Client(),
		})
		_, err := ins.Introspect(ctx, "tok-no-sub")
		var gwErr *domain.GatewayError
		if !errors.As(err, &gwErr) || gwErr.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expected 401 GatewayError, got %v", err)
		}
	})

	t.Run("userinfo 401 fails closed", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusUnauthorized)
		}))
		defer srv.Close()

		ins := auth.NewOAuthIntrospector(auth.IntrospectionConfig{
			TokenInfoEndpoint: srv.URL + "/userinfo",
			HTTPClient:        srv.Client(),
		})
		_, err := ins.Introspect(ctx, "revoked-tok")
		var gwErr *domain.GatewayError
		if !errors.As(err, &gwErr) || gwErr.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expected 401 GatewayError, got %v", err)
		}
	})
}

func TestOAuthIntrospector_L1AndL2CachingAndTTLBounds(t *testing.T) {
	ctx := context.Background()
	rawToken := "secret-bearer-token-value-12345"
	sum := sha256.Sum256([]byte(rawToken))
	expectedKey := "gw:auth:introspect:" + hex.EncodeToString(sum[:])

	t.Run("L1 hit, L2 hit across instances, SHA-256 key, and TTL bounded by exp", func(t *testing.T) {
		mr := miniredis.RunT(t)
		rf := storage.NewRedisFabric(mr.Addr(), "", 0)
		t.Cleanup(func() { _ = rf.Client().Close() })

		var hits atomic.Int32
		exp := time.Now().UTC().Add(4 * time.Second).Unix()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"active": true,
				"sub":    "cached-user",
				"email":  "cached@example.com",
				"exp":    exp,
			})
		}))
		defer srv.Close()

		// CacheTTL (5m) > exp - now (4s) -> effective TTL must be bounded by exp - now.
		ins1 := auth.NewOAuthIntrospector(auth.IntrospectionConfig{
			TokenInfoEndpoint: srv.URL + "/introspect",
			ClientID:          "cid",
			ClientSecret:      "csec",
			CacheTTL:          5 * time.Minute,
			HTTPClient:        srv.Client(),
			Redis:             rf,
		})

		res1, err := ins1.Introspect(ctx, rawToken)
		if err != nil {
			t.Fatalf("first Introspect failed: %v", err)
		}
		if hits.Load() != 1 {
			t.Fatalf("expected 1 upstream call, got %d", hits.Load())
		}

		// Mutate returned result to verify cache isolation.
		res1.Claims["sub"] = "mutated"
		res1.Email = "mutated@example.com"

		// L1 cache hit on ins1.
		res2, err := ins1.Introspect(ctx, rawToken)
		if err != nil {
			t.Fatalf("second Introspect failed: %v", err)
		}
		if hits.Load() != 1 {
			t.Fatalf("expected L1 cache hit (still 1 upstream call), got %d", hits.Load())
		}
		if res2.Email != "cached@example.com" || res2.Claims["sub"] != "cached-user" {
			t.Fatalf("cached result was mutated: %+v", res2)
		}

		// Verify Redis key uses SHA-256 digest and never raw token, and TTL <= 4s.
		keys := mr.Keys()
		if len(keys) != 1 || keys[0] != expectedKey {
			t.Fatalf("expected redis key [%q], got %v", expectedKey, keys)
		}
		val, err := mr.Get(expectedKey)
		if err != nil {
			t.Fatalf("miniredis get: %v", err)
		}
		if strings.Contains(val, rawToken) {
			t.Fatalf("raw token must never appear in cached redis payload")
		}
		ttl := mr.TTL(expectedKey)
		if ttl <= 0 || ttl > 4*time.Second {
			t.Fatalf("expected redis TTL in (0, 4s], got %v", ttl)
		}

		// Second introspector with empty L1 hits L2 Redis without touching upstream.
		ins2 := auth.NewOAuthIntrospector(auth.IntrospectionConfig{
			TokenInfoEndpoint: srv.URL + "/introspect",
			ClientID:          "cid",
			ClientSecret:      "csec",
			CacheTTL:          5 * time.Minute,
			HTTPClient:        srv.Client(),
			Redis:             rf,
		})
		res3, err := ins2.Introspect(ctx, rawToken)
		if err != nil {
			t.Fatalf("L2 Introspect failed: %v", err)
		}
		if hits.Load() != 1 {
			t.Fatalf("expected L2 cache hit (still 1 upstream call), got %d", hits.Load())
		}
		if res3.Subject != "cached-user" {
			t.Fatalf("unexpected L2 result: %+v", res3)
		}

		// InvalidateToken clears L1 and L2.
		ins2.InvalidateToken(ctx, rawToken)
		if len(mr.Keys()) != 0 {
			t.Fatalf("expected redis key deleted after InvalidateToken, got %v", mr.Keys())
		}
	})

	t.Run("TTL bounded by CacheTTL when exp is further in the future", func(t *testing.T) {
		mr := miniredis.RunT(t)
		rf := storage.NewRedisFabric(mr.Addr(), "", 0)
		t.Cleanup(func() { _ = rf.Client().Close() })

		exp := time.Now().UTC().Add(10 * time.Minute).Unix()
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"active": true,
				"sub":    "user-ttl",
				"exp":    exp,
			})
		}))
		defer srv.Close()

		ins := auth.NewOAuthIntrospector(auth.IntrospectionConfig{
			TokenInfoEndpoint: srv.URL + "/introspect",
			ClientID:          "cid",
			ClientSecret:      "csec",
			CacheTTL:          3 * time.Second,
			HTTPClient:        srv.Client(),
			Redis:             rf,
		})
		if _, err := ins.Introspect(ctx, rawToken); err != nil {
			t.Fatalf("Introspect failed: %v", err)
		}
		ttl := mr.TTL(expectedKey)
		if ttl <= 0 || ttl > 3*time.Second {
			t.Fatalf("expected redis TTL bounded by CacheTTL (<= 3s), got %v", ttl)
		}
	})
}

func TestOAuthIntrospector_SingleflightDeduplication(t *testing.T) {
	ctx := context.Background()
	var hits atomic.Int32
	gate := make(chan struct{})
	firstEntered := make(chan struct{})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits.Add(1) == 1 {
			close(firstEntered)
		}
		<-gate
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"active": true,
			"sub":    "sf-user",
			"exp":    time.Now().UTC().Add(2 * time.Minute).Unix(),
		})
	}))
	defer srv.Close()

	ins := auth.NewOAuthIntrospector(auth.IntrospectionConfig{
		TokenInfoEndpoint: srv.URL + "/introspect",
		ClientID:          "cid",
		ClientSecret:      "csec",
		HTTPClient:        srv.Client(),
	})

	const workers = 20
	results := make([]*auth.IntrospectionResult, workers)
	errs := make([]error, workers)
	var wg sync.WaitGroup
	wg.Add(workers)

	for i := 0; i < workers; i++ {
		idx := i
		go func() {
			defer wg.Done()
			results[idx], errs[idx] = ins.Introspect(ctx, "concurrent-miss-token")
		}()
	}

	<-firstEntered
	time.Sleep(30 * time.Millisecond)
	close(gate)
	wg.Wait()

	if hits.Load() != 1 {
		t.Fatalf("expected singleflight to coalesce into 1 upstream call, got %d", hits.Load())
	}
	for i := 0; i < workers; i++ {
		if errs[i] != nil {
			t.Fatalf("worker %d failed: %v", i, errs[i])
		}
		if results[i] == nil || results[i].Subject != "sf-user" {
			t.Fatalf("worker %d got unexpected result: %+v", i, results[i])
		}
	}
}

func TestOAuthIntrospector_SSRFPolicyAndFailClosedErrors(t *testing.T) {
	ctx := context.Background()

	t.Run("default nil HTTPClient enforces SSRF policy", func(t *testing.T) {
		var hits atomic.Int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()

		// Nil NetworkPolicy blocks insecure HTTP and private/loopback targets.
		strictIns := auth.NewOAuthIntrospector(auth.IntrospectionConfig{
			TokenInfoEndpoint: srv.URL + "/introspect",
			ClientID:          "cid",
			ClientSecret:      "csec",
		})
		_, err := strictIns.Introspect(ctx, "tok-1")
		if !errors.Is(err, network.ErrInsecureHTTPBlocked) {
			t.Fatalf("expected ErrInsecureHTTPBlocked, got %v", err)
		}
		if hits.Load() != 0 {
			t.Fatalf("expected 0 requests when blocked by SSRF policy, got %d", hits.Load())
		}

		// AllowInsecureHTTP without AllowPrivateNetworks still blocks loopback.
		httpOnlyPolicy, err := network.NewPolicy(config.OutboundSSRFConfig{
			AllowInsecureHTTP: true,
		})
		if err != nil {
			t.Fatalf("new policy: %v", err)
		}
		noPrivateIns := auth.NewOAuthIntrospector(auth.IntrospectionConfig{
			TokenInfoEndpoint: srv.URL + "/introspect",
			ClientID:          "cid",
			ClientSecret:      "csec",
			NetworkPolicy:     httpOnlyPolicy,
		})
		_, err = noPrivateIns.Introspect(ctx, "tok-2")
		if !errors.Is(err, network.ErrPrivateNetworkBlocked) {
			t.Fatalf("expected ErrPrivateNetworkBlocked, got %v", err)
		}
		if hits.Load() != 0 {
			t.Fatalf("expected 0 requests when loopback blocked, got %d", hits.Load())
		}
	})

	t.Run("empty token and unconfigured endpoint fail closed", func(t *testing.T) {
		unconfigured := auth.NewOAuthIntrospector(auth.IntrospectionConfig{})
		if unconfigured.Enabled() {
			t.Fatalf("expected Enabled() == false")
		}
		if _, err := unconfigured.Introspect(ctx, "tok"); err == nil {
			t.Fatalf("expected error for unconfigured introspector")
		}

		configured := auth.NewOAuthIntrospector(auth.IntrospectionConfig{
			TokenInfoEndpoint: "https://idp.example.com/introspect",
		})
		_, err := configured.Introspect(ctx, "   ")
		var gwErr *domain.GatewayError
		if !errors.As(err, &gwErr) || gwErr.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expected 401 GatewayError for empty token, got %v", err)
		}
	})

	t.Run("upstream 500, invalid JSON, oversized body, and context timeout fail closed", func(t *testing.T) {
		srv500 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
		}))
		defer srv500.Close()

		ins500 := auth.NewOAuthIntrospector(auth.IntrospectionConfig{
			TokenInfoEndpoint: srv500.URL + "/introspect",
			ClientID:          "cid",
			HTTPClient:        srv500.Client(),
		})
		_, err := ins500.Introspect(ctx, "tok")
		var gwErr *domain.GatewayError
		if !errors.As(err, &gwErr) || gwErr.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("expected 503 GatewayError on upstream 500, got %v", err)
		}

		srvBadJSON := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("{not-json"))
		}))
		defer srvBadJSON.Close()

		insBadJSON := auth.NewOAuthIntrospector(auth.IntrospectionConfig{
			TokenInfoEndpoint: srvBadJSON.URL + "/introspect",
			ClientID:          "cid",
			HTTPClient:        srvBadJSON.Client(),
		})
		_, err = insBadJSON.Introspect(ctx, "tok")
		if !errors.As(err, &gwErr) || gwErr.Code != "introspection_invalid_response" {
			t.Fatalf("expected introspection_invalid_response, got %v", err)
		}

		srvHuge := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			chunk := strings.Repeat("a", 1<<20+1024)
			_, _ = w.Write([]byte(`{"active":true,"sub":"` + chunk + `"}`))
		}))
		defer srvHuge.Close()

		insHuge := auth.NewOAuthIntrospector(auth.IntrospectionConfig{
			TokenInfoEndpoint: srvHuge.URL + "/introspect",
			ClientID:          "cid",
			HTTPClient:        srvHuge.Client(),
		})
		_, err = insHuge.Introspect(ctx, "tok")
		if !errors.As(err, &gwErr) || gwErr.Code != "introspection_response_too_large" {
			t.Fatalf("expected introspection_response_too_large, got %v", err)
		}

		srvSlow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			time.Sleep(150 * time.Millisecond)
			_ = json.NewEncoder(w).Encode(map[string]any{"active": true, "sub": "late"})
		}))
		defer srvSlow.Close()

		insSlow := auth.NewOAuthIntrospector(auth.IntrospectionConfig{
			TokenInfoEndpoint: srvSlow.URL + "/introspect",
			ClientID:          "cid",
			HTTPClient:        srvSlow.Client(),
		})
		shortCtx, cancel := context.WithTimeout(ctx, 25*time.Millisecond)
		defer cancel()
		if _, err := insSlow.Introspect(shortCtx, "tok"); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("expected context.DeadlineExceeded, got %v", err)
		}
	})
}
