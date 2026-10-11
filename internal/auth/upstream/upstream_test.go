package upstream_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/auth/upstream"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
)

func TestStaticStrategy(t *testing.T) {
	strat := upstream.NewStaticStrategy("Authorization", "my-secret-token", map[string]string{
		"X-Custom-Env": "production",
	})

	if strat.Type() != "static" {
		t.Fatalf("expected type static, got %q", strat.Type())
	}

	req, _ := http.NewRequest(http.MethodGet, "https://example.com/api", nil)
	authCtx := &upstream.UpstreamAuthContext{
		ExtraHeaders: map[string]string{
			"X-Request-Trace": "trace_abc",
		},
	}

	if err := strat.Apply(context.Background(), req, authCtx); err != nil {
		t.Fatalf("apply failed: %v", err)
	}

	if req.Header.Get("Authorization") != "Bearer my-secret-token" {
		t.Fatalf("unexpected Authorization header: %q", req.Header.Get("Authorization"))
	}
	if req.Header.Get("X-Custom-Env") != "production" {
		t.Fatalf("unexpected X-Custom-Env: %q", req.Header.Get("X-Custom-Env"))
	}
	if req.Header.Get("X-Request-Trace") != "trace_abc" {
		t.Fatalf("unexpected X-Request-Trace: %q", req.Header.Get("X-Request-Trace"))
	}
}

func TestDelegationStrategy(t *testing.T) {
	strat := upstream.NewDelegationStrategy("Authorization", true)

	t.Run("Fails without delegated token", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, "https://example.com/api", nil)
		if err := strat.Apply(context.Background(), req, nil); err == nil {
			t.Fatalf("expected error without delegated token, got nil")
		}
	})

	t.Run("Applies token and forwards caller metadata", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, "https://example.com/api", nil)
		authCtx := &upstream.UpstreamAuthContext{
			CallingOrgID:   "org_123",
			CallingUserID:  "user_456",
			CallingAgentID: "agent_789",
			DelegatedToken: "delegated-jwt-xyz",
		}

		if err := strat.Apply(context.Background(), req, authCtx); err != nil {
			t.Fatalf("apply failed: %v", err)
		}

		if req.Header.Get("Authorization") != "Bearer delegated-jwt-xyz" {
			t.Fatalf("unexpected Authorization: %q", req.Header.Get("Authorization"))
		}
		if req.Header.Get("X-Gateway-Caller-Org") != "org_123" {
			t.Fatalf("unexpected org header: %q", req.Header.Get("X-Gateway-Caller-Org"))
		}
	})
}

func TestJWTStrategy(t *testing.T) {
	strat, err := upstream.NewJWTStrategy(
		"key_1",
		"super-secret-hmac-key-for-vault-32b",
		"goroute-gateway",
		[]string{"https://upstream.internal/api"},
		5*time.Minute,
	)
	if err != nil {
		t.Fatalf("NewJWTStrategy failed: %v", err)
	}

	t.Run("Rejects untrusted audience", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, "https://malicious.internal/api", nil)
		authCtx := &upstream.UpstreamAuthContext{
			TargetURL: "https://malicious.internal/api",
		}
		if err := strat.Apply(context.Background(), req, authCtx); err == nil {
			t.Fatalf("expected untrusted audience to be rejected, got nil error")
		}
	})

	t.Run("Signs and sets token for trusted audience", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, "https://upstream.internal/api", nil)
		authCtx := &upstream.UpstreamAuthContext{
			TargetURL:    "https://upstream.internal/api",
			CallingOrgID: "org_acme",
		}
		if err := strat.Apply(context.Background(), req, authCtx); err != nil {
			t.Fatalf("apply failed: %v", err)
		}

		authHeader := req.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			t.Fatalf("expected Bearer token, got %q", authHeader)
		}
		parts := strings.Split(authHeader[7:], ".")
		if len(parts) != 3 {
			t.Fatalf("expected 3-part JWT, got %d parts", len(parts))
		}
	})
}

func TestOAuth2StrategyTokenCaching(t *testing.T) {
	var requestCount int32
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&requestCount, 1)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{
			"access_token": "token-m2m-cached-12345",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	defer ts.Close()

	p, _ := network.NewPolicy(config.OutboundSSRFConfig{
		AllowInsecureHTTP:    true,
		AllowPrivateNetworks: true,
	})

	strat := upstream.NewOAuth2Strategy(ts.URL+"/oauth/token", "client_1", "secret_1", []string{"tools:read"}, p)

	req1, _ := http.NewRequest(http.MethodGet, "https://upstream.internal/call", nil)
	if err := strat.Apply(context.Background(), req1, nil); err != nil {
		t.Fatalf("apply 1 failed: %v", err)
	}

	req2, _ := http.NewRequest(http.MethodGet, "https://upstream.internal/call", nil)
	if err := strat.Apply(context.Background(), req2, nil); err != nil {
		t.Fatalf("apply 2 failed: %v", err)
	}

	if atomic.LoadInt32(&requestCount) != 1 {
		t.Fatalf("expected exactly 1 token request due to caching, got %d", atomic.LoadInt32(&requestCount))
	}
	if req1.Header.Get("Authorization") != "Bearer token-m2m-cached-12345" {
		t.Fatalf("unexpected Authorization: %q", req1.Header.Get("Authorization"))
	}
}

func TestRedactionAndPrincipalDigest(t *testing.T) {
	t.Run("RedactSecret masks sensitive values", func(t *testing.T) {
		if got := upstream.RedactSecret("sk-gw-1234567890abcdef"); got != "sk-g...cdef" {
			t.Fatalf("unexpected RedactSecret result: %q", got)
		}
		if got := upstream.RedactSecret("short"); got != "[REDACTED]" {
			t.Fatalf("unexpected RedactSecret for short string: %q", got)
		}
	})

	t.Run("SanitizeHeaders masks only sensitive headers", func(t *testing.T) {
		h := http.Header{
			"Authorization": []string{"Bearer secret_token_xyz"},
			"x-api-key":     []string{"sk-secret-key-1234"},
			"Content-Type":  []string{"application/json"},
		}

		sanitized := upstream.SanitizeHeaders(h)
		if strings.Contains(sanitized["Authorization"], "secret_token_xyz") {
			t.Fatalf("Authorization was not redacted: %q", sanitized["Authorization"])
		}
		if sanitized["Content-Type"] != "application/json" {
			t.Fatalf("Content-Type was improperly altered: %q", sanitized["Content-Type"])
		}
	})

	t.Run("PrincipalDigest ensures cache isolation", func(t *testing.T) {
		ctx1 := &upstream.UpstreamAuthContext{
			ServerID:      "srv_1",
			CallingOrgID:  "org_1",
			CallingUserID: "user_a",
		}
		ctx2 := &upstream.UpstreamAuthContext{
			ServerID:      "srv_1",
			CallingOrgID:  "org_1",
			CallingUserID: "user_b",
		}

		d1 := ctx1.PrincipalDigest()
		d2 := ctx2.PrincipalDigest()
		if d1 == "" || d2 == "" {
			t.Fatalf("expected non-empty digests")
		}
		if d1 == d2 {
			t.Fatalf("expected different users to have distinct principal digests for cache isolation")
		}
	})
}
