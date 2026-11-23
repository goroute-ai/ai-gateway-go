package auth_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
)

func TestExternalAuthorizer_WebhookOPAAndSSRF(t *testing.T) {
	loopbackPolicy, err := network.NewPolicy(config.OutboundSSRFConfig{
		AllowPrivateNetworks: true,
		AllowLoopbackHTTP:    true,
		AllowInsecureHTTP:    true,
	})
	if err != nil {
		t.Fatalf("NewPolicy: %v", err)
	}

	t.Run("webhook verifies HMAC signature, allows/denies, and honors cache_ttl", func(t *testing.T) {
		var calls atomic.Int32
		const secret = "top-secret-hmac"
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls.Add(1)
			body, _ := io.ReadAll(r.Body)
			mac := hmac.New(sha256.New, []byte(secret))
			_, _ = mac.Write(body)
			wantSig := "sha256=" + hex.EncodeToString(mac.Sum(nil))
			if got := r.Header.Get("X-GoRoute-Signature-256"); got != wantSig {
				http.Error(w, "bad sig", http.StatusUnauthorized)
				return
			}
			var req auth.AuthzRequest
			_ = json.Unmarshal(body, &req)
			if req.Model == "forbidden-model" {
				_ = json.NewEncoder(w).Encode(auth.AuthzDecision{Allow: false, Reason: "blocked by policy", ErrorCode: "policy_denied"})
				return
			}
			_ = json.NewEncoder(w).Encode(auth.AuthzDecision{Allow: true})
		}))
		defer srv.Close()

		ext, err := auth.NewExternalAuthorizer(auth.ExternalAuthorizerConfig{
			Mode:       "webhook",
			URL:        srv.URL,
			HMACSecret: secret,
			CacheTTL:   5 * time.Second,
		}, loopbackPolicy)
		if err != nil {
			t.Fatalf("NewExternalAuthorizer: %v", err)
		}

		reqAllow := &auth.AuthzRequest{
			Identity: &domain.IdentityContext{OrgID: "org-1", VirtualKeyID: "vk-1"},
			Action:   auth.AuthzActionInference,
			Model:    "gpt-4o",
		}
		if err := auth.EvaluateAuthorizer(context.Background(), ext, reqAllow); err != nil {
			t.Fatalf("expected allow, got %v", err)
		}
		if err := auth.EvaluateAuthorizer(context.Background(), ext, reqAllow); err != nil {
			t.Fatalf("expected cached allow, got %v", err)
		}
		if calls.Load() != 1 {
			t.Fatalf("expected 1 HTTP call due to cache_ttl, got %d", calls.Load())
		}

		reqDeny := &auth.AuthzRequest{
			Identity: &domain.IdentityContext{OrgID: "org-1", VirtualKeyID: "vk-1"},
			Action:   auth.AuthzActionInference,
			Model:    "forbidden-model",
		}
		err = auth.EvaluateAuthorizer(context.Background(), ext, reqDeny)
		var gwErr *domain.GatewayError
		if !errors.As(err, &gwErr) || gwErr.StatusCode != http.StatusForbidden || gwErr.Code != "policy_denied" {
			t.Fatalf("expected 403 policy_denied, got %v", err)
		}
	})

	t.Run("OPA mode wraps input and supports boolean or object result", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var body map[string]auth.AuthzRequest
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body["input"].MCPTool == "delete_repo" {
				_, _ = w.Write([]byte(`{"result": false}`))
				return
			}
			_, _ = w.Write([]byte(`{"result": true}`))
		}))
		defer srv.Close()

		ext, err := auth.NewExternalAuthorizer(auth.ExternalAuthorizerConfig{
			Mode: "opa",
			URL:  srv.URL,
		}, loopbackPolicy)
		if err != nil {
			t.Fatalf("NewExternalAuthorizer: %v", err)
		}

		if err := auth.EvaluateAuthorizer(context.Background(), ext, &auth.AuthzRequest{
			Action:  auth.AuthzActionMCPToolCall,
			MCPTool: "get_issue",
		}); err != nil {
			t.Fatalf("expected OPA allow, got %v", err)
		}
		if err := auth.EvaluateAuthorizer(context.Background(), ext, &auth.AuthzRequest{
			Action:  auth.AuthzActionMCPToolCall,
			MCPTool: "delete_repo",
		}); err == nil {
			t.Fatalf("expected OPA deny for delete_repo")
		}
	})

	t.Run("fail_mode closed rejects on error while SSRF policy blocks cloud metadata IP", func(t *testing.T) {
		strictPolicy, err := network.NewPolicy(config.OutboundSSRFConfig{})
		if err != nil {
			t.Fatalf("NewPolicy: %v", err)
		}
		ext, err := auth.NewExternalAuthorizer(auth.ExternalAuthorizerConfig{
			Mode:     "webhook",
			URL:      "http://169.254.169.254/latest/meta-data/",
			FailMode: "closed",
			Timeout:  200 * time.Millisecond,
		}, strictPolicy)
		if err != nil {
			t.Fatalf("NewExternalAuthorizer: %v", err)
		}
		err = auth.EvaluateAuthorizer(context.Background(), ext, &auth.AuthzRequest{Action: auth.AuthzActionInference})
		var gwErr *domain.GatewayError
		if !errors.As(err, &gwErr) || gwErr.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("expected 503 fail-closed on SSRF blocked target, got %v", err)
		}
	})
}
