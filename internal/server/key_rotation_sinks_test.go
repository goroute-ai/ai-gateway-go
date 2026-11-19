package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
)

func TestKeyRotationSecretSink_VaultKV2AndWebhookAndAWS(t *testing.T) {
	ctx := context.Background()
	event := auth.KeyRotatedSecretEvent{
		OrgID:        "org-1",
		TeamID:       "team-1",
		VirtualKeyID: "vk-1",
		Name:         "prod-key",
		KeyPrefix:    "sk-gw-new",
		RawKey:       "sk-gw-new-secret-value",
		RotatedAt:    time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC),
	}

	t.Run("vault_kv2 sends X-Vault-Token namespace and nested data payload", func(t *testing.T) {
		var gotPath, gotToken, gotNS string
		var gotBody map[string]auth.KeyRotatedSecretEvent
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotPath = r.URL.Path
			gotToken = r.Header.Get("X-Vault-Token")
			gotNS = r.Header.Get("X-Vault-Namespace")
			if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
				t.Fatalf("decode vault body: %v", err)
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()

		sink, err := newKeyRotationSecretSinkWithClient(config.AuthConfig{
			KeyRotationSink: config.KeyRotationSinkConfig{
				Driver:     "vault_kv2",
				Address:    srv.URL,
				Token:      "hvs.vault-token",
				Mount:      "kv",
				PathPrefix: "goroute/keys",
				Namespace:  "admin/prod",
			},
		}, srv.Client(), nil)
		if err != nil {
			t.Fatalf("newKeyRotationSecretSinkWithClient: %v", err)
		}
		if err := sink.DeliverRotatedSecret(ctx, event); err != nil {
			t.Fatalf("DeliverRotatedSecret: %v", err)
		}
		if gotPath != "/v1/kv/data/goroute/keys/org-1/vk-1" {
			t.Fatalf("vault path = %q", gotPath)
		}
		if gotToken != "hvs.vault-token" || gotNS != "admin/prod" {
			t.Fatalf("vault headers mismatch: token=%q ns=%q", gotToken, gotNS)
		}
		if gotBody["data"].RawKey != event.RawKey || gotBody["data"].VirtualKeyID != event.VirtualKeyID {
			t.Fatalf("vault payload mismatch: %+v", gotBody)
		}
	})

	t.Run("aws_secrets_manager signs SigV4 PutSecretValue and falls back to CreateSecret", func(t *testing.T) {
		var targets []string
		var authHeaders []string
		var createName string
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			target := r.Header.Get("X-Amz-Target")
			targets = append(targets, target)
			authHeaders = append(authHeaders, r.Header.Get("Authorization"))
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatalf("decode aws payload: %v", err)
			}
			if target == "secretsmanager.PutSecretValue" {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(`{"__type":"ResourceNotFoundException","Message":"Secrets Manager can't find the specified secret."}`))
				return
			}
			createName, _ = payload["Name"].(string)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"ARN":"arn:aws:secretsmanager:us-east-1:123456789012:secret:ok"}`))
		}))
		defer srv.Close()

		sink, err := newKeyRotationSecretSinkWithClient(config.AuthConfig{
			KeyRotationSink: config.KeyRotationSinkConfig{
				Driver:             "aws_secrets_manager",
				Address:            srv.URL,
				Region:             "us-east-1",
				PathPrefix:         "goroute/keys",
				AWSAccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
				AWSSecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			},
		}, srv.Client(), nil)
		if err != nil {
			t.Fatalf("newKeyRotationSecretSinkWithClient(aws): %v", err)
		}
		if err := sink.DeliverRotatedSecret(ctx, event); err != nil {
			t.Fatalf("DeliverRotatedSecret(aws): %v", err)
		}
		if len(targets) != 2 || targets[0] != "secretsmanager.PutSecretValue" || targets[1] != "secretsmanager.CreateSecret" {
			t.Fatalf("unexpected target sequence: %v", targets)
		}
		for i, h := range authHeaders {
			if !strings.HasPrefix(h, "AWS4-HMAC-SHA256 ") || !strings.Contains(h, "/us-east-1/secretsmanager/aws4_request") {
				t.Fatalf("request %d missing SigV4 secretsmanager authorization: %q", i, h)
			}
		}
		if createName != "goroute/keys/org-1/vk-1" {
			t.Fatalf("CreateSecret Name = %q", createName)
		}
	})

	t.Run("aws rejects ambient IAM fallback when AllowAmbientCloudIAM is false", func(t *testing.T) {
		_, err := newKeyRotationSecretSink(config.AuthConfig{
			AllowAmbientCloudIAM: false,
			KeyRotationSink: config.KeyRotationSinkConfig{
				Driver: "aws_secrets_manager",
				Region: "us-east-1",
			},
		}, nil)
		if err == nil || !strings.Contains(err.Error(), "allow_ambient_cloud_iam") {
			t.Fatalf("expected ambient IAM opt-in error, got %v", err)
		}
	})

	t.Run("default SSRF policy blocks loopback sink delivery and non-HTTPS urls", func(t *testing.T) {
		strictPolicy, err := network.NewPolicy(config.OutboundSSRFConfig{AllowPrivateNetworks: false})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := newKeyRotationSecretSink(config.AuthConfig{
			KeyRotationSink: config.KeyRotationSinkConfig{
				Driver:  "vault_kv2",
				Address: "http://127.0.0.1:8200",
				Token:   "hvs.tok",
			},
		}, strictPolicy); err == nil {
			t.Fatal("expected HTTP Vault address to be rejected")
		}

		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			t.Fatal("SSRF policy should block loopback before reaching handler")
		}))
		defer srv.Close()

		sink, err := newKeyRotationSecretSink(config.AuthConfig{
			KeyRotationSink: config.KeyRotationSinkConfig{
				Driver:  "webhook",
				Address: srv.URL,
				Token:   "bearer-tok",
			},
		}, strictPolicy)
		if err != nil {
			t.Fatalf("newKeyRotationSecretSink(webhook): %v", err)
		}
		if err := sink.DeliverRotatedSecret(ctx, event); err == nil {
			t.Fatal("expected strict SSRF policy to block delivery to loopback HTTPS URL")
		}
	})
}
