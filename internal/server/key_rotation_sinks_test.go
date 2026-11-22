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

	t.Run("unsupported sink driver like aws_secrets_manager is rejected", func(t *testing.T) {
		_, err := newKeyRotationSecretSink(config.AuthConfig{
			KeyRotationSink: config.KeyRotationSinkConfig{
				Driver:  "aws_secrets_manager",
				Address: "https://secretsmanager.us-east-1.amazonaws.com",
			},
		}, nil)
		if err == nil || !strings.Contains(err.Error(), "unsupported auth.key_rotation_sink.driver") {
			t.Fatalf("expected unsupported key_rotation_sink driver error, got %v", err)
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

	t.Run("webhook delivers bearer token and full event payload over TLS and deduplicates legacy url", func(t *testing.T) {
		var gotAuth, gotMethod string
		var gotPayload auth.KeyRotatedSecretEvent
		srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			gotMethod = r.Method
			gotAuth = r.Header.Get("Authorization")
			if err := json.NewDecoder(r.Body).Decode(&gotPayload); err != nil {
				t.Fatalf("decode webhook payload: %v", err)
			}
			w.WriteHeader(http.StatusOK)
		}))
		defer srv.Close()

		sink, err := newKeyRotationSecretSinkWithClient(config.AuthConfig{
			KeyRotationSink: config.KeyRotationSinkConfig{
				Driver:  "webhook",
				Address: srv.URL,
				Token:   "webhook-secret-token",
			},
		}, srv.Client(), nil)
		if err != nil {
			t.Fatalf("newKeyRotationSecretSinkWithClient(webhook): %v", err)
		}
		if err := sink.DeliverRotatedSecret(ctx, event); err != nil {
			t.Fatalf("DeliverRotatedSecret(webhook): %v", err)
		}
		if gotMethod != http.MethodPost || gotAuth != "Bearer webhook-secret-token" {
			t.Fatalf("webhook method=%q auth=%q", gotMethod, gotAuth)
		}
		if gotPayload.RawKey != event.RawKey || gotPayload.VirtualKeyID != event.VirtualKeyID || gotPayload.OrgID != event.OrgID {
			t.Fatalf("webhook payload mismatch: %+v", gotPayload)
		}

		// When driver=webhook omits address and legacy key_rotation_delivery_url is set, returns nil to avoid duplicate POSTs.
		dedupSink, err := newKeyRotationSecretSink(config.AuthConfig{
			KeyRotationDeliveryURL:   srv.URL,
			KeyRotationDeliveryToken: "legacy-token",
			KeyRotationSink: config.KeyRotationSinkConfig{
				Driver: "webhook",
			},
		}, nil)
		if err != nil {
			t.Fatalf("newKeyRotationSecretSink(dedup): %v", err)
		}
		if dedupSink != nil {
			t.Fatalf("expected nil sink when webhook driver omits address alongside legacy key_rotation_delivery_url")
		}
	})
}
