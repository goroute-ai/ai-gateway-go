package openaicompat_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/adapter/openaicompat"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
)

func TestAzureProfile_AmbientCloudIAMRequiresExplicitOptIn(t *testing.T) {
	policy, err := network.NewPolicy(config.OutboundSSRFConfig{
		AllowPrivateNetworks: true,
		AllowInsecureHTTP:    true,
	})
	if err != nil {
		t.Fatalf("NewPolicy: %v", err)
	}

	var gotAuth string
	upstreamSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":      "chatcmpl-az",
			"object":  "chat.completion",
			"created": 1700000000,
			"model":   "gpt-4.1",
			"choices": []map[string]any{{
				"index":         0,
				"finish_reason": "stop",
				"message":       map[string]any{"role": "assistant", "content": "ok"},
			}},
		})
	}))
	defer upstreamSrv.Close()

	req := &domain.CanonicalChatRequest{
		Model: "azure/gpt-4.1",
		Messages: []domain.CanonicalMessage{
			{Role: "user", Content: "hello"},
		},
	}
	dep := &domain.Deployment{
		ID:             "dep-az",
		DeploymentName: "gpt-4.1",
		Credential: &domain.ProviderCredential{
			Provider: domain.ProviderType("azure"),
			BaseURL:  upstreamSrv.URL,
			Headers: map[string]string{
				"auth_mode":             "managed_identity",
				"azure_deployment_name": "gpt-4.1",
				"api-version":           "2024-10-21",
			},
		},
	}

	// Default disabled -> fails closed even with managed_identity requested.
	regDefault := openaicompat.NewProfileRegistry(upstreamSrv.Client(), policy)
	adpDefault, err := regDefault.CreateAdapter(domain.ProviderType("azure"))
	if err != nil {
		t.Fatalf("CreateAdapter(default): %v", err)
	}
	if _, err := adpDefault.ChatCompletion(t.Context(), dep, req); err == nil || !strings.Contains(err.Error(), "DecryptedAPIKey") {
		t.Fatalf("expected Azure adapter with AllowAmbientCloudIAM=false to reject empty/ambient key, got: %v", err)
	}

	// Explicitly enabled -> propagates AllowAmbientCloudIAM=true into AzureAuthStrategy.
	imdsSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token": "az-msi-optin-token",
			"expires_in":   "3600",
		})
	}))
	defer imdsSrv.Close()
	t.Setenv("MSI_ENDPOINT", imdsSrv.URL)

	regOptIn := openaicompat.NewProfileRegistry(upstreamSrv.Client(), policy)
	regOptIn.SetAllowAmbientCloudIAM(true)
	adpOptIn, err := regOptIn.CreateAdapter(domain.ProviderType("azure"))
	if err != nil {
		t.Fatalf("CreateAdapter(opt-in): %v", err)
	}
	if _, err := adpOptIn.ChatCompletion(t.Context(), dep, req); err != nil {
		t.Fatalf("expected Azure ChatCompletion with AllowAmbientCloudIAM=true to succeed, got: %v", err)
	}
	if gotAuth != "Bearer az-msi-optin-token" {
		t.Fatalf("expected Bearer az-msi-optin-token sent to Azure upstream, got %q", gotAuth)
	}
}
