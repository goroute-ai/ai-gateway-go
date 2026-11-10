package openaicompat_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/adapter"
	"github.com/goroute-ai/ai-gateway-go/internal/adapter/openaicompat"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCustomProvider_SSRFEnforcement verifies that RegisterCustom rejects private/loopback/cloud-metadata URLs.
func TestCustomProvider_SSRFEnforcement(t *testing.T) {
	reg := openaicompat.NewProfileRegistry(nil)

	blockedURLs := []string{
		"http://127.0.0.1:8080/v1",
		"http://localhost:8000/v1",
		"http://169.254.169.254/latest/meta-data/", // AWS/GCP metadata IP
		"http://10.0.0.1:9000/v1",
		"http://192.168.1.50/v1",
		"ftp://example.com/v1", // Non-http scheme
		"://bad-url",
	}

	for _, u := range blockedURLs {
		t.Run("Blocked_"+u, func(t *testing.T) {
			err := reg.RegisterCustom(config.CustomProviderConfig{
				ID:      "bad-provider",
				BaseURL: u,
			})
			require.Error(t, err, "expected error for SSRF-blocked or invalid URL %q", u)
		})
	}
}

// TestCustomProvider_BoundedResolution verifies strict bounded resolution:
// Unregistered, uncatalogued, or typo provider names return false/error, preventing arbitrary wildcard dispatch.
func TestCustomProvider_BoundedResolution(t *testing.T) {
	profileReg := openaicompat.NewProfileRegistry(nil)
	mainReg := adapter.NewRegistry()
	mainReg.SetDynamicResolver(profileReg.DynamicResolver())

	// Known launch set should resolve
	for _, p := range []domain.ProviderType{"groq", "deepseek", "together", "azure"} {
		adp, err := mainReg.Get(p)
		require.NoError(t, err)
		assert.NotNil(t, adp)
		assert.Equal(t, p, adp.Provider())
	}

	// Unknown / typo providers must fail resolution
	typos := []domain.ProviderType{
		"grok",
		"groq-typo",
		"deep-seek",
		"togethr",
		"azur",
		"unknown_vendor",
		"",
	}

	for _, p := range typos {
		t.Run("Typo_"+string(p), func(t *testing.T) {
			adp, err := mainReg.Get(p)
			require.Error(t, err)
			assert.Nil(t, adp)
			assert.Contains(t, err.Error(), "no provider adapter registered")
		})
	}
}

// TestCustomProvider_EndToEndDispatch verifies registration and execution of a custom OpenAI-compatible provider.
func TestCustomProvider_EndToEndDispatch(t *testing.T) {
	var capturedAuth string
	var capturedCustomHeader string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuth = r.Header.Get("Authorization")
		capturedCustomHeader = r.Header.Get("X-Custom-Env")

		resp := map[string]any{
			"id":      "chatcmpl-custom-123",
			"object":  "chat.completion",
			"created": 1700000000,
			"model":   "my-self-hosted-model",
			"choices": []map[string]any{
				{
					"index": 0,
					"message": map[string]any{
						"role":    "assistant",
						"content": "Custom provider output",
					},
					"finish_reason": "stop",
				},
			},
			"usage": map[string]any{
				"prompt_tokens":     8,
				"completion_tokens": 3,
				"total_tokens":      11,
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	profileReg := openaicompat.NewProfileRegistry(srv.Client())
	mainReg := adapter.NewRegistry()
	mainReg.SetDynamicResolver(profileReg.DynamicResolver())

	// Register valid custom provider pointing to a public domain
	// For testing, register with custom profile
	customCfg := config.CustomProviderConfig{
		ID:          "vllm-cluster",
		DisplayName: "Self-Hosted vLLM Cluster",
		BaseURL:     "https://vllm.internal-domain.com/v1", // Public-looking domain passes syntax
		DefaultHeaders: map[string]string{
			"X-Custom-Env": "staging",
		},
		SupportsStreaming: "supported",
		SupportsTools:     "supported",
	}

	err := profileReg.RegisterCustom(customCfg)
	require.NoError(t, err)

	// Retrieve via dynamic adapter registry
	adp, err := mainReg.Get("vllm-cluster")
	require.NoError(t, err)
	assert.Equal(t, domain.ProviderType("vllm-cluster"), adp.Provider())

	// Execute call pointing to test server
	dep := &domain.Deployment{
		ID: "dep-vllm-1",
		GlobalModel: &domain.GlobalModel{
			ID:        "vllm-cluster/my-self-hosted-model",
			Provider:  "vllm-cluster",
			ModelName: "my-self-hosted-model",
		},
		Credential: &domain.ProviderCredential{
			BaseURL:         srv.URL,
			DecryptedAPIKey: "vllm-token-abc",
			Headers: map[string]string{
				"X-Custom-Env": "staging",
			},
		},
	}

	chatReq := &domain.CanonicalChatRequest{
		Model: "my-self-hosted-model",
		Messages: []domain.CanonicalMessage{
			{Role: "user", Content: "Hello cluster"},
		},
	}

	resp, err := adp.ChatCompletion(context.Background(), dep, chatReq)
	require.NoError(t, err)
	assert.Equal(t, "Custom provider output", resp.Choices[0].Message.Content)
	assert.Equal(t, "Bearer vllm-token-abc", capturedAuth)
	assert.Equal(t, "staging", capturedCustomHeader)
}

// TestCustomProvider_InvalidID verifies invalid characters in custom provider ID are rejected.
func TestCustomProvider_InvalidID(t *testing.T) {
	reg := openaicompat.NewProfileRegistry(nil)

	invalidIDs := []string{
		"invalid id with spaces",
		"provider/with/slashes",
		"provider:with:colons",
		"provider@special",
		"",
	}

	for _, id := range invalidIDs {
		err := reg.RegisterCustom(config.CustomProviderConfig{
			ID:      id,
			BaseURL: "https://api.custom.com/v1",
		})
		require.Error(t, err, "expected error for invalid ID %q", id)
	}
}
