package gemini

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
)

func TestChatCompletion_SafetyBlockReturnsError(t *testing.T) {
	// Mock server returning promptFeedback with SAFETY block
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{
			"promptFeedback": {
				"blockReason": "SAFETY",
				"safetyRatings": [
					{"category": "HARM_CATEGORY_DANGEROUS_CONTENT", "probability": "HIGH"}
				]
			}
		}`))
	}))
	defer ts.Close()

	client := ts.Client()
	adapter := NewAdapter(client)
	pol, err := network.NewPolicy(config.OutboundSSRFConfig{
		AllowPrivateNetworks: true,
		AllowInsecureHTTP:    true,
	})
	if err != nil {
		t.Fatalf("network.NewPolicy: %v", err)
	}
	adapter.SetSSRFPolicy(pol)

	dep := &domain.Deployment{
		ID: "dep-gemini",
		Credential: &domain.ProviderCredential{
			BaseURL:         ts.URL,
			DecryptedAPIKey: "test-key",
		},
	}

	req := &domain.CanonicalChatRequest{
		Model: "gemini-2.5-flash",
		Messages: []domain.CanonicalMessage{
			{Role: "user", Content: "unsafe prompt"},
		},
	}

	resp, err := adapter.ChatCompletion(context.Background(), dep, req)
	if err == nil {
		t.Fatalf("expected error on safety block, got nil (with resp: %+v)", resp)
	}

	gwErr, ok := err.(*domain.GatewayError)
	if !ok {
		t.Fatalf("expected *domain.GatewayError, got %T: %v", err, err)
	}
	if gwErr.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", gwErr.StatusCode)
	}
	if gwErr.Code != "safety_violation" {
		t.Fatalf("expected code 'safety_violation', got %s", gwErr.Code)
	}
}

func TestIsVertexExpressKey_HostEquality(t *testing.T) {
	cases := []struct {
		name    string
		baseURL string
		want    bool
	}{
		{name: "nil_empty", baseURL: "", want: false},
		{name: "canonical_vertex", baseURL: "https://aiplatform.googleapis.com/v1", want: true},
		{name: "regional_vertex", baseURL: "https://us-central1-aiplatform.googleapis.com/v1beta1", want: true},
		{name: "path_spoof", baseURL: "https://evil.com/aiplatform.googleapis.com/v1", want: false},
		{name: "suffix_domain_spoof", baseURL: "https://aiplatform.googleapis.com.evil.com/v1", want: false},
		{name: "prefix_without_dot_spoof", baseURL: "https://notaiplatform.googleapis.com/v1", want: false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var cred *domain.ProviderCredential
			if tc.name != "nil_empty" {
				cred = &domain.ProviderCredential{BaseURL: tc.baseURL}
			}
			if got := isVertexExpressKey(cred); got != tc.want {
				t.Fatalf("isVertexExpressKey(%q) = %v, want %v", tc.baseURL, got, tc.want)
			}
		})
	}
}
