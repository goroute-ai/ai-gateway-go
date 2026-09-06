package gemini

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
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
