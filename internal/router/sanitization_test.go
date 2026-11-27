// Sanitization tests verify that non-OpenAI wire providers (such as Google
// Gemini and Anthropic) strip OpenAI-only extra parameters while preserving
// provider-supported fields.

package router

import (
	"slices"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

func TestSanitizeRequestForDeployment_GeminiStripsOpenAIOnlyExtraParams(t *testing.T) {
	req := &domain.CanonicalChatRequest{
		Model: "gemini-2.5-flash",
		Messages: []domain.CanonicalMessage{
			{Role: "user", Content: "Hello"},
		},
		ExtraParams: map[string]any{
			"store":        true,
			"service_tier": "default",
			"logit_bias":   map[string]int{"1": 2},
			"top_k":        40,
		},
	}
	dep := &domain.Deployment{
		GlobalModel: &domain.GlobalModel{
			ID:        "gemini/gemini-2.5-flash",
			Provider:  domain.ProviderGemini,
			ModelName: "gemini-2.5-flash",
			Capabilities: domain.ModelCapabilities{
				Streaming:         domain.CapabilitySupported,
				Tools:             domain.CapabilitySupported,
				Vision:            domain.CapabilitySupported,
				Reasoning:         domain.CapabilitySupported,
				StructuredOutputs: domain.CapabilitySupported,
			},
		},
	}

	sanitized, dropped := sanitizeRequestForDeployment(req, dep, true)
	for _, stripped := range []string{"logit_bias", "service_tier", "store"} {
		if _, exists := sanitized.ExtraParams[stripped]; exists {
			t.Fatalf("expected OpenAI-only extra param %q to be stripped for Gemini", stripped)
		}
		if !slices.Contains(dropped, stripped) {
			t.Fatalf("expected %q in dropped list, got %v", stripped, dropped)
		}
	}
	if sanitized.ExtraParams["top_k"] != 40 {
		t.Fatalf("expected non-OpenAI-only extra param top_k preserved, got %#v", sanitized.ExtraParams["top_k"])
	}
}
