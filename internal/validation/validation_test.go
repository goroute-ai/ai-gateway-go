package validation

import (
	"context"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

func TestValidatorCapabilitiesContextAndParameters(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	val := NewValidator(repo)

	// 1. Invalid temperature (> 2.0)
	badTemp := 2.5
	err := val.ValidateChatRequest(ctx, "", &domain.CanonicalChatRequest{
		Model:       "gpt-4.1-mini",
		Temperature: &badTemp,
		Messages:    []domain.CanonicalMessage{{Role: "user", Content: "hi"}},
	}, 10)
	if err == nil {
		t.Fatal("expected error for invalid temperature 2.5")
	}

	// 2. Vision request on non-vision model (`claude-3-5-haiku-latest` has SupportsVision: false in seed)
	err = val.ValidateChatRequest(ctx, "", &domain.CanonicalChatRequest{
		Model: "claude-3-5-haiku-latest",
		Messages: []domain.CanonicalMessage{
			{
				Role: "user",
				Parts: []domain.ContentPart{
					{Type: "image_url", ImageURL: &domain.ImageURL{URL: "https://example.com/img.png"}},
				},
			},
		},
	}, 20)
	if err == nil {
		t.Fatal("expected capability_not_supported error for vision input on non-vision model")
	}

	// 3. Context window exceeded (`claude-3-5-haiku-latest` MaxInputTokens: 200000)
	err = val.ValidateChatRequest(ctx, "", &domain.CanonicalChatRequest{
		Model:    "claude-3-5-haiku-latest",
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "hi"}},
	}, 250000)
	if err == nil {
		t.Fatal("expected context_length_exceeded error")
	}

	// 4. Max output tokens exceeded (`claude-3-5-haiku-latest` MaxOutputTokens: 8192)
	tooLargeMax := 16000
	err = val.ValidateChatRequest(ctx, "", &domain.CanonicalChatRequest{
		Model:     "claude-3-5-haiku-latest",
		MaxTokens: &tooLargeMax,
		Messages:  []domain.CanonicalMessage{{Role: "user", Content: "hi"}},
	}, 50)
	if err == nil {
		t.Fatal("expected max_output_tokens_exceeded error")
	}
}

func TestValidatorTriStateCapabilities(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	val := NewValidator(repo)

	// Register a model with CapabilityUnknown across all capability dimensions
	unknownModel := &domain.GlobalModel{
		ID:             "groq/llama-unknown-caps",
		Provider:       domain.ProviderGroq,
		ModelName:      "llama-unknown-caps",
		MaxInputTokens: 32768,
		Capabilities: domain.ModelCapabilities{
			Tools:     domain.CapabilityUnknown,
			Streaming: domain.CapabilityUnknown,
			Vision:    domain.CapabilityUnknown,
		},
		LifecycleStatus: domain.ModelStatusActive,
	}
	_ = repo.UpsertGlobalModel(ctx, unknownModel)

	// Register a model with CapabilityUnsupported for tools and vision
	unsupportedModel := &domain.GlobalModel{
		ID:             "custom/text-only-model",
		Provider:       domain.ProviderOpenAI,
		ModelName:      "text-only-model",
		MaxInputTokens: 8192,
		Capabilities: domain.ModelCapabilities{
			Tools:     domain.CapabilityUnsupported,
			Streaming: domain.CapabilityUnsupported,
			Vision:    domain.CapabilityUnsupported,
		},
		LifecycleStatus: domain.ModelStatusActive,
	}
	_ = repo.UpsertGlobalModel(ctx, unsupportedModel)

	// 1. Model with CapabilityUnknown MUST pass validation for streaming, tools, and vision
	// to allow upstream provider invocation
	err := val.ValidateChatRequest(ctx, "", &domain.CanonicalChatRequest{
		Model:  "groq/llama-unknown-caps",
		Stream: true,
		Tools: []domain.CanonicalTool{
			{Type: "function", Function: domain.CanonicalFunction{Name: "get_weather"}},
		},
		Messages: []domain.CanonicalMessage{
			{
				Role: "user",
				Parts: []domain.ContentPart{
					{Type: "image_url", ImageURL: &domain.ImageURL{URL: "https://example.com/test.png"}},
				},
			},
		},
	}, 100)
	if err != nil {
		t.Fatalf("expected request with unknown capabilities to PASS validation, but got error: %v", err)
	}

	// 2. Model with CapabilityUnsupported for Streaming MUST be rejected with HTTP 400
	err = val.ValidateChatRequest(ctx, "", &domain.CanonicalChatRequest{
		Model:    "custom/text-only-model",
		Stream:   true,
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "stream test"}},
	}, 10)
	if err == nil {
		t.Fatal("expected error for streaming on unsupported model")
	}
	if gwErr, ok := err.(*domain.GatewayError); !ok || gwErr.StatusCode != 400 || gwErr.Code != "capability_not_supported" {
		t.Fatalf("expected 400 capability_not_supported, got %+v", err)
	}

	// 3. Model with CapabilityUnsupported for Tools MUST be rejected with HTTP 400
	err = val.ValidateChatRequest(ctx, "", &domain.CanonicalChatRequest{
		Model: "custom/text-only-model",
		Tools: []domain.CanonicalTool{
			{Type: "function", Function: domain.CanonicalFunction{Name: "search"}},
		},
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "tool test"}},
	}, 10)
	if err == nil {
		t.Fatal("expected error for tools on unsupported model")
	}
	if gwErr, ok := err.(*domain.GatewayError); !ok || gwErr.StatusCode != 400 || gwErr.Code != "capability_not_supported" {
		t.Fatalf("expected 400 capability_not_supported, got %+v", err)
	}

	// 4. Model with CapabilityUnsupported for Vision MUST be rejected with HTTP 400
	err = val.ValidateChatRequest(ctx, "", &domain.CanonicalChatRequest{
		Model: "custom/text-only-model",
		Messages: []domain.CanonicalMessage{
			{
				Role: "user",
				Parts: []domain.ContentPart{
					{Type: "image_url", ImageURL: &domain.ImageURL{URL: "https://example.com/photo.jpg"}},
				},
			},
		},
	}, 10)
	if err == nil {
		t.Fatal("expected error for vision on unsupported model")
	}
	if gwErr, ok := err.(*domain.GatewayError); !ok || gwErr.StatusCode != 400 || gwErr.Code != "capability_not_supported" {
		t.Fatalf("expected 400 capability_not_supported, got %+v", err)
	}
}
