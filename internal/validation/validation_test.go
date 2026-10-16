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
