package openai

import (
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

func TestToOpenAIRequest_ReasoningModelSanitization(t *testing.T) {
	temp := 0.7
	topP := 0.9
	req := &domain.CanonicalChatRequest{
		Model:       "o3-mini",
		Temperature: &temp,
		TopP:        &topP,
		Messages: []domain.CanonicalMessage{
			{Role: "system", Content: "You are a coding assistant."},
			{Role: "user", Content: "Write quicksort in Go."},
		},
	}

	out := toOpenAIRequest("o3-mini", req, false)

	// Temperature and TopP must be omitted for reasoning models
	if out.Temperature != nil {
		t.Fatalf("expected temperature to be nil for o3-mini, got %v", *out.Temperature)
	}
	if out.TopP != nil {
		t.Fatalf("expected top_p to be nil for o3-mini, got %v", *out.TopP)
	}

	// System role must be converted to developer
	if len(out.Messages) != 2 {
		t.Fatalf("expected 2 messages, got %d", len(out.Messages))
	}
	if out.Messages[0].Role != "developer" {
		t.Fatalf("expected role 'developer' for system message in o3-mini, got %s", out.Messages[0].Role)
	}
}

func TestToOpenAIRequest_StandardModelPreservesParameters(t *testing.T) {
	temp := 0.7
	topP := 0.9
	req := &domain.CanonicalChatRequest{
		Model:       "gpt-4o",
		Temperature: &temp,
		TopP:        &topP,
		Messages: []domain.CanonicalMessage{
			{Role: "system", Content: "You are a helpful assistant."},
			{Role: "user", Content: "Hello!"},
		},
	}

	out := toOpenAIRequest("gpt-4o", req, false)

	if out.Temperature == nil || *out.Temperature != 0.7 {
		t.Fatalf("expected temperature 0.7 preserved for gpt-4o")
	}
	if out.TopP == nil || *out.TopP != 0.9 {
		t.Fatalf("expected top_p 0.9 preserved for gpt-4o")
	}
	if out.Messages[0].Role != "system" {
		t.Fatalf("expected role 'system' preserved for gpt-4o, got %s", out.Messages[0].Role)
	}
}
