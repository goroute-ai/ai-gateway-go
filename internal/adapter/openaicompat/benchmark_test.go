package openaicompat_test

import (
	"encoding/json"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/adapter"
	"github.com/goroute-ai/ai-gateway-go/internal/adapter/openaicompat"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

func BenchmarkDialectValidationAndAdaptation(b *testing.B) {
	reg := openaicompat.NewProfileRegistry(nil)
	profile, ok := reg.Get("groq")
	if !ok {
		b.Fatal("groq profile not found")
	}
	validator := openaicompat.NewRequestValidator(profile)

	maxTokens := 2048
	temp := 0.7
	req := &domain.CanonicalChatRequest{
		Model: "llama-3.3-70b-versatile",
		Messages: []domain.CanonicalMessage{
			{Role: "system", Content: "You are a helpful programming assistant."},
			{Role: "user", Content: "How do I optimize memory allocations in Go?"},
		},
		Temperature: &temp,
		MaxTokens:   &maxTokens,
		Tools: []domain.CanonicalTool{
			{
				Type: "function",
				Function: domain.CanonicalFunction{
					Name:        "search_docs",
					Description: "Search documentation repository",
					Parameters: map[string]any{
						"type": "object",
						"properties": map[string]any{
							"query": map[string]any{"type": "string"},
						},
					},
				},
			},
		},
	}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		constraints, caps, err := validator.ValidateAndResolveConstraints(req, req.Model)
		if err != nil || constraints == nil || caps == nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkStreamingDeltaExtraction(b *testing.B) {
	rawChunkJSON := []byte(`{
		"id": "chatcmpl-bench-123",
		"object": "chat.completion.chunk",
		"created": 1700000000,
		"model": "deepseek-reasoner",
		"choices": [
			{
				"index": 0,
				"delta": {
					"role": "assistant",
					"reasoning_content": "We need to analyze the memory profile and avoid unnecessary heap escapes.",
					"content": "To reduce allocations, use sync.Pool and preallocate slices."
				},
				"finish_reason": null
			}
		],
		"usage": {
			"prompt_tokens": 25,
			"completion_tokens": 18,
			"total_tokens": 43
		}
	}`)

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		var raw struct {
			ID      string `json:"id"`
			Created int64  `json:"created"`
			Model   string `json:"model"`
			Choices []struct {
				Index int `json:"index"`
				Delta struct {
					Role             string                     `json:"role,omitempty"`
					Content          string                     `json:"content,omitempty"`
					ReasoningContent string                     `json:"reasoning_content,omitempty"`
					ToolCalls        []domain.CanonicalToolCall `json:"tool_calls,omitempty"`
				} `json:"delta"`
				FinishReason *string `json:"finish_reason,omitempty"`
			} `json:"choices"`
			Usage *domain.TokenUsage `json:"usage,omitempty"`
		}
		if err := json.Unmarshal(rawChunkJSON, &raw); err != nil {
			b.Fatal(err)
		}
		if len(raw.Choices) > 0 {
			_ = raw.Choices[0].Delta.ReasoningContent
			_ = raw.Choices[0].Delta.Content
		}
	}
}

func BenchmarkDynamicProviderResolution(b *testing.B) {
	profileReg := openaicompat.NewProfileRegistry(nil)
	mainReg := adapter.NewRegistry()
	mainReg.SetDynamicResolver(profileReg.DynamicResolver())

	providers := []domain.ProviderType{"groq", "deepseek", "together", "azure"}

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		p := providers[i%len(providers)]
		adp, err := mainReg.Get(p)
		if err != nil || adp == nil {
			b.Fatal(err)
		}
	}
}
