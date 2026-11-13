package vertex_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/adapter/vertex"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

func TestVertex_Gemini_Region_ToolResult_And_ThoughtTokens(t *testing.T) {
	var capturedPath string
	var capturedBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &capturedBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"candidates": [{
				"content": {"role": "model", "parts": [{"thought": true, "text": "chain"}, {"text": "42"}]},
				"finishReason": "STOP"
			}],
			"usageMetadata": {
				"promptTokenCount": 12,
				"candidatesTokenCount": 3,
				"thoughtsTokenCount": 7,
				"cachedContentTokenCount": 4,
				"totalTokenCount": 22
			}
		}`))
	}))
	defer srv.Close()

	adp := vertex.NewAdapter(srv.Client(), nil)
	dep := &domain.Deployment{
		ID:     "dep-vertex-global",
		Region: "global",
		GlobalModel: &domain.GlobalModel{
			ID:        "vertex_ai/gemini-2.5-pro",
			Provider:  domain.ProviderVertex,
			ModelName: "gemini-2.5-pro",
		},
		Credential: &domain.ProviderCredential{
			BaseURL:         srv.URL,
			DecryptedAPIKey: "ya29.static-token",
		},
	}

	req := &domain.CanonicalChatRequest{
		Model:           "gemini-2.5-pro",
		ReasoningEffort: "high",
		Messages: []domain.CanonicalMessage{
			{Role: "user", Content: "Weather?"},
			{Role: "assistant", ToolCalls: []domain.CanonicalToolCall{{ID: "c1", Type: "function", Function: domain.CanonicalFunctionCall{Name: "get_weather", Arguments: `{"city":"NYC"}`}}}},
			{Role: "tool", Name: "get_weather", ToolCallID: "c1", Content: `{"temp":72}`},
		},
	}

	resp, err := adp.ChatCompletion(context.Background(), dep, req)
	if err != nil {
		t.Fatalf("ChatCompletion failed: %v", err)
	}

	if !strings.Contains(capturedPath, "/locations/global/publishers/google/models/gemini-2.5-pro:generateContent") {
		t.Fatalf("expected /locations/global/ path, got %q", capturedPath)
	}
	if resp.Choices[0].Message.ReasoningContent != "chain" {
		t.Fatalf("expected ReasoningContent='chain', got %q", resp.Choices[0].Message.ReasoningContent)
	}
	if resp.Usage.ReasoningTokens != 7 || resp.Usage.CachedPromptTokens != 4 || resp.Usage.CompletionTokens != 10 {
		t.Fatalf("unexpected usage: %+v", resp.Usage)
	}

	contents := capturedBody["contents"].([]any)
	toolMsg := contents[2].(map[string]any)
	if toolMsg["role"] != "function" {
		t.Fatalf("expected role=function for tool message, got %v", toolMsg["role"])
	}
	toolPart := toolMsg["parts"].([]any)[0].(map[string]any)
	if _, ok := toolPart["functionResponse"]; !ok {
		t.Fatalf("expected functionResponse part, got %#v", toolPart)
	}
}

func TestVertex_PartnerClaude_RawPredict_And_StreamRawPredict(t *testing.T) {
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		if strings.HasSuffix(r.URL.Path, ":streamRawPredict") {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = w.Write([]byte("event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"m1\",\"usage\":{\"input_tokens\":10,\"cache_read_input_tokens\":5}}}\n\n"))
			_, _ = w.Write([]byte("event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"hello\"}}\n\n"))
			_, _ = w.Write([]byte("event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":2}}\n\n"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"id": "vr_1",
			"content": [{"type": "text", "text": "claude on vertex"}],
			"stop_reason": "end_turn",
			"usage": {"input_tokens": 10, "output_tokens": 4, "cache_read_input_tokens": 3}
		}`))
	}))
	defer srv.Close()

	adp := vertex.NewAdapter(srv.Client(), nil)
	dep := &domain.Deployment{
		ID:     "dep-vertex-claude",
		Region: "us-east5",
		GlobalModel: &domain.GlobalModel{
			ID:        "vertex_ai/claude-sonnet-4-5@20250929",
			Provider:  domain.ProviderVertex,
			ModelName: "claude-sonnet-4-5@20250929",
		},
		Credential: &domain.ProviderCredential{
			BaseURL:         srv.URL,
			DecryptedAPIKey: "ya29.static-token",
		},
	}

	req := &domain.CanonicalChatRequest{
		Model:    "claude-sonnet-4-5@20250929",
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "hi"}},
	}

	resp, err := adp.ChatCompletion(context.Background(), dep, req)
	if err != nil {
		t.Fatalf("ChatCompletion failed: %v", err)
	}
	if resp.Choices[0].Message.Content != "claude on vertex" || resp.Usage.PromptTokens != 13 {
		t.Fatalf("unexpected claude response: %+v", resp)
	}

	var streamed string
	usage, err := adp.StreamChatCompletion(context.Background(), dep, req, func(chunk *domain.CanonicalStreamChunk) error {
		if len(chunk.Choices) > 0 {
			streamed += chunk.Choices[0].Delta.Content
		}
		return nil
	})
	if err != nil {
		t.Fatalf("StreamChatCompletion failed: %v", err)
	}
	if streamed != "hello" || usage.PromptTokens != 15 || usage.CompletionTokens != 2 {
		t.Fatalf("unexpected stream result=%q usage=%+v", streamed, usage)
	}
	if len(paths) != 2 || !strings.Contains(paths[0], "/publishers/anthropic/models/") || !strings.HasSuffix(paths[0], ":rawPredict") || !strings.HasSuffix(paths[1], ":streamRawPredict") {
		t.Fatalf("unexpected vertex claude paths: %#v", paths)
	}
}
