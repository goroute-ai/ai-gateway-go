package cohere_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/adapter/cohere"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

func TestCohere_Extensions_ToolChoice_Schema_Thinking_Citations(t *testing.T) {
	var captured map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &captured)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"id": "ch_1",
			"message": {
				"role": "assistant",
				"content": [{"type": "thinking", "thinking": "step 1"}, {"type": "text", "text": "answer"}],
				"citations": [{"start": 0, "end": 6, "sources": [{"type": "document", "id": "d1", "document": {"url": "https://example.com", "title": "Ex"}}]}]
			},
			"finish_reason": "COMPLETE",
			"usage": {"tokens": {"input_tokens": 10, "output_tokens": 5}}
		}`))
	}))
	defer srv.Close()

	adp := cohere.NewAdapter(srv.Client(), nil)
	dep := &domain.Deployment{
		ID:          "dep-coh-ext",
		GlobalModel: &domain.GlobalModel{ID: "cohere/command-a-reasoning-08-2025", Provider: domain.ProviderCohere, ModelName: "command-a-reasoning-08-2025"},
		Credential:  &domain.ProviderCredential{BaseURL: srv.URL, DecryptedAPIKey: "coh-test"},
	}

	resp, err := adp.ChatCompletion(context.Background(), dep, &domain.CanonicalChatRequest{
		Model:           "command-a-reasoning-08-2025",
		ReasoningEffort: "high",
		ToolChoice:      "required",
		ResponseFormat:  &domain.ResponseFormat{Type: "json_schema", JSONSchema: map[string]any{"schema": map[string]any{"type": "object"}}},
		Messages:        []domain.CanonicalMessage{{Role: "user", Content: "hi"}},
	})
	if err != nil {
		t.Fatalf("ChatCompletion failed: %v", err)
	}
	if captured["tool_choice"] != "REQUIRED" {
		t.Fatalf("expected tool_choice=REQUIRED, got %v", captured["tool_choice"])
	}
	if rf := captured["response_format"].(map[string]any); rf["type"] != "json_object" || rf["schema"] == nil {
		t.Fatalf("expected response_format with schema, got %#v", rf)
	}
	if th := captured["thinking"].(map[string]any); th["type"] != "enabled" || th["token_budget"] != float64(8192) {
		t.Fatalf("expected thinking token_budget=8192, got %#v", th)
	}
	if resp.Choices[0].Message.ReasoningContent != "step 1" {
		t.Fatalf("expected ReasoningContent='step 1', got %q", resp.Choices[0].Message.ReasoningContent)
	}
	if len(resp.Choices[0].Message.Annotations) != 1 || resp.Choices[0].Message.Annotations[0].URLCitation.URL != "https://example.com" {
		t.Fatalf("expected citation annotation, got %#v", resp.Choices[0].Message.Annotations)
	}
}
