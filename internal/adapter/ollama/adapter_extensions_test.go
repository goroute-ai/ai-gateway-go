package ollama_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/adapter/ollama"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

func TestOllama_Tools_Vision_JSONSchema(t *testing.T) {
	var captured map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &captured)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"model": "llama3.2-vision",
			"message": {
				"role": "assistant",
				"content": "",
				"thinking": "Let me reason this out",
				"tool_calls": [{"function": {"name": "get_weather", "arguments": {"city": "Paris"}}}]
			},
			"done": true,
			"prompt_eval_count": 12,
			"eval_count": 8
		}`))
	}))
	defer srv.Close()

	adp := ollama.NewAdapter(srv.Client())
	dep := &domain.Deployment{
		ID:          "dep-oll-ext",
		GlobalModel: &domain.GlobalModel{ID: "ollama/llama3.2-vision", Provider: domain.ProviderOllama, ModelName: "llama3.2-vision"},
		Credential:  &domain.ProviderCredential{BaseURL: srv.URL},
	}

	imgB64 := base64.StdEncoding.EncodeToString([]byte("png"))
	resp, err := adp.ChatCompletion(context.Background(), dep, &domain.CanonicalChatRequest{
		Model:           "llama3.2-vision",
		ReasoningEffort: "high",
		Tools: []domain.CanonicalTool{{
			Type:     "function",
			Function: domain.CanonicalFunction{Name: "get_weather", Parameters: map[string]any{"type": "object"}},
		}},
		ResponseFormat: &domain.ResponseFormat{
			Type:       "json_schema",
			JSONSchema: map[string]any{"schema": map[string]any{"type": "object"}},
		},
		Messages: []domain.CanonicalMessage{{
			Role: "user",
			Parts: []domain.ContentPart{
				{Type: "text", Text: "Describe"},
				{Type: "image_url", ImageURL: &domain.ImageURL{URL: "data:image/png;base64," + imgB64}},
			},
		}},
	})
	if err != nil {
		t.Fatalf("ChatCompletion failed: %v", err)
	}
	if len(resp.Choices[0].Message.ToolCalls) != 1 || resp.Choices[0].Message.ToolCalls[0].Function.Name != "get_weather" {
		t.Fatalf("expected tool_call get_weather, got %#v", resp.Choices[0].Message.ToolCalls)
	}
	if resp.Choices[0].Message.ReasoningContent != "Let me reason this out" {
		t.Fatalf("expected reasoning content to be preserved, got %q", resp.Choices[0].Message.ReasoningContent)
	}
	if resp.Choices[0].FinishReason != "tool_calls" {
		t.Fatalf("expected finish_reason=tool_calls, got %q", resp.Choices[0].FinishReason)
	}
	msgs := captured["messages"].([]any)
	imgs := msgs[0].(map[string]any)["images"].([]any)
	if len(imgs) != 1 || imgs[0] != imgB64 {
		t.Fatalf("expected stripped base64 image in ollama payload, got %#v", imgs)
	}
	if _, ok := captured["format"].(map[string]any); !ok {
		t.Fatalf("expected json_schema format map in ollama payload, got %#v", captured["format"])
	}
	if _, ok := captured["tools"].([]any); !ok {
		t.Fatalf("expected tools in ollama payload")
	}
	if captured["think"] != "high" {
		t.Fatalf("expected reasoning effort to map to think=high, got %#v", captured["think"])
	}
}
