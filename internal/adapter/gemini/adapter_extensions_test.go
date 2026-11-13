package gemini_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/adapter/gemini"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

func TestGemini_Extensions_ThinkingLevel_Schema_ToolChoice_Parts(t *testing.T) {
	var captured map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &captured)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"candidates": [{
				"content": {"role": "model", "parts": [{"thought": true, "text": "hmm"}, {"text": "{\"ok\":true}"}]},
				"finishReason": "STOP"
			}],
			"usageMetadata": {"promptTokenCount": 10, "candidatesTokenCount": 5, "totalTokenCount": 15}
		}`))
	}))
	defer srv.Close()

	adp := gemini.NewAdapter(srv.Client())
	dep := &domain.Deployment{
		ID: "dep-gem-ext",
		GlobalModel: &domain.GlobalModel{
			ID:        "gemini/gemini-3-flash-preview",
			Provider:  domain.ProviderGemini,
			ModelName: "gemini-3-flash-preview",
		},
		Credential: &domain.ProviderCredential{
			BaseURL:         srv.URL,
			DecryptedAPIKey: "gem-test-key",
		},
	}

	imgB64 := base64.StdEncoding.EncodeToString([]byte("img"))
	pdfB64 := base64.StdEncoding.EncodeToString([]byte("%PDF"))
	req := &domain.CanonicalChatRequest{
		Model:           "gemini-3-flash-preview",
		ReasoningEffort: "high",
		ToolChoice: map[string]any{
			"type":     "function",
			"function": map[string]any{"name": "lookup"},
		},
		Tools: []domain.CanonicalTool{
			{Type: "function", Function: domain.CanonicalFunction{Name: "lookup", Parameters: map[string]any{"type": "object"}}},
		},
		ResponseFormat: &domain.ResponseFormat{
			Type: "json_schema",
			JSONSchema: map[string]any{
				"schema": map[string]any{"type": "object", "properties": map[string]any{"ok": map[string]any{"type": "boolean"}}},
			},
		},
		Messages: []domain.CanonicalMessage{
			{
				Role: "user",
				Parts: []domain.ContentPart{
					{Type: "text", Text: "Analyze"},
					{Type: "image_url", ImageURL: &domain.ImageURL{URL: "data:image/png;base64," + imgB64}},
					{Type: "document", Document: &domain.DocumentPart{MimeType: "application/pdf", Data: pdfB64}},
				},
			},
		},
	}

	resp, err := adp.ChatCompletion(context.Background(), dep, req)
	if err != nil {
		t.Fatalf("ChatCompletion failed: %v", err)
	}
	if resp.Choices[0].Message.ReasoningContent != "hmm" {
		t.Fatalf("expected ReasoningContent='hmm', got %q", resp.Choices[0].Message.ReasoningContent)
	}

	genCfg := captured["generationConfig"].(map[string]any)
	tc := genCfg["thinkingConfig"].(map[string]any)
	if tc["thinkingLevel"] != "HIGH" {
		t.Fatalf("expected thinkingLevel=HIGH for gemini-3, got %#v", tc)
	}
	if genCfg["responseMimeType"] != "application/json" {
		t.Fatalf("expected responseMimeType=application/json, got %#v", genCfg)
	}
	if _, ok := genCfg["responseJsonSchema"].(map[string]any); !ok {
		t.Fatalf("expected responseJsonSchema in generationConfig, got %#v", genCfg)
	}

	toolCfg := captured["toolConfig"].(map[string]any)
	fcc := toolCfg["functionCallingConfig"].(map[string]any)
	if fcc["mode"] != "ANY" {
		t.Fatalf("expected functionCallingConfig.mode=ANY, got %#v", fcc)
	}

	contents := captured["contents"].([]any)
	parts := contents[0].(map[string]any)["parts"].([]any)
	if len(parts) != 3 {
		t.Fatalf("expected 3 parts (text, inlineData image, inlineData pdf), got %d", len(parts))
	}
}

func TestGemini_25_ThinkingBudget(t *testing.T) {
	var captured map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &captured)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"candidates":[{"content":{"role":"model","parts":[{"text":"ok"}]},"finishReason":"STOP"}]}`))
	}))
	defer srv.Close()

	adp := gemini.NewAdapter(srv.Client())
	dep := &domain.Deployment{
		ID:          "dep-gem-25",
		GlobalModel: &domain.GlobalModel{ID: "gemini/gemini-2.5-pro", Provider: domain.ProviderGemini, ModelName: "gemini-2.5-pro"},
		Credential:  &domain.ProviderCredential{BaseURL: srv.URL, DecryptedAPIKey: "gem-test-key"},
	}
	_, err := adp.ChatCompletion(context.Background(), dep, &domain.CanonicalChatRequest{
		Model:           "gemini-2.5-pro",
		ReasoningEffort: "medium",
		Messages:        []domain.CanonicalMessage{{Role: "user", Content: "hi"}},
	})
	if err != nil {
		t.Fatalf("ChatCompletion failed: %v", err)
	}
	tc := captured["generationConfig"].(map[string]any)["thinkingConfig"].(map[string]any)
	if tc["thinkingBudget"] != float64(4096) {
		t.Fatalf("expected thinkingBudget=4096, got %#v", tc)
	}
}

func TestGemini_25_ReasoningNoneDisablesThinking(t *testing.T) {
	var captured map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &captured)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"candidates":[{"content":{"role":"model","parts":[{"text":"ok"}]},"finishReason":"STOP"}]}`))
	}))
	defer srv.Close()

	adp := gemini.NewAdapter(srv.Client())
	dep := &domain.Deployment{
		ID:          "dep-gem-25-none",
		GlobalModel: &domain.GlobalModel{ID: "gemini/gemini-2.5-pro", Provider: domain.ProviderGemini, ModelName: "gemini-2.5-pro"},
		Credential:  &domain.ProviderCredential{BaseURL: srv.URL, DecryptedAPIKey: "gem-test-key"},
	}
	_, err := adp.ChatCompletion(context.Background(), dep, &domain.CanonicalChatRequest{
		Model: "gemini-2.5-pro", ReasoningEffort: "none", Messages: []domain.CanonicalMessage{{Role: "user", Content: "hi"}},
	})
	if err != nil {
		t.Fatalf("ChatCompletion failed: %v", err)
	}
	tc := captured["generationConfig"].(map[string]any)["thinkingConfig"].(map[string]any)
	if tc["thinkingBudget"] != float64(0) {
		t.Fatalf("expected reasoning_effort=none to set thinkingBudget=0, got %#v", tc)
	}
}
