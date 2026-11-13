package anthropic_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/adapter/anthropic"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

func TestAnthropic_Extensions_PayloadAndCacheAccounting(t *testing.T) {
	var captured map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &captured)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"id": "msg_1",
			"type": "message",
			"role": "assistant",
			"model": "claude-sonnet-4-6",
			"content": [
				{"type": "tool_use", "id": "tu_1", "name": "weather_get_forecast", "input": {"city": "NYC"}}
			],
			"stop_reason": "tool_use",
			"usage": {
				"input_tokens": 100,
				"output_tokens": 20,
				"cache_read_input_tokens": 60,
				"cache_creation_input_tokens": 30
			}
		}`))
	}))
	defer srv.Close()

	adp := anthropic.NewAdapter(srv.Client())
	dep := &domain.Deployment{
		ID: "dep-ant-ext",
		GlobalModel: &domain.GlobalModel{
			ID:        "anthropic/claude-sonnet-4-6",
			Provider:  domain.ProviderAnthropic,
			ModelName: "claude-sonnet-4-6",
		},
		Credential: &domain.ProviderCredential{
			BaseURL:         srv.URL,
			DecryptedAPIKey: "sk-ant-test",
		},
	}

	imgB64 := base64.StdEncoding.EncodeToString([]byte("img"))
	docB64 := base64.StdEncoding.EncodeToString([]byte("%PDF"))
	req := &domain.CanonicalChatRequest{
		Model:           "claude-sonnet-4-6",
		ReasoningEffort: "high",
		ToolChoice: map[string]any{
			"type":     "function",
			"function": map[string]any{"name": "weather.get/forecast"},
		},
		Tools: []domain.CanonicalTool{
			{
				Type:         "function",
				CacheControl: &domain.CacheControl{Type: "ephemeral"},
				Function: domain.CanonicalFunction{
					Name:        "weather.get/forecast",
					Description: "Get weather",
					Parameters:  map[string]any{"type": "object"},
				},
			},
		},
		ResponseFormat: &domain.ResponseFormat{
			Type: "json_schema",
			JSONSchema: map[string]any{
				"schema": map[string]any{"type": "object", "properties": map[string]any{"ok": map[string]any{"type": "boolean"}}},
			},
		},
		Messages: []domain.CanonicalMessage{
			{Role: "system", Content: "Be concise.", CacheControl: &domain.CacheControl{Type: "ephemeral"}},
			{
				Role: "user",
				Parts: []domain.ContentPart{
					{Type: "text", Text: "Look"},
					{Type: "image_url", ImageURL: &domain.ImageURL{URL: "data:image/png;base64," + imgB64}},
					{Type: "document", Document: &domain.DocumentPart{MimeType: "application/pdf", Data: docB64}},
				},
			},
		},
	}

	resp, err := adp.ChatCompletion(context.Background(), dep, req)
	if err != nil {
		t.Fatalf("ChatCompletion failed: %v", err)
	}

	// PromptTokens must equal InputTokens + CacheReadInputTokens (100 + 60 = 160)
	if resp.Usage.PromptTokens != 160 {
		t.Fatalf("expected PromptTokens=160, got %d", resp.Usage.PromptTokens)
	}
	if resp.Usage.CachedPromptTokens != 60 || resp.Usage.CacheCreationTokens != 30 {
		t.Fatalf("expected cached=60 cache_creation=30, got %d / %d", resp.Usage.CachedPromptTokens, resp.Usage.CacheCreationTokens)
	}
	// Tool name reverse-mapped from weather_get_forecast -> weather.get/forecast
	if len(resp.Choices[0].Message.ToolCalls) != 1 || resp.Choices[0].Message.ToolCalls[0].Function.Name != "weather.get/forecast" {
		t.Fatalf("expected reverse-mapped tool name weather.get/forecast, got %#v", resp.Choices[0].Message.ToolCalls)
	}

	// Adaptive thinking for Claude 4.6
	thinking, ok := captured["thinking"].(map[string]any)
	if !ok || thinking["type"] != "adaptive" {
		t.Fatalf("expected adaptive thinking for 4.6 model, got %#v", captured["thinking"])
	}
	outCfg, ok := captured["output_config"].(map[string]any)
	if !ok || outCfg["effort"] != "high" {
		t.Fatalf("expected output_config.effort=high, got %#v", captured["output_config"])
	}
	if _, ok := captured["output_format"].(map[string]any); !ok {
		t.Fatalf("expected output_format in payload, got %#v", captured["output_format"])
	}
	// System array with cache_control
	sysArr, ok := captured["system"].([]any)
	if !ok || len(sysArr) != 1 {
		t.Fatalf("expected system array with cache_control, got %#v", captured["system"])
	}
	// Tool choice sanitized
	tc := captured["tool_choice"].(map[string]any)
	if tc["type"] != "tool" || tc["name"] != "weather_get_forecast" {
		t.Fatalf("expected sanitized tool_choice, got %#v", tc)
	}
}

func TestAnthropic_ReasoningPreservesExplicitMaxTokens(t *testing.T) {
	var captured map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&captured)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","role":"assistant","model":"claude-3-7-sonnet","content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn","usage":{"input_tokens":1,"output_tokens":1}}`))
	}))
	defer srv.Close()

	adp := anthropic.NewAdapter(srv.Client())
	maxTokens := 1500
	_, err := adp.ChatCompletion(context.Background(), &domain.Deployment{
		GlobalModel: &domain.GlobalModel{Provider: domain.ProviderAnthropic, ModelName: "claude-3-7-sonnet"},
		Credential:  &domain.ProviderCredential{BaseURL: srv.URL, DecryptedAPIKey: "sk-ant-test"},
	}, &domain.CanonicalChatRequest{
		Model: "claude-3-7-sonnet", MaxTokens: &maxTokens, ReasoningEffort: "high",
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "solve"}},
	})
	if err != nil {
		t.Fatalf("ChatCompletion: %v", err)
	}
	if captured["max_tokens"] != float64(maxTokens) {
		t.Fatalf("max_tokens = %v, want explicit limit %d", captured["max_tokens"], maxTokens)
	}
	thinking := captured["thinking"].(map[string]any)
	if thinking["budget_tokens"] != float64(maxTokens-1) {
		t.Fatalf("thinking budget = %v, want %d below max_tokens", thinking["budget_tokens"], maxTokens-1)
	}
}

func TestAnthropic_ReasoningRejectsImpossibleExplicitMaxTokens(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { calls++ }))
	defer srv.Close()

	adp := anthropic.NewAdapter(srv.Client())
	maxTokens := 1024
	_, err := adp.ChatCompletion(context.Background(), &domain.Deployment{
		GlobalModel: &domain.GlobalModel{Provider: domain.ProviderAnthropic, ModelName: "claude-3-7-sonnet"},
		Credential:  &domain.ProviderCredential{BaseURL: srv.URL, DecryptedAPIKey: "sk-ant-test"},
	}, &domain.CanonicalChatRequest{
		Model: "claude-3-7-sonnet", MaxTokens: &maxTokens, ReasoningEffort: "high",
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "solve"}},
	})
	if err == nil || calls != 0 {
		t.Fatalf("expected invalid request before dispatch, err=%v calls=%d", err, calls)
	}
}

func TestAnthropic_LegacyThinkingBudgetAndStreamReverseMap(t *testing.T) {
	var captured map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &captured)
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"m1\",\"model\":\"claude-3-7-sonnet\",\"usage\":{\"input_tokens\":80,\"cache_read_input_tokens\":20,\"cache_creation_input_tokens\":10}}}\n\n"))
		_, _ = w.Write([]byte("event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"tool_use\",\"id\":\"tu_2\",\"name\":\"a_b_c\"}}\n\n"))
		_, _ = w.Write([]byte("event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{}\"}}\n\n"))
		_, _ = w.Write([]byte("event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"tool_use\"},\"usage\":{\"output_tokens\":12}}\n\n"))
	}))
	defer srv.Close()

	adp := anthropic.NewAdapter(srv.Client())
	dep := &domain.Deployment{
		ID: "dep-ant-legacy",
		GlobalModel: &domain.GlobalModel{
			ID:        "anthropic/claude-3-7-sonnet",
			Provider:  domain.ProviderAnthropic,
			ModelName: "claude-3-7-sonnet",
		},
		Credential: &domain.ProviderCredential{
			BaseURL:         srv.URL,
			DecryptedAPIKey: "sk-ant-test",
		},
	}
	req := &domain.CanonicalChatRequest{
		Model:           "claude-3-7-sonnet",
		ReasoningEffort: "medium",
		Tools: []domain.CanonicalTool{
			{Type: "function", Function: domain.CanonicalFunction{Name: "a.b:c", Parameters: map[string]any{"type": "object"}}},
		},
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "hi"}},
	}

	var toolName string
	usage, err := adp.StreamChatCompletion(context.Background(), dep, req, func(chunk *domain.CanonicalStreamChunk) error {
		for _, c := range chunk.Choices {
			for _, tc := range c.Delta.ToolCalls {
				if tc.Function.Name != "" {
					toolName = tc.Function.Name
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("StreamChatCompletion failed: %v", err)
	}
	if toolName != "a.b:c" {
		t.Fatalf("expected reverse-mapped stream tool name a.b:c, got %q", toolName)
	}
	if usage.PromptTokens != 100 || usage.CachedPromptTokens != 20 || usage.CacheCreationTokens != 10 {
		t.Fatalf("unexpected stream usage: %+v", usage)
	}
	thinking := captured["thinking"].(map[string]any)
	if thinking["type"] != "enabled" || thinking["budget_tokens"] != float64(4096) {
		t.Fatalf("expected enabled thinking with budget_tokens=4096, got %#v", thinking)
	}
}
