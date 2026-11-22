package openrouter_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/adapter"
	"github.com/goroute-ai/ai-gateway-go/internal/adapter/openrouter"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
)

func testPolicy(t *testing.T) *network.Policy {
	t.Helper()
	pol, err := network.NewPolicy(config.OutboundSSRFConfig{
		AllowPrivateNetworks: true,
		AllowInsecureHTTP:    true,
	})
	if err != nil {
		t.Fatalf("NewPolicy: %v", err)
	}
	return pol
}

func TestOpenRouterAdapter_ChatReasoningStreamAndModels(t *testing.T) {
	ctx := context.Background()
	var capturedChat map[string]any

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/chat/completions" {
			if r.Header.Get("Authorization") != "Bearer sk-or-test" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			if r.Header.Get("HTTP-Referer") == "" || r.Header.Get("X-Title") == "" {
				http.Error(w, "missing attribution headers", http.StatusBadRequest)
				return
			}
			body, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(body, &capturedChat)
			if stream, _ := capturedChat["stream"].(bool); stream {
				w.Header().Set("Content-Type", "text/event-stream")
				fmt.Fprint(w, "data: {\"id\":\"gen-1\",\"created\":1700000000,\"model\":\"openai/gpt-4o-mini\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"reasoning\":\"thinking\",\"content\":\"OK\"}}]}\n\n")
				fmt.Fprint(w, "data: {\"id\":\"gen-1\",\"created\":1700000000,\"model\":\"openai/gpt-4o-mini\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":6,\"completion_tokens\":2,\"total_tokens\":8}}\n\n")
				fmt.Fprint(w, "data: [DONE]\n\n")
				return
			}
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"id":"gen-1","object":"chat.completion","created":1700000000,"model":"openai/gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","reasoning":"chain","content":"OK"},"finish_reason":"stop"}],"usage":{"prompt_tokens":6,"completion_tokens":2,"total_tokens":8}}`)
			return
		}
		if r.URL.Path == "/models" {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"data":[{"id":"openai/gpt-4o-mini","name":"GPT-4o mini","context_length":128000,"pricing":{"prompt":"0.00000015","completion":"0.0000006"}}]}`)
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	adp := openrouter.NewAdapter(srv.Client())
	adp.SetSSRFPolicy(testPolicy(t))

	dep := &domain.Deployment{
		ID: "dep-openrouter",
		Credential: &domain.ProviderCredential{
			Provider:        domain.ProviderOpenRouter,
			BaseURL:         srv.URL,
			DecryptedAPIKey: "sk-or-test",
		},
		GlobalModel: &domain.GlobalModel{ModelName: "openai/gpt-4o-mini"},
	}

	resp, err := adp.ChatCompletion(ctx, dep, &domain.CanonicalChatRequest{
		Model:           "openai/gpt-4o-mini",
		Messages:        []domain.CanonicalMessage{{Role: "user", Content: "hi"}},
		ReasoningEffort: "low",
	})
	if err != nil {
		t.Fatalf("ChatCompletion: %v", err)
	}
	if resp.Provider != domain.ProviderOpenRouter || resp.Choices[0].Message.ReasoningContent != "chain" {
		t.Fatalf("unexpected openrouter response: %+v", resp)
	}
	reasoningCfg, ok := capturedChat["reasoning"].(map[string]any)
	if !ok || reasoningCfg["effort"] != "low" {
		t.Fatalf("expected openrouter reasoning config effort=low, got %#v", capturedChat["reasoning"])
	}

	var text, reasoning strings.Builder
	usage, err := adp.StreamChatCompletion(ctx, dep, &domain.CanonicalChatRequest{
		Model:    "openai/gpt-4o-mini",
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "hi"}},
	}, func(c *domain.CanonicalStreamChunk) error {
		if len(c.Choices) > 0 {
			text.WriteString(c.Choices[0].Delta.Content)
			reasoning.WriteString(c.Choices[0].Delta.ReasoningContent)
		}
		return nil
	})
	if err != nil || text.String() != "OK" || reasoning.String() != "thinking" || usage.TotalTokens != 8 {
		t.Fatalf("StreamChatCompletion failed: text=%q reasoning=%q usage=%+v err=%v", text.String(), reasoning.String(), usage, err)
	}

	models, err := adp.ListModels(ctx, dep.Credential)
	if err != nil || len(models) != 1 || models[0].ModelName != "openai/gpt-4o-mini" {
		t.Fatalf("ListModels failed: models=%+v err=%v", models, err)
	}
	if _, ok := any(adp).(adapter.PrefillSupportChecker); !ok {
		t.Fatal("expected PrefillSupportChecker implementation")
	}
}
