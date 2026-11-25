package ollama_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/adapter"
	"github.com/goroute-ai/ai-gateway-go/internal/adapter/ollama"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
)

func testLoopbackPolicy(t *testing.T) *network.Policy {
	t.Helper()
	pol, err := network.NewPolicy(config.OutboundSSRFConfig{
		AllowLoopbackHTTP: true,
	})
	if err != nil {
		t.Fatalf("NewPolicy: %v", err)
	}
	return pol
}

func TestOllamaAdapter_ChatStreamCompletionEmbeddingsAndTags(t *testing.T) {
	ctx := t.Context()
	var capturedChat map[string]any
	var lastAuthHeader string
	var lastCustomHeader string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lastAuthHeader = r.Header.Get("Authorization")
		lastCustomHeader = r.Header.Get("X-Ollama-Tenant")

		switch r.URL.Path {
		case "/v1/chat/completions":
			body, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(body, &capturedChat)
			if stream, _ := capturedChat["stream"].(bool); stream {
				w.Header().Set("Content-Type", "text/event-stream")
				fmt.Fprint(w, "data: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"created\":1700000000,\"model\":\"qwen2.5:0.5b\",\"system_fingerprint\":\"fp_ollama\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"reasoning\":\"step1\",\"content\":\"Hi\"}}]}\n\n")
				fmt.Fprint(w, "data: {\"id\":\"chatcmpl-1\",\"object\":\"chat.completion.chunk\",\"created\":1700000000,\"model\":\"qwen2.5:0.5b\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"!\"},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":10,\"prompt_tokens_details\":{\"cached_tokens\":4},\"completion_tokens\":2,\"total_tokens\":12}}\n\n")
				fmt.Fprint(w, "data: [DONE]\n\n")
				return
			}
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"id":"chatcmpl-1","object":"chat.completion","created":1700000000,"model":"qwen2.5:0.5b","system_fingerprint":"fp_ollama","choices":[{"index":0,"message":{"role":"assistant","content":"OK","reasoning_content":"thought","tool_calls":[{"id":"call_1","index":0,"type":"function","function":{"name":"get_weather","arguments":"{\"city\":\"Tokyo\"}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":14,"prompt_tokens_details":{"cached_tokens":6},"completion_tokens":8,"completion_tokens_details":{"reasoning_tokens":3},"total_tokens":22}}`)
		case "/v1/completions":
			body, _ := io.ReadAll(r.Body)
			var payload map[string]any
			_ = json.Unmarshal(body, &payload)
			if stream, _ := payload["stream"].(bool); stream {
				w.Header().Set("Content-Type", "text/event-stream")
				fmt.Fprint(w, "data: {\"id\":\"cmpl-1\",\"object\":\"text_completion\",\"created\":1700000000,\"model\":\"qwen2.5:0.5b\",\"choices\":[{\"index\":0,\"text\":\"4\",\"finish_reason\":\"stop\"}]}\n\n")
				fmt.Fprint(w, "data: [DONE]\n\n")
				return
			}
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"id":"cmpl-1","object":"text_completion","created":1700000000,"model":"qwen2.5:0.5b","choices":[{"index":0,"text":"4","finish_reason":"stop"}],"usage":{"prompt_tokens":5,"completion_tokens":1,"total_tokens":6}}`)
		case "/v1/embeddings":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"object":"list","model":"all-minilm:latest","data":[{"object":"embedding","index":0,"embedding":[0.1,0.2]},{"object":"embedding","index":1,"embedding":[0.3,0.4]}],"usage":{"prompt_tokens":6,"total_tokens":6}}`)
		case "/api/tags":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"models":[{"name":"qwen2.5:0.5b","model":"qwen2.5:0.5b","modified_at":"2026-11-25T13:29:15Z","details":{"context_length":32768},"capabilities":["completion","tools"]},{"name":"all-minilm:latest","model":"all-minilm:latest","modified_at":"2026-11-25T13:29:24Z","capabilities":["embedding"]}]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	adp := ollama.NewAdapter(srv.Client())
	adp.SetSSRFPolicy(testLoopbackPolicy(t))

	if adp.Provider() != domain.ProviderOllama {
		t.Fatalf("Provider() = %q, want ollama", adp.Provider())
	}
	if !adp.SupportsOperation(domain.OperationChat) || !adp.SupportsOperation(domain.OperationCompletion) || !adp.SupportsOperation(domain.OperationEmbedding) {
		t.Fatal("expected ollama to support chat, completion, and embedding operations")
	}
	if adp.SupportsOperation(domain.OperationAudioSTT) {
		t.Fatal("expected ollama not to support audio_stt")
	}
	if !adapter.SupportsAssistantPrefill(adp) {
		t.Fatal("expected SupportsAssistantPrefill to be true")
	}

	// 1. Keyless local deployment (no API key -> no Authorization header).
	dep := &domain.Deployment{
		ID: "dep-ollama-local",
		Credential: &domain.ProviderCredential{
			Provider: domain.ProviderOllama,
			BaseURL:  srv.URL,
			Headers:  map[string]string{"X-Ollama-Tenant": "local-dev"},
		},
		GlobalModel: &domain.GlobalModel{ModelName: "qwen2.5:0.5b"},
	}

	chatResp, err := adp.ChatCompletion(ctx, dep, &domain.CanonicalChatRequest{
		Model:           "qwen2.5:0.5b",
		Messages:        []domain.CanonicalMessage{{Role: "user", Content: "hi"}},
		ReasoningEffort: "low",
		ExtraParams: map[string]any{
			"model":      "evil-override",
			"keep_alive": "0",
			"options":    map[string]any{"num_ctx": 4096},
		},
	})
	if err != nil {
		t.Fatalf("ChatCompletion: %v", err)
	}
	if lastAuthHeader != "" {
		t.Fatalf("expected empty Authorization header for keyless Ollama, got %q", lastAuthHeader)
	}
	if lastCustomHeader != "local-dev" {
		t.Fatalf("expected custom header X-Ollama-Tenant=local-dev, got %q", lastCustomHeader)
	}
	if capturedChat["model"] != "qwen2.5:0.5b" {
		t.Fatalf("ExtraParams overwrote reserved model field: %#v", capturedChat["model"])
	}
	if _, leaked := capturedChat["keep_alive"]; leaked {
		t.Fatalf("expected ExtraParams keep_alive to be stripped to prevent VRAM eviction, got %#v", capturedChat["keep_alive"])
	}
	opts, ok := capturedChat["options"].(map[string]any)
	if !ok || opts["num_ctx"] != float64(4096) {
		t.Fatalf("expected safe ExtraParams options.num_ctx=4096 to pass through, got %#v", capturedChat["options"])
	}
	if chatResp.Provider != domain.ProviderOllama || chatResp.Usage.CachedPromptTokens != 6 || chatResp.Usage.ReasoningTokens != 3 {
		t.Fatalf("unexpected chat response/usage: %+v", chatResp)
	}
	if len(chatResp.Choices) != 1 || len(chatResp.Choices[0].Message.ToolCalls) != 1 || chatResp.Choices[0].Message.ReasoningContent != "thought" {
		t.Fatalf("unexpected chat choice: %+v", chatResp.Choices)
	}

	// 2. Streaming chat with /v1 suffix already present on BaseURL (no double /v1/v1) + optional Bearer key.
	v1Dep := &domain.Deployment{
		ID: "dep-ollama-v1",
		Credential: &domain.ProviderCredential{
			Provider:        domain.ProviderOllama,
			BaseURL:         srv.URL + "/v1",
			DecryptedAPIKey: "ollama-cloud-secret",
		},
		GlobalModel: &domain.GlobalModel{ModelName: "qwen2.5:0.5b"},
	}
	var streamedText, streamedReasoning strings.Builder
	usage, err := adp.StreamChatCompletion(ctx, v1Dep, &domain.CanonicalChatRequest{
		Model:    "qwen2.5:0.5b",
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "hi"}},
	}, func(c *domain.CanonicalStreamChunk) error {
		if len(c.Choices) > 0 {
			streamedText.WriteString(c.Choices[0].Delta.Content)
			streamedReasoning.WriteString(c.Choices[0].Delta.ReasoningContent)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("StreamChatCompletion: %v", err)
	}
	if lastAuthHeader != "Bearer ollama-cloud-secret" {
		t.Fatalf("expected Bearer auth when key is configured, got %q", lastAuthHeader)
	}
	if streamedText.String() != "Hi!" || streamedReasoning.String() != "step1" || usage.TotalTokens != 12 || usage.CachedPromptTokens != 4 {
		t.Fatalf("unexpected stream result: text=%q reasoning=%q usage=%+v", streamedText.String(), streamedReasoning.String(), usage)
	}

	// 3. TextCompletion & StreamTextCompletion.
	compResp, err := adp.TextCompletion(ctx, dep, &domain.CanonicalCompletionRequest{
		Model:  "qwen2.5:0.5b",
		Prompt: domain.CompletionPrompt{Strings: []string{"2+2="}},
	})
	if err != nil || len(compResp.Choices) != 1 || compResp.Choices[0].Text != "4" {
		t.Fatalf("TextCompletion failed: resp=%+v err=%v", compResp, err)
	}
	ch, err := adp.StreamTextCompletion(ctx, dep, &domain.CanonicalCompletionRequest{
		Model:  "qwen2.5:0.5b",
		Prompt: domain.CompletionPrompt{Strings: []string{"2+2="}},
	})
	if err != nil {
		t.Fatalf("StreamTextCompletion: %v", err)
	}
	var compStreamed strings.Builder
	for chunk := range ch {
		if len(chunk.Choices) > 0 {
			compStreamed.WriteString(chunk.Choices[0].Delta.Content)
		}
	}
	if compStreamed.String() != "4" {
		t.Fatalf("StreamTextCompletion text=%q, want 4", compStreamed.String())
	}

	// 4. Embeddings.
	embResp, err := adp.Embeddings(ctx, dep, &domain.CanonicalEmbeddingRequest{
		Model: "all-minilm:latest",
		Input: []string{"hello", "world"},
	})
	if err != nil || len(embResp.Data) != 2 || embResp.Usage.PromptTokens != 6 || embResp.Provider != domain.ProviderOllama {
		t.Fatalf("Embeddings failed: resp=%+v err=%v", embResp, err)
	}

	// 5. ListModels via /api/tags (works even when BaseURL has /v1 suffix).
	models, err := adp.ListModels(ctx, v1Dep.Credential)
	if err != nil || len(models) != 2 || models[0].ModelName != "qwen2.5:0.5b" || models[1].ModelName != "all-minilm:latest" {
		t.Fatalf("ListModels (/api/tags) failed: models=%+v err=%v", models, err)
	}
}

func TestOllamaAdapter_ListModelsFallbackAndErrors(t *testing.T) {
	ctx := t.Context()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/tags":
			http.NotFound(w, r)
		case "/v1/models":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"object":"list","data":[{"id":"llama3.2:latest","created":1700000000}]}`)
		case "/v1/chat/completions":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"error":"model 'missing' not found"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	adp := ollama.NewAdapter(srv.Client())
	adp.SetSSRFPolicy(testLoopbackPolicy(t))

	cred := &domain.ProviderCredential{Provider: domain.ProviderOllama, BaseURL: srv.URL}
	models, err := adp.ListModels(ctx, cred)
	if err != nil || len(models) != 1 || models[0].ModelName != "llama3.2:latest" {
		t.Fatalf("ListModels fallback (/v1/models) failed: models=%+v err=%v", models, err)
	}

	_, err = adp.ChatCompletion(ctx, &domain.Deployment{Credential: cred}, &domain.CanonicalChatRequest{
		Model:    "missing",
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "hi"}},
	})
	var gwErr *domain.GatewayError
	if !errors.As(err, &gwErr) {
		t.Fatalf("expected *domain.GatewayError, got %T (%v)", err, err)
	}
	if gwErr.StatusCode != http.StatusNotFound || !strings.Contains(gwErr.Message, "missing") {
		t.Fatalf("unexpected GatewayError: %+v", gwErr)
	}
}

func TestOllamaAdapter_SSRFFailsClosedWithoutLoopbackPolicy(t *testing.T) {
	strictPol, err := network.NewPolicy(config.OutboundSSRFConfig{})
	if err != nil {
		t.Fatalf("NewPolicy: %v", err)
	}
	adp := ollama.NewAdapter(nil)
	adp.SetSSRFPolicy(strictPol)

	_, err = adp.ChatCompletion(context.Background(), &domain.Deployment{
		Credential: &domain.ProviderCredential{Provider: domain.ProviderOllama},
	}, &domain.CanonicalChatRequest{
		Model:    "qwen2.5:0.5b",
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "hi"}},
	})
	var gwErr *domain.GatewayError
	if !errors.As(err, &gwErr) || gwErr.Code != "invalid_base_url" {
		t.Fatalf("expected invalid_base_url GatewayError under strict SSRF policy, got %v", err)
	}
}
