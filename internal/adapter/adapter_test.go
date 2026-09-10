package adapter_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/adapter"
	"github.com/goroute-ai/ai-gateway-go/internal/adapter/anthropic"
	"github.com/goroute-ai/ai-gateway-go/internal/adapter/gemini"
	"github.com/goroute-ai/ai-gateway-go/internal/adapter/mistral"
	"github.com/goroute-ai/ai-gateway-go/internal/adapter/ollama"
	"github.com/goroute-ai/ai-gateway-go/internal/adapter/openai"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

func TestAllFiveProviderAdapters_ChatStreamEmbeddingsAndModels(t *testing.T) {
	ctx := context.Background()

	// 1. Mock OpenAI Server
	oaiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/chat/completions":
			if strings.Contains(r.Header.Get("Accept"), "text/event-stream") {
				w.Header().Set("Content-Type", "text/event-stream")
				fmt.Fprint(w, "data: {\"id\":\"1\",\"object\":\"chat.completion.chunk\",\"model\":\"gpt-4.1\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Hello \"}}]}\n\n")
				fmt.Fprint(w, "data: {\"id\":\"1\",\"object\":\"chat.completion.chunk\",\"model\":\"gpt-4.1\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"World\"},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":2,\"total_tokens\":12}}\n\n")
				fmt.Fprint(w, "data: [DONE]\n\n")
				return
			}
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"id":"chatcmpl-1","object":"chat.completion","created":1700000000,"model":"gpt-4.1","choices":[{"index":0,"message":{"role":"assistant","content":"OpenAI ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":8,"completion_tokens":4,"total_tokens":12}}`)
		case "/embeddings":
			fmt.Fprint(w, `{"object":"list","model":"text-embedding-3-small","data":[{"object":"embedding","index":0,"embedding":[0.1,0.2,0.3]}],"usage":{"prompt_tokens":5,"total_tokens":5}}`)
		case "/models":
			fmt.Fprint(w, `{"object":"list","data":[{"id":"gpt-4.1","object":"model","created":1700000000,"owned_by":"openai"}]}`)
		}
	}))
	defer oaiSrv.Close()

	// 2. Mock Anthropic Server
	antSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("anthropic-version") != "2023-06-01" {
			t.Errorf("expected anthropic-version header")
		}
		switch r.URL.Path {
		case "/v1/messages":
			if strings.Contains(r.Header.Get("Accept"), "text/event-stream") {
				w.Header().Set("Content-Type", "text/event-stream")
				fmt.Fprint(w, "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"model\":\"claude-sonnet-4\",\"usage\":{\"input_tokens\":15}}}\n\n")
				fmt.Fprint(w, "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Claude stream\"}}\n\n")
				fmt.Fprint(w, "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":6}}\n\n")
				return
			}
			fmt.Fprint(w, `{"id":"msg_1","type":"message","role":"assistant","model":"claude-sonnet-4","content":[{"type":"thinking","thinking":"step 1"},{"type":"text","text":"Claude ok"}],"stop_reason":"end_turn","usage":{"input_tokens":12,"output_tokens":5}}`)
		case "/v1/models":
			fmt.Fprint(w, `{"data":[{"id":"claude-sonnet-4-20250514","display_name":"Claude Sonnet 4","type":"model"}]}`)
		}
	}))
	defer antSrv.Close()

	// 3. Mock Gemini Server
	gemSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, ":generateContent"):
			fmt.Fprint(w, `{"candidates":[{"index":0,"content":{"role":"model","parts":[{"text":"Gemini ok"}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":9,"candidatesTokenCount":3,"totalTokenCount":12}}`)
		case strings.HasSuffix(r.URL.Path, ":streamGenerateContent"):
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprint(w, "data: {\"candidates\":[{\"index\":0,\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"Gemini stream\"}]},\"finishReason\":\"STOP\"}],\"usageMetadata\":{\"promptTokenCount\":9,\"candidatesTokenCount\":4,\"totalTokenCount\":13}}\n\n")
		case strings.HasSuffix(r.URL.Path, ":embedContent"):
			fmt.Fprint(w, `{"embedding":{"values":[0.5,0.6]}}`)
		case r.URL.Path == "/v1beta/models":
			fmt.Fprint(w, `{"models":[{"name":"models/gemini-2.5-pro","displayName":"Gemini 2.5 Pro"}]}`)
		}
	}))
	defer gemSrv.Close()

	// 4. Mock Mistral Server
	misSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/chat/completions":
			fmt.Fprint(w, `{"id":"cmpl-m1","object":"chat.completion","created":1700000000,"model":"mistral-large-latest","choices":[{"index":0,"message":{"role":"assistant","content":"Mistral ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":7,"completion_tokens":3,"total_tokens":10}}`)
		case "/embeddings":
			fmt.Fprint(w, `{"id":"emb-1","object":"list","model":"mistral-embed","data":[{"object":"embedding","index":0,"embedding":[0.9,0.8]}],"usage":{"prompt_tokens":4,"total_tokens":4}}`)
		case "/models":
			fmt.Fprint(w, `{"object":"list","data":[{"id":"mistral-large-latest","object":"model"}]}`)
		}
	}))
	defer misSrv.Close()

	// 5. Mock Ollama Server (NDJSON streaming)
	ollSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/chat":
			w.Header().Set("Content-Type", "application/x-ndjson")
			fmt.Fprintln(w, `{"model":"llama3.3","message":{"role":"assistant","content":"Ollama ok"},"done":true,"prompt_eval_count":6,"eval_count":2}`)
		case "/api/embed":
			fmt.Fprint(w, `{"model":"nomic-embed-text","embeddings":[[0.11,0.22]],"prompt_eval_count":3}`)
		case "/api/tags":
			fmt.Fprint(w, `{"models":[{"name":"llama3.3:latest","model":"llama3.3:latest"}]}`)
		}
	}))
	defer ollSrv.Close()

	reg := adapter.NewRegistry()
	reg.Register(openai.NewAdapter(oaiSrv.Client()))
	reg.Register(anthropic.NewAdapter(antSrv.Client()))
	reg.Register(gemini.NewAdapter(gemSrv.Client()))
	reg.Register(mistral.NewAdapter(misSrv.Client()))
	reg.Register(ollama.NewAdapter(ollSrv.Client()))

	req := &domain.CanonicalChatRequest{
		Model: "test-model",
		Messages: []domain.CanonicalMessage{
			{Role: "system", Content: "You are helpful."},
			{Role: "user", Content: "Say hello."},
		},
	}

	testCases := []struct {
		provider domain.ProviderType
		baseURL  string
		expected string
	}{
		{domain.ProviderOpenAI, oaiSrv.URL, "OpenAI ok"},
		{domain.ProviderAnthropic, antSrv.URL, "Claude ok"},
		{domain.ProviderGemini, gemSrv.URL, "Gemini ok"},
		{domain.ProviderMistral, misSrv.URL, "Mistral ok"},
		{domain.ProviderOllama, ollSrv.URL, "Ollama ok"},
	}

	for _, tc := range testCases {
		adp, err := reg.Get(tc.provider)
		if err != nil {
			t.Fatalf("get adapter %s: %v", tc.provider, err)
		}
		dep := &domain.Deployment{
			Credential: &domain.ProviderCredential{
				Provider:        tc.provider,
				BaseURL:         tc.baseURL,
				DecryptedAPIKey: "test-secret",
			},
			GlobalModel: &domain.GlobalModel{ModelName: "test-model"},
		}

		// Sync chat
		resp, err := adp.ChatCompletion(ctx, dep, req)
		if err != nil {
			t.Fatalf("%s ChatCompletion error: %v", tc.provider, err)
		}
		if len(resp.Choices) == 0 || resp.Choices[0].Message.Content != tc.expected {
			t.Fatalf("%s unexpected content: %+v", tc.provider, resp.Choices)
		}

		// ListModels discovery
		models, err := adp.ListModels(ctx, dep.Credential)
		if err != nil || len(models) == 0 {
			t.Fatalf("%s ListModels failed: err=%v count=%d", tc.provider, err, len(models))
		}
	}

	// Verify Anthropic SSE state machine & Ollama NDJSON -> SSE conversion
	antAdp, _ := reg.Get(domain.ProviderAnthropic)
	var antStreamed string
	antUsage, err := antAdp.StreamChatCompletion(ctx, &domain.Deployment{
		Credential: &domain.ProviderCredential{BaseURL: antSrv.URL, DecryptedAPIKey: "k"},
	}, req, func(c *domain.CanonicalStreamChunk) error {
		if len(c.Choices) > 0 {
			antStreamed += c.Choices[0].Delta.Content
		}
		return nil
	})
	if err != nil || antStreamed != "Claude stream" || antUsage.TotalTokens != 21 {
		t.Fatalf("Anthropic stream failed: err=%v text=%q usage=%+v", err, antStreamed, antUsage)
	}

	ollAdp, _ := reg.Get(domain.ProviderOllama)
	var ollStreamed string
	ollUsage, err := ollAdp.StreamChatCompletion(ctx, &domain.Deployment{
		Credential: &domain.ProviderCredential{BaseURL: ollSrv.URL},
	}, req, func(c *domain.CanonicalStreamChunk) error {
		if len(c.Choices) > 0 {
			ollStreamed += c.Choices[0].Delta.Content
		}
		return nil
	})
	if err != nil || ollStreamed != "Ollama ok" || ollUsage.TotalTokens != 8 {
		t.Fatalf("Ollama NDJSON stream failed: err=%v text=%q usage=%+v", err, ollStreamed, ollUsage)
	}
}
