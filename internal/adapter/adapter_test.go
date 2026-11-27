package adapter_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/adapter"
	"github.com/goroute-ai/ai-gateway-go/internal/adapter/anthropic"
	"github.com/goroute-ai/ai-gateway-go/internal/adapter/gemini"
	"github.com/goroute-ai/ai-gateway-go/internal/adapter/groq"
	"github.com/goroute-ai/ai-gateway-go/internal/adapter/ollama"
	"github.com/goroute-ai/ai-gateway-go/internal/adapter/openai"
	"github.com/goroute-ai/ai-gateway-go/internal/adapter/openrouter"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
)

func TestAllProviderAdapters_ChatStreamEmbeddingsAndModels(t *testing.T) {
	ctx := context.Background()

	// 1. Mock OpenAI Server
	oaiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/chat/completions":
			if strings.Contains(r.Header.Get("Accept"), "text/event-stream") {
				w.Header().Set("Content-Type", "text/event-stream")
				fmt.Fprint(w, "data: {\"id\":\"1\",\"object\":\"chat.completion.chunk\",\"model\":\"gpt-4o-mini\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Hello \"}}]}\n\n")
				fmt.Fprint(w, "data: {\"id\":\"1\",\"object\":\"chat.completion.chunk\",\"model\":\"gpt-4o-mini\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"World\"},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":10,\"completion_tokens\":2,\"total_tokens\":12}}\n\n")
				fmt.Fprint(w, "data: [DONE]\n\n")
				return
			}
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"id":"chatcmpl-1","object":"chat.completion","created":1700000000,"model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"OpenAI ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":8,"completion_tokens":4,"total_tokens":12}}`)
		case "/embeddings":
			fmt.Fprint(w, `{"object":"list","model":"text-embedding-3-small","data":[{"object":"embedding","index":0,"embedding":[0.1,0.2,0.3]}],"usage":{"prompt_tokens":5,"total_tokens":5}}`)
		case "/models":
			fmt.Fprint(w, `{"object":"list","data":[{"id":"gpt-4o-mini","object":"model","created":1700000000,"owned_by":"openai"}]}`)
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
				fmt.Fprint(w, "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_1\",\"model\":\"claude-haiku-4-5-20251001\",\"usage\":{\"input_tokens\":15}}}\n\n")
				fmt.Fprint(w, "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"Claude stream\"}}\n\n")
				fmt.Fprint(w, "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":6}}\n\n")
				return
			}
			fmt.Fprint(w, `{"id":"msg_1","type":"message","role":"assistant","model":"claude-haiku-4-5-20251001","content":[{"type":"thinking","thinking":"step 1"},{"type":"text","text":"Claude ok"}],"stop_reason":"end_turn","usage":{"input_tokens":12,"output_tokens":5}}`)
		case "/v1/models":
			fmt.Fprint(w, `{"data":[{"id":"claude-haiku-4-5-20251001","display_name":"Claude Haiku 4.5","type":"model"}]}`)
		}
	}))
	defer antSrv.Close()

	// 3. Mock Groq Server
	groqSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/chat/completions":
			fmt.Fprint(w, `{"id":"chatcmpl-g1","object":"chat.completion","created":1700000000,"model":"llama-3.1-8b-instant","choices":[{"index":0,"message":{"role":"assistant","content":"Groq ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":7,"completion_tokens":3,"total_tokens":10}}`)
		case "/models":
			fmt.Fprint(w, `{"object":"list","data":[{"id":"llama-3.1-8b-instant","object":"model"}]}`)
		}
	}))
	defer groqSrv.Close()

	// 4. Mock OpenRouter Server
	orSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/chat/completions":
			fmt.Fprint(w, `{"id":"gen-or1","object":"chat.completion","created":1700000000,"model":"openai/gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"OpenRouter ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":7,"completion_tokens":3,"total_tokens":10}}`)
		case "/models":
			fmt.Fprint(w, `{"data":[{"id":"openai/gpt-4o-mini","name":"GPT-4o mini"}]}`)
		}
	}))
	defer orSrv.Close()

	// 5. Mock Ollama Server
	ollamaSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/chat/completions":
			fmt.Fprint(w, `{"id":"chatcmpl-ol1","object":"chat.completion","created":1700000000,"model":"qwen2.5:0.5b","choices":[{"index":0,"message":{"role":"assistant","content":"Ollama ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":7,"completion_tokens":3,"total_tokens":10}}`)
		case "/v1/embeddings":
			fmt.Fprint(w, `{"object":"list","model":"all-minilm:latest","data":[{"object":"embedding","index":0,"embedding":[0.1,0.2,0.3]}],"usage":{"prompt_tokens":5,"total_tokens":5}}`)
		case "/api/tags":
			fmt.Fprint(w, `{"models":[{"name":"qwen2.5:0.5b","model":"qwen2.5:0.5b"}]}`)
		}
	}))
	defer ollamaSrv.Close()

	// 6. Mock Gemini Server
	gemSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-goog-api-key") == "" {
			t.Errorf("expected x-goog-api-key header")
		}
		switch r.URL.Path {
		case "/v1beta/models/test-model:generateContent":
			fmt.Fprint(w, `{"responseId":"resp-gem-1","modelVersion":"gemini-2.5-flash","candidates":[{"index":0,"content":{"role":"model","parts":[{"text":"Gemini ok"}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":8,"candidatesTokenCount":3,"totalTokenCount":11}}`)
		case "/v1beta/models/test-model:streamGenerateContent":
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprint(w, "data: {\"responseId\":\"resp-gem-s1\",\"modelVersion\":\"gemini-2.5-flash\",\"candidates\":[{\"index\":0,\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"Gemini stream\"}]},\"finishReason\":\"STOP\"}],\"usageMetadata\":{\"promptTokenCount\":9,\"candidatesTokenCount\":4,\"thoughtsTokenCount\":2,\"totalTokenCount\":15}}\n\n")
		case "/v1beta/models":
			fmt.Fprint(w, `{"models":[{"name":"models/gemini-2.5-flash","displayName":"Gemini 2.5 Flash","supportedGenerationMethods":["generateContent"]}]}`)
		}
	}))
	defer gemSrv.Close()

	loopbackPol, err := network.NewPolicy(config.OutboundSSRFConfig{
		AllowPrivateNetworks: true,
		AllowInsecureHTTP:    true,
	})
	if err != nil {
		t.Fatalf("network.NewPolicy: %v", err)
	}

	reg := adapter.NewRegistry()
	oaiAdp := openai.NewAdapter(oaiSrv.Client())
	oaiAdp.SetSSRFPolicy(loopbackPol)
	antAdp := anthropic.NewAdapter(antSrv.Client())
	antAdp.SetSSRFPolicy(loopbackPol)
	groqAdp := groq.NewAdapter(groqSrv.Client())
	groqAdp.SetSSRFPolicy(loopbackPol)
	orAdp := openrouter.NewAdapter(orSrv.Client())
	orAdp.SetSSRFPolicy(loopbackPol)
	ollamaAdp := ollama.NewAdapter(ollamaSrv.Client())
	ollamaAdp.SetSSRFPolicy(loopbackPol)
	gemAdp := gemini.NewAdapter(gemSrv.Client())
	gemAdp.SetSSRFPolicy(loopbackPol)

	reg.Register(oaiAdp)
	reg.Register(antAdp)
	reg.Register(groqAdp)
	reg.Register(orAdp)
	reg.Register(ollamaAdp)
	reg.Register(gemAdp)

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
		{domain.ProviderGroq, groqSrv.URL, "Groq ok"},
		{domain.ProviderOpenRouter, orSrv.URL, "OpenRouter ok"},
		{domain.ProviderOllama, ollamaSrv.URL, "Ollama ok"},
		{domain.ProviderGemini, gemSrv.URL, "Gemini ok"},
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

		resp, err := adp.ChatCompletion(ctx, dep, req)
		if err != nil {
			t.Fatalf("%s ChatCompletion error: %v", tc.provider, err)
		}
		if len(resp.Choices) == 0 || resp.Choices[0].Message.Content != tc.expected {
			t.Fatalf("%s unexpected content: %+v", tc.provider, resp.Choices)
		}

		models, err := adp.ListModels(ctx, dep.Credential)
		if err != nil || len(models) == 0 {
			t.Fatalf("%s ListModels failed: err=%v count=%d", tc.provider, err, len(models))
		}
	}

	// Verify Anthropic SSE state machine
	antStreamAdp, _ := reg.Get(domain.ProviderAnthropic)
	var antStreamed string
	antUsage, err := antStreamAdp.StreamChatCompletion(ctx, &domain.Deployment{
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

	// Verify Gemini SSE stream
	gemStreamAdp, _ := reg.Get(domain.ProviderGemini)
	var gemStreamed string
	gemUsage, err := gemStreamAdp.StreamChatCompletion(ctx, &domain.Deployment{
		Credential:  &domain.ProviderCredential{BaseURL: gemSrv.URL, DecryptedAPIKey: "k"},
		GlobalModel: &domain.GlobalModel{ModelName: "test-model"},
	}, req, func(c *domain.CanonicalStreamChunk) error {
		if len(c.Choices) > 0 {
			gemStreamed += c.Choices[0].Delta.Content
		}
		return nil
	})
	if err != nil || gemStreamed != "Gemini stream" || gemUsage.TotalTokens != 15 || gemUsage.CompletionTokens != 6 || gemUsage.ReasoningTokens != 2 {
		t.Fatalf("Gemini stream failed: err=%v text=%q usage=%+v", err, gemStreamed, gemUsage)
	}
}

func TestReadBoundedBody_TruncatesWithGatewayError(t *testing.T) {
	body, err := adapter.ReadBoundedBody(strings.NewReader("hello"), 5, domain.ProviderOpenAI)
	if err != nil {
		t.Fatalf("unexpected error for exact-limit body: %v", err)
	}
	if string(body) != "hello" {
		t.Fatalf("got %q, want %q", string(body), "hello")
	}

	_, err = adapter.ReadBoundedBody(strings.NewReader("hello!"), 5, domain.ProviderOpenAI)
	if err == nil {
		t.Fatal("expected GatewayError when body exceeds limit")
	}
	var gwErr *domain.GatewayError
	if !errors.As(err, &gwErr) {
		t.Fatalf("expected *domain.GatewayError, got %T", err)
	}
	if gwErr.StatusCode != http.StatusBadGateway || gwErr.Code != "upstream_response_too_large" || gwErr.Retryable {
		t.Fatalf("unexpected GatewayError: %+v", gwErr)
	}
}
