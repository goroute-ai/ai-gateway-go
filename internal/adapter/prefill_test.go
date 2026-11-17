package adapter_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/adapter"
	"github.com/goroute-ai/ai-gateway-go/internal/adapter/anthropic"
	"github.com/goroute-ai/ai-gateway-go/internal/adapter/bedrock"
	"github.com/goroute-ai/ai-gateway-go/internal/adapter/cohere"
	"github.com/goroute-ai/ai-gateway-go/internal/adapter/gemini"
	"github.com/goroute-ai/ai-gateway-go/internal/adapter/mistral"
	"github.com/goroute-ai/ai-gateway-go/internal/adapter/ollama"
	"github.com/goroute-ai/ai-gateway-go/internal/adapter/openai"
	"github.com/goroute-ai/ai-gateway-go/internal/adapter/openaicompat"
	"github.com/goroute-ai/ai-gateway-go/internal/adapter/vertex"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
)

type stubAdapterWithoutPrefill struct{}

func (s *stubAdapterWithoutPrefill) Provider() domain.ProviderType {
	return domain.ProviderType("stub")
}

func (s *stubAdapterWithoutPrefill) ChatCompletion(context.Context, *domain.Deployment, *domain.CanonicalChatRequest) (*domain.CanonicalChatResponse, error) {
	return nil, nil
}

func (s *stubAdapterWithoutPrefill) StreamChatCompletion(context.Context, *domain.Deployment, *domain.CanonicalChatRequest, adapter.StreamChunkHandler) (*domain.TokenUsage, error) {
	return nil, nil
}

func (s *stubAdapterWithoutPrefill) Embeddings(context.Context, *domain.Deployment, *domain.CanonicalEmbeddingRequest) (*domain.CanonicalEmbeddingResponse, error) {
	return nil, nil
}

func (s *stubAdapterWithoutPrefill) ListModels(context.Context, *domain.ProviderCredential) ([]domain.DiscoveredModel, error) {
	return nil, nil
}

func TestSupportsAssistantPrefill_Matrix(t *testing.T) {
	if adapter.SupportsAssistantPrefill(nil) {
		t.Fatal("expected SupportsAssistantPrefill(nil) to be false")
	}
	if adapter.SupportsAssistantPrefill(&stubAdapterWithoutPrefill{}) {
		t.Fatal("expected adapter without PrefillSupportChecker to return false")
	}

	compatProfile := &openaicompat.DialectProfile{
		ID:               domain.ProviderGroq,
		EndpointStrategy: &adapter.StandardOpenAIEndpointStrategy{DefaultBaseURL: "https://api.groq.com/openai/v1"},
		AuthStrategy:     &adapter.BearerAuthStrategy{},
	}

	cases := []struct {
		name string
		adp  adapter.ProviderAdapter
		want bool
	}{
		{name: "openai", adp: openai.NewAdapter(nil), want: true},
		{name: "openaicompat", adp: openaicompat.NewAdapter(compatProfile, nil), want: true},
		{name: "mistral", adp: mistral.NewAdapter(nil), want: true},
		{name: "ollama", adp: ollama.NewAdapter(nil), want: true},
		{name: "anthropic", adp: anthropic.NewAdapter(nil), want: true},
		{name: "gemini", adp: gemini.NewAdapter(nil), want: false},
		{name: "vertex", adp: vertex.NewAdapter(nil, nil), want: false},
		{name: "bedrock", adp: bedrock.NewAdapter(nil, nil), want: false},
		{name: "cohere", adp: cohere.NewAdapter(nil, nil), want: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, ok := tc.adp.(adapter.PrefillSupportChecker); !ok {
				t.Fatalf("%s adapter does not implement PrefillSupportChecker", tc.name)
			}
			if got := adapter.SupportsAssistantPrefill(tc.adp); got != tc.want {
				t.Fatalf("SupportsAssistantPrefill(%s) = %v, want %v", tc.name, got, tc.want)
			}
		})
	}
}

func TestTrailingAssistantMessageSerializationAcrossAdapters(t *testing.T) {
	ctx := context.Background()
	pol, err := network.NewPolicy(config.OutboundSSRFConfig{
		AllowPrivateNetworks: true,
		AllowInsecureHTTP:    true,
	})
	if err != nil {
		t.Fatalf("network.NewPolicy: %v", err)
	}

	req := &domain.CanonicalChatRequest{
		Model: "test-model",
		Messages: []domain.CanonicalMessage{
			{Role: "user", Content: "Complete the sentence."},
			{Role: "assistant", Content: "The quick brown "},
		},
	}

	t.Run("openai", func(t *testing.T) {
		var captured map[string]any
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &captured)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"1","object":"chat.completion","model":"gpt-4.1","choices":[{"index":0,"message":{"role":"assistant","content":"fox"},"finish_reason":"stop"}]}`))
		}))
		defer srv.Close()

		adp := openai.NewAdapter(srv.Client())
		adp.SetSSRFPolicy(pol)
		_, err := adp.ChatCompletion(ctx, &domain.Deployment{
			Credential: &domain.ProviderCredential{BaseURL: srv.URL, DecryptedAPIKey: "k"},
		}, req)
		if err != nil {
			t.Fatalf("ChatCompletion: %v", err)
		}
		msgs := captured["messages"].([]any)
		last := msgs[len(msgs)-1].(map[string]any)
		if last["role"] != "assistant" || last["content"] != "The quick brown " {
			t.Fatalf("unexpected openai trailing message: %#v", last)
		}
	})

	t.Run("openaicompat", func(t *testing.T) {
		var captured map[string]any
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &captured)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"1","object":"chat.completion","model":"llama-3.3","choices":[{"index":0,"message":{"role":"assistant","content":"fox"},"finish_reason":"stop"}]}`))
		}))
		defer srv.Close()

		profile := &openaicompat.DialectProfile{
			ID: domain.ProviderGroq,
			EndpointStrategy: &adapter.StandardOpenAIEndpointStrategy{
				DefaultBaseURL: srv.URL,
				SSRFPolicy:     pol,
			},
			AuthStrategy: &adapter.BearerAuthStrategy{},
		}
		adp := openaicompat.NewAdapter(profile, srv.Client())
		adp.SetSSRFPolicy(pol)
		_, err := adp.ChatCompletion(ctx, &domain.Deployment{
			Credential: &domain.ProviderCredential{BaseURL: srv.URL, DecryptedAPIKey: "k"},
		}, req)
		if err != nil {
			t.Fatalf("ChatCompletion: %v", err)
		}
		msgs := captured["messages"].([]any)
		last := msgs[len(msgs)-1].(map[string]any)
		if last["role"] != "assistant" || last["content"] != "The quick brown " {
			t.Fatalf("unexpected openaicompat trailing message: %#v", last)
		}
	})

	t.Run("mistral", func(t *testing.T) {
		var captured map[string]any
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &captured)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"1","object":"chat.completion","model":"mistral-large","choices":[{"index":0,"message":{"role":"assistant","content":"fox"},"finish_reason":"stop"}]}`))
		}))
		defer srv.Close()

		adp := mistral.NewAdapter(srv.Client())
		adp.SetSSRFPolicy(pol)
		_, err := adp.ChatCompletion(ctx, &domain.Deployment{
			Credential: &domain.ProviderCredential{BaseURL: srv.URL, DecryptedAPIKey: "k"},
		}, req)
		if err != nil {
			t.Fatalf("ChatCompletion: %v", err)
		}
		msgs := captured["messages"].([]any)
		last := msgs[len(msgs)-1].(map[string]any)
		if last["role"] != "assistant" || last["content"] != "The quick brown " || last["prefix"] != true {
			t.Fatalf("unexpected mistral trailing message: %#v", last)
		}
	})

	t.Run("ollama", func(t *testing.T) {
		var captured map[string]any
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &captured)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"model":"llama3.3","message":{"role":"assistant","content":"fox"},"done":true}`))
		}))
		defer srv.Close()

		adp := ollama.NewAdapter(srv.Client())
		adp.SetSSRFPolicy(pol)
		_, err := adp.ChatCompletion(ctx, &domain.Deployment{
			Credential: &domain.ProviderCredential{BaseURL: srv.URL},
		}, req)
		if err != nil {
			t.Fatalf("ChatCompletion: %v", err)
		}
		msgs := captured["messages"].([]any)
		last := msgs[len(msgs)-1].(map[string]any)
		if last["role"] != "assistant" || last["content"] != "The quick brown " {
			t.Fatalf("unexpected ollama trailing message: %#v", last)
		}
	})

	t.Run("anthropic", func(t *testing.T) {
		var captured map[string]any
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &captured)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","role":"assistant","model":"claude-sonnet-4","content":[{"type":"text","text":"fox"}],"stop_reason":"end_turn","usage":{"input_tokens":5,"output_tokens":1}}`))
		}))
		defer srv.Close()

		adp := anthropic.NewAdapter(srv.Client())
		adp.SetSSRFPolicy(pol)
		_, err := adp.ChatCompletion(ctx, &domain.Deployment{
			Credential: &domain.ProviderCredential{BaseURL: srv.URL, DecryptedAPIKey: "k"},
		}, req)
		if err != nil {
			t.Fatalf("ChatCompletion: %v", err)
		}
		msgs := captured["messages"].([]any)
		last := msgs[len(msgs)-1].(map[string]any)
		blocks := last["content"].([]any)
		firstBlock := blocks[0].(map[string]any)
		if last["role"] != "assistant" || firstBlock["type"] != "text" || firstBlock["text"] != "The quick brown" {
			t.Fatalf("unexpected anthropic trailing message (expected trimmed trailing whitespace): %#v", last)
		}
	})

	t.Run("gemini", func(t *testing.T) {
		var captured map[string]any
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &captured)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"candidates":[{"index":0,"content":{"role":"model","parts":[{"text":"fox"}]},"finishReason":"STOP"}]}`))
		}))
		defer srv.Close()

		adp := gemini.NewAdapter(srv.Client())
		adp.SetSSRFPolicy(pol)
		_, err := adp.ChatCompletion(ctx, &domain.Deployment{
			Credential: &domain.ProviderCredential{BaseURL: srv.URL, DecryptedAPIKey: "k"},
		}, req)
		if err != nil {
			t.Fatalf("ChatCompletion: %v", err)
		}
		contents := captured["contents"].([]any)
		last := contents[len(contents)-1].(map[string]any)
		if last["role"] != "model" {
			t.Fatalf("expected gemini trailing role=model, got %#v", last)
		}
	})

	t.Run("bedrock", func(t *testing.T) {
		var captured map[string]any
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &captured)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"output":{"message":{"role":"assistant","content":[{"text":"fox"}]}},"stopReason":"end_turn","usage":{"inputTokens":5,"outputTokens":1,"totalTokens":6}}`))
		}))
		defer srv.Close()

		adp := bedrock.NewAdapter(srv.Client(), pol)
		_, err := adp.ChatCompletion(ctx, &domain.Deployment{
			Credential: &domain.ProviderCredential{BaseURL: srv.URL, DecryptedAPIKey: "ak:sk:us-east-1"},
		}, req)
		if err != nil {
			t.Fatalf("ChatCompletion: %v", err)
		}
		msgs := captured["messages"].([]any)
		last := msgs[len(msgs)-1].(map[string]any)
		if last["role"] != "assistant" {
			t.Fatalf("expected bedrock trailing role=assistant, got %#v", last)
		}
	})

	t.Run("cohere", func(t *testing.T) {
		var captured map[string]any
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &captured)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"ch_1","message":{"role":"assistant","content":[{"type":"text","text":"fox"}]},"finish_reason":"COMPLETE","usage":{"tokens":{"input_tokens":5,"output_tokens":1}}}`))
		}))
		defer srv.Close()

		adp := cohere.NewAdapter(srv.Client(), pol)
		_, err := adp.ChatCompletion(ctx, &domain.Deployment{
			Credential: &domain.ProviderCredential{BaseURL: srv.URL, DecryptedAPIKey: "k"},
		}, req)
		if err != nil {
			t.Fatalf("ChatCompletion: %v", err)
		}
		msgs := captured["messages"].([]any)
		last := msgs[len(msgs)-1].(map[string]any)
		if last["role"] != "assistant" {
			t.Fatalf("expected cohere trailing role=assistant, got %#v", last)
		}
	})
}
