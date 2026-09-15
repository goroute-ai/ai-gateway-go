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
	"github.com/goroute-ai/ai-gateway-go/internal/adapter/groq"
	"github.com/goroute-ai/ai-gateway-go/internal/adapter/openai"
	"github.com/goroute-ai/ai-gateway-go/internal/adapter/openrouter"
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

	cases := []struct {
		name string
		adp  adapter.ProviderAdapter
		want bool
	}{
		{name: "openai", adp: openai.NewAdapter(nil), want: true},
		{name: "anthropic", adp: anthropic.NewAdapter(nil), want: true},
		{name: "groq", adp: groq.NewAdapter(nil), want: true},
		{name: "openrouter", adp: openrouter.NewAdapter(nil), want: true},
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
			_, _ = w.Write([]byte(`{"id":"1","object":"chat.completion","model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"fox"},"finish_reason":"stop"}]}`))
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

	t.Run("groq", func(t *testing.T) {
		var captured map[string]any
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &captured)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"1","object":"chat.completion","model":"llama-3.1-8b-instant","choices":[{"index":0,"message":{"role":"assistant","content":"fox"},"finish_reason":"stop"}]}`))
		}))
		defer srv.Close()

		adp := groq.NewAdapter(srv.Client())
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
			t.Fatalf("unexpected groq trailing message: %#v", last)
		}
	})

	t.Run("openrouter", func(t *testing.T) {
		var captured map[string]any
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &captured)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"1","object":"chat.completion","model":"openai/gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"fox"},"finish_reason":"stop"}]}`))
		}))
		defer srv.Close()

		adp := openrouter.NewAdapter(srv.Client())
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
			t.Fatalf("unexpected openrouter trailing message: %#v", last)
		}
	})

	t.Run("anthropic", func(t *testing.T) {
		var captured map[string]any
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &captured)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","role":"assistant","model":"claude-haiku-4-5-20251001","content":[{"type":"text","text":"fox"}],"stop_reason":"end_turn","usage":{"input_tokens":5,"output_tokens":1}}`))
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
}
