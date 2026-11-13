package openai_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/adapter/openai"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

func TestOpenAI_ReasoningModels_GPT5_And_O4_EffortMapping(t *testing.T) {
	var captured map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &captured)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"c1","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}]}`))
	}))
	defer srv.Close()

	adp := openai.NewAdapter(srv.Client())
	dep := &domain.Deployment{
		ID:          "dep-oai-ext",
		GlobalModel: &domain.GlobalModel{ID: "openai/gpt-5", Provider: domain.ProviderOpenAI, ModelName: "gpt-5"},
		Credential:  &domain.ProviderCredential{BaseURL: srv.URL, DecryptedAPIKey: "sk-test"},
	}

	temp := 0.8
	_, err := adp.ChatCompletion(context.Background(), dep, &domain.CanonicalChatRequest{
		Model:           "gpt-5",
		Temperature:     &temp,
		ReasoningEffort: "max",
		Messages: []domain.CanonicalMessage{
			{Role: "system", Content: "sys"},
			{Role: "user", Content: "hi"},
		},
	})
	if err != nil {
		t.Fatalf("ChatCompletion failed: %v", err)
	}
	if captured["reasoning_effort"] != "xhigh" {
		t.Fatalf("expected reasoning_effort=xhigh for max, got %v", captured["reasoning_effort"])
	}
	if _, hasTemp := captured["temperature"]; hasTemp {
		t.Fatalf("expected temperature omitted for gpt-5 reasoning model")
	}
	msgs := captured["messages"].([]any)
	if msgs[0].(map[string]any)["role"] != "developer" {
		t.Fatalf("expected system role rewritten to developer for gpt-5")
	}
}
