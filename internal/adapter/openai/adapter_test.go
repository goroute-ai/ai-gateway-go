package openai

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
)

func TestToOpenAIRequest_ReasoningModelSanitization(t *testing.T) {
	temp := 0.7
	topP := 0.9
	req := &domain.CanonicalChatRequest{
		Model:       "o3-mini",
		Temperature: &temp,
		TopP:        &topP,
		Messages: []domain.CanonicalMessage{
			{Role: "system", Content: "You are a coding assistant."},
			{Role: "user", Content: "Write quicksort in Go."},
		},
	}

	out := toOpenAIRequest("o3-mini", req, false)

	// Temperature and TopP must be omitted for reasoning models
	if out.Temperature != nil {
		t.Fatalf("expected temperature to be nil for o3-mini, got %v", *out.Temperature)
	}
	if out.TopP != nil {
		t.Fatalf("expected top_p to be nil for o3-mini, got %v", *out.TopP)
	}

	// System role must be converted to developer
	if len(out.Messages) != 2 {
		t.Fatalf("expected 2 messages, got %d", len(out.Messages))
	}
	if out.Messages[0].Role != "developer" {
		t.Fatalf("expected role 'developer' for system message in o3-mini, got %s", out.Messages[0].Role)
	}
}

func TestToOpenAIRequest_StandardModelPreservesParameters(t *testing.T) {
	temp := 0.7
	topP := 0.9
	req := &domain.CanonicalChatRequest{
		Model:       "gpt-4o",
		Temperature: &temp,
		TopP:        &topP,
		Messages: []domain.CanonicalMessage{
			{Role: "system", Content: "You are a helpful assistant."},
			{Role: "user", Content: "Hello!"},
		},
	}

	out := toOpenAIRequest("gpt-4o", req, false)

	if out.Temperature == nil || *out.Temperature != 0.7 {
		t.Fatalf("expected temperature 0.7 preserved for gpt-4o")
	}
	if out.TopP == nil || *out.TopP != 0.9 {
		t.Fatalf("expected top_p 0.9 preserved for gpt-4o")
	}
	if out.Messages[0].Role != "system" {
		t.Fatalf("expected role 'system' preserved for gpt-4o, got %s", out.Messages[0].Role)
	}
}

func TestOpenAIModeration(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/moderations" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer test-key" {
			t.Fatalf("unexpected auth header: %s", r.Header.Get("Authorization"))
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"id": "modr-xyz-123",
			"model": "text-moderation-latest",
			"results": [
				{
					"flagged": false,
					"categories": {"hate": false, "violence": false},
					"category_scores": {"hate": 0.001, "violence": 0.002}
				}
			]
		}`))
	}))
	defer srv.Close()

	adp := NewAdapter(srv.Client())
	pol, err := network.NewPolicy(config.OutboundSSRFConfig{
		AllowPrivateNetworks: true,
		AllowInsecureHTTP:    true,
	})
	if err != nil {
		t.Fatalf("network.NewPolicy: %v", err)
	}
	adp.SetSSRFPolicy(pol)
	dep := &domain.Deployment{
		ID: "dep-openai-mod",
		GlobalModel: &domain.GlobalModel{
			ID:        "openai/text-moderation-latest",
			Provider:  domain.ProviderOpenAI,
			ModelName: "text-moderation-latest",
		},
		Credential: &domain.ProviderCredential{
			BaseURL:         srv.URL,
			DecryptedAPIKey: "test-key",
		},
	}

	req := &domain.CanonicalModerationRequest{
		Model: "text-moderation-latest",
		Input: []string{"I love writing Go code"},
	}

	res, err := adp.Moderate(context.Background(), dep, req)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}
	if res.ID != "modr-xyz-123" {
		t.Fatalf("expected ID 'modr-xyz-123', got %s", res.ID)
	}
	if len(res.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(res.Results))
	}
	if res.Results[0].Flagged {
		t.Fatalf("expected flagged=false")
	}
	if res.Results[0].CategoryScores["hate"] != 0.001 {
		t.Fatalf("expected hate score 0.001, got %f", res.Results[0].CategoryScores["hate"])
	}
}

func TestMarshalOpenAIRequestWithExtras(t *testing.T) {
	req := &domain.CanonicalChatRequest{
		Model: "gpt-4o",
		Messages: []domain.CanonicalMessage{
			{Role: "user", Content: "hello"},
		},
	}
	payload := toOpenAIRequest("gpt-4o", req, false)
	extra := map[string]any{
		"seed":     99,
		"logprobs": true,
		"model":    "clobber",
		"stream":   true,
		"messages": "clobber",
	}

	b, err := marshalOpenAIRequestWithExtras(payload, extra)
	if err != nil {
		t.Fatalf("marshalOpenAIRequestWithExtras failed: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(b, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if decoded["model"] != "gpt-4o" {
		t.Fatalf("expected model gpt-4o, got %v", decoded["model"])
	}
	if _, hasStream := decoded["stream"]; hasStream {
		t.Fatalf("expected stream to remain omitted when false, got %v", decoded["stream"])
	}
	if decoded["seed"] != float64(99) {
		t.Fatalf("expected seed 99, got %v", decoded["seed"])
	}
	if decoded["logprobs"] != true {
		t.Fatalf("expected logprobs true, got %v", decoded["logprobs"])
	}
}

func TestOpenAIAdapter_FailClosedBaseURLWithoutSSRFPolicy(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	// Without SetSSRFPolicy, ValidateAndResolveBaseURL must fail closed on loopback/private/insecure URLs.
	adp := NewAdapter(srv.Client())
	dep := &domain.Deployment{
		ID:          "dep-fail-closed",
		GlobalModel: &domain.GlobalModel{Provider: domain.ProviderOpenAI, ModelName: "gpt-4o"},
		Credential:  &domain.ProviderCredential{BaseURL: srv.URL, DecryptedAPIKey: "sk-test"},
	}
	req := &domain.CanonicalChatRequest{
		Model:    "gpt-4o",
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "hello"}},
	}

	if _, err := adp.ChatCompletion(context.Background(), dep, req); err == nil {
		t.Fatal("expected ChatCompletion without SetSSRFPolicy to reject loopback BaseURL")
	}
	if _, err := adp.StreamChatCompletion(context.Background(), dep, req, func(*domain.CanonicalStreamChunk) error { return nil }); err == nil {
		t.Fatal("expected StreamChatCompletion without SetSSRFPolicy to reject loopback BaseURL")
	}
	if _, err := adp.Embeddings(context.Background(), dep, &domain.CanonicalEmbeddingRequest{Model: "text-embedding-3-small", Input: []string{"hi"}}); err == nil {
		t.Fatal("expected Embeddings without SetSSRFPolicy to reject loopback BaseURL")
	}
	if calls != 0 {
		t.Fatalf("expected zero upstream dials when BaseURL fails validation, got %d", calls)
	}
}

func TestOpenAIAdapter_ModerateUsesResolvedModel(t *testing.T) {
	var sentModel string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Model string `json:"model"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode moderation body: %v", err)
		}
		sentModel = body.Model
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"modr-1","model":"omni-moderation-latest","results":[{"flagged":false}]}`))
	}))
	defer srv.Close()

	pol, err := network.NewPolicy(config.OutboundSSRFConfig{AllowPrivateNetworks: true, AllowInsecureHTTP: true})
	if err != nil {
		t.Fatalf("NewPolicy: %v", err)
	}
	adp := NewAdapter(srv.Client())
	adp.SetSSRFPolicy(pol)
	dep := &domain.Deployment{
		ID:          "dep-mod",
		GlobalModel: &domain.GlobalModel{Provider: domain.ProviderOpenAI, ModelName: "omni-moderation-latest"},
		Credential:  &domain.ProviderCredential{BaseURL: srv.URL, DecryptedAPIKey: "sk-test"},
	}
	_, err = adp.Moderate(context.Background(), dep, &domain.CanonicalModerationRequest{
		Model:         "alias-group-name",
		ResolvedModel: "omni-moderation-latest",
		Input:         []string{"hello"},
	})
	if err != nil {
		t.Fatalf("Moderate: %v", err)
	}
	if sentModel != "omni-moderation-latest" {
		t.Fatalf("sent model = %q, want omni-moderation-latest", sentModel)
	}
}
