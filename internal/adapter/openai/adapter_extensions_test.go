package openai_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/adapter/openai"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
)

func loopbackTestPolicy(t *testing.T) *network.Policy {
	t.Helper()
	pol, err := network.NewPolicy(config.OutboundSSRFConfig{
		AllowPrivateNetworks: true,
		AllowInsecureHTTP:    true,
	})
	if err != nil {
		t.Fatalf("network.NewPolicy: %v", err)
	}
	return pol
}

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
	adp.SetSSRFPolicy(loopbackTestPolicy(t))
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

func TestOpenAI_TranscribeAudio_IsTranslation(t *testing.T) {
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"text":"hello"}`))
	}))
	defer srv.Close()

	adp := openai.NewAdapter(srv.Client())
	adp.SetSSRFPolicy(loopbackTestPolicy(t))
	dep := &domain.Deployment{
		ID:          "dep-oai-audio",
		GlobalModel: &domain.GlobalModel{ID: "openai/whisper-1", Provider: domain.ProviderOpenAI, ModelName: "whisper-1"},
		Credential:  &domain.ProviderCredential{BaseURL: srv.URL, DecryptedAPIKey: "sk-test"},
	}

	// RequestID containing "translation" must NOT trigger /audio/translations when IsTranslation is false.
	_, err := adp.TranscribeAudio(context.Background(), dep, &domain.CanonicalAudioTranscriptionRequest{
		RequestID:     "req-translation-false",
		Model:         "whisper-1",
		FileName:      "test.mp3",
		FileReader:    strings.NewReader("audio"),
		IsTranslation: false,
	})
	if err != nil {
		t.Fatalf("TranscribeAudio (transcription) failed: %v", err)
	}

	_, err = adp.TranscribeAudio(context.Background(), dep, &domain.CanonicalAudioTranscriptionRequest{
		RequestID:     "req-1",
		Model:         "whisper-1",
		FileName:      "test.mp3",
		FileReader:    strings.NewReader("audio"),
		IsTranslation: true,
	})
	if err != nil {
		t.Fatalf("TranscribeAudio (translation) failed: %v", err)
	}

	if len(paths) != 2 || paths[0] != "/audio/transcriptions" || paths[1] != "/audio/translations" {
		t.Fatalf("unexpected paths: %v", paths)
	}
}

func TestOpenAI_StreamTextCompletion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/completions" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["stream"] != true {
			t.Fatalf("expected stream=true, got %v", body["stream"])
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: {\"id\":\"cmpl-1\",\"object\":\"text_completion\",\"model\":\"gpt-3.5-turbo-instruct\",\"choices\":[{\"index\":0,\"text\":\"Hello\",\"finish_reason\":null}]}\n\n"))
		_, _ = w.Write([]byte("data: {\"id\":\"cmpl-1\",\"object\":\"text_completion\",\"model\":\"gpt-3.5-turbo-instruct\",\"choices\":[{\"index\":0,\"text\":\" world\",\"finish_reason\":\"stop\"}]}\n\n"))
		_, _ = w.Write([]byte("data: [DONE]\n\n"))
	}))
	defer srv.Close()

	adp := openai.NewAdapter(srv.Client())
	adp.SetSSRFPolicy(loopbackTestPolicy(t))
	dep := &domain.Deployment{
		ID:          "dep-oai-cmpl",
		GlobalModel: &domain.GlobalModel{ID: "openai/gpt-3.5-turbo-instruct", Provider: domain.ProviderOpenAI, ModelName: "gpt-3.5-turbo-instruct"},
		Credential:  &domain.ProviderCredential{BaseURL: srv.URL, DecryptedAPIKey: "sk-test"},
	}

	ch, err := adp.StreamTextCompletion(context.Background(), dep, &domain.CanonicalCompletionRequest{
		Model:  "gpt-3.5-turbo-instruct",
		Prompt: domain.CompletionPrompt{Strings: []string{"Say hi"}},
	})
	if err != nil {
		t.Fatalf("StreamTextCompletion failed: %v", err)
	}

	var got string
	for chunk := range ch {
		if len(chunk.Choices) > 0 {
			got += chunk.Choices[0].Delta.Content
		}
	}
	if got != "Hello world" {
		t.Fatalf("expected 'Hello world', got %q", got)
	}
}
