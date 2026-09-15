package groq_test

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
	"github.com/goroute-ai/ai-gateway-go/internal/adapter/groq"
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

func TestGroqAdapter_ChatStreamCompletionAudioAndModels(t *testing.T) {
	ctx := context.Background()
	var capturedChat map[string]any

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer gsk-test" {
			http.Error(w, "missing bearer token", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/chat/completions":
			body, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(body, &capturedChat)
			if stream, _ := capturedChat["stream"].(bool); stream {
				w.Header().Set("Content-Type", "text/event-stream")
				fmt.Fprint(w, "data: {\"id\":\"chatcmpl-1\",\"created\":1700000000,\"model\":\"llama-3.1-8b-instant\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"reasoning\":\"think\",\"content\":\"ok\"}}]}\n\n")
				fmt.Fprint(w, "data: {\"id\":\"chatcmpl-1\",\"created\":1700000000,\"model\":\"llama-3.1-8b-instant\",\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":4,\"completion_tokens\":2,\"total_tokens\":6}}\n\n")
				fmt.Fprint(w, "data: [DONE]\n\n")
				return
			}
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"id":"chatcmpl-1","object":"chat.completion","created":1700000000,"model":"llama-3.1-8b-instant","choices":[{"index":0,"message":{"role":"assistant","content":"OK"},"finish_reason":"stop"}],"usage":{"prompt_tokens":5,"completion_tokens":1,"total_tokens":6}}`)
		case "/completions":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"id":"cmpl-1","object":"text_completion","created":1700000000,"model":"llama-3.1-8b-instant","choices":[{"index":0,"text":"2","finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":1,"total_tokens":4}}`)
		case "/audio/transcriptions", "/audio/translations":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"text":"hello groq","language":"en","duration":0.5}`)
		case "/audio/speech":
			w.Header().Set("Content-Type", "audio/wav")
			_, _ = w.Write([]byte("RIFFmockwav"))
		case "/models":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"object":"list","data":[{"id":"llama-3.1-8b-instant","object":"model","created":1700000000,"owned_by":"Meta"}]}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	adp := groq.NewAdapter(srv.Client())
	adp.SetSSRFPolicy(testPolicy(t))

	dep := &domain.Deployment{
		ID: "dep-groq",
		Credential: &domain.ProviderCredential{
			Provider:        domain.ProviderGroq,
			BaseURL:         srv.URL,
			DecryptedAPIKey: "gsk-test",
		},
		GlobalModel: &domain.GlobalModel{ModelName: "llama-3.1-8b-instant"},
	}

	maxTok := 16
	resp, err := adp.ChatCompletion(ctx, dep, &domain.CanonicalChatRequest{
		Model:     "llama-3.1-8b-instant",
		Messages:  []domain.CanonicalMessage{{Role: "user", Content: "hi"}},
		MaxTokens: &maxTok,
		ExtraParams: map[string]any{
			"service_tier": "auto",
			"logprobs":     true,
		},
	})
	if err != nil {
		t.Fatalf("ChatCompletion: %v", err)
	}
	if resp.Provider != domain.ProviderGroq || resp.Choices[0].Message.Content != "OK" {
		t.Fatalf("unexpected chat response: %+v", resp)
	}
	if _, leaked := capturedChat["service_tier"]; leaked {
		t.Fatal("expected service_tier to be stripped for Groq")
	}
	if _, leaked := capturedChat["logprobs"]; leaked {
		t.Fatal("expected logprobs to be stripped for Groq")
	}
	if capturedChat["max_tokens"] != float64(16) {
		t.Fatalf("expected max_tokens=16, got %v", capturedChat["max_tokens"])
	}

	var streamed strings.Builder
	usage, err := adp.StreamChatCompletion(ctx, dep, &domain.CanonicalChatRequest{
		Model:    "llama-3.1-8b-instant",
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "hi"}},
	}, func(c *domain.CanonicalStreamChunk) error {
		if len(c.Choices) > 0 {
			streamed.WriteString(c.Choices[0].Delta.Content)
		}
		return nil
	})
	if err != nil || streamed.String() != "ok" || usage.TotalTokens != 6 {
		t.Fatalf("StreamChatCompletion failed: content=%q usage=%+v err=%v", streamed.String(), usage, err)
	}

	cmpl, err := adp.TextCompletion(ctx, dep, &domain.CanonicalCompletionRequest{
		Model:  "llama-3.1-8b-instant",
		Prompt: domain.CompletionPrompt{Strings: []string{"1+1="}},
	})
	if err != nil || cmpl.Choices[0].Text != "2" {
		t.Fatalf("TextCompletion failed: resp=%+v err=%v", cmpl, err)
	}

	stt, err := adp.TranscribeAudio(ctx, dep, &domain.CanonicalAudioTranscriptionRequest{
		Model:      "whisper-large-v3-turbo",
		FileName:   "test.wav",
		FileReader: strings.NewReader("RIFF"),
	})
	if err != nil || stt.Text != "hello groq" {
		t.Fatalf("TranscribeAudio failed: stt=%+v err=%v", stt, err)
	}

	ttsReader, ct, err := adp.GenerateSpeech(ctx, dep, &domain.CanonicalAudioSpeechRequest{
		Model: "canopylabs/orpheus-v1-english",
		Input: "hi",
		Voice: "tara",
	})
	if err != nil || ct != "audio/wav" {
		t.Fatalf("GenerateSpeech failed: ct=%q err=%v", ct, err)
	}
	ttsReader.Close()

	models, err := adp.ListModels(ctx, dep.Credential)
	if err != nil || len(models) != 1 || models[0].ModelName != "llama-3.1-8b-instant" {
		t.Fatalf("ListModels failed: models=%+v err=%v", models, err)
	}
}

func TestGroqAdapter_DistillModelRejectsToolsAndCustomTemperature(t *testing.T) {
	ctx := context.Background()
	adp := groq.NewAdapter(nil)
	dep := &domain.Deployment{
		Credential: &domain.ProviderCredential{
			Provider:        domain.ProviderGroq,
			DecryptedAPIKey: "gsk-test",
		},
	}

	_, err := adp.ChatCompletion(ctx, dep, &domain.CanonicalChatRequest{
		Model:    "deepseek-r1-distill-llama-70b",
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "hi"}},
		Tools:    []domain.CanonicalTool{{Type: "function", Function: domain.CanonicalFunction{Name: "ping"}}},
	})
	if err == nil {
		t.Fatal("expected distill model with tools to return error")
	}

	temp := 0.7
	_, err = adp.ChatCompletion(ctx, dep, &domain.CanonicalChatRequest{
		Model:       "deepseek-r1-distill-llama-70b",
		Messages:    []domain.CanonicalMessage{{Role: "user", Content: "hi"}},
		Temperature: &temp,
	})
	if err == nil {
		t.Fatal("expected distill model with custom temperature to return error")
	}
	if _, ok := any(adp).(adapter.OperationSupportChecker); !ok {
		t.Fatal("expected OperationSupportChecker implementation")
	}
}
