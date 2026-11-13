package mistral_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/adapter/mistral"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

func TestMistral_Vision_Moderation_Audio(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/chat/completions":
			var body map[string]any
			b, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(b, &body)
			msgs := body["messages"].([]any)
			if _, isArr := msgs[0].(map[string]any)["content"].([]any); !isArr {
				t.Fatalf("expected multimodal content array, got %#v", msgs[0])
			}
			_, _ = w.Write([]byte(`{"id":"m1","model":"pixtral-large-latest","choices":[{"index":0,"message":{"role":"assistant","content":"cat"},"finish_reason":"stop"}]}`))
		case "/moderations":
			_, _ = w.Write([]byte(`{"id":"mod1","model":"mistral-moderation-latest","results":[{"categories":{"hate":false},"category_scores":{"hate":0.01}}]}`))
		case "/audio/transcriptions":
			_, _ = w.Write([]byte(`{"text":"transcribed hello"}`))
		}
	}))
	defer srv.Close()

	adp := mistral.NewAdapter(srv.Client())
	dep := &domain.Deployment{
		ID:          "dep-mis-ext",
		GlobalModel: &domain.GlobalModel{ID: "mistral/pixtral-large-latest", Provider: domain.ProviderMistral, ModelName: "pixtral-large-latest"},
		Credential:  &domain.ProviderCredential{BaseURL: srv.URL, DecryptedAPIKey: "mis-test"},
	}

	if !adp.SupportsOperation(domain.OperationModeration) || !adp.SupportsOperation(domain.OperationAudioSTT) || adp.SupportsOperation(domain.OperationRerank) {
		t.Fatalf("unexpected SupportsOperation matrix for mistral")
	}

	chatResp, err := adp.ChatCompletion(context.Background(), dep, &domain.CanonicalChatRequest{
		Model: "pixtral-large-latest",
		Messages: []domain.CanonicalMessage{{
			Role:  "user",
			Parts: []domain.ContentPart{{Type: "text", Text: "What is this?"}, {Type: "image_url", ImageURL: &domain.ImageURL{URL: "https://example.com/cat.png"}}},
		}},
	})
	if err != nil || chatResp.Choices[0].Message.Content != "cat" {
		t.Fatalf("vision chat failed: resp=%+v err=%v", chatResp, err)
	}

	modResp, err := adp.Moderate(context.Background(), dep, &domain.CanonicalModerationRequest{Model: "mistral-moderation-latest", Input: []string{"hello"}})
	if err != nil || len(modResp.Results) != 1 || modResp.Results[0].Flagged {
		t.Fatalf("moderation failed: resp=%+v err=%v", modResp, err)
	}

	audResp, err := adp.TranscribeAudio(context.Background(), dep, &domain.CanonicalAudioTranscriptionRequest{
		Model:      "voxtral-mini-latest",
		FileName:   "test.mp3",
		FileReader: strings.NewReader("fakeaudio"),
	})
	if err != nil || audResp.Text != "transcribed hello" {
		t.Fatalf("transcription failed: resp=%+v err=%v", audResp, err)
	}
}
