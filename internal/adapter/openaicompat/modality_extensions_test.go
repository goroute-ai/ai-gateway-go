package openaicompat_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/adapter"
	"github.com/goroute-ai/ai-gateway-go/internal/adapter/openaicompat"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

func TestOpenAICompat_OperationResponses_ChecksResponsesFlag(t *testing.T) {
	chatOnly := openaicompat.NewAdapter(&openaicompat.DialectProfile{
		ID:                  "test_chat_only",
		SupportedOperations: &openaicompat.ProviderOperations{Chat: true, Responses: false},
		AuthStrategy:        &adapter.BearerAuthStrategy{},
	}, nil)
	if !chatOnly.SupportsOperation(domain.OperationChat) {
		t.Fatal("expected OperationChat=true")
	}
	if chatOnly.SupportsOperation(domain.OperationResponses) {
		t.Fatal("expected OperationResponses=false when Responses flag is false")
	}

	withResp := openaicompat.NewAdapter(&openaicompat.DialectProfile{
		ID:                  "test_with_responses",
		SupportedOperations: &openaicompat.ProviderOperations{Chat: false, Responses: true},
		AuthStrategy:        &adapter.BearerAuthStrategy{},
	}, nil)
	if !withResp.SupportsOperation(domain.OperationResponses) {
		t.Fatal("expected OperationResponses=true when Responses flag is true")
	}
}

func TestOpenAICompat_ChatDoesNotImplyLegacyCompletion(t *testing.T) {
	chatOnly := openaicompat.NewAdapter(&openaicompat.DialectProfile{
		ID:                  "test_chat_only",
		SupportedOperations: &openaicompat.ProviderOperations{Chat: true},
		AuthStrategy:        &adapter.BearerAuthStrategy{},
	}, nil)
	if !chatOnly.SupportsOperation(domain.OperationChat) {
		t.Fatal("expected chat support")
	}
	if chatOnly.SupportsOperation(domain.OperationCompletion) {
		t.Fatal("chat support must not imply legacy completion support")
	}
}

func TestOpenAICompat_ExtendedProfileModalitiesAreDeclared(t *testing.T) {
	reg := openaicompat.NewProfileRegistry(nil, nil)
	provider, err := reg.CreateAdapter(domain.ProviderXAI)
	if err != nil {
		t.Fatalf("CreateAdapter(xai): %v", err)
	}
	if !provider.(*openaicompat.Adapter).SupportsOperation(domain.OperationImageGeneration) {
		t.Fatal("expected xAI image generation support")
	}
	if !provider.(*openaicompat.Adapter).SupportsOperation(domain.OperationAudioSTT) {
		t.Fatal("expected xAI audio transcription support")
	}
	fal, err := reg.CreateAdapter(domain.ProviderFal)
	if err != nil {
		t.Fatalf("CreateAdapter(fal): %v", err)
	}
	if !fal.(*openaicompat.Adapter).SupportsOperation(domain.OperationImageGeneration) || !fal.(*openaicompat.Adapter).SupportsOperation(domain.OperationImageEdit) {
		t.Fatal("expected fal image generation and edit support")
	}
}

func TestOpenAICompat_PublicAIFlattensContentPartLists(t *testing.T) {
	var gotContent any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Messages []struct {
				Content any `json:"content"`
			} `json:"messages"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode request: %v", err)
		}
		if len(body.Messages) != 1 {
			t.Errorf("messages count = %d, want 1", len(body.Messages))
		} else {
			gotContent = body.Messages[0].Content
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"chatcmpl-test","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1,"completion_tokens":1,"total_tokens":2}}`)
	}))
	defer srv.Close()

	reg := openaicompat.NewProfileRegistry(srv.Client(), nil)
	profile, ok := reg.Get(domain.ProviderPublicAI)
	if !ok || !profile.ConvertContentListToString {
		t.Fatal("Public AI profile must enable content-list-to-string conversion")
	}
	provider, err := reg.CreateAdapter(domain.ProviderPublicAI)
	if err != nil {
		t.Fatalf("CreateAdapter(publicai): %v", err)
	}
	_, err = provider.ChatCompletion(context.Background(), &domain.Deployment{
		Credential: &domain.ProviderCredential{BaseURL: srv.URL, DecryptedAPIKey: "test-key"},
	}, &domain.CanonicalChatRequest{
		Model: "test-model",
		Messages: []domain.CanonicalMessage{{Role: "user", Parts: []domain.ContentPart{
			{Type: "text", Text: "describe this"},
			{Type: "image_url", ImageURL: &domain.ImageURL{URL: "https://example.test/image.png"}},
		}}},
	})
	if err != nil {
		t.Fatalf("ChatCompletion: %v", err)
	}
	if got, ok := gotContent.(string); !ok || got != "describe this" {
		t.Fatalf("content = %#v, want flattened text string", gotContent)
	}
}

func TestOpenAICompat_RerankWireShapes(t *testing.T) {
	tests := []struct {
		name     string
		provider domain.ProviderType
		topKey   string
		response string
		wantText string
	}{
		{
			name:     "voyage data results and top_k",
			provider: domain.ProviderVoyage,
			topKey:   "top_k",
			response: `{"id":"voyage-1","data":[{"index":0,"relevance_score":0.9,"document":"voyage doc"}],"usage":{"total_tokens":7}}`,
			wantText: "voyage doc",
		},
		{
			name:     "jina results and top_n",
			provider: domain.ProviderJina,
			topKey:   "top_n",
			response: `{"id":"jina-1","results":[{"index":0,"relevance_score":0.8,"document":"jina doc"}]}`,
			wantText: "jina doc",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var body map[string]any
				if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
					t.Errorf("decode request: %v", err)
				}
				if _, ok := body[tc.topKey]; !ok {
					t.Errorf("request body missing %q: %#v", tc.topKey, body)
				}
				wrongTopKey := "top_n"
				if tc.topKey == "top_n" {
					wrongTopKey = "top_k"
				}
				if _, wrong := body[wrongTopKey]; wrong {
					t.Errorf("request body contains incompatible top-N field: %#v", body)
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, tc.response)
			}))
			defer srv.Close()

			adp := openaicompat.NewAdapter(&openaicompat.DialectProfile{
				ID:                  tc.provider,
				DefaultBaseURL:      srv.URL,
				AuthStrategy:        &adapter.BearerAuthStrategy{},
				SupportedOperations: &openaicompat.ProviderOperations{Rerank: true},
			}, srv.Client())
			topN := 1
			resp, err := adp.Rerank(context.Background(), &domain.Deployment{
				Credential: &domain.ProviderCredential{BaseURL: srv.URL},
			}, &domain.CanonicalRerankRequest{
				Model: "reranker", Query: "query", Documents: []domain.RerankDocument{{Text: "doc"}}, TopN: &topN,
			})
			if err != nil {
				t.Fatalf("Rerank failed: %v", err)
			}
			if len(resp.Results) != 1 || resp.Results[0].Document["text"] != tc.wantText {
				t.Fatalf("unexpected normalized results: %+v", resp.Results)
			}
			if tc.provider == domain.ProviderVoyage && resp.Usage.TotalTokens != 7 {
				t.Fatalf("Voyage total_tokens = %d, want 7", resp.Usage.TotalTokens)
			}
		})
	}
}

func TestOpenAICompat_OptionalModalities_DispatchAndGuard(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/completions":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"cmpl-1","model":"m1","choices":[{"index":0,"text":"done","finish_reason":"stop"}]}`))
		case "/rerank":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"rr-1","results":[{"index":0,"relevance_score":0.95}]}`))
		case "/moderations":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"mod-1","model":"m1","results":[{"flagged":false}]}`))
		case "/images/generations":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"created":1,"data":[{"url":"https://example.com/img.png"}]}`))
		case "/images/edits", "/images/variations":
			if err := r.ParseMultipartForm(1 << 20); err != nil {
				t.Errorf("parse multipart image request: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			image, _, err := r.FormFile("image")
			if err != nil {
				t.Errorf("missing multipart image: %v", err)
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			_ = image.Close()
			if r.URL.Path == "/images/edits" && r.FormValue("prompt") != "make blue" {
				t.Errorf("image edit prompt = %q", r.FormValue("prompt"))
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"created":1,"data":[{"url":"https://example.com/img.png"}]}`))
		case "/audio/transcriptions":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"text":"hello world"}`))
		case "/audio/speech":
			w.Header().Set("Content-Type", "audio/mpeg")
			_, _ = w.Write([]byte("ID3AUDIO"))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	profile := &openaicompat.DialectProfile{
		ID:             "test_all_ops",
		DefaultBaseURL: srv.URL,
		AuthStrategy:   &adapter.BearerAuthStrategy{},
		SupportedOperations: &openaicompat.ProviderOperations{
			Chat: true, Completion: true, Embeddings: true, Rerank: true, Moderations: true, ImageGen: true,
			ImageEdit: true, ImageVariation: true, AudioSTT: true, AudioTTS: true,
		},
	}
	adp := openaicompat.NewAdapter(profile, srv.Client())
	dep := &domain.Deployment{
		ID:         "dep-1",
		Credential: &domain.ProviderCredential{BaseURL: srv.URL, DecryptedAPIKey: "sk-test"},
	}

	cmpl, err := adp.TextCompletion(context.Background(), dep, &domain.CanonicalCompletionRequest{
		Model:  "m1",
		Prompt: domain.CompletionPrompt{Strings: []string{"hi"}},
	})
	if err != nil || len(cmpl.Choices) != 1 || cmpl.Choices[0].Text != "done" {
		t.Fatalf("TextCompletion failed: %+v err=%v", cmpl, err)
	}

	rr, err := adp.Rerank(context.Background(), dep, &domain.CanonicalRerankRequest{
		Model:     "m1",
		Query:     "q",
		Documents: []domain.RerankDocument{{Text: "doc1"}},
	})
	if err != nil || len(rr.Results) != 1 || rr.Results[0].RelevanceScore != 0.95 {
		t.Fatalf("Rerank failed: %+v err=%v", rr, err)
	}

	mod, err := adp.Moderate(context.Background(), dep, &domain.CanonicalModerationRequest{
		Model: "m1",
		Input: []string{"hi"},
	})
	if err != nil || len(mod.Results) != 1 {
		t.Fatalf("Moderate failed: %+v err=%v", mod, err)
	}

	img, err := adp.GenerateImage(context.Background(), dep, &domain.CanonicalImageRequest{
		Model:  "m1",
		Prompt: "cat",
	})
	if err != nil || len(img.Data) != 1 || img.Data[0].URL != "https://example.com/img.png" {
		t.Fatalf("GenerateImage failed: %+v err=%v", img, err)
	}
	for _, op := range []string{"edit", "variation"} {
		imgResp, err := adp.GenerateImage(context.Background(), dep, &domain.CanonicalImageRequest{
			Model: "m1", Prompt: "make blue", N: 1, Operation: op, ImageData: []byte("png"), ImageFilename: "source.png",
		})
		if err != nil || len(imgResp.Data) != 1 {
			t.Fatalf("GenerateImage(%s) failed: %+v err=%v", op, imgResp, err)
		}
	}

	stt, err := adp.TranscribeAudio(context.Background(), dep, &domain.CanonicalAudioTranscriptionRequest{
		Model:      "m1",
		FileName:   "a.mp3",
		FileReader: strings.NewReader("audio"),
	})
	if err != nil || stt.Text != "hello world" {
		t.Fatalf("TranscribeAudio failed: %+v err=%v", stt, err)
	}

	rc, ct, err := adp.GenerateSpeech(context.Background(), dep, &domain.CanonicalAudioSpeechRequest{
		Model: "m1",
		Input: "hello",
		Voice: "alloy",
	})
	if err != nil || ct != "audio/mpeg" {
		t.Fatalf("GenerateSpeech failed: ct=%q err=%v", ct, err)
	}
	b, _ := io.ReadAll(rc)
	_ = rc.Close()
	if string(b) != "ID3AUDIO" {
		t.Fatalf("unexpected audio bytes: %q", string(b))
	}

	// Unsupported profile must fail closed
	restricted := openaicompat.NewAdapter(&openaicompat.DialectProfile{
		ID:                  "test_restricted",
		SupportedOperations: &openaicompat.ProviderOperations{Chat: true},
		AuthStrategy:        &adapter.BearerAuthStrategy{},
	}, srv.Client())
	if _, err := restricted.Rerank(context.Background(), dep, &domain.CanonicalRerankRequest{Model: "m1", Query: "q"}); err == nil {
		t.Fatal("expected restricted profile to reject Rerank")
	}
	if _, err := restricted.GenerateImage(context.Background(), dep, &domain.CanonicalImageRequest{Model: "m1", Operation: "edit", ImageData: []byte("png")}); err == nil {
		t.Fatal("expected restricted profile to reject image edits")
	}
}
