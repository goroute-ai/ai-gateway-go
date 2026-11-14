package gateway_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/pkg/gateway"
)

func TestSDKDeclarativeRouterAndOneLineChat(t *testing.T) {
	ctx := context.Background()

	// 1. Mock upstream Gemini and Anthropic servers
	mockGemini := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, ":generateContent"):
			fmt.Fprint(w, `{"candidates":[{"index":0,"content":{"role":"model","parts":[{"text":"Gemini Flash SDK response"}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":10,"candidatesTokenCount":12,"totalTokenCount":22}}`)
		case strings.HasSuffix(r.URL.Path, ":streamGenerateContent"):
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprint(w, "data: {\"candidates\":[{\"index\":0,\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"Hello \"}]}}]}\n\n")
			fmt.Fprint(w, "data: {\"candidates\":[{\"index\":0,\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"from Stream!\"}]},\"finishReason\":\"STOP\"}],\"usageMetadata\":{\"promptTokenCount\":5,\"candidatesTokenCount\":5,\"totalTokenCount\":10}}\n\n")
		}
	}))
	defer mockGemini.Close()

	mockClaude := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/messages" {
			fmt.Fprint(w, `{"id":"msg_sdk","type":"message","role":"assistant","model":"claude-sonnet-4-20250514","content":[{"type":"text","text":"Claude Sonnet deep reasoning SDK response"}],"stop_reason":"end_turn","usage":{"input_tokens":30,"output_tokens":20}}`)
		}
	}))
	defer mockClaude.Close()

	// 2. Initialize Gateway SDK in 1 step with declarative ModelList
	gw, err := gateway.New(
		gateway.WithModelList(
			gateway.ModelEntry{
				ModelName: "fast",
				Model:     "gemini/gemini-2.5-flash",
				APIKey:    "dummy-gemini-key",
				APIBase:   mockGemini.URL,
			},
			gateway.ModelEntry{
				ModelName: "reasoning",
				Model:     "anthropic/claude-sonnet-4-20250514",
				APIKey:    "dummy-claude-key",
				APIBase:   mockClaude.URL,
			},
		),
	)
	if err != nil {
		t.Fatalf("gateway.New failed: %v", err)
	}
	defer gw.Close()

	// 3. Mode 1: Explicit Model Name ("gemini-2.5-flash") - resolved dynamically from the catalogue!
	res1, err := gw.Chat(ctx, "gemini-2.5-flash", "Explain Pure Go in one sentence.")
	if err != nil {
		t.Fatalf("Mode 1 (explicit model) failed: %v", err)
	}
	if res1.Provider != "gemini" || res1.Model != "gemini-2.5-flash" || res1.Content != "Gemini Flash SDK response" {
		t.Fatalf("unexpected Mode 1 result: %+v", res1)
	}

	// 4. Mode 2: Logical Alias ("fast")
	res2, err := gw.Chat(ctx, "fast", "What is 2 + 2?", gateway.WithSystem("Be concise."), gateway.WithTemperature(0.0))
	if err != nil {
		t.Fatalf("Mode 2 (logical alias) failed: %v", err)
	}
	if res2.Provider != "gemini" || res2.Model != "gemini-2.5-flash" {
		t.Fatalf("unexpected Mode 2 result: %+v", res2)
	}

	// 5. Mode 3: Smart Routing ("auto")
	res3, err := gw.Chat(ctx, "auto", "Analyze and architect a distributed consensus protocol step by step: prove safety guarantees and debug this code:\n```go\nfunc electLeader() { select {} }\n```")
	if err != nil {
		t.Fatalf("Mode 3 (smart routing) failed: %v", err)
	}
	if res3.Provider != "anthropic" || res3.Model != "claude-sonnet-4-20250514" || res3.Content != "Claude Sonnet deep reasoning SDK response" {
		t.Fatalf("unexpected Mode 3 result: %+v", res3)
	}

	// 6. Streaming Helper (`StreamChat`)
	var chunks []string
	streamRes, err := gw.StreamChat(ctx, "fast", "Stream a greeting", func(delta string) error {
		chunks = append(chunks, delta)
		return nil
	})
	if err != nil {
		t.Fatalf("StreamChat failed: %v", err)
	}
	if streamRes.Content != "Hello from Stream!" || len(chunks) != 2 {
		t.Fatalf("unexpected StreamChat output: content=%q chunks=%v", streamRes.Content, chunks)
	}
}

func TestSDKHelpersAndFailover(t *testing.T) {
	ctx := context.Background()

	gw, err := gateway.New(
		gateway.WithModelList(
			gateway.ModelEntry{
				ModelName:      "primary-chat",
				Model:          "gemini/gemini-2.5-flash",
				Fallbacks:      []string{"backup-claude"},
				SimulateStatus: 503,
			},
			gateway.ModelEntry{
				ModelName: "backup-claude",
				Model:     "anthropic/claude-sonnet-4-20250514",
			},
		),
		gateway.WithDemoMocksIfEnvMissing(),
	)
	if err != nil {
		t.Fatalf("gateway.New failed: %v", err)
	}
	defer gw.Close()

	// 1. Test cross-provider fallback (Primary 503 -> Secondary Claude)
	res, err := gw.Chat(ctx, "primary-chat", "Verify automatic failover.")
	if err != nil {
		t.Fatalf("Chat with fallback failed: %v", err)
	}
	if !res.FallbackAttempted || res.Provider != "anthropic" {
		t.Fatalf("expected FallbackAttempted=true and Provider=anthropic, got %+v", res)
	}

	// 2. Test ListModels
	models, err := gw.ListModels(ctx)
	if err != nil || len(models) == 0 {
		t.Fatalf("ListModels failed: err=%v models=%v", err, models)
	}

	// 3. Test IssueVirtualKey + WithKey + RevokeVirtualKey
	vk, err := gw.IssueVirtualKey(ctx, domain.VirtualKey{
		Name:          "test-scoped-key",
		AllowedModels: []string{"backup-claude"},
	})
	if err != nil || vk.RawKey == "" {
		t.Fatalf("IssueVirtualKey failed: %v", err)
	}
	scopedClient := gw.WithKey(vk.RawKey)
	if _, err := scopedClient.Chat(ctx, "backup-claude", "Hello"); err != nil {
		t.Fatalf("scopedClient.Chat on allowed model failed: %v", err)
	}
	if err := gw.RevokeVirtualKey(ctx, vk.ID); err != nil {
		t.Fatalf("RevokeVirtualKey failed: %v", err)
	}
	if _, err := scopedClient.Chat(ctx, "backup-claude", "Hello after revoke"); err == nil {
		t.Fatalf("expected revoked key to fail")
	}

	// 4. Test SpendSummary
	summary, err := gw.SpendSummary(ctx)
	if err != nil || summary.TotalRequests < 2 {
		t.Fatalf("SpendSummary failed: err=%v summary=%+v", err, summary)
	}
}

func TestSDK_PublicTypesAndLoggingOptions(t *testing.T) {
	ctx := context.Background()

	// Initialize embedded gateway with WithSilentLogs() and WithLogLevel("info")
	gw, err := gateway.New(
		gateway.WithDemoMocksIfEnvMissing(),
		gateway.WithSilentLogs(),
		gateway.WithLogLevel("info"),
		gateway.WithModelList(
			gateway.ModelEntry{
				ModelName: "test-fast",
				Model:     "gemini/gemini-2.5-flash",
			},
		),
	)
	if err != nil {
		t.Fatalf("New() with silent logs failed: %v", err)
	}
	defer gw.Close()

	// 1. Test ChatWithMessages with public ChatRequest
	res, err := gw.ChatWithMessages(ctx, gateway.ChatRequest{
		Model: "test-fast",
		Messages: []gateway.Message{
			{Role: "user", Content: "Hello with public types"},
		},
	})
	if err != nil {
		t.Fatalf("ChatWithMessages failed: %v", err)
	}
	if res.Content == "" {
		t.Fatalf("expected non-empty content from ChatWithMessages")
	}

	// 2. Test CreateVirtualKey with public VirtualKeyRequest
	vk, err := gw.CreateVirtualKey(ctx, gateway.VirtualKeyRequest{
		Name:            "test-public-key",
		Role:            "developer",
		MaxBudgetMicros: 10000000,
		AllowedModels:   []string{"test-fast"},
	})
	if err != nil {
		t.Fatalf("CreateVirtualKey failed: %v", err)
	}
	if vk.ID == "" || vk.Key == "" {
		t.Fatalf("expected populated ID and Key in VirtualKeyInfo, got %+v", vk)
	}
}

func TestSDKDataPlaneParityMethods(t *testing.T) {
	ctx := context.Background()

	remoteSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer sk-gw-remote-test" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/v1/completions":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"cmpl_1","object":"text_completion","model":"gpt-3.5-turbo-instruct","choices":[{"index":0,"text":"completed text"}]}`))
		case "/v1/embeddings":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"object":"list","model":"text-embedding-3-small","data":[{"index":0,"embedding":[0.1,0.2]}]}`))
		case "/v1/rerank":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"rr_1","results":[{"index":0,"relevance_score":0.95}]}`))
		case "/v1/moderations":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"modr_1","model":"omni-moderation-latest","results":[{"flagged":false}]}`))
		case "/v1/responses":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"resp_1","object":"response","status":"completed","model":"gpt-4o"}`))
		case "/v1/messages":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"msg_1","type":"message","role":"assistant"}`))
		case "/v1/audio/transcriptions":
			if !strings.HasPrefix(r.Header.Get("Content-Type"), "multipart/form-data;") {
				http.Error(w, "expected multipart", http.StatusBadRequest)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"text":"hello audio"}`))
		case "/v1/audio/speech":
			w.Header().Set("Content-Type", "audio/mpeg")
			_, _ = w.Write([]byte("ID3-AUDIO-BYTES"))
		case "/v1/images/generations":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"created":1730000000,"data":[{"url":"https://example.com/img.png"}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer remoteSrv.Close()

	client, err := gateway.New(gateway.WithRemote(remoteSrv.URL, "sk-gw-remote-test"))
	if err != nil {
		t.Fatalf("gateway.New(WithRemote): %v", err)
	}
	defer client.Close()

	cmpl, err := client.Completions(ctx, domain.CanonicalCompletionRequest{Model: "gpt-3.5-turbo-instruct", Prompt: domain.CompletionPrompt{Strings: []string{"hi"}}})
	if err != nil || len(cmpl.Choices) != 1 || cmpl.Choices[0].Text != "completed text" {
		t.Fatalf("Completions failed: res=%+v err=%v", cmpl, err)
	}

	emb, err := client.Embeddings(ctx, domain.CanonicalEmbeddingRequest{Model: "text-embedding-3-small", Input: []string{"hello"}})
	if err != nil || len(emb.Data) != 1 {
		t.Fatalf("Embeddings failed: res=%+v err=%v", emb, err)
	}

	rr, err := client.Rerank(ctx, domain.CanonicalRerankRequest{Model: "rerank-1", Query: "q", Documents: []domain.RerankDocument{{Text: "doc1"}}})
	if err != nil || len(rr.Results) != 1 {
		t.Fatalf("Rerank failed: res=%+v err=%v", rr, err)
	}

	mod, err := client.Moderations(ctx, domain.CanonicalModerationRequest{Model: "omni-moderation-latest", Input: []string{"safe"}})
	if err != nil || len(mod.Results) != 1 {
		t.Fatalf("Moderations failed: res=%+v err=%v", mod, err)
	}

	respOut, err := client.Responses(ctx, domain.CanonicalResponseRequest{Model: "gpt-4o", Input: json.RawMessage(`"hi"`)})
	if err != nil || respOut.ID != "resp_1" {
		t.Fatalf("Responses failed: res=%+v err=%v", respOut, err)
	}

	msgOut, err := client.Messages(ctx, map[string]any{"model": "claude-sonnet-4-20250514", "max_tokens": 16})
	if err != nil || msgOut["id"] != "msg_1" {
		t.Fatalf("Messages failed: res=%+v err=%v", msgOut, err)
	}

	sttOut, err := client.AudioTranscription(ctx, gateway.AudioTranscriptionRequest{
		Model:    "whisper-1",
		FileName: "sample.wav",
		Audio:    bytes.NewReader([]byte("RIFF-WAV")),
	})
	if err != nil || sttOut.Text != "hello audio" {
		t.Fatalf("AudioTranscription failed: res=%+v err=%v", sttOut, err)
	}

	ttsBytes, err := client.AudioSpeech(ctx, domain.CanonicalAudioSpeechRequest{Model: "tts-1", Input: "hi", Voice: "alloy"})
	if err != nil || string(ttsBytes) != "ID3-AUDIO-BYTES" {
		t.Fatalf("AudioSpeech failed: bytes=%q err=%v", string(ttsBytes), err)
	}

	imgOut, err := client.Images(ctx, domain.CanonicalImageRequest{Model: "dall-e-3", Prompt: "a cat"})
	if err != nil || len(imgOut.Data) != 1 {
		t.Fatalf("Images failed: res=%+v err=%v", imgOut, err)
	}
}

func TestSDKWithConfigFileGuardrailsScanner(t *testing.T) {
	scannerSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"decision":"block","violations":["blocked_by_config"]}`))
	}))
	defer scannerSrv.Close()

	cfgYAML := fmt.Sprintf(`
server:
  port: 8080
  environment: "test"
storage:
  mode: "memory"
guardrails:
  scanners:
    - name: "cfg-scanner"
      url: %q
      timeout_ms: 1000
      fail_open: false
`, scannerSrv.URL)

	cfgPath := filepath.Join(t.TempDir(), "gateway.yaml")
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0600); err != nil {
		t.Fatalf("write config file: %v", err)
	}

	client, err := gateway.New(
		gateway.WithConfigFile(cfgPath),
		gateway.WithAllowPrivateNetworks(),
		gateway.WithSilentLogs(),
		gateway.WithDemoMocksIfEnvMissing(),
		gateway.WithModelList(gateway.ModelEntry{
			ModelName: "fast",
			Model:     "openai/gpt-4o-mini",
		}),
	)
	if err != nil {
		t.Fatalf("gateway.New(WithConfigFile): %v", err)
	}
	defer client.Close()

	_, err = client.Chat(context.Background(), "fast", "hello")
	if err == nil || !strings.Contains(err.Error(), "400") && !strings.Contains(err.Error(), "guardrail") && !strings.Contains(err.Error(), "blocked") {
		t.Fatalf("expected guardrail block error from config-wired scanner, got: %v", err)
	}
}

func TestSDKStreamingParityAndWithConfigFileRedisAndWithKey(t *testing.T) {
	ctx := context.Background()

	mr, err := miniredis.Run()
	if err != nil {
		t.Fatalf("miniredis.Run: %v", err)
	}
	defer mr.Close()

	mockGemini := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: {\"candidates\":[{\"index\":0,\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"Stream \"}]}}]}\n\n")
		fmt.Fprint(w, "data: {\"candidates\":[{\"index\":0,\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"parity ok\"}]},\"finishReason\":\"STOP\"}],\"usageMetadata\":{\"promptTokenCount\":4,\"candidatesTokenCount\":3,\"totalTokenCount\":7}}\n\n")
	}))
	defer mockGemini.Close()

	mockOpenAI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: {\"id\":\"cmpl_s1\",\"object\":\"text_completion\",\"model\":\"gpt-3.5-turbo-instruct\",\"choices\":[{\"index\":0,\"text\":\"Stream \"}]}\n\n")
		fmt.Fprint(w, "data: {\"id\":\"cmpl_s1\",\"object\":\"text_completion\",\"model\":\"gpt-3.5-turbo-instruct\",\"choices\":[{\"index\":0,\"text\":\"parity ok\",\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":4,\"completion_tokens\":3,\"total_tokens\":7}}\n\n")
		fmt.Fprint(w, "data: [DONE]\n\n")
	}))
	defer mockOpenAI.Close()

	cfgYAML := fmt.Sprintf(`
server:
  port: 8080
  environment: "test"
redis:
  url: "redis://%s/0"
`, mr.Addr())

	cfgPath := filepath.Join(t.TempDir(), "gateway-redis.yaml")
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0600); err != nil {
		t.Fatalf("write config file: %v", err)
	}

	gw, err := gateway.New(
		gateway.WithConfigFile(cfgPath),
		gateway.WithAllowPrivateNetworks(),
		gateway.WithSilentLogs(),
		gateway.WithModelList(
			gateway.ModelEntry{
				ModelName: "fast",
				Model:     "gemini/gemini-2.5-flash",
				APIKey:    "test-key",
				APIBase:   mockGemini.URL,
			},
			gateway.ModelEntry{
				ModelName: "instruct",
				Model:     "openai/gpt-3.5-turbo-instruct",
				APIKey:    "test-key",
				APIBase:   mockOpenAI.URL,
			},
		),
	)
	if err != nil {
		t.Fatalf("gateway.New(WithConfigFile redis): %v", err)
	}

	vk, err := gw.IssueVirtualKey(ctx, domain.VirtualKey{
		Name:          "stream-parity-key",
		AllowedModels: []string{"fast", "instruct"},
	})
	if err != nil {
		t.Fatalf("IssueVirtualKey: %v", err)
	}

	scoped := gw.WithKey(vk.RawKey)
	defer scoped.Close()

	// 1. StreamCompletions
	var cmplDeltas []string
	cmplOut, err := scoped.StreamCompletions(ctx, domain.CanonicalCompletionRequest{
		Model:  "instruct",
		Prompt: domain.CompletionPrompt{Strings: []string{"Say hi"}},
	}, func(delta string) error {
		cmplDeltas = append(cmplDeltas, delta)
		return nil
	})
	if err != nil {
		t.Fatalf("StreamCompletions failed: %v", err)
	}
	if len(cmplOut.Choices) != 1 || cmplOut.Choices[0].Text != "Stream parity ok" || len(cmplDeltas) != 2 {
		t.Fatalf("unexpected StreamCompletions result: %+v deltas=%v", cmplOut, cmplDeltas)
	}

	// 2. StreamResponses
	var respDeltas []string
	respOut, err := scoped.StreamResponses(ctx, domain.CanonicalResponseRequest{
		Model: "fast",
		Input: json.RawMessage(`"Say hi"`),
	}, func(delta string) error {
		respDeltas = append(respDeltas, delta)
		return nil
	})
	if err != nil {
		t.Fatalf("StreamResponses failed: %v", err)
	}
	if respOut == nil || respOut.Status != "completed" || strings.Join(respDeltas, "") != "Stream parity ok" {
		t.Fatalf("unexpected StreamResponses result: %+v deltas=%v", respOut, respDeltas)
	}

	// 3. StreamMessages
	var msgDeltas []string
	msgOut, err := scoped.StreamMessages(ctx, map[string]any{
		"model":      "fast",
		"max_tokens": 32,
		"messages": []map[string]any{
			{"role": "user", "content": "Say hi"},
		},
	}, func(delta string) error {
		msgDeltas = append(msgDeltas, delta)
		return nil
	})
	if err != nil {
		t.Fatalf("StreamMessages failed: %v", err)
	}
	if msgOut["text"] != "Stream parity ok" || strings.Join(msgDeltas, "") != "Stream parity ok" {
		t.Fatalf("unexpected StreamMessages result: %+v deltas=%v", msgOut, msgDeltas)
	}
}
