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

	// 1. Mock upstream OpenAI and Anthropic servers
	mockOpenAI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Stream bool `json:"stream"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Stream {
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprint(w, "data: {\"id\":\"chatcmpl_s1\",\"object\":\"chat.completion.chunk\",\"model\":\"gpt-4o-mini\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"Hello \"}}]}\n\n")
			fmt.Fprint(w, "data: {\"id\":\"chatcmpl_s1\",\"object\":\"chat.completion.chunk\",\"model\":\"gpt-4o-mini\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"from Stream!\"},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":5,\"completion_tokens\":5,\"total_tokens\":10}}\n\n")
			fmt.Fprint(w, "data: [DONE]\n\n")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"id":"chatcmpl_sdk","object":"chat.completion","model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"OpenAI Mini SDK response"},"finish_reason":"stop"}],"usage":{"prompt_tokens":10,"completion_tokens":12,"total_tokens":22}}`)
	}))
	defer mockOpenAI.Close()

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
				Model:     "openai/gpt-4o-mini",
				APIKey:    "dummy-openai-key",
				APIBase:   mockOpenAI.URL,
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

	// 3. Mode 1: Explicit Model Name ("gpt-4o-mini") - resolved dynamically from the catalogue!
	res1, err := gw.Chat(ctx, "gpt-4o-mini", "Explain Pure Go in one sentence.")
	if err != nil {
		t.Fatalf("Mode 1 (explicit model) failed: %v", err)
	}
	if res1.Provider != "openai" || res1.Model != "gpt-4o-mini" || res1.Content != "OpenAI Mini SDK response" {
		t.Fatalf("unexpected Mode 1 result: %+v", res1)
	}

	// 4. Mode 2: Logical Alias ("fast")
	res2, err := gw.Chat(ctx, "fast", "What is 2 + 2?", gateway.WithSystem("Be concise."), gateway.WithTemperature(0.0))
	if err != nil {
		t.Fatalf("Mode 2 (logical alias) failed: %v", err)
	}
	if res2.Provider != "openai" || res2.Model != "gpt-4o-mini" {
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
				Model:          "groq/llama-3.1-8b-instant",
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
				Model:     "openai/gpt-4o-mini",
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

	mockGroq := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: {\"id\":\"chatcmpl_p1\",\"object\":\"chat.completion.chunk\",\"model\":\"llama-3.1-8b-instant\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"Stream \"}}]}\n\n")
		fmt.Fprint(w, "data: {\"id\":\"chatcmpl_p1\",\"object\":\"chat.completion.chunk\",\"model\":\"llama-3.1-8b-instant\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"parity ok\"},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":4,\"completion_tokens\":3,\"total_tokens\":7}}\n\n")
		fmt.Fprint(w, "data: [DONE]\n\n")
	}))
	defer mockGroq.Close()

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
				Model:     "groq/llama-3.1-8b-instant",
				APIKey:    "test-key",
				APIBase:   mockGroq.URL,
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
	defer gw.Close()

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

func TestWithKeyCloseDoesNotShutDownParent(t *testing.T) {
	ctx := context.Background()

	parent, err := gateway.New(
		gateway.WithDemoMocksIfEnvMissing(),
		gateway.WithSilentLogs(),
		gateway.WithModelList(
			gateway.ModelEntry{
				ModelName: "fast",
				Model:     "groq/llama-3.1-8b-instant",
			},
		),
	)
	if err != nil {
		t.Fatalf("gateway.New failed: %v", err)
	}
	defer parent.Close()

	vk, err := parent.IssueVirtualKey(ctx, domain.VirtualKey{
		Name:          "scoped-borrowed-key",
		AllowedModels: []string{"fast"},
	})
	if err != nil || vk.RawKey == "" {
		t.Fatalf("IssueVirtualKey failed: %v", err)
	}

	child := parent.WithKey(vk.RawKey)
	if _, err := child.Chat(ctx, "fast", "Hello from child before Close"); err != nil {
		t.Fatalf("child.Chat failed before Close: %v", err)
	}

	// Closing a borrowed WithKey client must be a no-op and leave parent operational.
	child.Close()

	res, err := parent.Chat(ctx, "fast", "Hello from parent after child.Close")
	if err != nil || res.Content == "" {
		t.Fatalf("parent.Chat failed after child.Close(): res=%+v err=%v", res, err)
	}
}

func TestSDK_FilesBatchesTokenizeImagesAndAdminLifecycle(t *testing.T) {
	ctx := context.Background()

	mockOpenAI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/images/edits":
			fmt.Fprint(w, `{"created":1730000001,"data":[{"url":"https://example.com/edited.png","revised_prompt":"edited image"}]}`)
		case "/v1/images/variations":
			fmt.Fprint(w, `{"created":1730000002,"data":[{"b64_json":"aGVsbG8="}]}`)
		case "/v1/chat/completions", "/chat/completions":
			fmt.Fprint(w, `{"id":"chatcmpl_batch","object":"chat.completion","created":1730000003,"model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"batch ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":5,"completion_tokens":2,"total_tokens":7}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer mockOpenAI.Close()

	cfgDir := t.TempDir()
	cfgPath := filepath.Join(cfgDir, "gateway.yaml")
	cfgYAML := `
server:
  environment: "development"
auth:
  master_admin_key: "sk-gw-master-admin-sdk-test-key"
`
	if err := os.WriteFile(cfgPath, []byte(cfgYAML), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	gw, err := gateway.New(
		gateway.WithConfigFile(cfgPath),
		gateway.WithSilentLogs(),
		gateway.WithAllowPrivateNetworks(),
		gateway.WithModelList(
			gateway.ModelEntry{
				ModelName: "dall-e-2",
				Model:     "openai/gpt-image-2",
				APIKey:    "sk-test-openai",
				APIBase:   mockOpenAI.URL,
			},
			gateway.ModelEntry{
				ModelName: "gpt-4o-mini",
				Model:     "openai/gpt-4o-mini",
				APIKey:    "sk-test-openai",
				APIBase:   mockOpenAI.URL,
			},
		),
	)
	if err != nil {
		t.Fatalf("gateway.New failed: %v", err)
	}
	defer gw.Close()

	// Issue a virtual key with wildcard endpoint access for data-plane tests
	dpKey, err := gw.IssueVirtualKey(ctx, domain.VirtualKey{
		Name:             "sdk-dp-wildcard",
		OrgID:            "org_default",
		AllowedModels:    []string{"*"},
		AllowedEndpoints: []string{"*"},
	})
	if err != nil || dpKey.RawKey == "" {
		t.Fatalf("IssueVirtualKey(dpKey) failed: %v", err)
	}
	dpClient := gw.WithKey(dpKey.RawKey)

	// 1. Files round-trip
	batchPayload := []byte(`{"custom_id":"req-1","method":"POST","url":"/v1/chat/completions","body":{"model":"gpt-4o-mini","messages":[{"role":"user","content":"hi"}]}}` + "\n")
	uploaded, err := dpClient.UploadFile(ctx, gateway.FileUploadRequest{
		FileName: "batch.jsonl",
		Purpose:  "batch",
		Content:  bytes.NewReader(batchPayload),
	})
	if err != nil {
		t.Fatalf("UploadFile failed: %v", err)
	}
	if uploaded.ID == "" || uploaded.Filename != "batch.jsonl" || uploaded.Purpose != "batch" {
		t.Fatalf("unexpected UploadFile result: %+v", uploaded)
	}

	files, err := dpClient.ListFiles(ctx, "batch")
	if err != nil || len(files) == 0 {
		t.Fatalf("ListFiles failed: files=%+v err=%v", files, err)
	}
	gotFile, err := dpClient.GetFile(ctx, uploaded.ID)
	if err != nil || gotFile.ID != uploaded.ID {
		t.Fatalf("GetFile failed: got=%+v err=%v", gotFile, err)
	}
	gotContent, err := dpClient.GetFileContent(ctx, uploaded.ID)
	if err != nil || !bytes.Equal(gotContent, batchPayload) {
		t.Fatalf("GetFileContent failed: len=%d err=%v", len(gotContent), err)
	}

	// 2. Batches round-trip
	batch, err := dpClient.CreateBatch(ctx, gateway.BatchCreateRequest{
		InputFileID: uploaded.ID,
		Endpoint:    "/v1/chat/completions",
	})
	if err != nil || batch.ID == "" {
		t.Fatalf("CreateBatch failed: batch=%+v err=%v", batch, err)
	}
	batches, err := dpClient.ListBatches(ctx)
	if err != nil || len(batches) == 0 {
		t.Fatalf("ListBatches failed: batches=%+v err=%v", batches, err)
	}
	gotBatch, err := dpClient.GetBatch(ctx, batch.ID)
	if err != nil || gotBatch.ID != batch.ID {
		t.Fatalf("GetBatch failed: got=%+v err=%v", gotBatch, err)
	}
	cancelled, err := dpClient.CancelBatch(ctx, batch.ID)
	if err != nil || cancelled.Status != "cancelled" {
		t.Fatalf("CancelBatch failed: cancelled=%+v err=%v", cancelled, err)
	}

	if err := dpClient.DeleteFile(ctx, uploaded.ID); err != nil {
		t.Fatalf("DeleteFile failed: %v", err)
	}
	if _, err := dpClient.GetFile(ctx, uploaded.ID); err == nil {
		t.Fatal("expected GetFile after DeleteFile to fail")
	}

	// 3. Tokenization
	tokResp, err := dpClient.Tokenize(ctx, gateway.TokenizeRequest{
		Model:  "gpt-4o-mini",
		Prompt: "Hello world from GoRoute SDK",
	})
	if err != nil || tokResp.Count <= 0 || tokResp.TotalTokens != tokResp.Count {
		t.Fatalf("Tokenize failed: resp=%+v err=%v", tokResp, err)
	}
	ctResp, err := dpClient.CountTokens(ctx, gateway.CountTokensRequest{
		Model:  "gpt-4o-mini",
		System: "Be concise.",
		Messages: []gateway.CountTokensMessage{
			{Role: "user", Content: "Count my tokens please."},
		},
	})
	if err != nil || ctResp.InputTokens <= 0 {
		t.Fatalf("CountTokens failed: resp=%+v err=%v", ctResp, err)
	}

	// 4. Images (Edit & Variation)
	fakePNG := []byte("\x89PNG\r\n\x1a\n" + "test-png-data")
	// Embedded gateway: catalog models lack image_edit/image_variation in SupportedOperations,
	// so verify the request passes auth + PNG validation and reaches router operation check.
	if _, err := dpClient.ImageEdit(ctx, gateway.ImageEditRequest{
		Model:     "dall-e-2",
		Prompt:    "Add a hat",
		ImageName: "img.png",
		Image:     bytes.NewReader(fakePNG),
	}); err == nil || !strings.Contains(err.Error(), "unsupported_operation") {
		t.Fatalf("expected unsupported_operation from embedded ImageEdit, got: %v", err)
	}
	if _, err := dpClient.ImageVariation(ctx, gateway.ImageVariationRequest{
		Model:     "dall-e-2",
		ImageName: "img.png",
		Image:     bytes.NewReader(fakePNG),
	}); err == nil || !strings.Contains(err.Error(), "unsupported_operation") {
		t.Fatalf("expected unsupported_operation from embedded ImageVariation, got: %v", err)
	}

	// Full multipart round-trip + response decoding for ImageEdit & ImageVariation
	mockImgGW := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseMultipartForm(4 << 20); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/images/edits":
			if r.FormValue("model") != "dall-e-2" || r.FormValue("prompt") != "Add a hat" || r.FormValue("size") != "512x512" {
				http.Error(w, "unexpected form fields", http.StatusBadRequest)
				return
			}
			_, _, errImg := r.FormFile("image")
			_, _, errMask := r.FormFile("mask")
			if errImg != nil || errMask != nil {
				http.Error(w, "missing image or mask", http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"created": 1700000003,
				"data":    []map[string]any{{"url": "https://example.com/edited.png"}},
			})
		case "/v1/images/variations":
			if r.FormValue("model") != "dall-e-2" || r.FormValue("size") != "512x512" {
				http.Error(w, "unexpected form fields", http.StatusBadRequest)
				return
			}
			if _, _, errImg := r.FormFile("image"); errImg != nil {
				http.Error(w, "missing image", http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"created": 1700000004,
				"data":    []map[string]any{{"b64_json": "aGVsbG8="}},
			})
		default:
			http.NotFound(w, r)
		}
	}))
	defer mockImgGW.Close()
	imgClient := gateway.NewClient(mockImgGW.URL, "sk-test")
	editResp, err := imgClient.ImageEdit(ctx, gateway.ImageEditRequest{
		Model:     "dall-e-2",
		Prompt:    "Add a hat",
		ImageName: "img.png",
		Image:     bytes.NewReader(fakePNG),
		MaskName:  "mask.png",
		Mask:      bytes.NewReader(fakePNG),
		N:         1,
		Size:      "512x512",
	})
	if err != nil || len(editResp.Data) != 1 || editResp.Data[0].URL != "https://example.com/edited.png" {
		t.Fatalf("ImageEdit failed: resp=%+v err=%v", editResp, err)
	}
	varResp, err := imgClient.ImageVariation(ctx, gateway.ImageVariationRequest{
		Model:     "dall-e-2",
		ImageName: "img.png",
		Image:     bytes.NewReader(fakePNG),
		N:         1,
		Size:      "512x512",
	})
	if err != nil || len(varResp.Data) != 1 || varResp.Data[0].B64JSON != "aGVsbG8=" {
		t.Fatalf("ImageVariation failed: resp=%+v err=%v", varResp, err)
	}

	// 5. Admin Lifecycle & Config
	adminPost := func(path string, body any) map[string]any {
		raw, _ := json.Marshal(body)
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, gw.BaseURL()+path, bytes.NewReader(raw))
		req.Header.Set("Authorization", "Bearer sk-gw-master-admin-sdk-test-key")
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST %s failed: %v", path, err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
			t.Fatalf("POST %s status %d", path, resp.StatusCode)
		}
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return out
	}

	teamCreated := adminPost("/admin/v1/teams", map[string]any{
		"org_id": "org_default",
		"name":   "sdk-team-1",
	})
	teamID, _ := teamCreated["id"].(string)
	if teamID == "" {
		t.Fatalf("expected team id, got %+v", teamCreated)
	}

	userCreated := adminPost("/admin/v1/users", map[string]any{
		"org_id":  "org_default",
		"team_id": teamID,
		"email":   "sdk-user@example.com",
		"name":    "SDK User",
		"role":    "developer",
	})
	userID, _ := userCreated["id"].(string)
	if userID == "" {
		t.Fatalf("expected user id, got %+v", userCreated)
	}

	vk, err := gw.IssueVirtualKey(ctx, domain.VirtualKey{
		Name:             "lifecycle-key",
		OrgID:            "org_default",
		TeamID:           teamID,
		UserID:           userID,
		AllowedModels:    []string{"gpt-4o-mini"},
		AllowedEndpoints: []string{"/v1/chat/completions"},
	})
	if err != nil || vk.RawKey == "" {
		t.Fatalf("IssueVirtualKey failed: %v", err)
	}

	// UpdateTeam
	newTeamName := "sdk-team-renamed"
	updatedTeam, err := gw.UpdateTeam(ctx, teamID, gateway.TeamUpdateRequest{Name: &newTeamName})
	if err != nil || updatedTeam.Name != newTeamName {
		t.Fatalf("UpdateTeam failed: updated=%+v err=%v", updatedTeam, err)
	}

	// UpdateUser
	newUserName := "SDK User Renamed"
	updatedUser, err := gw.UpdateUser(ctx, userID, gateway.UserUpdateRequest{Name: &newUserName})
	if err != nil || updatedUser.Name != newUserName {
		t.Fatalf("UpdateUser failed: updated=%+v err=%v", updatedUser, err)
	}

	// DeleteTeam & DeleteUser must return 409 Conflict while active key references them
	if err := gw.DeleteTeam(ctx, teamID); err == nil || !strings.Contains(err.Error(), "HTTP 409") {
		t.Fatalf("expected 409 Conflict deleting team with active key, got: %v", err)
	}
	if err := gw.DeleteUser(ctx, userID); err == nil || !strings.Contains(err.Error(), "HTTP 409") {
		t.Fatalf("expected 409 Conflict deleting user with active key, got: %v", err)
	}

	// RotateVirtualKey: new key works, old key fails
	rotated, err := gw.RotateVirtualKey(ctx, vk.ID)
	if err != nil || rotated.RawKey == "" || rotated.RawKey == vk.RawKey {
		t.Fatalf("RotateVirtualKey failed: rotated=%+v err=%v", rotated, err)
	}
	if _, err := gw.WithKey(vk.RawKey).Chat(ctx, "gpt-4o-mini", "old key"); err == nil {
		t.Fatal("expected old rotated key to fail")
	}
	if _, err := gw.WithKey(rotated.RawKey).Chat(ctx, "gpt-4o-mini", "new key"); err != nil {
		t.Fatalf("expected new rotated key to succeed, got: %v", err)
	}

	// UpdateVirtualKey: clear AllowedEndpoints to []string{} -> fail-closed 403
	emptyEndpoints := []string{}
	updatedKey, err := gw.UpdateVirtualKey(ctx, vk.ID, gateway.VirtualKeyUpdateRequest{
		AllowedEndpoints: &emptyEndpoints,
	})
	if err != nil {
		t.Fatalf("UpdateVirtualKey failed: %v", err)
	}
	if len(updatedKey.AllowedEndpoints) != 0 {
		t.Fatalf("expected AllowedEndpoints to be cleared, got: %v", updatedKey.AllowedEndpoints)
	}
	if _, err := gw.WithKey(rotated.RawKey).Chat(ctx, "gpt-4o-mini", "after clear"); err == nil || !strings.Contains(err.Error(), "HTTP 403") {
		t.Fatalf("expected 403 after clearing AllowedEndpoints, got: %v", err)
	}

	// Revoke key -> DeleteUser and DeleteTeam now succeed
	if err := gw.RevokeVirtualKey(ctx, vk.ID); err != nil {
		t.Fatalf("RevokeVirtualKey failed: %v", err)
	}
	if err := gw.DeleteUser(ctx, userID); err != nil {
		t.Fatalf("DeleteUser after key revoke failed: %v", err)
	}
	if err := gw.DeleteTeam(ctx, teamID); err != nil {
		t.Fatalf("DeleteTeam after key revoke failed: %v", err)
	}

	// GetConfig
	cfgMap, err := gw.GetConfig(ctx)
	if err != nil || cfgMap["server"] == nil {
		t.Fatalf("GetConfig failed: cfg=%+v err=%v", cfgMap, err)
	}
}

func TestSDK_RealtimeSession(t *testing.T) {
	ctx := context.Background()

	mockOpenAI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"id":"chatcmpl_rt","object":"chat.completion","created":1730000003,"model":"gpt-4o-realtime-preview","choices":[{"index":0,"message":{"role":"assistant","content":"realtime ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":4,"completion_tokens":2,"total_tokens":6}}`)
	}))
	defer mockOpenAI.Close()

	gw, err := gateway.New(
		gateway.WithSilentLogs(),
		gateway.WithAllowPrivateNetworks(),
		gateway.WithModelList(gateway.ModelEntry{
			ModelName: "gpt-4o-realtime-preview",
			Model:     "openai/gpt-4o-realtime-preview",
			APIKey:    "sk-test-openai",
			APIBase:   mockOpenAI.URL,
		}),
	)
	if err != nil {
		t.Fatalf("gateway.New failed: %v", err)
	}
	defer gw.Close()

	vk, err := gw.IssueVirtualKey(ctx, domain.VirtualKey{
		Name:             "realtime-sdk-key",
		OrgID:            "org_default",
		AllowedModels:    []string{"*"},
		AllowedEndpoints: []string{"*"},
	})
	if err != nil {
		t.Fatalf("IssueVirtualKey: %v", err)
	}

	sess, err := gw.WithKey(vk.RawKey).ConnectRealtime(ctx, "gpt-4o-realtime-preview")
	if err != nil {
		t.Fatalf("ConnectRealtime failed: %v", err)
	}
	defer sess.Close()

	created, err := sess.ReadEvent(ctx)
	if err != nil {
		t.Fatalf("ReadEvent(session.created) failed: %v", err)
	}
	if created.Type != "session.created" || created.Session == nil || created.Session.Model != "gpt-4o-realtime-preview" {
		t.Fatalf("unexpected session.created event: %+v", created)
	}

	if err := sess.SendEvent(ctx, gateway.RealtimeEvent{
		Type: "session.update",
		Session: &gateway.RealtimeSessionConfig{
			Modalities:   []string{"text"},
			Instructions: "Speak tersely.",
		},
	}); err != nil {
		t.Fatalf("SendEvent(session.update) failed: %v", err)
	}

	updated, err := sess.ReadEvent(ctx)
	if err != nil {
		t.Fatalf("ReadEvent(session.updated) failed: %v", err)
	}
	if updated.Type != "session.updated" || updated.Session == nil || updated.Session.Instructions != "Speak tersely." {
		t.Fatalf("unexpected session.updated event: %+v", updated)
	}
}

func TestSDK_PureSDKModalityAndFinOpsWrappers(t *testing.T) {
	ctx := context.Background()

	mockOpenAI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch strings.TrimPrefix(r.URL.Path, "/v1") {
		case "/embeddings":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"object":"list","data":[{"object":"embedding","index":0,"embedding":[0.1,0.2,0.3]}],"model":"text-embedding-3-small","usage":{"prompt_tokens":3,"total_tokens":3}}`)
		case "/moderations":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"id":"modr_1","model":"omni-moderation-latest","results":[{"flagged":false,"categories":{"hate":false},"category_scores":{"hate":0.01}}]}`)
		case "/chat/completions":
			var req map[string]any
			_ = json.NewDecoder(r.Body).Decode(&req)
			if stream, _ := req["stream"].(bool); stream {
				w.Header().Set("Content-Type", "text/event-stream")
				fmt.Fprint(w, "data: {\"id\":\"chatcmpl_s\",\"object\":\"chat.completion.chunk\",\"created\":1730000010,\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Hello \"}}]}\n\n")
				fmt.Fprint(w, "data: {\"id\":\"chatcmpl_s\",\"object\":\"chat.completion.chunk\",\"created\":1730000010,\"model\":\"gpt-4o\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Responses!\"},\"finish_reason\":\"stop\"}],\"usage\":{\"prompt_tokens\":4,\"completion_tokens\":2,\"total_tokens\":6}}\n\n")
				fmt.Fprint(w, "data: [DONE]\n\n")
				return
			}
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"id":"chatcmpl_r","object":"chat.completion","created":1730000010,"model":"gpt-4o","choices":[{"index":0,"message":{"role":"assistant","content":"Sync response"},"finish_reason":"stop"}],"usage":{"prompt_tokens":4,"completion_tokens":2,"total_tokens":6}}`)
		case "/responses":
			var req map[string]any
			_ = json.NewDecoder(r.Body).Decode(&req)
			if stream, _ := req["stream"].(bool); stream {
				w.Header().Set("Content-Type", "text/event-stream")
				fmt.Fprint(w, "data: {\"type\":\"response.output_text.delta\",\"delta\":\"Hello \"}\n\n")
				fmt.Fprint(w, "data: {\"type\":\"response.output_text.delta\",\"delta\":\"Responses!\"}\n\n")
				fmt.Fprint(w, "data: {\"type\":\"response.completed\",\"response\":{\"id\":\"resp_stream\",\"object\":\"response\",\"status\":\"completed\",\"model\":\"gpt-4o\",\"output\":[{\"id\":\"msg_1\",\"type\":\"message\",\"status\":\"completed\",\"role\":\"assistant\",\"content\":[{\"type\":\"output_text\",\"text\":\"Hello Responses!\"}]}]}}\n\n")
				fmt.Fprint(w, "data: [DONE]\n\n")
				return
			}
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"id":"resp_sync","object":"response","created_at":1730000010,"model":"gpt-4o","status":"completed","output":[{"id":"msg_1","type\":\"message","status":"completed","role":"assistant","content":[{"type":"output_text","text":"Sync response"}]}],"usage":{"prompt_tokens":4,"completion_tokens":2,"total_tokens":6}}`)
		case "/images/generations":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"created":1730000011,"data":[{"url":"https://example.com/generated.png"}]}`)
		case "/audio/speech":
			w.Header().Set("Content-Type", "audio/mpeg")
			_, _ = w.Write([]byte("MP3_BYTES"))
		case "/audio/transcriptions":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"text":"transcribed audio"}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer mockOpenAI.Close()

	gw, err := gateway.New(
		gateway.WithSilentLogs(),
		gateway.WithAllowPrivateNetworks(),
		gateway.WithModelList(
			gateway.ModelEntry{ModelName: "text-embedding-3-small", Model: "openai/text-embedding-3-small", APIKey: "sk-test", APIBase: mockOpenAI.URL},
			gateway.ModelEntry{ModelName: "omni-moderation-latest", Model: "openai/omni-moderation-latest", APIKey: "sk-test", APIBase: mockOpenAI.URL},
			gateway.ModelEntry{ModelName: "gpt-4o", Model: "openai/gpt-4o", APIKey: "sk-test", APIBase: mockOpenAI.URL},
			gateway.ModelEntry{ModelName: "gpt-image-1", Model: "openai/gpt-image-1", APIKey: "sk-test", APIBase: mockOpenAI.URL},
			gateway.ModelEntry{ModelName: "tts-1", Model: "openai/tts-1", APIKey: "sk-test", APIBase: mockOpenAI.URL},
			gateway.ModelEntry{ModelName: "whisper-1", Model: "openai/whisper-1", APIKey: "sk-test", APIBase: mockOpenAI.URL},
		),
	)
	if err != nil {
		t.Fatalf("gateway.New failed: %v", err)
	}
	defer gw.Close()

	vk, err := gw.IssueVirtualKey(ctx, domain.VirtualKey{
		Name:             "pure-sdk-key",
		OrgID:            "org_default",
		AllowedModels:    []string{"*"},
		AllowedEndpoints: []string{"*"},
	})
	if err != nil {
		t.Fatalf("IssueVirtualKey: %v", err)
	}
	client := gw.WithKey(vk.RawKey)

	emb, err := client.CreateEmbedding(ctx, gateway.EmbeddingRequest{
		Model: "text-embedding-3-small",
		Input: []string{"hello"},
	})
	if err != nil || len(emb.Data) != 1 {
		t.Fatalf("CreateEmbedding failed: emb=%+v err=%v", emb, err)
	}

	mod, err := client.CreateModeration(ctx, gateway.ModerationRequest{
		Model: "omni-moderation-latest",
		Input: []string{"harmless greeting"},
	})
	if err != nil || len(mod.Results) != 1 || mod.Results[0].Flagged {
		t.Fatalf("CreateModeration failed: mod=%+v err=%v", mod, err)
	}

	respOut, err := client.CreateResponse(ctx, gateway.ResponseRequest{
		Model: "gpt-4o",
		Input: "say hi",
	})
	if err != nil || respOut.Status != "completed" || len(respOut.Output) == 0 {
		t.Fatalf("CreateResponse failed: resp=%+v err=%v", respOut, err)
	}

	var streamed strings.Builder
	streamOut, err := client.StreamResponse(ctx, gateway.ResponseRequest{
		Model: "gpt-4o",
		Input: "stream hi",
	}, func(delta string) error {
		streamed.WriteString(delta)
		return nil
	})
	if err != nil || streamed.String() != "Hello Responses!" || !strings.HasPrefix(streamOut.ID, "resp_") || streamOut.Status != "completed" {
		t.Fatalf("StreamResponse failed: streamed=%q out=%+v err=%v", streamed.String(), streamOut, err)
	}

	imgOut, err := client.CreateImage(ctx, gateway.ImageGenerationRequest{
		Model:  "gpt-image-1",
		Prompt: "a lighthouse",
	})
	if err != nil || len(imgOut.Data) != 1 || imgOut.Data[0].URL != "https://example.com/generated.png" {
		t.Fatalf("CreateImage failed: img=%+v err=%v", imgOut, err)
	}

	speech, err := client.CreateSpeech(ctx, gateway.SpeechRequest{
		Model: "tts-1",
		Input: "hello",
		Voice: "alloy",
	})
	if err != nil || string(speech) != "MP3_BYTES" {
		t.Fatalf("CreateSpeech failed: speech=%q err=%v", string(speech), err)
	}

	stt, err := client.TranscribeAudio(ctx, gateway.AudioTranscriptionRequest{
		Model:    "whisper-1",
		FileName: "clip.wav",
		Audio:    bytes.NewReader([]byte("RIFF_WAV")),
	})
	if err != nil || stt.Text != "transcribed audio" {
		t.Fatalf("TranscribeAudio failed: stt=%+v err=%v", stt, err)
	}

	summary, err := gw.GetSpendSummary(ctx)
	if err != nil || summary.TotalRequests == 0 {
		t.Fatalf("GetSpendSummary failed: summary=%+v err=%v", summary, err)
	}
}
