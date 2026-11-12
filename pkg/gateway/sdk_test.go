package gateway_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
