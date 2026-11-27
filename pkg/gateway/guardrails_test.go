package gateway_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/pkg/gateway"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newMockOpenAIServer(t *testing.T, reply string) (*httptest.Server, *[]map[string]any, *atomic.Int32) {
	t.Helper()
	var mu sync.Mutex
	var recorded []map[string]any
	var calls atomic.Int32

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		body, err := io.ReadAll(r.Body)
		if err == nil {
			var payload map[string]any
			if json.Unmarshal(body, &payload) == nil {
				mu.Lock()
				recorded = append(recorded, payload)
				mu.Unlock()
			}
		}

		// Handle streaming requests cleanly if stream=true
		if len(recorded) > 0 {
			mu.Lock()
			last := recorded[len(recorded)-1]
			mu.Unlock()
			if stream, _ := last["stream"].(bool); stream {
				w.Header().Set("Content-Type", "text/event-stream")
				w.WriteHeader(http.StatusOK)
				chunk1 := map[string]any{
					"id":      "chatcmpl-stream-1",
					"object":  "chat.completion.chunk",
					"created": time.Now().Unix(),
					"model":   "test-model",
					"choices": []map[string]any{
						{
							"index": 0,
							"delta": map[string]any{"role": "assistant", "content": reply},
						},
					},
				}
				chunk2 := map[string]any{
					"id":      "chatcmpl-stream-1",
					"object":  "chat.completion.chunk",
					"created": time.Now().Unix(),
					"model":   "test-model",
					"choices": []map[string]any{
						{
							"index":         0,
							"delta":         map[string]any{},
							"finish_reason": "stop",
						},
					},
				}
				b1, _ := json.Marshal(chunk1)
				b2, _ := json.Marshal(chunk2)
				_, _ = w.Write([]byte("data: " + string(b1) + "\n\n"))
				_, _ = w.Write([]byte("data: " + string(b2) + "\n\n"))
				_, _ = w.Write([]byte("data: [DONE]\n\n"))
				return
			}
		}

		w.Header().Set("Content-Type", "application/json")
		resp := map[string]any{
			"id":      "chatcmpl-sdk-1",
			"object":  "chat.completion",
			"created": time.Now().Unix(),
			"model":   "test-model",
			"choices": []map[string]any{
				{
					"index": 0,
					"message": map[string]any{
						"role":    "assistant",
						"content": reply,
					},
					"finish_reason": "stop",
				},
			},
			"usage": map[string]any{
				"prompt_tokens":     8,
				"completion_tokens": 5,
				"total_tokens":      13,
			},
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	t.Cleanup(srv.Close)
	return srv, &recorded, &calls
}

func TestWithGuardrailScanner_ValidationErrors(t *testing.T) {
	t.Parallel()

	dummy := gateway.GuardrailScannerFunc(func(ctx context.Context, req gateway.GuardrailScanRequest) (gateway.GuardrailScanResult, error) {
		return gateway.GuardrailScanResult{Decision: gateway.GuardrailDecisionAllow}, nil
	})

	_, err := gateway.New(
		gateway.WithSilentLogs(),
		gateway.WithGuardrailScanner("   ", dummy),
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "name")

	_, err = gateway.New(
		gateway.WithSilentLogs(),
		gateway.WithGuardrailScanner("nil-scanner", nil),
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nil")

	_, err = gateway.New(
		gateway.WithSilentLogs(),
		gateway.WithRemote("http://127.0.0.1:8080", "key"),
		gateway.WithGuardrailScanner("remote-incompatible", dummy),
	)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "WithRemote")
}

func TestWithGuardrailScanner_AllowAndBlock(t *testing.T) {
	t.Parallel()

	srv, _, upstreamCalls := newMockOpenAIServer(t, "safe assistant reply")

	var seenRequests []gateway.GuardrailScanRequest
	var mu sync.Mutex
	scanner := gateway.GuardrailScannerFunc(func(ctx context.Context, req gateway.GuardrailScanRequest) (gateway.GuardrailScanResult, error) {
		mu.Lock()
		seenRequests = append(seenRequests, req)
		mu.Unlock()
		if req.Direction == "input" && len(req.Texts) > 0 && req.Texts[0] == "forbidden prompt" {
			return gateway.GuardrailScanResult{
				Decision:   gateway.GuardrailDecisionBlock,
				Violations: []string{"policy.forbidden"},
				Reason:     "forbidden keyword detected",
			}, nil
		}
		return gateway.GuardrailScanResult{Decision: gateway.GuardrailDecisionAllow}, nil
	})

	client, err := gateway.New(
		gateway.WithSilentLogs(),
		gateway.WithModelList(gateway.ModelEntry{
			ModelName: "test-model",
			Model:     "openai/gpt-4o-mini",
			APIKey:    "sk-test",
			APIBase:   srv.URL + "/v1",
		}),
		gateway.WithGuardrailScanner("policy-guard", scanner),
	)
	require.NoError(t, err)
	defer client.Close()

	// Allowed request calls upstream and runs both pre_call and post_call
	res, err := client.Chat(context.Background(), "test-model", "hello world")
	require.NoError(t, err)
	assert.Equal(t, "safe assistant reply", res.Content)
	assert.Equal(t, int32(1), upstreamCalls.Load())

	mu.Lock()
	require.Len(t, seenRequests, 2)
	assert.Equal(t, "input", seenRequests[0].Direction)
	assert.Equal(t, gateway.GuardrailHookPreCall, seenRequests[0].Hook)
	assert.Equal(t, []string{"hello world"}, seenRequests[0].Texts)
	assert.Equal(t, "output", seenRequests[1].Direction)
	assert.Equal(t, gateway.GuardrailHookPostCall, seenRequests[1].Hook)
	assert.Equal(t, []string{"safe assistant reply"}, seenRequests[1].Texts)
	mu.Unlock()

	// Blocked request stops before upstream
	_, err = client.Chat(context.Background(), "test-model", "forbidden prompt")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "400")
	assert.Contains(t, err.Error(), "forbidden keyword detected")
	assert.Equal(t, int32(1), upstreamCalls.Load(), "blocked pre_call must not call upstream")
}

func TestWithGuardrailScanner_ModifyPreAndPostCall(t *testing.T) {
	t.Parallel()

	srv, recorded, _ := newMockOpenAIServer(t, "raw upstream output with SSN 123-45-6789")

	scanner := gateway.GuardrailScannerFunc(func(ctx context.Context, req gateway.GuardrailScanRequest) (gateway.GuardrailScanResult, error) {
		switch req.Hook {
		case gateway.GuardrailHookPreCall:
			return gateway.GuardrailScanResult{
				Decision:      gateway.GuardrailDecisionModify,
				ModifiedTexts: []string{"sanitized user prompt"},
				Reason:        "masked input PII",
			}, nil
		case gateway.GuardrailHookPostCall:
			return gateway.GuardrailScanResult{
				Decision:      gateway.GuardrailDecisionModify,
				ModifiedTexts: []string{"redacted assistant response"},
				Reason:        "masked output PII",
			}, nil
		default:
			return gateway.GuardrailScanResult{Decision: gateway.GuardrailDecisionAllow}, nil
		}
	})

	client, err := gateway.New(
		gateway.WithSilentLogs(),
		gateway.WithModelList(gateway.ModelEntry{
			ModelName: "test-model",
			Model:     "openai/gpt-4o-mini",
			APIKey:    "sk-test",
			APIBase:   srv.URL + "/v1",
		}),
		gateway.WithGuardrailScanner("pii-redactor", scanner,
			gateway.WithGuardrailHooks(gateway.GuardrailHookPreCall, gateway.GuardrailHookPostCall),
		),
	)
	require.NoError(t, err)
	defer client.Close()

	res, err := client.Chat(context.Background(), "test-model", "secret user email alice@example.com")
	require.NoError(t, err)
	assert.Equal(t, "redacted assistant response", res.Content)

	require.Len(t, *recorded, 1)
	msgs, ok := (*recorded)[0]["messages"].([]any)
	require.True(t, ok)
	require.Len(t, msgs, 1)
	firstMsg := msgs[0].(map[string]any)
	assert.Equal(t, "sanitized user prompt", firstMsg["content"])

	// Streaming path runs pre_call modification as well.
	var streamed string
	_, err = client.StreamChat(context.Background(), "test-model", "another secret", func(delta string) error {
		streamed += delta
		return nil
	})
	require.NoError(t, err)
	assert.NotEmpty(t, streamed)
	require.Len(t, *recorded, 2)
	streamMsgs := (*recorded)[1]["messages"].([]any)
	assert.Equal(t, "sanitized user prompt", streamMsgs[0].(map[string]any)["content"])
}

func TestWithGuardrailScanner_TimeoutAndFailOpen(t *testing.T) {
	t.Parallel()

	srv, _, calls := newMockOpenAIServer(t, "ok")

	slowScanner := gateway.GuardrailScannerFunc(func(ctx context.Context, req gateway.GuardrailScanRequest) (gateway.GuardrailScanResult, error) {
		select {
		case <-ctx.Done():
			return gateway.GuardrailScanResult{}, ctx.Err()
		case <-time.After(250 * time.Millisecond):
			return gateway.GuardrailScanResult{Decision: gateway.GuardrailDecisionAllow}, nil
		}
	})

	// Fail-open=true allows request despite scanner timeout
	openClient, err := gateway.New(
		gateway.WithSilentLogs(),
		gateway.WithModelList(gateway.ModelEntry{
			ModelName: "test-model",
			Model:     "openai/gpt-4o-mini",
			APIKey:    "sk-test",
			APIBase:   srv.URL + "/v1",
		}),
		gateway.WithGuardrailScanner("slow-open", slowScanner,
			gateway.WithGuardrailHooks(gateway.GuardrailHookPreCall),
			gateway.WithGuardrailTimeout(30*time.Millisecond),
			gateway.WithGuardrailFailOpen(true),
		),
	)
	require.NoError(t, err)
	defer openClient.Close()

	res, err := openClient.Chat(context.Background(), "test-model", "hello")
	require.NoError(t, err)
	assert.Equal(t, "ok", res.Content)
	assert.Equal(t, int32(1), calls.Load())

	// Fail-open=false rejects request on scanner timeout/error
	errScanner := gateway.GuardrailScannerFunc(func(ctx context.Context, req gateway.GuardrailScanRequest) (gateway.GuardrailScanResult, error) {
		return gateway.GuardrailScanResult{}, errors.New("scanner internal boom")
	})

	closedClient, err := gateway.New(
		gateway.WithSilentLogs(),
		gateway.WithModelList(gateway.ModelEntry{
			ModelName: "test-model",
			Model:     "openai/gpt-4o-mini",
			APIKey:    "sk-test",
			APIBase:   srv.URL + "/v1",
		}),
		gateway.WithGuardrailScanner("strict-closed", errScanner,
			gateway.WithGuardrailHooks(gateway.GuardrailHookPreCall),
			gateway.WithGuardrailFailOpen(false),
		),
	)
	require.NoError(t, err)
	defer closedClient.Close()

	_, err = closedClient.Chat(context.Background(), "test-model", "hello")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "503")
	assert.Equal(t, int32(1), calls.Load(), "fail-closed error must block upstream call")
}

func TestWithGuardrailScanner_PrecedenceOrder(t *testing.T) {
	t.Parallel()

	srv, _, _ := newMockOpenAIServer(t, "ok")

	var mu sync.Mutex
	var order []string

	first := gateway.GuardrailScannerFunc(func(ctx context.Context, req gateway.GuardrailScanRequest) (gateway.GuardrailScanResult, error) {
		mu.Lock()
		order = append(order, "first")
		mu.Unlock()
		return gateway.GuardrailScanResult{Decision: gateway.GuardrailDecisionAllow}, nil
	})
	second := gateway.GuardrailScannerFunc(func(ctx context.Context, req gateway.GuardrailScanRequest) (gateway.GuardrailScanResult, error) {
		mu.Lock()
		order = append(order, "second")
		mu.Unlock()
		return gateway.GuardrailScanResult{Decision: gateway.GuardrailDecisionAllow}, nil
	})

	client, err := gateway.New(
		gateway.WithSilentLogs(),
		gateway.WithModelList(gateway.ModelEntry{
			ModelName: "test-model",
			Model:     "openai/gpt-4o-mini",
			APIKey:    "sk-test",
			APIBase:   srv.URL + "/v1",
		}),
		gateway.WithGuardrailScanner("second-scanner", second,
			gateway.WithGuardrailHooks(gateway.GuardrailHookPreCall),
			gateway.WithGuardrailPrecedence(20),
		),
		gateway.WithGuardrailScanner("first-scanner", first,
			gateway.WithGuardrailHooks(gateway.GuardrailHookPreCall),
			gateway.WithGuardrailPrecedence(5),
		),
	)
	require.NoError(t, err)
	defer client.Close()

	_, err = client.ChatMessages(context.Background(), domain.CanonicalChatRequest{
		Model: "test-model",
		Messages: []domain.CanonicalMessage{
			{Role: "user", Content: "check weather"},
		},
	})
	require.NoError(t, err)

	mu.Lock()
	assert.Equal(t, []string{"first", "second"}, order)
	mu.Unlock()
}
