package gateway_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/pkg/gateway"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newNamedMockOpenAIServer(t *testing.T, label string, calls *atomic.Int32) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls != nil {
			calls.Add(1)
		}
		var bodyMap map[string]any
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &bodyMap)
		if stream, _ := bodyMap["stream"].(bool); stream {
			w.Header().Set("Content-Type", "text/event-stream")
			chunk1 := map[string]any{
				"id":      "chatcmpl-stream-" + label,
				"object":  "chat.completion.chunk",
				"created": time.Now().Unix(),
				"model":   "gpt-4o-mini",
				"choices": []map[string]any{
					{"index": 0, "delta": map[string]any{"role": "assistant", "content": "stream-" + label}},
				},
			}
			chunk2 := map[string]any{
				"id":      "chatcmpl-stream-" + label,
				"object":  "chat.completion.chunk",
				"created": time.Now().Unix(),
				"model":   "gpt-4o-mini",
				"choices": []map[string]any{
					{"index": 0, "delta": map[string]any{}, "finish_reason": "stop"},
				},
				"usage": map[string]any{
					"prompt_tokens":     8,
					"completion_tokens": 4,
					"total_tokens":      12,
				},
			}
			b1, _ := json.Marshal(chunk1)
			b2, _ := json.Marshal(chunk2)
			_, _ = w.Write([]byte("data: " + string(b1) + "\n\n"))
			_, _ = w.Write([]byte("data: " + string(b2) + "\n\n"))
			_, _ = w.Write([]byte("data: [DONE]\n\n"))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":      "chatcmpl-" + label,
			"object":  "chat.completion",
			"created": time.Now().Unix(),
			"model":   "gpt-4o-mini",
			"choices": []map[string]any{
				{
					"index":         0,
					"message":       map[string]any{"role": "assistant", "content": "reply-" + label},
					"finish_reason": "stop",
				},
			},
			"usage": map[string]any{
				"prompt_tokens":     10,
				"completion_tokens": 5,
				"total_tokens":      15,
			},
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestRoutingOptions_ValidationErrors(t *testing.T) {
	t.Parallel()

	pluginFn := func(_ context.Context, rc gateway.RoutingPluginContext) ([]string, error) {
		return nil, nil
	}
	preRouterFn := func(_ context.Context, _ string, _ gateway.ChatRequest) (string, string, float64, error) {
		return "fast", "ok", 1.0, nil
	}

	_, err := gateway.New(gateway.WithSilentLogs(), gateway.WithRoutingPlugin("   ", pluginFn))
	require.Error(t, err)

	_, err = gateway.New(gateway.WithSilentLogs(), gateway.WithRoutingPlugin("empty-fn", nil))
	require.Error(t, err)

	_, err = gateway.New(gateway.WithRemote("http://127.0.0.1:9999", "sk-test"), gateway.WithRoutingPlugin("p", pluginFn))
	require.Error(t, err)

	_, err = gateway.New(gateway.WithSilentLogs(), gateway.WithPreRouter("  ", preRouterFn))
	require.Error(t, err)

	_, err = gateway.New(gateway.WithSilentLogs(), gateway.WithPreRouter("empty-pr", nil))
	require.Error(t, err)

	_, err = gateway.New(gateway.WithRemote("http://127.0.0.1:9999", "sk-test"), gateway.WithPreRouter("pr", preRouterFn))
	require.Error(t, err)

	_, err = gateway.New(gateway.WithSilentLogs(), gateway.WithPreRouterAlias("", "pr"))
	require.Error(t, err)

	_, err = gateway.New(gateway.WithRemote("http://127.0.0.1:9999", "sk-test"), gateway.WithPreRouterAlias("router/x", "pr"))
	require.Error(t, err)
}

func TestModelEntry_PriorityTierStepdownAndChatResultTelemetry(t *testing.T) {
	t.Parallel()

	var tier1Calls atomic.Int32
	srvTier1 := newNamedMockOpenAIServer(t, "tier1", &tier1Calls)

	gw, err := gateway.New(
		gateway.WithSilentLogs(),
		gateway.WithAllowPrivateNetworks(),
		gateway.WithModelList(
			gateway.ModelEntry{
				ModelName:       "tiered",
				Model:           "openai/gpt-4o-mini",
				APIKey:          "sk-tier0",
				RoutingStrategy: "priority-tiered",
				Priority:        0,
				SimulateStatus:  http.StatusServiceUnavailable,
			},
			gateway.ModelEntry{
				ModelName:       "tiered",
				Model:           "openai/gpt-4o-mini",
				APIKey:          "sk-tier1",
				APIBase:         srvTier1.URL,
				RoutingStrategy: "priority-tiered",
				Priority:        1,
			},
		),
	)
	require.NoError(t, err)
	defer gw.Close()

	res, err := gw.Chat(context.Background(), "tiered", "hello")
	require.NoError(t, err)
	assert.Equal(t, "reply-tier1", res.Content)
	assert.Equal(t, "openai", res.Provider)
	assert.Equal(t, "gpt-4o-mini", res.Model)
	assert.NotEmpty(t, res.WinningDeployment)
	assert.Equal(t, 2, res.RetryCount)
	assert.Equal(t, 1, res.TierStepdowns)
	assert.Equal(t, "priority_tier_stepdown", res.RouteReason)
	assert.Equal(t, "priority_tier_stepdown", res.FallbackReason)
	assert.Equal(t, int32(1), tier1Calls.Load())
}

func TestModelEntry_RegionTagsAndRoutingHints(t *testing.T) {
	t.Parallel()

	var usCalls, euCalls atomic.Int32
	srvUS := newNamedMockOpenAIServer(t, "us", &usCalls)
	srvEU := newNamedMockOpenAIServer(t, "eu", &euCalls)

	gw, err := gateway.New(
		gateway.WithSilentLogs(),
		gateway.WithAllowPrivateNetworks(),
		gateway.WithSessionAffinity(5*time.Minute, true),
		gateway.WithModelList(
			gateway.ModelEntry{
				ModelName: "geo-chat",
				Model:     "openai/gpt-4o-mini",
				APIKey:    "sk-us",
				APIBase:   srvUS.URL,
				Region:    "us-east-1",
				Tags:      []string{"tier:standard", "gpu"},
			},
			gateway.ModelEntry{
				ModelName: "geo-chat",
				Model:     "openai/gpt-4o-mini",
				APIKey:    "sk-eu",
				APIBase:   srvEU.URL,
				Region:    "eu-west-1",
				Tags:      []string{"tier:eu", "compliant"},
			},
		),
	)
	require.NoError(t, err)
	defer gw.Close()

	res, err := gw.ChatWithMessages(context.Background(), gateway.ChatRequest{
		Model:    "geo-chat",
		Messages: []gateway.Message{{Role: "user", Content: "route to eu"}},
		RoutingHints: &gateway.RoutingHints{
			AllowedRegion: "eu-west-1",
			Tags:          []string{"&compliant"},
			SessionID:     "sess-eu-1",
			Priority:      1,
		},
	})
	require.NoError(t, err)
	assert.Equal(t, "reply-eu", res.Content)
	assert.Equal(t, int32(0), usCalls.Load())
	assert.Equal(t, int32(1), euCalls.Load())

	// Second call using WithRoutingHints RequestOption and same SessionID stays pinned to EU.
	res2, err := gw.Chat(
		context.Background(),
		"geo-chat",
		"follow up",
		gateway.WithRoutingHints(gateway.RoutingHints{
			SessionID:    "sess-eu-1",
			HedgeAfterMs: 250,
		}),
	)
	require.NoError(t, err)
	assert.Equal(t, "reply-eu", res2.Content)
	assert.Equal(t, int32(0), usCalls.Load())
	assert.Equal(t, int32(2), euCalls.Load())
}

func TestChatRequest_RoutingHintsWirePayloadAndResultHeaders(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	var lastPayload map[string]any

	mockGW := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var decoded map[string]any
		_ = json.Unmarshal(raw, &decoded)
		mu.Lock()
		lastPayload = decoded
		mu.Unlock()

		w.Header().Set("X-Gateway-Provider", "openai")
		w.Header().Set("X-Gateway-Model", "gpt-4o-mini")
		w.Header().Set("X-Gateway-Deployment-Id", "dep-eu-42")
		w.Header().Set("X-Gateway-Request-Id", "req-wire-1")
		w.Header().Set("X-Gateway-Route-Reason", "context_window_fallback")
		w.Header().Set("X-Gateway-Fallback-Attempted", "true")
		w.Header().Set("X-Gateway-Fallback-Reason", "context_window_fallback")
		w.Header().Set("X-Gateway-Tier-Stepdowns", "2")
		w.Header().Set("X-Gateway-Stream-Continued", "true")
		w.Header().Set("X-Gateway-Routing-Micros", "412")
		w.Header().Set("X-Gateway-Cost-Micros", "95")

		if stream, _ := decoded["stream"].(bool); stream {
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = w.Write([]byte(`data: {"id":"c1","model":"gpt-4o-mini","choices":[{"index":0,"delta":{"content":"wire stream"}}]}` + "\n\n"))
			_, _ = w.Write([]byte("data: [DONE]\n\n"))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"chatcmpl-1","model":"gpt-4o-mini","provider":"openai","choices":[{"index":0,"message":{"role":"assistant","content":"wire sync"}}],"usage":{"prompt_tokens":5,"completion_tokens":2,"total_tokens":7}}`))
	}))
	defer mockGW.Close()

	client, err := gateway.New(gateway.WithRemote(mockGW.URL, "sk-remote-test"))
	require.NoError(t, err)
	defer client.Close()

	res, err := client.ChatWithMessages(context.Background(), gateway.ChatRequest{
		Model:    "fast",
		Messages: []gateway.Message{{Role: "user", Content: "check hints"}},
		RoutingHints: &gateway.RoutingHints{
			AllowedRegion:         "eu-central-1",
			Tags:                  []string{"&gpu", "!legacy"},
			SessionID:             "sess-wire-99",
			PreferredDeploymentID: "dep-eu-42",
			Priority:              3,
			HedgeAfterMs:          150,
		},
	})
	require.NoError(t, err)

	mu.Lock()
	ext, ok := lastPayload["goroute_extensions"].(map[string]any)
	mu.Unlock()
	require.True(t, ok, "expected goroute_extensions in outgoing JSON payload: %+v", lastPayload)
	assert.Equal(t, "eu-central-1", ext["allowed_region"])
	assert.Equal(t, []any{"&gpu", "!legacy"}, ext["tags"])
	assert.Equal(t, "sess-wire-99", ext["session_id"])
	assert.Equal(t, "dep-eu-42", ext["preferred_deployment_id"])
	assert.Equal(t, float64(3), ext["priority"])
	assert.Equal(t, float64(150), ext["hedge_after_ms"])

	assert.Equal(t, "wire sync", res.Content)
	assert.Equal(t, "dep-eu-42", res.WinningDeployment)
	assert.Equal(t, "context_window_fallback", res.RouteReason)
	assert.True(t, res.FallbackAttempted)
	assert.Equal(t, "context_window_fallback", res.FallbackReason)
	assert.Equal(t, 2, res.TierStepdowns)
	assert.True(t, res.StreamContinued)
	assert.Equal(t, int64(412), res.RoutingMicros)
	assert.Equal(t, int64(95), res.CostMicros)

	streamRes, err := client.StreamChat(context.Background(), "fast", "stream hints", nil, gateway.WithRoutingHints(gateway.RoutingHints{
		AllowedRegion: "eu-central-1",
		SessionID:     "sess-stream-1",
	}))
	require.NoError(t, err)
	assert.Equal(t, "wire stream", streamRes.Content)
	assert.Equal(t, "dep-eu-42", streamRes.WinningDeployment)
	assert.Equal(t, "context_window_fallback", streamRes.RouteReason)
	assert.True(t, streamRes.FallbackAttempted)
	assert.Equal(t, "context_window_fallback", streamRes.FallbackReason)
	assert.Equal(t, 2, streamRes.TierStepdowns)
	assert.True(t, streamRes.StreamContinued)
	assert.Equal(t, int64(412), streamRes.RoutingMicros)
}

func TestModelEntry_SpecializedFallbacksAndBudgets(t *testing.T) {
	t.Parallel()

	t.Run("context_window_and_content_policy_fallbacks", func(t *testing.T) {
		t.Parallel()

		var ctxCalls, policyCalls, generalCalls atomic.Int32
		srvCtxBackup := newNamedMockOpenAIServer(t, "ctx-backup", &ctxCalls)
		srvPolicyBackup := newNamedMockOpenAIServer(t, "policy-backup", &policyCalls)
		srvGeneralBackup := newNamedMockOpenAIServer(t, "general-backup", &generalCalls)

		srvPrimary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			raw, _ := io.ReadAll(r.Body)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			if strings.Contains(string(raw), "trigger-context") {
				_, _ = w.Write([]byte(`{"error":{"code":"context_length_exceeded","message":"maximum context length exceeded","type":"invalid_request_error"}}`))
				return
			}
			_, _ = w.Write([]byte(`{"error":{"code":"content_policy_violation","message":"blocked by safety policy","type":"invalid_request_error"}}`))
		}))
		defer srvPrimary.Close()

		gw, err := gateway.New(
			gateway.WithSilentLogs(),
			gateway.WithAllowPrivateNetworks(),
			gateway.WithModelList(
				gateway.ModelEntry{
					ModelName:              "primary-specialized",
					Model:                  "openai/gpt-4o-mini",
					APIKey:                 "sk-primary",
					APIBase:                srvPrimary.URL,
					Fallbacks:              []string{"general-backup"},
					ContextWindowFallbacks: []string{"ctx-backup"},
					ContentPolicyFallbacks: []string{"policy-backup"},
				},
				gateway.ModelEntry{
					ModelName: "ctx-backup",
					Model:     "openai/gpt-4o-mini",
					APIKey:    "sk-ctx",
					APIBase:   srvCtxBackup.URL,
				},
				gateway.ModelEntry{
					ModelName: "policy-backup",
					Model:     "openai/gpt-4o-mini",
					APIKey:    "sk-policy",
					APIBase:   srvPolicyBackup.URL,
				},
				gateway.ModelEntry{
					ModelName: "general-backup",
					Model:     "openai/gpt-4o-mini",
					APIKey:    "sk-general",
					APIBase:   srvGeneralBackup.URL,
				},
			),
		)
		require.NoError(t, err)
		defer gw.Close()

		ctxRes, err := gw.Chat(context.Background(), "primary-specialized", "trigger-context")
		require.NoError(t, err)
		assert.Equal(t, "reply-ctx-backup", ctxRes.Content)
		assert.True(t, ctxRes.FallbackAttempted)
		assert.Equal(t, "context_window_fallback", ctxRes.RouteReason)
		assert.Equal(t, "context_window_fallback", ctxRes.FallbackReason)

		policyRes, err := gw.Chat(context.Background(), "primary-specialized", "trigger-policy")
		require.NoError(t, err)
		assert.Equal(t, "reply-policy-backup", policyRes.Content)
		assert.True(t, policyRes.FallbackAttempted)
		assert.Equal(t, "content_policy_fallback", policyRes.RouteReason)
		assert.Equal(t, "content_policy_fallback", policyRes.FallbackReason)

		assert.Equal(t, int32(1), ctxCalls.Load())
		assert.Equal(t, int32(1), policyCalls.Load())
		assert.Equal(t, int32(0), generalCalls.Load())
	})

	t.Run("default_fallbacks_via_router_option", func(t *testing.T) {
		t.Parallel()

		var backupCalls atomic.Int32
		srvBackup := newNamedMockOpenAIServer(t, "default-fb", &backupCalls)

		gw, err := gateway.New(
			gateway.WithSilentLogs(),
			gateway.WithAllowPrivateNetworks(),
			gateway.WithDefaultFallbacks("default-backup"),
			gateway.WithModelList(
				gateway.ModelEntry{
					ModelName:      "failing-no-local-fb",
					Model:          "openai/gpt-4o-mini",
					APIKey:         "sk-fail",
					SimulateStatus: http.StatusServiceUnavailable,
				},
				gateway.ModelEntry{
					ModelName: "default-backup",
					Model:     "openai/gpt-4o-mini",
					APIKey:    "sk-backup",
					APIBase:   srvBackup.URL,
				},
			),
		)
		require.NoError(t, err)
		defer gw.Close()

		res, err := gw.Chat(context.Background(), "failing-no-local-fb", "hello")
		require.NoError(t, err)
		assert.Equal(t, "reply-default-fb", res.Content)
		assert.True(t, res.FallbackAttempted)
		assert.Equal(t, int32(1), backupCalls.Load())
	})

	t.Run("deployment_budget_enforcement", func(t *testing.T) {
		t.Parallel()

		var cappedCalls, openCalls atomic.Int32
		srvCapped := newNamedMockOpenAIServer(t, "capped", &cappedCalls)
		srvOpen := newNamedMockOpenAIServer(t, "open", &openCalls)

		gw, err := gateway.New(
			gateway.WithSilentLogs(),
			gateway.WithAllowPrivateNetworks(),
			gateway.WithModelList(
				gateway.ModelEntry{
					ModelName:         "budgeted",
					Model:             "openai/gpt-4o",
					APIKey:            "sk-capped",
					APIBase:           srvCapped.URL,
					Priority:          0,
					MaxBudgetMicros:   10, // Exhausted after 1st request
					BudgetResetPeriod: "daily",
				},
				gateway.ModelEntry{
					ModelName: "budgeted",
					Model:     "openai/gpt-4o",
					APIKey:    "sk-open",
					APIBase:   srvOpen.URL,
					Priority:  1,
				},
			),
		)
		require.NoError(t, err)
		defer gw.Close()

		res1, err := gw.Chat(context.Background(), "budgeted", "first")
		require.NoError(t, err)
		assert.Equal(t, "reply-capped", res1.Content)

		res2, err := gw.Chat(context.Background(), "budgeted", "second")
		require.NoError(t, err)
		assert.Equal(t, "reply-open", res2.Content)
		assert.Equal(t, int32(1), cappedCalls.Load())
		assert.Equal(t, int32(1), openCalls.Load())
	})
}

func TestWithPreRouterAndWithRoutingPlugin_PublicAPI(t *testing.T) {
	t.Parallel()

	var callsA, callsB atomic.Int32
	srvA := newNamedMockOpenAIServer(t, "plugin-a", &callsA)
	srvB := newNamedMockOpenAIServer(t, "plugin-b", &callsB)

	var seenPreRouterHints atomic.Bool
	var pluginCalls atomic.Int32

	gw, err := gateway.New(
		gateway.WithSilentLogs(),
		gateway.WithAllowPrivateNetworks(),
		gateway.WithPreRouterMode("custom_sdk"),
		gateway.WithPreRouter("custom_sdk", func(_ context.Context, orgID string, req gateway.ChatRequest) (string, string, float64, error) {
			if req.RoutingHints != nil && req.RoutingHints.AllowedRegion == "eu-west-1" {
				seenPreRouterHints.Store(true)
			}
			return "plugin-target", "custom_sdk:selected", 0.99, nil
		}),
		gateway.WithPreRouterAlias("router/custom-alias", "custom_sdk"),
		gateway.WithRoutingPlugin("only-eu-region", func(_ context.Context, rc gateway.RoutingPluginContext) ([]string, error) {
			pluginCalls.Add(1)
			var allowed []string
			for _, cand := range rc.Candidates {
				if cand.Region == "eu-west-1" && cand.ModelName == "gpt-4o-mini" && cand.Provider == "openai" {
					allowed = append(allowed, cand.DeploymentID)
				}
			}
			return allowed, nil
		}),
		gateway.WithModelList(
			gateway.ModelEntry{
				ModelName: "plugin-target",
				Model:     "openai/gpt-4o-mini",
				APIKey:    "sk-a",
				APIBase:   srvA.URL,
				Region:    "us-east-1",
			},
			gateway.ModelEntry{
				ModelName: "plugin-target",
				Model:     "openai/gpt-4o-mini",
				APIKey:    "sk-b",
				APIBase:   srvB.URL,
				Region:    "eu-west-1",
			},
		),
	)
	require.NoError(t, err)
	defer gw.Close()

	// 1. Default auto mode invokes custom_sdk pre-router + routing plugin.
	resAuto, err := gw.Chat(
		context.Background(),
		"auto",
		"route via auto",
		gateway.WithRoutingHints(gateway.RoutingHints{AllowedRegion: "eu-west-1"}),
	)
	require.NoError(t, err)
	assert.Equal(t, "reply-plugin-b", resAuto.Content)
	assert.Equal(t, "custom_sdk:selected", resAuto.RouteReason)
	assert.True(t, seenPreRouterHints.Load())

	// 2. Auto-bound virtual alias router/<name> works directly.
	resRouter, err := gw.Chat(context.Background(), "router/custom_sdk", "route via router/custom_sdk")
	require.NoError(t, err)
	assert.Equal(t, "reply-plugin-b", resRouter.Content)
	assert.Equal(t, "custom_sdk:selected", resRouter.RouteReason)

	// 3. Explicit WithPreRouterAlias works directly.
	resAlias, err := gw.Chat(context.Background(), "router/custom-alias", "route via custom alias")
	require.NoError(t, err)
	assert.Equal(t, "reply-plugin-b", resAlias.Content)
	assert.Equal(t, "custom_sdk:selected", resAlias.RouteReason)

	assert.Equal(t, int32(0), callsA.Load())
	assert.Equal(t, int32(3), callsB.Load())
	assert.Equal(t, int32(3), pluginCalls.Load())
}

func TestWithRoutingPlugin_ErrorAbortsRouting(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	srv := newNamedMockOpenAIServer(t, "ok", &calls)

	gw, err := gateway.New(
		gateway.WithSilentLogs(),
		gateway.WithAllowPrivateNetworks(),
		gateway.WithRoutingPlugin("abort-plugin", func(_ context.Context, _ gateway.RoutingPluginContext) ([]string, error) {
			return nil, errors.New("policy rejected all deployments")
		}),
		gateway.WithModelList(
			gateway.ModelEntry{
				ModelName: "blocked",
				Model:     "openai/gpt-4o-mini",
				APIKey:    "sk-ok",
				APIBase:   srv.URL,
			},
		),
	)
	require.NoError(t, err)
	defer gw.Close()

	_, err = gw.Chat(context.Background(), "blocked", "hello")
	require.Error(t, err)
	assert.Equal(t, int32(0), calls.Load())
}

func TestWithMidStreamContinuationAndRouterConfig(t *testing.T) {
	t.Parallel()

	srvDrop := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hj, ok := w.(http.Hijacker)
		if !ok {
			http.Error(w, "hijack unsupported", http.StatusInternalServerError)
			return
		}
		conn, buf, err := hj.Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = buf.WriteString("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n")
		sseBody := `data: {"id":"c1","model":"gpt-4o-mini","choices":[{"index":0,"delta":{"content":"Hello "}}]}` + "\n\n"
		_, _ = fmt.Fprintf(buf, "%x\r\n%s\r\n", len(sseBody), sseBody)
		_ = buf.Flush()
	}))
	defer srvDrop.Close()

	var contSawPrefill atomic.Bool
	srvCont := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var payload map[string]any
		_ = json.Unmarshal(raw, &payload)
		if msgs, ok := payload["messages"].([]any); ok {
			for _, m := range msgs {
				if mm, ok := m.(map[string]any); ok && mm["role"] == "assistant" {
					if txt, _ := mm["content"].(string); strings.Contains(txt, "Hello ") {
						contSawPrefill.Store(true)
					}
				}
			}
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte(`data: {"id":"c2","model":"gpt-4o-mini","choices":[{"index":0,"delta":{"content":"world!"},"finish_reason":"stop"}],"usage":{"prompt_tokens":10,"completion_tokens":2,"total_tokens":12}}` + "\n\n"))
		_, _ = w.Write([]byte("data: [DONE]\n\n"))
	}))
	defer srvCont.Close()

	gw, err := gateway.New(
		gateway.WithSilentLogs(),
		gateway.WithAllowPrivateNetworks(),
		gateway.WithRouterConfig(gateway.RouterOptions{
			EnableMidStreamContinuation: true,
			MaxStreamContinuations:      1,
		}),
		gateway.WithModelList(
			gateway.ModelEntry{
				ModelName: "cont-stream",
				Model:     "openai/gpt-4o-mini",
				APIKey:    "sk-drop",
				APIBase:   srvDrop.URL,
				Priority:  0,
			},
			gateway.ModelEntry{
				ModelName: "cont-stream",
				Model:     "openai/gpt-4o-mini",
				APIKey:    "sk-cont",
				APIBase:   srvCont.URL,
				Priority:  1,
			},
		),
	)
	require.NoError(t, err)
	defer gw.Close()

	var deltas []string
	res, err := gw.StreamChat(context.Background(), "cont-stream", "Say hello world", func(delta string) error {
		deltas = append(deltas, delta)
		return nil
	})
	require.NoError(t, err)
	assert.Equal(t, "Hello world!", res.Content)
	assert.Equal(t, []string{"Hello ", "world!"}, deltas)
	assert.True(t, contSawPrefill.Load(), "continuation upstream must receive assistant prefill")
}

func TestRemoteChat_TierStepdownsHeaderBounds(t *testing.T) {
	cases := []struct {
		name   string
		header string
		want   int
	}{
		{name: "valid", header: "3", want: 3},
		{name: "negative", header: "-5", want: 0},
		{name: "overflow_int32", header: "999999999999", want: 0},
		{name: "non_numeric", header: "abc", want: 0},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("X-Gateway-Provider", "openai")
				w.Header().Set("X-Gateway-Model", "gpt-4o-mini")
				w.Header().Set("X-Gateway-Tier-Stepdowns", tc.header)
				w.Header().Set("Content-Type", "application/json")
				_ = json.NewEncoder(w).Encode(map[string]any{
					"id":      "chatcmpl-bounds",
					"object":  "chat.completion",
					"created": time.Now().Unix(),
					"model":   "gpt-4o-mini",
					"choices": []map[string]any{
						{
							"index":         0,
							"message":       map[string]any{"role": "assistant", "content": "ok"},
							"finish_reason": "stop",
						},
					},
					"usage": map[string]any{"prompt_tokens": 2, "completion_tokens": 1, "total_tokens": 3},
				})
			}))
			defer srv.Close()

			gw, err := gateway.New(gateway.WithSilentLogs(), gateway.WithRemote(srv.URL, "sk-test"))
			require.NoError(t, err)
			defer gw.Close()

			res, err := gw.ChatWithMessages(context.Background(), gateway.ChatRequest{
				Model:    "gpt-4o-mini",
				Messages: []gateway.Message{{Role: "user", Content: "hi"}},
			})
			require.NoError(t, err)
			assert.Equal(t, tc.want, res.TierStepdowns)
		})
	}
}
