package drivers_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/guardrails"
	"github.com/goroute-ai/ai-gateway-go/internal/guardrails/drivers"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func allowLocalClient(t *testing.T) *http.Client {
	t.Helper()
	pol, err := network.NewPolicy(config.OutboundSSRFConfig{
		AllowPrivateNetworks: true,
		AllowInsecureHTTP:    true,
	})
	require.NoError(t, err)
	return network.NewHTTPClient(pol)
}

func TestGenericHTTPDriver_RichPayloadAndHeaderSanitization(t *testing.T) {
	t.Setenv("TEST_GENERIC_WEBHOOK_KEY", "env-header-secret")

	var gotHeaders http.Header
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeaders = r.Header.Clone()
		require.NoError(t, json.NewDecoder(r.Body).Decode(&gotBody))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"decision":"allow"}`))
	}))
	defer srv.Close()

	drv, err := drivers.NewGenericHTTPDriver(guardrails.DriverConfig{
		Definition: &domain.GuardrailDefinition{
			ID:         "def-rich-1",
			Name:       "rich-webhook",
			Provider:   "generic_http",
			EventHooks: []domain.GuardrailHook{domain.GuardrailHookPreCall},
		},
		EffectiveConfig: map[string]any{
			"url":                 srv.URL,
			"redact_auth_headers": true,
			"headers": map[string]any{
				"X-Custom-Key": "os.environ/TEST_GENERIC_WEBHOOK_KEY",
			},
		},
		DecryptedSecrets: map[string]any{
			"bearer_token": "vault-secret-token",
		},
	}, allowLocalClient(t))
	require.NoError(t, err)
	assert.Equal(t, "generic_http", drv.Name())
	assert.Equal(t, []domain.GuardrailHook{domain.GuardrailHookPreCall}, drv.SupportedHooks())

	input := &domain.GuardrailEvalInput{
		Direction:    domain.GuardrailDirectionInput,
		Hook:         domain.GuardrailHookPreCall,
		RequestID:    "call-123",
		TraceID:      "trace-456",
		OrgID:        "org-1",
		TeamID:       "team-1",
		VirtualKeyID: "vk-1",
		EndUserID:    "user-1",
		Model:        "gpt-4o",
		Tags:         []string{"prod"},
		Texts:        []string{"hello world"},
		StructuredMessages: []domain.CanonicalMessage{
			{Role: "user", Content: "hello world"},
		},
		Images: []domain.ImageURL{{URL: "https://example.com/img.png", Detail: "low"}},
		Tools: []domain.CanonicalTool{
			{Type: "function", Function: domain.CanonicalFunction{Name: "lookup_user", Description: "Look up user"}},
		},
		ToolCalls: []domain.CanonicalToolCall{
			{ID: "tc-1", Type: "function", Function: domain.CanonicalFunctionCall{Name: "lookup_user", Arguments: `{"id":1}`}},
		},
		RequestHeaders: map[string]string{
			"Content-Type":        "application/json",
			"User-Agent":          "goroute-sdk/1.0",
			"X-Request-ID":        "req-abc",
			"Accept":              "application/json",
			"Authorization":       "Bearer super-secret-caller-token",
			"X-Api-Key":           "raw-api-key-secret",
			"Cookie":              "session=secret-cookie",
			"Proxy-Authorization": "Basic secret-proxy",
			"X-Untrusted-Header":  "should-not-be-forwarded",
		},
		Metadata: map[string]any{"task_id": "task-99"},
	}

	res, err := drv.Evaluate(context.Background(), input)
	require.NoError(t, err)
	assert.Equal(t, domain.GuardrailDecisionAllow, res.Decision)

	// Outbound headers
	assert.Equal(t, "Bearer vault-secret-token", gotHeaders.Get("Authorization"))
	assert.Equal(t, "env-header-secret", gotHeaders.Get("X-Custom-Key"))
	assert.Equal(t, "call-123", gotHeaders.Get("X-GoRoute-Call-ID"))
	assert.Equal(t, "trace-456", gotHeaders.Get("X-GoRoute-Trace-ID"))

	// Rich body fields
	assert.Equal(t, "request", gotBody["input_type"])
	assert.Equal(t, "pre_call", gotBody["hook"])
	assert.Equal(t, "call-123", gotBody["call_id"])
	assert.Equal(t, "call-123", gotBody["request_id"])
	assert.Equal(t, "trace-456", gotBody["trace_id"])
	assert.Equal(t, "gpt-4o", gotBody["model"])
	assert.Equal(t, []any{"hello world"}, gotBody["texts"])
	assert.Len(t, gotBody["structured_messages"], 1)
	assert.Len(t, gotBody["images"], 1)
	assert.Len(t, gotBody["tools"], 1)
	assert.Len(t, gotBody["tool_calls"], 1)
	assert.Equal(t, map[string]any{"task_id": "task-99"}, gotBody["metadata"])

	// Allowlisted & redacted request_headers (no raw secrets!)
	reqHeaders, ok := gotBody["request_headers"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "application/json", reqHeaders["content-type"])
	assert.Equal(t, "goroute-sdk/1.0", reqHeaders["user-agent"])
	assert.Equal(t, "req-abc", reqHeaders["x-request-id"])
	assert.Equal(t, "application/json", reqHeaders["accept"])
	assert.Equal(t, "[present]", reqHeaders["authorization"])
	assert.Equal(t, "[present]", reqHeaders["x-api-key"])
	assert.Equal(t, "[present]", reqHeaders["cookie"])
	assert.Equal(t, "[present]", reqHeaders["proxy-authorization"])
	assert.Nil(t, reqHeaders["x-untrusted-header"])
}

func TestGenericHTTPDriver_DefaultDoesNotExposeAuthHeaders(t *testing.T) {
	var gotBody map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, json.NewDecoder(r.Body).Decode(&gotBody))
		_, _ = w.Write([]byte(`{"decision":"allow"}`))
	}))
	defer srv.Close()

	drv, err := drivers.NewGenericHTTPDriver(guardrails.DriverConfig{
		EffectiveConfig: map[string]any{"url": srv.URL},
	}, allowLocalClient(t))
	require.NoError(t, err)

	_, err = drv.Evaluate(context.Background(), &domain.GuardrailEvalInput{
		Direction: domain.GuardrailDirectionOutput,
		Hook:      domain.GuardrailHookPostCall,
		Texts:     []string{"reply"},
		RequestHeaders: map[string]string{
			"Authorization": "Bearer secret-jwt",
			"X-Api-Key":     "sk-secret",
			"Content-Type":  "application/json",
		},
	})
	require.NoError(t, err)
	assert.Equal(t, "response", gotBody["input_type"])
	reqHeaders := gotBody["request_headers"].(map[string]any)
	assert.Equal(t, "application/json", reqHeaders["content-type"])
	assert.NotContains(t, reqHeaders, "authorization")
	assert.NotContains(t, reqHeaders, "x-api-key")
}

func TestGenericHTTPDriver_DecisionsModifyAndLegacyCompat(t *testing.T) {
	var respPayload string
	var statusCode int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if statusCode != 0 {
			w.WriteHeader(statusCode)
		}
		_, _ = w.Write([]byte(respPayload))
	}))
	defer srv.Close()

	drv, err := drivers.NewGenericHTTPDriver(guardrails.DriverConfig{
		Definition: &domain.GuardrailDefinition{ID: "d1", Name: "mod-hook"},
		EffectiveConfig: map[string]any{
			"url": srv.URL,
		},
	}, allowLocalClient(t))
	require.NoError(t, err)

	// 1. Modify with modified_texts + modified_tool_calls + structured violations + usage_units
	statusCode = http.StatusOK
	respPayload = `{
		"decision": "modify",
		"modified_texts": ["sanitized prompt"],
		"modified_tool_calls": [{"id":"tc-1","type":"function","function":{"name":"safe_tool","arguments":"{\"ok\":true}"}}],
		"violations": [{"category":"pii","rule":"email","severity":"medium","message":"redacted email"}],
		"usage_units": 42
	}`
	res, err := drv.Evaluate(context.Background(), &domain.GuardrailEvalInput{Texts: []string{"raw"}})
	require.NoError(t, err)
	assert.Equal(t, domain.GuardrailDecisionModify, res.Decision)
	assert.Equal(t, []string{"sanitized prompt"}, res.ModifiedTexts)
	require.Len(t, res.ModifiedToolCalls, 1)
	assert.Equal(t, "safe_tool", res.ModifiedToolCalls[0].Function.Name)
	assert.Equal(t, int64(42), res.UsageUnits)
	require.Len(t, res.Violations, 1)
	assert.Equal(t, "pii", res.Violations[0].Category)

	// 2. Flag decision with string violations
	respPayload = `{"decision":"flag","violations":["soft_warning"],"reason":"needs review","usage_units":5}`
	res, err = drv.Evaluate(context.Background(), &domain.GuardrailEvalInput{Texts: []string{"hi"}})
	require.NoError(t, err)
	assert.Equal(t, domain.GuardrailDecisionFlag, res.Decision)
	assert.Equal(t, "needs review", res.ErrorMessage)
	assert.Equal(t, int64(5), res.UsageUnits)
	require.Len(t, res.Violations, 1)
	assert.Equal(t, "soft_warning", res.Violations[0].Rule)

	// 3. Block decision
	respPayload = `{"decision":"block","reason":"policy violation"}`
	res, err = drv.Evaluate(context.Background(), &domain.GuardrailEvalInput{Texts: []string{"bad"}})
	require.NoError(t, err)
	assert.Equal(t, domain.GuardrailDecisionBlock, res.Decision)
	assert.Equal(t, "policy violation", res.ErrorMessage)
	require.Len(t, res.Violations, 1)

	// 4. Legacy {blocked, sanitized_text, violations}
	respPayload = `{"blocked":true,"violations":["legacy_rule"]}`
	res, err = drv.Evaluate(context.Background(), &domain.GuardrailEvalInput{Texts: []string{"bad"}})
	require.NoError(t, err)
	assert.Equal(t, domain.GuardrailDecisionBlock, res.Decision)
	require.Len(t, res.Violations, 1)
	assert.Equal(t, "legacy_rule", res.Violations[0].Rule)

	respPayload = `{"blocked":false,"sanitized_text":"clean legacy text","violations":["legacy_pii"]}`
	res, err = drv.Evaluate(context.Background(), &domain.GuardrailEvalInput{Texts: []string{"dirty"}})
	require.NoError(t, err)
	assert.Equal(t, domain.GuardrailDecisionModify, res.Decision)
	assert.Equal(t, []string{"clean legacy text"}, res.ModifiedTexts)

	// 5. Unsupported decision & HTTP 500 return errors
	respPayload = `{"decision":"unknown_action"}`
	_, err = drv.Evaluate(context.Background(), &domain.GuardrailEvalInput{Texts: []string{"x"}})
	require.Error(t, err)

	statusCode = http.StatusInternalServerError
	respPayload = `internal error`
	_, err = drv.Evaluate(context.Background(), &domain.GuardrailEvalInput{Texts: []string{"x"}})
	require.Error(t, err)
}

func TestGenericHTTPDriver_SSRFBlockingDefaultClient(t *testing.T) {
	var hits atomic.Int32
	loopbackSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		_, _ = w.Write([]byte(`{"decision":"allow"}`))
	}))
	defer loopbackSrv.Close()

	// nil httpClient enforces strict SSRF policy (blocks loopback & insecure HTTP).
	drv, err := drivers.NewGenericHTTPDriver(guardrails.DriverConfig{
		EffectiveConfig: map[string]any{"url": loopbackSrv.URL},
	}, nil)
	require.NoError(t, err)

	_, err = drv.Evaluate(context.Background(), &domain.GuardrailEvalInput{Texts: []string{"hello"}})
	require.Error(t, err)
	assert.Zero(t, hits.Load(), "SSRF policy must block request before dialing loopback server")

	// HTTPS loopback IP literal is also blocked by strict SSRF policy.
	drvHTTPS, err := drivers.NewGenericHTTPDriver(guardrails.DriverConfig{
		EffectiveConfig: map[string]any{"url": "https://127.0.0.1:8443/scan"},
	}, nil)
	require.NoError(t, err)
	_, err = drvHTTPS.Evaluate(context.Background(), &domain.GuardrailEvalInput{Texts: []string{"hello"}})
	require.Error(t, err)
}

func TestGenericHTTPDriver_PipelineToolCallModifyAndPerScannerPolicies(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	require.NoError(t, repo.CreateOrganization(ctx, &domain.Organization{ID: "org-1", Name: "Org 1"}))

	slowSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
			return
		case <-time.After(200 * time.Millisecond):
			_, _ = w.Write([]byte(`{"decision":"allow"}`))
		}
	}))
	defer slowSrv.Close()

	modSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(15 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"decision": "modify",
			"modified_texts": ["scrubbed response"],
			"modified_tool_calls": [{"id":"tc-1","type":"function","function":{"name":"search_docs","arguments":"{\"query\":\"safe\"}"}}]
		}`))
	}))
	defer modSrv.Close()

	// Guardrail 1: slow + fail_open=true + TimeoutMs=35 (times out -> fails open)
	require.NoError(t, repo.CreateGuardrailDefinition(ctx, &domain.GuardrailDefinition{
		ID:         "g-slow-open",
		OrgID:      "org-1",
		Name:       "slow-open",
		Provider:   drivers.DriverNameGenericHTTP,
		EventHooks: []domain.GuardrailHook{domain.GuardrailHookPostCall},
		DefaultOn:  true,
		TimeoutMs:  35,
		FailOpen:   true,
		Precedence: 1,
		Config:     map[string]any{"url": slowSrv.URL},
		Status:     domain.GuardrailStatusActive,
	}))
	// Guardrail 2: fast + fail_open=false + TimeoutMs=250 (succeeds & rewrites output)
	require.NoError(t, repo.CreateGuardrailDefinition(ctx, &domain.GuardrailDefinition{
		ID:         "g-fast-mod",
		OrgID:      "org-1",
		Name:       "fast-mod",
		Provider:   drivers.DriverNameGenericHTTP,
		EventHooks: []domain.GuardrailHook{domain.GuardrailHookPostCall},
		DefaultOn:  true,
		TimeoutMs:  250,
		FailOpen:   false,
		Precedence: 2,
		Config:     map[string]any{"url": modSrv.URL},
		Status:     domain.GuardrailStatusActive,
	}))

	client := allowLocalClient(t)
	pipeline := guardrails.NewPipeline(guardrails.NewEngine(repo), repo)
	pipeline.RegisterDriver(drivers.DriverNameGenericHTTP, func(_ context.Context, cfg guardrails.DriverConfig) (guardrails.Driver, error) {
		return drivers.NewGenericHTTPDriver(cfg, client)
	})

	resp := &domain.CanonicalChatResponse{
		Model: "gpt-4o",
		Choices: []domain.CanonicalChoice{{
			Index: 0,
			Message: domain.CanonicalMessage{
				Role:    "assistant",
				Content: "original unsafe response",
				ToolCalls: []domain.CanonicalToolCall{{
					ID:       "tc-1",
					Type:     "function",
					Function: domain.CanonicalFunctionCall{Name: "search_docs", Arguments: `{"query":"secret"}`},
				}},
			},
		}},
	}
	out, err := pipeline.EvaluatePostCall(ctx, guardrails.PipelineRequestContext{
		RequestID: "req-pipe-1",
		OrgID:     "org-1",
		Model:     "gpt-4o",
	}, resp)
	require.NoError(t, err)
	assert.True(t, out.Redacted)
	assert.Equal(t, "scrubbed response", resp.Choices[0].Message.Content)
	require.Len(t, resp.Choices[0].Message.ToolCalls, 1)
	assert.Equal(t, `{"query":"safe"}`, resp.Choices[0].Message.ToolCalls[0].Function.Arguments)
}
