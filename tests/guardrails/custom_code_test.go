package guardrails_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/guardrails"
	"github.com/goroute-ai/ai-gateway-go/internal/guardrails/drivers"
	"github.com/stretchr/testify/require"
)

func TestCustomCodeGuardrailEndToEndHTTP(t *testing.T) {
	lab := newGuardrailLab(t)
	ctx := context.Background()

	// Mock external moderation webhook allowed via injected test client for the positive-path test.
	var webhookHits int
	webhookSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		webhookHits++
		var payload map[string]any
		_ = json.NewDecoder(r.Body).Decode(&payload)
		w.Header().Set("Content-Type", "application/json")
		text, _ := payload["text"].(string)
		if strings.Contains(text, "webhook-block") {
			_ = json.NewEncoder(w).Encode(map[string]any{"block": true, "reason": "webhook rejected"})
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"block": false})
	}))
	defer webhookSrv.Close()

	lab.gw.GuardrailPipeline().RegisterDriver(drivers.CustomCodeProvider, func(_ context.Context, cfg guardrails.DriverConfig) (guardrails.Driver, error) {
		// Use explicit test HTTP client only when definition explicitly enables test webhook client;
		// otherwise default to nil -> strict production network.NewHTTPClient SSRF policy.
		if useTestClient, _ := cfg.EffectiveConfig["use_test_http_client"].(bool); useTestClient {
			return drivers.NewCustomCodeDriver(cfg, webhookSrv.Client())
		}
		return drivers.NewCustomCodeDriver(cfg, nil)
	})

	// 1. Pre-call Starlark guardrail: redacts SSNs and blocks "deny-phrase".
	require.NoError(t, lab.repo.CreateGuardrailDefinition(ctx, &domain.GuardrailDefinition{
		ID:         "cc-pre-policy",
		OrgID:      lab.orgID,
		Name:       "cc-pre-policy",
		Provider:   drivers.CustomCodeProvider,
		EventHooks: []domain.GuardrailHook{domain.GuardrailHookPreCall},
		DefaultOn:  true,
		Precedence: 1,
		Status:     domain.GuardrailStatusActive,
		Config: map[string]any{
			"custom_code": `
def apply_guardrail(inputs, request_data, input_type):
    if input_type != "request":
        return allow()
    txt = inputs["texts"][0]
    if regex_match(lower(txt), "deny-phrase"):
        return block(reason="blocked by starlark policy", category="policy", rule="deny-phrase")
    if regex_match(txt, "\\b\\d{3}-\\d{2}-\\d{4}\\b"):
        redacted = [regex_replace(t, "\\b\\d{3}-\\d{2}-\\d{4}\\b", "[REDACTED_SSN]") for t in inputs["texts"]]
        return modify(texts=redacted, reason="redacted ssn")
    return allow()
`,
		},
	}))

	// 2. Opt-in Starlark webhook guardrail (uses http_post against webhookSrv).
	require.NoError(t, lab.repo.CreateGuardrailDefinition(ctx, &domain.GuardrailDefinition{
		ID:         "cc-webhook",
		OrgID:      lab.orgID,
		Name:       "cc-webhook",
		Provider:   drivers.CustomCodeProvider,
		EventHooks: []domain.GuardrailHook{domain.GuardrailHookPreCall},
		DefaultOn:  false,
		Precedence: 2,
		Status:     domain.GuardrailStatusActive,
		Config: map[string]any{
			"use_test_http_client": true,
			"execution_timeout_ms": 2000,
			"custom_code": `
def apply_guardrail(inputs, request_data, input_type):
    resp = http_post("` + webhookSrv.URL + `", json={"text": inputs["texts"][0]})
    if resp["json"]["block"]:
        return block(reason=resp["json"]["reason"])
    return allow()
`,
		},
	}))

	// 3. Opt-in Starlark SSRF probe guardrail (nil httpClient -> strict SSRF protection).
	require.NoError(t, lab.repo.CreateGuardrailDefinition(ctx, &domain.GuardrailDefinition{
		ID:         "cc-ssrf-probe",
		OrgID:      lab.orgID,
		Name:       "cc-ssrf-probe",
		Provider:   drivers.CustomCodeProvider,
		EventHooks: []domain.GuardrailHook{domain.GuardrailHookPreCall},
		DefaultOn:  false,
		Precedence: 3,
		Status:     domain.GuardrailStatusActive,
		Config: map[string]any{
			"custom_code": `
def apply_guardrail(inputs, request_data, input_type):
    http_get("https://169.254.169.254/latest/meta-data/")
    return allow()
`,
		},
	}))

	// 4. Opt-in runaway loop guardrail.
	require.NoError(t, lab.repo.CreateGuardrailDefinition(ctx, &domain.GuardrailDefinition{
		ID:         "cc-runaway",
		OrgID:      lab.orgID,
		Name:       "cc-runaway",
		Provider:   drivers.CustomCodeProvider,
		EventHooks: []domain.GuardrailHook{domain.GuardrailHookPreCall},
		DefaultOn:  false,
		Precedence: 4,
		Status:     domain.GuardrailStatusActive,
		Config: map[string]any{
			"max_execution_steps": 1500,
			"custom_code": `
def apply_guardrail(inputs, request_data, input_type):
    n = 0
    for i in range(1000000):
        n += i
    return allow()
`,
		},
	}))

	// Case A: Block on "deny-phrase" before reaching upstream.
	lab.clearUpstreamCalls()
	resp, raw := lab.doJSON(http.MethodPost, "/v1/chat/completions", lab.authHeaders, map[string]any{
		"model":    "fast",
		"messages": []map[string]any{{"role": "user", "content": "please trigger DENY-PHRASE now"}},
	}, nil)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode, string(raw))
	require.Contains(t, string(raw), "blocked by starlark policy")
	require.Empty(t, lab.upstreamCalls())

	// Case B: Modify/redact SSN before forwarding to upstream.
	lab.clearUpstreamCalls()
	resp, raw = lab.doJSON(http.MethodPost, "/v1/chat/completions", lab.authHeaders, map[string]any{
		"model":    "fast",
		"messages": []map[string]any{{"role": "user", "content": "my ssn is 123-45-6789"}},
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(raw))
	calls := lab.upstreamCalls()
	require.Len(t, calls, 1)
	require.Contains(t, calls[0].Body, "[REDACTED_SSN]")
	require.NotContains(t, calls[0].Body, "123-45-6789")

	// Case C: Opt-in webhook guardrail executes http_post and blocks.
	lab.clearUpstreamCalls()
	resp, raw = lab.doJSON(http.MethodPost, "/v1/chat/completions", lab.authHeaders, map[string]any{
		"model":    "fast",
		"messages": []map[string]any{{"role": "user", "content": "webhook-block payload"}},
		"goroute_extensions": map[string]any{
			"guardrails": []map[string]any{{"name": "cc-webhook", "enabled": true}},
		},
	}, nil)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode, string(raw))
	require.Contains(t, string(raw), "webhook rejected")
	require.Equal(t, 1, webhookHits)
	require.Empty(t, lab.upstreamCalls())

	// Case D: Strict SSRF policy blocks metadata IP and fails closed with 503 guardrail_unavailable.
	lab.clearUpstreamCalls()
	resp, raw = lab.doJSON(http.MethodPost, "/v1/chat/completions", lab.authHeaders, map[string]any{
		"model":    "fast",
		"messages": []map[string]any{{"role": "user", "content": "hello"}},
		"goroute_extensions": map[string]any{
			"guardrails": []map[string]any{{"name": "cc-ssrf-probe", "enabled": true}},
		},
	}, nil)
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode, string(raw))
	require.Empty(t, lab.upstreamCalls())

	// Case E: Runaway loop hits SetMaxExecutionSteps and fails closed cleanly.
	lab.clearUpstreamCalls()
	resp, raw = lab.doJSON(http.MethodPost, "/v1/chat/completions", lab.authHeaders, map[string]any{
		"model":    "fast",
		"messages": []map[string]any{{"role": "user", "content": "hello"}},
		"goroute_extensions": map[string]any{
			"guardrails": []map[string]any{{"name": "cc-runaway", "enabled": true}},
		},
	}, nil)
	require.Equal(t, http.StatusServiceUnavailable, resp.StatusCode, string(raw))
	require.Empty(t, lab.upstreamCalls())
}

func TestCustomCodePostCallToolCallModification(t *testing.T) {
	lab := newGuardrailLab(t)
	ctx := context.Background()

	lab.gw.GuardrailPipeline().RegisterDriver(drivers.CustomCodeProvider, func(_ context.Context, cfg guardrails.DriverConfig) (guardrails.Driver, error) {
		return drivers.NewCustomCodeDriver(cfg, nil)
	})

	require.NoError(t, lab.repo.CreateGuardrailDefinition(ctx, &domain.GuardrailDefinition{
		ID:         "cc-post-tool-redact",
		OrgID:      lab.orgID,
		Name:       "cc-post-tool-redact",
		Provider:   drivers.CustomCodeProvider,
		EventHooks: []domain.GuardrailHook{domain.GuardrailHookPostCall},
		DefaultOn:  true,
		Precedence: 1,
		Status:     domain.GuardrailStatusActive,
		Config: map[string]any{
			"custom_code": `
def apply_guardrail(inputs, request_data, input_type):
    if input_type != "response":
        return allow()
    updated_calls = []
    for tc in inputs["tool_calls"]:
        args = json_parse(tc["function"]["arguments"])
        if "api_secret" in args:
            args["api_secret"] = "[REDACTED]"
        updated_calls.append({
            "id": tc["id"],
            "type": tc["type"],
            "function": {
                "name": tc["function"]["name"],
                "arguments": json_dumps(args),
            },
        })
    return modify(tool_calls=updated_calls, reason="sanitized tool call args")
`,
		},
	}))

	chatResp := &domain.CanonicalChatResponse{
		ID:    "chatcmpl-1",
		Model: "fast",
		Choices: []domain.CanonicalChoice{{
			Index: 0,
			Message: domain.CanonicalMessage{
				Role: "assistant",
				ToolCalls: []domain.CanonicalToolCall{{
					ID:   "tc-1",
					Type: "function",
					Function: domain.CanonicalFunctionCall{
						Name:      "call_service",
						Arguments: `{"endpoint":"https://api.example.com","api_secret":"sk-live-secret"}`,
					},
				}},
			},
		}},
	}

	outcome, err := lab.gw.GuardrailPipeline().EvaluatePostCall(ctx, guardrails.PipelineRequestContext{
		OrgID: lab.orgID,
		Model: "fast",
	}, chatResp)
	require.NoError(t, err)
	require.True(t, outcome.Redacted)
	require.Equal(t, domain.GuardrailDecisionModify, outcome.Result.Decision)
	require.Len(t, chatResp.Choices[0].Message.ToolCalls, 1)
	require.NotContains(t, chatResp.Choices[0].Message.ToolCalls[0].Function.Arguments, "sk-live-secret")
	require.Contains(t, chatResp.Choices[0].Message.ToolCalls[0].Function.Arguments, "[REDACTED]")
}
