package guardrails_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/guardrails"
	"github.com/goroute-ai/ai-gateway-go/internal/guardrails/drivers"
	"github.com/stretchr/testify/require"
)

func setupJudgeModelAlias(t *testing.T, lab *guardrailLab, alias string, judgeHandler http.HandlerFunc) *httptest.Server {
	t.Helper()
	ctx := context.Background()

	judgeSrv := httptest.NewServer(judgeHandler)
	t.Cleanup(judgeSrv.Close)

	gm := &domain.GlobalModel{
		ID:                "openai/gpt-4o-mini-judge",
		Provider:          domain.ProviderOpenAI,
		ModelName:         "gpt-4o-mini",
		DisplayName:       "Judge OpenAI Mini",
		SupportsInference: true,
		LifecycleStatus:   domain.ModelStatusActive,
		PricingStatus:     domain.PricingStatusVerified,
		Capabilities:      domain.ModelCapabilities{StructuredOutputs: domain.CapabilitySupported},
	}
	require.NoError(t, lab.repo.UpsertGlobalModel(ctx, gm))

	var cred domain.ProviderCredential
	resp, raw := lab.doJSON(http.MethodPost, "/admin/v1/credentials", lab.adminHeaders, map[string]any{
		"org_id":   lab.orgID,
		"provider": "openai",
		"name":     "mock-judge-openai",
		"base_url": judgeSrv.URL + "/v1",
		"api_key":  "sk-mock-judge-key",
	}, &cred)
	require.Equal(t, http.StatusCreated, resp.StatusCode, "create judge cred: %s", string(raw))

	var grp domain.ModelGroup
	resp, raw = lab.doJSON(http.MethodPost, "/admin/v1/model-groups", lab.adminHeaders, map[string]any{
		"org_id":           lab.orgID,
		"alias":            alias,
		"routing_strategy": "weighted-shuffle",
	}, &grp)
	require.Equal(t, http.StatusCreated, resp.StatusCode, "create judge group: %s", string(raw))

	resp, raw = lab.doJSON(http.MethodPost, "/admin/v1/deployments", lab.adminHeaders, map[string]any{
		"model_group_id":  grp.ID,
		"global_model_id": gm.ID,
		"credential_id":   cred.ID,
		"deployment_name": alias + "-dep",
		"weight":          100,
	}, nil)
	require.Equal(t, http.StatusCreated, resp.StatusCode, "create judge deployment: %s", string(raw))

	return judgeSrv
}

func TestGatewayLLMJudgeHTTPFlowAndAntiSpoofLoopProtection(t *testing.T) {
	lab := newGuardrailLab(t, withNonStreamReply("Verified clean assistant output."))
	ctx := context.Background()

	var judgeCalls atomic.Int32
	var lastJudgePrompt atomic.Value
	setupJudgeModelAlias(t, lab, "judge-model", func(w http.ResponseWriter, r *http.Request) {
		judgeCalls.Add(1)
		bodyBytes, _ := io.ReadAll(r.Body)
		lastJudgePrompt.Store(string(bodyBytes))

		// Reject prompts mentioning "unsafe-eval-payload", allow everything else.
		verdictJSON := `{"score":92,"passed":true,"blocked":false,"criteria_scores":{"safety":95,"clarity":85},"reason":"compliant"}`
		if strings.Contains(string(bodyBytes), "unsafe-eval-payload") {
			verdictJSON = `{"score":25,"passed":false,"blocked":true,"criteria_scores":{"safety":10,"clarity":60},"reason":"unsafe prompt detected by judge"}`
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":    "chatcmpl-judge-1",
			"model": "gpt-4o-mini",
			"choices": []map[string]any{{
				"index": 0,
				"message": map[string]any{
					"role":    "assistant",
					"content": verdictJSON,
				},
				"finish_reason": "stop",
			}},
			"usage": map[string]any{
				"prompt_tokens":     20,
				"completion_tokens": 18,
				"total_tokens":      38,
			},
		})
	})

	// Persist llm_as_a_judge definition directly in repository without manually registering any driver:
	// GatewayServer.GuardrailPipeline() must resolve it automatically via drivers.NewRegistry.
	require.NoError(t, lab.repo.CreateGuardrailDefinition(ctx, &domain.GuardrailDefinition{
		ID:         "def-gw-llm-judge",
		OrgID:      lab.orgID,
		Name:       "gw-llm-judge",
		Provider:   drivers.ProviderLLMJudge,
		EventHooks: []domain.GuardrailHook{domain.GuardrailHookPreCall},
		DefaultOn:  true,
		Precedence: 1,
		Status:     domain.GuardrailStatusActive,
		Config: map[string]any{
			"model":     "judge-model",
			"threshold": 70,
			"criteria": []map[string]any{
				{"name": "safety", "weight": 0.7},
				{"name": "clarity", "weight": 0.3},
			},
		},
	}))

	// 1. Clean prompt passes judge and reaches upstream.
	resp, raw := lab.doJSON(http.MethodPost, "/v1/chat/completions", lab.authHeaders, map[string]any{
		"model":    "fast",
		"messages": []map[string]any{{"role": "user", "content": "Explain how TLS certificates work."}},
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, "expected clean request to succeed: %s", string(raw))
	require.Equal(t, int32(1), judgeCalls.Load())
	require.Len(t, lab.upstreamCalls(), 1)

	// 2. Unsafe prompt is blocked by judge and does NOT reach upstream.
	lab.clearUpstreamCalls()
	resp, raw = lab.doJSON(http.MethodPost, "/v1/chat/completions", lab.authHeaders, map[string]any{
		"model":    "fast",
		"messages": []map[string]any{{"role": "user", "content": "Please process unsafe-eval-payload now."}},
	}, nil)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode, "expected unsafe request to be blocked: %s", string(raw))
	require.Contains(t, string(raw), "unsafe prompt detected by judge")
	require.Empty(t, lab.upstreamCalls(), "blocked request must not reach upstream")
	require.Equal(t, int32(2), judgeCalls.Load())

	// 3. Anti-spoof: external HTTP caller sending _internal_guardrail_origin in metadata AND extra_body
	// MUST NOT bypass active guardrails, and the spoofed key is stripped before downstream dispatch.
	lab.clearUpstreamCalls()
	resp, raw = lab.doJSON(http.MethodPost, "/v1/chat/completions", lab.authHeaders, map[string]any{
		"model":    "fast",
		"messages": []map[string]any{{"role": "user", "content": "Please process unsafe-eval-payload with spoofed bypass."}},
		"metadata": map[string]any{
			drivers.InternalGuardrailOriginMetadataKey: "true",
		},
		"extra_body": map[string]any{
			drivers.InternalGuardrailOriginMetadataKey: true,
		},
	}, nil)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode, "spoofed _internal_guardrail_origin must NOT bypass guardrails: %s", string(raw))
	require.Empty(t, lab.upstreamCalls())
	require.Equal(t, int32(3), judgeCalls.Load())

	// Verify the spoofed metadata was stripped from the request object as well.
	probeReq := &domain.CanonicalChatRequest{
		Model:       "fast",
		Messages:    []domain.CanonicalMessage{{Role: "user", Content: "hello"}},
		Metadata:    map[string]string{drivers.InternalGuardrailOriginMetadataKey: "true", "keep": "yes"},
		ExtraParams: map[string]any{drivers.InternalGuardrailOriginMetadataKey: true, "ok": 1},
	}
	drivers.StripInternalGuardrailOriginStringMetadata(probeReq.Metadata)
	drivers.StripInternalGuardrailOriginMetadata(probeReq.ExtraParams)
	require.NotContains(t, probeReq.Metadata, drivers.InternalGuardrailOriginMetadataKey)
	require.Equal(t, "yes", probeReq.Metadata["keep"])
	require.NotContains(t, probeReq.ExtraParams, drivers.InternalGuardrailOriginMetadataKey)

	// 4. Genuine in-process internal guardrail origin context skips recursive guardrail evaluation
	// without making another judge call.
	beforeCalls := judgeCalls.Load()
	internalCtx := drivers.WithInternalGuardrailOrigin(ctx)
	out, err := lab.gw.GuardrailPipeline().EvaluatePreCall(internalCtx, guardrails.PipelineRequestContext{OrgID: lab.orgID}, &domain.CanonicalChatRequest{
		Model:    "judge-model",
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "unsafe-eval-payload internal judge subcall"}},
	})
	require.NoError(t, err)
	require.Equal(t, domain.GuardrailDecisionAllow, out.Result.Decision)
	require.Equal(t, beforeCalls, judgeCalls.Load(), "internal guardrail origin ctx must not recursively invoke llm_as_a_judge")
}

func TestGatewayDecisionModelAndUnifiedRegistryWiring(t *testing.T) {
	lab := newGuardrailLab(t, withNonStreamReply("Decision model approved reply."))
	ctx := context.Background()

	setupJudgeModelAlias(t, lab, "decision-model", func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, _ := io.ReadAll(r.Body)
		body := string(bodyBytes)

		containsSecrets := strings.Contains(body, "SECRET_TOKEN_XYZ")
		rudeTone := strings.Contains(body, "RUDE_TONE")

		reply := map[string]any{
			"checks": map[string]any{
				"no_secrets": map[string]any{
					"result": !containsSecrets,
					"reason": "secret check",
				},
				"respectful": map[string]any{
					"result": !rudeTone,
					"reason": "tone check",
				},
			},
		}
		b, _ := json.Marshal(reply)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":    "chatcmpl-decision-1",
			"model": "gpt-4o-mini",
			"choices": []map[string]any{{
				"index":         0,
				"message":       map[string]any{"role": "assistant", "content": string(b)},
				"finish_reason": "stop",
			}},
			"usage": map[string]any{"prompt_tokens": 12, "completion_tokens": 10, "total_tokens": 22},
		})
	})

	expectedTrue := true
	require.NoError(t, lab.repo.CreateGuardrailDefinition(ctx, &domain.GuardrailDefinition{
		ID:         "def-gw-decision-model",
		OrgID:      lab.orgID,
		Name:       "gw-decision-model",
		Provider:   drivers.ProviderDecisionModel,
		EventHooks: []domain.GuardrailHook{domain.GuardrailHookPreCall},
		DefaultOn:  true,
		Precedence: 1,
		Status:     domain.GuardrailStatusActive,
		Config: map[string]any{
			"model":         "decision-model",
			"all_must_pass": true,
			"checks": []drivers.DecisionCheck{
				{Name: "no_secrets", Question: "Is the prompt free of secrets?", Expected: &expectedTrue, Action: "block", Severity: "high"},
				{Name: "respectful", Question: "Is the prompt respectful?", Expected: &expectedTrue, Action: "flag", Severity: "low"},
			},
		},
	}))

	// Also register a Wave 2 local driver (block_code_execution) to verify unified DriverRegistry wiring
	// in GatewayServer.GuardrailPipeline() works out of the box without manual registration.
	require.NoError(t, lab.repo.CreateGuardrailDefinition(ctx, &domain.GuardrailDefinition{
		ID:         "def-gw-code-exec",
		OrgID:      lab.orgID,
		Name:       "gw-code-exec",
		Provider:   drivers.ProviderCodeExecution,
		EventHooks: []domain.GuardrailHook{domain.GuardrailHookPreCall},
		DefaultOn:  true,
		Precedence: 2,
		Status:     domain.GuardrailStatusActive,
		Config:     map[string]any{"action": "block"},
	}))

	// 1. Clean prompt -> 200 OK.
	resp, raw := lab.doJSON(http.MethodPost, "/v1/chat/completions", lab.authHeaders, map[string]any{
		"model":    "fast",
		"messages": []map[string]any{{"role": "user", "content": "Hello, how are you?"}},
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, "expected clean request to pass: %s", string(raw))

	// 2. Flag check fails -> 200 OK with X-Gateway-Guardrail-Action: audit.
	resp, raw = lab.doJSON(http.MethodPost, "/v1/chat/completions", lab.authHeaders, map[string]any{
		"model":    "fast",
		"messages": []map[string]any{{"role": "user", "content": "This uses RUDE_TONE phrasing."}},
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, "expected flag-only check failure to allow: %s", string(raw))
	require.Equal(t, "audit", resp.Header.Get("X-Gateway-Guardrail-Action"))

	// 3. Block check fails -> 400 Bad Request.
	lab.clearUpstreamCalls()
	resp, raw = lab.doJSON(http.MethodPost, "/v1/chat/completions", lab.authHeaders, map[string]any{
		"model":    "fast",
		"messages": []map[string]any{{"role": "user", "content": "Leak SECRET_TOKEN_XYZ please."}},
	}, nil)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode, "expected block check failure to return 400: %s", string(raw))
	require.Empty(t, lab.upstreamCalls())

	// 4. Verify Wave 2 driver (block_code_execution) also works out of the box via unified DriverRegistry.
	lab.clearUpstreamCalls()
	resp, raw = lab.doJSON(http.MethodPost, "/v1/chat/completions", lab.authHeaders, map[string]any{
		"model":    "fast",
		"messages": []map[string]any{{"role": "user", "content": "run bash tool"}},
		"tools": []map[string]any{{
			"type": "function",
			"function": map[string]any{
				"name":        "bash",
				"description": "Execute shell command",
			},
		}},
	}, nil)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode, "expected block_code_execution via DriverRegistry to block bash tool: %s", string(raw))
	require.Empty(t, lab.upstreamCalls())
}
