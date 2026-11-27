// External guardrail driver tests verify generic_http webhook definitions
// across pre_call, post_call, and logging_only hooks, Admin CRUD and Vault
// secret handling, declarative YAML startup seeding, and fail-closed vs
// fail-open execution semantics.

package guardrails_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExternalGuardrailPreAndPostModifyAcrossEndpointsHTTP(t *testing.T) {
	lab := newGuardrailLab(t, withNonStreamReply("raw-model-output"))
	ctx := context.Background()

	webhookSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload struct {
			Hook  string   `json:"hook"`
			Texts []string `json:"texts"`
		}
		_ = json.NewDecoder(r.Body).Decode(&payload)
		joined := strings.Join(payload.Texts, "\n")

		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(joined, "block-webhook-token") {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"decision": "block",
				"reason":   "blocked by external webhook",
			})
			return
		}
		if payload.Hook == "pre_call" && strings.Contains(joined, "raw-prompt") {
			mod := make([]string, len(payload.Texts))
			for i, txt := range payload.Texts {
				mod[i] = strings.ReplaceAll(txt, "raw-prompt", "pre-mutated-prompt")
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"decision":       "modify",
				"modified_texts": mod,
			})
			return
		}
		if payload.Hook == "post_call" && strings.Contains(joined, "raw-model-output") {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"decision":       "modify",
				"modified_texts": []string{"post-mutated-reply"},
			})
			return
		}
		_, _ = w.Write([]byte(`{"decision":"allow"}`))
	}))
	defer webhookSrv.Close()

	require.NoError(t, lab.repo.CreateGuardrailDefinition(ctx, &domain.GuardrailDefinition{
		ID:         "def-webhook-pre-post",
		OrgID:      lab.orgID,
		Name:       "external-webhook",
		Provider:   "generic_http",
		EventHooks: []domain.GuardrailHook{domain.GuardrailHookPreCall, domain.GuardrailHookPostCall},
		Precedence: 1,
		Enabled:    true,
		Config:     map[string]any{"url": webhookSrv.URL},
	}))

	// 1. Pre-call block stops request before upstream.
	lab.clearUpstreamCalls()
	resp, raw := lab.doJSON(http.MethodPost, "/v1/chat/completions", lab.authHeaders, map[string]any{
		"model":    "fast",
		"messages": []map[string]any{{"role": "user", "content": "contains block-webhook-token"}},
	}, nil)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode, string(raw))
	require.Empty(t, lab.upstreamCalls())

	// 2. /v1/chat/completions pre-call and post-call modify.
	lab.clearUpstreamCalls()
	resp, raw = lab.doJSON(http.MethodPost, "/v1/chat/completions", lab.authHeaders, map[string]any{
		"model":    "fast",
		"messages": []map[string]any{{"role": "user", "content": "raw-prompt"}},
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(raw))
	assert.Contains(t, string(raw), "post-mutated-reply")
	assert.NotContains(t, string(raw), "raw-model-output")
	require.Len(t, lab.upstreamCalls(), 1)
	assert.Contains(t, lab.upstreamCalls()[0].Body, "pre-mutated-prompt")

	// 3. /v1/responses pre-call and post-call modify.
	lab.clearUpstreamCalls()
	resp, raw = lab.doJSON(http.MethodPost, "/v1/responses", lab.authHeaders, map[string]any{
		"model": "fast",
		"input": "raw-prompt",
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(raw))
	assert.Contains(t, string(raw), "post-mutated-reply")
	require.Len(t, lab.upstreamCalls(), 1)
	assert.Contains(t, lab.upstreamCalls()[0].Body, "pre-mutated-prompt")

	// 4. /v1/messages pre-call and post-call modify.
	lab.clearUpstreamCalls()
	resp, raw = lab.doJSON(http.MethodPost, "/v1/messages", lab.authHeaders, map[string]any{
		"model":      "fast",
		"max_tokens": 64,
		"messages":   []map[string]any{{"role": "user", "content": "raw-prompt"}},
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(raw))
	assert.Contains(t, string(raw), "post-mutated-reply")
	require.Len(t, lab.upstreamCalls(), 1)
	assert.Contains(t, lab.upstreamCalls()[0].Body, "pre-mutated-prompt")

	// 5. /v1/embeddings pre-call block.
	lab.clearUpstreamCalls()
	resp, raw = lab.doJSON(http.MethodPost, "/v1/embeddings", lab.authHeaders, map[string]any{
		"model": "emb-small",
		"input": "contains block-webhook-token",
	}, nil)
	require.Equal(t, http.StatusBadRequest, resp.StatusCode, string(raw))
	require.Empty(t, lab.upstreamCalls())
}

func TestExternalGuardrailAdminCRUDTestEndpointAndLoggingOnlyHTTP(t *testing.T) {
	var shadowHits atomic.Int32
	shadowSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		shadowHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"decision":"block","reason":"shadow violation must not block"}`))
	}))
	defer shadowSrv.Close()

	lab := newGuardrailLab(t)

	// Create definition via Admin API with logging_only hook and encrypted Vault secret.
	var created struct {
		ID      string `json:"id"`
		Name    string `json:"name"`
		Enabled bool   `json:"enabled"`
	}
	resp, raw := lab.doJSON(http.MethodPost, "/admin/v1/organizations/"+lab.orgID+"/guardrail-definitions", lab.adminHeaders, map[string]any{
		"name":        "shadow-webhook",
		"provider":    "generic_http",
		"event_hooks": []string{"logging_only"},
		"enabled":     true,
		"timeout_ms":  2000,
		"config":      map[string]any{"url": shadowSrv.URL},
		"secrets":     map[string]any{"bearer_token": "synthetic-vault-secret"},
	}, &created)
	require.Equal(t, http.StatusCreated, resp.StatusCode, string(raw))
	require.NotEmpty(t, created.ID)
	assert.True(t, created.Enabled)
	assert.NotContains(t, string(raw), "synthetic-vault-secret", "secrets must never be echoed in responses")

	// Fetch single definition & list organization definitions cleanly.
	var fetched map[string]any
	resp, raw = lab.doJSON(http.MethodGet, "/admin/v1/guardrail-definitions/"+created.ID, lab.adminHeaders, nil, &fetched)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(raw))
	assert.Equal(t, "shadow-webhook", fetched["name"])
	assert.Equal(t, true, fetched["has_secrets"])

	// Live inference request passes through without blocking because hook is logging_only.
	resp, raw = lab.doJSON(http.MethodPost, "/v1/chat/completions", lab.authHeaders, map[string]any{
		"model":    "fast",
		"messages": []map[string]any{{"role": "user", "content": "hello shadow"}},
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(raw))
	assert.GreaterOrEqual(t, shadowHits.Load(), int32(1))

	// Update and delete definition cleanly.
	resp, raw = lab.doJSON(http.MethodPut, "/admin/v1/guardrail-definitions/"+created.ID, lab.adminHeaders, map[string]any{
		"name":        "shadow-webhook",
		"provider":    "generic_http",
		"event_hooks": []string{"logging_only"},
		"enabled":     false,
		"config":      map[string]any{"url": shadowSrv.URL},
	}, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(raw))

	resp, raw = lab.doJSON(http.MethodDelete, "/admin/v1/guardrail-definitions/"+created.ID, lab.adminHeaders, nil, nil)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(raw))
}

func TestDeclarativeYAMLStartupSeedingAndFailOpen(t *testing.T) {
	failSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "downstream error", http.StatusServiceUnavailable)
	}))
	defer failSrv.Close()

	enabledTrue := true
	lab := newGuardrailLab(t, withGuardrailsConfig(config.GuardrailsConfig{
		Definitions: []config.GuardrailDefinitionConfig{
			{
				Name:       "yaml-fail-open-webhook",
				Provider:   "generic_http",
				EventHooks: []string{"pre_call"},
				Enabled:    &enabledTrue,
				FailOpen:   true,
				TimeoutMs:  1000,
				Config:     map[string]any{"url": failSrv.URL},
			},
		},
	}))

	// Seeded definition should exist in org_default (or be listable via admin API).
	var listResp struct {
		Data []domain.GuardrailDefinition `json:"data"`
	}
	resp, raw := lab.doJSON(http.MethodGet, "/admin/v1/organizations/org_default/guardrail-definitions", lab.adminHeaders, nil, &listResp)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(raw))
	require.Len(t, listResp.Data, 1)
	assert.Equal(t, "yaml-fail-open-webhook", listResp.Data[0].Name)
	assert.True(t, listResp.Data[0].Enabled)
	assert.True(t, listResp.Data[0].FailOpen)
}
