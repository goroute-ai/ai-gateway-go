package server_test

import (
	"bytes"
	"encoding/json"
	"fmt"
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

func adminReq(t *testing.T, handler http.Handler, method, path, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		require.NoError(t, json.NewEncoder(&buf).Encode(body))
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func TestAdminRouting_ModelGroupAndDeploymentCRUD_DrainAndSanitizeConfig(t *testing.T) {
	h := newRoutingHarness(t, func(cfg *config.Config) {
		cfg.Router.DropUnsupportedParams = true
		cfg.Router.FallbackOnUnsupportedParams = true
		cfg.Router.AllowStrategyOverride = true
		cfg.Router.DebugRoutingHeaders = true
		cfg.Router.FallbackOnSaturation = true
		cfg.Router.DisableCooldowns = true
		cfg.Router.LatencyTolerancePct = 0.15
		cfg.Router.Scheduler.MaxParallelWaitMs = 250
	})

	var dep1Hits, dep2Hits atomic.Int32
	srv1 := mockOpenAIChatServer(t, "dep1", &dep1Hits)
	defer srv1.Close()
	srv2 := mockOpenAIChatServer(t, "dep2", &dep2Hits)
	defer srv2.Close()

	cred1 := h.createOpenAICredential("c1", srv1.URL)
	cred2 := h.createOpenAICredential("c2", srv2.URL)

	m := &domain.GlobalModel{
		ID: "openai/gpt-4o-mini", Provider: domain.ProviderOpenAI, ModelName: "gpt-4o-mini",
		SupportsInference: true, SupportsStreaming: true, SupportsTools: true,
		Capabilities: domain.ModelCapabilities{Streaming: domain.CapabilitySupported, Tools: domain.CapabilitySupported},
	}
	require.NoError(t, h.repo.UpsertGlobalModel(h.ctx, m))

	master := h.cfg.Auth.MasterAdminKey
	recMG := adminReq(t, h.gw.Handler(), http.MethodPost, "/admin/v1/model-groups", master, map[string]any{
		"org_id":                  h.org.ID,
		"alias":                   "p5-crud-alias",
		"routing_strategy":        "weighted-shuffle",
		"drop_unsupported_params": true,
		"saturation_fallbacks":    []map[string]any{{"target": "fast"}},
	})
	require.Equal(t, http.StatusCreated, recMG.Code)
	var createdMG domain.ModelGroup
	require.NoError(t, json.Unmarshal(recMG.Body.Bytes(), &createdMG))
	assert.True(t, createdMG.DropUnsupportedParams)
	require.Len(t, createdMG.SaturationFallbacks, 1)

	// GET model group
	getMG := adminReq(t, h.gw.Handler(), http.MethodGet, "/admin/v1/model-groups/"+createdMG.ID, master, nil)
	require.Equal(t, http.StatusOK, getMG.Code)

	// PUT model group preserves IsActive=true when omitted and validates invalid strategy
	badPut := adminReq(t, h.gw.Handler(), http.MethodPut, "/admin/v1/model-groups/"+createdMG.ID, master, map[string]any{
		"routing_strategy": "nonexistent-strategy",
	})
	assert.Equal(t, http.StatusBadRequest, badPut.Code)

	putMG := adminReq(t, h.gw.Handler(), http.MethodPut, "/admin/v1/model-groups/"+createdMG.ID, master, map[string]any{
		"routing_strategy":  "round-robin",
		"disable_cooldowns": true,
	})
	require.Equal(t, http.StatusOK, putMG.Code)
	var updatedMG domain.ModelGroup
	require.NoError(t, json.Unmarshal(putMG.Body.Bytes(), &updatedMG))
	assert.Equal(t, domain.StrategyRoundRobin, updatedMG.RoutingStrategy)
	assert.True(t, updatedMG.DisableCooldowns)
	assert.True(t, updatedMG.IsActive)

	// Legacy underscore and alias routing strategies canonicalize cleanly.
	legacyPost := adminReq(t, h.gw.Handler(), http.MethodPost, "/admin/v1/model-groups", master, map[string]any{
		"org_id":           h.org.ID,
		"alias":            "p5-legacy-strategy",
		"routing_strategy": "weighted_shuffle",
	})
	require.Equal(t, http.StatusCreated, legacyPost.Code, legacyPost.Body.String())
	var legacyMG domain.ModelGroup
	require.NoError(t, json.Unmarshal(legacyPost.Body.Bytes(), &legacyMG))
	assert.Equal(t, domain.StrategyWeightedShuffle, legacyMG.RoutingStrategy)

	legacyPutRR := adminReq(t, h.gw.Handler(), http.MethodPut, "/admin/v1/model-groups/"+legacyMG.ID, master, map[string]any{
		"routing_strategy": "round_robin",
	})
	require.Equal(t, http.StatusOK, legacyPutRR.Code, legacyPutRR.Body.String())
	require.NoError(t, json.Unmarshal(legacyPutRR.Body.Bytes(), &legacyMG))
	assert.Equal(t, domain.StrategyRoundRobin, legacyMG.RoutingStrategy)

	legacyPutSS := adminReq(t, h.gw.Handler(), http.MethodPut, "/admin/v1/model-groups/"+legacyMG.ID, master, map[string]any{
		"routing_strategy": "simple-shuffle",
	})
	require.Equal(t, http.StatusOK, legacyPutSS.Code, legacyPutSS.Body.String())
	require.NoError(t, json.Unmarshal(legacyPutSS.Body.Bytes(), &legacyMG))
	assert.Equal(t, domain.StrategyWeightedShuffle, legacyMG.RoutingStrategy)

	require.Equal(t, http.StatusOK, adminReq(t, h.gw.Handler(), http.MethodDelete, "/admin/v1/model-groups/"+legacyMG.ID, master, nil).Code)

	// Create 2 deployments, verify GET & PATCH + live drain.
	recD1 := adminReq(t, h.gw.Handler(), http.MethodPost, "/admin/v1/deployments", master, map[string]any{
		"model_group_id":        createdMG.ID,
		"global_model_id":       m.ID,
		"credential_id":         cred1.ID,
		"deployment_name":       "node-1",
		"weight":                100,
		"priority":              1,
		"max_parallel_requests": 4,
		"itpm_capacity":         10000,
		"otpm_capacity":         5000,
	})
	require.Equal(t, http.StatusCreated, recD1.Code)
	var d1 domain.Deployment
	require.NoError(t, json.Unmarshal(recD1.Body.Bytes(), &d1))

	recD2 := adminReq(t, h.gw.Handler(), http.MethodPost, "/admin/v1/deployments", master, map[string]any{
		"model_group_id":  createdMG.ID,
		"global_model_id": m.ID,
		"credential_id":   cred2.ID,
		"deployment_name": "node-2",
		"weight":          100,
		"priority":        2,
	})
	require.Equal(t, http.StatusCreated, recD2.Code)
	var d2 domain.Deployment
	require.NoError(t, json.Unmarshal(recD2.Body.Bytes(), &d2))

	// GET deployment
	getD1 := adminReq(t, h.gw.Handler(), http.MethodGet, "/admin/v1/deployments/"+d1.ID, master, nil)
	require.Equal(t, http.StatusOK, getD1.Code)

	// Invalid status in PATCH -> 400
	badPatch := adminReq(t, h.gw.Handler(), http.MethodPatch, "/admin/v1/deployments/"+d1.ID, master, map[string]any{"status": "bogus"})
	assert.Equal(t, http.StatusBadRequest, badPatch.Code)

	// Drain d1 (`status = "disabled"`): live traffic must route only to d2.
	drainRec := adminReq(t, h.gw.Handler(), http.MethodPatch, "/admin/v1/deployments/"+d1.ID, master, map[string]any{
		"status":                "disabled",
		"max_parallel_requests": 8,
	})
	require.Equal(t, http.StatusOK, drainRec.Code)
	var drained domain.Deployment
	require.NoError(t, json.Unmarshal(drainRec.Body.Bytes(), &drained))
	assert.Equal(t, domain.DeploymentStatusDisabled, drained.Status)
	assert.Equal(t, 8, drained.MaxParallelRequests)

	for i := 0; i < 3; i++ {
		chatReq := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"p5-crud-alias","messages":[{"role":"user","content":"hi"}]}`))
		chatReq.Header.Set("Authorization", "Bearer "+h.rawKey)
		chatReq.Header.Set("Content-Type", "application/json")
		chatRec := httptest.NewRecorder()
		h.gw.Handler().ServeHTTP(chatRec, chatReq)
		require.Equal(t, http.StatusOK, chatRec.Code)
		assert.Equal(t, d2.ID, chatRec.Header().Get("X-Gateway-Deployment-Id"))
	}
	assert.Equal(t, int32(0), dep1Hits.Load(), "drained deployment must receive zero live requests")
	assert.Equal(t, int32(3), dep2Hits.Load())

	// Cross-org operator denied on GET deployment & PUT model group.
	otherOrg := &domain.Organization{ID: "org-other-p5", Name: "Other", Slug: "other-p5", IsActive: true}
	require.NoError(t, h.repo.CreateOrganization(h.ctx, otherOrg))
	otherKeyRec := adminReq(t, h.gw.Handler(), http.MethodPost, "/admin/v1/keys", master, map[string]any{
		"org_id": otherOrg.ID, "name": "other-org-admin", "role": "org_admin",
	})
	require.Equal(t, http.StatusCreated, otherKeyRec.Code)
	var otherVK domain.VirtualKey
	require.NoError(t, json.Unmarshal(otherKeyRec.Body.Bytes(), &otherVK))

	denyDep := adminReq(t, h.gw.Handler(), http.MethodGet, "/admin/v1/deployments/"+d1.ID, otherVK.RawKey, nil)
	assert.Equal(t, http.StatusForbidden, denyDep.Code)
	denyMG := adminReq(t, h.gw.Handler(), http.MethodPut, "/admin/v1/model-groups/"+createdMG.ID, otherVK.RawKey, map[string]any{"description": "hijack"})
	assert.Equal(t, http.StatusForbidden, denyMG.Code)

	// Verify /admin/v1/config exposes all new non-secret RouterConfig fields.
	cfgRec := adminReq(t, h.gw.Handler(), http.MethodGet, "/admin/v1/config", master, nil)
	require.Equal(t, http.StatusOK, cfgRec.Code)
	var cfgPayload map[string]any
	require.NoError(t, json.Unmarshal(cfgRec.Body.Bytes(), &cfgPayload))
	rtrMap, ok := cfgPayload["router"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, true, rtrMap["drop_unsupported_params"])
	assert.Equal(t, true, rtrMap["fallback_on_unsupported_params"])
	assert.Equal(t, true, rtrMap["allow_strategy_override"])
	assert.Equal(t, true, rtrMap["debug_routing_headers"])
	assert.Equal(t, true, rtrMap["fallback_on_saturation"])
	assert.Equal(t, true, rtrMap["disable_cooldowns"])
	assert.Equal(t, 0.15, rtrMap["latency_tolerance_pct"])
	schedMap, ok := rtrMap["scheduler"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, float64(250), schedMap["max_parallel_wait_ms"])
	assert.Contains(t, rtrMap, "retry_policy")
	assert.Contains(t, rtrMap, "cooldown_policy")
	assert.Contains(t, rtrMap, "bandit")
	assert.Contains(t, rtrMap, "semantic_router")

	// DELETE deployment & model group
	delD1 := adminReq(t, h.gw.Handler(), http.MethodDelete, "/admin/v1/deployments/"+d1.ID, master, nil)
	assert.Equal(t, http.StatusOK, delD1.Code)
	assert.Equal(t, http.StatusNotFound, adminReq(t, h.gw.Handler(), http.MethodGet, "/admin/v1/deployments/"+d1.ID, master, nil).Code)

	delMG := adminReq(t, h.gw.Handler(), http.MethodDelete, "/admin/v1/model-groups/"+createdMG.ID, master, nil)
	assert.Equal(t, http.StatusOK, delMG.Code)
	assert.Equal(t, http.StatusNotFound, adminReq(t, h.gw.Handler(), http.MethodGet, "/admin/v1/model-groups/"+createdMG.ID, master, nil).Code)
}

func TestAdminRouting_InferenceTelemetry_DroppedParams_And_RedactedDebugHeaders(t *testing.T) {
	h := newRoutingHarness(t, func(cfg *config.Config) {
		cfg.Router.DefaultMaxRetries = 0
		cfg.Router.DebugRoutingHeaders = true
	})

	// Primary deployment returns 502; fallback deployment succeeds with partial capabilities (no tools).
	srvBad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte(`{"error":{"message":"upstream-secret-sk-should-never-leak","code":"backend_down"}}`))
	}))
	defer srvBad.Close()

	srvOK := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		// Tools must have been dropped by DropUnsupportedParams!
		if _, hasTools := body["tools"]; hasTools {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if stream, _ := body["stream"].(bool); stream {
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprint(w, "data: {\"id\":\"s1\",\"object\":\"chat.completion.chunk\",\"model\":\"partial-mini\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"streamed\"}}]}\n\n")
			fmt.Fprint(w, "data: [DONE]\n\n")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"id":"ok-1","model":"partial-mini","choices":[{"index":0,"message":{"role":"assistant","content":"dropped-ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":4,"completion_tokens":2,"total_tokens":6}}`)
	}))
	defer srvOK.Close()

	credBad := h.createOpenAICredential("bad", srvBad.URL)
	credOK := h.createOpenAICredential("ok", srvOK.URL)

	mPartial := &domain.GlobalModel{
		ID: "openai/partial-mini", Provider: domain.ProviderOpenAI, ModelName: "partial-mini",
		SupportsInference: true, SupportsStreaming: true, MaxOutputTokens: 512,
		Capabilities: domain.ModelCapabilities{
			Streaming:         domain.CapabilitySupported,
			Tools:             domain.CapabilityUnsupported,
			StructuredOutputs: domain.CapabilityUnsupported,
		},
	}
	require.NoError(t, h.repo.UpsertGlobalModel(h.ctx, mPartial))

	mgPrimary := &domain.ModelGroup{
		ID: "mg-err-primary", OrgID: h.org.ID, Alias: "p5-telemetry", RoutingStrategy: domain.StrategyWeightedShuffle,
		DropUnsupportedParams: true, FallbackTargets: []domain.FallbackTarget{{GroupAliasOrID: "p5-fallback"}}, IsActive: true,
	}
	mgFallback := &domain.ModelGroup{
		ID: "mg-err-fb", OrgID: h.org.ID, Alias: "p5-fallback", RoutingStrategy: domain.StrategyWeightedShuffle,
		DropUnsupportedParams: true, IsActive: true,
	}
	require.NoError(t, h.repo.CreateModelGroup(h.ctx, mgPrimary))
	require.NoError(t, h.repo.CreateModelGroup(h.ctx, mgFallback))

	require.NoError(t, h.repo.CreateDeployment(h.ctx, &domain.Deployment{
		ID: "dep-bad-node", ModelGroupID: mgPrimary.ID, GlobalModelID: mPartial.ID, CredentialID: credBad.ID,
		Weight: 100, Priority: 1, Status: domain.DeploymentStatusActive, GlobalModel: mPartial,
	}))
	require.NoError(t, h.repo.CreateDeployment(h.ctx, &domain.Deployment{
		ID: "dep-ok-node", ModelGroupID: mgFallback.ID, GlobalModelID: mPartial.ID, CredentialID: credOK.ID,
		Weight: 100, Priority: 1, Status: domain.DeploymentStatusActive, GlobalModel: mPartial,
	}))

	payload := `{"model":"p5-telemetry","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"ping","parameters":{"type":"object"}}}],"max_tokens":4096}`

	// Without X-Gateway-Debug-Routing: true -> X-Gateway-Fallback-Errors MUST NOT be emitted.
	reqNoDbg := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(payload))
	reqNoDbg.Header.Set("Authorization", "Bearer "+h.rawKey)
	reqNoDbg.Header.Set("Content-Type", "application/json")
	recNoDbg := httptest.NewRecorder()
	h.gw.Handler().ServeHTTP(recNoDbg, reqNoDbg)
	require.Equal(t, http.StatusOK, recNoDbg.Code)
	assert.Equal(t, "dep-ok-node", recNoDbg.Header().Get("X-Gateway-Deployment-Id"))
	assert.Contains(t, recNoDbg.Header().Get("X-Gateway-Dropped-Params"), "tools")
	assert.Contains(t, recNoDbg.Header().Get("X-Gateway-Dropped-Params"), "max_tokens")
	assert.Equal(t, "0", recNoDbg.Header().Get("X-Gateway-Retry-Count"))
	assert.Empty(t, recNoDbg.Header().Get("X-Gateway-Fallback-Errors"))

	// With X-Gateway-Debug-Routing: true -> redacted X-Gateway-Fallback-Errors IS emitted (and never leaks secret upstream body).
	reqDbg := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(payload))
	reqDbg.Header.Set("Authorization", "Bearer "+h.rawKey)
	reqDbg.Header.Set("Content-Type", "application/json")
	reqDbg.Header.Set("X-Gateway-Debug-Routing", "true")
	recDbg := httptest.NewRecorder()
	h.gw.Handler().ServeHTTP(recDbg, reqDbg)
	require.Equal(t, http.StatusOK, recDbg.Code)
	fbErrs := recDbg.Header().Get("X-Gateway-Fallback-Errors")
	assert.NotEmpty(t, fbErrs)
	assert.NotContains(t, fbErrs, "upstream-secret-sk-should-never-leak")
	assert.Contains(t, fbErrs, "p5-telemetry/dep-bad-node:")

	// Streaming pre-chunk emission carries X-Gateway-Deployment-Id and X-Gateway-Dropped-Params too.
	streamPayload := `{"model":"p5-fallback","stream":true,"messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"ping","parameters":{"type":"object"}}}]}`
	reqStream := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(streamPayload))
	reqStream.Header.Set("Authorization", "Bearer "+h.rawKey)
	reqStream.Header.Set("Content-Type", "application/json")
	recStream := httptest.NewRecorder()
	h.gw.Handler().ServeHTTP(recStream, reqStream)
	require.Equal(t, http.StatusOK, recStream.Code)
	assert.Equal(t, "dep-ok-node", recStream.Header().Get("X-Gateway-Deployment-Id"))
	assert.Contains(t, recStream.Header().Get("X-Gateway-Dropped-Params"), "tools")
}
