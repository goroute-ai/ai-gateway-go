package server_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"nhooyr.io/websocket"
)

func TestRoutingHardening_PriorityClampingAndRoutingTagAllowlistsAcrossEndpoints(t *testing.T) {
	h := newRoutingHarness(t, func(cfg *config.Config) {
		cfg.Router.Scheduler.Enabled = true
		cfg.Router.Scheduler.MaxQueueDepth = 10
	})
	require.NoError(t, h.repo.SetOrgProviderSubscription(h.ctx, &domain.OrgProviderSubscription{
		OrgID:     h.org.ID,
		Provider:  domain.ProviderAnthropic,
		IsEnabled: true,
	}))

	var depProdEastHits atomic.Int32
	srvProdEast := mockOpenAIChatServer(t, "prod-east", &depProdEastHits)
	defer srvProdEast.Close()

	var depStagingHits atomic.Int32
	srvStaging := mockOpenAIChatServer(t, "staging", &depStagingHits)
	defer srvStaging.Close()

	var anthHits atomic.Int32
	srvAnth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		anthHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"id":"msg_1","type":"message","role":"assistant","model":"claude-test","content":[{"type":"text","text":"ok"}],"stop_reason":"end_turn","usage":{"input_tokens":5,"output_tokens":3}}`)
	}))
	defer srvAnth.Close()

	credEast := h.createOpenAICredential("east-cred", srvProdEast.URL)
	credStaging := h.createOpenAICredential("staging-cred", srvStaging.URL)
	anthCredBody, _ := json.Marshal(map[string]any{
		"org_id":   h.org.ID,
		"provider": "anthropic",
		"name":     "anth-cred",
		"base_url": srvAnth.URL,
		"api_key":  "sk-ant-test",
	})
	anthCredReq := httptest.NewRequest(http.MethodPost, "/admin/v1/credentials", bytes.NewReader(anthCredBody))
	anthCredReq.Header.Set("Authorization", "Bearer "+h.cfg.Auth.MasterAdminKey)
	anthCredReq.Header.Set("Content-Type", "application/json")
	anthCredRec := httptest.NewRecorder()
	h.gw.Handler().ServeHTTP(anthCredRec, anthCredReq)
	require.Equal(t, http.StatusCreated, anthCredRec.Code)
	var credAnth domain.ProviderCredential
	require.NoError(t, json.Unmarshal(anthCredRec.Body.Bytes(), &credAnth))

	group := &domain.ModelGroup{Alias: "chat-route-test", RoutingStrategy: domain.StrategyWeightedShuffle}
	gm := &domain.GlobalModel{ID: "openai/gpt-4o-mini", Provider: domain.ProviderOpenAI, ModelName: "gpt-4o-mini", LifecycleStatus: domain.ModelStatusActive, MaxInputTokens: 128000, MaxOutputTokens: 4096, SupportsInference: true}
	h.registerModelAndDep(group, gm, credEast, &domain.Deployment{
		DeploymentName: "dep-prod-east",
		Tags:           []string{"prod-east", "fast"},
		Weight:         100,
	})
	h.registerModelAndDep(group, gm, credStaging, &domain.Deployment{
		DeploymentName: "dep-staging",
		Tags:           []string{"staging", "prod-west"},
		Weight:         100,
	})
	h.registerModelAndDep(
		&domain.ModelGroup{Alias: "claude-test", RoutingStrategy: domain.StrategyWeightedShuffle},
		&domain.GlobalModel{ID: "anthropic/claude-test", Provider: domain.ProviderAnthropic, ModelName: "claude-test", LifecycleStatus: domain.ModelStatusActive, MaxInputTokens: 100000, MaxOutputTokens: 4096, SupportsInference: true},
		&credAnth,
		&domain.Deployment{
			DeploymentName: "dep-anth",
			Tags:           []string{"prod-east", "fast"},
			Weight:         100,
		},
	)

	// Create a team via admin API with min_priority_rank=5 and allowed_routing_tags=["prod-*", "fast"].
	teamBody, _ := json.Marshal(map[string]any{
		"org_id":               h.org.ID,
		"name":                 "restricted-team",
		"min_priority_rank":    5,
		"allowed_routing_tags": []string{"prod-*", "fast"},
	})
	teamReq := httptest.NewRequest(http.MethodPost, "/admin/v1/teams", bytes.NewReader(teamBody))
	teamReq.Header.Set("Authorization", "Bearer "+h.cfg.Auth.MasterAdminKey)
	teamReq.Header.Set("Content-Type", "application/json")
	teamRec := httptest.NewRecorder()
	h.gw.Handler().ServeHTTP(teamRec, teamReq)
	require.Equal(t, http.StatusCreated, teamRec.Code, teamRec.Body.String())
	var createdTeam domain.Team
	require.NoError(t, json.Unmarshal(teamRec.Body.Bytes(), &createdTeam))
	assert.Equal(t, 5, createdTeam.MinPriorityRank)
	assert.Equal(t, []string{"prod-*", "fast"}, createdTeam.AllowedRoutingTags)

	// Issue a key inside that team further narrowed to allowed_routing_tags=["prod-east*", "fast"] and min_priority_rank=7.
	keyBody, _ := json.Marshal(map[string]any{
		"org_id":               h.org.ID,
		"team_id":              createdTeam.ID,
		"name":                 "restricted-key",
		"min_priority_rank":    7,
		"allowed_routing_tags": []string{"prod-east*", "fast"},
	})
	keyReq := httptest.NewRequest(http.MethodPost, "/admin/v1/keys", bytes.NewReader(keyBody))
	keyReq.Header.Set("Authorization", "Bearer "+h.cfg.Auth.MasterAdminKey)
	keyReq.Header.Set("Content-Type", "application/json")
	keyRec := httptest.NewRecorder()
	h.gw.Handler().ServeHTTP(keyRec, keyReq)
	require.Equal(t, http.StatusCreated, keyRec.Code, keyRec.Body.String())
	var issuedKey domain.VirtualKey
	require.NoError(t, json.Unmarshal(keyRec.Body.Bytes(), &issuedKey))
	assert.Equal(t, 7, issuedKey.MinPriorityRank)
	assert.Equal(t, []string{"prod-east*", "fast"}, issuedKey.AllowedRoutingTags)

	callEndpoint := func(path string, headers map[string]string, body any) *httptest.ResponseRecorder {
		b, err := json.Marshal(body)
		require.NoError(t, err)
		req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(b))
		req.Header.Set("Authorization", "Bearer "+issuedKey.RawKey)
		req.Header.Set("Content-Type", "application/json")
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		h.gw.Handler().ServeHTTP(rec, req)
		return rec
	}

	// Disallowed tags across all 3 endpoints -> 403 routing_tag_not_allowed (including ! / & operators).
	disallowedCases := []struct {
		name string
		tag  string
	}{
		{name: "not in team or key", tag: "gpu-h100"},
		{name: "in team prod-* but denied by key prod-east*", tag: "prod-west"},
		{name: "denied by team prod-* and key prod-east*", tag: "dev-east"},
		{name: "negation bypass attempt", tag: "!staging"},
		{name: "required bypass attempt", tag: "&prod-west"},
		{name: "wildcard expansion bypass", tag: "*"},
	}
	for _, tc := range disallowedCases {
		t.Run("chat_"+tc.name, func(t *testing.T) {
			rec := callEndpoint("/v1/chat/completions", map[string]string{"X-Gateway-Tags": tc.tag}, map[string]any{
				"model":    "chat-route-test",
				"messages": []map[string]any{{"role": "user", "content": "hi"}},
			})
			require.Equal(t, http.StatusForbidden, rec.Code, rec.Body.String())
			assert.Contains(t, rec.Body.String(), "routing_tag_not_allowed")
		})
	}

	respDenied := callEndpoint("/v1/responses", map[string]string{"X-Gateway-Tags": "prod-west"}, map[string]any{
		"model": "chat-route-test",
		"input": "hello",
	})
	require.Equal(t, http.StatusForbidden, respDenied.Code)
	assert.Contains(t, respDenied.Body.String(), "routing_tag_not_allowed")

	anthDenied := callEndpoint("/v1/messages", map[string]string{"X-Gateway-Tags": "prod-west"}, map[string]any{
		"model":      "claude-test",
		"max_tokens": 16,
		"messages":   []map[string]any{{"role": "user", "content": "hi"}},
	})
	require.Equal(t, http.StatusForbidden, anthDenied.Code)
	assert.Contains(t, anthDenied.Body.String(), "not permitted")

	// Intersection allowed tag ("prod-east" satisfies both "prod-*" and "prod-east*") + spoofed negative priority -> succeeds!
	okChat := callEndpoint("/v1/chat/completions", map[string]string{
		"X-Gateway-Priority": "-10",
		"X-Gateway-Tags":     "&prod-east,fast",
	}, map[string]any{
		"model":    "chat-route-test",
		"messages": []map[string]any{{"role": "user", "content": "hi"}},
	})
	require.Equal(t, http.StatusOK, okChat.Code, okChat.Body.String())
	assert.Equal(t, int32(1), depProdEastHits.Load())
	assert.Equal(t, int32(0), depStagingHits.Load())

	okAnth := callEndpoint("/v1/messages", map[string]string{
		"X-Gateway-Priority": "1",
		"X-Gateway-Tags":     "fast",
	}, map[string]any{
		"model":      "claude-test",
		"max_tokens": 16,
		"messages":   []map[string]any{{"role": "user", "content": "hi"}},
	})
	require.Equal(t, http.StatusOK, okAnth.Code, okAnth.Body.String())
	assert.Equal(t, int32(1), anthHits.Load())
}

func TestRoutingHardening_FallbackBudgetGateRejectsCostlierFallbackHop(t *testing.T) {
	h := newRoutingHarness(t, func(cfg *config.Config) {
		cfg.RateLimit.Enabled = true
	})

	primarySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":{"message":"primary down","type":"server_error"}}`))
	}))
	defer primarySrv.Close()

	var fallbackHits atomic.Int32
	fallbackSrv := mockOpenAIChatServer(t, "expensive-fallback", &fallbackHits)
	defer fallbackSrv.Close()

	credPrimary := h.createOpenAICredential("cheap-cred", primarySrv.URL)
	credExpensive := h.createOpenAICredential("exp-cred", fallbackSrv.URL)

	gmCheap := &domain.GlobalModel{
		ID:                    "openai/cheap-model",
		Provider:              domain.ProviderOpenAI,
		ModelName:             "cheap-model",
		LifecycleStatus:       domain.ModelStatusActive,
		PricingStatus:         domain.PricingStatusVerified,
		SupportsInference:     true,
		MaxInputTokens:        128000,
		MaxOutputTokens:       4096,
		InputCostMicrosPer1M:  100_000, // $0.10 / 1M -> trivial for small prompt
		OutputCostMicrosPer1M: 200_000,
	}
	gmExpensive := &domain.GlobalModel{
		ID:                    "openai/expensive-model",
		Provider:              domain.ProviderOpenAI,
		ModelName:             "expensive-model",
		LifecycleStatus:       domain.ModelStatusActive,
		PricingStatus:         domain.PricingStatusVerified,
		SupportsInference:     true,
		MaxInputTokens:        128000,
		MaxOutputTokens:       4096,
		InputCostMicrosPer1M:  50_000_000_000, // $50k / 1M -> far above key budget
		OutputCostMicrosPer1M: 50_000_000_000,
	}
	require.NoError(t, h.repo.UpsertGlobalModel(h.ctx, gmCheap))
	require.NoError(t, h.repo.UpsertGlobalModel(h.ctx, gmExpensive))

	fbGroup := &domain.ModelGroup{
		ID:              "mg-exp-fb",
		OrgID:           h.org.ID,
		Alias:           "expensive-model",
		RoutingStrategy: domain.StrategyWeightedShuffle,
		IsActive:        true,
	}
	require.NoError(t, h.repo.CreateModelGroup(h.ctx, fbGroup))
	h.registerModelAndDep(fbGroup, gmExpensive, credExpensive, &domain.Deployment{
		DeploymentName: "dep-exp",
		Weight:         100,
	})

	primaryGroup := &domain.ModelGroup{
		ID:               "mg-cheap-primary",
		OrgID:            h.org.ID,
		Alias:            "cheap-model",
		RoutingStrategy:  domain.StrategyWeightedShuffle,
		FallbackGroupIDs: []string{"expensive-model"},
		MaxRetries:       0,
		IsActive:         true,
	}
	require.NoError(t, h.repo.CreateModelGroup(h.ctx, primaryGroup))
	h.registerModelAndDep(primaryGroup, gmCheap, credPrimary, &domain.Deployment{
		DeploymentName: "dep-cheap",
		Weight:         100,
	})

	// Issue key with max budget 1000 micros ($0.001) - enough for cheap primary, far below expensive fallback.
	keyBody, _ := json.Marshal(map[string]any{
		"org_id":            h.org.ID,
		"name":              "tight-budget-key",
		"max_budget_micros": 1000,
	})
	keyReq := httptest.NewRequest(http.MethodPost, "/admin/v1/keys", bytes.NewReader(keyBody))
	keyReq.Header.Set("Authorization", "Bearer "+h.cfg.Auth.MasterAdminKey)
	keyReq.Header.Set("Content-Type", "application/json")
	keyRec := httptest.NewRecorder()
	h.gw.Handler().ServeHTTP(keyRec, keyReq)
	require.Equal(t, http.StatusCreated, keyRec.Code, keyRec.Body.String())
	var budgetKey domain.VirtualKey
	require.NoError(t, json.Unmarshal(keyRec.Body.Bytes(), &budgetKey))

	reqBody, _ := json.Marshal(map[string]any{
		"model":      "cheap-model",
		"max_tokens": 10,
		"messages":   []map[string]any{{"role": "user", "content": "hello"}},
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(reqBody))
	req.Header.Set("Authorization", "Bearer "+budgetKey.RawKey)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.gw.Handler().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusTooManyRequests, rec.Code, rec.Body.String())
	assert.Contains(t, rec.Body.String(), "fallback_budget_exceeded")
	assert.Equal(t, int32(0), fallbackHits.Load(), "costlier fallback upstream must never be invoked")
}

func TestRoutingHardening_GuardrailActionRoute_PinningRBACResponsesAndThrottledAudit(t *testing.T) {
	now := time.Date(2026, 11, 19, 10, 0, 0, 0, time.UTC)
	h := newRoutingHarness(t, nil)
	h.gw.SetNowFunc(func() time.Time { return now })

	var publicHits atomic.Int32
	publicSrv := mockOpenAIChatServer(t, "public-cloud", &publicHits)
	defer publicSrv.Close()

	var privateHits atomic.Int32
	var lastPrivateBody string
	privateSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		privateHits.Add(1)
		b, _ := io.ReadAll(r.Body)
		lastPrivateBody = string(b)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"id":"chatcmpl-priv","object":"chat.completion","created":1700000000,"model":"private-local","choices":[{"index":0,"message":{"role":"assistant","content":"safe local reply"},"finish_reason":"stop"}],"usage":{"prompt_tokens":8,"completion_tokens":4,"total_tokens":12}}`)
	}))
	defer privateSrv.Close()

	credPublic := h.createOpenAICredential("pub-cred", publicSrv.URL)
	credPrivate := h.createOpenAICredential("priv-cred", privateSrv.URL)
	gmPub := &domain.GlobalModel{ID: "openai/public-cloud", Provider: domain.ProviderOpenAI, ModelName: "public-cloud", LifecycleStatus: domain.ModelStatusActive, SupportsInference: true, MaxInputTokens: 128000, MaxOutputTokens: 4096}
	gmPriv := &domain.GlobalModel{ID: "openai/private-local", Provider: domain.ProviderOpenAI, ModelName: "private-local", LifecycleStatus: domain.ModelStatusActive, SupportsInference: true, MaxInputTokens: 128000, MaxOutputTokens: 4096}
	h.registerModelAndDep(&domain.ModelGroup{Alias: "public-cloud", RoutingStrategy: domain.StrategyWeightedShuffle}, gmPub, credPublic, &domain.Deployment{DeploymentName: "dep-pub", Weight: 100})
	h.registerModelAndDep(&domain.ModelGroup{Alias: "private-local", RoutingStrategy: domain.StrategyWeightedShuffle}, gmPriv, credPrivate, &domain.Deployment{DeploymentName: "dep-priv", Weight: 100})

	// Configure guardrail policy via admin API: PII -> route to "private-local".
	polBody, _ := json.Marshal(map[string]any{
		"enable_pii_detection":   true,
		"pii_action":             "route",
		"sensitive_route_target": "private-local",
	})
	polReq := httptest.NewRequest(http.MethodPost, "/admin/v1/organizations/"+h.org.ID+"/guardrails", bytes.NewReader(polBody))
	polReq.Header.Set("Authorization", "Bearer "+h.cfg.Auth.MasterAdminKey)
	polReq.Header.Set("Content-Type", "application/json")
	polRec := httptest.NewRecorder()
	h.gw.Handler().ServeHTTP(polRec, polReq)
	require.Equal(t, http.StatusOK, polRec.Code, polRec.Body.String())

	// Turn 1: Contains PII + session header -> re-routed to private-local without redacting PII!
	rec1 := h.doRequest(http.MethodPost, "/v1/chat/completions", map[string]string{
		"X-Gateway-Session-Id": "sess-pii-1",
	}, map[string]any{
		"model":    "public-cloud",
		"messages": []map[string]any{{"role": "user", "content": "Customer email is alice@example.com"}},
	})
	require.Equal(t, http.StatusOK, rec1.Code, rec1.Body.String())
	assert.Equal(t, "route", rec1.Header().Get("X-Gateway-Guardrail-Action"))
	assert.Equal(t, "private-local", rec1.Header().Get("X-Gateway-Sensitive-Route"))
	assert.Equal(t, int32(0), publicHits.Load())
	assert.Equal(t, int32(1), privateHits.Load())
	assert.Contains(t, lastPrivateBody, "alice@example.com")

	// Turn 2: Same session without PII stays pinned to private-local!
	rec2 := h.doRequest(http.MethodPost, "/v1/chat/completions", map[string]string{
		"X-Gateway-Session-Id": "sess-pii-1",
	}, map[string]any{
		"model":    "public-cloud",
		"messages": []map[string]any{{"role": "user", "content": "Summarize that customer note."}},
	})
	require.Equal(t, http.StatusOK, rec2.Code, rec2.Body.String())
	assert.Equal(t, "private-local", rec2.Header().Get("X-Gateway-Sensitive-Route"))
	assert.Equal(t, int32(2), privateHits.Load())
	assert.Equal(t, int32(0), publicHits.Load())

	// Also verify /v1/responses applies guardrail routing & charges routed model.
	respRec := h.doRequest(http.MethodPost, "/v1/responses", nil, map[string]any{
		"model": "public-cloud",
		"input": "Send receipt to bob@example.com",
	})
	require.Equal(t, http.StatusOK, respRec.Code, respRec.Body.String())
	assert.Equal(t, "private-local", respRec.Header().Get("X-Gateway-Sensitive-Route"))
	assert.Equal(t, int32(3), privateHits.Load())

	// Throttled audit log verification: bursts inside 60s suppress repeated rows; next event after 60s reports suppressed_count!
	for i := 0; i < 3; i++ {
		r := h.doRequest(http.MethodPost, "/v1/chat/completions", nil, map[string]any{
			"model":    "public-cloud",
			"messages": []map[string]any{{"role": "user", "content": "Email carol@example.com"}},
		})
		require.Equal(t, http.StatusOK, r.Code)
	}
	logs1, err := h.repo.ListAuditLogs(h.ctx, h.org.ID, 50)
	require.NoError(t, err)
	routedCount := 0
	for _, l := range logs1 {
		if l.Action == "guardrail.routed" {
			routedCount++
		}
	}
	assert.Equal(t, 1, routedCount, "expected only 1 guardrail.routed audit log within 60s window")

	// Advance clock by 65s and send one more PII request -> new audit log emits suppressed_count=5.
	now = now.Add(65 * time.Second)
	rAfter := h.doRequest(http.MethodPost, "/v1/chat/completions", nil, map[string]any{
		"model":    "public-cloud",
		"messages": []map[string]any{{"role": "user", "content": "Email dave@example.com"}},
	})
	require.Equal(t, http.StatusOK, rAfter.Code)
	logs2, err := h.repo.ListAuditLogs(h.ctx, h.org.ID, 50)
	require.NoError(t, err)
	var latestSuppressed int
	routedCount = 0
	for _, l := range logs2 {
		if l.Action == "guardrail.routed" {
			routedCount++
			if v, ok := l.Details["suppressed_count"].(int); ok && v > latestSuppressed {
				latestSuppressed = v
			}
		}
	}
	assert.Equal(t, 2, routedCount)
	assert.Equal(t, 5, latestSuppressed)

	// RBAC check: key not permitted to access "private-local" gets 403 and privateSrv receives no call.
	rbacKeyBody, _ := json.Marshal(map[string]any{
		"org_id":         h.org.ID,
		"name":           "public-only-key",
		"allowed_models": []string{"public-cloud"},
	})
	rkReq := httptest.NewRequest(http.MethodPost, "/admin/v1/keys", bytes.NewReader(rbacKeyBody))
	rkReq.Header.Set("Authorization", "Bearer "+h.cfg.Auth.MasterAdminKey)
	rkReq.Header.Set("Content-Type", "application/json")
	rkRec := httptest.NewRecorder()
	h.gw.Handler().ServeHTTP(rkRec, rkReq)
	require.Equal(t, http.StatusCreated, rkRec.Code)
	var pubOnlyKey domain.VirtualKey
	require.NoError(t, json.Unmarshal(rkRec.Body.Bytes(), &pubOnlyKey))

	privCallsBefore := privateHits.Load()
	blockedReqBody, _ := json.Marshal(map[string]any{
		"model":    "public-cloud",
		"messages": []map[string]any{{"role": "user", "content": "Contact eve@example.com"}},
	})
	blockedReq := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(blockedReqBody))
	blockedReq.Header.Set("Authorization", "Bearer "+pubOnlyKey.RawKey)
	blockedReq.Header.Set("Content-Type", "application/json")
	blockedRec := httptest.NewRecorder()
	h.gw.Handler().ServeHTTP(blockedRec, blockedReq)
	assert.Equal(t, http.StatusForbidden, blockedRec.Code, blockedRec.Body.String())
	assert.Equal(t, privCallsBefore, privateHits.Load())
}

func TestRoutingHardening_AdminValidationAndUpdateEndpoints(t *testing.T) {
	h := newRoutingHarness(t, nil)

	adminJSON := func(method, path string, body any) *httptest.ResponseRecorder {
		b, _ := json.Marshal(body)
		req := httptest.NewRequest(method, path, bytes.NewReader(b))
		req.Header.Set("Authorization", "Bearer "+h.cfg.Auth.MasterAdminKey)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.gw.Handler().ServeHTTP(rec, req)
		return rec
	}

	// Guardrail policy rejects route action without sensitive_route_target and unknown actions.
	rec := adminJSON(http.MethodPost, "/admin/v1/organizations/"+h.org.ID+"/guardrails", map[string]any{
		"enable_pii_detection": true,
		"pii_action":           "route",
	})
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	recBadAction := adminJSON(http.MethodPost, "/admin/v1/organizations/"+h.org.ID+"/guardrails", map[string]any{
		"enable_prompt_injection": true,
		"prompt_injection_action": "route",
	})
	assert.Equal(t, http.StatusBadRequest, recBadAction.Code)

	// Guardrail definition create/update/patch preserves sensitive_route_target.
	defCreate := adminJSON(http.MethodPost, "/admin/v1/organizations/"+h.org.ID+"/guardrail-definitions", map[string]any{
		"name":                   "pii-router",
		"provider":               "local",
		"sensitive_route_target": "private-local",
	})
	require.Equal(t, http.StatusCreated, defCreate.Code, defCreate.Body.String())
	var createdDef struct {
		ID                   string `json:"id"`
		SensitiveRouteTarget string `json:"sensitive_route_target"`
	}
	require.NoError(t, json.Unmarshal(defCreate.Body.Bytes(), &createdDef))
	assert.Equal(t, "private-local", createdDef.SensitiveRouteTarget)

	defPatch := adminJSON(http.MethodPatch, "/admin/v1/guardrail-definitions/"+createdDef.ID, map[string]any{
		"sensitive_route_target": "sovereign-vllm",
	})
	require.Equal(t, http.StatusOK, defPatch.Code, defPatch.Body.String())
	assert.Contains(t, defPatch.Body.String(), "sovereign-vllm")

	// Team & key create/update reject negative min_priority_rank and persist positive values.
	badTeam := adminJSON(http.MethodPost, "/admin/v1/teams", map[string]any{
		"org_id":            h.org.ID,
		"name":              "bad-prio-team",
		"min_priority_rank": -1,
	})
	assert.Equal(t, http.StatusBadRequest, badTeam.Code)

	okTeam := adminJSON(http.MethodPost, "/admin/v1/teams", map[string]any{
		"org_id":               h.org.ID,
		"name":                 "good-prio-team",
		"min_priority_rank":    3,
		"allowed_routing_tags": []string{" tier-a ", ""},
	})
	require.Equal(t, http.StatusCreated, okTeam.Code)
	var tm domain.Team
	require.NoError(t, json.Unmarshal(okTeam.Body.Bytes(), &tm))
	assert.Equal(t, []string{"tier-a"}, tm.AllowedRoutingTags)

	updTeam := adminJSON(http.MethodPut, "/admin/v1/teams/"+tm.ID, map[string]any{
		"min_priority_rank":    9,
		"allowed_routing_tags": []string{"prod-*"},
	})
	require.Equal(t, http.StatusOK, updTeam.Code, updTeam.Body.String())
	var tm2 domain.Team
	require.NoError(t, json.Unmarshal(updTeam.Body.Bytes(), &tm2))
	assert.Equal(t, 9, tm2.MinPriorityRank)
	assert.Equal(t, []string{"prod-*"}, tm2.AllowedRoutingTags)

	// Virtual key update validates min_priority_rank and persists allowed_routing_tags.
	updKey := adminJSON(http.MethodPut, "/admin/v1/keys/"+issuedIDFromOrg(t, h), map[string]any{
		"min_priority_rank":    4,
		"allowed_routing_tags": []string{"fast-*"},
	})
	require.Equal(t, http.StatusOK, updKey.Code, updKey.Body.String())
	assert.Contains(t, updKey.Body.String(), `"min_priority_rank":4`)
	assert.Contains(t, updKey.Body.String(), `"fast-*"`)
}

func TestRoutingHardening_NonChatGuardrailActionRouteAndCredentialAutoResolve(t *testing.T) {
	h := newRoutingHarness(t, nil)

	var privateHits, publicHits atomic.Int32
	privateSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		privateHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "embeddings") {
			_, _ = w.Write([]byte(`{"object":"list","data":[{"object":"embedding","index":0,"embedding":[0.1,0.2]}],"model":"private-local","usage":{"prompt_tokens":3,"total_tokens":3}}`))
			return
		}
		_, _ = w.Write([]byte(`{"id":"c1","object":"text_completion","model":"private-local","choices":[{"text":"safe-ok","index":0,"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":2,"total_tokens":5}}`))
	}))
	defer privateSrv.Close()

	publicSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		publicHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"object":"list","data":[{"object":"embedding","index":0,"embedding":[0.9]}],"model":"public-cloud","usage":{"prompt_tokens":3,"total_tokens":3}}`))
	}))
	defer publicSrv.Close()

	privCred := h.createOpenAICredential("priv", privateSrv.URL)
	pubCred := h.createOpenAICredential("pub", publicSrv.URL)

	privMG := &domain.ModelGroup{ID: "mg-priv-nc", OrgID: h.org.ID, Alias: "private-local", RoutingStrategy: domain.StrategyWeightedShuffle, IsActive: true}
	pubMG := &domain.ModelGroup{ID: "mg-pub-nc", OrgID: h.org.ID, Alias: "public-cloud", RoutingStrategy: domain.StrategyWeightedShuffle, IsActive: true}
	require.NoError(t, h.repo.CreateModelGroup(h.ctx, privMG))
	require.NoError(t, h.repo.CreateModelGroup(h.ctx, pubMG))

	mPriv := &domain.GlobalModel{
		ID: "openai/private-local", Provider: domain.ProviderOpenAI, ModelName: "private-local",
		SupportsInference: true, Capabilities: domain.ModelCapabilities{Embeddings: domain.CapabilitySupported, Streaming: domain.CapabilitySupported},
	}
	mPub := &domain.GlobalModel{
		ID: "openai/public-cloud", Provider: domain.ProviderOpenAI, ModelName: "public-cloud",
		SupportsInference: true, Capabilities: domain.ModelCapabilities{Embeddings: domain.CapabilitySupported, Streaming: domain.CapabilitySupported},
	}
	require.NoError(t, h.repo.UpsertGlobalModel(h.ctx, mPriv))
	require.NoError(t, h.repo.UpsertGlobalModel(h.ctx, mPub))

	require.NoError(t, h.repo.CreateDeployment(h.ctx, &domain.Deployment{
		ID: "dep-priv-nc", ModelGroupID: privMG.ID, GlobalModelID: mPriv.ID, CredentialID: privCred.ID,
		Weight: 100, Priority: 1, Status: domain.DeploymentStatusActive, GlobalModel: mPriv,
	}))
	require.NoError(t, h.repo.CreateDeployment(h.ctx, &domain.Deployment{
		ID: "dep-pub-nc", ModelGroupID: pubMG.ID, GlobalModelID: mPub.ID, CredentialID: pubCred.ID,
		Weight: 100, Priority: 1, Status: domain.DeploymentStatusActive, GlobalModel: mPub,
	}))

	polBody, _ := json.Marshal(map[string]any{
		"enable_pii_detection":   true,
		"pii_action":             "route",
		"sensitive_route_target": "private-local",
	})
	polReq := httptest.NewRequest(http.MethodPost, "/admin/v1/organizations/"+h.org.ID+"/guardrails", bytes.NewReader(polBody))
	polReq.Header.Set("Authorization", "Bearer "+h.cfg.Auth.MasterAdminKey)
	polReq.Header.Set("Content-Type", "application/json")
	polRec := httptest.NewRecorder()
	h.gw.Handler().ServeHTTP(polRec, polReq)
	require.Equal(t, http.StatusOK, polRec.Code)

	// 1. /v1/embeddings with PII routes to private-local and emits routing headers.
	embReq := httptest.NewRequest(http.MethodPost, "/v1/embeddings", strings.NewReader(`{"model":"public-cloud","input":"Contact alice@example.com for details"}`))
	embReq.Header.Set("Authorization", "Bearer "+h.rawKey)
	embReq.Header.Set("Content-Type", "application/json")
	embRec := httptest.NewRecorder()
	h.gw.Handler().ServeHTTP(embRec, embReq)
	require.Equal(t, http.StatusOK, embRec.Code, embRec.Body.String())
	assert.Equal(t, "route", embRec.Header().Get("X-Gateway-Guardrail-Action"))
	assert.Equal(t, "private-local", embRec.Header().Get("X-Gateway-Sensitive-Route"))
	assert.Equal(t, int32(1), privateHits.Load())
	assert.Equal(t, int32(0), publicHits.Load())

	// 2. /v1/completions with PII also routes to private-local and sets route headers.
	cmpReq := httptest.NewRequest(http.MethodPost, "/v1/completions", strings.NewReader(`{"model":"public-cloud","prompt":"Contact bob@example.com"}`))
	cmpReq.Header.Set("Authorization", "Bearer "+h.rawKey)
	cmpReq.Header.Set("Content-Type", "application/json")
	cmpRec := httptest.NewRecorder()
	h.gw.Handler().ServeHTTP(cmpRec, cmpReq)
	require.Equal(t, http.StatusOK, cmpRec.Code, cmpRec.Body.String())
	assert.Equal(t, "route", cmpRec.Header().Get("X-Gateway-Guardrail-Action"))
	assert.Equal(t, "private-local", cmpRec.Header().Get("X-Gateway-Sensitive-Route"))
	assert.Equal(t, int32(2), privateHits.Load())
	assert.Equal(t, int32(0), publicHits.Load())

	// 3. Deployment creation: multiple OpenAI credentials -> 400 ambiguous_provider_credential when credential_id omitted.
	ambBody, _ := json.Marshal(map[string]any{
		"model_group_id":  privMG.ID,
		"global_model_id": mPriv.ID,
		"deployment_name": "ambiguous-dep",
	})
	ambReq := httptest.NewRequest(http.MethodPost, "/admin/v1/deployments", bytes.NewReader(ambBody))
	ambReq.Header.Set("Authorization", "Bearer "+h.cfg.Auth.MasterAdminKey)
	ambReq.Header.Set("Content-Type", "application/json")
	ambRec := httptest.NewRecorder()
	h.gw.Handler().ServeHTTP(ambRec, ambReq)
	assert.Equal(t, http.StatusBadRequest, ambRec.Code)
	assert.Contains(t, ambRec.Body.String(), "ambiguous_provider_credential")

	// Single active credential for Anthropic auto-resolves cleanly & records org_id in deployment.created audit log.
	antCredBody, _ := json.Marshal(map[string]any{
		"org_id":   h.org.ID,
		"provider": "anthropic",
		"name":     "single-ant-cred",
		"api_key":  "sk-ant-test-key",
	})
	acReq := httptest.NewRequest(http.MethodPost, "/admin/v1/credentials", bytes.NewReader(antCredBody))
	acReq.Header.Set("Authorization", "Bearer "+h.cfg.Auth.MasterAdminKey)
	acReq.Header.Set("Content-Type", "application/json")
	acRec := httptest.NewRecorder()
	h.gw.Handler().ServeHTTP(acRec, acReq)
	require.Equal(t, http.StatusCreated, acRec.Code)
	var antCred domain.ProviderCredential
	require.NoError(t, json.Unmarshal(acRec.Body.Bytes(), &antCred))

	mAnt := &domain.GlobalModel{ID: "anthropic/claude-3-5-haiku-latest", Provider: domain.ProviderAnthropic, ModelName: "claude-3-5-haiku-latest", SupportsInference: true}
	require.NoError(t, h.repo.UpsertGlobalModel(h.ctx, mAnt))

	autoDepBody, _ := json.Marshal(map[string]any{
		"model_group_id":  privMG.ID,
		"global_model_id": mAnt.ID,
		"deployment_name": "auto-resolved-ant",
	})
	autoReq := httptest.NewRequest(http.MethodPost, "/admin/v1/deployments", bytes.NewReader(autoDepBody))
	autoReq.Header.Set("Authorization", "Bearer "+h.cfg.Auth.MasterAdminKey)
	autoReq.Header.Set("Content-Type", "application/json")
	autoRec := httptest.NewRecorder()
	h.gw.Handler().ServeHTTP(autoRec, autoReq)
	require.Equal(t, http.StatusCreated, autoRec.Code, autoRec.Body.String())
	var createdDep domain.Deployment
	require.NoError(t, json.Unmarshal(autoRec.Body.Bytes(), &createdDep))
	assert.Equal(t, antCred.ID, createdDep.CredentialID)

	logs, err := h.repo.ListAuditLogs(h.ctx, h.org.ID, 50)
	require.NoError(t, err)
	foundDepAudit := false
	for _, lg := range logs {
		if lg != nil && lg.Action == "deployment.created" && lg.ResourceID == createdDep.ID {
			foundDepAudit = true
			break
		}
	}
	assert.True(t, foundDepAudit, "deployment.created audit log must carry targetOrgID")
}

func TestNonChatEndpoints_EnforceRoutingHintsAndEmitTelemetry(t *testing.T) {
	h := newRoutingHarness(t, nil)

	restrictedKeyBody, _ := json.Marshal(map[string]any{
		"org_id":               h.org.ID,
		"name":                 "nonchat-restricted-key",
		"min_priority_rank":    2,
		"allowed_routing_tags": []string{"tier:public"},
	})
	rkReq := httptest.NewRequest(http.MethodPost, "/admin/v1/keys", bytes.NewReader(restrictedKeyBody))
	rkReq.Header.Set("Authorization", "Bearer "+h.cfg.Auth.MasterAdminKey)
	rkReq.Header.Set("Content-Type", "application/json")
	rkRec := httptest.NewRecorder()
	h.gw.Handler().ServeHTTP(rkRec, rkReq)
	require.Equal(t, http.StatusCreated, rkRec.Code)
	var rk domain.VirtualKey
	require.NoError(t, json.Unmarshal(rkRec.Body.Bytes(), &rk))

	// Disallowed tag in header or body must return 403 across non-chat & legacy completions endpoints.
	for _, tc := range []struct {
		path string
		body string
	}{
		{`/v1/completions`, `{"model":"gpt-4o-mini","prompt":"hello","goroute_extensions":{"tags":["tier:vip"]}}`},
		{`/v1/embeddings`, `{"model":"text-embedding-3-small","input":"hello","goroute_extensions":{"tags":["tier:vip"]}}`},
		{`/v1/moderations`, `{"model":"omni-moderation-latest","input":"hello","goroute_extensions":{"tags":["tier:vip"]}}`},
		{`/v1/images/generations`, `{"model":"dall-e-3","prompt":"a cat","goroute_extensions":{"tags":["tier:vip"]}}`},
		{`/v1/audio/speech`, `{"model":"tts-1","input":"hello","voice":"alloy","goroute_extensions":{"tags":["tier:vip"]}}`},
	} {
		req := httptest.NewRequest(http.MethodPost, tc.path, strings.NewReader(tc.body))
		req.Header.Set("Authorization", "Bearer "+rk.RawKey)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		h.gw.Handler().ServeHTTP(rec, req)
		assert.Equal(t, http.StatusForbidden, rec.Code, "path=%s body=%s", tc.path, rec.Body.String())
		assert.Contains(t, rec.Body.String(), "routing_tag_not_allowed")
	}

	// Header-only disallowed tag also blocked even without JSON body extensions.
	hdrReq := httptest.NewRequest(http.MethodPost, "/v1/embeddings", strings.NewReader(`{"model":"text-embedding-3-small","input":"hello"}`))
	hdrReq.Header.Set("Authorization", "Bearer "+rk.RawKey)
	hdrReq.Header.Set("Content-Type", "application/json")
	hdrReq.Header.Set("X-Gateway-Tags", "tier:vip")
	hdrRec := httptest.NewRecorder()
	h.gw.Handler().ServeHTTP(hdrRec, hdrReq)
	assert.Equal(t, http.StatusForbidden, hdrRec.Code)
}

func issuedIDFromOrg(t *testing.T, h *routingTestHarness) string {
	t.Helper()
	keys, err := h.repo.ListVirtualKeys(h.ctx, h.org.ID)
	require.NoError(t, err)
	require.NotEmpty(t, keys)
	return keys[0].ID
}

func TestBatchAndRealtime_GuardrailActionRouteAndRoutingHints(t *testing.T) {
	h := newRoutingHarness(t, nil)

	var privateHits, publicHits atomic.Int32
	privateSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		privateHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"chat-priv","object":"chat.completion","model":"private-local","choices":[{"index":0,"message":{"role":"assistant","content":"private-ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":5,"completion_tokens":3,"total_tokens":8}}`))
	}))
	defer privateSrv.Close()

	publicSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		publicHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"chat-pub","object":"chat.completion","model":"public-cloud","choices":[{"index":0,"message":{"role":"assistant","content":"public-ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":5,"completion_tokens":3,"total_tokens":8}}`))
	}))
	defer publicSrv.Close()

	privCred := h.createOpenAICredential("priv-br", privateSrv.URL)
	pubCred := h.createOpenAICredential("pub-br", publicSrv.URL)

	privMG := &domain.ModelGroup{ID: "mg-priv-br", OrgID: h.org.ID, Alias: "private-local", RoutingStrategy: domain.StrategyWeightedShuffle, IsActive: true}
	pubMG := &domain.ModelGroup{ID: "mg-pub-br", OrgID: h.org.ID, Alias: "public-cloud", RoutingStrategy: domain.StrategyWeightedShuffle, IsActive: true}
	require.NoError(t, h.repo.CreateModelGroup(h.ctx, privMG))
	require.NoError(t, h.repo.CreateModelGroup(h.ctx, pubMG))
	mPriv := &domain.GlobalModel{
		ID: "openai/priv-br", Provider: domain.ProviderOpenAI, ModelName: "gpt-4o-mini",
		SupportsInference: true, Capabilities: domain.ModelCapabilities{Streaming: domain.CapabilitySupported},
	}
	mPub := &domain.GlobalModel{
		ID: "openai/pub-br", Provider: domain.ProviderOpenAI, ModelName: "gpt-4o-mini",
		SupportsInference: true, Capabilities: domain.ModelCapabilities{Streaming: domain.CapabilitySupported},
	}
	require.NoError(t, h.repo.UpsertGlobalModel(h.ctx, mPriv))
	require.NoError(t, h.repo.UpsertGlobalModel(h.ctx, mPub))
	require.NoError(t, h.repo.CreateDeployment(h.ctx, &domain.Deployment{
		ID: "dep-priv-br", ModelGroupID: privMG.ID, GlobalModelID: mPriv.ID, CredentialID: privCred.ID,
		Weight: 100, Priority: 1, Status: domain.DeploymentStatusActive, GlobalModel: mPriv,
		Tags: []string{"tier:public"},
	}))
	require.NoError(t, h.repo.CreateDeployment(h.ctx, &domain.Deployment{
		ID: "dep-pub-br", ModelGroupID: pubMG.ID, GlobalModelID: mPub.ID, CredentialID: pubCred.ID,
		Weight: 100, Priority: 1, Status: domain.DeploymentStatusActive, GlobalModel: mPub,
		Tags: []string{"tier:public"},
	}))

	polReq := httptest.NewRequest(http.MethodPost, "/admin/v1/organizations/"+h.org.ID+"/guardrails", strings.NewReader(`{"enable_pii_detection":true,"pii_action":"route","sensitive_route_target":"private-local"}`))
	polReq.Header.Set("Authorization", "Bearer "+h.cfg.Auth.MasterAdminKey)
	polReq.Header.Set("Content-Type", "application/json")
	polRec := httptest.NewRecorder()
	h.gw.Handler().ServeHTTP(polRec, polReq)
	require.Equal(t, http.StatusOK, polRec.Code, polRec.Body.String())

	// Issue a restricted key allowed to use tier:public and both models.
	keyBody, _ := json.Marshal(map[string]any{
		"org_id":               h.org.ID,
		"name":                 "batch-rt-key",
		"allowed_routing_tags": []string{"tier:public"},
		"allowed_models":       []string{"public-cloud", "private-local"},
	})
	kReq := httptest.NewRequest(http.MethodPost, "/admin/v1/keys", bytes.NewReader(keyBody))
	kReq.Header.Set("Authorization", "Bearer "+h.cfg.Auth.MasterAdminKey)
	kReq.Header.Set("Content-Type", "application/json")
	kRec := httptest.NewRecorder()
	h.gw.Handler().ServeHTTP(kRec, kReq)
	require.Equal(t, http.StatusCreated, kRec.Code, kRec.Body.String())
	var vk domain.VirtualKey
	require.NoError(t, json.Unmarshal(kRec.Body.Bytes(), &vk))

	// 1. Batch upload + execution:
	// - b1: clean public-cloud -> publicSrv
	// - b2: PII -> GuardrailActionRoute -> privateSrv
	// - b3: disallowed routing tag -> failed with routing_tag_not_allowed
	jsonl := strings.Join([]string{
		`{"custom_id":"b1","method":"POST","url":"/v1/chat/completions","body":{"model":"public-cloud","messages":[{"role":"user","content":"hello public"}]}}`,
		`{"custom_id":"b2","method":"POST","url":"/v1/chat/completions","body":{"model":"public-cloud","messages":[{"role":"user","content":"reach me at alice@example.com"}]}}`,
		`{"custom_id":"b3","method":"POST","url":"/v1/chat/completions","body":{"model":"public-cloud","messages":[{"role":"user","content":"vip attempt"}],"goroute_extensions":{"tags":["tier:vip"]}}}`,
	}, "\n") + "\n"

	var mpBuf bytes.Buffer
	mw := multipart.NewWriter(&mpBuf)
	_ = mw.WriteField("purpose", "batch")
	fw, err := mw.CreateFormFile("file", "batch.jsonl")
	require.NoError(t, err)
	_, _ = fw.Write([]byte(jsonl))
	require.NoError(t, mw.Close())

	upReq := httptest.NewRequest(http.MethodPost, "/v1/files", &mpBuf)
	upReq.Header.Set("Authorization", "Bearer "+vk.RawKey)
	upReq.Header.Set("Content-Type", mw.FormDataContentType())
	upRec := httptest.NewRecorder()
	h.gw.Handler().ServeHTTP(upRec, upReq)
	require.Equal(t, http.StatusCreated, upRec.Code, upRec.Body.String())
	var fileObj domain.CanonicalFile
	require.NoError(t, json.Unmarshal(upRec.Body.Bytes(), &fileObj))

	batchCreateReq := httptest.NewRequest(http.MethodPost, "/v1/batches", strings.NewReader(fmt.Sprintf(`{"input_file_id":%q,"endpoint":"/v1/chat/completions","completion_window":"24h"}`, fileObj.ID)))
	batchCreateReq.Header.Set("Authorization", "Bearer "+vk.RawKey)
	batchCreateReq.Header.Set("Content-Type", "application/json")
	batchCreateRec := httptest.NewRecorder()
	h.gw.Handler().ServeHTTP(batchCreateRec, batchCreateReq)
	require.Equal(t, http.StatusCreated, batchCreateRec.Code, batchCreateRec.Body.String())
	var createdBatch domain.CanonicalBatch
	require.NoError(t, json.Unmarshal(batchCreateRec.Body.Bytes(), &createdBatch))

	var finalBatch domain.CanonicalBatch
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		getReq := httptest.NewRequest(http.MethodGet, "/v1/batches/"+createdBatch.ID, nil)
		getReq.Header.Set("Authorization", "Bearer "+vk.RawKey)
		getRec := httptest.NewRecorder()
		h.gw.Handler().ServeHTTP(getRec, getReq)
		require.Equal(t, http.StatusOK, getRec.Code)
		require.NoError(t, json.Unmarshal(getRec.Body.Bytes(), &finalBatch))
		if finalBatch.Status == "completed" || finalBatch.Status == "failed" {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	require.Equal(t, "completed", finalBatch.Status)
	require.NotEmpty(t, finalBatch.OutputFileID)

	outReq := httptest.NewRequest(http.MethodGet, "/v1/files/"+finalBatch.OutputFileID+"/content", nil)
	outReq.Header.Set("Authorization", "Bearer "+vk.RawKey)
	outRec := httptest.NewRecorder()
	h.gw.Handler().ServeHTTP(outRec, outReq)
	require.Equal(t, http.StatusOK, outRec.Code)
	outBody := outRec.Body.String()
	assert.Contains(t, outBody, `"custom_id":"b1"`)
	assert.Contains(t, outBody, `"custom_id":"b2"`)
	assert.Contains(t, outBody, `"private-ok"`)
	assert.Contains(t, outBody, `"custom_id":"b3"`)
	assert.Contains(t, outBody, `"routing_tag_not_allowed"`)
	assert.Equal(t, int32(1), publicHits.Load())
	assert.Equal(t, int32(1), privateHits.Load())

	// 2. Realtime WebSocket: upgrade tag rejection + live PII GuardrailActionRoute turn.
	ts := httptest.NewServer(h.gw.Handler())
	defer ts.Close()
	wsBase := "ws" + strings.TrimPrefix(ts.URL, "http")

	badHdr := http.Header{
		"Authorization":  {"Bearer " + vk.RawKey},
		"X-Gateway-Tags": {"tier:vip"},
	}
	_, badResp, dialErr := websocket.Dial(h.ctx, wsBase+"/v1/realtime?model=public-cloud", &websocket.DialOptions{HTTPHeader: badHdr})
	require.Error(t, dialErr)
	if badResp != nil {
		assert.Equal(t, http.StatusForbidden, badResp.StatusCode)
	}

	okHdr := http.Header{"Authorization": {"Bearer " + vk.RawKey}}
	conn, _, err := websocket.Dial(h.ctx, wsBase+"/v1/realtime?model=public-cloud", &websocket.DialOptions{HTTPHeader: okHdr, Subprotocols: []string{"realtime"}})
	require.NoError(t, err)
	defer conn.Close(websocket.StatusNormalClosure, "done")

	_, _, err = conn.Read(h.ctx) // session.created
	require.NoError(t, err)

	// Disallowed turn-level routing tag returns structured Realtime error.
	require.NoError(t, conn.Write(h.ctx, websocket.MessageText, []byte(`{"type":"conversation.item.create","item":{"role":"user","content":[{"type":"input_text","text":"Email me at bob@example.com"}]}}`)))
	_, _, err = conn.Read(h.ctx) // conversation.item.created
	require.NoError(t, err)

	require.NoError(t, conn.Write(h.ctx, websocket.MessageText, []byte(`{"type":"response.create","goroute_extensions":{"tags":["tier:vip"]}}`)))
	_, errFrame, err := conn.Read(h.ctx)
	require.NoError(t, err)
	assert.Contains(t, string(errFrame), `"routing_tag_not_allowed"`)

	// Normal response.create with PII triggers GuardrailActionRoute -> privateSrv!
	require.NoError(t, conn.Write(h.ctx, websocket.MessageText, []byte(`{"type":"response.create"}`)))
	var seenDone bool
	for i := 0; i < 8; i++ {
		_, frame, rErr := conn.Read(h.ctx)
		require.NoError(t, rErr)
		require.NotContains(t, string(frame), `"type":"error"`, "unexpected realtime error frame: %s", string(frame))
		if strings.Contains(string(frame), `"type":"response.done"`) {
			assert.Contains(t, string(frame), "private-ok")
			seenDone = true
			break
		}
	}
	assert.True(t, seenDone, "expected realtime response.done from routed private-local upstream")
	assert.Equal(t, int32(2), privateHits.Load())
}

func TestEmbeddings_SinglePassBatchedGuardrailAudit(t *testing.T) {
	h := newRoutingHarness(t, nil)
	var embedHits atomic.Int32
	openaiSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		embedHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"object":"list","data":[{"object":"embedding","index":0,"embedding":[0.1,0.2]},{"object":"embedding","index":1,"embedding":[0.3,0.4]}],"model":"text-embedding-3-small","usage":{"prompt_tokens":6,"total_tokens":6}}`))
	}))
	defer openaiSrv.Close()

	require.NoError(t, h.repo.SetOrgProviderSubscription(h.ctx, &domain.OrgProviderSubscription{
		OrgID: h.org.ID, Provider: domain.ProviderOpenAI, IsEnabled: true,
	}))
	credB, _ := json.Marshal(map[string]any{
		"org_id": h.org.ID, "provider": "openai", "name": "openai-emb",
		"base_url": openaiSrv.URL, "api_key": "sk-openai-key",
	})
	cReq := httptest.NewRequest(http.MethodPost, "/admin/v1/credentials", bytes.NewReader(credB))
	cReq.Header.Set("Authorization", "Bearer "+h.cfg.Auth.MasterAdminKey)
	cReq.Header.Set("Content-Type", "application/json")
	cRec := httptest.NewRecorder()
	h.gw.Handler().ServeHTTP(cRec, cReq)
	require.Equal(t, http.StatusCreated, cRec.Code, cRec.Body.String())
	var cred domain.ProviderCredential
	require.NoError(t, json.Unmarshal(cRec.Body.Bytes(), &cred))

	privMG := &domain.ModelGroup{ID: "mg-emb-priv", OrgID: h.org.ID, Alias: "private-embed", RoutingStrategy: domain.StrategyWeightedShuffle, IsActive: true}
	pubMG := &domain.ModelGroup{ID: "mg-emb-pub", OrgID: h.org.ID, Alias: "public-embed", RoutingStrategy: domain.StrategyWeightedShuffle, IsActive: true}
	require.NoError(t, h.repo.CreateModelGroup(h.ctx, privMG))
	require.NoError(t, h.repo.CreateModelGroup(h.ctx, pubMG))
	gm := &domain.GlobalModel{
		ID: "openai/text-embedding-3-small", Provider: domain.ProviderOpenAI, ModelName: "text-embedding-3-small",
		SupportsInference: true, Capabilities: domain.ModelCapabilities{Embeddings: domain.CapabilitySupported},
	}
	require.NoError(t, h.repo.UpsertGlobalModel(h.ctx, gm))
	require.NoError(t, h.repo.CreateDeployment(h.ctx, &domain.Deployment{
		ID: "dep-emb-priv", ModelGroupID: privMG.ID, GlobalModelID: gm.ID, CredentialID: cred.ID, Weight: 100, Priority: 1, Status: domain.DeploymentStatusActive, GlobalModel: gm,
	}))
	require.NoError(t, h.repo.CreateDeployment(h.ctx, &domain.Deployment{
		ID: "dep-emb-pub", ModelGroupID: pubMG.ID, GlobalModelID: gm.ID, CredentialID: cred.ID, Weight: 100, Priority: 1, Status: domain.DeploymentStatusActive, GlobalModel: gm,
	}))

	polReq := httptest.NewRequest(http.MethodPost, "/admin/v1/organizations/"+h.org.ID+"/guardrails", strings.NewReader(`{"enable_pii_detection":true,"pii_action":"route","sensitive_route_target":"private-embed"}`))
	polReq.Header.Set("Authorization", "Bearer "+h.cfg.Auth.MasterAdminKey)
	polReq.Header.Set("Content-Type", "application/json")
	polRec := httptest.NewRecorder()
	h.gw.Handler().ServeHTTP(polRec, polReq)
	require.Equal(t, http.StatusOK, polRec.Code, polRec.Body.String())

	reqBody := `{"model":"public-embed","input":["find alice@example.com","doc with bob@example.com and carol@example.com"]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/embeddings", strings.NewReader(reqBody))
	req.Header.Set("Authorization", "Bearer "+h.rawKey)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	h.gw.Handler().ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "private-embed", rec.Header().Get("X-Gateway-Sensitive-Route"))
	assert.Equal(t, int32(1), embedHits.Load())

	logs, err := h.repo.ListAuditLogs(h.ctx, h.org.ID, 50)
	require.NoError(t, err)
	routeAudits := 0
	for _, lg := range logs {
		if lg != nil && lg.Action == "guardrail.routed" && lg.Resource == "embeddings" {
			routeAudits++
		}
	}
	assert.Equal(t, 1, routeAudits, "multi-input /v1/embeddings must emit exactly one guardrail.routed audit log")
}
