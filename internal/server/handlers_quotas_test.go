package server_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/server"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type quotaHandlerTestEnv struct {
	repo       *storage.MemoryRepository
	mr         *miniredis.Miniredis
	gw         *server.GatewayServer
	handler    http.Handler
	masterKey  string
	orgAAdmin  *domain.VirtualKey
	orgAViewer *domain.VirtualKey
	teamA1Adm  *domain.VirtualKey
	orgBAdmin  *domain.VirtualKey
}

func setupQuotaHandlerTestEnv(t *testing.T, upstream http.Handler) *quotaHandlerTestEnv {
	t.Helper()
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	mr := miniredis.RunT(t)
	redisFabric := storage.NewRedisFabric(mr.Addr(), "", 0)
	t.Cleanup(func() { _ = redisFabric.Client().Close() })

	require.NoError(t, repo.CreateOrganization(ctx, &domain.Organization{
		ID:                    "org_a",
		Name:                  "Org A",
		Slug:                  "org-a",
		MaxBudgetMicros:       10_000_000,
		SelfServeBudgetPolicy: domain.SelfServeBudgetDisabled,
		IsActive:              true,
	}))
	require.NoError(t, repo.CreateOrganization(ctx, &domain.Organization{
		ID:              "org_b",
		Name:            "Org B",
		Slug:            "org-b",
		MaxBudgetMicros: 10_000_000,
		IsActive:        true,
	}))

	require.NoError(t, repo.CreateTeam(ctx, &domain.Team{
		ID:              "team_a1",
		OrgID:           "org_a",
		Name:            "Team A1",
		MaxBudgetMicros: 5_000_000,
		IsActive:        true,
	}))
	require.NoError(t, repo.CreateTeam(ctx, &domain.Team{
		ID:       "team_b1",
		OrgID:    "org_b",
		Name:     "Team B1",
		IsActive: true,
	}))

	require.NoError(t, repo.CreateProject(ctx, &domain.Project{
		ID:       "proj_a1",
		OrgID:    "org_a",
		TeamID:   "team_a1",
		Name:     "Project A1",
		IsActive: true,
	}))

	require.NoError(t, repo.CreateUser(ctx, &domain.User{
		ID:       "usr_org_a_adm",
		OrgID:    "org_a",
		Email:    "orgadm@a.example",
		Name:     "Org A Admin",
		Role:     domain.RoleOrgAdmin,
		IsActive: true,
	}))
	require.NoError(t, repo.CreateUser(ctx, &domain.User{
		ID:       "usr_org_a_view",
		OrgID:    "org_a",
		Email:    "orgview@a.example",
		Name:     "Org A Viewer",
		Role:     domain.RoleOrgViewer,
		IsActive: true,
	}))
	require.NoError(t, repo.CreateUser(ctx, &domain.User{
		ID:       "usr_team_a1_adm",
		OrgID:    "org_a",
		TeamID:   "team_a1",
		Email:    "teamadm@a.example",
		Name:     "Team A1 Admin",
		Role:     domain.RoleTeamAdmin,
		IsActive: true,
	}))
	require.NoError(t, repo.CreateUser(ctx, &domain.User{
		ID:       "usr_a1_dev",
		OrgID:    "org_a",
		TeamID:   "team_a1",
		Email:    "dev@a.example",
		Name:     "Dev A1",
		Role:     domain.RoleDeveloper,
		IsActive: true,
	}))
	require.NoError(t, repo.CreateUser(ctx, &domain.User{
		ID:       "usr_org_b_adm",
		OrgID:    "org_b",
		Email:    "orgadm@b.example",
		Name:     "Org B Admin",
		Role:     domain.RoleOrgAdmin,
		IsActive: true,
	}))

	var httpClient *http.Client
	var mockURL string
	if upstream != nil {
		ts := httptest.NewServer(upstream)
		t.Cleanup(ts.Close)
		httpClient = ts.Client()
		mockURL = ts.URL
	}

	cfg := config.Default()
	cfg.Auth.MasterAdminKey = "sk-gw-master-quotas-test"
	cfg.RateLimit.Enabled = true
	cfg.RateLimit.FallbackToLocalOnOutage = false
	cfg.Security.Network.OutboundSSRF.AllowPrivateNetworks = true
	cfg.Security.Network.OutboundSSRF.AllowInsecureHTTP = true

	gw, err := server.New(cfg, repo, redisFabric, httpClient)
	require.NoError(t, err)
	gw.StartWorkers(ctx)
	t.Cleanup(func() { gw.Shutdown(ctx) })

	handler := gw.Handler()

	orgAAdmin, err := gw.AuthService().IssueVirtualKey(ctx, &domain.VirtualKey{
		OrgID: "org_a", UserID: "usr_org_a_adm", Name: "org-a-adm", Role: domain.RoleOrgAdmin,
	})
	require.NoError(t, err)
	orgAViewer, err := gw.AuthService().IssueVirtualKey(ctx, &domain.VirtualKey{
		OrgID: "org_a", UserID: "usr_org_a_view", Name: "org-a-view", Role: domain.RoleOrgViewer,
	})
	require.NoError(t, err)
	teamA1Adm, err := gw.AuthService().IssueVirtualKey(ctx, &domain.VirtualKey{
		OrgID: "org_a", TeamID: "team_a1", UserID: "usr_team_a1_adm", Name: "team-a1-adm", Role: domain.RoleTeamAdmin,
	})
	require.NoError(t, err)
	orgBAdmin, err := gw.AuthService().IssueVirtualKey(ctx, &domain.VirtualKey{
		OrgID: "org_b", UserID: "usr_org_b_adm", Name: "org-b-adm", Role: domain.RoleOrgAdmin,
	})
	require.NoError(t, err)

	if mockURL != "" {
		rec := doAdminJSONRequest(t, handler, http.MethodPost, "/admin/v1/credentials", cfg.Auth.MasterAdminKey, map[string]any{
			"org_id":   "org_a",
			"provider": "openai",
			"name":     "mock-openai",
			"base_url": mockURL,
			"api_key":  "sk-upstream-mock",
		})
		require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
		var cred domain.ProviderCredential
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &cred))

		for _, m := range []struct {
			alias   string
			modelID string
		}{
			{alias: "gpt-4.1", modelID: "openai/gpt-4.1"},
			{alias: "gpt-4.1-mini", modelID: "openai/gpt-4.1-mini"},
		} {
			rec = doAdminJSONRequest(t, handler, http.MethodPost, "/admin/v1/model-groups", cfg.Auth.MasterAdminKey, map[string]any{
				"org_id":           "org_a",
				"alias":            m.alias,
				"routing_strategy": "simple-shuffle",
			})
			require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
			var mg domain.ModelGroup
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &mg))

			rec = doAdminJSONRequest(t, handler, http.MethodPost, "/admin/v1/deployments", cfg.Auth.MasterAdminKey, map[string]any{
				"model_group_id":  mg.ID,
				"global_model_id": m.modelID,
				"credential_id":   cred.ID,
				"weight":          1,
			})
			require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
		}
	}

	return &quotaHandlerTestEnv{
		repo:       repo,
		mr:         mr,
		gw:         gw,
		handler:    handler,
		masterKey:  cfg.Auth.MasterAdminKey,
		orgAAdmin:  orgAAdmin,
		orgAViewer: orgAViewer,
		teamA1Adm:  teamA1Adm,
		orgBAdmin:  orgBAdmin,
	}
}

func TestAdminQuotaAndBudgetWindowEndpoints_CRUDAndRBAC(t *testing.T) {
	env := setupQuotaHandlerTestEnv(t, nil)

	// Unauthenticated requests are rejected with 401.
	for _, tc := range []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/admin/v1/quotas"},
		{http.MethodPut, "/admin/v1/quotas"},
		{http.MethodDelete, "/admin/v1/quotas/p1"},
		{http.MethodGet, "/admin/v1/budget-windows"},
		{http.MethodPut, "/admin/v1/budget-windows"},
		{http.MethodPost, "/admin/v1/keys/" + env.teamA1Adm.ID + "/temp-budget"},
	} {
		rec := doAdminJSONRequest(t, env.handler, tc.method, tc.path, "", nil)
		assert.Equal(t, http.StatusUnauthorized, rec.Code, "%s %s", tc.method, tc.path)
	}

	// team_admin is rejected on org-wide quota, budget-window, and temp-budget routes (403).
	for _, tc := range []struct {
		method string
		path   string
		body   any
	}{
		{http.MethodGet, "/admin/v1/quotas", nil},
		{http.MethodPut, "/admin/v1/quotas", map[string]any{"scope_type": "key", "scope_id": "k1", "rpm_limit": 10}},
		{http.MethodGet, "/admin/v1/budget-windows", nil},
		{http.MethodPut, "/admin/v1/budget-windows", map[string]any{"scope_type": "key", "scope_id": "k1", "window_type": "daily", "max_budget_micros": 100}},
		{http.MethodPost, "/admin/v1/keys/" + env.teamA1Adm.ID + "/temp-budget", map[string]any{"temp_budget_increase_micros": 100, "ttl_seconds": 60}},
	} {
		rec := doAdminJSONRequest(t, env.handler, tc.method, tc.path, env.teamA1Adm.RawKey, tc.body)
		assert.Equal(t, http.StatusForbidden, rec.Code, "%s %s", tc.method, tc.path)
	}

	// org_viewer can GET, but cannot write (403).
	rec := doAdminJSONRequest(t, env.handler, http.MethodGet, "/admin/v1/quotas", env.orgAViewer.RawKey, nil)
	assert.Equal(t, http.StatusOK, rec.Code)
	rec = doAdminJSONRequest(t, env.handler, http.MethodPut, "/admin/v1/quotas", env.orgAViewer.RawKey, map[string]any{
		"scope_type": "model_per_key", "scope_id": env.teamA1Adm.ID, "model_pattern": "gpt-4.1", "itpm_limit": 500,
	})
	assert.Equal(t, http.StatusForbidden, rec.Code)

	// org_admin upserts a quota policy.
	rec = doAdminJSONRequest(t, env.handler, http.MethodPut, "/admin/v1/quotas", env.orgAAdmin.RawKey, map[string]any{
		"scope_type":    "model_per_key",
		"scope_id":      env.teamA1Adm.ID,
		"model_pattern": "gpt-4.1",
		"itpm_limit":    500,
		"otpm_limit":    300,
		"tpd_limit":     5000,
		"rpm_limit":     10,
	})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var pol domain.QuotaPolicy
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &pol))
	assert.Equal(t, "org_a", pol.OrgID)
	assert.Equal(t, domain.QuotaScopeModelPerKey, pol.ScopeType)
	assert.Equal(t, 500, pol.ITPMLimit)
	assert.Equal(t, 300, pol.OTPMLimit)
	assert.Equal(t, int64(5000), pol.TPDLimit)
	assert.True(t, pol.IsActive)

	// org_b admin cannot read, overwrite, or delete org_a's policies.
	rec = doAdminJSONRequest(t, env.handler, http.MethodGet, "/admin/v1/quotas?org_id=org_a", env.orgBAdmin.RawKey, nil)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	rec = doAdminJSONRequest(t, env.handler, http.MethodDelete, "/admin/v1/quotas/"+pol.ID, env.orgBAdmin.RawKey, nil)
	assert.Equal(t, http.StatusForbidden, rec.Code)

	// org_viewer lists the policy.
	rec = doAdminJSONRequest(t, env.handler, http.MethodGet, "/admin/v1/quotas?scope_type=model_per_key&active_only=true", env.orgAViewer.RawKey, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	var listPolResp struct {
		Data []*domain.QuotaPolicy `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &listPolResp))
	require.Len(t, listPolResp.Data, 1)
	assert.Equal(t, pol.ID, listPolResp.Data[0].ID)

	// Upsert & list budget windows.
	for _, wt := range []string{"daily", "weekly", "monthly", "rolling_24h"} {
		rec = doAdminJSONRequest(t, env.handler, http.MethodPut, "/admin/v1/budget-windows", env.orgAAdmin.RawKey, map[string]any{
			"scope_type":        "key",
			"scope_id":          env.teamA1Adm.ID,
			"window_type":       wt,
			"max_budget_micros": 1_000_000,
		})
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	}
	rec = doAdminJSONRequest(t, env.handler, http.MethodGet, "/admin/v1/budget-windows?scope_type=key&scope_id="+env.teamA1Adm.ID, env.orgAViewer.RawKey, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	var listBWResp struct {
		Data []*domain.BudgetWindowLimit `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &listBWResp))
	assert.Len(t, listBWResp.Data, 4)

	// Validation on temp-budget: negative or missing/past expiry -> 400.
	rec = doAdminJSONRequest(t, env.handler, http.MethodPost, "/admin/v1/keys/"+env.teamA1Adm.ID+"/temp-budget", env.orgAAdmin.RawKey, map[string]any{
		"temp_budget_increase_micros": 500_000,
	})
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	rec = doAdminJSONRequest(t, env.handler, http.MethodPost, "/admin/v1/keys/"+env.teamA1Adm.ID+"/temp-budget", env.orgAAdmin.RawKey, map[string]any{
		"temp_budget_increase_micros": 500_000,
		"temp_budget_expires_at":      time.Now().UTC().Add(-1 * time.Minute),
	})
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	// Valid temp-budget boost succeeds, and 0 clears it.
	rec = doAdminJSONRequest(t, env.handler, http.MethodPost, "/admin/v1/keys/"+env.teamA1Adm.ID+"/temp-budget", env.orgAAdmin.RawKey, map[string]any{
		"temp_budget_increase_micros": 500_000,
		"ttl_seconds":                 300,
	})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var boostedVK domain.VirtualKey
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &boostedVK))
	assert.Equal(t, int64(500_000), boostedVK.TempBudgetIncreaseMicros)
	require.NotNil(t, boostedVK.TempBudgetExpiresAt)

	rec = doAdminJSONRequest(t, env.handler, http.MethodPost, "/admin/v1/keys/"+env.teamA1Adm.ID+"/temp-budget", env.orgAAdmin.RawKey, map[string]any{
		"temp_budget_increase_micros": 0,
	})
	require.Equal(t, http.StatusOK, rec.Code)
	var clearedVK domain.VirtualKey
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &clearedVK))
	assert.Equal(t, int64(0), clearedVK.TempBudgetIncreaseMicros)
	assert.Nil(t, clearedVK.TempBudgetExpiresAt)

	// Delete quota policy.
	rec = doAdminJSONRequest(t, env.handler, http.MethodDelete, "/admin/v1/quotas/"+pol.ID, env.orgAAdmin.RawKey, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	rec = doAdminJSONRequest(t, env.handler, http.MethodDelete, "/admin/v1/quotas/"+pol.ID, env.orgAAdmin.RawKey, nil)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestModelScopedITPM_OTPM_TPD_EnforcementAndReconciliation(t *testing.T) {
	var nextPromptTokens atomic.Int64
	var nextCompletionTokens atomic.Int64
	nextPromptTokens.Store(45)
	nextCompletionTokens.Store(10)

	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := nextPromptTokens.Load()
		c := nextCompletionTokens.Load()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":      "chatcmpl-quota-test",
			"object":  "chat.completion",
			"model":   "gpt-4.1",
			"choices": []map[string]any{{"index": 0, "message": map[string]any{"role": "assistant", "content": "ok"}, "finish_reason": "stop"}},
			"usage":   map[string]any{"prompt_tokens": p, "completion_tokens": c, "total_tokens": p + c},
		})
	})

	env := setupQuotaHandlerTestEnv(t, upstream)
	ctx := context.Background()

	devKey, err := env.gw.AuthService().IssueVirtualKey(ctx, &domain.VirtualKey{
		OrgID:     "org_a",
		TeamID:    "team_a1",
		ProjectID: "proj_a1",
		UserID:    "usr_a1_dev",
		Name:      "model-quota-dev",
		Role:      domain.RoleDeveloper,
	})
	require.NoError(t, err)

	callChat := func(model string, maxTokens int) *httptest.ResponseRecorder {
		payload := map[string]any{
			"model":    model,
			"messages": []map[string]string{{"role": "user", "content": "hi"}},
		}
		if maxTokens > 0 {
			payload["max_tokens"] = maxTokens
		}
		raw, _ := json.Marshal(payload)
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(string(raw)))
		req.Header.Set("Authorization", "Bearer "+devKey.RawKey)
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		env.handler.ServeHTTP(rr, req)
		return rr
	}

	// 1. Configure model_per_key ITPM=50, OTPM=40, TPD=120 for gpt-4.1.
	rec := doAdminJSONRequest(t, env.handler, http.MethodPut, "/admin/v1/quotas", env.orgAAdmin.RawKey, map[string]any{
		"scope_type":    "model_per_key",
		"scope_id":      devKey.ID,
		"model_pattern": "gpt-4.1",
		"itpm_limit":    50,
		"otpm_limit":    40,
		"tpd_limit":     120,
	})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	// Also configure model_per_team for gpt-4.1-mini so we verify separate model isolation.
	rec = doAdminJSONRequest(t, env.handler, http.MethodPut, "/admin/v1/quotas", env.orgAAdmin.RawKey, map[string]any{
		"scope_type":    "model_per_team",
		"scope_id":      "team_a1",
		"model_pattern": "gpt-4.1-mini",
		"itpm_limit":    100,
	})
	require.Equal(t, http.StatusOK, rec.Code)

	// Request 1 to gpt-4.1: estimate ~10 input, max_tokens=10 -> upstream returns prompt=45, completion=10.
	// Reconciliation adjusts ITPM from ~10 up to 45!
	rr := callChat("gpt-4.1", 10)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())

	// Request 2 to gpt-4.1 (estInput >= 6): 45 + >=6 > 50 -> rejected with model_per_key_itpm_exceeded.
	rr = callChat("gpt-4.1", 10)
	assert.Equal(t, http.StatusTooManyRequests, rr.Code)
	assert.Contains(t, rr.Body.String(), "model_per_key_itpm_exceeded")

	// Meanwhile gpt-4.1-mini is unaffected by gpt-4.1's ITPM exhaustion!
	rr = callChat("gpt-4.1-mini", 10)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())

	// 2. Test OTPM reconciliation across /v1/messages and /v1/responses on a fresh key.
	otpmKey, err := env.gw.AuthService().IssueVirtualKey(ctx, &domain.VirtualKey{
		OrgID:     "org_a",
		TeamID:    "team_a1",
		ProjectID: "proj_a1",
		UserID:    "usr_a1_dev",
		Name:      "model-otpm-key",
		Role:      domain.RoleDeveloper,
	})
	require.NoError(t, err)

	rec = doAdminJSONRequest(t, env.handler, http.MethodPut, "/admin/v1/quotas", env.orgAAdmin.RawKey, map[string]any{
		"scope_type":    "model_per_project",
		"scope_id":      "proj_a1",
		"model_pattern": "gpt-4.1",
		"otpm_limit":    30,
	})
	require.Equal(t, http.StatusOK, rec.Code)

	// Upstream returns prompt=5, completion=30 -> OTPM reaches 30/30.
	nextPromptTokens.Store(5)
	nextCompletionTokens.Store(30)

	msgReq := httptest.NewRequest(http.MethodPost, "/v1/messages", strings.NewReader(`{"model":"gpt-4.1","max_tokens":15,"messages":[{"role":"user","content":"hi"}]}`))
	msgReq.Header.Set("Authorization", "Bearer "+otpmKey.RawKey)
	msgReq.Header.Set("Content-Type", "application/json")
	msgRR := httptest.NewRecorder()
	env.handler.ServeHTTP(msgRR, msgReq)
	require.Equal(t, http.StatusOK, msgRR.Code, msgRR.Body.String())

	// Subsequent /v1/responses request (even with max_output_tokens=1 or omitted!) fails with model_per_project_otpm_exceeded.
	respReq := httptest.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(`{"model":"gpt-4.1","max_output_tokens":5,"input":"hello"}`))
	respReq.Header.Set("Authorization", "Bearer "+otpmKey.RawKey)
	respReq.Header.Set("Content-Type", "application/json")
	respRR := httptest.NewRecorder()
	env.handler.ServeHTTP(respRR, respReq)
	assert.Equal(t, http.StatusTooManyRequests, respRR.Code)
	assert.Contains(t, respRR.Body.String(), "model_per_project_otpm_exceeded")

	// Also verify omitted max_tokens on chat completions still blocks when OTPM=30/30.
	chatNoMaxReq := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"gpt-4.1","messages":[{"role":"user","content":"hi"}]}`))
	chatNoMaxReq.Header.Set("Authorization", "Bearer "+otpmKey.RawKey)
	chatNoMaxReq.Header.Set("Content-Type", "application/json")
	chatNoMaxRR := httptest.NewRecorder()
	env.handler.ServeHTTP(chatNoMaxRR, chatNoMaxReq)
	assert.Equal(t, http.StatusTooManyRequests, chatNoMaxRR.Code)
	assert.Contains(t, chatNoMaxRR.Body.String(), "model_per_project_otpm_exceeded")

	// 3. Test TPD enforcement on model_per_org (independent of minute ITPM/OTPM).
	tpdKey, err := env.gw.AuthService().IssueVirtualKey(ctx, &domain.VirtualKey{
		OrgID:  "org_a",
		Name:   "model-tpd-key",
		Role:   domain.RoleServiceAccount,
		UserID: "usr_a1_dev",
	})
	require.NoError(t, err)

	rec = doAdminJSONRequest(t, env.handler, http.MethodPut, "/admin/v1/quotas", env.orgAAdmin.RawKey, map[string]any{
		"scope_type":    "model_per_org",
		"scope_id":      "org_a",
		"model_pattern": "gpt-4.1-mini",
		"tpd_limit":     60,
	})
	require.Equal(t, http.StatusOK, rec.Code)

	nextPromptTokens.Store(30)
	nextCompletionTokens.Store(20) // total 50 <= 60
	reqTPD1 := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"gpt-4.1-mini","max_tokens":5,"messages":[{"role":"user","content":"hi"}]}`))
	reqTPD1.Header.Set("Authorization", "Bearer "+tpdKey.RawKey)
	reqTPD1.Header.Set("Content-Type", "application/json")
	rrTPD1 := httptest.NewRecorder()
	env.handler.ServeHTTP(rrTPD1, reqTPD1)
	require.Equal(t, http.StatusOK, rrTPD1.Code, rrTPD1.Body.String())

	// Second request (estTotal >= 15 -> 50 + 15 > 60) must reject with model_per_org_tpd_exceeded.
	reqTPD2 := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"gpt-4.1-mini","max_tokens":10,"messages":[{"role":"user","content":"hi"}]}`))
	reqTPD2.Header.Set("Authorization", "Bearer "+tpdKey.RawKey)
	reqTPD2.Header.Set("Content-Type", "application/json")
	rrTPD2 := httptest.NewRecorder()
	env.handler.ServeHTTP(rrTPD2, reqTPD2)
	assert.Equal(t, http.StatusTooManyRequests, rrTPD2.Code)
	assert.Contains(t, rrTPD2.Body.String(), "model_per_org_tpd_exceeded")
}

func TestMultiWindowBudgetLimits_SimultaneousDailyWeeklyMonthlyRolling24h(t *testing.T) {
	// gpt-4.1 pricing in seeded catalog: input=2M micros/1M, output=8M micros/1M.
	// With prompt=100000, completion=10000 -> cost = 200_000 + 80_000 = 280_000 micros ($0.28).
	// Upper bound for short prompt (~100 bytes) + max_tokens=5000: (100*2M + 5000*8M)/1M = 40_200 micros.
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"chatcmpl-bw","object":"chat.completion","model":"gpt-4.1","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":100000,"completion_tokens":10000,"total_tokens":110000}}`))
	})

	env := setupQuotaHandlerTestEnv(t, upstream)
	ctx := context.Background()

	bwKey, err := env.gw.AuthService().IssueVirtualKey(ctx, &domain.VirtualKey{
		OrgID:  "org_a",
		TeamID: "team_a1",
		UserID: "usr_a1_dev",
		Name:   "multi-window-key",
		Role:   domain.RoleDeveloper,
	})
	require.NoError(t, err)

	now := time.Now().UTC()
	// Daily = 300_000, Rolling24h = 500_000, Weekly = 800_000, Monthly = 2_000_000.
	windows := []struct {
		wt    domain.BudgetWindowType
		max   int64
		reset time.Time
	}{
		{domain.BudgetWindowDaily, 300_000, now.Add(2 * time.Hour)},
		{domain.BudgetWindowRolling24h, 500_000, now.Add(24 * time.Hour)},
		{domain.BudgetWindowWeekly, 800_000, now.Add(7 * 24 * time.Hour)},
		{domain.BudgetWindowMonthly, 2_000_000, now.Add(30 * 24 * time.Hour)},
	}
	for _, w := range windows {
		require.NoError(t, env.repo.UpsertBudgetWindowLimit(ctx, &domain.BudgetWindowLimit{
			OrgID:           "org_a",
			ScopeType:       domain.QuotaScopeKey,
			ScopeID:         bwKey.ID,
			WindowType:      w.wt,
			MaxBudgetMicros: w.max,
			WindowResetAt:   w.reset,
		}))
	}

	callChat := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"gpt-4.1","max_tokens":5000,"messages":[{"role":"user","content":"hi"}]}`))
		req.Header.Set("Authorization", "Bearer "+bwKey.RawKey)
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		env.handler.ServeHTTP(rr, req)
		return rr
	}

	// Request 1 admitted (cost=280_000).
	rr := callChat()
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())

	// Request 2 (280_000 + ~40_200 > 300_000 daily) must be rejected even though rolling_24h/weekly/monthly have headroom!
	rr = callChat()
	assert.Equal(t, http.StatusTooManyRequests, rr.Code)
	assert.Contains(t, rr.Body.String(), "key_budget_exceeded")

	// Wait for spend worker flush and verify DB spent_micros updated on all 4 windows.
	require.Eventually(t, func() bool {
		listed, listErr := env.repo.ListBudgetWindowLimits(ctx, storage.BudgetWindowFilter{
			OrgID:     "org_a",
			ScopeType: domain.QuotaScopeKey,
			ScopeID:   bwKey.ID,
		})
		if listErr != nil || len(listed) != 4 {
			return false
		}
		for _, w := range listed {
			if w.SpentMicros != 280_000 {
				return false
			}
		}
		return true
	}, 3*time.Second, 25*time.Millisecond)

	// Advance past daily reset (now + 3h): daily resets to 0, while rolling_24h stays at 280_000/500_000!
	resetWindows, err := env.repo.ResetExpiredBudgetWindowsWithResults(ctx, now.Add(3*time.Hour))
	require.NoError(t, err)
	require.Len(t, resetWindows, 1)
	assert.Equal(t, domain.BudgetWindowDaily, resetWindows[0].WindowType)
	require.NoError(t, env.gw.Limiter().ResetBudgetWindowSpend(ctx, resetWindows))

	// Request 3 admitted (daily=0 + 40_200 <= 300_000, rolling_24h=280_000 + 40_200 <= 500_000), settles another 280_000 -> rolling_24h=560_000!
	rr = callChat()
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())

	// Request 4 rejected because rolling_24h (560_000 > 500_000) is now exhausted, even though daily (280_000/300_000) or higher daily wouldn't block!
	rr = callChat()
	assert.Equal(t, http.StatusTooManyRequests, rr.Code)
	assert.Contains(t, rr.Body.String(), "key_budget_exceeded")
}

func TestTempBudgetBoost_AdmissionAndExpiration(t *testing.T) {
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"chatcmpl-tb","object":"chat.completion","model":"gpt-4.1","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}`))
	})

	env := setupQuotaHandlerTestEnv(t, upstream)
	ctx := context.Background()

	// Create key with base MaxBudgetMicros = 100 and pre-existing SpentMicros = 90.
	// Upper bound for gpt-4.1 with max_tokens=20 is (len*2 + 20*8) > 160, exceeding remaining 10 micros.
	tbKey, err := env.gw.AuthService().IssueVirtualKey(ctx, &domain.VirtualKey{
		OrgID:           "org_a",
		TeamID:          "team_a1",
		UserID:          "usr_a1_dev",
		Name:            "temp-boost-key",
		Role:            domain.RoleDeveloper,
		MaxBudgetMicros: 100,
		SpentMicros:     90,
	})
	require.NoError(t, err)

	callChat := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"gpt-4.1","max_tokens":20,"messages":[{"role":"user","content":"hi"}]}`))
		req.Header.Set("Authorization", "Bearer "+tbKey.RawKey)
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		env.handler.ServeHTTP(rr, req)
		return rr
	}

	// 1. Before temp boost: rejected with key_budget_exceeded.
	rr := callChat()
	assert.Equal(t, http.StatusTooManyRequests, rr.Code)
	assert.Contains(t, rr.Body.String(), "key_budget_exceeded")

	// 2. Grant temp budget increase of +5000 micros with 300s TTL -> effective budget = 5100.
	rec := doAdminJSONRequest(t, env.handler, http.MethodPost, "/admin/v1/keys/"+tbKey.ID+"/temp-budget", env.orgAAdmin.RawKey, map[string]any{
		"temp_budget_increase_micros": 5000,
		"ttl_seconds":                 300,
	})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	// 3. With active temp boost: admitted!
	rr = callChat()
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())

	// 3b. Regression check: boost must NOT be double-applied (base 100 + 5000 = 5100, NOT 10100).
	// A key with base=100, increase=5000, spent=5050 only has 50 micros left (< ~170 needed), so it must reject.
	tbNoDoubleKey, err := env.gw.AuthService().IssueVirtualKey(ctx, &domain.VirtualKey{
		OrgID:           "org_a",
		TeamID:          "team_a1",
		UserID:          "usr_a1_dev",
		Name:            "temp-boost-no-double-key",
		Role:            domain.RoleDeveloper,
		MaxBudgetMicros: 100,
		SpentMicros:     5050,
	})
	require.NoError(t, err)
	recDouble := doAdminJSONRequest(t, env.handler, http.MethodPost, "/admin/v1/keys/"+tbNoDoubleKey.ID+"/temp-budget", env.orgAAdmin.RawKey, map[string]any{
		"temp_budget_increase_micros": 5000,
		"ttl_seconds":                 300,
	})
	require.Equal(t, http.StatusOK, recDouble.Code, recDouble.Body.String())
	reqNoDouble := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(`{"model":"gpt-4.1","max_tokens":20,"messages":[{"role":"user","content":"hi"}]}`))
	reqNoDouble.Header.Set("Authorization", "Bearer "+tbNoDoubleKey.RawKey)
	reqNoDouble.Header.Set("Content-Type", "application/json")
	rrNoDouble := httptest.NewRecorder()
	env.handler.ServeHTTP(rrNoDouble, reqNoDouble)
	assert.Equal(t, http.StatusTooManyRequests, rrNoDouble.Code)
	assert.Contains(t, rrNoDouble.Body.String(), "key_budget_exceeded")

	// 4. Expire the temp boost and invalidate auth cache -> effective budget reverts to 100 -> rejected!
	past := time.Now().UTC().Add(-10 * time.Second)
	require.NoError(t, env.repo.SetTempBudgetBoost(ctx, domain.QuotaScopeKey, tbKey.ID, 5000, &past))
	env.gw.AuthService().InvalidateKeyID(ctx, tbKey.ID)

	rr = callChat()
	assert.Equal(t, http.StatusTooManyRequests, rr.Code)
	assert.Contains(t, rr.Body.String(), "key_budget_exceeded")
}

func TestSelfServeBudgetPolicy_DisabledLowerOnlyCeiling(t *testing.T) {
	env := setupQuotaHandlerTestEnv(t, nil)
	ctx := context.Background()

	// Issue a developer key inside team_a1 with initial budget 2_000_000.
	keyA1, err := env.gw.AuthService().IssueVirtualKey(ctx, &domain.VirtualKey{
		OrgID:           "org_a",
		TeamID:          "team_a1",
		UserID:          "usr_a1_dev",
		Name:            "self-serve-key",
		Role:            domain.RoleDeveloper,
		MaxBudgetMicros: 2_000_000,
	})
	require.NoError(t, err)

	// 1. Policy = disabled (default): team_admin cannot modify key/team budget or issue a key with max_budget_micros > 0, but org_admin can.
	rec := doAdminJSONRequest(t, env.handler, http.MethodPost, "/admin/v1/keys", env.teamA1Adm.RawKey, map[string]any{
		"name":              "self-serve-disabled-issue",
		"team_id":           "team_a1",
		"role":              "developer",
		"max_budget_micros": 1_000_000,
	})
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), "self_serve_budget_disabled")

	rec = doAdminJSONRequest(t, env.handler, http.MethodPost, "/admin/v1/keys", env.teamA1Adm.RawKey, map[string]any{
		"name":    "self-serve-disabled-no-budget",
		"team_id": "team_a1",
		"role":    "developer",
	})
	require.Equal(t, http.StatusCreated, rec.Code)

	rec = doAdminJSONRequest(t, env.handler, http.MethodPut, "/admin/v1/keys/"+keyA1.ID, env.teamA1Adm.RawKey, map[string]any{
		"max_budget_micros": 1_000_000,
	})
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), "self_serve_budget_disabled")

	rec = doAdminJSONRequest(t, env.handler, http.MethodPut, "/admin/v1/teams/team_a1", env.teamA1Adm.RawKey, map[string]any{
		"max_budget_micros": 3_000_000,
	})
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), "self_serve_budget_disabled")

	// Non-budget updates by team_admin still work under disabled policy.
	rec = doAdminJSONRequest(t, env.handler, http.MethodPut, "/admin/v1/keys/"+keyA1.ID, env.teamA1Adm.RawKey, map[string]any{
		"name": "self-serve-key-renamed",
	})
	require.Equal(t, http.StatusOK, rec.Code)

	// org_admin bypasses self-serve restriction.
	rec = doAdminJSONRequest(t, env.handler, http.MethodPut, "/admin/v1/keys/"+keyA1.ID, env.orgAAdmin.RawKey, map[string]any{
		"max_budget_micros": 3_000_000,
	})
	require.Equal(t, http.StatusOK, rec.Code)

	// 2. Policy = lower_only: team_admin can lower budget, cannot raise or remove cap (0).
	require.NoError(t, env.repo.CreateOrganization(ctx, &domain.Organization{
		ID:                    "org_lower",
		Name:                  "Lower Only Org",
		Slug:                  "lower-only-org",
		MaxBudgetMicros:       10_000_000,
		SelfServeBudgetPolicy: domain.SelfServeBudgetLowerOnly,
		IsActive:              true,
	}))
	require.NoError(t, env.repo.CreateTeam(ctx, &domain.Team{
		ID:              "team_lower",
		OrgID:           "org_lower",
		Name:            "Team Lower",
		MaxBudgetMicros: 5_000_000,
		IsActive:        true,
	}))
	require.NoError(t, env.repo.CreateUser(ctx, &domain.User{
		ID: "usr_lower_adm", OrgID: "org_lower", TeamID: "team_lower", Email: "ta@lower.example", Name: "TA", Role: domain.RoleTeamAdmin, IsActive: true,
	}))
	taLowerVK, err := env.gw.AuthService().IssueVirtualKey(ctx, &domain.VirtualKey{
		OrgID: "org_lower", TeamID: "team_lower", UserID: "usr_lower_adm", Name: "ta-lower", Role: domain.RoleTeamAdmin,
	})
	require.NoError(t, err)
	keyLower, err := env.gw.AuthService().IssueVirtualKey(ctx, &domain.VirtualKey{
		OrgID: "org_lower", TeamID: "team_lower", Name: "key-lower", Role: domain.RoleDeveloper, MaxBudgetMicros: 4_000_000,
	})
	require.NoError(t, err)

	// Lowering succeeds (4M -> 2M).
	rec = doAdminJSONRequest(t, env.handler, http.MethodPut, "/admin/v1/keys/"+keyLower.ID, taLowerVK.RawKey, map[string]any{
		"max_budget_micros": 2_000_000,
	})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	// Raising (2M -> 3M) or removing cap (0) fails with 403.
	rec = doAdminJSONRequest(t, env.handler, http.MethodPut, "/admin/v1/keys/"+keyLower.ID, taLowerVK.RawKey, map[string]any{
		"max_budget_micros": 3_000_000,
	})
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), "self_serve_budget_policy_violation")

	rec = doAdminJSONRequest(t, env.handler, http.MethodPut, "/admin/v1/keys/"+keyLower.ID, taLowerVK.RawKey, map[string]any{
		"max_budget_micros": 0,
	})
	assert.Equal(t, http.StatusForbidden, rec.Code)

	// Lowering team budget succeeds (5M -> 3M); raising fails.
	rec = doAdminJSONRequest(t, env.handler, http.MethodPut, "/admin/v1/teams/team_lower", taLowerVK.RawKey, map[string]any{
		"max_budget_micros": 3_000_000,
	})
	require.Equal(t, http.StatusOK, rec.Code)
	rec = doAdminJSONRequest(t, env.handler, http.MethodPut, "/admin/v1/teams/team_lower", taLowerVK.RawKey, map[string]any{
		"max_budget_micros": 4_000_000,
	})
	assert.Equal(t, http.StatusForbidden, rec.Code)

	// 3. Policy = ceiling: team_admin can raise key budget up to team ceiling (5M), and team budget up to org ceiling (10M).
	require.NoError(t, env.repo.CreateOrganization(ctx, &domain.Organization{
		ID:                    "org_ceil",
		Name:                  "Ceiling Org",
		Slug:                  "ceiling-org",
		MaxBudgetMicros:       10_000_000,
		SelfServeBudgetPolicy: domain.SelfServeBudgetCeiling,
		IsActive:              true,
	}))
	require.NoError(t, env.repo.CreateTeam(ctx, &domain.Team{
		ID:              "team_ceil",
		OrgID:           "org_ceil",
		Name:            "Team Ceiling",
		MaxBudgetMicros: 5_000_000,
		IsActive:        true,
	}))
	require.NoError(t, env.repo.CreateUser(ctx, &domain.User{
		ID: "usr_ceil_adm", OrgID: "org_ceil", TeamID: "team_ceil", Email: "ta@ceil.example", Name: "TA Ceil", Role: domain.RoleTeamAdmin, IsActive: true,
	}))
	taCeilVK, err := env.gw.AuthService().IssueVirtualKey(ctx, &domain.VirtualKey{
		OrgID: "org_ceil", TeamID: "team_ceil", UserID: "usr_ceil_adm", Name: "ta-ceil", Role: domain.RoleTeamAdmin,
	})
	require.NoError(t, err)
	keyCeil, err := env.gw.AuthService().IssueVirtualKey(ctx, &domain.VirtualKey{
		OrgID: "org_ceil", TeamID: "team_ceil", Name: "key-ceil", Role: domain.RoleDeveloper, MaxBudgetMicros: 1_000_000,
	})
	require.NoError(t, err)

	// Raising key budget within team ceiling (1M -> 4.5M) succeeds.
	rec = doAdminJSONRequest(t, env.handler, http.MethodPut, "/admin/v1/keys/"+keyCeil.ID, taCeilVK.RawKey, map[string]any{
		"max_budget_micros": 4_500_000,
	})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	// Exceeding team ceiling (5.5M) or setting unlimited (0) fails with 403.
	rec = doAdminJSONRequest(t, env.handler, http.MethodPut, "/admin/v1/keys/"+keyCeil.ID, taCeilVK.RawKey, map[string]any{
		"max_budget_micros": 5_500_000,
	})
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), "self_serve_budget_exceeds_ceiling")

	rec = doAdminJSONRequest(t, env.handler, http.MethodPut, "/admin/v1/keys/"+keyCeil.ID, taCeilVK.RawKey, map[string]any{
		"max_budget_micros": 0,
	})
	assert.Equal(t, http.StatusForbidden, rec.Code)

	// Raising team budget within org ceiling (5M -> 8M) succeeds, exceeding org ceiling (12M) fails.
	rec = doAdminJSONRequest(t, env.handler, http.MethodPut, "/admin/v1/teams/team_ceil", taCeilVK.RawKey, map[string]any{
		"max_budget_micros": 8_000_000,
	})
	require.Equal(t, http.StatusOK, rec.Code)
	rec = doAdminJSONRequest(t, env.handler, http.MethodPut, "/admin/v1/teams/team_ceil", taCeilVK.RawKey, map[string]any{
		"max_budget_micros": 12_000_000,
	})
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), "self_serve_budget_exceeds_ceiling")

	// Issuing a new key as team_admin under ceiling respects team ceiling (8M).
	rec = doAdminJSONRequest(t, env.handler, http.MethodPost, "/admin/v1/keys", taCeilVK.RawKey, map[string]any{
		"name":              "ceil-issue-ok",
		"team_id":           "team_ceil",
		"role":              "developer",
		"max_budget_micros": 6_000_000,
	})
	require.Equal(t, http.StatusCreated, rec.Code)
	rec = doAdminJSONRequest(t, env.handler, http.MethodPost, "/admin/v1/keys", taCeilVK.RawKey, map[string]any{
		"name":              "ceil-issue-too-high",
		"team_id":           "team_ceil",
		"role":              "developer",
		"max_budget_micros": 9_000_000,
	})
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), "self_serve_budget_exceeds_ceiling")
}

func TestProjectQuotaSharesUsageAcrossGatewayReplicas(t *testing.T) {
	env := setupQuotaHandlerTestEnv(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"chat-quota","object":"chat.completion","model":"gpt-4.1","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":45,"completion_tokens":5,"total_tokens":50}}`))
	}))
	ctx := context.Background()
	redisTwo := storage.NewRedisFabric(env.mr.Addr(), "", 0)
	t.Cleanup(func() { _ = redisTwo.Client().Close() })
	cfg := config.Default()
	cfg.Auth.MasterAdminKey = env.masterKey
	cfg.RateLimit.Enabled = true
	cfg.RateLimit.FallbackToLocalOnOutage = false
	cfg.Security.Network.OutboundSSRF.AllowPrivateNetworks = true
	cfg.Security.Network.OutboundSSRF.AllowInsecureHTTP = true
	replica, err := server.New(cfg, env.repo, redisTwo, nil)
	require.NoError(t, err)
	t.Cleanup(func() { replica.Shutdown(ctx) })

	key, err := env.gw.AuthService().IssueVirtualKey(ctx, &domain.VirtualKey{
		OrgID: "org_a", TeamID: "team_a1", ProjectID: "proj_a1", UserID: "usr_a1_dev",
		Name: "project-shared-quota", Role: domain.RoleDeveloper,
	})
	require.NoError(t, err)
	require.NoError(t, env.repo.UpsertQuotaPolicy(ctx, &domain.QuotaPolicy{
		OrgID: "org_a", ScopeType: domain.QuotaScopeModelPerProject, ScopeID: "proj_a1",
		ModelPattern: "gpt-4.1", TPDLimit: 50, IsActive: true,
	}))
	request := func(handler http.Handler) *httptest.ResponseRecorder {
		return doAdminJSONRequest(t, handler, http.MethodPost, "/v1/chat/completions", key.RawKey, map[string]any{
			"model": "gpt-4.1", "messages": []map[string]string{{"role": "user", "content": "hi"}}, "max_tokens": 8,
		})
	}
	first := request(env.handler)
	require.Equal(t, http.StatusOK, first.Code, first.Body.String())
	second := request(replica.Handler())
	require.Equal(t, http.StatusTooManyRequests, second.Code, second.Body.String())
	require.Contains(t, second.Body.String(), "tpd")
}
