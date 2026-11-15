package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/goroute-ai/ai-gateway-go/internal/adapter"
	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/finops"
	"github.com/goroute-ai/ai-gateway-go/internal/guardrails"
	"github.com/goroute-ai/ai-gateway-go/internal/observability"
	"github.com/goroute-ai/ai-gateway-go/internal/ratelimit"
	"github.com/goroute-ai/ai-gateway-go/internal/router"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/goroute-ai/ai-gateway-go/internal/validation"
)

type recordingBudgetAdapter struct {
	mu     sync.Mutex
	models []string
}

func (a *recordingBudgetAdapter) Provider() domain.ProviderType { return domain.ProviderOpenAI }
func (a *recordingBudgetAdapter) ChatCompletion(_ context.Context, dep *domain.Deployment, req *domain.CanonicalChatRequest) (*domain.CanonicalChatResponse, error) {
	modelName := req.Model
	if dep != nil && dep.GlobalModel != nil && dep.GlobalModel.ModelName != "" {
		modelName = dep.GlobalModel.ModelName
	}
	a.mu.Lock()
	a.models = append(a.models, modelName)
	a.mu.Unlock()
	return &domain.CanonicalChatResponse{
		ID:       "chatcmpl-test",
		Object:   "chat.completion",
		Created:  time.Now().Unix(),
		Model:    modelName,
		Provider: domain.ProviderOpenAI,
		Choices: []domain.CanonicalChoice{{
			Index:        0,
			Message:      domain.CanonicalMessage{Role: "assistant", Content: "ok"},
			FinishReason: "stop",
		}},
		Usage: domain.TokenUsage{PromptTokens: 10, CompletionTokens: 5, TotalTokens: 15},
	}, nil
}
func (a *recordingBudgetAdapter) StreamChatCompletion(context.Context, *domain.Deployment, *domain.CanonicalChatRequest, adapter.StreamChunkHandler) (*domain.TokenUsage, error) {
	return &domain.TokenUsage{}, nil
}
func (a *recordingBudgetAdapter) Embeddings(context.Context, *domain.Deployment, *domain.CanonicalEmbeddingRequest) (*domain.CanonicalEmbeddingResponse, error) {
	return &domain.CanonicalEmbeddingResponse{}, nil
}
func (a *recordingBudgetAdapter) ListModels(context.Context, *domain.ProviderCredential) ([]domain.DiscoveredModel, error) {
	return nil, nil
}
func (a *recordingBudgetAdapter) recordedModels() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]string, len(a.models))
	copy(out, a.models)
	return out
}

func setupBudgetPolicyTestServer(t *testing.T, adp *recordingBudgetAdapter, throttlePct float64) (*GatewayServer, *miniredis.Miniredis, *storage.MemoryRepository, *domain.Organization) {
	t.Helper()
	ctx := context.Background()
	mr := miniredis.RunT(t)
	redisFabric := storage.NewRedisFabric(mr.Addr(), "", 0)
	t.Cleanup(func() { _ = redisFabric.Client().Close() })

	repo := storage.NewMemoryRepository()
	vault, err := auth.NewVault("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("vault: %v", err)
	}
	org := &domain.Organization{Name: "PolicyOrg", Slug: "policy-org", IsActive: true}
	if err := repo.CreateOrganization(ctx, org); err != nil {
		t.Fatal(err)
	}
	cred := &domain.ProviderCredential{
		OrgID: org.ID, Provider: domain.ProviderOpenAI, Name: "c1", BaseURL: "https://api.example.com", IsActive: true,
	}
	if err := vault.EncryptCredential(cred, "sk-test"); err != nil {
		t.Fatal(err)
	}
	if err := repo.CreateProviderCredential(ctx, cred); err != nil {
		t.Fatal(err)
	}

	expensiveGM := &domain.GlobalModel{
		ID:                    "openai/gpt-4.1",
		Provider:              domain.ProviderOpenAI,
		ModelName:             "gpt-4.1",
		SupportsInference:     true,
		LifecycleStatus:       domain.ModelStatusActive,
		PricingStatus:         domain.PricingStatusVerified,
		InputCostMicrosPer1M:  5_000_000,
		OutputCostMicrosPer1M: 15_000_000,
		MaxOutputTokens:       512,
		MaxInputTokens:        128000,
	}
	cheapGM := &domain.GlobalModel{
		ID:                    "openai/gpt-4.1-mini",
		Provider:              domain.ProviderOpenAI,
		ModelName:             "gpt-4.1-mini",
		SupportsInference:     true,
		LifecycleStatus:       domain.ModelStatusActive,
		PricingStatus:         domain.PricingStatusVerified,
		InputCostMicrosPer1M:  100_000,
		OutputCostMicrosPer1M: 400_000,
		MaxOutputTokens:       512,
		MaxInputTokens:        128000,
	}
	if err := repo.UpsertGlobalModel(ctx, expensiveGM); err != nil {
		t.Fatal(err)
	}
	if err := repo.UpsertGlobalModel(ctx, cheapGM); err != nil {
		t.Fatal(err)
	}

	expGroup := &domain.ModelGroup{ID: "mg-exp", OrgID: org.ID, Alias: "gpt-4.1", RoutingStrategy: domain.StrategyWeightedShuffle, IsActive: true}
	cheapGroup := &domain.ModelGroup{ID: "mg-cheap", OrgID: org.ID, Alias: "gpt-4.1-mini", RoutingStrategy: domain.StrategyWeightedShuffle, IsActive: true}
	if err := repo.CreateModelGroup(ctx, expGroup); err != nil {
		t.Fatal(err)
	}
	if err := repo.CreateModelGroup(ctx, cheapGroup); err != nil {
		t.Fatal(err)
	}
	if err := repo.CreateDeployment(ctx, &domain.Deployment{
		ID: "dep-exp", ModelGroupID: expGroup.ID, GlobalModelID: expensiveGM.ID, CredentialID: cred.ID, DeploymentName: "d-exp", Weight: 1, Status: domain.DeploymentStatusActive,
	}); err != nil {
		t.Fatal(err)
	}
	if err := repo.CreateDeployment(ctx, &domain.Deployment{
		ID: "dep-cheap", ModelGroupID: cheapGroup.ID, GlobalModelID: cheapGM.ID, CredentialID: cred.ID, DeploymentName: "d-cheap", Weight: 1, Status: domain.DeploymentStatusActive,
	}); err != nil {
		t.Fatal(err)
	}

	reg := adapter.NewRegistry()
	reg.Register(adp)
	cfg := config.Default()
	cfg.FinOps.BudgetExceededThrottlePct = throttlePct
	cfg.Router.BaseRetryDelay = time.Millisecond
	cfg.Router.MaxRetryDelay = 5 * time.Millisecond

	rbac := auth.NewRBACEngine(repo)
	limiter := ratelimit.NewLimiter(redisFabric, 60, 300)
	collector := observability.NewCollector()
	depBudgets := router.NewDeploymentBudgetTracker(redisFabric)
	rm := router.NewReliabilityManager(repo, reg, router.NewIntelligentRouter(repo, cfg.Router), router.NewLoadBalancer(redisFabric), vault, rbac, redisFabric, cfg.Router)
	rm.SetDeploymentBudgetTracker(depBudgets)
	spendWorker := finops.NewSpendWorker(repo, limiter, cfg.FinOps)

	s := &GatewayServer{
		cfg:         cfg,
		repo:        repo,
		rbac:        rbac,
		limiter:     limiter,
		reliability: rm,
		depBudgets:  depBudgets,
		validator:   validation.NewValidator(repo),
		guardrails:  guardrails.NewEngine(repo),
		spendWorker: spendWorker,
		collector:   collector,
	}
	return s, mr, repo, org
}

func TestAcquireRequestQuotaWithBound_SoftBudgetThrottle(t *testing.T) {
	ctx := context.Background()
	adp := &recordingBudgetAdapter{}
	s, mr, _, org := setupBudgetPolicyTestServer(t, adp, 0.1)

	// Key has exceeded budget (1_000_000 / 1_000_000) with ThrottleOnBudgetExceeded=true
	// and RPMLimit=20 -> scaled down to max(1, int(20 * 0.1)) = 2 RPM.
	id := &domain.IdentityContext{
		VirtualKeyID:                "vk-throttle-1",
		OrgID:                       org.ID,
		KeyRPMLimit:                 20,
		KeyMaxBudgetMicros:          1_000_000,
		KeySpentMicros:              1_000_000,
		KeyThrottleOnBudgetExceeded: true,
	}

	rel1, err := s.acquireRequestQuotaWithBound(ctx, id, "openai/gpt-4.1", 10, 10, 32, "req-thr-1")
	if err != nil {
		t.Fatalf("first throttled request should be admitted, got: %v", err)
	}
	rel1(10)

	rel2, err := s.acquireRequestQuotaWithBound(ctx, id, "openai/gpt-4.1", 10, 10, 32, "req-thr-2")
	if err != nil {
		t.Fatalf("second throttled request should be admitted, got: %v", err)
	}
	rel2(10)

	// Third request in same minute must fail with rate limit (RPM=2), NOT budget_exceeded.
	_, err = s.acquireRequestQuotaWithBound(ctx, id, "openai/gpt-4.1", 10, 10, 32, "req-thr-3")
	if err == nil {
		t.Fatal("expected third request to hit throttled RPM limit")
	}
	var gwErr *domain.GatewayError
	if !errors.As(err, &gwErr) || gwErr.Type != domain.ErrorTypeRateLimit || gwErr.Code != "key_rpm_exceeded" {
		t.Fatalf("expected key_rpm_exceeded rate limit error, got: %v", err)
	}

	// Verify Redis-lagging budget exhaustion also triggers soft throttling when idCtx.KeySpentMicros lags.
	lagID := &domain.IdentityContext{
		VirtualKeyID:                "vk-throttle-lag",
		OrgID:                       org.ID,
		KeyRPMLimit:                 10,
		KeyMaxBudgetMicros:          500,
		KeySpentMicros:              0, // stale L1 cache floor
		KeyThrottleOnBudgetExceeded: true,
	}
	s.limiter.RecordSpendIncrement(ctx, lagID.VirtualKeyID, "", org.ID, 500)
	_ = mr // keep miniredis active

	relLag, err := s.acquireRequestQuotaWithBound(ctx, lagID, "openai/gpt-4.1", 10, 10, 32, "req-thr-lag-1")
	if err != nil {
		t.Fatalf("expected lagging-cache throttled request to be admitted, got: %v", err)
	}
	relLag(10)
	if _, err := s.acquireRequestQuotaWithBound(ctx, lagID, "openai/gpt-4.1", 10, 10, 32, "req-thr-lag-2"); err == nil {
		t.Fatal("expected second lagging-cache request to hit throttled RPM=1")
	}
}

func TestChatCompletions_BudgetFallbackOnEntityBudget(t *testing.T) {
	adp := &recordingBudgetAdapter{}
	s, _, repo, org := setupBudgetPolicyTestServer(t, adp, 0.1)

	// gpt-4.1 upper-bound for ~100 input bytes + 64 output tokens:
	//   (100*5M + 64*15M) / 1M = 1460 micros.
	// gpt-4.1-mini upper-bound:
	//   (100*100K + 64*400K) / 1M = 36 micros.
	// Set KeyMaxBudgetMicros = 500 so gpt-4.1 rejects, while gpt-4.1-mini is within budget.
	id := &domain.IdentityContext{
		VirtualKeyID:       "vk-fb-entity",
		KeyPrefix:          "sk-gw-fb",
		OrgID:              org.ID,
		KeyMaxBudgetMicros: 500,
		KeyBudgetFallbacks: map[string][]string{
			"gpt-4.1": {"gpt-4.1-mini"},
		},
	}

	body := `{"model":"gpt-4.1","max_tokens":64,"messages":[{"role":"user","content":"Hello budget fallback test"}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(body))
	req.Header.Set("X-Gateway-Request-Id", "req-fb-entity-1")
	req = req.WithContext(auth.WithIdentity(req.Context(), id))
	rec := httptest.NewRecorder()
	s.handleChatCompletions(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("X-Gateway-Budget-Fallback"); got != "gpt-4.1-mini" {
		t.Fatalf("X-Gateway-Budget-Fallback = %q, want %q", got, "gpt-4.1-mini")
	}
	if got := rec.Header().Get("X-Gateway-Original-Model"); got != "gpt-4.1" {
		t.Fatalf("X-Gateway-Original-Model = %q, want %q", got, "gpt-4.1")
	}
	if models := adp.recordedModels(); len(models) != 1 || models[0] != "gpt-4.1-mini" {
		t.Fatalf("adapter received models = %v, want [gpt-4.1-mini]", models)
	}

	_ = s.spendWorker.FlushNow(context.Background())
	logs, err := repo.ListSpendLogs(context.Background(), org.ID, 10)
	if err != nil || len(logs) != 1 {
		t.Fatalf("expected 1 spend log, got len=%d err=%v", len(logs), err)
	}
	if logs[0].RequestedModel != "gpt-4.1" || logs[0].ResolvedModel != "gpt-4.1-mini" {
		t.Fatalf("spend log models = (requested=%q, resolved=%q), want (gpt-4.1, gpt-4.1-mini)", logs[0].RequestedModel, logs[0].ResolvedModel)
	}

	// RBAC check: fallback model outside KeyAllowedModels must NOT be selected.
	rbacID := &domain.IdentityContext{
		VirtualKeyID:       "vk-fb-rbac",
		KeyPrefix:          "sk-gw-rbac",
		OrgID:              org.ID,
		KeyAllowedModels:   []string{"gpt-4.1"},
		KeyMaxBudgetMicros: 500,
		KeyBudgetFallbacks: map[string][]string{
			"gpt-4.1": {"gpt-4.1-mini"},
		},
	}
	req2 := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(body))
	req2.Header.Set("X-Gateway-Request-Id", "req-fb-rbac-1")
	req2 = req2.WithContext(auth.WithIdentity(req2.Context(), rbacID))
	rec2 := httptest.NewRecorder()
	s.handleChatCompletions(rec2, req2)
	if rec2.Code != http.StatusTooManyRequests {
		t.Fatalf("expected 429 when fallback violates RBAC allowlist, got %d (body=%s)", rec2.Code, rec2.Body.String())
	}
}

func TestChatCompletions_BudgetFallbackOnDeploymentBudget(t *testing.T) {
	ctx := context.Background()
	adp := &recordingBudgetAdapter{}
	s, _, repo, org := setupBudgetPolicyTestServer(t, adp, 0.1)

	// Set deployment budget on dep-exp and exhaust it.
	expGroup := &domain.ModelGroup{ID: "mg-exp-cap", OrgID: org.ID, Alias: "expensive-alias", RoutingStrategy: domain.StrategyWeightedShuffle, IsActive: true}
	if err := repo.CreateModelGroup(ctx, expGroup); err != nil {
		t.Fatal(err)
	}
	creds, err := repo.ListProviderCredentials(ctx, org.ID)
	if err != nil || len(creds) == 0 {
		t.Fatalf("ListProviderCredentials: %v", err)
	}
	if err := repo.CreateDeployment(ctx, &domain.Deployment{
		ID:                "dep-exp-capped",
		ModelGroupID:      expGroup.ID,
		GlobalModelID:     "openai/gpt-4.1",
		CredentialID:      creds[0].ID,
		DeploymentName:    "d-exp-capped",
		Weight:            1,
		MaxBudgetMicros:   100,
		BudgetResetPeriod: "monthly",
		Status:            domain.DeploymentStatusActive,
	}); err != nil {
		t.Fatal(err)
	}
	s.depBudgets.RecordSpend(ctx, org.ID, "dep-exp-capped", "", "monthly", 100)

	id := &domain.IdentityContext{
		VirtualKeyID: "vk-fb-dep",
		KeyPrefix:    "sk-gw-dep",
		OrgID:        org.ID,
		OrgBudgetFallbacks: map[string][]string{
			"expensive-alias": {"gpt-4.1-mini"},
		},
	}
	body := `{"model":"expensive-alias","max_tokens":32,"messages":[{"role":"user","content":"route around exhausted deployment"}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(body))
	req.Header.Set("X-Gateway-Request-Id", "req-fb-dep-1")
	req = req.WithContext(auth.WithIdentity(req.Context(), id))
	rec := httptest.NewRecorder()
	s.handleChatCompletions(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("X-Gateway-Budget-Fallback"); got != "gpt-4.1-mini" {
		t.Fatalf("X-Gateway-Budget-Fallback = %q, want %q", got, "gpt-4.1-mini")
	}
	if models := adp.recordedModels(); len(models) != 1 || models[0] != "gpt-4.1-mini" {
		t.Fatalf("adapter received models = %v, want [gpt-4.1-mini]", models)
	}
}

func TestChatCompletions_SoftBudgetThrottleAdmitsAndSetsHeader(t *testing.T) {
	adp := &recordingBudgetAdapter{}
	s, _, _, org := setupBudgetPolicyTestServer(t, adp, 0.1)

	id := &domain.IdentityContext{
		VirtualKeyID:                "vk-http-thr",
		KeyPrefix:                   "sk-gw-thr",
		OrgID:                       org.ID,
		KeyRPMLimit:                 10, // scaled to 1 RPM
		KeyMaxBudgetMicros:          1_000,
		KeySpentMicros:              1_000,
		KeyThrottleOnBudgetExceeded: true,
	}

	body := `{"model":"gpt-4.1","max_tokens":16,"messages":[{"role":"user","content":"soft throttle request"}]}`
	req1 := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(body))
	req1.Header.Set("X-Gateway-Request-Id", "req-http-thr-1")
	req1 = req1.WithContext(auth.WithIdentity(req1.Context(), id))
	rec1 := httptest.NewRecorder()
	s.handleChatCompletions(rec1, req1)

	if rec1.Code != http.StatusOK {
		t.Fatalf("first throttled chat status = %d, want 200 (body=%s)", rec1.Code, rec1.Body.String())
	}
	if got := rec1.Header().Get("X-Gateway-Budget-Throttled"); got != "true" {
		t.Fatalf("X-Gateway-Budget-Throttled = %q, want %q", got, "true")
	}

	// Second request within the same minute must be rate-limited at throttled RPM=1.
	req2 := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewBufferString(body))
	req2.Header.Set("X-Gateway-Request-Id", "req-http-thr-2")
	req2 = req2.WithContext(auth.WithIdentity(req2.Context(), id))
	rec2 := httptest.NewRecorder()
	s.handleChatCompletions(rec2, req2)
	if rec2.Code != http.StatusTooManyRequests {
		t.Fatalf("second throttled chat status = %d, want 429", rec2.Code)
	}
}

func TestAdminLifecycle_SoftBudgetFieldsRoundTrip(t *testing.T) {
	repo := storage.NewMemoryRepository()
	cfg := config.Default()
	cfg.Auth.MasterAdminKey = "admin_master_secret"

	gw, err := New(cfg, repo, nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	handler := gw.Handler()

	doReq := func(method, path string, payload any) *httptest.ResponseRecorder {
		var body *bytes.Reader
		if payload != nil {
			b, err := json.Marshal(payload)
			if err != nil {
				t.Fatal(err)
			}
			body = bytes.NewReader(b)
		} else {
			body = bytes.NewReader(nil)
		}
		req := httptest.NewRequest(method, path, body)
		req.Header.Set("Authorization", "Bearer "+cfg.Auth.MasterAdminKey)
		if payload != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}

	// Create Org with soft budget fields.
	rec := doReq(http.MethodPost, "/admin/v1/organizations", map[string]any{
		"id":                          "org_sb_rt",
		"name":                        "Soft Budget Org",
		"slug":                        "soft-budget-org",
		"max_budget_micros":           10_000_000,
		"soft_budget_micros":          7_500_000,
		"throttle_on_budget_exceeded": true,
		"budget_fallbacks":            map[string][]string{"gpt-4.1": {"gpt-4.1-mini"}},
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create org status=%d body=%s", rec.Code, rec.Body.String())
	}
	var orgResp domain.Organization
	if err := json.Unmarshal(rec.Body.Bytes(), &orgResp); err != nil {
		t.Fatal(err)
	}
	if orgResp.SoftBudgetMicros != 7_500_000 || !orgResp.ThrottleOnBudgetExceeded || len(orgResp.BudgetFallbacks["gpt-4.1"]) != 1 {
		t.Fatalf("unexpected org response: %+v", orgResp)
	}

	// Create and update Team.
	rec = doReq(http.MethodPost, "/admin/v1/teams", map[string]any{
		"id":                 "team_sb_rt",
		"org_id":             "org_sb_rt",
		"name":               "Team SB",
		"soft_budget_micros": 1_000_000,
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create team status=%d body=%s", rec.Code, rec.Body.String())
	}
	rec = doReq(http.MethodPut, "/admin/v1/teams/team_sb_rt", map[string]any{
		"soft_budget_micros":          2_000_000,
		"throttle_on_budget_exceeded": true,
		"budget_fallbacks":            map[string][]string{"gpt-4.1": {"gpt-4o-mini"}},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("update team status=%d body=%s", rec.Code, rec.Body.String())
	}
	var teamResp domain.Team
	_ = json.Unmarshal(rec.Body.Bytes(), &teamResp)
	if teamResp.SoftBudgetMicros != 2_000_000 || !teamResp.ThrottleOnBudgetExceeded || teamResp.BudgetFallbacks["gpt-4.1"][0] != "gpt-4o-mini" {
		t.Fatalf("unexpected updated team: %+v", teamResp)
	}

	// Negative soft_budget_micros rejected with 400.
	rec = doReq(http.MethodPut, "/admin/v1/teams/team_sb_rt", map[string]any{
		"soft_budget_micros": -1,
	})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for negative soft_budget_micros, got %d", rec.Code)
	}

	// Create and update User.
	rec = doReq(http.MethodPost, "/admin/v1/users", map[string]any{
		"id":     "user_sb_rt",
		"org_id": "org_sb_rt",
		"email":  "sb@example.com",
		"name":   "SB User",
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("create user status=%d body=%s", rec.Code, rec.Body.String())
	}
	rec = doReq(http.MethodPut, "/admin/v1/users/user_sb_rt", map[string]any{
		"soft_budget_micros":          500_000,
		"throttle_on_budget_exceeded": true,
		"budget_fallbacks":            map[string][]string{"gpt-4.1": {"gpt-4.1-mini"}},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("update user status=%d body=%s", rec.Code, rec.Body.String())
	}

	// Issue and update VirtualKey, then verify AuthService projects fields onto IdentityContext.
	rec = doReq(http.MethodPost, "/admin/v1/keys", map[string]any{
		"id":                 "vk_sb_rt",
		"org_id":             "org_sb_rt",
		"team_id":            "team_sb_rt",
		"user_id":            "user_sb_rt",
		"name":               "sb-key",
		"soft_budget_micros": 100_000,
	})
	if rec.Code != http.StatusCreated {
		t.Fatalf("issue key status=%d body=%s", rec.Code, rec.Body.String())
	}
	var issuedKey domain.VirtualKey
	_ = json.Unmarshal(rec.Body.Bytes(), &issuedKey)

	rec = doReq(http.MethodPut, "/admin/v1/keys/vk_sb_rt", map[string]any{
		"soft_budget_micros":          250_000,
		"throttle_on_budget_exceeded": true,
		"budget_fallbacks":            map[string][]string{"gpt-4.1": {"gpt-4.1-mini"}},
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("update key status=%d body=%s", rec.Code, rec.Body.String())
	}

	idCtx, err := gw.AuthService().AuthenticateVirtualKey(context.Background(), issuedKey.RawKey)
	if err != nil {
		t.Fatalf("AuthenticateVirtualKey: %v", err)
	}
	if idCtx.KeySoftBudgetMicros != 250_000 || !idCtx.KeyThrottleOnBudgetExceeded || idCtx.KeyBudgetFallbacks["gpt-4.1"][0] != "gpt-4.1-mini" {
		t.Fatalf("unexpected key fields on IdentityContext: %+v", idCtx)
	}
	if idCtx.TeamSoftBudgetMicros != 2_000_000 || !idCtx.TeamThrottleOnBudgetExceeded {
		t.Fatalf("unexpected team fields on IdentityContext: %+v", idCtx)
	}
	if idCtx.UserSoftBudgetMicros != 500_000 || !idCtx.UserThrottleOnBudgetExceeded {
		t.Fatalf("unexpected user fields on IdentityContext: %+v", idCtx)
	}
	if idCtx.OrgSoftBudgetMicros != 7_500_000 || !idCtx.OrgThrottleOnBudgetExceeded {
		t.Fatalf("unexpected org fields on IdentityContext: %+v", idCtx)
	}
}
