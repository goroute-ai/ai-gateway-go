package e2e_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/goroute-ai/ai-gateway-go/internal/adapter"
	"github.com/goroute-ai/ai-gateway-go/internal/adapter/openai"
	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/logger"
	"github.com/goroute-ai/ai-gateway-go/internal/router"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
	"github.com/goroute-ai/ai-gateway-go/internal/server"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

func postRoutingChat(t *testing.T, ts *httptest.Server, apiKey string, payload map[string]any) (*http.Response, []byte) {
	t.Helper()
	b, err := json.Marshal(payload)
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	req, err := http.NewRequest(http.MethodPost, ts.URL+"/v1/chat/completions", bytes.NewReader(b))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST /v1/chat/completions: %v", err)
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	return resp, raw
}

// TestE2E_Routing_PostgresMigrations0020And0021 verifies that migrations 0020 and 0021
// apply cleanly on live PostgreSQL and persist/reload all v1.20.0 routing schema columns.
func TestE2E_Routing_PostgresMigrations0020And0021(t *testing.T) {
	ctx := context.Background()
	pgDSN := getEnvOrDefault("GATEWAY_POSTGRES_DSN", "postgres://gateway:gateway@localhost:5432/aigateway?sslmode=disable")

	pool, err := storage.NewPostgresPool(ctx, pgDSN)
	if err != nil {
		if os.Getenv("GATEWAY_REQUIRE_LIVE_DEPS") == "1" {
			t.Fatalf("GATEWAY_REQUIRE_LIVE_DEPS=1 set, cannot connect to PostgreSQL: %v", err)
		}
		t.Skipf("skipping live PostgreSQL migration test: %v", err)
	}
	defer pool.Close()

	if err := storage.RunMigrationsDir(ctx, pool, "../../migrations"); err != nil {
		t.Fatalf("RunMigrationsDir: %v", err)
	}

	assertCols := func(table string, cols []string) {
		t.Helper()
		for _, col := range cols {
			var count int
			err := pool.QueryRow(ctx,
				`SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = $1 AND column_name = $2`,
				table, col,
			).Scan(&count)
			if err != nil || count == 0 {
				t.Fatalf("expected column %s.%s from migrations 0020/0021 (count=%d err=%v)", table, col, count, err)
			}
		}
	}

	assertCols("model_groups", []string{
		"context_window_fallbacks",
		"content_policy_fallbacks",
		"fallback_targets",
		"retry_policy",
		"cooldown_policy",
	})
	assertCols("model_deployments", []string{
		"tags",
		"max_budget_micros",
		"budget_reset_period",
	})
	assertCols("global_models", []string{
		"quality_tier",
	})

	pgRepo, err := storage.NewPostgresRepository(ctx, pool)
	if err != nil {
		t.Fatalf("NewPostgresRepository: %v", err)
	}

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	org := &domain.Organization{Name: "Routing Migration Org " + suffix, Slug: "routing-mig-" + suffix, IsActive: true}
	if err := pgRepo.CreateOrganization(ctx, org); err != nil {
		t.Fatalf("CreateOrganization: %v", err)
	}

	gm := &domain.GlobalModel{
		ID:                    "openai/v120-mig-" + suffix,
		Provider:              domain.ProviderOpenAI,
		ModelName:             "routing-mig-" + suffix,
		QualityTier:           4,
		SupportsInference:     true,
		LifecycleStatus:       domain.ModelStatusActive,
		PricingStatus:         domain.PricingStatusVerified,
		InputCostMicrosPer1M:  100_000,
		OutputCostMicrosPer1M: 200_000,
	}
	if err := pgRepo.UpsertGlobalModel(ctx, gm); err != nil {
		t.Fatalf("UpsertGlobalModel: %v", err)
	}
	gotGM, err := pgRepo.GetGlobalModel(ctx, gm.ID)
	if err != nil || gotGM.QualityTier != 4 {
		t.Fatalf("GetGlobalModel quality_tier mismatch: got=%+v err=%v", gotGM, err)
	}

	mg := &domain.ModelGroup{
		OrgID:           org.ID,
		Alias:           "v120-mig-group-" + suffix,
		RoutingStrategy: domain.StrategyFastestResponse,
		ContextWindowFallbacks: []domain.FallbackTarget{
			{GroupAliasOrID: "long-ctx", Overrides: map[string]any{"max_tokens": float64(4096)}},
		},
		ContentPolicyFallbacks: []domain.FallbackTarget{
			{GroupAliasOrID: "safe-ctx"},
		},
		FallbackTargets: []domain.FallbackTarget{
			{GroupAliasOrID: "default-fb"},
		},
		RetryPolicy: &domain.RetryPolicy{
			RateLimitRetries: 3,
			TimeoutRetries:   2,
			DefaultRetries:   1,
		},
		CooldownPolicy: &domain.CooldownPolicy{
			AllowedFails:         map[string]int{"429": 3},
			FailureRateThreshold: 0.25,
			MinRequestsPerMinute: 10,
			MaxCooldownSeconds:   90,
		},
		IsActive: true,
	}
	if err := pgRepo.CreateModelGroup(ctx, mg); err != nil {
		t.Fatalf("CreateModelGroup: %v", err)
	}
	gotMG, err := pgRepo.GetModelGroupByAlias(ctx, org.ID, mg.Alias)
	if err != nil {
		t.Fatalf("GetModelGroupByAlias: %v", err)
	}
	if len(gotMG.ContextWindowFallbacks) != 1 || gotMG.ContextWindowFallbacks[0].GroupAliasOrID != "long-ctx" {
		t.Fatalf("ContextWindowFallbacks not persisted: %+v", gotMG.ContextWindowFallbacks)
	}
	if len(gotMG.ContentPolicyFallbacks) != 1 || gotMG.ContentPolicyFallbacks[0].GroupAliasOrID != "safe-ctx" {
		t.Fatalf("ContentPolicyFallbacks not persisted: %+v", gotMG.ContentPolicyFallbacks)
	}
	if gotMG.RetryPolicy == nil || gotMG.RetryPolicy.RateLimitRetries != 3 {
		t.Fatalf("RetryPolicy not persisted: %+v", gotMG.RetryPolicy)
	}
	if gotMG.CooldownPolicy == nil || gotMG.CooldownPolicy.MaxCooldownSeconds != 90 {
		t.Fatalf("CooldownPolicy not persisted: %+v", gotMG.CooldownPolicy)
	}

	cred := &domain.ProviderCredential{
		OrgID:    org.ID,
		Provider: domain.ProviderOpenAI,
		Name:     "v120-mig-cred-" + suffix,
		BaseURL:  "https://api.openai.com/v1",
		IsActive: true,
	}
	if err := pgRepo.CreateProviderCredential(ctx, cred); err != nil {
		t.Fatalf("CreateProviderCredential: %v", err)
	}

	dep := &domain.Deployment{
		ModelGroupID:      mg.ID,
		GlobalModelID:     gm.ID,
		CredentialID:      cred.ID,
		DeploymentName:    "v120-mig-dep",
		Priority:          2,
		Tags:              []string{"tier:primary", "compliance:eu"},
		MaxBudgetMicros:   25_000_000,
		BudgetResetPeriod: "daily",
		Status:            domain.DeploymentStatusActive,
	}
	if err := pgRepo.CreateDeployment(ctx, dep); err != nil {
		t.Fatalf("CreateDeployment: %v", err)
	}
	deps, err := pgRepo.ListDeploymentsByGroup(ctx, mg.ID)
	if err != nil || len(deps) != 1 {
		t.Fatalf("ListDeploymentsByGroup: len=%d err=%v", len(deps), err)
	}
	if deps[0].CredentialID != cred.ID || deps[0].Priority != 2 || deps[0].MaxBudgetMicros != 25_000_000 || deps[0].BudgetResetPeriod != "daily" || len(deps[0].Tags) != 2 {
		t.Fatalf("Deployment v1.20 fields not persisted: %+v", deps[0])
	}
}

// TestE2E_Routing_LiveClusterMultiPodRoutingAndCircuitBreaker exercises multi-pod routing,
// shared session affinity, and cross-pod circuit breaker failover on live Postgres + Redis.
func TestE2E_Routing_LiveClusterMultiPodRoutingAndCircuitBreaker(t *testing.T) {
	ts1, ts2, node1, node2, pgRepo, redisFabric, cleanup := setupDualNodeCluster(t)
	defer cleanup()

	affCfg := config.Default().Router
	affCfg.SessionAffinityTTL = 5 * time.Minute
	affCfg.SessionAffinityRepinOnFailover = true
	node1.Reliability().SetAffinityStore(router.NewAffinityStoreFromRouterConfig(redisFabric, affCfg))
	node2.Reliability().SetAffinityStore(router.NewAffinityStoreFromRouterConfig(redisFabric, affCfg))

	ctx := context.Background()
	var primaryFail atomic.Bool
	var primaryHits atomic.Int64
	primarySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		primaryHits.Add(1)
		if primaryFail.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprint(w, `{"error":{"message":"primary down"}}`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"id":"live-p","object":"chat.completion","model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"live-primary"},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":2,"total_tokens":5}}`)
	}))
	defer primarySrv.Close()

	fallbackSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"id":"live-fb","object":"chat.completion","model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"live-fallback"},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":2,"total_tokens":5}}`)
	}))
	defer fallbackSrv.Close()

	c1 := &httpClientHelper{t: t, ts: ts1}
	adminHeaders := map[string]string{"Authorization": "Bearer sk-gw-cluster-admin-key"}
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())

	var org domain.Organization
	resp, raw := c1.doJSON("POST", "/admin/v1/organizations", adminHeaders, map[string]any{
		"name": "LiveRoutingClusterOrg", "slug": "live-routing-" + suffix,
	}, &org)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create org failed: %d %s", resp.StatusCode, raw)
	}

	gmID := "openai/live-v120-" + suffix
	if err := pgRepo.UpsertGlobalModel(ctx, &domain.GlobalModel{
		ID: gmID, Provider: domain.ProviderOpenAI, ModelName: "live-routing-" + suffix,
		SupportsInference: true, LifecycleStatus: domain.ModelStatusActive, PricingStatus: domain.PricingStatusVerified,
		MaxOutputTokens: 4096,
	}); err != nil {
		t.Fatalf("UpsertGlobalModel: %v", err)
	}

	mustCreate := func(path string, body any, out any) {
		t.Helper()
		r, b := c1.doJSON("POST", path, adminHeaders, body, out)
		if r.StatusCode != http.StatusCreated {
			t.Fatalf("POST %s failed: %d %s", path, r.StatusCode, string(b))
		}
	}

	var pCred, fCred, fbMG, pMG, pDep map[string]any
	mustCreate("/admin/v1/credentials", map[string]any{
		"org_id": org.ID, "provider": "openai", "name": "p-c", "api_key": "sk-p", "base_url": primarySrv.URL,
	}, &pCred)
	mustCreate("/admin/v1/credentials", map[string]any{
		"org_id": org.ID, "provider": "openai", "name": "f-c", "api_key": "sk-f", "base_url": fallbackSrv.URL,
	}, &fCred)

	mustCreate("/admin/v1/model-groups", map[string]any{
		"org_id": org.ID, "alias": "live-fb-" + suffix, "routing_strategy": "round-robin",
	}, &fbMG)
	mustCreate("/admin/v1/deployments", map[string]any{
		"model_group_id": fbMG["id"], "global_model_id": gmID, "credential_id": fCred["id"],
		"deployment_name": "fb-dep", "weight": 100,
	}, nil)

	mustCreate("/admin/v1/model-groups", map[string]any{
		"org_id": org.ID, "alias": "live-primary-" + suffix, "routing_strategy": "round-robin",
		"max_retries": 0, "failure_threshold": 2, "cooldown_seconds": 5,
		"fallback_targets": []map[string]any{{"target": fbMG["id"]}},
	}, &pMG)
	mustCreate("/admin/v1/deployments", map[string]any{
		"model_group_id": pMG["id"], "global_model_id": gmID, "credential_id": pCred["id"],
		"deployment_name": "p-dep", "weight": 100,
	}, &pDep)
	pDepID, _ := pDep["id"].(string)
	if pDepID == "" {
		t.Fatalf("expected non-empty deployment id, got %+v", pDep)
	}

	var vk domain.VirtualKey
	mustCreate("/admin/v1/keys", map[string]any{
		"org_id": org.ID, "name": "live-v120-key", "allowed_endpoints": []string{"*"},
	}, &vk)

	reqBody := map[string]any{
		"model":    "live-primary-" + suffix,
		"messages": []map[string]string{{"role": "user", "content": "cluster ping"}},
		"goroute_extensions": map[string]any{
			"session_id": "live-sess-" + suffix,
		},
	}

	// Healthy request on Pod 1
	r1, b1 := postRoutingChat(t, ts1, vk.RawKey, reqBody)
	if r1.StatusCode != http.StatusOK {
		t.Fatalf("pod1 healthy request failed: %d %s", r1.StatusCode, string(b1))
	}

	// Trip primary circuit on Pod 1
	primaryFail.Store(true)
	for i := 0; i < 2; i++ {
		rTrip, bTrip := postRoutingChat(t, ts1, vk.RawKey, reqBody)
		if rTrip.StatusCode != http.StatusOK || rTrip.Header.Get("X-Gateway-Fallback-Attempted") != "true" {
			t.Fatalf("pod1 failover %d failed: status=%d fb=%q body=%s", i, rTrip.StatusCode, rTrip.Header.Get("X-Gateway-Fallback-Attempted"), string(bTrip))
		}
	}

	if st := node2.Reliability().GetCircuitState(ctx, pDepID); st != router.CircuitOpen {
		t.Fatalf("expected node2 to observe OPEN circuit from Redis, got %s", st)
	}

	primaryHits.Store(0)
	r2, b2 := postRoutingChat(t, ts2, vk.RawKey, reqBody)
	if r2.StatusCode != http.StatusOK || r2.Header.Get("X-Gateway-Fallback-Attempted") != "true" {
		t.Fatalf("pod2 fallback request failed: status=%d body=%s", r2.StatusCode, string(b2))
	}
	if primaryHits.Load() != 0 {
		t.Fatalf("expected pod2 to skip OPEN primary deployment, got %d hits", primaryHits.Load())
	}
}

// TestE2E_Routing_MultiPodCircuitBreakerAndAffinity verifies shared Redis session affinity,
// cross-pod failover repinning, and circuit breaker OPEN/HALF_OPEN/CLOSED coordination using miniredis.
func TestE2E_Routing_MultiPodCircuitBreakerAndAffinity(t *testing.T) {
	logger.Init(logger.Config{Level: "error", Format: "text"})
	defer logger.Init(logger.Config{Level: "info", Format: "text"})

	ctx := context.Background()
	mr := miniredis.RunT(t)
	repo := storage.NewMemoryRepository()

	var depAHits, depBHits atomic.Int64
	var depAFail, depBFail atomic.Bool

	makeUpstream := func(tag string, hits *atomic.Int64, fail *atomic.Bool) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			hits.Add(1)
			if fail.Load() {
				w.WriteHeader(http.StatusServiceUnavailable)
				fmt.Fprintf(w, `{"error":{"message":"%s unavailable"}}`, tag)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"id":"chat-%s","object":"chat.completion","model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"%s"},"finish_reason":"stop"}],"usage":{"prompt_tokens":4,"completion_tokens":2,"total_tokens":6}}`, tag, tag)
		}))
	}

	upA := makeUpstream("dep-a", &depAHits, &depAFail)
	defer upA.Close()
	upB := makeUpstream("dep-b", &depBHits, &depBFail)
	defer upB.Close()

	pods := make([]*server.GatewayServer, 2)
	servers := make([]*httptest.Server, 2)
	workerCtx, workerCancel := context.WithCancel(ctx)
	defer workerCancel()

	for i := 0; i < 2; i++ {
		cfg := config.Default()
		cfg.Logging.Level = "error"
		cfg.Auth.MasterAdminKey = "sk-gw-v120-admin"
		cfg.Auth.MasterEncryptionKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
		cfg.Security.Network.OutboundSSRF.AllowPrivateNetworks = true
		cfg.Security.Network.OutboundSSRF.AllowInsecureHTTP = true
		cfg.Router.DefaultMaxRetries = 1
		cfg.Router.BaseRetryDelay = time.Millisecond
		cfg.Router.MaxRetryDelay = 5 * time.Millisecond
		cfg.Router.FailureThreshold = 1
		cfg.Router.DefaultCooldown = 2 * time.Second
		cfg.Router.SessionAffinityTTL = 5 * time.Minute
		cfg.Router.SessionAffinityRepinOnFailover = true

		fabric := storage.NewRedisFabric(mr.Addr(), "", 0)
		gw, err := server.New(cfg, repo, fabric, nil)
		if err != nil {
			t.Fatalf("server.New(%d): %v", i, err)
		}
		gw.Reliability().SetAffinityStore(router.NewAffinityStoreFromRouterConfig(fabric, cfg.Router))
		gw.StartWorkers(workerCtx)
		pods[i] = gw
		servers[i] = httptest.NewServer(gw.Handler())
	}
	defer func() {
		for i := 0; i < 2; i++ {
			servers[i].Close()
			pods[i].Shutdown(context.Background())
		}
	}()

	c0 := &httpClientHelper{t: t, ts: servers[0]}
	adminHeaders := map[string]string{"Authorization": "Bearer sk-gw-v120-admin"}

	var org map[string]any
	c0.doJSON("POST", "/admin/v1/organizations", adminHeaders, map[string]any{"name": "AffOrg", "slug": "aff-org"}, &org)
	orgID := org["id"].(string)

	_ = repo.UpsertGlobalModel(ctx, &domain.GlobalModel{
		ID: "openai/gpt-4o-mini", Provider: domain.ProviderOpenAI, ModelName: "gpt-4o-mini",
		SupportsInference: true, LifecycleStatus: domain.ModelStatusActive, PricingStatus: domain.PricingStatusVerified,
		MaxOutputTokens: 4096,
	})

	var credA, credB, grp, depA, depB map[string]any
	c0.doJSON("POST", "/admin/v1/credentials", adminHeaders, map[string]any{
		"org_id": orgID, "provider": "openai", "name": "c-a", "api_key": "sk-a", "base_url": upA.URL,
	}, &credA)
	c0.doJSON("POST", "/admin/v1/credentials", adminHeaders, map[string]any{
		"org_id": orgID, "provider": "openai", "name": "c-b", "api_key": "sk-b", "base_url": upB.URL,
	}, &credB)
	c0.doJSON("POST", "/admin/v1/model-groups", adminHeaders, map[string]any{
		"org_id": orgID, "alias": "aff-group", "routing_strategy": "round-robin",
		"max_retries": 1, "failure_threshold": 1, "cooldown_seconds": 2,
	}, &grp)
	c0.doJSON("POST", "/admin/v1/deployments", adminHeaders, map[string]any{
		"model_group_id": grp["id"], "global_model_id": "openai/gpt-4o-mini",
		"credential_id": credA["id"], "deployment_name": "dep-a", "weight": 100,
	}, &depA)
	c0.doJSON("POST", "/admin/v1/deployments", adminHeaders, map[string]any{
		"model_group_id": grp["id"], "global_model_id": "openai/gpt-4o-mini",
		"credential_id": credB["id"], "deployment_name": "dep-b", "weight": 100,
	}, &depB)

	var vk domain.VirtualKey
	c0.doJSON("POST", "/admin/v1/keys", adminHeaders, map[string]any{"org_id": orgID, "name": "aff-key"}, &vk)

	reqBody := map[string]any{
		"model":    "aff-group",
		"messages": []map[string]string{{"role": "user", "content": "sticky session check"}},
		"goroute_extensions": map[string]any{
			"session_id": "sess-v120-01",
		},
	}

	// 1. First request on Pod 0 establishes affinity pin.
	resp, raw := postRoutingChat(t, servers[0], vk.RawKey, reqBody)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("initial affinity request failed: %d %s", resp.StatusCode, string(raw))
	}
	// Wait briefly for async Redis affinity write to settle.
	time.Sleep(30 * time.Millisecond)

	pinnedIsA := depAHits.Load() == 1 && depBHits.Load() == 0
	if !pinnedIsA && !(depBHits.Load() == 1 && depAHits.Load() == 0) {
		t.Fatalf("expected exactly 1 upstream hit on initial request, got A=%d B=%d", depAHits.Load(), depBHits.Load())
	}

	// 2. Subsequent requests across Pod 0 and Pod 1 must stay pinned to the same deployment.
	depAHits.Store(0)
	depBHits.Store(0)
	for i := 0; i < 6; i++ {
		r, b := postRoutingChat(t, servers[i%2], vk.RawKey, reqBody)
		if r.StatusCode != http.StatusOK {
			t.Fatalf("pinned request %d failed: %d %s", i, r.StatusCode, string(b))
		}
	}
	if pinnedIsA && (depAHits.Load() != 6 || depBHits.Load() != 0) {
		t.Fatalf("expected all 6 sticky requests on dep-a across both pods, got A=%d B=%d", depAHits.Load(), depBHits.Load())
	}
	if !pinnedIsA && (depBHits.Load() != 6 || depAHits.Load() != 0) {
		t.Fatalf("expected all 6 sticky requests on dep-b across both pods, got A=%d B=%d", depAHits.Load(), depBHits.Load())
	}

	// 3. Fault the pinned deployment; Pod 0 trips its circuit breaker and repins to the healthy peer.
	pinnedID := depB["id"].(string)
	pinnedHits := &depBHits
	healthyHits := &depAHits
	pinnedFail := &depBFail
	if pinnedIsA {
		pinnedID = depA["id"].(string)
		pinnedHits = &depAHits
		healthyHits = &depBHits
		pinnedFail = &depAFail
	}
	pinnedFail.Store(true)
	pinnedHits.Store(0)
	healthyHits.Store(0)

	rFailover, bFailover := postRoutingChat(t, servers[0], vk.RawKey, reqBody)
	if rFailover.StatusCode != http.StatusOK {
		t.Fatalf("failover request failed: %d %s", rFailover.StatusCode, string(bFailover))
	}
	if st := pods[1].Reliability().GetCircuitState(ctx, pinnedID); st != router.CircuitOpen {
		t.Fatalf("expected Pod 1 to observe OPEN circuit for %s, got %s", pinnedID, st)
	}

	// Allow async repin write to settle, then verify Pod 1 hits only the healthy peer.
	time.Sleep(30 * time.Millisecond)
	pinnedHits.Store(0)
	healthyHits.Store(0)
	for i := 0; i < 4; i++ {
		r, b := postRoutingChat(t, servers[1], vk.RawKey, reqBody)
		if r.StatusCode != http.StatusOK {
			t.Fatalf("post-failover Pod 1 request %d failed: %d %s", i, r.StatusCode, string(b))
		}
	}
	if pinnedHits.Load() != 0 || healthyHits.Load() != 4 {
		t.Fatalf("expected Pod 1 to route exclusively to healthy peer, got pinned=%d healthy=%d", pinnedHits.Load(), healthyHits.Load())
	}

	// 4. Heal the faulted deployment and fast-forward miniredis past cooldown -> HALF_OPEN -> CLOSED.
	pinnedFail.Store(false)
	mr.FastForward(3 * time.Second)
	if st := pods[0].Reliability().GetCircuitState(ctx, pinnedID); st != router.CircuitHalfOpen {
		t.Fatalf("expected HALF_OPEN after cooldown expiry, got %s", st)
	}
}

// TestE2E_Routing_PriorityTiersAndSpecializedFallbacks verifies priority-tier stepdowns
// and context-window specialized fallbacks with parameter overrides end-to-end.
func TestE2E_Routing_PriorityTiersAndSpecializedFallbacks(t *testing.T) {
	logger.Init(logger.Config{Level: "error", Format: "text"})
	defer logger.Init(logger.Config{Level: "info", Format: "text"})

	ctx := context.Background()
	mr := miniredis.RunT(t)
	repo := storage.NewMemoryRepository()

	var tier0Fail atomic.Bool
	var tier0Hits, tier1Hits atomic.Int64
	tier0Srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tier0Hits.Add(1)
		if tier0Fail.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprint(w, `{"error":{"message":"tier0 down"}}`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"id":"t0","object":"chat.completion","model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"tier0-ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":2,"total_tokens":5}}`)
	}))
	defer tier0Srv.Close()

	tier1Srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tier1Hits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"id":"t1","object":"chat.completion","model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"tier1-ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":2,"total_tokens":5}}`)
	}))
	defer tier1Srv.Close()

	var longCtxMu sync.Mutex
	var lastLongCtxMaxTokens float64
	longCtxSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var decoded map[string]any
		if err := json.Unmarshal(raw, &decoded); err == nil {
			if mt, ok := decoded["max_completion_tokens"].(float64); ok {
				longCtxMu.Lock()
				lastLongCtxMaxTokens = mt
				longCtxMu.Unlock()
			} else if mt, ok := decoded["max_tokens"].(float64); ok {
				longCtxMu.Lock()
				lastLongCtxMaxTokens = mt
				longCtxMu.Unlock()
			}
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"id":"long-ctx","object":"chat.completion","model":"gpt-4.1","choices":[{"index":0,"message":{"role":"assistant","content":"long-ctx-ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":30,"completion_tokens":2,"total_tokens":32}}`)
	}))
	defer longCtxSrv.Close()

	cfg := config.Default()
	cfg.Logging.Level = "error"
	cfg.Auth.MasterAdminKey = "sk-gw-tier-admin"
	cfg.Auth.MasterEncryptionKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	cfg.Security.Network.OutboundSSRF.AllowPrivateNetworks = true
	cfg.Security.Network.OutboundSSRF.AllowInsecureHTTP = true
	cfg.Router.DefaultMaxRetries = 0
	cfg.Router.BaseRetryDelay = time.Millisecond
	cfg.Router.MaxRetryDelay = 5 * time.Millisecond
	cfg.Router.FailureThreshold = 2

	gw, err := server.New(cfg, repo, storage.NewRedisFabric(mr.Addr(), "", 0), nil)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	workerCtx, workerCancel := context.WithCancel(ctx)
	gw.StartWorkers(workerCtx)
	ts := httptest.NewServer(gw.Handler())
	defer func() {
		ts.Close()
		workerCancel()
		gw.Shutdown(context.Background())
	}()

	ch := &httpClientHelper{t: t, ts: ts}
	adminHeaders := map[string]string{"Authorization": "Bearer sk-gw-tier-admin"}

	var org map[string]any
	ch.doJSON("POST", "/admin/v1/organizations", adminHeaders, map[string]any{"name": "TierOrg", "slug": "tier-org"}, &org)
	orgID := org["id"].(string)

	_ = repo.UpsertGlobalModel(ctx, &domain.GlobalModel{
		ID: "openai/gpt-4o-mini", Provider: domain.ProviderOpenAI, ModelName: "gpt-4o-mini",
		SupportsInference: true, LifecycleStatus: domain.ModelStatusActive, PricingStatus: domain.PricingStatusVerified,
		MaxInputTokens: 128000, MaxOutputTokens: 4096,
	})
	_ = repo.UpsertGlobalModel(ctx, &domain.GlobalModel{
		ID: "openai/tiny-ctx", Provider: domain.ProviderOpenAI, ModelName: "tiny-ctx",
		SupportsInference: true, LifecycleStatus: domain.ModelStatusActive, PricingStatus: domain.PricingStatusVerified,
		MaxInputTokens: 20, MaxOutputTokens: 512,
	})
	_ = repo.UpsertGlobalModel(ctx, &domain.GlobalModel{
		ID: "openai/gpt-4.1", Provider: domain.ProviderOpenAI, ModelName: "gpt-4.1",
		SupportsInference: true, LifecycleStatus: domain.ModelStatusActive, PricingStatus: domain.PricingStatusVerified,
		MaxInputTokens: 128000, MaxOutputTokens: 8192,
	})

	var c0, c1, cLong, tieredMG, longCtxMG, shortCtxMG map[string]any
	ch.doJSON("POST", "/admin/v1/credentials", adminHeaders, map[string]any{
		"org_id": orgID, "provider": "openai", "name": "t0", "api_key": "sk-0", "base_url": tier0Srv.URL,
	}, &c0)
	ch.doJSON("POST", "/admin/v1/credentials", adminHeaders, map[string]any{
		"org_id": orgID, "provider": "openai", "name": "t1", "api_key": "sk-1", "base_url": tier1Srv.URL,
	}, &c1)
	ch.doJSON("POST", "/admin/v1/credentials", adminHeaders, map[string]any{
		"org_id": orgID, "provider": "openai", "name": "cl", "api_key": "sk-l", "base_url": longCtxSrv.URL,
	}, &cLong)

	ch.doJSON("POST", "/admin/v1/model-groups", adminHeaders, map[string]any{
		"org_id": orgID, "alias": "tiered-chat", "routing_strategy": "round-robin",
		"max_retries": 0, "failure_threshold": 2, "cooldown_seconds": 5,
	}, &tieredMG)
	ch.doJSON("POST", "/admin/v1/deployments", adminHeaders, map[string]any{
		"model_group_id": tieredMG["id"], "global_model_id": "openai/gpt-4o-mini",
		"credential_id": c0["id"], "deployment_name": "dep-tier0", "priority": 0, "weight": 100,
	}, nil)
	ch.doJSON("POST", "/admin/v1/deployments", adminHeaders, map[string]any{
		"model_group_id": tieredMG["id"], "global_model_id": "openai/gpt-4o-mini",
		"credential_id": c1["id"], "deployment_name": "dep-tier1", "priority": 1, "weight": 100,
	}, nil)

	ch.doJSON("POST", "/admin/v1/model-groups", adminHeaders, map[string]any{
		"org_id": orgID, "alias": "long-ctx", "routing_strategy": "round-robin",
	}, &longCtxMG)
	ch.doJSON("POST", "/admin/v1/deployments", adminHeaders, map[string]any{
		"model_group_id": longCtxMG["id"], "global_model_id": "openai/gpt-4.1",
		"credential_id": cLong["id"], "deployment_name": "dep-long-ctx", "weight": 100,
	}, nil)

	ch.doJSON("POST", "/admin/v1/model-groups", adminHeaders, map[string]any{
		"org_id": orgID, "alias": "short-ctx", "routing_strategy": "round-robin",
		"context_window_fallbacks": []map[string]any{
			{"target": "long-ctx", "overrides": map[string]any{"max_tokens": 256}},
		},
	}, &shortCtxMG)
	ch.doJSON("POST", "/admin/v1/deployments", adminHeaders, map[string]any{
		"model_group_id": shortCtxMG["id"], "global_model_id": "openai/tiny-ctx",
		"credential_id": c0["id"], "deployment_name": "dep-short-ctx", "weight": 100,
	}, nil)

	var vk domain.VirtualKey
	ch.doJSON("POST", "/admin/v1/keys", adminHeaders, map[string]any{"org_id": orgID, "name": "tier-key"}, &vk)

	// Part A: Priority tiers keep traffic on tier 0 until tier 0 fails, then step down to tier 1.
	for i := 0; i < 4; i++ {
		r, b := postRoutingChat(t, ts, vk.RawKey, map[string]any{
			"model":    "tiered-chat",
			"messages": []map[string]string{{"role": "user", "content": "tier0 healthy"}},
		})
		if r.StatusCode != http.StatusOK {
			t.Fatalf("tier0 request %d failed: %d %s", i, r.StatusCode, string(b))
		}
	}
	if tier0Hits.Load() != 4 || tier1Hits.Load() != 0 {
		t.Fatalf("expected all 4 requests on tier 0 while healthy, got t0=%d t1=%d", tier0Hits.Load(), tier1Hits.Load())
	}

	tier0Fail.Store(true)
	rStep, bStep := postRoutingChat(t, ts, vk.RawKey, map[string]any{
		"model":    "tiered-chat",
		"messages": []map[string]string{{"role": "user", "content": "stepdown"}},
	})
	if rStep.StatusCode != http.StatusOK || tier1Hits.Load() != 1 {
		t.Fatalf("expected stepdown to tier 1 with 200 OK, got status=%d t1=%d body=%s", rStep.StatusCode, tier1Hits.Load(), string(bStep))
	}

	// Part B: Context-window fallback routes oversized prompt to long-ctx with max_tokens=256 override.
	longPrompt := "token-overflow " + string(bytes.Repeat([]byte("word "), 60))
	rCtx, bCtx := postRoutingChat(t, ts, vk.RawKey, map[string]any{
		"model":      "short-ctx",
		"max_tokens": 512,
		"messages":   []map[string]string{{"role": "user", "content": longPrompt}},
	})
	if rCtx.StatusCode != http.StatusOK {
		t.Fatalf("context-window fallback failed: %d %s", rCtx.StatusCode, string(bCtx))
	}
	if rCtx.Header.Get("X-Gateway-Fallback-Attempted") != "true" {
		t.Fatalf("expected X-Gateway-Fallback-Attempted=true on context-window fallback, got %q", rCtx.Header.Get("X-Gateway-Fallback-Attempted"))
	}
	longCtxMu.Lock()
	gotMaxTokens := lastLongCtxMaxTokens
	longCtxMu.Unlock()
	if gotMaxTokens != 256 {
		t.Fatalf("expected FallbackTarget override max_tokens=256 on long-ctx upstream, got %v", gotMaxTokens)
	}
}

// TestE2E_Routing_AdaptiveBanditMultiPod verifies Thompson-sampling adaptive bandit
// learning on Pod 1 syncs via Redis (miniredis) to Pod 2.
func TestE2E_Routing_AdaptiveBanditMultiPod(t *testing.T) {
	ctx := context.Background()
	mr := miniredis.RunT(t)
	repo := storage.NewMemoryRepository()
	vault, _ := auth.NewVault("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	rbac := auth.NewRBACEngine(repo)

	org := &domain.Organization{Name: "BanditE2EOrg", Slug: "bandit-e2e-org", IsActive: true}
	if err := repo.CreateOrganization(ctx, org); err != nil {
		t.Fatalf("CreateOrganization: %v", err)
	}

	fastSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"id":"b-fast","object":"chat.completion","model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"fast-win"},"finish_reason":"stop"}],"usage":{"prompt_tokens":4,"completion_tokens":2,"total_tokens":6}}`)
	}))
	defer fastSrv.Close()

	slowFailSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		fmt.Fprint(w, `{"error":{"message":"slow arm degraded"}}`)
	}))
	defer slowFailSrv.Close()

	fastCred := &domain.ProviderCredential{OrgID: org.ID, Provider: domain.ProviderOpenAI, Name: "fast-c", BaseURL: fastSrv.URL, IsActive: true}
	_ = vault.EncryptCredential(fastCred, "sk-fast")
	_ = repo.CreateProviderCredential(ctx, fastCred)

	slowCred := &domain.ProviderCredential{OrgID: org.ID, Provider: domain.ProviderOpenAI, Name: "slow-c", BaseURL: slowFailSrv.URL, IsActive: true}
	_ = vault.EncryptCredential(slowCred, "sk-slow")
	_ = repo.CreateProviderCredential(ctx, slowCred)

	_ = repo.UpsertGlobalModel(ctx, &domain.GlobalModel{
		ID: "openai/gpt-4o-mini", Provider: domain.ProviderOpenAI, ModelName: "gpt-4o-mini",
		SupportsInference: true, LifecycleStatus: domain.ModelStatusActive, PricingStatus: domain.PricingStatusVerified,
	})

	fastMG := &domain.ModelGroup{OrgID: org.ID, Alias: "bandit-fast", RoutingStrategy: domain.StrategyRoundRobin, IsActive: true}
	_ = repo.CreateModelGroup(ctx, fastMG)
	_ = repo.CreateDeployment(ctx, &domain.Deployment{
		ModelGroupID: fastMG.ID, GlobalModelID: "openai/gpt-4o-mini", CredentialID: fastCred.ID,
		DeploymentName: "b-fast-dep", Status: domain.DeploymentStatusActive,
	})

	slowMG := &domain.ModelGroup{OrgID: org.ID, Alias: "bandit-slow", RoutingStrategy: domain.StrategyRoundRobin, FailureThreshold: 1, CooldownSeconds: 1, IsActive: true}
	_ = repo.CreateModelGroup(ctx, slowMG)
	_ = repo.CreateDeployment(ctx, &domain.Deployment{
		ModelGroupID: slowMG.ID, GlobalModelID: "openai/gpt-4o-mini", CredentialID: slowCred.ID,
		DeploymentName: "b-slow-dep", Status: domain.DeploymentStatusActive,
	})

	pol, err := network.NewPolicy(config.OutboundSSRFConfig{AllowPrivateNetworks: true, AllowInsecureHTTP: true})
	if err != nil {
		t.Fatalf("network.NewPolicy: %v", err)
	}
	adp := openai.NewAdapter(fastSrv.Client())
	adp.SetSSRFPolicy(pol)
	reg := adapter.NewRegistry()
	reg.Register(adp)

	rCfg := config.Default().Router
	rCfg.PreRouterMode = router.PreRouterModeAdaptive
	rCfg.DefaultMaxRetries = 0
	rCfg.Bandit = config.BanditConfig{
		Enabled:         true,
		DefaultAlpha:    1.0,
		DefaultBeta:     1.0,
		ExplorationRate: 0.0,
		LatencyWeight:   0.2,
		CandidateModels: []string{"bandit-fast", "bandit-slow"},
	}

	buildPod := func(seed uint64) (*router.IntelligentRouter, *router.BanditPreRouter, *router.ReliabilityManager) {
		fabric := storage.NewRedisFabric(mr.Addr(), "", 0)
		ir := router.NewIntelligentRouter(repo, rCfg)
		bandit := router.NewBanditPreRouter(
			rCfg,
			fabric,
			router.WithBanditRepository(repo),
			router.WithBanditFlushInterval(20*time.Millisecond),
			router.WithBanditRNG(rand.New(rand.NewPCG(seed, seed+1))),
		)
		ir.SetBanditPreRouter(bandit)
		rm := router.NewReliabilityManager(repo, reg, ir, router.NewLoadBalancer(fabric), vault, rbac, fabric, rCfg)
		return ir, bandit, rm
	}

	// Pod 1 executes requests & records outcomes into miniredis.
	_, bandit1, rm1 := buildPod(101)
	bandit1.Start(ctx)

	for i := 0; i < 20; i++ {
		bandit1.RecordOutcome(org.ID, router.TaskBucketSimpleQA, "bandit-fast", true, 12, false)
		bandit1.RecordOutcome(org.ID, router.TaskBucketSimpleQA, "bandit-slow", false, 500, true)
	}
	// Also verify end-to-end ExecuteChat through Pod 1 updates bandit without errors when fast arm is selected.
	_, _, _ = rm1.ExecuteChat(ctx, &domain.IdentityContext{OrgID: org.ID}, &domain.CanonicalChatRequest{
		Model:    router.VirtualAliasAdaptive,
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "quick question"}},
	})
	bandit1.Stop() // flushes queued rewards to miniredis

	// Pod 2 warms up from shared miniredis and routes overwhelmingly to bandit-fast.
	ir2, bandit2, rm2 := buildPod(202)
	if err := bandit2.WarmupOrg(ctx, org.ID); err != nil {
		t.Fatalf("bandit2.WarmupOrg: %v", err)
	}

	alphaFast, betaFast := bandit2.GetPrior(org.ID, router.TaskBucketSimpleQA, "bandit-fast")
	alphaSlow, betaSlow := bandit2.GetPrior(org.ID, router.TaskBucketSimpleQA, "bandit-slow")
	if alphaFast <= betaFast || betaSlow <= alphaSlow {
		t.Fatalf("expected Pod 2 synced priors to favor bandit-fast (a=%.2f b=%.2f) over bandit-slow (a=%.2f b=%.2f)",
			alphaFast, betaFast, alphaSlow, betaSlow)
	}

	fastSelections := 0
	const trials = 30
	for i := 0; i < trials; i++ {
		dec, err := ir2.ResolveGroup(ctx, org.ID, &domain.CanonicalChatRequest{
			Model:    router.VirtualAliasAdaptive,
			Messages: []domain.CanonicalMessage{{Role: "user", Content: "simple hello"}},
		})
		if err != nil {
			t.Fatalf("ir2.ResolveGroup(%d): %v", i, err)
		}
		if dec.TargetGroupAlias == "bandit-fast" {
			fastSelections++
		}
	}
	if fastSelections < 27 {
		t.Fatalf("expected Pod 2 Thompson sampling to choose bandit-fast >= 27/%d times, got %d", trials, fastSelections)
	}

	resp, meta, err := rm2.ExecuteChat(ctx, &domain.IdentityContext{OrgID: org.ID}, &domain.CanonicalChatRequest{
		Model:    router.VirtualAliasAdaptive,
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "simple hello"}},
	})
	if err != nil || resp == nil {
		t.Fatalf("rm2.ExecuteChat failed: %v", err)
	}
	if meta.RouteDecision == nil || meta.RouteDecision.PreRouterName != router.PreRouterModeAdaptive {
		t.Fatalf("expected adaptive pre-router decision, got %+v", meta.RouteDecision)
	}
}
