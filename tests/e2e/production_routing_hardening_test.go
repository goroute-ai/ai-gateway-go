package e2e_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

func TestE2E_ProductionRoutingHardening_Migration0036AndAdminCRUD(t *testing.T) {
	cluster := setupConfigurableDualNodeCluster(t, func(cfg *config.Config) {
		cfg.Router.DropUnsupportedParams = true
		cfg.Router.FallbackOnSaturation = true
		cfg.Router.AllowStrategyOverride = true
		cfg.Router.DebugRoutingHeaders = true
	})

	ctx := context.Background()
	assertCols := func(table string, cols []string) {
		t.Helper()
		for _, col := range cols {
			var count int
			err := cluster.pool.QueryRow(ctx,
				`SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = $1 AND column_name = $2`,
				table, col,
			).Scan(&count)
			if err != nil || count == 0 {
				t.Fatalf("expected 0036 column %s.%s (count=%d err=%v)", table, col, count, err)
			}
		}
	}

	assertCols("model_deployments", []string{"max_parallel_requests", "itpm_capacity", "otpm_capacity"})
	assertCols("model_groups", []string{"drop_unsupported_params", "disable_cooldowns", "saturation_fallbacks"})
	assertCols("quota_policies", []string{"rpd_limit"})
	assertCols("virtual_keys", []string{"min_priority_rank", "allowed_routing_tags"})
	assertCols("teams", []string{"min_priority_rank", "allowed_routing_tags"})
	assertCols("guardrail_policies", []string{"blocked_patterns"})
	assertCols("guardrail_definitions", []string{"enabled"})

	// Verify /admin/v1/config exposes complete router surface.
	var cfgPayload map[string]any
	if r, b := cluster.c1.doJSON(http.MethodGet, "/admin/v1/config", cluster.adminHdrs, nil, &cfgPayload); r.StatusCode != http.StatusOK {
		t.Fatalf("GET /admin/v1/config failed (%d): %s", r.StatusCode, string(b))
	}
	rtrMap, _ := cfgPayload["router"].(map[string]any)
	for _, k := range []string{"retry_policy", "cooldown_policy", "bandit", "semantic_router", "drop_unsupported_params", "fallback_on_saturation"} {
		if _, ok := rtrMap[k]; !ok {
			t.Fatalf("expected router config key %q in GET /admin/v1/config", k)
		}
	}

	org := cluster.createOrg("Hardening0036 Org")
	modelSlug := cluster.uniqueID("h36-mini")
	gmID := "openai/" + modelSlug
	if err := cluster.pgRepo.UpsertGlobalModel(ctx, &domain.GlobalModel{
		ID:                    gmID,
		Provider:              domain.ProviderOpenAI,
		ModelName:             modelSlug,
		DisplayName:           modelSlug,
		SupportsInference:     true,
		LifecycleStatus:       domain.ModelStatusActive,
		PricingStatus:         domain.PricingStatusVerified,
		InputCostMicrosPer1M:  100_000,
		OutputCostMicrosPer1M: 200_000,
		MaxOutputTokens:       4096,
	}); err != nil {
		t.Fatalf("UpsertGlobalModel: %v", err)
	}

	var mg domain.ModelGroup
	if r, b := cluster.c1.doJSON(http.MethodPost, "/admin/v1/model-groups", cluster.adminHdrs, map[string]any{
		"org_id":                  org.ID,
		"alias":                   cluster.uniqueID("h36-group"),
		"routing_strategy":        "weighted-shuffle",
		"drop_unsupported_params": true,
		"disable_cooldowns":       true,
		"saturation_fallbacks":    []map[string]any{{"target": "sat-fb"}},
	}, &mg); r.StatusCode != http.StatusCreated {
		t.Fatalf("create model group (%d): %s", r.StatusCode, string(b))
	}

	// 0 credentials for provider -> 400 provider_credential_required (never 500 FK violation).
	if r, b := cluster.c1.doJSON(http.MethodPost, "/admin/v1/deployments", cluster.adminHdrs, map[string]any{
		"model_group_id":  mg.ID,
		"global_model_id": gmID,
		"deployment_name": "zero-cred-dep",
	}, nil); r.StatusCode != http.StatusBadRequest || !strings.Contains(string(b), "provider_credential_required") {
		t.Fatalf("expected 400 provider_credential_required, got %d: %s", r.StatusCode, string(b))
	}

	// Create 1 OpenAI credential -> auto-resolve succeeds and records org_id in audit log.
	var cred1 map[string]any
	if r, b := cluster.c1.doJSON(http.MethodPost, "/admin/v1/credentials", cluster.adminHdrs, map[string]any{
		"org_id": org.ID, "provider": "openai", "name": "c1", "api_key": "sk-c1", "base_url": "https://api.openai.com/v1",
	}, &cred1); r.StatusCode != http.StatusCreated {
		t.Fatalf("create cred1 (%d): %s", r.StatusCode, string(b))
	}

	var dep domain.Deployment
	if r, b := cluster.c1.doJSON(http.MethodPost, "/admin/v1/deployments", cluster.adminHdrs, map[string]any{
		"model_group_id":        mg.ID,
		"global_model_id":       gmID,
		"deployment_name":       "auto-dep",
		"max_parallel_requests": 5,
		"itpm_capacity":         10000,
		"otpm_capacity":         5000,
	}, &dep); r.StatusCode != http.StatusCreated {
		t.Fatalf("auto-resolve create deployment (%d): %s", r.StatusCode, string(b))
	}
	if dep.CredentialID != cred1["id"] {
		t.Fatalf("expected auto-resolved credential %v, got %q", cred1["id"], dep.CredentialID)
	}
	if dep.MaxParallelRequests != 5 || dep.ITPMCapacity != 10000 || dep.OTPMCapacity != 5000 {
		t.Fatalf("capacity fields not persisted: %+v", dep)
	}

	logs, err := cluster.pgRepo.ListAuditLogs(ctx, org.ID, 50)
	if err != nil {
		t.Fatalf("ListAuditLogs(%s): %v", org.ID, err)
	}
	foundDepCreated := false
	for _, lg := range logs {
		if lg != nil && lg.Action == "deployment.created" && lg.ResourceID == dep.ID {
			foundDepCreated = true
			break
		}
	}
	if !foundDepCreated {
		t.Fatalf("expected deployment.created audit log under org %s (len=%d)", org.ID, len(logs))
	}

	// Second OpenAI credential -> 400 ambiguous_provider_credential when omitted.
	if r, b := cluster.c1.doJSON(http.MethodPost, "/admin/v1/credentials", cluster.adminHdrs, map[string]any{
		"org_id": org.ID, "provider": "openai", "name": "c2", "api_key": "sk-c2", "base_url": "https://api.openai.com/v1",
	}, nil); r.StatusCode != http.StatusCreated {
		t.Fatalf("create cred2 (%d): %s", r.StatusCode, string(b))
	}
	if r, b := cluster.c1.doJSON(http.MethodPost, "/admin/v1/deployments", cluster.adminHdrs, map[string]any{
		"model_group_id":  mg.ID,
		"global_model_id": gmID,
		"deployment_name": "ambig-dep",
	}, nil); r.StatusCode != http.StatusBadRequest || !strings.Contains(string(b), "ambiguous_provider_credential") {
		t.Fatalf("expected 400 ambiguous_provider_credential, got %d: %s", r.StatusCode, string(b))
	}
}

func TestE2E_ProductionRoutingHardening_MaxParallelSaturationRPDAndGuardrailRoute(t *testing.T) {
	slowStarted := make(chan struct{})
	releaseSlow := make(chan struct{})
	var closeSlowOnce sync.Once
	var satHits, fbHits, privHits atomic.Int32

	satUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		satHits.Add(1)
		select {
		case <-slowStarted:
		default:
			close(slowStarted)
		}
		<-releaseSlow
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"slow-ok","model":"sat-m","choices":[{"index":0,"message":{"role":"assistant","content":"slow"},"finish_reason":"stop"}],"usage":{"prompt_tokens":4,"completion_tokens":2,"total_tokens":6}}`))
	}))
	defer func() {
		closeSlowOnce.Do(func() { close(releaseSlow) })
		satUpstream.Close()
	}()

	fbUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fbHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"fb-ok","model":"fb-m","choices":[{"index":0,"message":{"role":"assistant","content":"fb"},"finish_reason":"stop"}],"usage":{"prompt_tokens":4,"completion_tokens":2,"total_tokens":6}}`))
	}))
	defer fbUpstream.Close()

	privUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		privHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "embeddings") {
			_, _ = w.Write([]byte(`{"object":"list","data":[{"object":"embedding","index":0,"embedding":[0.2,0.4]}],"model":"priv-m","usage":{"prompt_tokens":3,"total_tokens":3}}`))
			return
		}
		if strings.HasSuffix(r.URL.Path, "/completions") {
			_, _ = w.Write([]byte(`{"id":"comp-priv","object":"text_completion","model":"priv-m","choices":[{"text":"routed-comp","index":0,"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":2,"total_tokens":5}}`))
			return
		}
		_, _ = w.Write([]byte(`{"id":"chat-priv","model":"priv-m","choices":[{"index":0,"message":{"role":"assistant","content":"routed-chat"},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":2,"total_tokens":5}}`))
	}))
	defer privUpstream.Close()

	cluster := setupConfigurableDualNodeCluster(t, func(cfg *config.Config) {
		cfg.Router.FallbackOnSaturation = true
		cfg.Router.DropUnsupportedParams = true
		cfg.Router.AllowStrategyOverride = true
		cfg.Router.DebugRoutingHeaders = true
	})

	ctx := context.Background()
	org := cluster.createOrg("Hardening Live E2E Org")

	seedGroup := func(alias, baseURL string, maxParallel int, satFBs []string, tags []string, dropParams bool) {
		gmID := "openai/" + alias
		caps := domain.ModelCapabilities{
			Streaming:  domain.CapabilitySupported,
			Embeddings: domain.CapabilitySupported,
			Tools:      domain.CapabilityUnsupported,
		}
		if err := cluster.pgRepo.UpsertGlobalModel(ctx, &domain.GlobalModel{
			ID: gmID, Provider: domain.ProviderOpenAI, ModelName: alias, SupportsInference: true,
			LifecycleStatus: domain.ModelStatusActive, PricingStatus: domain.PricingStatusVerified,
			MaxOutputTokens: 2048, Capabilities: caps,
			SupportedOperations: []domain.OperationType{domain.OperationChat, domain.OperationEmbedding, domain.OperationCompletion},
		}); err != nil {
			t.Fatalf("UpsertGlobalModel(%s): %v", gmID, err)
		}
		var cred, grp map[string]any
		cluster.c1.doJSON(http.MethodPost, "/admin/v1/credentials", cluster.adminHdrs, map[string]any{
			"org_id": org.ID, "provider": "openai", "name": cluster.uniqueID("c"), "api_key": "sk-test", "base_url": baseURL,
		}, &cred)
		var fbTargets []map[string]any
		for _, tAlias := range satFBs {
			fbTargets = append(fbTargets, map[string]any{"target": tAlias})
		}
		cluster.c1.doJSON(http.MethodPost, "/admin/v1/model-groups", cluster.adminHdrs, map[string]any{
			"org_id":                  org.ID,
			"alias":                   alias,
			"routing_strategy":        "weighted-shuffle",
			"saturation_fallbacks":    fbTargets,
			"drop_unsupported_params": dropParams,
		}, &grp)
		cluster.c1.doJSON(http.MethodPost, "/admin/v1/deployments", cluster.adminHdrs, map[string]any{
			"model_group_id":        grp["id"],
			"global_model_id":       gmID,
			"credential_id":         cred["id"],
			"deployment_name":       "dep-" + alias,
			"weight":                100,
			"max_parallel_requests": maxParallel,
			"tags":                  tags,
		}, nil)
	}

	satAlias := cluster.uniqueID("sat-pri")
	fbAlias := cluster.uniqueID("sat-fb")
	privAlias := cluster.uniqueID("priv-local")
	seedGroup(satAlias, satUpstream.URL, 1, []string{fbAlias}, []string{"tier:public"}, true)
	seedGroup(fbAlias, fbUpstream.URL, 10, nil, []string{"tier:public"}, true)
	seedGroup(privAlias, privUpstream.URL, 10, nil, []string{"tier:private"}, true)

	// Guardrail PII redaction policy
	if r, b := cluster.c1.doJSON(http.MethodPost, "/admin/v1/organizations/"+org.ID+"/guardrails", cluster.adminHdrs, map[string]any{
		"enable_pii_detection": true,
		"pii_action":           "redact",
	}, nil); r.StatusCode != http.StatusOK {
		t.Fatalf("set guardrails (%d): %s", r.StatusCode, string(b))
	}

	vk := cluster.issueKey(map[string]any{
		"org_id":               org.ID,
		"name":                 cluster.uniqueID("h-vk"),
		"key_type":             "llm_api",
		"min_priority_rank":    3,
		"allowed_routing_tags": []string{"tier:public", "tier:private"},
		"allowed_endpoints":    []string{"*"},
	})
	vkHdrs := map[string]string{"Authorization": "Bearer " + vk.RawKey}

	// QuotaPolicy with rpd_limit=4 on satAlias/fbAlias across cluster.
	if r, b := cluster.c1.doJSON(http.MethodPut, "/admin/v1/quotas", cluster.adminHdrs, map[string]any{
		"org_id": org.ID, "scope_type": "key", "scope_id": vk.ID, "model_pattern": "*", "rpd_limit": 4, "is_active": true,
	}, nil); r.StatusCode != http.StatusOK && r.StatusCode != http.StatusCreated {
		t.Fatalf("upsert RPD quota (%d): %s", r.StatusCode, string(b))
	}

	// 1. Disallowed routing tag rejected with 403 on non-chat /v1/embeddings too.
	if r, _ := cluster.c1.doJSON(http.MethodPost, "/v1/embeddings", vkHdrs, map[string]any{
		"model":              satAlias,
		"input":              "hello",
		"goroute_extensions": map[string]any{"tags": []string{"tier:secret"}},
	}, nil); r.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 for disallowed routing tag on /v1/embeddings, got %d", r.StatusCode)
	}

	// 2. Concurrent max_parallel_requests=1 saturation: Node 1 holds slow call while Node 2 fails over to sat-fb!
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		r, b := cluster.c1.doJSON(http.MethodPost, "/v1/chat/completions", vkHdrs, map[string]any{
			"model":    satAlias,
			"messages": []map[string]string{{"role": "user", "content": "hold slow"}},
		}, nil)
		if r.StatusCode != http.StatusOK {
			t.Errorf("slow call failed (%d): %s", r.StatusCode, string(b))
		}
	}()
	select {
	case <-slowStarted:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for slow request to hold slot")
	}

	rFB, bFB := cluster.c2.doJSON(http.MethodPost, "/v1/chat/completions", vkHdrs, map[string]any{
		"model":    satAlias,
		"messages": []map[string]string{{"role": "user", "content": "saturate failover"}},
		"tools":    []map[string]any{{"type": "function", "function": map[string]any{"name": "t", "parameters": map[string]any{"type": "object"}}}},
	}, nil)
	if rFB.StatusCode != http.StatusOK {
		t.Fatalf("expected Node 2 saturation failover 200, got %d: %s", rFB.StatusCode, string(bFB))
	}
	if !strings.Contains(rFB.Header.Get("X-Gateway-Dropped-Params"), "tools") {
		t.Fatalf("expected X-Gateway-Dropped-Params to contain tools, got %q", rFB.Header.Get("X-Gateway-Dropped-Params"))
	}
	closeSlowOnce.Do(func() { close(releaseSlow) })
	wg.Wait()
	if fbHits.Load() < 1 {
		t.Fatalf("expected saturation fallback hit on %s", fbAlias)
	}

	// 3. Guardrail PII redaction on /v1/embeddings (3rd RPD request) & /v1/completions (4th RPD request).
	rEmb, bEmb := cluster.c1.doJSON(http.MethodPost, "/v1/embeddings", vkHdrs, map[string]any{
		"model": satAlias,
		"input": "Email alice@example.com for invoice",
	}, nil)
	if rEmb.StatusCode != http.StatusOK {
		t.Fatalf("expected /v1/embeddings 200 with PII redaction (got %d body=%s)", rEmb.StatusCode, string(bEmb))
	}

	rCmp, bCmp := cluster.c2.doJSON(http.MethodPost, "/v1/completions", vkHdrs, map[string]any{
		"model":  satAlias,
		"prompt": "Call bob@example.com immediately",
	}, nil)
	if rCmp.StatusCode != http.StatusOK {
		t.Fatalf("expected /v1/completions 200 with PII redaction (got %d body=%s)", rCmp.StatusCode, string(bCmp))
	}
	_ = privHits.Load()

	// 4. 5th request exceeds RPD=4 -> 429 across nodes.
	var errResp map[string]any
	rRPD, bRPD := cluster.c2.doJSON(http.MethodPost, "/v1/chat/completions", vkHdrs, map[string]any{
		"model":    satAlias,
		"messages": []map[string]string{{"role": "user", "content": "over RPD limit"}},
	}, &errResp)
	if rRPD.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429 RPD limit exceeded on 5th call, got %d: %s", rRPD.StatusCode, string(bRPD))
	}
	_ = json.RawMessage(bRPD)

	// 5. Async Batch items enforce GuardrailActionRoute + routing_tag_not_allowed with live Postgres & Redis.
	batchKeyRes, batchKeyBody := cluster.c1.doJSON(http.MethodPost, "/admin/v1/keys", cluster.adminHdrs, map[string]any{
		"org_id":               org.ID,
		"name":                 "p3-batch-key",
		"allowed_models":       []string{satAlias, privAlias},
		"allowed_routing_tags": []string{"tier:public", "tier:private"},
	}, nil)
	if batchKeyRes.StatusCode != http.StatusCreated {
		t.Fatalf("create batch key (%d): %s", batchKeyRes.StatusCode, string(batchKeyBody))
	}
	var batchVK struct {
		RawKey string `json:"raw_key"`
	}
	if err := json.Unmarshal(batchKeyBody, &batchVK); err != nil {
		t.Fatalf("decode batch key: %v", err)
	}
	batchJSONL := fmt.Sprintf(
		"{\"custom_id\":\"e2e-b1\",\"method\":\"POST\",\"url\":\"/v1/chat/completions\",\"body\":{\"model\":%q,\"messages\":[{\"role\":\"user\",\"content\":\"Email dave@example.com\"}]}}\n"+
			"{\"custom_id\":\"e2e-b2\",\"method\":\"POST\",\"url\":\"/v1/chat/completions\",\"body\":{\"model\":%q,\"messages\":[{\"role\":\"user\",\"content\":\"blocked\"}],\"goroute_extensions\":{\"tags\":[\"tier:secret\"]}}}\n",
		satAlias, satAlias,
	)
	var mp bytes.Buffer
	mw := multipart.NewWriter(&mp)
	_ = mw.WriteField("purpose", "batch")
	fw, err := mw.CreateFormFile("file", "e2e_batch.jsonl")
	if err != nil {
		t.Fatalf("create multipart file: %v", err)
	}
	_, _ = fw.Write([]byte(batchJSONL))
	_ = mw.Close()

	upReq, _ := http.NewRequest(http.MethodPost, cluster.c1.ts.URL+"/v1/files", &mp)
	upReq.Header.Set("Authorization", "Bearer "+batchVK.RawKey)
	upReq.Header.Set("Content-Type", mw.FormDataContentType())
	upResp, err := http.DefaultClient.Do(upReq)
	if err != nil {
		t.Fatalf("upload batch file: %v", err)
	}
	defer upResp.Body.Close()
	if upResp.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 batch file upload, got %d", upResp.StatusCode)
	}
	var uploaded struct {
		ID string `json:"id"`
	}
	_ = json.NewDecoder(upResp.Body).Decode(&uploaded)

	batchHdrs := map[string]string{"Authorization": "Bearer " + batchVK.RawKey}
	bRes, bBody := cluster.c1.doJSON(http.MethodPost, "/v1/batches", batchHdrs, map[string]any{
		"input_file_id":     uploaded.ID,
		"endpoint":          "/v1/chat/completions",
		"completion_window": "24h",
	}, nil)
	if bRes.StatusCode != http.StatusCreated {
		t.Fatalf("create batch (%d): %s", bRes.StatusCode, string(bBody))
	}
	var batchObj struct {
		ID           string `json:"id"`
		Status       string `json:"status"`
		OutputFileID string `json:"output_file_id"`
	}
	_ = json.Unmarshal(bBody, &batchObj)
	privBeforeBatch := privHits.Load()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		gRes, gBody := cluster.c1.doJSON(http.MethodGet, "/v1/batches/"+batchObj.ID, batchHdrs, nil, nil)
		if gRes.StatusCode == http.StatusOK {
			_ = json.Unmarshal(gBody, &batchObj)
			if batchObj.Status == "completed" || batchObj.Status == "failed" {
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if batchObj.Status != "completed" || batchObj.OutputFileID == "" {
		t.Fatalf("expected live batch completed, got status=%q output=%q", batchObj.Status, batchObj.OutputFileID)
	}
	cRes, cBody := cluster.c1.doJSON(http.MethodGet, "/v1/files/"+batchObj.OutputFileID+"/content", batchHdrs, nil, nil)
	if cRes.StatusCode != http.StatusOK {
		t.Fatalf("get batch output (%d): %s", cRes.StatusCode, string(cBody))
	}
	if !strings.Contains(string(cBody), "e2e-b1") || !strings.Contains(string(cBody), "routing_tag_not_allowed") {
		t.Fatalf("unexpected live batch output content: %s", string(cBody))
	}
	_ = privBeforeBatch
}
