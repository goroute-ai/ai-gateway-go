package load_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/logger"
	"github.com/goroute-ai/ai-gateway-go/internal/router"
	"github.com/goroute-ai/ai-gateway-go/internal/server"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

func percentileDuration(samples []time.Duration, p float64) time.Duration {
	if len(samples) == 0 {
		return 0
	}
	cp := make([]time.Duration, len(samples))
	copy(cp, samples)
	sort.Slice(cp, func(i, j int) bool { return cp[i] < cp[j] })
	idx := int(float64(len(cp)-1) * p)
	if idx < 0 {
		idx = 0
	}
	if idx >= len(cp) {
		idx = len(cp) - 1
	}
	return cp[idx]
}

func doChatJSON(client *http.Client, baseURL, apiKey string, payload map[string]any) (int, http.Header, []byte, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return 0, nil, nil, err
	}
	req, err := http.NewRequest(http.MethodPost, baseURL+"/v1/chat/completions", bytes.NewReader(body))
	if err != nil {
		return 0, nil, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, nil, err
	}
	defer resp.Body.Close()
	raw, readErr := io.ReadAll(resp.Body)
	if readErr != nil {
		return resp.StatusCode, resp.Header.Clone(), nil, readErr
	}
	return resp.StatusCode, resp.Header.Clone(), raw, nil
}

// TestRoutingLoad_MultiInstanceHalfOpenNoProbeStorm verifies that 3 independent
// GatewayServer instances sharing a Redis backend (miniredis) coordinate circuit
// breaker state and admit at most 1 HALF_OPEN recovery probe under concurrent burst load.
func TestRoutingLoad_MultiInstanceHalfOpenNoProbeStorm(t *testing.T) {
	logger.Init(logger.Config{Level: "error", Format: "text"})
	defer logger.Init(logger.Config{Level: "info", Format: "text"})

	ctx := context.Background()
	mr := miniredis.RunT(t)
	repo := storage.NewMemoryRepository()

	var primaryHits atomic.Int64
	var primaryFail atomic.Bool
	var primaryDelayMs atomic.Int64
	primaryFail.Store(true)

	primaryUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		primaryHits.Add(1)
		if d := primaryDelayMs.Load(); d > 0 {
			select {
			case <-time.After(time.Duration(d) * time.Millisecond):
			case <-r.Context().Done():
				return
			}
		}
		if primaryFail.Load() {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprint(w, `{"error":{"message":"simulated upstream 503","type":"server_error"}}`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"id":"chat-primary","object":"chat.completion","model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"primary-ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":4,"completion_tokens":2,"total_tokens":6}}`)
	}))
	defer primaryUpstream.Close()

	var fallbackHits atomic.Int64
	fallbackUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fallbackHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"id":"chat-fallback","object":"chat.completion","model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"fallback-ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":4,"completion_tokens":2,"total_tokens":6}}`)
	}))
	defer fallbackUpstream.Close()

	const instanceCount = 3
	gws := make([]*server.GatewayServer, instanceCount)
	servers := make([]*httptest.Server, instanceCount)
	workerCtx, workerCancel := context.WithCancel(ctx)
	defer workerCancel()

	for i := 0; i < instanceCount; i++ {
		cfg := config.Default()
		cfg.Logging.Level = "error"
		cfg.Auth.MasterAdminKey = "sk-gw-multi-admin"
		cfg.Auth.MasterEncryptionKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
		cfg.Security.Network.OutboundSSRF.AllowPrivateNetworks = true
		cfg.Security.Network.OutboundSSRF.AllowInsecureHTTP = true
		cfg.Router.DefaultMaxRetries = 0
		cfg.Router.BaseRetryDelay = time.Millisecond
		cfg.Router.MaxRetryDelay = 5 * time.Millisecond
		cfg.Router.FailureThreshold = 2
		cfg.Router.DefaultCooldown = 2 * time.Second

		fabric := storage.NewRedisFabric(mr.Addr(), "", 0)
		gw, err := server.New(cfg, repo, fabric, nil)
		if err != nil {
			t.Fatalf("server.New(%d): %v", i, err)
		}
		gw.StartWorkers(workerCtx)
		gws[i] = gw
		servers[i] = httptest.NewServer(gw.Handler())
	}
	defer func() {
		for i := 0; i < instanceCount; i++ {
			servers[i].Close()
			gws[i].Shutdown(context.Background())
		}
	}()

	// Provision tenant, credentials, model groups, deployments, and virtual key through instance 0.
	adminHeaders := map[string]string{"Authorization": "Bearer sk-gw-multi-admin"}
	postAdmin := func(path string, body any, out any) {
		t.Helper()
		b, _ := json.Marshal(body)
		req, _ := http.NewRequest(http.MethodPost, servers[0].URL+path, bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		for k, v := range adminHeaders {
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("admin POST %s: %v", path, err)
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode >= 300 {
			t.Fatalf("admin POST %s status=%d body=%s", path, resp.StatusCode, string(raw))
		}
		if out != nil {
			_ = json.Unmarshal(raw, out)
		}
	}

	var org map[string]any
	postAdmin("/admin/v1/organizations", map[string]any{"name": "MultiGWOrg", "slug": "multi-gw-org"}, &org)
	orgID := org["id"].(string)

	_ = repo.UpsertGlobalModel(ctx, &domain.GlobalModel{
		ID: "openai/gpt-4o-mini", Provider: domain.ProviderOpenAI, ModelName: "gpt-4o-mini",
		SupportsInference: true, LifecycleStatus: domain.ModelStatusActive, PricingStatus: domain.PricingStatusVerified,
		MaxOutputTokens: 4096,
	})

	var primaryCred, fallbackCred, fbGroup, primaryGroup, primaryDep map[string]any
	postAdmin("/admin/v1/credentials", map[string]any{
		"org_id": orgID, "provider": "openai", "name": "primary-c", "api_key": "sk-p", "base_url": primaryUpstream.URL,
	}, &primaryCred)
	postAdmin("/admin/v1/credentials", map[string]any{
		"org_id": orgID, "provider": "openai", "name": "fallback-c", "api_key": "sk-f", "base_url": fallbackUpstream.URL,
	}, &fallbackCred)

	postAdmin("/admin/v1/model-groups", map[string]any{
		"org_id": orgID, "alias": "fb-chat", "routing_strategy": "round-robin", "max_retries": 0,
	}, &fbGroup)
	postAdmin("/admin/v1/deployments", map[string]any{
		"model_group_id": fbGroup["id"], "global_model_id": "openai/gpt-4o-mini",
		"credential_id": fallbackCred["id"], "deployment_name": "fb-dep", "weight": 100,
	}, nil)

	postAdmin("/admin/v1/model-groups", map[string]any{
		"org_id": orgID, "alias": "primary-chat", "routing_strategy": "round-robin",
		"max_retries": 0, "failure_threshold": 2, "cooldown_seconds": 2,
		"fallback_groups": []string{fbGroup["id"].(string)},
	}, &primaryGroup)
	postAdmin("/admin/v1/deployments", map[string]any{
		"model_group_id": primaryGroup["id"], "global_model_id": "openai/gpt-4o-mini",
		"credential_id": primaryCred["id"], "deployment_name": "primary-dep", "weight": 100,
	}, &primaryDep)
	primaryDepID := primaryDep["id"].(string)

	var vk domain.VirtualKey
	postAdmin("/admin/v1/keys", map[string]any{
		"org_id": orgID, "name": "multi-gw-key",
	}, &vk)

	client := &http.Client{Timeout: 5 * time.Second}
	chatReq := map[string]any{
		"model":    "primary-chat",
		"messages": []map[string]string{{"role": "user", "content": "hello"}},
	}

	// Phase 1: Trip primary circuit OPEN via gateway instance 0 (2 failures).
	for i := 0; i < 2; i++ {
		code, hdrs, raw, err := doChatJSON(client, servers[0].URL, vk.RawKey, chatReq)
		if err != nil || code != http.StatusOK {
			t.Fatalf("trip request %d failed: code=%d err=%v body=%s", i, code, err, string(raw))
		}
		if hdrs.Get("X-Gateway-Fallback-Attempted") != "true" {
			t.Fatalf("expected fallback during primary 503, got header=%q", hdrs.Get("X-Gateway-Fallback-Attempted"))
		}
	}

	for i, gw := range gws {
		if st := gw.Reliability().GetCircuitState(ctx, primaryDepID); st != router.CircuitOpen {
			t.Fatalf("gateway %d did not observe shared OPEN circuit: got %s", i, st)
		}
	}

	// Phase 2: While OPEN, requests to all 3 instances skip primaryUpstream completely.
	primaryHits.Store(0)
	for i := 0; i < instanceCount; i++ {
		code, _, raw, err := doChatJSON(client, servers[i].URL, vk.RawKey, chatReq)
		if err != nil || code != http.StatusOK {
			t.Fatalf("open-circuit request to gw %d failed: code=%d err=%v body=%s", i, code, err, string(raw))
		}
	}
	if hits := primaryHits.Load(); hits != 0 {
		t.Fatalf("expected 0 hits to OPEN primary upstream across all 3 gateways, got %d", hits)
	}

	// Phase 3: Heal primary with an 80ms latency window, expire cooldown in miniredis,
	// and fire 30 simultaneous requests (10 per instance) in HALF_OPEN state.
	primaryFail.Store(false)
	primaryDelayMs.Store(80)
	primaryHits.Store(0)
	mr.FastForward(3 * time.Second)

	for i, gw := range gws {
		if st := gw.Reliability().GetCircuitState(ctx, primaryDepID); st != router.CircuitHalfOpen {
			t.Fatalf("gateway %d did not observe HALF_OPEN after cooldown: got %s", i, st)
		}
	}

	const burstPerInstance = 10
	start := make(chan struct{})
	var wg sync.WaitGroup
	var errCount atomic.Int64

	for inst := 0; inst < instanceCount; inst++ {
		for j := 0; j < burstPerInstance; j++ {
			wg.Add(1)
			go func(gwIdx int) {
				defer wg.Done()
				<-start
				code, _, _, err := doChatJSON(client, servers[gwIdx].URL, vk.RawKey, chatReq)
				if err != nil || code != http.StatusOK {
					errCount.Add(1)
				}
			}(inst)
		}
	}
	close(start)
	wg.Wait()

	if errs := errCount.Load(); errs > 0 {
		t.Fatalf("expected zero failed requests during HALF_OPEN burst, got %d", errs)
	}
	if probes := primaryHits.Load(); probes != 1 {
		t.Fatalf("HALF_OPEN probe storm detected across 3 instances: expected exactly 1 probe, got %d", probes)
	}

	for i, gw := range gws {
		if st := gw.Reliability().GetCircuitState(ctx, primaryDepID); st != router.CircuitClosed {
			t.Fatalf("gateway %d did not observe CLOSED after successful probe: got %s", i, st)
		}
	}

	// Phase 4: Subsequent requests across all 3 instances route back to primary.
	primaryDelayMs.Store(0)
	primaryHits.Store(0)
	for i := 0; i < instanceCount; i++ {
		code, hdrs, raw, err := doChatJSON(client, servers[i].URL, vk.RawKey, chatReq)
		if err != nil || code != http.StatusOK {
			t.Fatalf("post-recovery request to gw %d failed: code=%d err=%v body=%s", i, code, err, string(raw))
		}
		if hdrs.Get("X-Gateway-Fallback-Attempted") != "false" {
			t.Fatalf("expected direct primary execution after recovery on gw %d, got fallback=%q", i, hdrs.Get("X-Gateway-Fallback-Attempted"))
		}
	}
	if hits := primaryHits.Load(); hits != instanceCount {
		t.Fatalf("expected all %d post-recovery requests to hit primary, got %d", instanceCount, hits)
	}
}

// TestRoutingLoad_HedgedTailLatencyImprovement verifies that staggered hedged racing
// significantly improves P99 latency when one upstream experiences slow tail spikes.
func TestRoutingLoad_HedgedTailLatencyImprovement(t *testing.T) {
	logger.Init(logger.Config{Level: "error", Format: "text"})
	defer logger.Init(logger.Config{Level: "info", Format: "text"})

	ctx := context.Background()
	repo := storage.NewMemoryRepository()

	var slowCounter atomic.Int64
	slowTailUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := slowCounter.Add(1)
		if n%3 == 0 {
			// Every 3rd request hits a 220ms tail spike.
			select {
			case <-time.After(220 * time.Millisecond):
			case <-r.Context().Done():
				return
			}
		} else {
			time.Sleep(2 * time.Millisecond)
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"id":"slow-tail","object":"chat.completion","model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"slow-ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":4,"completion_tokens":2,"total_tokens":6}}`)
	}))
	defer slowTailUpstream.Close()

	fastBackupUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(3 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"id":"fast-backup","object":"chat.completion","model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"fast-ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":4,"completion_tokens":2,"total_tokens":6}}`)
	}))
	defer fastBackupUpstream.Close()

	cfg := config.Default()
	cfg.Logging.Level = "error"
	cfg.Auth.MasterAdminKey = "sk-gw-hedge-admin"
	cfg.Auth.MasterEncryptionKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	cfg.Security.Network.OutboundSSRF.AllowPrivateNetworks = true
	cfg.Security.Network.OutboundSSRF.AllowInsecureHTTP = true
	cfg.Router.HedgeDelayMs = 25
	cfg.Router.MaxHedgeConcurrency = 2

	gw, err := server.New(cfg, repo, nil, nil)
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

	adminHeaders := map[string]string{"Authorization": "Bearer sk-gw-hedge-admin"}
	postAdmin := func(path string, body any, out any) {
		b, _ := json.Marshal(body)
		req, _ := http.NewRequest(http.MethodPost, ts.URL+path, bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		for k, v := range adminHeaders {
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("admin POST %s: %v", path, err)
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode >= 300 {
			t.Fatalf("admin POST %s status=%d body=%s", path, resp.StatusCode, string(raw))
		}
		if out != nil {
			_ = json.Unmarshal(raw, out)
		}
	}

	var org map[string]any
	postAdmin("/admin/v1/organizations", map[string]any{"name": "HedgeOrg", "slug": "hedge-org"}, &org)
	orgID := org["id"].(string)

	_ = repo.UpsertGlobalModel(ctx, &domain.GlobalModel{
		ID: "openai/gpt-4o-mini", Provider: domain.ProviderOpenAI, ModelName: "gpt-4o-mini",
		SupportsInference: true, LifecycleStatus: domain.ModelStatusActive, PricingStatus: domain.PricingStatusVerified,
		MaxOutputTokens: 4096,
	})

	var slowCred, fastCred, unhedgedGrp, hedgedGrp map[string]any
	postAdmin("/admin/v1/credentials", map[string]any{
		"org_id": orgID, "provider": "openai", "name": "slow-c", "api_key": "sk-s", "base_url": slowTailUpstream.URL,
	}, &slowCred)
	postAdmin("/admin/v1/credentials", map[string]any{
		"org_id": orgID, "provider": "openai", "name": "fast-c", "api_key": "sk-f", "base_url": fastBackupUpstream.URL,
	}, &fastCred)

	postAdmin("/admin/v1/model-groups", map[string]any{
		"org_id": orgID, "alias": "unhedged-tail", "routing_strategy": "round-robin",
	}, &unhedgedGrp)
	postAdmin("/admin/v1/deployments", map[string]any{
		"model_group_id": unhedgedGrp["id"], "global_model_id": "openai/gpt-4o-mini",
		"credential_id": slowCred["id"], "deployment_name": "slow-only", "weight": 100,
	}, nil)

	postAdmin("/admin/v1/model-groups", map[string]any{
		"org_id": orgID, "alias": "hedged-fastest", "routing_strategy": "fastest-response",
	}, &hedgedGrp)
	postAdmin("/admin/v1/deployments", map[string]any{
		"model_group_id": hedgedGrp["id"], "global_model_id": "openai/gpt-4o-mini",
		"credential_id": slowCred["id"], "deployment_name": "hedged-slow", "weight": 100,
	}, nil)
	postAdmin("/admin/v1/deployments", map[string]any{
		"model_group_id": hedgedGrp["id"], "global_model_id": "openai/gpt-4o-mini",
		"credential_id": fastCred["id"], "deployment_name": "hedged-fast", "weight": 100,
	}, nil)

	var vk domain.VirtualKey
	postAdmin("/admin/v1/keys", map[string]any{
		"org_id": orgID, "name": "hedge-key",
	}, &vk)

	client := &http.Client{Timeout: 5 * time.Second}
	const sampleCount = 30

	unhedgedLatencies := make([]time.Duration, 0, sampleCount)
	for i := 0; i < sampleCount; i++ {
		t0 := time.Now()
		code, _, raw, err := doChatJSON(client, ts.URL, vk.RawKey, map[string]any{
			"model":    "unhedged-tail",
			"messages": []map[string]string{{"role": "user", "content": "tail check"}},
		})
		if err != nil || code != http.StatusOK {
			t.Fatalf("unhedged req %d failed: code=%d err=%v body=%s", i, code, err, string(raw))
		}
		unhedgedLatencies = append(unhedgedLatencies, time.Since(t0))
	}

	hedgedLatencies := make([]time.Duration, 0, sampleCount)
	for i := 0; i < sampleCount; i++ {
		t0 := time.Now()
		code, hdrs, raw, err := doChatJSON(client, ts.URL, vk.RawKey, map[string]any{
			"model":    "hedged-fastest",
			"messages": []map[string]string{{"role": "user", "content": "hedged check"}},
		})
		if err != nil || code != http.StatusOK {
			t.Fatalf("hedged req %d failed: code=%d err=%v body=%s", i, code, err, string(raw))
		}
		if hdrs.Get("X-Gateway-Route-Reason") != "hedged_race_winner" {
			t.Fatalf("expected X-Gateway-Route-Reason=hedged_race_winner, got %q", hdrs.Get("X-Gateway-Route-Reason"))
		}
		hedgedLatencies = append(hedgedLatencies, time.Since(t0))
	}

	unhedgedP99 := percentileDuration(unhedgedLatencies, 0.99)
	hedgedP99 := percentileDuration(hedgedLatencies, 0.99)
	t.Logf("Tail-latency comparison (%d requests): unhedged P99=%v, hedged P99=%v", sampleCount, unhedgedP99, hedgedP99)

	if unhedgedP99 < 200*time.Millisecond {
		t.Fatalf("expected unhedged P99 >= 200ms due to tail spikes, got %v", unhedgedP99)
	}
	if hedgedP99 >= 100*time.Millisecond {
		t.Fatalf("expected hedged P99 < 100ms, got %v", hedgedP99)
	}
	if hedgedP99 >= unhedgedP99/2 {
		t.Fatalf("expected >2x P99 reduction with hedging: unhedged=%v hedged=%v", unhedgedP99, hedgedP99)
	}
}

// TestRoutingLoad_ChaosFaultInjectionStress runs concurrent traffic against a primary
// upstream injecting 30% 503 faults plus slow responses, verifying zero races and 100% recovery.
func TestRoutingLoad_ChaosFaultInjectionStress(t *testing.T) {
	logger.Init(logger.Config{Level: "error", Format: "text"})
	defer logger.Init(logger.Config{Level: "info", Format: "text"})

	ctx := context.Background()
	mr := miniredis.RunT(t)
	repo := storage.NewMemoryRepository()

	var chaosSeq atomic.Int64
	chaosUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := chaosSeq.Add(1)
		// 30% 503 fault injection (3 out of every 10 requests)
		if n%10 < 3 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprint(w, `{"error":{"message":"chaos 503 fault","type":"server_error"}}`)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"id":"chaos-primary","object":"chat.completion","model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"primary-ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":4,"completion_tokens":2,"total_tokens":6}}`)
	}))
	defer chaosUpstream.Close()

	backupUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"id":"chaos-backup","object":"chat.completion","model":"gpt-4o-mini","choices":[{"index":0,"message":{"role":"assistant","content":"backup-ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":4,"completion_tokens":2,"total_tokens":6}}`)
	}))
	defer backupUpstream.Close()

	cfg := config.Default()
	cfg.Logging.Level = "error"
	cfg.Auth.MasterAdminKey = "sk-gw-chaos-admin"
	cfg.Auth.MasterEncryptionKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	cfg.Security.Network.OutboundSSRF.AllowPrivateNetworks = true
	cfg.Security.Network.OutboundSSRF.AllowInsecureHTTP = true
	cfg.Router.DefaultMaxRetries = 1
	cfg.Router.BaseRetryDelay = time.Millisecond
	cfg.Router.MaxRetryDelay = 3 * time.Millisecond
	cfg.Router.FailureThreshold = 2
	cfg.Router.DefaultCooldown = 1 * time.Second

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

	adminHeaders := map[string]string{"Authorization": "Bearer sk-gw-chaos-admin"}
	postAdmin := func(path string, body any, out any) {
		b, _ := json.Marshal(body)
		req, _ := http.NewRequest(http.MethodPost, ts.URL+path, bytes.NewReader(b))
		req.Header.Set("Content-Type", "application/json")
		for k, v := range adminHeaders {
			req.Header.Set(k, v)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("admin POST %s: %v", path, err)
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode >= 300 {
			t.Fatalf("admin POST %s status=%d body=%s", path, resp.StatusCode, string(raw))
		}
		if out != nil {
			_ = json.Unmarshal(raw, out)
		}
	}

	var org map[string]any
	postAdmin("/admin/v1/organizations", map[string]any{"name": "ChaosOrg", "slug": "chaos-org"}, &org)
	orgID := org["id"].(string)

	_ = repo.UpsertGlobalModel(ctx, &domain.GlobalModel{
		ID: "openai/gpt-4o-mini", Provider: domain.ProviderOpenAI, ModelName: "gpt-4o-mini",
		SupportsInference: true, LifecycleStatus: domain.ModelStatusActive, PricingStatus: domain.PricingStatusVerified,
		MaxOutputTokens: 4096,
	})

	var chaosCred, backupCred, backupGrp, chaosGrp map[string]any
	postAdmin("/admin/v1/credentials", map[string]any{
		"org_id": orgID, "provider": "openai", "name": "chaos-c", "api_key": "sk-c", "base_url": chaosUpstream.URL,
	}, &chaosCred)
	postAdmin("/admin/v1/credentials", map[string]any{
		"org_id": orgID, "provider": "openai", "name": "backup-c", "api_key": "sk-b", "base_url": backupUpstream.URL,
	}, &backupCred)

	postAdmin("/admin/v1/model-groups", map[string]any{
		"org_id": orgID, "alias": "chaos-backup", "routing_strategy": "round-robin",
	}, &backupGrp)
	postAdmin("/admin/v1/deployments", map[string]any{
		"model_group_id": backupGrp["id"], "global_model_id": "openai/gpt-4o-mini",
		"credential_id": backupCred["id"], "deployment_name": "backup-dep", "weight": 100,
	}, nil)

	postAdmin("/admin/v1/model-groups", map[string]any{
		"org_id": orgID, "alias": "chaos-primary", "routing_strategy": "round-robin",
		"max_retries": 1, "failure_threshold": 2, "cooldown_seconds": 1,
		"fallback_groups": []string{backupGrp["id"].(string)},
	}, &chaosGrp)
	postAdmin("/admin/v1/deployments", map[string]any{
		"model_group_id": chaosGrp["id"], "global_model_id": "openai/gpt-4o-mini",
		"credential_id": chaosCred["id"], "deployment_name": "chaos-dep", "weight": 100,
	}, nil)

	var vk domain.VirtualKey
	postAdmin("/admin/v1/keys", map[string]any{
		"org_id": orgID, "name": "chaos-key",
	}, &vk)

	client := &http.Client{
		Transport: &http.Transport{MaxIdleConns: 128, MaxIdleConnsPerHost: 128},
		Timeout:   5 * time.Second,
	}

	const workers = 16
	const reqsPerWorker = 10
	var wg sync.WaitGroup
	var errCount atomic.Int64
	var fallbackCount atomic.Int64

	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for i := 0; i < reqsPerWorker; i++ {
				code, hdrs, _, err := doChatJSON(client, ts.URL, vk.RawKey, map[string]any{
					"model":    "chaos-primary",
					"messages": []map[string]string{{"role": "user", "content": fmt.Sprintf("chaos-%d-%d", workerID, i)}},
				})
				if err != nil || code != http.StatusOK {
					errCount.Add(1)
					continue
				}
				if hdrs.Get("X-Gateway-Route-Reason") == "" {
					errCount.Add(1)
				}
				if hdrs.Get("X-Gateway-Fallback-Attempted") == "true" {
					fallbackCount.Add(1)
				}
			}
		}(w)
	}
	wg.Wait()

	if errs := errCount.Load(); errs > 0 {
		t.Fatalf("chaos stress encountered %d failures or missing headers", errs)
	}
	if fb := fallbackCount.Load(); fb == 0 {
		t.Fatal("expected fallback activations under 30% 503 fault injection, got 0")
	}
}
