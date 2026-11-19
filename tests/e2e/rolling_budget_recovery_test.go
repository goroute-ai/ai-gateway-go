package e2e_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/redis/go-redis/v9"
)

func TestLiveStack_Rolling24hRecoveryAndDualNodeConcurrency(t *testing.T) {
	if os.Getenv("GATEWAY_POSTGRES_DSN") == "" && os.Getenv("GATEWAY_REQUIRE_LIVE_DEPS") != "1" {
		t.Skip("live postgres/redis env not configured")
	}

	ts1, ts2, node1, node2, pgRepo, redisFabric, cleanup := setupDualNodeCluster(t)
	defer cleanup()

	ctx := context.Background()
	t0 := time.Date(2026, 11, 18, 12, 0, 0, 250_000_000, time.UTC)
	var clockMu sync.Mutex
	curTime := t0
	clock := func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		return curTime
	}
	setClock := func(ts time.Time) {
		clockMu.Lock()
		curTime = ts
		clockMu.Unlock()
	}
	node1.SetNowFunc(clock)
	node2.SetNowFunc(clock)

	// Returns fixed usage costing 50,000 micros per call: (5000*2_000_000 + 5000*8_000_000)/1_000_000.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"id":"chat-roll","object":"chat.completion","model":"rolling-chat","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":5000,"completion_tokens":5000,"total_tokens":10000}}`)
	}))
	defer upstream.Close()

	c1 := &httpClientHelper{t: t, ts: ts1}
	adminHeaders := map[string]string{"Authorization": "Bearer sk-gw-cluster-admin-key"}

	var orgResp map[string]any
	resp, raw := c1.doJSON(http.MethodPost, "/admin/v1/organizations", adminHeaders, map[string]any{
		"name": "RollingRecoveryOrg",
		"slug": fmt.Sprintf("rolling-rec-%d", time.Now().UnixNano()),
	}, &orgResp)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create org (%d): %s", resp.StatusCode, string(raw))
	}
	orgID := orgResp["id"].(string)

	const modelAlias = "rolling-chat"
	const gmID = "openai/rolling-chat-e2e"
	_ = pgRepo.UpsertGlobalModel(ctx, &domain.GlobalModel{
		ID:                    gmID,
		Provider:              domain.ProviderOpenAI,
		ModelName:             modelAlias,
		SupportsInference:     true,
		LifecycleStatus:       domain.ModelStatusActive,
		PricingStatus:         domain.PricingStatusVerified,
		InputCostMicrosPer1M:  2_000_000,
		OutputCostMicrosPer1M: 8_000_000,
		SupportedOperations:   []domain.OperationType{domain.OperationChat},
	})
	var credResp, grpResp map[string]any
	resp, raw = c1.doJSON(http.MethodPost, "/admin/v1/credentials", adminHeaders, map[string]any{
		"org_id": orgID, "provider": "openai", "name": "roll-cred", "api_key": "sk-m", "base_url": upstream.URL,
	}, &credResp)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create cred (%d): %s", resp.StatusCode, string(raw))
	}
	resp, raw = c1.doJSON(http.MethodPost, "/admin/v1/model-groups", adminHeaders, map[string]any{
		"org_id": orgID, "alias": modelAlias, "routing_strategy": "weighted_shuffle",
	}, &grpResp)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create group (%d): %s", resp.StatusCode, string(raw))
	}
	resp, raw = c1.doJSON(http.MethodPost, "/admin/v1/deployments", adminHeaders, map[string]any{
		"model_group_id": grpResp["id"], "global_model_id": gmID,
		"credential_id": credResp["id"], "deployment_name": "roll-dep", "weight": 1,
	}, nil)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create deployment (%d): %s", resp.StatusCode, string(raw))
	}

	var vk domain.VirtualKey
	resp, raw = c1.doJSON(http.MethodPost, "/admin/v1/keys", adminHeaders, map[string]any{
		"org_id": orgID, "name": "rolling-recovery-key",
	}, &vk)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create key (%d): %s", resp.StatusCode, string(raw))
	}

	// Configure rolling_24h budget of 150,000 micros with window_reset_at 48h in the past.
	// Pre-call reserve for max_tokens=5000 is ~40,200 micros and actual settled cost is 50,000 micros.
	if err := pgRepo.UpsertBudgetWindowLimit(ctx, &domain.BudgetWindowLimit{
		OrgID:           orgID,
		ScopeType:       domain.QuotaScopeKey,
		ScopeID:         vk.ID,
		WindowType:      domain.BudgetWindowRolling24h,
		MaxBudgetMicros: 150_000,
		WindowResetAt:   t0.Add(-48 * time.Hour),
	}); err != nil {
		t.Fatalf("UpsertBudgetWindowLimit: %v", err)
	}

	// Seed two charges with different timestamps in PostgreSQL:
	//   - charge 1: 50,000 micros at t0 - 20h (expires at t0 + 4h)
	//   - charge 2: 50,000 micros at t0 - 10h (expires at t0 + 14h)
	runSuffix := time.Now().UnixNano()
	if err := pgRepo.RecordSpendBatch(ctx, []domain.SpendEvent{
		{
			ID:             fmt.Sprintf("sp-live-roll-%d-1", runSuffix),
			RequestID:      fmt.Sprintf("req-live-roll-%d-1", runSuffix),
			OrgID:          orgID,
			VirtualKeyID:   vk.ID,
			Endpoint:       "/v1/chat/completions",
			Modality:       domain.ModalityChat,
			RequestedModel: modelAlias,
			ResolvedModel:  modelAlias,
			Provider:       domain.ProviderOpenAI,
			CostMicros:     50_000,
			CreatedAt:      t0.Add(-20 * time.Hour),
		},
		{
			ID:             fmt.Sprintf("sp-live-roll-%d-2", runSuffix),
			RequestID:      fmt.Sprintf("req-live-roll-%d-2", runSuffix),
			OrgID:          orgID,
			VirtualKeyID:   vk.ID,
			Endpoint:       "/v1/chat/completions",
			Modality:       domain.ModalityChat,
			RequestedModel: modelAlias,
			ResolvedModel:  modelAlias,
			Provider:       domain.ProviderOpenAI,
			CostMicros:     50_000,
			CreatedAt:      t0.Add(-10 * time.Hour),
		},
	}); err != nil {
		t.Fatalf("RecordSpendBatch: %v", err)
	}

	// Wipe Redis completely so both nodes hit cold recovery simultaneously.
	if _, err := redisFabric.Execute(func(rdb redis.UniversalClient) (any, error) {
		return rdb.FlushDB(ctx).Result()
	}); err != nil {
		t.Fatalf("FlushDB: %v", err)
	}

	callChat := func(baseURL, key string) int {
		payload, _ := json.Marshal(map[string]any{
			"model":      modelAlias,
			"max_tokens": 5000,
			"messages":   []map[string]string{{"role": "user", "content": "hi"}},
		})
		req, _ := http.NewRequest(http.MethodPost, baseURL+"/v1/chat/completions", bytes.NewReader(payload))
		req.Header.Set("Authorization", "Bearer "+key)
		req.Header.Set("Content-Type", "application/json")
		r, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("POST /v1/chat/completions %s: %v", baseURL, err)
		}
		defer r.Body.Close()
		return r.StatusCode
	}

	// Simultaneous requests on node1 and node2 against cold Redis + 100,000 active / 150,000 cap:
	// strictly 1 must succeed (200 -> settles 50,000) and 1 must reject (429).
	start := make(chan struct{})
	var okCount, rejectCount atomic.Int32
	var wg sync.WaitGroup
	for _, baseURL := range []string{ts1.URL, ts2.URL} {
		wg.Add(1)
		go func(u string) {
			defer wg.Done()
			<-start
			switch code := callChat(u, vk.RawKey); code {
			case http.StatusOK:
				okCount.Add(1)
			case http.StatusTooManyRequests:
				rejectCount.Add(1)
			default:
				t.Errorf("unexpected status %d from %s", code, u)
			}
		}(baseURL)
	}
	close(start)
	wg.Wait()
	if okCount.Load() != 1 || rejectCount.Load() != 1 {
		t.Fatalf("expected 1 admitted and 1 rejected on concurrent cold recovery, got ok=%d reject=%d", okCount.Load(), rejectCount.Load())
	}

	// Immediately calling again on either node while at 150,000 / 150,000 rejects (429).
	if got := callChat(ts2.URL, vk.RawKey); got != http.StatusTooManyRequests {
		t.Fatalf("expected 429 when full 150,000/150,000 active, got %d", got)
	}

	// Wait for the outbox worker to persist the t0 call into PostgreSQL spend_logs, then delete
	// ONLY the rolling spend sorted set and verify admission reloads persisted spend and still rejects.
	flushDeadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(flushDeadline) {
		hist, histErr := pgRepo.ListRollingWindowHistory(ctx, orgID, domain.QuotaScopeKey, vk.ID, clock())
		if histErr == nil && len(hist) >= 3 {
			break
		}
		time.Sleep(25 * time.Millisecond)
	}
	if _, err := redisFabric.Execute(func(rdb redis.UniversalClient) (any, error) {
		keyPattern := fmt.Sprintf("gw:dq:{org:%s}:r24h:key:%s:*", orgID, vk.ID)
		rKeys, err := rdb.Keys(ctx, keyPattern).Result()
		if err != nil || len(rKeys) == 0 {
			return nil, fmt.Errorf("expected rolling spend ZSET matching %s, got %v (err=%v)", keyPattern, rKeys, err)
		}
		return rdb.Del(ctx, rKeys...).Result()
	}); err != nil {
		t.Fatalf("delete only rolling ZSET: %v", err)
	}
	if got := callChat(ts1.URL, vk.RawKey); got != http.StatusTooManyRequests {
		t.Fatalf("expected 429 after deleting only rolling spend ZSET (reload from Postgres), got %d", got)
	}

	// At t0 + 4h: charge 1 (t0-20h) has aged out (100,000 active out of 150,000).
	// Room for 1 more 50,000-micro request, then next request rejects.
	setClock(t0.Add(4 * time.Hour))
	if got := callChat(ts1.URL, vk.RawKey); got != http.StatusOK {
		t.Fatalf("expected 200 at +4h after first charge expired, got %d", got)
	}
	if got := callChat(ts2.URL, vk.RawKey); got != http.StatusTooManyRequests {
		t.Fatalf("expected 429 after filling freed +4h capacity, got %d", got)
	}

	// At t0 + 14h: charge 2 (t0-10h) has aged out (100,000 active: t0 req + t0+4h req).
	setClock(t0.Add(14 * time.Hour))
	if got := callChat(ts2.URL, vk.RawKey); got != http.StatusOK {
		t.Fatalf("expected 200 at +14h after second charge expired, got %d", got)
	}

	// Verify migration rolling_hold_micros recovery after Redis FlushDB + scheduled expiration.
	var vkHold domain.VirtualKey
	resp, raw = c1.doJSON(http.MethodPost, "/admin/v1/keys", adminHeaders, map[string]any{
		"org_id": orgID, "name": "rolling-hold-key",
	}, &vkHold)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create hold key (%d): %s", resp.StatusCode, string(raw))
	}
	tHoldStart := t0.Add(14 * time.Hour)
	setClock(tHoldStart)
	if err := pgRepo.UpsertBudgetWindowLimit(ctx, &domain.BudgetWindowLimit{
		OrgID:           orgID,
		ScopeType:       domain.QuotaScopeKey,
		ScopeID:         vkHold.ID,
		WindowType:      domain.BudgetWindowRolling24h,
		MaxBudgetMicros: 120_000,
		WindowResetAt:   tHoldStart.Add(-48 * time.Hour),
	}); err != nil {
		t.Fatalf("UpsertBudgetWindowLimit hold key: %v", err)
	}
	if err := pgRepo.IncrementBudgetWindowSpend(ctx, orgID, domain.QuotaScopeKey, vkHold.ID, 90_000); err != nil {
		t.Fatalf("IncrementBudgetWindowSpend hold: %v", err)
	}
	holdExpiry := tHoldStart.Add(6 * time.Hour)
	pgPool, err := storage.NewPostgresPool(ctx, getEnvOrDefault("GATEWAY_POSTGRES_DSN", "postgres://gateway:gateway@localhost:5432/aigateway?sslmode=disable"))
	if err != nil {
		t.Fatalf("NewPostgresPool: %v", err)
	}
	defer pgPool.Close()
	if err := pgPool.QueryRow(ctx,
		`UPDATE budget_window_limits SET rolling_hold_expires_at = $1 WHERE org_id = $2 AND scope_type = 'key' AND scope_id = $3 AND window_type = 'rolling_24h' RETURNING id`,
		holdExpiry, orgID, vkHold.ID,
	).Scan(new(string)); err != nil {
		t.Fatalf("set deterministic hold expiry: %v", err)
	}
	if _, err := redisFabric.Execute(func(rdb redis.UniversalClient) (any, error) {
		return rdb.FlushDB(ctx).Result()
	}); err != nil {
		t.Fatalf("FlushDB before hold check: %v", err)
	}

	// Before holdExpiry (tHoldStart + 5h): 90,000 hold + ~40,200 reserve > 120,000 -> must reject 429.
	setClock(tHoldStart.Add(5 * time.Hour))
	if got := callChat(ts1.URL, vkHold.RawKey); got != http.StatusTooManyRequests {
		t.Fatalf("expected 429 while migration hold still active before expiry, got %d", got)
	}
	// At exact holdExpiry (tHoldStart + 6h): migration hold expired -> 200.
	setClock(holdExpiry)
	if got := callChat(ts2.URL, vkHold.RawKey); got != http.StatusOK {
		t.Fatalf("expected 200 after migration hold expired at %v, got %d", holdExpiry, got)
	}
}
