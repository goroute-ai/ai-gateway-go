package e2e_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

func TestLiveStack_ConcurrentBudgetNoOverspendAndSSEDisconnect(t *testing.T) {
	ts, _, pgRepo, _, cleanup := setupLiveGateway(t)
	defer cleanup()

	ctx := context.Background()
	h := &httpClientHelper{t: t, ts: ts}
	adminHeaders := map[string]string{"Authorization": "Bearer sk-gw-master-admin-live-e2e-key"}

	// Mock upstream that charges deterministic tokens and supports slow SSE for disconnect test
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/rerank", "/rerank", "/v2/rerank":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"id":"rk","results":[{"index":0,"relevance_score":0.9}],"meta":{"billed_units":{"search_units":1}},"usage":{"total_tokens":1}}`)
		case "/v1/chat/completions", "/chat/completions":
			w.Header().Set("Content-Type", "text/event-stream")
			flusher, _ := w.(http.Flusher)
			for i := 0; i < 10; i++ {
				select {
				case <-r.Context().Done():
					return
				default:
					fmt.Fprintf(w, "data: {\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"model\":\"gpt-4o-mini\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hi \"}}]}\n\n")
					if flusher != nil {
						flusher.Flush()
					}
					time.Sleep(15 * time.Millisecond)
				}
			}
			fmt.Fprint(w, "data: [DONE]\n\n")
		}
	}))
	defer upstream.Close()

	var orgResp map[string]any
	resp, raw := h.doJSON(http.MethodPost, "/admin/v1/organizations", adminHeaders, map[string]any{
		"name": "ConcOrg", "slug": fmt.Sprintf("conc-org-%d", time.Now().UnixNano()),
	}, &orgResp)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create org (%d): %s", resp.StatusCode, string(raw))
	}
	orgID := orgResp["id"].(string)

	// Key budget = 5000 micros; each rerank search unit costs 1000 micros -> max 5 requests should succeed.
	const maxBudgetMicros = int64(5000)
	var vkCreated domain.VirtualKey
	resp, raw = h.doJSON(http.MethodPost, "/admin/v1/keys", adminHeaders, map[string]any{
		"org_id": orgID, "name": "tight-budget-key", "max_budget_micros": maxBudgetMicros,
	}, &vkCreated)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create key (%d): %s", resp.StatusCode, string(raw))
	}
	apiKey := vkCreated.RawKey
	keyID := vkCreated.ID

	_ = pgRepo.UpsertGlobalModel(ctx, &domain.GlobalModel{
		ID: "cohere/tight-rerank", Provider: domain.ProviderCohere, ModelName: "tight-rerank",
		SupportsInference: true, LifecycleStatus: domain.ModelStatusActive, PricingStatus: domain.PricingStatusVerified,
		RerankCostMicrosPerSearchUnit: 1000,
		SupportedOperations:           []domain.OperationType{domain.OperationRerank},
	})
	_ = pgRepo.UpsertGlobalModel(ctx, &domain.GlobalModel{
		ID: "openai/sse-leak-check", Provider: domain.ProviderOpenAI, ModelName: "sse-leak-check",
		SupportsInference: true, LifecycleStatus: domain.ModelStatusActive, PricingStatus: domain.PricingStatusVerified,
		InputCostMicrosPer1M: 1000, OutputCostMicrosPer1M: 1000,
		SupportedOperations: []domain.OperationType{domain.OperationChat},
	})

	wire := func(provider, alias, gmID string) {
		var credResp, grpResp map[string]any
		h.doJSON(http.MethodPost, "/admin/v1/credentials", adminHeaders, map[string]any{
			"org_id": orgID, "provider": provider, "name": alias + "-c", "api_key": "sk-m", "base_url": upstream.URL,
		}, &credResp)
		h.doJSON(http.MethodPost, "/admin/v1/model-groups", adminHeaders, map[string]any{
			"org_id": orgID, "alias": alias, "routing_strategy": "weighted_shuffle",
		}, &grpResp)
		h.doJSON(http.MethodPost, "/admin/v1/deployments", adminHeaders, map[string]any{
			"model_group_id": grpResp["id"], "global_model_id": gmID,
			"credential_id": credResp["id"], "deployment_name": alias + "-d", "weight": 1,
		}, nil)
	}
	wire("cohere", "tight-rerank", "cohere/tight-rerank")
	wire("openai", "sse-leak-check", "openai/sse-leak-check")

	// 1. 40 concurrent rerank requests against 5000-micro budget (1000 micros each).
	var okCount, rejectCount atomic.Int32
	var sampleErrBody atomic.Value
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			payload, _ := json.Marshal(map[string]any{
				"model": "tight-rerank", "query": "q", "documents": []string{"d1"},
			})
			req, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/rerank", bytes.NewReader(payload))
			req.Header.Set("Authorization", "Bearer "+apiKey)
			req.Header.Set("Content-Type", "application/json")
			r, err := http.DefaultClient.Do(req)
			if err != nil {
				return
			}
			var buf bytes.Buffer
			_, _ = buf.ReadFrom(r.Body)
			r.Body.Close()
			if r.StatusCode == http.StatusOK {
				okCount.Add(1)
			} else {
				sampleErrBody.CompareAndSwap(nil, fmt.Sprintf("status=%d body=%s", r.StatusCode, buf.String()))
				rejectCount.Add(1)
			}
		}()
	}
	wg.Wait()

	if okCount.Load() > 5 || okCount.Load() == 0 {
		t.Fatalf("expected 1..5 succeeded requests within 5000-micro budget, got ok=%d reject=%d (sampleErr=%v)", okCount.Load(), rejectCount.Load(), sampleErrBody.Load())
	}
	if rejectCount.Load() == 0 {
		t.Fatalf("expected excess concurrent requests to be rejected")
	}

	// Verify settled key spend in PostgreSQL never exceeded maxBudgetMicros.
	time.Sleep(150 * time.Millisecond)
	vk, err := pgRepo.GetVirtualKeyByID(ctx, keyID)
	if err != nil {
		t.Fatalf("GetVirtualKeyByID: %v", err)
	}
	if vk.SpentMicros > maxBudgetMicros {
		t.Fatalf("BUDGET OVERSPEND DETECTED: spent_micros=%d > max_budget=%d", vk.SpentMicros, maxBudgetMicros)
	}

	// 2. SSE Client Disconnect & Goroutine Leak Check (separate unlimited key).
	var sseKeyResp domain.VirtualKey
	h.doJSON(http.MethodPost, "/admin/v1/keys", adminHeaders, map[string]any{
		"org_id": orgID, "name": "sse-key",
	}, &sseKeyResp)
	sseKey := sseKeyResp.RawKey

	runtime.GC()
	baseGoroutines := runtime.NumGoroutine()

	var sseWG sync.WaitGroup
	for i := 0; i < 20; i++ {
		sseWG.Add(1)
		go func(idx int) {
			defer sseWG.Done()
			reqCtx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if idx%2 == 0 {
				go func() {
					time.Sleep(35 * time.Millisecond)
					cancel()
				}()
			}
			payload, _ := json.Marshal(map[string]any{
				"model":    "sse-leak-check",
				"stream":   true,
				"messages": []map[string]any{{"role": "user", "content": "hi"}},
			})
			req, _ := http.NewRequestWithContext(reqCtx, http.MethodPost, ts.URL+"/v1/chat/completions", bytes.NewReader(payload))
			req.Header.Set("Authorization", "Bearer "+sseKey)
			req.Header.Set("Content-Type", "application/json")
			r, err := http.DefaultClient.Do(req)
			if err == nil {
				r.Body.Close()
			}
		}(i)
	}
	sseWG.Wait()
	time.Sleep(250 * time.Millisecond)
	runtime.GC()
	afterGoroutines := runtime.NumGoroutine()
	if afterGoroutines > baseGoroutines+15 {
		t.Fatalf("potential goroutine leak after SSE disconnects: before=%d after=%d", baseGoroutines, afterGoroutines)
	}
}
