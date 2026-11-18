package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/finops"
	"github.com/goroute-ai/ai-gateway-go/internal/server"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"nhooyr.io/websocket"
)

type quotaTestEnv struct {
	repo    *storage.MemoryRepository
	mr      *miniredis.Miniredis
	gw      *server.GatewayServer
	handler http.Handler
	org     *domain.Organization
	cred    *domain.ProviderCredential
	gm      *domain.GlobalModel
}

func setupRealtimeBatchQuotaEnv(t *testing.T, upstreamHandler http.HandlerFunc) *quotaTestEnv {
	t.Helper()
	ctx := context.Background()
	mr := miniredis.RunT(t)
	redisFabric := storage.NewRedisFabric(mr.Addr(), "", 0)
	t.Cleanup(func() { _ = redisFabric.Client().Close() })

	upstream := httptest.NewServer(upstreamHandler)
	t.Cleanup(upstream.Close)

	repo := storage.NewMemoryRepository()
	cfg := config.Default()
	cfg.Auth.MasterAdminKey = "admin_secret_key"
	cfg.Security.Network.OutboundSSRF.AllowPrivateNetworks = true
	cfg.Security.Network.OutboundSSRF.AllowInsecureHTTP = true
	cfg.FinOps.FlushInterval = 25 * time.Millisecond

	gw, err := server.New(cfg, repo, redisFabric, upstream.Client())
	require.NoError(t, err)
	gw.StartWorkers(ctx)
	t.Cleanup(func() { gw.Shutdown(context.Background()) })

	org := &domain.Organization{ID: "org-q-" + uuid.NewString()[:8], Name: "Quota Org", Slug: "quota-org-" + uuid.NewString()[:8], IsActive: true}
	require.NoError(t, repo.CreateOrganization(ctx, org))

	credBody, _ := json.Marshal(map[string]any{
		"org_id":   org.ID,
		"provider": "openai",
		"name":     "openai-quota",
		"base_url": upstream.URL + "/v1",
		"api_key":  "sk-openai-quota",
	})
	credReq := httptest.NewRequest(http.MethodPost, "/admin/v1/credentials", bytes.NewReader(credBody))
	credReq.Header.Set("Authorization", "Bearer admin_secret_key")
	credReq.Header.Set("Content-Type", "application/json")
	credRec := httptest.NewRecorder()
	gw.Handler().ServeHTTP(credRec, credReq)
	require.Equal(t, http.StatusCreated, credRec.Code, credRec.Body.String())

	var cred domain.ProviderCredential
	require.NoError(t, json.Unmarshal(credRec.Body.Bytes(), &cred))

	gm := &domain.GlobalModel{
		ID:                    "openai/gpt-4.1-mini",
		Provider:              domain.ProviderOpenAI,
		ModelName:             "gpt-4.1-mini",
		SupportsInference:     true,
		LifecycleStatus:       domain.ModelStatusActive,
		PricingStatus:         domain.PricingStatusVerified,
		InputCostMicrosPer1M:  2_000_000,
		OutputCostMicrosPer1M: 8_000_000,
		MaxOutputTokens:       100,
	}
	require.NoError(t, repo.UpsertGlobalModel(ctx, gm))

	mg := &domain.ModelGroup{
		ID:              "mg-q-" + uuid.NewString()[:8],
		OrgID:           org.ID,
		Alias:           "gpt-4.1-mini",
		RoutingStrategy: domain.StrategyWeightedShuffle,
		IsActive:        true,
	}
	require.NoError(t, repo.CreateModelGroup(ctx, mg))

	dep := &domain.Deployment{
		ID:             "dep-q-" + uuid.NewString()[:8],
		ModelGroupID:   mg.ID,
		GlobalModelID:  gm.ID,
		CredentialID:   cred.ID,
		DeploymentName: "openai-quota-1",
		Status:         domain.DeploymentStatusActive,
		GlobalModel:    gm,
		Credential:     &cred,
	}
	require.NoError(t, repo.CreateDeployment(ctx, dep))

	return &quotaTestEnv{
		repo:    repo,
		mr:      mr,
		gw:      gw,
		handler: gw.Handler(),
		org:     org,
		cred:    &cred,
		gm:      gm,
	}
}

func (e *quotaTestEnv) issueKey(t *testing.T, payload map[string]any) domain.VirtualKey {
	t.Helper()
	payload["org_id"] = e.org.ID
	b, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/keys", bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer admin_secret_key")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	e.handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())

	var vk domain.VirtualKey
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &vk))
	require.NotEmpty(t, vk.RawKey)
	return vk
}

func (e *quotaTestEnv) uploadBatchFile(t *testing.T, rawKey, filename, jsonl string) domain.CanonicalFile {
	t.Helper()
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	require.NoError(t, writer.WriteField("purpose", "batch"))
	part, err := writer.CreateFormFile("file", filename)
	require.NoError(t, err)
	_, err = part.Write([]byte(jsonl))
	require.NoError(t, err)
	require.NoError(t, writer.Close())

	req := httptest.NewRequest(http.MethodPost, "/v1/files", body)
	req.Header.Set("Authorization", "Bearer "+rawKey)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	rec := httptest.NewRecorder()
	e.handler.ServeHTTP(rec, req)
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())

	var f domain.CanonicalFile
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &f))
	return f
}

func TestRealtimeWebSocket_UpgradeRateAndConcurrencyLimit(t *testing.T) {
	env := setupRealtimeBatchQuotaEnv(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":      "chatcmpl-" + uuid.NewString(),
			"object":  "chat.completion",
			"created": time.Now().Unix(),
			"model":   "gpt-4.1-mini",
			"choices": []map[string]any{
				{"index": 0, "message": map[string]any{"role": "assistant", "content": "ok"}, "finish_reason": "stop"},
			},
			"usage": map[string]any{"prompt_tokens": 10, "completion_tokens": 2, "total_tokens": 12},
		})
	})

	vkConc := env.issueKey(t, map[string]any{
		"name":                    "ws-conc-key",
		"max_concurrent_requests": 1,
		"rpm_limit":               10,
	})

	ts := httptest.NewServer(env.handler)
	defer ts.Close()
	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/v1/realtime?model=gpt-4.1-mini"

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// 1. Open first WS connection -> succeeds.
	conn1, resp1, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
		Subprotocols: []string{"realtime"},
		HTTPHeader:   http.Header{"Authorization": []string{"Bearer " + vkConc.RawKey}},
	})
	require.NoError(t, err)
	require.Equal(t, http.StatusSwitchingProtocols, resp1.StatusCode)

	// Read session.created
	_, raw, err := conn1.Read(ctx)
	require.NoError(t, err)
	var scEv map[string]any
	require.NoError(t, json.Unmarshal(raw, &scEv))
	assert.Equal(t, "session.created", scEv["type"])

	// 2. Concurrent second WS upgrade -> rejected with 429 key_concurrency_exceeded.
	_, resp2, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
		Subprotocols: []string{"realtime"},
		HTTPHeader:   http.Header{"Authorization": []string{"Bearer " + vkConc.RawKey}},
	})
	require.Error(t, err)
	require.NotNil(t, resp2)
	assert.Equal(t, http.StatusTooManyRequests, resp2.StatusCode)
	body2, _ := io.ReadAll(resp2.Body)
	_ = resp2.Body.Close()
	assert.Contains(t, string(body2), "key_concurrency_exceeded")

	// 3. Even with MaxConcurrent=1, a turn inside conn1 must succeed (not blocked by session conc hold).
	itemBytes, _ := json.Marshal(map[string]any{
		"type": "conversation.item.create",
		"item": map[string]any{
			"type": "message",
			"role": "user",
			"content": []map[string]any{
				{"type": "input_text", "text": "ping"},
			},
		},
	})
	require.NoError(t, conn1.Write(ctx, websocket.MessageText, itemBytes))
	_, _, err = conn1.Read(ctx) // conversation.item.created
	require.NoError(t, err)

	reqBytes, _ := json.Marshal(map[string]any{"type": "response.create"})
	require.NoError(t, conn1.Write(ctx, websocket.MessageText, reqBytes))
	gotDone := false
	for !gotDone {
		_, evRaw, readErr := conn1.Read(ctx)
		require.NoError(t, readErr)
		var ev map[string]any
		require.NoError(t, json.Unmarshal(evRaw, &ev))
		if ev["type"] == "response.done" {
			gotDone = true
		}
	}

	// 4. Close conn1 -> concurrency slot is released -> new WS connection succeeds.
	_ = conn1.Close(websocket.StatusNormalClosure, "done")
	require.Eventually(t, func() bool {
		c, r, dialErr := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
			Subprotocols: []string{"realtime"},
			HTTPHeader:   http.Header{"Authorization": []string{"Bearer " + vkConc.RawKey}},
		})
		if dialErr != nil {
			if r != nil && r.Body != nil {
				_ = r.Body.Close()
			}
			return false
		}
		_ = c.Close(websocket.StatusNormalClosure, "ok")
		return true
	}, 2*time.Second, 20*time.Millisecond)

	// 5. Verify RPM limit on WS upgrade.
	vkRPM := env.issueKey(t, map[string]any{
		"name":      "ws-rpm-key",
		"rpm_limit": 1,
	})
	cRPM, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
		Subprotocols: []string{"realtime"},
		HTTPHeader:   http.Header{"Authorization": []string{"Bearer " + vkRPM.RawKey}},
	})
	require.NoError(t, err)
	_ = cRPM.Close(websocket.StatusNormalClosure, "done")

	_, respRPM, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
		Subprotocols: []string{"realtime"},
		HTTPHeader:   http.Header{"Authorization": []string{"Bearer " + vkRPM.RawKey}},
	})
	require.Error(t, err)
	require.NotNil(t, respRPM)
	assert.Equal(t, http.StatusTooManyRequests, respRPM.StatusCode)
	rpmBody, _ := io.ReadAll(respRPM.Body)
	_ = respRPM.Body.Close()
	assert.Contains(t, string(rpmBody), "key_rpm_exceeded")
}

func TestRealtimeWebSocket_BudgetedTurnsAndExhaustion(t *testing.T) {
	var upstreamCalls atomic.Int32
	env := setupRealtimeBatchQuotaEnv(t, func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":      "chatcmpl-" + uuid.NewString(),
			"object":  "chat.completion",
			"created": time.Now().Unix(),
			"model":   "gpt-4.1-mini",
			"choices": []map[string]any{
				{"index": 0, "message": map[string]any{"role": "assistant", "content": "Budgeted reply"}, "finish_reason": "stop"},
			},
			"usage": map[string]any{"prompt_tokens": 20, "completion_tokens": 10, "total_tokens": 30},
		})
	})

	// Upper bound for turn with max_output_tokens=100 is at least 100 * 8 = 800 micros (+ input ~200 = ~1000).
	// Set budget to 1500 micros: enough for turn 1 (upper bound ~1200, actual cost 20*2 + 10*8 = 120 micros),
	// Wait: after turn 1 settles to 120 micros, remaining budget is 1380.
	// If turn 2 requests max_output_tokens=200 (upper bound >= 1600 > 1380), turn 2 must be rejected!
	vk := env.issueKey(t, map[string]any{
		"name":              "ws-budget-key",
		"max_budget_micros": 1500,
	})

	ts := httptest.NewServer(env.handler)
	defer ts.Close()
	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/v1/realtime?model=gpt-4.1-mini"

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
		Subprotocols: []string{"realtime"},
		HTTPHeader:   http.Header{"Authorization": []string{"Bearer " + vk.RawKey}},
	})
	require.NoError(t, err)
	defer conn.Close(websocket.StatusNormalClosure, "test done")

	_, _, err = conn.Read(ctx) // session.created
	require.NoError(t, err)

	// Add user message
	itemBytes, _ := json.Marshal(map[string]any{
		"type": "conversation.item.create",
		"item": map[string]any{
			"type": "message",
			"role": "user",
			"content": []map[string]any{
				{"type": "input_text", "text": "Hello budgeted realtime"},
			},
		},
	})
	require.NoError(t, conn.Write(ctx, websocket.MessageText, itemBytes))
	_, _, err = conn.Read(ctx) // conversation.item.created
	require.NoError(t, err)

	// Turn 1: max_output_tokens = 50 -> admitted and settled immediately after completion.
	turn1Bytes, _ := json.Marshal(map[string]any{
		"type":     "response.create",
		"response": map[string]any{"max_output_tokens": 50},
	})
	require.NoError(t, conn.Write(ctx, websocket.MessageText, turn1Bytes))
	for {
		_, evRaw, readErr := conn.Read(ctx)
		require.NoError(t, readErr)
		var ev map[string]any
		require.NoError(t, json.Unmarshal(evRaw, &ev))
		if ev["type"] == "response.done" {
			break
		}
		require.NotEqual(t, "error", ev["type"], "unexpected error event: %s", string(evRaw))
	}
	assert.Equal(t, int32(1), upstreamCalls.Load())

	// Verify immediate per-turn settlement in Redis (20*2 + 10*8 = 120 micros) & SpendLogs.
	expectedCost := finops.CalculateCostMicros(env.gm, domain.TokenUsage{PromptTokens: 20, CompletionTokens: 10, TotalTokens: 30})
	spendKey := fmt.Sprintf("gw:spend:{org:%s}:key:%s", env.org.ID, vk.ID)
	gotSpend, err := env.mr.Get(spendKey)
	require.NoError(t, err)
	assert.Equal(t, fmt.Sprintf("%d", expectedCost), gotSpend)

	resKey := fmt.Sprintf("gw:budget:{org:%s}:reservations:key:%s", env.org.ID, vk.ID)
	members, _ := env.mr.ZMembers(resKey)
	assert.Empty(t, members, "turn reservation must be settled immediately after turn completion")

	require.Eventually(t, func() bool {
		logs, listErr := env.repo.ListSpendLogs(context.Background(), env.org.ID, 10)
		return listErr == nil && len(logs) == 1 && logs[0].Modality == domain.ModalityRealtime && logs[0].CostMicros == expectedCost
	}, 2*time.Second, 20*time.Millisecond)

	// Turn 2: max_output_tokens = 200 -> exceeds remaining budget -> error event without calling upstream.
	turn2Bytes, _ := json.Marshal(map[string]any{
		"type":     "response.create",
		"response": map[string]any{"max_output_tokens": 200},
	})
	require.NoError(t, conn.Write(ctx, websocket.MessageText, turn2Bytes))
	_, errRaw, err := conn.Read(ctx)
	require.NoError(t, err)
	var errEv struct {
		Type  string `json:"type"`
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	require.NoError(t, json.Unmarshal(errRaw, &errEv))
	assert.Equal(t, "error", errEv.Type)
	assert.Equal(t, "key_budget_exceeded", errEv.Error.Code)
	assert.Equal(t, int32(1), upstreamCalls.Load(), "rejected turn must not call upstream")

	// Also verify new WS upgrade fails when budget is completely exhausted.
	require.NoError(t, env.mr.Set(spendKey, "1500"))
	_, respExhausted, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
		Subprotocols: []string{"realtime"},
		HTTPHeader:   http.Header{"Authorization": []string{"Bearer " + vk.RawKey}},
	})
	require.Error(t, err)
	require.NotNil(t, respExhausted)
	assert.Equal(t, http.StatusTooManyRequests, respExhausted.StatusCode)
	exhaustedBody, _ := io.ReadAll(respExhausted.Body)
	_ = respExhausted.Body.Close()
	assert.Contains(t, string(exhaustedBody), "key_budget_exceeded")
}

func TestRealtimeWebSocket_DisconnectMidTurnSettlesInputCost(t *testing.T) {
	dispatched := make(chan struct{}, 1)
	testDone := make(chan struct{})
	env := setupRealtimeBatchQuotaEnv(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case dispatched <- struct{}{}:
		default:
		}
		select {
		case <-r.Context().Done():
		case <-testDone:
		}
	})
	t.Cleanup(func() { close(testDone) })

	vk := env.issueKey(t, map[string]any{
		"name":                    "ws-disconnect-key",
		"max_concurrent_requests": 1,
		"max_budget_micros":       100_000,
	})

	ts := httptest.NewServer(env.handler)
	defer ts.Close()
	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/v1/realtime?model=gpt-4.1-mini"

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
		Subprotocols: []string{"realtime"},
		HTTPHeader:   http.Header{"Authorization": []string{"Bearer " + vk.RawKey}},
	})
	require.NoError(t, err)

	_, _, err = conn.Read(ctx) // session.created
	require.NoError(t, err)

	itemBytes, _ := json.Marshal(map[string]any{
		"type": "conversation.item.create",
		"item": map[string]any{
			"type": "message",
			"role": "user",
			"content": []map[string]any{
				{"type": "input_text", "text": "Disconnect mid turn test prompt"},
			},
		},
	})
	require.NoError(t, conn.Write(ctx, websocket.MessageText, itemBytes))
	_, _, err = conn.Read(ctx) // conversation.item.created
	require.NoError(t, err)

	turnBytes, _ := json.Marshal(map[string]any{
		"type":     "response.create",
		"response": map[string]any{"max_output_tokens": 50},
	})
	require.NoError(t, conn.Write(ctx, websocket.MessageText, turnBytes))

	select {
	case <-dispatched:
	case <-time.After(3 * time.Second):
		t.Fatal("upstream did not receive turn request")
	}

	// Disconnect client mid-turn.
	_ = conn.CloseNow()

	// Verify reservation cleared, positive input cost settled in Redis & SpendLogs with StatusCode 499, and concurrency released.
	resKey := fmt.Sprintf("gw:budget:{org:%s}:reservations:key:%s", env.org.ID, vk.ID)
	spendKey := fmt.Sprintf("gw:spend:{org:%s}:key:%s", env.org.ID, vk.ID)
	require.Eventually(t, func() bool {
		members, _ := env.mr.ZMembers(resKey)
		spend, _ := env.mr.Get(spendKey)
		logs, listErr := env.repo.ListSpendLogs(context.Background(), env.org.ID, 10)
		return len(members) == 0 && spend != "" && spend != "0" && listErr == nil && len(logs) == 1 && logs[0].StatusCode == 499 && logs[0].CostMicros > 0
	}, 3*time.Second, 25*time.Millisecond)

	// New WS upgrade succeeds (concurrency slot was released).
	conn2, _, err := websocket.Dial(ctx, wsURL, &websocket.DialOptions{
		Subprotocols: []string{"realtime"},
		HTTPHeader:   http.Header{"Authorization": []string{"Bearer " + vk.RawKey}},
	})
	require.NoError(t, err)
	_ = conn2.Close(websocket.StatusNormalClosure, "ok")
}

func TestBatch_JSONLEstimationAndEnqueuedTokenLimit(t *testing.T) {
	gate := make(chan struct{})
	inFlight := make(chan struct{}, 4)
	var gateOnce sync.Once
	closeGate := func() { gateOnce.Do(func() { close(gate) }) }
	defer closeGate()

	env := setupRealtimeBatchQuotaEnv(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case inFlight <- struct{}{}:
		default:
		}
		<-gate
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":      "chatcmpl-" + uuid.NewString(),
			"object":  "chat.completion",
			"created": time.Now().Unix(),
			"model":   "gpt-4.1-mini",
			"choices": []map[string]any{
				{"index": 0, "message": map[string]any{"role": "assistant", "content": "Batch ok"}, "finish_reason": "stop"},
			},
			"usage": map[string]any{"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
		})
	})

	// Line 1 has max_tokens=50; line 2 omits max_tokens -> falls back to gm.MaxOutputTokens (100).
	// Total estimated_tokens will be ~ (input1+50) + (input2+100) ~ 170-180 tokens.
	// Limit 250 allows 1 batch, rejects 2nd concurrent batch.
	vk := env.issueKey(t, map[string]any{
		"name":                       "batch-enq-key",
		"batch_enqueued_token_limit": 250,
	})

	jsonl := `{"custom_id":"r1","method":"POST","url":"/v1/chat/completions","body":{"model":"gpt-4.1-mini","max_tokens":50,"messages":[{"role":"user","content":"Hello one"}]}}` + "\n" +
		`{"custom_id":"r2","method":"POST","url":"/v1/chat/completions","body":{"model":"gpt-4.1-mini","messages":[{"role":"user","content":"Hello two"}]}}` + "\n"
	file := env.uploadBatchFile(t, vk.RawKey, "batch.jsonl", jsonl)

	createBatch := func() *httptest.ResponseRecorder {
		b, _ := json.Marshal(map[string]any{
			"input_file_id":     file.ID,
			"endpoint":          "/v1/chat/completions",
			"completion_window": "24h",
		})
		req := httptest.NewRequest(http.MethodPost, "/v1/batches", bytes.NewReader(b))
		req.Header.Set("Authorization", "Bearer "+vk.RawKey)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		env.handler.ServeHTTP(rec, req)
		return rec
	}

	// 1. Create Batch 1 -> 201 Created with EstimatedTokens > 150.
	rec1 := createBatch()
	require.Equal(t, http.StatusCreated, rec1.Code, rec1.Body.String())
	var batch1 domain.CanonicalBatch
	require.NoError(t, json.Unmarshal(rec1.Body.Bytes(), &batch1))
	assert.Greater(t, batch1.EstimatedTokens, int64(150))
	assert.LessOrEqual(t, batch1.EstimatedTokens, int64(250))

	// Wait until async worker reaches upstream.
	select {
	case <-inFlight:
	case <-time.After(2 * time.Second):
		t.Fatal("batch 1 did not start processing")
	}

	enqSumKey := fmt.Sprintf("gw:batch:{org:%s}:enqueued:key:%s:sum", env.org.ID, vk.ID)
	gotSum, err := env.mr.Get(enqSumKey)
	require.NoError(t, err)
	assert.Equal(t, fmt.Sprintf("%d", batch1.EstimatedTokens), gotSum)

	// 2. Concurrent Batch 2 -> rejected with 429 key_batch_enqueued_tokens_exceeded.
	rec2 := createBatch()
	assert.Equal(t, http.StatusTooManyRequests, rec2.Code, rec2.Body.String())
	assert.Contains(t, rec2.Body.String(), "key_batch_enqueued_tokens_exceeded")

	// 3. Unblock upstream -> Batch 1 completes -> enqueued hold is released -> Batch 2 succeeds.
	closeGate()
	require.Eventually(t, func() bool {
		b, getErr := env.repo.GetBatch(context.Background(), env.org.ID, batch1.ID)
		sum, _ := env.mr.Get(enqSumKey)
		return getErr == nil && b.Status == "completed" && sum == "0"
	}, 3*time.Second, 20*time.Millisecond)

	rec3 := createBatch()
	require.Equal(t, http.StatusCreated, rec3.Code, rec3.Body.String())
	var batch2 domain.CanonicalBatch
	require.NoError(t, json.Unmarshal(rec3.Body.Bytes(), &batch2))
	require.Eventually(t, func() bool {
		b, getErr := env.repo.GetBatch(context.Background(), env.org.ID, batch2.ID)
		sum, _ := env.mr.Get(enqSumKey)
		return getErr == nil && b.Status == "completed" && sum == "0"
	}, 3*time.Second, 20*time.Millisecond)
}

func TestBatch_CancelReleasesEnqueuedTokenHold(t *testing.T) {
	gate := make(chan struct{})
	inFlight := make(chan struct{}, 2)
	var gateOnce sync.Once
	closeGate := func() { gateOnce.Do(func() { close(gate) }) }
	defer closeGate()

	env := setupRealtimeBatchQuotaEnv(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case inFlight <- struct{}{}:
		default:
		}
		<-gate
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":      "chatcmpl-" + uuid.NewString(),
			"object":  "chat.completion",
			"created": time.Now().Unix(),
			"model":   "gpt-4.1-mini",
			"choices": []map[string]any{
				{"index": 0, "message": map[string]any{"role": "assistant", "content": "ok"}, "finish_reason": "stop"},
			},
			"usage": map[string]any{"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
		})
	})

	vk := env.issueKey(t, map[string]any{
		"name":                       "batch-cancel-key",
		"batch_enqueued_token_limit": 150,
	})

	jsonl := `{"custom_id":"r1","method":"POST","url":"/v1/chat/completions","body":{"model":"gpt-4.1-mini","max_tokens":80,"messages":[{"role":"user","content":"Hello"}]}}` + "\n"
	file := env.uploadBatchFile(t, vk.RawKey, "cancel.jsonl", jsonl)

	payload, _ := json.Marshal(map[string]any{"input_file_id": file.ID})
	req1 := httptest.NewRequest(http.MethodPost, "/v1/batches", bytes.NewReader(payload))
	req1.Header.Set("Authorization", "Bearer "+vk.RawKey)
	req1.Header.Set("Content-Type", "application/json")
	rec1 := httptest.NewRecorder()
	env.handler.ServeHTTP(rec1, req1)
	require.Equal(t, http.StatusCreated, rec1.Code, rec1.Body.String())

	var batch1 domain.CanonicalBatch
	require.NoError(t, json.Unmarshal(rec1.Body.Bytes(), &batch1))

	select {
	case <-inFlight:
	case <-time.After(2 * time.Second):
		t.Fatal("batch 1 did not start")
	}

	// Cancel batch 1 -> immediately releases enqueued token hold.
	cancelReq := httptest.NewRequest(http.MethodPost, "/v1/batches/"+batch1.ID+"/cancel", nil)
	cancelReq.Header.Set("Authorization", "Bearer "+vk.RawKey)
	cancelRec := httptest.NewRecorder()
	env.handler.ServeHTTP(cancelRec, cancelReq)
	require.Equal(t, http.StatusOK, cancelRec.Code, cancelRec.Body.String())

	enqSumKey := fmt.Sprintf("gw:batch:{org:%s}:enqueued:key:%s:sum", env.org.ID, vk.ID)
	gotSum, err := env.mr.Get(enqSumKey)
	require.NoError(t, err)
	assert.Equal(t, "0", gotSum)

	// New batch succeeds immediately after cancel!
	closeGate()
	req2 := httptest.NewRequest(http.MethodPost, "/v1/batches", bytes.NewReader(payload))
	req2.Header.Set("Authorization", "Bearer "+vk.RawKey)
	req2.Header.Set("Content-Type", "application/json")
	rec2 := httptest.NewRecorder()
	env.handler.ServeHTTP(rec2, req2)
	require.Equal(t, http.StatusCreated, rec2.Code, rec2.Body.String())

	var batch2 domain.CanonicalBatch
	require.NoError(t, json.Unmarshal(rec2.Body.Bytes(), &batch2))
	require.Eventually(t, func() bool {
		b, getErr := env.repo.GetBatch(context.Background(), env.org.ID, batch2.ID)
		return getErr == nil && b.Status == "completed"
	}, 3*time.Second, 20*time.Millisecond)
}

func TestBatch_BudgetedReservationSettlementAndUnknownPricing(t *testing.T) {
	gate := make(chan struct{})
	inFlight := make(chan struct{}, 2)
	var gateOnce sync.Once
	closeGate := func() { gateOnce.Do(func() { close(gate) }) }
	defer closeGate()

	env := setupRealtimeBatchQuotaEnv(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case inFlight <- struct{}{}:
		default:
		}
		<-gate
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":      "chatcmpl-" + uuid.NewString(),
			"object":  "chat.completion",
			"created": time.Now().Unix(),
			"model":   "gpt-4.1-mini",
			"choices": []map[string]any{
				{"index": 0, "message": map[string]any{"role": "assistant", "content": "Budget batch ok"}, "finish_reason": "stop"},
			},
			"usage": map[string]any{"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
		})
	})

	// Add an unverified model to verify budgeted batch fails closed.
	require.NoError(t, env.repo.UpsertGlobalModel(context.Background(), &domain.GlobalModel{
		ID:            "custom/unverified-batch-model",
		Provider:      domain.ProviderOpenAI,
		ModelName:     "unverified-batch-model",
		PricingStatus: domain.PricingStatusUnknown,
	}))

	// 1. Unverified pricing -> 403 pricing_unknown_budget_restricted.
	vkBudget := env.issueKey(t, map[string]any{
		"name":              "batch-budget-key",
		"max_budget_micros": 1200,
	})
	unverifiedFile := env.uploadBatchFile(t, vkBudget.RawKey, "unverified.jsonl",
		`{"custom_id":"u1","method":"POST","url":"/v1/chat/completions","body":{"model":"unverified-batch-model","max_tokens":50,"messages":[{"role":"user","content":"hi"}]}}`+"\n")
	uPayload, _ := json.Marshal(map[string]any{"input_file_id": unverifiedFile.ID})
	uReq := httptest.NewRequest(http.MethodPost, "/v1/batches", bytes.NewReader(uPayload))
	uReq.Header.Set("Authorization", "Bearer "+vkBudget.RawKey)
	uReq.Header.Set("Content-Type", "application/json")
	uRec := httptest.NewRecorder()
	env.handler.ServeHTTP(uRec, uReq)
	assert.Equal(t, http.StatusForbidden, uRec.Code, uRec.Body.String())
	assert.Contains(t, uRec.Body.String(), "pricing_unknown_budget_restricted")

	// 2. Unknown/missing model pricing -> 503 budget_estimate_unavailable.
	unknownFile := env.uploadBatchFile(t, vkBudget.RawKey, "unknown.jsonl",
		`{"custom_id":"u2","method":"POST","url":"/v1/chat/completions","body":{"model":"nonexistent-model-xyz","max_tokens":50,"messages":[{"role":"user","content":"hi"}]}}`+"\n")
	unkPayload, _ := json.Marshal(map[string]any{"input_file_id": unknownFile.ID})
	unkReq := httptest.NewRequest(http.MethodPost, "/v1/batches", bytes.NewReader(unkPayload))
	unkReq.Header.Set("Authorization", "Bearer "+vkBudget.RawKey)
	unkReq.Header.Set("Content-Type", "application/json")
	unkRec := httptest.NewRecorder()
	env.handler.ServeHTTP(unkRec, unkReq)
	assert.Equal(t, http.StatusServiceUnavailable, unkRec.Code, unkRec.Body.String())
	assert.Contains(t, unkRec.Body.String(), "budget_estimate_unavailable")

	// 3. Verified pricing -> reserves upper-bound budget before async dispatch, blocks 2nd concurrent batch, settles actual spend on completion.
	verifiedFile := env.uploadBatchFile(t, vkBudget.RawKey, "verified.jsonl",
		`{"custom_id":"v1","method":"POST","url":"/v1/chat/completions","body":{"model":"gpt-4.1-mini","max_tokens":80,"messages":[{"role":"user","content":"Hello budgeted batch"}]}}`+"\n")
	vPayload, _ := json.Marshal(map[string]any{"input_file_id": verifiedFile.ID})

	vReq1 := httptest.NewRequest(http.MethodPost, "/v1/batches", bytes.NewReader(vPayload))
	vReq1.Header.Set("Authorization", "Bearer "+vkBudget.RawKey)
	vReq1.Header.Set("Content-Type", "application/json")
	vRec1 := httptest.NewRecorder()
	env.handler.ServeHTTP(vRec1, vReq1)
	require.Equal(t, http.StatusCreated, vRec1.Code, vRec1.Body.String())

	var batch1 domain.CanonicalBatch
	require.NoError(t, json.Unmarshal(vRec1.Body.Bytes(), &batch1))
	assert.Greater(t, batch1.ReservedCostMicros, int64(640)) // >= 80 * 8 = 640
	assert.LessOrEqual(t, batch1.ReservedCostMicros, int64(1200))

	select {
	case <-inFlight:
	case <-time.After(2 * time.Second):
		t.Fatal("budgeted batch 1 did not reach upstream")
	}

	// Reservation for batch1.ID is active while running.
	resKey := fmt.Sprintf("gw:budget:{org:%s}:reservations:key:%s", env.org.ID, vkBudget.ID)
	members, _ := env.mr.ZMembers(resKey)
	assert.Contains(t, members, batch1.ID)

	// Second concurrent batch exceeds remaining budget (1200 - ~840 < ~840) -> 429 key_budget_exceeded.
	vReq2 := httptest.NewRequest(http.MethodPost, "/v1/batches", bytes.NewReader(vPayload))
	vReq2.Header.Set("Authorization", "Bearer "+vkBudget.RawKey)
	vReq2.Header.Set("Content-Type", "application/json")
	vRec2 := httptest.NewRecorder()
	env.handler.ServeHTTP(vRec2, vReq2)
	assert.Equal(t, http.StatusTooManyRequests, vRec2.Code, vRec2.Body.String())
	assert.Contains(t, vRec2.Body.String(), "key_budget_exceeded")

	// Complete batch 1 -> reservation is cleared, actual spend (10*2 + 5*8 = 60 micros) is settled, and batch 2 now fits!
	closeGate()
	expectedActual := finops.CalculateCostMicros(env.gm, domain.TokenUsage{PromptTokens: 10, CompletionTokens: 5, TotalTokens: 15})
	spendKey := fmt.Sprintf("gw:spend:{org:%s}:key:%s", env.org.ID, vkBudget.ID)
	require.Eventually(t, func() bool {
		b, getErr := env.repo.GetBatch(context.Background(), env.org.ID, batch1.ID)
		m, _ := env.mr.ZMembers(resKey)
		sp, _ := env.mr.Get(spendKey)
		logs, lErr := env.repo.ListSpendLogs(context.Background(), env.org.ID, 10)
		return getErr == nil && b.Status == "completed" && len(m) == 0 &&
			sp == fmt.Sprintf("%d", expectedActual) && lErr == nil && len(logs) == 1 && logs[0].Modality == domain.ModalityBatch
	}, 3*time.Second, 20*time.Millisecond)

	// Because actual spend (60) was much smaller than upper-bound reservation (~840), batch 2 now succeeds!
	vReq3 := httptest.NewRequest(http.MethodPost, "/v1/batches", bytes.NewReader(vPayload))
	vReq3.Header.Set("Authorization", "Bearer "+vkBudget.RawKey)
	vReq3.Header.Set("Content-Type", "application/json")
	vRec3 := httptest.NewRecorder()
	env.handler.ServeHTTP(vRec3, vReq3)
	require.Equal(t, http.StatusCreated, vRec3.Code, vRec3.Body.String())

	var batch2 domain.CanonicalBatch
	require.NoError(t, json.Unmarshal(vRec3.Body.Bytes(), &batch2))
	require.Eventually(t, func() bool {
		b, getErr := env.repo.GetBatch(context.Background(), env.org.ID, batch2.ID)
		return getErr == nil && b.Status == "completed"
	}, 3*time.Second, 20*time.Millisecond)
}
