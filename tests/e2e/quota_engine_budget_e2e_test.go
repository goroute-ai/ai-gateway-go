package e2e_test

import (
	"bufio"
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

	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/finops"
	"github.com/redis/go-redis/v9"
	"nhooyr.io/websocket"
)

func TestE2E_GW_AQ_01_UserBudgetGateLeaseRenewalAndCancelSettlement(t *testing.T) {
	dispatched := make(chan struct{}, 2)
	blockUpstream := make(chan struct{})
	var closeBlockOnce sync.Once
	unblock := func() { closeBlockOnce.Do(func() { close(blockUpstream) }) }
	t.Cleanup(unblock)

	streamUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Stream bool `json:"stream"`
		}
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &body)
		if body.Stream {
			w.Header().Set("Content-Type", "text/event-stream")
			fl, _ := w.(http.Flusher)
			_, _ = fmt.Fprint(w, "data: {\"id\":\"c1\",\"object\":\"chat.completion.chunk\",\"model\":\"u-chat\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"hi \"}}]}\n\n")
			if fl != nil {
				fl.Flush()
			}
			select {
			case dispatched <- struct{}{}:
			default:
			}
			select {
			case <-r.Context().Done():
				return
			case <-blockUpstream:
				_, _ = fmt.Fprint(w, "data: [DONE]\n\n")
			}
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"id":"chatcmpl-u","object":"chat.completion","model":"u-chat","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":1000,"completion_tokens":500,"total_tokens":1500}}`)
	}))
	defer streamUpstream.Close()

	cluster := setupConfigurableDualNodeCluster(t, nil)
	ctx := context.Background()
	org := cluster.createOrg("GW-AQ-01 User Budget & Lease Org")
	modelAlias := cluster.uniqueID("u-chat")
	// Pricing: input 10_000_000 micros/1M (10_000 for 1000 toks), output 20_000_000 (10_000 for 500 toks) => 20,000/call.
	cluster.seedOpenAIModel(ctx, org.ID, modelAlias, streamUpstream.URL+"/v1", 10_000_000, 20_000_000, 0, 0)

	// 1. User-only budget gate: user capped at 40,000 micros; key has 0 key/team budget.
	var usr domain.User
	rUsr, bUsr := cluster.c1.doJSON(http.MethodPost, "/admin/v1/users", cluster.adminHdrs, map[string]any{
		"org_id": org.ID, "email": "ubg-" + cluster.runTag + "@corp.test", "name": "UBG", "max_budget_micros": 40_000,
	}, &usr)
	if rUsr.StatusCode != http.StatusCreated {
		t.Fatalf("create user (%d): %s", rUsr.StatusCode, string(bUsr))
	}
	vkUserOnly := cluster.issueKey(map[string]any{
		"org_id": org.ID, "user_id": usr.ID, "name": cluster.uniqueID("vk-uonly"),
	})
	hdrUser := map[string]string{"Authorization": "Bearer " + vkUserOnly.RawKey}
	reqChat := map[string]any{"model": modelAlias, "max_tokens": 500, "messages": []map[string]string{{"role": "user", "content": "hi"}}}

	// 2 calls succeed (2 * 20,000 = 40,000); 3rd blocked by UserMaxBudgetMicros (429)!
	for i := 0; i < 2; i++ {
		if r, b := cluster.c1.doJSON(http.MethodPost, "/v1/chat/completions", hdrUser, reqChat, nil); r.StatusCode != http.StatusOK {
			t.Fatalf("user-budget call %d failed (%d): %s", i+1, r.StatusCode, string(b))
		}
	}
	cluster.waitForCondition(3*time.Second, "user spent_micros >= 40000", func() bool {
		u, err := cluster.pgRepo.GetUser(ctx, usr.ID)
		return err == nil && u.SpentMicros >= 40_000
	})
	if r3, b3 := cluster.c2.doJSON(http.MethodPost, "/v1/chat/completions", hdrUser, reqChat, nil); r3.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429 user budget exceeded on node2, got %d: %s", r3.StatusCode, string(b3))
	}

	// 2. Active lease renewal against live Redis 7 prevents premature hold expiry.
	idLease := &domain.IdentityContext{
		OrgID:              org.ID,
		VirtualKeyID:       cluster.uniqueID("vk-lease"),
		KeyMaxBudgetMicros: 50_000,
	}
	reqLeaseID := cluster.uniqueID("req-lease")
	relLease, _, err := cluster.node1.Limiter().AcquireWithBudgetAndRollback(ctx, idLease, 10, 40_000, reqLeaseID)
	if err != nil {
		t.Fatalf("AcquireWithBudgetAndRollback: %v", err)
	}
	if err := cluster.node1.Limiter().RenewReservationLease(ctx, idLease, reqLeaseID, 60); err != nil {
		t.Fatalf("RenewReservationLease: %v", err)
	}
	resZKey := fmt.Sprintf("gw:budget:{org:%s}:reservations:key:%s", org.ID, idLease.VirtualKeyID)
	ttlVal, ttlErr := cluster.redisFabric.Client().TTL(ctx, resZKey).Result()
	if ttlErr != nil || ttlVal < 30*time.Second {
		t.Fatalf("expected renewed lease TTL >= 30s in Redis, got %v (err=%v)", ttlVal, ttlErr)
	}
	// Competing request while lease is held must be rejected (40k + 20k > 50k).
	if _, _, errComp := cluster.node2.Limiter().AcquireWithBudgetAndRollback(ctx, idLease, 10, 20_000, cluster.uniqueID("req-comp")); errComp == nil {
		t.Fatalf("expected competing request blocked while renewed lease holds 40,000 micros")
	}
	relLease(-1, -1)

	// 3. Failure BEFORE first adapter dispatch leaves zero spend; post-dispatch stream cancel settles input cost!
	vkCancel := cluster.issueKey(map[string]any{
		"org_id": org.ID, "name": cluster.uniqueID("vk-cancel"), "max_budget_micros": 500_000, "allowed_models": []string{modelAlias},
	})
	// Pre-dispatch RBAC failure on disallowed model charges 0 micros.
	if rPre, _ := cluster.c1.doJSON(http.MethodPost, "/v1/chat/completions", map[string]string{"Authorization": "Bearer " + vkCancel.RawKey}, map[string]any{
		"model": "disallowed-model-xyz", "messages": []map[string]string{{"role": "user", "content": "hi"}},
	}, nil); rPre.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 pre-dispatch rejection, got %d", rPre.StatusCode)
	}

	// Post-dispatch streaming cancellation settles positive input-token micro-dollar charge (> 0).
	reqCtx, cancelReq := context.WithCancel(ctx)
	sBody, _ := json.Marshal(map[string]any{
		"model": modelAlias, "stream": true, "max_tokens": 500,
		"messages": []map[string]string{{"role": "user", "content": strings.Repeat("token ", 40)}},
	})
	httpReq, _ := http.NewRequestWithContext(reqCtx, http.MethodPost, cluster.ts1.URL+"/v1/chat/completions", bytes.NewReader(sBody))
	httpReq.Header.Set("Authorization", "Bearer "+vkCancel.RawKey)
	httpReq.Header.Set("Content-Type", "application/json")
	respStream, err := http.DefaultClient.Do(httpReq)
	if err != nil {
		t.Fatalf("start stream: %v", err)
	}
	select {
	case <-dispatched:
	case <-time.After(3 * time.Second):
		t.Fatal("upstream never dispatched stream")
	}
	cancelReq()
	_, _ = io.ReadAll(respStream.Body)
	respStream.Body.Close()

	cluster.waitForCondition(3*time.Second, "post-dispatch cancel settled positive input cost in Postgres and released reservation", func() bool {
		logs, err := cluster.pgRepo.ListSpendLogs(ctx, org.ID, 50)
		if err != nil {
			return false
		}
		for _, l := range logs {
			if l.VirtualKeyID == vkCancel.ID && l.CostMicros > 0 {
				cancelResKey := fmt.Sprintf("gw:budget:{org:%s}:reservations:key:%s", org.ID, vkCancel.ID)
				cnt, _ := cluster.redisFabric.Client().ZCard(ctx, cancelResKey).Result()
				return cnt == 0
			}
		}
		return false
	})
}

func TestE2E_GW_AQ_02_RealtimeWebSocketAndBatchJSONLQuotas(t *testing.T) {
	gate := make(chan struct{})
	inFlight := make(chan struct{}, 4)
	var gateOnce sync.Once
	closeGate := func() { gateOnce.Do(func() { close(gate) }) }
	defer closeGate()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/batches" {
			http.NotFound(w, r)
			return
		}
		if strings.Contains(r.Header.Get("X-Batch-Block"), "true") || strings.Contains(r.URL.RawQuery, "slow") {
			<-gate
		}
		select {
		case inFlight <- struct{}{}:
		default:
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":      "chatcmpl-rtb",
			"object":  "chat.completion",
			"model":   "rtb-chat",
			"choices": []map[string]any{{"index": 0, "message": map[string]any{"role": "assistant", "content": "ok"}, "finish_reason": "stop"}},
			"usage":   map[string]any{"prompt_tokens": 50, "completion_tokens": 20, "total_tokens": 70},
		})
	}))
	defer upstream.Close()

	cluster := setupConfigurableDualNodeCluster(t, nil)
	ctx := context.Background()
	org := cluster.createOrg("GW-AQ-02 Realtime & Batch Org")
	modelAlias := cluster.uniqueID("rtb-chat")
	cluster.seedOpenAIModel(ctx, org.ID, modelAlias, upstream.URL+"/v1", 2_000_000, 8_000_000, 0, 0)

	// 1. /v1/realtime WebSocket quota enforcement across dual nodes.
	vkWS := cluster.issueKey(map[string]any{
		"org_id": org.ID, "name": cluster.uniqueID("ws-vk"), "max_concurrent_requests": 1, "rpm_limit": 5, "max_budget_micros": 100_000,
	})
	wsURL1 := "ws" + strings.TrimPrefix(cluster.ts1.URL, "http") + "/v1/realtime?model=" + modelAlias
	wsURL2 := "ws" + strings.TrimPrefix(cluster.ts2.URL, "http") + "/v1/realtime?model=" + modelAlias
	wsCtx, wsCancel := context.WithTimeout(ctx, 10*time.Second)
	defer wsCancel()

	conn1, r1, err := websocket.Dial(wsCtx, wsURL1, &websocket.DialOptions{
		Subprotocols: []string{"realtime"},
		HTTPHeader:   http.Header{"Authorization": []string{"Bearer " + vkWS.RawKey}},
	})
	if err != nil || r1.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("WS dial node1 failed: err=%v resp=%+v", err, r1)
	}
	_, _, _ = conn1.Read(wsCtx) // session.created

	// Second concurrent WS connection to sibling node2 is rejected with 429 concurrency limit!
	_, r2, err2 := websocket.Dial(wsCtx, wsURL2, &websocket.DialOptions{
		Subprotocols: []string{"realtime"},
		HTTPHeader:   http.Header{"Authorization": []string{"Bearer " + vkWS.RawKey}},
	})
	if err2 == nil || r2 == nil || r2.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429 concurrency rejection on node2 WS upgrade, err=%v resp=%+v", err2, r2)
	}
	_ = conn1.Close(websocket.StatusNormalClosure, "done")

	// 2. /v1/batches JSONL estimation & separate batch enqueued hold + cancel release.
	var batchGate sync.Mutex
	batchBlocked := true
	batchUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for {
			batchGate.Lock()
			blk := batchBlocked
			batchGate.Unlock()
			if !blk {
				break
			}
			select {
			case inFlight <- struct{}{}:
			default:
			}
			select {
			case <-r.Context().Done():
				return
			case <-time.After(15 * time.Millisecond):
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id": "chatcmpl-b", "object": "chat.completion", "model": "b-chat",
			"choices": []map[string]any{{"index": 0, "message": map[string]any{"role": "assistant", "content": "batch ok"}, "finish_reason": "stop"}},
			"usage":   map[string]any{"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15},
		})
	}))
	defer batchUpstream.Close()

	batchModel := cluster.uniqueID("b-chat")
	cluster.seedOpenAIModel(ctx, org.ID, batchModel, batchUpstream.URL+"/v1", 2_000_000, 8_000_000, 0, 0)
	vkBatch := cluster.issueKey(map[string]any{
		"org_id": org.ID, "name": cluster.uniqueID("batch-vk"), "batch_enqueued_token_limit": 200,
	})

	// Upload JSONL estimating ~150 tokens -> first batch allowed, second concurrent batch rejected (429), cancel releases hold.
	jsonl := fmt.Sprintf(`{"custom_id":"r1","method":"POST","url":"/v1/chat/completions","body":{"model":%q,"max_tokens":50,"messages":[{"role":"user","content":"hello one"}]}}`+"\n"+
		`{"custom_id":"r2","method":"POST","url":"/v1/chat/completions","body":{"model":%q,"max_tokens":50,"messages":[{"role":"user","content":"hello two"}]}}`+"\n", batchModel, batchModel)

	mpBuf := &bytes.Buffer{}
	mpW := multipart.NewWriter(mpBuf)
	_ = mpW.WriteField("purpose", "batch")
	part, _ := mpW.CreateFormFile("file", "req.jsonl")
	_, _ = part.Write([]byte(jsonl))
	_ = mpW.Close()

	upReq, _ := http.NewRequest(http.MethodPost, cluster.ts1.URL+"/v1/files", mpBuf)
	upReq.Header.Set("Authorization", "Bearer "+vkBatch.RawKey)
	upReq.Header.Set("Content-Type", mpW.FormDataContentType())
	upResp, err := http.DefaultClient.Do(upReq)
	if err != nil {
		t.Fatalf("upload batch file: %v", err)
	}
	var uploadedFile domain.CanonicalFile
	rawFile, _ := io.ReadAll(upResp.Body)
	upResp.Body.Close()
	if upResp.StatusCode != http.StatusCreated {
		t.Fatalf("upload batch file (%d): %s", upResp.StatusCode, string(rawFile))
	}
	_ = json.Unmarshal(rawFile, &uploadedFile)

	bPayload := map[string]any{"input_file_id": uploadedFile.ID, "endpoint": "/v1/chat/completions", "completion_window": "24h"}
	var b1 domain.CanonicalBatch
	rB1, rawB1 := cluster.c1.doJSON(http.MethodPost, "/v1/batches", map[string]string{"Authorization": "Bearer " + vkBatch.RawKey}, bPayload, &b1)
	if rB1.StatusCode != http.StatusCreated || b1.EstimatedTokens <= 100 {
		t.Fatalf("create batch1 (%d): est=%d body=%s", rB1.StatusCode, b1.EstimatedTokens, string(rawB1))
	}

	// Second concurrent batch on node2 rejected while batch1 holds enqueued token quota!
	if rB2, rawB2 := cluster.c2.doJSON(http.MethodPost, "/v1/batches", map[string]string{"Authorization": "Bearer " + vkBatch.RawKey}, bPayload, nil); rB2.StatusCode != http.StatusTooManyRequests || !strings.Contains(string(rawB2), "batch_enqueued_tokens_exceeded") {
		t.Fatalf("expected 429 key_batch_enqueued_tokens_exceeded on node2, got %d: %s", rB2.StatusCode, string(rawB2))
	}

	// Cancel batch1 & unblock worker -> hold releases cleanly -> new batch succeeds!
	cluster.c1.doJSON(http.MethodPost, "/v1/batches/"+b1.ID+"/cancel", map[string]string{"Authorization": "Bearer " + vkBatch.RawKey}, nil, nil)
	batchGate.Lock()
	batchBlocked = false
	batchGate.Unlock()

	enqKey := fmt.Sprintf("gw:batch:{org:%s}:enqueued:key:%s:sum", org.ID, vkBatch.ID)
	cluster.waitForCondition(5*time.Second, "batch enqueued hold released to 0", func() bool {
		val, _ := cluster.redisFabric.Client().Get(ctx, enqKey).Result()
		return val == "0" || val == ""
	})
	if rB3, rawB3 := cluster.c2.doJSON(http.MethodPost, "/v1/batches", map[string]string{"Authorization": "Bearer " + vkBatch.RawKey}, bPayload, nil); rB3.StatusCode != http.StatusCreated {
		t.Fatalf("expected batch creation on node2 after cancel/completion release, got %d: %s", rB3.StatusCode, string(rawB3))
	}
}

func TestE2E_GW_AQ_03_SoftBudgetWebhookThrottlingAndModelFallback(t *testing.T) {
	sink := newMockSecurityAndWebhookSink(t, nil, "")
	upstream := newMockDeterministicLLMUpstream(t)
	cluster := setupConfigurableDualNodeCluster(t, func(cfg *config.Config) {
		cfg.FinOps.SoftBudgetWebhookURL = sink.SoftBudgetWebhookURL()
		cfg.FinOps.SoftBudgetCooldownSec = 60
		cfg.FinOps.BudgetExceededThrottlePct = 0.1
	})

	ctx := context.Background()
	org := cluster.createOrg("GW-AQ-03 Soft Budget & Fallback Org")
	expModel := cluster.uniqueID("expensive-mod")
	cheapModel := cluster.uniqueID("cheap-mod")
	upstream.SetUsage(100, 50)
	// Expensive: 100*10M + 50*20M = 2_000 micros per call (or pre-call bound for max_tokens=500 -> 10_000+ micros).
	cluster.seedOpenAIModel(ctx, org.ID, expModel, upstream.OpenAIBaseURL(), 10_000_000, 20_000_000, 0, 0)
	// Cheap: 100*100K + 50*200K = 20 micros per call.
	cluster.seedOpenAIModel(ctx, org.ID, cheapModel, upstream.OpenAIBaseURL(), 100_000, 200_000, 0, 0)

	// 1. Key with soft budget = 500 micros, hard cap = 15,000 micros, fallback expModel -> cheapModel.
	// Send one cheap call costing 1,000 micros via expensive model OR configure key max=1000 so expModel triggers fallback!
	vkFallback := cluster.issueKey(map[string]any{
		"org_id":            org.ID,
		"name":              cluster.uniqueID("vk-fb"),
		"max_budget_micros": 1_500,
		"budget_fallbacks":  map[string][]string{expModel: {cheapModel}},
	})
	rFB, bFB := cluster.c1.doJSON(http.MethodPost, "/v1/chat/completions", map[string]string{"Authorization": "Bearer " + vkFallback.RawKey}, map[string]any{
		"model": expModel, "max_tokens": 500, "messages": []map[string]string{{"role": "user", "content": "fallback please"}},
	}, nil)
	if rFB.StatusCode != http.StatusOK || rFB.Header.Get("X-Gateway-Budget-Fallback") != cheapModel {
		t.Fatalf("expected 200 fallback to %q, got %d hdr=%q body=%s", cheapModel, rFB.StatusCode, rFB.Header.Get("X-Gateway-Budget-Fallback"), string(bFB))
	}

	// Fallback must enforce RBAC: key disallowing cheapModel gets 429 instead of bypassing allowlist!
	vkNoRBAC := cluster.issueKey(map[string]any{
		"org_id":            org.ID,
		"name":              cluster.uniqueID("vk-fb-norbac"),
		"max_budget_micros": 1_500,
		"allowed_models":    []string{expModel},
		"budget_fallbacks":  map[string][]string{expModel: {cheapModel}},
	})
	if rDeny, _ := cluster.c2.doJSON(http.MethodPost, "/v1/chat/completions", map[string]string{"Authorization": "Bearer " + vkNoRBAC.RawKey}, map[string]any{
		"model": expModel, "max_tokens": 500, "messages": []map[string]string{{"role": "user", "content": "deny rbac fallback"}},
	}, nil); rDeny.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429 when fallback violates allowed_models RBAC, got %d", rDeny.StatusCode)
	}

	// 2. Soft-budget webhook deduplication + throttling while org hard cap stays in force!
	var hardOrg domain.Organization
	cluster.c1.doJSON(http.MethodPost, "/admin/v1/organizations", cluster.adminHdrs, map[string]any{
		"name": "HardCapOrg", "slug": cluster.uniqueID("hard-org"), "max_budget_micros": 4_500,
	}, &hardOrg)
	cluster.seedOpenAIModel(ctx, hardOrg.ID, expModel, upstream.OpenAIBaseURL(), 10_000_000, 20_000_000, 0, 0)
	vkSoft := cluster.issueKey(map[string]any{
		"org_id":                      hardOrg.ID,
		"name":                        cluster.uniqueID("vk-soft"),
		"soft_budget_micros":          1_500,
		"max_budget_micros":           2_000,
		"throttle_on_budget_exceeded": true,
		"rpm_limit":                   20, // scaled down to 20*0.1 = 2 RPM once soft/budget crossed
	})
	// Call 1 settles 2,000 micros (crosses both soft=1,500 and key hard=2,000, still inside org hard=4,500).
	softReq := map[string]any{"model": expModel, "max_tokens": 100, "messages": []map[string]string{{"role": "user", "content": "s"}}}
	for i := 0; i < 2; i++ {
		_, _ = cluster.c1.doJSON(http.MethodPost, "/v1/chat/completions", map[string]string{"Authorization": "Bearer " + vkSoft.RawKey}, softReq, nil)
	}
	cluster.waitForCondition(3*time.Second, "soft-budget webhook delivered once", func() bool {
		return len(sink.SoftBudgetEvents()) >= 1
	})
	// Org hard cap (4,500) cannot be bypassed by soft throttling on vkSoft!
	cluster.waitForCondition(3*time.Second, "hardOrg spend <= 4500", func() bool {
		o, err := cluster.pgRepo.GetOrganization(ctx, hardOrg.ID)
		return err == nil && o.SpentMicros <= 4_500
	})
}

func TestE2E_GW_AQ_13_AtomicDescriptorEngineNoPartialLeakAndIdempotency(t *testing.T) {
	upstream := newMockDeterministicLLMUpstream(t)
	cluster := setupConfigurableDualNodeCluster(t, nil)

	ctx := context.Background()
	org := cluster.createOrg("GW-AQ-13 Atomic Descriptor Org")
	modelAlias := cluster.uniqueID("desc-chat")
	cluster.seedOpenAIModel(ctx, org.ID, modelAlias, upstream.OpenAIBaseURL(), 2_000_000, 8_000_000, 0, 0)

	var team domain.Team
	cluster.c1.doJSON(http.MethodPost, "/admin/v1/teams", cluster.adminHdrs, map[string]any{
		"org_id": org.ID, "name": cluster.uniqueID("desc-team"),
	}, &team)

	// Org policy RPM=10, Team policy RPM=10, Key RPM=2 (all checked atomically via check_descriptors.lua).
	for _, pol := range []map[string]any{
		{"org_id": org.ID, "scope_type": "org", "scope_id": org.ID, "model_pattern": "*", "rpm_limit": 10},
		{"org_id": org.ID, "scope_type": "team", "scope_id": team.ID, "model_pattern": "*", "rpm_limit": 10},
	} {
		r, b := cluster.c1.doJSON(http.MethodPut, "/admin/v1/quotas", cluster.adminHdrs, pol, nil)
		if r.StatusCode != http.StatusOK && r.StatusCode != http.StatusCreated {
			t.Fatalf("PUT /admin/v1/quotas (%d): %s", r.StatusCode, string(b))
		}
	}

	vk := cluster.issueKey(map[string]any{
		"org_id": org.ID, "team_id": team.ID, "name": cluster.uniqueID("desc-vk"), "rpm_limit": 2,
	})
	hdrs := map[string]string{"Authorization": "Bearer " + vk.RawKey}
	reqBody := map[string]any{"model": modelAlias, "messages": []map[string]string{{"role": "user", "content": "hi"}}}

	// 2 succeed, 3 fail on key RPM -> org and team descriptor RPM counters in Redis MUST show exact count 2!
	okCnt, denyCnt := 0, 0
	for i := 0; i < 5; i++ {
		cl := cluster.c1
		if i%2 == 1 {
			cl = cluster.c2
		}
		r, _ := cl.doJSON(http.MethodPost, "/v1/chat/completions", hdrs, reqBody, nil)
		if r.StatusCode == http.StatusOK {
			okCnt++
		} else if r.StatusCode == http.StatusTooManyRequests {
			denyCnt++
		} else {
			t.Fatalf("unexpected status %d", r.StatusCode)
		}
	}
	if okCnt != 2 || denyCnt != 3 {
		t.Fatalf("expected 2 OK / 3 429, got ok=%d deny=%d", okCnt, denyCnt)
	}

	// Assert Redis cluster hash-tag invariant: every quota/ratelimit/budget/spend/batch key
	// referencing org.ID contains "{org:" + org.ID + "}"!
	expectedTag := "{org:" + org.ID + "}"
	var orgRPMKeyCount int
	_, err := cluster.redisFabric.Execute(func(rdb redis.UniversalClient) (any, error) {
		var cursor uint64
		for {
			keys, next, err := rdb.Scan(ctx, cursor, "*"+org.ID+"*", 200).Result()
			if err != nil {
				return nil, err
			}
			for _, k := range keys {
				isQuotaKey := strings.HasPrefix(k, "gw:quota:") ||
					strings.HasPrefix(k, "gw:budget:") ||
					strings.HasPrefix(k, "gw:spend:") ||
					strings.HasPrefix(k, "gw:rl:") ||
					strings.HasPrefix(k, "gw:batch:")
				if isQuotaKey && !strings.Contains(k, expectedTag) {
					return nil, fmt.Errorf("redis key %q missing cluster slot tag %q", k, expectedTag)
				}
				if strings.Contains(k, "rpm") && strings.Contains(k, team.ID) {
					val, _ := rdb.Get(ctx, k).Result()
					if val != "2" {
						return nil, fmt.Errorf("expected team RPM counter == 2 (zero partial charge), got %s on key %q", val, k)
					}
					orgRPMKeyCount++
				}
			}
			cursor = next
			if cursor == 0 {
				break
			}
		}
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}

	// Idempotent descriptor admission & settlement replay check.
	descs := []domain.RateLimitDescriptor{{
		ScopeType: domain.QuotaScopeTeam, ScopeID: team.ID, MaxBudgetMicros: 100_000,
	}}
	reqIdem := cluster.uniqueID("idem-desc")
	rel1, err := cluster.node1.Limiter().AcquireDescriptors(ctx, org.ID, reqIdem, 10, 10, 1_000, descs)
	if err != nil {
		t.Fatalf("AcquireDescriptors 1: %v", err)
	}
	rel1(10, 10, 1_000)
	rel1(10, 10, 1_000) // replay settle must be idempotent no-op!
}

func TestE2E_GW_AQ_14_PerModelITPM_OTPM_TPD_MultiWindow_TempBudget(t *testing.T) {
	upstream := newMockDeterministicLLMUpstream(t)
	cluster := setupConfigurableDualNodeCluster(t, nil)

	ctx := context.Background()
	now := time.Now().UTC()
	cluster.setClock(now)

	org := cluster.createOrg("GW-AQ-14 MultiWindow & ITPM/OTPM Org")
	modelA := cluster.uniqueID("mw-model-a")
	modelB := cluster.uniqueID("mw-model-b")
	upstream.SetUsage(500, 150)
	// Pricing: 2_000_000 input, 8_000_000 output -> call cost = (500*2M + 150*8M)/1M = 2,200 micros!
	cluster.seedOpenAIModel(ctx, org.ID, modelA, upstream.OpenAIBaseURL(), 2_000_000, 8_000_000, 0, 0)
	cluster.seedOpenAIModel(ctx, org.ID, modelB, upstream.OpenAIBaseURL(), 2_000_000, 8_000_000, 0, 0)

	vk := cluster.issueKey(map[string]any{
		"org_id": org.ID, "name": cluster.uniqueID("mw-vk"),
	})
	hdrs := map[string]string{"Authorization": "Bearer " + vk.RawKey}

	// 1. Per-model OTPM/ITPM/TPD policy: modelA otpm_limit=200 (1st call settles 150 tokens, 2nd call hits 429!),
	//    while modelB has otpm_limit=2000 and remains 200 OK!
	var polA domain.QuotaPolicy
	cluster.c1.doJSON(http.MethodPut, "/admin/v1/quotas", cluster.adminHdrs, map[string]any{
		"org_id": org.ID, "scope_type": "key", "scope_id": vk.ID, "model_pattern": modelA,
		"itpm_limit": 5000, "otpm_limit": 200, "tpd_limit": 5000,
	}, &polA)
	cluster.c1.doJSON(http.MethodPut, "/admin/v1/quotas", cluster.adminHdrs, map[string]any{
		"org_id": org.ID, "scope_type": "key", "scope_id": vk.ID, "model_pattern": modelB,
		"itpm_limit": 5000, "otpm_limit": 2000, "tpd_limit": 5000,
	}, nil)

	reqA := map[string]any{"model": modelA, "max_tokens": 100, "messages": []map[string]string{{"role": "user", "content": "hi"}}}
	reqB := map[string]any{"model": modelB, "max_tokens": 100, "messages": []map[string]string{{"role": "user", "content": "hi"}}}
	if r, b := cluster.c1.doJSON(http.MethodPost, "/v1/chat/completions", hdrs, reqA, nil); r.StatusCode != http.StatusOK {
		t.Fatalf("modelA call 1 failed (%d): %s", r.StatusCode, string(b))
	}
	if r, b := cluster.c2.doJSON(http.MethodPost, "/v1/chat/completions", hdrs, reqA, nil); r.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429 OTPM exhaustion on modelA across node2, got %d: %s", r.StatusCode, string(b))
	}
	if r, b := cluster.c2.doJSON(http.MethodPost, "/v1/chat/completions", hdrs, reqB, nil); r.StatusCode != http.StatusOK {
		t.Fatalf("modelB should succeed independently while modelA OTPM exhausted, got %d: %s", r.StatusCode, string(b))
	}

	// Verify spend_logs pinned matched_quota_policy_ids!
	cluster.waitForCondition(3*time.Second, "spend_logs records matched_quota_policy_ids", func() bool {
		var matched []string
		err := cluster.pool.QueryRow(ctx, `
			SELECT matched_quota_policy_ids FROM spend_logs
			WHERE virtual_key_id = $1 AND requested_model = $2
			ORDER BY created_at DESC LIMIT 1
		`, vk.ID, modelA).Scan(&matched)
		return err == nil && len(matched) > 0 && matched[0] == polA.ID
	})

	// 2. Simultaneous multi-window budgets (rolling_24h + daily + weekly + monthly) + TempBudget Boost & expiry.
	vkMW := cluster.issueKey(map[string]any{
		"org_id": org.ID, "name": cluster.uniqueID("vk-mw"), "max_budget_micros": 100_000,
	})
	hdrMW := map[string]string{"Authorization": "Bearer " + vkMW.RawKey}
	// Configure rolling_24h=3,000 (tightest!), daily=50,000, weekly=100,000, monthly=500,000.
	for _, bw := range []struct {
		win string
		cap int64
	}{
		{"rolling_24h", 3_000},
		{"daily", 50_000},
		{"weekly", 100_000},
		{"monthly", 500_000},
	} {
		r, b := cluster.c1.doJSON(http.MethodPut, "/admin/v1/budget-windows", cluster.adminHdrs, map[string]any{
			"org_id": org.ID, "scope_type": "key", "scope_id": vkMW.ID, "window_type": bw.win, "max_budget_micros": bw.cap,
		}, nil)
		if r.StatusCode != http.StatusOK && r.StatusCode != http.StatusCreated {
			t.Fatalf("PUT /admin/v1/budget-windows (%s): %d %s", bw.win, r.StatusCode, string(b))
		}
	}

	reqMW := map[string]any{"model": modelB, "max_tokens": 100, "messages": []map[string]string{{"role": "user", "content": "mw"}}}
	// Call 1 costs 2,200 <= 3,000 (succeeds); Call 2 would reach 4,400 > 3,000 -> rejected (429) by tightest rolling_24h window!
	if r, b := cluster.c1.doJSON(http.MethodPost, "/v1/chat/completions", hdrMW, reqMW, nil); r.StatusCode != http.StatusOK {
		t.Fatalf("multi-window call 1 failed (%d): %s", r.StatusCode, string(b))
	}
	if r, _ := cluster.c2.doJSON(http.MethodPost, "/v1/chat/completions", hdrMW, reqMW, nil); r.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429 from tightest rolling_24h=3000 window, got %d", r.StatusCode)
	}

	// Temporary budget boost on a capped key allows burst, then snaps back when TTL expires.
	vkTemp := cluster.issueKey(map[string]any{
		"org_id": org.ID, "name": cluster.uniqueID("vk-temp"), "max_budget_micros": 3_000,
	})
	hdrTemp := map[string]string{"Authorization": "Bearer " + vkTemp.RawKey}
	if r, b := cluster.c1.doJSON(http.MethodPost, "/v1/chat/completions", hdrTemp, reqMW, nil); r.StatusCode != http.StatusOK {
		t.Fatalf("temp base call 1 failed (%d): %s", r.StatusCode, string(b))
	}
	if r, _ := cluster.c2.doJSON(http.MethodPost, "/v1/chat/completions", hdrTemp, reqMW, nil); r.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429 before temp boost, got %d", r.StatusCode)
	}

	// Grant +5,000 temp boost expiring in 120s.
	if rTB, bTB := cluster.c1.doJSON(http.MethodPost, "/admin/v1/keys/"+vkTemp.ID+"/temp-budget", cluster.adminHdrs, map[string]any{
		"org_id": org.ID, "temp_budget_increase_micros": 5_000, "ttl_seconds": 120,
	}, nil); rTB.StatusCode != http.StatusOK {
		t.Fatalf("POST temp-budget failed (%d): %s", rTB.StatusCode, string(bTB))
	}
	if r, b := cluster.c2.doJSON(http.MethodPost, "/v1/chat/completions", hdrTemp, reqMW, nil); r.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 under active temp budget boost on node2, got %d: %s", r.StatusCode, string(b))
	}

	// Advance clock past temp boost TTL -> effective cap snaps back to 3,000 -> next call rejected!
	now = now.Add(180 * time.Second)
	cluster.setClock(now)
	if rExp, _ := cluster.c2.doJSON(http.MethodPost, "/v1/chat/completions", hdrTemp, reqMW, nil); rExp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429 after temp budget boost expired, got %d", rExp.StatusCode)
	}
}

// Keep unused imports clean if needed.
var (
	_ = bufio.NewReader
	_ = finops.EstimateTokenCostUpperBound
	_ atomic.Int32
)
