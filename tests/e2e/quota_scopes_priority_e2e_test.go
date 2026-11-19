package e2e_test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

func TestE2E_GW_AQ_15_EndUserTagMAGSessionAndMCPQuotas(t *testing.T) {
	upstream := newMockDeterministicLLMUpstream(t)
	cluster := setupConfigurableDualNodeCluster(t, nil)

	ctx := context.Background()
	org := cluster.createOrg("GW-AQ-15 Contextual Scopes Org")
	modelAlpha := cluster.uniqueID("scope-alpha")
	modelBeta := cluster.uniqueID("scope-beta")
	modelSess := cluster.uniqueID("scope-sess")
	upstream.SetUsage(100, 50)
	cluster.seedOpenAIModel(ctx, org.ID, modelAlpha, upstream.OpenAIBaseURL(), 2_000_000, 8_000_000, 0, 0)
	cluster.seedOpenAIModel(ctx, org.ID, modelBeta, upstream.OpenAIBaseURL(), 2_000_000, 8_000_000, 0, 0)
	cluster.seedOpenAIModel(ctx, org.ID, modelSess, upstream.OpenAIBaseURL(), 2_000_000, 8_000_000, 0, 0)

	var team domain.Team
	cluster.c1.doJSON(http.MethodPost, "/admin/v1/teams", cluster.adminHdrs, map[string]any{
		"org_id": org.ID, "name": cluster.uniqueID("scope-team"),
	}, &team)

	vk := cluster.issueKey(map[string]any{
		"org_id":              org.ID,
		"team_id":             team.ID,
		"name":                cluster.uniqueID("scopes-vk"),
		"key_type":            "llm_api",
		"max_iterations":      2,
		"allowed_endpoints":   []string{"*"},
		"allowed_mcp_servers": []string{"*"},
	})
	vkHdrs := map[string]string{"Authorization": "Bearer " + vk.RawKey}

	// 1. EndUser scope: eu-1 capped at RPM=1; eu-2 unaffected under identical virtual key.
	resp, raw := cluster.c1.doJSON(http.MethodPost, "/admin/v1/end-users", cluster.adminHdrs, map[string]any{
		"org_id": org.ID, "end_user_id": "eu-1", "rpm_limit": 1,
	}, nil)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		t.Fatalf("upsert end-user (%d): %s", resp.StatusCode, string(raw))
	}
	if r, b := cluster.c1.doJSON(http.MethodPost, "/v1/chat/completions", vkHdrs, map[string]any{
		"model": modelAlpha, "user": "eu-1", "messages": []map[string]string{{"role": "user", "content": "eu1-a"}},
	}, nil); r.StatusCode != http.StatusOK {
		t.Fatalf("eu-1 call 1 failed (%d): %s", r.StatusCode, string(b))
	}
	if r, _ := cluster.c2.doJSON(http.MethodPost, "/v1/chat/completions", vkHdrs, map[string]any{
		"model": modelAlpha, "user": "eu-1", "messages": []map[string]string{{"role": "user", "content": "eu1-b"}},
	}, nil); r.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429 on eu-1 RPM=1 across node2, got %d", r.StatusCode)
	}
	if r, b := cluster.c2.doJSON(http.MethodPost, "/v1/chat/completions", vkHdrs, map[string]any{
		"model": modelAlpha, "user": "eu-2", "messages": []map[string]string{{"role": "user", "content": "eu2-a"}},
	}, nil); r.StatusCode != http.StatusOK {
		t.Fatalf("eu-2 should remain unaffected (%d): %s", r.StatusCode, string(b))
	}

	// 2. Tag scope: tag "env:canary" RPM=1 enforced across node1 -> node2.
	resp, raw = cluster.c1.doJSON(http.MethodPost, "/admin/v1/tags", cluster.adminHdrs, map[string]any{
		"org_id": org.ID, "tag": "env:canary", "rpm_limit": 1,
	}, nil)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		t.Fatalf("upsert tag (%d): %s", resp.StatusCode, string(raw))
	}
	tagHdrs := map[string]string{
		"Authorization":  "Bearer " + vk.RawKey,
		"X-Gateway-Tags": "env:canary",
	}
	if r, b := cluster.c1.doJSON(http.MethodPost, "/v1/chat/completions", tagHdrs, map[string]any{
		"model": modelAlpha, "messages": []map[string]string{{"role": "user", "content": "tag-1"}},
	}, nil); r.StatusCode != http.StatusOK {
		t.Fatalf("tag call 1 failed (%d): %s", r.StatusCode, string(b))
	}
	if r, b := cluster.c2.doJSON(http.MethodPost, "/v1/chat/completions", tagHdrs, map[string]any{
		"model": modelAlpha, "messages": []map[string]string{{"role": "user", "content": "tag-2"}},
	}, nil); r.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429 for env:canary tag RPM=1 on node2, got %d: %s", r.StatusCode, string(b))
	}

	// 3. ModelAccessGroup shared RPM=1 across modelAlpha & modelBeta.
	var magResp struct {
		Group domain.ModelAccessGroup `json:"group"`
	}
	resp, raw = cluster.c1.doJSON(http.MethodPost, "/admin/v1/model-access-groups", cluster.adminHdrs, map[string]any{
		"org_id": org.ID, "name": cluster.uniqueID("shared-pool"), "rpm_limit": 1,
	}, &magResp)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create MAG (%d): %s", resp.StatusCode, string(raw))
	}
	magID := magResp.Group.ID
	if magID == "" {
		var m map[string]any
		_ = json.Unmarshal(raw, &m)
		magID, _ = m["id"].(string)
	}
	for _, mod := range []string{modelAlpha, modelBeta} {
		cluster.c1.doJSON(http.MethodPost, "/admin/v1/model-access-groups/"+magID+"/members", cluster.adminHdrs, map[string]any{
			"org_id": org.ID, "member_type": "model", "member_id": mod,
		}, nil)
	}
	cluster.c1.doJSON(http.MethodPost, "/admin/v1/model-access-groups/"+magID+"/members", cluster.adminHdrs, map[string]any{
		"org_id": org.ID, "member_type": "team", "member_id": team.ID,
	}, nil)

	// Wait a clean separation or use clean user/tags without previous limiter counters? Note: call 1 used modelAlpha,
	// Wait: eu-2 call created earlier already ran BEFORE MAG was created, so MAG counter starts at 0!
	if r, b := cluster.c1.doJSON(http.MethodPost, "/v1/chat/completions", vkHdrs, map[string]any{
		"model": modelAlpha, "messages": []map[string]string{{"role": "user", "content": "mag-1"}},
	}, nil); r.StatusCode != http.StatusOK {
		t.Fatalf("MAG modelAlpha call 1 failed (%d): %s", r.StatusCode, string(b))
	}
	if r, b := cluster.c2.doJSON(http.MethodPost, "/v1/chat/completions", vkHdrs, map[string]any{
		"model": modelBeta, "messages": []map[string]string{{"role": "user", "content": "mag-2"}},
	}, nil); r.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429 shared MAG pool exhausted via modelBeta on node2, got %d: %s", r.StatusCode, string(b))
	}

	// 4. AgentSession (X-Gateway-Session-Id) max_iterations=2 independently enforced per session ID.
	sess1Hdrs := map[string]string{"Authorization": "Bearer " + vk.RawKey, "X-Gateway-Session-Id": "sess-1-" + cluster.runTag}
	sess2Hdrs := map[string]string{"Authorization": "Bearer " + vk.RawKey, "X-Gateway-Session-Id": "sess-2-" + cluster.runTag}
	for turn := 1; turn <= 2; turn++ {
		if r, b := cluster.c1.doJSON(http.MethodPost, "/v1/chat/completions", sess1Hdrs, map[string]any{
			"model": modelSess, "messages": []map[string]string{{"role": "user", "content": "turn"}},
		}, nil); r.StatusCode != http.StatusOK {
			t.Fatalf("sess-1 turn %d failed (%d): %s", turn, r.StatusCode, string(b))
		}
	}
	if r, b := cluster.c2.doJSON(http.MethodPost, "/v1/chat/completions", sess1Hdrs, map[string]any{
		"model": modelSess, "messages": []map[string]string{{"role": "user", "content": "turn-3"}},
	}, nil); r.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429 agent_session_iterations_exceeded on node2, got %d: %s", r.StatusCode, string(b))
	}
	if r, b := cluster.c2.doJSON(http.MethodPost, "/v1/chat/completions", sess2Hdrs, map[string]any{
		"model": modelSess, "messages": []map[string]string{{"role": "user", "content": "sess2"}},
	}, nil); r.StatusCode != http.StatusOK {
		t.Fatalf("independent sess-2 failed (%d): %s", r.StatusCode, string(b))
	}

	// 5. Upstream MCP server RPM limit: blocks excess tools/call at gateway before upstream egress.
	mcpSlug := cluster.uniqueID("mcp-rpm")
	var mcpCreated struct {
		Server domain.MCPServer `json:"server"`
	}
	resp, raw = cluster.c1.doJSON(http.MethodPost, "/admin/v1/mcp/servers", cluster.adminHdrs, map[string]any{
		"org_id": org.ID, "name": "RPM Capped MCP", "slug": mcpSlug,
		"protocol_version": "2026-07-28", "transport_type": "streamable_http",
		"endpoint_url": upstream.MCPEndpointURL(), "auth_type": "none", "rpm_limit": 2,
	}, &mcpCreated)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create rpm-limited mcp server (%d): %s", resp.StatusCode, string(raw))
	}
	cluster.c1.doJSON(http.MethodPost, "/admin/v1/mcp/servers/"+mcpCreated.Server.ID+"/sync", cluster.adminHdrs, nil, nil)

	// Issue default key (not llm_api, since llm_api restricts endpoints to /v1/* only) for MCP calls.
	vkMCP := cluster.issueKey(map[string]any{
		"org_id":              org.ID,
		"team_id":             team.ID,
		"name":                cluster.uniqueID("mcp-scopes-vk"),
		"allowed_endpoints":   []string{"*"},
		"allowed_mcp_servers": []string{"*"},
	})
	vkMCPHdrs := map[string]string{"Authorization": "Bearer " + vkMCP.RawKey}

	callsBeforeMCP := upstream.MCPCalls()
	mcpReq := map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": map[string]any{"name": "echo_tool", "arguments": map[string]string{"msg": "hi"}}}
	type rpcEnvelope struct {
		Result any `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	for i := 0; i < 2; i++ {
		var rpcResp rpcEnvelope
		r, b := cluster.c1.doJSON(http.MethodPost, "/mcp/"+mcpSlug, vkMCPHdrs, mcpReq, &rpcResp)
		if r.StatusCode != http.StatusOK || rpcResp.Error != nil {
			t.Fatalf("mcp call %d failed (%d): %s", i+1, r.StatusCode, string(b))
		}
	}
	var rpcErrResp rpcEnvelope
	r3, b3 := cluster.c2.doJSON(http.MethodPost, "/mcp/"+mcpSlug, vkMCPHdrs, mcpReq, &rpcErrResp)
	if r3.StatusCode != http.StatusTooManyRequests {
		if r3.StatusCode != http.StatusOK || rpcErrResp.Error == nil || !strings.Contains(rpcErrResp.Error.Message, "mcp_server_rpm_exceeded") {
			t.Fatalf("expected 429 or JSON-RPC mcp_server_rpm_exceeded error on 3rd MCP call exceeding rpm_limit=2 across node2, got %d: %s", r3.StatusCode, string(b3))
		}
	}
	if delta := upstream.MCPCalls() - callsBeforeMCP; delta != 2 {
		t.Fatalf("expected upstream mock MCP called exactly 2 times, got %d", delta)
	}
}

func TestE2E_GW_AQ_16_SaturationPriorityCapacityAndPTUTeamShares(t *testing.T) {
	upstream := newMockDeterministicLLMUpstream(t)
	cluster := setupConfigurableDualNodeCluster(t, func(cfg *config.Config) {
		cfg.Router.PriorityCapacity = config.PriorityCapacityConfig{
			Enabled:               true,
			SaturationThreshold:   0.60,
			ActiveCallerTTL:       30 * time.Second,
			WindowDuration:        time.Minute,
			DefaultWeight:         1.0,
			DefaultBorrowMultiple: 2.0,
		}
	})

	ctx := context.Background()
	org := cluster.createOrg("GW-AQ-16 PTU & Priority Org")
	modelAlias := cluster.uniqueID("ptu-chat")
	upstream.SetUsage(100, 50)
	// Seed deployment with tight RPMCapacity=3 and TPMCapacity=100_000.
	_, _, depID := cluster.seedOpenAIModel(ctx, org.ID, modelAlias, upstream.OpenAIBaseURL(), 2_000_000, 8_000_000, 3, 100_000)

	var teamAlpha, teamBeta domain.Team
	cluster.c1.doJSON(http.MethodPost, "/admin/v1/teams", cluster.adminHdrs, map[string]any{"org_id": org.ID, "name": cluster.uniqueID("alpha-team")}, &teamAlpha)
	cluster.c1.doJSON(http.MethodPost, "/admin/v1/teams", cluster.adminHdrs, map[string]any{"org_id": org.ID, "name": cluster.uniqueID("beta-team")}, &teamBeta)

	// Priority classes: critical (rank 1, weight 4.0) vs batch (rank 3, weight 0.5).
	cluster.c1.doJSON(http.MethodPost, "/admin/v1/priority-classes", cluster.adminHdrs, map[string]any{
		"org_id": org.ID, "name": "critical", "weight": 4.0, "priority_rank": 1, "max_borrow_multiple": 2.0,
	}, nil)
	cluster.c1.doJSON(http.MethodPost, "/admin/v1/priority-classes", cluster.adminHdrs, map[string]any{
		"org_id": org.ID, "name": "batch", "weight": 0.5, "priority_rank": 3, "max_borrow_multiple": 1.0,
	}, nil)

	// Assign PTU shares on deployment: Team Alpha 2 RPM reserved, Team Beta 1 RPM reserved.
	if r, b := cluster.c1.doJSON(http.MethodPost, "/admin/v1/deployments/"+depID+"/ptu-shares", cluster.adminHdrs, map[string]any{
		"org_id": org.ID, "team_id": teamAlpha.ID, "reserved_rpm": 2, "reserved_tpm": 50_000,
	}, nil); r.StatusCode != http.StatusOK && r.StatusCode != http.StatusCreated {
		t.Fatalf("upsert PTU share Alpha (%d): %s", r.StatusCode, string(b))
	}
	if r, b := cluster.c1.doJSON(http.MethodPost, "/admin/v1/deployments/"+depID+"/ptu-shares", cluster.adminHdrs, map[string]any{
		"org_id": org.ID, "team_id": teamBeta.ID, "reserved_rpm": 1, "reserved_tpm": 25_000,
	}, nil); r.StatusCode != http.StatusOK && r.StatusCode != http.StatusCreated {
		t.Fatalf("upsert PTU share Beta (%d): %s", r.StatusCode, string(b))
	}

	vkAlpha := cluster.issueKey(map[string]any{"org_id": org.ID, "team_id": teamAlpha.ID, "name": cluster.uniqueID("alpha-vk")})
	vkBeta := cluster.issueKey(map[string]any{"org_id": org.ID, "team_id": teamBeta.ID, "name": cluster.uniqueID("beta-vk")})

	chatBody := map[string]any{"model": modelAlias, "messages": []map[string]string{{"role": "user", "content": "ptu"}}}

	// Team Beta hits its reserved 1 RPM share -> 2nd request rejected with ptu_share_exceeded / 429,
	// leaving Team Alpha's 2 RPM share protected without starvation.
	if r, b := cluster.c1.doJSON(http.MethodPost, "/v1/chat/completions", map[string]string{
		"Authorization": "Bearer " + vkBeta.RawKey, "X-Gateway-Priority": "3",
	}, chatBody, nil); r.StatusCode != http.StatusOK {
		t.Fatalf("Team Beta 1st PTU request failed (%d): %s", r.StatusCode, string(b))
	}
	if r, b := cluster.c2.doJSON(http.MethodPost, "/v1/chat/completions", map[string]string{
		"Authorization": "Bearer " + vkBeta.RawKey, "X-Gateway-Priority": "3",
	}, chatBody, nil); r.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429 when Team Beta exceeds reserved_rpm=1 under node2, got %d: %s", r.StatusCode, string(b))
	}

	// Team Alpha still completes both of its reserved critical requests cleanly across node1 and node2.
	var wg sync.WaitGroup
	results := make(chan int, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			cl := cluster.c1
			if idx%2 == 1 {
				cl = cluster.c2
			}
			r, _ := cl.doJSON(http.MethodPost, "/v1/chat/completions", map[string]string{
				"Authorization": "Bearer " + vkAlpha.RawKey, "X-Gateway-Priority": "1",
			}, chatBody, nil)
			results <- r.StatusCode
		}(i)
	}
	wg.Wait()
	close(results)
	for code := range results {
		if code != http.StatusOK {
			t.Fatalf("expected Team Alpha protected critical calls to return 200, got %d", code)
		}
	}
}
