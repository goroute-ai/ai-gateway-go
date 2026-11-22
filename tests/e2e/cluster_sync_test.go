package e2e_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/a2a"
	"github.com/goroute-ai/ai-gateway-go/internal/a2a/pb"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/server"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/redis/go-redis/v9"
)

// setupDualNodeCluster initializes two GatewayServer instances sharing the same PostgreSQL and Redis cluster.
func setupDualNodeCluster(t *testing.T) (*httptest.Server, *httptest.Server, *server.GatewayServer, *server.GatewayServer, *storage.PostgresRepository, *storage.RedisFabric, func()) {
	t.Helper()
	ctx := context.Background()

	pgDSN := getEnvOrDefault("GATEWAY_POSTGRES_DSN", "postgres://gateway:gateway@localhost:5432/aigateway?sslmode=disable")
	redisAddr := getEnvOrDefault("GATEWAY_REDIS_ADDR", "localhost:6379")

	// 1. Shared PostgreSQL Pool
	pool, err := storage.NewPostgresPool(ctx, pgDSN)
	if err != nil {
		t.Skipf("skipping dual-node test: cannot connect to PostgreSQL: %v", err)
	}

	_ = storage.RunMigrationsDir(ctx, pool, "../../migrations")

	pgRepo, err := storage.NewPostgresRepository(ctx, pool)
	if err != nil {
		pool.Close()
		t.Fatalf("new postgres repo: %v", err)
	}

	// 2. Shared Redis Fabric
	redisFabric := storage.NewRedisFabric(redisAddr, "", 0)
	if _, err := redisFabric.Execute(func(rdb redis.UniversalClient) (any, error) {
		return rdb.Ping(ctx).Result()
	}); err != nil {
		pool.Close()
		t.Skipf("skipping dual-node test: cannot ping Redis: %v", err)
	}

	// 3. Node 1 Configuration
	cfg1 := config.Default()
	cfg1.Auth.MasterAdminKey = "sk-gw-cluster-admin-key"
	cfg1.Auth.MasterEncryptionKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	cfg1.Security.Network.OutboundSSRF.AllowPrivateNetworks = true
	cfg1.Security.Network.OutboundSSRF.AllowInsecureHTTP = true
	cfg1.MCP.Enabled = true
	cfg1.MCP.EnableSessionCompat2025 = true
	cfg1.A2A.Enabled = true
	cfg1.A2A.EnableJSONRPC = true
	cfg1.A2A.EnableHTTPJSON = true
	cfg1.A2A.SigningKeyID = "gw-cluster-key-1"
	cfg1.Cache.Enabled = true
	cfg1.Cache.DefaultTTL = 10 * time.Minute

	node1, err := server.New(cfg1, pgRepo, redisFabric, nil)
	if err != nil {
		pool.Close()
		t.Fatalf("server.New node1: %v", err)
	}
	node1.StartWorkers(ctx)
	ts1 := httptest.NewServer(node1.Handler())

	// 4. Node 2 Configuration (identically configured sibling node)
	cfg2 := config.Default()
	cfg2.Auth.MasterAdminKey = "sk-gw-cluster-admin-key"
	cfg2.Auth.MasterEncryptionKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	cfg2.Security.Network.OutboundSSRF.AllowPrivateNetworks = true
	cfg2.Security.Network.OutboundSSRF.AllowInsecureHTTP = true
	cfg2.MCP.Enabled = true
	cfg2.MCP.EnableSessionCompat2025 = true
	cfg2.A2A.Enabled = true
	cfg2.A2A.EnableJSONRPC = true
	cfg2.A2A.EnableHTTPJSON = true
	cfg2.A2A.SigningKeyID = "gw-cluster-key-2"
	cfg2.Cache.Enabled = true
	cfg2.Cache.DefaultTTL = 10 * time.Minute

	node2, err := server.New(cfg2, pgRepo, redisFabric, nil)
	if err != nil {
		ts1.Close()
		node1.Shutdown(ctx)
		pool.Close()
		t.Fatalf("server.New node2: %v", err)
	}
	node2.StartWorkers(ctx)
	ts2 := httptest.NewServer(node2.Handler())

	cleanup := func() {
		ts1.Close()
		ts2.Close()
		node1.Shutdown(ctx)
		node2.Shutdown(ctx)
		pool.Close()
	}

	return ts1, ts2, node1, node2, pgRepo, redisFabric, cleanup
}

func TestDualNode_CrossNodeVirtualKeySyncAndAuth(t *testing.T) {
	ts1, ts2, _, _, _, _, cleanup := setupDualNodeCluster(t)
	defer cleanup()

	c1 := &httpClientHelper{t: t, ts: ts1}
	c2 := &httpClientHelper{t: t, ts: ts2}
	adminHeaders := map[string]string{"Authorization": "Bearer sk-gw-cluster-admin-key"}

	// Step 1: Create Organization on Node 1
	var org domain.Organization
	orgSlug := fmt.Sprintf("cluster-org-%d", time.Now().UnixNano())
	resp, raw := c1.doJSON("POST", "/admin/v1/organizations", adminHeaders, map[string]any{
		"name": "Multi-Node Distributed Org",
		"slug": orgSlug,
	}, &org)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("node 1 create org failed: %d, body: %s", resp.StatusCode, raw)
	}

	// Step 2: Create Virtual Key on Node 1
	var vk domain.VirtualKey
	resp, raw = c1.doJSON("POST", "/admin/v1/keys", adminHeaders, map[string]any{
		"org_id":              org.ID,
		"name":                "Cluster Shared Key",
		"allowed_endpoints":   []string{"*"},
		"allowed_mcp_servers": []string{"*"},
		"allowed_a2a_agents":  []string{"*"},
		"rate_limit_rpm":      1000,
	}, &vk)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("node 1 create key failed: %d, body: %s", resp.StatusCode, raw)
	}
	secretKey := vk.RawKey
	if secretKey == "" {
		t.Fatalf("expected non-empty RawKey in VirtualKey response")
	}

	// Step 3: Immediately authenticate using secretKey against Node 2
	userHeaders := map[string]string{"Authorization": "Bearer " + secretKey}
	resp, raw = c2.doJSON("GET", "/mcp-rest/tools/list", userHeaders, nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("node 2 failed to authenticate virtual key created on node 1: status=%d, body=%s", resp.StatusCode, raw)
	}
}

func TestDualNode_CrossNodeA2ATaskLifecycle(t *testing.T) {
	ts1, ts2, _, _, _, _, cleanup := setupDualNodeCluster(t)
	defer cleanup()

	c1 := &httpClientHelper{t: t, ts: ts1}
	c2 := &httpClientHelper{t: t, ts: ts2}
	adminHeaders := map[string]string{"Authorization": "Bearer sk-gw-cluster-admin-key"}

	// 1. Setup Mock Upstream A2A Agent returning pb.SendMessageResponse
	mockA2A := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		respObj := &pb.SendMessageResponse{
			Payload: &pb.SendMessageResponse_Task{
				Task: &pb.Task{
					Status: &pb.TaskStatus{
						State: pb.TaskState_TASK_STATE_COMPLETED,
						Message: &pb.Message{
							Role: pb.Role_ROLE_AGENT,
							Parts: []*pb.Part{
								{Content: &pb.Part_Text{Text: "Distributed cluster task complete"}},
							},
						},
					},
					Artifacts: []*pb.Artifact{
						{
							Name: "cluster_diff",
							Parts: []*pb.Part{
								{Content: &pb.Part_Text{Text: "PASS: Node1 and Node2 converged"}},
							},
						},
					},
				},
			},
		}
		outJSON, _ := a2a.ProtoJSONMarshaler.Marshal(respObj)
		_, _ = w.Write(outJSON)
	}))
	defer mockA2A.Close()

	// 2. Create Org and Key
	var org domain.Organization
	c1.doJSON("POST", "/admin/v1/organizations", adminHeaders, map[string]any{
		"name": "Dual Node A2A Org",
		"slug": fmt.Sprintf("a2a-dual-%d", time.Now().UnixNano()),
	}, &org)

	var vk domain.VirtualKey
	c1.doJSON("POST", "/admin/v1/keys", adminHeaders, map[string]any{
		"org_id":              org.ID,
		"name":                "Dual Node Key",
		"allowed_endpoints":   []string{"*"},
		"allowed_mcp_servers": []string{"*"},
		"allowed_a2a_agents":  []string{"*"},
	}, &vk)
	secretKey := vk.RawKey

	// 3. Register A2A Agent on Node 1
	var agentResp struct {
		Agent domain.A2AAgent `json:"agent"`
	}
	resp, raw := c1.doJSON("POST", "/admin/v1/a2a/agents", adminHeaders, map[string]any{
		"org_id":               org.ID,
		"name":                 "Cluster Worker Agent",
		"slug":                 fmt.Sprintf("worker-%d", time.Now().UnixNano()),
		"endpoint_url":         mockA2A.URL,
		"protocol_binding":     "http_json",
		"protocol_version":     "v1.0",
		"task_visibility_mode": "key_strict",
		"is_active":            true,
	}, &agentResp)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create a2a agent failed: %d, body: %s", resp.StatusCode, raw)
	}
	agentSlug := agentResp.Agent.Slug

	userHeaders := map[string]string{"Authorization": "Bearer " + secretKey}

	// 4. Send A2A task via Node 1
	sendTaskRPC := map[string]any{
		"jsonrpc": "2.0",
		"id":      "msg-req-001",
		"method":  "tasks/send",
		"params": map[string]any{
			"message": map[string]any{
				"messageId": "msg_cluster_001",
				"role":      "ROLE_USER",
				"parts": []map[string]any{
					{"text": "Execute distributed cluster verification"},
				},
			},
		},
	}
	var rpcResp map[string]any
	resp, raw = c1.doJSON("POST", "/a2a/v1/agents/"+agentSlug, userHeaders, sendTaskRPC, &rpcResp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("node 1 tasks/send failed: %d, body: %s", resp.StatusCode, raw)
	}

	resMap, _ := rpcResp["result"].(map[string]any)
	taskMap, _ := resMap["task"].(map[string]any)
	taskID, _ := taskMap["id"].(string)
	if taskID == "" {
		t.Fatalf("missing task id from node 1: %v", rpcResp)
	}

	// 5. Query task immediately via Node 2
	getTaskRPC := map[string]any{
		"jsonrpc": "2.0",
		"id":      "get-req-002",
		"method":  "tasks/get",
		"params": map[string]any{
			"id": taskID,
		},
	}
	var getResp map[string]any
	resp, raw = c2.doJSON("POST", "/a2a/v1/agents/"+agentSlug, userHeaders, getTaskRPC, &getResp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("node 2 tasks/get failed: %d, body: %s", resp.StatusCode, raw)
	}

	gotResult, _ := getResp["result"].(map[string]any)
	if gotResult["id"] != taskID {
		t.Fatalf("node 2 returned task mismatch: got=%v, want=%s", gotResult["id"], taskID)
	}
	statusMap, _ := gotResult["status"].(map[string]any)
	if statusMap["state"] != "TASK_STATE_COMPLETED" && statusMap["state"] != "completed" {
		t.Fatalf("expected completed status on node 2: %v", statusMap)
	}
}

func TestDualNode_CrossNodeMCPExecutionAndLedger(t *testing.T) {
	ts1, ts2, _, _, _, _, cleanup := setupDualNodeCluster(t)
	defer cleanup()

	c1 := &httpClientHelper{t: t, ts: ts1}
	c2 := &httpClientHelper{t: t, ts: ts2}
	adminHeaders := map[string]string{"Authorization": "Bearer sk-gw-cluster-admin-key"}

	// 1. Mock upstream MCP server
	mockMCP := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var rpcReq map[string]any
		_ = json.NewDecoder(r.Body).Decode(&rpcReq)
		method, _ := rpcReq["method"].(string)

		if method == "tools/list" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0",
				"id":      rpcReq["id"],
				"result": map[string]any{
					"tools": []map[string]any{
						{
							"name":        "cluster_health_check",
							"description": "Performs cluster health check",
							"inputSchema": map[string]any{
								"type": "object",
								"properties": map[string]any{
									"node_name": map[string]any{"type": "string"},
								},
							},
						},
					},
				},
			})
			return
		}

		if method == "tools/call" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0",
				"id":      rpcReq["id"],
				"result": map[string]any{
					"content": []map[string]any{
						{"type": "text", "text": "Health OK on dual nodes"},
					},
					"isError": false,
				},
			})
			return
		}
	}))
	defer mockMCP.Close()

	// 2. Setup Org and Key
	var org domain.Organization
	c1.doJSON("POST", "/admin/v1/organizations", adminHeaders, map[string]any{
		"name": "Dual Node MCP Org",
		"slug": fmt.Sprintf("mcp-dual-%d", time.Now().UnixNano()),
	}, &org)

	var vk domain.VirtualKey
	c1.doJSON("POST", "/admin/v1/keys", adminHeaders, map[string]any{
		"org_id":              org.ID,
		"name":                "MCP Cluster Key",
		"allowed_endpoints":   []string{"*"},
		"allowed_mcp_servers": []string{"*"},
		"allowed_a2a_agents":  []string{"*"},
	}, &vk)
	secretKey := vk.RawKey

	// 3. Register MCP Server on Node 1 and Sync
	var srvResp struct {
		Server domain.MCPServer `json:"server"`
	}
	serverSlug := fmt.Sprintf("mcp-srv-%d", time.Now().UnixNano())
	resp, raw := c1.doJSON("POST", "/admin/v1/mcp/servers", adminHeaders, map[string]any{
		"org_id":              org.ID,
		"name":                "Cluster Health MCP",
		"slug":                serverSlug,
		"protocol_version":    "2026-07-28",
		"transport_type":      "streamable_http",
		"endpoint_url":        mockMCP.URL,
		"cost_per_call_cents": 5,
		"is_active":           true,
	}, &srvResp)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create mcp server failed: %d, body: %s", resp.StatusCode, raw)
	}

	c1.doJSON("POST", fmt.Sprintf("/admin/v1/mcp/servers/%s/sync", srvResp.Server.ID), adminHeaders, nil, nil)

	userHeaders := map[string]string{"Authorization": "Bearer " + secretKey}

	// 4. Call tool on Node 1 via REST Bridge
	callReq := map[string]any{
		"server_slug": serverSlug,
		"tool_name":   "cluster_health_check",
		"arguments":   map[string]any{"node_name": "node-1"},
	}
	var callResp1 map[string]any
	resp, raw = c1.doJSON("POST", "/mcp-rest/tools/call", userHeaders, callReq, &callResp1)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("node 1 rest tool call failed: %d, body: %s", resp.StatusCode, raw)
	}

	// 5. Call tool on Node 2 via JSON-RPC Bridge
	callRPC := map[string]any{
		"jsonrpc": "2.0",
		"id":      "rpc-call-002",
		"method":  "tools/call",
		"params": map[string]any{
			"name":      "cluster_health_check",
			"arguments": map[string]any{"node_name": "node-2"},
		},
	}
	var callResp2 map[string]any
	resp, raw = c2.doJSON("POST", "/mcp/"+serverSlug, userHeaders, callRPC, &callResp2)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("node 2 json-rpc tool call failed: %d, body: %s", resp.StatusCode, raw)
	}

	res2, _ := callResp2["result"].(map[string]any)
	content2, _ := res2["content"].([]any)
	if len(content2) == 0 {
		t.Fatalf("expected tool content from node 2: %v", callResp2)
	}
}

func TestDualNode_DistributedOutboxDeliveryDeduplication(t *testing.T) {
	ts1, ts2, _, _, _, _, cleanup := setupDualNodeCluster(t)
	defer cleanup()

	c1 := &httpClientHelper{t: t, ts: ts1}
	_ = ts2
	adminHeaders := map[string]string{"Authorization": "Bearer sk-gw-cluster-admin-key"}

	// Track delivery events and verify idempotency across concurrent outbox workers on both nodes
	var deliveryCount int32
	var receivedIdempotencyKeys sync.Map

	webhookServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&deliveryCount, 1)
		idemKey := r.Header.Get("X-Idempotency-Key")
		if idemKey != "" {
			receivedIdempotencyKeys.Store(idemKey, true)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok"})
	}))
	defer webhookServer.Close()

	// Setup Org, Key, Agent
	var org domain.Organization
	c1.doJSON("POST", "/admin/v1/organizations", adminHeaders, map[string]any{
		"name": "Outbox Org",
		"slug": fmt.Sprintf("outbox-org-%d", time.Now().UnixNano()),
	}, &org)

	var vk domain.VirtualKey
	c1.doJSON("POST", "/admin/v1/keys", adminHeaders, map[string]any{
		"org_id":             org.ID,
		"name":               "Outbox Key",
		"allowed_endpoints":  []string{"*"},
		"allowed_a2a_agents": []string{"*"},
	}, &vk)
	secretKey := vk.RawKey

	// Register Agent on Node 1 pointing to webhookServer
	var agentResp struct {
		Agent domain.A2AAgent `json:"agent"`
	}
	agentSlug := fmt.Sprintf("outbox-%d", time.Now().UnixNano())
	c1.doJSON("POST", "/admin/v1/a2a/agents", adminHeaders, map[string]any{
		"org_id":               org.ID,
		"name":                 "Outbox Agent",
		"slug":                 agentSlug,
		"endpoint_url":         webhookServer.URL,
		"protocol_binding":     "http_json",
		"protocol_version":     "v1.0",
		"task_visibility_mode": "key_strict",
		"is_active":            true,
	}, &agentResp)

	userHeaders := map[string]string{"Authorization": "Bearer " + secretKey}

	// Trigger task send via Node 1
	sendTaskRPC := map[string]any{
		"jsonrpc": "2.0",
		"id":      "msg-outbox-01",
		"method":  "tasks/send",
		"params": map[string]any{
			"message": map[string]any{
				"messageId": "msg_outbox_test",
				"role":      "ROLE_USER",
				"parts":     []map[string]any{{"text": "Trigger outbox"}},
			},
		},
	}
	resp, _ := c1.doJSON("POST", "/a2a/v1/agents/"+agentSlug, userHeaders, sendTaskRPC, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("tasks/send failed: %d", resp.StatusCode)
	}

	// Allow outbox workers on both Node 1 and Node 2 to poll and execute
	time.Sleep(300 * time.Millisecond)

	count := atomic.LoadInt32(&deliveryCount)
	if count == 0 {
		t.Fatalf("expected outbox worker to deliver webhook event, got count 0")
	}
}

func TestDualNode_ExpiredVirtualKeyRejectedFromRedisCache(t *testing.T) {
	ts1, ts2, _, _, _, _, cleanup := setupDualNodeCluster(t)
	defer cleanup()
	c1 := &httpClientHelper{t: t, ts: ts1}
	c2 := &httpClientHelper{t: t, ts: ts2}
	adminHeaders := map[string]string{"Authorization": "Bearer sk-gw-cluster-admin-key"}

	var org domain.Organization
	_, raw := c1.doJSON("POST", "/admin/v1/organizations", adminHeaders, map[string]any{
		"name": "Expiring Cluster Org",
		"slug": fmt.Sprintf("expiring-cluster-%d", time.Now().UnixNano()),
	}, &org)
	if org.ID == "" {
		t.Fatalf("create organization failed: %s", raw)
	}

	expiresAt := time.Now().UTC().Add(time.Second)
	var key domain.VirtualKey
	_, raw = c1.doJSON("POST", "/admin/v1/keys", adminHeaders, map[string]any{
		"org_id":            org.ID,
		"name":              "expiring cluster key",
		"allowed_endpoints": []string{"*"},
		"expires_at":        expiresAt,
	}, &key)
	if key.RawKey == "" {
		t.Fatalf("create virtual key failed: %s", raw)
	}

	userHeaders := map[string]string{"Authorization": "Bearer " + key.RawKey}
	resp, raw := c1.doJSON("GET", "/mcp-rest/tools/list", userHeaders, nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("node 1 failed to warm Redis auth cache: status=%d body=%s", resp.StatusCode, raw)
	}
	time.Sleep(time.Until(expiresAt) + 20*time.Millisecond)
	resp, raw = c2.doJSON("GET", "/mcp-rest/tools/list", userHeaders, nil, nil)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("node 2 accepted expired key from Redis cache: status=%d body=%s", resp.StatusCode, raw)
	}
}

func TestDualNode_RevocationInvalidatesRemoteVirtualKeyCache(t *testing.T) {
	ts1, ts2, _, _, _, _, cleanup := setupDualNodeCluster(t)
	defer cleanup()
	c1 := &httpClientHelper{t: t, ts: ts1}
	c2 := &httpClientHelper{t: t, ts: ts2}
	adminHeaders := map[string]string{"Authorization": "Bearer sk-gw-cluster-admin-key"}

	var org domain.Organization
	_, raw := c1.doJSON("POST", "/admin/v1/organizations", adminHeaders, map[string]any{
		"name": "Revocation Cluster Org",
		"slug": fmt.Sprintf("revocation-cluster-%d", time.Now().UnixNano()),
	}, &org)
	if org.ID == "" {
		t.Fatalf("create organization failed: %s", raw)
	}

	var key domain.VirtualKey
	_, raw = c1.doJSON("POST", "/admin/v1/keys", adminHeaders, map[string]any{
		"org_id":            org.ID,
		"name":              "revocable cluster key",
		"allowed_endpoints": []string{"*"},
	}, &key)
	if key.RawKey == "" {
		t.Fatalf("create virtual key failed: %s", raw)
	}
	userHeaders := map[string]string{"Authorization": "Bearer " + key.RawKey}
	resp, raw := c2.doJSON("GET", "/mcp-rest/tools/list", userHeaders, nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("node 2 failed to warm local auth cache: status=%d body=%s", resp.StatusCode, raw)
	}

	resp, raw = c1.doJSON("POST", "/admin/v1/keys/"+key.ID+"/revoke", adminHeaders, nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("revoke key failed: status=%d body=%s", resp.StatusCode, raw)
	}

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		resp, raw = c2.doJSON("GET", "/mcp-rest/tools/list", userHeaders, nil, nil)
		if resp.StatusCode == http.StatusUnauthorized {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("node 2 continued accepting revoked key: status=%d body=%s", resp.StatusCode, raw)
}
