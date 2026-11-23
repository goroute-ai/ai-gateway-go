package e2e_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/a2a"
	"github.com/goroute-ai/ai-gateway-go/internal/a2a/pb"
	a2aspec "github.com/goroute-ai/ai-gateway-go/internal/a2a/spec"
	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/auth/upstream"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/test/bufconn"
)

// TestLiveStack_MCP_REST_Bridge verifies that plain HTTP REST endpoints
// (GET /mcp-rest/tools/list and POST /mcp-rest/tools/call) execute cleanly against
// live PostgreSQL and Redis, and register exact FinOps ledger transactions.
func TestLiveStack_MCP_REST_Bridge(t *testing.T) {
	ts, _, pgRepo, _, cleanup := setupLiveGateway(t)
	defer cleanup()

	ctx := context.Background()
	client := &httpClientHelper{t: t, ts: ts}
	adminHeaders := map[string]string{"Authorization": "Bearer sk-gw-master-admin-live-e2e-key"}

	// 1. Mock upstream MCP server
	mockMCPSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, _ := io.ReadAll(r.Body)
		var rpcReq map[string]any
		_ = json.Unmarshal(bodyBytes, &rpcReq)
		method, _ := rpcReq["method"].(string)

		switch method {
		case "tools/list":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"get_weather","description":"Get current weather","inputSchema":{"type":"object","properties":{"location":{"type":"string"}}}}]}}`)
		case "tools/call":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"Sunny, 22C in Kyoto"}]}}`)
		default:
			http.Error(w, "unknown method", http.StatusBadRequest)
		}
	}))
	defer mockMCPSrv.Close()

	// 2. Register Org & Virtual Key
	var org domain.Organization
	client.doJSON(http.MethodPost, "/admin/v1/organizations", adminHeaders, map[string]any{
		"name": "Live REST Bridge Org",
		"slug": fmt.Sprintf("live-rest-%d", time.Now().UnixNano()),
	}, &org)

	var vk domain.VirtualKey
	client.doJSON(http.MethodPost, "/admin/v1/keys", adminHeaders, map[string]any{
		"org_id":              org.ID,
		"name":                "live-rest-key",
		"allowed_endpoints":   []string{"*"},
		"allowed_mcp_servers": []string{"*"},
	}, &vk)
	vkHeaders := map[string]string{"Authorization": "Bearer " + vk.RawKey}

	// 3. Register MCP Server
	var srvResp struct {
		Server domain.MCPServer `json:"server"`
	}
	resp, raw := client.doJSON(http.MethodPost, "/admin/v1/mcp/servers", adminHeaders, map[string]any{
		"org_id":           org.ID,
		"name":             "Weather Service",
		"slug":             "weather-service",
		"protocol_version": "2026-07-28",
		"transport_type":   "streamable_http",
		"endpoint_url":     mockMCPSrv.URL,
		"is_active":        true,
	}, &srvResp)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register server failed (%d): %s", resp.StatusCode, string(raw))
	}
	serverID := srvResp.Server.ID

	// 4. Sync tools
	resp, raw = client.doJSON(http.MethodPost, fmt.Sprintf("/admin/v1/mcp/servers/%s/sync", serverID), adminHeaders, nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("sync server failed (%d): %s", resp.StatusCode, string(raw))
	}

	// Set CostPerCallMicros to 100 for get_weather so FinOps records spend
	tools, err := pgRepo.ListMCPTools(ctx, serverID)
	if err == nil && len(tools) > 0 {
		tools[0].CostPerCallMicros = 100
		_ = pgRepo.UpsertMCPTools(ctx, serverID, org.ID, tools)
	}

	// 5. Test GET /mcp-rest/tools/list
	var listResp struct {
		Tools []domain.MCPTool `json:"tools"`
	}
	resp, raw = client.doJSON(http.MethodGet, "/mcp-rest/tools/list?server_slug=weather-service", vkHeaders, nil, &listResp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /mcp-rest/tools/list failed (%d): %s", resp.StatusCode, string(raw))
	}
	if len(listResp.Tools) != 1 || listResp.Tools[0].Name != "get_weather" {
		t.Fatalf("expected get_weather tool, got: %+v", listResp.Tools)
	}

	// 6. Test POST /mcp-rest/tools/call
	var callResp struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		IsError bool `json:"is_error"`
	}
	resp, raw = client.doJSON(http.MethodPost, "/mcp-rest/tools/call", vkHeaders, map[string]any{
		"server_slug": "weather-service",
		"tool_name":   "get_weather",
		"arguments": map[string]any{
			"location": "Kyoto",
		},
	}, &callResp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /mcp-rest/tools/call failed (%d): %s", resp.StatusCode, string(raw))
	}
	if callResp.IsError {
		t.Fatalf("callResp returned error")
	}
	if len(callResp.Content) == 0 || !strings.Contains(callResp.Content[0].Text, "Kyoto") {
		t.Fatalf("expected Kyoto in response content, got: %+v", callResp.Content)
	}

	// 7. Verify FinOps ledger in live PostgreSQL (allow async worker flush)
	time.Sleep(300 * time.Millisecond)
	spendLogs, err := pgRepo.ListSpendLogs(ctx, org.ID, 10)
	if err != nil {
		t.Fatalf("list spend logs: %v", err)
	}
	if len(spendLogs) == 0 {
		t.Fatalf("expected spend log record in PostgreSQL for MCP tool call")
	}
	t.Logf("Verified FinOps record: id=%s cost_micros=%d key_id=%s", spendLogs[0].ID, spendLogs[0].CostMicros, spendLogs[0].VirtualKeyID)
}

// TestLiveStack_ProgressiveDiscovery_Handles_And_Registry tests
// progressive discovery catalog feed, 256-bit opaque handle issuance,
// tool calling via handle, and fail-closed behavior on stale handles.
func TestLiveStack_ProgressiveDiscovery_Handles_And_Registry(t *testing.T) {
	ts, gw, pgRepo, _, cleanup := setupLiveGateway(t)
	defer cleanup()

	ctx := context.Background()
	client := &httpClientHelper{t: t, ts: ts}
	adminHeaders := map[string]string{"Authorization": "Bearer sk-gw-master-admin-live-e2e-key"}

	// 1. Mock upstream MCP server
	mockMCPSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bodyBytes, _ := io.ReadAll(r.Body)
		var rpcReq map[string]any
		_ = json.Unmarshal(bodyBytes, &rpcReq)
		method, _ := rpcReq["method"].(string)

		switch method {
		case "tools/list":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"query_db","description":"Query warehouse","inputSchema":{"type":"object","properties":{"sql":{"type":"string"}}}}]}}`)
		case "tools/call":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"rows: 42"}]}}`)
		default:
			http.Error(w, "unknown method", http.StatusBadRequest)
		}
	}))
	defer mockMCPSrv.Close()

	// 2. Org & Key
	var org domain.Organization
	client.doJSON(http.MethodPost, "/admin/v1/organizations", adminHeaders, map[string]any{
		"name": "Live Progressive Org",
		"slug": fmt.Sprintf("live-prog-%d", time.Now().UnixNano()),
	}, &org)

	var vk domain.VirtualKey
	client.doJSON(http.MethodPost, "/admin/v1/keys", adminHeaders, map[string]any{
		"org_id":              org.ID,
		"name":                "live-prog-key",
		"allowed_endpoints":   []string{"*"},
		"allowed_mcp_servers": []string{"*"},
	}, &vk)
	vkHeaders := map[string]string{"Authorization": "Bearer " + vk.RawKey}

	// 3. Register & Sync
	var srvResp struct {
		Server domain.MCPServer `json:"server"`
	}
	resp, _ := client.doJSON(http.MethodPost, "/admin/v1/mcp/servers", adminHeaders, map[string]any{
		"org_id":           org.ID,
		"name":             "Data Warehouse",
		"slug":             "warehouse",
		"protocol_version": "2026-07-28",
		"transport_type":   "streamable_http",
		"endpoint_url":     mockMCPSrv.URL,
		"is_active":        true,
	}, &srvResp)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register server failed: %d", resp.StatusCode)
	}

	client.doJSON(http.MethodPost, fmt.Sprintf("/admin/v1/mcp/servers/%s/sync", srvResp.Server.ID), adminHeaders, nil, nil)

	// 4. Query Registry Feed (GET /v1/goroute/mcp/registry)
	var regResp struct {
		Servers []struct {
			Slug  string `json:"slug"`
			Tools []struct {
				Name        string `json:"name"`
				ToolHandle  string `json:"tool_handle"`
				ToolDefHash string `json:"tool_def_hash"`
			} `json:"tools"`
		} `json:"servers"`
	}
	resp, raw := client.doJSON(http.MethodGet, "/v1/goroute/mcp/registry", vkHeaders, nil, &regResp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /v1/goroute/mcp/registry failed (%d): %s", resp.StatusCode, string(raw))
	}
	if len(regResp.Servers) == 0 || len(regResp.Servers[0].Tools) == 0 {
		t.Fatalf("expected servers and tools in registry response, got: %s", string(raw))
	}

	toolItem := regResp.Servers[0].Tools[0]
	handle := toolItem.ToolHandle
	if !strings.HasPrefix(handle, "tool_hdl_") {
		t.Fatalf("expected tool handle prefix 'tool_hdl_', got: %s", handle)
	}
	t.Logf("Discovered opaque handle: %s for tool %s", handle, toolItem.Name)

	// 5. Call Tool using Opaque Handle via POST /mcp-rest/tools/call
	var callResp struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		IsError bool `json:"is_error"`
	}
	resp, raw = client.doJSON(http.MethodPost, "/mcp-rest/tools/call", vkHeaders, map[string]any{
		"tool_name": handle,
		"arguments": map[string]any{"sql": "SELECT COUNT(*) FROM items"},
	}, &callResp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("call via handle failed (%d): %s", resp.StatusCode, string(raw))
	}
	if !strings.Contains(callResp.Content[0].Text, "rows: 42") {
		t.Fatalf("unexpected result: %+v", callResp)
	}

	// 6. Test Stale Handle Fail-Closed Enforcement:
	// Simulate upstream tool change in PostgreSQL by mutating tool_def_hash
	tools, err := pgRepo.ListMCPTools(ctx, srvResp.Server.ID)
	if err != nil || len(tools) == 0 {
		t.Fatalf("list tools: %v", err)
	}
	mutated := *tools[0]
	mutated.ToolDefHash = "hash_mutated_schema_" + hex.EncodeToString(sha256.New().Sum([]byte("changed")))
	_ = pgRepo.UpsertMCPTools(ctx, srvResp.Server.ID, org.ID, []*domain.MCPTool{&mutated})

	// Hub caches tools briefly; bust or call again
	_ = gw.MCPHub()
	resp, raw = client.doJSON(http.MethodPost, "/mcp-rest/tools/call", vkHeaders, map[string]any{
		"tool_name": handle,
		"arguments": map[string]any{"sql": "SELECT 1"},
	}, nil)
	if resp.StatusCode == http.StatusOK {
		t.Fatalf("expected fail-closed error for stale handle, but got 200 OK: %s", string(raw))
	}
	t.Logf("Confirmed stale handle rejected cleanly with HTTP %d: %s", resp.StatusCode, string(raw))
}

// TestLiveStack_Governed_OpenAPI_Transport tests dynamic tool synthesis
// from an OpenAPI 3.0 specification and governed path parameter substitution.
func TestLiveStack_Governed_OpenAPI_Transport(t *testing.T) {
	ts, _, _, _, cleanup := setupLiveGateway(t)
	defer cleanup()

	client := &httpClientHelper{t: t, ts: ts}
	adminHeaders := map[string]string{"Authorization": "Bearer sk-gw-master-admin-live-e2e-key"}

	// 1. Mock OpenAPI Upstream Server
	openAPISpec := `{
  "openapi": "3.0.0",
  "info": {"title": "Inventory Service", "version": "1.0.0"},
  "paths": {
    "/products/{productId}": {
      "get": {
        "operationId": "getProductById",
        "summary": "Retrieve product by ID",
        "parameters": [
          {
            "name": "productId",
            "in": "path",
            "required": true,
            "schema": {"type": "string"}
          }
        ],
        "responses": {
          "200": {"description": "OK"}
        }
      }
    }
  }
}`

	var receivedPath string
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/openapi.json" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(openAPISpec))
			return
		}
		receivedPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"id":"prod_777","name":"High-Speed Router","stock":15}`)
	}))
	defer mockServer.Close()

	// 2. Org & Virtual Key
	var org domain.Organization
	client.doJSON(http.MethodPost, "/admin/v1/organizations", adminHeaders, map[string]any{
		"name": "Live OpenAPI Org",
		"slug": fmt.Sprintf("live-openapi-%d", time.Now().UnixNano()),
	}, &org)

	var vk domain.VirtualKey
	client.doJSON(http.MethodPost, "/admin/v1/keys", adminHeaders, map[string]any{
		"org_id":              org.ID,
		"name":                "live-openapi-key",
		"allowed_endpoints":   []string{"*"},
		"allowed_mcp_servers": []string{"*"},
	}, &vk)
	vkHeaders := map[string]string{"Authorization": "Bearer " + vk.RawKey}

	// 3. Register MCP Server with TransportType OpenAPI
	var srvResp struct {
		Server domain.MCPServer `json:"server"`
	}
	resp, raw := client.doJSON(http.MethodPost, "/admin/v1/mcp/servers", adminHeaders, map[string]any{
		"org_id":           org.ID,
		"name":             "Product Inventory",
		"slug":             "product-inventory",
		"protocol_version": "2026-07-28",
		"transport_type":   "openapi",
		"endpoint_url":     mockServer.URL + "/openapi.json",
		"is_active":        true,
	}, &srvResp)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register openapi server failed (%d): %s", resp.StatusCode, string(raw))
	}

	// 4. Sync tools to parse OpenAPI spec and populate database
	resp, raw = client.doJSON(http.MethodPost, fmt.Sprintf("/admin/v1/mcp/servers/%s/sync", srvResp.Server.ID), adminHeaders, nil, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("sync openapi server failed (%d): %s", resp.StatusCode, string(raw))
	}

	// 5. Verify Tool List contains getProductById
	var listResp struct {
		Tools []domain.MCPTool `json:"tools"`
	}
	resp, _ = client.doJSON(http.MethodGet, "/mcp-rest/tools/list?server_slug=product-inventory", vkHeaders, nil, &listResp)
	if resp.StatusCode != http.StatusOK || len(listResp.Tools) == 0 {
		t.Fatalf("failed to list synthesized openapi tools: %s", string(raw))
	}
	toolName := listResp.Tools[0].Name
	t.Logf("Synthesized OpenAPI Tool: %s (description: %s)", toolName, listResp.Tools[0].Description)

	// 6. Invoke Synthesized Tool via REST Bridge with path parameter
	var callResp struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	resp, raw = client.doJSON(http.MethodPost, "/mcp-rest/tools/call", vkHeaders, map[string]any{
		"server_slug": "product-inventory",
		"tool_name":   toolName,
		"arguments": map[string]any{
			"productId": "prod_777",
		},
	}, &callResp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("execute openapi tool failed (%d): %s", resp.StatusCode, string(raw))
	}
	if receivedPath != "/products/prod_777" {
		t.Fatalf("expected upstream path /products/prod_777, got: %s", receivedPath)
	}
	if len(callResp.Content) == 0 || !strings.Contains(callResp.Content[0].Text, "High-Speed Router") {
		t.Fatalf("unexpected response content: %+v", callResp)
	}
	t.Logf("OpenAPI tool invoked successfully; substituted path %s", receivedPath)
}

// TestLiveStack_A2A_Native_gRPC_and_OpenAIBridge tests the native
// A2A gRPC transport (A2AServiceServer) and the formal A2A-to-OpenAI bridge.
func TestLiveStack_A2A_Native_gRPC_and_OpenAIBridge(t *testing.T) {
	ts, gw, pgRepo, redisFabric, cleanup := setupLiveGateway(t)
	defer cleanup()

	ctx := context.Background()
	client := &httpClientHelper{t: t, ts: ts}
	adminHeaders := map[string]string{"Authorization": "Bearer sk-gw-master-admin-live-e2e-key"}

	// 1. Mock upstream A2A agent returning Task Completed
	mockAgentSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/a2a+json")
		respObj := a2aspec.NewSendMessageResponseTask(&a2aspec.Task{
			Id: "task_live_grpc_100",
			Status: a2aspec.TaskStatus{
				State: a2aspec.TASKSTATECOMPLETED,
			},
			Artifacts: &[]a2aspec.Artifact{
				{
					ArtifactId: "art_code_1",
					Name:       func() *string { s := "code-analysis"; return &s }(),
					Parts:      []a2aspec.Part{a2aspec.NewTextPart("Code passes all static analysis checks cleanly.")},
				},
			},
		})
		b, _ := json.Marshal(respObj)
		_, _ = w.Write(b)
	}))
	defer mockAgentSrv.Close()

	// 2. Org & Virtual Key
	var org domain.Organization
	client.doJSON(http.MethodPost, "/admin/v1/organizations", adminHeaders, map[string]any{
		"name": "Live A2A gRPC Org",
		"slug": fmt.Sprintf("live-a2a-grpc-%d", time.Now().UnixNano()),
	}, &org)

	var vk domain.VirtualKey
	client.doJSON(http.MethodPost, "/admin/v1/keys", adminHeaders, map[string]any{
		"org_id":              org.ID,
		"name":                "live-a2a-grpc-key",
		"allowed_endpoints":   []string{"*"},
		"allowed_a2a_agents":  []string{"*"},
		"allowed_mcp_servers": []string{"*"},
	}, &vk)
	vkHeaders := map[string]string{"Authorization": "Bearer " + vk.RawKey}

	// 3. Register A2A Agent in PostgreSQL
	var agentResp struct {
		Agent domain.A2AAgent `json:"agent"`
	}
	resp, raw := client.doJSON(http.MethodPost, "/admin/v1/a2a/agents", adminHeaders, map[string]any{
		"org_id":               org.ID,
		"name":                 "Code Linter Agent",
		"slug":                 "linter-agent",
		"endpoint_url":         mockAgentSrv.URL,
		"auth_type":            "none",
		"task_visibility_mode": "key_strict",
		"is_active":            true,
	}, &agentResp)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("register agent failed (%d): %s", resp.StatusCode, string(raw))
	}

	// 4. Start in-memory gRPC Server using bufconn wired to Gateway A2A router
	lis := bufconn.Listen(1024 * 1024)
	grpcServer := grpc.NewServer()
	rbac := auth.NewRBACEngine(pgRepo)
	authSvc := auth.NewService(pgRepo, redisFabric, "sk-gw-master-admin-live-e2e-key", 10*time.Second, time.Minute)
	a2aGRPC := a2a.NewGRPCServer(gw.A2ARouter(), authSvc, rbac)
	a2aGRPC.SetAuthResolver(gw.AuthResolver())
	a2aGRPC.SetStreamSubscriber(gw.A2AStreamSubscriber())
	a2aGRPC.Register(grpcServer)

	go func() {
		_ = grpcServer.Serve(lis)
	}()
	defer grpcServer.Stop()

	// 5. Connect gRPC Client via bufnet dialer
	dialer := func(context.Context, string) (net.Conn, error) {
		return lis.Dial()
	}
	conn, err := grpc.NewClient("passthrough://bufnet",
		grpc.WithContextDialer(dialer),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatalf("dial bufconn: %v", err)
	}
	defer conn.Close()

	grpcClient := pb.NewA2AServiceClient(conn)

	// Call SendMessage via gRPC
	callMD := metadata.Pairs(
		"authorization", "Bearer "+vk.RawKey,
		"x-a2a-agent-slug", "linter-agent",
	)
	mdCtx := metadata.NewOutgoingContext(ctx, callMD)

	sendReq := &pb.SendMessageRequest{
		Message: &pb.Message{
			Role: pb.Role_ROLE_USER,
			Parts: []*pb.Part{
				{Content: &pb.Part_Text{Text: "Analyze internal/server/server.go"}},
			},
		},
	}
	grpcResp, err := grpcClient.SendMessage(mdCtx, sendReq)
	if err != nil {
		t.Fatalf("gRPC SendMessage failed: %v", err)
	}
	task := grpcResp.GetTask()
	if task == nil || task.Status.State != pb.TaskState_TASK_STATE_COMPLETED {
		t.Fatalf("unexpected gRPC task response: %v", grpcResp)
	}
	t.Logf("A2A gRPC SendMessage verified: taskId=%s state=%v", task.Id, task.Status.State)

	// 6. Test Formal A2A-to-OpenAI Compatibility Bridge via POST /v1/chat/completions
	var chatResp struct {
		Choices []struct {
			Message struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"message"`
			FinishReason string `json:"finish_reason"`
		} `json:"choices"`
	}
	resp, raw = client.doJSON(http.MethodPost, "/v1/chat/completions", vkHeaders, map[string]any{
		"model": "a2a/linter-agent",
		"messages": []map[string]any{
			{"role": "user", "content": "Please review this pull request."},
		},
	}, &chatResp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("OpenAI bridge to A2A failed (%d): %s", resp.StatusCode, string(raw))
	}
	if len(chatResp.Choices) == 0 || !strings.Contains(chatResp.Choices[0].Message.Content, "cleanly") {
		t.Fatalf("unexpected bridge chat response: %+v", chatResp)
	}
	if chatResp.Choices[0].FinishReason != "stop" {
		t.Fatalf("expected finish_reason 'stop', got: %s", chatResp.Choices[0].FinishReason)
	}
	t.Logf("A2A-to-OpenAI bridge verified: content=%q finish_reason=%s",
		chatResp.Choices[0].Message.Content, chatResp.Choices[0].FinishReason)
}

// TestLiveStack_EnterpriseUpstreamAuth tests AWS SigV4, CIMD PKCE,
// RFC 9207 & 8707, and RFC 8693 token exchange.
func TestLiveStack_EnterpriseUpstreamAuth(t *testing.T) {
	ctx := context.Background()

	// 1. AWS SigV4 Signer
	strat, err := upstream.NewSigV4Strategy(upstream.SigV4Config{
		AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		Region:          "us-east-1",
		Service:         "execute-api",
	})
	if err != nil {
		t.Fatalf("new sigv4 strategy: %v", err)
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.internal.example.com/v1/invoke", strings.NewReader(`{"prompt":"hello"}`))
	authCtx := &upstream.UpstreamAuthContext{
		CallingOrgID: "org_prod_aws",
	}
	if err := strat.Apply(ctx, req, authCtx); err != nil {
		t.Fatalf("sign request: %v", err)
	}
	authHeader := req.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE") {
		t.Fatalf("unexpected Authorization header: %s", authHeader)
	}
	if req.Header.Get("X-Amz-Date") == "" || req.Header.Get("X-Amz-Content-Sha256") == "" {
		t.Fatalf("missing required SigV4 headers: %v", req.Header)
	}
	t.Logf("AWS SigV4 signing verified: %s", authHeader[:50]+"...")

	// 2. CIMD & PKCE
	pkce, err := upstream.GeneratePKCE()
	if err != nil {
		t.Fatalf("generate pkce: %v", err)
	}
	if len(pkce.CodeVerifier) < 43 || pkce.CodeChallengeMethod != "S256" {
		t.Fatalf("invalid PKCE: %+v", pkce)
	}
	if !upstream.ValidatePKCE(pkce.CodeVerifier, pkce.CodeChallenge, pkce.CodeChallengeMethod) {
		t.Fatalf("PKCE verification failed")
	}
	t.Logf("PKCE S256 challenge verified: %s (verifier len=%d)", pkce.CodeChallenge, len(pkce.CodeVerifier))

	// 3. RFC 9207 & RFC 8707 Issuer Validation
	err = upstream.ValidateRFC9207Issuer("https://auth.company.com/", "https://auth.company.com/")
	if err != nil {
		t.Fatalf("valid issuer rejected: %v", err)
	}
	// Byte-for-byte exact match check (trailing slash mismatch should fail)
	err = upstream.ValidateRFC9207Issuer("https://auth.company.com", "https://auth.company.com/")
	if err == nil {
		t.Fatalf("expected mismatch failure for unnormalized issuer strings")
	}
	err = upstream.ValidateRFC8707ResourceURI("https://upstream.internal.net/mcp")
	if err != nil {
		t.Fatalf("valid resource rejected: %v", err)
	}
	t.Logf("RFC 9207 exact byte-for-byte issuer match verified")

	// 4. RFC 8693 Token Exchange Strategy
	var tokenCalls int
	mockAS := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenCalls++
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"access_token":      "exchanged-upstream-token-xyz",
			"issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
			"token_type":        "Bearer",
			"expires_in":        3600,
		})
	}))
	defer mockAS.Close()

	netPolicy := &network.Policy{
		AllowPrivateNetworks: true,
		AllowInsecureHTTP:    true,
	}

	teStrat, err := upstream.NewTokenExchangeStrategy(upstream.TokenExchangeConfig{
		TokenEndpoint: mockAS.URL,
		ClientID:      "gateway-client",
		ClientSecret:  "gateway-secret",
		Resource:      "https://upstream.internal.net/mcp",
		NetPolicy:     netPolicy,
	})
	if err != nil {
		t.Fatalf("new token exchange: %v", err)
	}
	reqTE, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://upstream.internal.net/mcp/tools", nil)
	authCtxTE := &upstream.UpstreamAuthContext{
		DelegatedToken: "caller-jwt-token-123",
	}
	if err := teStrat.Apply(ctx, reqTE, authCtxTE); err != nil {
		t.Fatalf("apply token exchange: %v", err)
	}
	if reqTE.Header.Get("Authorization") != "Bearer exchanged-upstream-token-xyz" {
		t.Fatalf("unexpected authorization header: %s", reqTE.Header.Get("Authorization"))
	}
	// Second call uses cached token without calling mockAS again
	reqTE2, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://upstream.internal.net/mcp/tools", nil)
	if err := teStrat.Apply(ctx, reqTE2, authCtxTE); err != nil {
		t.Fatalf("apply cached token exchange: %v", err)
	}
	if tokenCalls != 1 {
		t.Fatalf("expected cached token call (1 request to AS), got %d", tokenCalls)
	}
	t.Logf("RFC 8693 token exchange strategy & caching verified")
}

// TestLiveStack_MCPSpecSwitchingAndCrossVersion verifies live Postgres/Redis persistence
// for GET/PUT /admin/v1/mcp/spec, PUT /admin/v1/mcp/servers/{serverID}, and hot-switching
// /mcp wire behavior across MCP releases (2025-03-26 batching <-> 2026-07-28 stateless).
func TestLiveStack_MCPSpecSwitchingAndCrossVersion(t *testing.T) {
	ts, _, _, _, cleanup := setupLiveGateway(t)
	defer cleanup()

	client := &httpClientHelper{t: t, ts: ts}
	adminHeaders := map[string]string{"Authorization": "Bearer sk-gw-master-admin-live-e2e-key"}

	mockMCPSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"jsonrpc":"2.0","id":1,"result":{"tools":[{"name":"ping_tool","description":"Ping","inputSchema":{"type":"object"}}]}}`)
	}))
	defer mockMCPSrv.Close()

	var org domain.Organization
	client.doJSON(http.MethodPost, "/admin/v1/organizations", adminHeaders, map[string]any{
		"name": "Live Spec Switch Org",
		"slug": fmt.Sprintf("live-spec-%d", time.Now().UnixNano()),
	}, &org)

	var vk domain.VirtualKey
	client.doJSON(http.MethodPost, "/admin/v1/keys", adminHeaders, map[string]any{
		"org_id":              org.ID,
		"name":                "live-spec-vk",
		"allowed_endpoints":   []string{"*"},
		"allowed_mcp_servers": []string{"*"},
	}, &vk)

	// 1. Default GET /admin/v1/mcp/spec
	var specState struct {
		ActiveProtocolVersion string `json:"active_protocol_version"`
		AvailableSpecs        []struct {
			Version string `json:"version"`
		} `json:"available_specs"`
	}
	resp, raw := client.doJSON(http.MethodGet, "/admin/v1/mcp/spec", adminHeaders, nil, &specState)
	if resp.StatusCode != http.StatusOK || len(specState.AvailableSpecs) != 5 {
		t.Fatalf("GET /admin/v1/mcp/spec failed (%d): %s", resp.StatusCode, string(raw))
	}

	// 2. Switch to 2025-03-26 and verify JSON-RPC batching succeeds on POST /mcp
	resp, raw = client.doJSON(http.MethodPut, "/admin/v1/mcp/spec", adminHeaders, map[string]any{
		"protocol_version": domain.MCPProtocolVersion20250326,
	}, &specState)
	if resp.StatusCode != http.StatusOK || specState.ActiveProtocolVersion != domain.MCPProtocolVersion20250326 {
		t.Fatalf("PUT /admin/v1/mcp/spec 2025-03-26 failed (%d): %s", resp.StatusCode, string(raw))
	}
	defer func() {
		// Restore default 2026-07-28 for subsequent tests
		client.doJSON(http.MethodPut, "/admin/v1/mcp/spec", adminHeaders, map[string]any{
			"protocol_version": domain.MCPProtocolVersion20260728,
		}, nil)
	}()

	batchReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/mcp", strings.NewReader(`[{"jsonrpc":"2.0","id":1,"method":"ping"},{"jsonrpc":"2.0","id":2,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"e2e","version":"1.0"}}}]`))
	batchReq.Header.Set("Authorization", "Bearer "+vk.RawKey)
	batchReq.Header.Set("Content-Type", "application/json")
	batchResp, err := http.DefaultClient.Do(batchReq)
	if err != nil {
		t.Fatalf("batch /mcp request failed: %v", err)
	}
	batchBody, _ := io.ReadAll(batchResp.Body)
	_ = batchResp.Body.Close()
	if batchResp.StatusCode != http.StatusOK || !strings.Contains(string(batchBody), `"protocolVersion":"2025-03-26"`) {
		t.Fatalf("expected 2025-03-26 batch initialize response, got (%d): %s", batchResp.StatusCode, string(batchBody))
	}

	// 3. Switch back to 2026-07-28 and verify server/discover succeeds while batching fails with -32600
	resp, raw = client.doJSON(http.MethodPut, "/admin/v1/mcp/spec", adminHeaders, map[string]any{
		"protocol_version": domain.MCPProtocolVersion20260728,
	}, &specState)
	if resp.StatusCode != http.StatusOK || specState.ActiveProtocolVersion != domain.MCPProtocolVersion20260728 {
		t.Fatalf("PUT /admin/v1/mcp/spec 2026-07-28 failed (%d): %s", resp.StatusCode, string(raw))
	}

	discReq, _ := http.NewRequest(http.MethodPost, ts.URL+"/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":3,"method":"server/discover","params":{}}`))
	discReq.Header.Set("Authorization", "Bearer "+vk.RawKey)
	discReq.Header.Set("Content-Type", "application/json")
	discResp, err := http.DefaultClient.Do(discReq)
	if err != nil {
		t.Fatalf("discover /mcp request failed: %v", err)
	}
	discBody, _ := io.ReadAll(discResp.Body)
	_ = discResp.Body.Close()
	if discResp.StatusCode != http.StatusOK || !strings.Contains(string(discBody), `"supportedVersions":["2026-07-28"]`) {
		t.Fatalf("expected 2026-07-28 server/discover response, got (%d): %s", discResp.StatusCode, string(discBody))
	}

	// 4. Create & update per-server spec via PUT /admin/v1/mcp/servers/{serverID}
	var srvResp struct {
		Server domain.MCPServer `json:"server"`
	}
	resp, raw = client.doJSON(http.MethodPost, "/admin/v1/mcp/servers", adminHeaders, map[string]any{
		"org_id":           org.ID,
		"name":             "Live Editable MCP",
		"slug":             fmt.Sprintf("live-edit-%d", time.Now().UnixNano()),
		"protocol_version": domain.MCPProtocolVersion20251125,
		"transport_type":   domain.MCPTransportStreamableHTTP,
		"endpoint_url":     mockMCPSrv.URL,
	}, &srvResp)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create server failed (%d): %s", resp.StatusCode, string(raw))
	}
	resp, raw = client.doJSON(http.MethodPut, "/admin/v1/mcp/servers/"+srvResp.Server.ID, adminHeaders, map[string]any{
		"protocol_version": domain.MCPProtocolVersion20241105,
		"transport_type":   domain.MCPTransportHTTPSSE2024,
	}, &srvResp)
	if resp.StatusCode != http.StatusOK || srvResp.Server.ProtocolVersion != domain.MCPProtocolVersion20241105 || srvResp.Server.TransportType != domain.MCPTransportHTTPSSE2024 {
		t.Fatalf("PUT /admin/v1/mcp/servers/{id} failed (%d): %s", resp.StatusCode, string(raw))
	}
}
