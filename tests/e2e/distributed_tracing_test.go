package e2e_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/a2a"
	"github.com/goroute-ai/ai-gateway-go/internal/a2a/pb"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/server"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

func TestUnifiedObservability_W3CTracePropagation(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()

	// 1. Setup Mock Upstream OpenAI Provider
	var receivedInferenceTrace atomic.Pointer[string]
	mockOpenAI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tp := r.Header.Get("traceparent")
		receivedInferenceTrace.Store(&tp)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":      "chatcmpl_obs_test",
			"object":  "chat.completion",
			"created": time.Now().Unix(),
			"model":   "openai/gpt-4o",
			"choices": []map[string]any{
				{
					"index": 0,
					"message": map[string]any{
						"role":    "assistant",
						"content": "Observability trace verified.",
					},
					"finish_reason": "stop",
				},
			},
		})
	}))
	defer mockOpenAI.Close()

	// 2. Setup Mock Upstream MCP Server
	var receivedMCPTrace atomic.Pointer[string]
	mockMCP := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tp := r.Header.Get("traceparent")
		receivedMCPTrace.Store(&tp)

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
							"name":        "ping_tool",
							"description": "Observability ping tool",
							"inputSchema": map[string]any{"type": "object"},
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
						{"type": "text", "text": "pong from mcp"},
					},
					"isError": false,
				},
			})
			return
		}
	}))
	defer mockMCP.Close()

	// 3. Setup Mock Upstream A2A Agent
	var receivedA2ATrace atomic.Pointer[string]
	mockA2A := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tp := r.Header.Get("traceparent")
		receivedA2ATrace.Store(&tp)

		w.Header().Set("Content-Type", "application/json")
		respObj := &pb.SendMessageResponse{
			Payload: &pb.SendMessageResponse_Task{
				Task: &pb.Task{
					Status: &pb.TaskStatus{
						State: pb.TaskState_TASK_STATE_COMPLETED,
						Message: &pb.Message{
							Role:  pb.Role_ROLE_AGENT,
							Parts: []*pb.Part{{Content: &pb.Part_Text{Text: "A2A trace verified"}}},
						},
					},
				},
			},
		}
		outJSON, _ := a2a.ProtoJSONMarshaler.Marshal(respObj)
		_, _ = w.Write(outJSON)
	}))
	defer mockA2A.Close()

	// 4. Initialize Gateway
	cfg := config.Default()
	cfg.Auth.MasterAdminKey = "sk-gw-admin-obs-key"
	cfg.Auth.MasterEncryptionKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	cfg.Security.Network.OutboundSSRF.AllowPrivateNetworks = true
	cfg.Security.Network.OutboundSSRF.AllowInsecureHTTP = true
	cfg.MCP.Enabled = true
	cfg.A2A.Enabled = true
	cfg.A2A.EnableJSONRPC = true
	cfg.A2A.EnableHTTPJSON = true
	cfg.A2A.SigningKeyID = "gw-obs-key-1"

	gw, err := server.New(cfg, repo, nil, nil)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	ts := httptest.NewServer(gw.Handler())
	defer ts.Close()
	defer gw.Shutdown(ctx)

	client := &httpClientHelper{t: t, ts: ts}
	adminHeaders := map[string]string{"Authorization": "Bearer sk-gw-admin-obs-key"}

	// 5. Bootstrap Org, Credential, ModelGroup, Key, MCP Server, A2A Agent
	var org domain.Organization
	client.doJSON("POST", "/admin/v1/organizations", adminHeaders, map[string]any{
		"name": "Observability Org",
		"slug": fmt.Sprintf("obs-org-%d", time.Now().UnixNano()),
	}, &org)

	client.doJSON("POST", fmt.Sprintf("/admin/v1/organizations/%s/subscriptions", org.ID), adminHeaders, map[string]any{
		"provider": "openai", "is_enabled": true,
	}, nil)

	var cred domain.ProviderCredential
	client.doJSON("POST", "/admin/v1/credentials", adminHeaders, map[string]any{
		"org_id":   org.ID,
		"provider": "openai",
		"name":     "Mock OpenAI",
		"base_url": mockOpenAI.URL,
		"api_key":  "sk-mock-key",
	}, &cred)

	var mg domain.ModelGroup
	client.doJSON("POST", "/admin/v1/model-groups", adminHeaders, map[string]any{
		"org_id":           org.ID,
		"alias":            "gpt-4.1",
		"routing_strategy": "weighted-shuffle",
	}, &mg)

	var dep domain.Deployment
	client.doJSON("POST", "/admin/v1/deployments", adminHeaders, map[string]any{
		"model_group_id":  mg.ID,
		"credential_id":   cred.ID,
		"global_model_id": "openai/gpt-4.1",
		"deployment_name": "mock-openai-dep",
		"weight":          100,
	}, &dep)

	var vk domain.VirtualKey
	client.doJSON("POST", "/admin/v1/keys", adminHeaders, map[string]any{
		"org_id":              org.ID,
		"name":                "obs-key",
		"allowed_endpoints":   []string{"*"},
		"allowed_mcp_servers": []string{"*"},
		"allowed_a2a_agents":  []string{"*"},
	}, &vk)
	secretKey := vk.RawKey

	var srvResp struct {
		Server domain.MCPServer `json:"server"`
	}
	client.doJSON("POST", "/admin/v1/mcp/servers", adminHeaders, map[string]any{
		"org_id":           org.ID,
		"name":             "Obs MCP",
		"slug":             "obs-mcp",
		"protocol_version": "2026-07-28",
		"transport_type":   "streamable_http",
		"endpoint_url":     mockMCP.URL,
		"is_active":        true,
	}, &srvResp)
	client.doJSON("POST", fmt.Sprintf("/admin/v1/mcp/servers/%s/sync", srvResp.Server.ID), adminHeaders, nil, nil)

	var agentResp struct {
		Agent domain.A2AAgent `json:"agent"`
	}
	client.doJSON("POST", "/admin/v1/a2a/agents", adminHeaders, map[string]any{
		"org_id":               org.ID,
		"name":                 "Obs Agent",
		"slug":                 "obs-agent",
		"endpoint_url":         mockA2A.URL,
		"task_visibility_mode": "key_strict",
		"is_active":            true,
	}, &agentResp)

	// -------------------------------------------------------------------------
	// Test Case 1: Trace Context Ingestion & Propagation via Direct Inference
	// -------------------------------------------------------------------------
	const expectedTraceID = "4bf92f3577b34da6a3ce929d0e0e4736"
	const incomingTraceParent = "00-" + expectedTraceID + "-00f067aa0ba902b7-01"
	const incomingReqID = "req_obs_custom_001"

	infHeaders := map[string]string{
		"Authorization": "Bearer " + secretKey,
		"traceparent":   incomingTraceParent,
		"X-Request-Id":  incomingReqID,
	}

	chatReq := map[string]any{
		"model": "gpt-4.1",
		"messages": []map[string]any{
			{"role": "user", "content": "Test trace propagation"},
		},
	}
	resp, _ := client.doJSON("POST", "/v1/chat/completions", infHeaders, chatReq, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("chat completion failed: %d", resp.StatusCode)
	}

	// Verify gateway response headers
	if resp.Header.Get("X-Request-Id") != incomingReqID {
		t.Fatalf("expected X-Request-Id %q, got: %q", incomingReqID, resp.Header.Get("X-Request-Id"))
	}
	if !strings.Contains(resp.Header.Get("traceparent"), expectedTraceID) {
		t.Fatalf("expected traceparent response header to contain %q, got: %q", expectedTraceID, resp.Header.Get("traceparent"))
	}

	// Verify upstream OpenAI provider received the traceparent
	upInfTrace := receivedInferenceTrace.Load()
	if upInfTrace == nil || !strings.Contains(*upInfTrace, expectedTraceID) {
		t.Fatalf("upstream OpenAI did not receive traceparent containing %q: got %v", expectedTraceID, upInfTrace)
	}

	// -------------------------------------------------------------------------
	// Test Case 2: Trace Context Ingestion & Propagation via MCP REST Bridge
	// -------------------------------------------------------------------------
	mcpHeaders := map[string]string{
		"Authorization": "Bearer " + secretKey,
		"traceparent":   incomingTraceParent,
		"X-Request-Id":  "req_obs_mcp_002",
	}
	callReq := map[string]any{
		"server_slug": "obs-mcp",
		"tool_name":   "ping_tool",
		"arguments":   map[string]any{},
	}
	resp, _ = client.doJSON("POST", "/mcp-rest/tools/call", mcpHeaders, callReq, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("mcp tool call failed: %d", resp.StatusCode)
	}
	if resp.Header.Get("X-Request-Id") != "req_obs_mcp_002" {
		t.Fatalf("expected X-Request-Id req_obs_mcp_002, got: %q", resp.Header.Get("X-Request-Id"))
	}
	if !strings.Contains(resp.Header.Get("traceparent"), expectedTraceID) {
		t.Fatalf("expected mcp response traceparent to contain %q, got: %q", expectedTraceID, resp.Header.Get("traceparent"))
	}

	upMCPTrace := receivedMCPTrace.Load()
	if upMCPTrace == nil || !strings.Contains(*upMCPTrace, expectedTraceID) {
		t.Fatalf("upstream MCP server did not receive traceparent containing %q: got %v", expectedTraceID, upMCPTrace)
	}

	// -------------------------------------------------------------------------
	// Test Case 3: Trace Context Ingestion & Propagation via A2A Dispatch
	// -------------------------------------------------------------------------
	a2aHeaders := map[string]string{
		"Authorization": "Bearer " + secretKey,
		"traceparent":   incomingTraceParent,
		"X-Request-Id":  "req_obs_a2a_003",
	}
	a2aReq := map[string]any{
		"jsonrpc": "2.0",
		"id":      "obs-a2a-001",
		"method":  "tasks/send",
		"params": map[string]any{
			"message": map[string]any{
				"messageId": "msg_obs_01",
				"role":      "ROLE_USER",
				"parts":     []map[string]any{{"text": "Ping A2A with trace"}},
			},
		},
	}
	resp, _ = client.doJSON("POST", "/a2a/v1/agents/obs-agent", a2aHeaders, a2aReq, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("a2a send failed: %d", resp.StatusCode)
	}
	if resp.Header.Get("X-Request-Id") != "req_obs_a2a_003" {
		t.Fatalf("expected X-Request-Id req_obs_a2a_003, got: %q", resp.Header.Get("X-Request-Id"))
	}
	if !strings.Contains(resp.Header.Get("traceparent"), expectedTraceID) {
		t.Fatalf("expected a2a response traceparent to contain %q, got: %q", expectedTraceID, resp.Header.Get("traceparent"))
	}

	upA2ATrace := receivedA2ATrace.Load()
	if upA2ATrace == nil || !strings.Contains(*upA2ATrace, expectedTraceID) {
		t.Fatalf("upstream A2A agent did not receive traceparent containing %q: got %v", expectedTraceID, upA2ATrace)
	}
}
