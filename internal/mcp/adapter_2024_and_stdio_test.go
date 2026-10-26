package mcp_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/mcp"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
)

func TestHTTPSSEServer2024Transport(t *testing.T) {
	ctx := context.Background()

	// 1. Mock legacy 2024 HTTP+SSE Server
	var postReceivedMessage string
	var postURL string

	mockSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/sse":
			// Server-Sent Events endpoint
			w.Header().Set("Content-Type", "text/event-stream")
			w.Header().Set("Cache-Control", "no-cache")
			w.Header().Set("Connection", "keep-alive")
			flusher, _ := w.(http.Flusher)

			// Emit initial endpoint discovery event pointing to /message
			fmt.Fprintf(w, "event: endpoint\ndata: %s/message?sessionId=sess_2024_xyz\n\n", postURL)
			if flusher != nil {
				flusher.Flush()
			}

			// Keep connection open
			select {
			case <-r.Context().Done():
				return
			case <-time.After(5 * time.Second):
				return
			}

		case r.URL.Path == "/message":
			// POST message endpoint
			var rpcReq map[string]any
			_ = json.NewDecoder(r.Body).Decode(&rpcReq)
			method, _ := rpcReq["method"].(string)
			postReceivedMessage = method

			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0",
				"id":      rpcReq["id"],
				"result": map[string]any{
					"content": []map[string]any{
						{"type": "text", "text": "legacy 2024 sse response"},
					},
					"isError": false,
				},
			})

		default:
			http.NotFound(w, r)
		}
	}))
	defer mockSrv.Close()
	postURL = mockSrv.URL

	netPolicy := &network.Policy{AllowPrivateNetworks: true, AllowInsecureHTTP: true}
	transport := mcp.NewHTTPSSEServer2024Transport(netPolicy)
	defer transport.Close()

	server := &domain.MCPServer{
		ID:              "mcp_srv_2024",
		Name:            "Legacy 2024 Server",
		Slug:            "legacy-2024",
		ProtocolVersion: "2024-11-05",
		TransportType:   "http_sse_2024",
		EndpointURL:     mockSrv.URL + "/sse",
		IsActive:        true,
	}

	callReq := map[string]any{
		"jsonrpc": "2.0",
		"id":      "call_101",
		"method":  "tools/call",
		"params": map[string]any{
			"name":      "query_legacy",
			"arguments": map[string]any{"q": "test"},
		},
	}
	reqBytes, _ := json.Marshal(callReq)

	rpcResp, _, err := transport.RoundTrip(ctx, server, nil, nil, reqBytes, nil)
	if err != nil {
		t.Fatalf("roundtrip 2024 sse failed: %v", err)
	}

	if postReceivedMessage != "tools/call" {
		t.Fatalf("expected tools/call to be posted, got: %s", postReceivedMessage)
	}

	resultMap, _ := rpcResp.Result.(map[string]any)
	content, _ := resultMap["content"].([]any)
	if len(content) == 0 {
		t.Fatalf("expected non-empty content: %v", resultMap)
	}
	c0, _ := content[0].(map[string]any)
	if !strings.Contains(c0["text"].(string), "legacy 2024 sse response") {
		t.Fatalf("unexpected content: %v", c0)
	}
}

func TestStdioTransport_ProcessSandboxing(t *testing.T) {
	ctx := context.Background()

	// 1. Approved binary: cat with valid JSON-RPC echo
	policy := mcp.StdioSecurityPolicy{
		AllowedBinaries: []string{"cat"},
		DefaultTimeout:  5 * time.Second,
	}
	transport := mcp.NewStdioTransport(policy)

	// Command reads JSON-RPC on stdin and echoes JSON-RPC response on stdout
	server := &domain.MCPServer{
		ID:            "mcp_srv_stdio",
		Name:          "Local Echo Stdio Server",
		Slug:          "local-echo",
		TransportType: "stdio",
		EndpointURL:   "stdio://cat",
		IsActive:      true,
	}

	callReq := map[string]any{
		"jsonrpc": "2.0",
		"id":      10,
		"result": map[string]any{
			"content": []map[string]any{
				{"type": "text", "text": "stdio success"},
			},
			"isError": false,
		},
	}
	reqBytes, _ := json.Marshal(callReq)

	rpcResp, _, err := transport.RoundTrip(ctx, server, nil, nil, reqBytes, nil)
	if err != nil {
		t.Fatalf("stdio roundtrip failed: %v", err)
	}

	resultMap, _ := rpcResp.Result.(map[string]any)
	content, _ := resultMap["content"].([]any)
	if len(content) == 0 {
		t.Fatalf("expected non-empty content in stdio response: %v", resultMap)
	}
	c0, _ := content[0].(map[string]any)
	if !strings.Contains(c0["text"].(string), "stdio success") {
		t.Fatalf("unexpected stdio content: %v", c0)
	}

	// 2. Unapproved binary rejection
	disallowedServer := &domain.MCPServer{
		ID:            "mcp_srv_bad_stdio",
		TransportType: "stdio",
		EndpointURL:   "stdio://python3 -c 'print()'",
	}
	_, _, err = transport.RoundTrip(ctx, disallowedServer, nil, nil, reqBytes, nil)
	if err == nil || !strings.Contains(err.Error(), "not in approved allowlist") {
		t.Fatalf("expected binary not allowed error, got: %v", err)
	}
}
