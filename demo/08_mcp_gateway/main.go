package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"

	"github.com/goroute-ai/ai-gateway-go/demo/demoutil"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/pkg/gateway"
)

func main() {
	ctx := context.Background()

	// Setup mock upstream MCP server providing financial analysis tools
	upstreamMCPServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
							"name":        "calculate_discounted_cash_flow",
							"description": "Calculates DCF valuation given cash flows and discount rates",
							"inputSchema": map[string]any{
								"type": "object",
								"properties": map[string]any{
									"cash_flow":     map[string]any{"type": "number"},
									"discount_rate": map[string]any{"type": "number"},
								},
								"required": []string{"cash_flow", "discount_rate"},
							},
						},
						{
							"name":        "fetch_fx_rate",
							"description": "Returns currency foreign exchange conversion rates",
							"inputSchema": map[string]any{
								"type": "object",
								"properties": map[string]any{
									"from": map[string]any{"type": "string"},
									"to":   map[string]any{"type": "string"},
								},
								"required": []string{"from", "to"},
							},
						},
					},
				},
			})
			return
		}

		if method == "tools/call" {
			params, _ := rpcReq["params"].(map[string]any)
			toolName, _ := params["name"].(string)

			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0",
				"id":      rpcReq["id"],
				"result": map[string]any{
					"content": []map[string]any{
						{
							"type": "text",
							"text": fmt.Sprintf("Tool %s executed successfully with high-precision output: 14920485.928471928471", toolName),
						},
					},
				},
			})
			return
		}

		_ = json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      rpcReq["id"],
			"result":  map[string]any{"status": "ok"},
		})
	}))
	defer upstreamMCPServer.Close()

	// Start GoRoute AI Gateway
	gw, err := gateway.New(
		gateway.WithDemoMocksIfEnvMissing(),
	)
	if err != nil {
		demoutil.Fail("Gateway initialization failed", err)
	}
	defer gw.Close()

	demoutil.Banner("Model Context Protocol (MCP 2026-07-28 & 2025-11-25) Gateway")

	// Part 1: Register Upstream MCP Server
	demoutil.Part(1, "Register Upstream MCP Server via Admin Control Plane")
	serverSlug := "fin-tools"
	serverID, err := gw.RegisterMCPServer(ctx, domain.MCPServer{
		Name:            "Enterprise Finance Tools",
		Slug:            serverSlug,
		ProtocolVersion: "2026-07-28",
		EndpointURL:     upstreamMCPServer.URL,
		AuthType:        "none",
	})
	if err != nil {
		demoutil.Fail("Failed to register MCP server", err)
	}
	demoutil.Field("Registered Server ID", serverID)
	demoutil.Field("Protocol Standard", "MCP 2026-07-28 (Stateless Streamable HTTP)")

	// Part 2: Synchronize and Verify Tools
	demoutil.Part(2, "Sync Tools with Anti-Poisoning & Tool Pinning Protection")
	toolsCount, err := gw.SyncMCPTools(ctx, serverID)
	if err != nil {
		demoutil.Fail("Failed to sync MCP tools", err)
	}
	demoutil.Fieldf("Discovered Tools", "%d tools verified and cryptographic SHA-256 hashes pinned", toolsCount)

	// Part 3: Virtual Hub Aggregation
	demoutil.Part(3, "Virtual Hub Multi-Server Tool Aggregation (POST /mcp)")
	tools, err := gw.ListMCPTools(ctx, "/mcp")
	if err != nil {
		demoutil.Fail("Failed to list tools from Virtual Hub", err)
	}
	for i, t := range tools {
		name, _ := t["name"].(string)
		desc, _ := t["description"].(string)
		demoutil.Fieldf(fmt.Sprintf("Tool %d", i+1), "%-32s -> %s", name, desc)
	}

	// Part 4: Tool Execution with Arbitrary Precision Preservation
	demoutil.Part(4, "High-Precision Tool Invocation (POST /mcp/{serverSlug})")
	callResp, err := gw.CallMCPTool(ctx, "/mcp/"+serverSlug, "calculate_discounted_cash_flow", map[string]any{
		"cash_flow":     12500000.50,
		"discount_rate": 0.0825,
	})
	if err != nil {
		demoutil.Fail("Tool execution failed", err)
	}
	resMap, _ := callResp.Result.(map[string]any)
	contentList, _ := resMap["content"].([]any)
	if len(contentList) > 0 {
		firstContent, _ := contentList[0].(map[string]any)
		demoutil.Field("Result", firstContent["text"])
	}
	demoutil.Field("Precision Mode", "Preserved (Arbitrary Precision big.Rat / json.Number)")
}
