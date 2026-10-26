package mcp_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/mcp"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

func TestProgressiveDiscovery_HandlesAndFreshness(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()

	orgID := "org_prog_test"
	server := &domain.MCPServer{
		ID:              "mcp_srv_prog_1",
		OrgID:           orgID,
		Name:            "Progressive Storage Server",
		Slug:            "storage-service",
		ProtocolVersion: "2026-07-28",
		TransportType:   "streamable_http",
		EndpointURL:     "https://storage.internal.net/mcp",
		IsActive:        true,
	}
	_ = repo.CreateMCPServer(ctx, server)

	tool := &domain.MCPTool{
		ID:          "mcp_tool_write_blob",
		ServerID:    server.ID,
		OrgID:       orgID,
		Name:        "write_blob",
		Description: "Writes binary blob to object storage",
		ToolDefHash: "hash_v1_blob_writer",
		IsActive:    true,
	}
	_ = repo.UpsertMCPTools(ctx, server.ID, orgID, []*domain.MCPTool{tool})

	pdm := mcp.NewProgressiveDiscoveryManager(repo, nil, 10*time.Minute)

	// 1. Generate Opaque Handle
	rec, err := pdm.GenerateHandle(ctx, tool, server.Slug)
	if err != nil {
		t.Fatalf("generate handle: %v", err)
	}

	if !strings.HasPrefix(rec.Handle, mcp.HandlePrefix) {
		t.Fatalf("expected prefix %s, got: %s", mcp.HandlePrefix, rec.Handle)
	}
	// 256 bits = 64 hex chars + prefix
	if len(rec.Handle) != len(mcp.HandlePrefix)+64 {
		t.Fatalf("expected 256-bit handle length %d, got %d", len(mcp.HandlePrefix)+64, len(rec.Handle))
	}

	// 2. Resolve Handle Fresh
	resRec, resTool, err := pdm.ResolveHandle(ctx, rec.Handle)
	if err != nil {
		t.Fatalf("resolve handle: %v", err)
	}
	if resRec.ToolName != "write_blob" || resTool.ID != tool.ID {
		t.Fatalf("resolved tool mismatch: %v", resRec)
	}

	// 3. Stale Tool Handle Fail-Closed Check
	// Simulate tool update in upstream repository (hash changed to v2)
	updatedTool := *tool
	updatedTool.ToolDefHash = "hash_v2_new_schema"
	_ = repo.UpsertMCPTools(ctx, server.ID, orgID, []*domain.MCPTool{&updatedTool})

	_, _, err = pdm.ResolveHandle(ctx, rec.Handle)
	if err == nil || !strings.Contains(err.Error(), "stale tool handle") {
		t.Fatalf("expected stale tool handle error on schema change, got: %v", err)
	}

	// 4. Invalid handle rejection
	_, _, err = pdm.ResolveHandle(ctx, "invalid_handle_xyz")
	if err != mcp.ErrInvalidHandle {
		t.Fatalf("expected ErrInvalidHandle, got: %v", err)
	}
}

func TestProgressiveDiscovery_SearchAndRegistryFeed(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()

	orgID := "org_reg_test"
	srv := &domain.MCPServer{
		ID:              "mcp_srv_search",
		OrgID:           orgID,
		Name:            "Analytics Server",
		Slug:            "analytics",
		ProtocolVersion: "2026-07-28",
		TransportType:   "streamable_http",
		EndpointURL:     "https://analytics.internal/mcp",
		IsActive:        true,
	}
	_ = repo.CreateMCPServer(ctx, srv)

	tools := []*domain.MCPTool{
		{
			ID:          "mcp_tool_query_metrics",
			ServerID:    srv.ID,
			OrgID:       orgID,
			Name:        "query_metrics",
			Description: "Queries timeseries database metrics",
			ToolDefHash: "hash_qm",
			IsActive:    true,
		},
		{
			ID:          "mcp_tool_export_csv",
			ServerID:    srv.ID,
			OrgID:       orgID,
			Name:        "export_csv",
			Description: "Exports tabular records to CSV format",
			ToolDefHash: "hash_ec",
			IsActive:    true,
		},
	}
	_ = repo.UpsertMCPTools(ctx, srv.ID, orgID, tools)

	pdm := mcp.NewProgressiveDiscoveryManager(repo, nil, 10*time.Minute)
	idCtx := &domain.IdentityContext{OrgID: orgID}

	// Search matching "metrics"
	summaries, err := pdm.SearchTools(ctx, idCtx, "metrics", 5)
	if err != nil {
		t.Fatalf("search tools: %v", err)
	}
	if len(summaries) != 1 || summaries[0].Name != "query_metrics" {
		t.Fatalf("expected query_metrics in results, got: %v", summaries)
	}
	if !strings.HasPrefix(summaries[0].ToolHandle, mcp.HandlePrefix) {
		t.Fatalf("expected opaque handle in summary: %s", summaries[0].ToolHandle)
	}

	// Build Registry Feed
	feed, err := pdm.BuildRegistryFeed(ctx, idCtx)
	if err != nil {
		t.Fatalf("build registry feed: %v", err)
	}
	if len(feed) != 1 || feed[0].ServerSlug != "analytics" || feed[0].ToolCount != 2 {
		t.Fatalf("unexpected feed content: %v", feed)
	}
}

func TestHub_MetaToolsAndOpaqueHandleCall(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	netPolicy := &network.Policy{AllowPrivateNetworks: true, AllowInsecureHTTP: true}
	dispatcher := mcp.NewTransportDispatcher(netPolicy, nil, false)
	authResolver := mcp.NewAuthResolver(nil, netPolicy)

	hub := mcp.NewHub(repo, nil, nil, dispatcher, authResolver)

	orgID := "org_hub_prog"
	mockTargetSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var rpcReq map[string]any
		_ = json.NewDecoder(r.Body).Decode(&rpcReq)
		json.NewEncoder(w).Encode(map[string]any{
			"jsonrpc": "2.0",
			"id":      rpcReq["id"],
			"result": map[string]any{
				"content": []map[string]any{
					{"type": "text", "text": "executed via opaque handle"},
				},
				"isError": false,
			},
		})
	}))
	defer mockTargetSrv.Close()

	srv := &domain.MCPServer{
		ID:              "mcp_srv_target",
		OrgID:           orgID,
		Name:            "Echo Service",
		Slug:            "echo-svc",
		ProtocolVersion: "2026-07-28",
		TransportType:   "streamable_http",
		EndpointURL:     mockTargetSrv.URL,
		IsActive:        true,
	}
	_ = repo.CreateMCPServer(ctx, srv)

	tool := &domain.MCPTool{
		ID:          "mcp_tool_echo",
		ServerID:    srv.ID,
		OrgID:       orgID,
		Name:        "echo_msg",
		Description: "Echoes message back",
		ToolDefHash: "hash_echo_1",
		IsActive:    true,
	}
	_ = repo.UpsertMCPTools(ctx, srv.ID, orgID, []*domain.MCPTool{tool})

	idCtx := &domain.IdentityContext{
		OrgID: orgID,
	}

	// 1. Call Meta-Tool: search_tools
	searchResp, err := hub.CallTool(ctx, idCtx, mcp.ToolCallInput{
		ToolName: "search_tools",
		Arguments: map[string]any{
			"query": "echo",
		},
	}, mcp.CallMetadata{})
	if err != nil {
		t.Fatalf("search_tools meta-tool failed: %v", err)
	}
	if len(searchResp.Content) == 0 {
		t.Fatalf("expected non-empty search_tools content")
	}

	var foundSummaries []mcp.ToolSummary
	if err := json.Unmarshal([]byte(searchResp.Content[0].Text), &foundSummaries); err != nil {
		t.Fatalf("decode search_tools result: %v", err)
	}
	if len(foundSummaries) != 1 || foundSummaries[0].Name != "echo_msg" {
		t.Fatalf("expected echo_msg summary, got: %v", foundSummaries)
	}
	handle := foundSummaries[0].ToolHandle

	// 2. Call Meta-Tool: get_tool_schema
	schemaResp, err := hub.CallTool(ctx, idCtx, mcp.ToolCallInput{
		ToolName: "get_tool_schema",
		Arguments: map[string]any{
			"tool_handle": handle,
		},
	}, mcp.CallMetadata{})
	if err != nil {
		t.Fatalf("get_tool_schema meta-tool failed: %v", err)
	}
	if !strings.Contains(schemaResp.Content[0].Text, "echo_msg") {
		t.Fatalf("expected tool schema in response: %s", schemaResp.Content[0].Text)
	}

	// 3. Call Tool Directly Using Opaque Handle
	callResp, err := hub.CallTool(ctx, idCtx, mcp.ToolCallInput{
		ToolName: handle,
		Arguments: map[string]any{
			"msg": "hello",
		},
	}, mcp.CallMetadata{})
	if err != nil {
		t.Fatalf("call tool via opaque handle failed: %v", err)
	}
	if len(callResp.Content) == 0 || !strings.Contains(callResp.Content[0].Text, "executed via opaque handle") {
		t.Fatalf("unexpected call response: %v", callResp)
	}
}

func TestOpenAPITransport_GovernedAdapter(t *testing.T) {
	ctx := context.Background()

	// 1. Mock Target REST Service + OpenAPI 3.0 spec endpoint
	mockRESTServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/openapi.json":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{
  "openapi": "3.0.0",
  "info": {"title": "Pet Store API", "version": "1.0.0"},
  "paths": {
    "/pets/{petId}": {
      "get": {
        "operationId": "getPetById",
        "summary": "Find pet by ID",
        "parameters": [
          {"name": "petId", "in": "path", "required": true, "schema": {"type": "string"}},
          {"name": "verbose", "in": "query", "required": false, "schema": {"type": "boolean"}}
        ]
      }
    },
    "/pets": {
      "post": {
        "operationId": "createPet",
        "summary": "Create a new pet",
        "requestBody": {
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "type": "object",
                "properties": {
                  "name": {"type": "string"},
                  "tag": {"type": "string"}
                },
                "required": ["name"]
              }
            }
          }
        }
      }
    }
  }
}`)
		case strings.HasPrefix(r.URL.Path, "/pets/pet_99"):
			if r.Method != http.MethodGet {
				t.Errorf("expected GET, got %s", r.Method)
			}
			if r.URL.Query().Get("verbose") != "true" {
				t.Errorf("expected verbose=true, got %s", r.URL.Query().Get("verbose"))
			}
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"id":"pet_99","name":"Rover","status":"available"}`)

		case r.URL.Path == "/pets":
			if r.Method != http.MethodPost {
				t.Errorf("expected POST, got %s", r.Method)
			}
			body, _ := io.ReadAll(r.Body)
			if !strings.Contains(string(body), `"name":"Milo"`) {
				t.Errorf("unexpected POST body: %s", string(body))
			}
			w.WriteHeader(http.StatusCreated)
			fmt.Fprint(w, `{"id":"pet_100","name":"Milo","created":true}`)

		default:
			http.NotFound(w, r)
		}
	}))
	defer mockRESTServer.Close()

	netPolicy := &network.Policy{AllowPrivateNetworks: true, AllowInsecureHTTP: true}
	transport := mcp.NewOpenAPITransport(netPolicy)

	server := &domain.MCPServer{
		ID:            "mcp_srv_petstore",
		Name:          "Pet Store OpenAPI",
		Slug:          "petstore",
		TransportType: "openapi",
		EndpointURL:   mockRESTServer.URL + "/openapi.json",
		IsActive:      true,
	}

	// 2. Test tools/list on OpenAPI spec
	listReq := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/list",
		"params":  map[string]any{},
	}
	listBytes, _ := json.Marshal(listReq)

	rpcResp, _, err := transport.RoundTrip(ctx, server, nil, nil, listBytes, nil)
	if err != nil {
		t.Fatalf("roundtrip tools/list: %v", err)
	}

	resultMap, _ := rpcResp.Result.(map[string]any)
	toolsList, _ := resultMap["tools"].([]map[string]any)
	if len(toolsList) != 2 {
		t.Fatalf("expected 2 tools discovered from OpenAPI spec, got: %d", len(toolsList))
	}

	// Verify operation IDs
	opNames := make(map[string]bool)
	for _, tMap := range toolsList {
		opNames[tMap["name"].(string)] = true
	}
	if !opNames["getPetById"] || !opNames["createPet"] {
		t.Fatalf("missing expected operations in tools: %v", opNames)
	}

	// 3. Test tools/call: GET /pets/{petId}?verbose=true
	callGetReq := map[string]any{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "tools/call",
		"params": map[string]any{
			"name": "getPetById",
			"arguments": map[string]any{
				"petId":   "pet_99",
				"verbose": true,
			},
		},
	}
	callGetBytes, _ := json.Marshal(callGetReq)

	getResp, _, err := transport.RoundTrip(ctx, server, nil, nil, callGetBytes, nil)
	if err != nil {
		t.Fatalf("roundtrip tools/call getPetById: %v", err)
	}
	getResult, _ := getResp.Result.(map[string]any)
	getContent, _ := getResult["content"].([]map[string]any)
	if len(getContent) == 0 || !strings.Contains(getContent[0]["text"].(string), "Rover") {
		t.Fatalf("unexpected GET content: %v", getResult)
	}

	// 4. Test tools/call: POST /pets
	callPostReq := map[string]any{
		"jsonrpc": "2.0",
		"id":      3,
		"method":  "tools/call",
		"params": map[string]any{
			"name": "createPet",
			"arguments": map[string]any{
				"name": "Milo",
				"tag":  "dog",
			},
		},
	}
	callPostBytes, _ := json.Marshal(callPostReq)

	postResp, _, err := transport.RoundTrip(ctx, server, nil, nil, callPostBytes, nil)
	if err != nil {
		t.Fatalf("roundtrip tools/call createPet: %v", err)
	}
	postResult, _ := postResp.Result.(map[string]any)
	postContent, _ := postResult["content"].([]map[string]any)
	if len(postContent) == 0 || !strings.Contains(postContent[0]["text"].(string), "Milo") {
		t.Fatalf("unexpected POST content: %v", postResult)
	}
}
