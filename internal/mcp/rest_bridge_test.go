package mcp_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/mcp"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockSpendRecorder struct {
	events []domain.SpendEvent
}

func (m *mockSpendRecorder) Record(_ context.Context, ev domain.SpendEvent) error {
	m.events = append(m.events, ev)
	return nil
}

func setupRESTBridgeTest(t *testing.T) (*mcp.Hub, *mcp.RESTBridge, storage.Repository, *mockSpendRecorder, *httptest.Server) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	vault, err := auth.NewVault("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	require.NoError(t, err)
	rbac := auth.NewRBACEngine(repo)

	netPolicy, err := network.NewPolicy(config.OutboundSSRFConfig{
		AllowPrivateNetworks: true,
		AllowInsecureHTTP:    true,
	})
	require.NoError(t, err)

	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req mcp.JSONRPCRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(mcp.JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]any{
				"content": []map[string]any{
					{"type": "text", "text": "rest tool response from " + r.Header.Get("X-Server-Target")},
				},
				"isError": false,
			},
		})
	}))

	srv1 := &domain.MCPServer{
		ID:              "mcp_srv_alpha",
		OrgID:           "org_test",
		Name:            "Alpha Server",
		Slug:            "alpha-server",
		ProtocolVersion: domain.MCPProtocolVersion2026,
		TransportType:   domain.MCPTransportStreamableHTTP,
		EndpointURL:     mockUpstream.URL,
		AuthType:        domain.MCPAuthNone,
		StaticHeaders:   map[string]string{"X-Server-Target": "alpha"},
		IsActive:        true,
	}
	require.NoError(t, repo.CreateMCPServer(ctx, srv1))

	srv2 := &domain.MCPServer{
		ID:              "mcp_srv_beta",
		OrgID:           "org_test",
		Name:            "Beta Server",
		Slug:            "beta-server",
		ProtocolVersion: domain.MCPProtocolVersion2026,
		TransportType:   domain.MCPTransportStreamableHTTP,
		EndpointURL:     mockUpstream.URL,
		AuthType:        domain.MCPAuthNone,
		StaticHeaders:   map[string]string{"X-Server-Target": "beta"},
		IsActive:        true,
	}
	require.NoError(t, repo.CreateMCPServer(ctx, srv2))

	toolAlpha := &domain.MCPTool{
		ID:                "tool_alpha_unique",
		ServerID:          srv1.ID,
		OrgID:             "org_test",
		Name:              "unique_tool",
		Description:       "Unique to alpha",
		InputSchema:       map[string]any{"type": "object"},
		CostPerCallMicros: 250,
		IsActive:          true,
	}
	require.NoError(t, repo.UpsertMCPTools(ctx, srv1.ID, srv1.OrgID, []*domain.MCPTool{toolAlpha}))

	// Shared name on both alpha and beta (for ambiguous testing)
	toolAmbAlpha := &domain.MCPTool{
		ID:                "tool_amb_alpha",
		ServerID:          srv1.ID,
		OrgID:             "org_test",
		Name:              "calculate",
		Description:       "Calculate on alpha",
		InputSchema:       map[string]any{"type": "object"},
		CostPerCallMicros: 100,
		IsActive:          true,
	}
	toolAmbBeta := &domain.MCPTool{
		ID:                "tool_amb_beta",
		ServerID:          srv2.ID,
		OrgID:             "org_test",
		Name:              "calculate",
		Description:       "Calculate on beta",
		InputSchema:       map[string]any{"type": "object"},
		CostPerCallMicros: 100,
		IsActive:          true,
	}
	require.NoError(t, repo.UpsertMCPTools(ctx, srv1.ID, srv1.OrgID, []*domain.MCPTool{toolAlpha, toolAmbAlpha}))
	require.NoError(t, repo.UpsertMCPTools(ctx, srv2.ID, srv2.OrgID, []*domain.MCPTool{toolAmbBeta}))

	dispatcher := mcp.NewTransportDispatcher(netPolicy, storage.NewRedisFabric("localhost:6379", "", 0), false)
	authResolver := mcp.NewAuthResolver(vault, netPolicy)
	hub := mcp.NewHub(repo, vault, rbac, dispatcher, authResolver)

	recorder := &mockSpendRecorder{}
	hub.SetSpendRecorder(recorder)

	bridge := mcp.NewRESTBridge(hub)
	return hub, bridge, repo, recorder, mockUpstream
}

func TestRESTBridge_ListTools(t *testing.T) {
	_, bridge, _, _, mockUpstream := setupRESTBridgeTest(t)
	defer mockUpstream.Close()

	idCtx := &domain.IdentityContext{
		OrgID:                 "org_test",
		KeyPrefix:             "sk-gw-test",
		KeyAllowedMCPServers:  []string{"alpha-server", "beta-server"},
		TeamAllowedMCPServers: nil,
	}

	// 1. List all tools across authorized servers
	req := httptest.NewRequest(http.MethodGet, "/mcp-rest/tools/list", nil)
	req = req.WithContext(auth.WithIdentity(req.Context(), idCtx))
	w := httptest.NewRecorder()
	bridge.HandleListTools(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var listResp struct {
		Tools []domain.MCPTool `json:"tools"`
	}
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &listResp))
	assert.Len(t, listResp.Tools, 3)

	// 2. Filter tools by specific server_slug
	reqFilter := httptest.NewRequest(http.MethodGet, "/mcp-rest/tools/list?server_slug=alpha-server", nil)
	reqFilter = reqFilter.WithContext(auth.WithIdentity(reqFilter.Context(), idCtx))
	wFilter := httptest.NewRecorder()
	bridge.HandleListTools(wFilter, reqFilter)

	require.Equal(t, http.StatusOK, wFilter.Code)
	var filteredResp struct {
		Tools []domain.MCPTool `json:"tools"`
	}
	require.NoError(t, json.Unmarshal(wFilter.Body.Bytes(), &filteredResp))
	assert.Len(t, filteredResp.Tools, 2)

	// 3. Filter by non-existent server_slug
	reqNotFound := httptest.NewRequest(http.MethodGet, "/mcp-rest/tools/list?server_slug=ghost-server", nil)
	reqNotFound = reqNotFound.WithContext(auth.WithIdentity(reqNotFound.Context(), idCtx))
	wNotFound := httptest.NewRecorder()
	bridge.HandleListTools(wNotFound, reqNotFound)
	assert.Equal(t, http.StatusNotFound, wNotFound.Code)
}

func TestRESTBridge_CallTool_UnambiguousAndAmbiguous(t *testing.T) {
	_, bridge, _, recorder, mockUpstream := setupRESTBridgeTest(t)
	defer mockUpstream.Close()

	idCtx := &domain.IdentityContext{
		OrgID:                 "org_test",
		VirtualKeyID:          "vk_123",
		KeyPrefix:             "sk-gw-test",
		KeyAllowedMCPServers:  []string{"alpha-server", "beta-server"},
		TeamAllowedMCPServers: nil,
	}

	// 1. Call unique tool without server_slug (unambiguous resolution)
	callBody, _ := json.Marshal(map[string]any{
		"tool_name": "unique_tool",
		"arguments": map[string]any{"query": "antigravity"},
	})
	req := httptest.NewRequest(http.MethodPost, "/mcp-rest/tools/call", bytes.NewReader(callBody))
	req = req.WithContext(auth.WithIdentity(req.Context(), idCtx))
	w := httptest.NewRecorder()
	bridge.HandleCallTool(w, req)

	require.Equal(t, http.StatusOK, w.Code)
	var callResp mcp.CallToolResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &callResp))
	assert.False(t, callResp.IsError)
	require.Len(t, callResp.Content, 1)
	assert.Contains(t, callResp.Content[0].Text, "alpha")

	// Verify FinOps spend was debited (250 micros)
	require.Len(t, recorder.events, 1)
	assert.Equal(t, int64(250), recorder.events[0].CostMicros)
	assert.Equal(t, "mcp:alpha-server/unique_tool", recorder.events[0].ProtocolTarget)

	// 2. Call ambiguous tool without server_slug (must fail with 400 AmbiguousToolName)
	ambBody, _ := json.Marshal(map[string]any{
		"tool_name": "calculate",
		"arguments": map[string]any{"x": 10},
	})
	reqAmb := httptest.NewRequest(http.MethodPost, "/mcp-rest/tools/call", bytes.NewReader(ambBody))
	reqAmb = reqAmb.WithContext(auth.WithIdentity(reqAmb.Context(), idCtx))
	wAmb := httptest.NewRecorder()
	bridge.HandleCallTool(wAmb, reqAmb)

	assert.Equal(t, http.StatusBadRequest, wAmb.Code)
	var errResp map[string]any
	require.NoError(t, json.Unmarshal(wAmb.Body.Bytes(), &errResp))
	errObj := errResp["error"].(map[string]any)
	assert.Equal(t, "AmbiguousToolName", errObj["code"])
	serversList := errObj["matching_servers"].([]any)
	assert.Len(t, serversList, 2)

	// 3. Call ambiguous tool with server_slug disambiguation (succeeds on beta)
	disBody, _ := json.Marshal(map[string]any{
		"server_slug": "beta-server",
		"tool_name":   "calculate",
		"arguments":   map[string]any{"x": 10},
	})
	reqDis := httptest.NewRequest(http.MethodPost, "/mcp-rest/tools/call", bytes.NewReader(disBody))
	reqDis = reqDis.WithContext(auth.WithIdentity(reqDis.Context(), idCtx))
	wDis := httptest.NewRecorder()
	bridge.HandleCallTool(wDis, reqDis)

	require.Equal(t, http.StatusOK, wDis.Code)
	var disResp mcp.CallToolResponse
	require.NoError(t, json.Unmarshal(wDis.Body.Bytes(), &disResp))
	require.Len(t, disResp.Content, 1)
	assert.Contains(t, disResp.Content[0].Text, "beta")

	// Verify second FinOps spend event was debited (100 micros for calculate on beta)
	require.Len(t, recorder.events, 2)
	assert.Equal(t, int64(100), recorder.events[1].CostMicros)
	assert.Equal(t, "mcp:beta-server/calculate", recorder.events[1].ProtocolTarget)
}

func TestRESTBridge_RBACDenial(t *testing.T) {
	_, bridge, _, _, mockUpstream := setupRESTBridgeTest(t)
	defer mockUpstream.Close()

	// Virtual key only allowed to access alpha-server
	idCtx := &domain.IdentityContext{
		OrgID:                 "org_test",
		VirtualKeyID:          "vk_restricted",
		KeyPrefix:             "sk-gw-restricted",
		KeyAllowedMCPServers:  []string{"alpha-server"},
		TeamAllowedMCPServers: nil,
	}

	// Try to call beta-server explicitly -> 403 Forbidden
	callBody, _ := json.Marshal(map[string]any{
		"server_slug": "beta-server",
		"tool_name":   "calculate",
		"arguments":   map[string]any{"x": 10},
	})
	req := httptest.NewRequest(http.MethodPost, "/mcp-rest/tools/call", bytes.NewReader(callBody))
	req = req.WithContext(auth.WithIdentity(req.Context(), idCtx))
	w := httptest.NewRecorder()
	bridge.HandleCallTool(w, req)

	assert.Equal(t, http.StatusForbidden, w.Code)
}
