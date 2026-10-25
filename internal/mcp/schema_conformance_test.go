package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/mcp/spec"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupConformanceHub(t *testing.T, upstreamHandler http.HandlerFunc) (*Hub, storage.Repository, *domain.IdentityContext, *domain.MCPServer, func()) {
	t.Helper()

	repo := storage.NewMemoryRepository()
	ctx := t.Context()

	require.NoError(t, repo.CreateOrganization(ctx, &domain.Organization{
		ID:       "org_conf",
		Name:     "Conformance Org",
		IsActive: true,
	}))

	mockUpstream := httptest.NewServer(upstreamHandler)

	netPolicy, err := network.NewPolicy(config.OutboundSSRFConfig{
		AllowPrivateNetworks: true,
		AllowInsecureHTTP:    true,
	})
	require.NoError(t, err)

	vault, err := auth.NewVault("01234567890123456789012345678901")
	require.NoError(t, err)
	rbac := auth.NewRBACEngine(repo)
	dispatcher := NewTransportDispatcher(netPolicy, nil, true)
	authResolver := NewAuthResolver(vault, netPolicy)
	hub := NewHub(repo, vault, rbac, dispatcher, authResolver)

	srv := &domain.MCPServer{
		ID:              "srv_conf_1",
		OrgID:           "org_conf",
		Name:            "Conformance Upstream",
		Slug:            "conf-srv",
		ProtocolVersion: domain.MCPProtocolVersion20260728,
		TransportType:   domain.MCPTransportStreamableHTTP,
		EndpointURL:     mockUpstream.URL,
		AuthType:        "none",
		IsActive:        true,
	}
	require.NoError(t, repo.CreateMCPServer(ctx, srv))

	require.NoError(t, repo.UpsertMCPTools(ctx, srv.ID, srv.OrgID, []*domain.MCPTool{
		{
			ID:          "tool_conf_echo",
			ServerID:    srv.ID,
			OrgID:       srv.OrgID,
			Name:        "echo_msg",
			Description: "Echoes the supplied message",
			InputSchema: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"message": map[string]any{"type": "string"},
				},
				"required": []string{"message"},
			},
			IsActive: true,
		},
	}))

	idCtx := &domain.IdentityContext{
		OrgID:                "org_conf",
		KeyAllowedMCPServers: []string{"*"},
	}

	return hub, repo, idCtx, srv, mockUpstream.Close
}

func TestAllOfficialMCPSpecReleasesSchemaConformance(t *testing.T) {
	hub, _, idCtx, _, cleanup := setupConformanceHub(t, func(w http.ResponseWriter, r *http.Request) {
		var req JSONRPCRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		switch req.Method {
		case "tools/call":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0",
				"id":      req.ID,
				"result": map[string]any{
					"content": []map[string]any{
						{"type": "text", "text": "hello schema conformance"},
					},
					"isError": false,
				},
			})
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0",
				"id":      req.ID,
				"result":  map[string]any{},
			})
		}
	})
	defer cleanup()

	ctx := t.Context()

	for _, info := range spec.SupportedSpecs() {
		t.Run(info.Version, func(t *testing.T) {
			hub.SetRuntimeSettings(domain.MCPRuntimeSettings{
				ActiveProtocolVersion:  info.Version,
				StrictSchemaValidation: true,
			})
			assert.Equal(t, info.Version, hub.ActiveSpec())

			meta := map[string]any{}
			if info.RequiresMirroredHeaders {
				meta["io.modelcontextprotocol/protocolVersion"] = info.Version
				meta["io.modelcontextprotocol/clientCapabilities"] = map[string]any{}
			}

			// 1. Validate discovery / initialization payload & response against compiled official schema.yaml
			if info.SupportsServerDiscover {
				discReq, err := json.Marshal(map[string]any{
					"jsonrpc": "2.0",
					"id":      1,
					"method":  "server/discover",
					"params": map[string]any{
						"_meta": meta,
					},
				})
				require.NoError(t, err)
				require.NoError(t, spec.ValidateDefinition(info.Version, "ClientRequest", discReq))

				httpReq := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(string(discReq)))
				httpReq.Header.Set("MCP-Protocol-Version", info.Version)
				httpReq.Header.Set("Mcp-Method", "server/discover")

				res, dispErr := hub.DispatchHTTP(ctx, idCtx, "hub", "", httpReq, discReq)
				require.NoError(t, dispErr)
				require.Equal(t, http.StatusOK, res.HTTPStatus)
				require.NotNil(t, res.SingleResponse)
				require.Nil(t, res.SingleResponse.Error)

				resBytes, err := json.Marshal(res.SingleResponse.Result)
				require.NoError(t, err)
				require.NoError(t, spec.ValidateDefinition(info.Version, "DiscoverResult", resBytes))
			}

			if info.RequiresInitialize {
				initReq, err := json.Marshal(map[string]any{
					"jsonrpc": "2.0",
					"id":      1,
					"method":  "initialize",
					"params": map[string]any{
						"protocolVersion": info.Version,
						"capabilities":    map[string]any{},
						"clientInfo":      map[string]any{"name": "conformance-suite", "version": "1.0.0"},
					},
				})
				require.NoError(t, err)
				require.NoError(t, spec.ValidateDefinition(info.Version, "ClientRequest", initReq))

				httpReq := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(string(initReq)))
				res, dispErr := hub.DispatchHTTP(ctx, idCtx, "hub", "", httpReq, initReq)
				require.NoError(t, dispErr)
				require.Equal(t, http.StatusOK, res.HTTPStatus)
				require.NotNil(t, res.SingleResponse)
				require.Nil(t, res.SingleResponse.Error)

				resBytes, err := json.Marshal(res.SingleResponse.Result)
				require.NoError(t, err)
				require.NoError(t, spec.ValidateDefinition(info.Version, "InitializeResult", resBytes))
			}

			// 2. Validate tools/list payload & ListToolsResult against compiled official schema.yaml
			listParams := map[string]any{}
			if len(meta) > 0 {
				listParams["_meta"] = meta
			}
			listReq, err := json.Marshal(map[string]any{
				"jsonrpc": "2.0",
				"id":      2,
				"method":  "tools/list",
				"params":  listParams,
			})
			require.NoError(t, err)
			require.NoError(t, spec.ValidateDefinition(info.Version, "ClientRequest", listReq))

			listHTTPReq := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(string(listReq)))
			if info.Version != domain.MCPProtocolVersion20241105 {
				listHTTPReq.Header.Set("MCP-Protocol-Version", info.Version)
			}
			if info.RequiresMirroredHeaders {
				listHTTPReq.Header.Set("Mcp-Method", "tools/list")
			}

			listRes, dispErr := hub.DispatchHTTP(ctx, idCtx, "hub", "", listHTTPReq, listReq)
			require.NoError(t, dispErr)
			require.Equal(t, http.StatusOK, listRes.HTTPStatus)
			require.NotNil(t, listRes.SingleResponse)
			require.Nil(t, listRes.SingleResponse.Error)

			listResBytes, err := json.Marshal(listRes.SingleResponse.Result)
			require.NoError(t, err)
			require.NoError(t, spec.ValidateDefinition(info.Version, "ListToolsResult", listResBytes))

			// 3. Validate tools/call payload & CallToolResult against compiled official schema.yaml
			callParams := map[string]any{
				"name":      "echo_msg",
				"arguments": map[string]any{"message": "ping"},
			}
			if len(meta) > 0 {
				callParams["_meta"] = meta
			}
			callReq, err := json.Marshal(map[string]any{
				"jsonrpc": "2.0",
				"id":      3,
				"method":  "tools/call",
				"params":  callParams,
			})
			require.NoError(t, err)
			require.NoError(t, spec.ValidateDefinition(info.Version, "ClientRequest", callReq))

			callHTTPReq := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(string(callReq)))
			if info.Version != domain.MCPProtocolVersion20241105 {
				callHTTPReq.Header.Set("MCP-Protocol-Version", info.Version)
			}
			if info.RequiresMirroredHeaders {
				callHTTPReq.Header.Set("Mcp-Method", "tools/call")
				callHTTPReq.Header.Set("Mcp-Name", "echo_msg")
			}

			callRes, dispErr := hub.DispatchHTTP(ctx, idCtx, "hub", "", callHTTPReq, callReq)
			require.NoError(t, dispErr)
			require.Equal(t, http.StatusOK, callRes.HTTPStatus)
			require.NotNil(t, callRes.SingleResponse)
			require.Nil(t, callRes.SingleResponse.Error)

			callResBytes, err := json.Marshal(callRes.SingleResponse.Result)
			require.NoError(t, err)
			require.NoError(t, spec.ValidateDefinition(info.Version, "CallToolResult", callResBytes))
		})
	}
}

func TestSpecProfileHTTPStatusBatchingAndStrictValidation(t *testing.T) {
	hub, _, idCtx, _, cleanup := setupConformanceHub(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "result": map[string]any{}})
	})
	defer cleanup()

	ctx := t.Context()

	// 1. 2025-03-26 supports batching; 2025-06-18 and later reject batch arrays.
	hub.SetRuntimeSettings(domain.MCPRuntimeSettings{ActiveProtocolVersion: domain.MCPProtocolVersion20250326})
	batchBody := []byte(`[{"jsonrpc":"2.0","id":1,"method":"ping"},{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}]`)
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	res, err := hub.DispatchHTTP(ctx, idCtx, "hub", "", req, batchBody)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, res.HTTPStatus)
	assert.True(t, res.IsBatch)
	assert.Len(t, res.BatchResponses, 2)

	hub.SetRuntimeSettings(domain.MCPRuntimeSettings{ActiveProtocolVersion: domain.MCPProtocolVersion20250618})
	res, err = hub.DispatchHTTP(ctx, idCtx, "hub", "", req, batchBody)
	require.NoError(t, err)
	require.NotNil(t, res.SingleResponse)
	require.NotNil(t, res.SingleResponse.Error)
	assert.Equal(t, CodeInvalidRequest, res.SingleResponse.Error.Code)

	// 2. 2026-07-28 mirrored headers & HTTP 400 status codes on -32020, -32021, -32022
	hub.SetRuntimeSettings(domain.MCPRuntimeSettings{
		ActiveProtocolVersion:  domain.MCPProtocolVersion20260728,
		StrictSchemaValidation: true,
	})
	profile := hub.ActiveProfile()

	badVerReq := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	badVerReq.Header.Set("MCP-Protocol-Version", "2024-11-05")
	badVerBody := []byte(`{"jsonrpc":"2.0","id":10,"method":"server/discover","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}`)
	res, err = hub.DispatchHTTP(ctx, idCtx, "hub", "", badVerReq, badVerBody)
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, res.HTTPStatus)
	require.NotNil(t, res.SingleResponse)
	require.NotNil(t, res.SingleResponse.Error)
	assert.Equal(t, CodeUnsupportedProtocolVersion, res.SingleResponse.Error.Code)

	mismatchHdrReq := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	mismatchHdrReq.Header.Set("MCP-Protocol-Version", domain.MCPProtocolVersion20260728)
	mismatchHdrReq.Header.Set("Mcp-Method", "tools/list")
	res, err = hub.DispatchHTTP(ctx, idCtx, "hub", "", mismatchHdrReq, badVerBody)
	require.NoError(t, err)
	assert.Equal(t, http.StatusBadRequest, res.HTTPStatus)
	require.NotNil(t, res.SingleResponse)
	require.NotNil(t, res.SingleResponse.Error)
	assert.Equal(t, CodeHeaderMismatch, res.SingleResponse.Error.Code)

	assert.Equal(t, http.StatusBadRequest, profile.HTTPStatusForResponse(false, &JSONRPCResponse{
		Error: &JSONRPCError{Code: CodeCapabilityNotSupported},
	}))

	// 3. Strict schema check rejects 2026-07-28 tools/list missing required _meta
	strictReq := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	strictReq.Header.Set("MCP-Protocol-Version", domain.MCPProtocolVersion20260728)
	strictReq.Header.Set("Mcp-Method", "tools/list")
	res, err = hub.DispatchHTTP(ctx, idCtx, "hub", "", strictReq, []byte(`{"jsonrpc":"2.0","id":11,"method":"tools/list","params":{}}`))
	require.NoError(t, err)
	require.NotNil(t, res.SingleResponse)
	require.NotNil(t, res.SingleResponse.Error)
	assert.Equal(t, CodeInvalidParams, res.SingleResponse.Error.Code)

	// 4. 2026-07-28 subscriptions/listen dispatches to SubscriptionReq
	subBody := []byte(`{"jsonrpc":"2.0","id":"sub_dispatch","method":"subscriptions/listen","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}},"notifications":{"toolsListChanged":true}}}`)
	subReq := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	subReq.Header.Set("MCP-Protocol-Version", domain.MCPProtocolVersion20260728)
	subReq.Header.Set("Mcp-Method", "subscriptions/listen")
	res, err = hub.DispatchHTTP(ctx, idCtx, "hub", "", subReq, subBody)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, res.HTTPStatus)
	require.NotNil(t, res.SubscriptionReq)
	assert.Equal(t, "subscriptions/listen", res.SubscriptionReq.Method)

	// 5. Notification HTTP status: 202 Accepted in >=2025-03-26 vs 200 OK in 2024-11-05
	assert.Equal(t, http.StatusAccepted, profile.HTTPStatusForResponse(true, nil))
	p2024, err := ProfileForVersion(domain.MCPProtocolVersion20241105)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, p2024.HTTPStatusForResponse(true, nil))
}

func TestCrossVersionGatewayToUpstreamBridging(t *testing.T) {
	var seenMethods []string
	var seenProtoHeader string
	hub, repo, idCtx, srv, cleanup := setupConformanceHub(t, func(w http.ResponseWriter, r *http.Request) {
		seenProtoHeader = r.Header.Get("MCP-Protocol-Version")
		var req JSONRPCRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		seenMethods = append(seenMethods, req.Method)
		w.Header().Set("Content-Type", "application/json")
		switch req.Method {
		case "tools/call":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0",
				"id":      req.ID,
				"result": map[string]any{
					"content": []map[string]any{{"type": "text", "text": "bridged from 2025-11-25"}},
				},
			})
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": req.ID, "result": map[string]any{}})
		}
	})
	defer cleanup()

	ctx := t.Context()
	// Re-pin the upstream server to 2025-11-25 while Gateway ingress stays on 2026-07-28.
	srv.ProtocolVersion = domain.MCPProtocolVersion20251125
	require.NoError(t, repo.UpdateMCPServer(ctx, srv))

	hub.SetRuntimeSettings(domain.MCPRuntimeSettings{
		ActiveProtocolVersion:  domain.MCPProtocolVersion20260728,
		StrictSchemaValidation: true,
	})

	callBody, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      99,
		"method":  "tools/call",
		"params": map[string]any{
			"_meta": map[string]any{
				"io.modelcontextprotocol/protocolVersion":    domain.MCPProtocolVersion20260728,
				"io.modelcontextprotocol/clientCapabilities": map[string]any{},
			},
			"name":      "echo_msg",
			"arguments": map[string]any{"message": "bridge-test"},
		},
	})
	require.NoError(t, err)

	httpReq := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(string(callBody)))
	httpReq.Header.Set("MCP-Protocol-Version", domain.MCPProtocolVersion20260728)
	httpReq.Header.Set("Mcp-Method", "tools/call")
	httpReq.Header.Set("Mcp-Name", "echo_msg")

	res, err := hub.DispatchHTTP(ctx, idCtx, "hub", "", httpReq, callBody)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, res.HTTPStatus)
	require.NotNil(t, res.SingleResponse)
	require.Nil(t, res.SingleResponse.Error)

	resBytes, err := json.Marshal(res.SingleResponse.Result)
	require.NoError(t, err)
	require.NoError(t, spec.ValidateDefinition(domain.MCPProtocolVersion20260728, "CallToolResult", resBytes))
	assert.Equal(t, domain.MCPProtocolVersion20251125, seenProtoHeader)
	assert.Contains(t, seenMethods, "tools/call")
}

func TestMCP2026SubscriptionsListenStreamConformance(t *testing.T) {
	sm := NewSubscriptionManager(nil)
	rec := httptest.NewRecorder()

	ctx, cancel := context.WithCancel(t.Context())
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil).WithContext(ctx)

	rpcReq := &JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      "sub_42",
		Method:  "subscriptions/listen",
		Params:  json.RawMessage(`{"notifications":{"toolsListChanged":true}}`),
	}
	idCtx := &domain.IdentityContext{OrgID: "org_conf"}

	done := make(chan struct{})
	go func() {
		defer close(done)
		sm.Serve2026SubscriptionStream(rec, req, idCtx, rpcReq)
	}()

	time.Sleep(30 * time.Millisecond)
	cancel()
	<-done

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "text/event-stream")

	scanner := bufio.NewScanner(strings.NewReader(rec.Body.String()))
	var firstData string
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "data: ") {
			firstData = strings.TrimPrefix(line, "data: ")
			break
		}
	}
	require.NotEmpty(t, firstData)

	require.NoError(t, spec.ValidateDefinition(domain.MCPProtocolVersion20260728, "SubscriptionsAcknowledgedNotification", []byte(firstData)))
	assert.Contains(t, firstData, `"io.modelcontextprotocol/subscriptionId":"sub_42"`)
}
