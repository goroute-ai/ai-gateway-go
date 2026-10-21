package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/auth/upstream"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// 1. Numeric Precision & Normalization Tests
func TestNumericPrecisionAndNormalization(t *testing.T) {
	// 42.0 == 42
	assert.True(t, CompareNumericValues("42.0", "42"))
	assert.True(t, CompareNumericValues("42.00000", "42"))

	// 1e3 == 1000, 1.5e2 == 150
	assert.True(t, CompareNumericValues("1e3", "1000"))
	assert.True(t, CompareNumericValues("1.5e2", "150"))
	assert.True(t, CompareNumericValues("-2.5e1", "-25"))

	// Large numbers > 2^53 (precision limit of IEEE 754 float64)
	// 2^53 = 9007199254740992
	// float64 cannot distinguish 9007199254740992 and 9007199254740993
	n1 := "9007199254740992"
	n2 := "9007199254740993"
	assert.False(t, CompareNumericValues(n1, n2), "arbitrary precision must distinguish consecutive integers beyond 2^53")
	assert.True(t, CompareNumericValues(n1, "9007199254740992.0"))

	// Very large 100-digit integer
	bigIntA := "12345678901234567890123456789012345678901234567890"
	bigIntB := "12345678901234567890123456789012345678901234567891"
	assert.True(t, CompareNumericValues(bigIntA, bigIntA+".0"))
	assert.False(t, CompareNumericValues(bigIntA, bigIntB))

	// Rejection of invalid / dangerous representations
	_, err := CanonicalDecimal("NaN")
	assert.Error(t, err)
	_, err = CanonicalDecimal("Infinity")
	assert.Error(t, err)
	_, err = CanonicalDecimal("-Inf")
	assert.Error(t, err)

	// Rejection of disallowed leading zeros in integer part
	_, err = CanonicalDecimal("01")
	assert.Error(t, err)
	_, err = CanonicalDecimal("-05")
	assert.Error(t, err)

	// Allowed valid zeros
	cZero, err := CanonicalDecimal("0")
	assert.NoError(t, err)
	assert.Equal(t, "0", cZero)

	cZeroFrac, err := CanonicalDecimal("0.123")
	assert.NoError(t, err)
	assert.Equal(t, "0.123", cZeroFrac)
}

// 2. Base64 Sentinel Framing Tests
func TestBase64SentinelFraming(t *testing.T) {
	// Plain ASCII without sentinel
	decoded, err := DecodeBase64Sentinel("hello world")
	assert.NoError(t, err)
	assert.Equal(t, "hello world", decoded)

	// Exact case-sensitive sentinel
	framed := "=?base64?VGhpcyBpcyBhIHRlc3Qh?="
	decoded, err = DecodeBase64Sentinel(framed)
	assert.NoError(t, err)
	assert.Equal(t, "This is a test!", decoded)

	// UTF-8 content via sentinel
	utf8Text := "Hello 🌍 世界"
	encoded := EncodeBase64Sentinel(utf8Text)
	assert.Contains(t, encoded, "=?base64?")
	assert.True(t, stringsHasSuffix(encoded, "?="))

	decodedUTF8, err := DecodeBase64Sentinel(encoded)
	assert.NoError(t, err)
	assert.Equal(t, utf8Text, decodedUTF8)

	// Rejection of raw non-ASCII bytes without sentinel
	_, err = DecodeBase64Sentinel("Unescaped non-ascii \x80\xFF")
	assert.Error(t, err, "raw non-ASCII bytes without sentinel must be rejected")
}

func stringsHasSuffix(s, suffix string) bool {
	return len(s) >= len(suffix) && s[len(s)-len(suffix):] == suffix
}

// 3. Mirrored Header Parameter Validation Tests
func TestMirroredHeaderParameterValidation(t *testing.T) {
	req := &JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      "req_1",
		Method:  "tools/call",
		Params: json.RawMessage(`{
			"name": "calculate_tax",
			"arguments": {
				"amount": 9007199254740993,
				"country": "US",
				"exempt": false
			}
		}`),
	}

	// Case 1: Matching headers
	httpReq := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	httpReq.Header.Set("Mcp-Name", "calculate_tax")
	httpReq.Header.Set("Mcp-Param-amount", "9007199254740993.0")
	httpReq.Header.Set("Mcp-Param-country", "US")
	httpReq.Header.Set("Mcp-Param-exempt", "false")

	err := ValidateMirroredHeaderParameters(httpReq, req)
	assert.Nil(t, err, "matching mirrored parameters must pass")

	// Case 2: Mismatch on tool name
	badNameReq := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	badNameReq.Header.Set("Mcp-Name", "other_tool")
	err = ValidateMirroredHeaderParameters(badNameReq, req)
	require.NotNil(t, err)
	assert.Equal(t, CodeHeaderMismatch, err.Code)

	// Case 3: Numeric mismatch (> 2^53 precision difference)
	badNumReq := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	badNumReq.Header.Set("Mcp-Param-amount", "9007199254740992")
	err = ValidateMirroredHeaderParameters(badNumReq, req)
	require.NotNil(t, err)
	assert.Equal(t, CodeHeaderMismatch, err.Code)

	// Case 4: Param present in header but missing from body
	missingParamReq := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	missingParamReq.Header.Set("Mcp-Param-currency", "USD")
	err = ValidateMirroredHeaderParameters(missingParamReq, req)
	require.NotNil(t, err)
	assert.Equal(t, CodeHeaderMismatch, err.Code)
}

// 4. HTTP Transport Constraints & Negotiation Tests
func TestHTTPTransportConstraints(t *testing.T) {
	// Rejection of GET method (405)
	getReq := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	status, err := ValidateHTTPRequest(getReq, nil)
	assert.Equal(t, http.StatusMethodNotAllowed, status)
	assert.Error(t, err)

	// Rejection of DELETE method (405)
	delReq := httptest.NewRequest(http.MethodDelete, "/mcp", nil)
	status, err = ValidateHTTPRequest(delReq, nil)
	assert.Equal(t, http.StatusMethodNotAllowed, status)
	assert.Error(t, err)

	// Rejection of unacceptable Accept header (406)
	badAcceptReq := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	badAcceptReq.Header.Set("Accept", "text/plain")
	status, err = ValidateHTTPRequest(badAcceptReq, nil)
	assert.Equal(t, http.StatusNotAcceptable, status)
	assert.Error(t, err)

	// Valid Accept headers
	validAcceptReq := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	validAcceptReq.Header.Set("Accept", "application/json")
	status, err = ValidateHTTPRequest(validAcceptReq, nil)
	assert.Equal(t, http.StatusOK, status)
	assert.NoError(t, err)

	validMCPReq := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	validMCPReq.Header.Set("Accept", "application/mcp+json")
	status, err = ValidateHTTPRequest(validMCPReq, nil)
	assert.Equal(t, http.StatusOK, status)
	assert.NoError(t, err)

	// Origin check
	originReq := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	originReq.Header.Set("Origin", "https://malicious.com")
	status, err = ValidateHTTPRequest(originReq, []string{"https://app.example.com"})
	assert.Equal(t, http.StatusForbidden, status)
	assert.Error(t, err)

	// Protocol version check
	assert.Nil(t, ValidateProtocolVersion("2026-07-28"))
	assert.Nil(t, ValidateProtocolVersion("2025-11-25"))
	assert.Nil(t, ValidateProtocolVersion(""))
	badVer := ValidateProtocolVersion("2024-11-05")
	require.NotNil(t, badVer)
	assert.Equal(t, CodeUnsupportedProtocolVersion, badVer.Code)

	// Client capability check
	capErr := ValidateClientCapabilities([]string{"sampling", "roots"}, map[string]any{"sampling": map[string]any{}})
	require.NotNil(t, capErr)
	assert.Equal(t, CodeCapabilityNotSupported, capErr.Code)

	okCap := ValidateClientCapabilities([]string{"sampling"}, map[string]any{"sampling": map[string]any{}})
	assert.Nil(t, okCap)
}

// 5. 2025 Session Expiry & Principal Digest Isolation Tests
func TestStreamableHTTP2025SessionSecurity(t *testing.T) {
	ctx := context.Background()

	netPolicy, err := network.NewPolicy(config.OutboundSSRFConfig{
		AllowPrivateNetworks: true,
		AllowInsecureHTTP:    true,
	})
	require.NoError(t, err)

	var sessionActive bool = true

	// Mock upstream 2025 server
	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientSess := r.Header.Get("Mcp-Session-Id")

		// If session is expired on upstream pod, return 404
		if clientSess == "upstream_sess_1" && !sessionActive {
			w.WriteHeader(http.StatusNotFound)
			return
		}

		// Initialize handshake
		if clientSess == "" {
			w.Header().Set("Mcp-Session-Id", "upstream_sess_1")
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      1,
				Result:  map[string]any{"protocolVersion": "2025-11-25"},
			})
			return
		}

		// Subsequent call with active session
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      2,
			Result:  map[string]any{"status": "ok"},
		})
	}))
	defer mockUpstream.Close()

	srv := &domain.MCPServer{
		ID:              "srv_2025",
		OrgID:           "org_test",
		Name:            "Legacy 2025 Server",
		Slug:            "legacy-2025",
		ProtocolVersion: domain.MCPProtocolVersion2025,
		TransportType:   domain.MCPTransportStreamableHTTP,
		EndpointURL:     mockUpstream.URL,
		AuthType:        "none",
		IsActive:        true,
	}

	adapter := NewStreamableHTTP2025Adapter(netPolicy, nil)
	adapter.sessionTTL = 2 * time.Second

	callerA := &upstream.UpstreamAuthContext{
		ServerID:          srv.ID,
		CallingOrgID:      "org_test",
		CallingUserID:     "user_100",
		CallingVirtualKey: "sk-gw-key-a",
	}

	callerB := &upstream.UpstreamAuthContext{
		ServerID:          srv.ID,
		CallingOrgID:      "org_test",
		CallingUserID:     "user_200",
		CallingVirtualKey: "sk-gw-key-b",
	}

	// 1. Initial Handshake from Caller A -> Gateway generates and tracks session
	initReq := []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}`)
	initResp, initHeaders, err := adapter.RoundTrip(ctx, srv, nil, callerA, initReq, http.Header{})
	require.NoError(t, err)
	require.NotNil(t, initResp)
	gwSessionID := initHeaders.Get("Mcp-Session-Id")
	require.NotEmpty(t, gwSessionID, "Gateway must expose gateway-scoped Mcp-Session-Id")
	assert.NotEqual(t, "upstream_sess_1", gwSessionID, "Gateway must not leak raw upstream session id")

	// 2. Caller A sends subsequent request with session ID -> succeeds
	callReq := []byte(`{"jsonrpc":"2.0","id":2,"method":"ping"}`)
	headers := http.Header{}
	headers.Set("Mcp-Session-Id", gwSessionID)
	callResp, _, err := adapter.RoundTrip(ctx, srv, nil, callerA, callReq, headers)
	require.NoError(t, err)
	require.NotNil(t, callResp)
	assert.Nil(t, callResp.Error)

	// 3. Caller B attempts to use Caller A's session -> Rejected (Principal Digest Mismatch)
	_, _, rpcErr := adapter.RoundTrip(ctx, srv, nil, callerB, callReq, headers)
	require.NotNil(t, rpcErr)
	var jsonRPCErr *JSONRPCError
	require.True(t, errors.As(rpcErr, &jsonRPCErr))
	assert.Equal(t, CodeInvalidRequest, jsonRPCErr.Code)
	assert.Contains(t, jsonRPCErr.Message, "belongs to a different caller principal")

	// 4. Upstream expires session (returns 404) -> Gateway deletes session and returns session_expired error (-32025)
	sessionActive = false
	_, _, rpcErr = adapter.RoundTrip(ctx, srv, nil, callerA, callReq, headers)
	require.NotNil(t, rpcErr)
	require.True(t, errors.As(rpcErr, &jsonRPCErr))
	assert.Equal(t, CodeSessionExpired, jsonRPCErr.Code)
	assert.Contains(t, jsonRPCErr.Message, "session_expired")
}

// 6. Hub Dispatch: Virtual Hub Aggregation, Scoped Routes & Toolsets
func TestMCPHubDispatch(t *testing.T) {
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

	// Mock upstream MCP 2026 server
	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req JSONRPCRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: map[string]any{
				"content": []map[string]any{
					{"type": "text", "text": "mock tool execution result"},
				},
			},
		})
	}))
	defer mockUpstream.Close()

	// Seed MCPServer
	srv := &domain.MCPServer{
		ID:              "mcp_srv_1",
		OrgID:           "org_test",
		Name:            "Enterprise Search",
		Slug:            "search-engine",
		ProtocolVersion: domain.MCPProtocolVersion2026,
		TransportType:   domain.MCPTransportStreamableHTTP,
		EndpointURL:     mockUpstream.URL,
		AuthType:        domain.MCPAuthStatic,
		IsActive:        true,
	}
	require.NoError(t, repo.CreateMCPServer(ctx, srv))

	// Seed MCPTool
	tool1 := &domain.MCPTool{
		ID:          "tool_search_1",
		ServerID:    srv.ID,
		OrgID:       "org_test",
		Name:        "web_search",
		Description: "Perform web search",
		InputSchema: map[string]any{"type": "object"},
		ToolDefHash: "sha256_mock_hash",
		IsActive:    true,
	}
	require.NoError(t, repo.UpsertMCPTools(ctx, srv.ID, srv.OrgID, []*domain.MCPTool{tool1}))

	// Seed MCPToolset
	ts := &domain.MCPToolset{
		ID:       "ts_1",
		OrgID:    "org_test",
		Name:     "Research Kit",
		Slug:     "research-kit",
		ToolIDs:  []string{tool1.ID},
		IsActive: true,
	}
	require.NoError(t, repo.CreateMCPToolset(ctx, ts))

	dispatcher := NewTransportDispatcher(netPolicy, storage.NewRedisFabric("localhost:6379", "", 0), false)
	authResolver := NewAuthResolver(vault, netPolicy)
	hub := NewHub(repo, vault, rbac, dispatcher, authResolver)

	idCtx := &domain.IdentityContext{
		KeyPrefix: "sk-gw-test-admin",
		OrgID:     "org_test",
	}

	// 1. Virtual Hub tools/list aggregation
	listReq := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	resp, _, err := hub.DispatchVirtualHub(ctx, idCtx, listReq, http.Header{})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Nil(t, resp.Error)

	resultMap, ok := resp.Result.(map[string]any)
	require.True(t, ok)
	toolsList, ok := resultMap["tools"].([]map[string]any)
	require.True(t, ok)
	assert.Len(t, toolsList, 1)
	assert.Equal(t, "web_search", toolsList[0]["name"])

	// Check _meta outcomes
	meta, ok := resultMap["_meta"].(map[string]any)
	require.True(t, ok)
	outcomes, ok := meta["goroute.ai/server_outcomes"].(map[string]string)
	require.True(t, ok)
	assert.Equal(t, "ok: 1 tools", outcomes["search-engine"])

	// 2. Scoped server tool execution
	callReq := []byte(`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"web_search","arguments":{"query":"GoRoute AI"}}}`)
	resp, _, err = hub.DispatchScopedServer(ctx, idCtx, "search-engine", callReq, http.Header{})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Nil(t, resp.Error)

	// 3. Curated Toolset tools/list
	resp, _, err = hub.DispatchToolset(ctx, idCtx, "research-kit", listReq, http.Header{})
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Nil(t, resp.Error)
	tsMap := resp.Result.(map[string]any)
	tsTools := tsMap["tools"].([]map[string]any)
	assert.Len(t, tsTools, 1)
}

// 7. DenyAll-Default RBAC Tests on MCP Routes
func TestMCPRBACRestrictions(t *testing.T) {
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

	srv := &domain.MCPServer{
		ID:              "mcp_srv_restricted",
		OrgID:           "org_test",
		Name:            "Sensitive Data",
		Slug:            "sensitive-data-server",
		ProtocolVersion: domain.MCPProtocolVersion2026,
		TransportType:   domain.MCPTransportStreamableHTTP,
		EndpointURL:     "https://internal.bank/mcp",
		AuthType:        "none",
		IsActive:        true,
	}
	require.NoError(t, repo.CreateMCPServer(ctx, srv))

	dispatcher := NewTransportDispatcher(netPolicy, storage.NewRedisFabric("localhost:6379", "", 0), false)
	authResolver := NewAuthResolver(vault, netPolicy)
	hub := NewHub(repo, vault, rbac, dispatcher, authResolver)

	// Case 1: Virtual Key with DenyAll default (explicit empty slice)
	idCtxDenyAll := &domain.IdentityContext{
		KeyPrefix:            "sk-gw-restricted-key",
		OrgID:                "org_test",
		KeyAllowedMCPServers: []string{}, // DenyAll
	}

	callReq := []byte(`{"jsonrpc":"2.0","id":10,"method":"tools/list"}`)
	resp, _, err := hub.DispatchScopedServer(ctx, idCtxDenyAll, "sensitive-data-server", callReq, http.Header{})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotNil(t, resp.Error)
	assert.Contains(t, resp.Error.Message, "Forbidden")

	// Case 2: Virtual Key with explicit server allowlist
	idCtxAllowed := &domain.IdentityContext{
		KeyPrefix:            "sk-gw-allowed-key",
		OrgID:                "org_test",
		KeyAllowedMCPServers: []string{"sensitive-data-server"},
	}
	errRbac := rbac.AuthorizeMCPServer(idCtxAllowed, "sensitive-data-server")
	assert.NoError(t, errRbac)
}
