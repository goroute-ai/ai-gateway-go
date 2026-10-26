package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/auth/upstream"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/guardrails"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

// Hub orchestrates multi-server MCP routing, tool aggregation, toolsets, and security enforcement.
type Hub struct {
	repo          storage.Repository
	vault         *auth.Vault
	rbac          *auth.RBACEngine
	dispatcher    *TransportDispatcher
	authResolver  *AuthResolver
	cache         *MCPCache
	mrtr          *MRTRManager
	subs          *SubscriptionManager
	guardrails    *guardrails.Engine
	spendRecorder SpendRecorder
	progressive   *ProgressiveDiscoveryManager
}

func (h *Hub) SetCache(c *MCPCache)                                   { h.cache = c }
func (h *Hub) SetMRTR(m *MRTRManager)                                 { h.mrtr = m }
func (h *Hub) SetSubscriptions(s *SubscriptionManager)                { h.subs = s }
func (h *Hub) SetGuardrails(g *guardrails.Engine)                     { h.guardrails = g }
func (h *Hub) SetSpendRecorder(sr SpendRecorder)                      { h.spendRecorder = sr }
func (h *Hub) SetProgressiveDiscovery(p *ProgressiveDiscoveryManager) { h.progressive = p }
func (h *Hub) Cache() *MCPCache                                       { return h.cache }
func (h *Hub) MRTR() *MRTRManager                                     { return h.mrtr }
func (h *Hub) Subscriptions() *SubscriptionManager                    { return h.subs }
func (h *Hub) Guardrails() *guardrails.Engine                         { return h.guardrails }
func (h *Hub) SpendRecorder() SpendRecorder                           { return h.spendRecorder }
func (h *Hub) ProgressiveDiscovery() *ProgressiveDiscoveryManager     { return h.progressive }
func (h *Hub) Dispatcher() *TransportDispatcher                       { return h.dispatcher }

// NewHub constructs a new MCP Hub instance.
func NewHub(
	repo storage.Repository,
	vault *auth.Vault,
	rbac *auth.RBACEngine,
	dispatcher *TransportDispatcher,
	authResolver *AuthResolver,
) *Hub {
	return &Hub{
		repo:         repo,
		vault:        vault,
		rbac:         rbac,
		dispatcher:   dispatcher,
		authResolver: authResolver,
		progressive:  NewProgressiveDiscoveryManager(repo, nil, HandleTTL),
	}
}

// ListTools returns the list of MCP tools available to the caller under their authorized scope.
// If serverSlug is non-empty, only tools on that specific server are returned.
// If serverSlug is empty, tools from all authorized, active servers are returned.
func (h *Hub) ListTools(ctx context.Context, idCtx *domain.IdentityContext, serverSlug string) ([]domain.MCPTool, error) {
	orgID := ""
	if idCtx != nil {
		orgID = idCtx.OrgID
	}

	serverSlug = strings.TrimSpace(serverSlug)
	if serverSlug != "" {
		server, err := h.repo.GetMCPServerBySlug(ctx, orgID, serverSlug)
		if err != nil || !server.IsActive {
			return nil, fmt.Errorf("mcp server %q not found or inactive", serverSlug)
		}
		if h.rbac != nil {
			if err := h.rbac.AuthorizeMCPServer(idCtx, server.Slug); err != nil {
				return nil, err
			}
		}
		tools, err := h.repo.ListMCPTools(ctx, server.ID)
		if err != nil {
			return nil, err
		}
		var activeTools []domain.MCPTool
		for _, t := range tools {
			if t != nil && t.IsActive {
				activeTools = append(activeTools, *t)
			}
		}
		return activeTools, nil
	}

	// Aggregate tools across all active, authorized servers in org
	servers, err := h.repo.ListMCPServers(ctx, orgID)
	if err != nil {
		return nil, fmt.Errorf("failed to list mcp servers: %w", err)
	}

	var aggregatedTools []domain.MCPTool
	for _, s := range servers {
		if !s.IsActive {
			continue
		}
		if h.rbac != nil && h.rbac.AuthorizeMCPServer(idCtx, s.Slug) != nil {
			continue
		}
		tools, err := h.repo.ListMCPTools(ctx, s.ID)
		if err != nil {
			continue
		}
		for _, t := range tools {
			if t != nil && t.IsActive {
				aggregatedTools = append(aggregatedTools, *t)
			}
		}
	}
	return aggregatedTools, nil
}

// CallTool executes a tool call through the unified MCP pipeline:
// RBAC Check -> Tool Pinning Check -> Call Guardrail Scan -> Response Cache / MRTR ->
// Upstream Dispatcher -> Result Guardrail Scan -> FinOps Debit.
func (h *Hub) CallTool(ctx context.Context, idCtx *domain.IdentityContext, input ToolCallInput, meta CallMetadata) (*CallToolResponse, error) {
	if strings.TrimSpace(input.ToolName) == "" {
		return nil, errors.New("tool_name is required")
	}

	// 0. Meta-Tools Execution (search_tools, get_tool_schema)
	if input.ToolName == "search_tools" && h.progressive != nil {
		q, _ := input.Arguments["query"].(string)
		lim := 10
		if lFloat, ok := input.Arguments["limit"].(float64); ok && lFloat > 0 {
			lim = int(lFloat)
		}
		summaries, err := h.progressive.SearchTools(ctx, idCtx, q, lim)
		if err != nil {
			return nil, err
		}
		resJSON, _ := json.Marshal(summaries)
		return &CallToolResponse{
			Content: []ToolContent{{Type: "text", Text: string(resJSON)}},
			IsError: false,
		}, nil
	}
	if input.ToolName == "get_tool_schema" && h.progressive != nil {
		hdl, _ := input.Arguments["tool_handle"].(string)
		rec, tool, err := h.progressive.ResolveHandle(ctx, hdl)
		if err != nil {
			return &CallToolResponse{
				Content: []ToolContent{{Type: "text", Text: fmt.Sprintf(`{"error": %q}`, err.Error())}},
				IsError: true,
			}, nil
		}
		schemaJSON, _ := json.Marshal(map[string]any{
			"name":        tool.Name,
			"server_slug": rec.ServerSlug,
			"description": tool.Description,
			"inputSchema": tool.InputSchema,
			"tool_handle": rec.Handle,
		})
		return &CallToolResponse{
			Content: []ToolContent{{Type: "text", Text: string(schemaJSON)}},
			IsError: false,
		}, nil
	}

	orgID := ""
	if idCtx != nil {
		orgID = idCtx.OrgID
	}

	var targetServer *domain.MCPServer
	var targetTool *domain.MCPTool

	// 0b. Opaque Tool Handle Resolution (tool_hdl_...)
	if strings.HasPrefix(input.ToolName, HandlePrefix) && h.progressive != nil {
		rec, tool, err := h.progressive.ResolveHandle(ctx, input.ToolName)
		if err != nil {
			return nil, err
		}
		input.ToolName = rec.ToolName
		input.ServerSlug = rec.ServerSlug
		targetTool = tool
	}

	serverSlug := strings.TrimSpace(input.ServerSlug)
	if serverSlug != "" {
		server, err := h.repo.GetMCPServerBySlug(ctx, orgID, serverSlug)
		if err != nil || !server.IsActive {
			return nil, fmt.Errorf("mcp server %q not found or inactive", serverSlug)
		}
		if h.rbac != nil {
			if err := h.rbac.AuthorizeMCPServer(idCtx, server.Slug); err != nil {
				return nil, err
			}
		}
		targetServer = server

		tools, err := h.repo.ListMCPTools(ctx, server.ID)
		if err == nil {
			for _, t := range tools {
				if t != nil && t.Name == input.ToolName && t.IsActive {
					targetTool = t
					break
				}
			}
		}
	} else {
		// Unambiguous resolution across all authorized servers
		servers, err := h.repo.ListMCPServers(ctx, orgID)
		if err != nil {
			return nil, fmt.Errorf("failed to list mcp servers: %w", err)
		}

		var matchServers []*domain.MCPServer
		var matchTools []*domain.MCPTool

		for _, s := range servers {
			if !s.IsActive {
				continue
			}
			if h.rbac != nil && h.rbac.AuthorizeMCPServer(idCtx, s.Slug) != nil {
				continue
			}
			tools, err := h.repo.ListMCPTools(ctx, s.ID)
			if err != nil {
				continue
			}
			for _, t := range tools {
				if t != nil && t.Name == input.ToolName && t.IsActive {
					matchServers = append(matchServers, s)
					matchTools = append(matchTools, t)
					break
				}
			}
		}

		if len(matchServers) == 0 {
			return nil, fmt.Errorf("tool %q not found or caller not authorized", input.ToolName)
		}
		if len(matchServers) > 1 {
			var slugs []string
			for _, ms := range matchServers {
				slugs = append(slugs, ms.Slug)
			}
			return nil, &AmbiguousToolError{
				ToolName:        input.ToolName,
				MatchingServers: slugs,
			}
		}

		targetServer = matchServers[0]
		targetTool = matchTools[0]
	}

	// 1. Tool Pinning Check
	if targetServer.PinnedToolHash != "" && h.guardrails != nil && targetTool != nil {
		if err := h.guardrails.VerifyToolPinning(targetTool, targetServer.PinnedToolHash); err != nil {
			return nil, fmt.Errorf("tool pinning violation: %w", err)
		}
	}

	// 2. Call Guardrails Scan on arguments
	if h.guardrails != nil {
		if _, err := h.guardrails.EvaluateMCPToolCall(ctx, orgID, input.ToolName, input.Arguments); err != nil {
			return nil, fmt.Errorf("guardrail blocked tool call: %w", err)
		}
	}

	// 3. Cache check
	var cacheKey string
	if h.cache != nil {
		keyPrefix := ""
		if idCtx != nil {
			keyPrefix = idCtx.KeyPrefix
		}
		argsBytes, _ := json.Marshal(input.Arguments)
		cacheKey = h.cache.ComputeCacheKey(orgID, keyPrefix, targetServer.Slug, "tools/call:"+input.ToolName, argsBytes, targetServer.ConfigVersion)
		if cachedResp, ok := h.cache.Get(ctx, cacheKey); ok {
			callResp, err := extractCallToolResponse(cachedResp.Result)
			if err == nil {
				return callResp, nil
			}
		}
	}

	// 4. Resolve BYOK user credential if available
	var userCred *domain.MCPUserCredential
	if idCtx != nil && idCtx.UserID != "" {
		userCred, _ = h.repo.GetMCPUserCredential(ctx, targetServer.ID, idCtx.UserID)
	}

	// 5. Build transport headers & auth context
	reqHeaders := make(http.Header)
	if meta.CallerMetadata != nil {
		for k, v := range meta.CallerMetadata {
			reqHeaders.Set(k, v)
		}
	}

	teamID := ""
	userID := ""
	vkID := ""
	if idCtx != nil {
		teamID = idCtx.TeamID
		userID = idCtx.UserID
		vkID = idCtx.VirtualKeyID
	}

	authCtx := &upstream.UpstreamAuthContext{
		ServerID:          targetServer.ID,
		ServerSlug:        targetServer.Slug,
		TargetURL:         targetServer.EndpointURL,
		CallingOrgID:      orgID,
		CallingTeamID:     teamID,
		CallingUserID:     userID,
		CallingVirtualKey: vkID,
	}

	strat, extraHeaders := h.authResolver.ResolveStrategy(ctx, targetServer, userCred, reqHeaders)
	authCtx.ExtraHeaders = extraHeaders

	// 6. Upstream Dispatch
	reqID := meta.RequestID
	if reqID == "" {
		reqID = "req_" + uuid.NewString()
	}

	paramsMap := map[string]any{
		"name": input.ToolName,
	}
	if input.Arguments != nil {
		paramsMap["arguments"] = input.Arguments
	} else {
		paramsMap["arguments"] = map[string]any{}
	}
	paramsBytes, _ := json.Marshal(paramsMap)

	jsonRPCReq := JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      reqID,
		Method:  "tools/call",
		Params:  paramsBytes,
	}
	reqBodyBytes, _ := json.Marshal(jsonRPCReq)

	resp, _, err := h.dispatcher.Dispatch(ctx, targetServer, strat, authCtx, reqBodyBytes, reqHeaders)
	if err != nil {
		return nil, fmt.Errorf("upstream dispatch error: %w", err)
	}
	if resp == nil {
		return nil, errors.New("upstream returned empty response")
	}
	if resp.Error != nil {
		return nil, fmt.Errorf("upstream mcp error (%d): %s", resp.Error.Code, resp.Error.Message)
	}

	// 7. Output guardrail inspection and redaction on tool call result
	if h.guardrails != nil && resp.Result != nil {
		if _, redactedResult, err := h.guardrails.EvaluateMCPToolResult(ctx, orgID, resp.Result); err == nil {
			resp.Result = redactedResult
		}
	}

	// 8. Cache storage if response is valid and cacheable
	if cacheKey != "" && h.cache != nil && ShouldCache("tools/call", resp) {
		_ = h.cache.Set(ctx, cacheKey, resp, 5*time.Minute)
	}

	// 9. FinOps spend debit
	if h.spendRecorder != nil && targetTool != nil && targetTool.CostPerCallMicros > 0 {
		h.spendRecorder.Enqueue(domain.SpendEvent{
			ID:             "spend_" + uuid.NewString(),
			RequestID:      reqID,
			Protocol:       "mcp",
			ProtocolTarget: fmt.Sprintf("mcp:%s/%s", targetServer.Slug, targetTool.Name),
			OrgID:          orgID,
			TeamID:         teamID,
			UserID:         userID,
			VirtualKeyID:   vkID,
			Endpoint:       "/mcp",
			CostMicros:     targetTool.CostPerCallMicros,
			CreatedAt:      time.Now().UTC(),
		})
	}

	callResp, err := extractCallToolResponse(resp.Result)
	if err != nil {
		return nil, fmt.Errorf("failed to parse upstream tool result: %w", err)
	}
	return callResp, nil
}

// DispatchVirtualHub routes calls to the multi-server virtual hub (`POST /mcp`).
func (h *Hub) DispatchVirtualHub(
	ctx context.Context,
	idCtx *domain.IdentityContext,
	reqBody []byte,
	reqHeaders http.Header,
) (*JSONRPCResponse, http.Header, error) {
	var jsonReq JSONRPCRequest
	dec := json.NewDecoder(bytes.NewReader(reqBody))
	dec.UseNumber()
	if err := dec.Decode(&jsonReq); err != nil {
		return &JSONRPCResponse{
			JSONRPC: "2.0",
			Error: &JSONRPCError{
				Code:    CodeParseError,
				Message: fmt.Sprintf("invalid json-rpc: %v", err),
			},
		}, nil, nil
	}

	// Validate mirrored header parameters for tools/call
	if err := ValidateMirroredHeaderParameters(&http.Request{Header: reqHeaders}, &jsonReq); err != nil {
		return &JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      jsonReq.ID,
			Error:   err,
		}, nil, nil
	}

	switch jsonReq.Method {
	case "tools/list":
		return h.handleVirtualToolsList(ctx, idCtx, jsonReq.ID)
	case "tools/call":
		return h.handleVirtualToolsCall(ctx, idCtx, &jsonReq, reqBody, reqHeaders)
	case "ping":
		return &JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      jsonReq.ID,
			Result:  map[string]any{},
		}, nil, nil
	default:
		return &JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      jsonReq.ID,
			Error: &JSONRPCError{
				Code:    CodeMethodNotFound,
				Message: fmt.Sprintf("method %q not supported on virtual hub route; use scoped /mcp/{serverSlug}", jsonReq.Method),
			},
		}, nil, nil
	}
}

// DispatchScopedServer routes calls directly to a specific MCP server (`POST /mcp/{serverSlug}`).
func (h *Hub) DispatchScopedServer(
	ctx context.Context,
	idCtx *domain.IdentityContext,
	serverSlug string,
	reqBody []byte,
	reqHeaders http.Header,
) (*JSONRPCResponse, http.Header, error) {
	serverSlug = strings.TrimSpace(serverSlug)
	orgID := ""
	if idCtx != nil {
		orgID = idCtx.OrgID
	}

	server, err := h.repo.GetMCPServerBySlug(ctx, orgID, serverSlug)
	if err != nil || !server.IsActive {
		return &JSONRPCResponse{
			JSONRPC: "2.0",
			Error: &JSONRPCError{
				Code:    CodeInvalidRequest,
				Message: fmt.Sprintf("mcp server %q not found or inactive", serverSlug),
			},
		}, nil, nil
	}

	// RBAC Check
	if h.rbac != nil {
		if err := h.rbac.AuthorizeMCPServer(idCtx, serverSlug); err != nil {
			return &JSONRPCResponse{
				JSONRPC: "2.0",
				Error: &JSONRPCError{
					Code:    CodeInvalidRequest,
					Message: fmt.Sprintf("Forbidden: %v", err),
				},
			}, nil, nil
		}
	}

	// Validate JSON-RPC request and mirrored headers
	var jsonReq JSONRPCRequest
	dec := json.NewDecoder(bytes.NewReader(reqBody))
	dec.UseNumber()
	if err := dec.Decode(&jsonReq); err != nil {
		return &JSONRPCResponse{
			JSONRPC: "2.0",
			Error: &JSONRPCError{
				Code:    CodeParseError,
				Message: fmt.Sprintf("invalid json-rpc: %v", err),
			},
		}, nil, nil
	}

	if err := ValidateMirroredHeaderParameters(&http.Request{Header: reqHeaders}, &jsonReq); err != nil {
		return &JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      jsonReq.ID,
			Error:   err,
		}, nil, nil
	}

	// If method is tools/call, route through unified CallTool
	if jsonReq.Method == "tools/call" {
		var toolCallParams struct {
			Name      string         `json:"name"`
			Arguments map[string]any `json:"arguments"`
		}
		if len(jsonReq.Params) > 0 {
			_ = json.Unmarshal(jsonReq.Params, &toolCallParams)
		}

		callerMeta := make(map[string]string)
		for k := range reqHeaders {
			callerMeta[k] = reqHeaders.Get(k)
		}

		callResp, err := h.CallTool(ctx, idCtx, ToolCallInput{
			ServerSlug: serverSlug,
			ToolName:   toolCallParams.Name,
			Arguments:  toolCallParams.Arguments,
		}, CallMetadata{
			ProtocolVersion: domain.MCPProtocolVersion2026,
			RequestID:       fmt.Sprint(jsonReq.ID),
			CallerMetadata:  callerMeta,
		})

		if err != nil {
			return &JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      jsonReq.ID,
				Error: &JSONRPCError{
					Code:    CodeInvalidRequest,
					Message: err.Error(),
				},
			}, nil, nil
		}

		resMap := map[string]any{
			"content": callResp.Content,
		}
		if callResp.IsError {
			resMap["isError"] = true
		}
		if len(callResp.Meta) > 0 {
			resMap["_meta"] = callResp.Meta
		}

		return &JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      jsonReq.ID,
			Result:  resMap,
		}, nil, nil
	}

	// Cache check for tools/list
	var cacheKey string
	if h.cache != nil && jsonReq.Method == "tools/list" {
		keyPrefix := ""
		if idCtx != nil {
			keyPrefix = idCtx.KeyPrefix
		}
		cacheKey = h.cache.ComputeCacheKey(orgID, keyPrefix, serverSlug, "tools/list", nil, server.ConfigVersion)
		if cachedResp, ok := h.cache.Get(ctx, cacheKey); ok {
			// Post-cache Tool Pinning check if server enforces pinned hash
			if server.PinnedToolHash != "" && h.guardrails != nil {
				tools, _ := h.repo.ListMCPTools(ctx, server.ID)
				for _, t := range tools {
					if err := h.guardrails.VerifyToolPinning(t, server.PinnedToolHash); err != nil {
						return &JSONRPCResponse{
							JSONRPC: "2.0",
							ID:      jsonReq.ID,
							Error: &JSONRPCError{
								Code:    CodeInvalidRequest,
								Message: fmt.Sprintf("Tool pinning violation: %v", err),
							},
						}, nil, nil
					}
				}
			}
			cachedResp.ID = jsonReq.ID
			return cachedResp, nil, nil
		}
	}

	// Resolve BYOK user credential if available
	var userCred *domain.MCPUserCredential
	if idCtx != nil && idCtx.UserID != "" {
		userCred, _ = h.repo.GetMCPUserCredential(ctx, server.ID, idCtx.UserID)
	}

	authCtx := &upstream.UpstreamAuthContext{
		ServerID:          server.ID,
		ServerSlug:        server.Slug,
		TargetURL:         server.EndpointURL,
		CallingOrgID:      orgID,
		CallingTeamID:     idCtx.TeamID,
		CallingUserID:     idCtx.UserID,
		CallingVirtualKey: idCtx.VirtualKeyID,
	}

	strat, extraHeaders := h.authResolver.ResolveStrategy(ctx, server, userCred, reqHeaders)
	authCtx.ExtraHeaders = extraHeaders

	resp, respHeaders, err := h.dispatcher.Dispatch(ctx, server, strat, authCtx, reqBody, reqHeaders)
	if err != nil || resp == nil {
		return resp, respHeaders, err
	}

	// Cache storage if response is valid and cacheable
	if cacheKey != "" && h.cache != nil && ShouldCache(jsonReq.Method, resp) {
		_ = h.cache.Set(ctx, cacheKey, resp, 5*time.Minute)
	}

	return resp, respHeaders, nil
}

// DispatchToolset routes calls to a curated toolset (`POST /mcp/toolsets/{toolsetSlug}`).
func (h *Hub) DispatchToolset(
	ctx context.Context,
	idCtx *domain.IdentityContext,
	toolsetSlug string,
	reqBody []byte,
	reqHeaders http.Header,
) (*JSONRPCResponse, http.Header, error) {
	toolsetSlug = strings.TrimSpace(toolsetSlug)
	orgID := ""
	if idCtx != nil {
		orgID = idCtx.OrgID
	}

	toolset, err := h.repo.GetMCPToolsetBySlug(ctx, orgID, toolsetSlug)
	if err != nil || !toolset.IsActive {
		return &JSONRPCResponse{
			JSONRPC: "2.0",
			Error: &JSONRPCError{
				Code:    CodeInvalidRequest,
				Message: fmt.Sprintf("toolset %q not found or inactive", toolsetSlug),
			},
		}, nil, nil
	}

	var jsonReq JSONRPCRequest
	dec := json.NewDecoder(bytes.NewReader(reqBody))
	dec.UseNumber()
	if err := dec.Decode(&jsonReq); err != nil {
		return &JSONRPCResponse{
			JSONRPC: "2.0",
			Error: &JSONRPCError{
				Code:    CodeParseError,
				Message: fmt.Sprintf("invalid json-rpc: %v", err),
			},
		}, nil, nil
	}

	switch jsonReq.Method {
	case "tools/list":
		var allowedTools []map[string]any
		for _, toolID := range toolset.ToolIDs {
			tool, err := h.repo.GetMCPTool(ctx, toolID)
			if err != nil || !tool.IsActive {
				continue
			}
			server, err := h.repo.GetMCPServer(ctx, tool.ServerID)
			if err != nil || !server.IsActive {
				continue
			}
			if h.rbac != nil && h.rbac.AuthorizeMCPServer(idCtx, server.Slug) != nil {
				continue
			}
			allowedTools = append(allowedTools, map[string]any{
				"name":        tool.Name,
				"description": tool.Description,
				"inputSchema": tool.InputSchema,
			})
		}
		return &JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      jsonReq.ID,
			Result: map[string]any{
				"tools": allowedTools,
			},
		}, nil, nil

	case "tools/call":
		var params struct {
			Name      string         `json:"name"`
			Arguments map[string]any `json:"arguments"`
		}
		_ = json.Unmarshal(jsonReq.Params, &params)
		if params.Name == "" {
			return &JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      jsonReq.ID,
				Error: &JSONRPCError{
					Code:    CodeInvalidParams,
					Message: "missing tool name in tools/call",
				},
			}, nil, nil
		}

		// Find tool in toolset
		var targetServer *domain.MCPServer
		for _, toolID := range toolset.ToolIDs {
			tool, err := h.repo.GetMCPTool(ctx, toolID)
			if err == nil && tool.Name == params.Name && tool.IsActive {
				server, err := h.repo.GetMCPServer(ctx, tool.ServerID)
				if err == nil && server.IsActive {
					targetServer = server
					break
				}
			}
		}

		if targetServer == nil {
			return &JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      jsonReq.ID,
				Error: &JSONRPCError{
					Code:    CodeMethodNotFound,
					Message: fmt.Sprintf("tool %q is not member of toolset %q", params.Name, toolsetSlug),
				},
			}, nil, nil
		}

		// Scoped dispatch to target server via CallTool
		callerMeta := make(map[string]string)
		for k := range reqHeaders {
			callerMeta[k] = reqHeaders.Get(k)
		}
		callResp, err := h.CallTool(ctx, idCtx, ToolCallInput{
			ServerSlug: targetServer.Slug,
			ToolName:   params.Name,
			Arguments:  params.Arguments,
		}, CallMetadata{
			ProtocolVersion: domain.MCPProtocolVersion2026,
			RequestID:       fmt.Sprint(jsonReq.ID),
			CallerMetadata:  callerMeta,
		})
		if err != nil {
			return &JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      jsonReq.ID,
				Error: &JSONRPCError{
					Code:    CodeInvalidRequest,
					Message: err.Error(),
				},
			}, nil, nil
		}

		resMap := map[string]any{
			"content": callResp.Content,
		}
		if callResp.IsError {
			resMap["isError"] = true
		}
		if len(callResp.Meta) > 0 {
			resMap["_meta"] = callResp.Meta
		}

		return &JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      jsonReq.ID,
			Result:  resMap,
		}, nil, nil

	default:
		return &JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      jsonReq.ID,
			Error: &JSONRPCError{
				Code:    CodeMethodNotFound,
				Message: fmt.Sprintf("method %q not supported on toolset route", jsonReq.Method),
			},
		}, nil, nil
	}
}

func (h *Hub) handleVirtualToolsList(ctx context.Context, idCtx *domain.IdentityContext, id any) (*JSONRPCResponse, http.Header, error) {
	orgID := ""
	if idCtx != nil {
		orgID = idCtx.OrgID
	}

	servers, err := h.repo.ListMCPServers(ctx, orgID)
	if err != nil {
		return nil, nil, err
	}

	var aggregatedTools []map[string]any
	serverOutcomes := make(map[string]string)

	for _, s := range servers {
		if !s.IsActive {
			continue
		}
		if h.rbac != nil && h.rbac.AuthorizeMCPServer(idCtx, s.Slug) != nil {
			continue
		}

		tools, err := h.repo.ListMCPTools(ctx, s.ID)
		if err != nil {
			serverOutcomes[s.Slug] = "error: " + err.Error()
			continue
		}

		for _, t := range tools {
			if t != nil && t.IsActive {
				aggregatedTools = append(aggregatedTools, map[string]any{
					"name":        t.Name,
					"description": t.Description,
					"inputSchema": t.InputSchema,
				})
			}
		}
		serverOutcomes[s.Slug] = fmt.Sprintf("ok: %d tools", len(tools))
	}

	return &JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result: map[string]any{
			"tools": aggregatedTools,
			"_meta": map[string]any{
				"goroute.ai/server_outcomes": serverOutcomes,
			},
		},
	}, nil, nil
}

func (h *Hub) handleVirtualToolsCall(
	ctx context.Context,
	idCtx *domain.IdentityContext,
	req *JSONRPCRequest,
	reqBody []byte,
	reqHeaders http.Header,
) (*JSONRPCResponse, http.Header, error) {
	var params struct {
		Name      string         `json:"name"`
		Arguments map[string]any `json:"arguments"`
	}
	_ = json.Unmarshal(req.Params, &params)
	if params.Name == "" {
		return &JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error: &JSONRPCError{
				Code:    CodeInvalidParams,
				Message: "missing tool name in tools/call params",
			},
		}, nil, nil
	}

	callerMeta := make(map[string]string)
	for k := range reqHeaders {
		callerMeta[k] = reqHeaders.Get(k)
	}

	callResp, err := h.CallTool(ctx, idCtx, ToolCallInput{
		ServerSlug: "", // Let CallTool perform unambiguous resolution
		ToolName:   params.Name,
		Arguments:  params.Arguments,
	}, CallMetadata{
		ProtocolVersion: domain.MCPProtocolVersion2026,
		RequestID:       fmt.Sprint(req.ID),
		CallerMetadata:  callerMeta,
	})

	if err != nil {
		var ambErr *AmbiguousToolError
		code := CodeInvalidRequest
		if errors.As(err, &ambErr) {
			code = CodeInvalidParams
		} else if strings.Contains(strings.ToLower(err.Error()), "not found") {
			code = CodeMethodNotFound
		}
		return &JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error: &JSONRPCError{
				Code:    code,
				Message: err.Error(),
			},
		}, nil, nil
	}

	resMap := map[string]any{
		"content": callResp.Content,
	}
	if callResp.IsError {
		resMap["isError"] = true
	}
	if len(callResp.Meta) > 0 {
		resMap["_meta"] = callResp.Meta
	}

	return &JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result:  resMap,
	}, nil, nil
}

func extractCallToolResponse(result any) (*CallToolResponse, error) {
	if result == nil {
		return &CallToolResponse{}, nil
	}

	resMap, ok := result.(map[string]any)
	if !ok {
		return &CallToolResponse{
			Content: []ToolContent{
				{
					Type: "text",
					Text: fmt.Sprint(result),
				},
			},
		}, nil
	}

	callResp := &CallToolResponse{}

	// isError
	if ie, exists := resMap["isError"]; exists {
		if b, ok := ie.(bool); ok {
			callResp.IsError = b
		}
	} else if ie, exists := resMap["is_error"]; exists {
		if b, ok := ie.(bool); ok {
			callResp.IsError = b
		}
	}

	// _meta
	if m, exists := resMap["_meta"]; exists {
		if metaMap, ok := m.(map[string]any); ok {
			callResp.Meta = metaMap
		}
	}

	// content
	if rawContent, exists := resMap["content"]; exists {
		switch c := rawContent.(type) {
		case []ToolContent:
			callResp.Content = c
		case []any:
			for _, item := range c {
				if itemMap, ok := item.(map[string]any); ok {
					tc := ToolContent{
						Type: fmt.Sprint(itemMap["type"]),
					}
					if txt, ok := itemMap["text"].(string); ok {
						tc.Text = txt
					}
					if data, ok := itemMap["data"].(string); ok {
						tc.Data = data
					}
					if mime, ok := itemMap["mimeType"].(string); ok {
						tc.MimeType = mime
					}
					if res, ok := itemMap["resource"].(map[string]any); ok {
						tc.Resource = res
					}
					callResp.Content = append(callResp.Content, tc)
				}
			}
		case []map[string]any:
			for _, itemMap := range c {
				tc := ToolContent{
					Type: fmt.Sprint(itemMap["type"]),
				}
				if txt, ok := itemMap["text"].(string); ok {
					tc.Text = txt
				}
				if data, ok := itemMap["data"].(string); ok {
					tc.Data = data
				}
				if mime, ok := itemMap["mimeType"].(string); ok {
					tc.MimeType = mime
				}
				if res, ok := itemMap["resource"].(map[string]any); ok {
					tc.Resource = res
				}
				callResp.Content = append(callResp.Content, tc)
			}
		}
	}

	return callResp, nil
}
