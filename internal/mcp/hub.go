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
	"github.com/goroute-ai/ai-gateway-go/internal/observability"
	"github.com/goroute-ai/ai-gateway-go/internal/ratelimit"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

// HubOption configures optional capabilities on an MCP Hub instance.
type HubOption func(*Hub)

// WithGuardrailPipeline attaches a unified v2 guardrail Pipeline to the MCP Hub.
func WithGuardrailPipeline(p *guardrails.Pipeline) HubOption {
	return func(h *Hub) {
		h.SetGuardrailPipeline(p)
	}
}

// WithLimiter attaches a rate/quota Limiter to the MCP Hub for per-server, per-key, and per-team MCP RPM enforcement.
func WithLimiter(l *ratelimit.Limiter) HubOption {
	return func(h *Hub) {
		h.SetLimiter(l)
	}
}

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
	pipeline      *guardrails.Pipeline
	limiter       *ratelimit.Limiter
	spendRecorder SpendRecorder
	progressive   *ProgressiveDiscoveryManager
}

func (h *Hub) SetCache(c *MCPCache)                    { h.cache = c }
func (h *Hub) SetMRTR(m *MRTRManager)                  { h.mrtr = m }
func (h *Hub) SetSubscriptions(s *SubscriptionManager) { h.subs = s }
func (h *Hub) SetGuardrails(g *guardrails.Engine)      { h.guardrails = g }
func (h *Hub) SetLimiter(l *ratelimit.Limiter)         { h.limiter = l }
func (h *Hub) SetGuardrailPipeline(p *guardrails.Pipeline) {
	h.pipeline = p
	if h.guardrails == nil && p != nil && p.Engine() != nil {
		h.guardrails = p.Engine()
	}
}
func (h *Hub) ApplyOptions(opts ...HubOption) {
	for _, opt := range opts {
		if opt != nil {
			opt(h)
		}
	}
}
func (h *Hub) SetSpendRecorder(sr SpendRecorder) { h.spendRecorder = sr }
func (h *Hub) SetProgressiveDiscovery(p *ProgressiveDiscoveryManager) {
	if p != nil && p.rbac == nil {
		p.SetRBAC(h.rbac)
	}
	h.progressive = p
}
func (h *Hub) Cache() *MCPCache                                   { return h.cache }
func (h *Hub) MRTR() *MRTRManager                                 { return h.mrtr }
func (h *Hub) Subscriptions() *SubscriptionManager                { return h.subs }
func (h *Hub) Guardrails() *guardrails.Engine                     { return h.guardrails }
func (h *Hub) GuardrailPipeline() *guardrails.Pipeline            { return h.pipeline }
func (h *Hub) Limiter() *ratelimit.Limiter                        { return h.limiter }
func (h *Hub) SpendRecorder() SpendRecorder                       { return h.spendRecorder }
func (h *Hub) ProgressiveDiscovery() *ProgressiveDiscoveryManager { return h.progressive }
func (h *Hub) Dispatcher() *TransportDispatcher                   { return h.dispatcher }

// NewHub constructs a new MCP Hub instance.
func NewHub(
	repo storage.Repository,
	vault *auth.Vault,
	rbac *auth.RBACEngine,
	dispatcher *TransportDispatcher,
	authResolver *AuthResolver,
) *Hub {
	pdm := NewProgressiveDiscoveryManager(repo, nil, HandleTTL)
	pdm.SetRBAC(rbac)
	return &Hub{
		repo:         repo,
		vault:        vault,
		rbac:         rbac,
		dispatcher:   dispatcher,
		authResolver: authResolver,
		progressive:  pdm,
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
				h.recordAudit(ctx, idCtx, "mcp.rbac.denied", "mcp_server", server.Slug, map[string]any{
					"operation": "tools/list",
					"reason":    err.Error(),
				})
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
		rec, tool, err := h.progressive.ResolveHandleForIdentity(ctx, idCtx, hdl)
		if err == nil && h.rbac != nil {
			if rbacErr := h.rbac.AuthorizeMCPServer(idCtx, rec.ServerSlug); rbacErr != nil {
				h.recordAudit(ctx, idCtx, "mcp.rbac.denied", "mcp_server", rec.ServerSlug, map[string]any{
					"operation": "get_tool_schema",
					"tool_name": rec.ToolName,
					"reason":    rbacErr.Error(),
				})
				err = rbacErr
			}
		}
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
		rec, tool, err := h.progressive.ResolveHandleForIdentity(ctx, idCtx, input.ToolName)
		if err != nil {
			return nil, err
		}
		if rec.OrgID != orgID {
			return nil, ErrHandleNotFound
		}
		if h.rbac != nil {
			if err := h.rbac.AuthorizeMCPServer(idCtx, rec.ServerSlug); err != nil {
				h.recordAudit(ctx, idCtx, "mcp.rbac.denied", "mcp_server", rec.ServerSlug, map[string]any{
					"operation": "tools/call",
					"tool_name": rec.ToolName,
					"reason":    err.Error(),
				})
				return nil, err
			}
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
				h.recordAudit(ctx, idCtx, "mcp.rbac.denied", "mcp_server", server.Slug, map[string]any{
					"operation": "tools/call",
					"tool_name": input.ToolName,
					"reason":    err.Error(),
				})
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
	if targetServer.PinnedToolHash != "" && (h.guardrails != nil || h.pipeline != nil) {
		if targetTool == nil {
			return nil, fmt.Errorf("tool pinning violation: tool %q not found in catalog", input.ToolName)
		}
		pinnedHash := targetTool.ToolDefHash
		if pinnedHash == "" {
			pinnedHash = targetServer.PinnedToolHash
		}
		pinEng := h.guardrails
		if pinEng == nil && h.pipeline != nil {
			pinEng = h.pipeline.Engine()
		}
		if err := pinEng.VerifyToolPinning(targetTool, pinnedHash); err != nil {
			return nil, fmt.Errorf("tool pinning violation: %w", err)
		}
	}

	reqID := meta.RequestID
	if reqID == "" {
		reqID = "req_" + uuid.NewString()
	}

	releaseMCPQuota, quotaErr := h.acquireMCPToolQuota(ctx, idCtx, targetServer, reqID)
	if quotaErr != nil {
		return nil, quotaErr
	}
	defer releaseMCPQuota(0, 0, 0)

	var mcpPRC guardrails.PipelineRequestContext
	var mcpCallCtx *guardrails.MCPCallContext
	if h.pipeline != nil {
		mcpPRC = buildMCPPipelineRequestContext(ctx, idCtx, reqID, meta.CallerMetadata, nil)
		mcpCallCtx = &guardrails.MCPCallContext{
			ServerID:   targetServer.ID,
			ServerSlug: targetServer.Slug,
			ServerURL:  targetServer.EndpointURL,
			ToolName:   input.ToolName,
			Arguments:  input.Arguments,
		}
		if targetTool != nil {
			mcpCallCtx.ToolID = targetTool.ID
			mcpCallCtx.ToolDefHash = targetTool.ToolDefHash
		}
	}

	// 2. Call Guardrails Scan on arguments (Layer 0 Engine + Layer 1 pre_mcp_call Pipeline)
	if h.pipeline != nil {
		if _, err := h.pipeline.EvaluatePreMCPCall(ctx, mcpPRC, mcpCallCtx); err != nil {
			return nil, fmt.Errorf("guardrail blocked tool call: %w", err)
		}
		if h.pipeline.Engine() == nil && h.guardrails != nil {
			if _, err := h.guardrails.EvaluateMCPToolCall(ctx, orgID, input.ToolName, input.Arguments); err != nil {
				return nil, fmt.Errorf("guardrail blocked tool call: %w", err)
			}
		}
	} else if h.guardrails != nil {
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
				h.recordAudit(ctx, idCtx, "mcp.tool.call", "mcp_tool", targetServer.Slug+"/"+input.ToolName, map[string]any{
					"server_slug": targetServer.Slug,
					"tool_name":   input.ToolName,
					"cache_hit":   true,
					"is_error":    callResp.IsError,
				})
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
		DelegatedToken:    extractDelegatedBearerFromHeaders(reqHeaders),
	}

	strat, extraHeaders := h.authResolver.ResolveStrategy(ctx, targetServer, userCred, reqHeaders)
	authCtx.ExtraHeaders = extraHeaders

	// 6. Upstream Dispatch (with optional concurrent during_mcp_call guardrails)
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

	dispatchCtx := ctx
	var duringHandle *guardrails.DuringCallHandle
	if h.pipeline != nil {
		var duringErr error
		dispatchCtx, duringHandle, duringErr = h.pipeline.StartDuringMCPCall(ctx, mcpPRC, mcpCallCtx)
		if duringErr != nil {
			return nil, fmt.Errorf("guardrail blocked tool call: %w", duringErr)
		}
		if duringHandle != nil {
			defer duringHandle.Close()
		}
	}

	resp, _, err := h.dispatcher.Dispatch(dispatchCtx, targetServer, strat, authCtx, reqBodyBytes, reqHeaders)
	if err != nil {
		if duringHandle != nil {
			if bErr := duringHandle.Blocked(); bErr != nil {
				return nil, fmt.Errorf("guardrail blocked tool call: %w", bErr)
			}
			if _, wErr := duringHandle.Wait(ctx); wErr != nil {
				return nil, fmt.Errorf("guardrail blocked tool call: %w", wErr)
			}
		}
		return nil, fmt.Errorf("upstream dispatch error: %w", err)
	}
	if duringHandle != nil {
		if _, wErr := duringHandle.Wait(ctx); wErr != nil {
			return nil, fmt.Errorf("guardrail blocked tool call: %w", wErr)
		}
	}
	if resp == nil {
		return nil, errors.New("upstream returned empty response")
	}
	if resp.Error != nil {
		return nil, fmt.Errorf("upstream mcp error (%d): %s", resp.Error.Code, resp.Error.Message)
	}

	// 7. Output guardrail inspection and redaction on tool call result
	if h.pipeline != nil && resp.Result != nil {
		_, redactedResult, err := h.pipeline.EvaluatePostMCPCall(ctx, mcpPRC, mcpCallCtx, resp.Result)
		if err != nil {
			return nil, fmt.Errorf("guardrail result inspection failed: %w", err)
		}
		resp.Result = redactedResult
		if h.pipeline.Engine() == nil && h.guardrails != nil && resp.Result != nil {
			_, redactedLegacy, err := h.guardrails.EvaluateMCPToolResult(ctx, orgID, resp.Result)
			if err != nil {
				return nil, fmt.Errorf("guardrail result inspection failed: %w", err)
			}
			resp.Result = redactedLegacy
		}
	} else if h.guardrails != nil && resp.Result != nil {
		_, redactedResult, err := h.guardrails.EvaluateMCPToolResult(ctx, orgID, resp.Result)
		if err != nil {
			return nil, fmt.Errorf("guardrail result inspection failed: %w", err)
		}
		resp.Result = redactedResult
	}

	// 8. FinOps spend debit. Do not cache a success until accounting is durable.
	if h.spendRecorder != nil && targetTool != nil && targetTool.CostPerCallMicros > 0 {
		if err := h.spendRecorder.Record(ctx, domain.SpendEvent{
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
		}); err != nil {
			return nil, fmt.Errorf("persist MCP spend event: %w", err)
		}
	}
	// 9. Cache storage if response is valid and cacheable.
	if cacheKey != "" && h.cache != nil && ShouldCache("tools/call", resp) {
		_ = h.cache.Set(ctx, cacheKey, resp, 5*time.Minute)
	}

	callResp, err := extractCallToolResponse(resp.Result)
	if err != nil {
		return nil, fmt.Errorf("failed to parse upstream tool result: %w", err)
	}
	h.recordAudit(ctx, idCtx, "mcp.tool.call", "mcp_tool", targetServer.Slug+"/"+input.ToolName, map[string]any{
		"server_slug": targetServer.Slug,
		"tool_name":   input.ToolName,
		"cache_hit":   false,
		"is_error":    callResp.IsError,
	})
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
			h.recordAudit(ctx, idCtx, "mcp.rbac.denied", "mcp_server", serverSlug, map[string]any{
				"operation": "jsonrpc",
				"reason":    err.Error(),
			})
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

	// Guardrail input scan for resources/read and prompts/get
	isGuardedMethod := jsonReq.Method == "resources/read" || jsonReq.Method == "prompts/get"
	var scopedPRC guardrails.PipelineRequestContext
	var scopedCallCtx *guardrails.MCPCallContext
	if isGuardedMethod && (h.pipeline != nil || h.guardrails != nil) {
		var paramsMap map[string]any
		if len(jsonReq.Params) > 0 {
			_ = json.Unmarshal(jsonReq.Params, &paramsMap)
		}
		if h.pipeline != nil {
			scopedPRC = buildMCPPipelineRequestContext(ctx, idCtx, fmt.Sprint(jsonReq.ID), nil, reqHeaders)
			scopedCallCtx = &guardrails.MCPCallContext{
				ServerID:   server.ID,
				ServerSlug: server.Slug,
				ServerURL:  server.EndpointURL,
				ToolName:   jsonReq.Method,
				Arguments:  paramsMap,
			}
			if _, err := h.pipeline.EvaluatePreMCPCall(ctx, scopedPRC, scopedCallCtx); err != nil {
				return &JSONRPCResponse{
					JSONRPC: "2.0",
					ID:      jsonReq.ID,
					Error: &JSONRPCError{
						Code:    CodeInvalidRequest,
						Message: fmt.Sprintf("guardrail blocked %s: %v", jsonReq.Method, err),
					},
				}, nil, nil
			}
			if h.pipeline.Engine() == nil && h.guardrails != nil {
				if _, err := h.guardrails.EvaluateMCPToolCall(ctx, orgID, jsonReq.Method, paramsMap); err != nil {
					return &JSONRPCResponse{
						JSONRPC: "2.0",
						ID:      jsonReq.ID,
						Error: &JSONRPCError{
							Code:    CodeInvalidRequest,
							Message: fmt.Sprintf("guardrail blocked %s: %v", jsonReq.Method, err),
						},
					}, nil, nil
				}
			}
		} else if h.guardrails != nil {
			if _, err := h.guardrails.EvaluateMCPToolCall(ctx, orgID, jsonReq.Method, paramsMap); err != nil {
				return &JSONRPCResponse{
					JSONRPC: "2.0",
					ID:      jsonReq.ID,
					Error: &JSONRPCError{
						Code:    CodeInvalidRequest,
						Message: fmt.Sprintf("guardrail blocked %s: %v", jsonReq.Method, err),
					},
				}, nil, nil
			}
		}
	}

	// Resolve BYOK user credential if available
	var userCred *domain.MCPUserCredential
	if idCtx != nil && idCtx.UserID != "" {
		userCred, _ = h.repo.GetMCPUserCredential(ctx, server.ID, idCtx.UserID)
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
		ServerID:          server.ID,
		ServerSlug:        server.Slug,
		TargetURL:         server.EndpointURL,
		CallingOrgID:      orgID,
		CallingTeamID:     teamID,
		CallingUserID:     userID,
		CallingVirtualKey: vkID,
		DelegatedToken:    extractDelegatedBearerFromHeaders(reqHeaders),
	}

	strat, extraHeaders := h.authResolver.ResolveStrategy(ctx, server, userCred, reqHeaders)
	authCtx.ExtraHeaders = extraHeaders

	dispatchCtx := ctx
	var duringHandle *guardrails.DuringCallHandle
	if isGuardedMethod && h.pipeline != nil && scopedCallCtx != nil {
		var duringErr error
		dispatchCtx, duringHandle, duringErr = h.pipeline.StartDuringMCPCall(ctx, scopedPRC, scopedCallCtx)
		if duringErr != nil {
			return &JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      jsonReq.ID,
				Error: &JSONRPCError{
					Code:    CodeInvalidRequest,
					Message: fmt.Sprintf("guardrail blocked %s: %v", jsonReq.Method, duringErr),
				},
			}, nil, nil
		}
		if duringHandle != nil {
			defer duringHandle.Close()
		}
	}

	resp, respHeaders, err := h.dispatcher.Dispatch(dispatchCtx, server, strat, authCtx, reqBody, reqHeaders)
	if duringHandle != nil {
		if bErr := duringHandle.Blocked(); bErr != nil {
			return &JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      jsonReq.ID,
				Error: &JSONRPCError{
					Code:    CodeInvalidRequest,
					Message: fmt.Sprintf("guardrail blocked %s: %v", jsonReq.Method, bErr),
				},
			}, respHeaders, nil
		}
		if _, wErr := duringHandle.Wait(ctx); wErr != nil {
			return &JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      jsonReq.ID,
				Error: &JSONRPCError{
					Code:    CodeInvalidRequest,
					Message: fmt.Sprintf("guardrail blocked %s: %v", jsonReq.Method, wErr),
				},
			}, respHeaders, nil
		}
	}
	if err != nil || resp == nil {
		return resp, respHeaders, err
	}

	// Guardrail output inspection/redaction for resources/read and prompts/get
	if isGuardedMethod && resp.Result != nil {
		if h.pipeline != nil && scopedCallCtx != nil {
			_, redactedResult, err := h.pipeline.EvaluatePostMCPCall(ctx, scopedPRC, scopedCallCtx, resp.Result)
			if err != nil {
				return &JSONRPCResponse{
					JSONRPC: "2.0",
					ID:      jsonReq.ID,
					Error: &JSONRPCError{
						Code:    CodeInvalidRequest,
						Message: fmt.Sprintf("guardrail result inspection failed: %v", err),
					},
				}, respHeaders, nil
			}
			resp.Result = redactedResult
			if h.pipeline.Engine() == nil && h.guardrails != nil && resp.Result != nil {
				_, redactedLegacy, err := h.guardrails.EvaluateMCPToolResult(ctx, orgID, resp.Result)
				if err != nil {
					return &JSONRPCResponse{
						JSONRPC: "2.0",
						ID:      jsonReq.ID,
						Error: &JSONRPCError{
							Code:    CodeInvalidRequest,
							Message: fmt.Sprintf("guardrail result inspection failed: %v", err),
						},
					}, respHeaders, nil
				}
				resp.Result = redactedLegacy
			}
		} else if h.guardrails != nil {
			_, redactedResult, err := h.guardrails.EvaluateMCPToolResult(ctx, orgID, resp.Result)
			if err != nil {
				return &JSONRPCResponse{
					JSONRPC: "2.0",
					ID:      jsonReq.ID,
					Error: &JSONRPCError{
						Code:    CodeInvalidRequest,
						Message: fmt.Sprintf("guardrail result inspection failed: %v", err),
					},
				}, respHeaders, nil
			}
			resp.Result = redactedResult
		}
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

func auditActorID(idCtx *domain.IdentityContext) string {
	if idCtx == nil {
		return ""
	}
	if idCtx.VirtualKeyID != "" {
		return idCtx.VirtualKeyID
	}
	if idCtx.UserID != "" {
		return idCtx.UserID
	}
	return idCtx.KeyPrefix
}

func minPositiveMCPInt(a, b int) int {
	if a <= 0 {
		return b
	}
	if b <= 0 || a < b {
		return a
	}
	return b
}

func matchesMCPModelPattern(pattern, serverSlug string) bool {
	p := strings.ToLower(strings.TrimSpace(pattern))
	slug := strings.ToLower(strings.TrimSpace(serverSlug))
	switch p {
	case "mcp", "mcp/*", "mcp:*":
		return true
	}
	if slug != "" && (p == slug || p == "mcp/"+slug || p == "mcp:"+slug) {
		return true
	}
	return false
}

func (h *Hub) acquireMCPToolQuota(
	ctx context.Context,
	idCtx *domain.IdentityContext,
	targetServer *domain.MCPServer,
	reqID string,
) (func(actualInput, actualOutput int, actualCostMicros int64), error) {
	noop := func(int, int, int64) {}
	if h == nil || h.limiter == nil || targetServer == nil {
		return noop, nil
	}
	orgID := targetServer.OrgID
	if orgID == "" && idCtx != nil {
		orgID = idCtx.OrgID
	}

	serverDesc := domain.RateLimitDescriptor{
		PolicyID:     targetServer.ID,
		ScopeType:    domain.QuotaScopeMCPServer,
		ScopeID:      targetServer.ID,
		ModelPattern: "*",
		RPMLimit:     targetServer.RPMLimit,
	}
	var keyDesc, teamDesc domain.RateLimitDescriptor
	if idCtx != nil && idCtx.VirtualKeyID != "" {
		keyDesc = domain.RateLimitDescriptor{
			PolicyID:     idCtx.VirtualKeyID,
			ScopeType:    domain.QuotaScopeKey,
			ScopeID:      idCtx.VirtualKeyID,
			ModelPattern: "mcp",
			RPMLimit:     idCtx.KeyMCPRPMLimit,
		}
	}
	if idCtx != nil && idCtx.TeamID != "" {
		teamDesc = domain.RateLimitDescriptor{
			PolicyID:     idCtx.TeamID,
			ScopeType:    domain.QuotaScopeTeam,
			ScopeID:      idCtx.TeamID,
			ModelPattern: "mcp",
			RPMLimit:     idCtx.TeamMCPRPMLimit,
		}
	}

	if h.repo != nil && orgID != "" {
		if qRepo, ok := h.repo.(storage.QuotaPolicyRepository); ok && qRepo != nil {
			policies, err := qRepo.ListQuotaPolicies(ctx, storage.QuotaPolicyFilter{
				OrgID:      orgID,
				ActiveOnly: true,
			})
			if err != nil {
				return nil, &domain.GatewayError{
					StatusCode:    http.StatusServiceUnavailable,
					Type:          domain.ErrorTypeRateLimit,
					Code:          "quota_policy_unavailable",
					Message:       "Unable to evaluate MCP quota policies",
					RetryAfterSec: 5,
				}
			}
			for _, qp := range policies {
				if qp == nil || !qp.IsActive {
					continue
				}
				switch qp.ScopeType {
				case domain.QuotaScopeMCPServer:
					if qp.ScopeID == "*" || qp.ScopeID == targetServer.ID || qp.ScopeID == targetServer.Slug {
						serverDesc.RPMLimit = minPositiveMCPInt(serverDesc.RPMLimit, qp.RPMLimit)
						serverDesc.MaxConcurrent = minPositiveMCPInt(serverDesc.MaxConcurrent, qp.MaxConcurrent)
					}
				case domain.QuotaScopeKey, domain.QuotaScopeModelPerKey:
					if idCtx != nil && idCtx.VirtualKeyID != "" && (qp.ScopeID == idCtx.VirtualKeyID || qp.ScopeID == "*") && matchesMCPModelPattern(qp.ModelPattern, targetServer.Slug) {
						keyDesc.RPMLimit = minPositiveMCPInt(keyDesc.RPMLimit, qp.RPMLimit)
						keyDesc.MaxConcurrent = minPositiveMCPInt(keyDesc.MaxConcurrent, qp.MaxConcurrent)
					}
				case domain.QuotaScopeTeam, domain.QuotaScopeModelPerTeam:
					if idCtx != nil && idCtx.TeamID != "" && (qp.ScopeID == idCtx.TeamID || qp.ScopeID == "*") && matchesMCPModelPattern(qp.ModelPattern, targetServer.Slug) {
						teamDesc.RPMLimit = minPositiveMCPInt(teamDesc.RPMLimit, qp.RPMLimit)
						teamDesc.MaxConcurrent = minPositiveMCPInt(teamDesc.MaxConcurrent, qp.MaxConcurrent)
					}
				}
			}
		}
	}

	var descriptors []domain.RateLimitDescriptor
	if serverDesc.ScopeID != "" && serverDesc.HasLimits() {
		descriptors = append(descriptors, serverDesc)
	}
	if keyDesc.ScopeID != "" && keyDesc.HasLimits() {
		descriptors = append(descriptors, keyDesc)
	}
	if teamDesc.ScopeID != "" && teamDesc.HasLimits() {
		descriptors = append(descriptors, teamDesc)
	}
	if len(descriptors) == 0 {
		return noop, nil
	}
	return h.limiter.AcquireDescriptors(ctx, orgID, reqID, 0, 0, 0, descriptors)
}

func (h *Hub) recordAudit(ctx context.Context, idCtx *domain.IdentityContext, action, resource, resourceID string, details map[string]any) {
	if h == nil || h.repo == nil {
		return
	}
	orgID := ""
	if idCtx != nil {
		orgID = idCtx.OrgID
	}
	_ = h.repo.RecordAuditLog(ctx, &domain.AuditLog{
		OrgID:      orgID,
		ActorID:    auditActorID(idCtx),
		Action:     action,
		Resource:   resource,
		ResourceID: resourceID,
		Details:    details,
	})
}

func buildMCPPipelineRequestContext(
	ctx context.Context,
	idCtx *domain.IdentityContext,
	reqID string,
	callerMeta map[string]string,
	reqHeaders http.Header,
) guardrails.PipelineRequestContext {
	prc := guardrails.PipelineRequestContext{
		RequestID: reqID,
	}
	if idCtx != nil {
		prc.OrgID = idCtx.OrgID
		prc.TeamID = idCtx.TeamID
		prc.VirtualKeyID = idCtx.VirtualKeyID
		prc.EndUserID = idCtx.UserID
		if role := strings.TrimSpace(string(idCtx.Role)); role != "" {
			prc.CallerRoles = []string{role}
		}
	}

	prc.TraceID = observability.TraceFromContext(ctx).TraceID

	sanitizedHeaders := make(map[string]string)
	addHeader := func(k, v string) {
		lk := strings.ToLower(strings.TrimSpace(k))
		switch lk {
		case "", "authorization", "x-api-key", "cookie", "proxy-authorization", "x-goroute-end-user-token", "x-end-user-token":
			return
		}
		if (lk == "x-goroute-trace-id" || lk == "x-trace-id") && prc.TraceID == "" {
			prc.TraceID = strings.TrimSpace(v)
		}
		if lk == "x-goroute-tags" && len(prc.Tags) == 0 {
			for _, part := range strings.Split(v, ",") {
				if trimmed := strings.TrimSpace(part); trimmed != "" {
					prc.Tags = append(prc.Tags, trimmed)
				}
			}
		}
		sanitizedHeaders[k] = v
	}

	for k, v := range callerMeta {
		addHeader(k, v)
	}
	for k, vals := range reqHeaders {
		if len(vals) > 0 {
			addHeader(k, vals[0])
		}
	}
	if len(sanitizedHeaders) > 0 {
		prc.RequestHeaders = sanitizedHeaders
	}

	if claims := guardrails.OIDCClaimsFromContext(ctx); len(claims) > 0 {
		prc.Metadata = map[string]any{"oidc_claims": claims}
	}
	return prc
}

func extractDelegatedBearerFromHeaders(h http.Header) string {
	if len(h) == 0 {
		return ""
	}
	for _, hdr := range []string{"X-GoRoute-End-User-Token", "X-End-User-Token"} {
		if val := strings.TrimSpace(h.Get(hdr)); val != "" {
			return stripBearerPrefix(val)
		}
	}
	if authHdr := strings.TrimSpace(h.Get("Authorization")); authHdr != "" {
		tok := stripBearerPrefix(authHdr)
		if strings.Count(tok, ".") == 2 && !strings.HasPrefix(tok, "sk-gw-") {
			return tok
		}
	}
	return ""
}
