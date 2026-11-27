package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/auth/upstream"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/guardrails"
	"github.com/goroute-ai/ai-gateway-go/internal/mcp/spec"
	"github.com/goroute-ai/ai-gateway-go/internal/observability"
	"github.com/goroute-ai/ai-gateway-go/internal/ratelimit"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

// HubOption configures optional capabilities on an MCP Hub instance.
type HubOption func(*Hub)

// WithLimiter attaches a rate/quota Limiter to the MCP Hub for per-server, per-key, and per-team MCP RPM enforcement.
func WithLimiter(l *ratelimit.Limiter) HubOption {
	return func(h *Hub) {
		h.SetLimiter(l)
	}
}

// Hub orchestrates multi-server MCP routing, tool aggregation, toolsets, and security enforcement.
type Hub struct {
	repo             storage.Repository
	vault            *auth.Vault
	rbac             *auth.RBACEngine
	dispatcher       *TransportDispatcher
	authResolver     *AuthResolver
	cache            *MCPCache
	mrtr             *MRTRManager
	subs             *SubscriptionManager
	guardrails       *guardrails.Engine
	limiter          *ratelimit.Limiter
	spendRecorder    SpendRecorder
	progressive      *ProgressiveDiscoveryManager
	customAuthorizer auth.Authorizer
	instruments      *observability.Instruments
	runtimeSettings  atomic.Pointer[domain.MCPRuntimeSettings]
}

// SetInstruments attaches OpenTelemetry metric instruments to the MCP Hub.
func (h *Hub) SetInstruments(inst *observability.Instruments) { h.instruments = inst }

// SetCache attaches the response cache used for cacheable MCP tool calls and listings.
func (h *Hub) SetCache(c *MCPCache) { h.cache = c }

// SetMRTR attaches the multi-region tool routing manager to the MCP Hub.
func (h *Hub) SetMRTR(m *MRTRManager) { h.mrtr = m }

// SetSubscriptions attaches the MCP resource subscription manager to the Hub.
func (h *Hub) SetSubscriptions(s *SubscriptionManager) { h.subs = s }

// SetGuardrails attaches the built-in guardrail Engine to the MCP Hub.
func (h *Hub) SetGuardrails(g *guardrails.Engine) { h.guardrails = g }

// SetLimiter attaches the rate and budget Limiter to the MCP Hub.
func (h *Hub) SetLimiter(l *ratelimit.Limiter) { h.limiter = l }

// ApplyOptions applies functional HubOption values to an existing Hub.
func (h *Hub) ApplyOptions(opts ...HubOption) {
	for _, opt := range opts {
		if opt != nil {
			opt(h)
		}
	}
}

// SetSpendRecorder attaches a SpendRecorder for durable MCP tool-call cost tracking.
func (h *Hub) SetSpendRecorder(sr SpendRecorder) { h.spendRecorder = sr }

// SetProgressiveDiscovery configures the progressive tool discovery manager and wires Hub RBAC.
func (h *Hub) SetProgressiveDiscovery(p *ProgressiveDiscoveryManager) {
	if p != nil && p.rbac == nil {
		p.SetRBAC(h.rbac)
	}
	h.progressive = p
}

// Cache returns the Hub's MCP tool metadata/result cache.
func (h *Hub) Cache() *MCPCache { return h.cache }

// MRTR returns the Hub's multi-region tool routing manager.
func (h *Hub) MRTR() *MRTRManager { return h.mrtr }

// Subscriptions returns the MCP resource subscription manager.
func (h *Hub) Subscriptions() *SubscriptionManager { return h.subs }

// Guardrails returns the attached guardrail Engine, if any.
func (h *Hub) Guardrails() *guardrails.Engine { return h.guardrails }

// Limiter returns the attached rate and budget Limiter, if any.
func (h *Hub) Limiter() *ratelimit.Limiter { return h.limiter }

// SpendRecorder returns the attached MCP SpendRecorder, if any.
func (h *Hub) SpendRecorder() SpendRecorder { return h.spendRecorder }

// ProgressiveDiscovery returns the attached ProgressiveDiscoveryManager, if any.
func (h *Hub) ProgressiveDiscovery() *ProgressiveDiscoveryManager { return h.progressive }

// Dispatcher returns the underlying MCP TransportDispatcher.
func (h *Hub) Dispatcher() *TransportDispatcher { return h.dispatcher }

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
	h := &Hub{
		repo:         repo,
		vault:        vault,
		rbac:         rbac,
		dispatcher:   dispatcher,
		authResolver: authResolver,
		progressive:  pdm,
	}
	h.SetRuntimeSettings(domain.MCPRuntimeSettings{
		ActiveProtocolVersion: spec.DefaultVersion,
	})
	return h
}

// SetRuntimeSettings updates the active gateway-wide MCP API specification selected via Web UI.
func (h *Hub) SetRuntimeSettings(settings domain.MCPRuntimeSettings) {
	if h == nil {
		return
	}
	if !spec.IsSupported(settings.ActiveProtocolVersion) {
		settings.ActiveProtocolVersion = spec.DefaultVersion
	}
	cp := settings
	h.runtimeSettings.Store(&cp)
}

// RuntimeSettings returns the active gateway-wide MCP specification settings.
func (h *Hub) RuntimeSettings() domain.MCPRuntimeSettings {
	if h == nil {
		return domain.MCPRuntimeSettings{ActiveProtocolVersion: spec.DefaultVersion}
	}
	if ptr := h.runtimeSettings.Load(); ptr != nil {
		return *ptr
	}
	return domain.MCPRuntimeSettings{ActiveProtocolVersion: spec.DefaultVersion}
}

// ActiveSpec returns the currently active official MCP release version string.
func (h *Hub) ActiveSpec() string {
	return h.RuntimeSettings().ActiveProtocolVersion
}

// ActiveProfile returns the compiled SpecProfile driver matching the active UI-selected MCP release.
func (h *Hub) ActiveProfile() SpecProfile {
	ver := h.ActiveSpec()
	prof, err := ProfileForVersion(ver)
	if err != nil {
		prof, _ = ProfileForVersion(spec.DefaultVersion)
	}
	return prof
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
				if h.authorizeToolCall(ctx, idCtx, server.Slug, t.Name, false) != nil {
					continue
				}
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
				if h.authorizeToolCall(ctx, idCtx, s.Slug, t.Name, false) != nil {
					continue
				}
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

	if resp, handled, err := h.tryCallMetaTool(ctx, idCtx, input); handled || err != nil {
		return resp, err
	}

	orgID := ""
	if idCtx != nil {
		orgID = idCtx.OrgID
	}

	targetServer, targetTool, resolvedToolName, err := h.resolveToolTarget(ctx, idCtx, orgID, input)
	if err != nil {
		return nil, err
	}
	input.ToolName = resolvedToolName

	if err := h.authorizeToolCall(ctx, idCtx, targetServer.Slug, input.ToolName, true); err != nil {
		return nil, err
	}
	if h.customAuthorizer != nil {
		if err := auth.EvaluateAuthorizer(ctx, h.customAuthorizer, &auth.AuthzRequest{
			Identity:     idCtx,
			Action:       auth.AuthzActionMCPToolCall,
			ResourceType: "mcp_tool",
			ResourceID:   targetServer.Slug + "/" + input.ToolName,
			MCPServer:    targetServer.Slug,
			MCPTool:      input.ToolName,
		}); err != nil {
			return nil, err
		}
	}

	if err := h.verifyToolPinning(targetServer, targetTool, input.ToolName); err != nil {
		return nil, err
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

	if err := h.evaluatePreMCPGuardrails(ctx, orgID, input.ToolName, input.Arguments); err != nil {
		return nil, fmt.Errorf("guardrail blocked tool call: %w", err)
	}

	reqHeaders, authCtx, authStrategy := h.resolveUpstreamAuth(ctx, idCtx, orgID, targetServer, meta.CallerMetadata, nil)
	paramsMap := map[string]any{"name": input.ToolName}
	if input.Arguments != nil {
		paramsMap["arguments"] = input.Arguments
	} else {
		paramsMap["arguments"] = map[string]any{}
	}
	paramsBytes, _ := json.Marshal(paramsMap)
	reqBodyBytes, _ := json.Marshal(JSONRPCRequest{
		JSONRPC: "2.0",
		ID:      reqID,
		Method:  "tools/call",
		Params:  paramsBytes,
	})

	spanCtx, toolSpan := observability.StartGenAISpan(ctx, nil, observability.GenAISpanStart{
		Operation:     "execute_tool",
		ToolName:      input.ToolName,
		MCPServerSlug: targetServer.Slug,
		ServerAddress: targetServer.EndpointURL,
		OrgID:         orgID,
	})
	resp, _, err := h.dispatcher.Dispatch(spanCtx, targetServer, authStrategy, authCtx, reqBodyBytes, reqHeaders)
	if err != nil {
		err = fmt.Errorf("upstream dispatch error: %w", err)
		observability.FinishGenAISpan(toolSpan, observability.GenAISpanEnd{Err: err, ErrorType: "mcp_dispatch_error"})
		if h.instruments != nil {
			h.instruments.RecordMCPRequest(spanCtx, "tools/call", "error")
		}
		return nil, err
	}
	if resp == nil {
		emptyErr := errors.New("upstream returned empty response")
		observability.FinishGenAISpan(toolSpan, observability.GenAISpanEnd{Err: emptyErr, ErrorType: "mcp_empty_response"})
		if h.instruments != nil {
			h.instruments.RecordMCPRequest(spanCtx, "tools/call", "error")
		}
		return nil, emptyErr
	}
	if resp.Error != nil {
		rpcErr := fmt.Errorf("upstream mcp error (%d): %s", resp.Error.Code, resp.Error.Message)
		observability.FinishGenAISpan(toolSpan, observability.GenAISpanEnd{Err: rpcErr, ErrorType: "mcp_rpc_error"})
		if h.instruments != nil {
			h.instruments.RecordMCPRequest(spanCtx, "tools/call", "error")
		}
		return nil, rpcErr
	}
	observability.FinishGenAISpan(toolSpan, observability.GenAISpanEnd{})
	if h.instruments != nil {
		h.instruments.RecordMCPRequest(spanCtx, "tools/call", "ok")
	}

	if err := h.evaluatePostMCPGuardrails(ctx, orgID, resp); err != nil {
		return nil, fmt.Errorf("guardrail result inspection failed: %w", err)
	}

	if err := h.recordMCPToolSpend(ctx, idCtx, orgID, reqID, targetServer, targetTool); err != nil {
		return nil, err
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

func (h *Hub) tryCallMetaTool(ctx context.Context, idCtx *domain.IdentityContext, input ToolCallInput) (*CallToolResponse, bool, error) {
	if h.progressive == nil {
		return nil, false, nil
	}
	switch input.ToolName {
	case "search_tools":
		q, _ := input.Arguments["query"].(string)
		lim := 10
		if lFloat, ok := input.Arguments["limit"].(float64); ok && lFloat > 0 {
			lim = int(lFloat)
		}
		summaries, err := h.progressive.SearchTools(ctx, idCtx, q, lim)
		if err != nil {
			return nil, true, err
		}
		resJSON, _ := json.Marshal(summaries)
		return &CallToolResponse{
			Content: []ToolContent{{Type: "text", Text: string(resJSON)}},
			IsError: false,
		}, true, nil
	case "get_tool_schema":
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
			}, true, nil
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
		}, true, nil
	default:
		return nil, false, nil
	}
}

func (h *Hub) resolveToolTarget(
	ctx context.Context,
	idCtx *domain.IdentityContext,
	orgID string,
	input ToolCallInput,
) (*domain.MCPServer, *domain.MCPTool, string, error) {
	var targetTool *domain.MCPTool
	toolName := input.ToolName
	serverSlug := strings.TrimSpace(input.ServerSlug)

	if strings.HasPrefix(toolName, HandlePrefix) && h.progressive != nil {
		rec, tool, err := h.progressive.ResolveHandleForIdentity(ctx, idCtx, toolName)
		if err != nil {
			return nil, nil, toolName, err
		}
		if rec.OrgID != orgID {
			return nil, nil, toolName, ErrHandleNotFound
		}
		if h.rbac != nil {
			if err := h.rbac.AuthorizeMCPServer(idCtx, rec.ServerSlug); err != nil {
				h.recordAudit(ctx, idCtx, "mcp.rbac.denied", "mcp_server", rec.ServerSlug, map[string]any{
					"operation": "tools/call",
					"tool_name": rec.ToolName,
					"reason":    err.Error(),
				})
				return nil, nil, toolName, err
			}
		}
		toolName = rec.ToolName
		serverSlug = rec.ServerSlug
		targetTool = tool
	}

	if serverSlug != "" {
		server, err := h.repo.GetMCPServerBySlug(ctx, orgID, serverSlug)
		if err != nil || !server.IsActive {
			return nil, nil, toolName, fmt.Errorf("mcp server %q not found or inactive", serverSlug)
		}
		if h.rbac != nil {
			if err := h.rbac.AuthorizeMCPServer(idCtx, server.Slug); err != nil {
				h.recordAudit(ctx, idCtx, "mcp.rbac.denied", "mcp_server", server.Slug, map[string]any{
					"operation": "tools/call",
					"tool_name": toolName,
					"reason":    err.Error(),
				})
				return nil, nil, toolName, err
			}
		}
		if tools, err := h.repo.ListMCPTools(ctx, server.ID); err == nil {
			for _, t := range tools {
				if t != nil && t.Name == toolName && t.IsActive {
					targetTool = t
					break
				}
			}
		}
		return server, targetTool, toolName, nil
	}

	servers, err := h.repo.ListMCPServers(ctx, orgID)
	if err != nil {
		return nil, nil, toolName, fmt.Errorf("failed to list mcp servers: %w", err)
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
			if t != nil && t.Name == toolName && t.IsActive {
				matchServers = append(matchServers, s)
				matchTools = append(matchTools, t)
				break
			}
		}
	}
	if len(matchServers) == 0 {
		return nil, nil, toolName, fmt.Errorf("tool %q not found or caller not authorized", toolName)
	}
	if len(matchServers) > 1 {
		slugs := make([]string, 0, len(matchServers))
		for _, ms := range matchServers {
			slugs = append(slugs, ms.Slug)
		}
		return nil, nil, toolName, &AmbiguousToolError{
			ToolName:        toolName,
			MatchingServers: slugs,
		}
	}
	return matchServers[0], matchTools[0], toolName, nil
}

func (h *Hub) verifyToolPinning(server *domain.MCPServer, tool *domain.MCPTool, toolName string) error {
	if server.PinnedToolHash == "" || h.guardrails == nil {
		return nil
	}
	if tool == nil {
		return fmt.Errorf("tool pinning violation: tool %q not found in catalog", toolName)
	}
	pinnedHash := tool.ToolDefHash
	if pinnedHash == "" {
		pinnedHash = server.PinnedToolHash
	}
	if err := h.guardrails.VerifyToolPinning(tool, pinnedHash); err != nil {
		return fmt.Errorf("tool pinning violation: %w", err)
	}
	return nil
}

func (h *Hub) evaluatePreMCPGuardrails(
	ctx context.Context,
	orgID, methodOrTool string,
	args map[string]any,
) error {
	if h.guardrails != nil {
		if _, err := h.guardrails.EvaluateMCPToolCall(ctx, orgID, methodOrTool, args); err != nil {
			return err
		}
	}
	return nil
}

func (h *Hub) evaluatePostMCPGuardrails(
	ctx context.Context,
	orgID string,
	resp *JSONRPCResponse,
) error {
	if resp == nil || resp.Result == nil {
		return nil
	}
	if h.guardrails != nil {
		_, redactedResult, err := h.guardrails.EvaluateMCPToolResult(ctx, orgID, resp.Result)
		if err != nil {
			return err
		}
		resp.Result = redactedResult
	}
	return nil
}

func (h *Hub) resolveUpstreamAuth(
	ctx context.Context,
	idCtx *domain.IdentityContext,
	orgID string,
	server *domain.MCPServer,
	callerMeta map[string]string,
	baseHeaders http.Header,
) (http.Header, *upstream.UpstreamAuthContext, upstream.Strategy) {
	reqHeaders := baseHeaders
	if reqHeaders == nil {
		reqHeaders = make(http.Header)
		for k, v := range callerMeta {
			reqHeaders.Set(k, v)
		}
	}

	var userCred *domain.MCPUserCredential
	teamID, userID, vkID := "", "", ""
	if idCtx != nil {
		teamID = idCtx.TeamID
		userID = idCtx.UserID
		vkID = idCtx.VirtualKeyID
		if userID != "" {
			userCred, _ = h.repo.GetMCPUserCredential(ctx, server.ID, userID)
		}
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
	return reqHeaders, authCtx, strat
}

func (h *Hub) recordMCPToolSpend(
	ctx context.Context,
	idCtx *domain.IdentityContext,
	orgID, reqID string,
	server *domain.MCPServer,
	tool *domain.MCPTool,
) error {
	if h.spendRecorder == nil || tool == nil || tool.CostPerCallMicros <= 0 {
		return nil
	}
	teamID, userID, vkID := "", "", ""
	if idCtx != nil {
		teamID = idCtx.TeamID
		userID = idCtx.UserID
		vkID = idCtx.VirtualKeyID
	}
	if err := h.spendRecorder.Record(ctx, domain.SpendEvent{
		ID:             "spend_" + uuid.NewString(),
		RequestID:      reqID,
		Protocol:       "mcp",
		ProtocolTarget: fmt.Sprintf("mcp:%s/%s", server.Slug, tool.Name),
		OrgID:          orgID,
		TeamID:         teamID,
		UserID:         userID,
		VirtualKeyID:   vkID,
		Endpoint:       "/mcp",
		CostMicros:     tool.CostPerCallMicros,
		CreatedAt:      time.Now().UTC(),
	}); err != nil {
		return fmt.Errorf("persist MCP spend event: %w", err)
	}
	return nil
}

// HTTPDispatchResult holds the structured output of an HTTP MCP dispatch across all official specs.
type HTTPDispatchResult struct {
	HTTPStatus      int
	ExtraHeaders    http.Header
	IsBatch         bool
	IsNotification  bool
	SingleResponse  *JSONRPCResponse
	BatchResponses  []*JSONRPCResponse
	SubscriptionReq *JSONRPCRequest // non-nil when `subscriptions/listen` SSE stream should be opened
}

// DispatchHTTP executes an incoming HTTP MCP JSON-RPC request (single, batch, or notification)
// enforcing the gateway's active UI-selected MCP specification profile.
func (h *Hub) DispatchHTTP(
	ctx context.Context,
	idCtx *domain.IdentityContext,
	routeKind string, // "hub", "scoped", "toolset"
	targetSlug string,
	r *http.Request,
	reqBody []byte,
) (*HTTPDispatchResult, error) {
	profile := h.ActiveProfile()
	settings := h.RuntimeSettings()

	msgs, isBatch, rpcErr := profile.ParseAndValidateBody(r, reqBody, settings.StrictSchemaValidation)
	if rpcErr != nil {
		resp := &JSONRPCResponse{
			JSONRPC: "2.0",
			Error:   rpcErr,
		}
		return &HTTPDispatchResult{
			HTTPStatus:     profile.HTTPStatusForResponse(false, resp),
			SingleResponse: resp,
		}, nil
	}

	dispatchSingle := func(parsed ParsedRPCMessage) (*JSONRPCResponse, http.Header, error) {
		switch routeKind {
		case "scoped":
			return h.dispatchScopedRequest(ctx, idCtx, targetSlug, &parsed.Request, parsed.Raw, r.Header, profile)
		case "toolset":
			return h.dispatchToolsetRequest(ctx, idCtx, targetSlug, &parsed.Request, r.Header, profile)
		default:
			return h.dispatchVirtualRequest(ctx, idCtx, &parsed.Request, r.Header, profile)
		}
	}

	if !isBatch {
		msg := msgs[0]
		if msg.Request.Method == "subscriptions/listen" && profile.Info().SupportsSubscriptionsPost {
			return &HTTPDispatchResult{
				HTTPStatus:      http.StatusOK,
				SubscriptionReq: &msg.Request,
			}, nil
		}

		resp, extraHdrs, err := dispatchSingle(msg)
		if err != nil {
			return nil, err
		}
		if msg.IsNotification && (resp == nil || resp.Error == nil) && profile.Version() != domain.MCPProtocolVersion20241105 {
			return &HTTPDispatchResult{
				HTTPStatus:     http.StatusAccepted,
				ExtraHeaders:   extraHdrs,
				IsNotification: true,
			}, nil
		}
		return &HTTPDispatchResult{
			HTTPStatus:     profile.HTTPStatusForResponse(msg.IsNotification, resp),
			ExtraHeaders:   extraHdrs,
			SingleResponse: resp,
		}, nil
	}

	batchOut := make([]*JSONRPCResponse, 0, len(msgs))
	var combinedHeaders http.Header
	for _, msg := range msgs {
		resp, extraHdrs, err := dispatchSingle(msg)
		if err != nil {
			return nil, err
		}
		if combinedHeaders == nil && len(extraHdrs) > 0 {
			combinedHeaders = extraHdrs
		}
		if !msg.IsNotification && resp != nil {
			batchOut = append(batchOut, resp)
		}
	}
	if len(batchOut) == 0 {
		return &HTTPDispatchResult{
			HTTPStatus:     http.StatusAccepted,
			ExtraHeaders:   combinedHeaders,
			IsBatch:        true,
			IsNotification: true,
		}, nil
	}
	return &HTTPDispatchResult{
		HTTPStatus:     http.StatusOK,
		ExtraHeaders:   combinedHeaders,
		IsBatch:        true,
		BatchResponses: batchOut,
	}, nil
}

// DispatchVirtualHub routes calls to the multi-server virtual hub (`POST /mcp`).
func (h *Hub) DispatchVirtualHub(
	ctx context.Context,
	idCtx *domain.IdentityContext,
	reqBody []byte,
	reqHeaders http.Header,
) (*JSONRPCResponse, http.Header, error) {
	profile := h.ActiveProfile()
	req := &http.Request{Header: reqHeaders}
	msgs, _, rpcErr := profile.ParseAndValidateBody(req, reqBody, false)
	if rpcErr != nil {
		return &JSONRPCResponse{
			JSONRPC: "2.0",
			Error:   rpcErr,
		}, nil, nil
	}
	return h.dispatchVirtualRequest(ctx, idCtx, &msgs[0].Request, reqHeaders, profile)
}

func (h *Hub) dispatchVirtualRequest(
	ctx context.Context,
	idCtx *domain.IdentityContext,
	jsonReq *JSONRPCRequest,
	reqHeaders http.Header,
	profile SpecProfile,
) (*JSONRPCResponse, http.Header, error) {
	switch jsonReq.Method {
	case "server/discover":
		if !profile.Info().SupportsServerDiscover {
			return methodNotFoundRPC(jsonReq.ID, jsonReq.Method, profile.Version()), nil, nil
		}
		return &JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      jsonReq.ID,
			Result: profile.ShapeResult("server/discover", map[string]any{
				"supportedVersions": []string{profile.Version()},
				"capabilities":      gatewayServerCapabilities(profile),
				"instructions":      "GoRoute AI Gateway MCP Virtual Hub",
			}),
		}, nil, nil
	case "initialize":
		if !profile.Info().RequiresInitialize {
			return methodNotFoundRPC(jsonReq.ID, "initialize (removed in "+profile.Version()+"; use server/discover or _meta)", profile.Version()), nil, nil
		}
		return &JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      jsonReq.ID,
			Result: map[string]any{
				"protocolVersion": profile.Version(),
				"capabilities":    gatewayServerCapabilities(profile),
				"serverInfo": map[string]any{
					"name":    "GoRoute AI Gateway MCP Hub",
					"version": profile.Version(),
				},
			},
		}, nil, nil
	case "notifications/initialized":
		if !profile.Info().RequiresInitialize {
			return methodNotFoundRPC(jsonReq.ID, jsonReq.Method, profile.Version()), nil, nil
		}
		return &JSONRPCResponse{JSONRPC: "2.0", ID: jsonReq.ID, Result: map[string]any{}}, nil, nil
	case "ping":
		if !profile.SupportsMethod("ping") {
			return methodNotFoundRPC(jsonReq.ID, jsonReq.Method, profile.Version()), nil, nil
		}
		return &JSONRPCResponse{JSONRPC: "2.0", ID: jsonReq.ID, Result: map[string]any{}}, nil, nil
	case "tools/list":
		resp, hdrs, err := h.handleVirtualToolsList(ctx, idCtx, jsonReq.ID, profile)
		if h.instruments != nil {
			status := "ok"
			if err != nil || (resp != nil && resp.Error != nil) {
				status = "error"
			}
			h.instruments.RecordMCPRequest(ctx, "tools/list", status)
		}
		return resp, hdrs, err
	case "tools/call":
		return h.handleVirtualToolsCall(ctx, idCtx, jsonReq, reqHeaders, profile)
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

func gatewayServerCapabilities(profile SpecProfile) map[string]any {
	caps := map[string]any{
		"tools": map[string]any{"listChanged": true},
	}
	if !profile.SupportsMethod("ping") {
		caps["resources"] = map[string]any{"subscribe": true, "listChanged": true}
		caps["prompts"] = map[string]any{"listChanged": true}
	}
	return caps
}

func methodNotFoundRPC(id any, method, version string) *JSONRPCResponse {
	return &JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error: &JSONRPCError{
			Code:    CodeMethodNotFound,
			Message: fmt.Sprintf("method %q not supported in MCP specification %s", method, version),
		},
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
	profile := h.ActiveProfile()
	msgs, _, rpcErr := profile.ParseAndValidateBody(&http.Request{Header: reqHeaders}, reqBody, false)
	if rpcErr != nil {
		return &JSONRPCResponse{
			JSONRPC: "2.0",
			Error:   rpcErr,
		}, nil, nil
	}
	return h.dispatchScopedRequest(ctx, idCtx, serverSlug, &msgs[0].Request, msgs[0].Raw, reqHeaders, profile)
}

func (h *Hub) dispatchScopedRequest(
	ctx context.Context,
	idCtx *domain.IdentityContext,
	serverSlug string,
	jsonReq *JSONRPCRequest,
	reqBody []byte,
	reqHeaders http.Header,
	profile SpecProfile,
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
			ID:      jsonReq.ID,
			Error: &JSONRPCError{
				Code:    CodeInvalidRequest,
				Message: fmt.Sprintf("mcp server %q not found or inactive", serverSlug),
			},
		}, nil, nil
	}

	if h.rbac != nil {
		if err := h.rbac.AuthorizeMCPServer(idCtx, serverSlug); err != nil {
			h.recordAudit(ctx, idCtx, "mcp.rbac.denied", "mcp_server", serverSlug, map[string]any{
				"operation": "jsonrpc",
				"reason":    err.Error(),
			})
			return &JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      jsonReq.ID,
				Error: &JSONRPCError{
					Code:    CodeInvalidRequest,
					Message: fmt.Sprintf("Forbidden: %v", err),
				},
			}, nil, nil
		}
	}

	if !profile.SupportsMethod(jsonReq.Method) {
		return methodNotFoundRPC(jsonReq.ID, jsonReq.Method, profile.Version()), nil, nil
	}

	if jsonReq.Method == "tools/call" {
		return h.dispatchScopedToolsCall(ctx, idCtx, serverSlug, jsonReq, reqHeaders, profile)
	}

	var cacheKey string
	if h.cache != nil && jsonReq.Method == "tools/list" {
		keyPrefix := ""
		if idCtx != nil {
			keyPrefix = idCtx.KeyPrefix
		}
		cacheKey = h.cache.ComputeCacheKey(orgID, keyPrefix, serverSlug, "tools/list", nil, server.ConfigVersion)
		if cachedResp, ok := h.cache.Get(ctx, cacheKey); ok {
			if errResp := h.verifyCachedListPinning(ctx, server, jsonReq); errResp != nil {
				return errResp, nil, nil
			}
			shapedCopy := *cachedResp
			shapedCopy.ID = jsonReq.ID
			shapedCopy.Result = h.filterScopedToolsListResult(ctx, idCtx, serverSlug, shapedCopy.Result)
			shapedCopy.Result = profile.ShapeResult(jsonReq.Method, shapedCopy.Result)
			return &shapedCopy, nil, nil
		}
	}

	isGuardedMethod := jsonReq.Method == "resources/read" || jsonReq.Method == "prompts/get"
	if isGuardedMethod && h.guardrails != nil {
		var paramsMap map[string]any
		if len(jsonReq.Params) > 0 {
			_ = json.Unmarshal(jsonReq.Params, &paramsMap)
		}
		if err := h.evaluatePreMCPGuardrails(ctx, orgID, jsonReq.Method, paramsMap); err != nil {
			return scopedJSONRPCError(jsonReq.ID, fmt.Sprintf("guardrail blocked %s: %v", jsonReq.Method, err)), nil, nil
		}
	}

	_, authCtx, strat := h.resolveUpstreamAuth(ctx, idCtx, orgID, server, nil, reqHeaders)
	resp, respHeaders, err := h.dispatcher.Dispatch(ctx, server, strat, authCtx, reqBody, reqHeaders)
	if h.instruments != nil {
		status := "ok"
		if err != nil || (resp != nil && resp.Error != nil) {
			status = "error"
		}
		h.instruments.RecordMCPRequest(ctx, jsonReq.Method, status)
	}
	if err != nil {
		return nil, respHeaders, fmt.Errorf("upstream dispatch error: %w", err)
	}
	if resp == nil {
		return nil, respHeaders, nil
	}

	if isGuardedMethod && resp.Result != nil {
		if err := h.evaluatePostMCPGuardrails(ctx, orgID, resp); err != nil {
			return scopedJSONRPCError(jsonReq.ID, fmt.Sprintf("guardrail result inspection failed: %v", err)), respHeaders, nil
		}
	}

	if cacheKey != "" && h.cache != nil && ShouldCache(jsonReq.Method, resp) {
		_ = h.cache.Set(ctx, cacheKey, resp, 5*time.Minute)
	}

	if resp.Result != nil {
		if jsonReq.Method == "tools/list" {
			resp.Result = h.filterScopedToolsListResult(ctx, idCtx, serverSlug, resp.Result)
		}
		resp.Result = profile.ShapeResult(jsonReq.Method, resp.Result)
	}
	return resp, respHeaders, nil
}

func scopedJSONRPCError(id any, message string) *JSONRPCResponse {
	return &JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error: &JSONRPCError{
			Code:    CodeInvalidRequest,
			Message: message,
		},
	}
}

func (h *Hub) dispatchScopedToolsCall(
	ctx context.Context,
	idCtx *domain.IdentityContext,
	serverSlug string,
	jsonReq *JSONRPCRequest,
	reqHeaders http.Header,
	profile SpecProfile,
) (*JSONRPCResponse, http.Header, error) {
	var toolCallParams struct {
		Name      string         `json:"name"`
		Arguments map[string]any `json:"arguments"`
	}
	if len(jsonReq.Params) > 0 {
		_ = json.Unmarshal(jsonReq.Params, &toolCallParams)
	}

	callerMeta := make(map[string]string, len(reqHeaders))
	for k := range reqHeaders {
		callerMeta[k] = reqHeaders.Get(k)
	}

	callResp, err := h.CallTool(ctx, idCtx, ToolCallInput{
		ServerSlug: serverSlug,
		ToolName:   toolCallParams.Name,
		Arguments:  toolCallParams.Arguments,
	}, CallMetadata{
		ProtocolVersion: profile.Version(),
		RequestID:       fmt.Sprint(jsonReq.ID),
		CallerMetadata:  callerMeta,
	})
	if err != nil {
		return scopedJSONRPCError(jsonReq.ID, err.Error()), nil, nil
	}

	return &JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      jsonReq.ID,
		Result:  buildCallToolResultMap(callResp, profile),
	}, nil, nil
}

func (h *Hub) verifyCachedListPinning(ctx context.Context, server *domain.MCPServer, jsonReq *JSONRPCRequest) *JSONRPCResponse {
	if server.PinnedToolHash == "" || h.guardrails == nil {
		return nil
	}
	tools, _ := h.repo.ListMCPTools(ctx, server.ID)
	for _, t := range tools {
		if err := h.guardrails.VerifyToolPinning(t, server.PinnedToolHash); err != nil {
			return scopedJSONRPCError(jsonReq.ID, fmt.Sprintf("Tool pinning violation: %v", err))
		}
	}
	return nil
}

// DispatchToolset routes calls to a curated toolset (`POST /mcp/toolsets/{toolsetSlug}`).
func (h *Hub) DispatchToolset(
	ctx context.Context,
	idCtx *domain.IdentityContext,
	toolsetSlug string,
	reqBody []byte,
	reqHeaders http.Header,
) (*JSONRPCResponse, http.Header, error) {
	profile := h.ActiveProfile()
	msgs, _, rpcErr := profile.ParseAndValidateBody(&http.Request{Header: reqHeaders}, reqBody, false)
	if rpcErr != nil {
		return &JSONRPCResponse{
			JSONRPC: "2.0",
			Error:   rpcErr,
		}, nil, nil
	}
	return h.dispatchToolsetRequest(ctx, idCtx, toolsetSlug, &msgs[0].Request, reqHeaders, profile)
}

func (h *Hub) dispatchToolsetRequest(
	ctx context.Context,
	idCtx *domain.IdentityContext,
	toolsetSlug string,
	jsonReq *JSONRPCRequest,
	reqHeaders http.Header,
	profile SpecProfile,
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
			ID:      jsonReq.ID,
			Error: &JSONRPCError{
				Code:    CodeInvalidRequest,
				Message: fmt.Sprintf("toolset %q not found or inactive", toolsetSlug),
			},
		}, nil, nil
	}
	if h.rbac != nil {
		if rbacErr := h.rbac.AuthorizeMCPToolset(idCtx, toolsetSlug); rbacErr != nil {
			h.recordAudit(ctx, idCtx, "mcp.rbac.denied", "mcp_toolset", toolsetSlug, map[string]any{
				"operation": jsonReq.Method,
				"reason":    rbacErr.Error(),
			})
			return &JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      jsonReq.ID,
				Error: &JSONRPCError{
					Code:    CodeInvalidRequest,
					Message: fmt.Sprintf("Forbidden: %v", rbacErr),
				},
			}, nil, nil
		}
	}

	switch jsonReq.Method {
	case "server/discover":
		if !profile.Info().SupportsServerDiscover {
			return methodNotFoundRPC(jsonReq.ID, jsonReq.Method, profile.Version()), nil, nil
		}
		return &JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      jsonReq.ID,
			Result: profile.ShapeResult("server/discover", map[string]any{
				"supportedVersions": []string{profile.Version()},
				"capabilities":      map[string]any{"tools": map[string]any{"listChanged": false}},
			}),
		}, nil, nil
	case "initialize":
		if !profile.Info().RequiresInitialize {
			return methodNotFoundRPC(jsonReq.ID, jsonReq.Method, profile.Version()), nil, nil
		}
		return &JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      jsonReq.ID,
			Result: map[string]any{
				"protocolVersion": profile.Version(),
				"capabilities":    map[string]any{"tools": map[string]any{"listChanged": false}},
				"serverInfo":      map[string]any{"name": "GoRoute Toolset " + toolsetSlug, "version": profile.Version()},
			},
		}, nil, nil
	case "tools/list":
		allowedTools := make([]map[string]any, 0, len(toolset.ToolIDs))
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
			if h.authorizeToolCall(ctx, idCtx, server.Slug, tool.Name, false) != nil {
				continue
			}
			inSchema := tool.InputSchema
			if inSchema == nil {
				inSchema = map[string]any{"type": "object"}
			}
			allowedTools = append(allowedTools, map[string]any{
				"name":        tool.Name,
				"description": tool.Description,
				"inputSchema": inSchema,
			})
		}
		return &JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      jsonReq.ID,
			Result: profile.ShapeResult("tools/list", map[string]any{
				"tools": allowedTools,
			}),
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
			ProtocolVersion: profile.Version(),
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

		return &JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      jsonReq.ID,
			Result:  buildCallToolResultMap(callResp, profile),
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

func (h *Hub) handleVirtualToolsList(ctx context.Context, idCtx *domain.IdentityContext, id any, profile SpecProfile) (*JSONRPCResponse, http.Header, error) {
	orgID := ""
	if idCtx != nil {
		orgID = idCtx.OrgID
	}

	servers, err := h.repo.ListMCPServers(ctx, orgID)
	if err != nil {
		return nil, nil, err
	}

	aggregatedTools := make([]map[string]any, 0)
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

		shownCount := 0
		for _, t := range tools {
			if t != nil && t.IsActive {
				if h.authorizeToolCall(ctx, idCtx, s.Slug, t.Name, false) != nil {
					continue
				}
				inSchema := t.InputSchema
				if inSchema == nil {
					inSchema = map[string]any{"type": "object"}
				}
				aggregatedTools = append(aggregatedTools, map[string]any{
					"name":        t.Name,
					"description": t.Description,
					"inputSchema": inSchema,
				})
				shownCount++
			}
		}
		serverOutcomes[s.Slug] = fmt.Sprintf("ok: %d tools", shownCount)
	}

	return &JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result: profile.ShapeResult("tools/list", map[string]any{
			"tools": aggregatedTools,
			"_meta": map[string]any{
				"goroute.ai/server_outcomes": serverOutcomes,
			},
		}),
	}, nil, nil
}

func (h *Hub) handleVirtualToolsCall(
	ctx context.Context,
	idCtx *domain.IdentityContext,
	req *JSONRPCRequest,
	reqHeaders http.Header,
	profile SpecProfile,
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
		ProtocolVersion: profile.Version(),
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

	return &JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result:  buildCallToolResultMap(callResp, profile),
	}, nil, nil
}

func buildCallToolResultMap(callResp *CallToolResponse, profile SpecProfile) map[string]any {
	content := callResp.Content
	if content == nil {
		content = []ToolContent{}
	}
	resMap := map[string]any{
		"content": content,
	}
	if callResp.IsError {
		resMap["isError"] = true
	}
	if callResp.StructuredContent != nil && profile.Info().SupportsStructuredContent {
		resMap["structuredContent"] = callResp.StructuredContent
	}
	if callResp.ResultType != "" {
		resMap["resultType"] = callResp.ResultType
	}
	if len(callResp.Meta) > 0 {
		resMap["_meta"] = callResp.Meta
	}
	if shaped, ok := profile.ShapeResult("tools/call", resMap).(map[string]any); ok {
		return shaped
	}
	return resMap
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
	if sc, exists := resMap["structuredContent"]; exists {
		callResp.StructuredContent = sc
	}
	if rt, exists := resMap["resultType"]; exists {
		if rts, ok := rt.(string); ok {
			callResp.ResultType = rts
		}
	}

	decodeContentItem := func(itemMap map[string]any) ToolContent {
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
		if uri, ok := itemMap["uri"].(string); ok {
			tc.URI = uri
		}
		if name, ok := itemMap["name"].(string); ok {
			tc.Name = name
		}
		if title, ok := itemMap["title"].(string); ok {
			tc.Title = title
		}
		if desc, ok := itemMap["description"].(string); ok {
			tc.Description = desc
		}
		if res, ok := itemMap["resource"].(map[string]any); ok {
			tc.Resource = res
		}
		if ann, ok := itemMap["annotations"].(map[string]any); ok {
			tc.Annotations = ann
		}
		if m, ok := itemMap["_meta"].(map[string]any); ok {
			tc.Meta = m
		}
		return tc
	}

	// content
	if rawContent, exists := resMap["content"]; exists {
		switch c := rawContent.(type) {
		case []ToolContent:
			callResp.Content = c
		case []any:
			for _, item := range c {
				if itemMap, ok := item.(map[string]any); ok {
					callResp.Content = append(callResp.Content, decodeContentItem(itemMap))
				}
			}
		case []map[string]any:
			for _, itemMap := range c {
				callResp.Content = append(callResp.Content, decodeContentItem(itemMap))
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
