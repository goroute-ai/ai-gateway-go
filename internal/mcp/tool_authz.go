package mcp

import (
	"context"

	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

// SetCustomAuthorizer attaches a post-authentication Authorizer evaluated on MCP tool calls.
func (h *Hub) SetCustomAuthorizer(authorizer auth.Authorizer) {
	if h == nil {
		return
	}
	h.customAuthorizer = authorizer
}

// authorizeToolCall enforces 3-state AllowedMCPTools RBAC on MCP tool calls.
func (h *Hub) authorizeToolCall(
	ctx context.Context,
	idCtx *domain.IdentityContext,
	serverSlug, toolName string,
	auditDenial bool,
) error {
	if h.rbac != nil {
		if err := h.rbac.AuthorizeMCPTool(idCtx, serverSlug, toolName); err != nil {
			if auditDenial {
				h.recordAudit(ctx, idCtx, "mcp.rbac.denied", "mcp_tool", serverSlug+"/"+toolName, map[string]any{
					"operation": "tools/call",
					"tool_name": toolName,
					"reason":    err.Error(),
				})
			}
			return err
		}
	}
	return nil
}

// filterScopedToolsListResult returns a shallow copy of a tools/list JSON-RPC result with unauthorized
// tools removed, never mutating cached upstream responses in place.
func (h *Hub) filterScopedToolsListResult(
	ctx context.Context,
	idCtx *domain.IdentityContext,
	serverSlug string,
	result any,
) any {
	resMap, ok := result.(map[string]any)
	if !ok || resMap == nil {
		return result
	}
	rawTools, exists := resMap["tools"]
	if !exists || rawTools == nil {
		return result
	}

	var filtered []any
	switch list := rawTools.(type) {
	case []any:
		filtered = make([]any, 0, len(list))
		for _, item := range list {
			name := ""
			if m, ok := item.(map[string]any); ok {
				name, _ = m["name"].(string)
			}
			if name != "" && h.authorizeToolCall(ctx, idCtx, serverSlug, name, false) != nil {
				continue
			}
			filtered = append(filtered, item)
		}
	case []map[string]any:
		filtered = make([]any, 0, len(list))
		for _, m := range list {
			name, _ := m["name"].(string)
			if name != "" && h.authorizeToolCall(ctx, idCtx, serverSlug, name, false) != nil {
				continue
			}
			filtered = append(filtered, m)
		}
	default:
		return result
	}

	out := make(map[string]any, len(resMap))
	for k, v := range resMap {
		out[k] = v
	}
	out["tools"] = filtered
	return out
}
