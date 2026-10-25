package mcp

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

// WithToolPolicyStore attaches an explicit ToolPolicyRepository to the MCP Hub for unconditional
// per-org/team/key blocked-tool enforcement across direct /mcp, scoped server, and toolset routes.
func WithToolPolicyStore(store storage.ToolPolicyRepository) HubOption {
	return func(h *Hub) {
		h.SetToolPolicyStore(store)
	}
}

// SetToolPolicyStore configures the ToolPolicyRepository evaluated unconditionally on MCP requests.
func (h *Hub) SetToolPolicyStore(store storage.ToolPolicyRepository) {
	if h == nil {
		return
	}
	h.toolPolicyStore = store
	if h.progressive != nil {
		h.progressive.SetToolPolicyStore(store)
	}
}

// SetCustomAuthorizer attaches a post-authentication Authorizer evaluated on MCP tool calls.
func (h *Hub) SetCustomAuthorizer(authorizer auth.Authorizer) {
	if h == nil {
		return
	}
	h.customAuthorizer = authorizer
}

func resolveEffectiveToolPolicies(ctx context.Context, store storage.ToolPolicyRepository, idCtx *domain.IdentityContext) map[string]*storage.ToolPolicy {
	if store == nil || idCtx == nil || strings.TrimSpace(idCtx.OrgID) == "" {
		return nil
	}
	policies, err := store.ResolveEffectiveToolPolicies(ctx, idCtx.OrgID, idCtx.TeamID, idCtx.VirtualKeyID)
	if err != nil {
		return nil
	}
	return policies
}

func isToolBlockedByPolicies(policies map[string]*storage.ToolPolicy, serverSlug, toolName string) bool {
	if len(policies) == 0 || strings.TrimSpace(toolName) == "" {
		return false
	}
	candidates := []string{toolName}
	if slug := strings.TrimSpace(serverSlug); slug != "" && !strings.Contains(toolName, ":") {
		candidates = append(candidates, slug+":"+toolName)
	}
	clean := strings.TrimPrefix(toolName, "mcp__")
	clean = strings.TrimPrefix(clean, "mcp_")
	if clean != toolName {
		candidates = append(candidates, clean)
	} else {
		candidates = append(candidates, "mcp_"+toolName, "mcp__"+toolName)
	}
	for _, name := range candidates {
		if p, ok := policies[name]; ok && p != nil && p.InputPolicy == storage.ToolTrustBlocked {
			return true
		}
	}
	return false
}

func (h *Hub) loadToolPolicies(ctx context.Context, idCtx *domain.IdentityContext) map[string]*storage.ToolPolicy {
	store := h.toolPolicyStore
	if store == nil && h.repo != nil {
		if tpRepo, ok := h.repo.(storage.ToolPolicyRepository); ok {
			store = tpRepo
		}
	}
	return resolveEffectiveToolPolicies(ctx, store, idCtx)
}

// authorizeToolCall enforces both positive 3-state AllowedMCPTools RBAC and unconditional stored ToolPolicy.
func (h *Hub) authorizeToolCall(
	ctx context.Context,
	idCtx *domain.IdentityContext,
	serverSlug, toolName string,
	policies map[string]*storage.ToolPolicy,
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
	if isToolBlockedByPolicies(policies, serverSlug, toolName) {
		err := &domain.GatewayError{
			StatusCode: http.StatusForbidden,
			Type:       domain.ErrorTypePermission,
			Code:       "violated_tool_policy",
			Message:    fmt.Sprintf("Tool %q is blocked by tenant tool policy", toolName),
		}
		if auditDenial {
			h.recordAudit(ctx, idCtx, "mcp.tool_policy.blocked", "mcp_tool", serverSlug+"/"+toolName, map[string]any{
				"server_slug": serverSlug,
				"tool_name":   toolName,
				"reason":      err.Message,
			})
		}
		return err
	}
	return nil
}

// filterScopedToolsListResult returns a shallow copy of a tools/list JSON-RPC result with unauthorized
// or ToolPolicy-blocked tools removed, never mutating cached upstream responses in place.
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
	policies := h.loadToolPolicies(ctx, idCtx)

	var filtered []any
	switch list := rawTools.(type) {
	case []any:
		filtered = make([]any, 0, len(list))
		for _, item := range list {
			name := ""
			if m, ok := item.(map[string]any); ok {
				name, _ = m["name"].(string)
			}
			if name != "" && h.authorizeToolCall(ctx, idCtx, serverSlug, name, policies, false) != nil {
				continue
			}
			filtered = append(filtered, item)
		}
	case []map[string]any:
		filtered = make([]any, 0, len(list))
		for _, m := range list {
			name, _ := m["name"].(string)
			if name != "" && h.authorizeToolCall(ctx, idCtx, serverSlug, name, policies, false) != nil {
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
