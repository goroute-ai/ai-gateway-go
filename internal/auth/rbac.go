package auth

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

// SmartAliases lists the built-in intelligent routing aliases that bypass single-model name checks at ingress
// (their resolved concrete models are still validated against Org Subscriptions and Policies).
var SmartAliases = []string{"auto", "fast", "reasoning", "coding"}

// RBACEngine enforces Endpoint permissions, Virtual Key model scopes, Team model scopes,
// Organization Model Policies (Layer 3), and Organization Provider Subscriptions (Layer 2).
type RBACEngine struct {
	repo storage.Repository
}

func NewRBACEngine(repo storage.Repository) *RBACEngine {
	return &RBACEngine{repo: repo}
}

// AuthorizeEndpoint checks whether the authenticated Virtual Key is permitted to call the HTTP endpoint path.
func (e *RBACEngine) AuthorizeEndpoint(idCtx *domain.IdentityContext, path string) error {
	if idCtx == nil {
		return &domain.GatewayError{
			StatusCode: http.StatusUnauthorized,
			Type:       domain.ErrorTypeAuthentication,
			Code:       "unauthenticated",
			Message:    "No identity context present on request",
		}
	}
	if len(idCtx.AllowedEndpoints) == 0 {
		return nil
	}
	for _, pattern := range idCtx.AllowedEndpoints {
		if pattern == "*" || pattern == path {
			return nil
		}
		if strings.HasSuffix(pattern, "*") {
			prefix := strings.TrimSuffix(pattern, "*")
			if strings.HasPrefix(path, prefix) {
				return nil
			}
		}
	}
	return &domain.GatewayError{
		StatusCode: http.StatusForbidden,
		Type:       domain.ErrorTypePermission,
		Code:       "endpoint_not_allowed",
		Message:    fmt.Sprintf("Virtual key %s is not permitted to access endpoint %s", idCtx.KeyPrefix, path),
	}
}

// AuthorizeRequestedModel verifies Virtual Key and Team model allowlists for the requested model or smart alias.
func (e *RBACEngine) AuthorizeRequestedModel(idCtx *domain.IdentityContext, requestedModel string) error {
	if len(idCtx.KeyAllowedModels) > 0 && !matchesModelAllowlist(idCtx.KeyAllowedModels, requestedModel) {
		return &domain.GatewayError{
			StatusCode: http.StatusForbidden,
			Type:       domain.ErrorTypePermission,
			Code:       "key_model_restricted",
			Message:    fmt.Sprintf("Virtual key %s is not authorized to use model %q", idCtx.KeyPrefix, requestedModel),
		}
	}
	if len(idCtx.TeamAllowedModels) > 0 && !matchesModelAllowlist(idCtx.TeamAllowedModels, requestedModel) {
		return &domain.GatewayError{
			StatusCode: http.StatusForbidden,
			Type:       domain.ErrorTypePermission,
			Code:       "team_model_restricted",
			Message:    fmt.Sprintf("Team is not authorized to use model %q", requestedModel),
		}
	}
	return nil
}

// AuthorizeMCPServer checks 3-state RBAC allowlists for the requested MCP server slug.
func (e *RBACEngine) AuthorizeMCPServer(idCtx *domain.IdentityContext, serverSlug string) error {
	if idCtx == nil {
		return &domain.GatewayError{
			StatusCode: http.StatusUnauthorized,
			Type:       domain.ErrorTypeAuthentication,
			Code:       "unauthenticated",
			Message:    "No identity context present on request",
		}
	}
	if !domain.CheckAllowlist3State(idCtx.KeyAllowedMCPServers, idCtx.TeamAllowedMCPServers, serverSlug) {
		return &domain.GatewayError{
			StatusCode: http.StatusForbidden,
			Type:       domain.ErrorTypePermission,
			Code:       "mcp_server_restricted",
			Message:    fmt.Sprintf("Virtual key %s is not authorized to access MCP server %q", idCtx.KeyPrefix, serverSlug),
		}
	}
	return nil
}

// AuthorizeA2AAgent checks 3-state RBAC allowlists for the requested A2A agent slug.
func (e *RBACEngine) AuthorizeA2AAgent(idCtx *domain.IdentityContext, agentSlug string) error {
	if idCtx == nil {
		return &domain.GatewayError{
			StatusCode: http.StatusUnauthorized,
			Type:       domain.ErrorTypeAuthentication,
			Code:       "unauthenticated",
			Message:    "No identity context present on request",
		}
	}
	if !domain.CheckAllowlist3State(idCtx.KeyAllowedA2AAgents, idCtx.TeamAllowedA2AAgents, agentSlug) {
		return &domain.GatewayError{
			StatusCode: http.StatusForbidden,
			Type:       domain.ErrorTypePermission,
			Code:       "a2a_agent_restricted",
			Message:    fmt.Sprintf("Virtual key %s is not authorized to interact with A2A agent %q", idCtx.KeyPrefix, agentSlug),
		}
	}
	return nil
}

// AuthorizeClientApp checks 3-state RBAC allowlists for client applications.
func (e *RBACEngine) AuthorizeClientApp(idCtx *domain.IdentityContext, clientApp string) error {
	if idCtx == nil || clientApp == "" {
		return nil
	}
	if !domain.CheckAllowlist3State(idCtx.KeyAllowedClientApps, idCtx.TeamAllowedClientApps, clientApp) {
		return &domain.GatewayError{
			StatusCode: http.StatusForbidden,
			Type:       domain.ErrorTypePermission,
			Code:       "client_app_restricted",
			Message:    fmt.Sprintf("Client application %q is not authorized for virtual key %s", clientApp, idCtx.KeyPrefix),
		}
	}
	return nil
}

// AuthorizeDeployment enforces Layer 2 (Org Provider Subscription) and Layer 3 (Org Model Availability Policy)
// for a concrete Deployment before dispatching an upstream call.
func (e *RBACEngine) AuthorizeDeployment(ctx context.Context, orgID string, dep *domain.Deployment) error {
	if dep == nil || dep.GlobalModel == nil {
		return nil
	}

	// Layer 2: Check Organization Provider Subscription
	subs, err := e.repo.GetOrgProviderSubscriptions(ctx, orgID)
	if err != nil {
		return &domain.GatewayError{
			StatusCode: http.StatusInternalServerError,
			Type:       domain.ErrorTypeServer,
			Code:       "auth_repository_error",
			Message:    "Failed to verify organization provider subscriptions: " + err.Error(),
		}
	}
	if len(subs) > 0 {
		subscribed := false
		for _, s := range subs {
			if s.Provider == dep.GlobalModel.Provider && s.IsEnabled {
				subscribed = true
				break
			}
		}
		if !subscribed {
			return &domain.GatewayError{
				StatusCode: http.StatusForbidden,
				Type:       domain.ErrorTypePermission,
				Code:       "provider_not_subscribed",
				Message:    fmt.Sprintf("Organization is not subscribed to provider %q", dep.GlobalModel.Provider),
			}
		}
	}

	// Layer 3: Check Organization Model Policy
	policies, err := e.repo.GetOrgModelPolicies(ctx, orgID)
	if err != nil {
		return &domain.GatewayError{
			StatusCode: http.StatusInternalServerError,
			Type:       domain.ErrorTypeServer,
			Code:       "auth_repository_error",
			Message:    "Failed to verify organization model policies: " + err.Error(),
		}
	}
	if len(policies) > 0 {
		for _, p := range policies {
			if p.GlobalModelID == dep.GlobalModel.ID && !p.IsEnabled {
				return &domain.GatewayError{
					StatusCode: http.StatusForbidden,
					Type:       domain.ErrorTypePermission,
					Code:       "model_disabled_by_org_policy",
					Message:    fmt.Sprintf("Model %q is disabled by organization model policy", dep.GlobalModel.ID),
				}
			}
		}
	}
	return nil
}

// AuthorizeAdminAction enforces operator RBAC, organization isolation, and read-only viewer restrictions
// across Control Plane (/admin/v1/*) operations.
func AuthorizeAdminAction(op *domain.OperatorContext, targetOrgID string, write bool) error {
	if op == nil {
		return &domain.GatewayError{
			StatusCode: http.StatusUnauthorized,
			Type:       domain.ErrorTypeAuthentication,
			Code:       "unauthenticated",
			Message:    "No operator context present on request",
		}
	}

	switch op.Role {
	case domain.OperatorRolePlatformAdmin:
		return nil
	case domain.OperatorRoleOrgAdmin:
		if targetOrgID == "" {
			return &domain.GatewayError{
				StatusCode: http.StatusForbidden,
				Type:       domain.ErrorTypePermission,
				Code:       "platform_admin_required",
				Message:    "Platform admin role is required for global or cross-organization operations",
			}
		}
		if op.OrgID == "" || targetOrgID != op.OrgID {
			return &domain.GatewayError{
				StatusCode: http.StatusForbidden,
				Type:       domain.ErrorTypePermission,
				Code:       "cross_org_access_denied",
				Message:    fmt.Sprintf("Operator in organization %q is not authorized to access organization %q", op.OrgID, targetOrgID),
			}
		}
		return nil
	case domain.OperatorRoleOrgViewer:
		if write {
			return &domain.GatewayError{
				StatusCode: http.StatusForbidden,
				Type:       domain.ErrorTypePermission,
				Code:       "read_only_role",
				Message:    "Role org_viewer is read-only and cannot perform write operations",
			}
		}
		if targetOrgID == "" {
			return &domain.GatewayError{
				StatusCode: http.StatusForbidden,
				Type:       domain.ErrorTypePermission,
				Code:       "platform_admin_required",
				Message:    "Platform admin role is required for global or cross-organization operations",
			}
		}
		if op.OrgID == "" || targetOrgID != op.OrgID {
			return &domain.GatewayError{
				StatusCode: http.StatusForbidden,
				Type:       domain.ErrorTypePermission,
				Code:       "cross_org_access_denied",
				Message:    fmt.Sprintf("Operator in organization %q is not authorized to access organization %q", op.OrgID, targetOrgID),
			}
		}
		return nil
	default:
		return &domain.GatewayError{
			StatusCode: http.StatusForbidden,
			Type:       domain.ErrorTypePermission,
			Code:       "insufficient_permissions",
			Message:    fmt.Sprintf("Operator role %q is not authorized for control plane access", op.Role),
		}
	}
}

func matchesModelAllowlist(allowed []string, target string) bool {
	for _, item := range allowed {
		if item == "*" || item == target {
			return true
		}
	}
	return false
}
