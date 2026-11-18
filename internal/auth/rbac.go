package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/redis/go-redis/v9"
)

// SmartAliases lists the built-in intelligent routing aliases that bypass single-model name checks at ingress
// (their resolved concrete models are still validated against Org Subscriptions and Policies).
var SmartAliases = []string{"auto", "fast", "reasoning", "coding"}

type cachedOrgSubs struct {
	subs      []*domain.OrgProviderSubscription
	expiresAt time.Time
}

type cachedOrgPolicies struct {
	policies  []*domain.OrgModelPolicy
	expiresAt time.Time
}

type cachedAccessRules struct {
	rules     []*domain.AccessGroupRule
	expiresAt time.Time
}

// RBACEngine enforces Endpoint permissions, Virtual Key model scopes, Team model scopes,
// Dynamic Access Group Rules, Organization Model Policies (Layer 3), and Organization Provider Subscriptions (Layer 2).
type RBACEngine struct {
	repo               storage.Repository
	redis              *storage.RedisFabric
	cacheTTL           time.Duration
	subCache           sync.Map // orgID -> cachedOrgSubs
	polCache           sync.Map // orgID -> cachedOrgPolicies
	ruleCache          sync.Map // orgID -> cachedAccessRules
	invalidationMu     sync.Mutex
	invalidationCancel context.CancelFunc
}

func NewRBACEngine(repo storage.Repository) *RBACEngine {
	return &RBACEngine{
		repo:     repo,
		cacheTTL: 15 * time.Second,
	}
}

// SetRedis attaches a RedisFabric for L2 caching and cross-pod invalidation of org policies.
func (e *RBACEngine) SetRedis(redisFabric *storage.RedisFabric) {
	e.redis = redisFabric
}

// InvalidateOrgPolicies evicts cached provider subscriptions and model policies for orgID.
func (e *RBACEngine) InvalidateOrgPolicies(ctx context.Context, orgID string) {
	if orgID == "" {
		return
	}
	e.subCache.Delete(orgID)
	e.polCache.Delete(orgID)
	if e.redis != nil {
		_, _ = e.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
			return rdb.Del(ctx, rbacSubsCacheKey(orgID), rbacPoliciesCacheKey(orgID)).Result()
		})
		e.redis.PublishInvalidation(ctx, storage.InvalidationEvent{
			Type:  "rbac_org",
			OrgID: orgID,
		})
	}
}

// HandleInvalidation processes a pub/sub invalidation event for org policies and dynamic access rules.
func (e *RBACEngine) HandleInvalidation(ev storage.InvalidationEvent) {
	if ev.OrgID == "" {
		return
	}
	switch ev.Type {
	case "rbac_org", "org":
		e.subCache.Delete(ev.OrgID)
		e.polCache.Delete(ev.OrgID)
		e.ruleCache.Delete(ev.OrgID)
	case "rbac_access_rules":
		e.ruleCache.Delete(ev.OrgID)
	}
}

func rbacSubsCacheKey(orgID string) string {
	return "gw:rbac:subs:" + orgID
}

func rbacPoliciesCacheKey(orgID string) string {
	return "gw:rbac:policies:" + orgID
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

// AuthorizeRequestedModel verifies Virtual Key, Project, Team Member, Team, and dynamic access group model allowlists
// for the requested model or smart alias, and enforces project model quota declaration requirements when configured.
func (e *RBACEngine) AuthorizeRequestedModel(idCtx *domain.IdentityContext, requestedModel string) error {
	if idCtx == nil {
		return &domain.GatewayError{
			StatusCode: http.StatusUnauthorized,
			Type:       domain.ErrorTypeAuthentication,
			Code:       "unauthenticated",
			Message:    "No identity context present on request",
		}
	}
	keyRestricted := len(idCtx.KeyAllowedModels) > 0 && !matchesModelAllowlist(idCtx.KeyAllowedModels, requestedModel)
	projectRestricted := len(idCtx.ProjectAllowedModels) > 0 && !matchesModelAllowlist(idCtx.ProjectAllowedModels, requestedModel)
	memberRestricted := len(idCtx.TeamMemberAllowedModels) > 0 && !matchesModelAllowlist(idCtx.TeamMemberAllowedModels, requestedModel)
	teamRestricted := len(idCtx.TeamAllowedModels) > 0 && !matchesModelAllowlist(idCtx.TeamAllowedModels, requestedModel)
	if keyRestricted || projectRestricted || memberRestricted || teamRestricted {
		// Dynamic access group rules may grant additional models for matching trusted attributes.
		dynamicallyAllowed := len(idCtx.DynamicAllowedModels) > 0 && matchesModelAllowlist(idCtx.DynamicAllowedModels, requestedModel)
		if !dynamicallyAllowed && e != nil {
			if eval, err := e.EvaluateIdentityAccessRules(context.Background(), idCtx); err == nil && matchesModelAllowlist(eval.AllowedModels, requestedModel) {
				dynamicallyAllowed = true
			}
		}
		if !dynamicallyAllowed {
			if keyRestricted {
				return &domain.GatewayError{
					StatusCode: http.StatusForbidden,
					Type:       domain.ErrorTypePermission,
					Code:       "key_model_restricted",
					Message:    fmt.Sprintf("Virtual key %s is not authorized to use model %q", idCtx.KeyPrefix, requestedModel),
				}
			}
			if projectRestricted {
				return &domain.GatewayError{
					StatusCode: http.StatusForbidden,
					Type:       domain.ErrorTypePermission,
					Code:       "project_model_restricted",
					Message:    fmt.Sprintf("Project %q is not authorized to use model %q", idCtx.ProjectID, requestedModel),
				}
			}
			if memberRestricted {
				return &domain.GatewayError{
					StatusCode: http.StatusForbidden,
					Type:       domain.ErrorTypePermission,
					Code:       "team_member_model_restricted",
					Message:    fmt.Sprintf("Team member is not authorized to use model %q", requestedModel),
				}
			}
			return &domain.GatewayError{
				StatusCode: http.StatusForbidden,
				Type:       domain.ErrorTypePermission,
				Code:       "team_model_restricted",
				Message:    fmt.Sprintf("Team is not authorized to use model %q", requestedModel),
			}
		}
	}

	if idCtx.ProjectID != "" && idCtx.ProjectEnforceModelQuota {
		if !e.hasDeclaredProjectModelQuota(idCtx, requestedModel) {
			return &domain.GatewayError{
				StatusCode: http.StatusForbidden,
				Type:       domain.ErrorTypePermission,
				Code:       "project_model_quota_required",
				Message:    fmt.Sprintf("Project %q requires positive model RPM/TPM quota limits for key %s before admitting model %q", idCtx.ProjectID, idCtx.KeyPrefix, requestedModel),
			}
		}
	}
	return nil
}

func (e *RBACEngine) hasDeclaredProjectModelQuota(idCtx *domain.IdentityContext, requestedModel string) bool {
	if idCtx == nil {
		return false
	}
	if idCtx.KeyRPMLimit > 0 || idCtx.KeyTPMLimit > 0 {
		return true
	}
	if e != nil && e.repo != nil {
		if qRepo, ok := e.repo.(storage.QuotaPolicyRepository); ok && qRepo != nil {
			policies, err := qRepo.ListQuotaPolicies(context.Background(), storage.QuotaPolicyFilter{
				OrgID:      idCtx.OrgID,
				ActiveOnly: true,
			})
			if err == nil {
				for _, qp := range policies {
					if qp == nil || !qp.IsActive {
						continue
					}
					matchesScope := ((qp.ScopeType == domain.QuotaScopeProject || qp.ScopeType == domain.QuotaScopeModelPerProject) && qp.ScopeID == idCtx.ProjectID) ||
						(qp.ScopeType == domain.QuotaScopeModelPerKey && idCtx.VirtualKeyID != "" && qp.ScopeID == idCtx.VirtualKeyID)
					if !matchesScope {
						continue
					}
					pattern := strings.TrimSpace(qp.ModelPattern)
					if pattern != "" && pattern != "*" && !matchesModelAllowlist([]string{pattern}, requestedModel) {
						continue
					}
					if qp.RPMLimit > 0 || qp.TPMLimit > 0 || qp.ITPMLimit > 0 || qp.OTPMLimit > 0 || qp.TPDLimit > 0 {
						return true
					}
				}
			}
		}
	}
	return false
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
	subs, err := e.getOrgProviderSubscriptions(ctx, orgID)
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
	policies, err := e.getOrgModelPolicies(ctx, orgID)
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

func (e *RBACEngine) getOrgProviderSubscriptions(ctx context.Context, orgID string) ([]*domain.OrgProviderSubscription, error) {
	now := time.Now().UTC()
	if val, ok := e.subCache.Load(orgID); ok {
		entry := val.(cachedOrgSubs)
		if now.Before(entry.expiresAt) {
			return entry.subs, nil
		}
		e.subCache.Delete(orgID)
	}
	if e.redis != nil {
		res, err := e.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
			return rdb.Get(ctx, rbacSubsCacheKey(orgID)).Result()
		})
		if err == nil {
			if jsonStr, ok := res.(string); ok && jsonStr != "" {
				var subs []*domain.OrgProviderSubscription
				if json.Unmarshal([]byte(jsonStr), &subs) == nil {
					e.subCache.Store(orgID, cachedOrgSubs{subs: subs, expiresAt: now.Add(e.cacheTTL)})
					return subs, nil
				}
			}
		}
	}
	subs, err := e.repo.GetOrgProviderSubscriptions(ctx, orgID)
	if err != nil {
		return nil, err
	}
	if e.redis != nil {
		if b, mErr := json.Marshal(subs); mErr == nil {
			_, _ = e.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
				return rdb.Set(ctx, rbacSubsCacheKey(orgID), b, e.cacheTTL).Result()
			})
		}
	}
	e.subCache.Store(orgID, cachedOrgSubs{subs: subs, expiresAt: now.Add(e.cacheTTL)})
	return subs, nil
}

func (e *RBACEngine) getOrgModelPolicies(ctx context.Context, orgID string) ([]*domain.OrgModelPolicy, error) {
	now := time.Now().UTC()
	if val, ok := e.polCache.Load(orgID); ok {
		entry := val.(cachedOrgPolicies)
		if now.Before(entry.expiresAt) {
			return entry.policies, nil
		}
		e.polCache.Delete(orgID)
	}
	if e.redis != nil {
		res, err := e.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
			return rdb.Get(ctx, rbacPoliciesCacheKey(orgID)).Result()
		})
		if err == nil {
			if jsonStr, ok := res.(string); ok && jsonStr != "" {
				var policies []*domain.OrgModelPolicy
				if json.Unmarshal([]byte(jsonStr), &policies) == nil {
					e.polCache.Store(orgID, cachedOrgPolicies{policies: policies, expiresAt: now.Add(e.cacheTTL)})
					return policies, nil
				}
			}
		}
	}
	policies, err := e.repo.GetOrgModelPolicies(ctx, orgID)
	if err != nil {
		return nil, err
	}
	if e.redis != nil {
		if b, mErr := json.Marshal(policies); mErr == nil {
			_, _ = e.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
				return rdb.Set(ctx, rbacPoliciesCacheKey(orgID), b, e.cacheTTL).Result()
			})
		}
	}
	e.polCache.Store(orgID, cachedOrgPolicies{policies: policies, expiresAt: now.Add(e.cacheTTL)})
	return policies, nil
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
	case domain.OperatorRoleTeamAdmin:
		return &domain.GatewayError{
			StatusCode: http.StatusForbidden,
			Type:       domain.ErrorTypePermission,
			Code:       "insufficient_permissions",
			Message:    "Operator role \"team_admin\" is not authorized for organization-wide or platform control plane operations",
		}
	default:
		return &domain.GatewayError{
			StatusCode: http.StatusForbidden,
			Type:       domain.ErrorTypePermission,
			Code:       "insufficient_permissions",
			Message:    fmt.Sprintf("Operator role %q is not authorized for control plane access", op.Role),
		}
	}
}

// AuthorizeTeamAdminAction enforces team-scoped Control Plane RBAC.
// Platform admins, org admins (within own org), and org viewers (read-only within own org)
// follow AuthorizeAdminAction semantics; team_admin operators strictly require
// op.OrgID == targetOrgID && op.TeamID != "" && op.TeamID == targetTeamID.
func AuthorizeTeamAdminAction(op *domain.OperatorContext, targetOrgID, targetTeamID string, write bool) error {
	if op == nil {
		return &domain.GatewayError{
			StatusCode: http.StatusUnauthorized,
			Type:       domain.ErrorTypeAuthentication,
			Code:       "unauthenticated",
			Message:    "No operator context present on request",
		}
	}

	switch op.Role {
	case domain.OperatorRolePlatformAdmin, domain.OperatorRoleOrgAdmin, domain.OperatorRoleOrgViewer:
		return AuthorizeAdminAction(op, targetOrgID, write)
	case domain.OperatorRoleTeamAdmin:
		if op.OrgID == "" || targetOrgID == "" || op.OrgID != targetOrgID {
			return &domain.GatewayError{
				StatusCode: http.StatusForbidden,
				Type:       domain.ErrorTypePermission,
				Code:       "cross_org_access_denied",
				Message:    fmt.Sprintf("Operator in organization %q is not authorized to access organization %q", op.OrgID, targetOrgID),
			}
		}
		if op.TeamID == "" {
			return &domain.GatewayError{
				StatusCode: http.StatusForbidden,
				Type:       domain.ErrorTypePermission,
				Code:       "team_scope_required",
				Message:    "Operator with role team_admin must be scoped to an active team",
			}
		}
		if targetTeamID == "" || op.TeamID != targetTeamID {
			return &domain.GatewayError{
				StatusCode: http.StatusForbidden,
				Type:       domain.ErrorTypePermission,
				Code:       "cross_team_access_denied",
				Message:    fmt.Sprintf("Operator in team %q is not authorized to access team %q", op.TeamID, targetTeamID),
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
		if strings.HasSuffix(item, "*") {
			prefix := strings.TrimSuffix(item, "*")
			if prefix != "" && strings.HasPrefix(target, prefix) {
				return true
			}
		}
	}
	return false
}
