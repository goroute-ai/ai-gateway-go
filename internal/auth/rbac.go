package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/redis/go-redis/v9"
	"golang.org/x/sync/singleflight"
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
	magCache           sync.Map // orgID -> cachedSlice[*domain.ModelAccessGroup]
	quotaPolicyCache   sync.Map // orgID -> cachedSlice[*domain.QuotaPolicy]
	tagCache           sync.Map // orgID -> cachedSlice[*domain.Tag]
	budgetWindowCache  sync.Map // orgID -> cachedSlice[*domain.BudgetWindowLimit]
	endUserCache       sync.Map // orgID+"\x00"+externalID -> cachedValue[*domain.EndUser]
	cacheFlight        singleflight.Group
	invalidationMu     sync.Mutex
	invalidationCancel context.CancelFunc
}

type cachedSlice[T any] struct {
	items     []T
	expiresAt time.Time
}

type cachedValue[T any] struct {
	val       T
	expiresAt time.Time
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

// InvalidatePolicyScope evicts cached org-scoped governance policies ("rbac_mag", "rbac_quotas", "rbac_tags", "rbac_bw")
// locally, in L2 Redis, and across pods via Pub/Sub.
func (e *RBACEngine) InvalidatePolicyScope(ctx context.Context, scopeType, orgID string) {
	if e == nil || orgID == "" {
		return
	}
	var redisKey string
	switch scopeType {
	case "rbac_mag":
		e.magCache.Delete(orgID)
		redisKey = rbacMAGCacheKey(orgID)
	case "rbac_quotas":
		e.quotaPolicyCache.Delete(orgID)
		redisKey = rbacQuotasCacheKey(orgID)
	case "rbac_tags":
		e.tagCache.Delete(orgID)
		redisKey = rbacTagsCacheKey(orgID)
	case "rbac_bw":
		e.budgetWindowCache.Delete(orgID)
		redisKey = rbacBWCacheKey(orgID)
	default:
		return
	}
	if e.redis != nil {
		if redisKey != "" {
			_, _ = e.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
				return rdb.Del(ctx, redisKey).Result()
			})
		}
		e.redis.PublishInvalidation(ctx, storage.InvalidationEvent{
			Type:  scopeType,
			OrgID: orgID,
		})
	}
}

// HandleInvalidation processes a pub/sub invalidation event for org policies, governance caches, and access rules.
func (e *RBACEngine) HandleInvalidation(ev storage.InvalidationEvent) {
	if ev.OrgID == "" {
		return
	}
	switch ev.Type {
	case "rbac_org", "org":
		e.subCache.Delete(ev.OrgID)
		e.polCache.Delete(ev.OrgID)
		e.ruleCache.Delete(ev.OrgID)
		e.magCache.Delete(ev.OrgID)
		e.quotaPolicyCache.Delete(ev.OrgID)
		e.tagCache.Delete(ev.OrgID)
		e.budgetWindowCache.Delete(ev.OrgID)
	case "rbac_access_rules":
		e.ruleCache.Delete(ev.OrgID)
	case "rbac_mag":
		e.magCache.Delete(ev.OrgID)
	case "rbac_quotas":
		e.quotaPolicyCache.Delete(ev.OrgID)
	case "rbac_tags":
		e.tagCache.Delete(ev.OrgID)
	case "rbac_bw":
		e.budgetWindowCache.Delete(ev.OrgID)
	case "rbac_enduser":
		if ev.EntityID != "" {
			e.endUserCache.Delete(ev.OrgID + "\x00" + ev.EntityID)
		}
	}
}

func rbacSubsCacheKey(orgID string) string {
	return "gw:rbac:subs:" + orgID
}

func rbacPoliciesCacheKey(orgID string) string {
	return "gw:rbac:policies:" + orgID
}

func rbacMAGCacheKey(orgID string) string {
	return "gw:rbac:mag:" + orgID
}

func rbacQuotasCacheKey(orgID string) string {
	return "gw:rbac:quotas:" + orgID
}

func rbacTagsCacheKey(orgID string) string {
	return "gw:rbac:tags:" + orgID
}

func rbacBWCacheKey(orgID string) string {
	return "gw:rbac:bw:" + orgID
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
	_, err := e.AuthorizeRequestedModelWithEval(idCtx, requestedModel)
	return err
}

// AuthorizeRequestedModelWithEval enforces AuthorizeRequestedModel and returns the ModelAccessGroupEvaluation
// computed during authorization so downstream quota descriptor builders can reuse it with zero extra lookups.
func (e *RBACEngine) AuthorizeRequestedModelWithEval(idCtx *domain.IdentityContext, requestedModel string) (ModelAccessGroupEvaluation, error) {
	if idCtx == nil {
		return ModelAccessGroupEvaluation{}, &domain.GatewayError{
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

	allowDynamic := !projectRestricted && !memberRestricted && idCtx.DelegatedUserID == "" && idCtx.DelegatedTeamID == ""
	accessGroups := idCtx.AccessGroups
	dynamicAllowedModels := idCtx.DynamicAllowedModels
	if idCtx.DelegatedUserID == "" && idCtx.DelegatedTeamID == "" && e != nil && (len(accessGroups) == 0 || (allowDynamic && len(dynamicAllowedModels) == 0 && (keyRestricted || teamRestricted))) {
		if eval, err := e.EvaluateIdentityAccessRules(context.Background(), idCtx); err == nil {
			if len(accessGroups) == 0 && len(eval.AccessGroups) > 0 {
				accessGroups = eval.AccessGroups
			}
			if allowDynamic && len(dynamicAllowedModels) == 0 && len(eval.AllowedModels) > 0 {
				dynamicAllowedModels = eval.AllowedModels
			}
		}
	}

	var magEval ModelAccessGroupEvaluation
	if e != nil && e.repo != nil {
		eval, err := e.EvaluateModelAccessGroupsWithCache(context.Background(), idCtx, requestedModel, accessGroups)
		if err != nil {
			return ModelAccessGroupEvaluation{}, &domain.GatewayError{
				StatusCode: http.StatusServiceUnavailable,
				Type:       domain.ErrorTypeServer,
				Code:       "model_access_group_unavailable",
				Message:    "Unable to evaluate model access group policies",
				Retryable:  true,
			}
		}
		magEval = eval
	}

	if magEval.GatedByGroup && !magEval.MatchedGatedGroup {
		return magEval, &domain.GatewayError{
			StatusCode: http.StatusForbidden,
			Type:       domain.ErrorTypePermission,
			Code:       "model_access_group_denied",
			Message:    fmt.Sprintf("Identity %s is not a member of any model access group authorizing model %q", idCtx.KeyPrefix, requestedModel),
		}
	}

	if keyRestricted || projectRestricted || memberRestricted || teamRestricted {
		// Dynamic access group rules or ModelAccessGroup memberships may grant additional models,
		// unless explicitly restricted by project, team-member, or delegated agent narrowing.
		dynamicallyAllowed := allowDynamic && len(dynamicAllowedModels) > 0 && matchesModelAllowlist(dynamicAllowedModels, requestedModel)
		if !dynamicallyAllowed {
			dynamicallyAllowed = (!keyRestricted || magEval.GrantedForKey) &&
				(!projectRestricted || magEval.GrantedForProject) &&
				(!memberRestricted || magEval.GrantedForMember) &&
				(!teamRestricted || magEval.GrantedForTeam) &&
				magEval.GrantedForAny
		}
		if !dynamicallyAllowed {
			if keyRestricted {
				return magEval, &domain.GatewayError{
					StatusCode: http.StatusForbidden,
					Type:       domain.ErrorTypePermission,
					Code:       "key_model_restricted",
					Message:    fmt.Sprintf("Virtual key %s is not authorized to use model %q", idCtx.KeyPrefix, requestedModel),
				}
			}
			if projectRestricted {
				return magEval, &domain.GatewayError{
					StatusCode: http.StatusForbidden,
					Type:       domain.ErrorTypePermission,
					Code:       "project_model_restricted",
					Message:    fmt.Sprintf("Project %q is not authorized to use model %q", idCtx.ProjectID, requestedModel),
				}
			}
			if memberRestricted {
				return magEval, &domain.GatewayError{
					StatusCode: http.StatusForbidden,
					Type:       domain.ErrorTypePermission,
					Code:       "team_member_model_restricted",
					Message:    fmt.Sprintf("Team member is not authorized to use model %q", requestedModel),
				}
			}
			return magEval, &domain.GatewayError{
				StatusCode: http.StatusForbidden,
				Type:       domain.ErrorTypePermission,
				Code:       "team_model_restricted",
				Message:    fmt.Sprintf("Team is not authorized to use model %q", requestedModel),
			}
		}
	}

	if idCtx.ProjectID != "" && idCtx.ProjectEnforceModelQuota {
		if !e.hasDeclaredProjectModelQuota(idCtx, requestedModel) {
			return magEval, &domain.GatewayError{
				StatusCode: http.StatusForbidden,
				Type:       domain.ErrorTypePermission,
				Code:       "project_model_quota_required",
				Message:    fmt.Sprintf("Project %q requires positive model RPM/TPM quota limits for key %s before admitting model %q", idCtx.ProjectID, idCtx.KeyPrefix, requestedModel),
			}
		}
	}
	return magEval, nil
}

func (e *RBACEngine) hasDeclaredProjectModelQuota(idCtx *domain.IdentityContext, requestedModel string) bool {
	if idCtx == nil {
		return false
	}
	if idCtx.KeyRPMLimit > 0 || idCtx.KeyTPMLimit > 0 {
		return true
	}
	if e != nil {
		policies, err := e.GetCachedQuotaPolicies(context.Background(), idCtx.OrgID)
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

// MatchesModelPattern reports whether target matches pattern where '*' matches zero or more
// arbitrary characters (linear-time two-pointer scan, safe against regex backtracking).
func MatchesModelPattern(pattern, target string) bool {
	if pattern == "" {
		return false
	}
	if pattern == "*" {
		return true
	}
	if !strings.Contains(pattern, "*") {
		return pattern == target
	}
	pi, ti := 0, 0
	starIdx, matchIdx := -1, 0
	for ti < len(target) {
		if pi < len(pattern) && pattern[pi] == target[ti] {
			pi++
			ti++
		} else if pi < len(pattern) && pattern[pi] == '*' {
			starIdx = pi
			matchIdx = ti
			pi++
		} else if starIdx != -1 {
			pi = starIdx + 1
			matchIdx++
			ti = matchIdx
		} else {
			return false
		}
	}
	for pi < len(pattern) && pattern[pi] == '*' {
		pi++
	}
	return pi == len(pattern)
}

func matchesModelAllowlist(allowed []string, target string) bool {
	for _, item := range allowed {
		if MatchesModelPattern(item, target) {
			return true
		}
	}
	return false
}

func loadOrgCachedSlice[T any](
	ctx context.Context,
	e *RBACEngine,
	cache *sync.Map,
	flightPrefix string,
	redisKey string,
	orgID string,
	fetcher func(context.Context) ([]T, error),
) ([]T, error) {
	if e == nil || orgID == "" {
		return fetcher(ctx)
	}
	now := time.Now().UTC()
	if val, ok := cache.Load(orgID); ok {
		entry := val.(cachedSlice[T])
		if now.Before(entry.expiresAt) {
			return entry.items, nil
		}
		cache.Delete(orgID)
	}
	val, err, _ := e.cacheFlight.Do(flightPrefix+":"+orgID, func() (any, error) {
		now := time.Now().UTC()
		if val, ok := cache.Load(orgID); ok {
			entry := val.(cachedSlice[T])
			if now.Before(entry.expiresAt) {
				return entry.items, nil
			}
			cache.Delete(orgID)
		}
		if e.redis != nil && redisKey != "" {
			res, rErr := e.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
				return rdb.Get(ctx, redisKey).Result()
			})
			if rErr == nil {
				if jsonStr, ok := res.(string); ok && jsonStr != "" {
					var items []T
					if json.Unmarshal([]byte(jsonStr), &items) == nil {
						cache.Store(orgID, cachedSlice[T]{items: items, expiresAt: now.Add(e.cacheTTL)})
						return items, nil
					}
				}
			}
		}
		items, fErr := fetcher(ctx)
		if fErr != nil {
			return nil, fErr
		}
		if e.redis != nil && redisKey != "" {
			if b, mErr := json.Marshal(items); mErr == nil {
				_, _ = e.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
					return rdb.Set(ctx, redisKey, b, e.cacheTTL).Result()
				})
			}
		}
		cache.Store(orgID, cachedSlice[T]{items: items, expiresAt: now.Add(e.cacheTTL)})
		return items, nil
	})
	if err != nil {
		return nil, err
	}
	out, _ := val.([]T)
	return out, nil
}

// GetCachedModelAccessGroups returns active org-scoped ModelAccessGroups from L1/L2 cache or storage.
func (e *RBACEngine) GetCachedModelAccessGroups(ctx context.Context, orgID string) ([]*domain.ModelAccessGroup, error) {
	if e == nil || e.repo == nil || orgID == "" {
		return nil, nil
	}
	magRepo, ok := e.repo.(storage.ModelAccessGroupRepository)
	if !ok || magRepo == nil {
		return nil, nil
	}
	return loadOrgCachedSlice(ctx, e, &e.magCache, "mag", rbacMAGCacheKey(orgID), orgID, func(lookupCtx context.Context) ([]*domain.ModelAccessGroup, error) {
		groups, err := magRepo.ListModelAccessGroups(lookupCtx, storage.ModelAccessGroupFilter{
			OrgID:      orgID,
			ActiveOnly: true,
		})
		if err != nil || len(groups) == 0 {
			return groups, err
		}
		needsMemberHydration := false
		for _, g := range groups {
			if g != nil && g.Members == nil {
				needsMemberHydration = true
				break
			}
		}
		if needsMemberHydration {
			if members, memErr := magRepo.ListModelAccessGroupMembersByOrg(lookupCtx, orgID); memErr == nil {
				byGroup := make(map[string][]*domain.ModelAccessGroupMember)
				for _, m := range members {
					if m != nil && m.GroupID != "" {
						byGroup[m.GroupID] = append(byGroup[m.GroupID], m)
					}
				}
				for _, g := range groups {
					if g != nil && g.Members == nil {
						if list := byGroup[g.ID]; list != nil {
							g.Members = list
						} else {
							g.Members = []*domain.ModelAccessGroupMember{}
						}
					}
				}
			}
		}
		return groups, nil
	})
}

// GetCachedQuotaPolicies returns active org-scoped QuotaPolicies from L1/L2 cache or storage.
func (e *RBACEngine) GetCachedQuotaPolicies(ctx context.Context, orgID string) ([]*domain.QuotaPolicy, error) {
	if e == nil || e.repo == nil || orgID == "" {
		return nil, nil
	}
	qpRepo, ok := e.repo.(storage.QuotaPolicyRepository)
	if !ok || qpRepo == nil {
		return nil, nil
	}
	return loadOrgCachedSlice(ctx, e, &e.quotaPolicyCache, "qp", rbacQuotasCacheKey(orgID), orgID, func(lookupCtx context.Context) ([]*domain.QuotaPolicy, error) {
		return qpRepo.ListQuotaPolicies(lookupCtx, storage.QuotaPolicyFilter{
			OrgID:      orgID,
			ActiveOnly: true,
		})
	})
}

// GetCachedTags returns org-scoped Tags from L1/L2 cache or storage.
func (e *RBACEngine) GetCachedTags(ctx context.Context, orgID string) ([]*domain.Tag, error) {
	if e == nil || e.repo == nil || orgID == "" {
		return nil, nil
	}
	tagRepo, ok := e.repo.(storage.TagRepository)
	if !ok || tagRepo == nil {
		return nil, nil
	}
	return loadOrgCachedSlice(ctx, e, &e.tagCache, "tag", rbacTagsCacheKey(orgID), orgID, func(lookupCtx context.Context) ([]*domain.Tag, error) {
		return tagRepo.ListTags(lookupCtx, storage.TagFilter{OrgID: orgID})
	})
}

// GetCachedBudgetWindowLimits returns org-scoped BudgetWindowLimits from L1/L2 cache or storage.
func (e *RBACEngine) GetCachedBudgetWindowLimits(ctx context.Context, orgID string) ([]*domain.BudgetWindowLimit, error) {
	if e == nil || e.repo == nil || orgID == "" {
		return nil, nil
	}
	bwRepo, ok := e.repo.(storage.BudgetWindowRepository)
	if !ok || bwRepo == nil {
		return nil, nil
	}
	return loadOrgCachedSlice(ctx, e, &e.budgetWindowCache, "bw", rbacBWCacheKey(orgID), orgID, func(lookupCtx context.Context) ([]*domain.BudgetWindowLimit, error) {
		return bwRepo.ListBudgetWindowLimits(lookupCtx, storage.BudgetWindowFilter{OrgID: orgID})
	})
}

// GetOrCreateCachedEndUser resolves an EndUser by (orgID, externalID) using a short-TTL L1 cache + singleflight.
func (e *RBACEngine) GetOrCreateCachedEndUser(ctx context.Context, orgID, externalID string) (*domain.EndUser, error) {
	if e == nil || e.repo == nil || orgID == "" || strings.TrimSpace(externalID) == "" {
		return nil, nil
	}
	euRepo, ok := e.repo.(storage.EndUserRepository)
	if !ok || euRepo == nil {
		return nil, nil
	}
	externalID = strings.TrimSpace(externalID)
	cacheKey := orgID + "\x00" + externalID
	now := time.Now().UTC()
	if val, hit := e.endUserCache.Load(cacheKey); hit {
		entry := val.(cachedValue[*domain.EndUser])
		if now.Before(entry.expiresAt) {
			return entry.val, nil
		}
		e.endUserCache.Delete(cacheKey)
	}
	v, err, _ := e.cacheFlight.Do("eu:"+cacheKey, func() (any, error) {
		eu, err := euRepo.GetOrCreateEndUser(ctx, orgID, externalID)
		if err != nil {
			return nil, err
		}
		if eu != nil {
			e.endUserCache.Store(cacheKey, cachedValue[*domain.EndUser]{
				val:       eu,
				expiresAt: time.Now().UTC().Add(e.cacheTTL),
			})
		}
		return eu, nil
	})
	if err != nil {
		return nil, err
	}
	eu, _ := v.(*domain.EndUser)
	return eu, nil
}

// InvalidateEndUser evicts a single cached EndUser entry and broadcasts Pub/Sub eviction.
func (e *RBACEngine) InvalidateEndUser(ctx context.Context, orgID, externalID string) {
	if e == nil || orgID == "" || externalID == "" {
		return
	}
	e.endUserCache.Delete(orgID + "\x00" + strings.TrimSpace(externalID))
	if e.redis != nil {
		e.redis.PublishInvalidation(ctx, storage.InvalidationEvent{
			Type:     "rbac_enduser",
			OrgID:    orgID,
			EntityID: strings.TrimSpace(externalID),
		})
	}
}

// ModelAccessGroupEvaluation summarizes active ModelAccessGroup matches for an identity and model.
type ModelAccessGroupEvaluation struct {
	MatchingGroups    []*domain.ModelAccessGroup
	GatedByGroup      bool
	MatchedGatedGroup bool
	GrantedForKey     bool
	GrantedForTeam    bool
	GrantedForProject bool
	GrantedForMember  bool
	GrantedForAny     bool
}

// EvaluateModelAccessGroupsWithCache evaluates active org-scoped ModelAccessGroups using RBACEngine's L1/L2 cache.
func (e *RBACEngine) EvaluateModelAccessGroupsWithCache(
	ctx context.Context,
	idCtx *domain.IdentityContext,
	requestedModel string,
	accessGroups []string,
) (ModelAccessGroupEvaluation, error) {
	var eval ModelAccessGroupEvaluation
	if e == nil || e.repo == nil || idCtx == nil || idCtx.OrgID == "" || strings.TrimSpace(requestedModel) == "" {
		return eval, nil
	}
	groups, err := e.GetCachedModelAccessGroups(ctx, idCtx.OrgID)
	if err != nil {
		return eval, err
	}
	if len(groups) == 0 {
		return eval, nil
	}
	var members []*domain.ModelAccessGroupMember
	allHydrated := true
	for _, g := range groups {
		if g == nil {
			continue
		}
		if g.Members == nil {
			allHydrated = false
			break
		}
		members = append(members, g.Members...)
	}
	if !allHydrated {
		if magRepo, ok := e.repo.(storage.ModelAccessGroupRepository); ok && magRepo != nil {
			mList, mErr := magRepo.ListModelAccessGroupMembersByOrg(ctx, idCtx.OrgID)
			if mErr != nil {
				return eval, mErr
			}
			members = mList
		}
	}
	return evaluateModelAccessGroupsFromData(idCtx, requestedModel, accessGroups, groups, members), nil
}

// EvaluateModelAccessGroups evaluates active org-scoped ModelAccessGroups and their members
// against an authenticated IdentityContext and requested model.
func EvaluateModelAccessGroups(
	ctx context.Context,
	repo storage.Repository,
	idCtx *domain.IdentityContext,
	requestedModel string,
	accessGroups []string,
) (ModelAccessGroupEvaluation, error) {
	var eval ModelAccessGroupEvaluation
	if repo == nil || idCtx == nil || idCtx.OrgID == "" || strings.TrimSpace(requestedModel) == "" {
		return eval, nil
	}
	magRepo, ok := repo.(storage.ModelAccessGroupRepository)
	if !ok || magRepo == nil {
		return eval, nil
	}
	groups, err := magRepo.ListModelAccessGroups(ctx, storage.ModelAccessGroupFilter{
		OrgID:      idCtx.OrgID,
		ActiveOnly: true,
	})
	if err != nil {
		return eval, err
	}
	if len(groups) == 0 {
		return eval, nil
	}
	members, err := magRepo.ListModelAccessGroupMembersByOrg(ctx, idCtx.OrgID)
	if err != nil {
		return eval, err
	}
	return evaluateModelAccessGroupsFromData(idCtx, requestedModel, accessGroups, groups, members), nil
}

func evaluateModelAccessGroupsFromData(
	idCtx *domain.IdentityContext,
	requestedModel string,
	accessGroups []string,
	groups []*domain.ModelAccessGroup,
	members []*domain.ModelAccessGroupMember,
) ModelAccessGroupEvaluation {
	var eval ModelAccessGroupEvaluation
	modelMembersByGroup := make(map[string][]string)
	principalMembersByGroup := make(map[string][]*domain.ModelAccessGroupMember)
	for _, m := range members {
		if m == nil || m.OrgID != idCtx.OrgID || m.GroupID == "" {
			continue
		}
		if m.MemberType == domain.ModelAccessGroupMemberModel {
			modelMembersByGroup[m.GroupID] = append(modelMembersByGroup[m.GroupID], m.MemberID)
			continue
		}
		principalMembersByGroup[m.GroupID] = append(principalMembersByGroup[m.GroupID], m)
	}

	allowDynamic := idCtx.DelegatedUserID == "" && idCtx.DelegatedTeamID == ""
	for _, g := range groups {
		if g == nil || !g.IsActive || g.OrgID != idCtx.OrgID {
			continue
		}
		if !matchesModelAllowlist(modelMembersByGroup[g.ID], requestedModel) {
			continue
		}

		principals := principalMembersByGroup[g.ID]
		keyMatch := false
		teamMatch := false
		userMatch := false
		projectMatch := false
		orgMatch := false
		for _, m := range principals {
			switch m.MemberType {
			case domain.ModelAccessGroupMemberKey:
				if idCtx.VirtualKeyID != "" && m.MemberID == idCtx.VirtualKeyID {
					keyMatch = true
				}
			case domain.ModelAccessGroupMemberTeam:
				if idCtx.TeamID != "" && idCtx.DelegatedTeamID == "" && m.MemberID == idCtx.TeamID {
					teamMatch = true
				}
			case domain.ModelAccessGroupMemberUser:
				if idCtx.UserID != "" && idCtx.DelegatedUserID == "" && m.MemberID == idCtx.UserID {
					userMatch = true
				}
			case domain.ModelAccessGroupMemberProject:
				if idCtx.ProjectID != "" && m.MemberID == idCtx.ProjectID {
					projectMatch = true
				}
			case domain.ModelAccessGroupMemberOrg:
				if idCtx.OrgID != "" && m.MemberID == idCtx.OrgID {
					orgMatch = true
				}
			}
		}
		ruleGroupMatch := allowDynamic && hasModelAccessGroupRef(accessGroups, g)
		principalMatched := keyMatch || teamMatch || userMatch || projectMatch || orgMatch || ruleGroupMatch

		keyRef := hasModelAccessGroupRef(idCtx.KeyAllowedModels, g)
		teamRef := hasModelAccessGroupRef(idCtx.TeamAllowedModels, g)
		projRef := hasModelAccessGroupRef(idCtx.ProjectAllowedModels, g)
		memberRef := hasModelAccessGroupRef(idCtx.TeamMemberAllowedModels, g)
		dynRef := allowDynamic && hasModelAccessGroupRef(idCtx.DynamicAllowedModels, g)

		if len(principals) > 0 {
			eval.GatedByGroup = true
			if !principalMatched {
				continue
			}
			eval.MatchedGatedGroup = true
			eval.MatchingGroups = append(eval.MatchingGroups, g)
			eval.GrantedForAny = true
			if keyMatch || keyRef || ruleGroupMatch || len(idCtx.KeyAllowedModels) == 0 {
				eval.GrantedForKey = true
			}
			if teamMatch || teamRef || ruleGroupMatch || len(idCtx.TeamAllowedModels) == 0 {
				eval.GrantedForTeam = true
			}
			if projectMatch || projRef || len(idCtx.ProjectAllowedModels) == 0 {
				eval.GrantedForProject = true
			}
			if userMatch || memberRef || len(idCtx.TeamMemberAllowedModels) == 0 {
				eval.GrantedForMember = true
			}
			continue
		}

		// Ungated group: applies as a shared org-wide quota pool and also grants access
		// when referenced by name or ID in an identity allowlist or AccessGroups.
		eval.MatchingGroups = append(eval.MatchingGroups, g)
		if keyRef || teamRef || projRef || memberRef || dynRef || ruleGroupMatch {
			eval.GrantedForAny = true
			if keyRef || ruleGroupMatch || len(idCtx.KeyAllowedModels) == 0 {
				eval.GrantedForKey = true
			}
			if teamRef || ruleGroupMatch || len(idCtx.TeamAllowedModels) == 0 {
				eval.GrantedForTeam = true
			}
			if projRef || len(idCtx.ProjectAllowedModels) == 0 {
				eval.GrantedForProject = true
			}
			if memberRef || len(idCtx.TeamMemberAllowedModels) == 0 {
				eval.GrantedForMember = true
			}
		}
	}

	return eval
}

func hasModelAccessGroupRef(list []string, g *domain.ModelAccessGroup) bool {
	if g == nil || len(list) == 0 {
		return false
	}
	return slices.Contains(list, g.Name) || slices.Contains(list, g.ID)
}
