package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/goroute-ai/ai-gateway-go/internal/adapter"
	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/guardrails"
	"github.com/goroute-ai/ai-gateway-go/internal/logger"
	"github.com/goroute-ai/ai-gateway-go/internal/mcp/spec"
	catalog "github.com/goroute-ai/ai-gateway-go/internal/modelcatalog"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func (s *GatewayServer) authorizeAdmin(w http.ResponseWriter, r *http.Request, targetOrgID string, write bool) (*domain.OperatorContext, bool) {
	op := auth.OperatorFromContext(r.Context())
	if err := auth.AuthorizeAdminAction(op, targetOrgID, write); err != nil {
		domain.WriteHTTPError(w, err)
		return nil, false
	}
	if s.customAuthorizer != nil {
		action := auth.AuthzActionAdminRead
		if write {
			action = auth.AuthzActionAdminWrite
		}
		if err := s.evaluateCustomAuthorizer(r.Context(), &auth.AuthzRequest{
			Operator:     op,
			Action:       action,
			ResourceType: "admin_api",
			ResourceID:   targetOrgID,
			HTTPMethod:   r.Method,
			HTTPPath:     r.URL.Path,
		}); err != nil {
			domain.WriteHTTPError(w, err)
			return nil, false
		}
	}
	return op, true
}

func (s *GatewayServer) authorizeTeamAdmin(w http.ResponseWriter, r *http.Request, targetOrgID, targetTeamID string, write bool) (*domain.OperatorContext, bool) {
	op := auth.OperatorFromContext(r.Context())
	if err := auth.AuthorizeTeamAdminAction(op, targetOrgID, targetTeamID, write); err != nil {
		domain.WriteHTTPError(w, err)
		return nil, false
	}
	if s.customAuthorizer != nil {
		action := auth.AuthzActionAdminRead
		if write {
			action = auth.AuthzActionAdminWrite
		}
		resID := targetOrgID
		if targetTeamID != "" {
			resID = targetOrgID + "/" + targetTeamID
		}
		if err := s.evaluateCustomAuthorizer(r.Context(), &auth.AuthzRequest{
			Operator:     op,
			Action:       action,
			ResourceType: "admin_team_api",
			ResourceID:   resID,
			HTTPMethod:   r.Method,
			HTTPPath:     r.URL.Path,
		}); err != nil {
			domain.WriteHTTPError(w, err)
			return nil, false
		}
	}
	return op, true
}

func isPrivilegedOrgOrPlatformRole(role domain.Role) bool {
	switch role {
	case domain.RolePlatformAdmin, domain.RoleOrgAdmin, domain.RoleOrgViewer, domain.RoleViewer:
		return true
	default:
		return false
	}
}

func ensureOperatorCanMutateTargetRole(w http.ResponseWriter, op *domain.OperatorContext, targetRole domain.Role, resource string) bool {
	if targetRole == domain.RolePlatformAdmin && (op == nil || op.Role != domain.OperatorRolePlatformAdmin) {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusForbidden,
			Type:       domain.ErrorTypePermission,
			Code:       "platform_admin_required",
			Message:    fmt.Sprintf("Only platform_admin can modify %s with platform_admin role", resource),
		})
		return false
	}
	if op != nil && op.Role == domain.OperatorRoleTeamAdmin && isPrivilegedOrgOrPlatformRole(targetRole) {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusForbidden,
			Type:       domain.ErrorTypePermission,
			Code:       "insufficient_permissions",
			Message:    fmt.Sprintf("team_admin cannot modify %s with organization-wide or platform roles", resource),
		})
		return false
	}
	return true
}

func (s *GatewayServer) validateTeamAdminKeyTargetUser(ctx context.Context, w http.ResponseWriter, op *domain.OperatorContext, orgID, userID string) bool {
	if op == nil || op.Role != domain.OperatorRoleTeamAdmin || strings.TrimSpace(userID) == "" {
		return true
	}
	if !s.userBelongsToTeam(ctx, orgID, op.TeamID, userID) {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusForbidden,
			Type:       domain.ErrorTypePermission,
			Code:       "cross_team_access_denied",
			Message:    "team_admin can only bind virtual keys to users belonging to their own team",
		})
		return false
	}
	if targetUser, err := s.lookupUserByID(ctx, userID); err == nil && targetUser != nil &&
		(targetUser.Role == domain.RolePlatformAdmin || targetUser.Role == domain.RoleOrgAdmin) {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusForbidden,
			Type:       domain.ErrorTypePermission,
			Code:       "cross_role_access_denied",
			Message:    "team_admin cannot bind virtual keys to organization or platform administrators",
		})
		return false
	}
	return true
}

func hasDisallowedTeamAdminEndpoint(endpoints []string) bool {
	for _, ep := range endpoints {
		trimmed := strings.TrimSpace(ep)
		if trimmed == "*" || trimmed == "/*" || strings.HasPrefix(trimmed, "/scim") || strings.HasPrefix(trimmed, "/admin") {
			return true
		}
	}
	return false
}

func (s *GatewayServer) validateCredentialBaseURL(raw string) (string, error) {
	if strings.TrimSpace(raw) == "" {
		return "", nil
	}
	pol := s.netPolicy
	if pol == nil {
		var err error
		pol, err = network.NewPolicy(config.OutboundSSRFConfig{})
		if err != nil {
			return "", err
		}
	}
	return adapter.ValidateAndResolveBaseURL(raw, "", pol)
}

func (s *GatewayServer) authorizeCustomBaseURL(op *domain.OperatorContext, cleanBaseURL string) *domain.GatewayError {
	if cleanBaseURL != "" && s.cfg != nil {
		ssrf := s.cfg.Security.Network.OutboundSSRF
		privilegedNetworkPolicy := ssrf.AllowPrivateNetworks ||
			len(ssrf.AllowedPrivateCIDRs) > 0 ||
			ssrf.AllowLoopbackHTTP ||
			ssrf.AllowInsecureHTTP
		if privilegedNetworkPolicy && (op == nil || op.Role != domain.OperatorRolePlatformAdmin) {
			return &domain.GatewayError{
				StatusCode: http.StatusForbidden,
				Type:       domain.ErrorTypePermission,
				Code:       "platform_admin_required",
				Message:    "Custom BaseURL with private, loopback, or insecure HTTP network access requires platform_admin role",
			}
		}
	}
	return nil
}

func validateCredentialHeaders(headers map[string]string) *domain.GatewayError {
	for rawKey, rawVal := range headers {
		k := strings.TrimSpace(rawKey)
		if k == "" {
			return &domain.GatewayError{
				StatusCode: http.StatusBadRequest,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "invalid_credential_header",
				Message:    "Custom credential header names cannot be empty",
			}
		}
		if adapter.HasUnsafeHeaderChars(rawKey) {
			return &domain.GatewayError{
				StatusCode: http.StatusBadRequest,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "invalid_credential_header",
				Message:    "Custom credential header names must not contain control characters",
			}
		}
		if adapter.HasUnsafeHeaderChars(rawVal) {
			return &domain.GatewayError{
				StatusCode: http.StatusBadRequest,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "invalid_credential_header",
				Message:    fmt.Sprintf("Custom credential header %q value must not contain control characters", k),
			}
		}
		if adapter.IsReservedCustomHeader(k) {
			return &domain.GatewayError{
				StatusCode: http.StatusBadRequest,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "invalid_credential_header",
				Message:    fmt.Sprintf("Custom credential header %q is reserved and cannot be overridden", k),
			}
		}
	}
	return nil
}

func sanitizeCredentialForResponse(cred *domain.ProviderCredential) *domain.ProviderCredential {
	if cred == nil {
		return nil
	}
	cp := *cred
	cp.Headers = redactHeaders(cred.Headers)
	return &cp
}

func resolveScopedOrgID(r *http.Request, explicitOrgID string) string {
	explicitOrgID = strings.TrimSpace(explicitOrgID)
	if explicitOrgID != "" {
		return explicitOrgID
	}
	if op := auth.OperatorFromContext(r.Context()); op != nil && op.Role != domain.OperatorRolePlatformAdmin {
		return op.OrgID
	}
	return ""
}

func resolveScopedTeamID(r *http.Request, explicitTeamID string) string {
	explicitTeamID = strings.TrimSpace(explicitTeamID)
	if explicitTeamID != "" {
		return explicitTeamID
	}
	if op := auth.OperatorFromContext(r.Context()); op != nil && op.Role == domain.OperatorRoleTeamAdmin {
		return op.TeamID
	}
	return ""
}

func (s *GatewayServer) audit(ctx context.Context, orgID, action, resource, resourceID string, details map[string]any) {
	s.auditWithDiff(ctx, orgID, action, resource, resourceID, details, nil, nil)
}

// --- Organizations, Layer 2 Subscriptions, Layer 3 Model Policies & Security Guardrails ---

const maxAdminRequestBodyBytes = 2 << 20 // 2 MiB

func decodeAdminJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxAdminRequestBodyBytes)
	return json.NewDecoder(r.Body).Decode(dst)
}

func (s *GatewayServer) handleAdminCreateOrg(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorizeAdmin(w, r, "", true); !ok {
		return
	}
	var org domain.Organization
	if err := decodeAdminJSON(w, r, &org); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 400, Type: domain.ErrorTypeInvalidRequest, Message: err.Error()})
		return
	}
	if org.SoftBudgetMicros < 0 {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 400, Type: domain.ErrorTypeInvalidRequest, Code: "invalid_soft_budget", Message: "soft_budget_micros cannot be negative"})
		return
	}
	if org.SelfServeBudgetPolicy != "" && !org.SelfServeBudgetPolicy.IsValid() {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 400, Type: domain.ErrorTypeInvalidRequest, Code: "invalid_self_serve_budget_policy", Message: "self_serve_budget_policy must be disabled, lower_only, or ceiling"})
		return
	}
	if org.LifecycleWebhookURL != "" {
		cleanWebhook, wErr := s.validateLifecycleWebhookURL(org.LifecycleWebhookURL)
		if wErr != nil {
			domain.WriteHTTPError(w, wErr)
			return
		}
		org.LifecycleWebhookURL = cleanWebhook
	}
	org.IsActive = true
	if org.BudgetResetPeriod == "" {
		org.BudgetResetPeriod = domain.BudgetResetMonthly
	}
	if err := s.repo.CreateOrganization(r.Context(), &org); err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	s.auditWithDiff(r.Context(), org.ID, "organization.created", "organization", org.ID, map[string]any{"name": org.Name}, nil, &org)
	writeJSON(w, http.StatusCreated, org)
}

func (s *GatewayServer) handleAdminListOrgs(w http.ResponseWriter, r *http.Request) {
	op := auth.OperatorFromContext(r.Context())
	if op != nil && op.Role != domain.OperatorRolePlatformAdmin {
		if _, ok := s.authorizeAdmin(w, r, op.OrgID, false); !ok {
			return
		}
		org, err := s.repo.GetOrganization(r.Context(), op.OrgID)
		if err != nil {
			domain.WriteHTTPError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"data": []*domain.Organization{org}})
		return
	}
	if _, ok := s.authorizeAdmin(w, r, "", false); !ok {
		return
	}
	orgs, err := s.repo.ListOrganizations(r.Context())
	if err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": orgs})
}

func (s *GatewayServer) handleAdminSetOrgSubscription(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "orgID")
	if _, ok := s.authorizeAdmin(w, r, orgID, true); !ok {
		return
	}
	var sub domain.OrgProviderSubscription
	if err := decodeAdminJSON(w, r, &sub); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 400, Type: domain.ErrorTypeInvalidRequest, Message: err.Error()})
		return
	}
	sub.OrgID = orgID
	var beforeSub *domain.OrgProviderSubscription
	if subs, err := s.repo.GetOrgProviderSubscriptions(r.Context(), orgID); err == nil {
		for _, item := range subs {
			if item != nil && item.Provider == sub.Provider {
				cp := *item
				beforeSub = &cp
				break
			}
		}
	}
	if err := s.repo.SetOrgProviderSubscription(r.Context(), &sub); err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	if s.rbac != nil {
		s.rbac.InvalidateOrgPolicies(r.Context(), orgID)
	}
	s.auditWithDiff(r.Context(), orgID, "organization.subscription.updated", "org_provider_subscription", string(sub.Provider), map[string]any{
		"provider":        sub.Provider,
		"is_enabled":      sub.IsEnabled,
		"auto_enable_new": sub.AutoEnableNew,
	}, beforeSub, &sub)
	writeJSON(w, http.StatusOK, sub)
}

func (s *GatewayServer) handleAdminGetOrgSubscriptions(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "orgID")
	if _, ok := s.authorizeAdmin(w, r, orgID, false); !ok {
		return
	}
	subs, err := s.repo.GetOrgProviderSubscriptions(r.Context(), orgID)
	if err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": subs})
}

func (s *GatewayServer) handleAdminSetOrgModelPolicy(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "orgID")
	if _, ok := s.authorizeAdmin(w, r, orgID, true); !ok {
		return
	}
	var pol domain.OrgModelPolicy
	if err := decodeAdminJSON(w, r, &pol); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 400, Type: domain.ErrorTypeInvalidRequest, Message: err.Error()})
		return
	}
	pol.OrgID = orgID
	var beforePol *domain.OrgModelPolicy
	if pols, err := s.repo.GetOrgModelPolicies(r.Context(), orgID); err == nil {
		for _, item := range pols {
			if item != nil && item.GlobalModelID == pol.GlobalModelID {
				cp := *item
				beforePol = &cp
				break
			}
		}
	}
	if err := s.repo.SetOrgModelPolicy(r.Context(), &pol); err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	if s.rbac != nil {
		s.rbac.InvalidateOrgPolicies(r.Context(), orgID)
	}
	s.auditWithDiff(r.Context(), orgID, "organization.model_policy.updated", "org_model_policy", pol.GlobalModelID, map[string]any{
		"global_model_id": pol.GlobalModelID,
		"is_enabled":      pol.IsEnabled,
	}, beforePol, &pol)
	writeJSON(w, http.StatusOK, pol)
}

func (s *GatewayServer) handleAdminGetOrgModelPolicies(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "orgID")
	if _, ok := s.authorizeAdmin(w, r, orgID, false); !ok {
		return
	}
	pols, err := s.repo.GetOrgModelPolicies(r.Context(), orgID)
	if err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": pols})
}

func (s *GatewayServer) handleAdminSetGuardrailPolicy(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "orgID")
	if _, ok := s.authorizeAdmin(w, r, orgID, true); !ok {
		return
	}
	pol := domain.GuardrailPolicy{
		Mode:         domain.GuardrailModeEnforce,
		ScanAllRoles: true,
	}
	if err := decodeAdminJSON(w, r, &pol); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 400, Type: domain.ErrorTypeInvalidRequest, Message: err.Error()})
		return
	}
	pol.OrgID = orgID
	if err := validateGuardrailPolicy(&pol); err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	beforePol, _ := s.repo.GetGuardrailPolicy(r.Context(), orgID)
	if err := s.repo.SetGuardrailPolicy(r.Context(), &pol); err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	s.auditWithDiff(r.Context(), orgID, "organization.guardrails.updated", "guardrail_policy", orgID, map[string]any{
		"enable_prompt_injection": pol.EnablePromptInjection,
		"prompt_injection_action": pol.PromptInjectionAction,
		"enable_pii_detection":    pol.EnablePIIDetection,
		"pii_action":              pol.PIIAction,
		"enable_secret_detection": pol.EnableSecretDetection,
		"secret_action":           pol.SecretAction,
		"redact_output_pii":       pol.RedactOutputPII,
	}, beforePol, &pol)
	writeJSON(w, http.StatusOK, pol)
}

func validateGuardrailPolicy(pol *domain.GuardrailPolicy) *domain.GatewayError {
	if pol == nil {
		return nil
	}
	for _, field := range []struct {
		name   string
		action domain.GuardrailAction
	}{
		{name: "prompt_injection_action", action: pol.PromptInjectionAction},
		{name: "pii_action", action: pol.PIIAction},
		{name: "secret_action", action: pol.SecretAction},
		{name: "toxicity_action", action: pol.ToxicityAction},
	} {
		if field.action == "" {
			continue
		}
		switch field.action {
		case domain.GuardrailActionBlock, domain.GuardrailActionRedact, domain.GuardrailActionAudit:
		default:
			return &domain.GatewayError{
				StatusCode: http.StatusBadRequest,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "invalid_guardrail_action",
				Message:    fmt.Sprintf("unsupported %s %q", field.name, field.action),
			}
		}
	}
	if err := guardrails.ValidateBlockedPatterns(pol.BlockedPatterns); err != nil {
		return &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_guardrail_pattern",
			Message:    err.Error(),
		}
	}
	return nil
}

func normalizeRoutingTags(tags []string) []string {
	if tags == nil {
		return nil
	}
	out := make([]string, 0, len(tags))
	for _, t := range tags {
		t = strings.TrimSpace(t)
		if t != "" {
			out = append(out, t)
		}
	}
	return out
}

func (s *GatewayServer) handleAdminGetGuardrailPolicy(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "orgID")
	if _, ok := s.authorizeAdmin(w, r, orgID, false); !ok {
		return
	}
	pol, err := s.repo.GetGuardrailPolicy(r.Context(), orgID)
	if err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	if pol == nil {
		pol = &domain.GuardrailPolicy{OrgID: orgID}
	}
	writeJSON(w, http.StatusOK, pol)
}

// --- Teams & Users ---

func (s *GatewayServer) handleAdminCreateTeam(w http.ResponseWriter, r *http.Request) {
	var team domain.Team
	if err := decodeAdminJSON(w, r, &team); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 400, Type: domain.ErrorTypeInvalidRequest, Message: err.Error()})
		return
	}
	team.OrgID = resolveScopedOrgID(r, team.OrgID)
	if _, ok := s.authorizeAdmin(w, r, team.OrgID, true); !ok {
		return
	}
	if team.SoftBudgetMicros < 0 {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 400, Type: domain.ErrorTypeInvalidRequest, Code: "invalid_soft_budget", Message: "soft_budget_micros cannot be negative"})
		return
	}
	if team.MinPriorityRank < 0 {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 400, Type: domain.ErrorTypeInvalidRequest, Code: "invalid_min_priority_rank", Message: "min_priority_rank cannot be negative"})
		return
	}
	team.AllowedRoutingTags = normalizeRoutingTags(team.AllowedRoutingTags)
	team.IsActive = true
	if err := s.repo.CreateTeam(r.Context(), &team); err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	s.auditWithDiff(r.Context(), team.OrgID, "team.created", "team", team.ID, map[string]any{
		"name":              team.Name,
		"min_priority_rank": team.MinPriorityRank,
	}, nil, &team)
	writeJSON(w, http.StatusCreated, team)
}

func (s *GatewayServer) handleAdminListTeams(w http.ResponseWriter, r *http.Request) {
	orgID := resolveScopedOrgID(r, r.URL.Query().Get("org_id"))
	teamID := resolveScopedTeamID(r, r.URL.Query().Get("team_id"))
	op, ok := s.authorizeTeamAdmin(w, r, orgID, teamID, false)
	if !ok {
		return
	}
	if op.Role == domain.OperatorRoleTeamAdmin {
		team, err := s.repo.GetTeam(r.Context(), op.TeamID)
		if err != nil {
			if errors.Is(err, storage.ErrNotFound) {
				writeJSON(w, http.StatusOK, map[string]any{"data": []*domain.Team{}})
				return
			}
			domain.WriteHTTPError(w, err)
			return
		}
		if team == nil || team.OrgID != op.OrgID {
			writeJSON(w, http.StatusOK, map[string]any{"data": []*domain.Team{}})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"data": []*domain.Team{team}})
		return
	}
	teams, err := s.repo.ListTeams(r.Context(), orgID)
	if err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	if teamID != "" {
		filtered := make([]*domain.Team, 0, 1)
		for _, t := range teams {
			if t != nil && t.ID == teamID {
				filtered = append(filtered, t)
			}
		}
		teams = filtered
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": teams})
}

func (s *GatewayServer) handleAdminCreateUser(w http.ResponseWriter, r *http.Request) {
	var user domain.User
	if err := decodeAdminJSON(w, r, &user); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 400, Type: domain.ErrorTypeInvalidRequest, Message: err.Error()})
		return
	}
	user.OrgID = resolveScopedOrgID(r, user.OrgID)
	op, ok := s.authorizeAdmin(w, r, user.OrgID, true)
	if !ok {
		return
	}
	if user.Role == domain.RolePlatformAdmin && op.Role != domain.OperatorRolePlatformAdmin {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 403, Type: domain.ErrorTypePermission, Code: "platform_admin_required", Message: "Only platform_admin can create platform_admin users"})
		return
	}
	if user.SoftBudgetMicros < 0 {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 400, Type: domain.ErrorTypeInvalidRequest, Code: "invalid_soft_budget", Message: "soft_budget_micros cannot be negative"})
		return
	}
	user.IsActive = true
	user.SCIMActive = true
	if user.Role == "" {
		user.Role = domain.RoleDeveloper
	}
	if err := s.repo.CreateUser(r.Context(), &user); err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	s.auditWithDiff(r.Context(), user.OrgID, "user.created", "user", user.ID, map[string]any{"email": user.Email, "role": user.Role}, nil, &user)
	writeJSON(w, http.StatusCreated, user)
}

func (s *GatewayServer) handleAdminListUsers(w http.ResponseWriter, r *http.Request) {
	orgID := resolveScopedOrgID(r, r.URL.Query().Get("org_id"))
	teamID := resolveScopedTeamID(r, r.URL.Query().Get("team_id"))
	if _, ok := s.authorizeTeamAdmin(w, r, orgID, teamID, false); !ok {
		return
	}
	users, err := s.repo.ListUsers(r.Context(), orgID)
	if err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	if teamID != "" {
		filtered := make([]*domain.User, 0)
		for _, u := range users {
			if u != nil && u.TeamID == teamID {
				filtered = append(filtered, u)
			}
		}
		users = filtered
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": users})
}

// --- Virtual API Keys ---

func (s *GatewayServer) handleAdminIssueKey(w http.ResponseWriter, r *http.Request) {
	var payload struct {
		domain.VirtualKey
		AllowedMCPServers optionalStringSlice `json:"allowed_mcp_servers"`
		AllowedA2AAgents  optionalStringSlice `json:"allowed_a2a_agents"`
		AllowedClientApps optionalStringSlice `json:"allowed_client_apps"`
	}
	if err := decodeAdminJSON(w, r, &payload); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 400, Type: domain.ErrorTypeInvalidRequest, Message: err.Error()})
		return
	}
	req := payload.VirtualKey
	issueOpts := auth.IssueVirtualKeyOptions{}
	if payload.AllowedMCPServers.Set {
		req.AllowedMCPServers = payload.AllowedMCPServers.Value
		issueOpts.InheritMCPServers = payload.AllowedMCPServers.Value == nil
	}
	if payload.AllowedA2AAgents.Set {
		req.AllowedA2AAgents = payload.AllowedA2AAgents.Value
		issueOpts.InheritA2AAgents = payload.AllowedA2AAgents.Value == nil
	}
	if payload.AllowedClientApps.Set {
		req.AllowedClientApps = payload.AllowedClientApps.Value
		issueOpts.InheritClientApps = payload.AllowedClientApps.Value == nil
	}
	req.OrgID = resolveScopedOrgID(r, req.OrgID)
	req.TeamID = strings.TrimSpace(req.TeamID)
	req.ProjectID = strings.TrimSpace(req.ProjectID)
	req.UserID = strings.TrimSpace(req.UserID)

	if req.ProjectID != "" {
		pmRepo, ok := s.projectMembershipRepo()
		if !ok {
			if _, authOK := s.authorizeTeamAdmin(w, r, req.OrgID, req.TeamID, true); !authOK {
				return
			}
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusNotImplemented,
				Type:       domain.ErrorTypeServer,
				Code:       "projects_unsupported",
				Message:    "Configured storage repository does not support projects",
			})
			return
		}
		proj, pErr := pmRepo.GetProject(r.Context(), req.ProjectID)
		if pErr != nil || proj == nil {
			if _, authOK := s.authorizeTeamAdmin(w, r, req.OrgID, req.TeamID, true); !authOK {
				return
			}
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusNotFound,
				Type:       domain.ErrorTypeNotFound,
				Code:       "project_not_found",
				Message:    "Project not found",
			})
			return
		}
		if req.TeamID == "" {
			req.TeamID = proj.TeamID
		}
		opCheck, authOK := s.authorizeTeamAdmin(w, r, req.OrgID, req.TeamID, true)
		if !authOK {
			return
		}
		if proj.OrgID != req.OrgID {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusForbidden,
				Type:       domain.ErrorTypePermission,
				Code:       "cross_org_access_denied",
				Message:    "Project does not belong to the requested organization",
			})
			return
		}
		if proj.TeamID != req.TeamID {
			if opCheck.Role == domain.OperatorRoleTeamAdmin {
				domain.WriteHTTPError(w, &domain.GatewayError{
					StatusCode: http.StatusForbidden,
					Type:       domain.ErrorTypePermission,
					Code:       "cross_team_access_denied",
					Message:    "Project does not belong to your team",
				})
				return
			}
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusBadRequest,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "project_team_mismatch",
				Message:    "Project does not belong to the specified team",
			})
			return
		}
	}

	op, ok := s.authorizeTeamAdmin(w, r, req.OrgID, req.TeamID, true)
	if !ok {
		return
	}
	if req.Role == domain.RolePlatformAdmin && op.Role != domain.OperatorRolePlatformAdmin {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 403, Type: domain.ErrorTypePermission, Code: "platform_admin_required", Message: "Only platform_admin can issue platform_admin keys"})
		return
	}
	if op.Role == domain.OperatorRoleTeamAdmin {
		if req.CanImpersonate {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusForbidden,
				Type:       domain.ErrorTypePermission,
				Code:       "insufficient_permissions",
				Message:    "team_admin cannot issue virtual keys with can_impersonate enabled",
			})
			return
		}
		if hasDisallowedTeamAdminEndpoint(req.AllowedEndpoints) {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusForbidden,
				Type:       domain.ErrorTypePermission,
				Code:       "insufficient_permissions",
				Message:    "team_admin cannot issue virtual keys with wildcard, /admin, or /scim allowed_endpoints",
			})
			return
		}
		if isPrivilegedOrgOrPlatformRole(req.Role) {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusForbidden,
				Type:       domain.ErrorTypePermission,
				Code:       "insufficient_permissions",
				Message:    fmt.Sprintf("team_admin cannot issue virtual keys with role %q", req.Role),
			})
			return
		}
		if !s.validateTeamAdminKeyTargetUser(r.Context(), w, op, req.OrgID, req.UserID) {
			return
		}
		if req.MaxBudgetMicros > 0 {
			if !s.enforceSelfServeBudgetPolicy(r.Context(), w, op, req.OrgID, req.TeamID, 0, req.MaxBudgetMicros) {
				return
			}
		}
	}
	if req.KeyType != "" && !auth.IsValidKeyType(req.KeyType) {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 400, Type: domain.ErrorTypeInvalidRequest, Code: "invalid_key_type", Message: fmt.Sprintf("unsupported key_type %q", req.KeyType)})
		return
	}
	if req.RotationIntervalSec < 0 {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 400, Type: domain.ErrorTypeInvalidRequest, Code: "invalid_rotation_interval", Message: "rotation_interval_sec cannot be negative"})
		return
	}
	if req.SoftBudgetMicros < 0 {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 400, Type: domain.ErrorTypeInvalidRequest, Code: "invalid_soft_budget", Message: "soft_budget_micros cannot be negative"})
		return
	}
	if req.MinPriorityRank < 0 {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 400, Type: domain.ErrorTypeInvalidRequest, Code: "invalid_min_priority_rank", Message: "min_priority_rank cannot be negative"})
		return
	}
	req.AllowedRoutingTags = normalizeRoutingTags(req.AllowedRoutingTags)
	if !s.enforceGuaranteedThroughput(r.Context(), w, req.OrgID, req.TeamID, "", req.RPMLimit, req.TPMLimit) {
		return
	}
	vk, err := s.authSvc.IssueVirtualKeyWithOptions(r.Context(), &req, issueOpts)
	if err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	s.auditWithDiff(r.Context(), vk.OrgID, "virtual_key.issued", "virtual_key", vk.ID, map[string]any{
		"key_prefix":            vk.KeyPrefix,
		"name":                  vk.Name,
		"key_type":              vk.KeyType,
		"can_impersonate":       vk.CanImpersonate,
		"rotation_interval_sec": vk.RotationIntervalSec,
		"min_priority_rank":     vk.MinPriorityRank,
	}, nil, vk)
	writeJSON(w, http.StatusCreated, vk)
}

func (s *GatewayServer) handleAdminListKeys(w http.ResponseWriter, r *http.Request) {
	orgID := resolveScopedOrgID(r, r.URL.Query().Get("org_id"))
	teamID := resolveScopedTeamID(r, r.URL.Query().Get("team_id"))
	if _, ok := s.authorizeTeamAdmin(w, r, orgID, teamID, false); !ok {
		return
	}
	status := strings.TrimSpace(r.URL.Query().Get("status"))
	userID := strings.TrimSpace(r.URL.Query().Get("user_id"))
	projectID := strings.TrimSpace(r.URL.Query().Get("project_id"))
	search := strings.TrimSpace(r.URL.Query().Get("search"))
	limit, okLim := parseNonNegativeIntQuery(r, "limit")
	offset, okOff := parseNonNegativeIntQuery(r, "offset")
	if !okLim || !okOff {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_pagination",
			Message:    "limit and offset must be non-negative integers",
		})
		return
	}
	if govRepo, hasGov := s.keyGovernanceRepo(); hasGov {
		keys, total, err := govRepo.ListVirtualKeysFiltered(r.Context(), storage.VirtualKeyFilter{
			OrgID:     orgID,
			Status:    status,
			TeamID:    teamID,
			UserID:    userID,
			ProjectID: projectID,
			Search:    search,
			Limit:     limit,
			Offset:    offset,
		})
		if err != nil {
			domain.WriteHTTPError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"data":   keys,
			"total":  total,
			"limit":  limit,
			"offset": offset,
		})
		return
	}
	keys, err := s.repo.ListVirtualKeys(r.Context(), orgID)
	if err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	if teamID != "" {
		filtered := make([]*domain.VirtualKey, 0)
		for _, k := range keys {
			if k != nil && k.TeamID == teamID {
				filtered = append(filtered, k)
			}
		}
		keys = filtered
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": keys, "total": len(keys)})
}

func (s *GatewayServer) handleAdminRevokeKey(w http.ResponseWriter, r *http.Request) {
	keyID := chi.URLParam(r, "keyID")
	vk, err := s.repo.GetVirtualKeyByID(r.Context(), keyID)
	if err != nil {
		if _, ok := s.authorizeTeamAdmin(w, r, resolveScopedOrgID(r, r.URL.Query().Get("org_id")), resolveScopedTeamID(r, r.URL.Query().Get("team_id")), true); !ok {
			return
		}
		domain.WriteHTTPError(w, err)
		return
	}
	op, ok := s.authorizeTeamAdmin(w, r, vk.OrgID, vk.TeamID, true)
	if !ok {
		return
	}
	if !ensureOperatorCanMutateTargetRole(w, op, vk.Role, "virtual key") {
		return
	}
	if !verifyExplicitOrgMatch(w, r, vk.OrgID, nil) {
		return
	}
	actorID := "master_admin"
	if op != nil && op.ActorID != "" {
		actorID = op.ActorID
	}
	if err := s.authSvc.RevokeKeyWithActor(r.Context(), keyID, actorID); err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	after, _ := s.repo.GetVirtualKeyByID(r.Context(), keyID)
	s.auditWithDiff(r.Context(), vk.OrgID, "virtual_key.revoked", "virtual_key", keyID, map[string]any{"revoked_by": actorID}, vk, after)
	writeJSON(w, http.StatusOK, map[string]any{"status": "revoked", "id": keyID, "revoked_by": actorID})
}

// --- Boundary 2 Provider Credentials Vault & Lifecycle ---

func (s *GatewayServer) handleAdminCreateCredential(w http.ResponseWriter, r *http.Request) {
	var req struct {
		OrgID     string              `json:"org_id"`
		Provider  domain.ProviderType `json:"provider"`
		Name      string              `json:"name"`
		BaseURL   string              `json:"base_url"`
		APIKey    string              `json:"api_key"`
		Headers   map[string]string   `json:"headers,omitempty"`
		ExpiresAt *time.Time          `json:"expires_at,omitempty"`
	}
	if err := decodeAdminJSON(w, r, &req); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 400, Type: domain.ErrorTypeInvalidRequest, Message: err.Error()})
		return
	}
	req.OrgID = resolveScopedOrgID(r, req.OrgID)
	op, ok := s.authorizeAdmin(w, r, req.OrgID, true)
	if !ok {
		return
	}
	cleanBaseURL, err := s.validateCredentialBaseURL(req.BaseURL)
	if err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_base_url",
			Message:    err.Error(),
		})
		return
	}
	if gwErr := s.authorizeCustomBaseURL(op, cleanBaseURL); gwErr != nil {
		domain.WriteHTTPError(w, gwErr)
		return
	}
	if gwErr := validateCredentialHeaders(req.Headers); gwErr != nil {
		domain.WriteHTTPError(w, gwErr)
		return
	}
	cred := &domain.ProviderCredential{
		OrgID:     req.OrgID,
		Provider:  req.Provider,
		Name:      req.Name,
		BaseURL:   cleanBaseURL,
		Headers:   req.Headers,
		IsActive:  true,
		ExpiresAt: req.ExpiresAt,
	}
	if err := s.vault.EncryptCredential(cred, req.APIKey); err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	if err := s.repo.CreateProviderCredential(r.Context(), cred); err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	s.auditWithDiff(r.Context(), cred.OrgID, "credential.created", "provider_credential", cred.ID, map[string]any{
		"provider":    cred.Provider,
		"name":        cred.Name,
		"key_version": cred.KeyVersion,
	}, nil, cred)
	writeJSON(w, http.StatusCreated, sanitizeCredentialForResponse(cred))
}

func (s *GatewayServer) handleAdminListCredentials(w http.ResponseWriter, r *http.Request) {
	orgID := resolveScopedOrgID(r, r.URL.Query().Get("org_id"))
	if _, ok := s.authorizeAdmin(w, r, orgID, false); !ok {
		return
	}
	creds, err := s.repo.ListProviderCredentials(r.Context(), orgID)
	if err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	safeCreds := make([]*domain.ProviderCredential, len(creds))
	for i, c := range creds {
		safeCreds[i] = sanitizeCredentialForResponse(c)
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": safeCreds})
}

func (s *GatewayServer) handleAdminRotateCredential(w http.ResponseWriter, r *http.Request) {
	credID := chi.URLParam(r, "credID")
	var req struct {
		NewAPIKey string     `json:"api_key"`
		BaseURL   string     `json:"base_url,omitempty"`
		ExpiresAt *time.Time `json:"expires_at,omitempty"`
	}
	if err := decodeAdminJSON(w, r, &req); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 400, Type: domain.ErrorTypeInvalidRequest, Message: err.Error()})
		return
	}
	cred, err := s.repo.GetProviderCredential(r.Context(), credID)
	if err != nil || cred == nil {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 404, Type: domain.ErrorTypeNotFound, Message: "Credential not found"})
		return
	}
	op, ok := s.authorizeAdmin(w, r, cred.OrgID, true)
	if !ok {
		return
	}
	var cleanBaseURL string
	if strings.TrimSpace(req.BaseURL) != "" {
		var err error
		cleanBaseURL, err = s.validateCredentialBaseURL(req.BaseURL)
		if err != nil {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusBadRequest,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "invalid_base_url",
				Message:    err.Error(),
			})
			return
		}
		if gwErr := s.authorizeCustomBaseURL(op, cleanBaseURL); gwErr != nil {
			domain.WriteHTTPError(w, gwErr)
			return
		}
	}
	beforeCred := *cred
	if err := s.vault.RotateCredential(cred, req.NewAPIKey); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 400, Type: domain.ErrorTypeInvalidRequest, Message: err.Error()})
		return
	}
	if req.ExpiresAt != nil {
		cred.ExpiresAt = req.ExpiresAt
	}
	if cleanBaseURL != "" {
		cred.BaseURL = cleanBaseURL
	}
	if err := s.repo.UpdateProviderCredential(r.Context(), cred); err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	s.auditWithDiff(r.Context(), cred.OrgID, "credential.rotated", "provider_credential", cred.ID, map[string]any{
		"provider":    cred.Provider,
		"key_version": cred.KeyVersion,
	}, &beforeCred, cred)
	writeJSON(w, http.StatusOK, sanitizeCredentialForResponse(cred))
}

func (s *GatewayServer) handleAdminValidateCredential(w http.ResponseWriter, r *http.Request) {
	credID := chi.URLParam(r, "credID")
	cred, err := s.repo.GetProviderCredential(r.Context(), credID)
	if err != nil || cred == nil {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 404, Type: domain.ErrorTypeNotFound, Message: "Credential not found"})
		return
	}
	op, ok := s.authorizeAdmin(w, r, cred.OrgID, true)
	if !ok {
		return
	}
	if cred.ExpiresAt != nil && time.Now().UTC().After(*cred.ExpiresAt) {
		writeJSON(w, http.StatusOK, map[string]any{
			"id":       cred.ID,
			"provider": cred.Provider,
			"valid":    false,
			"reason":   "credential_expired",
		})
		return
	}
	adp, err := s.reg.Get(cred.Provider)
	if err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	rawKey, err := s.vault.DecryptCredential(cred)
	if err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	cleanBaseURL, err := s.validateCredentialBaseURL(cred.BaseURL)
	if err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_base_url",
			Message:    err.Error(),
		})
		return
	}
	if gwErr := s.authorizeCustomBaseURL(op, cleanBaseURL); gwErr != nil {
		domain.WriteHTTPError(w, gwErr)
		return
	}
	credCopy := *cred
	credCopy.BaseURL = cleanBaseURL
	credCopy.DecryptedAPIKey = rawKey
	start := time.Now()
	beforeCred := *cred
	models, discErr := adp.ListModels(r.Context(), &credCopy)
	latencyMs := time.Since(start).Milliseconds()
	now := time.Now().UTC()
	cred.LastValidatedAt = &now
	_ = s.repo.UpdateProviderCredential(r.Context(), cred)

	valid := discErr == nil
	validationStatus := "success"
	errMsg := ""
	if discErr != nil {
		if gwErr, ok := discErr.(*domain.GatewayError); ok && gwErr.Code == "list_models_unsupported" {
			valid = true
			validationStatus = "unsupported_by_provider"
		} else {
			validationStatus = "failed"
			errMsg = logger.ScrubSecrets(discErr.Error())
		}
	}
	s.auditWithDiff(r.Context(), cred.OrgID, "credential.validated", "provider_credential", cred.ID, map[string]any{
		"provider":          cred.Provider,
		"valid":             valid,
		"validation_status": validationStatus,
		"discovered_models": len(models),
		"latency_ms":        latencyMs,
	}, &beforeCred, cred)
	writeJSON(w, http.StatusOK, map[string]any{
		"id":                cred.ID,
		"provider":          cred.Provider,
		"valid":             valid,
		"validation_status": validationStatus,
		"discovered_models": len(models),
		"latency_ms":        latencyMs,
		"last_validated_at": now,
		"error":             errMsg,
	})
}

func (s *GatewayServer) handleAdminPreflightValidateCredential(w http.ResponseWriter, r *http.Request) {
	var req struct {
		OrgID    string              `json:"org_id,omitempty"`
		Provider domain.ProviderType `json:"provider"`
		APIKey   string              `json:"api_key"`
		BaseURL  string              `json:"base_url,omitempty"`
		Headers  map[string]string   `json:"headers,omitempty"`
	}
	if err := decodeAdminJSON(w, r, &req); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 400, Type: domain.ErrorTypeInvalidRequest, Message: err.Error()})
		return
	}
	op, ok := s.authorizeAdmin(w, r, resolveScopedOrgID(r, req.OrgID), true)
	if !ok {
		return
	}
	cleanBaseURL, err := s.validateCredentialBaseURL(req.BaseURL)
	if err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_base_url",
			Message:    err.Error(),
		})
		return
	}
	if gwErr := s.authorizeCustomBaseURL(op, cleanBaseURL); gwErr != nil {
		domain.WriteHTTPError(w, gwErr)
		return
	}
	if gwErr := validateCredentialHeaders(req.Headers); gwErr != nil {
		domain.WriteHTTPError(w, gwErr)
		return
	}
	if req.Provider == "" {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 400, Type: domain.ErrorTypeInvalidRequest, Message: "provider is required"})
		return
	}
	req.Provider = config.NormalizeProvider(string(req.Provider))
	if req.APIKey == "" && req.Provider != domain.ProviderOllama {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 400, Type: domain.ErrorTypeInvalidRequest, Message: "api_key is required"})
		return
	}

	adp, err := s.reg.Get(req.Provider)
	if err != nil {
		domain.WriteHTTPError(w, err)
		return
	}

	credCopy := domain.ProviderCredential{
		Provider:        req.Provider,
		DecryptedAPIKey: req.APIKey,
		BaseURL:         cleanBaseURL,
		Headers:         req.Headers,
	}

	start := time.Now()
	models, discErr := adp.ListModels(r.Context(), &credCopy)
	latencyMs := time.Since(start).Milliseconds()

	valid := discErr == nil
	validationStatus := "success"
	errMsg := ""
	if discErr != nil {
		if gwErr, ok := discErr.(*domain.GatewayError); ok && gwErr.Code == "list_models_unsupported" {
			valid = true
			validationStatus = "unsupported_by_provider"
		} else {
			validationStatus = "failed"
			errMsg = logger.ScrubSecrets(discErr.Error())
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"provider":          req.Provider,
		"valid":             valid,
		"validation_status": validationStatus,
		"discovered_models": len(models),
		"latency_ms":        latencyMs,
		"error":             errMsg,
	})
}

// --- Layer 4 Model Groups & Deployments ---

func validateFallbackTargets(field string, targets []domain.FallbackTarget) error {
	for _, ft := range targets {
		if strings.TrimSpace(ft.GroupAliasOrID) == "" {
			return fmt.Errorf("%s entries must specify a non-empty target", field)
		}
	}
	return nil
}

func validateModelGroupFields(mg *domain.ModelGroup) error {
	if mg == nil {
		return fmt.Errorf("model group payload is required")
	}
	if mg.RoutingStrategy != "" {
		normalized := domain.NormalizeRoutingStrategy(mg.RoutingStrategy)
		if !domain.IsValidRoutingStrategy(normalized) {
			return fmt.Errorf("unsupported routing_strategy %q", mg.RoutingStrategy)
		}
		mg.RoutingStrategy = normalized
	}
	for _, pair := range []struct {
		name    string
		targets []domain.FallbackTarget
	}{
		{"context_window_fallbacks", mg.ContextWindowFallbacks},
		{"content_policy_fallbacks", mg.ContentPolicyFallbacks},
		{"fallback_targets", mg.FallbackTargets},
		{"saturation_fallbacks", mg.SaturationFallbacks},
	} {
		if err := validateFallbackTargets(pair.name, pair.targets); err != nil {
			return err
		}
	}
	if mg.CooldownPolicy != nil && (mg.CooldownPolicy.FailureRateThreshold < 0 || mg.CooldownPolicy.FailureRateThreshold > 1) {
		return fmt.Errorf("cooldown_policy.failure_rate_threshold must be between 0 and 1")
	}
	if mg.MaxRetries < 0 || mg.CooldownSeconds < 0 || mg.FailureThreshold < 0 {
		return fmt.Errorf("max_retries, cooldown_seconds, and failure_threshold cannot be negative")
	}
	return nil
}

func validateDeploymentFields(dep *domain.Deployment) error {
	if dep == nil {
		return fmt.Errorf("deployment payload is required")
	}
	if dep.Weight < 0 {
		return fmt.Errorf("weight cannot be negative")
	}
	if dep.RPMCapacity < 0 || dep.TPMCapacity < 0 || dep.ITPMCapacity < 0 || dep.OTPMCapacity < 0 || dep.MaxParallelRequests < 0 {
		return fmt.Errorf("deployment capacity limits cannot be negative")
	}
	if dep.TimeoutMs < 0 || dep.Priority < 0 {
		return fmt.Errorf("timeout_ms and priority cannot be negative")
	}
	if dep.MaxBudgetMicros < 0 {
		return fmt.Errorf("max_budget_micros cannot be negative")
	}
	if dep.BudgetResetPeriod != "" {
		switch domain.BudgetResetPeriod(dep.BudgetResetPeriod) {
		case domain.BudgetResetDaily, domain.BudgetResetMonthly, domain.BudgetResetNever:
		default:
			return fmt.Errorf("budget_reset_period must be daily, monthly, or never")
		}
	}
	if dep.Status != "" {
		switch dep.Status {
		case domain.DeploymentStatusActive, domain.DeploymentStatusCooldown, domain.DeploymentStatusDisabled:
		default:
			return fmt.Errorf("status must be active, cooldown, or disabled")
		}
	}
	if len(dep.Tags) > 0 {
		cleanTags := make([]string, 0, len(dep.Tags))
		for _, t := range dep.Tags {
			if trimmed := strings.TrimSpace(t); trimmed != "" {
				cleanTags = append(cleanTags, trimmed)
			}
		}
		dep.Tags = cleanTags
	}
	return nil
}

func (s *GatewayServer) resolveDeploymentOrgID(ctx context.Context, modelGroupID string) string {
	if strings.TrimSpace(modelGroupID) == "" {
		return ""
	}
	if mg, err := s.repo.GetModelGroupByID(ctx, modelGroupID); err == nil && mg != nil {
		return mg.OrgID
	}
	return ""
}

func writeStorageLookupError(w http.ResponseWriter, err error, code, notFoundMsg string) {
	if errors.Is(err, storage.ErrNotFound) {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusNotFound,
			Type:       domain.ErrorTypeNotFound,
			Code:       code,
			Message:    notFoundMsg,
		})
		return
	}
	if errors.Is(err, storage.ErrConflict) {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusConflict,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "conflict",
			Message:    err.Error(),
		})
		return
	}
	domain.WriteHTTPError(w, err)
}

func (s *GatewayServer) handleAdminCreateModelGroup(w http.ResponseWriter, r *http.Request) {
	var req struct {
		domain.ModelGroup
		LegacyFallbackGroups []string `json:"fallback_groups,omitempty"`
	}
	if err := decodeAdminJSON(w, r, &req); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 400, Type: domain.ErrorTypeInvalidRequest, Message: err.Error()})
		return
	}
	mg := req.ModelGroup
	if len(mg.FallbackGroupIDs) == 0 && len(req.LegacyFallbackGroups) > 0 {
		mg.FallbackGroupIDs = req.LegacyFallbackGroups
	}
	if err := validateModelGroupFields(&mg); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 400, Type: domain.ErrorTypeInvalidRequest, Message: err.Error()})
		return
	}
	mg.OrgID = resolveScopedOrgID(r, mg.OrgID)
	if _, ok := s.authorizeAdmin(w, r, mg.OrgID, true); !ok {
		return
	}
	mg.IsActive = true
	if err := s.repo.CreateModelGroup(r.Context(), &mg); err != nil {
		writeStorageLookupError(w, err, "model_group_not_found", "Model group not found")
		return
	}
	s.invalidateRoutingCaches(r.Context(), storage.InvalidationEvent{EntityType: "model_group", EntityID: mg.ID, OrgID: mg.OrgID})
	s.auditWithDiff(r.Context(), mg.OrgID, "model_group.created", "model_group", mg.ID, map[string]any{"alias": mg.Alias, "strategy": mg.RoutingStrategy}, nil, &mg)
	writeJSON(w, http.StatusCreated, mg)
}

func (s *GatewayServer) handleAdminListModelGroups(w http.ResponseWriter, r *http.Request) {
	orgID := resolveScopedOrgID(r, r.URL.Query().Get("org_id"))
	if _, ok := s.authorizeAdmin(w, r, orgID, false); !ok {
		return
	}
	groups, err := s.repo.ListModelGroups(r.Context(), orgID)
	if err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": groups})
}

func (s *GatewayServer) handleAdminGetModelGroup(w http.ResponseWriter, r *http.Request) {
	groupID := strings.TrimSpace(chi.URLParam(r, "groupID"))
	mg, err := s.repo.GetModelGroupByID(r.Context(), groupID)
	if err != nil || mg == nil {
		if _, ok := s.authorizeAdmin(w, r, resolveScopedOrgID(r, r.URL.Query().Get("org_id")), false); !ok {
			return
		}
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: http.StatusNotFound, Type: domain.ErrorTypeNotFound, Code: "model_group_not_found", Message: "Model group not found"})
		return
	}
	if _, ok := s.authorizeAdmin(w, r, mg.OrgID, false); !ok {
		return
	}
	writeJSON(w, http.StatusOK, mg)
}

func (s *GatewayServer) handleAdminUpdateModelGroup(w http.ResponseWriter, r *http.Request) {
	groupID := strings.TrimSpace(chi.URLParam(r, "groupID"))
	existing, err := s.repo.GetModelGroupByID(r.Context(), groupID)
	if err != nil || existing == nil {
		if _, ok := s.authorizeAdmin(w, r, resolveScopedOrgID(r, r.URL.Query().Get("org_id")), true); !ok {
			return
		}
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: http.StatusNotFound, Type: domain.ErrorTypeNotFound, Code: "model_group_not_found", Message: "Model group not found"})
		return
	}
	if _, ok := s.authorizeAdmin(w, r, existing.OrgID, true); !ok {
		return
	}
	var req struct {
		Alias                  *string                  `json:"alias,omitempty"`
		Description            *string                  `json:"description,omitempty"`
		RoutingStrategy        *string                  `json:"routing_strategy,omitempty"`
		FallbackGroupIDs       *[]string                `json:"fallback_group_ids,omitempty"`
		LegacyFallbackGroups   *[]string                `json:"fallback_groups,omitempty"`
		ContextWindowFallbacks *[]domain.FallbackTarget `json:"context_window_fallbacks,omitempty"`
		ContentPolicyFallbacks *[]domain.FallbackTarget `json:"content_policy_fallbacks,omitempty"`
		FallbackTargets        *[]domain.FallbackTarget `json:"fallback_targets,omitempty"`
		SaturationFallbacks    *[]domain.FallbackTarget `json:"saturation_fallbacks,omitempty"`
		DropUnsupportedParams  *bool                    `json:"drop_unsupported_params,omitempty"`
		DisableCooldowns       *bool                    `json:"disable_cooldowns,omitempty"`
		RetryPolicy            *domain.RetryPolicy      `json:"retry_policy,omitempty"`
		CooldownPolicy         *domain.CooldownPolicy   `json:"cooldown_policy,omitempty"`
		MaxRetries             *int                     `json:"max_retries,omitempty"`
		CooldownSeconds        *int                     `json:"cooldown_seconds,omitempty"`
		FailureThreshold       *int                     `json:"failure_threshold,omitempty"`
		IsActive               *bool                    `json:"is_active,omitempty"`
	}
	if err := decodeAdminJSON(w, r, &req); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: http.StatusBadRequest, Type: domain.ErrorTypeInvalidRequest, Message: err.Error()})
		return
	}
	updated := *existing
	if req.Alias != nil {
		alias := strings.TrimSpace(*req.Alias)
		if alias == "" {
			domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: http.StatusBadRequest, Type: domain.ErrorTypeInvalidRequest, Message: "alias cannot be empty"})
			return
		}
		updated.Alias = alias
	}
	if req.Description != nil {
		updated.Description = strings.TrimSpace(*req.Description)
	}
	if req.RoutingStrategy != nil {
		updated.RoutingStrategy = domain.RoutingStrategy(strings.TrimSpace(*req.RoutingStrategy))
	}
	if req.FallbackGroupIDs != nil {
		updated.FallbackGroupIDs = slices.Clone(*req.FallbackGroupIDs)
	} else if req.LegacyFallbackGroups != nil {
		updated.FallbackGroupIDs = slices.Clone(*req.LegacyFallbackGroups)
	}
	if req.ContextWindowFallbacks != nil {
		updated.ContextWindowFallbacks = slices.Clone(*req.ContextWindowFallbacks)
	}
	if req.ContentPolicyFallbacks != nil {
		updated.ContentPolicyFallbacks = slices.Clone(*req.ContentPolicyFallbacks)
	}
	if req.FallbackTargets != nil {
		updated.FallbackTargets = slices.Clone(*req.FallbackTargets)
	}
	if req.SaturationFallbacks != nil {
		updated.SaturationFallbacks = slices.Clone(*req.SaturationFallbacks)
	}
	if req.DropUnsupportedParams != nil {
		updated.DropUnsupportedParams = *req.DropUnsupportedParams
	}
	if req.DisableCooldowns != nil {
		updated.DisableCooldowns = *req.DisableCooldowns
	}
	if req.RetryPolicy != nil {
		rp := *req.RetryPolicy
		updated.RetryPolicy = &rp
	}
	if req.CooldownPolicy != nil {
		cp := *req.CooldownPolicy
		updated.CooldownPolicy = &cp
	}
	if req.MaxRetries != nil {
		updated.MaxRetries = *req.MaxRetries
	}
	if req.CooldownSeconds != nil {
		updated.CooldownSeconds = *req.CooldownSeconds
	}
	if req.FailureThreshold != nil {
		updated.FailureThreshold = *req.FailureThreshold
	}
	if req.IsActive != nil {
		updated.IsActive = *req.IsActive
	}
	if err := validateModelGroupFields(&updated); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: http.StatusBadRequest, Type: domain.ErrorTypeInvalidRequest, Message: err.Error()})
		return
	}
	if err := s.repo.UpdateModelGroup(r.Context(), &updated); err != nil {
		writeStorageLookupError(w, err, "model_group_not_found", "Model group not found")
		return
	}
	s.invalidateRoutingCaches(r.Context(), storage.InvalidationEvent{EntityType: "model_group", EntityID: updated.ID, OrgID: updated.OrgID})
	s.auditWithDiff(r.Context(), updated.OrgID, "model_group.updated", "model_group", updated.ID, map[string]any{"alias": updated.Alias, "strategy": updated.RoutingStrategy, "is_active": updated.IsActive}, existing, &updated)
	writeJSON(w, http.StatusOK, updated)
}

func (s *GatewayServer) handleAdminDeleteModelGroup(w http.ResponseWriter, r *http.Request) {
	groupID := strings.TrimSpace(chi.URLParam(r, "groupID"))
	existing, err := s.repo.GetModelGroupByID(r.Context(), groupID)
	if err != nil || existing == nil {
		if _, ok := s.authorizeAdmin(w, r, resolveScopedOrgID(r, r.URL.Query().Get("org_id")), true); !ok {
			return
		}
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: http.StatusNotFound, Type: domain.ErrorTypeNotFound, Code: "model_group_not_found", Message: "Model group not found"})
		return
	}
	if _, ok := s.authorizeAdmin(w, r, existing.OrgID, true); !ok {
		return
	}
	if err := s.repo.DeleteModelGroup(r.Context(), groupID); err != nil {
		writeStorageLookupError(w, err, "model_group_not_found", "Model group not found")
		return
	}
	s.invalidateRoutingCaches(r.Context(), storage.InvalidationEvent{EntityType: "model_group", EntityID: groupID, OrgID: existing.OrgID})
	s.auditWithDiff(r.Context(), existing.OrgID, "model_group.deleted", "model_group", groupID, map[string]any{"alias": existing.Alias}, existing, nil)
	writeJSON(w, http.StatusOK, map[string]any{"status": "deleted", "id": groupID})
}

func (s *GatewayServer) handleAdminCreateDeployment(w http.ResponseWriter, r *http.Request) {
	var dep domain.Deployment
	if err := decodeAdminJSON(w, r, &dep); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 400, Type: domain.ErrorTypeInvalidRequest, Message: err.Error()})
		return
	}
	if err := validateDeploymentFields(&dep); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 400, Type: domain.ErrorTypeInvalidRequest, Message: err.Error()})
		return
	}
	targetOrgID := ""
	if dep.ModelGroupID != "" {
		mg, err := s.repo.GetModelGroupByID(r.Context(), dep.ModelGroupID)
		if err != nil || mg == nil {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusNotFound,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "model_group_not_found",
				Message:    "Model group not found",
			})
			return
		}
		targetOrgID = mg.OrgID
	}
	if _, ok := s.authorizeAdmin(w, r, targetOrgID, true); !ok {
		return
	}
	gm, gmErr := s.repo.GetGlobalModel(r.Context(), dep.GlobalModelID)
	strictPostgres := s.cfg != nil && strings.EqualFold(s.cfg.Storage.Mode, "postgres")
	if pg, ok := s.repo.(*storage.PostgresRepository); ok && pg.HasPostgresPool() {
		strictPostgres = true
	}
	if strictPostgres && (gmErr != nil || gm == nil) {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusNotFound,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "global_model_not_found",
			Message:    fmt.Sprintf("Global model %q not found in catalogue", dep.GlobalModelID),
		})
		return
	}
	if dep.CredentialID == "" {
		var providerHint domain.ProviderType
		if gm != nil {
			providerHint = gm.Provider
		} else if parsedProv, _, _ := config.ParseProviderModel(dep.GlobalModelID); parsedProv != "" {
			providerHint = parsedProv
		}
		if providerHint != "" && targetOrgID != "" {
			creds, listErr := s.repo.ListProviderCredentials(r.Context(), targetOrgID)
			if listErr != nil {
				domain.WriteHTTPError(w, listErr)
				return
			}
			var matches []*domain.ProviderCredential
			for _, c := range creds {
				if c != nil && c.IsActive && c.Provider == providerHint {
					matches = append(matches, c)
				}
			}
			switch len(matches) {
			case 1:
				dep.CredentialID = matches[0].ID
			case 0:
				if strictPostgres {
					domain.WriteHTTPError(w, &domain.GatewayError{
						StatusCode: http.StatusBadRequest,
						Type:       domain.ErrorTypeInvalidRequest,
						Code:       "provider_credential_required",
						Message:    fmt.Sprintf("No active provider credential configured for %q in target organization; create one or specify credential_id", providerHint),
					})
					return
				}
			default:
				domain.WriteHTTPError(w, &domain.GatewayError{
					StatusCode: http.StatusBadRequest,
					Type:       domain.ErrorTypeInvalidRequest,
					Code:       "ambiguous_provider_credential",
					Message:    fmt.Sprintf("Multiple active credentials exist for provider %q; specify credential_id explicitly", providerHint),
				})
				return
			}
		} else if strictPostgres {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusBadRequest,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "provider_credential_required",
				Message:    "credential_id is required when provider cannot be resolved unambiguously",
			})
			return
		}
	}
	if dep.CredentialID != "" {
		cred, err := s.repo.GetProviderCredential(r.Context(), dep.CredentialID)
		if err != nil || cred == nil {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusNotFound,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "provider_credential_not_found",
				Message:    "Provider credential not found",
			})
			return
		}
		if targetOrgID != "" && cred.OrgID != targetOrgID {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusForbidden,
				Type:       domain.ErrorTypePermission,
				Code:       "cross_tenant_credential",
				Message:    "Provider credential does not belong to target organization",
			})
			return
		}
	}
	dep.Status = domain.DeploymentStatusActive
	if err := s.repo.CreateDeployment(r.Context(), &dep); err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	s.invalidateRoutingCaches(r.Context(), storage.InvalidationEvent{EntityType: "deployment", EntityID: dep.ID, OrgID: targetOrgID})
	s.auditWithDiff(r.Context(), targetOrgID, "deployment.created", "deployment", dep.ID, map[string]any{
		"model_group_id":  dep.ModelGroupID,
		"global_model_id": dep.GlobalModelID,
		"credential_id":   dep.CredentialID,
		"priority":        dep.Priority,
		"weight":          dep.Weight,
	}, nil, &dep)
	writeJSON(w, http.StatusCreated, dep)
}

func (s *GatewayServer) handleAdminListDeployments(w http.ResponseWriter, r *http.Request) {
	groupID := r.URL.Query().Get("model_group_id")
	targetOrgID := s.resolveDeploymentOrgID(r.Context(), groupID)
	if _, ok := s.authorizeAdmin(w, r, targetOrgID, false); !ok {
		return
	}
	var deps []*domain.Deployment
	var err error
	if groupID != "" {
		deps, err = s.repo.ListDeploymentsByGroup(r.Context(), groupID)
	} else {
		deps, err = s.repo.ListAllDeployments(r.Context())
	}
	if err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": deps})
}

func (s *GatewayServer) handleAdminGetDeployment(w http.ResponseWriter, r *http.Request) {
	depID := strings.TrimSpace(chi.URLParam(r, "depID"))
	dep, err := s.repo.GetDeployment(r.Context(), depID)
	if err != nil || dep == nil {
		if _, ok := s.authorizeAdmin(w, r, "", false); !ok {
			return
		}
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: http.StatusNotFound, Type: domain.ErrorTypeNotFound, Code: "deployment_not_found", Message: "Deployment not found"})
		return
	}
	targetOrgID := s.resolveDeploymentOrgID(r.Context(), dep.ModelGroupID)
	if _, ok := s.authorizeAdmin(w, r, targetOrgID, false); !ok {
		return
	}
	writeJSON(w, http.StatusOK, dep)
}

func (s *GatewayServer) handleAdminPatchDeployment(w http.ResponseWriter, r *http.Request) {
	depID := strings.TrimSpace(chi.URLParam(r, "depID"))
	existing, err := s.repo.GetDeployment(r.Context(), depID)
	if err != nil || existing == nil {
		if _, ok := s.authorizeAdmin(w, r, "", true); !ok {
			return
		}
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: http.StatusNotFound, Type: domain.ErrorTypeNotFound, Code: "deployment_not_found", Message: "Deployment not found"})
		return
	}
	targetOrgID := s.resolveDeploymentOrgID(r.Context(), existing.ModelGroupID)
	if _, ok := s.authorizeAdmin(w, r, targetOrgID, true); !ok {
		return
	}
	var req struct {
		DeploymentName      *string   `json:"deployment_name,omitempty"`
		Region              *string   `json:"region,omitempty"`
		Weight              *int      `json:"weight,omitempty"`
		RPMCapacity         *int      `json:"rpm_capacity,omitempty"`
		TPMCapacity         *int      `json:"tpm_capacity,omitempty"`
		ITPMCapacity        *int      `json:"itpm_capacity,omitempty"`
		OTPMCapacity        *int      `json:"otpm_capacity,omitempty"`
		MaxParallelRequests *int      `json:"max_parallel_requests,omitempty"`
		TimeoutMs           *int      `json:"timeout_ms,omitempty"`
		Priority            *int      `json:"priority,omitempty"`
		Status              *string   `json:"status,omitempty"`
		Tags                *[]string `json:"tags,omitempty"`
		MaxBudgetMicros     *int64    `json:"max_budget_micros,omitempty"`
		BudgetResetPeriod   *string   `json:"budget_reset_period,omitempty"`
	}
	if err := decodeAdminJSON(w, r, &req); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: http.StatusBadRequest, Type: domain.ErrorTypeInvalidRequest, Message: err.Error()})
		return
	}
	updated := *existing
	if req.DeploymentName != nil {
		updated.DeploymentName = strings.TrimSpace(*req.DeploymentName)
	}
	if req.Region != nil {
		updated.Region = strings.TrimSpace(*req.Region)
	}
	if req.Weight != nil {
		updated.Weight = *req.Weight
	}
	if req.RPMCapacity != nil {
		updated.RPMCapacity = *req.RPMCapacity
	}
	if req.TPMCapacity != nil {
		updated.TPMCapacity = *req.TPMCapacity
	}
	if req.ITPMCapacity != nil {
		updated.ITPMCapacity = *req.ITPMCapacity
	}
	if req.OTPMCapacity != nil {
		updated.OTPMCapacity = *req.OTPMCapacity
	}
	if req.MaxParallelRequests != nil {
		updated.MaxParallelRequests = *req.MaxParallelRequests
	}
	if req.TimeoutMs != nil {
		updated.TimeoutMs = *req.TimeoutMs
	}
	if req.Priority != nil {
		updated.Priority = *req.Priority
	}
	if req.Status != nil {
		updated.Status = domain.DeploymentStatus(strings.ToLower(strings.TrimSpace(*req.Status)))
	}
	if req.Tags != nil {
		updated.Tags = slices.Clone(*req.Tags)
	}
	if req.MaxBudgetMicros != nil {
		updated.MaxBudgetMicros = *req.MaxBudgetMicros
	}
	if req.BudgetResetPeriod != nil {
		updated.BudgetResetPeriod = strings.TrimSpace(*req.BudgetResetPeriod)
	}
	if err := validateDeploymentFields(&updated); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: http.StatusBadRequest, Type: domain.ErrorTypeInvalidRequest, Message: err.Error()})
		return
	}
	if err := s.repo.UpdateDeployment(r.Context(), &updated); err != nil {
		writeStorageLookupError(w, err, "deployment_not_found", "Deployment not found")
		return
	}
	s.invalidateRoutingCaches(r.Context(), storage.InvalidationEvent{EntityType: "deployment", EntityID: updated.ID, OrgID: targetOrgID})
	s.auditWithDiff(r.Context(), targetOrgID, "deployment.updated", "deployment", updated.ID, map[string]any{
		"status":                updated.Status,
		"weight":                updated.Weight,
		"priority":              updated.Priority,
		"max_parallel_requests": updated.MaxParallelRequests,
	}, existing, &updated)
	writeJSON(w, http.StatusOK, updated)
}

func (s *GatewayServer) handleAdminDeleteDeployment(w http.ResponseWriter, r *http.Request) {
	depID := strings.TrimSpace(chi.URLParam(r, "depID"))
	existing, err := s.repo.GetDeployment(r.Context(), depID)
	if err != nil || existing == nil {
		if _, ok := s.authorizeAdmin(w, r, "", true); !ok {
			return
		}
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: http.StatusNotFound, Type: domain.ErrorTypeNotFound, Code: "deployment_not_found", Message: "Deployment not found"})
		return
	}
	targetOrgID := s.resolveDeploymentOrgID(r.Context(), existing.ModelGroupID)
	if _, ok := s.authorizeAdmin(w, r, targetOrgID, true); !ok {
		return
	}
	if err := s.repo.DeleteDeployment(r.Context(), depID); err != nil {
		writeStorageLookupError(w, err, "deployment_not_found", "Deployment not found")
		return
	}
	s.invalidateRoutingCaches(r.Context(), storage.InvalidationEvent{EntityType: "deployment", EntityID: depID, OrgID: targetOrgID})
	s.auditWithDiff(r.Context(), targetOrgID, "deployment.deleted", "deployment", depID, map[string]any{
		"model_group_id":  existing.ModelGroupID,
		"global_model_id": existing.GlobalModelID,
	}, existing, nil)
	writeJSON(w, http.StatusOK, map[string]any{"status": "deleted", "id": depID})
}

// --- Layer 1 Global Catalogue, Automated Discovery & Versioned Pricing ---

func (s *GatewayServer) handleAdminListCatalogue(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorizeAdmin(w, r, "", false); !ok {
		return
	}
	models, err := s.repo.ListGlobalModels(r.Context())
	if err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": models})
}

func (s *GatewayServer) handleAdminTriggerDiscoverySync(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorizeAdmin(w, r, "", true); !ok {
		return
	}
	report, err := s.discovery.SyncNow(r.Context())
	if err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	s.audit(r.Context(), "", "catalogue.discovery.synced", "catalogue", "global", map[string]any{
		"report": report,
	})
	writeJSON(w, http.StatusOK, report)
}

func (s *GatewayServer) handleAdminImportCatalogue(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorizeAdmin(w, r, "", true); !ok {
		return
	}
	targetProv := domain.ProviderType(strings.ToLower(strings.TrimSpace(r.URL.Query().Get("provider"))))
	var models []*domain.GlobalModel
	if targetProv != "" {
		models = catalog.Search(targetProv, "")
	} else {
		models = catalog.All()
	}

	imported := 0
	for _, m := range models {
		if err := s.repo.UpsertGlobalModel(r.Context(), m); err == nil {
			imported++
		}
	}

	s.audit(r.Context(), "", "catalogue.import.completed", "catalogue", "global", map[string]any{
		"imported": imported,
		"provider": string(targetProv),
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"imported": imported,
		"provider": string(targetProv),
		"total":    catalog.Count(),
	})
}

func (s *GatewayServer) handleAdminUpdateModelPricing(w http.ResponseWriter, r *http.Request) {
	op, ok := s.authorizeAdmin(w, r, "", true)
	if !ok {
		return
	}
	var req struct {
		GlobalModelID              string               `json:"global_model_id"`
		InputCostMicrosPer1M       int64                `json:"input_cost_micros_per_1m"`
		OutputCostMicrosPer1M      int64                `json:"output_cost_micros_per_1m"`
		CachedInputCostMicrosPer1M int64                `json:"cached_input_cost_micros_per_1m"`
		ReasoningCostMicrosPer1M   int64                `json:"reasoning_cost_micros_per_1m"`
		PricingStatus              domain.PricingStatus `json:"pricing_status,omitempty"`
		PricingProvenanceSource    string               `json:"pricing_provenance_source,omitempty"`
		PricingEffectiveDate       string               `json:"pricing_effective_date,omitempty"`
		ChangedBy                  string               `json:"changed_by,omitempty"`
	}
	if err := decodeAdminJSON(w, r, &req); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 400, Type: domain.ErrorTypeInvalidRequest, Message: err.Error()})
		return
	}
	if req.ChangedBy == "" {
		req.ChangedBy = op.ActorID
	}
	if req.PricingStatus == "" {
		req.PricingStatus = domain.PricingStatusVerified
	}
	if req.PricingProvenanceSource == "" {
		req.PricingProvenanceSource = "admin-audit-" + time.Now().UTC().Format("2006-01-02")
	}
	if req.PricingEffectiveDate == "" {
		req.PricingEffectiveDate = time.Now().UTC().Format(time.RFC3339)
	}
	beforeModel, _ := s.repo.GetGlobalModel(r.Context(), req.GlobalModelID)
	gm, err := s.repo.UpdateModelPricing(
		r.Context(), req.GlobalModelID, req.InputCostMicrosPer1M, req.OutputCostMicrosPer1M,
		req.CachedInputCostMicrosPer1M, req.ReasoningCostMicrosPer1M, req.PricingStatus,
		req.PricingProvenanceSource, req.PricingEffectiveDate, req.ChangedBy,
	)
	if err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 404, Type: domain.ErrorTypeNotFound, Message: err.Error()})
		return
	}
	hist, _ := s.repo.ListModelPricingHistory(r.Context(), req.GlobalModelID)
	s.auditWithDiff(r.Context(), "", "catalogue.pricing.updated", "global_model", gm.ID, map[string]any{
		"model_name":               gm.ModelName,
		"pricing_version":          gm.PricingVersion,
		"input_cost_micros_per_1m": gm.InputCostMicrosPer1M,
		"pricing_status":           gm.PricingStatus,
		"provenance_source":        gm.PricingProvenanceSource,
	}, beforeModel, gm)
	writeJSON(w, http.StatusOK, map[string]any{
		"model":   gm,
		"history": hist,
	})
}

func (s *GatewayServer) handleAdminListModelPricingHistory(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorizeAdmin(w, r, "", false); !ok {
		return
	}
	modelID := r.URL.Query().Get("global_model_id")
	hist, err := s.repo.ListModelPricingHistory(r.Context(), modelID)
	if err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": hist})
}

// --- Observability, Active Deployment Health & Cache Invalidation ---

func (s *GatewayServer) handleAdminObservabilityMetrics(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorizeAdmin(w, r, "", false); !ok {
		return
	}
	writeJSON(w, http.StatusOK, s.collector.Snapshot())
}

func (s *GatewayServer) handleAdminListDeploymentHealth(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorizeAdmin(w, r, "", false); !ok {
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": s.healthMon.GetReports()})
}

func (s *GatewayServer) handleAdminProbeDeployments(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorizeAdmin(w, r, "", true); !ok {
		return
	}
	reports, err := s.healthMon.ProbeAllNow(r.Context())
	if err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	s.audit(r.Context(), "", "health.deployments.probed", "deployment_health", "all", map[string]any{
		"probed_count": len(reports),
	})
	writeJSON(w, http.StatusOK, map[string]any{"data": reports})
}

func (s *GatewayServer) handleAdminInvalidateCache(w http.ResponseWriter, r *http.Request) {
	var req struct {
		OrgID string `json:"org_id,omitempty"`
		Model string `json:"model,omitempty"`
	}
	_ = decodeAdminJSON(w, r, &req)
	req.OrgID = resolveScopedOrgID(r, req.OrgID)
	if _, ok := s.authorizeAdmin(w, r, req.OrgID, true); !ok {
		return
	}
	purged, nsVer, err := s.respCache.Invalidate(r.Context(), req.OrgID, req.Model)
	if err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusServiceUnavailable,
			Type:       domain.ErrorTypeServer,
			Code:       "cache_invalidation_unavailable",
			Message:    "Response cache invalidation could not update shared state",
		})
		return
	}
	s.invalidateRoutingCaches(r.Context(), storage.InvalidationEvent{
		EntityType: "all",
		EntityID:   req.Model,
		OrgID:      req.OrgID,
	})
	if s.respCache != nil && s.respCache.Type() == config.CacheTypeLocal && s.redisFabric != nil {
		s.redisFabric.PublishInvalidation(r.Context(), storage.InvalidationEvent{
			EntityType: "response_cache",
			EntityID:   req.Model,
			OrgID:      req.OrgID,
		})
	}
	s.audit(r.Context(), req.OrgID, "cache.invalidated", "response_cache", "global", map[string]any{
		"org_id":            req.OrgID,
		"model":             req.Model,
		"purged_entries":    purged,
		"namespace_version": nsVer,
	})
	writeJSON(w, http.StatusOK, map[string]any{
		"status":            "invalidated",
		"purged_entries":    purged,
		"namespace_version": nsVer,
	})
}

// --- FinOps Analytics & Governance Audit Logs ---

func (s *GatewayServer) handleAdminSpendSummary(w http.ResponseWriter, r *http.Request) {
	orgID := resolveScopedOrgID(r, r.URL.Query().Get("org_id"))
	teamID := resolveScopedTeamID(r, r.URL.Query().Get("team_id"))
	if _, ok := s.authorizeTeamAdmin(w, r, orgID, teamID, false); !ok {
		return
	}
	_ = s.spendWorker.FlushNow(r.Context())
	if teamID != "" {
		if tsRepo, ok := s.repo.(storage.TeamSpendRepository); ok && tsRepo != nil {
			sum, err := tsRepo.GetTeamSpendSummary(r.Context(), orgID, teamID)
			if err != nil {
				domain.WriteHTTPError(w, err)
				return
			}
			writeJSON(w, http.StatusOK, sum)
			return
		}
		logs, err := s.repo.ListSpendLogs(r.Context(), orgID, 10000)
		if err != nil {
			domain.WriteHTTPError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, summarizeSpendEventsForTeam(logs, teamID))
		return
	}
	sum, err := s.repo.GetSpendSummary(r.Context(), orgID)
	if err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, sum)
}

func summarizeSpendEventsForTeam(events []domain.SpendEvent, teamID string) *storage.SpendSummary {
	sum := &storage.SpendSummary{
		SpendByProvider:   make(map[string]int64),
		SpendByModel:      make(map[string]int64),
		SpendByTeam:       make(map[string]int64),
		SpendByUser:       make(map[string]int64),
		SpendByVirtualKey: make(map[string]int64),
	}
	for _, ev := range events {
		if ev.TeamID != teamID {
			continue
		}
		sum.TotalRequests++
		sum.TotalTokens += int64(ev.Usage.TotalTokens)
		sum.TotalCostMicros += ev.CostMicros
		if ev.PricingStatus == domain.PricingStatusUnknown || ev.PricingStatus == domain.PricingStatusUnrecorded {
			sum.UnpricedRequests++
			sum.UnpricedTokens += int64(ev.Usage.TotalTokens)
		}
		sum.SpendByProvider[string(ev.Provider)] += ev.CostMicros
		sum.SpendByModel[ev.ResolvedModel] += ev.CostMicros
		if ev.TeamID != "" {
			sum.SpendByTeam[ev.TeamID] += ev.CostMicros
		}
		if ev.UserID != "" {
			sum.SpendByUser[ev.UserID] += ev.CostMicros
		}
		if ev.VirtualKeyID != "" {
			sum.SpendByVirtualKey[ev.VirtualKeyID] += ev.CostMicros
		}
	}
	sum.TotalCostUSD = float64(sum.TotalCostMicros) / 1_000_000.0
	return sum
}

func (s *GatewayServer) handleAdminSpendLogs(w http.ResponseWriter, r *http.Request) {
	orgID := resolveScopedOrgID(r, r.URL.Query().Get("org_id"))
	teamID := resolveScopedTeamID(r, r.URL.Query().Get("team_id"))
	if _, ok := s.authorizeTeamAdmin(w, r, orgID, teamID, false); !ok {
		return
	}
	_ = s.spendWorker.FlushNow(r.Context())
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	if teamID != "" {
		if tsRepo, ok := s.repo.(storage.TeamSpendRepository); ok && tsRepo != nil {
			logs, err := tsRepo.ListTeamSpendLogs(r.Context(), orgID, teamID, limit)
			if err != nil {
				domain.WriteHTTPError(w, err)
				return
			}
			if logs == nil {
				logs = []domain.SpendEvent{}
			}
			writeJSON(w, http.StatusOK, map[string]any{"data": logs})
			return
		}
		logs, err := s.repo.ListSpendLogs(r.Context(), orgID, limit)
		if err != nil {
			domain.WriteHTTPError(w, err)
			return
		}
		filtered := make([]domain.SpendEvent, 0)
		for _, ev := range logs {
			if ev.TeamID == teamID {
				filtered = append(filtered, ev)
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"data": filtered})
		return
	}
	logs, err := s.repo.ListSpendLogs(r.Context(), orgID, limit)
	if err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": logs})
}
func (s *GatewayServer) handleAdminAuditLogs(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	orgID := resolveScopedOrgID(r, q.Get("org_id"))
	if _, ok := s.authorizeAdmin(w, r, orgID, false); !ok {
		return
	}
	limit, _ := strconv.Atoi(q.Get("limit"))
	filter := domain.AuditLogFilter{
		OrgID:      orgID,
		ActorID:    strings.TrimSpace(q.Get("actor_id")),
		Action:     strings.TrimSpace(q.Get("action")),
		Resource:   strings.TrimSpace(q.Get("resource")),
		ResourceID: strings.TrimSpace(q.Get("resource_id")),
		Cursor:     strings.TrimSpace(q.Get("cursor")),
		Limit:      limit,
	}
	if rawSince := strings.TrimSpace(q.Get("since")); rawSince != "" {
		ts, err := time.Parse(time.RFC3339, rawSince)
		if err != nil {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusBadRequest,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "invalid_since_timestamp",
				Message:    "since must be an RFC3339 timestamp",
			})
			return
		}
		filter.Since = &ts
	}
	if rawUntil := strings.TrimSpace(q.Get("until")); rawUntil != "" {
		ts, err := time.Parse(time.RFC3339, rawUntil)
		if err != nil {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusBadRequest,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "invalid_until_timestamp",
				Message:    "until must be an RFC3339 timestamp",
			})
			return
		}
		filter.Until = &ts
	}

	logs, nextCursor, err := s.repo.ListAuditLogsFiltered(r.Context(), filter)
	if err != nil {
		if strings.Contains(err.Error(), "cursor") {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusBadRequest,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "invalid_cursor",
				Message:    err.Error(),
			})
			return
		}
		domain.WriteHTTPError(w, err)
		return
	}
	if logs == nil {
		logs = []*domain.AuditLog{}
	}
	resp := map[string]any{"data": logs}
	if nextCursor != "" {
		resp["next_cursor"] = nextCursor
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *GatewayServer) handleAdminGetConfig(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorizeAdmin(w, r, "", false); !ok {
		return
	}
	out := sanitizeRuntimeConfig(s.cfg)
	if mcpMap, ok := out["mcp"].(map[string]any); ok && s.mcpHub != nil {
		rs := s.mcpHub.RuntimeSettings()
		mcpMap["active_protocol_version"] = rs.ActiveProtocolVersion
		mcpMap["strict_schema_validation"] = rs.StrictSchemaValidation
		mcpMap["supported_versions"] = spec.SupportedVersions()
	}
	writeJSON(w, http.StatusOK, out)
}

func redactSecret(val string) string {
	if strings.TrimSpace(val) == "" {
		return ""
	}
	return "[REDACTED]"
}

func redactURLPassword(raw string) string {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return ""
	}
	u, err := url.Parse(trimmed)
	if err != nil || u.User == nil {
		return trimmed
	}
	if _, hasPass := u.User.Password(); !hasPass {
		return trimmed
	}
	u.User = url.UserPassword(u.User.Username(), "REDACTED")
	return u.String()
}

func redactHeaders(headers map[string]string) map[string]string {
	if len(headers) == 0 {
		return nil
	}
	out := make(map[string]string, len(headers))
	for k := range headers {
		out[k] = "[REDACTED]"
	}
	return out
}

func sanitizeRuntimeConfig(cfg *config.Config) map[string]any {
	if cfg == nil {
		return map[string]any{}
	}

	definitions := make([]map[string]any, 0, len(cfg.Guardrails.Definitions))
	for _, def := range cfg.Guardrails.Definitions {
		enabled := true
		if def.Enabled != nil {
			enabled = *def.Enabled
		}
		definitions = append(definitions, map[string]any{
			"name":        def.Name,
			"provider":    def.Provider,
			"event_hooks": def.EventHooks,
			"enabled":     enabled,
			"timeout_ms":  def.TimeoutMs,
			"fail_open":   def.FailOpen,
			"precedence":  def.Precedence,
			"has_secrets": len(def.Secrets) > 0,
		})
	}

	modelList := make([]map[string]any, 0, len(cfg.ModelList))
	for _, m := range cfg.ModelList {
		modelList = append(modelList, map[string]any{
			"model_name":              m.ModelName,
			"routing_strategy":        m.RoutingStrategy,
			"fallbacks":               m.Fallbacks,
			"saturation_fallbacks":    m.SaturationFallbacks,
			"drop_unsupported_params": m.DropUnsupportedParams,
			"disable_cooldowns":       m.DisableCooldowns,
			"model_params": map[string]any{
				"model":                 m.ModelParams.Model,
				"api_key":               redactSecret(m.ModelParams.APIKey),
				"api_base":              redactURLPassword(m.ModelParams.APIBase),
				"region":                m.ModelParams.Region,
				"weight":                m.ModelParams.Weight,
				"rpm":                   m.ModelParams.RPM,
				"tpm":                   m.ModelParams.TPM,
				"itpm":                  m.ModelParams.ITPM,
				"otpm":                  m.ModelParams.OTPM,
				"max_parallel_requests": m.ModelParams.MaxParallelRequests,
				"priority":              m.ModelParams.Priority,
				"tags":                  m.ModelParams.Tags,
				"max_budget_micros":     m.ModelParams.MaxBudgetMicros,
				"budget_reset_period":   m.ModelParams.BudgetResetPeriod,
				"headers":               redactHeaders(m.ModelParams.Headers),
			},
		})
	}

	ssoProviders := make([]map[string]any, 0, len(cfg.Auth.SSOProviders))
	for _, p := range cfg.Auth.SSOProviders {
		ssoProviders = append(ssoProviders, map[string]any{
			"id":                     p.ID,
			"name":                   p.Name,
			"type":                   p.Type,
			"display_name":           p.DisplayName,
			"client_id":              p.ClientID,
			"client_secret":          redactSecret(p.ClientSecret),
			"issuer":                 p.Issuer,
			"authorization_endpoint": p.AuthorizationEndpoint,
			"token_endpoint":         p.TokenEndpoint,
			"jwks_url":               p.JWKSURL,
			"discovery_url":          p.DiscoveryURL,
			"scopes":                 p.Scopes,
			"redirect_url":           p.RedirectURL,
			"allowed_email_domains":  p.AllowedEmailDomains,
			"auto_register":          p.AutoRegister,
			"default_org_id":         p.DefaultOrgID,
			"default_team_id":        p.DefaultTeamID,
			"default_role":           p.DefaultRole,
		})
	}

	oidcIssuers := make([]map[string]any, 0, len(cfg.Auth.OIDCIssuers))
	for _, iss := range cfg.Auth.OIDCIssuers {
		oidcIssuers = append(oidcIssuers, map[string]any{
			"issuer":                       iss.Issuer,
			"audience":                     iss.Audience,
			"jwks_url":                     iss.JWKSURL,
			"discovery_url":                iss.DiscoveryURL,
			"algorithms":                   iss.Algorithms,
			"allowed_email_domains":        iss.AllowedEmailDomains,
			"allow_unverified_email":       iss.AllowUnverifiedEmail,
			"allow_privileged_role_claims": iss.AllowPrivilegedRoleClaims,
			"auto_register":                iss.AutoRegister,
			"default_org_id":               iss.DefaultOrgID,
			"default_team_id":              iss.DefaultTeamID,
			"default_role":                 iss.DefaultRole,
		})
	}

	return map[string]any{
		"server": map[string]any{
			"environment":                    cfg.Server.Environment,
			"public_base_url":                cfg.Server.PublicBaseURL,
			"host":                           cfg.Server.Host,
			"port":                           cfg.Server.Port,
			"grpc_port":                      cfg.Server.GRPCPort,
			"read_timeout":                   cfg.Server.ReadTimeout.String(),
			"write_timeout":                  cfg.Server.WriteTimeout.String(),
			"idle_timeout":                   cfg.Server.IdleTimeout.String(),
			"shutdown_timeout":               cfg.Server.ShutdownTimeout.String(),
			"cors_allowed_origins":           cfg.Server.CORSAllowedOrigins,
			"cors_allow_credentials":         cfg.Server.CORSAllowCredentials,
			"enable_hsts":                    cfg.Server.EnableHSTS,
			"max_file_storage_bytes_per_org": cfg.Server.MaxFileStorageBytesPerOrg,
			"max_concurrent_file_uploads":    cfg.Server.MaxConcurrentFileUploads,
		},
		"logging": map[string]any{
			"level":      cfg.Logging.Level,
			"format":     cfg.Logging.Format,
			"add_source": cfg.Logging.AddSource,
		},
		"otel": map[string]any{
			"enabled":                cfg.OTel.Enabled,
			"endpoint":               redactURLPassword(cfg.OTel.Endpoint),
			"service_name":           cfg.OTel.ServiceName,
			"service_version":        cfg.OTel.ServiceVersion,
			"deployment_environment": cfg.OTel.DeploymentEnvironment,
			"headers":                redactHeaders(cfg.OTel.Headers),
			"traces": map[string]any{
				"enabled":         cfg.OTel.TracesEnabled(),
				"endpoint":        redactURLPassword(cfg.OTel.Traces.Endpoint),
				"sampler":         cfg.OTel.Traces.Sampler,
				"sampler_arg":     cfg.OTel.Traces.SamplerArg,
				"capture_content": cfg.OTel.Traces.CaptureContent,
			},
			"metrics": map[string]any{
				"enabled":         cfg.OTel.MetricsEnabled(),
				"endpoint":        redactURLPassword(cfg.OTel.Metrics.Endpoint),
				"export_interval": cfg.OTel.Metrics.ExportInterval.String(),
			},
			"logs": map[string]any{
				"enabled":  cfg.OTel.LogsEnabled(),
				"endpoint": redactURLPassword(cfg.OTel.Logs.Endpoint),
			},
		},
		"health": map[string]any{
			"probe_enabled":  cfg.Health.IsProbeEnabled(),
			"probe_interval": cfg.Health.ProbeInterval.String(),
			"probe_timeout":  cfg.Health.ProbeTimeout.String(),
		},
		"tracing": map[string]any{
			"enabled":       cfg.OTel.TracesEnabled(),
			"otlp_endpoint": redactURLPassword(cfg.OTel.ResolvedTracesEndpoint()),
			"service_name":  cfg.OTel.ServiceName,
			"headers":       redactHeaders(cfg.OTel.Headers),
		},
		"security": map[string]any{
			"outbound_ssrf": map[string]any{
				"allow_private_networks": cfg.Security.Network.OutboundSSRF.AllowPrivateNetworks,
				"allowed_private_cidrs":  cfg.Security.Network.OutboundSSRF.AllowedPrivateCIDRs,
				"allow_insecure_http":    cfg.Security.Network.OutboundSSRF.AllowInsecureHTTP,
				"allow_loopback_http":    cfg.Security.Network.OutboundSSRF.AllowLoopbackHTTP,
				"allowed_schemes":        cfg.Security.Network.OutboundSSRF.AllowedSchemes,
				"blocked_ips":            cfg.Security.Network.OutboundSSRF.BlockedIPs,
				"dial_timeout":           cfg.Security.Network.OutboundSSRF.DialTimeout.String(),
				"max_redirects":          cfg.Security.Network.OutboundSSRF.MaxRedirects,
				"egress_proxy_url":       redactURLPassword(cfg.Security.Network.OutboundSSRF.EgressProxyURL),
			},
			"inbound_caller": map[string]any{
				"expose_on_public_internet": cfg.Security.Network.InboundCaller.ExposeOnPublicInternet,
				"allowed_client_cidrs":      cfg.Security.Network.InboundCaller.AllowedClientCIDRs,
				"trusted_proxy_cidrs":       cfg.Security.Network.InboundCaller.TrustedProxyCIDRs,
			},
		},
		"storage": map[string]any{
			"mode":              cfg.Storage.Mode,
			"postgres_dsn":      redactURLPassword(cfg.Storage.PostgresDSN),
			"redis_addr":        cfg.Storage.RedisAddr,
			"redis_addrs":       cfg.Storage.RedisAddrs,
			"redis_master_name": cfg.Storage.RedisMasterName,
			"redis_pass":        redactSecret(cfg.Storage.RedisPass),
			"redis_db":          cfg.Storage.RedisDB,
		},
		"auth": map[string]any{
			"master_admin_key":                    redactSecret(cfg.Auth.MasterAdminKey),
			"master_encryption_key":               redactSecret(cfg.Auth.MasterEncryptionKey),
			"previous_master_encryption_keys_cnt": len(cfg.Auth.PreviousMasterEncryptionKeys),
			"allow_master_key_data_plane":         cfg.Auth.AllowMasterKeyDataPlane,
			"enable_data_plane_jwt":               cfg.Auth.EnableDataPlaneJWT,
			"custom_api_key_header":               cfg.Auth.CustomAPIKeyHeader,
			"jwt_issuer":                          cfg.Auth.JWTIssuer,
			"jwt_audience":                        cfg.Auth.JWTAudience,
			"oidc_jwks_url":                       cfg.Auth.OIDCJWKSURL,
			"default_org_id":                      cfg.Auth.DefaultOrgID,
			"default_virtual_key":                 redactSecret(cfg.Auth.DefaultVirtualKey),
			"l1_cache_ttl":                        cfg.Auth.L1CacheTTL.String(),
			"l2_cache_ttl":                        cfg.Auth.L2CacheTTL.String(),
			"key_rotation_delivery_url":           redactURLPassword(cfg.Auth.KeyRotationDeliveryURL),
			"key_rotation_delivery_token":         redactSecret(cfg.Auth.KeyRotationDeliveryToken),
			"key_rotation_sink": map[string]any{
				"driver":      cfg.Auth.KeyRotationSink.Driver,
				"address":     redactURLPassword(cfg.Auth.KeyRotationSink.Address),
				"mount":       cfg.Auth.KeyRotationSink.Mount,
				"path_prefix": cfg.Auth.KeyRotationSink.PathPrefix,
				"namespace":   cfg.Auth.KeyRotationSink.Namespace,
				"token":       redactSecret(cfg.Auth.KeyRotationSink.Token),
			},
			"key_rotation_poll_interval":     cfg.Auth.KeyRotationPollInterval.String(),
			"key_rotation_grace_period":      cfg.Auth.KeyRotationGracePeriod.String(),
			"key_expiry_alert_poll_interval": cfg.Auth.KeyExpiryAlertPollInterval.String(),
			"session_secret":                 redactSecret(cfg.Auth.SessionSecret),
			"session_ttl":                    cfg.Auth.SessionTTL.String(),
			"cli_login_default_ttl":          cfg.Auth.CLILoginDefaultTTL.String(),
			"cli_login_max_ttl":              cfg.Auth.CLILoginMaxTTL.String(),
			"auth_start_rate_limit_per_min":  cfg.Auth.AuthStartRateLimitPerMin,
			"oidc_issuers":                   oidcIssuers,
			"sso_providers":                  ssoProviders,
			"introspection": map[string]any{
				"token_info_endpoint":          cfg.Auth.Introspection.TokenInfoEndpoint,
				"issuer":                       cfg.Auth.Introspection.Issuer,
				"audience":                     cfg.Auth.Introspection.Audience,
				"discovery_url":                cfg.Auth.Introspection.DiscoveryURL,
				"client_id":                    cfg.Auth.Introspection.ClientID,
				"client_secret":                redactSecret(cfg.Auth.Introspection.ClientSecret),
				"mode":                         cfg.Auth.Introspection.Mode,
				"cache_ttl":                    cfg.Auth.Introspection.CacheTTL.String(),
				"auto_register":                cfg.Auth.Introspection.AutoRegister,
				"allow_unverified_email":       cfg.Auth.Introspection.AllowUnverifiedEmail,
				"allow_privileged_role_claims": cfg.Auth.Introspection.AllowPrivilegedRoleClaims,
			},
			"external_authorizer": map[string]any{
				"enabled":     cfg.Auth.ExternalAuthorizer.Enabled,
				"mode":        cfg.Auth.ExternalAuthorizer.Mode,
				"url":         redactURLPassword(cfg.Auth.ExternalAuthorizer.URL),
				"timeout":     cfg.Auth.ExternalAuthorizer.Timeout.String(),
				"fail_mode":   cfg.Auth.ExternalAuthorizer.FailMode,
				"cache_ttl":   cfg.Auth.ExternalAuthorizer.CacheTTL.String(),
				"auth_header": redactSecret(cfg.Auth.ExternalAuthorizer.AuthHeader),
				"hmac_secret": redactSecret(cfg.Auth.ExternalAuthorizer.HMACSecret),
			},
		},
		"audit": map[string]any{
			"siem_webhook": map[string]any{
				"enabled":        cfg.Audit.SIEMWebhook.Enabled,
				"url":            redactURLPassword(cfg.Audit.SIEMWebhook.URL),
				"secret":         redactSecret(cfg.Audit.SIEMWebhook.Secret),
				"auth_header":    redactSecret(cfg.Audit.SIEMWebhook.AuthHeader),
				"batch_size":     cfg.Audit.SIEMWebhook.BatchSize,
				"flush_interval": cfg.Audit.SIEMWebhook.FlushInterval.String(),
				"timeout":        cfg.Audit.SIEMWebhook.Timeout.String(),
				"max_queue_size": cfg.Audit.SIEMWebhook.MaxQueueSize,
			},
		},
		"router": map[string]any{
			"default_fast_alias":                 cfg.Router.DefaultFastAlias,
			"default_reasoning_alias":            cfg.Router.DefaultReasoningAlias,
			"default_coding_alias":               cfg.Router.DefaultCodingAlias,
			"complexity_threshold":               cfg.Router.ComplexityThreshold,
			"long_context_tokens":                cfg.Router.LongContextTokens,
			"default_max_retries":                cfg.Router.DefaultMaxRetries,
			"base_retry_delay":                   cfg.Router.BaseRetryDelay.String(),
			"max_retry_delay":                    cfg.Router.MaxRetryDelay.String(),
			"default_cooldown":                   cfg.Router.DefaultCooldown.String(),
			"failure_window":                     cfg.Router.FailureWindow.String(),
			"failure_threshold":                  cfg.Router.FailureThreshold,
			"max_fallback_depth":                 cfg.Router.MaxFallbackDepth,
			"retry_policy":                       cfg.Router.RetryPolicy,
			"cooldown_policy":                    cfg.Router.CooldownPolicy,
			"enable_mid_stream_continuation":     cfg.Router.EnableMidStreamContinuation,
			"max_stream_continuations":           cfg.Router.MaxStreamContinuations,
			"health_staleness_threshold":         cfg.Router.HealthStalenessThreshold.String(),
			"strict_capacity_filtering":          cfg.Router.StrictCapacityFiltering,
			"provider_budgets":                   cfg.Router.ProviderBudgets,
			"session_affinity_ttl":               cfg.Router.SessionAffinityTTL.String(),
			"session_affinity_repin_on_failover": cfg.Router.SessionAffinityRepinOnFailover,
			"prompt_cache_affinity":              cfg.Router.PromptCacheAffinity,
			"pre_router_mode":                    cfg.Router.PreRouterMode,
			"semantic_router": map[string]any{
				"enabled":              cfg.Router.SemanticRouter.Enabled,
				"embedding_model":      cfg.Router.SemanticRouter.EmbeddingModel,
				"similarity_threshold": cfg.Router.SemanticRouter.SimilarityThreshold,
				"timeout":              cfg.Router.SemanticRouter.Timeout.String(),
				"routes":               cfg.Router.SemanticRouter.Routes,
			},
			"bandit": map[string]any{
				"enabled":          cfg.Router.Bandit.Enabled,
				"default_alpha":    cfg.Router.Bandit.DefaultAlpha,
				"default_beta":     cfg.Router.Bandit.DefaultBeta,
				"exploration_rate": cfg.Router.Bandit.ExplorationRate,
				"decay_half_life":  cfg.Router.Bandit.DecayHalfLife.String(),
				"latency_weight":   cfg.Router.Bandit.LatencyWeight,
				"cost_weight":      cfg.Router.Bandit.CostWeight,
				"sync_interval":    cfg.Router.Bandit.SyncInterval.String(),
				"candidate_models": cfg.Router.Bandit.CandidateModels,
			},
			"hedge_delay_ms":                 cfg.Router.HedgeDelayMs,
			"max_hedge_concurrency":          cfg.Router.MaxHedgeConcurrency,
			"latency_tolerance_pct":          cfg.Router.LatencyTolerancePct,
			"max_honored_retry_after":        cfg.Router.MaxHonoredRetryAfter.String(),
			"disable_cooldowns":              cfg.Router.DisableCooldowns,
			"fallback_on_saturation":         cfg.Router.FallbackOnSaturation,
			"drop_unsupported_params":        cfg.Router.DropUnsupportedParams,
			"fallback_on_unsupported_params": cfg.Router.FallbackOnUnsupportedParams,
			"allow_strategy_override":        cfg.Router.AllowStrategyOverride,
			"debug_routing_headers":          cfg.Router.DebugRoutingHeaders,
			"scheduler": map[string]any{
				"enabled":              cfg.Router.Scheduler.Enabled,
				"max_queue_depth":      cfg.Router.Scheduler.MaxQueueDepth,
				"max_wait_time":        cfg.Router.Scheduler.MaxWaitTime.String(),
				"default_priority":     cfg.Router.Scheduler.DefaultPriority,
				"max_parallel_wait_ms": cfg.Router.Scheduler.MaxParallelWaitMs,
			},
			"priority_capacity": map[string]any{
				"enabled":                 cfg.Router.PriorityCapacity.Enabled,
				"saturation_threshold":    cfg.Router.PriorityCapacity.SaturationThreshold,
				"active_caller_ttl":       cfg.Router.PriorityCapacity.ActiveCallerTTL.String(),
				"window_duration":         cfg.Router.PriorityCapacity.WindowDuration.String(),
				"default_weight":          cfg.Router.PriorityCapacity.DefaultWeight,
				"default_borrow_multiple": cfg.Router.PriorityCapacity.DefaultBorrowMultiple,
			},
		},
		"rate_limit": map[string]any{
			"enabled":                     cfg.RateLimit.Enabled,
			"fallback_to_local_on_outage": cfg.RateLimit.FallbackToLocalOnOutage,
			"window_seconds":              cfg.RateLimit.WindowSeconds,
			"concurrency_ttl_sec":         cfg.RateLimit.ConcurrencyTTLSec,
			"default_estimated_tpm":       cfg.RateLimit.DefaultEstimatedTPM,
			"redis_timeout":               cfg.RateLimit.RedisTimeout.String(),
			"global_rpm_limit":            cfg.RateLimit.GlobalRPMLimit,
			"global_tpm_limit":            cfg.RateLimit.GlobalTPMLimit,
			"global_max_concurrent":       cfg.RateLimit.GlobalMaxConcurrent,
		},
		"finops": map[string]any{
			"channel_buffer_size": cfg.FinOps.ChannelBufferSize,
			"batch_size":          cfg.FinOps.BatchSize,
			"flush_interval":      cfg.FinOps.FlushInterval.String(),
			"worker_count":        cfg.FinOps.WorkerCount,
		},
		"discovery": map[string]any{
			"enabled":       cfg.Discovery.Enabled,
			"sync_interval": cfg.Discovery.SyncInterval.String(),
			"auto_approve":  cfg.Discovery.AutoApprove,
		},
		"cache": map[string]any{
			"enabled":             cfg.Cache.Enabled,
			"type":                cfg.Cache.Type,
			"default_ttl":         cfg.Cache.DefaultTTL.String(),
			"namespace":           cfg.Cache.Namespace,
			"max_entries":         cfg.Cache.MaxEntries,
			"max_item_bytes":      cfg.Cache.MaxItemBytes,
			"excluded_call_types": cfg.Cache.ExcludedCallTypes,
			"redis_addr":          cfg.Cache.RedisAddr,
			"redis_addrs":         cfg.Cache.RedisAddrs,
			"redis_master_name":   cfg.Cache.RedisMasterName,
			"redis_pass":          redactSecret(cfg.Cache.RedisPass),
			"redis_db":            cfg.Cache.RedisDB,
			"redis_tls":           cfg.Cache.RedisTLS,
			"semantic": map[string]any{
				"embedding_model":      cfg.Cache.Semantic.EmbeddingModel,
				"similarity_threshold": cfg.Cache.Semantic.SimilarityThreshold,
				"index_name":           cfg.Cache.Semantic.IndexName,
				"vector_algorithm":     cfg.Cache.Semantic.VectorAlgorithm,
				"embedding_timeout":    cfg.Cache.Semantic.EmbeddingTimeout.String(),
				"max_messages":         cfg.Cache.Semantic.MaxMessages,
				"max_input_chars":      cfg.Cache.Semantic.MaxInputChars,
			},
		},
		"guardrails": map[string]any{
			"definitions": definitions,
		},
		"mcp": map[string]any{
			"enabled":                     cfg.MCP.Enabled,
			"default_protocol_version":    cfg.MCP.DefaultProtocolVersion,
			"strict_schema_validation":    cfg.MCP.StrictSchemaValidation,
			"allow_stdio_servers":         cfg.MCP.AllowStdioServers,
			"allowed_stdio_binaries":      cfg.MCP.AllowedStdioBinaries,
			"enable_session_compat_2025":  cfg.MCP.EnableSessionCompat2025,
			"session_ttl_2025":            cfg.MCP.SessionTTL2025.String(),
			"cache_key_secret":            redactSecret(cfg.MCP.CacheKeySecret),
			"max_payload_bytes":           cfg.MCP.MaxPayloadBytes,
			"default_timeout":             cfg.MCP.DefaultTimeout.String(),
			"subscriptions_listen_active": cfg.MCP.SubscriptionsListenActive,
		},
		"a2a": map[string]any{
			"enabled":                      cfg.A2A.Enabled,
			"enable_jsonrpc":               cfg.A2A.EnableJSONRPC,
			"enable_http_json":             cfg.A2A.EnableHTTPJSON,
			"enable_subscribe_post_compat": cfg.A2A.EnableSubscribePostCompat,
			"allow_legacy_card_discovery":  cfg.A2A.AllowLegacyCardDiscovery,
			"max_task_lifespan":            cfg.A2A.MaxTaskLifespan.String(),
			"stream_buffer_capacity":       cfg.A2A.StreamBufferCapacity,
			"stream_publish_interval":      cfg.A2A.StreamPublishInterval.String(),
			"max_push_retries":             cfg.A2A.MaxPushRetries,
			"signing_key_id":               cfg.A2A.SigningKeyID,
			"allowed_signing_algs":         cfg.A2A.AllowedSigningAlgs,
			"trusted_card_jwks":            cfg.A2A.TrustedCardJWKS,
		},
		"providers": map[string]any{
			"request_timeout":         cfg.Providers.RequestTimeout.String(),
			"response_header_timeout": cfg.Providers.ResponseHeaderTimeout.String(),
			"stream_idle_timeout":     cfg.Providers.StreamIdleTimeout.String(),
			"max_idle_conns":          cfg.Providers.MaxIdleConns,
			"max_idle_conns_per_host": cfg.Providers.MaxIdleConnsPerHost,
		},
		"model_list": modelList,
	}
}
