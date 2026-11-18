package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/goroute-ai/ai-gateway-go/internal/adapter"
	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/modelcatalog"
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
	return op, true
}

func (s *GatewayServer) authorizeTeamAdmin(w http.ResponseWriter, r *http.Request, targetOrgID, targetTeamID string, write bool) (*domain.OperatorContext, bool) {
	op := auth.OperatorFromContext(r.Context())
	if err := auth.AuthorizeTeamAdminAction(op, targetOrgID, targetTeamID, write); err != nil {
		domain.WriteHTTPError(w, err)
		return nil, false
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
	if cleanBaseURL != "" && s.cfg != nil &&
		(s.cfg.Security.Network.OutboundSSRF.AllowPrivateNetworks || len(s.cfg.Security.Network.OutboundSSRF.AllowedPrivateCIDRs) > 0) &&
		(op == nil || op.Role != domain.OperatorRolePlatformAdmin) {
		return &domain.GatewayError{
			StatusCode: http.StatusForbidden,
			Type:       domain.ErrorTypePermission,
			Code:       "platform_admin_required",
			Message:    "Custom BaseURL with private network access requires platform_admin role",
		}
	}
	return nil
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
	if s == nil || s.repo == nil {
		return
	}
	actorID := "master_admin"
	var impersonatedBy string
	if op := auth.OperatorFromContext(ctx); op != nil {
		if op.ActorID != "" {
			actorID = op.ActorID
		}
		impersonatedBy = op.ImpersonatedByActorID
	}
	if impersonatedBy != "" {
		enriched := make(map[string]any, len(details)+2)
		for k, v := range details {
			enriched[k] = v
		}
		enriched["actor_id"] = actorID
		enriched["impersonated_by"] = impersonatedBy
		details = enriched
	}
	_ = s.repo.RecordAuditLog(ctx, &domain.AuditLog{
		OrgID:      orgID,
		ActorID:    actorID,
		Action:     action,
		Resource:   resource,
		ResourceID: resourceID,
		Details:    details,
	})
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
	org.IsActive = true
	if org.BudgetResetPeriod == "" {
		org.BudgetResetPeriod = domain.BudgetResetMonthly
	}
	if err := s.repo.CreateOrganization(r.Context(), &org); err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	s.audit(r.Context(), org.ID, "organization.created", "organization", org.ID, map[string]any{"name": org.Name})
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
	if err := s.repo.SetOrgProviderSubscription(r.Context(), &sub); err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	if s.rbac != nil {
		s.rbac.InvalidateOrgPolicies(r.Context(), orgID)
	}
	s.audit(r.Context(), orgID, "organization.subscription.updated", "org_provider_subscription", string(sub.Provider), map[string]any{
		"provider":        sub.Provider,
		"is_enabled":      sub.IsEnabled,
		"auto_enable_new": sub.AutoEnableNew,
	})
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
	if err := s.repo.SetOrgModelPolicy(r.Context(), &pol); err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	if s.rbac != nil {
		s.rbac.InvalidateOrgPolicies(r.Context(), orgID)
	}
	s.audit(r.Context(), orgID, "organization.model_policy.updated", "org_model_policy", pol.GlobalModelID, map[string]any{
		"global_model_id": pol.GlobalModelID,
		"is_enabled":      pol.IsEnabled,
	})
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
	if err := s.repo.SetGuardrailPolicy(r.Context(), &pol); err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	s.audit(r.Context(), orgID, "organization.guardrails.updated", "guardrail_policy", orgID, map[string]any{
		"enable_prompt_injection": pol.EnablePromptInjection,
		"prompt_injection_action": pol.PromptInjectionAction,
		"enable_pii_detection":    pol.EnablePIIDetection,
		"pii_action":              pol.PIIAction,
		"enable_secret_detection": pol.EnableSecretDetection,
		"secret_action":           pol.SecretAction,
		"redact_output_pii":       pol.RedactOutputPII,
	})
	writeJSON(w, http.StatusOK, pol)
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

func (s *GatewayServer) handleAdminSimulateGuardrails(w http.ResponseWriter, r *http.Request) {
	orgID := chi.URLParam(r, "orgID")
	if _, ok := s.authorizeAdmin(w, r, orgID, false); !ok {
		return
	}
	var req struct {
		Prompt string                  `json:"prompt"`
		Policy *domain.GuardrailPolicy `json:"policy,omitempty"`
	}
	if err := decodeAdminJSON(w, r, &req); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 400, Type: domain.ErrorTypeInvalidRequest, Message: err.Error()})
		return
	}
	if strings.TrimSpace(req.Prompt) == "" {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 400, Type: domain.ErrorTypeInvalidRequest, Message: "prompt is required"})
		return
	}

	pol := req.Policy
	if pol == nil {
		var err error
		pol, err = s.repo.GetGuardrailPolicy(r.Context(), orgID)
		if err != nil {
			domain.WriteHTTPError(w, err)
			return
		}
		if pol == nil {
			pol = &domain.GuardrailPolicy{OrgID: orgID}
		}
	} else if pol.OrgID == "" {
		pol.OrgID = orgID
	}

	canReq := &domain.CanonicalChatRequest{
		Messages: []domain.CanonicalMessage{
			{Role: "user", Content: req.Prompt},
		},
	}

	outcome, evalErr := s.guardrails.EvaluateInputWithPolicy(r.Context(), pol, canReq)
	resp := map[string]any{
		"allowed":         evalErr == nil,
		"applied_action":  outcome.AppliedAction,
		"violations":      outcome.Violations,
		"redacted":        outcome.Redacted,
		"redacted_prompt": canReq.Messages[0].Content,
	}
	if evalErr != nil {
		resp["error_message"] = evalErr.Error()
	}
	writeJSON(w, http.StatusOK, resp)
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
	team.IsActive = true
	if err := s.repo.CreateTeam(r.Context(), &team); err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	s.audit(r.Context(), team.OrgID, "team.created", "team", team.ID, map[string]any{"name": team.Name})
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
	s.audit(r.Context(), user.OrgID, "user.created", "user", user.ID, map[string]any{"email": user.Email, "role": user.Role})
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
	var req domain.VirtualKey
	if err := decodeAdminJSON(w, r, &req); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 400, Type: domain.ErrorTypeInvalidRequest, Message: err.Error()})
		return
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
		if req.UserID != "" && !s.userBelongsToTeam(r.Context(), req.OrgID, op.TeamID, req.UserID) {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusForbidden,
				Type:       domain.ErrorTypePermission,
				Code:       "cross_team_access_denied",
				Message:    "team_admin can only issue virtual keys for users belonging to their own team",
			})
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
	vk, err := s.authSvc.IssueVirtualKey(r.Context(), &req)
	if err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	s.audit(r.Context(), vk.OrgID, "virtual_key.issued", "virtual_key", vk.ID, map[string]any{
		"key_prefix":            vk.KeyPrefix,
		"name":                  vk.Name,
		"key_type":              vk.KeyType,
		"can_impersonate":       vk.CanImpersonate,
		"rotation_interval_sec": vk.RotationIntervalSec,
	})
	writeJSON(w, http.StatusCreated, vk)
}

func (s *GatewayServer) handleAdminListKeys(w http.ResponseWriter, r *http.Request) {
	orgID := resolveScopedOrgID(r, r.URL.Query().Get("org_id"))
	teamID := resolveScopedTeamID(r, r.URL.Query().Get("team_id"))
	if _, ok := s.authorizeTeamAdmin(w, r, orgID, teamID, false); !ok {
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
	writeJSON(w, http.StatusOK, map[string]any{"data": keys})
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
	if _, ok := s.authorizeTeamAdmin(w, r, vk.OrgID, vk.TeamID, true); !ok {
		return
	}
	if !verifyExplicitOrgMatch(w, r, vk.OrgID, nil) {
		return
	}
	if err := s.authSvc.RevokeKey(r.Context(), keyID); err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	s.audit(r.Context(), vk.OrgID, "virtual_key.revoked", "virtual_key", keyID, nil)
	writeJSON(w, http.StatusOK, map[string]any{"status": "revoked", "id": keyID})
}

// --- Boundary 2 Provider Credentials Vault & Lifecycle ---

func (s *GatewayServer) handleAdminCreateCredential(w http.ResponseWriter, r *http.Request) {
	var req struct {
		OrgID               string              `json:"org_id"`
		Provider            domain.ProviderType `json:"provider"`
		Name                string              `json:"name"`
		BaseURL             string              `json:"base_url"`
		AzureDeploymentName string              `json:"azure_deployment_name,omitempty"`
		APIVersion          string              `json:"api_version,omitempty"`
		APIKey              string              `json:"api_key"`
		Headers             map[string]string   `json:"headers,omitempty"`
		ExpiresAt           *time.Time          `json:"expires_at,omitempty"`
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
	cred := &domain.ProviderCredential{
		OrgID:               req.OrgID,
		Provider:            req.Provider,
		Name:                req.Name,
		BaseURL:             cleanBaseURL,
		AzureDeploymentName: req.AzureDeploymentName,
		APIVersion:          req.APIVersion,
		Headers:             req.Headers,
		IsActive:            true,
		ExpiresAt:           req.ExpiresAt,
	}
	if err := s.vault.EncryptCredential(cred, req.APIKey); err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	if err := s.repo.CreateProviderCredential(r.Context(), cred); err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	s.audit(r.Context(), cred.OrgID, "credential.created", "provider_credential", cred.ID, map[string]any{
		"provider":    cred.Provider,
		"name":        cred.Name,
		"key_version": cred.KeyVersion,
	})
	writeJSON(w, http.StatusCreated, cred)
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
	writeJSON(w, http.StatusOK, map[string]any{"data": creds})
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
	s.audit(r.Context(), cred.OrgID, "credential.rotated", "provider_credential", cred.ID, map[string]any{
		"provider":    cred.Provider,
		"key_version": cred.KeyVersion,
	})
	writeJSON(w, http.StatusOK, cred)
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
			errMsg = discErr.Error()
		}
	}
	s.audit(r.Context(), cred.OrgID, "credential.validated", "provider_credential", cred.ID, map[string]any{
		"provider":          cred.Provider,
		"valid":             valid,
		"validation_status": validationStatus,
		"discovered_models": len(models),
		"latency_ms":        latencyMs,
	})
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
		OrgID               string              `json:"org_id,omitempty"`
		Provider            domain.ProviderType `json:"provider"`
		APIKey              string              `json:"api_key"`
		BaseURL             string              `json:"base_url,omitempty"`
		AzureDeploymentName string              `json:"azure_deployment_name,omitempty"`
		APIVersion          string              `json:"api_version,omitempty"`
		Headers             map[string]string   `json:"headers,omitempty"`
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
	if req.Provider == "" {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 400, Type: domain.ErrorTypeInvalidRequest, Message: "provider is required"})
		return
	}
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
		Provider:            req.Provider,
		DecryptedAPIKey:     req.APIKey,
		BaseURL:             cleanBaseURL,
		AzureDeploymentName: req.AzureDeploymentName,
		APIVersion:          req.APIVersion,
		Headers:             req.Headers,
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
			errMsg = discErr.Error()
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
	for _, pair := range []struct {
		name    string
		targets []domain.FallbackTarget
	}{
		{"context_window_fallbacks", mg.ContextWindowFallbacks},
		{"content_policy_fallbacks", mg.ContentPolicyFallbacks},
		{"fallback_targets", mg.FallbackTargets},
	} {
		if err := validateFallbackTargets(pair.name, pair.targets); err != nil {
			domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 400, Type: domain.ErrorTypeInvalidRequest, Message: err.Error()})
			return
		}
	}
	if mg.CooldownPolicy != nil && (mg.CooldownPolicy.FailureRateThreshold < 0 || mg.CooldownPolicy.FailureRateThreshold > 1) {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 400, Type: domain.ErrorTypeInvalidRequest, Message: "cooldown_policy.failure_rate_threshold must be between 0 and 1"})
		return
	}
	mg.OrgID = resolveScopedOrgID(r, mg.OrgID)
	if _, ok := s.authorizeAdmin(w, r, mg.OrgID, true); !ok {
		return
	}
	mg.IsActive = true
	if err := s.repo.CreateModelGroup(r.Context(), &mg); err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	s.audit(r.Context(), mg.OrgID, "model_group.created", "model_group", mg.ID, map[string]any{"alias": mg.Alias, "strategy": mg.RoutingStrategy})
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

func (s *GatewayServer) handleAdminCreateDeployment(w http.ResponseWriter, r *http.Request) {
	var dep domain.Deployment
	if err := decodeAdminJSON(w, r, &dep); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 400, Type: domain.ErrorTypeInvalidRequest, Message: err.Error()})
		return
	}
	if dep.MaxBudgetMicros < 0 {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 400, Type: domain.ErrorTypeInvalidRequest, Message: "max_budget_micros cannot be negative"})
		return
	}
	if dep.BudgetResetPeriod != "" {
		switch domain.BudgetResetPeriod(dep.BudgetResetPeriod) {
		case domain.BudgetResetDaily, domain.BudgetResetMonthly, domain.BudgetResetNever:
		default:
			domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: 400, Type: domain.ErrorTypeInvalidRequest, Message: "budget_reset_period must be daily, monthly, or never"})
			return
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
	s.audit(r.Context(), "", "deployment.created", "deployment", dep.ID, map[string]any{
		"model_group_id":  dep.ModelGroupID,
		"global_model_id": dep.GlobalModelID,
		"priority":        dep.Priority,
		"weight":          dep.Weight,
	})
	writeJSON(w, http.StatusCreated, dep)
}

func (s *GatewayServer) handleAdminListDeployments(w http.ResponseWriter, r *http.Request) {
	groupID := r.URL.Query().Get("model_group_id")
	targetOrgID := ""
	if groupID != "" {
		if mg, err := s.repo.GetModelGroupByID(r.Context(), groupID); err == nil && mg != nil {
			targetOrgID = mg.OrgID
		}
	}
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
	s.audit(r.Context(), "", "catalogue.pricing.updated", "global_model", gm.ID, map[string]any{
		"model_name":               gm.ModelName,
		"pricing_version":          gm.PricingVersion,
		"input_cost_micros_per_1m": gm.InputCostMicrosPer1M,
		"pricing_status":           gm.PricingStatus,
		"provenance_source":        gm.PricingProvenanceSource,
	})
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
	orgID := resolveScopedOrgID(r, r.URL.Query().Get("org_id"))
	if _, ok := s.authorizeAdmin(w, r, orgID, false); !ok {
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	logs, err := s.repo.ListAuditLogs(r.Context(), orgID, limit)
	if err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": logs})
}

func (s *GatewayServer) handleAdminGetConfig(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorizeAdmin(w, r, "", false); !ok {
		return
	}
	writeJSON(w, http.StatusOK, sanitizeRuntimeConfig(s.cfg))
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

	scanners := make([]map[string]any, 0, len(cfg.Guardrails.Scanners))
	for _, sc := range cfg.Guardrails.Scanners {
		scanners = append(scanners, map[string]any{
			"name":       sc.Name,
			"url":        redactURLPassword(sc.URL),
			"timeout_ms": sc.TimeoutMs,
			"fail_open":  sc.FailOpen,
			"headers":    redactHeaders(sc.Headers),
		})
	}

	customProviders := make([]map[string]any, 0, len(cfg.Providers.CustomOpenAICompatible))
	for _, cp := range cfg.Providers.CustomOpenAICompatible {
		customProviders = append(customProviders, map[string]any{
			"id":                          cp.ID,
			"display_name":                cp.DisplayName,
			"base_url":                    redactURLPassword(cp.BaseURL),
			"supports_streaming":          cp.SupportsStreaming,
			"supports_tools":              cp.SupportsTools,
			"supports_structured_outputs": cp.SupportsStructuredOutputs,
			"supports_list_models":        cp.SupportsListModels,
			"supported_operations":        cp.SupportedOperations,
			"param_mappings":              cp.ParamMappings,
			"reasoning_mapping":           cp.ReasoningMapping,
			"default_headers":             redactHeaders(cp.DefaultHeaders),
		})
	}

	modelList := make([]map[string]any, 0, len(cfg.ModelList))
	for _, m := range cfg.ModelList {
		modelList = append(modelList, map[string]any{
			"model_name":       m.ModelName,
			"routing_strategy": m.RoutingStrategy,
			"fallbacks":        m.Fallbacks,
			"model_params": map[string]any{
				"model":                 m.ModelParams.Model,
				"api_key":               redactSecret(m.ModelParams.APIKey),
				"api_base":              redactURLPassword(m.ModelParams.APIBase),
				"region":                m.ModelParams.Region,
				"weight":                m.ModelParams.Weight,
				"rpm":                   m.ModelParams.RPM,
				"tpm":                   m.ModelParams.TPM,
				"azure_deployment_name": m.ModelParams.AzureDeploymentName,
				"api_version":           m.ModelParams.APIVersion,
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
			"tenant_id":              p.TenantID,
		})
	}

	return map[string]any{
		"server": map[string]any{
			"environment":                    cfg.Server.Environment,
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
		"tracing": map[string]any{
			"enabled":       cfg.Tracing.Enabled,
			"otlp_endpoint": redactURLPassword(cfg.Tracing.OTLPEndpoint),
			"service_name":  cfg.Tracing.ServiceName,
			"headers":       redactHeaders(cfg.Tracing.Headers),
		},
		"security": map[string]any{
			"outbound_ssrf": map[string]any{
				"allow_private_networks": cfg.Security.Network.OutboundSSRF.AllowPrivateNetworks,
				"allowed_private_cidrs":  cfg.Security.Network.OutboundSSRF.AllowedPrivateCIDRs,
				"allow_insecure_http":    cfg.Security.Network.OutboundSSRF.AllowInsecureHTTP,
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
			"master_admin_key":            redactSecret(cfg.Auth.MasterAdminKey),
			"master_encryption_key":       redactSecret(cfg.Auth.MasterEncryptionKey),
			"allow_master_key_data_plane": cfg.Auth.AllowMasterKeyDataPlane,
			"enable_data_plane_jwt":       cfg.Auth.EnableDataPlaneJWT,
			"custom_api_key_header":       cfg.Auth.CustomAPIKeyHeader,
			"jwt_secret":                  redactSecret(cfg.Auth.JWTSecret),
			"jwt_issuer":                  cfg.Auth.JWTIssuer,
			"jwt_audience":                cfg.Auth.JWTAudience,
			"oidc_jwks_url":               cfg.Auth.OIDCJWKSURL,
			"default_org_id":              cfg.Auth.DefaultOrgID,
			"default_virtual_key":         redactSecret(cfg.Auth.DefaultVirtualKey),
			"l1_cache_ttl":                cfg.Auth.L1CacheTTL.String(),
			"l2_cache_ttl":                cfg.Auth.L2CacheTTL.String(),
			"key_rotation_poll_interval":  cfg.Auth.KeyRotationPollInterval.String(),
			"key_rotation_grace_period":   cfg.Auth.KeyRotationGracePeriod.String(),
			"ui_username":                 cfg.Auth.UIUsername,
			"ui_password":                 redactSecret(cfg.Auth.UIPassword),
			"session_secret":              redactSecret(cfg.Auth.SessionSecret),
			"session_ttl":                 cfg.Auth.SessionTTL.String(),
			"enable_hibp_check":           cfg.Auth.EnableHIBPCheck,
			"sso_providers":               ssoProviders,
		},
		"router": map[string]any{
			"default_fast_alias":      cfg.Router.DefaultFastAlias,
			"default_reasoning_alias": cfg.Router.DefaultReasoningAlias,
			"default_coding_alias":    cfg.Router.DefaultCodingAlias,
			"complexity_threshold":    cfg.Router.ComplexityThreshold,
			"long_context_tokens":     cfg.Router.LongContextTokens,
			"default_max_retries":     cfg.Router.DefaultMaxRetries,
			"base_retry_delay":        cfg.Router.BaseRetryDelay.String(),
			"max_retry_delay":         cfg.Router.MaxRetryDelay.String(),
			"default_cooldown":        cfg.Router.DefaultCooldown.String(),
			"failure_window":          cfg.Router.FailureWindow.String(),
			"failure_threshold":       cfg.Router.FailureThreshold,
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
			"enabled":        cfg.Cache.Enabled,
			"default_ttl":    cfg.Cache.DefaultTTL.String(),
			"max_l1_entries": cfg.Cache.MaxL1Entries,
		},
		"guardrails": map[string]any{
			"scanners": scanners,
		},
		"mcp": map[string]any{
			"enabled":                     cfg.MCP.Enabled,
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
			"request_timeout":          cfg.Providers.RequestTimeout.String(),
			"response_header_timeout":  cfg.Providers.ResponseHeaderTimeout.String(),
			"stream_idle_timeout":      cfg.Providers.StreamIdleTimeout.String(),
			"max_idle_conns":           cfg.Providers.MaxIdleConns,
			"max_idle_conns_per_host":  cfg.Providers.MaxIdleConnsPerHost,
			"custom_openai_compatible": customProviders,
		},
		"model_list": modelList,
	}
}
