package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

// optionalStringSlice preserves 3-state JSON patch semantics:
// omitted => Set:false, JSON null => Set:true with Value:nil (Inherit),
// JSON [] => Set:true with non-nil Value:[]string{} (DenyAll).
type optionalStringSlice struct {
	Set   bool
	Value []string
}

func (o *optionalStringSlice) UnmarshalJSON(data []byte) error {
	o.Set = true
	if bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		o.Value = nil
		return nil
	}
	var s []string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	if s == nil {
		s = []string{}
	}
	o.Value = s
	return nil
}

func (s *GatewayServer) lookupUserByID(ctx context.Context, userID string) (*domain.User, error) {
	if s == nil || s.repo == nil {
		return nil, storage.ErrNotFound
	}
	if ul, ok := s.repo.(storage.UserLookupRepository); ok {
		return ul.GetUser(ctx, userID)
	}
	users, err := s.repo.ListUsers(ctx, "")
	if err != nil {
		return nil, err
	}
	for _, u := range users {
		if u != nil && u.ID == userID {
			return u, nil
		}
	}
	return nil, storage.ErrNotFound
}

func applySoftBudgetPolicyPatch(
	w http.ResponseWriter,
	softBudget *int64,
	throttle *bool,
	fallbacks map[string][]string,
	dstSoftBudget *int64,
	dstThrottle *bool,
	dstFallbacks *map[string][]string,
) bool {
	if softBudget != nil {
		if *softBudget < 0 {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusBadRequest,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "invalid_soft_budget",
				Message:    "soft_budget_micros cannot be negative",
			})
			return false
		}
		*dstSoftBudget = *softBudget
	}
	if throttle != nil {
		*dstThrottle = *throttle
	}
	if fallbacks != nil {
		*dstFallbacks = domain.CloneBudgetFallbacks(fallbacks)
	}
	return true
}

func isVirtualKeyActive(vk *domain.VirtualKey, now time.Time) bool {
	if vk == nil || !vk.IsActive {
		return false
	}
	if vk.ExpiresAt != nil && !now.Before(*vk.ExpiresAt) {
		return false
	}
	return true
}

func verifyExplicitOrgMatch(w http.ResponseWriter, r *http.Request, targetOrgID string, bodyOrgID *string) bool {
	if queryOrgID := strings.TrimSpace(r.URL.Query().Get("org_id")); queryOrgID != "" && queryOrgID != targetOrgID {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusForbidden,
			Type:       domain.ErrorTypePermission,
			Code:       "cross_org_access_denied",
			Message:    "Target resource does not belong to the requested organization",
		})
		return false
	}
	if bodyOrgID != nil {
		if explicit := strings.TrimSpace(*bodyOrgID); explicit != "" && explicit != targetOrgID {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusForbidden,
				Type:       domain.ErrorTypePermission,
				Code:       "cross_org_access_denied",
				Message:    "Target resource does not belong to the requested organization",
			})
			return false
		}
	}
	return true
}

func (s *GatewayServer) enforceSelfServeBudgetPolicy(ctx context.Context, w http.ResponseWriter, op *domain.OperatorContext, orgID, teamID string, currentMax, requestedMax int64) bool {
	if op == nil || op.Role == domain.OperatorRolePlatformAdmin || op.Role == domain.OperatorRoleOrgAdmin {
		return true
	}
	if requestedMax == currentMax {
		return true
	}
	org, err := s.repo.GetOrganization(ctx, orgID)
	if err != nil || org == nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusForbidden,
			Type:       domain.ErrorTypePermission,
			Code:       "self_serve_budget_policy_unavailable",
			Message:    "Unable to evaluate organization self_serve_budget_policy",
		})
		return false
	}
	policy := org.SelfServeBudgetPolicy
	if policy == "" {
		policy = domain.SelfServeBudgetDisabled
	}
	switch policy {
	case domain.SelfServeBudgetDisabled:
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusForbidden,
			Type:       domain.ErrorTypePermission,
			Code:       "self_serve_budget_disabled",
			Message:    "Organization self_serve_budget_policy is disabled; only org_admin or platform_admin may modify budgets",
		})
		return false
	case domain.SelfServeBudgetLowerOnly:
		if requestedMax == 0 || (currentMax > 0 && requestedMax > currentMax) {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusForbidden,
				Type:       domain.ErrorTypePermission,
				Code:       "self_serve_budget_policy_violation",
				Message:    "Organization self_serve_budget_policy 'lower_only' only permits lowering an existing budget cap",
			})
			return false
		}
		return true
	case domain.SelfServeBudgetCeiling:
		ceiling := org.MaxBudgetMicros
		if teamID != "" {
			if team, teamErr := s.repo.GetTeam(ctx, teamID); teamErr == nil && team != nil && team.MaxBudgetMicros > 0 {
				if ceiling == 0 || team.MaxBudgetMicros < ceiling {
					ceiling = team.MaxBudgetMicros
				}
			}
		}
		if ceiling <= 0 || requestedMax == 0 || requestedMax > ceiling {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusForbidden,
				Type:       domain.ErrorTypePermission,
				Code:       "self_serve_budget_exceeds_ceiling",
				Message:    "Requested budget exceeds parent ceiling under self_serve_budget_policy 'ceiling'",
			})
			return false
		}
		return true
	default:
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusForbidden,
			Type:       domain.ErrorTypePermission,
			Code:       "self_serve_budget_disabled",
			Message:    "Unsupported organization self_serve_budget_policy",
		})
		return false
	}
}

func (s *GatewayServer) handleAdminUpdateTeam(w http.ResponseWriter, r *http.Request) {
	teamID := strings.TrimSpace(chi.URLParam(r, "teamID"))
	if teamID == "" {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "missing_team_id",
			Message:    "teamID is required",
		})
		return
	}

	existing, err := s.repo.GetTeam(r.Context(), teamID)
	if err != nil || existing == nil {
		if _, ok := s.authorizeTeamAdmin(w, r, resolveScopedOrgID(r, r.URL.Query().Get("org_id")), teamID, true); !ok {
			return
		}
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusNotFound,
			Type:       domain.ErrorTypeNotFound,
			Code:       "team_not_found",
			Message:    "Team not found",
		})
		return
	}

	op, ok := s.authorizeTeamAdmin(w, r, existing.OrgID, existing.ID, true)
	if !ok {
		return
	}

	var req struct {
		OrgID                        *string                   `json:"org_id,omitempty"`
		Name                         *string                   `json:"name,omitempty"`
		MaxBudgetMicros              *int64                    `json:"max_budget_micros,omitempty"`
		SoftBudgetMicros             *int64                    `json:"soft_budget_micros,omitempty"`
		ThrottleOnBudgetExceeded     *bool                     `json:"throttle_on_budget_exceeded,omitempty"`
		BudgetFallbacks              map[string][]string       `json:"budget_fallbacks,omitempty"`
		BudgetResetPeriod            *domain.BudgetResetPeriod `json:"budget_reset_period,omitempty"`
		RPMLimit                     *int                      `json:"rpm_limit,omitempty"`
		TPMLimit                     *int                      `json:"tpm_limit,omitempty"`
		MCPRPMLimit                  *int                      `json:"mcp_rpm_limit,omitempty"`
		MaxConcurrentRequests        *int                      `json:"max_concurrent_requests,omitempty"`
		BatchEnqueuedTokenLimit      *int64                    `json:"batch_enqueued_token_limit,omitempty"`
		MaxIterations                *int                      `json:"max_iterations,omitempty"`
		MaxBudgetPerSessionMicros    *int64                    `json:"max_budget_per_session_micros,omitempty"`
		AllowedModels                optionalStringSlice       `json:"allowed_models"`
		AllowedDeployments           optionalStringSlice       `json:"allowed_deployments"`
		AllowedMCPServers            optionalStringSlice       `json:"allowed_mcp_servers"`
		AllowedMCPTools              optionalStringSlice       `json:"allowed_mcp_tools"`
		AllowedMCPToolsets           optionalStringSlice       `json:"allowed_mcp_toolsets"`
		AllowedA2AAgents             optionalStringSlice       `json:"allowed_a2a_agents"`
		AllowedClientApps            optionalStringSlice       `json:"allowed_client_apps"`
		MinPriorityRank              *int                      `json:"min_priority_rank,omitempty"`
		AllowedRoutingTags           optionalStringSlice       `json:"allowed_routing_tags"`
		EnforceGuaranteedThroughput  *bool                     `json:"enforce_guaranteed_throughput,omitempty"`
		DefaultMemberMaxBudgetMicros *int64                    `json:"default_member_max_budget_micros,omitempty"`
		DefaultMemberRPMLimit        *int                      `json:"default_member_rpm_limit,omitempty"`
		DefaultMemberTPMLimit        *int                      `json:"default_member_tpm_limit,omitempty"`
		DefaultMemberAllowedModels   optionalStringSlice       `json:"default_member_allowed_models"`
		TeamMemberPermissions        optionalStringSlice       `json:"team_member_permissions"`
		IsActive                     *bool                     `json:"is_active,omitempty"`
	}
	if err := decodeAdminJSON(w, r, &req); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Message:    err.Error(),
		})
		return
	}
	if !verifyExplicitOrgMatch(w, r, existing.OrgID, req.OrgID) {
		return
	}

	updated := *existing
	if req.Name != nil {
		name := strings.TrimSpace(*req.Name)
		if name == "" {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusBadRequest,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "invalid_team_name",
				Message:    "Team name cannot be empty",
			})
			return
		}
		updated.Name = name
	}
	if strings.TrimSpace(updated.Name) == "" {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_team_name",
			Message:    "Team name is required",
		})
		return
	}
	if req.MaxBudgetMicros != nil {
		if *req.MaxBudgetMicros < 0 {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusBadRequest,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "invalid_budget",
				Message:    "max_budget_micros cannot be negative",
			})
			return
		}
		if !s.enforceSelfServeBudgetPolicy(r.Context(), w, op, existing.OrgID, "", existing.MaxBudgetMicros, *req.MaxBudgetMicros) {
			return
		}
		updated.MaxBudgetMicros = *req.MaxBudgetMicros
	}
	if !applySoftBudgetPolicyPatch(w, req.SoftBudgetMicros, req.ThrottleOnBudgetExceeded, req.BudgetFallbacks, &updated.SoftBudgetMicros, &updated.ThrottleOnBudgetExceeded, &updated.BudgetFallbacks) {
		return
	}
	if req.BudgetResetPeriod != nil && *req.BudgetResetPeriod != "" {
		updated.BudgetResetPeriod = *req.BudgetResetPeriod
	}
	if req.RPMLimit != nil {
		if *req.RPMLimit < 0 {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusBadRequest,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "invalid_rpm_limit",
				Message:    "rpm_limit cannot be negative",
			})
			return
		}
		updated.RPMLimit = *req.RPMLimit
	}
	if req.TPMLimit != nil {
		if *req.TPMLimit < 0 {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusBadRequest,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "invalid_tpm_limit",
				Message:    "tpm_limit cannot be negative",
			})
			return
		}
		updated.TPMLimit = *req.TPMLimit
	}
	if req.MaxConcurrentRequests != nil {
		if *req.MaxConcurrentRequests < 0 {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusBadRequest,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "invalid_concurrency_limit",
				Message:    "max_concurrent_requests cannot be negative",
			})
			return
		}
		updated.MaxConcurrentRequests = *req.MaxConcurrentRequests
	}
	if req.BatchEnqueuedTokenLimit != nil {
		if *req.BatchEnqueuedTokenLimit < 0 {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusBadRequest,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "invalid_batch_enqueued_token_limit",
				Message:    "batch_enqueued_token_limit cannot be negative",
			})
			return
		}
		updated.BatchEnqueuedTokenLimit = *req.BatchEnqueuedTokenLimit
	}
	if req.MCPRPMLimit != nil {
		if *req.MCPRPMLimit < 0 {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusBadRequest,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "invalid_mcp_rpm_limit",
				Message:    "mcp_rpm_limit cannot be negative",
			})
			return
		}
		updated.MCPRPMLimit = *req.MCPRPMLimit
	}
	if req.MaxIterations != nil {
		if *req.MaxIterations < 0 {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusBadRequest,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "invalid_max_iterations",
				Message:    "max_iterations cannot be negative",
			})
			return
		}
		updated.MaxIterations = *req.MaxIterations
	}
	if req.MaxBudgetPerSessionMicros != nil {
		if *req.MaxBudgetPerSessionMicros < 0 {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusBadRequest,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "invalid_session_budget",
				Message:    "max_budget_per_session_micros cannot be negative",
			})
			return
		}
		updated.MaxBudgetPerSessionMicros = *req.MaxBudgetPerSessionMicros
	}
	if req.AllowedModels.Set {
		updated.AllowedModels = req.AllowedModels.Value
	}
	if req.AllowedDeployments.Set {
		updated.AllowedDeployments = req.AllowedDeployments.Value
	}
	if req.AllowedMCPServers.Set {
		updated.AllowedMCPServers = req.AllowedMCPServers.Value
	}
	if req.AllowedMCPTools.Set {
		updated.AllowedMCPTools = req.AllowedMCPTools.Value
	}
	if req.AllowedMCPToolsets.Set {
		updated.AllowedMCPToolsets = req.AllowedMCPToolsets.Value
	}
	if req.AllowedA2AAgents.Set {
		updated.AllowedA2AAgents = req.AllowedA2AAgents.Value
	}
	if req.AllowedClientApps.Set {
		updated.AllowedClientApps = req.AllowedClientApps.Value
	}
	if req.MinPriorityRank != nil {
		if *req.MinPriorityRank < 0 {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusBadRequest,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "invalid_min_priority_rank",
				Message:    "min_priority_rank cannot be negative",
			})
			return
		}
		updated.MinPriorityRank = *req.MinPriorityRank
	}
	if req.AllowedRoutingTags.Set {
		updated.AllowedRoutingTags = normalizeRoutingTags(req.AllowedRoutingTags.Value)
	}
	if req.EnforceGuaranteedThroughput != nil {
		updated.EnforceGuaranteedThroughput = *req.EnforceGuaranteedThroughput
	}
	if req.DefaultMemberMaxBudgetMicros != nil {
		if *req.DefaultMemberMaxBudgetMicros < 0 {
			domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: http.StatusBadRequest, Type: domain.ErrorTypeInvalidRequest, Code: "invalid_budget", Message: "default_member_max_budget_micros cannot be negative"})
			return
		}
		updated.DefaultMemberMaxBudgetMicros = *req.DefaultMemberMaxBudgetMicros
	}
	if req.DefaultMemberRPMLimit != nil {
		if *req.DefaultMemberRPMLimit < 0 {
			domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: http.StatusBadRequest, Type: domain.ErrorTypeInvalidRequest, Code: "invalid_rpm_limit", Message: "default_member_rpm_limit cannot be negative"})
			return
		}
		updated.DefaultMemberRPMLimit = *req.DefaultMemberRPMLimit
	}
	if req.DefaultMemberTPMLimit != nil {
		if *req.DefaultMemberTPMLimit < 0 {
			domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: http.StatusBadRequest, Type: domain.ErrorTypeInvalidRequest, Code: "invalid_tpm_limit", Message: "default_member_tpm_limit cannot be negative"})
			return
		}
		updated.DefaultMemberTPMLimit = *req.DefaultMemberTPMLimit
	}
	if req.DefaultMemberAllowedModels.Set {
		updated.DefaultMemberAllowedModels = req.DefaultMemberAllowedModels.Value
	}
	if req.TeamMemberPermissions.Set {
		updated.TeamMemberPermissions = req.TeamMemberPermissions.Value
	}
	if req.IsActive != nil {
		updated.IsActive = *req.IsActive
	}

	if err := s.repo.UpdateTeam(r.Context(), &updated); err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	if s.authSvc != nil {
		s.authSvc.InvalidateTeam(r.Context(), updated.ID)
	}
	s.auditWithDiff(r.Context(), updated.OrgID, "team.updated", "team", updated.ID, map[string]any{
		"name":              updated.Name,
		"max_budget_micros": updated.MaxBudgetMicros,
		"min_priority_rank": updated.MinPriorityRank,
		"is_active":         updated.IsActive,
	}, existing, &updated)
	writeJSON(w, http.StatusOK, updated)
}

func (s *GatewayServer) handleAdminDeleteTeam(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxAdminRequestBodyBytes)
	teamID := strings.TrimSpace(chi.URLParam(r, "teamID"))
	if teamID == "" {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "missing_team_id",
			Message:    "teamID is required",
		})
		return
	}

	existing, err := s.repo.GetTeam(r.Context(), teamID)
	if err != nil || existing == nil {
		if _, ok := s.authorizeAdmin(w, r, resolveScopedOrgID(r, r.URL.Query().Get("org_id")), true); !ok {
			return
		}
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusNotFound,
			Type:       domain.ErrorTypeNotFound,
			Code:       "team_not_found",
			Message:    "Team not found",
		})
		return
	}

	if _, ok := s.authorizeAdmin(w, r, existing.OrgID, true); !ok {
		return
	}
	if !verifyExplicitOrgMatch(w, r, existing.OrgID, nil) {
		return
	}

	keys, err := s.repo.ListVirtualKeys(r.Context(), existing.OrgID)
	if err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	now := time.Now().UTC()
	for _, vk := range keys {
		if vk != nil && vk.TeamID == teamID && isVirtualKeyActive(vk, now) {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusConflict,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "team_has_active_keys",
				Message:    "Cannot delete team while it still has active virtual keys; revoke or reassign active keys first",
			})
			return
		}
	}

	if ptuRepo, ok := s.repo.(storage.PTUShareRepository); ok && ptuRepo != nil {
		hasPTU, err := ptuRepo.HasTeamPTUShares(r.Context(), teamID)
		if err != nil {
			domain.WriteHTTPError(w, err)
			return
		}
		if hasPTU {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusConflict,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "team_has_active_ptu_shares",
				Message:    "Cannot delete team while it has active deployment PTU shares; delete or reassign PTU shares first",
			})
			return
		}
	}

	if err := s.repo.DeleteTeam(r.Context(), teamID); err != nil {
		if errors.Is(err, storage.ErrTeamHasActivePTUShares) {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusConflict,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "team_has_active_ptu_shares",
				Message:    "Cannot delete team while it has active deployment PTU shares; delete or reassign PTU shares first",
			})
			return
		}
		domain.WriteHTTPError(w, err)
		return
	}
	if s.authSvc != nil {
		s.authSvc.InvalidateTeam(r.Context(), teamID)
	}
	s.auditWithDiff(r.Context(), existing.OrgID, "team.deleted", "team", teamID, map[string]any{
		"name": existing.Name,
	}, existing, nil)
	writeJSON(w, http.StatusOK, map[string]any{"status": "deleted", "id": teamID})
}

func (s *GatewayServer) handleAdminUpdateUser(w http.ResponseWriter, r *http.Request) {
	userID := strings.TrimSpace(chi.URLParam(r, "userID"))
	if userID == "" {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "missing_user_id",
			Message:    "userID is required",
		})
		return
	}

	existing, err := s.lookupUserByID(r.Context(), userID)
	if err != nil || existing == nil {
		if _, ok := s.authorizeAdmin(w, r, resolveScopedOrgID(r, r.URL.Query().Get("org_id")), true); !ok {
			return
		}
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusNotFound,
			Type:       domain.ErrorTypeNotFound,
			Code:       "user_not_found",
			Message:    "User not found",
		})
		return
	}

	op, ok := s.authorizeAdmin(w, r, existing.OrgID, true)
	if !ok {
		return
	}
	if !ensureOperatorCanMutateTargetRole(w, op, existing.Role, "user") {
		return
	}

	var req struct {
		OrgID                    *string                   `json:"org_id,omitempty"`
		TeamID                   *string                   `json:"team_id,omitempty"`
		Email                    *string                   `json:"email,omitempty"`
		Name                     *string                   `json:"name,omitempty"`
		Role                     *domain.Role              `json:"role,omitempty"`
		OIDCIssuer               *string                   `json:"oidc_issuer,omitempty"`
		OIDCSubject              *string                   `json:"oidc_subject,omitempty"`
		SCIMExternalID           *string                   `json:"scim_external_id,omitempty"`
		SCIMActive               *bool                     `json:"scim_active,omitempty"`
		MaxBudgetMicros          *int64                    `json:"max_budget_micros,omitempty"`
		SoftBudgetMicros         *int64                    `json:"soft_budget_micros,omitempty"`
		ThrottleOnBudgetExceeded *bool                     `json:"throttle_on_budget_exceeded,omitempty"`
		BudgetFallbacks          map[string][]string       `json:"budget_fallbacks,omitempty"`
		BudgetResetPeriod        *domain.BudgetResetPeriod `json:"budget_reset_period,omitempty"`
		RPMLimit                 *int                      `json:"rpm_limit,omitempty"`
		TPMLimit                 *int                      `json:"tpm_limit,omitempty"`
		MaxConcurrentRequests    *int                      `json:"max_concurrent_requests,omitempty"`
		BatchEnqueuedTokenLimit  *int64                    `json:"batch_enqueued_token_limit,omitempty"`
		IsActive                 *bool                     `json:"is_active,omitempty"`
	}
	if err := decodeAdminJSON(w, r, &req); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Message:    err.Error(),
		})
		return
	}
	if !verifyExplicitOrgMatch(w, r, existing.OrgID, req.OrgID) {
		return
	}

	updated := *existing
	if req.Email != nil {
		email := strings.TrimSpace(*req.Email)
		if email == "" {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusBadRequest,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "invalid_user_email",
				Message:    "User email cannot be empty",
			})
			return
		}
		updated.Email = email
	}
	if strings.TrimSpace(updated.Email) == "" {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_user_email",
			Message:    "User email is required",
		})
		return
	}
	if req.Name != nil {
		updated.Name = strings.TrimSpace(*req.Name)
	}
	if req.TeamID != nil {
		teamID := strings.TrimSpace(*req.TeamID)
		if teamID != "" {
			team, err := s.repo.GetTeam(r.Context(), teamID)
			if err != nil || team == nil {
				domain.WriteHTTPError(w, &domain.GatewayError{
					StatusCode: http.StatusBadRequest,
					Type:       domain.ErrorTypeInvalidRequest,
					Code:       "team_not_found",
					Message:    "Specified team was not found",
				})
				return
			}
			if team.OrgID != existing.OrgID {
				domain.WriteHTTPError(w, &domain.GatewayError{
					StatusCode: http.StatusForbidden,
					Type:       domain.ErrorTypePermission,
					Code:       "cross_org_team_assignment",
					Message:    "Specified team does not belong to user's organization",
				})
				return
			}
		}
		updated.TeamID = teamID
	}
	if req.Role != nil && *req.Role != "" {
		if *req.Role == domain.RolePlatformAdmin && op.Role != domain.OperatorRolePlatformAdmin {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusForbidden,
				Type:       domain.ErrorTypePermission,
				Code:       "platform_admin_required",
				Message:    "Only platform_admin can assign platform_admin role",
			})
			return
		}
		updated.Role = *req.Role
	}
	if req.OIDCIssuer != nil {
		updated.OIDCIssuer = strings.TrimSpace(*req.OIDCIssuer)
	}
	if req.OIDCSubject != nil {
		updated.OIDCSubject = strings.TrimSpace(*req.OIDCSubject)
	}
	if req.SCIMExternalID != nil {
		updated.SCIMExternalID = strings.TrimSpace(*req.SCIMExternalID)
	}
	if req.SCIMActive != nil {
		updated.SCIMActive = *req.SCIMActive
	}
	if req.MaxBudgetMicros != nil {
		if *req.MaxBudgetMicros < 0 {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusBadRequest,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "invalid_budget",
				Message:    "max_budget_micros cannot be negative",
			})
			return
		}
		if !s.enforceSelfServeBudgetPolicy(r.Context(), w, op, existing.OrgID, updated.TeamID, existing.MaxBudgetMicros, *req.MaxBudgetMicros) {
			return
		}
		updated.MaxBudgetMicros = *req.MaxBudgetMicros
	}
	if !applySoftBudgetPolicyPatch(w, req.SoftBudgetMicros, req.ThrottleOnBudgetExceeded, req.BudgetFallbacks, &updated.SoftBudgetMicros, &updated.ThrottleOnBudgetExceeded, &updated.BudgetFallbacks) {
		return
	}
	if req.BudgetResetPeriod != nil && *req.BudgetResetPeriod != "" {
		updated.BudgetResetPeriod = *req.BudgetResetPeriod
	}
	if req.RPMLimit != nil {
		if *req.RPMLimit < 0 {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusBadRequest,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "invalid_rpm_limit",
				Message:    "rpm_limit cannot be negative",
			})
			return
		}
		updated.RPMLimit = *req.RPMLimit
	}
	if req.TPMLimit != nil {
		if *req.TPMLimit < 0 {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusBadRequest,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "invalid_tpm_limit",
				Message:    "tpm_limit cannot be negative",
			})
			return
		}
		updated.TPMLimit = *req.TPMLimit
	}
	if req.MaxConcurrentRequests != nil {
		if *req.MaxConcurrentRequests < 0 {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusBadRequest,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "invalid_concurrency_limit",
				Message:    "max_concurrent_requests cannot be negative",
			})
			return
		}
		updated.MaxConcurrentRequests = *req.MaxConcurrentRequests
	}
	if req.BatchEnqueuedTokenLimit != nil {
		if *req.BatchEnqueuedTokenLimit < 0 {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusBadRequest,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "invalid_batch_enqueued_token_limit",
				Message:    "batch_enqueued_token_limit cannot be negative",
			})
			return
		}
		updated.BatchEnqueuedTokenLimit = *req.BatchEnqueuedTokenLimit
	}
	if req.IsActive != nil {
		updated.IsActive = *req.IsActive
	}

	if err := s.repo.UpdateUser(r.Context(), &updated); err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	if s.authSvc != nil {
		if !updated.IsActive || !updated.SCIMActive {
			s.authSvc.InvalidateUserKeys(r.Context(), updated.OrgID, updated.ID)
		} else {
			s.authSvc.InvalidateOrg(r.Context(), updated.OrgID)
		}
	}
	if s.sessionMgr != nil && (!updated.IsActive || !updated.SCIMActive || updated.Role != existing.Role || updated.OrgID != existing.OrgID || updated.OIDCIssuer != existing.OIDCIssuer || updated.OIDCSubject != existing.OIDCSubject) {
		_ = s.sessionMgr.RevokeAllUserSessions(r.Context(), updated.ID)
	}
	s.auditWithDiff(r.Context(), updated.OrgID, "user.updated", "user", updated.ID, map[string]any{
		"email":            updated.Email,
		"role":             updated.Role,
		"team_id":          updated.TeamID,
		"scim_external_id": updated.SCIMExternalID,
		"scim_active":      updated.SCIMActive,
		"is_active":        updated.IsActive,
	}, existing, updated)
	writeJSON(w, http.StatusOK, updated)
}

func (s *GatewayServer) handleAdminDeleteUser(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxAdminRequestBodyBytes)
	userID := strings.TrimSpace(chi.URLParam(r, "userID"))
	if userID == "" {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "missing_user_id",
			Message:    "userID is required",
		})
		return
	}

	existing, err := s.lookupUserByID(r.Context(), userID)
	if err != nil || existing == nil {
		if _, ok := s.authorizeAdmin(w, r, resolveScopedOrgID(r, r.URL.Query().Get("org_id")), true); !ok {
			return
		}
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusNotFound,
			Type:       domain.ErrorTypeNotFound,
			Code:       "user_not_found",
			Message:    "User not found",
		})
		return
	}

	op, ok := s.authorizeAdmin(w, r, existing.OrgID, true)
	if !ok {
		return
	}
	if !ensureOperatorCanMutateTargetRole(w, op, existing.Role, "user") {
		return
	}
	if !verifyExplicitOrgMatch(w, r, existing.OrgID, nil) {
		return
	}

	keys, err := s.repo.ListVirtualKeys(r.Context(), existing.OrgID)
	if err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	now := time.Now().UTC()
	for _, vk := range keys {
		if vk != nil && vk.UserID == userID && isVirtualKeyActive(vk, now) {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusConflict,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "user_has_active_keys",
				Message:    "Cannot delete user while they still have active virtual keys; revoke or reassign active keys first",
			})
			return
		}
	}

	if err := s.repo.DeleteUser(r.Context(), userID); err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	if s.authSvc != nil {
		s.authSvc.InvalidateOrg(r.Context(), existing.OrgID)
	}
	if s.sessionMgr != nil {
		_ = s.sessionMgr.RevokeAllUserSessions(r.Context(), userID)
	}
	s.auditWithDiff(r.Context(), existing.OrgID, "user.deleted", "user", userID, map[string]any{
		"email": existing.Email,
	}, existing, nil)
	writeJSON(w, http.StatusOK, map[string]any{"status": "deleted", "id": userID})
}

func assignNonNegativeInt(w http.ResponseWriter, val *int, errCode, errMsg string, dst *int) bool {
	if val == nil {
		return true
	}
	if *val < 0 {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       errCode,
			Message:    errMsg,
		})
		return false
	}
	*dst = *val
	return true
}

func assignNonNegativeInt64(w http.ResponseWriter, val *int64, errCode, errMsg string, dst *int64) bool {
	if val == nil {
		return true
	}
	if *val < 0 {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       errCode,
			Message:    errMsg,
		})
		return false
	}
	*dst = *val
	return true
}

type adminUpdateKeyRequest struct {
	OrgID                     *string                   `json:"org_id,omitempty"`
	Name                      *string                   `json:"name,omitempty"`
	TeamID                    *string                   `json:"team_id,omitempty"`
	ProjectID                 *string                   `json:"project_id,omitempty"`
	UserID                    *string                   `json:"user_id,omitempty"`
	Role                      *domain.Role              `json:"role,omitempty"`
	KeyType                   *domain.KeyType           `json:"key_type,omitempty"`
	AllowedModels             optionalStringSlice       `json:"allowed_models"`
	AllowedDeployments        optionalStringSlice       `json:"allowed_deployments"`
	AllowedEndpoints          optionalStringSlice       `json:"allowed_endpoints"`
	AllowedMCPServers         optionalStringSlice       `json:"allowed_mcp_servers"`
	AllowedMCPTools           optionalStringSlice       `json:"allowed_mcp_tools"`
	AllowedMCPToolsets        optionalStringSlice       `json:"allowed_mcp_toolsets"`
	AllowedA2AAgents          optionalStringSlice       `json:"allowed_a2a_agents"`
	AllowedClientApps         optionalStringSlice       `json:"allowed_client_apps"`
	MaxBudgetMicros           *int64                    `json:"max_budget_micros,omitempty"`
	SoftBudgetMicros          *int64                    `json:"soft_budget_micros,omitempty"`
	ThrottleOnBudgetExceeded  *bool                     `json:"throttle_on_budget_exceeded,omitempty"`
	BudgetFallbacks           map[string][]string       `json:"budget_fallbacks,omitempty"`
	BudgetResetPeriod         *domain.BudgetResetPeriod `json:"budget_reset_period,omitempty"`
	RPMLimit                  *int                      `json:"rpm_limit,omitempty"`
	TPMLimit                  *int                      `json:"tpm_limit,omitempty"`
	MCPRPMLimit               *int                      `json:"mcp_rpm_limit,omitempty"`
	MaxConcurrentRequests     *int                      `json:"max_concurrent_requests,omitempty"`
	BatchEnqueuedTokenLimit   *int64                    `json:"batch_enqueued_token_limit,omitempty"`
	MaxIterations             *int                      `json:"max_iterations,omitempty"`
	MaxBudgetPerSessionMicros *int64                    `json:"max_budget_per_session_micros,omitempty"`
	RotationIntervalSec       *int64                    `json:"rotation_interval_sec,omitempty"`
	KeyRotationAt             *time.Time                `json:"key_rotation_at,omitempty"`
	ExpiresAt                 *time.Time                `json:"expires_at,omitempty"`
	CanImpersonate            *bool                     `json:"can_impersonate,omitempty"`
	IsActive                  *bool                     `json:"is_active,omitempty"`
	Tags                      optionalStringSlice       `json:"tags"`
	MinPriorityRank           *int                      `json:"min_priority_rank,omitempty"`
	AllowedRoutingTags        optionalStringSlice       `json:"allowed_routing_tags"`
	Metadata                  map[string]string         `json:"metadata,omitempty"`
}

func (s *GatewayServer) applyVirtualKeyScopePatch(
	ctx context.Context,
	w http.ResponseWriter,
	op *domain.OperatorContext,
	existing *domain.VirtualKey,
	req *adminUpdateKeyRequest,
	updated *domain.VirtualKey,
) bool {
	if req.Name != nil {
		name := strings.TrimSpace(*req.Name)
		if name == "" {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusBadRequest,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "invalid_key_name",
				Message:    "Virtual key name cannot be empty",
			})
			return false
		}
		updated.Name = name
	}
	if req.TeamID != nil {
		newTeamID := strings.TrimSpace(*req.TeamID)
		if op.Role == domain.OperatorRoleTeamAdmin && newTeamID != op.TeamID {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusForbidden,
				Type:       domain.ErrorTypePermission,
				Code:       "cross_team_access_denied",
				Message:    "team_admin cannot reassign a virtual key outside their own team",
			})
			return false
		}
		updated.TeamID = newTeamID
	}
	if req.ProjectID != nil {
		newProjectID := strings.TrimSpace(*req.ProjectID)
		if newProjectID != "" {
			pmRepo, ok := s.projectMembershipRepo()
			if !ok {
				domain.WriteHTTPError(w, &domain.GatewayError{
					StatusCode: http.StatusNotImplemented,
					Type:       domain.ErrorTypeServer,
					Code:       "projects_unsupported",
					Message:    "Configured storage repository does not support projects",
				})
				return false
			}
			proj, pErr := pmRepo.GetProject(ctx, newProjectID)
			if pErr != nil || proj == nil {
				domain.WriteHTTPError(w, &domain.GatewayError{
					StatusCode: http.StatusNotFound,
					Type:       domain.ErrorTypeNotFound,
					Code:       "project_not_found",
					Message:    "Project not found",
				})
				return false
			}
			if proj.OrgID != existing.OrgID {
				domain.WriteHTTPError(w, &domain.GatewayError{
					StatusCode: http.StatusForbidden,
					Type:       domain.ErrorTypePermission,
					Code:       "cross_org_access_denied",
					Message:    "Project does not belong to the virtual key's organization",
				})
				return false
			}
			if op.Role == domain.OperatorRoleTeamAdmin && proj.TeamID != op.TeamID {
				domain.WriteHTTPError(w, &domain.GatewayError{
					StatusCode: http.StatusForbidden,
					Type:       domain.ErrorTypePermission,
					Code:       "cross_team_access_denied",
					Message:    "team_admin cannot bind a virtual key to a project outside their own team",
				})
				return false
			}
			if updated.TeamID == "" {
				updated.TeamID = proj.TeamID
			} else if proj.TeamID != updated.TeamID {
				domain.WriteHTTPError(w, &domain.GatewayError{
					StatusCode: http.StatusBadRequest,
					Type:       domain.ErrorTypeInvalidRequest,
					Code:       "project_team_mismatch",
					Message:    "Project does not belong to the virtual key's team",
				})
				return false
			}
		}
		updated.ProjectID = newProjectID
	}
	if req.UserID != nil {
		newUserID := strings.TrimSpace(*req.UserID)
		effectiveKeyType := auth.NormalizeKeyType(updated.KeyType)
		if req.KeyType != nil {
			effectiveKeyType = auth.NormalizeKeyType(*req.KeyType)
		}
		if effectiveKeyType == domain.KeyTypeServiceAccount && req.KeyType == nil && newUserID != "" {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusBadRequest,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "invalid_service_account_user",
				Message:    "service_account virtual keys cannot be attributed to a user_id",
			})
			return false
		}
		if !s.validateTeamAdminKeyTargetUser(ctx, w, op, existing.OrgID, newUserID) {
			return false
		}
		updated.UserID = newUserID
	}
	if req.Role != nil && *req.Role != "" {
		if *req.Role == domain.RolePlatformAdmin && op.Role != domain.OperatorRolePlatformAdmin {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusForbidden,
				Type:       domain.ErrorTypePermission,
				Code:       "platform_admin_required",
				Message:    "Only platform_admin can assign platform_admin role to virtual keys",
			})
			return false
		}
		if op.Role == domain.OperatorRoleTeamAdmin && isPrivilegedOrgOrPlatformRole(*req.Role) {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusForbidden,
				Type:       domain.ErrorTypePermission,
				Code:       "insufficient_permissions",
				Message:    "team_admin cannot assign organization-wide or platform roles to virtual keys",
			})
			return false
		}
		updated.Role = *req.Role
	}
	return true
}

func (s *GatewayServer) applyVirtualKeyAccessAndLimitsPatch(
	ctx context.Context,
	w http.ResponseWriter,
	op *domain.OperatorContext,
	existing *domain.VirtualKey,
	req *adminUpdateKeyRequest,
	updated *domain.VirtualKey,
) bool {
	if req.AllowedModels.Set {
		updated.AllowedModels = req.AllowedModels.Value
	}
	if req.AllowedDeployments.Set {
		updated.AllowedDeployments = req.AllowedDeployments.Value
	}
	if req.AllowedEndpoints.Set {
		if op.Role == domain.OperatorRoleTeamAdmin && hasDisallowedTeamAdminEndpoint(req.AllowedEndpoints.Value) {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusForbidden,
				Type:       domain.ErrorTypePermission,
				Code:       "insufficient_permissions",
				Message:    "team_admin cannot configure wildcard, /admin, or /scim allowed_endpoints",
			})
			return false
		}
		updated.AllowedEndpoints = req.AllowedEndpoints.Value
	}
	if req.AllowedMCPServers.Set {
		updated.AllowedMCPServers = req.AllowedMCPServers.Value
	}
	if req.AllowedMCPTools.Set {
		updated.AllowedMCPTools = req.AllowedMCPTools.Value
	}
	if req.AllowedMCPToolsets.Set {
		updated.AllowedMCPToolsets = req.AllowedMCPToolsets.Value
	}
	if req.AllowedA2AAgents.Set {
		updated.AllowedA2AAgents = req.AllowedA2AAgents.Value
	}
	if req.AllowedClientApps.Set {
		updated.AllowedClientApps = req.AllowedClientApps.Value
	}
	if req.KeyType != nil {
		if !auth.IsValidKeyType(*req.KeyType) {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusBadRequest,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "invalid_key_type",
				Message:    "Unsupported key_type preset",
			})
			return false
		}
		kt := auth.NormalizeKeyType(*req.KeyType)
		updated.KeyType = kt
		if !req.AllowedEndpoints.Set && kt != auth.NormalizeKeyType(existing.KeyType) {
			if kt == domain.KeyTypeDefault {
				updated.AllowedEndpoints = []string{"*"}
			} else {
				updated.AllowedEndpoints = nil
			}
		}
		auth.ApplyKeyTypePreset(updated)
	}
	if req.MaxBudgetMicros != nil {
		if !assignNonNegativeInt64(w, req.MaxBudgetMicros, "invalid_budget", "max_budget_micros cannot be negative", &updated.MaxBudgetMicros) {
			return false
		}
		if !s.enforceSelfServeBudgetPolicy(ctx, w, op, existing.OrgID, updated.TeamID, existing.MaxBudgetMicros, *req.MaxBudgetMicros) {
			return false
		}
	}
	if !applySoftBudgetPolicyPatch(w, req.SoftBudgetMicros, req.ThrottleOnBudgetExceeded, req.BudgetFallbacks, &updated.SoftBudgetMicros, &updated.ThrottleOnBudgetExceeded, &updated.BudgetFallbacks) {
		return false
	}
	if req.BudgetResetPeriod != nil && *req.BudgetResetPeriod != "" {
		updated.BudgetResetPeriod = *req.BudgetResetPeriod
	}
	if !assignNonNegativeInt(w, req.RPMLimit, "invalid_rpm_limit", "rpm_limit cannot be negative", &updated.RPMLimit) ||
		!assignNonNegativeInt(w, req.TPMLimit, "invalid_tpm_limit", "tpm_limit cannot be negative", &updated.TPMLimit) ||
		!assignNonNegativeInt(w, req.MaxConcurrentRequests, "invalid_concurrency_limit", "max_concurrent_requests cannot be negative", &updated.MaxConcurrentRequests) ||
		!assignNonNegativeInt64(w, req.BatchEnqueuedTokenLimit, "invalid_batch_enqueued_token_limit", "batch_enqueued_token_limit cannot be negative", &updated.BatchEnqueuedTokenLimit) ||
		!assignNonNegativeInt(w, req.MCPRPMLimit, "invalid_mcp_rpm_limit", "mcp_rpm_limit cannot be negative", &updated.MCPRPMLimit) ||
		!assignNonNegativeInt(w, req.MaxIterations, "invalid_max_iterations", "max_iterations cannot be negative", &updated.MaxIterations) ||
		!assignNonNegativeInt64(w, req.MaxBudgetPerSessionMicros, "invalid_session_budget", "max_budget_per_session_micros cannot be negative", &updated.MaxBudgetPerSessionMicros) ||
		!assignNonNegativeInt(w, req.MinPriorityRank, "invalid_min_priority_rank", "min_priority_rank cannot be negative", &updated.MinPriorityRank) {
		return false
	}
	if req.Tags.Set {
		updated.Tags = req.Tags.Value
	}
	if req.AllowedRoutingTags.Set {
		updated.AllowedRoutingTags = normalizeRoutingTags(req.AllowedRoutingTags.Value)
	}
	if !assignNonNegativeInt64(w, req.RotationIntervalSec, "invalid_rotation_interval", "rotation_interval_sec cannot be negative", &updated.RotationIntervalSec) {
		return false
	}
	if req.RotationIntervalSec != nil {
		if *req.RotationIntervalSec == 0 {
			updated.KeyRotationAt = nil
		} else if req.KeyRotationAt == nil && (updated.KeyRotationAt == nil || existing.RotationIntervalSec != *req.RotationIntervalSec) {
			nextRot := time.Now().UTC().Add(time.Duration(*req.RotationIntervalSec) * time.Second)
			updated.KeyRotationAt = &nextRot
		}
	}
	if req.KeyRotationAt != nil {
		rotAt := req.KeyRotationAt.UTC()
		updated.KeyRotationAt = &rotAt
	}
	if req.ExpiresAt != nil {
		updated.ExpiresAt = req.ExpiresAt
	}
	if req.CanImpersonate != nil {
		if *req.CanImpersonate && op.Role == domain.OperatorRoleTeamAdmin {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusForbidden,
				Type:       domain.ErrorTypePermission,
				Code:       "insufficient_permissions",
				Message:    "team_admin cannot enable can_impersonate on virtual keys",
			})
			return false
		}
		updated.CanImpersonate = *req.CanImpersonate
	}
	if req.IsActive != nil {
		updated.IsActive = *req.IsActive
		if !*req.IsActive {
			if updated.RevokedAt == nil {
				now := time.Now().UTC()
				updated.RevokedAt = &now
			}
			if op != nil && op.ActorID != "" {
				updated.RevokedBy = op.ActorID
			}
		} else {
			updated.RevokedAt = nil
			updated.RevokedBy = ""
		}
	}
	if req.Metadata != nil {
		updated.Metadata = req.Metadata
	}
	return true
}

func (s *GatewayServer) handleAdminUpdateKey(w http.ResponseWriter, r *http.Request) {
	keyID := strings.TrimSpace(chi.URLParam(r, "keyID"))
	if keyID == "" {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "missing_key_id",
			Message:    "keyID is required",
		})
		return
	}

	existing, err := s.repo.GetVirtualKeyByID(r.Context(), keyID)
	if err != nil || existing == nil {
		if _, ok := s.authorizeTeamAdmin(w, r, resolveScopedOrgID(r, r.URL.Query().Get("org_id")), resolveScopedTeamID(r, r.URL.Query().Get("team_id")), true); !ok {
			return
		}
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusNotFound,
			Type:       domain.ErrorTypeNotFound,
			Code:       "virtual_key_not_found",
			Message:    "Virtual key not found",
		})
		return
	}

	op, ok := s.authorizeTeamAdmin(w, r, existing.OrgID, existing.TeamID, true)
	if !ok {
		return
	}
	if !ensureOperatorCanMutateTargetRole(w, op, existing.Role, "virtual key") {
		return
	}

	var req adminUpdateKeyRequest
	if err := decodeAdminJSON(w, r, &req); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Message:    err.Error(),
		})
		return
	}
	if !verifyExplicitOrgMatch(w, r, existing.OrgID, req.OrgID) {
		return
	}

	updated := *existing
	if !s.applyVirtualKeyScopePatch(r.Context(), w, op, existing, &req, &updated) {
		return
	}
	if !s.applyVirtualKeyAccessAndLimitsPatch(r.Context(), w, op, existing, &req, &updated) {
		return
	}
	if !s.enforceGuaranteedThroughput(r.Context(), w, updated.OrgID, updated.TeamID, updated.ID, updated.RPMLimit, updated.TPMLimit) {
		return
	}
	if err := s.authSvc.UpdateVirtualKey(r.Context(), &updated); err != nil {
		var gwErr *domain.GatewayError
		if errors.As(err, &gwErr) {
			domain.WriteHTTPError(w, gwErr)
			return
		}
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Message:    err.Error(),
		})
		return
	}

	saved, err := s.repo.GetVirtualKeyByID(r.Context(), keyID)
	if err != nil || saved == nil {
		saved = &updated
	}
	s.auditWithDiff(r.Context(), saved.OrgID, "virtual_key.updated", "virtual_key", saved.ID, map[string]any{
		"name":                  saved.Name,
		"team_id":               saved.TeamID,
		"project_id":            saved.ProjectID,
		"user_id":               saved.UserID,
		"key_type":              saved.KeyType,
		"rotation_interval_sec": saved.RotationIntervalSec,
		"max_budget_micros":     saved.MaxBudgetMicros,
		"rpm_limit":             saved.RPMLimit,
		"tpm_limit":             saved.TPMLimit,
		"can_impersonate":       saved.CanImpersonate,
		"min_priority_rank":     saved.MinPriorityRank,
		"is_active":             saved.IsActive,
	}, existing, saved)
	writeJSON(w, http.StatusOK, saved)
}

func (s *GatewayServer) handleAdminRotateKey(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxAdminRequestBodyBytes)
	keyID := strings.TrimSpace(chi.URLParam(r, "keyID"))
	if keyID == "" {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "missing_key_id",
			Message:    "keyID is required",
		})
		return
	}

	existing, err := s.repo.GetVirtualKeyByID(r.Context(), keyID)
	if err != nil || existing == nil {
		if _, ok := s.authorizeTeamAdmin(w, r, resolveScopedOrgID(r, r.URL.Query().Get("org_id")), resolveScopedTeamID(r, r.URL.Query().Get("team_id")), true); !ok {
			return
		}
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusNotFound,
			Type:       domain.ErrorTypeNotFound,
			Code:       "virtual_key_not_found",
			Message:    "Virtual key not found",
		})
		return
	}

	op, ok := s.authorizeTeamAdmin(w, r, existing.OrgID, existing.TeamID, true)
	if !ok {
		return
	}
	if !ensureOperatorCanMutateTargetRole(w, op, existing.Role, "virtual key") {
		return
	}

	var req struct {
		OrgID              *string `json:"org_id,omitempty"`
		GracePeriodSeconds *int64  `json:"grace_period_seconds,omitempty"`
	}
	if r.Body != nil {
		r.Body = http.MaxBytesReader(w, r.Body, maxAdminRequestBodyBytes)
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
			var maxBytesErr *http.MaxBytesError
			if errors.As(err, &maxBytesErr) {
				domain.WriteHTTPError(w, &domain.GatewayError{
					StatusCode: http.StatusRequestEntityTooLarge,
					Type:       domain.ErrorTypeInvalidRequest,
					Code:       "request_body_too_large",
					Message:    "Request body exceeds the 2 MiB limit",
				})
				return
			}
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusBadRequest,
				Type:       domain.ErrorTypeInvalidRequest,
				Message:    err.Error(),
			})
			return
		}
	}
	if !verifyExplicitOrgMatch(w, r, existing.OrgID, req.OrgID) {
		return
	}

	var gracePeriod time.Duration
	if req.GracePeriodSeconds != nil {
		if *req.GracePeriodSeconds < 0 {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusBadRequest,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "invalid_grace_period",
				Message:    "grace_period_seconds cannot be negative",
			})
			return
		}
		gracePeriod = time.Duration(*req.GracePeriodSeconds) * time.Second
	}

	rotated, err := s.authSvc.RotateVirtualKeyWithGrace(r.Context(), keyID, gracePeriod)
	if err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	s.auditWithDiff(r.Context(), rotated.OrgID, "virtual_key.rotated", "virtual_key", rotated.ID, map[string]any{
		"key_prefix":           rotated.KeyPrefix,
		"name":                 rotated.Name,
		"grace_period_seconds": int64(gracePeriod / time.Second),
	}, existing, rotated)
	writeJSON(w, http.StatusOK, rotated)
}
