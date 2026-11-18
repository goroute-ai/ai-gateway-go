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

	var req struct {
		OrgID                    *string                   `json:"org_id,omitempty"`
		Name                     *string                   `json:"name,omitempty"`
		MaxBudgetMicros          *int64                    `json:"max_budget_micros,omitempty"`
		SoftBudgetMicros         *int64                    `json:"soft_budget_micros,omitempty"`
		ThrottleOnBudgetExceeded *bool                     `json:"throttle_on_budget_exceeded,omitempty"`
		BudgetFallbacks          map[string][]string       `json:"budget_fallbacks,omitempty"`
		BudgetResetPeriod        *domain.BudgetResetPeriod `json:"budget_reset_period,omitempty"`
		RPMLimit                 *int                      `json:"rpm_limit,omitempty"`
		TPMLimit                 *int                      `json:"tpm_limit,omitempty"`
		MaxConcurrentRequests    *int                      `json:"max_concurrent_requests,omitempty"`
		BatchEnqueuedTokenLimit  *int64                    `json:"batch_enqueued_token_limit,omitempty"`
		AllowedModels            optionalStringSlice       `json:"allowed_models"`
		AllowedMCPServers        optionalStringSlice       `json:"allowed_mcp_servers"`
		AllowedA2AAgents         optionalStringSlice       `json:"allowed_a2a_agents"`
		AllowedClientApps        optionalStringSlice       `json:"allowed_client_apps"`
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
	if req.AllowedModels.Set {
		updated.AllowedModels = req.AllowedModels.Value
	}
	if req.AllowedMCPServers.Set {
		updated.AllowedMCPServers = req.AllowedMCPServers.Value
	}
	if req.AllowedA2AAgents.Set {
		updated.AllowedA2AAgents = req.AllowedA2AAgents.Value
	}
	if req.AllowedClientApps.Set {
		updated.AllowedClientApps = req.AllowedClientApps.Value
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
	s.audit(r.Context(), updated.OrgID, "team.updated", "team", updated.ID, map[string]any{
		"name":              updated.Name,
		"max_budget_micros": updated.MaxBudgetMicros,
		"is_active":         updated.IsActive,
	})
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

	if err := s.repo.DeleteTeam(r.Context(), teamID); err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	if s.authSvc != nil {
		s.authSvc.InvalidateTeam(r.Context(), teamID)
	}
	s.audit(r.Context(), existing.OrgID, "team.deleted", "team", teamID, map[string]any{
		"name": existing.Name,
	})
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

	var req struct {
		OrgID                    *string                   `json:"org_id,omitempty"`
		TeamID                   *string                   `json:"team_id,omitempty"`
		Email                    *string                   `json:"email,omitempty"`
		Name                     *string                   `json:"name,omitempty"`
		Role                     *domain.Role              `json:"role,omitempty"`
		OIDCSubject              *string                   `json:"oidc_subject,omitempty"`
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
	if req.OIDCSubject != nil {
		updated.OIDCSubject = strings.TrimSpace(*req.OIDCSubject)
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
		s.authSvc.InvalidateOrg(r.Context(), updated.OrgID)
	}
	s.audit(r.Context(), updated.OrgID, "user.updated", "user", updated.ID, map[string]any{
		"email":     updated.Email,
		"role":      updated.Role,
		"team_id":   updated.TeamID,
		"is_active": updated.IsActive,
	})
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
	s.audit(r.Context(), existing.OrgID, "user.deleted", "user", userID, map[string]any{
		"email": existing.Email,
	})
	writeJSON(w, http.StatusOK, map[string]any{"status": "deleted", "id": userID})
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
		if _, ok := s.authorizeAdmin(w, r, resolveScopedOrgID(r, r.URL.Query().Get("org_id")), true); !ok {
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

	op, ok := s.authorizeAdmin(w, r, existing.OrgID, true)
	if !ok {
		return
	}

	var req struct {
		OrgID                    *string                   `json:"org_id,omitempty"`
		Name                     *string                   `json:"name,omitempty"`
		TeamID                   *string                   `json:"team_id,omitempty"`
		UserID                   *string                   `json:"user_id,omitempty"`
		Role                     *domain.Role              `json:"role,omitempty"`
		AllowedModels            optionalStringSlice       `json:"allowed_models"`
		AllowedEndpoints         optionalStringSlice       `json:"allowed_endpoints"`
		AllowedMCPServers        optionalStringSlice       `json:"allowed_mcp_servers"`
		AllowedA2AAgents         optionalStringSlice       `json:"allowed_a2a_agents"`
		AllowedClientApps        optionalStringSlice       `json:"allowed_client_apps"`
		MaxBudgetMicros          *int64                    `json:"max_budget_micros,omitempty"`
		SoftBudgetMicros         *int64                    `json:"soft_budget_micros,omitempty"`
		ThrottleOnBudgetExceeded *bool                     `json:"throttle_on_budget_exceeded,omitempty"`
		BudgetFallbacks          map[string][]string       `json:"budget_fallbacks,omitempty"`
		BudgetResetPeriod        *domain.BudgetResetPeriod `json:"budget_reset_period,omitempty"`
		RPMLimit                 *int                      `json:"rpm_limit,omitempty"`
		TPMLimit                 *int                      `json:"tpm_limit,omitempty"`
		MaxConcurrentRequests    *int                      `json:"max_concurrent_requests,omitempty"`
		BatchEnqueuedTokenLimit  *int64                    `json:"batch_enqueued_token_limit,omitempty"`
		ExpiresAt                *time.Time                `json:"expires_at,omitempty"`
		IsActive                 *bool                     `json:"is_active,omitempty"`
		Metadata                 map[string]string         `json:"metadata,omitempty"`
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
				Code:       "invalid_key_name",
				Message:    "Virtual key name cannot be empty",
			})
			return
		}
		updated.Name = name
	}
	if req.TeamID != nil {
		updated.TeamID = strings.TrimSpace(*req.TeamID)
	}
	if req.UserID != nil {
		updated.UserID = strings.TrimSpace(*req.UserID)
	}
	if req.Role != nil && *req.Role != "" {
		if *req.Role == domain.RolePlatformAdmin && op.Role != domain.OperatorRolePlatformAdmin {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusForbidden,
				Type:       domain.ErrorTypePermission,
				Code:       "platform_admin_required",
				Message:    "Only platform_admin can assign platform_admin role to virtual keys",
			})
			return
		}
		updated.Role = *req.Role
	}
	if req.AllowedModels.Set {
		updated.AllowedModels = req.AllowedModels.Value
	}
	if req.AllowedEndpoints.Set {
		updated.AllowedEndpoints = req.AllowedEndpoints.Value
	}
	if req.AllowedMCPServers.Set {
		updated.AllowedMCPServers = req.AllowedMCPServers.Value
	}
	if req.AllowedA2AAgents.Set {
		updated.AllowedA2AAgents = req.AllowedA2AAgents.Value
	}
	if req.AllowedClientApps.Set {
		updated.AllowedClientApps = req.AllowedClientApps.Value
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
	if req.ExpiresAt != nil {
		updated.ExpiresAt = req.ExpiresAt
	}
	if req.IsActive != nil {
		updated.IsActive = *req.IsActive
	}
	if req.Metadata != nil {
		updated.Metadata = req.Metadata
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
	s.audit(r.Context(), saved.OrgID, "virtual_key.updated", "virtual_key", saved.ID, map[string]any{
		"name":              saved.Name,
		"team_id":           saved.TeamID,
		"user_id":           saved.UserID,
		"max_budget_micros": saved.MaxBudgetMicros,
		"rpm_limit":         saved.RPMLimit,
		"tpm_limit":         saved.TPMLimit,
		"is_active":         saved.IsActive,
	})
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
		if _, ok := s.authorizeAdmin(w, r, resolveScopedOrgID(r, r.URL.Query().Get("org_id")), true); !ok {
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

	if _, ok := s.authorizeAdmin(w, r, existing.OrgID, true); !ok {
		return
	}

	var req struct {
		OrgID *string `json:"org_id,omitempty"`
	}
	if r.Body != nil {
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
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

	rotated, err := s.authSvc.RotateVirtualKey(r.Context(), keyID)
	if err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	s.audit(r.Context(), rotated.OrgID, "virtual_key.rotated", "virtual_key", rotated.ID, map[string]any{
		"key_prefix": rotated.KeyPrefix,
		"name":       rotated.Name,
	})
	writeJSON(w, http.StatusOK, rotated)
}
