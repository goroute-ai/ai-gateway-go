package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

func (s *GatewayServer) projectMembershipRepo() (storage.ProjectAndMembershipRepository, bool) {
	if s == nil || s.repo == nil {
		return nil, false
	}
	r, ok := s.repo.(storage.ProjectAndMembershipRepository)
	return r, ok && r != nil
}

func isValidTenantRole(role domain.Role) bool {
	switch role {
	case domain.RolePlatformAdmin,
		domain.RoleOrgAdmin,
		domain.RoleOrgViewer,
		domain.RoleTeamAdmin,
		domain.RoleDeveloper,
		domain.RoleServiceAccount,
		domain.RoleViewer:
		return true
	default:
		return false
	}
}

func (s *GatewayServer) userBelongsToTeam(ctx context.Context, orgID, teamID, userID string) bool {
	user, err := s.lookupUserByID(ctx, userID)
	if err != nil || user == nil || user.OrgID != orgID {
		return false
	}
	if user.TeamID == teamID {
		return true
	}
	if pmRepo, ok := s.projectMembershipRepo(); ok {
		if m, mErr := pmRepo.GetTeamMembership(ctx, teamID, userID); mErr == nil && m != nil && m.OrgID == orgID && m.TeamID == teamID {
			return true
		}
	}
	return false
}

func (s *GatewayServer) handleAdminCreateProject(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID                       string   `json:"id,omitempty"`
		OrgID                    string   `json:"org_id,omitempty"`
		TeamID                   string   `json:"team_id,omitempty"`
		Name                     string   `json:"name"`
		Description              string   `json:"description,omitempty"`
		MaxBudgetMicros          int64    `json:"max_budget_micros,omitempty"`
		RPMLimit                 int      `json:"rpm_limit,omitempty"`
		TPMLimit                 int      `json:"tpm_limit,omitempty"`
		AllowedModels            []string `json:"allowed_models,omitempty"`
		EnforceProjectModelQuota bool     `json:"enforce_project_model_quota,omitempty"`
		IsActive                 *bool    `json:"is_active,omitempty"`
	}
	if err := decodeAdminJSON(w, r, &req); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Message:    err.Error(),
		})
		return
	}

	orgID := resolveScopedOrgID(r, req.OrgID)
	teamID := resolveScopedTeamID(r, req.TeamID)
	if _, ok := s.authorizeTeamAdmin(w, r, orgID, teamID, true); !ok {
		return
	}
	if orgID == "" {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "missing_org_id",
			Message:    "org_id is required",
		})
		return
	}
	if teamID == "" {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "missing_team_id",
			Message:    "team_id is required",
		})
		return
	}

	pmRepo, ok := s.projectMembershipRepo()
	if !ok {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusNotImplemented,
			Type:       domain.ErrorTypeServer,
			Code:       "projects_unsupported",
			Message:    "Configured storage repository does not support projects",
		})
		return
	}

	team, err := s.repo.GetTeam(r.Context(), teamID)
	if err != nil || team == nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusNotFound,
			Type:       domain.ErrorTypeNotFound,
			Code:       "team_not_found",
			Message:    "Team not found",
		})
		return
	}
	if team.OrgID != orgID {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusForbidden,
			Type:       domain.ErrorTypePermission,
			Code:       "cross_org_access_denied",
			Message:    "Team does not belong to the requested organization",
		})
		return
	}

	name := strings.TrimSpace(req.Name)
	if name == "" {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_project_name",
			Message:    "Project name is required",
		})
		return
	}
	if req.MaxBudgetMicros < 0 {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_budget",
			Message:    "max_budget_micros cannot be negative",
		})
		return
	}
	if req.RPMLimit < 0 {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_rpm_limit",
			Message:    "rpm_limit cannot be negative",
		})
		return
	}
	if req.TPMLimit < 0 {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_tpm_limit",
			Message:    "tpm_limit cannot be negative",
		})
		return
	}

	isActive := true
	if req.IsActive != nil {
		isActive = *req.IsActive
	}
	proj := &domain.Project{
		ID:                       strings.TrimSpace(req.ID),
		OrgID:                    orgID,
		TeamID:                   teamID,
		Name:                     name,
		Description:              req.Description,
		MaxBudgetMicros:          req.MaxBudgetMicros,
		RPMLimit:                 req.RPMLimit,
		TPMLimit:                 req.TPMLimit,
		AllowedModels:            req.AllowedModels,
		EnforceProjectModelQuota: req.EnforceProjectModelQuota,
		IsActive:                 isActive,
	}
	if err := pmRepo.CreateProject(r.Context(), proj); err != nil {
		if errors.Is(err, storage.ErrConflict) {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusConflict,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "project_conflict",
				Message:    "A project with this id or name already exists in the team",
			})
			return
		}
		domain.WriteHTTPError(w, err)
		return
	}

	s.auditWithDiff(r.Context(), proj.OrgID, "project.created", "project", proj.ID, map[string]any{
		"team_id":                     proj.TeamID,
		"name":                        proj.Name,
		"enforce_project_model_quota": proj.EnforceProjectModelQuota,
	}, nil, proj)
	writeJSON(w, http.StatusCreated, proj)
}

func (s *GatewayServer) handleAdminListProjects(w http.ResponseWriter, r *http.Request) {
	orgID := resolveScopedOrgID(r, r.URL.Query().Get("org_id"))
	teamID := resolveScopedTeamID(r, r.URL.Query().Get("team_id"))
	if _, ok := s.authorizeTeamAdmin(w, r, orgID, teamID, false); !ok {
		return
	}

	pmRepo, ok := s.projectMembershipRepo()
	if !ok {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusNotImplemented,
			Type:       domain.ErrorTypeServer,
			Code:       "projects_unsupported",
			Message:    "Configured storage repository does not support projects",
		})
		return
	}

	projects, err := pmRepo.ListProjects(r.Context(), orgID, teamID)
	if err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	if projects == nil {
		projects = []*domain.Project{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": projects})
}

func (s *GatewayServer) handleAdminUpdateProject(w http.ResponseWriter, r *http.Request) {
	projectID := strings.TrimSpace(chi.URLParam(r, "projectID"))
	if projectID == "" {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "missing_project_id",
			Message:    "projectID is required",
		})
		return
	}

	pmRepo, ok := s.projectMembershipRepo()
	if !ok {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusNotImplemented,
			Type:       domain.ErrorTypeServer,
			Code:       "projects_unsupported",
			Message:    "Configured storage repository does not support projects",
		})
		return
	}

	existing, err := pmRepo.GetProject(r.Context(), projectID)
	if err != nil || existing == nil {
		if _, ok := s.authorizeTeamAdmin(w, r, resolveScopedOrgID(r, r.URL.Query().Get("org_id")), resolveScopedTeamID(r, r.URL.Query().Get("team_id")), true); !ok {
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

	op, ok := s.authorizeTeamAdmin(w, r, existing.OrgID, existing.TeamID, true)
	if !ok {
		return
	}

	var req struct {
		OrgID                    *string             `json:"org_id,omitempty"`
		TeamID                   *string             `json:"team_id,omitempty"`
		Name                     *string             `json:"name,omitempty"`
		Description              *string             `json:"description,omitempty"`
		MaxBudgetMicros          *int64              `json:"max_budget_micros,omitempty"`
		RPMLimit                 *int                `json:"rpm_limit,omitempty"`
		TPMLimit                 *int                `json:"tpm_limit,omitempty"`
		AllowedModels            optionalStringSlice `json:"allowed_models"`
		EnforceProjectModelQuota *bool               `json:"enforce_project_model_quota,omitempty"`
		IsActive                 *bool               `json:"is_active,omitempty"`
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
	if req.TeamID != nil {
		newTeamID := strings.TrimSpace(*req.TeamID)
		if newTeamID == "" {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusBadRequest,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "missing_team_id",
				Message:    "team_id cannot be empty",
			})
			return
		}
		if op.Role == domain.OperatorRoleTeamAdmin && newTeamID != op.TeamID {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusForbidden,
				Type:       domain.ErrorTypePermission,
				Code:       "cross_team_access_denied",
				Message:    "team_admin cannot reassign a project outside their own team",
			})
			return
		}
		if newTeamID != existing.TeamID {
			team, tErr := s.repo.GetTeam(r.Context(), newTeamID)
			if tErr != nil || team == nil {
				domain.WriteHTTPError(w, &domain.GatewayError{
					StatusCode: http.StatusNotFound,
					Type:       domain.ErrorTypeNotFound,
					Code:       "team_not_found",
					Message:    "Specified team was not found",
				})
				return
			}
			if team.OrgID != existing.OrgID {
				domain.WriteHTTPError(w, &domain.GatewayError{
					StatusCode: http.StatusForbidden,
					Type:       domain.ErrorTypePermission,
					Code:       "cross_org_access_denied",
					Message:    "Specified team does not belong to project's organization",
				})
				return
			}
		}
		updated.TeamID = newTeamID
	}
	if req.Name != nil {
		name := strings.TrimSpace(*req.Name)
		if name == "" {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusBadRequest,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "invalid_project_name",
				Message:    "Project name cannot be empty",
			})
			return
		}
		updated.Name = name
	}
	if req.Description != nil {
		updated.Description = *req.Description
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
	if req.AllowedModels.Set {
		updated.AllowedModels = req.AllowedModels.Value
	}
	if req.EnforceProjectModelQuota != nil {
		updated.EnforceProjectModelQuota = *req.EnforceProjectModelQuota
	}
	if req.IsActive != nil {
		updated.IsActive = *req.IsActive
	}

	if err := pmRepo.UpdateProject(r.Context(), &updated); err != nil {
		if errors.Is(err, storage.ErrConflict) {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusConflict,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "project_conflict",
				Message:    "A project with this name already exists in the team",
			})
			return
		}
		domain.WriteHTTPError(w, err)
		return
	}
	if s.authSvc != nil {
		s.authSvc.InvalidateTeam(r.Context(), updated.TeamID)
		if existing.TeamID != updated.TeamID {
			s.authSvc.InvalidateTeam(r.Context(), existing.TeamID)
		}
	}
	s.auditWithDiff(r.Context(), updated.OrgID, "project.updated", "project", updated.ID, map[string]any{
		"team_id":                     updated.TeamID,
		"name":                        updated.Name,
		"enforce_project_model_quota": updated.EnforceProjectModelQuota,
		"is_active":                   updated.IsActive,
	}, existing, updated)
	writeJSON(w, http.StatusOK, updated)
}

func (s *GatewayServer) handleAdminDeleteProject(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxAdminRequestBodyBytes)
	projectID := strings.TrimSpace(chi.URLParam(r, "projectID"))
	if projectID == "" {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "missing_project_id",
			Message:    "projectID is required",
		})
		return
	}

	pmRepo, ok := s.projectMembershipRepo()
	if !ok {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusNotImplemented,
			Type:       domain.ErrorTypeServer,
			Code:       "projects_unsupported",
			Message:    "Configured storage repository does not support projects",
		})
		return
	}

	existing, err := pmRepo.GetProject(r.Context(), projectID)
	if err != nil || existing == nil {
		if _, ok := s.authorizeTeamAdmin(w, r, resolveScopedOrgID(r, r.URL.Query().Get("org_id")), resolveScopedTeamID(r, r.URL.Query().Get("team_id")), true); !ok {
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

	if _, ok := s.authorizeTeamAdmin(w, r, existing.OrgID, existing.TeamID, true); !ok {
		return
	}
	if !verifyExplicitOrgMatch(w, r, existing.OrgID, nil) {
		return
	}

	if err := pmRepo.DeleteProject(r.Context(), projectID); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusNotFound,
				Type:       domain.ErrorTypeNotFound,
				Code:       "project_not_found",
				Message:    "Project not found",
			})
			return
		}
		domain.WriteHTTPError(w, err)
		return
	}
	if s.authSvc != nil {
		s.authSvc.InvalidateTeam(r.Context(), existing.TeamID)
	}
	s.auditWithDiff(r.Context(), existing.OrgID, "project.deleted", "project", projectID, map[string]any{
		"team_id": existing.TeamID,
		"name":    existing.Name,
	}, existing, nil)
	writeJSON(w, http.StatusOK, map[string]any{"status": "deleted", "id": projectID})
}

func (s *GatewayServer) handleAdminUpsertTeamMember(w http.ResponseWriter, r *http.Request) {
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

	pmRepo, ok := s.projectMembershipRepo()
	if !ok {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusNotImplemented,
			Type:       domain.ErrorTypeServer,
			Code:       "memberships_unsupported",
			Message:    "Configured storage repository does not support team memberships",
		})
		return
	}

	team, err := s.repo.GetTeam(r.Context(), teamID)
	if err != nil || team == nil {
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

	op, ok := s.authorizeTeamAdmin(w, r, team.OrgID, team.ID, true)
	if !ok {
		return
	}

	var req struct {
		ID              string      `json:"id,omitempty"`
		OrgID           *string     `json:"org_id,omitempty"`
		UserID          string      `json:"user_id"`
		Role            domain.Role `json:"role,omitempty"`
		MaxBudgetMicros int64       `json:"max_budget_micros,omitempty"`
		RPMLimit        int         `json:"rpm_limit,omitempty"`
		TPMLimit        int         `json:"tpm_limit,omitempty"`
		AllowedModels   []string    `json:"allowed_models,omitempty"`
	}
	if err := decodeAdminJSON(w, r, &req); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Message:    err.Error(),
		})
		return
	}
	if !verifyExplicitOrgMatch(w, r, team.OrgID, req.OrgID) {
		return
	}

	userID := strings.TrimSpace(req.UserID)
	if userID == "" {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "missing_user_id",
			Message:    "user_id is required",
		})
		return
	}
	role := req.Role
	if role == "" {
		role = domain.RoleDeveloper
	}
	if !isValidTenantRole(role) {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_role",
			Message:    fmt.Sprintf("Unsupported role %q", role),
		})
		return
	}
	if role == domain.RolePlatformAdmin && op.Role != domain.OperatorRolePlatformAdmin {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusForbidden,
			Type:       domain.ErrorTypePermission,
			Code:       "platform_admin_required",
			Message:    "Only platform_admin can assign platform_admin role",
		})
		return
	}
	if op.Role == domain.OperatorRoleTeamAdmin && isPrivilegedOrgOrPlatformRole(role) {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusForbidden,
			Type:       domain.ErrorTypePermission,
			Code:       "insufficient_permissions",
			Message:    fmt.Sprintf("team_admin cannot assign organization-wide or platform role %q", role),
		})
		return
	}
	if req.MaxBudgetMicros < 0 {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_budget",
			Message:    "max_budget_micros cannot be negative",
		})
		return
	}
	if req.RPMLimit < 0 {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_rpm_limit",
			Message:    "rpm_limit cannot be negative",
		})
		return
	}
	if req.TPMLimit < 0 {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_tpm_limit",
			Message:    "tpm_limit cannot be negative",
		})
		return
	}

	user, uErr := s.lookupUserByID(r.Context(), userID)
	if uErr != nil || user == nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusNotFound,
			Type:       domain.ErrorTypeNotFound,
			Code:       "user_not_found",
			Message:    "User not found",
		})
		return
	}
	if user.OrgID != team.OrgID {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusForbidden,
			Type:       domain.ErrorTypePermission,
			Code:       "cross_org_access_denied",
			Message:    "User does not belong to the team's organization",
		})
		return
	}

	m := &domain.TeamMembership{
		ID:              strings.TrimSpace(req.ID),
		OrgID:           team.OrgID,
		TeamID:          team.ID,
		UserID:          userID,
		Role:            role,
		MaxBudgetMicros: req.MaxBudgetMicros,
		RPMLimit:        req.RPMLimit,
		TPMLimit:        req.TPMLimit,
		AllowedModels:   req.AllowedModels,
	}
	applyTeamMemberDefaults(team, m)
	if err := pmRepo.UpsertTeamMembership(r.Context(), m); err != nil {
		if errors.Is(err, storage.ErrConflict) {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusConflict,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "team_membership_conflict",
				Message:    err.Error(),
			})
			return
		}
		domain.WriteHTTPError(w, err)
		return
	}
	if s.authSvc != nil {
		s.authSvc.InvalidateTeam(r.Context(), team.ID)
	}
	s.auditWithDiff(r.Context(), team.OrgID, "team_membership.upserted", "team_membership", m.ID, map[string]any{
		"team_id": team.ID,
		"user_id": userID,
		"role":    m.Role,
	}, nil, m)
	writeJSON(w, http.StatusOK, m)
}

func (s *GatewayServer) handleAdminListTeamMembers(w http.ResponseWriter, r *http.Request) {
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

	pmRepo, ok := s.projectMembershipRepo()
	if !ok {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusNotImplemented,
			Type:       domain.ErrorTypeServer,
			Code:       "memberships_unsupported",
			Message:    "Configured storage repository does not support team memberships",
		})
		return
	}

	team, err := s.repo.GetTeam(r.Context(), teamID)
	if err != nil || team == nil {
		if _, ok := s.authorizeTeamAdmin(w, r, resolveScopedOrgID(r, r.URL.Query().Get("org_id")), teamID, false); !ok {
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

	if _, ok := s.authorizeTeamAdmin(w, r, team.OrgID, team.ID, false); !ok {
		return
	}
	if !verifyExplicitOrgMatch(w, r, team.OrgID, nil) {
		return
	}

	members, err := pmRepo.ListTeamMemberships(r.Context(), team.OrgID, team.ID, strings.TrimSpace(r.URL.Query().Get("user_id")))
	if err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	if members == nil {
		members = []*domain.TeamMembership{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": members})
}

func (s *GatewayServer) handleAdminDeleteTeamMember(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxAdminRequestBodyBytes)
	teamID := strings.TrimSpace(chi.URLParam(r, "teamID"))
	userID := strings.TrimSpace(chi.URLParam(r, "userID"))
	if teamID == "" || userID == "" {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "missing_team_or_user_id",
			Message:    "teamID and userID are required",
		})
		return
	}

	pmRepo, ok := s.projectMembershipRepo()
	if !ok {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusNotImplemented,
			Type:       domain.ErrorTypeServer,
			Code:       "memberships_unsupported",
			Message:    "Configured storage repository does not support team memberships",
		})
		return
	}

	team, err := s.repo.GetTeam(r.Context(), teamID)
	if err != nil || team == nil {
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

	if _, ok := s.authorizeTeamAdmin(w, r, team.OrgID, team.ID, true); !ok {
		return
	}
	if !verifyExplicitOrgMatch(w, r, team.OrgID, nil) {
		return
	}

	existingMember, _ := pmRepo.GetTeamMembership(r.Context(), team.ID, userID)
	if err := pmRepo.DeleteTeamMembership(r.Context(), team.ID, userID); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusNotFound,
				Type:       domain.ErrorTypeNotFound,
				Code:       "team_membership_not_found",
				Message:    "Team membership not found",
			})
			return
		}
		domain.WriteHTTPError(w, err)
		return
	}
	if s.authSvc != nil {
		s.authSvc.InvalidateTeam(r.Context(), team.ID)
	}
	s.auditWithDiff(r.Context(), team.OrgID, "team_membership.deleted", "team_membership", userID, map[string]any{
		"team_id": team.ID,
		"user_id": userID,
	}, existingMember, nil)
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "deleted",
		"id":      userID,
		"team_id": team.ID,
		"user_id": userID,
	})
}
