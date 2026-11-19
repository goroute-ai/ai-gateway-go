package server

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

func (s *GatewayServer) endUserRepo() (storage.EndUserRepository, bool) {
	if s == nil || s.repo == nil {
		return nil, false
	}
	r, ok := s.repo.(storage.EndUserRepository)
	return r, ok && r != nil
}

func (s *GatewayServer) tagRepo() (storage.TagRepository, bool) {
	if s == nil || s.repo == nil {
		return nil, false
	}
	r, ok := s.repo.(storage.TagRepository)
	return r, ok && r != nil
}

func (s *GatewayServer) modelAccessGroupRepo() (storage.ModelAccessGroupRepository, bool) {
	if s == nil || s.repo == nil {
		return nil, false
	}
	r, ok := s.repo.(storage.ModelAccessGroupRepository)
	return r, ok && r != nil
}

// --- End Users (/admin/v1/end-users) ---

func (s *GatewayServer) handleAdminUpsertEndUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID                string                   `json:"id,omitempty"`
		OrgID             string                   `json:"org_id"`
		EndUserID         string                   `json:"end_user_id"`
		Alias             string                   `json:"alias,omitempty"`
		MaxBudgetMicros   int64                    `json:"max_budget_micros,omitempty"`
		BudgetResetPeriod domain.BudgetResetPeriod `json:"budget_reset_period,omitempty"`
		BudgetResetAt     *time.Time               `json:"budget_reset_at,omitempty"`
		RPMLimit          int                      `json:"rpm_limit,omitempty"`
		TPMLimit          int                      `json:"tpm_limit,omitempty"`
		ITPMLimit         int                      `json:"itpm_limit,omitempty"`
		OTPMLimit         int                      `json:"otpm_limit,omitempty"`
		TPDLimit          int64                    `json:"tpd_limit,omitempty"`
		MaxConcurrent     int                      `json:"max_concurrent,omitempty"`
		AllowedModels     []string                 `json:"allowed_models,omitempty"`
		IsActive          *bool                    `json:"is_active,omitempty"`
		IsBlocked         *bool                    `json:"is_blocked,omitempty"`
		Metadata          map[string]string        `json:"metadata,omitempty"`
	}
	if err := decodeAdminJSON(w, r, &req); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_json_body",
			Message:    err.Error(),
		})
		return
	}

	req.OrgID = resolveScopedOrgID(r, req.OrgID)
	if _, ok := s.authorizeAdmin(w, r, req.OrgID, true); !ok {
		return
	}

	euRepo, ok := s.endUserRepo()
	if !ok {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusNotImplemented,
			Type:       domain.ErrorTypeServer,
			Code:       "end_users_unsupported",
			Message:    "Configured storage repository does not support end users",
		})
		return
	}

	isActive := true
	if req.IsActive != nil {
		isActive = *req.IsActive
	}
	if req.IsBlocked != nil && *req.IsBlocked {
		isActive = false
	}
	eu := &domain.EndUser{
		ID:                strings.TrimSpace(req.ID),
		OrgID:             req.OrgID,
		EndUserID:         strings.TrimSpace(req.EndUserID),
		Alias:             strings.TrimSpace(req.Alias),
		MaxBudgetMicros:   req.MaxBudgetMicros,
		BudgetResetPeriod: req.BudgetResetPeriod,
		BudgetResetAt:     req.BudgetResetAt,
		RPMLimit:          req.RPMLimit,
		TPMLimit:          req.TPMLimit,
		ITPMLimit:         req.ITPMLimit,
		OTPMLimit:         req.OTPMLimit,
		TPDLimit:          req.TPDLimit,
		MaxConcurrent:     req.MaxConcurrent,
		AllowedModels:     req.AllowedModels,
		IsActive:          isActive,
		Metadata:          req.Metadata,
	}
	if err := euRepo.UpsertEndUser(r.Context(), eu); err != nil {
		if errors.Is(err, storage.ErrConflict) {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusConflict,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "end_user_conflict",
				Message:    err.Error(),
			})
			return
		}
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_end_user",
			Message:    err.Error(),
		})
		return
	}

	if s.rbac != nil {
		s.rbac.InvalidateEndUser(r.Context(), eu.OrgID, eu.EndUserID)
	}
	s.auditWithDiff(r.Context(), eu.OrgID, "end_user.upserted", "end_user", eu.ID, map[string]any{
		"end_user_id": eu.EndUserID,
		"is_active":   eu.IsActive,
	}, nil, eu)
	status := http.StatusOK
	if r.Method == http.MethodPost {
		status = http.StatusCreated
	}
	writeJSON(w, status, eu)
}

func (s *GatewayServer) handleAdminListEndUsers(w http.ResponseWriter, r *http.Request) {
	orgID := resolveScopedOrgID(r, r.URL.Query().Get("org_id"))
	if _, ok := s.authorizeAdmin(w, r, orgID, false); !ok {
		return
	}
	euRepo, ok := s.endUserRepo()
	if !ok {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusNotImplemented,
			Type:       domain.ErrorTypeServer,
			Code:       "end_users_unsupported",
			Message:    "Configured storage repository does not support end users",
		})
		return
	}

	activeOnly := false
	if raw := strings.TrimSpace(r.URL.Query().Get("active_only")); raw != "" {
		activeOnly = strings.EqualFold(raw, "true") || raw == "1"
	}
	list, err := euRepo.ListEndUsers(r.Context(), storage.EndUserFilter{
		OrgID:      orgID,
		EndUserID:  strings.TrimSpace(r.URL.Query().Get("end_user_id")),
		ActiveOnly: activeOnly,
	})
	if err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	if list == nil {
		list = []*domain.EndUser{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": list})
}

func (s *GatewayServer) resolveEndUserByIDOrExternal(r *http.Request, euRepo storage.EndUserRepository, idOrExt string) (*domain.EndUser, error) {
	eu, err := euRepo.GetEndUser(r.Context(), idOrExt)
	if err == nil && eu != nil {
		return eu, nil
	}
	if !errors.Is(err, storage.ErrNotFound) {
		return nil, err
	}
	scopedOrg := resolveScopedOrgID(r, r.URL.Query().Get("org_id"))
	if scopedOrg != "" {
		return euRepo.GetEndUserByExternalID(r.Context(), scopedOrg, idOrExt)
	}
	return nil, storage.ErrNotFound
}

func (s *GatewayServer) handleAdminGetEndUser(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(chi.URLParam(r, "id"))
	if id == "" {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "missing_end_user_id",
			Message:    "id is required",
		})
		return
	}
	euRepo, ok := s.endUserRepo()
	if !ok {
		if _, authOK := s.authorizeAdmin(w, r, resolveScopedOrgID(r, r.URL.Query().Get("org_id")), false); !authOK {
			return
		}
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusNotImplemented,
			Type:       domain.ErrorTypeServer,
			Code:       "end_users_unsupported",
			Message:    "Configured storage repository does not support end users",
		})
		return
	}
	existing, err := s.resolveEndUserByIDOrExternal(r, euRepo, id)
	if err != nil || existing == nil {
		if _, authOK := s.authorizeAdmin(w, r, resolveScopedOrgID(r, r.URL.Query().Get("org_id")), false); !authOK {
			return
		}
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusNotFound,
			Type:       domain.ErrorTypeNotFound,
			Code:       "end_user_not_found",
			Message:    "End user not found",
		})
		return
	}
	if _, authOK := s.authorizeAdmin(w, r, existing.OrgID, false); !authOK {
		return
	}
	if !verifyExplicitOrgMatch(w, r, existing.OrgID, nil) {
		return
	}
	writeJSON(w, http.StatusOK, existing)
}

func (s *GatewayServer) handleAdminDeleteEndUser(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(chi.URLParam(r, "id"))
	if id == "" {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "missing_end_user_id",
			Message:    "id is required",
		})
		return
	}
	euRepo, ok := s.endUserRepo()
	if !ok {
		if _, authOK := s.authorizeAdmin(w, r, resolveScopedOrgID(r, r.URL.Query().Get("org_id")), true); !authOK {
			return
		}
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusNotImplemented,
			Type:       domain.ErrorTypeServer,
			Code:       "end_users_unsupported",
			Message:    "Configured storage repository does not support end users",
		})
		return
	}
	existing, err := s.resolveEndUserByIDOrExternal(r, euRepo, id)
	if err != nil || existing == nil {
		if _, authOK := s.authorizeAdmin(w, r, resolveScopedOrgID(r, r.URL.Query().Get("org_id")), true); !authOK {
			return
		}
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusNotFound,
			Type:       domain.ErrorTypeNotFound,
			Code:       "end_user_not_found",
			Message:    "End user not found",
		})
		return
	}
	if _, authOK := s.authorizeAdmin(w, r, existing.OrgID, true); !authOK {
		return
	}
	if !verifyExplicitOrgMatch(w, r, existing.OrgID, nil) {
		return
	}
	if err := euRepo.DeleteEndUser(r.Context(), existing.ID); err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	if s.rbac != nil {
		s.rbac.InvalidateEndUser(r.Context(), existing.OrgID, existing.EndUserID)
	}
	s.auditWithDiff(r.Context(), existing.OrgID, "end_user.deleted", "end_user", existing.ID, map[string]any{
		"end_user_id": existing.EndUserID,
	}, existing, nil)
	writeJSON(w, http.StatusOK, map[string]any{"deleted": true, "id": existing.ID})
}

// --- Tags (/admin/v1/tags) ---

func (s *GatewayServer) handleAdminUpsertTag(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID                string                   `json:"id,omitempty"`
		OrgID             string                   `json:"org_id"`
		Tag               string                   `json:"tag"`
		Description       string                   `json:"description,omitempty"`
		MaxBudgetMicros   int64                    `json:"max_budget_micros,omitempty"`
		BudgetResetPeriod domain.BudgetResetPeriod `json:"budget_reset_period,omitempty"`
		BudgetResetAt     *time.Time               `json:"budget_reset_at,omitempty"`
		RPMLimit          int                      `json:"rpm_limit,omitempty"`
		TPMLimit          int                      `json:"tpm_limit,omitempty"`
		ITPMLimit         int                      `json:"itpm_limit,omitempty"`
		OTPMLimit         int                      `json:"otpm_limit,omitempty"`
		TPDLimit          int64                    `json:"tpd_limit,omitempty"`
		MaxConcurrent     int                      `json:"max_concurrent,omitempty"`
		AllowedModels     []string                 `json:"allowed_models,omitempty"`
		IsActive          *bool                    `json:"is_active,omitempty"`
		Metadata          map[string]string        `json:"metadata,omitempty"`
	}
	if err := decodeAdminJSON(w, r, &req); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_json_body",
			Message:    err.Error(),
		})
		return
	}

	req.OrgID = resolveScopedOrgID(r, req.OrgID)
	if _, ok := s.authorizeAdmin(w, r, req.OrgID, true); !ok {
		return
	}

	tRepo, ok := s.tagRepo()
	if !ok {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusNotImplemented,
			Type:       domain.ErrorTypeServer,
			Code:       "tags_unsupported",
			Message:    "Configured storage repository does not support tags",
		})
		return
	}

	isActive := true
	if req.IsActive != nil {
		isActive = *req.IsActive
	}
	t := &domain.Tag{
		ID:                strings.TrimSpace(req.ID),
		OrgID:             req.OrgID,
		Tag:               strings.TrimSpace(req.Tag),
		Description:       strings.TrimSpace(req.Description),
		MaxBudgetMicros:   req.MaxBudgetMicros,
		BudgetResetPeriod: req.BudgetResetPeriod,
		BudgetResetAt:     req.BudgetResetAt,
		RPMLimit:          req.RPMLimit,
		TPMLimit:          req.TPMLimit,
		ITPMLimit:         req.ITPMLimit,
		OTPMLimit:         req.OTPMLimit,
		TPDLimit:          req.TPDLimit,
		MaxConcurrent:     req.MaxConcurrent,
		AllowedModels:     req.AllowedModels,
		IsActive:          isActive,
		Metadata:          req.Metadata,
	}
	if err := tRepo.UpsertTag(r.Context(), t); err != nil {
		if errors.Is(err, storage.ErrConflict) {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusConflict,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "tag_conflict",
				Message:    err.Error(),
			})
			return
		}
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_tag",
			Message:    err.Error(),
		})
		return
	}

	if s.rbac != nil {
		s.rbac.InvalidatePolicyScope(r.Context(), "rbac_tags", t.OrgID)
	}
	s.auditWithDiff(r.Context(), t.OrgID, "tag.upserted", "tag", t.ID, map[string]any{
		"tag":       t.Tag,
		"is_active": t.IsActive,
	}, nil, t)
	status := http.StatusOK
	if r.Method == http.MethodPost {
		status = http.StatusCreated
	}
	writeJSON(w, status, t)
}

func (s *GatewayServer) handleAdminListTags(w http.ResponseWriter, r *http.Request) {
	orgID := resolveScopedOrgID(r, r.URL.Query().Get("org_id"))
	if _, ok := s.authorizeAdmin(w, r, orgID, false); !ok {
		return
	}
	tRepo, ok := s.tagRepo()
	if !ok {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusNotImplemented,
			Type:       domain.ErrorTypeServer,
			Code:       "tags_unsupported",
			Message:    "Configured storage repository does not support tags",
		})
		return
	}

	activeOnly := false
	if raw := strings.TrimSpace(r.URL.Query().Get("active_only")); raw != "" {
		activeOnly = strings.EqualFold(raw, "true") || raw == "1"
	}
	list, err := tRepo.ListTags(r.Context(), storage.TagFilter{
		OrgID:      orgID,
		Tag:        strings.TrimSpace(r.URL.Query().Get("tag")),
		ActiveOnly: activeOnly,
	})
	if err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	if list == nil {
		list = []*domain.Tag{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": list})
}

func (s *GatewayServer) resolveTagByIDOrName(r *http.Request, tRepo storage.TagRepository, idOrName string) (*domain.Tag, error) {
	t, err := tRepo.GetTag(r.Context(), idOrName)
	if err == nil && t != nil {
		return t, nil
	}
	if !errors.Is(err, storage.ErrNotFound) {
		return nil, err
	}
	scopedOrg := resolveScopedOrgID(r, r.URL.Query().Get("org_id"))
	if scopedOrg != "" {
		return tRepo.GetTagByName(r.Context(), scopedOrg, idOrName)
	}
	return nil, storage.ErrNotFound
}

func (s *GatewayServer) handleAdminGetTag(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(chi.URLParam(r, "id"))
	if id == "" {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "missing_tag_id",
			Message:    "id is required",
		})
		return
	}
	tRepo, ok := s.tagRepo()
	if !ok {
		if _, authOK := s.authorizeAdmin(w, r, resolveScopedOrgID(r, r.URL.Query().Get("org_id")), false); !authOK {
			return
		}
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusNotImplemented,
			Type:       domain.ErrorTypeServer,
			Code:       "tags_unsupported",
			Message:    "Configured storage repository does not support tags",
		})
		return
	}
	existing, err := s.resolveTagByIDOrName(r, tRepo, id)
	if err != nil || existing == nil {
		if _, authOK := s.authorizeAdmin(w, r, resolveScopedOrgID(r, r.URL.Query().Get("org_id")), false); !authOK {
			return
		}
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusNotFound,
			Type:       domain.ErrorTypeNotFound,
			Code:       "tag_not_found",
			Message:    "Tag not found",
		})
		return
	}
	if _, authOK := s.authorizeAdmin(w, r, existing.OrgID, false); !authOK {
		return
	}
	if !verifyExplicitOrgMatch(w, r, existing.OrgID, nil) {
		return
	}
	writeJSON(w, http.StatusOK, existing)
}

func (s *GatewayServer) handleAdminDeleteTag(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(chi.URLParam(r, "id"))
	if id == "" {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "missing_tag_id",
			Message:    "id is required",
		})
		return
	}
	tRepo, ok := s.tagRepo()
	if !ok {
		if _, authOK := s.authorizeAdmin(w, r, resolveScopedOrgID(r, r.URL.Query().Get("org_id")), true); !authOK {
			return
		}
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusNotImplemented,
			Type:       domain.ErrorTypeServer,
			Code:       "tags_unsupported",
			Message:    "Configured storage repository does not support tags",
		})
		return
	}
	existing, err := s.resolveTagByIDOrName(r, tRepo, id)
	if err != nil || existing == nil {
		if _, authOK := s.authorizeAdmin(w, r, resolveScopedOrgID(r, r.URL.Query().Get("org_id")), true); !authOK {
			return
		}
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusNotFound,
			Type:       domain.ErrorTypeNotFound,
			Code:       "tag_not_found",
			Message:    "Tag not found",
		})
		return
	}
	if _, authOK := s.authorizeAdmin(w, r, existing.OrgID, true); !authOK {
		return
	}
	if !verifyExplicitOrgMatch(w, r, existing.OrgID, nil) {
		return
	}
	if err := tRepo.DeleteTag(r.Context(), existing.ID); err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	if s.rbac != nil {
		s.rbac.InvalidatePolicyScope(r.Context(), "rbac_tags", existing.OrgID)
	}
	s.auditWithDiff(r.Context(), existing.OrgID, "tag.deleted", "tag", existing.ID, map[string]any{
		"tag": existing.Tag,
	}, existing, nil)
	writeJSON(w, http.StatusOK, map[string]any{"deleted": true, "id": existing.ID})
}

// --- Model Access Groups (/admin/v1/model-access-groups) ---

func (s *GatewayServer) handleAdminUpsertModelAccessGroup(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID                string                           `json:"id,omitempty"`
		OrgID             string                           `json:"org_id"`
		Name              string                           `json:"name"`
		Description       string                           `json:"description,omitempty"`
		MaxBudgetMicros   int64                            `json:"max_budget_micros,omitempty"`
		BudgetResetPeriod domain.BudgetResetPeriod         `json:"budget_reset_period,omitempty"`
		BudgetResetAt     *time.Time                       `json:"budget_reset_at,omitempty"`
		RPMLimit          int                              `json:"rpm_limit,omitempty"`
		TPMLimit          int                              `json:"tpm_limit,omitempty"`
		ITPMLimit         int                              `json:"itpm_limit,omitempty"`
		OTPMLimit         int                              `json:"otpm_limit,omitempty"`
		TPDLimit          int64                            `json:"tpd_limit,omitempty"`
		MaxConcurrent     int                              `json:"max_concurrent,omitempty"`
		IsActive          *bool                            `json:"is_active,omitempty"`
		Metadata          map[string]string                `json:"metadata,omitempty"`
		Members           []*domain.ModelAccessGroupMember `json:"members,omitempty"`
	}
	if err := decodeAdminJSON(w, r, &req); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_json_body",
			Message:    err.Error(),
		})
		return
	}

	req.OrgID = resolveScopedOrgID(r, req.OrgID)
	if _, ok := s.authorizeAdmin(w, r, req.OrgID, true); !ok {
		return
	}

	magRepo, ok := s.modelAccessGroupRepo()
	if !ok {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusNotImplemented,
			Type:       domain.ErrorTypeServer,
			Code:       "model_access_groups_unsupported",
			Message:    "Configured storage repository does not support model access groups",
		})
		return
	}

	isActive := true
	if req.IsActive != nil {
		isActive = *req.IsActive
	}
	group := &domain.ModelAccessGroup{
		ID:                strings.TrimSpace(req.ID),
		OrgID:             req.OrgID,
		Name:              strings.TrimSpace(req.Name),
		Description:       strings.TrimSpace(req.Description),
		MaxBudgetMicros:   req.MaxBudgetMicros,
		BudgetResetPeriod: req.BudgetResetPeriod,
		BudgetResetAt:     req.BudgetResetAt,
		RPMLimit:          req.RPMLimit,
		TPMLimit:          req.TPMLimit,
		ITPMLimit:         req.ITPMLimit,
		OTPMLimit:         req.OTPMLimit,
		TPDLimit:          req.TPDLimit,
		MaxConcurrent:     req.MaxConcurrent,
		IsActive:          isActive,
		Metadata:          req.Metadata,
	}
	if err := magRepo.UpsertModelAccessGroup(r.Context(), group); err != nil {
		if errors.Is(err, storage.ErrConflict) {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusConflict,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "model_access_group_conflict",
				Message:    err.Error(),
			})
			return
		}
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_model_access_group",
			Message:    err.Error(),
		})
		return
	}

	for _, m := range req.Members {
		if m == nil {
			continue
		}
		m.OrgID = group.OrgID
		m.GroupID = group.ID
		if err := magRepo.AddModelAccessGroupMember(r.Context(), m); err != nil {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusBadRequest,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "invalid_model_access_group_member",
				Message:    err.Error(),
			})
			return
		}
	}
	if members, err := magRepo.ListModelAccessGroupMembers(r.Context(), group.ID); err == nil {
		group.Members = members
	}

	if s.rbac != nil {
		s.rbac.InvalidatePolicyScope(r.Context(), "rbac_mag", group.OrgID)
	}
	s.auditWithDiff(r.Context(), group.OrgID, "model_access_group.upserted", "model_access_group", group.ID, map[string]any{
		"name":      group.Name,
		"is_active": group.IsActive,
	}, nil, group)
	status := http.StatusOK
	if r.Method == http.MethodPost {
		status = http.StatusCreated
	}
	writeJSON(w, status, group)
}

func (s *GatewayServer) handleAdminListModelAccessGroups(w http.ResponseWriter, r *http.Request) {
	orgID := resolveScopedOrgID(r, r.URL.Query().Get("org_id"))
	if _, ok := s.authorizeAdmin(w, r, orgID, false); !ok {
		return
	}
	magRepo, ok := s.modelAccessGroupRepo()
	if !ok {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusNotImplemented,
			Type:       domain.ErrorTypeServer,
			Code:       "model_access_groups_unsupported",
			Message:    "Configured storage repository does not support model access groups",
		})
		return
	}

	activeOnly := false
	if raw := strings.TrimSpace(r.URL.Query().Get("active_only")); raw != "" {
		activeOnly = strings.EqualFold(raw, "true") || raw == "1"
	}
	list, err := magRepo.ListModelAccessGroups(r.Context(), storage.ModelAccessGroupFilter{
		OrgID:      orgID,
		Name:       strings.TrimSpace(r.URL.Query().Get("name")),
		ActiveOnly: activeOnly,
	})
	if err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	for _, g := range list {
		if g == nil {
			continue
		}
		if members, mErr := magRepo.ListModelAccessGroupMembers(r.Context(), g.ID); mErr == nil {
			g.Members = members
		}
	}
	if list == nil {
		list = []*domain.ModelAccessGroup{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": list})
}

func (s *GatewayServer) resolveModelAccessGroupByIDOrName(r *http.Request, magRepo storage.ModelAccessGroupRepository, idOrName string) (*domain.ModelAccessGroup, error) {
	g, err := magRepo.GetModelAccessGroup(r.Context(), idOrName)
	if err == nil && g != nil {
		return g, nil
	}
	if !errors.Is(err, storage.ErrNotFound) {
		return nil, err
	}
	scopedOrg := resolveScopedOrgID(r, r.URL.Query().Get("org_id"))
	if scopedOrg != "" {
		return magRepo.GetModelAccessGroupByName(r.Context(), scopedOrg, idOrName)
	}
	return nil, storage.ErrNotFound
}

func (s *GatewayServer) handleAdminGetModelAccessGroup(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(chi.URLParam(r, "id"))
	if id == "" {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "missing_model_access_group_id",
			Message:    "id is required",
		})
		return
	}
	magRepo, ok := s.modelAccessGroupRepo()
	if !ok {
		if _, authOK := s.authorizeAdmin(w, r, resolveScopedOrgID(r, r.URL.Query().Get("org_id")), false); !authOK {
			return
		}
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusNotImplemented,
			Type:       domain.ErrorTypeServer,
			Code:       "model_access_groups_unsupported",
			Message:    "Configured storage repository does not support model access groups",
		})
		return
	}
	existing, err := s.resolveModelAccessGroupByIDOrName(r, magRepo, id)
	if err != nil || existing == nil {
		if _, authOK := s.authorizeAdmin(w, r, resolveScopedOrgID(r, r.URL.Query().Get("org_id")), false); !authOK {
			return
		}
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusNotFound,
			Type:       domain.ErrorTypeNotFound,
			Code:       "model_access_group_not_found",
			Message:    "Model access group not found",
		})
		return
	}
	if _, authOK := s.authorizeAdmin(w, r, existing.OrgID, false); !authOK {
		return
	}
	if !verifyExplicitOrgMatch(w, r, existing.OrgID, nil) {
		return
	}
	if members, mErr := magRepo.ListModelAccessGroupMembers(r.Context(), existing.ID); mErr == nil {
		existing.Members = members
	}
	writeJSON(w, http.StatusOK, existing)
}

func (s *GatewayServer) handleAdminDeleteModelAccessGroup(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(chi.URLParam(r, "id"))
	if id == "" {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "missing_model_access_group_id",
			Message:    "id is required",
		})
		return
	}
	magRepo, ok := s.modelAccessGroupRepo()
	if !ok {
		if _, authOK := s.authorizeAdmin(w, r, resolveScopedOrgID(r, r.URL.Query().Get("org_id")), true); !authOK {
			return
		}
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusNotImplemented,
			Type:       domain.ErrorTypeServer,
			Code:       "model_access_groups_unsupported",
			Message:    "Configured storage repository does not support model access groups",
		})
		return
	}
	existing, err := s.resolveModelAccessGroupByIDOrName(r, magRepo, id)
	if err != nil || existing == nil {
		if _, authOK := s.authorizeAdmin(w, r, resolveScopedOrgID(r, r.URL.Query().Get("org_id")), true); !authOK {
			return
		}
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusNotFound,
			Type:       domain.ErrorTypeNotFound,
			Code:       "model_access_group_not_found",
			Message:    "Model access group not found",
		})
		return
	}
	if _, authOK := s.authorizeAdmin(w, r, existing.OrgID, true); !authOK {
		return
	}
	if !verifyExplicitOrgMatch(w, r, existing.OrgID, nil) {
		return
	}
	if err := magRepo.DeleteModelAccessGroup(r.Context(), existing.ID); err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	if s.rbac != nil {
		s.rbac.InvalidatePolicyScope(r.Context(), "rbac_mag", existing.OrgID)
	}
	s.auditWithDiff(r.Context(), existing.OrgID, "model_access_group.deleted", "model_access_group", existing.ID, map[string]any{
		"name": existing.Name,
	}, existing, nil)
	writeJSON(w, http.StatusOK, map[string]any{"deleted": true, "id": existing.ID})
}

func (s *GatewayServer) handleAdminAddModelAccessGroupMember(w http.ResponseWriter, r *http.Request) {
	groupIDParam := strings.TrimSpace(chi.URLParam(r, "id"))
	if groupIDParam == "" {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "missing_model_access_group_id",
			Message:    "id is required",
		})
		return
	}
	magRepo, ok := s.modelAccessGroupRepo()
	if !ok {
		if _, authOK := s.authorizeAdmin(w, r, resolveScopedOrgID(r, r.URL.Query().Get("org_id")), true); !authOK {
			return
		}
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusNotImplemented,
			Type:       domain.ErrorTypeServer,
			Code:       "model_access_groups_unsupported",
			Message:    "Configured storage repository does not support model access groups",
		})
		return
	}
	existing, err := s.resolveModelAccessGroupByIDOrName(r, magRepo, groupIDParam)
	if err != nil || existing == nil {
		if _, authOK := s.authorizeAdmin(w, r, resolveScopedOrgID(r, r.URL.Query().Get("org_id")), true); !authOK {
			return
		}
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusNotFound,
			Type:       domain.ErrorTypeNotFound,
			Code:       "model_access_group_not_found",
			Message:    "Model access group not found",
		})
		return
	}
	if _, authOK := s.authorizeAdmin(w, r, existing.OrgID, true); !authOK {
		return
	}

	var req struct {
		ID         string                            `json:"id,omitempty"`
		OrgID      *string                           `json:"org_id,omitempty"`
		MemberType domain.ModelAccessGroupMemberType `json:"member_type"`
		MemberID   string                            `json:"member_id"`
	}
	if err := decodeAdminJSON(w, r, &req); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_json_body",
			Message:    err.Error(),
		})
		return
	}
	if !verifyExplicitOrgMatch(w, r, existing.OrgID, req.OrgID) {
		return
	}

	member := &domain.ModelAccessGroupMember{
		ID:         strings.TrimSpace(req.ID),
		OrgID:      existing.OrgID,
		GroupID:    existing.ID,
		MemberType: req.MemberType,
		MemberID:   strings.TrimSpace(req.MemberID),
	}
	if err := magRepo.AddModelAccessGroupMember(r.Context(), member); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_model_access_group_member",
			Message:    err.Error(),
		})
		return
	}
	if s.rbac != nil {
		s.rbac.InvalidatePolicyScope(r.Context(), "rbac_mag", existing.OrgID)
	}
	s.auditWithDiff(r.Context(), existing.OrgID, "model_access_group_member.added", "model_access_group_member", member.ID, map[string]any{
		"group_id":    existing.ID,
		"member_type": member.MemberType,
		"member_id":   member.MemberID,
	}, nil, member)
	writeJSON(w, http.StatusCreated, member)
}

func (s *GatewayServer) handleAdminListModelAccessGroupMembers(w http.ResponseWriter, r *http.Request) {
	groupIDParam := strings.TrimSpace(chi.URLParam(r, "id"))
	if groupIDParam == "" {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "missing_model_access_group_id",
			Message:    "id is required",
		})
		return
	}
	magRepo, ok := s.modelAccessGroupRepo()
	if !ok {
		if _, authOK := s.authorizeAdmin(w, r, resolveScopedOrgID(r, r.URL.Query().Get("org_id")), false); !authOK {
			return
		}
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusNotImplemented,
			Type:       domain.ErrorTypeServer,
			Code:       "model_access_groups_unsupported",
			Message:    "Configured storage repository does not support model access groups",
		})
		return
	}
	existing, err := s.resolveModelAccessGroupByIDOrName(r, magRepo, groupIDParam)
	if err != nil || existing == nil {
		if _, authOK := s.authorizeAdmin(w, r, resolveScopedOrgID(r, r.URL.Query().Get("org_id")), false); !authOK {
			return
		}
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusNotFound,
			Type:       domain.ErrorTypeNotFound,
			Code:       "model_access_group_not_found",
			Message:    "Model access group not found",
		})
		return
	}
	if _, authOK := s.authorizeAdmin(w, r, existing.OrgID, false); !authOK {
		return
	}
	if !verifyExplicitOrgMatch(w, r, existing.OrgID, nil) {
		return
	}
	members, err := magRepo.ListModelAccessGroupMembers(r.Context(), existing.ID)
	if err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	if members == nil {
		members = []*domain.ModelAccessGroupMember{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": members})
}

func (s *GatewayServer) handleAdminRemoveModelAccessGroupMember(w http.ResponseWriter, r *http.Request) {
	groupIDParam := strings.TrimSpace(chi.URLParam(r, "id"))
	memberIDParam := strings.TrimSpace(chi.URLParam(r, "memberID"))
	if groupIDParam == "" || memberIDParam == "" {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "missing_member_id",
			Message:    "group id and memberID are required",
		})
		return
	}
	magRepo, ok := s.modelAccessGroupRepo()
	if !ok {
		if _, authOK := s.authorizeAdmin(w, r, resolveScopedOrgID(r, r.URL.Query().Get("org_id")), true); !authOK {
			return
		}
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusNotImplemented,
			Type:       domain.ErrorTypeServer,
			Code:       "model_access_groups_unsupported",
			Message:    "Configured storage repository does not support model access groups",
		})
		return
	}
	existing, err := s.resolveModelAccessGroupByIDOrName(r, magRepo, groupIDParam)
	if err != nil || existing == nil {
		if _, authOK := s.authorizeAdmin(w, r, resolveScopedOrgID(r, r.URL.Query().Get("org_id")), true); !authOK {
			return
		}
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusNotFound,
			Type:       domain.ErrorTypeNotFound,
			Code:       "model_access_group_not_found",
			Message:    "Model access group not found",
		})
		return
	}
	if _, authOK := s.authorizeAdmin(w, r, existing.OrgID, true); !authOK {
		return
	}
	if !verifyExplicitOrgMatch(w, r, existing.OrgID, nil) {
		return
	}

	var delErr error
	if memberTypeRaw := strings.TrimSpace(r.URL.Query().Get("member_type")); memberTypeRaw != "" {
		delErr = magRepo.RemoveModelAccessGroupMemberByTuple(r.Context(), existing.ID, domain.ModelAccessGroupMemberType(strings.ToLower(memberTypeRaw)), memberIDParam)
	} else {
		delErr = magRepo.RemoveModelAccessGroupMember(r.Context(), existing.ID, memberIDParam)
	}
	if delErr != nil {
		if errors.Is(delErr, storage.ErrNotFound) {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusNotFound,
				Type:       domain.ErrorTypeNotFound,
				Code:       "model_access_group_member_not_found",
				Message:    "Model access group member not found",
			})
			return
		}
		domain.WriteHTTPError(w, delErr)
		return
	}
	if s.rbac != nil {
		s.rbac.InvalidatePolicyScope(r.Context(), "rbac_mag", existing.OrgID)
	}
	s.auditWithDiff(r.Context(), existing.OrgID, "model_access_group_member.removed", "model_access_group_member", memberIDParam, map[string]any{
		"group_id": existing.ID,
	}, map[string]any{"group_id": existing.ID, "member_id": memberIDParam}, nil)
	writeJSON(w, http.StatusOK, map[string]any{"deleted": true, "id": memberIDParam})
}
