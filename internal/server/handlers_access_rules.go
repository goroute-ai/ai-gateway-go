package server

import (
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

func (s *GatewayServer) accessRuleRepo() (storage.AccessRuleRepository, bool) {
	if s == nil || s.repo == nil {
		return nil, false
	}
	r, ok := s.repo.(storage.AccessRuleRepository)
	return r, ok && r != nil
}

func (s *GatewayServer) handleAdminCreateAccessGroupRule(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID            string                    `json:"id,omitempty"`
		OrgID         string                    `json:"org_id,omitempty"`
		Name          string                    `json:"name"`
		Attribute     string                    `json:"attribute"`
		Operator      domain.AccessRuleOperator `json:"operator"`
		Value         string                    `json:"value"`
		AllowedModels []string                  `json:"allowed_models,omitempty"`
		AccessGroupID string                    `json:"access_group_id,omitempty"`
		Priority      int                       `json:"priority,omitempty"`
		IsActive      *bool                     `json:"is_active,omitempty"`
	}
	if err := decodeAdminJSON(w, r, &req); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Message:    err.Error(),
		})
		return
	}

	orgID := resolveScopedOrgID(r, strings.TrimSpace(req.OrgID))
	if _, ok := s.authorizeAdmin(w, r, orgID, true); !ok {
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

	ruleRepo, ok := s.accessRuleRepo()
	if !ok {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusNotImplemented,
			Type:       domain.ErrorTypeServer,
			Code:       "access_rules_unsupported",
			Message:    "Configured storage repository does not support dynamic access group rules",
		})
		return
	}

	if _, err := s.repo.GetOrganization(r.Context(), orgID); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusNotFound,
			Type:       domain.ErrorTypeNotFound,
			Code:       "organization_not_found",
			Message:    "Organization not found",
		})
		return
	}

	isActive := true
	if req.IsActive != nil {
		isActive = *req.IsActive
	}
	rule := &domain.AccessGroupRule{
		ID:            strings.TrimSpace(req.ID),
		OrgID:         orgID,
		Name:          req.Name,
		Attribute:     req.Attribute,
		Operator:      req.Operator,
		Value:         req.Value,
		AllowedModels: req.AllowedModels,
		AccessGroupID: req.AccessGroupID,
		Priority:      req.Priority,
		IsActive:      isActive,
	}
	if err := auth.ValidateAccessGroupRule(rule); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_access_group_rule",
			Message:    err.Error(),
		})
		return
	}

	if err := ruleRepo.CreateAccessGroupRule(r.Context(), rule); err != nil {
		if errors.Is(err, storage.ErrConflict) {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusConflict,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "access_group_rule_conflict",
				Message:    "An access group rule with this id already exists",
			})
			return
		}
		domain.WriteHTTPError(w, err)
		return
	}

	if s.rbac != nil {
		s.rbac.InvalidateAccessGroupRules(r.Context(), rule.OrgID)
	}
	s.audit(r.Context(), rule.OrgID, "access_group_rule.created", "access_group_rule", rule.ID, map[string]any{
		"name":            rule.Name,
		"attribute":       rule.Attribute,
		"operator":        rule.Operator,
		"access_group_id": rule.AccessGroupID,
		"allowed_models":  rule.AllowedModels,
		"priority":        rule.Priority,
		"is_active":       rule.IsActive,
	})
	writeJSON(w, http.StatusCreated, rule)
}

func (s *GatewayServer) handleAdminListAccessGroupRules(w http.ResponseWriter, r *http.Request) {
	orgID := resolveScopedOrgID(r, strings.TrimSpace(r.URL.Query().Get("org_id")))
	if _, ok := s.authorizeAdmin(w, r, orgID, false); !ok {
		return
	}

	ruleRepo, ok := s.accessRuleRepo()
	if !ok {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusNotImplemented,
			Type:       domain.ErrorTypeServer,
			Code:       "access_rules_unsupported",
			Message:    "Configured storage repository does not support dynamic access group rules",
		})
		return
	}

	activeOnly := strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("active_only")), "true")
	rules, err := ruleRepo.ListAccessGroupRules(r.Context(), orgID, activeOnly)
	if err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	if rules == nil {
		rules = []*domain.AccessGroupRule{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": rules})
}

func (s *GatewayServer) handleAdminDeleteAccessGroupRule(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxAdminRequestBodyBytes)
	id := strings.TrimSpace(chi.URLParam(r, "id"))
	if id == "" {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "missing_rule_id",
			Message:    "id is required",
		})
		return
	}

	ruleRepo, ok := s.accessRuleRepo()
	if !ok {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusNotImplemented,
			Type:       domain.ErrorTypeServer,
			Code:       "access_rules_unsupported",
			Message:    "Configured storage repository does not support dynamic access group rules",
		})
		return
	}

	existing, err := ruleRepo.GetAccessGroupRule(r.Context(), id)
	if err != nil || existing == nil {
		if _, ok := s.authorizeAdmin(w, r, resolveScopedOrgID(r, r.URL.Query().Get("org_id")), true); !ok {
			return
		}
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusNotFound,
			Type:       domain.ErrorTypeNotFound,
			Code:       "access_group_rule_not_found",
			Message:    "Access group rule not found",
		})
		return
	}

	if _, ok := s.authorizeAdmin(w, r, existing.OrgID, true); !ok {
		return
	}
	if !verifyExplicitOrgMatch(w, r, existing.OrgID, nil) {
		return
	}

	if err := ruleRepo.DeleteAccessGroupRule(r.Context(), id); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusNotFound,
				Type:       domain.ErrorTypeNotFound,
				Code:       "access_group_rule_not_found",
				Message:    "Access group rule not found",
			})
			return
		}
		domain.WriteHTTPError(w, err)
		return
	}

	if s.rbac != nil {
		s.rbac.InvalidateAccessGroupRules(r.Context(), existing.OrgID)
	}
	s.audit(r.Context(), existing.OrgID, "access_group_rule.deleted", "access_group_rule", id, map[string]any{
		"name":            existing.Name,
		"attribute":       existing.Attribute,
		"operator":        existing.Operator,
		"access_group_id": existing.AccessGroupID,
	})
	writeJSON(w, http.StatusOK, map[string]any{"status": "deleted", "id": id})
}
