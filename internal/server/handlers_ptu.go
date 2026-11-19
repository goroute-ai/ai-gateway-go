package server

import (
	"context"
	"errors"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

func (s *GatewayServer) ptuRepo() (storage.PTUShareRepository, bool) {
	if s == nil || s.repo == nil {
		return nil, false
	}
	r, ok := s.repo.(storage.PTUShareRepository)
	return r, ok && r != nil
}

func (s *GatewayServer) resolveDeploymentAndOrg(ctx context.Context, depID string) (*domain.Deployment, string, error) {
	if s == nil || s.repo == nil {
		return nil, "", storage.ErrNotFound
	}
	deps, err := s.repo.ListAllDeployments(ctx)
	if err != nil {
		return nil, "", err
	}
	var target *domain.Deployment
	for _, d := range deps {
		if d != nil && d.ID == depID {
			target = d
			break
		}
	}
	if target == nil {
		return nil, "", storage.ErrNotFound
	}
	if strings.TrimSpace(target.ModelGroupID) == "" {
		return target, "", nil
	}
	mg, err := s.repo.GetModelGroupByID(ctx, target.ModelGroupID)
	if err != nil || mg == nil {
		return target, "", err
	}
	return target, mg.OrgID, nil
}

func (s *GatewayServer) handleAdminUpsertDeploymentPTUShare(w http.ResponseWriter, r *http.Request) {
	depID := strings.TrimSpace(chi.URLParam(r, "depID"))
	if depID == "" {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "missing_deployment_id",
			Message:    "depID is required",
		})
		return
	}

	dep, targetOrgID, err := s.resolveDeploymentAndOrg(r.Context(), depID)
	if err != nil || dep == nil {
		if _, ok := s.authorizeAdmin(w, r, resolveScopedOrgID(r, r.URL.Query().Get("org_id")), true); !ok {
			return
		}
		if err != nil && !errors.Is(err, storage.ErrNotFound) {
			domain.WriteHTTPError(w, err)
			return
		}
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusNotFound,
			Type:       domain.ErrorTypeNotFound,
			Code:       "deployment_not_found",
			Message:    "Deployment not found",
		})
		return
	}

	if _, ok := s.authorizeAdmin(w, r, targetOrgID, true); !ok {
		return
	}

	ptuRepo, ok := s.ptuRepo()
	if !ok {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusNotImplemented,
			Type:       domain.ErrorTypeServer,
			Code:       "ptu_shares_unsupported",
			Message:    "Configured storage repository does not support PTU shares",
		})
		return
	}

	var req struct {
		OrgID       *string `json:"org_id,omitempty"`
		TeamID      string  `json:"team_id"`
		ReservedRPM int     `json:"reserved_rpm"`
		ReservedTPM int     `json:"reserved_tpm"`
	}
	if err := decodeAdminJSON(w, r, &req); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Message:    err.Error(),
		})
		return
	}
	if !verifyExplicitOrgMatch(w, r, targetOrgID, req.OrgID) {
		return
	}

	teamID := strings.TrimSpace(req.TeamID)
	if teamID == "" {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "missing_team_id",
			Message:    "team_id is required",
		})
		return
	}
	if req.ReservedRPM < 0 || req.ReservedTPM < 0 {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_ptu_share",
			Message:    "reserved_rpm and reserved_tpm must be non-negative",
		})
		return
	}

	team, err := s.repo.GetTeam(r.Context(), teamID)
	if err != nil || team == nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusNotFound,
			Type:       domain.ErrorTypeNotFound,
			Code:       "team_not_found",
			Message:    "Target team not found",
		})
		return
	}
	if targetOrgID != "" && team.OrgID != targetOrgID {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusForbidden,
			Type:       domain.ErrorTypePermission,
			Code:       "cross_org_access_denied",
			Message:    "Target team does not belong to deployment's organization",
		})
		return
	}
	effectiveOrgID := targetOrgID
	if effectiveOrgID == "" {
		effectiveOrgID = team.OrgID
	}

	if dep.RPMCapacity > 0 || dep.TPMCapacity > 0 {
		existing, err := ptuRepo.ListDeploymentPTUShares(r.Context(), depID)
		if err != nil {
			domain.WriteHTTPError(w, err)
			return
		}
		totalRPM := req.ReservedRPM
		totalTPM := req.ReservedTPM
		for _, item := range existing {
			if item == nil || item.TeamID == teamID {
				continue
			}
			totalRPM += item.ReservedRPM
			totalTPM += item.ReservedTPM
		}
		if dep.RPMCapacity > 0 && totalRPM > dep.RPMCapacity {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusBadRequest,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "ptu_capacity_exceeded",
				Message:    "Total reserved PTU RPM exceeds deployment rpm_capacity",
			})
			return
		}
		if dep.TPMCapacity > 0 && totalTPM > dep.TPMCapacity {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusBadRequest,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "ptu_capacity_exceeded",
				Message:    "Total reserved PTU TPM exceeds deployment tpm_capacity",
			})
			return
		}
	}

	var beforeShare *domain.DeploymentPTUShare
	if shares, err := ptuRepo.ListDeploymentPTUShares(r.Context(), depID); err == nil {
		for _, item := range shares {
			if item != nil && item.TeamID == teamID {
				cp := *item
				beforeShare = &cp
				break
			}
		}
	}
	share := &domain.DeploymentPTUShare{
		OrgID:        effectiveOrgID,
		DeploymentID: depID,
		TeamID:       teamID,
		ReservedRPM:  req.ReservedRPM,
		ReservedTPM:  req.ReservedTPM,
	}
	if err := ptuRepo.UpsertDeploymentPTUShare(r.Context(), share); err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	s.invalidateRoutingCaches(r.Context(), storage.InvalidationEvent{EntityType: "ptu_share", EntityID: depID, OrgID: effectiveOrgID})

	s.auditWithDiff(r.Context(), effectiveOrgID, "ptu_share.upserted", "deployment_ptu_share", share.ID, map[string]any{
		"deployment_id": depID,
		"team_id":       teamID,
		"reserved_rpm":  share.ReservedRPM,
		"reserved_tpm":  share.ReservedTPM,
	}, beforeShare, share)
	writeJSON(w, http.StatusOK, share)
}

func (s *GatewayServer) handleAdminListDeploymentPTUShares(w http.ResponseWriter, r *http.Request) {
	depID := strings.TrimSpace(chi.URLParam(r, "depID"))
	if depID == "" {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "missing_deployment_id",
			Message:    "depID is required",
		})
		return
	}

	dep, targetOrgID, err := s.resolveDeploymentAndOrg(r.Context(), depID)
	if err != nil || dep == nil {
		if _, ok := s.authorizeAdmin(w, r, resolveScopedOrgID(r, r.URL.Query().Get("org_id")), false); !ok {
			return
		}
		if err != nil && !errors.Is(err, storage.ErrNotFound) {
			domain.WriteHTTPError(w, err)
			return
		}
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusNotFound,
			Type:       domain.ErrorTypeNotFound,
			Code:       "deployment_not_found",
			Message:    "Deployment not found",
		})
		return
	}

	if _, ok := s.authorizeAdmin(w, r, targetOrgID, false); !ok {
		return
	}
	if !verifyExplicitOrgMatch(w, r, targetOrgID, nil) {
		return
	}

	ptuRepo, ok := s.ptuRepo()
	if !ok {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusNotImplemented,
			Type:       domain.ErrorTypeServer,
			Code:       "ptu_shares_unsupported",
			Message:    "Configured storage repository does not support PTU shares",
		})
		return
	}

	shares, err := ptuRepo.ListDeploymentPTUShares(r.Context(), depID)
	if err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	if shares == nil {
		shares = []*domain.DeploymentPTUShare{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": shares})
}

func (s *GatewayServer) handleAdminDeleteDeploymentPTUShare(w http.ResponseWriter, r *http.Request) {
	depID := strings.TrimSpace(chi.URLParam(r, "depID"))
	teamID := strings.TrimSpace(chi.URLParam(r, "teamID"))
	if depID == "" || teamID == "" {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "missing_ptu_share_params",
			Message:    "depID and teamID are required",
		})
		return
	}

	dep, targetOrgID, err := s.resolveDeploymentAndOrg(r.Context(), depID)
	if err != nil || dep == nil {
		if _, ok := s.authorizeAdmin(w, r, resolveScopedOrgID(r, r.URL.Query().Get("org_id")), true); !ok {
			return
		}
		if err != nil && !errors.Is(err, storage.ErrNotFound) {
			domain.WriteHTTPError(w, err)
			return
		}
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusNotFound,
			Type:       domain.ErrorTypeNotFound,
			Code:       "deployment_not_found",
			Message:    "Deployment not found",
		})
		return
	}

	if _, ok := s.authorizeAdmin(w, r, targetOrgID, true); !ok {
		return
	}
	if !verifyExplicitOrgMatch(w, r, targetOrgID, nil) {
		return
	}

	ptuRepo, ok := s.ptuRepo()
	if !ok {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusNotImplemented,
			Type:       domain.ErrorTypeServer,
			Code:       "ptu_shares_unsupported",
			Message:    "Configured storage repository does not support PTU shares",
		})
		return
	}

	var beforeShare *domain.DeploymentPTUShare
	if shares, listErr := ptuRepo.ListDeploymentPTUShares(r.Context(), depID); listErr == nil {
		for _, item := range shares {
			if item != nil && item.TeamID == teamID {
				cp := *item
				beforeShare = &cp
				break
			}
		}
	}
	if err := ptuRepo.DeleteDeploymentPTUShare(r.Context(), depID, teamID); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusNotFound,
				Type:       domain.ErrorTypeNotFound,
				Code:       "ptu_share_not_found",
				Message:    "Deployment PTU share not found",
			})
			return
		}
		domain.WriteHTTPError(w, err)
		return
	}
	s.invalidateRoutingCaches(r.Context(), storage.InvalidationEvent{EntityType: "ptu_share", EntityID: depID, OrgID: targetOrgID})

	s.auditWithDiff(r.Context(), targetOrgID, "ptu_share.deleted", "deployment_ptu_share", depID+":"+teamID, map[string]any{
		"deployment_id": depID,
		"team_id":       teamID,
	}, beforeShare, nil)
	writeJSON(w, http.StatusOK, map[string]any{
		"status":        "deleted",
		"deployment_id": depID,
		"team_id":       teamID,
	})
}

func (s *GatewayServer) handleAdminUpsertPriorityClass(w http.ResponseWriter, r *http.Request) {
	var req struct {
		ID                string  `json:"id,omitempty"`
		OrgID             string  `json:"org_id,omitempty"`
		Name              string  `json:"name"`
		Weight            float64 `json:"weight"`
		PriorityRank      int     `json:"priority_rank"`
		MaxBorrowMultiple float64 `json:"max_borrow_multiple"`
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

	ptuRepo, ok := s.ptuRepo()
	if !ok {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusNotImplemented,
			Type:       domain.ErrorTypeServer,
			Code:       "priority_classes_unsupported",
			Message:    "Configured storage repository does not support priority classes",
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

	if strings.TrimSpace(req.Name) == "" || req.Weight < 0 || req.MaxBorrowMultiple < 0 {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_priority_class",
			Message:    "name is required and weight/max_borrow_multiple must be non-negative",
		})
		return
	}

	pc := &domain.PriorityClass{
		ID:                strings.TrimSpace(req.ID),
		OrgID:             orgID,
		Name:              strings.TrimSpace(req.Name),
		Weight:            req.Weight,
		PriorityRank:      req.PriorityRank,
		MaxBorrowMultiple: req.MaxBorrowMultiple,
	}
	var beforePC *domain.PriorityClass
	if pcs, listErr := ptuRepo.ListPriorityClasses(r.Context(), orgID); listErr == nil {
		for _, item := range pcs {
			if item != nil && ((pc.ID != "" && item.ID == pc.ID) || strings.EqualFold(item.Name, pc.Name)) {
				cp := *item
				beforePC = &cp
				break
			}
		}
	}
	if err := ptuRepo.UpsertPriorityClass(r.Context(), pc); err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	s.invalidateRoutingCaches(r.Context(), storage.InvalidationEvent{EntityType: "priority_class", EntityID: pc.ID, OrgID: orgID})

	s.auditWithDiff(r.Context(), orgID, "priority_class.upserted", "priority_class", pc.ID, map[string]any{
		"name":                pc.Name,
		"weight":              pc.Weight,
		"priority_rank":       pc.PriorityRank,
		"max_borrow_multiple": pc.MaxBorrowMultiple,
	}, beforePC, pc)
	writeJSON(w, http.StatusOK, pc)
}

func (s *GatewayServer) handleAdminListPriorityClasses(w http.ResponseWriter, r *http.Request) {
	orgID := resolveScopedOrgID(r, strings.TrimSpace(r.URL.Query().Get("org_id")))
	if _, ok := s.authorizeAdmin(w, r, orgID, false); !ok {
		return
	}

	ptuRepo, ok := s.ptuRepo()
	if !ok {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusNotImplemented,
			Type:       domain.ErrorTypeServer,
			Code:       "priority_classes_unsupported",
			Message:    "Configured storage repository does not support priority classes",
		})
		return
	}

	classes, err := ptuRepo.ListPriorityClasses(r.Context(), orgID)
	if err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	if classes == nil {
		classes = []*domain.PriorityClass{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": classes})
}
