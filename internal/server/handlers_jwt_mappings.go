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

func (s *GatewayServer) jwtMappingRepo() (storage.JWTMappingRepository, bool) {
	if s == nil || s.repo == nil {
		return nil, false
	}
	r, ok := s.repo.(storage.JWTMappingRepository)
	return r, ok && r != nil
}

func (s *GatewayServer) lookupJWTKeyMappingByID(ctx context.Context, mappingRepo storage.JWTMappingRepository, id string) (*domain.JWTKeyMapping, error) {
	if getter, ok := s.repo.(storage.JWTMappingLookupRepository); ok && getter != nil {
		return getter.GetJWTKeyMapping(ctx, id)
	}
	list, err := mappingRepo.ListJWTKeyMappings(ctx, "")
	if err != nil {
		return nil, err
	}
	for _, m := range list {
		if m != nil && m.ID == id {
			return m, nil
		}
	}
	return nil, storage.ErrNotFound
}

func (s *GatewayServer) handleAdminCreateJWTMapping(w http.ResponseWriter, r *http.Request) {
	var req struct {
		OrgID        string `json:"org_id"`
		Issuer       string `json:"issuer"`
		ClaimName    string `json:"claim_name"`
		ClaimValue   string `json:"claim_value"`
		VirtualKeyID string `json:"virtual_key_id"`
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

	issuer := strings.TrimSpace(req.Issuer)
	claimName := strings.TrimSpace(req.ClaimName)
	claimValue := strings.TrimSpace(req.ClaimValue)
	vkID := strings.TrimSpace(req.VirtualKeyID)
	if issuer == "" || claimName == "" || claimValue == "" || vkID == "" {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_jwt_mapping",
			Message:    "issuer, claim_name, claim_value, and virtual_key_id are required",
		})
		return
	}

	mappingRepo, ok := s.jwtMappingRepo()
	if !ok {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusNotImplemented,
			Type:       domain.ErrorTypeServer,
			Code:       "jwt_mappings_unsupported",
			Message:    "Configured storage repository does not support JWT key mappings",
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

	vk, err := s.repo.GetVirtualKeyByID(r.Context(), vkID)
	if err != nil || vk == nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusNotFound,
			Type:       domain.ErrorTypeNotFound,
			Code:       "virtual_key_not_found",
			Message:    "Target virtual key not found",
		})
		return
	}
	if vk.OrgID != orgID {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusForbidden,
			Type:       domain.ErrorTypePermission,
			Code:       "cross_org_access_denied",
			Message:    "Target virtual key does not belong to the requested organization",
		})
		return
	}

	mapping := &domain.JWTKeyMapping{
		OrgID:        orgID,
		Issuer:       issuer,
		ClaimName:    claimName,
		ClaimValue:   claimValue,
		VirtualKeyID: vkID,
	}
	if err := mappingRepo.CreateJWTKeyMapping(r.Context(), mapping); err != nil {
		if errors.Is(err, storage.ErrConflict) {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusConflict,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "jwt_mapping_conflict",
				Message:    "A JWT key mapping for this (issuer, claim_name, claim_value) already exists",
			})
			return
		}
		domain.WriteHTTPError(w, err)
		return
	}

	s.auditWithDiff(r.Context(), mapping.OrgID, "jwt_mapping.created", "jwt_key_mapping", mapping.ID, map[string]any{
		"issuer":         mapping.Issuer,
		"claim_name":     mapping.ClaimName,
		"claim_value":    mapping.ClaimValue,
		"virtual_key_id": mapping.VirtualKeyID,
	}, nil, mapping)
	writeJSON(w, http.StatusCreated, mapping)
}

func (s *GatewayServer) handleAdminListJWTMappings(w http.ResponseWriter, r *http.Request) {
	orgID := resolveScopedOrgID(r, strings.TrimSpace(r.URL.Query().Get("org_id")))
	if _, ok := s.authorizeAdmin(w, r, orgID, false); !ok {
		return
	}

	mappingRepo, ok := s.jwtMappingRepo()
	if !ok {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusNotImplemented,
			Type:       domain.ErrorTypeServer,
			Code:       "jwt_mappings_unsupported",
			Message:    "Configured storage repository does not support JWT key mappings",
		})
		return
	}

	mappings, err := mappingRepo.ListJWTKeyMappings(r.Context(), orgID)
	if err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	if mappings == nil {
		mappings = []*domain.JWTKeyMapping{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"data": mappings})
}

func (s *GatewayServer) handleAdminDeleteJWTMapping(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxAdminRequestBodyBytes)
	id := strings.TrimSpace(chi.URLParam(r, "id"))
	if id == "" {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "missing_mapping_id",
			Message:    "id is required",
		})
		return
	}

	mappingRepo, ok := s.jwtMappingRepo()
	if !ok {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusNotImplemented,
			Type:       domain.ErrorTypeServer,
			Code:       "jwt_mappings_unsupported",
			Message:    "Configured storage repository does not support JWT key mappings",
		})
		return
	}

	existing, err := s.lookupJWTKeyMappingByID(r.Context(), mappingRepo, id)
	if err != nil || existing == nil {
		if _, ok := s.authorizeAdmin(w, r, resolveScopedOrgID(r, r.URL.Query().Get("org_id")), true); !ok {
			return
		}
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusNotFound,
			Type:       domain.ErrorTypeNotFound,
			Code:       "jwt_mapping_not_found",
			Message:    "JWT key mapping not found",
		})
		return
	}

	if _, ok := s.authorizeAdmin(w, r, existing.OrgID, true); !ok {
		return
	}
	if !verifyExplicitOrgMatch(w, r, existing.OrgID, nil) {
		return
	}

	if err := mappingRepo.DeleteJWTKeyMapping(r.Context(), id); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusNotFound,
				Type:       domain.ErrorTypeNotFound,
				Code:       "jwt_mapping_not_found",
				Message:    "JWT key mapping not found",
			})
			return
		}
		domain.WriteHTTPError(w, err)
		return
	}

	s.auditWithDiff(r.Context(), existing.OrgID, "jwt_mapping.deleted", "jwt_key_mapping", id, map[string]any{
		"issuer":         existing.Issuer,
		"claim_name":     existing.ClaimName,
		"claim_value":    existing.ClaimValue,
		"virtual_key_id": existing.VirtualKeyID,
	}, existing, nil)
	writeJSON(w, http.StatusOK, map[string]any{"status": "deleted", "id": id})
}
