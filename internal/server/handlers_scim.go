package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

const (
	scimContentType        = "application/scim+json"
	scimSchemaUser         = "urn:ietf:params:scim:schemas:core:2.0:User"
	scimSchemaGroup        = "urn:ietf:params:scim:schemas:core:2.0:Group"
	scimSchemaListResponse = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	scimSchemaPatchOp      = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	scimSchemaError        = "urn:ietf:params:scim:api:messages:2.0:Error"
)

type scimContextKey int

const scimOrgContextKey scimContextKey = 1

type scimScope struct {
	OrgID string
}

func scimOrgFromContext(ctx context.Context) string {
	if s, ok := ctx.Value(scimOrgContextKey).(scimScope); ok {
		return s.OrgID
	}
	return ""
}

func writeSCIMJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", scimContentType)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeSCIMError(w http.ResponseWriter, status int, scimType, detail string) {
	resp := map[string]any{
		"schemas": []string{scimSchemaError},
		"status":  strconv.Itoa(status),
		"detail":  detail,
	}
	if scimType != "" {
		resp["scimType"] = scimType
	}
	writeSCIMJSON(w, status, resp)
}

type scimMeta struct {
	ResourceType string `json:"resourceType"`
	Created      string `json:"created,omitempty"`
	LastModified string `json:"lastModified,omitempty"`
	Location     string `json:"location,omitempty"`
}

type scimName struct {
	Formatted  string `json:"formatted,omitempty"`
	GivenName  string `json:"givenName,omitempty"`
	FamilyName string `json:"familyName,omitempty"`
}

type scimEmail struct {
	Value   string `json:"value"`
	Type    string `json:"type,omitempty"`
	Primary bool   `json:"primary,omitempty"`
}

type scimGroupRef struct {
	Value   string `json:"value"`
	Display string `json:"display,omitempty"`
	Ref     string `json:"$ref,omitempty"`
}

type scimRoleRef struct {
	Value   string `json:"value"`
	Primary bool   `json:"primary,omitempty"`
}

type scimUserResource struct {
	Schemas     []string       `json:"schemas"`
	ID          string         `json:"id"`
	ExternalID  string         `json:"externalId,omitempty"`
	UserName    string         `json:"userName"`
	Name        *scimName      `json:"name,omitempty"`
	DisplayName string         `json:"displayName,omitempty"`
	Emails      []scimEmail    `json:"emails,omitempty"`
	Active      bool           `json:"active"`
	Groups      []scimGroupRef `json:"groups,omitempty"`
	Roles       []scimRoleRef  `json:"roles,omitempty"`
	Meta        scimMeta       `json:"meta"`
}

type scimUserRequest struct {
	Schemas     []string      `json:"schemas"`
	ExternalID  string        `json:"externalId"`
	UserName    string        `json:"userName"`
	Name        *scimName     `json:"name"`
	DisplayName string        `json:"displayName"`
	Emails      []scimEmail   `json:"emails"`
	Active      *bool         `json:"active"`
	Roles       []scimRoleRef `json:"roles"`
}

type scimMemberRef struct {
	Value   string `json:"value"`
	Display string `json:"display,omitempty"`
	Ref     string `json:"$ref,omitempty"`
}

type scimGroupResource struct {
	Schemas     []string        `json:"schemas"`
	ID          string          `json:"id"`
	DisplayName string          `json:"displayName"`
	Members     []scimMemberRef `json:"members"`
	Meta        scimMeta        `json:"meta"`
}

type scimGroupRequest struct {
	Schemas     []string        `json:"schemas"`
	DisplayName string          `json:"displayName"`
	Members     []scimMemberRef `json:"members"`
}

type scimPatchRequest struct {
	Schemas    []string            `json:"schemas"`
	Operations []scimPatchOpDetail `json:"Operations"`
}

type scimPatchOpDetail struct {
	Op    string          `json:"op"`
	Path  string          `json:"path,omitempty"`
	Value json.RawMessage `json:"value,omitempty"`
}

type scimListResponse struct {
	Schemas      []string `json:"schemas"`
	TotalResults int      `json:"totalResults"`
	StartIndex   int      `json:"startIndex"`
	ItemsPerPage int      `json:"itemsPerPage"`
	Resources    any      `json:"Resources"`
}

func (s *GatewayServer) scimAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var opts auth.ExtractorOptions
		if s.authSvc != nil {
			opts = s.authSvc.ExtractorOptions()
		}
		cred, err := auth.ExtractCredentials(r, opts)
		if err != nil {
			writeSCIMError(w, http.StatusBadRequest, "invalidSyntax", err.Error())
			return
		}
		token := strings.TrimSpace(cred.Token)
		if token == "" {
			writeSCIMError(w, http.StatusUnauthorized, "", "Valid SCIM virtual key or org_admin/platform_admin credential is required")
			return
		}

		requestedOrg := strings.TrimSpace(r.URL.Query().Get("org_id"))
		if requestedOrg == "" {
			requestedOrg = strings.TrimSpace(r.Header.Get("X-Gateway-Org-Id"))
		}

		// 1. Master Admin Key (platform_admin)
		if s.authSvc != nil && s.authSvc.ValidateAdminKey(token) {
			orgID := requestedOrg
			if orgID == "" && s.cfg != nil {
				orgID = strings.TrimSpace(s.cfg.Auth.DefaultOrgID)
			}
			if orgID == "" {
				orgID = "org_default"
			}
			org, orgErr := s.repo.GetOrganization(r.Context(), orgID)
			if orgErr != nil || org == nil || !org.IsActive {
				writeSCIMError(w, http.StatusForbidden, "", "Target organization is inactive or does not exist")
				return
			}
			op := &domain.OperatorContext{
				ActorID:        "master_admin",
				Role:           domain.OperatorRolePlatformAdmin,
				OrgID:          org.ID,
				AuthMethod:     "master_key",
				CanImpersonate: true,
			}
			ctx := auth.WithOperator(r.Context(), op)
			ctx = context.WithValue(ctx, scimOrgContextKey, scimScope{OrgID: org.ID})
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		// 2. Virtual API Key (SCIM-scoped or org_admin/platform_admin)
		if strings.HasPrefix(token, "sk-gw-") {
			idCtx, authErr := s.authSvc.AuthenticateVirtualKey(r.Context(), token)
			if authErr != nil {
				var gwErr *domain.GatewayError
				if errors.As(authErr, &gwErr) {
					writeSCIMError(w, gwErr.StatusCode, "", gwErr.Message)
					return
				}
				writeSCIMError(w, http.StatusUnauthorized, "", authErr.Error())
				return
			}
			if idCtx.KeyType == domain.KeyTypeLLMAPI {
				writeSCIMError(w, http.StatusForbidden, "", "Virtual keys with key_type \"llm_api\" are not authorized for SCIM endpoints")
				return
			}
			if idCtx.KeyType == domain.KeyTypeReadOnly && r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions {
				writeSCIMError(w, http.StatusForbidden, "", "Read-only virtual keys cannot mutate SCIM resources")
				return
			}

			isPrivilegedAdmin := idCtx.Role == domain.RoleOrgAdmin || idCtx.Role == domain.RolePlatformAdmin
			hasExplicitSCIMScope := hasSCIMEndpointPattern(idCtx.AllowedEndpoints) && idCtx.TeamID == ""
			endpointAllowed := s.rbac == nil || s.rbac.AuthorizeEndpoint(idCtx, r.URL.Path) == nil
			managementAdmin := isPrivilegedAdmin && idCtx.KeyType == domain.KeyTypeManagement

			if !((hasExplicitSCIMScope && endpointAllowed) || (isPrivilegedAdmin && (endpointAllowed || managementAdmin))) {
				writeSCIMError(w, http.StatusForbidden, "", "Virtual key is not authorized to access SCIM v2 endpoints")
				return
			}

			targetOrg := idCtx.OrgID
			if requestedOrg != "" && requestedOrg != idCtx.OrgID {
				if idCtx.Role != domain.RolePlatformAdmin {
					writeSCIMError(w, http.StatusForbidden, "", "Cross-organization SCIM access denied")
					return
				}
				org, orgErr := s.repo.GetOrganization(r.Context(), requestedOrg)
				if orgErr != nil || org == nil || !org.IsActive {
					writeSCIMError(w, http.StatusForbidden, "", "Target organization is inactive or does not exist")
					return
				}
				targetOrg = org.ID
			}
			if targetOrg == "" {
				writeSCIMError(w, http.StatusForbidden, "", "Organization scope is required for SCIM operations")
				return
			}

			actorID := idCtx.VirtualKeyID
			if idCtx.UserID != "" {
				actorID = idCtx.UserID
			}
			opRole := domain.OperatorRoleOrgAdmin
			if idCtx.Role == domain.RolePlatformAdmin {
				opRole = domain.OperatorRolePlatformAdmin
			}
			op := &domain.OperatorContext{
				ActorID:    actorID,
				Role:       opRole,
				OrgID:      targetOrg,
				TeamID:     idCtx.TeamID,
				AuthMethod: "virtual_key",
			}
			ctx := auth.WithOperator(r.Context(), op)
			ctx = context.WithValue(ctx, scimOrgContextKey, scimScope{OrgID: targetOrg})
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		// 3. Operator JWT/OIDC (org_admin or platform_admin only)
		op, opErr := s.authSvc.AuthenticateOperatorWithSource(r.Context(), cred)
		if opErr != nil {
			var gwErr *domain.GatewayError
			if errors.As(opErr, &gwErr) {
				writeSCIMError(w, gwErr.StatusCode, "", gwErr.Message)
				return
			}
			writeSCIMError(w, http.StatusUnauthorized, "", opErr.Error())
			return
		}
		if op.Role != domain.OperatorRoleOrgAdmin && op.Role != domain.OperatorRolePlatformAdmin {
			writeSCIMError(w, http.StatusForbidden, "", "SCIM provisioning requires org_admin or platform_admin role")
			return
		}
		targetOrg := op.OrgID
		if requestedOrg != "" && requestedOrg != op.OrgID {
			if op.Role != domain.OperatorRolePlatformAdmin {
				writeSCIMError(w, http.StatusForbidden, "", "Cross-organization SCIM access denied")
				return
			}
			org, orgErr := s.repo.GetOrganization(r.Context(), requestedOrg)
			if orgErr != nil || org == nil || !org.IsActive {
				writeSCIMError(w, http.StatusForbidden, "", "Target organization is inactive or does not exist")
				return
			}
			targetOrg = org.ID
		}
		if targetOrg == "" && s.cfg != nil {
			targetOrg = strings.TrimSpace(s.cfg.Auth.DefaultOrgID)
		}
		if targetOrg == "" {
			writeSCIMError(w, http.StatusBadRequest, "invalidValue", "org_id is required")
			return
		}
		ctx := auth.WithOperator(r.Context(), op)
		ctx = context.WithValue(ctx, scimOrgContextKey, scimScope{OrgID: targetOrg})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func hasSCIMEndpointPattern(patterns []string) bool {
	for _, p := range patterns {
		trimmed := strings.TrimSpace(p)
		if strings.HasPrefix(trimmed, "/scim") {
			return true
		}
	}
	return false
}

// --- SCIM Users Handlers ---

func (s *GatewayServer) handleSCIMListUsers(w http.ResponseWriter, r *http.Request) {
	orgID := scimOrgFromContext(r.Context())
	filterStr := strings.TrimSpace(r.URL.Query().Get("filter"))

	users, err := s.repo.ListUsers(r.Context(), orgID)
	if err != nil {
		writeSCIMError(w, http.StatusInternalServerError, "", err.Error())
		return
	}

	var matched []*domain.User
	if filterStr != "" {
		attr, val, ok := parseSCIMEqFilter(filterStr)
		if !ok {
			writeSCIMError(w, http.StatusBadRequest, "invalidFilter", fmt.Sprintf("unsupported SCIM filter %q", filterStr))
			return
		}
		for _, u := range users {
			if u != nil && u.OrgID == orgID && scimUserMatchesFilter(u, attr, val) {
				matched = append(matched, u)
			}
		}
	} else {
		for _, u := range users {
			if u != nil && u.OrgID == orgID {
				matched = append(matched, u)
			}
		}
	}

	total, startIdx, page := paginateSCIMSlice(matched, r)
	resources := make([]scimUserResource, 0, len(page))
	for _, u := range page {
		resources = append(resources, s.toSCIMUser(r.Context(), orgID, u))
	}
	writeSCIMJSON(w, http.StatusOK, scimListResponse{
		Schemas:      []string{scimSchemaListResponse},
		TotalResults: total,
		StartIndex:   startIdx,
		ItemsPerPage: len(resources),
		Resources:    resources,
	})
}

func (s *GatewayServer) handleSCIMCreateUser(w http.ResponseWriter, r *http.Request) {
	orgID := scimOrgFromContext(r.Context())
	var req scimUserRequest
	if err := decodeAdminJSON(w, r, &req); err != nil {
		writeSCIMError(w, http.StatusBadRequest, "invalidSyntax", err.Error())
		return
	}

	email := extractSCIMPrimaryEmail(req.Emails, req.UserName)
	if email == "" {
		writeSCIMError(w, http.StatusBadRequest, "invalidValue", "userName or emails.value is required")
		return
	}
	extID := strings.TrimSpace(req.ExternalID)

	if extID != "" {
		if scimRepo, ok := s.repo.(storage.SCIMRepository); ok && scimRepo != nil {
			if existing, err := scimRepo.GetUserBySCIMExternalID(r.Context(), orgID, extID); err == nil && existing != nil {
				writeSCIMError(w, http.StatusConflict, "uniqueness", fmt.Sprintf("user with externalId %q already exists", extID))
				return
			}
		}
	}
	existingUsers, err := s.repo.ListUsers(r.Context(), orgID)
	if err != nil {
		writeSCIMError(w, http.StatusInternalServerError, "", err.Error())
		return
	}
	for _, u := range existingUsers {
		if u == nil || u.OrgID != orgID {
			continue
		}
		if extID != "" && u.SCIMExternalID == extID {
			writeSCIMError(w, http.StatusConflict, "uniqueness", fmt.Sprintf("user with externalId %q already exists", extID))
			return
		}
		if strings.EqualFold(u.Email, email) {
			writeSCIMError(w, http.StatusConflict, "uniqueness", fmt.Sprintf("user with userName/email %q already exists", email))
			return
		}
	}

	active := true
	if req.Active != nil {
		active = *req.Active
	}
	role := resolveSCIMUserRole(req.Roles, auth.OperatorFromContext(r.Context()), domain.RoleDeveloper)
	displayName := extractSCIMDisplayName(req.DisplayName, req.Name, email)

	user := &domain.User{
		OrgID:             orgID,
		Email:             email,
		Name:              displayName,
		Role:              role,
		SCIMExternalID:    extID,
		SCIMActive:        active,
		IsActive:          active,
		BudgetResetPeriod: domain.BudgetResetMonthly,
	}
	if err := s.repo.CreateUser(r.Context(), user); err != nil {
		writeSCIMError(w, http.StatusBadRequest, "", err.Error())
		return
	}

	s.auditWithDiff(r.Context(), orgID, "scim.user.created", "user", user.ID, map[string]any{
		"email":            user.Email,
		"scim_external_id": user.SCIMExternalID,
		"scim_active":      user.SCIMActive,
	}, nil, user)
	writeSCIMJSON(w, http.StatusCreated, s.toSCIMUser(r.Context(), orgID, user))
}

func (s *GatewayServer) handleSCIMGetUser(w http.ResponseWriter, r *http.Request) {
	orgID := scimOrgFromContext(r.Context())
	userID := strings.TrimSpace(chi.URLParam(r, "id"))
	user, err := s.lookupSCIMUser(r.Context(), orgID, userID)
	if err != nil {
		writeSCIMError(w, http.StatusNotFound, "", "User not found")
		return
	}
	writeSCIMJSON(w, http.StatusOK, s.toSCIMUser(r.Context(), orgID, user))
}

func (s *GatewayServer) handleSCIMReplaceUser(w http.ResponseWriter, r *http.Request) {
	orgID := scimOrgFromContext(r.Context())
	userID := strings.TrimSpace(chi.URLParam(r, "id"))
	existing, err := s.lookupSCIMUser(r.Context(), orgID, userID)
	if err != nil {
		writeSCIMError(w, http.StatusNotFound, "", "User not found")
		return
	}

	var req scimUserRequest
	if err := decodeAdminJSON(w, r, &req); err != nil {
		writeSCIMError(w, http.StatusBadRequest, "invalidSyntax", err.Error())
		return
	}
	email := extractSCIMPrimaryEmail(req.Emails, req.UserName)
	if email == "" {
		writeSCIMError(w, http.StatusBadRequest, "invalidValue", "userName or emails.value is required")
		return
	}

	active := true
	if req.Active != nil {
		active = *req.Active
	}

	updated := *existing
	updated.Email = email
	updated.Name = extractSCIMDisplayName(req.DisplayName, req.Name, email)
	updated.SCIMExternalID = strings.TrimSpace(req.ExternalID)
	updated.SCIMActive = active
	updated.IsActive = active
	if len(req.Roles) > 0 {
		updated.Role = resolveSCIMUserRole(req.Roles, auth.OperatorFromContext(r.Context()), existing.Role)
	}

	if err := s.repo.UpdateUser(r.Context(), &updated); err != nil {
		writeSCIMError(w, http.StatusBadRequest, "", err.Error())
		return
	}
	s.handleSCIMUserActiveTransition(r.Context(), orgID, existing, &updated)
	writeSCIMJSON(w, http.StatusOK, s.toSCIMUser(r.Context(), orgID, &updated))
}

func (s *GatewayServer) handleSCIMPatchUser(w http.ResponseWriter, r *http.Request) {
	orgID := scimOrgFromContext(r.Context())
	userID := strings.TrimSpace(chi.URLParam(r, "id"))
	existing, err := s.lookupSCIMUser(r.Context(), orgID, userID)
	if err != nil {
		writeSCIMError(w, http.StatusNotFound, "", "User not found")
		return
	}

	var patch scimPatchRequest
	if err := decodeAdminJSON(w, r, &patch); err != nil {
		writeSCIMError(w, http.StatusBadRequest, "invalidSyntax", err.Error())
		return
	}

	updated := *existing
	for _, op := range patch.Operations {
		if err := applySCIMUserPatchOp(&updated, op, auth.OperatorFromContext(r.Context())); err != nil {
			writeSCIMError(w, http.StatusBadRequest, "invalidValue", err.Error())
			return
		}
	}

	if err := s.repo.UpdateUser(r.Context(), &updated); err != nil {
		writeSCIMError(w, http.StatusBadRequest, "", err.Error())
		return
	}
	s.handleSCIMUserActiveTransition(r.Context(), orgID, existing, &updated)
	writeSCIMJSON(w, http.StatusOK, s.toSCIMUser(r.Context(), orgID, &updated))
}

func (s *GatewayServer) handleSCIMDeleteUser(w http.ResponseWriter, r *http.Request) {
	orgID := scimOrgFromContext(r.Context())
	userID := strings.TrimSpace(chi.URLParam(r, "id"))
	existing, err := s.lookupSCIMUser(r.Context(), orgID, userID)
	if err != nil {
		writeSCIMError(w, http.StatusNotFound, "", "User not found")
		return
	}

	updated := *existing
	updated.SCIMActive = false
	updated.IsActive = false
	if err := s.repo.UpdateUser(r.Context(), &updated); err != nil {
		writeSCIMError(w, http.StatusInternalServerError, "", err.Error())
		return
	}
	if s.authSvc != nil {
		s.authSvc.InvalidateUserKeys(r.Context(), orgID, updated.ID)
	}
	s.auditWithDiff(r.Context(), orgID, "scim.user.deprovisioned", "user", updated.ID, map[string]any{
		"email":            updated.Email,
		"scim_external_id": updated.SCIMExternalID,
		"scim_active":      false,
		"is_active":        false,
	}, existing, &updated)
	w.WriteHeader(http.StatusNoContent)
}

func (s *GatewayServer) handleSCIMUserActiveTransition(ctx context.Context, orgID string, prev, curr *domain.User) {
	if !curr.SCIMActive || !curr.IsActive {
		if s.authSvc != nil {
			s.authSvc.InvalidateUserKeys(ctx, orgID, curr.ID)
		}
		s.auditWithDiff(ctx, orgID, "scim.user.deprovisioned", "user", curr.ID, map[string]any{
			"email":            curr.Email,
			"scim_external_id": curr.SCIMExternalID,
			"scim_active":      curr.SCIMActive,
			"is_active":        curr.IsActive,
		}, prev, curr)
		return
	}
	if (prev != nil && (!prev.SCIMActive || !prev.IsActive)) && curr.SCIMActive && curr.IsActive {
		if s.authSvc != nil {
			s.authSvc.InvalidateUserKeys(ctx, orgID, curr.ID)
		}
	}
	s.auditWithDiff(ctx, orgID, "scim.user.updated", "user", curr.ID, map[string]any{
		"email":            curr.Email,
		"scim_external_id": curr.SCIMExternalID,
		"scim_active":      curr.SCIMActive,
		"is_active":        curr.IsActive,
	}, prev, curr)
}

func (s *GatewayServer) lookupSCIMUser(ctx context.Context, orgID, userID string) (*domain.User, error) {
	if userID == "" {
		return nil, storage.ErrNotFound
	}
	u, err := s.lookupUserByID(ctx, userID)
	if err == nil && u != nil && u.OrgID == orgID {
		return u, nil
	}
	if scimRepo, ok := s.repo.(storage.SCIMRepository); ok && scimRepo != nil {
		if u2, extErr := scimRepo.GetUserBySCIMExternalID(ctx, orgID, userID); extErr == nil && u2 != nil && u2.OrgID == orgID {
			return u2, nil
		}
	}
	return nil, storage.ErrNotFound
}

// --- SCIM Groups Handlers ---

func (s *GatewayServer) handleSCIMListGroups(w http.ResponseWriter, r *http.Request) {
	orgID := scimOrgFromContext(r.Context())
	filterStr := strings.TrimSpace(r.URL.Query().Get("filter"))

	teams, err := s.repo.ListTeams(r.Context(), orgID)
	if err != nil {
		writeSCIMError(w, http.StatusInternalServerError, "", err.Error())
		return
	}

	var matched []*domain.Team
	if filterStr != "" {
		attr, val, ok := parseSCIMEqFilter(filterStr)
		if !ok {
			writeSCIMError(w, http.StatusBadRequest, "invalidFilter", fmt.Sprintf("unsupported SCIM filter %q", filterStr))
			return
		}
		for _, t := range teams {
			if t != nil && t.OrgID == orgID && scimGroupMatchesFilter(t, attr, val) {
				matched = append(matched, t)
			}
		}
	} else {
		for _, t := range teams {
			if t != nil && t.OrgID == orgID {
				matched = append(matched, t)
			}
		}
	}

	total, startIdx, page := paginateSCIMSlice(matched, r)
	resources := make([]scimGroupResource, 0, len(page))
	for _, t := range page {
		resources = append(resources, s.toSCIMGroup(r.Context(), orgID, t))
	}
	writeSCIMJSON(w, http.StatusOK, scimListResponse{
		Schemas:      []string{scimSchemaListResponse},
		TotalResults: total,
		StartIndex:   startIdx,
		ItemsPerPage: len(resources),
		Resources:    resources,
	})
}

func (s *GatewayServer) handleSCIMCreateGroup(w http.ResponseWriter, r *http.Request) {
	orgID := scimOrgFromContext(r.Context())
	var req scimGroupRequest
	if err := decodeAdminJSON(w, r, &req); err != nil {
		writeSCIMError(w, http.StatusBadRequest, "invalidSyntax", err.Error())
		return
	}
	displayName := strings.TrimSpace(req.DisplayName)
	if displayName == "" {
		writeSCIMError(w, http.StatusBadRequest, "invalidValue", "displayName is required")
		return
	}

	if scimRepo, ok := s.repo.(storage.SCIMRepository); ok && scimRepo != nil {
		if existing, err := scimRepo.GetTeamByName(r.Context(), orgID, displayName); err == nil && existing != nil {
			writeSCIMError(w, http.StatusConflict, "uniqueness", fmt.Sprintf("group %q already exists", displayName))
			return
		}
	}

	team := &domain.Team{
		OrgID:             orgID,
		Name:              displayName,
		BudgetResetPeriod: domain.BudgetResetMonthly,
		IsActive:          true,
	}
	if err := s.repo.CreateTeam(r.Context(), team); err != nil {
		writeSCIMError(w, http.StatusBadRequest, "", err.Error())
		return
	}
	if err := s.syncSCIMGroupMembers(r.Context(), orgID, team.ID, req.Members, true); err != nil {
		_ = s.repo.DeleteTeam(r.Context(), team.ID)
		writeSCIMError(w, http.StatusBadRequest, "invalidValue", err.Error())
		return
	}
	s.auditWithDiff(r.Context(), orgID, "scim.group.created", "team", team.ID, map[string]any{
		"name":         team.Name,
		"member_count": len(req.Members),
	}, nil, team)
	writeSCIMJSON(w, http.StatusCreated, s.toSCIMGroup(r.Context(), orgID, team))
}

func (s *GatewayServer) handleSCIMGetGroup(w http.ResponseWriter, r *http.Request) {
	orgID := scimOrgFromContext(r.Context())
	teamID := strings.TrimSpace(chi.URLParam(r, "id"))
	team, err := s.repo.GetTeam(r.Context(), teamID)
	if err != nil || team == nil || team.OrgID != orgID {
		writeSCIMError(w, http.StatusNotFound, "", "Group not found")
		return
	}
	writeSCIMJSON(w, http.StatusOK, s.toSCIMGroup(r.Context(), orgID, team))
}

func (s *GatewayServer) handleSCIMReplaceGroup(w http.ResponseWriter, r *http.Request) {
	orgID := scimOrgFromContext(r.Context())
	teamID := strings.TrimSpace(chi.URLParam(r, "id"))
	existing, err := s.repo.GetTeam(r.Context(), teamID)
	if err != nil || existing == nil || existing.OrgID != orgID {
		writeSCIMError(w, http.StatusNotFound, "", "Group not found")
		return
	}

	var req scimGroupRequest
	if err := decodeAdminJSON(w, r, &req); err != nil {
		writeSCIMError(w, http.StatusBadRequest, "invalidSyntax", err.Error())
		return
	}
	displayName := strings.TrimSpace(req.DisplayName)
	if displayName == "" {
		writeSCIMError(w, http.StatusBadRequest, "invalidValue", "displayName is required")
		return
	}
	if displayName != existing.Name {
		if scimRepo, ok := s.repo.(storage.SCIMRepository); ok && scimRepo != nil {
			if dup, dupErr := scimRepo.GetTeamByName(r.Context(), orgID, displayName); dupErr == nil && dup != nil && dup.ID != existing.ID {
				writeSCIMError(w, http.StatusConflict, "uniqueness", fmt.Sprintf("group %q already exists", displayName))
				return
			}
		}
	}

	updated := *existing
	updated.Name = displayName
	if err := s.repo.UpdateTeam(r.Context(), &updated); err != nil {
		writeSCIMError(w, http.StatusBadRequest, "", err.Error())
		return
	}
	if err := s.syncSCIMGroupMembers(r.Context(), orgID, updated.ID, req.Members, true); err != nil {
		writeSCIMError(w, http.StatusBadRequest, "invalidValue", err.Error())
		return
	}
	if s.authSvc != nil {
		s.authSvc.InvalidateTeam(r.Context(), updated.ID)
	}
	s.auditWithDiff(r.Context(), orgID, "scim.group.updated", "team", updated.ID, map[string]any{
		"name":         updated.Name,
		"member_count": len(req.Members),
	}, existing, &updated)
	writeSCIMJSON(w, http.StatusOK, s.toSCIMGroup(r.Context(), orgID, &updated))
}

func (s *GatewayServer) handleSCIMPatchGroup(w http.ResponseWriter, r *http.Request) {
	orgID := scimOrgFromContext(r.Context())
	teamID := strings.TrimSpace(chi.URLParam(r, "id"))
	existing, err := s.repo.GetTeam(r.Context(), teamID)
	if err != nil || existing == nil || existing.OrgID != orgID {
		writeSCIMError(w, http.StatusNotFound, "", "Group not found")
		return
	}

	var patch scimPatchRequest
	if err := decodeAdminJSON(w, r, &patch); err != nil {
		writeSCIMError(w, http.StatusBadRequest, "invalidSyntax", err.Error())
		return
	}

	updated := *existing
	currentMembers := s.collectGroupMemberIDs(r.Context(), orgID, existing.ID)
	membersChanged := false

	for _, op := range patch.Operations {
		opName := strings.ToLower(strings.TrimSpace(op.Op))
		path := strings.TrimSpace(op.Path)
		lowerPath := strings.ToLower(path)

		switch {
		case path == "":
			var body map[string]json.RawMessage
			if err := json.Unmarshal(op.Value, &body); err != nil {
				writeSCIMError(w, http.StatusBadRequest, "invalidValue", "invalid patch value object")
				return
			}
			if rawName, ok := body["displayName"]; ok {
				var name string
				if err := json.Unmarshal(rawName, &name); err != nil || strings.TrimSpace(name) == "" {
					writeSCIMError(w, http.StatusBadRequest, "invalidValue", "invalid displayName in patch")
					return
				}
				updated.Name = strings.TrimSpace(name)
			}
			if rawMembers, ok := body["members"]; ok {
				var refs []scimMemberRef
				if err := json.Unmarshal(rawMembers, &refs); err != nil {
					writeSCIMError(w, http.StatusBadRequest, "invalidValue", "invalid members in patch")
					return
				}
				if opName == "add" {
					currentMembers = mergeMemberIDs(currentMembers, refs)
				} else if opName == "remove" {
					currentMembers = removeMemberIDs(currentMembers, refs)
				} else {
					currentMembers = extractMemberIDs(refs)
				}
				membersChanged = true
			}
		case lowerPath == "displayname":
			var name string
			if err := json.Unmarshal(op.Value, &name); err != nil || strings.TrimSpace(name) == "" {
				writeSCIMError(w, http.StatusBadRequest, "invalidValue", "invalid displayName value")
				return
			}
			updated.Name = strings.TrimSpace(name)
		case lowerPath == "members":
			if opName == "remove" && len(op.Value) == 0 {
				currentMembers = nil
				membersChanged = true
				continue
			}
			var refs []scimMemberRef
			if err := json.Unmarshal(op.Value, &refs); err != nil {
				writeSCIMError(w, http.StatusBadRequest, "invalidValue", "invalid members value")
				return
			}
			switch opName {
			case "replace":
				currentMembers = extractMemberIDs(refs)
			case "add":
				currentMembers = mergeMemberIDs(currentMembers, refs)
			case "remove":
				currentMembers = removeMemberIDs(currentMembers, refs)
			default:
				writeSCIMError(w, http.StatusBadRequest, "invalidValue", fmt.Sprintf("unsupported patch op %q", op.Op))
				return
			}
			membersChanged = true
		case strings.HasPrefix(lowerPath, "members["):
			memberID, ok := extractMemberFilterValue(path)
			if !ok {
				writeSCIMError(w, http.StatusBadRequest, "invalidPath", fmt.Sprintf("unsupported member filter path %q", path))
				return
			}
			if opName == "remove" {
				currentMembers = removeMemberIDs(currentMembers, []scimMemberRef{{Value: memberID}})
				membersChanged = true
			} else {
				writeSCIMError(w, http.StatusBadRequest, "invalidValue", fmt.Sprintf("unsupported op %q for member filter path", op.Op))
				return
			}
		default:
			writeSCIMError(w, http.StatusBadRequest, "invalidPath", fmt.Sprintf("unsupported patch path %q", path))
			return
		}
	}

	if updated.Name != existing.Name {
		if scimRepo, ok := s.repo.(storage.SCIMRepository); ok && scimRepo != nil {
			if dup, dupErr := scimRepo.GetTeamByName(r.Context(), orgID, updated.Name); dupErr == nil && dup != nil && dup.ID != existing.ID {
				writeSCIMError(w, http.StatusConflict, "uniqueness", fmt.Sprintf("group %q already exists", updated.Name))
				return
			}
		}
	}
	if err := s.repo.UpdateTeam(r.Context(), &updated); err != nil {
		writeSCIMError(w, http.StatusBadRequest, "", err.Error())
		return
	}
	if membersChanged {
		refs := make([]scimMemberRef, 0, len(currentMembers))
		for _, id := range currentMembers {
			refs = append(refs, scimMemberRef{Value: id})
		}
		if err := s.syncSCIMGroupMembers(r.Context(), orgID, updated.ID, refs, true); err != nil {
			writeSCIMError(w, http.StatusBadRequest, "invalidValue", err.Error())
			return
		}
	}
	if s.authSvc != nil {
		s.authSvc.InvalidateTeam(r.Context(), updated.ID)
	}
	s.auditWithDiff(r.Context(), orgID, "scim.group.patched", "team", updated.ID, map[string]any{
		"name":         updated.Name,
		"member_count": len(currentMembers),
	}, existing, &updated)
	writeSCIMJSON(w, http.StatusOK, s.toSCIMGroup(r.Context(), orgID, &updated))
}

func (s *GatewayServer) handleSCIMDeleteGroup(w http.ResponseWriter, r *http.Request) {
	orgID := scimOrgFromContext(r.Context())
	teamID := strings.TrimSpace(chi.URLParam(r, "id"))
	existing, err := s.repo.GetTeam(r.Context(), teamID)
	if err != nil || existing == nil || existing.OrgID != orgID {
		writeSCIMError(w, http.StatusNotFound, "", "Group not found")
		return
	}

	keys, err := s.repo.ListVirtualKeys(r.Context(), orgID)
	if err != nil {
		writeSCIMError(w, http.StatusInternalServerError, "", err.Error())
		return
	}
	now := time.Now().UTC()
	for _, vk := range keys {
		if vk != nil && vk.TeamID == existing.ID && isVirtualKeyActive(vk, now) {
			writeSCIMError(w, http.StatusConflict, "", "Cannot delete group while it still has active virtual keys")
			return
		}
	}

	if err := s.repo.DeleteTeam(r.Context(), existing.ID); err != nil {
		if errors.Is(err, storage.ErrConflict) {
			writeSCIMError(w, http.StatusConflict, "", err.Error())
			return
		}
		writeSCIMError(w, http.StatusInternalServerError, "", err.Error())
		return
	}
	if users, uErr := s.repo.ListUsers(r.Context(), orgID); uErr == nil {
		pmRepo, hasPM := s.repo.(storage.ProjectAndMembershipRepository)
		for _, u := range users {
			if u == nil || u.OrgID != orgID || u.TeamID != existing.ID {
				continue
			}
			cp := *u
			cp.TeamID = ""
			if hasPM && pmRepo != nil {
				if ms, mErr := pmRepo.ListTeamMemberships(r.Context(), orgID, "", u.ID); mErr == nil {
					for _, m := range ms {
						if m != nil && m.TeamID != existing.ID {
							cp.TeamID = m.TeamID
							break
						}
					}
				}
			}
			_ = s.repo.UpdateUser(r.Context(), &cp)
		}
	}
	if s.authSvc != nil {
		s.authSvc.InvalidateTeam(r.Context(), existing.ID)
		s.authSvc.InvalidateOrg(r.Context(), orgID)
	}
	s.auditWithDiff(r.Context(), orgID, "scim.group.deleted", "team", existing.ID, map[string]any{
		"name": existing.Name,
	}, existing, nil)
	w.WriteHeader(http.StatusNoContent)
}

// --- SCIM Helpers ---

func (s *GatewayServer) toSCIMUser(ctx context.Context, orgID string, u *domain.User) scimUserResource {
	var groups []scimGroupRef
	seenTeams := make(map[string]struct{})
	addTeam := func(teamID string) {
		if teamID == "" {
			return
		}
		if _, exists := seenTeams[teamID]; exists {
			return
		}
		seenTeams[teamID] = struct{}{}
		display := teamID
		if team, err := s.repo.GetTeam(ctx, teamID); err == nil && team != nil && team.OrgID == orgID {
			display = team.Name
		}
		groups = append(groups, scimGroupRef{
			Value:   teamID,
			Display: display,
			Ref:     "/scim/v2/Groups/" + teamID,
		})
	}
	addTeam(u.TeamID)
	if pmRepo, ok := s.repo.(storage.ProjectAndMembershipRepository); ok && pmRepo != nil {
		if memberships, err := pmRepo.ListTeamMemberships(ctx, orgID, "", u.ID); err == nil {
			for _, m := range memberships {
				if m != nil {
					addTeam(m.TeamID)
				}
			}
		}
	}

	var nameObj *scimName
	if u.Name != "" {
		nameObj = &scimName{Formatted: u.Name}
	}
	var emails []scimEmail
	if u.Email != "" {
		emails = []scimEmail{{Value: u.Email, Type: "work", Primary: true}}
	}
	return scimUserResource{
		Schemas:     []string{scimSchemaUser},
		ID:          u.ID,
		ExternalID:  u.SCIMExternalID,
		UserName:    u.Email,
		Name:        nameObj,
		DisplayName: u.Name,
		Emails:      emails,
		Active:      u.IsActive && u.SCIMActive,
		Groups:      groups,
		Roles:       []scimRoleRef{{Value: string(u.Role), Primary: true}},
		Meta: scimMeta{
			ResourceType: "User",
			Created:      formatSCIMTime(u.CreatedAt),
			LastModified: formatSCIMTime(u.UpdatedAt),
			Location:     "/scim/v2/Users/" + u.ID,
		},
	}
}

func (s *GatewayServer) toSCIMGroup(ctx context.Context, orgID string, t *domain.Team) scimGroupResource {
	memberIDs := s.collectGroupMemberIDs(ctx, orgID, t.ID)
	members := make([]scimMemberRef, 0, len(memberIDs))
	for _, uid := range memberIDs {
		display := uid
		if u, err := s.lookupUserByID(ctx, uid); err == nil && u != nil && u.OrgID == orgID {
			if u.Name != "" {
				display = u.Name
			} else if u.Email != "" {
				display = u.Email
			}
		}
		members = append(members, scimMemberRef{
			Value:   uid,
			Display: display,
			Ref:     "/scim/v2/Users/" + uid,
		})
	}
	return scimGroupResource{
		Schemas:     []string{scimSchemaGroup},
		ID:          t.ID,
		DisplayName: t.Name,
		Members:     members,
		Meta: scimMeta{
			ResourceType: "Group",
			Created:      formatSCIMTime(t.CreatedAt),
			LastModified: formatSCIMTime(t.UpdatedAt),
			Location:     "/scim/v2/Groups/" + t.ID,
		},
	}
}

func (s *GatewayServer) collectGroupMemberIDs(ctx context.Context, orgID, teamID string) []string {
	seen := make(map[string]struct{})
	var ids []string
	add := func(uid string) {
		uid = strings.TrimSpace(uid)
		if uid == "" {
			return
		}
		if _, ok := seen[uid]; !ok {
			seen[uid] = struct{}{}
			ids = append(ids, uid)
		}
	}
	if pmRepo, ok := s.repo.(storage.ProjectAndMembershipRepository); ok && pmRepo != nil {
		if memberships, err := pmRepo.ListTeamMemberships(ctx, orgID, teamID, ""); err == nil {
			for _, m := range memberships {
				if m != nil && m.OrgID == orgID && m.TeamID == teamID {
					add(m.UserID)
				}
			}
		}
	}
	if users, err := s.repo.ListUsers(ctx, orgID); err == nil {
		for _, u := range users {
			if u != nil && u.OrgID == orgID && u.TeamID == teamID {
				add(u.ID)
			}
		}
	}
	return ids
}

func (s *GatewayServer) syncSCIMGroupMembers(ctx context.Context, orgID, teamID string, desiredRefs []scimMemberRef, replace bool) error {
	desired := make(map[string]struct{}, len(desiredRefs))
	desiredUsers := make([]*domain.User, 0, len(desiredRefs))
	for _, ref := range desiredRefs {
		uid := strings.TrimSpace(ref.Value)
		if uid == "" {
			continue
		}
		if _, dup := desired[uid]; dup {
			continue
		}
		u, err := s.lookupSCIMUser(ctx, orgID, uid)
		if err != nil || u == nil || u.OrgID != orgID {
			return fmt.Errorf("member user %q not found in organization", uid)
		}
		desired[u.ID] = struct{}{}
		desiredUsers = append(desiredUsers, u)
	}

	pmRepo, hasPM := s.repo.(storage.ProjectAndMembershipRepository)

	if replace {
		existingIDs := s.collectGroupMemberIDs(ctx, orgID, teamID)
		for _, uid := range existingIDs {
			if _, keep := desired[uid]; keep {
				continue
			}
			if hasPM && pmRepo != nil {
				_ = pmRepo.DeleteTeamMembership(ctx, teamID, uid)
			}
			if u, err := s.lookupUserByID(ctx, uid); err == nil && u != nil && u.OrgID == orgID && u.TeamID == teamID {
				cp := *u
				cp.TeamID = ""
				if hasPM && pmRepo != nil {
					if ms, mErr := pmRepo.ListTeamMemberships(ctx, orgID, "", uid); mErr == nil {
						for _, m := range ms {
							if m != nil && m.TeamID != teamID {
								cp.TeamID = m.TeamID
								break
							}
						}
					}
				}
				_ = s.repo.UpdateUser(ctx, &cp)
			}
		}
	}

	for _, u := range desiredUsers {
		if hasPM && pmRepo != nil {
			role := u.Role
			if role == "" {
				role = domain.RoleDeveloper
			}
			if existingM, err := pmRepo.GetTeamMembership(ctx, teamID, u.ID); err != nil || existingM == nil {
				if err := pmRepo.UpsertTeamMembership(ctx, &domain.TeamMembership{
					OrgID:  orgID,
					TeamID: teamID,
					UserID: u.ID,
					Role:   role,
				}); err != nil {
					return err
				}
			}
		}
		if u.TeamID == "" {
			cp := *u
			cp.TeamID = teamID
			if err := s.repo.UpdateUser(ctx, &cp); err != nil {
				return err
			}
		}
	}
	return nil
}

func applySCIMUserPatchOp(u *domain.User, op scimPatchOpDetail, caller *domain.OperatorContext) error {
	opName := strings.ToLower(strings.TrimSpace(op.Op))
	if opName != "replace" && opName != "add" && opName != "remove" {
		return fmt.Errorf("unsupported patch op %q", op.Op)
	}
	path := strings.TrimSpace(op.Path)
	lowerPath := strings.ToLower(path)

	if path == "" {
		var body map[string]json.RawMessage
		if err := json.Unmarshal(op.Value, &body); err != nil {
			return fmt.Errorf("invalid patch value object")
		}
		if rawActive, ok := body["active"]; ok {
			b, err := parseSCIMBool(rawActive)
			if err != nil {
				return err
			}
			u.SCIMActive = b
			u.IsActive = b
		}
		if rawExt, ok := body["externalId"]; ok {
			var s string
			if err := json.Unmarshal(rawExt, &s); err != nil {
				return fmt.Errorf("invalid externalId")
			}
			u.SCIMExternalID = strings.TrimSpace(s)
		}
		if rawUserName, ok := body["userName"]; ok {
			var s string
			if err := json.Unmarshal(rawUserName, &s); err != nil || strings.TrimSpace(s) == "" {
				return fmt.Errorf("invalid userName")
			}
			u.Email = strings.TrimSpace(s)
		}
		if rawDisplay, ok := body["displayName"]; ok {
			var s string
			if err := json.Unmarshal(rawDisplay, &s); err != nil {
				return fmt.Errorf("invalid displayName")
			}
			u.Name = strings.TrimSpace(s)
		}
		if rawName, ok := body["name"]; ok {
			var n scimName
			if err := json.Unmarshal(rawName, &n); err != nil {
				return fmt.Errorf("invalid name")
			}
			if dn := extractSCIMDisplayName("", &n, ""); dn != "" {
				u.Name = dn
			}
		}
		if rawEmails, ok := body["emails"]; ok {
			var emails []scimEmail
			if err := json.Unmarshal(rawEmails, &emails); err != nil {
				return fmt.Errorf("invalid emails")
			}
			if em := extractSCIMPrimaryEmail(emails, ""); em != "" {
				u.Email = em
			}
		}
		if rawRoles, ok := body["roles"]; ok {
			var roles []scimRoleRef
			if err := json.Unmarshal(rawRoles, &roles); err != nil {
				return fmt.Errorf("invalid roles")
			}
			u.Role = resolveSCIMUserRole(roles, caller, u.Role)
		}
		return nil
	}

	switch {
	case lowerPath == "active":
		if opName == "remove" {
			u.SCIMActive = false
			u.IsActive = false
			return nil
		}
		b, err := parseSCIMBool(op.Value)
		if err != nil {
			return err
		}
		u.SCIMActive = b
		u.IsActive = b
	case lowerPath == "externalid":
		if opName == "remove" {
			u.SCIMExternalID = ""
			return nil
		}
		var s string
		if err := json.Unmarshal(op.Value, &s); err != nil {
			return fmt.Errorf("invalid externalId")
		}
		u.SCIMExternalID = strings.TrimSpace(s)
	case lowerPath == "username":
		var s string
		if err := json.Unmarshal(op.Value, &s); err != nil || strings.TrimSpace(s) == "" {
			return fmt.Errorf("invalid userName")
		}
		u.Email = strings.TrimSpace(s)
	case lowerPath == "displayname" || lowerPath == "name.formatted":
		var s string
		if err := json.Unmarshal(op.Value, &s); err != nil {
			return fmt.Errorf("invalid displayName")
		}
		u.Name = strings.TrimSpace(s)
	case lowerPath == "name":
		var n scimName
		if err := json.Unmarshal(op.Value, &n); err != nil {
			return fmt.Errorf("invalid name")
		}
		if dn := extractSCIMDisplayName("", &n, ""); dn != "" {
			u.Name = dn
		}
	case lowerPath == "emails":
		var emails []scimEmail
		if err := json.Unmarshal(op.Value, &emails); err != nil {
			return fmt.Errorf("invalid emails")
		}
		if em := extractSCIMPrimaryEmail(emails, ""); em != "" {
			u.Email = em
		}
	case lowerPath == "emails.value" || strings.HasPrefix(lowerPath, "emails["):
		var s string
		if err := json.Unmarshal(op.Value, &s); err != nil || strings.TrimSpace(s) == "" {
			return fmt.Errorf("invalid email value")
		}
		u.Email = strings.TrimSpace(s)
	case lowerPath == "roles":
		var roles []scimRoleRef
		if err := json.Unmarshal(op.Value, &roles); err != nil {
			return fmt.Errorf("invalid roles")
		}
		u.Role = resolveSCIMUserRole(roles, caller, u.Role)
	default:
		return fmt.Errorf("unsupported patch path %q", path)
	}
	return nil
}

func parseSCIMBool(raw json.RawMessage) (bool, error) {
	var b bool
	if err := json.Unmarshal(raw, &b); err == nil {
		return b, nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		switch strings.ToLower(strings.TrimSpace(s)) {
		case "true":
			return true, nil
		case "false":
			return false, nil
		}
	}
	return false, fmt.Errorf("invalid boolean value")
}

func extractSCIMPrimaryEmail(emails []scimEmail, userName string) string {
	for _, em := range emails {
		if em.Primary && strings.TrimSpace(em.Value) != "" {
			return strings.TrimSpace(em.Value)
		}
	}
	for _, em := range emails {
		if strings.TrimSpace(em.Value) != "" {
			return strings.TrimSpace(em.Value)
		}
	}
	return strings.TrimSpace(userName)
}

func extractSCIMDisplayName(displayName string, name *scimName, fallback string) string {
	if strings.TrimSpace(displayName) != "" {
		return strings.TrimSpace(displayName)
	}
	if name != nil {
		if strings.TrimSpace(name.Formatted) != "" {
			return strings.TrimSpace(name.Formatted)
		}
		combined := strings.TrimSpace(strings.TrimSpace(name.GivenName) + " " + strings.TrimSpace(name.FamilyName))
		if combined != "" {
			return combined
		}
	}
	return strings.TrimSpace(fallback)
}

func resolveSCIMUserRole(roles []scimRoleRef, caller *domain.OperatorContext, fallback domain.Role) domain.Role {
	for _, r := range roles {
		candidate := domain.Role(strings.ToLower(strings.TrimSpace(r.Value)))
		switch candidate {
		case domain.RolePlatformAdmin:
			if caller != nil && caller.Role == domain.OperatorRolePlatformAdmin {
				return candidate
			}
		case domain.RoleOrgAdmin, domain.RoleOrgViewer, domain.RoleTeamAdmin, domain.RoleDeveloper, domain.RoleServiceAccount, domain.RoleViewer:
			return candidate
		}
	}
	if fallback != "" {
		return fallback
	}
	return domain.RoleDeveloper
}

func formatSCIMTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

var scimEqFilterRe = regexp.MustCompile(`^\s*([a-zA-Z0-9_.\[\]"\s=]+?)\s+[eE][qQ]\s+(?:"([^"]*)"|(true|false))\s*$`)

func parseSCIMEqFilter(filter string) (attr string, val string, ok bool) {
	m := scimEqFilterRe.FindStringSubmatch(filter)
	if len(m) != 4 {
		return "", "", false
	}
	attr = strings.ToLower(strings.TrimSpace(m[1]))
	if m[3] != "" {
		val = strings.ToLower(m[3])
	} else {
		val = m[2]
	}
	return attr, val, true
}

func scimUserMatchesFilter(u *domain.User, attr, val string) bool {
	switch {
	case attr == "username" || attr == "emails.value" || strings.HasPrefix(attr, "emails["):
		return strings.EqualFold(u.Email, val)
	case attr == "externalid":
		return u.SCIMExternalID != "" && u.SCIMExternalID == val
	case attr == "id":
		return u.ID == val
	case attr == "active":
		active := u.IsActive && u.SCIMActive
		return strconv.FormatBool(active) == strings.ToLower(val)
	case attr == "displayname":
		return strings.EqualFold(u.Name, val)
	default:
		return false
	}
}

func scimGroupMatchesFilter(t *domain.Team, attr, val string) bool {
	switch attr {
	case "displayname":
		return t.Name == val || strings.EqualFold(t.Name, val)
	case "id":
		return t.ID == val
	default:
		return false
	}
}

func paginateSCIMSlice[T any](items []T, r *http.Request) (total, startIndex int, page []T) {
	total = len(items)
	startIndex = 1
	if raw := strings.TrimSpace(r.URL.Query().Get("startIndex")); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil && v >= 1 {
			startIndex = v
		}
	}
	count := 100
	if raw := strings.TrimSpace(r.URL.Query().Get("count")); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil {
			if v < 0 {
				v = 0
			}
			if v > 500 {
				v = 500
			}
			count = v
		}
	}
	offset := startIndex - 1
	if offset >= total || count == 0 {
		return total, startIndex, nil
	}
	end := offset + count
	if end > total {
		end = total
	}
	return total, startIndex, items[offset:end]
}

func extractMemberIDs(refs []scimMemberRef) []string {
	seen := make(map[string]struct{}, len(refs))
	var out []string
	for _, r := range refs {
		id := strings.TrimSpace(r.Value)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; !ok {
			seen[id] = struct{}{}
			out = append(out, id)
		}
	}
	return out
}

func mergeMemberIDs(existing []string, add []scimMemberRef) []string {
	seen := make(map[string]struct{}, len(existing)+len(add))
	out := make([]string, 0, len(existing)+len(add))
	for _, id := range existing {
		if _, ok := seen[id]; !ok {
			seen[id] = struct{}{}
			out = append(out, id)
		}
	}
	for _, r := range add {
		id := strings.TrimSpace(r.Value)
		if id == "" {
			continue
		}
		if _, ok := seen[id]; !ok {
			seen[id] = struct{}{}
			out = append(out, id)
		}
	}
	return out
}

func removeMemberIDs(existing []string, rem []scimMemberRef) []string {
	drop := make(map[string]struct{}, len(rem))
	for _, r := range rem {
		id := strings.TrimSpace(r.Value)
		if id != "" {
			drop[id] = struct{}{}
		}
	}
	var out []string
	for _, id := range existing {
		if _, ok := drop[id]; !ok {
			out = append(out, id)
		}
	}
	return out
}

var scimMemberFilterRe = regexp.MustCompile(`(?i)^members\[\s*value\s+eq\s+"([^"]+)"\s*\]$`)

func extractMemberFilterValue(path string) (string, bool) {
	m := scimMemberFilterRe.FindStringSubmatch(strings.TrimSpace(path))
	if len(m) != 2 {
		return "", false
	}
	return strings.TrimSpace(m[1]), true
}
