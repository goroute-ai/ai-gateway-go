package auth

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

const (
	// HeaderImpersonateUser specifies the target user ID for Control Plane operator impersonation.
	HeaderImpersonateUser = "X-Gateway-Impersonate-User"
	// HeaderImpersonateEmail specifies the target user email for Control Plane operator impersonation.
	HeaderImpersonateEmail = "X-Gateway-Impersonate-Email"
	// HeaderDelegatedUserID specifies the delegated user ID for Data Plane permission narrowing.
	HeaderDelegatedUserID = "X-Gateway-Delegated-User-Id"
	// HeaderDelegatedTeamID specifies the delegated team ID for Data Plane permission narrowing.
	HeaderDelegatedTeamID = "X-Gateway-Delegated-Team-Id"

	base64UTF8Prefix   = "base64-utf8:"
	denyAllModelMarker = "\x00__gw_deny_all__"
)

// DecodeHeaderValue decodes an optional `base64-utf8:<b64>` header value into a trimmed UTF-8 string.
func DecodeHeaderValue(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", nil
	}
	if len(trimmed) >= len(base64UTF8Prefix) && strings.EqualFold(trimmed[:len(base64UTF8Prefix)], base64UTF8Prefix) {
		encoded := strings.TrimSpace(trimmed[len(base64UTF8Prefix):])
		if encoded == "" {
			return "", &domain.GatewayError{
				StatusCode: http.StatusBadRequest,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "invalid_header_encoding",
				Message:    "Empty base64-utf8 header payload",
			}
		}
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			decoded, err = base64.RawStdEncoding.DecodeString(encoded)
		}
		if err != nil || !utf8.Valid(decoded) {
			return "", &domain.GatewayError{
				StatusCode: http.StatusBadRequest,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "invalid_header_encoding",
				Message:    "Invalid base64-utf8 header encoding",
			}
		}
		return strings.TrimSpace(string(decoded)), nil
	}
	return trimmed, nil
}

// ResolveImpersonatedOperator applies Control Plane (/admin/v1/*) operator impersonation
// when X-Gateway-Impersonate-User or X-Gateway-Impersonate-Email is supplied by a Master Admin Key
// or a Virtual Key with CanImpersonate == true.
func (s *Service) ResolveImpersonatedOperator(ctx context.Context, op *domain.OperatorContext, r *http.Request) (*domain.OperatorContext, error) {
	if s == nil || op == nil || r == nil {
		return op, nil
	}
	targetUserID, err := DecodeHeaderValue(r.Header.Get(HeaderImpersonateUser))
	if err != nil {
		return nil, err
	}
	targetEmail, err := DecodeHeaderValue(r.Header.Get(HeaderImpersonateEmail))
	if err != nil {
		return nil, err
	}
	if targetUserID == "" && targetEmail == "" {
		return op, nil
	}

	canImpersonate := op.AuthMethod == "master_key" || (op.AuthMethod == "virtual_key" && op.CanImpersonate)
	if !canImpersonate {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusForbidden,
			Type:       domain.ErrorTypePermission,
			Code:       "impersonation_not_allowed",
			Message:    "Caller credential is not authorized to impersonate users",
		}
	}
	if s.repo == nil {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusServiceUnavailable,
			Type:       domain.ErrorTypeServer,
			Code:       "auth_repository_unavailable",
			Message:    "Identity repository is not configured",
		}
	}

	var user *domain.User
	if targetUserID != "" {
		u, uErr := lookupUserByIDAnyOrg(ctx, s.repo, targetUserID)
		if uErr != nil {
			if errors.Is(uErr, storage.ErrNotFound) || strings.Contains(strings.ToLower(uErr.Error()), "not found") {
				return nil, &domain.GatewayError{
					StatusCode: http.StatusNotFound,
					Type:       domain.ErrorTypeNotFound,
					Code:       "user_not_found",
					Message:    "Impersonation target user was not found",
				}
			}
			return nil, &domain.GatewayError{
				StatusCode: http.StatusServiceUnavailable,
				Type:       domain.ErrorTypeServer,
				Code:       "user_lookup_unavailable",
				Message:    "Unable to resolve impersonation target user",
				Retryable:  true,
			}
		}
		user = u
	}
	if targetEmail != "" {
		byEmail, eErr := lookupUserByEmailAnyOrg(ctx, s.repo, op.OrgID, targetEmail)
		if eErr != nil {
			if errors.Is(eErr, storage.ErrNotFound) || strings.Contains(strings.ToLower(eErr.Error()), "not found") {
				return nil, &domain.GatewayError{
					StatusCode: http.StatusNotFound,
					Type:       domain.ErrorTypeNotFound,
					Code:       "user_not_found",
					Message:    "Impersonation target user email was not found",
				}
			}
			return nil, &domain.GatewayError{
				StatusCode: http.StatusServiceUnavailable,
				Type:       domain.ErrorTypeServer,
				Code:       "user_lookup_unavailable",
				Message:    "Unable to resolve impersonation target email",
				Retryable:  true,
			}
		}
		if user != nil && user.ID != byEmail.ID {
			return nil, &domain.GatewayError{
				StatusCode: http.StatusBadRequest,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "impersonation_target_mismatch",
				Message:    "Impersonation user ID and email refer to different users",
			}
		}
		user = byEmail
	}
	if user == nil {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusNotFound,
			Type:       domain.ErrorTypeNotFound,
			Code:       "user_not_found",
			Message:    "Impersonation target user was not found",
		}
	}
	if op.OrgID != "" && user.OrgID != op.OrgID {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusForbidden,
			Type:       domain.ErrorTypePermission,
			Code:       "cross_org_access_denied",
			Message:    "Cannot impersonate a user in another organization",
		}
	}

	org, err := s.repo.GetOrganization(ctx, user.OrgID)
	if err != nil || org == nil || !org.IsActive {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusForbidden,
			Type:       domain.ErrorTypePermission,
			Code:       "organization_inactive",
			Message:    "Organization associated with impersonation target user is inactive",
		}
	}
	if !user.IsActive {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusForbidden,
			Type:       domain.ErrorTypePermission,
			Code:       "user_inactive",
			Message:    "Impersonation target user is inactive",
		}
	}
	if !user.SCIMActive {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusForbidden,
			Type:       domain.ErrorTypePermission,
			Code:       "scim_deprovisioned",
			Message:    "Impersonation target user has been deprovisioned via SCIM",
		}
	}

	targetRole, ok := s.MapDomainRoleToOperatorRole(user.Role)
	targetTeamID := user.TeamID
	if !ok || (targetRole == domain.OperatorRoleTeamAdmin && targetTeamID == "") {
		if pmRepo, pmOK := s.repo.(storage.ProjectAndMembershipRepository); pmOK && pmRepo != nil {
			if memberships, mErr := pmRepo.ListTeamMemberships(ctx, user.OrgID, "", user.ID); mErr == nil {
				for _, m := range memberships {
					if m != nil && m.Role == domain.RoleTeamAdmin {
						targetRole = domain.OperatorRoleTeamAdmin
						targetTeamID = m.TeamID
						ok = true
						break
					}
				}
			}
		}
	}
	if !ok {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusForbidden,
			Type:       domain.ErrorTypePermission,
			Code:       "insufficient_permissions",
			Message:    fmt.Sprintf("Target user role %q is not authorized for control plane access", user.Role),
		}
	}
	if err := authorizeImpersonationRole(op, targetRole, targetTeamID); err != nil {
		return nil, err
	}
	if targetRole == domain.OperatorRoleTeamAdmin && targetTeamID != "" {
		if team, teamErr := s.repo.GetTeam(ctx, targetTeamID); teamErr == nil && team != nil {
			if team.OrgID != user.OrgID {
				return nil, &domain.GatewayError{
					StatusCode: http.StatusForbidden,
					Type:       domain.ErrorTypePermission,
					Code:       "team_org_mismatch",
					Message:    "Target user's team does not belong to its organization",
				}
			}
			if !team.IsActive {
				return nil, &domain.GatewayError{
					StatusCode: http.StatusForbidden,
					Type:       domain.ErrorTypePermission,
					Code:       "team_inactive",
					Message:    "Target user's team is inactive",
				}
			}
		}
	}

	impersonated := &domain.OperatorContext{
		ActorID:               user.ID,
		ImpersonatedByActorID: op.ActorID,
		Role:                  targetRole,
		OrgID:                 user.OrgID,
		TeamID:                targetTeamID,
		AuthMethod:            op.AuthMethod,
		CanImpersonate:        false,
		DeprecatedKeyRevokeAt: op.DeprecatedKeyRevokeAt,
	}

	_ = s.repo.RecordAuditLog(ctx, &domain.AuditLog{
		OrgID:      user.OrgID,
		ActorID:    user.ID,
		Action:     "operator.impersonated",
		Resource:   "user",
		ResourceID: user.ID,
		Details: map[string]any{
			"actor_id":        user.ID,
			"impersonated_by": op.ActorID,
			"auth_method":     op.AuthMethod,
			"role":            string(targetRole),
			"method":          r.Method,
			"path":            r.URL.Path,
		},
	})

	return impersonated, nil
}

func authorizeImpersonationRole(caller *domain.OperatorContext, targetRole domain.OperatorRole, targetTeamID string) error {
	switch caller.Role {
	case domain.OperatorRolePlatformAdmin:
		return nil
	case domain.OperatorRoleOrgAdmin:
		if targetRole == domain.OperatorRolePlatformAdmin {
			return &domain.GatewayError{
				StatusCode: http.StatusForbidden,
				Type:       domain.ErrorTypePermission,
				Code:       "platform_admin_required",
				Message:    "org_admin cannot impersonate a platform_admin user",
			}
		}
		return nil
	case domain.OperatorRoleTeamAdmin:
		if targetRole != domain.OperatorRoleTeamAdmin {
			return &domain.GatewayError{
				StatusCode: http.StatusForbidden,
				Type:       domain.ErrorTypePermission,
				Code:       "insufficient_permissions",
				Message:    "team_admin cannot impersonate users with broader roles",
			}
		}
		if caller.TeamID == "" || targetTeamID == "" || caller.TeamID != targetTeamID {
			return &domain.GatewayError{
				StatusCode: http.StatusForbidden,
				Type:       domain.ErrorTypePermission,
				Code:       "cross_team_access_denied",
				Message:    "team_admin cannot impersonate users outside their own team",
			}
		}
		return nil
	case domain.OperatorRoleOrgViewer:
		if targetRole != domain.OperatorRoleOrgViewer {
			return &domain.GatewayError{
				StatusCode: http.StatusForbidden,
				Type:       domain.ErrorTypePermission,
				Code:       "insufficient_permissions",
				Message:    "org_viewer cannot impersonate users with write roles",
			}
		}
		return nil
	default:
		return &domain.GatewayError{
			StatusCode: http.StatusForbidden,
			Type:       domain.ErrorTypePermission,
			Code:       "insufficient_permissions",
			Message:    "Caller role is not authorized to impersonate users",
		}
	}
}

// ApplyDelegatedCallerNarrowing narrows a Data Plane IdentityContext when
// X-Gateway-Delegated-User-Id and/or X-Gateway-Delegated-Team-Id are supplied.
// Permissions and ceilings can only be narrowed (strict intersection / min), never widened.
func ApplyDelegatedCallerNarrowing(ctx context.Context, repo storage.Repository, idCtx *domain.IdentityContext, r *http.Request) (*domain.IdentityContext, error) {
	if idCtx == nil || r == nil {
		return idCtx, nil
	}
	delegatedUserID, err := DecodeHeaderValue(r.Header.Get(HeaderDelegatedUserID))
	if err != nil {
		return nil, err
	}
	delegatedTeamID, err := DecodeHeaderValue(r.Header.Get(HeaderDelegatedTeamID))
	if err != nil {
		return nil, err
	}
	if delegatedUserID == "" && delegatedTeamID == "" {
		return idCtx, nil
	}
	if repo == nil {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusServiceUnavailable,
			Type:       domain.ErrorTypeServer,
			Code:       "auth_repository_unavailable",
			Message:    "Identity repository is not configured",
		}
	}

	var delegatedUser *domain.User
	if delegatedUserID != "" {
		u, uErr := lookupUserByIDAnyOrg(ctx, repo, delegatedUserID)
		if uErr != nil {
			if errors.Is(uErr, storage.ErrNotFound) || strings.Contains(strings.ToLower(uErr.Error()), "not found") {
				return nil, &domain.GatewayError{
					StatusCode: http.StatusForbidden,
					Type:       domain.ErrorTypePermission,
					Code:       "delegated_user_not_found",
					Message:    "Delegated user was not found",
				}
			}
			return nil, &domain.GatewayError{
				StatusCode: http.StatusServiceUnavailable,
				Type:       domain.ErrorTypeServer,
				Code:       "user_lookup_unavailable",
				Message:    "Unable to resolve delegated user identity",
				Retryable:  true,
			}
		}
		if u.OrgID != idCtx.OrgID {
			return nil, &domain.GatewayError{
				StatusCode: http.StatusForbidden,
				Type:       domain.ErrorTypePermission,
				Code:       "cross_org_access_denied",
				Message:    "Delegated user does not belong to caller organization",
			}
		}
		if !u.IsActive {
			return nil, &domain.GatewayError{
				StatusCode: http.StatusForbidden,
				Type:       domain.ErrorTypePermission,
				Code:       "user_inactive",
				Message:    "Delegated user is inactive",
			}
		}
		if !u.SCIMActive {
			return nil, &domain.GatewayError{
				StatusCode: http.StatusForbidden,
				Type:       domain.ErrorTypePermission,
				Code:       "scim_deprovisioned",
				Message:    "Delegated user has been deprovisioned via SCIM",
			}
		}
		delegatedUser = u
	}

	var delegatedTeam *domain.Team
	if delegatedTeamID != "" {
		team, tErr := repo.GetTeam(ctx, delegatedTeamID)
		if tErr != nil || team == nil {
			if tErr == nil || errors.Is(tErr, storage.ErrNotFound) || strings.Contains(strings.ToLower(tErr.Error()), "not found") {
				return nil, &domain.GatewayError{
					StatusCode: http.StatusForbidden,
					Type:       domain.ErrorTypePermission,
					Code:       "delegated_team_not_found",
					Message:    "Delegated team was not found",
				}
			}
			return nil, &domain.GatewayError{
				StatusCode: http.StatusServiceUnavailable,
				Type:       domain.ErrorTypeServer,
				Code:       "team_policy_unavailable",
				Message:    "Unable to resolve delegated team policy",
				Retryable:  true,
			}
		}
		if team.OrgID != idCtx.OrgID {
			return nil, &domain.GatewayError{
				StatusCode: http.StatusForbidden,
				Type:       domain.ErrorTypePermission,
				Code:       "cross_org_access_denied",
				Message:    "Delegated team does not belong to caller organization",
			}
		}
		if !team.IsActive {
			return nil, &domain.GatewayError{
				StatusCode: http.StatusForbidden,
				Type:       domain.ErrorTypePermission,
				Code:       "team_inactive",
				Message:    "Delegated team is inactive",
			}
		}
		delegatedTeam = team
	}

	out := cloneIdentityContext(idCtx)
	// Prevent dynamic access rules from re-widening a narrowed delegated request.
	out.DynamicAllowedModels = nil

	if delegatedTeam != nil {
		out.DelegatedTeamID = delegatedTeam.ID
		out.TeamID = delegatedTeam.ID
		if delegatedTeam.MinPriorityRank > out.TeamMinPriorityRank {
			out.TeamMinPriorityRank = delegatedTeam.MinPriorityRank
		}
		if len(delegatedTeam.AllowedRoutingTags) > 0 {
			out.TeamAllowedRoutingTags = intersectModelAllowlists(out.TeamAllowedRoutingTags, delegatedTeam.AllowedRoutingTags)
			if len(out.KeyAllowedRoutingTags) > 0 {
				out.KeyAllowedRoutingTags = intersectModelAllowlists(out.KeyAllowedRoutingTags, delegatedTeam.AllowedRoutingTags)
			}
		}

		if len(delegatedTeam.AllowedModels) > 0 {
			out.TeamAllowedModels = intersectModelAllowlists(out.TeamAllowedModels, delegatedTeam.AllowedModels)
			if len(out.KeyAllowedModels) > 0 {
				out.KeyAllowedModels = intersectModelAllowlists(out.KeyAllowedModels, delegatedTeam.AllowedModels)
			}
		}

		mcpEffective := intersect3StateAllowlists(
			effective3StateAllowlist(out.KeyAllowedMCPServers, out.TeamAllowedMCPServers),
			delegatedTeam.AllowedMCPServers,
		)
		if mcpEffective != nil {
			out.KeyAllowedMCPServers = slices.Clone(mcpEffective)
			out.TeamAllowedMCPServers = slices.Clone(mcpEffective)
		}

		a2aEffective := intersect3StateAllowlists(
			effective3StateAllowlist(out.KeyAllowedA2AAgents, out.TeamAllowedA2AAgents),
			delegatedTeam.AllowedA2AAgents,
		)
		if a2aEffective != nil {
			out.KeyAllowedA2AAgents = slices.Clone(a2aEffective)
			out.TeamAllowedA2AAgents = slices.Clone(a2aEffective)
		}

		appEffective := intersect3StateAllowlists(
			effective3StateAllowlist(out.KeyAllowedClientApps, out.TeamAllowedClientApps),
			delegatedTeam.AllowedClientApps,
		)
		if appEffective != nil {
			out.KeyAllowedClientApps = slices.Clone(appEffective)
			out.TeamAllowedClientApps = slices.Clone(appEffective)
		}

		out.TeamRPMLimit = minPositiveInt(out.KeyRPMLimit, out.TeamRPMLimit, delegatedTeam.RPMLimit)
		out.TeamTPMLimit = minPositiveInt(out.KeyTPMLimit, out.TeamTPMLimit, delegatedTeam.TPMLimit)
		out.TeamMaxConcurrent = minPositiveInt(out.KeyMaxConcurrent, out.TeamMaxConcurrent, delegatedTeam.MaxConcurrentRequests)
		out.TeamBatchEnqueuedTokenLimit = minPositiveInt64(out.KeyBatchEnqueuedTokenLimit, out.TeamBatchEnqueuedTokenLimit, delegatedTeam.BatchEnqueuedTokenLimit)
		out.TeamMaxBudgetMicros, out.TeamSpentMicros = narrowBudgetScope(
			out.KeyMaxBudgetMicros, out.KeySpentMicros,
			out.TeamMaxBudgetMicros, out.TeamSpentMicros,
			delegatedTeam.MaxBudgetMicros, delegatedTeam.SpentMicros,
		)
	}

	if delegatedUser != nil {
		out.DelegatedUserID = delegatedUser.ID
		out.UserID = delegatedUser.ID
		out.SCIMActive = out.SCIMActive && delegatedUser.SCIMActive

		out.UserRPMLimit = minPositiveInt(out.KeyRPMLimit, out.UserRPMLimit, delegatedUser.RPMLimit)
		out.UserTPMLimit = minPositiveInt(out.KeyTPMLimit, out.UserTPMLimit, delegatedUser.TPMLimit)
		out.UserMaxConcurrent = minPositiveInt(out.KeyMaxConcurrent, out.UserMaxConcurrent, delegatedUser.MaxConcurrentRequests)
		out.UserBatchEnqueuedTokenLimit = minPositiveInt64(out.KeyBatchEnqueuedTokenLimit, out.UserBatchEnqueuedTokenLimit, delegatedUser.BatchEnqueuedTokenLimit)
		out.UserMaxBudgetMicros, out.UserSpentMicros = narrowBudgetScope(
			out.KeyMaxBudgetMicros, out.KeySpentMicros,
			out.UserMaxBudgetMicros, out.UserSpentMicros,
			delegatedUser.MaxBudgetMicros, delegatedUser.SpentMicros,
		)

		if out.TeamID != "" {
			if pmRepo, ok := repo.(storage.ProjectAndMembershipRepository); ok && pmRepo != nil {
				membership, mErr := pmRepo.GetTeamMembership(ctx, out.TeamID, delegatedUser.ID)
				if mErr == nil && membership != nil && membership.OrgID == out.OrgID && membership.TeamID == out.TeamID {
					if len(membership.AllowedModels) > 0 {
						out.TeamMemberAllowedModels = intersectModelAllowlists(out.TeamMemberAllowedModels, membership.AllowedModels)
						if len(out.KeyAllowedModels) > 0 {
							out.KeyAllowedModels = intersectModelAllowlists(out.KeyAllowedModels, membership.AllowedModels)
						}
					}
					out.TeamMemberRPMLimit = minPositiveInt(out.TeamMemberRPMLimit, membership.RPMLimit)
					out.TeamMemberTPMLimit = minPositiveInt(out.TeamMemberTPMLimit, membership.TPMLimit)
					out.TeamMemberMaxBudgetMicros, out.TeamMemberSpentMicros = narrowBudgetScope(
						0, 0,
						out.TeamMemberMaxBudgetMicros, out.TeamMemberSpentMicros,
						membership.MaxBudgetMicros, membership.SpentMicros,
					)
					// Mirror member ceilings onto User limits so Limiter enforces them.
					out.UserRPMLimit = minPositiveInt(out.UserRPMLimit, membership.RPMLimit)
					out.UserTPMLimit = minPositiveInt(out.UserTPMLimit, membership.TPMLimit)
					out.UserMaxBudgetMicros, out.UserSpentMicros = narrowBudgetScope(
						0, 0,
						out.UserMaxBudgetMicros, out.UserSpentMicros,
						membership.MaxBudgetMicros, membership.SpentMicros,
					)
				} else if mErr != nil && !errors.Is(mErr, storage.ErrNotFound) {
					return nil, &domain.GatewayError{
						StatusCode: http.StatusServiceUnavailable,
						Type:       domain.ErrorTypeServer,
						Code:       "team_membership_unavailable",
						Message:    "Unable to resolve delegated team membership policy",
						Retryable:  true,
					}
				}
			}
		}
	}

	return out, nil
}

func cloneIdentityContext(idCtx *domain.IdentityContext) *domain.IdentityContext {
	cp := *idCtx
	cp.KeyAllowedModels = slices.Clone(idCtx.KeyAllowedModels)
	cp.ProjectAllowedModels = slices.Clone(idCtx.ProjectAllowedModels)
	cp.TeamAllowedModels = slices.Clone(idCtx.TeamAllowedModels)
	cp.TeamMemberAllowedModels = slices.Clone(idCtx.TeamMemberAllowedModels)
	cp.DynamicAllowedModels = slices.Clone(idCtx.DynamicAllowedModels)
	cp.KeyAllowedDeployments = slices.Clone(idCtx.KeyAllowedDeployments)
	cp.ProjectAllowedDeployments = slices.Clone(idCtx.ProjectAllowedDeployments)
	cp.TeamAllowedDeployments = slices.Clone(idCtx.TeamAllowedDeployments)
	cp.AccessGroups = slices.Clone(idCtx.AccessGroups)
	cp.AllowedEndpoints = slices.Clone(idCtx.AllowedEndpoints)
	cp.KeyAllowedMCPServers = cloneNilPreservingSlice(idCtx.KeyAllowedMCPServers)
	cp.ProjectAllowedMCPServers = cloneNilPreservingSlice(idCtx.ProjectAllowedMCPServers)
	cp.TeamAllowedMCPServers = cloneNilPreservingSlice(idCtx.TeamAllowedMCPServers)
	cp.DynamicAllowedMCPServers = slices.Clone(idCtx.DynamicAllowedMCPServers)
	cp.KeyAllowedMCPTools = cloneNilPreservingSlice(idCtx.KeyAllowedMCPTools)
	cp.ProjectAllowedMCPTools = cloneNilPreservingSlice(idCtx.ProjectAllowedMCPTools)
	cp.TeamAllowedMCPTools = cloneNilPreservingSlice(idCtx.TeamAllowedMCPTools)
	cp.DynamicAllowedMCPTools = slices.Clone(idCtx.DynamicAllowedMCPTools)
	cp.KeyAllowedMCPToolsets = cloneNilPreservingSlice(idCtx.KeyAllowedMCPToolsets)
	cp.ProjectAllowedMCPToolsets = cloneNilPreservingSlice(idCtx.ProjectAllowedMCPToolsets)
	cp.TeamAllowedMCPToolsets = cloneNilPreservingSlice(idCtx.TeamAllowedMCPToolsets)
	cp.KeyAllowedA2AAgents = cloneNilPreservingSlice(idCtx.KeyAllowedA2AAgents)
	cp.ProjectAllowedA2AAgents = cloneNilPreservingSlice(idCtx.ProjectAllowedA2AAgents)
	cp.TeamAllowedA2AAgents = cloneNilPreservingSlice(idCtx.TeamAllowedA2AAgents)
	cp.DynamicAllowedA2AAgents = slices.Clone(idCtx.DynamicAllowedA2AAgents)
	cp.KeyAllowedClientApps = cloneNilPreservingSlice(idCtx.KeyAllowedClientApps)
	cp.TeamAllowedClientApps = cloneNilPreservingSlice(idCtx.TeamAllowedClientApps)
	cp.KeyBudgetFallbacks = domain.CloneBudgetFallbacks(idCtx.KeyBudgetFallbacks)
	cp.TeamBudgetFallbacks = domain.CloneBudgetFallbacks(idCtx.TeamBudgetFallbacks)
	cp.UserBudgetFallbacks = domain.CloneBudgetFallbacks(idCtx.UserBudgetFallbacks)
	cp.OrgBudgetFallbacks = domain.CloneBudgetFallbacks(idCtx.OrgBudgetFallbacks)
	cp.KeyTags = slices.Clone(idCtx.KeyTags)
	cp.KeyAllowedRoutingTags = slices.Clone(idCtx.KeyAllowedRoutingTags)
	cp.ProjectAllowedRoutingTags = slices.Clone(idCtx.ProjectAllowedRoutingTags)
	cp.TeamAllowedRoutingTags = slices.Clone(idCtx.TeamAllowedRoutingTags)
	cp.KeyMetadata = maps.Clone(idCtx.KeyMetadata)
	return &cp
}

func cloneNilPreservingSlice(src []string) []string {
	if src == nil {
		return nil
	}
	return slices.Clone(src)
}

func effective3StateAllowlist(keyAllowlist, teamAllowlist []string) []string {
	if keyAllowlist != nil {
		return keyAllowlist
	}
	return teamAllowlist
}

func intersect3StateAllowlists(a, b []string) []string {
	if b == nil {
		return cloneNilPreservingSlice(a)
	}
	if len(b) == 0 {
		return []string{}
	}
	if a == nil {
		return slices.Clone(b)
	}
	if len(a) == 0 {
		return []string{}
	}
	out := intersectAllowlistPatterns(a, b)
	if len(out) == 0 {
		return []string{}
	}
	return out
}

func intersectModelAllowlists(existing, restriction []string) []string {
	if len(restriction) == 0 {
		return slices.Clone(existing)
	}
	if len(existing) == 0 {
		return slices.Clone(restriction)
	}
	out := intersectAllowlistPatterns(existing, restriction)
	if len(out) == 0 {
		return []string{denyAllModelMarker}
	}
	return out
}

func intersectAllowlistPatterns(a, b []string) []string {
	var out []string
	seen := make(map[string]struct{})
	add := func(item string) {
		if item == "" {
			return
		}
		if _, exists := seen[item]; !exists {
			seen[item] = struct{}{}
			out = append(out, item)
		}
	}
	for _, p1 := range a {
		for _, p2 := range b {
			if merged, ok := intersectPatternPair(p1, p2); ok {
				add(merged)
			}
		}
	}
	return out
}

func intersectPatternPair(p1, p2 string) (string, bool) {
	if p1 == "" || p2 == "" {
		return "", false
	}
	if p1 == "*" {
		return p2, true
	}
	if p2 == "*" {
		return p1, true
	}
	w1 := strings.HasSuffix(p1, "*")
	w2 := strings.HasSuffix(p2, "*")
	if w1 && w2 {
		pre1 := strings.TrimSuffix(p1, "*")
		pre2 := strings.TrimSuffix(p2, "*")
		if strings.HasPrefix(pre1, pre2) {
			return p1, true
		}
		if strings.HasPrefix(pre2, pre1) {
			return p2, true
		}
		return "", false
	}
	if w1 {
		pre1 := strings.TrimSuffix(p1, "*")
		if pre1 != "" && strings.HasPrefix(p2, pre1) {
			return p2, true
		}
		return "", false
	}
	if w2 {
		pre2 := strings.TrimSuffix(p2, "*")
		if pre2 != "" && strings.HasPrefix(p1, pre2) {
			return p1, true
		}
		return "", false
	}
	if p1 == p2 {
		return p1, true
	}
	return "", false
}

func minPositiveInt(vals ...int) int {
	best := 0
	for _, v := range vals {
		if v > 0 && (best == 0 || v < best) {
			best = v
		}
	}
	return best
}

func minPositiveInt64(vals ...int64) int64 {
	var best int64
	for _, v := range vals {
		if v > 0 && (best == 0 || v < best) {
			best = v
		}
	}
	return best
}

// narrowBudgetScope computes the effective (maxBudget, spentBudget) pair such that
// the remaining headroom (max - spent) equals the minimum remaining headroom across
// all active positive budgets (key, prior scope, and delegated target).
func narrowBudgetScope(keyMax, keySpent, scopeMax, scopeSpent, targetMax, targetSpent int64) (int64, int64) {
	hasCap := false
	var minRem int64

	consider := func(maxB, spentB int64) {
		if maxB <= 0 {
			return
		}
		rem := maxB - spentB
		if rem < 0 {
			rem = 0
		}
		if !hasCap || rem < minRem {
			minRem = rem
			hasCap = true
		}
	}

	consider(keyMax, keySpent)
	consider(scopeMax, scopeSpent)
	consider(targetMax, targetSpent)

	if !hasCap {
		return 0, 0
	}
	if targetMax > 0 && max(int64(0), targetMax-targetSpent) <= minRem {
		return targetMax, targetSpent
	}
	if minRem == 0 && targetSpent == 0 {
		// Ensure Limiter observes an exhausted positive ceiling (spent >= max > 0).
		return 1, 1
	}
	return targetSpent + minRem, targetSpent
}

func lookupUserByIDAnyOrg(ctx context.Context, repo storage.Repository, userID string) (*domain.User, error) {
	if ul, ok := repo.(storage.UserLookupRepository); ok && ul != nil {
		return ul.GetUser(ctx, userID)
	}
	orgs, err := repo.ListOrganizations(ctx)
	if err != nil {
		return nil, err
	}
	for _, org := range orgs {
		if org == nil {
			continue
		}
		users, err := repo.ListUsers(ctx, org.ID)
		if err != nil {
			continue
		}
		for _, u := range users {
			if u != nil && u.ID == userID {
				return u, nil
			}
		}
	}
	return nil, storage.ErrNotFound
}

func lookupUserByEmailAnyOrg(ctx context.Context, repo storage.Repository, scopedOrgID, email string) (*domain.User, error) {
	if oidcRepo, ok := repo.(storage.OIDCUserRepository); ok && oidcRepo != nil {
		return oidcRepo.GetUserByEmail(ctx, email)
	}
	if scopedOrgID != "" {
		users, err := repo.ListUsers(ctx, scopedOrgID)
		if err != nil {
			return nil, err
		}
		for _, u := range users {
			if u != nil && strings.EqualFold(u.Email, email) {
				return u, nil
			}
		}
		return nil, storage.ErrNotFound
	}
	orgs, err := repo.ListOrganizations(ctx)
	if err != nil {
		return nil, err
	}
	for _, org := range orgs {
		if org == nil {
			continue
		}
		users, err := repo.ListUsers(ctx, org.ID)
		if err != nil {
			continue
		}
		for _, u := range users {
			if u != nil && strings.EqualFold(u.Email, email) {
				return u, nil
			}
		}
	}
	return nil, storage.ErrNotFound
}
