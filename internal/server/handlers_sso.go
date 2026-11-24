package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

func (s *GatewayServer) mapUserRoleForControlPlane(role domain.Role) (domain.OperatorRole, bool) {
	if s != nil && s.authSvc != nil {
		return s.authSvc.MapDomainRoleToOperatorRole(role)
	}
	switch role {
	case domain.RolePlatformAdmin:
		return domain.OperatorRolePlatformAdmin, true
	case domain.RoleOrgAdmin:
		return domain.OperatorRoleOrgAdmin, true
	case domain.RoleOrgViewer:
		return domain.OperatorRoleOrgViewer, true
	case domain.RoleTeamAdmin:
		return domain.OperatorRoleTeamAdmin, true
	default:
		return "", false
	}
}

func extractRawSessionToken(r *http.Request) string {
	if r == nil {
		return ""
	}
	if c, err := r.Cookie(auth.SessionCookieName); err == nil && strings.TrimSpace(c.Value) != "" {
		return strings.TrimSpace(c.Value)
	}
	if h := strings.TrimSpace(r.Header.Get("X-Session-Token")); h != "" {
		return h
	}
	authz := strings.TrimSpace(r.Header.Get("Authorization"))
	if len(authz) > 7 && strings.EqualFold(authz[:7], "Bearer ") {
		tok := strings.TrimSpace(authz[7:])
		if auth.IsSessionTokenAudience(tok) {
			return tok
		}
	}
	return ""
}

func (s *GatewayServer) resolveLogoutContext(ctx context.Context, r *http.Request, op *domain.OperatorContext) (providerID, idTokenHint string) {
	if op != nil && op.SessionID != "" {
		if sessRepo, ok := s.repo.(storage.OperatorSessionRepository); ok && sessRepo != nil {
			if sess, err := sessRepo.GetOperatorSession(ctx, op.SessionID); err == nil && sess != nil {
				providerID = strings.TrimSpace(sess.ProviderID)
				if s.sessionMgr != nil {
					idTokenHint = s.sessionMgr.DecryptIDTokenHint(sess)
				}
			}
		}
	}
	if providerID == "" && s.sessionMgr != nil {
		if rawTok := extractRawSessionToken(r); rawTok != "" {
			if claims, sess, err := s.sessionMgr.VerifySession(ctx, rawTok); err == nil {
				if claims != nil && strings.TrimSpace(claims.ProviderID) != "" {
					providerID = strings.TrimSpace(claims.ProviderID)
				} else if sess != nil && strings.TrimSpace(sess.ProviderID) != "" {
					providerID = strings.TrimSpace(sess.ProviderID)
				}
				if idTokenHint == "" && sess != nil {
					idTokenHint = s.sessionMgr.DecryptIDTokenHint(sess)
				}
			}
		}
	}
	// Only fall back to query ?provider= if the verified session carries no bound provider.
	if providerID == "" {
		providerID = strings.TrimSpace(r.URL.Query().Get("provider"))
	}
	return providerID, idTokenHint
}

func (s *GatewayServer) handleAuthLogout(w http.ResponseWriter, r *http.Request) {
	op := auth.OperatorFromContext(r.Context())
	providerID, idTokenHint := s.resolveLogoutContext(r.Context(), r, op)

	if op != nil && op.SessionID != "" && s.sessionMgr != nil {
		expiresAt := time.Now().UTC().Add(s.sessionMgr.TTL())
		if err := s.sessionMgr.RevokeSession(r.Context(), op.SessionID, expiresAt); err != nil {
			domain.WriteHTTPError(w, err)
			return
		}
		s.audit(r.Context(), op.OrgID, "auth.logout", "operator_session", op.SessionID, map[string]any{
			"actor_id": op.ActorID,
			"provider": providerID,
		})
	}
	auth.ClearSessionCookie(w)

	resp := map[string]any{
		"status": "logged_out",
	}
	if providerID != "" && s.ssoMgr != nil {
		postLogoutRedirect := ""
		if base := s.requestBaseURL(r); base != "" {
			postLogoutRedirect = base + "/ui/"
		}
		if endSessionURL, err := s.ssoMgr.BuildEndSessionURL(r.Context(), providerID, idTokenHint, postLogoutRedirect); err == nil && endSessionURL != "" {
			resp["end_session_url"] = endSessionURL
		}
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *GatewayServer) handleAuthMe(w http.ResponseWriter, r *http.Request) {
	op := auth.OperatorFromContext(r.Context())
	if op == nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusUnauthorized,
			Type:       domain.ErrorTypeAuthentication,
			Code:       "unauthenticated",
			Message:    "Authentication is required",
		})
		return
	}

	resp := map[string]any{
		"operator": op,
	}
	if op.CSRFToken != "" {
		resp["csrf_token"] = op.CSRFToken
	}

	if ul, ok := s.repo.(storage.UserLookupRepository); ok && ul != nil && op.ActorID != "" && op.ActorID != "master_admin" {
		if user, err := ul.GetUser(r.Context(), op.ActorID); err == nil && user != nil {
			resp["user"] = user
		}
	}

	writeJSON(w, http.StatusOK, resp)
}

type cliStartRequest struct {
	Provider   string `json:"provider,omitempty"`
	ClientName string `json:"client_name,omitempty"`
}

type cliCompleteRequest struct {
	OrgID         string   `json:"org_id,omitempty"`
	TeamID        string   `json:"team_id,omitempty"`
	ProjectID     string   `json:"project_id,omitempty"`
	KeyName       string   `json:"key_name,omitempty"`
	AllowedModels []string `json:"allowed_models,omitempty"`
	TTLSeconds    int64    `json:"ttl_seconds,omitempty"`
}

func (s *GatewayServer) requestBaseURL(r *http.Request) string {
	if s != nil && s.cfg != nil && strings.TrimSpace(s.cfg.Server.PublicBaseURL) != "" {
		return strings.TrimRight(strings.TrimSpace(s.cfg.Server.PublicBaseURL), "/")
	}
	if r == nil {
		return ""
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	} else if isFromTrustedProxy(r.Context()) && strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https") {
		scheme = "https"
	}
	host := strings.TrimSpace(r.Host)
	if host == "" || strings.ContainsAny(host, " \t\r\n/@\\?#") {
		return ""
	}
	return scheme + "://" + host
}

func acceptsJSONResponse(r *http.Request) bool {
	if r == nil {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("format")), "json") {
		return true
	}
	return strings.Contains(strings.ToLower(r.Header.Get("Accept")), "application/json")
}

func prefersHTMLRedirect(r *http.Request) bool {
	if r == nil || acceptsJSONResponse(r) {
		return false
	}
	return strings.Contains(strings.ToLower(r.Header.Get("Accept")), "text/html")
}

func mapIDPErrorCode(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "access_denied",
		"login_required",
		"interaction_required",
		"consent_required",
		"account_selection_required",
		"temporarily_unavailable",
		"server_error",
		"invalid_request",
		"unauthorized_client":
		return strings.ToLower(strings.TrimSpace(raw))
	default:
		return "sso_provider_error"
	}
}

func sanitizeLogString(raw string, maxLen int) string {
	var b strings.Builder
	for _, r := range strings.TrimSpace(raw) {
		if r < 0x20 || r == 0x7f {
			b.WriteByte(' ')
			continue
		}
		b.WriteRune(r)
		if maxLen > 0 && b.Len() >= maxLen {
			break
		}
	}
	return strings.TrimSpace(b.String())
}

func buildUICallbackErrorRedirect(redirectAfter, errCode string) string {
	safeCode := strings.TrimSpace(errCode)
	if safeCode == "" {
		safeCode = "sso_provider_error"
	}
	if clean, err := validateSafeRedirectAfter(redirectAfter); err == nil && strings.HasPrefix(clean, "/ui") {
		if u, pErr := url.Parse(clean); pErr == nil && u.Path != "" {
			q := u.Query()
			q.Set("auth_error", safeCode)
			u.RawQuery = q.Encode()
			u.Fragment = ""
			return u.String()
		}
	}
	return "/ui/?auth_error=" + url.QueryEscape(safeCode)
}

func writeSSOCallbackError(w http.ResponseWriter, r *http.Request, redirectAfter, errCode string, err error) {
	if prefersHTMLRedirect(r) {
		http.Redirect(w, r, buildUICallbackErrorRedirect(redirectAfter, errCode), http.StatusFound)
		return
	}
	writeSSOError(w, err)
}

func validateSafeRedirectAfter(raw string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", nil
	}
	if strings.ContainsAny(trimmed, "\r\n\x00") {
		return "", errors.New("redirect_after contains invalid control characters")
	}
	if !strings.HasPrefix(trimmed, "/") || strings.HasPrefix(trimmed, "//") || strings.HasPrefix(trimmed, "/\\") {
		return "", errors.New("redirect_after must be a relative path starting with /")
	}
	u, err := url.Parse(trimmed)
	if err != nil || u.Scheme != "" || u.Host != "" {
		return "", errors.New("redirect_after must not specify a scheme or host")
	}
	return trimmed, nil
}

func writeSSOError(w http.ResponseWriter, err error) {
	var ssoErr *auth.SSOError
	if errors.As(err, &ssoErr) && ssoErr != nil {
		if ssoErr.RetryAfter > 0 {
			secs := int(math.Ceil(ssoErr.RetryAfter.Seconds()))
			if secs < 1 {
				secs = 1
			}
			w.Header().Set("Retry-After", strconv.Itoa(secs))
		}
		domain.WriteHTTPError(w, ssoErr.GatewayError())
		return
	}
	domain.WriteHTTPError(w, err)
}

func (s *GatewayServer) handleAuthSSOProviders(w http.ResponseWriter, r *http.Request) {
	providers := []auth.SSOProviderPublicInfo{}
	if s.ssoMgr != nil {
		providers = s.ssoMgr.ListProviders()
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"providers": providers,
	})
}

func (s *GatewayServer) handleAuthSSOLogin(w http.ResponseWriter, r *http.Request) {
	if s.ssoMgr == nil || s.ssoStateStore == nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusServiceUnavailable,
			Type:       domain.ErrorTypeServer,
			Code:       "sso_unavailable",
			Message:    "SSO authentication is not initialized",
		})
		return
	}

	providerID := strings.TrimSpace(chi.URLParam(r, "provider"))
	redirectAfter, err := validateSafeRedirectAfter(r.URL.Query().Get("redirect_after"))
	if err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_redirect_after",
			Message:    err.Error(),
		})
		return
	}

	cliLoginID := strings.TrimSpace(r.URL.Query().Get("cli_login_id"))
	if cliLoginID != "" {
		if s.cliLoginStore == nil {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusServiceUnavailable,
				Type:       domain.ErrorTypeServer,
				Code:       "cli_login_unavailable",
				Message:    "CLI login store is not initialized",
			})
			return
		}
		cliSess, cliErr := s.cliLoginStore.Get(r.Context(), cliLoginID)
		if cliErr != nil {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusNotFound,
				Type:       domain.ErrorTypeNotFound,
				Code:       "cli_login_not_found",
				Message:    "CLI login session was not found or has expired",
			})
			return
		}
		if cliSess.Status == auth.CLILoginStatusCompleted {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusConflict,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "cli_login_already_completed",
				Message:    "CLI login session has already been completed",
			})
			return
		}
	}

	redirectURI := ""
	if base := s.requestBaseURL(r); base != "" {
		redirectURI = base + "/auth/sso/" + url.PathEscape(providerID) + "/callback"
	}

	authURL, state, err := s.ssoMgr.BuildAuthorizationURL(
		r.Context(),
		providerID,
		redirectURI,
		redirectAfter,
		cliLoginID,
		s.ssoStateStore,
	)
	if err != nil {
		writeSSOError(w, err)
		return
	}

	if acceptsJSONResponse(r) {
		writeJSON(w, http.StatusOK, map[string]any{
			"authorization_url": authURL,
			"state":             state,
		})
		return
	}
	http.Redirect(w, r, authURL, http.StatusFound)
}

func (s *GatewayServer) handleAuthSSOCallback(w http.ResponseWriter, r *http.Request) {
	if s.ssoMgr == nil || s.ssoStateStore == nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusServiceUnavailable,
			Type:       domain.ErrorTypeServer,
			Code:       "sso_unavailable",
			Message:    "SSO authentication is not initialized",
		})
		return
	}

	providerID := strings.TrimSpace(chi.URLParam(r, "provider"))
	if idpErr := strings.TrimSpace(r.URL.Query().Get("error")); idpErr != "" {
		mappedCode := mapIDPErrorCode(idpErr)
		slog.WarnContext(
			r.Context(),
			"oidc callback returned provider error",
			"provider", sanitizeLogString(providerID, 64),
			"idp_error", sanitizeLogString(idpErr, 64),
			"idp_error_description", sanitizeLogString(r.URL.Query().Get("error_description"), 256),
		)
		writeSSOCallbackError(w, r, "", mappedCode, &domain.GatewayError{
			StatusCode:  http.StatusUnauthorized,
			Type:        domain.ErrorTypeAuthentication,
			Code:        "sso_provider_error",
			Message:     "SSO provider rejected the authentication request (" + mappedCode + ")",
			AuthFailure: true,
		})
		return
	}

	code := strings.TrimSpace(r.URL.Query().Get("code"))
	state := strings.TrimSpace(r.URL.Query().Get("state"))
	if code == "" || state == "" {
		writeSSOCallbackError(w, r, "", "missing_sso_params", &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "missing_sso_params",
			Message:    "code and state query parameters are required",
		})
		return
	}

	authState, err := s.ssoStateStore.Consume(r.Context(), state)
	if err != nil {
		writeSSOCallbackError(w, r, "", "invalid_sso_state", &domain.GatewayError{
			StatusCode:  http.StatusUnauthorized,
			Type:        domain.ErrorTypeAuthentication,
			Code:        "invalid_sso_state",
			Message:     "Invalid, expired, or already used SSO state",
			AuthFailure: true,
		})
		return
	}

	p, ok := s.ssoMgr.GetProvider(providerID)
	if !ok {
		writeSSOCallbackError(w, r, authState.RedirectAfter, "sso_provider_not_found", &domain.GatewayError{
			StatusCode: http.StatusNotFound,
			Type:       domain.ErrorTypeNotFound,
			Code:       "sso_provider_not_found",
			Message:    fmt.Sprintf("SSO provider %q is not configured", providerID),
		})
		return
	}
	if authState.Provider != p.ID() {
		writeSSOCallbackError(w, r, authState.RedirectAfter, "sso_provider_mismatch", &domain.GatewayError{
			StatusCode:  http.StatusUnauthorized,
			Type:        domain.ErrorTypeAuthentication,
			Code:        "sso_provider_mismatch",
			Message:     "SSO state does not match callback provider",
			AuthFailure: true,
		})
		return
	}

	idClaims, err := s.ssoMgr.ExchangeAndVerify(
		r.Context(),
		p.ID(),
		code,
		authState.RedirectURI,
		authState.CodeVerifier,
		authState.Nonce,
	)
	if err != nil {
		writeSSOCallbackError(w, r, authState.RedirectAfter, "sso_exchange_failed", err)
		return
	}

	user, err := s.resolveOrProvisionSSOUser(r.Context(), p, idClaims)
	if err != nil {
		writeSSOCallbackError(w, r, authState.RedirectAfter, "sso_user_not_authorized", err)
		return
	}

	if authState.CLILoginID != "" {
		if user.Role == domain.RoleOrgViewer || user.Role == domain.RoleViewer {
			writeSSOCallbackError(w, r, authState.RedirectAfter, "insufficient_permissions", &domain.GatewayError{
				StatusCode: http.StatusForbidden,
				Type:       domain.ErrorTypePermission,
				Code:       "insufficient_permissions",
				Message:    "Read-only viewer accounts cannot approve CLI virtual key issuance",
			})
			return
		}
		if _, cliErr := s.mintAndCompleteCLILogin(
			r.Context(),
			authState.CLILoginID,
			user.OrgID,
			user.TeamID,
			"",
			user.ID,
			"",
			nil,
			0,
		); cliErr != nil {
			writeSSOCallbackError(w, r, authState.RedirectAfter, "cli_login_failed", cliErr)
			return
		}
	}

	opRole, hasOpRole := s.mapUserRoleForControlPlane(user.Role)
	if !hasOpRole {
		if authState.CLILoginID != "" {
			s.audit(r.Context(), user.OrgID, "auth.sso.cli_login", "cli_login", authState.CLILoginID, map[string]any{
				"user_id":  user.ID,
				"provider": p.ID(),
			})
			if authState.RedirectAfter != "" {
				http.Redirect(w, r, authState.RedirectAfter, http.StatusFound)
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"status":       "cli_login_completed",
				"provider":     p.ID(),
				"cli_login_id": authState.CLILoginID,
				"cli_status":   "completed",
				"user":         user,
			})
			return
		}
		writeSSOCallbackError(w, r, authState.RedirectAfter, "insufficient_permissions", &domain.GatewayError{
			StatusCode: http.StatusForbidden,
			Type:       domain.ErrorTypePermission,
			Code:       "insufficient_permissions",
			Message:    "User role is not authorized for Control Plane access",
		})
		return
	}

	if s.sessionMgr == nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusServiceUnavailable,
			Type:       domain.ErrorTypeServer,
			Code:       "session_manager_unavailable",
			Message:    "Session authentication is not initialized",
		})
		return
	}

	issued, err := s.sessionMgr.IssueSessionWithOIDC(r.Context(), user.ID, user.OrgID, user.TeamID, p.ID(), idClaims.RawIDToken, opRole)
	if err != nil {
		domain.WriteHTTPError(w, err)
		return
	}

	auth.SetSessionCookie(w, issued.Token, issued.ExpiresAt)
	s.audit(r.Context(), user.OrgID, "auth.sso.login", "operator_session", issued.Session.ID, map[string]any{
		"user_id":  user.ID,
		"provider": p.ID(),
		"subject":  idClaims.Subject,
	})

	if authState.RedirectAfter != "" {
		http.Redirect(w, r, authState.RedirectAfter, http.StatusFound)
		return
	}

	resp := map[string]any{
		"token":         issued.Token,
		"session_token": issued.Token,
		"csrf_token":    issued.CSRFToken,
		"expires_at":    issued.ExpiresAt.UTC().Format(time.RFC3339),
		"provider":      p.ID(),
		"operator": domain.OperatorContext{
			ActorID:    user.ID,
			Role:       opRole,
			OrgID:      user.OrgID,
			TeamID:     user.TeamID,
			AuthMethod: "session",
			SessionID:  issued.Session.ID,
		},
		"user": user,
	}
	if authState.CLILoginID != "" {
		resp["cli_login_id"] = authState.CLILoginID
		resp["cli_status"] = "completed"
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *GatewayServer) resolveOrProvisionSSOUser(ctx context.Context, p *auth.SSOProvider, claims *auth.SSOIDTokenClaims) (*domain.User, error) {
	if s.repo == nil {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusServiceUnavailable,
			Type:       domain.ErrorTypeServer,
			Code:       "auth_repository_unavailable",
			Message:    "Identity repository is not configured",
		}
	}

	orgID := strings.TrimSpace(claims.OrgID)
	if orgID == "" {
		orgID = p.DefaultOrgID()
	}
	if orgID == "" && s.cfg != nil {
		orgID = strings.TrimSpace(s.cfg.Auth.DefaultOrgID)
	}
	if orgID == "" {
		if org, err := s.repo.GetOrganization(ctx, "org_default"); err == nil && org != nil && org.IsActive {
			orgID = org.ID
		}
	}
	if orgID == "" {
		return nil, &domain.GatewayError{
			StatusCode:  http.StatusUnauthorized,
			Type:        domain.ErrorTypeAuthentication,
			Code:        "missing_org_id",
			Message:     "Organization could not be determined for SSO user",
			AuthFailure: true,
		}
	}

	org, err := s.repo.GetOrganization(ctx, orgID)
	if err != nil || org == nil || !org.IsActive {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusForbidden,
			Type:       domain.ErrorTypePermission,
			Code:       "organization_inactive",
			Message:    "Organization associated with this SSO login is inactive or does not exist",
		}
	}

	singleTrustedIssuer := s.ssoMgr != nil && len(s.ssoMgr.ListProviders()) == 1 &&
		(s.authResolver == nil || s.authResolver.SingleJWTIssuer())

	var user *domain.User
	if oidcRepo, ok := s.repo.(storage.OIDCUserRepository); ok && oidcRepo != nil {
		user, err = oidcRepo.GetUserByOIDCIdentity(ctx, orgID, claims.Issuer, claims.Subject)
		if errors.Is(err, storage.ErrNotFound) && singleTrustedIssuer {
			user, err = oidcRepo.GetUserByOIDCIdentity(ctx, orgID, "", claims.Subject)
		}
		if errors.Is(err, storage.ErrConflict) {
			return nil, &domain.GatewayError{
				StatusCode: http.StatusConflict,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "ambiguous_oidc_identity",
				Message:    "Multiple OIDC users share this subject without a bound issuer; contact an administrator to bind oidc_issuer",
			}
		}
		if err != nil && !errors.Is(err, storage.ErrNotFound) {
			return nil, &domain.GatewayError{
				StatusCode: http.StatusServiceUnavailable,
				Type:       domain.ErrorTypeServer,
				Code:       "user_lookup_unavailable",
				Message:    "Unable to resolve SSO user identity",
				Retryable:  true,
			}
		}
	} else {
		u, lookupErr := s.repo.GetUserByOIDCSubject(ctx, claims.Subject)
		if lookupErr != nil && !errors.Is(lookupErr, storage.ErrNotFound) {
			return nil, &domain.GatewayError{
				StatusCode: http.StatusServiceUnavailable,
				Type:       domain.ErrorTypeServer,
				Code:       "user_lookup_unavailable",
				Message:    "Unable to resolve SSO user identity",
				Retryable:  true,
			}
		}
		if lookupErr == nil && u != nil && u.OrgID == orgID &&
			(u.OIDCIssuer == claims.Issuer || (u.OIDCIssuer == "" && singleTrustedIssuer)) {
			user = u
		}
	}

	mappedRole := auth.ResolveMappedRole(
		claims.Role,
		claims.Groups,
		p.GroupRoleMappings(),
		p.RoleMappingStrategy(),
		p.DefaultRole(),
		p.AllowPrivilegedRoleClaims(),
	)
	mappedTeamID := auth.ResolveMappedTeamID(claims.TeamIDs, claims.Groups, p.GroupTeamMappings(), p.DefaultTeamID())

	if user == nil {
		if !p.AutoRegister() {
			return nil, &domain.GatewayError{
				StatusCode:  http.StatusUnauthorized,
				Type:        domain.ErrorTypeAuthentication,
				Code:        "unknown_user",
				Message:     "No registered user matches the SSO identity",
				AuthFailure: true,
			}
		}

		teamID := mappedTeamID
		if teamID != "" {
			team, teamErr := s.repo.GetTeam(ctx, teamID)
			if teamErr != nil || team == nil {
				return nil, &domain.GatewayError{
					StatusCode: http.StatusForbidden,
					Type:       domain.ErrorTypePermission,
					Code:       "team_not_found",
					Message:    "Default team associated with this SSO login was not found",
				}
			}
			if team.OrgID != orgID {
				return nil, &domain.GatewayError{
					StatusCode: http.StatusForbidden,
					Type:       domain.ErrorTypePermission,
					Code:       "team_org_mismatch",
					Message:    "Default team does not belong to target organization",
				}
			}
			if !team.IsActive {
				return nil, &domain.GatewayError{
					StatusCode: http.StatusForbidden,
					Type:       domain.ErrorTypePermission,
					Code:       "team_inactive",
					Message:    "Default team associated with this SSO login is inactive",
				}
			}
		}

		email := strings.TrimSpace(claims.Email)
		if email == "" {
			email = fmt.Sprintf("%s@%s.%s.oidc.local",
				sanitizeSSOEmailPart(claims.Subject, "oidc-user"),
				sanitizeSSOEmailPart(claims.Issuer, "issuer"),
				sanitizeSSOEmailPart(orgID, "default"),
			)
		}
		name := strings.TrimSpace(claims.DisplayName)
		if name == "" {
			name = email
		}

		jitUser := &domain.User{
			OrgID:             orgID,
			TeamID:            teamID,
			Email:             email,
			Name:              name,
			Role:              mappedRole,
			OIDCIssuer:        claims.Issuer,
			OIDCSubject:       claims.Subject,
			BudgetResetPeriod: domain.BudgetResetMonthly,
			IsActive:          true,
			SCIMActive:        true,
		}

		if oidcRepo, ok := s.repo.(storage.OIDCUserRepository); ok && oidcRepo != nil {
			createdUser, _, jitErr := oidcRepo.GetOrCreateUserByOIDCSubject(ctx, jitUser)
			if jitErr != nil {
				if errors.Is(jitErr, storage.ErrConflict) {
					return nil, &domain.GatewayError{
						StatusCode: http.StatusForbidden,
						Type:       domain.ErrorTypePermission,
						Code:       "user_provisioning_conflict",
						Message:    jitErr.Error(),
					}
				}
				return nil, &domain.GatewayError{
					StatusCode: http.StatusServiceUnavailable,
					Type:       domain.ErrorTypeServer,
					Code:       "user_provisioning_unavailable",
					Message:    "Unable to provision SSO user: " + jitErr.Error(),
					Retryable:  true,
				}
			}
			user = createdUser
		} else {
			if createErr := s.repo.CreateUser(ctx, jitUser); createErr != nil {
				return nil, &domain.GatewayError{
					StatusCode: http.StatusServiceUnavailable,
					Type:       domain.ErrorTypeServer,
					Code:       "user_provisioning_unavailable",
					Message:    "Unable to provision SSO user: " + createErr.Error(),
					Retryable:  true,
				}
			}
			user = jitUser
		}
	} else if p.SyncRolesOnLogin() {
		beforeUser := *user
		updatedUser := *user
		roleChanged := updatedUser.Role != mappedRole
		teamChanged := false
		if mappedTeamID != "" && mappedTeamID != updatedUser.TeamID {
			if team, teamErr := s.repo.GetTeam(ctx, mappedTeamID); teamErr == nil && team != nil && team.OrgID == orgID && team.IsActive {
				updatedUser.TeamID = mappedTeamID
				teamChanged = true
			}
		}
		if roleChanged {
			updatedUser.Role = mappedRole
		}
		if roleChanged || teamChanged {
			if updateErr := s.repo.UpdateUser(ctx, &updatedUser); updateErr != nil {
				return nil, &domain.GatewayError{
					StatusCode: http.StatusServiceUnavailable,
					Type:       domain.ErrorTypeServer,
					Code:       "sso_role_sync_failed",
					Message:    "Unable to synchronize SSO user role/team: " + updateErr.Error(),
					Retryable:  true,
				}
			}
			user = &updatedUser
			if roleChanged && s.sessionMgr != nil {
				_ = s.sessionMgr.RevokeAllUserSessions(ctx, user.ID)
			}
			if s.authSvc != nil {
				s.authSvc.InvalidateUserKeys(ctx, user.OrgID, user.ID)
			}
			s.auditWithDiff(ctx, user.OrgID, "sso.role_synced", "user", user.ID, map[string]any{
				"provider":     p.ID(),
				"before_role":  beforeUser.Role,
				"after_role":   user.Role,
				"before_team":  beforeUser.TeamID,
				"after_team":   user.TeamID,
				"groups_count": len(claims.Groups),
			}, &beforeUser, user)
		}
	}

	if !user.IsActive {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusForbidden,
			Type:       domain.ErrorTypePermission,
			Code:       "user_inactive",
			Message:    "User account is inactive",
		}
	}
	if !user.SCIMActive {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusForbidden,
			Type:       domain.ErrorTypePermission,
			Code:       "scim_deprovisioned",
			Message:    "User account has been deprovisioned via SCIM",
		}
	}
	return user, nil
}

func sanitizeSSOEmailPart(raw, fallback string) string {
	cleaned := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			return r
		}
		return '-'
	}, strings.TrimSpace(raw))
	if cleaned == "" {
		return fallback
	}
	return cleaned
}

func (s *GatewayServer) handleAuthCLIStart(w http.ResponseWriter, r *http.Request) {
	if s.cliLoginStore == nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusServiceUnavailable,
			Type:       domain.ErrorTypeServer,
			Code:       "cli_login_unavailable",
			Message:    "CLI login flow is not initialized",
		})
		return
	}

	var req cliStartRequest
	if r.Body != nil {
		dec := json.NewDecoder(io.LimitReader(r.Body, 64<<10))
		if err := dec.Decode(&req); err != nil && !errors.Is(err, io.EOF) {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusBadRequest,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "invalid_request",
				Message:    err.Error(),
			})
			return
		}
	}

	providerID := strings.ToLower(strings.TrimSpace(req.Provider))
	if providerID != "" && s.ssoMgr != nil {
		if _, ok := s.ssoMgr.GetProvider(providerID); !ok {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusNotFound,
				Type:       domain.ErrorTypeNotFound,
				Code:       "sso_provider_not_found",
				Message:    fmt.Sprintf("SSO provider %q is not configured", providerID),
			})
			return
		}
	}

	sess, err := s.cliLoginStore.Start(r.Context(), providerID)
	if err != nil {
		domain.WriteHTTPError(w, err)
		return
	}

	verificationURL := s.requestBaseURL(r) + "/ui/cli?login_id=" + url.QueryEscape(sess.LoginID) + "&user_code=" + url.QueryEscape(sess.UserCode)
	if sess.Provider != "" {
		verificationURL += "&provider=" + url.QueryEscape(sess.Provider)
	}

	intervalSec := int(s.cliLoginStore.PollInterval().Seconds())
	if intervalSec < 1 {
		intervalSec = 1
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"login_id":         sess.LoginID,
		"user_code":        sess.UserCode,
		"verification_url": verificationURL,
		"expires_in":       int(s.cliLoginStore.TTL().Seconds()),
		"interval":         intervalSec,
	})
}

func (s *GatewayServer) handleAuthCLIComplete(w http.ResponseWriter, r *http.Request) {
	op := auth.OperatorFromContext(r.Context())
	if op == nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusUnauthorized,
			Type:       domain.ErrorTypeAuthentication,
			Code:       "unauthenticated",
			Message:    "Authentication is required",
		})
		return
	}
	if s.cliLoginStore == nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusServiceUnavailable,
			Type:       domain.ErrorTypeServer,
			Code:       "cli_login_unavailable",
			Message:    "CLI login flow is not initialized",
		})
		return
	}

	loginID := strings.TrimSpace(chi.URLParam(r, "login_id"))
	if loginID == "" {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "missing_login_id",
			Message:    "login_id is required",
		})
		return
	}

	var req cliCompleteRequest
	if r.Body != nil {
		dec := json.NewDecoder(io.LimitReader(r.Body, 64<<10))
		if err := dec.Decode(&req); err != nil && !errors.Is(err, io.EOF) {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusBadRequest,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "invalid_request",
				Message:    err.Error(),
			})
			return
		}
	}

	orgID := strings.TrimSpace(req.OrgID)
	if orgID == "" {
		orgID = strings.TrimSpace(op.OrgID)
	}
	if orgID == "" && s.cfg != nil {
		orgID = strings.TrimSpace(s.cfg.Auth.DefaultOrgID)
	}
	if orgID == "" {
		orgID = "org_default"
	}

	if op.Role == domain.OperatorRoleOrgViewer {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusForbidden,
			Type:       domain.ErrorTypePermission,
			Code:       "insufficient_permissions",
			Message:    "Read-only org_viewer operators cannot approve CLI virtual key issuance",
		})
		return
	}

	if op.Role != domain.OperatorRolePlatformAdmin && orgID != op.OrgID {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusForbidden,
			Type:       domain.ErrorTypePermission,
			Code:       "cross_org_access_denied",
			Message:    fmt.Sprintf("Operator in organization %q is not authorized to access organization %q", op.OrgID, orgID),
		})
		return
	}

	teamID := strings.TrimSpace(req.TeamID)
	if op.Role == domain.OperatorRoleTeamAdmin {
		if teamID == "" {
			teamID = op.TeamID
		}
		if op.TeamID == "" || teamID != op.TeamID {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusForbidden,
				Type:       domain.ErrorTypePermission,
				Code:       "cross_team_access_denied",
				Message:    fmt.Sprintf("Operator in team %q is not authorized to access team %q", op.TeamID, teamID),
			})
			return
		}
	}

	userID := ""
	if op.ActorID != "" && op.ActorID != "master_admin" {
		if u, err := s.lookupUserByID(r.Context(), op.ActorID); err == nil && u != nil && u.OrgID == orgID {
			userID = u.ID
		}
	}

	completed, err := s.mintAndCompleteCLILogin(
		r.Context(),
		loginID,
		orgID,
		teamID,
		strings.TrimSpace(req.ProjectID),
		userID,
		strings.TrimSpace(req.KeyName),
		req.AllowedModels,
		req.TTLSeconds,
	)
	if err != nil {
		domain.WriteHTTPError(w, err)
		return
	}

	s.audit(r.Context(), orgID, "auth.cli.complete", "cli_login", loginID, map[string]any{
		"actor_id":   op.ActorID,
		"team_id":    teamID,
		"key_id":     completed.KeyID,
		"key_prefix": completed.KeyPrefix,
	})

	writeJSON(w, http.StatusOK, map[string]any{
		"status":     "completed",
		"login_id":   completed.LoginID,
		"org_id":     completed.OrgID,
		"team_id":    completed.TeamID,
		"key_id":     completed.KeyID,
		"key_prefix": completed.KeyPrefix,
	})
}

func (s *GatewayServer) mintAndCompleteCLILogin(
	ctx context.Context,
	loginID, orgID, teamID, projectID, userID, keyName string,
	allowedModels []string,
	ttlSeconds int64,
) (*auth.CLILoginSession, error) {
	if s.cliLoginStore == nil || s.authSvc == nil {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusServiceUnavailable,
			Type:       domain.ErrorTypeServer,
			Code:       "cli_login_unavailable",
			Message:    "CLI login service is not initialized",
		}
	}

	existing, err := s.cliLoginStore.Get(ctx, loginID)
	if err != nil {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusNotFound,
			Type:       domain.ErrorTypeNotFound,
			Code:       "cli_login_not_found",
			Message:    "CLI login session was not found or has expired",
		}
	}
	if existing.Status == auth.CLILoginStatusCompleted {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusConflict,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "cli_login_already_completed",
			Message:    "CLI login session has already been completed",
		}
	}

	org, err := s.repo.GetOrganization(ctx, orgID)
	if err != nil || org == nil || !org.IsActive {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusForbidden,
			Type:       domain.ErrorTypePermission,
			Code:       "organization_inactive",
			Message:    "Target organization is inactive or does not exist",
		}
	}

	if teamID != "" {
		team, teamErr := s.repo.GetTeam(ctx, teamID)
		if teamErr != nil || team == nil {
			return nil, &domain.GatewayError{
				StatusCode: http.StatusNotFound,
				Type:       domain.ErrorTypeNotFound,
				Code:       "team_not_found",
				Message:    "Target team not found",
			}
		}
		if team.OrgID != orgID {
			return nil, &domain.GatewayError{
				StatusCode: http.StatusForbidden,
				Type:       domain.ErrorTypePermission,
				Code:       "cross_org_access_denied",
				Message:    "Target team does not belong to the selected organization",
			}
		}
		if !team.IsActive {
			return nil, &domain.GatewayError{
				StatusCode: http.StatusForbidden,
				Type:       domain.ErrorTypePermission,
				Code:       "team_inactive",
				Message:    "Target team is inactive",
			}
		}
	}

	if keyName == "" {
		keyName = "cli-" + loginID
	}
	defaultTTL := 24 * time.Hour
	maxTTL := 30 * 24 * time.Hour
	if s.cfg != nil {
		if s.cfg.Auth.CLILoginDefaultTTL > 0 {
			defaultTTL = s.cfg.Auth.CLILoginDefaultTTL
		}
		if s.cfg.Auth.CLILoginMaxTTL > 0 {
			maxTTL = s.cfg.Auth.CLILoginMaxTTL
		}
	}
	effectiveTTL := defaultTTL
	if ttlSeconds > 0 {
		effectiveTTL = time.Duration(ttlSeconds) * time.Second
		if effectiveTTL > maxTTL {
			effectiveTTL = maxTTL
		}
	}
	expTime := time.Now().UTC().Add(effectiveTTL)
	expiresAt := &expTime

	vk, err := s.authSvc.IssueVirtualKey(ctx, &domain.VirtualKey{
		Name:          keyName,
		OrgID:         orgID,
		TeamID:        teamID,
		ProjectID:     projectID,
		UserID:        userID,
		Role:          domain.RoleDeveloper,
		KeyType:       domain.KeyTypeLLMAPI,
		AllowedModels: append([]string(nil), allowedModels...),
		ExpiresAt:     expiresAt,
	})
	if err != nil {
		return nil, err
	}

	completed, err := s.cliLoginStore.Complete(ctx, loginID, orgID, teamID, userID, vk.ID, vk.KeyPrefix, vk.RawKey)
	if err != nil {
		// Best-effort cleanup if the CLI login raced or expired during key issuance.
		_ = s.authSvc.RevokeKey(ctx, vk.ID)
		if errors.Is(err, auth.ErrCLILoginAlreadyCompleted) {
			return nil, &domain.GatewayError{
				StatusCode: http.StatusConflict,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "cli_login_already_completed",
				Message:    "CLI login session has already been completed",
			}
		}
		if errors.Is(err, auth.ErrCLILoginNotFound) {
			return nil, &domain.GatewayError{
				StatusCode: http.StatusNotFound,
				Type:       domain.ErrorTypeNotFound,
				Code:       "cli_login_not_found",
				Message:    "CLI login session was not found or has expired",
			}
		}
		return nil, err
	}
	return completed, nil
}

func (s *GatewayServer) handleAuthCLIPoll(w http.ResponseWriter, r *http.Request) {
	if s.cliLoginStore == nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusServiceUnavailable,
			Type:       domain.ErrorTypeServer,
			Code:       "cli_login_unavailable",
			Message:    "CLI login flow is not initialized",
		})
		return
	}

	loginID := strings.TrimSpace(chi.URLParam(r, "login_id"))
	if loginID == "" {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "missing_login_id",
			Message:    "login_id is required",
		})
		return
	}

	res, err := s.cliLoginStore.Poll(r.Context(), loginID)
	if err != nil {
		if errors.Is(err, auth.ErrCLILoginNotFound) {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusNotFound,
				Type:       domain.ErrorTypeNotFound,
				Code:       "cli_login_not_found",
				Message:    "CLI login session was not found, expired, or already consumed",
			})
			return
		}
		writeSSOError(w, err)
		return
	}

	if res.Status == auth.CLILoginStatusPending {
		writeJSON(w, http.StatusAccepted, map[string]any{
			"status":     string(res.Status),
			"login_id":   res.LoginID,
			"expires_in": res.ExpiresIn,
			"interval":   res.Interval,
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status":      string(res.Status),
		"login_id":    res.LoginID,
		"api_key":     res.APIKey,
		"virtual_key": res.APIKey,
		"key_id":      res.KeyID,
		"key_prefix":  res.KeyPrefix,
		"org_id":      res.OrgID,
		"team_id":     res.TeamID,
	})
}
