package server

import (
	"context"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/logger"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

type authLoginRequest struct {
	Email    string `json:"email"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type authPasswordRequest struct {
	UserID          string `json:"user_id,omitempty"`
	Email           string `json:"email,omitempty"`
	CurrentPassword string `json:"current_password,omitempty"`
	NewPassword     string `json:"new_password"`
	Password        string `json:"password,omitempty"`
}

const minControlPlanePasswordLen = 8

func extractClientIP(r *http.Request) string {
	if r == nil {
		return ""
	}
	host := strings.TrimSpace(r.RemoteAddr)
	if h, _, err := net.SplitHostPort(host); err == nil {
		return strings.TrimSpace(h)
	}
	return host
}

func mapUserRoleForControlPlane(role domain.Role) (domain.OperatorRole, bool) {
	switch role {
	case domain.RolePlatformAdmin:
		return domain.OperatorRolePlatformAdmin, true
	case domain.RoleOrgAdmin:
		return domain.OperatorRoleOrgAdmin, true
	case domain.RoleViewer, domain.RoleOrgViewer:
		return domain.OperatorRoleOrgViewer, true
	case domain.RoleTeamAdmin:
		return domain.OperatorRoleTeamAdmin, true
	default:
		return "", false
	}
}

func (s *GatewayServer) lookupUserByEmail(ctx context.Context, email string) (*domain.User, error) {
	email = strings.TrimSpace(email)
	if email == "" || s.repo == nil {
		return nil, storage.ErrNotFound
	}
	if oidcRepo, ok := s.repo.(storage.OIDCUserRepository); ok && oidcRepo != nil {
		return oidcRepo.GetUserByEmail(ctx, email)
	}
	orgs, err := s.repo.ListOrganizations(ctx)
	if err != nil {
		return nil, err
	}
	for _, org := range orgs {
		if org == nil {
			continue
		}
		users, err := s.repo.ListUsers(ctx, org.ID)
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

// screenPassword uses SHA-1 solely for the HIBP k-anonymity prefix protocol, not password storage.
func (s *GatewayServer) screenPassword(w http.ResponseWriter, r *http.Request, password string, rejectionStatus int) bool {
	if s == nil || s.cfg == nil || !s.cfg.Auth.EnableHIBPCheck || s.breachScreener == nil {
		return true
	}
	digest := sha1.Sum([]byte(password))
	breached, err := s.breachScreener.CheckDigest(r.Context(), hex.EncodeToString(digest[:]))
	if err != nil {
		logger.WarnContext(r.Context(), "HIBP password breach check failed; continuing",
			slog.String("component", "auth"),
			slog.String("error", err.Error()),
		)
		return true
	}
	if !breached {
		return true
	}
	domain.WriteHTTPError(w, &domain.GatewayError{
		StatusCode: rejectionStatus,
		Type:       domain.ErrorTypeInvalidRequest,
		Code:       "breached_password",
		Message:    "Password has appeared in a known data breach; choose a different password",
	})
	return false
}

func (s *GatewayServer) handleAuthLogin(w http.ResponseWriter, r *http.Request) {
	var req authLoginRequest
	if err := decodeAdminJSON(w, r, &req); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_request",
			Message:    err.Error(),
		})
		return
	}

	identifier := strings.TrimSpace(req.Email)
	if identifier == "" {
		identifier = strings.TrimSpace(req.Username)
	}
	if identifier == "" || req.Password == "" {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "missing_credentials",
			Message:    "email (or username) and password are required",
		})
		return
	}

	clientIP := extractClientIP(r)
	if s.loginThrottle != nil {
		if err := s.loginThrottle.Check(r.Context(), identifier, clientIP); err != nil {
			domain.WriteHTTPError(w, err)
			return
		}
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

	// 1. Check configured UIUsername / UIPassword admin credentials if configured.
	if s.cfg != nil && strings.TrimSpace(s.cfg.Auth.UIUsername) != "" && s.cfg.Auth.UIPassword != "" &&
		strings.EqualFold(identifier, strings.TrimSpace(s.cfg.Auth.UIUsername)) {
		var matched bool
		if strings.HasPrefix(s.cfg.Auth.UIPassword, "scrypt:") {
			matched, _ = auth.VerifyPassword(req.Password, s.cfg.Auth.UIPassword)
		} else {
			matched = subtle.ConstantTimeCompare([]byte(req.Password), []byte(s.cfg.Auth.UIPassword)) == 1
		}
		if !matched {
			if s.loginThrottle != nil {
				s.loginThrottle.RecordFailure(r.Context(), identifier, clientIP)
			}
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusUnauthorized,
				Type:       domain.ErrorTypeAuthentication,
				Code:       "invalid_credentials",
				Message:    "Invalid username or password",
			})
			return
		}

		if s.loginThrottle != nil {
			s.loginThrottle.RecordSuccess(r.Context(), identifier, clientIP)
		}

		if !s.screenPassword(w, r, req.Password, http.StatusForbidden) {
			return
		}
		resetRequired := false

		orgID := strings.TrimSpace(s.cfg.Auth.DefaultOrgID)
		if orgID == "" {
			orgID = "org_default"
		}
		issued, err := s.sessionMgr.IssueSyntheticSession(r.Context(), auth.UIAdminActorID, orgID, domain.OperatorRolePlatformAdmin)
		if err != nil {
			domain.WriteHTTPError(w, err)
			return
		}
		auth.SetSessionCookie(w, issued.Token, issued.ExpiresAt)
		s.audit(r.Context(), orgID, "auth.login", "operator_session", issued.Session.ID, map[string]any{
			"actor_id":                auth.UIAdminActorID,
			"auth_method":             "ui_credentials",
			"password_reset_required": resetRequired,
		})
		writeJSON(w, http.StatusOK, map[string]any{
			"token":                   issued.Token,
			"session_token":           issued.Token,
			"csrf_token":              issued.CSRFToken,
			"expires_at":              issued.ExpiresAt.UTC().Format(time.RFC3339),
			"password_reset_required": resetRequired,
			"operator": domain.OperatorContext{
				ActorID:    auth.UIAdminActorID,
				Role:       domain.OperatorRolePlatformAdmin,
				OrgID:      orgID,
				AuthMethod: "session",
				SessionID:  issued.Session.ID,
			},
		})
		return
	}

	// 2. Database user credential authentication.
	sessRepo, hasSessRepo := s.repo.(storage.OperatorSessionRepository)
	if !hasSessRepo || sessRepo == nil {
		if s.loginThrottle != nil {
			s.loginThrottle.RecordFailure(r.Context(), identifier, clientIP)
		}
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusUnauthorized,
			Type:       domain.ErrorTypeAuthentication,
			Code:       "invalid_credentials",
			Message:    "Invalid email or password",
		})
		return
	}

	user, err := s.lookupUserByEmail(r.Context(), identifier)
	if err != nil || user == nil {
		if s.loginThrottle != nil {
			s.loginThrottle.RecordFailure(r.Context(), identifier, clientIP)
		}
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusUnauthorized,
			Type:       domain.ErrorTypeAuthentication,
			Code:       "invalid_credentials",
			Message:    "Invalid email or password",
		})
		return
	}

	cred, err := sessRepo.GetUserCredential(r.Context(), user.ID)
	if err != nil || cred == nil {
		if s.loginThrottle != nil {
			s.loginThrottle.RecordFailure(r.Context(), identifier, clientIP)
		}
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusUnauthorized,
			Type:       domain.ErrorTypeAuthentication,
			Code:       "invalid_credentials",
			Message:    "Invalid email or password",
		})
		return
	}

	valid, needsUpgrade := auth.VerifyPassword(req.Password, cred.PasswordHash)
	if !valid {
		if s.loginThrottle != nil {
			s.loginThrottle.RecordFailure(r.Context(), identifier, clientIP)
		}
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusUnauthorized,
			Type:       domain.ErrorTypeAuthentication,
			Code:       "invalid_credentials",
			Message:    "Invalid email or password",
		})
		return
	}

	if s.loginThrottle != nil {
		s.loginThrottle.RecordSuccess(r.Context(), identifier, clientIP)
	}

	if !user.IsActive {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusForbidden,
			Type:       domain.ErrorTypePermission,
			Code:       "user_inactive",
			Message:    "Operator user account is inactive",
		})
		return
	}
	if !user.SCIMActive {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusForbidden,
			Type:       domain.ErrorTypePermission,
			Code:       "scim_deprovisioned",
			Message:    "Operator user account has been deprovisioned via SCIM",
		})
		return
	}

	org, err := s.repo.GetOrganization(r.Context(), user.OrgID)
	if err != nil || !org.IsActive {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusForbidden,
			Type:       domain.ErrorTypePermission,
			Code:       "organization_inactive",
			Message:    "Organization associated with this user is inactive",
		})
		return
	}

	opRole, ok := mapUserRoleForControlPlane(user.Role)
	if !ok {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusForbidden,
			Type:       domain.ErrorTypePermission,
			Code:       "insufficient_permissions",
			Message:    "User role is not authorized for Control Plane access",
		})
		return
	}

	if !s.screenPassword(w, r, req.Password, http.StatusForbidden) {
		return
	}

	resetRequired := cred.PasswordResetRequired
	if needsUpgrade {
		if upgraded, hashErr := auth.HashPasswordScrypt(req.Password); hashErr == nil {
			_ = sessRepo.UpsertUserPassword(r.Context(), user.ID, upgraded, resetRequired)
		}
	}

	issued, err := s.sessionMgr.IssueSession(r.Context(), user.ID, user.OrgID, user.TeamID, opRole)
	if err != nil {
		domain.WriteHTTPError(w, err)
		return
	}

	auth.SetSessionCookie(w, issued.Token, issued.ExpiresAt)
	s.audit(r.Context(), user.OrgID, "auth.login", "operator_session", issued.Session.ID, map[string]any{
		"user_id":                 user.ID,
		"password_reset_required": resetRequired,
		"password_hash_upgraded":  needsUpgrade,
	})

	writeJSON(w, http.StatusOK, map[string]any{
		"token":                   issued.Token,
		"session_token":           issued.Token,
		"csrf_token":              issued.CSRFToken,
		"expires_at":              issued.ExpiresAt.UTC().Format(time.RFC3339),
		"password_reset_required": resetRequired,
		"operator": domain.OperatorContext{
			ActorID:    user.ID,
			Role:       opRole,
			OrgID:      user.OrgID,
			TeamID:     user.TeamID,
			AuthMethod: "session",
			SessionID:  issued.Session.ID,
		},
		"user": user,
	})
}

func (s *GatewayServer) handleAuthLogout(w http.ResponseWriter, r *http.Request) {
	op := auth.OperatorFromContext(r.Context())
	if op != nil && op.SessionID != "" && s.sessionMgr != nil {
		expiresAt := time.Now().UTC().Add(s.sessionMgr.TTL())
		if err := s.sessionMgr.RevokeSession(r.Context(), op.SessionID, expiresAt); err != nil {
			domain.WriteHTTPError(w, err)
			return
		}
		s.audit(r.Context(), op.OrgID, "auth.logout", "operator_session", op.SessionID, map[string]any{
			"actor_id": op.ActorID,
		})
	}
	auth.ClearSessionCookie(w)
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "logged_out",
	})
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

	if ul, ok := s.repo.(storage.UserLookupRepository); ok && ul != nil && op.ActorID != "" && op.ActorID != auth.UIAdminActorID && op.ActorID != "master_admin" {
		if user, err := ul.GetUser(r.Context(), op.ActorID); err == nil && user != nil {
			resp["user"] = user
		}
	}
	if sessRepo, ok := s.repo.(storage.OperatorSessionRepository); ok && sessRepo != nil && op.ActorID != "" {
		if cred, err := sessRepo.GetUserCredential(r.Context(), op.ActorID); err == nil && cred != nil {
			resp["password_reset_required"] = cred.PasswordResetRequired
		}
	}

	writeJSON(w, http.StatusOK, resp)
}

func (s *GatewayServer) handleAuthPassword(w http.ResponseWriter, r *http.Request) {
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

	var req authPasswordRequest
	if err := decodeAdminJSON(w, r, &req); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_request",
			Message:    err.Error(),
		})
		return
	}

	newPassword := req.NewPassword
	if newPassword == "" {
		newPassword = req.Password
	}
	if len(newPassword) < minControlPlanePasswordLen {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "weak_password",
			Message:    "new_password must be at least 8 characters",
		})
		return
	}

	sessRepo, hasSessRepo := s.repo.(storage.OperatorSessionRepository)
	if !hasSessRepo || sessRepo == nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusServiceUnavailable,
			Type:       domain.ErrorTypeServer,
			Code:       "credential_store_unavailable",
			Message:    "User credential storage is unavailable",
		})
		return
	}

	targetUserID := strings.TrimSpace(req.UserID)
	targetEmail := strings.TrimSpace(req.Email)
	var targetUser *domain.User
	var err error

	if targetUserID == "" && targetEmail == "" {
		targetUserID = op.ActorID
	}

	if targetUserID != "" {
		if ul, ok := s.repo.(storage.UserLookupRepository); ok && ul != nil {
			targetUser, err = ul.GetUser(r.Context(), targetUserID)
		} else {
			err = storage.ErrNotFound
		}
	} else {
		targetUser, err = s.lookupUserByEmail(r.Context(), targetEmail)
	}
	if err != nil || targetUser == nil {
		status := http.StatusNotFound
		code := "user_not_found"
		msg := "Target user was not found"
		if !errors.Is(err, storage.ErrNotFound) && err != nil && !strings.Contains(strings.ToLower(err.Error()), "not found") {
			status = http.StatusInternalServerError
			code = "user_lookup_failed"
			msg = err.Error()
		}
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: status,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       code,
			Message:    msg,
		})
		return
	}

	isSelf := op.ActorID == targetUser.ID
	if !isSelf {
		if _, ok := s.authorizeAdmin(w, r, targetUser.OrgID, true); !ok {
			return
		}
	} else {
		// Self-rotation requires verifying current_password when a credential already exists.
		if existing, credErr := sessRepo.GetUserCredential(r.Context(), targetUser.ID); credErr == nil && existing != nil {
			valid, _ := auth.VerifyPassword(req.CurrentPassword, existing.PasswordHash)
			if !valid {
				domain.WriteHTTPError(w, &domain.GatewayError{
					StatusCode: http.StatusUnauthorized,
					Type:       domain.ErrorTypeAuthentication,
					Code:       "invalid_current_password",
					Message:    "current_password is incorrect",
				})
				return
			}
		}
	}

	if !s.screenPassword(w, r, newPassword, http.StatusBadRequest) {
		return
	}

	hashed, err := auth.HashPasswordScrypt(newPassword)
	if err != nil {
		domain.WriteHTTPError(w, err)
		return
	}

	beforeCred, _ := sessRepo.GetUserCredential(r.Context(), targetUser.ID)
	if err := sessRepo.UpsertUserPassword(r.Context(), targetUser.ID, hashed, false); err != nil {
		domain.WriteHTTPError(w, err)
		return
	}

	if s.sessionMgr != nil {
		_ = s.sessionMgr.RevokeAllUserSessions(r.Context(), targetUser.ID)
	}
	if isSelf {
		auth.ClearSessionCookie(w)
	}

	var beforeAudit map[string]any
	if beforeCred != nil {
		beforeAudit = map[string]any{
			"password_configured":     beforeCred.PasswordHash != "",
			"password_reset_required": beforeCred.PasswordResetRequired,
			"failed_attempts":         beforeCred.FailedAttempts,
			"locked":                  beforeCred.LockedUntil != nil && beforeCred.LockedUntil.After(time.Now().UTC()),
		}
	}
	afterAudit := map[string]any{
		"password_configured":     true,
		"password_reset_required": false,
		"failed_attempts":         0,
		"locked":                  false,
	}
	s.auditWithDiff(r.Context(), targetUser.OrgID, "auth.password.updated", "user_credential", targetUser.ID, map[string]any{
		"self_service": isSelf,
	}, beforeAudit, afterAudit)

	writeJSON(w, http.StatusOK, map[string]any{
		"status":                  "password_updated",
		"user_id":                 targetUser.ID,
		"password_reset_required": false,
	})
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
	UserCode      string   `json:"user_code,omitempty"`
	AllowedModels []string `json:"allowed_models,omitempty"`
	TTLSeconds    int64    `json:"ttl_seconds,omitempty"`
}

func (s *GatewayServer) canonicalBaseURL(r *http.Request) string {
	if s != nil && s.cfg != nil {
		if pub := strings.TrimRight(strings.TrimSpace(s.cfg.Server.PublicBaseURL), "/"); pub != "" {
			return pub
		}
	}
	if r == nil {
		return ""
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	} else if s.isTrustedProxyRequest(r) && strings.EqualFold(strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")), "https") {
		scheme = "https"
	}
	host := sanitizeCanonicalHost(r.Host)
	if host == "" && s != nil && s.cfg != nil {
		cfgHost := strings.TrimSpace(s.cfg.Server.Host)
		if cfgHost == "" || cfgHost == "0.0.0.0" || cfgHost == "::" {
			cfgHost = "localhost"
		}
		if s.cfg.Server.Port > 0 {
			host = fmt.Sprintf("%s:%d", cfgHost, s.cfg.Server.Port)
		} else {
			host = cfgHost
		}
	}
	if host == "" {
		return ""
	}
	return scheme + "://" + host
}

func (s *GatewayServer) isTrustedProxyRequest(r *http.Request) bool {
	if s == nil || s.cfg == nil || r == nil {
		return false
	}
	var cidrs []string
	cidrs = append(cidrs, s.cfg.Security.Network.InboundCaller.TrustedProxyCIDRs...)
	cidrs = append(cidrs, s.cfg.Auth.ProxyAuth.TrustedProxyCIDRs...)
	if len(cidrs) == 0 {
		return false
	}
	remoteHost := strings.TrimSpace(r.RemoteAddr)
	if h, _, err := net.SplitHostPort(remoteHost); err == nil {
		remoteHost = h
	}
	ip := net.ParseIP(remoteHost)
	if ip == nil {
		return false
	}
	for _, rawCIDR := range cidrs {
		rawCIDR = strings.TrimSpace(rawCIDR)
		if rawCIDR == "" {
			continue
		}
		if _, subnet, err := net.ParseCIDR(rawCIDR); err == nil && subnet.Contains(ip) {
			return true
		}
		if singleIP := net.ParseIP(rawCIDR); singleIP != nil && singleIP.Equal(ip) {
			return true
		}
	}
	return false
}

func sanitizeCanonicalHost(rawHost string) string {
	host := strings.TrimSpace(rawHost)
	if host == "" {
		return ""
	}
	if strings.ContainsAny(host, "/\\@?# \t\r\n\x00") {
		return ""
	}
	// Validate host or host:port structure.
	if h, p, err := net.SplitHostPort(host); err == nil {
		if h == "" || p == "" || !isValidHostnameOrLiteralIP(h) {
			return ""
		}
		return host
	}
	if !isValidHostnameOrLiteralIP(host) {
		return ""
	}
	return host
}

func isValidHostnameOrLiteralIP(h string) bool {
	if ip := net.ParseIP(strings.Trim(h, "[]")); ip != nil {
		return true
	}
	if strings.HasPrefix(h, ".") || strings.HasSuffix(h, ".") {
		return false
	}
	for _, r := range h {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '.' {
			continue
		}
		return false
	}
	return true
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
	if base := s.canonicalBaseURL(r); base != "" {
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
		desc := strings.TrimSpace(r.URL.Query().Get("error_description"))
		msg := "SSO provider returned error: " + idpErr
		if desc != "" {
			msg += " (" + desc + ")"
		}
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode:  http.StatusUnauthorized,
			Type:        domain.ErrorTypeAuthentication,
			Code:        "sso_provider_error",
			Message:     msg,
			AuthFailure: true,
		})
		return
	}

	code := strings.TrimSpace(r.URL.Query().Get("code"))
	state := strings.TrimSpace(r.URL.Query().Get("state"))
	if code == "" || state == "" {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "missing_sso_params",
			Message:    "code and state query parameters are required",
		})
		return
	}

	authState, err := s.ssoStateStore.Consume(r.Context(), state)
	if err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
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
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusNotFound,
			Type:       domain.ErrorTypeNotFound,
			Code:       "sso_provider_not_found",
			Message:    fmt.Sprintf("SSO provider %q is not configured", providerID),
		})
		return
	}
	if authState.Provider != p.ID() {
		domain.WriteHTTPError(w, &domain.GatewayError{
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
		writeSSOError(w, err)
		return
	}

	user, err := s.resolveOrProvisionSSOUser(r.Context(), p, idClaims)
	if err != nil {
		domain.WriteHTTPError(w, err)
		return
	}

	if authState.CLILoginID != "" && user.Role != domain.RoleViewer && user.Role != domain.RoleOrgViewer {
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
			domain.WriteHTTPError(w, cliErr)
			return
		}
	}

	opRole, hasOpRole := mapUserRoleForControlPlane(user.Role)
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
		domain.WriteHTTPError(w, &domain.GatewayError{
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

	issued, err := s.sessionMgr.IssueSession(r.Context(), user.ID, user.OrgID, user.TeamID, opRole)
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

	providerOrgID := ""
	if p != nil {
		providerOrgID = strings.TrimSpace(p.DefaultOrgID())
	}
	claimOrgID := strings.TrimSpace(claims.OrgID)
	if providerOrgID != "" && claimOrgID != "" && claimOrgID != providerOrgID {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusForbidden,
			Type:       domain.ErrorTypePermission,
			Code:       "cross_org_access_denied",
			Message:    "SSO token org_id claim does not match provider organization",
		}
	}
	orgID := providerOrgID
	if orgID == "" {
		orgID = claimOrgID
	}
	if orgID == "" && s.cfg != nil {
		orgID = strings.TrimSpace(s.cfg.Auth.DefaultOrgID)
	}
	if orgID == "" {
		if org, err := s.repo.GetOrganization(ctx, "org_default"); err == nil && org != nil && org.IsActive {
			orgID = org.ID
		} else if orgs, err := s.repo.ListOrganizations(ctx); err == nil {
			for _, o := range orgs {
				if o != nil && o.IsActive {
					orgID = o.ID
					break
				}
			}
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

		teamID := ""
		if len(claims.TeamIDs) > 0 {
			teamID = strings.TrimSpace(claims.TeamIDs[0])
		}
		if teamID == "" {
			teamID = p.DefaultTeamID()
		}
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
			Role:              resolveSSOProvisionRole(claims.Role, p.DefaultRole()),
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

func resolveSSOProvisionRole(claimRole, defaultRole string) domain.Role {
	for _, candidate := range []string{claimRole, defaultRole} {
		switch domain.Role(strings.ToLower(strings.TrimSpace(candidate))) {
		case domain.RoleOrgAdmin,
			domain.RoleOrgViewer,
			domain.RoleTeamAdmin,
			domain.RoleDeveloper,
			domain.RoleServiceAccount,
			domain.RoleViewer:
			return domain.Role(strings.ToLower(strings.TrimSpace(candidate)))
		}
	}
	return domain.RoleOrgViewer
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

	verificationURL := s.canonicalBaseURL(r) + "/ui/cli?login_id=" + url.QueryEscape(sess.LoginID)
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
			Code:       "cli_approve_read_only_denied",
			Message:    "Read-only viewer operators cannot approve CLI login sessions or mint virtual API keys",
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

	if err := s.cliLoginStore.VerifyUserCode(r.Context(), loginID, req.UserCode); err != nil {
		if errors.Is(err, auth.ErrCLILoginInvalidUserCode) {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusForbidden,
				Type:       domain.ErrorTypePermission,
				Code:       "invalid_cli_user_code",
				Message:    "Provided user_code does not match the pending CLI login session",
			})
			return
		}
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusNotFound,
			Type:       domain.ErrorTypeNotFound,
			Code:       "cli_login_not_found",
			Message:    "CLI login session was not found or has expired",
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
	if op.ActorID != "" && op.ActorID != "master_admin" && op.ActorID != auth.UIAdminActorID {
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
	var expiresAt *time.Time
	if ttlSeconds > 0 {
		t := time.Now().UTC().Add(time.Duration(ttlSeconds) * time.Second)
		expiresAt = &t
	}

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
