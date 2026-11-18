package server

import (
	"context"
	"crypto/subtle"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/logger"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

type authLoginRequest struct {
	Email        string `json:"email"`
	Username     string `json:"username"`
	Password     string `json:"password"`
	PasswordSHA1 string `json:"password_sha1,omitempty"`
}

type authPasswordRequest struct {
	UserID          string `json:"user_id,omitempty"`
	Email           string `json:"email,omitempty"`
	CurrentPassword string `json:"current_password,omitempty"`
	NewPassword     string `json:"new_password"`
	Password        string `json:"password,omitempty"`
	PasswordSHA1    string `json:"password_sha1,omitempty"`
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

func (s *GatewayServer) checkPasswordHIBP(ctx context.Context, sha1Hex string) (bool, error) {
	if s == nil || s.cfg == nil || !s.cfg.Auth.EnableHIBPCheck || s.breachScreener == nil {
		return false, nil
	}
	sha1Hex = strings.TrimSpace(sha1Hex)
	if sha1Hex == "" {
		return false, nil
	}
	return s.breachScreener.CheckDigest(ctx, sha1Hex)
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

		resetRequired := false
		if breached, err := s.checkPasswordHIBP(r.Context(), req.PasswordSHA1); err != nil {
			logger.WarnContext(r.Context(), "HIBP password breach check failed; continuing login",
				slog.String("component", "auth"),
				slog.String("error", err.Error()),
			)
		} else if breached {
			resetRequired = true
		}

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

	resetRequired := cred.PasswordResetRequired
	if breached, err := s.checkPasswordHIBP(r.Context(), req.PasswordSHA1); err != nil {
		logger.WarnContext(r.Context(), "HIBP password breach check failed; continuing login",
			slog.String("component", "auth"),
			slog.String("user_id", user.ID),
			slog.String("error", err.Error()),
		)
	} else if breached {
		resetRequired = true
	}

	targetHash := cred.PasswordHash
	if needsUpgrade {
		if upgraded, hashErr := auth.HashPasswordScrypt(req.Password); hashErr == nil {
			targetHash = upgraded
		}
	}
	if needsUpgrade || resetRequired != cred.PasswordResetRequired {
		_ = sessRepo.UpsertUserPassword(r.Context(), user.ID, targetHash, resetRequired)
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

	if breached, hibpErr := s.checkPasswordHIBP(r.Context(), req.PasswordSHA1); hibpErr != nil {
		logger.WarnContext(r.Context(), "HIBP password breach check failed during password update",
			slog.String("component", "auth"),
			slog.String("user_id", targetUser.ID),
			slog.String("error", hibpErr.Error()),
		)
	} else if breached {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "breached_password",
			Message:    "Password has appeared in a known data breach; choose a different password",
		})
		return
	}

	hashed, err := auth.HashPasswordScrypt(newPassword)
	if err != nil {
		domain.WriteHTTPError(w, err)
		return
	}

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

	s.audit(r.Context(), targetUser.OrgID, "auth.password.updated", "user_credential", targetUser.ID, map[string]any{
		"self_service": isSelf,
	})

	writeJSON(w, http.StatusOK, map[string]any{
		"status":                  "password_updated",
		"user_id":                 targetUser.ID,
		"password_reset_required": false,
	})
}
