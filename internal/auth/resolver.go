package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

// ResolverConfig configures unified Data Plane credential and identity resolution.
type ResolverConfig struct {
	Service                    *Service
	Repo                       storage.Repository
	RBAC                       *RBACEngine
	JWTVerifier                *JWTVerifier
	Introspector               *OAuthIntrospector
	ProxyAuth                  *ProxyAuthenticator
	EnableDataPlaneJWT         bool
	DefaultOrgID               string
	IntrospectionAutoRegister  bool
	IntrospectionDefaultTeamID string
	IntrospectionDefaultRole   string
	ProxyAutoRegister          bool
	ProxyDefaultTeamID         string
	ProxyDefaultRole           string
}

// AuthResolver resolves Data Plane HTTP requests into a frozen domain.IdentityContext
// with an attached domain.Principal across Virtual API Keys, OIDC/JWT (with claim-to-key
// mapping and race-safe JIT user provisioning), OAuth token introspection, and trusted
// reverse-proxy identity headers.
type AuthResolver struct {
	authSvc                    *Service
	repo                       storage.Repository
	rbac                       *RBACEngine
	jwtVerifier                *JWTVerifier
	introspector               *OAuthIntrospector
	proxyAuth                  *ProxyAuthenticator
	enableDataPlaneJWT         bool
	defaultOrgID               string
	introspectionAutoRegister  bool
	introspectionDefaultTeamID string
	introspectionDefaultRole   string
	proxyAutoRegister          bool
	proxyDefaultTeamID         string
	proxyDefaultRole           string
}

// NewAuthResolver constructs a unified AuthResolver from cfg.
func NewAuthResolver(cfg ResolverConfig) *AuthResolver {
	repo := cfg.Repo
	if repo == nil && cfg.Service != nil {
		repo = cfg.Service.Repo()
	}
	jwtVerifier := cfg.JWTVerifier
	if jwtVerifier == nil && cfg.Service != nil {
		jwtVerifier = cfg.Service.JWTVerifier()
	}
	return &AuthResolver{
		authSvc:                    cfg.Service,
		repo:                       repo,
		rbac:                       cfg.RBAC,
		jwtVerifier:                jwtVerifier,
		introspector:               cfg.Introspector,
		proxyAuth:                  cfg.ProxyAuth,
		enableDataPlaneJWT:         cfg.EnableDataPlaneJWT,
		defaultOrgID:               strings.TrimSpace(cfg.DefaultOrgID),
		introspectionAutoRegister:  cfg.IntrospectionAutoRegister,
		introspectionDefaultTeamID: strings.TrimSpace(cfg.IntrospectionDefaultTeamID),
		introspectionDefaultRole:   strings.TrimSpace(cfg.IntrospectionDefaultRole),
		proxyAutoRegister:          cfg.ProxyAutoRegister,
		proxyDefaultTeamID:         strings.TrimSpace(cfg.ProxyDefaultTeamID),
		proxyDefaultRole:           strings.TrimSpace(cfg.ProxyDefaultRole),
	}
}

// SetRBAC attaches an RBACEngine for dynamic access group rule projection during identity resolution.
func (r *AuthResolver) SetRBAC(rbac *RBACEngine) {
	if r != nil {
		r.rbac = rbac
	}
}

// ExtractorOptions returns the inbound credential extraction options for this resolver.
func (r *AuthResolver) ExtractorOptions() ExtractorOptions {
	if r == nil || r.authSvc == nil {
		return ExtractorOptions{}
	}
	return r.authSvc.ExtractorOptions()
}

// ResolveRequest authenticates an inbound Data Plane HTTP request and returns a frozen
// IdentityContext carrying tenant budgets, rate limits, model allowlists, and Principal.
func (r *AuthResolver) ResolveRequest(ctx context.Context, req *http.Request) (*domain.IdentityContext, error) {
	if r == nil {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusUnauthorized,
			Type:       domain.ErrorTypeAuthentication,
			Code:       "unauthenticated",
			Message:    "Authentication resolver is not configured",
		}
	}

	cred, err := ExtractCredentials(req, r.ExtractorOptions())
	if err != nil {
		return nil, err
	}

	token := strings.TrimSpace(cred.Token)
	var idCtx *domain.IdentityContext
	if token == "" {
		if r.proxyAuth != nil && r.proxyAuth.Enabled() {
			idCtx, err = r.resolveProxyAuth(ctx, req)
		} else if r.authSvc != nil {
			idCtx, err = r.authSvc.AuthenticateVirtualKey(ctx, "")
		} else {
			return nil, &domain.GatewayError{
				StatusCode: http.StatusUnauthorized,
				Type:       domain.ErrorTypeAuthentication,
				Code:       "missing_api_key",
				Message:    "Missing Authorization Bearer token",
			}
		}
	} else {
		isMasterFallback := r.authSvc != nil && r.authSvc.AllowMasterKeyDataPlane() && r.authSvc.ValidateAdminKey(token)
		if cred.Source == CredentialSourceBearer && !strings.HasPrefix(token, "sk-gw-") && !isMasterFallback {
			if strings.Count(token, ".") == 2 {
				if r.enableDataPlaneJWT {
					idCtx, err = r.resolveJWTBearer(ctx, token)
				} else {
					// Fail closed when EnableDataPlaneJWT is false.
					return nil, invalidAPIKeyError()
				}
			} else if r.introspector != nil && r.introspector.Enabled() {
				idCtx, err = r.resolveIntrospectedBearer(ctx, token)
			} else {
				idCtx, err = r.authenticateVirtualKeyWithPrincipal(ctx, token)
			}
		} else {
			idCtx, err = r.authenticateVirtualKeyWithPrincipal(ctx, token)
		}
	}
	if err != nil {
		return nil, err
	}
	if r.rbac != nil && idCtx != nil {
		idCtx = r.rbac.EnrichIdentityWithAccessRules(ctx, idCtx)
	}
	return idCtx, nil
}

func (r *AuthResolver) authenticateVirtualKeyWithPrincipal(ctx context.Context, rawToken string) (*domain.IdentityContext, error) {
	if r.authSvc == nil {
		return nil, invalidAPIKeyError()
	}
	idCtx, err := r.authSvc.AuthenticateVirtualKey(ctx, rawToken)
	if err != nil {
		return nil, err
	}
	cp := *idCtx
	if cp.Principal == nil {
		cp.Principal = &domain.Principal{
			AuthMethod:    "virtual_key",
			PrincipalType: "virtual_key",
			Subject:       cp.VirtualKeyID,
		}
	}
	return &cp, nil
}

func (r *AuthResolver) resolveJWTBearer(ctx context.Context, rawToken string) (*domain.IdentityContext, error) {
	if r.jwtVerifier == nil || !r.jwtVerifier.Enabled() {
		return nil, &domain.GatewayError{
			StatusCode:  http.StatusUnauthorized,
			Type:        domain.ErrorTypeAuthentication,
			Code:        "invalid_token",
			Message:     "JWT verification is not configured",
			AuthFailure: true,
		}
	}

	claims, err := r.jwtVerifier.Verify(ctx, rawToken)
	if err != nil {
		return nil, &domain.GatewayError{
			StatusCode:  http.StatusUnauthorized,
			Type:        domain.ErrorTypeAuthentication,
			Code:        "invalid_token",
			Message:     "Invalid or expired JWT: " + err.Error(),
			AuthFailure: true,
		}
	}

	ov := r.jwtVerifier.VerifierForIssuer(claims.Issuer)
	effectiveIssuer := strings.TrimSpace(claims.Issuer)
	if effectiveIssuer == "" && ov != nil {
		effectiveIssuer = ov.Issuer()
	}

	principal := &domain.Principal{
		AuthMethod:    "jwt",
		PrincipalType: "user",
		Issuer:        effectiveIssuer,
		Subject:       claims.Subject,
		Email:         claims.Email,
		RawClaims:     cloneClaimsMap(claims.RawClaims),
	}

	if mappingRepo, ok := r.repo.(storage.JWTMappingRepository); ok && mappingRepo != nil {
		mapping, found, err := r.findJWTKeyMapping(ctx, mappingRepo, effectiveIssuer, claims)
		if err != nil {
			return nil, &domain.GatewayError{
				StatusCode: http.StatusServiceUnavailable,
				Type:       domain.ErrorTypeServer,
				Code:       "jwt_mapping_lookup_failed",
				Message:    "Unable to resolve JWT key mapping",
				Retryable:  true,
			}
		}
		if found && mapping != nil {
			if r.authSvc == nil {
				return nil, invalidAPIKeyError()
			}
			vkCtx, err := r.authSvc.AuthenticateVirtualKeyByID(ctx, mapping.VirtualKeyID)
			if err != nil {
				return nil, err
			}
			if vkCtx.OrgID != mapping.OrgID {
				return nil, &domain.GatewayError{
					StatusCode: http.StatusForbidden,
					Type:       domain.ErrorTypePermission,
					Code:       "cross_org_access_denied",
					Message:    "JWT key mapping organization does not match target virtual key",
				}
			}
			out := *vkCtx
			mappedPrincipal := *principal
			mappedPrincipal.PrincipalType = "virtual_key"
			out.Principal = &mappedPrincipal
			return &out, nil
		}
	}

	orgID := strings.TrimSpace(claims.OrgID)
	if orgID == "" && ov != nil {
		orgID = ov.DefaultOrgID()
	}
	if orgID == "" {
		orgID = r.defaultOrgID
	}

	var claimTeamID string
	if len(claims.TeamIDs) > 0 {
		claimTeamID = strings.TrimSpace(claims.TeamIDs[0])
	}

	var autoRegister bool
	var defaultTeamID, defaultRole string
	if ov != nil {
		autoRegister = ov.AutoRegister()
		defaultTeamID = ov.DefaultTeamID()
		defaultRole = ov.DefaultRole()
	}

	return r.resolveOrProvisionUser(ctx, userResolutionParams{
		orgID:         orgID,
		subject:       claims.Subject,
		email:         claims.Email,
		displayName:   extractRawDisplayName(claims.RawClaims, claims.Email, claims.Subject),
		claimTeamID:   claimTeamID,
		claimRole:     claims.Role,
		autoRegister:  autoRegister,
		defaultTeamID: defaultTeamID,
		defaultRole:   defaultRole,
		principal:     principal,
	})
}

type claimPair struct {
	name  string
	value string
}

func (r *AuthResolver) findJWTKeyMapping(ctx context.Context, repo storage.JWTMappingRepository, issuer string, claims *JWTClaims) (*domain.JWTKeyMapping, bool, error) {
	if issuer == "" || claims == nil {
		return nil, false, nil
	}

	candidates := collectJWTClaimCandidates(claims)
	for _, c := range candidates {
		mapping, err := repo.ResolveJWTKeyMapping(ctx, issuer, c.name, c.value)
		if err == nil && mapping != nil {
			return mapping, true, nil
		}
		if err != nil && !errors.Is(err, storage.ErrNotFound) {
			return nil, false, err
		}
	}
	return nil, false, nil
}

func collectJWTClaimCandidates(claims *JWTClaims) []claimPair {
	var out []claimPair
	seen := make(map[claimPair]struct{})
	add := func(name, val string) {
		name = strings.TrimSpace(name)
		val = strings.TrimSpace(val)
		if name == "" || val == "" {
			return
		}
		p := claimPair{name: name, value: val}
		if _, dup := seen[p]; dup {
			return
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}

	add("sub", claims.Subject)
	add("email", claims.Email)
	add("role", claims.Role)
	add("org_id", claims.OrgID)
	for _, tid := range claims.TeamIDs {
		add("team_ids", tid)
	}

	if len(claims.RawClaims) > 0 {
		keys := make([]string, 0, len(claims.RawClaims))
		for k := range claims.RawClaims {
			switch k {
			case "exp", "nbf", "iat", "jti", "iss":
				continue
			default:
				keys = append(keys, k)
			}
		}
		sort.Strings(keys)
		for _, k := range keys {
			rawVal := claims.RawClaims[k]
			switch v := rawVal.(type) {
			case string:
				add(k, v)
			case []string:
				for _, item := range v {
					add(k, item)
				}
			case []any:
				for _, item := range v {
					if s, ok := item.(string); ok {
						add(k, s)
					}
				}
			}
		}
	}

	return out
}

func (r *AuthResolver) resolveIntrospectedBearer(ctx context.Context, rawToken string) (*domain.IdentityContext, error) {
	res, err := r.introspector.Introspect(ctx, rawToken)
	if err != nil {
		return nil, err
	}
	subject := strings.TrimSpace(res.Subject)
	if subject == "" {
		subject = strings.TrimSpace(res.UserID)
	}
	email := strings.TrimSpace(res.Email)
	if subject == "" && email == "" {
		return nil, invalidIntrospectionTokenError("Introspected token has no subject or email")
	}

	orgID := strings.TrimSpace(res.OrgID)
	if orgID == "" {
		orgID = r.defaultOrgID
	}

	principal := &domain.Principal{
		AuthMethod:    "introspection",
		PrincipalType: "user",
		Issuer:        strings.TrimSpace(res.Issuer),
		Subject:       subject,
		Email:         email,
		RawClaims:     cloneClaimsMap(res.Claims),
	}

	return r.resolveOrProvisionUser(ctx, userResolutionParams{
		orgID:         orgID,
		subject:       subject,
		email:         email,
		displayName:   extractRawDisplayName(res.Claims, email, subject),
		claimTeamID:   strings.TrimSpace(res.TeamID),
		claimRole:     strings.TrimSpace(res.Role),
		autoRegister:  r.introspectionAutoRegister,
		defaultTeamID: r.introspectionDefaultTeamID,
		defaultRole:   r.introspectionDefaultRole,
		principal:     principal,
	})
}

func (r *AuthResolver) resolveProxyAuth(ctx context.Context, req *http.Request) (*domain.IdentityContext, error) {
	proxyID, err := r.proxyAuth.Authenticate(req)
	if err != nil {
		return nil, err
	}

	orgID := strings.TrimSpace(proxyID.OrgID)
	if orgID == "" {
		orgID = r.defaultOrgID
	}
	if orgID == "" {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusUnauthorized,
			Type:       domain.ErrorTypeAuthentication,
			Code:       "missing_org_id",
			Message:    "Organization could not be determined for reverse-proxy identity",
		}
	}

	if r.repo == nil {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusServiceUnavailable,
			Type:       domain.ErrorTypeServer,
			Code:       "auth_repository_unavailable",
			Message:    "Identity repository is not configured",
		}
	}

	org, err := r.repo.GetOrganization(ctx, orgID)
	if err != nil || org == nil || !org.IsActive {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusForbidden,
			Type:       domain.ErrorTypePermission,
			Code:       "organization_inactive",
			Message:    "Organization associated with this identity is inactive or does not exist",
		}
	}

	var user *domain.User
	if proxyID.UserID != "" {
		if ul, ok := r.repo.(storage.UserLookupRepository); ok {
			if candidate, getErr := ul.GetUser(ctx, proxyID.UserID); getErr == nil && candidate != nil && candidate.OrgID == orgID {
				user = candidate
			}
		}
		if user == nil {
			user, err = r.lookupUserByOrgAndSubject(ctx, orgID, proxyID.UserID)
			if err != nil && !errors.Is(err, storage.ErrNotFound) {
				return nil, &domain.GatewayError{
					StatusCode: http.StatusServiceUnavailable,
					Type:       domain.ErrorTypeServer,
					Code:       "user_lookup_unavailable",
					Message:    "Unable to resolve proxy user identity",
					Retryable:  true,
				}
			}
		}
	}
	if user == nil && proxyID.UserEmail != "" {
		candidate, emailErr := r.lookupUserByOrgAndEmail(ctx, orgID, proxyID.UserEmail)
		if emailErr != nil && !errors.Is(emailErr, storage.ErrNotFound) {
			var gwErr *domain.GatewayError
			if errors.As(emailErr, &gwErr) {
				return nil, gwErr
			}
			return nil, &domain.GatewayError{
				StatusCode: http.StatusServiceUnavailable,
				Type:       domain.ErrorTypeServer,
				Code:       "user_lookup_unavailable",
				Message:    "Unable to resolve proxy user identity by email",
				Retryable:  true,
			}
		}
		if candidate != nil && candidate.OIDCSubject != "" && proxyID.UserID != "" && candidate.OIDCSubject != proxyID.UserID && candidate.ID != proxyID.UserID {
			return nil, &domain.GatewayError{
				StatusCode: http.StatusUnauthorized,
				Type:       domain.ErrorTypeAuthentication,
				Code:       "subject_mismatch",
				Message:    "Proxy user identifier does not match registered OIDC subject",
			}
		}
		user = candidate
	}

	if user == nil {
		if !r.proxyAutoRegister {
			return nil, &domain.GatewayError{
				StatusCode:  http.StatusUnauthorized,
				Type:        domain.ErrorTypeAuthentication,
				Code:        "unknown_user",
				Message:     "No registered user matches the reverse-proxy identity headers",
				AuthFailure: true,
			}
		}
		return r.resolveOrProvisionUser(ctx, userResolutionParams{
			orgID:         orgID,
			subject:       proxyID.UserID,
			email:         proxyID.UserEmail,
			displayName:   firstNonEmpty(proxyID.UserEmail, proxyID.UserID),
			claimTeamID:   proxyID.TeamID,
			autoRegister:  true,
			defaultTeamID: r.proxyDefaultTeamID,
			defaultRole:   r.proxyDefaultRole,
			principal: &domain.Principal{
				AuthMethod:    "proxy",
				PrincipalType: "user",
				Subject:       proxyID.UserID,
				Email:         proxyID.UserEmail,
			},
		})
	}

	if !user.IsActive {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusForbidden,
			Type:       domain.ErrorTypePermission,
			Code:       "user_inactive",
			Message:    "User associated with this identity is inactive",
		}
	}

	principal := &domain.Principal{
		AuthMethod:    "proxy",
		PrincipalType: "user",
		Subject:       firstNonEmpty(proxyID.UserID, user.ID),
		Email:         firstNonEmpty(user.Email, proxyID.UserEmail),
	}

	teamIDOverride := ""
	if user.TeamID == "" && proxyID.TeamID != "" {
		teamIDOverride = proxyID.TeamID
	}
	return r.projectUserIdentity(ctx, org, user, principal, teamIDOverride)
}

type userResolutionParams struct {
	orgID         string
	subject       string
	email         string
	displayName   string
	claimTeamID   string
	claimRole     string
	autoRegister  bool
	defaultTeamID string
	defaultRole   string
	principal     *domain.Principal
}

func (r *AuthResolver) resolveOrProvisionUser(ctx context.Context, p userResolutionParams) (*domain.IdentityContext, error) {
	if r.repo == nil {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusServiceUnavailable,
			Type:       domain.ErrorTypeServer,
			Code:       "auth_repository_unavailable",
			Message:    "Identity repository is not configured",
		}
	}
	if strings.TrimSpace(p.orgID) == "" {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusUnauthorized,
			Type:       domain.ErrorTypeAuthentication,
			Code:       "missing_org_id",
			Message:    "Organization could not be determined for authenticated principal",
		}
	}

	org, err := r.repo.GetOrganization(ctx, p.orgID)
	if err != nil || org == nil || !org.IsActive {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusForbidden,
			Type:       domain.ErrorTypePermission,
			Code:       "organization_inactive",
			Message:    "Organization associated with this principal is inactive or does not exist",
		}
	}

	var user *domain.User
	if p.subject != "" {
		user, err = r.lookupUserByOrgAndSubject(ctx, p.orgID, p.subject)
		if err != nil && !errors.Is(err, storage.ErrNotFound) {
			return nil, &domain.GatewayError{
				StatusCode: http.StatusServiceUnavailable,
				Type:       domain.ErrorTypeServer,
				Code:       "user_lookup_unavailable",
				Message:    "Unable to resolve user identity",
				Retryable:  true,
			}
		}
	}

	if user == nil && p.email != "" {
		candidate, emailErr := r.lookupUserByOrgAndEmail(ctx, p.orgID, p.email)
		if emailErr != nil && !errors.Is(emailErr, storage.ErrNotFound) {
			var gwErr *domain.GatewayError
			if errors.As(emailErr, &gwErr) {
				return nil, gwErr
			}
			return nil, &domain.GatewayError{
				StatusCode: http.StatusServiceUnavailable,
				Type:       domain.ErrorTypeServer,
				Code:       "user_lookup_unavailable",
				Message:    "Unable to resolve user identity by email",
				Retryable:  true,
			}
		}
		if candidate != nil {
			if candidate.OIDCSubject != "" && p.subject != "" && candidate.OIDCSubject != p.subject {
				return nil, &domain.GatewayError{
					StatusCode:  http.StatusUnauthorized,
					Type:        domain.ErrorTypeAuthentication,
					Code:        "subject_mismatch",
					Message:     "Authenticated subject does not match registered user OIDC subject",
					AuthFailure: true,
				}
			}
			user = candidate
		}
	}

	if user == nil {
		if !p.autoRegister {
			return nil, &domain.GatewayError{
				StatusCode:  http.StatusUnauthorized,
				Type:        domain.ErrorTypeAuthentication,
				Code:        "unknown_user",
				Message:     "No registered user matches the authenticated principal",
				AuthFailure: true,
			}
		}

		teamID := firstNonEmpty(p.claimTeamID, p.defaultTeamID)
		if teamID != "" {
			if _, teamErr := r.validateOrgTeam(ctx, p.orgID, teamID); teamErr != nil {
				return nil, teamErr
			}
		}

		email := strings.TrimSpace(p.email)
		if email == "" {
			email = synthesizeOIDCEmail(p.orgID, p.subject)
		}

		jitUser := &domain.User{
			OrgID:             p.orgID,
			TeamID:            teamID,
			Email:             email,
			Name:              firstNonEmpty(p.displayName, email, p.subject),
			Role:              resolveJITRole(p.claimRole, p.defaultRole),
			OIDCSubject:       p.subject,
			BudgetResetPeriod: domain.BudgetResetMonthly,
			IsActive:          true,
		}

		if oidcRepo, ok := r.repo.(storage.OIDCUserRepository); ok && oidcRepo != nil {
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
					Message:    "Unable to provision JIT user: " + jitErr.Error(),
					Retryable:  true,
				}
			}
			user = createdUser
		} else {
			if createErr := r.repo.CreateUser(ctx, jitUser); createErr != nil {
				return nil, &domain.GatewayError{
					StatusCode: http.StatusServiceUnavailable,
					Type:       domain.ErrorTypeServer,
					Code:       "user_provisioning_unavailable",
					Message:    "Unable to provision JIT user: " + createErr.Error(),
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

	return r.projectUserIdentity(ctx, org, user, p.principal, "")
}

func (r *AuthResolver) lookupUserByOrgAndSubject(ctx context.Context, orgID, subject string) (*domain.User, error) {
	if oidcRepo, ok := r.repo.(storage.OIDCUserRepository); ok && oidcRepo != nil {
		return oidcRepo.GetUserByOrgAndOIDCSubject(ctx, orgID, subject)
	}
	u, err := r.repo.GetUserByOIDCSubject(ctx, subject)
	if err != nil {
		return nil, storage.ErrNotFound
	}
	if u == nil || u.OrgID != orgID {
		return nil, storage.ErrNotFound
	}
	return u, nil
}

func (r *AuthResolver) lookupUserByOrgAndEmail(ctx context.Context, orgID, email string) (*domain.User, error) {
	if oidcRepo, ok := r.repo.(storage.OIDCUserRepository); ok && oidcRepo != nil {
		u, err := oidcRepo.GetUserByEmail(ctx, email)
		if err != nil {
			return nil, err
		}
		if u == nil {
			return nil, storage.ErrNotFound
		}
		if u.OrgID != orgID {
			return nil, &domain.GatewayError{
				StatusCode: http.StatusForbidden,
				Type:       domain.ErrorTypePermission,
				Code:       "cross_org_access_denied",
				Message:    "User email belongs to a different organization",
			}
		}
		return u, nil
	}
	users, err := r.repo.ListUsers(ctx, orgID)
	if err != nil {
		return nil, err
	}
	for _, u := range users {
		if u != nil && strings.EqualFold(u.Email, email) && u.OrgID == orgID {
			return u, nil
		}
	}
	return nil, storage.ErrNotFound
}

func (r *AuthResolver) validateOrgTeam(ctx context.Context, orgID, teamID string) (*domain.Team, error) {
	team, err := r.repo.GetTeam(ctx, teamID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) || strings.Contains(strings.ToLower(err.Error()), "not found") {
			return nil, &domain.GatewayError{
				StatusCode: http.StatusForbidden,
				Type:       domain.ErrorTypePermission,
				Code:       "team_not_found",
				Message:    "Team associated with this identity was not found",
			}
		}
		return nil, &domain.GatewayError{
			StatusCode: http.StatusServiceUnavailable,
			Type:       domain.ErrorTypeServer,
			Code:       "team_policy_unavailable",
			Message:    "Unable to resolve team policy",
			Retryable:  true,
		}
	}
	if team.OrgID != orgID {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusForbidden,
			Type:       domain.ErrorTypePermission,
			Code:       "team_org_mismatch",
			Message:    "Team does not belong to the target organization",
		}
	}
	if !team.IsActive {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusForbidden,
			Type:       domain.ErrorTypePermission,
			Code:       "team_inactive",
			Message:    "Team associated with this identity is inactive",
		}
	}
	return team, nil
}

func (r *AuthResolver) projectUserIdentity(
	ctx context.Context,
	org *domain.Organization,
	user *domain.User,
	principal *domain.Principal,
	teamIDOverride string,
) (*domain.IdentityContext, error) {
	teamID := strings.TrimSpace(user.TeamID)
	if teamID == "" {
		teamID = strings.TrimSpace(teamIDOverride)
	}

	prefixMethod := "oidc"
	if principal != nil && principal.AuthMethod != "" {
		prefixMethod = principal.AuthMethod
	}

	idCtx := &domain.IdentityContext{
		KeyPrefix:                    fmt.Sprintf("%s:%s", prefixMethod, user.ID),
		OrgID:                        org.ID,
		TeamID:                       teamID,
		UserID:                       user.ID,
		Role:                         user.Role,
		Principal:                    principal,
		AllowedEndpoints:             []string{"*"},
		UserRPMLimit:                 user.RPMLimit,
		UserTPMLimit:                 user.TPMLimit,
		UserMaxConcurrent:            user.MaxConcurrentRequests,
		UserBatchEnqueuedTokenLimit:  user.BatchEnqueuedTokenLimit,
		UserMaxBudgetMicros:          user.MaxBudgetMicros,
		UserSoftBudgetMicros:         user.SoftBudgetMicros,
		UserThrottleOnBudgetExceeded: user.ThrottleOnBudgetExceeded,
		UserBudgetFallbacks:          domain.CloneBudgetFallbacks(user.BudgetFallbacks),
		UserSpentMicros:              user.SpentMicros,
		OrgRPMLimit:                  org.RPMLimit,
		OrgTPMLimit:                  org.TPMLimit,
		OrgMaxConcurrent:             org.MaxConcurrentRequests,
		OrgBatchEnqueuedTokenLimit:   org.BatchEnqueuedTokenLimit,
		OrgMaxBudgetMicros:           org.MaxBudgetMicros,
		OrgSoftBudgetMicros:          org.SoftBudgetMicros,
		OrgThrottleOnBudgetExceeded:  org.ThrottleOnBudgetExceeded,
		OrgBudgetFallbacks:           domain.CloneBudgetFallbacks(org.BudgetFallbacks),
		OrgSpentMicros:               org.SpentMicros,
	}

	if teamID != "" {
		team, err := r.validateOrgTeam(ctx, org.ID, teamID)
		if err != nil {
			return nil, err
		}
		idCtx.TeamAllowedModels = append([]string(nil), team.AllowedModels...)
		if team.AllowedMCPServers != nil {
			idCtx.TeamAllowedMCPServers = append([]string(nil), team.AllowedMCPServers...)
		}
		if team.AllowedA2AAgents != nil {
			idCtx.TeamAllowedA2AAgents = append([]string(nil), team.AllowedA2AAgents...)
		}
		if team.AllowedClientApps != nil {
			idCtx.TeamAllowedClientApps = append([]string(nil), team.AllowedClientApps...)
		}
		idCtx.TeamRPMLimit = team.RPMLimit
		idCtx.TeamTPMLimit = team.TPMLimit
		idCtx.TeamMaxConcurrent = team.MaxConcurrentRequests
		idCtx.TeamBatchEnqueuedTokenLimit = team.BatchEnqueuedTokenLimit
		idCtx.TeamMaxBudgetMicros = team.MaxBudgetMicros
		idCtx.TeamSoftBudgetMicros = team.SoftBudgetMicros
		idCtx.TeamThrottleOnBudgetExceeded = team.ThrottleOnBudgetExceeded
		idCtx.TeamBudgetFallbacks = domain.CloneBudgetFallbacks(team.BudgetFallbacks)
		idCtx.TeamSpentMicros = team.SpentMicros
	}

	return idCtx, nil
}

func resolveJITRole(claimRole, defaultRole string) domain.Role {
	for _, candidate := range []string{claimRole, defaultRole} {
		switch domain.Role(strings.ToLower(strings.TrimSpace(candidate))) {
		case domain.RolePlatformAdmin,
			domain.RoleOrgAdmin,
			domain.RoleOrgViewer,
			domain.RoleTeamAdmin,
			domain.RoleDeveloper,
			domain.RoleServiceAccount,
			domain.RoleViewer:
			return domain.Role(strings.ToLower(strings.TrimSpace(candidate)))
		}
	}
	return domain.RoleDeveloper
}

func extractRawDisplayName(raw map[string]any, fallbacks ...string) string {
	if raw != nil {
		if v, ok := raw["name"].(string); ok && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return firstNonEmpty(fallbacks...)
}

func synthesizeOIDCEmail(orgID, subject string) string {
	cleanSub := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			return r
		}
		return '-'
	}, strings.TrimSpace(subject))
	if cleanSub == "" {
		cleanSub = "oidc-user"
	}
	cleanOrg := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			return r
		}
		return '-'
	}, strings.TrimSpace(orgID))
	if cleanOrg == "" {
		cleanOrg = "default"
	}
	return fmt.Sprintf("%s@%s.oidc.local", cleanSub, cleanOrg)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if trimmed := strings.TrimSpace(v); trimmed != "" {
			return trimmed
		}
	}
	return ""
}

func invalidAPIKeyError() *domain.GatewayError {
	return &domain.GatewayError{
		StatusCode: http.StatusUnauthorized,
		Type:       domain.ErrorTypeAuthentication,
		Code:       "invalid_api_key",
		Message:    "Invalid or revoked virtual API key",
	}
}
