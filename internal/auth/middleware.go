package auth

import (
	"context"
	"net/http"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

const (
	// HeaderKeyDeprecated is emitted when a request authenticates with a deprecated virtual key during its rotation grace period.
	HeaderKeyDeprecated = "X-Gateway-Key-Deprecated"
	// HeaderKeyRevokeAt communicates the RFC3339 UTC timestamp when a deprecated virtual key will stop working.
	HeaderKeyRevokeAt = "X-Gateway-Key-Revoke-At"
)

func writeDeprecatedKeyHeaders(w http.ResponseWriter, revokeAt *time.Time) {
	if w == nil || revokeAt == nil {
		return
	}
	w.Header().Set(HeaderKeyDeprecated, "true")
	w.Header().Set(HeaderKeyRevokeAt, revokeAt.UTC().Format(time.RFC3339))
}

func enforceReadOnlyKeyMethod(idCtx *domain.IdentityContext, method string) error {
	if idCtx == nil || idCtx.KeyType != domain.KeyTypeReadOnly {
		return nil
	}
	switch method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return nil
	default:
		return &domain.GatewayError{
			StatusCode: http.StatusForbidden,
			Type:       domain.ErrorTypePermission,
			Code:       "read_only_key",
			Message:    "Virtual keys with key_type \"read_only\" only permit read-only HTTP methods",
		}
	}
}

type ctxKey int

const (
	identityContextKey ctxKey = 1
	operatorContextKey ctxKey = 2
)

// WithIdentity attaches IdentityContext to a context.Context.
func WithIdentity(ctx context.Context, id *domain.IdentityContext) context.Context {
	return context.WithValue(ctx, identityContextKey, id)
}

// IdentityFromContext retrieves the authenticated IdentityContext from context.Context.
func IdentityFromContext(ctx context.Context) *domain.IdentityContext {
	if v, ok := ctx.Value(identityContextKey).(*domain.IdentityContext); ok {
		return v
	}
	return nil
}

// WithOperator attaches OperatorContext to a context.Context.
func WithOperator(ctx context.Context, op *domain.OperatorContext) context.Context {
	return context.WithValue(ctx, operatorContextKey, op)
}

// OperatorFromContext retrieves the authenticated OperatorContext from context.Context.
func OperatorFromContext(ctx context.Context) *domain.OperatorContext {
	if v, ok := ctx.Value(operatorContextKey).(*domain.OperatorContext); ok {
		return v
	}
	return nil
}

// ExtractBearerToken extracts a token from supported inbound credential headers or route-scoped parameters.
// If conflicting primary credentials are provided, it returns an empty string for backwards compatibility.
func ExtractBearerToken(r *http.Request) string {
	token, _ := ExtractGatewayCredentials(r)
	return token
}

// ExtractGatewayCredentials extracts the caller token from supported inbound credential headers or route-scoped parameters.
// If conflicting primary headers are provided with different values without an explicit gateway override header,
// it returns an ambiguous_gateway_credentials error (HTTP 400).
func ExtractGatewayCredentials(r *http.Request) (string, error) {
	cred, err := ExtractGatewayCredentialsWithSource(r)
	return cred.Token, err
}

// ExtractGatewayCredentialsWithSource extracts the caller credential together with its transport source.
func ExtractGatewayCredentialsWithSource(r *http.Request) (ExtractedCredentials, error) {
	return ExtractCredentials(r, ExtractorOptions{})
}

// DataPlaneMiddleware authenticates Data Plane requests (`/v1/*`, `/mcp/*`, `/a2a/*`) using
// the Service's configured AuthResolver when present, or Virtual API Keys (`sk-gw-...`) otherwise,
// and enforces endpoint RBAC.
func DataPlaneMiddleware(svc *Service, rbac *RBACEngine) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var (
				idCtx *domain.IdentityContext
				err   error
			)
			if svc != nil && svc.DataPlaneResolver() != nil {
				idCtx, err = svc.DataPlaneResolver().ResolveRequest(r.Context(), r)
			} else {
				var opts ExtractorOptions
				if svc != nil {
					opts = svc.ExtractorOptions()
				}
				var cred ExtractedCredentials
				cred, err = ExtractCredentials(r, opts)
				if err == nil {
					idCtx, err = svc.AuthenticateVirtualKey(r.Context(), cred.Token)
				}
			}
			if err != nil {
				domain.WriteHTTPError(w, err)
				return
			}
			if idCtx != nil {
				writeDeprecatedKeyHeaders(w, idCtx.DeprecatedKeyRevokeAt)
			}
			if rbac != nil {
				if err := rbac.AuthorizeEndpoint(idCtx, r.URL.Path); err != nil {
					domain.WriteHTTPError(w, err)
					return
				}
				if svc == nil || svc.DataPlaneResolver() == nil || svc.DataPlaneResolver().rbac == nil {
					idCtx = rbac.EnrichIdentityWithAccessRules(r.Context(), idCtx)
				}
			}
			if err := enforceReadOnlyKeyMethod(idCtx, r.Method); err != nil {
				domain.WriteHTTPError(w, err)
				return
			}
			next.ServeHTTP(w, r.WithContext(WithIdentity(r.Context(), idCtx)))
		})
	}
}

// DataPlaneMiddlewareWithResolver authenticates Data Plane requests via an explicit AuthResolver
// and enforces endpoint RBAC.
func DataPlaneMiddlewareWithResolver(resolver *AuthResolver, rbac *RBACEngine) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			idCtx, err := resolver.ResolveRequest(r.Context(), r)
			if err != nil {
				domain.WriteHTTPError(w, err)
				return
			}
			if idCtx != nil {
				writeDeprecatedKeyHeaders(w, idCtx.DeprecatedKeyRevokeAt)
			}
			if rbac != nil {
				if err := rbac.AuthorizeEndpoint(idCtx, r.URL.Path); err != nil {
					domain.WriteHTTPError(w, err)
					return
				}
				if resolver == nil || resolver.rbac == nil {
					idCtx = rbac.EnrichIdentityWithAccessRules(r.Context(), idCtx)
				}
			}
			if err := enforceReadOnlyKeyMethod(idCtx, r.Method); err != nil {
				domain.WriteHTTPError(w, err)
				return
			}
			next.ServeHTTP(w, r.WithContext(WithIdentity(r.Context(), idCtx)))
		})
	}
}

// AdminControlPlaneMiddleware protects `/admin/v1/*` routes and resolves OperatorContext from
// MasterAdminKey, admin-role VirtualKey, validated inbound Bearer JWT/OIDC, or Control Plane session cookie/JWT.
// Mutating requests authenticated via session cookie must present a valid X-CSRF-Token header.
func AdminControlPlaneMiddleware(svc *Service) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var opts ExtractorOptions
			if svc != nil {
				opts = svc.ExtractorOptions()
			}
			cred, err := ExtractAdminCredentials(r, opts)
			if err != nil {
				domain.WriteHTTPError(w, err)
				return
			}
			op, err := svc.AuthenticateOperatorWithSource(r.Context(), cred)
			if err != nil {
				domain.WriteHTTPError(w, err)
				return
			}
			if cred.Source == CredentialSourceCookie && IsMutatingHTTPMethod(r.Method) {
				if err := ValidateCSRF(r, op); err != nil {
					domain.WriteHTTPError(w, err)
					return
				}
			}
			if op != nil {
				writeDeprecatedKeyHeaders(w, op.DeprecatedKeyRevokeAt)
			}
			next.ServeHTTP(w, r.WithContext(WithOperator(r.Context(), op)))
		})
	}
}
