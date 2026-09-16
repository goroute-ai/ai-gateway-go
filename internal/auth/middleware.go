package auth

import (
	"context"
	"net/http"
	"strings"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

type ctxKey int

const identityContextKey ctxKey = 1

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

// ExtractBearerToken extracts a token from `Authorization: Bearer <token>` or `x-api-key: <token>`.
// If conflicting credentials are provided, it falls back to the Bearer token for backwards compatibility.
func ExtractBearerToken(r *http.Request) string {
	token, _ := ExtractGatewayCredentials(r)
	return token
}

// ExtractGatewayCredentials extracts the caller token from `Authorization: Bearer <token>` or `x-api-key: <token>`.
// If both headers are provided with conflicting values, it returns an ambiguous_gateway_credentials error (HTTP 400).
func ExtractGatewayCredentials(r *http.Request) (string, error) {
	var authBearer string
	authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
	if strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
		authBearer = strings.TrimSpace(authHeader[7:])
	}

	apiKey := strings.TrimSpace(r.Header.Get("x-api-key"))

	if authBearer != "" && apiKey != "" && authBearer != apiKey {
		return "", &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeAuthentication,
			Code:       "ambiguous_gateway_credentials",
			Message:    "Conflicting authentication credentials: both Authorization Bearer token and x-api-key header were provided with different values",
		}
	}

	if authBearer != "" {
		return authBearer, nil
	}
	return apiKey, nil
}

// DataPlaneMiddleware authenticates `/v1/*` requests using Virtual API Keys (`sk-gw-...`) and checks endpoint RBAC.
func DataPlaneMiddleware(svc *Service, rbac *RBACEngine) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token, err := ExtractGatewayCredentials(r)
			if err != nil {
				domain.WriteHTTPError(w, err)
				return
			}
			idCtx, err := svc.AuthenticateVirtualKey(r.Context(), token)
			if err != nil {
				domain.WriteHTTPError(w, err)
				return
			}
			if rbac != nil {
				if err := rbac.AuthorizeEndpoint(idCtx, r.URL.Path); err != nil {
					domain.WriteHTTPError(w, err)
					return
				}
			}
			next.ServeHTTP(w, r.WithContext(WithIdentity(r.Context(), idCtx)))
		})
	}
}

// AdminControlPlaneMiddleware protects `/admin/v1/*` routes using the Master Admin Key.
func AdminControlPlaneMiddleware(svc *Service) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := ExtractBearerToken(r)
			if !svc.ValidateAdminKey(token) {
				domain.WriteHTTPError(w, &domain.GatewayError{
					StatusCode: http.StatusUnauthorized,
					Type:       domain.ErrorTypeAuthentication,
					Code:       "invalid_admin_key",
					Message:    "Valid Master Admin Key is required to access /admin/v1/* endpoints",
				})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
