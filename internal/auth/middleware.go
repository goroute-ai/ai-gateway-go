package auth

import (
	"context"
	"net/http"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

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

// DataPlaneMiddleware authenticates `/v1/*` requests using Virtual API Keys (`sk-gw-...`) and checks endpoint RBAC.
func DataPlaneMiddleware(svc *Service, rbac *RBACEngine) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var opts ExtractorOptions
			if svc != nil {
				opts = svc.ExtractorOptions()
			}
			cred, err := ExtractCredentials(r, opts)
			if err != nil {
				domain.WriteHTTPError(w, err)
				return
			}
			idCtx, err := svc.AuthenticateVirtualKey(r.Context(), cred.Token)
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

// AdminControlPlaneMiddleware protects `/admin/v1/*` routes and resolves OperatorContext from
// MasterAdminKey, admin-role VirtualKey, or validated inbound Bearer JWT/OIDC.
func AdminControlPlaneMiddleware(svc *Service) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var opts ExtractorOptions
			if svc != nil {
				opts = svc.ExtractorOptions()
			}
			cred, err := ExtractCredentials(r, opts)
			if err != nil {
				domain.WriteHTTPError(w, err)
				return
			}
			op, err := svc.AuthenticateOperatorWithSource(r.Context(), cred)
			if err != nil {
				domain.WriteHTTPError(w, err)
				return
			}
			next.ServeHTTP(w, r.WithContext(WithOperator(r.Context(), op)))
		})
	}
}
