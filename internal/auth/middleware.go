package auth

import (
	"context"
	"net/http"
	"strings"

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

// CredentialSource identifies which HTTP request field supplied a gateway credential.
type CredentialSource string

const (
	CredentialSourceNone      CredentialSource = ""
	CredentialSourceBearer    CredentialSource = "bearer"
	CredentialSourceHeaderKey CredentialSource = "header_key"
	CredentialSourceWebSocket CredentialSource = "websocket"
)

// ExtractedCredentials carries a trimmed credential token alongside its transport source.
type ExtractedCredentials struct {
	Token  string
	Source CredentialSource
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
	cred, err := ExtractGatewayCredentialsWithSource(r)
	return cred.Token, err
}

// ExtractGatewayCredentialsWithSource extracts the caller credential together with its transport source.
func ExtractGatewayCredentialsWithSource(r *http.Request) (ExtractedCredentials, error) {
	var bearerToken string
	authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
	if strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
		bearerToken = strings.TrimSpace(authHeader[7:])
	}

	headerToken := strings.TrimSpace(r.Header.Get("x-api-key"))

	if bearerToken != "" && headerToken != "" && bearerToken != headerToken {
		return ExtractedCredentials{}, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeAuthentication,
			Code:       "ambiguous_gateway_credentials",
			Message:    "Conflicting authentication credentials: both Authorization Bearer token and x-api-key header were provided with different values",
		}
	}

	if bearerToken != "" {
		return ExtractedCredentials{Token: bearerToken, Source: CredentialSourceBearer}, nil
	}
	if headerToken != "" {
		return ExtractedCredentials{Token: headerToken, Source: CredentialSourceHeaderKey}, nil
	}
	if !isRealtimeWebSocketRequest(r) {
		return ExtractedCredentials{}, nil
	}

	// Browser WebSocket clients can use the OpenAI-compatible subprotocol or query authentication.
	for _, proto := range strings.Split(r.Header.Get("Sec-WebSocket-Protocol"), ",") {
		proto = strings.TrimSpace(proto)
		if strings.HasPrefix(proto, "openai-insecure-api-key.") {
			return ExtractedCredentials{
				Token:  strings.TrimPrefix(proto, "openai-insecure-api-key."),
				Source: CredentialSourceWebSocket,
			}, nil
		}
	}

	// Check query parameter for websocket connections
	if qKey := r.URL.Query().Get("api_key"); qKey != "" {
		return ExtractedCredentials{Token: qKey, Source: CredentialSourceWebSocket}, nil
	}
	if qToken := r.URL.Query().Get("token"); qToken != "" {
		return ExtractedCredentials{Token: qToken, Source: CredentialSourceWebSocket}, nil
	}

	return ExtractedCredentials{}, nil
}

func isRealtimeWebSocketRequest(r *http.Request) bool {
	if r.Method != http.MethodGet {
		return false
	}
	switch r.URL.Path {
	case "/v1/realtime", "/realtime", "/openai/v1/realtime":
	default:
		return false
	}
	if !strings.EqualFold(strings.TrimSpace(r.Header.Get("Upgrade")), "websocket") {
		return false
	}
	for _, token := range strings.Split(r.Header.Get("Connection"), ",") {
		if strings.EqualFold(strings.TrimSpace(token), "upgrade") {
			return true
		}
	}
	return false
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

// AdminControlPlaneMiddleware protects `/admin/v1/*` routes and resolves OperatorContext from
// MasterAdminKey, admin-role VirtualKey, or validated inbound Bearer JWT/OIDC.
func AdminControlPlaneMiddleware(svc *Service) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			cred, err := ExtractGatewayCredentialsWithSource(r)
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
