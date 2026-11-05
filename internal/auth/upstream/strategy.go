package upstream

import (
	"context"
	"net/http"
)

// Strategy defines the interface for applying upstream credentials to outgoing HTTP requests.
type Strategy interface {
	// Type returns the unique identifier for this authentication strategy (e.g. "static", "oauth2_client_credentials").
	Type() string

	// Apply injects authentication headers or credentials into the outgoing request.
	Apply(ctx context.Context, req *http.Request, authCtx *UpstreamAuthContext) error
}
