package gateway

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

// KeyRotatedSecretEvent carries a newly minted virtual key secret produced during automated rotation.
type KeyRotatedSecretEvent = auth.KeyRotatedSecretEvent

// KeySecretSink receives newly minted virtual key secrets from scheduled rotation sweeps.
type KeySecretSink = auth.KeySecretSink

// KeySecretSinkFunc adapts a Go function into a KeySecretSink.
type KeySecretSinkFunc = auth.KeySecretSinkFunc

// CustomAuthMode controls how a CustomAuthenticator participates in inbound request authentication.
type CustomAuthMode string

const (
	// CustomAuthModeOff disables custom authentication and uses standard gateway authentication.
	CustomAuthModeOff CustomAuthMode = "off"
	// CustomAuthModeOn requires the custom authenticator to succeed; abstentions or errors fail closed.
	CustomAuthModeOn CustomAuthMode = "on"
	// CustomAuthModeAuto runs the custom authenticator first and falls back to standard gateway
	// authentication when it returns a nil decision or a non-GatewayError error, while failing
	// closed on explicit *domain.GatewayError rejections.
	CustomAuthModeAuto CustomAuthMode = "auto"
)

// ParseCustomAuthMode normalizes and validates a CustomAuthMode string.
// An empty string resolves to CustomAuthModeOff.
func ParseCustomAuthMode(raw string) (CustomAuthMode, error) {
	mode := CustomAuthMode(strings.ToLower(strings.TrimSpace(raw)))
	switch mode {
	case "":
		return CustomAuthModeOff, nil
	case CustomAuthModeOff, CustomAuthModeOn, CustomAuthModeAuto:
		return mode, nil
	default:
		return "", fmt.Errorf("unsupported custom auth mode %q (expected \"on\", \"off\", or \"auto\")", raw)
	}
}

// Valid reports whether m is a recognized CustomAuthMode value.
func (m CustomAuthMode) Valid() bool {
	switch CustomAuthMode(strings.ToLower(strings.TrimSpace(string(m)))) {
	case CustomAuthModeOff, CustomAuthModeOn, CustomAuthModeAuto:
		return true
	default:
		return false
	}
}

// AuthDecision represents the authentication outcome returned by a CustomAuthenticator.
// Callers must populate either Identity (direct IdentityContext) or VirtualKey (gateway virtual key
// to resolve via standard key lookup), never both.
type AuthDecision struct {
	// Identity provides a pre-resolved gateway IdentityContext directly.
	Identity *domain.IdentityContext `json:"identity,omitempty"`
	// VirtualKey supplies a gateway virtual API key (`sk-gw-...`) to resolve via standard auth.
	VirtualKey string `json:"virtual_key,omitempty"`
	// RunPostChecks controls whether gateway RBAC and budget enforcement checks run after
	// custom authentication succeeds.
	RunPostChecks bool `json:"run_post_checks,omitempty"`
}

// CustomAuthenticator evaluates an inbound HTTP request and returns an AuthDecision,
// nil to abstain (falling back to standard auth when running in CustomAuthModeAuto),
// or an error to reject or abort authentication.
type CustomAuthenticator interface {
	Authenticate(ctx context.Context, r *http.Request) (*AuthDecision, error)
}

// CustomAuthenticatorFunc adapts a Go function into a CustomAuthenticator.
type CustomAuthenticatorFunc func(ctx context.Context, r *http.Request) (*AuthDecision, error)

// Authenticate invokes f(ctx, r).
func (f CustomAuthenticatorFunc) Authenticate(ctx context.Context, r *http.Request) (*AuthDecision, error) {
	return f(ctx, r)
}

// EvaluateCustomAuth executes authenticator according to mode ("on", "off", or "auto").
//
// Return semantics:
//   - (*AuthDecision, nil): custom authentication succeeded; the caller should honor the returned
//     Identity or VirtualKey (and enforce RBAC/budget checks when RunPostChecks is true).
//   - (nil, nil): fall back to standard gateway authentication (occurs in "off" mode, or in "auto"
//     mode when authenticator is nil, returns (nil, nil), or returns a non-*domain.GatewayError).
//   - (nil, *domain.GatewayError): authentication failed closed and must be rejected.
func EvaluateCustomAuth(ctx context.Context, r *http.Request, mode CustomAuthMode, authenticator CustomAuthenticator) (*AuthDecision, error) {
	normalizedMode, err := ParseCustomAuthMode(string(mode))
	if err != nil {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusInternalServerError,
			Type:       domain.ErrorTypeServer,
			Code:       "invalid_custom_auth_mode",
			Message:    err.Error(),
		}
	}

	if normalizedMode == CustomAuthModeOff {
		return nil, nil
	}

	if r == nil {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_request",
			Message:    "HTTP request is required for custom authentication",
		}
	}

	if authenticator == nil {
		if normalizedMode == CustomAuthModeAuto {
			return nil, nil
		}
		return nil, &domain.GatewayError{
			StatusCode: http.StatusUnauthorized,
			Type:       domain.ErrorTypeAuthentication,
			Code:       "custom_auth_unavailable",
			Message:    "Custom authentication is enabled but no authenticator is configured",
		}
	}

	if ctx == nil {
		ctx = r.Context()
	}
	if ctx == nil {
		ctx = context.Background()
	}

	decision, err := authenticator.Authenticate(ctx, r)
	if err != nil {
		var gwErr *domain.GatewayError
		if errors.As(err, &gwErr) && gwErr != nil {
			return nil, gwErr
		}
		if normalizedMode == CustomAuthModeAuto {
			return nil, nil
		}
		return nil, &domain.GatewayError{
			StatusCode: http.StatusUnauthorized,
			Type:       domain.ErrorTypeAuthentication,
			Code:       "custom_auth_failed",
			Message:    err.Error(),
		}
	}

	if decision == nil {
		if normalizedMode == CustomAuthModeAuto {
			return nil, nil
		}
		return nil, &domain.GatewayError{
			StatusCode: http.StatusUnauthorized,
			Type:       domain.ErrorTypeAuthentication,
			Code:       "custom_auth_rejected",
			Message:    "Custom authenticator did not return an authentication decision",
		}
	}

	trimmedKey := strings.TrimSpace(decision.VirtualKey)
	hasIdentity := decision.Identity != nil
	hasKey := trimmedKey != ""

	if !hasIdentity && !hasKey {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusUnauthorized,
			Type:       domain.ErrorTypeAuthentication,
			Code:       "invalid_custom_auth_decision",
			Message:    "Custom authenticator decision must specify either Identity or VirtualKey",
		}
	}
	if hasIdentity && hasKey {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusUnauthorized,
			Type:       domain.ErrorTypeAuthentication,
			Code:       "ambiguous_custom_auth_decision",
			Message:    "Custom authenticator decision must not specify both Identity and VirtualKey",
		}
	}

	return &AuthDecision{
		Identity:      decision.Identity,
		VirtualKey:    trimmedKey,
		RunPostChecks: decision.RunPostChecks,
	}, nil
}
