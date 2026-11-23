package gateway

import "github.com/goroute-ai/ai-gateway-go/internal/auth"

// AuthzAction identifies the logical authorization operation evaluated by a CustomAuthorizer.
type AuthzAction = auth.AuthzAction

// Supported post-authentication authorization actions evaluated by a CustomAuthorizer.
const (
	AuthzActionInference   = auth.AuthzActionInference
	AuthzActionMCPToolCall = auth.AuthzActionMCPToolCall
	AuthzActionA2AInvoke   = auth.AuthzActionA2AInvoke
	AuthzActionAdminRead   = auth.AuthzActionAdminRead
	AuthzActionAdminWrite  = auth.AuthzActionAdminWrite
)

// AuthzRequest carries the authenticated identity and resource context passed to CustomAuthorizer.
type AuthzRequest = auth.AuthzRequest

// AuthzDecision represents the policy outcome returned by CustomAuthorizer.
type AuthzDecision = auth.AuthzDecision

// CustomAuthorizer evaluates post-authentication authorization policies for inference, MCP, A2A, and Admin routes.
type CustomAuthorizer = auth.Authorizer

// CustomAuthorizerFunc adapts a Go function into a CustomAuthorizer.
type CustomAuthorizerFunc = auth.AuthorizerFunc

// WithCustomAuthorizer installs a post-authentication authorization policy hook on an embedded gateway.
// It executes after standard RBAC checks and fails closed on denial or error.
func WithCustomAuthorizer(authorizer CustomAuthorizer) Option {
	return func(c *clientConfig) {
		c.customAuthorizer = authorizer
	}
}
