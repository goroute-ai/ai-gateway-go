package upstream

import (
	"context"
	"fmt"
	"net/http"
	"strings"
)

// DelegationStrategy propagates caller identity or delegated credentials to the upstream service.
type DelegationStrategy struct {
	HeaderName         string `json:"header_name"`
	ForwardCallerIdent bool   `json:"forward_caller_identity"`
}

// NewDelegationStrategy creates a new DelegationStrategy.
func NewDelegationStrategy(headerName string, forwardCallerIdent bool) *DelegationStrategy {
	if headerName == "" {
		headerName = "Authorization"
	}
	return &DelegationStrategy{
		HeaderName:         headerName,
		ForwardCallerIdent: forwardCallerIdent,
	}
}

func (s *DelegationStrategy) Type() string {
	return "delegation"
}

func (s *DelegationStrategy) Apply(ctx context.Context, req *http.Request, authCtx *UpstreamAuthContext) error {
	if req == nil {
		return fmt.Errorf("upstream delegation auth: nil request")
	}
	if authCtx == nil || authCtx.DelegatedToken == "" {
		return fmt.Errorf("upstream delegation auth: no delegated token available in context")
	}

	token := strings.TrimSpace(authCtx.DelegatedToken)
	if strings.EqualFold(s.HeaderName, "Authorization") && !strings.HasPrefix(strings.ToLower(token), "bearer ") {
		token = "Bearer " + token
	}
	req.Header.Set(s.HeaderName, token)

	if s.ForwardCallerIdent {
		if authCtx.CallingOrgID != "" {
			req.Header.Set("X-Gateway-Caller-Org", authCtx.CallingOrgID)
		}
		if authCtx.CallingUserID != "" {
			req.Header.Set("X-Gateway-Caller-User", authCtx.CallingUserID)
		}
		if authCtx.CallingAgentID != "" {
			req.Header.Set("X-Gateway-Caller-Agent", authCtx.CallingAgentID)
		}
	}

	return nil
}
