package upstream

import (
	"context"
	"fmt"
	"net/http"
	"strings"
)

// StaticStrategy applies pre-configured static tokens or headers (e.g. API keys or Bearer tokens).
type StaticStrategy struct {
	HeaderName  string            `json:"header_name"`
	HeaderValue string            `json:"-"` // Redacted from logs
	Extra       map[string]string `json:"-"` // Redacted from logs
}

// NewStaticStrategy creates a new StaticStrategy.
func NewStaticStrategy(headerName, headerValue string, extra map[string]string) *StaticStrategy {
	if headerName == "" {
		headerName = "Authorization"
	}
	return &StaticStrategy{
		HeaderName:  headerName,
		HeaderValue: headerValue,
		Extra:       extra,
	}
}

func (s *StaticStrategy) Type() string {
	return "static"
}

func (s *StaticStrategy) Apply(ctx context.Context, req *http.Request, authCtx *UpstreamAuthContext) error {
	if req == nil {
		return fmt.Errorf("upstream static auth: nil request")
	}

	if s.HeaderValue != "" {
		val := s.HeaderValue
		if strings.EqualFold(s.HeaderName, "Authorization") && !strings.HasPrefix(strings.ToLower(val), "bearer ") {
			val = "Bearer " + val
		}
		req.Header.Set(s.HeaderName, val)
	}

	for k, v := range s.Extra {
		req.Header.Set(k, v)
	}

	// Apply any request-scoped extra headers from context
	if authCtx != nil {
		for k, v := range authCtx.ExtraHeaders {
			req.Header.Set(k, v)
		}
	}

	return nil
}
