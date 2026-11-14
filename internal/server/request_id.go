package server

import (
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/goroute-ai/ai-gateway-go/internal/logger"
)

// gatewayRequestID reuses the ID assigned by HTTPMiddleware so logs, provider
// requests, response headers, and spend records share one correlation value.
func gatewayRequestID(r *http.Request) string {
	if r == nil {
		return "req_" + uuid.NewString()
	}
	if id := logger.RequestIDFromContext(r.Context()); id != "" {
		return id
	}
	if id := strings.TrimSpace(r.Header.Get("X-Request-Id")); id != "" {
		return id
	}
	return "req_" + uuid.NewString()
}
