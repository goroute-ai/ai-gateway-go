package server

import (
	"net/http/httptest"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/logger"
)

func TestGatewayRequestIDReusesMiddlewareContextID(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Request-Id", "client-id")
	req = req.WithContext(logger.WithRequestID(req.Context(), "middleware-id"))
	if got := gatewayRequestID(req); got != "middleware-id" {
		t.Fatalf("gatewayRequestID = %q, want middleware ID", got)
	}
}

func TestGatewayRequestIDFallsBackToHeaderAndThenGenerates(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("X-Request-Id", "  client-id  ")
	if got := gatewayRequestID(req); got != "client-id" {
		t.Fatalf("gatewayRequestID = %q, want trimmed header value", got)
	}
	req.Header.Del("X-Request-Id")
	if got := gatewayRequestID(req); len(got) < len("req_")+1 || got[:4] != "req_" {
		t.Fatalf("generated ID = %q, want req_ prefix", got)
	}
}
