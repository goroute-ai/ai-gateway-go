package server_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/server"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSecurityHeadersMiddleware(t *testing.T) {
	okHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	t.Run("CSP applied on /ui/* and /admin/v1/* without HSTS", func(t *testing.T) {
		h := server.SecurityHeadersMiddleware(false)(okHandler)

		for _, path := range []string{"/ui", "/ui/", "/ui/keys", "/admin/v1/keys"} {
			req := httptest.NewRequest(http.MethodGet, path, nil)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)

			assert.Equal(t, http.StatusOK, rec.Code)
			assert.Equal(t, "DENY", rec.Header().Get("X-Frame-Options"))
			assert.Equal(t, "nosniff", rec.Header().Get("X-Content-Type-Options"))
			assert.Equal(t, "no-referrer", rec.Header().Get("Referrer-Policy"))
			assert.Empty(t, rec.Header().Get("Strict-Transport-Security"))

			csp := rec.Header().Get("Content-Security-Policy")
			assert.Contains(t, csp, "default-src 'self'")
			assert.Contains(t, csp, "script-src 'self'")
			assert.Contains(t, csp, "style-src 'self' 'unsafe-inline'")
			assert.Contains(t, csp, "img-src 'self' data:")
			assert.Contains(t, csp, "font-src 'self'")
			assert.Contains(t, csp, "connect-src 'self'")
			assert.Contains(t, csp, "frame-ancestors 'none'")
		}
	})

	t.Run("HSTS emitted when enabled and CSP omitted on data plane", func(t *testing.T) {
		h := server.SecurityHeadersMiddleware(true)(okHandler)

		req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "DENY", rec.Header().Get("X-Frame-Options"))
		assert.Equal(t, "nosniff", rec.Header().Get("X-Content-Type-Options"))
		assert.Equal(t, "no-referrer", rec.Header().Get("Referrer-Policy"))
		assert.Equal(t, "max-age=63072000; includeSubDomains", rec.Header().Get("Strict-Transport-Security"))
		assert.Empty(t, rec.Header().Get("Content-Security-Policy"))
	})
}

func TestCORSMiddleware(t *testing.T) {
	okHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	t.Run("safe-by-default empty allowlist denies cross-origin", func(t *testing.T) {
		h := server.CORSMiddleware(nil, false)(okHandler)

		req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
		req.Header.Set("Origin", "https://evil.example.com")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		assert.Empty(t, rec.Header().Get("Access-Control-Allow-Origin"))

		pre := httptest.NewRequest(http.MethodOptions, "/v1/models", nil)
		pre.Header.Set("Origin", "https://evil.example.com")
		pre.Header.Set("Access-Control-Request-Method", "POST")
		preRec := httptest.NewRecorder()
		h.ServeHTTP(preRec, pre)
		assert.Equal(t, http.StatusForbidden, preRec.Code)
		assert.Empty(t, preRec.Header().Get("Access-Control-Allow-Origin"))
	})

	t.Run("explicit allowlist with credentials", func(t *testing.T) {
		h := server.CORSMiddleware([]string{"https://console.example.com"}, true)(okHandler)

		// Allowed preflight
		pre := httptest.NewRequest(http.MethodOptions, "/admin/v1/keys", nil)
		pre.Header.Set("Origin", "https://console.example.com")
		pre.Header.Set("Access-Control-Request-Method", "GET")
		preRec := httptest.NewRecorder()
		h.ServeHTTP(preRec, pre)
		assert.Equal(t, http.StatusNoContent, preRec.Code)
		assert.Equal(t, "https://console.example.com", preRec.Header().Get("Access-Control-Allow-Origin"))
		assert.Equal(t, "true", preRec.Header().Get("Access-Control-Allow-Credentials"))
		assert.Contains(t, preRec.Header().Values("Vary"), "Origin")
		assert.NotEmpty(t, preRec.Header().Get("Access-Control-Allow-Methods"))

		// Allowed GET
		req := httptest.NewRequest(http.MethodGet, "/admin/v1/keys", nil)
		req.Header.Set("Origin", "https://console.example.com")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "https://console.example.com", rec.Header().Get("Access-Control-Allow-Origin"))
		assert.Equal(t, "true", rec.Header().Get("Access-Control-Allow-Credentials"))

		// Disallowed origin
		bad := httptest.NewRequest(http.MethodGet, "/admin/v1/keys", nil)
		bad.Header.Set("Origin", "https://other.example.com")
		badRec := httptest.NewRecorder()
		h.ServeHTTP(badRec, bad)
		assert.Empty(t, badRec.Header().Get("Access-Control-Allow-Origin"))
		assert.Empty(t, badRec.Header().Get("Access-Control-Allow-Credentials"))
	})

	t.Run("wildcard without credentials is allowed", func(t *testing.T) {
		h := server.CORSMiddleware([]string{"*"}, false)(okHandler)

		req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
		req.Header.Set("Origin", "https://any.example.com")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		assert.Equal(t, "*", rec.Header().Get("Access-Control-Allow-Origin"))
		assert.Empty(t, rec.Header().Get("Access-Control-Allow-Credentials"))
	})

	t.Run("wildcard is never combined with AllowCredentials true", func(t *testing.T) {
		h := server.CORSMiddleware([]string{"*"}, true)(okHandler)

		pre := httptest.NewRequest(http.MethodOptions, "/v1/models", nil)
		pre.Header.Set("Origin", "https://any.example.com")
		pre.Header.Set("Access-Control-Request-Method", "GET")
		preRec := httptest.NewRecorder()
		h.ServeHTTP(preRec, pre)
		assert.Equal(t, http.StatusForbidden, preRec.Code)
		assert.Empty(t, preRec.Header().Get("Access-Control-Allow-Origin"))
		assert.Empty(t, preRec.Header().Get("Access-Control-Allow-Credentials"))

		req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
		req.Header.Set("Origin", "https://any.example.com")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		assert.Empty(t, rec.Header().Get("Access-Control-Allow-Origin"))
		assert.Empty(t, rec.Header().Get("Access-Control-Allow-Credentials"))
	})
}

func TestGatewayServer_SecurityHeadersAndCORSIntegration(t *testing.T) {
	cfg := config.Default()
	cfg.Server.EnableHSTS = true
	cfg.Server.CORSAllowedOrigins = []string{"https://ops.example.com"}
	cfg.Server.CORSAllowCredentials = true

	srv, err := server.New(cfg, storage.NewMemoryRepository(), nil, nil)
	require.NoError(t, err)
	defer srv.Shutdown(t.Context())

	// /ui/ emits security headers including CSP and HSTS
	uiReq := httptest.NewRequest(http.MethodGet, "/ui/", nil)
	uiRec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(uiRec, uiReq)
	assert.Equal(t, http.StatusOK, uiRec.Code)
	assert.Equal(t, "DENY", uiRec.Header().Get("X-Frame-Options"))
	assert.Equal(t, "nosniff", uiRec.Header().Get("X-Content-Type-Options"))
	assert.Equal(t, "no-referrer", uiRec.Header().Get("Referrer-Policy"))
	assert.Equal(t, "max-age=63072000; includeSubDomains", uiRec.Header().Get("Strict-Transport-Security"))
	assert.Contains(t, uiRec.Header().Get("Content-Security-Policy"), "frame-ancestors 'none'")

	// /admin/v1/* preflight OPTIONS succeeds before admin auth middleware
	preReq := httptest.NewRequest(http.MethodOptions, "/admin/v1/organizations", nil)
	preReq.Header.Set("Origin", "https://ops.example.com")
	preReq.Header.Set("Access-Control-Request-Method", "GET")
	preRec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(preRec, preReq)
	assert.Equal(t, http.StatusNoContent, preRec.Code)
	assert.Equal(t, "https://ops.example.com", preRec.Header().Get("Access-Control-Allow-Origin"))
	assert.Equal(t, "true", preRec.Header().Get("Access-Control-Allow-Credentials"))
	assert.Contains(t, preRec.Header().Get("Content-Security-Policy"), "default-src 'self'")
}
