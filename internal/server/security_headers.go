package server

import (
	"net/http"
	"strings"

	"github.com/goroute-ai/ai-gateway-go/internal/ui"
)

// SecurityHeadersMiddleware attaches baseline HTTP security headers to responses.
// It applies Content-Security-Policy on /ui/* and /admin/v1/* routes, and optionally
// emits Strict-Transport-Security when enableHSTS is true.
func SecurityHeadersMiddleware(enableHSTS bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			h.Set("X-Frame-Options", "DENY")
			h.Set("X-Content-Type-Options", "nosniff")
			h.Set("Referrer-Policy", "no-referrer")

			if enableHSTS {
				h.Set("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
			}

			if isCSPProtectedPath(r.URL.Path) {
				h.Set("Content-Security-Policy", ui.ContentSecurityPolicy)
			} else {
				h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
			}
			if isNoStorePath(r.URL.Path) {
				h.Set("Cache-Control", "no-store")
				h.Set("Pragma", "no-cache")
			}

			next.ServeHTTP(w, r)
		})
	}
}

func isNoStorePath(path string) bool {
	return path == "/auth" ||
		strings.HasPrefix(path, "/auth/") ||
		path == "/admin/v1" ||
		strings.HasPrefix(path, "/admin/v1/")
}

func isCSPProtectedPath(path string) bool {
	return path == "/ui" ||
		strings.HasPrefix(path, "/ui/") ||
		path == "/admin/v1" ||
		strings.HasPrefix(path, "/admin/v1/")
}

// CORSMiddleware enforces a safe-by-default Cross-Origin Resource Sharing policy.
// When allowedOrigins is empty, no CORS headers are emitted. Wildcard ("*") is
// never combined with allowCredentials=true and never applied to Control Plane
// (/auth/* or /admin/v1/*) routes.
func CORSMiddleware(allowedOrigins []string, allowCredentials bool) func(http.Handler) http.Handler {
	allowAll := false
	allowedSet := make(map[string]struct{}, len(allowedOrigins))
	for _, raw := range allowedOrigins {
		origin := strings.TrimSpace(raw)
		if origin == "" || strings.EqualFold(origin, "null") {
			continue
		}
		if origin == "*" {
			if !allowCredentials {
				allowAll = true
			}
			continue
		}
		allowedSet[origin] = struct{}{}
	}
	hasExplicitAllowlist := len(allowedSet) > 0

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := w.Header()
			if hasExplicitAllowlist {
				h.Add("Vary", "Origin")
			}

			origin := strings.TrimSpace(r.Header.Get("Origin"))
			if origin == "" || strings.EqualFold(origin, "null") {
				if strings.EqualFold(origin, "null") && r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
					w.WriteHeader(http.StatusForbidden)
					return
				}
				next.ServeHTTP(w, r)
				return
			}

			var matchedOrigin string
			if _, ok := allowedSet[origin]; ok {
				matchedOrigin = origin
			} else if allowAll && !allowCredentials && !isNoStorePath(r.URL.Path) {
				matchedOrigin = "*"
			}

			if matchedOrigin == "" {
				if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
					w.WriteHeader(http.StatusForbidden)
					return
				}
				next.ServeHTTP(w, r)
				return
			}

			h.Set("Access-Control-Allow-Origin", matchedOrigin)
			if matchedOrigin != "*" && allowCredentials {
				h.Set("Access-Control-Allow-Credentials", "true")
			}
			h.Set("Access-Control-Expose-Headers", "X-Trace-Id, traceparent, X-Gateway-Request-Id, X-Gateway-Provider, X-Gateway-Model, X-Gateway-Cost-Micros, X-Gateway-Cache, X-Gateway-Cache-Type, X-Gateway-Cache-Similarity, X-Gateway-Guardrail-Action, X-Gateway-Pricing-Status, X-Gateway-Latency-Ms, X-Gateway-Route-Reason, X-Gateway-Fallback-Attempted, X-Gateway-Routing-Micros, X-Gateway-Stream-Continued, X-Gateway-Tier-Stepdowns, X-RateLimit-Limit-Requests, X-RateLimit-Remaining-Requests, X-RateLimit-Reset-Requests, X-RateLimit-Limit-Tokens, X-RateLimit-Remaining-Tokens, X-RateLimit-Reset-Tokens, X-RateLimit-Scope, X-RateLimit-Type, X-RateLimit-Reset-At, Retry-After")

			if r.Method == http.MethodOptions {
				h.Add("Vary", "Access-Control-Request-Method")
				h.Add("Vary", "Access-Control-Request-Headers")
				h.Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
				h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-API-Key, X-CSRF-Token, X-Gateway-Client-App, X-Requested-With, Accept, Origin")
				h.Set("Access-Control-Max-Age", "86400")
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
