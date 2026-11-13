package server

import (
	"net/http"
	"strings"
)

const uiAndAdminCSP = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'"

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
				h.Set("Content-Security-Policy", uiAndAdminCSP)
			}

			next.ServeHTTP(w, r)
		})
	}
}

func isCSPProtectedPath(path string) bool {
	return path == "/ui" ||
		strings.HasPrefix(path, "/ui/") ||
		path == "/admin/v1" ||
		strings.HasPrefix(path, "/admin/v1/")
}

// CORSMiddleware enforces a safe-by-default Cross-Origin Resource Sharing policy.
// When allowedOrigins is empty, no CORS headers are emitted. Wildcard ("*") is
// never combined with allowCredentials=true.
func CORSMiddleware(allowedOrigins []string, allowCredentials bool) func(http.Handler) http.Handler {
	allowAll := false
	allowedSet := make(map[string]struct{}, len(allowedOrigins))
	for _, raw := range allowedOrigins {
		origin := strings.TrimSpace(raw)
		if origin == "" {
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

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := strings.TrimSpace(r.Header.Get("Origin"))
			if origin == "" {
				next.ServeHTTP(w, r)
				return
			}

			var matchedOrigin string
			if _, ok := allowedSet[origin]; ok {
				matchedOrigin = origin
			} else if allowAll && !allowCredentials {
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

			h := w.Header()
			h.Set("Access-Control-Allow-Origin", matchedOrigin)
			if matchedOrigin != "*" {
				h.Add("Vary", "Origin")
				if allowCredentials {
					h.Set("Access-Control-Allow-Credentials", "true")
				}
			}

			if r.Method == http.MethodOptions {
				h.Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
				h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type, X-API-Key, X-Requested-With, Accept, Origin")
				h.Set("Access-Control-Max-Age", "86400")
				w.WriteHeader(http.StatusNoContent)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}
