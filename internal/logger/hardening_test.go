package logger

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/observability"
)

func TestScrubSecrets_ExpandedPatternsAndPII(t *testing.T) {
	cases := []struct {
		name      string
		input     string
		forbidden string
	}{
		{"github_classic", "token=ghp_1234567890abcdef1234567890abcdef", "ghp_1234567890"},
		{"github_fine", "token=github_pat_1234567890abcdef1234567890abcdef", "github_pat_1234567890"},
		{"slack", "slack=xoxb-" + "123456789012-123456789012-abcdefghijklmnop", "xoxb-" + "123456789012"},
		{"google_api_key", "key=AIza" + "SyDaGmWKa4JsXZ-HjGw7ISLn_3namBGewQe", "AIza" + "SyDaGmWKa4JsXZ"},
		{"pem_private_key", "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA\n-----END RSA PRIVATE KEY-----", "MIIEowIBAAKCAQEA"},
		{"jwt", "jwt=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U", "eyJzdWIiOiIxMjM0NTY3ODkwIn0"},
		{"basic_auth", "Authorization: Basic dXNlcjpzZWNyZXRwYXNzd29yZA==", "dXNlcjpzZWNyZXRwYXNzd29yZA"},
		{"dsn", "postgres://admin:supersecretpass@db.internal:5432/prod", "supersecretpass"},
		{"email_pii", "user email is alice.smith@example.com", "alice.smith@example.com"},
		{"ssn_pii", "ssn 123-45-6789", "123-45-6789"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := ScrubSecrets(tc.input)
			if strings.Contains(out, tc.forbidden) {
				t.Fatalf("expected %q to be scrubbed, got %q", tc.forbidden, out)
			}
		})
	}

	// slog.KindAny struct scrubbing
	var buf bytes.Buffer
	l := New(Config{Level: "info", Format: "json", Output: &buf})
	type payload struct {
		DSN   string
		Email string
	}
	l.Info("any attr", slog.Any("cfg", payload{
		DSN:   "redis://user:mysecret@cache.local:6379",
		Email: "bob@example.com",
	}))
	logged := buf.String()
	if strings.Contains(logged, "mysecret") || strings.Contains(logged, "bob@example.com") {
		t.Fatalf("expected slog.KindAny payload to be scrubbed, got %s", logged)
	}
}

func TestHTTPMiddleware_SanitizesRequestIDAndNoDuplicates(t *testing.T) {
	var buf bytes.Buffer
	l := New(Config{Level: "info", Format: "json", Output: &buf})
	mw := HTTPMiddleware(l)

	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Malicious CRLF in X-Request-Id must be rejected and replaced
	req := httptest.NewRequest(http.MethodGet, "/v1/chat/completions", nil)
	req.Header.Set("X-Request-Id", "bad\r\nid\ninjection")
	tc := observability.ParseOrGenerateTrace(req)
	req = req.WithContext(observability.WithTraceContext(req.Context(), tc))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	gwID := rec.Header().Get("X-Gateway-Request-Id")
	if !strings.HasPrefix(gwID, "req_") {
		t.Fatalf("expected sanitized fallback req_ ID, got %q", gwID)
	}

	// Verify trace_id and request_id appear exactly once in raw JSON log line
	line := buf.String()
	if strings.Count(line, `"request_id"`) != 1 {
		t.Fatalf("expected exactly 1 request_id in log line, got: %s", line)
	}
	if strings.Count(line, `"trace_id"`) != 1 {
		t.Fatalf("expected exactly 1 trace_id in log line, got: %s", line)
	}

	var parsed map[string]any
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid json log: %v", err)
	}
}

func TestResponseRecorder_SetsOctetStreamWhenContentTypeUnset(t *testing.T) {
	var buf bytes.Buffer
	l := New(Config{Level: "info", Format: "json", Output: &buf})
	mw := HTTPMiddleware(l)

	t.Run("defaults unset content-type to application/octet-stream", func(t *testing.T) {
		handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write([]byte("<html><script>alert(1)</script></html>"))
		}))
		req := httptest.NewRequest(http.MethodGet, "/v1/custom", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if got := rec.Header().Get("Content-Type"); got != "application/octet-stream" {
			t.Fatalf("expected Content-Type application/octet-stream, got %q", got)
		}
	})

	t.Run("preserves explicit content-type", func(t *testing.T) {
		handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			_, _ = w.Write([]byte("ok"))
		}))
		req := httptest.NewRequest(http.MethodGet, "/v1/custom", nil)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if got := rec.Header().Get("Content-Type"); got != "text/plain; charset=utf-8" {
			t.Fatalf("expected explicit Content-Type to be preserved, got %q", got)
		}
	})
}
