package logger

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type captureSlogHandler struct {
	records []map[string]any
}

func (c *captureSlogHandler) Enabled(context.Context, slog.Level) bool { return true }
func (c *captureSlogHandler) Handle(_ context.Context, r slog.Record) error {
	m := map[string]any{"msg": r.Message, "level": r.Level.String()}
	r.Attrs(func(a slog.Attr) bool {
		m[a.Key] = a.Value.Any()
		return true
	})
	c.records = append(c.records, m)
	return nil
}
func (c *captureSlogHandler) WithAttrs([]slog.Attr) slog.Handler { return c }
func (c *captureSlogHandler) WithGroup(string) slog.Handler      { return c }

func TestHTTPMiddlewareIncludesDownstreamTenantIdentityAndOTLPScrubsSecrets(t *testing.T) {
	var buf bytes.Buffer
	otlpCap := &captureSlogHandler{}
	l := NewWithOTLPHandler(Config{Level: "info", Format: "json", Output: &buf}, otlpCap)

	mw := HTTPMiddleware(l)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulates downstream auth middleware setting tenant identity on a child context.
		SetRequestIdentity(r.Context(), RequestIdentity{
			OrgID:        "org_acme",
			TeamID:       "team_ai",
			VirtualKeyID: "vk_123",
			KeyPrefix:    "sk-gw-abc123",
		})
		SetInferenceMeta(r.Context(), InferenceMeta{
			Model:      "gpt-4.1",
			Provider:   "openai",
			CostMicros: 500,
		})
		l.InfoContext(r.Context(), "calling upstream with Bearer sk-secret-token-9999",
			slog.String("email", "alice@example.com"),
			slog.String("api_key", "sk-gw-live-supersecret"),
		)
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	rec := httptest.NewRecorder()
	mw.ServeHTTP(rec, req)

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) < 2 {
		t.Fatalf("expected >= 2 log lines, got %q", buf.String())
	}

	// Verify final HTTP access log line includes tenant identity resolved by downstream auth MW.
	var accessLog map[string]any
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &accessLog); err != nil {
		t.Fatalf("unmarshal access log: %v", err)
	}
	if accessLog["org_id"] != "org_acme" || accessLog["team_id"] != "team_ai" || accessLog["virtual_key_id"] != "vk_123" || accessLog["key_prefix"] != "sk-gw-abc123" {
		t.Fatalf("HTTP access log missing tenant identity: %+v", accessLog)
	}
	if accessLog["model"] != "gpt-4.1" || accessLog["provider"] != "openai" {
		t.Fatalf("HTTP access log missing inference meta: %+v", accessLog)
	}

	// Verify OTLP handler received scrubbed records (zero raw secrets or emails!).
	if len(otlpCap.records) < 2 {
		t.Fatalf("expected >= 2 OTLP records, got %d", len(otlpCap.records))
	}
	firstOTLP := otlpCap.records[0]
	if msg, _ := firstOTLP["msg"].(string); strings.Contains(msg, "sk-secret-token-9999") {
		t.Fatalf("secret leaked into OTLP log message: %q", msg)
	}
	if email, _ := firstOTLP["email"].(string); strings.Contains(email, "alice@example.com") {
		t.Fatalf("email leaked into OTLP log attribute: %q", email)
	}
	if apiKey, _ := firstOTLP["api_key"].(string); strings.Contains(apiKey, "supersecret") {
		t.Fatalf("api_key leaked into OTLP log attribute: %q", apiKey)
	}
	accessOTLP := otlpCap.records[len(otlpCap.records)-1]
	if accessOTLP["org_id"] != "org_acme" {
		t.Fatalf("expected org_id on OTLP access log, got %+v", accessOTLP)
	}
}
