package logger_test

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/logger"
	"github.com/goroute-ai/ai-gateway-go/internal/observability"
)

func TestLevelParsing(t *testing.T) {
	tests := []struct {
		input    string
		expected slog.Level
	}{
		{"debug", slog.LevelDebug},
		{"DEBUG", slog.LevelDebug},
		{"info", slog.LevelInfo},
		{"warn", slog.LevelWarn},
		{"warning", slog.LevelWarn},
		{"error", slog.LevelError},
		{"unknown", slog.LevelInfo},
		{"", slog.LevelInfo},
	}

	for _, tc := range tests {
		actual := logger.ParseLevel(tc.input)
		if actual != tc.expected {
			t.Errorf("ParseLevel(%q) = %v, expected %v", tc.input, actual, tc.expected)
		}
	}
}

func TestJSONAndTextFormatting(t *testing.T) {
	// 1. Test JSON output
	var bufJSON bytes.Buffer
	lJSON := logger.New(logger.Config{
		Level:  "info",
		Format: "json",
		Output: &bufJSON,
	})

	lJSON.Info("test json message", "service", "ai-gateway", "cost_micros", 150)
	var parsed map[string]any
	if err := json.Unmarshal(bufJSON.Bytes(), &parsed); err != nil {
		t.Fatalf("expected valid JSON, got error: %v, raw: %s", err, bufJSON.String())
	}
	if parsed["msg"] != "test json message" {
		t.Errorf("expected msg 'test json message', got %v", parsed["msg"])
	}
	if parsed["service"] != "ai-gateway" {
		t.Errorf("expected service 'ai-gateway', got %v", parsed["service"])
	}
	if parsed["cost_micros"] != float64(150) {
		t.Errorf("expected cost_micros 150, got %v", parsed["cost_micros"])
	}

	// 2. Test Text output
	var bufText bytes.Buffer
	lText := logger.New(logger.Config{
		Level:  "info",
		Format: "text",
		Output: &bufText,
	})
	lText.Info("test text message", "key", "val")
	if !strings.Contains(bufText.String(), "test text message") || !strings.Contains(bufText.String(), "key=val") {
		t.Errorf("expected formatted text, got: %s", bufText.String())
	}
}

func TestContextAttributeExtraction(t *testing.T) {
	var buf bytes.Buffer
	l := logger.New(logger.Config{
		Level:  "info",
		Format: "json",
		Output: &buf,
	})

	ctx := context.Background()
	// Attach W3C Trace context
	ctx = observability.WithTraceContext(ctx, observability.TraceContext{
		TraceID: "0123456789abcdef0123456789abcdef",
		SpanID:  "0123456789abcdef",
	})
	// Attach Request ID
	ctx = logger.WithRequestID(ctx, "req_test_12345")
	// Attach Identity Context
	ctx = auth.WithIdentity(ctx, &domain.IdentityContext{
		OrgID:        "org_enterprise_abc",
		TeamID:       "team_finance_1",
		VirtualKeyID: "vk_789",
		KeyPrefix:    "sk-gw-789",
	})

	l.InfoContext(ctx, "authenticated execution")

	var m map[string]any
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		t.Fatalf("decode log failed: %v", err)
	}

	if m["trace_id"] != "0123456789abcdef0123456789abcdef" {
		t.Errorf("expected trace_id, got %v", m["trace_id"])
	}
	if m["span_id"] != "0123456789abcdef" {
		t.Errorf("expected span_id, got %v", m["span_id"])
	}
	if m["request_id"] != "req_test_12345" {
		t.Errorf("expected request_id, got %v", m["request_id"])
	}
	if m["org_id"] != "org_enterprise_abc" {
		t.Errorf("expected org_id, got %v", m["org_id"])
	}
	if m["team_id"] != "team_finance_1" {
		t.Errorf("expected team_id, got %v", m["team_id"])
	}
	if m["virtual_key_id"] != "vk_789" {
		t.Errorf("expected virtual_key_id, got %v", m["virtual_key_id"])
	}
	if m["key_prefix"] != "sk-gw-789" {
		t.Errorf("expected key_prefix, got %v", m["key_prefix"])
	}
}

func TestHTTPMiddleware(t *testing.T) {
	var buf bytes.Buffer
	l := logger.New(logger.Config{
		Level:  "info",
		Format: "json",
		Output: &buf,
	})

	mw := logger.HTTPMiddleware(l)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"success"}`))
	}))

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	req.Header.Set("X-Request-Id", "req_custom_999")
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if w.Header().Get("X-Gateway-Request-Id") != "req_custom_999" {
		t.Errorf("expected X-Gateway-Request-Id to be set")
	}

	var m map[string]any
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		t.Fatalf("decode log failed: %v", err)
	}

	if m["method"] != "POST" {
		t.Errorf("expected method POST, got %v", m["method"])
	}
	if m["path"] != "/v1/chat/completions" {
		t.Errorf("expected path /v1/chat/completions, got %v", m["path"])
	}
	if m["status"] != float64(200) {
		t.Errorf("expected status 200, got %v", m["status"])
	}
	if m["request_id"] != "req_custom_999" {
		t.Errorf("expected request_id req_custom_999, got %v", m["request_id"])
	}
}

func TestHealthProbeFilter(t *testing.T) {
	var buf bytes.Buffer
	l := logger.New(logger.Config{
		Level:  "info", // Probes should be suppressed at INFO level
		Format: "json",
		Output: &buf,
	})

	mw := logger.HTTPMiddleware(l)
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// Since logger level is INFO, /healthz (which emits at DEBUG) should produce NO output
	if buf.Len() != 0 {
		t.Errorf("expected /healthz to be filtered out at INFO level, got: %s", buf.String())
	}
}

func TestWithComponent(t *testing.T) {
	var buf bytes.Buffer
	logger.Init(logger.Config{
		Level:  "info",
		Format: "json",
		Output: &buf,
	})

	compLogger := logger.WithComponent("router")
	compLogger.Info("route selected", "model", "fast")

	var m map[string]any
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil {
		t.Fatalf("decode log failed: %v", err)
	}
	if m["component"] != "router" {
		t.Errorf("expected component 'router', got %v", m["component"])
	}
	if m["model"] != "fast" {
		t.Errorf("expected model 'fast', got %v", m["model"])
	}
}
