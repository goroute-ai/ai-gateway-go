package observability

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

func TestCollector_CapsProvidersMap(t *testing.T) {
	c := NewCollector()
	for i := range maxProviderEntries + 50 {
		c.Record(RequestObservation{
			Provider:   fmt.Sprintf("provider-%d", i),
			StatusCode: 200,
			LatencyMs:  5,
		})
	}

	snap := c.Snapshot()
	if len(snap.Providers) > maxProviderEntries {
		t.Fatalf("expected providers map to be capped at %d, got %d", maxProviderEntries, len(snap.Providers))
	}
}

func TestParseOrGenerateTrace_RejectsInvalidAndAllZeroTraceIDs(t *testing.T) {
	// All-zero traceparent must be rejected
	reqZero := httptest.NewRequest(http.MethodGet, "/test", nil)
	reqZero.Header.Set("traceparent", "00-00000000000000000000000000000000-0123456789abcdef-01")
	tcZero := ParseOrGenerateTrace(reqZero)
	if tcZero.TraceID == "00000000000000000000000000000000" || !isValidTraceID(tcZero.TraceID) {
		t.Fatalf("expected valid non-zero trace ID, got %q", tcZero.TraceID)
	}

	// Non-hex X-Trace-Id must be rejected
	reqBadHex := httptest.NewRequest(http.MethodGet, "/test", nil)
	reqBadHex.Header.Set("X-Trace-Id", "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz")
	tcBad := ParseOrGenerateTrace(reqBadHex)
	if tcBad.TraceID == "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz" || !isValidTraceID(tcBad.TraceID) {
		t.Fatalf("expected valid hex trace ID, got %q", tcBad.TraceID)
	}

	// Valid hex traceparent is accepted and lowercased
	reqValid := httptest.NewRequest(http.MethodGet, "/test", nil)
	reqValid.Header.Set("traceparent", "00-0123456789ABCDEF0123456789ABCDEF-0123456789abcdef-01")
	tcValid := ParseOrGenerateTrace(reqValid)
	if tcValid.TraceID != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("expected lowercased valid trace ID, got %q", tcValid.TraceID)
	}
}

func TestOTLPSamplerConfiguration(t *testing.T) {
	t.Setenv("OTEL_TRACES_SAMPLER", "always_off")
	s := resolveOTLPSamplerFromEnv()
	if s.Description() != sdktrace.NeverSample().Description() {
		t.Fatalf("expected NeverSample, got %q", s.Description())
	}

	t.Setenv("OTEL_TRACES_SAMPLER", "traceidratio")
	t.Setenv("OTEL_TRACES_SAMPLER_ARG", "0.25")
	s2 := resolveOTLPSamplerFromEnv()
	if s2.Description() != sdktrace.TraceIDRatioBased(0.25).Description() {
		t.Fatalf("expected TraceIDRatioBased(0.25), got %q", s2.Description())
	}
}

func TestTraceMiddleware_SanitizesRequestIDAndSetsDefaultContentType(t *testing.T) {
	mw := TraceMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("<html><script>alert(1)</script></html>"))
	}))

	t.Run("drops unsafe X-Request-Id and sets octet-stream fallback", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/test", nil)
		req.Header.Set("X-Request-Id", "<script>alert(1)</script>")
		rec := httptest.NewRecorder()
		mw.ServeHTTP(rec, req)

		if got := rec.Header().Get("X-Request-Id"); got != "" {
			t.Fatalf("expected unsafe X-Request-Id to be dropped, got %q", got)
		}
		if got := rec.Header().Get("Content-Type"); got != "application/octet-stream" {
			t.Fatalf("expected fallback Content-Type application/octet-stream, got %q", got)
		}
	})

	t.Run("preserves safe X-Request-Id", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/v1/test", nil)
		req.Header.Set("X-Request-Id", "req_safe-123.abc:45")
		rec := httptest.NewRecorder()
		mw.ServeHTTP(rec, req)

		if got := rec.Header().Get("X-Request-Id"); got != "req_safe-123.abc:45" {
			t.Fatalf("expected safe X-Request-Id to be preserved, got %q", got)
		}
	})
}
