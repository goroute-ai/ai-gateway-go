package observability

import (
	"fmt"
	"net/http/httptest"
	"testing"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

func TestCollector_CapsProvidersMap(t *testing.T) {
	c := NewCollector()
	for i := 0; i < maxProviderEntries+50; i++ {
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
	reqZero := httptest.NewRequest("GET", "/test", nil)
	reqZero.Header.Set("traceparent", "00-00000000000000000000000000000000-0123456789abcdef-01")
	tcZero := ParseOrGenerateTrace(reqZero)
	if tcZero.TraceID == "00000000000000000000000000000000" || !isValidTraceID(tcZero.TraceID) {
		t.Fatalf("expected valid non-zero trace ID, got %q", tcZero.TraceID)
	}

	// Non-hex X-Trace-Id must be rejected
	reqBadHex := httptest.NewRequest("GET", "/test", nil)
	reqBadHex.Header.Set("X-Trace-Id", "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz")
	tcBad := ParseOrGenerateTrace(reqBadHex)
	if tcBad.TraceID == "zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz" || !isValidTraceID(tcBad.TraceID) {
		t.Fatalf("expected valid hex trace ID, got %q", tcBad.TraceID)
	}

	// Valid hex traceparent is accepted and lowercased
	reqValid := httptest.NewRequest("GET", "/test", nil)
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
