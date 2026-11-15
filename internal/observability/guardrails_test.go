package observability

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestCollector_GuardrailMetricsPrometheusAndOTLP(t *testing.T) {
	col := NewCollector()
	col.RecordGuardrailEvaluation(GuardrailObservation{
		GuardrailName: "pii-detector",
		Hook:          "pre_call",
		Decision:      "block",
		LatencyMs:     12,
	})
	col.RecordGuardrailEvaluation(GuardrailObservation{
		GuardrailName: "pii-detector",
		Hook:          "pre_call",
		Decision:      "allow",
		LatencyMs:     4,
	})
	col.RecordGuardrailEvaluation(GuardrailObservation{
		GuardrailName: "pii-detector",
		Hook:          "pre_call",
		Decision:      "error",
		LatencyMs:     80,
		IsError:       true,
	})

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rec := httptest.NewRecorder()
	col.PrometheusHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	for _, want := range []string{
		`gateway_guardrail_evaluations_total{guardrail="pii-detector",hook="pre_call",decision="allow"} 1`,
		`gateway_guardrail_evaluations_total{guardrail="pii-detector",hook="pre_call",decision="block"} 1`,
		`gateway_guardrail_evaluations_total{guardrail="pii-detector",hook="pre_call",decision="error"} 1`,
		`gateway_guardrail_errors_total{guardrail="pii-detector",hook="pre_call"} 1`,
		`gateway_guardrail_duration_ms_bucket{guardrail="pii-detector",hook="pre_call",le="5"} 1`,
		`gateway_guardrail_duration_ms_bucket{guardrail="pii-detector",hook="pre_call",le="25"} 2`,
		`gateway_guardrail_duration_ms_bucket{guardrail="pii-detector",hook="pre_call",le="+Inf"} 3`,
		`gateway_guardrail_duration_ms_sum{guardrail="pii-detector",hook="pre_call"} 96`,
		`gateway_guardrail_duration_ms_count{guardrail="pii-detector",hook="pre_call"} 3`,
	} {
		if !strings.Contains(body, want) {
			t.Fatalf("expected Prometheus output to contain %q, got:\n%s", want, body)
		}
	}
	if strings.Contains(body, "deployment_id=") || strings.Contains(body, "name=") {
		t.Fatalf("Prometheus labels must not expose forbidden keys: %s", body)
	}

	exp := &OTLPMetricsExporter{
		collector:   col,
		serviceName: "test",
		startTimeNs: 1,
	}
	payload := exp.buildPayload()
	foundEval := false
	foundErr := false
	for _, m := range payload.ResourceMetrics[0].ScopeMetrics[0].Metrics {
		if m.Name == "gateway_guardrail_evaluations_total" {
			foundEval = true
		}
		if m.Name == "gateway_guardrail_errors_total" {
			foundErr = true
		}
	}
	if !foundEval || !foundErr {
		t.Fatalf("expected OTLP guardrail metrics in payload, eval=%v err=%v", foundEval, foundErr)
	}
}

func TestGuardrailOTELSpanScrubsSensitiveViolationTags(t *testing.T) {
	recorder := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	tracer := tp.Tracer("test")

	ctx, span := StartGuardrailEvaluateSpan(context.Background(), tracer, "dlp-scanner", "pre_call")
	_ = ctx
	FinishGuardrailEvaluateSpan(span, "modify", []string{
		"pii.email",
		"user@example.com raw secret",
		"sk-live-secret-token-12345",
		"prompt_injection",
	}, 18, false)

	spans := recorder.Ended()
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}
	if spans[0].Name() != "guardrail.evaluate" {
		t.Fatalf("expected span name guardrail.evaluate, got %q", spans[0].Name())
	}
	attrMap := make(map[string]any)
	for _, a := range spans[0].Attributes() {
		attrMap[string(a.Key)] = a.Value.AsInterface()
	}
	if attrMap["guardrail.name"] != "dlp-scanner" {
		t.Fatalf("unexpected guardrail.name: %v", attrMap["guardrail.name"])
	}
	if attrMap["guardrail.hook"] != "pre_call" {
		t.Fatalf("unexpected guardrail.hook: %v", attrMap["guardrail.hook"])
	}
	if attrMap["guardrail.decision"] != "modify" {
		t.Fatalf("unexpected guardrail.decision: %v", attrMap["guardrail.decision"])
	}
	if attrMap["guardrail.latency_ms"] != int64(18) {
		t.Fatalf("unexpected guardrail.latency_ms: %v", attrMap["guardrail.latency_ms"])
	}
	cats, ok := attrMap["guardrail.violation_categories"].([]string)
	if !ok {
		t.Fatalf("expected string slice categories, got %T", attrMap["guardrail.violation_categories"])
	}
	joined := strings.Join(cats, ",")
	if strings.Contains(joined, "example.com") || strings.Contains(joined, "sk-live") {
		t.Fatalf("sensitive material leaked into span attributes: %v", cats)
	}
	if !strings.Contains(joined, "pii.email") || !strings.Contains(joined, "policy_violation") || !strings.Contains(joined, "prompt_injection") {
		t.Fatalf("expected scrubbed category tags, got %v", cats)
	}
}
