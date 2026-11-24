package observability

import (
	"context"
	"strings"
	"testing"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestCollector_GuardrailMetricsOTel(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = mp.Shutdown(context.Background()) })

	inst, err := NewInstruments(mp.Meter(instrumentationScopeName))
	if err != nil {
		t.Fatalf("NewInstruments: %v", err)
	}

	col := NewCollector()
	col.SetInstruments(inst)
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
	// Simulate the blocked request being recorded once by the gateway handler (must NOT double-count).
	col.Record(RequestObservation{StatusCode: 400, GuardrailBlocked: true})

	snap := col.Snapshot()
	if snap.GuardrailBlocks != 1 {
		t.Fatalf("expected exactly 1 blocked request (no double-counting), got %d", snap.GuardrailBlocks)
	}
	if len(snap.GuardrailMetrics) != 1 {
		t.Fatalf("expected 1 guardrail summary, got %d", len(snap.GuardrailMetrics))
	}
	gm := snap.GuardrailMetrics[0]
	if gm.Evaluations != 3 || gm.Errors != 1 || gm.DurationSumMs != 96 || gm.DurationCount != 3 || gm.DecisionCounts["block"] != 1 {
		t.Fatalf("unexpected guardrail snapshot summary: %+v", gm)
	}

	metricsMap := collectMetricMap(t, reader)
	blocksMetric, ok := metricsMap["gateway.guardrail.blocks"]
	if !ok || sumInt64Value(t, blocksMetric) != 1 {
		t.Fatalf("expected gateway.guardrail.blocks=1 (no double-counting), got %+v", blocksMetric)
	}
	evals, ok := metricsMap["gateway.guardrail.evaluations"]
	if !ok {
		t.Fatalf("missing gateway.guardrail.evaluations in OTel metrics")
	}
	if sumInt64Value(t, evals) != 3 {
		t.Fatalf("expected 3 total guardrail evaluations, got %d", sumInt64Value(t, evals))
	}
	errsMetric, ok := metricsMap["gateway.guardrail.errors"]
	if !ok || sumInt64Value(t, errsMetric) != 1 {
		t.Fatalf("expected gateway.guardrail.errors=1, got %+v", errsMetric)
	}
	durMetric, ok := metricsMap["gateway.guardrail.duration"]
	if !ok {
		t.Fatalf("missing gateway.guardrail.duration histogram")
	}
	hist, ok := durMetric.Data.(metricdata.Histogram[float64])
	if !ok || len(hist.DataPoints) != 1 || hist.DataPoints[0].Count != 3 || hist.DataPoints[0].Sum != 96 {
		t.Fatalf("unexpected gateway.guardrail.duration histogram: %+v", durMetric.Data)
	}
}

func TestGuardrailOTELSpanScrubsSensitiveViolationTags(t *testing.T) {
	recorder := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })
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
	if attrMap["guardrail.name"] != "dlp-scanner" || attrMap["guardrail.hook"] != "pre_call" || attrMap["guardrail.decision"] != "modify" || attrMap["guardrail.latency_ms"] != int64(18) {
		t.Fatalf("unexpected guardrail span attributes: %+v", attrMap)
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
