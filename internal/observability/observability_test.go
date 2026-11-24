package observability

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func collectMetricMap(t *testing.T, reader *sdkmetric.ManualReader) map[string]metricdata.Metrics {
	t.Helper()
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("collect OTel metrics: %v", err)
	}
	out := make(map[string]metricdata.Metrics)
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			out[m.Name] = m
		}
	}
	return out
}

func sumInt64Value(t *testing.T, m metricdata.Metrics) int64 {
	t.Helper()
	sum, ok := m.Data.(metricdata.Sum[int64])
	if !ok {
		t.Fatalf("metric %q expected Sum[int64], got %T", m.Name, m.Data)
	}
	var total int64
	for _, dp := range sum.DataPoints {
		total += dp.Value
	}
	return total
}

func gaugeInt64Value(t *testing.T, m metricdata.Metrics) int64 {
	t.Helper()
	g, ok := m.Data.(metricdata.Gauge[int64])
	if !ok || len(g.DataPoints) == 0 {
		t.Fatalf("metric %q expected non-empty Gauge[int64], got %T", m.Name, m.Data)
	}
	return g.DataPoints[0].Value
}

func TestCollectorSnapshotAndOTelInstruments(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	t.Cleanup(func() { _ = mp.Shutdown(context.Background()) })

	inst, err := NewInstruments(mp.Meter(instrumentationScopeName))
	if err != nil {
		t.Fatalf("NewInstruments: %v", err)
	}

	col := NewCollector()
	col.SetInstruments(inst)
	col.SetFinOpsOutboxProvider(func() (int64, int64, int64) { return 3, 1, 2 })
	col.SetAuditSIEMProvider(func() (int64, int64, int64) { return 12, 1, 0 })
	col.SetOTelStatusProvider(func() OTelStatus {
		return OTelStatus{Enabled: true, TracesActive: true, MetricsActive: true}
	})
	if err := inst.RegisterOperationalCallbacks(OperationalMetricsProviders{
		CacheTelemetry: func() CacheTelemetry {
			return CacheTelemetry{
				Enabled: true, Type: "redis-semantic", Status: "ok",
				Hits: 9, Misses: 1, SemanticHits: 6, Errors: 2, Entries: 42, Evictions: 3,
			}
		},
		FinOpsOutbox: func() (int64, int64, int64) { return 3, 1, 2 },
		AuditSIEM:    func() (int64, int64, int64) { return 12, 1, 0 },
		DeploymentHealth: func() []DeploymentHealthMetric {
			return []DeploymentHealthMetric{{Provider: "openai", Model: "gpt-4.1", Healthy: true, ProbeLatencyMs: 35}}
		},
	}); err != nil {
		t.Fatalf("RegisterOperationalCallbacks: %v", err)
	}

	col.RecordDeploymentAttempt("dep-bad", "primary-dead", "openai", "gpt-4.1-mini", 40, true)
	col.Record(RequestObservation{
		Provider:          "anthropic",
		Model:             "claude-haiku-4-5-20251001",
		DeploymentID:      "dep-ant",
		DeploymentName:    "anthropic-live",
		StatusCode:        200,
		LatencyMs:         650,
		TTFTMs:            220,
		RoutingMicros:     85,
		PromptTokens:      19,
		CompletionTokens:  7,
		CostMicros:        44,
		FallbackAttempted: true,
		RetryCount:        1,
	})
	col.Record(RequestObservation{
		Provider:         "groq",
		Model:            "llama-3.1-8b-instant",
		DeploymentID:     "dep-groq",
		DeploymentName:   "groq-live",
		StatusCode:       200,
		LatencyMs:        420,
		TTFTMs:           150,
		RoutingMicros:    42,
		PromptTokens:     13,
		CompletionTokens: 2,
		CostMicros:       4,
	})
	col.Record(RequestObservation{
		Provider:   "groq",
		Model:      "llama-3.1-8b-instant",
		StatusCode: 200,
		CacheHit:   true,
	})
	col.Record(RequestObservation{StatusCode: 429, RateLimited: true})
	col.Record(RequestObservation{StatusCode: 400, GuardrailBlocked: true})
	col.RecordStream(2*time.Second, 250*time.Millisecond, false)
	col.RecordStream(3*time.Second, 0, true)
	inst.RecordGenAIOperation(context.Background(), GenAIOperationObservation{
		Operation:    "chat",
		Provider:     "anthropic",
		RequestModel: "claude-haiku-4-5-20251001",
		Duration:     650 * time.Millisecond,
		TTFT:         220 * time.Millisecond,
		InputTokens:  19,
		OutputTokens: 7,
	})
	inst.RecordMCPRequest(context.Background(), "tools/call", "ok")
	inst.RecordA2ARequest(context.Background(), "message/send", "ok")

	snap := col.Snapshot()
	if snap.TotalRequests != 5 || snap.TotalFallbacks != 1 || snap.SlowestProvider != "anthropic" || snap.HighestFailureDeployment != "primary-dead" {
		t.Fatalf("unexpected snapshot summary: %+v", snap)
	}
	if snap.CacheHits != 1 || snap.RateLimitRejections != 1 || snap.GuardrailBlocks != 1 {
		t.Fatalf("unexpected cache/rl/guardrail counters: %+v", snap)
	}
	if !snap.OTelEnabled || len(snap.OTelSignals) != 2 || snap.FinOpsOutboxPending != 3 || snap.AuditSIEMDelivered != 12 {
		t.Fatalf("unexpected OTel/outbox/SIEM snapshot fields: %+v", snap)
	}

	// Verify pure dot-separated OTel GenAI & gateway.* metrics via ManualReader.
	metricsMap := collectMetricMap(t, reader)
	for _, wantName := range []string{
		"gen_ai.client.operation.duration",
		"gen_ai.client.token.usage",
		"gen_ai.server.time_to_first_token",
		"gateway.requests",
		"gateway.errors",
		"gateway.request.duration",
		"gateway.routing.overhead",
		"gateway.routing.fallbacks",
		"gateway.routing.retries",
		"gateway.ratelimit.rejections",
		"gateway.guardrail.blocks",
		"gateway.streams",
		"gateway.stream.errors",
		"gateway.stream.duration",
		"gateway.stream.ttft",
		"gateway.provider.requests",
		"gateway.provider.spend",
		"gateway.cache.hits",
		"gateway.cache.misses",
		"gateway.cache.errors",
		"gateway.cache.semantic_hits",
		"gateway.cache.entries",
		"gateway.cache.evictions",
		"gateway.redis.circuit_breaker.state",
		"gateway.finops.outbox.pending",
		"gateway.finops.outbox.dead_letter",
		"gateway.finops.outbox.backpressure",
		"gateway.audit.siem.delivered",
		"gateway.audit.siem.failed",
		"gateway.audit.siem.dropped",
		"gateway.deployment.healthy",
		"gateway.deployment.probe.latency",
		"gateway.mcp.requests",
		"gateway.a2a.requests",
		"gateway.go.memory.heap_alloc",
		"gateway.go.gc.cycles",
		"gateway.go.gc.pause",
	} {
		if _, ok := metricsMap[wantName]; !ok {
			t.Fatalf("expected OTel metric %q to be registered and collected", wantName)
		}
	}
	if got := sumInt64Value(t, metricsMap["gateway.requests"]); got != 5 {
		t.Fatalf("expected gateway.requests=5, got %d", got)
	}
	if got := sumInt64Value(t, metricsMap["gateway.cache.hits"]); got != 9 {
		t.Fatalf("expected gateway.cache.hits=9, got %d", got)
	}
	if got := gaugeInt64Value(t, metricsMap["gateway.cache.entries"]); got != 42 {
		t.Fatalf("expected gateway.cache.entries=42, got %d", got)
	}
	if got := gaugeInt64Value(t, metricsMap["gateway.finops.outbox.pending"]); got != 3 {
		t.Fatalf("expected gateway.finops.outbox.pending=3, got %d", got)
	}

	// Authoritative cache telemetry provider overrides Collector counters in Snapshot().
	col.SetCacheTelemetryProvider(func() CacheTelemetry {
		return CacheTelemetry{
			Enabled: true, Type: "redis-semantic", Status: "ok",
			Hits: 9, Misses: 1, SemanticHits: 6, Errors: 2, Entries: 42, Evictions: 3,
		}
	})
	snapRich := col.Snapshot()
	if !snapRich.CacheEnabled || snapRich.CacheType != "redis-semantic" || snapRich.CacheHitRate != 0.9 {
		t.Fatalf("unexpected rich cache telemetry snapshot: %+v", snapRich)
	}
}

func TestCollectorSlidingWindowEvictsStaleLatencySpikes(t *testing.T) {
	col := NewCollector()
	// Record initial high-latency spike.
	col.Record(RequestObservation{Provider: "openai", StatusCode: 200, LatencyMs: 9000})
	// Push maxWindowSamples low-latency observations to flush out the old spike completely.
	for range maxWindowSamples {
		col.Record(RequestObservation{Provider: "openai", StatusCode: 200, LatencyMs: 20})
	}
	snap := col.Snapshot()
	if snap.P99LatencyMs != 20 {
		t.Fatalf("expected sliding window P99 to decay to 20ms after %d new samples, got %dms", maxWindowSamples, snap.P99LatencyMs)
	}
}

func TestTraceMiddlewareSetsLowCardinalityChiRouteAndTraceFlags(t *testing.T) {
	recorder := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })

	r := chi.NewRouter()
	r.Use(TraceMiddlewareWithTracer(tp.Tracer("test")))
	r.Get("/admin/v1/keys/{keyID}", func(w http.ResponseWriter, r *http.Request) {
		tc := TraceFromContext(r.Context())
		if len(tc.TraceID) != 32 {
			t.Errorf("expected 32-char trace_id, got %q", tc.TraceID)
		}
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodGet, "/admin/v1/keys/vk-12345-secret-id", nil)
	req.Header.Set("traceparent", "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	if got := rec.Header().Get("X-Trace-Id"); got != "4bf92f3577b34da6a3ce929d0e0e4736" {
		t.Fatalf("expected propagated X-Trace-Id, got %q", got)
	}
	spans := recorder.Ended()
	if len(spans) != 1 {
		t.Fatalf("expected 1 span, got %d", len(spans))
	}
	if spans[0].Name() != "HTTP GET /admin/v1/keys/{keyID}" {
		t.Fatalf("expected low-cardinality chi route span name, got %q", spans[0].Name())
	}
}
