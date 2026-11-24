package observability

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestNewOTLPTracerExportsServerSpansAndPropagatesTraceContext(t *testing.T) {
	requests := make(chan string, 2)
	exporter := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		requests <- r.URL.Path + ":" + string(body)
		w.WriteHeader(http.StatusOK)
	}))
	defer exporter.Close()

	policy, err := network.NewPolicy(config.OutboundSSRFConfig{
		AllowPrivateNetworks: true,
		AllowInsecureHTTP:    true,
		AllowedSchemes:       []string{"http", "https"},
	})
	if err != nil {
		t.Fatalf("create network policy: %v", err)
	}
	tracer, shutdown, err := NewOTLPTracer(context.Background(), config.TracingConfig{
		Enabled:      true,
		OTLPEndpoint: exporter.URL,
		ServiceName:  "gateway-test",
	}, policy)
	if err != nil {
		t.Fatalf("create OTLP tracer: %v", err)
	}

	handler := TraceMiddlewareWithTracer(tracer)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tc := TraceFromContext(r.Context())
		if tc.TraceID != "0123456789abcdef0123456789abcdef" {
			t.Errorf("trace ID was not propagated: %q", tc.TraceID)
		}
		if tc.SpanID == "" || tc.SpanID == "0123456789abcdef" {
			t.Errorf("expected a child span ID, got %q", tc.SpanID)
		}
	}))
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Header.Set("traceparent", "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01")
	resp := httptest.NewRecorder()
	handler.ServeHTTP(resp, req)
	if resp.Header().Get("X-Trace-Id") != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("unexpected trace response header: %q", resp.Header().Get("X-Trace-Id"))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := shutdown(ctx); err != nil {
		t.Fatalf("shutdown tracer: %v", err)
	}
	select {
	case payload := <-requests:
		if !strings.HasPrefix(payload, "/v1/traces:") || !strings.Contains(payload, "gateway-test") {
			t.Fatalf("unexpected OTLP request: %s", payload)
		}
	case <-ctx.Done():
		t.Fatal("timed out waiting for OTLP export")
	}
}

func TestNewTelemetryRuntimeRespectsEnabledFalseEvenWithEndpoint(t *testing.T) {
	hit := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hit = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	rt, err := NewTelemetryRuntime(context.Background(), config.OTelConfig{
		Enabled:  false,
		Endpoint: srv.URL,
		Logs:     config.OTelLogsConfig{Enabled: true},
	}, nil, RuntimeOptions{})
	if err != nil {
		t.Fatalf("expected disabled OTel runtime to succeed with nil policy: %v", err)
	}
	st := rt.Status()
	if st.Enabled || st.TracesActive || st.MetricsActive || st.LogsActive || rt.LogHandler() != nil {
		t.Fatalf("expected all OTLP signals disabled, got status=%+v logHandler=%v", st, rt.LogHandler())
	}
	if err := rt.Shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown disabled runtime: %v", err)
	}
	if hit {
		t.Fatal("expected zero outbound OTLP requests when otel.enabled is false")
	}
}

func TestNewTelemetryRuntimeExportsAllThreeOTLPSignals(t *testing.T) {
	var mu sync.Mutex
	paths := make(map[string]int)
	headersSeen := make(map[string]string)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		mu.Lock()
		paths[r.URL.Path]++
		headersSeen[r.URL.Path] = r.Header.Get("X-OTLP-Auth")
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	policy, err := network.NewPolicy(config.OutboundSSRFConfig{
		AllowPrivateNetworks: true,
		AllowInsecureHTTP:    true,
		AllowedSchemes:       []string{"http", "https"},
	})
	if err != nil {
		t.Fatalf("create policy: %v", err)
	}

	rt, err := NewTelemetryRuntime(context.Background(), config.OTelConfig{
		Enabled:               true,
		Endpoint:              srv.URL,
		ServiceName:           "goroute-3sig-test",
		DeploymentEnvironment: "staging",
		Headers:               map[string]string{"X-OTLP-Auth": "token-123"},
		Metrics:               config.OTelMetricsConfig{ExportInterval: 50 * time.Millisecond},
		Logs:                  config.OTelLogsConfig{Enabled: true},
	}, policy, RuntimeOptions{ServiceVersion: "v0.1.0"})
	if err != nil {
		t.Fatalf("NewTelemetryRuntime: %v", err)
	}
	st := rt.Status()
	if !st.Enabled || !st.TracesActive || !st.MetricsActive || !st.LogsActive || rt.LogHandler() == nil {
		t.Fatalf("expected all 3 OTLP signals active, got %+v", st)
	}

	// Emit one trace span, one metric, and one OTLP log record.
	_, span := StartGenAISpan(context.Background(), rt.Tracer(), GenAISpanStart{
		Operation: "chat", Provider: "openai", RequestModel: "gpt-4.1",
	})
	RecordGenAIFirstToken(span, 40*time.Millisecond)
	FinishGenAISpan(span, GenAISpanEnd{ResponseModel: "gpt-4.1", InputTokens: 10, OutputTokens: 5})

	rt.Instruments().RecordRequest(context.Background(), RequestObservation{Provider: "openai", StatusCode: 200, LatencyMs: 50})
	slog.New(rt.LogHandler()).Info("otlp 3-signal log test", slog.String("org_id", "org_test"))

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := rt.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown 3-signal runtime: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	for _, p := range []string{"/v1/traces", "/v1/metrics", "/v1/logs"} {
		if paths[p] == 0 {
			t.Fatalf("expected OTLP POST to %s, got paths=%v", p, paths)
		}
		if headersSeen[p] != "token-123" {
			t.Fatalf("expected X-OTLP-Auth header on %s, got %q", p, headersSeen[p])
		}
	}
}

func TestGenAISpanPrivacyDefaultAndCacheLookupSpan(t *testing.T) {
	recorder := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
	t.Cleanup(func() { _ = tp.Shutdown(context.Background()) })
	tracer := tp.Tracer("test")

	temp := 0.2
	ctx, span := StartGenAISpan(context.Background(), tracer, GenAISpanStart{
		Operation:    "chat",
		Provider:     "anthropic",
		RequestModel: "claude-haiku-4-5-20251001",
		Temperature:  &temp,
		OrgID:        "org_alpha",
	})
	RecordGenAIFirstToken(span, 125*time.Millisecond)
	FinishGenAISpan(span, GenAISpanEnd{
		ResponseModel:  "claude-haiku-4-5-20251001",
		InputTokens:    100,
		OutputTokens:   40,
		CostMicros:     250,
		CaptureContent: false, // privacy default must omit input/output messages
		ScrubbedInput:  "secret prompt must not appear",
		ScrubbedOutput: "secret completion must not appear",
	})

	_, cacheSpan := StartCacheLookupSpan(ctx, tracer, "redis-semantic", "gpt-4.1")
	FinishCacheLookupSpan(cacheSpan, true, "semantic", 0.94, nil)

	spans := recorder.Ended()
	if len(spans) != 2 {
		t.Fatalf("expected 2 spans, got %d", len(spans))
	}
	if spans[0].Name() != "chat claude-haiku-4-5-20251001" {
		t.Fatalf("unexpected GenAI span name: %q", spans[0].Name())
	}
	attrs := make(map[string]any)
	for _, a := range spans[0].Attributes() {
		attrs[string(a.Key)] = a.Value.AsInterface()
	}
	if attrs["gen_ai.operation.name"] != "chat" || attrs["gen_ai.provider.name"] != "anthropic" || attrs["gen_ai.usage.input_tokens"] != int64(100) {
		t.Fatalf("unexpected GenAI span attrs: %+v", attrs)
	}
	if _, leaked := attrs["gen_ai.input.messages"]; leaked {
		t.Fatal("gen_ai.input.messages must not be attached when CaptureContent is false")
	}
	if len(spans[0].Events()) != 1 || spans[0].Events()[0].Name != "gen_ai.first_token" {
		t.Fatalf("expected gen_ai.first_token span event, got %+v", spans[0].Events())
	}
	if spans[1].Name() != "cache.lookup" {
		t.Fatalf("expected cache.lookup span, got %q", spans[1].Name())
	}
}

func TestNewOTLPTracerIsNoopWhenEndpointIsUnset(t *testing.T) {
	tracer, shutdown, err := NewOTLPTracer(context.Background(), config.TracingConfig{}, nil)
	if err != nil || tracer == nil {
		t.Fatalf("expected disabled tracing to return a no-op tracer, tracer=%v err=%v", tracer, err)
	}
	if err := shutdown(context.Background()); err != nil {
		t.Fatalf("shutdown no-op tracer: %v", err)
	}
}

func TestNoopTracingStillCreatesChildCorrelationID(t *testing.T) {
	tracer, shutdown, err := NewOTLPTracer(context.Background(), config.TracingConfig{}, nil)
	if err != nil {
		t.Fatalf("create no-op tracer: %v", err)
	}
	defer shutdown(context.Background())
	handler := TraceMiddlewareWithTracer(tracer)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tc := TraceFromContext(r.Context())
		if tc.TraceID != "0123456789abcdef0123456789abcdef" || tc.SpanID == "0123456789abcdef" {
			t.Errorf("expected trace ID to continue with a new span ID, got %+v", tc)
		}
	}))
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Header.Set("traceparent", "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01")
	handler.ServeHTTP(httptest.NewRecorder(), req)
}

func TestNewOTLPTracerRejectsEndpointBlockedByNetworkPolicy(t *testing.T) {
	policy, err := network.NewPolicy(config.OutboundSSRFConfig{AllowedSchemes: []string{"https"}})
	if err != nil {
		t.Fatalf("create network policy: %v", err)
	}
	if _, _, err := NewOTLPTracer(context.Background(), config.TracingConfig{Enabled: true, OTLPEndpoint: "http://collector.example/v1/traces"}, policy); err == nil {
		t.Fatal("expected insecure endpoint to be rejected by the outbound policy")
	}
}
