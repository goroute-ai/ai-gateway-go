package observability

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
)

func TestNewOTLPTracerExportsServerSpansAndPropagatesTraceContext(t *testing.T) {
	requests := make(chan string, 1)
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
	if _, _, err := NewOTLPTracer(context.Background(), config.TracingConfig{OTLPEndpoint: "http://collector.example/v1/traces"}, policy); err == nil {
		t.Fatal("expected insecure endpoint to be rejected by the outbound policy")
	}
}
