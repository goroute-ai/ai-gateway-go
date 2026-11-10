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

func TestOTLPMetricsExporterPushesMetricsOnPeriodicAndShutdownFlush(t *testing.T) {
	requests := make(chan string, 4)
	headersSeen := make(chan string, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		headersSeen <- r.Header.Get("X-OTLP-Token")
		requests <- r.URL.Path + ":" + string(body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	policy, err := network.NewPolicy(config.OutboundSSRFConfig{
		AllowPrivateNetworks: true,
		AllowInsecureHTTP:    true,
		AllowedSchemes:       []string{"http", "https"},
	})
	if err != nil {
		t.Fatalf("create network policy: %v", err)
	}

	collector := NewCollector()
	collector.SetAdditionalMetricsProvider(func() map[string]float64 {
		return map[string]float64{
			"gateway_finops_outbox_pending": 3,
		}
	})
	collector.Record(RequestObservation{
		Provider:         "openai",
		Model:            "gpt-4.1",
		StatusCode:       http.StatusOK,
		LatencyMs:        42,
		TTFTMs:           12,
		PromptTokens:     100,
		CompletionTokens: 50,
		CostMicros:       250,
	})
	collector.RecordSpendRedisDrift()

	exporter, err := NewOTLPMetricsExporter(collector, OTLPMetricsConfig{
		OTLPEndpoint:   srv.URL + "/v1/traces", // verifies /v1/traces is rewritten to /v1/metrics
		ServiceName:    "gateway-metrics-test",
		Headers:        map[string]string{"X-OTLP-Token": "secret-metrics-token"},
		ExportInterval: 20 * time.Millisecond,
	}, policy)
	if err != nil {
		t.Fatalf("NewOTLPMetricsExporter: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	exporter.Start(ctx)

	var payload string
	select {
	case payload = <-requests:
	case <-ctx.Done():
		t.Fatal("timed out waiting for periodic OTLP metrics export")
	}

	if gotHeader := <-headersSeen; gotHeader != "secret-metrics-token" {
		t.Fatalf("expected X-OTLP-Token header to be forwarded, got %q", gotHeader)
	}
	for _, want := range []string{
		"/v1/metrics:",
		"gateway-metrics-test",
		"gateway_requests_total",
		"gateway_provider_requests_total",
		"gateway_finops_redis_drift_total",
		"gateway_finops_outbox_pending",
		"openai",
	} {
		if !strings.Contains(payload, want) {
			t.Fatalf("OTLP metrics payload missing %q: %s", want, payload)
		}
	}

	if err := exporter.Shutdown(ctx); err != nil {
		t.Fatalf("Shutdown OTLP metrics exporter: %v", err)
	}
}

func TestOTLPMetricsExporterNoopAndNetworkPolicyValidation(t *testing.T) {
	collector := NewCollector()

	noopExporter, err := NewOTLPMetricsExporter(collector, OTLPMetricsConfig{}, nil)
	if err != nil || noopExporter == nil {
		t.Fatalf("expected no-op OTLP metrics exporter when endpoint is unset, got exporter=%v err=%v", noopExporter, err)
	}
	noopExporter.Start(context.Background())
	if err := noopExporter.ExportOnce(context.Background()); err != nil {
		t.Fatalf("noop ExportOnce: %v", err)
	}
	if err := noopExporter.Shutdown(context.Background()); err != nil {
		t.Fatalf("noop Shutdown: %v", err)
	}

	policy, err := network.NewPolicy(config.OutboundSSRFConfig{AllowedSchemes: []string{"https"}})
	if err != nil {
		t.Fatalf("create network policy: %v", err)
	}
	if _, err := NewOTLPMetricsExporterFromTracingConfig(collector, config.TracingConfig{
		OTLPEndpoint: "http://collector.example/v1/metrics",
	}, time.Second, policy); err == nil {
		t.Fatal("expected insecure OTLP metrics endpoint to be rejected by outbound network policy")
	}
}
