package observability

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
)

// OTLPMetricsConfig configures periodic or on-demand OTLP/HTTP metrics export.
type OTLPMetricsConfig struct {
	OTLPEndpoint   string
	ServiceName    string
	Headers        map[string]string
	ExportInterval time.Duration
}

// OTLPMetricsExporter pushes Collector telemetry snapshots to an OTLP/HTTP `/v1/metrics` endpoint.
type OTLPMetricsExporter struct {
	collector   *Collector
	endpointURL string
	serviceName string
	headers     map[string]string
	interval    time.Duration
	httpClient  *http.Client
	startTimeNs uint64

	mu     sync.Mutex
	cancel context.CancelFunc
	done   chan struct{}
}

type otlpExportMetricsRequest struct {
	ResourceMetrics []otlpResourceMetrics `json:"resourceMetrics"`
}

type otlpResourceMetrics struct {
	Resource     otlpResource       `json:"resource"`
	ScopeMetrics []otlpScopeMetrics `json:"scopeMetrics"`
}

type otlpResource struct {
	Attributes []otlpKeyValue `json:"attributes"`
}

type otlpScopeMetrics struct {
	Scope   otlpInstrumentationScope `json:"scope"`
	Metrics []otlpMetric             `json:"metrics"`
}

type otlpInstrumentationScope struct {
	Name string `json:"name"`
}

type otlpKeyValue struct {
	Key   string       `json:"key"`
	Value otlpAnyValue `json:"value"`
}

type otlpAnyValue struct {
	StringValue string `json:"stringValue,omitempty"`
}

type otlpMetric struct {
	Name        string     `json:"name"`
	Description string     `json:"description,omitempty"`
	Unit        string     `json:"unit,omitempty"`
	Sum         *otlpSum   `json:"sum,omitempty"`
	Gauge       *otlpGauge `json:"gauge,omitempty"`
}

type otlpSum struct {
	DataPoints             []otlpNumberDataPoint `json:"dataPoints"`
	AggregationTemporality int                   `json:"aggregationTemporality"` // 2 = AGGREGATION_TEMPORALITY_CUMULATIVE
	IsMonotonic            bool                  `json:"isMonotonic"`
}

type otlpGauge struct {
	DataPoints []otlpNumberDataPoint `json:"dataPoints"`
}

type otlpNumberDataPoint struct {
	Attributes        []otlpKeyValue `json:"attributes,omitempty"`
	StartTimeUnixNano uint64         `json:"startTimeUnixNano,omitempty"`
	TimeUnixNano      uint64         `json:"timeUnixNano"`
	AsInt             *int64         `json:"asInt,omitempty"`
	AsDouble          *float64       `json:"asDouble,omitempty"`
}

// NewOTLPMetricsExporterFromTracingConfig creates an OTLP HTTP metrics exporter sharing the tracing OTLP endpoint and headers.
func NewOTLPMetricsExporterFromTracingConfig(collector *Collector, cfg config.TracingConfig, interval time.Duration, policy *network.Policy) (*OTLPMetricsExporter, error) {
	return NewOTLPMetricsExporter(collector, OTLPMetricsConfig{
		OTLPEndpoint:   cfg.OTLPEndpoint,
		ServiceName:    cfg.ServiceName,
		Headers:        cfg.Headers,
		ExportInterval: interval,
	}, policy)
}

// NewOTLPMetricsExporter validates the outbound OTLP HTTP metrics endpoint against the network security policy
// and returns an OTLPMetricsExporter (or a no-op exporter when OTLPEndpoint is unset).
func NewOTLPMetricsExporter(collector *Collector, cfg OTLPMetricsConfig, policy *network.Policy) (*OTLPMetricsExporter, error) {
	rawEndpoint := strings.TrimSpace(cfg.OTLPEndpoint)
	if rawEndpoint == "" {
		rawEndpoint = strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT"))
	}
	if rawEndpoint == "" {
		rawEndpoint = strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"))
	}
	serviceName := strings.TrimSpace(cfg.ServiceName)
	if serviceName == "" {
		serviceName = "ai-gateway-go"
	}
	interval := cfg.ExportInterval
	if interval <= 0 {
		interval = 60 * time.Second
	}
	if rawEndpoint == "" {
		return &OTLPMetricsExporter{
			collector:   collector,
			serviceName: serviceName,
			interval:    interval,
			startTimeNs: uint64(time.Now().UTC().UnixNano()),
		}, nil
	}

	endpoint, err := url.Parse(rawEndpoint)
	if err != nil || endpoint.Host == "" {
		return nil, fmt.Errorf("invalid metrics.otlp_endpoint")
	}
	switch endpoint.Path {
	case "", "/", "/v1/traces":
		endpoint.Path = "/v1/metrics"
	}
	if policy == nil {
		return nil, fmt.Errorf("metrics.otlp_endpoint requires an outbound network policy")
	}
	if err := policy.ValidateURL(endpoint); err != nil {
		return nil, fmt.Errorf("metrics.otlp_endpoint is blocked by outbound network policy: %w", err)
	}

	headersCopy := make(map[string]string, len(cfg.Headers))
	for k, v := range cfg.Headers {
		headersCopy[k] = v
	}

	return &OTLPMetricsExporter{
		collector:   collector,
		endpointURL: endpoint.String(),
		serviceName: serviceName,
		headers:     headersCopy,
		interval:    interval,
		httpClient:  network.NewHTTPClient(policy),
		startTimeNs: uint64(time.Now().UTC().UnixNano()),
	}, nil
}

// Start launches background periodic OTLP metric exports until ctx is cancelled or Shutdown is called.
func (e *OTLPMetricsExporter) Start(ctx context.Context) {
	if e == nil || e.endpointURL == "" || e.collector == nil {
		return
	}
	e.mu.Lock()
	if e.cancel != nil {
		e.mu.Unlock()
		return
	}
	runCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	e.cancel = cancel
	e.done = done
	interval := e.interval
	e.mu.Unlock()

	go func() {
		defer close(done)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-runCtx.Done():
				return
			case <-ticker.C:
				expCtx, expCancel := context.WithTimeout(runCtx, 10*time.Second)
				_ = e.ExportOnce(expCtx)
				expCancel()
			}
		}
	}()
}

// Shutdown stops the periodic export loop and flushes a final metric snapshot.
func (e *OTLPMetricsExporter) Shutdown(ctx context.Context) error {
	if e == nil || e.endpointURL == "" || e.collector == nil {
		return nil
	}
	e.mu.Lock()
	cancel := e.cancel
	done := e.done
	e.cancel = nil
	e.done = nil
	e.mu.Unlock()

	if cancel != nil {
		cancel()
		if done != nil {
			select {
			case <-done:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
	return e.ExportOnce(ctx)
}

// ExportOnce snapshots the Collector and pushes a single OTLP/HTTP metrics payload to `/v1/metrics`.
func (e *OTLPMetricsExporter) ExportOnce(ctx context.Context) error {
	if e == nil || e.endpointURL == "" || e.collector == nil {
		return nil
	}
	payload := e.buildPayload()
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal OTLP metrics payload: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.endpointURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("build OTLP metrics request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range e.headers {
		req.Header.Set(k, v)
	}
	resp, err := e.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("push OTLP metrics: %w", err)
	}
	defer func() {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("OTLP metrics collector returned HTTP %d", resp.StatusCode)
	}
	return nil
}

func (e *OTLPMetricsExporter) buildPayload() otlpExportMetricsRequest {
	snap := e.collector.Snapshot()
	e.collector.mu.RLock()
	additionalProvider := e.collector.additionalMetrics
	e.collector.mu.RUnlock()
	var extra map[string]float64
	if additionalProvider != nil {
		extra = additionalProvider()
	}

	nowNs := uint64(snap.GeneratedAt.UnixNano())
	if nowNs == 0 {
		nowNs = uint64(time.Now().UTC().UnixNano())
	}
	startNs := e.startTimeNs
	if startNs == 0 || startNs > nowNs {
		startNs = nowNs
	}

	intCounter := func(name, desc string, val int64, attrs ...otlpKeyValue) otlpMetric {
		v := val
		return otlpMetric{
			Name:        name,
			Description: desc,
			Sum: &otlpSum{
				AggregationTemporality: 2,
				IsMonotonic:            true,
				DataPoints: []otlpNumberDataPoint{{
					Attributes:        attrs,
					StartTimeUnixNano: startNs,
					TimeUnixNano:      nowNs,
					AsInt:             &v,
				}},
			},
		}
	}
	intGauge := func(name, desc, unit string, points ...otlpNumberDataPoint) otlpMetric {
		return otlpMetric{
			Name:        name,
			Description: desc,
			Unit:        unit,
			Gauge:       &otlpGauge{DataPoints: points},
		}
	}
	kv := func(k, v string) otlpKeyValue {
		return otlpKeyValue{Key: k, Value: otlpAnyValue{StringValue: v}}
	}
	intPoint := func(val int64, attrs ...otlpKeyValue) otlpNumberDataPoint {
		v := val
		return otlpNumberDataPoint{
			Attributes:   attrs,
			TimeUnixNano: nowNs,
			AsInt:        &v,
		}
	}

	metrics := []otlpMetric{
		intCounter("gateway_requests_total", "Total inference requests processed by the AI Gateway.", snap.TotalRequests),
		intCounter("gateway_errors_total", "Total failed requests.", snap.TotalErrors),
		intGauge("gateway_latency_ms", "Request latency percentiles in milliseconds.", "ms",
			intPoint(snap.P50LatencyMs, kv("quantile", "0.5")),
			intPoint(snap.P95LatencyMs, kv("quantile", "0.95")),
			intPoint(snap.P99LatencyMs, kv("quantile", "0.99")),
		),
		intGauge("gateway_ttft_ms", "Time-To-First-Token in milliseconds.", "ms",
			intPoint(snap.P95TTFTMs, kv("quantile", "0.95")),
		),
		intCounter("gateway_streams_total", "Total completed streaming inference calls.", snap.StreamRequests),
		intCounter("gateway_stream_errors_total", "Streaming inference calls that ended with an upstream or handler error.", snap.StreamErrors),
		intGauge("gateway_routing_overhead_micros", "Stage 1 + Stage 2 routing decision overhead in microseconds.", "us",
			intPoint(snap.P95RoutingOverheadMicros, kv("quantile", "0.95")),
		),
		intCounter("gateway_fallbacks_total", "Total cross-group/cross-provider fallback executions.", snap.TotalFallbacks),
		intCounter("gateway_retries_total", "Total intra-group retry attempts.", snap.TotalRetries),
		intCounter("gateway_cache_hits_total", "Total exact-match response cache hits.", snap.CacheHits),
		intCounter("gateway_ratelimit_rejections_total", "Total requests rejected by rate limiting or budget guards.", snap.RateLimitRejections),
		intCounter("gateway_guardrail_blocks_total", "Total requests blocked by security guardrails.", snap.GuardrailBlocks),
		intCounter("gateway_finops_redis_drift_total", "Total FinOps spend events that exhausted Redis reconciliation retries.", snap.SpendRedisDriftTotal),
	}

	provNames := make([]string, 0, len(snap.Providers))
	for prov := range snap.Providers {
		provNames = append(provNames, prov)
	}
	sort.Strings(provNames)
	for _, prov := range provNames {
		pm := snap.Providers[prov]
		attr := kv("provider", prov)
		metrics = append(metrics,
			intCounter("gateway_provider_requests_total", "Total provider requests.", pm.TotalRequests, attr),
			intCounter("gateway_provider_errors_total", "Total provider errors.", pm.ErrorCount, attr),
			intGauge("gateway_provider_latency_p95_ms", "Provider P95 latency in milliseconds.", "ms", intPoint(pm.P95LatencyMs, attr)),
			intCounter("gateway_provider_spend_micros_total", "Provider spend in micro-dollars.", pm.TotalCostMicros, attr),
		)
	}

	if len(extra) > 0 {
		extraNames := make([]string, 0, len(extra))
		for name := range extra {
			extraNames = append(extraNames, name)
		}
		sort.Strings(extraNames)
		for _, name := range extraNames {
			val := extra[name]
			if strings.HasSuffix(name, "_total") || strings.HasSuffix(name, "_count") || strings.HasSuffix(name, "_sum") {
				v := val
				metrics = append(metrics, otlpMetric{
					Name: name,
					Sum: &otlpSum{
						AggregationTemporality: 2,
						IsMonotonic:            true,
						DataPoints: []otlpNumberDataPoint{{
							StartTimeUnixNano: startNs,
							TimeUnixNano:      nowNs,
							AsDouble:          &v,
						}},
					},
				})
			} else {
				v := val
				metrics = append(metrics, otlpMetric{
					Name: name,
					Gauge: &otlpGauge{
						DataPoints: []otlpNumberDataPoint{{
							TimeUnixNano: nowNs,
							AsDouble:     &v,
						}},
					},
				})
			}
		}
	}

	return otlpExportMetricsRequest{
		ResourceMetrics: []otlpResourceMetrics{{
			Resource: otlpResource{
				Attributes: []otlpKeyValue{kv("service.name", e.serviceName)},
			},
			ScopeMetrics: []otlpScopeMetrics{{
				Scope:   otlpInstrumentationScope{Name: "github.com/goroute-ai/ai-gateway-go"},
				Metrics: metrics,
			}},
		}},
	}
}
