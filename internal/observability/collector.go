package observability

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

const maxReservoirSamples = 1024

type reservoir struct {
	samples []int64
	sum     int64
	count   int64
}

func (r *reservoir) add(val int64) {
	r.sum += val
	r.count++
	if len(r.samples) < maxReservoirSamples {
		r.samples = append(r.samples, val)
	} else {
		idx := int(r.count % maxReservoirSamples)
		r.samples[idx] = val
	}
}

func (r *reservoir) stats() (avg float64, p50, p95, p99 int64) {
	if r.count == 0 || len(r.samples) == 0 {
		return 0, 0, 0, 0
	}
	avg = float64(r.sum) / float64(r.count)
	sorted := make([]int64, len(r.samples))
	copy(sorted, r.samples)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
	n := len(sorted)
	p50 = sorted[(n*50)/100]
	p95Idx := (n * 95) / 100
	if p95Idx >= n {
		p95Idx = n - 1
	}
	p99Idx := (n * 99) / 100
	if p99Idx >= n {
		p99Idx = n - 1
	}
	return avg, p50, sorted[p95Idx], sorted[p99Idx]
}

// ProviderTelemetry summarizes latency, TTFT, error rate, and spend for an upstream provider.
type ProviderTelemetry struct {
	Provider        string  `json:"provider"`
	TotalRequests   int64   `json:"total_requests"`
	ErrorCount      int64   `json:"error_count"`
	ErrorRate       float64 `json:"error_rate"`
	AvgLatencyMs    float64 `json:"avg_latency_ms"`
	P50LatencyMs    int64   `json:"p50_latency_ms"`
	P95LatencyMs    int64   `json:"p95_latency_ms"`
	P99LatencyMs    int64   `json:"p99_latency_ms"`
	AvgTTFTMs       float64 `json:"avg_ttft_ms"`
	P95TTFTMs       int64   `json:"p95_ttft_ms"`
	TotalTokens     int64   `json:"total_tokens"`
	TotalCostMicros int64   `json:"total_cost_micros"`
}

// DeploymentTelemetry summarizes health, failure rate, and latency for a specific deployment.
type DeploymentTelemetry struct {
	DeploymentID   string  `json:"deployment_id"`
	DeploymentName string  `json:"deployment_name"`
	Provider       string  `json:"provider"`
	Model          string  `json:"model"`
	TotalRequests  int64   `json:"total_requests"`
	ErrorCount     int64   `json:"error_count"`
	ErrorRate      float64 `json:"error_rate"`
	AvgLatencyMs   float64 `json:"avg_latency_ms"`
	P95LatencyMs   int64   `json:"p95_latency_ms"`
	AvgTTFTMs      float64 `json:"avg_ttft_ms"`
}

// TelemetrySnapshot provides a complete operational view of the gateway.
type TelemetrySnapshot struct {
	GeneratedAt              time.Time                      `json:"generated_at"`
	TotalRequests            int64                          `json:"total_requests"`
	TotalErrors              int64                          `json:"total_errors"`
	GlobalErrorRate          float64                        `json:"global_error_rate"`
	AvgLatencyMs             float64                        `json:"avg_latency_ms"`
	P50LatencyMs             int64                          `json:"p50_latency_ms"`
	P95LatencyMs             int64                          `json:"p95_latency_ms"`
	P99LatencyMs             int64                          `json:"p99_latency_ms"`
	AvgTTFTMs                float64                        `json:"avg_ttft_ms"`
	P95TTFTMs                int64                          `json:"p95_ttft_ms"`
	AvgRoutingOverheadMicros float64                        `json:"avg_routing_overhead_micros"`
	P95RoutingOverheadMicros int64                          `json:"p95_routing_overhead_micros"`
	TotalFallbacks           int64                          `json:"total_fallbacks"`
	FallbackRate             float64                        `json:"fallback_rate"`
	TotalRetries             int64                          `json:"total_retries"`
	CacheHits                int64                          `json:"cache_hits"`
	CacheMisses              int64                          `json:"cache_misses"`
	RateLimitRejections      int64                          `json:"rate_limit_rejections"`
	GuardrailBlocks          int64                          `json:"guardrail_blocks"`
	GuardrailRedactions      int64                          `json:"guardrail_redactions"`
	SlowestProvider          string                         `json:"slowest_provider,omitempty"`
	HighestFailureDeployment string                         `json:"highest_failure_deployment,omitempty"`
	Providers                map[string]ProviderTelemetry   `json:"providers"`
	Deployments              map[string]DeploymentTelemetry `json:"deployments"`
}

type providerInternal struct {
	totalReqs   int64
	errors      int64
	tokens      int64
	costMicros  int64
	latencyHist reservoir
	ttftHist    reservoir
}

type deploymentInternal struct {
	id          string
	name        string
	provider    string
	model       string
	totalReqs   int64
	errors      int64
	latencyHist reservoir
	ttftHist    reservoir
}

// RequestObservation is recorded after each inference or control-plane operation.
type RequestObservation struct {
	Provider          string
	Model             string
	DeploymentID      string
	DeploymentName    string
	StatusCode        int
	LatencyMs         int64
	TTFTMs            int64
	RoutingMicros     int64
	PromptTokens      int
	CompletionTokens  int
	CostMicros        int64
	CacheHit          bool
	FallbackAttempted bool
	RetryCount        int
	RateLimited       bool
	GuardrailBlocked  bool
	GuardrailRedacted bool
}

// Collector aggregates metrics, latency percentiles, TTFT, and routing overhead across the gateway.
type Collector struct {
	mu                  sync.RWMutex
	totalRequests       int64
	totalErrors         int64
	totalFallbacks      int64
	totalRetries        int64
	cacheHits           int64
	cacheMisses         int64
	rateLimitRejections int64
	guardrailBlocks     int64
	guardrailRedactions int64
	globalLatency       reservoir
	globalTTFT          reservoir
	routingMicros       reservoir
	providers           map[string]*providerInternal
	deployments         map[string]*deploymentInternal
}

func NewCollector() *Collector {
	return &Collector{
		providers:   make(map[string]*providerInternal),
		deployments: make(map[string]*deploymentInternal),
	}
}

// Record ingests telemetry from a single inference request.
func (c *Collector) Record(obs RequestObservation) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.totalRequests++
	isErr := obs.StatusCode >= 400
	if isErr {
		c.totalErrors++
	}
	if obs.LatencyMs >= 0 && !obs.CacheHit && !obs.RateLimited && !obs.GuardrailBlocked {
		c.globalLatency.add(obs.LatencyMs)
	}
	if obs.TTFTMs > 0 {
		c.globalTTFT.add(obs.TTFTMs)
	}
	if obs.RoutingMicros > 0 {
		c.routingMicros.add(obs.RoutingMicros)
	}
	if obs.FallbackAttempted {
		c.totalFallbacks++
	}
	if obs.RetryCount > 0 {
		c.totalRetries += int64(obs.RetryCount)
	}
	if obs.CacheHit {
		c.cacheHits++
	} else if !obs.RateLimited && !obs.GuardrailBlocked {
		c.cacheMisses++
	}
	if obs.RateLimited {
		c.rateLimitRejections++
	}
	if obs.GuardrailBlocked {
		c.guardrailBlocks++
	}
	if obs.GuardrailRedacted {
		c.guardrailRedactions++
	}

	if obs.Provider != "" {
		p, ok := c.providers[obs.Provider]
		if !ok {
			p = &providerInternal{}
			c.providers[obs.Provider] = p
		}
		p.totalReqs++
		if isErr {
			p.errors++
		}
		p.tokens += int64(obs.PromptTokens + obs.CompletionTokens)
		p.costMicros += obs.CostMicros
		if obs.LatencyMs >= 0 && !obs.CacheHit {
			p.latencyHist.add(obs.LatencyMs)
		}
		if obs.TTFTMs > 0 {
			p.ttftHist.add(obs.TTFTMs)
		}
	}

	if obs.DeploymentID != "" {
		d, ok := c.deployments[obs.DeploymentID]
		if !ok {
			d = &deploymentInternal{
				id:       obs.DeploymentID,
				name:     obs.DeploymentName,
				provider: obs.Provider,
				model:    obs.Model,
			}
			c.deployments[obs.DeploymentID] = d
		}
		d.totalReqs++
		if isErr {
			d.errors++
		}
		if obs.LatencyMs >= 0 {
			d.latencyHist.add(obs.LatencyMs)
		}
		if obs.TTFTMs > 0 {
			d.ttftHist.add(obs.TTFTMs)
		}
	}
}

// RecordDeploymentAttempt records an individual upstream deployment attempt (including failed primary attempts prior to failover).
func (c *Collector) RecordDeploymentAttempt(depID, depName, provider, model string, latencyMs int64, failed bool) {
	if depID == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	d, ok := c.deployments[depID]
	if !ok {
		d = &deploymentInternal{
			id:       depID,
			name:     depName,
			provider: provider,
			model:    model,
		}
		c.deployments[depID] = d
	}
	d.totalReqs++
	if failed {
		d.errors++
	}
	if latencyMs > 0 {
		d.latencyHist.add(latencyMs)
	}
}

// Snapshot computes the full operational telemetry snapshot.
func (c *Collector) Snapshot() TelemetrySnapshot {
	c.mu.RLock()
	defer c.mu.RUnlock()

	avgLat, p50Lat, p95Lat, p99Lat := c.globalLatency.stats()
	avgTTFT, _, p95TTFT, _ := c.globalTTFT.stats()
	avgRoute, _, p95Route, _ := c.routingMicros.stats()

	var errRate, fbRate float64
	if c.totalRequests > 0 {
		errRate = float64(c.totalErrors) / float64(c.totalRequests)
		fbRate = float64(c.totalFallbacks) / float64(c.totalRequests)
	}

	provMap := make(map[string]ProviderTelemetry, len(c.providers))
	var slowestProv string
	var maxProvLat float64
	for name, p := range c.providers {
		pAvgLat, pP50, pP95, pP99 := p.latencyHist.stats()
		pAvgTTFT, _, pP95TTFT, _ := p.ttftHist.stats()
		var pErrRate float64
		if p.totalReqs > 0 {
			pErrRate = float64(p.errors) / float64(p.totalReqs)
		}
		if pAvgLat > maxProvLat {
			maxProvLat = pAvgLat
			slowestProv = name
		}
		provMap[name] = ProviderTelemetry{
			Provider:        name,
			TotalRequests:   p.totalReqs,
			ErrorCount:      p.errors,
			ErrorRate:       pErrRate,
			AvgLatencyMs:    pAvgLat,
			P50LatencyMs:    pP50,
			P95LatencyMs:    pP95,
			P99LatencyMs:    pP99,
			AvgTTFTMs:       pAvgTTFT,
			P95TTFTMs:       pP95TTFT,
			TotalTokens:     p.tokens,
			TotalCostMicros: p.costMicros,
		}
	}

	depMap := make(map[string]DeploymentTelemetry, len(c.deployments))
	var highestFailDep string
	var maxFailRate float64
	for id, d := range c.deployments {
		dAvgLat, _, dP95, _ := d.latencyHist.stats()
		dAvgTTFT, _, _, _ := d.ttftHist.stats()
		var dErrRate float64
		if d.totalReqs > 0 {
			dErrRate = float64(d.errors) / float64(d.totalReqs)
		}
		if dErrRate > maxFailRate {
			maxFailRate = dErrRate
			highestFailDep = d.name
			if highestFailDep == "" {
				highestFailDep = id
			}
		}
		depMap[id] = DeploymentTelemetry{
			DeploymentID:   id,
			DeploymentName: d.name,
			Provider:       d.provider,
			Model:          d.model,
			TotalRequests:  d.totalReqs,
			ErrorCount:     d.errors,
			ErrorRate:      dErrRate,
			AvgLatencyMs:   dAvgLat,
			P95LatencyMs:   dP95,
			AvgTTFTMs:      dAvgTTFT,
		}
	}

	return TelemetrySnapshot{
		GeneratedAt:              time.Now().UTC(),
		TotalRequests:            c.totalRequests,
		TotalErrors:              c.totalErrors,
		GlobalErrorRate:          errRate,
		AvgLatencyMs:             avgLat,
		P50LatencyMs:             p50Lat,
		P95LatencyMs:             p95Lat,
		P99LatencyMs:             p99Lat,
		AvgTTFTMs:                avgTTFT,
		P95TTFTMs:                p95TTFT,
		AvgRoutingOverheadMicros: avgRoute,
		P95RoutingOverheadMicros: p95Route,
		TotalFallbacks:           c.totalFallbacks,
		FallbackRate:             fbRate,
		TotalRetries:             c.totalRetries,
		CacheHits:                c.cacheHits,
		CacheMisses:              c.cacheMisses,
		RateLimitRejections:      c.rateLimitRejections,
		GuardrailBlocks:          c.guardrailBlocks,
		GuardrailRedactions:      c.guardrailRedactions,
		SlowestProvider:          slowestProv,
		HighestFailureDeployment: highestFailDep,
		Providers:                provMap,
		Deployments:              depMap,
	}
}

// PrometheusHandler renders metrics in standard Prometheus text exposition format (`GET /metrics`).
func (c *Collector) PrometheusHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		snap := c.Snapshot()
		var b strings.Builder

		b.WriteString("# HELP gateway_requests_total Total inference requests processed by the AI Gateway.\n")
		b.WriteString("# TYPE gateway_requests_total counter\n")
		b.WriteString(fmt.Sprintf("gateway_requests_total %d\n", snap.TotalRequests))

		b.WriteString("# HELP gateway_errors_total Total failed requests.\n")
		b.WriteString("# TYPE gateway_errors_total counter\n")
		b.WriteString(fmt.Sprintf("gateway_errors_total %d\n", snap.TotalErrors))

		b.WriteString("# HELP gateway_latency_ms Request latency percentiles in milliseconds.\n")
		b.WriteString("# TYPE gateway_latency_ms gauge\n")
		b.WriteString(fmt.Sprintf("gateway_latency_ms{quantile=\"0.5\"} %d\n", snap.P50LatencyMs))
		b.WriteString(fmt.Sprintf("gateway_latency_ms{quantile=\"0.95\"} %d\n", snap.P95LatencyMs))
		b.WriteString(fmt.Sprintf("gateway_latency_ms{quantile=\"0.99\"} %d\n", snap.P99LatencyMs))

		b.WriteString("# HELP gateway_ttft_ms Time-To-First-Token in milliseconds.\n")
		b.WriteString("# TYPE gateway_ttft_ms gauge\n")
		b.WriteString(fmt.Sprintf("gateway_ttft_ms{quantile=\"0.95\"} %d\n", snap.P95TTFTMs))

		b.WriteString("# HELP gateway_routing_overhead_micros Stage 1 + Stage 2 routing decision overhead in microseconds.\n")
		b.WriteString("# TYPE gateway_routing_overhead_micros gauge\n")
		b.WriteString(fmt.Sprintf("gateway_routing_overhead_micros{quantile=\"0.95\"} %d\n", snap.P95RoutingOverheadMicros))

		b.WriteString("# HELP gateway_fallbacks_total Total cross-group/cross-provider fallback executions.\n")
		b.WriteString("# TYPE gateway_fallbacks_total counter\n")
		b.WriteString(fmt.Sprintf("gateway_fallbacks_total %d\n", snap.TotalFallbacks))

		b.WriteString("# HELP gateway_retries_total Total intra-group retry attempts.\n")
		b.WriteString("# TYPE gateway_retries_total counter\n")
		b.WriteString(fmt.Sprintf("gateway_retries_total %d\n", snap.TotalRetries))

		b.WriteString("# HELP gateway_cache_hits_total Total exact-match response cache hits.\n")
		b.WriteString("# TYPE gateway_cache_hits_total counter\n")
		b.WriteString(fmt.Sprintf("gateway_cache_hits_total %d\n", snap.CacheHits))

		b.WriteString("# HELP gateway_ratelimit_rejections_total Total requests rejected by rate limiting or budget guards.\n")
		b.WriteString("# TYPE gateway_ratelimit_rejections_total counter\n")
		b.WriteString(fmt.Sprintf("gateway_ratelimit_rejections_total %d\n", snap.RateLimitRejections))

		b.WriteString("# HELP gateway_guardrail_blocks_total Total requests blocked by security guardrails.\n")
		b.WriteString("# TYPE gateway_guardrail_blocks_total counter\n")
		b.WriteString(fmt.Sprintf("gateway_guardrail_blocks_total %d\n", snap.GuardrailBlocks))

		for prov, pm := range snap.Providers {
			b.WriteString(fmt.Sprintf("gateway_provider_requests_total{provider=%q} %d\n", prov, pm.TotalRequests))
			b.WriteString(fmt.Sprintf("gateway_provider_errors_total{provider=%q} %d\n", prov, pm.ErrorCount))
			b.WriteString(fmt.Sprintf("gateway_provider_latency_p95_ms{provider=%q} %d\n", prov, pm.P95LatencyMs))
			b.WriteString(fmt.Sprintf("gateway_provider_spend_micros_total{provider=%q} %d\n", prov, pm.TotalCostMicros))
		}

		for id, dm := range snap.Deployments {
			b.WriteString(fmt.Sprintf("gateway_deployment_requests_total{deployment_id=%q,name=%q,provider=%q} %d\n", id, dm.DeploymentName, dm.Provider, dm.TotalRequests))
			b.WriteString(fmt.Sprintf("gateway_deployment_errors_total{deployment_id=%q,name=%q,provider=%q} %d\n", id, dm.DeploymentName, dm.Provider, dm.ErrorCount))
		}

		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(b.String()))
	}
}
