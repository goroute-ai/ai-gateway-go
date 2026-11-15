package observability

import (
	"fmt"
	"math/rand/v2"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	maxReservoirSamples  = 1024
	maxProviderEntries   = 256
	maxDeploymentEntries = 4096
	maxGuardrailEntries  = 512
)

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
		return
	}
	// Vitter's Algorithm R: uniform reservoir sampling over all r.count items seen.
	if idx := rand.Int64N(r.count); idx < maxReservoirSamples {
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
	SpendRedisDriftTotal     int64                          `json:"spend_redis_drift_total"`
	StreamRequests           int64                          `json:"stream_requests"`
	StreamErrors             int64                          `json:"stream_errors"`
	StreamDurationSumMs      int64                          `json:"stream_duration_sum_ms"`
	StreamDurationCount      int64                          `json:"stream_duration_count"`
	StreamTTFTSumMs          int64                          `json:"stream_ttft_sum_ms"`
	StreamTTFTCount          int64                          `json:"stream_ttft_count"`
	SlowestProvider          string                         `json:"slowest_provider,omitempty"`
	HighestFailureDeployment string                         `json:"highest_failure_deployment,omitempty"`
	Providers                map[string]ProviderTelemetry   `json:"providers"`
	Deployments              map[string]DeploymentTelemetry `json:"deployments"`
	GuardrailMetrics         []GuardrailMetricSummary       `json:"guardrail_metrics,omitempty"`
}

type guardrailInternal struct {
	guardrail      string
	hook           string
	evaluations    int64
	errors         int64
	decisionCounts map[string]int64
	durationSumMs  int64
	durationCount  int64
	buckets        []int64
	lastAccess     uint64
}

type providerInternal struct {
	totalReqs   int64
	errors      int64
	tokens      int64
	costMicros  int64
	latencyHist reservoir
	ttftHist    reservoir
	lastAccess  uint64
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
	lastAccess  uint64
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
	spendRedisDrift     int64
	streamRequests      int64
	streamErrors        int64
	streamDuration      reservoir
	streamTTFT          reservoir
	globalLatency       reservoir
	globalTTFT          reservoir
	routingMicros       reservoir
	providers           map[string]*providerInternal
	maxProviders        int
	deployments         map[string]*deploymentInternal
	maxDeployments      int
	guardrails          map[GuardrailMetricKey]*guardrailInternal
	maxGuardrails       int
	accessSeq           uint64
	additionalMetrics   func() map[string]float64
}

func NewCollector() *Collector {
	return &Collector{
		providers:      make(map[string]*providerInternal),
		maxProviders:   maxProviderEntries,
		deployments:    make(map[string]*deploymentInternal),
		maxDeployments: maxDeploymentEntries,
		guardrails:     make(map[GuardrailMetricKey]*guardrailInternal),
		maxGuardrails:  maxGuardrailEntries,
	}
}

// SetAdditionalMetricsProvider attaches low-cardinality runtime gauges and
// counters from subsystems whose measurements are maintained outside Collector.
func (c *Collector) SetAdditionalMetricsProvider(provider func() map[string]float64) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.additionalMetrics = provider
	c.mu.Unlock()
}

// RecordSpendRedisDrift increments the counter for FinOps outbox events whose
// Redis spend reconciliation could not be completed within max retries.
func (c *Collector) RecordSpendRedisDrift() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.spendRedisDrift++
}

// RecordStream adds low-cardinality timing and failure measurements for one
// completed streaming inference response.
func (c *Collector) RecordStream(duration, ttft time.Duration, failed bool) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.streamRequests++
	if failed {
		c.streamErrors++
	}
	if duration >= 0 {
		c.streamDuration.add(duration.Milliseconds())
	}
	if ttft > 0 {
		c.streamTTFT.add(ttft.Milliseconds())
	}
}

// RecordGuardrailEvaluation records low-cardinality guardrail evaluation counters and duration histogram.
func (c *Collector) RecordGuardrailEvaluation(obs GuardrailObservation) {
	if c == nil {
		return
	}
	guardrailLabel := sanitizeGuardrailLabel(obs.GuardrailName)
	hookLabel := sanitizeGuardrailLabel(obs.Hook)
	decisionLabel := NormalizeGuardrailDecision(obs.Decision, obs.IsError)
	latencyMs := obs.LatencyMs
	if latencyMs < 0 {
		latencyMs = 0
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if c.guardrails == nil {
		c.guardrails = make(map[GuardrailMetricKey]*guardrailInternal)
	}
	if decisionLabel == "block" {
		c.guardrailBlocks++
	} else if decisionLabel == "modify" {
		c.guardrailRedactions++
	}

	c.accessSeq++
	key := GuardrailMetricKey{Guardrail: guardrailLabel, Hook: hookLabel}
	g, ok := c.guardrails[key]
	if !ok {
		limit := c.maxGuardrails
		if limit <= 0 {
			limit = maxGuardrailEntries
		}
		if len(c.guardrails) >= limit {
			var evictKey GuardrailMetricKey
			var oldest uint64
			for k, v := range c.guardrails {
				if oldest == 0 || v.lastAccess < oldest {
					oldest = v.lastAccess
					evictKey = k
				}
			}
			if oldest != 0 {
				delete(c.guardrails, evictKey)
			}
		}
		g = &guardrailInternal{
			guardrail:      guardrailLabel,
			hook:           hookLabel,
			decisionCounts: make(map[string]int64),
			buckets:        make([]int64, len(guardrailLatencyBoundsMs)+1),
		}
		c.guardrails[key] = g
	}
	g.lastAccess = c.accessSeq
	g.evaluations++
	if obs.IsError || decisionLabel == "error" {
		g.errors++
	}
	g.decisionCounts[decisionLabel]++
	g.durationSumMs += latencyMs
	g.durationCount++
	for i, bound := range guardrailLatencyBoundsMs {
		if latencyMs <= bound {
			g.buckets[i]++
		}
	}
	g.buckets[len(guardrailLatencyBoundsMs)]++ // +Inf bucket
}

// getOrCreateProvider returns an existing providerInternal or creates a new one,
// evicting the least-recently-updated entry if the bounded capacity is reached. Caller must hold c.mu.
func (c *Collector) getOrCreateProvider(provider string) *providerInternal {
	c.accessSeq++
	if p, ok := c.providers[provider]; ok {
		p.lastAccess = c.accessSeq
		return p
	}
	limit := c.maxProviders
	if limit <= 0 {
		limit = maxProviderEntries
	}
	if len(c.providers) >= limit {
		var evictID string
		var oldest uint64
		first := true
		for id, entry := range c.providers {
			if first || entry.lastAccess < oldest {
				oldest = entry.lastAccess
				evictID = id
				first = false
			}
		}
		if evictID != "" {
			delete(c.providers, evictID)
		}
	}
	p := &providerInternal{lastAccess: c.accessSeq}
	c.providers[provider] = p
	return p
}

// getOrCreateDeployment returns an existing deploymentInternal or creates a new one,
// evicting the least-recently-updated entry if the bounded capacity is reached. Caller must hold c.mu.
func (c *Collector) getOrCreateDeployment(depID, depName, provider, model string) *deploymentInternal {
	c.accessSeq++
	if d, ok := c.deployments[depID]; ok {
		d.lastAccess = c.accessSeq
		return d
	}
	limit := c.maxDeployments
	if limit <= 0 {
		limit = maxDeploymentEntries
	}
	if len(c.deployments) >= limit {
		var evictID string
		var oldest uint64
		first := true
		for id, entry := range c.deployments {
			if first || entry.lastAccess < oldest {
				oldest = entry.lastAccess
				evictID = id
				first = false
			}
		}
		if evictID != "" {
			delete(c.deployments, evictID)
		}
	}
	d := &deploymentInternal{
		id:         depID,
		name:       depName,
		provider:   provider,
		model:      model,
		lastAccess: c.accessSeq,
	}
	c.deployments[depID] = d
	return d
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
		p := c.getOrCreateProvider(obs.Provider)
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
		d := c.getOrCreateDeployment(obs.DeploymentID, obs.DeploymentName, obs.Provider, obs.Model)
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
	d := c.getOrCreateDeployment(depID, depName, provider, model)
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

	guardrailList := make([]GuardrailMetricSummary, 0, len(c.guardrails))
	for _, g := range c.guardrails {
		decCopy := make(map[string]int64, len(g.decisionCounts))
		for k, v := range g.decisionCounts {
			decCopy[k] = v
		}
		bucketsCopy := make([]int64, len(g.buckets))
		copy(bucketsCopy, g.buckets)
		boundsCopy := make([]int64, len(guardrailLatencyBoundsMs))
		copy(boundsCopy, guardrailLatencyBoundsMs)
		guardrailList = append(guardrailList, GuardrailMetricSummary{
			Guardrail:        g.guardrail,
			Hook:             g.hook,
			Evaluations:      g.evaluations,
			Errors:           g.errors,
			DecisionCounts:   decCopy,
			DurationSumMs:    g.durationSumMs,
			DurationCount:    g.durationCount,
			HistogramBuckets: bucketsCopy,
			HistogramBoundMs: boundsCopy,
		})
	}
	sort.Slice(guardrailList, func(i, j int) bool {
		if guardrailList[i].Guardrail != guardrailList[j].Guardrail {
			return guardrailList[i].Guardrail < guardrailList[j].Guardrail
		}
		return guardrailList[i].Hook < guardrailList[j].Hook
	})

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
		SpendRedisDriftTotal:     c.spendRedisDrift,
		StreamRequests:           c.streamRequests,
		StreamErrors:             c.streamErrors,
		StreamDurationSumMs:      c.streamDuration.sum,
		StreamDurationCount:      c.streamDuration.count,
		StreamTTFTSumMs:          c.streamTTFT.sum,
		StreamTTFTCount:          c.streamTTFT.count,
		SlowestProvider:          slowestProv,
		HighestFailureDeployment: highestFailDep,
		Providers:                provMap,
		Deployments:              depMap,
		GuardrailMetrics:         guardrailList,
	}
}

// PrometheusHandler renders metrics in standard Prometheus text exposition format (`GET /metrics`).
func (c *Collector) PrometheusHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		snap := c.Snapshot()
		c.mu.RLock()
		additionalMetrics := c.additionalMetrics
		c.mu.RUnlock()
		var extra map[string]float64
		if additionalMetrics != nil {
			extra = additionalMetrics()
		}
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

		b.WriteString("# HELP gateway_streams_total Total completed streaming inference calls.\n")
		b.WriteString("# TYPE gateway_streams_total counter\n")
		b.WriteString(fmt.Sprintf("gateway_streams_total %d\n", snap.StreamRequests))
		b.WriteString("# HELP gateway_stream_errors_total Streaming inference calls that ended with an upstream or handler error.\n")
		b.WriteString("# TYPE gateway_stream_errors_total counter\n")
		b.WriteString(fmt.Sprintf("gateway_stream_errors_total %d\n", snap.StreamErrors))
		b.WriteString("# HELP gateway_stream_duration_seconds_sum Total upstream stream execution duration in seconds.\n")
		b.WriteString("# TYPE gateway_stream_duration_seconds_sum counter\n")
		b.WriteString(fmt.Sprintf("gateway_stream_duration_seconds_sum %g\n", float64(snap.StreamDurationSumMs)/1000))
		b.WriteString("# HELP gateway_stream_duration_seconds_count Number of measured streaming inference calls.\n")
		b.WriteString("# TYPE gateway_stream_duration_seconds_count counter\n")
		b.WriteString(fmt.Sprintf("gateway_stream_duration_seconds_count %d\n", snap.StreamDurationCount))
		b.WriteString("# HELP gateway_stream_ttft_seconds_sum Total time-to-first-token for streaming inference calls.\n")
		b.WriteString("# TYPE gateway_stream_ttft_seconds_sum counter\n")
		b.WriteString(fmt.Sprintf("gateway_stream_ttft_seconds_sum %g\n", float64(snap.StreamTTFTSumMs)/1000))
		b.WriteString("# HELP gateway_stream_ttft_seconds_count Number of streaming calls with a measured first token.\n")
		b.WriteString("# TYPE gateway_stream_ttft_seconds_count counter\n")
		b.WriteString(fmt.Sprintf("gateway_stream_ttft_seconds_count %d\n", snap.StreamTTFTCount))

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

		if len(snap.GuardrailMetrics) > 0 {
			b.WriteString("# HELP gateway_guardrail_evaluations_total Total guardrail evaluations by guardrail, hook, and decision.\n")
			b.WriteString("# TYPE gateway_guardrail_evaluations_total counter\n")
			for _, gm := range snap.GuardrailMetrics {
				decisions := make([]string, 0, len(gm.DecisionCounts))
				for dec := range gm.DecisionCounts {
					decisions = append(decisions, dec)
				}
				sort.Strings(decisions)
				for _, dec := range decisions {
					b.WriteString(fmt.Sprintf("gateway_guardrail_evaluations_total{guardrail=%q,hook=%q,decision=%q} %d\n", gm.Guardrail, gm.Hook, dec, gm.DecisionCounts[dec]))
				}
			}

			b.WriteString("# HELP gateway_guardrail_errors_total Total guardrail evaluation errors by guardrail and hook.\n")
			b.WriteString("# TYPE gateway_guardrail_errors_total counter\n")
			for _, gm := range snap.GuardrailMetrics {
				b.WriteString(fmt.Sprintf("gateway_guardrail_errors_total{guardrail=%q,hook=%q} %d\n", gm.Guardrail, gm.Hook, gm.Errors))
			}

			b.WriteString("# HELP gateway_guardrail_duration_ms Guardrail evaluation duration in milliseconds.\n")
			b.WriteString("# TYPE gateway_guardrail_duration_ms histogram\n")
			for _, gm := range snap.GuardrailMetrics {
				for idx, bound := range gm.HistogramBoundMs {
					var val int64
					if idx < len(gm.HistogramBuckets) {
						val = gm.HistogramBuckets[idx]
					}
					b.WriteString(fmt.Sprintf("gateway_guardrail_duration_ms_bucket{guardrail=%q,hook=%q,le=\"%d\"} %d\n", gm.Guardrail, gm.Hook, bound, val))
				}
				var infVal int64
				if len(gm.HistogramBuckets) > len(gm.HistogramBoundMs) {
					infVal = gm.HistogramBuckets[len(gm.HistogramBoundMs)]
				} else {
					infVal = gm.DurationCount
				}
				b.WriteString(fmt.Sprintf("gateway_guardrail_duration_ms_bucket{guardrail=%q,hook=%q,le=\"+Inf\"} %d\n", gm.Guardrail, gm.Hook, infVal))
				b.WriteString(fmt.Sprintf("gateway_guardrail_duration_ms_sum{guardrail=%q,hook=%q} %d\n", gm.Guardrail, gm.Hook, gm.DurationSumMs))
				b.WriteString(fmt.Sprintf("gateway_guardrail_duration_ms_count{guardrail=%q,hook=%q} %d\n", gm.Guardrail, gm.Hook, gm.DurationCount))
			}
		}

		b.WriteString("# HELP gateway_finops_redis_drift_total Total FinOps spend events that exhausted Redis reconciliation retries.\n")
		b.WriteString("# TYPE gateway_finops_redis_drift_total counter\n")
		b.WriteString(fmt.Sprintf("gateway_finops_redis_drift_total %d\n", snap.SpendRedisDriftTotal))

		for prov, pm := range snap.Providers {
			b.WriteString(fmt.Sprintf("gateway_provider_requests_total{provider=%q} %d\n", prov, pm.TotalRequests))
			b.WriteString(fmt.Sprintf("gateway_provider_errors_total{provider=%q} %d\n", prov, pm.ErrorCount))
			b.WriteString(fmt.Sprintf("gateway_provider_latency_p95_ms{provider=%q} %d\n", prov, pm.P95LatencyMs))
			b.WriteString(fmt.Sprintf("gateway_provider_spend_micros_total{provider=%q} %d\n", prov, pm.TotalCostMicros))
		}
		for name, value := range extra {
			metricType := "gauge"
			if strings.HasSuffix(name, "_total") || strings.HasSuffix(name, "_count") || strings.HasSuffix(name, "_sum") {
				metricType = "counter"
			}
			b.WriteString(fmt.Sprintf("# TYPE %s %s\n", name, metricType))
			b.WriteString(fmt.Sprintf("%s %g\n", name, value))
		}

		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(b.String()))
	}
}
