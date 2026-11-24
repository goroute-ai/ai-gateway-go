package observability

import (
	"context"
	"maps"
	"slices"
	"sort"
	"sync"
	"time"
)

const (
	maxWindowSamples     = 1024
	maxProviderEntries   = 256
	maxDeploymentEntries = 4096
	maxGuardrailEntries  = 512
)

// slidingWindow tracks a bounded FIFO ring buffer of the latest maxWindowSamples
// observations so UI latency/TTFT percentiles always reflect recent traffic rather
// than stale all-time lifetime samples.
type slidingWindow struct {
	samples []int64
	nextIdx int
	sum     int64
	count   int64
}

func (w *slidingWindow) add(val int64) {
	w.sum += val
	w.count++
	if len(w.samples) < maxWindowSamples {
		w.samples = append(w.samples, val)
		return
	}
	w.samples[w.nextIdx] = val
	w.nextIdx = (w.nextIdx + 1) % maxWindowSamples
}

func (w *slidingWindow) stats() (avg float64, p50, p95, p99 int64) {
	if w.count == 0 || len(w.samples) == 0 {
		return 0, 0, 0, 0
	}
	var winSum int64
	sorted := make([]int64, len(w.samples))
	for i, v := range w.samples {
		sorted[i] = v
		winSum += v
	}
	slices.Sort(sorted)
	n := len(sorted)
	avg = float64(winSum) / float64(n)
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

// CacheTelemetry summarizes live response-cache state from the active cache backend.
type CacheTelemetry struct {
	Enabled      bool
	Type         string // "local", "redis", "redis-semantic"
	Status       string // "ok", "degraded", "disabled"
	Hits         int64
	Misses       int64
	SemanticHits int64
	Errors       int64
	Entries      int64
	Evictions    int64
}

// TelemetrySnapshot provides the live in-process operational snapshot served by
// GET /admin/v1/observability/metrics strictly for the embedded Operator Web UI.
type TelemetrySnapshot struct {
	GeneratedAt                time.Time                      `json:"generated_at"`
	OTelEnabled                bool                           `json:"otel_enabled"`
	OTelSignals                []string                       `json:"otel_signals,omitempty"`
	TotalRequests              int64                          `json:"total_requests"`
	TotalErrors                int64                          `json:"total_errors"`
	GlobalErrorRate            float64                        `json:"global_error_rate"`
	AvgLatencyMs               float64                        `json:"avg_latency_ms"`
	P50LatencyMs               int64                          `json:"p50_latency_ms"`
	P95LatencyMs               int64                          `json:"p95_latency_ms"`
	P99LatencyMs               int64                          `json:"p99_latency_ms"`
	AvgTTFTMs                  float64                        `json:"avg_ttft_ms"`
	P95TTFTMs                  int64                          `json:"p95_ttft_ms"`
	AvgRoutingOverheadMicros   float64                        `json:"avg_routing_overhead_micros"`
	P95RoutingOverheadMicros   int64                          `json:"p95_routing_overhead_micros"`
	TotalFallbacks             int64                          `json:"total_fallbacks"`
	FallbackRate               float64                        `json:"fallback_rate"`
	TotalRetries               int64                          `json:"total_retries"`
	CacheEnabled               bool                           `json:"cache_enabled"`
	CacheType                  string                         `json:"cache_type,omitempty"`
	CacheStatus                string                         `json:"cache_status,omitempty"`
	CacheHits                  int64                          `json:"cache_hits"`
	CacheMisses                int64                          `json:"cache_misses"`
	CacheSemanticHits          int64                          `json:"cache_semantic_hits,omitempty"`
	CacheErrors                int64                          `json:"cache_errors,omitempty"`
	CacheEntries               int64                          `json:"cache_entries,omitempty"`
	CacheEvictions             int64                          `json:"cache_evictions,omitempty"`
	CacheHitRate               float64                        `json:"cache_hit_rate"`
	RateLimitRejections        int64                          `json:"rate_limit_rejections"`
	GuardrailBlocks            int64                          `json:"guardrail_blocks"`
	GuardrailRedactions        int64                          `json:"guardrail_redactions"`
	SpendRedisDriftTotal       int64                          `json:"spend_redis_drift_total"`
	FinOpsOutboxPending        int64                          `json:"finops_outbox_pending"`
	FinOpsOutboxDeadLetter     int64                          `json:"finops_outbox_dead_letter"`
	FinOpsOutboxBackpressure   int64                          `json:"finops_outbox_backpressure"`
	AuditSIEMDelivered         int64                          `json:"audit_siem_delivered"`
	AuditSIEMFailed            int64                          `json:"audit_siem_failed"`
	AuditSIEMDropped           int64                          `json:"audit_siem_dropped"`
	RoutingSignalDegradedTotal int64                          `json:"routing_signal_degraded_total"`
	RedisCBState               int                            `json:"redis_cb_state"`
	StreamRequests             int64                          `json:"stream_requests"`
	StreamErrors               int64                          `json:"stream_errors"`
	StreamDurationSumMs        int64                          `json:"stream_duration_sum_ms"`
	StreamDurationCount        int64                          `json:"stream_duration_count"`
	StreamTTFTSumMs            int64                          `json:"stream_ttft_sum_ms"`
	StreamTTFTCount            int64                          `json:"stream_ttft_count"`
	SlowestProvider            string                         `json:"slowest_provider,omitempty"`
	HighestFailureDeployment   string                         `json:"highest_failure_deployment,omitempty"`
	Providers                  map[string]ProviderTelemetry   `json:"providers"`
	Deployments                map[string]DeploymentTelemetry `json:"deployments"`
	GuardrailMetrics           []GuardrailMetricSummary       `json:"guardrail_metrics,omitempty"`
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
	latencyHist slidingWindow
	ttftHist    slidingWindow
	lastAccess  uint64
}

type deploymentInternal struct {
	id          string
	name        string
	provider    string
	model       string
	totalReqs   int64
	errors      int64
	latencyHist slidingWindow
	ttftHist    slidingWindow
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

// Collector aggregates bounded sliding-window telemetry for the Operator Web UI
// (`GET /admin/v1/observability/metrics`) and forwards observations to OpenTelemetry
// Instruments for OTLP/HTTP export.
type Collector struct {
	mu                     sync.RWMutex
	instruments            *Instruments
	totalRequests          int64
	totalErrors            int64
	totalFallbacks         int64
	totalRetries           int64
	cacheHits              int64
	cacheMisses            int64
	rateLimitRejections    int64
	guardrailBlocks        int64
	guardrailRedactions    int64
	spendRedisDrift        int64
	routingSignalDegraded  int64
	redisCBState           int
	redisCBStateProvider   func() int
	cacheMetricsProvider   func() (hits, misses int64)
	cacheTelemetryProvider func() CacheTelemetry
	finopsOutboxProvider   func() (pending, deadLetter, backpressure int64)
	auditSIEMProvider      func() (delivered, failed, dropped int64)
	otelStatusProvider     func() OTelStatus
	streamRequests         int64
	streamErrors           int64
	streamDuration         slidingWindow
	streamTTFT             slidingWindow
	globalLatency          slidingWindow
	globalTTFT             slidingWindow
	routingMicros          slidingWindow
	providers              map[string]*providerInternal
	maxProviders           int
	deployments            map[string]*deploymentInternal
	maxDeployments         int
	guardrails             map[GuardrailMetricKey]*guardrailInternal
	maxGuardrails          int
	accessSeq              uint64
}

// NewCollector creates a bounded, concurrency-safe telemetry Collector.
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

// SetInstruments attaches OpenTelemetry metric instruments so every observation recorded
// on Collector is also exported over OTLP/HTTP.
func (c *Collector) SetInstruments(inst *Instruments) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.instruments = inst
	c.mu.Unlock()
}

// Instruments returns the attached OpenTelemetry Instruments, if any.
func (c *Collector) Instruments() *Instruments {
	if c == nil {
		return nil
	}
	c.mu.RLock()
	inst := c.instruments
	c.mu.RUnlock()
	return inst
}

// RecordSpendRedisDrift increments the counter for FinOps outbox events whose
// Redis spend reconciliation could not be completed within max retries.
func (c *Collector) RecordSpendRedisDrift() {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.spendRedisDrift++
	inst := c.instruments
	c.mu.Unlock()
	if inst != nil {
		inst.RecordSpendRedisDrift(context.Background())
	}
}

// RecordRoutingSignalDegraded increments the counter for routing operations that
// fell back to process-local state because shared Redis signals were unavailable.
func (c *Collector) RecordRoutingSignalDegraded() {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.routingSignalDegraded++
	inst := c.instruments
	c.mu.Unlock()
	if inst != nil {
		inst.RecordRoutingSignalDegraded(context.Background())
	}
}

// SetRedisCBState sets the observed Redis circuit breaker state code
// (0=closed, 1=half_open, 2=open).
func (c *Collector) SetRedisCBState(stateCode int) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.redisCBState = stateCode
	c.mu.Unlock()
}

// SetRedisCBStateProvider attaches a dynamic callback returning the Redis
// circuit breaker state code (0=closed, 1=half_open, 2=open).
func (c *Collector) SetRedisCBStateProvider(provider func() int) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.redisCBStateProvider = provider
	c.mu.Unlock()
}

// SetCacheMetricsProvider attaches a dynamic callback returning authoritative
// eligible response cache hits and misses from ResponseCache.
func (c *Collector) SetCacheMetricsProvider(provider func() (hits, misses int64)) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.cacheMetricsProvider = provider
	c.mu.Unlock()
}

// SetCacheTelemetryProvider attaches a dynamic callback returning full live
// response-cache telemetry for Snapshot().
func (c *Collector) SetCacheTelemetryProvider(provider func() CacheTelemetry) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.cacheTelemetryProvider = provider
	c.mu.Unlock()
}

// SetFinOpsOutboxProvider attaches a callback returning live FinOps outbox stats for Snapshot().
func (c *Collector) SetFinOpsOutboxProvider(provider func() (pending, deadLetter, backpressure int64)) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.finopsOutboxProvider = provider
	c.mu.Unlock()
}

// SetAuditSIEMProvider attaches a callback returning live Audit SIEM delivery stats for Snapshot().
func (c *Collector) SetAuditSIEMProvider(provider func() (delivered, failed, dropped int64)) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.auditSIEMProvider = provider
	c.mu.Unlock()
}

// SetOTelStatusProvider attaches a callback reporting active OTLP signals for Snapshot().
func (c *Collector) SetOTelStatusProvider(provider func() OTelStatus) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.otelStatusProvider = provider
	c.mu.Unlock()
}

// RecordStream adds timing and failure measurements for one completed streaming inference response.
func (c *Collector) RecordStream(duration, ttft time.Duration, failed bool) {
	if c == nil {
		return
	}
	c.mu.Lock()
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
	inst := c.instruments
	c.mu.Unlock()
	if inst != nil {
		inst.RecordStream(context.Background(), duration, ttft, failed)
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
	latencyMs := max(obs.LatencyMs, 0)

	c.mu.Lock()
	if c.guardrails == nil {
		c.guardrails = make(map[GuardrailMetricKey]*guardrailInternal)
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
	if obs.IsError || decisionLabel == guardrailDecisionError {
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
	inst := c.instruments
	c.mu.Unlock()

	if inst != nil {
		inst.RecordGuardrail(context.Background(), obs)
	}
}

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
	if c == nil {
		return
	}
	c.mu.Lock()
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
	inst := c.instruments
	c.mu.Unlock()

	if inst != nil {
		inst.RecordRequest(context.Background(), obs)
	}
}

// RecordDeploymentAttempt records an individual upstream deployment attempt (including failed primary attempts prior to failover).
func (c *Collector) RecordDeploymentAttempt(depID, depName, provider, model string, latencyMs int64, failed bool) {
	if c == nil || depID == "" {
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

// Snapshot computes the full operational telemetry snapshot for the Operator Web UI.
func (c *Collector) Snapshot() TelemetrySnapshot {
	c.mu.RLock()

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
		maps.Copy(decCopy, g.decisionCounts)
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

	cbState := c.redisCBState
	cbProvider := c.redisCBStateProvider
	cacheProvider := c.cacheMetricsProvider
	cacheTelemetryProvider := c.cacheTelemetryProvider
	outboxProvider := c.finopsOutboxProvider
	siemProvider := c.auditSIEMProvider
	otelStatusProvider := c.otelStatusProvider

	cacheHits := c.cacheHits
	cacheMisses := c.cacheMisses
	cacheHitRate := 0.0
	if totalCache := cacheHits + cacheMisses; totalCache > 0 {
		cacheHitRate = float64(cacheHits) / float64(totalCache)
	}

	snap := TelemetrySnapshot{
		GeneratedAt:                time.Now().UTC(),
		TotalRequests:              c.totalRequests,
		TotalErrors:                c.totalErrors,
		GlobalErrorRate:            errRate,
		AvgLatencyMs:               avgLat,
		P50LatencyMs:               p50Lat,
		P95LatencyMs:               p95Lat,
		P99LatencyMs:               p99Lat,
		AvgTTFTMs:                  avgTTFT,
		P95TTFTMs:                  p95TTFT,
		AvgRoutingOverheadMicros:   avgRoute,
		P95RoutingOverheadMicros:   p95Route,
		TotalFallbacks:             c.totalFallbacks,
		FallbackRate:               fbRate,
		TotalRetries:               c.totalRetries,
		CacheHits:                  cacheHits,
		CacheMisses:                cacheMisses,
		CacheHitRate:               cacheHitRate,
		RateLimitRejections:        c.rateLimitRejections,
		GuardrailBlocks:            c.guardrailBlocks,
		GuardrailRedactions:        c.guardrailRedactions,
		SpendRedisDriftTotal:       c.spendRedisDrift,
		RoutingSignalDegradedTotal: c.routingSignalDegraded,
		RedisCBState:               cbState,
		StreamRequests:             c.streamRequests,
		StreamErrors:               c.streamErrors,
		StreamDurationSumMs:        c.streamDuration.sum,
		StreamDurationCount:        c.streamDuration.count,
		StreamTTFTSumMs:            c.streamTTFT.sum,
		StreamTTFTCount:            c.streamTTFT.count,
		SlowestProvider:            slowestProv,
		HighestFailureDeployment:   highestFailDep,
		Providers:                  provMap,
		Deployments:                depMap,
		GuardrailMetrics:           guardrailList,
	}
	c.mu.RUnlock()

	if cbProvider != nil {
		snap.RedisCBState = cbProvider()
	}
	if otelStatusProvider != nil {
		st := otelStatusProvider()
		snap.OTelEnabled = st.Enabled
		snap.OTelSignals = st.ActiveSignals()
	}
	if outboxProvider != nil {
		snap.FinOpsOutboxPending, snap.FinOpsOutboxDeadLetter, snap.FinOpsOutboxBackpressure = outboxProvider()
	}
	if siemProvider != nil {
		snap.AuditSIEMDelivered, snap.AuditSIEMFailed, snap.AuditSIEMDropped = siemProvider()
	}
	if cacheTelemetryProvider != nil {
		ct := cacheTelemetryProvider()
		snap.CacheEnabled = ct.Enabled
		snap.CacheType = ct.Type
		snap.CacheStatus = ct.Status
		snap.CacheHits = ct.Hits
		snap.CacheMisses = ct.Misses
		snap.CacheSemanticHits = ct.SemanticHits
		snap.CacheErrors = ct.Errors
		snap.CacheEntries = ct.Entries
		snap.CacheEvictions = ct.Evictions
		if total := ct.Hits + ct.Misses; total > 0 {
			snap.CacheHitRate = float64(ct.Hits) / float64(total)
		} else {
			snap.CacheHitRate = 0
		}
	} else if cacheProvider != nil {
		h, m := cacheProvider()
		snap.CacheHits = h
		snap.CacheMisses = m
		if total := h + m; total > 0 {
			snap.CacheHitRate = float64(h) / float64(total)
		} else {
			snap.CacheHitRate = 0
		}
	}
	return snap
}
