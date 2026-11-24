package observability

import (
	"context"
	"errors"
	"math"
	"runtime/metrics"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

// Official OpenTelemetry GenAI Semantic Convention histogram bucket boundaries.
var (
	genAIDurationBucketsSec = []float64{0.01, 0.02, 0.04, 0.08, 0.16, 0.32, 0.64, 1.28, 2.56, 5.12, 10.24, 20.48, 40.96, 81.92}
	genAITokenBuckets       = []float64{1, 4, 16, 64, 256, 1024, 4096, 16384, 65536, 262144, 1048576, 4194304}
	genAITTFTBucketsSec     = []float64{0.001, 0.005, 0.01, 0.02, 0.04, 0.06, 0.08, 0.1, 0.25, 0.5, 0.75, 1.0, 2.5, 5.0, 7.5, 10.0}
	guardrailBucketsMs      = []float64{5, 10, 25, 50, 100, 250, 500, 1000}
	routingOverheadBuckets  = []float64{10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000}
)

// DeploymentHealthMetric summarizes one deployment's active probe state for OTel export.
type DeploymentHealthMetric struct {
	Provider       string
	Model          string
	Healthy        bool
	ProbeLatencyMs int64
}

// UpstreamHTTPMetricsSnapshot mirrors low-cardinality outbound HTTP transport counters.
type UpstreamHTTPMetricsSnapshot struct {
	Requests           int64
	DialAttempts       int64
	TLSHandshakes      int64
	FreshConnections   int64
	ReusedConnections  int64
	HTTP1Responses     int64
	HTTP2Responses     int64
	FirstByteWaitNanos int64
	FirstByteWaitCount int64
	IdleTimeouts       int64
}

// BudgetMetricsSnapshot captures low-cardinality budget reservation lookup counters.
type BudgetMetricsSnapshot struct {
	IndexedLookups         int64
	CatalogScans           int64
	BudgetedChecks         int64
	PricingSummaries       int64
	PricingSummaryRebuilds int64
	CatalogSize            int64
}

// StorageLookupMetricsSnapshot captures Postgres fallback lookup counters.
type StorageLookupMetricsSnapshot struct {
	SubscriptionFallbacks      int64
	EmptySubscriptionFallbacks int64
	GuardrailFallbacks         int64
	MissingGuardrailFallbacks  int64
}

// OperationalMetricsProviders wires live runtime state into OTel Observable instruments.
type OperationalMetricsProviders struct {
	CacheTelemetry   func() CacheTelemetry
	RedisCBState     func() int
	FinOpsOutbox     func() (pending, deadLetter, backpressure int64)
	AuditSIEM        func() (delivered, failed, dropped int64)
	DeploymentHealth func() []DeploymentHealthMetric
	UpstreamHTTP     func() UpstreamHTTPMetricsSnapshot
	KeyRotation      func() (deliveries, failures int64)
	BudgetStats      func() BudgetMetricsSnapshot
	StorageLookups   func() StorageLookupMetricsSnapshot
}

// GenAIOperationObservation records one GenAI upstream operation for OTel GenAI histograms.
type GenAIOperationObservation struct {
	Operation    string
	Provider     string
	RequestModel string
	ErrorType    string
	Duration     time.Duration
	TTFT         time.Duration
	InputTokens  int64
	OutputTokens int64
}

// Instruments holds GoRoute's pure OpenTelemetry dot-separated metrics under
// `gen_ai.*` (OpenTelemetry GenAI Semantic Conventions) and `gateway.*`.
type Instruments struct {
	meter metric.Meter

	// OpenTelemetry GenAI Semantic Convention Histograms
	genAIOperationDuration metric.Float64Histogram
	genAITokenUsage        metric.Int64Histogram
	genAITimeToFirstToken  metric.Float64Histogram

	// Core Gateway & Routing Instruments
	requests              metric.Int64Counter
	errors                metric.Int64Counter
	requestDuration       metric.Float64Histogram
	routingOverhead       metric.Float64Histogram
	routingFallbacks      metric.Int64Counter
	routingRetries        metric.Int64Counter
	routingSignalDegraded metric.Int64Counter
	ratelimitRejections   metric.Int64Counter

	// Streaming Instruments
	streams        metric.Int64Counter
	streamErrors   metric.Int64Counter
	streamDuration metric.Float64Histogram
	streamTTFT     metric.Float64Histogram

	// Provider Instruments
	providerRequests metric.Int64Counter
	providerErrors   metric.Int64Counter
	providerSpend    metric.Int64Counter

	// Guardrail Instruments
	guardrailBlocks      metric.Int64Counter
	guardrailEvaluations metric.Int64Counter
	guardrailErrors      metric.Int64Counter
	guardrailDuration    metric.Float64Histogram

	// FinOps & Protocol Instruments
	finopsRedisDrift metric.Int64Counter
	mcpRequests      metric.Int64Counter
	a2aRequests      metric.Int64Counter

	regMu        sync.Mutex
	registration metric.Registration
}

// NewInstruments creates all synchronous OpenTelemetry instruments on meter.
func NewInstruments(meter metric.Meter) (*Instruments, error) {
	if meter == nil {
		return nil, errors.New("nil OpenTelemetry meter")
	}
	inst := &Instruments{meter: meter}
	if err := inst.initGenAIAndCoreInstruments(meter); err != nil {
		return nil, err
	}
	if err := inst.initStreamAndProviderInstruments(meter); err != nil {
		return nil, err
	}
	if err := inst.initGuardrailAndProtocolInstruments(meter); err != nil {
		return nil, err
	}
	return inst, nil
}

func (i *Instruments) initGenAIAndCoreInstruments(meter metric.Meter) error {
	var err error
	if i.genAIOperationDuration, err = meter.Float64Histogram(
		"gen_ai.client.operation.duration",
		metric.WithDescription("Duration of GenAI client operations."),
		metric.WithUnit("s"),
		metric.WithExplicitBucketBoundaries(genAIDurationBucketsSec...),
	); err != nil {
		return err
	}
	if i.genAITokenUsage, err = meter.Int64Histogram(
		"gen_ai.client.token.usage",
		metric.WithDescription("Measures number of input and output tokens used."),
		metric.WithUnit("{token}"),
		metric.WithExplicitBucketBoundaries(genAITokenBuckets...),
	); err != nil {
		return err
	}
	if i.genAITimeToFirstToken, err = meter.Float64Histogram(
		"gen_ai.server.time_to_first_token",
		metric.WithDescription("Time to generate first token for successful streaming responses."),
		metric.WithUnit("s"),
		metric.WithExplicitBucketBoundaries(genAITTFTBucketsSec...),
	); err != nil {
		return err
	}
	if i.requests, err = meter.Int64Counter(
		"gateway.requests",
		metric.WithDescription("Total inference requests processed by the AI Gateway."),
		metric.WithUnit("{request}"),
	); err != nil {
		return err
	}
	if i.errors, err = meter.Int64Counter(
		"gateway.errors",
		metric.WithDescription("Total failed inference requests."),
		metric.WithUnit("{request}"),
	); err != nil {
		return err
	}
	if i.requestDuration, err = meter.Float64Histogram(
		"gateway.request.duration",
		metric.WithDescription("End-to-end non-cached gateway inference request duration."),
		metric.WithUnit("s"),
		metric.WithExplicitBucketBoundaries(genAIDurationBucketsSec...),
	); err != nil {
		return err
	}
	if i.routingOverhead, err = meter.Float64Histogram(
		"gateway.routing.overhead",
		metric.WithDescription("Stage 1 + Stage 2 routing decision overhead."),
		metric.WithUnit("us"),
		metric.WithExplicitBucketBoundaries(routingOverheadBuckets...),
	); err != nil {
		return err
	}
	if i.routingFallbacks, err = meter.Int64Counter(
		"gateway.routing.fallbacks",
		metric.WithDescription("Total cross-group or cross-provider fallback executions."),
		metric.WithUnit("{fallback}"),
	); err != nil {
		return err
	}
	if i.routingRetries, err = meter.Int64Counter(
		"gateway.routing.retries",
		metric.WithDescription("Total intra-group retry attempts."),
		metric.WithUnit("{retry}"),
	); err != nil {
		return err
	}
	if i.routingSignalDegraded, err = meter.Int64Counter(
		"gateway.routing.signal_degraded",
		metric.WithDescription("Total routing operations degraded to process-local signals due to Redis unavailability."),
		metric.WithUnit("{operation}"),
	); err != nil {
		return err
	}
	if i.ratelimitRejections, err = meter.Int64Counter(
		"gateway.ratelimit.rejections",
		metric.WithDescription("Total requests rejected by rate limiting or budget guards."),
		metric.WithUnit("{request}"),
	); err != nil {
		return err
	}
	return nil
}

func (i *Instruments) initStreamAndProviderInstruments(meter metric.Meter) error {
	var err error
	if i.streams, err = meter.Int64Counter(
		"gateway.streams",
		metric.WithDescription("Total completed streaming inference calls."),
		metric.WithUnit("{stream}"),
	); err != nil {
		return err
	}
	if i.streamErrors, err = meter.Int64Counter(
		"gateway.stream.errors",
		metric.WithDescription("Streaming inference calls that ended with an upstream or handler error."),
		metric.WithUnit("{stream}"),
	); err != nil {
		return err
	}
	if i.streamDuration, err = meter.Float64Histogram(
		"gateway.stream.duration",
		metric.WithDescription("Upstream streaming inference duration."),
		metric.WithUnit("s"),
		metric.WithExplicitBucketBoundaries(genAIDurationBucketsSec...),
	); err != nil {
		return err
	}
	if i.streamTTFT, err = meter.Float64Histogram(
		"gateway.stream.ttft",
		metric.WithDescription("Time-to-first-token for streaming inference calls."),
		metric.WithUnit("s"),
		metric.WithExplicitBucketBoundaries(genAITTFTBucketsSec...),
	); err != nil {
		return err
	}
	if i.providerRequests, err = meter.Int64Counter(
		"gateway.provider.requests",
		metric.WithDescription("Total requests by upstream provider."),
		metric.WithUnit("{request}"),
	); err != nil {
		return err
	}
	if i.providerErrors, err = meter.Int64Counter(
		"gateway.provider.errors",
		metric.WithDescription("Total errors by upstream provider."),
		metric.WithUnit("{request}"),
	); err != nil {
		return err
	}
	if i.providerSpend, err = meter.Int64Counter(
		"gateway.provider.spend",
		metric.WithDescription("Total upstream provider spend in micro-dollars."),
		metric.WithUnit("{micro_usd}"),
	); err != nil {
		return err
	}
	return nil
}

func (i *Instruments) initGuardrailAndProtocolInstruments(meter metric.Meter) error {
	var err error
	if i.guardrailBlocks, err = meter.Int64Counter(
		"gateway.guardrail.blocks",
		metric.WithDescription("Total requests blocked by security guardrails."),
		metric.WithUnit("{request}"),
	); err != nil {
		return err
	}
	if i.guardrailEvaluations, err = meter.Int64Counter(
		"gateway.guardrail.evaluations",
		metric.WithDescription("Total guardrail evaluations by guardrail, hook, and decision."),
		metric.WithUnit("{evaluation}"),
	); err != nil {
		return err
	}
	if i.guardrailErrors, err = meter.Int64Counter(
		"gateway.guardrail.errors",
		metric.WithDescription("Total guardrail evaluation errors by guardrail and hook."),
		metric.WithUnit("{error}"),
	); err != nil {
		return err
	}
	if i.guardrailDuration, err = meter.Float64Histogram(
		"gateway.guardrail.duration",
		metric.WithDescription("Guardrail evaluation duration."),
		metric.WithUnit("ms"),
		metric.WithExplicitBucketBoundaries(guardrailBucketsMs...),
	); err != nil {
		return err
	}
	if i.finopsRedisDrift, err = meter.Int64Counter(
		"gateway.finops.redis_drift",
		metric.WithDescription("Total FinOps spend events that exhausted Redis reconciliation retries."),
		metric.WithUnit("{event}"),
	); err != nil {
		return err
	}
	if i.mcpRequests, err = meter.Int64Counter(
		"gateway.mcp.requests",
		metric.WithDescription("Total MCP protocol operations by method and status."),
		metric.WithUnit("{request}"),
	); err != nil {
		return err
	}
	if i.a2aRequests, err = meter.Int64Counter(
		"gateway.a2a.requests",
		metric.WithDescription("Total A2A protocol operations by method and status."),
		metric.WithUnit("{request}"),
	); err != nil {
		return err
	}
	return nil
}

type operationalInstruments struct {
	cacheHits, cacheMisses, cacheErrors, cacheSemanticHits, cacheEvictions metric.Int64ObservableCounter
	cacheEntries                                                           metric.Int64ObservableGauge
	redisCBState                                                           metric.Int64ObservableGauge
	outboxPending                                                          metric.Int64ObservableGauge
	outboxDeadLetter, outboxBackpressure                                   metric.Int64ObservableCounter
	siemDelivered, siemFailed, siemDropped                                 metric.Int64ObservableCounter
	depHealthy, depProbeLatency                                            metric.Int64ObservableGauge
	upReqs, upDials, upTLS, upFresh, upReused, upH1, upH2, upIdle          metric.Int64ObservableCounter
	upFBW                                                                  metric.Float64ObservableCounter
	rotDelivered, rotFailed                                                metric.Int64ObservableCounter
	budgetIndexed, budgetScans, budgetChecks                               metric.Int64ObservableCounter
	budgetSummaries, budgetRebuilds                                        metric.Int64ObservableCounter
	catalogSize                                                            metric.Int64ObservableGauge
	storageFallbacks                                                       metric.Int64ObservableCounter
	goHeapAlloc, goHeapInuse, goHeapObjects                                metric.Int64ObservableGauge
	goGCCycles                                                             metric.Int64ObservableCounter
	goGCPause                                                              metric.Float64ObservableCounter
}

func (op *operationalInstruments) initCacheAndPlatform(m metric.Meter) error {
	var err error
	if op.cacheHits, err = m.Int64ObservableCounter("gateway.cache.hits", metric.WithDescription("Total response cache hits (exact and semantic)."), metric.WithUnit("{operation}")); err != nil {
		return err
	}
	if op.cacheMisses, err = m.Int64ObservableCounter("gateway.cache.misses", metric.WithDescription("Total response cache misses."), metric.WithUnit("{operation}")); err != nil {
		return err
	}
	if op.cacheErrors, err = m.Int64ObservableCounter("gateway.cache.errors", metric.WithDescription("Total fail-open response cache errors."), metric.WithUnit("{error}")); err != nil {
		return err
	}
	if op.cacheSemanticHits, err = m.Int64ObservableCounter("gateway.cache.semantic_hits", metric.WithDescription("Total semantic vector similarity response cache hits."), metric.WithUnit("{operation}")); err != nil {
		return err
	}
	if op.cacheEntries, err = m.Int64ObservableGauge("gateway.cache.entries", metric.WithDescription("Current in-memory response cache entry count."), metric.WithUnit("{entry}")); err != nil {
		return err
	}
	if op.cacheEvictions, err = m.Int64ObservableCounter("gateway.cache.evictions", metric.WithDescription("Total response cache LRU evictions."), metric.WithUnit("{eviction}")); err != nil {
		return err
	}
	if op.redisCBState, err = m.Int64ObservableGauge("gateway.redis.circuit_breaker.state", metric.WithDescription("Current Redis circuit breaker state (0=closed, 1=half_open, 2=open).")); err != nil {
		return err
	}
	if op.outboxPending, err = m.Int64ObservableGauge("gateway.finops.outbox.pending", metric.WithDescription("Current pending FinOps spend outbox depth."), metric.WithUnit("{event}")); err != nil {
		return err
	}
	if op.outboxDeadLetter, err = m.Int64ObservableCounter("gateway.finops.outbox.dead_letter", metric.WithDescription("Cumulative FinOps spend outbox dead-letter events."), metric.WithUnit("{event}")); err != nil {
		return err
	}
	if op.outboxBackpressure, err = m.Int64ObservableCounter("gateway.finops.outbox.backpressure", metric.WithDescription("Cumulative FinOps spend outbox backpressure rejections."), metric.WithUnit("{event}")); err != nil {
		return err
	}
	if op.siemDelivered, err = m.Int64ObservableCounter("gateway.audit.siem.delivered", metric.WithDescription("Cumulative audit events delivered to external SIEM webhook."), metric.WithUnit("{event}")); err != nil {
		return err
	}
	if op.siemFailed, err = m.Int64ObservableCounter("gateway.audit.siem.failed", metric.WithDescription("Cumulative audit events that failed SIEM webhook delivery."), metric.WithUnit("{event}")); err != nil {
		return err
	}
	if op.siemDropped, err = m.Int64ObservableCounter("gateway.audit.siem.dropped", metric.WithDescription("Cumulative audit events dropped due to full SIEM queue."), metric.WithUnit("{event}")); err != nil {
		return err
	}
	if op.depHealthy, err = m.Int64ObservableGauge("gateway.deployment.healthy", metric.WithDescription("Active upstream deployment probe health (1=healthy, 0=unhealthy).")); err != nil {
		return err
	}
	if op.depProbeLatency, err = m.Int64ObservableGauge("gateway.deployment.probe.latency", metric.WithDescription("Latest active upstream deployment health probe latency."), metric.WithUnit("ms")); err != nil {
		return err
	}
	return nil
}

func (op *operationalInstruments) initUpstreamAndBudget(m metric.Meter) error {
	var err error
	if op.upReqs, err = m.Int64ObservableCounter("gateway.upstream.http.requests", metric.WithDescription("Total outbound upstream HTTP requests."), metric.WithUnit("{request}")); err != nil {
		return err
	}
	if op.upDials, err = m.Int64ObservableCounter("gateway.upstream.http.dial_attempts", metric.WithDescription("Total outbound upstream TCP dial attempts."), metric.WithUnit("{attempt}")); err != nil {
		return err
	}
	if op.upTLS, err = m.Int64ObservableCounter("gateway.upstream.http.tls_handshakes", metric.WithDescription("Total outbound upstream TLS handshakes."), metric.WithUnit("{handshake}")); err != nil {
		return err
	}
	if op.upFresh, err = m.Int64ObservableCounter("gateway.upstream.http.connections.fresh", metric.WithDescription("Total fresh outbound upstream connections."), metric.WithUnit("{connection}")); err != nil {
		return err
	}
	if op.upReused, err = m.Int64ObservableCounter("gateway.upstream.http.connections.reused", metric.WithDescription("Total reused outbound upstream connections."), metric.WithUnit("{connection}")); err != nil {
		return err
	}
	if op.upH1, err = m.Int64ObservableCounter("gateway.upstream.http.responses.http1", metric.WithDescription("Total HTTP/1.x upstream responses."), metric.WithUnit("{response}")); err != nil {
		return err
	}
	if op.upH2, err = m.Int64ObservableCounter("gateway.upstream.http.responses.http2", metric.WithDescription("Total HTTP/2 upstream responses."), metric.WithUnit("{response}")); err != nil {
		return err
	}
	if op.upFBW, err = m.Float64ObservableCounter("gateway.upstream.http.first_byte_wait", metric.WithDescription("Cumulative upstream time waiting for first response byte."), metric.WithUnit("s")); err != nil {
		return err
	}
	if op.upIdle, err = m.Int64ObservableCounter("gateway.upstream.http.idle_timeouts", metric.WithDescription("Total upstream stream idle timeouts."), metric.WithUnit("{timeout}")); err != nil {
		return err
	}
	if op.rotDelivered, err = m.Int64ObservableCounter("gateway.key_rotation.deliveries", metric.WithDescription("Total automated key rotation deliveries."), metric.WithUnit("{delivery}")); err != nil {
		return err
	}
	if op.rotFailed, err = m.Int64ObservableCounter("gateway.key_rotation.delivery_failures", metric.WithDescription("Total automated key rotation delivery failures."), metric.WithUnit("{failure}")); err != nil {
		return err
	}
	return nil
}

func (op *operationalInstruments) initStorageAndRuntime(m metric.Meter) error {
	var err error
	if op.budgetIndexed, err = m.Int64ObservableCounter("gateway.budget.indexed_lookups", metric.WithDescription("Total indexed model budget lookups."), metric.WithUnit("{lookup}")); err != nil {
		return err
	}
	if op.budgetScans, err = m.Int64ObservableCounter("gateway.budget.catalog_scans", metric.WithDescription("Total fallback catalog scans during budget checks."), metric.WithUnit("{scan}")); err != nil {
		return err
	}
	if op.budgetChecks, err = m.Int64ObservableCounter("gateway.budget.reservation_checks", metric.WithDescription("Total budgeted reservation checks."), metric.WithUnit("{check}")); err != nil {
		return err
	}
	if op.budgetSummaries, err = m.Int64ObservableCounter("gateway.budget.pricing_summary_lookups", metric.WithDescription("Total pricing summary lookups."), metric.WithUnit("{lookup}")); err != nil {
		return err
	}
	if op.budgetRebuilds, err = m.Int64ObservableCounter("gateway.budget.pricing_summary_rebuilds", metric.WithDescription("Total pricing summary cache rebuilds."), metric.WithUnit("{rebuild}")); err != nil {
		return err
	}
	if op.catalogSize, err = m.Int64ObservableGauge("gateway.model_catalog.size", metric.WithDescription("Current global model catalog size."), metric.WithUnit("{model}")); err != nil {
		return err
	}
	if op.storageFallbacks, err = m.Int64ObservableCounter("gateway.storage.fallback_queries", metric.WithDescription("Total PostgreSQL fallback lookup queries by query type."), metric.WithUnit("{query}")); err != nil {
		return err
	}
	if op.goHeapAlloc, err = m.Int64ObservableGauge("gateway.go.memory.heap_alloc", metric.WithDescription("Live Go heap bytes allocated (non-STW runtime/metrics)."), metric.WithUnit("By")); err != nil {
		return err
	}
	if op.goHeapInuse, err = m.Int64ObservableGauge("gateway.go.memory.heap_inuse", metric.WithDescription("Go heap bytes currently in use (non-STW runtime/metrics)."), metric.WithUnit("By")); err != nil {
		return err
	}
	if op.goHeapObjects, err = m.Int64ObservableGauge("gateway.go.memory.heap_objects", metric.WithDescription("Live Go heap object count (non-STW runtime/metrics)."), metric.WithUnit("{object}")); err != nil {
		return err
	}
	if op.goGCCycles, err = m.Int64ObservableCounter("gateway.go.gc.cycles", metric.WithDescription("Total completed Go garbage collection cycles."), metric.WithUnit("{cycle}")); err != nil {
		return err
	}
	if op.goGCPause, err = m.Float64ObservableCounter("gateway.go.gc.pause", metric.WithDescription("Cumulative Go garbage collection pause time (non-STW runtime/metrics)."), metric.WithUnit("s")); err != nil {
		return err
	}
	return nil
}

func (op *operationalInstruments) all() []metric.Observable {
	return []metric.Observable{
		op.cacheHits, op.cacheMisses, op.cacheErrors, op.cacheSemanticHits, op.cacheEntries, op.cacheEvictions,
		op.redisCBState,
		op.outboxPending, op.outboxDeadLetter, op.outboxBackpressure,
		op.siemDelivered, op.siemFailed, op.siemDropped,
		op.depHealthy, op.depProbeLatency,
		op.upReqs, op.upDials, op.upTLS, op.upFresh, op.upReused, op.upH1, op.upH2, op.upFBW, op.upIdle,
		op.rotDelivered, op.rotFailed,
		op.budgetIndexed, op.budgetScans, op.budgetChecks, op.budgetSummaries, op.budgetRebuilds, op.catalogSize,
		op.storageFallbacks,
		op.goHeapAlloc, op.goHeapInuse, op.goHeapObjects, op.goGCCycles, op.goGCPause,
	}
}

func (op *operationalInstruments) observe(o metric.Observer, p OperationalMetricsProviders) {
	if p.CacheTelemetry != nil {
		ct := p.CacheTelemetry()
		o.ObserveInt64(op.cacheHits, ct.Hits)
		o.ObserveInt64(op.cacheMisses, ct.Misses)
		o.ObserveInt64(op.cacheErrors, ct.Errors)
		o.ObserveInt64(op.cacheSemanticHits, ct.SemanticHits)
		o.ObserveInt64(op.cacheEntries, ct.Entries)
		o.ObserveInt64(op.cacheEvictions, ct.Evictions)
	}
	if p.RedisCBState != nil {
		o.ObserveInt64(op.redisCBState, int64(p.RedisCBState()))
	} else {
		o.ObserveInt64(op.redisCBState, 0)
	}
	if p.FinOpsOutbox != nil {
		pending, deadLetter, backpressure := p.FinOpsOutbox()
		o.ObserveInt64(op.outboxPending, pending)
		o.ObserveInt64(op.outboxDeadLetter, deadLetter)
		o.ObserveInt64(op.outboxBackpressure, backpressure)
	}
	if p.AuditSIEM != nil {
		delivered, failed, dropped := p.AuditSIEM()
		o.ObserveInt64(op.siemDelivered, delivered)
		o.ObserveInt64(op.siemFailed, failed)
		o.ObserveInt64(op.siemDropped, dropped)
	}
	if p.DeploymentHealth != nil {
		for _, d := range p.DeploymentHealth() {
			attrs := metric.WithAttributes(
				attribute.String("provider", sanitizeMetricLabel(d.Provider)),
				attribute.String("model", sanitizeMetricLabel(d.Model)),
			)
			v := int64(0)
			if d.Healthy {
				v = 1
			}
			o.ObserveInt64(op.depHealthy, v, attrs)
			o.ObserveInt64(op.depProbeLatency, d.ProbeLatencyMs, attrs)
		}
	}
	op.observeInfraAndRuntime(o, p)
}

func (op *operationalInstruments) observeInfraAndRuntime(o metric.Observer, p OperationalMetricsProviders) {
	if p.UpstreamHTTP != nil {
		s := p.UpstreamHTTP()
		o.ObserveInt64(op.upReqs, s.Requests)
		o.ObserveInt64(op.upDials, s.DialAttempts)
		o.ObserveInt64(op.upTLS, s.TLSHandshakes)
		o.ObserveInt64(op.upFresh, s.FreshConnections)
		o.ObserveInt64(op.upReused, s.ReusedConnections)
		o.ObserveInt64(op.upH1, s.HTTP1Responses)
		o.ObserveInt64(op.upH2, s.HTTP2Responses)
		o.ObserveFloat64(op.upFBW, float64(s.FirstByteWaitNanos)/float64(time.Second))
		o.ObserveInt64(op.upIdle, s.IdleTimeouts)
	}
	if p.KeyRotation != nil {
		del, fail := p.KeyRotation()
		o.ObserveInt64(op.rotDelivered, del)
		o.ObserveInt64(op.rotFailed, fail)
	}
	if p.BudgetStats != nil {
		bs := p.BudgetStats()
		o.ObserveInt64(op.budgetIndexed, bs.IndexedLookups)
		o.ObserveInt64(op.budgetScans, bs.CatalogScans)
		o.ObserveInt64(op.budgetChecks, bs.BudgetedChecks)
		o.ObserveInt64(op.budgetSummaries, bs.PricingSummaries)
		o.ObserveInt64(op.budgetRebuilds, bs.PricingSummaryRebuilds)
		o.ObserveInt64(op.catalogSize, bs.CatalogSize)
	}
	if p.StorageLookups != nil {
		sl := p.StorageLookups()
		o.ObserveInt64(op.storageFallbacks, sl.SubscriptionFallbacks, metric.WithAttributes(attribute.String("query_type", "subscription")))
		o.ObserveInt64(op.storageFallbacks, sl.EmptySubscriptionFallbacks, metric.WithAttributes(attribute.String("query_type", "subscription_empty")))
		o.ObserveInt64(op.storageFallbacks, sl.GuardrailFallbacks, metric.WithAttributes(attribute.String("query_type", "guardrail")))
		o.ObserveInt64(op.storageFallbacks, sl.MissingGuardrailFallbacks, metric.WithAttributes(attribute.String("query_type", "guardrail_missing")))
	}

	// Non-STW Go runtime memory & GC telemetry via stdlib runtime/metrics.
	samples := []metrics.Sample{
		{Name: "/memory/classes/heap/objects:bytes"},
		{Name: "/memory/classes/heap/unused:bytes"},
		{Name: "/gc/heap/objects:objects"},
		{Name: "/gc/cycles/total:gc-cycles"},
		{Name: "/gc/pauses:seconds"},
	}
	metrics.Read(samples)
	heapAlloc := uint64Sample(samples[0])
	heapUnused := uint64Sample(samples[1])
	heapObjects := uint64Sample(samples[2])
	gcCycles := uint64Sample(samples[3])
	gcPauseSec := float64HistogramSumSample(samples[4])
	o.ObserveInt64(op.goHeapAlloc, heapAlloc)
	o.ObserveInt64(op.goHeapInuse, heapAlloc+heapUnused)
	o.ObserveInt64(op.goHeapObjects, heapObjects)
	o.ObserveInt64(op.goGCCycles, gcCycles)
	o.ObserveFloat64(op.goGCPause, gcPauseSec)
}

// RegisterOperationalCallbacks registers asynchronous Observable instruments backed by
// live runtime providers and non-STW Go runtime/metrics counters.
func (i *Instruments) RegisterOperationalCallbacks(p OperationalMetricsProviders) error {
	if i == nil || i.meter == nil {
		return nil
	}
	i.regMu.Lock()
	defer i.regMu.Unlock()
	if i.registration != nil {
		_ = i.registration.Unregister()
		i.registration = nil
	}

	var op operationalInstruments
	if err := op.initCacheAndPlatform(i.meter); err != nil {
		return err
	}
	if err := op.initUpstreamAndBudget(i.meter); err != nil {
		return err
	}
	if err := op.initStorageAndRuntime(i.meter); err != nil {
		return err
	}

	reg, err := i.meter.RegisterCallback(func(_ context.Context, o metric.Observer) error {
		op.observe(o, p)
		return nil
	}, op.all()...)
	if err != nil {
		return err
	}
	i.registration = reg
	return nil
}

// RecordGenAIOperation records OpenTelemetry GenAI semantic convention duration, token usage, and TTFT histograms.
func (i *Instruments) RecordGenAIOperation(ctx context.Context, obs GenAIOperationObservation) {
	if i == nil {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	baseAttrs := []attribute.KeyValue{
		attribute.String("gen_ai.operation.name", sanitizeMetricLabel(obs.Operation)),
		attribute.String("gen_ai.provider.name", sanitizeMetricLabel(obs.Provider)),
		attribute.String("gen_ai.request.model", sanitizeMetricLabel(obs.RequestModel)),
	}
	durAttrs := baseAttrs
	if obs.ErrorType != "" {
		durAttrs = append(append([]attribute.KeyValue{}, baseAttrs...), attribute.String("error.type", sanitizeMetricLabel(obs.ErrorType)))
	}
	if obs.Duration >= 0 {
		i.genAIOperationDuration.Record(ctx, obs.Duration.Seconds(), metric.WithAttributes(durAttrs...))
	}
	if obs.TTFT > 0 {
		i.genAITimeToFirstToken.Record(ctx, obs.TTFT.Seconds(), metric.WithAttributes(baseAttrs...))
	}
	if obs.InputTokens > 0 {
		inAttrs := append(append([]attribute.KeyValue{}, baseAttrs...), attribute.String("gen_ai.token.type", "input"))
		i.genAITokenUsage.Record(ctx, obs.InputTokens, metric.WithAttributes(inAttrs...))
	}
	if obs.OutputTokens > 0 {
		outAttrs := append(append([]attribute.KeyValue{}, baseAttrs...), attribute.String("gen_ai.token.type", "output"))
		i.genAITokenUsage.Record(ctx, obs.OutputTokens, metric.WithAttributes(outAttrs...))
	}
}

// RecordRequest records core gateway request, latency, routing, provider, rate-limit, and guardrail counters.
func (i *Instruments) RecordRequest(ctx context.Context, obs RequestObservation) {
	if i == nil {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	i.requests.Add(ctx, 1)
	isErr := obs.StatusCode >= 400
	if isErr {
		i.errors.Add(ctx, 1)
	}
	if obs.LatencyMs >= 0 && !obs.CacheHit && !obs.RateLimited && !obs.GuardrailBlocked {
		i.requestDuration.Record(ctx, float64(obs.LatencyMs)/1000.0)
	}
	if obs.RoutingMicros > 0 {
		i.routingOverhead.Record(ctx, float64(obs.RoutingMicros))
	}
	if obs.FallbackAttempted {
		i.routingFallbacks.Add(ctx, 1)
	}
	if obs.RetryCount > 0 {
		i.routingRetries.Add(ctx, int64(obs.RetryCount))
	}
	if obs.RateLimited {
		i.ratelimitRejections.Add(ctx, 1)
	}
	if obs.GuardrailBlocked {
		i.guardrailBlocks.Add(ctx, 1)
	}
	if obs.Provider != "" {
		pAttr := metric.WithAttributes(attribute.String("provider", sanitizeMetricLabel(obs.Provider)))
		i.providerRequests.Add(ctx, 1, pAttr)
		if isErr {
			i.providerErrors.Add(ctx, 1, pAttr)
		}
		if obs.CostMicros > 0 {
			i.providerSpend.Add(ctx, obs.CostMicros, pAttr)
		}
	}
}

// RecordStream records streaming count, failure, duration, and TTFT histograms.
func (i *Instruments) RecordStream(ctx context.Context, duration, ttft time.Duration, failed bool) {
	if i == nil {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	i.streams.Add(ctx, 1)
	if failed {
		i.streamErrors.Add(ctx, 1)
	}
	if duration >= 0 {
		i.streamDuration.Record(ctx, duration.Seconds())
	}
	if ttft > 0 {
		i.streamTTFT.Record(ctx, ttft.Seconds())
	}
}

// RecordGuardrail records guardrail evaluation counters, errors, and duration histogram.
func (i *Instruments) RecordGuardrail(ctx context.Context, obs GuardrailObservation) {
	if i == nil {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	gLabel := sanitizeGuardrailLabel(obs.GuardrailName)
	hLabel := sanitizeGuardrailLabel(obs.Hook)
	decLabel := NormalizeGuardrailDecision(obs.Decision, obs.IsError)
	i.guardrailEvaluations.Add(ctx, 1, metric.WithAttributes(
		attribute.String("guardrail", gLabel),
		attribute.String("hook", hLabel),
		attribute.String("decision", decLabel),
	))
	if obs.IsError || decLabel == guardrailDecisionError {
		i.guardrailErrors.Add(ctx, 1, metric.WithAttributes(
			attribute.String("guardrail", gLabel),
			attribute.String("hook", hLabel),
		))
	}
	lat := max(obs.LatencyMs, 0)
	i.guardrailDuration.Record(ctx, float64(lat), metric.WithAttributes(
		attribute.String("guardrail", gLabel),
		attribute.String("hook", hLabel),
	))
}

// RecordRoutingSignalDegraded increments gateway.routing.signal_degraded.
func (i *Instruments) RecordRoutingSignalDegraded(ctx context.Context) {
	if i == nil {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	i.routingSignalDegraded.Add(ctx, 1)
}

// RecordSpendRedisDrift increments gateway.finops.redis_drift.
func (i *Instruments) RecordSpendRedisDrift(ctx context.Context) {
	if i == nil {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	i.finopsRedisDrift.Add(ctx, 1)
}

// RecordMCPRequest increments gateway.mcp.requests by method and status.
func (i *Instruments) RecordMCPRequest(ctx context.Context, method, status string) {
	if i == nil {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	i.mcpRequests.Add(ctx, 1, metric.WithAttributes(
		attribute.String("method", sanitizeMetricLabel(method)),
		attribute.String("status", sanitizeMetricLabel(status)),
	))
}

// RecordA2ARequest increments gateway.a2a.requests by method and status.
func (i *Instruments) RecordA2ARequest(ctx context.Context, method, status string) {
	if i == nil {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	i.a2aRequests.Add(ctx, 1, metric.WithAttributes(
		attribute.String("method", sanitizeMetricLabel(method)),
		attribute.String("status", sanitizeMetricLabel(status)),
	))
}

func uint64Sample(s metrics.Sample) int64 {
	if s.Value.Kind() != metrics.KindUint64 {
		return 0
	}
	v := s.Value.Uint64()
	if v > 1<<62 {
		return 1 << 62
	}
	return int64(v)
}

func float64HistogramSumSample(s metrics.Sample) float64 {
	if s.Value.Kind() != metrics.KindFloat64Histogram {
		return 0
	}
	h := s.Value.Float64Histogram()
	if h == nil || len(h.Counts) == 0 || len(h.Buckets) < len(h.Counts)+1 {
		return 0
	}
	var sum float64
	for i, c := range h.Counts {
		if c == 0 {
			continue
		}
		lo := h.Buckets[i]
		hi := h.Buckets[i+1]
		var rep float64
		switch {
		case math.IsInf(lo, -1) && !math.IsInf(hi, 1):
			if hi > 0 {
				rep = hi / 2
			}
		case math.IsInf(hi, 1) && !math.IsInf(lo, -1):
			if lo > 0 {
				rep = lo
			}
		case !math.IsInf(lo, 0) && !math.IsInf(hi, 0):
			if lo < 0 {
				lo = 0
			}
			if hi > lo {
				rep = (lo + hi) / 2
			} else if lo > 0 {
				rep = lo
			}
		}
		sum += rep * float64(c)
	}
	return sum
}

func sanitizeMetricLabel(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "unknown"
	}
	if len(s) > 128 {
		s = s[:128]
	}
	return s
}
