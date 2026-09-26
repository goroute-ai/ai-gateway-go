package router

import (
	"context"
	"math"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/redis/go-redis/v9"
)

const leastBusyReservationTTL = 2 * time.Second

type deploymentTelemetry struct {
	inFlight           int
	ewmaLatencyMs      float64
	ewmaTTFTMs         float64
	usedRPM            int
	usedTPM            int
	usedITPM           int
	usedOTPM           int
	windowStart        time.Time
	reservations       []time.Time
	sharedReservations []time.Time
}

func pruneReservationSlice(s []time.Time, now time.Time) ([]time.Time, int) {
	if len(s) == 0 {
		return s, 0
	}
	n := 0
	for _, exp := range s {
		if exp.After(now) {
			s[n] = exp
			n++
		}
	}
	return s[:n], n
}

func (m *deploymentTelemetry) pruneReservations(now time.Time) int {
	var n int
	m.reservations, n = pruneReservationSlice(m.reservations, now)
	return n
}

func (m *deploymentTelemetry) addReservation(now time.Time, ttl time.Duration) {
	m.reservations = append(m.reservations, now.Add(ttl))
}

func (m *deploymentTelemetry) pruneSharedReservations(now time.Time) int {
	var n int
	m.sharedReservations, n = pruneReservationSlice(m.sharedReservations, now)
	return n
}

func (m *deploymentTelemetry) addSharedReservation(now time.Time, ttl time.Duration) {
	m.sharedReservations = append(m.sharedReservations, now.Add(ttl))
}

func (m *deploymentTelemetry) consumeReservation(now time.Time) {
	if m.pruneReservations(now) > 0 {
		m.reservations = m.reservations[1:]
	}
	if m.pruneSharedReservations(now) > 0 {
		m.sharedReservations = m.sharedReservations[1:]
	}
}

func (m *deploymentTelemetry) checkWindow(now time.Time) {
	if m.windowStart.IsZero() {
		m.windowStart = now
		return
	}
	if now.Sub(m.windowStart) >= time.Minute {
		m.usedRPM = 0
		m.usedTPM = 0
		m.usedITPM = 0
		m.usedOTPM = 0
		m.windowStart = now
	}
}

// LoadBalancer implements Stage 2 of the Two-Stage Routing Engine:
// selecting the optimal healthy Deployment inside a ModelGroup using one of 5 production strategies:
// 1. weighted-shuffle
// 2. least-busy
// 3. latency-based (EWMA TTFT / normalized latency + tolerance band)
// 4. usage-based-headroom
// 5. lowest-cost
type LoadBalancer struct {
	mu                  sync.RWMutex
	metrics             map[string]*deploymentTelemetry
	rrCounters          sync.Map // map[string]*atomic.Uint64 keyed by ModelGroupID
	redis               *storage.RedisFabric
	sharedDegraded      atomic.Bool
	sharedChecked       atomic.Bool
	latencyTolerancePct atomic.Uint64
}

// NewLoadBalancer creates a Stage 2 deployment LoadBalancer optionally backed by RedisFabric telemetry.
func NewLoadBalancer(redisFabric ...*storage.RedisFabric) *LoadBalancer {
	lb := &LoadBalancer{
		metrics: make(map[string]*deploymentTelemetry),
	}
	lb.SetLatencyTolerancePct(0.10)
	if len(redisFabric) > 0 {
		lb.redis = redisFabric[0]
	}
	return lb
}

// SetLatencyTolerancePct sets the fractional band above minimum latency within which
// latency-based selection randomizes candidates to prevent thundering-herd oscillation.
func (lb *LoadBalancer) SetLatencyTolerancePct(pct float64) {
	if lb == nil {
		return
	}
	if pct < 0 {
		pct = 0
	} else if pct > 1 {
		pct = 1
	}
	lb.latencyTolerancePct.Store(math.Float64bits(pct))
}

// LatencyTolerancePct returns the configured latency tolerance band in [0, 1].
func (lb *LoadBalancer) LatencyTolerancePct() float64 {
	if lb == nil {
		return 0
	}
	return math.Float64frombits(lb.latencyTolerancePct.Load())
}

// Select chooses one deployment from the candidate list of healthy deployments according to strategy.
func (lb *LoadBalancer) Select(strategy domain.RoutingStrategy, candidates []*domain.Deployment) *domain.Deployment {
	return lb.SelectWithSignals(strategy, candidates, nil)
}

// SelectWithSignals selects one deployment using a pre-fetched SignalSnapshot when available
// so Stage 2 executes without duplicate Redis signal reads.
func (lb *LoadBalancer) SelectWithSignals(strategy domain.RoutingStrategy, candidates []*domain.Deployment, snap *SignalSnapshot) *domain.Deployment {
	if len(candidates) == 0 {
		return nil
	}
	if len(candidates) == 1 {
		return candidates[0]
	}
	if isAdaptiveStrategy(strategy) {
		if snap != nil && snap.fromRedis && snap.signals != nil {
			return lb.selectUsingSignals(strategy, candidates, snap.signals)
		}
		if snap == nil && lb.redis != nil {
			shared, err := lb.readSharedSignals(candidates)
			if err != nil {
				lb.setSharedDegraded(true, string(strategy))
			} else {
				lb.setSharedDegraded(false, string(strategy))
				return lb.selectUsingSignals(strategy, candidates, shared)
			}
		}
	}

	switch strategy {
	case domain.StrategyLeastBusy:
		return lb.selectLeastBusy(candidates)
	case domain.StrategyLatencyBased:
		return lb.selectLowestLatency(candidates)
	case domain.StrategyUsageBasedHeadroom:
		return lb.selectHighestHeadroom(candidates)
	case domain.StrategyLowestCost:
		return lb.selectLowestCost(candidates)
	case domain.StrategyRoundRobin:
		return lb.selectRoundRobin(candidates)
	default: // StrategyWeightedShuffle
		return lb.selectWeightedRandom(candidates)
	}
}

func (lb *LoadBalancer) selectRoundRobin(candidates []*domain.Deployment) *domain.Deployment {
	key := candidates[0].ModelGroupID
	val, ok := lb.rrCounters.Load(key)
	if !ok {
		val, _ = lb.rrCounters.LoadOrStore(key, &atomic.Uint64{})
	}
	counter := val.(*atomic.Uint64)
	idx := (counter.Add(1) - 1) % uint64(len(candidates))
	return candidates[idx]
}

func isAdaptiveStrategy(strategy domain.RoutingStrategy) bool {
	return strategy == domain.StrategyLeastBusy || strategy == domain.StrategyLatencyBased || strategy == domain.StrategyUsageBasedHeadroom
}

func pickRandomTie(ties []*domain.Deployment) *domain.Deployment {
	if len(ties) == 0 {
		return nil
	}
	if len(ties) == 1 {
		return ties[0]
	}
	return ties[rand.IntN(len(ties))]
}

func (lb *LoadBalancer) selectUsingSignals(strategy domain.RoutingStrategy, candidates []*domain.Deployment, signals map[string]deploymentTelemetry) *domain.Deployment {
	switch strategy {
	case domain.StrategyLeastBusy:
		lb.mu.Lock()
		defer lb.mu.Unlock()
		now := time.Now()
		var ties []*domain.Deployment
		minInFlight := math.MaxInt
		for _, d := range candidates {
			inFlight := signals[d.ID].inFlight
			if m, ok := lb.metrics[d.ID]; ok {
				inFlight += m.pruneSharedReservations(now)
			}
			if inFlight < minInFlight {
				minInFlight = inFlight
				ties = ties[:0]
				ties = append(ties, d)
			} else if inFlight == minInFlight {
				ties = append(ties, d)
			}
		}
		best := pickRandomTie(ties)
		if best != nil {
			lb.getOrCreate(best.ID).addSharedReservation(now, leastBusyReservationTTL)
		}
		return best
	case domain.StrategyLatencyBased:
		minLatency := math.MaxFloat64
		for _, d := range candidates {
			lat := effectiveLatencySignal(signals[d.ID])
			if lat < minLatency {
				minLatency = lat
			}
		}
		threshold := minLatency
		if tol := lb.LatencyTolerancePct(); tol > 0 && minLatency > 0 {
			threshold = minLatency * (1.0 + tol)
		}
		var chosen *domain.Deployment
		eligible := 0
		for _, d := range candidates {
			if effectiveLatencySignal(signals[d.ID]) <= threshold {
				if eligible == 0 || rand.IntN(eligible+1) == 0 {
					chosen = d
				}
				eligible++
			}
		}
		return chosen
	case domain.StrategyUsageBasedHeadroom:
		var ties []*domain.Deployment
		maxHeadroom := -math.MaxFloat64
		now := time.Now()
		for _, d := range candidates {
			capTPM := d.TPMCapacity
			if capTPM <= 0 {
				capTPM = 1000000
			}
			signal := signals[d.ID]
			usedTPM := 0
			if signal.windowStart.IsZero() || now.Sub(signal.windowStart) < time.Minute {
				usedTPM = signal.usedTPM
			}
			headroom := 1 - (float64(usedTPM) / float64(capTPM))
			if headroom > maxHeadroom {
				maxHeadroom = headroom
				ties = ties[:0]
				ties = append(ties, d)
			} else if headroom == maxHeadroom {
				ties = append(ties, d)
			}
		}
		return pickRandomTie(ties)
	default:
		return nil
	}
}

func (lb *LoadBalancer) selectWeightedRandom(candidates []*domain.Deployment) *domain.Deployment {
	hasExplicit := false
	hasRPM := false
	hasTPM := false
	for _, d := range candidates {
		if d.Weight > 0 {
			hasExplicit = true
		}
		if d.RPMCapacity > 0 {
			hasRPM = true
		}
		if d.TPMCapacity > 0 {
			hasTPM = true
		}
	}
	if !hasExplicit && !hasRPM && !hasTPM {
		return candidates[rand.IntN(len(candidates))]
	}
	candidateWeight := func(d *domain.Deployment) int {
		if hasExplicit {
			if d.Weight > 0 {
				return d.Weight
			}
			return 100
		}
		if hasRPM {
			if d.RPMCapacity > 0 {
				return d.RPMCapacity
			}
			return 1
		}
		if d.TPMCapacity > 0 {
			return d.TPMCapacity
		}
		return 1
	}
	totalWeight := 0
	for _, d := range candidates {
		totalWeight += candidateWeight(d)
	}
	r := rand.IntN(totalWeight)
	acc := 0
	for _, d := range candidates {
		acc += candidateWeight(d)
		if r < acc {
			return d
		}
	}
	return candidates[0]
}

func effectiveLatencySignal(m deploymentTelemetry) float64 {
	if m.ewmaTTFTMs > 0 {
		return m.ewmaTTFTMs
	}
	if m.ewmaLatencyMs > 0 {
		return m.ewmaLatencyMs
	}
	return 250.0 // Default baseline 250ms for unexplored deployments
}

func (lb *LoadBalancer) selectLeastBusy(candidates []*domain.Deployment) *domain.Deployment {
	lb.mu.Lock()
	defer lb.mu.Unlock()

	now := time.Now()
	var ties []*domain.Deployment
	minInFlight := math.MaxInt
	for _, d := range candidates {
		inFlight := 0
		if m, ok := lb.metrics[d.ID]; ok {
			inFlight = m.inFlight + m.pruneReservations(now)
		}
		if inFlight < minInFlight {
			minInFlight = inFlight
			ties = ties[:0]
			ties = append(ties, d)
		} else if inFlight == minInFlight {
			ties = append(ties, d)
		}
	}
	best := pickRandomTie(ties)
	if best != nil {
		lb.getOrCreate(best.ID).addReservation(now, leastBusyReservationTTL)
	}
	return best
}

func (lb *LoadBalancer) selectLowestLatency(candidates []*domain.Deployment) *domain.Deployment {
	lb.mu.RLock()
	defer lb.mu.RUnlock()

	minLatency := math.MaxFloat64
	for _, d := range candidates {
		lat := 250.0 // Default baseline 250ms for unexplored deployments
		if m, ok := lb.metrics[d.ID]; ok {
			lat = effectiveLatencySignal(*m)
		}
		if lat < minLatency {
			minLatency = lat
		}
	}
	threshold := minLatency
	if tol := lb.LatencyTolerancePct(); tol > 0 && minLatency > 0 {
		threshold = minLatency * (1.0 + tol)
	}
	var chosen *domain.Deployment
	eligible := 0
	for _, d := range candidates {
		lat := 250.0
		if m, ok := lb.metrics[d.ID]; ok {
			lat = effectiveLatencySignal(*m)
		}
		if lat <= threshold {
			if eligible == 0 || rand.IntN(eligible+1) == 0 {
				chosen = d
			}
			eligible++
		}
	}
	return chosen
}

func (lb *LoadBalancer) selectHighestHeadroom(candidates []*domain.Deployment) *domain.Deployment {
	lb.mu.RLock()
	defer lb.mu.RUnlock()

	var ties []*domain.Deployment
	maxHeadroom := -math.MaxFloat64
	now := time.Now()
	for _, d := range candidates {
		capTPM := d.TPMCapacity
		if capTPM <= 0 {
			capTPM = 1000000
		}
		usedTPM := 0
		if m, ok := lb.metrics[d.ID]; ok {
			if m.windowStart.IsZero() || now.Sub(m.windowStart) < time.Minute {
				usedTPM = m.usedTPM
			}
		}
		headroom := 1.0 - (float64(usedTPM) / float64(capTPM))
		if headroom > maxHeadroom {
			maxHeadroom = headroom
			ties = ties[:0]
			ties = append(ties, d)
		} else if headroom == maxHeadroom {
			ties = append(ties, d)
		}
	}
	best := pickRandomTie(ties)
	if best == nil && len(candidates) > 0 {
		best = candidates[0]
	}
	return best
}

func (lb *LoadBalancer) selectLowestCost(candidates []*domain.Deployment) *domain.Deployment {
	var ties []*domain.Deployment
	minCost := int64(math.MaxInt64)
	for _, d := range candidates {
		var cost int64 = 10000000
		if d.GlobalModel != nil {
			cost = d.GlobalModel.InputCostMicrosPer1M + d.GlobalModel.OutputCostMicrosPer1M
		}
		if cost < minCost {
			minCost = cost
			ties = ties[:0]
			ties = append(ties, d)
		} else if cost == minCost {
			ties = append(ties, d)
		}
	}
	return pickRandomTie(ties)
}

// OnRequestStart increments in-flight counters for a deployment.
func (lb *LoadBalancer) OnRequestStart(depID string) {
	lb.OnRequestStartWithTokens(depID, 0, 0)
}

// OnRequestStartWithTokens increments in-flight/RPM counters and pre-reserves
// estimated input/output tokens so concurrent bursts do not overshoot TPM/ITPM/OTPM caps.
func (lb *LoadBalancer) OnRequestStartWithTokens(depID string, estInput, estOutput int) {
	if estInput < 0 {
		estInput = 0
	}
	if estOutput < 0 {
		estOutput = 0
	}
	estTotal := estInput + estOutput
	now := time.Now()
	lb.mu.Lock()
	m := lb.getOrCreate(depID)
	m.checkWindow(now)
	m.consumeReservation(now)
	m.inFlight++
	m.usedRPM++
	m.usedTPM += estTotal
	m.usedITPM += estInput
	m.usedOTPM += estOutput
	lb.mu.Unlock()
	if lb.redis != nil && lb.redis.Client() != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		if _, err := lb.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
			return startRoutingSignalScript.Run(ctx, rdb, []string{routingSignalKey(depID)}, now.Unix(), routingSignalTTLSeconds, estInput, estOutput).Result()
		}); err != nil {
			lb.setSharedDegraded(true, "signal_update")
		}
	}
}

// OnRequestEnd decrements in-flight counters and updates EWMA total latency and token usage.
func (lb *LoadBalancer) OnRequestEnd(depID string, latencyMs int64, totalTokens int) {
	lb.recordRequestEndWithUsage(depID, latencyMs, 0, 0, 0, totalTokens, 0, false)
}

// OnStreamRequestEnd decrements in-flight counters and updates EWMA total latency, TTFT, and token usage.
func (lb *LoadBalancer) OnStreamRequestEnd(depID string, latencyMs, ttftMs int64, totalTokens int) {
	lb.recordRequestEndWithUsage(depID, latencyMs, ttftMs, 0, 0, totalTokens, 0, false)
}

// OnRequestEndWithUsage reconciles pre-reserved tokens against actual input/output usage and
// records token-normalized latency (ms per 100 output tokens for non-TTFT calls with completion tokens).
func (lb *LoadBalancer) OnRequestEndWithUsage(depID string, latencyMs, ttftMs int64, estInput, estOutput, actualInput, actualOutput int) {
	lb.recordRequestEndWithUsage(depID, latencyMs, ttftMs, estInput, estOutput, actualInput, actualOutput, true)
}

// OnRequestFailure decrements in-flight counters, refunds pre-reserved tokens, and penalizes EWMA latency.
func (lb *LoadBalancer) OnRequestFailure(depID string, latencyMs int64, isTimeout bool, estInput, estOutput int) {
	if estInput < 0 {
		estInput = 0
	}
	if estOutput < 0 {
		estOutput = 0
	}
	penalty := float64(latencyMs)
	if isTimeout {
		if penalty < 5000 {
			penalty = 5000
		} else {
			penalty *= 1.5
		}
	} else if penalty < 1000 {
		penalty = 1000
	}

	deltaIn := -estInput
	deltaOut := -estOutput
	deltaTotal := deltaIn + deltaOut

	now := time.Now()
	lb.mu.Lock()
	m := lb.getOrCreate(depID)
	sameWindow := !m.windowStart.IsZero() && now.Sub(m.windowStart) < time.Minute
	m.checkWindow(now)
	if m.inFlight > 0 {
		m.inFlight--
	}
	if sameWindow {
		m.usedTPM = max(0, m.usedTPM+deltaTotal)
		m.usedITPM = max(0, m.usedITPM+deltaIn)
		m.usedOTPM = max(0, m.usedOTPM+deltaOut)
	}
	const alpha = 0.3
	if m.ewmaLatencyMs == 0 {
		m.ewmaLatencyMs = penalty
	} else {
		m.ewmaLatencyMs = alpha*penalty + (1-alpha)*m.ewmaLatencyMs
	}
	if isTimeout && m.ewmaTTFTMs > 0 {
		m.ewmaTTFTMs = alpha*penalty + (1-alpha)*m.ewmaTTFTMs
	}
	lb.mu.Unlock()

	if lb.redis != nil && lb.redis.Client() != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		ttftArg := 0
		if isTimeout {
			ttftArg = -1
		}
		if _, err := lb.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
			return endRoutingSignalScript.Run(ctx, rdb, []string{routingSignalKey(depID)}, now.Unix(), deltaTotal, penalty, ttftArg, routingSignalTTLSeconds, deltaIn, deltaOut).Result()
		}); err != nil {
			lb.setSharedDegraded(true, "signal_update")
		}
	}
}

func (lb *LoadBalancer) recordRequestEndWithUsage(
	depID string,
	latencyMs, ttftMs int64,
	estInput, estOutput, actualInput, actualOutput int,
	normalizeByOutput bool,
) {
	if estInput < 0 {
		estInput = 0
	}
	if estOutput < 0 {
		estOutput = 0
	}
	if actualInput < 0 {
		actualInput = 0
	}
	if actualOutput < 0 {
		actualOutput = 0
	}
	deltaIn := actualInput - estInput
	deltaOut := actualOutput - estOutput
	deltaTotal := deltaIn + deltaOut

	latMetric := float64(latencyMs)
	if normalizeByOutput && ttftMs <= 0 && latencyMs > 0 && actualOutput > 0 {
		latMetric = (float64(latencyMs) * 100.0) / float64(actualOutput)
	}

	now := time.Now()
	lb.mu.Lock()
	m := lb.getOrCreate(depID)
	sameWindow := !m.windowStart.IsZero() && now.Sub(m.windowStart) < time.Minute
	m.checkWindow(now)
	if m.inFlight > 0 {
		m.inFlight--
	}
	if sameWindow || deltaTotal > 0 {
		m.usedTPM = max(0, m.usedTPM+deltaTotal)
	}
	if sameWindow || deltaIn > 0 {
		m.usedITPM = max(0, m.usedITPM+deltaIn)
	}
	if sameWindow || deltaOut > 0 {
		m.usedOTPM = max(0, m.usedOTPM+deltaOut)
	}
	const alpha = 0.3
	if latMetric > 0 {
		if m.ewmaLatencyMs == 0 {
			m.ewmaLatencyMs = latMetric
		} else {
			m.ewmaLatencyMs = alpha*latMetric + (1-alpha)*m.ewmaLatencyMs
		}
	}
	if ttftMs > 0 {
		if m.ewmaTTFTMs == 0 {
			m.ewmaTTFTMs = float64(ttftMs)
		} else {
			m.ewmaTTFTMs = alpha*float64(ttftMs) + (1-alpha)*m.ewmaTTFTMs
		}
	}
	lb.mu.Unlock()
	if lb.redis != nil && lb.redis.Client() != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		if _, err := lb.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
			return endRoutingSignalScript.Run(ctx, rdb, []string{routingSignalKey(depID)}, now.Unix(), deltaTotal, latMetric, ttftMs, routingSignalTTLSeconds, deltaIn, deltaOut).Result()
		}); err != nil {
			lb.setSharedDegraded(true, "signal_update")
		}
	}
}

func (lb *LoadBalancer) getOrCreate(depID string) *deploymentTelemetry {
	m, ok := lb.metrics[depID]
	if !ok {
		m = &deploymentTelemetry{}
		lb.metrics[depID] = m
	}
	return m
}

// DeploymentWindowUsage returns the current 1-minute window (usedRPM, usedTPM)
// for depID from shared Redis routing signals or local telemetry.
func (lb *LoadBalancer) DeploymentWindowUsage(depID string, now time.Time) (usedRPM, usedTPM int) {
	if lb == nil || depID == "" {
		return 0, 0
	}
	var signals map[string]deploymentTelemetry
	if lb.redis != nil && lb.redis.Client() != nil {
		shared, err := lb.readSharedSignals([]*domain.Deployment{{ID: depID}})
		if err != nil {
			lb.setSharedDegraded(true, "capacity_read")
		} else {
			lb.setSharedDegraded(false, "capacity_read")
			signals = shared
		}
	}
	if signals == nil {
		lb.mu.RLock()
		defer lb.mu.RUnlock()
	}
	return deploymentWindowUsage(lb, signals, depID, now)
}

// AggregateWindowUsage sums current 1-minute (usedRPM, usedTPM) and configured
// (capRPM, capTPM) across candidates.
func (lb *LoadBalancer) AggregateWindowUsage(candidates []*domain.Deployment, now time.Time) (usedRPM, usedTPM, capRPM, capTPM int) {
	return lb.AggregateWindowUsageWithSignals(candidates, nil, now)
}

// AggregateWindowUsageWithSignals sums current 1-minute (usedRPM, usedTPM) and configured
// (capRPM, capTPM) across candidates, reusing snap when non-nil to avoid redundant Redis reads.
func (lb *LoadBalancer) AggregateWindowUsageWithSignals(candidates []*domain.Deployment, snap *SignalSnapshot, now time.Time) (usedRPM, usedTPM, capRPM, capTPM int) {
	if len(candidates) == 0 {
		return 0, 0, 0, 0
	}
	var signals map[string]deploymentTelemetry
	if snap != nil && snap.signals != nil {
		signals = snap.signals
	} else if lb != nil && lb.redis != nil && lb.redis.Client() != nil {
		shared, err := lb.readSharedSignals(candidates)
		if err != nil {
			lb.setSharedDegraded(true, "capacity_read")
		} else {
			lb.setSharedDegraded(false, "capacity_read")
			signals = shared
		}
	}
	if lb != nil && signals == nil {
		lb.mu.RLock()
		defer lb.mu.RUnlock()
	}
	for _, d := range candidates {
		if d == nil {
			continue
		}
		if d.RPMCapacity > 0 {
			capRPM += d.RPMCapacity
		}
		if d.TPMCapacity > 0 {
			capTPM += d.TPMCapacity
		}
		if lb != nil {
			uRPM, uTPM := deploymentWindowUsage(lb, signals, d.ID, now)
			usedRPM += uRPM
			usedTPM += uTPM
		}
	}
	return usedRPM, usedTPM, capRPM, capTPM
}
