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
		m.windowStart = now
	}
}

// LoadBalancer implements Stage 2 of the Two-Stage Routing Engine:
// selecting the optimal healthy Deployment inside a ModelGroup using one of 5 production strategies:
// 1. weighted-shuffle
// 2. least-busy
// 3. latency-based (EWMA TTFT)
// 4. usage-based-headroom
// 5. lowest-cost
type LoadBalancer struct {
	mu             sync.RWMutex
	metrics        map[string]*deploymentTelemetry
	rrCounters     sync.Map // map[string]*atomic.Uint64 keyed by ModelGroupID
	redis          *storage.RedisFabric
	sharedDegraded atomic.Bool
	sharedChecked  atomic.Bool
}

func NewLoadBalancer(redisFabric ...*storage.RedisFabric) *LoadBalancer {
	lb := &LoadBalancer{
		metrics: make(map[string]*deploymentTelemetry),
	}
	if len(redisFabric) > 0 {
		lb.redis = redisFabric[0]
	}
	return lb
}

// Select chooses one deployment from the candidate list of healthy deployments according to strategy.
func (lb *LoadBalancer) Select(strategy domain.RoutingStrategy, candidates []*domain.Deployment) *domain.Deployment {
	if len(candidates) == 0 {
		return nil
	}
	if len(candidates) == 1 {
		return candidates[0]
	}
	if lb.redis != nil && isAdaptiveStrategy(strategy) {
		shared, err := lb.readSharedSignals(candidates)
		if err != nil {
			lb.setSharedDegraded(true, string(strategy))
		} else {
			lb.setSharedDegraded(false, string(strategy))
			return lb.selectUsingSignals(strategy, candidates, shared)
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
		var ties []*domain.Deployment
		minLatency := math.MaxFloat64
		for _, d := range candidates {
			lat := effectiveLatencySignal(signals[d.ID])
			if lat < minLatency {
				minLatency = lat
				ties = ties[:0]
				ties = append(ties, d)
			} else if lat == minLatency {
				ties = append(ties, d)
			}
		}
		return pickRandomTie(ties)
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
	totalWeight := 0
	for _, d := range candidates {
		w := d.Weight
		if w <= 0 {
			w = 100
		}
		totalWeight += w
	}
	r := rand.IntN(totalWeight)
	acc := 0
	for _, d := range candidates {
		w := d.Weight
		if w <= 0 {
			w = 100
		}
		acc += w
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

	var ties []*domain.Deployment
	minLatency := math.MaxFloat64
	for _, d := range candidates {
		lat := 250.0 // Default baseline 250ms for unexplored deployments
		if m, ok := lb.metrics[d.ID]; ok {
			lat = effectiveLatencySignal(*m)
		}
		if lat < minLatency {
			minLatency = lat
			ties = ties[:0]
			ties = append(ties, d)
		} else if lat == minLatency {
			ties = append(ties, d)
		}
	}
	return pickRandomTie(ties)
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
	now := time.Now()
	lb.mu.Lock()
	m := lb.getOrCreate(depID)
	m.checkWindow(now)
	m.consumeReservation(now)
	m.inFlight++
	m.usedRPM++
	lb.mu.Unlock()
	if lb.redis != nil && lb.redis.Client() != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()
		if _, err := lb.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
			return startRoutingSignalScript.Run(ctx, rdb, []string{routingSignalKey(depID)}, now.Unix(), routingSignalTTLSeconds).Result()
		}); err != nil {
			lb.setSharedDegraded(true, "signal_update")
		}
	}
}

// OnRequestEnd decrements in-flight counters and updates EWMA total latency and token usage.
func (lb *LoadBalancer) OnRequestEnd(depID string, latencyMs int64, totalTokens int) {
	lb.recordRequestEnd(depID, latencyMs, 0, totalTokens)
}

// OnStreamRequestEnd decrements in-flight counters and updates EWMA total latency, TTFT, and token usage.
func (lb *LoadBalancer) OnStreamRequestEnd(depID string, latencyMs, ttftMs int64, totalTokens int) {
	lb.recordRequestEnd(depID, latencyMs, ttftMs, totalTokens)
}

func (lb *LoadBalancer) recordRequestEnd(depID string, latencyMs, ttftMs int64, totalTokens int) {
	now := time.Now()
	lb.mu.Lock()
	m := lb.getOrCreate(depID)
	m.checkWindow(now)
	if m.inFlight > 0 {
		m.inFlight--
	}
	m.usedTPM += totalTokens
	const alpha = 0.3
	if latencyMs > 0 {
		if m.ewmaLatencyMs == 0 {
			m.ewmaLatencyMs = float64(latencyMs)
		} else {
			m.ewmaLatencyMs = alpha*float64(latencyMs) + (1-alpha)*m.ewmaLatencyMs
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
			return endRoutingSignalScript.Run(ctx, rdb, []string{routingSignalKey(depID)}, now.Unix(), totalTokens, latencyMs, ttftMs, routingSignalTTLSeconds).Result()
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
	if len(candidates) == 0 {
		return 0, 0, 0, 0
	}
	var signals map[string]deploymentTelemetry
	if lb != nil && lb.redis != nil && lb.redis.Client() != nil {
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
