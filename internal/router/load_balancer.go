package router

import (
	"math"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

type deploymentTelemetry struct {
	inFlight    int
	ewmaTTFTMs  float64
	usedRPM     int
	usedTPM     int
	windowStart time.Time
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
	mu      sync.RWMutex
	metrics map[string]*deploymentTelemetry
}

func NewLoadBalancer() *LoadBalancer {
	return &LoadBalancer{
		metrics: make(map[string]*deploymentTelemetry),
	}
}

// Select chooses one deployment from the candidate list of healthy deployments according to strategy.
func (lb *LoadBalancer) Select(strategy domain.RoutingStrategy, candidates []*domain.Deployment) *domain.Deployment {
	if len(candidates) == 0 {
		return nil
	}
	if len(candidates) == 1 {
		return candidates[0]
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
	default: // StrategyWeightedShuffle
		return lb.selectWeightedRandom(candidates)
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

func (lb *LoadBalancer) selectLeastBusy(candidates []*domain.Deployment) *domain.Deployment {
	lb.mu.RLock()
	defer lb.mu.RUnlock()

	var best *domain.Deployment
	minInFlight := math.MaxInt
	for _, d := range candidates {
		inFlight := 0
		if m, ok := lb.metrics[d.ID]; ok {
			inFlight = m.inFlight
		}
		if inFlight < minInFlight {
			minInFlight = inFlight
			best = d
		}
	}
	return best
}

func (lb *LoadBalancer) selectLowestLatency(candidates []*domain.Deployment) *domain.Deployment {
	lb.mu.RLock()
	defer lb.mu.RUnlock()

	var best *domain.Deployment
	minLatency := math.MaxFloat64
	for _, d := range candidates {
		lat := 250.0 // Default baseline 250ms for unexplored deployments
		if m, ok := lb.metrics[d.ID]; ok && m.ewmaTTFTMs > 0 {
			lat = m.ewmaTTFTMs
		}
		if lat < minLatency {
			minLatency = lat
			best = d
		}
	}
	return best
}

func (lb *LoadBalancer) selectHighestHeadroom(candidates []*domain.Deployment) *domain.Deployment {
	lb.mu.RLock()
	defer lb.mu.RUnlock()

	var best *domain.Deployment
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
			best = d
		}
	}
	if best == nil && len(candidates) > 0 {
		best = candidates[0]
	}
	return best
}

func (lb *LoadBalancer) selectLowestCost(candidates []*domain.Deployment) *domain.Deployment {
	var best *domain.Deployment
	minCost := int64(math.MaxInt64)
	for _, d := range candidates {
		var cost int64 = 10000000
		if d.GlobalModel != nil {
			cost = d.GlobalModel.InputCostMicrosPer1M + d.GlobalModel.OutputCostMicrosPer1M
		}
		if cost < minCost {
			minCost = cost
			best = d
		}
	}
	return best
}

// OnRequestStart increments in-flight counters for a deployment.
func (lb *LoadBalancer) OnRequestStart(depID string) {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	m := lb.getOrCreate(depID)
	m.checkWindow(time.Now())
	m.inFlight++
	m.usedRPM++
}

// OnRequestEnd decrements in-flight counters and updates EWMA latency and token usage.
func (lb *LoadBalancer) OnRequestEnd(depID string, latencyMs int64, totalTokens int) {
	lb.mu.Lock()
	defer lb.mu.Unlock()
	m := lb.getOrCreate(depID)
	m.checkWindow(time.Now())
	if m.inFlight > 0 {
		m.inFlight--
	}
	m.usedTPM += totalTokens
	if latencyMs > 0 {
		const alpha = 0.3
		if m.ewmaTTFTMs == 0 {
			m.ewmaTTFTMs = float64(latencyMs)
		} else {
			m.ewmaTTFTMs = alpha*float64(latencyMs) + (1-alpha)*m.ewmaTTFTMs
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
