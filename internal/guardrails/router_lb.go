package guardrails

import (
	"context"
	"errors"
	"fmt"
	"math"
	"math/rand/v2"
	"sort"
	"sync"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/sony/gobreaker/v2"
)

const (
	defaultGuardrailFailureThreshold    uint32 = 3
	defaultGuardrailCooldown                   = 30 * time.Second
	defaultGuardrailHalfOpenMaxRequests uint32 = 1
)

var errParentCanceled = errors.New("guardrail parent context canceled")

// LBConfig configures weighted load balancing and circuit-breaker cooldowns
// across guardrail instances sharing the same Name.
type LBConfig struct {
	FailureThreshold    uint32
	Cooldown            time.Duration
	HalfOpenMaxRequests uint32
	Interval            time.Duration
	OnStateChange       func(name string, from, to gobreaker.State)
	RandFloat64         func() float64
}

// RouterLB distributes guardrail evaluations across active GuardrailDefinition candidates
// sharing a Name using weighted shuffle and gobreaker/v2 cooldown circuit breakers.
type RouterLB struct {
	cfg      LBConfig
	mu       sync.RWMutex
	breakers map[string]*gobreaker.CircuitBreaker[*domain.GuardrailEvalResult]
}

// NewRouterLB constructs a RouterLB with sensible production defaults.
func NewRouterLB(cfg LBConfig) *RouterLB {
	if cfg.FailureThreshold == 0 {
		cfg.FailureThreshold = defaultGuardrailFailureThreshold
	}
	if cfg.Cooldown <= 0 {
		cfg.Cooldown = defaultGuardrailCooldown
	}
	if cfg.HalfOpenMaxRequests == 0 {
		cfg.HalfOpenMaxRequests = defaultGuardrailHalfOpenMaxRequests
	}
	if cfg.RandFloat64 == nil {
		cfg.RandFloat64 = rand.Float64
	}
	return &RouterLB{
		cfg:      cfg,
		breakers: make(map[string]*gobreaker.CircuitBreaker[*domain.GuardrailEvalResult]),
	}
}

// WeightedShuffle returns candidates ordered probabilistically by Weight using
// Efraimidis-Spirakis weighted random sampling without replacement.
func (lb *RouterLB) WeightedShuffle(candidates []*ResolvedCandidate) []*ResolvedCandidate {
	if len(candidates) <= 1 {
		out := make([]*ResolvedCandidate, len(candidates))
		copy(out, candidates)
		return out
	}

	randFn := rand.Float64
	if lb != nil && lb.cfg.RandFloat64 != nil {
		randFn = lb.cfg.RandFloat64
	}

	type scored struct {
		cand  *ResolvedCandidate
		score float64
		idx   int
	}
	items := make([]scored, len(candidates))
	for i, c := range candidates {
		w := 1
		if c != nil && c.Weight > 0 {
			w = c.Weight
		}
		u := randFn()
		if u <= 0 {
			u = 1e-12
		} else if u >= 1 {
			u = 1 - 1e-12
		}
		items[i] = scored{
			cand:  c,
			score: -math.Log(u) / float64(w),
			idx:   i,
		}
	}

	sort.Slice(items, func(i, j int) bool {
		if items[i].score != items[j].score {
			return items[i].score < items[j].score
		}
		return items[i].idx < items[j].idx
	})

	out := make([]*ResolvedCandidate, len(items))
	for i := range items {
		out[i] = items[i].cand
	}
	return out
}

// Execute runs evalFn across the candidates of rg in weighted-shuffled order, skipping or
// failing over past candidates whose gobreaker circuit breaker is open or that return errors.
// When all candidates fail, Execute honors the group's FailOpen policy.
func (lb *RouterLB) Execute(
	ctx context.Context,
	rg ResolvedGuardrail,
	evalFn func(ctx context.Context, cand *ResolvedCandidate) (*domain.GuardrailEvalResult, error),
) (*domain.GuardrailEvalResult, *ResolvedCandidate, error) {
	if len(rg.Candidates) == 0 {
		return &domain.GuardrailEvalResult{Decision: domain.GuardrailDecisionAllow}, nil, nil
	}

	ordered := lb.WeightedShuffle(rg.Candidates)
	var lastErr error
	var lastCand *ResolvedCandidate

	for _, cand := range ordered {
		if cand == nil || cand.Definition == nil {
			continue
		}
		if err := ctx.Err(); err != nil {
			return nil, cand, err
		}
		lastCand = cand

		cb := lb.breakerFor(cand.Definition)
		res, err := cb.Execute(func() (*domain.GuardrailEvalResult, error) {
			out, evalErr := evalFn(ctx, cand)
			if evalErr != nil {
				if ctx.Err() != nil {
					return nil, fmt.Errorf("%w: %v", errParentCanceled, evalErr)
				}
				return nil, evalErr
			}
			return out, nil
		})
		if err == nil {
			if res == nil {
				res = &domain.GuardrailEvalResult{Decision: domain.GuardrailDecisionAllow}
			}
			return res, cand, nil
		}
		if errors.Is(err, errParentCanceled) {
			return nil, cand, ctx.Err()
		}
		lastErr = err
	}

	failOpen := rg.FailOpen
	if lastCand != nil {
		failOpen = lastCand.FailOpen
	}
	if failOpen && lastErr != nil {
		return &domain.GuardrailEvalResult{
			Decision:          domain.GuardrailDecisionAllow,
			AppliedGuardrails: []string{rg.Name},
			ErrorMessage:      lastErr.Error(),
		}, lastCand, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no healthy guardrail candidates available for %q", rg.Name)
	}
	return nil, lastCand, lastErr
}

// State returns the current gobreaker.State for a guardrail definition ID.
func (lb *RouterLB) State(definitionID string) gobreaker.State {
	if lb == nil || definitionID == "" {
		return gobreaker.StateClosed
	}
	lb.mu.RLock()
	cb, ok := lb.breakers[definitionID]
	lb.mu.RUnlock()
	if !ok {
		return gobreaker.StateClosed
	}
	return cb.State()
}

// Reset clears the circuit breaker for definitionID so a fresh breaker is created on next use.
func (lb *RouterLB) Reset(definitionID string) {
	if lb == nil || definitionID == "" {
		return
	}
	lb.mu.Lock()
	delete(lb.breakers, definitionID)
	lb.mu.Unlock()
}

func (lb *RouterLB) breakerFor(def *domain.GuardrailDefinition) *gobreaker.CircuitBreaker[*domain.GuardrailEvalResult] {
	key := def.ID
	if key == "" {
		key = def.OrgID + ":" + def.Name
	}

	lb.mu.RLock()
	cb, ok := lb.breakers[key]
	lb.mu.RUnlock()
	if ok {
		return cb
	}

	lb.mu.Lock()
	defer lb.mu.Unlock()
	if cb, ok = lb.breakers[key]; ok {
		return cb
	}

	threshold := lb.cfg.FailureThreshold
	cb = gobreaker.NewCircuitBreaker[*domain.GuardrailEvalResult](gobreaker.Settings{
		Name:        key,
		MaxRequests: lb.cfg.HalfOpenMaxRequests,
		Interval:    lb.cfg.Interval,
		Timeout:     lb.cfg.Cooldown,
		ReadyToTrip: func(counts gobreaker.Counts) bool {
			return counts.ConsecutiveFailures >= threshold
		},
		IsExcluded: func(err error) bool {
			return errors.Is(err, errParentCanceled)
		},
		OnStateChange: lb.cfg.OnStateChange,
	})
	lb.breakers[key] = cb
	return cb
}
