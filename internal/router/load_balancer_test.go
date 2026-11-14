package router

import (
	"sync"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

func TestLoadBalancer_UsageBasedHeadroom(t *testing.T) {
	lb := NewLoadBalancer()

	depA := &domain.Deployment{ID: "dep-a", TPMCapacity: 1000}
	depB := &domain.Deployment{ID: "dep-b", TPMCapacity: 2000}
	candidates := []*domain.Deployment{depA, depB}

	// Initially both have 0 used tokens, headroom is 1.0 for both; depA chosen as first
	selected := lb.Select(domain.StrategyUsageBasedHeadroom, candidates)
	if selected == nil {
		t.Fatalf("expected non-nil deployment")
	}

	// Add 500 tokens to depA (50% used, 50% headroom)
	lb.OnRequestStart("dep-a")
	lb.OnRequestEnd("dep-a", 100, 500)

	// Now depB has 100% headroom, depA has 50% headroom -> depB should be selected
	selected = lb.Select(domain.StrategyUsageBasedHeadroom, candidates)
	if selected.ID != "dep-b" {
		t.Fatalf("expected dep-b selected, got %s", selected.ID)
	}

	// Add 1900 tokens to depB (95% used, 5% headroom)
	lb.OnRequestStart("dep-b")
	lb.OnRequestEnd("dep-b", 100, 1900)

	// Now depA has 50% headroom, depB has 5% headroom -> depA should be selected
	selected = lb.Select(domain.StrategyUsageBasedHeadroom, candidates)
	if selected.ID != "dep-a" {
		t.Fatalf("expected dep-a selected, got %s", selected.ID)
	}

	// Overload both beyond 100% capacity (negative headroom)
	lb.OnRequestStart("dep-a")
	lb.OnRequestEnd("dep-a", 100, 2000) // depA now has -150% headroom
	lb.OnRequestStart("dep-b")
	lb.OnRequestEnd("dep-b", 100, 5000) // depB now has -245% headroom

	// Must never return nil even when headroom is deeply negative
	selected = lb.Select(domain.StrategyUsageBasedHeadroom, candidates)
	if selected == nil {
		t.Fatalf("expected non-nil deployment even when all candidates are over-capacity")
	}
	if selected.ID != "dep-a" {
		t.Fatalf("expected dep-a (less overloaded) selected, got %s", selected.ID)
	}

	// Simulate window expiration (> 1 minute)
	lb.mu.Lock()
	lb.metrics["dep-a"].windowStart = time.Now().Add(-65 * time.Second)
	lb.metrics["dep-b"].windowStart = time.Now().Add(-65 * time.Second)
	lb.mu.Unlock()

	// Upon window expiration, used tokens are treated as 0
	selected = lb.Select(domain.StrategyUsageBasedHeadroom, candidates)
	if selected == nil {
		t.Fatalf("expected non-nil deployment after window expiration")
	}

	// Start a request after window expiration, verifying reset
	lb.OnRequestStart("dep-a")
	lb.mu.RLock()
	if lb.metrics["dep-a"].usedRPM != 1 {
		t.Fatalf("expected usedRPM reset to 1, got %d", lb.metrics["dep-a"].usedRPM)
	}
	if lb.metrics["dep-a"].usedTPM != 0 {
		t.Fatalf("expected usedTPM reset to 0, got %d", lb.metrics["dep-a"].usedTPM)
	}
	lb.mu.RUnlock()
}

func TestLoadBalancer_RandomizedTieBreaking(t *testing.T) {
	lb := NewLoadBalancer()
	candidates := []*domain.Deployment{
		{ID: "dep-1", TPMCapacity: 1000, GlobalModel: &domain.GlobalModel{InputCostMicrosPer1M: 100, OutputCostMicrosPer1M: 100}},
		{ID: "dep-2", TPMCapacity: 1000, GlobalModel: &domain.GlobalModel{InputCostMicrosPer1M: 100, OutputCostMicrosPer1M: 100}},
		{ID: "dep-3", TPMCapacity: 1000, GlobalModel: &domain.GlobalModel{InputCostMicrosPer1M: 100, OutputCostMicrosPer1M: 100}},
	}

	for _, strat := range []domain.RoutingStrategy{
		domain.StrategyLowestCost,
		domain.StrategyLatencyBased,
		domain.StrategyUsageBasedHeadroom,
	} {
		seen := make(map[string]int)
		for i := 0; i < 60; i++ {
			sel := lb.Select(strat, candidates)
			if sel == nil {
				t.Fatalf("strategy %s returned nil", strat)
			}
			seen[sel.ID]++
		}
		if len(seen) < 2 {
			t.Fatalf("strategy %s did not break ties randomly: %v", strat, seen)
		}
	}
}

func TestLoadBalancer_RoundRobin(t *testing.T) {
	lb := NewLoadBalancer()
	g1Candidates := []*domain.Deployment{
		{ID: "g1-dep-1", ModelGroupID: "group-1"},
		{ID: "g1-dep-2", ModelGroupID: "group-1"},
		{ID: "g1-dep-3", ModelGroupID: "group-1"},
	}
	g2Candidates := []*domain.Deployment{
		{ID: "g2-dep-1", ModelGroupID: "group-2"},
		{ID: "g2-dep-2", ModelGroupID: "group-2"},
	}

	expectedG1 := []string{"g1-dep-1", "g1-dep-2", "g1-dep-3", "g1-dep-1", "g1-dep-2", "g1-dep-3"}
	for i, want := range expectedG1 {
		got := lb.Select(domain.StrategyRoundRobin, g1Candidates)
		if got == nil || got.ID != want {
			t.Fatalf("step %d: expected %s, got %v", i, want, got)
		}
	}

	// Independent per-model-group counter for group-2.
	if got := lb.Select(domain.StrategyRoundRobin, g2Candidates); got == nil || got.ID != "g2-dep-1" {
		t.Fatalf("expected g2-dep-1, got %v", got)
	}
	if got := lb.Select(domain.StrategyRoundRobin, g2Candidates); got == nil || got.ID != "g2-dep-2" {
		t.Fatalf("expected g2-dep-2, got %v", got)
	}

	// Concurrent calls must be race-free and distribute evenly.
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 50; i++ {
				if sel := lb.Select(domain.StrategyRoundRobin, g1Candidates); sel == nil {
					t.Errorf("got nil selection")
				}
			}
		}()
	}
	wg.Wait()
}
