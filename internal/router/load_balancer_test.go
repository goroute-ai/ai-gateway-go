package router

import (
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
