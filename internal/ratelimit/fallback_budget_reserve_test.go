package ratelimit

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

func TestCheckBudgetReserve_ExcludesOwnPrimaryReservationAndEnforcesFailClosed(t *testing.T) {
	ctx := context.Background()
	mr := miniredis.RunT(t)
	rf := storage.NewRedisFabric(mr.Addr(), "", 0)
	defer func() { _ = rf.Client().Close() }()

	lim := NewLimiter(rf, 60, 300)
	lim.SetFallbackToLocalOnOutage(false)
	id := &domain.IdentityContext{
		OrgID:               "org-fb-budget",
		VirtualKeyID:        "vk-fb-1",
		KeyMaxBudgetMicros:  1000,
		TeamID:              "team-fb-1",
		TeamMaxBudgetMicros: 2000,
	}

	// Acquire primary reservation of 400 micros under req-1.
	rel, err := lim.AcquireWithBudget(ctx, id, 10, 400, "req-1")
	if err != nil {
		t.Fatalf("AcquireWithBudget: %v", err)
	}
	defer rel(-1, -1)

	// Re-probing fallback costing 900 micros under the same req-1 replaces req-1's 400 micros -> 900 <= 1000 allowed!
	if err := lim.CheckBudgetReserve(ctx, id, 900, "req-1"); err != nil {
		t.Fatalf("expected 900 micros replacement for req-1 to fit within 1000 budget, got: %v", err)
	}

	// Fallback costing 1050 micros exceeds KeyMaxBudgetMicros 1000 -> rejected!
	if err := lim.CheckBudgetReserve(ctx, id, 1050, "req-1"); err == nil {
		t.Fatal("expected fallback exceeding 1000 budget to be rejected")
	} else if ge, ok := err.(*domain.GatewayError); !ok || ge.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429 budget error, got %T: %v", err, err)
	}

	// Fail closed if Redis is down and FallbackLocal == false.
	mr.Close()
	if err := lim.CheckBudgetReserve(ctx, id, 500, "req-1"); err == nil {
		t.Fatal("expected fail-closed error when Redis unavailable and FallbackLocal=false")
	} else if ge, ok := err.(*domain.GatewayError); !ok || ge.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 rate_limiter_unavailable, got %T: %v", err, err)
	}
}

func TestCheckDescriptorBudgetReserve_ExcludesOwnReservationAndFailsClosed(t *testing.T) {
	ctx := context.Background()
	mr := miniredis.RunT(t)
	rf := storage.NewRedisFabric(mr.Addr(), "", 0)
	defer func() { _ = rf.Client().Close() }()

	lim := NewLimiter(rf, 60, 300)
	lim.SetFallbackToLocalOnOutage(false)
	descs := []domain.RateLimitDescriptor{
		{
			ScopeType:       domain.QuotaScopeProject,
			ScopeID:         "proj-1",
			MaxBudgetMicros: 1000,
			WindowTTLSec:    3600,
		},
	}

	rel, _, err := lim.AcquireDescriptorsWithMeta(ctx, "org-desc", "req-desc-1", 10, 0, 300, descs)
	if err != nil {
		t.Fatalf("AcquireDescriptorsWithMeta: %v", err)
	}
	defer rel(-1, -1, -1)

	// Adding another independent request takes 400 -> total other reservation = 400.
	rel2, _, err := lim.AcquireDescriptorsWithMeta(ctx, "org-desc", "req-desc-2", 10, 0, 400, descs)
	if err != nil {
		t.Fatalf("AcquireDescriptorsWithMeta req-2: %v", err)
	}
	defer rel2(-1, -1, -1)

	// Probing for req-desc-1 replaces req-desc-1's 300 while keeping req-desc-2's 400 -> max additional is 600.
	if err := lim.CheckDescriptorBudgetReserve(ctx, "org-desc", descs, 550, "req-desc-1"); err != nil {
		t.Fatalf("expected 400 + 550 <= 1000 to fit, got: %v", err)
	}
	if err := lim.CheckDescriptorBudgetReserve(ctx, "org-desc", descs, 650, "req-desc-1"); err == nil {
		t.Fatal("expected 400 + 650 > 1000 to be rejected")
	}

	// Verify nil-Redis fail-closed mode too.
	noRedisFailClosed := NewLimiter(nil, 60, 300)
	noRedisFailClosed.SetFallbackToLocalOnOutage(false)
	if err := noRedisFailClosed.CheckDescriptorBudgetReserve(ctx, "org-desc", descs, 100, "r1"); err == nil {
		t.Fatal("expected 503 when Redis is nil and FallbackLocal=false")
	}

	// Local fallback mode tracks exclusions accurately.
	localLim := NewLimiter(nil, 60, 300)
	localLim.SetFallbackToLocalOnOutage(true)
	localLim.SetNowFunc(func() time.Time { return time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC) })
	relL, _, err := localLim.AcquireDescriptorsWithMeta(ctx, "org-desc", "loc-1", 10, 0, 600, descs)
	if err != nil {
		t.Fatalf("local AcquireDescriptorsWithMeta: %v", err)
	}
	defer relL(-1, -1, -1)
	if err := localLim.CheckDescriptorBudgetReserve(ctx, "org-desc", descs, 900, "loc-1"); err != nil {
		t.Fatalf("expected local replacement 900 <= 1000 to succeed, got: %v", err)
	}
	if err := localLim.CheckDescriptorBudgetReserve(ctx, "org-desc", descs, 1050, "loc-1"); err == nil {
		t.Fatal("expected local 1050 > 1000 to fail")
	}
}
