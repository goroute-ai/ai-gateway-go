package ratelimit

import (
	"context"
	"errors"
	"testing"

	"github.com/alicebob/miniredis/v2"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

func TestBudgetBypassRejectedWhenReserveIsZero(t *testing.T) {
	mr := miniredis.RunT(t)
	redisFabric := storage.NewRedisFabric(mr.Addr(), "", 0)
	t.Cleanup(func() { _ = redisFabric.Client().Close() })
	limiter := NewLimiter(redisFabric, 60, 300)
	ctx := context.Background()

	id := &domain.IdentityContext{
		VirtualKeyID:       "vk-bypass",
		OrgID:              "org-bypass",
		KeyMaxBudgetMicros: 1000,
	}

	if _, err := limiter.AcquireWithBudget(ctx, id, 10, 0, "req-zero-1"); err == nil {
		t.Fatal("expected AcquireWithBudget with reserveMicros=0 to be rejected when budget is configured")
	} else {
		var gwErr *domain.GatewayError
		if !errors.As(err, &gwErr) || gwErr.Code != "budget_reservation_unavailable" {
			t.Fatalf("unexpected error for reserve=0: %v", err)
		}
	}

	if _, err := limiter.Acquire(ctx, id, 10); err == nil {
		t.Fatal("expected Acquire without budget reservation to be rejected when budget is configured")
	}
}

func TestPrefixFreeRequestIDAndO1ReservationSum(t *testing.T) {
	mr := miniredis.RunT(t)
	redisFabric := storage.NewRedisFabric(mr.Addr(), "", 0)
	t.Cleanup(func() { _ = redisFabric.Client().Close() })
	limiter := NewLimiter(redisFabric, 60, 300)
	ctx := context.Background()

	id := &domain.IdentityContext{
		VirtualKeyID:       "vk-pfx",
		OrgID:              "org-pfx",
		KeyMaxBudgetMicros: 1000,
	}

	rel1, err := limiter.AcquireWithBudget(ctx, id, 10, 100, "req1")
	if err != nil {
		t.Fatalf("acquire req1: %v", err)
	}
	rel10, err := limiter.AcquireWithBudget(ctx, id, 10, 200, "req10")
	if err != nil {
		t.Fatalf("acquire req10: %v", err)
	}

	sumKey := "gw:budget:{org:org-pfx}:reservations:key:vk-pfx:sum"
	gotSum, err := mr.Get(sumKey)
	if err != nil || gotSum != "300" {
		t.Fatalf("expected reserved_sum=300, got %q err=%v", gotSum, err)
	}

	// Settle only req1; req10 must remain untouched!
	if err := limiter.RecordSpendIncrementForRequest(ctx, "req1", id.VirtualKeyID, "", id.OrgID, 50); err != nil {
		t.Fatalf("record spend req1: %v", err)
	}
	gotSum, err = mr.Get(sumKey)
	if err != nil || gotSum != "200" {
		t.Fatalf("expected reserved_sum=200 after settling req1 (req10 preserved), got %q err=%v", gotSum, err)
	}
	resZSet := "gw:budget:{org:org-pfx}:reservations:key:vk-pfx"
	if _, err := mr.ZScore(resZSet, "req10"); err != nil {
		t.Fatalf("expected req10 to still exist in reservation zset: %v", err)
	}

	// Renew with empty TeamID and UserID must not touch or fail on empty-ID keys.
	if err := limiter.RenewReservationLease(ctx, id, "req10", 7200); err != nil {
		t.Fatalf("RenewReservationLease: %v", err)
	}
	if ttl := mr.TTL(sumKey); ttl <= 3660 {
		t.Fatalf("expected sumKey TTL > 3660s after renewal, got %v", ttl)
	}

	rel1(10, 50)
	rel10(-1, 0) // release req10 without charge
	gotSum, _ = mr.Get(sumKey)
	if gotSum != "0" {
		t.Fatalf("expected reserved_sum=0 after releasing req10, got %q", gotSum)
	}
}

func TestPerUserLimitsAndResetSpendCountersUserScope(t *testing.T) {
	mr := miniredis.RunT(t)
	redisFabric := storage.NewRedisFabric(mr.Addr(), "", 0)
	t.Cleanup(func() { _ = redisFabric.Client().Close() })
	limiter := NewLimiter(redisFabric, 60, 300)
	ctx := context.Background()

	id := &domain.IdentityContext{
		VirtualKeyID:        "vk-u1",
		UserID:              "user-1",
		OrgID:               "org-u",
		UserRPMLimit:        1,
		UserMaxBudgetMicros: 500,
	}

	rel, err := limiter.AcquireWithBudget(ctx, id, 10, 200, "req-u1")
	if err != nil {
		t.Fatalf("first user acquire: %v", err)
	}
	rel(10, -2)

	// Second request in same minute hits USER_RPM_EXCEEDED.
	if _, err := limiter.AcquireWithBudget(ctx, id, 10, 100, "req-u2"); err == nil {
		t.Fatal("expected USER_RPM_EXCEEDED")
	} else {
		var gwErr *domain.GatewayError
		if !errors.As(err, &gwErr) || gwErr.Code != "user_rpm_exceeded" {
			t.Fatalf("expected user_rpm_exceeded, got %v", err)
		}
	}

	// Record user spend and verify ResetSpendCounters supports "user" scope.
	if err := limiter.RecordSpendIncrementForUserEvent(ctx, "ev-u1", "req-u1", id.VirtualKeyID, "", id.UserID, id.OrgID, 250); err != nil {
		t.Fatalf("RecordSpendIncrementForUserEvent: %v", err)
	}
	userSpendKey := "gw:spend:{org:org-u}:user:user-1"
	if v, err := mr.Get(userSpendKey); err != nil || v != "250" {
		t.Fatalf("expected user spend 250, got %q err=%v", v, err)
	}
	if err := limiter.ResetSpendCounters(ctx, []storage.BudgetResetEvent{{
		ID:       "reset-u1",
		Scope:    "user",
		EntityID: id.UserID,
		OrgID:    id.OrgID,
	}}); err != nil {
		t.Fatalf("ResetSpendCounters user scope: %v", err)
	}
	if mr.Exists(userSpendKey) {
		t.Fatalf("expected %q to be deleted after user budget reset", userSpendKey)
	}
}

func TestGlobalLimitsRollbackOrgAcquisitionOnFailure(t *testing.T) {
	mr := miniredis.RunT(t)
	redisFabric := storage.NewRedisFabric(mr.Addr(), "", 0)
	t.Cleanup(func() { _ = redisFabric.Client().Close() })
	limiter := NewLimiter(redisFabric, 60, 300)
	limiter.SetGlobalLimits(1, 0, 0) // allow only 1 global RPM
	ctx := context.Background()

	idA := &domain.IdentityContext{
		VirtualKeyID:       "vk-a",
		OrgID:              "org-a",
		KeyRPMLimit:        10,
		KeyMaxBudgetMicros: 1000,
	}
	idB := &domain.IdentityContext{
		VirtualKeyID:       "vk-b",
		OrgID:              "org-b",
		KeyRPMLimit:        10,
		KeyMaxBudgetMicros: 1000,
	}

	relA, err := limiter.AcquireWithBudget(ctx, idA, 10, 100, "req-ga")
	if err != nil {
		t.Fatalf("org-a acquire: %v", err)
	}
	defer relA(10, 0)

	// org-b passes org-scoped check, then fails global RPM=1 -> must roll back org-b's RPM, conc, and budget reservation!
	if _, err := limiter.AcquireWithBudget(ctx, idB, 10, 150, "req-gb"); err == nil {
		t.Fatal("expected global_rpm_exceeded")
	} else {
		var gwErr *domain.GatewayError
		if !errors.As(err, &gwErr) || gwErr.Code != "global_rpm_exceeded" {
			t.Fatalf("expected global_rpm_exceeded, got %v", err)
		}
	}

	if v, _ := mr.Get("gw:budget:{org:org-b}:reservations:key:vk-b:sum"); v != "" && v != "0" {
		t.Fatalf("expected org-b reservation sum rolled back to 0, got %q", v)
	}
	if v, _ := mr.Get("gw:rl:{org:org-b}:conc:vk-b"); v != "" && v != "0" {
		t.Fatalf("expected org-b conc rolled back to 0, got %q", v)
	}
}

func TestRecordSpendIncrementsBatchPipelining(t *testing.T) {
	mr := miniredis.RunT(t)
	redisFabric := storage.NewRedisFabric(mr.Addr(), "", 0)
	t.Cleanup(func() { _ = redisFabric.Client().Close() })
	limiter := NewLimiter(redisFabric, 60, 300)
	ctx := context.Background()

	errs := limiter.RecordSpendIncrementsBatch(ctx, []SpendIncrementEvent{
		{EventID: "ev-b1", RequestID: "req-b1", VirtualKeyID: "vk-b1", OrgID: "org-b1", UserID: "u-b1", CostMicros: 120},
		{EventID: "ev-b2", RequestID: "req-b2", VirtualKeyID: "vk-b1", OrgID: "org-b1", UserID: "u-b1", CostMicros: 80},
	})
	for i, err := range errs {
		if err != nil {
			t.Fatalf("batch[%d] err: %v", i, err)
		}
	}
	if v, err := mr.Get("gw:spend:{org:org-b1}:key:vk-b1"); err != nil || v != "200" {
		t.Fatalf("expected key spend 200, got %q err=%v", v, err)
	}
	if v, err := mr.Get("gw:spend:{org:org-b1}:user:u-b1"); err != nil || v != "200" {
		t.Fatalf("expected user spend 200, got %q err=%v", v, err)
	}
}
