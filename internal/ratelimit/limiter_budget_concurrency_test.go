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
	if members, _ := mr.ZMembers("gw:rl:{org:org-b}:zconc:vk-b"); len(members) != 0 {
		t.Fatalf("expected org-b zconc rolled back to 0 members, got %v", members)
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

func TestTeamAndOrgConcurrencyEnforcementReconcileAndRollback(t *testing.T) {
	mr := miniredis.RunT(t)
	redisFabric := storage.NewRedisFabric(mr.Addr(), "", 0)
	t.Cleanup(func() { _ = redisFabric.Client().Close() })
	limiter := NewLimiter(redisFabric, 60, 300)
	ctx := context.Background()

	idTeam := &domain.IdentityContext{
		VirtualKeyID:      "vk-conc-1",
		TeamID:            "team-conc-1",
		OrgID:             "org-conc-1",
		TeamMaxConcurrent: 1,
		OrgMaxConcurrent:  2,
	}

	rel1, err := limiter.Acquire(ctx, idTeam, 10)
	if err != nil {
		t.Fatalf("first team/org conc acquire: %v", err)
	}
	if members, err := mr.ZMembers("gw:rl:{org:org-conc-1}:zconc:team:team-conc-1"); err != nil || len(members) != 1 {
		t.Fatalf("expected zconc:team:team-conc-1 to have 1 slot, got %v err=%v", members, err)
	}
	if members, err := mr.ZMembers("gw:rl:{org:org-conc-1}:zconc:org:org-conc-1"); err != nil || len(members) != 1 {
		t.Fatalf("expected zconc:org:org-conc-1 to have 1 slot, got %v err=%v", members, err)
	}

	// Second concurrent request on the same team hits TEAM_CONCURRENCY_EXCEEDED.
	if _, err := limiter.Acquire(ctx, idTeam, 10); err == nil {
		t.Fatal("expected team_concurrency_exceeded")
	} else {
		var gwErr *domain.GatewayError
		if !errors.As(err, &gwErr) || gwErr.Code != "team_concurrency_exceeded" {
			t.Fatalf("expected team_concurrency_exceeded, got %v", err)
		}
	}

	// Different team in the same org succeeds (org conc 2/2), then 3rd hits ORG_CONCURRENCY_EXCEEDED.
	idTeam2 := &domain.IdentityContext{
		VirtualKeyID:      "vk-conc-2",
		TeamID:            "team-conc-2",
		OrgID:             "org-conc-1",
		TeamMaxConcurrent: 5,
		OrgMaxConcurrent:  2,
	}
	rel2, err := limiter.Acquire(ctx, idTeam2, 10)
	if err != nil {
		t.Fatalf("second org conc acquire: %v", err)
	}
	if _, err := limiter.Acquire(ctx, idTeam2, 10); err == nil {
		t.Fatal("expected org_concurrency_exceeded")
	} else {
		var gwErr *domain.GatewayError
		if !errors.As(err, &gwErr) || gwErr.Code != "org_concurrency_exceeded" {
			t.Fatalf("expected org_concurrency_exceeded, got %v", err)
		}
	}

	// Releasing both decrements team and org concurrency back to 0.
	rel1(10)
	rel2(10)
	if members, _ := mr.ZMembers("gw:rl:{org:org-conc-1}:zconc:team:team-conc-1"); len(members) != 0 {
		t.Fatalf("expected zconc:team:team-conc-1=0 after release, got %v", members)
	}
	if members, _ := mr.ZMembers("gw:rl:{org:org-conc-1}:zconc:org:org-conc-1"); len(members) != 0 {
		t.Fatalf("expected zconc:org:org-conc-1=0 after release, got %v", members)
	}

	// Verify rollback_acquire.lua rolls back team_conc and org_conc when global limit fails.
	limiter.SetGlobalLimits(0, 0, 1)
	gRel, err := limiter.Acquire(ctx, idTeam, 10)
	if err != nil {
		t.Fatalf("global conc 1 acquire: %v", err)
	}
	defer gRel(10)

	idRollback := &domain.IdentityContext{
		VirtualKeyID:      "vk-rb",
		TeamID:            "team-rb",
		OrgID:             "org-rb",
		TeamMaxConcurrent: 5,
		OrgMaxConcurrent:  5,
	}
	if _, err := limiter.Acquire(ctx, idRollback, 10); err == nil {
		t.Fatal("expected global_concurrency_exceeded")
	}
	if members, _ := mr.ZMembers("gw:rl:{org:org-rb}:zconc:team:team-rb"); len(members) != 0 {
		t.Fatalf("expected rolled back team zconc=0, got %v", members)
	}
	if members, _ := mr.ZMembers("gw:rl:{org:org-rb}:zconc:org:org-rb"); len(members) != 0 {
		t.Fatalf("expected rolled back org zconc=0, got %v", members)
	}
}

func TestColdStartSpendHydrationPreventsOverspendAfterRedisFlush(t *testing.T) {
	mr := miniredis.RunT(t)
	redisFabric := storage.NewRedisFabric(mr.Addr(), "", 0)
	t.Cleanup(func() { _ = redisFabric.Client().Close() })
	limiter := NewLimiter(redisFabric, 60, 300)
	ctx := context.Background()

	// Simulate flushed/cold Redis while Postgres already has spent_micros recorded on idCtx.
	scopes := []struct {
		name      string
		idCtx     *domain.IdentityContext
		wantCode  string
		spendKey  string
		wantFloor string
	}{
		{
			name: "key spend floor",
			idCtx: &domain.IdentityContext{
				VirtualKeyID:       "vk-cold",
				OrgID:              "org-cold",
				KeyMaxBudgetMicros: 1000,
				KeySpentMicros:     850,
			},
			wantCode:  "key_budget_exceeded",
			spendKey:  "gw:spend:{org:org-cold}:key:vk-cold",
			wantFloor: "850",
		},
		{
			name: "team spend floor",
			idCtx: &domain.IdentityContext{
				VirtualKeyID:        "vk-cold-t",
				TeamID:              "team-cold",
				OrgID:               "org-cold",
				TeamMaxBudgetMicros: 1000,
				TeamSpentMicros:     900,
			},
			wantCode:  "team_budget_exceeded",
			spendKey:  "gw:spend:{org:org-cold}:team:team-cold",
			wantFloor: "900",
		},
		{
			name: "user spend floor",
			idCtx: &domain.IdentityContext{
				VirtualKeyID:        "vk-cold-u",
				UserID:              "user-cold",
				OrgID:               "org-cold",
				UserMaxBudgetMicros: 1000,
				UserSpentMicros:     920,
			},
			wantCode:  "user_budget_exceeded",
			spendKey:  "gw:spend:{org:org-cold}:user:user-cold",
			wantFloor: "920",
		},
		{
			name: "org spend floor",
			idCtx: &domain.IdentityContext{
				VirtualKeyID:       "vk-cold-o",
				OrgID:              "org-cold-floor",
				OrgMaxBudgetMicros: 1000,
				OrgSpentMicros:     950,
			},
			wantCode:  "org_budget_exceeded",
			spendKey:  "gw:spend:{org:org-cold-floor}:org:org-cold-floor",
			wantFloor: "950",
		},
	}

	for _, sc := range scopes {
		t.Run(sc.name, func(t *testing.T) {
			mr.FlushAll()
			if _, err := limiter.AcquireWithBudget(ctx, sc.idCtx, 10, 200, "req-over-"+sc.name); err == nil {
				t.Fatalf("expected %s when cold Redis is hydrated with DB floor", sc.wantCode)
			} else {
				var gwErr *domain.GatewayError
				if !errors.As(err, &gwErr) || gwErr.Code != sc.wantCode {
					t.Fatalf("expected %s, got %v", sc.wantCode, err)
				}
			}
			if got, err := mr.Get(sc.spendKey); err != nil || got != sc.wantFloor {
				t.Fatalf("expected %s seeded to %q, got %q err=%v", sc.spendKey, sc.wantFloor, got, err)
			}
			// Request within remaining budget (50 <= 1000 - floor) succeeds.
			rel, err := limiter.AcquireWithBudget(ctx, sc.idCtx, 10, 50, "req-ok-"+sc.name)
			if err != nil {
				t.Fatalf("expected request within remaining budget to succeed, got %v", err)
			}
			rel(10, 50)
		})
	}
}

func TestSetFallbackToLocalOnOutageEnforcesQuotasInMemory(t *testing.T) {
	limiter := NewLimiter(nil, 60, 300)
	limiter.SetFallbackToLocalOnOutage(true)
	ctx := context.Background()

	id := &domain.IdentityContext{
		VirtualKeyID:       "vk-local-1",
		TeamID:             "team-local-1",
		UserID:             "user-local-1",
		OrgID:              "org-local-1",
		KeyRPMLimit:        2,
		TeamMaxConcurrent:  1,
		KeyMaxBudgetMicros: 500,
		KeySpentMicros:     400,
	}

	// First request within RPM, concurrency, and hydrated budget floor (400 + 80 <= 500) succeeds.
	rel1, err := limiter.AcquireWithBudget(ctx, id, 10, 80, "req-loc-1")
	if err != nil {
		t.Fatalf("first degraded local acquire failed: %v", err)
	}

	// Second concurrent request exceeds TeamMaxConcurrent=1 while rel1 is active.
	if _, err := limiter.AcquireWithBudget(ctx, id, 10, 10, "req-loc-conc"); err == nil {
		t.Fatal("expected team_concurrency_exceeded in local fallback mode")
	} else {
		var gwErr *domain.GatewayError
		if !errors.As(err, &gwErr) || gwErr.Code != "team_concurrency_exceeded" {
			t.Fatalf("expected team_concurrency_exceeded, got %v", err)
		}
	}

	// Settle rel1 with 60 micros actual cost (total local spend = 460).
	rel1(10, 60)

	// Next request reserving 50 micros exceeds KeyMaxBudgetMicros (460 + 50 > 500).
	if _, err := limiter.AcquireWithBudget(ctx, id, 10, 50, "req-loc-budget"); err == nil {
		t.Fatal("expected key_budget_exceeded in local fallback mode")
	} else {
		var gwErr *domain.GatewayError
		if !errors.As(err, &gwErr) || gwErr.Code != "key_budget_exceeded" {
			t.Fatalf("expected key_budget_exceeded, got %v", err)
		}
	}

	// Request reserving 30 micros succeeds (2nd RPM in window).
	rel2, err := limiter.AcquireWithBudget(ctx, id, 10, 30, "req-loc-2")
	if err != nil {
		t.Fatalf("second degraded local acquire failed: %v", err)
	}
	rel2(10, 20)

	// 3rd request in same window hits KEY_RPM_EXCEEDED (KeyRPMLimit=2).
	if _, err := limiter.AcquireWithBudget(ctx, id, 10, 10, "req-loc-3"); err == nil {
		t.Fatal("expected key_rpm_exceeded on 3rd request")
	} else {
		var gwErr *domain.GatewayError
		if !errors.As(err, &gwErr) || gwErr.Code != "key_rpm_exceeded" {
			t.Fatalf("expected key_rpm_exceeded, got %v", err)
		}
	}
}
