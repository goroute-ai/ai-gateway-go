package ratelimit

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

func allQuotaScopes() []domain.QuotaScopeType {
	return []domain.QuotaScopeType{
		domain.QuotaScopeOrg,
		domain.QuotaScopeTeam,
		domain.QuotaScopeTeamMember,
		domain.QuotaScopeProject,
		domain.QuotaScopeUser,
		domain.QuotaScopeKey,
		domain.QuotaScopeEndUser,
		domain.QuotaScopeTag,
		domain.QuotaScopeModelAccessGroup,
		domain.QuotaScopeAgentSession,
		domain.QuotaScopeMCPServer,
		domain.QuotaScopeModelPerKey,
		domain.QuotaScopeModelPerTeam,
		domain.QuotaScopeModelPerProject,
		domain.QuotaScopeModelPerUser,
		domain.QuotaScopeModelPerOrg,
		domain.QuotaScopeModelPerEndUser,
	}
}

func TestDescriptorKeysAlignToSameRedisClusterSlot(t *testing.T) {
	now := time.Date(2026, 11, 18, 12, 34, 56, 0, time.UTC)

	cases := []struct {
		name  string
		orgID string
		tag   string
	}{
		{name: "explicit org", orgID: "org_cluster_42", tag: "{org:org_cluster_42}"},
		{name: "empty org falls back to default", orgID: "", tag: "{org:default}"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var descs []domain.RateLimitDescriptor
			for i, sc := range allQuotaScopes() {
				pattern := "*"
				if i%2 == 1 {
					pattern = "gpt-4.1"
				}
				descs = append(descs, domain.RateLimitDescriptor{
					ScopeType:       sc,
					ScopeID:         fmt.Sprintf("entity_%d", i),
					ModelPattern:    pattern,
					RPMLimit:        100,
					TPMLimit:        10000,
					ITPMLimit:       6000,
					OTPMLimit:       4000,
					TPDLimit:        100000,
					MaxConcurrent:   10,
					MaxIterations:   20,
					MaxBudgetMicros: 500000,
				})
			}

			checkKeys := descriptorCheckKeys(tc.orgID, descs, now)
			if want := len(descs) * 13; len(checkKeys) != want {
				t.Fatalf("descriptorCheckKeys len = %d, want %d", len(checkKeys), want)
			}
			for i, k := range checkKeys {
				if !strings.Contains(k, tc.tag) {
					t.Fatalf("checkKeys[%d] = %q missing hash tag %q", i, k, tc.tag)
				}
			}
			assertSameClusterSlot(t, "descriptorCheckKeys", checkKeys)

			recKeys := descriptorReconcileKeys(tc.orgID, descs, now)
			if want := len(descs) * 10; len(recKeys) != want {
				t.Fatalf("descriptorReconcileKeys len = %d, want %d", len(recKeys), want)
			}
			for i, k := range recKeys {
				if !strings.Contains(k, tc.tag) {
					t.Fatalf("recKeys[%d] = %q missing hash tag %q", i, k, tc.tag)
				}
			}
			assertSameClusterSlot(t, "descriptorReconcileKeys", recKeys)

			// Verify alignment with legacy acquireKeys and spendKeys for the same org.
			legacy := acquireKeys(&domain.IdentityContext{
				VirtualKeyID: "vk_1",
				TeamID:       "team_1",
				UserID:       "user_1",
				OrgID:        tc.orgID,
			}, now.Unix()/60)
			allKeys := append(append([]string{}, checkKeys...), recKeys...)
			allKeys = append(allKeys, legacy...)
			assertSameClusterSlot(t, "descriptor + legacy keys", allKeys)
		})
	}

	// Verify every actual key written to miniredis during a live AcquireDescriptors + release
	// across all 17 scope types carries {org:<orgID>} and hashes to the same cluster slot.
	mr := miniredis.RunT(t)
	fabric := storage.NewRedisFabric(mr.Addr(), "", 0)
	t.Cleanup(func() { _ = fabric.Client().Close() })
	limiter := NewLimiter(fabric, 60, 300)

	orgID := "org_live_slots"
	tag := "{org:" + orgID + "}"
	var liveDescs []domain.RateLimitDescriptor
	for i, sc := range allQuotaScopes() {
		liveDescs = append(liveDescs, domain.RateLimitDescriptor{
			ScopeType:       sc,
			ScopeID:         fmt.Sprintf("live_%d", i),
			RPMLimit:        10,
			TPMLimit:        1000,
			ITPMLimit:       500,
			OTPMLimit:       500,
			TPDLimit:        5000,
			MaxConcurrent:   5,
			MaxIterations:   5,
			MaxBudgetMicros: 10000,
		})
	}

	rel, err := limiter.AcquireDescriptors(context.Background(), orgID, "req-slot-check", 50, 25, 100, liveDescs)
	if err != nil {
		t.Fatalf("AcquireDescriptors across all scopes failed: %v", err)
	}
	rel(60, 30, 80)

	writtenKeys := mr.Keys()
	if len(writtenKeys) == 0 {
		t.Fatal("expected Redis keys to be written")
	}
	for i, k := range writtenKeys {
		if !strings.Contains(k, tag) {
			t.Fatalf("written Redis key[%d] = %q missing hash tag %q", i, k, tag)
		}
	}
	assertSameClusterSlot(t, "live miniredis descriptor keys", writtenKeys)
}

func TestAcquireDescriptors_AllOrNothingZeroMutationOnIthFailure(t *testing.T) {
	mr := miniredis.RunT(t)
	fabric := storage.NewRedisFabric(mr.Addr(), "", 0)
	t.Cleanup(func() { _ = fabric.Client().Close() })
	limiter := NewLimiter(fabric, 60, 300)
	ctx := context.Background()

	orgID := "org_atomic"
	descs := []domain.RateLimitDescriptor{
		{
			ScopeType:        domain.QuotaScopeOrg,
			ScopeID:          orgID,
			RPMLimit:         100,
			TPMLimit:         10000,
			ITPMLimit:        5000,
			OTPMLimit:        5000,
			TPDLimit:         50000,
			MaxConcurrent:    10,
			MaxIterations:    10,
			MaxBudgetMicros:  100000,
			SpentFloorMicros: 1000,
		},
		{
			ScopeType:       domain.QuotaScopeTeam,
			ScopeID:         "team_eng",
			RPMLimit:        50,
			TPMLimit:        5000,
			ITPMLimit:       2500,
			OTPMLimit:       2500,
			TPDLimit:        25000,
			MaxConcurrent:   5,
			MaxBudgetMicros: 50000,
		},
		{
			ScopeType:       domain.QuotaScopeKey,
			ScopeID:         "vk_1",
			RPMLimit:        20,
			TPMLimit:        2000,
			MaxConcurrent:   4,
			MaxBudgetMicros: 20000,
		},
		{
			// 4th descriptor (index 3) will reject on ITPM (estInput=600 > 500)
			ScopeType:    domain.QuotaScopeEndUser,
			ScopeID:      "eu_strict",
			ModelPattern: "gpt-4.1",
			ITPMLimit:    500,
		},
	}

	// First request fails on descriptor 3: ZERO keys may exist in Redis!
	_, err := limiter.AcquireDescriptors(ctx, orgID, "req-fail-first", 600, 100, 500, descs)
	var gwErr *domain.GatewayError
	if !errors.As(err, &gwErr) {
		t.Fatalf("expected GatewayError, got %v", err)
	}
	if gwErr.StatusCode != http.StatusTooManyRequests || gwErr.Code != "end_user_itpm_exceeded" {
		t.Fatalf("expected 429 end_user_itpm_exceeded, got status=%d code=%q msg=%q", gwErr.StatusCode, gwErr.Code, gwErr.Message)
	}
	if gwErr.RetryAfterSec <= 0 || gwErr.RetryAfterSec > 60 {
		t.Fatalf("expected RetryAfterSec in [1,60], got %d", gwErr.RetryAfterSec)
	}
	if keys := mr.Keys(); len(keys) != 0 {
		t.Fatalf("expected ZERO Redis keys written on rejected acquire, found %d: %v", len(keys), keys)
	}

	// Admit one valid request first, snapshot every key's state, then trigger failure on descriptor 3
	// via budget limit and assert zero counter mutations across descriptors 0..2.
	descs[3].ITPMLimit = 1000
	descs[3].MaxBudgetMicros = 700
	rel1, err := limiter.AcquireDescriptors(ctx, orgID, "req-ok-1", 200, 50, 500, descs)
	if err != nil {
		t.Fatalf("expected first valid acquire to succeed: %v", err)
	}
	defer rel1(200, 50, 500)

	snapshot := mr.Dump()

	// Second request tries to reserve 300 -> 500+300 > 700 on descriptor 3.
	_, err = limiter.AcquireDescriptors(ctx, orgID, "req-fail-budget", 100, 25, 300, descs)
	if !errors.As(err, &gwErr) || gwErr.StatusCode != http.StatusTooManyRequests || gwErr.Code != "end_user_budget_exceeded" {
		t.Fatalf("expected 429 end_user_budget_exceeded, got %v", err)
	}
	if gwErr.Type != domain.ErrorTypeBudgetExceeded || gwErr.RetryAfterSec != 60 {
		t.Fatalf("expected budget_exceeded_error with RetryAfterSec=60, got type=%q retry=%d", gwErr.Type, gwErr.RetryAfterSec)
	}

	if after := mr.Dump(); after != snapshot {
		t.Fatalf("Redis state mutated on i-th descriptor failure!\nBEFORE:\n%s\nAFTER:\n%s", snapshot, after)
	}
}

func TestAcquireDescriptors_SeparateITPMOTPMTPDAndReconciliation(t *testing.T) {
	mr := miniredis.RunT(t)
	fixedNow := time.Date(2026, 11, 18, 12, 34, 15, 0, time.UTC)
	mr.SetTime(fixedNow)
	fabric := storage.NewRedisFabric(mr.Addr(), "", 0)
	t.Cleanup(func() { _ = fabric.Client().Close() })
	limiter := NewLimiter(fabric, 60, 300)
	limiter.nowFunc = func() time.Time { return fixedNow }
	ctx := context.Background()

	orgID := "org_tokens"
	desc := domain.RateLimitDescriptor{
		ScopeType:     domain.QuotaScopeModelPerKey,
		ScopeID:       "vk_tok",
		ModelPattern:  "claude-sonnet-4",
		TPMLimit:      500,
		ITPMLimit:     200,
		OTPMLimit:     150,
		TPDLimit:      400,
		MaxConcurrent: 2,
	}

	// Acquire with estInput=100, estOutput=80 (total=180).
	rel1, err := limiter.AcquireDescriptors(ctx, orgID, "req-tok-1", 100, 80, 0, []domain.RateLimitDescriptor{desc})
	if err != nil {
		t.Fatalf("acquire 1 failed: %v", err)
	}

	ks := buildDescriptorKeySet(orgID, desc, fixedNow.Unix()/60, fixedNow.Format("20060102"))
	assertRedisInt(t, mr, ks.itpm, "100")
	assertRedisInt(t, mr, ks.otpm, "80")
	assertRedisInt(t, mr, ks.tpm, "180")
	assertRedisInt(t, mr, ks.tpd, "180")
	if members, _ := mr.ZMembers(ks.conc); len(members) != 1 {
		t.Fatalf("redis zset %s members = %v, want 1", ks.conc, members)
	}

	// Reconcile with actualInput=140 (+40), actualOutput=30 (-50) -> totalDelta = -10.
	rel1(140, 30, 0)
	assertRedisInt(t, mr, ks.itpm, "140")
	assertRedisInt(t, mr, ks.otpm, "30")
	assertRedisInt(t, mr, ks.tpm, "170")
	assertRedisInt(t, mr, ks.tpd, "170")
	if members, _ := mr.ZMembers(ks.conc); len(members) != 0 {
		t.Fatalf("redis zset %s members = %v, want 0", ks.conc, members)
	}

	// Calling rel1 a second time must be a no-op (idempotent sync.Once).
	rel1(140, 30, 0)
	assertRedisInt(t, mr, ks.itpm, "140")
	assertRedisInt(t, mr, ks.otpm, "30")
	assertRedisInt(t, mr, ks.tpm, "170")

	// Verify ITPM is enforced independently (140 + 70 > 200).
	_, err = limiter.AcquireDescriptors(ctx, orgID, "req-tok-itpm-fail", 70, 10, 0, []domain.RateLimitDescriptor{desc})
	var gwErr *domain.GatewayError
	if !errors.As(err, &gwErr) || gwErr.Code != "model_per_key_itpm_exceeded" {
		t.Fatalf("expected model_per_key_itpm_exceeded, got %v", err)
	}

	// Verify OTPM is enforced independently (30 + 130 > 150).
	_, err = limiter.AcquireDescriptors(ctx, orgID, "req-tok-otpm-fail", 10, 130, 0, []domain.RateLimitDescriptor{desc})
	if !errors.As(err, &gwErr) || gwErr.Code != "model_per_key_otpm_exceeded" {
		t.Fatalf("expected model_per_key_otpm_exceeded, got %v", err)
	}

	// Admit another request that stays within ITPM/OTPM/TPM/TPD, then refund it with actual=(0, 0)
	// and verify negative deltas subtract cleanly without underflowing.
	rel2, err := limiter.AcquireDescriptors(ctx, orgID, "req-tok-2", 50, 100, 0, []domain.RateLimitDescriptor{desc})
	if err != nil {
		t.Fatalf("acquire 2 failed: %v", err)
	}
	assertRedisInt(t, mr, ks.itpm, "190")
	assertRedisInt(t, mr, ks.otpm, "130")
	assertRedisInt(t, mr, ks.tpm, "320")
	assertRedisInt(t, mr, ks.tpd, "320")

	// TPD check: 320 + 90 > 400 (even though TPM=500 allows it? Wait: also keep itpm<=200 and otpm<=150 via separate desc).
	tpdOnly := domain.RateLimitDescriptor{
		ScopeType:    domain.QuotaScopeModelPerKey,
		ScopeID:      "vk_tok",
		ModelPattern: "claude-sonnet-4",
		TPDLimit:     400,
	}
	_, err = limiter.AcquireDescriptors(ctx, orgID, "req-tok-tpd-fail", 50, 40, 0, []domain.RateLimitDescriptor{tpdOnly})
	if !errors.As(err, &gwErr) || gwErr.Code != "model_per_key_tpd_exceeded" {
		t.Fatalf("expected model_per_key_tpd_exceeded, got %v", err)
	}
	if gwErr.RetryAfterSec <= 0 || gwErr.RetryAfterSec > 86400 {
		t.Fatalf("expected TPD RetryAfterSec in [1,86400], got %d", gwErr.RetryAfterSec)
	}

	// Cancel req-tok-2 using negative sentinel tokens (-1, -1) -> treated as 0 actual tokens (full refund of estimate).
	rel2(-1, -1, -1)
	assertRedisInt(t, mr, ks.itpm, "140")
	assertRedisInt(t, mr, ks.otpm, "30")
	assertRedisInt(t, mr, ks.tpm, "170")
	assertRedisInt(t, mr, ks.tpd, "170")
	if members, _ := mr.ZMembers(ks.conc); len(members) != 0 {
		t.Fatalf("redis zset %s members = %v, want 0", ks.conc, members)
	}
}

func TestAcquireDescriptors_MaxIterationsSessionTTL(t *testing.T) {
	mr := miniredis.RunT(t)
	fabric := storage.NewRedisFabric(mr.Addr(), "", 0)
	t.Cleanup(func() { _ = fabric.Client().Close() })
	limiter := NewLimiter(fabric, 60, 300)
	ctx := context.Background()

	orgID := "org_agent"
	sessionDesc := domain.RateLimitDescriptor{
		ScopeType:     domain.QuotaScopeAgentSession,
		ScopeID:       "sess_001",
		MaxIterations: 3,
		WindowTTLSec:  600,
	}

	for i := 1; i <= 3; i++ {
		rel, err := limiter.AcquireDescriptors(ctx, orgID, fmt.Sprintf("iter-%d", i), 10, 5, 0, []domain.RateLimitDescriptor{sessionDesc})
		if err != nil {
			t.Fatalf("iteration %d failed unexpectedly: %v", i, err)
		}
		rel(10, 5, 0)
	}

	// 4th iteration must be rejected with agent_session_iterations_exceeded.
	_, err := limiter.AcquireDescriptors(ctx, orgID, "iter-4", 10, 5, 0, []domain.RateLimitDescriptor{sessionDesc})
	var gwErr *domain.GatewayError
	if !errors.As(err, &gwErr) || gwErr.StatusCode != http.StatusTooManyRequests || gwErr.Code != "agent_session_iterations_exceeded" {
		t.Fatalf("expected 429 agent_session_iterations_exceeded, got %v", err)
	}
	if gwErr.RetryAfterSec <= 0 || gwErr.RetryAfterSec > 600 {
		t.Fatalf("expected RetryAfterSec in (0,600], got %d", gwErr.RetryAfterSec)
	}

	iterKey := fmt.Sprintf("gw:dq:{org:%s}:iter:agent_session:sess_001", orgID)
	if ttl := mr.TTL(iterKey); ttl <= 0 || ttl > 600*time.Second {
		t.Fatalf("expected iter key TTL in (0,600s], got %v", ttl)
	}

	// After the session TTL expires, a new iteration is admitted.
	mr.FastForward(601 * time.Second)
	rel, err := limiter.AcquireDescriptors(ctx, orgID, "iter-after-ttl", 10, 5, 0, []domain.RateLimitDescriptor{sessionDesc})
	if err != nil {
		t.Fatalf("expected iteration after TTL expiry to succeed: %v", err)
	}
	rel(10, 5, 0)
}

func TestAcquireDescriptors_BudgetReservationSettleRefundOutboxAndExpiry(t *testing.T) {
	mr := miniredis.RunT(t)
	now := time.Now().UTC().Truncate(time.Second)
	mr.SetTime(now)

	fabricA := storage.NewRedisFabric(mr.Addr(), "", 0)
	fabricB := storage.NewRedisFabric(mr.Addr(), "", 0)
	t.Cleanup(func() {
		_ = fabricA.Client().Close()
		_ = fabricB.Client().Close()
	})
	limiterA := NewLimiter(fabricA, 60, 300)
	limiterB := NewLimiter(fabricB, 60, 300)
	limiterA.nowFunc = func() time.Time { return now }
	limiterB.nowFunc = func() time.Time { return now }
	ctx := context.Background()

	orgID := "org_budget"
	desc := domain.RateLimitDescriptor{
		ScopeType:        domain.QuotaScopeProject,
		ScopeID:          "proj_alpha",
		MaxBudgetMicros:  1000,
		SpentFloorMicros: 200,
		MaxConcurrent:    5,
	}
	ks := buildDescriptorKeySet(orgID, desc, now.Unix()/60, now.Format("20060102"))

	// Missing reserveMicros or request ID fails closed with 503 budget_reservation_unavailable.
	_, err := limiterA.AcquireDescriptors(ctx, orgID, "req-zero-res", 10, 10, 0, []domain.RateLimitDescriptor{desc})
	var gwErr *domain.GatewayError
	if !errors.As(err, &gwErr) || gwErr.StatusCode != http.StatusServiceUnavailable || gwErr.Code != "budget_reservation_unavailable" {
		t.Fatalf("expected 503 budget_reservation_unavailable, got %v", err)
	}
	_, err = limiterA.AcquireDescriptors(ctx, orgID, "", 10, 10, 100, []domain.RateLimitDescriptor{desc})
	if !errors.As(err, &gwErr) || gwErr.StatusCode != http.StatusServiceUnavailable || gwErr.Code != "budget_reservation_unavailable" {
		t.Fatalf("expected 503 budget_reservation_unavailable for empty reqID, got %v", err)
	}

	// Reserve 500 (floor=200 + res=500 = 700 <= 1000).
	rel1, err := limiterA.AcquireDescriptors(ctx, orgID, "req-b1", 10, 10, 500, []domain.RateLimitDescriptor{desc})
	if err != nil {
		t.Fatalf("acquire req-b1 failed: %v", err)
	}
	assertRedisInt(t, mr, ks.spend, "200")
	assertRedisInt(t, mr, ks.resSum, "500")

	// Duplicate active request ID returns 429 budget_reservation_conflict.
	_, err = limiterB.AcquireDescriptors(ctx, orgID, "req-b1", 10, 10, 100, []domain.RateLimitDescriptor{desc})
	if !errors.As(err, &gwErr) || gwErr.StatusCode != http.StatusTooManyRequests || gwErr.Code != "budget_reservation_conflict" {
		t.Fatalf("expected 429 budget_reservation_conflict, got %v", err)
	}

	// Second concurrent request reserving 400 exceeds 1000 (200+500+400 > 1000).
	_, err = limiterB.AcquireDescriptors(ctx, orgID, "req-b2", 10, 10, 400, []domain.RateLimitDescriptor{desc})
	if !errors.As(err, &gwErr) || gwErr.Code != "project_budget_exceeded" {
		t.Fatalf("expected project_budget_exceeded, got %v", err)
	}

	// Refund req-b1 (actualCostMicros = -1): reservation removed, spend stays 200.
	rel1(0, 0, -1)
	assertRedisInt(t, mr, ks.resSum, "0")
	assertRedisInt(t, mr, ks.spend, "200")
	if members, _ := mr.ZMembers(ks.resZSet); len(members) != 0 {
		t.Fatalf("expected empty reservation zset after refund, got %v", members)
	}

	// Now req-b2 reserving 400 succeeds and settles actualCostMicros=350 (spend -> 550).
	rel2, err := limiterB.AcquireDescriptors(ctx, orgID, "req-b2", 10, 10, 400, []domain.RateLimitDescriptor{desc})
	if err != nil {
		t.Fatalf("acquire req-b2 after refund failed: %v", err)
	}
	rel2(10, 10, 350)
	rel2(10, 10, 350) // idempotent second call
	assertRedisInt(t, mr, ks.resSum, "0")
	assertRedisInt(t, mr, ks.spend, "550")

	// Outbox deferral (actualCostMicros = -2): concurrency decrements, reservation remains intact.
	rel3, err := limiterA.AcquireDescriptors(ctx, orgID, "req-b3-outbox", 10, 10, 400, []domain.RateLimitDescriptor{desc})
	if err != nil {
		t.Fatalf("acquire req-b3-outbox failed: %v", err)
	}
	if members, _ := mr.ZMembers(ks.conc); len(members) != 1 {
		t.Fatalf("redis zset %s members = %v, want 1", ks.conc, members)
	}
	rel3(10, 10, -2)
	if members, _ := mr.ZMembers(ks.conc); len(members) != 0 {
		t.Fatalf("redis zset %s members = %v, want 0", ks.conc, members)
	}
	assertRedisInt(t, mr, ks.resSum, "400")
	assertRedisInt(t, mr, ks.spend, "550")

	// While req-b3-outbox is still reserved (550+400=950), reserving 100 is rejected.
	_, err = limiterB.AcquireDescriptors(ctx, orgID, "req-b4", 10, 10, 100, []domain.RateLimitDescriptor{desc})
	if !errors.As(err, &gwErr) || gwErr.Code != "project_budget_exceeded" {
		t.Fatalf("expected project_budget_exceeded while outbox hold active, got %v", err)
	}

	// Once req-b3-outbox reservation lease expires, Phase 1+2 cleans it up and admits req-b4.
	mr.SetTime(now.Add(defaultDescriptorReservationTTLSec*time.Second + 10*time.Second))
	rel4, err := limiterB.AcquireDescriptors(ctx, orgID, "req-b4", 10, 10, 100, []domain.RateLimitDescriptor{desc})
	if err != nil {
		t.Fatalf("expected req-b4 to succeed after expired reservation cleanup: %v", err)
	}
	assertRedisInt(t, mr, ks.resSum, "100")
	rel4(10, 10, 100)
	assertRedisInt(t, mr, ks.spend, "650")

	// Concurrency safety: 16 concurrent goroutines competing for 350 remaining budget (reserve=200 each)
	// must admit at most 1 request across both limiter instances.
	var wg sync.WaitGroup
	var admitted atomic.Int32
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			lim := limiterA
			if i%2 == 1 {
				lim = limiterB
			}
			if _, aErr := lim.AcquireDescriptors(ctx, orgID, fmt.Sprintf("race-%d", i), 1, 1, 200, []domain.RateLimitDescriptor{desc}); aErr == nil {
				admitted.Add(1)
			}
		}(i)
	}
	wg.Wait()
	if got := admitted.Load(); got != 1 {
		t.Fatalf("admitted %d concurrent budget reservations, want 1 (remaining=350, reserve=200)", got)
	}
}

func TestAcquireDescriptors_LocalFallbackAndFailClosed(t *testing.T) {
	ctx := context.Background()
	orgID := "org_fallback"
	descs := []domain.RateLimitDescriptor{
		{
			ScopeType:       domain.QuotaScopeOrg,
			ScopeID:         orgID,
			RPMLimit:        5,
			TPMLimit:        500,
			ITPMLimit:       300,
			OTPMLimit:       200,
			TPDLimit:        1000,
			MaxConcurrent:   2,
			MaxBudgetMicros: 500,
		},
		{
			ScopeType:     domain.QuotaScopeAgentSession,
			ScopeID:       "sess_local",
			MaxIterations: 2,
			WindowTTLSec:  120,
		},
	}

	// 1. Fail-closed 503 when Redis is nil and fallback is disabled.
	failClosed := NewLimiter(nil, 60, 300)
	_, err := failClosed.AcquireDescriptors(ctx, orgID, "req-fc-nil", 10, 10, 50, descs)
	var gwErr *domain.GatewayError
	if !errors.As(err, &gwErr) || gwErr.StatusCode != http.StatusServiceUnavailable || gwErr.Code != "rate_limiter_unavailable" {
		t.Fatalf("expected 503 rate_limiter_unavailable with nil Redis, got %v", err)
	}

	// Unmetered descriptors (zero limits) succeed even without Redis.
	unmeteredRel, err := failClosed.AcquireDescriptors(ctx, orgID, "req-unmetered", 10, 10, 0, []domain.RateLimitDescriptor{
		{ScopeType: domain.QuotaScopeKey, ScopeID: "vk_unmetered"},
	})
	if err != nil {
		t.Fatalf("expected unmetered descriptors to succeed without Redis, got %v", err)
	}
	unmeteredRel(10, 10, 0)

	// 2. Fail-closed 503 when Redis is unreachable and fallback is disabled.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	deadAddr := ln.Addr().String()
	_ = ln.Close()

	unreachableFailClosed := NewLimiter(storage.NewRedisFabric(deadAddr, "", 0), 60, 300)
	unreachableFailClosed.SetRedisTimeout(200 * time.Millisecond)
	_, err = unreachableFailClosed.AcquireDescriptors(ctx, orgID, "req-fc-down", 10, 10, 50, descs)
	if !errors.As(err, &gwErr) || gwErr.StatusCode != http.StatusServiceUnavailable || gwErr.Code != "rate_limiter_unavailable" {
		t.Fatalf("expected 503 rate_limiter_unavailable with unreachable Redis, got %v", err)
	}

	// 3. Full local in-memory enforcement when fallbackToLocalOnOutage is enabled
	// (including when Redis is configured but unreachable).
	clock := time.Date(2026, 11, 18, 23, 59, 10, 0, time.UTC)
	local := NewLimiter(storage.NewRedisFabric(deadAddr, "", 0), 60, 300)
	local.SetRedisTimeout(150 * time.Millisecond)
	local.SetFallbackToLocalOnOutage(true)
	local.nowFunc = func() time.Time { return clock }

	// Iteration 1 succeeds.
	rel1, err := local.AcquireDescriptors(ctx, orgID, "local-1", 100, 50, 200, descs)
	if err != nil {
		t.Fatalf("local acquire 1 failed: %v", err)
	}
	// Reconcile actual input=120, actual output=30, settle cost=150.
	rel1(120, 30, 150)

	// Iteration 2 succeeds (refund budget -1).
	rel2, err := local.AcquireDescriptors(ctx, orgID, "local-2", 50, 50, 200, descs)
	if err != nil {
		t.Fatalf("local acquire 2 failed: %v", err)
	}
	rel2(50, 50, -1)

	// Snapshot org local counters before failing on descriptor 1 (agent_session max_iterations=2).
	local.localMu.Lock()
	orgKey := orgHashTag(orgID) + ":org:" + orgID
	rpmBefore := local.localDescRPM[orgKey]
	itpmBefore := local.localDescITPM[orgKey]
	otpmBefore := local.localDescOTPM[orgKey]
	tpdBefore := local.localDescTPD[orgKey]
	spentBefore := local.localDescSpent[orgKey]
	local.localMu.Unlock()

	// Iteration 3 must fail on descriptor 1 with ZERO mutation to descriptor 0!
	_, err = local.AcquireDescriptors(ctx, orgID, "local-3", 50, 50, 100, descs)
	if !errors.As(err, &gwErr) || gwErr.StatusCode != http.StatusTooManyRequests || gwErr.Code != "agent_session_iterations_exceeded" {
		t.Fatalf("expected 429 agent_session_iterations_exceeded, got %v", err)
	}

	local.localMu.Lock()
	if local.localDescRPM[orgKey] != rpmBefore ||
		local.localDescITPM[orgKey] != itpmBefore ||
		local.localDescOTPM[orgKey] != otpmBefore ||
		local.localDescTPD[orgKey] != tpdBefore ||
		local.localDescSpent[orgKey] != spentBefore {
		local.localMu.Unlock()
		t.Fatalf("local fallback mutated descriptor 0 on descriptor 1 failure")
	}
	local.localMu.Unlock()

	// Advance past minute + UTC day boundary and session TTL (120s): minute/day/session counters reset,
	// while durable local spend (150) remains enforced.
	clock = clock.Add(3 * time.Minute)
	rel3, err := local.AcquireDescriptors(ctx, orgID, "local-after-rollover", 100, 50, 300, descs)
	if err != nil {
		t.Fatalf("local acquire after window/day/session rollover failed: %v", err)
	}
	// Outbox deferral (-2) keeps reservation of 300 active (150 + 300 = 450).
	rel3(100, 50, -2)
	_, err = local.AcquireDescriptors(ctx, orgID, "local-over-budget", 10, 10, 100, descs)
	if !errors.As(err, &gwErr) || gwErr.StatusCode != http.StatusTooManyRequests || gwErr.Code != "org_budget_exceeded" {
		t.Fatalf("expected 429 org_budget_exceeded with active local outbox hold, got %v", err)
	}

	// Disabled limiter bypasses all checks.
	failClosed.SetEnabled(false)
	relDis, err := failClosed.AcquireDescriptors(ctx, orgID, "req-disabled", 10, 10, 50, descs)
	if err != nil {
		t.Fatalf("disabled limiter should admit without Redis: %v", err)
	}
	relDis(10, 10, 50)
}

func TestAcquireDescriptors_RPMTPMConcurrencyAndNegativeClamp(t *testing.T) {
	mr := miniredis.RunT(t)
	fixedNow := time.Date(2026, 11, 18, 10, 20, 30, 0, time.UTC)
	mr.SetTime(fixedNow)
	fabric := storage.NewRedisFabric(mr.Addr(), "", 0)
	t.Cleanup(func() { _ = fabric.Client().Close() })
	limiter := NewLimiter(fabric, 60, 300)
	limiter.nowFunc = func() time.Time { return fixedNow }
	ctx := context.Background()

	orgID := "org_dims"
	desc := domain.RateLimitDescriptor{
		ScopeType:     domain.QuotaScopeTeam,
		ScopeID:       "team_core",
		RPMLimit:      2,
		TPMLimit:      300,
		MaxConcurrent: 1,
	}

	rel1, err := limiter.AcquireDescriptors(ctx, orgID, "req-dim-1", 100, 50, 0, []domain.RateLimitDescriptor{desc})
	if err != nil {
		t.Fatalf("acquire 1 failed: %v", err)
	}

	// Concurrent request hits team_concurrency_exceeded.
	_, err = limiter.AcquireDescriptors(ctx, orgID, "req-dim-conc", 10, 10, 0, []domain.RateLimitDescriptor{desc})
	var gwErr *domain.GatewayError
	if !errors.As(err, &gwErr) || gwErr.StatusCode != http.StatusTooManyRequests || gwErr.Code != "team_concurrency_exceeded" {
		t.Fatalf("expected 429 team_concurrency_exceeded, got %v", err)
	}
	if gwErr.RetryAfterSec != 5 {
		t.Fatalf("expected concurrency RetryAfterSec=5, got %d", gwErr.RetryAfterSec)
	}

	// Release with 0 actual tokens (delta = -150) clamps cleanly to 0.
	rel1(0, 0, 0)
	ks := buildDescriptorKeySet(orgID, desc, fixedNow.Unix()/60, fixedNow.Format("20060102"))
	assertRedisInt(t, mr, ks.tpm, "0")
	if members, _ := mr.ZMembers(ks.conc); len(members) != 0 {
		t.Fatalf("redis zset %s members = %v, want 0", ks.conc, members)
	}

	// Request exceeding TPM (estTotal = 350 > 300) hits team_tpm_exceeded without incrementing RPM.
	_, err = limiter.AcquireDescriptors(ctx, orgID, "req-dim-tpm", 200, 150, 0, []domain.RateLimitDescriptor{desc})
	if !errors.As(err, &gwErr) || gwErr.Code != "team_tpm_exceeded" {
		t.Fatalf("expected team_tpm_exceeded, got %v", err)
	}
	assertRedisInt(t, mr, ks.rpm, "1")

	// Second valid request uses RPM slot 2/2.
	rel2, err := limiter.AcquireDescriptors(ctx, orgID, "req-dim-2", 50, 50, 0, []domain.RateLimitDescriptor{desc})
	if err != nil {
		t.Fatalf("acquire 2 failed: %v", err)
	}
	rel2(50, 50, 0)

	// Third request in same minute hits team_rpm_exceeded.
	_, err = limiter.AcquireDescriptors(ctx, orgID, "req-dim-rpm", 10, 10, 0, []domain.RateLimitDescriptor{desc})
	if !errors.As(err, &gwErr) || gwErr.Code != "team_rpm_exceeded" {
		t.Fatalf("expected team_rpm_exceeded, got %v", err)
	}
	if gwErr.RetryAfterSec != 30 {
		t.Fatalf("expected RPM RetryAfterSec=30 at :30s, got %d", gwErr.RetryAfterSec)
	}
}

func assertRedisInt(t *testing.T, mr *miniredis.Miniredis, key, want string) {
	t.Helper()
	got, err := mr.Get(key)
	if err != nil || got != want {
		t.Fatalf("redis key %s = %q (err=%v), want %q", key, got, err, want)
	}
}
