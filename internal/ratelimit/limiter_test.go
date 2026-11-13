package ratelimit_test

import (
	"context"
	"errors"
	"fmt"
	"github.com/alicebob/miniredis/v2"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/ratelimit"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func TestLimiterFailsClosedWithoutRedisForConfiguredLimits(t *testing.T) {
	ctx := context.Background()
	idCtx := &domain.IdentityContext{
		VirtualKeyID:       "vk-limited",
		OrgID:              "org-limited",
		KeyRPMLimit:        10,
		KeyMaxBudgetMicros: 1_000_000,
	}

	for i := 0; i < 2; i++ {
		limiter := ratelimit.NewLimiter(nil, 60, 300)
		_, err := limiter.Acquire(ctx, idCtx, 5)
		var gatewayErr *domain.GatewayError
		if !errors.As(err, &gatewayErr) {
			t.Fatalf("limiter %d: expected a gateway error, got %v", i, err)
		}
		if gatewayErr.StatusCode != http.StatusServiceUnavailable || gatewayErr.Code != "rate_limiter_unavailable" {
			t.Fatalf("limiter %d: expected fail-closed 503, got status=%d code=%q", i, gatewayErr.StatusCode, gatewayErr.Code)
		}
	}
}

func TestLimiterAllowsUnmeteredRequestWithoutRedis(t *testing.T) {
	limiter := ratelimit.NewLimiter(nil, 60, 300)
	release, err := limiter.Acquire(context.Background(), &domain.IdentityContext{
		VirtualKeyID: "vk-unmetered",
		OrgID:        "org-unmetered",
	}, 5)
	if err != nil {
		t.Fatalf("unmetered request should not require Redis: %v", err)
	}
	release(5)
}

func TestLimiterFailsClosedWhenRedisIsUnreachable(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}

	limiter := ratelimit.NewLimiter(storage.NewRedisFabric(addr, "", 0), 60, 300)
	_, err = limiter.Acquire(context.Background(), &domain.IdentityContext{
		VirtualKeyID: "vk-limited",
		KeyRPMLimit:  10,
	}, 5)
	var gatewayErr *domain.GatewayError
	if !errors.As(err, &gatewayErr) || gatewayErr.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected fail-closed 503 when Redis is unreachable, got %v", err)
	}
}

func TestLimiterInstancesShareRedisQuotaState(t *testing.T) {
	redisServer := miniredis.RunT(t)
	fabricA := storage.NewRedisFabric(redisServer.Addr(), "", 0)
	fabricB := storage.NewRedisFabric(redisServer.Addr(), "", 0)
	limiterA := ratelimit.NewLimiter(fabricA, 60, 300)
	limiterB := ratelimit.NewLimiter(fabricB, 60, 300)
	idCtx := &domain.IdentityContext{VirtualKeyID: "vk-shared", KeyRPMLimit: 1}

	release, err := limiterA.Acquire(context.Background(), idCtx, 1)
	if err != nil {
		t.Fatalf("first limiter acquire failed: %v", err)
	}
	release(1)

	if _, err := limiterB.Acquire(context.Background(), idCtx, 1); err == nil {
		t.Fatal("second limiter should observe the shared RPM counter")
	}
}

func TestTokenizerProfilesAndRequestEstimate(t *testing.T) {
	req := &domain.CanonicalChatRequest{
		Model:    "gpt-4.1",
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "Hello world"}},
	}
	if tokens := ratelimit.EstimateRequestTokens(req); tokens <= 0 {
		t.Fatalf("expected positive token estimate, got %d", tokens)
	}
	profiles := map[string]ratelimit.TokenizerProfile{
		"gpt-4.1":                  ratelimit.ProfileO200K,
		"claude-sonnet-4-20250514": ratelimit.ProfileClaudeBPE,
		"gemini-2.5-flash":         ratelimit.ProfileGeminiSP,
	}
	for model, want := range profiles {
		if got := ratelimit.ResolveTokenizerProfile(model); got != want {
			t.Errorf("ResolveTokenizerProfile(%q) = %s, want %s", model, got, want)
		}
	}
}

func TestModalityTokenEstimatesScaleWithRequestSizeAndTPMBoundary(t *testing.T) {
	smallText := ratelimit.EstimateTextInputsTokens("text-embedding-3-small", []string{"short"}, 4)
	largeText := ratelimit.EstimateTextInputsTokens("text-embedding-3-small", []string{strings.Repeat("x", 12000)}, 4)
	if largeText <= smallText {
		t.Fatalf("expected large embedding input estimate %d to exceed small input %d", largeText, smallText)
	}

	smallAudio := ratelimit.EstimateAudioUploadTokens("whisper-1", 1024, "")
	largeAudio := ratelimit.EstimateAudioUploadTokens("whisper-1", 1024*1024, "")
	if largeAudio <= smallAudio {
		t.Fatalf("expected large audio estimate %d to exceed small upload %d", largeAudio, smallAudio)
	}

	smallRerank := ratelimit.EstimateRerankTokens("rerank-model", "q", []domain.RerankDocument{{Text: "short"}})
	largeRerank := ratelimit.EstimateRerankTokens("rerank-model", "q", []domain.RerankDocument{{Text: strings.Repeat("x", 12000)}})
	if largeRerank <= smallRerank {
		t.Fatalf("expected large rerank estimate %d to exceed small request %d", largeRerank, smallRerank)
	}

	shortImage := ratelimit.EstimateImageGenerationTokens("dall-e-3", "a cat", 1)
	longImage := ratelimit.EstimateImageGenerationTokens("dall-e-3", strings.Repeat("x", 12000), 1)
	if longImage <= shortImage {
		t.Fatalf("expected longer image prompt estimate %d to exceed short prompt %d", longImage, shortImage)
	}

	largeLimiter := ratelimit.NewLimiter(nil, 60, 300)
	id := &domain.IdentityContext{VirtualKeyID: "large", KeyTPMLimit: smallText}
	if _, err := largeLimiter.Acquire(context.Background(), id, largeText); err == nil {
		t.Fatal("expected the size-aware estimate to reject a request above the TPM limit")
	}
}

func TestBudgetReservationsAreAtomicAcrossLimiterInstances(t *testing.T) {
	mr := miniredis.RunT(t)
	redisFabric := storage.NewRedisFabric(mr.Addr(), "", 0)
	t.Cleanup(func() { _ = redisFabric.Client().Close() })
	first := ratelimit.NewLimiter(redisFabric, 60, 300)
	second := ratelimit.NewLimiter(redisFabric, 60, 300)
	identity := &domain.IdentityContext{VirtualKeyID: "budget-key", OrgID: "budget-org", KeyMaxBudgetMicros: 100}

	r1, err := first.AcquireWithBudget(context.Background(), identity, 10, 60, "request-1")
	if err != nil {
		t.Fatalf("first reservation: %v", err)
	}
	if _, err := second.AcquireWithBudget(context.Background(), identity, 10, 60, "request-2"); err == nil {
		t.Fatal("expected concurrent reservation to be rejected when total upper bounds exceed budget")
	}
	r1(-1, 0) // failed request releases its reservation
	if members, _ := mr.ZMembers("gw:budget:{org:budget-org}:reservations:key:budget-key"); len(members) != 0 {
		t.Fatalf("reservation should be released, remain: %v", members)
	}
	r2, err := second.AcquireWithBudget(context.Background(), identity, 10, 60, "request-3")
	if err != nil {
		t.Fatalf("reservation after release: %v", err)
	}
	r2(10, -2)
	second.RecordSpendIncrementForRequest(context.Background(), "request-3", "budget-key", "", "budget-org", 45)
	if got, _ := mr.Get("gw:spend:{org:budget-org}:key:budget-key"); got != "45" {
		t.Fatalf("actual spend = %q, want 45", got)
	}

	// Concurrent calls on independent limiter instances must not oversubscribe.
	identity.KeyMaxBudgetMicros = 100
	var wg sync.WaitGroup
	var admitted atomic.Int32
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			lim := first
			if i%2 == 1 {
				lim = second
			}
			if _, err := lim.AcquireWithBudget(context.Background(), identity, 1, 30, fmt.Sprintf("concurrent-%d", i)); err == nil {
				admitted.Add(1)
			}
		}(i)
	}
	wg.Wait()
	if got := admitted.Load(); got != 1 {
		t.Fatalf("admitted %d concurrent reservations, want 1 after 45 micros spent", got)
	}
}

func TestResetSpendCountersClearsRedisSpendKeys(t *testing.T) {
	ctx := context.Background()
	mr := miniredis.RunT(t)
	redisFabric := storage.NewRedisFabric(mr.Addr(), "", 0)
	t.Cleanup(func() { _ = redisFabric.Client().Close() })
	limiter := ratelimit.NewLimiter(redisFabric, 60, 300)

	id := &domain.IdentityContext{
		VirtualKeyID:        "vk-reset",
		TeamID:              "team-reset",
		OrgID:               "org-reset",
		KeyMaxBudgetMicros:  100,
		TeamMaxBudgetMicros: 100,
		OrgMaxBudgetMicros:  100,
	}

	limiter.RecordSpendIncrement(ctx, id.VirtualKeyID, id.TeamID, id.OrgID, 100)
	if _, err := limiter.AcquireWithBudget(ctx, id, 1, 10, "req-blocked"); err == nil {
		t.Fatal("expected budget to be exhausted before reset")
	}

	events := []storage.BudgetResetEvent{
		{ID: "reset-org-1", Scope: "org", EntityID: id.OrgID, OrgID: id.OrgID},
		{ID: "reset-team-1", Scope: "team", EntityID: id.TeamID, OrgID: id.OrgID},
		{ID: "reset-key-1", Scope: "key", EntityID: id.VirtualKeyID, OrgID: id.OrgID},
	}
	if err := limiter.ResetSpendCounters(ctx, events); err != nil {
		t.Fatalf("ResetSpendCounters: %v", err)
	}

	for _, key := range []string{
		"gw:spend:{org:org-reset}:org:org-reset",
		"gw:spend:{org:org-reset}:team:team-reset",
		"gw:spend:{org:org-reset}:key:vk-reset",
	} {
		if mr.Exists(key) {
			t.Fatalf("expected Redis key %q to be deleted", key)
		}
	}
	limiter.RecordSpendIncrement(ctx, id.VirtualKeyID, id.TeamID, id.OrgID, 1)
	if err := limiter.ResetSpendCounters(ctx, events); err != nil {
		t.Fatalf("replay same ResetSpendCounters events: %v", err)
	}
	if !mr.Exists("gw:spend:{org:org-reset}:key:vk-reset") {
		t.Fatal("replaying a delivered reset must not erase spend recorded after the reset")
	}

	// A new event for a later budget period clears the new period's spend.
	for i := range events {
		events[i].ID += "-next"
	}
	if err := limiter.ResetSpendCounters(ctx, events); err != nil {
		t.Fatalf("ResetSpendCounters next period: %v", err)
	}
	if mr.Exists("gw:spend:{org:org-reset}:key:vk-reset") {
		t.Fatal("new reset event should clear the current spend counter")
	}

	release, err := limiter.AcquireWithBudget(ctx, id, 1, 10, "req-after-reset")
	if err != nil {
		t.Fatalf("expected budget to be admitted after reset, got %v", err)
	}
	release(1, 10)

	// Nil limiter / empty slices should be no-ops without error.
	var nilLimiter *ratelimit.Limiter
	if err := nilLimiter.ResetSpendCounters(ctx, events); err != nil {
		t.Fatalf("nil limiter ResetSpendCounters: %v", err)
	}
	if err := limiter.ResetSpendCounters(ctx, nil); err != nil {
		t.Fatalf("empty ResetSpendCounters: %v", err)
	}
}

func TestRecordSpendIncrementForEventIsIdempotent(t *testing.T) {
	mr := miniredis.RunT(t)
	redisFabric := storage.NewRedisFabric(mr.Addr(), "", 0)
	t.Cleanup(func() { _ = redisFabric.Client().Close() })
	limiter := ratelimit.NewLimiter(redisFabric, 60, 300)
	ctx := context.Background()

	id := &domain.IdentityContext{
		VirtualKeyID:       "vk-idem",
		TeamID:             "team-idem",
		OrgID:              "org-idem",
		KeyMaxBudgetMicros: 500,
	}
	release, err := limiter.AcquireWithBudget(ctx, id, 10, 100, "req-idem-1")
	if err != nil {
		t.Fatalf("acquire with budget: %v", err)
	}
	release(10, -2)

	if err := limiter.RecordSpendIncrementForEvent(ctx, "ev-idem-1", "req-idem-1", "vk-idem", "team-idem", "org-idem", 75); err != nil {
		t.Fatalf("first event spend increment: %v", err)
	}
	// Replay with the same event ID must be a strict no-op on spend counters.
	if err := limiter.RecordSpendIncrementForEvent(ctx, "ev-idem-1", "req-idem-1", "vk-idem", "team-idem", "org-idem", 75); err != nil {
		t.Fatalf("replay event spend increment: %v", err)
	}

	for _, scopeKey := range []string{"gw:spend:key:vk-idem", "gw:spend:team:team-idem", "gw:spend:org:org-idem"} {
		if got, _ := mr.Get(scopeKey); got != "75" {
			t.Fatalf("%s = %q, want 75", scopeKey, got)
		}
	}
	if members, _ := mr.ZMembers("gw:budget:reservations:key:vk-idem"); len(members) != 0 {
		t.Fatalf("expected reservation to be removed, remaining: %v", members)
	}

	// Empty event_id falls back to request_id for idempotency.
	if err := limiter.RecordSpendIncrementForRequest(ctx, "req-fallback-1", "vk-idem", "team-idem", "org-idem", 25); err != nil {
		t.Fatalf("first request fallback increment: %v", err)
	}
	if err := limiter.RecordSpendIncrementForRequest(ctx, "req-fallback-1", "vk-idem", "team-idem", "org-idem", 25); err != nil {
		t.Fatalf("replay request fallback increment: %v", err)
	}
	if got, _ := mr.Get("gw:spend:key:vk-idem"); got != "100" {
		t.Fatalf("gw:spend:key:vk-idem = %q, want 100", got)
	}

	// Unreachable Redis returns an error so SpendWorker can retry via outbox.
	mr.Close()
	if err := limiter.RecordSpendIncrementForEvent(ctx, "ev-fail", "req-fail", "vk-idem", "team-idem", "org-idem", 10); err == nil {
		t.Fatal("expected error when Redis is unreachable")
	}
}

func TestRenewReservationLeaseExtendsScoreAndTTL(t *testing.T) {
	mr := miniredis.RunT(t)
	redisFabric := storage.NewRedisFabric(mr.Addr(), "", 0)
	t.Cleanup(func() { _ = redisFabric.Client().Close() })
	limiter := ratelimit.NewLimiter(redisFabric, 60, 300)
	ctx := context.Background()

	id := &domain.IdentityContext{
		VirtualKeyID:        "vk-lease",
		TeamID:              "team-lease",
		OrgID:               "org-lease",
		KeyMaxBudgetMicros:  500,
		TeamMaxBudgetMicros: 500,
		OrgMaxBudgetMicros:  500,
	}
	release, err := limiter.AcquireWithBudget(ctx, id, 10, 100, "req-lease-1")
	if err != nil {
		t.Fatalf("acquire with budget: %v", err)
	}
	defer release(10, -2)

	resKey := "gw:budget:reservations:key:vk-lease"
	initialScore, err := mr.ZScore(resKey, "req-lease-1|100")
	if err != nil {
		t.Fatalf("initial ZScore: %v", err)
	}

	if err := limiter.RenewReservationLease(ctx, id, "req-lease-1", 7200); err != nil {
		t.Fatalf("RenewReservationLease: %v", err)
	}

	for _, key := range []string{
		"gw:budget:reservations:key:vk-lease",
		"gw:budget:reservations:team:team-lease",
		"gw:budget:reservations:org:org-lease",
	} {
		renewedScore, err := mr.ZScore(key, "req-lease-1|100")
		if err != nil {
			t.Fatalf("renewed ZScore for %s: %v", key, err)
		}
		if renewedScore <= initialScore {
			t.Fatalf("%s score = %v, want > initial %v", key, renewedScore, initialScore)
		}
		if ttl := mr.TTL(key); ttl <= 3660 {
			t.Fatalf("%s TTL = %v, want > 3660s", key, ttl)
		}
	}
}
