package ratelimit_test

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

	"github.com/alicebob/miniredis/v2"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/ratelimit"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
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
