package ratelimit_test

import (
	"context"
	"errors"
	"net"
	"net/http"
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
