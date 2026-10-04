package ratelimit_test

import (
	"context"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/ratelimit"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

func TestLimiterSetEnabledFalseBypassesLimits(t *testing.T) {
	limiter := ratelimit.NewLimiter(nil, 60, 300)
	limiter.SetGlobalLimits(1, 1, 1)
	limiter.SetEnabled(false)

	idCtx := &domain.IdentityContext{
		VirtualKeyID:       "vk-disabled",
		OrgID:              "org-disabled",
		KeyRPMLimit:        1,
		KeyTPMLimit:        1,
		KeyMaxBudgetMicros: 100,
	}

	release, err := limiter.Acquire(context.Background(), idCtx, 50)
	if err != nil {
		t.Fatalf("expected disabled limiter to bypass limits, got err: %v", err)
	}
	release(50)

	releaseBudget, err := limiter.AcquireWithBudget(context.Background(), idCtx, 50, 500, "req-disabled-1")
	if err != nil {
		t.Fatalf("expected disabled limiter to bypass budget limits, got err: %v", err)
	}
	releaseBudget(50, 500)
}

func TestLimiterSetDefaultEstimatedTPM(t *testing.T) {
	mr := miniredis.RunT(t)
	fabric := storage.NewRedisFabric(mr.Addr(), "", 0)
	defer func() { _ = fabric.Client().Close() }()

	limiter := ratelimit.NewLimiter(fabric, 60, 300)
	limiter.SetDefaultEstimatedTPM(100)

	idCtx := &domain.IdentityContext{
		VirtualKeyID: "vk-est-tpm",
		OrgID:        "org-est-tpm",
		KeyTPMLimit:  150,
	}

	release1, err := limiter.Acquire(context.Background(), idCtx, 0)
	if err != nil {
		t.Fatalf("first acquire with 0 estimate (default 100 <= 150) failed: %v", err)
	}
	defer release1(100)

	// Second call with 0 estimate also uses 100 -> total 200 > 150, must be rejected.
	_, err = limiter.Acquire(context.Background(), idCtx, 0)
	var gwErr *domain.GatewayError
	if !errors.As(err, &gwErr) || gwErr.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429 rate limit error on second 0-estimate acquire, got %v", err)
	}
}

func TestLimiterSetRedisTimeout(t *testing.T) {
	// Start a TCP listener that accepts connections and never replies, simulating a stalled Redis.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer func() { _ = ln.Close() }()

	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				<-done
			}(conn)
		}
	}()

	fabric := storage.NewRedisFabric(ln.Addr().String(), "", 0)
	defer func() { _ = fabric.Client().Close() }()

	limiter := ratelimit.NewLimiter(fabric, 60, 300)
	limiter.SetRedisTimeout(25 * time.Millisecond)

	idCtx := &domain.IdentityContext{
		VirtualKeyID: "vk-timeout",
		OrgID:        "org-timeout",
		KeyRPMLimit:  10,
	}

	start := time.Now()
	_, err = limiter.Acquire(context.Background(), idCtx, 10)
	elapsed := time.Since(start)

	var gwErr *domain.GatewayError
	if !errors.As(err, &gwErr) || gwErr.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("expected 503 rate_limiter_unavailable on Redis timeout, got %v", err)
	}
	if elapsed > 500*time.Millisecond {
		t.Fatalf("expected RedisTimeout to bound Acquire duration, took %v", elapsed)
	}
}
