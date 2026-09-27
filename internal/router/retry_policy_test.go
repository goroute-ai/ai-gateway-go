package router

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

type stubNetError struct {
	msg     string
	timeout bool
}

func (e stubNetError) Error() string   { return e.msg }
func (e stubNetError) Timeout() bool   { return e.timeout }
func (e stubNetError) Temporary() bool { return true }

var _ net.Error = stubNetError{}

func TestRetryPolicy_ErrorRetryClass(t *testing.T) {
	tests := []struct {
		name           string
		err            error
		numDeployments int
		want           string
	}{
		{
			name:           "nil error defaults",
			err:            nil,
			numDeployments: 2,
			want:           retryClassDefault,
		},
		{
			name:           "429 rate limit",
			err:            domain.ClassifyUpstreamStatus(domain.ProviderOpenAI, http.StatusTooManyRequests, "slow down", 5),
			numDeployments: 1,
			want:           retryClassRateLimit,
		},
		{
			name:           "408 request timeout via ClassifyUpstreamStatus",
			err:            domain.ClassifyUpstreamStatus(domain.ProviderOpenAI, http.StatusRequestTimeout, "request timeout", 0),
			numDeployments: 1,
			want:           retryClassTimeout,
		},
		{
			name:           "context deadline exceeded wrapped",
			err:            fmt.Errorf("upstream call: %w", context.DeadlineExceeded),
			numDeployments: 2,
			want:           retryClassTimeout,
		},
		{
			name:           "net timeout error",
			err:            stubNetError{msg: "i/o timeout", timeout: true},
			numDeployments: 1,
			want:           retryClassTimeout,
		},
		{
			name:           "500 internal server error",
			err:            domain.ClassifyUpstreamStatus(domain.ProviderOpenAI, http.StatusInternalServerError, "oops", 0),
			numDeployments: 1,
			want:           retryClassServerError,
		},
		{
			name:           "502 bad gateway",
			err:            &domain.GatewayError{StatusCode: http.StatusBadGateway, Type: domain.ErrorTypeUpstream, Code: "upstream_transport_error"},
			numDeployments: 1,
			want:           retryClassServerError,
		},
		{
			name:           "503 service unavailable",
			err:            domain.ClassifyUpstreamStatus(domain.ProviderAnthropic, http.StatusServiceUnavailable, "unavailable", 0),
			numDeployments: 2,
			want:           retryClassServerError,
		},
		{
			name:           "504 gateway timeout",
			err:            domain.ClassifyUpstreamStatus(domain.ProviderAnthropic, http.StatusGatewayTimeout, "gateway timeout", 0),
			numDeployments: 2,
			want:           retryClassServerError,
		},
		{
			name:           "529 overloaded maps to server_error",
			err:            domain.ClassifyUpstreamStatus(domain.ProviderAnthropic, 529, "overloaded", 0),
			numDeployments: 2,
			want:           retryClassServerError,
		},
		{
			name:           "non-timeout net error is transport server_error",
			err:            stubNetError{msg: "connection reset", timeout: false},
			numDeployments: 2,
			want:           retryClassServerError,
		},
		{
			name:           "401 via ClassifyUpstreamStatus retains auth class despite 502 status",
			err:            domain.ClassifyUpstreamStatus(domain.ProviderOpenAI, http.StatusUnauthorized, "bad key", 0),
			numDeployments: 2,
			want:           retryClassAuth,
		},
		{
			name:           "401 direct GatewayError single deployment",
			err:            &domain.GatewayError{StatusCode: http.StatusUnauthorized, Type: domain.ErrorTypeAuthentication},
			numDeployments: 1,
			want:           retryClassAuth,
		},
		{
			name:           "403 forbidden classifies as auth",
			err:            &domain.GatewayError{StatusCode: http.StatusForbidden, Type: domain.ErrorTypePermission},
			numDeployments: 3,
			want:           retryClassAuth,
		},
		{
			name:           "404 not found",
			err:            domain.ClassifyUpstreamStatus(domain.ProviderOpenAI, http.StatusNotFound, "missing model", 0),
			numDeployments: 2,
			want:           retryClassNotFound,
		},
		{
			name:           "400 bad request",
			err:            domain.ClassifyUpstreamStatus(domain.ProviderOpenAI, http.StatusBadRequest, "invalid param", 0),
			numDeployments: 2,
			want:           retryClassBadRequest,
		},
		{
			name:           "unknown error falls back to default",
			err:            errors.New("unexpected internal failure"),
			numDeployments: 2,
			want:           retryClassDefault,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := errorRetryClass(tc.err, tc.numDeployments); got != tc.want {
				t.Fatalf("errorRetryClass(%v, %d) = %q, want %q", tc.err, tc.numDeployments, got, tc.want)
			}
		})
	}
}

func TestRetryPolicy_EffectivePolicyAndPerExceptionBudgets(t *testing.T) {
	cfg := config.RouterConfig{
		DefaultMaxRetries: 2,
		RetryPolicy: domain.RetryPolicy{
			RateLimitRetries:   4,
			ServerErrorRetries: 2,
			DefaultRetries:     1,
		},
	}
	group := &domain.ModelGroup{
		ID:         "grp-1",
		MaxRetries: 3,
		RetryPolicy: &domain.RetryPolicy{
			ServerErrorRetries: 1,
		},
	}

	eff := effectiveRetryPolicy(cfg, group)
	if eff.RateLimitRetries != 4 {
		t.Fatalf("RateLimitRetries = %d, want 4", eff.RateLimitRetries)
	}
	if eff.ServerErrorRetries != 1 {
		t.Fatalf("ServerErrorRetries = %d, want 1 (group override)", eff.ServerErrorRetries)
	}
	if eff.TimeoutRetries != 1 {
		t.Fatalf("TimeoutRetries = %d, want 1 (inherited from DefaultRetries)", eff.TimeoutRetries)
	}
	if eff.BadRequestRetries != 0 || eff.NotFoundRetries != 0 {
		t.Fatalf("BadRequestRetries=%d NotFoundRetries=%d, want 0/0", eff.BadRequestRetries, eff.NotFoundRetries)
	}

	// Legacy group without RetryPolicy falls back to group.MaxRetries for transient classes,
	// while keeping 400/404 at 0.
	legacyEff := effectiveRetryPolicy(config.RouterConfig{DefaultMaxRetries: 2}, &domain.ModelGroup{MaxRetries: 3})
	if legacyEff.RateLimitRetries != 3 || legacyEff.TimeoutRetries != 3 || legacyEff.ServerErrorRetries != 3 || legacyEff.AuthErrorRetries != 3 {
		t.Fatalf("unexpected legacy policy: %+v", legacyEff)
	}
	if legacyEff.BadRequestRetries != 0 || legacyEff.NotFoundRetries != 0 {
		t.Fatalf("legacy policy should not retry 400/404 by default: %+v", legacyEff)
	}

	// Verify per-category tracking: consuming 429 budget never grants 400 or extra 503 retries.
	err429 := domain.ClassifyUpstreamStatus(domain.ProviderOpenAI, http.StatusTooManyRequests, "rate limited", 1)
	err503 := domain.ClassifyUpstreamStatus(domain.ProviderOpenAI, http.StatusServiceUnavailable, "unavailable", 0)
	err400 := domain.ClassifyUpstreamStatus(domain.ProviderOpenAI, http.StatusBadRequest, "bad input", 0)

	tracker := newRetryBudgetTracker(eff, 3)

	// 400 has 0 budget even though 429 has 4 retries available.
	if tracker.canRetryErr(err400) || tracker.consumeErr(err400) {
		t.Fatal("400 bad_request should not be granted a retry from 429 budget")
	}

	// 503 has 1 retry available.
	if !tracker.consumeErr(err503) {
		t.Fatal("expected first 503 retry to succeed")
	}
	if tracker.consumeErr(err503) {
		t.Fatal("expected second 503 retry to be rejected after 1-retry budget exhausted")
	}

	// 429 still has all 4 retries intact independently.
	for i := 0; i < 4; i++ {
		if !tracker.consumeErr(err429) {
			t.Fatalf("expected 429 retry #%d to succeed", i+1)
		}
	}
	if tracker.consumeErr(err429) {
		t.Fatal("expected 5th 429 retry to be rejected")
	}
	if tracker.consumed(retryClassRateLimit) != 4 || tracker.consumed(retryClassServerError) != 1 || tracker.consumed(retryClassBadRequest) != 0 {
		t.Fatalf("unexpected consumed counts: %+v", tracker.used)
	}
}

func TestRetryPolicy_AuthMultiDeploymentRetryAndSingleAttemptTrip(t *testing.T) {
	err401 := domain.ClassifyUpstreamStatus(domain.ProviderOpenAI, http.StatusUnauthorized, "invalid key", 0)
	cfg := config.RouterConfig{DefaultMaxRetries: 2}
	group := &domain.ModelGroup{
		ID:               "grp-auth",
		FailureThreshold: 3,
	}

	retryPolicy := effectiveRetryPolicy(cfg, group)
	cooldownPolicy := effectiveCooldownPolicy(cfg, group)

	// Single deployment: 401 is NOT retryable and trips cooldown on 1 attempt.
	singleTracker := newRetryBudgetTracker(retryPolicy, 1)
	if singleTracker.canRetryErr(err401) || singleTracker.consumeErr(err401) {
		t.Fatal("single-deployment 401 must not be retryable")
	}
	authClass := errorRetryClass(err401, 1)
	if got := allowedFailsForClass(cooldownPolicy, group.FailureThreshold, authClass); got != 1 {
		t.Fatalf("allowedFailsForClass(auth) = %d, want 1", got)
	}

	// Multi-deployment (e.g. 2 credentials): 401 IS retryable to failover to another deployment,
	// while the failing deployment still trips on 1 attempt unless overridden.
	multiTracker := newRetryBudgetTracker(retryPolicy, 2)
	if !multiTracker.canRetryErr(err401) || !multiTracker.consumeErr(err401) {
		t.Fatal("multi-deployment 401 should allow failover retry")
	}

	// Explicit AllowedFails override for auth.
	overridePolicy := domain.CooldownPolicy{
		AllowedFails: map[string]int{retryClassAuth: 2},
	}
	if got := allowedFailsForClass(overridePolicy, 5, retryClassAuth); got != 2 {
		t.Fatalf("allowedFailsForClass(auth override) = %d, want 2", got)
	}
	if got := allowedFailsForClass(overridePolicy, 5, retryClassServerError); got != 5 {
		t.Fatalf("allowedFailsForClass(server_error) = %d, want 5", got)
	}
}

func TestRetryPolicy_EffectiveCooldownPolicyAndDuration(t *testing.T) {
	cfg := config.RouterConfig{
		DefaultCooldown: 60 * time.Second,
		CooldownPolicy: domain.CooldownPolicy{
			AllowedFails: map[string]int{
				retryClassRateLimit:   5,
				retryClassServerError: 3,
			},
			FailureRateThreshold: 0.4,
			MinRequestsPerMinute: 20,
			MaxCooldownSeconds:   120,
		},
	}
	group := &domain.ModelGroup{
		CooldownPolicy: &domain.CooldownPolicy{
			AllowedFails: map[string]int{
				retryClassRateLimit: 8,
			},
			MaxCooldownSeconds: 180,
		},
	}

	eff := effectiveCooldownPolicy(cfg, group)
	if eff.AllowedFails[retryClassRateLimit] != 8 || eff.AllowedFails[retryClassServerError] != 3 {
		t.Fatalf("unexpected merged AllowedFails: %+v", eff.AllowedFails)
	}
	// Ensure caller config map was not mutated.
	if cfg.CooldownPolicy.AllowedFails[retryClassRateLimit] != 5 {
		t.Fatalf("cfg.CooldownPolicy.AllowedFails mutated: %+v", cfg.CooldownPolicy.AllowedFails)
	}
	if eff.FailureRateThreshold != 0.4 || eff.MinRequestsPerMinute != 20 || eff.MaxCooldownSeconds != 180 {
		t.Fatalf("unexpected merged CooldownPolicy: %+v", eff)
	}

	// Default MaxCooldownSeconds is 300s when unset.
	defaultCapPolicy := effectiveCooldownPolicy(config.RouterConfig{}, nil)
	if defaultCapPolicy.MaxCooldownSeconds != 300 {
		t.Fatalf("default MaxCooldownSeconds = %d, want 300", defaultCapPolicy.MaxCooldownSeconds)
	}

	tests := []struct {
		name            string
		policy          domain.CooldownPolicy
		groupCooldown   int
		defaultCooldown time.Duration
		retryAfterSec   int
		want            time.Duration
	}{
		{
			name:            "uses default cooldown when group unset",
			policy:          domain.CooldownPolicy{MaxCooldownSeconds: 300},
			groupCooldown:   0,
			defaultCooldown: 45 * time.Second,
			retryAfterSec:   0,
			want:            45 * time.Second,
		},
		{
			name:            "group cooldown overrides default",
			policy:          domain.CooldownPolicy{MaxCooldownSeconds: 300},
			groupCooldown:   90,
			defaultCooldown: 45 * time.Second,
			retryAfterSec:   0,
			want:            90 * time.Second,
		},
		{
			name:            "honors Retry-After within cap",
			policy:          domain.CooldownPolicy{MaxCooldownSeconds: 300},
			groupCooldown:   60,
			defaultCooldown: 60 * time.Second,
			retryAfterSec:   150,
			want:            150 * time.Second,
		},
		{
			name:            "honors short Retry-After",
			policy:          domain.CooldownPolicy{MaxCooldownSeconds: 300},
			groupCooldown:   60,
			defaultCooldown: 60 * time.Second,
			retryAfterSec:   12,
			want:            12 * time.Second,
		},
		{
			name:            "caps Retry-After by explicit MaxCooldownSeconds",
			policy:          domain.CooldownPolicy{MaxCooldownSeconds: 120},
			groupCooldown:   60,
			defaultCooldown: 60 * time.Second,
			retryAfterSec:   600,
			want:            120 * time.Second,
		},
		{
			name:            "caps Retry-After by default 300s when MaxCooldownSeconds unset",
			policy:          domain.CooldownPolicy{},
			groupCooldown:   60,
			defaultCooldown: 60 * time.Second,
			retryAfterSec:   900,
			want:            300 * time.Second,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := effectiveCooldownDuration(tc.policy, tc.groupCooldown, tc.defaultCooldown, tc.retryAfterSec)
			if got != tc.want {
				t.Fatalf("effectiveCooldownDuration = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestRetryPolicy_FailureRateTrackerRedisAndThreshold(t *testing.T) {
	ctx := context.Background()
	mr := miniredis.RunT(t)
	fabric := storage.NewRedisFabric(mr.Addr(), "", 0)
	tracker := newFailureRateTracker(fabric)

	const depID = "dep-rate-1"
	policy := domain.CooldownPolicy{
		FailureRateThreshold: 0.4,
		MinRequestsPerMinute: 10,
	}

	// 6 successes + 3 failures = 9 reqs, 3 fails -> below MinRequestsPerMinute (10).
	for i := 0; i < 6; i++ {
		reqs, fails := tracker.record(ctx, depID, false)
		if reqs != i+1 || fails != 0 {
			t.Fatalf("after success %d: got (%d, %d), want (%d, 0)", i+1, reqs, fails, i+1)
		}
	}
	for i := 0; i < 3; i++ {
		reqs, fails := tracker.record(ctx, depID, true)
		if shouldTripByFailureRate(policy, reqs, fails) {
			t.Fatalf("should not trip below MinRequestsPerMinute: reqs=%d fails=%d", reqs, fails)
		}
	}

	// 10th request is a failure: reqs=10, fails=4 -> rate 0.4 >= 0.4 and reqs >= 10 -> trip!
	reqs, fails := tracker.record(ctx, depID, true)
	if reqs != 10 || fails != 4 {
		t.Fatalf("got (%d, %d), want (10, 4)", reqs, fails)
	}
	if !shouldTripByFailureRate(policy, reqs, fails) {
		t.Fatalf("expected trip at reqs=%d fails=%d threshold=%v", reqs, fails, policy.FailureRateThreshold)
	}

	// Verify cluster hash-tag keys and 60s TTL in Redis.
	reqKey := failureRateReqKey(depID)
	failKey := failureRateFailKey(depID)
	if reqKey != "gw:router:{dep:dep-rate-1}:reqs_1m" || failKey != "gw:router:{dep:dep-rate-1}:fails_1m" {
		t.Fatalf("unexpected keys: req=%q fail=%q", reqKey, failKey)
	}
	if ttl := mr.TTL(reqKey); ttl <= 0 || ttl > 60*time.Second {
		t.Fatalf("unexpected req key TTL: %v", ttl)
	}
	if ttl := mr.TTL(failKey); ttl <= 0 || ttl > 60*time.Second {
		t.Fatalf("unexpected fail key TTL: %v", ttl)
	}

	// Advancing past 60s resets the 1m window in Redis.
	mr.FastForward(61 * time.Second)
	reqs, fails = tracker.record(ctx, depID, false)
	if reqs != 1 || fails != 0 {
		t.Fatalf("after 60s window expiry: got (%d, %d), want (1, 0)", reqs, fails)
	}
}

func TestRetryPolicy_FailureRateTrackerLocalFallbackAndConcurrency(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(1_700_000_000, 0)
	var clockMu sync.Mutex
	tracker := newFailureRateTracker(nil)
	tracker.nowFn = func() time.Time {
		clockMu.Lock()
		defer clockMu.Unlock()
		return now
	}

	const depID = "dep-local-1"
	const workers = 8
	const perWorker = 25
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				tracker.record(ctx, depID, worker%2 == 0 && i%5 == 0)
			}
		}(w)
	}
	wg.Wait()

	reqs, fails := tracker.record(ctx, depID, true)
	// 8 * 25 = 200 concurrent + 1 = 201 reqs; 4 even workers * 5 failures = 20 + 1 = 21 fails.
	if reqs != 201 || fails != 21 {
		t.Fatalf("concurrent local fallback counts = (%d, %d), want (201, 21)", reqs, fails)
	}

	// Advance clock by 60s -> local window rolls over.
	clockMu.Lock()
	now = now.Add(60 * time.Second)
	clockMu.Unlock()

	reqs, fails = tracker.record(ctx, depID, false)
	if reqs != 1 || fails != 0 {
		t.Fatalf("after local window expiry: got (%d, %d), want (1, 0)", reqs, fails)
	}

	// Verify Redis failure transparently falls back to local counters.
	mr := miniredis.RunT(t)
	redisTracker := newFailureRateTracker(storage.NewRedisFabric(mr.Addr(), "", 0))
	mr.Close()
	reqs, fails = redisTracker.record(ctx, "dep-down", true)
	if reqs != 1 || fails != 1 {
		t.Fatalf("fallback on Redis outage = (%d, %d), want (1, 1)", reqs, fails)
	}
}

func TestRetryPolicy_ShouldTripByFailureRateEdgeCases(t *testing.T) {
	if shouldTripByFailureRate(domain.CooldownPolicy{FailureRateThreshold: 0}, 100, 100) {
		t.Fatal("zero FailureRateThreshold must disable rate tripping")
	}
	if shouldTripByFailureRate(domain.CooldownPolicy{FailureRateThreshold: 0.5}, 0, 0) {
		t.Fatal("zero requests must not trip")
	}
	if shouldTripByFailureRate(domain.CooldownPolicy{FailureRateThreshold: 0.5, MinRequestsPerMinute: 10}, 9, 9) {
		t.Fatal("below MinRequestsPerMinute must not trip")
	}
	if shouldTripByFailureRate(domain.CooldownPolicy{FailureRateThreshold: 0.5, MinRequestsPerMinute: 10}, 10, 4) {
		t.Fatal("40% failure rate below 50% threshold must not trip")
	}
	if !shouldTripByFailureRate(domain.CooldownPolicy{FailureRateThreshold: 0.5, MinRequestsPerMinute: 10}, 10, 5) {
		t.Fatal("50% failure rate at 50% threshold should trip")
	}
}

func TestRetryPolicy_LoneDeploymentSafetyNet(t *testing.T) {
	loneGroup := &domain.ModelGroup{ID: "grp-lone"}
	fallbackGroup := &domain.ModelGroup{ID: "grp-fb", FallbackGroupIDs: []string{"backup"}}

	// 1 active deployment, no fallbacks, transient 429 without explicit AllowedFails["rate_limit"] -> protected.
	if !isLoneDeploymentProtected(loneGroup, 1, false, retryClassRateLimit, domain.CooldownPolicy{}) {
		t.Fatal("expected lone deployment without fallbacks to be protected from 429 cooldown")
	}

	// 1 active deployment, no fallbacks, failure-rate threshold -> protected.
	if !isLoneDeploymentProtected(loneGroup, 1, false, cooldownClassFailRate, domain.CooldownPolicy{FailureRateThreshold: 0.4}) {
		t.Fatal("expected lone deployment without fallbacks to be protected from failure-rate cooldown")
	}

	// Explicit AllowedFails["rate_limit"] > 0 overrides lone-deployment 429 protection.
	explicitRatePolicy := domain.CooldownPolicy{
		AllowedFails: map[string]int{retryClassRateLimit: 3},
	}
	if isLoneDeploymentProtected(loneGroup, 1, false, retryClassRateLimit, explicitRatePolicy) {
		t.Fatal("explicit AllowedFails[rate_limit] > 0 should allow tripping even on lone deployment")
	}

	// Auth and server errors are NOT masked by lone-deployment protection.
	if isLoneDeploymentProtected(loneGroup, 1, false, retryClassAuth, domain.CooldownPolicy{}) {
		t.Fatal("auth error should not be shielded by lone-deployment protection")
	}
	if isLoneDeploymentProtected(loneGroup, 1, false, retryClassServerError, domain.CooldownPolicy{}) {
		t.Fatal("server_error should not be shielded by lone-deployment protection")
	}

	// Multiple active deployments -> not protected.
	if isLoneDeploymentProtected(loneGroup, 2, false, retryClassRateLimit, domain.CooldownPolicy{}) {
		t.Fatal("multi-deployment group should not be protected")
	}

	// Fallback present (via param or group) -> not protected.
	if isLoneDeploymentProtected(loneGroup, 1, true, retryClassRateLimit, domain.CooldownPolicy{}) {
		t.Fatal("group with hasFallbacks=true should not be protected")
	}
	if isLoneDeploymentProtected(fallbackGroup, 1, false, retryClassRateLimit, domain.CooldownPolicy{}) {
		t.Fatal("group with FallbackGroupIDs should not be protected")
	}
}
