package router

import (
	"context"
	_ "embed"
	"errors"
	"maps"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/redis/go-redis/v9"
)

const (
	retryClassRateLimit   = "rate_limit"
	retryClassTimeout     = "timeout"
	retryClassServerError = "server_error"
	retryClassAuth        = "auth"
	retryClassNotFound    = "not_found"
	retryClassBadRequest  = "bad_request"
	retryClassDefault     = "default"
	cooldownClassFailRate = "failure_rate"

	defaultFailureThreshold  = 3
	defaultCooldownDuration  = 60 * time.Second
	defaultMaxCooldownSec    = 300
	defaultFailureRateWindow = 60 * time.Second
)

//go:embed scripts/record_failure_rate.lua
var recordFailureRateLua string

var recordFailureRateScript = redis.NewScript(recordFailureRateLua)

// errorRetryClass classifies an upstream or transport error into a canonical
// retry/cooldown category.
//
// Auth failures are always classified as "auth" so cooldown policies can trip
// immediately; retryBudgetTracker gates actual retries on numDeployments > 1.
func errorRetryClass(err error, numDeployments int) string {
	_ = numDeployments
	if err == nil {
		return retryClassDefault
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return retryClassTimeout
	}

	var gwErr *domain.GatewayError
	if errors.As(err, &gwErr) {
		return classifyGatewayErrorClass(gwErr)
	}

	var netErr net.Error
	if errors.As(err, &netErr) {
		if netErr.Timeout() {
			return retryClassTimeout
		}
		return retryClassServerError
	}

	return retryClassDefault
}

func classifyGatewayErrorClass(gwErr *domain.GatewayError) string {
	// Check AuthFailure and authentication types first because
	// domain.ClassifyUpstreamStatus rewrites 401/403 StatusCode to 502.
	if gwErr.AuthFailure ||
		gwErr.StatusCode == http.StatusUnauthorized ||
		gwErr.StatusCode == http.StatusForbidden ||
		gwErr.Type == domain.ErrorTypeAuthentication {
		return retryClassAuth
	}

	// Check 408 before ErrorTypeRateLimit because domain.ClassifyUpstreamStatus
	// tags HTTP 408 with ErrorTypeRateLimit.
	if gwErr.StatusCode == http.StatusRequestTimeout {
		return retryClassTimeout
	}
	if gwErr.StatusCode == http.StatusTooManyRequests {
		return retryClassRateLimit
	}
	if gwErr.StatusCode == http.StatusNotFound || gwErr.Type == domain.ErrorTypeNotFound {
		return retryClassNotFound
	}
	if gwErr.StatusCode == http.StatusBadRequest ||
		gwErr.StatusCode == http.StatusUnprocessableEntity ||
		gwErr.Type == domain.ErrorTypeInvalidRequest {
		return retryClassBadRequest
	}
	if gwErr.StatusCode == http.StatusInternalServerError ||
		gwErr.StatusCode == http.StatusBadGateway ||
		gwErr.StatusCode == http.StatusServiceUnavailable ||
		gwErr.StatusCode == http.StatusGatewayTimeout ||
		gwErr.StatusCode == 529 ||
		gwErr.StatusCode >= 500 {
		return retryClassServerError
	}
	if gwErr.Type == domain.ErrorTypeRateLimit {
		return retryClassRateLimit
	}
	if gwErr.Type == domain.ErrorTypeUpstream || gwErr.Type == domain.ErrorTypeServer {
		return retryClassServerError
	}
	return retryClassDefault
}

// effectiveRetryPolicy merges router-level defaults, ModelGroup overrides, and
// legacy MaxRetries fallbacks into a resolved per-class RetryPolicy.
func effectiveRetryPolicy(cfg config.RouterConfig, group *domain.ModelGroup) domain.RetryPolicy {
	out := cfg.RetryPolicy
	if group != nil && group.RetryPolicy != nil {
		gp := group.RetryPolicy
		if gp.RateLimitRetries > 0 {
			out.RateLimitRetries = gp.RateLimitRetries
		}
		if gp.TimeoutRetries > 0 {
			out.TimeoutRetries = gp.TimeoutRetries
		}
		if gp.ServerErrorRetries > 0 {
			out.ServerErrorRetries = gp.ServerErrorRetries
		}
		if gp.AuthErrorRetries > 0 {
			out.AuthErrorRetries = gp.AuthErrorRetries
		}
		if gp.NotFoundRetries > 0 {
			out.NotFoundRetries = gp.NotFoundRetries
		}
		if gp.BadRequestRetries > 0 {
			out.BadRequestRetries = gp.BadRequestRetries
		}
		if gp.DefaultRetries > 0 {
			out.DefaultRetries = gp.DefaultRetries
		}
	}

	baseRetries := cfg.DefaultMaxRetries
	if group != nil && group.MaxRetries > 0 {
		baseRetries = group.MaxRetries
	}
	if baseRetries < 0 {
		baseRetries = 0
	}

	if out.DefaultRetries <= 0 {
		out.DefaultRetries = baseRetries
	}
	if out.RateLimitRetries <= 0 {
		out.RateLimitRetries = out.DefaultRetries
	}
	if out.TimeoutRetries <= 0 {
		out.TimeoutRetries = out.DefaultRetries
	}
	if out.ServerErrorRetries <= 0 {
		out.ServerErrorRetries = out.DefaultRetries
	}
	if out.AuthErrorRetries <= 0 {
		// Multi-deployment failover on 401/403 uses the fallback budget when unset;
		// retryBudgetTracker still disables auth retries when numDeployments <= 1.
		out.AuthErrorRetries = out.DefaultRetries
	}
	if out.NotFoundRetries < 0 {
		out.NotFoundRetries = 0
	}
	if out.BadRequestRetries < 0 {
		out.BadRequestRetries = 0
	}
	return out
}

// retryBudgetTracker enforces independent per-error-class retry budgets so an
// allowance for one category (e.g. 429) never grants retries for another (e.g. 400).
type retryBudgetTracker struct {
	policy         domain.RetryPolicy
	numDeployments int
	used           map[string]int
	totalRetries   int
}

func newRetryBudgetTracker(policy domain.RetryPolicy, numDeployments int) *retryBudgetTracker {
	return &retryBudgetTracker{
		policy:         policy,
		numDeployments: numDeployments,
		used:           make(map[string]int),
	}
}

func (t *retryBudgetTracker) budgetForClass(errClass string) int {
	var budget int
	switch errClass {
	case retryClassRateLimit:
		budget = t.policy.RateLimitRetries
	case retryClassTimeout:
		budget = t.policy.TimeoutRetries
	case retryClassServerError:
		budget = t.policy.ServerErrorRetries
	case retryClassAuth:
		if t.numDeployments <= 1 {
			return 0
		}
		budget = t.policy.AuthErrorRetries
	case retryClassNotFound:
		budget = t.policy.NotFoundRetries
	case retryClassBadRequest:
		budget = t.policy.BadRequestRetries
	default:
		budget = t.policy.DefaultRetries
	}
	if budget < 0 {
		return 0
	}
	return budget
}

func (t *retryBudgetTracker) consumed(errClass string) int {
	if t == nil || t.used == nil {
		return 0
	}
	return t.used[errClass]
}

func (t *retryBudgetTracker) remaining(errClass string) int {
	if t == nil {
		return 0
	}
	rem := t.budgetForClass(errClass) - t.consumed(errClass)
	if rem < 0 {
		return 0
	}
	return rem
}

func (t *retryBudgetTracker) canRetry(errClass string) bool {
	return t != nil && t.remaining(errClass) > 0
}

func (t *retryBudgetTracker) consume(errClass string) bool {
	if !t.canRetry(errClass) {
		return false
	}
	if t.used == nil {
		t.used = make(map[string]int)
	}
	t.used[errClass]++
	t.totalRetries++
	return true
}

func (t *retryBudgetTracker) canRetryErr(err error) bool {
	if t == nil {
		return false
	}
	return t.canRetry(errorRetryClass(err, t.numDeployments))
}

func (t *retryBudgetTracker) consumeErr(err error) bool {
	if t == nil {
		return false
	}
	return t.consume(errorRetryClass(err, t.numDeployments))
}

// effectiveCooldownPolicy merges router-level defaults and ModelGroup overrides
// into a CooldownPolicy with a default MaxCooldownSeconds cap of 300s.
func effectiveCooldownPolicy(cfg config.RouterConfig, group *domain.ModelGroup) domain.CooldownPolicy {
	out := cfg.CooldownPolicy
	if cfg.CooldownPolicy.AllowedFails != nil {
		out.AllowedFails = maps.Clone(cfg.CooldownPolicy.AllowedFails)
	}
	if group != nil && group.CooldownPolicy != nil {
		gp := group.CooldownPolicy
		if len(gp.AllowedFails) > 0 {
			if out.AllowedFails == nil {
				out.AllowedFails = make(map[string]int, len(gp.AllowedFails))
			}
			for class, limit := range gp.AllowedFails {
				if limit > 0 {
					out.AllowedFails[class] = limit
				}
			}
		}
		if gp.FailureRateThreshold > 0 {
			out.FailureRateThreshold = gp.FailureRateThreshold
		}
		if gp.MinRequestsPerMinute > 0 {
			out.MinRequestsPerMinute = gp.MinRequestsPerMinute
		}
		if gp.MaxCooldownSeconds > 0 {
			out.MaxCooldownSeconds = gp.MaxCooldownSeconds
		}
	}
	if out.MaxCooldownSeconds <= 0 {
		out.MaxCooldownSeconds = defaultMaxCooldownSec
	}
	return out
}

// allowedFailsForClass returns the failure threshold for a specific error class,
// tripping on 1 attempt for auth failures unless explicitly overridden.
func allowedFailsForClass(policy domain.CooldownPolicy, defaultThreshold int, errClass string) int {
	if policy.AllowedFails != nil {
		if v, ok := policy.AllowedFails[errClass]; ok && v > 0 {
			return v
		}
	}
	if errClass == retryClassAuth {
		return 1
	}
	if defaultThreshold > 0 {
		return defaultThreshold
	}
	return defaultFailureThreshold
}

// effectiveCooldownDuration computes the cooldown duration for a tripped deployment,
// honoring upstream Retry-After while enforcing MaxCooldownSeconds (default 300s).
func effectiveCooldownDuration(policy domain.CooldownPolicy, groupCooldownSec int, defaultCooldown time.Duration, retryAfterSec int) time.Duration {
	dur := defaultCooldown
	if groupCooldownSec > 0 {
		dur = time.Duration(groupCooldownSec) * time.Second
	}
	if dur <= 0 {
		dur = defaultCooldownDuration
	}
	if retryAfterSec > 0 {
		dur = time.Duration(retryAfterSec) * time.Second
	}

	maxSec := policy.MaxCooldownSeconds
	if maxSec <= 0 {
		maxSec = defaultMaxCooldownSec
	}
	maxCooldown := time.Duration(maxSec) * time.Second
	if dur > maxCooldown {
		return maxCooldown
	}
	return dur
}

type localFailureWindow struct {
	windowStart time.Time
	reqs        int
	fails       int
}

// failureRateTracker maintains 1-minute request and failure counters per
// deployment using atomic Redis Lua counters with a process-local fallback.
type failureRateTracker struct {
	redis *storage.RedisFabric
	nowFn func() time.Time
	mu    sync.Mutex
	local map[string]*localFailureWindow
}

func newFailureRateTracker(redisFabric *storage.RedisFabric) *failureRateTracker {
	return &failureRateTracker{
		redis: redisFabric,
		nowFn: time.Now,
		local: make(map[string]*localFailureWindow),
	}
}

func failureRateReqKey(depID string) string {
	return "gw:router:" + depHashTag(depID) + ":reqs_1m"
}

func failureRateFailKey(depID string) string {
	return "gw:router:" + depHashTag(depID) + ":fails_1m"
}

func (t *failureRateTracker) now() time.Time {
	if t != nil && t.nowFn != nil {
		return t.nowFn()
	}
	return time.Now()
}

func (t *failureRateTracker) record(ctx context.Context, depID string, failed bool) (int, int) {
	if depID == "" {
		depID = "default"
	}
	if t.redis != nil && t.redis.Client() != nil {
		failedArg := 0
		if failed {
			failedArg = 1
		}
		res, err := t.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
			return recordFailureRateScript.Run(
				ctx,
				rdb,
				[]string{failureRateReqKey(depID), failureRateFailKey(depID)},
				failedArg,
				defaultFailureRateWindow.Milliseconds(),
			).Int64Slice()
		})
		if err == nil {
			if vals, ok := res.([]int64); ok && len(vals) == 2 {
				return int(vals[0]), int(vals[1])
			}
		}
	}

	now := t.now()
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.local == nil {
		t.local = make(map[string]*localFailureWindow)
	}
	w, ok := t.local[depID]
	if !ok || now.Sub(w.windowStart) >= defaultFailureRateWindow {
		w = &localFailureWindow{windowStart: now}
		t.local[depID] = w
	}
	w.reqs++
	if failed {
		w.fails++
	}
	return w.reqs, w.fails
}

// shouldTripByFailureRate reports whether observed 1m request/failure counts
// meet both MinRequestsPerMinute and FailureRateThreshold.
func shouldTripByFailureRate(policy domain.CooldownPolicy, reqs, fails int) bool {
	if policy.FailureRateThreshold <= 0 || reqs <= 0 || fails <= 0 {
		return false
	}
	if policy.MinRequestsPerMinute > 0 && reqs < policy.MinRequestsPerMinute {
		return false
	}
	return float64(fails)/float64(reqs) >= policy.FailureRateThreshold
}

// isLoneDeploymentProtected guards single-deployment groups without fallbacks
// against self-blacklisting on transient 429s or percentage failure-rate spikes,
// unless AllowedFails["rate_limit"] > 0 explicitly requires tripping on 429s.
func isLoneDeploymentProtected(group *domain.ModelGroup, activeDeployments int, hasFallbacks bool, errClass string, policy domain.CooldownPolicy) bool {
	if activeDeployments != 1 || hasFallbacks {
		return false
	}
	if group != nil && (len(group.FallbackGroupIDs) > 0 || len(group.FallbackTargets) > 0) {
		return false
	}

	switch errClass {
	case retryClassRateLimit:
		if policy.AllowedFails != nil && policy.AllowedFails[retryClassRateLimit] > 0 {
			return false
		}
		return true
	case cooldownClassFailRate, "":
		return true
	default:
		return false
	}
}
