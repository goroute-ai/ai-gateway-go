package server

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/redis/go-redis/v9"
)

const (
	authStartRateWindow     = time.Minute
	maxLocalRateLimitBucket = 10000
)

var authStartRateLimitLua = redis.NewScript(`
local current = redis.call('INCR', KEYS[1])
if current == 1 then
	redis.call('PEXPIRE', KEYS[1], ARGV[1])
end
local ttl = redis.call('PTTL', KEYS[1])
return {current, ttl}
`)

type localRateBucket struct {
	count   int
	resetAt time.Time
}

type authStartRateLimiter struct {
	redis       *storage.RedisFabric
	limitPerMin int

	mu      sync.Mutex
	buckets map[string]localRateBucket
	now     func() time.Time
}

func newAuthStartRateLimiter(redisFabric *storage.RedisFabric, limitPerMin int) *authStartRateLimiter {
	if limitPerMin <= 0 {
		limitPerMin = 30
	}
	return &authStartRateLimiter{
		redis:       redisFabric,
		limitPerMin: limitPerMin,
		buckets:     make(map[string]localRateBucket),
		now:         time.Now,
	}
}

func (l *authStartRateLimiter) wrap(next http.HandlerFunc) http.HandlerFunc {
	if l == nil || l.limitPerMin <= 0 {
		return next
	}
	return l.middleware(next).ServeHTTP
}

func (l *authStartRateLimiter) middleware(next http.Handler) http.Handler {
	if l == nil || l.limitPerMin <= 0 {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		clientIP := "unknown"
		if ip := extractRemoteIP(r.RemoteAddr); ip != nil {
			clientIP = ip.String()
		}
		allowed, retryAfter := l.allow(r.Context(), clientIP)
		if !allowed {
			secs := int(retryAfter.Seconds())
			if secs < 1 {
				secs = 1
			}
			w.Header().Set("Retry-After", strconv.Itoa(secs))
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusTooManyRequests,
				Type:       domain.ErrorTypeRateLimit,
				Code:       "auth_rate_limit_exceeded",
				Message:    "Too many authentication initiation requests; please retry shortly",
				Retryable:  true,
			})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (l *authStartRateLimiter) allow(ctx context.Context, clientIP string) (bool, time.Duration) {
	key := "gw:auth:start_rl:" + strings.TrimSpace(clientIP)
	if l.redis != nil && l.redis.Client() != nil {
		res, err := l.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
			return authStartRateLimitLua.Run(ctx, rdb, []string{key}, authStartRateWindow.Milliseconds()).Result()
		})
		if err == nil {
			if arr, ok := res.([]any); ok && len(arr) == 2 {
				cnt, _ := arr[0].(int64)
				ttlMs, _ := arr[1].(int64)
				if cnt > int64(l.limitPerMin) {
					if ttlMs <= 0 {
						ttlMs = authStartRateWindow.Milliseconds()
					}
					return false, time.Duration(ttlMs) * time.Millisecond
				}
				return true, 0
			}
		}
	}

	now := l.now().UTC()
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.buckets) >= maxLocalRateLimitBucket {
		for k, b := range l.buckets {
			if !now.Before(b.resetAt) {
				delete(l.buckets, k)
			}
		}
	}
	b, ok := l.buckets[clientIP]
	if !ok || !now.Before(b.resetAt) {
		l.buckets[clientIP] = localRateBucket{count: 1, resetAt: now.Add(authStartRateWindow)}
		return true, 0
	}
	if b.count >= l.limitPerMin {
		return false, b.resetAt.Sub(now)
	}
	b.count++
	l.buckets[clientIP] = b
	return true, 0
}
