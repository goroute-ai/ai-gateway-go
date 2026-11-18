package upstream

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/redis/go-redis/v9"
	"golang.org/x/sync/singleflight"
)

const (
	defaultTokenCachePrefix      = "gw:upstream_token:"
	defaultTokenEarlyRefreshSkew = 30 * time.Second
	defaultTokenLockTTL          = 10 * time.Second
	defaultTokenLockWaitTimeout  = 5 * time.Second
	defaultTokenLockPollInterval = 25 * time.Millisecond
	defaultTokenTTL              = 1 * time.Hour
	defaultRefreshExecTimeout    = 30 * time.Second
)

var releaseTokenLockScript = redis.NewScript(`
if redis.call("GET", KEYS[1]) == ARGV[1] then
	return redis.call("DEL", KEYS[1])
end
return 0
`)

// CachedToken represents a cached upstream bearer token and its refresh watermark.
type CachedToken struct {
	AccessToken  string    `json:"access_token"`
	ExpiresAt    time.Time `json:"expires_at"`
	RefreshAfter time.Time `json:"refresh_after"`
}

// TokenRefreshFunc fetches a fresh upstream access token and its TTL.
type TokenRefreshFunc func(ctx context.Context) (accessToken string, ttl time.Duration, err error)

// DistributedTokenCacheConfig tunes L1/L2 caching and Redis distributed locking.
type DistributedTokenCacheConfig struct {
	KeyPrefix        string
	EarlyRefreshSkew time.Duration
	LockTTL          time.Duration
	LockWaitTimeout  time.Duration
	LockPollInterval time.Duration
	Now              func() time.Time
}

// DistributedTokenCache coordinates upstream token caching across goroutines and gateway pods
// using a process-local L1 cache, singleflight coalescing, an optional Redis L2 cache, and
// a Redis distributed mutex (SET NX PX + Lua release).
type DistributedTokenCache struct {
	redis            *storage.RedisFabric
	keyPrefix        string
	earlyRefreshSkew time.Duration
	lockTTL          time.Duration
	lockWaitTimeout  time.Duration
	lockPollInterval time.Duration
	now              func() time.Time

	mu      sync.RWMutex
	l1      map[string]CachedToken
	sfGroup singleflight.Group
}

// NewDistributedTokenCache constructs a DistributedTokenCache.
// Passing a nil redisFabric creates an in-process L1 + singleflight cache.
func NewDistributedTokenCache(redisFabric *storage.RedisFabric, cfg DistributedTokenCacheConfig) *DistributedTokenCache {
	prefix := cfg.KeyPrefix
	if prefix == "" {
		prefix = defaultTokenCachePrefix
	}
	skew := cfg.EarlyRefreshSkew
	if skew <= 0 {
		skew = defaultTokenEarlyRefreshSkew
	}
	lockTTL := cfg.LockTTL
	if lockTTL <= 0 {
		lockTTL = defaultTokenLockTTL
	}
	lockWait := cfg.LockWaitTimeout
	if lockWait <= 0 {
		lockWait = defaultTokenLockWaitTimeout
	}
	poll := cfg.LockPollInterval
	if poll <= 0 {
		poll = defaultTokenLockPollInterval
	}
	nowFn := cfg.Now
	if nowFn == nil {
		nowFn = time.Now
	}

	return &DistributedTokenCache{
		redis:            redisFabric,
		keyPrefix:        prefix,
		earlyRefreshSkew: skew,
		lockTTL:          lockTTL,
		lockWaitTimeout:  lockWait,
		lockPollInterval: poll,
		now:              nowFn,
		l1:               make(map[string]CachedToken),
	}
}

// GetOrRefresh returns a fresh cached token for cacheKey, or coordinates a single refresh
// across goroutines (via singleflight) and pods (via Redis distributed lock).
func (c *DistributedTokenCache) GetOrRefresh(ctx context.Context, cacheKey string, refreshFn TokenRefreshFunc) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if refreshFn == nil {
		return "", errors.New("token_cache: refresh function is nil")
	}

	digest := hashTokenCacheKey(cacheKey)

	// 1. Fast path: L1 in-memory cache hit.
	if entry, ok := c.getL1(digest); ok {
		return entry.AccessToken, nil
	}

	// 2. Coalesce concurrent misses on this pod using singleflight.
	ch := c.sfGroup.DoChan(digest, func() (any, error) {
		refreshCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), defaultRefreshExecTimeout)
		defer cancel()
		return c.getOrRefreshCoalesced(refreshCtx, digest, refreshFn)
	})

	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case res := <-ch:
		if res.Err != nil {
			return "", res.Err
		}
		tok, _ := res.Val.(string)
		return tok, nil
	}
}

// Invalidate removes a cached token from both L1 and L2 (best-effort on Redis).
func (c *DistributedTokenCache) Invalidate(ctx context.Context, cacheKey string) {
	if c == nil {
		return
	}
	digest := hashTokenCacheKey(cacheKey)
	c.mu.Lock()
	delete(c.l1, digest)
	c.mu.Unlock()

	if c.redis != nil && c.redis.Client() != nil {
		if ctx == nil {
			ctx = context.Background()
		}
		dataKey := c.dataKey(digest)
		_, _ = c.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
			return rdb.Del(ctx, dataKey).Result()
		})
	}
}

func (c *DistributedTokenCache) getOrRefreshCoalesced(ctx context.Context, digest string, refreshFn TokenRefreshFunc) (string, error) {
	// Re-check L1 after winning/entering singleflight.
	if entry, ok := c.getL1(digest); ok {
		return entry.AccessToken, nil
	}

	// Check L2 Redis before attempting lock acquisition.
	if entry, ok := c.getL2(ctx, digest); ok {
		c.setL1(digest, entry)
		return entry.AccessToken, nil
	}

	// If Redis is unavailable/unconfigured, refresh directly under singleflight.
	if c.redis == nil || c.redis.Client() == nil {
		entry, err := c.executeRefresh(ctx, refreshFn)
		if err != nil {
			return "", err
		}
		c.setL1(digest, entry)
		return entry.AccessToken, nil
	}

	lockKey := c.lockKey(digest)
	nonce := newLockNonce()

	acquired, lockErr := c.acquireLock(ctx, lockKey, nonce)
	if lockErr != nil {
		// Graceful degradation when Redis is unhealthy or circuit breaker is open.
		entry, err := c.executeRefresh(ctx, refreshFn)
		if err != nil {
			return "", err
		}
		c.setL1(digest, entry)
		return entry.AccessToken, nil
	}

	if acquired {
		defer c.releaseLock(context.WithoutCancel(ctx), lockKey, nonce)

		// Double-check L2 after acquiring lock in case the previous holder just wrote it.
		if entry, ok := c.getL2(ctx, digest); ok {
			c.setL1(digest, entry)
			return entry.AccessToken, nil
		}

		entry, err := c.executeRefresh(ctx, refreshFn)
		if err != nil {
			return "", err
		}
		c.setL1(digest, entry)
		c.setL2(ctx, digest, entry)
		return entry.AccessToken, nil
	}

	// Another pod holds the refresh lock; poll L2 until populated or wait timeout elapses.
	deadline := c.now().Add(c.lockWaitTimeout)
	for c.now().Before(deadline) {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(c.lockPollInterval):
		}

		if entry, ok := c.getL2(ctx, digest); ok {
			c.setL1(digest, entry)
			return entry.AccessToken, nil
		}

		// If the holder released/expired the lock without populating L2, try taking over.
		reacquired, reErr := c.acquireLock(ctx, lockKey, nonce)
		if reErr == nil && reacquired {
			defer c.releaseLock(context.WithoutCancel(ctx), lockKey, nonce)
			if entry, ok := c.getL2(ctx, digest); ok {
				c.setL1(digest, entry)
				return entry.AccessToken, nil
			}
			entry, err := c.executeRefresh(ctx, refreshFn)
			if err != nil {
				return "", err
			}
			c.setL1(digest, entry)
			c.setL2(ctx, digest, entry)
			return entry.AccessToken, nil
		}
	}

	// Wait timeout exceeded; perform fallback refresh so caller is not starved.
	entry, err := c.executeRefresh(ctx, refreshFn)
	if err != nil {
		return "", err
	}
	c.setL1(digest, entry)
	c.setL2(ctx, digest, entry)
	return entry.AccessToken, nil
}

func (c *DistributedTokenCache) executeRefresh(ctx context.Context, refreshFn TokenRefreshFunc) (CachedToken, error) {
	token, ttl, err := refreshFn(ctx)
	if err != nil {
		return CachedToken{}, err
	}
	if token == "" {
		return CachedToken{}, errors.New("token_cache: empty access token returned by refresh")
	}
	if ttl <= 0 {
		ttl = defaultTokenTTL
	}

	now := c.now().UTC()
	expiresAt := now.Add(ttl)

	skew := c.earlyRefreshSkew
	if ttl <= skew*3/2 {
		skew = ttl / 4
	}
	refreshAfter := expiresAt.Add(-skew)

	return CachedToken{
		AccessToken:  token,
		ExpiresAt:    expiresAt,
		RefreshAfter: refreshAfter,
	}, nil
}

func (c *DistributedTokenCache) isFresh(entry CachedToken) bool {
	if entry.AccessToken == "" {
		return false
	}
	now := c.now().UTC()
	if !entry.RefreshAfter.IsZero() {
		return now.Before(entry.RefreshAfter) && now.Before(entry.ExpiresAt)
	}
	return now.Add(c.earlyRefreshSkew).Before(entry.ExpiresAt)
}

func (c *DistributedTokenCache) getL1(digest string) (CachedToken, bool) {
	c.mu.RLock()
	entry, ok := c.l1[digest]
	c.mu.RUnlock()
	if !ok || !c.isFresh(entry) {
		return CachedToken{}, false
	}
	return entry, true
}

func (c *DistributedTokenCache) setL1(digest string, entry CachedToken) {
	c.mu.Lock()
	c.l1[digest] = entry
	c.mu.Unlock()
}

func (c *DistributedTokenCache) getL2(ctx context.Context, digest string) (CachedToken, bool) {
	if c.redis == nil || c.redis.Client() == nil {
		return CachedToken{}, false
	}
	dataKey := c.dataKey(digest)
	val, err := c.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
		return rdb.Get(ctx, dataKey).Bytes()
	})
	if err != nil {
		return CachedToken{}, false
	}
	raw, ok := val.([]byte)
	if !ok || len(raw) == 0 {
		return CachedToken{}, false
	}
	var entry CachedToken
	if err := json.Unmarshal(raw, &entry); err != nil {
		return CachedToken{}, false
	}
	if !c.isFresh(entry) {
		return CachedToken{}, false
	}
	return entry, true
}

func (c *DistributedTokenCache) setL2(ctx context.Context, digest string, entry CachedToken) {
	if c.redis == nil || c.redis.Client() == nil {
		return
	}
	ttl := entry.ExpiresAt.Sub(c.now().UTC())
	if ttl <= 0 {
		return
	}
	raw, err := json.Marshal(entry)
	if err != nil {
		return
	}
	dataKey := c.dataKey(digest)
	_, _ = c.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
		return rdb.Set(ctx, dataKey, raw, ttl).Result()
	})
}

func (c *DistributedTokenCache) acquireLock(ctx context.Context, lockKey, nonce string) (bool, error) {
	lockMillis := c.lockTTL.Milliseconds()
	if lockMillis <= 0 {
		lockMillis = 10000
	}
	res, err := c.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
		return rdb.Do(ctx, "SET", lockKey, nonce, "NX", "PX", lockMillis).Result()
	})
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return false, nil
		}
		return false, err
	}
	status, ok := res.(string)
	return ok && status == "OK", nil
}

func (c *DistributedTokenCache) releaseLock(ctx context.Context, lockKey, nonce string) {
	relCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	_, _ = c.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
		return releaseTokenLockScript.Run(relCtx, rdb, []string{lockKey}, nonce).Result()
	})
}

func (c *DistributedTokenCache) dataKey(digest string) string {
	return c.keyPrefix + digest
}

func (c *DistributedTokenCache) lockKey(digest string) string {
	return c.keyPrefix + "lock:" + digest
}

func hashTokenCacheKey(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

func newLockNonce() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("fallback-%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(b[:])
}
