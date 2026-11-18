package auth

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/redis/go-redis/v9"
	"golang.org/x/crypto/scrypt"
)

const (
	// ScryptDefaultN is the default CPU/memory cost parameter (2^15) for password hashing.
	ScryptDefaultN = 32768
	// ScryptDefaultR is the default block size parameter for scrypt.
	ScryptDefaultR = 8
	// ScryptDefaultP is the default parallelization parameter for scrypt.
	ScryptDefaultP = 1
	// ScryptDefaultSaltBytes is the per-password cryptographic salt length in bytes.
	ScryptDefaultSaltBytes = 16
	// ScryptDefaultKeyLen is the derived key length in bytes.
	ScryptDefaultKeyLen = 32

	// DefaultLoginMaxAttempts is the number of consecutive failed login attempts before lockout.
	DefaultLoginMaxAttempts = 5
	// DefaultLoginLockoutDuration is the duration an (email, client_ip) tuple remains locked after 5 failures.
	DefaultLoginLockoutDuration = 300 * time.Second

	// DefaultHIBPRangeBaseURL is the default Have I Been Pwned k-anonymity range API base URL.
	DefaultHIBPRangeBaseURL = "https://api.pwnedpasswords.com/range"
)

// HashPasswordScrypt hashes a plaintext password using golang.org/x/crypto/scrypt (N=32768, r=8, p=1)
// with a fresh 16-byte cryptographic random salt, returning `scrypt:32768:8:1:<salt_hex>:<hash_hex>`.
func HashPasswordScrypt(password string) (string, error) {
	return HashPasswordScryptWithCost(password, ScryptDefaultN, ScryptDefaultR, ScryptDefaultP)
}

// HashPasswordScryptWithCost hashes a plaintext password using golang.org/x/crypto/scrypt
// with explicit (N, r, p) parameters and a fresh 16-byte random salt.
func HashPasswordScryptWithCost(password string, n, r, p int) (string, error) {
	if password == "" {
		return "", errors.New("password cannot be empty")
	}
	salt := make([]byte, ScryptDefaultSaltBytes)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate password salt: %w", err)
	}
	dk, err := scrypt.Key([]byte(password), salt, n, r, p, ScryptDefaultKeyLen)
	if err != nil {
		return "", fmt.Errorf("derive scrypt key: %w", err)
	}
	return fmt.Sprintf(
		"scrypt:%d:%d:%d:%s:%s",
		n,
		r,
		p,
		hex.EncodeToString(salt),
		hex.EncodeToString(dk),
	), nil
}

// VerifyPassword verifies a plaintext password against a stored `scrypt:<N>:<r>:<p>:<salt_hex>:<hash_hex>`
// digest in constant time, returning `needsUpgrade = true` when a weaker scrypt cost parameter matched.
func VerifyPassword(password, storedHash string) (valid bool, needsUpgrade bool) {
	storedHash = strings.TrimSpace(storedHash)
	if password == "" || !strings.HasPrefix(storedHash, "scrypt:") {
		return false, false
	}
	parts := strings.Split(storedHash, ":")
	if len(parts) != 6 {
		return false, false
	}
	n, errN := strconv.Atoi(parts[1])
	r, errR := strconv.Atoi(parts[2])
	p, errP := strconv.Atoi(parts[3])
	if errN != nil || errR != nil || errP != nil || n <= 1 || r <= 0 || p <= 0 {
		return false, false
	}
	salt, errSalt := hex.DecodeString(parts[4])
	expected, errHash := hex.DecodeString(parts[5])
	if errSalt != nil || errHash != nil || len(salt) == 0 || len(expected) == 0 {
		return false, false
	}
	derived, err := scrypt.Key([]byte(password), salt, n, r, p, len(expected))
	if err != nil {
		return false, false
	}
	if subtle.ConstantTimeCompare(derived, expected) != 1 {
		return false, false
	}
	upgrade := n < ScryptDefaultN || r < ScryptDefaultR || p < ScryptDefaultP
	return true, upgrade
}

type loginThrottleEntry struct {
	attempts    int
	lockedUntil time.Time
	expiresAt   time.Time
}

// LoginThrottle enforces brute-force lockout per (email, client_ip) tuple, locking for 300s after 5 consecutive failures.
// It uses Redis when available and automatically falls back to thread-safe in-memory state.
type LoginThrottle struct {
	redis           *storage.RedisFabric
	maxAttempts     int
	lockoutDuration time.Duration
	mu              sync.Mutex
	entries         map[string]*loginThrottleEntry
	now             func() time.Time
}

// NewLoginThrottle constructs a LoginThrottle with the default 5-attempt / 300s lockout policy.
func NewLoginThrottle(redisFabric *storage.RedisFabric) *LoginThrottle {
	return NewLoginThrottleWithConfig(redisFabric, DefaultLoginMaxAttempts, DefaultLoginLockoutDuration)
}

// NewLoginThrottleWithConfig constructs a LoginThrottle with custom maxAttempts and lockoutDuration.
func NewLoginThrottleWithConfig(redisFabric *storage.RedisFabric, maxAttempts int, lockoutDuration time.Duration) *LoginThrottle {
	if maxAttempts <= 0 {
		maxAttempts = DefaultLoginMaxAttempts
	}
	if lockoutDuration <= 0 {
		lockoutDuration = DefaultLoginLockoutDuration
	}
	return &LoginThrottle{
		redis:           redisFabric,
		maxAttempts:     maxAttempts,
		lockoutDuration: lockoutDuration,
		entries:         make(map[string]*loginThrottleEntry),
		now:             time.Now,
	}
}

// SetNowFunc overrides the clock function for deterministic lockout testing.
func (t *LoginThrottle) SetNowFunc(fn func() time.Time) {
	if t == nil || fn == nil {
		return
	}
	t.mu.Lock()
	t.now = fn
	t.mu.Unlock()
}

func (t *LoginThrottle) currentTime() time.Time {
	t.mu.Lock()
	fn := t.now
	t.mu.Unlock()
	if fn == nil {
		return time.Now().UTC()
	}
	return fn().UTC()
}

func loginThrottleKey(email, clientIP string) string {
	normEmail := strings.ToLower(strings.TrimSpace(email))
	normIP := strings.TrimSpace(clientIP)
	sum := sha256.Sum256([]byte(normEmail + "|" + normIP))
	return hex.EncodeToString(sum[:])
}

func loginThrottleRedisCountKey(hash string) string {
	return "gw:auth:login_throttle:count:" + hash
}

func loginThrottleRedisLockKey(hash string) string {
	return "gw:auth:login_throttle:lock:" + hash
}

// IsLocked reports whether (email, clientIP) is currently locked out and returns the remaining lockout duration.
func (t *LoginThrottle) IsLocked(ctx context.Context, email, clientIP string) (bool, time.Duration) {
	if t == nil {
		return false, 0
	}
	now := t.currentTime()
	key := loginThrottleKey(email, clientIP)

	if t.redis != nil {
		res, err := t.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
			return rdb.Get(ctx, loginThrottleRedisLockKey(key)).Result()
		})
		if err == nil {
			if raw, ok := res.(string); ok && raw != "" {
				if untilUnixNano, parseErr := strconv.ParseInt(raw, 10, 64); parseErr == nil {
					until := time.Unix(0, untilUnixNano).UTC()
					if now.Before(until) {
						return true, until.Sub(now)
					}
				}
			}
		}
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	entry, ok := t.entries[key]
	if !ok || entry == nil {
		return false, 0
	}
	if !entry.lockedUntil.IsZero() {
		if now.Before(entry.lockedUntil) {
			return true, entry.lockedUntil.Sub(now)
		}
		delete(t.entries, key)
		return false, 0
	}
	if !entry.expiresAt.IsZero() && !now.Before(entry.expiresAt) {
		delete(t.entries, key)
		return false, 0
	}
	return false, 0
}

// Check returns a 429 GatewayError if (email, clientIP) is currently locked out.
func (t *LoginThrottle) Check(ctx context.Context, email, clientIP string) error {
	if locked, retryAfter := t.IsLocked(ctx, email, clientIP); locked {
		secs := int(retryAfter.Seconds())
		if secs <= 0 {
			secs = 1
		}
		return &domain.GatewayError{
			StatusCode: http.StatusTooManyRequests,
			Type:       domain.ErrorTypeRateLimit,
			Code:       "login_throttled",
			Message:    fmt.Sprintf("Too many failed login attempts; account locked for %ds", secs),
			Retryable:  true,
		}
	}
	return nil
}

// RecordFailure increments the consecutive failure count for (email, clientIP) and locks the tuple
// for 300s once 5 consecutive failures have been recorded.
func (t *LoginThrottle) RecordFailure(ctx context.Context, email, clientIP string) (attempts int, locked bool, retryAfter time.Duration) {
	if t == nil {
		return 0, false, 0
	}
	now := t.currentTime()
	key := loginThrottleKey(email, clientIP)

	t.mu.Lock()
	entry, ok := t.entries[key]
	if !ok || entry == nil || (!entry.expiresAt.IsZero() && !now.Before(entry.expiresAt)) || (!entry.lockedUntil.IsZero() && !now.Before(entry.lockedUntil)) {
		entry = &loginThrottleEntry{}
		t.entries[key] = entry
	}
	if !entry.lockedUntil.IsZero() && now.Before(entry.lockedUntil) {
		rem := entry.lockedUntil.Sub(now)
		att := entry.attempts
		t.mu.Unlock()
		return att, true, rem
	}
	entry.attempts++
	entry.expiresAt = now.Add(t.lockoutDuration)
	attempts = entry.attempts
	var lockedUntil time.Time
	if attempts >= t.maxAttempts {
		lockedUntil = now.Add(t.lockoutDuration)
		entry.lockedUntil = lockedUntil
		locked = true
		retryAfter = t.lockoutDuration
	}
	t.mu.Unlock()

	if t.redis != nil {
		res, err := t.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
			cnt, incrErr := rdb.Incr(ctx, loginThrottleRedisCountKey(key)).Result()
			if incrErr != nil {
				return nil, incrErr
			}
			if cnt == 1 {
				_ = rdb.Expire(ctx, loginThrottleRedisCountKey(key), t.lockoutDuration).Err()
			}
			if int(cnt) >= t.maxAttempts {
				until := now.Add(t.lockoutDuration)
				_ = rdb.Set(ctx, loginThrottleRedisLockKey(key), strconv.FormatInt(until.UnixNano(), 10), t.lockoutDuration).Err()
			}
			return cnt, nil
		})
		if err == nil {
			if cnt, ok := res.(int64); ok {
				attempts = int(cnt)
				if attempts >= t.maxAttempts {
					locked = true
					retryAfter = t.lockoutDuration
					t.mu.Lock()
					if e := t.entries[key]; e != nil {
						e.attempts = attempts
						e.lockedUntil = now.Add(t.lockoutDuration)
					}
					t.mu.Unlock()
				}
			}
		}
	}

	return attempts, locked, retryAfter
}

// RecordSuccess clears any recorded login failures or lockout state for (email, clientIP).
func (t *LoginThrottle) RecordSuccess(ctx context.Context, email, clientIP string) {
	if t == nil {
		return
	}
	key := loginThrottleKey(email, clientIP)
	t.mu.Lock()
	delete(t.entries, key)
	t.mu.Unlock()

	if t.redis != nil {
		_, _ = t.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
			return rdb.Del(ctx, loginThrottleRedisCountKey(key), loginThrottleRedisLockKey(key)).Result()
		})
	}
}

// BreachScreener checks a 40-character SHA-1 hex digest against a k-anonymity breach range API.
type BreachScreener interface {
	CheckDigest(ctx context.Context, sha1Hex string) (bool, error)
}

// HIBPRangeClient queries the Have I Been Pwned k-anonymity range endpoint (`/range/<5hex>`)
// strictly through network.NewHTTPClient(netPolicy) without touching plaintext passwords.
type HIBPRangeClient struct {
	baseURL   string
	netPolicy *network.Policy
}

// NewHIBPRangeClient constructs an HIBPRangeClient bound to an outbound network.Policy.
func NewHIBPRangeClient(rangeBaseURL string, netPolicy *network.Policy) *HIBPRangeClient {
	trimmed := strings.TrimRight(strings.TrimSpace(rangeBaseURL), "/")
	if trimmed == "" {
		trimmed = DefaultHIBPRangeBaseURL
	}
	return &HIBPRangeClient{
		baseURL:   trimmed,
		netPolicy: netPolicy,
	}
}

// CheckDigest validates that sha1Hex is a 40-character hex digest, sends only its 5-character
// uppercase prefix to `<baseURL>/range/<5hex>` (or `<baseURL>/<5hex>` if `/range` is already the base suffix),
// and checks the remaining 35-character suffix locally in constant time.
func (c *HIBPRangeClient) CheckDigest(ctx context.Context, sha1Hex string) (bool, error) {
	if c == nil {
		return false, nil
	}
	normalized := strings.ToUpper(strings.TrimSpace(sha1Hex))
	if normalized == "" {
		return false, nil
	}
	if len(normalized) != 40 {
		return false, errors.New("hibp: sha1Hex must be 40 hex characters")
	}
	if decoded, err := hex.DecodeString(normalized); err != nil || len(decoded) != 20 {
		return false, errors.New("hibp: invalid sha1Hex encoding")
	}

	prefix := normalized[:5]
	suffix := normalized[5:]

	base := strings.TrimRight(c.baseURL, "/")
	if base == "" {
		base = DefaultHIBPRangeBaseURL
	}
	var reqURL string
	if strings.HasSuffix(base, "/range") {
		reqURL = base + "/" + prefix
	} else {
		reqURL = base + "/range/" + prefix
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return false, fmt.Errorf("hibp: build request: %w", err)
	}
	req.Header.Set("Add-Padding", "true")
	req.Header.Set("User-Agent", "GoRoute-AI-Gateway")

	client := network.NewHTTPClient(c.netPolicy)
	resp, err := client.Do(req)
	if err != nil {
		return false, fmt.Errorf("hibp: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("hibp: unexpected status %d", resp.StatusCode)
	}

	scanner := bufio.NewScanner(io.LimitReader(resp.Body, 1<<20))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		lineSuffix, countStr, hasColon := strings.Cut(line, ":")
		if !hasColon {
			continue
		}
		lineSuffix = strings.TrimSpace(lineSuffix)
		if len(lineSuffix) != 35 {
			continue
		}
		count, err := strconv.Atoi(strings.TrimSpace(countStr))
		if err != nil || count <= 0 {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(strings.ToUpper(lineSuffix)), []byte(suffix)) == 1 {
			return true, nil
		}
	}
	if err := scanner.Err(); err != nil {
		return false, fmt.Errorf("hibp: read response: %w", err)
	}
	return false, nil
}
