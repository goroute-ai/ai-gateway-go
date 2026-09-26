package router

import (
	"container/list"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/observability"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/redis/go-redis/v9"
)

const (
	defaultAffinityMaxEntries        = 4096
	defaultAffinityTTL               = 30 * time.Minute
	defaultPromptCachePrefixMessages = 2
	defaultAffinityRedisReadTimeout  = 50 * time.Millisecond
	defaultAffinityRedisWriteTimeout = 200 * time.Millisecond
	maxAsyncAffinityWrites           = 64
)

// AffinityConfig configures session, response, and prompt-cache affinity tracking.
type AffinityConfig struct {
	MaxLocalEntries           int
	DefaultTTL                time.Duration
	RepinOnFailover           bool
	PromptCacheAffinity       bool
	PromptCachePrefixMessages int
	RedisReadTimeout          time.Duration
	RedisWriteTimeout         time.Duration
}

type affinityEntry struct {
	key       string
	depID     string
	expiresAt time.Time
	seq       uint64
}

type affinityLRU struct {
	mu       sync.Mutex
	capacity int
	seq      uint64
	items    map[string]*list.Element
	order    *list.List
}

func newAffinityLRU(capacity int) *affinityLRU {
	if capacity <= 0 {
		capacity = defaultAffinityMaxEntries
	}
	return &affinityLRU{
		capacity: capacity,
		items:    make(map[string]*list.Element, capacity),
		order:    list.New(),
	}
}

func (l *affinityLRU) get(key string, now time.Time) (string, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	elem, ok := l.items[key]
	if !ok {
		return "", false
	}
	entry := elem.Value.(affinityEntry)
	if !entry.expiresAt.IsZero() && !now.Before(entry.expiresAt) {
		delete(l.items, key)
		l.order.Remove(elem)
		return "", false
	}
	l.order.MoveToFront(elem)
	return entry.depID, true
}

func (l *affinityLRU) set(key, depID string, expiresAt time.Time) uint64 {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.seq++
	seq := l.seq
	if elem, ok := l.items[key]; ok {
		elem.Value = affinityEntry{
			key:       key,
			depID:     depID,
			expiresAt: expiresAt,
			seq:       seq,
		}
		l.order.MoveToFront(elem)
		return seq
	}
	if len(l.items) >= l.capacity {
		if oldest := l.order.Back(); oldest != nil {
			delete(l.items, oldest.Value.(affinityEntry).key)
			l.order.Remove(oldest)
		}
	}
	l.items[key] = l.order.PushFront(affinityEntry{
		key:       key,
		depID:     depID,
		expiresAt: expiresAt,
		seq:       seq,
	})
	return seq
}

func (l *affinityLRU) isLatestSeq(key string, seq uint64) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	elem, ok := l.items[key]
	if !ok {
		return false
	}
	return elem.Value.(affinityEntry).seq == seq
}

func (l *affinityLRU) len() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.items)
}

// AffinityStore resolves and pins deployment affinity across response chains,
// sessions, and prompt-cache prefixes using a bounded local LRU backed by Redis.
type AffinityStore struct {
	cfg       AffinityConfig
	lru       *affinityLRU
	redis     *storage.RedisFabric
	collector atomic.Pointer[observability.Collector]
	nowFn     func() time.Time
	sem       chan struct{}
	wg        sync.WaitGroup
}

// NewAffinityStore creates a new AffinityStore with a bounded process-local LRU
// and optional Redis backing.
func NewAffinityStore(redisFabric *storage.RedisFabric, cfg AffinityConfig) *AffinityStore {
	if cfg.MaxLocalEntries <= 0 {
		cfg.MaxLocalEntries = defaultAffinityMaxEntries
	}
	if cfg.DefaultTTL <= 0 {
		cfg.DefaultTTL = defaultAffinityTTL
	}
	if cfg.PromptCachePrefixMessages <= 0 {
		cfg.PromptCachePrefixMessages = defaultPromptCachePrefixMessages
	}
	if cfg.RedisReadTimeout <= 0 {
		cfg.RedisReadTimeout = defaultAffinityRedisReadTimeout
	}
	if cfg.RedisWriteTimeout <= 0 {
		cfg.RedisWriteTimeout = defaultAffinityRedisWriteTimeout
	}
	return &AffinityStore{
		cfg:   cfg,
		lru:   newAffinityLRU(cfg.MaxLocalEntries),
		redis: redisFabric,
		nowFn: time.Now,
		sem:   make(chan struct{}, maxAsyncAffinityWrites),
	}
}

// NewAffinityStoreFromRouterConfig constructs an AffinityStore from RouterConfig.
func NewAffinityStoreFromRouterConfig(redisFabric *storage.RedisFabric, cfg config.RouterConfig) *AffinityStore {
	ttl := cfg.SessionAffinityTTL
	if ttl <= 0 {
		ttl = defaultAffinityTTL
	}
	return NewAffinityStore(redisFabric, AffinityConfig{
		DefaultTTL:          ttl,
		RepinOnFailover:     cfg.SessionAffinityRepinOnFailover,
		PromptCacheAffinity: cfg.PromptCacheAffinity,
	})
}

// SetCollector attaches an observability collector for reporting Redis degradation.
func (s *AffinityStore) SetCollector(collector *observability.Collector) {
	if s == nil {
		return
	}
	s.collector.Store(collector)
}

// RepinOnFailover reports whether failover to a healthy deployment should update the affinity pin.
func (s *AffinityStore) RepinOnFailover() bool {
	return s != nil && s.cfg.RepinOnFailover
}

// DefaultTTL returns the configured affinity pin duration.
func (s *AffinityStore) DefaultTTL() time.Duration {
	if s == nil || s.cfg.DefaultTTL <= 0 {
		return defaultAffinityTTL
	}
	return s.cfg.DefaultTTL
}

func orgClusterHashTag(orgID string) string {
	orgID = strings.TrimSpace(orgID)
	if orgID == "" {
		orgID = "default"
	}
	return "{org:" + orgID + "}"
}

// ResponseAffinityKey returns the Redis Cluster slot-aligned key for a response ID.
func ResponseAffinityKey(orgID, respID string) string {
	return fmt.Sprintf("gw:affinity:%s:resp:%s", orgClusterHashTag(orgID), respID)
}

// SessionAffinityKey returns the Redis Cluster slot-aligned key for a session ID.
func SessionAffinityKey(orgID, sessionID string) string {
	return fmt.Sprintf("gw:affinity:%s:session:%s", orgClusterHashTag(orgID), sessionID)
}

// PromptCacheAffinityKey returns the Redis Cluster slot-aligned key for a prompt prefix hash.
func PromptCacheAffinityKey(orgID, groupAlias, prefixHash string) string {
	groupAlias = strings.TrimSpace(groupAlias)
	if groupAlias == "" {
		groupAlias = "default"
	}
	return fmt.Sprintf("gw:affinity:%s:pcache:%s:%s", orgClusterHashTag(orgID), groupAlias, prefixHash)
}

// SensitiveRouteKey returns the cluster-hash-tagged Redis key pinning a session's private route target.
func SensitiveRouteKey(orgID, sessionID string) string {
	return fmt.Sprintf("gw:affinity:%s:sensitive_route:%s", orgClusterHashTag(orgID), sessionID)
}

// GetSensitiveRoute returns any previously pinned private/compliance model target for (orgID, sessionID).
func (s *AffinityStore) GetSensitiveRoute(ctx context.Context, orgID, sessionID string) string {
	if s == nil {
		return ""
	}
	sessionID = strings.TrimSpace(sessionID)
	if sessionID == "" {
		return ""
	}
	key := SensitiveRouteKey(orgID, sessionID)
	now := s.nowFn()
	if target, ok := s.lru.get(key, now); ok && target != "" {
		return target
	}
	if target := s.getRedis(ctx, key); target != "" {
		s.lru.set(key, target, now.Add(s.DefaultTTL()))
		return target
	}
	return ""
}

// SetSensitiveRoute pins (orgID, sessionID) to a designated private model target for session affinity duration.
func (s *AffinityStore) SetSensitiveRoute(ctx context.Context, orgID, sessionID, target string) {
	if s == nil {
		return
	}
	sessionID = strings.TrimSpace(sessionID)
	target = strings.TrimSpace(target)
	if sessionID == "" || target == "" {
		return
	}
	key := SensitiveRouteKey(orgID, sessionID)
	expiresAt := s.nowFn().Add(s.DefaultTTL())
	s.lru.set(key, target, expiresAt)
	if s.redis != nil && s.redis.Client() != nil {
		ttl := s.DefaultTTL()
		_, _ = s.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
			rCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 100*time.Millisecond)
			defer cancel()
			return rdb.Set(rCtx, key, target, ttl).Result()
		})
	}
}

func writeLenString(h hash.Hash, s string) {
	var lenBuf [8]byte
	binary.BigEndian.PutUint64(lenBuf[:], uint64(len(s)))
	_, _ = h.Write(lenBuf[:])
	_, _ = h.Write([]byte(s))
}

// ComputePromptPrefixHash computes a deterministic SHA-256 hex digest of the
// first maxMessages system, developer, or user messages in req.
func ComputePromptPrefixHash(req *domain.CanonicalChatRequest, maxMessages int) string {
	if req == nil || len(req.Messages) == 0 {
		return ""
	}
	if maxMessages <= 0 {
		maxMessages = defaultPromptCachePrefixMessages
	}
	h := sha256.New()
	matched := 0
	for _, msg := range req.Messages {
		role := strings.ToLower(strings.TrimSpace(msg.Role))
		if role != "system" && role != "developer" && role != "user" {
			continue
		}
		writeLenString(h, role)
		writeLenString(h, msg.Content)
		if msg.Content == "" && len(msg.Parts) > 0 {
			for _, part := range msg.Parts {
				writeLenString(h, part.Type)
				writeLenString(h, part.Text)
				if part.ImageURL != nil {
					writeLenString(h, part.ImageURL.URL)
				}
				if part.Document != nil {
					writeLenString(h, part.Document.URL)
					writeLenString(h, part.Document.Filename)
				}
			}
		}
		matched++
		if matched >= maxMessages {
			break
		}
	}
	if matched == 0 {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Lookup resolves the preferred or previously pinned deployment ID and primary
// affinity key for the request following precedence:
// PreferredDeploymentID -> respID -> sessionID -> pcache.
func (s *AffinityStore) Lookup(ctx context.Context, orgID, groupAlias string, req *domain.CanonicalChatRequest, prevRespID string) (depID string, key string) {
	if s == nil {
		return "", ""
	}
	var keys []string
	if trimmedResp := strings.TrimSpace(prevRespID); trimmedResp != "" {
		keys = append(keys, ResponseAffinityKey(orgID, trimmedResp))
	}
	var preferred string
	if req != nil && req.GoRouteExtensions != nil {
		preferred = strings.TrimSpace(req.GoRouteExtensions.PreferredDeploymentID)
		if sessID := strings.TrimSpace(req.GoRouteExtensions.SessionID); sessID != "" {
			keys = append(keys, SessionAffinityKey(orgID, sessID))
		}
	}
	if s.cfg.PromptCacheAffinity {
		if prefixHash := ComputePromptPrefixHash(req, s.cfg.PromptCachePrefixMessages); prefixHash != "" {
			keys = append(keys, PromptCacheAffinityKey(orgID, groupAlias, prefixHash))
		}
	}

	primaryKey := ""
	if len(keys) > 0 {
		primaryKey = keys[0]
	}
	if preferred != "" {
		return preferred, primaryKey
	}
	if len(keys) == 0 {
		return "", ""
	}

	now := s.nowFn()
	for _, candidateKey := range keys {
		if id, ok := s.lru.get(candidateKey, now); ok && id != "" {
			return id, candidateKey
		}
		if id := s.getRedis(ctx, candidateKey); id != "" {
			s.lru.set(candidateKey, id, now.Add(s.DefaultTTL()))
			return id, candidateKey
		}
	}
	return "", primaryKey
}

// SelectOrPin returns the matching deployment from candidates when depID is
// present in candidates. Otherwise it returns (nil, false) so callers can select
// an alternative healthy deployment and optionally re-pin.
func (s *AffinityStore) SelectOrPin(depID string, candidates []*domain.Deployment) (*domain.Deployment, bool) {
	if depID == "" || len(candidates) == 0 {
		return nil, false
	}
	for _, dep := range candidates {
		if dep != nil && dep.ID == depID {
			return dep, true
		}
	}
	return nil, false
}

// PinAsync synchronously stores the affinity mapping in the process-local LRU
// and asynchronously persists it to Redis with a bounded timeout.
func (s *AffinityStore) PinAsync(orgID, key, depID string, ttl time.Duration) {
	if s == nil || key == "" || depID == "" {
		return
	}
	if ttl <= 0 {
		ttl = s.DefaultTTL()
	}
	expiresAt := s.nowFn().Add(ttl)
	seq := s.lru.set(key, depID, expiresAt)

	if s.redis == nil || s.redis.Client() == nil {
		return
	}

	s.wg.Add(1)
	select {
	case s.sem <- struct{}{}:
		go func() {
			defer func() {
				<-s.sem
				s.wg.Done()
			}()
			if !s.lru.isLatestSeq(key, seq) {
				return
			}
			rCtx, cancel := context.WithTimeout(context.Background(), s.cfg.RedisWriteTimeout)
			defer cancel()
			_, err := s.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
				return rdb.Set(rCtx, key, depID, ttl).Result()
			})
			if err != nil {
				s.recordDegraded()
			}
		}()
	default:
		s.wg.Done()
		s.recordDegraded()
	}
}

// Wait blocks until all in-flight asynchronous Redis pin writes complete or ctx ends.
func (s *AffinityStore) Wait(ctx context.Context) error {
	if s == nil {
		return nil
	}
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (s *AffinityStore) getRedis(ctx context.Context, key string) string {
	if s.redis == nil || s.redis.Client() == nil {
		return ""
	}
	if ctx == nil {
		ctx = context.Background()
	}
	rCtx, cancel := context.WithTimeout(ctx, s.cfg.RedisReadTimeout)
	defer cancel()
	val, err := s.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
		return rdb.Get(rCtx, key).Result()
	})
	if err != nil {
		if !errors.Is(err, redis.Nil) {
			s.recordDegraded()
		}
		return ""
	}
	depID, _ := val.(string)
	return depID
}

func (s *AffinityStore) recordDegraded() {
	if c := s.collector.Load(); c != nil {
		c.RecordRoutingSignalDegraded()
	}
}
