package mcp

import (
	"container/list"
	"context"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"strings"
	"sync"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/redis/go-redis/v9"
)

const (
	maxMCPCacheMemEntries   = 4096
	mcpMethodServerDiscover = "server/discover"
	mcpMethodToolsList      = "tools/list"
	mcpMethodToolsCall      = "tools/call"
)

// MCPCache provides high-performance length-prefixed HMAC caching for MCP operations.
type MCPCache struct {
	secret   []byte
	redis    *storage.RedisFabric
	memMu    sync.Mutex
	memStore map[string]*list.Element
	memLRU   *list.List
	maxMem   int
}

type cacheEntry struct {
	key       string
	data      []byte
	expiresAt time.Time
}

// NewMCPCacheStrict creates a new MCP cache instance and fails if no HMAC secret is configured.
func NewMCPCacheStrict(secret []byte, redis *storage.RedisFabric) (*MCPCache, error) {
	if len(secret) == 0 {
		return nil, errors.New("mcp cache: HMAC secret must be configured")
	}
	cp := make([]byte, len(secret))
	copy(cp, secret)
	return &MCPCache{
		secret:   cp,
		redis:    redis,
		memStore: make(map[string]*list.Element),
		memLRU:   list.New(),
		maxMem:   maxMCPCacheMemEntries,
	}, nil
}

// DeriveCacheKeySecret returns an explicit MCP cache HMAC secret or derives a domain-separated
// 32-byte subkey via HKDF-SHA256 from masterEncryptionKey so raw KEK bytes are never reused directly.
func DeriveCacheKeySecret(cacheKeySecret, masterEncryptionKey string) []byte {
	if trimmed := strings.TrimSpace(cacheKeySecret); trimmed != "" {
		return []byte(trimmed)
	}
	if seed := strings.TrimSpace(masterEncryptionKey); seed != "" {
		derived, err := hkdf.Key(sha256.New, []byte(seed), nil, "goroute-mcp-cache-hmac-v1", 32)
		if err == nil {
			return derived
		}
	}
	return nil
}

// IsCacheableDiscoveryMethod reports whether method is a read-only discovery RPC eligible for MCP caching.
func IsCacheableDiscoveryMethod(method string) bool {
	switch method {
	case mcpMethodServerDiscover, mcpMethodToolsList, "resources/list", "resources/templates/list", "prompts/list":
		return true
	default:
		return false
	}
}

func normalizeCacheParams(raw json.RawMessage) []byte {
	if len(raw) == 0 {
		return nil
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		return raw
	}
	delete(m, "_meta")
	if len(m) == 0 {
		return nil
	}
	canon, err := json.Marshal(m)
	if err != nil {
		return raw
	}
	return canon
}

func extractTTLMs(val any) (int64, bool) {
	switch ttl := val.(type) {
	case int:
		return int64(ttl), true
	case int64:
		return ttl, true
	case float64:
		return int64(ttl), true
	case json.Number:
		if n, err := ttl.Int64(); err == nil {
			return n, true
		}
	}
	return 0, false
}

// CacheTTL computes the effective cache TTL from a result's ttlMs field, falling back to defaultTTL.
func CacheTTL(resp *JSONRPCResponse, defaultTTL time.Duration) time.Duration {
	if resp == nil {
		return defaultTTL
	}
	if resMap, ok := resp.Result.(map[string]any); ok {
		if ttlMs, hasTTL := extractTTLMs(resMap["ttlMs"]); hasTTL && ttlMs > 0 {
			return time.Duration(ttlMs) * time.Millisecond
		}
	}
	return defaultTTL
}

// NewMCPCache creates a new MCP cache instance. If secret is empty, a random per-process
// ephemeral secret is generated so no hardcoded fallback secret is ever used.
func NewMCPCache(secret []byte, redis *storage.RedisFabric) *MCPCache {
	if len(secret) == 0 {
		ephemeral := make([]byte, 32)
		if _, err := rand.Read(ephemeral); err != nil {
			panic("mcp cache: failed to generate random HMAC secret: " + err.Error())
		}
		secret = ephemeral
	}
	c, _ := NewMCPCacheStrict(secret, redis)
	return c
}

// ComputeCacheKey generates a length-prefixed, collision-resistant HMAC-SHA256 cache key.
func (c *MCPCache) ComputeCacheKey(
	orgID string,
	keyPrefix string,
	serverSlug string,
	method string,
	params []byte,
	configVersion int64,
) string {
	mac := hmac.New(sha256.New, c.secret)

	// Write length-prefixed segments: len(field):field
	writeSegment := func(field []byte) {
		lenPrefix := fmt.Sprintf("%d:", len(field))
		mac.Write([]byte(lenPrefix))
		mac.Write(field)
		mac.Write([]byte("|"))
	}

	writeSegment([]byte(orgID))
	writeSegment([]byte(keyPrefix))
	writeSegment([]byte(serverSlug))
	writeSegment([]byte(method))
	writeSegment(params)
	writeSegment([]byte(fmt.Sprintf("%d", configVersion)))

	return "gw:mcp:cache:" + hex.EncodeToString(mac.Sum(nil))
}

// ShouldCache inspects the method and JSON-RPC response structure to ensure safety and CacheableResult rules.
// Never caches InputRequiredResult, input_required, requestState, ttlMs=0, or session-bound structures.
func ShouldCache(method string, resp *JSONRPCResponse) bool {
	if resp == nil || resp.Error != nil {
		return false
	}

	resMap := inspectResultMap(resp.Result)
	if hasUncacheableResultFields(resMap) {
		return false
	}

	hasExplicitPositiveTTL, scope, validDirectives := extractCacheableToolDirectives(resMap)
	if !validDirectives {
		return false
	}

	if IsCacheableDiscoveryMethod(method) {
		return true
	}
	if method == mcpMethodToolsCall {
		// Opt-in CacheableResult only: positive ttlMs and valid public/private cacheScope.
		return hasExplicitPositiveTTL && (scope == "public" || scope == "private")
	}
	return false
}

func hasUncacheableResultFields(resMap map[string]any) bool {
	if resMap == nil {
		return false
	}
	if rt, _ := resMap["resultType"].(string); strings.EqualFold(rt, "input_required") {
		return true
	}
	if typ, _ := resMap["type"].(string); strings.EqualFold(typ, "InputRequiredResult") {
		return true
	}
	if rs, _ := resMap["requestState"].(string); strings.TrimSpace(rs) != "" {
		return true
	}
	if ir, hasIR := resMap["inputRequests"]; hasIR && ir != nil {
		if irMap, ok := ir.(map[string]any); !ok || len(irMap) > 0 {
			return true
		}
	}
	return hasUncacheableMetaFields(resMap)
}

func hasUncacheableMetaFields(resMap map[string]any) bool {
	metaMap, ok := resMap["_meta"].(map[string]any)
	if !ok {
		return false
	}
	if rs, _ := metaMap["requestState"].(string); strings.TrimSpace(rs) != "" {
		return true
	}
	if tok, _ := metaMap["mrtrToken"].(string); strings.TrimSpace(tok) != "" {
		return true
	}
	req, _ := metaMap["inputRequired"].(bool)
	return req
}

func extractCacheableToolDirectives(resMap map[string]any) (bool, string, bool) {
	if resMap == nil {
		return false, "", true
	}
	var hasExplicitPositiveTTL bool
	if ttlVal, exists := resMap["ttlMs"]; exists {
		ttlMs, ok := extractTTLMs(ttlVal)
		if !ok || ttlMs <= 0 {
			return false, "", false
		}
		hasExplicitPositiveTTL = true
	}
	var scope string
	if sc, ok := resMap["cacheScope"].(string); ok && sc != "" {
		if sc != "public" && sc != "private" {
			return false, "", false
		}
		scope = sc
	}
	return hasExplicitPositiveTTL, scope, true
}

func inspectResultMap(res any) map[string]any {
	if res == nil {
		return nil
	}
	if m, ok := res.(map[string]any); ok {
		return m
	}
	m, err := resultAsMap(res)
	if err != nil {
		return nil
	}
	return m
}

func resultAsMap(res any) (map[string]any, error) {
	if res == nil {
		return nil, nil
	}
	if m, ok := res.(map[string]any); ok {
		return maps.Clone(m), nil
	}
	b, err := json.Marshal(res)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// Get retrieves a cached JSONRPCResponse if present and unexpired.
func (c *MCPCache) Get(ctx context.Context, key string) (*JSONRPCResponse, bool) {
	if c.redis != nil {
		res, err := c.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
			return rdb.Get(ctx, key).Result()
		})
		if err == nil {
			if dataStr, ok := res.(string); ok && dataStr != "" {
				var resp JSONRPCResponse
				if err := json.Unmarshal([]byte(dataStr), &resp); err == nil {
					return &resp, true
				}
			}
		}
	}

	c.memMu.Lock()
	defer c.memMu.Unlock()
	elem, ok := c.memStore[key]
	if !ok {
		return nil, false
	}
	entry := elem.Value.(*cacheEntry)
	if time.Now().After(entry.expiresAt) {
		c.memLRU.Remove(elem)
		delete(c.memStore, key)
		return nil, false
	}
	c.memLRU.MoveToFront(elem)

	var resp JSONRPCResponse
	if err := json.Unmarshal(entry.data, &resp); err != nil {
		return nil, false
	}
	return &resp, true
}

// Set stores a JSONRPCResponse in the cache with the specified TTL.
func (c *MCPCache) Set(ctx context.Context, key string, resp *JSONRPCResponse, ttl time.Duration) error {
	if resp == nil || ttl <= 0 {
		return nil
	}

	data, err := json.Marshal(resp)
	if err != nil {
		return err
	}

	if c.redis != nil {
		_, _ = c.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
			return rdb.Set(ctx, key, string(data), ttl).Result()
		})
	}

	c.memMu.Lock()
	defer c.memMu.Unlock()
	now := time.Now()
	if elem, ok := c.memStore[key]; ok {
		entry := elem.Value.(*cacheEntry)
		entry.data = data
		entry.expiresAt = now.Add(ttl)
		c.memLRU.MoveToFront(elem)
		return nil
	}
	for c.memLRU.Len() >= c.maxMem {
		tail := c.memLRU.Back()
		if tail == nil {
			break
		}
		tailEntry := tail.Value.(*cacheEntry)
		c.memLRU.Remove(tail)
		delete(c.memStore, tailEntry.key)
	}
	if tail := c.memLRU.Back(); tail != nil {
		if tailEntry := tail.Value.(*cacheEntry); now.After(tailEntry.expiresAt) {
			c.memLRU.Remove(tail)
			delete(c.memStore, tailEntry.key)
		}
	}
	elem := c.memLRU.PushFront(&cacheEntry{
		key:       key,
		data:      data,
		expiresAt: now.Add(ttl),
	})
	c.memStore[key] = elem
	return nil
}

// InvalidateKey deletes a cache entry by key.
func (c *MCPCache) InvalidateKey(ctx context.Context, key string) error {
	if c.redis != nil {
		_, _ = c.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
			return rdb.Del(ctx, key).Result()
		})
	}

	c.memMu.Lock()
	defer c.memMu.Unlock()
	if elem, ok := c.memStore[key]; ok {
		c.memLRU.Remove(elem)
		delete(c.memStore, key)
	}
	return nil
}
