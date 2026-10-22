package mcp

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/redis/go-redis/v9"
)

// MCPCache provides high-performance length-prefixed HMAC caching for MCP operations.
type MCPCache struct {
	secret   []byte
	redis    *storage.RedisFabric
	memMu    sync.RWMutex
	memStore map[string]cacheEntry
}

type cacheEntry struct {
	data      []byte
	expiresAt time.Time
}

// NewMCPCache creates a new MCP cache instance.
func NewMCPCache(secret []byte, redis *storage.RedisFabric) *MCPCache {
	if len(secret) == 0 {
		secret = []byte("default-mcp-cache-hmac-secret")
	}
	return &MCPCache{
		secret:   secret,
		redis:    redis,
		memStore: make(map[string]cacheEntry),
	}
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

// ShouldCache inspects the method and JSON-RPC response to ensure safety.
// Never caches InputRequiredResult, requestState, or session-bound structures.
func ShouldCache(method string, resp *JSONRPCResponse) bool {
	if resp == nil || resp.Error != nil {
		return false
	}

	// Always cache discovery methods
	if method == "tools/list" || method == "resources/list" || method == "prompts/list" {
		return true
	}

	// For tools/call: inspect result payload
	resultBytes, err := json.Marshal(resp.Result)
	if err != nil {
		return false
	}

	// Forbid caching interactive or stateful results
	lower := bytes.ToLower(resultBytes)
	if bytes.Contains(lower, []byte("inputrequiredresult")) ||
		bytes.Contains(lower, []byte("requeststate")) ||
		bytes.Contains(lower, []byte("mrtr_")) {
		return false
	}

	return false // Non-discovery methods default to non-cacheable unless explicitly enabled
}

// Get retrieves a cached JSONRPCResponse if present and unexpired.
func (c *MCPCache) Get(ctx context.Context, key string) (*JSONRPCResponse, bool) {
	if c.redis != nil {
		res, err := c.redis.Execute(func(rdb *redis.Client) (any, error) {
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

	c.memMu.RLock()
	defer c.memMu.RUnlock()
	entry, ok := c.memStore[key]
	if !ok || time.Now().After(entry.expiresAt) {
		return nil, false
	}

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
		_, _ = c.redis.Execute(func(rdb *redis.Client) (any, error) {
			return rdb.Set(ctx, key, string(data), ttl).Result()
		})
	}

	c.memMu.Lock()
	defer c.memMu.Unlock()
	c.memStore[key] = cacheEntry{
		data:      data,
		expiresAt: time.Now().Add(ttl),
	}
	return nil
}

// InvalidateKey deletes a cache entry by key.
func (c *MCPCache) InvalidateKey(ctx context.Context, key string) error {
	if c.redis != nil {
		_, _ = c.redis.Execute(func(rdb *redis.Client) (any, error) {
			return rdb.Del(ctx, key).Result()
		})
	}

	c.memMu.Lock()
	defer c.memMu.Unlock()
	delete(c.memStore, key)
	return nil
}
