package cache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sync"
	"sync/atomic"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/redis/go-redis/v9"
)

type memItem struct {
	resp      *domain.CanonicalChatResponse
	orgID     string
	model     string
	expiresAt time.Time
}

// ResponseCache provides tenant-isolated, model-versioned exact-match response caching
// for deterministic requests (`temperature == 0` or `X-Gateway-Cache-Control: enabled`).
type ResponseCache struct {
	enabled          bool
	ttl              time.Duration
	redis            *storage.RedisFabric
	namespaceVersion atomic.Int64
	l1               sync.Map
}

func NewResponseCache(enabled bool, ttl time.Duration, redisFabric *storage.RedisFabric) *ResponseCache {
	if ttl <= 0 {
		ttl = 1 * time.Hour
	}
	rc := &ResponseCache{
		enabled: enabled,
		ttl:     ttl,
		redis:   redisFabric,
	}
	rc.namespaceVersion.Store(1)
	return rc
}

// IsCacheable reports whether a ChatCompletion request is eligible for exact-match caching.
func (c *ResponseCache) IsCacheable(req *domain.CanonicalChatRequest, cacheControlHeader string) bool {
	if !c.enabled || req == nil || req.Stream {
		return false
	}
	if cacheControlHeader == "no-cache" || cacheControlHeader == "bypass" {
		return false
	}
	if cacheControlHeader == "enabled" || cacheControlHeader == "force" {
		return true
	}
	return req.Temperature != nil && *req.Temperature == 0
}

// ComputeKey generates a collision-resistant SHA-256 cache key scoped to the Organization, Model, and Cache Epoch Version.
func (c *ResponseCache) ComputeKey(orgID string, req *domain.CanonicalChatRequest) string {
	type keyPayload struct {
		NamespaceVer    int64                     `json:"ns_ver"`
		OrgID           string                    `json:"org_id"`
		Model           string                    `json:"model"`
		ResolvedModel   string                    `json:"resolved_model,omitempty"`
		Messages        []domain.CanonicalMessage `json:"messages"`
		Tools           []domain.CanonicalTool    `json:"tools,omitempty"`
		ToolChoice      any                       `json:"tool_choice,omitempty"`
		ResponseFormat  *domain.ResponseFormat    `json:"response_format,omitempty"`
		MaxTokens       *int                      `json:"max_tokens,omitempty"`
		Stop            []string                  `json:"stop,omitempty"`
		Temperature     *float64                  `json:"temperature,omitempty"`
		TopP            *float64                  `json:"top_p,omitempty"`
		ReasoningEffort string                    `json:"reasoning_effort,omitempty"`
		User            string                    `json:"user,omitempty"`
	}
	b, _ := json.Marshal(keyPayload{
		NamespaceVer:    c.namespaceVersion.Load(),
		OrgID:           orgID,
		Model:           req.Model,
		ResolvedModel:   req.ResolvedModel,
		Messages:        req.Messages,
		Tools:           req.Tools,
		ToolChoice:      req.ToolChoice,
		ResponseFormat:  req.ResponseFormat,
		MaxTokens:       req.MaxTokens,
		Stop:            req.Stop,
		Temperature:     req.Temperature,
		TopP:            req.TopP,
		ReasoningEffort: req.ReasoningEffort,
		User:            req.User,
	})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func (c *ResponseCache) Get(ctx context.Context, key string) (*domain.CanonicalChatResponse, bool) {
	now := time.Now()
	if val, ok := c.l1.Load(key); ok {
		item := val.(memItem)
		if now.Before(item.expiresAt) {
			cp := *item.resp
			return &cp, true
		}
		c.l1.Delete(key)
	}

	if c.redis != nil && c.redis.Client() != nil {
		res, err := c.redis.Execute(func(rdb *redis.Client) (any, error) {
			return rdb.Get(ctx, "gw:cache:resp:"+key).Result()
		})
		if err == nil {
			if raw, ok := res.(string); ok && raw != "" {
				var resp domain.CanonicalChatResponse
				if json.Unmarshal([]byte(raw), &resp) == nil {
					c.l1.Store(key, memItem{resp: &resp, model: resp.Model, expiresAt: now.Add(c.ttl)})
					cp := resp
					return &cp, true
				}
			}
		}
	}
	return nil, false
}

func (c *ResponseCache) Set(ctx context.Context, key string, resp *domain.CanonicalChatResponse) {
	c.SetWithMeta(ctx, key, "", resp)
}

func (c *ResponseCache) SetWithMeta(ctx context.Context, key, orgID string, resp *domain.CanonicalChatResponse) {
	if resp == nil {
		return
	}
	cp := *resp
	c.l1.Store(key, memItem{resp: &cp, orgID: orgID, model: resp.Model, expiresAt: time.Now().Add(c.ttl)})
	if c.redis != nil && c.redis.Client() != nil {
		if b, err := json.Marshal(resp); err == nil {
			_, _ = c.redis.Execute(func(rdb *redis.Client) (any, error) {
				return rdb.Set(ctx, "gw:cache:resp:"+key, b, c.ttl).Result()
			})
		}
	}
}

// Invalidate removes cached entries matching orgID or model, or bumps the global namespace version if both are empty.
// Returns the number of local L1 entries purged and the active namespace version.
func (c *ResponseCache) Invalidate(ctx context.Context, orgID, model string) (int, int64) {
	purged := 0
	if orgID == "" && model == "" {
		newVer := c.namespaceVersion.Add(1)
		c.l1.Range(func(key, _ any) bool {
			c.l1.Delete(key)
			purged++
			return true
		})
		return purged, newVer
	}

	c.l1.Range(func(key, value any) bool {
		item := value.(memItem)
		matchOrg := orgID != "" && item.orgID == orgID
		matchModel := model != "" && item.model == model
		if matchOrg || matchModel {
			c.l1.Delete(key)
			purged++
			if c.redis != nil && c.redis.Client() != nil {
				if ks, ok := key.(string); ok {
					_, _ = c.redis.Execute(func(rdb *redis.Client) (any, error) {
						return rdb.Del(ctx, "gw:cache:resp:"+ks).Result()
					})
				}
			}
		}
		return true
	})
	return purged, c.namespaceVersion.Load()
}
