package cache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"sync"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/redis/go-redis/v9"
)

type cacheEpochs struct {
	Global       int64 `json:"global"`
	Organization int64 `json:"organization"`
	Model        int64 `json:"model"`
}

type cacheEntry struct {
	Response  *domain.CanonicalChatResponse `json:"response"`
	OrgID     string                        `json:"org_id"`
	Model     string                        `json:"model"`
	Epochs    cacheEpochs                   `json:"epochs"`
	ExpiresAt time.Time                     `json:"expires_at"`
}

// ResponseCache provides tenant-isolated exact-match response caching. Every hit validates
// shared invalidation epochs before returning either an L1 or Redis entry.
type ResponseCache struct {
	enabled bool
	ttl     time.Duration
	redis   *storage.RedisFabric
	l1      sync.Map

	epochMu     sync.RWMutex
	globalEpoch int64
	orgEpochs   map[string]int64
	modelEpochs map[string]int64
	revision    int64
}

func NewResponseCache(enabled bool, ttl time.Duration, redisFabric *storage.RedisFabric) *ResponseCache {
	if ttl <= 0 {
		ttl = time.Hour
	}
	return &ResponseCache{
		enabled:     enabled,
		ttl:         ttl,
		redis:       redisFabric,
		orgEpochs:   make(map[string]int64),
		modelEpochs: make(map[string]int64),
	}
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

// ComputeKey generates a collision-resistant SHA-256 cache key scoped to the organization and request.
func (c *ResponseCache) ComputeKey(orgID string, req *domain.CanonicalChatRequest) string {
	type keyPayload struct {
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
		entry := val.(cacheEntry)
		if now.Before(entry.ExpiresAt) {
			current, err := c.currentEpochs(ctx, entry.OrgID, entry.Model)
			if err != nil {
				return nil, false
			}
			if current == entry.Epochs {
				return cloneResponse(entry.Response), true
			}
		}
		c.l1.Delete(key)
	}

	if c.redis == nil || c.redis.Client() == nil {
		return nil, false
	}
	res, err := c.redis.Execute(func(rdb *redis.Client) (any, error) {
		return rdb.Get(ctx, "gw:cache:resp:"+key).Result()
	})
	if err != nil {
		return nil, false
	}
	raw, ok := res.(string)
	if !ok || raw == "" {
		return nil, false
	}
	var entry cacheEntry
	if json.Unmarshal([]byte(raw), &entry) != nil || entry.Response == nil {
		return nil, false
	}
	if !now.Before(entry.ExpiresAt) {
		return nil, false
	}
	current, err := c.currentEpochs(ctx, entry.OrgID, entry.Model)
	if err != nil || current != entry.Epochs {
		return nil, false
	}
	c.l1.Store(key, entry)
	return cloneResponse(entry.Response), true
}

func (c *ResponseCache) Set(ctx context.Context, key string, resp *domain.CanonicalChatResponse) {
	c.SetWithMeta(ctx, key, "", resp)
}

func (c *ResponseCache) SetWithMeta(ctx context.Context, key, orgID string, resp *domain.CanonicalChatResponse) {
	if resp == nil {
		return
	}
	model := resp.Model
	epochs, err := c.currentEpochs(ctx, orgID, model)
	if err != nil {
		return
	}
	entry := cacheEntry{
		Response:  cloneResponse(resp),
		OrgID:     orgID,
		Model:     model,
		Epochs:    epochs,
		ExpiresAt: time.Now().Add(c.ttl),
	}
	if c.redis != nil && c.redis.Client() != nil {
		b, err := json.Marshal(entry)
		if err != nil {
			return
		}
		if _, err := c.redis.Execute(func(rdb *redis.Client) (any, error) {
			return rdb.Set(ctx, "gw:cache:resp:"+key, b, c.ttl).Result()
		}); err != nil {
			return
		}
	}
	c.l1.Store(key, entry)
}

// Invalidate advances shared global, organization, and/or model epochs and removes matching local entries.
// The returned revision is monotonic across all invalidation operations.
func (c *ResponseCache) Invalidate(ctx context.Context, orgID, model string) (int, int64, error) {
	var revision int64
	if c.redis != nil && c.redis.Client() != nil {
		keys := []string{cacheRevisionKey()}
		if orgID == "" && model == "" {
			keys = append(keys, cacheGlobalEpochKey())
		} else {
			if orgID != "" {
				keys = append(keys, cacheOrgEpochKey(orgID))
			}
			if model != "" {
				keys = append(keys, cacheModelEpochKey(model))
			}
		}
		res, err := c.redis.Execute(func(rdb *redis.Client) (any, error) {
			return invalidateCacheEpochsScript.Run(ctx, rdb, keys).Int64()
		})
		if err != nil {
			return 0, 0, err
		}
		var ok bool
		revision, ok = res.(int64)
		if !ok {
			return 0, 0, fmt.Errorf("cache invalidation returned unexpected revision")
		}
	} else {
		c.epochMu.Lock()
		c.revision++
		revision = c.revision
		if orgID == "" && model == "" {
			c.globalEpoch++
		} else {
			if orgID != "" {
				c.orgEpochs[orgID]++
			}
			if model != "" {
				c.modelEpochs[model]++
			}
		}
		c.epochMu.Unlock()
	}

	purged := 0
	c.l1.Range(func(key, value any) bool {
		entry := value.(cacheEntry)
		matchScope := orgID == "" && model == ""
		matchOrg := orgID != "" && entry.OrgID == orgID
		matchModel := model != "" && entry.Model == model
		if matchScope || matchOrg || matchModel {
			c.l1.Delete(key)
			purged++
		}
		return true
	})
	return purged, revision, nil
}

func (c *ResponseCache) currentEpochs(ctx context.Context, orgID, model string) (cacheEpochs, error) {
	if c.redis == nil || c.redis.Client() == nil {
		c.epochMu.RLock()
		defer c.epochMu.RUnlock()
		return cacheEpochs{Global: c.globalEpoch, Organization: c.orgEpochs[orgID], Model: c.modelEpochs[model]}, nil
	}
	keys := []string{cacheGlobalEpochKey(), cacheOrgEpochKey(orgID), cacheModelEpochKey(model)}
	res, err := c.redis.Execute(func(rdb *redis.Client) (any, error) {
		return rdb.MGet(ctx, keys...).Result()
	})
	if err != nil {
		return cacheEpochs{}, err
	}
	values, ok := res.([]any)
	if !ok || len(values) != len(keys) {
		return cacheEpochs{}, fmt.Errorf("cache epoch lookup returned unexpected values")
	}
	parsed := make([]int64, len(values))
	for i, value := range values {
		if value == nil {
			continue
		}
		text, ok := value.(string)
		if !ok {
			return cacheEpochs{}, fmt.Errorf("cache epoch %d has unexpected type %T", i, value)
		}
		parsed[i], err = strconv.ParseInt(text, 10, 64)
		if err != nil {
			return cacheEpochs{}, fmt.Errorf("parse cache epoch %d: %w", i, err)
		}
	}
	return cacheEpochs{Global: parsed[0], Organization: parsed[1], Model: parsed[2]}, nil
}

func cloneResponse(resp *domain.CanonicalChatResponse) *domain.CanonicalChatResponse {
	if resp == nil {
		return nil
	}
	cp := *resp
	return &cp
}

func cacheGlobalEpochKey() string { return "gw:cache:{epochs}:global" }
func cacheRevisionKey() string    { return "gw:cache:{epochs}:revision" }

func cacheOrgEpochKey(orgID string) string {
	return fmt.Sprintf("gw:cache:{epochs}:org:%x", sha256.Sum256([]byte(orgID)))
}

func cacheModelEpochKey(model string) string {
	return fmt.Sprintf("gw:cache:{epochs}:model:%x", sha256.Sum256([]byte(model)))
}
