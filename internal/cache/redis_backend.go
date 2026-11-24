package cache

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/redis/go-redis/v9"
)

const redisScanBatchSize = 256

type redisKVEnvelope struct {
	OrgID          string          `json:"org_id"`
	Model          string          `json:"model"`
	RequestedModel string          `json:"requested_model,omitempty"`
	Modality       string          `json:"modality,omitempty"`
	Payload        json.RawMessage `json:"payload"`
}

// RedisBackend is a direct Redis key-value exact-match cache backend (1 GET on read,
// 1 SET EX on write, non-blocking SCAN+UNLINK on admin invalidation).
type RedisBackend struct {
	redis        *storage.RedisFabric
	namespace    string
	maxItemBytes int
}

// NewRedisBackend constructs a direct Redis key-value Backend.
func NewRedisBackend(redisFabric *storage.RedisFabric, namespace string, maxItemBytes int) *RedisBackend {
	ns := strings.TrimRight(strings.TrimSpace(namespace), ":")
	if ns == "" {
		ns = "gw:cache"
	}
	if maxItemBytes <= 0 {
		maxItemBytes = defaultLocalMaxItemBytes
	}
	return &RedisBackend{
		redis:        redisFabric,
		namespace:    ns,
		maxItemBytes: maxItemBytes,
	}
}

// Type returns "redis".
func (b *RedisBackend) Type() string { return config.CacheTypeRedis }

func (b *RedisBackend) kvKey(orgID, key string) string {
	return fmt.Sprintf("%s:kv:%s:%s", b.namespace, orgTag(orgID), key)
}

func (b *RedisBackend) kvPattern(orgID string) string {
	if orgID != "" {
		return fmt.Sprintf("%s:kv:%s:*", b.namespace, orgTag(orgID))
	}
	return fmt.Sprintf("%s:kv:*", b.namespace)
}

// Get executes a single Redis GET for the exact cache key.
func (b *RedisBackend) Get(ctx context.Context, orgID, key string) ([]byte, bool, error) {
	if b == nil || key == "" || b.redis == nil || b.redis.Client() == nil {
		return nil, false, nil
	}
	res, err := b.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
		return rdb.Get(ctx, b.kvKey(orgID, key)).Bytes()
	})
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return nil, false, nil
		}
		return nil, false, err
	}
	raw, ok := res.([]byte)
	if !ok || len(raw) == 0 {
		return nil, false, nil
	}
	var env redisKVEnvelope
	if err := json.Unmarshal(raw, &env); err != nil || len(env.Payload) == 0 {
		return nil, false, nil
	}
	return env.Payload, true, nil
}

// Set executes a single Redis SET EX for the exact cache key.
func (b *RedisBackend) Set(ctx context.Context, orgID, key string, value []byte, meta EntryMeta, ttl time.Duration) error {
	if b == nil || key == "" || len(value) == 0 || ttl <= 0 || b.redis == nil || b.redis.Client() == nil {
		return nil
	}
	if b.maxItemBytes > 0 && len(value) > b.maxItemBytes {
		return nil
	}
	env := redisKVEnvelope{
		OrgID:          meta.OrgID,
		Model:          meta.Model,
		RequestedModel: meta.RequestedModel,
		Modality:       meta.Modality,
		Payload:        json.RawMessage(value),
	}
	raw, err := json.Marshal(env)
	if err != nil {
		return err
	}
	_, err = b.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
		return rdb.Set(ctx, b.kvKey(orgID, key), raw, ttl).Result()
	})
	return err
}

// Invalidate scans keys matching the requested org/global scope and unlinks matching entries.
func (b *RedisBackend) Invalidate(ctx context.Context, orgID, model string) (int, error) {
	if b == nil || b.redis == nil || b.redis.Client() == nil {
		return 0, nil
	}
	keys, err := scanRedisKeys(ctx, b.redis, b.kvPattern(orgID))
	if err != nil {
		return 0, err
	}
	if len(keys) == 0 {
		return 0, nil
	}

	if model == "" {
		return unlinkRedisKeys(ctx, b.redis, keys)
	}

	// Filter scanned keys by stored model metadata in batches before unlinking.
	var toDelete []string
	_, isCluster := b.redis.Client().(*redis.ClusterClient)
	for i := 0; i < len(keys); i += redisScanBatchSize {
		end := min(i+redisScanBatchSize, len(keys))
		batch := keys[i:end]
		rawItems := fetchRedisBatchBytes(ctx, b.redis, batch, isCluster)
		for idx, raw := range rawItems {
			if len(raw) == 0 {
				continue
			}
			var meta struct {
				Model          string `json:"model"`
				RequestedModel string `json:"requested_model"`
			}
			if json.Unmarshal(raw, &meta) == nil && (meta.Model == model || meta.RequestedModel == model) {
				toDelete = append(toDelete, batch[idx])
			}
		}
	}
	if len(toDelete) == 0 {
		return 0, nil
	}
	return unlinkRedisKeys(ctx, b.redis, toDelete)
}

func fetchRedisBatchBytes(ctx context.Context, fabric *storage.RedisFabric, batch []string, isCluster bool) [][]byte {
	out := make([][]byte, len(batch))
	if fabric == nil || fabric.Client() == nil || len(batch) == 0 {
		return out
	}
	if !isCluster {
		res, err := fabric.Execute(func(rdb redis.UniversalClient) (any, error) {
			return rdb.MGet(ctx, batch...).Result()
		})
		if err != nil {
			return out
		}
		vals, _ := res.([]any)
		for i := 0; i < len(vals) && i < len(out); i++ {
			switch v := vals[i].(type) {
			case string:
				out[i] = []byte(v)
			case []byte:
				out[i] = v
			}
		}
		return out
	}
	// On Redis Cluster, MGET across slots returns CROSSSLOT; pipeline GETs instead.
	res, err := fabric.Execute(func(rdb redis.UniversalClient) (any, error) {
		pipe := rdb.Pipeline()
		cmds := make([]*redis.StringCmd, len(batch))
		for i, k := range batch {
			cmds[i] = pipe.Get(ctx, k)
		}
		_, pipeErr := pipe.Exec(ctx)
		if pipeErr != nil && !errors.Is(pipeErr, redis.Nil) {
			return cmds, nil
		}
		return cmds, nil
	})
	if err != nil {
		return out
	}
	cmds, _ := res.([]*redis.StringCmd)
	for i := 0; i < len(cmds) && i < len(out); i++ {
		if b, cErr := cmds[i].Bytes(); cErr == nil {
			out[i] = b
		}
	}
	return out
}

// Stats returns zero local metrics because storage is delegated directly to Redis.
func (b *RedisBackend) Stats() BackendStats { return BackendStats{} }

func scanRedisKeys(ctx context.Context, fabric *storage.RedisFabric, pattern string) ([]string, error) {
	if fabric == nil || fabric.Client() == nil {
		return nil, nil
	}
	var (
		mu      sync.Mutex
		allKeys []string
	)
	if cluster, ok := fabric.Client().(*redis.ClusterClient); ok {
		err := cluster.ForEachMaster(ctx, func(mCtx context.Context, master *redis.Client) error {
			keys, scanErr := scanSingleNode(mCtx, master, pattern)
			if scanErr != nil {
				return scanErr
			}
			mu.Lock()
			allKeys = append(allKeys, keys...)
			mu.Unlock()
			return nil
		})
		return allKeys, err
	}
	res, err := fabric.Execute(func(rdb redis.UniversalClient) (any, error) {
		return scanSingleNode(ctx, rdb, pattern)
	})
	if err != nil {
		return nil, err
	}
	keys, _ := res.([]string)
	return keys, nil
}

func scanSingleNode(ctx context.Context, rdb redis.UniversalClient, pattern string) ([]string, error) {
	var (
		cursor uint64
		out    []string
	)
	for {
		keys, next, err := rdb.Scan(ctx, cursor, pattern, redisScanBatchSize).Result()
		if err != nil {
			return nil, err
		}
		out = append(out, keys...)
		cursor = next
		if cursor == 0 {
			break
		}
	}
	return out, nil
}

func unlinkRedisKeys(ctx context.Context, fabric *storage.RedisFabric, keys []string) (int, error) {
	if fabric == nil || fabric.Client() == nil || len(keys) == 0 {
		return 0, nil
	}
	deleted := 0
	// In Redis Cluster, UNLINK with multi-slot keys returns CROSSSLOT, so delete per-key
	// when running against a ClusterClient and in batches on standalone/Sentinel.
	if _, isCluster := fabric.Client().(*redis.ClusterClient); isCluster {
		for _, k := range keys {
			res, err := fabric.Execute(func(rdb redis.UniversalClient) (any, error) {
				return rdb.Unlink(ctx, k).Result()
			})
			if err != nil {
				return deleted, err
			}
			if n, ok := res.(int64); ok {
				deleted += int(n)
			}
		}
		return deleted, nil
	}

	for i := 0; i < len(keys); i += redisScanBatchSize {
		end := min(i+redisScanBatchSize, len(keys))
		batch := keys[i:end]
		res, err := fabric.Execute(func(rdb redis.UniversalClient) (any, error) {
			return rdb.Unlink(ctx, batch...).Result()
		})
		if err != nil {
			return deleted, err
		}
		if n, ok := res.(int64); ok {
			deleted += int(n)
		}
	}
	return deleted, nil
}
