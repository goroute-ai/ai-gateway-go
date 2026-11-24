package cache

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/redis/go-redis/v9"
)

// vectorRedisClient abstracts RediSearch / Hash operations so RedisSemanticBackend can run
// against live Redis 8+ via go-redis/v9 as well as deterministic in-memory unit-test doubles.
type vectorRedisClient interface {
	Do(ctx context.Context, args ...any) (any, error)
	HSetWithExpire(ctx context.Context, key string, ttlSec int64, kvPairs ...any) error
	ScanKeys(ctx context.Context, pattern string) ([]string, error)
	UnlinkKeys(ctx context.Context, keys []string) (int, error)
}

type fabricVectorClient struct {
	fabric *storage.RedisFabric
}

type redisIndexStateErr struct {
	err error
}

func (f *fabricVectorClient) Do(ctx context.Context, args ...any) (any, error) {
	if f == nil || f.fabric == nil || f.fabric.Client() == nil {
		return nil, errors.New("redis client unavailable")
	}
	res, err := f.fabric.Execute(func(rdb redis.UniversalClient) (any, error) {
		val, cmdErr := rdb.Do(ctx, args...).Result()
		if cmdErr != nil && (isNoSuchIndexError(cmdErr) || isIndexAlreadyExistsError(cmdErr) || isUnknownCommandError(cmdErr)) {
			// Redis responded cleanly over the network; surface the protocol reply without
			// tripping or re-opening the RedisFabric circuit breaker during half-open recovery.
			return redisIndexStateErr{err: cmdErr}, nil
		}
		return val, cmdErr
	})
	if err != nil {
		return nil, err
	}
	if se, ok := res.(redisIndexStateErr); ok {
		return nil, se.err
	}
	return res, nil
}

func (f *fabricVectorClient) HSetWithExpire(ctx context.Context, key string, ttlSec int64, kvPairs ...any) error {
	if f == nil || f.fabric == nil || f.fabric.Client() == nil {
		return errors.New("redis client unavailable")
	}
	_, err := f.fabric.Execute(func(rdb redis.UniversalClient) (any, error) {
		pipe := rdb.TxPipeline()
		pipe.HSet(ctx, key, kvPairs...)
		pipe.Expire(ctx, key, time.Duration(ttlSec)*time.Second)
		return pipe.Exec(ctx)
	})
	return err
}

func (f *fabricVectorClient) ScanKeys(ctx context.Context, pattern string) ([]string, error) {
	return scanRedisKeys(ctx, f.fabric, pattern)
}

func (f *fabricVectorClient) UnlinkKeys(ctx context.Context, keys []string) (int, error) {
	return unlinkRedisKeys(ctx, f.fabric, keys)
}

// RedisSemanticBackend implements Redis Vector Similarity Search (RediSearch FT.CREATE / FT.SEARCH)
// using Hash documents with HNSW (default) or FLAT cosine indexes and strict TAG scope isolation.
// Non-semantic KV operations (e.g. completions/embeddings) delegate to the embedded RedisBackend.
type RedisSemanticBackend struct {
	*RedisBackend
	client       vectorRedisClient
	cfg          config.SemanticCacheConfig
	embedFn      EmbedFunc
	namespace    string
	maxItemBytes int

	indexMu           sync.Mutex
	indexReady        atomic.Bool
	indexDim          atomic.Int64
	searchUnsupported atomic.Bool
}

// NewRedisSemanticBackend constructs a Redis Vector Similarity Search SemanticBackend.
func NewRedisSemanticBackend(
	redisFabric *storage.RedisFabric,
	namespace string,
	maxItemBytes int,
	cfg config.SemanticCacheConfig,
	embedFn EmbedFunc,
) *RedisSemanticBackend {
	return newRedisSemanticBackendWithClient(
		NewRedisBackend(redisFabric, namespace, maxItemBytes),
		&fabricVectorClient{fabric: redisFabric},
		namespace,
		maxItemBytes,
		cfg,
		embedFn,
	)
}

func newRedisSemanticBackendWithClient(
	kv *RedisBackend,
	client vectorRedisClient,
	namespace string,
	maxItemBytes int,
	cfg config.SemanticCacheConfig,
	embedFn EmbedFunc,
) *RedisSemanticBackend {
	ns := strings.TrimRight(strings.TrimSpace(namespace), ":")
	if ns == "" {
		ns = "gw:cache"
	}
	if maxItemBytes <= 0 {
		maxItemBytes = defaultLocalMaxItemBytes
	}
	if cfg.SimilarityThreshold <= 0 || cfg.SimilarityThreshold > 1 {
		cfg.SimilarityThreshold = 0.90
	}
	if strings.TrimSpace(cfg.IndexName) == "" {
		cfg.IndexName = "gw_semantic_cache_idx"
	}
	cfg.VectorAlgorithm = strings.ToUpper(strings.TrimSpace(cfg.VectorAlgorithm))
	if cfg.VectorAlgorithm != config.VectorAlgorithmFLAT {
		cfg.VectorAlgorithm = config.VectorAlgorithmHNSW
	}
	if cfg.EmbeddingTimeout <= 0 {
		cfg.EmbeddingTimeout = 2 * time.Second
	}
	if cfg.MaxInputChars <= 0 {
		cfg.MaxInputChars = 8000
	}
	return &RedisSemanticBackend{
		RedisBackend: kv,
		client:       client,
		cfg:          cfg,
		embedFn:      embedFn,
		namespace:    ns,
		maxItemBytes: maxItemBytes,
	}
}

// Type returns "redis-semantic".
func (b *RedisSemanticBackend) Type() string { return config.CacheTypeRedisSemantic }

func (b *RedisSemanticBackend) semPrefix() string {
	return b.namespace + ":sem:"
}

func (b *RedisSemanticBackend) semDocKey(orgID, scopeHash, prompt string) string {
	sum := sha256.Sum256([]byte(scopeHash + "\x00" + prompt))
	return fmt.Sprintf("%s%s:%s", b.semPrefix(), orgTag(orgID), hex.EncodeToString(sum[:12]))
}

func (b *RedisSemanticBackend) truncatePrompt(prompt string) string {
	prompt = strings.TrimSpace(prompt)
	return truncateUTF8(prompt, b.cfg.MaxInputChars)
}

// truncateUTF8 trims s to at most maxRunes Unicode code points without splitting multi-byte UTF-8 sequences.
func truncateUTF8(s string, maxRunes int) string {
	if maxRunes <= 0 || len(s) <= maxRunes {
		return s
	}
	count := 0
	for i := range s {
		if count == maxRunes {
			return s[:i]
		}
		count++
	}
	return s
}

func (b *RedisSemanticBackend) embedPrompt(ctx context.Context, orgID, prompt string) ([]float32, error) {
	if b.embedFn == nil {
		return nil, errors.New("semantic cache embed function is not configured")
	}
	embedCtx, cancel := context.WithTimeout(ctx, b.cfg.EmbeddingTimeout)
	defer cancel()
	vec, err := b.embedFn(embedCtx, orgID, b.cfg.EmbeddingModel, prompt)
	if err != nil {
		return nil, err
	}
	if len(vec) == 0 {
		return nil, errors.New("semantic cache received empty embedding vector")
	}
	return vec, nil
}

func (b *RedisSemanticBackend) ensureIndex(ctx context.Context, dim int) error {
	if b.searchUnsupported.Load() {
		return errors.New("redis server does not support FT.CREATE/FT.SEARCH vector indexing")
	}
	if b.indexReady.Load() {
		if existingDim := int(b.indexDim.Load()); existingDim > 0 && existingDim != dim {
			slog.Error("cache: semantic vector dimension mismatch against active RediSearch index; rotate cache.semantic.index_name or run FT.DROPINDEX <index> DD",
				"index", b.cfg.IndexName,
				"index_dim", existingDim,
				"embedding_dim", dim,
				"embedding_model", b.cfg.EmbeddingModel,
			)
			return fmt.Errorf("semantic cache index %q has vector dim=%d but embedding model %q returned dim=%d (rotate cache.semantic.index_name or run FT.DROPINDEX %s DD)",
				b.cfg.IndexName, existingDim, b.cfg.EmbeddingModel, dim, b.cfg.IndexName)
		}
		return nil
	}
	b.indexMu.Lock()
	defer b.indexMu.Unlock()
	if b.indexReady.Load() {
		if existingDim := int(b.indexDim.Load()); existingDim > 0 && existingDim != dim {
			return fmt.Errorf("semantic cache index %q has vector dim=%d but embedding model %q returned dim=%d (rotate cache.semantic.index_name or run FT.DROPINDEX %s DD)",
				b.cfg.IndexName, existingDim, b.cfg.EmbeddingModel, dim, b.cfg.IndexName)
		}
		return nil
	}
	if b.searchUnsupported.Load() {
		return errors.New("redis server does not support FT.CREATE/FT.SEARCH vector indexing")
	}
	if b.client == nil {
		return errors.New("semantic cache redis client is nil")
	}

	// Check if index already exists and verify vector dimension/algorithm compatibility.
	infoRaw, infoErr := b.client.Do(ctx, "FT.INFO", b.cfg.IndexName)
	if infoErr == nil {
		existingDim, existingAlgo := parseFTInfoVectorSpec(infoRaw)
		if existingDim > 0 && existingDim != dim {
			slog.Error("cache: semantic vector dimension mismatch against existing RediSearch index; rotate cache.semantic.index_name or run FT.DROPINDEX <index> DD",
				"index", b.cfg.IndexName,
				"index_dim", existingDim,
				"embedding_dim", dim,
				"embedding_model", b.cfg.EmbeddingModel,
			)
			return fmt.Errorf("semantic cache index %q has vector dim=%d but embedding model %q returned dim=%d (rotate cache.semantic.index_name or run FT.DROPINDEX %s DD)",
				b.cfg.IndexName, existingDim, b.cfg.EmbeddingModel, dim, b.cfg.IndexName)
		}
		if existingAlgo != "" && !strings.EqualFold(existingAlgo, b.cfg.VectorAlgorithm) {
			slog.Warn("cache: existing RediSearch index algorithm differs from configured vector_algorithm",
				"index", b.cfg.IndexName,
				"index_algorithm", existingAlgo,
				"configured_algorithm", b.cfg.VectorAlgorithm,
			)
		}
		b.indexDim.Store(int64(dim))
		b.indexReady.Store(true)
		return nil
	}
	if isUnknownCommandError(infoErr) {
		b.searchUnsupported.Store(true)
		slog.Warn("cache: redis-semantic disabled at runtime because Redis does not support RediSearch (requires Redis 8+ or Redis Stack)",
			"index", b.cfg.IndexName, "error", infoErr)
		return infoErr
	}

	// Create vector index on Hash documents with strict TAG isolation fields.
	_, createErr := b.client.Do(ctx,
		"FT.CREATE", b.cfg.IndexName,
		"ON", "HASH",
		"PREFIX", "1", b.semPrefix(),
		"SCHEMA",
		"scope", "TAG",
		"org_id", "TAG",
		"model", "TAG",
		"prompt", "TEXT",
		"response", "TEXT", "NOINDEX",
		"embedding", "VECTOR", b.cfg.VectorAlgorithm, "6",
		"TYPE", "FLOAT32",
		"DIM", strconv.Itoa(dim),
		"DISTANCE_METRIC", "COSINE",
	)
	if createErr != nil {
		if isUnknownCommandError(createErr) {
			b.searchUnsupported.Store(true)
			slog.Warn("cache: redis-semantic disabled at runtime because Redis does not support FT.CREATE (requires Redis 8+ or Redis Stack)",
				"index", b.cfg.IndexName, "error", createErr)
			return createErr
		}
		if !isIndexAlreadyExistsError(createErr) {
			return fmt.Errorf("semantic cache FT.CREATE %s: %w", b.cfg.IndexName, createErr)
		}
	}

	b.indexDim.Store(int64(dim))
	b.indexReady.Store(true)
	return nil
}

// SearchSemantic embeds the prompt once, queries RediSearch KNN within the exact scope TAG,
// validates cosine similarity against the threshold, and returns the embedding for reuse on miss.
func (b *RedisSemanticBackend) SearchSemantic(ctx context.Context, q SemanticLookup) (SemanticLookupOutcome, error) {
	if b == nil || b.client == nil || q.ScopeHash == "" {
		return SemanticLookupOutcome{}, nil
	}
	prompt := b.truncatePrompt(q.Prompt)
	if prompt == "" {
		return SemanticLookupOutcome{}, nil
	}
	if b.searchUnsupported.Load() {
		return SemanticLookupOutcome{}, errors.New("redis server does not support vector search")
	}

	vec, err := b.embedPrompt(ctx, q.OrgID, prompt)
	if err != nil {
		return SemanticLookupOutcome{}, err
	}
	if err := b.ensureIndex(ctx, len(vec)); err != nil {
		return SemanticLookupOutcome{Embedding: vec}, err
	}

	query := fmt.Sprintf("(@scope:{%s})=>[KNN 1 @embedding $vec AS vector_distance]", q.ScopeHash)
	raw, err := b.client.Do(ctx,
		"FT.SEARCH", b.cfg.IndexName, query,
		"PARAMS", "2", "vec", float32SliceToBytes(vec),
		"SORTBY", "vector_distance", "ASC",
		"RETURN", "4", "scope", "response", "prompt", "vector_distance",
		"DIALECT", "2",
	)
	if err != nil {
		if isUnknownCommandError(err) {
			b.searchUnsupported.Store(true)
			return SemanticLookupOutcome{Embedding: vec}, err
		}
		// Reset indexReady on any Redis error (e.g., "no such index" after ephemeral Redis
		// restart/FLUSHALL, or transient connection loss) so ensureIndex lazily recreates the
		// RediSearch index automatically without requiring a gateway restart.
		b.indexReady.Store(false)
		if isNoSuchIndexError(err) {
			if reErr := b.ensureIndex(ctx, len(vec)); reErr == nil {
				return SemanticLookupOutcome{Embedding: vec}, nil
			}
		}
		return SemanticLookupOutcome{Embedding: vec}, err
	}

	docs := parseFTSearchDocs(raw)
	if len(docs) == 0 {
		return SemanticLookupOutcome{Embedding: vec}, nil
	}

	top := docs[0]
	// Defense-in-depth: never accept a document whose stored scope TAG differs from the caller scope.
	if top.Scope != q.ScopeHash || len(top.Response) == 0 {
		return SemanticLookupOutcome{Embedding: vec}, nil
	}

	threshold := b.cfg.SimilarityThreshold
	if q.ThresholdOverride > 0 && q.ThresholdOverride <= 1.0 {
		threshold = q.ThresholdOverride
	}

	similarity := 1.0 - top.Distance
	if similarity > 1.0 {
		similarity = 1.0
	}
	if similarity < 0 {
		similarity = 0
	}
	if similarity < threshold {
		return SemanticLookupOutcome{Similarity: similarity, Hit: false, Embedding: vec}, nil
	}

	return SemanticLookupOutcome{
		Payload:    []byte(top.Response),
		Similarity: similarity,
		Hit:        true,
		Embedding:  vec,
	}, nil
}

// StoreSemantic stores the serialized response and its prompt vector in a Redis Hash with TTL.
// Reuses s.Embedding from the preceding SearchSemantic miss to avoid a duplicate embedding call.
func (b *RedisSemanticBackend) StoreSemantic(ctx context.Context, s SemanticStore) error {
	if b == nil || b.client == nil || s.ScopeHash == "" || len(s.Payload) == 0 || s.TTL <= 0 {
		return nil
	}
	if b.maxItemBytes > 0 && len(s.Payload) > b.maxItemBytes {
		return nil
	}
	if b.searchUnsupported.Load() {
		return nil
	}
	prompt := b.truncatePrompt(s.Prompt)
	if prompt == "" {
		return nil
	}

	vec := s.Embedding
	if len(vec) == 0 {
		var err error
		vec, err = b.embedPrompt(ctx, s.OrgID, prompt)
		if err != nil {
			return err
		}
	}
	if err := b.ensureIndex(ctx, len(vec)); err != nil {
		return err
	}

	docKey := b.semDocKey(s.OrgID, s.ScopeHash, prompt)
	ttlSec := int64(s.TTL.Seconds())
	if ttlSec < 1 {
		ttlSec = 1
	}

	modelTagValue := modelTag(s.Model)
	if s.RequestedModel != "" && s.RequestedModel != s.Model {
		modelTagValue = modelTagValue + "," + modelTag(s.RequestedModel)
	}
	if err := b.client.HSetWithExpire(ctx, docKey, ttlSec,
		"scope", s.ScopeHash,
		"org_id", orgTag(s.OrgID),
		"model", modelTagValue,
		"prompt", prompt,
		"response", string(s.Payload),
		"embedding", float32SliceToBytes(vec),
	); err != nil {
		b.indexReady.Store(false)
		return err
	}
	return nil
}

// Invalidate removes matching semantic documents (and any KV entries in the embedded RedisBackend)
// without dropping the RediSearch index definition.
func (b *RedisSemanticBackend) Invalidate(ctx context.Context, orgID, model string) (int, error) {
	if b == nil {
		return 0, nil
	}
	total := 0
	if b.RedisBackend != nil {
		n, err := b.RedisBackend.Invalidate(ctx, orgID, model)
		if err != nil {
			return 0, err
		}
		total += n
	}
	if b.client == nil {
		return total, nil
	}

	// Fast path when model filter is absent: SCAN semantic prefix directly (works even before index creation).
	if model == "" {
		pattern := b.semPrefix() + "*"
		if orgID != "" {
			pattern = fmt.Sprintf("%s%s:*", b.semPrefix(), orgTag(orgID))
		}
		keys, err := b.client.ScanKeys(ctx, pattern)
		if err != nil {
			return total, err
		}
		if len(keys) == 0 {
			return total, nil
		}
		n, err := b.client.UnlinkKeys(ctx, keys)
		return total + n, err
	}

	// Model-scoped semantic invalidation via FT.SEARCH NOCONTENT.
	if b.searchUnsupported.Load() {
		return total, nil
	}
	var parts []string
	if orgID != "" {
		parts = append(parts, fmt.Sprintf("@org_id:{%s}", orgTag(orgID)))
	}
	parts = append(parts, fmt.Sprintf("@model:{%s}", modelTag(model)))
	query := strings.Join(parts, " ")

	for {
		raw, err := b.client.Do(ctx, "FT.SEARCH", b.cfg.IndexName, query, "NOCONTENT", "LIMIT", "0", strconv.Itoa(redisScanBatchSize))
		if err != nil {
			if isUnknownCommandError(err) {
				return total, nil
			}
			b.indexReady.Store(false)
			if isNoSuchIndexError(err) {
				return total, nil
			}
			return total, err
		}
		docKeys := parseFTSearchKeys(raw)
		if len(docKeys) == 0 {
			break
		}
		n, uErr := b.client.UnlinkKeys(ctx, docKeys)
		if uErr != nil {
			return total + n, uErr
		}
		total += n
		if n == 0 || len(docKeys) < redisScanBatchSize {
			break
		}
	}
	return total, nil
}

func float32SliceToBytes(vec []float32) []byte {
	buf := make([]byte, len(vec)*4)
	for i, v := range vec {
		binary.LittleEndian.PutUint32(buf[i*4:], math.Float32bits(v))
	}
	return buf
}

func isUnknownCommandError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "unknown command") || strings.Contains(msg, "err unknown command")
}

func isNoSuchIndexError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "no such index") ||
		strings.Contains(msg, "unknown index name") ||
		strings.Contains(msg, "index not found") ||
		strings.Contains(msg, "search_index_not_found")
}

func isIndexAlreadyExistsError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "index already exists") || strings.Contains(msg, "already exists")
}

type ftSearchDoc struct {
	ID       string
	Scope    string
	Response string
	Prompt   string
	Distance float64
}

// parseFTSearchDocs supports both RESP3 map responses (go-redis/v9 default on Redis 8)
// and RESP2 array responses ([count, docID, [k, v, ...]]).
func parseFTSearchDocs(raw any) []ftSearchDoc {
	switch v := raw.(type) {
	case map[any]any:
		return parseFTSearchDocsRESP3(v)
	case map[string]any:
		conv := make(map[any]any, len(v))
		for k, val := range v {
			conv[k] = val
		}
		return parseFTSearchDocsRESP3(conv)
	case []any:
		return parseFTSearchDocsRESP2(v)
	default:
		return nil
	}
}

func parseFTSearchDocsRESP3(m map[any]any) []ftSearchDoc {
	resultsRaw, ok := m["results"]
	if !ok {
		return nil
	}
	results, ok := resultsRaw.([]any)
	if !ok || len(results) == 0 {
		return nil
	}
	docs := make([]ftSearchDoc, 0, len(results))
	for _, item := range results {
		row := asAnyMap(item)
		if row == nil {
			continue
		}
		doc := ftSearchDoc{ID: asString(row["id"])}
		attrs := asAnyMap(row["extra_attributes"])
		if attrs != nil {
			doc.Scope = asString(attrs["scope"])
			doc.Response = asString(attrs["response"])
			doc.Prompt = asString(attrs["prompt"])
			doc.Distance = asFloat64(attrs["vector_distance"])
		}
		docs = append(docs, doc)
	}
	return docs
}

func parseFTSearchDocsRESP2(arr []any) []ftSearchDoc {
	if len(arr) < 3 {
		return nil
	}
	var docs []ftSearchDoc
	for i := 1; i+1 < len(arr); i += 2 {
		doc := ftSearchDoc{ID: asString(arr[i])}
		fields, ok := arr[i+1].([]any)
		if ok {
			for j := 0; j+1 < len(fields); j += 2 {
				k := asString(fields[j])
				val := fields[j+1]
				switch k {
				case "scope":
					doc.Scope = asString(val)
				case "response":
					doc.Response = asString(val)
				case "prompt":
					doc.Prompt = asString(val)
				case "vector_distance":
					doc.Distance = asFloat64(val)
				}
			}
		}
		docs = append(docs, doc)
	}
	return docs
}

func parseFTSearchKeys(raw any) []string {
	if m := asAnyMap(raw); m != nil {
		results, _ := m["results"].([]any)
		keys := make([]string, 0, len(results))
		for _, item := range results {
			if row := asAnyMap(item); row != nil {
				if id := asString(row["id"]); id != "" {
					keys = append(keys, id)
				}
			}
		}
		return keys
	}
	if arr, ok := raw.([]any); ok {
		if len(arr) < 2 {
			return nil
		}
		keys := make([]string, 0, len(arr)-1)
		for i := 1; i < len(arr); i++ {
			if id := asString(arr[i]); id != "" {
				keys = append(keys, id)
			}
		}
		return keys
	}
	return nil
}

// parseFTInfoVectorSpec inspects FT.INFO output (RESP3 map or RESP2 alternating array)
// and extracts the vector dimension and algorithm for the "embedding" field when present.
func parseFTInfoVectorSpec(raw any) (dim int, algo string) {
	attrs := extractFTInfoAttributes(raw)
	for _, attr := range attrs {
		m := kvSliceOrMap(attr)
		if len(m) == 0 {
			continue
		}
		ident := strings.ToLower(asString(m["identifier"]))
		attrName := strings.ToLower(asString(m["attribute"]))
		if ident != "embedding" && attrName != "embedding" {
			continue
		}
		if d := int(asFloat64(m["dim"])); d > 0 {
			dim = d
		}
		if a := strings.ToUpper(strings.TrimSpace(asString(m["algorithm"]))); a != "" {
			algo = a
		}
		if idxMap := kvSliceOrMap(m["index"]); len(idxMap) > 0 {
			if dim == 0 {
				if d := int(asFloat64(idxMap["dimensions"])); d > 0 {
					dim = d
				} else if d := int(asFloat64(idxMap["dim"])); d > 0 {
					dim = d
				}
			}
			if algo == "" {
				if a := strings.ToUpper(strings.TrimSpace(asString(idxMap["algorithm"]))); a != "" {
					algo = a
				}
			}
		}
		return dim, algo
	}
	return 0, ""
}

func extractFTInfoAttributes(raw any) []any {
	if m := asAnyMap(raw); m != nil {
		if attrs, ok := m["attributes"].([]any); ok {
			return attrs
		}
		return nil
	}
	if arr, ok := raw.([]any); ok {
		for i := 0; i+1 < len(arr); i += 2 {
			if strings.EqualFold(asString(arr[i]), "attributes") {
				if attrs, ok := arr[i+1].([]any); ok {
					return attrs
				}
			}
		}
	}
	return nil
}

func kvSliceOrMap(v any) map[string]any {
	if m := asAnyMap(v); m != nil {
		out := make(map[string]any, len(m))
		for k, val := range m {
			out[strings.ToLower(asString(k))] = val
		}
		return out
	}
	if arr, ok := v.([]any); ok {
		out := make(map[string]any, len(arr)/2)
		for i := 0; i+1 < len(arr); i += 2 {
			out[strings.ToLower(asString(arr[i]))] = arr[i+1]
		}
		return out
	}
	return nil
}

func asAnyMap(v any) map[any]any {
	switch m := v.(type) {
	case map[any]any:
		return m
	case map[string]any:
		out := make(map[any]any, len(m))
		for k, val := range m {
			out[k] = val
		}
		return out
	default:
		return nil
	}
}

func asString(v any) string {
	switch s := v.(type) {
	case string:
		return s
	case []byte:
		return string(s)
	default:
		if v == nil {
			return ""
		}
		return fmt.Sprint(v)
	}
}

func asFloat64(v any) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case float32:
		return float64(n)
	case int64:
		return float64(n)
	case int:
		return float64(n)
	case string:
		f, _ := strconv.ParseFloat(strings.TrimSpace(n), 64)
		return f
	case []byte:
		f, _ := strconv.ParseFloat(strings.TrimSpace(string(n)), 64)
		return f
	default:
		return 2.0 // Max cosine distance on parse failure -> fail closed (miss)
	}
}
