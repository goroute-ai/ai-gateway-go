package cache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// CacheType labels emitted on response telemetry headers.
const (
	CacheHitTypeExact    = "exact"
	CacheHitTypeSemantic = "semantic"
)

// EntryMeta captures scoping metadata stored alongside a cached response for scoped invalidation.
type EntryMeta struct {
	OrgID          string
	Model          string
	RequestedModel string // Original ModelGroup alias requested by caller (when distinct from resolved Model)
	Modality       string // "chat", "completion", "embedding"
}

// BackendStats reports point-in-time backend size and eviction diagnostics.
type BackendStats struct {
	Entries   int
	Capacity  int
	Evictions uint64
}

// Backend is the single-tier storage strategy implemented by LocalBackend, RedisBackend,
// and RedisSemanticBackend.
type Backend interface {
	Type() string
	Get(ctx context.Context, orgID, key string) ([]byte, bool, error)
	Set(ctx context.Context, orgID, key string, value []byte, meta EntryMeta, ttl time.Duration) error
	Invalidate(ctx context.Context, orgID, model string) (int, error)
	Stats() BackendStats
}

// EmbedFunc embeds a single prompt string for semantic cache lookup/storage.
type EmbedFunc func(ctx context.Context, orgID, model, input string) ([]float32, error)

// SemanticLookup describes a vector-similarity cache query scoped by tenant and request parameters.
type SemanticLookup struct {
	OrgID             string
	ScopeHash         string
	Prompt            string
	ThresholdOverride float64 // > 0 overrides configured similarity_threshold
}

// SemanticLookupOutcome captures the result of a semantic vector search, including the computed
// prompt embedding so a cache miss can be stored without calling the embedding model twice.
type SemanticLookupOutcome struct {
	Payload    []byte
	Similarity float64
	Hit        bool
	Embedding  []float32
}

// SemanticStore describes a vector-indexed semantic cache write.
type SemanticStore struct {
	OrgID          string
	Model          string
	RequestedModel string
	ScopeHash      string
	Prompt         string
	Payload        []byte
	Embedding      []float32 // Optional pre-computed vector reused from LookupChat
	TTL            time.Duration
}

// SemanticBackend extends Backend with Redis Vector Similarity Search capabilities.
type SemanticBackend interface {
	Backend
	SearchSemantic(ctx context.Context, q SemanticLookup) (SemanticLookupOutcome, error)
	StoreSemantic(ctx context.Context, s SemanticStore) error
}

func orgTag(orgID string) string {
	sum := sha256.Sum256([]byte(orgID))
	return hex.EncodeToString(sum[:8])
}

func modelTag(model string) string {
	sum := sha256.Sum256([]byte(model))
	return hex.EncodeToString(sum[:8])
}
