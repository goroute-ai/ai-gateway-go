package cache

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"path"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeVectorRedisClient simulates Redis 8 FT.INFO / FT.CREATE / HSET / EXPIRE / FT.SEARCH (RESP3)
// with real cosine distance calculation for deterministic offline unit tests.
type fakeVectorRedisClient struct {
	mu               sync.Mutex
	indexCreated     bool
	indexName        string
	indexAlgorithm   string
	indexDim         int
	docs             map[string]map[string]any
	unknownCommand   bool
	forceWrongScope  string
	ftCreateCount    int
	ftSearchCount    int
	hsetExpireCount  int
	lastTTLSec       int64
	returnRESP2Shape bool
}

func newFakeVectorRedisClient() *fakeVectorRedisClient {
	return &fakeVectorRedisClient{docs: make(map[string]map[string]any)}
}

var (
	reScopeFilter = regexp.MustCompile(`@scope:\{([^}]+)\}`)
	reOrgFilter   = regexp.MustCompile(`@org_id:\{([^}]+)\}`)
	reModelFilter = regexp.MustCompile(`@model:\{([^}]+)\}`)
)

func (f *fakeVectorRedisClient) Do(_ context.Context, args ...any) (any, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(args) == 0 {
		return nil, errors.New("empty command")
	}
	cmd := strings.ToUpper(fmt.Sprint(args[0]))
	if f.unknownCommand && strings.HasPrefix(cmd, "FT.") {
		return nil, fmt.Errorf("ERR unknown command '%s'", cmd)
	}
	switch cmd {
	case "FT.INFO":
		if !f.indexCreated {
			return nil, errors.New("Unknown index name")
		}
		if f.returnRESP2Shape {
			return []any{
				"index_name", f.indexName,
				"attributes", []any{
					[]any{
						"identifier", "embedding",
						"attribute", "embedding",
						"type", "VECTOR",
						"algorithm", f.indexAlgorithm,
						"dim", int64(f.indexDim),
					},
				},
			}, nil
		}
		return map[any]any{
			"index_name": f.indexName,
			"attributes": []any{
				map[any]any{
					"identifier": "embedding",
					"attribute":  "embedding",
					"type":       "VECTOR",
					"index": map[any]any{
						"algorithm":  f.indexAlgorithm,
						"dimensions": int64(f.indexDim),
					},
				},
			},
		}, nil
	case "FT.CREATE":
		f.indexCreated = true
		f.ftCreateCount++
		f.indexName = fmt.Sprint(args[1])
		for i := 2; i < len(args); i++ {
			if strings.ToUpper(fmt.Sprint(args[i])) == "VECTOR" && i+1 < len(args) {
				f.indexAlgorithm = strings.ToUpper(fmt.Sprint(args[i+1]))
			}
			if strings.ToUpper(fmt.Sprint(args[i])) == "DIM" && i+1 < len(args) {
				_, _ = fmt.Sscanf(fmt.Sprint(args[i+1]), "%d", &f.indexDim)
			}
		}
		return "OK", nil
	case "HSET":
		key := fmt.Sprint(args[1])
		doc := make(map[string]any)
		for i := 2; i+1 < len(args); i += 2 {
			doc[fmt.Sprint(args[i])] = args[i+1]
		}
		f.docs[key] = doc
		return int64(len(doc)), nil
	case "EXPIRE":
		return int64(1), nil
	case "FT.SEARCH":
		if !f.indexCreated {
			return nil, errors.New("SEARCH_INDEX_NOT_FOUND Index not found: " + fmt.Sprint(args[1]))
		}
		f.ftSearchCount++
		query := fmt.Sprint(args[2])

		// NOCONTENT tag search for invalidation.
		isNoContent := false
		var queryVec []float32
		for i := 3; i < len(args); i++ {
			tok := strings.ToUpper(fmt.Sprint(args[i]))
			if tok == "NOCONTENT" {
				isNoContent = true
			}
			if tok == "VEC" && i+1 < len(args) {
				if rawBytes, ok := args[i+1].([]byte); ok {
					queryVec = bytesToFloat32Slice(rawBytes)
				}
			}
		}

		var wantScope, wantOrg, wantModel string
		if m := reScopeFilter.FindStringSubmatch(query); len(m) == 2 {
			wantScope = m[1]
		}
		if m := reOrgFilter.FindStringSubmatch(query); len(m) == 2 {
			wantOrg = m[1]
		}
		if m := reModelFilter.FindStringSubmatch(query); len(m) == 2 {
			wantModel = m[1]
		}

		type scored struct {
			id   string
			doc  map[string]any
			dist float64
		}
		var matches []scored
		for id, doc := range f.docs {
			if wantScope != "" && fmt.Sprint(doc["scope"]) != wantScope && f.forceWrongScope == "" {
				continue
			}
			if wantOrg != "" && fmt.Sprint(doc["org_id"]) != wantOrg {
				continue
			}
			if wantModel != "" {
				matchedTag := false
				for _, tag := range strings.Split(fmt.Sprint(doc["model"]), ",") {
					if strings.TrimSpace(tag) == wantModel {
						matchedTag = true
						break
					}
				}
				if !matchedTag {
					continue
				}
			}
			dist := 0.0
			if len(queryVec) > 0 {
				if rawVec, ok := doc["embedding"].([]byte); ok {
					dist = cosineDistance(queryVec, bytesToFloat32Slice(rawVec))
				}
			}
			matches = append(matches, scored{id: id, doc: doc, dist: dist})
		}
		sort.Slice(matches, func(i, j int) bool { return matches[i].dist < matches[j].dist })

		if isNoContent {
			results := make([]any, 0, len(matches))
			for _, m := range matches {
				results = append(results, map[any]any{"id": m.id})
			}
			return map[any]any{"total_results": int64(len(matches)), "results": results}, nil
		}

		if len(matches) == 0 {
			if f.returnRESP2Shape {
				return []any{int64(0)}, nil
			}
			return map[any]any{"total_results": int64(0), "results": []any{}}, nil
		}

		top := matches[0]
		scopeVal := fmt.Sprint(top.doc["scope"])
		if f.forceWrongScope != "" {
			scopeVal = f.forceWrongScope
		}
		if f.returnRESP2Shape {
			return []any{
				int64(1),
				top.id,
				[]any{
					"scope", scopeVal,
					"response", fmt.Sprint(top.doc["response"]),
					"prompt", fmt.Sprint(top.doc["prompt"]),
					"vector_distance", fmt.Sprintf("%.6f", top.dist),
				},
			}, nil
		}
		return map[any]any{
			"total_results": int64(1),
			"results": []any{
				map[any]any{
					"id": top.id,
					"extra_attributes": map[any]any{
						"scope":           scopeVal,
						"response":        fmt.Sprint(top.doc["response"]),
						"prompt":          fmt.Sprint(top.doc["prompt"]),
						"vector_distance": fmt.Sprintf("%.6f", top.dist),
					},
				},
			},
		}, nil
	default:
		return nil, fmt.Errorf("unsupported fake cmd %s", cmd)
	}
}

func (f *fakeVectorRedisClient) HSetWithExpire(_ context.Context, key string, ttlSec int64, kvPairs ...any) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	doc := make(map[string]any)
	for i := 0; i+1 < len(kvPairs); i += 2 {
		doc[fmt.Sprint(kvPairs[i])] = kvPairs[i+1]
	}
	f.docs[key] = doc
	f.hsetExpireCount++
	f.lastTTLSec = ttlSec
	return nil
}

func (f *fakeVectorRedisClient) ScanKeys(_ context.Context, pattern string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var keys []string
	for k := range f.docs {
		if ok, _ := path.Match(pattern, k); ok {
			keys = append(keys, k)
		}
	}
	return keys, nil
}

func (f *fakeVectorRedisClient) UnlinkKeys(_ context.Context, keys []string) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, k := range keys {
		if _, ok := f.docs[k]; ok {
			delete(f.docs, k)
			n++
		}
	}
	return n, nil
}

func bytesToFloat32Slice(b []byte) []float32 {
	out := make([]float32, len(b)/4)
	for i := range out {
		out[i] = math.Float32frombits(binary.LittleEndian.Uint32(b[i*4:]))
	}
	return out
}

func cosineDistance(a, b []float32) float64 {
	if len(a) == 0 || len(a) != len(b) {
		return 2.0
	}
	var dot, na, nb float64
	for i := range a {
		dot += float64(a[i]) * float64(b[i])
		na += float64(a[i]) * float64(a[i])
		nb += float64(b[i]) * float64(b[i])
	}
	if na == 0 || nb == 0 {
		return 2.0
	}
	return 1.0 - (dot / (math.Sqrt(na) * math.Sqrt(nb)))
}

func TestRedisSemanticBackend_SingleEmbedPerMissSimilarityAndScopeIsolation(t *testing.T) {
	fake := newFakeVectorRedisClient()
	var embedCalls atomic.Int32

	// Deterministic 3D vectors: France queries are nearly colinear (~0.995 similarity),
	// water boiling query is orthogonal (~0.0 similarity).
	embedFn := func(_ context.Context, _, _, input string) ([]float32, error) {
		embedCalls.Add(1)
		lower := strings.ToLower(input)
		switch {
		case strings.Contains(lower, "capital of france"):
			return []float32{1.0, 0.0, 0.0}, nil
		case strings.Contains(lower, "france's capital"):
			return []float32{0.995, 0.0998, 0.0}, nil // cosine sim ~0.995
		case strings.Contains(lower, "boiling point"):
			return []float32{0.0, 0.0, 1.0}, nil // cosine sim 0.0
		default:
			return []float32{0.5, 0.5, 0.5}, nil
		}
	}

	semCfg := config.SemanticCacheConfig{
		EmbeddingModel:      "gemini-embedding-001",
		SimilarityThreshold: 0.90,
		IndexName:           "gw_test_sem_idx",
		VectorAlgorithm:     config.VectorAlgorithmHNSW,
		EmbeddingTimeout:    2 * time.Second,
		MaxMessages:         4,
		MaxInputChars:       8000,
	}
	backend := newRedisSemanticBackendWithClient(nil, fake, "gw:cache", 1<<20, semCfg, embedFn)
	rc := NewResponseCacheWithBackend(true, time.Hour, backend, []string{"embedding"}, 4)

	ctx := context.Background()
	req1 := &domain.CanonicalChatRequest{
		Model: "gemini-2.5-flash",
		Messages: []domain.CanonicalMessage{
			{Role: "system", Content: "Be concise."},
			{Role: "user", Content: "What is the capital of France?"},
		},
	}

	// 1. First request misses, lazily creates HNSW index with DIM=3, and embeds ONCE.
	lookup1 := rc.LookupChat(ctx, "org-1", "team-1", "", req1, RequestCacheOptions{})
	require.True(t, lookup1.Eligible)
	require.False(t, lookup1.Hit)
	assert.Equal(t, int32(1), embedCalls.Load())
	assert.True(t, fake.indexCreated)
	assert.Equal(t, "HNSW", fake.indexAlgorithm)
	assert.Equal(t, 3, fake.indexDim)

	// 2. StoreChat reuses lookup1's embedding -> STILL only 1 embed call total!
	rc.StoreChat(ctx, lookup1, "org-1", &domain.CanonicalChatResponse{
		ID:       "resp-france",
		Provider: domain.ProviderOpenAI,
		Model:    "gemini-2.5-flash",
		Choices:  []domain.CanonicalChoice{{Index: 0, Message: domain.CanonicalMessage{Role: "assistant", Content: "Paris."}}},
	})
	assert.Equal(t, int32(1), embedCalls.Load(), "StoreChat must reuse miss embedding without a second embed call")

	// 3. Paraphrased query in same scope -> semantic HIT!
	reqParaphrase := &domain.CanonicalChatRequest{
		Model: "gemini-2.5-flash",
		Messages: []domain.CanonicalMessage{
			{Role: "system", Content: "Be concise."},
			{Role: "user", Content: "Tell me France's capital city."},
		},
	}
	hit2 := rc.LookupChat(ctx, "org-1", "team-1", "", reqParaphrase, RequestCacheOptions{})
	require.True(t, hit2.Hit)
	assert.Equal(t, CacheHitTypeSemantic, hit2.CacheType)
	assert.GreaterOrEqual(t, hit2.Similarity, 0.99)
	assert.Equal(t, "Paris.", hit2.Response.Choices[0].Message.Content)
	assert.Equal(t, uint64(1), rc.Metrics().SemanticHits)

	// 4. Unrelated prompt -> below threshold MISS.
	reqUnrelated := &domain.CanonicalChatRequest{
		Model: "gemini-2.5-flash",
		Messages: []domain.CanonicalMessage{
			{Role: "system", Content: "Be concise."},
			{Role: "user", Content: "What is the boiling point of water?"},
		},
	}
	miss3 := rc.LookupChat(ctx, "org-1", "team-1", "", reqUnrelated, RequestCacheOptions{})
	assert.False(t, miss3.Hit)

	// 5. Strict isolation: different org OR different system prompt MUST MISS.
	missOtherOrg := rc.LookupChat(ctx, "org-2", "team-1", "", reqParaphrase, RequestCacheOptions{})
	assert.False(t, missOtherOrg.Hit, "cross-org semantic hit must never occur")

	reqDiffSys := &domain.CanonicalChatRequest{
		Model: "gemini-2.5-flash",
		Messages: []domain.CanonicalMessage{
			{Role: "system", Content: "Answer in French poems."},
			{Role: "user", Content: "Tell me France's capital city."},
		},
	}
	missDiffSys := rc.LookupChat(ctx, "org-1", "team-1", "", reqDiffSys, RequestCacheOptions{})
	assert.False(t, missDiffSys.Hit, "different system prompt must isolate scope")

	// 6. max_messages guard skips long conversations (> 4 non-system messages).
	longReq := &domain.CanonicalChatRequest{
		Model: "gemini-2.5-flash",
		Messages: []domain.CanonicalMessage{
			{Role: "user", Content: "turn 1"},
			{Role: "assistant", Content: "a1"},
			{Role: "user", Content: "turn 2"},
			{Role: "assistant", Content: "a2"},
			{Role: "user", Content: "Tell me France's capital city."},
		},
	}
	beforeLong := embedCalls.Load()
	missLong := rc.LookupChat(ctx, "org-1", "team-1", "", longReq, RequestCacheOptions{})
	assert.False(t, missLong.Hit)
	assert.Equal(t, beforeLong, embedCalls.Load(), "requests exceeding max_messages must skip embedding")

	// 7. Model-scoped invalidation removes matching semantic docs without dropping index.
	purged, _, err := rc.Invalidate(ctx, "org-1", "gemini-2.5-flash")
	require.NoError(t, err)
	assert.Equal(t, 1, purged)
	assert.False(t, rc.LookupChat(ctx, "org-1", "team-1", "", reqParaphrase, RequestCacheOptions{}).Hit)
}

func TestRedisSemanticBackend_RESP2ParsingDefenseInDepthAndFailOpen(t *testing.T) {
	fake := newFakeVectorRedisClient()
	fake.returnRESP2Shape = true

	embedFn := func(_ context.Context, _, _, _ string) ([]float32, error) {
		return []float32{1, 0}, nil
	}
	semCfg := config.SemanticCacheConfig{
		EmbeddingModel:      "gemini-embedding-001",
		SimilarityThreshold: 0.90,
		IndexName:           "gw_resp2_idx",
		VectorAlgorithm:     config.VectorAlgorithmFLAT,
		EmbeddingTimeout:    time.Second,
		MaxMessages:         4,
	}
	backend := newRedisSemanticBackendWithClient(nil, fake, "gw:cache", 1<<20, semCfg, embedFn)
	rc := NewResponseCacheWithBackend(true, time.Hour, backend, []string{"embedding"}, 4)

	ctx := context.Background()
	req := &domain.CanonicalChatRequest{
		Model:    "gemini-2.5-flash",
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "hello"}},
	}
	miss := rc.LookupChat(ctx, "org-1", "", "", req, RequestCacheOptions{})
	rc.StoreChat(ctx, miss, "org-1", &domain.CanonicalChatResponse{
		ID:      "resp-1",
		Model:   "gemini-2.5-flash",
		Choices: []domain.CanonicalChoice{{Index: 0, Message: domain.CanonicalMessage{Role: "assistant", Content: "hi"}}},
	})
	assert.Equal(t, "FLAT", fake.indexAlgorithm)

	// RESP2 response parses cleanly.
	hit := rc.LookupChat(ctx, "org-1", "", "", req, RequestCacheOptions{})
	require.True(t, hit.Hit)
	assert.Equal(t, "hi", hit.Response.Choices[0].Message.Content)

	// Defense-in-depth: mismatched scope field returned by Redis is rejected.
	fake.forceWrongScope = "wrong-scope-tag"
	rejected := rc.LookupChat(ctx, "org-1", "", "", req, RequestCacheOptions{})
	assert.False(t, rejected.Hit)
	fake.forceWrongScope = ""

	// Unknown command (e.g. Redis 7 without RediSearch) fails open cleanly.
	fakeNoSearch := newFakeVectorRedisClient()
	fakeNoSearch.unknownCommand = true
	bNoSearch := newRedisSemanticBackendWithClient(nil, fakeNoSearch, "gw:cache", 1<<20, semCfg, embedFn)
	rcNoSearch := NewResponseCacheWithBackend(true, time.Hour, bNoSearch, []string{"embedding"}, 4)

	res := rcNoSearch.LookupChat(ctx, "org-1", "", "", req, RequestCacheOptions{})
	assert.False(t, res.Hit)
	assert.True(t, bNoSearch.searchUnsupported.Load())
	assert.GreaterOrEqual(t, rcNoSearch.Metrics().Errors, uint64(1))
}

func TestRedisSemanticBackend_EmbeddingTimeoutFailsOpen(t *testing.T) {
	fake := newFakeVectorRedisClient()
	slowEmbed := func(ctx context.Context, _, _, _ string) ([]float32, error) {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(500 * time.Millisecond):
			return []float32{1, 0}, nil
		}
	}
	semCfg := config.SemanticCacheConfig{
		EmbeddingModel:      "gemini-embedding-001",
		SimilarityThreshold: 0.90,
		EmbeddingTimeout:    25 * time.Millisecond,
	}
	backend := newRedisSemanticBackendWithClient(nil, fake, "gw:cache", 1<<20, semCfg, slowEmbed)
	rc := NewResponseCacheWithBackend(true, time.Hour, backend, []string{"embedding"}, 4)

	req := &domain.CanonicalChatRequest{
		Model:    "gemini-2.5-flash",
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "slow"}},
	}
	res := rc.LookupChat(context.Background(), "org-1", "", "", req, RequestCacheOptions{})
	assert.False(t, res.Hit)
	assert.GreaterOrEqual(t, rc.Metrics().Errors, uint64(1))
}

func TestRedisSemanticBackend_AliasInvalidationAndSelfHealingAfterRestart(t *testing.T) {
	fake := newFakeVectorRedisClient()
	embedFn := func(_ context.Context, _, _, _ string) ([]float32, error) {
		return []float32{1, 0, 0}, nil
	}
	semCfg := config.SemanticCacheConfig{
		EmbeddingModel:      "gemini-embedding-001",
		SimilarityThreshold: 0.90,
		IndexName:           "gw_selfheal_idx",
		VectorAlgorithm:     config.VectorAlgorithmHNSW,
		EmbeddingTimeout:    2 * time.Second,
	}
	backend := newRedisSemanticBackendWithClient(nil, fake, "gw:cache", 1<<20, semCfg, embedFn)
	rc := NewResponseCacheWithBackend(true, time.Hour, backend, []string{"embedding"}, 4)
	ctx := context.Background()

	// 1. Store using ModelGroup alias "fast-chat" resolving to upstream "gemini-3.5-flash-lite".
	req := &domain.CanonicalChatRequest{
		Model:    "fast-chat",
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "capital of japan"}},
	}
	miss := rc.LookupChat(ctx, "org-1", "", "", req, RequestCacheOptions{})
	require.False(t, miss.Hit)
	rc.StoreChat(ctx, miss, "org-1", &domain.CanonicalChatResponse{
		ID:      "resp-1",
		Model:   "gemini-3.5-flash-lite",
		Choices: []domain.CanonicalChoice{{Index: 0, Message: domain.CanonicalMessage{Role: "assistant", Content: "Tokyo"}}},
	})

	// 2. Invalidating by the ModelGroup alias "fast-chat" purges the indexed semantic doc.
	purged, _, err := rc.Invalidate(ctx, "org-1", "fast-chat")
	require.NoError(t, err)
	assert.Equal(t, 1, purged)

	// 3. Simulate ephemeral Redis restart (index & docs wiped) while backend still has indexReady=true.
	fake.mu.Lock()
	fake.indexCreated = false
	fake.docs = make(map[string]map[string]any)
	fake.mu.Unlock()
	require.True(t, backend.indexReady.Load())

	// Next LookupChat sees "no such index", resets indexReady, lazily runs FT.CREATE, and StoreChat succeeds!
	afterRestartMiss := rc.LookupChat(ctx, "org-1", "", "", req, RequestCacheOptions{})
	require.False(t, afterRestartMiss.Hit)
	rc.StoreChat(ctx, afterRestartMiss, "org-1", &domain.CanonicalChatResponse{
		ID:      "resp-2",
		Model:   "gemini-3.5-flash-lite",
		Choices: []domain.CanonicalChoice{{Index: 0, Message: domain.CanonicalMessage{Role: "assistant", Content: "Tokyo"}}},
	})

	// Subsequent paraphrase hits seamlessly on the recreated RediSearch index.
	hit := rc.LookupChat(ctx, "org-1", "", "", &domain.CanonicalChatRequest{
		Model:    "fast-chat",
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "japan capital city"}},
	}, RequestCacheOptions{})
	require.True(t, hit.Hit)
	assert.Equal(t, CacheHitTypeSemantic, hit.CacheType)
	assert.GreaterOrEqual(t, fake.ftCreateCount, 2)
	assert.GreaterOrEqual(t, fake.hsetExpireCount, 2, "StoreSemantic must use atomic HSetWithExpire")
	assert.Equal(t, int64(3600), fake.lastTTLSec)
}

func TestRedisSemanticBackend_MultimodalToolAndMultiTurnScopeIsolation(t *testing.T) {
	fake := newFakeVectorRedisClient()
	var embedCalls atomic.Int32
	embedFn := func(_ context.Context, _, _, _ string) ([]float32, error) {
		embedCalls.Add(1)
		return []float32{1, 0, 0}, nil
	}
	semCfg := config.SemanticCacheConfig{
		EmbeddingModel:      "gemini-embedding-001",
		SimilarityThreshold: 0.90,
		IndexName:           "gw_safety_idx",
		VectorAlgorithm:     config.VectorAlgorithmHNSW,
		EmbeddingTimeout:    2 * time.Second,
		MaxMessages:         -1, // Unlimited turns (H4)
	}
	backend := newRedisSemanticBackendWithClient(nil, fake, "gw:cache", 1<<20, semCfg, embedFn)
	rc := NewResponseCacheWithBackend(true, time.Hour, backend, []string{"embedding"}, -1)
	ctx := context.Background()

	// 1. Multimodal image message must skip semantic caching completely (H2).
	imgReq := &domain.CanonicalChatRequest{
		Model: "gemini-3.5-flash-lite",
		Messages: []domain.CanonicalMessage{{
			Role:    "user",
			Content: "Describe this image",
			Parts: []domain.ContentPart{
				{Type: "text", Text: "Describe this image"},
				{Type: "image_url", ImageURL: &domain.ImageURL{URL: "https://example.com/a.png"}},
			},
		}},
	}
	imgLookup := rc.LookupChat(ctx, "org-1", "", "", imgReq, RequestCacheOptions{})
	assert.False(t, imgLookup.Hit)
	assert.Equal(t, int32(0), embedCalls.Load(), "multimodal image requests must bypass semantic embedding")

	// 2. Document part must also bypass semantic caching (H2).
	docReq := &domain.CanonicalChatRequest{
		Model: "gemini-3.5-flash-lite",
		Messages: []domain.CanonicalMessage{{
			Role:    "user",
			Content: "Summarize this PDF",
			Parts: []domain.ContentPart{
				{Type: "document", Document: &domain.DocumentPart{MimeType: "application/pdf", Data: "JVBERi0="}},
			},
		}},
	}
	docLookup := rc.LookupChat(ctx, "org-1", "", "", docReq, RequestCacheOptions{})
	assert.False(t, docLookup.Hit)
	assert.Equal(t, int32(0), embedCalls.Load(), "multimodal document requests must bypass semantic embedding")

	// 3. Tool-result / tool_calls messages must bypass semantic caching (H2).
	toolReq := &domain.CanonicalChatRequest{
		Model: "gemini-3.5-flash-lite",
		Messages: []domain.CanonicalMessage{
			{Role: "user", Content: "What is the weather?"},
			{Role: "assistant", ToolCalls: []domain.CanonicalToolCall{{ID: "tc-1", Type: "function"}}},
			{Role: "tool", ToolCallID: "tc-1", Content: `{"temp":72}`},
			{Role: "user", Content: "Summarize it"},
		},
	}
	toolLookup := rc.LookupChat(ctx, "org-1", "", "", toolReq, RequestCacheOptions{})
	assert.False(t, toolLookup.Hit)
	assert.Equal(t, int32(0), embedCalls.Load(), "tool-call conversations must bypass semantic embedding")

	// 4. Multi-turn conversations with different prior turns MUST NOT collide (H2),
	//    and max_messages: -1 must allow > 4 non-system turns (H4).
	pythonTurns := &domain.CanonicalChatRequest{
		Model: "gemini-3.5-flash-lite",
		Messages: []domain.CanonicalMessage{
			{Role: "user", Content: "Let's discuss Python."},
			{Role: "assistant", Content: "Sure, Python is great."},
			{Role: "user", Content: "How do decorators work?"},
			{Role: "assistant", Content: "They wrap functions."},
			{Role: "user", Content: "How do I install packages?"},
		},
	}
	rustTurns := &domain.CanonicalChatRequest{
		Model: "gemini-3.5-flash-lite",
		Messages: []domain.CanonicalMessage{
			{Role: "user", Content: "Let's discuss Rust."},
			{Role: "assistant", Content: "Sure, Rust is great."},
			{Role: "user", Content: "How does ownership work?"},
			{Role: "assistant", Content: "Values have a single owner."},
			{Role: "user", Content: "How do I install packages?"},
		},
	}
	missPy := rc.LookupChat(ctx, "org-1", "", "", pythonTurns, RequestCacheOptions{})
	require.False(t, missPy.Hit)
	assert.Equal(t, int32(1), embedCalls.Load(), "max_messages=-1 must embed 5-turn conversation")
	rc.StoreChat(ctx, missPy, "org-1", &domain.CanonicalChatResponse{
		ID:      "resp-py",
		Model:   "gemini-3.5-flash-lite",
		Choices: []domain.CanonicalChoice{{Index: 0, Message: domain.CanonicalMessage{Role: "assistant", Content: "Use pip install."}}},
	})

	// Same final prompt under Rust prior turns MUST MISS!
	missRust := rc.LookupChat(ctx, "org-1", "", "", rustTurns, RequestCacheOptions{})
	assert.False(t, missRust.Hit, "different prior turns must isolate semantic scope")

	// Same prior turns with paraphrased final user message HITS!
	pythonParaphrase := &domain.CanonicalChatRequest{
		Model: "gemini-3.5-flash-lite",
		Messages: []domain.CanonicalMessage{
			{Role: "user", Content: "Let's discuss Python."},
			{Role: "assistant", Content: "Sure, Python is great."},
			{Role: "user", Content: "How do decorators work?"},
			{Role: "assistant", Content: "They wrap functions."},
			{Role: "user", Content: "How can I install third-party libraries?"},
		},
	}
	hitPy := rc.LookupChat(ctx, "org-1", "", "", pythonParaphrase, RequestCacheOptions{})
	require.True(t, hitPy.Hit)
	assert.Equal(t, "Use pip install.", hitPy.Response.Choices[0].Message.Content)

	// 5. Different ExtraParams (e.g. n=2) or User isolates semantic scope (M1).
	reqN2 := &domain.CanonicalChatRequest{
		Model:       "gemini-3.5-flash-lite",
		Messages:    pythonParaphrase.Messages,
		ExtraParams: map[string]any{"n": 2},
	}
	assert.False(t, rc.LookupChat(ctx, "org-1", "", "", reqN2, RequestCacheOptions{}).Hit, "ExtraParams must isolate semantic scope")

	reqOtherUser := &domain.CanonicalChatRequest{
		Model:    "gemini-3.5-flash-lite",
		Messages: pythonParaphrase.Messages,
		User:     "user-42",
	}
	assert.False(t, rc.LookupChat(ctx, "org-1", "", "", reqOtherUser, RequestCacheOptions{}).Hit, "User must isolate semantic scope")
}

func TestRedisSemanticBackend_DimensionMismatchDetectionAndUTF8Truncation(t *testing.T) {
	// 1. FT.INFO dimension mismatch returns error & increments error counter instead of silently indexing wrong dim (H5).
	fake := newFakeVectorRedisClient()
	fake.indexCreated = true
	fake.indexName = "gw_dim_idx"
	fake.indexAlgorithm = "HNSW"
	fake.indexDim = 1536 // Pre-existing index created with 1536-dim model

	embed3072 := func(_ context.Context, _, _, _ string) ([]float32, error) {
		return make([]float32, 3072), nil
	}
	semCfg := config.SemanticCacheConfig{
		EmbeddingModel:      "gemini-embedding-001",
		SimilarityThreshold: 0.90,
		IndexName:           "gw_dim_idx",
		VectorAlgorithm:     config.VectorAlgorithmHNSW,
		EmbeddingTimeout:    time.Second,
	}
	backend := newRedisSemanticBackendWithClient(nil, fake, "gw:cache", 1<<20, semCfg, embed3072)
	rc := NewResponseCacheWithBackend(true, time.Hour, backend, []string{"embedding"}, 4)

	res := rc.LookupChat(context.Background(), "org-1", "", "", &domain.CanonicalChatRequest{
		Model:    "gemini-3.5-flash-lite",
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "hello"}},
	}, RequestCacheOptions{})
	assert.False(t, res.Hit)
	assert.False(t, backend.indexReady.Load(), "mismatched index must not mark indexReady=true")
	assert.GreaterOrEqual(t, rc.Metrics().Errors, uint64(1))

	// 2. Rune-safe UTF-8 truncation never splits multi-byte CJK/emoji runes (M9).
	cjk := "你好世界🚀GoRoute"
	got := truncateUTF8(cjk, 5)
	assert.Equal(t, "你好世界🚀", got)
	assert.Equal(t, cjk, truncateUTF8(cjk, 100))
}
