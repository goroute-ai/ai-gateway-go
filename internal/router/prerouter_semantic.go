package router

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/redis/go-redis/v9"
)

const (
	defaultSemanticSimilarityThreshold = 0.75
	defaultSemanticEmbedTimeout        = 500 * time.Millisecond
	semanticCentroidRedisTTL           = 24 * time.Hour
)

// EmbedFn embeds a batch of input strings for a given organization and model,
// returning one float32 vector per input string.
type EmbedFn func(ctx context.Context, orgID, model string, inputs []string) ([][]float32, error)

type semanticRouteEntry struct {
	Name        string      `json:"name"`
	TargetAlias string      `json:"target_alias"`
	Centroid    []float32   `json:"centroid,omitempty"`
	Utterances  [][]float32 `json:"utterances,omitempty"`
}

// SemanticPreRouter routes requests based on cosine similarity between the
// latest user message embedding and pre-warmed route utterance embeddings.
// Any miss, timeout, empty input, or embedding error fails open to DefaultAlias.
type SemanticPreRouter struct {
	cfg          config.SemanticRouterConfig
	defaultAlias string
	embedFn      EmbedFn
	redis        *storage.RedisFabric

	mu    sync.RWMutex
	cache map[string][]semanticRouteEntry
}

// NewSemanticPreRouter constructs a SemanticPreRouter from SemanticRouterConfig.
// defaultAlias defaults to "fast" when empty, SimilarityThreshold defaults to 0.75,
// and Timeout defaults to 500ms.
func NewSemanticPreRouter(cfg config.SemanticRouterConfig, defaultAlias string, embedFn EmbedFn, redisFabric *storage.RedisFabric) *SemanticPreRouter {
	if strings.TrimSpace(defaultAlias) == "" {
		defaultAlias = "fast"
	}
	if cfg.SimilarityThreshold <= 0 {
		cfg.SimilarityThreshold = defaultSemanticSimilarityThreshold
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = defaultSemanticEmbedTimeout
	}
	return &SemanticPreRouter{
		cfg:          cfg,
		defaultAlias: strings.TrimSpace(defaultAlias),
		embedFn:      embedFn,
		redis:        redisFabric,
		cache:        make(map[string][]semanticRouteEntry),
	}
}

// Name returns "semantic".
func (s *SemanticPreRouter) Name() string {
	return PreRouterModeSemantic
}

// DefaultAlias returns the fail-open target alias used when no route matches
// or when embedding fails or times out.
func (s *SemanticPreRouter) DefaultAlias() string {
	if s == nil || s.defaultAlias == "" {
		return "fast"
	}
	return s.defaultAlias
}

// SemanticCentroidsRedisKey returns the Redis Cluster hash-tag safe key used to
// persist warmed semantic route centroids and utterance vectors for an org.
func SemanticCentroidsRedisKey(orgID string) string {
	return fmt.Sprintf("gw:router:semantic:{org:%s}:centroids", orgID)
}

// Warmup batch-embeds all configured route utterances once for orgID,
// L2-normalizes every utterance vector, computes each route's normalized centroid,
// and stores the result in memory (and optionally in Redis).
func (s *SemanticPreRouter) Warmup(ctx context.Context, orgID string) error {
	if s == nil {
		return errors.New("semantic pre-router is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}

	type utteranceRef struct {
		routeIdx int
		text     string
	}
	type routeSpec struct {
		name        string
		targetAlias string
		inputs      []string
	}

	specs := make([]routeSpec, 0, len(s.cfg.Routes))
	var allInputs []string
	var refs []utteranceRef

	for _, r := range s.cfg.Routes {
		target := strings.TrimSpace(r.TargetModel)
		if target == "" {
			continue
		}
		var inputs []string
		for _, u := range r.Utterances {
			if trimmed := strings.TrimSpace(u); trimmed != "" {
				inputs = append(inputs, trimmed)
			}
		}
		if len(inputs) == 0 {
			if desc := strings.TrimSpace(r.Description); desc != "" {
				inputs = append(inputs, desc)
			}
		}
		if len(inputs) == 0 {
			continue
		}
		routeIdx := len(specs)
		specs = append(specs, routeSpec{
			name:        strings.TrimSpace(r.Name),
			targetAlias: target,
			inputs:      inputs,
		})
		for _, in := range inputs {
			refs = append(refs, utteranceRef{routeIdx: routeIdx, text: in})
			allInputs = append(allInputs, in)
		}
	}

	if len(allInputs) == 0 {
		s.mu.Lock()
		s.cache[orgID] = nil
		s.mu.Unlock()
		return nil
	}
	if s.embedFn == nil {
		return errors.New("semantic pre-router embed function is nil")
	}

	vectors, err := s.embedFn(ctx, orgID, s.cfg.EmbeddingModel, allInputs)
	if err != nil {
		return fmt.Errorf("semantic warmup embed: %w", err)
	}
	if len(vectors) != len(allInputs) {
		return fmt.Errorf("semantic warmup embed: got %d vectors for %d utterances", len(vectors), len(allInputs))
	}

	entries := make([]semanticRouteEntry, len(specs))
	for i, sp := range specs {
		name := sp.name
		if name == "" {
			name = sp.targetAlias
		}
		entries[i] = semanticRouteEntry{
			Name:        name,
			TargetAlias: sp.targetAlias,
			Utterances:  make([][]float32, 0, len(sp.inputs)),
		}
	}

	for i, ref := range refs {
		normVec, ok := normalizeL2(vectors[i])
		if !ok {
			continue
		}
		entries[ref.routeIdx].Utterances = append(entries[ref.routeIdx].Utterances, normVec)
	}

	for i := range entries {
		entries[i].Centroid = computeNormalizedCentroid(entries[i].Utterances)
	}

	s.mu.Lock()
	s.cache[orgID] = entries
	s.mu.Unlock()

	if s.redis != nil && s.redis.Client() != nil {
		if payload, mErr := json.Marshal(entries); mErr == nil {
			key := SemanticCentroidsRedisKey(orgID)
			_, _ = s.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
				return rdb.Set(ctx, key, payload, semanticCentroidRedisTTL).Result()
			})
		}
	}

	return nil
}

// Route embeds the latest user message within the configured timeout and matches
// against warmed utterance vectors. It always fails open to DefaultAlias (err == nil).
func (s *SemanticPreRouter) Route(ctx context.Context, orgID string, req *domain.CanonicalChatRequest) (string, string, float64, error) {
	if s == nil {
		return "fast", "semantic:nil_router", 0, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}

	query := extractLatestUserText(req)
	if query == "" {
		return s.defaultAlias, "semantic:empty_query", 0, nil
	}
	if s.embedFn == nil {
		return s.defaultAlias, "semantic:no_embed_fn", 0, nil
	}

	entries := s.loadRouteEntries(ctx, orgID)
	if len(entries) == 0 {
		return s.defaultAlias, "semantic:not_warmed_up", 0, nil
	}

	embedCtx, cancel := context.WithTimeout(ctx, s.cfg.Timeout)
	defer cancel()

	vectors, err := s.embedFn(embedCtx, orgID, s.cfg.EmbeddingModel, []string{query})
	if err != nil || len(vectors) == 0 {
		return s.defaultAlias, "semantic:embed_fallback", 0, nil
	}

	queryVec, ok := normalizeL2(vectors[0])
	if !ok {
		return s.defaultAlias, "semantic:zero_vector_fallback", 0, nil
	}

	bestScore := -1.0
	var bestEntry *semanticRouteEntry
	for i := range entries {
		entry := &entries[i]
		routeScore := maxRouteSimilarity(queryVec, entry)
		if routeScore > bestScore {
			bestScore = routeScore
			bestEntry = entry
		}
	}

	if bestScore < 0 {
		bestScore = 0
	}
	if bestEntry != nil && bestScore >= s.cfg.SimilarityThreshold {
		return bestEntry.TargetAlias, "semantic:route:" + bestEntry.Name, bestScore, nil
	}

	return s.defaultAlias, "semantic:below_threshold", bestScore, nil
}

func (s *SemanticPreRouter) loadRouteEntries(ctx context.Context, orgID string) []semanticRouteEntry {
	s.mu.RLock()
	entries, ok := s.cache[orgID]
	if !ok && orgID != "" {
		entries, ok = s.cache[""]
	}
	s.mu.RUnlock()
	if ok {
		return entries
	}

	if s.redis == nil || s.redis.Client() == nil {
		return nil
	}

	redisCtx, cancel := context.WithTimeout(ctx, s.cfg.Timeout)
	defer cancel()

	key := SemanticCentroidsRedisKey(orgID)
	raw, err := s.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
		return rdb.Get(redisCtx, key).Bytes()
	})
	if err != nil {
		return nil
	}
	b, ok := raw.([]byte)
	if !ok || len(b) == 0 {
		return nil
	}

	var decoded []semanticRouteEntry
	if err := json.Unmarshal(b, &decoded); err != nil {
		return nil
	}

	// Ensure vectors loaded from Redis are normalized even if written externally.
	for i := range decoded {
		if len(decoded[i].Centroid) > 0 {
			if norm, valid := normalizeL2(decoded[i].Centroid); valid {
				decoded[i].Centroid = norm
			} else {
				decoded[i].Centroid = nil
			}
		}
		for j := range decoded[i].Utterances {
			if norm, valid := normalizeL2(decoded[i].Utterances[j]); valid {
				decoded[i].Utterances[j] = norm
			} else {
				decoded[i].Utterances[j] = nil
			}
		}
	}

	s.mu.Lock()
	s.cache[orgID] = decoded
	s.mu.Unlock()

	return decoded
}

func maxRouteSimilarity(queryVec []float32, entry *semanticRouteEntry) float64 {
	if entry == nil {
		return -1
	}
	best := -1.0
	for _, u := range entry.Utterances {
		if len(u) == 0 {
			continue
		}
		if sim := cosineSimilarityUnit(queryVec, u); sim > best {
			best = sim
		}
	}
	if len(entry.Utterances) == 0 && len(entry.Centroid) > 0 {
		if sim := cosineSimilarityUnit(queryVec, entry.Centroid); sim > best {
			best = sim
		}
	}
	return best
}

func normalizeL2(vec []float32) ([]float32, bool) {
	if len(vec) == 0 {
		return nil, false
	}
	var sumSq float64
	for _, v := range vec {
		fv := float64(v)
		if math.IsNaN(fv) || math.IsInf(fv, 0) {
			return nil, false
		}
		sumSq += fv * fv
	}
	if sumSq <= 0 {
		return nil, false
	}
	invNorm := 1.0 / math.Sqrt(sumSq)
	out := make([]float32, len(vec))
	for i, v := range vec {
		out[i] = float32(float64(v) * invNorm)
	}
	return out, true
}

func computeNormalizedCentroid(vecs [][]float32) []float32 {
	if len(vecs) == 0 {
		return nil
	}
	dim := len(vecs[0])
	if dim == 0 {
		return nil
	}
	acc := make([]float64, dim)
	count := 0
	for _, v := range vecs {
		if len(v) != dim {
			continue
		}
		for i, x := range v {
			acc[i] += float64(x)
		}
		count++
	}
	if count == 0 {
		return nil
	}
	raw := make([]float32, dim)
	for i, sum := range acc {
		raw[i] = float32(sum / float64(count))
	}
	norm, ok := normalizeL2(raw)
	if !ok {
		return nil
	}
	return norm
}

func cosineSimilarityUnit(a, b []float32) float64 {
	if len(a) == 0 || len(a) != len(b) {
		return 0
	}
	var dot float64
	for i := range a {
		dot += float64(a[i]) * float64(b[i])
	}
	if math.IsNaN(dot) || math.IsInf(dot, 0) {
		return 0
	}
	if dot > 1.0 {
		return 1.0
	}
	if dot < -1.0 {
		return -1.0
	}
	return dot
}
