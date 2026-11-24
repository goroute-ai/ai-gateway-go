package cache

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"maps"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

// RequestCacheOptions captures normalized per-request cache control directives parsed from
// HTTP Cache-Control, X-Gateway-Cache-Control, and X-Gateway-Cache-Similarity headers.
type RequestCacheOptions struct {
	Bypass             bool
	Force              bool
	Enabled            bool
	SimilarityOverride float64
}

// ParseCacheControl parses standard Cache-Control, X-Gateway-Cache-Control, and optional
// X-Gateway-Cache-Similarity headers case-insensitively. Disabling directives always win.
func ParseCacheControl(cacheControl, gatewayCacheControl, similarityHeader string) RequestCacheOptions {
	var opts RequestCacheOptions
	combined := strings.TrimSpace(cacheControl)
	if gw := strings.TrimSpace(gatewayCacheControl); gw != "" {
		if combined != "" {
			combined += "," + gw
		} else {
			combined = gw
		}
	}
	if combined != "" {
		for _, rawPart := range strings.Split(combined, ",") {
			part := strings.ToLower(strings.TrimSpace(rawPart))
			switch part {
			case "":
				continue
			case "no-cache", "no-store", "bypass", "max-age=0":
				opts.Bypass = true
				opts.Force = false
				opts.Enabled = false
				return opts
			case "force":
				opts.Force = true
				opts.Enabled = true
			case "enabled":
				opts.Enabled = true
			}
		}
	}
	if simStr := strings.TrimSpace(similarityHeader); simStr != "" {
		if f, err := strconv.ParseFloat(simStr, 64); err == nil && f > 0 && f <= 1.0 {
			opts.SimilarityOverride = f
		}
	}
	return opts
}

// ChatLookupResult captures the outcome of a chat cache lookup, carrying pre-computed keys
// and (for semantic mode) the prompt embedding so a miss can be stored with zero extra embeds.
type ChatLookupResult struct {
	Eligible   bool
	Hit        bool
	CacheType  string // "exact" or "semantic"
	Similarity float64
	Response   *domain.CanonicalChatResponse

	exactKey       string
	requestedModel string
	scopeHash      string
	prompt         string
	embedding      []float32
}

// MetricsSnapshot captures backend-agnostic response cache counters and local occupancy stats.
type MetricsSnapshot struct {
	BackendType  string
	Hits         uint64
	Misses       uint64
	SemanticHits uint64
	Errors       uint64
	Entries      int
	Capacity     int
	Evictions    uint64
}

// ResponseCache provides tenant-isolated response caching backed by one explicit Backend
// ("local", "redis", or "redis-semantic").
type ResponseCache struct {
	enabled     bool
	ttl         time.Duration
	backend     Backend
	semantic    SemanticBackend
	excluded    map[string]bool
	maxMessages int

	revision     atomic.Int64
	hits         atomic.Uint64
	misses       atomic.Uint64
	semanticHits atomic.Uint64
	errors       atomic.Uint64
}

// NewResponseCacheFromConfig constructs a ResponseCache with the configured backend type
// ("local", "redis", or "redis-semantic").
func NewResponseCacheFromConfig(cfg config.CacheConfig, redisFabric *storage.RedisFabric, embedFn EmbedFunc) *ResponseCache {
	ttl := cfg.DefaultTTL
	if ttl <= 0 {
		ttl = time.Hour
	}
	maxEntries := cfg.MaxEntries
	if maxEntries <= 0 && cfg.MaxL1Entries > 0 {
		maxEntries = cfg.MaxL1Entries
	}
	if maxEntries <= 0 {
		maxEntries = defaultLocalMaxEntries
	}
	maxItemBytes := cfg.MaxItemBytes
	if maxItemBytes <= 0 {
		maxItemBytes = defaultLocalMaxItemBytes
	}
	cacheType := strings.ToLower(strings.TrimSpace(cfg.Type))
	if cacheType == "" {
		cacheType = config.CacheTypeLocal
	}

	var backend Backend
	var semBackend SemanticBackend
	switch cacheType {
	case config.CacheTypeRedis:
		if redisFabric != nil && redisFabric.Client() != nil {
			backend = NewRedisBackend(redisFabric, cfg.Namespace, maxItemBytes)
		} else {
			slog.Warn("cache: cache.type=redis configured without active Redis client; falling back to local in-memory cache")
			backend = NewLocalBackend(maxEntries, maxItemBytes)
		}
	case config.CacheTypeRedisSemantic:
		if redisFabric != nil && redisFabric.Client() != nil {
			sb := NewRedisSemanticBackend(redisFabric, cfg.Namespace, maxItemBytes, cfg.Semantic, embedFn)
			backend = sb
			semBackend = sb
		} else {
			slog.Warn("cache: cache.type=redis-semantic configured without active Redis client; falling back to local in-memory cache")
			backend = NewLocalBackend(maxEntries, maxItemBytes)
		}
	default:
		backend = NewLocalBackend(maxEntries, maxItemBytes)
	}

	excluded := make(map[string]bool, len(cfg.ExcludedCallTypes))
	for _, ct := range cfg.ExcludedCallTypes {
		if norm := normalizeCallType(ct); norm != "" {
			excluded[norm] = true
		}
	}

	return &ResponseCache{
		enabled:     cfg.Enabled,
		ttl:         ttl,
		backend:     backend,
		semantic:    semBackend,
		excluded:    excluded,
		maxMessages: cfg.Semantic.MaxMessages,
	}
}

// NewResponseCacheWithBackend creates a ResponseCache around an explicit Backend (useful for tests).
func NewResponseCacheWithBackend(enabled bool, ttl time.Duration, backend Backend, excludedCallTypes []string, maxMessages int) *ResponseCache {
	if ttl <= 0 {
		ttl = time.Hour
	}
	excluded := make(map[string]bool, len(excludedCallTypes))
	for _, ct := range excludedCallTypes {
		if norm := normalizeCallType(ct); norm != "" {
			excluded[norm] = true
		}
	}
	sem, _ := backend.(SemanticBackend)
	return &ResponseCache{
		enabled:     enabled,
		ttl:         ttl,
		backend:     backend,
		semantic:    sem,
		excluded:    excluded,
		maxMessages: maxMessages,
	}
}

// NewLocalResponseCache creates an in-memory ResponseCache with default settings.
func NewLocalResponseCache(enabled bool, ttl time.Duration, maxEntries int) *ResponseCache {
	return NewResponseCacheWithBackend(enabled, ttl, NewLocalBackend(maxEntries, defaultLocalMaxItemBytes), []string{"embedding"}, 4)
}

func normalizeCallType(ct string) string {
	switch strings.ToLower(strings.TrimSpace(ct)) {
	case "chat", "chat_completion", "completion_chat", "messages", "responses":
		return "chat"
	case "completion", "text_completion", "legacy_completion":
		return "completion"
	case "embedding", "embeddings", "aembedding":
		return "embedding"
	default:
		return strings.ToLower(strings.TrimSpace(ct))
	}
}

func (c *ResponseCache) isCallTypeExcluded(callType string) bool {
	if c == nil || len(c.excluded) == 0 {
		return false
	}
	return c.excluded[normalizeCallType(callType)]
}

// Enabled reports whether response caching is enabled.
func (c *ResponseCache) Enabled() bool {
	return c != nil && c.enabled
}

// Type returns the active backend type ("local", "redis", or "redis-semantic").
func (c *ResponseCache) Type() string {
	if c == nil || c.backend == nil {
		return config.CacheTypeLocal
	}
	return c.backend.Type()
}

// IsCacheable reports whether a synchronous ChatCompletion request is eligible for caching.
func (c *ResponseCache) IsCacheable(req *domain.CanonicalChatRequest, opts RequestCacheOptions) bool {
	if c == nil || !c.enabled || req == nil || req.Stream || c.isCallTypeExcluded("chat") {
		return false
	}
	if opts.Bypass {
		return false
	}
	if opts.Enabled || opts.Force {
		return true
	}
	// Semantic cache is explicitly enabled to match paraphrased prompts (unless bypassed or streaming);
	// exact-match cache requires temperature == 0 or a non-nil seed by default for deterministic outputs.
	if c.semantic != nil {
		return req.Temperature == nil || *req.Temperature == 0 || hasNonNilExtraParam(req.ExtraParams, "seed")
	}
	return (req.Temperature != nil && *req.Temperature == 0) || hasNonNilExtraParam(req.ExtraParams, "seed")
}

func hasNonNilExtraParam(extra map[string]any, key string) bool {
	if len(extra) == 0 {
		return false
	}
	v, ok := extra[key]
	return ok && v != nil
}

// LookupChat checks the configured backend (exact or semantic) for a cached chat response.
func (c *ResponseCache) LookupChat(
	ctx context.Context,
	orgID, teamID, allowedModelScope string,
	req *domain.CanonicalChatRequest,
	opts RequestCacheOptions,
) ChatLookupResult {
	if !c.IsCacheable(req, opts) {
		return ChatLookupResult{}
	}

	exactKey := c.ComputeKeyWithScope(orgID, teamID, allowedModelScope, req)
	if exactKey == "" {
		return ChatLookupResult{}
	}
	res := ChatLookupResult{
		Eligible:       true,
		exactKey:       exactKey,
		requestedModel: req.Model,
	}

	// Semantic mode: attempt exact KV fast-path first (zero embedding cost on identical repeat),
	// then fall back to Redis Vector Similarity Search if eligible by max_messages.
	if c.semantic != nil {
		if raw, hit, err := c.backend.Get(ctx, orgID, exactKey); err == nil && hit {
			var resp domain.CanonicalChatResponse
			if json.Unmarshal(raw, &resp) == nil {
				c.hits.Add(1)
				res.Hit = true
				res.CacheType = CacheHitTypeExact
				res.Response = cloneResponse(&resp)
				return res
			}
		} else if err != nil {
			c.errors.Add(1)
			slog.Warn("cache: exact lookup failed (failing open)", "backend", c.Type(), "org_id", orgID, "error", err)
		}

		if prompt, priorTurns, ok := extractSemanticPrompt(req, c.maxMessages); ok {
			scopeHash := computeSemanticScopeHash(orgID, teamID, allowedModelScope, req, priorTurns)
			if scopeHash != "" {
				res.scopeHash = scopeHash
				res.prompt = prompt
				outcome, err := c.semantic.SearchSemantic(ctx, SemanticLookup{
					OrgID:             orgID,
					ScopeHash:         scopeHash,
					Prompt:            prompt,
					ThresholdOverride: opts.SimilarityOverride,
				})
				res.embedding = outcome.Embedding
				if err != nil {
					c.errors.Add(1)
					c.misses.Add(1)
					slog.Warn("cache: semantic lookup failed (failing open)", "backend", c.Type(), "org_id", orgID, "error", err)
					return res
				}
				if outcome.Hit && len(outcome.Payload) > 0 {
					var resp domain.CanonicalChatResponse
					if json.Unmarshal(outcome.Payload, &resp) == nil {
						c.hits.Add(1)
						c.semanticHits.Add(1)
						res.Hit = true
						res.CacheType = CacheHitTypeSemantic
						res.Similarity = outcome.Similarity
						res.Response = cloneResponse(&resp)
						return res
					}
				}
			}
		}
		c.misses.Add(1)
		return res
	}

	// Exact-match mode ("local" or "redis").
	raw, hit, err := c.backend.Get(ctx, orgID, exactKey)
	if err != nil {
		c.errors.Add(1)
		c.misses.Add(1)
		slog.Warn("cache: exact lookup failed (failing open)", "backend", c.Type(), "org_id", orgID, "error", err)
		return res
	}
	if !hit || len(raw) == 0 {
		c.misses.Add(1)
		return res
	}
	var resp domain.CanonicalChatResponse
	if json.Unmarshal(raw, &resp) != nil {
		c.misses.Add(1)
		return res
	}
	c.hits.Add(1)
	res.Hit = true
	res.CacheType = CacheHitTypeExact
	res.Response = cloneResponse(&resp)
	return res
}

// StoreChat persists a chat response in the active backend, reusing any embedding computed
// during LookupChat so semantic cache writes never trigger a duplicate embedding API call.
func (c *ResponseCache) StoreChat(ctx context.Context, lookup ChatLookupResult, orgID string, resp *domain.CanonicalChatResponse) {
	if c == nil || !c.enabled || !lookup.Eligible || lookup.exactKey == "" || resp == nil {
		return
	}
	raw, err := json.Marshal(cloneResponse(resp))
	if err != nil {
		return
	}
	meta := EntryMeta{
		OrgID:          orgID,
		Model:          resp.Model,
		RequestedModel: lookup.requestedModel,
		Modality:       "chat",
	}
	if err := c.backend.Set(ctx, orgID, lookup.exactKey, raw, meta, c.ttl); err != nil {
		c.errors.Add(1)
		slog.Warn("cache: exact store failed", "backend", c.Type(), "org_id", orgID, "error", err)
	}
	if c.semantic != nil && lookup.scopeHash != "" && lookup.prompt != "" {
		if err := c.semantic.StoreSemantic(ctx, SemanticStore{
			OrgID:          orgID,
			Model:          resp.Model,
			RequestedModel: lookup.requestedModel,
			ScopeHash:      lookup.scopeHash,
			Prompt:         lookup.prompt,
			Payload:        raw,
			Embedding:      lookup.embedding,
			TTL:            c.ttl,
		}); err != nil {
			c.errors.Add(1)
			slog.Warn("cache: semantic store failed", "backend", c.Type(), "org_id", orgID, "error", err)
		}
	}
}

// ComputeKey generates a collision-resistant SHA-256 cache key scoped to orgID and req.
func (c *ResponseCache) ComputeKey(orgID string, req *domain.CanonicalChatRequest) string {
	return c.ComputeKeyWithScope(orgID, "", "", req)
}

// ComputeKeyWithScope generates a collision-resistant SHA-256 cache key scoped to orgID,
// and for all virtual router aliases ("auto" and "router/*"), also scoped to teamID and
// allowedModelScope so distinct keys/teams never share aliased cache entries across allowlists.
func (c *ResponseCache) ComputeKeyWithScope(orgID, teamID, allowedModelScope string, req *domain.CanonicalChatRequest) string {
	type keyPayload struct {
		OrgID          string                       `json:"org_id"`
		TeamID         string                       `json:"team_id,omitempty"`
		EffectiveModel string                       `json:"effective_model,omitempty"`
		Request        *domain.CanonicalChatRequest `json:"request"`
	}
	if req == nil {
		return ""
	}
	canonical := *req
	canonical.RequestID = ""
	canonical.Stream = false
	payload := keyPayload{
		OrgID:   orgID,
		Request: &canonical,
	}
	if isVirtualModelAlias(req.Model) {
		payload.TeamID = teamID
		if allowedModelScope != "" {
			payload.EffectiveModel = allowedModelScope
		} else {
			payload.EffectiveModel = req.ResolvedModel
		}
	}
	h := sha256.New()
	if err := json.NewEncoder(h).Encode(payload); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

func isVirtualModelAlias(model string) bool {
	m := strings.ToLower(strings.TrimSpace(model))
	return m == "auto" || strings.HasPrefix(m, "router/")
}

// extractSemanticPrompt extracts the final user prompt and any preceding non-system turns for
// semantic vector caching. Returns ok=false when the conversation exceeds maxMessages (when > 0;
// maxMessages < 0 is unlimited), when any message contains non-text multimodal parts (images,
// documents, audio) or tool/tool_calls content, or when the final non-system turn is not a user message.
func extractSemanticPrompt(req *domain.CanonicalChatRequest, maxMessages int) (string, []domain.CanonicalMessage, bool) {
	if req == nil || len(req.Messages) == 0 {
		return "", nil, false
	}
	var nonSystem []domain.CanonicalMessage
	for _, msg := range req.Messages {
		if messageHasNonTextMultimodalParts(msg) {
			return "", nil, false
		}
		role := strings.ToLower(strings.TrimSpace(msg.Role))
		if role == "tool" || len(msg.ToolCalls) > 0 || strings.TrimSpace(msg.ToolCallID) != "" {
			return "", nil, false
		}
		if role != "system" && role != "developer" {
			nonSystem = append(nonSystem, msg)
		}
	}
	if len(nonSystem) == 0 {
		return "", nil, false
	}
	if maxMessages > 0 && len(nonSystem) > maxMessages {
		return "", nil, false
	}
	last := nonSystem[len(nonSystem)-1]
	if strings.ToLower(strings.TrimSpace(last.Role)) != "user" {
		return "", nil, false
	}
	lastUser := extractMessageText(last)
	if strings.TrimSpace(lastUser) == "" {
		return "", nil, false
	}
	var priorTurns []domain.CanonicalMessage
	if len(nonSystem) > 1 {
		priorTurns = nonSystem[:len(nonSystem)-1]
	}
	return lastUser, priorTurns, true
}

func messageHasNonTextMultimodalParts(msg domain.CanonicalMessage) bool {
	for _, p := range msg.Parts {
		if p.ImageURL != nil || p.Document != nil {
			return true
		}
		pt := strings.ToLower(strings.TrimSpace(p.Type))
		if pt != "" && pt != "text" && pt != "input_text" {
			return true
		}
	}
	return false
}

func extractMessageText(msg domain.CanonicalMessage) string {
	if t := strings.TrimSpace(msg.Content); t != "" {
		return t
	}
	var sb strings.Builder
	for _, p := range msg.Parts {
		if p.Type == "text" && strings.TrimSpace(p.Text) != "" {
			if sb.Len() > 0 {
				sb.WriteByte('\n')
			}
			sb.WriteString(strings.TrimSpace(p.Text))
		}
	}
	return sb.String()
}

// computeSemanticScopeHash binds tenant identity, model, system instructions, prior multi-turn
// conversation context, tools, extra provider params, and generation parameters into a hex TAG
// so vector similarity never leaks across scopes or conversation contexts.
func computeSemanticScopeHash(orgID, teamID, allowedModelScope string, req *domain.CanonicalChatRequest, priorTurns []domain.CanonicalMessage) string {
	type scopePayload struct {
		OrgID             string                    `json:"org_id"`
		TeamID            string                    `json:"team_id,omitempty"`
		AllowedModelScope string                    `json:"allowed_model_scope,omitempty"`
		Model             string                    `json:"model"`
		SystemMessages    []string                  `json:"system_messages,omitempty"`
		PriorTurns        []domain.CanonicalMessage `json:"prior_turns,omitempty"`
		Tools             []domain.CanonicalTool    `json:"tools,omitempty"`
		ToolChoice        any                       `json:"tool_choice,omitempty"`
		ResponseFormat    *domain.ResponseFormat    `json:"response_format,omitempty"`
		ReasoningEffort   string                    `json:"reasoning_effort,omitempty"`
		Temperature       *float64                  `json:"temperature,omitempty"`
		TopP              *float64                  `json:"top_p,omitempty"`
		MaxTokens         *int                      `json:"max_tokens,omitempty"`
		Stop              []string                  `json:"stop,omitempty"`
		User              string                    `json:"user,omitempty"`
		ExtraParams       map[string]any            `json:"extra_params,omitempty"`
	}
	if req == nil {
		return ""
	}
	var sysMsgs []string
	for _, msg := range req.Messages {
		role := strings.ToLower(strings.TrimSpace(msg.Role))
		if role == "system" || role == "developer" {
			sysMsgs = append(sysMsgs, role+":"+extractMessageText(msg))
		}
	}
	sp := scopePayload{
		OrgID:           orgID,
		Model:           req.Model,
		SystemMessages:  sysMsgs,
		PriorTurns:      priorTurns,
		Tools:           req.Tools,
		ToolChoice:      req.ToolChoice,
		ResponseFormat:  req.ResponseFormat,
		ReasoningEffort: req.ReasoningEffort,
		Temperature:     req.Temperature,
		TopP:            req.TopP,
		MaxTokens:       req.MaxTokens,
		Stop:            req.Stop,
		User:            req.User,
		ExtraParams:     req.ExtraParams,
	}
	if isVirtualModelAlias(req.Model) {
		sp.TeamID = teamID
		sp.AllowedModelScope = allowedModelScope
	}
	h := sha256.New()
	if err := json.NewEncoder(h).Encode(sp); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))[:32]
}

// IsCompletionCacheable reports whether a synchronous legacy completion request is cacheable.
func (c *ResponseCache) IsCompletionCacheable(req *domain.CanonicalCompletionRequest, opts RequestCacheOptions) bool {
	if c == nil || !c.enabled || req == nil || req.Stream || c.isCallTypeExcluded("completion") {
		return false
	}
	if opts.Bypass {
		return false
	}
	if opts.Enabled || opts.Force {
		return true
	}
	return req.Temperature != nil && *req.Temperature == 0
}

// ComputeCompletionKeyWithScope generates a SHA-256 key for `/v1/completions`.
func (c *ResponseCache) ComputeCompletionKeyWithScope(orgID, teamID, effectiveModel string, req *domain.CanonicalCompletionRequest) string {
	type completionKeyPayload struct {
		Modality       string                             `json:"modality"`
		OrgID          string                             `json:"org_id"`
		TeamID         string                             `json:"team_id,omitempty"`
		EffectiveModel string                             `json:"effective_model,omitempty"`
		Request        *domain.CanonicalCompletionRequest `json:"request"`
	}
	if req == nil {
		return ""
	}
	canonical := *req
	canonical.RequestID = ""
	canonical.Stream = false
	effModel := effectiveModel
	if effModel == "" {
		effModel = req.ResolvedModel
	}
	h := sha256.New()
	if err := json.NewEncoder(h).Encode(completionKeyPayload{
		Modality:       "completion",
		OrgID:          orgID,
		TeamID:         teamID,
		EffectiveModel: effModel,
		Request:        &canonical,
	}); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

// GetCompletion retrieves a cached `/v1/completions` response.
func (c *ResponseCache) GetCompletion(ctx context.Context, orgID, key string) (*domain.CanonicalCompletionResponse, bool) {
	if c == nil || !c.enabled || key == "" {
		return nil, false
	}
	raw, hit, err := c.backend.Get(ctx, orgID, "cmpl:"+key)
	if err != nil {
		c.errors.Add(1)
		c.misses.Add(1)
		slog.Warn("cache: completion lookup failed (failing open)", "backend", c.Type(), "org_id", orgID, "error", err)
		return nil, false
	}
	if !hit || len(raw) == 0 {
		c.misses.Add(1)
		return nil, false
	}
	var resp domain.CanonicalCompletionResponse
	if json.Unmarshal(raw, &resp) != nil {
		c.misses.Add(1)
		return nil, false
	}
	c.hits.Add(1)
	return cloneCompletionResponse(&resp), true
}

// SetCompletionWithMeta stores a `/v1/completions` response, optionally recording the caller's
// requested ModelGroup alias so scoped invalidation matches both alias and resolved upstream model.
func (c *ResponseCache) SetCompletionWithMeta(ctx context.Context, key, orgID string, resp *domain.CanonicalCompletionResponse, requestedModel ...string) {
	if c == nil || !c.enabled || key == "" || resp == nil {
		return
	}
	raw, err := json.Marshal(cloneCompletionResponse(resp))
	if err != nil {
		return
	}
	reqModel := ""
	if len(requestedModel) > 0 {
		reqModel = requestedModel[0]
	}
	if err := c.backend.Set(ctx, orgID, "cmpl:"+key, raw, EntryMeta{
		OrgID:          orgID,
		Model:          resp.Model,
		RequestedModel: reqModel,
		Modality:       "completion",
	}, c.ttl); err != nil {
		c.errors.Add(1)
		slog.Warn("cache: completion store failed", "backend", c.Type(), "org_id", orgID, "error", err)
	}
}

// IsEmbeddingCacheable reports whether a `/v1/embeddings` request is cacheable.
// Embeddings are excluded by default via cache.excluded_call_types=["embedding"] unless opted in.
func (c *ResponseCache) IsEmbeddingCacheable(req *domain.CanonicalEmbeddingRequest, opts RequestCacheOptions) bool {
	if c == nil || !c.enabled || req == nil || len(req.Input) == 0 || c.isCallTypeExcluded("embedding") {
		return false
	}
	if opts.Bypass {
		return false
	}
	return true
}

// ComputeEmbeddingKeyWithScope generates a SHA-256 key for `/v1/embeddings`.
func (c *ResponseCache) ComputeEmbeddingKeyWithScope(orgID, teamID, effectiveModel string, req *domain.CanonicalEmbeddingRequest) string {
	type embeddingKeyPayload struct {
		Modality       string                            `json:"modality"`
		OrgID          string                            `json:"org_id"`
		TeamID         string                            `json:"team_id,omitempty"`
		EffectiveModel string                            `json:"effective_model,omitempty"`
		Request        *domain.CanonicalEmbeddingRequest `json:"request"`
	}
	if req == nil {
		return ""
	}
	canonical := *req
	canonical.RequestID = ""
	effModel := effectiveModel
	if effModel == "" {
		effModel = req.ResolvedModel
	}
	h := sha256.New()
	if err := json.NewEncoder(h).Encode(embeddingKeyPayload{
		Modality:       "embedding",
		OrgID:          orgID,
		TeamID:         teamID,
		EffectiveModel: effModel,
		Request:        &canonical,
	}); err != nil {
		return ""
	}
	return hex.EncodeToString(h.Sum(nil))
}

// GetEmbedding retrieves a cached `/v1/embeddings` response.
func (c *ResponseCache) GetEmbedding(ctx context.Context, orgID, key string) (*domain.CanonicalEmbeddingResponse, bool) {
	if c == nil || !c.enabled || key == "" {
		return nil, false
	}
	raw, hit, err := c.backend.Get(ctx, orgID, "emb:"+key)
	if err != nil {
		c.errors.Add(1)
		c.misses.Add(1)
		slog.Warn("cache: embedding lookup failed (failing open)", "backend", c.Type(), "org_id", orgID, "error", err)
		return nil, false
	}
	if !hit || len(raw) == 0 {
		c.misses.Add(1)
		return nil, false
	}
	var resp domain.CanonicalEmbeddingResponse
	if json.Unmarshal(raw, &resp) != nil {
		c.misses.Add(1)
		return nil, false
	}
	c.hits.Add(1)
	return cloneEmbeddingResponse(&resp), true
}

// SetEmbeddingWithMeta stores a `/v1/embeddings` response, optionally recording the caller's
// requested ModelGroup alias so scoped invalidation matches both alias and resolved upstream model.
func (c *ResponseCache) SetEmbeddingWithMeta(ctx context.Context, key, orgID string, resp *domain.CanonicalEmbeddingResponse, requestedModel ...string) {
	if c == nil || !c.enabled || key == "" || resp == nil {
		return
	}
	raw, err := json.Marshal(cloneEmbeddingResponse(resp))
	if err != nil {
		return
	}
	reqModel := ""
	if len(requestedModel) > 0 {
		reqModel = requestedModel[0]
	}
	if err := c.backend.Set(ctx, orgID, "emb:"+key, raw, EntryMeta{
		OrgID:          orgID,
		Model:          resp.Model,
		RequestedModel: reqModel,
		Modality:       "embedding",
	}, c.ttl); err != nil {
		c.errors.Add(1)
		slog.Warn("cache: embedding store failed", "backend", c.Type(), "org_id", orgID, "error", err)
	}
}

// Invalidate purges cached entries matching orgID and/or model from the active backend.
func (c *ResponseCache) Invalidate(ctx context.Context, orgID, model string) (int, int64, error) {
	if c == nil || c.backend == nil {
		return 0, 0, nil
	}
	purged, err := c.backend.Invalidate(ctx, orgID, model)
	if err != nil {
		c.errors.Add(1)
		return 0, 0, err
	}
	rev := c.revision.Add(1)
	return purged, rev, nil
}

// Metrics returns backend-agnostic hit, miss, semantic hit, error, and local occupancy stats.
func (c *ResponseCache) Metrics() MetricsSnapshot {
	if c == nil {
		return MetricsSnapshot{}
	}
	var stats BackendStats
	backendType := config.CacheTypeLocal
	if c.backend != nil {
		stats = c.backend.Stats()
		backendType = c.backend.Type()
	}
	return MetricsSnapshot{
		BackendType:  backendType,
		Hits:         c.hits.Load(),
		Misses:       c.misses.Load(),
		SemanticHits: c.semanticHits.Load(),
		Errors:       c.errors.Load(),
		Entries:      stats.Entries,
		Capacity:     stats.Capacity,
		Evictions:    stats.Evictions,
	}
}

func cloneResponse(resp *domain.CanonicalChatResponse) *domain.CanonicalChatResponse {
	if resp == nil {
		return nil
	}
	cp := *resp
	if resp.Metadata != nil {
		cp.Metadata = maps.Clone(resp.Metadata)
	}
	if resp.Choices != nil {
		cp.Choices = make([]domain.CanonicalChoice, len(resp.Choices))
		for i, ch := range resp.Choices {
			cp.Choices[i] = ch
			cp.Choices[i].Message = cloneMessage(ch.Message)
		}
	}
	return &cp
}

func cloneCompletionResponse(resp *domain.CanonicalCompletionResponse) *domain.CanonicalCompletionResponse {
	if resp == nil {
		return nil
	}
	cp := *resp
	if resp.Choices != nil {
		cp.Choices = slices.Clone(resp.Choices)
	}
	return &cp
}

func cloneEmbeddingResponse(resp *domain.CanonicalEmbeddingResponse) *domain.CanonicalEmbeddingResponse {
	if resp == nil {
		return nil
	}
	cp := *resp
	if resp.Data != nil {
		cp.Data = make([]domain.EmbeddingData, len(resp.Data))
		for i, d := range resp.Data {
			cp.Data[i] = d
			if d.Embedding != nil {
				cp.Data[i].Embedding = slices.Clone(d.Embedding)
			}
		}
	}
	return &cp
}

func cloneMessage(msg domain.CanonicalMessage) domain.CanonicalMessage {
	if msg.ToolCalls != nil {
		msg.ToolCalls = slices.Clone(msg.ToolCalls)
	}
	if msg.CacheControl != nil {
		cc := *msg.CacheControl
		msg.CacheControl = &cc
	}
	if msg.Parts != nil {
		parts := make([]domain.ContentPart, len(msg.Parts))
		for i, p := range msg.Parts {
			parts[i] = p
			if p.ImageURL != nil {
				img := *p.ImageURL
				parts[i].ImageURL = &img
			}
			if p.Document != nil {
				doc := *p.Document
				parts[i].Document = &doc
			}
			if p.CacheControl != nil {
				cc := *p.CacheControl
				parts[i].CacheControl = &cc
			}
		}
		msg.Parts = parts
	}
	if msg.Annotations != nil {
		anns := make([]domain.Annotation, len(msg.Annotations))
		for i, a := range msg.Annotations {
			anns[i] = a
			if a.URLCitation != nil {
				cit := *a.URLCitation
				anns[i].URLCitation = &cit
			}
		}
		msg.Annotations = anns
	}
	return msg
}
