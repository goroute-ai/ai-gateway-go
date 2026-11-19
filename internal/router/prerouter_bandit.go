package router

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"math/rand/v2"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/modelcatalog"
	"github.com/goroute-ai/ai-gateway-go/internal/ratelimit"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/redis/go-redis/v9"
)

// TaskBucket categorizes an inference request for per-task bandit arm priors.
type TaskBucket string

const (
	TaskBucketSimpleQA    TaskBucket = "simple_qa"
	TaskBucketCoding      TaskBucket = "coding"
	TaskBucketReasoning   TaskBucket = "reasoning"
	TaskBucketToolUse     TaskBucket = "tool_use"
	TaskBucketLongContext TaskBucket = "long_context"
)

const (
	defaultBanditLongContextTokens = 32000
	defaultBanditAlpha             = 1.0
	defaultBanditBeta              = 1.0
	defaultBanditSyncInterval      = 15 * time.Second
	defaultBanditFlushInterval     = 250 * time.Millisecond
	defaultBanditBatchSize         = 64
	defaultBanditRewardBufferSize  = 2048
	defaultBanditMaxLatencyMs      = int64(10000)
	banditRedisTimeout             = 200 * time.Millisecond
)

var allTaskBuckets = []TaskBucket{
	TaskBucketSimpleQA,
	TaskBucketCoding,
	TaskBucketReasoning,
	TaskBucketToolUse,
	TaskBucketLongContext,
}

var codingMarkers = []string{
	"```", "func ", "def ", "class ", "struct ", "interface ",
	"import ", "select ", "const ", "refactor", "compile",
	"stack trace", "unit test", "implement", "function",
	"golang", "python", "typescript", "javascript", "sql", "regex",
}

var reasoningMarkers = []string{
	"step by step", "analyze", "architect", "prove", "theorem",
	"trade-off", "root cause", "mathematical", "algorithm",
	"deduce", "reasoning", "derive", "hypothesis", "formal proof",
}

// ClassifyTaskBucket maps a chat request to one of the five bandit task buckets.
func ClassifyTaskBucket(req *domain.CanonicalChatRequest, longContextTokens int) TaskBucket {
	if req == nil {
		return TaskBucketSimpleQA
	}
	if longContextTokens <= 0 {
		longContextTokens = defaultBanditLongContextTokens
	}
	if ratelimit.EstimateRequestTokens(req) >= longContextTokens {
		return TaskBucketLongContext
	}
	if len(req.Tools) > 0 {
		return TaskBucketToolUse
	}
	for _, m := range req.Messages {
		if m.Role == "tool" || len(m.ToolCalls) > 0 {
			return TaskBucketToolUse
		}
	}
	if strings.TrimSpace(req.ReasoningEffort) != "" {
		return TaskBucketReasoning
	}

	var sb strings.Builder
	hasUserMsg := false
	for _, m := range req.Messages {
		if m.Role == "user" {
			hasUserMsg = true
			appendMessageText(&sb, m)
		}
	}
	if !hasUserMsg {
		for _, m := range req.Messages {
			appendMessageText(&sb, m)
		}
	}
	text := strings.ToLower(sb.String())
	if text == "" {
		return TaskBucketSimpleQA
	}

	codingHits := countKeywordHits(text, codingMarkers)
	reasoningHits := countKeywordHits(text, reasoningMarkers)

	if codingHits > 0 && codingHits >= reasoningHits {
		return TaskBucketCoding
	}
	if reasoningHits > 0 {
		return TaskBucketReasoning
	}
	return TaskBucketSimpleQA
}

func appendMessageText(sb *strings.Builder, m domain.CanonicalMessage) {
	if m.Content != "" {
		sb.WriteString(m.Content)
		sb.WriteByte(' ')
	}
	for _, p := range m.Parts {
		if p.Text != "" {
			sb.WriteString(p.Text)
			sb.WriteByte(' ')
		}
	}
}

func countKeywordHits(text string, markers []string) int {
	hits := 0
	for _, kw := range markers {
		if strings.Contains(text, kw) {
			hits++
		}
	}
	return hits
}

// BanditPrior holds the Beta(alpha, beta) posterior parameters for a single arm.
type BanditPrior struct {
	Alpha     float64
	Beta      float64
	UpdatedAt time.Time
}

// BanditStats summarizes runtime counters for observability and testing.
type BanditStats struct {
	RecordedOutcomes uint64
	FlushedBatches   uint64
	DroppedOutcomes  uint64
	SyncCount        uint64
	SyncErrors       uint64
	FlushErrors      uint64
	SnapshotArms     int
}

type banditBucketKey struct {
	orgID  string
	bucket TaskBucket
}

type banditArmKey struct {
	orgID  string
	bucket TaskBucket
	alias  string
}

type banditOutcomeEvent struct {
	orgID      string
	bucket     TaskBucket
	alias      string
	deltaAlpha float64
	deltaBeta  float64
}

// BanditOption configures optional BanditPreRouter behavior.
type BanditOption func(*BanditPreRouter)

// WithBanditAliasCosts sets static cost values (e.g. micros per 1M tokens) per candidate alias.
func WithBanditAliasCosts(costs map[string]float64) BanditOption {
	return func(b *BanditPreRouter) {
		for k, v := range costs {
			if k != "" && v >= 0 {
				b.aliasCosts[k] = v
			}
		}
	}
}

// WithBanditLatencyWeight overrides the latency penalty weight subtracted from normalized arm scores.
func WithBanditLatencyWeight(w float64) BanditOption {
	return func(b *BanditPreRouter) {
		if w >= 0 {
			b.latencyWeight = w
		}
	}
}

// WithBanditMaxLatencyMs sets the latency threshold above which a completion counts as excessive latency.
func WithBanditMaxLatencyMs(maxLatencyMs int64) BanditOption {
	return func(b *BanditPreRouter) {
		if maxLatencyMs > 0 {
			b.maxLatencyMs = maxLatencyMs
		}
	}
}

// WithBanditRewardBufferSize sets the buffered channel capacity for async outcome events.
func WithBanditRewardBufferSize(size int) BanditOption {
	return func(b *BanditPreRouter) {
		if size > 0 {
			b.rewardBufferSize = size
		}
	}
}

// WithBanditBatchSize sets the max outcome batch size flushed to Redis at once.
func WithBanditBatchSize(size int) BanditOption {
	return func(b *BanditPreRouter) {
		if size > 0 {
			b.batchSize = size
		}
	}
}

// WithBanditFlushInterval sets the max delay before pending reward increments are flushed to Redis.
func WithBanditFlushInterval(d time.Duration) BanditOption {
	return func(b *BanditPreRouter) {
		if d > 0 {
			b.flushInterval = d
		}
	}
}

// WithBanditRNG sets a deterministic RNG (protected by mutex) for testing.
func WithBanditRNG(rng *rand.Rand) BanditOption {
	return func(b *BanditPreRouter) {
		b.customRNG = rng
	}
}

// WithBanditRepository attaches a repository used to resolve group/deployment costs during sync.
func WithBanditRepository(repo storage.Repository) BanditOption {
	return func(b *BanditPreRouter) {
		b.repo = repo
	}
}

// BanditPreRouter implements a Thompson-Sampling contextual multi-armed bandit pre-router
// using Beta(alpha, beta) priors backed by an in-memory snapshot and async Redis persistence.
type BanditPreRouter struct {
	cfg               config.BanditConfig
	longContextTokens int
	candidates        []string
	defaultAlpha      float64
	defaultBeta       float64
	costWeight        float64
	latencyWeight     float64
	syncInterval      time.Duration
	flushInterval     time.Duration
	batchSize         int
	rewardBufferSize  int
	maxLatencyMs      int64

	redis *storage.RedisFabric
	repo  storage.Repository

	mu             sync.RWMutex
	snapshot       map[banditArmKey]BanditPrior
	aliasCosts     map[string]float64
	aliasLatencies map[string]float64

	seenBuckets sync.Map // map[banditBucketKey]struct{}

	customRNG *rand.Rand
	rngMu     sync.Mutex
	rngPool   sync.Pool

	rewardCh chan banditOutcomeEvent

	stateMu sync.Mutex
	running bool
	stopped atomic.Bool
	cancel  context.CancelFunc
	done    chan struct{}

	syncMu sync.Mutex

	recordedOutcomes atomic.Uint64
	flushedBatches   atomic.Uint64
	droppedOutcomes  atomic.Uint64
	syncCount        atomic.Uint64
	syncErrors       atomic.Uint64
	flushErrors      atomic.Uint64
}

// NewBanditPreRouter constructs a Thompson-Sampling BanditPreRouter.
func NewBanditPreRouter(cfg config.RouterConfig, redisFabric *storage.RedisFabric, opts ...BanditOption) *BanditPreRouter {
	bCfg := cfg.Bandit
	defaultAlpha := bCfg.DefaultAlpha
	if defaultAlpha <= 0 {
		defaultAlpha = defaultBanditAlpha
	}
	defaultBeta := bCfg.DefaultBeta
	if defaultBeta <= 0 {
		defaultBeta = defaultBanditBeta
	}
	syncInterval := bCfg.SyncInterval
	if syncInterval <= 0 {
		syncInterval = defaultBanditSyncInterval
	}
	longCtx := cfg.LongContextTokens
	if longCtx <= 0 {
		longCtx = defaultBanditLongContextTokens
	}
	costWeight := bCfg.CostWeight
	if costWeight < 0 {
		costWeight = 0
	}
	latencyWeight := bCfg.LatencyWeight
	if latencyWeight < 0 {
		latencyWeight = 0
	}

	candidates := dedupeNonEmptyStrings(bCfg.CandidateModels)
	if len(candidates) == 0 {
		candidates = dedupeNonEmptyStrings([]string{
			cfg.DefaultFastAlias,
			cfg.DefaultCodingAlias,
			cfg.DefaultReasoningAlias,
		})
	}

	b := &BanditPreRouter{
		cfg:               bCfg,
		longContextTokens: longCtx,
		candidates:        candidates,
		defaultAlpha:      defaultAlpha,
		defaultBeta:       defaultBeta,
		costWeight:        costWeight,
		latencyWeight:     latencyWeight,
		syncInterval:      syncInterval,
		flushInterval:     defaultBanditFlushInterval,
		batchSize:         defaultBanditBatchSize,
		rewardBufferSize:  defaultBanditRewardBufferSize,
		maxLatencyMs:      defaultBanditMaxLatencyMs,
		redis:             redisFabric,
		snapshot:          make(map[banditArmKey]BanditPrior),
		aliasCosts:        make(map[string]float64),
		aliasLatencies:    make(map[string]float64),
		rngPool: sync.Pool{
			New: func() any {
				return rand.New(rand.NewPCG(rand.Uint64(), rand.Uint64()))
			},
		},
	}

	for _, opt := range opts {
		if opt != nil {
			opt(b)
		}
	}

	// Pre-populate costs from embedded model catalog for any candidate aliases that match catalog IDs.
	for _, alias := range b.candidates {
		if _, ok := b.aliasCosts[alias]; ok {
			continue
		}
		if gm, ok := catalog.Lookup(alias); ok && gm != nil {
			cost := float64(gm.InputCostMicrosPer1M + gm.OutputCostMicrosPer1M)
			if cost > 0 {
				b.aliasCosts[alias] = cost
			}
		}
	}

	b.rewardCh = make(chan banditOutcomeEvent, b.rewardBufferSize)
	return b
}

// Name returns the pre-router identifier ("adaptive").
func (b *BanditPreRouter) Name() string {
	return "adaptive"
}

// SetAliasCost updates the known cost metric for a candidate alias in memory.
func (b *BanditPreRouter) SetAliasCost(alias string, cost float64) {
	if alias == "" || cost < 0 {
		return
	}
	b.mu.Lock()
	b.aliasCosts[alias] = cost
	b.mu.Unlock()
}

// Route selects a candidate model alias using Thompson Sampling over the in-memory Beta prior snapshot.
// Zero Redis calls are executed on the hot path.
func (b *BanditPreRouter) Route(ctx context.Context, orgID string, req *domain.CanonicalChatRequest) (targetAlias string, reason string, score float64, err error) {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return "", "", 0, err
		}
	}
	if len(b.candidates) == 0 {
		return "", "bandit:no_candidates", 0, errors.New("bandit pre-router: no candidate models configured")
	}

	normOrg := normalizeBanditOrgID(orgID)
	bucket := ClassifyTaskBucket(req, b.longContextTokens)
	b.trackBucket(normOrg, bucket)

	if len(b.candidates) == 1 {
		return b.candidates[0], fmt.Sprintf("bandit:%s:single_candidate", bucket), 1.0, nil
	}

	priors, normCosts, normLatencies := b.readArmInputs(normOrg, bucket, time.Now())

	bestIdx := 0
	bestScore := math.Inf(-1)
	explored := false
	b.withRNG(func(rng *rand.Rand) bool {
		if b.cfg.ExplorationRate > 0 && rng.Float64() < b.cfg.ExplorationRate {
			bestIdx = rng.IntN(len(b.candidates))
			bestScore = 0
			explored = true
			return true
		}
		for i := range b.candidates {
			sampledProb := sampleBeta(priors[i].Alpha, priors[i].Beta, rng)
			armScore := sampledProb - b.costWeight*normCosts[i] - b.latencyWeight*normLatencies[i]
			if armScore > bestScore {
				bestScore = armScore
				bestIdx = i
			}
		}
		return true
	})

	if explored {
		return b.candidates[bestIdx], fmt.Sprintf("bandit:%s:explore", bucket), bestScore, nil
	}
	return b.candidates[bestIdx], fmt.Sprintf("bandit:%s:thompson", bucket), bestScore, nil
}

func (b *BanditPreRouter) readArmInputs(orgID string, bucket TaskBucket, now time.Time) ([]BanditPrior, []float64, []float64) {
	priors := make([]BanditPrior, len(b.candidates))
	costs := make([]float64, len(b.candidates))
	hasCost := make([]bool, len(b.candidates))
	latencies := make([]float64, len(b.candidates))
	hasLat := make([]bool, len(b.candidates))
	minCost := math.Inf(1)
	maxCost := -1.0
	minLat := math.Inf(1)
	maxLat := -1.0

	b.mu.RLock()
	for i, alias := range b.candidates {
		key := banditArmKey{orgID: orgID, bucket: bucket, alias: alias}
		if p, ok := b.snapshot[key]; ok {
			priors[i] = b.applyDecay(p, now)
		} else {
			priors[i] = BanditPrior{Alpha: b.defaultAlpha, Beta: b.defaultBeta}
		}
		if c, ok := b.aliasCosts[alias]; ok {
			costs[i] = c
			hasCost[i] = true
			if c < minCost {
				minCost = c
			}
			if c > maxCost {
				maxCost = c
			}
		}
		if l, ok := b.aliasLatencies[alias]; ok && l > 0 {
			latencies[i] = l
			hasLat[i] = true
			if l < minLat {
				minLat = l
			}
			if l > maxLat {
				maxLat = l
			}
		}
	}
	b.mu.RUnlock()

	normCosts := make([]float64, len(b.candidates))
	if maxCost > minCost {
		span := maxCost - minCost
		for i := range costs {
			if hasCost[i] {
				normCosts[i] = (costs[i] - minCost) / span
			} else {
				normCosts[i] = 0.5
			}
		}
	}

	normLatencies := make([]float64, len(b.candidates))
	if maxLat > minLat {
		span := maxLat - minLat
		for i := range latencies {
			if hasLat[i] {
				normLatencies[i] = (latencies[i] - minLat) / span
			} else {
				normLatencies[i] = 0.5
			}
		}
	}
	return priors, normCosts, normLatencies
}

func (b *BanditPreRouter) applyDecay(p BanditPrior, now time.Time) BanditPrior {
	if b.cfg.DecayHalfLife <= 0 || p.UpdatedAt.IsZero() {
		return p
	}
	elapsed := now.Sub(p.UpdatedAt)
	if elapsed <= 0 {
		return p
	}
	decay := math.Exp(-math.Ln2 * elapsed.Seconds() / b.cfg.DecayHalfLife.Seconds())
	p.Alpha = b.defaultAlpha + math.Max(0, p.Alpha-b.defaultAlpha)*decay
	p.Beta = b.defaultBeta + math.Max(0, p.Beta-b.defaultBeta)*decay
	return p
}

func (b *BanditPreRouter) withRNG(fn func(*rand.Rand) bool) bool {
	if b.customRNG != nil {
		b.rngMu.Lock()
		defer b.rngMu.Unlock()
		return fn(b.customRNG)
	}
	rng := b.rngPool.Get().(*rand.Rand)
	defer b.rngPool.Put(rng)
	return fn(rng)
}

func (b *BanditPreRouter) trackBucket(orgID string, bucket TaskBucket) {
	b.seenBuckets.LoadOrStore(banditBucketKey{orgID: orgID, bucket: bucket}, struct{}{})
}

// WarmupOrg registers all task buckets for an org and performs an immediate snapshot sync from Redis.
func (b *BanditPreRouter) WarmupOrg(ctx context.Context, orgID string) error {
	normOrg := normalizeBanditOrgID(orgID)
	for _, bucket := range allTaskBuckets {
		b.trackBucket(normOrg, bucket)
	}
	return b.Sync(ctx)
}

// GetPrior returns the current in-memory Beta(alpha, beta) prior for an arm.
func (b *BanditPreRouter) GetPrior(orgID string, bucket TaskBucket, alias string) (alpha, beta float64) {
	normOrg := normalizeBanditOrgID(orgID)
	if bucket == "" {
		bucket = TaskBucketSimpleQA
	}
	b.mu.RLock()
	p, ok := b.snapshot[banditArmKey{orgID: normOrg, bucket: bucket, alias: alias}]
	b.mu.RUnlock()
	if !ok {
		return b.defaultAlpha, b.defaultBeta
	}
	return p.Alpha, p.Beta
}

// Stats returns a point-in-time snapshot of worker and cache counters.
func (b *BanditPreRouter) Stats() BanditStats {
	b.mu.RLock()
	arms := len(b.snapshot)
	b.mu.RUnlock()
	return BanditStats{
		RecordedOutcomes: b.recordedOutcomes.Load(),
		FlushedBatches:   b.flushedBatches.Load(),
		DroppedOutcomes:  b.droppedOutcomes.Load(),
		SyncCount:        b.syncCount.Load(),
		SyncErrors:       b.syncErrors.Load(),
		FlushErrors:      b.flushErrors.Load(),
		SnapshotArms:     arms,
	}
}

// Start launches the async reward persistence and periodic snapshot sync worker.
func (b *BanditPreRouter) Start(ctx context.Context) {
	if ctx == nil {
		ctx = context.Background()
	}
	b.stateMu.Lock()
	if b.running {
		b.stateMu.Unlock()
		return
	}
	b.stopped.Store(false)
	workerCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	b.cancel = cancel
	b.done = done
	b.running = true
	b.stateMu.Unlock()

	go b.runWorker(workerCtx, done)
}

// Stop signals the async reward worker to drain all queued outcomes, flush to Redis, and exit.
func (b *BanditPreRouter) Stop() {
	b.stopped.Store(true)
	b.stateMu.Lock()
	running := b.running
	cancel := b.cancel
	done := b.done
	b.stateMu.Unlock()

	if running {
		if cancel != nil {
			cancel()
		}
		if done != nil {
			<-done
		}
		return
	}

	// Worker was never started; synchronously drain any queued events.
	b.drainAndFlush(context.Background())
}

// RecordOutcome asynchronously records a request outcome for the specified (orgID, bucket, alias).
// +1 is added to alpha on fast non-error completion; +1 is added to beta on upstream error,
// refusal, or excessive latency (latencyMs > maxLatencyMs).
func (b *BanditPreRouter) RecordOutcome(orgID string, bucket TaskBucket, alias string, success bool, latencyMs int64, excessiveLatency bool) {
	if alias == "" || b.stopped.Load() {
		return
	}
	normOrg := normalizeBanditOrgID(orgID)
	if bucket == "" {
		bucket = TaskBucketSimpleQA
	}
	b.trackBucket(normOrg, bucket)

	if latencyMs > 0 {
		lat := float64(latencyMs)
		b.mu.Lock()
		if cur, ok := b.aliasLatencies[alias]; !ok || cur <= 0 {
			b.aliasLatencies[alias] = lat
		} else {
			b.aliasLatencies[alias] = 0.3*lat + 0.7*cur
		}
		b.mu.Unlock()
	}

	ev := banditOutcomeEvent{
		orgID:  normOrg,
		bucket: bucket,
		alias:  alias,
	}
	if !success || excessiveLatency || (b.maxLatencyMs > 0 && latencyMs > b.maxLatencyMs) {
		ev.deltaBeta = 1.0
	} else {
		ev.deltaAlpha = 1.0
	}

	b.recordedOutcomes.Add(1)
	select {
	case b.rewardCh <- ev:
	default:
		b.droppedOutcomes.Add(1)
	}
}

func (b *BanditPreRouter) runWorker(ctx context.Context, done chan struct{}) {
	defer func() {
		b.stateMu.Lock()
		b.running = false
		b.stateMu.Unlock()
		close(done)
	}()

	flushTicker := time.NewTicker(b.flushInterval)
	defer flushTicker.Stop()
	syncTicker := time.NewTicker(b.syncInterval)
	defer syncTicker.Stop()

	pending := make(map[banditArmKey]BanditPrior)
	pendingCount := 0

	flushPending := func(flushCtx context.Context) {
		if len(pending) == 0 {
			return
		}
		b.applyAndPersistDeltas(flushCtx, pending)
		clear(pending)
		pendingCount = 0
	}

	for {
		select {
		case <-ctx.Done():
			for {
				select {
				case ev := <-b.rewardCh:
					accumulateDelta(pending, ev)
					pendingCount++
				default:
					flushCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
					flushPending(flushCtx)
					cancel()
					return
				}
			}
		case ev := <-b.rewardCh:
			accumulateDelta(pending, ev)
			pendingCount++
			if pendingCount >= b.batchSize {
				flushPending(ctx)
			}
		case <-flushTicker.C:
			flushPending(ctx)
		case <-syncTicker.C:
			flushPending(ctx)
			_ = b.Sync(ctx)
		}
	}
}

func (b *BanditPreRouter) drainAndFlush(ctx context.Context) {
	pending := make(map[banditArmKey]BanditPrior)
	for {
		select {
		case ev := <-b.rewardCh:
			accumulateDelta(pending, ev)
		default:
			if len(pending) > 0 {
				b.applyAndPersistDeltas(ctx, pending)
			}
			return
		}
	}
}

func accumulateDelta(pending map[banditArmKey]BanditPrior, ev banditOutcomeEvent) {
	key := banditArmKey{orgID: ev.orgID, bucket: ev.bucket, alias: ev.alias}
	cur := pending[key]
	cur.Alpha += ev.deltaAlpha
	cur.Beta += ev.deltaBeta
	pending[key] = cur
}

func (b *BanditPreRouter) applyAndPersistDeltas(ctx context.Context, deltas map[banditArmKey]BanditPrior) {
	if len(deltas) == 0 {
		return
	}
	now := time.Now()

	// Always update the local snapshot immediately so local routing adapts even if Redis is unavailable.
	b.mu.Lock()
	for key, d := range deltas {
		cur, ok := b.snapshot[key]
		if !ok {
			cur = BanditPrior{Alpha: b.defaultAlpha, Beta: b.defaultBeta}
		}
		cur.Alpha += d.Alpha
		cur.Beta += d.Beta
		cur.UpdatedAt = now
		b.snapshot[key] = cur
	}
	b.mu.Unlock()

	if b.redis == nil || b.redis.Client() == nil {
		return
	}

	b.syncMu.Lock()
	defer b.syncMu.Unlock()

	opCtx, cancel := context.WithTimeout(context.Background(), banditRedisTimeout)
	defer cancel()

	_, err := b.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
		pipe := rdb.Pipeline()
		for arm, d := range deltas {
			rKey := banditRedisKey(arm.orgID, arm.bucket)
			if d.Alpha != 0 {
				pipe.HIncrByFloat(opCtx, rKey, arm.alias+":alpha", d.Alpha)
			}
			if d.Beta != 0 {
				pipe.HIncrByFloat(opCtx, rKey, arm.alias+":beta", d.Beta)
			}
		}
		_, err := pipe.Exec(opCtx)
		return nil, err
	})
	if err != nil {
		b.flushErrors.Add(1)
		slog.Debug("bandit reward flush to Redis failed; continuing with local priors", "error", err)
		return
	}
	b.flushedBatches.Add(1)
}

// Sync refreshes the in-memory Beta prior snapshot from Redis (and optional repository costs)
// for all observed (orgID, TaskBucket) pairs. Degrades gracefully when Redis is unavailable.
func (b *BanditPreRouter) Sync(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}

	b.refreshRepoCosts(ctx)

	if b.redis == nil || b.redis.Client() == nil {
		return nil
	}

	var buckets []banditBucketKey
	b.seenBuckets.Range(func(k, _ any) bool {
		if bk, ok := k.(banditBucketKey); ok {
			buckets = append(buckets, bk)
		}
		return true
	})
	if len(buckets) == 0 {
		return nil
	}

	b.syncMu.Lock()
	defer b.syncMu.Unlock()

	opCtx, cancel := context.WithTimeout(ctx, banditRedisTimeout)
	defer cancel()

	res, err := b.redis.Execute(func(rdb redis.UniversalClient) (any, error) {
		pipe := rdb.Pipeline()
		cmds := make(map[banditBucketKey]*redis.MapStringStringCmd, len(buckets))
		for _, bk := range buckets {
			cmds[bk] = pipe.HGetAll(opCtx, banditRedisKey(bk.orgID, bk.bucket))
		}
		_, err := pipe.Exec(opCtx)
		if err != nil && !errors.Is(err, redis.Nil) {
			return nil, err
		}
		parsed := make(map[banditArmKey]BanditPrior)
		now := time.Now()
		for bk, cmd := range cmds {
			fields, err := cmd.Result()
			if err != nil && !errors.Is(err, redis.Nil) {
				return nil, err
			}
			for field, raw := range fields {
				val, parseErr := strconv.ParseFloat(raw, 64)
				if parseErr != nil || math.IsNaN(val) || math.IsInf(val, 0) {
					continue
				}
				switch {
				case strings.HasSuffix(field, ":alpha"):
					alias := strings.TrimSuffix(field, ":alpha")
					ak := banditArmKey{orgID: bk.orgID, bucket: bk.bucket, alias: alias}
					p := ensurePrior(parsed, ak, b.defaultAlpha, b.defaultBeta, now)
					p.Alpha = math.Max(1e-6, b.defaultAlpha+val)
					parsed[ak] = p
				case strings.HasSuffix(field, ":beta"):
					alias := strings.TrimSuffix(field, ":beta")
					ak := banditArmKey{orgID: bk.orgID, bucket: bk.bucket, alias: alias}
					p := ensurePrior(parsed, ak, b.defaultAlpha, b.defaultBeta, now)
					p.Beta = math.Max(1e-6, b.defaultBeta+val)
					parsed[ak] = p
				}
			}
		}
		return parsed, nil
	})
	if err != nil {
		b.syncErrors.Add(1)
		slog.Debug("bandit snapshot sync from Redis failed; retaining local snapshot", "error", err)
		return err
	}

	parsed, ok := res.(map[banditArmKey]BanditPrior)
	if !ok {
		return nil
	}

	b.mu.Lock()
	for ak, p := range parsed {
		b.snapshot[ak] = p
	}
	b.mu.Unlock()
	b.syncCount.Add(1)
	return nil
}

func (b *BanditPreRouter) refreshRepoCosts(ctx context.Context) {
	if b.repo == nil || len(b.candidates) == 0 {
		return
	}
	var orgs []string
	seenOrg := make(map[string]struct{})
	b.seenBuckets.Range(func(k, _ any) bool {
		if bk, ok := k.(banditBucketKey); ok {
			if _, exists := seenOrg[bk.orgID]; !exists {
				seenOrg[bk.orgID] = struct{}{}
				orgs = append(orgs, bk.orgID)
			}
		}
		return true
	})
	for _, orgID := range orgs {
		groups, err := b.repo.ListModelGroups(ctx, orgID)
		if err != nil {
			continue
		}
		for _, g := range groups {
			if g == nil || !g.IsActive || !slices.Contains(b.candidates, g.Alias) {
				continue
			}
			deps, err := b.repo.ListDeploymentsByGroup(ctx, g.ID)
			if err != nil {
				continue
			}
			var minCost float64
			for _, d := range deps {
				if d == nil || d.Status != domain.DeploymentStatusActive || d.GlobalModel == nil {
					continue
				}
				c := float64(d.GlobalModel.InputCostMicrosPer1M + d.GlobalModel.OutputCostMicrosPer1M)
				if c > 0 && (minCost == 0 || c < minCost) {
					minCost = c
				}
			}
			if minCost > 0 {
				b.mu.Lock()
				if _, exists := b.aliasCosts[g.Alias]; !exists {
					b.aliasCosts[g.Alias] = minCost
				}
				b.mu.Unlock()
			}
		}
	}
}

func ensurePrior(m map[banditArmKey]BanditPrior, key banditArmKey, defAlpha, defBeta float64, now time.Time) BanditPrior {
	if p, ok := m[key]; ok {
		return p
	}
	return BanditPrior{Alpha: defAlpha, Beta: defBeta, UpdatedAt: now}
}

// sampleGamma draws a sample from Gamma(alpha, 1) using the Marsaglia-Tsang (2000) method.
func sampleGamma(alpha float64, rng *rand.Rand) float64 {
	if alpha <= 0 {
		alpha = 1e-9
	}
	if alpha < 1.0 {
		// Boost alpha by 1 and scale by U^(1/alpha) where U in (0, 1].
		u := 1.0 - rng.Float64()
		return sampleGamma(alpha+1.0, rng) * math.Pow(u, 1.0/alpha)
	}

	d := alpha - 1.0/3.0
	c := 1.0 / math.Sqrt(9.0*d)
	for {
		var x, v float64
		for {
			x = rng.NormFloat64()
			v = 1.0 + c*x
			if v > 0 {
				break
			}
		}
		v = v * v * v
		u := 1.0 - rng.Float64()
		x2 := x * x
		if u < 1.0-0.0331*x2*x2 {
			return d * v
		}
		if math.Log(u) < 0.5*x2+d*(1.0-v+math.Log(v)) {
			return d * v
		}
	}
}

// sampleBeta draws a sample from Beta(alpha, beta) via X / (X + Y) where X ~ Gamma(alpha, 1), Y ~ Gamma(beta, 1).
func sampleBeta(alpha, beta float64, rng *rand.Rand) float64 {
	if alpha <= 0 {
		alpha = 1.0
	}
	if beta <= 0 {
		beta = 1.0
	}
	x := sampleGamma(alpha, rng)
	y := sampleGamma(beta, rng)
	sum := x + y
	if sum <= 0 || math.IsNaN(sum) {
		return alpha / (alpha + beta)
	}
	return x / sum
}

func normalizeBanditOrgID(orgID string) string {
	orgID = strings.TrimSpace(orgID)
	if orgID == "" {
		return "default"
	}
	return orgID
}

func banditRedisKey(orgID string, bucket TaskBucket) string {
	return fmt.Sprintf("gw:router:bandit:{org:%s}:%s", normalizeBanditOrgID(orgID), bucket)
}

func dedupeNonEmptyStrings(items []string) []string {
	if len(items) == 0 {
		return nil
	}
	out := make([]string, 0, len(items))
	seen := make(map[string]struct{}, len(items))
	for _, item := range items {
		trimmed := strings.TrimSpace(item)
		if trimmed == "" {
			continue
		}
		if _, ok := seen[trimmed]; ok {
			continue
		}
		seen[trimmed] = struct{}{}
		out = append(out, trimmed)
	}
	return out
}
