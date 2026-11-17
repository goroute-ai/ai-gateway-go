package router

import (
	"context"
	"math"
	"math/rand/v2"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/redis/go-redis/v9"
)

type countingRedisHook struct {
	cmds atomic.Int64
}

func (h *countingRedisHook) DialHook(next redis.DialHook) redis.DialHook {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		return next(ctx, network, addr)
	}
}

func (h *countingRedisHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		h.cmds.Add(1)
		return next(ctx, cmd)
	}
}

func (h *countingRedisHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return func(ctx context.Context, cmds []redis.Cmder) error {
		h.cmds.Add(int64(len(cmds)))
		return next(ctx, cmds)
	}
}

func TestBanditClassifyTaskBucket(t *testing.T) {
	tests := []struct {
		name              string
		req               *domain.CanonicalChatRequest
		longContextTokens int
		want              TaskBucket
	}{
		{
			name: "nil_request_defaults_simple_qa",
			req:  nil,
			want: TaskBucketSimpleQA,
		},
		{
			name: "simple_qa",
			req: &domain.CanonicalChatRequest{
				Messages: []domain.CanonicalMessage{
					{Role: "user", Content: "What is the capital of Japan?"},
				},
			},
			want: TaskBucketSimpleQA,
		},
		{
			name: "coding_go_snippet",
			req: &domain.CanonicalChatRequest{
				Messages: []domain.CanonicalMessage{
					{Role: "user", Content: "Write a Go function to merge two sorted slices:\n```go\nfunc merge(a, b []int) []int\n```"},
				},
			},
			want: TaskBucketCoding,
		},
		{
			name: "coding_python_refactor",
			req: &domain.CanonicalChatRequest{
				Messages: []domain.CanonicalMessage{
					{Role: "user", Content: "Refactor this Python class Parser and def parse_tokens to fix compile errors."},
				},
			},
			want: TaskBucketCoding,
		},
		{
			name: "reasoning_keywords",
			req: &domain.CanonicalChatRequest{
				Messages: []domain.CanonicalMessage{
					{Role: "user", Content: "Analyze step by step and prove the mathematical theorem for distributed consensus."},
				},
			},
			want: TaskBucketReasoning,
		},
		{
			name: "reasoning_effort_explicit",
			req: &domain.CanonicalChatRequest{
				ReasoningEffort: "high",
				Messages: []domain.CanonicalMessage{
					{Role: "user", Content: "Explain this briefly."},
				},
			},
			want: TaskBucketReasoning,
		},
		{
			name: "tool_use_declared_tools",
			req: &domain.CanonicalChatRequest{
				Tools: []domain.CanonicalTool{
					{Type: "function", Function: domain.CanonicalFunction{Name: "get_weather"}},
				},
				Messages: []domain.CanonicalMessage{
					{Role: "user", Content: "What is the weather in Tokyo?"},
				},
			},
			want: TaskBucketToolUse,
		},
		{
			name: "tool_use_tool_message",
			req: &domain.CanonicalChatRequest{
				Messages: []domain.CanonicalMessage{
					{Role: "user", Content: "Run lookup"},
					{Role: "tool", Content: `{"temp":22}`, ToolCallID: "call_1"},
				},
			},
			want: TaskBucketToolUse,
		},
		{
			name: "long_context_threshold",
			req: &domain.CanonicalChatRequest{
				Messages: []domain.CanonicalMessage{
					{Role: "user", Content: strings.Repeat("word ", 600)},
				},
			},
			longContextTokens: 400,
			want:              TaskBucketLongContext,
		},
		{
			name: "multimodal_parts_text_coding",
			req: &domain.CanonicalChatRequest{
				Messages: []domain.CanonicalMessage{
					{
						Role: "user",
						Parts: []domain.ContentPart{
							{Type: "text", Text: "Implement a SQL query with SELECT id FROM users."},
						},
					},
				},
			},
			want: TaskBucketCoding,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ClassifyTaskBucket(tc.req, tc.longContextTokens)
			if got != tc.want {
				t.Fatalf("ClassifyTaskBucket() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestBanditSamplers_GammaAndBetaMoments(t *testing.T) {
	rng := rand.New(rand.NewPCG(1337, 4242))

	// Gamma(alpha, 1): E[X] = alpha, Var[X] = alpha
	for _, alpha := range []float64{0.4, 1.0, 3.5, 12.0} {
		const n = 25000
		sum := 0.0
		sumSq := 0.0
		for range n {
			x := sampleGamma(alpha, rng)
			if x <= 0 || math.IsNaN(x) || math.IsInf(x, 0) {
				t.Fatalf("invalid Gamma(%v) sample: %v", alpha, x)
			}
			sum += x
			sumSq += x * x
		}
		mean := sum / n
		variance := sumSq/n - mean*mean
		if math.Abs(mean-alpha) > 0.12*alpha+0.05 {
			t.Fatalf("Gamma(%v) mean = %.4f, want ~%.4f", alpha, mean, alpha)
		}
		if math.Abs(variance-alpha) > 0.20*alpha+0.08 {
			t.Fatalf("Gamma(%v) variance = %.4f, want ~%.4f", alpha, variance, alpha)
		}
	}

	// Beta(alpha, beta): E[X] = a/(a+b), Var[X] = ab / ((a+b)^2 (a+b+1))
	betaCases := [][2]float64{{0.5, 0.5}, {1, 1}, {8, 2}, {2, 10}}
	for _, ab := range betaCases {
		a, b := ab[0], ab[1]
		const n = 25000
		sum := 0.0
		sumSq := 0.0
		for range n {
			x := sampleBeta(a, b, rng)
			if x < 0 || x > 1 || math.IsNaN(x) {
				t.Fatalf("invalid Beta(%v,%v) sample: %v", a, b, x)
			}
			sum += x
			sumSq += x * x
		}
		mean := sum / n
		variance := sumSq/n - mean*mean
		wantMean := a / (a + b)
		wantVar := (a * b) / ((a + b) * (a + b) * (a + b + 1))
		if math.Abs(mean-wantMean) > 0.015 {
			t.Fatalf("Beta(%v,%v) mean = %.4f, want %.4f", a, b, mean, wantMean)
		}
		if math.Abs(variance-wantVar) > 0.01 {
			t.Fatalf("Beta(%v,%v) variance = %.4f, want %.4f", a, b, variance, wantVar)
		}
	}
}

func TestBanditPreRouter_NameAndConvergence(t *testing.T) {
	cfg := config.Default().Router
	cfg.Bandit = config.BanditConfig{
		Enabled:         true,
		DefaultAlpha:    1.0,
		DefaultBeta:     1.0,
		CostWeight:      0.35,
		CandidateModels: []string{"cheap-fast", "expensive-pro"},
	}

	b := NewBanditPreRouter(
		cfg,
		nil,
		WithBanditAliasCosts(map[string]float64{
			"cheap-fast":    10.0,
			"expensive-pro": 100.0,
		}),
		WithBanditMaxLatencyMs(500),
		WithBanditRNG(rand.New(rand.NewPCG(7, 11))),
	)
	if b.Name() != "adaptive" {
		t.Fatalf("Name() = %q, want adaptive", b.Name())
	}

	ctx := context.Background()
	b.Start(ctx)
	defer b.Stop()

	// Scenario 1: Equal high reliability in simple_qa -> lower-cost arm ("cheap-fast") dominates.
	for range 40 {
		b.RecordOutcome("org-conv", TaskBucketSimpleQA, "cheap-fast", true, 80, false)
		b.RecordOutcome("org-conv", TaskBucketSimpleQA, "expensive-pro", true, 90, false)
	}
	// Scenario 2: In coding bucket, cheap-fast is unreliable/slow, expensive-pro succeeds -> expensive-pro dominates.
	for range 40 {
		b.RecordOutcome("org-conv", TaskBucketCoding, "cheap-fast", false, 120, false)
		b.RecordOutcome("org-conv", TaskBucketCoding, "expensive-pro", true, 150, false)
	}
	// Flush buffered outcomes cleanly by stopping and restarting or waiting briefly.
	b.Stop()

	qaReq := &domain.CanonicalChatRequest{
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "What is 2+2?"}},
	}
	cheapWins := 0
	for range 200 {
		alias, reason, _, err := b.Route(ctx, "org-conv", qaReq)
		if err != nil {
			t.Fatalf("Route qa failed: %v", err)
		}
		if !strings.Contains(reason, string(TaskBucketSimpleQA)) {
			t.Fatalf("unexpected reason %q", reason)
		}
		if alias == "cheap-fast" {
			cheapWins++
		}
	}
	if cheapWins < 180 {
		t.Fatalf("expected lower-cost arm cheap-fast to win simple_qa, got %d/200", cheapWins)
	}

	codeReq := &domain.CanonicalChatRequest{
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "Write a Go func:\n```go\nfunc foo() {}\n```"}},
	}
	proWins := 0
	for range 200 {
		alias, reason, _, err := b.Route(ctx, "org-conv", codeReq)
		if err != nil {
			t.Fatalf("Route coding failed: %v", err)
		}
		if !strings.Contains(reason, string(TaskBucketCoding)) {
			t.Fatalf("unexpected reason %q", reason)
		}
		if alias == "expensive-pro" {
			proWins++
		}
	}
	if proWins < 185 {
		t.Fatalf("expected higher-reward arm expensive-pro to win coding, got %d/200", proWins)
	}

	// Different org must retain neutral priors and not inherit org-conv's failure bias.
	a, bt := b.GetPrior("org-other", TaskBucketCoding, "cheap-fast")
	if a != 1.0 || bt != 1.0 {
		t.Fatalf("expected isolated default prior (1,1) for org-other, got (%v,%v)", a, bt)
	}
}

func TestBanditPreRouter_ZeroRedisHopHotPathAndAsyncPersistence(t *testing.T) {
	mr := miniredis.RunT(t)
	redisA := storage.NewRedisFabric(mr.Addr(), "", 0)
	redisB := storage.NewRedisFabric(mr.Addr(), "", 0)
	defer redisA.Client().Close()
	defer redisB.Client().Close()

	hookB := &countingRedisHook{}
	redisB.Client().AddHook(hookB)

	cfg := config.Default().Router
	cfg.Bandit = config.BanditConfig{
		Enabled:         true,
		DefaultAlpha:    1.0,
		DefaultBeta:     1.0,
		CostWeight:      0.1,
		SyncInterval:    50 * time.Millisecond,
		CandidateModels: []string{"arm-a", "arm-b"},
	}

	writer := NewBanditPreRouter(
		cfg,
		redisA,
		WithBanditMaxLatencyMs(200),
		WithBanditBatchSize(8),
		WithBanditFlushInterval(20*time.Millisecond),
	)

	ctx := context.Background()
	writer.Start(ctx)

	// Record outcomes on writer: arm-a succeeds quickly, arm-b suffers errors + excessive latency (both flag and threshold).
	for range 30 {
		writer.RecordOutcome("org-redis", TaskBucketReasoning, "arm-a", true, 50, false)
	}
	for range 15 {
		writer.RecordOutcome("org-redis", TaskBucketReasoning, "arm-b", false, 50, false)
	}
	for range 10 {
		writer.RecordOutcome("org-redis", TaskBucketReasoning, "arm-b", true, 500, false) // > maxLatencyMs=200
	}
	for range 5 {
		writer.RecordOutcome("org-redis", TaskBucketReasoning, "arm-b", true, 50, true) // excessiveLatency=true
	}
	writer.Stop()

	// Verify Cluster hash-tag safe Redis key and HINCRBYFLOAT values.
	expectedKey := "gw:router:bandit:{org:org-redis}:reasoning"
	if !mr.Exists(expectedKey) {
		t.Fatalf("expected Redis hash key %q to exist", expectedKey)
	}
	if got := mr.HGet(expectedKey, "arm-a:alpha"); got != "30" {
		t.Fatalf("arm-a:alpha = %q, want 30", got)
	}
	if got := mr.HGet(expectedKey, "arm-b:beta"); got != "30" {
		t.Fatalf("arm-b:beta = %q, want 30", got)
	}

	// Reader instance syncs once into its in-memory snapshot.
	reader := NewBanditPreRouter(
		cfg,
		redisB,
		WithBanditRNG(rand.New(rand.NewPCG(99, 101))),
	)
	if err := reader.WarmupOrg(ctx, "org-redis"); err != nil {
		t.Fatalf("WarmupOrg failed: %v", err)
	}

	aAlpha, aBeta := reader.GetPrior("org-redis", TaskBucketReasoning, "arm-a")
	bAlpha, bBeta := reader.GetPrior("org-redis", TaskBucketReasoning, "arm-b")
	if aAlpha != 31.0 || aBeta != 1.0 {
		t.Fatalf("reader prior for arm-a = (%v,%v), want (31,1)", aAlpha, aBeta)
	}
	if bAlpha != 1.0 || bBeta != 31.0 {
		t.Fatalf("reader prior for arm-b = (%v,%v), want (1,31)", bAlpha, bBeta)
	}

	// Reset Redis command counter and verify ZERO Redis commands during hot-path Route calls!
	hookB.cmds.Store(0)
	reasoningReq := &domain.CanonicalChatRequest{
		ReasoningEffort: "high",
		Messages:        []domain.CanonicalMessage{{Role: "user", Content: "Prove correctness."}},
	}
	armAWins := 0
	for range 200 {
		alias, _, _, err := reader.Route(ctx, "org-redis", reasoningReq)
		if err != nil {
			t.Fatalf("reader.Route failed: %v", err)
		}
		if alias == "arm-a" {
			armAWins++
		}
	}
	if cmds := hookB.cmds.Load(); cmds != 0 {
		t.Fatalf("expected ZERO Redis commands on hot path Route, observed %d", cmds)
	}
	if armAWins < 190 {
		t.Fatalf("expected arm-a to dominate after snapshot sync, got %d/200", armAWins)
	}

	// Even if Redis completely goes away, hot-path Route keeps working from snapshot.
	mr.Close()
	alias, _, _, err := reader.Route(ctx, "org-redis", reasoningReq)
	if err != nil || alias == "" {
		t.Fatalf("expected Route to succeed after Redis shutdown, alias=%q err=%v", alias, err)
	}
}

func TestBanditPreRouter_GracefulDegradationAndDecay(t *testing.T) {
	// 1. Nil RedisFabric degrades gracefully.
	cfg := config.Default().Router
	cfg.Bandit = config.BanditConfig{
		Enabled:         true,
		DefaultAlpha:    1.0,
		DefaultBeta:     1.0,
		DecayHalfLife:   time.Hour,
		CandidateModels: []string{"m1", "m2"},
	}
	b := NewBanditPreRouter(cfg, nil)
	ctx := context.Background()
	b.Start(ctx)
	b.RecordOutcome("", TaskBucketToolUse, "m1", true, 20, false)
	if err := b.Sync(ctx); err != nil {
		t.Fatalf("Sync with nil Redis should return nil, got %v", err)
	}
	b.Stop()

	if a, bt := b.GetPrior("", TaskBucketToolUse, "m1"); a != 2.0 || bt != 1.0 {
		t.Fatalf("expected local prior (2,1) with nil Redis, got (%v,%v)", a, bt)
	}

	// 2. Unreachable Redis degrades gracefully without failing Route or panicking.
	mr := miniredis.RunT(t)
	badFabric := storage.NewRedisFabric(mr.Addr(), "", 0)
	defer badFabric.Client().Close()
	mr.Close() // closed before any writes

	degraded := NewBanditPreRouter(cfg, badFabric, WithBanditFlushInterval(10*time.Millisecond))
	degraded.Start(ctx)
	for range 15 {
		degraded.RecordOutcome("org-deg", TaskBucketSimpleQA, "m1", true, 30, false)
		degraded.RecordOutcome("org-deg", TaskBucketSimpleQA, "m2", false, 30, false)
	}
	degraded.Stop()

	if err := degraded.Sync(ctx); err == nil {
		t.Fatal("expected Sync against closed Redis to report error for observability")
	}
	alias, _, _, err := degraded.Route(ctx, "org-deg", &domain.CanonicalChatRequest{
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "hi"}},
	})
	if err != nil || alias == "" {
		t.Fatalf("expected Route to succeed despite Redis failure, alias=%q err=%v", alias, err)
	}
	if a, _ := degraded.GetPrior("org-deg", TaskBucketSimpleQA, "m1"); a != 16.0 {
		t.Fatalf("expected local snapshot alpha=16 despite Redis outage, got %v", a)
	}

	// 3. Verify exponential decay moves stale excess counts back toward prior.
	stale := BanditPrior{
		Alpha:     101.0,
		Beta:      1.0,
		UpdatedAt: time.Now().Add(-2 * time.Hour), // 2 half-lives -> 0.25x excess
	}
	decayed := b.applyDecay(stale, time.Now())
	if math.Abs(decayed.Alpha-26.0) > 1.0 {
		t.Fatalf("expected decayed alpha ~26.0 after 2 half-lives, got %v", decayed.Alpha)
	}
}

func TestBanditPreRouter_ConcurrentRaceSafety(t *testing.T) {
	mr := miniredis.RunT(t)
	fabric := storage.NewRedisFabric(mr.Addr(), "", 0)
	defer fabric.Client().Close()

	cfg := config.Default().Router
	cfg.Bandit = config.BanditConfig{
		Enabled:         true,
		DefaultAlpha:    1.0,
		DefaultBeta:     1.0,
		CostWeight:      0.2,
		SyncInterval:    15 * time.Millisecond,
		CandidateModels: []string{"fast", "coding", "reasoning"},
	}

	b := NewBanditPreRouter(
		cfg,
		fabric,
		WithBanditAliasCosts(map[string]float64{"fast": 1, "coding": 10, "reasoning": 50}),
		WithBanditFlushInterval(10*time.Millisecond),
		WithBanditBatchSize(16),
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b.Start(ctx)

	reqs := []*domain.CanonicalChatRequest{
		{Messages: []domain.CanonicalMessage{{Role: "user", Content: "hi"}}},
		{Messages: []domain.CanonicalMessage{{Role: "user", Content: "Write func main() in Go"}}},
		{ReasoningEffort: "high", Messages: []domain.CanonicalMessage{{Role: "user", Content: "Analyze"}}},
		{Tools: []domain.CanonicalTool{{Type: "function", Function: domain.CanonicalFunction{Name: "search"}}}},
	}

	var wg sync.WaitGroup
	for g := range 8 {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for i := range 100 {
				req := reqs[(workerID+i)%len(reqs)]
				alias, _, _, err := b.Route(ctx, "org-race", req)
				if err != nil {
					t.Errorf("Route error: %v", err)
					return
				}
				bucket := ClassifyTaskBucket(req, cfg.LongContextTokens)
				b.RecordOutcome("org-race", bucket, alias, (i%3) != 0, int64(50+i), false)
				if i%25 == 0 {
					_, _ = b.GetPrior("org-race", bucket, alias)
					_ = b.Stats()
				}
			}
		}(g)
	}
	wg.Wait()
	b.Stop()

	// Ensure post-Stop RecordOutcome is a safe no-op.
	b.RecordOutcome("org-race", TaskBucketSimpleQA, "fast", true, 10, false)

	stats := b.Stats()
	if stats.RecordedOutcomes != 800 {
		t.Fatalf("RecordedOutcomes = %d, want 800", stats.RecordedOutcomes)
	}
}

func TestBanditPreRouter_RepoCostResolutionAndEdgeCases(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	org := &domain.Organization{Name: "BanditOrg", Slug: "bandit-org", IsActive: true}
	if err := repo.CreateOrganization(ctx, org); err != nil {
		t.Fatalf("CreateOrganization: %v", err)
	}
	cred := &domain.ProviderCredential{OrgID: org.ID, Provider: domain.ProviderOpenAI, Name: "oai", IsActive: true}
	_ = repo.CreateProviderCredential(ctx, cred)
	_ = repo.UpsertGlobalModel(ctx, &domain.GlobalModel{
		ID:                    "openai/cheap-model",
		Provider:              domain.ProviderOpenAI,
		ModelName:             "cheap-model",
		InputCostMicrosPer1M:  100_000,
		OutputCostMicrosPer1M: 200_000,
		SupportsInference:     true,
		LifecycleStatus:       domain.ModelStatusActive,
	})
	_ = repo.UpsertGlobalModel(ctx, &domain.GlobalModel{
		ID:                    "openai/pricy-model",
		Provider:              domain.ProviderOpenAI,
		ModelName:             "pricy-model",
		InputCostMicrosPer1M:  5_000_000,
		OutputCostMicrosPer1M: 15_000_000,
		SupportsInference:     true,
		LifecycleStatus:       domain.ModelStatusActive,
	})

	cheapGroup := &domain.ModelGroup{OrgID: org.ID, Alias: "fast", IsActive: true}
	_ = repo.CreateModelGroup(ctx, cheapGroup)
	_ = repo.CreateDeployment(ctx, &domain.Deployment{
		ModelGroupID:   cheapGroup.ID,
		GlobalModelID:  "openai/cheap-model",
		CredentialID:   cred.ID,
		DeploymentName: "cheap-dep",
		Status:         domain.DeploymentStatusActive,
	})
	pricyGroup := &domain.ModelGroup{OrgID: org.ID, Alias: "reasoning", IsActive: true}
	_ = repo.CreateModelGroup(ctx, pricyGroup)
	_ = repo.CreateDeployment(ctx, &domain.Deployment{
		ModelGroupID:   pricyGroup.ID,
		GlobalModelID:  "openai/pricy-model",
		CredentialID:   cred.ID,
		DeploymentName: "pricy-dep",
		Status:         domain.DeploymentStatusActive,
	})

	// Empty CandidateModels falls back to DefaultFastAlias / DefaultCodingAlias / DefaultReasoningAlias.
	cfg := config.Default().Router
	cfg.Bandit = config.BanditConfig{
		Enabled:      true,
		CostWeight:   0.4,
		DefaultAlpha: 1.0,
		DefaultBeta:  1.0,
	}
	b := NewBanditPreRouter(cfg, nil, WithBanditRepository(repo), WithBanditRNG(rand.New(rand.NewPCG(1, 2))))
	if err := b.WarmupOrg(ctx, org.ID); err != nil {
		t.Fatalf("WarmupOrg: %v", err)
	}

	b.mu.RLock()
	fastCost := b.aliasCosts["fast"]
	reasoningCost := b.aliasCosts["reasoning"]
	b.mu.RUnlock()
	if fastCost != 300_000 || reasoningCost != 20_000_000 {
		t.Fatalf("unexpected repo-resolved costs fast=%v reasoning=%v", fastCost, reasoningCost)
	}

	// Cancelled context returns ctx.Err().
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, _, _, err := b.Route(cctx, org.ID, &domain.CanonicalChatRequest{}); err == nil {
		t.Fatal("expected error for cancelled context")
	}

	// Empty candidates returns error.
	emptyRouter := NewBanditPreRouter(config.RouterConfig{}, nil)
	if _, _, _, err := emptyRouter.Route(ctx, org.ID, &domain.CanonicalChatRequest{}); err == nil {
		t.Fatal("expected error when no candidates are configured")
	}

	// ExplorationRate = 1.0 forces explore reason.
	cfgExplore := cfg
	cfgExplore.Bandit.ExplorationRate = 1.0
	cfgExplore.Bandit.CandidateModels = []string{"a", "b"}
	exploreRouter := NewBanditPreRouter(cfgExplore, nil, WithBanditRNG(rand.New(rand.NewPCG(5, 6))))
	_, reason, _, err := exploreRouter.Route(ctx, org.ID, &domain.CanonicalChatRequest{})
	if err != nil || !strings.Contains(reason, ":explore") {
		t.Fatalf("expected explore reason, got reason=%q err=%v", reason, err)
	}
}
