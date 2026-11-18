package router

import (
	"container/heap"
	"context"
	"math/rand/v2"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

var (
	benchDepSink   *domain.Deployment
	benchDecSink   *RouteDecision
	benchFloatSink float64
	benchIntSink   int
)

func setupRouterBenchmarkFixture(tb testing.TB) (
	ctx context.Context,
	orgID string,
	ir *IntelligentRouter,
	fp *FilterPipeline,
	lb *LoadBalancer,
	deployments []*domain.Deployment,
	req *domain.CanonicalChatRequest,
) {
	tb.Helper()
	ctx = context.Background()
	repo := storage.NewMemoryRepository()

	org := &domain.Organization{
		Name:     "BenchOrg",
		Slug:     "bench-org",
		IsActive: true,
	}
	if err := repo.CreateOrganization(ctx, org); err != nil {
		tb.Fatalf("CreateOrganization: %v", err)
	}

	cred := &domain.ProviderCredential{
		OrgID:    org.ID,
		Provider: domain.ProviderOpenAI,
		Name:     "bench-cred",
		IsActive: true,
	}
	if err := repo.CreateProviderCredential(ctx, cred); err != nil {
		tb.Fatalf("CreateProviderCredential: %v", err)
	}

	gm := &domain.GlobalModel{
		ID:                "openai/gpt-4.1-mini",
		Provider:          domain.ProviderOpenAI,
		ModelName:         "gpt-4.1-mini",
		SupportsInference: true,
		SupportsStreaming: true,
		MaxInputTokens:    128000,
		MaxOutputTokens:   16384,
		LifecycleStatus:   domain.ModelStatusActive,
		PricingStatus:     domain.PricingStatusVerified,
	}
	if err := repo.UpsertGlobalModel(ctx, gm); err != nil {
		tb.Fatalf("UpsertGlobalModel: %v", err)
	}

	mg := &domain.ModelGroup{
		OrgID:           org.ID,
		Alias:           "fast",
		RoutingStrategy: domain.StrategyWeightedShuffle,
		MaxRetries:      1,
		IsActive:        true,
	}
	if err := repo.CreateModelGroup(ctx, mg); err != nil {
		tb.Fatalf("CreateModelGroup: %v", err)
	}

	deployments = make([]*domain.Deployment, 4)
	for i := range deployments {
		dep := &domain.Deployment{
			ModelGroupID:   mg.ID,
			GlobalModelID:  gm.ID,
			GlobalModel:    gm,
			CredentialID:   cred.ID,
			Credential:     cred,
			DeploymentName: "fast-dep",
			Region:         "us-east-1",
			Priority:       0,
			Weight:         100,
			Status:         domain.DeploymentStatusActive,
		}
		if err := repo.CreateDeployment(ctx, dep); err != nil {
			tb.Fatalf("CreateDeployment(%d): %v", i, err)
		}
		dep.GlobalModel = gm
		dep.Credential = cred
		deployments[i] = dep
	}

	rCfg := config.Default().Router
	ir = NewIntelligentRouter(repo, rCfg)
	lb = NewLoadBalancer()
	fp = NewFilterPipeline(nil, lb, rCfg)

	req = &domain.CanonicalChatRequest{
		Model: "auto",
		Messages: []domain.CanonicalMessage{
			{Role: "user", Content: "Hello, summarize this status."},
		},
	}
	return ctx, org.ID, ir, fp, lb, deployments, req
}

func BenchmarkRouter_ResolveGroupAndSelect_FastPath(b *testing.B) {
	ctx, orgID, ir, fp, lb, deployments, req := setupRouterBenchmarkFixture(b)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		decision, err := ir.ResolveGroup(ctx, orgID, req)
		if err != nil {
			b.Fatalf("ResolveGroup: %v", err)
		}
		eligible, err := fp.FilterEligibleDeployments(ctx, orgID, decision.TargetGroupAlias, req, deployments, 0)
		if err != nil {
			b.Fatalf("FilterEligibleDeployments: %v", err)
		}
		tiers := partitionByPriority(eligible)
		selected := lb.Select(decision.ModelGroup.RoutingStrategy, tiers[0])
		benchDecSink = decision
		benchDepSink = selected
	}
}

func BenchmarkRouter_Stage2FilterAndSelect_ZeroAlloc(b *testing.B) {
	ctx, orgID, _, fp, lb, deployments, req := setupRouterBenchmarkFixture(b)

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		eligible, err := fp.FilterEligibleDeployments(ctx, orgID, "fast", req, deployments, 0)
		if err != nil {
			b.Fatalf("FilterEligibleDeployments: %v", err)
		}
		tiers := partitionByPriority(eligible)
		selected := lb.Select(domain.StrategyWeightedShuffle, tiers[0])
		benchDepSink = selected
	}
}

func BenchmarkFilterChain_TagsAndRegion(b *testing.B) {
	ctx := context.Background()
	gm := &domain.GlobalModel{
		ID:                "openai/gpt-4.1-mini",
		Provider:          domain.ProviderOpenAI,
		ModelName:         "gpt-4.1-mini",
		SupportsInference: true,
		SupportsStreaming: true,
		MaxInputTokens:    128000,
		LifecycleStatus:   domain.ModelStatusActive,
	}
	cred := &domain.ProviderCredential{
		ID:       "cred-filter-bench",
		Provider: domain.ProviderOpenAI,
		IsActive: true,
	}

	candidates := []*domain.Deployment{
		{ID: "d1", GlobalModel: gm, Credential: cred, Status: domain.DeploymentStatusActive, Region: "us-east-1", Tags: []string{"tier:primary", "compliance:us"}},
		{ID: "d2", GlobalModel: gm, Credential: cred, Status: domain.DeploymentStatusActive, Region: "eu-west-1", Tags: []string{"tier:primary", "compliance:eu", "legacy"}},
		{ID: "d3", GlobalModel: gm, Credential: cred, Status: domain.DeploymentStatusActive, Region: "eu-west-1", Tags: []string{"tier:primary", "compliance:eu", "gpu:h100"}},
		{ID: "d4", GlobalModel: gm, Credential: cred, Status: domain.DeploymentStatusActive, Region: "ap-south-1", Tags: []string{"tier:secondary", "compliance:apac"}},
		{ID: "d5", GlobalModel: gm, Credential: cred, Status: domain.DeploymentStatusActive, Region: "eu-west-1", Tags: []string{"tier:canary", "compliance:eu"}},
		{ID: "d6", GlobalModel: gm, Credential: cred, Status: domain.DeploymentStatusActive, Region: "eu-west-1", Tags: []string{"tier:fast", "compliance:eu", "gpu:l40s"}},
		{ID: "d7", GlobalModel: gm, Credential: cred, Status: domain.DeploymentStatusActive, Region: "us-west-2", Tags: []string{"tier:fast", "compliance:us"}},
		{ID: "d8", GlobalModel: gm, Credential: cred, Status: domain.DeploymentStatusActive, Region: "eu-west-1", Tags: []string{"compliance:eu"}},
	}

	fp := NewFilterPipeline(nil, nil, config.Default().Router)
	req := &domain.CanonicalChatRequest{
		Model: "fast",
		GoRouteExtensions: &domain.GoRouteExtensions{
			AllowedRegion: "eu-west-1",
			Tags:          []string{"&compliance:eu", "!legacy", "tier:*"},
		},
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out, err := fp.FilterEligibleDeployments(ctx, "org-bench", "fast", req, candidates, 128)
		if err != nil {
			b.Fatalf("FilterEligibleDeployments: %v", err)
		}
		benchIntSink = len(out)
	}
}

func BenchmarkPriorityTiers_SingleTierFastPath(b *testing.B) {
	deployments := []*domain.Deployment{
		{ID: "d1", Priority: 0, Status: domain.DeploymentStatusActive},
		{ID: "d2", Priority: 0, Status: domain.DeploymentStatusActive},
		{ID: "d3", Priority: 0, Status: domain.DeploymentStatusActive},
		{ID: "d4", Priority: 0, Status: domain.DeploymentStatusActive},
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tiers := partitionByPriority(deployments)
		benchIntSink = len(tiers[0])
	}
}

func BenchmarkBandit_SampleBeta(b *testing.B) {
	b.Run("StandardAlphaBeta", func(b *testing.B) {
		rng := rand.New(rand.NewPCG(42, 99))
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			benchFloatSink = sampleBeta(5.0, 2.0, rng)
		}
	})

	b.Run("SubUnitAlphaBoost", func(b *testing.B) {
		rng := rand.New(rand.NewPCG(7, 13))
		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			benchFloatSink = sampleBeta(0.5, 0.5, rng)
		}
	})
}

func BenchmarkScheduler_PriorityHeap(b *testing.B) {
	b.Run("WaiterHeapPushPop", func(b *testing.B) {
		priorities := []int{5, 1, 0, 3, 2, 0, 4, 1}
		waiters := make([]*schedulerWaiter, len(priorities))
		for i, p := range priorities {
			waiters[i] = &schedulerWaiter{
				priority: p,
				seq:      uint64(i + 1),
				index:    -1,
			}
		}
		h := make(waiterHeap, 0, len(waiters))

		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			for j, w := range waiters {
				w.seq = uint64(i*len(waiters) + j + 1)
				heap.Push(&h, w)
			}
			for h.Len() > 0 {
				w := heap.Pop(&h).(*schedulerWaiter)
				benchIntSink = w.priority
			}
		}
	})

	b.Run("AcquireReleaseFastPath", func(b *testing.B) {
		ctx := context.Background()
		sched := NewPriorityScheduler(64, 128, time.Second)

		b.ReportAllocs()
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			release, err := sched.Acquire(ctx, i%4)
			if err != nil {
				b.Fatalf("Acquire: %v", err)
			}
			release()
		}
	})
}

func TestRouter_HotPathLatencyBudget(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping benchmark latency budget check in -short mode")
	}

	fastRes := testing.Benchmark(BenchmarkRouter_ResolveGroupAndSelect_FastPath)
	const maxFastPathNsPerOp = 50_000 // 50 µs budget
	t.Logf("ResolveGroupAndSelect_FastPath: %d ns/op, %d B/op, %d allocs/op",
		fastRes.NsPerOp(), fastRes.AllocedBytesPerOp(), fastRes.AllocsPerOp())
	if fastRes.NsPerOp() >= maxFastPathNsPerOp {
		t.Fatalf("hot-path latency %d ns/op exceeded 50µs budget (%d ns/op)", fastRes.NsPerOp(), maxFastPathNsPerOp)
	}

	stage2Res := testing.Benchmark(BenchmarkRouter_Stage2FilterAndSelect_ZeroAlloc)
	t.Logf("Stage2FilterAndSelect_ZeroAlloc: %d ns/op, %d B/op, %d allocs/op",
		stage2Res.NsPerOp(), stage2Res.AllocedBytesPerOp(), stage2Res.AllocsPerOp())
	if stage2Res.AllocsPerOp() != 0 {
		t.Fatalf("expected 0 allocs/op on Stage 2 fast path, got %d", stage2Res.AllocsPerOp())
	}

	tierRes := testing.Benchmark(BenchmarkPriorityTiers_SingleTierFastPath)
	t.Logf("PriorityTiers_SingleTierFastPath: %d ns/op, %d B/op, %d allocs/op",
		tierRes.NsPerOp(), tierRes.AllocedBytesPerOp(), tierRes.AllocsPerOp())
	if tierRes.AllocsPerOp() != 0 {
		t.Fatalf("expected 0 allocs/op on single-tier priority fast path, got %d", tierRes.AllocsPerOp())
	}
}
