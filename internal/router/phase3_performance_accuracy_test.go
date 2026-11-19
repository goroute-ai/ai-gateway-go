package router

import (
	"context"
	"math/rand/v2"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type hgetallCountHook struct {
	roundTrips atomic.Int64
}

func (h *hgetallCountHook) DialHook(next redis.DialHook) redis.DialHook {
	return next
}

func (h *hgetallCountHook) ProcessHook(next redis.ProcessHook) redis.ProcessHook {
	return func(ctx context.Context, cmd redis.Cmder) error {
		if strings.EqualFold(cmd.Name(), "hgetall") {
			h.roundTrips.Add(1)
		}
		return next(ctx, cmd)
	}
}

func (h *hgetallCountHook) ProcessPipelineHook(next redis.ProcessPipelineHook) redis.ProcessPipelineHook {
	return func(ctx context.Context, cmds []redis.Cmder) error {
		for _, c := range cmds {
			if strings.EqualFold(c.Name(), "hgetall") {
				h.roundTrips.Add(1)
				break
			}
		}
		return next(ctx, cmds)
	}
}

// nonRevisionCountingRepo wraps a Repository without exposing RoutingRevisionProvider,
// simulating Postgres L1 behavior and counting metadata reads.
type nonRevisionCountingRepo struct {
	storage.Repository
	ptu               storage.PTUShareRepository
	listGroupsCalls   atomic.Int64
	listDepsCalls     atomic.Int64
	listPTUShareCalls atomic.Int64
	listPriorityCalls atomic.Int64
}

func (r *nonRevisionCountingRepo) ListModelGroups(ctx context.Context, orgID string) ([]*domain.ModelGroup, error) {
	r.listGroupsCalls.Add(1)
	return r.Repository.ListModelGroups(ctx, orgID)
}

func (r *nonRevisionCountingRepo) ListDeploymentsByGroup(ctx context.Context, groupID string) ([]*domain.Deployment, error) {
	r.listDepsCalls.Add(1)
	return r.Repository.ListDeploymentsByGroup(ctx, groupID)
}

func (r *nonRevisionCountingRepo) UpsertDeploymentPTUShare(ctx context.Context, share *domain.DeploymentPTUShare) error {
	return r.ptu.UpsertDeploymentPTUShare(ctx, share)
}

func (r *nonRevisionCountingRepo) ListDeploymentPTUShares(ctx context.Context, deploymentID string) ([]*domain.DeploymentPTUShare, error) {
	r.listPTUShareCalls.Add(1)
	return r.ptu.ListDeploymentPTUShares(ctx, deploymentID)
}

func (r *nonRevisionCountingRepo) DeleteDeploymentPTUShare(ctx context.Context, deploymentID, teamID string) error {
	return r.ptu.DeleteDeploymentPTUShare(ctx, deploymentID, teamID)
}

func (r *nonRevisionCountingRepo) HasTeamPTUShares(ctx context.Context, teamID string) (bool, error) {
	return r.ptu.HasTeamPTUShares(ctx, teamID)
}

func (r *nonRevisionCountingRepo) UpsertPriorityClass(ctx context.Context, pc *domain.PriorityClass) error {
	return r.ptu.UpsertPriorityClass(ctx, pc)
}

func (r *nonRevisionCountingRepo) ListPriorityClasses(ctx context.Context, orgID string) ([]*domain.PriorityClass, error) {
	r.listPriorityCalls.Add(1)
	return r.ptu.ListPriorityClasses(ctx, orgID)
}

func TestPhase3_SingleRedisHGetAllPipelinePerHop(t *testing.T) {
	ctx := context.Background()
	mr := miniredis.RunT(t)
	rf := storage.NewRedisFabric(mr.Addr(), "", 0)
	t.Cleanup(func() { _ = rf.Client().Close() })

	hook := &hgetallCountHook{}
	rf.Client().AddHook(hook)

	cfg := config.RouterConfig{
		StrictCapacityFiltering: true,
		BaseRetryDelay:          time.Millisecond,
		MaxRetryDelay:           5 * time.Millisecond,
	}
	repo, reg, vault, _, _, rm, org := newRoutingTestEnv(t, rf, cfg)
	adp := &routingMockAdapter{provider: domain.ProviderOpenAI}
	reg.Register(adp)

	group := &domain.ModelGroup{
		OrgID:           org.ID,
		Alias:           "single-snapshot-group",
		RoutingStrategy: domain.StrategyLatencyBased,
		IsActive:        true,
	}
	require.NoError(t, repo.CreateModelGroup(ctx, group))

	for i, name := range []string{"dep-1", "dep-2", "dep-3"} {
		d := registerRoutingModelAndDep(t, repo, vault, org.ID, group, &domain.GlobalModel{
			ID: "openai/snap-" + name, Provider: domain.ProviderOpenAI, ModelName: "snap-" + name,
			SupportsInference: true, LifecycleStatus: domain.ModelStatusActive,
		}, name, "http://localhost")
		d.RPMCapacity = 100 + i
		d.TPMCapacity = 10000
		require.NoError(t, repo.UpdateDeployment(ctx, d))
	}

	hook.roundTrips.Store(0)
	resp, meta, err := rm.ExecuteChat(ctx, &domain.IdentityContext{OrgID: org.ID}, &domain.CanonicalChatRequest{
		Model:    "single-snapshot-group",
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "hello"}},
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotNil(t, meta.WinningDeployment)
	assert.LessOrEqual(t, hook.roundTrips.Load(), int64(1), "expected at most 1 Redis HGetAll pipeline round-trip per group hop")
}

func TestPhase3_PreReservedTokensBlockBurstAndFailureRefunds(t *testing.T) {
	ctx := context.Background()

	runSub := func(t *testing.T, rf *storage.RedisFabric) {
		t.Helper()
		lb := NewLoadBalancer(rf)
		dep := &domain.Deployment{
			ID:          "dep-burst",
			Status:      domain.DeploymentStatusActive,
			TPMCapacity: 100,
			GlobalModel: &domain.GlobalModel{
				ID: "openai/gpt-4o-mini", Provider: domain.ProviderOpenAI, ModelName: "gpt-4o-mini",
			},
			Credential: &domain.ProviderCredential{IsActive: true},
		}
		candidates := []*domain.Deployment{dep}
		fp := NewFilterPipeline(nil, lb, config.RouterConfig{StrictCapacityFiltering: true})

		// Seed a prior streaming TTFT sample so timeout penalty updates EWMA TTFT too.
		lb.OnRequestEndWithUsage(dep.ID, 100, 50, 0, 0, 0, 0)

		// Pre-reserve 70 tokens before completion ends.
		lb.OnRequestStartWithTokens(dep.ID, 40, 30)

		now := time.Now()
		_, usedTPM, _, _ := lb.AggregateWindowUsage(candidates, now)
		assert.Equal(t, 70, usedTPM, "pre-reserved tokens should immediately reflect in window TPM")

		// A second burst requesting 40 tokens (70 + 40 > 100) must be blocked by Stage 6 strict filtering.
		eligible, err := fp.FilterEligibleDeployments(ctx, "org-1", "grp", &domain.CanonicalChatRequest{Model: "grp"}, candidates, 40)
		require.NoError(t, err)
		assert.Empty(t, eligible, "saturated pre-reserved TPM should block concurrent burst")

		// Failure refunds pre-reserved tokens and records timeout EWMA latency penalty.
		lb.OnRequestFailure(dep.ID, 250, true, 40, 30)

		snap := lb.SnapshotSignals(candidates)
		_, usedTPMAfter, _, _ := lb.AggregateWindowUsageWithSignals(candidates, snap, time.Now())
		assert.Equal(t, 0, usedTPMAfter, "OnRequestFailure must refund pre-reserved tokens without going negative")

		sig := snap.signals[dep.ID]
		assert.Greater(t, sig.ewmaLatencyMs, 250.0, "timeout failure should penalize EWMA latency (> raw latency)")
		assert.Greater(t, sig.ewmaTTFTMs, 50.0, "timeout failure should penalize EWMA TTFT")

		// Subsequent request should now pass strict capacity filtering again.
		eligibleAfter, err := fp.FilterEligibleDeployments(ctx, "org-1", "grp", &domain.CanonicalChatRequest{Model: "grp"}, candidates, 40)
		require.NoError(t, err)
		assert.Len(t, eligibleAfter, 1)
	}

	t.Run("local", func(t *testing.T) {
		runSub(t, nil)
	})
	t.Run("redis", func(t *testing.T) {
		mr := miniredis.RunT(t)
		rf := storage.NewRedisFabric(mr.Addr(), "", 0)
		t.Cleanup(func() { _ = rf.Client().Close() })
		runSub(t, rf)
	})
}

func TestPhase3_NormalizedLatencyAndToleranceBand(t *testing.T) {
	lb := NewLoadBalancer()
	lb.SetLatencyTolerancePct(0.10)
	assert.InDelta(t, 0.10, lb.LatencyTolerancePct(), 1e-9)

	depA := &domain.Deployment{ID: "dep-a", Status: domain.DeploymentStatusActive, Weight: 100}
	depB := &domain.Deployment{ID: "dep-b", Status: domain.DeploymentStatusActive, Weight: 100}
	depC := &domain.Deployment{ID: "dep-c", Status: domain.DeploymentStatusActive, Weight: 100}

	// Same raw latency (1000ms), different output token counts -> dep-a is 1000ms/100tok, dep-b is 10000ms/100tok.
	lb.OnRequestEndWithUsage(depA.ID, 1000, 0, 50, 100, 50, 100)
	lb.OnRequestEndWithUsage(depB.ID, 1000, 0, 50, 10, 50, 10)

	for i := 0; i < 30; i++ {
		got := lb.Select(domain.StrategyLatencyBased, []*domain.Deployment{depA, depB})
		require.NotNil(t, got)
		assert.Equal(t, depA.ID, got.ID, "normalized ms-per-100-tokens must prefer dep-a (10x faster per token)")
	}

	// Add dep-c within 5% of dep-a (normalized 1040ms vs 1000ms) -> both dep-a and dep-c are inside the 10% band, dep-b outside.
	lb.OnRequestEndWithUsage(depC.ID, 1040, 0, 50, 100, 50, 100)
	counts := map[string]int{}
	for i := 0; i < 200; i++ {
		got := lb.Select(domain.StrategyLatencyBased, []*domain.Deployment{depA, depB, depC})
		require.NotNil(t, got)
		counts[got.ID]++
	}
	assert.Zero(t, counts[depB.ID], "out-of-band deployment dep-b must not receive traffic")
	assert.Greater(t, counts[depA.ID], 20, "in-band best deployment dep-a should receive substantial share")
	assert.Greater(t, counts[depC.ID], 20, "in-band deployment dep-c should share traffic via reservoir sampling")
}

func TestPhase3_WeightedRandomFallbackChain(t *testing.T) {
	lb := NewLoadBalancer()

	t.Run("rpm_fallback_when_weights_zero", func(t *testing.T) {
		high := &domain.Deployment{ID: "rpm-high", Weight: 0, RPMCapacity: 900}
		low := &domain.Deployment{ID: "rpm-low", Weight: 0, RPMCapacity: 100}
		highHits := 0
		for i := 0; i < 400; i++ {
			if lb.Select(domain.StrategyWeightedShuffle, []*domain.Deployment{high, low}).ID == high.ID {
				highHits++
			}
		}
		assert.Greater(t, highHits, 300, "900 vs 100 RPM capacity should strongly favor rpm-high")
	})

	t.Run("tpm_fallback_when_weight_and_rpm_zero", func(t *testing.T) {
		high := &domain.Deployment{ID: "tpm-high", Weight: 0, RPMCapacity: 0, TPMCapacity: 9000}
		low := &domain.Deployment{ID: "tpm-low", Weight: 0, RPMCapacity: 0, TPMCapacity: 1000}
		highHits := 0
		for i := 0; i < 400; i++ {
			if lb.Select(domain.StrategyWeightedShuffle, []*domain.Deployment{high, low}).ID == high.ID {
				highHits++
			}
		}
		assert.Greater(t, highHits, 300, "9000 vs 1000 TPM capacity should strongly favor tpm-high")
	})

	t.Run("uniform_100_when_all_zero", func(t *testing.T) {
		d1 := &domain.Deployment{ID: "u-1"}
		d2 := &domain.Deployment{ID: "u-2"}
		hits := map[string]int{}
		for i := 0; i < 400; i++ {
			hits[lb.Select(domain.StrategyWeightedShuffle, []*domain.Deployment{d1, d2}).ID]++
		}
		assert.Greater(t, hits[d1.ID], 120)
		assert.Greater(t, hits[d2.ID], 120)
	})
}

func TestPhase3_WildcardProviderResolution(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	vault, err := auth.NewVault("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	require.NoError(t, err)
	org := &domain.Organization{Name: "WildcardOrg", Slug: "wildcard-org", IsActive: true}
	require.NoError(t, repo.CreateOrganization(ctx, org))
	require.NoError(t, repo.SetOrgProviderSubscription(ctx, &domain.OrgProviderSubscription{
		OrgID: org.ID, Provider: domain.ProviderOpenAI, IsEnabled: true,
	}))

	// Embedding-only model must NOT be picked for chat wildcard resolution.
	embedGroup := &domain.ModelGroup{OrgID: org.ID, Alias: "embed-only", RoutingStrategy: domain.StrategyWeightedShuffle, IsActive: true}
	require.NoError(t, repo.CreateModelGroup(ctx, embedGroup))
	registerRoutingModelAndDep(t, repo, vault, org.ID, embedGroup, &domain.GlobalModel{
		ID: "openai/text-embedding-3-small", Provider: domain.ProviderOpenAI, ModelName: "text-embedding-3-small",
		SupportsInference:   false,
		SupportedOperations: []domain.OperationType{domain.OperationEmbedding},
		Capabilities:        domain.ModelCapabilities{Embeddings: domain.CapabilitySupported},
		LifecycleStatus:     domain.ModelStatusActive,
	}, "dep-embed", "http://localhost")

	// Chat-capable OpenAI model + group.
	chatGroup := &domain.ModelGroup{OrgID: org.ID, Alias: "openai-chat-fast", RoutingStrategy: domain.StrategyWeightedShuffle, IsActive: true}
	require.NoError(t, repo.CreateModelGroup(ctx, chatGroup))
	registerRoutingModelAndDep(t, repo, vault, org.ID, chatGroup, &domain.GlobalModel{
		ID: "openai/gpt-4o-mini", Provider: domain.ProviderOpenAI, ModelName: "gpt-4o-mini",
		SupportsInference:   true,
		SupportedOperations: []domain.OperationType{domain.OperationChat},
		Capabilities:        domain.ModelCapabilities{Streaming: domain.CapabilitySupported},
		LifecycleStatus:     domain.ModelStatusActive,
	}, "dep-chat", "http://localhost")

	// Explicitly enable openai/gpt-4o-mini for this org so wildcard resolution prefers it over catalog defaults.
	require.NoError(t, repo.SetOrgModelPolicy(ctx, &domain.OrgModelPolicy{
		OrgID: org.ID, GlobalModelID: "openai/gpt-4o-mini", IsEnabled: true,
	}))

	ir := NewIntelligentRouter(repo, config.RouterConfig{})
	decision, err := ir.ResolveGroup(ctx, org.ID, &domain.CanonicalChatRequest{
		Model:    "openai/*",
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "hi"}},
	})
	require.NoError(t, err)
	require.NotNil(t, decision)
	require.NotNil(t, decision.ModelGroup)
	assert.NotContains(t, decision.TargetGroupAlias, "*")
	assert.Equal(t, "openai/gpt-4o-mini", decision.TargetGroupAlias)
	deps, err := repo.ListDeploymentsByGroup(ctx, decision.ModelGroup.ID)
	require.NoError(t, err)
	require.NotEmpty(t, deps)
	assert.Equal(t, "gpt-4o-mini", deps[0].GlobalModel.ModelName)
}

func TestPhase3_BanditLatencyWeightFavorsFasterArm(t *testing.T) {
	ctx := context.Background()
	cfg := config.RouterConfig{
		Bandit: config.BanditConfig{
			CandidateModels: []string{"fast-model", "slow-model"},
			DefaultAlpha:    100,
			DefaultBeta:     1,
			ExplorationRate: 0,
		},
	}
	b := NewBanditPreRouter(
		cfg,
		nil,
		WithBanditLatencyWeight(0.5),
		WithBanditRNG(rand.New(rand.NewPCG(42, 7))),
	)

	for i := 0; i < 5; i++ {
		b.RecordOutcome("org-1", TaskBucketSimpleQA, "fast-model", true, 50, false)
		b.RecordOutcome("org-1", TaskBucketSimpleQA, "slow-model", true, 2500, false)
	}

	req := &domain.CanonicalChatRequest{
		Model:    "router/adaptive",
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "hi"}},
	}
	fastCount := 0
	for i := 0; i < 40; i++ {
		alias, _, _, err := b.Route(ctx, "org-1", req)
		require.NoError(t, err)
		if alias == "fast-model" {
			fastCount++
		}
	}
	assert.Equal(t, 40, fastCount, "latency weight with equal high success priors should deterministically prefer fast-model")
}

func TestPhase3_L1CachingAndInvalidateCache(t *testing.T) {
	ctx := context.Background()
	base := storage.NewMemoryRepository()
	vault, err := auth.NewVault("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	require.NoError(t, err)
	org := &domain.Organization{Name: "L1Org", Slug: "l1-org", IsActive: true}
	require.NoError(t, base.CreateOrganization(ctx, org))

	mg := &domain.ModelGroup{OrgID: org.ID, Alias: "l1-fast", RoutingStrategy: domain.StrategyWeightedShuffle, IsActive: true}
	require.NoError(t, base.CreateModelGroup(ctx, mg))
	dep := registerRoutingModelAndDep(t, base, vault, org.ID, mg, &domain.GlobalModel{
		ID:                    "openai/l1-mini",
		Provider:              domain.ProviderOpenAI,
		ModelName:             "l1-mini",
		SupportsInference:     true,
		InputCostMicrosPer1M:  100,
		OutputCostMicrosPer1M: 200,
		Capabilities:          domain.ModelCapabilities{Streaming: domain.CapabilitySupported},
		LifecycleStatus:       domain.ModelStatusActive,
	}, "dep-l1", "http://localhost")

	require.NoError(t, base.UpsertDeploymentPTUShare(ctx, &domain.DeploymentPTUShare{
		OrgID: org.ID, DeploymentID: dep.ID, TeamID: "team-1", ReservedRPM: 50, ReservedTPM: 5000,
	}))
	require.NoError(t, base.UpsertPriorityClass(ctx, &domain.PriorityClass{
		OrgID: org.ID, Name: "gold", Weight: 4, PriorityRank: 1, MaxBorrowMultiple: 2,
	}))

	counting := &nonRevisionCountingRepo{Repository: base, ptu: base}
	cfg := config.RouterConfig{DefaultFastAlias: "l1-fast"}

	// 1. IntelligentRouter.ListActiveModelGroupsCached
	ir := NewIntelligentRouter(counting, cfg)
	g1, err := ir.ListActiveModelGroupsCached(ctx, org.ID)
	require.NoError(t, err)
	require.Len(t, g1, 1)
	_, err = ir.ListActiveModelGroupsCached(ctx, org.ID)
	require.NoError(t, err)
	assert.Equal(t, int64(1), counting.listGroupsCalls.Load(), "second call within L1 TTL should hit cache")

	ir.InvalidateCache(storage.InvalidationEvent{EntityType: "model_group", OrgID: org.ID})
	_, err = ir.ListActiveModelGroupsCached(ctx, org.ID)
	require.NoError(t, err)
	assert.Equal(t, int64(2), counting.listGroupsCalls.Load(), "InvalidateCache must evict IntelligentRouter L1 cache")

	// 2. QualityPreRouter
	counting.listGroupsCalls.Store(0)
	counting.listDepsCalls.Store(0)
	qr := NewQualityPreRouter(counting, cfg, nil)
	qReq := &domain.CanonicalChatRequest{Model: "auto", Messages: []domain.CanonicalMessage{{Role: "user", Content: "hi"}}}
	_, _, _, err = qr.Route(ctx, org.ID, qReq)
	require.NoError(t, err)
	_, _, _, err = qr.Route(ctx, org.ID, qReq)
	require.NoError(t, err)
	assert.Equal(t, int64(1), counting.listGroupsCalls.Load())
	assert.Equal(t, int64(1), counting.listDepsCalls.Load())

	qr.InvalidateCache(storage.InvalidationEvent{EntityType: "deployment", OrgID: org.ID})
	_, _, _, err = qr.Route(ctx, org.ID, qReq)
	require.NoError(t, err)
	assert.Equal(t, int64(2), counting.listGroupsCalls.Load())
	assert.Equal(t, int64(2), counting.listDepsCalls.Load())

	// 3. DynamicPriorityLimiter
	dpl := NewDynamicPriorityLimiter(nil, counting, DynamicPriorityConfig{Enabled: true})
	_, err = dpl.EvaluateDeploymentPTU(ctx, dep, "team-1")
	require.NoError(t, err)
	_, err = dpl.EvaluateDeploymentPTU(ctx, dep, "team-1")
	require.NoError(t, err)
	assert.Equal(t, int64(1), counting.listPTUShareCalls.Load())

	dpl.ResolvePriorityClassName(ctx, &domain.IdentityContext{OrgID: org.ID}, qReq)
	dpl.ResolvePriorityClassName(ctx, &domain.IdentityContext{OrgID: org.ID}, qReq)
	assert.Equal(t, int64(1), counting.listPriorityCalls.Load())

	dpl.InvalidateCache(storage.InvalidationEvent{EntityType: "ptu_share", EntityID: dep.ID, OrgID: org.ID})
	dpl.InvalidateCache(storage.InvalidationEvent{EntityType: "priority_class", OrgID: org.ID})

	_, err = dpl.EvaluateDeploymentPTU(ctx, dep, "team-1")
	require.NoError(t, err)
	dpl.ResolvePriorityClassName(ctx, &domain.IdentityContext{OrgID: org.ID}, qReq)
	assert.Equal(t, int64(2), counting.listPTUShareCalls.Load())
	assert.Equal(t, int64(2), counting.listPriorityCalls.Load())
}

func TestPhase3_ZeroDelaySiblingFailoverAndMaxHonoredRetryAfter(t *testing.T) {
	ctx := context.Background()
	cfg := config.RouterConfig{
		BaseRetryDelay:       500 * time.Millisecond,
		MaxRetryDelay:        500 * time.Millisecond,
		MaxHonoredRetryAfter: 60 * time.Second,
		DefaultMaxRetries:    2,
	}
	repo, reg, vault, _, _, rm, org := newRoutingTestEnv(t, nil, cfg)

	group := &domain.ModelGroup{
		OrgID:           org.ID,
		Alias:           "zero-delay-failover",
		RoutingStrategy: domain.StrategyWeightedShuffle,
		MaxRetries:      2,
		IsActive:        true,
	}
	require.NoError(t, repo.CreateModelGroup(ctx, group))

	depFail := registerRoutingModelAndDep(t, repo, vault, org.ID, group, &domain.GlobalModel{
		ID: "openai/fail-fast", Provider: domain.ProviderOpenAI, ModelName: "fail-fast",
		SupportsInference: true, LifecycleStatus: domain.ModelStatusActive,
	}, "dep-fail", "http://localhost")
	depOK := registerRoutingModelAndDep(t, repo, vault, org.ID, group, &domain.GlobalModel{
		ID: "openai/ok-sib", Provider: domain.ProviderOpenAI, ModelName: "ok-sib",
		SupportsInference: true, LifecycleStatus: domain.ModelStatusActive,
	}, "dep-ok", "http://localhost")

	// Weight dep-fail heavily so it tries first; return retryable 502; healthy sibling dep-ok must succeed without 500ms sleep.
	depFail.Weight = 100000
	depOK.Weight = 1
	require.NoError(t, repo.UpdateDeployment(ctx, depFail))
	require.NoError(t, repo.UpdateDeployment(ctx, depOK))

	adp := &routingMockAdapter{
		provider: domain.ProviderOpenAI,
		chatFn: func(_ context.Context, dep *domain.Deployment, req *domain.CanonicalChatRequest) (*domain.CanonicalChatResponse, error) {
			if dep.ID == depFail.ID {
				return nil, &domain.GatewayError{
					StatusCode: http.StatusBadGateway,
					Type:       domain.ErrorTypeUpstream,
					Code:       "upstream_502",
					Retryable:  true,
				}
			}
			return &domain.CanonicalChatResponse{
				ID:       "ok-sib-resp",
				Provider: domain.ProviderOpenAI,
				Model:    req.ResolvedModel,
				Usage:    domain.TokenUsage{PromptTokens: 5, CompletionTokens: 3, TotalTokens: 8},
			}, nil
		},
	}
	reg.Register(adp)

	start := time.Now()
	resp, meta, err := rm.ExecuteChat(ctx, &domain.IdentityContext{OrgID: org.ID}, &domain.CanonicalChatRequest{
		Model:    "zero-delay-failover",
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "hello"}},
	})
	elapsed := time.Since(start)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotNil(t, meta.WinningDeployment)
	assert.Equal(t, depOK.ID, meta.WinningDeployment.ID)
	assert.Less(t, elapsed, 200*time.Millisecond, "failover to healthy untried sibling must skip BaseRetryDelay sleep")

	// Verify CalculateBackoffWithMaxRetryAfter honors Retry-After: 3 even when MaxRetryDelay=500ms,
	// while falling back to exponential jitter <= MaxRetryDelay for Retry-After: 600 (> MaxHonoredRetryAfter=60s).
	honored := CalculateBackoffWithMaxRetryAfter(0, 3, 50*time.Millisecond, 500*time.Millisecond, 60*time.Second)
	assert.Equal(t, 3*time.Second, honored)

	excessive := CalculateBackoffWithMaxRetryAfter(1, 600, 50*time.Millisecond, 500*time.Millisecond, 60*time.Second)
	assert.LessOrEqual(t, excessive, 500*time.Millisecond)
	assert.GreaterOrEqual(t, excessive, time.Duration(0))

	// Sanity check timeout error helper with net.Error.
	assert.True(t, isTimeoutErr(net.Error(timeoutNetErr{})))
}

type timeoutNetErr struct{}

func (timeoutNetErr) Error() string   { return "i/o timeout" }
func (timeoutNetErr) Timeout() bool   { return true }
func (timeoutNetErr) Temporary() bool { return true }
