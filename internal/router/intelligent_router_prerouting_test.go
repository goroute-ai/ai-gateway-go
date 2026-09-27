package router_test

import (
	"context"
	"errors"
	"math/rand/v2"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	catalog "github.com/goroute-ai/ai-gateway-go/internal/modelcatalog"
	"github.com/goroute-ai/ai-gateway-go/internal/router"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

type errPreRouter struct {
	name string
}

func (e *errPreRouter) Name() string { return e.name }
func (e *errPreRouter) Route(_ context.Context, _ string, _ *domain.CanonicalChatRequest) (string, string, float64, error) {
	return "", "", 0, errors.New("simulated prerouter failure")
}

func seedRoutingTestOrgAndGroups(t *testing.T, ctx context.Context, repo storage.Repository) *domain.Organization {
	t.Helper()
	org := &domain.Organization{
		Name:     "PreRouterTestOrg",
		Slug:     "prerouter-test-org",
		IsActive: true,
	}
	if err := repo.CreateOrganization(ctx, org); err != nil {
		t.Fatalf("CreateOrganization: %v", err)
	}

	models := []*domain.GlobalModel{
		{
			ID:                    "openai/gpt-4o-mini",
			Provider:              domain.ProviderOpenAI,
			ModelName:             "gpt-4o-mini",
			SupportsInference:     true,
			SupportsStreaming:     true,
			SupportsTools:         true,
			MaxInputTokens:        128000,
			InputCostMicrosPer1M:  150_000,
			OutputCostMicrosPer1M: 600_000,
			QualityTier:           catalog.QualityTierEconomy,
			LifecycleStatus:       domain.ModelStatusActive,
		},
		{
			ID:                    "anthropic/claude-sonnet-4-20250514",
			Provider:              domain.ProviderAnthropic,
			ModelName:             "claude-sonnet-4-20250514",
			SupportsInference:     true,
			SupportsStreaming:     true,
			SupportsTools:         true,
			MaxInputTokens:        200000,
			InputCostMicrosPer1M:  3_000_000,
			OutputCostMicrosPer1M: 15_000_000,
			QualityTier:           catalog.QualityTierFrontier,
			LifecycleStatus:       domain.ModelStatusActive,
		},
		{
			ID:                    "openai/o3-mini",
			Provider:              domain.ProviderOpenAI,
			ModelName:             "o3-mini",
			SupportsInference:     true,
			SupportsReasoning:     true,
			SupportsTools:         true,
			MaxInputTokens:        200000,
			InputCostMicrosPer1M:  1_100_000,
			OutputCostMicrosPer1M: 4_400_000,
			QualityTier:           catalog.QualityTierReasoning,
			LifecycleStatus:       domain.ModelStatusActive,
		},
	}
	for _, gm := range models {
		if err := repo.UpsertGlobalModel(ctx, gm); err != nil {
			t.Fatalf("UpsertGlobalModel(%s): %v", gm.ID, err)
		}
	}

	groups := []struct {
		alias string
		gmID  string
	}{
		{alias: "fast", gmID: "openai/gpt-4o-mini"},
		{alias: "coding", gmID: "anthropic/claude-sonnet-4-20250514"},
		{alias: "reasoning", gmID: "openai/o3-mini"},
	}
	for _, g := range groups {
		mg := &domain.ModelGroup{
			OrgID:           org.ID,
			Alias:           g.alias,
			RoutingStrategy: domain.StrategyWeightedShuffle,
			IsActive:        true,
		}
		if err := repo.CreateModelGroup(ctx, mg); err != nil {
			t.Fatalf("CreateModelGroup(%s): %v", g.alias, err)
		}
		if err := repo.CreateDeployment(ctx, &domain.Deployment{
			ModelGroupID:   mg.ID,
			GlobalModelID:  g.gmID,
			DeploymentName: g.alias + "-dep",
			Status:         domain.DeploymentStatusActive,
		}); err != nil {
			t.Fatalf("CreateDeployment(%s): %v", g.alias, err)
		}
	}
	return org
}

func TestIntelligentRouter_PreRouterWiringAutoAndVirtualAliases(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	org := seedRoutingTestOrgAndGroups(t, ctx, repo)

	cfg := config.Default().Router
	cfg.Bandit = config.BanditConfig{
		Enabled:         true,
		CandidateModels: []string{"fast", "coding", "reasoning"},
	}
	ir := router.NewIntelligentRouter(repo, cfg)

	if ir.PreRouters() == nil {
		t.Fatal("expected PreRouters() registry to be initialized")
	}
	if ir.Bandit() == nil {
		t.Fatal("expected Bandit() to be initialized when cfg.Bandit.Enabled is true")
	}

	// Wire SemanticPreRouter with deterministic embeddings.
	semCfg := config.SemanticRouterConfig{
		Enabled:             true,
		EmbeddingModel:      "text-embedding-3-small",
		SimilarityThreshold: 0.75,
		Timeout:             100 * time.Millisecond,
		Routes: []config.SemanticRouteConfig{
			{
				Name:        "coding",
				TargetModel: "coding",
				Utterances:  []string{"write golang code", "refactor python service"},
			},
		},
	}
	embedFn := func(_ context.Context, _ string, _ string, inputs []string) ([][]float32, error) {
		out := make([][]float32, len(inputs))
		for i, text := range inputs {
			lower := strings.ToLower(text)
			if strings.Contains(lower, "golang") || strings.Contains(lower, "python") || strings.Contains(lower, "code") {
				out[i] = []float32{1, 0}
			} else {
				out[i] = []float32{0, 1}
			}
		}
		return out, nil
	}
	sr := router.NewSemanticPreRouter(semCfg, "fast", embedFn, nil)
	if err := sr.Warmup(ctx, org.ID); err != nil {
		t.Fatalf("SemanticPreRouter.Warmup: %v", err)
	}
	ir.SetSemanticPreRouter(sr)

	// 1. "auto" defaults to heuristic pre-router.
	decAutoSimple, err := ir.ResolveGroup(ctx, org.ID, &domain.CanonicalChatRequest{
		Model:    "auto",
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "Hello!"}},
	})
	if err != nil {
		t.Fatalf("ResolveGroup(auto simple): %v", err)
	}
	if decAutoSimple.TargetGroupAlias != "fast" || decAutoSimple.PreRouterName != router.PreRouterModeHeuristic {
		t.Fatalf("auto simple got alias=%q preRouter=%q, want fast/heuristic", decAutoSimple.TargetGroupAlias, decAutoSimple.PreRouterName)
	}

	decAutoComplex, err := ir.ResolveGroup(ctx, org.ID, &domain.CanonicalChatRequest{
		Model:           "auto",
		ReasoningEffort: "high",
		Messages:        []domain.CanonicalMessage{{Role: "user", Content: "Prove the invariant"}},
	})
	if err != nil {
		t.Fatalf("ResolveGroup(auto complex): %v", err)
	}
	if decAutoComplex.TargetGroupAlias != "reasoning" || decAutoComplex.PreRouterName != router.PreRouterModeHeuristic {
		t.Fatalf("auto complex got alias=%q preRouter=%q, want reasoning/heuristic", decAutoComplex.TargetGroupAlias, decAutoComplex.PreRouterName)
	}

	// 2. "router/heuristic" invokes heuristic pre-router explicitly.
	decHeur, err := ir.ResolveGroup(ctx, org.ID, &domain.CanonicalChatRequest{
		Model:    "router/heuristic",
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "Hi"}},
	})
	if err != nil || decHeur.TargetGroupAlias != "fast" || decHeur.PreRouterName != router.PreRouterModeHeuristic {
		t.Fatalf("router/heuristic got dec=%+v err=%v", decHeur, err)
	}

	// 3. "router/semantic" invokes SemanticPreRouter.
	decSemMatch, err := ir.ResolveGroup(ctx, org.ID, &domain.CanonicalChatRequest{
		Model:    "router/semantic",
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "Help me write golang code"}},
	})
	if err != nil {
		t.Fatalf("ResolveGroup(router/semantic match): %v", err)
	}
	if decSemMatch.TargetGroupAlias != "coding" || decSemMatch.PreRouterName != router.PreRouterModeSemantic || !strings.HasPrefix(decSemMatch.Reason, "semantic:route:coding") {
		t.Fatalf("router/semantic match got %+v", decSemMatch)
	}
	if decSemMatch.ModelGroup == nil || decSemMatch.ModelGroup.Alias != "coding" {
		t.Fatalf("expected ModelGroup alias coding, got %+v", decSemMatch.ModelGroup)
	}

	// Semantic below threshold fails open to DefaultAlias ("fast").
	decSemMiss, err := ir.ResolveGroup(ctx, org.ID, &domain.CanonicalChatRequest{
		Model:    "router/semantic",
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "What is the capital of France?"}},
	})
	if err != nil || decSemMiss.TargetGroupAlias != "fast" || decSemMiss.Reason != "semantic:below_threshold" {
		t.Fatalf("router/semantic miss got %+v err=%v", decSemMiss, err)
	}

	// 4. "router/quality" invokes QualityPreRouter.
	decQualSimple, err := ir.ResolveGroup(ctx, org.ID, &domain.CanonicalChatRequest{
		Model:    "router/quality",
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "Hi"}},
	})
	if err != nil || decQualSimple.TargetGroupAlias != "fast" || decQualSimple.PreRouterName != router.PreRouterModeQuality {
		t.Fatalf("router/quality simple got %+v err=%v", decQualSimple, err)
	}

	decQualTools, err := ir.ResolveGroup(ctx, org.ID, &domain.CanonicalChatRequest{
		Model:    "router/quality",
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "Run tool"}},
		Tools:    []domain.CanonicalTool{{Type: "function"}},
	})
	if err != nil || decQualTools.TargetGroupAlias != "reasoning" || decQualTools.PreRouterName != router.PreRouterModeQuality {
		t.Fatalf("router/quality tools got %+v err=%v", decQualTools, err)
	}

	// SetQualityPreRouter with CacheAwareRouting=true short-circuits on cache hit.
	cacheCfg := cfg
	cacheCfg.CacheAwareRouting = true
	ir.SetQualityPreRouter(router.NewQualityPreRouter(repo, cacheCfg, func(_ context.Context, _ string, _ *domain.CanonicalChatRequest) (string, bool) {
		return "fast", true
	}))
	decQualCache, err := ir.ResolveGroup(ctx, org.ID, &domain.CanonicalChatRequest{
		Model:           "router/quality",
		ReasoningEffort: "high",
		Messages:        []domain.CanonicalMessage{{Role: "user", Content: "Prove theorem"}},
	})
	if err != nil || decQualCache.TargetGroupAlias != "fast" || decQualCache.Reason != "quality:cache_hit" {
		t.Fatalf("router/quality cache hit got %+v err=%v", decQualCache, err)
	}

	// 5. "router/adaptive" invokes BanditPreRouter and sets BanditBucket + PreRouterName.
	bandit := router.NewBanditPreRouter(cfg, nil, router.WithBanditRNG(rand.New(rand.NewPCG(1, 2))))
	for i := 0; i < 40; i++ {
		bandit.RecordOutcome(org.ID, router.TaskBucketCoding, "coding", true, 50, false)
		bandit.RecordOutcome(org.ID, router.TaskBucketCoding, "fast", false, 50, false)
	}
	bandit.Stop() // drains queued outcomes synchronously into snapshot
	ir.SetBanditPreRouter(bandit)
	if ir.Bandit() != bandit {
		t.Fatal("expected Bandit() to return updated BanditPreRouter")
	}

	decAdaptive, err := ir.ResolveGroup(ctx, org.ID, &domain.CanonicalChatRequest{
		Model:    "router/adaptive",
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "Implement a golang struct and unit test"}},
	})
	if err != nil {
		t.Fatalf("ResolveGroup(router/adaptive): %v", err)
	}
	if decAdaptive.TargetGroupAlias != "coding" || decAdaptive.PreRouterName != router.PreRouterModeAdaptive || decAdaptive.BanditBucket != router.TaskBucketCoding {
		t.Fatalf("router/adaptive got alias=%q preRouter=%q bucket=%q reason=%q",
			decAdaptive.TargetGroupAlias, decAdaptive.PreRouterName, decAdaptive.BanditBucket, decAdaptive.Reason)
	}
}

func TestIntelligentRouter_PreRouterModesAndFallbackToHeuristic(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	org := seedRoutingTestOrgAndGroups(t, ctx, repo)

	// Case 1: PreRouterMode="semantic" without SetSemanticPreRouter falls back to heuristic.
	semModeCfg := config.Default().Router
	semModeCfg.PreRouterMode = router.PreRouterModeSemantic
	irSemFallback := router.NewIntelligentRouter(repo, semModeCfg)
	if irSemFallback.Bandit() != nil {
		t.Fatal("expected Bandit() to be nil when cfg.Bandit.Enabled is false")
	}

	decAuto, err := irSemFallback.ResolveGroup(ctx, org.ID, &domain.CanonicalChatRequest{
		Model:    "auto",
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "Hi there"}},
	})
	if err != nil || decAuto.TargetGroupAlias != "fast" || decAuto.PreRouterName != router.PreRouterModeHeuristic {
		t.Fatalf("auto with unwired semantic mode should fall back to heuristic, got %+v err=%v", decAuto, err)
	}

	// Requesting "router/semantic" or "router/adaptive" before wiring also falls back cleanly to heuristic.
	decVirtSem, err := irSemFallback.ResolveGroup(ctx, org.ID, &domain.CanonicalChatRequest{
		Model:           "router/semantic",
		ReasoningEffort: "high",
		Messages:        []domain.CanonicalMessage{{Role: "user", Content: "Solve"}},
	})
	if err != nil || decVirtSem.TargetGroupAlias != "reasoning" || decVirtSem.PreRouterName != router.PreRouterModeHeuristic {
		t.Fatalf("router/semantic unwired fallback got %+v err=%v", decVirtSem, err)
	}

	decVirtAdapt, err := irSemFallback.ResolveGroup(ctx, org.ID, &domain.CanonicalChatRequest{
		Model:    "router/adaptive",
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "Hi"}},
	})
	if err != nil || decVirtAdapt.TargetGroupAlias != "fast" || decVirtAdapt.PreRouterName != router.PreRouterModeHeuristic {
		t.Fatalf("router/adaptive unwired fallback got %+v err=%v", decVirtAdapt, err)
	}

	// Case 2: Failing registered PreRouter falls back to heuristic.
	irSemFallback.RegisterPreRouter(&errPreRouter{name: router.PreRouterModeAdaptive})
	decErrFallback, err := irSemFallback.ResolveGroup(ctx, org.ID, &domain.CanonicalChatRequest{
		Model:    "router/adaptive",
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "Quick question"}},
	})
	if err != nil || decErrFallback.TargetGroupAlias != "fast" || decErrFallback.PreRouterName != router.PreRouterModeHeuristic {
		t.Fatalf("failing adaptive router should fall back to heuristic, got %+v err=%v", decErrFallback, err)
	}

	// Case 3: PreRouterMode="quality" routes "auto" through QualityPreRouter.
	qualModeCfg := config.Default().Router
	qualModeCfg.PreRouterMode = router.PreRouterModeQuality
	irQual := router.NewIntelligentRouter(repo, qualModeCfg)
	decQualAuto, err := irQual.ResolveGroup(ctx, org.ID, &domain.CanonicalChatRequest{
		Model:    "auto",
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "Call tool"}},
		Tools:    []domain.CanonicalTool{{Type: "function"}},
	})
	if err != nil || decQualAuto.TargetGroupAlias != "reasoning" || decQualAuto.PreRouterName != router.PreRouterModeQuality {
		t.Fatalf("auto with quality mode got %+v err=%v", decQualAuto, err)
	}

	// Case 4: PreRouterMode="adaptive" with Bandit enabled routes "auto" through BanditPreRouter.
	adaptModeCfg := config.Default().Router
	adaptModeCfg.PreRouterMode = router.PreRouterModeAdaptive
	adaptModeCfg.Bandit = config.BanditConfig{
		Enabled:         true,
		CandidateModels: []string{"coding"},
	}
	irAdapt := router.NewIntelligentRouter(repo, adaptModeCfg)
	decAdaptAuto, err := irAdapt.ResolveGroup(ctx, org.ID, &domain.CanonicalChatRequest{
		Model:    "auto",
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "Write a function"}},
	})
	if err != nil || decAdaptAuto.TargetGroupAlias != "coding" || decAdaptAuto.PreRouterName != router.PreRouterModeAdaptive || decAdaptAuto.BanditBucket != router.TaskBucketCoding {
		t.Fatalf("auto with adaptive mode got %+v err=%v", decAdaptAuto, err)
	}
}

func TestIntelligentRouter_VirtualAliasSmartFallbackAndExplicitNoRegression(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	org := &domain.Organization{Name: "FallbackOrg", Slug: "fallback-org", IsActive: true}
	if err := repo.CreateOrganization(ctx, org); err != nil {
		t.Fatalf("CreateOrganization: %v", err)
	}

	// Only "fast" active group exists (neither "nonexistent-target" nor "anthropic/claude-3-opus").
	if err := repo.CreateModelGroup(ctx, &domain.ModelGroup{
		OrgID:           org.ID,
		Alias:           "fast",
		RoutingStrategy: domain.StrategyWeightedShuffle,
		IsActive:        true,
	}); err != nil {
		t.Fatalf("CreateModelGroup: %v", err)
	}

	ir := router.NewIntelligentRouter(repo, config.Default().Router)
	// Register a custom virtual alias whose PreRouter points to an unconfigured alias.
	ir.RegisterPreRouter(&stubPreRouter{name: "custom", alias: "nonexistent-target"})
	ir.PreRouters().RegisterAlias("router/custom", "custom")

	// Virtual alias must retain isSmartAlias=true and fall back to "fast", never hitting dynamic provider lookup or 404.
	decCustom, err := ir.ResolveGroup(ctx, org.ID, &domain.CanonicalChatRequest{
		Model:    "router/custom",
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "Hello"}},
	})
	if err != nil || decCustom.ModelGroup == nil || decCustom.ModelGroup.Alias != "fast" {
		t.Fatalf("expected router/custom smart-alias fallback to fast, got dec=%+v err=%v", decCustom, err)
	}

	// Explicit existing group alias must bypass PreRouter and preserve "explicit_model".
	decExplicit, err := ir.ResolveGroup(ctx, org.ID, &domain.CanonicalChatRequest{
		Model:    "fast",
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "Prove this theorem step by step"}},
	})
	if err != nil || decExplicit.TargetGroupAlias != "fast" || decExplicit.Reason != "explicit_model" || decExplicit.PreRouterName != "" {
		t.Fatalf("explicit group alias got %+v err=%v", decExplicit, err)
	}

	// Explicit unconfigured model must still return 404 (no fallback to "fast").
	_, err = ir.ResolveGroup(ctx, org.ID, &domain.CanonicalChatRequest{
		Model:    "anthropic/claude-3-opus",
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "Hi"}},
	})
	gwErr, ok := err.(*domain.GatewayError)
	if !ok || gwErr.StatusCode != 404 || gwErr.Code != "model_group_not_found" {
		t.Fatalf("expected 404 model_group_not_found for explicit unconfigured model, got %+v", err)
	}

	// Comma-separated model list is not treated as a virtual alias and returns 404 if not an alias itself.
	if got := router.ParseCommaSeparatedModels("fast,reasoning"); len(got) != 2 {
		t.Fatalf("ParseCommaSeparatedModels unexpected: %v", got)
	}
	_, err = ir.ResolveGroup(ctx, org.ID, &domain.CanonicalChatRequest{
		Model:    "fast,reasoning",
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "Hi"}},
	})
	if err == nil {
		t.Fatal("expected comma-separated model string not to be treated as a single virtual alias")
	}
}

func TestIntelligentRouter_ConcurrentSettersAndResolveGroup(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	org := seedRoutingTestOrgAndGroups(t, ctx, repo)

	cfg := config.Default().Router
	cfg.Bandit.Enabled = true
	cfg.Bandit.CandidateModels = []string{"fast", "coding"}
	ir := router.NewIntelligentRouter(repo, cfg)

	semCfg := config.SemanticRouterConfig{
		Enabled:             true,
		SimilarityThreshold: 0.5,
		Routes: []config.SemanticRouteConfig{
			{Name: "coding", TargetModel: "coding", Utterances: []string{"code"}},
		},
	}
	sr := router.NewSemanticPreRouter(semCfg, "fast", func(_ context.Context, _ string, _ string, inputs []string) ([][]float32, error) {
		out := make([][]float32, len(inputs))
		for i := range inputs {
			out[i] = []float32{1, 0}
		}
		return out, nil
	}, nil)
	_ = sr.Warmup(ctx, org.ID)

	var wg sync.WaitGroup
	models := []string{"auto", "router/heuristic", "router/semantic", "router/quality", "router/adaptive", "fast"}
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			switch idx % 4 {
			case 0:
				ir.SetSemanticPreRouter(sr)
			case 1:
				ir.SetQualityPreRouter(router.NewQualityPreRouter(repo, cfg, nil))
			case 2:
				ir.SetBanditPreRouter(router.NewBanditPreRouter(cfg, nil))
			case 3:
				_ = ir.Bandit()
				_ = ir.PreRouters()
			}
			for _, m := range models {
				dec, err := ir.ResolveGroup(ctx, org.ID, &domain.CanonicalChatRequest{
					Model:    m,
					Messages: []domain.CanonicalMessage{{Role: "user", Content: "write code"}},
				})
				if err != nil || dec == nil || dec.ModelGroup == nil {
					t.Errorf("concurrent ResolveGroup(%q) failed: dec=%+v err=%v", m, dec, err)
				}
			}
		}(i)
	}
	wg.Wait()
}
