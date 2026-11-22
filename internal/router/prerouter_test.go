package router_test

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	catalog "github.com/goroute-ai/ai-gateway-go/internal/modelcatalog"
	"github.com/goroute-ai/ai-gateway-go/internal/router"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

type stubPreRouter struct {
	name  string
	alias string
}

func (s *stubPreRouter) Name() string { return s.name }
func (s *stubPreRouter) Route(_ context.Context, _ string, _ *domain.CanonicalChatRequest) (string, string, float64, error) {
	return s.alias, "stub:" + s.name, 0.88, nil
}

func TestPreRouterRegistryAndVirtualAliases(t *testing.T) {
	reg := router.NewPreRouterRegistry("semantic")
	heur := router.NewHeuristicPreRouter(config.Default().Router)
	sem := &stubPreRouter{name: router.PreRouterModeSemantic, alias: "coding"}
	qual := &stubPreRouter{name: router.PreRouterModeQuality, alias: "fast"}
	adap := &stubPreRouter{name: router.PreRouterModeAdaptive, alias: "reasoning"}

	reg.Register(heur)
	reg.Register(sem)
	reg.Register(qual)
	reg.Register(adap)

	if got := reg.Names(); len(got) != 4 {
		t.Fatalf("expected 4 registered routers, got %v", got)
	}

	aliasExpectations := []struct {
		model       string
		expectName  string
		expectAlias string
	}{
		{model: "auto", expectName: "semantic", expectAlias: "coding"},
		{model: "", expectName: "semantic", expectAlias: "coding"},
		{model: "router/heuristic", expectName: "heuristic", expectAlias: "fast"},
		{model: "router/semantic", expectName: "semantic", expectAlias: "coding"},
		{model: "router/quality", expectName: "quality", expectAlias: "fast"},
		{model: "router/adaptive", expectName: "adaptive", expectAlias: "reasoning"},
	}

	ctx := context.Background()
	for _, tc := range aliasExpectations {
		if !reg.IsVirtualAlias(tc.model) {
			t.Errorf("expected %q to be recognized as virtual alias", tc.model)
		}
		pr, ok := reg.ResolveAlias(tc.model)
		if !ok || pr == nil {
			t.Fatalf("ResolveAlias(%q) returned false", tc.model)
		}
		if pr.Name() != tc.expectName {
			t.Errorf("ResolveAlias(%q).Name() = %q, want %q", tc.model, pr.Name(), tc.expectName)
		}
		alias, _, _, matched, err := reg.Route(ctx, "org-1", &domain.CanonicalChatRequest{
			Model:    tc.model,
			Messages: []domain.CanonicalMessage{{Role: "user", Content: "hi"}},
		})
		if err != nil || !matched {
			t.Fatalf("Route(%q) matched=%v err=%v", tc.model, matched, err)
		}
		if alias != tc.expectAlias {
			t.Errorf("Route(%q) alias = %q, want %q", tc.model, alias, tc.expectAlias)
		}
	}

	// Explicit model names must NOT be matched as virtual aliases.
	if reg.IsVirtualAlias("gpt-4o") {
		t.Fatal("gpt-4o must not be treated as a virtual alias")
	}
	if _, _, _, matched, err := reg.Route(ctx, "org-1", &domain.CanonicalChatRequest{Model: "gpt-4o"}); matched || err != nil {
		t.Fatalf("expected explicit model not to match pre-router, got matched=%v err=%v", matched, err)
	}

	// Custom alias & SetDefaultMode + fallback to heuristic if default mode is unregistered.
	reg.RegisterAlias("router/custom", "quality")
	if pr, ok := reg.ResolveAlias("router/custom"); !ok || pr.Name() != "quality" {
		t.Fatalf("expected router/custom to resolve to quality, got ok=%v pr=%v", ok, pr)
	}
	reg.SetDefaultMode("unregistered-mode")
	if pr, ok := reg.ResolveAlias("auto"); !ok || pr.Name() != "heuristic" {
		t.Fatalf("expected auto to fall back to heuristic when default mode unregistered, got ok=%v pr=%v", ok, pr)
	}

	// Concurrent reads/writes under -race.
	var wg sync.WaitGroup
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			if idx%2 == 0 {
				reg.SetDefaultMode("quality")
			} else {
				reg.SetDefaultMode("semantic")
			}
			_, _, _, _, _ = reg.Route(ctx, "org-1", &domain.CanonicalChatRequest{
				Model:    "auto",
				Messages: []domain.CanonicalMessage{{Role: "user", Content: "hello"}},
			})
		}(i)
	}
	wg.Wait()
}

func TestPreRouterHeuristicDelegationAndStandalone(t *testing.T) {
	cfg := config.Default().Router
	repo := storage.NewMemoryRepository()
	ir := router.NewIntelligentRouter(repo, cfg)

	standalone := router.NewHeuristicPreRouter(cfg)
	delegating := router.NewHeuristicPreRouterWithRouter(ir)

	if standalone.Name() != "heuristic" || delegating.Name() != "heuristic" {
		t.Fatalf("unexpected heuristic router names: %q, %q", standalone.Name(), delegating.Name())
	}

	cases := []struct {
		name      string
		req       *domain.CanonicalChatRequest
		wantAlias string
	}{
		{
			name: "simple prompt",
			req: &domain.CanonicalChatRequest{
				Model:    "auto",
				Messages: []domain.CanonicalMessage{{Role: "user", Content: "Hi there!"}},
			},
			wantAlias: "fast",
		},
		{
			name: "explicit reasoning effort",
			req: &domain.CanonicalChatRequest{
				Model:           "auto",
				ReasoningEffort: "high",
				Messages:        []domain.CanonicalMessage{{Role: "user", Content: "Solve this"}},
			},
			wantAlias: "reasoning",
		},
		{
			name: "code and analysis",
			req: &domain.CanonicalChatRequest{
				Model:    "auto",
				Messages: []domain.CanonicalMessage{{Role: "user", Content: "Please analyze and debug this distributed concurrency algorithm:\n```go\nfunc main() {}\n```"}},
			},
			wantAlias: "reasoning",
		},
	}

	ctx := context.Background()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a1, r1, s1, err1 := standalone.Route(ctx, "org-1", tc.req)
			a2, r2, s2, err2 := delegating.Route(ctx, "org-1", tc.req)
			if err1 != nil || err2 != nil {
				t.Fatalf("unexpected errors: standalone=%v delegating=%v", err1, err2)
			}
			if a1 != tc.wantAlias || a2 != tc.wantAlias {
				t.Fatalf("got aliases (%q, %q), want %q", a1, a2, tc.wantAlias)
			}
			if a1 != a2 || r1 != r2 || s1 != s2 {
				t.Fatalf("standalone (%q,%q,%.3f) diverged from delegating (%q,%q,%.3f)", a1, r1, s1, a2, r2, s2)
			}
		})
	}

	if _, _, _, err := standalone.Route(ctx, "org-1", nil); err == nil {
		t.Fatal("expected error for nil request")
	}
}

func TestPreRouterSemanticWarmupRoutingRedisAndFailOpen(t *testing.T) {
	mr := miniredis.RunT(t)
	redisFabric := storage.NewRedisFabric(mr.Addr(), "", 0)

	semCfg := config.SemanticRouterConfig{
		Enabled:             true,
		EmbeddingModel:      "text-embedding-3-small",
		SimilarityThreshold: 0.75,
		Timeout:             100 * time.Millisecond,
		Routes: []config.SemanticRouteConfig{
			{
				Name:        "coding",
				TargetModel: "coding-group",
				Utterances:  []string{"write python code", "debug go goroutine"},
			},
			{
				Name:        "billing",
				TargetModel: "support-group",
				Utterances:  []string{"refund invoice", "update credit card"},
			},
		},
	}

	// Deterministic 3D vector embedder:
	// - coding utterances/queries -> near [1, 0, 0]
	// - billing utterances/queries -> near [0, 1, 0]
	// - unrelated queries -> [0, 0, 1] (cosine sim = 0.0 < 0.75)
	var batchCalls atomic.Int32
	embedFn := func(_ context.Context, _ string, _ string, inputs []string) ([][]float32, error) {
		if len(inputs) > 1 {
			batchCalls.Add(1)
		}
		out := make([][]float32, len(inputs))
		for i, text := range inputs {
			lower := strings.ToLower(text)
			switch {
			case strings.Contains(lower, "python") || strings.Contains(lower, "goroutine") || strings.Contains(lower, "golang") || strings.Contains(lower, "code"):
				out[i] = []float32{3.0, 0.3, 0.0} // unnormalized intentionally to test L2 normalization
			case strings.Contains(lower, "refund") || strings.Contains(lower, "credit") || strings.Contains(lower, "invoice"):
				out[i] = []float32{0.0, 4.0, 0.2}
			default:
				out[i] = []float32{0.0, 0.0, 2.0}
			}
		}
		return out, nil
	}

	ctx := context.Background()
	sr := router.NewSemanticPreRouter(semCfg, "fast-default", embedFn, redisFabric)
	if sr.Name() != "semantic" {
		t.Fatalf("Name() = %q, want semantic", sr.Name())
	}
	if err := sr.Warmup(ctx, "org-1"); err != nil {
		t.Fatalf("Warmup failed: %v", err)
	}
	if batchCalls.Load() != 1 {
		t.Fatalf("expected exactly 1 batch embed call during Warmup, got %d", batchCalls.Load())
	}

	// Verify Redis persistence at gw:router:semantic:{org:<orgID>}:centroids with normalized vectors.
	redisKey := router.SemanticCentroidsRedisKey("org-1")
	if redisKey != "gw:router:semantic:{org:org-1}:centroids" {
		t.Fatalf("unexpected redis key %q", redisKey)
	}
	rawRedis, err := mr.Get(redisKey)
	if err != nil || rawRedis == "" {
		t.Fatalf("expected semantic centroids in Redis at %q, err=%v", redisKey, err)
	}
	var persisted []struct {
		Name        string      `json:"name"`
		TargetAlias string      `json:"target_alias"`
		Centroid    []float32   `json:"centroid"`
		Utterances  [][]float32 `json:"utterances"`
	}
	if err := json.Unmarshal([]byte(rawRedis), &persisted); err != nil {
		t.Fatalf("unmarshal Redis centroids: %v", err)
	}
	if len(persisted) != 2 || len(persisted[0].Centroid) != 3 {
		t.Fatalf("unexpected persisted Redis centroids: %+v", persisted)
	}

	// Route extracts latest user message in multi-turn chat and picks highest-scoring target.
	alias, reason, score, err := sr.Route(ctx, "org-1", &domain.CanonicalChatRequest{
		Model: "router/semantic",
		Messages: []domain.CanonicalMessage{
			{Role: "user", Content: "Can I get a refund on my invoice?"},
			{Role: "assistant", Content: "Sure, anything else?"},
			{Role: "user", Content: "Help me debug a golang race condition"},
		},
	})
	if err != nil {
		t.Fatalf("Route unexpected error: %v", err)
	}
	if alias != "coding-group" || score < 0.90 || !strings.HasPrefix(reason, "semantic:route:coding") {
		t.Fatalf("got alias=%q reason=%q score=%.3f, want coding-group", alias, reason, score)
	}

	// Cross-pod Redis hydration: a fresh SemanticPreRouter without local Warmup loads from Redis.
	srReplica := router.NewSemanticPreRouter(semCfg, "fast-default", embedFn, redisFabric)
	alias2, _, score2, err := srReplica.Route(ctx, "org-1", &domain.CanonicalChatRequest{
		Model:    "router/semantic",
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "Please refund my invoice"}},
	})
	if err != nil || alias2 != "support-group" || score2 < 0.90 {
		t.Fatalf("cross-pod hydrated Route got alias=%q score=%.3f err=%v, want support-group", alias2, score2, err)
	}

	// Below threshold -> fails open to DefaultAlias.
	aliasMiss, reasonMiss, scoreMiss, err := sr.Route(ctx, "org-1", &domain.CanonicalChatRequest{
		Model:    "router/semantic",
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "What is the weather in Tokyo?"}},
	})
	if err != nil || aliasMiss != "fast-default" || reasonMiss != "semantic:below_threshold" || scoreMiss >= 0.75 {
		t.Fatalf("below threshold got alias=%q reason=%q score=%.3f err=%v", aliasMiss, reasonMiss, scoreMiss, err)
	}

	// Empty query -> fails open without error.
	aliasEmpty, reasonEmpty, _, err := sr.Route(ctx, "org-1", &domain.CanonicalChatRequest{
		Model:    "router/semantic",
		Messages: []domain.CanonicalMessage{{Role: "system", Content: "You are helpful."}},
	})
	if err != nil || aliasEmpty != "fast-default" || reasonEmpty != "semantic:empty_query" {
		t.Fatalf("empty query got alias=%q reason=%q err=%v", aliasEmpty, reasonEmpty, err)
	}

	// Embed timeout -> strict timeout triggers and fails open cleanly.
	slowCfg := semCfg
	slowCfg.Timeout = 20 * time.Millisecond
	slowSR := router.NewSemanticPreRouter(slowCfg, "fast-default", func(c context.Context, _ string, _ string, inputs []string) ([][]float32, error) {
		if len(inputs) > 1 {
			return embedFn(c, "org-1", "", inputs)
		}
		<-c.Done()
		return nil, c.Err()
	}, nil)
	_ = slowSR.Warmup(ctx, "org-1")
	start := time.Now()
	aliasTimeout, reasonTimeout, _, err := slowSR.Route(ctx, "org-1", &domain.CanonicalChatRequest{
		Model:    "router/semantic",
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "Help me write python"}},
	})
	if err != nil || aliasTimeout != "fast-default" || reasonTimeout != "semantic:embed_fallback" {
		t.Fatalf("timeout got alias=%q reason=%q err=%v", aliasTimeout, reasonTimeout, err)
	}
	if elapsed := time.Since(start); elapsed > 200*time.Millisecond {
		t.Fatalf("timeout took too long: %v", elapsed)
	}

	// Embed error -> fails open cleanly.
	errSR := router.NewSemanticPreRouter(semCfg, "fast-default", func(_ context.Context, _ string, _ string, inputs []string) ([][]float32, error) {
		if len(inputs) > 1 {
			return embedFn(ctx, "org-1", "", inputs)
		}
		return nil, errors.New("upstream 503")
	}, nil)
	_ = errSR.Warmup(ctx, "org-1")
	aliasErr, reasonErr, _, err := errSR.Route(ctx, "org-1", &domain.CanonicalChatRequest{
		Model:    "router/semantic",
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "Help me write python"}},
	})
	if err != nil || aliasErr != "fast-default" || reasonErr != "semantic:embed_fallback" {
		t.Fatalf("embed error got alias=%q reason=%q err=%v", aliasErr, reasonErr, err)
	}

	// Concurrent Route + Warmup under -race.
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			if idx%4 == 0 {
				_ = sr.Warmup(ctx, "org-1")
			}
			a, _, _, rErr := sr.Route(ctx, "org-1", &domain.CanonicalChatRequest{
				Model:    "router/semantic",
				Messages: []domain.CanonicalMessage{{Role: "user", Content: "write python code"}},
			})
			if rErr != nil || a != "coding-group" {
				t.Errorf("concurrent Route got alias=%q err=%v", a, rErr)
			}
		}(i)
	}
	wg.Wait()
}

func TestPreRouterQualityTierSelectionAndCacheAwareMode(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	org := &domain.Organization{Name: "QualOrg", Slug: "qual-org", IsActive: true}
	if err := repo.CreateOrganization(ctx, org); err != nil {
		t.Fatalf("CreateOrganization: %v", err)
	}

	// Seed models across tiers (leaving QualityTier=0 on some to verify catalog inference!).
	economyModel := &domain.GlobalModel{
		ID:                    "openai/gpt-4o-mini",
		Provider:              domain.ProviderOpenAI,
		ModelName:             "gpt-4o-mini",
		SupportsInference:     true,
		SupportsStreaming:     true,
		SupportsTools:         true,
		MaxInputTokens:        128000,
		InputCostMicrosPer1M:  150_000,
		OutputCostMicrosPer1M: 600_000, // total 750k -> Tier 1 inferred
		LifecycleStatus:       domain.ModelStatusActive,
	}
	standardModel := &domain.GlobalModel{
		ID:                    "openrouter/openai/gpt-4o-mini",
		Provider:              domain.ProviderOpenRouter,
		ModelName:             "openai/gpt-4o-mini",
		SupportsInference:     true,
		SupportsStreaming:     true,
		SupportsTools:         true,
		MaxInputTokens:        1000000,
		InputCostMicrosPer1M:  300_000,
		OutputCostMicrosPer1M: 2_500_000, // total 2.8M -> Tier 2 inferred
		LifecycleStatus:       domain.ModelStatusActive,
	}
	frontierCheapModel := &domain.GlobalModel{
		ID:                    "openai/gpt-4.1",
		Provider:              domain.ProviderOpenAI,
		ModelName:             "gpt-4.1",
		SupportsInference:     true,
		SupportsStreaming:     true,
		SupportsTools:         true,
		MaxInputTokens:        1000000,
		InputCostMicrosPer1M:  2_000_000,
		OutputCostMicrosPer1M: 8_000_000, // total 10M -> Tier 3 inferred
		QualityTier:           catalog.QualityTierFrontier,
		LifecycleStatus:       domain.ModelStatusActive,
	}
	frontierExpensiveModel := &domain.GlobalModel{
		ID:                    "anthropic/claude-opus-3",
		Provider:              domain.ProviderAnthropic,
		ModelName:             "claude-opus-3",
		SupportsInference:     true,
		SupportsStreaming:     true,
		SupportsTools:         true,
		MaxInputTokens:        200000,
		InputCostMicrosPer1M:  15_000_000,
		OutputCostMicrosPer1M: 75_000_000, // total 90M -> Tier 3
		QualityTier:           catalog.QualityTierFrontier,
		LifecycleStatus:       domain.ModelStatusActive,
	}
	reasoningCheapModel := &domain.GlobalModel{
		ID:                    "openai/o3-mini",
		Provider:              domain.ProviderOpenAI,
		ModelName:             "o3-mini",
		SupportsInference:     true,
		SupportsReasoning:     true,
		SupportsTools:         true,
		MaxInputTokens:        200000,
		InputCostMicrosPer1M:  1_100_000,
		OutputCostMicrosPer1M: 4_400_000, // total 5.5M -> Tier 4 inferred
		LifecycleStatus:       domain.ModelStatusActive,
	}
	reasoningExpensiveModel := &domain.GlobalModel{
		ID:                    "openai/o1",
		Provider:              domain.ProviderOpenAI,
		ModelName:             "o1",
		SupportsInference:     true,
		SupportsReasoning:     true,
		MaxInputTokens:        200000,
		InputCostMicrosPer1M:  15_000_000,
		OutputCostMicrosPer1M: 60_000_000, // total 75M -> Tier 4 inferred
		LifecycleStatus:       domain.ModelStatusActive,
	}
	// Disabled / cheap trap model that must NOT be selected.
	disabledCheapModel := &domain.GlobalModel{
		ID:                    "openai/o3-disabled",
		Provider:              domain.ProviderOpenAI,
		ModelName:             "o3-disabled",
		SupportsInference:     true,
		QualityTier:           catalog.QualityTierReasoning,
		InputCostMicrosPer1M:  10,
		OutputCostMicrosPer1M: 10,
		LifecycleStatus:       domain.ModelStatusActive,
	}

	for _, gm := range []*domain.GlobalModel{
		economyModel, standardModel, frontierCheapModel, frontierExpensiveModel,
		reasoningCheapModel, reasoningExpensiveModel, disabledCheapModel,
	} {
		if err := repo.UpsertGlobalModel(ctx, gm); err != nil {
			t.Fatalf("UpsertGlobalModel(%s): %v", gm.ID, err)
		}
	}

	addGroup := func(alias string, active bool, depStatus domain.DeploymentStatus, gmID string) {
		mg := &domain.ModelGroup{
			OrgID:           org.ID,
			Alias:           alias,
			RoutingStrategy: domain.StrategyWeightedShuffle,
			IsActive:        active,
		}
		if err := repo.CreateModelGroup(ctx, mg); err != nil {
			t.Fatalf("CreateModelGroup(%s): %v", alias, err)
		}
		if err := repo.CreateDeployment(ctx, &domain.Deployment{
			ModelGroupID:   mg.ID,
			GlobalModelID:  gmID,
			DeploymentName: alias + "-dep",
			Status:         depStatus,
		}); err != nil {
			t.Fatalf("CreateDeployment(%s): %v", alias, err)
		}
	}

	addGroup("economy-fast", true, domain.DeploymentStatusActive, economyModel.ID)
	addGroup("standard-chat", true, domain.DeploymentStatusActive, standardModel.ID)
	addGroup("frontier-opus", true, domain.DeploymentStatusActive, frontierExpensiveModel.ID)
	addGroup("frontier-gpt41", true, domain.DeploymentStatusActive, frontierCheapModel.ID)
	addGroup("reasoning-o1", true, domain.DeploymentStatusActive, reasoningExpensiveModel.ID)
	addGroup("reasoning-o3-mini", true, domain.DeploymentStatusActive, reasoningCheapModel.ID)
	addGroup("inactive-group", false, domain.DeploymentStatusActive, disabledCheapModel.ID)
	addGroup("cooldown-group", true, domain.DeploymentStatusCooldown, disabledCheapModel.ID)

	cfg := config.Default().Router
	qr := router.NewQualityPreRouter(repo, cfg, nil)
	if qr.Name() != "quality" {
		t.Fatalf("Name() = %q, want quality", qr.Name())
	}

	// 1. Short/simple -> Tier 1 -> picks cheapest overall ("economy-fast").
	alias, reason, _, err := qr.Route(ctx, org.ID, &domain.CanonicalChatRequest{
		Model:    "router/quality",
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "Hi!"}},
	})
	if err != nil || alias != "economy-fast" {
		t.Fatalf("tier 1 simple got alias=%q reason=%q err=%v, want economy-fast", alias, reason, err)
	}

	// 2. Standard multi-turn -> Tier 2 -> excludes tier 1 economy, picks cheapest tier >= 2 ("standard-chat").
	alias, reason, _, err = qr.Route(ctx, org.ID, &domain.CanonicalChatRequest{
		Model: "router/quality",
		Messages: []domain.CanonicalMessage{
			{Role: "user", Content: "Tell me about cloud networking"},
			{Role: "assistant", Content: "Sure, what aspect?"},
			{Role: "user", Content: "Explain VPC peering briefly."},
		},
	})
	if err != nil || alias != "standard-chat" {
		t.Fatalf("tier 2 standard got alias=%q reason=%q err=%v, want standard-chat", alias, reason, err)
	}

	// 3. Code / tools -> Tier 3 -> selects cheapest eligible tier >= 3.
	// Note: reasoning-o3-mini (tier 4, 5.5M) is cheaper than frontier-gpt41 (tier 3, 10M) and frontier-opus (90M)
	// and meets EffectiveQualityTier >= 3!
	alias, reason, _, err = qr.Route(ctx, org.ID, &domain.CanonicalChatRequest{
		Model:    "router/quality",
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "Call the weather tool"}},
		Tools:    []domain.CanonicalTool{{Type: "function"}},
	})
	if err != nil || alias != "reasoning-o3-mini" {
		t.Fatalf("tier 3 tools got alias=%q reason=%q err=%v, want reasoning-o3-mini", alias, reason, err)
	}

	// 4. Reasoning keyword / ReasoningEffort -> Tier 4 -> selects cheapest tier 4 ("reasoning-o3-mini", NOT "reasoning-o1").
	alias, reason, _, err = qr.Route(ctx, org.ID, &domain.CanonicalChatRequest{
		Model:           "router/quality",
		ReasoningEffort: "high",
		Messages:        []domain.CanonicalMessage{{Role: "user", Content: "Derive the bound"}},
	})
	if err != nil || alias != "reasoning-o3-mini" {
		t.Fatalf("tier 4 reasoning got alias=%q reason=%q err=%v, want reasoning-o3-mini", alias, reason, err)
	}

	// 5. Cache-aware mode short-circuits BEFORE escalating to Tier 4 reasoning!
	cacheCfg := cfg
	cacheCfg.CacheAwareRouting = true
	var cacheChecks atomic.Int32
	cacheQR := router.NewQualityPreRouter(repo, cacheCfg, func(_ context.Context, gotOrg string, _ *domain.CanonicalChatRequest) (string, bool) {
		cacheChecks.Add(1)
		if gotOrg == org.ID {
			return "economy-fast", true
		}
		return "", false
	})
	aliasCached, reasonCached, _, err := cacheQR.Route(ctx, org.ID, &domain.CanonicalChatRequest{
		Model:           "router/quality",
		ReasoningEffort: "high",
		Messages:        []domain.CanonicalMessage{{Role: "user", Content: "Use reasoning to prove Fermat's theorem"}},
	})
	if err != nil || aliasCached != "economy-fast" || reasonCached != "quality:cache_hit" || cacheChecks.Load() != 1 {
		t.Fatalf("cache-aware mode got alias=%q reason=%q checks=%d err=%v, want economy-fast", aliasCached, reasonCached, cacheChecks.Load(), err)
	}

	// When CacheAwareRouting is false, CacheHitCheckFn must not be consulted.
	noCacheCfg := cfg
	noCacheCfg.CacheAwareRouting = false
	var skippedChecks atomic.Int32
	noCacheQR := router.NewQualityPreRouter(repo, noCacheCfg, func(_ context.Context, _ string, _ *domain.CanonicalChatRequest) (string, bool) {
		skippedChecks.Add(1)
		return "economy-fast", true
	})
	aliasNoCache, _, _, err := noCacheQR.Route(ctx, org.ID, &domain.CanonicalChatRequest{
		Model:    "router/quality",
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "Apply reasoning to prove this"}},
	})
	if err != nil || aliasNoCache != "reasoning-o3-mini" || skippedChecks.Load() != 0 {
		t.Fatalf("disabled cache-aware mode got alias=%q skippedChecks=%d err=%v", aliasNoCache, skippedChecks.Load(), err)
	}
}

func TestPreRouterQualityTierFallbackAndCapabilityFiltering(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	org := &domain.Organization{Name: "QualFallback", Slug: "qual-fb", IsActive: true}
	_ = repo.CreateOrganization(ctx, org)

	// Only a Tier 1 model that does NOT support tools, and a Tier 2 model that supports tools.
	noToolsEco := &domain.GlobalModel{
		ID:                    "custom/eco-notools",
		Provider:              domain.ProviderOpenAI,
		ModelName:             "eco-notools",
		SupportsInference:     true,
		QualityTier:           catalog.QualityTierEconomy,
		InputCostMicrosPer1M:  50_000,
		OutputCostMicrosPer1M: 100_000,
		Capabilities: domain.ModelCapabilities{
			Tools: domain.CapabilityUnsupported,
		},
		LifecycleStatus: domain.ModelStatusActive,
	}
	toolsStd := &domain.GlobalModel{
		ID:                    "custom/std-tools",
		Provider:              domain.ProviderOpenAI,
		ModelName:             "std-tools",
		SupportsInference:     true,
		QualityTier:           catalog.QualityTierStandard,
		InputCostMicrosPer1M:  500_000,
		OutputCostMicrosPer1M: 1_500_000,
		Capabilities: domain.ModelCapabilities{
			Tools: domain.CapabilitySupported,
		},
		LifecycleStatus: domain.ModelStatusActive,
	}
	_ = repo.UpsertGlobalModel(ctx, noToolsEco)
	_ = repo.UpsertGlobalModel(ctx, toolsStd)

	g1 := &domain.ModelGroup{OrgID: org.ID, Alias: "eco-only", RoutingStrategy: domain.StrategyWeightedShuffle, IsActive: true}
	g2 := &domain.ModelGroup{OrgID: org.ID, Alias: "std-tools", RoutingStrategy: domain.StrategyWeightedShuffle, IsActive: true}
	_ = repo.CreateModelGroup(ctx, g1)
	_ = repo.CreateModelGroup(ctx, g2)
	_ = repo.CreateDeployment(ctx, &domain.Deployment{ModelGroupID: g1.ID, GlobalModelID: noToolsEco.ID, DeploymentName: "d1", Status: domain.DeploymentStatusActive})
	_ = repo.CreateDeployment(ctx, &domain.Deployment{ModelGroupID: g2.ID, GlobalModelID: toolsStd.ID, DeploymentName: "d2", Status: domain.DeploymentStatusActive})

	qr := router.NewQualityPreRouter(repo, config.Default().Router, nil)

	// Request requires Tier 3 (tools) and Tier 4 (reasoning_effort); no Tier 3/4 exists,
	// so it must gracefully degrade to the highest available eligible tier ("std-tools", Tier 2),
	// skipping "eco-only" because Tools is CapabilityUnsupported.
	alias, reason, _, err := qr.Route(ctx, org.ID, &domain.CanonicalChatRequest{
		Model:           "router/quality",
		ReasoningEffort: "medium",
		Tools:           []domain.CanonicalTool{{Type: "function"}},
		Messages:        []domain.CanonicalMessage{{Role: "user", Content: "Run tool"}},
	})
	if err != nil {
		t.Fatalf("Route failed: %v", err)
	}
	if alias != "std-tools" || !strings.Contains(reason, "best_available_tier_2") {
		t.Fatalf("got alias=%q reason=%q, want std-tools with best_available_tier_2", alias, reason)
	}
}
