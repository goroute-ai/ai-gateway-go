package router

import (
	"context"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/adapter"
	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

func TestPartitionByPriority(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		if tiers := partitionByPriority(nil); len(tiers) != 0 {
			t.Fatalf("expected 0 tiers for nil, got %d", len(tiers))
		}
		if tiers := partitionByPriority([]*domain.Deployment{}); len(tiers) != 0 {
			t.Fatalf("expected 0 tiers for empty slice, got %d", len(tiers))
		}
	})

	t.Run("single", func(t *testing.T) {
		d := &domain.Deployment{ID: "only", Priority: 2}
		tiers := partitionByPriority([]*domain.Deployment{d})
		if len(tiers) != 1 || len(tiers[0]) != 1 || tiers[0][0].ID != "only" {
			t.Fatalf("unexpected single deployment tiers: %+v", tiers)
		}
	})

	t.Run("uniform_and_negative_zero_normalization", func(t *testing.T) {
		deps := []*domain.Deployment{
			{ID: "a", Priority: -3},
			{ID: "b", Priority: 0},
			{ID: "c", Priority: -1},
		}
		tiers := partitionByPriority(deps)
		if len(tiers) != 1 {
			t.Fatalf("expected 1 tier for normalized uniform priority, got %d", len(tiers))
		}
		if len(tiers[0]) != 3 || tiers[0][0].ID != "a" || tiers[0][1].ID != "b" || tiers[0][2].ID != "c" {
			t.Fatalf("unexpected order in uniform tier: %+v", tiers[0])
		}

		samePos := []*domain.Deployment{
			{ID: "x", Priority: 5},
			{ID: "y", Priority: 5},
		}
		tiersPos := partitionByPriority(samePos)
		if len(tiersPos) != 1 || tiersPos[0][0].ID != "x" || tiersPos[0][1].ID != "y" {
			t.Fatalf("expected 1 tier for uniform positive priority, got %+v", tiersPos)
		}
	})

	t.Run("zero_alloc_fast_path", func(t *testing.T) {
		var empty []*domain.Deployment
		single := []*domain.Deployment{{ID: "s", Priority: 1}}
		uniform := []*domain.Deployment{
			{ID: "u1", Priority: -2},
			{ID: "u2", Priority: 0},
			{ID: "u3", Priority: 0},
		}

		if allocs := testing.AllocsPerRun(100, func() {
			tiers := partitionByPriority(empty)
			if len(tiers) != 0 {
				t.Fatalf("unexpected len %d", len(tiers))
			}
		}); allocs != 0 {
			t.Fatalf("expected 0 allocs for empty fast-path, got %v", allocs)
		}

		if allocs := testing.AllocsPerRun(100, func() {
			tiers := partitionByPriority(single)
			if len(tiers) != 1 {
				t.Fatalf("unexpected len %d", len(tiers))
			}
		}); allocs != 0 {
			t.Fatalf("expected 0 allocs for single fast-path, got %v", allocs)
		}

		if allocs := testing.AllocsPerRun(100, func() {
			tiers := partitionByPriority(uniform)
			if len(tiers) != 1 {
				t.Fatalf("unexpected len %d", len(tiers))
			}
		}); allocs != 0 {
			t.Fatalf("expected 0 allocs for uniform fast-path, got %v", allocs)
		}
	})

	t.Run("multi_tier_ordering_and_intra_tier_order", func(t *testing.T) {
		deps := []*domain.Deployment{
			{ID: "p2-a", Priority: 2},
			{ID: "p0-neg", Priority: -10},
			{ID: "p1-a", Priority: 1},
			{ID: "p2-b", Priority: 2},
			{ID: "p0-zero", Priority: 0},
			{ID: "p1-b", Priority: 1},
			{ID: "p5-a", Priority: 5},
		}
		tiers := partitionByPriority(deps)
		if len(tiers) != 4 {
			t.Fatalf("expected 4 tiers, got %d", len(tiers))
		}
		want := [][]string{
			{"p0-neg", "p0-zero"},
			{"p1-a", "p1-b"},
			{"p2-a", "p2-b"},
			{"p5-a"},
		}
		for ti, wantIDs := range want {
			if len(tiers[ti]) != len(wantIDs) {
				t.Fatalf("tier %d len = %d, want %d", ti, len(tiers[ti]), len(wantIDs))
			}
			for di, wantID := range wantIDs {
				if tiers[ti][di].ID != wantID {
					t.Fatalf("tier[%d][%d] = %s, want %s", ti, di, tiers[ti][di].ID, wantID)
				}
			}
		}
	})
}

type priorityTierTestAdapter struct {
	provider domain.ProviderType

	mu    sync.Mutex
	calls []string

	behavior func(depID string) error
}

func (a *priorityTierTestAdapter) record(depID string) {
	a.mu.Lock()
	a.calls = append(a.calls, depID)
	a.mu.Unlock()
}

func (a *priorityTierTestAdapter) recordedCalls() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]string, len(a.calls))
	copy(out, a.calls)
	return out
}

func (a *priorityTierTestAdapter) resetCalls() {
	a.mu.Lock()
	a.calls = nil
	a.mu.Unlock()
}

func (a *priorityTierTestAdapter) checkErr(dep *domain.Deployment) error {
	a.record(dep.ID)
	if a.behavior != nil {
		return a.behavior(dep.ID)
	}
	return nil
}

func (a *priorityTierTestAdapter) Provider() domain.ProviderType { return a.provider }

func (a *priorityTierTestAdapter) ChatCompletion(_ context.Context, dep *domain.Deployment, _ *domain.CanonicalChatRequest) (*domain.CanonicalChatResponse, error) {
	if err := a.checkErr(dep); err != nil {
		return nil, err
	}
	return &domain.CanonicalChatResponse{
		ID:       "chat-" + dep.ID,
		Provider: a.provider,
		Choices:  []domain.CanonicalChoice{{Message: domain.CanonicalMessage{Role: "assistant", Content: dep.ID}}},
		Usage:    domain.TokenUsage{TotalTokens: 10},
	}, nil
}

func (a *priorityTierTestAdapter) StreamChatCompletion(_ context.Context, dep *domain.Deployment, _ *domain.CanonicalChatRequest, onChunk adapter.StreamChunkHandler) (*domain.TokenUsage, error) {
	if err := a.checkErr(dep); err != nil {
		return nil, err
	}
	if err := onChunk(&domain.CanonicalStreamChunk{ID: "chunk-" + dep.ID}); err != nil {
		return nil, err
	}
	return &domain.TokenUsage{TotalTokens: 8}, nil
}

func (a *priorityTierTestAdapter) Embeddings(_ context.Context, dep *domain.Deployment, _ *domain.CanonicalEmbeddingRequest) (*domain.CanonicalEmbeddingResponse, error) {
	if err := a.checkErr(dep); err != nil {
		return nil, err
	}
	return &domain.CanonicalEmbeddingResponse{
		Model: dep.GlobalModel.ModelName,
		Data:  []domain.EmbeddingData{{Index: 0, Embedding: []float64{0.1, 0.2}}},
		Usage: domain.TokenUsage{TotalTokens: 4},
	}, nil
}

func (a *priorityTierTestAdapter) TextCompletion(_ context.Context, dep *domain.Deployment, _ *domain.CanonicalCompletionRequest) (*domain.CanonicalCompletionResponse, error) {
	if err := a.checkErr(dep); err != nil {
		return nil, err
	}
	return &domain.CanonicalCompletionResponse{
		ID:       "comp-" + dep.ID,
		Provider: a.provider,
		Choices:  []domain.CanonicalCompletionChoice{{Index: 0, Text: dep.ID}},
		Usage:    domain.TokenUsage{TotalTokens: 6},
	}, nil
}

func (a *priorityTierTestAdapter) StreamTextCompletion(_ context.Context, dep *domain.Deployment, _ *domain.CanonicalCompletionRequest) (<-chan domain.CanonicalStreamChunk, error) {
	if err := a.checkErr(dep); err != nil {
		return nil, err
	}
	ch := make(chan domain.CanonicalStreamChunk, 1)
	ch <- domain.CanonicalStreamChunk{ID: "cstream-" + dep.ID}
	close(ch)
	return ch, nil
}

func (a *priorityTierTestAdapter) Rerank(_ context.Context, dep *domain.Deployment, _ *domain.CanonicalRerankRequest) (*domain.CanonicalRerankResponse, error) {
	if err := a.checkErr(dep); err != nil {
		return nil, err
	}
	return &domain.CanonicalRerankResponse{ID: "rerank-" + dep.ID, Usage: domain.RerankUsage{TotalTokens: 3}}, nil
}

func (a *priorityTierTestAdapter) Moderate(_ context.Context, dep *domain.Deployment, _ *domain.CanonicalModerationRequest) (*domain.CanonicalModerationResponse, error) {
	if err := a.checkErr(dep); err != nil {
		return nil, err
	}
	return &domain.CanonicalModerationResponse{ID: "mod-" + dep.ID}, nil
}

func (a *priorityTierTestAdapter) TranscribeAudio(_ context.Context, dep *domain.Deployment, _ *domain.CanonicalAudioTranscriptionRequest) (*domain.CanonicalAudioResponse, error) {
	if err := a.checkErr(dep); err != nil {
		return nil, err
	}
	return &domain.CanonicalAudioResponse{Text: dep.ID}, nil
}

func (a *priorityTierTestAdapter) GenerateSpeech(_ context.Context, dep *domain.Deployment, _ *domain.CanonicalAudioSpeechRequest) (io.ReadCloser, string, error) {
	if err := a.checkErr(dep); err != nil {
		return nil, "", err
	}
	return io.NopCloser(strings.NewReader(dep.ID)), "audio/mpeg", nil
}

func (a *priorityTierTestAdapter) GenerateImage(_ context.Context, dep *domain.Deployment, _ *domain.CanonicalImageRequest) (*domain.CanonicalImageResponse, error) {
	if err := a.checkErr(dep); err != nil {
		return nil, err
	}
	return &domain.CanonicalImageResponse{Data: []domain.ImageItem{{URL: "https://example.com/" + dep.ID}}}, nil
}

func (a *priorityTierTestAdapter) ListModels(context.Context, *domain.ProviderCredential) ([]domain.DiscoveredModel, error) {
	return nil, nil
}

type priorityTierFixture struct {
	org     *domain.Organization
	repo    *storage.MemoryRepository
	rm      *ReliabilityManager
	adp     *priorityTierTestAdapter
	primary *domain.ModelGroup
	fbGroup *domain.ModelGroup
	tier0A  *domain.Deployment
	tier0B  *domain.Deployment
	tier1A  *domain.Deployment
	fbDep   *domain.Deployment
}

func setupPriorityTierFixture(t *testing.T, maxRetries, failureThreshold int, behavior func(depID string) error) *priorityTierFixture {
	t.Helper()
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	vault, err := auth.NewVault("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	rbac := auth.NewRBACEngine(repo)

	org := &domain.Organization{Name: "TierOrg", Slug: "tier-org", IsActive: true}
	if err := repo.CreateOrganization(ctx, org); err != nil {
		t.Fatal(err)
	}

	cred := &domain.ProviderCredential{
		OrgID:    org.ID,
		Provider: domain.ProviderOpenAI,
		Name:     "tier-cred",
		BaseURL:  "https://api.example.com",
		IsActive: true,
	}
	if err := vault.EncryptCredential(cred, "sk-tier"); err != nil {
		t.Fatal(err)
	}
	if err := repo.CreateProviderCredential(ctx, cred); err != nil {
		t.Fatal(err)
	}

	gm := &domain.GlobalModel{
		ID:                "openai/tier-universal",
		Provider:          domain.ProviderOpenAI,
		ModelName:         "tier-universal",
		DisplayName:       "Tier Universal",
		SupportsInference: true,
		LifecycleStatus:   domain.ModelStatusActive,
		PricingStatus:     domain.PricingStatusVerified,
		Capabilities: domain.ModelCapabilities{
			Streaming:  domain.CapabilitySupported,
			Embeddings: domain.CapabilitySupported,
			Rerank:     domain.CapabilitySupported,
			Moderation: domain.CapabilitySupported,
			ImageGen:   domain.CapabilitySupported,
			AudioSTT:   domain.CapabilitySupported,
			AudioTTS:   domain.CapabilitySupported,
		},
	}
	if err := repo.UpsertGlobalModel(ctx, gm); err != nil {
		t.Fatal(err)
	}

	fbGroup := &domain.ModelGroup{
		OrgID:           org.ID,
		Alias:           "tier-fallback-group",
		RoutingStrategy: domain.StrategyLeastBusy,
		MaxRetries:      0,
		IsActive:        true,
	}
	if err := repo.CreateModelGroup(ctx, fbGroup); err != nil {
		t.Fatal(err)
	}
	fbDep := &domain.Deployment{
		ModelGroupID:   fbGroup.ID,
		GlobalModelID:  gm.ID,
		CredentialID:   cred.ID,
		DeploymentName: "fb-dep",
		Priority:       0,
		Weight:         100,
		Status:         domain.DeploymentStatusActive,
	}
	if err := repo.CreateDeployment(ctx, fbDep); err != nil {
		t.Fatal(err)
	}

	primary := &domain.ModelGroup{
		OrgID:            org.ID,
		Alias:            "tier-primary-group",
		RoutingStrategy:  domain.StrategyLeastBusy,
		FallbackGroupIDs: []string{fbGroup.ID},
		MaxRetries:       maxRetries,
		FailureThreshold: failureThreshold,
		CooldownSeconds:  30,
		IsActive:         true,
	}
	if err := repo.CreateModelGroup(ctx, primary); err != nil {
		t.Fatal(err)
	}

	tier0A := &domain.Deployment{
		ModelGroupID:   primary.ID,
		GlobalModelID:  gm.ID,
		CredentialID:   cred.ID,
		DeploymentName: "tier0-a",
		Priority:       0,
		Weight:         100,
		Status:         domain.DeploymentStatusActive,
	}
	tier0B := &domain.Deployment{
		ModelGroupID:   primary.ID,
		GlobalModelID:  gm.ID,
		CredentialID:   cred.ID,
		DeploymentName: "tier0-b",
		Priority:       -1, // normalizes to 0
		Weight:         100,
		Status:         domain.DeploymentStatusActive,
	}
	tier1A := &domain.Deployment{
		ModelGroupID:   primary.ID,
		GlobalModelID:  gm.ID,
		CredentialID:   cred.ID,
		DeploymentName: "tier1-a",
		Priority:       1,
		Weight:         100,
		Status:         domain.DeploymentStatusActive,
	}
	for _, d := range []*domain.Deployment{tier0A, tier0B, tier1A} {
		if err := repo.CreateDeployment(ctx, d); err != nil {
			t.Fatal(err)
		}
	}

	adp := &priorityTierTestAdapter{
		provider: domain.ProviderOpenAI,
		behavior: behavior,
	}
	reg := adapter.NewRegistry()
	reg.Register(adp)

	rCfg := config.RouterConfig{
		DefaultMaxRetries: maxRetries,
		BaseRetryDelay:    1 * time.Millisecond,
		MaxRetryDelay:     2 * time.Millisecond,
		DefaultCooldown:   30 * time.Second,
		FailureWindow:     time.Minute,
		FailureThreshold:  failureThreshold,
	}
	rm := NewReliabilityManager(repo, reg, NewIntelligentRouter(repo, rCfg), NewLoadBalancer(), vault, rbac, nil, rCfg)

	return &priorityTierFixture{
		org:     org,
		repo:    repo,
		rm:      rm,
		adp:     adp,
		primary: primary,
		fbGroup: fbGroup,
		tier0A:  tier0A,
		tier0B:  tier0B,
		tier1A:  tier1A,
		fbDep:   fbDep,
	}
}

func TestPriorityTiers_HealthyTrafficStaysInTier0(t *testing.T) {
	ctx := context.Background()
	fx := setupPriorityTierFixture(t, 1, 3, nil)
	idCtx := &domain.IdentityContext{OrgID: fx.org.ID}

	for i := 0; i < 20; i++ {
		resp, meta, err := fx.rm.ExecuteChat(ctx, idCtx, &domain.CanonicalChatRequest{
			Model:    fx.primary.Alias,
			Messages: []domain.CanonicalMessage{{Role: "user", Content: "hello"}},
		})
		if err != nil {
			t.Fatalf("ExecuteChat[%d] failed: %v", i, err)
		}
		if resp == nil || meta.WinningDeployment == nil {
			t.Fatalf("missing response/winning deployment on call %d", i)
		}
		if meta.WinningDeployment.ID != fx.tier0A.ID && meta.WinningDeployment.ID != fx.tier0B.ID {
			t.Fatalf("call %d routed outside tier 0 to %s", i, meta.WinningDeployment.ID)
		}
		if meta.TierStepdowns != 0 || meta.FallbackReason != "" || meta.FallbackAttempted {
			t.Fatalf("expected no stepdown/fallback while tier 0 healthy, got meta=%+v", meta)
		}
	}

	for _, id := range fx.adp.recordedCalls() {
		if id == fx.tier1A.ID || id == fx.fbDep.ID {
			t.Fatalf("lower tier or fallback group %s should not receive traffic when tier 0 is healthy", id)
		}
	}
}

func TestPriorityTiers_ExhaustsIntraTierBeforeStepdownAndFallbackGroup(t *testing.T) {
	ctx := context.Background()
	var failTier0 atomic.Bool
	failTier0.Store(true)

	var fx *priorityTierFixture
	fx = setupPriorityTierFixture(t, 1, 1, func(depID string) error {
		if failTier0.Load() && (depID == fx.tier0A.ID || depID == fx.tier0B.ID) {
			return &domain.GatewayError{
				StatusCode: http.StatusBadGateway,
				Type:       domain.ErrorTypeUpstream,
				Code:       "upstream_502",
				Message:    "tier 0 unavailable",
				Retryable:  true,
			}
		}
		return nil
	})
	idCtx := &domain.IdentityContext{OrgID: fx.org.ID}

	// 1. First request tries BOTH tier 0 deployments (MaxRetries=1 -> 2 attempts),
	//    trips their circuit breakers (FailureThreshold=1), then steps down to Tier 1
	//    without touching FallbackGroupIDs.
	resp, meta, err := fx.rm.ExecuteChat(ctx, idCtx, &domain.CanonicalChatRequest{
		Model:    fx.primary.Alias,
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "stepdown"}},
	})
	if err != nil {
		t.Fatalf("ExecuteChat failed: %v", err)
	}
	if resp == nil || meta.WinningDeployment == nil || meta.WinningDeployment.ID != fx.tier1A.ID {
		t.Fatalf("expected winning deployment %s, got %+v", fx.tier1A.ID, meta.WinningDeployment)
	}
	if meta.TierStepdowns != 1 || meta.FallbackReason != "priority_tier_stepdown" {
		t.Fatalf("expected TierStepdowns=1 and FallbackReason=priority_tier_stepdown, got stepdowns=%d reason=%q", meta.TierStepdowns, meta.FallbackReason)
	}
	if meta.FallbackAttempted {
		t.Fatalf("expected FallbackAttempted=false when Tier 1 succeeded before FallbackGroupIDs")
	}
	if meta.RetryCount != 1 {
		t.Fatalf("expected 1 intra-tier retry in Tier 0 before stepdown, got %d", meta.RetryCount)
	}

	calls := fx.adp.recordedCalls()
	if len(calls) != 3 {
		t.Fatalf("expected 3 calls (tier0-a, tier0-b, tier1-a), got %v", calls)
	}
	if !slices.Contains(calls[:2], fx.tier0A.ID) || !slices.Contains(calls[:2], fx.tier0B.ID) || calls[2] != fx.tier1A.ID {
		t.Fatalf("expected both tier 0 candidates exhausted before tier 1, got call order %v", calls)
	}
	if slices.Contains(calls, fx.fbDep.ID) {
		t.Fatalf("fallback group deployment %s should not be called when tier 1 succeeds", fx.fbDep.ID)
	}
	if fx.rm.GetCircuitState(ctx, fx.tier0A.ID) != CircuitOpen || fx.rm.GetCircuitState(ctx, fx.tier0B.ID) != CircuitOpen {
		t.Fatalf("expected both tier 0 circuits to be OPEN")
	}

	// 2. Subsequent request skips circuit-broken Tier 0 and hits Tier 1 directly.
	fx.adp.resetCalls()
	resp2, meta2, err := fx.rm.ExecuteChat(ctx, idCtx, &domain.CanonicalChatRequest{
		Model:    fx.primary.Alias,
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "after-cb"}},
	})
	if err != nil {
		t.Fatalf("second ExecuteChat failed: %v", err)
	}
	if resp2 == nil || meta2.WinningDeployment == nil || meta2.WinningDeployment.ID != fx.tier1A.ID {
		t.Fatalf("expected tier1-a while tier 0 circuits open, got %+v", meta2.WinningDeployment)
	}
	if meta2.FallbackAttempted {
		t.Fatalf("expected FallbackAttempted=false")
	}
	if got := fx.adp.recordedCalls(); len(got) != 1 || got[0] != fx.tier1A.ID {
		t.Fatalf("expected single call to tier1-a, got %v", got)
	}
}

func TestPriorityTiers_StepsDownThenFallsBackToFallbackGroup(t *testing.T) {
	ctx := context.Background()
	var fx *priorityTierFixture
	fx = setupPriorityTierFixture(t, 0, 3, func(depID string) error {
		if depID == fx.tier0A.ID || depID == fx.tier0B.ID || depID == fx.tier1A.ID {
			return &domain.GatewayError{
				StatusCode: http.StatusServiceUnavailable,
				Type:       domain.ErrorTypeUpstream,
				Code:       "upstream_503",
				Message:    "primary group tiers unavailable",
				Retryable:  true,
			}
		}
		return nil
	})
	idCtx := &domain.IdentityContext{OrgID: fx.org.ID}

	resp, meta, err := fx.rm.ExecuteChat(ctx, idCtx, &domain.CanonicalChatRequest{
		Model:    fx.primary.Alias,
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "full-fallback"}},
	})
	if err != nil {
		t.Fatalf("ExecuteChat failed: %v", err)
	}
	if resp == nil || meta.WinningDeployment == nil || meta.WinningDeployment.ID != fx.fbDep.ID {
		t.Fatalf("expected fallback group dep %s, got %+v", fx.fbDep.ID, meta.WinningDeployment)
	}
	if meta.TierStepdowns != 1 || meta.FallbackReason != "priority_tier_stepdown" || !meta.FallbackAttempted {
		t.Fatalf("expected TierStepdowns=1, FallbackReason=priority_tier_stepdown, FallbackAttempted=true; got %+v", meta)
	}
}

func TestPriorityTiers_AbortsImmediatelyOnNonRetryableAndCancel(t *testing.T) {
	t.Run("non_retryable_400", func(t *testing.T) {
		ctx := context.Background()
		fx := setupPriorityTierFixture(t, 1, 2, func(string) error {
			return &domain.GatewayError{
				StatusCode: http.StatusBadRequest,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "invalid_request",
				Message:    "bad request payload",
				Retryable:  false,
			}
		})
		idCtx := &domain.IdentityContext{OrgID: fx.org.ID}

		_, meta, err := fx.rm.ExecuteChat(ctx, idCtx, &domain.CanonicalChatRequest{
			Model:    fx.primary.Alias,
			Messages: []domain.CanonicalMessage{{Role: "user", Content: "bad"}},
		})
		var gwErr *domain.GatewayError
		if !errors.As(err, &gwErr) || gwErr.StatusCode != http.StatusBadRequest {
			t.Fatalf("expected 400 GatewayError, got %v", err)
		}
		if meta.TierStepdowns != 0 || meta.FallbackReason != "" || meta.FallbackAttempted || meta.RetryCount != 0 {
			t.Fatalf("expected immediate abort without stepdown/retry/fallback, got %+v", meta)
		}
		if calls := fx.adp.recordedCalls(); len(calls) != 1 {
			t.Fatalf("expected exactly 1 call before abort, got %v", calls)
		}
	})

	t.Run("context_canceled", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		fx := setupPriorityTierFixture(t, 1, 2, func(string) error {
			cancel()
			return context.Canceled
		})
		idCtx := &domain.IdentityContext{OrgID: fx.org.ID}

		_, meta, err := fx.rm.ExecuteChat(ctx, idCtx, &domain.CanonicalChatRequest{
			Model:    fx.primary.Alias,
			Messages: []domain.CanonicalMessage{{Role: "user", Content: "cancel"}},
		})
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("expected context.Canceled, got %v", err)
		}
		if meta.TierStepdowns != 0 || meta.FallbackReason != "" || meta.FallbackAttempted {
			t.Fatalf("expected immediate abort on context.Canceled, got %+v", meta)
		}
		if calls := fx.adp.recordedCalls(); len(calls) != 1 {
			t.Fatalf("expected exactly 1 call before abort, got %v", calls)
		}
	})
}

func TestPriorityTiers_AllExecutionLoops(t *testing.T) {
	type execCase struct {
		name string
		run  func(ctx context.Context, rm *ReliabilityManager, idCtx *domain.IdentityContext, alias string) (*ExecutionMeta, error)
	}

	cases := []execCase{
		{
			name: "ExecuteChat",
			run: func(ctx context.Context, rm *ReliabilityManager, idCtx *domain.IdentityContext, alias string) (*ExecutionMeta, error) {
				_, meta, err := rm.ExecuteChat(ctx, idCtx, &domain.CanonicalChatRequest{
					Model:    alias,
					Messages: []domain.CanonicalMessage{{Role: "user", Content: "hi"}},
				})
				return meta, err
			},
		},
		{
			name: "ExecuteStream",
			run: func(ctx context.Context, rm *ReliabilityManager, idCtx *domain.IdentityContext, alias string) (*ExecutionMeta, error) {
				_, meta, err := rm.ExecuteStream(ctx, idCtx, &domain.CanonicalChatRequest{
					Model:    alias,
					Stream:   true,
					Messages: []domain.CanonicalMessage{{Role: "user", Content: "hi"}},
				}, func(*domain.CanonicalStreamChunk) error { return nil }, nil)
				return meta, err
			},
		},
		{
			name: "ExecuteEmbeddings",
			run: func(ctx context.Context, rm *ReliabilityManager, idCtx *domain.IdentityContext, alias string) (*ExecutionMeta, error) {
				_, meta, err := rm.ExecuteEmbeddings(ctx, idCtx, &domain.CanonicalEmbeddingRequest{
					Model: alias,
					Input: []string{"embed"},
				})
				return meta, err
			},
		},
		{
			name: "ExecuteCompletion",
			run: func(ctx context.Context, rm *ReliabilityManager, idCtx *domain.IdentityContext, alias string) (*ExecutionMeta, error) {
				_, meta, err := rm.ExecuteCompletion(ctx, idCtx, &domain.CanonicalCompletionRequest{
					Model:  alias,
					Prompt: domain.CompletionPrompt{Strings: []string{"complete"}},
				})
				return meta, err
			},
		},
		{
			name: "ExecuteCompletionStream",
			run: func(ctx context.Context, rm *ReliabilityManager, idCtx *domain.IdentityContext, alias string) (*ExecutionMeta, error) {
				ch, meta, err := rm.ExecuteCompletionStream(ctx, idCtx, &domain.CanonicalCompletionRequest{
					Model:  alias,
					Stream: true,
					Prompt: domain.CompletionPrompt{Strings: []string{"complete"}},
				})
				if ch != nil {
					for range ch {
					}
				}
				return meta, err
			},
		},
		{
			name: "ExecuteRerank",
			run: func(ctx context.Context, rm *ReliabilityManager, idCtx *domain.IdentityContext, alias string) (*ExecutionMeta, error) {
				_, meta, err := rm.ExecuteRerank(ctx, idCtx, &domain.CanonicalRerankRequest{
					Model:     alias,
					Query:     "q",
					Documents: []domain.RerankDocument{{Text: "doc"}},
				})
				return meta, err
			},
		},
		{
			name: "ExecuteModeration",
			run: func(ctx context.Context, rm *ReliabilityManager, idCtx *domain.IdentityContext, alias string) (*ExecutionMeta, error) {
				_, meta, err := rm.ExecuteModeration(ctx, idCtx, &domain.CanonicalModerationRequest{
					Model: alias,
					Input: []string{"check"},
				})
				return meta, err
			},
		},
		{
			name: "ExecuteAudioTranscription",
			run: func(ctx context.Context, rm *ReliabilityManager, idCtx *domain.IdentityContext, alias string) (*ExecutionMeta, error) {
				_, meta, err := rm.ExecuteAudioTranscription(ctx, idCtx, &domain.CanonicalAudioTranscriptionRequest{
					Model: alias,
				})
				return meta, err
			},
		},
		{
			name: "ExecuteAudioSpeech",
			run: func(ctx context.Context, rm *ReliabilityManager, idCtx *domain.IdentityContext, alias string) (*ExecutionMeta, error) {
				rc, _, meta, err := rm.ExecuteAudioSpeech(ctx, idCtx, &domain.CanonicalAudioSpeechRequest{
					Model: alias,
					Input: "say hi",
				})
				if rc != nil {
					_ = rc.Close()
				}
				return meta, err
			},
		},
		{
			name: "ExecuteImage",
			run: func(ctx context.Context, rm *ReliabilityManager, idCtx *domain.IdentityContext, alias string) (*ExecutionMeta, error) {
				_, meta, err := rm.ExecuteImage(ctx, idCtx, &domain.CanonicalImageRequest{
					Model:  alias,
					Prompt: "draw",
				})
				return meta, err
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name+"_stepdown", func(t *testing.T) {
			ctx := context.Background()
			var fx *priorityTierFixture
			fx = setupPriorityTierFixture(t, 0, 3, func(depID string) error {
				if depID == fx.tier0A.ID || depID == fx.tier0B.ID {
					return &domain.GatewayError{
						StatusCode: http.StatusServiceUnavailable,
						Type:       domain.ErrorTypeUpstream,
						Code:       "upstream_unavailable",
						Message:    "tier 0 down",
						Retryable:  true,
					}
				}
				return nil
			})
			idCtx := &domain.IdentityContext{OrgID: fx.org.ID}

			meta, err := tc.run(ctx, fx.rm, idCtx, fx.primary.Alias)
			if err != nil {
				t.Fatalf("%s stepdown failed: %v", tc.name, err)
			}
			if meta == nil || meta.WinningDeployment == nil || meta.WinningDeployment.ID != fx.tier1A.ID {
				t.Fatalf("%s expected winning deployment %s, got %+v", tc.name, fx.tier1A.ID, meta)
			}
			if meta.TierStepdowns != 1 || meta.FallbackReason != "priority_tier_stepdown" || meta.FallbackAttempted {
				t.Fatalf("%s unexpected meta: %+v", tc.name, meta)
			}
		})

		t.Run(tc.name+"_non_retryable_400_abort", func(t *testing.T) {
			ctx := context.Background()
			fx := setupPriorityTierFixture(t, 1, 2, func(string) error {
				return &domain.GatewayError{
					StatusCode: http.StatusBadRequest,
					Type:       domain.ErrorTypeInvalidRequest,
					Code:       "invalid_request",
					Message:    "bad request",
					Retryable:  false,
				}
			})
			idCtx := &domain.IdentityContext{OrgID: fx.org.ID}

			meta, err := tc.run(ctx, fx.rm, idCtx, fx.primary.Alias)
			var gwErr *domain.GatewayError
			if !errors.As(err, &gwErr) || gwErr.StatusCode != http.StatusBadRequest {
				t.Fatalf("%s expected 400 GatewayError, got %v", tc.name, err)
			}
			if meta.TierStepdowns != 0 || meta.FallbackReason != "" || meta.FallbackAttempted {
				t.Fatalf("%s should abort without stepdown/fallback, got %+v", tc.name, meta)
			}
			if calls := fx.adp.recordedCalls(); len(calls) != 1 {
				t.Fatalf("%s expected 1 call before abort, got %v", tc.name, calls)
			}
		})
	}
}
