package router

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/goroute-ai/ai-gateway-go/internal/adapter"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type multiModalityMockAdapter struct {
	routingMockAdapter
	mu              sync.Mutex
	failOnceByDepID map[string]int
	embCalls        []string
	rerankCalls     []string
	modCalls        []string
	compCalls       []string
	compStreamCalls []string
	sttCalls        []string
	ttsCalls        []string
	imgCalls        []string
	onTTSStream     func() (io.ReadCloser, string, error)
	onCompStream    func() (<-chan domain.CanonicalStreamChunk, error)
}

func (a *multiModalityMockAdapter) shouldFail(depID string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.failOnceByDepID != nil && a.failOnceByDepID[depID] > 0 {
		a.failOnceByDepID[depID]--
		return &domain.GatewayError{
			StatusCode: http.StatusBadGateway,
			Type:       domain.ErrorTypeUpstream,
			Code:       "upstream_502",
			Retryable:  true,
		}
	}
	return nil
}

func (a *multiModalityMockAdapter) Embeddings(_ context.Context, dep *domain.Deployment, req *domain.CanonicalEmbeddingRequest) (*domain.CanonicalEmbeddingResponse, error) {
	a.mu.Lock()
	a.embCalls = append(a.embCalls, dep.ID)
	a.mu.Unlock()
	if err := a.shouldFail(dep.ID); err != nil {
		return nil, err
	}
	return &domain.CanonicalEmbeddingResponse{Object: "list", Model: req.ResolvedModel, Provider: a.provider, Usage: domain.TokenUsage{PromptTokens: 4, TotalTokens: 4}}, nil
}

func (a *multiModalityMockAdapter) Rerank(_ context.Context, dep *domain.Deployment, req *domain.CanonicalRerankRequest) (*domain.CanonicalRerankResponse, error) {
	a.mu.Lock()
	a.rerankCalls = append(a.rerankCalls, dep.ID)
	a.mu.Unlock()
	if err := a.shouldFail(dep.ID); err != nil {
		return nil, err
	}
	return &domain.CanonicalRerankResponse{ID: "rr-" + dep.ID, Model: req.ResolvedModel, Provider: a.provider, Usage: domain.RerankUsage{TotalTokens: 3}}, nil
}

func (a *multiModalityMockAdapter) Moderate(_ context.Context, dep *domain.Deployment, req *domain.CanonicalModerationRequest) (*domain.CanonicalModerationResponse, error) {
	a.mu.Lock()
	a.modCalls = append(a.modCalls, dep.ID)
	a.mu.Unlock()
	if err := a.shouldFail(dep.ID); err != nil {
		return nil, err
	}
	return &domain.CanonicalModerationResponse{ID: "mod-" + dep.ID, Model: req.ResolvedModel}, nil
}

func (a *multiModalityMockAdapter) TextCompletion(_ context.Context, dep *domain.Deployment, req *domain.CanonicalCompletionRequest) (*domain.CanonicalCompletionResponse, error) {
	a.mu.Lock()
	a.compCalls = append(a.compCalls, dep.ID)
	a.mu.Unlock()
	if err := a.shouldFail(dep.ID); err != nil {
		return nil, err
	}
	return &domain.CanonicalCompletionResponse{ID: "cmp-" + dep.ID, Model: req.ResolvedModel, Provider: a.provider, Usage: domain.TokenUsage{PromptTokens: 2, CompletionTokens: 3, TotalTokens: 5}}, nil
}

func (a *multiModalityMockAdapter) StreamTextCompletion(_ context.Context, dep *domain.Deployment, _ *domain.CanonicalCompletionRequest) (<-chan domain.CanonicalStreamChunk, error) {
	a.mu.Lock()
	a.compStreamCalls = append(a.compStreamCalls, dep.ID)
	a.mu.Unlock()
	if err := a.shouldFail(dep.ID); err != nil {
		return nil, err
	}
	if a.onCompStream != nil {
		return a.onCompStream()
	}
	ch := make(chan domain.CanonicalStreamChunk, 1)
	ch <- domain.CanonicalStreamChunk{ID: "cs-" + dep.ID, Choices: []domain.CanonicalStreamChoice{{Index: 0, Delta: domain.CanonicalStreamDelta{Content: "ok"}}}}
	close(ch)
	return ch, nil
}

func (a *multiModalityMockAdapter) TranscribeAudio(_ context.Context, dep *domain.Deployment, _ *domain.CanonicalAudioTranscriptionRequest) (*domain.CanonicalAudioResponse, error) {
	a.mu.Lock()
	a.sttCalls = append(a.sttCalls, dep.ID)
	a.mu.Unlock()
	if err := a.shouldFail(dep.ID); err != nil {
		return nil, err
	}
	return &domain.CanonicalAudioResponse{Text: "hello-" + dep.ID}, nil
}

func (a *multiModalityMockAdapter) GenerateSpeech(_ context.Context, dep *domain.Deployment, _ *domain.CanonicalAudioSpeechRequest) (io.ReadCloser, string, error) {
	a.mu.Lock()
	a.ttsCalls = append(a.ttsCalls, dep.ID)
	a.mu.Unlock()
	if err := a.shouldFail(dep.ID); err != nil {
		return nil, "", err
	}
	if a.onTTSStream != nil {
		return a.onTTSStream()
	}
	return io.NopCloser(strings.NewReader("audio-" + dep.ID)), "audio/mpeg", nil
}

func (a *multiModalityMockAdapter) GenerateImage(_ context.Context, dep *domain.Deployment, _ *domain.CanonicalImageRequest) (*domain.CanonicalImageResponse, error) {
	a.mu.Lock()
	a.imgCalls = append(a.imgCalls, dep.ID)
	a.mu.Unlock()
	if err := a.shouldFail(dep.ID); err != nil {
		return nil, err
	}
	return &domain.CanonicalImageResponse{Created: 123, Data: []domain.ImageItem{{URL: "https://example.invalid/" + dep.ID}}}, nil
}

func TestPhase4_DeploymentSlotLimiterRedisAndLocal(t *testing.T) {
	ctx := context.Background()

	runSub := func(t *testing.T, rf *storage.RedisFabric) {
		t.Helper()
		limiter := NewDeploymentSlotLimiter(rf, 60)
		var now atomic.Int64
		now.Store(time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC).Unix())
		limiter.now = func() time.Time { return time.Unix(now.Load(), 0).UTC() }

		rel1, ok := limiter.AcquireDeploymentSlot(ctx, "dep-slot-1", 2)
		require.True(t, ok)
		rel2, ok := limiter.AcquireDeploymentSlot(ctx, "dep-slot-1", 2)
		require.True(t, ok)

		// 3rd concurrent acquisition rejected.
		_, ok = limiter.AcquireDeploymentSlot(ctx, "dep-slot-1", 2)
		assert.False(t, ok)

		counts := limiter.ActiveCounts(ctx, []*domain.Deployment{{ID: "dep-slot-1", MaxParallelRequests: 2}})
		assert.Equal(t, 2, counts["dep-slot-1"])

		// Releasing one slot allows next acquisition.
		rel1()
		rel3, ok := limiter.AcquireDeploymentSlot(ctx, "dep-slot-1", 2)
		require.True(t, ok)
		rel2()
		rel3()

		// Self-healing expiry reclaims leaked leases past TTL.
		_, ok = limiter.AcquireDeploymentSlot(ctx, "dep-slot-1", 1)
		require.True(t, ok)
		_, ok = limiter.AcquireDeploymentSlot(ctx, "dep-slot-1", 1)
		assert.False(t, ok)

		now.Add(61)
		relAfterExpiry, ok := limiter.AcquireDeploymentSlot(ctx, "dep-slot-1", 1)
		require.True(t, ok, "expired lease should be self-healed")
		relAfterExpiry()
	}

	t.Run("local", func(t *testing.T) { runSub(t, nil) })
	t.Run("redis", func(t *testing.T) {
		mr := miniredis.RunT(t)
		rf := storage.NewRedisFabric(mr.Addr(), "", 0)
		t.Cleanup(func() { _ = rf.Client().Close() })
		runSub(t, rf)
	})
}

func TestPhase4_MaxParallelRequestsStreamHoldAcrossModalities(t *testing.T) {
	ctx := context.Background()
	mr := miniredis.RunT(t)
	rf := storage.NewRedisFabric(mr.Addr(), "", 0)
	t.Cleanup(func() { _ = rf.Client().Close() })

	cfg := config.RouterConfig{BaseRetryDelay: time.Millisecond, MaxRetryDelay: 5 * time.Millisecond}
	repo, reg, vault, _, _, rm, org := newRoutingTestEnv(t, rf, cfg)

	adp := &multiModalityMockAdapter{
		routingMockAdapter: routingMockAdapter{provider: domain.ProviderOpenAI},
	}
	reg.Register(adp)

	group := &domain.ModelGroup{OrgID: org.ID, Alias: "stream-slot-group", RoutingStrategy: domain.StrategyWeightedShuffle, IsActive: true}
	require.NoError(t, repo.CreateModelGroup(ctx, group))
	dep := registerRoutingModelAndDep(t, repo, vault, org.ID, group, &domain.GlobalModel{
		ID: "openai/stream-slot", Provider: domain.ProviderOpenAI, ModelName: "stream-slot",
		SupportsInference: true, LifecycleStatus: domain.ModelStatusActive,
		Capabilities: domain.ModelCapabilities{
			Streaming: domain.CapabilitySupported,
			AudioTTS:  domain.CapabilitySupported,
		},
	}, "dep-stream-slot", "http://localhost")
	dep.MaxParallelRequests = 1
	require.NoError(t, repo.UpdateDeployment(ctx, dep))

	// 1. Chat SSE stream holds slot across StreamChatCompletion duration.
	chatEntered := make(chan struct{})
	chatRelease := make(chan struct{})
	adp.streamFn = func(_ context.Context, _ *domain.Deployment, _ *domain.CanonicalChatRequest, emit adapter.StreamChunkHandler) (*domain.TokenUsage, error) {
		close(chatEntered)
		<-chatRelease
		_ = emit(&domain.CanonicalStreamChunk{ID: "c1", Choices: []domain.CanonicalStreamChoice{{Index: 0}}})
		return &domain.TokenUsage{PromptTokens: 2, CompletionTokens: 1, TotalTokens: 3}, nil
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _, err := rm.ExecuteStream(ctx, &domain.IdentityContext{OrgID: org.ID}, &domain.CanonicalChatRequest{
			Model: "stream-slot-group", Stream: true, Messages: []domain.CanonicalMessage{{Role: "user", Content: "hi"}},
		}, func(*domain.CanonicalStreamChunk) error { return nil }, nil)
		assert.NoError(t, err)
	}()

	<-chatEntered
	_, _, satErr := rm.ExecuteStream(ctx, &domain.IdentityContext{OrgID: org.ID}, &domain.CanonicalChatRequest{
		Model: "stream-slot-group", Stream: true, Messages: []domain.CanonicalMessage{{Role: "user", Content: "second"}},
	}, func(*domain.CanonicalStreamChunk) error { return nil }, nil)
	require.Error(t, satErr)
	var gwErr *domain.GatewayError
	require.ErrorAs(t, satErr, &gwErr)
	assert.Equal(t, http.StatusTooManyRequests, gwErr.StatusCode)

	close(chatRelease)
	wg.Wait()

	// 2. CompletionStream holds slot inside forwarding goroutine until upstream channel closes.
	upCh := make(chan domain.CanonicalStreamChunk, 1)
	adp.onCompStream = func() (<-chan domain.CanonicalStreamChunk, error) {
		return upCh, nil
	}
	outCh, _, err := rm.ExecuteCompletionStream(ctx, &domain.IdentityContext{OrgID: org.ID}, &domain.CanonicalCompletionRequest{
		Model: "stream-slot-group", Prompt: domain.CompletionPrompt{Strings: []string{"hello"}}, Stream: true,
	})
	require.NoError(t, err)

	// Second call while stream channel still open is blocked by MaxParallelRequests=1.
	_, _, err2 := rm.ExecuteCompletionStream(ctx, &domain.IdentityContext{OrgID: org.ID}, &domain.CanonicalCompletionRequest{
		Model: "stream-slot-group", Prompt: domain.CompletionPrompt{Strings: []string{"blocked"}}, Stream: true,
	})
	require.Error(t, err2)

	close(upCh)
	for range outCh {
	}

	// 3. AudioSpeech holds slot AND loadBalancer active in_flight until caller calls rc.Close().
	readInFlight := func() int {
		rm.loadBalancer.mu.RLock()
		defer rm.loadBalancer.mu.RUnlock()
		if m, ok := rm.loadBalancer.metrics[dep.ID]; ok && m != nil {
			return m.inFlight
		}
		return 0
	}
	rc, _, _, err := rm.ExecuteAudioSpeech(ctx, &domain.IdentityContext{OrgID: org.ID}, &domain.CanonicalAudioSpeechRequest{
		Model: "stream-slot-group", Input: "speak", Voice: "alloy",
	})
	require.NoError(t, err)
	assert.Equal(t, 1, readInFlight(), "in_flight must remain 1 while speech stream is open")

	_, _, _, errBlocked := rm.ExecuteAudioSpeech(ctx, &domain.IdentityContext{OrgID: org.ID}, &domain.CanonicalAudioSpeechRequest{
		Model: "stream-slot-group", Input: "blocked", Voice: "alloy",
	})
	require.Error(t, errBlocked)

	require.NoError(t, rc.Close())
	assert.Equal(t, 0, readInFlight(), "in_flight must settle to 0 when speech stream closes")

	// Slot is now free again.
	rc2, _, _, errAfterClose := rm.ExecuteAudioSpeech(ctx, &domain.IdentityContext{OrgID: org.ID}, &domain.CanonicalAudioSpeechRequest{
		Model: "stream-slot-group", Input: "speak2", Voice: "alloy",
	})
	require.NoError(t, errAfterClose)
	require.NoError(t, rc2.Close())
}

func TestPhase4_MaxParallelWaitMsBoundedWait(t *testing.T) {
	ctx := context.Background()
	cfg := config.RouterConfig{
		BaseRetryDelay: time.Millisecond,
		MaxRetryDelay:  5 * time.Millisecond,
		Scheduler:      config.SchedulerConfig{MaxParallelWaitMs: 180},
	}
	repo, reg, vault, _, _, rm, org := newRoutingTestEnv(t, nil, cfg)

	adp := &routingMockAdapter{provider: domain.ProviderOpenAI}
	reg.Register(adp)

	group := &domain.ModelGroup{OrgID: org.ID, Alias: "wait-group", RoutingStrategy: domain.StrategyWeightedShuffle, IsActive: true}
	require.NoError(t, repo.CreateModelGroup(ctx, group))
	dep := registerRoutingModelAndDep(t, repo, vault, org.ID, group, &domain.GlobalModel{
		ID: "openai/wait-model", Provider: domain.ProviderOpenAI, ModelName: "wait-model",
		SupportsInference: true, LifecycleStatus: domain.ModelStatusActive,
	}, "dep-wait", "http://localhost")
	dep.MaxParallelRequests = 1
	require.NoError(t, repo.UpdateDeployment(ctx, dep))

	// Hold slot for 40ms -> 2nd caller with MaxParallelWaitMs=180 waits and succeeds.
	rel, ok := rm.slotLimiter.AcquireDeploymentSlot(ctx, dep.ID, 1)
	require.True(t, ok)
	go func() {
		time.Sleep(40 * time.Millisecond)
		rel()
	}()

	resp, _, err := rm.ExecuteChat(ctx, &domain.IdentityContext{OrgID: org.ID}, &domain.CanonicalChatRequest{
		Model: "wait-group", Messages: []domain.CanonicalMessage{{Role: "user", Content: "waited"}},
	})
	require.NoError(t, err)
	require.NotNil(t, resp)

	// Hold slot past MaxParallelWaitMs (30ms wait < 200ms hold) -> returns 429 saturation.
	rmShortWait := NewReliabilityManager(repo, reg, rm.intelligentRouter, rm.loadBalancer, vault, rm.rbac, nil, config.RouterConfig{
		Scheduler: config.SchedulerConfig{MaxParallelWaitMs: 25},
	})
	relHold, ok := rmShortWait.slotLimiter.AcquireDeploymentSlot(ctx, dep.ID, 1)
	require.True(t, ok)
	defer relHold()

	_, _, errTimeout := rmShortWait.ExecuteChat(ctx, &domain.IdentityContext{OrgID: org.ID}, &domain.CanonicalChatRequest{
		Model: "wait-group", Messages: []domain.CanonicalMessage{{Role: "user", Content: "too-slow"}},
	})
	require.Error(t, errTimeout)
	var gwErr *domain.GatewayError
	require.ErrorAs(t, errTimeout, &gwErr)
	assert.Equal(t, http.StatusTooManyRequests, gwErr.StatusCode)
	assert.Equal(t, "deployment_capacity_saturated", gwErr.Code)
}

func TestPhase4_Stage6_ITPMAndOTPMFiltering(t *testing.T) {
	ctx := context.Background()
	lb := NewLoadBalancer()
	depITPM := &domain.Deployment{
		ID:           "dep-itpm-cap",
		Status:       domain.DeploymentStatusActive,
		ITPMCapacity: 100,
		OTPMCapacity: 500,
		GlobalModel:  &domain.GlobalModel{ID: "openai/m1", Provider: domain.ProviderOpenAI, ModelName: "m1"},
		Credential:   &domain.ProviderCredential{IsActive: true},
	}
	depOTPM := &domain.Deployment{
		ID:           "dep-otpm-cap",
		Status:       domain.DeploymentStatusActive,
		ITPMCapacity: 500,
		OTPMCapacity: 50,
		GlobalModel:  &domain.GlobalModel{ID: "openai/m2", Provider: domain.ProviderOpenAI, ModelName: "m2"},
		Credential:   &domain.ProviderCredential{IsActive: true},
	}
	fp := NewFilterPipeline(nil, lb, config.RouterConfig{StrictCapacityFiltering: true})

	// Pre-reserve 80 input + 30 output on depITPM; estInput=30 exceeds depITPM's 100 ITPM cap -> only depOTPM survives.
	lb.OnRequestStartWithTokens(depITPM.ID, 80, 30)
	maxOut20 := 20
	got, sat, err := fp.FilterEligibleDeploymentsDetailed(ctx, "org-1", "grp", &domain.CanonicalChatRequest{Model: "grp", MaxTokens: &maxOut20}, []*domain.Deployment{depITPM, depOTPM}, 30, nil)
	require.NoError(t, err)
	assert.False(t, sat)
	require.Len(t, got, 1)
	assert.Equal(t, depOTPM.ID, got[0].ID)

	// Now pre-reserve 35 output on depOTPM; MaxTokens=20 (35+20 > 50 OTPMCapacity) saturates BOTH -> empty + sat=true.
	lb.OnRequestStartWithTokens(depOTPM.ID, 10, 35)
	got2, sat2, err := fp.FilterEligibleDeploymentsDetailed(ctx, "org-1", "grp", &domain.CanonicalChatRequest{Model: "grp", MaxTokens: &maxOut20}, []*domain.Deployment{depITPM, depOTPM}, 30, nil)
	require.NoError(t, err)
	assert.Empty(t, got2)
	assert.True(t, sat2)
}

func TestPhase4_FallbackOnSaturation_Stage6AndPriorityCapacity(t *testing.T) {
	ctx := context.Background()

	t.Run("saturation_fallbacks_on_stage6_and_rbac_gate", func(t *testing.T) {
		cfg := config.RouterConfig{
			FallbackOnSaturation: true,
			BaseRetryDelay:       time.Millisecond,
			MaxRetryDelay:        5 * time.Millisecond,
		}
		repo, reg, vault, _, _, rm, org := newRoutingTestEnv(t, nil, cfg)
		adp := &routingMockAdapter{provider: domain.ProviderOpenAI}
		reg.Register(adp)

		fbGroup := &domain.ModelGroup{OrgID: org.ID, Alias: "sat-overflow", RoutingStrategy: domain.StrategyWeightedShuffle, IsActive: true}
		require.NoError(t, repo.CreateModelGroup(ctx, fbGroup))
		fbDep := registerRoutingModelAndDep(t, repo, vault, org.ID, fbGroup, &domain.GlobalModel{
			ID: "openai/overflow", Provider: domain.ProviderOpenAI, ModelName: "overflow",
			SupportsInference: true, LifecycleStatus: domain.ModelStatusActive,
		}, "dep-overflow", "http://localhost")

		blockedGroup := &domain.ModelGroup{OrgID: org.ID, Alias: "restricted-overflow", RoutingStrategy: domain.StrategyWeightedShuffle, IsActive: true}
		require.NoError(t, repo.CreateModelGroup(ctx, blockedGroup))
		registerRoutingModelAndDep(t, repo, vault, org.ID, blockedGroup, &domain.GlobalModel{
			ID: "openai/restricted", Provider: domain.ProviderOpenAI, ModelName: "restricted",
			SupportsInference: true, LifecycleStatus: domain.ModelStatusActive,
		}, "dep-restricted", "http://localhost")

		primary := &domain.ModelGroup{
			OrgID:               org.ID,
			Alias:               "primary-sat",
			RoutingStrategy:     domain.StrategyWeightedShuffle,
			SaturationFallbacks: []domain.FallbackTarget{{GroupAliasOrID: "restricted-overflow"}, {GroupAliasOrID: "sat-overflow"}},
			IsActive:            true,
		}
		require.NoError(t, repo.CreateModelGroup(ctx, primary))
		pDep := registerRoutingModelAndDep(t, repo, vault, org.ID, primary, &domain.GlobalModel{
			ID: "openai/primary", Provider: domain.ProviderOpenAI, ModelName: "primary",
			SupportsInference: true, LifecycleStatus: domain.ModelStatusActive,
		}, "dep-p", "http://localhost")
		pDep.MaxParallelRequests = 1
		require.NoError(t, repo.UpdateDeployment(ctx, pDep))

		// Hold primary's single slot so primary is Stage-6 saturated.
		rel, ok := rm.slotLimiter.AcquireDeploymentSlot(ctx, pDep.ID, 1)
		require.True(t, ok)
		defer rel()

		// Identity is only allowed "primary-sat" and "sat-overflow" (NOT "restricted-overflow").
		idCtx := &domain.IdentityContext{
			OrgID:            org.ID,
			KeyAllowedModels: []string{"primary-sat", "sat-overflow"},
		}
		resp, meta, err := rm.ExecuteChat(ctx, idCtx, &domain.CanonicalChatRequest{
			Model: "primary-sat", Messages: []domain.CanonicalMessage{{Role: "user", Content: "spillover"}},
		})
		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.True(t, meta.FallbackAttempted)
		assert.Equal(t, "saturation_fallback", meta.FallbackReason)
		assert.Equal(t, fbDep.ID, meta.WinningDeployment.ID)
	})

	t.Run("saturation_fallbacks_on_priority_capacity_exceeded", func(t *testing.T) {
		mr := miniredis.RunT(t)
		rf := storage.NewRedisFabric(mr.Addr(), "", 0)
		t.Cleanup(func() { _ = rf.Client().Close() })

		cfg := config.RouterConfig{
			FallbackOnSaturation: true,
			BaseRetryDelay:       time.Millisecond,
			MaxRetryDelay:        5 * time.Millisecond,
		}
		repo, reg, vault, _, _, rm, org := newRoutingTestEnv(t, rf, cfg)
		adp := &routingMockAdapter{provider: domain.ProviderOpenAI}
		reg.Register(adp)

		dpl := NewDynamicPriorityLimiter(rf, repo, DynamicPriorityConfig{
			Enabled:               true,
			SaturationThreshold:   0.5,
			ActiveCallerTTL:       30 * time.Second,
			WindowDuration:        time.Minute,
			DefaultBorrowMultiple: 1.0,
		})
		rm.SetPriorityCapacityLimiter(dpl)

		fbGroup := &domain.ModelGroup{OrgID: org.ID, Alias: "prio-overflow", RoutingStrategy: domain.StrategyWeightedShuffle, IsActive: true}
		require.NoError(t, repo.CreateModelGroup(ctx, fbGroup))
		fbDep := registerRoutingModelAndDep(t, repo, vault, org.ID, fbGroup, &domain.GlobalModel{
			ID: "openai/prio-fb", Provider: domain.ProviderOpenAI, ModelName: "prio-fb",
			SupportsInference: true, LifecycleStatus: domain.ModelStatusActive,
		}, "dep-prio-fb", "http://localhost")

		primary := &domain.ModelGroup{
			OrgID:               org.ID,
			Alias:               "prio-primary",
			RoutingStrategy:     domain.StrategyWeightedShuffle,
			SaturationFallbacks: []domain.FallbackTarget{{GroupAliasOrID: "prio-overflow"}},
			IsActive:            true,
		}
		require.NoError(t, repo.CreateModelGroup(ctx, primary))
		pDep := registerRoutingModelAndDep(t, repo, vault, org.ID, primary, &domain.GlobalModel{
			ID: "openai/prio-p", Provider: domain.ProviderOpenAI, ModelName: "prio-p",
			SupportsInference: true, LifecycleStatus: domain.ModelStatusActive,
		}, "dep-prio-p", "http://localhost")
		pDep.RPMCapacity = 100
		require.NoError(t, repo.UpdateDeployment(ctx, pDep))

		idCtx := &domain.IdentityContext{
			OrgID:        org.ID,
			TeamID:       "team-a",
			TeamRPMLimit: 1,
		}

		// Request 1 uses this team's 1 RPM share on prio-primary cleanly.
		resp1, meta1, err := rm.ExecuteChat(ctx, idCtx, &domain.CanonicalChatRequest{
			Model: "prio-primary", Messages: []domain.CanonicalMessage{{Role: "user", Content: "first"}},
		})
		require.NoError(t, err)
		require.NotNil(t, resp1)
		assert.Equal(t, pDep.ID, meta1.WinningDeployment.ID)

		// Request 2 hits priority_capacity_exceeded (1/1 RPM exhausted) -> spills to prio-overflow via SaturationFallbacks.
		resp, meta, err := rm.ExecuteChat(ctx, idCtx, &domain.CanonicalChatRequest{
			Model: "prio-primary", Messages: []domain.CanonicalMessage{{Role: "user", Content: "prio fallback"}},
		})
		require.NoError(t, err)
		require.NotNil(t, resp)
		assert.True(t, meta.FallbackAttempted)
		assert.Equal(t, "saturation_fallback", meta.FallbackReason)
		assert.Equal(t, fbDep.ID, meta.WinningDeployment.ID)
	})
}

func TestPhase4_DisableCooldownsConfigAndGroupLevel(t *testing.T) {
	ctx := context.Background()

	runMode := func(t *testing.T, globalDisable, groupDisable bool) {
		t.Helper()
		cfg := config.RouterConfig{
			DisableCooldowns:  globalDisable,
			FailureThreshold:  1,
			DefaultCooldown:   30 * time.Second,
			DefaultMaxRetries: 0,
		}
		repo, reg, vault, _, _, rm, org := newRoutingTestEnv(t, nil, cfg)

		var failMode atomic.Bool
		failMode.Store(true)
		adp := &routingMockAdapter{
			provider: domain.ProviderOpenAI,
			chatFn: func(_ context.Context, dep *domain.Deployment, req *domain.CanonicalChatRequest) (*domain.CanonicalChatResponse, error) {
				if failMode.Load() {
					return nil, &domain.GatewayError{
						StatusCode:  http.StatusUnauthorized,
						Type:        domain.ErrorTypeAuthentication,
						Code:        "upstream_401",
						AuthFailure: true,
					}
				}
				return &domain.CanonicalChatResponse{ID: "recovered", Provider: domain.ProviderOpenAI, Model: req.ResolvedModel}, nil
			},
		}
		reg.Register(adp)

		group := &domain.ModelGroup{
			OrgID:            org.ID,
			Alias:            "cooldown-group",
			RoutingStrategy:  domain.StrategyWeightedShuffle,
			DisableCooldowns: groupDisable,
			FailureThreshold: 1,
			CooldownSeconds:  30,
			MaxRetries:       0,
			IsActive:         true,
		}
		require.NoError(t, repo.CreateModelGroup(ctx, group))
		dep := registerRoutingModelAndDep(t, repo, vault, org.ID, group, &domain.GlobalModel{
			ID: "openai/cd-model", Provider: domain.ProviderOpenAI, ModelName: "cd-model",
			SupportsInference: true, LifecycleStatus: domain.ModelStatusActive,
		}, "dep-cd", "http://localhost")

		// Even multiple auth failures exceeding threshold=1 must NOT open circuit breaker.
		for i := 0; i < 3; i++ {
			_, _, err := rm.ExecuteChat(ctx, &domain.IdentityContext{OrgID: org.ID}, &domain.CanonicalChatRequest{
				Model: "cooldown-group", Messages: []domain.CanonicalMessage{{Role: "user", Content: "hi"}},
			})
			require.Error(t, err)
			assert.Equal(t, CircuitClosed, rm.GetCircuitState(ctx, dep.ID))
			assert.False(t, rm.IsInCooldown(ctx, dep.ID))
		}

		failMode.Store(false)
		resp, meta, err := rm.ExecuteChat(ctx, &domain.IdentityContext{OrgID: org.ID}, &domain.CanonicalChatRequest{
			Model: "cooldown-group", Messages: []domain.CanonicalMessage{{Role: "user", Content: "recover"}},
		})
		require.NoError(t, err)
		assert.Equal(t, dep.ID, meta.WinningDeployment.ID)
		assert.Equal(t, "recovered", resp.ID)
	}

	t.Run("global_config", func(t *testing.T) { runMode(t, true, false) })
	t.Run("model_group", func(t *testing.T) { runMode(t, false, true) })
}

func TestPhase4_UnifiedNonChatPoliciesAll8Modalities(t *testing.T) {
	ctx := context.Background()
	cfg := config.RouterConfig{
		BaseRetryDelay:    time.Millisecond,
		MaxRetryDelay:     5 * time.Millisecond,
		DefaultMaxRetries: 2,
		FailureThreshold:  1,
		DefaultCooldown:   30 * time.Second,
	}
	repo, reg, vault, _, _, rm, org := newRoutingTestEnv(t, nil, cfg)

	adp := &multiModalityMockAdapter{
		routingMockAdapter: routingMockAdapter{provider: domain.ProviderOpenAI},
		failOnceByDepID:    make(map[string]int),
	}
	reg.Register(adp)

	allCaps := domain.ModelCapabilities{
		Streaming:  domain.CapabilitySupported,
		Embeddings: domain.CapabilitySupported,
		Rerank:     domain.CapabilitySupported,
		Moderation: domain.CapabilitySupported,
		ImageGen:   domain.CapabilitySupported,
		AudioSTT:   domain.CapabilitySupported,
		AudioTTS:   domain.CapabilitySupported,
	}

	fbGroup := &domain.ModelGroup{OrgID: org.ID, Alias: "nonchat-fb", RoutingStrategy: domain.StrategyWeightedShuffle, IsActive: true}
	require.NoError(t, repo.CreateModelGroup(ctx, fbGroup))
	fbDep := registerRoutingModelAndDep(t, repo, vault, org.ID, fbGroup, &domain.GlobalModel{
		ID: "openai/all-fb", Provider: domain.ProviderOpenAI, ModelName: "all-fb",
		SupportsInference: true, Capabilities: allCaps, LifecycleStatus: domain.ModelStatusActive,
	}, "dep-all-fb", "http://localhost")

	primary := &domain.ModelGroup{
		OrgID:           org.ID,
		Alias:           "nonchat-primary",
		RoutingStrategy: domain.StrategyRoundRobin,
		FallbackTargets: []domain.FallbackTarget{{GroupAliasOrID: "nonchat-fb"}},
		IsActive:        true,
	}
	require.NoError(t, repo.CreateModelGroup(ctx, primary))
	pExcluded := registerRoutingModelAndDep(t, repo, vault, org.ID, primary, &domain.GlobalModel{
		ID: "openai/all-excluded", Provider: domain.ProviderOpenAI, ModelName: "all-excluded",
		SupportsInference: true, Capabilities: allCaps, LifecycleStatus: domain.ModelStatusActive,
	}, "dep-excluded", "http://localhost")
	pWinner := registerRoutingModelAndDep(t, repo, vault, org.ID, primary, &domain.GlobalModel{
		ID: "openai/all-win", Provider: domain.ProviderOpenAI, ModelName: "all-win",
		SupportsInference: true, Capabilities: allCaps, LifecycleStatus: domain.ModelStatusActive,
	}, "dep-win", "http://localhost")

	// Prove FilterPipeline RoutingPlugins run for ALL 8 non-chat modalities by excluding pExcluded.
	rm.SetRoutingPlugins(RoutingPluginFunc{
		PluginName: "filter-out-excluded",
		Fn: func(_ context.Context, rc *RoutingContext) ([]*domain.Deployment, error) {
			var out []*domain.Deployment
			for _, d := range rc.Candidates {
				if d.ID != pExcluded.ID {
					out = append(out, d)
				}
			}
			return out, nil
		},
	})

	idCtx := &domain.IdentityContext{OrgID: org.ID}

	// Verify 7 primary calls go only to pWinner (never pExcluded), then force pWinner failure -> FallbackTargets picks fbDep across modalities.
	_, mEmb, err := rm.ExecuteEmbeddings(ctx, idCtx, &domain.CanonicalEmbeddingRequest{Model: "nonchat-primary", Input: []string{"hi"}})
	require.NoError(t, err)
	assert.Equal(t, pWinner.ID, mEmb.WinningDeployment.ID)

	_, mRR, err := rm.ExecuteRerank(ctx, idCtx, &domain.CanonicalRerankRequest{Model: "nonchat-primary", Query: "q"})
	require.NoError(t, err)
	assert.Equal(t, pWinner.ID, mRR.WinningDeployment.ID)

	_, mMod, err := rm.ExecuteModeration(ctx, idCtx, &domain.CanonicalModerationRequest{Model: "nonchat-primary", Input: []string{"ok"}})
	require.NoError(t, err)
	assert.Equal(t, pWinner.ID, mMod.WinningDeployment.ID)

	_, mCmp, err := rm.ExecuteCompletion(ctx, idCtx, &domain.CanonicalCompletionRequest{Model: "nonchat-primary", Prompt: domain.CompletionPrompt{Strings: []string{"p"}}})
	require.NoError(t, err)
	assert.Equal(t, pWinner.ID, mCmp.WinningDeployment.ID)

	ch, mCmpS, err := rm.ExecuteCompletionStream(ctx, idCtx, &domain.CanonicalCompletionRequest{Model: "nonchat-primary", Prompt: domain.CompletionPrompt{Strings: []string{"p"}}, Stream: true})
	require.NoError(t, err)
	for range ch {
	}
	assert.Equal(t, pWinner.ID, mCmpS.WinningDeployment.ID)

	_, mSTT, err := rm.ExecuteAudioTranscription(ctx, idCtx, &domain.CanonicalAudioTranscriptionRequest{Model: "nonchat-primary", Prompt: "x"})
	require.NoError(t, err)
	assert.Equal(t, pWinner.ID, mSTT.WinningDeployment.ID)

	rc, _, mTTS, err := rm.ExecuteAudioSpeech(ctx, idCtx, &domain.CanonicalAudioSpeechRequest{Model: "nonchat-primary", Input: "hello"})
	require.NoError(t, err)
	require.NoError(t, rc.Close())
	assert.Equal(t, pWinner.ID, mTTS.WinningDeployment.ID)

	_, mImg, err := rm.ExecuteImage(ctx, idCtx, &domain.CanonicalImageRequest{Model: "nonchat-primary", Prompt: "cat"})
	require.NoError(t, err)
	assert.Equal(t, pWinner.ID, mImg.WinningDeployment.ID)

	// Confirm pExcluded was NEVER called on any of the 8 modalities.
	for _, calls := range [][]string{adp.embCalls, adp.rerankCalls, adp.modCalls, adp.compCalls, adp.compStreamCalls, adp.sttCalls, adp.ttsCalls, adp.imgCalls} {
		assert.NotContains(t, calls, pExcluded.ID)
	}

	// Force retryable failure on pWinner -> retries / FallbackTargets hop to fbDep works!
	adp.mu.Lock()
	adp.failOnceByDepID[pWinner.ID] = 5
	adp.mu.Unlock()
	_, mImgFB, err := rm.ExecuteImage(ctx, idCtx, &domain.CanonicalImageRequest{Model: "nonchat-primary", Prompt: "fallback-cat"})
	require.NoError(t, err)
	assert.True(t, mImgFB.FallbackAttempted)
	assert.Equal(t, fbDep.ID, mImgFB.WinningDeployment.ID)
}
