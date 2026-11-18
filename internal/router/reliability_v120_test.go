package router

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/goroute-ai/ai-gateway-go/internal/adapter"
	"github.com/goroute-ai/ai-gateway-go/internal/adapter/openai"
	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

type v120MockAdapter struct {
	provider      domain.ProviderType
	supportsPref  bool
	chatFn        func(ctx context.Context, dep *domain.Deployment, req *domain.CanonicalChatRequest) (*domain.CanonicalChatResponse, error)
	streamFn      func(ctx context.Context, dep *domain.Deployment, req *domain.CanonicalChatRequest, onChunk adapter.StreamChunkHandler) (*domain.TokenUsage, error)
	mu            sync.Mutex
	capturedCalls []string
	capturedReqs  []domain.CanonicalChatRequest
}

func (a *v120MockAdapter) Provider() domain.ProviderType { return a.provider }

func (a *v120MockAdapter) SupportsAssistantPrefill() bool { return a.supportsPref }

func (a *v120MockAdapter) ChatCompletion(ctx context.Context, dep *domain.Deployment, req *domain.CanonicalChatRequest) (*domain.CanonicalChatResponse, error) {
	a.mu.Lock()
	a.capturedCalls = append(a.capturedCalls, dep.ID)
	if req != nil {
		a.capturedReqs = append(a.capturedReqs, *req)
	}
	a.mu.Unlock()
	if a.chatFn != nil {
		return a.chatFn(ctx, dep, req)
	}
	return &domain.CanonicalChatResponse{
		ID:       "chat-ok-" + dep.ID,
		Provider: a.provider,
		Model:    req.ResolvedModel,
		Choices:  []domain.CanonicalChoice{{Index: 0, Message: domain.CanonicalMessage{Role: "assistant", Content: "ok:" + dep.ID}, FinishReason: "stop"}},
		Usage:    domain.TokenUsage{PromptTokens: 10, CompletionTokens: 5, TotalTokens: 15},
	}, nil
}

func (a *v120MockAdapter) StreamChatCompletion(ctx context.Context, dep *domain.Deployment, req *domain.CanonicalChatRequest, onChunk adapter.StreamChunkHandler) (*domain.TokenUsage, error) {
	a.mu.Lock()
	a.capturedCalls = append(a.capturedCalls, dep.ID)
	if req != nil {
		a.capturedReqs = append(a.capturedReqs, *req)
	}
	a.mu.Unlock()
	if a.streamFn != nil {
		return a.streamFn(ctx, dep, req, onChunk)
	}
	return nil, errors.New("stream not configured")
}

func (a *v120MockAdapter) Embeddings(context.Context, *domain.Deployment, *domain.CanonicalEmbeddingRequest) (*domain.CanonicalEmbeddingResponse, error) {
	return nil, errors.New("not implemented")
}

func (a *v120MockAdapter) HealthCheck(context.Context, *domain.Deployment) error { return nil }

func (a *v120MockAdapter) ListModels(context.Context, *domain.ProviderCredential) ([]domain.DiscoveredModel, error) {
	return nil, nil
}

func (a *v120MockAdapter) calls() []string {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]string, len(a.capturedCalls))
	copy(out, a.capturedCalls)
	return out
}

func (a *v120MockAdapter) reqs() []domain.CanonicalChatRequest {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]domain.CanonicalChatRequest, len(a.capturedReqs))
	copy(out, a.capturedReqs)
	return out
}

type v120NoPrefillAdapter struct {
	provider domain.ProviderType
	streamFn func(ctx context.Context, dep *domain.Deployment, req *domain.CanonicalChatRequest, onChunk adapter.StreamChunkHandler) (*domain.TokenUsage, error)
	calls    atomic.Int32
}

func (a *v120NoPrefillAdapter) Provider() domain.ProviderType { return a.provider }
func (a *v120NoPrefillAdapter) ChatCompletion(context.Context, *domain.Deployment, *domain.CanonicalChatRequest) (*domain.CanonicalChatResponse, error) {
	return nil, errors.New("not implemented")
}
func (a *v120NoPrefillAdapter) StreamChatCompletion(ctx context.Context, dep *domain.Deployment, req *domain.CanonicalChatRequest, onChunk adapter.StreamChunkHandler) (*domain.TokenUsage, error) {
	a.calls.Add(1)
	return a.streamFn(ctx, dep, req, onChunk)
}
func (a *v120NoPrefillAdapter) Embeddings(context.Context, *domain.Deployment, *domain.CanonicalEmbeddingRequest) (*domain.CanonicalEmbeddingResponse, error) {
	return nil, errors.New("not implemented")
}
func (a *v120NoPrefillAdapter) HealthCheck(context.Context, *domain.Deployment) error { return nil }
func (a *v120NoPrefillAdapter) ListModels(context.Context, *domain.ProviderCredential) ([]domain.DiscoveredModel, error) {
	return nil, nil
}

func newV120TestEnv(t *testing.T, redisFabric *storage.RedisFabric, cfg config.RouterConfig) (*storage.MemoryRepository, *adapter.Registry, *auth.Vault, *auth.RBACEngine, *LoadBalancer, *ReliabilityManager, *domain.Organization) {
	t.Helper()
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	vault, err := auth.NewVault("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("NewVault: %v", err)
	}
	rbac := auth.NewRBACEngine(repo)
	org := &domain.Organization{Name: "V120Org", Slug: "v120-org", IsActive: true}
	if err := repo.CreateOrganization(ctx, org); err != nil {
		t.Fatalf("CreateOrganization: %v", err)
	}
	reg := adapter.NewRegistry()
	lb := NewLoadBalancer(redisFabric)
	ir := NewIntelligentRouter(repo, cfg)
	rm := NewReliabilityManager(repo, reg, ir, lb, vault, rbac, redisFabric, cfg)
	return repo, reg, vault, rbac, lb, rm, org
}

func registerV120ModelAndDep(
	t *testing.T,
	repo *storage.MemoryRepository,
	vault *auth.Vault,
	orgID string,
	group *domain.ModelGroup,
	gm *domain.GlobalModel,
	depName string,
	baseURL string,
) *domain.Deployment {
	t.Helper()
	ctx := context.Background()
	if err := repo.UpsertGlobalModel(ctx, gm); err != nil {
		t.Fatalf("UpsertGlobalModel: %v", err)
	}
	cred := &domain.ProviderCredential{
		OrgID:    orgID,
		Provider: gm.Provider,
		Name:     "cred-" + depName,
		BaseURL:  baseURL,
		IsActive: true,
	}
	if err := vault.EncryptCredential(cred, "sk-test-"+depName); err != nil {
		t.Fatalf("EncryptCredential: %v", err)
	}
	if err := repo.CreateProviderCredential(ctx, cred); err != nil {
		t.Fatalf("CreateProviderCredential: %v", err)
	}
	dep := &domain.Deployment{
		ModelGroupID:   group.ID,
		GlobalModelID:  gm.ID,
		CredentialID:   cred.ID,
		DeploymentName: depName,
		Weight:         100,
		Status:         domain.DeploymentStatusActive,
	}
	if err := repo.CreateDeployment(ctx, dep); err != nil {
		t.Fatalf("CreateDeployment: %v", err)
	}
	return dep
}

func TestV120_ContextWindowFallbackAndOverrides(t *testing.T) {
	ctx := context.Background()

	t.Run("prefilter_128k_escapes_to_1m_with_overrides_without_mutating_caller_req", func(t *testing.T) {
		cfg := config.RouterConfig{BaseRetryDelay: time.Millisecond, MaxRetryDelay: 5 * time.Millisecond}
		repo, reg, vault, _, _, rm, org := newV120TestEnv(t, nil, cfg)

		adp := &v120MockAdapter{provider: domain.ProviderOpenAI}
		reg.Register(adp)

		longGroup := &domain.ModelGroup{OrgID: org.ID, Alias: "long-1m", RoutingStrategy: domain.StrategyWeightedShuffle, IsActive: true}
		if err := repo.CreateModelGroup(ctx, longGroup); err != nil {
			t.Fatal(err)
		}
		longDep := registerV120ModelAndDep(t, repo, vault, org.ID, longGroup, &domain.GlobalModel{
			ID: "openai/gpt-4.1-1m", Provider: domain.ProviderOpenAI, ModelName: "gpt-4.1-1m",
			MaxInputTokens: 1000000, SupportsInference: true, LifecycleStatus: domain.ModelStatusActive,
		}, "dep-1m", "http://localhost")

		primaryGroup := &domain.ModelGroup{
			OrgID:           org.ID,
			Alias:           "primary-128k",
			RoutingStrategy: domain.StrategyWeightedShuffle,
			ContextWindowFallbacks: []domain.FallbackTarget{
				{
					GroupAliasOrID: "long-1m",
					Overrides: map[string]any{
						"max_tokens":       1024,
						"temperature":      0.2,
						"top_p":            0.85,
						"reasoning_effort": "low",
						"stop":             []string{"END"},
					},
				},
			},
			IsActive: true,
		}
		if err := repo.CreateModelGroup(ctx, primaryGroup); err != nil {
			t.Fatal(err)
		}
		primaryDep := registerV120ModelAndDep(t, repo, vault, org.ID, primaryGroup, &domain.GlobalModel{
			ID: "openai/gpt-4o-128k", Provider: domain.ProviderOpenAI, ModelName: "gpt-4o-128k",
			MaxInputTokens: 128000, SupportsInference: true, LifecycleStatus: domain.ModelStatusActive,
		}, "dep-128k", "http://localhost")

		origMaxTokens := 4096
		origTemp := 0.9
		origTopP := 1.0
		callerReq := &domain.CanonicalChatRequest{
			Model:           "primary-128k",
			Messages:        []domain.CanonicalMessage{{Role: "user", Content: strings.Repeat("word ", 140000)}},
			MaxTokens:       &origMaxTokens,
			Temperature:     &origTemp,
			TopP:            &origTopP,
			ReasoningEffort: "high",
			Stop:            []string{"HALT"},
		}

		resp, meta, err := rm.ExecuteChat(ctx, &domain.IdentityContext{OrgID: org.ID}, callerReq)
		if err != nil {
			t.Fatalf("ExecuteChat failed: %v", err)
		}
		if resp == nil || meta.WinningDeployment == nil || meta.WinningDeployment.ID != longDep.ID {
			t.Fatalf("expected winning dep %s, got %+v", longDep.ID, meta.WinningDeployment)
		}
		if !meta.FallbackAttempted || meta.FallbackReason != "context_window_fallback" {
			t.Fatalf("expected FallbackAttempted=true, FallbackReason=context_window_fallback; got %+v", meta)
		}

		// Primary 128k deployment must not have been invoked at all (pruned by FilterEligibleDeployments).
		calls := adp.calls()
		if len(calls) != 1 || calls[0] != longDep.ID || slices.Contains(calls, primaryDep.ID) {
			t.Fatalf("expected single call to %s, got %v", longDep.ID, calls)
		}

		// Verify caller request was not mutated.
		if *callerReq.MaxTokens != 4096 || *callerReq.Temperature != 0.9 || *callerReq.TopP != 1.0 || callerReq.ReasoningEffort != "high" || !slices.Equal(callerReq.Stop, []string{"HALT"}) {
			t.Fatalf("caller request was mutated: max=%d temp=%v top_p=%v effort=%q stop=%v",
				*callerReq.MaxTokens, *callerReq.Temperature, *callerReq.TopP, callerReq.ReasoningEffort, callerReq.Stop)
		}

		// Verify upstream received overridden parameters.
		sentReqs := adp.reqs()
		if len(sentReqs) != 1 {
			t.Fatalf("expected 1 sent request, got %d", len(sentReqs))
		}
		got := sentReqs[0]
		if got.MaxTokens == nil || *got.MaxTokens != 1024 || got.Temperature == nil || *got.Temperature != 0.2 ||
			got.TopP == nil || *got.TopP != 0.85 || got.ReasoningEffort != "low" || !slices.Equal(got.Stop, []string{"END"}) {
			t.Fatalf("expected fallback overrides applied, got max=%v temp=%v top_p=%v effort=%q stop=%v",
				got.MaxTokens, got.Temperature, got.TopP, got.ReasoningEffort, got.Stop)
		}
	})

	t.Run("upstream_context_error_and_default_fallbacks", func(t *testing.T) {
		cfg := config.RouterConfig{
			BaseRetryDelay:   time.Millisecond,
			MaxRetryDelay:    5 * time.Millisecond,
			DefaultFallbacks: []domain.FallbackTarget{{GroupAliasOrID: "default-1m"}},
		}
		repo, reg, vault, _, _, rm, org := newV120TestEnv(t, nil, cfg)

		var primaryDepID string
		adp := &v120MockAdapter{
			provider: domain.ProviderOpenAI,
			chatFn: func(_ context.Context, dep *domain.Deployment, req *domain.CanonicalChatRequest) (*domain.CanonicalChatResponse, error) {
				if dep.ID == primaryDepID {
					return nil, domain.ClassifyUpstreamStatus(domain.ProviderOpenAI, http.StatusBadRequest, "context_length_exceeded: maximum context length", 0)
				}
				return &domain.CanonicalChatResponse{ID: "ok-default", Provider: domain.ProviderOpenAI, Model: req.ResolvedModel}, nil
			},
		}
		reg.Register(adp)

		defaultGroup := &domain.ModelGroup{OrgID: org.ID, Alias: "default-1m", RoutingStrategy: domain.StrategyWeightedShuffle, IsActive: true}
		if err := repo.CreateModelGroup(ctx, defaultGroup); err != nil {
			t.Fatal(err)
		}
		defaultDep := registerV120ModelAndDep(t, repo, vault, org.ID, defaultGroup, &domain.GlobalModel{
			ID: "openai/gpt-4.1-default", Provider: domain.ProviderOpenAI, ModelName: "gpt-4.1-default",
			SupportsInference: true, LifecycleStatus: domain.ModelStatusActive,
		}, "dep-default", "http://localhost")

		primaryGroup := &domain.ModelGroup{OrgID: org.ID, Alias: "small-primary", RoutingStrategy: domain.StrategyWeightedShuffle, IsActive: true}
		if err := repo.CreateModelGroup(ctx, primaryGroup); err != nil {
			t.Fatal(err)
		}
		primaryDep := registerV120ModelAndDep(t, repo, vault, org.ID, primaryGroup, &domain.GlobalModel{
			ID: "openai/gpt-4o-small", Provider: domain.ProviderOpenAI, ModelName: "gpt-4o-small",
			SupportsInference: true, LifecycleStatus: domain.ModelStatusActive,
		}, "dep-small", "http://localhost")
		primaryDepID = primaryDep.ID

		resp, meta, err := rm.ExecuteChat(ctx, &domain.IdentityContext{OrgID: org.ID}, &domain.CanonicalChatRequest{
			Model:    "small-primary",
			Messages: []domain.CanonicalMessage{{Role: "user", Content: "short text"}},
		})
		if err != nil {
			t.Fatalf("ExecuteChat failed: %v", err)
		}
		if resp.ID != "ok-default" || meta.WinningDeployment.ID != defaultDep.ID {
			t.Fatalf("expected default fallback dep %s, got %+v", defaultDep.ID, meta.WinningDeployment)
		}
		if !meta.FallbackAttempted || meta.FallbackReason != "default_fallback" {
			t.Fatalf("expected FallbackAttempted=true, FallbackReason=default_fallback; got %+v", meta)
		}
		if state := rm.GetCircuitState(ctx, primaryDep.ID); state != CircuitClosed {
			t.Fatalf("context window error must not trip circuit breaker, got %s", state)
		}
	})
}

func TestV120_ContentPolicyFallbackVsLocalGuardrailFailClosed(t *testing.T) {
	ctx := context.Background()
	cfg := config.RouterConfig{
		BaseRetryDelay:    time.Millisecond,
		MaxRetryDelay:     5 * time.Millisecond,
		DefaultMaxRetries: 2,
	}
	repo, reg, vault, _, _, rm, org := newV120TestEnv(t, nil, cfg)

	var mode atomic.Int32 // 0 = upstream content_policy, 1 = local guardrail_blocked
	var primaryDepID, cpDepID, generalDepID string
	adp := &v120MockAdapter{
		provider: domain.ProviderOpenAI,
		chatFn: func(_ context.Context, dep *domain.Deployment, req *domain.CanonicalChatRequest) (*domain.CanonicalChatResponse, error) {
			if dep.ID == primaryDepID {
				if mode.Load() == 0 {
					return nil, domain.ClassifyUpstreamStatus(domain.ProviderOpenAI, http.StatusBadRequest, "Rejected: content_policy_violation", 0)
				}
				return nil, &domain.GatewayError{
					StatusCode: http.StatusForbidden,
					Type:       domain.ErrorTypePermission,
					Code:       "guardrail_blocked",
					Message:    "Blocked by local PII guardrail",
					Retryable:  false,
				}
			}
			return &domain.CanonicalChatResponse{ID: "ok-" + dep.ID, Provider: domain.ProviderOpenAI, Model: req.ResolvedModel}, nil
		},
	}
	reg.Register(adp)

	cpGroup := &domain.ModelGroup{OrgID: org.ID, Alias: "cp-safe", RoutingStrategy: domain.StrategyWeightedShuffle, IsActive: true}
	_ = repo.CreateModelGroup(ctx, cpGroup)
	cpDep := registerV120ModelAndDep(t, repo, vault, org.ID, cpGroup, &domain.GlobalModel{
		ID: "openai/cp-model", Provider: domain.ProviderOpenAI, ModelName: "cp-model",
		SupportsInference: true, LifecycleStatus: domain.ModelStatusActive,
	}, "dep-cp", "http://localhost")
	cpDepID = cpDep.ID

	genGroup := &domain.ModelGroup{OrgID: org.ID, Alias: "gen-fb", RoutingStrategy: domain.StrategyWeightedShuffle, IsActive: true}
	_ = repo.CreateModelGroup(ctx, genGroup)
	genDep := registerV120ModelAndDep(t, repo, vault, org.ID, genGroup, &domain.GlobalModel{
		ID: "openai/gen-model", Provider: domain.ProviderOpenAI, ModelName: "gen-model",
		SupportsInference: true, LifecycleStatus: domain.ModelStatusActive,
	}, "dep-gen", "http://localhost")
	generalDepID = genDep.ID

	primaryGroup := &domain.ModelGroup{
		OrgID:                  org.ID,
		Alias:                  "cp-primary",
		RoutingStrategy:        domain.StrategyWeightedShuffle,
		ContentPolicyFallbacks: []domain.FallbackTarget{{GroupAliasOrID: "cp-safe"}},
		FallbackGroupIDs:       []string{genGroup.ID},
		IsActive:               true,
	}
	_ = repo.CreateModelGroup(ctx, primaryGroup)
	primaryDep := registerV120ModelAndDep(t, repo, vault, org.ID, primaryGroup, &domain.GlobalModel{
		ID: "openai/primary-cp", Provider: domain.ProviderOpenAI, ModelName: "primary-cp",
		SupportsInference: true, LifecycleStatus: domain.ModelStatusActive,
	}, "dep-primary-cp", "http://localhost")
	primaryDepID = primaryDep.ID

	// 1. Provider content_policy triggers content_policy_fallbacks (NOT general fallback).
	mode.Store(0)
	resp, meta, err := rm.ExecuteChat(ctx, &domain.IdentityContext{OrgID: org.ID}, &domain.CanonicalChatRequest{
		Model:    "cp-primary",
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "test"}},
	})
	if err != nil {
		t.Fatalf("ExecuteChat content policy fallback failed: %v", err)
	}
	if resp == nil || meta.WinningDeployment.ID != cpDepID {
		t.Fatalf("expected winning dep %s, got %+v", cpDepID, meta.WinningDeployment)
	}
	if !meta.FallbackAttempted || meta.FallbackReason != "content_policy_fallback" {
		t.Fatalf("expected FallbackAttempted=true, FallbackReason=content_policy_fallback; got %+v", meta)
	}
	if slices.Contains(adp.calls(), generalDepID) {
		t.Fatalf("general fallback %s must not be called when content_policy_fallbacks succeeds", generalDepID)
	}

	// 2. Local guardrail_blocked fails closed immediately with 0 retries and 0 fallbacks.
	adp.mu.Lock()
	adp.capturedCalls = nil
	adp.mu.Unlock()
	mode.Store(1)
	_, meta2, err2 := rm.ExecuteChat(ctx, &domain.IdentityContext{OrgID: org.ID}, &domain.CanonicalChatRequest{
		Model:    "cp-primary",
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "secret ssn"}},
	})
	var gwErr *domain.GatewayError
	if !errors.As(err2, &gwErr) || gwErr.Code != "guardrail_blocked" {
		t.Fatalf("expected guardrail_blocked error, got %v", err2)
	}
	if meta2.FallbackAttempted || meta2.RetryCount != 0 {
		t.Fatalf("expected zero retries and no fallback on local guardrail block, got %+v", meta2)
	}
	if calls := adp.calls(); len(calls) != 1 || calls[0] != primaryDepID {
		t.Fatalf("expected single call to primary before fail-closed abort, got %v", calls)
	}
	if state := rm.GetCircuitState(ctx, primaryDepID); state != CircuitClosed {
		t.Fatalf("local guardrail block must not trip circuit breaker, got %s", state)
	}
}

func TestV120_PerExceptionRetryPolicyAndLoneDeploymentSafetyNet(t *testing.T) {
	ctx := context.Background()

	t.Run("429_vs_400_vs_multi_and_single_deployment_401", func(t *testing.T) {
		cfg := config.RouterConfig{
			BaseRetryDelay:   time.Millisecond,
			MaxRetryDelay:    5 * time.Millisecond,
			FailureWindow:    time.Minute,
			FailureThreshold: 5,
			DefaultCooldown:  5 * time.Second,
			RetryPolicy: domain.RetryPolicy{
				RateLimitRetries:  2,
				BadRequestRetries: 0,
				AuthErrorRetries:  1,
				DefaultRetries:    1,
			},
		}
		repo, reg, vault, _, _, rm, org := newV120TestEnv(t, nil, cfg)

		var calls429 atomic.Int32
		var mode atomic.Int32 // 0=429->succeed on 3rd, 1=400, 2=401 on depA then ok on depB
		var depAuthA, depAuthB string

		adp := &v120MockAdapter{
			provider: domain.ProviderOpenAI,
			chatFn: func(_ context.Context, dep *domain.Deployment, req *domain.CanonicalChatRequest) (*domain.CanonicalChatResponse, error) {
				switch mode.Load() {
				case 0:
					if calls429.Add(1) < 3 {
						return nil, domain.ClassifyUpstreamStatus(domain.ProviderOpenAI, http.StatusTooManyRequests, "rate limit", 0)
					}
					return &domain.CanonicalChatResponse{ID: "ok-429", Provider: domain.ProviderOpenAI, Model: req.ResolvedModel}, nil
				case 1:
					return nil, domain.ClassifyUpstreamStatus(domain.ProviderOpenAI, http.StatusBadRequest, "bad schema", 0)
				default:
					if dep.ID == depAuthA {
						return nil, domain.ClassifyUpstreamStatus(domain.ProviderOpenAI, http.StatusUnauthorized, "bad api key", 0)
					}
					return &domain.CanonicalChatResponse{ID: "ok-" + dep.ID, Provider: domain.ProviderOpenAI, Model: req.ResolvedModel}, nil
				}
			},
		}
		reg.Register(adp)

		// Single-deployment group for 429 vs 400 vs single-dep 401.
		singleGroup := &domain.ModelGroup{OrgID: org.ID, Alias: "retry-single", RoutingStrategy: domain.StrategyRoundRobin, IsActive: true}
		_ = repo.CreateModelGroup(ctx, singleGroup)
		singleDep := registerV120ModelAndDep(t, repo, vault, org.ID, singleGroup, &domain.GlobalModel{
			ID: "openai/retry-single", Provider: domain.ProviderOpenAI, ModelName: "retry-single",
			SupportsInference: true, LifecycleStatus: domain.ModelStatusActive,
		}, "dep-single", "http://localhost")

		// 1) 429 retries twice and succeeds on 3rd attempt.
		mode.Store(0)
		resp, meta, err := rm.ExecuteChat(ctx, &domain.IdentityContext{OrgID: org.ID}, &domain.CanonicalChatRequest{
			Model: "retry-single", Messages: []domain.CanonicalMessage{{Role: "user", Content: "hi"}},
		})
		if err != nil || resp.ID != "ok-429" {
			t.Fatalf("expected 429 retry recovery, got resp=%+v err=%v", resp, err)
		}
		if meta.RetryCount != 2 || calls429.Load() != 3 {
			t.Fatalf("expected RetryCount=2 and 3 calls, got retry=%d calls=%d", meta.RetryCount, calls429.Load())
		}

		// 2) 400 fails immediately with 0 retries.
		adp.mu.Lock()
		adp.capturedCalls = nil
		adp.mu.Unlock()
		mode.Store(1)
		_, meta400, err400 := rm.ExecuteChat(ctx, &domain.IdentityContext{OrgID: org.ID}, &domain.CanonicalChatRequest{
			Model: "retry-single", Messages: []domain.CanonicalMessage{{Role: "user", Content: "hi"}},
		})
		if err400 == nil || meta400.RetryCount != 0 || len(adp.calls()) != 1 {
			t.Fatalf("expected immediate 400 abort with 1 call, got err=%v retry=%d calls=%v", err400, meta400.RetryCount, adp.calls())
		}

		// 3) Single-deployment 401 does NOT retry and trips cooldown immediately.
		adp.mu.Lock()
		adp.capturedCalls = nil
		adp.mu.Unlock()
		depAuthA = singleDep.ID
		mode.Store(2)
		_, metaSingleAuth, errSingleAuth := rm.ExecuteChat(ctx, &domain.IdentityContext{OrgID: org.ID}, &domain.CanonicalChatRequest{
			Model: "retry-single", Messages: []domain.CanonicalMessage{{Role: "user", Content: "hi"}},
		})
		if errSingleAuth == nil || metaSingleAuth.RetryCount != 0 || len(adp.calls()) != 1 {
			t.Fatalf("expected single-dep 401 to skip retry, got err=%v retry=%d calls=%v", errSingleAuth, metaSingleAuth.RetryCount, adp.calls())
		}
		if state := rm.GetCircuitState(ctx, singleDep.ID); state != CircuitOpen {
			t.Fatalf("expected single-dep 401 to trip circuit OPEN, got %s", state)
		}

		// 4) Multi-deployment 401 fails over from depA to depB and succeeds.
		multiGroup := &domain.ModelGroup{OrgID: org.ID, Alias: "retry-multi", RoutingStrategy: domain.StrategyRoundRobin, IsActive: true}
		_ = repo.CreateModelGroup(ctx, multiGroup)
		dep1 := registerV120ModelAndDep(t, repo, vault, org.ID, multiGroup, &domain.GlobalModel{
			ID: "openai/retry-multi", Provider: domain.ProviderOpenAI, ModelName: "retry-multi",
			SupportsInference: true, LifecycleStatus: domain.ModelStatusActive,
		}, "dep-auth-1", "http://localhost")
		dep2 := registerV120ModelAndDep(t, repo, vault, org.ID, multiGroup, &domain.GlobalModel{
			ID: "openai/retry-multi", Provider: domain.ProviderOpenAI, ModelName: "retry-multi",
			SupportsInference: true, LifecycleStatus: domain.ModelStatusActive,
		}, "dep-auth-2", "http://localhost")
		depAuthA = dep1.ID
		depAuthB = dep2.ID

		adp.mu.Lock()
		adp.capturedCalls = nil
		adp.mu.Unlock()
		respMulti, metaMulti, errMulti := rm.ExecuteChat(ctx, &domain.IdentityContext{OrgID: org.ID}, &domain.CanonicalChatRequest{
			Model: "retry-multi", Messages: []domain.CanonicalMessage{{Role: "user", Content: "hi"}},
		})
		if errMulti != nil || respMulti == nil {
			t.Fatalf("expected multi-dep 401 failover success, got err=%v", errMulti)
		}
		if metaMulti.WinningDeployment.ID != depAuthB || metaMulti.RetryCount != 1 {
			t.Fatalf("expected winning=%s retry=1, got winning=%v retry=%d", depAuthB, metaMulti.WinningDeployment.ID, metaMulti.RetryCount)
		}
		if rm.GetCircuitState(ctx, depAuthA) != CircuitOpen || rm.GetCircuitState(ctx, depAuthB) != CircuitClosed {
			t.Fatalf("expected depA OPEN and depB CLOSED, got A=%s B=%s", rm.GetCircuitState(ctx, depAuthA), rm.GetCircuitState(ctx, depAuthB))
		}
	})

	t.Run("lone_deployment_429_safety_net_and_capped_retry_after_and_failure_rate", func(t *testing.T) {
		mr := miniredis.RunT(t)
		rf := storage.NewRedisFabric(mr.Addr(), "", 0)
		defer rf.Client().Close()

		cfg := config.RouterConfig{
			BaseRetryDelay:    time.Millisecond,
			MaxRetryDelay:     3 * time.Millisecond,
			FailureWindow:     time.Minute,
			FailureThreshold:  2,
			DefaultCooldown:   30 * time.Second,
			DefaultMaxRetries: 0,
			CooldownPolicy: domain.CooldownPolicy{
				MaxCooldownSeconds: 2,
			},
		}
		repo, reg, vault, _, _, rm, org := newV120TestEnv(t, rf, cfg)

		var return429 atomic.Bool
		return429.Store(true)
		var retryAfter atomic.Int32
		adp := &v120MockAdapter{
			provider: domain.ProviderOpenAI,
			chatFn: func(_ context.Context, dep *domain.Deployment, req *domain.CanonicalChatRequest) (*domain.CanonicalChatResponse, error) {
				if return429.Load() {
					return nil, domain.ClassifyUpstreamStatus(domain.ProviderOpenAI, http.StatusTooManyRequests, "slow down", int(retryAfter.Load()))
				}
				return &domain.CanonicalChatResponse{ID: "ok-" + dep.ID, Provider: domain.ProviderOpenAI, Model: req.ResolvedModel}, nil
			},
		}
		reg.Register(adp)

		// 1) Lone deployment with no fallbacks and no AllowedFails["rate_limit"] override: never blacklists on 429.
		loneGroup := &domain.ModelGroup{
			OrgID:            org.ID,
			Alias:            "lone-429",
			RoutingStrategy:  domain.StrategyWeightedShuffle,
			FailureThreshold: 1,
			IsActive:         true,
		}
		_ = repo.CreateModelGroup(ctx, loneGroup)
		loneDep := registerV120ModelAndDep(t, repo, vault, org.ID, loneGroup, &domain.GlobalModel{
			ID: "openai/lone-429", Provider: domain.ProviderOpenAI, ModelName: "lone-429",
			SupportsInference: true, LifecycleStatus: domain.ModelStatusActive,
		}, "dep-lone", "http://localhost")

		for i := 0; i < 4; i++ {
			_, _, err := rm.ExecuteChat(ctx, &domain.IdentityContext{OrgID: org.ID}, &domain.CanonicalChatRequest{
				Model: "lone-429", Messages: []domain.CanonicalMessage{{Role: "user", Content: "hi"}},
			})
			if err == nil {
				t.Fatal("expected 429 error")
			}
			if state := rm.GetCircuitState(ctx, loneDep.ID); state != CircuitClosed {
				t.Fatalf("lone deployment must remain CLOSED on transient 429 (iter %d), got %s", i, state)
			}
		}

		// 2) Explicit AllowedFails["rate_limit"]=2 overrides lone-deployment protection and honors Retry-After capped by MaxCooldownSeconds=2.
		retryAfter.Store(600)
		loneGroup2 := &domain.ModelGroup{
			OrgID:            org.ID,
			Alias:            "lone-429-override",
			RoutingStrategy:  domain.StrategyWeightedShuffle,
			FailureThreshold: 1,
			CooldownPolicy: &domain.CooldownPolicy{
				AllowedFails:       map[string]int{"rate_limit": 2},
				MaxCooldownSeconds: 2,
			},
			IsActive: true,
		}
		_ = repo.CreateModelGroup(ctx, loneGroup2)
		loneDep2 := registerV120ModelAndDep(t, repo, vault, org.ID, loneGroup2, &domain.GlobalModel{
			ID: "openai/lone-429", Provider: domain.ProviderOpenAI, ModelName: "lone-429",
			SupportsInference: true, LifecycleStatus: domain.ModelStatusActive,
		}, "dep-lone-override", "http://localhost")

		_, _, _ = rm.ExecuteChat(ctx, &domain.IdentityContext{OrgID: org.ID}, &domain.CanonicalChatRequest{
			Model: "lone-429-override", Messages: []domain.CanonicalMessage{{Role: "user", Content: "hi"}},
		})
		if rm.GetCircuitState(ctx, loneDep2.ID) != CircuitClosed {
			t.Fatal("expected CLOSED after 1st 429 when AllowedFails[rate_limit]=2")
		}
		_, _, _ = rm.ExecuteChat(ctx, &domain.IdentityContext{OrgID: org.ID}, &domain.CanonicalChatRequest{
			Model: "lone-429-override", Messages: []domain.CanonicalMessage{{Role: "user", Content: "hi"}},
		})
		if rm.GetCircuitState(ctx, loneDep2.ID) != CircuitOpen {
			t.Fatal("expected OPEN after 2nd 429 when AllowedFails[rate_limit]=2")
		}
		// Verify cooldown was capped to 2s (not 600s).
		mr.FastForward(2*time.Second + 100*time.Millisecond)
		if state := rm.GetCircuitState(ctx, loneDep2.ID); state != CircuitHalfOpen {
			t.Fatalf("expected HALF_OPEN after capped 2s cooldown, got %s", state)
		}

		// 3) 1m failure rate threshold trip with MinRequestsPerMinute on a non-lone group.
		rateGroup := &domain.ModelGroup{
			OrgID:            org.ID,
			Alias:            "rate-trip",
			RoutingStrategy:  domain.StrategyRoundRobin,
			FailureThreshold: 100, // high fixed threshold so only failure rate trips
			CooldownPolicy: &domain.CooldownPolicy{
				FailureRateThreshold: 0.5,
				MinRequestsPerMinute: 4,
				MaxCooldownSeconds:   10,
			},
			IsActive: true,
		}
		_ = repo.CreateModelGroup(ctx, rateGroup)
		rateDep := registerV120ModelAndDep(t, repo, vault, org.ID, rateGroup, &domain.GlobalModel{
			ID: "openai/rate-trip", Provider: domain.ProviderOpenAI, ModelName: "rate-trip",
			SupportsInference: true, LifecycleStatus: domain.ModelStatusActive,
		}, "dep-rate-1", "http://localhost")
		_ = registerV120ModelAndDep(t, repo, vault, org.ID, rateGroup, &domain.GlobalModel{
			ID: "openai/rate-trip", Provider: domain.ProviderOpenAI, ModelName: "rate-trip",
			SupportsInference: true, LifecycleStatus: domain.ModelStatusActive,
		}, "dep-rate-2", "http://localhost")

		// Seed 2 successes + 1 failure for dep-rate-1 -> 3 reqs (< MinRequestsPerMinute=4) -> stays CLOSED.
		rm.recordSuccess(ctx, rateDep)
		rm.recordSuccess(ctx, rateDep)
		rm.recordAttemptFailure(ctx, rateDep, rateGroup, 2, errors.New("boom"))
		if rm.GetCircuitState(ctx, rateDep.ID) != CircuitClosed {
			t.Fatal("expected CLOSED before MinRequestsPerMinute=4 is reached")
		}
		// 2nd failure -> 4 reqs, 2 fails = 50% >= 0.5 -> trips OPEN!
		rm.recordAttemptFailure(ctx, rateDep, rateGroup, 2, errors.New("boom"))
		if rm.GetCircuitState(ctx, rateDep.ID) != CircuitOpen {
			t.Fatal("expected OPEN once 1m failure rate reaches 0.5 with 4 requests")
		}
	})
}

func TestV120_FilterChainRegionTagsPluginCapacityBudgetsAndScheduler(t *testing.T) {
	ctx := context.Background()
	mr := miniredis.RunT(t)
	rf := storage.NewRedisFabric(mr.Addr(), "", 0)
	defer rf.Client().Close()

	cfg := config.RouterConfig{
		BaseRetryDelay:          time.Millisecond,
		MaxRetryDelay:           5 * time.Millisecond,
		StrictCapacityFiltering: true,
		ProviderBudgets: map[string]int64{
			string(domain.ProviderAnthropic): 1000,
		},
	}
	repo, reg, vault, _, lb, rm, org := newV120TestEnv(t, rf, cfg)

	oaiAdp := &v120MockAdapter{provider: domain.ProviderOpenAI}
	antAdp := &v120MockAdapter{provider: domain.ProviderAnthropic}
	reg.Register(oaiAdp)
	reg.Register(antAdp)

	budgets := NewDeploymentBudgetTracker(rf)
	rm.SetDeploymentBudgetTracker(budgets)

	group := &domain.ModelGroup{OrgID: org.ID, Alias: "filtered-group", RoutingStrategy: domain.StrategyRoundRobin, IsActive: true}
	_ = repo.CreateModelGroup(ctx, group)

	makeDep := func(name string, prov domain.ProviderType, region string, tags []string, rpm, tpm int, maxBudget int64) *domain.Deployment {
		gm := &domain.GlobalModel{
			ID: string(prov) + "/m-" + name, Provider: prov, ModelName: "m-" + name,
			SupportsInference: true, LifecycleStatus: domain.ModelStatusActive,
		}
		if err := repo.UpsertGlobalModel(ctx, gm); err != nil {
			t.Fatalf("UpsertGlobalModel: %v", err)
		}
		cred := &domain.ProviderCredential{
			OrgID:    org.ID,
			Provider: gm.Provider,
			Name:     "cred-" + name,
			BaseURL:  "http://localhost",
			IsActive: true,
		}
		if err := vault.EncryptCredential(cred, "sk-test-"+name); err != nil {
			t.Fatalf("EncryptCredential: %v", err)
		}
		if err := repo.CreateProviderCredential(ctx, cred); err != nil {
			t.Fatalf("CreateProviderCredential: %v", err)
		}
		d := &domain.Deployment{
			ModelGroupID:    group.ID,
			GlobalModelID:   gm.ID,
			CredentialID:    cred.ID,
			DeploymentName:  name,
			Region:          region,
			Tags:            tags,
			Weight:          100,
			RPMCapacity:     rpm,
			TPMCapacity:     tpm,
			MaxBudgetMicros: maxBudget,
			Status:          domain.DeploymentStatusActive,
		}
		if err := repo.CreateDeployment(ctx, d); err != nil {
			t.Fatalf("CreateDeployment: %v", err)
		}
		return d
	}

	_ = makeDep("us-dep", domain.ProviderOpenAI, "us-east", []string{"gpu", "v2-fast"}, 100, 100000, 0)
	_ = makeDep("eu-legacy", domain.ProviderOpenAI, "eu-west", []string{"gpu", "legacy", "v2-fast"}, 100, 100000, 0)
	depSat := makeDep("eu-saturated", domain.ProviderOpenAI, "eu-west", []string{"gpu", "v2-fast"}, 1, 100000, 0)
	depBudExp := makeDep("eu-budget-exhausted", domain.ProviderOpenAI, "eu-west", []string{"gpu", "v2-fast"}, 100, 100000, 500)
	depProvBud := makeDep("eu-prov-budget", domain.ProviderAnthropic, "eu-west", []string{"gpu", "v2-fast"}, 100, 100000, 0)
	depPluginOut := makeDep("eu-plugin-excluded", domain.ProviderOpenAI, "eu-west", []string{"gpu", "v2-fast"}, 100, 100000, 0)
	depWinner := makeDep("eu-winner", domain.ProviderOpenAI, "eu-west", []string{"gpu", "v2-fast"}, 100, 100000, 5000)

	// Saturate depSat's 1 RPM capacity.
	lb.OnRequestStart(depSat.ID)
	lb.OnRequestEnd(depSat.ID, 5, 10)

	// Exhaust depBudExp's 500 micro-dollar cap and Anthropic's 1000 provider cap.
	budgets.RecordSpend(ctx, org.ID, depBudExp.ID, "", depBudExp.BudgetResetPeriod, 500)
	budgets.RecordSpend(ctx, org.ID, "", string(domain.ProviderAnthropic), "", 1000)

	// Register RoutingPlugin that filters out depPluginOut.
	rm.SetRoutingPlugins(RoutingPluginFunc{
		PluginName: "exclude-specific",
		Fn: func(_ context.Context, rc *RoutingContext) ([]*domain.Deployment, error) {
			var kept []*domain.Deployment
			for _, d := range rc.Candidates {
				if d.ID != depPluginOut.ID {
					kept = append(kept, d)
				}
			}
			return kept, nil
		},
	})

	req := &domain.CanonicalChatRequest{
		Model:    "filtered-group",
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "route me"}},
		GoRouteExtensions: &domain.GoRouteExtensions{
			AllowedRegion: "eu-west",
			Tags:          []string{"&gpu", "!legacy", "v2*"},
		},
	}
	resp, meta, err := rm.ExecuteChat(ctx, &domain.IdentityContext{OrgID: org.ID}, req)
	if err != nil {
		t.Fatalf("ExecuteChat failed: %v", err)
	}
	if resp == nil || meta.WinningDeployment == nil || meta.WinningDeployment.ID != depWinner.ID {
		t.Fatalf("expected winning dep %s (%s), got %+v (provBud=%s)", depWinner.ID, depWinner.DeploymentName, meta.WinningDeployment, depProvBud.ID)
	}

	// Verify PriorityScheduler integration (bounded concurrency + priority ordering + shedding).
	gate := make(chan struct{})
	started := make(chan struct{}, 1)
	var execOrder []string
	var orderMu sync.Mutex

	schedGroup := &domain.ModelGroup{OrgID: org.ID, Alias: "sched-group", RoutingStrategy: domain.StrategyRoundRobin, IsActive: true}
	_ = repo.CreateModelGroup(ctx, schedGroup)
	_ = registerV120ModelAndDep(t, repo, vault, org.ID, schedGroup, &domain.GlobalModel{
		ID: "openai/sched", Provider: domain.ProviderOpenAI, ModelName: "sched",
		SupportsInference: true, LifecycleStatus: domain.ModelStatusActive,
	}, "dep-sched", "http://localhost")

	oaiAdp.chatFn = func(_ context.Context, dep *domain.Deployment, req *domain.CanonicalChatRequest) (*domain.CanonicalChatResponse, error) {
		tag := req.Messages[0].Content
		if tag == "inflight" {
			select {
			case started <- struct{}{}:
			default:
			}
			<-gate
		}
		orderMu.Lock()
		execOrder = append(execOrder, tag)
		orderMu.Unlock()
		return &domain.CanonicalChatResponse{ID: "sched-" + tag, Provider: domain.ProviderOpenAI, Model: req.ResolvedModel}, nil
	}

	sched := NewPriorityScheduler(1, 2, time.Second)
	rm.SetScheduler(sched)
	rm.SetRoutingPlugins()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, _, _ = rm.ExecuteChat(ctx, &domain.IdentityContext{OrgID: org.ID}, &domain.CanonicalChatRequest{
			Model: "sched-group", Messages: []domain.CanonicalMessage{{Role: "user", Content: "inflight"}},
			GoRouteExtensions: &domain.GoRouteExtensions{Priority: 5},
		})
	}()
	<-started

	// Queue low priority (10) then high priority (0); 3rd queued request must be shed immediately.
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _, _ = rm.ExecuteChat(ctx, &domain.IdentityContext{OrgID: org.ID}, &domain.CanonicalChatRequest{
			Model: "sched-group", Messages: []domain.CanonicalMessage{{Role: "user", Content: "low"}},
			GoRouteExtensions: &domain.GoRouteExtensions{Priority: 10},
		})
	}()
	// Wait briefly until low priority is queued.
	for sched.Stats().Queued < 1 {
		time.Sleep(2 * time.Millisecond)
	}
	go func() {
		defer wg.Done()
		_, _, _ = rm.ExecuteChat(ctx, &domain.IdentityContext{OrgID: org.ID}, &domain.CanonicalChatRequest{
			Model: "sched-group", Messages: []domain.CanonicalMessage{{Role: "user", Content: "high"}},
			GoRouteExtensions: &domain.GoRouteExtensions{Priority: 0},
		})
	}()
	for sched.Stats().Queued < 2 {
		time.Sleep(2 * time.Millisecond)
	}

	_, _, shedErr := rm.ExecuteChat(ctx, &domain.IdentityContext{OrgID: org.ID}, &domain.CanonicalChatRequest{
		Model: "sched-group", Messages: []domain.CanonicalMessage{{Role: "user", Content: "shed"}},
	})
	var gwErr *domain.GatewayError
	if !errors.As(shedErr, &gwErr) || gwErr.Code != "scheduler_queue_full" {
		t.Fatalf("expected scheduler_queue_full error, got %v", shedErr)
	}

	close(gate)
	wg.Wait()

	orderMu.Lock()
	gotOrder := slices.Clone(execOrder)
	orderMu.Unlock()
	if !slices.Equal(gotOrder, []string{"inflight", "high", "low"}) {
		t.Fatalf("expected execution order [inflight high low], got %v", gotOrder)
	}
}

func TestV120_AffinityPinAndFailoverRepin(t *testing.T) {
	ctx := context.Background()
	mr := miniredis.RunT(t)
	rf := storage.NewRedisFabric(mr.Addr(), "", 0)
	defer rf.Client().Close()

	cfg := config.RouterConfig{
		BaseRetryDelay:                 time.Millisecond,
		MaxRetryDelay:                  5 * time.Millisecond,
		DefaultMaxRetries:              1,
		DefaultCooldown:                5 * time.Second,
		FailureThreshold:               1,
		SessionAffinityTTL:             10 * time.Minute,
		SessionAffinityRepinOnFailover: true,
		PromptCacheAffinity:            true,
	}
	repo, reg, vault, rbac, lb, rm1, org := newV120TestEnv(t, rf, cfg)
	aff1 := NewAffinityStoreFromRouterConfig(rf, cfg)
	rm1.SetAffinityStore(aff1)

	var failDepID atomic.Value
	failDepID.Store("")
	adp := &v120MockAdapter{
		provider: domain.ProviderOpenAI,
		chatFn: func(_ context.Context, dep *domain.Deployment, req *domain.CanonicalChatRequest) (*domain.CanonicalChatResponse, error) {
			if target, _ := failDepID.Load().(string); target != "" && dep.ID == target {
				return nil, domain.ClassifyUpstreamStatus(domain.ProviderOpenAI, http.StatusServiceUnavailable, "down", 0)
			}
			return &domain.CanonicalChatResponse{ID: "ok-" + dep.ID, Provider: domain.ProviderOpenAI, Model: req.ResolvedModel}, nil
		},
	}
	reg.Register(adp)

	group := &domain.ModelGroup{OrgID: org.ID, Alias: "aff-group", RoutingStrategy: domain.StrategyRoundRobin, MaxRetries: 1, FailureThreshold: 1, CooldownSeconds: 1, IsActive: true}
	_ = repo.CreateModelGroup(ctx, group)
	dep1 := registerV120ModelAndDep(t, repo, vault, org.ID, group, &domain.GlobalModel{
		ID: "openai/aff", Provider: domain.ProviderOpenAI, ModelName: "aff",
		SupportsInference: true, LifecycleStatus: domain.ModelStatusActive,
	}, "dep-1", "http://localhost")
	dep2 := registerV120ModelAndDep(t, repo, vault, org.ID, group, &domain.GlobalModel{
		ID: "openai/aff", Provider: domain.ProviderOpenAI, ModelName: "aff",
		SupportsInference: true, LifecycleStatus: domain.ModelStatusActive,
	}, "dep-2", "http://localhost")

	// 1. First request with SessionID pins to a deployment (dep1 under round-robin).
	_, meta1, err := rm1.ExecuteChat(ctx, &domain.IdentityContext{OrgID: org.ID}, &domain.CanonicalChatRequest{
		Model:             "aff-group",
		Messages:          []domain.CanonicalMessage{{Role: "user", Content: "hello"}},
		GoRouteExtensions: &domain.GoRouteExtensions{SessionID: "sess-123"},
	})
	if err != nil {
		t.Fatalf("first session request failed: %v", err)
	}
	pinnedID := meta1.WinningDeployment.ID
	if err := aff1.Wait(ctx); err != nil {
		t.Fatalf("aff1.Wait: %v", err)
	}

	// 2. Second ReliabilityManager sharing miniredis resolves the same pinned deployment across multiple calls.
	rm2 := NewReliabilityManager(repo, reg, NewIntelligentRouter(repo, cfg), lb, vault, rbac, rf, cfg)
	aff2 := NewAffinityStoreFromRouterConfig(rf, cfg)
	rm2.SetAffinityStore(aff2)
	for i := 0; i < 3; i++ {
		_, metaN, err := rm2.ExecuteChat(ctx, &domain.IdentityContext{OrgID: org.ID}, &domain.CanonicalChatRequest{
			Model:             "aff-group",
			Messages:          []domain.CanonicalMessage{{Role: "user", Content: "turn"}},
			GoRouteExtensions: &domain.GoRouteExtensions{SessionID: "sess-123"},
		})
		if err != nil {
			t.Fatalf("sticky session request %d failed: %v", i, err)
		}
		if metaN.WinningDeployment.ID != pinnedID {
			t.Fatalf("expected sticky dep %s, got %s", pinnedID, metaN.WinningDeployment.ID)
		}
	}

	// 3. Failover re-pinning: fail pinnedID -> routes to otherID and re-pins sess-123 to otherID.
	failDepID.Store(pinnedID)
	_, metaFailover, err := rm2.ExecuteChat(ctx, &domain.IdentityContext{OrgID: org.ID}, &domain.CanonicalChatRequest{
		Model:             "aff-group",
		Messages:          []domain.CanonicalMessage{{Role: "user", Content: "failover"}},
		GoRouteExtensions: &domain.GoRouteExtensions{SessionID: "sess-123"},
	})
	if err != nil {
		t.Fatalf("failover session request failed: %v", err)
	}
	otherID := dep2.ID
	if pinnedID == dep2.ID {
		otherID = dep1.ID
	}
	if metaFailover.WinningDeployment.ID != otherID {
		t.Fatalf("expected failover to %s, got %s", otherID, metaFailover.WinningDeployment.ID)
	}
	if err := aff2.Wait(ctx); err != nil {
		t.Fatalf("aff2.Wait: %v", err)
	}

	// Verify Redis was updated to the new pinned deployment, and stays pinned on a fresh pod even after pinnedID recovers.
	failDepID.Store("")
	mr.FastForward(2 * time.Second)
	for _, k := range circuitKeys(pinnedID) {
		mr.Del(k)
	}
	pinnedDep := dep1
	if pinnedID == dep2.ID {
		pinnedDep = dep2
	}
	rm1.recordSuccess(ctx, pinnedDep)
	rm2.recordSuccess(ctx, pinnedDep)
	rm3 := NewReliabilityManager(repo, reg, NewIntelligentRouter(repo, cfg), lb, vault, rbac, rf, cfg)
	aff3 := NewAffinityStoreFromRouterConfig(rf, cfg)
	rm3.SetAffinityStore(aff3)
	_, metaAfter, err := rm3.ExecuteChat(ctx, &domain.IdentityContext{OrgID: org.ID}, &domain.CanonicalChatRequest{
		Model:             "aff-group",
		Messages:          []domain.CanonicalMessage{{Role: "user", Content: "post-repin"}},
		GoRouteExtensions: &domain.GoRouteExtensions{SessionID: "sess-123"},
	})
	if err != nil {
		t.Fatalf("post-repin request failed: %v", err)
	}
	if metaAfter.WinningDeployment.ID != otherID {
		t.Fatalf("expected session re-pinned to %s, got %s", otherID, metaAfter.WinningDeployment.ID)
	}

	// 4. Verify previous_response_id (ExtraParams) and PromptCacheAffinity pins.
	aff1.PinAsync(org.ID, ResponseAffinityKey(org.ID, "resp_1"), dep1.ID, time.Minute)
	aff1.PinAsync(org.ID, ResponseAffinityKey(org.ID, "resp_abc"), dep2.ID, time.Minute)
	if err := aff1.Wait(ctx); err != nil {
		t.Fatal(err)
	}
	_, metaResp1, err := rm2.ExecuteChat(ctx, &domain.IdentityContext{OrgID: org.ID}, &domain.CanonicalChatRequest{
		Model:       "aff-group",
		Messages:    []domain.CanonicalMessage{{Role: "user", Content: "follow-up-1"}},
		ExtraParams: map[string]any{"previous_response_id": "resp_1"},
	})
	if err != nil || metaResp1.WinningDeployment.ID != dep1.ID {
		t.Fatalf("expected previous_response_id affinity to %s, got %+v (err=%v)", dep1.ID, metaResp1, err)
	}
	_, metaRespID, err := rm2.ExecuteChat(ctx, &domain.IdentityContext{OrgID: org.ID}, &domain.CanonicalChatRequest{
		Model:       "aff-group",
		Messages:    []domain.CanonicalMessage{{Role: "user", Content: "follow-up"}},
		ExtraParams: map[string]any{"previous_response_id": "resp_abc"},
	})
	if err != nil || metaRespID.WinningDeployment.ID != dep2.ID {
		t.Fatalf("expected previous_response_id affinity to %s, got %+v (err=%v)", dep2.ID, metaRespID, err)
	}

	// PromptCacheAffinity pins first N system/user messages.
	_, metaPC1, err := rm1.ExecuteChat(ctx, &domain.IdentityContext{OrgID: org.ID}, &domain.CanonicalChatRequest{
		Model: "aff-group",
		Messages: []domain.CanonicalMessage{
			{Role: "system", Content: "Shared long system prompt"},
			{Role: "user", Content: "Question 1"},
		},
	})
	if err != nil {
		t.Fatalf("prompt cache req 1 failed: %v", err)
	}
	if err := aff1.Wait(ctx); err != nil {
		t.Fatal(err)
	}
	_, metaPC2, err := rm2.ExecuteChat(ctx, &domain.IdentityContext{OrgID: org.ID}, &domain.CanonicalChatRequest{
		Model: "aff-group",
		Messages: []domain.CanonicalMessage{
			{Role: "system", Content: "Shared long system prompt"},
			{Role: "user", Content: "Question 1"},
			{Role: "assistant", Content: "Answer 1"},
			{Role: "user", Content: "Question 2"},
		},
	})
	if err != nil {
		t.Fatalf("prompt cache req 2 failed: %v", err)
	}
	if metaPC2.WinningDeployment.ID != metaPC1.WinningDeployment.ID {
		t.Fatalf("expected prompt cache affinity to %s, got %s", metaPC1.WinningDeployment.ID, metaPC2.WinningDeployment.ID)
	}
}

func TestV120_MidStreamSSEContinuationAndRefusals(t *testing.T) {
	ctx := context.Background()

	t.Run("sse_drops_after_3_chunks_and_continues_with_prefill_combined_usage_and_otel_event", func(t *testing.T) {
		var srvACalls atomic.Int32
		srvA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			srvACalls.Add(1)
			hj, ok := w.(http.Hijacker)
			if !ok {
				t.Fatalf("ResponseWriter does not implement http.Hijacker")
			}
			conn, buf, err := hj.Hijack()
			if err != nil {
				t.Fatalf("Hijack: %v", err)
			}
			defer conn.Close()
			_, _ = buf.WriteString("HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n")
			sseBody := strings.Join([]string{
				`data: {"id":"c1","choices":[{"index":0,"delta":{"content":"Hello "}}]}` + "\n\n",
				`data: {"id":"c2","choices":[{"index":0,"delta":{"content":"streaming "}}]}` + "\n\n",
				`data: {"id":"c3","choices":[{"index":0,"delta":{"content":"world"}}],"usage":{"prompt_tokens":10,"completion_tokens":3,"total_tokens":13}}` + "\n\n",
			}, "")
			_, _ = fmt.Fprintf(buf, "%x\r\n%s\r\n", len(sseBody), sseBody)
			// Intentionally omit terminating 0-length chunk so client reads io.ErrUnexpectedEOF mid-stream.
			_ = buf.Flush()
		}))
		defer srvA.Close()

		var srvBBody map[string]any
		var srvBCalls atomic.Int32
		srvB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			srvBCalls.Add(1)
			raw, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(raw, &srvBBody)
			w.Header().Set("Content-Type", "text/event-stream")
			flusher, _ := w.(http.Flusher)
			fmt.Fprint(w, "data: {\"id\":\"c4\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\" continued!\"}}],\"usage\":{\"prompt_tokens\":15,\"completion_tokens\":2,\"total_tokens\":17}}\n\n")
			fmt.Fprint(w, "data: [DONE]\n\n")
			if flusher != nil {
				flusher.Flush()
			}
		}))
		defer srvB.Close()

		cfg := config.RouterConfig{
			BaseRetryDelay:              time.Millisecond,
			MaxRetryDelay:               5 * time.Millisecond,
			EnableMidStreamContinuation: true,
			MaxStreamContinuations:      1,
		}
		repo, reg, vault, _, _, rm, org := newV120TestEnv(t, nil, cfg)

		pol, err := network.NewPolicy(config.OutboundSSRFConfig{AllowPrivateNetworks: true, AllowInsecureHTTP: true})
		if err != nil {
			t.Fatalf("network.NewPolicy: %v", err)
		}
		oaiAdp := openai.NewAdapter(srvA.Client())
		oaiAdp.SetSSRFPolicy(pol)
		reg.Register(oaiAdp)

		sr := tracetest.NewSpanRecorder()
		tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sr))
		defer func() { _ = tp.Shutdown(ctx) }()
		rm.SetTracer(tp.Tracer("v120-test"))

		group := &domain.ModelGroup{OrgID: org.ID, Alias: "stream-cont", RoutingStrategy: domain.StrategyRoundRobin, IsActive: true}
		_ = repo.CreateModelGroup(ctx, group)
		_ = registerV120ModelAndDep(t, repo, vault, org.ID, group, &domain.GlobalModel{
			ID: "openai/gpt-4o", Provider: domain.ProviderOpenAI, ModelName: "gpt-4o",
			SupportsInference: true, SupportsStreaming: true, LifecycleStatus: domain.ModelStatusActive,
		}, "dep-a", srvA.URL)
		// Place dep-b in priority tier 1 so dep-a is deterministically tried first and dep-b handles continuation.
		credB := &domain.ProviderCredential{
			OrgID:    org.ID,
			Provider: domain.ProviderOpenAI,
			Name:     "cred-dep-b",
			BaseURL:  srvB.URL,
			IsActive: true,
		}
		if err := vault.EncryptCredential(credB, "sk-test-dep-b"); err != nil {
			t.Fatalf("EncryptCredential: %v", err)
		}
		if err := repo.CreateProviderCredential(ctx, credB); err != nil {
			t.Fatalf("CreateProviderCredential: %v", err)
		}
		depB := &domain.Deployment{
			ModelGroupID:   group.ID,
			GlobalModelID:  "openai/gpt-4o",
			CredentialID:   credB.ID,
			DeploymentName: "dep-b",
			Weight:         100,
			Priority:       1,
			Status:         domain.DeploymentStatusActive,
		}
		if err := repo.CreateDeployment(ctx, depB); err != nil {
			t.Fatalf("CreateDeployment: %v", err)
		}

		maxTok := 20
		var emitted strings.Builder
		usage, meta, err := rm.ExecuteStream(ctx, &domain.IdentityContext{OrgID: org.ID}, &domain.CanonicalChatRequest{
			Model:     "stream-cont",
			Stream:    true,
			MaxTokens: &maxTok,
			Messages:  []domain.CanonicalMessage{{Role: "user", Content: "Say hello"}},
		}, func(chunk *domain.CanonicalStreamChunk) error {
			for _, ch := range chunk.Choices {
				emitted.WriteString(ch.Delta.Content)
			}
			return nil
		}, nil)
		if err != nil {
			t.Fatalf("ExecuteStream mid-stream continuation failed: %v", err)
		}
		if emitted.String() != "Hello streaming world continued!" {
			t.Fatalf("emitted text = %q, want %q", emitted.String(), "Hello streaming world continued!")
		}
		if !meta.StreamContinued {
			t.Fatal("expected meta.StreamContinued = true")
		}
		if meta.WinningDeployment == nil || meta.WinningDeployment.ID != depB.ID {
			t.Fatalf("expected winning dep %s, got %+v", depB.ID, meta.WinningDeployment)
		}
		if srvACalls.Load() != 1 || srvBCalls.Load() != 1 {
			t.Fatalf("expected 1 call each to srvA and srvB, got A=%d B=%d", srvACalls.Load(), srvBCalls.Load())
		}
		if usage == nil || usage.PromptTokens != 25 || usage.CompletionTokens != 5 || usage.TotalTokens != 30 {
			t.Fatalf("unexpected combined usage: %+v", usage)
		}

		// Verify Server B received trailing assistant prefill and adjusted max_tokens.
		msgs, _ := srvBBody["messages"].([]any)
		if len(msgs) != 2 {
			t.Fatalf("expected 2 messages on continuation request, got %d (%+v)", len(msgs), srvBBody)
		}
		lastMsg, _ := msgs[1].(map[string]any)
		if lastMsg["role"] != "assistant" || lastMsg["content"] != "Hello streaming world" {
			t.Fatalf("unexpected assistant prefill message: %+v", lastMsg)
		}
		if gotMax, ok := srvBBody["max_completion_tokens"].(float64); !ok || int(gotMax) >= maxTok {
			t.Fatalf("expected adjusted max_completion_tokens < %d, got %v", maxTok, srvBBody["max_completion_tokens"])
		}

		// Verify OTel event router.stream_continuation was emitted.
		foundEvent := false
		for _, sp := range sr.Ended() {
			for _, ev := range sp.Events() {
				if ev.Name == "router.stream_continuation" {
					foundEvent = true
					break
				}
			}
		}
		if !foundEvent {
			t.Fatal("expected router.stream_continuation OTel event")
		}
	})

	t.Run("refuses_continuation_for_tool_calls_json_schema_and_non_prefill_adapter", func(t *testing.T) {
		cfg := config.RouterConfig{
			BaseRetryDelay:              time.Millisecond,
			MaxRetryDelay:               5 * time.Millisecond,
			EnableMidStreamContinuation: true,
			MaxStreamContinuations:      1,
		}
		repo, reg, vault, _, _, rm, org := newV120TestEnv(t, nil, cfg)

		var emitToolCalls atomic.Bool
		var dep2Calls atomic.Int32
		adp := &v120MockAdapter{
			provider:     domain.ProviderOpenAI,
			supportsPref: true,
			streamFn: func(_ context.Context, dep *domain.Deployment, _ *domain.CanonicalChatRequest, onChunk adapter.StreamChunkHandler) (*domain.TokenUsage, error) {
				if strings.HasSuffix(dep.DeploymentName, "-2") {
					dep2Calls.Add(1)
					return &domain.TokenUsage{TotalTokens: 1}, nil
				}
				if emitToolCalls.Load() {
					_ = onChunk(&domain.CanonicalStreamChunk{
						ID: "tc1",
						Choices: []domain.CanonicalStreamChoice{{
							Index: 0,
							Delta: domain.CanonicalStreamDelta{ToolCalls: []domain.CanonicalToolCall{{ID: "call_1"}}},
						}},
					})
				} else {
					_ = onChunk(&domain.CanonicalStreamChunk{
						ID:      "js1",
						Choices: []domain.CanonicalStreamChoice{{Index: 0, Delta: domain.CanonicalStreamDelta{Content: "{\"a\":"}}},
					})
				}
				return nil, io.ErrUnexpectedEOF
			},
		}
		reg.Register(adp)

		group := &domain.ModelGroup{OrgID: org.ID, Alias: "refuse-group", RoutingStrategy: domain.StrategyWeightedShuffle, IsActive: true}
		_ = repo.CreateModelGroup(ctx, group)
		_ = registerV120ModelAndDep(t, repo, vault, org.ID, group, &domain.GlobalModel{
			ID: "openai/refuse", Provider: domain.ProviderOpenAI, ModelName: "refuse",
			SupportsInference: true, SupportsStreaming: true, Capabilities: domain.ModelCapabilities{Streaming: domain.CapabilitySupported, StructuredOutputs: domain.CapabilitySupported},
			LifecycleStatus: domain.ModelStatusActive,
		}, "dep-1", "http://localhost")
		// Place dep-2 in priority tier 1 so dep-1 is always attempted first while dep-2 remains available for continuation.
		gmRefuse := &domain.GlobalModel{
			ID: "openai/refuse", Provider: domain.ProviderOpenAI, ModelName: "refuse",
			SupportsInference: true, SupportsStreaming: true, Capabilities: domain.ModelCapabilities{Streaming: domain.CapabilitySupported, StructuredOutputs: domain.CapabilitySupported},
			LifecycleStatus: domain.ModelStatusActive,
		}
		_ = repo.UpsertGlobalModel(ctx, gmRefuse)
		cred2 := &domain.ProviderCredential{OrgID: org.ID, Provider: domain.ProviderOpenAI, Name: "cred-dep-2", BaseURL: "http://localhost", IsActive: true}
		_ = vault.EncryptCredential(cred2, "sk-test-dep-2")
		_ = repo.CreateProviderCredential(ctx, cred2)
		_ = repo.CreateDeployment(ctx, &domain.Deployment{
			ModelGroupID: group.ID, GlobalModelID: gmRefuse.ID, CredentialID: cred2.ID,
			DeploymentName: "dep-2", Weight: 100, Priority: 1, Status: domain.DeploymentStatusActive,
		})

		// 1. Tool-call delta refusal.
		emitToolCalls.Store(true)
		_, metaTool, errTool := rm.ExecuteStream(ctx, &domain.IdentityContext{OrgID: org.ID}, &domain.CanonicalChatRequest{
			Model:    "refuse-group",
			Stream:   true,
			Messages: []domain.CanonicalMessage{{Role: "user", Content: "call tool"}},
		}, func(*domain.CanonicalStreamChunk) error { return nil }, nil)
		if errTool == nil || metaTool.StreamContinued || dep2Calls.Load() != 0 {
			t.Fatalf("expected tool-call continuation refusal, got err=%v continued=%v dep2Calls=%d", errTool, metaTool.StreamContinued, dep2Calls.Load())
		}

		// 2. json_schema refusal.
		emitToolCalls.Store(false)
		_, metaSchema, errSchema := rm.ExecuteStream(ctx, &domain.IdentityContext{OrgID: org.ID}, &domain.CanonicalChatRequest{
			Model:          "refuse-group",
			Stream:         true,
			ResponseFormat: &domain.ResponseFormat{Type: "json_schema", JSONSchema: map[string]any{"type": "object"}},
			Messages:       []domain.CanonicalMessage{{Role: "user", Content: "return json"}},
		}, func(*domain.CanonicalStreamChunk) error { return nil }, nil)
		if errSchema == nil || metaSchema.StreamContinued || dep2Calls.Load() != 0 {
			t.Fatalf("expected json_schema continuation refusal, got err=%v continued=%v dep2Calls=%d", errSchema, metaSchema.StreamContinued, dep2Calls.Load())
		}

		// 3. Non-prefill adapter refusal.
		noPrefillAdp := &v120NoPrefillAdapter{
			provider: domain.ProviderGemini,
			streamFn: func(_ context.Context, _ *domain.Deployment, _ *domain.CanonicalChatRequest, onChunk adapter.StreamChunkHandler) (*domain.TokenUsage, error) {
				_ = onChunk(&domain.CanonicalStreamChunk{ID: "np1", Choices: []domain.CanonicalStreamChoice{{Index: 0, Delta: domain.CanonicalStreamDelta{Content: "hello"}}}})
				return nil, io.ErrUnexpectedEOF
			},
		}
		reg.Register(noPrefillAdp)
		npGroup := &domain.ModelGroup{OrgID: org.ID, Alias: "no-prefill-group", RoutingStrategy: domain.StrategyRoundRobin, IsActive: true}
		_ = repo.CreateModelGroup(ctx, npGroup)
		_ = registerV120ModelAndDep(t, repo, vault, org.ID, npGroup, &domain.GlobalModel{
			ID: "gemini/np-1", Provider: domain.ProviderGemini, ModelName: "np-1",
			SupportsInference: true, SupportsStreaming: true, LifecycleStatus: domain.ModelStatusActive,
		}, "np-dep-1", "http://localhost")
		_ = registerV120ModelAndDep(t, repo, vault, org.ID, npGroup, &domain.GlobalModel{
			ID: "gemini/np-2", Provider: domain.ProviderGemini, ModelName: "np-2",
			SupportsInference: true, SupportsStreaming: true, LifecycleStatus: domain.ModelStatusActive,
		}, "np-dep-2", "http://localhost")

		_, metaNP, errNP := rm.ExecuteStream(ctx, &domain.IdentityContext{OrgID: org.ID}, &domain.CanonicalChatRequest{
			Model:    "no-prefill-group",
			Stream:   true,
			Messages: []domain.CanonicalMessage{{Role: "user", Content: "hi"}},
		}, func(*domain.CanonicalStreamChunk) error { return nil }, nil)
		if errNP == nil || metaNP.StreamContinued || noPrefillAdp.calls.Load() != 1 {
			t.Fatalf("expected non-prefill refusal with 1 call, got err=%v continued=%v calls=%d", errNP, metaNP.StreamContinued, noPrefillAdp.calls.Load())
		}

		// 4. max_tokens already reached completes cleanly with merged usage.
		maxTok := 2
		adp.streamFn = func(_ context.Context, _ *domain.Deployment, _ *domain.CanonicalChatRequest, onChunk adapter.StreamChunkHandler) (*domain.TokenUsage, error) {
			_ = onChunk(&domain.CanonicalStreamChunk{
				ID:      "mt1",
				Choices: []domain.CanonicalStreamChoice{{Index: 0, Delta: domain.CanonicalStreamDelta{Content: "twenty characters!!!"}}},
				Usage:   &domain.TokenUsage{PromptTokens: 4, CompletionTokens: 2, TotalTokens: 6},
			})
			return nil, io.ErrUnexpectedEOF
		}
		dep2Calls.Store(0)
		usageMT, metaMT, errMT := rm.ExecuteStream(ctx, &domain.IdentityContext{OrgID: org.ID}, &domain.CanonicalChatRequest{
			Model:     "refuse-group",
			Stream:    true,
			MaxTokens: &maxTok,
			Messages:  []domain.CanonicalMessage{{Role: "user", Content: "hi"}},
		}, func(*domain.CanonicalStreamChunk) error { return nil }, nil)
		if errMT != nil || metaMT.StreamContinued || dep2Calls.Load() != 0 {
			t.Fatalf("expected clean completion on max_tokens reached, got err=%v continued=%v dep2Calls=%d", errMT, metaMT.StreamContinued, dep2Calls.Load())
		}
		if usageMT == nil || usageMT.TotalTokens != 6 {
			t.Fatalf("expected merged partial usage TotalTokens=6, got %+v", usageMT)
		}
	})
}

func TestV120_HedgedRacingAndBanditRewardUpdates(t *testing.T) {
	ctx := context.Background()

	t.Run("fastest_response_and_hedge_after_ms_and_comma_separated_models_chat_and_stream", func(t *testing.T) {
		cfg := config.RouterConfig{
			BaseRetryDelay:      time.Millisecond,
			MaxRetryDelay:       5 * time.Millisecond,
			HedgeDelayMs:        0,
			MaxHedgeConcurrency: 3,
			FailureThreshold:    1,
			DefaultCooldown:     10 * time.Second,
		}
		repo, reg, vault, _, _, rm, org := newV120TestEnv(t, nil, cfg)
		rm.SetAffinityStore(NewAffinityStoreFromRouterConfig(nil, cfg))

		var slowCanceled atomic.Bool
		adp := &v120MockAdapter{
			provider: domain.ProviderOpenAI,
			chatFn: func(rCtx context.Context, dep *domain.Deployment, req *domain.CanonicalChatRequest) (*domain.CanonicalChatResponse, error) {
				if strings.Contains(dep.DeploymentName, "slow") {
					select {
					case <-time.After(250 * time.Millisecond):
						return &domain.CanonicalChatResponse{ID: "slow", Provider: domain.ProviderOpenAI, Model: req.ResolvedModel}, nil
					case <-rCtx.Done():
						slowCanceled.Store(true)
						return nil, rCtx.Err()
					}
				}
				return &domain.CanonicalChatResponse{ID: "fast-win", Provider: domain.ProviderOpenAI, Model: req.ResolvedModel}, nil
			},
			streamFn: func(rCtx context.Context, dep *domain.Deployment, _ *domain.CanonicalChatRequest, onChunk adapter.StreamChunkHandler) (*domain.TokenUsage, error) {
				if strings.Contains(dep.DeploymentName, "slow") {
					select {
					case <-time.After(250 * time.Millisecond):
						_ = onChunk(&domain.CanonicalStreamChunk{ID: "s-slow", Choices: []domain.CanonicalStreamChoice{{Delta: domain.CanonicalStreamDelta{Content: "slow"}}}})
						return &domain.TokenUsage{TotalTokens: 1}, nil
					case <-rCtx.Done():
						slowCanceled.Store(true)
						return nil, rCtx.Err()
					}
				}
				_ = onChunk(&domain.CanonicalStreamChunk{ID: "s-fast", Choices: []domain.CanonicalStreamChoice{{Delta: domain.CanonicalStreamDelta{Content: "fast-stream"}}}})
				return &domain.TokenUsage{PromptTokens: 2, CompletionTokens: 3, TotalTokens: 5}, nil
			},
		}
		reg.Register(adp)

		// 1) StrategyFastestResponse group: fast deployment wins, slow deployment is canceled and stays CLOSED.
		fastestGroup := &domain.ModelGroup{
			OrgID:            org.ID,
			Alias:            "fastest-group",
			RoutingStrategy:  domain.StrategyFastestResponse,
			FailureThreshold: 1,
			CooldownSeconds:  10,
			IsActive:         true,
		}
		_ = repo.CreateModelGroup(ctx, fastestGroup)
		depSlow := registerV120ModelAndDep(t, repo, vault, org.ID, fastestGroup, &domain.GlobalModel{
			ID: "openai/fastest-slow", Provider: domain.ProviderOpenAI, ModelName: "fastest-slow",
			SupportsInference: true, SupportsStreaming: true, LifecycleStatus: domain.ModelStatusActive,
		}, "dep-slow", "http://localhost")
		depFast := registerV120ModelAndDep(t, repo, vault, org.ID, fastestGroup, &domain.GlobalModel{
			ID: "openai/fastest-fast", Provider: domain.ProviderOpenAI, ModelName: "fastest-fast",
			SupportsInference: true, SupportsStreaming: true, LifecycleStatus: domain.ModelStatusActive,
		}, "dep-fast", "http://localhost")
		slowID := depSlow.ID
		fastID := depFast.ID

		resp, meta, err := rm.ExecuteChat(ctx, &domain.IdentityContext{OrgID: org.ID}, &domain.CanonicalChatRequest{
			Model:    "fastest-group",
			Messages: []domain.CanonicalMessage{{Role: "user", Content: "race"}},
		})
		if err != nil || resp == nil || resp.ID != "fast-win" {
			t.Fatalf("expected fast-win, got resp=%+v err=%v", resp, err)
		}
		if meta.WinningDeployment == nil || meta.WinningDeployment.ID != fastID || meta.RouteDecision.Reason != "hedged_race_winner" {
			t.Fatalf("expected winner %s with hedged_race_winner, got %+v / %+v", fastID, meta.WinningDeployment, meta.RouteDecision)
		}
		// Give canceled goroutine a brief moment to observe rCtx.Done().
		deadline := time.Now().Add(200 * time.Millisecond)
		for !slowCanceled.Load() && time.Now().Before(deadline) {
			time.Sleep(2 * time.Millisecond)
		}
		if !slowCanceled.Load() {
			t.Fatal("expected losing racer context to be canceled")
		}
		if state := rm.GetCircuitState(ctx, slowID); state != CircuitClosed {
			t.Fatalf("canceled losing racer must not trip circuit breaker, got %s", state)
		}

		// 2) Streaming hedged race via StrategyFastestResponse.
		slowCanceled.Store(false)
		var streamText strings.Builder
		streamUsage, streamMeta, streamErr := rm.ExecuteStream(ctx, &domain.IdentityContext{OrgID: org.ID}, &domain.CanonicalChatRequest{
			Model:    "fastest-group",
			Stream:   true,
			Messages: []domain.CanonicalMessage{{Role: "user", Content: "race-stream"}},
		}, func(chunk *domain.CanonicalStreamChunk) error {
			for _, c := range chunk.Choices {
				streamText.WriteString(c.Delta.Content)
			}
			return nil
		}, nil)
		if streamErr != nil || streamText.String() != "fast-stream" {
			t.Fatalf("expected fast-stream, got %q err=%v", streamText.String(), streamErr)
		}
		if streamMeta.WinningDeployment == nil || streamMeta.WinningDeployment.ID != fastID || streamMeta.RouteDecision.Reason != "hedged_race_winner" {
			t.Fatalf("unexpected stream race meta: %+v", streamMeta)
		}
		if streamUsage == nil || streamUsage.TotalTokens != 5 {
			t.Fatalf("unexpected stream usage: %+v", streamUsage)
		}

		// 3) Request-level GoRouteExtensions.HedgeAfterMs on non-fastest group.
		hedgeExtGroup := &domain.ModelGroup{
			OrgID:           org.ID,
			Alias:           "ext-hedge",
			RoutingStrategy: domain.StrategyRoundRobin,
			IsActive:        true,
		}
		_ = repo.CreateModelGroup(ctx, hedgeExtGroup)
		depExtSlow := registerV120ModelAndDep(t, repo, vault, org.ID, hedgeExtGroup, &domain.GlobalModel{
			ID: "openai/ext-slow", Provider: domain.ProviderOpenAI, ModelName: "ext-slow",
			SupportsInference: true, LifecycleStatus: domain.ModelStatusActive,
		}, "dep-ext-slow", "http://localhost")
		depExtFast := registerV120ModelAndDep(t, repo, vault, org.ID, hedgeExtGroup, &domain.GlobalModel{
			ID: "openai/ext-fast", Provider: domain.ProviderOpenAI, ModelName: "ext-fast",
			SupportsInference: true, LifecycleStatus: domain.ModelStatusActive,
		}, "dep-ext-fast", "http://localhost")
		slowCanceled.Store(false)

		extResp, extMeta, extErr := rm.ExecuteChat(ctx, &domain.IdentityContext{OrgID: org.ID}, &domain.CanonicalChatRequest{
			Model:             "ext-hedge",
			Messages:          []domain.CanonicalMessage{{Role: "user", Content: "hedge-after"}},
			GoRouteExtensions: &domain.GoRouteExtensions{HedgeAfterMs: 5, PreferredDeploymentID: depExtSlow.ID},
		})
		if extErr != nil || extResp.ID != "fast-win" || extMeta.WinningDeployment.ID != depExtFast.ID || extMeta.RouteDecision.Reason != "hedged_race_winner" {
			t.Fatalf("expected HedgeAfterMs winner %s, got resp=%+v meta=%+v err=%v", depExtFast.ID, extResp, extMeta, extErr)
		}
		deadlineExt := time.Now().Add(200 * time.Millisecond)
		for !slowCanceled.Load() && time.Now().Before(deadlineExt) {
			time.Sleep(2 * time.Millisecond)
		}
		if !slowCanceled.Load() {
			t.Fatal("expected stalled primary racer to be canceled after hedge won")
		}

		// 4) Comma-separated model list ("slow-alias, fast-alias") races across groups.
		slowAliasGroup := &domain.ModelGroup{OrgID: org.ID, Alias: "slow-alias", RoutingStrategy: domain.StrategyRoundRobin, IsActive: true}
		fastAliasGroup := &domain.ModelGroup{OrgID: org.ID, Alias: "fast-alias", RoutingStrategy: domain.StrategyRoundRobin, IsActive: true}
		_ = repo.CreateModelGroup(ctx, slowAliasGroup)
		_ = repo.CreateModelGroup(ctx, fastAliasGroup)
		_ = registerV120ModelAndDep(t, repo, vault, org.ID, slowAliasGroup, &domain.GlobalModel{
			ID: "openai/alias-slow", Provider: domain.ProviderOpenAI, ModelName: "alias-slow",
			SupportsInference: true, SupportsStreaming: true, LifecycleStatus: domain.ModelStatusActive,
		}, "dep-alias-slow", "http://localhost")
		depAliasFast := registerV120ModelAndDep(t, repo, vault, org.ID, fastAliasGroup, &domain.GlobalModel{
			ID: "openai/alias-fast", Provider: domain.ProviderOpenAI, ModelName: "alias-fast",
			SupportsInference: true, SupportsStreaming: true, LifecycleStatus: domain.ModelStatusActive,
		}, "dep-alias-fast", "http://localhost")

		commaResp, commaMeta, commaErr := rm.ExecuteChat(ctx, &domain.IdentityContext{OrgID: org.ID}, &domain.CanonicalChatRequest{
			Model:    "slow-alias, fast-alias",
			Messages: []domain.CanonicalMessage{{Role: "user", Content: "comma-race"}},
		})
		if commaErr != nil || commaResp.ID != "fast-win" {
			t.Fatalf("expected comma-separated fast-win, got resp=%+v err=%v", commaResp, commaErr)
		}
		if commaMeta.WinningDeployment.ID != depAliasFast.ID || commaMeta.RouteDecision.Reason != "hedged_race_winner" {
			t.Fatalf("expected comma-separated winner %s, got %+v / %+v", depAliasFast.ID, commaMeta.WinningDeployment, commaMeta.RouteDecision)
		}

		// Comma-separated streaming race.
		var commaStreamText strings.Builder
		_, commaStreamMeta, commaStreamErr := rm.ExecuteStream(ctx, &domain.IdentityContext{OrgID: org.ID}, &domain.CanonicalChatRequest{
			Model:    "slow-alias, fast-alias",
			Stream:   true,
			Messages: []domain.CanonicalMessage{{Role: "user", Content: "comma-stream"}},
		}, func(chunk *domain.CanonicalStreamChunk) error {
			for _, c := range chunk.Choices {
				commaStreamText.WriteString(c.Delta.Content)
			}
			return nil
		}, nil)
		if commaStreamErr != nil || commaStreamText.String() != "fast-stream" || commaStreamMeta.WinningDeployment.ID != depAliasFast.ID {
			t.Fatalf("expected comma-separated stream winner %s (%q), got %+v (%q) err=%v", depAliasFast.ID, "fast-stream", commaStreamMeta.WinningDeployment, commaStreamText.String(), commaStreamErr)
		}
	})

	t.Run("bandit_prerouter_records_alpha_and_beta_outcomes", func(t *testing.T) {
		cfg := config.RouterConfig{
			BaseRetryDelay: time.Millisecond,
			MaxRetryDelay:  5 * time.Millisecond,
			PreRouterMode:  PreRouterModeAdaptive,
			Bandit: config.BanditConfig{
				Enabled:         true,
				DefaultAlpha:    1.0,
				DefaultBeta:     1.0,
				CandidateModels: []string{"bandit-arm"},
			},
		}
		repo, reg, vault, _, _, rm, org := newV120TestEnv(t, nil, cfg)
		bandit := NewBanditPreRouter(cfg, nil, WithBanditRepository(repo), WithBanditMaxLatencyMs(30))
		rm.intelligentRouter.SetBanditPreRouter(bandit)

		var outcomeMode atomic.Int32 // 0=fast ok, 1=refusal, 2=slow (>30ms), 3=error
		adp := &v120MockAdapter{
			provider: domain.ProviderOpenAI,
			chatFn: func(_ context.Context, dep *domain.Deployment, req *domain.CanonicalChatRequest) (*domain.CanonicalChatResponse, error) {
				switch outcomeMode.Load() {
				case 0:
					return &domain.CanonicalChatResponse{
						ID:       "ok-fast",
						Provider: domain.ProviderOpenAI,
						Model:    req.ResolvedModel,
						Choices:  []domain.CanonicalChoice{{Index: 0, Message: domain.CanonicalMessage{Role: "assistant", Content: "ok"}, FinishReason: "stop"}},
					}, nil
				case 1:
					return &domain.CanonicalChatResponse{
						ID:       "refusal",
						Provider: domain.ProviderOpenAI,
						Model:    req.ResolvedModel,
						Choices:  []domain.CanonicalChoice{{Index: 0, Message: domain.CanonicalMessage{Role: "assistant", Content: ""}, FinishReason: "content_filter"}},
					}, nil
				case 2:
					time.Sleep(45 * time.Millisecond)
					return &domain.CanonicalChatResponse{
						ID:       "ok-slow",
						Provider: domain.ProviderOpenAI,
						Model:    req.ResolvedModel,
						Choices:  []domain.CanonicalChoice{{Index: 0, Message: domain.CanonicalMessage{Role: "assistant", Content: "slow"}, FinishReason: "stop"}},
					}, nil
				default:
					return nil, domain.ClassifyUpstreamStatus(domain.ProviderOpenAI, http.StatusBadRequest, "bad input", 0)
				}
			},
		}
		reg.Register(adp)

		armGroup := &domain.ModelGroup{OrgID: org.ID, Alias: "bandit-arm", RoutingStrategy: domain.StrategyRoundRobin, IsActive: true}
		_ = repo.CreateModelGroup(ctx, armGroup)
		_ = registerV120ModelAndDep(t, repo, vault, org.ID, armGroup, &domain.GlobalModel{
			ID: "openai/bandit-arm", Provider: domain.ProviderOpenAI, ModelName: "bandit-arm",
			SupportsInference: true, LifecycleStatus: domain.ModelStatusActive,
		}, "dep-bandit", "http://localhost")

		req := &domain.CanonicalChatRequest{
			Model:    VirtualAliasAdaptive,
			Messages: []domain.CanonicalMessage{{Role: "user", Content: "What is 2+2?"}},
		}
		bucket := ClassifyTaskBucket(req, cfg.LongContextTokens)

		// 1) Fast success -> alpha + 1.
		outcomeMode.Store(0)
		if _, _, err := rm.ExecuteChat(ctx, &domain.IdentityContext{OrgID: org.ID}, req); err != nil {
			t.Fatalf("bandit fast success failed: %v", err)
		}
		// 2) Refusal (content_filter) -> beta + 1.
		outcomeMode.Store(1)
		if _, _, err := rm.ExecuteChat(ctx, &domain.IdentityContext{OrgID: org.ID}, req); err != nil {
			t.Fatalf("bandit refusal call failed: %v", err)
		}
		// 3) Slow (>30ms maxLatencyMs) -> beta + 1.
		outcomeMode.Store(2)
		if _, _, err := rm.ExecuteChat(ctx, &domain.IdentityContext{OrgID: org.ID}, req); err != nil {
			t.Fatalf("bandit slow call failed: %v", err)
		}
		// 4) Non-retryable error -> beta + 1.
		outcomeMode.Store(3)
		if _, _, err := rm.ExecuteChat(ctx, &domain.IdentityContext{OrgID: org.ID}, req); err == nil {
			t.Fatal("expected error for mode 3")
		}

		// Flush buffered bandit rewards synchronously.
		bandit.Stop()

		alpha, beta := bandit.GetPrior(org.ID, bucket, "bandit-arm")
		// Initial prior (1, 1) + 1 alpha + 3 beta = (2, 4).
		if alpha != 2.0 || beta != 4.0 {
			t.Fatalf("expected bandit prior (alpha=2, beta=4), got (alpha=%v, beta=%v)", alpha, beta)
		}
	})
}
