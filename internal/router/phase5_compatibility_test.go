package router

import (
	"context"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/adapter"
	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPhase5_Stage3CapablePreferenceAndPartialFallback(t *testing.T) {
	ctx := context.Background()
	orgID := "org-phase5-filter"
	lb := NewLoadBalancer(nil)
	fp := NewFilterPipeline(nil, lb, config.RouterConfig{DropUnsupportedParams: true})

	partialDep := &domain.Deployment{
		ID:            "dep-partial",
		GlobalModelID: "openai/partial",
		Weight:        100,
		Status:        domain.DeploymentStatusActive,
		GlobalModel: &domain.GlobalModel{
			ID: "openai/partial", Provider: domain.ProviderOpenAI, ModelName: "partial", SupportsInference: true,
			Capabilities: domain.ModelCapabilities{Tools: domain.CapabilityUnsupported, StructuredOutputs: domain.CapabilityUnsupported, Reasoning: domain.CapabilityUnsupported},
		},
	}
	fullDep := &domain.Deployment{
		ID:            "dep-full",
		GlobalModelID: "openai/full",
		Weight:        100,
		Status:        domain.DeploymentStatusActive,
		GlobalModel: &domain.GlobalModel{
			ID: "openai/full", Provider: domain.ProviderOpenAI, ModelName: "full", SupportsInference: true, SupportsTools: true,
			Capabilities: domain.ModelCapabilities{Tools: domain.CapabilitySupported, StructuredOutputs: domain.CapabilitySupported, Reasoning: domain.CapabilitySupported},
		},
	}

	reqTools := &domain.CanonicalChatRequest{
		Model:    "mix",
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "hi"}},
		Tools:    []domain.CanonicalTool{{Type: "function", Function: domain.CanonicalFunction{Name: "fn"}}},
	}

	// Both candidates present: Stage 3 prefers the fully capable deployment and excludes partial.
	eligible, sat, err := fp.FilterEligibleDeploymentsForGroup(ctx, orgID, "mix", false, reqTools, []*domain.Deployment{partialDep, fullDep}, 100, nil)
	require.NoError(t, err)
	assert.False(t, sat)
	require.Len(t, eligible, 1)
	assert.Equal(t, "dep-full", eligible[0].ID)

	// Only partial candidate present & DropUnsupportedParams=true -> allows partial candidate as fallback.
	eligiblePartial, sat, err := fp.FilterEligibleDeploymentsForGroup(ctx, orgID, "mix", false, reqTools, []*domain.Deployment{partialDep}, 100, nil)
	require.NoError(t, err)
	assert.False(t, sat)
	require.Len(t, eligiblePartial, 1)
	assert.Equal(t, "dep-partial", eligiblePartial[0].ID)

	// Per-request override DropUnsupportedParams=false rejects partial candidate.
	dropFalse := false
	reqStrict := *reqTools
	reqStrict.GoRouteExtensions = &domain.GoRouteExtensions{DropUnsupportedParams: &dropFalse}
	eligibleStrict, _, err := fp.FilterEligibleDeploymentsForGroup(ctx, orgID, "mix", true, &reqStrict, []*domain.Deployment{partialDep}, 100, nil)
	require.NoError(t, err)
	assert.Empty(t, eligibleStrict)
}

func TestPhase5_SanitizeRequestForDeployment(t *testing.T) {
	origTemp := 0.7
	origTopP := 0.9
	origMaxTokens := 8192
	origExtra := map[string]any{
		"parallel_tool_calls": true,
		"thinking":            map[string]any{"type": "enabled", "budget_tokens": 1024},
		"logprobs":            true,
		"seed":                42,
		"custom_keep":         "ok",
	}
	req := &domain.CanonicalChatRequest{
		Model:           "alias",
		Messages:        []domain.CanonicalMessage{{Role: "user", Content: "hi"}},
		Tools:           []domain.CanonicalTool{{Type: "function", Function: domain.CanonicalFunction{Name: "f"}}},
		ToolChoice:      "auto",
		Temperature:     &origTemp,
		TopP:            &origTopP,
		MaxTokens:       &origMaxTokens,
		ResponseFormat:  &domain.ResponseFormat{Type: "json_schema", JSONSchema: map[string]any{"name": "s"}},
		ReasoningEffort: "high",
		ExtraParams:     origExtra,
	}

	depAnthropicPartial := &domain.Deployment{
		ID: "dep-ant",
		GlobalModel: &domain.GlobalModel{
			ID: "anthropic/limited", Provider: domain.ProviderAnthropic, ModelName: "claude-limited",
			MaxOutputTokens: 2048,
			Capabilities:    domain.ModelCapabilities{Tools: domain.CapabilityUnsupported, StructuredOutputs: domain.CapabilityUnsupported, Reasoning: domain.CapabilityUnsupported},
		},
	}

	sanitized, dropped := sanitizeRequestForDeployment(req, depAnthropicPartial, true)
	assert.Nil(t, sanitized.Tools)
	assert.Nil(t, sanitized.ToolChoice)
	assert.Nil(t, sanitized.ResponseFormat)
	assert.Empty(t, sanitized.ReasoningEffort)
	require.NotNil(t, sanitized.MaxTokens)
	assert.Equal(t, 2048, *sanitized.MaxTokens)
	assert.Equal(t, "ok", sanitized.ExtraParams["custom_keep"])
	assert.NotContains(t, sanitized.ExtraParams, "parallel_tool_calls")
	assert.NotContains(t, sanitized.ExtraParams, "thinking")
	assert.NotContains(t, sanitized.ExtraParams, "logprobs")
	assert.NotContains(t, sanitized.ExtraParams, "seed")
	assert.Equal(t, []string{"logprobs", "max_tokens", "parallel_tool_calls", "reasoning_effort", "response_format", "seed", "thinking", "tool_choice", "tools"}, dropped)

	// Verify caller struct pointers and map were NOT mutated.
	assert.Equal(t, 8192, *req.MaxTokens)
	assert.Contains(t, req.ExtraParams, "thinking")
	assert.Contains(t, req.ExtraParams, "logprobs")

	// Reasoning o3-mini strips temperature & top_p.
	depReasoning := &domain.Deployment{
		ID: "dep-o3",
		GlobalModel: &domain.GlobalModel{
			ID: "openai/o3-mini", Provider: domain.ProviderOpenAI, ModelName: "o3-mini",
			Capabilities: domain.ModelCapabilities{Tools: domain.CapabilitySupported, StructuredOutputs: domain.CapabilitySupported, Reasoning: domain.CapabilitySupported},
		},
	}
	sanO3, droppedO3 := sanitizeRequestForDeployment(req, depReasoning, true)
	assert.Nil(t, sanO3.Temperature)
	assert.Nil(t, sanO3.TopP)
	assert.Equal(t, []string{"temperature", "top_p"}, droppedO3)
	assert.NotNil(t, req.Temperature)

	// OpenAI-compatible dialect providers (e.g., groq, deepseek) preserve OpenAI-wire ExtraParams like seed.
	depGroq := &domain.Deployment{
		ID: "dep-groq",
		GlobalModel: &domain.GlobalModel{
			ID: "groq/llama-3.3-70b-versatile", Provider: domain.ProviderGroq, ModelName: "llama-3.3-70b-versatile",
			Capabilities: domain.ModelCapabilities{Tools: domain.CapabilitySupported, StructuredOutputs: domain.CapabilitySupported, Reasoning: domain.CapabilityUnsupported},
		},
	}
	sanGroq, droppedGroq := sanitizeRequestForDeployment(req, depGroq, true)
	assert.Equal(t, 42, sanGroq.ExtraParams["seed"])
	assert.Equal(t, true, sanGroq.ExtraParams["logprobs"])
	assert.NotContains(t, droppedGroq, "seed")
	assert.NotContains(t, droppedGroq, "logprobs")
}

func TestPhase5_FallbackOnUnsupportedParams_And_StrategyOverride(t *testing.T) {
	ctx := context.Background()
	orgID := "org-phase5-router"
	repo := storage.NewMemoryRepository()
	require.NoError(t, repo.CreateOrganization(ctx, &domain.Organization{ID: orgID, Name: "P5", Slug: "p5", IsActive: true}))
	require.NoError(t, repo.SetOrgProviderSubscription(ctx, &domain.OrgProviderSubscription{OrgID: orgID, Provider: domain.ProviderOpenAI, IsEnabled: true}))

	var mu sync.Mutex
	var reqs []domain.CanonicalChatRequest
	mockAdp := &routingMockAdapter{
		provider: domain.ProviderOpenAI,
		chatFn: func(_ context.Context, dep *domain.Deployment, r *domain.CanonicalChatRequest) (*domain.CanonicalChatResponse, error) {
			mu.Lock()
			reqs = append(reqs, *r)
			mu.Unlock()
			if dep.ID == "dep-primary" {
				return nil, &domain.GatewayError{
					StatusCode: http.StatusBadRequest,
					Type:       domain.ErrorTypeInvalidRequest,
					Code:       "unsupported_parameter",
					Message:    "Unsupported parameter: reasoning_effort is not supported with this model",
					Retryable:  false,
				}
			}
			return &domain.CanonicalChatResponse{
				ID:       "ok-" + dep.ID,
				Provider: domain.ProviderOpenAI,
				Model:    r.ResolvedModel,
				Choices:  []domain.CanonicalChoice{{Index: 0, Message: domain.CanonicalMessage{Role: "assistant", Content: "ok"}, FinishReason: "stop"}},
				Usage:    domain.TokenUsage{PromptTokens: 5, CompletionTokens: 3, TotalTokens: 8},
			}, nil
		},
	}

	reg := adapter.NewRegistry()
	reg.Register(mockAdp)

	require.NoError(t, repo.CreateModelGroup(ctx, &domain.ModelGroup{
		ID:                    "mg-primary",
		OrgID:                 orgID,
		Alias:                 "primary",
		RoutingStrategy:       domain.StrategyRoundRobin,
		DropUnsupportedParams: true,
		FallbackTargets:       []domain.FallbackTarget{{GroupAliasOrID: "fallback"}},
		IsActive:              true,
	}))
	require.NoError(t, repo.CreateModelGroup(ctx, &domain.ModelGroup{
		ID:              "mg-fallback",
		OrgID:           orgID,
		Alias:           "fallback",
		RoutingStrategy: domain.StrategyLeastBusy,
		IsActive:        true,
	}))

	mPrimary := &domain.GlobalModel{
		ID: "openai/p-model", Provider: domain.ProviderOpenAI, ModelName: "p-model", SupportsInference: true,
		Capabilities: domain.ModelCapabilities{Streaming: domain.CapabilitySupported, Tools: domain.CapabilityUnsupported},
	}
	mFallback := &domain.GlobalModel{
		ID: "openai/f-model", Provider: domain.ProviderOpenAI, ModelName: "f-model", SupportsInference: true, SupportsTools: true,
		Capabilities: domain.ModelCapabilities{Streaming: domain.CapabilitySupported, Tools: domain.CapabilitySupported},
	}
	require.NoError(t, repo.UpsertGlobalModel(ctx, mPrimary))
	require.NoError(t, repo.UpsertGlobalModel(ctx, mFallback))

	cred := &domain.ProviderCredential{ID: "cred-1", OrgID: orgID, Provider: domain.ProviderOpenAI, DecryptedAPIKey: "sk-test", IsActive: true}
	require.NoError(t, repo.CreateDeployment(ctx, &domain.Deployment{
		ID: "dep-primary", ModelGroupID: "mg-primary", GlobalModelID: mPrimary.ID, CredentialID: cred.ID,
		Weight: 100, Priority: 1, Status: domain.DeploymentStatusActive, GlobalModel: mPrimary, Credential: cred,
	}))
	require.NoError(t, repo.CreateDeployment(ctx, &domain.Deployment{
		ID: "dep-fallback", ModelGroupID: "mg-fallback", GlobalModelID: mFallback.ID, CredentialID: cred.ID,
		Weight: 100, Priority: 1, Status: domain.DeploymentStatusActive, GlobalModel: mFallback, Credential: cred,
	}))

	cfg := config.RouterConfig{
		DefaultMaxRetries:           0,
		FailureThreshold:            1,
		DefaultCooldown:             30 * time.Second,
		FallbackOnUnsupportedParams: true,
		AllowStrategyOverride:       true,
	}
	lb := NewLoadBalancer(nil)
	ir := NewIntelligentRouter(repo, cfg)
	v, vaultErr := auth.NewVault("0123456789abcdef0123456789abcdef")
	require.NoError(t, vaultErr)
	rm := NewReliabilityManager(repo, reg, ir, lb, v, nil, nil, cfg)

	resp, meta, err := rm.ExecuteChat(ctx, &domain.IdentityContext{OrgID: orgID}, &domain.CanonicalChatRequest{
		Model:           "primary",
		Messages:        []domain.CanonicalMessage{{Role: "user", Content: "hello"}},
		Tools:           []domain.CanonicalTool{{Type: "function", Function: domain.CanonicalFunction{Name: "calc"}}},
		ReasoningEffort: "high",
	})
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.NotNil(t, meta)
	assert.Equal(t, "dep-fallback", meta.WinningDeployment.ID)
	assert.True(t, meta.FallbackAttempted)
	assert.NotEmpty(t, meta.FallbackErrors)
	// First attempt on primary stripped unsupported tools; second succeeded on fallback.
	require.Len(t, reqs, 2)
	assert.Nil(t, reqs[0].Tools)
	assert.Len(t, reqs[1].Tools, 1)
	// Primary must NOT be tripped into Open cooldown after an unsupported-parameter rejection.
	assert.Equal(t, CircuitClosed, rm.GetCircuitState(ctx, "dep-primary"))

	// Strategy override helper respects AllowStrategyOverride flag.
	mg := &domain.ModelGroup{RoutingStrategy: domain.StrategyRoundRobin}
	reqStrat := &domain.CanonicalChatRequest{GoRouteExtensions: &domain.GoRouteExtensions{RoutingStrategy: string(domain.StrategyLowestCost)}}
	assert.Equal(t, domain.StrategyRoundRobin, resolveEffectiveStrategy(mg, reqStrat, false))
	assert.Equal(t, domain.StrategyLowestCost, resolveEffectiveStrategy(mg, reqStrat, true))
}

func TestPhase5_ExecuteCompletion_PromotedFallbackPreservesExtensionsAndSanitizes(t *testing.T) {
	ctx := context.Background()
	orgID := "org-promo-1"
	repo := storage.NewMemoryRepository()
	require.NoError(t, repo.CreateOrganization(ctx, &domain.Organization{ID: orgID, Name: "Promo", Slug: "promo", IsActive: true}))
	require.NoError(t, repo.SetOrgProviderSubscription(ctx, &domain.OrgProviderSubscription{OrgID: orgID, Provider: domain.ProviderAnthropic, IsEnabled: true}))

	promoAdp := &routingMockAdapter{
		provider: domain.ProviderAnthropic,
		chatFn: func(_ context.Context, _ *domain.Deployment, r *domain.CanonicalChatRequest) (*domain.CanonicalChatResponse, error) {
			return &domain.CanonicalChatResponse{
				ID:       "promo-chat-1",
				Model:    r.ResolvedModel,
				Provider: domain.ProviderAnthropic,
				Choices: []domain.CanonicalChoice{{
					Index:        0,
					Message:      domain.CanonicalMessage{Role: "assistant", Content: "promoted-ok"},
					FinishReason: "stop",
				}},
				Usage: domain.TokenUsage{PromptTokens: 4, CompletionTokens: 2, TotalTokens: 6},
			}, nil
		},
	}
	reg := adapter.NewRegistry()
	reg.Register(promoAdp)

	require.NoError(t, repo.CreateModelGroup(ctx, &domain.ModelGroup{
		ID:                    "mg-promo",
		OrgID:                 orgID,
		Alias:                 "legacy-comp",
		RoutingStrategy:       domain.StrategyWeightedShuffle,
		DropUnsupportedParams: true,
		IsActive:              true,
	}))
	gm := &domain.GlobalModel{
		ID:                "anthropic/claude-promo",
		Provider:          domain.ProviderAnthropic,
		ModelName:         "claude-promo",
		SupportsInference: true,
		Capabilities: domain.ModelCapabilities{
			Streaming: domain.CapabilitySupported,
			Reasoning: domain.CapabilityUnsupported,
		},
	}
	require.NoError(t, repo.UpsertGlobalModel(ctx, gm))
	cred := &domain.ProviderCredential{
		ID: "cred-promo", OrgID: orgID, Provider: domain.ProviderAnthropic, DecryptedAPIKey: "sk-ant-test", IsActive: true,
	}
	require.NoError(t, repo.CreateDeployment(ctx, &domain.Deployment{
		ID: "dep-promo", ModelGroupID: "mg-promo", GlobalModelID: gm.ID, CredentialID: cred.ID,
		Region: "eu-west-1", Weight: 100, Priority: 1, Status: domain.DeploymentStatusActive,
		GlobalModel: gm, Credential: cred,
	}))

	cfg := config.RouterConfig{DefaultCooldown: 30 * time.Second}
	lb := NewLoadBalancer(nil)
	ir := NewIntelligentRouter(repo, cfg)
	v, err := auth.NewVault("0123456789abcdef0123456789abcdef")
	require.NoError(t, err)
	rm := NewReliabilityManager(repo, reg, ir, lb, v, nil, nil, cfg)

	dropTrue := true
	resp, meta, execErr := rm.ExecuteCompletion(ctx, &domain.IdentityContext{OrgID: orgID}, &domain.CanonicalCompletionRequest{
		RequestID: "req-promo-1",
		Model:     "legacy-comp",
		Prompt:    domain.CompletionPrompt{Strings: []string{"hello world"}},
		Metadata:  map[string]string{"seed": "42"},
		GoRouteExtensions: &domain.GoRouteExtensions{
			AllowedRegion:         "eu-west-1",
			DropUnsupportedParams: &dropTrue,
		},
	})
	require.NoError(t, execErr)
	require.NotNil(t, resp)
	require.NotNil(t, meta)
	assert.Equal(t, "promoted-ok", resp.Choices[0].Text)
	require.Len(t, promoAdp.capturedReqs, 1)
	require.NotNil(t, promoAdp.capturedReqs[0].GoRouteExtensions)
	assert.Equal(t, "eu-west-1", promoAdp.capturedReqs[0].GoRouteExtensions.AllowedRegion)
	assert.Equal(t, "42", promoAdp.capturedReqs[0].Metadata["seed"])
}
