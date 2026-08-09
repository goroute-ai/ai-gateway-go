package validation

import (
	"context"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func seedCompatGroup(t *testing.T, repo *storage.MemoryRepository, orgID, alias string, dropParams bool, models []*domain.GlobalModel, fallbacks []domain.FallbackTarget) {
	t.Helper()
	ctx := context.Background()
	mg := &domain.ModelGroup{
		ID:                    "mg-" + alias,
		OrgID:                 orgID,
		Alias:                 alias,
		RoutingStrategy:       domain.StrategyWeightedShuffle,
		DropUnsupportedParams: dropParams,
		FallbackTargets:       fallbacks,
		IsActive:              true,
	}
	require.NoError(t, repo.CreateModelGroup(ctx, mg))
	for i, m := range models {
		require.NoError(t, repo.UpsertGlobalModel(ctx, m))
		require.NoError(t, repo.CreateDeployment(ctx, &domain.Deployment{
			ID:             mg.ID + "-dep-" + string(rune('a'+i)),
			ModelGroupID:   mg.ID,
			GlobalModelID:  m.ID,
			DeploymentName: "dep-" + m.ModelName,
			Weight:         100,
			Priority:       1,
			Status:         domain.DeploymentStatusActive,
		}))
	}
}

func TestValidator_CompatibilityModes(t *testing.T) {
	ctx := context.Background()
	orgID := "org-val-compat"

	partialModel := &domain.GlobalModel{
		ID:                "openai/partial-chat",
		Provider:          domain.ProviderOpenAI,
		ModelName:         "partial-chat",
		MaxInputTokens:    16000,
		MaxOutputTokens:   1024,
		SupportsInference: true,
		Capabilities: domain.ModelCapabilities{
			Streaming:         domain.CapabilitySupported,
			Tools:             domain.CapabilityUnsupported,
			StructuredOutputs: domain.CapabilityUnsupported,
			Reasoning:         domain.CapabilityUnsupported,
		},
	}
	fullModel := &domain.GlobalModel{
		ID:                "openai/full-chat",
		Provider:          domain.ProviderOpenAI,
		ModelName:         "full-chat",
		MaxInputTokens:    128000,
		MaxOutputTokens:   16384,
		SupportsInference: true,
		SupportsTools:     true,
		SupportsReasoning: true,
		Capabilities: domain.ModelCapabilities{
			Streaming:         domain.CapabilitySupported,
			Tools:             domain.CapabilitySupported,
			StructuredOutputs: domain.CapabilitySupported,
			Reasoning:         domain.CapabilitySupported,
		},
	}

	t.Run("drop_unsupported_params precedence (router, group, request)", func(t *testing.T) {
		repo := storage.NewMemoryRepository()
		seedCompatGroup(t, repo, orgID, "partial-group", false, []*domain.GlobalModel{partialModel}, nil)
		val := NewValidator(repo)

		tooHighTokens := 4096
		reqWithUnsupported := &domain.CanonicalChatRequest{
			Model:           "partial-group",
			Messages:        []domain.CanonicalMessage{{Role: "user", Content: "hi"}},
			Tools:           []domain.CanonicalTool{{Type: "function", Function: domain.CanonicalFunction{Name: "get_time"}}},
			ResponseFormat:  &domain.ResponseFormat{Type: "json_schema", JSONSchema: map[string]any{"name": "ok"}},
			ReasoningEffort: "high",
			MaxTokens:       &tooHighTokens,
		}

		// Default false -> rejected.
		err := val.ValidateChatRequest(ctx, orgID, reqWithUnsupported, 32)
		require.Error(t, err)

		// Per-request true -> allowed even when router/group false.
		dropTrue := true
		reqOverrideTrue := *reqWithUnsupported
		reqOverrideTrue.GoRouteExtensions = &domain.GoRouteExtensions{DropUnsupportedParams: &dropTrue}
		assert.NoError(t, val.ValidateChatRequest(ctx, orgID, &reqOverrideTrue, 32))

		// Router-level true -> allowed by default.
		val.SetDropUnsupportedParams(true)
		assert.NoError(t, val.ValidateChatRequest(ctx, orgID, reqWithUnsupported, 32))

		// Per-request explicit false overrides router-level true -> rejected.
		dropFalse := false
		reqOverrideFalse := *reqWithUnsupported
		reqOverrideFalse.GoRouteExtensions = &domain.GoRouteExtensions{DropUnsupportedParams: &dropFalse}
		assert.Error(t, val.ValidateChatRequest(ctx, orgID, &reqOverrideFalse, 32))
	})

	t.Run("fallback_on_unsupported_params allows validation only when fallbacks exist", func(t *testing.T) {
		repo := storage.NewMemoryRepository()
		seedCompatGroup(t, repo, orgID, "no-fb", false, []*domain.GlobalModel{partialModel}, nil)
		seedCompatGroup(t, repo, orgID, "with-fb", false, []*domain.GlobalModel{partialModel}, []domain.FallbackTarget{{GroupAliasOrID: "backup"}})

		val := NewValidator(repo)
		val.SetFallbackOnUnsupportedParams(true)

		reqTools := func(model string) *domain.CanonicalChatRequest {
			return &domain.CanonicalChatRequest{
				Model:    model,
				Messages: []domain.CanonicalMessage{{Role: "user", Content: "hi"}},
				Tools:    []domain.CanonicalTool{{Type: "function", Function: domain.CanonicalFunction{Name: "fn"}}},
			}
		}

		assert.Error(t, val.ValidateChatRequest(ctx, orgID, reqTools("no-fb"), 32))
		assert.NoError(t, val.ValidateChatRequest(ctx, orgID, reqTools("with-fb"), 32))
	})

	t.Run("multi_deployment group passes if any active deployment supports requirement", func(t *testing.T) {
		repo := storage.NewMemoryRepository()
		seedCompatGroup(t, repo, orgID, "mixed-group", false, []*domain.GlobalModel{partialModel, fullModel}, nil)

		val := NewValidator(repo)
		req := &domain.CanonicalChatRequest{
			Model:           "mixed-group",
			Messages:        []domain.CanonicalMessage{{Role: "user", Content: "hi"}},
			Tools:           []domain.CanonicalTool{{Type: "function", Function: domain.CanonicalFunction{Name: "fn"}}},
			ResponseFormat:  &domain.ResponseFormat{Type: "json_schema", JSONSchema: map[string]any{"name": "res"}},
			ReasoningEffort: "medium",
		}
		assert.NoError(t, val.ValidateChatRequest(ctx, orgID, req, 32))
	})
}
