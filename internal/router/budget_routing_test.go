package router_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/adapter"
	"github.com/goroute-ai/ai-gateway-go/internal/adapter/openai"
	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/router"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBudgetAwareRouting_FallbackChain verifies that a caller with a budget:
// 1. Skips an unverified/unknown-priced primary group.
// 2. Traverses the fallback chain to find a verified/known-priced model.
// 3. Fails closed with HTTP 403 if all groups in the fallback chain have unknown pricing.
func TestBudgetAwareRouting_FallbackChain(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	vault, _ := auth.NewVault("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	rbac := auth.NewRBACEngine(repo)

	org := &domain.Organization{Name: "BudgetOrg", Slug: "budget-org", IsActive: true}
	_ = repo.CreateOrganization(ctx, org)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"id":"chatcmpl-test","object":"chat.completion","created":1700000000,"model":"test-model","choices":[{"index":0,"message":{"role":"assistant","content":"Upstream success"},"finish_reason":"stop"}],"usage":{"prompt_tokens":5,"completion_tokens":5,"total_tokens":10}}`)
	}))
	defer srv.Close()

	cred := &domain.ProviderCredential{
		OrgID:    org.ID,
		Provider: domain.ProviderOpenAI,
		Name:     "oai-cred",
		BaseURL:  srv.URL,
		IsActive: true,
	}
	_ = vault.EncryptCredential(cred, "sk-test-key")
	_ = repo.CreateProviderCredential(ctx, cred)

	// Create an unverified/unknown model
	unknownModel := &domain.GlobalModel{
		ID:            "openai/unknown-custom-model",
		Provider:      domain.ProviderOpenAI,
		ModelName:     "unknown-custom-model",
		PricingStatus: domain.PricingStatusUnknown,
	}
	_ = repo.UpsertGlobalModel(ctx, unknownModel)

	// Create a verified model
	verifiedModel := &domain.GlobalModel{
		ID:                     "openai/verified-model",
		Provider:               domain.ProviderOpenAI,
		ModelName:              "verified-model",
		PricingStatus:          domain.PricingStatusVerified,
		PricingProvenanceSource: "vendor-doc-2025",
	}
	_ = repo.UpsertGlobalModel(ctx, verifiedModel)

	// Group 2 (Fallback): Has verified model
	verifiedGroup := &domain.ModelGroup{
		OrgID:           org.ID,
		Alias:           "verified-group",
		RoutingStrategy: domain.StrategyLowestCost,
		IsActive:        true,
	}
	_ = repo.CreateModelGroup(ctx, verifiedGroup)
	_ = repo.CreateDeployment(ctx, &domain.Deployment{
		ModelGroupID:   verifiedGroup.ID,
		GlobalModelID:  verifiedModel.ID,
		CredentialID:   cred.ID,
		DeploymentName: "verified-dep",
		Status:         domain.DeploymentStatusActive,
	})

	// Group 1 (Primary): Has unknown model, fallbacks to Group 2
	primaryGroup := &domain.ModelGroup{
		OrgID:            org.ID,
		Alias:            "primary-group",
		RoutingStrategy:  domain.StrategyLowestCost,
		FallbackGroupIDs: []string{verifiedGroup.ID},
		IsActive:         true,
	}
	_ = repo.CreateModelGroup(ctx, primaryGroup)
	_ = repo.CreateDeployment(ctx, &domain.Deployment{
		ModelGroupID:   primaryGroup.ID,
		GlobalModelID:  unknownModel.ID,
		CredentialID:   cred.ID,
		DeploymentName: "unknown-dep",
		Status:         domain.DeploymentStatusActive,
	})

	reg := adapter.NewRegistry()
	reg.Register(openai.NewAdapter(srv.Client()))

	ir := router.NewIntelligentRouter(repo, config.RouterConfig{})
	lb := router.NewLoadBalancer()
	rm := router.NewReliabilityManager(repo, reg, ir, lb, vault, rbac, nil, config.RouterConfig{})

	// 1. Unconstrained caller succeeds on primary unknown-priced model
	unconstrainedCtx := &domain.IdentityContext{
		OrgID:              org.ID,
		KeyMaxBudgetMicros: 0, // unlimited
	}
	resp, meta, err := rm.ExecuteChat(ctx, unconstrainedCtx, &domain.CanonicalChatRequest{
		Model: "primary-group",
		Messages: []domain.CanonicalMessage{
			{Role: "user", Content: "Hello"},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, "unknown-dep", meta.WinningDeployment.DeploymentName)
	assert.False(t, meta.FallbackAttempted)
	assert.Equal(t, "Upstream success", resp.Choices[0].Message.Content)

	// 2. Budget-constrained caller automatically bypasses Group 1 and falls back to Group 2
	budgetedCtx := &domain.IdentityContext{
		OrgID:              org.ID,
		KeyMaxBudgetMicros: 10_000_000, // strict budget
	}
	resp, meta, err = rm.ExecuteChat(ctx, budgetedCtx, &domain.CanonicalChatRequest{
		Model: "primary-group",
		Messages: []domain.CanonicalMessage{
			{Role: "user", Content: "Hello"},
		},
	})
	require.NoError(t, err)
	assert.True(t, meta.FallbackAttempted, "should have activated fallback chain")
	assert.Equal(t, "verified-dep", meta.WinningDeployment.DeploymentName)

	// 3. Budget-constrained caller fails closed with HTTP 403 when no verified models exist in chain
	allUnknownGroup := &domain.ModelGroup{
		OrgID:           org.ID,
		Alias:           "all-unknown",
		RoutingStrategy: domain.StrategyLowestCost,
		IsActive:        true,
	}
	_ = repo.CreateModelGroup(ctx, allUnknownGroup)
	_ = repo.CreateDeployment(ctx, &domain.Deployment{
		ModelGroupID:   allUnknownGroup.ID,
		GlobalModelID:  unknownModel.ID,
		CredentialID:   cred.ID,
		DeploymentName: "only-unknown-dep",
		Status:         domain.DeploymentStatusActive,
	})

	_, _, err = rm.ExecuteChat(ctx, budgetedCtx, &domain.CanonicalChatRequest{
		Model: "all-unknown",
		Messages: []domain.CanonicalMessage{
			{Role: "user", Content: "Hello"},
		},
	})
	require.Error(t, err)
	gwErr, ok := err.(*domain.GatewayError)
	require.True(t, ok)
	assert.Equal(t, http.StatusForbidden, gwErr.StatusCode)
	assert.Equal(t, "pricing_unknown_budget_restricted", gwErr.Code)
}

// TestBudgetAwareRouting_StreamingSelectedCallback verifies that onSelected is invoked
// with the winning deployment before any stream chunks arrive.
func TestBudgetAwareRouting_StreamingSelectedCallback(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	vault, _ := auth.NewVault("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	rbac := auth.NewRBACEngine(repo)

	org := &domain.Organization{Name: "StreamOrg", Slug: "stream-org", IsActive: true}
	_ = repo.CreateOrganization(ctx, org)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		flusher, _ := w.(http.Flusher)
		time.Sleep(10 * time.Millisecond) // Ensure delay so callback order is deterministic
		fmt.Fprintf(w, "data: {\"id\":\"chunk-1\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Chunk\"}}]}\n\n")
		flusher.Flush()
		fmt.Fprintf(w, "data: [DONE]\n\n")
		flusher.Flush()
	}))
	defer srv.Close()

	cred := &domain.ProviderCredential{
		OrgID:    org.ID,
		Provider: domain.ProviderOpenAI,
		Name:     "stream-cred",
		BaseURL:  srv.URL,
		IsActive: true,
	}
	_ = vault.EncryptCredential(cred, "sk-stream-key")
	_ = repo.CreateProviderCredential(ctx, cred)

	streamModel := &domain.GlobalModel{
		ID:            "openai/gpt-4.1-mini",
		Provider:      domain.ProviderOpenAI,
		ModelName:     "gpt-4.1-mini",
		PricingStatus: domain.PricingStatusVerified,
	}
	_ = repo.UpsertGlobalModel(ctx, streamModel)

	streamGroup := &domain.ModelGroup{
		OrgID:           org.ID,
		Alias:           "stream-group",
		RoutingStrategy: domain.StrategyLowestCost,
		IsActive:        true,
	}
	_ = repo.CreateModelGroup(ctx, streamGroup)
	_ = repo.CreateDeployment(ctx, &domain.Deployment{
		ModelGroupID:   streamGroup.ID,
		GlobalModelID:  streamModel.ID,
		CredentialID:   cred.ID,
		DeploymentName: "stream-dep-1",
		Status:         domain.DeploymentStatusActive,
	})

	reg := adapter.NewRegistry()
	reg.Register(openai.NewAdapter(srv.Client()))

	ir := router.NewIntelligentRouter(repo, config.RouterConfig{})
	lb := router.NewLoadBalancer()
	rm := router.NewReliabilityManager(repo, reg, ir, lb, vault, rbac, nil, config.RouterConfig{})

	var selectedDep *domain.Deployment
	var chunkCount int

	onSelected := func(dep *domain.Deployment) {
		selectedDep = dep
		assert.Equal(t, 0, chunkCount, "onSelected must be invoked before any chunks arrive")
	}

	onChunk := func(chunk *domain.CanonicalStreamChunk) error {
		chunkCount++
		assert.NotNil(t, selectedDep, "selectedDep must be populated before receiving chunk")
		return nil
	}

	_, meta, err := rm.ExecuteStream(ctx, &domain.IdentityContext{OrgID: org.ID}, &domain.CanonicalChatRequest{
		Model:  "stream-group",
		Stream: true,
		Messages: []domain.CanonicalMessage{
			{Role: "user", Content: "Stream test"},
		},
	}, onChunk, onSelected)

	require.NoError(t, err)
	require.NotNil(t, selectedDep)
	assert.Equal(t, "stream-dep-1", selectedDep.DeploymentName)
	assert.Equal(t, domain.PricingStatusVerified, domain.ResolvePricingStatus(selectedDep.GlobalModel))
	assert.Equal(t, 1, chunkCount)
	assert.Equal(t, "stream-dep-1", meta.WinningDeployment.DeploymentName)
}
