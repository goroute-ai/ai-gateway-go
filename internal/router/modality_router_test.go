package router_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/adapter"
	"github.com/goroute-ai/ai-gateway-go/internal/adapter/cohere"
	"github.com/goroute-ai/ai-gateway-go/internal/adapter/openai"
	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/router"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestExecuteRerank(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	vault, _ := auth.NewVault("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	rbac := auth.NewRBACEngine(repo)

	org := &domain.Organization{Name: "TestOrg", Slug: "test-org", IsActive: true}
	require.NoError(t, repo.CreateOrganization(ctx, org))

	cohereServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v2/rerank", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"id":"rerank-123","results":[{"index":0,"relevance_score":0.98}],"meta":{"billed_units":{"search_units":1}}}`)
	}))
	defer cohereServer.Close()

	cred := &domain.ProviderCredential{
		OrgID:    org.ID,
		Provider: domain.ProviderCohere,
		Name:     "cohere-cred",
		BaseURL:  cohereServer.URL,
		IsActive: true,
	}
	require.NoError(t, vault.EncryptCredential(cred, "test-api-key"))
	require.NoError(t, repo.CreateProviderCredential(ctx, cred))

	gm := &domain.GlobalModel{
		ID:                "cohere/rerank-v3.5",
		Provider:          domain.ProviderCohere,
		ModelName:         "rerank-v3.5",
		DisplayName:       "Cohere Rerank v3.5",
		SupportsInference: true,
		LifecycleStatus:   domain.ModelStatusActive,
		Capabilities: domain.ModelCapabilities{
			Rerank: domain.CapabilitySupported,
		},
	}
	require.NoError(t, repo.UpsertGlobalModel(ctx, gm))

	group := &domain.ModelGroup{
		OrgID:           org.ID,
		Alias:           "rerank-v3.5",
		RoutingStrategy: domain.StrategyWeightedShuffle,
		IsActive:        true,
	}
	require.NoError(t, repo.CreateModelGroup(ctx, group))

	dep := &domain.Deployment{
		ModelGroupID:   group.ID,
		GlobalModelID:  gm.ID,
		CredentialID:   cred.ID,
		DeploymentName: "cohere-rerank-dep",
		Weight:         1,
		Status:         domain.DeploymentStatusActive,
	}
	require.NoError(t, repo.CreateDeployment(ctx, dep))

	reg := adapter.NewRegistry()
	reg.Register(cohere.NewAdapter(cohereServer.Client(), nil))

	rCfg := config.Default().Router
	rCfg.BaseRetryDelay = 1 * time.Millisecond
	rCfg.MaxRetryDelay = 5 * time.Millisecond

	ir := router.NewIntelligentRouter(repo, rCfg)
	lb := router.NewLoadBalancer()
	rm := router.NewReliabilityManager(repo, reg, ir, lb, vault, rbac, nil, rCfg)

	req := &domain.CanonicalRerankRequest{
		Model:     "rerank-v3.5",
		Query:     "deep learning",
		Documents: []domain.RerankDocument{{Text: "Deep learning is a subset of machine learning."}},
	}
	idCtx := &domain.IdentityContext{OrgID: org.ID}

	resp, meta, err := rm.ExecuteRerank(ctx, idCtx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "rerank-123", resp.ID)
	assert.Len(t, resp.Results, 1)
	assert.Equal(t, 0.98, resp.Results[0].RelevanceScore)
	assert.Equal(t, 1, resp.Usage.SearchUnits)
	assert.Equal(t, dep.ID, meta.WinningDeployment.ID)
}

func TestExecuteModeration(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	vault, _ := auth.NewVault("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	rbac := auth.NewRBACEngine(repo)

	org := &domain.Organization{Name: "TestOrg", Slug: "test-org", IsActive: true}
	require.NoError(t, repo.CreateOrganization(ctx, org))

	oaiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v1/moderations", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"id":"modr-123","model":"omni-moderation-latest","results":[{"flagged":true,"categories":{"hate":true,"violence":false},"category_scores":{"hate":0.95,"violence":0.01}}]}`)
	}))
	defer oaiServer.Close()

	cred := &domain.ProviderCredential{
		OrgID:    org.ID,
		Provider: domain.ProviderOpenAI,
		Name:     "oai-cred",
		BaseURL:  oaiServer.URL + "/v1",
		IsActive: true,
	}
	require.NoError(t, vault.EncryptCredential(cred, "test-api-key"))
	require.NoError(t, repo.CreateProviderCredential(ctx, cred))

	gm := &domain.GlobalModel{
		ID:                "openai/omni-moderation-latest",
		Provider:          domain.ProviderOpenAI,
		ModelName:         "omni-moderation-latest",
		DisplayName:       "OpenAI Omni Moderation Latest",
		SupportsInference: true,
		LifecycleStatus:   domain.ModelStatusActive,
		Capabilities: domain.ModelCapabilities{
			Moderation: domain.CapabilitySupported,
		},
	}
	require.NoError(t, repo.UpsertGlobalModel(ctx, gm))

	group := &domain.ModelGroup{
		OrgID:           org.ID,
		Alias:           "omni-moderation-latest",
		RoutingStrategy: domain.StrategyWeightedShuffle,
		IsActive:        true,
	}
	require.NoError(t, repo.CreateModelGroup(ctx, group))

	dep := &domain.Deployment{
		ModelGroupID:   group.ID,
		GlobalModelID:  gm.ID,
		CredentialID:   cred.ID,
		DeploymentName: "oai-moderation-dep",
		Weight:         1,
		Status:         domain.DeploymentStatusActive,
	}
	require.NoError(t, repo.CreateDeployment(ctx, dep))

	reg := adapter.NewRegistry()
	reg.Register(openai.NewAdapter(oaiServer.Client()))

	rCfg := config.Default().Router
	rCfg.BaseRetryDelay = 1 * time.Millisecond
	rCfg.MaxRetryDelay = 5 * time.Millisecond

	ir := router.NewIntelligentRouter(repo, rCfg)
	lb := router.NewLoadBalancer()
	rm := router.NewReliabilityManager(repo, reg, ir, lb, vault, rbac, nil, rCfg)

	req := &domain.CanonicalModerationRequest{
		Model: "omni-moderation-latest",
		Input: []string{"some sensitive test text"},
	}
	idCtx := &domain.IdentityContext{OrgID: org.ID}

	resp, meta, err := rm.ExecuteModeration(ctx, idCtx, req)
	require.NoError(t, err)
	require.NotNil(t, resp)
	assert.Equal(t, "modr-123", resp.ID)
	assert.Len(t, resp.Results, 1)
	assert.True(t, resp.Results[0].Flagged)
	assert.True(t, resp.Results[0].Categories["hate"])
	assert.Equal(t, 0.95, resp.Results[0].CategoryScores["hate"])
	assert.Equal(t, dep.ID, meta.WinningDeployment.ID)
}
