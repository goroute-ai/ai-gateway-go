package router_test

import (
	"context"
	"fmt"
	"io"
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
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
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

	pol, polErr := network.NewPolicy(config.OutboundSSRFConfig{AllowPrivateNetworks: true, AllowInsecureHTTP: true})
	require.NoError(t, polErr)
	reg := adapter.NewRegistry()
	reg.Register(cohere.NewAdapter(cohereServer.Client(), pol))

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

	pol, polErr := network.NewPolicy(config.OutboundSSRFConfig{AllowPrivateNetworks: true, AllowInsecureHTTP: true})
	require.NoError(t, polErr)
	oaiAdp := openai.NewAdapter(oaiServer.Client())
	oaiAdp.SetSSRFPolicy(pol)
	reg := adapter.NewRegistry()
	reg.Register(oaiAdp)

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

func TestExecuteCompletionStream_SuccessAndUnsupported(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	vault, _ := auth.NewVault("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	rbac := auth.NewRBACEngine(repo)

	org := &domain.Organization{Name: "Test Org", Slug: "test-org-cmpl-stream", IsActive: true}
	require.NoError(t, repo.CreateOrganization(ctx, org))

	oaiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = fmt.Fprint(w, "data: {\"id\":\"cmpl-1\",\"object\":\"text_completion\",\"model\":\"gpt-3.5-turbo-instruct\",\"choices\":[{\"index\":0,\"text\":\"ok\",\"finish_reason\":\"stop\"}]}\n\n")
		_, _ = fmt.Fprint(w, "data: [DONE]\n\n")
	}))
	defer oaiServer.Close()

	// 1. Supported provider (openai)
	oaiModel := &domain.GlobalModel{ID: "openai/gpt-3.5-turbo-instruct", Provider: domain.ProviderOpenAI, ModelName: "gpt-3.5-turbo-instruct", SupportsInference: true, LifecycleStatus: domain.ModelStatusActive}
	require.NoError(t, repo.UpsertGlobalModel(ctx, oaiModel))
	oaiCred := &domain.ProviderCredential{OrgID: org.ID, Provider: domain.ProviderOpenAI, BaseURL: oaiServer.URL, IsActive: true}
	require.NoError(t, vault.EncryptCredential(oaiCred, "sk-oai"))
	require.NoError(t, repo.CreateProviderCredential(ctx, oaiCred))

	mgOAI := &domain.ModelGroup{OrgID: org.ID, Alias: "cmpl-ok", RoutingStrategy: domain.StrategyWeightedShuffle, IsActive: true}
	require.NoError(t, repo.CreateModelGroup(ctx, mgOAI))
	require.NoError(t, repo.CreateDeployment(ctx, &domain.Deployment{
		ModelGroupID: mgOAI.ID, GlobalModelID: oaiModel.ID, CredentialID: oaiCred.ID, Weight: 1, Status: domain.DeploymentStatusActive,
	}))

	// 2. Unsupported provider (cohere does not implement StreamingCompletionAdapter)
	cohModel := &domain.GlobalModel{ID: "cohere/command-r", Provider: domain.ProviderCohere, ModelName: "command-r", SupportsInference: true, LifecycleStatus: domain.ModelStatusActive}
	require.NoError(t, repo.UpsertGlobalModel(ctx, cohModel))
	cohCred := &domain.ProviderCredential{OrgID: org.ID, Provider: domain.ProviderCohere, BaseURL: oaiServer.URL, IsActive: true}
	require.NoError(t, vault.EncryptCredential(cohCred, "sk-coh"))
	require.NoError(t, repo.CreateProviderCredential(ctx, cohCred))

	mgCoh := &domain.ModelGroup{OrgID: org.ID, Alias: "cmpl-unsup", RoutingStrategy: domain.StrategyWeightedShuffle, IsActive: true}
	require.NoError(t, repo.CreateModelGroup(ctx, mgCoh))
	require.NoError(t, repo.CreateDeployment(ctx, &domain.Deployment{
		ModelGroupID: mgCoh.ID, GlobalModelID: cohModel.ID, CredentialID: cohCred.ID, Weight: 1, Status: domain.DeploymentStatusActive,
	}))

	pol, polErr := network.NewPolicy(config.OutboundSSRFConfig{AllowPrivateNetworks: true, AllowInsecureHTTP: true})
	require.NoError(t, polErr)
	oaiAdp := openai.NewAdapter(oaiServer.Client())
	oaiAdp.SetSSRFPolicy(pol)
	reg := adapter.NewRegistry()
	reg.Register(oaiAdp)
	reg.Register(cohere.NewAdapter(oaiServer.Client(), pol))

	rCfg := config.Default().Router
	rCfg.BaseRetryDelay = time.Millisecond
	rCfg.MaxRetryDelay = 5 * time.Millisecond
	rm := router.NewReliabilityManager(repo, reg, router.NewIntelligentRouter(repo, rCfg), router.NewLoadBalancer(), vault, rbac, nil, rCfg)

	idCtx := &domain.IdentityContext{OrgID: org.ID}
	ch, meta, err := rm.ExecuteCompletionStream(ctx, idCtx, &domain.CanonicalCompletionRequest{
		Model:  "cmpl-ok",
		Prompt: domain.CompletionPrompt{Strings: []string{"hi"}},
	})
	require.NoError(t, err)
	require.NotNil(t, meta)
	assert.NotNil(t, meta.WinningDeployment)
	var text string
	for c := range ch {
		if len(c.Choices) > 0 {
			text += c.Choices[0].Delta.Content
		}
	}
	assert.Equal(t, "ok", text)

	_, _, err = rm.ExecuteCompletionStream(ctx, idCtx, &domain.CanonicalCompletionRequest{
		Model:  "cmpl-unsup",
		Prompt: domain.CompletionPrompt{Strings: []string{"hi"}},
	})
	require.Error(t, err)
	var gwErr *domain.GatewayError
	require.ErrorAs(t, err, &gwErr)
	assert.Equal(t, "unsupported_capability", gwErr.Code)
}

func TestReliabilityManager_DeploymentTimeoutEnforcement(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	vault, _ := auth.NewVault("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	rbac := auth.NewRBACEngine(repo)

	org := &domain.Organization{Name: "Timeout Org", Slug: "timeout-org", IsActive: true}
	require.NoError(t, repo.CreateOrganization(ctx, org))

	slowSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/audio/speech" {
			w.Header().Set("Content-Type", "audio/mpeg")
			_, _ = w.Write([]byte("AUDIO"))
			return
		}
		select {
		case <-time.After(300 * time.Millisecond):
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"id":"c1","choices":[{"index":0,"message":{"role":"assistant","content":"late"},"finish_reason":"stop"}]}`))
		case <-r.Context().Done():
			return
		}
	}))
	defer slowSrv.Close()

	model := &domain.GlobalModel{
		ID: "openai/gpt-4o", Provider: domain.ProviderOpenAI, ModelName: "gpt-4o",
		SupportsInference: true, LifecycleStatus: domain.ModelStatusActive,
		Capabilities: domain.ModelCapabilities{AudioTTS: domain.CapabilitySupported},
	}
	require.NoError(t, repo.UpsertGlobalModel(ctx, model))
	cred := &domain.ProviderCredential{OrgID: org.ID, Provider: domain.ProviderOpenAI, BaseURL: slowSrv.URL, IsActive: true}
	require.NoError(t, vault.EncryptCredential(cred, "sk-test"))
	require.NoError(t, repo.CreateProviderCredential(ctx, cred))

	mg := &domain.ModelGroup{OrgID: org.ID, Alias: "gpt-4o", RoutingStrategy: domain.StrategyWeightedShuffle, MaxRetries: 0, IsActive: true}
	require.NoError(t, repo.CreateModelGroup(ctx, mg))
	require.NoError(t, repo.CreateDeployment(ctx, &domain.Deployment{
		ModelGroupID: mg.ID, GlobalModelID: model.ID, CredentialID: cred.ID, Weight: 1, TimeoutMs: 50, Status: domain.DeploymentStatusActive,
	}))

	pol, polErr := network.NewPolicy(config.OutboundSSRFConfig{AllowPrivateNetworks: true, AllowInsecureHTTP: true})
	require.NoError(t, polErr)
	oaiAdp := openai.NewAdapter(slowSrv.Client())
	oaiAdp.SetSSRFPolicy(pol)
	reg := adapter.NewRegistry()
	reg.Register(oaiAdp)

	rCfg := config.Default().Router
	rCfg.BaseRetryDelay = time.Millisecond
	rCfg.MaxRetryDelay = 5 * time.Millisecond
	rm := router.NewReliabilityManager(repo, reg, router.NewIntelligentRouter(repo, rCfg), router.NewLoadBalancer(), vault, rbac, nil, rCfg)

	idCtx := &domain.IdentityContext{OrgID: org.ID}
	_, _, err := rm.ExecuteChat(ctx, idCtx, &domain.CanonicalChatRequest{
		Model:    "gpt-4o",
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "hi"}},
	})
	require.Error(t, err)

	rc, ct, _, err := rm.ExecuteAudioSpeech(ctx, idCtx, &domain.CanonicalAudioSpeechRequest{
		Model: "gpt-4o", Input: "hi", Voice: "alloy",
	})
	require.NoError(t, err)
	assert.Equal(t, "audio/mpeg", ct)
	b, readErr := io.ReadAll(rc)
	require.NoError(t, readErr)
	assert.Equal(t, "AUDIO", string(b))
	require.NoError(t, rc.Close())
}
