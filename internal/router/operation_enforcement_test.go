package router_test

import (
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/adapter"
	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/router"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/stretchr/testify/require"
)

type opCheckedMockAdapter struct {
	provider  domain.ProviderType
	supported map[domain.OperationType]bool
}

func (a *opCheckedMockAdapter) Provider() domain.ProviderType { return a.provider }
func (a *opCheckedMockAdapter) SupportsOperation(op domain.OperationType) bool {
	return a.supported[op]
}
func (a *opCheckedMockAdapter) ChatCompletion(context.Context, *domain.Deployment, *domain.CanonicalChatRequest) (*domain.CanonicalChatResponse, error) {
	return &domain.CanonicalChatResponse{ID: "chat-ok"}, nil
}
func (a *opCheckedMockAdapter) StreamChatCompletion(context.Context, *domain.Deployment, *domain.CanonicalChatRequest, adapter.StreamChunkHandler) (*domain.TokenUsage, error) {
	return &domain.TokenUsage{}, nil
}
func (a *opCheckedMockAdapter) Embeddings(context.Context, *domain.Deployment, *domain.CanonicalEmbeddingRequest) (*domain.CanonicalEmbeddingResponse, error) {
	return &domain.CanonicalEmbeddingResponse{}, nil
}
func (a *opCheckedMockAdapter) Rerank(context.Context, *domain.Deployment, *domain.CanonicalRerankRequest) (*domain.CanonicalRerankResponse, error) {
	return &domain.CanonicalRerankResponse{ID: "rerank-ok"}, nil
}
func (a *opCheckedMockAdapter) GenerateImage(context.Context, *domain.Deployment, *domain.CanonicalImageRequest) (*domain.CanonicalImageResponse, error) {
	return &domain.CanonicalImageResponse{}, nil
}
func (a *opCheckedMockAdapter) TranscribeAudio(context.Context, *domain.Deployment, *domain.CanonicalAudioTranscriptionRequest) (*domain.CanonicalAudioResponse, error) {
	return &domain.CanonicalAudioResponse{}, nil
}
func (a *opCheckedMockAdapter) GenerateSpeech(context.Context, *domain.Deployment, *domain.CanonicalAudioSpeechRequest) (io.ReadCloser, string, error) {
	return io.NopCloser(strings.NewReader("")), "audio/mpeg", nil
}
func (a *opCheckedMockAdapter) ListModels(context.Context, *domain.ProviderCredential) ([]domain.DiscoveredModel, error) {
	return nil, nil
}

func TestReliabilityManager_EnforcesModelAndAdapterOperationSupport(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	vault, err := auth.NewVault("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	require.NoError(t, err)
	rbac := auth.NewRBACEngine(repo)

	org := &domain.Organization{Name: "OpOrg", Slug: "op-org", IsActive: true}
	require.NoError(t, repo.CreateOrganization(ctx, org))

	cred := &domain.ProviderCredential{
		OrgID:    org.ID,
		Provider: domain.ProviderCohere,
		Name:     "op-cred",
		BaseURL:  "https://api.example.com",
		IsActive: true,
	}
	require.NoError(t, vault.EncryptCredential(cred, "test-api-key"))
	require.NoError(t, repo.CreateProviderCredential(ctx, cred))

	// Model only supports rerank (not chat), while adapter supports chat + rerank, not images.
	gm := &domain.GlobalModel{
		ID:                "cohere/rerank-only",
		Provider:          domain.ProviderCohere,
		ModelName:         "rerank-only",
		DisplayName:       "Rerank Only",
		SupportsInference: true,
		LifecycleStatus:   domain.ModelStatusActive,
		SupportedOperations: []domain.OperationType{
			domain.OperationRerank,
		},
	}
	require.NoError(t, repo.UpsertGlobalModel(ctx, gm))

	group := &domain.ModelGroup{
		OrgID:           org.ID,
		Alias:           "rerank-only",
		RoutingStrategy: domain.StrategyWeightedShuffle,
		IsActive:        true,
	}
	require.NoError(t, repo.CreateModelGroup(ctx, group))

	dep := &domain.Deployment{
		ModelGroupID:   group.ID,
		GlobalModelID:  gm.ID,
		CredentialID:   cred.ID,
		DeploymentName: "dep-1",
		Weight:         1,
		Status:         domain.DeploymentStatusActive,
	}
	require.NoError(t, repo.CreateDeployment(ctx, dep))

	// Model that declares images, so we can test adapter-level OperationSupportChecker rejection.
	gmImg := &domain.GlobalModel{
		ID:                "cohere/img-declared",
		Provider:          domain.ProviderCohere,
		ModelName:         "img-declared",
		DisplayName:       "Image Declared",
		SupportsInference: true,
		LifecycleStatus:   domain.ModelStatusActive,
		SupportedOperations: []domain.OperationType{
			domain.OperationImageGeneration,
		},
	}
	require.NoError(t, repo.UpsertGlobalModel(ctx, gmImg))
	groupImg := &domain.ModelGroup{
		OrgID:           org.ID,
		Alias:           "img-declared",
		RoutingStrategy: domain.StrategyWeightedShuffle,
		IsActive:        true,
	}
	require.NoError(t, repo.CreateModelGroup(ctx, groupImg))
	require.NoError(t, repo.CreateDeployment(ctx, &domain.Deployment{
		ModelGroupID:   groupImg.ID,
		GlobalModelID:  gmImg.ID,
		CredentialID:   cred.ID,
		DeploymentName: "dep-img",
		Weight:         1,
		Status:         domain.DeploymentStatusActive,
	}))

	reg := adapter.NewRegistry()
	reg.Register(&opCheckedMockAdapter{
		provider: domain.ProviderCohere,
		supported: map[domain.OperationType]bool{
			domain.OperationChat:            true,
			domain.OperationRerank:          true,
			domain.OperationImageGeneration: false,
		},
	})

	rCfg := config.Default().Router
	rCfg.BaseRetryDelay = 1 * time.Millisecond
	rCfg.MaxRetryDelay = 5 * time.Millisecond

	rm := router.NewReliabilityManager(
		repo,
		reg,
		router.NewIntelligentRouter(repo, rCfg),
		router.NewLoadBalancer(),
		vault,
		rbac,
		nil,
		rCfg,
	)

	idCtx := &domain.IdentityContext{OrgID: org.ID}

	// 1. Model rejects ExecuteChat because SupportedOperations only allows rerank.
	_, _, err = rm.ExecuteChat(ctx, idCtx, &domain.CanonicalChatRequest{
		Model:    "rerank-only",
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "hi"}},
	})
	require.Error(t, err)

	// 2. ExecuteRerank succeeds because both model and adapter support rerank.
	rerankResp, _, err := rm.ExecuteRerank(ctx, idCtx, &domain.CanonicalRerankRequest{
		Model:     "rerank-only",
		Query:     "q",
		Documents: []domain.RerankDocument{{Text: "doc"}},
	})
	require.NoError(t, err)
	require.Equal(t, "rerank-ok", rerankResp.ID)

	// 3. Adapter OperationSupportChecker rejects ExecuteImage even when model declares images.
	_, _, err = rm.ExecuteImage(ctx, idCtx, &domain.CanonicalImageRequest{
		Model:  "img-declared",
		Prompt: "a cat",
	})
	require.Error(t, err)
}
