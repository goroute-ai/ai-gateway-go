package router_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/goroute-ai/ai-gateway-go/internal/adapter"
	"github.com/goroute-ai/ai-gateway-go/internal/adapter/openai"
	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/ratelimit"
	"github.com/goroute-ai/ai-gateway-go/internal/router"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFallbackHop_EnforcesRBACQuotaAndUpstream429Throttle(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	mr := miniredis.RunT(t)
	redisFabric := storage.NewRedisFabric(mr.Addr(), "", 0)
	defer func() { _ = redisFabric.Client().Close() }()

	vault, err := auth.NewVault("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	require.NoError(t, err)
	rbac := auth.NewRBACEngine(repo)

	org := &domain.Organization{ID: "org-fb", Name: "Fallback Org", Slug: "fallback-org", IsActive: true}
	require.NoError(t, repo.CreateOrganization(ctx, org))

	primarySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "4")
		w.WriteHeader(http.StatusTooManyRequests)
		fmt.Fprint(w, `{"error":{"message":"rate limited upstream","type":"rate_limit_error"}}`)
	}))
	defer primarySrv.Close()

	var fallbackHits atomic.Int32
	fallbackSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fallbackHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"id":"chatcmpl-fb","object":"chat.completion","created":1700000000,"model":"fallback-model","choices":[{"index":0,"message":{"role":"assistant","content":"fallback ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":5,"completion_tokens":5,"total_tokens":10}}`)
	}))
	defer fallbackSrv.Close()

	credPrimary := &domain.ProviderCredential{
		OrgID:    org.ID,
		Provider: domain.ProviderOpenAI,
		Name:     "primary-cred",
		BaseURL:  primarySrv.URL,
		IsActive: true,
	}
	require.NoError(t, vault.EncryptCredential(credPrimary, "sk-primary"))
	require.NoError(t, repo.CreateProviderCredential(ctx, credPrimary))

	credFallback := &domain.ProviderCredential{
		OrgID:    org.ID,
		Provider: domain.ProviderOpenAI,
		Name:     "fallback-cred",
		BaseURL:  fallbackSrv.URL,
		IsActive: true,
	}
	require.NoError(t, vault.EncryptCredential(credFallback, "sk-fallback"))
	require.NoError(t, repo.CreateProviderCredential(ctx, credFallback))

	gmPrimary := &domain.GlobalModel{ID: "openai/primary-model", Provider: domain.ProviderOpenAI, ModelName: "primary-model", LifecycleStatus: domain.ModelStatusActive}
	gmFallback := &domain.GlobalModel{ID: "openai/fallback-model", Provider: domain.ProviderOpenAI, ModelName: "fallback-model", LifecycleStatus: domain.ModelStatusActive}
	require.NoError(t, repo.UpsertGlobalModel(ctx, gmPrimary))
	require.NoError(t, repo.UpsertGlobalModel(ctx, gmFallback))

	fbGroup := &domain.ModelGroup{
		ID:              "mg-fb",
		OrgID:           org.ID,
		Alias:           "fallback-alias",
		RoutingStrategy: domain.StrategyLowestCost,
		IsActive:        true,
	}
	require.NoError(t, repo.CreateModelGroup(ctx, fbGroup))
	require.NoError(t, repo.CreateDeployment(ctx, &domain.Deployment{
		ModelGroupID:   fbGroup.ID,
		GlobalModelID:  gmFallback.ID,
		CredentialID:   credFallback.ID,
		DeploymentName: "dep-fallback",
		Status:         domain.DeploymentStatusActive,
		TimeoutMs:      3000,
	}))

	primaryGroup := &domain.ModelGroup{
		ID:               "mg-primary",
		OrgID:            org.ID,
		Alias:            "primary-alias",
		RoutingStrategy:  domain.StrategyLowestCost,
		FallbackGroupIDs: []string{fbGroup.ID},
		IsActive:         true,
	}
	require.NoError(t, repo.CreateModelGroup(ctx, primaryGroup))
	require.NoError(t, repo.CreateDeployment(ctx, &domain.Deployment{
		ModelGroupID:   primaryGroup.ID,
		GlobalModelID:  gmPrimary.ID,
		CredentialID:   credPrimary.ID,
		DeploymentName: "dep-primary",
		Status:         domain.DeploymentStatusActive,
		TimeoutMs:      3000,
	}))

	reg := adapter.NewRegistry()
	netPol, err := network.NewPolicy(config.OutboundSSRFConfig{AllowPrivateNetworks: true, AllowInsecureHTTP: true})
	require.NoError(t, err)
	oai := openai.NewAdapter(primarySrv.Client())
	oai.SetSSRFPolicy(netPol)
	reg.Register(oai)

	ir := router.NewIntelligentRouter(repo, config.RouterConfig{})
	lb := router.NewLoadBalancer()
	limiter := ratelimit.NewLimiter(redisFabric, 60, 30)
	limiter.SetEnabled(true)

	rm := router.NewReliabilityManager(repo, reg, ir, lb, vault, rbac, redisFabric, config.RouterConfig{
		DefaultMaxRetries: 0,
		FailureThreshold:  5,
		DefaultCooldown:   2 * time.Second,
	})
	rm.SetLimiter(limiter, true)

	// 1. Key restricted strictly to primary-alias must NOT traverse into fallback-alias.
	restrictedKey := &domain.IdentityContext{
		VirtualKeyID:     "vk-restricted",
		OrgID:            org.ID,
		KeyAllowedModels: []string{"primary-alias"},
	}
	reqCtx := auth.WithIdentity(ctx, restrictedKey)
	_, metaRestricted, execErr := rm.ExecuteChat(reqCtx, restrictedKey, &domain.CanonicalChatRequest{
		Model:    "primary-alias",
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "hi"}},
	})
	require.Error(t, execErr)
	assert.False(t, metaRestricted.FallbackAttempted, "blocked fallback must not mark fallback attempted or hit upstream")
	assert.Equal(t, int32(0), fallbackHits.Load())

	// Upstream 429 must have triggered dynamic upstream throttle marker for vk-restricted.
	retryAfter, throttled := limiter.CheckUpstream429Throttle(ctx, org.ID, "vk-restricted")
	assert.True(t, throttled)
	assert.Positive(t, retryAfter)

	// 2. Key with wildcard access triggers fallbackQuotaChecker on fallback-alias.
	wildKey := &domain.IdentityContext{
		VirtualKeyID: "vk-wild",
		OrgID:        org.ID,
	}
	rm.SetFallbackQuotaChecker(func(_ context.Context, _ *domain.IdentityContext, alias string, _ int) error {
		if alias == "fallback-alias" {
			return &domain.GatewayError{
				StatusCode: http.StatusTooManyRequests,
				Type:       domain.ErrorTypeRateLimit,
				Code:       "model_per_key_rpm_exceeded",
				Message:    "fallback model quota exhausted",
			}
		}
		return nil
	})
	_, _, quotaErr := rm.ExecuteChat(auth.WithIdentity(ctx, wildKey), wildKey, &domain.CanonicalChatRequest{
		Model:    "primary-alias",
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "hi"}},
	})
	require.Error(t, quotaErr)
	assert.Contains(t, quotaErr.Error(), "fallback model quota exhausted")
	assert.Equal(t, int32(0), fallbackHits.Load())

	// 3. Clearing fallback quota checker lets allowed key succeed via fallback.
	rm.SetFallbackQuotaChecker(nil)
	resp, metaOK, okErr := rm.ExecuteChat(auth.WithIdentity(ctx, wildKey), wildKey, &domain.CanonicalChatRequest{
		Model:    "primary-alias",
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "hi"}},
	})
	require.NoError(t, okErr)
	assert.True(t, metaOK.FallbackAttempted)
	assert.Equal(t, int32(1), fallbackHits.Load())
	assert.Equal(t, "fallback ok", resp.Choices[0].Message.Content)
}
