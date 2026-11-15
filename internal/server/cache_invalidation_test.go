package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/server"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// nonRevCountingRepo wraps *storage.MemoryRepository without exposing RoutingRevisionProvider,
// exercising TTL+PubSub L1 invalidation on a replica just like Postgres-backed pods.
type nonRevCountingRepo struct {
	storage.Repository
	ptu               storage.PTUShareRepository
	listGroupsCalls   atomic.Int64
	listPriorityCalls atomic.Int64
}

func (r *nonRevCountingRepo) ListModelGroups(ctx context.Context, orgID string) ([]*domain.ModelGroup, error) {
	r.listGroupsCalls.Add(1)
	return r.Repository.ListModelGroups(ctx, orgID)
}

func (r *nonRevCountingRepo) UpsertDeploymentPTUShare(ctx context.Context, share *domain.DeploymentPTUShare) error {
	return r.ptu.UpsertDeploymentPTUShare(ctx, share)
}

func (r *nonRevCountingRepo) ListDeploymentPTUShares(ctx context.Context, deploymentID string) ([]*domain.DeploymentPTUShare, error) {
	return r.ptu.ListDeploymentPTUShares(ctx, deploymentID)
}

func (r *nonRevCountingRepo) DeleteDeploymentPTUShare(ctx context.Context, deploymentID, teamID string) error {
	return r.ptu.DeleteDeploymentPTUShare(ctx, deploymentID, teamID)
}

func (r *nonRevCountingRepo) HasTeamPTUShares(ctx context.Context, teamID string) (bool, error) {
	return r.ptu.HasTeamPTUShares(ctx, teamID)
}

func (r *nonRevCountingRepo) UpsertPriorityClass(ctx context.Context, pc *domain.PriorityClass) error {
	return r.ptu.UpsertPriorityClass(ctx, pc)
}

func (r *nonRevCountingRepo) ListPriorityClasses(ctx context.Context, orgID string) ([]*domain.PriorityClass, error) {
	r.listPriorityCalls.Add(1)
	return r.ptu.ListPriorityClasses(ctx, orgID)
}

func TestRoutingCache_RedisPubSubInvalidatesL1AcrossReplicas(t *testing.T) {
	ctx := context.Background()
	mr := miniredis.RunT(t)

	newReplicaCfg := func() *config.Config {
		cfg := config.Default()
		cfg.Auth.MasterAdminKey = "sk-gw-pubsub-admin-test-key"
		cfg.Security.Network.OutboundSSRF.AllowPrivateNetworks = true
		cfg.Security.Network.OutboundSSRF.AllowInsecureHTTP = true
		cfg.Router.PreRouterMode = "quality"
		cfg.Router.DefaultFastAlias = "fast-a"
		cfg.Router.PriorityCapacity.Enabled = true
		cfg.Router.BaseRetryDelay = time.Millisecond
		cfg.Router.MaxRetryDelay = 5 * time.Millisecond
		return cfg
	}

	baseRepo := storage.NewMemoryRepository()
	countingRepo := &nonRevCountingRepo{Repository: baseRepo, ptu: baseRepo}

	rfA := storage.NewRedisFabric(mr.Addr(), "", 0)
	rfB := storage.NewRedisFabric(mr.Addr(), "", 0)
	t.Cleanup(func() {
		if rfA.Client() != nil {
			_ = rfA.Client().Close()
		}
		if rfB.Client() != nil {
			_ = rfB.Client().Close()
		}
	})

	gwA, err := server.New(newReplicaCfg(), baseRepo, rfA, nil)
	require.NoError(t, err)
	gwB, err := server.New(newReplicaCfg(), countingRepo, rfB, nil)
	require.NoError(t, err)

	gwB.StartWorkers(ctx)
	t.Cleanup(func() {
		shutCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		gwB.Shutdown(shutCtx)
	})

	// Allow Pub/Sub subscription goroutine to register on miniredis.
	time.Sleep(50 * time.Millisecond)

	org := &domain.Organization{ID: "org-pubsub-l1", Name: "PubSub Org", Slug: "pubsub-org", IsActive: true}
	require.NoError(t, baseRepo.CreateOrganization(ctx, org))
	require.NoError(t, baseRepo.SetOrgProviderSubscription(ctx, &domain.OrgProviderSubscription{
		OrgID: org.ID, Provider: domain.ProviderOpenAI, IsEnabled: true,
	}))

	keyBody, _ := json.Marshal(map[string]any{"org_id": org.ID, "name": "pubsub-key"})
	keyReq := httptest.NewRequest(http.MethodPost, "/admin/v1/keys", bytes.NewReader(keyBody))
	keyReq.Header.Set("Authorization", "Bearer sk-gw-pubsub-admin-test-key")
	keyReq.Header.Set("Content-Type", "application/json")
	keyRec := httptest.NewRecorder()
	gwA.Handler().ServeHTTP(keyRec, keyReq)
	require.Equal(t, http.StatusCreated, keyRec.Code, keyRec.Body.String())
	var vk domain.VirtualKey
	require.NoError(t, json.Unmarshal(keyRec.Body.Bytes(), &vk))

	var upHits atomic.Int32
	srvUp := mockOpenAIChatServer(t, "up-a", &upHits)
	defer srvUp.Close()

	credBody, _ := json.Marshal(map[string]any{
		"org_id": org.ID, "provider": "openai", "name": "cred-a",
		"base_url": srvUp.URL, "api_key": "sk-up-a",
	})
	credReq := httptest.NewRequest(http.MethodPost, "/admin/v1/credentials", bytes.NewReader(credBody))
	credReq.Header.Set("Authorization", "Bearer sk-gw-pubsub-admin-test-key")
	credReq.Header.Set("Content-Type", "application/json")
	credRec := httptest.NewRecorder()
	gwA.Handler().ServeHTTP(credRec, credReq)
	require.Equal(t, http.StatusCreated, credRec.Code, credRec.Body.String())
	var cred domain.ProviderCredential
	require.NoError(t, json.Unmarshal(credRec.Body.Bytes(), &cred))

	require.NoError(t, baseRepo.UpsertGlobalModel(ctx, &domain.GlobalModel{
		ID: "openai/fast-a", Provider: domain.ProviderOpenAI, ModelName: "fast-a",
		SupportsInference: true, QualityTier: 1,
		Capabilities: domain.ModelCapabilities{Streaming: domain.CapabilitySupported}, LifecycleStatus: domain.ModelStatusActive,
	}))
	mgA := &domain.ModelGroup{OrgID: org.ID, Alias: "fast-a", RoutingStrategy: domain.StrategyWeightedShuffle, IsActive: true}
	require.NoError(t, baseRepo.CreateModelGroup(ctx, mgA))
	require.NoError(t, baseRepo.CreateDeployment(ctx, &domain.Deployment{
		ModelGroupID: mgA.ID, GlobalModelID: "openai/fast-a", CredentialID: cred.ID,
		DeploymentName: "dep-a", Weight: 100, Status: domain.DeploymentStatusActive,
	}))

	sendChat := func() *httptest.ResponseRecorder {
		body := []byte(`{"model":"auto","messages":[{"role":"user","content":"hi"}]}`)
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+vk.RawKey)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		gwB.Handler().ServeHTTP(rec, req)
		return rec
	}

	countingRepo.listGroupsCalls.Store(0)
	countingRepo.listPriorityCalls.Store(0)

	// Warm replica B L1 caches.
	require.Equal(t, http.StatusOK, sendChat().Code)
	groupsAfterFirst := countingRepo.listGroupsCalls.Load()
	prioAfterFirst := countingRepo.listPriorityCalls.Load()
	require.GreaterOrEqual(t, groupsAfterFirst, int64(1))
	require.GreaterOrEqual(t, prioAfterFirst, int64(1))

	// Second request immediately hits L1 caches (repo call counts do not grow).
	require.Equal(t, http.StatusOK, sendChat().Code)
	assert.Equal(t, groupsAfterFirst, countingRepo.listGroupsCalls.Load(), "replica B should serve model groups from L1 cache")
	assert.Equal(t, prioAfterFirst, countingRepo.listPriorityCalls.Load(), "replica B should serve priority classes from L1 cache")

	// Mutate model group & priority class on replica A -> publishes Redis Pub/Sub Invalidations.
	mgBody, _ := json.Marshal(map[string]any{
		"org_id": org.ID, "alias": "fast-b", "routing_strategy": "weighted-shuffle",
	})
	mgReq := httptest.NewRequest(http.MethodPost, "/admin/v1/model-groups", bytes.NewReader(mgBody))
	mgReq.Header.Set("Authorization", "Bearer sk-gw-pubsub-admin-test-key")
	mgReq.Header.Set("Content-Type", "application/json")
	mgRec := httptest.NewRecorder()
	gwA.Handler().ServeHTTP(mgRec, mgReq)
	require.Equal(t, http.StatusCreated, mgRec.Code, mgRec.Body.String())

	pcBody, _ := json.Marshal(map[string]any{
		"org_id": org.ID, "name": "interactive", "weight": 3, "priority_rank": 1, "max_borrow_multiple": 2,
	})
	pcReq := httptest.NewRequest(http.MethodPost, "/admin/v1/priority-classes", bytes.NewReader(pcBody))
	pcReq.Header.Set("Authorization", "Bearer sk-gw-pubsub-admin-test-key")
	pcReq.Header.Set("Content-Type", "application/json")
	pcRec := httptest.NewRecorder()
	gwA.Handler().ServeHTTP(pcRec, pcReq)
	require.Equal(t, http.StatusOK, pcRec.Code, pcRec.Body.String())

	// Wait briefly for Pub/Sub delivery to evict replica B L1 caches, then verify next request reloads from repo.
	require.Eventually(t, func() bool {
		require.Equal(t, http.StatusOK, sendChat().Code)
		return countingRepo.listGroupsCalls.Load() > groupsAfterFirst &&
			countingRepo.listPriorityCalls.Load() > prioAfterFirst
	}, 2*time.Second, 25*time.Millisecond, "replica B must evict L1 routing caches after Pub/Sub invalidation")
}
