package router

import (
	"context"
	"errors"
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
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

type stubChatAdapter struct {
	provider domain.ProviderType
	fn       func(ctx context.Context, dep *domain.Deployment, req *domain.CanonicalChatRequest) (*domain.CanonicalChatResponse, error)
	streamFn func(ctx context.Context, dep *domain.Deployment, req *domain.CanonicalChatRequest, onChunk adapter.StreamChunkHandler) (*domain.TokenUsage, error)
}

func (s *stubChatAdapter) Provider() domain.ProviderType { return s.provider }
func (s *stubChatAdapter) ChatCompletion(ctx context.Context, dep *domain.Deployment, req *domain.CanonicalChatRequest) (*domain.CanonicalChatResponse, error) {
	return s.fn(ctx, dep, req)
}
func (s *stubChatAdapter) StreamChatCompletion(ctx context.Context, dep *domain.Deployment, req *domain.CanonicalChatRequest, onChunk adapter.StreamChunkHandler) (*domain.TokenUsage, error) {
	if s.streamFn != nil {
		return s.streamFn(ctx, dep, req, onChunk)
	}
	return nil, errors.New("not implemented")
}
func (s *stubChatAdapter) Embeddings(context.Context, *domain.Deployment, *domain.CanonicalEmbeddingRequest) (*domain.CanonicalEmbeddingResponse, error) {
	return nil, errors.New("not implemented")
}
func (s *stubChatAdapter) HealthCheck(context.Context, *domain.Deployment) error { return nil }
func (s *stubChatAdapter) ListModels(context.Context, *domain.ProviderCredential) ([]domain.DiscoveredModel, error) {
	return nil, nil
}

func TestExecuteEmbeddings_RetryFallbackAndCircuitBreaker(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	vault, _ := auth.NewVault("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	rbac := auth.NewRBACEngine(repo)

	org := &domain.Organization{Name: "EmbOrg", Slug: "emb-org", IsActive: true}
	_ = repo.CreateOrganization(ctx, org)

	var primaryCalls atomic.Int32
	primarySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		primaryCalls.Add(1)
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprint(w, `{"error":{"message":"upstream error"}}`)
	}))
	defer primarySrv.Close()

	var fallbackCalls atomic.Int32
	fallbackSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fallbackCalls.Add(1)
		fmt.Fprint(w, `{"object":"list","data":[{"object":"embedding","index":0,"embedding":[0.1,0.2]}],"model":"text-embedding-3-small","usage":{"prompt_tokens":4,"total_tokens":4}}`)
	}))
	defer fallbackSrv.Close()

	pCred := &domain.ProviderCredential{OrgID: org.ID, Provider: domain.ProviderOpenAI, Name: "p", BaseURL: primarySrv.URL, IsActive: true}
	_ = vault.EncryptCredential(pCred, "sk-p")
	_ = repo.CreateProviderCredential(ctx, pCred)

	fbCred := &domain.ProviderCredential{OrgID: org.ID, Provider: domain.ProviderOpenAI, Name: "fb", BaseURL: fallbackSrv.URL, IsActive: true}
	_ = vault.EncryptCredential(fbCred, "sk-fb")
	_ = repo.CreateProviderCredential(ctx, fbCred)

	fbGroup := &domain.ModelGroup{
		OrgID:           org.ID,
		Alias:           "emb-fallback",
		RoutingStrategy: domain.StrategyLeastBusy,
		MaxRetries:      0,
		IsActive:        true,
	}
	_ = repo.CreateModelGroup(ctx, fbGroup)
	fbDep := &domain.Deployment{
		ModelGroupID:   fbGroup.ID,
		GlobalModelID:  "openai/text-embedding-3-small",
		CredentialID:   fbCred.ID,
		DeploymentName: "emb-fb-dep",
		Status:         domain.DeploymentStatusActive,
	}
	_ = repo.CreateDeployment(ctx, fbDep)

	primaryGroup := &domain.ModelGroup{
		OrgID:            org.ID,
		Alias:            "emb-primary",
		RoutingStrategy:  domain.StrategyLeastBusy,
		MaxRetries:       1,
		FailureThreshold: 2,
		CooldownSeconds:  5,
		FallbackGroupIDs: []string{fbGroup.ID},
		IsActive:         true,
	}
	_ = repo.CreateModelGroup(ctx, primaryGroup)
	primaryDep := &domain.Deployment{
		ModelGroupID:   primaryGroup.ID,
		GlobalModelID:  "openai/text-embedding-3-small",
		CredentialID:   pCred.ID,
		DeploymentName: "emb-primary-dep",
		Status:         domain.DeploymentStatusActive,
	}
	_ = repo.CreateDeployment(ctx, primaryDep)

	reg := adapter.NewRegistry()
	reg.Register(openai.NewAdapter(primarySrv.Client()))
	lb := NewLoadBalancer()
	ir := NewIntelligentRouter(repo, config.RouterConfig{})
	rm := NewReliabilityManager(repo, reg, ir, lb, vault, rbac, nil, config.RouterConfig{
		BaseRetryDelay: 1 * time.Millisecond,
		MaxRetryDelay:  5 * time.Millisecond,
		FailureWindow:  time.Minute,
	})

	resp, meta, err := rm.ExecuteEmbeddings(ctx, &domain.IdentityContext{OrgID: org.ID}, &domain.CanonicalEmbeddingRequest{
		Model: "emb-primary",
		Input: []string{"hello world"},
	})
	if err != nil {
		t.Fatalf("ExecuteEmbeddings failed: %v", err)
	}
	if resp == nil || len(resp.Data) != 1 {
		t.Fatalf("unexpected embedding response: %+v", resp)
	}
	if !meta.FallbackAttempted {
		t.Fatal("expected FallbackAttempted=true")
	}
	if meta.RetryCount != 1 {
		t.Fatalf("expected RetryCount=1, got %d", meta.RetryCount)
	}
	if meta.WinningDeployment == nil || meta.WinningDeployment.ID != fbDep.ID {
		t.Fatalf("expected winning deployment %s, got %+v", fbDep.ID, meta.WinningDeployment)
	}
	if meta.TTFTMs != 0 {
		t.Fatalf("expected TTFTMs=0 for non-streaming embeddings, got %d", meta.TTFTMs)
	}
	if primaryCalls.Load() != 2 {
		t.Fatalf("expected 2 primary calls (1 initial + 1 retry), got %d", primaryCalls.Load())
	}
	if fallbackCalls.Load() != 1 {
		t.Fatalf("expected 1 fallback call, got %d", fallbackCalls.Load())
	}
	if state := rm.GetCircuitState(ctx, primaryDep.ID); state != CircuitOpen {
		t.Fatalf("expected primary circuit state OPEN after 2 failures, got %s", state)
	}
}

func TestCircuitFailureAggregationAcrossManagers(t *testing.T) {
	ctx := context.Background()
	redisServer := miniredis.RunT(t)
	cfg := config.RouterConfig{
		FailureThreshold: 3,
		DefaultCooldown:  5 * time.Second,
		FailureWindow:    time.Minute,
	}
	first := NewReliabilityManager(nil, nil, nil, nil, nil, nil, storage.NewRedisFabric(redisServer.Addr(), "", 0), cfg)
	second := NewReliabilityManager(nil, nil, nil, nil, nil, nil, storage.NewRedisFabric(redisServer.Addr(), "", 0), cfg)
	dep := &domain.Deployment{ID: "shared-agg-dep"}

	first.recordFailure(ctx, dep, 3, 5)
	if first.GetCircuitState(ctx, dep.ID) != CircuitClosed {
		t.Fatal("circuit should remain closed after 1 failure")
	}

	second.recordFailure(ctx, dep, 3, 5)
	if second.GetCircuitState(ctx, dep.ID) != CircuitClosed {
		t.Fatal("circuit should remain closed after 2 cross-manager failures")
	}

	first.recordFailure(ctx, dep, 3, 5)
	if first.GetCircuitState(ctx, dep.ID) != CircuitOpen || second.GetCircuitState(ctx, dep.ID) != CircuitOpen {
		t.Fatal("expected shared circuit to trip to OPEN on the 3rd cross-manager failure")
	}
}

func TestRetryLoopNormalizesUntypedErrorsAndExcludesCaller4xxAndCancel(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	vault, _ := auth.NewVault("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	rbac := auth.NewRBACEngine(repo)

	org := &domain.Organization{Name: "ErrOrg", Slug: "err-org", IsActive: true}
	_ = repo.CreateOrganization(ctx, org)

	cred := &domain.ProviderCredential{OrgID: org.ID, Provider: domain.ProviderOpenAI, Name: "c", BaseURL: "http://localhost", IsActive: true}
	_ = vault.EncryptCredential(cred, "sk-test")
	_ = repo.CreateProviderCredential(ctx, cred)

	mg := &domain.ModelGroup{
		OrgID:            org.ID,
		Alias:            "err-group",
		RoutingStrategy:  domain.StrategyLeastBusy,
		MaxRetries:       1,
		FailureThreshold: 2,
		CooldownSeconds:  5,
		IsActive:         true,
	}
	_ = repo.CreateModelGroup(ctx, mg)
	dep := &domain.Deployment{
		ModelGroupID:   mg.ID,
		GlobalModelID:  "openai/gpt-4.1-mini",
		CredentialID:   cred.ID,
		DeploymentName: "err-dep",
		Status:         domain.DeploymentStatusActive,
	}
	_ = repo.CreateDeployment(ctx, dep)

	var mode atomic.Int32 // 0 = 400 non-retryable, 1 = context.Canceled, 2 = untyped transport error
	reg := adapter.NewRegistry()
	reg.Register(&stubChatAdapter{
		provider: domain.ProviderOpenAI,
		fn: func(ctx context.Context, dep *domain.Deployment, req *domain.CanonicalChatRequest) (*domain.CanonicalChatResponse, error) {
			switch mode.Load() {
			case 0:
				return nil, &domain.GatewayError{StatusCode: http.StatusBadRequest, Type: domain.ErrorTypeInvalidRequest, Message: "bad input", Retryable: false}
			case 1:
				return nil, context.Canceled
			default:
				return nil, errors.New("dial tcp: connection reset by peer")
			}
		},
	})

	rm := NewReliabilityManager(repo, reg, NewIntelligentRouter(repo, config.RouterConfig{}), NewLoadBalancer(), vault, rbac, nil, config.RouterConfig{
		BaseRetryDelay: 1 * time.Millisecond,
		MaxRetryDelay:  5 * time.Millisecond,
		FailureWindow:  time.Minute,
	})
	idCtx := &domain.IdentityContext{OrgID: org.ID}
	req := &domain.CanonicalChatRequest{Model: "err-group", Messages: []domain.CanonicalMessage{{Role: "user", Content: "hi"}}}

	// 1. Caller 4xx must not trip breaker.
	mode.Store(0)
	if _, _, err := rm.ExecuteChat(ctx, idCtx, req); err == nil {
		t.Fatal("expected 400 error")
	}
	if state := rm.GetCircuitState(ctx, dep.ID); state != CircuitClosed {
		t.Fatalf("caller 4xx must not trip circuit, got %s", state)
	}

	// 2. Context cancellation must not trip breaker.
	mode.Store(1)
	if _, _, err := rm.ExecuteChat(ctx, idCtx, req); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	if state := rm.GetCircuitState(ctx, dep.ID); state != CircuitClosed {
		t.Fatalf("context cancellation must not trip circuit, got %s", state)
	}

	// 3. Untyped transport error must be normalized, retried (2 attempts), and trip breaker (threshold=2).
	mode.Store(2)
	_, _, err := rm.ExecuteChat(ctx, idCtx, req)
	var gwErr *domain.GatewayError
	if !errors.As(err, &gwErr) || gwErr.StatusCode != http.StatusBadGateway {
		t.Fatalf("expected normalized 502 GatewayError, got %v", err)
	}
	if state := rm.GetCircuitState(ctx, dep.ID); state != CircuitOpen {
		t.Fatalf("untyped transport errors should trip circuit to OPEN, got %s", state)
	}
}

func TestLoadBalancer_LeastBusyAtomicReservation(t *testing.T) {
	lb := NewLoadBalancer()
	depA := &domain.Deployment{ID: "dep-a"}
	depB := &domain.Deployment{ID: "dep-b"}
	candidates := []*domain.Deployment{depA, depB}

	// Concurrent burst before OnRequestStart is called must alternate instead of herding onto dep-a.
	picks := make([]string, 4)
	for i := range picks {
		picks[i] = lb.Select(domain.StrategyLeastBusy, candidates).ID
	}
	if picks[0] != "dep-a" || picks[1] != "dep-b" || picks[2] != "dep-a" || picks[3] != "dep-b" {
		t.Fatalf("expected alternating reservations [dep-a dep-b dep-a dep-b], got %v", picks)
	}

	// OnRequestStart consumes one reservation while incrementing inFlight, keeping total effective load balanced.
	lb.OnRequestStart("dep-a")
	lb.mu.RLock()
	mA := lb.metrics["dep-a"]
	if mA.inFlight != 1 || len(mA.reservations) != 1 {
		t.Fatalf("expected dep-a inFlight=1 and 1 remaining reservation, got inFlight=%d reservations=%d", mA.inFlight, len(mA.reservations))
	}
	lb.mu.RUnlock()

	// Expired reservations are pruned.
	lb.mu.Lock()
	lb.metrics["dep-a"].reservations = []time.Time{time.Now().Add(-time.Second)}
	lb.metrics["dep-a"].inFlight = 0
	lb.metrics["dep-b"].reservations = nil
	lb.metrics["dep-b"].inFlight = 0
	lb.mu.Unlock()

	if sel := lb.Select(domain.StrategyLeastBusy, candidates); sel.ID != "dep-a" {
		t.Fatalf("expected dep-a after expired reservation pruning, got %s", sel.ID)
	}
}

func TestLatencyVsTTFTSeparation(t *testing.T) {
	ctx := context.Background()
	redisServer := miniredis.RunT(t)
	redisFabric := storage.NewRedisFabric(redisServer.Addr(), "", 0)
	defer redisFabric.Client().Close()

	repo := storage.NewMemoryRepository()
	vault, _ := auth.NewVault("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	rbac := auth.NewRBACEngine(repo)

	org := &domain.Organization{Name: "LatOrg", Slug: "lat-org", IsActive: true}
	_ = repo.CreateOrganization(ctx, org)
	cred := &domain.ProviderCredential{OrgID: org.ID, Provider: domain.ProviderOpenAI, Name: "c", BaseURL: "http://localhost", IsActive: true}
	_ = vault.EncryptCredential(cred, "sk-test")
	_ = repo.CreateProviderCredential(ctx, cred)

	mg := &domain.ModelGroup{
		OrgID:           org.ID,
		Alias:           "lat-group",
		RoutingStrategy: domain.StrategyLatencyBased,
		IsActive:        true,
	}
	_ = repo.CreateModelGroup(ctx, mg)
	dep := &domain.Deployment{
		ModelGroupID:   mg.ID,
		GlobalModelID:  "openai/gpt-4.1-mini",
		CredentialID:   cred.ID,
		DeploymentName: "lat-dep",
		Status:         domain.DeploymentStatusActive,
	}
	_ = repo.CreateDeployment(ctx, dep)

	reg := adapter.NewRegistry()
	reg.Register(&stubChatAdapter{
		provider: domain.ProviderOpenAI,
		fn: func(ctx context.Context, dep *domain.Deployment, req *domain.CanonicalChatRequest) (*domain.CanonicalChatResponse, error) {
			time.Sleep(15 * time.Millisecond)
			return &domain.CanonicalChatResponse{
				ID:      "resp-1",
				Choices: []domain.CanonicalChoice{{Message: domain.CanonicalMessage{Role: "assistant", Content: "ok"}}},
				Usage:   domain.TokenUsage{TotalTokens: 10},
			}, nil
		},
		streamFn: func(ctx context.Context, dep *domain.Deployment, req *domain.CanonicalChatRequest, onChunk adapter.StreamChunkHandler) (*domain.TokenUsage, error) {
			time.Sleep(10 * time.Millisecond)
			if err := onChunk(&domain.CanonicalStreamChunk{ID: "c1"}); err != nil {
				return nil, err
			}
			time.Sleep(20 * time.Millisecond)
			return &domain.TokenUsage{TotalTokens: 12}, nil
		},
	})

	lb := NewLoadBalancer(redisFabric)
	rm := NewReliabilityManager(repo, reg, NewIntelligentRouter(repo, config.RouterConfig{}), lb, vault, rbac, redisFabric, config.RouterConfig{})
	idCtx := &domain.IdentityContext{OrgID: org.ID}
	req := &domain.CanonicalChatRequest{Model: "lat-group", Messages: []domain.CanonicalMessage{{Role: "user", Content: "hi"}}}

	// Non-streaming must set LatencyMs > 0, TTFTMs == 0, and only populate ewma_latency_ms in Redis.
	_, chatMeta, err := rm.ExecuteChat(ctx, idCtx, req)
	if err != nil {
		t.Fatalf("ExecuteChat failed: %v", err)
	}
	if chatMeta.LatencyMs <= 0 {
		t.Fatalf("expected non-streaming LatencyMs > 0, got %d", chatMeta.LatencyMs)
	}
	if chatMeta.TTFTMs != 0 {
		t.Fatalf("expected non-streaming TTFTMs == 0, got %d", chatMeta.TTFTMs)
	}
	fields, err := redisFabric.Client().HGetAll(ctx, routingSignalKey(dep.ID)).Result()
	if err != nil {
		t.Fatalf("HGetAll failed: %v", err)
	}
	if fields["ewma_latency_ms"] == "" {
		t.Fatal("expected ewma_latency_ms to be populated after non-streaming chat")
	}
	if fields["ewma_ttft_ms"] != "" {
		t.Fatalf("expected ewma_ttft_ms to remain empty after non-streaming chat, got %q", fields["ewma_ttft_ms"])
	}

	// Streaming must set TTFTMs > 0, LatencyMs >= TTFTMs, and populate ewma_ttft_ms in Redis.
	_, streamMeta, err := rm.ExecuteStream(ctx, idCtx, req, func(*domain.CanonicalStreamChunk) error { return nil }, nil)
	if err != nil {
		t.Fatalf("ExecuteStream failed: %v", err)
	}
	if streamMeta.TTFTMs <= 0 || streamMeta.LatencyMs < streamMeta.TTFTMs {
		t.Fatalf("expected streaming TTFTMs > 0 and LatencyMs >= TTFTMs, got ttft=%d latency=%d", streamMeta.TTFTMs, streamMeta.LatencyMs)
	}
	fields, err = redisFabric.Client().HGetAll(ctx, routingSignalKey(dep.ID)).Result()
	if err != nil {
		t.Fatalf("HGetAll failed: %v", err)
	}
	if fields["ewma_ttft_ms"] == "" {
		t.Fatal("expected ewma_ttft_ms to be populated after streaming chat")
	}
}
