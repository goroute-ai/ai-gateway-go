package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/goroute-ai/ai-gateway-go/internal/adapter"
	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/finops"
	"github.com/goroute-ai/ai-gateway-go/internal/guardrails"
	"github.com/goroute-ai/ai-gateway-go/internal/observability"
	"github.com/goroute-ai/ai-gateway-go/internal/ratelimit"
	"github.com/goroute-ai/ai-gateway-go/internal/router"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/goroute-ai/ai-gateway-go/internal/validation"
)

func TestBudgetQuoteUsesKnownRatesAndFailsUnknownModels(t *testing.T) {
	s := &GatewayServer{repo: storage.NewMemoryRepository()}
	quote, err := s.tokenBudgetUpperBound(context.Background(), "", "openai/gpt-4.1", 100, 200)
	if err != nil {
		t.Fatalf("known model quote: %v", err)
	}
	if quote <= 0 {
		t.Fatalf("expected positive upper-bound quote, got %d", quote)
	}
	if _, err := s.tokenBudgetUpperBound(context.Background(), "", "custom/unpriced-model", 100, 200); err == nil {
		t.Fatal("expected unknown pricing to fail closed")
	}
}

func TestBudgetAliasUsesCachedPricingSummaryAndRefreshes(t *testing.T) {
	repo := storage.NewMemoryRepository()
	stats := &budgetLookupStats{}
	s := &GatewayServer{repo: repo, budgetStats: stats}
	for i := 0; i < 2; i++ {
		if _, err := s.tokenBudgetUpperBound(context.Background(), "", "auto", 100, 100); err != nil {
			t.Fatalf("alias quote %d: %v", i+1, err)
		}
	}
	if got := stats.catalogScans.Load(); got != 1 {
		t.Fatalf("catalog summary scans = %d, want 1 across repeated alias requests", got)
	}

	if _, err := repo.UpdateModelPricing(context.Background(), "openai/gpt-4.1", 777777777, 666666666, -1, -1, domain.PricingStatusVerified, "test", "", "test"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.tokenBudgetUpperBound(context.Background(), "", "auto", 100, 100); err != nil {
		t.Fatalf("alias quote after pricing update: %v", err)
	}
	if got := stats.catalogScans.Load(); got != 2 {
		t.Fatalf("catalog summary scans after pricing update = %d, want 2", got)
	}
}

func TestUnverifiedBudgetLookupDoesNotRescanCatalog(t *testing.T) {
	repo := storage.NewMemoryRepository()
	if err := repo.UpsertGlobalModel(context.Background(), &domain.GlobalModel{
		ID: "custom/unpriced-budget-model", Provider: domain.ProviderOpenAI, ModelName: "unpriced-budget-model", PricingStatus: domain.PricingStatusUnknown,
	}); err != nil {
		t.Fatal(err)
	}
	stats := &budgetLookupStats{}
	s := &GatewayServer{repo: repo, budgetStats: stats}
	_, err := s.tokenBudgetUpperBound(context.Background(), "", "unpriced-budget-model", 100, 100)
	if !errors.Is(err, errBudgetPricingUnverified) {
		t.Fatalf("unpriced model error = %v, want unverified pricing", err)
	}
	if got := stats.catalogScans.Load(); got != 0 {
		t.Fatalf("unverified model lookup performed %d catalog scans, want 0", got)
	}
}

func TestBudgetedUnsupportedEndpointRejectsBeforeDispatch(t *testing.T) {
	id := &domain.IdentityContext{KeyMaxBudgetMicros: 100}
	w := httptest.NewRecorder()
	if !rejectBudgetedUnsupported(w, id) {
		t.Fatal("expected a budgeted unsupported endpoint to be rejected")
	}
	if w.Code != 503 {
		t.Fatalf("status = %d, want 503", w.Code)
	}
	if rejectBudgetedUnsupported(httptest.NewRecorder(), &domain.IdentityContext{}) {
		t.Fatal("unbudgeted request should continue")
	}
}

func TestNonTokenModalityEndpointsRejectBudgetedRequests(t *testing.T) {
	repo := storage.NewMemoryRepository()
	s := &GatewayServer{
		repo:      repo,
		rbac:      auth.NewRBACEngine(repo),
		collector: observability.NewCollector(),
	}
	id := &domain.IdentityContext{
		VirtualKeyID:       "vk-budget",
		OrgID:              "org-budget",
		KeyMaxBudgetMicros: 1000,
	}

	assertBudgetEstimateUnavailable := func(name string, w *httptest.ResponseRecorder) {
		t.Helper()
		if w.Code != http.StatusServiceUnavailable {
			t.Fatalf("%s: status = %d, want 503 (body=%s)", name, w.Code, w.Body.String())
		}
		var errResp struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &errResp); err != nil {
			t.Fatalf("%s: decode error body: %v", name, err)
		}
		if errResp.Error.Code != "budget_estimate_unavailable" {
			t.Fatalf("%s: error.code = %q, want budget_estimate_unavailable", name, errResp.Error.Code)
		}
	}

	// 1. Images generations
	{
		req := httptest.NewRequest(http.MethodPost, "/v1/images/generations", bytes.NewBufferString(`{"model":"dall-e-3","prompt":"a cat"}`))
		req = req.WithContext(auth.WithIdentity(req.Context(), id))
		w := httptest.NewRecorder()
		s.handleImageGenerations(w, req)
		assertBudgetEstimateUnavailable("images/generations", w)
	}

	// 2. Audio speech
	{
		req := httptest.NewRequest(http.MethodPost, "/v1/audio/speech", bytes.NewBufferString(`{"model":"tts-1","input":"hello"}`))
		req = req.WithContext(auth.WithIdentity(req.Context(), id))
		w := httptest.NewRecorder()
		s.handleAudioSpeech(w, req)
		assertBudgetEstimateUnavailable("audio/speech", w)
	}

	// 3. Audio transcriptions (multipart)
	{
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		fw, err := mw.CreateFormFile("file", "sample.wav")
		if err != nil {
			t.Fatal(err)
		}
		_, _ = fw.Write([]byte("RIFF0000WAVE"))
		_ = mw.WriteField("model", "whisper-1")
		_ = mw.Close()

		req := httptest.NewRequest(http.MethodPost, "/v1/audio/transcriptions", &buf)
		req.Header.Set("Content-Type", mw.FormDataContentType())
		req = req.WithContext(auth.WithIdentity(req.Context(), id))
		w := httptest.NewRecorder()
		s.handleAudioTranscriptions(w, req)
		assertBudgetEstimateUnavailable("audio/transcriptions", w)
	}

	// 4. Moderations
	{
		req := httptest.NewRequest(http.MethodPost, "/v1/moderations", bytes.NewBufferString(`{"model":"omni-moderation-latest","input":"hello"}`))
		req = req.WithContext(auth.WithIdentity(req.Context(), id))
		w := httptest.NewRecorder()
		s.handleModerations(w, req)
		assertBudgetEstimateUnavailable("moderations", w)
	}

	// 5. Rerank
	{
		req := httptest.NewRequest(http.MethodPost, "/v1/rerank", bytes.NewBufferString(`{"model":"rerank-english-v3.0","query":"q","documents":["doc1"]}`))
		req = req.WithContext(auth.WithIdentity(req.Context(), id))
		w := httptest.NewRecorder()
		s.handleRerank(w, req)
		assertBudgetEstimateUnavailable("rerank", w)
	}
}

func TestResolveMatchedVerifiedModel_ResolvesModelGroupAlias(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	if err := repo.UpsertGlobalModel(ctx, &domain.GlobalModel{
		ID:                           "openai/custom-tts-alias-target",
		Provider:                     domain.ProviderOpenAI,
		ModelName:                    "custom-tts-alias-target",
		AudioTTSCostMicrosPer1KChars: 15000,
		PricingStatus:                domain.PricingStatusVerified,
	}); err != nil {
		t.Fatal(err)
	}
	mg := &domain.ModelGroup{
		ID:       "mg-tts-alias",
		OrgID:    "org-alias",
		Alias:    "prod-tts",
		IsActive: true,
	}
	if err := repo.CreateModelGroup(ctx, mg); err != nil {
		t.Fatal(err)
	}
	if err := repo.CreateDeployment(ctx, &domain.Deployment{
		ID:            "dep-tts-alias",
		ModelGroupID:  mg.ID,
		GlobalModelID: "openai/custom-tts-alias-target",
		Status:        domain.DeploymentStatusActive,
	}); err != nil {
		t.Fatal(err)
	}

	s := &GatewayServer{repo: repo}
	gm, sawUnverified, err := s.resolveMatchedVerifiedModel(ctx, "org-alias", "prod-tts")
	if err != nil {
		t.Fatalf("resolveMatchedVerifiedModel: %v", err)
	}
	if sawUnverified {
		t.Fatal("expected sawUnverified=false for verified deployment alias")
	}
	if gm == nil || gm.AudioTTSCostMicrosPer1KChars != 15000 {
		t.Fatalf("resolved global model = %#v, want AudioTTSCostMicrosPer1KChars=15000", gm)
	}
}

func TestUserOnlyBudgetAdmissionAndExhaustion(t *testing.T) {
	if identityHasBudget(nil) {
		t.Fatal("nil identity must not have budget")
	}
	if identityHasBudget(&domain.IdentityContext{}) {
		t.Fatal("zero budgets must not report identityHasBudget=true")
	}
	if !identityHasBudget(&domain.IdentityContext{UserMaxBudgetMicros: 100}) {
		t.Fatal("identityHasBudget must return true when only UserMaxBudgetMicros > 0")
	}

	ctx := context.Background()
	mr := miniredis.RunT(t)
	redisFabric := storage.NewRedisFabric(mr.Addr(), "", 0)
	t.Cleanup(func() { _ = redisFabric.Client().Close() })

	repo := storage.NewMemoryRepository()
	if err := repo.UpsertGlobalModel(ctx, &domain.GlobalModel{
		ID:                    "openai/gpt-4.1",
		Provider:              domain.ProviderOpenAI,
		ModelName:             "gpt-4.1",
		InputCostMicrosPer1M:  2_000_000,
		OutputCostMicrosPer1M: 8_000_000,
		MaxOutputTokens:       100,
		PricingStatus:         domain.PricingStatusVerified,
	}); err != nil {
		t.Fatal(err)
	}

	limiter := ratelimit.NewLimiter(redisFabric, 60, 300)
	s := &GatewayServer{
		repo:    repo,
		limiter: limiter,
	}

	upperBound, err := s.tokenBudgetUpperBound(ctx, "org-user-only", "openai/gpt-4.1", 100, 100)
	if err != nil {
		t.Fatalf("tokenBudgetUpperBound: %v", err)
	}
	if upperBound <= 0 {
		t.Fatalf("expected positive upper bound, got %d", upperBound)
	}

	id := &domain.IdentityContext{
		VirtualKeyID:        "vk-user-only",
		UserID:              "user-only-1",
		OrgID:               "org-user-only",
		UserMaxBudgetMicros: upperBound,
	}

	release1, err := s.acquireRequestQuotaWithCost(ctx, id, "openai/gpt-4.1", 100, 100, 100, "req-user-1")
	if err != nil {
		t.Fatalf("first user-only budgeted admission failed: %v", err)
	}
	resKey := "gw:budget:{org:org-user-only}:reservations:user:user-only-1"
	if members, _ := mr.ZMembers(resKey); len(members) != 1 || members[0] != "req-user-1" {
		t.Fatalf("expected user reservation req-user-1, got %v", members)
	}

	// Concurrent second request must be rejected because remaining user budget is insufficient.
	_, err = s.acquireRequestQuotaWithCost(ctx, id, "openai/gpt-4.1", 100, 100, 100, "req-user-2")
	var gwErr *domain.GatewayError
	if !errors.As(err, &gwErr) || gwErr.StatusCode != http.StatusTooManyRequests || gwErr.Code != "user_budget_exceeded" {
		t.Fatalf("expected 429 user_budget_exceeded while reserved, got %v", err)
	}

	// Refund first request (-1) and verify re-admission succeeds.
	release1(-1, -1)
	if members, _ := mr.ZMembers(resKey); len(members) != 0 {
		t.Fatalf("expected reservation to be cleared on refund, got %v", members)
	}

	release2, err := s.acquireRequestQuotaWithCost(ctx, id, "openai/gpt-4.1", 100, 100, 100, "req-user-2")
	if err != nil {
		t.Fatalf("re-admission after refund failed: %v", err)
	}
	// Settle full upperBound cost against Redis spend counter.
	release2(100, upperBound)

	spendKey := "gw:spend:{org:org-user-only}:user:user-only-1"
	if got, _ := mr.Get(spendKey); got != strconv.FormatInt(upperBound, 10) {
		t.Fatalf("user spend counter = %q, want %d", got, upperBound)
	}

	// Subsequent request must be rejected with user_budget_exceeded.
	_, err = s.acquireRequestQuotaWithCost(ctx, id, "openai/gpt-4.1", 100, 100, 100, "req-user-3")
	if !errors.As(err, &gwErr) || gwErr.StatusCode != http.StatusTooManyRequests || gwErr.Code != "user_budget_exceeded" {
		t.Fatalf("expected 429 user_budget_exceeded after budget exhaustion, got %v", err)
	}
}

func TestReservationLeaseRenewerInvokesAndStopsCleanly(t *testing.T) {
	ctx := context.Background()
	mr := miniredis.RunT(t)
	redisFabric := storage.NewRedisFabric(mr.Addr(), "", 0)
	t.Cleanup(func() { _ = redisFabric.Client().Close() })

	repo := storage.NewMemoryRepository()
	if err := repo.UpsertGlobalModel(ctx, &domain.GlobalModel{
		ID:                    "openai/gpt-4.1",
		Provider:              domain.ProviderOpenAI,
		ModelName:             "gpt-4.1",
		InputCostMicrosPer1M:  2_000_000,
		OutputCostMicrosPer1M: 8_000_000,
		MaxOutputTokens:       100,
		PricingStatus:         domain.PricingStatusVerified,
	}); err != nil {
		t.Fatal(err)
	}

	stats := &budgetLookupStats{leaseRenewInterval: 15 * time.Millisecond}
	s := &GatewayServer{
		repo:        repo,
		limiter:     ratelimit.NewLimiter(redisFabric, 60, 300),
		budgetStats: stats,
	}

	id := &domain.IdentityContext{
		VirtualKeyID:        "vk-lease-test",
		OrgID:               "org-lease-test",
		UserID:              "user-lease-test",
		UserMaxBudgetMicros: 1_000_000,
	}

	release, err := s.acquireRequestQuotaWithCost(ctx, id, "openai/gpt-4.1", 100, 100, 100, "req-lease-active")
	if err != nil {
		t.Fatalf("acquireRequestQuotaWithCost: %v", err)
	}

	resKey := "gw:budget:{org:org-lease-test}:reservations:user:user-lease-test"
	initialScore, err := mr.ZScore(resKey, "req-lease-active")
	if err != nil {
		t.Fatalf("initial ZScore: %v", err)
	}

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if stats.leaseRenewals.Load() >= 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got := stats.leaseRenewals.Load(); got < 2 {
		t.Fatalf("expected at least 2 lease renewals, got %d", got)
	}

	renewedScore, err := mr.ZScore(resKey, "req-lease-active")
	if err != nil {
		t.Fatalf("renewed ZScore: %v", err)
	}
	if renewedScore < initialScore {
		t.Fatalf("renewedScore %v < initialScore %v", renewedScore, initialScore)
	}

	// Releasing must stop the background renewer cleanly and clear the reservation.
	release(-1, -1)
	countAfterStop := stats.leaseRenewals.Load()
	time.Sleep(60 * time.Millisecond)
	if got := stats.leaseRenewals.Load(); got != countAfterStop {
		t.Fatalf("lease renewals continued after stop: before=%d after=%d", countAfterStop, got)
	}
	if members, _ := mr.ZMembers(resKey); len(members) != 0 {
		t.Fatalf("expected reservation to be removed on release, got %v", members)
	}

	// Context cancellation also stops the renewer cleanly even before stop() is called.
	cancelCtx, cancel := context.WithCancel(ctx)
	stopByCtx := s.startReservationLeaseRenewer(cancelCtx, id, "req-lease-ctx-cancel")
	cancel()
	stopByCtx()
}

type budgetStreamTestAdapter struct {
	providerErr error
	chatErr     error
	onStreamFn  func(ctx context.Context, emit adapter.StreamChunkHandler) error
}

func (a *budgetStreamTestAdapter) Provider() domain.ProviderType { return domain.ProviderOpenAI }
func (a *budgetStreamTestAdapter) ChatCompletion(context.Context, *domain.Deployment, *domain.CanonicalChatRequest) (*domain.CanonicalChatResponse, error) {
	if a.chatErr != nil {
		return nil, a.chatErr
	}
	return &domain.CanonicalChatResponse{
		ID:       "chat-ok",
		Model:    "gpt-4.1",
		Provider: domain.ProviderOpenAI,
		Usage:    domain.TokenUsage{PromptTokens: 10, CompletionTokens: 5, TotalTokens: 15},
	}, nil
}
func (a *budgetStreamTestAdapter) StreamChatCompletion(ctx context.Context, _ *domain.Deployment, _ *domain.CanonicalChatRequest, onChunk adapter.StreamChunkHandler) (*domain.TokenUsage, error) {
	if a.onStreamFn != nil {
		if err := a.onStreamFn(ctx, onChunk); err != nil {
			return nil, err
		}
	}
	if a.providerErr != nil {
		return nil, a.providerErr
	}
	return &domain.TokenUsage{PromptTokens: 10, CompletionTokens: 5, TotalTokens: 15}, nil
}
func (a *budgetStreamTestAdapter) Embeddings(context.Context, *domain.Deployment, *domain.CanonicalEmbeddingRequest) (*domain.CanonicalEmbeddingResponse, error) {
	return &domain.CanonicalEmbeddingResponse{}, nil
}
func (a *budgetStreamTestAdapter) ListModels(context.Context, *domain.ProviderCredential) ([]domain.DiscoveredModel, error) {
	return nil, nil
}

type nonFlushingRecorder struct {
	rec *httptest.ResponseRecorder
}

func (n *nonFlushingRecorder) Header() http.Header         { return n.rec.Header() }
func (n *nonFlushingRecorder) Write(b []byte) (int, error) { return n.rec.Write(b) }
func (n *nonFlushingRecorder) WriteHeader(statusCode int)  { n.rec.WriteHeader(statusCode) }

func setupBudgetSettlementServer(t *testing.T, adp adapter.ProviderAdapter) (*GatewayServer, *miniredis.Miniredis, *storage.MemoryRepository, *domain.GlobalModel, *domain.Organization) {
	t.Helper()
	ctx := context.Background()
	mr := miniredis.RunT(t)
	redisFabric := storage.NewRedisFabric(mr.Addr(), "", 0)
	t.Cleanup(func() { _ = redisFabric.Client().Close() })

	repo := storage.NewMemoryRepository()
	vault, err := auth.NewVault("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("vault: %v", err)
	}
	org := &domain.Organization{Name: "BudgetSettleOrg", Slug: "budget-settle-org", IsActive: true}
	if err := repo.CreateOrganization(ctx, org); err != nil {
		t.Fatal(err)
	}
	cred := &domain.ProviderCredential{
		OrgID: org.ID, Provider: domain.ProviderOpenAI, Name: "c1", BaseURL: "https://api.example.com", IsActive: true,
	}
	if err := vault.EncryptCredential(cred, "sk-test"); err != nil {
		t.Fatal(err)
	}
	if err := repo.CreateProviderCredential(ctx, cred); err != nil {
		t.Fatal(err)
	}
	gm := &domain.GlobalModel{
		ID:                    "openai/gpt-4.1",
		Provider:              domain.ProviderOpenAI,
		ModelName:             "gpt-4.1",
		SupportsInference:     true,
		LifecycleStatus:       domain.ModelStatusActive,
		PricingStatus:         domain.PricingStatusVerified,
		InputCostMicrosPer1M:  5_000_000,
		OutputCostMicrosPer1M: 15_000_000,
		MaxOutputTokens:       512,
	}
	if err := repo.UpsertGlobalModel(ctx, gm); err != nil {
		t.Fatal(err)
	}
	group := &domain.ModelGroup{OrgID: org.ID, Alias: "gpt-4.1", RoutingStrategy: domain.StrategyWeightedShuffle, IsActive: true}
	if err := repo.CreateModelGroup(ctx, group); err != nil {
		t.Fatal(err)
	}
	if err := repo.CreateDeployment(ctx, &domain.Deployment{
		ModelGroupID: group.ID, GlobalModelID: gm.ID, CredentialID: cred.ID, DeploymentName: "d1", Weight: 1, Status: domain.DeploymentStatusActive,
	}); err != nil {
		t.Fatal(err)
	}

	reg := adapter.NewRegistry()
	reg.Register(adp)
	rCfg := config.Default().Router
	rCfg.BaseRetryDelay = time.Millisecond
	rCfg.MaxRetryDelay = 5 * time.Millisecond
	rbac := auth.NewRBACEngine(repo)
	limiter := ratelimit.NewLimiter(redisFabric, 60, 300)
	collector := observability.NewCollector()
	rm := router.NewReliabilityManager(repo, reg, router.NewIntelligentRouter(repo, rCfg), router.NewLoadBalancer(redisFabric), vault, rbac, redisFabric, rCfg)
	spendWorker := finops.NewSpendWorker(repo, limiter, config.FinOpsConfig{BatchSize: 50, FlushInterval: 50 * time.Millisecond})

	s := &GatewayServer{
		repo:        repo,
		rbac:        rbac,
		limiter:     limiter,
		reliability: rm,
		validator:   validation.NewValidator(repo),
		guardrails:  guardrails.NewEngine(repo),
		spendWorker: spendWorker,
		collector:   collector,
	}
	return s, mr, repo, gm, org
}

func TestPreDispatchVsPostDispatchCancellationSettlement(t *testing.T) {
	endpoints := []struct {
		name string
		path string
		body func(stream bool) []byte
		call func(s *GatewayServer, w http.ResponseWriter, r *http.Request)
	}{
		{
			name: "chat_completions",
			path: "/v1/chat/completions",
			body: func(stream bool) []byte {
				return []byte(`{"model":"gpt-4.1","max_tokens":64,"stream":` + map[bool]string{true: "true", false: "false"}[stream] + `,"messages":[{"role":"user","content":"Hello world for budget settlement accounting test"}]}`)
			},
			call: func(s *GatewayServer, w http.ResponseWriter, r *http.Request) {
				s.handleChatCompletions(w, r)
			},
		},
		{
			name: "messages",
			path: "/v1/messages",
			body: func(stream bool) []byte {
				return []byte(`{"model":"gpt-4.1","max_tokens":64,"stream":` + map[bool]string{true: "true", false: "false"}[stream] + `,"messages":[{"role":"user","content":"Hello world for budget settlement accounting test"}]}`)
			},
			call: func(s *GatewayServer, w http.ResponseWriter, r *http.Request) {
				s.handleAnthropicMessages(w, r)
			},
		},
		{
			name: "responses",
			path: "/v1/responses",
			body: func(stream bool) []byte {
				return []byte(`{"model":"gpt-4.1","max_output_tokens":64,"stream":` + map[bool]string{true: "true", false: "false"}[stream] + `,"input":"Hello world for budget settlement accounting test"}`)
			},
			call: func(s *GatewayServer, w http.ResponseWriter, r *http.Request) {
				s.handleResponses(w, r)
			},
		},
	}

	for _, ep := range endpoints {
		t.Run(ep.name+"/pre_dispatch_refund", func(t *testing.T) {
			adp := &budgetStreamTestAdapter{}
			s, mr, repo, _, org := setupBudgetSettlementServer(t, adp)
			id := &domain.IdentityContext{
				VirtualKeyID:        "vk-pre-" + ep.name,
				UserID:              "user-pre-" + ep.name,
				OrgID:               org.ID,
				UserMaxBudgetMicros: 5_000_000,
			}

			req := httptest.NewRequest(http.MethodPost, ep.path, bytes.NewReader(ep.body(true)))
			req.Header.Set("X-Gateway-Request-Id", "req-pre-"+ep.name)
			req = req.WithContext(auth.WithIdentity(req.Context(), id))
			// nonFlushingRecorder fails sse.NewWriter / Flusher check after quota acquisition and before provider dispatch.
			rec := &nonFlushingRecorder{rec: httptest.NewRecorder()}
			ep.call(s, rec, req)

			resKey := "gw:budget:{org:" + org.ID + "}:reservations:user:" + id.UserID
			if members, _ := mr.ZMembers(resKey); len(members) != 0 {
				t.Fatalf("expected pre-dispatch refund to clear reservation, got %v", members)
			}
			spendKey := "gw:spend:{org:" + org.ID + "}:user:" + id.UserID
			if got, _ := mr.Get(spendKey); got != "" && got != "0" {
				t.Fatalf("expected $0.00 spend on pre-dispatch exit, got %q", got)
			}
			_ = s.spendWorker.FlushNow(context.Background())
			logs, err := repo.ListSpendLogs(context.Background(), org.ID, 10)
			if err != nil {
				t.Fatal(err)
			}
			if len(logs) != 0 {
				t.Fatalf("expected 0 spend logs on pre-dispatch failure, got %d", len(logs))
			}
		})

		t.Run(ep.name+"/post_dispatch_cancel_499", func(t *testing.T) {
			var cancelReq context.CancelFunc
			adp := &budgetStreamTestAdapter{
				onStreamFn: func(ctx context.Context, emit adapter.StreamChunkHandler) error {
					_ = emit(&domain.CanonicalStreamChunk{
						ID:    "chunk-1",
						Model: "gpt-4.1",
						Choices: []domain.CanonicalStreamChoice{{
							Index: 0,
							Delta: domain.CanonicalStreamDelta{Role: "assistant", Content: "partial"},
						}},
					})
					cancelReq()
					<-ctx.Done()
					return ctx.Err()
				},
			}
			s, mr, repo, gm, org := setupBudgetSettlementServer(t, adp)
			id := &domain.IdentityContext{
				VirtualKeyID:        "vk-499-" + ep.name,
				UserID:              "user-499-" + ep.name,
				OrgID:               org.ID,
				UserMaxBudgetMicros: 5_000_000,
			}

			reqCtx, cancel := context.WithCancel(context.Background())
			cancelReq = cancel
			defer cancel()

			req := httptest.NewRequest(http.MethodPost, ep.path, bytes.NewReader(ep.body(true)))
			req.Header.Set("X-Gateway-Request-Id", "req-499-"+ep.name)
			req = req.WithContext(auth.WithIdentity(reqCtx, id))
			rec := httptest.NewRecorder()
			ep.call(s, rec, req)

			resKey := "gw:budget:{org:" + org.ID + "}:reservations:user:" + id.UserID
			if members, _ := mr.ZMembers(resKey); len(members) != 0 {
				t.Fatalf("expected reservation to be settled on 499 cancel, got %v", members)
			}

			if err := s.spendWorker.FlushNow(context.Background()); err != nil {
				t.Fatalf("FlushNow: %v", err)
			}
			logs, err := repo.ListSpendLogs(context.Background(), org.ID, 10)
			if err != nil {
				t.Fatal(err)
			}
			if len(logs) != 1 {
				t.Fatalf("expected 1 spend log on 499 cancel, got %d", len(logs))
			}
			ev := logs[0]
			if ev.StatusCode != 499 {
				t.Fatalf("SpendEvent StatusCode = %d, want 499", ev.StatusCode)
			}
			wantCost, ok := finops.EstimateTokenCostUpperBound(gm, ev.Usage.PromptTokens, 0)
			if !ok || wantCost <= 0 {
				t.Fatalf("expected positive upper bound input cost, got %d (ok=%v)", wantCost, ok)
			}
			if ev.CostMicros != wantCost {
				t.Fatalf("SpendEvent CostMicros = %d, want %d", ev.CostMicros, wantCost)
			}
			spendKey := "gw:spend:{org:" + org.ID + "}:user:" + id.UserID
			gotSpend, _ := mr.Get(spendKey)
			if gotSpend == "" || gotSpend == "0" {
				t.Fatalf("expected positive Redis spend counter on 499 cancel, got %q", gotSpend)
			}
		})

		t.Run(ep.name+"/post_dispatch_stream_failure_502", func(t *testing.T) {
			adp := &budgetStreamTestAdapter{
				onStreamFn: func(_ context.Context, emit adapter.StreamChunkHandler) error {
					_ = emit(&domain.CanonicalStreamChunk{
						ID:    "chunk-1",
						Model: "gpt-4.1",
						Choices: []domain.CanonicalStreamChoice{{
							Index: 0,
							Delta: domain.CanonicalStreamDelta{Role: "assistant", Content: "partial"},
						}},
					})
					return &domain.GatewayError{
						StatusCode: http.StatusBadGateway,
						Type:       domain.ErrorTypeUpstream,
						Code:       "upstream_stream_error",
						Message:    "upstream connection reset",
					}
				},
			}
			s, mr, repo, gm, org := setupBudgetSettlementServer(t, adp)
			id := &domain.IdentityContext{
				VirtualKeyID:        "vk-502-" + ep.name,
				UserID:              "user-502-" + ep.name,
				OrgID:               org.ID,
				UserMaxBudgetMicros: 5_000_000,
			}

			req := httptest.NewRequest(http.MethodPost, ep.path, bytes.NewReader(ep.body(true)))
			req.Header.Set("X-Gateway-Request-Id", "req-502-"+ep.name)
			req = req.WithContext(auth.WithIdentity(req.Context(), id))
			rec := httptest.NewRecorder()
			ep.call(s, rec, req)

			resKey := "gw:budget:{org:" + org.ID + "}:reservations:user:" + id.UserID
			if members, _ := mr.ZMembers(resKey); len(members) != 0 {
				t.Fatalf("expected reservation to be settled on 502 failure, got %v", members)
			}

			if err := s.spendWorker.FlushNow(context.Background()); err != nil {
				t.Fatalf("FlushNow: %v", err)
			}
			logs, err := repo.ListSpendLogs(context.Background(), org.ID, 10)
			if err != nil {
				t.Fatal(err)
			}
			if len(logs) != 1 {
				t.Fatalf("expected 1 spend log on 502 stream failure, got %d", len(logs))
			}
			ev := logs[0]
			if ev.StatusCode != http.StatusBadGateway {
				t.Fatalf("SpendEvent StatusCode = %d, want 502", ev.StatusCode)
			}
			wantCost, ok := finops.EstimateTokenCostUpperBound(gm, ev.Usage.PromptTokens, 0)
			if !ok || wantCost <= 0 {
				t.Fatalf("expected positive upper bound input cost, got %d (ok=%v)", wantCost, ok)
			}
			if ev.CostMicros != wantCost {
				t.Fatalf("SpendEvent CostMicros = %d, want %d", ev.CostMicros, wantCost)
			}
			spendKey := "gw:spend:{org:" + org.ID + "}:user:" + id.UserID
			gotSpend, _ := mr.Get(spendKey)
			if gotSpend == "" || gotSpend == "0" {
				t.Fatalf("expected positive Redis spend counter on 502 stream failure, got %q", gotSpend)
			}
		})

		t.Run(ep.name+"/post_dispatch_sync_failure_502", func(t *testing.T) {
			adp := &budgetStreamTestAdapter{
				chatErr: &domain.GatewayError{
					StatusCode: http.StatusBadGateway,
					Type:       domain.ErrorTypeUpstream,
					Code:       "upstream_sync_error",
					Message:    "upstream error after dispatch",
				},
			}
			s, mr, repo, gm, org := setupBudgetSettlementServer(t, adp)
			id := &domain.IdentityContext{
				VirtualKeyID:        "vk-sync-502-" + ep.name,
				UserID:              "user-sync-502-" + ep.name,
				OrgID:               org.ID,
				UserMaxBudgetMicros: 5_000_000,
			}

			req := httptest.NewRequest(http.MethodPost, ep.path, bytes.NewReader(ep.body(false)))
			req.Header.Set("X-Gateway-Request-Id", "req-sync-502-"+ep.name)
			req = req.WithContext(auth.WithIdentity(req.Context(), id))
			rec := httptest.NewRecorder()
			ep.call(s, rec, req)

			resKey := "gw:budget:{org:" + org.ID + "}:reservations:user:" + id.UserID
			if members, _ := mr.ZMembers(resKey); len(members) != 0 {
				t.Fatalf("expected reservation to be settled on 502 sync failure, got %v", members)
			}

			if err := s.spendWorker.FlushNow(context.Background()); err != nil {
				t.Fatalf("FlushNow: %v", err)
			}
			logs, err := repo.ListSpendLogs(context.Background(), org.ID, 10)
			if err != nil {
				t.Fatal(err)
			}
			if len(logs) != 1 {
				t.Fatalf("expected 1 spend log on 502 sync failure, got %d", len(logs))
			}
			ev := logs[0]
			if ev.StatusCode != http.StatusBadGateway {
				t.Fatalf("SpendEvent StatusCode = %d, want 502", ev.StatusCode)
			}
			wantCost, ok := finops.EstimateTokenCostUpperBound(gm, ev.Usage.PromptTokens, 0)
			if !ok || wantCost <= 0 {
				t.Fatalf("expected positive upper bound input cost, got %d (ok=%v)", wantCost, ok)
			}
			if ev.CostMicros != wantCost {
				t.Fatalf("SpendEvent CostMicros = %d, want %d", ev.CostMicros, wantCost)
			}
			spendKey := "gw:spend:{org:" + org.ID + "}:user:" + id.UserID
			gotSpend, _ := mr.Get(spendKey)
			if gotSpend == "" || gotSpend == "0" {
				t.Fatalf("expected positive Redis spend counter on 502 sync failure, got %q", gotSpend)
			}
		})
	}
}

func TestHybridAdmissionRollbackAndDescriptorLeaseRenewerAndHardCap(t *testing.T) {
	ctx := context.Background()
	mr := miniredis.RunT(t)
	redisFabric := storage.NewRedisFabric(mr.Addr(), "", 0)
	defer func() { _ = redisFabric.Client().Close() }()

	repo := storage.NewMemoryRepository()
	if err := repo.UpsertGlobalModel(ctx, &domain.GlobalModel{
		ID:                    "openai/gpt-4.1",
		Provider:              domain.ProviderOpenAI,
		ModelName:             "gpt-4.1",
		InputCostMicrosPer1M:  2_000_000,
		OutputCostMicrosPer1M: 8_000_000,
		MaxOutputTokens:       100,
		PricingStatus:         domain.PricingStatusVerified,
	}); err != nil {
		t.Fatal(err)
	}

	stats := &budgetLookupStats{leaseRenewInterval: 15 * time.Millisecond}
	s := &GatewayServer{
		repo:        repo,
		limiter:     ratelimit.NewLimiter(redisFabric, 60, 300),
		budgetStats: stats,
		cfg:         config.Default(),
	}

	// 1. Hybrid admission rollback: key has RPM=1, TPM=100; project has TPM=10 (< 50 est tokens).
	// When descriptor acquisition fails on project TPM, key RPM/TPM must roll back cleanly.
	idBlockedByDesc := &domain.IdentityContext{
		VirtualKeyID:    "vk-hyb-rb",
		OrgID:           "org-hyb-rb",
		ProjectID:       "proj-tight",
		KeyRPMLimit:     1,
		KeyTPMLimit:     100,
		ProjectTPMLimit: 10,
	}
	if _, _, err := s.acquireQuotaWithThrottle(ctx, idBlockedByDesc, "openai/gpt-4.1", 50, 50, 0, "req-hyb-fail"); err == nil {
		t.Fatal("expected descriptor project TPM limit rejection")
	}

	// Verify key RPM=1 was NOT consumed by the failed hybrid admission.
	idClean := &domain.IdentityContext{
		VirtualKeyID: "vk-hyb-rb",
		OrgID:        "org-hyb-rb",
		KeyRPMLimit:  1,
		KeyTPMLimit:  100,
	}
	relClean, _, err := s.acquireQuotaWithThrottle(ctx, idClean, "openai/gpt-4.1", 50, 50, 0, "req-hyb-ok")
	if err != nil {
		t.Fatalf("expected zero partial RPM/TPM charge after failed descriptor step, got: %v", err)
	}
	relClean(50, 0, 0)

	// 2. Descriptor-only budget lease renewal (no legacy 4-scope budgets configured).
	idDescLease := &domain.IdentityContext{
		VirtualKeyID:           "vk-desc-lease",
		OrgID:                  "org-desc-lease",
		ProjectID:              "proj-lease-srv",
		ProjectMaxBudgetMicros: 5_000_000,
	}
	relLease, _, err := s.acquireQuotaWithThrottle(ctx, idDescLease, "openai/gpt-4.1", 100, 100, 100, "req-desc-lease")
	if err != nil {
		t.Fatalf("acquireQuotaWithThrottle(desc-lease): %v", err)
	}
	beforeRenewals := stats.leaseRenewals.Load()
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if stats.leaseRenewals.Load() >= beforeRenewals+2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if stats.leaseRenewals.Load() < beforeRenewals+2 {
		t.Fatalf("expected descriptor reservation lease renewals, got delta=%d", stats.leaseRenewals.Load()-beforeRenewals)
	}
	relLease(-1, -1, -1)

	// 3. Soft-throttling preserves hard cap on unthrottled scope:
	// Key has ThrottleOnBudgetExceeded=true (exhausted), but Org has hard cap without throttle.
	idHardCap := &domain.IdentityContext{
		VirtualKeyID:                "vk-soft-org-hard",
		OrgID:                       "org-soft-org-hard",
		KeyRPMLimit:                 10,
		KeyMaxBudgetMicros:          100,
		KeySpentMicros:              100,
		KeyThrottleOnBudgetExceeded: true,
		OrgMaxBudgetMicros:          50,
		OrgSpentMicros:              100,
		OrgThrottleOnBudgetExceeded: false,
	}
	if _, _, err := s.acquireQuotaWithThrottle(ctx, idHardCap, "openai/gpt-4.1", 100, 100, 100, "req-hard-cap"); err == nil {
		t.Fatal("expected unthrottled Org hard cap to reject even when key soft-throttle is active")
	}
}
