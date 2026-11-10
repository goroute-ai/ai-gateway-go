package router_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/adapter"
	"github.com/goroute-ai/ai-gateway-go/internal/adapter/anthropic"
	"github.com/goroute-ai/ai-gateway-go/internal/adapter/openai"
	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/router"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

func TestTwoStageRouterRetriesCooldownAndCrossProviderFallback(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	vault, _ := auth.NewVault("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	rbac := auth.NewRBACEngine(repo)

	org := &domain.Organization{Name: "TestOrg", Slug: "test-org", IsActive: true}
	_ = repo.CreateOrganization(ctx, org)

	// OpenAI server initially returns 429 Too Many Requests to trigger retry -> circuit OPEN -> fallback to Anthropic
	var oaiHealthy atomic.Bool
	var oaiCalls atomic.Int32
	flakyOAI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		oaiCalls.Add(1)
		if oaiHealthy.Load() {
			fmt.Fprint(w, `{"id":"chatcmpl-recovered","object":"chat.completion","created":1700000000,"model":"gpt-4.1-mini","choices":[{"index":0,"message":{"role":"assistant","content":"OpenAI recovered via half-open probe"},"finish_reason":"stop"}],"usage":{"prompt_tokens":8,"completion_tokens":5,"total_tokens":13}}`)
			return
		}
		w.WriteHeader(http.StatusTooManyRequests)
		fmt.Fprint(w, `{"error":{"message":"rate limit"}}`)
	}))
	defer flakyOAI.Close()

	// Anthropic fallback server succeeds with 200 OK
	var antCalls atomic.Int32
	healthyAnt := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		antCalls.Add(1)
		fmt.Fprint(w, `{"id":"msg_fb","type":"message","role":"assistant","model":"claude-sonnet-4-20250514","content":[{"type":"text","text":"Fallback Claude succeeded"}],"stop_reason":"end_turn","usage":{"input_tokens":10,"output_tokens":4}}`)
	}))
	defer healthyAnt.Close()

	oaiCred := &domain.ProviderCredential{OrgID: org.ID, Provider: domain.ProviderOpenAI, Name: "oai", BaseURL: flakyOAI.URL, IsActive: true}
	_ = vault.EncryptCredential(oaiCred, "sk-oai")
	_ = repo.CreateProviderCredential(ctx, oaiCred)

	antCred := &domain.ProviderCredential{OrgID: org.ID, Provider: domain.ProviderAnthropic, Name: "ant", BaseURL: healthyAnt.URL, IsActive: true}
	_ = vault.EncryptCredential(antCred, "sk-ant")
	_ = repo.CreateProviderCredential(ctx, antCred)

	// Fallback group (Anthropic Claude)
	fbGroup := &domain.ModelGroup{
		OrgID:           org.ID,
		Alias:           "reasoning",
		RoutingStrategy: domain.StrategyLatencyBased,
		MaxRetries:      1,
		IsActive:        true,
	}
	_ = repo.CreateModelGroup(ctx, fbGroup)
	_ = repo.CreateDeployment(ctx, &domain.Deployment{
		ModelGroupID:   fbGroup.ID,
		GlobalModelID:  "anthropic/claude-sonnet-4-20250514",
		CredentialID:   antCred.ID,
		DeploymentName: "ant-prod-1",
		Status:         domain.DeploymentStatusActive,
	})

	// Primary group ("fast" -> OpenAI) with fallback to "reasoning" (Anthropic)
	primaryGroup := &domain.ModelGroup{
		OrgID:            org.ID,
		Alias:            "fast",
		RoutingStrategy:  domain.StrategyWeightedShuffle,
		FallbackGroupIDs: []string{fbGroup.ID},
		MaxRetries:       1,
		FailureThreshold: 2,
		CooldownSeconds:  1, // 1 second cooldown so we can test OPEN -> HALF_OPEN -> CLOSED transition
		IsActive:         true,
	}
	_ = repo.CreateModelGroup(ctx, primaryGroup)
	oaiDep := &domain.Deployment{
		ModelGroupID:   primaryGroup.ID,
		GlobalModelID:  "openai/gpt-4.1-mini",
		CredentialID:   oaiCred.ID,
		DeploymentName: "oai-prod-1",
		Status:         domain.DeploymentStatusActive,
	}
	_ = repo.CreateDeployment(ctx, oaiDep)

	reg := adapter.NewRegistry()
	reg.Register(openai.NewAdapter(flakyOAI.Client()))
	reg.Register(anthropic.NewAdapter(healthyAnt.Client()))

	rCfg := config.Default().Router
	rCfg.BaseRetryDelay = 1 * time.Millisecond
	rCfg.MaxRetryDelay = 5 * time.Millisecond

	ir := router.NewIntelligentRouter(repo, rCfg)
	lb := router.NewLoadBalancer()
	rm := router.NewReliabilityManager(repo, reg, ir, lb, vault, rbac, nil, rCfg)

	// 1. Simple prompt with model: "auto" -> Stage 1 routes to "fast" (OpenAI) -> OpenAI fails twice (429) -> trips Circuit OPEN -> falls back to Anthropic!
	req := &domain.CanonicalChatRequest{
		Model:    "auto",
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "Hi there!"}},
	}
	resp, meta, err := rm.ExecuteChat(ctx, &domain.IdentityContext{OrgID: org.ID}, req)
	if err != nil {
		t.Fatalf("ExecuteChat failed: %v", err)
	}
	if !meta.FallbackAttempted || resp.Provider != domain.ProviderAnthropic {
		t.Fatalf("expected fallback to Anthropic, got meta=%+v provider=%s", meta, resp.Provider)
	}
	if rm.GetCircuitState(ctx, oaiDep.ID) != router.CircuitOpen {
		t.Fatalf("expected OpenAI deployment circuit breaker to be OPEN after 2 failures, got %s", rm.GetCircuitState(ctx, oaiDep.ID))
	}

	// 2. Wait for 1s cooldown window to elapse, heal OpenAI upstream, and verify HALF_OPEN recovery probe closes the circuit!
	time.Sleep(1100 * time.Millisecond)
	if state := rm.GetCircuitState(ctx, oaiDep.ID); state != router.CircuitHalfOpen {
		t.Fatalf("expected circuit state HALF_OPEN after cooldown window, got %s", state)
	}
	oaiHealthy.Store(true)
	respRecovered, metaRecovered, err := rm.ExecuteChat(ctx, &domain.IdentityContext{OrgID: org.ID}, req)
	if err != nil {
		t.Fatalf("ExecuteChat on half-open recovery failed: %v", err)
	}
	if respRecovered.Provider != domain.ProviderOpenAI || metaRecovered.FallbackAttempted {
		t.Fatalf("expected half-open probe to succeed on OpenAI without fallback, got provider=%s fb=%v", respRecovered.Provider, metaRecovered.FallbackAttempted)
	}
	if state := rm.GetCircuitState(ctx, oaiDep.ID); state != router.CircuitClosed {
		t.Fatalf("expected circuit state CLOSED after successful half-open probe, got %s", state)
	}

	// 3. Complex architectural prompt with model: "auto" -> Stage 1 routes directly to "reasoning"
	complexReq := &domain.CanonicalChatRequest{
		Model: "auto",
		Messages: []domain.CanonicalMessage{
			{Role: "user", Content: "Please analyze step by step how to architect a distributed concurrency algorithm and prove its correctness:\n```go\nfunc main() {}\n```"},
		},
	}
	decision, err := ir.ResolveGroup(ctx, org.ID, complexReq)
	if err != nil || decision.TargetGroupAlias != "reasoning" {
		t.Fatalf("expected complex prompt to route to 'reasoning', got %+v (err=%v)", decision, err)
	}
}

func TestIntelligentRouter_DynamicRoutingAuthorization(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	rCfg := config.Default().Router
	ir := router.NewIntelligentRouter(repo, rCfg)

	orgA := &domain.Organization{ID: "org-a", Name: "Org A", Slug: "org-a", IsActive: true}
	_ = repo.CreateOrganization(ctx, orgA)

	// 1. Tenant Org A has no Groq credential -> Requesting direct "groq/llama-3.3-70b-versatile" fails
	req := &domain.CanonicalChatRequest{
		Model: "groq/llama-3.3-70b-versatile",
		Messages: []domain.CanonicalMessage{
			{Role: "user", Content: "Hello"},
		},
	}
	dec, err := ir.ResolveGroup(ctx, orgA.ID, req)
	if err == nil {
		t.Fatalf("expected failure for tenant without credentials, got dec: %+v", dec)
	}

	// 2. Add Groq credential for Org A, but set Layer 2 Provider Subscription to disabled
	groqCred := &domain.ProviderCredential{
		ID:              "cred-groq-a",
		OrgID:           orgA.ID,
		Provider:        domain.ProviderGroq,
		Name:            "groq-a",
		DecryptedAPIKey: "gsk_test",
		IsActive:        true,
	}
	_ = repo.CreateProviderCredential(ctx, groqCred)
	_ = repo.SetOrgProviderSubscription(ctx, &domain.OrgProviderSubscription{
		OrgID:     orgA.ID,
		Provider:  domain.ProviderGroq,
		IsEnabled: false, // Explicitly disabled
	})

	dec, err = ir.ResolveGroup(ctx, orgA.ID, req)
	if err == nil {
		t.Fatalf("expected failure when provider subscription is disabled, got dec: %+v", dec)
	}

	// 3. Enable Provider Subscription, but set Layer 3 Org Model Policy to disabled for this model
	_ = repo.SetOrgProviderSubscription(ctx, &domain.OrgProviderSubscription{
		OrgID:     orgA.ID,
		Provider:  domain.ProviderGroq,
		IsEnabled: true,
	})
	_ = repo.SetOrgModelPolicy(ctx, &domain.OrgModelPolicy{
		OrgID:         orgA.ID,
		GlobalModelID: "groq/llama-3.3-70b-versatile",
		IsEnabled:     false, // Explicitly disabled
	})

	dec, err = ir.ResolveGroup(ctx, orgA.ID, req)
	if err == nil {
		t.Fatalf("expected failure when model policy is disabled, got dec: %+v", dec)
	}

	// 4. Enable Org Model Policy -> Authorized! Dynamic router auto-provisions ModelGroup and Deployment from catalogue!
	_ = repo.SetOrgModelPolicy(ctx, &domain.OrgModelPolicy{
		OrgID:         orgA.ID,
		GlobalModelID: "groq/llama-3.3-70b-versatile",
		IsEnabled:     true,
	})

	dec, err = ir.ResolveGroup(ctx, orgA.ID, req)
	if err != nil {
		t.Fatalf("expected successful dynamic routing for authorized tenant, got err: %v", err)
	}
	if dec == nil || dec.ModelGroup == nil {
		t.Fatalf("expected non-nil decision and model group, got %+v", dec)
	}
	if dec.TargetGroupAlias != "llama-3.3-70b-versatile" {
		t.Fatalf("expected alias llama-3.3-70b-versatile, got %s", dec.TargetGroupAlias)
	}

	// Verify model in repo was seeded with domain.ModelStatusActive so it's visible in GET /v1/models
	gm, err := repo.GetGlobalModel(ctx, "groq/llama-3.3-70b-versatile")
	if err != nil || gm == nil {
		t.Fatalf("expected global model to be dynamically imported into repo, got gm=%v, err=%v", gm, err)
	}
	if gm.LifecycleStatus != domain.ModelStatusActive {
		t.Fatalf("expected lifecycle status to be active, got %s", gm.LifecycleStatus)
	}

	// 5. Test direct catalogue import for a model defined in embedded catalog: "cerebras/llama-3.3-70b"
	cerebrasCred := &domain.ProviderCredential{
		ID:              "cred-cerebras-a",
		OrgID:           orgA.ID,
		Provider:        domain.ProviderCerebras,
		Name:            "cerebras-a",
		DecryptedAPIKey: "csk_test",
		IsActive:        true,
	}
	_ = repo.CreateProviderCredential(ctx, cerebrasCred)
	_ = repo.SetOrgProviderSubscription(ctx, &domain.OrgProviderSubscription{
		OrgID:     orgA.ID,
		Provider:  domain.ProviderCerebras,
		IsEnabled: true,
	})

	cerebrasReq := &domain.CanonicalChatRequest{
		Model: "cerebras/llama-3.3-70b",
		Messages: []domain.CanonicalMessage{
			{Role: "user", Content: "Hello Cerebras"},
		},
	}
	decCerebras, err := ir.ResolveGroup(ctx, orgA.ID, cerebrasReq)
	if err != nil {
		t.Fatalf("expected successful dynamic routing for Cerebras, got %v", err)
	}
	if decCerebras.TargetGroupAlias != "llama-3.3-70b" {
		t.Fatalf("expected alias llama-3.3-70b, got %s", decCerebras.TargetGroupAlias)
	}

	gmCerebras, err := repo.GetGlobalModel(ctx, "cerebras/llama-3.3-70b")
	if err != nil || gmCerebras == nil {
		t.Fatalf("expected Cerebras model in repo, got %v", err)
	}
	if gmCerebras.LifecycleStatus != domain.ModelStatusActive {
		t.Fatalf("expected active lifecycle status, got %s", gmCerebras.LifecycleStatus)
	}
	if gmCerebras.PricingProvenanceSource != "global-model-catalog-v1.0" {
		t.Fatalf("expected provenance global-model-catalog-v1.0, got %s", gmCerebras.PricingProvenanceSource)
	}
	if gmCerebras.PricingStatus != domain.PricingStatusUnknown {
		t.Fatalf("expected pricing status unknown, got %s", gmCerebras.PricingStatus)
	}
	if gmCerebras.InputCostMicrosPer1M <= 0 {
		t.Fatalf("expected non-zero input cost from catalog, got %d", gmCerebras.InputCostMicrosPer1M)
	}
}

func TestIntelligentRouter_ExplicitModelNoFallback(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	rCfg := config.Default().Router
	ir := router.NewIntelligentRouter(repo, rCfg)

	org := &domain.Organization{ID: "org-no-fallback", Name: "No Fallback Org", Slug: "no-fallback-org", IsActive: true}
	_ = repo.CreateOrganization(ctx, org)

	// Configure an active model group for "fast" in this org
	fastGroup := &domain.ModelGroup{
		ID:              "group-fast",
		OrgID:           org.ID,
		Alias:           "fast",
		RoutingStrategy: domain.StrategyLatencyBased,
		IsActive:        true,
	}
	_ = repo.CreateModelGroup(ctx, fastGroup)

	// 1. User explicitly requests an unconfigured model without credentials: "anthropic/claude-3-opus"
	// The gateway MUST NOT silently fall back to group "fast" (groups[0]); it must return 404!
	req := &domain.CanonicalChatRequest{
		Model: "anthropic/claude-3-opus",
		Messages: []domain.CanonicalMessage{
			{Role: "user", Content: "Hello Claude"},
		},
	}
	dec, err := ir.ResolveGroup(ctx, org.ID, req)
	if err == nil {
		t.Fatalf("expected 404 error for explicit unauthorized model, but got routed to %+v", dec)
	}
	gwErr, ok := err.(*domain.GatewayError)
	if !ok || gwErr.StatusCode != 404 || gwErr.Code != "model_group_not_found" {
		t.Fatalf("expected 404 model_group_not_found, got %+v", err)
	}

	// 2. User requests smart alias "auto" -> Should successfully route to "fast" group
	autoReq := &domain.CanonicalChatRequest{
		Model: "auto",
		Messages: []domain.CanonicalMessage{
			{Role: "user", Content: "Fast question"},
		},
	}
	decAuto, err := ir.ResolveGroup(ctx, org.ID, autoReq)
	if err != nil {
		t.Fatalf("expected smart alias auto to route to active group, got err: %v", err)
	}
	if decAuto.ModelGroup.Alias != "fast" {
		t.Fatalf("expected smart alias auto to resolve to fast group, got %s", decAuto.ModelGroup.Alias)
	}
}

type failingRepo struct {
	storage.Repository
	failSubs bool
	failPols bool
}

func (f *failingRepo) GetOrgProviderSubscriptions(ctx context.Context, orgID string) ([]*domain.OrgProviderSubscription, error) {
	if f.failSubs {
		return nil, fmt.Errorf("simulated db connection timeout")
	}
	return f.Repository.GetOrgProviderSubscriptions(ctx, orgID)
}

func (f *failingRepo) GetOrgModelPolicies(ctx context.Context, orgID string) ([]*domain.OrgModelPolicy, error) {
	if f.failPols {
		return nil, fmt.Errorf("simulated db connection timeout")
	}
	return f.Repository.GetOrgModelPolicies(ctx, orgID)
}

func TestIntelligentRouter_FailClosedOnRepoError(t *testing.T) {
	ctx := context.Background()
	memRepo := storage.NewMemoryRepository()
	rCfg := config.Default().Router

	org := &domain.Organization{ID: "org-fail-closed", Name: "Fail Closed Org", Slug: "fail-closed", IsActive: true}
	_ = memRepo.CreateOrganization(ctx, org)

	// Org has active Groq credential
	groqCred := &domain.ProviderCredential{
		ID:              "cred-groq-fc",
		OrgID:           org.ID,
		Provider:        domain.ProviderGroq,
		Name:            "groq-fc",
		DecryptedAPIKey: "gsk_test",
		IsActive:        true,
	}
	_ = memRepo.CreateProviderCredential(ctx, groqCred)

	req := &domain.CanonicalChatRequest{
		Model: "groq/llama-3.3-70b-versatile",
		Messages: []domain.CanonicalMessage{
			{Role: "user", Content: "Hello"},
		},
	}

	// 1. When GetOrgProviderSubscriptions fails with a database error, dynamic router MUST FAIL CLOSED
	failSubsRepo := &failingRepo{Repository: memRepo, failSubs: true}
	irSubs := router.NewIntelligentRouter(failSubsRepo, rCfg)
	_, err := irSubs.ResolveGroup(ctx, org.ID, req)
	if err == nil {
		t.Fatal("expected failure when GetOrgProviderSubscriptions returns database error (fail closed)")
	}

	// 2. When GetOrgModelPolicies fails with a database error, dynamic router MUST FAIL CLOSED
	failPolsRepo := &failingRepo{Repository: memRepo, failPols: true}
	irPols := router.NewIntelligentRouter(failPolsRepo, rCfg)
	_, err = irPols.ResolveGroup(ctx, org.ID, req)
	if err == nil {
		t.Fatal("expected failure when GetOrgModelPolicies returns database error (fail closed)")
	}
}

func TestIntelligentRouter_RejectsPreloadedNonInferenceModel(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	org := &domain.Organization{ID: "org-non-inference", Name: "Non Inference", Slug: "non-inference", IsActive: true}
	_ = repo.CreateOrganization(ctx, org)
	_ = repo.CreateProviderCredential(ctx, &domain.ProviderCredential{
		ID: "cred-groq-non-inference", OrgID: org.ID, Provider: domain.ProviderGroq,
		Name: "groq", IsActive: true,
	})
	_ = repo.UpsertGlobalModel(ctx, &domain.GlobalModel{
		ID: "groq/image-only", Provider: domain.ProviderGroq, ModelName: "image-only",
		LifecycleStatus: domain.ModelStatusActive, SupportsInference: false,
	})

	ir := router.NewIntelligentRouter(repo, config.Default().Router)
	_, err := ir.ResolveGroup(ctx, org.ID, &domain.CanonicalChatRequest{
		Model: "groq/image-only", Messages: []domain.CanonicalMessage{{Role: "user", Content: "hello"}},
	})
	if err == nil {
		t.Fatal("expected a preloaded non-inference model to be rejected")
	}
}

func TestIntelligentRouter_RequiresRegisteredTransportEvenWithCredentialBaseURL(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	org := &domain.Organization{ID: "org-unknown-transport", Name: "Unknown Transport", Slug: "unknown-transport", IsActive: true}
	_ = repo.CreateOrganization(ctx, org)
	_ = repo.CreateProviderCredential(ctx, &domain.ProviderCredential{
		ID: "cred-custom-endpoint", OrgID: org.ID, Provider: domain.ProviderType("unregistered"),
		Name: "custom", BaseURL: "https://example.invalid/v1", IsActive: true,
	})

	ir := router.NewIntelligentRouter(repo, config.Default().Router)
	_, err := ir.ResolveGroup(ctx, org.ID, &domain.CanonicalChatRequest{
		Model: "unregistered/model-x", Messages: []domain.CanonicalMessage{{Role: "user", Content: "hello"}},
	})
	if err == nil {
		t.Fatal("expected provider with only a credential base URL to be rejected without a registered transport")
	}
}

func TestIntelligentRouter_RefuseUncallableProviderWithoutEndpoint(t *testing.T) {
	ctx := context.Background()
	memRepo := storage.NewMemoryRepository()
	rCfg := config.Default().Router
	ir := router.NewIntelligentRouter(memRepo, rCfg)

	org := &domain.Organization{ID: "org-uncallable", Name: "Uncallable Org", Slug: "uncallable", IsActive: true}
	_ = memRepo.CreateOrganization(ctx, org)

	// Org has active credential for an uncallable third-party tool (e.g. "duckduckgo") without APIBase
	toolCred := &domain.ProviderCredential{
		ID:              "cred-duckduckgo",
		OrgID:           org.ID,
		Provider:        domain.ProviderType("duckduckgo"),
		Name:            "ddg-key",
		DecryptedAPIKey: "tool_key",
		IsActive:        true,
	}
	_ = memRepo.CreateProviderCredential(ctx, toolCred)

	req := &domain.CanonicalChatRequest{
		Model: "duckduckgo/search-tool",
		Messages: []domain.CanonicalMessage{
			{Role: "user", Content: "Hello"},
		},
	}

	// Router MUST refuse to dynamically provision an uncallable provider without a registered transport.
	dec, err := ir.ResolveGroup(ctx, org.ID, req)
	if err == nil {
		t.Fatalf("expected 404 for uncallable provider without api_base, got decision: %+v", dec)
	}
	gwErr, ok := err.(*domain.GatewayError)
	if !ok || gwErr.StatusCode != 404 || gwErr.Code != "model_group_not_found" {
		t.Fatalf("expected 404 model_group_not_found, got %+v", err)
	}

	// A credential BaseURL alone does not register a compatible adapter.
	toolCred.BaseURL = "https://custom-openai-compat.internal/v1"
	_ = memRepo.UpdateProviderCredential(ctx, toolCred)
	if _, err := ir.ResolveGroup(ctx, org.ID, req); err == nil {
		t.Fatal("expected a credential BaseURL without a registered transport to remain uncallable")
	}

	// A startup-registered custom profile is callable even when its endpoint comes from the profile.
	ir.SetProviderCallable(func(provider domain.ProviderType) bool { return provider == domain.ProviderType("duckduckgo") })

	decCustom, err := ir.ResolveGroup(ctx, org.ID, req)
	if err != nil {
		t.Fatalf("expected dynamic provisioning to succeed for a registered custom profile, got error: %v", err)
	}
	if decCustom.TargetGroupAlias != "search-tool" {
		t.Fatalf("expected alias search-tool, got %s", decCustom.TargetGroupAlias)
	}
}
