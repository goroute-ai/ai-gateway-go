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
