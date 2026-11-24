package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/server"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

func TestDeclarativeModelListBootstrapAndDynamicRouting(t *testing.T) {
	ctx := context.Background()

	// 1. Mock upstream OpenAI and Anthropic servers
	openaiUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/chat/completions") {
			var reqBody struct {
				Model string `json:"model"`
			}
			_ = json.NewDecoder(r.Body).Decode(&reqBody)
			if reqBody.Model == "" {
				reqBody.Model = "gpt-4o-mini"
			}
			fmt.Fprintf(w, `{"id":"chatcmpl_boot","object":"chat.completion","model":%q,"choices":[{"index":0,"message":{"role":"assistant","content":"Declarative OpenAI reply"},"finish_reason":"stop"}],"usage":{"prompt_tokens":10,"completion_tokens":6,"total_tokens":16}}`, reqBody.Model)
		}
	}))
	defer openaiUpstream.Close()

	antUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/messages" {
			fmt.Fprint(w, `{"id":"msg_boot","type":"message","role":"assistant","model":"claude-sonnet-4-20250514","content":[{"type":"text","text":"Declarative Claude reply"}],"stop_reason":"end_turn","usage":{"input_tokens":20,"output_tokens":15}}`)
		}
	}))
	defer antUpstream.Close()

	// 2. Set environment variables referenced via "os.environ/..." syntax
	t.Setenv("TEST_BOOT_OPENAI_KEY", "sk-DeclarativeBootKey")
	t.Setenv("TEST_BOOT_ANTHROPIC_KEY", "sk-ant-DeclarativeBootKey")

	// 3. Configure Gateway purely via declarative `ModelList` (ZERO /admin/v1/* calls!)
	cfg := config.Default()
	cfg.Auth.MasterAdminKey = "sk-gw-master-declarative-key"
	cfg.Auth.DefaultVirtualKey = "sk-gw-bootstrap-default-key"
	cfg.Security.Network.OutboundSSRF.AllowPrivateNetworks = true
	cfg.Security.Network.OutboundSSRF.AllowInsecureHTTP = true
	cfg.ModelList = []config.ModelListEntry{
		{
			ModelName: "fast",
			ModelParams: config.ModelParams{
				Model:   "openai/gpt-4o-mini",
				APIKey:  "os.environ/TEST_BOOT_OPENAI_KEY",
				APIBase: openaiUpstream.URL,
			},
		},
		{
			ModelName: "reasoning",
			ModelParams: config.ModelParams{
				Model:   "anthropic/claude-sonnet-4-20250514",
				APIKey:  "os.environ/TEST_BOOT_ANTHROPIC_KEY",
				APIBase: antUpstream.URL,
			},
		},
	}

	gw, err := server.New(cfg, storage.NewMemoryRepository(), nil, nil)
	if err != nil {
		t.Fatalf("server.New with declarative ModelList failed: %v", err)
	}
	gw.StartWorkers(ctx)
	defer gw.Shutdown(ctx)

	ts := httptest.NewServer(gw.Handler())
	defer ts.Close()

	callChat := func(model, prompt string) (*http.Response, domain.CanonicalChatResponse) {
		b, _ := json.Marshal(domain.CanonicalChatRequest{
			Model:    model,
			Messages: []domain.CanonicalMessage{{Role: "user", Content: prompt}},
		})
		req, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/chat/completions", bytes.NewReader(b))
		req.Header.Set("Authorization", "Bearer "+cfg.Auth.DefaultVirtualKey)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("chat request (%s) failed: %v", model, err)
		}
		defer resp.Body.Close()
		var out domain.CanonicalChatResponse
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp, out
	}

	// Test A: Logical alias ("fast") works immediately without any /admin/v1/* setup
	resp, out := callChat("fast", "Hello!")
	if resp.StatusCode != http.StatusOK || out.Provider != domain.ProviderOpenAI {
		t.Fatalf("expected 200 OK from OpenAI on 'fast', got status=%d provider=%s", resp.StatusCode, out.Provider)
	}

	// Test B: Dynamic Catalogue Model ("gpt-4o-mini" and "openai/gpt-4o") resolves on the fly
	// even though only "fast" and "reasoning" were declared in ModelList!
	resp, out = callChat("gpt-4o-mini", "Explain Go")
	if resp.StatusCode != http.StatusOK || resp.Header.Get("X-Gateway-Model") != "gpt-4o-mini" {
		t.Fatalf("expected dynamic resolution for 'gpt-4o-mini', got status=%d model=%s", resp.StatusCode, resp.Header.Get("X-Gateway-Model"))
	}

	resp, out = callChat("openai/gpt-4o", "Explain Go deeply")
	if resp.StatusCode != http.StatusOK || resp.Header.Get("X-Gateway-Model") != "gpt-4o" {
		t.Fatalf("expected dynamic resolution for 'openai/gpt-4o', got status=%d model=%s", resp.StatusCode, resp.Header.Get("X-Gateway-Model"))
	}

	// Test C: Smart Routing ("auto") routes complex prompt to Anthropic Claude ("reasoning")
	resp, out = callChat("auto", "Analyze step by step the distributed concurrency design and prove the mathematical trade-off:\n```go\nfunc solve() {}\n```")
	if resp.StatusCode != http.StatusOK || out.Provider != domain.ProviderAnthropic {
		t.Fatalf("expected 'auto' complex prompt to route to Anthropic, got status=%d provider=%s", resp.StatusCode, out.Provider)
	}
}

func TestObservabilityMetricsRequiresAdminCredentialAndLegacyMetricsRemoved(t *testing.T) {
	cfg := config.Default()
	cfg.Auth.MasterAdminKey = "sk-gw-metrics-test-master"
	gateway, err := server.New(cfg, storage.NewMemoryRepository(), nil, nil)
	if err != nil {
		t.Fatalf("create gateway: %v", err)
	}
	defer gateway.Shutdown(context.Background())

	// Legacy Prometheus /metrics endpoint is removed in v0.1 LTS (OTLP-only export).
	legacyReq := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	legacyReq.Header.Set("Authorization", "Bearer sk-gw-metrics-test-master")
	legacyRec := httptest.NewRecorder()
	gateway.Handler().ServeHTTP(legacyRec, legacyReq)
	if legacyRec.Code != http.StatusNotFound {
		t.Fatalf("expected 404 on removed /metrics endpoint, got %d", legacyRec.Code)
	}

	unauthenticated := httptest.NewRequest(http.MethodGet, "/admin/v1/observability/metrics", nil)
	unauthenticatedRecorder := httptest.NewRecorder()
	gateway.Handler().ServeHTTP(unauthenticatedRecorder, unauthenticated)
	if unauthenticatedRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without credentials, got %d", unauthenticatedRecorder.Code)
	}

	queryCredential := httptest.NewRequest(http.MethodGet, "/admin/v1/observability/metrics?token=sk-gw-metrics-test-master", nil)
	queryRecorder := httptest.NewRecorder()
	gateway.Handler().ServeHTTP(queryRecorder, queryCredential)
	if queryRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("expected query credentials to be rejected, got %d", queryRecorder.Code)
	}

	authenticated := httptest.NewRequest(http.MethodGet, "/admin/v1/observability/metrics", nil)
	authenticated.Header.Set("Authorization", "Bearer sk-gw-metrics-test-master")
	authenticatedRecorder := httptest.NewRecorder()
	gateway.Handler().ServeHTTP(authenticatedRecorder, authenticated)
	metricsBody := authenticatedRecorder.Body.String()
	if authenticatedRecorder.Code != http.StatusOK || !strings.Contains(metricsBody, `"total_requests"`) || !strings.Contains(metricsBody, `"cache_enabled"`) {
		t.Fatalf("expected 200 with TelemetrySnapshot JSON for admin credential, got %d: %s", authenticatedRecorder.Code, metricsBody)
	}
}

func TestBootstrapWiresRoutingFoundationFields(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()

	cfg := config.Default()
	cfg.Auth.MasterAdminKey = "sk-gw-bootstrap-foundation-master"
	cfg.ModelList = []config.ModelListEntry{
		{
			ModelName:       "tiered-fast",
			RoutingStrategy: string(domain.StrategyFastestResponse),
			ContextWindowFallbacks: []domain.FallbackTarget{
				{GroupAliasOrID: "long-ctx", Overrides: map[string]any{"max_tokens": 8192}},
			},
			ContentPolicyFallbacks: []domain.FallbackTarget{
				{GroupAliasOrID: "safe-tier"},
			},
			FallbackTargets: []domain.FallbackTarget{
				{GroupAliasOrID: "backup-fast"},
			},
			ModelParams: config.ModelParams{
				Model:             "openai/gpt-4.1-mini",
				APIKey:            "sk-test-bootstrap-foundation",
				Region:            "us-west",
				Weight:            80,
				RPM:               500,
				TPM:               250000,
				Priority:          3,
				Tags:              []string{"tier:fast", "region:us"},
				MaxBudgetMicros:   15000000,
				BudgetResetPeriod: "daily",
			},
		},
	}

	gw, err := server.New(cfg, repo, nil, nil)
	if err != nil {
		t.Fatalf("server.New failed: %v", err)
	}
	gw.StartWorkers(ctx)
	defer gw.Shutdown(ctx)

	mg, err := repo.GetModelGroupByAlias(ctx, cfg.Auth.DefaultOrgID, "tiered-fast")
	if err != nil {
		t.Fatalf("GetModelGroupByAlias failed: %v", err)
	}
	if mg.RoutingStrategy != domain.StrategyFastestResponse {
		t.Fatalf("RoutingStrategy = %q, want %q", mg.RoutingStrategy, domain.StrategyFastestResponse)
	}
	if len(mg.ContextWindowFallbacks) != 1 || mg.ContextWindowFallbacks[0].GroupAliasOrID != "long-ctx" {
		t.Fatalf("ContextWindowFallbacks mismatch: %+v", mg.ContextWindowFallbacks)
	}
	if len(mg.ContentPolicyFallbacks) != 1 || mg.ContentPolicyFallbacks[0].GroupAliasOrID != "safe-tier" {
		t.Fatalf("ContentPolicyFallbacks mismatch: %+v", mg.ContentPolicyFallbacks)
	}
	if len(mg.FallbackTargets) != 1 || mg.FallbackTargets[0].GroupAliasOrID != "backup-fast" {
		t.Fatalf("FallbackTargets mismatch: %+v", mg.FallbackTargets)
	}

	deps, err := repo.ListDeploymentsByGroup(ctx, mg.ID)
	if err != nil || len(deps) != 1 {
		t.Fatalf("ListDeploymentsByGroup failed: len=%d err=%v", len(deps), err)
	}
	dep := deps[0]
	if dep.Priority != 3 {
		t.Fatalf("Deployment.Priority = %d, want 3", dep.Priority)
	}
	if !reflect.DeepEqual(dep.Tags, []string{"tier:fast", "region:us"}) {
		t.Fatalf("Deployment.Tags = %#v, want [tier:fast region:us]", dep.Tags)
	}
	if dep.MaxBudgetMicros != 15000000 {
		t.Fatalf("Deployment.MaxBudgetMicros = %d, want 15000000", dep.MaxBudgetMicros)
	}
	if dep.BudgetResetPeriod != "daily" {
		t.Fatalf("Deployment.BudgetResetPeriod = %q, want daily", dep.BudgetResetPeriod)
	}
}
