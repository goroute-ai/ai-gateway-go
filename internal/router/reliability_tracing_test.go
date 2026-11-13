package router_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/adapter"
	"github.com/goroute-ai/ai-gateway-go/internal/adapter/openai"
	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/observability"
	"github.com/goroute-ai/ai-gateway-go/internal/router"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"go.opentelemetry.io/otel/codes"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

func TestReliabilityManagerEmitsGenAIClientChildSpansWithoutSecretsOrPrompts(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	vault, _ := auth.NewVault("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	rbac := auth.NewRBACEngine(repo)

	org := &domain.Organization{Name: "TraceOrg", Slug: "trace-org", IsActive: true}
	_ = repo.CreateOrganization(ctx, org)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"id":"chatcmpl-1","object":"chat.completion","created":1700000000,"model":"gpt-4.1-mini","choices":[{"index":0,"message":{"role":"assistant","content":"secret-response"},"finish_reason":"stop"}],"usage":{"prompt_tokens":12,"completion_tokens":7,"total_tokens":19}}`)
	}))
	defer upstream.Close()

	cred := &domain.ProviderCredential{OrgID: org.ID, Provider: domain.ProviderOpenAI, Name: "oai", BaseURL: upstream.URL, IsActive: true}
	_ = vault.EncryptCredential(cred, "sk-upstream-secret-credential-12345")
	_ = repo.CreateProviderCredential(ctx, cred)

	group := &domain.ModelGroup{
		OrgID:           org.ID,
		Alias:           "fast",
		RoutingStrategy: domain.StrategyWeightedShuffle,
		MaxRetries:      0,
		IsActive:        true,
	}
	_ = repo.CreateModelGroup(ctx, group)
	_ = repo.CreateDeployment(ctx, &domain.Deployment{
		ModelGroupID:   group.ID,
		CredentialID:   cred.ID,
		DeploymentName: "oai-primary",
		Weight:         100,
		Status:         domain.DeploymentStatusActive,
		GlobalModel: &domain.GlobalModel{
			Provider:  domain.ProviderOpenAI,
			ModelName: "gpt-4.1-mini",
		},
	})

	reg := adapter.NewRegistry()
	reg.Register(openai.NewAdapter(upstream.Client()))
	ir := router.NewIntelligentRouter(repo, config.RouterConfig{})
	lb := router.NewLoadBalancer()
	rm := router.NewReliabilityManager(repo, reg, ir, lb, vault, rbac, nil, config.RouterConfig{})

	sr := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sr))
	defer func() { _ = tp.Shutdown(ctx) }()

	parentTracer := tp.Tracer("test-server")
	var resp *domain.CanonicalChatResponse
	var err error
	handler := observability.TraceMiddlewareWithTracer(parentTracer)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp, _, err = rm.ExecuteChat(r.Context(), &domain.IdentityContext{OrgID: org.ID}, &domain.CanonicalChatRequest{
			Model: "fast",
			Messages: []domain.CanonicalMessage{
				{Role: "user", Content: "top-secret-prompt-text"},
			},
		})
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if err != nil || resp == nil {
		t.Fatalf("ExecuteChat failed: err=%v resp=%v", err, resp)
	}

	ended := sr.Ended()
	if len(ended) < 2 {
		t.Fatalf("expected server + gen_ai.client spans, got %d", len(ended))
	}

	var clientSpan sdktrace.ReadOnlySpan
	var serverSpan sdktrace.ReadOnlySpan
	for _, sp := range ended {
		switch sp.Name() {
		case "gen_ai.client":
			clientSpan = sp
		case "HTTP POST":
			serverSpan = sp
		}
	}
	if clientSpan == nil || serverSpan == nil {
		t.Fatalf("missing expected spans: server=%v client=%v", serverSpan != nil, clientSpan != nil)
	}
	if clientSpan.SpanKind() != trace.SpanKindClient {
		t.Fatalf("expected SpanKindClient, got %v", clientSpan.SpanKind())
	}
	if clientSpan.Parent().SpanID() != serverSpan.SpanContext().SpanID() {
		t.Fatalf("expected gen_ai.client parent %s, got %s", serverSpan.SpanContext().SpanID(), clientSpan.Parent().SpanID())
	}
	if clientSpan.Status().Code == codes.Error {
		t.Fatalf("unexpected error status on successful client span")
	}

	attrs := make(map[string]any)
	for _, a := range clientSpan.Attributes() {
		attrs[string(a.Key)] = a.Value.AsInterface()
		valStr := fmt.Sprint(a.Value.AsInterface())
		if strings.Contains(valStr, "top-secret-prompt-text") || strings.Contains(valStr, "sk-upstream-secret") {
			t.Fatalf("sensitive prompt or credential leaked into span attribute %s=%q", a.Key, valStr)
		}
	}
	if attrs["gen_ai.system"] != "openai" {
		t.Fatalf("gen_ai.system = %v, want openai", attrs["gen_ai.system"])
	}
	if attrs["gen_ai.request.model"] != "gpt-4.1-mini" {
		t.Fatalf("gen_ai.request.model = %v, want gpt-4.1-mini", attrs["gen_ai.request.model"])
	}
	if attrs["gen_ai.usage.input_tokens"] != int64(12) {
		t.Fatalf("gen_ai.usage.input_tokens = %v, want 12", attrs["gen_ai.usage.input_tokens"])
	}
	if attrs["gen_ai.usage.output_tokens"] != int64(7) {
		t.Fatalf("gen_ai.usage.output_tokens = %v, want 7", attrs["gen_ai.usage.output_tokens"])
	}
	if attrs["gen_ai.usage.total_tokens"] != int64(19) {
		t.Fatalf("gen_ai.usage.total_tokens = %v, want 19", attrs["gen_ai.usage.total_tokens"])
	}
}
