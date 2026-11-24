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
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
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

	pol, polErr := network.NewPolicy(config.OutboundSSRFConfig{AllowPrivateNetworks: true, AllowInsecureHTTP: true})
	if polErr != nil {
		t.Fatalf("network.NewPolicy: %v", polErr)
	}
	oaiAdp := openai.NewAdapter(upstream.Client())
	oaiAdp.SetSSRFPolicy(pol)
	reg := adapter.NewRegistry()
	reg.Register(oaiAdp)
	ir := router.NewIntelligentRouter(repo, config.RouterConfig{})
	lb := router.NewLoadBalancer()
	rm := router.NewReliabilityManager(repo, reg, ir, lb, vault, rbac, nil, config.RouterConfig{})
	rm.SetCostCalculator(func(_ *domain.GlobalModel, usage *domain.TokenUsage) int64 {
		if usage == nil {
			return 0
		}
		return int64(usage.PromptTokens*2 + usage.CompletionTokens*5)
	})

	sr := tracetest.NewSpanRecorder()
	tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(sr))
	defer func() { _ = tp.Shutdown(ctx) }()

	parentTracer := tp.Tracer("test-server")
	temp := 0.25
	topP := 0.9
	maxTok := 128
	var resp *domain.CanonicalChatResponse
	var err error
	handler := observability.TraceMiddlewareWithTracer(parentTracer)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp, _, err = rm.ExecuteChat(r.Context(), &domain.IdentityContext{OrgID: org.ID}, &domain.CanonicalChatRequest{
			Model:       "fast",
			Temperature: &temp,
			TopP:        &topP,
			MaxTokens:   &maxTok,
			Messages: []domain.CanonicalMessage{
				{Role: "user", Content: "top-secret-prompt-text email alice@example.com key sk-live-secret-token-999999"},
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
		case "chat gpt-4.1-mini":
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
		t.Fatalf("expected chat client span parent %s, got %s", serverSpan.SpanContext().SpanID(), clientSpan.Parent().SpanID())
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
	if attrs["gen_ai.operation.name"] != "chat" {
		t.Fatalf("gen_ai.operation.name = %v, want chat", attrs["gen_ai.operation.name"])
	}
	if attrs["gen_ai.provider.name"] != "openai" {
		t.Fatalf("gen_ai.provider.name = %v, want openai", attrs["gen_ai.provider.name"])
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
	if attrs["gen_ai.request.temperature"] != 0.25 || attrs["gen_ai.request.top_p"] != 0.9 || attrs["gen_ai.request.max_tokens"] != int64(128) {
		t.Fatalf("missing request params on span: %+v", attrs)
	}
	if attrs["gen_ai.response.id"] != "chatcmpl-1" || attrs["goroute.cost_micros"] != int64(59) {
		t.Fatalf("missing response id / cost_micros on span: %+v", attrs)
	}
	if _, exists := attrs["gen_ai.input.messages"]; exists {
		t.Fatalf("gen_ai.input.messages must not be set when captureContent=false")
	}

	// Verify opt-in capture_content=true exports scrubbed input/output messages (redacting secrets & emails).
	rm.SetCaptureContent(true)
	req2 := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)

	var optInSpan sdktrace.ReadOnlySpan
	for _, sp := range sr.Ended()[len(ended):] {
		if sp.Name() == "chat gpt-4.1-mini" {
			optInSpan = sp
		}
	}
	if optInSpan == nil {
		t.Fatalf("expected opt-in chat client span")
	}
	optAttrs := make(map[string]any)
	for _, a := range optInSpan.Attributes() {
		optAttrs[string(a.Key)] = a.Value.AsInterface()
	}
	inMsg, _ := optAttrs["gen_ai.input.messages"].(string)
	outMsg, _ := optAttrs["gen_ai.output.messages"].(string)
	if !strings.Contains(inMsg, "top-secret-prompt-text") || !strings.Contains(outMsg, "secret-response") {
		t.Fatalf("expected captured input/output messages when captureContent=true, got in=%q out=%q", inMsg, outMsg)
	}
	if strings.Contains(inMsg, "alice@example.com") || strings.Contains(inMsg, "sk-live-secret-token-999999") {
		t.Fatalf("PII or API secret leaked into captured gen_ai.input.messages: %q", inMsg)
	}
}
