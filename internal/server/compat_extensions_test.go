package server

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/adapter"
	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/finops"
	"github.com/goroute-ai/ai-gateway-go/internal/guardrails"
	"github.com/goroute-ai/ai-gateway-go/internal/ratelimit"
	"github.com/goroute-ai/ai-gateway-go/internal/router"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

func TestAcquireModalityBudget_DeterministicAndFailClosed(t *testing.T) {
	repo := storage.NewMemoryRepository()
	ctx := context.Background()

	// Verified rerank/image/TTS model
	_ = repo.UpsertGlobalModel(ctx, &domain.GlobalModel{
		ID:                            "cohere/rerank-v3.5",
		Provider:                      domain.ProviderCohere,
		ModelName:                     "rerank-v3.5",
		PricingStatus:                 domain.PricingStatusVerified,
		RerankCostMicrosPerSearchUnit: 2000,
		ImageCostMicrosBase:           40000,
		AudioTTSCostMicrosPer1KChars:  15000,
	})
	// Unverified model
	_ = repo.UpsertGlobalModel(ctx, &domain.GlobalModel{
		ID:                            "openrouter/unverified-rerank",
		Provider:                      domain.ProviderOpenRouter,
		ModelName:                     "unverified-rerank",
		PricingStatus:                 domain.PricingStatusUnknown,
		RerankCostMicrosPerSearchUnit: 2000,
	})

	s := &GatewayServer{
		repo:    repo,
		limiter: ratelimit.NewLimiter(nil, 60, 60),
	}
	id := &domain.IdentityContext{
		OrgID:              "org-1",
		VirtualKeyID:       "vk-1",
		KeyMaxBudgetMicros: 1_000_000,
	}

	gm, sawUnverified, err := s.resolveMatchedVerifiedModel(ctx, "org-1", "cohere/rerank-v3.5")
	if err != nil || gm == nil || sawUnverified {
		t.Fatalf("expected verified model match, got gm=%v sawUnverified=%v err=%v", gm, sawUnverified, err)
	}
	bound, ok := finops.EstimateRerankCostUpperBound(gm, 3)
	if !ok || bound != 6000 {
		t.Fatalf("expected rerank bound=6000, got bound=%d ok=%v", bound, ok)
	}

	_, err = s.acquireModalityBudget(ctx, id, "openrouter/unverified-rerank", 10, "req-2", func(gm *domain.GlobalModel) (int64, bool) {
		return finops.EstimateRerankCostUpperBound(gm, 3)
	})
	if err == nil {
		t.Fatal("expected unverified model to fail closed for budgeted caller")
	}
	if gwErr, ok := err.(*domain.GatewayError); !ok || gwErr.Code != "pricing_unknown_budget_restricted" {
		t.Fatalf("expected pricing_unknown_budget_restricted, got %v", err)
	}
}

func TestResolveMatchedVerifiedModel_UsesProviderSpecificImageVariantRates(t *testing.T) {
	repo := storage.NewMemoryRepository()
	ctx := context.Background()
	for _, gm := range []*domain.GlobalModel{
		{
			ID: "fal/openai/gpt-image-2", Provider: domain.ProviderFal, ModelName: "openai/gpt-image-2",
			PricingStatus: domain.PricingStatusVerified, ImageCostMicrosBase: 145000,
			ModalityPricingJSON: map[string]any{"high_3840x2160": int64(401000)},
		},
		{
			ID: "openrouter/openai/gpt-image-2", Provider: domain.ProviderOpenRouter, ModelName: "openai/gpt-image-2",
			PricingStatus: domain.PricingStatusVerified, ImageCostMicrosBase: 500000,
			ModalityPricingJSON: map[string]any{"high_3840x2160": int64(800000)},
		},
	} {
		if err := repo.UpsertGlobalModel(ctx, gm); err != nil {
			t.Fatalf("UpsertGlobalModel(%s): %v", gm.ID, err)
		}
	}

	s := &GatewayServer{repo: repo}
	gm, sawUnverified, err := s.resolveMatchedVerifiedModel(ctx, "org-1", "fal/openai/gpt-image-2")
	if err != nil || gm == nil || sawUnverified {
		t.Fatalf("resolve matched model: gm=%v sawUnverified=%v err=%v", gm, sawUnverified, err)
	}
	if got := gm.ModalityPricingJSON["high_3840x2160"]; got != int64(401000) {
		t.Fatalf("variant rate = %#v, want 401000 micros from fal model", got)
	}
	bound, ok := finops.EstimateImageCostUpperBound(gm, "high", "3840x2160", 1)
	if !ok || bound != 401000 {
		t.Fatalf("image budget bound = (%d, %v), want (401000, true)", bound, ok)
	}
}

func TestParseAnthropicMessage_PreservesDocumentAndCacheControl(t *testing.T) {
	msg := anthropicMsg{
		Role: "user",
		Content: []any{
			map[string]any{
				"type": "document",
				"source": map[string]any{
					"type":       "base64",
					"media_type": "application/pdf",
					"data":       "JVBERi0=",
				},
				"cache_control": map[string]any{"type": "ephemeral", "ttl": "5m"},
			},
		},
	}
	out := parseAnthropicMessage(msg)
	if len(out) != 1 || len(out[0].Parts) != 1 {
		t.Fatalf("expected 1 message with 1 document part, got %#v", out)
	}
	part := out[0].Parts[0]
	if part.Type != "document" || part.Document == nil || part.Document.MimeType != "application/pdf" {
		t.Fatalf("expected document part, got %#v", part)
	}
	if part.CacheControl == nil || part.CacheControl.Type != "ephemeral" || part.CacheControl.TTL != "5m" {
		t.Fatalf("expected cache_control preserved, got %#v", part.CacheControl)
	}
}

func TestParseResponsesInputMessages_PreservesMultimodalParts(t *testing.T) {
	raw := json.RawMessage(`[
		{
			"role": "user",
			"content": [
				{"type": "input_text", "text": "Inspect this"},
				{"type": "input_image", "image_url": "https://example.com/a.png", "detail": "high"},
				{"type": "input_file", "file_data": "JVBERi0=", "mime_type": "application/pdf", "filename": "doc.pdf"}
			]
		}
	]`)
	msgs := parseResponsesInputMessages("Be concise", raw)
	if len(msgs) != 2 {
		t.Fatalf("expected system + user messages, got %d", len(msgs))
	}
	if msgs[0].Role != "system" || msgs[0].Content != "Be concise" {
		t.Fatalf("unexpected system message: %#v", msgs[0])
	}
	userMsg := msgs[1]
	if userMsg.Content != "Inspect this" || len(userMsg.Parts) != 3 {
		t.Fatalf("expected 3 content parts, got content=%q parts=%#v", userMsg.Content, userMsg.Parts)
	}
	if userMsg.Parts[1].Type != "image_url" || userMsg.Parts[1].ImageURL == nil || userMsg.Parts[1].ImageURL.URL != "https://example.com/a.png" {
		t.Fatalf("expected image_url part preserved, got %#v", userMsg.Parts[1])
	}
	if userMsg.Parts[2].Type != "document" || userMsg.Parts[2].Document == nil || userMsg.Parts[2].Document.MimeType != "application/pdf" {
		t.Fatalf("expected document part preserved, got %#v", userMsg.Parts[2])
	}
}

func TestParseResponsesInputMessages_PreservesFunctionCallRoundTrip(t *testing.T) {
	raw := json.RawMessage(`[
		{"type":"function_call","call_id":"call_123","name":"lookup","arguments":"{\"q\":\"go\"}"},
		{"type":"function_call_output","call_id":"call_123","output":"found 3 results"},
		{"role":"assistant","tool_calls":[{"id":"call_456","type":"function","function":{"name":"lookup","arguments":"{\"q\":\"rust\"}"}}],"content":null}
	]`)
	msgs := parseResponsesInputMessages("", raw)
	if len(msgs) != 3 {
		t.Fatalf("messages count = %d, want 3: %#v", len(msgs), msgs)
	}
	call := msgs[0]
	if call.Role != "assistant" || len(call.ToolCalls) != 1 {
		t.Fatalf("function_call was not translated to an assistant tool call: %#v", call)
	}
	if tc := call.ToolCalls[0]; tc.ID != "call_123" || tc.Function.Name != "lookup" || tc.Function.Arguments != `{"q":"go"}` {
		t.Fatalf("unexpected function_call translation: %#v", tc)
	}
	output := msgs[1]
	if output.Role != "tool" || output.ToolCallID != "call_123" || output.Content != "found 3 results" {
		t.Fatalf("unexpected function_call_output translation: %#v", output)
	}
	chatStyleCall := msgs[2]
	if chatStyleCall.Role != "assistant" || len(chatStyleCall.ToolCalls) != 1 || chatStyleCall.ToolCalls[0].Function.Arguments != `{"q":"rust"}` {
		t.Fatalf("chat-style tool_calls were not preserved: %#v", chatStyleCall)
	}
}

type toolOnlyStreamAdapter struct {
	emitTextAfterTool bool
}

func (a *toolOnlyStreamAdapter) Provider() domain.ProviderType { return domain.ProviderOpenAI }
func (a *toolOnlyStreamAdapter) ChatCompletion(context.Context, *domain.Deployment, *domain.CanonicalChatRequest) (*domain.CanonicalChatResponse, error) {
	return &domain.CanonicalChatResponse{}, nil
}
func (a *toolOnlyStreamAdapter) StreamChatCompletion(_ context.Context, _ *domain.Deployment, _ *domain.CanonicalChatRequest, onChunk adapter.StreamChunkHandler) (*domain.TokenUsage, error) {
	idx := 0
	var finishPtr *string
	if !a.emitTextAfterTool {
		finish := "tool_calls"
		finishPtr = &finish
	}
	_ = onChunk(&domain.CanonicalStreamChunk{
		ID:     "chunk-1",
		Object: "chat.completion.chunk",
		Model:  "gpt-4o-mini",
		Choices: []domain.CanonicalStreamChoice{{
			Index: 0,
			Delta: domain.CanonicalStreamDelta{
				ToolCalls: []domain.CanonicalToolCall{{
					Index: &idx,
					ID:    "call_123",
					Type:  "function",
					Function: domain.CanonicalFunctionCall{
						Name:      "get_weather",
						Arguments: `{"city":"Tokyo"}`,
					},
				}},
			},
			FinishReason: finishPtr,
		}},
	})
	if a.emitTextAfterTool {
		finish := "stop"
		_ = onChunk(&domain.CanonicalStreamChunk{
			ID:     "chunk-2",
			Object: "chat.completion.chunk",
			Model:  "gpt-4o-mini",
			Choices: []domain.CanonicalStreamChoice{{
				Index:        0,
				Delta:        domain.CanonicalStreamDelta{Content: "Here is the result."},
				FinishReason: &finish,
			}},
		})
	}
	return &domain.TokenUsage{PromptTokens: 10, CompletionTokens: 5, TotalTokens: 15}, nil
}
func (a *toolOnlyStreamAdapter) Embeddings(context.Context, *domain.Deployment, *domain.CanonicalEmbeddingRequest) (*domain.CanonicalEmbeddingResponse, error) {
	return &domain.CanonicalEmbeddingResponse{}, nil
}
func (a *toolOnlyStreamAdapter) ListModels(context.Context, *domain.ProviderCredential) ([]domain.DiscoveredModel, error) {
	return nil, nil
}

func TestHandleResponses_ToolOnlyStreamOmitsEmptyMessageItem(t *testing.T) {
	out := executeResponsesStream(t, &toolOnlyStreamAdapter{})
	if !strings.Contains(out, `"type":"function_call"`) {
		t.Fatalf("expected function_call output item in stream, got:\n%s", out)
	}
	if strings.Contains(out, `"type":"message"`) || strings.Contains(out, `response.output_text.done`) {
		t.Fatalf("expected NO empty message or output_text.done in tool-only stream, got:\n%s", out)
	}
}

func TestHandleResponses_StreamOutputMatchesOutputIndexes(t *testing.T) {
	out := executeResponsesStream(t, &toolOnlyStreamAdapter{emitTextAfterTool: true})
	completed := strings.LastIndex(out, "event: response.completed\n")
	if completed < 0 {
		t.Fatalf("missing response.completed event:\n%s", out)
	}
	var event struct {
		Response struct {
			Output []struct {
				Type string `json:"type"`
			} `json:"output"`
		} `json:"response"`
	}
	dataStart := strings.Index(out[completed:], "data: ")
	if dataStart < 0 {
		t.Fatalf("response.completed event has no data:\n%s", out[completed:])
	}
	dataStart += completed + len("data: ")
	dataEnd := strings.Index(out[dataStart:], "\n\n")
	if dataEnd < 0 {
		t.Fatalf("response.completed event has no terminator:\n%s", out[dataStart:])
	}
	if err := json.Unmarshal([]byte(out[dataStart:dataStart+dataEnd]), &event); err != nil {
		t.Fatalf("decode response.completed: %v", err)
	}
	if len(event.Response.Output) != 2 || event.Response.Output[0].Type != "function_call" || event.Response.Output[1].Type != "message" {
		t.Fatalf("completed output order = %#v, want function_call at index 0 then message at index 1", event.Response.Output)
	}
}

func executeResponsesStream(t *testing.T, streamAdapter adapter.ProviderAdapter) string {
	t.Helper()
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	vault, err := auth.NewVault("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("vault: %v", err)
	}
	rbac := auth.NewRBACEngine(repo)

	org := &domain.Organization{Name: "RespOrg", Slug: "resp-org", IsActive: true}
	_ = repo.CreateOrganization(ctx, org)
	cred := &domain.ProviderCredential{
		OrgID: org.ID, Provider: domain.ProviderOpenAI, Name: "c1", BaseURL: "https://api.example.com", IsActive: true,
	}
	_ = vault.EncryptCredential(cred, "sk-test")
	_ = repo.CreateProviderCredential(ctx, cred)
	gm := &domain.GlobalModel{
		ID: "openai/gpt-4o-mini", Provider: domain.ProviderOpenAI, ModelName: "gpt-4o-mini",
		SupportsInference: true, LifecycleStatus: domain.ModelStatusActive, PricingStatus: domain.PricingStatusVerified,
	}
	_ = repo.UpsertGlobalModel(ctx, gm)
	group := &domain.ModelGroup{OrgID: org.ID, Alias: "gpt-4o-mini", RoutingStrategy: domain.StrategyWeightedShuffle, IsActive: true}
	_ = repo.CreateModelGroup(ctx, group)
	_ = repo.CreateDeployment(ctx, &domain.Deployment{
		ModelGroupID: group.ID, GlobalModelID: gm.ID, CredentialID: cred.ID, DeploymentName: "d1", Weight: 1, Status: domain.DeploymentStatusActive,
	})

	reg := adapter.NewRegistry()
	reg.Register(streamAdapter)
	rCfg := config.Default().Router
	rCfg.BaseRetryDelay = time.Millisecond
	rCfg.MaxRetryDelay = 5 * time.Millisecond
	rm := router.NewReliabilityManager(repo, reg, router.NewIntelligentRouter(repo, rCfg), router.NewLoadBalancer(), vault, rbac, nil, rCfg)

	s := &GatewayServer{
		repo:        repo,
		reliability: rm,
		limiter:     ratelimit.NewLimiter(nil, 60, 60),
		guardrails:  guardrails.NewEngine(repo),
	}

	body := []byte(`{"model":"gpt-4o-mini","input":"weather in Tokyo","stream":true}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/responses", bytes.NewReader(body))
	req = req.WithContext(auth.WithIdentity(req.Context(), &domain.IdentityContext{OrgID: org.ID, VirtualKeyID: "vk-1"}))
	rec := httptest.NewRecorder()
	s.handleResponses(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	return rec.Body.String()
}

func TestAudioTTS_RuneCountMatchesReservationAndSettlement(t *testing.T) {
	gm := &domain.GlobalModel{
		PricingStatus:                domain.PricingStatusVerified,
		AudioTTSCostMicrosPer1KChars: 15000, // 15 micros per rune
	}
	input := "こんにちは" // 5 runes, 15 UTF-8 bytes
	runes := len([]rune(input))
	if runes != 5 || len(input) != 15 {
		t.Fatalf("expected 5 runes and 15 bytes, got runes=%d bytes=%d", runes, len(input))
	}
	bound, ok := finops.EstimateAudioTTSCostUpperBound(gm, runes)
	if !ok {
		t.Fatal("expected TTS upper bound ok")
	}
	settled := finops.CalculateAudioTTSCostMicros(gm, runes)
	if bound != settled || settled != 75 {
		t.Fatalf("expected reservation bound (%d) == settlement (%d) == 75 micros", bound, settled)
	}
}
