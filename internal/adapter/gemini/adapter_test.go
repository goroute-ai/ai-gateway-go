package gemini

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/adapter"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/openapi/providers"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
)

func testLoopbackPolicy(t *testing.T) *network.Policy {
	t.Helper()
	pol, err := network.NewPolicy(config.OutboundSSRFConfig{
		AllowPrivateNetworks: true,
		AllowInsecureHTTP:    true,
	})
	if err != nil {
		t.Fatalf("network.NewPolicy: %v", err)
	}
	return pol
}

func TestGeminiAdapter_ChatThinkingToolsJSONStreamEmbeddingsAndModels(t *testing.T) {
	ctx := context.Background()
	var lastChatBody map[string]any
	var lastHeaders http.Header
	var sawQueryKey bool

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lastHeaders = r.Header.Clone()
		if r.URL.Query().Get("key") != "" {
			sawQueryKey = true
		}
		if r.Header.Get("x-goog-api-key") != "test-gemini-key" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":{"code":401,"message":"invalid key","status":"UNAUTHENTICATED"}}`))
			return
		}

		switch r.URL.Path {
		case "/v1beta/models/gemini-2.5-flash:generateContent":
			raw, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(raw, &lastChatBody)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{
				"responseId":"resp-gem-1",
				"modelVersion":"gemini-2.5-flash",
				"candidates":[{
					"index":0,
					"content":{"role":"model","parts":[
						{"thought":true,"text":"checking weather"},
						{"text":"{\"ok\":true}"},
						{"functionCall":{"id":"fc_1","name":"get_weather","args":{"city":"NYC"}}}
					]},
					"finishReason":"STOP"
				}],
				"usageMetadata":{
					"promptTokenCount":12,
					"cachedContentTokenCount":4,
					"candidatesTokenCount":6,
					"thoughtsTokenCount":14,
					"totalTokenCount":32
				}
			}`))

		case "/v1beta/models/gemini-2.5-flash:streamGenerateContent":
			if r.URL.Query().Get("alt") != "sse" {
				t.Errorf("expected alt=sse query param, got %q", r.URL.RawQuery)
			}
			w.Header().Set("Content-Type", "text/event-stream")
			_, _ = fmt.Fprint(w, "data: {\"responseId\":\"resp-s1\",\"modelVersion\":\"gemini-2.5-flash\",\"candidates\":[{\"index\":0,\"content\":{\"role\":\"model\",\"parts\":[{\"thought\":true,\"text\":\"step 1\"}]}}],\"usageMetadata\":{\"promptTokenCount\":10,\"thoughtsTokenCount\":5,\"totalTokenCount\":15}}\n\n")
			_, _ = fmt.Fprint(w, "data: {\"responseId\":\"resp-s1\",\"modelVersion\":\"gemini-2.5-flash\",\"candidates\":[{\"index\":0,\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"Hello \"}]}}]}\n\n")
			_, _ = fmt.Fprint(w, "data: {\"responseId\":\"resp-s1\",\"modelVersion\":\"gemini-2.5-flash\",\"candidates\":[{\"index\":0,\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"Gemini\"}]},\"finishReason\":\"STOP\"}],\"usageMetadata\":{\"promptTokenCount\":10,\"candidatesTokenCount\":3,\"thoughtsTokenCount\":5,\"totalTokenCount\":18}}\n\n")

		case "/v1beta/models/gemini-embedding-001:embedContent":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"embedding":{"values":[0.1,0.2,0.3,0.4]}}`))

		case "/v1beta/models/gemini-embedding-001:batchEmbedContents":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"embeddings":[{"values":[0.1,0.2]},{"values":[0.3,0.4]}]}`))

		case "/v1beta/models":
			w.Header().Set("Content-Type", "application/json")
			if r.URL.Query().Get("pageToken") == "page2" {
				_, _ = w.Write([]byte(`{"models":[{"name":"models/gemini-embedding-001","displayName":"Gemini Embedding 001","supportedGenerationMethods":["embedContent"]},{"name":"models/bidi-only","displayName":"Bidi Only","supportedGenerationMethods":["bidiGenerateContent"]}]}`))
				return
			}
			_, _ = w.Write([]byte(`{"models":[{"name":"models/gemini-2.5-flash","displayName":"Gemini 2.5 Flash","supportedGenerationMethods":["generateContent","countTokens"]}],"nextPageToken":"page2"}`))

		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	adp := NewAdapter(srv.Client())
	adp.SetSSRFPolicy(testLoopbackPolicy(t))

	if adp.Provider() != domain.ProviderGemini {
		t.Fatalf("unexpected provider: %s", adp.Provider())
	}
	if !adp.SupportsOperation(domain.OperationChat) || !adp.SupportsOperation(domain.OperationEmbedding) || adp.SupportsOperation(domain.OperationAudioSTT) {
		t.Fatal("unexpected SupportsOperation matrix")
	}
	if !adp.SupportsAssistantPrefill() {
		t.Fatal("expected SupportsAssistantPrefill() == true")
	}

	cred := &domain.ProviderCredential{
		Provider:        domain.ProviderGemini,
		BaseURL:         srv.URL,
		DecryptedAPIKey: "test-gemini-key",
		Headers:         map[string]string{"X-Custom-Header": "custom-val"},
	}
	chatDep := &domain.Deployment{
		Credential:  cred,
		GlobalModel: &domain.GlobalModel{ModelName: "gemini-2.5-flash"},
	}

	// 1. Sync chat with systemInstruction, image data URI, tool call + tool response, JSON schema, thinking, and ExtraParams
	temp := 0.2
	maxTok := 256
	chatResp, err := adp.ChatCompletion(ctx, chatDep, &domain.CanonicalChatRequest{
		Model:           "gemini-2.5-flash",
		Temperature:     &temp,
		MaxTokens:       &maxTok,
		Stop:            []string{"END"},
		ReasoningEffort: "medium",
		ResponseFormat: &domain.ResponseFormat{
			Type: "json_schema",
			JSONSchema: map[string]any{
				"name":   "status",
				"schema": map[string]any{"type": "object", "properties": map[string]any{"ok": map[string]any{"type": "boolean"}}},
			},
		},
		Tools: []domain.CanonicalTool{
			{
				Type: "function",
				Function: domain.CanonicalFunction{
					Name:        "get_weather",
					Description: "Get weather",
					Parameters:  map[string]any{"type": "object", "properties": map[string]any{"city": map[string]any{"type": "string"}}},
				},
			},
		},
		ToolChoice: "auto",
		ExtraParams: map[string]any{
			"top_k":           40,
			"seed":            7,
			"thinking_budget": 1024,
			"contents":        "must-not-overwrite",
		},
		Messages: []domain.CanonicalMessage{
			{Role: "system", Content: "Be concise."},
			{
				Role: "user",
				Parts: []domain.ContentPart{
					{Type: "text", Text: "What is the weather?"},
					{Type: "image_url", ImageURL: &domain.ImageURL{URL: "data:image/png;base64,iVBORw0KGgo="}},
				},
			},
			{
				Role: "assistant",
				ToolCalls: []domain.CanonicalToolCall{
					{ID: "call_1", Type: "function", Function: domain.CanonicalFunctionCall{Name: "get_weather", Arguments: `{"city":"NYC"}`}},
				},
			},
			{Role: "tool", ToolCallID: "call_1", Content: "72F sunny"},
		},
	})
	if err != nil {
		t.Fatalf("ChatCompletion failed: %v", err)
	}
	if sawQueryKey {
		t.Fatal("API key must never be sent in query parameters")
	}
	if lastHeaders.Get("X-Custom-Header") != "custom-val" {
		t.Fatalf("expected custom header preserved, got %q", lastHeaders.Get("X-Custom-Header"))
	}
	if chatResp.ID != "resp-gem-1" || chatResp.Provider != domain.ProviderGemini || len(chatResp.Choices) != 1 {
		t.Fatalf("unexpected chat response: %+v", chatResp)
	}
	choice := chatResp.Choices[0]
	if choice.Message.Content != `{"ok":true}` || choice.Message.ReasoningContent != "checking weather" {
		t.Fatalf("unexpected message content/reasoning: %+v", choice.Message)
	}
	if len(choice.Message.ToolCalls) != 1 || choice.Message.ToolCalls[0].Function.Name != "get_weather" || choice.FinishReason != "tool_calls" {
		t.Fatalf("unexpected tool calls / finish reason: %+v", choice)
	}
	// Verify critical FinOps billing invariant: CompletionTokens = candidates (6) + thoughts (14) = 20
	if chatResp.Usage.PromptTokens != 12 || chatResp.Usage.CachedPromptTokens != 4 ||
		chatResp.Usage.ReasoningTokens != 14 || chatResp.Usage.CompletionTokens != 20 || chatResp.Usage.TotalTokens != 32 {
		t.Fatalf("unexpected usage accounting: %+v", chatResp.Usage)
	}
	if _, ok := lastChatBody["systemInstruction"].(map[string]any); !ok {
		t.Fatalf("expected systemInstruction in payload: %#v", lastChatBody)
	}
	contentsSlice, ok := lastChatBody["contents"].([]any)
	if !ok || len(contentsSlice) != 3 {
		t.Fatalf("expected 3 content turns (user, model, user/toolResponse), got %#v", lastChatBody["contents"])
	}
	genCfg := lastChatBody["generationConfig"].(map[string]any)
	if genCfg["responseMimeType"] != "application/json" || genCfg["topK"].(float64) != 40 || genCfg["seed"].(float64) != 7 {
		t.Fatalf("unexpected generationConfig: %#v", genCfg)
	}
	thinkingCfg := genCfg["thinkingConfig"].(map[string]any)
	if thinkingCfg["thinkingBudget"].(float64) != 1024 {
		t.Fatalf("unexpected thinkingConfig for gemini-2.5-flash: %#v", thinkingCfg)
	}
	if _, hasLevel := thinkingCfg["thinkingLevel"]; hasLevel {
		t.Fatalf("gemini-2.5-flash must not emit thinkingLevel: %#v", thinkingCfg)
	}
	// Verify Gemini 3.x models use thinkingLevel instead of thinkingBudget
	gem3Cfg := buildGeminiGenerationConfig("gemini-3-flash-preview", &domain.CanonicalChatRequest{ReasoningEffort: "high"})
	if gem3Cfg == nil || gem3Cfg.ThinkingConfig == nil || gem3Cfg.ThinkingConfig.ThinkingLevel == nil || *gem3Cfg.ThinkingConfig.ThinkingLevel != "HIGH" || gem3Cfg.ThinkingConfig.ThinkingBudget != nil {
		t.Fatalf("expected gemini-3-flash-preview to emit thinkingLevel=HIGH only, got %+v", gem3Cfg)
	}
	gem25Cfg := buildGeminiGenerationConfig("gemini-2.5-flash", &domain.CanonicalChatRequest{ReasoningEffort: "low"})
	if gem25Cfg == nil || gem25Cfg.ThinkingConfig == nil || gem25Cfg.ThinkingConfig.ThinkingBudget == nil || *gem25Cfg.ThinkingConfig.ThinkingBudget != 1024 || gem25Cfg.ThinkingConfig.ThinkingLevel != nil {
		t.Fatalf("expected gemini-2.5-flash to emit thinkingBudget=1024 only, got %+v", gem25Cfg)
	}

	// 2. SSE streaming
	var streamedContent, streamedReasoning string
	var finalFinish string
	streamUsage, err := adp.StreamChatCompletion(ctx, chatDep, &domain.CanonicalChatRequest{
		Model:    "gemini-2.5-flash",
		Stream:   true,
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "Hi"}},
	}, func(chunk *domain.CanonicalStreamChunk) error {
		if len(chunk.Choices) > 0 {
			streamedContent += chunk.Choices[0].Delta.Content
			streamedReasoning += chunk.Choices[0].Delta.ReasoningContent
			if chunk.Choices[0].FinishReason != nil {
				finalFinish = *chunk.Choices[0].FinishReason
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("StreamChatCompletion failed: %v", err)
	}
	if streamedContent != "Hello Gemini" || streamedReasoning != "step 1" || finalFinish != "stop" {
		t.Fatalf("unexpected stream output: content=%q reasoning=%q finish=%q", streamedContent, streamedReasoning, finalFinish)
	}
	if streamUsage.PromptTokens != 10 || streamUsage.ReasoningTokens != 5 || streamUsage.CompletionTokens != 8 || streamUsage.TotalTokens != 18 {
		t.Fatalf("unexpected stream usage: %+v", streamUsage)
	}

	// 3. Single & batch embeddings
	embDep := &domain.Deployment{
		Credential:  cred,
		GlobalModel: &domain.GlobalModel{ModelName: "gemini-embedding-001"},
	}
	dims := 4
	singleEmb, err := adp.Embeddings(ctx, embDep, &domain.CanonicalEmbeddingRequest{
		Model:      "gemini-embedding-001",
		Input:      []string{"hello"},
		Dimensions: &dims,
	})
	if err != nil || len(singleEmb.Data) != 1 || len(singleEmb.Data[0].Embedding) != 4 {
		t.Fatalf("single Embeddings failed: err=%v resp=%+v", err, singleEmb)
	}
	batchEmb, err := adp.Embeddings(ctx, embDep, &domain.CanonicalEmbeddingRequest{
		Model: "gemini-embedding-001",
		Input: []string{"alpha", "beta"},
	})
	if err != nil || len(batchEmb.Data) != 2 || len(batchEmb.Data[1].Embedding) != 2 {
		t.Fatalf("batch Embeddings failed: err=%v resp=%+v", err, batchEmb)
	}

	// 4. Paginated ListModels (filtering out bidi-only models & stripping models/ prefix)
	models, err := adp.ListModels(ctx, cred)
	if err != nil {
		t.Fatalf("ListModels failed: %v", err)
	}
	if len(models) != 2 || models[0].ModelName != "gemini-2.5-flash" || models[1].ModelName != "gemini-embedding-001" {
		t.Fatalf("unexpected ListModels output: %+v", models)
	}
}

func TestGeminiAdapter_SecurityAndErrorHandling(t *testing.T) {
	ctx := context.Background()

	// 1. SSRF fail-closed without loopback policy
	strictPol, err := network.NewPolicy(config.OutboundSSRFConfig{})
	if err != nil {
		t.Fatalf("network.NewPolicy: %v", err)
	}
	adp := NewAdapter(nil)
	adp.SetSSRFPolicy(strictPol)

	_, err = adp.ChatCompletion(ctx, &domain.Deployment{
		Credential:  &domain.ProviderCredential{BaseURL: "http://127.0.0.1:8080", DecryptedAPIKey: "k"},
		GlobalModel: &domain.GlobalModel{ModelName: "gemini-2.5-flash"},
	}, &domain.CanonicalChatRequest{
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "hi"}},
	})
	var gwErr *domain.GatewayError
	if !errors.As(err, &gwErr) || gwErr.Code != "invalid_base_url" {
		t.Fatalf("expected invalid_base_url SSRF block, got %v", err)
	}

	// 2. Missing API key fails closed with 401 AuthFailure
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "7")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":{"code":429,"message":"quota exceeded","status":"RESOURCE_EXHAUSTED"}}`))
	}))
	defer srv.Close()

	adp = NewAdapter(srv.Client())
	adp.SetSSRFPolicy(testLoopbackPolicy(t))

	_, err = adp.ChatCompletion(ctx, &domain.Deployment{
		Credential:  &domain.ProviderCredential{BaseURL: srv.URL},
		GlobalModel: &domain.GlobalModel{ModelName: "gemini-2.5-flash"},
	}, &domain.CanonicalChatRequest{
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "hi"}},
	})
	if !errors.As(err, &gwErr) || gwErr.StatusCode != http.StatusUnauthorized || !gwErr.AuthFailure {
		t.Fatalf("expected 401 AuthFailure for missing key, got %v", err)
	}

	// 3. 429 upstream error classification with Retry-After
	_, err = adp.ChatCompletion(ctx, &domain.Deployment{
		Credential:  &domain.ProviderCredential{BaseURL: srv.URL, DecryptedAPIKey: "k"},
		GlobalModel: &domain.GlobalModel{ModelName: "gemini-2.5-flash"},
	}, &domain.CanonicalChatRequest{
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "hi"}},
	})
	if !errors.As(err, &gwErr) || gwErr.StatusCode != http.StatusTooManyRequests || !gwErr.Retryable || gwErr.RetryAfterSec != 7 || !strings.Contains(gwErr.Message, "quota exceeded") {
		t.Fatalf("unexpected 429 error classification: %+v", gwErr)
	}

	// 4. Model path injection rejection
	_, err = adp.ChatCompletion(ctx, &domain.Deployment{
		Credential:  &domain.ProviderCredential{BaseURL: srv.URL, DecryptedAPIKey: "k"},
		GlobalModel: &domain.GlobalModel{ModelName: "../../etc/passwd"},
	}, &domain.CanonicalChatRequest{
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "hi"}},
	})
	if !errors.As(err, &gwErr) || gwErr.Code != "invalid_model" {
		t.Fatalf("expected invalid_model for path traversal model ID, got %v", err)
	}

	// 5. Private remote media URL rejected by strict media SSRF policy
	_, err = adp.ChatCompletion(ctx, &domain.Deployment{
		Credential:  &domain.ProviderCredential{BaseURL: srv.URL, DecryptedAPIKey: "k"},
		GlobalModel: &domain.GlobalModel{ModelName: "gemini-2.5-flash"},
	}, &domain.CanonicalChatRequest{
		Messages: []domain.CanonicalMessage{{
			Role: "user",
			Parts: []domain.ContentPart{
				{Type: "image_url", ImageURL: &domain.ImageURL{URL: "http://169.254.169.254/latest/meta-data/"}},
			},
		}},
	})
	if !errors.As(err, &gwErr) || gwErr.Code != "invalid_media_url" {
		t.Fatalf("expected invalid_media_url for private media SSRF attempt, got %v", err)
	}

	// Ensure adapter implements expected interfaces
	var _ adapter.ProviderAdapter = adp
	var _ adapter.OperationSupportChecker = adp
	var _ adapter.PrefillSupportChecker = adp
}

func TestGeminiAdapter_SecurityRemediationSuite(t *testing.T) {
	ctx := context.Background()

	// SEC-10: Reject colon (AIP-136 custom method injection) and overly long / malformed model IDs
	badModels := []string{
		"gemini-2.5-flash:countTokens",
		"gemini/gemini-2.5-flash:batchGenerateContent",
		"-leading-dash",
		strings.Repeat("a", maxGeminiModelIDLen+1),
		"gemini 2.5 flash",
	}
	for _, m := range badModels {
		if _, err := normalizeGeminiModel(m); err == nil {
			t.Fatalf("SEC-10: expected normalizeGeminiModel(%q) to fail", m)
		}
	}
	if got, err := normalizeGeminiModel("gemini/gemini-2.5-flash-preview.05_20"); err != nil || got != "gemini-2.5-flash-preview.05_20" {
		t.Fatalf("SEC-10: valid model rejected: got=%q err=%v", got, err)
	}

	// SEC-06: cached_content and safety_settings are blocked by default; opt-in validates cached_content format
	adp := NewAdapter(nil)
	reqWithSensitiveExtra := &domain.CanonicalChatRequest{
		Model:    "gemini-2.5-flash",
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "hello"}},
		ExtraParams: map[string]any{
			"cached_content":  "cachedContents/tenant-b-secret-ctx",
			"safety_settings": []map[string]any{{"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_NONE"}},
			"thinking_budget": -1, // dynamic unlimited thinking must be ignored
			"top_k":           -5, // negative top_k must be ignored
		},
	}
	payload, err := adp.buildGeminiGenerateContentRequest(ctx, "gemini-2.5-flash", reqWithSensitiveExtra)
	if err != nil {
		t.Fatalf("buildGeminiGenerateContentRequest failed: %v", err)
	}
	if payload.CachedContent != nil {
		t.Fatalf("SEC-06: cached_content must be blocked by default, got %q", *payload.CachedContent)
	}
	if payload.SafetySettings != nil {
		t.Fatalf("SEC-06: safety_settings must be blocked by default, got %+v", *payload.SafetySettings)
	}
	if payload.GenerationConfig != nil && payload.GenerationConfig.ThinkingConfig != nil {
		t.Fatalf("SEC-06: negative thinking_budget must not be forwarded, got %+v", payload.GenerationConfig.ThinkingConfig)
	}
	if payload.GenerationConfig != nil && payload.GenerationConfig.TopK != nil {
		t.Fatalf("SEC-11: negative top_k must not be forwarded, got %v", *payload.GenerationConfig.TopK)
	}

	// Opt-in cached_content rejects invalid resource names and accepts valid cachedContents/<id>
	adp.SetAllowCachedContentPassthrough(true)
	adp.SetAllowSafetySettingsOverride(true)
	if _, err := adp.buildGeminiGenerateContentRequest(ctx, "gemini-2.5-flash", &domain.CanonicalChatRequest{
		Model:       "gemini-2.5-flash",
		Messages:    []domain.CanonicalMessage{{Role: "user", Content: "hi"}},
		ExtraParams: map[string]any{"cached_content": "../projects/other/cachedContents/evil"},
	}); err == nil {
		t.Fatal("SEC-06: expected invalid cached_content pattern to be rejected when opted in")
	}
	optedInPayload, err := adp.buildGeminiGenerateContentRequest(ctx, "gemini-2.5-flash", &domain.CanonicalChatRequest{
		Model:    "gemini-2.5-flash",
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "hi"}},
		ExtraParams: map[string]any{
			"cached_content":  "cachedContents/abc_123-xyz",
			"safety_settings": []map[string]any{{"category": "HARM_CATEGORY_HATE_SPEECH", "threshold": "BLOCK_MEDIUM_AND_ABOVE"}},
			"thinking_budget": 999999, // exceeds maxGeminiThinkingBudget
		},
	})
	if err != nil {
		t.Fatalf("SEC-06: valid opted-in request failed: %v", err)
	}
	if optedInPayload.CachedContent == nil || *optedInPayload.CachedContent != "cachedContents/abc_123-xyz" {
		t.Fatalf("SEC-06: expected opted-in cached_content preserved, got %+v", optedInPayload.CachedContent)
	}
	if optedInPayload.SafetySettings == nil || len(*optedInPayload.SafetySettings) != 1 {
		t.Fatalf("SEC-06: expected opted-in safety_settings preserved, got %+v", optedInPayload.SafetySettings)
	}
	if optedInPayload.GenerationConfig != nil && optedInPayload.GenerationConfig.ThinkingConfig != nil {
		t.Fatalf("SEC-06: oversized thinking_budget (>24576) must not be forwarded")
	}

	// SEC-11: int32 overflow safety & negative usage clamping
	if _, ok := asInt32(int64(1 << 40)); ok {
		t.Fatal("SEC-11: expected int64 overflow to be rejected by asInt32")
	}
	if _, ok := asInt32(float64(1.5)); ok {
		t.Fatal("SEC-11: expected non-integer float64 to be rejected by asInt32")
	}
	negPrompt := int32(-10)
	negCand := int32(-5)
	negThoughts := int32(-3)
	negCached := int32(99)
	negTotal := int32(-1)
	clamped := extractGeminiUsage(&providers.GeminiUsageMetadata{
		PromptTokenCount:        &negPrompt,
		CandidatesTokenCount:    &negCand,
		ThoughtsTokenCount:      &negThoughts,
		CachedContentTokenCount: &negCached,
		TotalTokenCount:         &negTotal,
	})
	if clamped.PromptTokens != 0 || clamped.CompletionTokens != 0 || clamped.ReasoningTokens != 0 || clamped.CachedPromptTokens != 0 || clamped.TotalTokens != 0 {
		t.Fatalf("SEC-11: expected all negative usage fields clamped to 0, got %+v", clamped)
	}

	// SEC-04 & SEC-11: Batch embedding >100 items and invalid dimensions rejected
	tooManyInputs := make([]string, maxGeminiBatchEmbedItems+1)
	for i := range tooManyInputs {
		tooManyInputs[i] = "x"
	}
	var gwErr *domain.GatewayError
	_, err = adp.Embeddings(ctx, &domain.Deployment{
		Credential:  &domain.ProviderCredential{DecryptedAPIKey: "k"},
		GlobalModel: &domain.GlobalModel{ModelName: "gemini-embedding-001"},
	}, &domain.CanonicalEmbeddingRequest{Model: "gemini-embedding-001", Input: tooManyInputs})
	if !errors.As(err, &gwErr) || gwErr.Code != "invalid_embedding_batch_size" {
		t.Fatalf("SEC-04: expected invalid_embedding_batch_size, got %v", err)
	}
	badDims := 999999
	_, err = adp.Embeddings(ctx, &domain.Deployment{
		Credential:  &domain.ProviderCredential{DecryptedAPIKey: "k"},
		GlobalModel: &domain.GlobalModel{ModelName: "gemini-embedding-001"},
	}, &domain.CanonicalEmbeddingRequest{Model: "gemini-embedding-001", Input: []string{"ok"}, Dimensions: &badDims})
	if !errors.As(err, &gwErr) || gwErr.Code != "invalid_embedding_dimensions" {
		t.Fatalf("SEC-11: expected invalid_embedding_dimensions, got %v", err)
	}

	// SEC-07: Inline data URI MIME validation & remote media fan-out cap (>8 parts)
	_, err = adp.buildGeminiGenerateContentRequest(ctx, "gemini-2.5-flash", &domain.CanonicalChatRequest{
		Model: "gemini-2.5-flash",
		Messages: []domain.CanonicalMessage{{
			Role: "user",
			Parts: []domain.ContentPart{
				{Type: "image_url", ImageURL: &domain.ImageURL{URL: "data:text/html;base64,PHNjcmlwdD4="}},
			},
		}},
	})
	if !errors.As(err, &gwErr) || gwErr.Code != "invalid_media_url" {
		t.Fatalf("SEC-07: expected disallowed inline data URI MIME to fail, got %v", err)
	}

	mediaSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write([]byte("png-bytes"))
	}))
	defer mediaSrv.Close()
	mediaAdp := NewAdapter(nil)
	mediaAdp.mediaClient = mediaSrv.Client()
	mediaAdp.mediaPolicy = testLoopbackPolicy(t)
	manyParts := make([]domain.ContentPart, maxRemoteMediaPartsPerRequest+1)
	for i := range manyParts {
		manyParts[i] = domain.ContentPart{
			Type:     "image_url",
			ImageURL: &domain.ImageURL{URL: mediaSrv.URL + "/img.png"},
		}
	}
	_, err = mediaAdp.buildGeminiGenerateContentRequest(ctx, "gemini-2.5-flash", &domain.CanonicalChatRequest{
		Model:    "gemini-2.5-flash",
		Messages: []domain.CanonicalMessage{{Role: "user", Parts: manyParts}},
	})
	if !errors.As(err, &gwErr) || gwErr.Code != "invalid_media_url" || !strings.Contains(gwErr.Message, "maximum of") {
		t.Fatalf("SEC-07: expected remote media fan-out cap error, got %v", err)
	}

	// SEC-08: Reserved/hop-by-hop/trace/auth-override headers ignored in applyGeminiHeaders
	httpReq, _ := http.NewRequest(http.MethodPost, "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent", nil)
	err = applyGeminiHeaders(httpReq, &domain.ProviderCredential{
		DecryptedAPIKey: "real-key",
		Headers: map[string]string{
			"Host":              "evil.example.com",
			"Content-Type":      "text/plain",
			"Transfer-Encoding": "chunked",
			"traceparent":       "00-evil-00",
			"x-goog-api-key":    "spoofed-key",
			"X-Good-Header":     "allowed",
			"X-Bad\r\nInjected": "nope",
		},
	})
	if err != nil {
		t.Fatalf("applyGeminiHeaders unexpected error: %v", err)
	}
	if httpReq.Header.Get("Content-Type") != "application/json" ||
		httpReq.Header.Get("x-goog-api-key") != "real-key" ||
		httpReq.Header.Get("Transfer-Encoding") != "" ||
		httpReq.Header.Get("Host") != "" ||
		httpReq.Header.Get("X-Good-Header") != "allowed" {
		t.Fatalf("SEC-08: reserved header guard failed: %+v", httpReq.Header)
	}

	// SEC-12: Transport errors are sanitized (no raw upstream URL/IP reflected) and ListModels wraps in GatewayError
	closedSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	closedURL := closedSrv.URL
	closedSrv.Close()
	netAdp := NewAdapter(closedSrv.Client())
	netAdp.SetSSRFPolicy(testLoopbackPolicy(t))
	_, err = netAdp.ListModels(ctx, &domain.ProviderCredential{BaseURL: closedURL, DecryptedAPIKey: "k"})
	if !errors.As(err, &gwErr) || gwErr.Code != "upstream_network_error" || strings.Contains(gwErr.Message, "127.0.0.1") {
		t.Fatalf("SEC-12: expected sanitized GatewayError from ListModels without IP leak, got %v", err)
	}

	// SEC-13: Repeated consecutive malformed SSE frames abort stream with invalid_upstream_stream
	malformedSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		for i := 0; i < maxMalformedSSEFrames; i++ {
			_, _ = w.Write([]byte("data: {not-valid-json\n\n"))
		}
	}))
	defer malformedSrv.Close()
	sseAdp := NewAdapter(malformedSrv.Client())
	sseAdp.SetSSRFPolicy(testLoopbackPolicy(t))
	_, err = sseAdp.StreamChatCompletion(ctx, &domain.Deployment{
		Credential:  &domain.ProviderCredential{BaseURL: malformedSrv.URL, DecryptedAPIKey: "k"},
		GlobalModel: &domain.GlobalModel{ModelName: "gemini-2.5-flash"},
	}, &domain.CanonicalChatRequest{
		Model:    "gemini-2.5-flash",
		Stream:   true,
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "hi"}},
	}, func(chunk *domain.CanonicalStreamChunk) error { return nil })
	if !errors.As(err, &gwErr) || gwErr.Code != "invalid_upstream_stream" {
		t.Fatalf("SEC-13: expected invalid_upstream_stream on repeated malformed SSE frames, got %v", err)
	}

	// S2-03: Oversized multi-line SSE event wraps sse.ErrEventTooLarge into structured GatewayError
	hugeSSESrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		chunk := strings.Repeat("a", 1024*1024)
		for i := 0; i < 5; i++ {
			_, _ = w.Write([]byte("data: " + chunk + "\n"))
		}
	}))
	defer hugeSSESrv.Close()
	hugeSSEAdp := NewAdapter(hugeSSESrv.Client())
	hugeSSEAdp.SetSSRFPolicy(testLoopbackPolicy(t))
	_, err = hugeSSEAdp.StreamChatCompletion(ctx, &domain.Deployment{
		Credential:  &domain.ProviderCredential{BaseURL: hugeSSESrv.URL, DecryptedAPIKey: "k"},
		GlobalModel: &domain.GlobalModel{ModelName: "gemini-2.5-flash"},
	}, &domain.CanonicalChatRequest{
		Model:    "gemini-2.5-flash",
		Stream:   true,
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "hi"}},
	}, func(chunk *domain.CanonicalStreamChunk) error { return nil })
	if !errors.As(err, &gwErr) || gwErr.Code != "upstream_stream_too_large" {
		t.Fatalf("S2-03: expected upstream_stream_too_large, got %v", err)
	}

	// S2-03: parseGeminiUpstreamError scrubs echoed secrets from upstream error payloads
	secretErrResp := &http.Response{
		StatusCode: http.StatusBadRequest,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(`{"error":{"code":400,"message":"rejected key AIzaSyD_exampleSyntheticKeyValue123456"}}`)),
	}
	parsedErr := parseGeminiUpstreamError(secretErrResp)
	if strings.Contains(parsedErr.Error(), "exampleSyntheticKeyValue123456") || !strings.Contains(parsedErr.Error(), "AIza[REDACTED]") {
		t.Fatalf("S2-03: expected upstream error secret to be scrubbed, got %v", parsedErr)
	}
}
