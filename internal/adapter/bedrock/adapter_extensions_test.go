package bedrock_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/adapter/bedrock"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

func testBedrockDeployment(endpoint string) *domain.Deployment {
	return &domain.Deployment{
		ID: "dep-bedrock-ext",
		GlobalModel: &domain.GlobalModel{
			ID:        "bedrock/anthropic.claude-sonnet-4-5-v1:0",
			Provider:  domain.ProviderBedrock,
			ModelName: "anthropic.claude-sonnet-4-5-v1:0",
		},
		Credential: &domain.ProviderCredential{
			BaseURL:         endpoint,
			DecryptedAPIKey: `{"aws_access_key_id":"AKIA_TEST","aws_secret_access_key":"SECRET_TEST","aws_region":"us-east-1"}`,
		},
	}
}

func TestBedrock_ChatCompletion_PayloadAndUsage(t *testing.T) {
	var captured map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &captured); err != nil {
			t.Fatalf("unmarshal request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"output": {
				"message": {
					"role": "assistant",
					"content": [
						{"reasoningContent": {"reasoningText": {"text": "Thinking step"}}},
						{"text": "{\"answer\":42}"}
					]
				}
			},
			"stopReason": "end_turn",
			"usage": {
				"inputTokens": 100,
				"outputTokens": 25,
				"totalTokens": 125,
				"cacheReadInputTokens": 40,
				"cacheWriteInputTokens": 15
			}
		}`))
	}))
	defer srv.Close()

	adp := bedrock.NewAdapter(srv.Client(), nil)
	imgData := base64.StdEncoding.EncodeToString([]byte("pngbytes"))
	pdfData := base64.StdEncoding.EncodeToString([]byte("%PDF-1.4"))

	req := &domain.CanonicalChatRequest{
		Model:           "anthropic.claude-sonnet-4-5-v1:0",
		ReasoningEffort: "high",
		ToolChoice: map[string]any{
			"type": "function",
			"function": map[string]any{
				"name": "get_weather",
			},
		},
		Tools: []domain.CanonicalTool{
			{
				Type: "function",
				Function: domain.CanonicalFunction{
					Name:        "get_weather",
					Description: "Get weather",
					Parameters: map[string]any{
						"type": "object",
						"properties": map[string]any{
							"city": map[string]any{"type": "string"},
						},
					},
				},
			},
		},
		ResponseFormat: &domain.ResponseFormat{
			Type: "json_schema",
			JSONSchema: map[string]any{
				"name": "answer_schema",
				"schema": map[string]any{
					"type": "object",
					"properties": map[string]any{
						"answer": map[string]any{"type": "integer"},
					},
				},
			},
		},
		Messages: []domain.CanonicalMessage{
			{
				Role:         "system",
				Content:      "You are helpful.",
				CacheControl: &domain.CacheControl{Type: "ephemeral"},
			},
			{
				Role: "user",
				Parts: []domain.ContentPart{
					{Type: "text", Text: "Inspect these"},
					{Type: "image_url", ImageURL: &domain.ImageURL{URL: "data:image/png;base64," + imgData}},
					{Type: "document", Document: &domain.DocumentPart{MimeType: "application/pdf", Data: pdfData, Filename: "spec.pdf"}},
				},
			},
			{
				Role: "assistant",
				ToolCalls: []domain.CanonicalToolCall{
					{ID: "tc-1", Type: "function", Function: domain.CanonicalFunctionCall{Name: "get_weather", Arguments: `{"city":"NYC"}`}},
					{ID: "tc-2", Type: "function", Function: domain.CanonicalFunctionCall{Name: "get_weather", Arguments: `{"city":"SFO"}`}},
				},
			},
			{
				Role:       "tool",
				ToolCallID: "tc-1",
				Content:    "sunny",
			},
			{
				Role:       "tool",
				ToolCallID: "tc-2",
				Content:    "foggy",
			},
		},
	}

	resp, err := adp.ChatCompletion(context.Background(), testBedrockDeployment(srv.URL), req)
	if err != nil {
		t.Fatalf("ChatCompletion failed: %v", err)
	}

	if resp.Usage.CachedPromptTokens != 40 {
		t.Fatalf("expected CachedPromptTokens=40, got %d", resp.Usage.CachedPromptTokens)
	}
	if resp.Usage.CacheCreationTokens != 15 {
		t.Fatalf("expected CacheCreationTokens=15, got %d", resp.Usage.CacheCreationTokens)
	}
	if resp.Choices[0].Message.ReasoningContent != "Thinking step" {
		t.Fatalf("expected ReasoningContent='Thinking step', got %q", resp.Choices[0].Message.ReasoningContent)
	}

	// Verify system cachePoint
	sysBlocks, ok := captured["system"].([]any)
	if !ok || len(sysBlocks) != 2 {
		t.Fatalf("expected 2 system blocks (text + cachePoint), got %#v", captured["system"])
	}

	// Verify toolConfig.toolChoice
	toolConfig, ok := captured["toolConfig"].(map[string]any)
	if !ok {
		t.Fatalf("expected toolConfig in payload")
	}
	tcChoice, ok := toolConfig["toolChoice"].(map[string]any)
	if !ok {
		t.Fatalf("expected toolChoice in toolConfig")
	}
	if _, ok := tcChoice["tool"].(map[string]any); !ok {
		t.Fatalf("expected toolConfig.toolChoice.tool, got %#v", tcChoice)
	}

	// Verify outputConfig.textFormat
	outputConfig, ok := captured["outputConfig"].(map[string]any)
	if !ok {
		t.Fatalf("expected outputConfig in payload, got %#v", captured["outputConfig"])
	}
	textFormat, ok := outputConfig["textFormat"].(map[string]any)
	if !ok || textFormat["type"] != "json_schema" {
		t.Fatalf("expected outputConfig.textFormat type=json_schema, got %#v", outputConfig)
	}

	// Verify additionalModelRequestFields.thinking
	addFields, ok := captured["additionalModelRequestFields"].(map[string]any)
	if !ok {
		t.Fatalf("expected additionalModelRequestFields in payload")
	}
	if _, ok := addFields["thinking"].(map[string]any); !ok {
		t.Fatalf("expected thinking in additionalModelRequestFields, got %#v", addFields)
	}

	// Verify user parts (text + image + document) and merged consecutive tool results
	msgs, ok := captured["messages"].([]any)
	if !ok || len(msgs) != 3 {
		t.Fatalf("expected 3 converse messages (user, assistant, merged tool user), got %d", len(msgs))
	}
	userMsg := msgs[0].(map[string]any)
	userContent := userMsg["content"].([]any)
	if len(userContent) != 3 {
		t.Fatalf("expected 3 content blocks in user message (text, image, document), got %d", len(userContent))
	}
	mergedToolMsg := msgs[2].(map[string]any)
	if mergedToolMsg["role"] != "user" {
		t.Fatalf("expected merged tool message role=user, got %v", mergedToolMsg["role"])
	}
	mergedContent := mergedToolMsg["content"].([]any)
	if len(mergedContent) != 2 {
		t.Fatalf("expected 2 merged toolResult blocks (no duplicate text block), got %d", len(mergedContent))
	}
	for i, blk := range mergedContent {
		m := blk.(map[string]any)
		if _, hasToolResult := m["toolResult"]; !hasToolResult {
			t.Fatalf("block %d missing toolResult: %#v", i, m)
		}
	}
}

func TestBedrock_RerankUsesAgentRuntimeWireFormat(t *testing.T) {
	var captured map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/rerank" {
			t.Errorf("path = %q, want /rerank", r.URL.Path)
		}
		if r.Header.Get("Authorization") == "" || !strings.Contains(r.Header.Get("Authorization"), "bedrock-agent-runtime") {
			t.Errorf("request is not SigV4 signed for Bedrock Agent Runtime: %q", r.Header.Get("Authorization"))
		}
		if err := json.NewDecoder(r.Body).Decode(&captured); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"rr-1","results":[{"index":0,"relevanceScore":0.93}],"usage":{"search_units":1}}`))
	}))
	defer srv.Close()

	adp := bedrock.NewAdapter(srv.Client(), nil)
	topN := 1
	resp, err := adp.Rerank(context.Background(), testBedrockDeployment(srv.URL), &domain.CanonicalRerankRequest{
		Model:     "arn:aws:bedrock:us-east-1:123456789012:inference-profile/reranker",
		Query:     "query",
		Documents: []domain.RerankDocument{{Text: "first"}, {Raw: map[string]any{"title": "second"}}},
		TopN:      &topN,
	})
	if err != nil {
		t.Fatalf("Rerank: %v", err)
	}
	if len(resp.Results) != 1 || resp.Results[0].RelevanceScore != 0.93 || resp.Usage.SearchUnits != 1 {
		t.Fatalf("unexpected rerank response: %+v", resp)
	}
	queries, ok := captured["queries"].([]any)
	if !ok || len(queries) != 1 {
		t.Fatalf("unexpected queries payload: %#v", captured["queries"])
	}
	configuration, ok := captured["rerankingConfiguration"].(map[string]any)
	if !ok || configuration["type"] != "BEDROCK_RERANKING_MODEL" {
		t.Fatalf("unexpected rerankingConfiguration: %#v", captured["rerankingConfiguration"])
	}
	if got := configuration["bedrockRerankingConfiguration"].(map[string]any)["numberOfResults"]; got != float64(1) {
		t.Fatalf("numberOfResults = %v, want 1", got)
	}
	if got := len(captured["sources"].([]any)); got != 2 {
		t.Fatalf("sources count = %d, want 2", got)
	}
}

func TestBedrock_TitanV2EmbeddingPreservesInputsAndDimensions(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if body["dimensions"] != float64(512) {
			t.Errorf("dimensions = %v, want 512", body["dimensions"])
		}
		if body["inputText"] == "" {
			t.Error("missing inputText")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"embedding":[0.1,0.2],"inputTextTokenCount":2}`))
	}))
	defer srv.Close()

	adp := bedrock.NewAdapter(srv.Client(), nil)
	dimensions := 512
	resp, err := adp.Embeddings(context.Background(), testBedrockDeployment(srv.URL), &domain.CanonicalEmbeddingRequest{
		Model: "amazon.titan-embed-text-v2:0", Input: []string{"first", "second"}, Dimensions: &dimensions,
	})
	if err != nil {
		t.Fatalf("Embeddings: %v", err)
	}
	if calls != 2 || len(resp.Data) != 2 || resp.Data[1].Index != 1 || resp.Usage.TotalTokens != 4 {
		t.Fatalf("unexpected multi-input response: calls=%d response=%+v", calls, resp)
	}
}

func TestBedrock_CohereV4EmbeddingUsesTextsAndInputType(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if body["input_type"] != "search_query" || body["output_dimension"] != float64(256) {
			t.Errorf("unexpected Cohere request fields: %#v", body)
		}
		if got := len(body["texts"].([]any)); got != 2 {
			t.Errorf("texts count = %d, want 2", got)
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"embeddings":{"float":[[0.1,0.2],[0.3,0.4]]},"inputTextTokenCount":6}`))
	}))
	defer srv.Close()

	adp := bedrock.NewAdapter(srv.Client(), nil)
	dimensions := 256
	resp, err := adp.Embeddings(context.Background(), testBedrockDeployment(srv.URL), &domain.CanonicalEmbeddingRequest{
		Model: "cohere.embed-v4:0", Input: []string{"one", "two"}, InputType: "search_query", Dimensions: &dimensions,
	})
	if err != nil {
		t.Fatalf("Embeddings: %v", err)
	}
	if len(resp.Data) != 2 || resp.Data[0].Embedding[0] != 0.1 || resp.Usage.TotalTokens != 6 {
		t.Fatalf("unexpected Cohere response: %+v", resp)
	}
}

func TestBedrock_EmbeddingDoesNotBillByteLengthAsTokenUsage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"embedding":[0.1,0.2]}`))
	}))
	defer srv.Close()

	adp := bedrock.NewAdapter(srv.Client(), nil)
	resp, err := adp.Embeddings(context.Background(), testBedrockDeployment(srv.URL), &domain.CanonicalEmbeddingRequest{
		Model: "amazon.titan-embed-text-v1", Input: []string{"longer than a token"},
	})
	if err != nil {
		t.Fatalf("Embeddings: %v", err)
	}
	if resp.Usage.TotalTokens != 0 {
		t.Fatalf("TotalTokens = %d, want 0 when upstream usage is missing", resp.Usage.TotalTokens)
	}
}

func TestBedrock_StreamChatCompletion_ToolUseAndCacheUsage(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.amazon.eventstream")
		hdr := map[string]string{":message-type": "event", ":event-type": "chunk"}
		frames := [][]byte{
			bedrock.EncodeEventStreamMessage(hdr, []byte(`{"contentBlockStart":{"contentBlockIndex":0,"start":{"text":""}}}`)),
			bedrock.EncodeEventStreamMessage(hdr, []byte(`{"contentBlockDelta":{"contentBlockIndex":0,"delta":{"text":"Searching"}}}`)),
			bedrock.EncodeEventStreamMessage(hdr, []byte(`{"contentBlockStart":{"contentBlockIndex":1,"start":{"toolUse":{"toolUseId":"call_99","name":"lookup"}}}}`)),
			bedrock.EncodeEventStreamMessage(hdr, []byte(`{"contentBlockDelta":{"contentBlockIndex":1,"delta":{"toolUse":{"input":"{\"q\":"}}}}`)),
			bedrock.EncodeEventStreamMessage(hdr, []byte(`{"contentBlockDelta":{"contentBlockIndex":1,"delta":{"toolUse":{"input":"\"go\"}"}}}}`)),
			bedrock.EncodeEventStreamMessage(hdr, []byte(`{"messageStop":{"stopReason":"tool_use"}}`)),
			bedrock.EncodeEventStreamMessage(hdr, []byte(`{"metadata":{"usage":{"inputTokens":50,"outputTokens":10,"totalTokens":60,"cacheReadInputTokens":20,"cacheWriteInputTokens":5}}}`)),
		}
		for _, f := range frames {
			_, _ = w.Write(f)
		}
	}))
	defer srv.Close()

	adp := bedrock.NewAdapter(srv.Client(), nil)
	req := &domain.CanonicalChatRequest{
		Model:    "anthropic.claude-sonnet-4-5-v1:0",
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "hi"}},
	}

	var toolID, toolName, args, finishReason string
	toolIndex := -1
	usage, err := adp.StreamChatCompletion(context.Background(), testBedrockDeployment(srv.URL), req, func(chunk *domain.CanonicalStreamChunk) error {
		for _, c := range chunk.Choices {
			for _, tc := range c.Delta.ToolCalls {
				if tc.Index != nil {
					toolIndex = *tc.Index
				}
				if tc.ID != "" {
					toolID = tc.ID
				}
				if tc.Function.Name != "" {
					toolName = tc.Function.Name
				}
				args += tc.Function.Arguments
			}
			if c.FinishReason != nil {
				finishReason = *c.FinishReason
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("StreamChatCompletion failed: %v", err)
	}
	if toolID != "call_99" || toolName != "lookup" || toolIndex != 0 {
		t.Fatalf("expected first tool index=0, id=call_99 name=lookup; got index=%d id=%q name=%q", toolIndex, toolID, toolName)
	}
	if args != `{"q":"go"}` {
		t.Fatalf("expected reassembled args '{\"q\":\"go\"}', got %q", args)
	}
	if finishReason != "tool_calls" {
		t.Fatalf("expected finishReason='tool_calls', got %q", finishReason)
	}
	if usage.PromptTokens != 70 || usage.CachedPromptTokens != 20 || usage.CacheCreationTokens != 5 {
		t.Fatalf("expected prompt=70 cacheRead=20 cacheWrite=5, got prompt=%d read=%d write=%d", usage.PromptTokens, usage.CachedPromptTokens, usage.CacheCreationTokens)
	}
}
