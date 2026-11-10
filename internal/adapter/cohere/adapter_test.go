package cohere_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/adapter/cohere"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCohereAdapter_ChatCompletion(t *testing.T) {
	var capturedAuth string
	var capturedBody map[string]any

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v2/chat", r.URL.Path)
		capturedAuth = r.Header.Get("Authorization")
		bodyBytes, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(bodyBytes, &capturedBody)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{
			"id": "cohere-chat-123",
			"message": {
				"role": "assistant",
				"content": [
					{"type": "text", "text": "Command R+ output"}
				],
				"tool_calls": [
					{
						"id": "call_abc",
						"type": "function",
						"function": {
							"name": "search_database",
							"arguments": "{\"query\":\"ai\"}"
						}
					}
				]
			},
			"finish_reason": "TOOL_CALL",
			"usage": {
				"tokens": {
					"input_tokens": 14,
					"output_tokens": 28
				}
			}
		}`))
	}))
	defer srv.Close()

	adp := cohere.NewAdapter(srv.Client(), nil)
	assert.Equal(t, domain.ProviderCohere, adp.Provider())

	dep := &domain.Deployment{
		ID: "dep-cohere-test",
		GlobalModel: &domain.GlobalModel{
			ID:        "cohere/command-r-plus-08-2024",
			Provider:  domain.ProviderCohere,
			ModelName: "command-r-plus-08-2024",
		},
		Credential: &domain.ProviderCredential{
			BaseURL:         srv.URL,
			DecryptedAPIKey: "cohere-secret-token",
		},
	}

	req := &domain.CanonicalChatRequest{
		Model: "command-r-plus-08-2024",
		Messages: []domain.CanonicalMessage{
			{Role: "user", Content: "Search ai"},
		},
		Tools: []domain.CanonicalTool{
			{
				Type: "function",
				Function: domain.CanonicalFunction{
					Name:        "search_database",
					Description: "Search documents",
				},
			},
		},
	}

	resp, err := adp.ChatCompletion(context.Background(), dep, req)
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Equal(t, "Bearer cohere-secret-token", capturedAuth)
	assert.NotNil(t, capturedBody["messages"])
	assert.NotNil(t, capturedBody["tools"])

	require.Len(t, resp.Choices, 1)
	assert.Equal(t, "Command R+ output", resp.Choices[0].Message.Content)
	assert.Equal(t, "tool_calls", resp.Choices[0].FinishReason)
	require.Len(t, resp.Choices[0].Message.ToolCalls, 1)
	assert.Equal(t, "search_database", resp.Choices[0].Message.ToolCalls[0].Function.Name)
	assert.Equal(t, "{\"query\":\"ai\"}", resp.Choices[0].Message.ToolCalls[0].Function.Arguments)
	assert.Equal(t, 14, resp.Usage.PromptTokens)
	assert.Equal(t, 28, resp.Usage.CompletionTokens)
	assert.Equal(t, 42, resp.Usage.TotalTokens)
}

func TestCohereAdapter_StreamChatCompletion(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)

		_, _ = fmt.Fprint(w, "data: {\"type\":\"content-delta\",\"delta\":{\"message\":{\"content\":{\"text\":\"Streaming \"}}}}\n\n")
		_, _ = fmt.Fprint(w, "data: {\"type\":\"content-delta\",\"delta\":{\"message\":{\"content\":{\"text\":\"Cohere!\"}}}}\n\n")
		_, _ = fmt.Fprint(w, "data: {\"type\":\"message-end\",\"delta\":{\"finish_reason\":\"COMPLETE\",\"usage\":{\"tokens\":{\"input_tokens\":8,\"output_tokens\":12}}}}\n\n")
		_, _ = fmt.Fprint(w, "data: [DONE]\n\n")
	}))
	defer srv.Close()

	adp := cohere.NewAdapter(srv.Client(), nil)

	dep := &domain.Deployment{
		ID: "dep-cohere-stream",
		GlobalModel: &domain.GlobalModel{
			ID:        "cohere/command-r-08-2024",
			Provider:  domain.ProviderCohere,
			ModelName: "command-r-08-2024",
		},
		Credential: &domain.ProviderCredential{
			BaseURL:         srv.URL,
			DecryptedAPIKey: "test-token",
		},
	}

	var chunks []string
	var finalStop string
	usage, err := adp.StreamChatCompletion(context.Background(), dep, &domain.CanonicalChatRequest{
		Model: "command-r-08-2024",
		Messages: []domain.CanonicalMessage{
			{Role: "user", Content: "Hello"},
		},
	}, func(chunk *domain.CanonicalStreamChunk) error {
		if len(chunk.Choices) > 0 {
			if chunk.Choices[0].Delta.Content != "" {
				chunks = append(chunks, chunk.Choices[0].Delta.Content)
			}
			if chunk.Choices[0].FinishReason != nil {
				finalStop = *chunk.Choices[0].FinishReason
			}
		}
		return nil
	})

	require.NoError(t, err)
	require.NotNil(t, usage)
	assert.Equal(t, []string{"Streaming ", "Cohere!"}, chunks)
	assert.Equal(t, "stop", finalStop)
	assert.Equal(t, 8, usage.PromptTokens)
	assert.Equal(t, 12, usage.CompletionTokens)
	assert.Equal(t, 20, usage.TotalTokens)
}

func TestCohereAdapter_Embeddings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/v2/embed", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{
			"id": "embed-123",
			"embeddings": {
				"float": [
					[0.1, -0.2, 0.3]
				]
			},
			"meta": {
				"billed_units": {
					"input_tokens": 5
				}
			}
		}`))
	}))
	defer srv.Close()

	adp := cohere.NewAdapter(srv.Client(), nil)

	dep := &domain.Deployment{
		ID: "dep-cohere-embed",
		GlobalModel: &domain.GlobalModel{
			ID:        "cohere/embed-english-v3.0",
			Provider:  domain.ProviderCohere,
			ModelName: "embed-english-v3.0",
		},
		Credential: &domain.ProviderCredential{
			BaseURL:         srv.URL,
			DecryptedAPIKey: "test-token",
		},
	}

	res, err := adp.Embeddings(context.Background(), dep, &domain.CanonicalEmbeddingRequest{
		Model: "embed-english-v3.0",
		Input: []string{"Cohere embeddings sentence"},
	})
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Len(t, res.Data, 1)
	assert.Equal(t, []float64{0.1, -0.2, 0.3}, res.Data[0].Embedding)
	assert.Equal(t, 5, res.Usage.PromptTokens)
}
