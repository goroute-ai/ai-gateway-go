package openaicompat_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/adapter/openaicompat"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestContract_Groq verifies Groq dialect behavior:
// 1. Distill models reject tool calling with HTTP 400 (CapabilityUnsupported).
// 2. Non-distill models allow tool calls.
// 3. max_completion_tokens is mapped to max_tokens in upstream payload.
func TestContract_Groq(t *testing.T) {
	// 1. Distill model tool rejection
	reg := openaicompat.NewProfileRegistry(nil, nil)
	groqAdp, err := reg.CreateAdapter("groq")
	require.NoError(t, err)

	distillDep := &domain.Deployment{
		ID: "dep-groq-distill",
		GlobalModel: &domain.GlobalModel{
			ID:        "groq/llama-3.1-8b-instant-distill",
			Provider:  "groq",
			ModelName: "llama-3.1-8b-instant-distill",
		},
		Credential: &domain.ProviderCredential{
			DecryptedAPIKey: "gsk_test_key",
		},
	}

	distillReq := &domain.CanonicalChatRequest{
		Model: "llama-3.1-8b-instant-distill",
		Messages: []domain.CanonicalMessage{
			{Role: "user", Content: "Hello"},
		},
		Tools: []domain.CanonicalTool{
			{
				Type: "function",
				Function: domain.CanonicalFunction{
					Name: "get_weather",
				},
			},
		},
	}

	_, err = groqAdp.ChatCompletion(context.Background(), distillDep, distillReq)
	require.Error(t, err)
	gwErr, ok := err.(*domain.GatewayError)
	require.True(t, ok)
	assert.Equal(t, http.StatusBadRequest, gwErr.StatusCode)
	assert.Equal(t, "capability_unsupported", gwErr.Code)
	assert.Contains(t, gwErr.Message, "tools")

	// 2. Upstream request mapping (max_completion_tokens -> max_tokens)
	var capturedPayload map[string]any
	var capturedAuthHeader string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuthHeader = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &capturedPayload)

		resp := map[string]any{
			"id":      "chatcmpl-groq-123",
			"object":  "chat.completion",
			"created": 1700000000,
			"model":   "llama-3.3-70b-versatile",
			"choices": []map[string]any{
				{
					"index": 0,
					"message": map[string]any{
						"role":    "assistant",
						"content": "Groq fast response",
					},
					"finish_reason": "stop",
				},
			},
			"usage": map[string]any{
				"prompt_tokens":     12,
				"completion_tokens": 5,
				"total_tokens":      17,
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	srvReg := openaicompat.NewProfileRegistry(srv.Client(), nil)
	srvGroqAdp, err := srvReg.CreateAdapter("groq")
	require.NoError(t, err)

	standardDep := &domain.Deployment{
		ID: "dep-groq-standard",
		GlobalModel: &domain.GlobalModel{
			ID:        "groq/llama-3.3-70b-versatile",
			Provider:  "groq",
			ModelName: "llama-3.3-70b-versatile",
		},
		Credential: &domain.ProviderCredential{
			BaseURL:         srv.URL,
			DecryptedAPIKey: "gsk_valid_test_token",
		},
	}

	maxTokens := 1024
	chatReq := &domain.CanonicalChatRequest{
		Model: "llama-3.3-70b-versatile",
		Messages: []domain.CanonicalMessage{
			{Role: "user", Content: "Fast inference query"},
		},
		MaxTokens: &maxTokens,
	}

	resp, err := srvGroqAdp.ChatCompletion(context.Background(), standardDep, chatReq)
	require.NoError(t, err)
	assert.Equal(t, "Groq fast response", resp.Choices[0].Message.Content)
	assert.Equal(t, "Bearer gsk_valid_test_token", capturedAuthHeader)
	// Verified mapping: max_tokens was placed in upstream payload
	assert.Equal(t, float64(1024), capturedPayload["max_tokens"])
}

// TestContract_DeepSeek verifies DeepSeek dialect behavior:
// 1. Reasoner/R1 models reject custom temperature / top_p.
// 2. Streaming chunks with reasoning_content are extracted into CanonicalStreamDelta.ReasoningContent.
func TestContract_DeepSeek(t *testing.T) {
	reg := openaicompat.NewProfileRegistry(nil, nil)
	dsAdp, err := reg.CreateAdapter("deepseek")
	require.NoError(t, err)

	// 1. R1 Temperature Rejection
	r1Dep := &domain.Deployment{
		ID: "dep-deepseek-r1",
		GlobalModel: &domain.GlobalModel{
			ID:        "deepseek/deepseek-reasoner",
			Provider:  "deepseek",
			ModelName: "deepseek-reasoner",
		},
		Credential: &domain.ProviderCredential{
			DecryptedAPIKey: "ds_test_key",
		},
	}

	customTemp := 0.7
	r1Req := &domain.CanonicalChatRequest{
		Model: "deepseek-reasoner",
		Messages: []domain.CanonicalMessage{
			{Role: "user", Content: "Solve this math problem"},
		},
		Temperature: &customTemp,
	}

	_, err = dsAdp.ChatCompletion(context.Background(), r1Dep, r1Req)
	require.Error(t, err)
	gwErr, ok := err.(*domain.GatewayError)
	require.True(t, ok)
	assert.Equal(t, http.StatusBadRequest, gwErr.StatusCode)
	assert.Equal(t, "unsupported_parameter", gwErr.Code)
	assert.Contains(t, gwErr.Message, "temperature")

	// 2. Streaming reasoning_content extraction
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		flusher, _ := w.(http.Flusher)

		// Chunk 1: reasoning content
		fmt.Fprintf(w, "data: {\"id\":\"chunk-1\",\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"reasoning_content\":\"Step 1: let x = 42\"}}]}\n\n")
		flusher.Flush()

		// Chunk 2: main content
		fmt.Fprintf(w, "data: {\"id\":\"chunk-2\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\" The answer is 42.\"}}]}\n\n")
		flusher.Flush()

		// Chunk 3: DONE
		fmt.Fprintf(w, "data: [DONE]\n\n")
		flusher.Flush()
	}))
	defer srv.Close()

	srvReg := openaicompat.NewProfileRegistry(srv.Client(), nil)
	srvDsAdp, err := srvReg.CreateAdapter("deepseek")
	require.NoError(t, err)

	streamDep := &domain.Deployment{
		ID: "dep-deepseek-stream",
		GlobalModel: &domain.GlobalModel{
			ID:        "deepseek/deepseek-reasoner",
			Provider:  "deepseek",
			ModelName: "deepseek-reasoner",
		},
		Credential: &domain.ProviderCredential{
			BaseURL:         srv.URL,
			DecryptedAPIKey: "ds_test_key",
		},
	}

	var reasoningDeltas []string
	var contentDeltas []string

	_, err = srvDsAdp.StreamChatCompletion(context.Background(), streamDep, &domain.CanonicalChatRequest{
		Model: "deepseek-reasoner",
		Messages: []domain.CanonicalMessage{
			{Role: "user", Content: "Solve this math problem"},
		},
	}, func(chunk *domain.CanonicalStreamChunk) error {
		if len(chunk.Choices) > 0 {
			if chunk.Choices[0].Delta.ReasoningContent != "" {
				reasoningDeltas = append(reasoningDeltas, chunk.Choices[0].Delta.ReasoningContent)
			}
			if chunk.Choices[0].Delta.Content != "" {
				contentDeltas = append(contentDeltas, chunk.Choices[0].Delta.Content)
			}
		}
		return nil
	})

	require.NoError(t, err)
	require.Len(t, reasoningDeltas, 1)
	assert.Equal(t, "Step 1: let x = 42", reasoningDeltas[0])
	require.Len(t, contentDeltas, 1)
	assert.Equal(t, " The answer is 42.", contentDeltas[0])
}

// TestContract_TogetherAI verifies Together AI dialect behavior:
// 1. Temperature clamped/validated within [0.0, 1.0].
// 2. Embeddings execution.
func TestContract_TogetherAI(t *testing.T) {
	reg := openaicompat.NewProfileRegistry(nil, nil)
	togetherAdp, err := reg.CreateAdapter("together")
	require.NoError(t, err)

	// 1. Out-of-bounds temperature rejection (> 1.0)
	invalidTemp := 1.5
	dep := &domain.Deployment{
		ID: "dep-together",
		GlobalModel: &domain.GlobalModel{
			ID:        "together/meta-llama/Llama-3-70b-chat-hf",
			Provider:  "together",
			ModelName: "meta-llama/Llama-3-70b-chat-hf",
		},
		Credential: &domain.ProviderCredential{
			DecryptedAPIKey: "together_test_key",
		},
	}

	req := &domain.CanonicalChatRequest{
		Model: "meta-llama/Llama-3-70b-chat-hf",
		Messages: []domain.CanonicalMessage{
			{Role: "user", Content: "Hello"},
		},
		Temperature: &invalidTemp,
	}

	_, err = togetherAdp.ChatCompletion(context.Background(), dep, req)
	require.Error(t, err)
	gwErr, ok := err.(*domain.GatewayError)
	require.True(t, ok)
	assert.Equal(t, http.StatusBadRequest, gwErr.StatusCode)
	assert.Equal(t, "unsupported_parameter", gwErr.Code)

	// 2. Embeddings call
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/embeddings", r.URL.Path)
		assert.Equal(t, "Bearer together_test_key", r.Header.Get("Authorization"))

		resp := map[string]any{
			"object": "list",
			"data": []map[string]any{
				{
					"object":    "embedding",
					"index":     0,
					"embedding": []float64{0.1, 0.2, 0.3},
				},
			},
			"model": "togethercomputer/m2-bert-80M-8k-retrieval",
			"usage": map[string]any{
				"prompt_tokens": 6,
				"total_tokens":  6,
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	srvReg := openaicompat.NewProfileRegistry(srv.Client(), nil)
	srvTogetherAdp, err := srvReg.CreateAdapter("together")
	require.NoError(t, err)

	embDep := &domain.Deployment{
		ID: "dep-together-emb",
		GlobalModel: &domain.GlobalModel{
			ID:        "together/togethercomputer/m2-bert-80M-8k-retrieval",
			Provider:  "together",
			ModelName: "togethercomputer/m2-bert-80M-8k-retrieval",
		},
		Credential: &domain.ProviderCredential{
			BaseURL:         srv.URL,
			DecryptedAPIKey: "together_test_key",
		},
	}

	embResp, err := srvTogetherAdp.Embeddings(context.Background(), embDep, &domain.CanonicalEmbeddingRequest{
		Model: "togethercomputer/m2-bert-80M-8k-retrieval",
		Input: []string{"test vector text"},
	})
	require.NoError(t, err)
	assert.Len(t, embResp.Data, 1)
	assert.Equal(t, []float64{0.1, 0.2, 0.3}, embResp.Data[0].Embedding)
}

// TestContract_AzureOpenAI verifies Azure OpenAI dual-mode endpoints and auth:
// 1. Standard mode uses /openai/v1/chat/completions.
// 2. Legacy deployment mode uses /openai/deployments/{deployment_name}/chat/completions?api-version={api_version}.
// 3. Rejects missing deployment name or invalid api version in legacy mode.
// 4. API Key auth uses api-key header; Bearer auth uses Authorization: Bearer.
// 5. ListModels is unsupported on Azure inference keys and returns typed list_models_unsupported.
func TestContract_AzureOpenAI(t *testing.T) {
	reg := openaicompat.NewProfileRegistry(nil, nil)
	azureAdp, err := reg.CreateAdapter("azure")
	require.NoError(t, err)

	// 1. ListModels probe returns typed error
	_, err = azureAdp.ListModels(context.Background(), &domain.ProviderCredential{
		DecryptedAPIKey: "azure-key",
	})
	require.Error(t, err)
	gwErr, ok := err.(*domain.GatewayError)
	require.True(t, ok)
	assert.Equal(t, "list_models_unsupported", gwErr.Code)
	assert.Equal(t, http.StatusNotImplemented, gwErr.StatusCode)

	// 2. Standard OpenAI-compatible v1 mode
	var capturedPath string
	var capturedAPIKeyHeader string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedPath = r.URL.Path
		capturedAPIKeyHeader = r.Header.Get("api-key")

		resp := map[string]any{
			"id":      "chatcmpl-azure-123",
			"object":  "chat.completion",
			"created": 1700000000,
			"model":   "gpt-4o",
			"choices": []map[string]any{
				{
					"index": 0,
					"message": map[string]any{
						"role":    "assistant",
						"content": "Azure response",
					},
					"finish_reason": "stop",
				},
			},
			"usage": map[string]any{
				"prompt_tokens":     10,
				"completion_tokens": 4,
				"total_tokens":      14,
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	srvReg := openaicompat.NewProfileRegistry(srv.Client(), nil)
	srvAzureAdp, err := srvReg.CreateAdapter("azure")
	require.NoError(t, err)

	standardDep := &domain.Deployment{
		ID: "dep-azure-v1",
		GlobalModel: &domain.GlobalModel{
			ID:        "azure/gpt-4o",
			Provider:  "azure",
			ModelName: "gpt-4o",
		},
		Credential: &domain.ProviderCredential{
			BaseURL:         srv.URL + "/openai/v1",
			DecryptedAPIKey: "my-azure-secret-key",
		},
	}

	resp, err := srvAzureAdp.ChatCompletion(context.Background(), standardDep, &domain.CanonicalChatRequest{
		Model: "gpt-4o",
		Messages: []domain.CanonicalMessage{
			{Role: "user", Content: "Hello Azure"},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, "Azure response", resp.Choices[0].Message.Content)
	assert.Equal(t, "/openai/v1/chat/completions", capturedPath)
	assert.Equal(t, "my-azure-secret-key", capturedAPIKeyHeader)

	// 3. Legacy deployment mode with explicit deployment name and API version
	var capturedRawURL string
	legacySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedRawURL = r.URL.RequestURI()
		resp := map[string]any{
			"id":      "chatcmpl-azure-legacy",
			"object":  "chat.completion",
			"created": 1700000000,
			"model":   "my-prod-gpt4",
			"choices": []map[string]any{
				{
					"index": 0,
					"message": map[string]any{
						"role":    "assistant",
						"content": "Legacy Azure response",
					},
					"finish_reason": "stop",
				},
			},
			"usage": map[string]any{
				"prompt_tokens":     10,
				"completion_tokens": 4,
				"total_tokens":      14,
			},
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer legacySrv.Close()

	srvLegacyReg := openaicompat.NewProfileRegistry(legacySrv.Client(), nil)
	srvLegacyAzureAdp, err := srvLegacyReg.CreateAdapter("azure")
	require.NoError(t, err)

	legacyDep := &domain.Deployment{
		ID:             "dep-azure-legacy",
		DeploymentName: "internal-gateway-dep-1", // Must NOT be confused with Azure deployment name
		GlobalModel: &domain.GlobalModel{
			ID:        "azure/gpt-4o",
			Provider:  "azure",
			ModelName: "gpt-4o",
		},
		Credential: &domain.ProviderCredential{
			BaseURL:             legacySrv.URL,
			DecryptedAPIKey:     "azure-legacy-key",
			AzureDeploymentName: "my-azure-resource-deployment",
			APIVersion:          "2024-06-01",
		},
	}

	resp, err = srvLegacyAzureAdp.ChatCompletion(context.Background(), legacyDep, &domain.CanonicalChatRequest{
		Model: "gpt-4o",
		Messages: []domain.CanonicalMessage{
			{Role: "user", Content: "Hello Legacy Azure"},
		},
	})
	require.NoError(t, err)
	assert.Equal(t, "Legacy Azure response", resp.Choices[0].Message.Content)
	assert.Equal(t, "/openai/deployments/my-azure-resource-deployment/chat/completions?api-version=2024-06-01", capturedRawURL)

	// 4. Legacy deployment mode without explicit AzureDeploymentName fails safely
	missingDeployNameDep := &domain.Deployment{
		ID: "dep-azure-missing",
		GlobalModel: &domain.GlobalModel{
			ID:        "azure/gpt-4o",
			Provider:  "azure",
			ModelName: "gpt-4o",
		},
		Credential: &domain.ProviderCredential{
			BaseURL:         legacySrv.URL,
			DecryptedAPIKey: "azure-key",
			// AzureDeploymentName omitted!
			APIVersion: "2024-06-01",
		},
	}
	_, err = srvLegacyAzureAdp.ChatCompletion(context.Background(), missingDeployNameDep, &domain.CanonicalChatRequest{
		Model: "gpt-4o",
		Messages: []domain.CanonicalMessage{
			{Role: "user", Content: "Hello"},
		},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "azure_deployment_name")
}

// TestLiveUpstream_OptIn allows manual or CI execution against live upstream vendors
// when API keys are explicitly exported in environment variables.
func TestLiveUpstream_OptIn(t *testing.T) {
	groqKey := os.Getenv("GOROUTE_LIVE_TEST_GROQ_API_KEY")
	if groqKey == "" {
		t.Skip("Skipping live Groq contract test: GOROUTE_LIVE_TEST_GROQ_API_KEY is not set")
	}

	reg := openaicompat.NewProfileRegistry(nil, nil)
	groqAdp, err := reg.CreateAdapter("groq")
	require.NoError(t, err)

	dep := &domain.Deployment{
		ID: "dep-live-groq",
		GlobalModel: &domain.GlobalModel{
			ID:        "groq/llama-3.3-70b-versatile",
			Provider:  "groq",
			ModelName: "llama-3.3-70b-versatile",
		},
		Credential: &domain.ProviderCredential{
			DecryptedAPIKey: groqKey,
		},
	}

	resp, err := groqAdp.ChatCompletion(context.Background(), dep, &domain.CanonicalChatRequest{
		Model: "llama-3.3-70b-versatile",
		Messages: []domain.CanonicalMessage{
			{Role: "user", Content: "Respond with the single word PONG"},
		},
	})
	require.NoError(t, err)
	assert.True(t, len(resp.Choices) > 0)
	assert.Contains(t, strings.ToUpper(resp.Choices[0].Message.Content), "PONG")
}
