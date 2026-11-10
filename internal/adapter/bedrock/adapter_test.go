package bedrock_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/adapter/bedrock"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSigV4_Sign(t *testing.T) {
	signer := &bedrock.SigV4Signer{
		AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
		SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		Region:          "us-east-1",
		Service:         "bedrock",
	}

	payload := []byte(`{"test":"hello"}`)
	req, err := http.NewRequest(http.MethodPost, "https://bedrock-runtime.us-east-1.amazonaws.com/model/test-model/converse", strings.NewReader(string(payload)))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")

	fixedTime := time.Date(2026, 11, 10, 12, 0, 0, 0, time.UTC)
	err = signer.Sign(req, payload, fixedTime)
	require.NoError(t, err)

	auth := req.Header.Get("Authorization")
	assert.True(t, strings.HasPrefix(auth, "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20261110/us-east-1/bedrock/aws4_request"))
	assert.Contains(t, auth, "SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date")
	assert.Contains(t, auth, "Signature=")
	assert.Equal(t, "20261110T120000Z", req.Header.Get("x-amz-date"))
}

func TestEventStream_EncodeDecode(t *testing.T) {
	headers := map[string]string{
		":message-type": "event",
		":event-type":   "chunk",
		":content-type": "application/json",
	}
	payload := []byte(`{"contentBlockDelta":{"delta":{"text":"Hello Bedrock!"}}}`)

	encoded := bedrock.EncodeEventStreamMessage(headers, payload)
	require.NotEmpty(t, encoded)

	msg, err := bedrock.DecodeEventStreamMessage(strings.NewReader(string(encoded)))
	require.NoError(t, err)
	require.NotNil(t, msg)
	assert.Equal(t, "event", msg.Headers[":message-type"])
	assert.Equal(t, "chunk", msg.Headers[":event-type"])
	assert.Equal(t, "application/json", msg.Headers[":content-type"])
	assert.Equal(t, payload, msg.Payload)
}

func TestBedrockAdapter_ConverseNonStreaming(t *testing.T) {
	var capturedAuth string
	var capturedBody map[string]any

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuth = r.Header.Get("Authorization")
		bodyBytes, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(bodyBytes, &capturedBody)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{
			"output": {
				"message": {
					"role": "assistant",
					"content": [
						{"text": "Bedrock Converse reply"},
						{
							"toolUse": {
								"toolUseId": "call_123",
								"name": "lookup_user",
								"input": {"id": 42}
							}
						}
					]
				}
			},
			"stopReason": "tool_use",
			"usage": {
				"inputTokens": 25,
				"outputTokens": 40,
				"totalTokens": 65
			}
		}`))
	}))
	defer srv.Close()

	adp := bedrock.NewAdapter(srv.Client(), nil)
	assert.Equal(t, domain.ProviderBedrock, adp.Provider())

	dep := &domain.Deployment{
		ID: "dep-bedrock-test",
		GlobalModel: &domain.GlobalModel{
			ID:        "bedrock/anthropic.claude-3-5-sonnet-20241022-v2:0",
			Provider:  domain.ProviderBedrock,
			ModelName: "anthropic.claude-3-5-sonnet-20241022-v2:0",
		},
		Credential: &domain.ProviderCredential{
			BaseURL:         srv.URL,
			DecryptedAPIKey: `{"aws_access_key_id":"test_key","aws_secret_access_key":"test_secret","aws_region":"us-east-1"}`,
		},
	}

	maxTokens := 2048
	temp := 0.7
	req := &domain.CanonicalChatRequest{
		Model: "anthropic.claude-3-5-sonnet-20241022-v2:0",
		Messages: []domain.CanonicalMessage{
			{Role: "system", Content: "You are a helpful assistant."},
			{Role: "user", Content: "Lookup user 42"},
		},
		MaxTokens:   &maxTokens,
		Temperature: &temp,
		Tools: []domain.CanonicalTool{
			{
				Type: "function",
				Function: domain.CanonicalFunction{
					Name:        "lookup_user",
					Description: "Lookup user details",
					Parameters: map[string]any{
						"type": "object",
						"properties": map[string]any{
							"id": map[string]any{"type": "integer"},
						},
					},
				},
			},
		},
	}

	resp, err := adp.ChatCompletion(context.Background(), dep, req)
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Contains(t, capturedAuth, "AWS4-HMAC-SHA256 Credential=test_key")
	assert.NotNil(t, capturedBody["system"])
	assert.NotNil(t, capturedBody["inferenceConfig"])
	assert.NotNil(t, capturedBody["toolConfig"])

	require.Len(t, resp.Choices, 1)
	choice := resp.Choices[0]
	assert.Equal(t, "Bedrock Converse reply", choice.Message.Content)
	assert.Equal(t, "tool_calls", choice.FinishReason)
	require.Len(t, choice.Message.ToolCalls, 1)
	assert.Equal(t, "lookup_user", choice.Message.ToolCalls[0].Function.Name)
	assert.Equal(t, `{"id":42}`, choice.Message.ToolCalls[0].Function.Arguments)
	assert.Equal(t, 25, resp.Usage.PromptTokens)
	assert.Equal(t, 40, resp.Usage.CompletionTokens)
	assert.Equal(t, 65, resp.Usage.TotalTokens)
}

func TestBedrockAdapter_ConverseStreaming(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/vnd.amazon.eventstream")
		w.WriteHeader(http.StatusOK)

		hdr := map[string]string{
			":message-type": "event",
			":event-type":   "chunk",
			":content-type": "application/json",
		}

		// Message 1: text delta
		msg1 := bedrock.EncodeEventStreamMessage(hdr, []byte(`{"contentBlockDelta":{"delta":{"text":"Hello "}}}`))
		_, _ = w.Write(msg1)

		// Message 2: text delta 2
		msg2 := bedrock.EncodeEventStreamMessage(hdr, []byte(`{"contentBlockDelta":{"delta":{"text":"streaming!"}}}`))
		_, _ = w.Write(msg2)

		// Message 3: stop
		msg3 := bedrock.EncodeEventStreamMessage(hdr, []byte(`{"messageStop":{"stopReason":"end_turn"}}`))
		_, _ = w.Write(msg3)

		// Message 4: usage metadata
		msg4 := bedrock.EncodeEventStreamMessage(hdr, []byte(`{"metadata":{"usage":{"inputTokens":12,"outputTokens":18,"totalTokens":30}}}`))
		_, _ = w.Write(msg4)
	}))
	defer srv.Close()

	adp := bedrock.NewAdapter(srv.Client(), nil)

	dep := &domain.Deployment{
		ID: "dep-bedrock-stream",
		GlobalModel: &domain.GlobalModel{
			ID:        "bedrock/amazon.nova-pro-v1:0",
			Provider:  domain.ProviderBedrock,
			ModelName: "amazon.nova-pro-v1:0",
		},
		Credential: &domain.ProviderCredential{
			BaseURL:         srv.URL,
			DecryptedAPIKey: "key:secret:us-east-1",
		},
	}

	var chunks []string
	var finalStopReason string
	usage, err := adp.StreamChatCompletion(context.Background(), dep, &domain.CanonicalChatRequest{
		Model: "amazon.nova-pro-v1:0",
		Messages: []domain.CanonicalMessage{
			{Role: "user", Content: "Hi"},
		},
	}, func(chunk *domain.CanonicalStreamChunk) error {
		if len(chunk.Choices) > 0 {
			if chunk.Choices[0].Delta.Content != "" {
				chunks = append(chunks, chunk.Choices[0].Delta.Content)
			}
			if chunk.Choices[0].FinishReason != nil {
				finalStopReason = *chunk.Choices[0].FinishReason
			}
		}
		return nil
	})

	require.NoError(t, err)
	require.NotNil(t, usage)
	assert.Equal(t, []string{"Hello ", "streaming!"}, chunks)
	assert.Equal(t, "stop", finalStopReason)
	assert.Equal(t, 12, usage.PromptTokens)
	assert.Equal(t, 18, usage.CompletionTokens)
	assert.Equal(t, 30, usage.TotalTokens)
}

func TestBedrockAdapter_Embeddings(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/model/amazon.titan-embed-text-v1/invoke", r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{
			"embedding": [0.123, -0.456, 0.789],
			"inputTextTokenCount": 8
		}`))
	}))
	defer srv.Close()

	adp := bedrock.NewAdapter(srv.Client(), nil)

	dep := &domain.Deployment{
		ID: "dep-bedrock-embed",
		GlobalModel: &domain.GlobalModel{
			ID:        "bedrock/amazon.titan-embed-text-v1",
			Provider:  domain.ProviderBedrock,
			ModelName: "amazon.titan-embed-text-v1",
		},
		Credential: &domain.ProviderCredential{
			BaseURL:         srv.URL,
			DecryptedAPIKey: "key:secret:us-east-1",
		},
	}

	res, err := adp.Embeddings(context.Background(), dep, &domain.CanonicalEmbeddingRequest{
		Model: "amazon.titan-embed-text-v1",
		Input: []string{"Embed this sentence"},
	})
	require.NoError(t, err)
	require.NotNil(t, res)
	assert.Equal(t, "amazon.titan-embed-text-v1", res.Model)
	require.Len(t, res.Data, 1)
	assert.Equal(t, []float64{0.123, -0.456, 0.789}, res.Data[0].Embedding)
	assert.Equal(t, 8, res.Usage.PromptTokens)
}

func TestBedrockAdapter_CredentialValidation(t *testing.T) {
	adp := bedrock.NewAdapter(nil, nil)

	// Valid JSON
	err := adp.ValidateCredential(context.Background(), &domain.ProviderCredential{
		DecryptedAPIKey: `{"aws_access_key_id":"k","aws_secret_access_key":"s"}`,
	})
	assert.NoError(t, err)

	// Valid colon-delimited
	err = adp.ValidateCredential(context.Background(), &domain.ProviderCredential{
		DecryptedAPIKey: "key:secret:us-west-2",
	})
	assert.NoError(t, err)

	// Invalid empty
	err = adp.ValidateCredential(context.Background(), &domain.ProviderCredential{
		DecryptedAPIKey: "",
	})
	assert.Error(t, err)
}
