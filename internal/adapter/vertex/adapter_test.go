package vertex_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/adapter/vertex"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func generateTestServiceAccountKey(t *testing.T, tokenURI string) string {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	der := x509.MarshalPKCS1PrivateKey(privKey)
	pemBlock := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: der,
	})

	sa := vertex.ServiceAccountKey{
		Type:         "service_account",
		ProjectID:    "test-project-123",
		PrivateKeyID: "key-abc",
		PrivateKey:   string(pemBlock),
		ClientEmail:  "test-sa@test-project-123.iam.gserviceaccount.com",
		TokenURI:     tokenURI,
	}

	b, err := json.Marshal(sa)
	require.NoError(t, err)
	return string(b)
}

func TestVertex_TokenExchangeAndCache(t *testing.T) {
	var tokenCalls int32
	oauthSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&tokenCalls, 1)
		require.Equal(t, "POST", r.Method)
		require.Equal(t, "application/x-www-form-urlencoded", r.Header.Get("Content-Type"))

		_ = r.ParseForm()
		assert.Equal(t, "urn:ietf:params:oauth:grant-type:jwt-bearer", r.Form.Get("grant_type"))
		assert.NotEmpty(t, r.Form.Get("assertion"))

		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"access_token": "ya29.test_token_access",
			"expires_in": 3600,
			"token_type": "Bearer"
		}`))
	}))
	defer oauthSrv.Close()

	saJSON := generateTestServiceAccountKey(t, oauthSrv.URL)
	ts, err := vertex.NewTokenSource(oauthSrv.Client(), saJSON)
	require.NoError(t, err)

	// First call -> exchanges token
	tok1, err := ts.GetToken(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "ya29.test_token_access", tok1)
	assert.Equal(t, int32(1), atomic.LoadInt32(&tokenCalls))

	// Second call -> cached
	tok2, err := ts.GetToken(context.Background())
	require.NoError(t, err)
	assert.Equal(t, tok1, tok2)
	assert.Equal(t, int32(1), atomic.LoadInt32(&tokenCalls))
}

func TestVertexAdapter_ChatCompletion(t *testing.T) {
	var capturedAuth string
	var capturedBody map[string]any

	vertexSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuth = r.Header.Get("Authorization")
		bodyBytes, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(bodyBytes, &capturedBody)

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{
			"candidates": [{
				"content": {
					"role": "model",
					"parts": [
						{"text": "Hello from Vertex AI!"},
						{
							"functionCall": {
								"name": "get_stock_quote",
								"args": {"ticker": "GOOG"}
							}
						}
					]
				},
				"finishReason": "STOP"
			}],
			"usageMetadata": {
				"promptTokenCount": 15,
				"candidatesTokenCount": 22,
				"totalTokenCount": 37
			}
		}`))
	}))
	defer vertexSrv.Close()

	adp := vertex.NewAdapter(vertexSrv.Client(), nil)
	assert.Equal(t, domain.ProviderVertex, adp.Provider())

	dep := &domain.Deployment{
		ID: "dep-vertex-test",
		GlobalModel: &domain.GlobalModel{
			ID:        "vertex/gemini-1.5-pro",
			Provider:  domain.ProviderVertex,
			ModelName: "gemini-1.5-pro",
		},
		Credential: &domain.ProviderCredential{
			BaseURL:         vertexSrv.URL,
			DecryptedAPIKey: "ya29.direct_token",
		},
	}

	req := &domain.CanonicalChatRequest{
		Model: "gemini-1.5-pro",
		Messages: []domain.CanonicalMessage{
			{Role: "user", Content: "What is Google stock price?"},
		},
		Tools: []domain.CanonicalTool{
			{
				Type: "function",
				Function: domain.CanonicalFunction{
					Name:        "get_stock_quote",
					Description: "Lookup stock price",
				},
			},
		},
	}

	resp, err := adp.ChatCompletion(context.Background(), dep, req)
	require.NoError(t, err)
	require.NotNil(t, resp)

	assert.Equal(t, "Bearer ya29.direct_token", capturedAuth)
	assert.NotNil(t, capturedBody["contents"])
	assert.NotNil(t, capturedBody["tools"])

	require.Len(t, resp.Choices, 1)
	assert.Equal(t, "Hello from Vertex AI!", resp.Choices[0].Message.Content)
	assert.Equal(t, "stop", resp.Choices[0].FinishReason)
	require.Len(t, resp.Choices[0].Message.ToolCalls, 1)
	assert.Equal(t, "get_stock_quote", resp.Choices[0].Message.ToolCalls[0].Function.Name)
	assert.Equal(t, `{"ticker":"GOOG"}`, resp.Choices[0].Message.ToolCalls[0].Function.Arguments)
	assert.Equal(t, 15, resp.Usage.PromptTokens)
	assert.Equal(t, 22, resp.Usage.CompletionTokens)
	assert.Equal(t, 37, resp.Usage.TotalTokens)
}

func TestVertexAdapter_StreamChatCompletion(t *testing.T) {
	vertexSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)

		_, _ = fmt.Fprint(w, "data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"Streaming \"}]}}]}\n\n")
		_, _ = fmt.Fprint(w, "data: {\"candidates\":[{\"content\":{\"parts\":[{\"text\":\"response!\"}]},\"finishReason\":\"STOP\"}],\"usageMetadata\":{\"promptTokenCount\":10,\"candidatesTokenCount\":15,\"totalTokenCount\":25}}\n\n")
		_, _ = fmt.Fprint(w, "data: [DONE]\n\n")
	}))
	defer vertexSrv.Close()

	adp := vertex.NewAdapter(vertexSrv.Client(), nil)

	dep := &domain.Deployment{
		ID: "dep-vertex-stream",
		GlobalModel: &domain.GlobalModel{
			ID:        "vertex/gemini-1.5-flash",
			Provider:  domain.ProviderVertex,
			ModelName: "gemini-1.5-flash",
		},
		Credential: &domain.ProviderCredential{
			BaseURL:         vertexSrv.URL,
			DecryptedAPIKey: "ya29.direct_token",
		},
	}

	var chunks []string
	var finalStop string
	usage, err := adp.StreamChatCompletion(context.Background(), dep, &domain.CanonicalChatRequest{
		Model: "gemini-1.5-flash",
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
	assert.Equal(t, []string{"Streaming ", "response!"}, chunks)
	assert.Equal(t, "stop", finalStop)
	assert.Equal(t, 10, usage.PromptTokens)
	assert.Equal(t, 15, usage.CompletionTokens)
	assert.Equal(t, 25, usage.TotalTokens)
}

func TestVertexAdapter_Embeddings(t *testing.T) {
	vertexSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.True(t, strings.HasSuffix(r.URL.Path, ":predict"))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{
			"predictions": [
				{
					"embeddings": {
						"values": [0.01, -0.02, 0.03]
					}
				}
			]
		}`))
	}))
	defer vertexSrv.Close()

	adp := vertex.NewAdapter(vertexSrv.Client(), nil)

	dep := &domain.Deployment{
		ID: "dep-vertex-embed",
		GlobalModel: &domain.GlobalModel{
			ID:        "vertex/text-embedding-004",
			Provider:  domain.ProviderVertex,
			ModelName: "text-embedding-004",
		},
		Credential: &domain.ProviderCredential{
			BaseURL:         vertexSrv.URL,
			DecryptedAPIKey: "ya29.direct_token",
		},
	}

	res, err := adp.Embeddings(context.Background(), dep, &domain.CanonicalEmbeddingRequest{
		Model: "text-embedding-004",
		Input: []string{"Hello Vertex embeddings"},
	})
	require.NoError(t, err)
	require.NotNil(t, res)
	require.Len(t, res.Data, 1)
	assert.Equal(t, []float64{0.01, -0.02, 0.03}, res.Data[0].Embedding)
}
