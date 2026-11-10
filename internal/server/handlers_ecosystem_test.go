package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/server"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPhase2_EcosystemBridgesAndTokenize(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	cfg := config.Default()
	cfg.Auth.MasterAdminKey = "admin_secret_key"
	cfg.Security.Network.OutboundSSRF.AllowPrivateNetworks = true
	cfg.Security.Network.OutboundSSRF.AllowInsecureHTTP = true

	// Mock upstream server handling completions and chat completions
	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/completions":
			fmt.Fprint(w, `{
				"id": "cmpl-test-123",
				"model": "gpt-3.5-turbo-instruct",
				"choices": [
					{"index": 0, "text": "This is a completed sentence.", "finish_reason": "stop"}
				],
				"usage": {"prompt_tokens": 5, "completion_tokens": 6, "total_tokens": 11}
			}`)
		case "/v1/chat/completions":
			// If streaming requested:
			var reqBody map[string]any
			_ = json.NewDecoder(r.Body).Decode(&reqBody)
			if stream, _ := reqBody["stream"].(bool); stream {
				w.Header().Set("Content-Type", "text/event-stream")
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, "data: {\"id\":\"chatcmpl-stream\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Hello \"}}]}\n\n")
				fmt.Fprint(w, "data: {\"id\":\"chatcmpl-stream\",\"choices\":[{\"index\":0,\"delta\":{\"content\":\"world!\"}}]}\n\n")
				fmt.Fprint(w, "data: [DONE]\n\n")
				return
			}
			fmt.Fprint(w, `{
				"id": "chatcmpl-anthropic-test",
				"model": "gpt-4.1-mini",
				"choices": [
					{
						"index": 0,
						"message": {"role": "assistant", "content": "Hello from Claude bridge!"},
						"finish_reason": "stop"
					}
				],
				"usage": {"prompt_tokens": 12, "completion_tokens": 5, "total_tokens": 17}
			}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer mockUpstream.Close()

	gw, err := server.New(cfg, repo, nil, mockUpstream.Client())
	require.NoError(t, err)
	handler := gw.Handler()

	org := &domain.Organization{ID: "org-ecosystem", Name: "Eco Org", Slug: "eco-org", IsActive: true}
	require.NoError(t, repo.CreateOrganization(ctx, org))

	// Issue Virtual Key
	var issuedKey domain.VirtualKey
	keyBody, _ := json.Marshal(map[string]any{
		"org_id": org.ID,
		"name":   "eco-key",
	})
	keyReq, _ := http.NewRequest(http.MethodPost, "/admin/v1/keys", bytes.NewReader(keyBody))
	keyReq.Header.Set("Authorization", "Bearer admin_secret_key")
	keyReq.Header.Set("Content-Type", "application/json")
	keyRec := httptest.NewRecorder()
	handler.ServeHTTP(keyRec, keyReq)
	require.Equal(t, http.StatusCreated, keyRec.Code)
	_ = json.Unmarshal(keyRec.Body.Bytes(), &issuedKey)
	require.NotEmpty(t, issuedKey.RawKey)

	// Create Credential via admin API
	var cred domain.ProviderCredential
	credBody, _ := json.Marshal(map[string]any{
		"org_id":   org.ID,
		"provider": "openai",
		"name":     "openai-eco",
		"base_url": mockUpstream.URL + "/v1",
		"api_key":  "sk-openai-eco",
	})
	credReq, _ := http.NewRequest(http.MethodPost, "/admin/v1/credentials", bytes.NewReader(credBody))
	credReq.Header.Set("Authorization", "Bearer admin_secret_key")
	credReq.Header.Set("Content-Type", "application/json")
	credRec := httptest.NewRecorder()
	handler.ServeHTTP(credRec, credReq)
	require.Equal(t, http.StatusCreated, credRec.Code)
	_ = json.Unmarshal(credRec.Body.Bytes(), &cred)

	// 1. Text Completion Model
	textGM := &domain.GlobalModel{
		ID:                "openai/gpt-3.5-turbo-instruct",
		Provider:          domain.ProviderOpenAI,
		ModelName:         "gpt-3.5-turbo-instruct",
		SupportsInference: true,
		LifecycleStatus:   domain.ModelStatusActive,
		PricingStatus:     domain.PricingStatusVerified,
	}
	require.NoError(t, repo.UpsertGlobalModel(ctx, textGM))

	textMG := &domain.ModelGroup{
		ID:              "mg-text-completion",
		OrgID:           org.ID,
		Alias:           "gpt-3.5-turbo-instruct",
		RoutingStrategy: domain.StrategyWeightedShuffle,
		IsActive:        true,
	}
	require.NoError(t, repo.CreateModelGroup(ctx, textMG))

	textDep := &domain.Deployment{
		ID:             "dep-text-comp",
		ModelGroupID:   textMG.ID,
		GlobalModelID:  textGM.ID,
		CredentialID:   cred.ID,
		DeploymentName: "openai-text-1",
		Status:         domain.DeploymentStatusActive,
		GlobalModel:    textGM,
		Credential:     &cred,
	}
	require.NoError(t, repo.CreateDeployment(ctx, textDep))

	// 2. Chat Model (used for Anthropic messages translation)
	chatGM := &domain.GlobalModel{
		ID:                "openai/gpt-4.1-mini",
		Provider:          domain.ProviderOpenAI,
		ModelName:         "gpt-4.1-mini",
		SupportsInference: true,
		LifecycleStatus:   domain.ModelStatusActive,
		PricingStatus:     domain.PricingStatusVerified,
	}
	require.NoError(t, repo.UpsertGlobalModel(ctx, chatGM))

	chatMG := &domain.ModelGroup{
		ID:              "mg-chat-mini",
		OrgID:           org.ID,
		Alias:           "gpt-4.1-mini",
		RoutingStrategy: domain.StrategyWeightedShuffle,
		IsActive:        true,
	}
	require.NoError(t, repo.CreateModelGroup(ctx, chatMG))

	chatDep := &domain.Deployment{
		ID:             "dep-chat-mini",
		ModelGroupID:   chatMG.ID,
		GlobalModelID:  chatGM.ID,
		CredentialID:   cred.ID,
		DeploymentName: "openai-chat-1",
		Status:         domain.DeploymentStatusActive,
		GlobalModel:    chatGM,
		Credential:     &cred,
	}
	require.NoError(t, repo.CreateDeployment(ctx, chatDep))

	t.Run("TestCompletionsEndpoint", func(t *testing.T) {
		payload := map[string]any{
			"model":  "gpt-3.5-turbo-instruct",
			"prompt": "Complete this sentence:",
		}
		b, _ := json.Marshal(payload)
		req, _ := http.NewRequest(http.MethodPost, "/v1/completions", bytes.NewReader(b))
		req.Header.Set("Authorization", "Bearer "+issuedKey.RawKey)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		require.Equal(t, http.StatusOK, rec.Code, "Response: %s", rec.Body.String())
		var resp domain.CanonicalCompletionResponse
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
		assert.Equal(t, "cmpl-test-123", resp.ID)
		assert.Len(t, resp.Choices, 1)
		assert.Equal(t, "This is a completed sentence.", resp.Choices[0].Text)
		assert.Equal(t, 11, resp.Usage.TotalTokens)
	})

	t.Run("TestAnthropicMessagesSync", func(t *testing.T) {
		payload := map[string]any{
			"model": "gpt-4.1-mini",
			"messages": []map[string]any{
				{"role": "user", "content": "Hello via Anthropic SDK!"},
			},
			"max_tokens": 1024,
			"system":     "You are a helpful assistant.",
		}
		b, _ := json.Marshal(payload)
		req, _ := http.NewRequest(http.MethodPost, "/anthropic/v1/messages", bytes.NewReader(b))
		req.Header.Set("x-api-key", issuedKey.RawKey)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		require.Equal(t, http.StatusOK, rec.Code, "Response: %s", rec.Body.String())
		var antResp map[string]any
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &antResp))
		assert.True(t, strings.HasPrefix(antResp["id"].(string), "msg_"))
		assert.Equal(t, "message", antResp["type"])
		assert.Equal(t, "assistant", antResp["role"])
		assert.Equal(t, "end_turn", antResp["stop_reason"])

		content := antResp["content"].([]any)
		require.Len(t, content, 1)
		block := content[0].(map[string]any)
		assert.Equal(t, "text", block["type"])
		assert.Equal(t, "Hello from Claude bridge!", block["text"])
	})

	t.Run("TestAnthropicMessagesStreaming", func(t *testing.T) {
		payload := map[string]any{
			"model": "gpt-4.1-mini",
			"messages": []map[string]any{
				{"role": "user", "content": "Stream to me"},
			},
			"max_tokens": 1024,
			"stream":     true,
		}
		b, _ := json.Marshal(payload)
		req, _ := http.NewRequest(http.MethodPost, "/v1/messages", bytes.NewReader(b))
		req.Header.Set("x-api-key", issuedKey.RawKey)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)
		assert.Equal(t, "text/event-stream", rec.Header().Get("Content-Type"))
		body := rec.Body.String()
		assert.Contains(t, body, "event: message_start")
		assert.Contains(t, body, "event: content_block_start")
		assert.Contains(t, body, "event: content_block_delta")
		assert.Contains(t, body, "event: content_block_stop")
		assert.Contains(t, body, "event: message_delta")
		assert.Contains(t, body, "event: message_stop")
	})

	t.Run("TestTokenizeAndCountTokens", func(t *testing.T) {
		// 1. /v1/tokenize
		tokPayload := map[string]any{
			"model":  "gpt-4o",
			"prompt": "Hello world, this is tokenization test.",
		}
		b, _ := json.Marshal(tokPayload)
		req, _ := http.NewRequest(http.MethodPost, "/v1/tokenize", bytes.NewReader(b))
		req.Header.Set("Authorization", "Bearer "+issuedKey.RawKey)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		require.Equal(t, http.StatusOK, rec.Code)
		var tokResp map[string]any
		require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &tokResp))
		assert.Greater(t, tokResp["count"].(float64), 0.0)

		// 2. /anthropic/v1/messages/count_tokens
		antTokPayload := map[string]any{
			"model": "claude-3-7-sonnet",
			"messages": []map[string]any{
				{"role": "user", "content": "Testing Anthropic token counting."},
			},
		}
		b2, _ := json.Marshal(antTokPayload)
		req2, _ := http.NewRequest(http.MethodPost, "/anthropic/v1/messages/count_tokens", bytes.NewReader(b2))
		req2.Header.Set("x-api-key", issuedKey.RawKey)
		req2.Header.Set("Content-Type", "application/json")
		rec2 := httptest.NewRecorder()
		handler.ServeHTTP(rec2, req2)

		require.Equal(t, http.StatusOK, rec2.Code)
		var antTokResp map[string]any
		require.NoError(t, json.Unmarshal(rec2.Body.Bytes(), &antTokResp))
		assert.Greater(t, antTokResp["input_tokens"].(float64), 0.0)
	})
}
