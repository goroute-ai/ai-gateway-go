package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/server"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupCompatTestGateway(t *testing.T, upstreamHandler http.HandlerFunc) (*server.GatewayServer, *storage.MemoryRepository, string) {
	t.Helper()
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	cfg := config.Default()
	cfg.Auth.MasterAdminKey = "admin_secret_key"
	cfg.Security.Network.OutboundSSRF.AllowPrivateNetworks = true
	cfg.Security.Network.OutboundSSRF.AllowInsecureHTTP = true

	upstream := httptest.NewServer(upstreamHandler)
	t.Cleanup(upstream.Close)

	gw, err := server.New(cfg, repo, nil, upstream.Client())
	require.NoError(t, err)
	handler := gw.Handler()

	org := &domain.Organization{ID: "org-compat", Name: "Compat Org", Slug: "compat-org", IsActive: true}
	require.NoError(t, repo.CreateOrganization(ctx, org))

	var issuedKey domain.VirtualKey
	keyBody, _ := json.Marshal(map[string]any{"org_id": org.ID, "name": "compat-key"})
	keyReq, _ := http.NewRequest(http.MethodPost, "/admin/v1/keys", bytes.NewReader(keyBody))
	keyReq.Header.Set("Authorization", "Bearer admin_secret_key")
	keyReq.Header.Set("Content-Type", "application/json")
	keyRec := httptest.NewRecorder()
	handler.ServeHTTP(keyRec, keyReq)
	require.Equal(t, http.StatusCreated, keyRec.Code)
	require.NoError(t, json.Unmarshal(keyRec.Body.Bytes(), &issuedKey))

	var cred domain.ProviderCredential
	credBody, _ := json.Marshal(map[string]any{
		"org_id":   org.ID,
		"provider": "openai",
		"name":     "openai-compat",
		"base_url": upstream.URL + "/v1",
		"api_key":  "sk-openai-compat",
	})
	credReq, _ := http.NewRequest(http.MethodPost, "/admin/v1/credentials", bytes.NewReader(credBody))
	credReq.Header.Set("Authorization", "Bearer admin_secret_key")
	credReq.Header.Set("Content-Type", "application/json")
	credRec := httptest.NewRecorder()
	handler.ServeHTTP(credRec, credReq)
	require.Equal(t, http.StatusCreated, credRec.Code)
	require.NoError(t, json.Unmarshal(credRec.Body.Bytes(), &cred))

	chatGM := &domain.GlobalModel{
		ID:                "openai/gpt-4o",
		Provider:          domain.ProviderOpenAI,
		ModelName:         "gpt-4o",
		DisplayName:       "GPT-4o",
		SupportsInference: true,
		LifecycleStatus:   domain.ModelStatusActive,
		PricingStatus:     domain.PricingStatusVerified,
	}
	require.NoError(t, repo.UpsertGlobalModel(ctx, chatGM))
	require.NoError(t, repo.CreateModelGroup(ctx, &domain.ModelGroup{
		ID:              "mg-gpt-4o",
		OrgID:           org.ID,
		Alias:           "gpt-4o",
		RoutingStrategy: domain.StrategyWeightedShuffle,
		IsActive:        true,
	}))
	require.NoError(t, repo.CreateDeployment(ctx, &domain.Deployment{
		ID:             "dep-gpt-4o",
		ModelGroupID:   "mg-gpt-4o",
		GlobalModelID:  chatGM.ID,
		CredentialID:   cred.ID,
		DeploymentName: "openai-gpt-4o",
		Weight:         100,
	}))

	ttsGM := &domain.GlobalModel{
		ID:                "openai/tts-1",
		Provider:          domain.ProviderOpenAI,
		ModelName:         "tts-1",
		DisplayName:       "TTS-1",
		SupportsInference: true,
		LifecycleStatus:   domain.ModelStatusActive,
		PricingStatus:     domain.PricingStatusVerified,
		Capabilities: domain.ModelCapabilities{
			AudioTTS: domain.CapabilitySupported,
		},
	}
	require.NoError(t, repo.UpsertGlobalModel(ctx, ttsGM))
	require.NoError(t, repo.CreateModelGroup(ctx, &domain.ModelGroup{
		ID:              "mg-tts-1",
		OrgID:           org.ID,
		Alias:           "tts-1",
		RoutingStrategy: domain.StrategyWeightedShuffle,
		IsActive:        true,
	}))
	require.NoError(t, repo.CreateDeployment(ctx, &domain.Deployment{
		ID:             "dep-tts-1",
		ModelGroupID:   "mg-tts-1",
		GlobalModelID:  ttsGM.ID,
		CredentialID:   cred.ID,
		DeploymentName: "openai-tts-1",
		Weight:         100,
	}))

	return gw, repo, issuedKey.RawKey
}

func TestChatCompletions_ExtraBodyAndUnknownFieldsForwarded(t *testing.T) {
	var capturedBody map[string]any
	gw, _, apiKey := setupCompatTestGateway(t, func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/chat/completions", r.URL.Path)
		require.NoError(t, json.NewDecoder(r.Body).Decode(&capturedBody))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"id": "chatcmpl-extra",
			"object": "chat.completion",
			"created": 1700000000,
			"model": "gpt-4o",
			"choices": [{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],
			"usage": {"prompt_tokens":5,"completion_tokens":2,"total_tokens":7}
		}`))
	})

	reqBody := `{
		"model": "gpt-4o",
		"messages": [{"role":"user","content":"hi"}],
		"extra_body": {"seed": 42, "model": "should-not-clobber", "stream": true},
		"top_k": 50
	}`
	req, _ := http.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(reqBody))
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	gw.Handler().ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "gpt-4o", capturedBody["model"])
	assert.Nil(t, capturedBody["stream"])
	assert.Equal(t, float64(42), capturedBody["seed"])
	assert.Equal(t, float64(50), capturedBody["top_k"])
}

func TestAnthropicRoutes_ReturnAnthropicErrorEnvelope(t *testing.T) {
	gw, _, apiKey := setupCompatTestGateway(t, func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})
	handler := gw.Handler()

	paths := []string{
		"/v1/messages",
		"/messages",
		"/anthropic/v1/messages",
		"/v1/messages/count_tokens",
	}

	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			req, _ := http.NewRequest(http.MethodPost, path, strings.NewReader(`{invalid`))
			req.Header.Set("Authorization", "Bearer "+apiKey)
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			require.Equal(t, http.StatusBadRequest, rec.Code)
			var env domain.AnthropicErrorEnvelope
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &env))
			assert.Equal(t, "error", env.Type)
			require.NotNil(t, env.Error)
			assert.Equal(t, "invalid_request_error", env.Error.Type)
			assert.NotEmpty(t, env.Error.Message)
		})
	}
}

func TestAudioSpeech_StreamsIncrementallyWithFlusher(t *testing.T) {
	gw, repo, apiKey := setupCompatTestGateway(t, func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/audio/speech", r.URL.Path)
		w.Header().Set("Content-Type", "audio/mpeg")
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		_, _ = w.Write([]byte("chunk1-"))
		if flusher != nil {
			flusher.Flush()
		}
		_, _ = w.Write([]byte("chunk2"))
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	gw.StartWorkers(ctx)
	defer gw.Shutdown(context.Background())

	reqBody := `{"model":"tts-1","input":"hello streaming world","voice":"alloy"}`
	req, _ := http.NewRequest(http.MethodPost, "/v1/audio/speech", strings.NewReader(reqBody))
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	gw.Handler().ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.True(t, rec.Flushed, "expected ResponseWriter to be flushed during TTS streaming")
	assert.Equal(t, "chunk1-chunk2", rec.Body.String())

	// Allow async spend worker a brief moment to flush if needed
	time.Sleep(50 * time.Millisecond)
	logs, err := repo.ListSpendLogs(context.Background(), "org-compat", 10)
	require.NoError(t, err)
	assert.NotEmpty(t, logs)
}

func TestResponses_ToolsAndFunctionCallOutput(t *testing.T) {
	var capturedChat map[string]any
	gw, _, apiKey := setupCompatTestGateway(t, func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/v1/chat/completions", r.URL.Path)
		require.NoError(t, json.NewDecoder(r.Body).Decode(&capturedChat))
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"id": "chatcmpl-tools",
			"object": "chat.completion",
			"created": 1700000001,
			"model": "gpt-4o",
			"choices": [{
				"index": 0,
				"message": {
					"role": "assistant",
					"content": "",
					"tool_calls": [{
						"id": "call_weather_1",
						"type": "function",
						"function": {
							"name": "get_weather",
							"arguments": "{\"city\":\"Tokyo\"}"
						}
					}]
				},
				"finish_reason": "tool_calls"
			}],
			"usage": {"prompt_tokens": 12, "completion_tokens": 8, "total_tokens": 20}
		}`))
	})

	reqBody := `{
		"model": "gpt-4o",
		"input": "What is the weather in Tokyo?",
		"tools": [{
			"type": "function",
			"name": "get_weather",
			"description": "Get current weather",
			"parameters": {"type":"object","properties":{"city":{"type":"string"}}}
		}],
		"tool_choice": {"type": "function", "name": "get_weather"}
	}`
	req, _ := http.NewRequest(http.MethodPost, "/v1/responses", strings.NewReader(reqBody))
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	gw.Handler().ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	// Verify tools and normalized tool_choice reached the upstream ChatCompletions call
	tools, ok := capturedChat["tools"].([]any)
	require.True(t, ok)
	require.Len(t, tools, 1)
	toolChoice, ok := capturedChat["tool_choice"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "function", toolChoice["type"])

	// Verify function_call output item in Responses output
	var out domain.CanonicalResponseOutput
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &out))
	require.Len(t, out.Output, 1)
	assert.Equal(t, "function_call", out.Output[0].Type)
	assert.Equal(t, "call_weather_1", out.Output[0].CallID)
	assert.Equal(t, "get_weather", out.Output[0].Name)
	assert.Equal(t, `{"city":"Tokyo"}`, out.Output[0].Arguments)
}
