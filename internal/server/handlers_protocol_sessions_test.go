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
	"time"

	"github.com/google/uuid"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/server"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"nhooyr.io/websocket"
)

func TestPhase6_ResponsesAPI(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	cfg := config.Default()
	cfg.Auth.MasterAdminKey = "admin_secret_key"
	cfg.Security.Network.OutboundSSRF.AllowPrivateNetworks = true
	cfg.Security.Network.OutboundSSRF.AllowInsecureHTTP = true

	mockOAI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/chat/completions") {
			var chatReq domain.CanonicalChatRequest
			_ = json.NewDecoder(r.Body).Decode(&chatReq)
			if chatReq.Stream {
				w.Header().Set("Content-Type", "text/event-stream")
				flusher, _ := w.(http.Flusher)
				chunk := map[string]any{
					"id":      "chatcmpl-stream-" + uuid.NewString(),
					"object":  "chat.completion.chunk",
					"created": time.Now().Unix(),
					"model":   "gpt-4.1-mini",
					"choices": []map[string]any{
						{
							"index": 0,
							"delta": map[string]any{
								"role":    "assistant",
								"content": "Four",
							},
						},
					},
				}
				b, _ := json.Marshal(chunk)
				fmt.Fprintf(w, "data: %s\n\n", string(b))
				flusher.Flush()
				fmt.Fprintf(w, "data: [DONE]\n\n")
				flusher.Flush()
				return
			}

			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":      "chatcmpl-" + uuid.NewString(),
				"object":  "chat.completion",
				"created": time.Now().Unix(),
				"model":   "gpt-4.1-mini",
				"choices": []map[string]any{
					{
						"index": 0,
						"message": map[string]any{
							"role":    "assistant",
							"content": "Four",
						},
						"finish_reason": "stop",
					},
				},
				"usage": map[string]any{
					"prompt_tokens":     15,
					"completion_tokens": 5,
					"total_tokens":      20,
				},
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer mockOAI.Close()

	gw, err := server.New(cfg, repo, nil, mockOAI.Client())
	require.NoError(t, err)
	handler := gw.Handler()

	org := &domain.Organization{ID: "org-responses", Name: "Responses Org", Slug: "responses-org", IsActive: true}
	require.NoError(t, repo.CreateOrganization(ctx, org))

	// Issue Virtual Key
	var issuedKey domain.VirtualKey
	keyBody, _ := json.Marshal(map[string]any{
		"org_id": org.ID,
		"name":   "responses-key",
	})
	keyReq, _ := http.NewRequest(http.MethodPost, "/admin/v1/keys", bytes.NewReader(keyBody))
	keyReq.Header.Set("Authorization", "Bearer admin_secret_key")
	keyReq.Header.Set("Content-Type", "application/json")
	keyRec := httptest.NewRecorder()
	handler.ServeHTTP(keyRec, keyReq)
	require.Equal(t, http.StatusCreated, keyRec.Code)
	_ = json.Unmarshal(keyRec.Body.Bytes(), &issuedKey)
	require.NotEmpty(t, issuedKey.RawKey)

	// Create Credential
	var cred domain.ProviderCredential
	credBody, _ := json.Marshal(map[string]any{
		"org_id":   org.ID,
		"provider": "openai",
		"name":     "openai-responses",
		"base_url": mockOAI.URL + "/v1",
		"api_key":  "sk-openai-key",
	})
	credReq, _ := http.NewRequest(http.MethodPost, "/admin/v1/credentials", bytes.NewReader(credBody))
	credReq.Header.Set("Authorization", "Bearer admin_secret_key")
	credReq.Header.Set("Content-Type", "application/json")
	credRec := httptest.NewRecorder()
	handler.ServeHTTP(credRec, credReq)
	require.Equal(t, http.StatusCreated, credRec.Code)
	_ = json.Unmarshal(credRec.Body.Bytes(), &cred)

	// Model setup
	gm := &domain.GlobalModel{
		ID:                "openai/gpt-4.1-mini",
		Provider:          domain.ProviderOpenAI,
		ModelName:         "gpt-4.1-mini",
		SupportsInference: true,
		LifecycleStatus:   domain.ModelStatusActive,
		PricingStatus:     domain.PricingStatusVerified,
	}
	require.NoError(t, repo.UpsertGlobalModel(ctx, gm))

	mg := &domain.ModelGroup{
		ID:              "mg-responses-mini",
		OrgID:           org.ID,
		Alias:           "gpt-4.1-mini",
		RoutingStrategy: domain.StrategyWeightedShuffle,
		IsActive:        true,
	}
	require.NoError(t, repo.CreateModelGroup(ctx, mg))

	dep := &domain.Deployment{
		ID:             "dep-responses-mini",
		ModelGroupID:   mg.ID,
		GlobalModelID:  gm.ID,
		CredentialID:   cred.ID,
		DeploymentName: "openai-responses-1",
		Status:         domain.DeploymentStatusActive,
		GlobalModel:    gm,
		Credential:     &cred,
	}
	require.NoError(t, repo.CreateDeployment(ctx, dep))

	dataHeaders := map[string]string{
		"Authorization": "Bearer " + issuedKey.RawKey,
		"Content-Type":  "application/json",
	}

	t.Run("NonStreaming_V1Responses", func(t *testing.T) {
		reqBody := `{
			"model": "gpt-4.1-mini",
			"instructions": "Answer concisely",
			"input": "What is 2+2?",
			"stream": false
		}`
		rec := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodPost, "/v1/responses", bytes.NewReader([]byte(reqBody)))
		for k, v := range dataHeaders {
			req.Header.Set(k, v)
		}
		handler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)

		var out domain.CanonicalResponseOutput
		err := json.Unmarshal(rec.Body.Bytes(), &out)
		require.NoError(t, err)
		assert.True(t, strings.HasPrefix(out.ID, "resp_"))
		assert.Equal(t, "response", out.Object)
		assert.Equal(t, "completed", out.Status)
		require.Len(t, out.Output, 1)
		assert.Equal(t, "message", out.Output[0].Type)
		assert.Equal(t, "assistant", out.Output[0].Role)
		require.Len(t, out.Output[0].Content, 1)
		assert.Equal(t, "output_text", out.Output[0].Content[0].Type)
		assert.Equal(t, "Four", out.Output[0].Content[0].Text)
	})

	t.Run("Streaming_ResponsesAlias", func(t *testing.T) {
		reqBody := `{
			"model": "gpt-4.1-mini",
			"input": "Calculate 2+2",
			"stream": true
		}`
		rec := httptest.NewRecorder()
		req, _ := http.NewRequest(http.MethodPost, "/responses", bytes.NewReader([]byte(reqBody)))
		for k, v := range dataHeaders {
			req.Header.Set(k, v)
		}
		handler.ServeHTTP(rec, req)
		assert.Equal(t, http.StatusOK, rec.Code)

		rawResp := rec.Body.String()
		assert.Contains(t, rawResp, "event: response.created")
		assert.Contains(t, rawResp, "event: response.output_item.added")
		assert.Contains(t, rawResp, "event: response.content_part.added")
		assert.Contains(t, rawResp, "event: response.output_text.delta")
		assert.Contains(t, rawResp, "event: response.output_text.done")
		assert.Contains(t, rawResp, "event: response.completed")
		assert.Contains(t, rawResp, "event: response.done")
	})
}

func TestPhase6_RealtimeWebSocket(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	cfg := config.Default()
	cfg.Auth.MasterAdminKey = "admin_secret_key"
	cfg.Security.Network.OutboundSSRF.AllowPrivateNetworks = true
	cfg.Security.Network.OutboundSSRF.AllowInsecureHTTP = true

	mockOAI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/chat/completions") {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"id":      "chatcmpl-" + uuid.NewString(),
				"object":  "chat.completion",
				"created": time.Now().Unix(),
				"model":   "gpt-4.1-mini",
				"choices": []map[string]any{
					{
						"index": 0,
						"message": map[string]any{
							"role":    "assistant",
							"content": "Hello! I am ready.",
						},
						"finish_reason": "stop",
					},
				},
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer mockOAI.Close()

	gw, err := server.New(cfg, repo, nil, mockOAI.Client())
	require.NoError(t, err)
	handler := gw.Handler()

	org := &domain.Organization{ID: "org-realtime", Name: "Realtime Org", Slug: "realtime-org", IsActive: true}
	require.NoError(t, repo.CreateOrganization(ctx, org))

	var issuedKey domain.VirtualKey
	keyBody, _ := json.Marshal(map[string]any{
		"org_id": org.ID,
		"name":   "realtime-key",
	})
	keyReq, _ := http.NewRequest(http.MethodPost, "/admin/v1/keys", bytes.NewReader(keyBody))
	keyReq.Header.Set("Authorization", "Bearer admin_secret_key")
	keyReq.Header.Set("Content-Type", "application/json")
	keyRec := httptest.NewRecorder()
	handler.ServeHTTP(keyRec, keyReq)
	require.Equal(t, http.StatusCreated, keyRec.Code)
	_ = json.Unmarshal(keyRec.Body.Bytes(), &issuedKey)
	require.NotEmpty(t, issuedKey.RawKey)

	var cred domain.ProviderCredential
	credBody, _ := json.Marshal(map[string]any{
		"org_id":   org.ID,
		"provider": "openai",
		"name":     "openai-rt",
		"base_url": mockOAI.URL + "/v1",
		"api_key":  "sk-openai-rt",
	})
	credReq, _ := http.NewRequest(http.MethodPost, "/admin/v1/credentials", bytes.NewReader(credBody))
	credReq.Header.Set("Authorization", "Bearer admin_secret_key")
	credReq.Header.Set("Content-Type", "application/json")
	credRec := httptest.NewRecorder()
	handler.ServeHTTP(credRec, credReq)
	require.Equal(t, http.StatusCreated, credRec.Code)
	_ = json.Unmarshal(credRec.Body.Bytes(), &cred)

	gm := &domain.GlobalModel{
		ID:                "openai/gpt-4.1-mini",
		Provider:          domain.ProviderOpenAI,
		ModelName:         "gpt-4.1-mini",
		SupportsInference: true,
		LifecycleStatus:   domain.ModelStatusActive,
		PricingStatus:     domain.PricingStatusVerified,
	}
	require.NoError(t, repo.UpsertGlobalModel(ctx, gm))

	mg := &domain.ModelGroup{
		ID:              "mg-rt-mini",
		OrgID:           org.ID,
		Alias:           "gpt-4.1-mini",
		RoutingStrategy: domain.StrategyWeightedShuffle,
		IsActive:        true,
	}
	require.NoError(t, repo.CreateModelGroup(ctx, mg))

	dep := &domain.Deployment{
		ID:             "dep-rt-mini",
		ModelGroupID:   mg.ID,
		GlobalModelID:  gm.ID,
		CredentialID:   cred.ID,
		DeploymentName: "openai-rt-1",
		Status:         domain.DeploymentStatusActive,
		GlobalModel:    gm,
		Credential:     &cred,
	}
	require.NoError(t, repo.CreateDeployment(ctx, dep))

	// Start real HTTP test server with gw.Handler() to enable WebSocket upgrading
	ts := httptest.NewServer(handler)
	defer ts.Close()

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "/v1/realtime?model=gpt-4.1-mini"

	wsCtx, wsCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer wsCancel()

	conn, _, err := websocket.Dial(wsCtx, wsURL, &websocket.DialOptions{
		Subprotocols: []string{"realtime"},
		HTTPHeader: http.Header{
			"Authorization": []string{"Bearer " + issuedKey.RawKey},
		},
	})
	require.NoError(t, err)
	defer conn.Close(websocket.StatusNormalClosure, "test done")

	// 1. Read initial session.created
	_, data, err := conn.Read(wsCtx)
	require.NoError(t, err)
	var scEv map[string]any
	err = json.Unmarshal(data, &scEv)
	require.NoError(t, err)
	assert.Equal(t, "session.created", scEv["type"])

	// 2. Send session.update
	updMsg := map[string]any{
		"type": "session.update",
		"session": map[string]any{
			"voice": "shimmer",
		},
	}
	updBytes, _ := json.Marshal(updMsg)
	err = conn.Write(wsCtx, websocket.MessageText, updBytes)
	require.NoError(t, err)

	// Read session.updated
	_, data, err = conn.Read(wsCtx)
	require.NoError(t, err)
	var suEv map[string]any
	err = json.Unmarshal(data, &suEv)
	require.NoError(t, err)
	assert.Equal(t, "session.updated", suEv["type"])

	// 3. Send conversation.item.create
	itemMsg := map[string]any{
		"type": "conversation.item.create",
		"item": map[string]any{
			"type": "message",
			"role": "user",
			"content": []map[string]any{
				{
					"type": "input_text",
					"text": "Hello, assistant!",
				},
			},
		},
	}
	itemBytes, _ := json.Marshal(itemMsg)
	err = conn.Write(wsCtx, websocket.MessageText, itemBytes)
	require.NoError(t, err)

	// Read conversation.item.created
	_, data, err = conn.Read(wsCtx)
	require.NoError(t, err)
	var cicEv map[string]any
	err = json.Unmarshal(data, &cicEv)
	require.NoError(t, err)
	assert.Equal(t, "conversation.item.created", cicEv["type"])

	// 4. Send response.create
	respMsg := map[string]any{
		"type": "response.create",
	}
	respBytes, _ := json.Marshal(respMsg)
	err = conn.Write(wsCtx, websocket.MessageText, respBytes)
	require.NoError(t, err)

	// Read response sequence
	receivedTypes := make([]string, 0)
	for len(receivedTypes) < 7 {
		_, data, err = conn.Read(wsCtx)
		require.NoError(t, err)
		var ev map[string]any
		_ = json.Unmarshal(data, &ev)
		tStr, _ := ev["type"].(string)
		receivedTypes = append(receivedTypes, tStr)
		if tStr == "response.done" {
			break
		}
	}

	assert.Contains(t, receivedTypes, "response.created")
	assert.Contains(t, receivedTypes, "response.output_item.added")
	assert.Contains(t, receivedTypes, "response.content_part.added")
	assert.Contains(t, receivedTypes, "response.text.delta")
	assert.Contains(t, receivedTypes, "response.text.done")
	assert.Contains(t, receivedTypes, "response.output_item.done")
	assert.Contains(t, receivedTypes, "response.done")
}
