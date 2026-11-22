package a2a_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/a2a"
	a2aspec "github.com/goroute-ai/ai-gateway-go/internal/a2a/spec"
	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func setupOpenAIBridgeTest(t *testing.T, upstreamHandler http.HandlerFunc) (*a2a.OpenAIBridge, storage.Repository, *httptest.Server) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	vault, err := auth.NewVault("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	require.NoError(t, err)
	rbac := auth.NewRBACEngine(repo)

	netPolicy, err := network.NewPolicy(config.OutboundSSRFConfig{AllowPrivateNetworks: true, AllowInsecureHTTP: true})
	require.NoError(t, err)

	mockServer := httptest.NewServer(upstreamHandler)

	agent := &domain.A2AAgent{
		ID:                 "agent_code_reviewer",
		OrgID:              "org_test",
		Name:               "Code Reviewer",
		Slug:               "code-reviewer",
		EndpointURL:        mockServer.URL,
		AuthType:           "none",
		TaskVisibilityMode: domain.TaskVisibilityKeyStrict,
		IsActive:           true,
	}
	require.NoError(t, repo.CreateA2AAgent(ctx, agent))

	redisFabric := storage.NewRedisFabric("localhost:6379", "", 0)
	signer := a2a.NewGatewayCardSigner("key_1", "ES256", nil, vault)
	verifier := a2a.NewUpstreamCardVerifier(nil)
	router := a2a.NewRouterService(repo, vault, rbac, netPolicy, redisFabric, signer, verifier)
	streams := a2a.NewStreamSubscriber(repo, rbac, redisFabric, 128)

	bridge := a2a.NewOpenAIBridge(router, streams, repo, rbac)
	return bridge, repo, mockServer
}

func TestOpenAIBridge_SyncCompletion(t *testing.T) {
	bridge, _, mockServer := setupOpenAIBridgeTest(t, func(w http.ResponseWriter, r *http.Request) {
		ctxID := "ctx_200"
		taskResp := a2aspec.NewSendMessageResponseTask(&a2aspec.Task{
			Id:        "task_100",
			ContextId: &ctxID,
			Status: a2aspec.TaskStatus{
				State: a2aspec.TASKSTATECOMPLETED,
				Message: &a2aspec.Message{
					MessageId: "m_up_1",
					Role:      a2aspec.ROLEAGENT,
					Parts:     []a2aspec.Part{a2aspec.NewTextPart("Code review passed: LGTM!")},
				},
			},
		})
		out, _ := json.Marshal(taskResp)
		w.Header().Set("Content-Type", a2a.MediaTypeA2AJSON)
		_, _ = w.Write(out)
	})
	defer mockServer.Close()

	idCtx := &domain.IdentityContext{
		OrgID:               "org_test",
		VirtualKeyID:        "vk_dev",
		KeyPrefix:           "sk-gw-test",
		KeyAllowedA2AAgents: []string{"code-reviewer"},
	}

	chatReq := &domain.CanonicalChatRequest{
		Model: "a2a/code-reviewer",
		Messages: []domain.CanonicalMessage{
			{Role: "system", Content: "You are a senior reviewer"},
			{Role: "user", Content: "First check"},
			{Role: "assistant", Content: "Checked formatting"},
			{Role: "user", Content: "Please review PR #42"},
		},
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	w := httptest.NewRecorder()

	bridge.HandleChatCompletion(w, req, idCtx, "code-reviewer", chatReq)

	require.Equal(t, http.StatusOK, w.Code)
	assert.True(t, strings.HasPrefix(w.Header().Get("X-Gateway-A2A-Task-Id"), "task_"))
	assert.Equal(t, "ctx_200", w.Header().Get("X-Gateway-A2A-Context-Id"))
	assert.Equal(t, "completed", w.Header().Get("X-Gateway-A2A-Task-State"))

	var compResp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &compResp))
	choices := compResp["choices"].([]any)
	require.Len(t, choices, 1)
	choice := choices[0].(map[string]any)
	assert.Equal(t, "stop", choice["finish_reason"])
	msg := choice["message"].(map[string]any)
	assert.Equal(t, "Code review passed: LGTM!", msg["content"])

	gorouteExt := compResp["goroute_a2a"].(map[string]any)
	assert.True(t, strings.HasPrefix(gorouteExt["task_id"].(string), "task_"))
	assert.Equal(t, "ctx_200", gorouteExt["context_id"])
	assert.Equal(t, "completed", gorouteExt["task_state"])
}

func TestOpenAIBridge_InputRequiredAndResumption(t *testing.T) {
	callCount := 0
	bridge, _, mockServer := setupOpenAIBridgeTest(t, func(w http.ResponseWriter, r *http.Request) {
		callCount++
		ctxID := "ctx_approval_1"
		var taskResp *a2aspec.SendMessageResponse
		if callCount == 1 {
			taskResp = a2aspec.NewSendMessageResponseTask(&a2aspec.Task{
				Id:        "task_approval_1",
				ContextId: &ctxID,
				Status: a2aspec.TaskStatus{
					State: a2aspec.TASKSTATEINPUTREQUIRED,
					Message: &a2aspec.Message{
						MessageId: "m_ask",
						Role:      a2aspec.ROLEAGENT,
						Parts:     []a2aspec.Part{a2aspec.NewTextPart("Do you approve deploying to prod? (yes/no)")},
					},
				},
			})
		} else {
			taskResp = a2aspec.NewSendMessageResponseTask(&a2aspec.Task{
				Id:        "task_approval_1",
				ContextId: &ctxID,
				Status: a2aspec.TaskStatus{
					State: a2aspec.TASKSTATECOMPLETED,
					Message: &a2aspec.Message{
						MessageId: "m_done",
						Role:      a2aspec.ROLEAGENT,
						Parts:     []a2aspec.Part{a2aspec.NewTextPart("Deployment to prod executed successfully.")},
					},
				},
			})
		}
		out, _ := json.Marshal(taskResp)
		w.Header().Set("Content-Type", a2a.MediaTypeA2AJSON)
		_, _ = w.Write(out)
	})
	defer mockServer.Close()

	idCtx := &domain.IdentityContext{
		OrgID:               "org_test",
		VirtualKeyID:        "vk_dev",
		KeyPrefix:           "sk-gw-test",
		KeyAllowedA2AAgents: []string{"code-reviewer"},
	}

	chatReq1 := &domain.CanonicalChatRequest{
		Model: "a2a/code-reviewer",
		Messages: []domain.CanonicalMessage{
			{Role: "user", Content: "Deploy build 891"},
		},
	}
	w1 := httptest.NewRecorder()
	bridge.HandleChatCompletion(w1, httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil), idCtx, "code-reviewer", chatReq1)

	require.Equal(t, http.StatusOK, w1.Code)
	assignedTaskID := w1.Header().Get("X-Gateway-A2A-Task-Id")
	require.NotEmpty(t, assignedTaskID)
	assert.Equal(t, "input_required", w1.Header().Get("X-Gateway-A2A-Task-State"))

	chatReq2 := &domain.CanonicalChatRequest{
		Model: "a2a/code-reviewer",
		Messages: []domain.CanonicalMessage{
			{Role: "user", Content: "yes, proceed"},
		},
		GoRouteExtensions: &domain.GoRouteExtensions{
			TaskID:    assignedTaskID,
			ContextID: "ctx_approval_1",
		},
	}
	w2 := httptest.NewRecorder()
	bridge.HandleChatCompletion(w2, httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil), idCtx, "code-reviewer", chatReq2)

	require.Equal(t, http.StatusOK, w2.Code)
	assert.Equal(t, "completed", w2.Header().Get("X-Gateway-A2A-Task-State"))
	var compResp2 map[string]any
	require.NoError(t, json.Unmarshal(w2.Body.Bytes(), &compResp2))
	choice2 := compResp2["choices"].([]any)[0].(map[string]any)
	msg2 := choice2["message"].(map[string]any)
	assert.Contains(t, msg2["content"], "Deployment to prod executed successfully.")
}

func TestOpenAIBridge_StreamingCompletion_PreservesWhitespaceAndHeader(t *testing.T) {
	bridge, _, mockServer := setupOpenAIBridgeTest(t, func(w http.ResponseWriter, r *http.Request) {
		ctxID := "ctx_stream_1"
		taskResp := a2aspec.NewSendMessageResponseTask(&a2aspec.Task{
			Id:        "task_stream_1",
			ContextId: &ctxID,
			Status: a2aspec.TaskStatus{
				State: a2aspec.TASKSTATECOMPLETED,
				Message: &a2aspec.Message{
					MessageId: "m_s_1",
					Role:      a2aspec.ROLEAGENT,
					Parts:     []a2aspec.Part{a2aspec.NewTextPart("Line 1\n  Indented line 2")},
				},
			},
		})
		out, _ := json.Marshal(taskResp)
		w.Header().Set("Content-Type", a2a.MediaTypeA2AJSON)
		_, _ = w.Write(out)
	})
	defer mockServer.Close()

	idCtx := &domain.IdentityContext{
		OrgID:               "org_test",
		VirtualKeyID:        "vk_dev",
		KeyPrefix:           "sk-gw-test",
		KeyAllowedA2AAgents: []string{"code-reviewer"},
	}

	chatReq := &domain.CanonicalChatRequest{
		Model:  "a2a/code-reviewer",
		Stream: true,
		Messages: []domain.CanonicalMessage{
			{Role: "user", Content: "Stream me something"},
		},
	}

	w := httptest.NewRecorder()
	bridge.HandleChatCompletion(w, httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil), idCtx, "code-reviewer", chatReq)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "text/event-stream")
	// M4.1 fix: X-Gateway-A2A-Task-Id must be non-empty even on new streamed task!
	assert.NotEmpty(t, w.Header().Get("X-Gateway-A2A-Task-Id"))
	assert.Equal(t, "ctx_stream_1", w.Header().Get("X-Gateway-A2A-Context-Id"))

	body := w.Body.String()
	assert.Contains(t, body, "data: [DONE]")
	// M4.2 fix: newlines & indentation must be preserved cleanly inside delta.content!
	assert.Contains(t, body, `Line 1\n  Indented line 2`)
}

func TestOpenAIBridge_TerminalFailure(t *testing.T) {
	bridge, _, mockServer := setupOpenAIBridgeTest(t, func(w http.ResponseWriter, r *http.Request) {
		ctxID := "ctx_fail_1"
		taskResp := a2aspec.NewSendMessageResponseTask(&a2aspec.Task{
			Id:        "task_fail_1",
			ContextId: &ctxID,
			Status:    a2aspec.TaskStatus{State: a2aspec.TASKSTATEFAILED},
		})
		out, _ := json.Marshal(taskResp)
		w.Header().Set("Content-Type", a2a.MediaTypeA2AJSON)
		_, _ = w.Write(out)
	})
	defer mockServer.Close()

	idCtx := &domain.IdentityContext{
		OrgID:               "org_test",
		VirtualKeyID:        "vk_dev",
		KeyPrefix:           "sk-gw-test",
		KeyAllowedA2AAgents: []string{"code-reviewer"},
	}

	chatReq := &domain.CanonicalChatRequest{
		Model:    "a2a/code-reviewer",
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "Will fail"}},
	}

	w := httptest.NewRecorder()
	bridge.HandleChatCompletion(w, httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil), idCtx, "code-reviewer", chatReq)

	assert.Equal(t, http.StatusBadGateway, w.Code)
	var errResp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &errResp))
	errObj := errResp["error"].(map[string]any)
	assert.Equal(t, "a2a_task_failed", errObj["code"])
}
