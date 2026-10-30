package a2a_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/a2a"
	"github.com/goroute-ai/ai-gateway-go/internal/a2a/pb"
	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
)

func setupOpenAIBridgeTest(t *testing.T, upstreamHandler http.HandlerFunc) (*a2a.OpenAIBridge, storage.Repository, *httptest.Server) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	vault, err := auth.NewVault("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	require.NoError(t, err)
	rbac := auth.NewRBACEngine(repo)

	netPolicy, err := network.NewPolicy(config.OutboundSSRFConfig{
		AllowPrivateNetworks: true,
		AllowInsecureHTTP:    true,
	})
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
	streams := a2a.NewStreamSubscriber(repo, redisFabric)

	bridge := a2a.NewOpenAIBridge(router, streams, repo, rbac)
	return bridge, repo, mockServer
}

func TestOpenAIBridge_SyncCompletion(t *testing.T) {
	bridge, _, mockServer := setupOpenAIBridgeTest(t, func(w http.ResponseWriter, r *http.Request) {
		taskResp := &pb.SendMessageResponse{
			Payload: &pb.SendMessageResponse_Task{
				Task: &pb.Task{
					Id:        "task_100",
					ContextId: "ctx_200",
					Status: &pb.TaskStatus{
						State: pb.TaskState_TASK_STATE_COMPLETED,
						Message: &pb.Message{
							Role: pb.Role_ROLE_AGENT,
							Parts: []*pb.Part{
								{
									Content: &pb.Part_Text{
										Text: "Code review passed: LGTM!",
									},
								},
							},
						},
					},
				},
			},
		}
		out, _ := protojson.Marshal(taskResp)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(out)
	})
	defer mockServer.Close()

	idCtx := &domain.IdentityContext{
		OrgID:                "org_test",
		VirtualKeyID:         "vk_dev",
		KeyPrefix:            "sk-gw-test",
		KeyAllowedA2AAgents:  []string{"code-reviewer"},
		TeamAllowedA2AAgents: nil,
	}

	chatReq := &domain.CanonicalChatRequest{
		Model: "a2a/code-reviewer",
		Messages: []domain.CanonicalMessage{
			{Role: "system", Content: "You are a senior reviewer"},
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
		var taskResp *pb.SendMessageResponse
		if callCount == 1 {
			// First turn: ask for user approval
			taskResp = &pb.SendMessageResponse{
				Payload: &pb.SendMessageResponse_Task{
					Task: &pb.Task{
						Id:        "task_approval_1",
						ContextId: "ctx_approval_1",
						Status: &pb.TaskStatus{
							State: pb.TaskState_TASK_STATE_INPUT_REQUIRED,
							Message: &pb.Message{
								Role: pb.Role_ROLE_AGENT,
								Parts: []*pb.Part{
									{
										Content: &pb.Part_Text{
											Text: "Do you approve deploying to prod? (yes/no)",
										},
									},
								},
							},
						},
					},
				},
			}
		} else {
			// Second turn: task completed
			taskResp = &pb.SendMessageResponse{
				Payload: &pb.SendMessageResponse_Task{
					Task: &pb.Task{
						Id:        "task_approval_1",
						ContextId: "ctx_approval_1",
						Status: &pb.TaskStatus{
							State: pb.TaskState_TASK_STATE_COMPLETED,
							Message: &pb.Message{
								Role: pb.Role_ROLE_AGENT,
								Parts: []*pb.Part{
									{
										Content: &pb.Part_Text{
											Text: "Deployment to prod executed successfully.",
										},
									},
								},
							},
						},
					},
				},
			}
		}
		out, _ := protojson.Marshal(taskResp)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(out)
	})
	defer mockServer.Close()

	idCtx := &domain.IdentityContext{
		OrgID:                "org_test",
		VirtualKeyID:         "vk_dev",
		KeyPrefix:            "sk-gw-test",
		KeyAllowedA2AAgents:  []string{"code-reviewer"},
		TeamAllowedA2AAgents: nil,
	}

	// Turn 1: Trigger input_required
	chatReq1 := &domain.CanonicalChatRequest{
		Model: "a2a/code-reviewer",
		Messages: []domain.CanonicalMessage{
			{Role: "user", Content: "Deploy build 891"},
		},
	}
	req1 := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	w1 := httptest.NewRecorder()
	bridge.HandleChatCompletion(w1, req1, idCtx, "code-reviewer", chatReq1)

	require.Equal(t, http.StatusOK, w1.Code)
	assignedTaskID := w1.Header().Get("X-Gateway-A2A-Task-Id")
	require.NotEmpty(t, assignedTaskID)
	assert.Equal(t, "input_required", w1.Header().Get("X-Gateway-A2A-Task-State"))

	var compResp1 map[string]any
	require.NoError(t, json.Unmarshal(w1.Body.Bytes(), &compResp1))
	gorouteExt1 := compResp1["goroute_a2a"].(map[string]any)
	assert.Equal(t, "input_required", gorouteExt1["task_state"])

	// Turn 2: Resume with task_id and context_id via GoRouteExtensions
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
	req2 := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	w2 := httptest.NewRecorder()
	bridge.HandleChatCompletion(w2, req2, idCtx, "code-reviewer", chatReq2)

	require.Equal(t, http.StatusOK, w2.Code)
	assert.Equal(t, "completed", w2.Header().Get("X-Gateway-A2A-Task-State"))
	var compResp2 map[string]any
	require.NoError(t, json.Unmarshal(w2.Body.Bytes(), &compResp2))
	choice2 := compResp2["choices"].([]any)[0].(map[string]any)
	msg2 := choice2["message"].(map[string]any)
	assert.Contains(t, msg2["content"], "Deployment to prod executed successfully.")
}

func TestOpenAIBridge_StreamingCompletion(t *testing.T) {
	bridge, _, mockServer := setupOpenAIBridgeTest(t, func(w http.ResponseWriter, r *http.Request) {
		taskResp := &pb.SendMessageResponse{
			Payload: &pb.SendMessageResponse_Task{
				Task: &pb.Task{
					Id:        "task_stream_1",
					ContextId: "ctx_stream_1",
					Status: &pb.TaskStatus{
						State: pb.TaskState_TASK_STATE_COMPLETED,
						Message: &pb.Message{
							Role: pb.Role_ROLE_AGENT,
							Parts: []*pb.Part{
								{
									Content: &pb.Part_Text{
										Text: "Streaming agent test output",
									},
								},
							},
						},
					},
				},
			},
		}
		out, _ := protojson.Marshal(taskResp)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(out)
	})
	defer mockServer.Close()

	idCtx := &domain.IdentityContext{
		OrgID:                "org_test",
		VirtualKeyID:         "vk_dev",
		KeyPrefix:            "sk-gw-test",
		KeyAllowedA2AAgents:  []string{"code-reviewer"},
		TeamAllowedA2AAgents: nil,
	}

	chatReq := &domain.CanonicalChatRequest{
		Model:  "a2a/code-reviewer",
		Stream: true,
		Messages: []domain.CanonicalMessage{
			{Role: "user", Content: "Stream me something"},
		},
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	w := httptest.NewRecorder()

	bridge.HandleChatCompletion(w, req, idCtx, "code-reviewer", chatReq)

	require.Equal(t, http.StatusOK, w.Code)
	assert.Contains(t, w.Header().Get("Content-Type"), "text/event-stream")

	body := w.Body.String()
	assert.Contains(t, body, "data: [DONE]")
	assert.Contains(t, body, "Streaming")
	assert.Contains(t, body, "agent")
	assert.Contains(t, body, "ctx_stream_1")
}

func TestOpenAIBridge_TerminalFailure(t *testing.T) {
	bridge, _, mockServer := setupOpenAIBridgeTest(t, func(w http.ResponseWriter, r *http.Request) {
		taskResp := &pb.SendMessageResponse{
			Payload: &pb.SendMessageResponse_Task{
				Task: &pb.Task{
					Id:        "task_fail_1",
					ContextId: "ctx_fail_1",
					Status: &pb.TaskStatus{
						State: pb.TaskState_TASK_STATE_FAILED,
					},
				},
			},
		}
		out, _ := protojson.Marshal(taskResp)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(out)
	})
	defer mockServer.Close()

	idCtx := &domain.IdentityContext{
		OrgID:                "org_test",
		VirtualKeyID:         "vk_dev",
		KeyPrefix:            "sk-gw-test",
		KeyAllowedA2AAgents:  []string{"code-reviewer"},
		TeamAllowedA2AAgents: nil,
	}

	chatReq := &domain.CanonicalChatRequest{
		Model: "a2a/code-reviewer",
		Messages: []domain.CanonicalMessage{
			{Role: "user", Content: "Will fail"},
		},
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	w := httptest.NewRecorder()

	bridge.HandleChatCompletion(w, req, idCtx, "code-reviewer", chatReq)

	// Must fail with HTTP 502 / bad gateway, NEVER finish_reason: stop
	assert.Equal(t, http.StatusBadGateway, w.Code)
	var errResp map[string]any
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &errResp))
	errObj := errResp["error"].(map[string]any)
	assert.Equal(t, "a2a_task_failed", errObj["code"])
}
