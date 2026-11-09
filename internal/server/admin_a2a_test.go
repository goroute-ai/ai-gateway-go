package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/a2a"
	"github.com/goroute-ai/ai-gateway-go/internal/a2a/pb"
	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/server"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAdminA2AAgentManagementAndKillSwitch(t *testing.T) {
	repo := storage.NewMemoryRepository()
	cfg := config.Default()
	cfg.Auth.MasterAdminKey = "sk-gw-master-admin-key"
	cfg.Security.Network.OutboundSSRF.AllowPrivateNetworks = true
	cfg.Security.Network.OutboundSSRF.AllowInsecureHTTP = true

	// Mock upstream A2A agent
	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := &pb.SendMessageResponse{
			Payload: &pb.SendMessageResponse_Message{
				Message: &pb.Message{
					MessageId: "resp_msg_001",
					Role:      pb.Role_ROLE_AGENT,
					Parts: []*pb.Part{
						{Content: &pb.Part_Text{Text: "Task completed successfully by upstream agent."}},
					},
				},
			},
		}
		respBytes, _ := a2a.ProtoJSONMarshaler.Marshal(resp)
		_, _ = w.Write(respBytes)
	}))
	defer mockUpstream.Close()

	srv, err := server.New(cfg, repo, nil, nil)
	require.NoError(t, err)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	adminKey := "sk-gw-master-admin-key"

	// Create test organization
	require.NoError(t, repo.CreateOrganization(context.Background(), &domain.Organization{
		ID:       "org_default",
		Name:     "Default Organization",
		IsActive: true,
	}))

	// Issue a virtual key for data-plane client calls
	vKey := &domain.VirtualKey{
		ID:                "key_a2a_tester",
		KeyHash:           auth.HashKey("sk-gw-client-test-key"),
		OrgID:             "org_default",
		TeamID:            "team_alpha",
		UserID:            "usr_analyst",
		Name:              "A2A Client Key",
		IsActive:          true,
		Role:              domain.RoleDeveloper,
		AllowedEndpoints:  []string{"/a2a/*", "/a2a/v1/*"},
		AllowedA2AAgents:  []string{"*"},
		AllowedMCPServers: []string{"*"},
		AllowedClientApps: []string{"*"},
		CreatedAt:         time.Now().UTC(),
		UpdatedAt:         time.Now().UTC(),
	}
	require.NoError(t, repo.CreateVirtualKey(context.Background(), vKey))
	clientBearer := "Bearer sk-gw-client-test-key"

	// 1. Create A2A Agent via POST /admin/v1/a2a/agents
	createPayload := []byte(fmt.Sprintf(`{
		"org_id": "org_default",
		"name": "Audit Agent",
		"slug": "audit-agent",
		"endpoint_url": "%s",
		"task_visibility_mode": "key_strict",
		"auth_type": "none",
		"max_task_iterations": 20,
		"max_task_budget_micros": 5000000
	}`, mockUpstream.URL))

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/admin/v1/a2a/agents", bytes.NewReader(createPayload))
	req.Header.Set("Authorization", "Bearer "+adminKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusCreated, resp.StatusCode)

	var createResp struct {
		Status string          `json:"status"`
		Agent  domain.A2AAgent `json:"agent"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&createResp))
	agentID := createResp.Agent.ID
	require.NotEmpty(t, agentID)
	assert.Equal(t, "audit-agent", createResp.Agent.Slug)

	// 2. List A2A Agents via GET /admin/v1/a2a/agents
	req, _ = http.NewRequest(http.MethodGet, ts.URL+"/admin/v1/a2a/agents?org_id=org_default", nil)
	req.Header.Set("Authorization", "Bearer "+adminKey)

	resp, err = http.DefaultClient.Do(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	var listResp struct {
		Agents []*domain.A2AAgent `json:"agents"`
	}
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&listResp))
	assert.Len(t, listResp.Agents, 1)

	// 3. Get A2A Agent by ID via GET /admin/v1/a2a/agents/{id}
	req, _ = http.NewRequest(http.MethodGet, fmt.Sprintf("%s/admin/v1/a2a/agents/%s", ts.URL, agentID), nil)
	req.Header.Set("Authorization", "Bearer "+adminKey)

	resp, err = http.DefaultClient.Do(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// 4. Send Message to Agent via Data Plane (POST /a2a/v1/agents/{agentSlug})
	sendReq := &pb.SendMessageRequest{
		Message: &pb.Message{
			MessageId: "msg_user_001",
			Role:      pb.Role_ROLE_USER,
			Parts: []*pb.Part{
				{Content: &pb.Part_Text{Text: "Please audit transaction TX-999"}},
			},
		},
	}
	sendBytes, err := a2a.ProtoJSONMarshaler.Marshal(sendReq)
	require.NoError(t, err)

	req, _ = http.NewRequest(http.MethodPost, ts.URL+"/a2a/v1/agents/audit-agent", bytes.NewReader(sendBytes))
	req.Header.Set("Authorization", clientBearer)
	req.Header.Set("Content-Type", "application/json")

	resp, err = http.DefaultClient.Do(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "Data plane A2A message must succeed when agent is active")

	var sendResp pb.SendMessageResponse
	require.NoError(t, a2a.StrictProtoJSONUnmarshaler.Unmarshal(bytesFromReader(t, resp.Body), &sendResp))
	assert.Contains(t, sendResp.GetMessage().GetParts()[0].GetText(), "Task completed successfully")

	// 5. Activate Emergency Kill-Switch via POST /admin/v1/a2a/agents/{id}/kill-switch
	killPayload := []byte(`{"killed": true}`)
	req, _ = http.NewRequest(http.MethodPost, fmt.Sprintf("%s/admin/v1/a2a/agents/%s/kill-switch", ts.URL, agentID), bytes.NewReader(killPayload))
	req.Header.Set("Authorization", "Bearer "+adminKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err = http.DefaultClient.Do(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// 6. Immediate enforcement: Data Plane invocation MUST return 503 Service Unavailable (agent_killed)
	req, _ = http.NewRequest(http.MethodPost, ts.URL+"/a2a/v1/agents/audit-agent", bytes.NewReader(sendBytes))
	req.Header.Set("Authorization", clientBearer)
	req.Header.Set("Content-Type", "application/json")

	resp, err = http.DefaultClient.Do(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode, "Emergency kill-switch must immediately reject callers with 503")

	var errResp map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&errResp))
	errObj := errResp["error"].(map[string]any)
	assert.Equal(t, "agent_killed", errObj["code"])

	// 7. Deactivate Kill-Switch: calls succeed again
	revivePayload := []byte(`{"killed": false}`)
	req, _ = http.NewRequest(http.MethodPost, fmt.Sprintf("%s/admin/v1/a2a/agents/%s/kill-switch", ts.URL, agentID), bytes.NewReader(revivePayload))
	req.Header.Set("Authorization", "Bearer "+adminKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err = http.DefaultClient.Do(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	req, _ = http.NewRequest(http.MethodPost, ts.URL+"/a2a/v1/agents/audit-agent", bytes.NewReader(sendBytes))
	req.Header.Set("Authorization", clientBearer)
	req.Header.Set("Content-Type", "application/json")

	resp, err = http.DefaultClient.Do(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusOK, resp.StatusCode, "Revived agent must accept data plane requests")
}

func TestAdminA2APushConfigRegistration(t *testing.T) {
	repo := storage.NewMemoryRepository()
	cfg := config.Default()
	cfg.Auth.MasterAdminKey = "sk-gw-master-admin-key"

	srv, err := server.New(cfg, repo, nil, nil)
	require.NoError(t, err)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	adminKey := "sk-gw-master-admin-key"

	pushPayload := []byte(`{
		"task_id": "task_audit_999",
		"target_url": "https://webhook.internal/a2a-notify",
		"auth_token": "secret-webhook-bearer"
	}`)

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/admin/v1/a2a/push-configs", bytes.NewReader(pushPayload))
	req.Header.Set("Authorization", "Bearer "+adminKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	assert.Equal(t, http.StatusCreated, resp.StatusCode)

	cfgStored, err := repo.GetA2APushNotificationConfig(context.Background(), "task_audit_999")
	require.NoError(t, err)
	assert.Equal(t, "https://webhook.internal/a2a-notify", cfgStored.TargetURL)
	assert.Equal(t, "secret-webhook-bearer", cfgStored.AuthToken)
}

func TestA2AOpenAIBridgeInference(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	cfg := config.Default()
	cfg.Auth.MasterAdminKey = "sk-gw-master-admin-key"
	cfg.Security.Network.OutboundSSRF.AllowPrivateNetworks = true
	cfg.Security.Network.OutboundSSRF.AllowInsecureHTTP = true

	// Mock upstream A2A agent
	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		resp := &pb.SendMessageResponse{
			Payload: &pb.SendMessageResponse_Task{
				Task: &pb.Task{
					Id:        "task_agent_123",
					ContextId: "ctx_agent_123",
					Status: &pb.TaskStatus{
						State: pb.TaskState_TASK_STATE_COMPLETED,
						Message: &pb.Message{
							Role: pb.Role_ROLE_AGENT,
							Parts: []*pb.Part{
								{Content: &pb.Part_Text{Text: "A2A agent responded to OpenAI chat request."}},
							},
						},
					},
				},
			},
		}
		respBytes, _ := a2a.ProtoJSONMarshaler.Marshal(resp)
		_, _ = w.Write(respBytes)
	}))
	defer mockUpstream.Close()

	srv, err := server.New(cfg, repo, nil, nil)
	require.NoError(t, err)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// Seed Virtual Key with permission to call a2a agent
	rawKey := "sk-gw-client-test-key-12345"
	keyHash := auth.HashKey(rawKey)
	vk := &domain.VirtualKey{
		ID:               "vk_test",
		KeyPrefix:        "sk-gw-client",
		KeyHash:          keyHash,
		Name:             "Dev Key",
		OrgID:            "org_default",
		Role:             domain.RoleDeveloper,
		AllowedA2AAgents: []string{"chat-agent"},
		IsActive:         true,
	}
	require.NoError(t, repo.CreateVirtualKey(ctx, vk))

	// Register chat-agent
	agent := &domain.A2AAgent{
		ID:                 "agent_chat",
		OrgID:              "org_default",
		Name:               "Chat Agent",
		Slug:               "chat-agent",
		EndpointURL:        mockUpstream.URL,
		AuthType:           "none",
		TaskVisibilityMode: domain.TaskVisibilityKeyStrict,
		IsActive:           true,
	}
	require.NoError(t, repo.CreateA2AAgent(ctx, agent))

	// Issue POST /v1/chat/completions with model: "a2a/chat-agent"
	reqPayload := []byte(`{
		"model": "a2a/chat-agent",
		"messages": [
			{"role": "user", "content": "Hello A2A Agent"}
		]
	}`)
	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/v1/chat/completions", bytes.NewReader(reqPayload))
	req.Header.Set("Authorization", "Bearer "+rawKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.NotEmpty(t, resp.Header.Get("X-Gateway-A2A-Task-Id"))
	assert.Equal(t, "completed", resp.Header.Get("X-Gateway-A2A-Task-State"))

	var compResp map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&compResp))
	choices := compResp["choices"].([]any)
	require.Len(t, choices, 1)
	choice := choices[0].(map[string]any)
	assert.Equal(t, "stop", choice["finish_reason"])
	msg := choice["message"].(map[string]any)
	assert.Equal(t, "A2A agent responded to OpenAI chat request.", msg["content"])
}

func bytesFromReader(t *testing.T, r ioReader) []byte {
	t.Helper()
	var buf bytes.Buffer
	_, err := buf.ReadFrom(r)
	require.NoError(t, err)
	return buf.Bytes()
}

type ioReader interface {
	Read(p []byte) (n int, err error)
}
