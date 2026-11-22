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

	a2aspec "github.com/goroute-ai/ai-gateway-go/internal/a2a/spec"
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

	// Mock upstream A2A agent (OpenAPI-first A2A v1.0)
	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/a2a+json")
		resp := a2aspec.NewSendMessageResponseMessage(&a2aspec.Message{
			MessageId: "resp_msg_001",
			Role:      a2aspec.ROLEAGENT,
			Parts:     []a2aspec.Part{a2aspec.NewTextPart("Task completed successfully by upstream agent.")},
		})
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer mockUpstream.Close()

	srv, err := server.New(cfg, repo, nil, nil)
	require.NoError(t, err)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	adminKey := "sk-gw-master-admin-key"

	require.NoError(t, repo.CreateOrganization(context.Background(), &domain.Organization{
		ID:       "org_default",
		Name:     "Default Organization",
		IsActive: true,
	}))
	require.NoError(t, repo.CreateTeam(context.Background(), &domain.Team{
		ID:       "team_alpha",
		OrgID:    "org_default",
		Name:     "Alpha Team",
		IsActive: true,
	}))
	require.NoError(t, repo.CreateUser(context.Background(), &domain.User{
		ID:       "usr_analyst",
		OrgID:    "org_default",
		Email:    "analyst@example.com",
		Role:     domain.RoleDeveloper,
		IsActive: true,
	}))

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
	createPayload := fmt.Appendf(nil, `{
		"org_id": "org_default",
		"name": "Audit Agent",
		"slug": "audit-agent",
		"endpoint_url": "%s",
		"task_visibility_mode": "key_strict",
		"protocol_binding": "HTTP+JSON",
		"auth_type": "none",
		"max_task_iterations": 20,
		"max_task_budget_micros": 5000000
	}`, mockUpstream.URL)

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/admin/v1/a2a/agents", bytes.NewReader(createPayload))
	req.Header.Set("Authorization", "Bearer "+adminKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
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
	defer resp.Body.Close()
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
	resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// 4. Send Message to Agent via Canonical A2A v1.0 Data Plane (POST /a2a/v1/agents/{agentSlug}/message:send)
	sendReq := &a2aspec.SendMessageRequest{
		Message: a2aspec.Message{
			MessageId: "msg_user_001",
			Role:      a2aspec.ROLEUSER,
			Parts:     []a2aspec.Part{a2aspec.NewTextPart("Please audit transaction TX-999")},
		},
	}
	sendBytes, err := json.Marshal(sendReq)
	require.NoError(t, err)

	req, _ = http.NewRequest(http.MethodPost, ts.URL+"/a2a/v1/agents/audit-agent/message:send", bytes.NewReader(sendBytes))
	req.Header.Set("Authorization", clientBearer)
	req.Header.Set("Content-Type", "application/a2a+json")

	resp, err = http.DefaultClient.Do(req)
	require.NoError(t, err)
	bodyBytes := bytesFromReader(t, resp.Body)
	resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode, "Data plane A2A message must succeed when agent is active: %s", string(bodyBytes))

	sendResp, err := a2aspec.DecodeStrict[a2aspec.SendMessageResponse]("SendMessageResponse", bodyBytes)
	require.NoError(t, err)
	require.NotNil(t, sendResp.Message)
	txt, ok := a2aspec.PartText(sendResp.Message.Parts[0])
	require.True(t, ok)
	assert.Contains(t, txt, "Task completed successfully")

	// 5. Activate Emergency Kill-Switch via POST /admin/v1/a2a/agents/{id}/kill-switch
	killPayload := []byte(`{"killed": true}`)
	req, _ = http.NewRequest(http.MethodPost, fmt.Sprintf("%s/admin/v1/a2a/agents/%s/kill-switch", ts.URL, agentID), bytes.NewReader(killPayload))
	req.Header.Set("Authorization", "Bearer "+adminKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err = http.DefaultClient.Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// 6. Immediate enforcement: Data Plane invocation MUST return 503 Service Unavailable (google.rpc.StatusError)
	req, _ = http.NewRequest(http.MethodPost, ts.URL+"/a2a/v1/agents/audit-agent/message:send", bytes.NewReader(sendBytes))
	req.Header.Set("Authorization", clientBearer)
	req.Header.Set("Content-Type", "application/a2a+json")

	resp, err = http.DefaultClient.Do(req)
	require.NoError(t, err)
	errBody := bytesFromReader(t, resp.Body)
	resp.Body.Close()
	assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode, "Emergency kill-switch must immediately reject callers with 503: %s", string(errBody))

	var statusErr a2aspec.GoogleRpcStatusError
	require.NoError(t, json.Unmarshal(errBody, &statusErr))
	assert.Equal(t, int32(http.StatusServiceUnavailable), statusErr.Error.Code)
	assert.Contains(t, statusErr.Error.Message, "kill-switch")

	// 7. Deactivate Kill-Switch: calls succeed again
	revivePayload := []byte(`{"killed": false}`)
	req, _ = http.NewRequest(http.MethodPost, fmt.Sprintf("%s/admin/v1/a2a/agents/%s/kill-switch", ts.URL, agentID), bytes.NewReader(revivePayload))
	req.Header.Set("Authorization", "Bearer "+adminKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err = http.DefaultClient.Do(req)
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	req, _ = http.NewRequest(http.MethodPost, ts.URL+"/a2a/v1/agents/audit-agent/message:send", bytes.NewReader(sendBytes))
	req.Header.Set("Authorization", clientBearer)
	req.Header.Set("Content-Type", "application/a2a+json")

	resp, err = http.DefaultClient.Do(req)
	require.NoError(t, err)
	resp.Body.Close()
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

	require.NoError(t, repo.CreateA2ATask(context.Background(), &domain.A2ATask{
		ID:    "task_audit_999",
		OrgID: "org_default",
		State: domain.A2ATaskStateSubmitted,
	}))

	adminKey := "sk-gw-master-admin-key"

	pushPayload := []byte(`{
		"task_id": "task_audit_999",
		"target_url": "https://webhook.example.com/a2a-notify",
		"auth_token": "secret-webhook-bearer"
	}`)

	req, _ := http.NewRequest(http.MethodPost, ts.URL+"/admin/v1/a2a/push-configs", bytes.NewReader(pushPayload))
	req.Header.Set("Authorization", "Bearer "+adminKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	assert.Equal(t, http.StatusCreated, resp.StatusCode)

	cfgs, total, err := repo.ListA2APushNotificationConfigs(context.Background(), "task_audit_999", 10, 0)
	require.NoError(t, err)
	require.Equal(t, 1, total)
	cfgStored := cfgs[0]
	assert.Equal(t, "https://webhook.example.com/a2a-notify", cfgStored.TargetURL)
	assert.NotEqual(t, "secret-webhook-bearer", cfgStored.EncryptedAuthCreds)
	assert.NotEmpty(t, cfgStored.EncryptedAuthCreds)
	assert.NotEmpty(t, cfgStored.EncryptedAuthDEK)
}

func TestA2AOpenAIBridgeInference(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	cfg := config.Default()
	cfg.Auth.MasterAdminKey = "sk-gw-master-admin-key"
	cfg.Security.Network.OutboundSSRF.AllowPrivateNetworks = true
	cfg.Security.Network.OutboundSSRF.AllowInsecureHTTP = true

	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/a2a+json")
		ctxID := "ctx_agent_123"
		resp := a2aspec.NewSendMessageResponseTask(&a2aspec.Task{
			Id:        "task_agent_123",
			ContextId: &ctxID,
			Status: a2aspec.TaskStatus{
				State: a2aspec.TASKSTATECOMPLETED,
				Message: &a2aspec.Message{
					MessageId: "msg_resp_1",
					Role:      a2aspec.ROLEAGENT,
					Parts:     []a2aspec.Part{a2aspec.NewTextPart("A2A agent responded to OpenAI chat request.")},
				},
			},
		})
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer mockUpstream.Close()

	srv, err := server.New(cfg, repo, nil, nil)
	require.NoError(t, err)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	rawKey := "sk-gw-client-test-key-12345"
	vk := &domain.VirtualKey{
		ID:               "vk_test",
		KeyPrefix:        "sk-gw-client",
		KeyHash:          auth.HashKey(rawKey),
		Name:             "Dev Key",
		OrgID:            "org_default",
		Role:             domain.RoleDeveloper,
		AllowedEndpoints: []string{"*"},
		AllowedA2AAgents: []string{"chat-agent"},
		IsActive:         true,
	}
	require.NoError(t, repo.CreateVirtualKey(ctx, vk))

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
