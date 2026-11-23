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

	a2aspec "github.com/goroute-ai/ai-gateway-go/internal/a2a/spec"
	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/server"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestA2AV1ContractAllOperationsAndAdminLifecycle(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	cfg := config.Default()
	cfg.Auth.MasterAdminKey = "sk-gw-master-admin-key"
	cfg.A2A.EnableSubscribePostCompat = true
	cfg.A2A.AllowLegacyCardDiscovery = true
	cfg.Security.Network.OutboundSSRF.AllowPrivateNetworks = true
	cfg.Security.Network.OutboundSSRF.AllowInsecureHTTP = true

	var mockUpstreamURL string
	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/agent-card.json":
			w.Header().Set("Content-Type", "application/a2a+json")
			card := a2aspec.AgentCard{
				Name:        "Contract Upstream Agent",
				Description: "Synced card",
				Version:     "1.0.0",
				Capabilities: a2aspec.AgentCapabilities{
					Streaming:         ptrBool(true),
					PushNotifications: ptrBool(true),
					ExtendedAgentCard: ptrBool(true),
				},
				DefaultInputModes:  []string{"text/plain"},
				DefaultOutputModes: []string{"text/plain"},
				Skills:             []a2aspec.AgentSkill{},
				SupportedInterfaces: []a2aspec.AgentInterface{
					{ProtocolBinding: domain.A2AProtocolBindingHTTPJSON, ProtocolVersion: "1.0", Url: mockUpstreamURL},
				},
			}
			_ = json.NewEncoder(w).Encode(card)
		case "/message:stream":
			w.Header().Set("Content-Type", "text/event-stream")
			frame, _ := json.Marshal(a2aspec.StreamResponse{
				Task: &a2aspec.Task{
					Id:        "upstream_stream_1",
					ContextId: ptrStr("ctx_stream_1"),
					Status: a2aspec.TaskStatus{
						State: a2aspec.TASKSTATECOMPLETED,
						Message: &a2aspec.Message{
							MessageId: "msg_stream_1",
							Role:      a2aspec.ROLEAGENT,
							Parts:     []a2aspec.Part{a2aspec.NewTextPart("stream done")},
						},
					},
				},
			})
			_, _ = fmt.Fprintf(w, "data: %s\n\n", string(frame))
		default:
			w.Header().Set("Content-Type", "application/a2a+json")
			resp := a2aspec.NewSendMessageResponseTask(&a2aspec.Task{
				Id:        "upstream_task_1",
				ContextId: ptrStr("ctx_1"),
				Status: a2aspec.TaskStatus{
					State: a2aspec.TASKSTATEWORKING,
					Message: &a2aspec.Message{
						MessageId: "msg_working_1",
						Role:      a2aspec.ROLEAGENT,
						Parts:     []a2aspec.Part{a2aspec.NewTextPart("working on it")},
					},
				},
			})
			_ = json.NewEncoder(w).Encode(resp)
		}
	}))
	defer mockUpstream.Close()
	mockUpstreamURL = mockUpstream.URL

	srv, err := server.New(cfg, repo, nil, nil)
	require.NoError(t, err)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	require.NoError(t, repo.CreateOrganization(ctx, &domain.Organization{ID: "org_default", Name: "Default", IsActive: true}))
	require.NoError(t, repo.CreateOrganization(ctx, &domain.Organization{ID: "org_other", Name: "Other", IsActive: true}))

	clientKey := "sk-gw-a2a-contract-client"
	require.NoError(t, repo.CreateVirtualKey(ctx, &domain.VirtualKey{
		ID:               "vk_contract",
		KeyPrefix:        "sk-gw-a2a",
		KeyHash:          auth.HashKey(clientKey),
		OrgID:            "org_default",
		Name:             "Contract Key",
		IsActive:         true,
		Role:             domain.RoleDeveloper,
		AllowedEndpoints: []string{"/a2a/*", "/a2a/v1/*"},
		AllowedA2AAgents: []string{"*"},
		CreatedAt:        time.Now().UTC(),
		UpdatedAt:        time.Now().UTC(),
	}))
	otherOrgKey := "sk-gw-other-org-client"
	require.NoError(t, repo.CreateVirtualKey(ctx, &domain.VirtualKey{
		ID:               "vk_other",
		KeyPrefix:        "sk-gw-other",
		KeyHash:          auth.HashKey(otherOrgKey),
		OrgID:            "org_other",
		Name:             "Other Key",
		IsActive:         true,
		Role:             domain.RoleDeveloper,
		AllowedEndpoints: []string{"/a2a/*", "/a2a/v1/*"},
		AllowedA2AAgents: []string{"*"},
		CreatedAt:        time.Now().UTC(),
		UpdatedAt:        time.Now().UTC(),
	}))

	adminAuth := "Bearer " + cfg.Auth.MasterAdminKey
	clientAuth := "Bearer " + clientKey
	otherAuth := "Bearer " + otherOrgKey

	// 1. Admin creates private agent and public agent
	privateCardJSON := fmt.Sprintf(`{"name":"Private Agent","description":"Private","version":"1.0.0","capabilities":{},"defaultInputModes":["text/plain"],"defaultOutputModes":["text/plain"],"skills":[],"supportedInterfaces":[{"protocolBinding":"HTTP+JSON","protocolVersion":"1.0","url":"%s"}]}`, mockUpstream.URL)
	extCardJSON := fmt.Sprintf(`{"name":"Private Agent Extended","description":"Extended","version":"1.0.0","capabilities":{"extendedAgentCard":true},"defaultInputModes":["text/plain"],"defaultOutputModes":["application/json"],"skills":[],"supportedInterfaces":[{"protocolBinding":"HTTP+JSON","protocolVersion":"1.0","url":"%s"}]}`, mockUpstream.URL)
	createPrivate := fmt.Sprintf(`{
		"org_id":"org_default",
		"name":"Private Agent",
		"slug":"private-agent",
		"endpoint_url":"%s",
		"agent_card_url":"%s/.well-known/agent-card.json",
		"agent_card_json":%q,
		"extended_agent_card_json":%q,
		"is_public_card":false,
		"protocol_binding":"HTTP+JSON",
		"task_visibility_mode":"key_strict"
	}`, mockUpstream.URL, mockUpstream.URL, privateCardJSON, extCardJSON)

	resp, raw := doContractReq(t, http.MethodPost, ts.URL+"/admin/v1/a2a/agents", adminAuth, "application/json", createPrivate)
	require.Equal(t, http.StatusCreated, resp.StatusCode, string(raw))
	var createdPrivate struct {
		Agent domain.A2AAgent `json:"agent"`
	}
	require.NoError(t, json.Unmarshal(raw, &createdPrivate))

	// Invalid agent_card_json rejected with 400
	resp, raw = doContractReq(t, http.MethodPost, ts.URL+"/admin/v1/a2a/agents", adminAuth, "application/json", `{
		"org_id":"org_default","name":"Bad","slug":"bad-card","endpoint_url":"https://example.com","agent_card_json":"{\"invalid\":true}"
	}`)
	assert.Equal(t, http.StatusBadRequest, resp.StatusCode, string(raw))

	// 2. Sync card from upstream agent_card_url
	resp, raw = doContractReq(t, http.MethodPost, fmt.Sprintf("%s/admin/v1/a2a/agents/%s/sync-card", ts.URL, createdPrivate.Agent.ID), adminAuth, "application/json", `{}`)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(raw))
	assert.Contains(t, string(raw), "Contract Upstream Agent")

	// 3. Well-known card discovery isolation (C2): unauthenticated cannot see private agent
	resp, raw = doContractReq(t, http.MethodGet, ts.URL+"/.well-known/agent-card.json?agent=private-agent", "", "", "")
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, string(raw))

	// Other org key cannot see org_default private agent
	resp, raw = doContractReq(t, http.MethodGet, ts.URL+"/.well-known/agent-card.json?agent=private-agent", otherAuth, "", "")
	assert.Equal(t, http.StatusNotFound, resp.StatusCode, string(raw))

	// Same org authenticated caller discovers private agent & legacy path works too
	resp, raw = doContractReq(t, http.MethodGet, ts.URL+"/.well-known/agent-card.json?agent=private-agent", clientAuth, "", "")
	require.Equal(t, http.StatusOK, resp.StatusCode, string(raw))
	assert.Equal(t, "1.0", resp.Header.Get("A2A-Version"))
	resp, _ = doContractReq(t, http.MethodGet, ts.URL+"/.well-known/agent.json?agent=private-agent", clientAuth, "", "")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Make agent public via PUT update -> unauthenticated discovery succeeds
	resp, raw = doContractReq(t, http.MethodPut, fmt.Sprintf("%s/admin/v1/a2a/agents/%s", ts.URL, createdPrivate.Agent.ID), adminAuth, "application/json", `{"is_public_card":true}`)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(raw))
	resp, raw = doContractReq(t, http.MethodGet, ts.URL+"/.well-known/agent-card.json?agent=private-agent", "", "", "")
	require.Equal(t, http.StatusOK, resp.StatusCode, string(raw))

	// 4. Header & Content-Type enforcement
	resp, raw = doContractReq(t, http.MethodPost, ts.URL+"/a2a/v1/agents/private-agent/message:send", clientAuth, "text/plain", `{}`)
	assert.Equal(t, http.StatusUnsupportedMediaType, resp.StatusCode, string(raw))

	reqBadVer, _ := http.NewRequest(http.MethodPost, ts.URL+"/a2a/v1/agents/private-agent/message:send", strings.NewReader(`{"message":{"messageId":"m1","role":"ROLE_USER","parts":[{"text":"hi"}]}}`))
	reqBadVer.Header.Set("Authorization", clientAuth)
	reqBadVer.Header.Set("Content-Type", "application/a2a+json")
	reqBadVer.Header.Set("A2A-Version", "2.0")
	respBadVer, err := http.DefaultClient.Do(reqBadVer)
	require.NoError(t, err)
	respBadVer.Body.Close()
	assert.Equal(t, http.StatusBadRequest, respBadVer.StatusCode)

	// 5. HTTP+JSON SendMessage + ExtendedAgentCard + Tasks + Push Configs + Cancel + Tenant variants
	sendBody := `{"message":{"messageId":"msg_rest_1","role":"ROLE_USER","parts":[{"text":"run check"}]}}`
	resp, raw = doContractReq(t, http.MethodPost, ts.URL+"/a2a/v1/agents/private-agent/message:send", clientAuth, "application/a2a+json", sendBody)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(raw))
	sendResp, err := a2aspec.DecodeStrict[a2aspec.SendMessageResponse]("SendMessageResponse", raw)
	require.NoError(t, err)
	require.NotNil(t, sendResp.Task)
	taskID := sendResp.Task.Id

	// Extended AgentCard (both root and tenant-scoped)
	resp, raw = doContractReq(t, http.MethodGet, ts.URL+"/a2a/v1/agents/private-agent/extendedAgentCard", clientAuth, "", "")
	require.Equal(t, http.StatusOK, resp.StatusCode, string(raw))
	assert.Contains(t, string(raw), "Private Agent Extended")
	resp, _ = doContractReq(t, http.MethodGet, ts.URL+"/a2a/v1/agents/private-agent/org_default/extendedAgentCard", clientAuth, "", "")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// ListTasks & GetTask (root and tenant-scoped)
	resp, raw = doContractReq(t, http.MethodGet, ts.URL+"/a2a/v1/agents/private-agent/tasks?pageSize=10", clientAuth, "", "")
	require.Equal(t, http.StatusOK, resp.StatusCode, string(raw))
	assert.Contains(t, string(raw), taskID)
	resp, _ = doContractReq(t, http.MethodGet, ts.URL+"/a2a/v1/agents/private-agent/org_default/tasks", clientAuth, "", "")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp, _ = doContractReq(t, http.MethodGet, fmt.Sprintf("%s/a2a/v1/agents/private-agent/tasks/%s", ts.URL, taskID), clientAuth, "", "")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp, _ = doContractReq(t, http.MethodGet, fmt.Sprintf("%s/a2a/v1/agents/private-agent/org_default/tasks/%s", ts.URL, taskID), clientAuth, "", "")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Push Notification Config CRUD (REST)
	pushBody := `{"url":"https://webhook.example.com/hook","token":"wh-tok-1"}`
	resp, raw = doContractReq(t, http.MethodPost, fmt.Sprintf("%s/a2a/v1/agents/private-agent/tasks/%s/pushNotificationConfigs", ts.URL, taskID), clientAuth, "application/a2a+json", pushBody)
	require.Equal(t, http.StatusCreated, resp.StatusCode, string(raw))
	var createdPush a2aspec.TaskPushNotificationConfig
	require.NoError(t, json.Unmarshal(raw, &createdPush))
	require.NotNil(t, createdPush.Id)

	resp, raw = doContractReq(t, http.MethodGet, fmt.Sprintf("%s/a2a/v1/agents/private-agent/tasks/%s/pushNotificationConfigs", ts.URL, taskID), clientAuth, "", "")
	require.Equal(t, http.StatusOK, resp.StatusCode, string(raw))
	assert.Contains(t, string(raw), *createdPush.Id)

	resp, _ = doContractReq(t, http.MethodGet, fmt.Sprintf("%s/a2a/v1/agents/private-agent/tasks/%s/pushNotificationConfigs/%s", ts.URL, taskID, *createdPush.Id), clientAuth, "", "")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	resp, _ = doContractReq(t, http.MethodDelete, fmt.Sprintf("%s/a2a/v1/agents/private-agent/tasks/%s/pushNotificationConfigs/%s", ts.URL, taskID, *createdPush.Id), clientAuth, "", "")
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// CancelTask (root and tenant JSON-RPC)
	resp, raw = doContractReq(t, http.MethodPost, fmt.Sprintf("%s/a2a/v1/agents/private-agent/tasks/%s:cancel", ts.URL, taskID), clientAuth, "application/a2a+json", `{}`)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(raw))
	assert.Contains(t, string(raw), "TASK_STATE_CANCELED")

	// SubscribeToTask (GET and POST compat since EnableSubscribePostCompat=true) on canceled (terminal) task completes cleanly
	resp, raw = doContractReq(t, http.MethodGet, fmt.Sprintf("%s/a2a/v1/agents/private-agent/tasks/%s:subscribe", ts.URL, taskID), clientAuth, "", "")
	require.Equal(t, http.StatusOK, resp.StatusCode, string(raw))
	assert.Contains(t, resp.Header.Get("Content-Type"), "text/event-stream")
	resp, _ = doContractReq(t, http.MethodPost, fmt.Sprintf("%s/a2a/v1/agents/private-agent/tasks/%s:subscribe", ts.URL, taskID), clientAuth, "application/a2a+json", `{}`)
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// SendStreamingMessage (REST)
	resp, raw = doContractReq(t, http.MethodPost, ts.URL+"/a2a/v1/agents/private-agent/message:stream", clientAuth, "application/a2a+json", sendBody)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(raw))
	assert.Contains(t, resp.Header.Get("Content-Type"), "text/event-stream")
	assert.Contains(t, string(raw), "stream done")

	// JSON-RPC 2.0 (root without trailing slash + tenant route)
	rpcReq := `{"jsonrpc":"2.0","id":"rpc-1","method":"SendMessage","params":{"message":{"messageId":"msg_rpc_1","role":"ROLE_USER","parts":[{"text":"rpc hello"}]}}}`
	resp, raw = doContractReq(t, http.MethodPost, ts.URL+"/a2a/v1/agents/private-agent", clientAuth, "application/json", rpcReq)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(raw))
	assert.Contains(t, string(raw), `"result"`)
	resp, raw = doContractReq(t, http.MethodPost, ts.URL+"/a2a/v1/agents/private-agent/org_default", clientAuth, "application/json", rpcReq)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(raw))
	assert.Contains(t, string(raw), `"result"`)

	// 6. Admin Outbox list + replay
	outboxEv := &domain.A2AOutboxEvent{
		ID:            "outbox_contract_1",
		TaskID:        taskID,
		EventType:     "status",
		TargetURL:     "https://webhook.example.com/hook",
		PayloadJSON:   `{"status":"canceled"}`,
		Status:        domain.OutboxStatusDeadLetter,
		AttemptCount:  5,
		LastError:     "timeout",
		NextAttemptAt: time.Now().UTC(),
		CreatedAt:     time.Now().UTC(),
		UpdatedAt:     time.Now().UTC(),
	}
	require.NoError(t, repo.CreateA2AOutboxEvent(ctx, outboxEv))

	resp, raw = doContractReq(t, http.MethodGet, ts.URL+"/admin/v1/a2a/outbox?org_id=org_default&status=dead_letter", adminAuth, "", "")
	require.Equal(t, http.StatusOK, resp.StatusCode, string(raw))
	assert.Contains(t, string(raw), "outbox_contract_1")

	resp, raw = doContractReq(t, http.MethodPost, fmt.Sprintf("%s/admin/v1/a2a/outbox/%s/replay", ts.URL, outboxEv.ID), adminAuth, "application/json", `{}`)
	require.Equal(t, http.StatusOK, resp.StatusCode, string(raw))
	assert.Contains(t, string(raw), `"status":"pending"`)

	// 7. Admin Delete Agent
	resp, _ = doContractReq(t, http.MethodDelete, fmt.Sprintf("%s/admin/v1/a2a/agents/%s", ts.URL, createdPrivate.Agent.ID), adminAuth, "", "")
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	_, gErr := repo.GetA2AAgent(ctx, createdPrivate.Agent.ID)
	assert.Error(t, gErr)
}

func TestA2ADisabledConfigGatesAllEndpointsAndBridge(t *testing.T) {
	repo := storage.NewMemoryRepository()
	cfg := config.Default()
	cfg.A2A.Enabled = false

	srv, err := server.New(cfg, repo, nil, nil)
	require.NoError(t, err)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// Discovery returns 404 when A2A disabled
	resp, _ := doContractReq(t, http.MethodGet, ts.URL+"/.well-known/agent-card.json", "", "", "")
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)

	// Execution routes not mounted -> 404
	resp, _ = doContractReq(t, http.MethodPost, ts.URL+"/a2a/v1/agents/any/message:send", "", "application/a2a+json", `{}`)
	assert.Equal(t, http.StatusNotFound, resp.StatusCode)
}

func doContractReq(t *testing.T, method, targetURL, authHeader, contentType, body string) (*http.Response, []byte) {
	t.Helper()
	var bodyReader *bytes.Reader
	if body != "" {
		bodyReader = bytes.NewReader([]byte(body))
	} else {
		bodyReader = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, targetURL, bodyReader)
	require.NoError(t, err)
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	raw := bytesFromReader(t, resp.Body)
	resp.Body.Close()
	return resp, raw
}

func ptrBool(v bool) *bool    { return &v }
func ptrStr(v string) *string { return &v }
