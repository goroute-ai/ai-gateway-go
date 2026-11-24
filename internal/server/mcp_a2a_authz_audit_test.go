package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/server"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMCPAndA2AAdminMutationsEmitRedactedAuditDiffs(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	cfg := config.Default()
	cfg.Auth.MasterAdminKey = "sk-gw-master-admin-key"
	cfg.Security.Network.OutboundSSRF.AllowPrivateNetworks = true
	cfg.Security.Network.OutboundSSRF.AllowInsecureHTTP = true
	cfg.Security.Network.OutboundSSRF.AllowLoopbackHTTP = true

	mockMCP := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		var rpc struct {
			ID     any    `json:"id"`
			Method string `json:"method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&rpc)
		switch rpc.Method {
		case "initialize":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0",
				"id":      rpc.ID,
				"result": map[string]any{
					"protocolVersion": "2026-07-28",
					"capabilities":    map[string]any{"tools": map[string]any{}},
					"serverInfo":      map[string]any{"name": "mock-mcp", "version": "1.0.0"},
				},
			})
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"jsonrpc": "2.0",
				"id":      rpc.ID,
				"result": map[string]any{
					"tools": []map[string]any{
						{"name": "get_status", "description": "Read status", "inputSchema": map[string]any{"type": "object"}},
					},
				},
			})
		}
	}))
	defer mockMCP.Close()

	srv, err := server.New(cfg, repo, nil, nil)
	require.NoError(t, err)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	require.NoError(t, repo.CreateOrganization(ctx, &domain.Organization{ID: "org_default", Name: "Default", IsActive: true}))
	require.NoError(t, repo.CreateUser(ctx, &domain.User{ID: "usr_mcp_1", OrgID: "org_default", Email: "mcp@example.com", Role: domain.RoleDeveloper, IsActive: true}))

	adminDo := func(method, path string, payload any, want int) []byte {
		t.Helper()
		var body *bytes.Reader
		if payload != nil {
			b, err := json.Marshal(payload)
			require.NoError(t, err)
			body = bytes.NewReader(b)
		} else {
			body = bytes.NewReader(nil)
		}
		req, err := http.NewRequest(method, ts.URL+path, body)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer sk-gw-master-admin-key")
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		out := bytesFromReader(t, resp.Body)
		require.Equal(t, want, resp.StatusCode, "body=%s", string(out))
		return out
	}

	// 1. MCP Server create -> update -> sync -> toolset -> user credential -> spec update
	mcpRaw := adminDo(http.MethodPost, "/admin/v1/mcp/servers", map[string]any{
		"org_id": "org_default", "name": "Audit MCP", "slug": "audit-mcp",
		"protocol_version": "2026-07-28", "transport_type": "streamable_http",
		"endpoint_url": mockMCP.URL, "auth_type": "static", "auth_secret": "super-secret-mcp-token",
	}, http.StatusCreated)
	var mcpResp struct {
		Server domain.MCPServer `json:"server"`
	}
	require.NoError(t, json.Unmarshal(mcpRaw, &mcpResp))

	adminDo(http.MethodPut, "/admin/v1/mcp/servers/"+mcpResp.Server.ID, map[string]any{
		"name": "Audit MCP Renamed", "rpm_limit": 50,
	}, http.StatusOK)

	syncRaw := adminDo(http.MethodPost, "/admin/v1/mcp/servers/"+mcpResp.Server.ID+"/sync", nil, http.StatusOK)
	var syncResp struct {
		Tools []domain.MCPTool `json:"tools"`
	}
	require.NoError(t, json.Unmarshal(syncRaw, &syncResp))
	require.Len(t, syncResp.Tools, 1)

	adminDo(http.MethodPost, "/admin/v1/mcp/toolsets", map[string]any{
		"org_id": "org_default", "name": "Read Set", "slug": "read-set", "tool_ids": []string{syncResp.Tools[0].ID},
	}, http.StatusCreated)

	adminDo(http.MethodPost, "/admin/v1/mcp/credentials", map[string]any{
		"org_id": "org_default", "server_id": mcpResp.Server.ID, "user_id": "usr_mcp_1", "token": "byok-secret-token-xyz",
	}, http.StatusOK)

	adminDo(http.MethodPut, "/admin/v1/mcp/spec", map[string]any{
		"protocol_version": "2025-11-25",
	}, http.StatusOK)

	// 2. A2A Agent create -> kill-switch -> push-config
	a2aRaw := adminDo(http.MethodPost, "/admin/v1/a2a/agents", map[string]any{
		"org_id": "org_default", "name": "Audit A2A", "slug": "audit-a2a",
		"endpoint_url": mockMCP.URL, "auth_type": "bearer", "auth_secret": "a2a-secret-key-xyz",
	}, http.StatusCreated)
	var a2aResp struct {
		Agent domain.A2AAgent `json:"agent"`
	}
	require.NoError(t, json.Unmarshal(a2aRaw, &a2aResp))

	adminDo(http.MethodPost, "/admin/v1/a2a/agents/"+a2aResp.Agent.ID+"/kill-switch", map[string]any{
		"killed": true,
	}, http.StatusOK)

	require.NoError(t, repo.CreateA2ATask(ctx, &domain.A2ATask{
		ID: "task_audit_push_1", AgentID: a2aResp.Agent.ID, OrgID: "org_default", State: domain.A2ATaskStateSubmitted,
	}))
	adminDo(http.MethodPost, "/admin/v1/a2a/push-configs", map[string]any{
		"task_id": "task_audit_push_1", "target_url": "https://hooks.example.com/a2a", "auth_token": "push-secret-bearer-xyz",
	}, http.StatusCreated)

	// 3. Verify every audit record exists with before/after diffs and zero secret leakage
	logs, err := repo.ListAuditLogs(ctx, "org_default", 100)
	require.NoError(t, err)
	globalLogs, err := repo.ListAuditLogs(ctx, "", 100)
	require.NoError(t, err)
	allLogs := append(logs, globalLogs...)

	byAction := make(map[string]*domain.AuditLog)
	for _, l := range allLogs {
		if l != nil {
			byAction[l.Action] = l
		}
	}

	expectedActions := []string{
		"mcp_server.created",
		"mcp_server.updated",
		"mcp_server.synced",
		"mcp_toolset.created",
		"mcp_user_credential.saved",
		"mcp.spec.updated",
		"a2a_agent.created",
		"a2a_agent.kill_switch_updated",
		"a2a_push_config.created",
	}
	for _, act := range expectedActions {
		rec, ok := byAction[act]
		require.True(t, ok, "missing expected audit action %q", act)
		raw, err := json.Marshal(rec)
		require.NoError(t, err)
		s := string(raw)
		for _, secret := range []string{"super-secret-mcp-token", "byok-secret-token-xyz", "a2a-secret-key-xyz", "push-secret-bearer-xyz"} {
			assert.NotContains(t, s, secret, "audit action %q leaked secret", act)
		}
	}

	assert.Equal(t, "Audit MCP", byAction["mcp_server.updated"].BeforeValue["name"])
	assert.Equal(t, "Audit MCP Renamed", byAction["mcp_server.updated"].AfterValue["name"])
	assert.Equal(t, false, byAction["a2a_agent.kill_switch_updated"].BeforeValue["is_killed"])
	assert.Equal(t, true, byAction["a2a_agent.kill_switch_updated"].AfterValue["is_killed"])
	if tokVal, exists := byAction["a2a_push_config.created"].AfterValue["auth_token"]; exists {
		assert.Equal(t, "[REDACTED]", tokVal)
	}
	assert.Equal(t, "2025-11-25", byAction["mcp.spec.updated"].AfterValue["active_protocol_version"])
}

func TestA2ATaskAndSubscribeEndpointsEnforceRBACAndCustomAuthorizer(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	cfg := config.Default()
	cfg.Auth.MasterAdminKey = "sk-gw-master-admin-key"

	srv, err := server.New(cfg, repo, nil, nil)
	require.NoError(t, err)

	var denyAgent string
	var authzErr error
	srv.SetCustomAuthorizer(auth.AuthorizerFunc(func(_ context.Context, req *auth.AuthzRequest) (*auth.AuthzDecision, error) {
		if authzErr != nil {
			return nil, authzErr
		}
		if req.Action == auth.AuthzActionA2AInvoke && req.A2AAgent == denyAgent {
			return &auth.AuthzDecision{Allow: false, Reason: "blocked by custom A2A policy", ErrorCode: "a2a_custom_denied"}, nil
		}
		return &auth.AuthzDecision{Allow: true}, nil
	}))

	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	require.NoError(t, repo.CreateOrganization(ctx, &domain.Organization{ID: "org_default", Name: "Default", IsActive: true}))
	require.NoError(t, repo.CreateTeam(ctx, &domain.Team{ID: "team_a2a", OrgID: "org_default", Name: "A2A Team", IsActive: true}))
	require.NoError(t, repo.CreateA2AAgent(ctx, &domain.A2AAgent{
		ID:                 "agent_sub_1",
		OrgID:              "org_default",
		Name:               "Sub Agent",
		Slug:               "sub-agent",
		EndpointURL:        "https://agent.example.com/a2a",
		TaskVisibilityMode: domain.TaskVisibilityTeam,
		IsActive:           true,
	}))
	require.NoError(t, repo.CreateA2ATask(ctx, &domain.A2ATask{
		ID:           "task_sub_1",
		AgentID:      "agent_sub_1",
		OrgID:        "org_default",
		TeamID:       "team_a2a",
		VirtualKeyID: "vk_allowed_a2a",
		State:        domain.A2ATaskStateCompleted,
		CreatedAt:    time.Now().UTC(),
		UpdatedAt:    time.Now().UTC(),
	}))

	require.NoError(t, repo.CreateVirtualKey(ctx, &domain.VirtualKey{
		ID: "vk_allowed_a2a", KeyPrefix: "sk-gw-allow", KeyHash: auth.HashKey("sk-gw-allow-a2a-key"),
		OrgID: "org_default", TeamID: "team_a2a", Name: "Allowed A2A", IsActive: true,
		AllowedEndpoints: []string{"*"}, AllowedA2AAgents: []string{"sub-agent"},
	}))
	require.NoError(t, repo.CreateVirtualKey(ctx, &domain.VirtualKey{
		ID: "vk_denied_a2a", KeyPrefix: "sk-gw-deny", KeyHash: auth.HashKey("sk-gw-deny-a2a-key"),
		OrgID: "org_default", TeamID: "team_a2a", Name: "Denied A2A", IsActive: true,
		AllowedEndpoints: []string{"*"}, AllowedA2AAgents: []string{},
	}))

	call := func(method, path, key string) (*http.Response, string) {
		t.Helper()
		req, err := http.NewRequest(method, ts.URL+path, nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+key)
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		return resp, string(bytesFromReader(t, resp.Body))
	}

	// 1. Key with allowed_a2a_agents: [] MUST be denied 403 on :subscribe even when task visibility is "team"
	resp, body := call(http.MethodGet, "/a2a/v1/agents/sub-agent/tasks/task_sub_1:subscribe", "sk-gw-deny-a2a-key")
	assert.Equal(t, http.StatusForbidden, resp.StatusCode, "body=%s", body)
	assert.Contains(t, body, "a2a_agent_restricted")

	// 2. Allowed key succeeds on GetTask, ListTasks, and :subscribe when CustomAuthorizer allows
	for _, ep := range []struct{ method, path string }{
		{http.MethodGet, "/a2a/v1/agents/sub-agent/tasks"},
		{http.MethodGet, "/a2a/v1/agents/sub-agent/tasks/task_sub_1"},
		{http.MethodGet, "/a2a/v1/agents/sub-agent/tasks/task_sub_1:subscribe"},
	} {
		r, b := call(ep.method, ep.path, "sk-gw-allow-a2a-key")
		assert.Equal(t, http.StatusOK, r.StatusCode, "%s %s body=%s", ep.method, ep.path, b)
	}

	// 3. CustomAuthorizer denial blocks ALL task endpoints (List, Get, Cancel, Subscribe) with 403
	denyAgent = "sub-agent"
	for _, ep := range []struct{ method, path string }{
		{http.MethodGet, "/a2a/v1/agents/sub-agent/tasks"},
		{http.MethodGet, "/a2a/v1/agents/sub-agent/tasks/task_sub_1"},
		{http.MethodPost, "/a2a/v1/agents/sub-agent/tasks/task_sub_1:cancel"},
		{http.MethodGet, "/a2a/v1/agents/sub-agent/tasks/task_sub_1:subscribe"},
	} {
		r, b := call(ep.method, ep.path, "sk-gw-allow-a2a-key")
		assert.Equal(t, http.StatusForbidden, r.StatusCode, "%s %s body=%s", ep.method, ep.path, b)
		assert.True(t, strings.Contains(b, "a2a_custom_denied"), "%s %s body=%s", ep.method, ep.path, b)
	}

	// 4. CustomAuthorizer error fails closed with 503 on task endpoints
	denyAgent = ""
	authzErr = errors.New("policy service unreachable")
	r, b := call(http.MethodGet, "/a2a/v1/agents/sub-agent/tasks/task_sub_1", "sk-gw-allow-a2a-key")
	assert.Equal(t, http.StatusServiceUnavailable, r.StatusCode, "body=%s", b)
	assert.Contains(t, b, fmt.Sprintf("authorizer_unavailable"))
}
