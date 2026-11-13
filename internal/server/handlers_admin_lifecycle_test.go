package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
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

func doAdminJSONRequest(t *testing.T, handler http.Handler, method, path, bearer string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var reqBody *bytes.Reader
	if body != nil {
		b, err := json.Marshal(body)
		require.NoError(t, err)
		reqBody = bytes.NewReader(b)
	} else {
		reqBody = bytes.NewReader(nil)
	}
	req, err := http.NewRequest(method, path, reqBody)
	require.NoError(t, err)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func TestAdminLifecycle_TeamUserKeyUpdateDeleteRotate(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	cfg := config.Default()
	cfg.Auth.MasterAdminKey = "admin_master_secret"

	gw, err := server.New(cfg, repo, nil, nil)
	require.NoError(t, err)
	handler := gw.Handler()

	// Create two organizations for tenant isolation testing
	orgA := &domain.Organization{ID: "org_alpha", Name: "Alpha Org", IsActive: true}
	orgB := &domain.Organization{ID: "org_beta", Name: "Beta Org", IsActive: true}
	require.NoError(t, repo.CreateOrganization(ctx, orgA))
	require.NoError(t, repo.CreateOrganization(ctx, orgB))

	// Issue org_admin keys for org_alpha and org_beta
	orgAdminKeyA, err := gw.AuthService().IssueVirtualKey(ctx, &domain.VirtualKey{
		OrgID: "org_alpha",
		Name:  "alpha-admin",
		Role:  domain.RoleOrgAdmin,
	})
	require.NoError(t, err)

	orgAdminKeyB, err := gw.AuthService().IssueVirtualKey(ctx, &domain.VirtualKey{
		OrgID: "org_beta",
		Name:  "beta-admin",
		Role:  domain.RoleOrgAdmin,
	})
	require.NoError(t, err)

	// 1. Create Team & User in org_alpha
	rec := doAdminJSONRequest(t, handler, http.MethodPost, "/admin/v1/teams", orgAdminKeyA.RawKey, map[string]any{
		"id":                "team_alpha_1",
		"name":              "Core Platform",
		"max_budget_micros": 10_000_000,
	})
	require.Equal(t, http.StatusCreated, rec.Code)

	rec = doAdminJSONRequest(t, handler, http.MethodPost, "/admin/v1/users", orgAdminKeyA.RawKey, map[string]any{
		"id":      "user_alpha_1",
		"email":   "dev@alpha.io",
		"name":    "Alpha Dev",
		"team_id": "team_alpha_1",
		"role":    "developer",
	})
	require.Equal(t, http.StatusCreated, rec.Code)

	// 2. Update Team (success path)
	rec = doAdminJSONRequest(t, handler, http.MethodPut, "/admin/v1/teams/team_alpha_1", orgAdminKeyA.RawKey, map[string]any{
		"name":              "Core AI Platform",
		"max_budget_micros": 25_000_000,
		"rpm_limit":         120,
	})
	require.Equal(t, http.StatusOK, rec.Code)
	var updatedTeam domain.Team
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &updatedTeam))
	assert.Equal(t, "Core AI Platform", updatedTeam.Name)
	assert.Equal(t, int64(25_000_000), updatedTeam.MaxBudgetMicros)
	assert.Equal(t, 120, updatedTeam.RPMLimit)
	assert.True(t, updatedTeam.IsActive)

	// 3. Update User (success path)
	rec = doAdminJSONRequest(t, handler, http.MethodPut, "/admin/v1/users/user_alpha_1", orgAdminKeyA.RawKey, map[string]any{
		"email":             "lead@alpha.io",
		"name":              "Alpha Lead",
		"role":              "team_admin",
		"max_budget_micros": 5_000_000,
	})
	require.Equal(t, http.StatusOK, rec.Code)
	var updatedUser domain.User
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &updatedUser))
	assert.Equal(t, "lead@alpha.io", updatedUser.Email)
	assert.Equal(t, "Alpha Lead", updatedUser.Name)
	assert.Equal(t, domain.RoleTeamAdmin, updatedUser.Role)
	assert.Equal(t, int64(5_000_000), updatedUser.MaxBudgetMicros)
	assert.True(t, updatedUser.IsActive)

	// 4. Issue Virtual Key bound to team_alpha_1 and user_alpha_1
	rec = doAdminJSONRequest(t, handler, http.MethodPost, "/admin/v1/keys", orgAdminKeyA.RawKey, map[string]any{
		"id":                "vk_alpha_worker",
		"name":              "worker-key",
		"team_id":           "team_alpha_1",
		"user_id":           "user_alpha_1",
		"max_budget_micros": 2_000_000,
		"rpm_limit":         30,
	})
	require.Equal(t, http.StatusCreated, rec.Code)
	var issuedKey domain.VirtualKey
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &issuedKey))
	require.True(t, strings.HasPrefix(issuedKey.RawKey, "sk-gw-"))
	originalRawKey := issuedKey.RawKey

	// Verify original key authenticates on Data Plane (/v1/models)
	rec = doAdminJSONRequest(t, handler, http.MethodGet, "/v1/models", originalRawKey, nil)
	require.Equal(t, http.StatusOK, rec.Code)

	// 5. Cross-org denial: org_beta admin cannot update/delete/rotate org_alpha's team, user, or key
	rec = doAdminJSONRequest(t, handler, http.MethodPut, "/admin/v1/teams/team_alpha_1", orgAdminKeyB.RawKey, map[string]any{
		"name": "Hijacked Team",
	})
	assert.Equal(t, http.StatusForbidden, rec.Code)

	rec = doAdminJSONRequest(t, handler, http.MethodDelete, "/admin/v1/teams/team_alpha_1", orgAdminKeyB.RawKey, nil)
	assert.Equal(t, http.StatusForbidden, rec.Code)

	rec = doAdminJSONRequest(t, handler, http.MethodPut, "/admin/v1/users/user_alpha_1", orgAdminKeyB.RawKey, map[string]any{
		"name": "Hijacked User",
	})
	assert.Equal(t, http.StatusForbidden, rec.Code)

	rec = doAdminJSONRequest(t, handler, http.MethodDelete, "/admin/v1/users/user_alpha_1", orgAdminKeyB.RawKey, nil)
	assert.Equal(t, http.StatusForbidden, rec.Code)

	rec = doAdminJSONRequest(t, handler, http.MethodPut, "/admin/v1/keys/vk_alpha_worker", orgAdminKeyB.RawKey, map[string]any{
		"name": "hijacked-key",
	})
	assert.Equal(t, http.StatusForbidden, rec.Code)

	rec = doAdminJSONRequest(t, handler, http.MethodPost, "/admin/v1/keys/vk_alpha_worker/rotate", orgAdminKeyB.RawKey, nil)
	assert.Equal(t, http.StatusForbidden, rec.Code)

	// Cross-org query/body mismatch even with master admin key is rejected
	rec = doAdminJSONRequest(t, handler, http.MethodDelete, "/admin/v1/teams/team_alpha_1?org_id=org_beta", "admin_master_secret", nil)
	assert.Equal(t, http.StatusForbidden, rec.Code)

	// 6. Update Virtual Key persists changes and updates cached identity
	rec = doAdminJSONRequest(t, handler, http.MethodPut, "/admin/v1/keys/vk_alpha_worker", orgAdminKeyA.RawKey, map[string]any{
		"name":              "worker-key-v2",
		"max_budget_micros": 8_000_000,
		"rpm_limit":         90,
		"tpm_limit":         50000,
		"allowed_models":    []string{"openai/gpt-4o"},
	})
	require.Equal(t, http.StatusOK, rec.Code)
	var updatedKey domain.VirtualKey
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &updatedKey))
	assert.Equal(t, "worker-key-v2", updatedKey.Name)
	assert.Equal(t, int64(8_000_000), updatedKey.MaxBudgetMicros)
	assert.Equal(t, 90, updatedKey.RPMLimit)
	assert.Equal(t, 50000, updatedKey.TPMLimit)
	assert.Equal(t, []string{"openai/gpt-4o"}, updatedKey.AllowedModels)

	storedKey, err := repo.GetVirtualKeyByID(ctx, "vk_alpha_worker")
	require.NoError(t, err)
	assert.Equal(t, "worker-key-v2", storedKey.Name)
	assert.Equal(t, int64(8_000_000), storedKey.MaxBudgetMicros)
	assert.Equal(t, 90, storedKey.RPMLimit)

	// 7. Rotate Virtual Key: returns new sk-gw-... once, invalidates old key, new key works
	rec = doAdminJSONRequest(t, handler, http.MethodPost, "/admin/v1/keys/vk_alpha_worker/rotate", orgAdminKeyA.RawKey, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	var rotatedKey domain.VirtualKey
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &rotatedKey))
	require.True(t, strings.HasPrefix(rotatedKey.RawKey, "sk-gw-"))
	assert.NotEqual(t, originalRawKey, rotatedKey.RawKey)
	assert.Equal(t, "worker-key-v2", rotatedKey.Name)

	// Old key must fail authentication on Data Plane
	rec = doAdminJSONRequest(t, handler, http.MethodGet, "/v1/models", originalRawKey, nil)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)

	// New key must succeed on Data Plane
	rec = doAdminJSONRequest(t, handler, http.MethodGet, "/v1/models", rotatedKey.RawKey, nil)
	assert.Equal(t, http.StatusOK, rec.Code)

	// Subsequent GET /admin/v1/keys must NOT expose raw_key
	rec = doAdminJSONRequest(t, handler, http.MethodGet, "/admin/v1/keys", orgAdminKeyA.RawKey, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	var listKeysResp struct {
		Data []*domain.VirtualKey `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &listKeysResp))
	for _, k := range listKeysResp.Data {
		assert.Empty(t, k.RawKey, "raw_key must never be returned in listKeys")
	}

	// 8. Deleting Team or User while active Virtual Key exists must be rejected with HTTP 409 Conflict
	rec = doAdminJSONRequest(t, handler, http.MethodDelete, "/admin/v1/teams/team_alpha_1", orgAdminKeyA.RawKey, nil)
	assert.Equal(t, http.StatusConflict, rec.Code)
	assert.Contains(t, rec.Body.String(), "active virtual keys")

	rec = doAdminJSONRequest(t, handler, http.MethodDelete, "/admin/v1/users/user_alpha_1", orgAdminKeyA.RawKey, nil)
	assert.Equal(t, http.StatusConflict, rec.Code)
	assert.Contains(t, rec.Body.String(), "active virtual keys")

	// 9. Revoke the Virtual Key, then Delete User and Delete Team succeed
	rec = doAdminJSONRequest(t, handler, http.MethodPost, "/admin/v1/keys/vk_alpha_worker/revoke", orgAdminKeyA.RawKey, nil)
	require.Equal(t, http.StatusOK, rec.Code)

	rec = doAdminJSONRequest(t, handler, http.MethodDelete, "/admin/v1/users/user_alpha_1", orgAdminKeyA.RawKey, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	_, err = repo.GetUser(ctx, "user_alpha_1")
	assert.ErrorIs(t, err, storage.ErrNotFound)

	rec = doAdminJSONRequest(t, handler, http.MethodDelete, "/admin/v1/teams/team_alpha_1", orgAdminKeyA.RawKey, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	_, err = repo.GetTeam(ctx, "team_alpha_1")
	assert.ErrorIs(t, err, storage.ErrNotFound)

	// Verify audit logs recorded lifecycle actions
	auditLogs, err := repo.ListAuditLogs(ctx, "org_alpha", 50)
	require.NoError(t, err)
	actions := make(map[string]bool)
	for _, l := range auditLogs {
		actions[l.Action] = true
	}
	assert.True(t, actions["team.updated"])
	assert.True(t, actions["team.deleted"])
	assert.True(t, actions["user.updated"])
	assert.True(t, actions["user.deleted"])
	assert.True(t, actions["virtual_key.updated"])
	assert.True(t, actions["virtual_key.rotated"])
}

func TestAdminLifecycle_UpdateKeyAllowedEndpointsNilVsEmpty(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	cfg := config.Default()
	cfg.Auth.MasterAdminKey = "admin_master_secret"

	gw, err := server.New(cfg, repo, nil, nil)
	require.NoError(t, err)
	handler := gw.Handler()

	require.NoError(t, repo.CreateOrganization(ctx, &domain.Organization{ID: "org_ep", Name: "EP Org", IsActive: true}))
	issued, err := gw.AuthService().IssueVirtualKey(ctx, &domain.VirtualKey{
		OrgID:            "org_ep",
		Name:             "ep-key",
		AllowedEndpoints: []string{"/v1/chat/completions"},
	})
	require.NoError(t, err)

	// (a) Omitting allowed_endpoints preserves existing endpoints
	rec := doAdminJSONRequest(t, handler, http.MethodPut, "/admin/v1/keys/"+issued.ID, cfg.Auth.MasterAdminKey, map[string]any{
		"name": "ep-key-renamed",
	})
	require.Equal(t, http.StatusOK, rec.Code)
	var preserved domain.VirtualKey
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &preserved))
	assert.Equal(t, []string{"/v1/chat/completions"}, preserved.AllowedEndpoints)

	// (b) Sending "allowed_endpoints": [] clears allowed_endpoints to [] and fails closed (403)
	rec = doAdminJSONRequest(t, handler, http.MethodPut, "/admin/v1/keys/"+issued.ID, cfg.Auth.MasterAdminKey, map[string]any{
		"allowed_endpoints": []string{},
	})
	require.Equal(t, http.StatusOK, rec.Code)
	var cleared domain.VirtualKey
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &cleared))
	assert.Empty(t, cleared.AllowedEndpoints)

	dpRec := doAdminJSONRequest(t, handler, http.MethodPost, "/v1/chat/completions", issued.RawKey, map[string]any{
		"model":    "gpt-4.1",
		"messages": []map[string]string{{"role": "user", "content": "hi"}},
	})
	assert.Equal(t, http.StatusForbidden, dpRec.Code)
	assert.True(t, strings.Contains(dpRec.Body.String(), "endpoint_not_allowed"))
}

func TestAdminLifecycle_ThreeStateAllowlistsSerializationAndUpdate(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	cfg := config.Default()
	cfg.Auth.MasterAdminKey = "admin_master_secret"

	gw, err := server.New(cfg, repo, nil, nil)
	require.NoError(t, err)
	defer gw.Shutdown(ctx)
	handler := gw.Handler()

	require.NoError(t, repo.CreateOrganization(ctx, &domain.Organization{ID: "org_3s", Name: "3-State Org", IsActive: true}))

	// 1. Create Team with nil (Inherit) MCP, [] (DenyAll) A2A, and ["cursor"] ClientApps
	rec := doAdminJSONRequest(t, handler, http.MethodPost, "/admin/v1/teams", cfg.Auth.MasterAdminKey, map[string]any{
		"id":                  "team_3s",
		"org_id":              "org_3s",
		"name":                "3S Team",
		"allowed_mcp_servers": nil,
		"allowed_a2a_agents":  []string{},
		"allowed_client_apps": []string{"cursor"},
	})
	require.Equal(t, http.StatusCreated, rec.Code)

	// Verify GET /admin/v1/teams explicitly serializes null vs [] vs ["..."] without omitting nil fields
	rec = doAdminJSONRequest(t, handler, http.MethodGet, "/admin/v1/teams?org_id=org_3s", cfg.Auth.MasterAdminKey, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	var teamsListRaw struct {
		Data []map[string]json.RawMessage `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &teamsListRaw))
	require.Len(t, teamsListRaw.Data, 1)
	assert.Equal(t, "null", string(teamsListRaw.Data[0]["allowed_mcp_servers"]))
	assert.Equal(t, "[]", string(teamsListRaw.Data[0]["allowed_a2a_agents"]))
	assert.Equal(t, `["cursor"]`, string(teamsListRaw.Data[0]["allowed_client_apps"]))

	// 2. PUT team omitting allowlists preserves existing nil / [] / ["cursor"], while updating name
	rec = doAdminJSONRequest(t, handler, http.MethodPut, "/admin/v1/teams/team_3s", cfg.Auth.MasterAdminKey, map[string]any{
		"name": "3S Team Updated",
	})
	require.Equal(t, http.StatusOK, rec.Code)
	storedTeam, err := repo.GetTeam(ctx, "team_3s")
	require.NoError(t, err)
	assert.Nil(t, storedTeam.AllowedMCPServers)
	assert.NotNil(t, storedTeam.AllowedA2AAgents)
	assert.Empty(t, storedTeam.AllowedA2AAgents)
	assert.Equal(t, []string{"cursor"}, storedTeam.AllowedClientApps)

	// 3. PUT team setting MCP to [] (DenyAll), A2A to null (Inherit), ClientApps to null (Inherit), AllowedModels to ["gpt-4o"] then null
	rec = doAdminJSONRequest(t, handler, http.MethodPut, "/admin/v1/teams/team_3s", cfg.Auth.MasterAdminKey, map[string]any{
		"allowed_models":      []string{"gpt-4o"},
		"allowed_mcp_servers": []string{},
		"allowed_a2a_agents":  nil,
		"allowed_client_apps": nil,
	})
	require.Equal(t, http.StatusOK, rec.Code)
	storedTeam, err = repo.GetTeam(ctx, "team_3s")
	require.NoError(t, err)
	assert.Equal(t, []string{"gpt-4o"}, storedTeam.AllowedModels)
	assert.NotNil(t, storedTeam.AllowedMCPServers)
	assert.Empty(t, storedTeam.AllowedMCPServers)
	assert.Nil(t, storedTeam.AllowedA2AAgents)
	assert.Nil(t, storedTeam.AllowedClientApps)

	// Reset allowed_models to null
	rec = doAdminJSONRequest(t, handler, http.MethodPut, "/admin/v1/teams/team_3s", cfg.Auth.MasterAdminKey, map[string]any{
		"allowed_models": nil,
	})
	require.Equal(t, http.StatusOK, rec.Code)
	storedTeam, err = repo.GetTeam(ctx, "team_3s")
	require.NoError(t, err)
	assert.Nil(t, storedTeam.AllowedModels)

	// 4. Issue Virtual Key with 3-state allowlists (nil Inherit, [] DenyAll, ["vscode"] Allowlist)
	issued, err := gw.AuthService().IssueVirtualKey(ctx, &domain.VirtualKey{
		ID:                "vk_3s",
		OrgID:             "org_3s",
		TeamID:            "team_3s",
		Name:              "3s-key",
		AllowedMCPServers: nil,
		AllowedA2AAgents:  []string{},
		AllowedClientApps: []string{"vscode"},
	})
	require.NoError(t, err)

	// Note: IssueVirtualKey defaults nil 3-state allowlists to []string{} (DenyAll) at creation;
	// verify GET /admin/v1/keys serializes [] (never omitted), then update to null (Inherit) via PUT.
	rec = doAdminJSONRequest(t, handler, http.MethodGet, "/admin/v1/keys?org_id=org_3s", cfg.Auth.MasterAdminKey, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	var keysListRaw struct {
		Data []map[string]json.RawMessage `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &keysListRaw))
	require.Len(t, keysListRaw.Data, 1)
	assert.Equal(t, "[]", string(keysListRaw.Data[0]["allowed_mcp_servers"]))
	assert.Equal(t, "[]", string(keysListRaw.Data[0]["allowed_a2a_agents"]))
	assert.Equal(t, `["vscode"]`, string(keysListRaw.Data[0]["allowed_client_apps"]))

	// 5. PUT key: revert allowed_mcp_servers & allowed_client_apps to null (Inherit), keep allowed_a2a_agents omitted (stays []), set allowed_models
	rec = doAdminJSONRequest(t, handler, http.MethodPut, "/admin/v1/keys/"+issued.ID, cfg.Auth.MasterAdminKey, map[string]any{
		"allowed_models":      []string{"claude-3-5-sonnet"},
		"allowed_mcp_servers": nil,
		"allowed_client_apps": nil,
	})
	require.Equal(t, http.StatusOK, rec.Code)
	var keyRespRaw map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &keyRespRaw))
	assert.Equal(t, "null", string(keyRespRaw["allowed_mcp_servers"]))
	assert.Equal(t, "[]", string(keyRespRaw["allowed_a2a_agents"]))
	assert.Equal(t, "null", string(keyRespRaw["allowed_client_apps"]))

	storedKey, err := repo.GetVirtualKeyByID(ctx, issued.ID)
	require.NoError(t, err)
	assert.Nil(t, storedKey.AllowedMCPServers)
	assert.NotNil(t, storedKey.AllowedA2AAgents)
	assert.Empty(t, storedKey.AllowedA2AAgents)
	assert.Nil(t, storedKey.AllowedClientApps)
	assert.Equal(t, []string{"claude-3-5-sonnet"}, storedKey.AllowedModels)

	// Verify GET /admin/v1/keys reflects the updated null vs [] distinction
	rec = doAdminJSONRequest(t, handler, http.MethodGet, "/admin/v1/keys?org_id=org_3s", cfg.Auth.MasterAdminKey, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &keysListRaw))
	require.Len(t, keysListRaw.Data, 1)
	assert.Equal(t, "null", string(keysListRaw.Data[0]["allowed_mcp_servers"]))
	assert.Equal(t, "[]", string(keysListRaw.Data[0]["allowed_a2a_agents"]))
	assert.Equal(t, "null", string(keysListRaw.Data[0]["allowed_client_apps"]))

	// 6. PUT key: transition allowed_a2a_agents from [] -> ["agent-x"], allowed_client_apps from null -> [] (DenyAll), allowed_models -> null
	rec = doAdminJSONRequest(t, handler, http.MethodPut, "/admin/v1/keys/"+issued.ID, cfg.Auth.MasterAdminKey, map[string]any{
		"allowed_models":      nil,
		"allowed_a2a_agents":  []string{"agent-x"},
		"allowed_client_apps": []string{},
	})
	require.Equal(t, http.StatusOK, rec.Code)
	storedKey, err = repo.GetVirtualKeyByID(ctx, issued.ID)
	require.NoError(t, err)
	assert.Nil(t, storedKey.AllowedModels)
	assert.Nil(t, storedKey.AllowedMCPServers)
	assert.Equal(t, []string{"agent-x"}, storedKey.AllowedA2AAgents)
	assert.NotNil(t, storedKey.AllowedClientApps)
	assert.Empty(t, storedKey.AllowedClientApps)
}

func TestAdminLifecycle_KeyRotationGracePeriodHeadersAndExpiry(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	cfg := config.Default()
	cfg.Auth.MasterAdminKey = "admin_master_secret"

	gw, err := server.New(cfg, repo, nil, nil)
	require.NoError(t, err)
	defer gw.Shutdown(ctx)
	handler := gw.Handler()

	var clockMu sync.RWMutex
	now := time.Date(2026, 11, 18, 14, 0, 0, 0, time.UTC)
	gw.AuthService().SetNowFunc(func() time.Time {
		clockMu.RLock()
		defer clockMu.RUnlock()
		return now
	})
	advance := func(d time.Duration) {
		clockMu.Lock()
		now = now.Add(d)
		clockMu.Unlock()
	}

	require.NoError(t, repo.CreateOrganization(ctx, &domain.Organization{ID: "org_grace", Name: "Grace Org", IsActive: true}))

	// 1. Issue key with key_type=llm_api and rotation_interval_sec=3600
	rec := doAdminJSONRequest(t, handler, http.MethodPost, "/admin/v1/keys", cfg.Auth.MasterAdminKey, map[string]any{
		"org_id":                "org_grace",
		"name":                  "rotatable-llm-key",
		"key_type":              "llm_api",
		"rotation_interval_sec": 3600,
	})
	require.Equal(t, http.StatusCreated, rec.Code)
	var issued domain.VirtualKey
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &issued))
	assert.Equal(t, domain.KeyTypeLLMAPI, issued.KeyType)
	assert.Equal(t, int64(3600), issued.RotationIntervalSec)
	require.NotNil(t, issued.KeyRotationAt)
	assert.True(t, issued.KeyRotationAt.Equal(now.Add(3600*time.Second)))
	oldRawKey := issued.RawKey
	require.True(t, strings.HasPrefix(oldRawKey, "sk-gw-"))

	// Negative grace_period_seconds must be rejected with 400
	rec = doAdminJSONRequest(t, handler, http.MethodPost, "/admin/v1/keys/"+issued.ID+"/rotate", cfg.Auth.MasterAdminKey, map[string]any{
		"grace_period_seconds": -10,
	})
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "invalid_grace_period")

	// 2. Rotate with 300s grace period
	advance(60 * time.Second)
	expectedRevokeAt := now.Add(300 * time.Second)
	expectedNextRotation := now.Add(3600 * time.Second)

	rec = doAdminJSONRequest(t, handler, http.MethodPost, "/admin/v1/keys/"+issued.ID+"/rotate", cfg.Auth.MasterAdminKey, map[string]any{
		"grace_period_seconds": 300,
	})
	require.Equal(t, http.StatusOK, rec.Code)
	var rotated domain.VirtualKey
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &rotated))
	newRawKey := rotated.RawKey
	assert.NotEqual(t, oldRawKey, newRawKey)
	require.NotNil(t, rotated.KeyRotationAt)
	assert.True(t, rotated.KeyRotationAt.Equal(expectedNextRotation))

	// 3. Old key still works on Data Plane during grace period and emits deprecation headers
	recOld := doAdminJSONRequest(t, handler, http.MethodGet, "/v1/models", oldRawKey, nil)
	require.Equal(t, http.StatusOK, recOld.Code)
	assert.Equal(t, "true", recOld.Header().Get(auth.HeaderKeyDeprecated))
	assert.Equal(t, expectedRevokeAt.Format(time.RFC3339), recOld.Header().Get(auth.HeaderKeyRevokeAt))

	// New key works on Data Plane without deprecation headers
	recNew := doAdminJSONRequest(t, handler, http.MethodGet, "/v1/models", newRawKey, nil)
	require.Equal(t, http.StatusOK, recNew.Code)
	assert.Empty(t, recNew.Header().Get(auth.HeaderKeyDeprecated))
	assert.Empty(t, recNew.Header().Get(auth.HeaderKeyRevokeAt))

	// 4. Advance past revoke_at: old key fails with 401, new key remains valid
	advance(301 * time.Second)
	recExpired := doAdminJSONRequest(t, handler, http.MethodGet, "/v1/models", oldRawKey, nil)
	assert.Equal(t, http.StatusUnauthorized, recExpired.Code)

	recNewAfter := doAdminJSONRequest(t, handler, http.MethodGet, "/v1/models", newRawKey, nil)
	assert.Equal(t, http.StatusOK, recNewAfter.Code)

	// 5. PUT /admin/v1/keys/{keyID} updates rotation_interval_sec (and clears schedule when set to 0)
	rec = doAdminJSONRequest(t, handler, http.MethodPut, "/admin/v1/keys/"+issued.ID, cfg.Auth.MasterAdminKey, map[string]any{
		"rotation_interval_sec": -1,
	})
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	rec = doAdminJSONRequest(t, handler, http.MethodPut, "/admin/v1/keys/"+issued.ID, cfg.Auth.MasterAdminKey, map[string]any{
		"rotation_interval_sec": 7200,
	})
	require.Equal(t, http.StatusOK, rec.Code)
	var updated domain.VirtualKey
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &updated))
	assert.Equal(t, int64(7200), updated.RotationIntervalSec)
	assert.NotNil(t, updated.KeyRotationAt)

	rec = doAdminJSONRequest(t, handler, http.MethodPut, "/admin/v1/keys/"+issued.ID, cfg.Auth.MasterAdminKey, map[string]any{
		"rotation_interval_sec": 0,
	})
	require.Equal(t, http.StatusOK, rec.Code)
	var disabled domain.VirtualKey
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &disabled))
	assert.Equal(t, int64(0), disabled.RotationIntervalSec)
	assert.Nil(t, disabled.KeyRotationAt)
}

func TestAdminLifecycle_KeyTypePresetsEnforcement(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	cfg := config.Default()
	cfg.Auth.MasterAdminKey = "admin_master_secret"

	gw, err := server.New(cfg, repo, nil, nil)
	require.NoError(t, err)
	defer gw.Shutdown(ctx)
	handler := gw.Handler()

	require.NoError(t, repo.CreateOrganization(ctx, &domain.Organization{ID: "org_presets", Name: "Presets Org", IsActive: true}))
	require.NoError(t, repo.CreateUser(ctx, &domain.User{
		ID:       "usr_preset_1",
		OrgID:    "org_presets",
		Email:    "dev@presets.io",
		Name:     "Preset Dev",
		Role:     domain.RoleDeveloper,
		IsActive: true,
	}))

	// Invalid key_type rejected with 400 on POST
	rec := doAdminJSONRequest(t, handler, http.MethodPost, "/admin/v1/keys", cfg.Auth.MasterAdminKey, map[string]any{
		"org_id":   "org_presets",
		"name":     "bad-type",
		"key_type": "unknown_preset",
	})
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "invalid_key_type")

	// 1. llm_api key: allowed on Data Plane (/v1/models), denied on Control Plane (/admin/v1/keys)
	rec = doAdminJSONRequest(t, handler, http.MethodPost, "/admin/v1/keys", cfg.Auth.MasterAdminKey, map[string]any{
		"org_id":   "org_presets",
		"name":     "llm-only-key",
		"key_type": "llm_api",
		"role":     "org_admin", // Preset must enforce non-admin role for llm_api
	})
	require.Equal(t, http.StatusCreated, rec.Code)
	var llmKey domain.VirtualKey
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &llmKey))
	assert.Equal(t, domain.KeyTypeLLMAPI, llmKey.KeyType)
	assert.Equal(t, domain.RoleServiceAccount, llmKey.Role)
	assert.Equal(t, domain.DefaultAllowedEndpoints, llmKey.AllowedEndpoints)

	rec = doAdminJSONRequest(t, handler, http.MethodGet, "/v1/models", llmKey.RawKey, nil)
	assert.Equal(t, http.StatusOK, rec.Code)
	rec = doAdminJSONRequest(t, handler, http.MethodGet, "/admin/v1/keys?org_id=org_presets", llmKey.RawKey, nil)
	assert.Equal(t, http.StatusForbidden, rec.Code)

	// 2. management key: allowed on /admin/v1/*, denied on Data Plane (/v1/models)
	rec = doAdminJSONRequest(t, handler, http.MethodPost, "/admin/v1/keys", cfg.Auth.MasterAdminKey, map[string]any{
		"org_id":   "org_presets",
		"name":     "mgmt-key",
		"key_type": "management",
	})
	require.Equal(t, http.StatusCreated, rec.Code)
	var mgmtKey domain.VirtualKey
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &mgmtKey))
	assert.Equal(t, domain.KeyTypeManagement, mgmtKey.KeyType)
	assert.Equal(t, domain.RoleOrgAdmin, mgmtKey.Role)
	assert.Equal(t, []string{"/admin/v1/*"}, mgmtKey.AllowedEndpoints)

	rec = doAdminJSONRequest(t, handler, http.MethodGet, "/admin/v1/keys?org_id=org_presets", mgmtKey.RawKey, nil)
	assert.Equal(t, http.StatusOK, rec.Code)
	rec = doAdminJSONRequest(t, handler, http.MethodGet, "/v1/models", mgmtKey.RawKey, nil)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), "endpoint_not_allowed")

	// Rotate management key with grace period and verify deprecation header on /admin/v1/keys too
	oldMgmtRawKey := mgmtKey.RawKey
	rec = doAdminJSONRequest(t, handler, http.MethodPost, "/admin/v1/keys/"+mgmtKey.ID+"/rotate", cfg.Auth.MasterAdminKey, map[string]any{
		"grace_period_seconds": 120,
	})
	require.Equal(t, http.StatusOK, rec.Code)
	rec = doAdminJSONRequest(t, handler, http.MethodGet, "/admin/v1/keys?org_id=org_presets", oldMgmtRawKey, nil)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "true", rec.Header().Get(auth.HeaderKeyDeprecated))
	assert.NotEmpty(t, rec.Header().Get(auth.HeaderKeyRevokeAt))

	// 3. read_only key: GET /v1/models & GET /admin/v1/keys allowed; POST /v1/chat/completions, POST /v1/files, POST /admin/v1/keys blocked
	rec = doAdminJSONRequest(t, handler, http.MethodPost, "/admin/v1/keys", cfg.Auth.MasterAdminKey, map[string]any{
		"org_id":   "org_presets",
		"name":     "ro-key",
		"key_type": "read_only",
		"role":     "org_admin", // Preset must clamp to org_viewer
	})
	require.Equal(t, http.StatusCreated, rec.Code)
	var roKey domain.VirtualKey
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &roKey))
	assert.Equal(t, domain.KeyTypeReadOnly, roKey.KeyType)
	assert.Equal(t, domain.RoleOrgViewer, roKey.Role)

	rec = doAdminJSONRequest(t, handler, http.MethodGet, "/v1/models", roKey.RawKey, nil)
	assert.Equal(t, http.StatusOK, rec.Code)
	rec = doAdminJSONRequest(t, handler, http.MethodGet, "/admin/v1/keys?org_id=org_presets", roKey.RawKey, nil)
	assert.Equal(t, http.StatusOK, rec.Code)
	rec = doAdminJSONRequest(t, handler, http.MethodPost, "/v1/chat/completions", roKey.RawKey, map[string]any{
		"model":    "gpt-4.1",
		"messages": []map[string]string{{"role": "user", "content": "hi"}},
	})
	assert.Equal(t, http.StatusForbidden, rec.Code)
	rec = doAdminJSONRequest(t, handler, http.MethodPost, "/v1/files", roKey.RawKey, nil)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), "read_only_key")
	rec = doAdminJSONRequest(t, handler, http.MethodPost, "/admin/v1/keys", roKey.RawKey, map[string]any{
		"org_id": "org_presets",
		"name":   "should-fail",
	})
	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Body.String(), "read_only_role")

	// 4. service_account key: enforces RoleServiceAccount and clears UserID
	rec = doAdminJSONRequest(t, handler, http.MethodPost, "/admin/v1/keys", cfg.Auth.MasterAdminKey, map[string]any{
		"org_id":   "org_presets",
		"name":     "sa-key",
		"key_type": "service_account",
		"user_id":  "usr_preset_1",
		"role":     "developer",
	})
	require.Equal(t, http.StatusCreated, rec.Code)
	var saKey domain.VirtualKey
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &saKey))
	assert.Equal(t, domain.KeyTypeServiceAccount, saKey.KeyType)
	assert.Equal(t, domain.RoleServiceAccount, saKey.Role)
	assert.Empty(t, saKey.UserID)

	rec = doAdminJSONRequest(t, handler, http.MethodGet, "/v1/models", saKey.RawKey, nil)
	assert.Equal(t, http.StatusOK, rec.Code)
	rec = doAdminJSONRequest(t, handler, http.MethodGet, "/admin/v1/keys?org_id=org_presets", saKey.RawKey, nil)
	assert.Equal(t, http.StatusForbidden, rec.Code)

	// 5. PUT /admin/v1/keys/{keyID} changing key_type from llm_api -> management updates preset routes & role
	rec = doAdminJSONRequest(t, handler, http.MethodPut, "/admin/v1/keys/"+llmKey.ID, cfg.Auth.MasterAdminKey, map[string]any{
		"key_type": "invalid_preset",
	})
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	rec = doAdminJSONRequest(t, handler, http.MethodPut, "/admin/v1/keys/"+llmKey.ID, cfg.Auth.MasterAdminKey, map[string]any{
		"key_type": "management",
	})
	require.Equal(t, http.StatusOK, rec.Code)
	var switched domain.VirtualKey
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &switched))
	assert.Equal(t, domain.KeyTypeManagement, switched.KeyType)
	assert.Equal(t, domain.RoleOrgAdmin, switched.Role)
	assert.Equal(t, []string{"/admin/v1/*"}, switched.AllowedEndpoints)

	rec = doAdminJSONRequest(t, handler, http.MethodGet, "/v1/models", llmKey.RawKey, nil)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	rec = doAdminJSONRequest(t, handler, http.MethodGet, "/admin/v1/keys?org_id=org_presets", llmKey.RawKey, nil)
	assert.Equal(t, http.StatusOK, rec.Code)
}
