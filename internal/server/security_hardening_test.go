package server_test

import (
	"bytes"
	"encoding/json"
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

func TestAdminCreateDeployment_CrossTenantCredentialRejected(t *testing.T) {
	ctx := t.Context()
	repo := storage.NewMemoryRepository()
	cfg := config.Default()
	cfg.Auth.MasterAdminKey = "sk-gw-master-admin-test-key"

	require.NoError(t, repo.CreateOrganization(ctx, &domain.Organization{ID: "org-1", Name: "Org 1", Slug: "org-1", IsActive: true}))
	require.NoError(t, repo.CreateOrganization(ctx, &domain.Organization{ID: "org-2", Name: "Org 2", Slug: "org-2", IsActive: true}))
	require.NoError(t, repo.CreateModelGroup(ctx, &domain.ModelGroup{ID: "mg-1", OrgID: "org-1", Alias: "fast"}))
	require.NoError(t, repo.CreateProviderCredential(ctx, &domain.ProviderCredential{
		ID:       "cred-org2",
		OrgID:    "org-2",
		Provider: domain.ProviderOpenAI,
		Name:     "org2-cred",
		IsActive: true,
	}))

	gw, err := server.New(cfg, repo, nil, nil)
	require.NoError(t, err)

	body := `{"model_group_id":"mg-1","global_model_id":"openai/gpt-4.1","credential_id":"cred-org2"}`
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/deployments", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+cfg.Auth.MasterAdminKey)
	rec := httptest.NewRecorder()
	gw.Handler().ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
}

func TestAdminCatalogueAndPricingHistory_RequireAuth(t *testing.T) {
	repo := storage.NewMemoryRepository()
	cfg := config.Default()
	cfg.Auth.MasterAdminKey = "sk-gw-master-admin-test-key"

	gw, err := server.New(cfg, repo, nil, nil)
	require.NoError(t, err)

	for _, path := range []string{"/admin/v1/catalogue", "/admin/v1/pricing/history"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		rec := httptest.NewRecorder()
		gw.Handler().ServeHTTP(rec, req)
		assert.Equal(t, http.StatusUnauthorized, rec.Code, "path %s must require auth", path)
	}
}

func TestAdminMCPToolsetAndCredential_CrossTenantRejected(t *testing.T) {
	ctx := t.Context()
	repo := storage.NewMemoryRepository()
	cfg := config.Default()
	cfg.Auth.MasterAdminKey = "sk-gw-master-admin-test-key"

	require.NoError(t, repo.CreateOrganization(ctx, &domain.Organization{ID: "org-1", Name: "Org 1", Slug: "org-1", IsActive: true}))
	require.NoError(t, repo.CreateOrganization(ctx, &domain.Organization{ID: "org-2", Name: "Org 2", Slug: "org-2", IsActive: true}))
	require.NoError(t, repo.CreateMCPServer(ctx, &domain.MCPServer{ID: "srv-org2", OrgID: "org-2", Name: "Org2 MCP", Slug: "org2-mcp", IsActive: true}))
	require.NoError(t, repo.UpsertMCPTools(ctx, "srv-org2", "org-2", []*domain.MCPTool{{ID: "tool-org2", ServerID: "srv-org2", Name: "t2"}}))
	require.NoError(t, repo.CreateUser(ctx, &domain.User{ID: "usr-org1", OrgID: "org-1", Email: "u1@example.com", Role: domain.RoleDeveloper, IsActive: true}))
	require.NoError(t, repo.CreateUser(ctx, &domain.User{ID: "usr-org2", OrgID: "org-2", Email: "u2@example.com", Role: domain.RoleDeveloper, IsActive: true}))

	gw, err := server.New(cfg, repo, nil, nil)
	require.NoError(t, err)

	// Cross-tenant tool in MCPToolset
	tsReq := httptest.NewRequest(http.MethodPost, "/admin/v1/mcp/toolsets", strings.NewReader(`{"org_id":"org-1","name":"ts","slug":"ts","tool_ids":["tool-org2"]}`))
	tsReq.Header.Set("Authorization", "Bearer "+cfg.Auth.MasterAdminKey)
	tsRec := httptest.NewRecorder()
	gw.Handler().ServeHTTP(tsRec, tsReq)
	assert.Equal(t, http.StatusForbidden, tsRec.Code)

	// Cross-tenant server in MCPUserCredential
	credReq := httptest.NewRequest(http.MethodPost, "/admin/v1/mcp/credentials", strings.NewReader(`{"org_id":"org-1","server_id":"srv-org2","user_id":"usr-org1","token":"tok"}`))
	credReq.Header.Set("Authorization", "Bearer "+cfg.Auth.MasterAdminKey)
	credRec := httptest.NewRecorder()
	gw.Handler().ServeHTTP(credRec, credReq)
	assert.Equal(t, http.StatusForbidden, credRec.Code)

	// Cross-tenant user in MCPUserCredential
	require.NoError(t, repo.CreateMCPServer(ctx, &domain.MCPServer{ID: "srv-org1", OrgID: "org-1", Name: "Org1 MCP", Slug: "org1-mcp", IsActive: true}))
	credReq2 := httptest.NewRequest(http.MethodPost, "/admin/v1/mcp/credentials", strings.NewReader(`{"org_id":"org-1","server_id":"srv-org1","user_id":"usr-org2","token":"tok"}`))
	credReq2.Header.Set("Authorization", "Bearer "+cfg.Auth.MasterAdminKey)
	credRec2 := httptest.NewRecorder()
	gw.Handler().ServeHTTP(credRec2, credReq2)
	assert.Equal(t, http.StatusForbidden, credRec2.Code)
}

func TestAdminSetA2APushConfig_TaskNotFoundReturns404(t *testing.T) {
	repo := storage.NewMemoryRepository()
	cfg := config.Default()
	cfg.Auth.MasterAdminKey = "sk-gw-master-admin-test-key"

	gw, err := server.New(cfg, repo, nil, nil)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/admin/v1/a2a/push-configs", strings.NewReader(`{"task_id":"missing-task","target_url":"https://webhook.example.com/hook"}`))
	req.Header.Set("Authorization", "Bearer "+cfg.Auth.MasterAdminKey)
	rec := httptest.NewRecorder()
	gw.Handler().ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestAdminMaxBytesReader_RejectsOversizedBody(t *testing.T) {
	repo := storage.NewMemoryRepository()
	cfg := config.Default()
	cfg.Auth.MasterAdminKey = "sk-gw-master-admin-test-key"

	gw, err := server.New(cfg, repo, nil, nil)
	require.NoError(t, err)

	oversized, _ := json.Marshal(map[string]string{
		"name": strings.Repeat("a", 3<<20), // 3 MiB > 2 MiB limit
	})
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/organizations", bytes.NewReader(oversized))
	req.Header.Set("Authorization", "Bearer "+cfg.Auth.MasterAdminKey)
	rec := httptest.NewRecorder()
	gw.Handler().ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

func TestInboundCallerAndTrustedRealIPMiddleware(t *testing.T) {
	t.Run("ExposeOnPublicInternet false blocks public IP and ignores spoofed X-Forwarded-For", func(t *testing.T) {
		repo := storage.NewMemoryRepository()
		cfg := config.Default()
		cfg.Security.Network.InboundCaller.ExposeOnPublicInternet = false

		gw, err := server.New(cfg, repo, nil, nil)
		require.NoError(t, err)

		req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		req.RemoteAddr = "8.8.8.8:44321"
		req.Header.Set("X-Forwarded-For", "127.0.0.1")
		rec := httptest.NewRecorder()
		gw.Handler().ServeHTTP(rec, req)
		assert.Equal(t, http.StatusForbidden, rec.Code)

		localReq := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		localReq.RemoteAddr = "127.0.0.1:44321"
		localRec := httptest.NewRecorder()
		gw.Handler().ServeHTTP(localRec, localReq)
		assert.Equal(t, http.StatusOK, localRec.Code)
	})

	t.Run("AllowedClientCIDRs and TrustedProxyCIDRs enforce caller IP", func(t *testing.T) {
		repo := storage.NewMemoryRepository()
		cfg := config.Default()
		cfg.Security.Network.InboundCaller.AllowedClientCIDRs = []string{"10.20.0.0/16"}
		cfg.Security.Network.InboundCaller.TrustedProxyCIDRs = []string{"10.0.0.0/24"}

		gw, err := server.New(cfg, repo, nil, nil)
		require.NoError(t, err)

		// Untrusted proxy spoofing X-Forwarded-For -> rejected
		spoofReq := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		spoofReq.RemoteAddr = "192.168.1.10:1234"
		spoofReq.Header.Set("X-Forwarded-For", "10.20.1.5")
		spoofRec := httptest.NewRecorder()
		gw.Handler().ServeHTTP(spoofRec, spoofReq)
		assert.Equal(t, http.StatusForbidden, spoofRec.Code)

		// Trusted proxy forwarding allowed client IP -> allowed
		proxyReq := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		proxyReq.RemoteAddr = "10.0.0.5:1234"
		proxyReq.Header.Set("X-Forwarded-For", "10.20.1.5")
		proxyRec := httptest.NewRecorder()
		gw.Handler().ServeHTTP(proxyRec, proxyReq)
		assert.Equal(t, http.StatusOK, proxyRec.Code)

		// Trusted proxy forwarding disallowed client IP -> rejected
		blockedReq := httptest.NewRequest(http.MethodGet, "/healthz", nil)
		blockedReq.RemoteAddr = "10.0.0.5:1234"
		blockedReq.Header.Set("X-Forwarded-For", "10.30.1.5")
		blockedRec := httptest.NewRecorder()
		gw.Handler().ServeHTTP(blockedRec, blockedReq)
		assert.Equal(t, http.StatusForbidden, blockedRec.Code)
	})
}
