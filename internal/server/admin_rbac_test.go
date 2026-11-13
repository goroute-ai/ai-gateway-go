package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/server"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

func TestAdminRBAC_DataPlaneMasterKeyDisabled_JWT_AuditLogs_And_MCPTools(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()

	_ = repo.CreateOrganization(ctx, &domain.Organization{ID: "org_a", Name: "Org A", Slug: "org-a", IsActive: true})
	_ = repo.CreateOrganization(ctx, &domain.Organization{ID: "org_b", Name: "Org B", Slug: "org-b", IsActive: true})

	_ = repo.CreateUser(ctx, &domain.User{
		ID:          "usr_admin_a",
		OrgID:       "org_a",
		Email:       "admin@orga.example",
		Name:        "Org A Admin",
		Role:        domain.RoleOrgAdmin,
		OIDCSubject: "oidc-admin-a",
		IsActive:    true,
	})
	_ = repo.CreateUser(ctx, &domain.User{
		ID:          "usr_viewer_a",
		OrgID:       "org_a",
		Email:       "viewer@orga.example",
		Name:        "Org A Viewer",
		Role:        domain.RoleViewer,
		OIDCSubject: "oidc-viewer-a",
		IsActive:    true,
	})

	// Seed an MCP server & tool in org_a for GET /admin/v1/mcp/tools
	_ = repo.CreateMCPServer(ctx, &domain.MCPServer{
		ID:            "mcp_srv_a",
		OrgID:         "org_a",
		Name:          "Org A Tools",
		Slug:          "orga-tools",
		TransportType: domain.MCPTransportStreamableHTTP,
		EndpointURL:   "https://mcp.orga.example/mcp",
		IsActive:      true,
	})
	_ = repo.UpsertMCPTools(ctx, "mcp_srv_a", "org_a", []*domain.MCPTool{
		{
			ID:          "tool_a_1",
			ServerID:    "mcp_srv_a",
			OrgID:       "org_a",
			Name:        "search_docs",
			Description: "Search org A docs",
			IsActive:    true,
		},
	})

	cfg := config.Default()
	cfg.Auth.MasterAdminKey = "sk-gw-master-rbac-test-key"
	cfg.Auth.JWTSecret = "jwt-rbac-test-secret-key"
	cfg.Auth.JWTIssuer = "https://idp.example.com"
	cfg.Auth.JWTAudience = "ai-gateway"
	cfg.Auth.DefaultOrgID = "org_a"
	cfg.MCP.Enabled = true

	gw, err := server.New(cfg, repo, nil, nil)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	gw.StartWorkers(ctx)
	defer gw.Shutdown(ctx)

	ts := httptest.NewServer(gw.Handler())
	defer ts.Close()

	doReq := func(method, path, token string, body any) (int, map[string]any) {
		t.Helper()
		var buf bytes.Buffer
		if body != nil {
			_ = json.NewEncoder(&buf).Encode(body)
		}
		req, _ := http.NewRequest(method, ts.URL+path, &buf)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s %s failed: %v", method, path, err)
		}
		defer resp.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}

	// 1. MasterAdminKey must be rejected on data-plane endpoints (/v1/chat/completions and /mcp) by default
	status, out := doReq(http.MethodPost, "/v1/chat/completions", cfg.Auth.MasterAdminKey, map[string]any{
		"model":    "gpt-4o",
		"messages": []map[string]string{{"role": "user", "content": "hi"}},
	})
	if status != http.StatusUnauthorized {
		t.Fatalf("expected 401 for MasterAdminKey on /v1/chat/completions, got %d (%v)", status, out)
	}
	if errObj, _ := out["error"].(map[string]any); errObj["code"] != "invalid_api_key" {
		t.Fatalf("expected error code invalid_api_key, got %v", out)
	}

	status, _ = doReq(http.MethodPost, "/mcp", cfg.Auth.MasterAdminKey, map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/list",
	})
	if status != http.StatusUnauthorized {
		t.Fatalf("expected 401 for MasterAdminKey on /mcp, got %d", status)
	}

	// Mint HS256 JWTs for org_admin and org_viewer
	exp := time.Now().UTC().Add(10 * time.Minute).Unix()
	adminJWT, err := auth.SignHS256(cfg.Auth.JWTSecret, &auth.JWTClaims{
		Subject:   "oidc-admin-a",
		Issuer:    cfg.Auth.JWTIssuer,
		Audience:  auth.AudienceClaim{cfg.Auth.JWTAudience},
		ExpiresAt: exp,
	})
	if err != nil {
		t.Fatalf("sign admin jwt: %v", err)
	}
	viewerJWT, err := auth.SignHS256(cfg.Auth.JWTSecret, &auth.JWTClaims{
		Subject:   "oidc-viewer-a",
		Issuer:    cfg.Auth.JWTIssuer,
		Audience:  auth.AudienceClaim{cfg.Auth.JWTAudience},
		ExpiresAt: exp,
	})
	if err != nil {
		t.Fatalf("sign viewer jwt: %v", err)
	}

	// 2. org_admin JWT: can create team in org_a, cannot create org globally, cannot access org_b
	status, _ = doReq(http.MethodPost, "/admin/v1/teams", adminJWT, map[string]any{
		"org_id": "org_a",
		"name":   "Alpha Team",
	})
	if status != http.StatusCreated {
		t.Fatalf("expected 201 creating team as org_admin in own org, got %d", status)
	}

	status, _ = doReq(http.MethodGet, "/admin/v1/teams?org_id=org_b", adminJWT, nil)
	if status != http.StatusForbidden {
		t.Fatalf("expected 403 for org_admin reading org_b, got %d", status)
	}

	status, _ = doReq(http.MethodPost, "/admin/v1/organizations", adminJWT, map[string]any{
		"name": "Rogue Org",
		"slug": "rogue",
	})
	if status != http.StatusForbidden {
		t.Fatalf("expected 403 for org_admin creating global organization, got %d", status)
	}

	status, _ = doReq(http.MethodPost, "/admin/v1/users", adminJWT, map[string]any{
		"org_id": "org_a",
		"email":  "escalate@orga.example",
		"name":   "Escalate",
		"role":   "platform_admin",
	})
	if status != http.StatusForbidden {
		t.Fatalf("expected 403 for org_admin creating platform_admin user, got %d", status)
	}

	// 3. org_viewer JWT: can read own org, denied on writes, denied on cross-org
	status, _ = doReq(http.MethodGet, "/admin/v1/teams", viewerJWT, nil)
	if status != http.StatusOK {
		t.Fatalf("expected 200 for org_viewer reading own org teams, got %d", status)
	}

	status, _ = doReq(http.MethodPost, "/admin/v1/teams", viewerJWT, map[string]any{
		"org_id": "org_a",
		"name":   "Viewer Should Fail",
	})
	if status != http.StatusForbidden {
		t.Fatalf("expected 403 for org_viewer writing team, got %d", status)
	}

	status, _ = doReq(http.MethodGet, "/admin/v1/teams?org_id=org_b", viewerJWT, nil)
	if status != http.StatusForbidden {
		t.Fatalf("expected 403 for org_viewer reading org_b, got %d", status)
	}

	// 4. Audit logs must record real ActorID ("usr_admin_a"), never hardcoded "admin"
	status, auditOut := doReq(http.MethodGet, "/admin/v1/audit/logs?org_id=org_a", viewerJWT, nil)
	if status != http.StatusOK {
		t.Fatalf("expected 200 for org_viewer reading audit logs, got %d", status)
	}
	logs, _ := auditOut["data"].([]any)
	if len(logs) == 0 {
		t.Fatalf("expected at least 1 audit log entry")
	}
	firstLog, _ := logs[0].(map[string]any)
	if firstLog["actor_id"] != "usr_admin_a" {
		t.Fatalf("expected audit actor_id usr_admin_a, got %v", firstLog["actor_id"])
	}

	// 5. GET /admin/v1/mcp/tools under AdminControlPlaneMiddleware
	status, _ = doReq(http.MethodGet, "/admin/v1/mcp/tools", "", nil)
	if status != http.StatusUnauthorized {
		t.Fatalf("expected 401 for unauthenticated GET /admin/v1/mcp/tools, got %d", status)
	}

	status, toolsOut := doReq(http.MethodGet, "/admin/v1/mcp/tools", viewerJWT, nil)
	if status != http.StatusOK {
		t.Fatalf("expected 200 for org_viewer GET /admin/v1/mcp/tools, got %d (%v)", status, toolsOut)
	}
	toolsList, _ := toolsOut["tools"].([]any)
	if len(toolsList) != 1 {
		t.Fatalf("expected 1 MCP tool for org_a, got %d (%v)", len(toolsList), toolsOut)
	}

	status, _ = doReq(http.MethodGet, "/admin/v1/mcp/tools?org_id=org_b", adminJWT, nil)
	if status != http.StatusForbidden {
		t.Fatalf("expected 403 for cross-org GET /admin/v1/mcp/tools, got %d", status)
	}

	status, toolsMaster := doReq(http.MethodGet, "/admin/v1/mcp/tools?org_id=org_a", cfg.Auth.MasterAdminKey, nil)
	if status != http.StatusOK {
		t.Fatalf("expected 200 for platform_admin GET /admin/v1/mcp/tools, got %d (%v)", status, toolsMaster)
	}
}
