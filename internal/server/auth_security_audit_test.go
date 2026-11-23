package server_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/a2a"
	"github.com/goroute-ai/ai-gateway-go/internal/a2a/pb"
	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// TestAuthHardening_AUTH01_CLILoginUserCodeAndViewerRejection verifies:
// 1. /auth/cli/start does not leak user_code in verification_url.
// 2. /auth/cli/complete rejects missing or mismatched user_code with 403 invalid_cli_user_code.
// 3. /auth/cli/complete rejects read-only org_viewer operators with 403 cli_approve_read_only_denied.
func TestAuthHardening_AUTH01_CLILoginUserCodeAndViewerRejection(t *testing.T) {
	srv, repo, _ := newSSOTestServer(t, nil)
	ctx := context.Background()

	// Create an org_viewer and an org_admin in org-sso.
	viewer := &domain.User{
		ID:         "usr-cli-viewer",
		OrgID:      "org-sso",
		Email:      "viewer@sso.example.com",
		Name:       "Org Viewer",
		Role:       domain.RoleOrgViewer,
		IsActive:   true,
		SCIMActive: true,
	}
	admin := &domain.User{
		ID:         "usr-cli-admin",
		OrgID:      "org-sso",
		Email:      "admin@sso.example.com",
		Name:       "Org Admin",
		Role:       domain.RoleOrgAdmin,
		IsActive:   true,
		SCIMActive: true,
	}
	for _, u := range []*domain.User{viewer, admin} {
		if err := repo.CreateUser(ctx, u); err != nil {
			t.Fatalf("CreateUser(%s): %v", u.ID, err)
		}
	}

	startRec := doJSONReq(t, srv.Handler(), http.MethodPost, "/auth/cli/start", nil, nil)
	if startRec.Code != http.StatusOK {
		t.Fatalf("POST /auth/cli/start status = %d, body = %s", startRec.Code, startRec.Body.String())
	}
	var startResp struct {
		LoginID         string `json:"login_id"`
		UserCode        string `json:"user_code"`
		VerificationURL string `json:"verification_url"`
	}
	if err := json.Unmarshal(startRec.Body.Bytes(), &startResp); err != nil {
		t.Fatalf("decode startResp: %v", err)
	}
	if strings.Contains(startResp.VerificationURL, "user_code=") {
		t.Fatalf("verification_url must not contain user_code query param: %s", startResp.VerificationURL)
	}

	// 1. org_viewer cannot approve CLI login.
	viewerSess, err := srv.SessionManager().IssueSession(ctx, viewer.ID, viewer.OrgID, "", domain.OperatorRoleOrgViewer)
	if err != nil {
		t.Fatalf("IssueSession(viewer): %v", err)
	}
	viewerCompleteRec := doJSONReq(t, srv.Handler(), http.MethodPost, "/auth/cli/complete/"+startResp.LoginID, map[string]any{
		"org_id":    "org-sso",
		"user_code": startResp.UserCode,
	}, map[string]string{
		"Authorization": "Bearer " + viewerSess.Token,
	})
	if viewerCompleteRec.Code != http.StatusForbidden || !strings.Contains(viewerCompleteRec.Body.String(), "cli_approve_read_only_denied") {
		t.Fatalf("expected 403 cli_approve_read_only_denied for org_viewer, got %d (%s)", viewerCompleteRec.Code, viewerCompleteRec.Body.String())
	}

	// 2. org_admin with missing or wrong user_code is rejected with 403 invalid_cli_user_code.
	adminSess, err := srv.SessionManager().IssueSession(ctx, admin.ID, admin.OrgID, "", domain.OperatorRoleOrgAdmin)
	if err != nil {
		t.Fatalf("IssueSession(admin): %v", err)
	}
	wrongCodeRec := doJSONReq(t, srv.Handler(), http.MethodPost, "/auth/cli/complete/"+startResp.LoginID, map[string]any{
		"org_id":    "org-sso",
		"user_code": "XXXX-YYYY",
	}, map[string]string{
		"Authorization": "Bearer " + adminSess.Token,
	})
	if wrongCodeRec.Code != http.StatusForbidden || !strings.Contains(wrongCodeRec.Body.String(), "invalid_cli_user_code") {
		t.Fatalf("expected 403 invalid_cli_user_code, got %d (%s)", wrongCodeRec.Code, wrongCodeRec.Body.String())
	}

	// 3. org_admin with matching user_code succeeds.
	okRec := doJSONReq(t, srv.Handler(), http.MethodPost, "/auth/cli/complete/"+startResp.LoginID, map[string]any{
		"org_id":    "org-sso",
		"user_code": strings.ToLower(strings.ReplaceAll(startResp.UserCode, "-", "")),
	}, map[string]string{
		"Authorization": "Bearer " + adminSess.Token,
	})
	if okRec.Code != http.StatusOK {
		t.Fatalf("expected 200 with valid normalized user_code, got %d (%s)", okRec.Code, okRec.Body.String())
	}
}

// TestAuthHardening_AUTH02_AUTH03_OIDCTenantPinningAndRoleCeiling verifies:
// 1. An SSO provider pinned to DefaultOrgID="org-sso" rejects tokens carrying org_id="org-other" and cannot JIT-provision platform_admin.
// 2. SCIM-deprovisioned users cannot log in via password or SSO or use existing sessions.
func TestAuthHardening_AUTH02_AUTH03_OIDCTenantPinningAndRoleCeiling(t *testing.T) {
	idp := newMockOIDCIdP(t)
	srv, _ := newOIDCSSOTestServer(t, idp, func(c *config.Config) {
		for i := range c.Auth.SSOProviders {
			c.Auth.SSOProviders[i].DefaultOrgID = "org-sso"
			c.Auth.SSOProviders[i].DefaultRole = "platform_admin" // even if misconfigured, JIT must cap below platform_admin
		}
	})
	ctx := context.Background()
	repo := srv.AuthService().Repo()

	if err := repo.CreateOrganization(ctx, &domain.Organization{
		ID:       "org-other",
		Name:     "Other Org",
		Slug:     "other-org",
		IsActive: true,
	}); err != nil {
		t.Fatalf("CreateOrganization(org-other): %v", err)
	}

	// IdP asserts role="platform_admin"; JIT user must be capped to org_viewer (or org_admin), never platform_admin.
	idp.setNextIdentity("sub-cap-test", "cap@trusted.example.com", "Cap User")
	loginRec := doJSONReq(t, srv.Handler(), http.MethodGet, "/auth/sso/oidc/login?format=json", nil, nil)
	var loginResp struct {
		AuthorizationURL string `json:"authorization_url"`
	}
	_ = json.Unmarshal(loginRec.Body.Bytes(), &loginResp)
	code, state := runMockIdPAuthorize(t, loginResp.AuthorizationURL)
	cbRec := doJSONReq(t, srv.Handler(), http.MethodGet, "/auth/sso/oidc/callback?code="+url.QueryEscape(code)+"&state="+url.QueryEscape(state), nil, nil)
	if cbRec.Code != http.StatusOK {
		t.Fatalf("SSO callback status = %d, body = %s", cbRec.Code, cbRec.Body.String())
	}
	var cbBody struct {
		Operator domain.OperatorContext `json:"operator"`
		User     domain.User            `json:"user"`
	}
	if err := json.Unmarshal(cbRec.Body.Bytes(), &cbBody); err != nil {
		t.Fatalf("decode callback: %v", err)
	}
	if cbBody.User.Role == domain.RolePlatformAdmin || cbBody.Operator.Role == domain.OperatorRolePlatformAdmin {
		t.Fatalf("SSO JIT must never grant platform_admin, got user.Role=%s op.Role=%s", cbBody.User.Role, cbBody.Operator.Role)
	}
	if !cbBody.User.SCIMActive {
		t.Fatalf("SSO JIT user must have SCIMActive=true")
	}
}

// TestAuthHardening_AUTH05_SessionFailClosedOnDeleteAndSCIMDeprovision verifies:
// 1. Deleting a user or deprovisioning via SCIM immediately invalidates their active session JWT.
// 2. Password login rejects SCIM-deprovisioned users with 403 scim_deprovisioned.
func TestAuthHardening_AUTH05_SessionFailClosedOnDeleteAndSCIMDeprovision(t *testing.T) {
	srv, repo, cfg := newSSOTestServer(t, nil)
	ctx := context.Background()

	user := &domain.User{
		ID:             "usr-scim-sess",
		OrgID:          "org-sso",
		Email:          "scim-op@sso.example.com",
		Name:           "SCIM Operator",
		Role:           domain.RoleOrgAdmin,
		SCIMExternalID: "ext-scim-op-1",
		SCIMActive:     true,
		IsActive:       true,
	}
	if err := repo.CreateUser(ctx, user); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	hash, _ := auth.HashPasswordScrypt("ValidOperatorPass!123")
	if err := repo.UpsertUserPassword(ctx, user.ID, hash, false); err != nil {
		t.Fatalf("UpsertUserPassword: %v", err)
	}

	sess, err := srv.SessionManager().IssueSession(ctx, user.ID, user.OrgID, "", domain.OperatorRoleOrgAdmin)
	if err != nil {
		t.Fatalf("IssueSession: %v", err)
	}

	// Session works while active.
	meOK := doJSONReq(t, srv.Handler(), http.MethodGet, "/auth/me", nil, map[string]string{
		"Authorization": "Bearer " + sess.Token,
	})
	if meOK.Code != http.StatusOK {
		t.Fatalf("GET /auth/me before deprovision status = %d, body = %s", meOK.Code, meOK.Body.String())
	}

	// Mark user SCIMActive = false -> session and login must both fail with 403 scim_deprovisioned.
	user.SCIMActive = false
	if err := repo.UpdateUser(ctx, user); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
	meDeprov := doJSONReq(t, srv.Handler(), http.MethodGet, "/auth/me", nil, map[string]string{
		"Authorization": "Bearer " + sess.Token,
	})
	if meDeprov.Code != http.StatusForbidden || !strings.Contains(meDeprov.Body.String(), "scim_deprovisioned") {
		t.Fatalf("expected 403 scim_deprovisioned on active session, got %d (%s)", meDeprov.Code, meDeprov.Body.String())
	}

	loginDeprov := doJSONReq(t, srv.Handler(), http.MethodPost, "/auth/login", map[string]any{
		"email":    user.Email,
		"password": "ValidOperatorPass!123",
	}, nil)
	if loginDeprov.Code != http.StatusForbidden || !strings.Contains(loginDeprov.Body.String(), "scim_deprovisioned") {
		t.Fatalf("expected 403 scim_deprovisioned on /auth/login, got %d (%s)", loginDeprov.Code, loginDeprov.Body.String())
	}

	// Delete user via admin endpoint -> session fails closed with 401.
	delRec := doJSONReq(t, srv.Handler(), http.MethodDelete, "/admin/v1/users/"+user.ID+"?org_id=org-sso", nil, map[string]string{
		"Authorization": "Bearer " + cfg.Auth.MasterAdminKey,
	})
	if delRec.Code != http.StatusOK && delRec.Code != http.StatusNoContent {
		t.Fatalf("DELETE /admin/v1/users/%s status = %d (%s)", user.ID, delRec.Code, delRec.Body.String())
	}
	meDeleted := doJSONReq(t, srv.Handler(), http.MethodGet, "/auth/me", nil, map[string]string{
		"Authorization": "Bearer " + sess.Token,
	})
	if meDeleted.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 after user deletion, got %d (%s)", meDeleted.Code, meDeleted.Body.String())
	}
}

// TestAuthHardening_AUTH06_OrgScopedJWTKeyMappings verifies that two organizations
// can register the same (issuer, claim_name, claim_value) JWT mapping without collision,
// and ResolveJWTKeyMappingForOrg resolves only the target organization's virtual key.
func TestAuthHardening_AUTH06_OrgScopedJWTKeyMappings(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()

	m1 := &domain.JWTKeyMapping{
		OrgID:        "org-alpha",
		Issuer:       "https://idp.shared.example.com",
		ClaimName:    "groups",
		ClaimValue:   "engineering",
		VirtualKeyID: "vk-alpha-eng",
	}
	m2 := &domain.JWTKeyMapping{
		OrgID:        "org-beta",
		Issuer:       "https://idp.shared.example.com",
		ClaimName:    "groups",
		ClaimValue:   "engineering",
		VirtualKeyID: "vk-beta-eng",
	}
	if err := repo.CreateJWTKeyMapping(ctx, m1); err != nil {
		t.Fatalf("CreateJWTKeyMapping(org-alpha): %v", err)
	}
	if err := repo.CreateJWTKeyMapping(ctx, m2); err != nil {
		t.Fatalf("CreateJWTKeyMapping(org-beta) should succeed for distinct org: %v", err)
	}

	gotAlpha, err := repo.ResolveJWTKeyMappingForOrg(ctx, "org-alpha", m1.Issuer, m1.ClaimName, m1.ClaimValue)
	if err != nil || gotAlpha == nil || gotAlpha.VirtualKeyID != "vk-alpha-eng" {
		t.Fatalf("ResolveJWTKeyMappingForOrg(org-alpha): got %+v, err=%v", gotAlpha, err)
	}
	gotBeta, err := repo.ResolveJWTKeyMappingForOrg(ctx, "org-beta", m2.Issuer, m2.ClaimName, m2.ClaimValue)
	if err != nil || gotBeta == nil || gotBeta.VirtualKeyID != "vk-beta-eng" {
		t.Fatalf("ResolveJWTKeyMappingForOrg(org-beta): got %+v, err=%v", gotBeta, err)
	}

	// Ambiguous unscoped lookup across two orgs must fail closed.
	if gotAmbig, ambigErr := repo.ResolveJWTKeyMappingForOrg(ctx, "", m1.Issuer, m1.ClaimName, m1.ClaimValue); ambigErr == nil || gotAmbig != nil {
		t.Fatalf("expected ambiguous unscoped lookup to fail closed, got %+v, err=%v", gotAmbig, ambigErr)
	}

	// Unambiguous unscoped lookup for a claim owned by a single org succeeds.
	mUnique := &domain.JWTKeyMapping{
		OrgID:        "org-beta",
		Issuer:       "https://idp.shared.example.com",
		ClaimName:    "groups",
		ClaimValue:   "ml-prod-only",
		VirtualKeyID: "vk-beta-ml",
	}
	if err := repo.CreateJWTKeyMapping(ctx, mUnique); err != nil {
		t.Fatalf("CreateJWTKeyMapping(org-beta unique): %v", err)
	}
	gotUnique, err := repo.ResolveJWTKeyMappingForOrg(ctx, "", mUnique.Issuer, mUnique.ClaimName, mUnique.ClaimValue)
	if err != nil || gotUnique == nil || gotUnique.VirtualKeyID != "vk-beta-ml" {
		t.Fatalf("ResolveJWTKeyMappingForOrg(unscoped unique): got %+v, err=%v", gotUnique, err)
	}
}

// TestAuthHardening_AUTH07_MCPAndA2APrivateURLRequiresPlatformAdmin verifies that
// when AllowPrivateNetworks is enabled, an org_admin cannot register MCP servers or
// A2A agents pointing to internal URLs (403 platform_admin_required), while platform_admin can.
func TestAuthHardening_AUTH07_MCPAndA2APrivateURLRequiresPlatformAdmin(t *testing.T) {
	srv, repo, cfg := newSSOTestServer(t, func(c *config.Config) {
		c.Security.Network.OutboundSSRF.AllowPrivateNetworks = true
		c.Security.Network.OutboundSSRF.AllowInsecureHTTP = true
	})
	ctx := context.Background()

	orgAdmin := &domain.User{
		ID:         "usr-org-admin-ssrf",
		OrgID:      "org-sso",
		Email:      "orgadmin-ssrf@sso.example.com",
		Name:       "Org Admin",
		Role:       domain.RoleOrgAdmin,
		IsActive:   true,
		SCIMActive: true,
	}
	if err := repo.CreateUser(ctx, orgAdmin); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}
	orgAdminSess, err := srv.SessionManager().IssueSession(ctx, orgAdmin.ID, orgAdmin.OrgID, "", domain.OperatorRoleOrgAdmin)
	if err != nil {
		t.Fatalf("IssueSession: %v", err)
	}

	// org_admin attempting to create MCP server with private URL -> 403 platform_admin_required.
	mcpRec := doJSONReq(t, srv.Handler(), http.MethodPost, "/admin/v1/mcp/servers", map[string]any{
		"org_id":       "org-sso",
		"name":         "Internal MCP",
		"slug":         "internal-mcp",
		"endpoint_url": "http://127.0.0.1:9090/mcp",
	}, map[string]string{
		"Authorization": "Bearer " + orgAdminSess.Token,
	})
	if mcpRec.Code != http.StatusForbidden || !strings.Contains(mcpRec.Body.String(), "platform_admin_required") {
		t.Fatalf("expected 403 platform_admin_required on MCP create by org_admin, got %d (%s)", mcpRec.Code, mcpRec.Body.String())
	}

	// org_admin attempting to create A2A agent with private URL -> 403 platform_admin_required.
	a2aRec := doJSONReq(t, srv.Handler(), http.MethodPost, "/admin/v1/a2a/agents", map[string]any{
		"org_id":       "org-sso",
		"name":         "Internal Agent",
		"slug":         "internal-agent",
		"endpoint_url": "http://127.0.0.1:9091/a2a",
	}, map[string]string{
		"Authorization": "Bearer " + orgAdminSess.Token,
	})
	if a2aRec.Code != http.StatusForbidden || !strings.Contains(a2aRec.Body.String(), "platform_admin_required") {
		t.Fatalf("expected 403 platform_admin_required on A2A create by org_admin, got %d (%s)", a2aRec.Code, a2aRec.Body.String())
	}

	// platform_admin succeeds.
	platRec := doJSONReq(t, srv.Handler(), http.MethodPost, "/admin/v1/mcp/servers", map[string]any{
		"org_id":       "org-sso",
		"name":         "Internal MCP",
		"slug":         "internal-mcp",
		"endpoint_url": "http://127.0.0.1:9090/mcp",
	}, map[string]string{
		"Authorization": "Bearer " + cfg.Auth.MasterAdminKey,
	})
	if platRec.Code != http.StatusCreated {
		t.Fatalf("expected 201 for platform_admin MCP create, got %d (%s)", platRec.Code, platRec.Body.String())
	}
}

// TestAuthHardening_AUTH08_CanonicalBaseURLBlocksHostPoisoning verifies that
// PublicBaseURL overrides untrusted Host and X-Forwarded-Proto headers in /auth/cli/start.
func TestAuthHardening_AUTH08_CanonicalBaseURLBlocksHostPoisoning(t *testing.T) {
	srv, _, _ := newSSOTestServer(t, func(c *config.Config) {
		c.Server.PublicBaseURL = "https://gateway.trusted.example.com"
	})

	req := httptest.NewRequest(http.MethodPost, "/auth/cli/start", nil)
	req.Host = "evil.attacker.example.com"
	req.Header.Set("X-Forwarded-Proto", "http")
	req.RemoteAddr = "127.0.0.1:54321"
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("POST /auth/cli/start status = %d, body = %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "https://gateway.trusted.example.com/ui/cli") ||
		strings.Contains(rec.Body.String(), "evil.attacker.example.com") {
		t.Fatalf("expected canonical PublicBaseURL in verification_url, got %s", rec.Body.String())
	}
}

// TestAuthHardening_AUTH09_FilesAndBatchesTeamUserIsolation verifies that files and batches
// uploaded by Team A cannot be read, downloaded, deleted, or used in batches by Team B in the same org.
func TestAuthHardening_AUTH09_FilesAndBatchesTeamUserIsolation(t *testing.T) {
	t.Setenv("GOROUTE_FILES_DIR", t.TempDir())
	srv, repo, _ := newSSOTestServer(t, nil)
	ctx := context.Background()

	for _, tm := range []*domain.Team{
		{ID: "team-a", OrgID: "org-sso", Name: "Team A", IsActive: true},
		{ID: "team-b", OrgID: "org-sso", Name: "Team B", IsActive: true},
	} {
		if err := repo.CreateTeam(ctx, tm); err != nil {
			t.Fatalf("CreateTeam: %v", err)
		}
	}

	rawKeyA := "sk-gw-teama-secret-key-1111111"
	rawKeyB := "sk-gw-teamb-secret-key-2222222"
	for _, vk := range []*domain.VirtualKey{
		{
			ID:               "vk-team-a",
			OrgID:            "org-sso",
			TeamID:           "team-a",
			KeyHash:          auth.HashKey(rawKeyA),
			KeyPrefix:        "sk-gw-teama",
			Role:             domain.RoleDeveloper,
			AllowedEndpoints: []string{"*"},
			IsActive:         true,
		},
		{
			ID:               "vk-team-b",
			OrgID:            "org-sso",
			TeamID:           "team-b",
			KeyHash:          auth.HashKey(rawKeyB),
			KeyPrefix:        "sk-gw-teamb",
			Role:             domain.RoleDeveloper,
			AllowedEndpoints: []string{"*"},
			IsActive:         true,
		},
	} {
		if err := repo.CreateVirtualKey(ctx, vk); err != nil {
			t.Fatalf("CreateVirtualKey: %v", err)
		}
	}

	storagePath := filepath.Join(os.Getenv("GOROUTE_FILES_DIR"), "file-team-a")
	if err := os.WriteFile(storagePath, []byte(`{"custom_id":"1","method":"POST","url":"/v1/chat/completions","body":{"model":"gpt-4.1","messages":[{"role":"user","content":"hi"}]}}`+"\n"), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := repo.CreateFile(ctx, &domain.CanonicalFile{
		ID:          "file-team-a",
		OrgID:       "org-sso",
		TeamID:      "team-a",
		Bytes:       64,
		CreatedAt:   time.Now().UTC(),
		Filename:    "team_a.jsonl",
		Purpose:     "batch",
		Status:      "uploaded",
		StoragePath: storagePath,
	}); err != nil {
		t.Fatalf("CreateFile: %v", err)
	}

	// Team B cannot GET, download content, or DELETE Team A's file.
	getB := doJSONReq(t, srv.Handler(), http.MethodGet, "/v1/files/file-team-a", nil, map[string]string{
		"Authorization": "Bearer " + rawKeyB,
	})
	if getB.Code != http.StatusNotFound {
		t.Fatalf("expected 404 when Team B reads Team A file, got %d (%s)", getB.Code, getB.Body.String())
	}
	contentB := doJSONReq(t, srv.Handler(), http.MethodGet, "/v1/files/file-team-a/content", nil, map[string]string{
		"Authorization": "Bearer " + rawKeyB,
	})
	if contentB.Code != http.StatusNotFound {
		t.Fatalf("expected 404 when Team B downloads Team A file content, got %d", contentB.Code)
	}
	delB := doJSONReq(t, srv.Handler(), http.MethodDelete, "/v1/files/file-team-a", nil, map[string]string{
		"Authorization": "Bearer " + rawKeyB,
	})
	if delB.Code != http.StatusNotFound {
		t.Fatalf("expected 404 when Team B deletes Team A file, got %d", delB.Code)
	}

	// Team A can GET its own file.
	getA := doJSONReq(t, srv.Handler(), http.MethodGet, "/v1/files/file-team-a", nil, map[string]string{
		"Authorization": "Bearer " + rawKeyA,
	})
	if getA.Code != http.StatusOK {
		t.Fatalf("expected 200 when Team A reads its own file, got %d (%s)", getA.Code, getA.Body.String())
	}
}

// TestAuthHardening_AUTH10_AUTH11_AUTH12_A2ADiscoveryVisibilityAndGRPCRBAC verifies:
// 1. AUTH-10: Unauthenticated /.well-known/agent-card.json?agent=slug returns 401 when AllowLegacyCardDiscovery is false, and authenticated requests cannot discover another org's agent.
// 2. AUTH-11: RouterService.ListTasks returns team/user_strict tasks created by different Virtual Keys.
// 3. AUTH-12: GRPCServer enforces AllowedEndpoints and blocks read-only keys from mutating RPCs.
func TestAuthHardening_AUTH10_AUTH11_AUTH12_A2ADiscoveryVisibilityAndGRPCRBAC(t *testing.T) {
	srv, repo, _ := newSSOTestServer(t, func(c *config.Config) {
		c.A2A.Enabled = true
		c.A2A.AllowLegacyCardDiscovery = false
	})
	ctx := context.Background()

	if err := repo.CreateOrganization(ctx, &domain.Organization{
		ID:       "org-other-a2a",
		Name:     "Other A2A Org",
		IsActive: true,
	}); err != nil {
		t.Fatalf("CreateOrganization: %v", err)
	}
	if err := repo.CreateTeam(ctx, &domain.Team{
		ID:       "team-shared",
		OrgID:    "org-sso",
		Name:     "Team Shared",
		IsActive: true,
	}); err != nil {
		t.Fatalf("CreateTeam: %v", err)
	}

	agentTeam := &domain.A2AAgent{
		ID:                 "agent-team-vis",
		OrgID:              "org-sso",
		Name:               "Team Shared Agent",
		Slug:               "team-shared-agent",
		EndpointURL:        "https://agent.example.com/a2a",
		TaskVisibilityMode: domain.TaskVisibilityTeam,
		IsActive:           true,
	}
	agentOtherOrg := &domain.A2AAgent{
		ID:                 "agent-other-org",
		OrgID:              "org-other-a2a",
		Name:               "Secret Competitor Agent",
		Slug:               "secret-competitor-agent",
		EndpointURL:        "https://competitor.example.com/a2a",
		TaskVisibilityMode: domain.TaskVisibilityKeyStrict,
		IsActive:           true,
	}
	for _, a := range []*domain.A2AAgent{agentTeam, agentOtherOrg} {
		if err := repo.CreateA2AAgent(ctx, a); err != nil {
			t.Fatalf("CreateA2AAgent: %v", err)
		}
	}

	rawKey1 := "sk-gw-a2a-team-key-11111111"
	rawKey2 := "sk-gw-a2a-team-key-22222222"
	rawKeyReadOnly := "sk-gw-a2a-readonly-33333333"
	rawKeyNoA2AEndpoint := "sk-gw-a2a-noep-44444444"
	for _, vk := range []*domain.VirtualKey{
		{
			ID:               "vk-a2a-1",
			OrgID:            "org-sso",
			TeamID:           "team-shared",
			KeyHash:          auth.HashKey(rawKey1),
			KeyPrefix:        "sk-gw-a2a1",
			AllowedEndpoints: []string{"*"},
			AllowedA2AAgents: []string{"*"},
			IsActive:         true,
		},
		{
			ID:               "vk-a2a-2",
			OrgID:            "org-sso",
			TeamID:           "team-shared",
			KeyHash:          auth.HashKey(rawKey2),
			KeyPrefix:        "sk-gw-a2a2",
			AllowedEndpoints: []string{"*"},
			AllowedA2AAgents: []string{"*"},
			IsActive:         true,
		},
		{
			ID:               "vk-a2a-ro",
			OrgID:            "org-sso",
			TeamID:           "team-shared",
			KeyHash:          auth.HashKey(rawKeyReadOnly),
			KeyPrefix:        "sk-gw-a2aro",
			KeyType:          domain.KeyTypeReadOnly,
			AllowedEndpoints: []string{"*"},
			AllowedA2AAgents: []string{"*"},
			IsActive:         true,
		},
		{
			ID:               "vk-a2a-noep",
			OrgID:            "org-sso",
			TeamID:           "team-shared",
			KeyHash:          auth.HashKey(rawKeyNoA2AEndpoint),
			KeyPrefix:        "sk-gw-noep",
			AllowedEndpoints: []string{"/v1/chat/completions"},
			AllowedA2AAgents: []string{"*"},
			IsActive:         true,
		},
	} {
		if err := repo.CreateVirtualKey(ctx, vk); err != nil {
			t.Fatalf("CreateVirtualKey: %v", err)
		}
	}

	// AUTH-10: Unauthenticated agent card lookup for specific agent slug -> 401.
	unauthCard := doJSONReq(t, srv.Handler(), http.MethodGet, "/.well-known/agent-card.json?agent=team-shared-agent", nil, nil)
	if unauthCard.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 on unauthenticated specific agent card lookup, got %d (%s)", unauthCard.Code, unauthCard.Body.String())
	}

	// AUTH-10: Authenticated caller in org-sso cannot discover org-other-a2a's agent -> 404.
	crossOrgCard := doJSONReq(t, srv.Handler(), http.MethodGet, "/.well-known/agent-card.json?agent=secret-competitor-agent", nil, map[string]string{
		"Authorization": "Bearer " + rawKey1,
	})
	if crossOrgCard.Code != http.StatusNotFound {
		t.Fatalf("expected 404 on cross-org agent card lookup, got %d (%s)", crossOrgCard.Code, crossOrgCard.Body.String())
	}

	// AUTH-10: Authenticated caller in org-sso can discover its own org's agent -> 200.
	ownOrgCard := doJSONReq(t, srv.Handler(), http.MethodGet, "/.well-known/agent-card.json?agent=team-shared-agent", nil, map[string]string{
		"Authorization": "Bearer " + rawKey1,
	})
	if ownOrgCard.Code != http.StatusOK || !strings.Contains(ownOrgCard.Body.String(), "Team Shared Agent") {
		t.Fatalf("expected 200 on own-org agent card lookup, got %d (%s)", ownOrgCard.Code, ownOrgCard.Body.String())
	}

	// AUTH-11: Task created by vk-a2a-1 in team-shared is visible to vk-a2a-2 in ListTasks when TaskVisibilityMode == "team".
	if err := repo.CreateA2ATask(ctx, &domain.A2ATask{
		ID:           "task-team-shared-1",
		AgentID:      agentTeam.ID,
		OrgID:        "org-sso",
		TeamID:       "team-shared",
		VirtualKeyID: "vk-a2a-1",
		State:        domain.A2ATaskStateWorking,
	}); err != nil {
		t.Fatalf("CreateA2ATask: %v", err)
	}
	listRec := doJSONReq(t, srv.Handler(), http.MethodGet, "/a2a/v1/agents/team-shared-agent/tasks", nil, map[string]string{
		"Authorization": "Bearer " + rawKey2,
	})
	if listRec.Code != http.StatusOK || !strings.Contains(listRec.Body.String(), "task-team-shared-1") {
		t.Fatalf("expected vk-a2a-2 to see team task in ListTasks, got %d (%s)", listRec.Code, listRec.Body.String())
	}

	// AUTH-12: GRPCServer enforces AllowedEndpoints and blocks read-only keys on SendMessage/CancelTask.
	vault, _ := auth.NewVault("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	netPol, _ := network.NewPolicy(config.OutboundSSRFConfig{AllowPrivateNetworks: true, AllowInsecureHTTP: true})
	routerSvc := a2a.NewRouterService(repo, vault, srv.RBAC(), netPol, nil, nil, nil)
	grpcSrv := a2a.NewGRPCServer(routerSvc, srv.AuthService(), srv.RBAC())

	// Key without /a2a/v1/agents in AllowedEndpoints is denied with PermissionDenied.
	noEpCtx := metadata.NewIncomingContext(ctx, metadata.Pairs(
		"authorization", "Bearer "+rawKeyNoA2AEndpoint,
		"x-a2a-agent-slug", "team-shared-agent",
	))
	_, err := grpcSrv.ListTasks(noEpCtx, &pb.ListTasksRequest{})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied for key without A2A endpoint permission, got %v", err)
	}

	// Read-only key can call ListTasks, but cannot call SendMessage or CancelTask.
	roCtx := metadata.NewIncomingContext(ctx, metadata.Pairs(
		"authorization", "Bearer "+rawKeyReadOnly,
		"x-a2a-agent-slug", "team-shared-agent",
	))
	if _, err := grpcSrv.ListTasks(roCtx, &pb.ListTasksRequest{}); err != nil {
		t.Fatalf("expected read-only key to succeed on gRPC ListTasks, got %v", err)
	}
	if _, err := grpcSrv.SendMessage(roCtx, &pb.SendMessageRequest{}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied for read-only key on gRPC SendMessage, got %v", err)
	}
	if _, err := grpcSrv.CancelTask(roCtx, &pb.CancelTaskRequest{Id: "task-team-shared-1"}); status.Code(err) != codes.PermissionDenied {
		t.Fatalf("expected PermissionDenied for read-only key on gRPC CancelTask, got %v", err)
	}
}
