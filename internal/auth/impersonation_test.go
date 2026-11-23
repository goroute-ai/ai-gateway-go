package auth_test

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

func TestSCIMActiveEnforcementAndImmediateEviction(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	if err := repo.CreateOrganization(ctx, &domain.Organization{ID: "org-scim", Name: "SCIM Org", IsActive: true}); err != nil {
		t.Fatalf("CreateOrganization: %v", err)
	}
	user := &domain.User{
		ID:             "usr-scim-1",
		OrgID:          "org-scim",
		Email:          "alice@scim.example",
		Name:           "Alice",
		Role:           domain.RoleDeveloper,
		OIDCSubject:    "oidc-alice",
		SCIMExternalID: "ext-alice-1",
		SCIMActive:     true,
		IsActive:       true,
	}
	if err := repo.CreateUser(ctx, user); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	svc := auth.NewService(repo, nil, "master-secret", time.Minute, time.Minute)
	vk, err := svc.IssueVirtualKey(ctx, &domain.VirtualKey{
		OrgID:  "org-scim",
		UserID: user.ID,
		Name:   "alice-key",
	})
	if err != nil {
		t.Fatalf("IssueVirtualKey: %v", err)
	}

	// Warm L1 cache with active user.
	idCtx, err := svc.AuthenticateVirtualKey(ctx, vk.RawKey)
	if err != nil {
		t.Fatalf("AuthenticateVirtualKey active: %v", err)
	}
	if !idCtx.SCIMActive {
		t.Fatalf("expected SCIMActive=true on IdentityContext")
	}

	// Deprovision only SCIMActive (keeping IsActive=true) and immediately evict user keys.
	user.SCIMActive = false
	if err := repo.UpdateUser(ctx, user); err != nil {
		t.Fatalf("UpdateUser: %v", err)
	}
	svc.InvalidateUserKeys(ctx, user.OrgID, user.ID)

	_, err = svc.AuthenticateVirtualKey(ctx, vk.RawKey)
	var gwErr *domain.GatewayError
	if !errors.As(err, &gwErr) || gwErr.StatusCode != http.StatusForbidden || gwErr.Code != "scim_deprovisioned" {
		t.Fatalf("expected 403 scim_deprovisioned, got %v", err)
	}

	// AuthResolver OIDC JWT auth also rejects !user.SCIMActive.
	idp := newTestOIDCIssuer(t)
	jwtVerifier := auth.NewJWTVerifier(auth.JWTConfig{
		Issuer:        idp.Issuer(),
		Audience:      "ai-gateway",
		OIDCJWKSURL:   idp.JWKSURL(),
		DefaultOrgID:  "org-scim",
		NetworkPolicy: idp.NetworkPolicy(),
	})
	tok := idp.SignClaims(&auth.JWTClaims{
		Subject:  user.OIDCSubject,
		Issuer:   idp.Issuer(),
		Audience: auth.AudienceClaim{"ai-gateway"},
		Email:    user.Email,
		OrgID:    user.OrgID,
	})
	resolver := auth.NewAuthResolver(auth.ResolverConfig{
		Service:            svc,
		Repo:               repo,
		JWTVerifier:        jwtVerifier,
		EnableDataPlaneJWT: true,
		DefaultOrgID:       "org-scim",
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	_, err = resolver.ResolveRequest(ctx, req)
	if !errors.As(err, &gwErr) || gwErr.StatusCode != http.StatusForbidden || gwErr.Code != "scim_deprovisioned" {
		t.Fatalf("expected AuthResolver 403 scim_deprovisioned, got %v", err)
	}
}

func TestOperatorImpersonation_ControlPlaneAndGuards(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	_ = repo.CreateOrganization(ctx, &domain.Organization{ID: "org-a", Name: "Org A", IsActive: true})
	_ = repo.CreateOrganization(ctx, &domain.Organization{ID: "org-b", Name: "Org B", IsActive: true})
	_ = repo.CreateTeam(ctx, &domain.Team{ID: "team-a1", OrgID: "org-a", Name: "A1", IsActive: true})
	_ = repo.CreateTeam(ctx, &domain.Team{ID: "team-a2", OrgID: "org-a", Name: "A2", IsActive: true})

	_ = repo.CreateUser(ctx, &domain.User{
		ID:         "usr-org-admin",
		OrgID:      "org-a",
		Email:      "orgadmin@orga.example",
		Name:       "Org Admin",
		Role:       domain.RoleOrgAdmin,
		IsActive:   true,
		SCIMActive: true,
	})
	_ = repo.CreateUser(ctx, &domain.User{
		ID:         "usr-plat-admin",
		OrgID:      "org-a",
		Email:      "platadmin@orga.example",
		Name:       "Plat Admin",
		Role:       domain.RolePlatformAdmin,
		IsActive:   true,
		SCIMActive: true,
	})
	_ = repo.CreateUser(ctx, &domain.User{
		ID:         "usr-team-admin-1",
		OrgID:      "org-a",
		TeamID:     "team-a1",
		Email:      "ta1@orga.example",
		Name:       "TA1",
		Role:       domain.RoleTeamAdmin,
		IsActive:   true,
		SCIMActive: true,
	})
	_ = repo.CreateUser(ctx, &domain.User{
		ID:         "usr-team-admin-2",
		OrgID:      "org-a",
		TeamID:     "team-a2",
		Email:      "ta2@orga.example",
		Name:       "TA2",
		Role:       domain.RoleTeamAdmin,
		IsActive:   true,
		SCIMActive: true,
	})
	_ = repo.CreateUser(ctx, &domain.User{
		ID:             "usr-deprov",
		OrgID:          "org-a",
		Email:          "deprov@orga.example",
		Name:           "Deprov",
		Role:           domain.RoleOrgAdmin,
		SCIMExternalID: "ext-deprov",
		IsActive:       true,
		SCIMActive:     false,
	})
	_ = repo.CreateUser(ctx, &domain.User{
		ID:         "usr-org-b",
		OrgID:      "org-b",
		Email:      "admin@orgb.example",
		Name:       "Org B Admin",
		Role:       domain.RoleOrgAdmin,
		IsActive:   true,
		SCIMActive: true,
	})

	svc := auth.NewService(repo, nil, "master-key-secret", time.Minute, time.Minute)
	impKey, err := svc.IssueVirtualKey(ctx, &domain.VirtualKey{
		OrgID:          "org-a",
		Name:           "impersonator-key",
		Role:           domain.RoleOrgAdmin,
		CanImpersonate: true,
	})
	if err != nil {
		t.Fatalf("IssueVirtualKey impKey: %v", err)
	}
	noImpKey, err := svc.IssueVirtualKey(ctx, &domain.VirtualKey{
		OrgID:          "org-a",
		Name:           "normal-admin-key",
		Role:           domain.RoleOrgAdmin,
		CanImpersonate: false,
	})
	if err != nil {
		t.Fatalf("IssueVirtualKey noImpKey: %v", err)
	}
	teamImpKey, err := svc.IssueVirtualKey(ctx, &domain.VirtualKey{
		OrgID:          "org-a",
		TeamID:         "team-a1",
		Name:           "team-imp-key",
		Role:           domain.RoleTeamAdmin,
		CanImpersonate: true,
	})
	if err != nil {
		t.Fatalf("IssueVirtualKey teamImpKey: %v", err)
	}

	var capturedOp *domain.OperatorContext
	mw := auth.AdminControlPlaneMiddleware(svc)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedOp = auth.OperatorFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	t.Run("MasterKey impersonates user with base64-utf8 email and writes audit log", func(t *testing.T) {
		capturedOp = nil
		req := httptest.NewRequest(http.MethodGet, "/admin/v1/users", nil)
		req.Header.Set("Authorization", "Bearer master-key-secret")
		encodedEmail := "base64-utf8:" + base64.StdEncoding.EncodeToString([]byte("orgadmin@orga.example"))
		req.Header.Set(auth.HeaderImpersonateEmail, encodedEmail)
		rec := httptest.NewRecorder()
		mw.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d (%s)", rec.Code, rec.Body.String())
		}
		if capturedOp == nil || capturedOp.ActorID != "usr-org-admin" || capturedOp.ImpersonatedByActorID != "master_admin" || capturedOp.Role != domain.OperatorRoleOrgAdmin || capturedOp.OrgID != "org-a" {
			t.Fatalf("unexpected impersonated OperatorContext: %+v", capturedOp)
		}
		logs, err := repo.ListAuditLogs(ctx, "org-a", 10)
		if err != nil || len(logs) == 0 {
			t.Fatalf("expected audit log entry, got len=%d err=%v", len(logs), err)
		}
		if logs[0].ActorID != "usr-org-admin" || logs[0].Details["impersonated_by"] != "master_admin" {
			t.Fatalf("expected actor_id and impersonated_by in audit log, got %+v", logs[0])
		}
	})

	t.Run("VirtualKey with CanImpersonate=true succeeds for same-org non-escalated target", func(t *testing.T) {
		capturedOp = nil
		req := httptest.NewRequest(http.MethodGet, "/admin/v1/teams", nil)
		req.Header.Set("Authorization", "Bearer "+impKey.RawKey)
		req.Header.Set(auth.HeaderImpersonateUser, "usr-team-admin-1")
		rec := httptest.NewRecorder()
		mw.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d (%s)", rec.Code, rec.Body.String())
		}
		if capturedOp == nil || capturedOp.ActorID != "usr-team-admin-1" || capturedOp.ImpersonatedByActorID != impKey.ID || capturedOp.Role != domain.OperatorRoleTeamAdmin || capturedOp.TeamID != "team-a1" {
			t.Fatalf("unexpected OperatorContext: %+v", capturedOp)
		}
	})

	t.Run("VirtualKey with CanImpersonate=false is rejected", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/admin/v1/users", nil)
		req.Header.Set("Authorization", "Bearer "+noImpKey.RawKey)
		req.Header.Set(auth.HeaderImpersonateUser, "usr-org-admin")
		rec := httptest.NewRecorder()
		mw.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d (%s)", rec.Code, rec.Body.String())
		}
	})

	t.Run("org_admin cannot escalate to platform_admin", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/admin/v1/users", nil)
		req.Header.Set("Authorization", "Bearer "+impKey.RawKey)
		req.Header.Set(auth.HeaderImpersonateUser, "usr-plat-admin")
		rec := httptest.NewRecorder()
		mw.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("expected 403, got %d (%s)", rec.Code, rec.Body.String())
		}
	})

	t.Run("team_admin cannot impersonate org_admin or other-team team_admin", func(t *testing.T) {
		for _, target := range []string{"usr-org-admin", "usr-team-admin-2"} {
			req := httptest.NewRequest(http.MethodGet, "/admin/v1/keys", nil)
			req.Header.Set("Authorization", "Bearer "+teamImpKey.RawKey)
			req.Header.Set(auth.HeaderImpersonateUser, target)
			rec := httptest.NewRecorder()
			mw.ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("expected 403 for target %s, got %d (%s)", target, rec.Code, rec.Body.String())
			}
		}
	})

	t.Run("Cross-org impersonation is rejected", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/admin/v1/users", nil)
		req.Header.Set("Authorization", "Bearer "+impKey.RawKey)
		req.Header.Set(auth.HeaderImpersonateUser, "usr-org-b")
		rec := httptest.NewRecorder()
		mw.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("expected 403 cross-org, got %d (%s)", rec.Code, rec.Body.String())
		}
	})

	t.Run("SCIM-deprovisioned target is rejected", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/admin/v1/users", nil)
		req.Header.Set("Authorization", "Bearer master-key-secret")
		req.Header.Set(auth.HeaderImpersonateUser, "usr-deprov")
		rec := httptest.NewRecorder()
		mw.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("expected 403 for deprovisioned target, got %d (%s)", rec.Code, rec.Body.String())
		}
	})

	t.Run("Invalid base64-utf8 header returns 400", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/admin/v1/users", nil)
		req.Header.Set("Authorization", "Bearer master-key-secret")
		req.Header.Set(auth.HeaderImpersonateUser, "base64-utf8:!!!not-valid-base64!!!")
		rec := httptest.NewRecorder()
		mw.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d (%s)", rec.Code, rec.Body.String())
		}
	})
}

func TestDelegatedAgentCallerNarrowing(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	_ = repo.CreateOrganization(ctx, &domain.Organization{ID: "org-del", Name: "Del Org", IsActive: true})
	_ = repo.CreateOrganization(ctx, &domain.Organization{ID: "org-other", Name: "Other Org", IsActive: true})

	_ = repo.CreateTeam(ctx, &domain.Team{
		ID:                    "team-tight",
		OrgID:                 "org-del",
		Name:                  "Tight Team",
		AllowedModels:         []string{"gpt-4.1", "gemini-2.5"},
		AllowedMCPServers:     []string{"mcp-shared", "mcp-team-only"},
		AllowedA2AAgents:      []string{"agent-shared"},
		AllowedClientApps:     []string{"cli", "web"},
		RPMLimit:              60,
		TPMLimit:              4000,
		MaxConcurrentRequests: 8,
		MaxBudgetMicros:       3_000_000,
		SpentMicros:           2_500_000, // remaining 500_000
		IsActive:              true,
	})
	_ = repo.CreateTeam(ctx, &domain.Team{
		ID:            "team-disjoint",
		OrgID:         "org-del",
		Name:          "Disjoint Team",
		AllowedModels: []string{"claude-3.5-sonnet"},
		IsActive:      true,
	})
	_ = repo.CreateTeam(ctx, &domain.Team{
		ID:       "team-inactive",
		OrgID:    "org-del",
		Name:     "Inactive Team",
		IsActive: false,
	})
	_ = repo.CreateTeam(ctx, &domain.Team{
		ID:       "team-other-org",
		OrgID:    "org-other",
		Name:     "Other Org Team",
		IsActive: true,
	})

	_ = repo.CreateUser(ctx, &domain.User{
		ID:                    "usr-tight",
		OrgID:                 "org-del",
		Email:                 "tight@del.example",
		Role:                  domain.RoleDeveloper,
		RPMLimit:              20,
		TPMLimit:              50000, // wider than team (4000) & key (10000) -> clamped to 10000 on user, 4000 on team
		MaxConcurrentRequests: 3,
		MaxBudgetMicros:       2_000_000,
		SpentMicros:           1_200_000, // remaining 800_000
		IsActive:              true,
		SCIMActive:            true,
	})
	_ = repo.CreateUser(ctx, &domain.User{
		ID:         "usr-inactive",
		OrgID:      "org-del",
		Email:      "inactive@del.example",
		Role:       domain.RoleDeveloper,
		IsActive:   false,
		SCIMActive: true,
	})
	_ = repo.CreateUser(ctx, &domain.User{
		ID:             "usr-deprov",
		OrgID:          "org-del",
		Email:          "deprov@del.example",
		Role:           domain.RoleDeveloper,
		SCIMExternalID: "ext-1",
		IsActive:       true,
		SCIMActive:     false,
	})
	_ = repo.CreateUser(ctx, &domain.User{
		ID:         "usr-other-org",
		OrgID:      "org-other",
		Email:      "other@other.example",
		Role:       domain.RoleDeveloper,
		IsActive:   true,
		SCIMActive: true,
	})
	_ = repo.CreateAccessGroupRule(ctx, &domain.AccessGroupRule{
		ID:            "rule-widen",
		OrgID:         "org-del",
		Name:          "allow-all-dynamic",
		Attribute:     "auth_method",
		Operator:      domain.AccessRuleOperatorEquals,
		Value:         "virtual_key",
		AllowedModels: []string{"gemini-2.5", "claude-3.5-sonnet"},
		IsActive:      true,
	})

	svc := auth.NewService(repo, nil, "master-key", time.Minute, time.Minute)
	rbac := auth.NewRBACEngine(repo)

	agentKey, err := svc.IssueVirtualKey(ctx, &domain.VirtualKey{
		OrgID:                 "org-del",
		Name:                  "agent-key",
		Role:                  domain.RoleServiceAccount,
		AllowedModels:         []string{"gpt-4.1", "claude-3.5-sonnet"},
		AllowedEndpoints:      []string{"/v1/*", "/mcp/*", "/a2a/*"},
		AllowedMCPServers:     []string{"mcp-shared", "mcp-key-only"},
		AllowedA2AAgents:      []string{"agent-shared", "agent-key-only"},
		AllowedClientApps:     []string{"cli", "ide"},
		RPMLimit:              100,
		TPMLimit:              10000,
		MaxConcurrentRequests: 10,
		MaxBudgetMicros:       5_000_000,
		SpentMicros:           1_000_000, // remaining 4_000_000
	})
	if err != nil {
		t.Fatalf("IssueVirtualKey: %v", err)
	}

	var gotID *domain.IdentityContext
	mw := auth.DataPlaneMiddleware(svc, rbac)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotID = auth.IdentityFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	t.Run("Strict intersection of allowlists and min of budgets/RPM/TPM/concurrency", func(t *testing.T) {
		gotID = nil
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
		req.Header.Set("Authorization", "Bearer "+agentKey.RawKey)
		req.Header.Set(auth.HeaderDelegatedUserID, "usr-tight")
		req.Header.Set(auth.HeaderDelegatedTeamID, "team-tight")
		rec := httptest.NewRecorder()
		mw.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d (%s)", rec.Code, rec.Body.String())
		}
		if gotID == nil || gotID.DelegatedUserID != "usr-tight" || gotID.DelegatedTeamID != "team-tight" {
			t.Fatalf("expected delegated IDs set, got %+v", gotID)
		}

		// Models: {"gpt-4.1", "claude-3.5-sonnet"} ∩ {"gpt-4.1", "gemini-2.5"} == {"gpt-4.1"}.
		// Dynamic access rules must NOT re-widen to gemini-2.5 or claude-3.5-sonnet.
		if err := rbac.AuthorizeRequestedModel(gotID, "gpt-4.1"); err != nil {
			t.Fatalf("expected gpt-4.1 to be allowed, got %v", err)
		}
		for _, denied := range []string{"claude-3.5-sonnet", "gemini-2.5"} {
			if err := rbac.AuthorizeRequestedModel(gotID, denied); err == nil {
				t.Fatalf("expected %s to be denied after narrowing", denied)
			}
		}

		// MCP servers: {"mcp-shared", "mcp-key-only"} ∩ {"mcp-shared", "mcp-team-only"} == {"mcp-shared"}.
		if err := rbac.AuthorizeMCPServer(gotID, "mcp-shared"); err != nil {
			t.Fatalf("expected mcp-shared allowed, got %v", err)
		}
		for _, denied := range []string{"mcp-key-only", "mcp-team-only"} {
			if err := rbac.AuthorizeMCPServer(gotID, denied); err == nil {
				t.Fatalf("expected MCP %s denied", denied)
			}
		}

		// A2A agents: {"agent-shared", "agent-key-only"} ∩ {"agent-shared"} == {"agent-shared"}.
		if err := rbac.AuthorizeA2AAgent(gotID, "agent-shared"); err != nil {
			t.Fatalf("expected agent-shared allowed, got %v", err)
		}
		if err := rbac.AuthorizeA2AAgent(gotID, "agent-key-only"); err == nil {
			t.Fatalf("expected agent-key-only denied")
		}

		// Client apps: {"cli", "ide"} ∩ {"cli", "web"} == {"cli"}.
		if err := rbac.AuthorizeClientApp(gotID, "cli"); err != nil {
			t.Fatalf("expected cli allowed, got %v", err)
		}
		for _, denied := range []string{"ide", "web"} {
			if err := rbac.AuthorizeClientApp(gotID, denied); err == nil {
				t.Fatalf("expected client app %s denied", denied)
			}
		}

		// Rate limits & budgets narrowed via min.
		if gotID.UserRPMLimit != 20 || gotID.TeamRPMLimit != 60 {
			t.Fatalf("unexpected RPM limits: user=%d team=%d", gotID.UserRPMLimit, gotID.TeamRPMLimit)
		}
		if gotID.UserTPMLimit != 10000 || gotID.TeamTPMLimit != 4000 {
			t.Fatalf("unexpected TPM limits: user=%d team=%d", gotID.UserTPMLimit, gotID.TeamTPMLimit)
		}
		if gotID.UserMaxConcurrent != 3 || gotID.TeamMaxConcurrent != 8 {
			t.Fatalf("unexpected concurrency limits: user=%d team=%d", gotID.UserMaxConcurrent, gotID.TeamMaxConcurrent)
		}
		if gotID.UserMaxBudgetMicros-gotID.UserSpentMicros != 800_000 {
			t.Fatalf("unexpected user remaining budget: %d", gotID.UserMaxBudgetMicros-gotID.UserSpentMicros)
		}
		if gotID.TeamMaxBudgetMicros-gotID.TeamSpentMicros != 500_000 {
			t.Fatalf("unexpected team remaining budget: %d", gotID.TeamMaxBudgetMicros-gotID.TeamSpentMicros)
		}
	})

	t.Run("Disjoint model allowlists deny all models rather than widening", func(t *testing.T) {
		// Key allows {"gpt-4.1", "claude-3.5-sonnet"}; tighten key to {"gpt-4.1"} via team-disjoint {"claude-3.5-sonnet"}.
		gptOnlyKey, err := svc.IssueVirtualKey(ctx, &domain.VirtualKey{
			OrgID:         "org-del",
			Name:          "gpt-only-key",
			Role:          domain.RoleServiceAccount,
			AllowedModels: []string{"gpt-4.1"},
		})
		if err != nil {
			t.Fatalf("IssueVirtualKey: %v", err)
		}
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
		req.Header.Set("Authorization", "Bearer "+gptOnlyKey.RawKey)
		req.Header.Set(auth.HeaderDelegatedTeamID, "team-disjoint")
		rec := httptest.NewRecorder()
		mw.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("expected 200 middleware, got %d", rec.Code)
		}
		for _, m := range []string{"gpt-4.1", "claude-3.5-sonnet", "gemini-2.5"} {
			if err := rbac.AuthorizeRequestedModel(gotID, m); err == nil {
				t.Fatalf("expected disjoint model %s to be denied", m)
			}
		}
	})

	t.Run("Rejects cross-org and inactive delegated identities with 403", func(t *testing.T) {
		cases := []struct {
			name   string
			userID string
			teamID string
		}{
			{"cross-org user", "usr-other-org", ""},
			{"cross-org team", "", "team-other-org"},
			{"inactive user", "usr-inactive", ""},
			{"scim deprovisioned user", "usr-deprov", ""},
			{"inactive team", "", "team-inactive"},
			{"unknown user", "usr-missing", ""},
		}
		for _, tc := range cases {
			req := httptest.NewRequest(http.MethodPost, "/mcp/mcp-shared", nil)
			req.Header.Set("Authorization", "Bearer "+agentKey.RawKey)
			if tc.userID != "" {
				req.Header.Set(auth.HeaderDelegatedUserID, tc.userID)
			}
			if tc.teamID != "" {
				req.Header.Set(auth.HeaderDelegatedTeamID, tc.teamID)
			}
			rec := httptest.NewRecorder()
			mw.ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("%s: expected 403, got %d (%s)", tc.name, rec.Code, rec.Body.String())
			}
		}
	})
}
