package server_test

import (
	"context"
	"encoding/json"
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

func TestAdminProjectsAndTeamMemberships_RBACAndMNMultiTeam(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()

	require.NoError(t, repo.CreateOrganization(ctx, &domain.Organization{ID: "org_a", Name: "Org A", Slug: "org-a", IsActive: true}))
	require.NoError(t, repo.CreateOrganization(ctx, &domain.Organization{ID: "org_b", Name: "Org B", Slug: "org-b", IsActive: true}))

	require.NoError(t, repo.CreateTeam(ctx, &domain.Team{ID: "team_a1", OrgID: "org_a", Name: "Team A1", IsActive: true}))
	require.NoError(t, repo.CreateTeam(ctx, &domain.Team{ID: "team_a2", OrgID: "org_a", Name: "Team A2", IsActive: true}))
	require.NoError(t, repo.CreateTeam(ctx, &domain.Team{ID: "team_b1", OrgID: "org_b", Name: "Team B1", IsActive: true}))

	require.NoError(t, repo.CreateUser(ctx, &domain.User{
		ID:       "usr_a1_admin",
		OrgID:    "org_a",
		TeamID:   "team_a1",
		Email:    "admin-a1@orga.example",
		Name:     "A1 Admin",
		Role:     domain.RoleTeamAdmin,
		IsActive: true,
	}))
	require.NoError(t, repo.CreateUser(ctx, &domain.User{
		ID:          "usr_multi",
		OrgID:       "org_a",
		TeamID:      "team_a1",
		Email:       "multi@orga.example",
		Name:        "Multi Team User",
		Role:        domain.RoleDeveloper,
		OIDCSubject: "sub-multi",
		IsActive:    true,
	}))
	require.NoError(t, repo.CreateUser(ctx, &domain.User{
		ID:       "usr_org_a_admin",
		OrgID:    "org_a",
		Email:    "orgadmin@orga.example",
		Name:     "Org A Admin",
		Role:     domain.RoleOrgAdmin,
		IsActive: true,
	}))
	require.NoError(t, repo.CreateUser(ctx, &domain.User{
		ID:       "usr_org_a_viewer",
		OrgID:    "org_a",
		Email:    "orgviewer@orga.example",
		Name:     "Org A Viewer",
		Role:     domain.RoleOrgViewer,
		IsActive: true,
	}))
	require.NoError(t, repo.CreateUser(ctx, &domain.User{
		ID:       "usr_b1_dev",
		OrgID:    "org_b",
		TeamID:   "team_b1",
		Email:    "dev-b1@orgb.example",
		Name:     "B1 Dev",
		Role:     domain.RoleDeveloper,
		IsActive: true,
	}))

	cfg := config.Default()
	cfg.Auth.MasterAdminKey = "sk-gw-master-projects-test"
	cfg.Auth.EnableDataPlaneJWT = true
	cfg.Auth.JWTSecret = "projects-test-jwt-secret"
	cfg.Auth.JWTIssuer = "https://idp.orga.example"
	cfg.Auth.JWTAudience = "ai-gateway"
	cfg.Auth.DefaultOrgID = "org_a"

	gw, err := server.New(cfg, repo, nil, nil)
	require.NoError(t, err)
	gw.StartWorkers(ctx)
	defer gw.Shutdown(ctx)
	handler := gw.Handler()

	teamA1AdminVK, err := gw.AuthService().IssueVirtualKey(ctx, &domain.VirtualKey{
		OrgID:  "org_a",
		TeamID: "team_a1",
		UserID: "usr_a1_admin",
		Name:   "a1-admin-key",
		Role:   domain.RoleTeamAdmin,
	})
	require.NoError(t, err)

	orgAAdminVK, err := gw.AuthService().IssueVirtualKey(ctx, &domain.VirtualKey{
		OrgID:  "org_a",
		UserID: "usr_org_a_admin",
		Name:   "org-a-admin-key",
		Role:   domain.RoleOrgAdmin,
	})
	require.NoError(t, err)

	orgAViewerVK, err := gw.AuthService().IssueVirtualKey(ctx, &domain.VirtualKey{
		OrgID:  "org_a",
		UserID: "usr_org_a_viewer",
		Name:   "org-a-viewer-key",
		Role:   domain.RoleOrgViewer,
	})
	require.NoError(t, err)

	// 1. M:N Multi-Team Membership: usr_multi joins team_a1 (developer) and team_a2 (team_admin) via org_admin
	rec := doAdminJSONRequest(t, handler, http.MethodPost, "/admin/v1/teams/team_a1/members", orgAAdminVK.RawKey, map[string]any{
		"user_id":           "usr_multi",
		"role":              "developer",
		"max_budget_micros": 2_000_000,
		"rpm_limit":         25,
		"tpm_limit":         5000,
		"allowed_models":    []string{"gpt-4.1"},
	})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	rec = doAdminJSONRequest(t, handler, http.MethodPost, "/admin/v1/teams/team_a2/members", orgAAdminVK.RawKey, map[string]any{
		"user_id":           "usr_multi",
		"role":              "team_admin",
		"max_budget_micros": 4_000_000,
		"rpm_limit":         80,
		"tpm_limit":         20000,
		"allowed_models":    []string{"gpt-4.1-mini"},
	})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	// Cross-org user cannot be added to org_a team
	rec = doAdminJSONRequest(t, handler, http.MethodPost, "/admin/v1/teams/team_a1/members", orgAAdminVK.RawKey, map[string]any{
		"user_id": "usr_b1_dev",
		"role":    "developer",
	})
	assert.Equal(t, http.StatusForbidden, rec.Code)

	// team_a1 admin can list and update team_a1 members, cannot assign org_admin, and cannot touch team_a2
	rec = doAdminJSONRequest(t, handler, http.MethodGet, "/admin/v1/teams/team_a1/members", teamA1AdminVK.RawKey, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	var membersResp struct {
		Data []*domain.TeamMembership `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &membersResp))
	require.Len(t, membersResp.Data, 1)
	assert.Equal(t, "usr_multi", membersResp.Data[0].UserID)

	rec = doAdminJSONRequest(t, handler, http.MethodPost, "/admin/v1/teams/team_a1/members", teamA1AdminVK.RawKey, map[string]any{
		"user_id": "usr_multi",
		"role":    "org_admin",
	})
	assert.Equal(t, http.StatusForbidden, rec.Code)

	rec = doAdminJSONRequest(t, handler, http.MethodGet, "/admin/v1/teams/team_a2/members", teamA1AdminVK.RawKey, nil)
	assert.Equal(t, http.StatusForbidden, rec.Code)
	rec = doAdminJSONRequest(t, handler, http.MethodPost, "/admin/v1/teams/team_a2/members", teamA1AdminVK.RawKey, map[string]any{
		"user_id": "usr_multi",
		"role":    "developer",
	})
	assert.Equal(t, http.StatusForbidden, rec.Code)
	rec = doAdminJSONRequest(t, handler, http.MethodDelete, "/admin/v1/teams/team_a2/members/usr_multi", teamA1AdminVK.RawKey, nil)
	assert.Equal(t, http.StatusForbidden, rec.Code)

	// org_viewer can read members/projects but cannot mutate
	rec = doAdminJSONRequest(t, handler, http.MethodGet, "/admin/v1/teams/team_a2/members", orgAViewerVK.RawKey, nil)
	assert.Equal(t, http.StatusOK, rec.Code)
	rec = doAdminJSONRequest(t, handler, http.MethodPost, "/admin/v1/teams/team_a2/members", orgAViewerVK.RawKey, map[string]any{
		"user_id": "usr_multi",
	})
	assert.Equal(t, http.StatusForbidden, rec.Code)

	// 2. Projects CRUD & team_admin isolation
	// team_a1 admin creates a project (team_id inferred from operator when omitted)
	rec = doAdminJSONRequest(t, handler, http.MethodPost, "/admin/v1/projects", teamA1AdminVK.RawKey, map[string]any{
		"id":                          "proj_a1_prod",
		"name":                        "A1 Prod",
		"description":                 "Team A1 production",
		"max_budget_micros":           5_000_000,
		"rpm_limit":                   120,
		"tpm_limit":                   30000,
		"allowed_models":              []string{"gpt-4.1"},
		"enforce_project_model_quota": true,
	})
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	var projA1 domain.Project
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &projA1))
	assert.Equal(t, "org_a", projA1.OrgID)
	assert.Equal(t, "team_a1", projA1.TeamID)
	assert.True(t, projA1.EnforceProjectModelQuota)
	assert.True(t, projA1.IsActive)

	// org_admin creates a project in team_a2
	rec = doAdminJSONRequest(t, handler, http.MethodPost, "/admin/v1/projects", orgAAdminVK.RawKey, map[string]any{
		"id":             "proj_a2_lab",
		"team_id":        "team_a2",
		"name":           "A2 Lab",
		"allowed_models": []string{"gpt-4.1-mini"},
	})
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())

	// team_a1 admin cannot create, list, update, or delete projects in team_a2 or org_b
	rec = doAdminJSONRequest(t, handler, http.MethodPost, "/admin/v1/projects", teamA1AdminVK.RawKey, map[string]any{
		"team_id": "team_a2",
		"name":    "Sneaky A2",
	})
	assert.Equal(t, http.StatusForbidden, rec.Code)

	rec = doAdminJSONRequest(t, handler, http.MethodGet, "/admin/v1/projects?team_id=team_a2", teamA1AdminVK.RawKey, nil)
	assert.Equal(t, http.StatusForbidden, rec.Code)

	rec = doAdminJSONRequest(t, handler, http.MethodPut, "/admin/v1/projects/proj_a2_lab", teamA1AdminVK.RawKey, map[string]any{
		"name": "Hijacked",
	})
	assert.Equal(t, http.StatusForbidden, rec.Code)

	rec = doAdminJSONRequest(t, handler, http.MethodDelete, "/admin/v1/projects/proj_a2_lab", teamA1AdminVK.RawKey, nil)
	assert.Equal(t, http.StatusForbidden, rec.Code)

	rec = doAdminJSONRequest(t, handler, http.MethodPut, "/admin/v1/projects/proj_a1_prod", teamA1AdminVK.RawKey, map[string]any{
		"team_id": "team_a2",
	})
	assert.Equal(t, http.StatusForbidden, rec.Code)

	// team_a1 admin listing projects returns only team_a1 projects
	rec = doAdminJSONRequest(t, handler, http.MethodGet, "/admin/v1/projects", teamA1AdminVK.RawKey, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	var projList struct {
		Data []*domain.Project `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &projList))
	require.Len(t, projList.Data, 1)
	assert.Equal(t, "proj_a1_prod", projList.Data[0].ID)

	// 3. Key project binding via POST /admin/v1/keys & PUT /admin/v1/keys/{keyID}
	// team_a1 admin binds key to proj_a1_prod (team_id inferred from project)
	rec = doAdminJSONRequest(t, handler, http.MethodPost, "/admin/v1/keys", teamA1AdminVK.RawKey, map[string]any{
		"name":       "key-bound-to-a1-prod",
		"project_id": "proj_a1_prod",
		"user_id":    "usr_multi",
		"role":       "developer",
		"rpm_limit":  15,
	})
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	var boundKey domain.VirtualKey
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &boundKey))
	assert.Equal(t, "proj_a1_prod", boundKey.ProjectID)
	assert.Equal(t, "team_a1", boundKey.TeamID)

	// team_a1 admin cannot bind a key to team_a2's project
	rec = doAdminJSONRequest(t, handler, http.MethodPost, "/admin/v1/keys", teamA1AdminVK.RawKey, map[string]any{
		"name":       "cross-team-proj-key",
		"project_id": "proj_a2_lab",
	})
	assert.Equal(t, http.StatusForbidden, rec.Code)

	// org_admin cannot bind key with mismatched team_id + project_id
	rec = doAdminJSONRequest(t, handler, http.MethodPost, "/admin/v1/keys", orgAAdminVK.RawKey, map[string]any{
		"name":       "mismatch-key",
		"team_id":    "team_a2",
		"project_id": "proj_a1_prod",
	})
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	// AuthenticateVirtualKey resolves Project + TeamMembership onto IdentityContext
	idCtx, err := gw.AuthService().AuthenticateVirtualKey(ctx, boundKey.RawKey)
	require.NoError(t, err)
	assert.Equal(t, "proj_a1_prod", idCtx.ProjectID)
	assert.Equal(t, []string{"gpt-4.1"}, idCtx.ProjectAllowedModels)
	assert.Equal(t, int64(5_000_000), idCtx.ProjectMaxBudgetMicros)
	assert.Equal(t, 120, idCtx.ProjectRPMLimit)
	assert.Equal(t, 30000, idCtx.ProjectTPMLimit)
	assert.True(t, idCtx.ProjectEnforceModelQuota)
	assert.Equal(t, []string{"gpt-4.1"}, idCtx.TeamMemberAllowedModels)
	assert.Equal(t, int64(2_000_000), idCtx.TeamMemberMaxBudgetMicros)
	assert.Equal(t, 25, idCtx.TeamMemberRPMLimit)
	assert.Equal(t, 5000, idCtx.TeamMemberTPMLimit)

	// M:N AuthResolver: JWT with team_ids=["team_a2"] resolves usr_multi's team_a2 membership
	tok, err := auth.SignHS256(cfg.Auth.JWTSecret, &auth.JWTClaims{
		Subject:   "sub-multi",
		Issuer:    cfg.Auth.JWTIssuer,
		Audience:  auth.AudienceClaim{cfg.Auth.JWTAudience},
		TeamIDs:   []string{"team_a2"},
		ExpiresAt: time.Now().UTC().Add(5 * time.Minute).Unix(),
	})
	require.NoError(t, err)
	jwtReq := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	jwtReq.Header.Set("Authorization", "Bearer "+tok)
	jwtIDCtx, err := gw.AuthService().DataPlaneResolver().ResolveRequest(ctx, jwtReq)
	require.NoError(t, err)
	assert.Equal(t, "team_a2", jwtIDCtx.TeamID)
	assert.Equal(t, domain.RoleTeamAdmin, jwtIDCtx.Role)
	assert.Equal(t, []string{"gpt-4.1-mini"}, jwtIDCtx.TeamMemberAllowedModels)
	assert.Equal(t, 80, jwtIDCtx.TeamMemberRPMLimit)
	assert.Equal(t, int64(4_000_000), jwtIDCtx.TeamMemberMaxBudgetMicros)

	// PUT /admin/v1/keys/{keyID} can unbind project_id and invalidate cache
	rec = doAdminJSONRequest(t, handler, http.MethodPut, "/admin/v1/keys/"+boundKey.ID, teamA1AdminVK.RawKey, map[string]any{
		"project_id": "",
	})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	idAfterUnbind, err := gw.AuthService().AuthenticateVirtualKey(ctx, boundKey.RawKey)
	require.NoError(t, err)
	assert.Equal(t, "", idAfterUnbind.ProjectID)
	assert.Empty(t, idAfterUnbind.ProjectAllowedModels)

	// Delete membership and project cleanly
	rec = doAdminJSONRequest(t, handler, http.MethodDelete, "/admin/v1/teams/team_a1/members/usr_multi", teamA1AdminVK.RawKey, nil)
	require.Equal(t, http.StatusOK, rec.Code)

	rec = doAdminJSONRequest(t, handler, http.MethodDelete, "/admin/v1/projects/proj_a1_prod", teamA1AdminVK.RawKey, nil)
	require.Equal(t, http.StatusOK, rec.Code)
}

func TestProjectModelRBAC_AndEnforceProjectModelQuota_DataPlane(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()

	require.NoError(t, repo.CreateOrganization(ctx, &domain.Organization{ID: "org_q", Name: "Quota Org", Slug: "quota-org", IsActive: true}))
	require.NoError(t, repo.CreateTeam(ctx, &domain.Team{
		ID:            "team_q",
		OrgID:         "org_q",
		Name:          "Quota Team",
		AllowedModels: []string{"gpt-4.1", "gpt-4.1-mini"},
		IsActive:      true,
	}))
	require.NoError(t, repo.CreateUser(ctx, &domain.User{
		ID:       "usr_q",
		OrgID:    "org_q",
		TeamID:   "team_q",
		Email:    "q@quota.example",
		Name:     "Q User",
		Role:     domain.RoleDeveloper,
		IsActive: true,
	}))
	require.NoError(t, repo.UpsertTeamMembership(ctx, &domain.TeamMembership{
		OrgID:         "org_q",
		TeamID:        "team_q",
		UserID:        "usr_q",
		Role:          domain.RoleDeveloper,
		AllowedModels: []string{"gpt-4.1", "gpt-4.1-mini"},
	}))
	require.NoError(t, repo.CreateProject(ctx, &domain.Project{
		ID:                       "proj_strict",
		OrgID:                    "org_q",
		TeamID:                   "team_q",
		Name:                     "Strict Project",
		AllowedModels:            []string{"gpt-4.1"},
		EnforceProjectModelQuota: true,
		IsActive:                 true,
	}))

	// Configure a mock OpenAI deployment so admitted requests can succeed or fail cleanly at upstream
	mockUpstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"id":"chatcmpl-1","object":"chat.completion","model":"gpt-4.1","choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],"usage":{"prompt_tokens":5,"completion_tokens":2,"total_tokens":7}}`))
	}))
	defer mockUpstream.Close()

	cfg := config.Default()
	cfg.Auth.MasterAdminKey = "sk-gw-master-proj-quota-test"
	cfg.RateLimit.FallbackToLocalOnOutage = true
	cfg.Security.Network.OutboundSSRF.AllowPrivateNetworks = true
	cfg.Security.Network.OutboundSSRF.AllowInsecureHTTP = true

	gw, err := server.New(cfg, repo, nil, mockUpstream.Client())
	require.NoError(t, err)
	gw.StartWorkers(ctx)
	defer gw.Shutdown(ctx)
	handler := gw.Handler()

	// Seed credential + model group + deployment via admin API
	rec := doAdminJSONRequest(t, handler, http.MethodPost, "/admin/v1/credentials", cfg.Auth.MasterAdminKey, map[string]any{
		"org_id":   "org_q",
		"provider": "openai",
		"name":     "mock-openai",
		"base_url": mockUpstream.URL,
		"api_key":  "sk-upstream-mock",
	})
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	var cred domain.ProviderCredential
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &cred))

	rec = doAdminJSONRequest(t, handler, http.MethodPost, "/admin/v1/model-groups", cfg.Auth.MasterAdminKey, map[string]any{
		"org_id":           "org_q",
		"alias":            "gpt-4.1",
		"routing_strategy": "simple-shuffle",
	})
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	var mg domain.ModelGroup
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &mg))

	rec = doAdminJSONRequest(t, handler, http.MethodPost, "/admin/v1/deployments", cfg.Auth.MasterAdminKey, map[string]any{
		"model_group_id":  mg.ID,
		"global_model_id": "openai/gpt-4.1",
		"credential_id":   cred.ID,
		"weight":          1,
	})
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())

	// Issue two keys bound to proj_strict: one without RPM/TPM limits, one with RPM=10
	unboundedKey, err := gw.AuthService().IssueVirtualKey(ctx, &domain.VirtualKey{
		OrgID:     "org_q",
		TeamID:    "team_q",
		ProjectID: "proj_strict",
		UserID:    "usr_q",
		Name:      "unbounded-strict-key",
		Role:      domain.RoleDeveloper,
	})
	require.NoError(t, err)

	boundedKey, err := gw.AuthService().IssueVirtualKey(ctx, &domain.VirtualKey{
		OrgID:     "org_q",
		TeamID:    "team_q",
		ProjectID: "proj_strict",
		UserID:    "usr_q",
		Name:      "bounded-strict-key",
		Role:      domain.RoleDeveloper,
		RPMLimit:  10,
	})
	require.NoError(t, err)

	callChat := func(bearer, model string) *httptest.ResponseRecorder {
		body := `{"model":"` + model + `","messages":[{"role":"user","content":"hi"}]}`
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+bearer)
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		handler.ServeHTTP(rr, req)
		return rr
	}

	// 1. Model allowed by team & membership, but outside ProjectAllowedModels -> 403 project_model_restricted
	rr := callChat(boundedKey.RawKey, "gpt-4.1-mini")
	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), "project_model_restricted")

	// 2. Model allowed by project, key lacks RPM/TPM limits & no QuotaPolicy -> 403 project_model_quota_required
	rr = callChat(unboundedKey.RawKey, "gpt-4.1")
	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), "project_model_quota_required")

	// 3. Key with positive RPM limit passes project_model_quota_required and reaches upstream -> 200
	rr = callChat(boundedKey.RawKey, "gpt-4.1")
	assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())

	// 4. Adding a QuotaScopeModelPerProject policy satisfies enforce_project_model_quota for unboundedKey!
	require.NoError(t, repo.UpsertQuotaPolicy(ctx, &domain.QuotaPolicy{
		OrgID:        "org_q",
		ScopeType:    domain.QuotaScopeModelPerProject,
		ScopeID:      "proj_strict",
		ModelPattern: "gpt-4.1",
		RPMLimit:     20,
		IsActive:     true,
	}))
	gw.RBAC().InvalidatePolicyScope(ctx, "rbac_quotas", "org_q")
	rr = callChat(unboundedKey.RawKey, "gpt-4.1")
	assert.Equal(t, http.StatusOK, rr.Code, rr.Body.String())

	// 5. TeamMemberAllowedModels restriction blocks model even if project & team allow it
	require.NoError(t, repo.UpsertTeamMembership(ctx, &domain.TeamMembership{
		OrgID:         "org_q",
		TeamID:        "team_q",
		UserID:        "usr_q",
		Role:          domain.RoleDeveloper,
		AllowedModels: []string{"gpt-4.1-mini"},
	}))
	gw.AuthService().InvalidateTeam(ctx, "team_q")

	rr = callChat(boundedKey.RawKey, "gpt-4.1")
	assert.Equal(t, http.StatusForbidden, rr.Code)
	assert.Contains(t, rr.Body.String(), "team_member_model_restricted")
}
