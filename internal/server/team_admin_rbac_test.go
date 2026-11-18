package server_test

import (
	"context"
	"encoding/json"
	"net/http"
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

func TestTeamAdminControlPlaneRBAC_IsolationAndScopedOperations(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()

	require.NoError(t, repo.CreateOrganization(ctx, &domain.Organization{ID: "org_a", Name: "Org A", Slug: "org-a", IsActive: true}))
	require.NoError(t, repo.CreateOrganization(ctx, &domain.Organization{ID: "org_b", Name: "Org B", Slug: "org-b", IsActive: true}))

	require.NoError(t, repo.CreateTeam(ctx, &domain.Team{ID: "team_a1", OrgID: "org_a", Name: "Team A1", MaxBudgetMicros: 50_000_000, IsActive: true}))
	require.NoError(t, repo.CreateTeam(ctx, &domain.Team{ID: "team_a2", OrgID: "org_a", Name: "Team A2", MaxBudgetMicros: 50_000_000, IsActive: true}))
	require.NoError(t, repo.CreateTeam(ctx, &domain.Team{ID: "team_b1", OrgID: "org_b", Name: "Team B1", MaxBudgetMicros: 50_000_000, IsActive: true}))

	require.NoError(t, repo.CreateUser(ctx, &domain.User{
		ID:          "usr_a1_admin",
		OrgID:       "org_a",
		TeamID:      "team_a1",
		Email:       "lead-a1@orga.example",
		Name:        "Team A1 Admin",
		Role:        domain.RoleTeamAdmin,
		OIDCSubject: "sub-a1-admin",
		IsActive:    true,
	}))
	require.NoError(t, repo.CreateUser(ctx, &domain.User{
		ID:       "usr_a1_dev",
		OrgID:    "org_a",
		TeamID:   "team_a1",
		Email:    "dev-a1@orga.example",
		Name:     "Team A1 Dev",
		Role:     domain.RoleDeveloper,
		IsActive: true,
	}))
	require.NoError(t, repo.CreateUser(ctx, &domain.User{
		ID:       "usr_a2_dev",
		OrgID:    "org_a",
		TeamID:   "team_a2",
		Email:    "dev-a2@orga.example",
		Name:     "Team A2 Dev",
		Role:     domain.RoleDeveloper,
		IsActive: true,
	}))

	cfg := config.Default()
	cfg.Auth.MasterAdminKey = "sk-gw-master-team-admin-test"
	cfg.Auth.JWTSecret = "team-admin-control-plane-jwt-secret"
	cfg.Auth.JWTIssuer = "https://idp.orga.example"
	cfg.Auth.JWTAudience = "ai-gateway"
	cfg.Auth.DefaultOrgID = "org_a"

	gw, err := server.New(cfg, repo, nil, nil)
	require.NoError(t, err)
	gw.StartWorkers(ctx)
	defer gw.Shutdown(ctx)
	handler := gw.Handler()

	// Issue a team_admin VirtualKey for team_a1, a key in team_a2, and an org-wide key in org_a.
	teamAdminVK, err := gw.AuthService().IssueVirtualKey(ctx, &domain.VirtualKey{
		ID:     "vk_team_a1_admin",
		OrgID:  "org_a",
		TeamID: "team_a1",
		UserID: "usr_a1_admin",
		Name:   "team-a1-admin-key",
		Role:   domain.RoleTeamAdmin,
	})
	require.NoError(t, err)

	otherTeamVK, err := gw.AuthService().IssueVirtualKey(ctx, &domain.VirtualKey{
		ID:     "vk_team_a2_worker",
		OrgID:  "org_a",
		TeamID: "team_a2",
		UserID: "usr_a2_dev",
		Name:   "team-a2-worker",
		Role:   domain.RoleDeveloper,
	})
	require.NoError(t, err)

	orgWideVK, err := gw.AuthService().IssueVirtualKey(ctx, &domain.VirtualKey{
		ID:    "vk_org_a_wide",
		OrgID: "org_a",
		Name:  "org-a-wide-key",
		Role:  domain.RoleServiceAccount,
	})
	require.NoError(t, err)

	// Record spend logs across team_a1 (1,500,000 micros) and team_a2 (4,200,000 micros).
	require.NoError(t, repo.RecordSpendBatch(ctx, []domain.SpendEvent{
		{
			ID:            "sp_a1_1",
			RequestID:     "req_a1_1",
			OrgID:         "org_a",
			TeamID:        "team_a1",
			UserID:        "usr_a1_dev",
			VirtualKeyID:  teamAdminVK.ID,
			Endpoint:      "/v1/chat/completions",
			ResolvedModel: "gpt-4.1",
			Provider:      domain.ProviderOpenAI,
			Usage:         domain.TokenUsage{PromptTokens: 100, CompletionTokens: 50, TotalTokens: 150},
			CostMicros:    1_500_000,
			PricingStatus: domain.PricingStatusVerified,
			CreatedAt:     time.Now().UTC(),
		},
		{
			ID:            "sp_a2_1",
			RequestID:     "req_a2_1",
			OrgID:         "org_a",
			TeamID:        "team_a2",
			UserID:        "usr_a2_dev",
			VirtualKeyID:  otherTeamVK.ID,
			Endpoint:      "/v1/chat/completions",
			ResolvedModel: "claude-sonnet-4",
			Provider:      domain.ProviderAnthropic,
			Usage:         domain.TokenUsage{PromptTokens: 300, CompletionTokens: 200, TotalTokens: 500},
			CostMicros:    4_200_000,
			PricingStatus: domain.PricingStatusVerified,
			CreatedAt:     time.Now().UTC(),
		},
	}))

	teamAdminJWT, err := auth.SignHS256(cfg.Auth.JWTSecret, &auth.JWTClaims{
		Subject:   "sub-a1-admin",
		Issuer:    cfg.Auth.JWTIssuer,
		Audience:  auth.AudienceClaim{cfg.Auth.JWTAudience},
		ExpiresAt: time.Now().UTC().Add(10 * time.Minute).Unix(),
	})
	require.NoError(t, err)

	for _, cred := range []struct {
		label  string
		bearer string
	}{
		{label: "team_admin_virtual_key", bearer: teamAdminVK.RawKey},
		{label: "team_admin_jwt", bearer: teamAdminJWT},
	} {
		t.Run(cred.label, func(t *testing.T) {
			// --- 1. Team Endpoints ---
			// Own team list returns only team_a1.
			rec := doAdminJSONRequest(t, handler, http.MethodGet, "/admin/v1/teams", cred.bearer, nil)
			require.Equal(t, http.StatusOK, rec.Code)
			var teamsResp struct {
				Data []*domain.Team `json:"data"`
			}
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &teamsResp))
			require.Len(t, teamsResp.Data, 1)
			assert.Equal(t, "team_a1", teamsResp.Data[0].ID)

			// Querying another team or another org is rejected with 403.
			rec = doAdminJSONRequest(t, handler, http.MethodGet, "/admin/v1/teams?team_id=team_a2", cred.bearer, nil)
			assert.Equal(t, http.StatusForbidden, rec.Code)
			rec = doAdminJSONRequest(t, handler, http.MethodGet, "/admin/v1/teams?org_id=org_b", cred.bearer, nil)
			assert.Equal(t, http.StatusForbidden, rec.Code)

			// Updating own team is allowed.
			rec = doAdminJSONRequest(t, handler, http.MethodPut, "/admin/v1/teams/team_a1", cred.bearer, map[string]any{
				"name":      "Team A1 Updated",
				"rpm_limit": 250,
			})
			require.Equal(t, http.StatusOK, rec.Code)
			var updatedTeam domain.Team
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &updatedTeam))
			assert.Equal(t, "Team A1 Updated", updatedTeam.Name)
			assert.Equal(t, 250, updatedTeam.RPMLimit)

			// Updating another team, creating a team, or deleting own/other team are all rejected with 403.
			rec = doAdminJSONRequest(t, handler, http.MethodPut, "/admin/v1/teams/team_a2", cred.bearer, map[string]any{
				"name": "Hijacked A2",
			})
			assert.Equal(t, http.StatusForbidden, rec.Code)
			rec = doAdminJSONRequest(t, handler, http.MethodPost, "/admin/v1/teams", cred.bearer, map[string]any{
				"name": "Unauthorized New Team",
			})
			assert.Equal(t, http.StatusForbidden, rec.Code)
			rec = doAdminJSONRequest(t, handler, http.MethodDelete, "/admin/v1/teams/team_a1", cred.bearer, nil)
			assert.Equal(t, http.StatusForbidden, rec.Code)

			// --- 2. Virtual Key Lifecycle Endpoints ---
			// Issuing a key for own team succeeds.
			rec = doAdminJSONRequest(t, handler, http.MethodPost, "/admin/v1/keys", cred.bearer, map[string]any{
				"name":              "a1-issued-by-" + cred.label,
				"team_id":           "team_a1",
				"user_id":           "usr_a1_dev",
				"role":              "developer",
				"max_budget_micros": 3_000_000,
			})
			require.Equal(t, http.StatusCreated, rec.Code)
			var issued domain.VirtualKey
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &issued))
			require.True(t, strings.HasPrefix(issued.RawKey, "sk-gw-"))
			assert.Equal(t, "team_a1", issued.TeamID)

			// Issuing an org-wide key (empty team_id), cross-team key, cross-team user, or privileged role fails with 403.
			rec = doAdminJSONRequest(t, handler, http.MethodPost, "/admin/v1/keys", cred.bearer, map[string]any{
				"name": "org-wide-attempt",
			})
			assert.Equal(t, http.StatusForbidden, rec.Code)

			rec = doAdminJSONRequest(t, handler, http.MethodPost, "/admin/v1/keys", cred.bearer, map[string]any{
				"name":    "cross-team-attempt",
				"team_id": "team_a2",
			})
			assert.Equal(t, http.StatusForbidden, rec.Code)

			rec = doAdminJSONRequest(t, handler, http.MethodPost, "/admin/v1/keys", cred.bearer, map[string]any{
				"name":    "cross-team-user-attempt",
				"team_id": "team_a1",
				"user_id": "usr_a2_dev",
			})
			assert.Equal(t, http.StatusForbidden, rec.Code)

			for _, forbiddenRole := range []string{"org_admin", "org_viewer", "viewer", "platform_admin"} {
				rec = doAdminJSONRequest(t, handler, http.MethodPost, "/admin/v1/keys", cred.bearer, map[string]any{
					"name":    "priv-escalation-" + forbiddenRole,
					"team_id": "team_a1",
					"role":    forbiddenRole,
				})
				assert.Equal(t, http.StatusForbidden, rec.Code, "expected 403 issuing role %s as team_admin", forbiddenRole)
			}

			// Listing keys returns only team_a1 keys.
			rec = doAdminJSONRequest(t, handler, http.MethodGet, "/admin/v1/keys", cred.bearer, nil)
			require.Equal(t, http.StatusOK, rec.Code)
			var keysResp struct {
				Data []*domain.VirtualKey `json:"data"`
			}
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &keysResp))
			require.NotEmpty(t, keysResp.Data)
			for _, k := range keysResp.Data {
				assert.Equal(t, "team_a1", k.TeamID, "team_admin must never see keys outside team_a1")
			}
			rec = doAdminJSONRequest(t, handler, http.MethodGet, "/admin/v1/keys?team_id=team_a2", cred.bearer, nil)
			assert.Equal(t, http.StatusForbidden, rec.Code)

			// Updating own team key succeeds; moving it out of team_a1 or escalating role fails with 403.
			rec = doAdminJSONRequest(t, handler, http.MethodPut, "/admin/v1/keys/"+issued.ID, cred.bearer, map[string]any{
				"name":      "a1-renamed-" + cred.label,
				"rpm_limit": 60,
			})
			require.Equal(t, http.StatusOK, rec.Code)

			rec = doAdminJSONRequest(t, handler, http.MethodPut, "/admin/v1/keys/"+issued.ID, cred.bearer, map[string]any{
				"team_id": "team_a2",
			})
			assert.Equal(t, http.StatusForbidden, rec.Code)

			rec = doAdminJSONRequest(t, handler, http.MethodPut, "/admin/v1/keys/"+issued.ID, cred.bearer, map[string]any{
				"team_id": "",
			})
			assert.Equal(t, http.StatusForbidden, rec.Code)

			rec = doAdminJSONRequest(t, handler, http.MethodPut, "/admin/v1/keys/"+issued.ID, cred.bearer, map[string]any{
				"role": "org_admin",
			})
			assert.Equal(t, http.StatusForbidden, rec.Code)

			// Updating, rotating, or revoking another team's key or an org-wide key fails with 403.
			for _, disallowedKeyID := range []string{otherTeamVK.ID, orgWideVK.ID} {
				rec = doAdminJSONRequest(t, handler, http.MethodPut, "/admin/v1/keys/"+disallowedKeyID, cred.bearer, map[string]any{
					"name": "tampered",
				})
				assert.Equal(t, http.StatusForbidden, rec.Code)
				rec = doAdminJSONRequest(t, handler, http.MethodPost, "/admin/v1/keys/"+disallowedKeyID+"/rotate", cred.bearer, nil)
				assert.Equal(t, http.StatusForbidden, rec.Code)
				rec = doAdminJSONRequest(t, handler, http.MethodPost, "/admin/v1/keys/"+disallowedKeyID+"/revoke", cred.bearer, nil)
				assert.Equal(t, http.StatusForbidden, rec.Code)
			}

			// Rotating and revoking own team's key succeeds.
			rec = doAdminJSONRequest(t, handler, http.MethodPost, "/admin/v1/keys/"+issued.ID+"/rotate", cred.bearer, nil)
			require.Equal(t, http.StatusOK, rec.Code)
			rec = doAdminJSONRequest(t, handler, http.MethodPost, "/admin/v1/keys/"+issued.ID+"/revoke", cred.bearer, nil)
			require.Equal(t, http.StatusOK, rec.Code)

			// --- 3. Users Endpoints ---
			// Listing users returns only team_a1 users.
			rec = doAdminJSONRequest(t, handler, http.MethodGet, "/admin/v1/users", cred.bearer, nil)
			require.Equal(t, http.StatusOK, rec.Code)
			var usersResp struct {
				Data []*domain.User `json:"data"`
			}
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &usersResp))
			require.Len(t, usersResp.Data, 2)
			for _, u := range usersResp.Data {
				assert.Equal(t, "team_a1", u.TeamID)
			}
			rec = doAdminJSONRequest(t, handler, http.MethodGet, "/admin/v1/users?team_id=team_a2", cred.bearer, nil)
			assert.Equal(t, http.StatusForbidden, rec.Code)

			// Creating, updating, or deleting users is rejected with 403 for team_admin.
			rec = doAdminJSONRequest(t, handler, http.MethodPost, "/admin/v1/users", cred.bearer, map[string]any{
				"email":   "new@orga.example",
				"name":    "New User",
				"team_id": "team_a1",
			})
			assert.Equal(t, http.StatusForbidden, rec.Code)
			rec = doAdminJSONRequest(t, handler, http.MethodPut, "/admin/v1/users/usr_a1_dev", cred.bearer, map[string]any{
				"name": "Modified Dev",
			})
			assert.Equal(t, http.StatusForbidden, rec.Code)
			rec = doAdminJSONRequest(t, handler, http.MethodDelete, "/admin/v1/users/usr_a1_dev", cred.bearer, nil)
			assert.Equal(t, http.StatusForbidden, rec.Code)

			// --- 4. Spend Summary & Logs Endpoints ---
			rec = doAdminJSONRequest(t, handler, http.MethodGet, "/admin/v1/spend/summary", cred.bearer, nil)
			require.Equal(t, http.StatusOK, rec.Code)
			var summary storage.SpendSummary
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &summary))
			assert.Equal(t, int64(1), summary.TotalRequests)
			assert.Equal(t, int64(150), summary.TotalTokens)
			assert.Equal(t, int64(1_500_000), summary.TotalCostMicros)
			assert.Equal(t, map[string]int64{"team_a1": 1_500_000}, summary.SpendByTeam)

			rec = doAdminJSONRequest(t, handler, http.MethodGet, "/admin/v1/spend/summary?team_id=team_a2", cred.bearer, nil)
			assert.Equal(t, http.StatusForbidden, rec.Code)

			rec = doAdminJSONRequest(t, handler, http.MethodGet, "/admin/v1/spend/logs", cred.bearer, nil)
			require.Equal(t, http.StatusOK, rec.Code)
			var spendLogsResp struct {
				Data []domain.SpendEvent `json:"data"`
			}
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &spendLogsResp))
			require.Len(t, spendLogsResp.Data, 1)
			assert.Equal(t, "team_a1", spendLogsResp.Data[0].TeamID)
			assert.Equal(t, int64(1_500_000), spendLogsResp.Data[0].CostMicros)

			rec = doAdminJSONRequest(t, handler, http.MethodGet, "/admin/v1/spend/logs?team_id=team_a2", cred.bearer, nil)
			assert.Equal(t, http.StatusForbidden, rec.Code)

			// --- 5. Org-Wide and Platform Endpoints Reject team_admin with 403 ---
			orgWideRoutes := []struct {
				method string
				path   string
				body   any
			}{
				{http.MethodGet, "/admin/v1/organizations", nil},
				{http.MethodPost, "/admin/v1/organizations", map[string]any{"name": "New Org"}},
				{http.MethodGet, "/admin/v1/credentials", nil},
				{http.MethodGet, "/admin/v1/model-groups", nil},
				{http.MethodGet, "/admin/v1/deployments", nil},
				{http.MethodGet, "/admin/v1/audit/logs", nil},
				{http.MethodGet, "/admin/v1/config", nil},
				{http.MethodGet, "/admin/v1/catalogue", nil},
				{http.MethodGet, "/admin/v1/jwt-mappings", nil},
				{http.MethodGet, "/admin/v1/access-group-rules", nil},
				{http.MethodPost, "/admin/v1/access-group-rules", map[string]any{
					"name": "r", "attribute": "team_id", "operator": "equals", "value": "team_a1", "allowed_models": []string{"*"},
				}},
			}
			for _, rt := range orgWideRoutes {
				rec = doAdminJSONRequest(t, handler, rt.method, rt.path, cred.bearer, rt.body)
				assert.Equal(t, http.StatusForbidden, rec.Code, "expected 403 on %s %s for team_admin", rt.method, rt.path)
			}
		})
	}
}

func TestAdminAccessGroupRules_CRUDAndDynamicModelGrant(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()

	require.NoError(t, repo.CreateOrganization(ctx, &domain.Organization{ID: "org_a", Name: "Org A", Slug: "org-a", IsActive: true}))
	require.NoError(t, repo.CreateOrganization(ctx, &domain.Organization{ID: "org_b", Name: "Org B", Slug: "org-b", IsActive: true}))
	require.NoError(t, repo.CreateTeam(ctx, &domain.Team{
		ID:            "team_a1",
		OrgID:         "org_a",
		Name:          "Restricted Team A1",
		AllowedModels: []string{"gpt-4.1-mini"},
		IsActive:      true,
	}))
	require.NoError(t, repo.CreateUser(ctx, &domain.User{
		ID:          "usr_researcher",
		OrgID:       "org_a",
		TeamID:      "team_a1",
		Email:       "researcher@orga.example",
		Name:        "AI Researcher",
		Role:        domain.RoleDeveloper,
		OIDCSubject: "sub-researcher",
		IsActive:    true,
	}))

	cfg := config.Default()
	cfg.Auth.MasterAdminKey = "sk-gw-master-access-rules-test"
	cfg.Auth.EnableDataPlaneJWT = true
	cfg.Auth.JWTSecret = "access-rules-dataplane-secret"
	cfg.Auth.JWTIssuer = "https://idp.orga.example"
	cfg.Auth.JWTAudience = "ai-gateway"
	cfg.Auth.DefaultOrgID = "org_a"

	gw, err := server.New(cfg, repo, nil, nil)
	require.NoError(t, err)
	gw.StartWorkers(ctx)
	defer gw.Shutdown(ctx)
	handler := gw.Handler()

	orgAdminA, err := gw.AuthService().IssueVirtualKey(ctx, &domain.VirtualKey{
		OrgID: "org_a",
		Name:  "org-a-admin",
		Role:  domain.RoleOrgAdmin,
	})
	require.NoError(t, err)

	orgViewerA, err := gw.AuthService().IssueVirtualKey(ctx, &domain.VirtualKey{
		OrgID: "org_a",
		Name:  "org-a-viewer",
		Role:  domain.RoleOrgViewer,
	})
	require.NoError(t, err)

	researcherJWT, err := auth.SignHS256(cfg.Auth.JWTSecret, &auth.JWTClaims{
		Subject:   "sub-researcher",
		Issuer:    cfg.Auth.JWTIssuer,
		Audience:  auth.AudienceClaim{cfg.Auth.JWTAudience},
		OrgID:     "org_a",
		ExpiresAt: time.Now().UTC().Add(10 * time.Minute).Unix(),
		RawClaims: map[string]any{
			"groups": []string{"engineering", "ai-research"},
		},
	})
	require.NoError(t, err)

	// 1. Before creating the rule, researcher in team_a1 only sees gpt-4.1-mini on GET /v1/models
	// and is denied claude-sonnet-4-20250514.
	rec := doAdminJSONRequest(t, handler, http.MethodGet, "/v1/models", researcherJWT, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "gpt-4.1-mini")
	assert.NotContains(t, rec.Body.String(), "claude-sonnet-4-20250514")

	// 2. org_viewer cannot create rule (403); invalid operator returns 400; cross-org returns 403.
	rec = doAdminJSONRequest(t, handler, http.MethodPost, "/admin/v1/access-group-rules", orgViewerA.RawKey, map[string]any{
		"name":           "Viewer Attempt",
		"attribute":      "jwt_claims.groups",
		"operator":       "in_list",
		"value":          "ai-research",
		"allowed_models": []string{"claude-sonnet-4-20250514"},
	})
	assert.Equal(t, http.StatusForbidden, rec.Code)

	rec = doAdminJSONRequest(t, handler, http.MethodPost, "/admin/v1/access-group-rules", orgAdminA.RawKey, map[string]any{
		"name":           "Bad Operator",
		"attribute":      "jwt_claims.groups",
		"operator":       "invalid_op",
		"value":          "ai-research",
		"allowed_models": []string{"claude-sonnet-4-20250514"},
	})
	assert.Equal(t, http.StatusBadRequest, rec.Code)

	rec = doAdminJSONRequest(t, handler, http.MethodPost, "/admin/v1/access-group-rules", orgAdminA.RawKey, map[string]any{
		"org_id":         "org_b",
		"name":           "Cross Org Attempt",
		"attribute":      "jwt_claims.groups",
		"operator":       "in_list",
		"value":          "ai-research",
		"allowed_models": []string{"claude-sonnet-4-20250514"},
	})
	assert.Equal(t, http.StatusForbidden, rec.Code)

	// 3. org_admin creates rule in org_a (201 Created).
	rec = doAdminJSONRequest(t, handler, http.MethodPost, "/admin/v1/access-group-rules", orgAdminA.RawKey, map[string]any{
		"name":            "AI Research Frontier Models",
		"attribute":       "jwt_claims.groups",
		"operator":        "in_list",
		"value":           "ai-research,ml-platform",
		"allowed_models":  []string{"claude-sonnet-4-20250514", "anthropic/claude-sonnet-4-20250514"},
		"access_group_id": "frontier-research",
		"priority":        20,
	})
	require.Equal(t, http.StatusCreated, rec.Code)
	var createdRule domain.AccessGroupRule
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &createdRule))
	require.NotEmpty(t, createdRule.ID)
	assert.Equal(t, "org_a", createdRule.OrgID)
	assert.Equal(t, "frontier-research", createdRule.AccessGroupID)

	// 4. GET /admin/v1/access-group-rules returns the created rule for org_admin and org_viewer.
	rec = doAdminJSONRequest(t, handler, http.MethodGet, "/admin/v1/access-group-rules", orgViewerA.RawKey, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	var listResp struct {
		Data []*domain.AccessGroupRule `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &listResp))
	require.Len(t, listResp.Data, 1)
	assert.Equal(t, createdRule.ID, listResp.Data[0].ID)

	// 5. Researcher JWT now dynamically receives access to claude-sonnet-4-20250514 on GET /v1/models!
	rec = doAdminJSONRequest(t, handler, http.MethodGet, "/v1/models", researcherJWT, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "gpt-4.1-mini")
	assert.Contains(t, rec.Body.String(), "claude-sonnet-4-20250514")

	// 6. Delete the rule and verify immediate cache eviction on GET /v1/models.
	rec = doAdminJSONRequest(t, handler, http.MethodDelete, "/admin/v1/access-group-rules/"+createdRule.ID, orgAdminA.RawKey, nil)
	require.Equal(t, http.StatusOK, rec.Code)

	rec = doAdminJSONRequest(t, handler, http.MethodGet, "/v1/models", researcherJWT, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.NotContains(t, rec.Body.String(), "claude-sonnet-4-20250514")

	// Verify audit logs recorded access_group_rule.created and access_group_rule.deleted.
	auditLogs, err := repo.ListAuditLogs(ctx, "org_a", 20)
	require.NoError(t, err)
	var sawCreated, sawDeleted bool
	for _, l := range auditLogs {
		if l.Action == "access_group_rule.created" && l.ResourceID == createdRule.ID {
			sawCreated = true
		}
		if l.Action == "access_group_rule.deleted" && l.ResourceID == createdRule.ID {
			sawDeleted = true
		}
	}
	assert.True(t, sawCreated, "expected access_group_rule.created audit log")
	assert.True(t, sawDeleted, "expected access_group_rule.deleted audit log")
}
