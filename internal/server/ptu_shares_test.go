package server_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/server"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAdminPTUShares_CRUD_Isolation_And_TeamDelete409Guard(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	cfg := config.Default()
	cfg.Auth.MasterAdminKey = "admin_master_secret"

	gw, err := server.New(cfg, repo, nil, nil)
	require.NoError(t, err)
	handler := gw.Handler()

	// Setup Org A & Org B
	require.NoError(t, repo.CreateOrganization(ctx, &domain.Organization{ID: "org_a", Name: "Org A", Slug: "org-a", IsActive: true}))
	require.NoError(t, repo.CreateOrganization(ctx, &domain.Organization{ID: "org_b", Name: "Org B", Slug: "org-b", IsActive: true}))

	adminKeyA, err := gw.AuthService().IssueVirtualKey(ctx, &domain.VirtualKey{
		OrgID: "org_a",
		Name:  "org-a-admin",
		Role:  domain.RoleOrgAdmin,
	})
	require.NoError(t, err)
	adminKeyB, err := gw.AuthService().IssueVirtualKey(ctx, &domain.VirtualKey{
		OrgID: "org_b",
		Name:  "org-b-admin",
		Role:  domain.RoleOrgAdmin,
	})
	require.NoError(t, err)
	viewerKeyA, err := gw.AuthService().IssueVirtualKey(ctx, &domain.VirtualKey{
		OrgID: "org_a",
		Name:  "org-a-viewer",
		Role:  domain.RoleOrgViewer,
	})
	require.NoError(t, err)

	// Setup teams, credential, model group, and deployment in Org A
	require.NoError(t, repo.CreateTeam(ctx, &domain.Team{ID: "team_a1", OrgID: "org_a", Name: "Team A1", IsActive: true}))
	require.NoError(t, repo.CreateTeam(ctx, &domain.Team{ID: "team_a2", OrgID: "org_a", Name: "Team A2", IsActive: true}))
	require.NoError(t, repo.CreateTeam(ctx, &domain.Team{ID: "team_b1", OrgID: "org_b", Name: "Team B1", IsActive: true}))

	require.NoError(t, repo.CreateModelGroup(ctx, &domain.ModelGroup{
		ID:              "mg_a",
		OrgID:           "org_a",
		Alias:           "gpt-4.1",
		RoutingStrategy: domain.StrategyWeightedShuffle,
		IsActive:        true,
	}))
	require.NoError(t, repo.CreateDeployment(ctx, &domain.Deployment{
		ID:             "dep_a1",
		ModelGroupID:   "mg_a",
		GlobalModelID:  "openai/gpt-4.1",
		DeploymentName: "ptu-dep-a1",
		RPMCapacity:    100,
		TPMCapacity:    100000,
		Status:         domain.DeploymentStatusActive,
	}))

	// 1. Upsert PTU share for team_a1
	rec := doAdminJSONRequest(t, handler, http.MethodPost, "/admin/v1/deployments/dep_a1/ptu-shares", adminKeyA.RawKey, map[string]any{
		"team_id":      "team_a1",
		"reserved_rpm": 60,
		"reserved_tpm": 60000,
	})
	require.Equal(t, http.StatusOK, rec.Code)
	var createdShare domain.DeploymentPTUShare
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &createdShare))
	assert.NotEmpty(t, createdShare.ID)
	assert.Equal(t, "org_a", createdShare.OrgID)
	assert.Equal(t, "dep_a1", createdShare.DeploymentID)
	assert.Equal(t, "team_a1", createdShare.TeamID)
	assert.Equal(t, 60, createdShare.ReservedRPM)
	assert.Equal(t, 60000, createdShare.ReservedTPM)

	// 2. Reject over-allocation beyond deployment capacity (60 + 50 > 100)
	rec = doAdminJSONRequest(t, handler, http.MethodPost, "/admin/v1/deployments/dep_a1/ptu-shares", adminKeyA.RawKey, map[string]any{
		"team_id":      "team_a2",
		"reserved_rpm": 50,
		"reserved_tpm": 10000,
	})
	require.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "ptu_capacity_exceeded")

	// 3. Cross-org team assignment rejected (403)
	rec = doAdminJSONRequest(t, handler, http.MethodPost, "/admin/v1/deployments/dep_a1/ptu-shares", adminKeyA.RawKey, map[string]any{
		"team_id":      "team_b1",
		"reserved_rpm": 10,
	})
	require.Equal(t, http.StatusForbidden, rec.Code)

	// 4. Cross-org operator rejected (403)
	rec = doAdminJSONRequest(t, handler, http.MethodGet, "/admin/v1/deployments/dep_a1/ptu-shares", adminKeyB.RawKey, nil)
	require.Equal(t, http.StatusForbidden, rec.Code)

	// 5. Org viewer can GET but cannot POST/DELETE
	rec = doAdminJSONRequest(t, handler, http.MethodGet, "/admin/v1/deployments/dep_a1/ptu-shares", viewerKeyA.RawKey, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	var listResp struct {
		Data []domain.DeploymentPTUShare `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &listResp))
	require.Len(t, listResp.Data, 1)
	assert.Equal(t, "team_a1", listResp.Data[0].TeamID)

	rec = doAdminJSONRequest(t, handler, http.MethodPost, "/admin/v1/deployments/dep_a1/ptu-shares", viewerKeyA.RawKey, map[string]any{
		"team_id":      "team_a2",
		"reserved_rpm": 10,
	})
	require.Equal(t, http.StatusForbidden, rec.Code)

	// 6. Attempt to delete team_a1 while PTU share exists -> 409 Conflict (team_has_active_ptu_shares)
	rec = doAdminJSONRequest(t, handler, http.MethodDelete, "/admin/v1/teams/team_a1", adminKeyA.RawKey, nil)
	require.Equal(t, http.StatusConflict, rec.Code)
	var errEnv domain.OpenAIErrorEnvelope
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &errEnv))
	require.NotNil(t, errEnv.Error)
	assert.Equal(t, "team_has_active_ptu_shares", errEnv.Error.Code)

	// 7. Delete the PTU share, then deleting team_a1 succeeds (200 OK)
	rec = doAdminJSONRequest(t, handler, http.MethodDelete, "/admin/v1/deployments/dep_a1/ptu-shares/team_a1", adminKeyA.RawKey, nil)
	require.Equal(t, http.StatusOK, rec.Code)

	rec = doAdminJSONRequest(t, handler, http.MethodDelete, "/admin/v1/teams/team_a1", adminKeyA.RawKey, nil)
	require.Equal(t, http.StatusOK, rec.Code)

	// 8. Priority classes admin API
	rec = doAdminJSONRequest(t, handler, http.MethodPost, "/admin/v1/priority-classes", adminKeyA.RawKey, map[string]any{
		"name":                "realtime",
		"weight":              4.0,
		"priority_rank":       0,
		"max_borrow_multiple": 2.5,
	})
	require.Equal(t, http.StatusOK, rec.Code)

	rec = doAdminJSONRequest(t, handler, http.MethodGet, "/admin/v1/priority-classes", adminKeyA.RawKey, nil)
	require.Equal(t, http.StatusOK, rec.Code)
	var pcResp struct {
		Data []domain.PriorityClass `json:"data"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &pcResp))
	require.Len(t, pcResp.Data, 1)
	assert.Equal(t, "realtime", pcResp.Data[0].Name)
	assert.Equal(t, 4.0, pcResp.Data[0].Weight)
}

func TestDataPlane_PTUShareEnforcement_EndToEnd(t *testing.T) {
	ctx := context.Background()
	var upstreamCalls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"id":"chatcmpl-ptu",
			"object":"chat.completion",
			"created":1700000000,
			"model":"gpt-4.1",
			"choices":[{"index":0,"message":{"role":"assistant","content":"ok"},"finish_reason":"stop"}],
			"usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}
		}`))
	}))
	defer upstream.Close()

	repo := storage.NewMemoryRepository()
	cfg := config.Default()
	cfg.Auth.MasterAdminKey = "admin_master_secret"
	cfg.Security.Network.OutboundSSRF.AllowPrivateNetworks = true
	cfg.Security.Network.OutboundSSRF.AllowInsecureHTTP = true

	gw, err := server.New(cfg, repo, nil, nil)
	require.NoError(t, err)
	handler := gw.Handler()

	org := &domain.Organization{ID: "org_e2e_ptu", Name: "E2E PTU", Slug: "e2e-ptu", IsActive: true}
	require.NoError(t, repo.CreateOrganization(ctx, org))
	require.NoError(t, repo.SetOrgProviderSubscription(ctx, &domain.OrgProviderSubscription{
		OrgID:     org.ID,
		Provider:  domain.ProviderOpenAI,
		IsEnabled: true,
	}))
	require.NoError(t, repo.SetOrgModelPolicy(ctx, &domain.OrgModelPolicy{
		OrgID:         org.ID,
		GlobalModelID: "openai/gpt-4.1",
		IsEnabled:     true,
		ApprovedBy:    "admin",
	}))
	team := &domain.Team{ID: "team_ptu_e2e", OrgID: org.ID, Name: "PTU Team", IsActive: true}
	require.NoError(t, repo.CreateTeam(ctx, team))

	credRec := doAdminJSONRequest(t, handler, http.MethodPost, "/admin/v1/credentials", cfg.Auth.MasterAdminKey, map[string]any{
		"org_id":   org.ID,
		"provider": "openai",
		"name":     "oai",
		"base_url": upstream.URL,
		"api_key":  "sk-upstream-test",
	})
	require.Equal(t, http.StatusCreated, credRec.Code, "cred body: %s", credRec.Body.String())
	var createdCred domain.ProviderCredential
	require.NoError(t, json.Unmarshal(credRec.Body.Bytes(), &createdCred))

	require.NoError(t, repo.CreateModelGroup(ctx, &domain.ModelGroup{
		ID:              "mg_ptu_e2e",
		OrgID:           org.ID,
		Alias:           "gpt-4.1",
		RoutingStrategy: domain.StrategyWeightedShuffle,
		IsActive:        true,
	}))
	require.NoError(t, repo.CreateDeployment(ctx, &domain.Deployment{
		ID:             "dep_ptu_e2e",
		ModelGroupID:   "mg_ptu_e2e",
		GlobalModelID:  "openai/gpt-4.1",
		CredentialID:   createdCred.ID,
		DeploymentName: "ptu-dep",
		RPMCapacity:    10,
		TPMCapacity:    10000,
		Status:         domain.DeploymentStatusActive,
	}))

	// Allocate PTU share: 1 RPM for team_ptu_e2e
	rec := doAdminJSONRequest(t, handler, http.MethodPost, "/admin/v1/deployments/dep_ptu_e2e/ptu-shares", cfg.Auth.MasterAdminKey, map[string]any{
		"team_id":      team.ID,
		"reserved_rpm": 1,
		"reserved_tpm": 5000,
	})
	require.Equal(t, http.StatusOK, rec.Code)

	vk, err := gw.AuthService().IssueVirtualKey(ctx, &domain.VirtualKey{
		OrgID:  org.ID,
		TeamID: team.ID,
		Name:   "ptu-caller",
		Role:   domain.RoleDeveloper,
	})
	require.NoError(t, err)

	// 1st call succeeds within PTU reserved_rpm=1
	req1 := doAdminJSONRequest(t, handler, http.MethodPost, "/v1/chat/completions", vk.RawKey, map[string]any{
		"model":    "gpt-4.1",
		"messages": []map[string]any{{"role": "user", "content": "hi"}},
	})
	require.Equal(t, http.StatusOK, req1.Code, "body: %s", req1.Body.String())
	assert.Equal(t, int32(1), upstreamCalls.Load())

	// 2nd call in the same window hits PTU share limit -> 429 ptu_share_exceeded
	req2 := doAdminJSONRequest(t, handler, http.MethodPost, "/v1/chat/completions", vk.RawKey, map[string]any{
		"model":    "gpt-4.1",
		"messages": []map[string]any{{"role": "user", "content": "hi again"}},
	})
	require.Equal(t, http.StatusTooManyRequests, req2.Code, "body: %s", req2.Body.String())
	assert.Contains(t, req2.Body.String(), "ptu_share_exceeded")
	assert.Equal(t, int32(1), upstreamCalls.Load())
}
