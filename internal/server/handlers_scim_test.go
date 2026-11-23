package server_test

import (
	"bytes"
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

func newSCIMTestServer(t *testing.T) (*server.GatewayServer, storage.Repository) {
	t.Helper()
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	require.NoError(t, repo.CreateOrganization(ctx, &domain.Organization{ID: "org_a", Name: "Org A", Slug: "org-a", IsActive: true}))
	require.NoError(t, repo.CreateOrganization(ctx, &domain.Organization{ID: "org_b", Name: "Org B", Slug: "org-b", IsActive: true}))

	cfg := config.Default()
	cfg.Auth.MasterAdminKey = "sk-gw-master-scim-test"
	cfg.Auth.DefaultOrgID = "org_a"

	srv, err := server.New(cfg, repo, nil, nil)
	require.NoError(t, err)
	return srv, repo
}

func doSCIMReq(t *testing.T, srv *server.GatewayServer, method, path, token string, body any) *httptest.ResponseRecorder {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		require.NoError(t, json.NewEncoder(&buf).Encode(body))
	}
	req := httptest.NewRequest(method, path, &buf)
	req.RemoteAddr = "127.0.0.1:4242"
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/scim+json")
	}
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	return rec
}

func TestSCIMAuthAndOrgIsolation(t *testing.T) {
	srv, repo := newSCIMTestServer(t)
	ctx := context.Background()

	require.NoError(t, repo.CreateUser(ctx, &domain.User{
		ID:       "usr_b_1",
		OrgID:    "org_b",
		Email:    "bob@orgb.example",
		Name:     "Bob",
		Role:     domain.RoleDeveloper,
		IsActive: true,
	}))
	require.NoError(t, repo.CreateTeam(ctx, &domain.Team{
		ID:       "team_b_1",
		OrgID:    "org_b",
		Name:     "OrgB Team",
		IsActive: true,
	}))

	scimKey, err := srv.AuthService().IssueVirtualKey(ctx, &domain.VirtualKey{
		OrgID:            "org_a",
		Name:             "scim-provisioner",
		Role:             domain.RoleServiceAccount,
		AllowedEndpoints: []string{"/scim/v2/*"},
	})
	require.NoError(t, err)

	usersOnlySCIMKey, err := srv.AuthService().IssueVirtualKey(ctx, &domain.VirtualKey{
		OrgID:            "org_a",
		Name:             "scim-users-only",
		Role:             domain.RoleServiceAccount,
		AllowedEndpoints: []string{"/scim/v2/Users", "/scim/v2/Users/*"},
	})
	require.NoError(t, err)

	llmKey, err := srv.AuthService().IssueVirtualKey(ctx, &domain.VirtualKey{
		OrgID:   "org_a",
		Name:    "llm-key",
		KeyType: domain.KeyTypeLLMAPI,
	})
	require.NoError(t, err)

	genericServiceKey, err := srv.AuthService().IssueVirtualKey(ctx, &domain.VirtualKey{
		OrgID: "org_a",
		Name:  "generic-service-key",
		Role:  domain.RoleServiceAccount,
	})
	require.NoError(t, err)

	viewerKey, err := srv.AuthService().IssueVirtualKey(ctx, &domain.VirtualKey{
		OrgID: "org_a",
		Name:  "org-viewer-key",
		Role:  domain.RoleOrgViewer,
	})
	require.NoError(t, err)

	orgAdminKey, err := srv.AuthService().IssueVirtualKey(ctx, &domain.VirtualKey{
		OrgID:   "org_a",
		Name:    "org-admin-mgmt-key",
		KeyType: domain.KeyTypeManagement,
		Role:    domain.RoleOrgAdmin,
	})
	require.NoError(t, err)

	// Unauthenticated -> 401
	rec := doSCIMReq(t, srv, http.MethodGet, "/scim/v2/Users", "", nil)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "application/scim+json")

	// LLM / generic service / org_viewer keys -> 403
	for _, tok := range []string{llmKey.RawKey, genericServiceKey.RawKey, viewerKey.RawKey} {
		rec = doSCIMReq(t, srv, http.MethodGet, "/scim/v2/Users", tok, nil)
		assert.Equal(t, http.StatusForbidden, rec.Code)
		assert.Contains(t, rec.Header().Get("Content-Type"), "application/scim+json")
	}

	// Users-only SCIM key allowed on /Users, denied on /Groups
	rec = doSCIMReq(t, srv, http.MethodGet, "/scim/v2/Users", usersOnlySCIMKey.RawKey, nil)
	assert.Equal(t, http.StatusOK, rec.Code)
	rec = doSCIMReq(t, srv, http.MethodGet, "/scim/v2/Groups", usersOnlySCIMKey.RawKey, nil)
	assert.Equal(t, http.StatusForbidden, rec.Code)

	// org_admin management key allowed
	rec = doSCIMReq(t, srv, http.MethodGet, "/scim/v2/Users", orgAdminKey.RawKey, nil)
	assert.Equal(t, http.StatusOK, rec.Code)

	// Cross-org access via query param or resource ID -> 403 / 404
	rec = doSCIMReq(t, srv, http.MethodGet, "/scim/v2/Users?org_id=org_b", scimKey.RawKey, nil)
	assert.Equal(t, http.StatusForbidden, rec.Code)

	rec = doSCIMReq(t, srv, http.MethodGet, "/scim/v2/Users/usr_b_1", scimKey.RawKey, nil)
	assert.Equal(t, http.StatusNotFound, rec.Code)

	rec = doSCIMReq(t, srv, http.MethodGet, "/scim/v2/Groups/team_b_1", scimKey.RawKey, nil)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestSCIMUserLifecycleAndImmediateKeyEviction(t *testing.T) {
	srv, repo := newSCIMTestServer(t)
	ctx := context.Background()

	scimKey, err := srv.AuthService().IssueVirtualKey(ctx, &domain.VirtualKey{
		OrgID:            "org_a",
		Name:             "scim-token",
		Role:             domain.RoleServiceAccount,
		AllowedEndpoints: []string{"/scim/v2/*"},
	})
	require.NoError(t, err)

	// 1. Create User via SCIM POST
	rec := doSCIMReq(t, srv, http.MethodPost, "/scim/v2/Users", scimKey.RawKey, map[string]any{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"externalId":  "okta-usr-001",
		"userName":    "alice@orga.example",
		"displayName": "Alice One",
		"emails": []map[string]any{
			{"value": "alice@orga.example", "primary": true, "type": "work"},
		},
		"active": true,
	})
	require.Equal(t, http.StatusCreated, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "application/scim+json")

	var createdUser map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &createdUser))
	userID := createdUser["id"].(string)
	require.NotEmpty(t, userID)
	assert.Equal(t, "okta-usr-001", createdUser["externalId"])
	assert.Equal(t, true, createdUser["active"])

	// Duplicate externalId -> 409 Conflict
	recDup := doSCIMReq(t, srv, http.MethodPost, "/scim/v2/Users", scimKey.RawKey, map[string]any{
		"externalId": "okta-usr-001",
		"userName":   "alice2@orga.example",
	})
	assert.Equal(t, http.StatusConflict, recDup.Code)

	// 2. List + Filter
	recList := doSCIMReq(t, srv, http.MethodGet, `/scim/v2/Users?filter=externalId+eq+%22okta-usr-001%22`, scimKey.RawKey, nil)
	require.Equal(t, http.StatusOK, recList.Code)
	var listResp map[string]any
	require.NoError(t, json.Unmarshal(recList.Body.Bytes(), &listResp))
	assert.Equal(t, float64(1), listResp["totalResults"])

	// 3. PUT replace
	recPut := doSCIMReq(t, srv, http.MethodPut, "/scim/v2/Users/"+userID, scimKey.RawKey, map[string]any{
		"externalId":  "okta-usr-001",
		"userName":    "alice@orga.example",
		"displayName": "Alice Replaced",
		"active":      true,
	})
	require.Equal(t, http.StatusOK, recPut.Code)
	var putResp map[string]any
	require.NoError(t, json.Unmarshal(recPut.Body.Bytes(), &putResp))
	assert.Equal(t, "Alice Replaced", putResp["displayName"])

	// 4. Issue a VirtualKey for this SCIM user and warm L1 cache via GET /v1/models
	userKey, err := srv.AuthService().IssueVirtualKey(ctx, &domain.VirtualKey{
		OrgID:  "org_a",
		UserID: userID,
		Name:   "alice-dataplane-key",
	})
	require.NoError(t, err)

	callModels := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
		req.RemoteAddr = "127.0.0.1:4242"
		req.Header.Set("Authorization", "Bearer "+userKey.RawKey)
		r := httptest.NewRecorder()
		srv.Handler().ServeHTTP(r, req)
		return r
	}
	assert.Equal(t, http.StatusOK, callModels().Code)

	// 5. Deprovision via PATCH active=false -> immediate L1/L2 eviction
	recPatch := doSCIMReq(t, srv, http.MethodPatch, "/scim/v2/Users/"+userID, scimKey.RawKey, map[string]any{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []map[string]any{
			{"op": "replace", "path": "active", "value": false},
		},
	})
	require.Equal(t, http.StatusOK, recPatch.Code)

	storedUser, err := repo.(storage.UserLookupRepository).GetUser(ctx, userID)
	require.NoError(t, err)
	assert.False(t, storedUser.SCIMActive)
	assert.False(t, storedUser.IsActive)

	// Immediately rejected despite L1 TTL not having expired
	recBlocked := callModels()
	assert.Equal(t, http.StatusForbidden, recBlocked.Code)

	// 6. Reactivate via pathless PATCH -> works again
	recReactivate := doSCIMReq(t, srv, http.MethodPatch, "/scim/v2/Users/"+userID, scimKey.RawKey, map[string]any{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []map[string]any{
			{"op": "replace", "value": map[string]any{"active": true, "displayName": "Alice Re-enabled"}},
		},
	})
	require.Equal(t, http.StatusOK, recReactivate.Code)
	assert.Equal(t, http.StatusOK, callModels().Code)

	// 7. Deprovision via DELETE -> 204 No Content and immediate key eviction
	recDel := doSCIMReq(t, srv, http.MethodDelete, "/scim/v2/Users/"+userID, scimKey.RawKey, nil)
	require.Equal(t, http.StatusNoContent, recDel.Code)

	storedAfterDel, err := repo.(storage.UserLookupRepository).GetUser(ctx, userID)
	require.NoError(t, err)
	assert.False(t, storedAfterDel.SCIMActive)
	assert.False(t, storedAfterDel.IsActive)
	assert.Equal(t, http.StatusForbidden, callModels().Code)
}

func TestSCIMGroupLifecycle(t *testing.T) {
	srv, repo := newSCIMTestServer(t)
	ctx := context.Background()

	require.NoError(t, repo.CreateUser(ctx, &domain.User{
		ID:       "usr_g_1",
		OrgID:    "org_a",
		Email:    "g1@orga.example",
		Name:     "Member One",
		Role:     domain.RoleDeveloper,
		IsActive: true,
	}))
	require.NoError(t, repo.CreateUser(ctx, &domain.User{
		ID:       "usr_g_2",
		OrgID:    "org_a",
		Email:    "g2@orga.example",
		Name:     "Member Two",
		Role:     domain.RoleDeveloper,
		IsActive: true,
	}))

	scimKey, err := srv.AuthService().IssueVirtualKey(ctx, &domain.VirtualKey{
		OrgID:            "org_a",
		Name:             "scim-group-token",
		Role:             domain.RoleServiceAccount,
		AllowedEndpoints: []string{"/scim/v2/*"},
	})
	require.NoError(t, err)

	// 1. Create Group with member usr_g_1
	rec := doSCIMReq(t, srv, http.MethodPost, "/scim/v2/Groups", scimKey.RawKey, map[string]any{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:Group"},
		"displayName": "ML Platform",
		"members": []map[string]any{
			{"value": "usr_g_1"},
		},
	})
	require.Equal(t, http.StatusCreated, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "application/scim+json")

	var grp map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &grp))
	groupID := grp["id"].(string)
	assert.Equal(t, "ML Platform", grp["displayName"])

	// Duplicate group displayName -> 409
	recDup := doSCIMReq(t, srv, http.MethodPost, "/scim/v2/Groups", scimKey.RawKey, map[string]any{
		"displayName": "ML Platform",
	})
	assert.Equal(t, http.StatusConflict, recDup.Code)

	// 2. Filter by displayName
	recList := doSCIMReq(t, srv, http.MethodGet, `/scim/v2/Groups?filter=displayName+eq+%22ML+Platform%22`, scimKey.RawKey, nil)
	require.Equal(t, http.StatusOK, recList.Code)
	var listResp map[string]any
	require.NoError(t, json.Unmarshal(recList.Body.Bytes(), &listResp))
	assert.Equal(t, float64(1), listResp["totalResults"])

	// Issue key for usr_g_1 and warm cache before SCIM patch
	memberKey, err := srv.AuthService().IssueVirtualKey(ctx, &domain.VirtualKey{
		OrgID:  "org_a",
		TeamID: groupID,
		UserID: "usr_g_1",
		Name:   "usr-g-1-key",
		Role:   domain.RoleDeveloper,
	})
	require.NoError(t, err)
	idBefore, err := srv.AuthService().AuthenticateVirtualKey(ctx, memberKey.RawKey)
	require.NoError(t, err)
	assert.Equal(t, groupID, idBefore.TeamID)

	// Failed atomic PATCH rolls back displayName + memberships and leaves auth cache intact
	invalidPatch := doSCIMReq(t, srv, http.MethodPatch, "/scim/v2/Groups/"+groupID, scimKey.RawKey, map[string]any{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []map[string]any{
			{"op": "replace", "path": "displayName", "value": "Invalid Partial Name"},
			{"op": "add", "path": "members", "value": []map[string]string{{"value": "missing-user"}}},
		},
	})
	require.Equal(t, http.StatusBadRequest, invalidPatch.Code)
	unchanged := doSCIMReq(t, srv, http.MethodGet, "/scim/v2/Groups/"+groupID, scimKey.RawKey, nil)
	require.Equal(t, http.StatusOK, unchanged.Code)
	assert.True(t, strings.Contains(unchanged.Body.String(), "ML Platform"))
	assert.False(t, strings.Contains(unchanged.Body.String(), "Invalid Partial Name"))

	// Stale UpdatedAt returns ErrConflict from UpdateSCIMGroup
	staleTeam, err := repo.GetTeam(ctx, groupID)
	require.NoError(t, err)
	staleSnapshot := *staleTeam
	staleSnapshot.UpdatedAt = staleSnapshot.UpdatedAt.Add(-time.Minute)
	staleSnapshot.Name = "Stale Rename"
	err = repo.(storage.SCIMRepository).UpdateSCIMGroup(ctx, &staleSnapshot, []string{"usr_g_1"}, true)
	assert.ErrorIs(t, err, storage.ErrConflict)

	// 3. PATCH add usr_g_2 and remove usr_g_1
	recPatch := doSCIMReq(t, srv, http.MethodPatch, "/scim/v2/Groups/"+groupID, scimKey.RawKey, map[string]any{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []map[string]any{
			{"op": "add", "path": "members", "value": []map[string]any{{"value": "usr_g_2"}}},
			{"op": "remove", "path": `members[value eq "usr_g_1"]`},
			{"op": "replace", "path": "displayName", "value": "ML Core"},
		},
	})
	require.Equal(t, http.StatusOK, recPatch.Code)

	recGet := doSCIMReq(t, srv, http.MethodGet, "/scim/v2/Groups/"+groupID, scimKey.RawKey, nil)
	require.Equal(t, http.StatusOK, recGet.Code)
	var gotGrp struct {
		DisplayName string `json:"displayName"`
		Members     []struct {
			Value string `json:"value"`
		} `json:"members"`
	}
	require.NoError(t, json.Unmarshal(recGet.Body.Bytes(), &gotGrp))
	assert.Equal(t, "ML Core", gotGrp.DisplayName)
	require.Len(t, gotGrp.Members, 1)
	assert.Equal(t, "usr_g_2", gotGrp.Members[0].Value)

	// Post-commit cache invalidation reflects usr_g_1 removal and evicts cached keys
	recUserAfter := doSCIMReq(t, srv, http.MethodGet, "/scim/v2/Users/usr_g_1", scimKey.RawKey, nil)
	require.Equal(t, http.StatusOK, recUserAfter.Code)
	assert.False(t, strings.Contains(recUserAfter.Body.String(), `"value":"`+groupID+`"`))
	// Warm key cache before direct repo mutation so SCIM PATCH must invalidate it
	_, err = srv.AuthService().AuthenticateVirtualKey(ctx, memberKey.RawKey)
	require.NoError(t, err)
	storedK, err := repo.GetVirtualKeyByHash(ctx, memberKey.KeyHash)
	require.NoError(t, err)
	storedK.AllowedModels = []string{"evicted-refresh-model"}
	require.NoError(t, repo.UpdateVirtualKey(ctx, storedK))
	recPatch2 := doSCIMReq(t, srv, http.MethodPatch, "/scim/v2/Groups/"+groupID, scimKey.RawKey, map[string]any{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []map[string]any{
			{"op": "add", "path": "members", "value": []map[string]any{{"value": "usr_g_1"}}},
		},
	})
	require.Equal(t, http.StatusOK, recPatch2.Code)
	idEvicted, err := srv.AuthService().AuthenticateVirtualKey(ctx, memberKey.RawKey)
	require.NoError(t, err)
	assert.Equal(t, []string{"evicted-refresh-model"}, idEvicted.KeyAllowedModels)

	// Restore previous single-member state before PUT step
	recPatchRestore := doSCIMReq(t, srv, http.MethodPatch, "/scim/v2/Groups/"+groupID, scimKey.RawKey, map[string]any{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []map[string]any{
			{"op": "remove", "path": `members[value eq "usr_g_1"]`},
		},
	})
	require.Equal(t, http.StatusOK, recPatchRestore.Code)
	require.NoError(t, srv.AuthService().RevokeKey(ctx, memberKey.ID))

	// 4. PUT replace group
	recPut := doSCIMReq(t, srv, http.MethodPut, "/scim/v2/Groups/"+groupID, scimKey.RawKey, map[string]any{
		"displayName": "ML Core V2",
		"members":     []map[string]any{{"value": "usr_g_1"}},
	})
	require.Equal(t, http.StatusOK, recPut.Code)

	// 5. DELETE group with active virtual key -> 409 Conflict and preserves memberships
	activeTeamKey, err := srv.AuthService().IssueVirtualKey(ctx, &domain.VirtualKey{
		OrgID:  "org_a",
		TeamID: groupID,
		Name:   "active-team-key",
	})
	require.NoError(t, err)
	recConflict := doSCIMReq(t, srv, http.MethodDelete, "/scim/v2/Groups/"+groupID, scimKey.RawKey, nil)
	assert.Equal(t, http.StatusConflict, recConflict.Code)

	recGetAfterConflict := doSCIMReq(t, srv, http.MethodGet, "/scim/v2/Groups/"+groupID, scimKey.RawKey, nil)
	require.Equal(t, http.StatusOK, recGetAfterConflict.Code)
	var afterConflict struct {
		Members []struct {
			Value string `json:"value"`
		} `json:"members"`
	}
	require.NoError(t, json.Unmarshal(recGetAfterConflict.Body.Bytes(), &afterConflict))
	require.Len(t, afterConflict.Members, 1)
	assert.Equal(t, "usr_g_1", afterConflict.Members[0].Value)

	require.NoError(t, srv.AuthService().RevokeKey(ctx, activeTeamKey.ID))

	// 6. DELETE group -> 204
	recDel := doSCIMReq(t, srv, http.MethodDelete, "/scim/v2/Groups/"+groupID, scimKey.RawKey, nil)
	require.Equal(t, http.StatusNoContent, recDel.Code)

	_, err = repo.GetTeam(ctx, groupID)
	assert.Error(t, err)
}

func TestSCIMTeamAdminEscalationGuards(t *testing.T) {
	srv, repo := newSCIMTestServer(t)
	ctx := context.Background()

	require.NoError(t, repo.CreateTeam(ctx, &domain.Team{ID: "team_a1", OrgID: "org_a", Name: "Team A1", IsActive: true}))
	teamAdminKey, err := srv.AuthService().IssueVirtualKey(ctx, &domain.VirtualKey{
		OrgID:  "org_a",
		TeamID: "team_a1",
		Name:   "ta-key",
		Role:   domain.RoleTeamAdmin,
	})
	require.NoError(t, err)

	// team_admin cannot issue a key with /scim or * allowed_endpoints
	for _, ep := range [][]string{{"/scim/v2/*"}, {"*"}} {
		body, _ := json.Marshal(map[string]any{
			"org_id":            "org_a",
			"team_id":           "team_a1",
			"name":              "esc-ep-key",
			"role":              "developer",
			"allowed_endpoints": ep,
		})
		req := httptest.NewRequest(http.MethodPost, "/admin/v1/keys", bytes.NewReader(body))
		req.RemoteAddr = "127.0.0.1:4242"
		req.Header.Set("Authorization", "Bearer "+teamAdminKey.RawKey)
		req.Header.Set("Content-Type", "application/json")
		rec := httptest.NewRecorder()
		srv.Handler().ServeHTTP(rec, req)
		assert.Equal(t, http.StatusForbidden, rec.Code)
	}

	// team_admin cannot update an existing key to add /scim or * allowed_endpoints
	normalKey, err := srv.AuthService().IssueVirtualKey(ctx, &domain.VirtualKey{
		OrgID:            "org_a",
		TeamID:           "team_a1",
		Name:             "normal-team-key",
		Role:             domain.RoleDeveloper,
		AllowedEndpoints: []string{"/v1/*"},
	})
	require.NoError(t, err)
	updBody, _ := json.Marshal(map[string]any{
		"allowed_endpoints": []string{"/scim/v2/*"},
	})
	reqUpd := httptest.NewRequest(http.MethodPut, "/admin/v1/keys/"+normalKey.ID, bytes.NewReader(updBody))
	reqUpd.RemoteAddr = "127.0.0.1:4242"
	reqUpd.Header.Set("Authorization", "Bearer "+teamAdminKey.RawKey)
	reqUpd.Header.Set("Content-Type", "application/json")
	recUpd := httptest.NewRecorder()
	srv.Handler().ServeHTTP(recUpd, reqUpd)
	assert.Equal(t, http.StatusForbidden, recUpd.Code)

	// Even if a team-scoped non-admin key exists with /scim/v2/* in storage, scimAuthMiddleware rejects it
	teamScopedSCIMKey, err := srv.AuthService().IssueVirtualKey(ctx, &domain.VirtualKey{
		OrgID:            "org_a",
		TeamID:           "team_a1",
		Name:             "team-scoped-scim",
		Role:             domain.RoleServiceAccount,
		AllowedEndpoints: []string{"/scim/v2/*"},
	})
	require.NoError(t, err)
	recSCIM := doSCIMReq(t, srv, http.MethodGet, "/scim/v2/Users", teamScopedSCIMKey.RawKey, nil)
	assert.Equal(t, http.StatusForbidden, recSCIM.Code)
}

func TestControlPlaneImpersonationAuditAndTeamAdminGuard(t *testing.T) {
	srv, repo := newSCIMTestServer(t)
	ctx := context.Background()

	require.NoError(t, repo.CreateTeam(ctx, &domain.Team{ID: "team_a1", OrgID: "org_a", Name: "Team A1", IsActive: true}))
	require.NoError(t, repo.CreateUser(ctx, &domain.User{
		ID:         "usr_org_admin_target",
		OrgID:      "org_a",
		Email:      "target@orga.example",
		Name:       "Target Admin",
		Role:       domain.RoleOrgAdmin,
		IsActive:   true,
		SCIMActive: true,
	}))

	// Issue a virtual key with can_impersonate=true via /admin/v1/keys
	issueBody, _ := json.Marshal(map[string]any{
		"org_id":          "org_a",
		"name":            "imp-key",
		"role":            "org_admin",
		"can_impersonate": true,
	})
	req := httptest.NewRequest(http.MethodPost, "/admin/v1/keys", bytes.NewReader(issueBody))
	req.RemoteAddr = "127.0.0.1:4242"
	req.Header.Set("Authorization", "Bearer sk-gw-master-scim-test")
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	require.Equal(t, http.StatusCreated, rec.Code)

	var issued domain.VirtualKey
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &issued))
	assert.True(t, issued.CanImpersonate)
	require.NotEmpty(t, issued.RawKey)

	// Use that key to impersonate usr_org_admin_target and create a team
	teamBody, _ := json.Marshal(map[string]any{
		"org_id": "org_a",
		"name":   "Impersonated Team",
	})
	reqTeam := httptest.NewRequest(http.MethodPost, "/admin/v1/teams", bytes.NewReader(teamBody))
	reqTeam.RemoteAddr = "127.0.0.1:4242"
	reqTeam.Header.Set("Authorization", "Bearer "+issued.RawKey)
	reqTeam.Header.Set(auth.HeaderImpersonateUser, "usr_org_admin_target")
	reqTeam.Header.Set("Content-Type", "application/json")
	recTeam := httptest.NewRecorder()
	srv.Handler().ServeHTTP(recTeam, reqTeam)
	require.Equal(t, http.StatusCreated, recTeam.Code)

	// Verify audit logs contain both actor_id and impersonated_by
	logs, err := repo.ListAuditLogs(ctx, "org_a", 20)
	require.NoError(t, err)
	foundTeamCreated := false
	for _, l := range logs {
		if l.Action == "team.created" {
			foundTeamCreated = true
			assert.Equal(t, "usr_org_admin_target", l.ActorID)
			assert.Equal(t, "usr_org_admin_target", l.Details["actor_id"])
			assert.Equal(t, issued.ID, l.Details["impersonated_by"])
		}
	}
	assert.True(t, foundTeamCreated, "expected team.created audit log with actor_id and impersonated_by")

	// team_admin cannot issue a key with can_impersonate=true
	teamAdminKey, err := srv.AuthService().IssueVirtualKey(ctx, &domain.VirtualKey{
		OrgID:  "org_a",
		TeamID: "team_a1",
		Name:   "ta-key",
		Role:   domain.RoleTeamAdmin,
	})
	require.NoError(t, err)
	escBody, _ := json.Marshal(map[string]any{
		"org_id":          "org_a",
		"team_id":         "team_a1",
		"name":            "esc-key",
		"role":            "developer",
		"can_impersonate": true,
	})
	reqEsc := httptest.NewRequest(http.MethodPost, "/admin/v1/keys", bytes.NewReader(escBody))
	reqEsc.RemoteAddr = "127.0.0.1:4242"
	reqEsc.Header.Set("Authorization", "Bearer "+teamAdminKey.RawKey)
	reqEsc.Header.Set("Content-Type", "application/json")
	recEsc := httptest.NewRecorder()
	srv.Handler().ServeHTTP(recEsc, reqEsc)
	assert.Equal(t, http.StatusForbidden, recEsc.Code)
}
