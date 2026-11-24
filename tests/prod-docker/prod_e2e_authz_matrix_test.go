//go:build proddocker

package proddocker_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestProdDocker_Suite5b_FullRBACMatrix_TeamAdmin_CSRF_OrgCutoff_AndOwnership verifies
// Capabilities 7, 8, 10, 17, and 18 across both production replicas.
func TestProdDocker_Suite5b_FullRBACMatrix_TeamAdmin_CSRF_OrgCutoff_AndOwnership(t *testing.T) {
	client := newProdTLSClient(t, false)
	resetFixtureAuthzPolicy(t, client)

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	globalID := seedCustomGlobalModel(t, "openai/prod-fixture-mini", "openai", "gpt-4o-mini", 100000, 200000)

	var org struct {
		ID string `json:"id"`
	}
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/organizations", map[string]any{
		"name": "RBAC Matrix Org " + suffix, "slug": "rbac-matrix-" + suffix,
	}, &org, http.StatusCreated)
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/organizations/"+org.ID+"/subscriptions", map[string]any{
		"provider": "openai", "is_enabled": true,
	}, nil, http.StatusOK)

	var cred, mgA, mgB struct {
		ID string `json:"id"`
	}
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/credentials", map[string]any{
		"org_id": org.ID, "provider": "openai", "name": "rbac-cred-" + suffix,
		"api_key": "sk-mock-rbac", "base_url": prodFixturesBase + "/llm/eu/v1",
	}, &cred, http.StatusCreated)
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/model-groups", map[string]any{
		"org_id": org.ID, "alias": "member-allowed-model", "routing_strategy": "round_robin",
	}, &mgA, http.StatusCreated)
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/model-groups", map[string]any{
		"org_id": org.ID, "alias": "member-blocked-model", "routing_strategy": "round_robin",
	}, &mgB, http.StatusCreated)
	for _, mgID := range []string{mgA.ID, mgB.ID} {
		mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/deployments", map[string]any{
			"model_group_id": mgID, "global_model_id": globalID, "credential_id": cred.ID,
			"deployment_name": "dep-" + mgID, "weight": 100, "priority": 1,
		}, nil, http.StatusCreated)
	}

	var teamA, teamB struct {
		ID string `json:"id"`
	}
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/teams", map[string]any{
		"org_id": org.ID, "name": "Team A " + suffix,
		"allowed_models": []string{"member-allowed-model", "member-blocked-model"},
	}, &teamA, http.StatusCreated)
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/teams", map[string]any{
		"org_id": org.ID, "name": "Team B " + suffix,
		"allowed_models": []string{"member-allowed-model"},
	}, &teamB, http.StatusCreated)

	// 1. Provision all 7 roles + management keys to test the complete RBAC matrix
	type roleEntry struct {
		role       string
		teamID     string
		canReadOrg bool
		canWrite   bool
	}
	roles := []roleEntry{
		{"platform_admin", "", true, true},
		{"org_admin", "", true, true},
		{"org_viewer", "", true, false},
		{"team_admin", teamA.ID, false, false},
		{"developer", teamA.ID, false, false},
		{"service_account", teamA.ID, false, false},
		{"viewer", teamA.ID, false, false},
	}
	roleKeys := map[string]string{}
	roleUsers := map[string]string{}
	for _, r := range roles {
		var u struct {
			ID string `json:"id"`
		}
		mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/users", map[string]any{
			"org_id": org.ID, "team_id": r.teamID,
			"email": r.role + "-" + suffix + "@goroute.local", "name": r.role, "role": r.role,
		}, &u, http.StatusCreated)
		roleUsers[r.role] = u.ID

		keyType := "management"
		if r.role == "developer" || r.role == "service_account" || r.role == "viewer" {
			keyType = "default"
		}
		var vk struct {
			RawKey string `json:"raw_key"`
		}
		mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/keys", map[string]any{
			"org_id": org.ID, "team_id": r.teamID, "user_id": u.ID,
			"name": "vk-" + r.role, "role": r.role, "key_type": keyType, "allowed_endpoints": []string{"*"},
		}, &vk, http.StatusCreated)
		roleKeys[r.role] = vk.RawKey

		// Org-wide admin read check (/admin/v1/audit/logs?org_id=...)
		readResp, _ := doReq(t, client, http.MethodGet, prodPod2Base+"/admin/v1/audit/logs?org_id="+org.ID+"&limit=1", nil, map[string]string{
			"Authorization": "Bearer " + vk.RawKey,
		})
		if r.canReadOrg && readResp.StatusCode != http.StatusOK {
			t.Fatalf("role %s expected 200 on GET /admin/v1/audit/logs, got %d", r.role, readResp.StatusCode)
		}
		if !r.canReadOrg && readResp.StatusCode != http.StatusForbidden {
			t.Fatalf("role %s expected 403 on GET /admin/v1/audit/logs, got %d", r.role, readResp.StatusCode)
		}

		// Org-wide admin write check (POST /admin/v1/teams)
		writeResp, _ := doReq(t, client, http.MethodPost, prodPod2Base+"/admin/v1/teams", map[string]any{
			"org_id": org.ID, "name": "Probe Team " + r.role + " " + suffix,
		}, map[string]string{"Authorization": "Bearer " + vk.RawKey})
		if r.canWrite && writeResp.StatusCode != http.StatusCreated {
			t.Fatalf("role %s expected 201 on POST /admin/v1/teams, got %d", r.role, writeResp.StatusCode)
		}
		if !r.canWrite && writeResp.StatusCode != http.StatusForbidden {
			t.Fatalf("role %s expected 403 on POST /admin/v1/teams, got %d", r.role, writeResp.StatusCode)
		}

		// Platform-admin-only gate (/admin/v1/config)
		cfgResp, _ := doReq(t, client, http.MethodGet, prodPod2Base+"/admin/v1/config", nil, map[string]string{
			"Authorization": "Bearer " + vk.RawKey,
		})
		if r.role == "platform_admin" && cfgResp.StatusCode != http.StatusOK {
			t.Fatalf("platform_admin expected 200 on GET /admin/v1/config, got %d", cfgResp.StatusCode)
		}
		if r.role != "platform_admin" && cfgResp.StatusCode != http.StatusForbidden {
			t.Fatalf("non-platform role %s expected 403 on GET /admin/v1/config, got %d", r.role, cfgResp.StatusCode)
		}
	}

	// Verify Data-Plane viewer retains full /v1/models access despite having zero Control Plane read privileges
	viewerDPResp, _ := doReq(t, client, http.MethodGet, prodPod2Base+"/v1/models", nil, map[string]string{
		"Authorization": "Bearer " + roleKeys["viewer"],
	})
	if viewerDPResp.StatusCode != http.StatusOK {
		t.Fatalf("role=viewer expected 200 on Data Plane GET /v1/models, got %d", viewerDPResp.StatusCode)
	}

	// 2. Anti-escalation: org_admin CANNOT issue a platform_admin key or create a platform_admin user
	escUserResp, _ := doReq(t, client, http.MethodPost, prodPod1Base+"/admin/v1/users", map[string]any{
		"org_id": org.ID, "email": "esc-" + suffix + "@goroute.local", "name": "Esc", "role": "platform_admin",
	}, map[string]string{"Authorization": "Bearer " + roleKeys["org_admin"]})
	if escUserResp.StatusCode != http.StatusForbidden {
		t.Fatalf("org_admin unexpectedly allowed to create platform_admin user: %d", escUserResp.StatusCode)
	}
	escKeyResp, _ := doReq(t, client, http.MethodPost, prodPod1Base+"/admin/v1/keys", map[string]any{
		"org_id": org.ID, "name": "esc-plat-key", "role": "platform_admin",
	}, map[string]string{"Authorization": "Bearer " + roleKeys["org_admin"]})
	if escKeyResp.StatusCode != http.StatusForbidden {
		t.Fatalf("org_admin unexpectedly allowed to issue platform_admin key: %d", escKeyResp.StatusCode)
	}

	// 3. Positive & Negative team_admin lifecycle (Team A allowed, Team B denied, escalation denied)
	taHdrs := map[string]string{"Authorization": "Bearer " + roleKeys["team_admin"]}
	// team_admin GET /admin/v1/users is automatically scoped to Team A (never leaks org_admin), and explicit team_id=teamB returns 403
	taListResp, taListBody := doReq(t, client, http.MethodGet, prodPod2Base+"/admin/v1/users?org_id="+org.ID, nil, taHdrs)
	if taListResp.StatusCode != http.StatusOK || strings.Contains(string(taListBody), "org_admin-"+suffix) {
		t.Fatalf("team_admin GET /admin/v1/users expected 200 scoped to teamA only, got %d: %s", taListResp.StatusCode, string(taListBody))
	}
	taCrossListResp, _ := doReq(t, client, http.MethodGet, prodPod2Base+"/admin/v1/users?org_id="+org.ID+"&team_id="+teamB.ID, nil, taHdrs)
	if taCrossListResp.StatusCode != http.StatusForbidden {
		t.Fatalf("team_admin GET /admin/v1/users?team_id=teamB expected 403 cross_team_access_denied, got %d", taCrossListResp.StatusCode)
	}
	ownKeyResp, ownKeyBody := doReq(t, client, http.MethodPost, prodPod1Base+"/admin/v1/keys", map[string]any{
		"org_id": org.ID, "team_id": teamA.ID, "name": "ta-own-team-key",
		"allowed_endpoints": []string{"/v1/*"}, "allowed_models": []string{"member-allowed-model"},
	}, taHdrs)
	if ownKeyResp.StatusCode != http.StatusCreated {
		t.Fatalf("team_admin failed to issue key in own teamA: %d %s", ownKeyResp.StatusCode, string(ownKeyBody))
	}
	var taKey struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(ownKeyBody, &taKey)

	// team_admin CAN rotate & revoke own team's key
	rotResp, rotBody := doReq(t, client, http.MethodPost, prodPod2Base+"/admin/v1/keys/"+taKey.ID+"/rotate", map[string]any{"grace_period_seconds": 30}, taHdrs)
	if rotResp.StatusCode != http.StatusOK {
		t.Fatalf("team_admin failed to rotate own team key: %d %s", rotResp.StatusCode, string(rotBody))
	}
	revResp, _ := doReq(t, client, http.MethodDelete, prodPod2Base+"/admin/v1/keys/"+taKey.ID, nil, taHdrs)
	if revResp.StatusCode != http.StatusOK {
		t.Fatalf("team_admin failed to revoke own team key: %d", revResp.StatusCode)
	}

	// team_admin DENIED on Team B key issuance, wildcard endpoints, can_impersonate, and org_admin role
	for _, neg := range []struct {
		name    string
		payload map[string]any
	}{
		{"cross_team", map[string]any{"org_id": org.ID, "team_id": teamB.ID, "name": "ta-b", "allowed_endpoints": []string{"/v1/*"}}},
		{"wildcard_endpoint", map[string]any{"org_id": org.ID, "team_id": teamA.ID, "name": "ta-wc", "allowed_endpoints": []string{"*"}}},
		{"can_impersonate", map[string]any{"org_id": org.ID, "team_id": teamA.ID, "name": "ta-imp", "allowed_endpoints": []string{"/v1/*"}, "can_impersonate": true}},
		{"org_admin_role", map[string]any{"org_id": org.ID, "team_id": teamA.ID, "name": "ta-oa", "allowed_endpoints": []string{"/v1/*"}, "role": "org_admin"}},
	} {
		r, b := doReq(t, client, http.MethodPost, prodPod1Base+"/admin/v1/keys", neg.payload, taHdrs)
		if r.StatusCode != http.StatusForbidden {
			t.Fatalf("team_admin negative case %q expected 403, got %d: %s", neg.name, r.StatusCode, string(b))
		}
	}

	// 4. team_member_permissions: restrict developer inside teamA to member-allowed-model only (using normalized "member" alias -> "developer")
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/teams/"+teamA.ID+"/members", map[string]any{
		"user_id": roleUsers["developer"], "role": "member",
		"allowed_models": []string{"member-allowed-model"},
	}, nil, http.StatusOK, http.StatusCreated)
	var memKey struct {
		RawKey string `json:"raw_key"`
	}
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/keys", map[string]any{
		"org_id": org.ID, "team_id": teamA.ID, "user_id": roleUsers["developer"], "name": "dev-member-scoped",
	}, &memKey, http.StatusCreated)

	okMem, okMemBody := doReq(t, client, http.MethodPost, prodPod2Base+"/v1/chat/completions", map[string]any{
		"model": "member-allowed-model", "messages": []map[string]any{{"role": "user", "content": "hi"}},
	}, map[string]string{"Authorization": "Bearer " + memKey.RawKey})
	if okMem.StatusCode != http.StatusOK {
		t.Fatalf("team member allowed model expected 200, got %d: %s", okMem.StatusCode, string(okMemBody))
	}
	denyMem, denyMemBody := doReq(t, client, http.MethodPost, prodPod2Base+"/v1/chat/completions", map[string]any{
		"model": "member-blocked-model", "messages": []map[string]any{{"role": "user", "content": "hi"}},
	}, map[string]string{"Authorization": "Bearer " + memKey.RawKey})
	if denyMem.StatusCode != http.StatusForbidden || !strings.Contains(string(denyMemBody), "team_member_model_restricted") {
		t.Fatalf("team member blocked model expected 403 team_member_model_restricted, got %d: %s", denyMem.StatusCode, string(denyMemBody))
	}

	// 5. key_type matrix (llm_api vs read_only) & Break-glass master key data-plane denial
	var roKey, llmKey struct {
		RawKey string `json:"raw_key"`
	}
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/keys", map[string]any{
		"org_id": org.ID, "name": "ro-key", "key_type": "read_only",
	}, &roKey, http.StatusCreated)
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/keys", map[string]any{
		"org_id": org.ID, "name": "llm-only-key", "key_type": "llm_api",
	}, &llmKey, http.StatusCreated)

	roGet, _ := doReq(t, client, http.MethodGet, prodPod2Base+"/v1/models", nil, map[string]string{"Authorization": "Bearer " + roKey.RawKey})
	if roGet.StatusCode != http.StatusOK {
		t.Fatalf("read_only key GET /v1/models expected 200, got %d", roGet.StatusCode)
	}
	roPost, roPostBody := doReq(t, client, http.MethodPost, prodPod2Base+"/v1/chat/completions", map[string]any{
		"model": "member-allowed-model", "messages": []map[string]any{{"role": "user", "content": "hi"}},
	}, map[string]string{"Authorization": "Bearer " + roKey.RawKey})
	if roPost.StatusCode != http.StatusForbidden || (!strings.Contains(string(roPostBody), "read_only_key") && !strings.Contains(string(roPostBody), "endpoint_not_allowed")) {
		t.Fatalf("read_only key POST /v1/chat/completions expected 403 (read_only_key or endpoint_not_allowed), got %d: %s", roPost.StatusCode, string(roPostBody))
	}
	llmAdmin, _ := doReq(t, client, http.MethodGet, prodPod2Base+"/admin/v1/keys?org_id="+org.ID, nil, map[string]string{"Authorization": "Bearer " + llmKey.RawKey})
	if llmAdmin.StatusCode != http.StatusForbidden && llmAdmin.StatusCode != http.StatusUnauthorized {
		t.Fatalf("llm_api key expected 401/403 on /admin/v1/keys, got %d", llmAdmin.StatusCode)
	}
	bgData, _ := doReq(t, client, http.MethodPost, prodPod1Base+"/v1/chat/completions", map[string]any{
		"model": "member-allowed-model", "messages": []map[string]any{{"role": "user", "content": "hi"}},
	}, map[string]string{"Authorization": "Bearer " + prodMasterKey})
	if bgData.StatusCode != http.StatusUnauthorized {
		t.Fatalf("master admin key expected 401 on data plane when allow_master_key_data_plane=false, got %d", bgData.StatusCode)
	}

	// 6. Cookie-session CSRF enforcement + Self-service /v1/self/keys ownership isolation
	adminJar, adminLogin := performKeycloakSSOLogin(t, "admin@goroute.local", "ProdAdmin!2026")
	adminCSRF, _ := adminLogin["csrf_token"].(string)
	noCSRFResp, _ := doReq(t, adminJar, http.MethodPost, prodPod2Base+"/admin/v1/keys", map[string]any{
		"org_id": "org_default", "name": "csrf-should-fail",
	}, nil)
	if noCSRFResp.StatusCode != http.StatusForbidden {
		t.Fatalf("cookie mutation without X-CSRF-Token expected 403, got %d", noCSRFResp.StatusCode)
	}
	withCSRFResp, _ := doReq(t, adminJar, http.MethodPost, prodPod2Base+"/admin/v1/keys", map[string]any{
		"org_id": "org_default", "name": "csrf-ok-" + suffix,
	}, map[string]string{"X-CSRF-Token": adminCSRF})
	if withCSRFResp.StatusCode != http.StatusCreated {
		t.Fatalf("cookie mutation with valid X-CSRF-Token expected 201, got %d", withCSRFResp.StatusCode)
	}

	// Self-service /v1/self/keys: fail-closed (403 self_service_disabled) until org enables developer_self_serve_keys=true
	selfDisabledResp, selfDisabledBody := doReq(t, adminJar, http.MethodPost, prodPod1Base+"/v1/self/keys", map[string]any{
		"name": "self-disabled-" + suffix,
	}, map[string]string{"X-CSRF-Token": adminCSRF})
	if selfDisabledResp.StatusCode != http.StatusForbidden || !strings.Contains(string(selfDisabledBody), "self_service_disabled") {
		t.Fatalf("POST /v1/self/keys before opt-in expected 403 self_service_disabled, got %d: %s", selfDisabledResp.StatusCode, string(selfDisabledBody))
	}
	mustAdminJSON(t, client, http.MethodPut, prodPod1Base+"/admin/v1/organizations/org_default", map[string]any{
		"developer_self_serve_keys": true,
	}, nil, http.StatusOK)
	defer func() {
		doReq(t, client, http.MethodPut, prodPod1Base+"/admin/v1/organizations/org_default", map[string]any{
			"developer_self_serve_keys": false,
		}, map[string]string{"Authorization": "Bearer " + prodMasterKey})
	}()
	time.Sleep(150 * time.Millisecond)

	// Self-service /v1/self/keys requires active team membership for the user
	adminUserObj, _ := adminLogin["user"].(map[string]any)
	adminUserID, _ := adminUserObj["id"].(string)
	var selfTeam struct {
		ID string `json:"id"`
	}
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/teams", map[string]any{
		"org_id": "org_default", "name": "Self Serve Team " + suffix,
	}, &selfTeam, http.StatusCreated)
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/teams/"+selfTeam.ID+"/members", map[string]any{
		"user_id": adminUserID, "role": "developer",
	}, nil, http.StatusOK, http.StatusCreated)

	// Once enabled: admin creates own key in selfTeam, orgadmin cannot revoke admin's key, admin deletes own key
	selfCreateResp, selfCreateBody := doReq(t, adminJar, http.MethodPost, prodPod1Base+"/v1/self/keys", map[string]any{
		"name": "self-owned-key-" + suffix, "team_id": selfTeam.ID,
	}, map[string]string{"X-CSRF-Token": adminCSRF})
	if selfCreateResp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /v1/self/keys failed: %d %s", selfCreateResp.StatusCode, string(selfCreateBody))
	}
	var selfKey struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(selfCreateBody, &selfKey)
	orgAdminJar, orgAdminLogin := performKeycloakSSOLogin(t, "orgadmin@goroute.local", "ProdOrgAdmin!2026")
	orgAdminCSRF, _ := orgAdminLogin["csrf_token"].(string)
	crossUserDel, _ := doReq(t, orgAdminJar, http.MethodDelete, prodPod2Base+"/v1/self/keys/"+selfKey.ID, nil, map[string]string{"X-CSRF-Token": orgAdminCSRF})
	if crossUserDel.StatusCode != http.StatusForbidden && crossUserDel.StatusCode != http.StatusNotFound {
		t.Fatalf("self-service cross-user key delete expected 403/404, got %d", crossUserDel.StatusCode)
	}
	ownDel, _ := doReq(t, adminJar, http.MethodDelete, prodPod2Base+"/v1/self/keys/"+selfKey.ID, nil, map[string]string{"X-CSRF-Token": adminCSRF})
	if ownDel.StatusCode != http.StatusOK {
		t.Fatalf("self-service own key delete expected 200, got %d", ownDel.StatusCode)
	}

	// 7. User deactivation invalidates user-owned virtual key; Org deactivation cuts off all keys across replicas
	mustAdminJSON(t, client, http.MethodPut, prodPod1Base+"/admin/v1/users/"+roleUsers["developer"], map[string]any{
		"scim_active": false,
	}, nil, http.StatusOK)
	deactUserResp, _ := doReq(t, client, http.MethodGet, prodPod2Base+"/v1/models", nil, map[string]string{"Authorization": "Bearer " + memKey.RawKey})
	if deactUserResp.StatusCode != http.StatusUnauthorized && deactUserResp.StatusCode != http.StatusForbidden {
		t.Fatalf("deactivated user's key expected 401/403 on Pod 2, got %d", deactUserResp.StatusCode)
	}

	mustAdminJSON(t, client, http.MethodPut, prodPod1Base+"/admin/v1/organizations/"+org.ID, map[string]any{
		"is_active": false,
	}, nil, http.StatusOK)
	deactOrgResp, _ := doReq(t, client, http.MethodGet, prodPod2Base+"/v1/models", nil, map[string]string{"Authorization": "Bearer " + llmKey.RawKey})
	if deactOrgResp.StatusCode != http.StatusForbidden && deactOrgResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("deactivated org key expected 401/403 on Pod 2, got %d", deactOrgResp.StatusCode)
	}
}

// TestProdDocker_Suite6b_Wildcards_OrgPolicies_Intersection_Quotas_TPM_Concurrency_AndWindows
// verifies Capabilities 1, 2, 9, 15, and 16 in depth across both production replicas.
func TestProdDocker_Suite6b_Wildcards_OrgPolicies_Intersection_Quotas_TPM_Concurrency_AndWindows(t *testing.T) {
	client := newProdTLSClient(t, false)
	resetFixtureAuthzPolicy(t, client)

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	globalID := seedCustomGlobalModel(t, "openai/prod-fixture-mini", "openai", "gpt-4o-mini", 100000, 200000)
	budgetGlobalID := seedCustomGlobalModel(t, "openai/prod-fixture-budget", "openai", "prod-fixture-budget", 50000000, 100000000)

	var org struct {
		ID string `json:"id"`
	}
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/organizations", map[string]any{
		"name": "Suite6b Org " + suffix, "slug": "suite6b-" + suffix,
	}, &org, http.StatusCreated)
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/organizations/"+org.ID+"/subscriptions", map[string]any{
		"provider": "openai", "is_enabled": true,
	}, nil, http.StatusOK)

	var credEU, credUS, credSlow struct {
		ID string `json:"id"`
	}
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/credentials", map[string]any{
		"org_id": org.ID, "provider": "openai", "name": "s6b-eu-" + suffix, "api_key": "sk-eu", "base_url": prodFixturesBase + "/llm/eu/v1",
	}, &credEU, http.StatusCreated)
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/credentials", map[string]any{
		"org_id": org.ID, "provider": "openai", "name": "s6b-us-" + suffix, "api_key": "sk-us", "base_url": prodFixturesBase + "/llm/us/v1",
	}, &credUS, http.StatusCreated)
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/credentials", map[string]any{
		"org_id": org.ID, "provider": "openai", "name": "s6b-slow-" + suffix, "api_key": "sk-slow", "base_url": prodFixturesBase + "/llm/slow/v1",
	}, &credSlow, http.StatusCreated)

	var mgRes, mgSlow, mgBud struct {
		ID string `json:"id"`
	}
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/model-groups", map[string]any{
		"org_id": org.ID, "alias": "residency-alpha", "routing_strategy": "round_robin",
	}, &mgRes, http.StatusCreated)
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/model-groups", map[string]any{
		"org_id": org.ID, "alias": "slow-concurrency-model", "routing_strategy": "round_robin",
	}, &mgSlow, http.StatusCreated)
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/model-groups", map[string]any{
		"org_id": org.ID, "alias": "prod-fixture-budget", "routing_strategy": "round_robin",
	}, &mgBud, http.StatusCreated)

	var depEU, depUS struct {
		ID string `json:"id"`
	}
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/deployments", map[string]any{
		"model_group_id": mgRes.ID, "global_model_id": globalID, "credential_id": credEU.ID,
		"deployment_name": "s6b-dep-eu", "tags": []string{"eu-gdpr"}, "weight": 100, "priority": 1,
	}, &depEU, http.StatusCreated)
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/deployments", map[string]any{
		"model_group_id": mgRes.ID, "global_model_id": globalID, "credential_id": credUS.ID,
		"deployment_name": "s6b-dep-us", "tags": []string{"us-east"}, "weight": 100, "priority": 1,
	}, &depUS, http.StatusCreated)
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/deployments", map[string]any{
		"model_group_id": mgSlow.ID, "global_model_id": globalID, "credential_id": credSlow.ID,
		"deployment_name": "s6b-dep-slow", "weight": 100, "priority": 1,
	}, nil, http.StatusCreated)
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/deployments", map[string]any{
		"model_group_id": mgBud.ID, "global_model_id": budgetGlobalID, "credential_id": credEU.ID,
		"deployment_name": "s6b-dep-bud", "weight": 100, "priority": 1,
	}, nil, http.StatusCreated)

	// 1. Wildcard allowed_models + non-chat /v1/responses & /v1/embeddings deployment enforcement
	var wcKey struct {
		RawKey string `json:"raw_key"`
	}
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/keys", map[string]any{
		"org_id": org.ID, "name": "wildcard-key",
		"allowed_models": []string{"residency-*"}, "allowed_deployments": []string{depEU.ID},
	}, &wcKey, http.StatusCreated)

	wcResp, wcBody := doReq(t, client, http.MethodPost, prodPod2Base+"/v1/responses", map[string]any{
		"model": "residency-alpha", "input": "hello",
	}, map[string]string{"Authorization": "Bearer " + wcKey.RawKey})
	if wcResp.StatusCode != http.StatusOK || !strings.Contains(string(wcBody), "eu-deployment-ok") {
		t.Fatalf("wildcard /v1/responses expected 200 eu-deployment-ok, got %d: %s", wcResp.StatusCode, string(wcBody))
	}
	wcEmb, wcEmbBody := doReq(t, client, http.MethodPost, prodPod1Base+"/v1/embeddings", map[string]any{
		"model": "residency-alpha", "input": "hello",
	}, map[string]string{"Authorization": "Bearer " + wcKey.RawKey})
	if wcEmb.StatusCode != http.StatusOK {
		t.Fatalf("wildcard /v1/embeddings expected 200, got %d: %s", wcEmb.StatusCode, string(wcEmbBody))
	}
	wcDeny, _ := doReq(t, client, http.MethodPost, prodPod2Base+"/v1/chat/completions", map[string]any{
		"model": "slow-concurrency-model", "messages": []map[string]any{{"role": "user", "content": "hi"}},
	}, map[string]string{"Authorization": "Bearer " + wcKey.RawKey})
	if wcDeny.StatusCode != http.StatusForbidden {
		t.Fatalf("wildcard allowed_models expected 403 on non-matching model, got %d", wcDeny.StatusCode)
	}

	// 2. Org Model Policy disable & unconditional Org Provider Subscription disable (strict 403 propagation via OrgPolicyDeniedError)
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/organizations/"+org.ID+"/models", map[string]any{
		"global_model_id": globalID, "is_enabled": false,
	}, nil, http.StatusOK)
	time.Sleep(150 * time.Millisecond)
	mpDeny, mpBody := doReq(t, client, http.MethodPost, prodPod2Base+"/v1/chat/completions", map[string]any{
		"model": "residency-alpha", "messages": []map[string]any{{"role": "user", "content": "hi"}},
	}, map[string]string{"Authorization": "Bearer " + wcKey.RawKey})
	if mpDeny.StatusCode != http.StatusForbidden || !strings.Contains(string(mpBody), "model_disabled_by_org_policy") {
		t.Fatalf("disabled Org Model Policy expected 403 model_disabled_by_org_policy on Pod 2, got %d: %s", mpDeny.StatusCode, string(mpBody))
	}
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/organizations/"+org.ID+"/models", map[string]any{
		"global_model_id": globalID, "is_enabled": true,
	}, nil, http.StatusOK)

	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/organizations/"+org.ID+"/subscriptions", map[string]any{
		"provider": "openai", "is_enabled": false,
	}, nil, http.StatusOK)
	time.Sleep(150 * time.Millisecond)
	subDeny, subBody := doReq(t, client, http.MethodPost, prodPod2Base+"/v1/chat/completions", map[string]any{
		"model": "residency-alpha", "messages": []map[string]any{{"role": "user", "content": "hi"}},
	}, map[string]string{"Authorization": "Bearer " + wcKey.RawKey})
	if subDeny.StatusCode != http.StatusForbidden || !strings.Contains(string(subBody), "provider_not_subscribed") {
		t.Fatalf("disabled Org Provider Subscription expected 403 provider_not_subscribed on Pod 2, got %d: %s", subDeny.StatusCode, string(subBody))
	}
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/organizations/"+org.ID+"/subscriptions", map[string]any{
		"provider": "openai", "is_enabled": true,
	}, nil, http.StatusOK)
	time.Sleep(150 * time.Millisecond)

	// 3. Team ∩ Project ∩ Key allowed_deployments empty intersection -> 403 deployment_restricted
	var team, projQuota struct {
		ID string `json:"id"`
	}
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/teams", map[string]any{
		"org_id": org.ID, "name": "Intersection Team " + suffix,
		"allowed_deployments": []string{depEU.ID, depUS.ID},
	}, &team, http.StatusCreated)
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/projects", map[string]any{
		"org_id": org.ID, "team_id": team.ID, "name": "Quota Enforced Project " + suffix,
		"allowed_deployments": []string{depEU.ID}, "enforce_model_quota": true,
	}, &projQuota, http.StatusCreated)

	var disjointKey, quotaKey struct {
		ID     string `json:"id"`
		RawKey string `json:"raw_key"`
	}
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/keys", map[string]any{
		"org_id": org.ID, "team_id": team.ID, "project_id": projQuota.ID, "name": "disjoint-dep-key",
		"allowed_deployments": []string{depUS.ID}, "rpm_limit": 20,
	}, &disjointKey, http.StatusCreated)
	disjResp, disjBody := doReq(t, client, http.MethodPost, prodPod2Base+"/v1/chat/completions", map[string]any{
		"model": "residency-alpha", "messages": []map[string]any{{"role": "user", "content": "hi"}},
	}, map[string]string{"Authorization": "Bearer " + disjointKey.RawKey})
	if disjResp.StatusCode != http.StatusForbidden || !strings.Contains(string(disjBody), "deployment_restricted") {
		t.Fatalf("empty Team∩Project∩Key deployment intersection expected 403 deployment_restricted, got %d: %s", disjResp.StatusCode, string(disjBody))
	}

	// 4. Project enforce_model_quota=true -> 403 before quota policy, 200 after PUT /admin/v1/quotas (model_per_key)
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/keys", map[string]any{
		"org_id": org.ID, "team_id": team.ID, "project_id": projQuota.ID, "name": "project-quota-key",
	}, &quotaKey, http.StatusCreated)
	pqDeny, pqBody := doReq(t, client, http.MethodPost, prodPod1Base+"/v1/chat/completions", map[string]any{
		"model": "residency-alpha", "messages": []map[string]any{{"role": "user", "content": "hi"}},
	}, map[string]string{"Authorization": "Bearer " + quotaKey.RawKey})
	if pqDeny.StatusCode != http.StatusForbidden || !strings.Contains(string(pqBody), "project_model_quota_required") {
		t.Fatalf("project enforce_model_quota expected 403 project_model_quota_required, got %d: %s", pqDeny.StatusCode, string(pqBody))
	}
	mustAdminJSON(t, client, http.MethodPut, prodPod1Base+"/admin/v1/quotas", map[string]any{
		"org_id": org.ID, "scope_type": "model_per_key", "scope_id": quotaKey.ID,
		"model_pattern": "residency-*", "rpm_limit": 10, "is_active": true,
	}, nil, http.StatusOK, http.StatusCreated)
	time.Sleep(150 * time.Millisecond)
	pqOK, pqOKBody := doReq(t, client, http.MethodPost, prodPod2Base+"/v1/chat/completions", map[string]any{
		"model": "residency-alpha", "messages": []map[string]any{{"role": "user", "content": "hi"}},
	}, map[string]string{"Authorization": "Bearer " + quotaKey.RawKey})
	if pqOK.StatusCode != http.StatusOK {
		t.Fatalf("project quota key after QuotaPolicy expected 200 on Pod 2, got %d: %s", pqOK.StatusCode, string(pqOKBody))
	}

	// 5. Distributed TPM limit across Pod 1 -> Pod 2 (mock returns 150 tokens; tpm_limit=160 -> 2nd call 429)
	var tpmKey struct {
		RawKey string `json:"raw_key"`
	}
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/keys", map[string]any{
		"org_id": org.ID, "name": "tpm-limit-key", "tpm_limit": 160,
	}, &tpmKey, http.StatusCreated)
	t1, t1b := doReq(t, client, http.MethodPost, prodPod1Base+"/v1/chat/completions", map[string]any{
		"model": "residency-alpha", "max_tokens": 50, "messages": []map[string]any{{"role": "user", "content": "first tpm call"}},
	}, map[string]string{"Authorization": "Bearer " + tpmKey.RawKey})
	if t1.StatusCode != http.StatusOK {
		t.Fatalf("TPM call #1 expected 200, got %d: %s", t1.StatusCode, string(t1b))
	}
	t2, t2b := doReq(t, client, http.MethodPost, prodPod2Base+"/v1/chat/completions", map[string]any{
		"model": "residency-alpha", "max_tokens": 50, "messages": []map[string]any{{"role": "user", "content": "second tpm call over limit"}},
	}, map[string]string{"Authorization": "Bearer " + tpmKey.RawKey})
	if t2.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("TPM call #2 on Pod 2 expected 429, got %d: %s", t2.StatusCode, string(t2b))
	}

	// 6. Distributed Concurrency limit (max_concurrent_requests=1) across Pod 1 & Pod 2 against /llm/slow/v1
	var concKey struct {
		RawKey string `json:"raw_key"`
	}
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/keys", map[string]any{
		"org_id": org.ID, "name": "conc-limit-key", "max_concurrent_requests": 1,
	}, &concKey, http.StatusCreated)
	var okCount, rlCount atomic.Int32
	var wg sync.WaitGroup
	for i, base := range []string{prodPod1Base, prodPod2Base} {
		wg.Add(1)
		go func(idx int, target string) {
			defer wg.Done()
			if idx == 1 {
				time.Sleep(100 * time.Millisecond)
			}
			r, _ := doReq(t, client, http.MethodPost, target+"/v1/chat/completions", map[string]any{
				"model": "slow-concurrency-model", "messages": []map[string]any{{"role": "user", "content": "slow"}},
			}, map[string]string{"Authorization": "Bearer " + concKey.RawKey})
			if r.StatusCode == http.StatusOK {
				okCount.Add(1)
			} else if r.StatusCode == http.StatusTooManyRequests {
				rlCount.Add(1)
			}
		}(i, base)
	}
	wg.Wait()
	if okCount.Load() != 1 || rlCount.Load() != 1 {
		t.Fatalf("distributed concurrency limit expected 1x200 + 1x429 across Pod 1 & Pod 2, got ok=%d 429=%d", okCount.Load(), rlCount.Load())
	}

	// 7. Rolling 24h Budget Window + Temporary Budget Increase unblocking + Soft Budget + spend_logs attribution
	var teamBud, projBud struct {
		ID string `json:"id"`
	}
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/teams", map[string]any{
		"org_id": org.ID, "name": "Budget Team " + suffix,
	}, &teamBud, http.StatusCreated)
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/projects", map[string]any{
		"org_id": org.ID, "team_id": teamBud.ID, "name": "Budget Project " + suffix,
	}, &projBud, http.StatusCreated)
	var winKey struct {
		ID     string `json:"id"`
		RawKey string `json:"raw_key"`
	}
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/keys", map[string]any{
		"org_id": org.ID, "team_id": teamBud.ID, "project_id": projBud.ID, "name": "budget-window-temp-key",
		"max_budget_micros": 12000, "soft_budget_micros": 5000, "rpm_limit": 20,
	}, &winKey, http.StatusCreated)
	mustAdminJSON(t, client, http.MethodPut, prodPod1Base+"/admin/v1/budget-windows", map[string]any{
		"org_id": org.ID, "scope_type": "virtual_key", "scope_id": winKey.ID,
		"window_type": "rolling_24h", "max_budget_micros": 50000,
	}, nil, http.StatusOK, http.StatusCreated)

	// Call #1 succeeds (immediately settles 10,000 micros atomically in Redis via reconcile.lua)
	bw1, bw1b := doReq(t, client, http.MethodPost, prodPod1Base+"/v1/chat/completions", map[string]any{
		"model": "prod-fixture-budget", "max_tokens": 16, "messages": []map[string]any{{"role": "user", "content": "spend 1"}},
	}, map[string]string{"Authorization": "Bearer " + winKey.RawKey})
	if bw1.StatusCode != http.StatusOK {
		t.Fatalf("budget window call #1 expected 200, got %d: %s", bw1.StatusCode, string(bw1b))
	}
	// Instant atomic Redis settlement: call #2 on Pod 2 MUST be rejected immediately with zero sleep!
	bw2, bw2b := doReq(t, client, http.MethodPost, prodPod2Base+"/v1/chat/completions", map[string]any{
		"model": "prod-fixture-budget", "max_tokens": 64, "messages": []map[string]any{{"role": "user", "content": "spend 2"}},
	}, map[string]string{"Authorization": "Bearer " + winKey.RawKey})
	if bw2.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected immediate 429 key_budget_exceeded on Pod 2 right after call #1 settled, got %d: %s", bw2.StatusCode, string(bw2b))
	}

	// Grant Temporary Budget Increase (+100,000 micros for 300s) -> immediately unblocks winKey on Pod 2!
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/keys/"+winKey.ID+"/temp-budget", map[string]any{
		"temp_budget_increase_micros": 100000, "ttl_seconds": 300,
	}, nil, http.StatusOK)
	time.Sleep(150 * time.Millisecond)
	unblk, unblkBody := doReq(t, client, http.MethodPost, prodPod2Base+"/v1/chat/completions", map[string]any{
		"model": "prod-fixture-budget", "max_tokens": 16, "messages": []map[string]any{{"role": "user", "content": "after temp budget"}},
	}, map[string]string{"Authorization": "Bearer " + winKey.RawKey})
	if unblk.StatusCode != http.StatusOK {
		t.Fatalf("TempBudget increase expected to unblock winKey on Pod 2, got %d: %s", unblk.StatusCode, string(unblkBody))
	}

	// Verify PostgreSQL spend_logs attribution carries exact org_id, team_id, project_id, virtual_key_id
	attrOut := strings.TrimSpace(psqlExec(t, fmt.Sprintf(
		"SELECT COUNT(*) FROM spend_logs WHERE org_id='%s' AND team_id='%s' AND project_id='%s' AND virtual_key_id='%s';",
		org.ID, teamBud.ID, projBud.ID, winKey.ID,
	)))
	if attrOut == "" || attrOut == "0" {
		t.Fatalf("expected attributed spend_logs row for org/team/project/key, got %q", attrOut)
	}
}

// TestProdDocker_Suite7b_MultiMCPHub_ToolAuthz_A2AKillSwitch_UnifiedGroups_AndDynamicRules
// verifies Capabilities 3, 4, 5, 11, and 14 (Webhook deny_tools/deny_agents/deny_paths) + 19 (MCP/A2A audits).
func TestProdDocker_Suite7b_MultiMCPHub_ToolAuthz_A2AKillSwitch_UnifiedGroups_AndDynamicRules(t *testing.T) {
	client := newProdTLSClient(t, false)
	defer resetFixtureAuthzPolicy(t, client)
	resetFixtureAuthzPolicy(t, client)

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	globalID := seedCustomGlobalModel(t, "openai/prod-fixture-mini", "openai", "gpt-4o-mini", 100000, 200000)

	var org struct {
		ID string `json:"id"`
	}
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/organizations", map[string]any{
		"name": "Suite7b Org " + suffix, "slug": "suite7b-" + suffix,
	}, &org, http.StatusCreated)
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/organizations/"+org.ID+"/subscriptions", map[string]any{
		"provider": "openai", "is_enabled": true,
	}, nil, http.StatusOK)

	// Register 2 MCP servers: github + slack, and sync both
	var ghSrv, slSrv struct {
		Server struct {
			ID string `json:"id"`
		} `json:"server"`
	}
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/mcp/servers", map[string]any{
		"org_id": org.ID, "name": "GitHub", "slug": "github",
		"protocol_version": "2026-07-28", "transport_type": "streamable_http",
		"endpoint_url": prodFixturesBase + "/mcp", "auth_type": "none",
	}, &ghSrv, http.StatusCreated)
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/mcp/servers", map[string]any{
		"org_id": org.ID, "name": "Slack", "slug": "slack",
		"protocol_version": "2026-07-28", "transport_type": "streamable_http",
		"endpoint_url": prodFixturesBase + "/mcp-slack", "auth_type": "none",
	}, &slSrv, http.StatusCreated)

	var ghSync struct {
		Tools []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"tools"`
	}
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/mcp/servers/"+ghSrv.Server.ID+"/sync", nil, &ghSync, http.StatusOK)
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/mcp/servers/"+slSrv.Server.ID+"/sync", nil, nil, http.StatusOK)
	var getIssueID string
	for _, tl := range ghSync.Tools {
		if tl.Name == "get_issue" {
			getIssueID = tl.ID
		}
	}
	tsSlug := "gh-only-ts-" + suffix
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/mcp/toolsets", map[string]any{
		"org_id": org.ID, "name": "GH Only TS", "slug": tsSlug, "tool_ids": []string{getIssueID},
	}, nil, http.StatusCreated)

	// Register A2A agent (key_strict)
	var a2aReg struct {
		Agent struct {
			ID string `json:"id"`
		} `json:"agent"`
	}
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/a2a/agents", map[string]any{
		"org_id": org.ID, "name": "Researcher 7b", "slug": "researcher",
		"endpoint_url": prodFixturesBase + "/a2a", "auth_type": "none", "task_visibility_mode": "key_strict",
	}, &a2aReg, http.StatusCreated)

	// 1. Multi-server /mcp Virtual Hub isolation + unlisted tool denial + unauthorized toolset denial
	var ghOnlyKey, wildcardToolKey, noToolsetKey struct {
		ID     string `json:"id"`
		RawKey string `json:"raw_key"`
	}
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/keys", map[string]any{
		"org_id": org.ID, "name": "gh-only-hub-key",
		"allowed_mcp_servers": []string{"github"}, "allowed_mcp_tools": []string{"github:get_issue"},
		"allowed_mcp_toolsets": []string{tsSlug}, "allowed_a2a_agents": []string{"researcher"},
	}, &ghOnlyKey, http.StatusCreated)
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/keys", map[string]any{
		"org_id": org.ID, "name": "wildcard-tool-key",
		"allowed_mcp_servers": []string{"github"}, "allowed_mcp_tools": []string{"github:get_*"},
		"allowed_mcp_toolsets": []string{}, "allowed_a2a_agents": []string{"researcher"},
	}, &wildcardToolKey, http.StatusCreated)
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/keys", map[string]any{
		"org_id": org.ID, "name": "no-toolset-key",
		"allowed_mcp_servers": []string{"github"}, "allowed_mcp_toolsets": []string{},
	}, &noToolsetKey, http.StatusCreated)

	// Virtual Hub POST /mcp tools/list must include get_issue and NEVER leak slack tools (list_channels, post_message)
	hubResp, hubBody := doReq(t, client, http.MethodPost, prodPod2Base+"/mcp", map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": "tools/list",
	}, map[string]string{"Authorization": "Bearer " + ghOnlyKey.RawKey})
	if hubResp.StatusCode != http.StatusOK || !strings.Contains(string(hubBody), "get_issue") || strings.Contains(string(hubBody), "post_message") || strings.Contains(string(hubBody), "list_files") {
		t.Fatalf("Virtual Hub /mcp isolation failed: status=%d body=%s", hubResp.StatusCode, string(hubBody))
	}
	// Direct /mcp/slack denied for ghOnlyKey
	slDeny, slBody := doReq(t, client, http.MethodPost, prodPod2Base+"/mcp/slack", map[string]any{
		"jsonrpc": "2.0", "id": 2, "method": "tools/list",
	}, map[string]string{"Authorization": "Bearer " + ghOnlyKey.RawKey})
	if slDeny.StatusCode == http.StatusOK && !strings.Contains(string(slBody), `"error"`) {
		t.Fatalf("ghOnlyKey unexpectedly allowed /mcp/slack: %d %s", slDeny.StatusCode, string(slBody))
	}
	// Calling unlisted tool list_files on /mcp/github returns mcp_tool_restricted
	unlistedResp, unlistedBody := doReq(t, client, http.MethodPost, prodPod2Base+"/mcp/github", map[string]any{
		"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": map[string]any{"name": "list_files", "arguments": map[string]any{}},
	}, map[string]string{"Authorization": "Bearer " + ghOnlyKey.RawKey})
	if unlistedResp.StatusCode == http.StatusOK && !strings.Contains(string(unlistedBody), "mcp_tool_restricted") && !strings.Contains(string(unlistedBody), `"error"`) {
		t.Fatalf("unlisted tool list_files expected denial, got: %d %s", unlistedResp.StatusCode, string(unlistedBody))
	}
	// Wildcard tool github:get_* allows get_issue
	wcToolResp, wcToolBody := doReq(t, client, http.MethodPost, prodPod2Base+"/mcp/github", map[string]any{
		"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": map[string]any{"name": "get_issue", "arguments": map[string]any{"id": "7"}},
	}, map[string]string{"Authorization": "Bearer " + wildcardToolKey.RawKey})
	if wcToolResp.StatusCode != http.StatusOK || !strings.Contains(string(wcToolBody), "fixture-mcp-ok") {
		t.Fatalf("wildcard tool pattern github:get_* expected 200, got: %d %s", wcToolResp.StatusCode, string(wcToolBody))
	}
	// Unauthorized toolset denied for noToolsetKey
	tsDeny, tsDenyBody := doReq(t, client, http.MethodPost, prodPod2Base+"/mcp/toolsets/"+tsSlug, map[string]any{
		"jsonrpc": "2.0", "id": 5, "method": "tools/list",
	}, map[string]string{"Authorization": "Bearer " + noToolsetKey.RawKey})
	if tsDeny.StatusCode == http.StatusOK && !strings.Contains(string(tsDenyBody), "mcp_toolset_restricted") && !strings.Contains(string(tsDenyBody), `"error"`) {
		t.Fatalf("unauthorized toolset expected denial, got: %d %s", tsDeny.StatusCode, string(tsDenyBody))
	}

	// 2. Project tri-state MCP & A2A inheritance (Key updated to null Inherit inherits from Project)
	var team, proj struct {
		ID string `json:"id"`
	}
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/teams", map[string]any{
		"org_id": org.ID, "name": "Agentic Team " + suffix,
	}, &team, http.StatusCreated)
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/projects", map[string]any{
		"org_id": org.ID, "team_id": team.ID, "name": "Agentic Project " + suffix,
		"allowed_mcp_servers": []string{"slack"}, "allowed_mcp_tools": []string{"slack:list_channels"},
		"allowed_a2a_agents": []string{"researcher"},
	}, &proj, http.StatusCreated)
	var inheritKey struct {
		ID     string `json:"id"`
		RawKey string `json:"raw_key"`
	}
	// Single-call tri-state creation: explicit JSON null persists SQL NULL (Inherit) without a follow-up PUT!
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/keys", map[string]any{
		"org_id": org.ID, "team_id": team.ID, "project_id": proj.ID, "name": "project-inherit-key",
		"allowed_mcp_servers": nil, "allowed_mcp_tools": nil, "allowed_a2a_agents": nil,
	}, &inheritKey, http.StatusCreated)

	inhMCP, inhMCPBody := doReq(t, client, http.MethodPost, prodPod2Base+"/mcp/slack", map[string]any{
		"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": map[string]any{"name": "list_channels", "arguments": map[string]any{}},
	}, map[string]string{"Authorization": "Bearer " + inheritKey.RawKey})
	if inhMCP.StatusCode != http.StatusOK || !strings.Contains(string(inhMCPBody), "prod-fixture-slack") {
		t.Fatalf("Project-inherited MCP tool call failed: %d %s", inhMCP.StatusCode, string(inhMCPBody))
	}
	inhA2A, inhA2ABody := doReq(t, client, http.MethodPost, prodPod2Base+"/a2a/v1/agents/researcher", map[string]any{
		"message": map[string]any{"messageId": "m-inh", "role": "ROLE_USER", "parts": []map[string]any{{"text": "hi"}}},
	}, map[string]string{"Authorization": "Bearer " + inheritKey.RawKey})
	if inhA2A.StatusCode != http.StatusOK || !strings.Contains(string(inhA2ABody), "prod-fixture-a2a-ok") {
		t.Fatalf("Project-inherited A2A call failed: %d %s", inhA2A.StatusCode, string(inhA2ABody))
	}

	// 3. A2A key_strict cross-key task isolation + Kill-Switch + ExternalAuthorizer deny_tools/deny_agents/deny_paths
	var taskResp struct {
		Task struct {
			ID string `json:"id"`
		} `json:"task"`
	}
	_ = json.Unmarshal(inhA2ABody, &taskResp)
	if taskResp.Task.ID == "" {
		t.Fatalf("expected created A2A task id in %s", string(inhA2ABody))
	}
	ownTaskResp, _ := doReq(t, client, http.MethodGet, prodPod2Base+"/a2a/v1/agents/researcher/tasks/"+taskResp.Task.ID, nil, map[string]string{"Authorization": "Bearer " + inheritKey.RawKey})
	if ownTaskResp.StatusCode != http.StatusOK {
		t.Fatalf("task owner GET /tasks/{id} expected 200, got %d", ownTaskResp.StatusCode)
	}
	otherTaskResp, _ := doReq(t, client, http.MethodGet, prodPod2Base+"/a2a/v1/agents/researcher/tasks/"+taskResp.Task.ID, nil, map[string]string{"Authorization": "Bearer " + ghOnlyKey.RawKey})
	if otherTaskResp.StatusCode != http.StatusNotFound {
		t.Fatalf("key_strict cross-key GET /tasks/{id} expected 404, got %d", otherTaskResp.StatusCode)
	}

	// Kill-Switch blocks invocation (503) and emits a2a_agent.kill_switch_updated audit log
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/a2a/agents/"+a2aReg.Agent.ID+"/kill-switch", map[string]any{
		"killed": true,
	}, nil, http.StatusOK)
	killedResp, killedBody := doReq(t, client, http.MethodPost, prodPod2Base+"/a2a/v1/agents/researcher", map[string]any{
		"message": map[string]any{"messageId": "m-kill", "role": "ROLE_USER", "parts": []map[string]any{{"text": "hi"}}},
	}, map[string]string{"Authorization": "Bearer " + inheritKey.RawKey})
	if killedResp.StatusCode != http.StatusServiceUnavailable || !strings.Contains(string(killedBody), "agent_killed") {
		t.Fatalf("A2A kill-switch expected 503 agent_killed on Pod 2, got %d: %s", killedResp.StatusCode, string(killedBody))
	}
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/a2a/agents/"+a2aReg.Agent.ID+"/kill-switch", map[string]any{
		"killed": false,
	}, nil, http.StatusOK)

	// ExternalAuthorizer denying MCP tools, A2A agent task reads, and Admin paths
	doReq(t, client, http.MethodPut, prodFixturesBase+"/_control/authz", map[string]any{
		"deny_tools":  []string{"get_issue"},
		"deny_agents": []string{"researcher"},
		"deny_paths":  []string{"/admin/v1/projects"},
		"reason":      "blocked by prod external policy matrix",
	}, nil)
	extMCP, extMCPBody := doReq(t, client, http.MethodPost, prodPod2Base+"/mcp/github", map[string]any{
		"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": map[string]any{"name": "get_issue", "arguments": map[string]any{}},
	}, map[string]string{"Authorization": "Bearer " + ghOnlyKey.RawKey})
	if extMCP.StatusCode == http.StatusOK && !strings.Contains(string(extMCPBody), "custom_authorization_denied") {
		t.Fatalf("ExternalAuthorizer deny_tools expected custom_authorization_denied block, got: %d %s", extMCP.StatusCode, string(extMCPBody))
	}
	extA2ATask, _ := doReq(t, client, http.MethodGet, prodPod2Base+"/a2a/v1/agents/researcher/tasks/"+taskResp.Task.ID, nil, map[string]string{"Authorization": "Bearer " + inheritKey.RawKey})
	if extA2ATask.StatusCode != http.StatusForbidden {
		t.Fatalf("ExternalAuthorizer deny_agents on A2A GetTask expected 403, got %d", extA2ATask.StatusCode)
	}
	extAdmin, _ := doReq(t, client, http.MethodGet, prodPod2Base+"/admin/v1/projects?org_id="+org.ID, nil, map[string]string{"Authorization": "Bearer " + prodMasterKey})
	if extAdmin.StatusCode != http.StatusForbidden {
		t.Fatalf("ExternalAuthorizer deny_paths on Admin API expected 403, got %d", extAdmin.StatusCode)
	}
	resetFixtureAuthzPolicy(t, client)

	// 4. Positive Unified Access Group Grant + Gated ModelAccessGroup + Dynamic AccessGroupRule
	var cred, mgGated struct {
		ID string `json:"id"`
	}
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/credentials", map[string]any{
		"org_id": org.ID, "provider": "openai", "name": "s7b-cred-" + suffix, "api_key": "sk-s7b", "base_url": prodFixturesBase + "/llm/eu/v1",
	}, &cred, http.StatusCreated)
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/model-groups", map[string]any{
		"org_id": org.ID, "alias": "gated-secret-model", "routing_strategy": "round_robin",
	}, &mgGated, http.StatusCreated)
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/deployments", map[string]any{
		"model_group_id": mgGated.ID, "global_model_id": globalID, "credential_id": cred.ID,
		"deployment_name": "dep-gated", "weight": 100, "priority": 1,
	}, nil, http.StatusCreated)

	var memberKey, outsiderKey struct {
		ID     string `json:"id"`
		RawKey string `json:"raw_key"`
	}
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/keys", map[string]any{
		"org_id": org.ID, "name": "uag-member-key", "allowed_models": []string{"other-only"},
		"allowed_mcp_servers": nil, "allowed_mcp_tools": nil, "allowed_a2a_agents": nil,
	}, &memberKey, http.StatusCreated)
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/keys", map[string]any{
		"org_id": org.ID, "name": "uag-outsider-key", "allowed_models": []string{"*"},
	}, &outsiderKey, http.StatusCreated)

	var gatedGroup struct {
		ID string `json:"id"`
	}
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/access-groups", map[string]any{
		"org_id":              org.ID,
		"name":                "gated-unified-" + suffix,
		"allowed_mcp_servers": []string{"github"},
		"allowed_mcp_tools":   []string{"github:list_files"},
		"allowed_a2a_agents":  []string{"researcher"},
	}, &gatedGroup, http.StatusOK, http.StatusCreated)
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/access-groups/"+gatedGroup.ID+"/members", map[string]any{
		"org_id": org.ID, "member_type": "model", "member_id": "gated-secret-model",
	}, nil, http.StatusOK, http.StatusCreated)
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/access-groups/"+gatedGroup.ID+"/members", map[string]any{
		"org_id": org.ID, "member_type": "key", "member_id": memberKey.ID,
	}, nil, http.StatusOK, http.StatusCreated)
	time.Sleep(150 * time.Millisecond)

	// Outsider with allowed_models=["*"] is DENIED gated-secret-model (403 model_access_group_denied)
	outResp, outBody := doReq(t, client, http.MethodPost, prodPod2Base+"/v1/chat/completions", map[string]any{
		"model": "gated-secret-model", "messages": []map[string]any{{"role": "user", "content": "hi"}},
	}, map[string]string{"Authorization": "Bearer " + outsiderKey.RawKey})
	if outResp.StatusCode != http.StatusForbidden || !strings.Contains(string(outBody), "model_access_group_denied") {
		t.Fatalf("outsider expected 403 model_access_group_denied, got %d: %s", outResp.StatusCode, string(outBody))
	}
	// Member key gains model + MCP server/tool + A2A agent positively from the Unified Access Group!
	memModelResp, memModelBody := doReq(t, client, http.MethodPost, prodPod2Base+"/v1/chat/completions", map[string]any{
		"model": "gated-secret-model", "messages": []map[string]any{{"role": "user", "content": "hi"}},
	}, map[string]string{"Authorization": "Bearer " + memberKey.RawKey})
	if memModelResp.StatusCode != http.StatusOK {
		t.Fatalf("UAG member model call expected 200, got %d: %s", memModelResp.StatusCode, string(memModelBody))
	}
	memMCPResp, memMCPBody := doReq(t, client, http.MethodPost, prodPod2Base+"/mcp/github", map[string]any{
		"jsonrpc": "2.0", "id": 8, "method": "tools/call", "params": map[string]any{"name": "list_files", "arguments": map[string]any{}},
	}, map[string]string{"Authorization": "Bearer " + memberKey.RawKey})
	if memMCPResp.StatusCode != http.StatusOK || !strings.Contains(string(memMCPBody), "fixture-mcp-ok") {
		t.Fatalf("UAG member MCP call expected 200, got %d: %s", memMCPResp.StatusCode, string(memMCPBody))
	}
	memA2AResp, memA2ABody := doReq(t, client, http.MethodPost, prodPod2Base+"/a2a/v1/agents/researcher", map[string]any{
		"message": map[string]any{"messageId": "m-uag", "role": "ROLE_USER", "parts": []map[string]any{{"text": "hi"}}},
	}, map[string]string{"Authorization": "Bearer " + memberKey.RawKey})
	if memA2AResp.StatusCode != http.StatusOK || !strings.Contains(string(memA2ABody), "prod-fixture-a2a-ok") {
		t.Fatalf("UAG member A2A call expected 200, got %d: %s", memA2AResp.StatusCode, string(memA2ABody))
	}

	// Dynamic AccessGroupRule matching jwt_claims.groups on org_default
	var dynRule struct {
		ID string `json:"id"`
	}
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/access-group-rules", map[string]any{
		"org_id": "org_default", "name": "dyn-jwt-rule-" + suffix,
		"attribute": "jwt_claims.groups", "operator": "contains", "value": "goroute-org-admins",
		"allowed_models": []string{"jwt-mapped-only-model"}, "priority": 100,
	}, &dynRule, http.StatusCreated)
	mustAdminJSON(t, client, http.MethodDelete, prodPod1Base+"/admin/v1/access-group-rules/"+dynRule.ID, nil, nil, http.StatusOK)

	// 5. Verify Audit Log server-side filters (action + resource) for MCP and A2A admin audit events
	for _, q := range []struct {
		action   string
		resource string
	}{
		{"mcp_server.created", "mcp_server"},
		{"mcp_toolset.created", "mcp_toolset"},
		{"a2a_agent.created", "a2a_agent"},
		{"a2a_agent.kill_switch_updated", "a2a_agent"},
	} {
		u := fmt.Sprintf("%s/admin/v1/audit/logs?org_id=%s&action=%s&resource=%s&limit=10",
			prodPod2Base, url.QueryEscape(org.ID), url.QueryEscape(q.action), url.QueryEscape(q.resource))
		raw := mustAdminJSON(t, client, http.MethodGet, u, nil, nil, http.StatusOK)
		if !strings.Contains(string(raw), q.action) {
			t.Fatalf("filtered audit query for %s/%s missing expected record: %s", q.action, q.resource, string(raw))
		}
	}
}

// TestProdDocker_Suite11_VirtualKeyLifecycle_Rotation_Endpoints_AndDelegation
// verifies Capability 6 (Virtual Key Permissions: endpoint allowlists, expiry, rotation grace window, cross-replica revocation, delegation).
func TestProdDocker_Suite11_VirtualKeyLifecycle_Rotation_Endpoints_AndDelegation(t *testing.T) {
	client := newProdTLSClient(t, false)
	resetFixtureAuthzPolicy(t, client)

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	globalID := seedCustomGlobalModel(t, "openai/prod-fixture-mini", "openai", "gpt-4o-mini", 100000, 200000)

	var org struct {
		ID string `json:"id"`
	}
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/organizations", map[string]any{
		"name": "Suite11 VK Org " + suffix, "slug": "suite11-" + suffix,
	}, &org, http.StatusCreated)
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/organizations/"+org.ID+"/subscriptions", map[string]any{
		"provider": "openai", "is_enabled": true,
	}, nil, http.StatusOK)

	var cred, mgA, mgB struct {
		ID string `json:"id"`
	}
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/credentials", map[string]any{
		"org_id": org.ID, "provider": "openai", "name": "s11-cred-" + suffix, "api_key": "sk-s11", "base_url": prodFixturesBase + "/llm/eu/v1",
	}, &cred, http.StatusCreated)
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/model-groups", map[string]any{
		"org_id": org.ID, "alias": "vk-model-a", "routing_strategy": "round_robin",
	}, &mgA, http.StatusCreated)
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/model-groups", map[string]any{
		"org_id": org.ID, "alias": "vk-model-b", "routing_strategy": "round_robin",
	}, &mgB, http.StatusCreated)
	for _, mgID := range []string{mgA.ID, mgB.ID} {
		mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/deployments", map[string]any{
			"model_group_id": mgID, "global_model_id": globalID, "credential_id": cred.ID,
			"deployment_name": "dep-" + mgID, "weight": 100, "priority": 1,
		}, nil, http.StatusCreated)
	}

	// 1. Endpoint allowlist: allowed_endpoints=["/v1/embeddings"] allows embeddings, blocks chat (403 endpoint_not_allowed)
	var epKey struct {
		RawKey string `json:"raw_key"`
	}
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/keys", map[string]any{
		"org_id": org.ID, "name": "emb-only-key", "allowed_endpoints": []string{"/v1/embeddings"},
	}, &epKey, http.StatusCreated)
	embOK, embBody := doReq(t, client, http.MethodPost, prodPod2Base+"/v1/embeddings", map[string]any{
		"model": "vk-model-a", "input": "embed me",
	}, map[string]string{"Authorization": "Bearer " + epKey.RawKey})
	if embOK.StatusCode != http.StatusOK {
		t.Fatalf("allowed_endpoints /v1/embeddings expected 200, got %d: %s", embOK.StatusCode, string(embBody))
	}
	chatDeny, chatDenyBody := doReq(t, client, http.MethodPost, prodPod2Base+"/v1/chat/completions", map[string]any{
		"model": "vk-model-a", "messages": []map[string]any{{"role": "user", "content": "hi"}},
	}, map[string]string{"Authorization": "Bearer " + epKey.RawKey})
	if chatDeny.StatusCode != http.StatusForbidden || !strings.Contains(string(chatDenyBody), "endpoint_not_allowed") {
		t.Fatalf("disallowed endpoint expected 403 endpoint_not_allowed, got %d: %s", chatDeny.StatusCode, string(chatDenyBody))
	}

	// 2. Expired key (expires_at in the past) immediately rejected with 401
	var expKey struct {
		RawKey string `json:"raw_key"`
	}
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/keys", map[string]any{
		"org_id": org.ID, "name": "expired-key", "expires_at": time.Now().UTC().Add(-5 * time.Minute).Format(time.RFC3339),
	}, &expKey, http.StatusCreated)
	expResp, _ := doReq(t, client, http.MethodGet, prodPod2Base+"/v1/models", nil, map[string]string{"Authorization": "Bearer " + expKey.RawKey})
	if expResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expired virtual key expected 401, got %d", expResp.StatusCode)
	}

	// 3. Rotation grace window (both old with deprecation header + new work) & immediate cross-replica revocation
	var rotKey struct {
		ID     string `json:"id"`
		RawKey string `json:"raw_key"`
	}
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/keys", map[string]any{
		"org_id": org.ID, "name": "rotate-grace-key",
	}, &rotKey, http.StatusCreated)
	var rotated struct {
		RawKey string `json:"raw_key"`
	}
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/keys/"+rotKey.ID+"/rotate", map[string]any{
		"grace_period_seconds": 60,
	}, &rotated, http.StatusOK)
	if rotated.RawKey == "" || rotated.RawKey == rotKey.RawKey {
		t.Fatalf("expected distinct new raw_key from rotation")
	}

	oldGrace, _ := doReq(t, client, http.MethodGet, prodPod2Base+"/v1/models", nil, map[string]string{"Authorization": "Bearer " + rotKey.RawKey})
	if oldGrace.StatusCode != http.StatusOK || oldGrace.Header.Get("X-Gateway-Key-Deprecated") != "true" {
		t.Fatalf("old key during grace window expected 200 + X-Gateway-Key-Deprecated=true, got %d hdr=%q", oldGrace.StatusCode, oldGrace.Header.Get("X-Gateway-Key-Deprecated"))
	}
	newGrace, _ := doReq(t, client, http.MethodGet, prodPod2Base+"/v1/models", nil, map[string]string{"Authorization": "Bearer " + rotated.RawKey})
	if newGrace.StatusCode != http.StatusOK {
		t.Fatalf("new rotated key expected 200 on Pod 2, got %d", newGrace.StatusCode)
	}
	// Revoke on Pod 1 -> BOTH old & new keys immediately 401 on Pod 2!
	mustAdminJSON(t, client, http.MethodDelete, prodPod1Base+"/admin/v1/keys/"+rotKey.ID, nil, nil, http.StatusOK)
	time.Sleep(150 * time.Millisecond)
	for _, tok := range []string{rotKey.RawKey, rotated.RawKey} {
		revResp, _ := doReq(t, client, http.MethodGet, prodPod2Base+"/v1/models", nil, map[string]string{"Authorization": "Bearer " + tok})
		if revResp.StatusCode != http.StatusUnauthorized {
			t.Fatalf("revoked key expected immediate 401 on Pod 2, got %d", revResp.StatusCode)
		}
	}

	// 4. Delegation narrowing (can_impersonate=true + X-Gateway-Delegated-Team-Id narrows allowed models)
	var delTeam struct {
		ID string `json:"id"`
	}
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/teams", map[string]any{
		"org_id": org.ID, "name": "Delegated Narrow Team", "allowed_models": []string{"vk-model-a"},
	}, &delTeam, http.StatusCreated)
	var impKey struct {
		RawKey string `json:"raw_key"`
	}
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/keys", map[string]any{
		"org_id": org.ID, "name": "impersonator-key", "can_impersonate": true,
		"allowed_models": []string{"vk-model-a", "vk-model-b"},
	}, &impKey, http.StatusCreated)

	delOK, _ := doReq(t, client, http.MethodPost, prodPod2Base+"/v1/chat/completions", map[string]any{
		"model": "vk-model-a", "messages": []map[string]any{{"role": "user", "content": "hi"}},
	}, map[string]string{"Authorization": "Bearer " + impKey.RawKey, "X-Gateway-Delegated-Team-Id": delTeam.ID})
	if delOK.StatusCode != http.StatusOK {
		t.Fatalf("delegated call to team-allowed model expected 200, got %d", delOK.StatusCode)
	}
	delDeny, _ := doReq(t, client, http.MethodPost, prodPod2Base+"/v1/chat/completions", map[string]any{
		"model": "vk-model-b", "messages": []map[string]any{{"role": "user", "content": "hi"}},
	}, map[string]string{"Authorization": "Bearer " + impKey.RawKey, "X-Gateway-Delegated-Team-Id": delTeam.ID})
	if delDeny.StatusCode != http.StatusForbidden {
		t.Fatalf("delegated call to model outside delegated team expected 403, got %d", delDeny.StatusCode)
	}

	// 5. Client Application access control (allowed_client_apps + X-Gateway-Client-App header + Team tri-state inheritance)
	var appTeam struct {
		ID string `json:"id"`
	}
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/teams", map[string]any{
		"org_id": org.ID, "name": "Client App Team " + suffix, "allowed_client_apps": []string{"cursor"},
	}, &appTeam, http.StatusCreated)
	var appInheritKey struct {
		RawKey string `json:"raw_key"`
	}
	mustAdminJSON(t, client, http.MethodPost, prodPod1Base+"/admin/v1/keys", map[string]any{
		"org_id": org.ID, "team_id": appTeam.ID, "name": "client-app-inherit-key",
		"allowed_client_apps": nil,
	}, &appInheritKey, http.StatusCreated)

	// Missing X-Gateway-Client-App header against explicit allowlist -> 403 client_app_required (no bypass!)
	appMissing, appMissingBody := doReq(t, client, http.MethodGet, prodPod2Base+"/v1/models", nil, map[string]string{
		"Authorization": "Bearer " + appInheritKey.RawKey,
	})
	if appMissing.StatusCode != http.StatusForbidden || !strings.Contains(string(appMissingBody), "client_app_required") {
		t.Fatalf("missing X-Gateway-Client-App expected 403 client_app_required, got %d: %s", appMissing.StatusCode, string(appMissingBody))
	}
	// Disallowed client app -> 403 client_app_restricted
	appDenied, appDeniedBody := doReq(t, client, http.MethodGet, prodPod2Base+"/v1/models", nil, map[string]string{
		"Authorization": "Bearer " + appInheritKey.RawKey, "X-Gateway-Client-App": "curl",
	})
	if appDenied.StatusCode != http.StatusForbidden || !strings.Contains(string(appDeniedBody), "client_app_restricted") {
		t.Fatalf("disallowed X-Gateway-Client-App expected 403 client_app_restricted, got %d: %s", appDenied.StatusCode, string(appDeniedBody))
	}
	// Allowed client app inherited from Team -> 200 OK
	appAllowed, appAllowedBody := doReq(t, client, http.MethodGet, prodPod2Base+"/v1/models", nil, map[string]string{
		"Authorization": "Bearer " + appInheritKey.RawKey, "X-Gateway-Client-App": "cursor",
	})
	if appAllowed.StatusCode != http.StatusOK {
		t.Fatalf("allowed X-Gateway-Client-App=cursor expected 200, got %d: %s", appAllowed.StatusCode, string(appAllowedBody))
	}
}
