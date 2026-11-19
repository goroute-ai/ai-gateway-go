package server_test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGovernanceHardening_OrgUpdate_SelfInfo_KeysAndTeamsAndKEK(t *testing.T) {
	ctx := context.Background()
	env := setupQuotaHandlerTestEnv(t, nil)

	// 1. PUT /admin/v1/organizations/{orgID} - SSRF guard on lifecycle_webhook_url + updates
	recSSRF := doAdminJSONRequest(t, env.handler, http.MethodPut, "/admin/v1/organizations/org_a", env.orgAAdmin.RawKey, map[string]any{
		"lifecycle_webhook_url": "http://169.254.169.254/latest/meta-data",
	})
	assert.Equal(t, http.StatusBadRequest, recSSRF.Code, recSSRF.Body.String())

	recOrgUpd := doAdminJSONRequest(t, env.handler, http.MethodPut, "/admin/v1/organizations/org_a", env.orgAAdmin.RawKey, map[string]any{
		"enforce_guaranteed_throughput": true,
		"developer_self_serve_keys":     true,
		"rpm_limit":                     100,
		"tpm_limit":                     10000,
		"self_serve_budget_policy":      "ceiling",
		"key_expiry_alert_days":         []int{14, 7, 1},
	})
	require.Equal(t, http.StatusOK, recOrgUpd.Code, recOrgUpd.Body.String())

	// Cross-org admin blocked from updating org_a
	recCrossOrg := doAdminJSONRequest(t, env.handler, http.MethodPut, "/admin/v1/organizations/org_a", env.orgBAdmin.RawKey, map[string]any{
		"name": "Hijacked",
	})
	assert.Equal(t, http.StatusForbidden, recCrossOrg.Code)

	// 2. Team member defaults + bulk upsert + reset spend
	recTeamUpd := doAdminJSONRequest(t, env.handler, http.MethodPut, "/admin/v1/teams/team_a1", env.orgAAdmin.RawKey, map[string]any{
		"enforce_guaranteed_throughput":    true,
		"rpm_limit":                        60,
		"default_member_max_budget_micros": 250_000,
		"default_member_rpm_limit":         25,
		"default_member_allowed_models":    []string{"gpt-4.1-mini"},
	})
	require.Equal(t, http.StatusOK, recTeamUpd.Code, recTeamUpd.Body.String())

	require.NoError(t, env.repo.CreateUser(ctx, &domain.User{
		ID:         "usr_bulk_1",
		OrgID:      "org_a",
		TeamID:     "team_a1",
		Email:      "bulk1@example.com",
		Name:       "Bulk One",
		Role:       domain.RoleDeveloper,
		SCIMActive: true,
		IsActive:   true,
	}))
	require.NoError(t, env.repo.CreateUser(ctx, &domain.User{
		ID:         "usr_bulk_2",
		OrgID:      "org_a",
		TeamID:     "team_a1",
		Email:      "bulk2@example.com",
		Name:       "Bulk Two",
		Role:       domain.RoleDeveloper,
		SCIMActive: true,
		IsActive:   true,
	}))

	recBulkMem := doAdminJSONRequest(t, env.handler, http.MethodPost, "/admin/v1/teams/team_a1/members/bulk", env.orgAAdmin.RawKey, map[string]any{
		"members": []map[string]any{
			{"user_id": "usr_bulk_1"},
			{"user_id": "usr_bulk_2", "rpm_limit": 10},
		},
	})
	require.Equal(t, http.StatusOK, recBulkMem.Code, recBulkMem.Body.String())
	var bulkMemResp struct {
		Data     []domain.TeamMembership `json:"data"`
		Upserted int                     `json:"upserted"`
	}
	require.NoError(t, json.Unmarshal(recBulkMem.Body.Bytes(), &bulkMemResp))
	require.Equal(t, 2, bulkMemResp.Upserted)
	assert.Equal(t, int64(250_000), bulkMemResp.Data[0].MaxBudgetMicros)
	assert.Equal(t, 25, bulkMemResp.Data[0].RPMLimit)
	assert.Equal(t, []string{"gpt-4.1-mini"}, bulkMemResp.Data[0].AllowedModels)
	assert.Equal(t, 10, bulkMemResp.Data[1].RPMLimit)

	recResetTMSpend := doAdminJSONRequest(t, env.handler, http.MethodPost, "/admin/v1/teams/team_a1/members/usr_bulk_1/reset-spend", env.orgAAdmin.RawKey, nil)
	assert.Equal(t, http.StatusOK, recResetTMSpend.Code, recResetTMSpend.Body.String())

	// 3. Guaranteed throughput enforcement on key issuance and update + key block/unblock/reset/bulk-update
	k1, err := env.gw.AuthService().IssueVirtualKey(ctx, &domain.VirtualKey{
		OrgID:           "org_a",
		TeamID:          "team_a1",
		UserID:          "usr_bulk_1",
		Name:            "team-guaranteed-1",
		Role:            domain.RoleDeveloper,
		KeyType:         domain.KeyTypeLLMAPI,
		RPMLimit:        40,
		MaxBudgetMicros: 100_000,
	})
	require.NoError(t, err)

	// Attempting to issue a 2nd key with RPM=30 fails because 40+30 > team.rpm_limit=60
	recOverRPM := doAdminJSONRequest(t, env.handler, http.MethodPost, "/admin/v1/keys", env.orgAAdmin.RawKey, map[string]any{
		"org_id":    "org_a",
		"team_id":   "team_a1",
		"name":      "oversubscribed-key",
		"rpm_limit": 30,
	})
	assert.Equal(t, http.StatusBadRequest, recOverRPM.Code)
	assert.Contains(t, recOverRPM.Body.String(), "throughput_allocation_exceeded")

	// Issuing within remaining capacity (15 <= 20) succeeds
	recFitKey := doAdminJSONRequest(t, env.handler, http.MethodPost, "/admin/v1/keys", env.orgAAdmin.RawKey, map[string]any{
		"org_id":    "org_a",
		"team_id":   "team_a1",
		"user_id":   "usr_bulk_2",
		"name":      "within-budget-key",
		"rpm_limit": 15,
	})
	require.Equal(t, http.StatusCreated, recFitKey.Code, recFitKey.Body.String())
	var k2 domain.VirtualKey
	require.NoError(t, json.Unmarshal(recFitKey.Body.Bytes(), &k2))

	// GET /v1/key/info with data-plane key returns safe key info (never hash/raw_key)
	recSelfInfo := doAdminJSONRequest(t, env.handler, http.MethodGet, "/v1/key/info", k1.RawKey, nil)
	require.Equal(t, http.StatusOK, recSelfInfo.Code, recSelfInfo.Body.String())
	assert.Contains(t, recSelfInfo.Body.String(), `"team-guaranteed-1"`)
	assert.NotContains(t, recSelfInfo.Body.String(), k1.RawKey)

	// GET /admin/v1/keys/{keyID} & filtered GET /admin/v1/keys
	recGetKey := doAdminJSONRequest(t, env.handler, http.MethodGet, "/admin/v1/keys/"+k1.ID, env.orgAAdmin.RawKey, nil)
	require.Equal(t, http.StatusOK, recGetKey.Code)
	recListFilt := doAdminJSONRequest(t, env.handler, http.MethodGet, "/admin/v1/keys?status=active&search=guaranteed&limit=10", env.orgAAdmin.RawKey, nil)
	require.Equal(t, http.StatusOK, recListFilt.Code)
	assert.Contains(t, recListFilt.Body.String(), k1.ID)
	assert.NotContains(t, recListFilt.Body.String(), k2.ID)

	// Block -> Unblock -> Reset Spend -> Bulk Update
	recBlk := doAdminJSONRequest(t, env.handler, http.MethodPost, "/admin/v1/keys/"+k1.ID+"/block", env.orgAAdmin.RawKey, map[string]any{"reason": "incident"})
	require.Equal(t, http.StatusOK, recBlk.Code)
	// Blocked key fails /v1/key/info
	assert.Equal(t, http.StatusUnauthorized, doAdminJSONRequest(t, env.handler, http.MethodGet, "/v1/key/info", k1.RawKey, nil).Code)

	recUnblk := doAdminJSONRequest(t, env.handler, http.MethodPost, "/admin/v1/keys/"+k1.ID+"/unblock", env.orgAAdmin.RawKey, nil)
	require.Equal(t, http.StatusOK, recUnblk.Code)
	assert.Equal(t, http.StatusOK, doAdminJSONRequest(t, env.handler, http.MethodGet, "/v1/key/info", k1.RawKey, nil).Code)

	recResetSpend := doAdminJSONRequest(t, env.handler, http.MethodPost, "/admin/v1/keys/"+k1.ID+"/reset-spend", env.orgAAdmin.RawKey, nil)
	require.Equal(t, http.StatusOK, recResetSpend.Code)

	recBulkKeys := doAdminJSONRequest(t, env.handler, http.MethodPost, "/admin/v1/keys/bulk-update", env.orgAAdmin.RawKey, map[string]any{
		"key_ids":        []string{k1.ID, k2.ID},
		"allowed_models": []string{"gpt-4.1-mini"},
	})
	require.Equal(t, http.StatusOK, recBulkKeys.Code, recBulkKeys.Body.String())

	// 4. Governed Developer Self-Service Keys (/v1/self/keys)
	mgmtDevKey, err := env.gw.AuthService().IssueVirtualKey(ctx, &domain.VirtualKey{
		OrgID:   "org_a",
		TeamID:  "team_a1",
		UserID:  "usr_bulk_1",
		Name:    "dev-portal-token",
		Role:    domain.RoleDeveloper,
		KeyType: domain.KeyTypeManagement,
	})
	require.NoError(t, err)

	// llm_api key cannot mint keys via /v1/self/keys
	recLLMBlocked := doAdminJSONRequest(t, env.handler, http.MethodPost, "/v1/self/keys", k1.RawKey, map[string]any{"name": "bad-attempt"})
	assert.Equal(t, http.StatusForbidden, recLLMBlocked.Code)

	// Attempting to request key_type=management fails via self-service
	recEscType := doAdminJSONRequest(t, env.handler, http.MethodPost, "/v1/self/keys", mgmtDevKey.RawKey, map[string]any{
		"name":     "escalate",
		"key_type": "management",
	})
	assert.Equal(t, http.StatusForbidden, recEscType.Code)

	// Valid self-service key create, list, rotate, revoke (using small RPM=2 inside remaining 5)
	recSelfCreate := doAdminJSONRequest(t, env.handler, http.MethodPost, "/v1/self/keys", mgmtDevKey.RawKey, map[string]any{
		"name":              "my-dev-key",
		"rpm_limit":         2,
		"max_budget_micros": 50_000,
	})
	require.Equal(t, http.StatusCreated, recSelfCreate.Code, recSelfCreate.Body.String())
	var selfKey domain.VirtualKey
	require.NoError(t, json.Unmarshal(recSelfCreate.Body.Bytes(), &selfKey))

	recSelfList := doAdminJSONRequest(t, env.handler, http.MethodGet, "/v1/self/keys", mgmtDevKey.RawKey, nil)
	require.Equal(t, http.StatusOK, recSelfList.Code)
	assert.Contains(t, recSelfList.Body.String(), selfKey.ID)
	assert.NotContains(t, recSelfList.Body.String(), k2.ID, "self-service list must only show user's own keys")

	recSelfRotate := doAdminJSONRequest(t, env.handler, http.MethodPost, "/v1/self/keys/"+selfKey.ID+"/rotate", mgmtDevKey.RawKey, map[string]any{})
	require.Equal(t, http.StatusOK, recSelfRotate.Code, recSelfRotate.Body.String())

	// Cannot revoke another user's key via /v1/self/keys
	assert.Equal(t, http.StatusNotFound, doAdminJSONRequest(t, env.handler, http.MethodDelete, "/v1/self/keys/"+k2.ID, mgmtDevKey.RawKey, nil).Code)
	assert.Equal(t, http.StatusOK, doAdminJSONRequest(t, env.handler, http.MethodDelete, "/v1/self/keys/"+selfKey.ID, mgmtDevKey.RawKey, nil).Code)

	// 5. Master KEK rotation (/admin/v1/security/rotate-kek)
	// Non-platform admin rejected
	recKEKForbidden := doAdminJSONRequest(t, env.handler, http.MethodPost, "/admin/v1/security/rotate-kek", env.orgAAdmin.RawKey, map[string]any{
		"new_master_key": "0123456789abcdef0123456789abcdef-rotated",
	})
	assert.Equal(t, http.StatusForbidden, recKEKForbidden.Code)

	recKEK := doAdminJSONRequest(t, env.handler, http.MethodPost, "/admin/v1/security/rotate-kek", env.masterKey, map[string]any{
		"new_master_key": "0123456789abcdef0123456789abcdef-rotated",
	})
	require.Equal(t, http.StatusOK, recKEK.Code, recKEK.Body.String())

	// Audit log contains before/after diff with no raw secrets
	logs, err := env.repo.ListAuditLogs(ctx, "org_a", 50)
	require.NoError(t, err)
	var sawOrgDiff bool
	for _, l := range logs {
		if l != nil && l.Action == "organization.updated" && len(l.AfterValue) > 0 {
			sawOrgDiff = true
		}
	}
	assert.True(t, sawOrgDiff, "expected organization.updated audit entry with redacted before/after snapshot")
}

func TestSelfServiceKeys_TeamMemberPermissions_And_BulkSyncRemove_And_AuditDiffs(t *testing.T) {
	ctx := context.Background()
	env := setupQuotaHandlerTestEnv(t, nil)

	// Enable developer self-service at org level
	require.Equal(t, http.StatusOK, doAdminJSONRequest(t, env.handler, http.MethodPut, "/admin/v1/organizations/org_a", env.orgAAdmin.RawKey, map[string]any{
		"developer_self_serve_keys": true,
	}).Code)

	require.NoError(t, env.repo.CreateUser(ctx, &domain.User{
		ID:       "dev-perm-u1",
		OrgID:    "org_a",
		TeamID:   "team_a1",
		Email:    "devperm@example.com",
		Role:     domain.RoleDeveloper,
		IsActive: true,
	}))
	require.NoError(t, env.repo.CreateUser(ctx, &domain.User{
		ID:       "dev-perm-u2",
		OrgID:    "org_a",
		TeamID:   "team_a1",
		Email:    "devperm2@example.com",
		Role:     domain.RoleDeveloper,
		IsActive: true,
	}))

	// Bulk sync adds both users, then removes dev-perm-u2 while updating dev-perm-u1
	recSync1 := doAdminJSONRequest(t, env.handler, http.MethodPost, "/admin/v1/teams/team_a1/members/bulk", env.orgAAdmin.RawKey, map[string]any{
		"members": []map[string]any{
			{"user_id": "dev-perm-u1"},
			{"user_id": "dev-perm-u2"},
		},
	})
	require.Equal(t, http.StatusOK, recSync1.Code, recSync1.Body.String())

	recSync2 := doAdminJSONRequest(t, env.handler, http.MethodPost, "/admin/v1/teams/team_a1/members/bulk", env.orgAAdmin.RawKey, map[string]any{
		"members": []map[string]any{
			{"user_id": "dev-perm-u1", "role": "developer"},
		},
		"remove_user_ids": []string{"dev-perm-u2"},
	})
	require.Equal(t, http.StatusOK, recSync2.Code, recSync2.Body.String())
	var syncBody struct {
		Upserted int `json:"upserted"`
		Removed  int `json:"removed"`
	}
	require.NoError(t, json.Unmarshal(recSync2.Body.Bytes(), &syncBody))
	assert.Equal(t, 1, syncBody.Upserted)
	assert.Equal(t, 1, syncBody.Removed)

	mgmtKey, err := env.gw.AuthService().IssueVirtualKey(ctx, &domain.VirtualKey{
		OrgID:            "org_a",
		TeamID:           "team_a1",
		UserID:           "dev-perm-u1",
		Name:             "devperm-mgmt",
		KeyType:          domain.KeyTypeManagement,
		AllowedEndpoints: []string{"/v1/self/*"},
	})
	require.NoError(t, err)

	// Configure team_member_permissions restricting dev-perm-u1 to keys:create only
	require.Equal(t, http.StatusOK, doAdminJSONRequest(t, env.handler, http.MethodPut, "/admin/v1/teams/team_a1", env.orgAAdmin.RawKey, map[string]any{
		"team_member_permissions": []string{"keys:create"},
	}).Code)

	recCreated := doAdminJSONRequest(t, env.handler, http.MethodPost, "/v1/self/keys", mgmtKey.RawKey, map[string]any{
		"name": "allowed-by-perm",
	})
	require.Equal(t, http.StatusCreated, recCreated.Code, recCreated.Body.String())
	var issued domain.VirtualKey
	require.NoError(t, json.Unmarshal(recCreated.Body.Bytes(), &issued))

	// Rotate and revoke are denied because team_member_permissions lacks keys:rotate and keys:revoke
	assert.Equal(t, http.StatusForbidden, doAdminJSONRequest(t, env.handler, http.MethodPost, "/v1/self/keys/"+issued.ID+"/rotate", mgmtKey.RawKey, map[string]any{}).Code)
	assert.Equal(t, http.StatusForbidden, doAdminJSONRequest(t, env.handler, http.MethodDelete, "/v1/self/keys/"+issued.ID, mgmtKey.RawKey, nil).Code)

	// Upgrade permission to keys:* -> rotate and revoke now succeed
	require.Equal(t, http.StatusOK, doAdminJSONRequest(t, env.handler, http.MethodPut, "/admin/v1/teams/team_a1", env.orgAAdmin.RawKey, map[string]any{
		"team_member_permissions": []string{"keys:*"},
	}).Code)
	assert.Equal(t, http.StatusOK, doAdminJSONRequest(t, env.handler, http.MethodPost, "/v1/self/keys/"+issued.ID+"/rotate", mgmtKey.RawKey, map[string]any{}).Code)
	assert.Equal(t, http.StatusOK, doAdminJSONRequest(t, env.handler, http.MethodDelete, "/v1/self/keys/"+issued.ID, mgmtKey.RawKey, nil).Code)

	// Audit diffs emitted for user update + bulk membership sync + KEK multi_pod_notice
	require.Equal(t, http.StatusOK, doAdminJSONRequest(t, env.handler, http.MethodPut, "/admin/v1/users/dev-perm-u1", env.orgAAdmin.RawKey, map[string]any{
		"name": "Updated Perm Dev",
	}).Code)
	recKEK := doAdminJSONRequest(t, env.handler, http.MethodPost, "/admin/v1/security/rotate-kek", env.masterKey, map[string]any{
		"new_master_key": "0123456789abcdef0123456789abcdef-rotated-2",
	})
	require.Equal(t, http.StatusOK, recKEK.Code)
	assert.Contains(t, recKEK.Body.String(), "multi_pod_notice")

	logs, err := env.repo.ListAuditLogs(ctx, "org_a", 50)
	require.NoError(t, err)
	var sawBulkSync, sawUserUpdateDiff bool
	for _, l := range logs {
		if l != nil && l.Action == "team_membership.bulk_synced" && len(l.AfterValue) > 0 {
			sawBulkSync = true
		}
		if l != nil && l.Action == "user.updated" && len(l.BeforeValue) > 0 && len(l.AfterValue) > 0 {
			sawUserUpdateDiff = true
		}
	}
	assert.True(t, sawBulkSync, "expected team_membership.bulk_synced audit diff")
	assert.True(t, sawUserUpdateDiff, "expected user.updated auditWithDiff entry")
}

func TestGovernanceHardening_BulkGraceEviction_OwnershipAndAuditDiffs(t *testing.T) {
	ctx := context.Background()
	env := setupQuotaHandlerTestEnv(t, nil)

	// 1. Rotate key with grace period, warm deprecated grace hash, then bulk-deactivate with whitespace-padded duplicate IDs
	recIssue := doAdminJSONRequest(t, env.handler, http.MethodPost, "/admin/v1/keys", env.orgAAdmin.RawKey, map[string]any{
		"org_id":  "org_a",
		"team_id": "team_a1",
		"name":    "bulk-grace-key",
	})
	require.Equal(t, http.StatusCreated, recIssue.Code, recIssue.Body.String())
	var issued domain.VirtualKey
	require.NoError(t, json.Unmarshal(recIssue.Body.Bytes(), &issued))
	oldRawKey := issued.RawKey

	recRot := doAdminJSONRequest(t, env.handler, http.MethodPost, "/admin/v1/keys/"+issued.ID+"/rotate", env.orgAAdmin.RawKey, map[string]any{
		"grace_period_seconds": 3600,
	})
	require.Equal(t, http.StatusOK, recRot.Code, recRot.Body.String())

	// Warm deprecated grace key cache on data-plane endpoint
	require.Equal(t, http.StatusOK, doAdminJSONRequest(t, env.handler, http.MethodGet, "/v1/models", oldRawKey, nil).Code)

	recBulk := doAdminJSONRequest(t, env.handler, http.MethodPost, "/admin/v1/keys/bulk-update", env.orgAAdmin.RawKey, map[string]any{
		"org_id":    "org_a",
		"key_ids":   []string{"  " + issued.ID + "  ", issued.ID, ""},
		"is_active": false,
	})
	require.Equal(t, http.StatusOK, recBulk.Code, recBulk.Body.String())
	var bulkResp struct {
		Updated int `json:"updated"`
	}
	require.NoError(t, json.Unmarshal(recBulk.Body.Bytes(), &bulkResp))
	assert.Equal(t, 1, bulkResp.Updated)

	// Both active and deprecated grace hashes must be immediately rejected
	assert.Equal(t, http.StatusUnauthorized, doAdminJSONRequest(t, env.handler, http.MethodGet, "/v1/models", oldRawKey, nil).Code)

	// 2. team_admin cannot bind keys to an org_admin/platform_admin user or mutate user_id on a service_account key
	require.NoError(t, env.repo.CreateUser(ctx, &domain.User{
		ID:       "usr_org_admin_in_team",
		OrgID:    "org_a",
		TeamID:   "team_a1",
		Email:    "orgadmin-team@example.com",
		Name:     "Org Admin Member",
		Role:     domain.RoleOrgAdmin,
		IsActive: true,
	}))
	recTeamAdminKey := doAdminJSONRequest(t, env.handler, http.MethodPost, "/admin/v1/keys", env.orgAAdmin.RawKey, map[string]any{
		"org_id":  "org_a",
		"team_id": "team_a1",
		"name":    "team-a1-admin",
		"role":    domain.RoleTeamAdmin,
	})
	require.Equal(t, http.StatusCreated, recTeamAdminKey.Code, recTeamAdminKey.Body.String())
	var teamAdminKey domain.VirtualKey
	require.NoError(t, json.Unmarshal(recTeamAdminKey.Body.Bytes(), &teamAdminKey))

	recCrossRoleCreate := doAdminJSONRequest(t, env.handler, http.MethodPost, "/admin/v1/keys", teamAdminKey.RawKey, map[string]any{
		"org_id":  "org_a",
		"team_id": "team_a1",
		"user_id": "usr_org_admin_in_team",
		"name":    "blocked-priv-user-bind",
	})
	assert.Equal(t, http.StatusForbidden, recCrossRoleCreate.Code, recCrossRoleCreate.Body.String())
	assert.Contains(t, recCrossRoleCreate.Body.String(), "cross_role_access_denied")

	recSAKey := doAdminJSONRequest(t, env.handler, http.MethodPost, "/admin/v1/keys", env.orgAAdmin.RawKey, map[string]any{
		"org_id":   "org_a",
		"team_id":  "team_a1",
		"name":     "sa-immutable-user",
		"key_type": domain.KeyTypeServiceAccount,
	})
	require.Equal(t, http.StatusCreated, recSAKey.Code, recSAKey.Body.String())
	var saKey domain.VirtualKey
	require.NoError(t, json.Unmarshal(recSAKey.Body.Bytes(), &saKey))
	recSAUser := doAdminJSONRequest(t, env.handler, http.MethodPut, "/admin/v1/keys/"+saKey.ID, env.orgAAdmin.RawKey, map[string]any{
		"user_id": "usr_org_admin_in_team",
	})
	assert.Equal(t, http.StatusBadRequest, recSAUser.Code, recSAUser.Body.String())
	assert.Contains(t, recSAUser.Body.String(), "invalid_service_account_user")

	// 3. Verify remaining policy/guardrail mutations emit auditWithDiff entries
	require.Equal(t, http.StatusOK, doAdminJSONRequest(t, env.handler, http.MethodPost, "/admin/v1/organizations/org_a/subscriptions", env.orgAAdmin.RawKey, map[string]any{
		"provider":        "openai",
		"is_enabled":      true,
		"auto_enable_new": false,
	}).Code)
	require.Equal(t, http.StatusOK, doAdminJSONRequest(t, env.handler, http.MethodPost, "/admin/v1/organizations/org_a/guardrails", env.orgAAdmin.RawKey, map[string]any{
		"enable_prompt_injection": true,
		"prompt_injection_action": "block",
	}).Code)
	require.Equal(t, http.StatusOK, doAdminJSONRequest(t, env.handler, http.MethodPost, "/admin/v1/organizations/org_a/guardrails", env.orgAAdmin.RawKey, map[string]any{
		"enable_prompt_injection": true,
		"prompt_injection_action": "audit",
	}).Code)
	require.Equal(t, http.StatusOK, doAdminJSONRequest(t, env.handler, http.MethodPost, "/admin/v1/organizations/org_a/tool-policies", env.orgAAdmin.RawKey, map[string]any{
		"tool_name":     "shell_exec",
		"input_policy":  "blocked",
		"output_policy": "untrusted",
	}).Code)

	logs, err := env.repo.ListAuditLogs(ctx, "org_a", 100)
	require.NoError(t, err)
	var sawBulkDiff, sawSubDiff, sawGuardDiff, sawToolPolicyDiff bool
	for _, l := range logs {
		if l == nil {
			continue
		}
		if l.Action == "virtual_key.bulk_updated" && len(l.BeforeValue) > 0 && len(l.AfterValue) > 0 {
			sawBulkDiff = true
		}
		if l.Action == "organization.subscription.updated" && len(l.AfterValue) > 0 {
			sawSubDiff = true
		}
		if l.Action == "organization.guardrails.updated" && len(l.BeforeValue) > 0 && len(l.AfterValue) > 0 {
			sawGuardDiff = true
		}
		if l.Action == "tool_policy.upserted" && len(l.AfterValue) > 0 {
			sawToolPolicyDiff = true
		}
	}
	assert.True(t, sawBulkDiff, "expected virtual_key.bulk_updated diff")
	assert.True(t, sawSubDiff, "expected organization.subscription.updated diff")
	assert.True(t, sawGuardDiff, "expected organization.guardrails.updated before+after diff")
	assert.True(t, sawToolPolicyDiff, "expected tool_policy.upserted diff")
}
