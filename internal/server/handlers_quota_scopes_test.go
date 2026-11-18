package server_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func doInferenceJSONRequestWithHeaders(
	t *testing.T,
	handler http.Handler,
	path string,
	rawKey string,
	headers map[string]string,
	body any,
) *httptest.ResponseRecorder {
	t.Helper()
	b, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(string(b)))
	req.Header.Set("Content-Type", "application/json")
	if rawKey != "" {
		req.Header.Set("Authorization", "Bearer "+rawKey)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func TestQuotaScopesAdminCRUD_AndRBACMatrix(t *testing.T) {
	env := setupQuotaHandlerTestEnv(t, nil)

	// 1. Unauthenticated requests -> 401
	for _, p := range []string{"/admin/v1/end-users", "/admin/v1/tags", "/admin/v1/model-access-groups"} {
		rec := doAdminJSONRequest(t, env.handler, http.MethodGet, p, "", nil)
		assert.Equal(t, http.StatusUnauthorized, rec.Code, p)
	}

	// 2. team_admin blocked from org-scoped endpoints -> 403
	for _, tc := range []struct {
		method string
		path   string
		body   map[string]any
	}{
		{http.MethodGet, "/admin/v1/end-users", nil},
		{http.MethodPut, "/admin/v1/end-users", map[string]any{"end_user_id": "eu-1"}},
		{http.MethodGet, "/admin/v1/tags", nil},
		{http.MethodPut, "/admin/v1/tags", map[string]any{"tag": "env:prod"}},
		{http.MethodGet, "/admin/v1/model-access-groups", nil},
		{http.MethodPut, "/admin/v1/model-access-groups", map[string]any{"name": "tier-1"}},
	} {
		rec := doAdminJSONRequest(t, env.handler, tc.method, tc.path, env.teamA1Adm.RawKey, tc.body)
		assert.Equal(t, http.StatusForbidden, rec.Code, "%s %s", tc.method, tc.path)
	}

	// 3. org_viewer blocked from writes -> 403, allowed on reads -> 200
	for _, tc := range []struct {
		path string
		body map[string]any
	}{
		{"/admin/v1/end-users", map[string]any{"end_user_id": "eu-1"}},
		{"/admin/v1/tags", map[string]any{"tag": "env:prod"}},
		{"/admin/v1/model-access-groups", map[string]any{"name": "tier-1"}},
	} {
		recWrite := doAdminJSONRequest(t, env.handler, http.MethodPut, tc.path, env.orgAViewer.RawKey, tc.body)
		assert.Equal(t, http.StatusForbidden, recWrite.Code, "viewer write %s", tc.path)
		recRead := doAdminJSONRequest(t, env.handler, http.MethodGet, tc.path, env.orgAViewer.RawKey, nil)
		assert.Equal(t, http.StatusOK, recRead.Code, "viewer read %s", tc.path)
	}

	// 4. org_admin full CRUD on end-users, tags, model-access-groups + cross-org isolation
	recEU := doAdminJSONRequest(t, env.handler, http.MethodPost, "/admin/v1/end-users", env.orgAAdmin.RawKey, map[string]any{
		"end_user_id":       "customer-42",
		"alias":             "Customer 42",
		"max_budget_micros": 500_000,
		"rpm_limit":         20,
		"allowed_models":    []string{"gpt-4.1"},
	})
	require.Equal(t, http.StatusCreated, recEU.Code, recEU.Body.String())
	var createdEU domain.EndUser
	require.NoError(t, json.Unmarshal(recEU.Body.Bytes(), &createdEU))
	assert.Equal(t, "org_a", createdEU.OrgID)
	assert.Equal(t, "customer-42", createdEU.EndUserID)

	// Cross-org org_b admin cannot read or delete org_a end user
	recCrossEU := doAdminJSONRequest(t, env.handler, http.MethodGet, "/admin/v1/end-users/"+createdEU.ID, env.orgBAdmin.RawKey, nil)
	assert.Equal(t, http.StatusForbidden, recCrossEU.Code)
	recCrossDelEU := doAdminJSONRequest(t, env.handler, http.MethodDelete, "/admin/v1/end-users/"+createdEU.ID, env.orgBAdmin.RawKey, nil)
	assert.Equal(t, http.StatusForbidden, recCrossDelEU.Code)

	// Tag CRUD
	recTag := doAdminJSONRequest(t, env.handler, http.MethodPut, "/admin/v1/tags", env.orgAAdmin.RawKey, map[string]any{
		"tag":               "feature:search",
		"description":       "Search feature workload",
		"max_budget_micros": 250_000,
		"rpm_limit":         15,
	})
	require.Equal(t, http.StatusOK, recTag.Code, recTag.Body.String())
	var createdTag domain.Tag
	require.NoError(t, json.Unmarshal(recTag.Body.Bytes(), &createdTag))
	assert.Equal(t, "org_a", createdTag.OrgID)
	assert.Equal(t, "feature:search", createdTag.Tag)

	recCrossTag := doAdminJSONRequest(t, env.handler, http.MethodDelete, "/admin/v1/tags/"+createdTag.ID, env.orgBAdmin.RawKey, nil)
	assert.Equal(t, http.StatusForbidden, recCrossTag.Code)

	// ModelAccessGroup CRUD + members
	recMAG := doAdminJSONRequest(t, env.handler, http.MethodPost, "/admin/v1/model-access-groups", env.orgAAdmin.RawKey, map[string]any{
		"name":              "frontier-pool",
		"description":       "Shared frontier pool",
		"max_budget_micros": 1_000_000,
		"rpm_limit":         30,
		"members": []map[string]any{
			{"member_type": "model", "member_id": "gpt-4.1"},
		},
	})
	require.Equal(t, http.StatusCreated, recMAG.Code, recMAG.Body.String())
	var createdMAG domain.ModelAccessGroup
	require.NoError(t, json.Unmarshal(recMAG.Body.Bytes(), &createdMAG))
	require.Len(t, createdMAG.Members, 1)

	recAddMem := doAdminJSONRequest(t, env.handler, http.MethodPost, "/admin/v1/model-access-groups/"+createdMAG.ID+"/members", env.orgAAdmin.RawKey, map[string]any{
		"member_type": "team",
		"member_id":   "team_a1",
	})
	require.Equal(t, http.StatusCreated, recAddMem.Code, recAddMem.Body.String())
	var addedMem domain.ModelAccessGroupMember
	require.NoError(t, json.Unmarshal(recAddMem.Body.Bytes(), &addedMem))

	recListMem := doAdminJSONRequest(t, env.handler, http.MethodGet, "/admin/v1/model-access-groups/"+createdMAG.ID+"/members", env.orgAAdmin.RawKey, nil)
	require.Equal(t, http.StatusOK, recListMem.Code)

	recDelMem := doAdminJSONRequest(t, env.handler, http.MethodDelete, "/admin/v1/model-access-groups/"+createdMAG.ID+"/members/"+addedMem.ID, env.orgAAdmin.RawKey, nil)
	require.Equal(t, http.StatusOK, recDelMem.Code)

	// Cleanup delete
	assert.Equal(t, http.StatusOK, doAdminJSONRequest(t, env.handler, http.MethodDelete, "/admin/v1/end-users/"+createdEU.ID, env.orgAAdmin.RawKey, nil).Code)
	assert.Equal(t, http.StatusOK, doAdminJSONRequest(t, env.handler, http.MethodDelete, "/admin/v1/tags/"+createdTag.ID, env.orgAAdmin.RawKey, nil).Code)
	assert.Equal(t, http.StatusOK, doAdminJSONRequest(t, env.handler, http.MethodDelete, "/admin/v1/model-access-groups/"+createdMAG.ID, env.orgAAdmin.RawKey, nil).Code)
}

func TestEndUserTagModelAccessGroupAndAgentSessionRuntimeEnforcement(t *testing.T) {
	ctx := context.Background()
	upstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"id":      "chatcmpl-quota-scopes",
			"object":  "chat.completion",
			"created": time.Now().Unix(),
			"model":   "gpt-4.1",
			"choices": []map[string]any{
				{
					"index": 0,
					"message": map[string]any{
						"role":    "assistant",
						"content": "ok",
					},
					"finish_reason": "stop",
				},
			},
			"usage": map[string]any{
				"prompt_tokens":     100,
				"completion_tokens": 50,
				"total_tokens":      150,
			},
		})
	})

	env := setupQuotaHandlerTestEnv(t, upstream)

	vkTeamA1, err := env.gw.AuthService().IssueVirtualKey(ctx, &domain.VirtualKey{
		OrgID:           "org_a",
		TeamID:          "team_a1",
		UserID:          "usr_a1_dev",
		Name:            "dev-key-a1",
		Role:            domain.RoleDeveloper,
		Tags:            []string{"key-tag:gold"},
		MaxBudgetMicros: 5_000_000,
	})
	require.NoError(t, err)

	// 1. EndUser auto-creation on inference + RPM enforcement + blocked enforcement
	recAuto := doInferenceJSONRequestWithHeaders(t, env.handler, "/v1/chat/completions", vkTeamA1.RawKey, nil, map[string]any{
		"model":    "gpt-4.1",
		"user":     "end-user-auto-1",
		"messages": []map[string]any{{"role": "user", "content": "hi"}},
	})
	require.Equal(t, http.StatusOK, recAuto.Code, recAuto.Body.String())

	autoEU, err := env.repo.GetEndUserByExternalID(ctx, "org_a", "end-user-auto-1")
	require.NoError(t, err)
	assert.Equal(t, "end-user-auto-1", autoEU.EndUserID)
	// Same external end_user_id in org_b must not exist yet (strictly org-isolated).
	_, err = env.repo.GetEndUserByExternalID(ctx, "org_b", "end-user-auto-1")
	assert.ErrorIs(t, err, storage.ErrNotFound)

	// Configure RPMLimit=1 on end-user-auto-1 -> 1st call under limit succeeds, 2nd call hits 429 end_user_rpm_exceeded.
	autoEU.RPMLimit = 1
	require.NoError(t, env.repo.UpsertEndUser(ctx, autoEU))
	recEURPM1 := doInferenceJSONRequestWithHeaders(t, env.handler, "/v1/chat/completions", vkTeamA1.RawKey, nil, map[string]any{
		"model":    "gpt-4.1",
		"user":     "end-user-auto-1",
		"messages": []map[string]any{{"role": "user", "content": "first call under rpm=1"}},
	})
	require.Equal(t, http.StatusOK, recEURPM1.Code, recEURPM1.Body.String())

	recEURPM2 := doInferenceJSONRequestWithHeaders(t, env.handler, "/v1/chat/completions", vkTeamA1.RawKey, nil, map[string]any{
		"model":    "gpt-4.1",
		"user":     "end-user-auto-1",
		"messages": []map[string]any{{"role": "user", "content": "second call under rpm=1"}},
	})
	assert.Equal(t, http.StatusTooManyRequests, recEURPM2.Code, recEURPM2.Body.String())
	assert.Contains(t, recEURPM2.Body.String(), "end_user_rpm_exceeded")

	// Blocked end-user -> 403 end_user_blocked
	require.NoError(t, env.repo.UpsertEndUser(ctx, &domain.EndUser{
		OrgID:     "org_a",
		EndUserID: "blocked-eu",
		IsActive:  false,
	}))
	recBlocked := doInferenceJSONRequestWithHeaders(t, env.handler, "/v1/chat/completions", vkTeamA1.RawKey, nil, map[string]any{
		"model":    "gpt-4.1",
		"user":     "blocked-eu",
		"messages": []map[string]any{{"role": "user", "content": "blocked"}},
	})
	assert.Equal(t, http.StatusForbidden, recBlocked.Code)
	assert.Contains(t, recBlocked.Body.String(), "end_user_blocked")

	// 2. Tag RPM enforcement via X-Gateway-Tags header and virtual key tags
	require.NoError(t, env.repo.UpsertTag(ctx, &domain.Tag{
		OrgID:    "org_a",
		Tag:      "campaign:launch",
		RPMLimit: 1,
		IsActive: true,
	}))
	recTag1 := doInferenceJSONRequestWithHeaders(t, env.handler, "/v1/chat/completions", vkTeamA1.RawKey, map[string]string{
		"X-Gateway-Tags": "campaign:launch",
	}, map[string]any{
		"model":    "gpt-4.1",
		"messages": []map[string]any{{"role": "user", "content": "tag 1"}},
	})
	require.Equal(t, http.StatusOK, recTag1.Code, recTag1.Body.String())

	recTag2 := doInferenceJSONRequestWithHeaders(t, env.handler, "/v1/chat/completions", vkTeamA1.RawKey, map[string]string{
		"X-Gateway-Tags": "campaign:launch",
	}, map[string]any{
		"model":    "gpt-4.1",
		"messages": []map[string]any{{"role": "user", "content": "tag 2"}},
	})
	assert.Equal(t, http.StatusTooManyRequests, recTag2.Code, recTag2.Body.String())
	assert.Contains(t, recTag2.Body.String(), "tag_rpm_exceeded")

	// 3. ModelAccessGroup shared RPM pool & principal membership gating
	require.NoError(t, env.repo.CreateTeam(ctx, &domain.Team{
		ID:       "team_a2",
		OrgID:    "org_a",
		Name:     "Team A2 Non-Member",
		IsActive: true,
	}))
	vkTeamA2, err := env.gw.AuthService().IssueVirtualKey(ctx, &domain.VirtualKey{
		OrgID:  "org_a",
		TeamID: "team_a2",
		Name:   "dev-key-a2",
		Role:   domain.RoleDeveloper,
	})
	require.NoError(t, err)

	mag := &domain.ModelAccessGroup{
		ID:       "mag_shared_mini",
		OrgID:    "org_a",
		Name:     "shared-mini-pool",
		RPMLimit: 1,
		IsActive: true,
	}
	require.NoError(t, env.repo.UpsertModelAccessGroup(ctx, mag))
	require.NoError(t, env.repo.AddModelAccessGroupMember(ctx, &domain.ModelAccessGroupMember{
		OrgID:      "org_a",
		GroupID:    mag.ID,
		MemberType: domain.ModelAccessGroupMemberModel,
		MemberID:   "gpt-4.1-mini",
	}))
	require.NoError(t, env.repo.AddModelAccessGroupMember(ctx, &domain.ModelAccessGroupMember{
		OrgID:      "org_a",
		GroupID:    mag.ID,
		MemberType: domain.ModelAccessGroupMemberTeam,
		MemberID:   "team_a1",
	}))

	// Non-member team_a2 is denied access to gpt-4.1-mini -> 403 model_access_group_denied
	recMAGDenied := doInferenceJSONRequestWithHeaders(t, env.handler, "/v1/chat/completions", vkTeamA2.RawKey, nil, map[string]any{
		"model":    "gpt-4.1-mini",
		"messages": []map[string]any{{"role": "user", "content": "non-member"}},
	})
	assert.Equal(t, http.StatusForbidden, recMAGDenied.Code, recMAGDenied.Body.String())
	assert.Contains(t, recMAGDenied.Body.String(), "model_access_group_denied")

	// Member team_a1 succeeds on 1st call, hits shared group RPM=1 on 2nd call -> 429 model_access_group_rpm_exceeded
	recMAG1 := doInferenceJSONRequestWithHeaders(t, env.handler, "/v1/chat/completions", vkTeamA1.RawKey, nil, map[string]any{
		"model":    "gpt-4.1-mini",
		"messages": []map[string]any{{"role": "user", "content": "member 1"}},
	})
	require.Equal(t, http.StatusOK, recMAG1.Code, recMAG1.Body.String())

	recMAG2 := doInferenceJSONRequestWithHeaders(t, env.handler, "/v1/chat/completions", vkTeamA1.RawKey, nil, map[string]any{
		"model":    "gpt-4.1-mini",
		"messages": []map[string]any{{"role": "user", "content": "member 2"}},
	})
	assert.Equal(t, http.StatusTooManyRequests, recMAG2.Code, recMAG2.Body.String())
	assert.Contains(t, recMAG2.Body.String(), "model_access_group_rpm_exceeded")

	// 4. AgentSession (X-Gateway-Session-Id) max_iterations & max_budget_per_session_micros enforcement
	recPutKey := doAdminJSONRequest(t, env.handler, http.MethodPut, "/admin/v1/keys/"+vkTeamA1.ID, env.orgAAdmin.RawKey, map[string]any{
		"max_iterations": 2,
	})
	require.Equal(t, http.StatusOK, recPutKey.Code, recPutKey.Body.String())

	for turn := 1; turn <= 2; turn++ {
		recSess := doInferenceJSONRequestWithHeaders(t, env.handler, "/v1/chat/completions", vkTeamA1.RawKey, map[string]string{
			"X-Gateway-Session-Id": "agent-loop-sess-1",
		}, map[string]any{
			"model":    "gpt-4.1",
			"messages": []map[string]any{{"role": "user", "content": "loop turn"}},
		})
		require.Equal(t, http.StatusOK, recSess.Code, "turn %d: %s", turn, recSess.Body.String())
	}
	// Turn 3 with same session_id fails closed -> 429 agent_session_iterations_exceeded
	recSess3 := doInferenceJSONRequestWithHeaders(t, env.handler, "/v1/chat/completions", vkTeamA1.RawKey, map[string]string{
		"X-Gateway-Session-Id": "agent-loop-sess-1",
	}, map[string]any{
		"model":    "gpt-4.1",
		"messages": []map[string]any{{"role": "user", "content": "loop turn 3"}},
	})
	assert.Equal(t, http.StatusTooManyRequests, recSess3.Code, recSess3.Body.String())
	assert.Contains(t, recSess3.Body.String(), "agent_session_iterations_exceeded")

	// Different session_id proceeds unaffected
	recOtherSess := doInferenceJSONRequestWithHeaders(t, env.handler, "/v1/chat/completions", vkTeamA1.RawKey, map[string]string{
		"X-Gateway-Session-Id": "agent-loop-sess-2",
	}, map[string]any{
		"model":    "gpt-4.1",
		"messages": []map[string]any{{"role": "user", "content": "fresh session"}},
	})
	assert.Equal(t, http.StatusOK, recOtherSess.Code, recOtherSess.Body.String())

	// Session budget cap via QuotaPolicy (agent_session wildcard *)
	recSessBudgetPol := doAdminJSONRequest(t, env.handler, http.MethodPut, "/admin/v1/quotas", env.orgAAdmin.RawKey, map[string]any{
		"org_id":                        "org_a",
		"scope_type":                    "agent_session",
		"scope_id":                      "*",
		"model_pattern":                 "*",
		"max_budget_per_session_micros": 1, // 1 micro-dollar ceiling
	})
	require.Equal(t, http.StatusOK, recSessBudgetPol.Code, recSessBudgetPol.Body.String())

	recSessBudgetHit := doInferenceJSONRequestWithHeaders(t, env.handler, "/v1/chat/completions", vkTeamA1.RawKey, map[string]string{
		"X-Gateway-Session-Id": "agent-budget-sess-1",
	}, map[string]any{
		"model":      "gpt-4.1",
		"max_tokens": 500,
		"messages":   []map[string]any{{"role": "user", "content": "exceed session budget"}},
	})
	assert.Equal(t, http.StatusTooManyRequests, recSessBudgetHit.Code, recSessBudgetHit.Body.String())
	assert.Contains(t, recSessBudgetHit.Body.String(), "agent_session_budget_exceeded")
}
