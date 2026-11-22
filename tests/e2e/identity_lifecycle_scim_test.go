package e2e_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/server"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

func TestE2E_Identity_ScheduledRotationStagedDeliveryGraceAndPresets(t *testing.T) {
	sink := newMockSecurityAndWebhookSink(t, "rot-delivery-bearer-token")
	upstream := newMockDeterministicLLMUpstream(t)
	cluster := setupConfigurableDualNodeCluster(t, nil)

	ctx := context.Background()
	now := time.Date(2026, 11, 19, 10, 0, 0, 0, time.UTC)
	cluster.setClock(now)

	// Negative delivery config checks on server.New: plain HTTP, credentials, query, missing token rejected.
	for _, tc := range []struct {
		name  string
		url   string
		token string
	}{
		{"plainHTTP", "http://vault.internal.example/hooks/rotate", "tok"},
		{"embeddedCreds", "https://user:pass@vault.internal.example/hooks/rotate", "tok"},
		{"queryString", "https://vault.internal.example/hooks/rotate?x=1", "tok"},
		{"missingToken", "https://vault.internal.example/hooks/rotate", ""},
	} {
		badCfg := config.Default()
		badCfg.Server.Environment = "test"
		badCfg.Discovery.Enabled = false
		badCfg.Auth.KeyRotationDeliveryURL = tc.url
		badCfg.Auth.KeyRotationDeliveryToken = tc.token
		if _, err := server.New(badCfg, storage.NewMemoryRepository(), nil, nil); err == nil {
			t.Fatalf("expected server.New rejection for %s delivery config", tc.name)
		}
	}

	org := cluster.createOrg("Rotation Org")
	modelAlias := cluster.uniqueID("rot-chat")
	cluster.seedOpenAIModel(ctx, org.ID, modelAlias, upstream.OpenAIBaseURL(), 2_000_000, 8_000_000, 0, 0)
	chatReq := map[string]any{"model": modelAlias, "messages": []map[string]string{{"role": "user", "content": "rot"}}}

	// 1. Key-type presets: llm_api (Data Plane only), management (Control Plane only), read_only (GET Control Plane only).
	llmKey := cluster.issueKey(map[string]any{
		"org_id": org.ID, "name": cluster.uniqueID("preset-llm"), "key_type": "llm_api",
	})
	mgmtKey := cluster.issueKey(map[string]any{
		"org_id": org.ID, "name": cluster.uniqueID("preset-mgmt"), "key_type": "management", "role": "org_admin",
	})
	roKey := cluster.issueKey(map[string]any{
		"org_id": org.ID, "name": cluster.uniqueID("preset-ro"), "key_type": "read_only", "role": "org_admin",
	})

	if r, b := cluster.c1.doJSON(http.MethodPost, "/v1/chat/completions", map[string]string{"Authorization": "Bearer " + llmKey.RawKey}, chatReq, nil); r.StatusCode != http.StatusOK {
		t.Fatalf("llm_api Data Plane expected 200, got %d: %s", r.StatusCode, string(b))
	}
	if r, _ := cluster.c1.doJSON(http.MethodGet, "/admin/v1/keys?org_id="+org.ID, map[string]string{"Authorization": "Bearer " + llmKey.RawKey}, nil, nil); r.StatusCode != http.StatusForbidden {
		t.Fatalf("llm_api Control Plane expected 403, got %d", r.StatusCode)
	}
	if r, _ := cluster.c1.doJSON(http.MethodPost, "/v1/chat/completions", map[string]string{"Authorization": "Bearer " + mgmtKey.RawKey}, chatReq, nil); r.StatusCode != http.StatusForbidden {
		t.Fatalf("management key Data Plane expected 403, got %d", r.StatusCode)
	}
	if r, _ := cluster.c1.doJSON(http.MethodGet, "/admin/v1/keys?org_id="+org.ID, map[string]string{"Authorization": "Bearer " + mgmtKey.RawKey}, nil, nil); r.StatusCode != http.StatusOK {
		t.Fatalf("management key Control Plane expected 200, got %d", r.StatusCode)
	}
	if r, _ := cluster.c1.doJSON(http.MethodGet, "/admin/v1/keys?org_id="+org.ID, map[string]string{"Authorization": "Bearer " + roKey.RawKey}, nil, nil); r.StatusCode != http.StatusOK {
		t.Fatalf("read_only key GET expected 200, got %d", r.StatusCode)
	}
	if r, _ := cluster.c1.doJSON(http.MethodPost, "/admin/v1/teams", map[string]string{"Authorization": "Bearer " + roKey.RawKey}, map[string]any{"org_id": org.ID, "name": "ro-blocked"}, nil); r.StatusCode != http.StatusForbidden {
		t.Fatalf("read_only key POST expected 403, got %d", r.StatusCode)
	}

	// 2. Manual rotation + grace period + deprecation headers + cross-node revocation on expiry.
	manualOldRaw := llmKey.RawKey
	var manualRotated domain.VirtualKey
	resp, raw := cluster.c1.doJSON(http.MethodPost, "/admin/v1/keys/"+llmKey.ID+"/rotate", cluster.adminHdrs, map[string]any{
		"org_id":               org.ID,
		"grace_period_seconds": 300,
	}, &manualRotated)
	if resp.StatusCode != http.StatusOK || manualRotated.RawKey == "" || manualRotated.RawKey == manualOldRaw {
		t.Fatalf("manual rotate failed (%d): %s", resp.StatusCode, string(raw))
	}

	// During grace window: both old (emits X-Gateway-Key-Deprecated: true) and new work across node1 & node2.
	rOld, bOld := cluster.c2.doJSON(http.MethodPost, "/v1/chat/completions", map[string]string{"Authorization": "Bearer " + manualOldRaw}, chatReq, nil)
	if rOld.StatusCode != http.StatusOK || rOld.Header.Get(auth.HeaderKeyDeprecated) != "true" {
		t.Fatalf("expected deprecated old key 200 with X-Gateway-Key-Deprecated=true on node2, got %d hdr=%q body=%s", rOld.StatusCode, rOld.Header.Get(auth.HeaderKeyDeprecated), string(bOld))
	}
	if rNew, bNew := cluster.c2.doJSON(http.MethodPost, "/v1/chat/completions", map[string]string{"Authorization": "Bearer " + manualRotated.RawKey}, chatReq, nil); rNew.StatusCode != http.StatusOK {
		t.Fatalf("expected rotated new key 200 on node2, got %d: %s", rNew.StatusCode, string(bNew))
	}

	// Advance clock past 300s grace -> old key fails immediately while new key keeps succeeding.
	now = now.Add(301 * time.Second)
	cluster.setClock(now)
	if rOldExp, _ := cluster.c2.doJSON(http.MethodPost, "/v1/chat/completions", map[string]string{"Authorization": "Bearer " + manualOldRaw}, chatReq, nil); rOldExp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected expired deprecated key 401 on node2, got %d", rOldExp.StatusCode)
	}
	if rNew, _ := cluster.c2.doJSON(http.MethodPost, "/v1/chat/completions", map[string]string{"Authorization": "Bearer " + manualRotated.RawKey}, chatReq, nil); rNew.StatusCode != http.StatusOK {
		t.Fatalf("expected rotated key still 200 after old grace expired, got %d", rNew.StatusCode)
	}

	// 3. Scheduled auto-rotation: due key untouched without delivery channel; staged replacement
	//    encrypted + reused identically across HTTPS delivery retries; promoted only on 2xx ACK.
	schedKey := cluster.issueKey(map[string]any{
		"org_id":                org.ID,
		"name":                  cluster.uniqueID("sched-key"),
		"key_type":              "llm_api",
		"rotation_interval_sec": 600,
	})
	schedOrigRaw := schedKey.RawKey
	now = now.Add(605 * time.Second)
	cluster.setClock(now)

	// Without delivery configured, RunOnce leaves scheduled key active.
	noDelMgr := auth.NewKeyRotationManager(cluster.node1.AuthService(), cluster.pgRepo, cluster.redisFabric, auth.KeyRotationConfig{
		GracePeriod: 5 * time.Minute,
		Now:         func() time.Time { return now },
	})
	resNoDel, err := noDelMgr.RunOnce(ctx)
	if err != nil || resNoDel.RotatedKeys != 0 {
		t.Fatalf("expected 0 rotations without delivery channel, got res=%+v err=%v", resNoDel, err)
	}

	// Configure TLS delivery webhook to fail twice (503) before ACKing (200).
	sink.SetRotationFailuresRemaining(2)
	tlsMgr := auth.NewKeyRotationManager(cluster.node1.AuthService(), cluster.pgRepo, cluster.redisFabric, auth.KeyRotationConfig{
		Deliver:     sink.HTTPSRotationDeliverFunc(),
		GracePeriod: 5 * time.Minute,
		Now:         func() time.Time { return now },
	})

	// Retry 1 & Retry 2 fail with 503 -> old key stays active, same staged replacement delivered both times.
	for attempt := 1; attempt <= 2; attempt++ {
		if _, err := tlsMgr.RunOnce(ctx); err != nil {
			t.Fatalf("tlsMgr.RunOnce attempt %d: %v", attempt, err)
		}
		rStill, _ := cluster.c2.doJSON(http.MethodPost, "/v1/chat/completions", map[string]string{"Authorization": "Bearer " + schedOrigRaw}, chatReq, nil)
		if rStill.StatusCode != http.StatusOK {
			t.Fatalf("attempt %d: scheduled key must remain active when delivery fails, got %d", attempt, rStill.StatusCode)
		}
		if rStill.Header.Get(auth.HeaderKeyDeprecated) != "" {
			t.Fatalf("attempt %d: old key must not enter deprecation grace before ACK", attempt)
		}
	}

	deliveriesBeforeACK := sink.RotationDeliveries()
	if len(deliveriesBeforeACK) < 2 {
		t.Fatalf("expected at least 2 failed HTTPS delivery attempts, got %d", len(deliveriesBeforeACK))
	}
	stagedSecret := deliveriesBeforeACK[0].RawKey
	if stagedSecret == "" || stagedSecret != deliveriesBeforeACK[1].RawKey {
		t.Fatalf("expected identical staged secret reused across retries: [0]=%q [1]=%q", deliveriesBeforeACK[0].RawKey, deliveriesBeforeACK[1].RawKey)
	}
	var dbStagedHash, dbStagedCipher string
	if err := cluster.pool.QueryRow(ctx, `SELECT COALESCE(staged_key_hash,''), COALESCE(staged_encrypted_raw_key,'') FROM virtual_keys WHERE id = $1`, schedKey.ID).Scan(&dbStagedHash, &dbStagedCipher); err != nil {
		t.Fatalf("query staged columns: %v", err)
	}
	if dbStagedHash == "" || dbStagedCipher == "" || strings.Contains(dbStagedCipher, stagedSecret) {
		t.Fatalf("expected encrypted staged secret in Postgres (hash=%q cipher_len=%d)", dbStagedHash, len(dbStagedCipher))
	}

	// Attempt 3 succeeds (200 ACK) -> promotes staged key, starts grace for old key across both nodes!
	resACK, err := tlsMgr.RunOnce(ctx)
	if err != nil || resACK.RotatedKeys != 1 {
		t.Fatalf("expected 1 promoted key on 2xx ACK, got res=%+v err=%v", resACK, err)
	}
	if rProm, bProm := cluster.c2.doJSON(http.MethodPost, "/v1/chat/completions", map[string]string{"Authorization": "Bearer " + stagedSecret}, chatReq, nil); rProm.StatusCode != http.StatusOK {
		t.Fatalf("promoted staged secret failed on node2 (%d): %s", rProm.StatusCode, string(bProm))
	}
	if rOldGrace, _ := cluster.c2.doJSON(http.MethodPost, "/v1/chat/completions", map[string]string{"Authorization": "Bearer " + schedOrigRaw}, chatReq, nil); rOldGrace.StatusCode != http.StatusOK || rOldGrace.Header.Get(auth.HeaderKeyDeprecated) != "true" {
		t.Fatalf("expected old scheduled key in grace with deprecation header on node2, got %d", rOldGrace.StatusCode)
	}

	now = now.Add(6 * time.Minute)
	cluster.setClock(now)
	if rOldDead, _ := cluster.c1.doJSON(http.MethodPost, "/v1/chat/completions", map[string]string{"Authorization": "Bearer " + schedOrigRaw}, chatReq, nil); rOldDead.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected old scheduled key 401 after grace expired, got %d", rOldDead.StatusCode)
	}
}

func TestE2E_Identity_TeamAdminRBACAndDynamicAccessGroupRules(t *testing.T) {
	idp := newMockEnterpriseIdentityProvider(t)
	upstream := newMockDeterministicLLMUpstream(t)
	cluster := setupConfigurableDualNodeCluster(t, func(cfg *config.Config) {
		cfg.Auth.EnableDataPlaneJWT = true
		cfg.Auth.OIDCIssuers = []config.OIDCIssuerConfig{
			{
				Issuer:       idp.IssuerA(),
				Audience:     "goroute-rbac",
				DiscoveryURL: idp.IssuerA() + "/.well-known/openid-configuration",
				Algorithms:   []string{"RS256"},
				AutoRegister: true,
				DefaultRole:  "developer",
			},
		}
	})

	ctx := context.Background()
	org := cluster.createOrg("RBAC & Rules Org")
	modelBase := cluster.uniqueID("rbac-base")
	modelDyn := cluster.uniqueID("rbac-dyn")
	cluster.seedOpenAIModel(ctx, org.ID, modelBase, upstream.OpenAIBaseURL(), 2_000_000, 8_000_000, 0, 0)
	cluster.seedOpenAIModel(ctx, org.ID, modelDyn, upstream.OpenAIBaseURL(), 2_000_000, 8_000_000, 0, 0)

	var teamA, teamB domain.Team
	cluster.c1.doJSON(http.MethodPost, "/admin/v1/teams", cluster.adminHdrs, map[string]any{
		"org_id": org.ID, "name": cluster.uniqueID("team-a"), "allowed_models": []string{modelBase},
	}, &teamA)
	cluster.c1.doJSON(http.MethodPost, "/admin/v1/teams", cluster.adminHdrs, map[string]any{
		"org_id": org.ID, "name": cluster.uniqueID("team-b"), "allowed_models": []string{modelBase},
	}, &teamB)

	taKey := cluster.issueKey(map[string]any{
		"org_id": org.ID, "team_id": teamA.ID, "name": cluster.uniqueID("ta-key"), "role": "team_admin",
	})
	taHdrs := map[string]string{"Authorization": "Bearer " + taKey.RawKey}

	// Team A admin manages Team A keys cleanly, but receives 403 on Team B and org-wide credentials.
	if r, b := cluster.c1.doJSON(http.MethodPost, "/admin/v1/keys", taHdrs, map[string]any{
		"org_id": org.ID, "team_id": teamA.ID, "name": cluster.uniqueID("team-a-child"), "key_type": "llm_api",
	}, nil); r.StatusCode != http.StatusCreated {
		t.Fatalf("team_admin create Team A key expected 201, got %d: %s", r.StatusCode, string(b))
	}
	if r, _ := cluster.c1.doJSON(http.MethodPost, "/admin/v1/keys", taHdrs, map[string]any{
		"org_id": org.ID, "team_id": teamB.ID, "name": cluster.uniqueID("team-b-x"), "key_type": "llm_api",
	}, nil); r.StatusCode != http.StatusForbidden {
		t.Fatalf("team_admin create Team B key expected 403, got %d", r.StatusCode)
	}
	if r, _ := cluster.c2.doJSON(http.MethodPost, "/admin/v1/credentials", taHdrs, map[string]any{
		"org_id": org.ID, "provider": "openai", "name": "blocked-cred", "api_key": "sk-x",
	}, nil); r.StatusCode != http.StatusForbidden {
		t.Fatalf("team_admin create org credential expected 403, got %d", r.StatusCode)
	}

	// Dynamic access group rule grants modelDyn based on JWT department=ml-research, revoked upon delete.
	var ruleCreated domain.AccessGroupRule
	resp, raw := cluster.c1.doJSON(http.MethodPost, "/admin/v1/access-group-rules", cluster.adminHdrs, map[string]any{
		"org_id":         org.ID,
		"name":           cluster.uniqueID("ml-rule"),
		"attribute":      "jwt_claims.department",
		"operator":       "equals",
		"value":          "ml-research",
		"allowed_models": []string{modelDyn},
		"priority":       10,
	}, &ruleCreated)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create access group rule (%d): %s", resp.StatusCode, string(raw))
	}

	// Create a team-scoped key mapped from a JWT claim so dynamic rule augments its restricted team/key allowlist.
	exp := time.Now().UTC().Add(10 * time.Minute).Unix()
	mlUserTok := idp.SignJWT("RS256", "kid-a-1", "JWT", map[string]any{
		"iss": idp.IssuerA(), "sub": "dyn-usr-" + cluster.runTag, "aud": "goroute-rbac",
		"org_id": org.ID, "team_ids": []string{teamA.ID}, "department": "ml-research",
		"email": "dyn-" + cluster.runTag + "@rbac.test", "exp": exp,
	})
	dynReq := map[string]any{"model": modelDyn, "messages": []map[string]string{{"role": "user", "content": "dyn"}}}
	if r, b := cluster.c2.doJSON(http.MethodPost, "/v1/chat/completions", map[string]string{"Authorization": "Bearer " + mlUserTok}, dynReq, nil); r.StatusCode != http.StatusOK {
		t.Fatalf("dynamic access rule grant on node2 expected 200, got %d: %s", r.StatusCode, string(b))
	}

	// Delete rule -> revoke across nodes.
	if r, b := cluster.c1.doJSON(http.MethodDelete, "/admin/v1/access-group-rules/"+ruleCreated.ID, cluster.adminHdrs, nil, nil); r.StatusCode != http.StatusOK {
		t.Fatalf("delete access group rule (%d): %s", r.StatusCode, string(b))
	}
	cluster.node1.RBAC().InvalidateAccessGroupRules(ctx, org.ID)
	cluster.node2.RBAC().InvalidateAccessGroupRules(ctx, org.ID)
	if r, _ := cluster.c2.doJSON(http.MethodPost, "/v1/chat/completions", map[string]string{"Authorization": "Bearer " + mlUserTok}, dynReq, nil); r.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 after access group rule deleted, got %d", r.StatusCode)
	}
}

func TestE2E_Identity_TeamMembershipsProjectsAndAllowlistPrecedence(t *testing.T) {
	upstream := newMockDeterministicLLMUpstream(t)
	cluster := setupConfigurableDualNodeCluster(t, nil)

	ctx := context.Background()
	org := cluster.createOrg("Projects & Memberships Org")
	modelMAG := cluster.uniqueID("proj-mag")
	modelDeniedByProject := cluster.uniqueID("proj-denied")
	// 10,000 micros/1M * 5_000_000? Let's make 1,000 prompt + 500 completion tokens cost cleanly:
	// Input 10_000_000 micros/1M * 1000 = 10,000 micros; Output 20_000_000 * 500 = 10,000 -> total 20,000 micros/call.
	upstream.SetUsage(1000, 500)
	cluster.seedOpenAIModel(ctx, org.ID, modelMAG, upstream.OpenAIBaseURL(), 10_000_000, 20_000_000, 0, 0)
	cluster.seedOpenAIModel(ctx, org.ID, modelDeniedByProject, upstream.OpenAIBaseURL(), 10_000_000, 20_000_000, 0, 0)

	var team domain.Team
	cluster.c1.doJSON(http.MethodPost, "/admin/v1/teams", cluster.adminHdrs, map[string]any{
		"org_id": org.ID, "name": cluster.uniqueID("proj-team"), "max_budget_micros": 1_000_000,
	}, &team)

	var usr domain.User
	resp, raw := cluster.c1.doJSON(http.MethodPost, "/admin/v1/users", cluster.adminHdrs, map[string]any{
		"org_id": org.ID, "team_id": team.ID, "email": "member-" + cluster.runTag + "@corp.test", "name": "Mem User", "role": "developer",
	}, &usr)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create user (%d): %s", resp.StatusCode, string(raw))
	}

	// Create MAG holding modelMAG, so explicit MAG reference works in project allowlist while broader dynamic rule still cannot bypass.
	var magResp struct {
		Group domain.ModelAccessGroup `json:"group"`
	}
	var magID string
	resp, raw = cluster.c1.doJSON(http.MethodPost, "/admin/v1/model-access-groups", cluster.adminHdrs, map[string]any{
		"org_id": org.ID, "name": cluster.uniqueID("allowed-mag"),
	}, &magResp)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create MAG (%d): %s", resp.StatusCode, string(raw))
	}
	magID = magResp.Group.ID
	if magID == "" {
		var flat map[string]any
		_ = json.Unmarshal(raw, &flat)
		magID, _ = flat["id"].(string)
	}
	cluster.c1.doJSON(http.MethodPost, "/admin/v1/model-access-groups/"+magID+"/members", cluster.adminHdrs, map[string]any{
		"org_id": org.ID, "member_type": "model", "member_id": modelMAG,
	}, nil)

	// Broader dynamic access rule trying to grant modelDeniedByProject globally for this org user.
	cluster.c1.doJSON(http.MethodPost, "/admin/v1/access-group-rules", cluster.adminHdrs, map[string]any{
		"org_id": org.ID, "name": cluster.uniqueID("broad-dyn"),
		"attribute": "user.email", "operator": "contains", "value": "@corp.test",
		"allowed_models": []string{modelDeniedByProject},
	}, nil)

	// Project restricts allowed_models to mag:<magID> (explicit MAG ref) and cap 50,000 micros.
	var proj domain.Project
	resp, raw = cluster.c1.doJSON(http.MethodPost, "/admin/v1/projects", cluster.adminHdrs, map[string]any{
		"org_id":            org.ID,
		"team_id":           team.ID,
		"name":              cluster.uniqueID("alpha-proj"),
		"max_budget_micros": 50_000,
		"allowed_models":    []string{magID},
	}, &proj)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create project (%d): %s", resp.StatusCode, string(raw))
	}

	// Team membership allows modelMAG & modelDeniedByProject and caps member spend at 50,000 micros.
	resp, raw = cluster.c1.doJSON(http.MethodPost, "/admin/v1/teams/"+team.ID+"/members", cluster.adminHdrs, map[string]any{
		"org_id":            org.ID,
		"user_id":           usr.ID,
		"role":              "developer",
		"max_budget_micros": 50_000,
		"allowed_models":    []string{magID, modelDeniedByProject},
	}, nil)
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		t.Fatalf("upsert team member (%d): %s", resp.StatusCode, string(raw))
	}

	vk := cluster.issueKey(map[string]any{
		"org_id": org.ID, "team_id": team.ID, "project_id": proj.ID, "user_id": usr.ID,
		"name": cluster.uniqueID("proj-vk"), "key_type": "llm_api",
	})
	hdrs := map[string]string{"Authorization": "Bearer " + vk.RawKey}

	// Precedence: broader dynamic access rule cannot override project allowlist!
	if r, b := cluster.c1.doJSON(http.MethodPost, "/v1/chat/completions", hdrs, map[string]any{
		"model": modelDeniedByProject, "messages": []map[string]string{{"role": "user", "content": "blocked"}},
	}, nil); r.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 project restriction blocking modelDeniedByProject despite broad dynamic rule, got %d: %s", r.StatusCode, string(b))
	}

	// Explicit MAG reference allows modelMAG across both nodes; 2 calls * 20,000 = 40,000 micros <= 50,000 cap.
	magReq := map[string]any{"model": modelMAG, "max_tokens": 500, "messages": []map[string]string{{"role": "user", "content": "ok"}}}
	if r, b := cluster.c1.doJSON(http.MethodPost, "/v1/chat/completions", hdrs, magReq, nil); r.StatusCode != http.StatusOK {
		t.Fatalf("call 1 via explicit MAG ref failed (%d): %s", r.StatusCode, string(b))
	}
	if r, b := cluster.c2.doJSON(http.MethodPost, "/v1/chat/completions", hdrs, magReq, nil); r.StatusCode != http.StatusOK {
		t.Fatalf("call 2 on node2 failed (%d): %s", r.StatusCode, string(b))
	}

	// Verify durable outbox settled exact integer micro-dollars to team, team_member, AND project simultaneously!
	cluster.waitForCondition(5*time.Second, "team, team_member, and project spend_micros == 40000", func() bool {
		var teamSpent, memSpent, projSpent int64
		_ = cluster.pool.QueryRow(ctx, `SELECT spent_micros FROM teams WHERE id = $1`, team.ID).Scan(&teamSpent)
		_ = cluster.pool.QueryRow(ctx, `SELECT spent_micros FROM team_memberships WHERE team_id = $1 AND user_id = $2`, team.ID, usr.ID).Scan(&memSpent)
		_ = cluster.pool.QueryRow(ctx, `SELECT spent_micros FROM projects WHERE id = $1`, proj.ID).Scan(&projSpent)
		return teamSpent == 40_000 && memSpent == 40_000 && projSpent == 40_000
	})

	// Next call pushes predicted spend to 60,000 > 50,000 project/member cap -> 429 on node2!
	if r, _ := cluster.c2.doJSON(http.MethodPost, "/v1/chat/completions", hdrs, magReq, nil); r.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429 once project/member 50,000 cap reached, got %d", r.StatusCode)
	}
}

func TestE2E_Identity_SCIMv2AtomicGroupsImpersonationAndAgentNarrowing(t *testing.T) {
	upstream := newMockDeterministicLLMUpstream(t)
	cluster := setupConfigurableDualNodeCluster(t, nil)

	ctx := context.Background()
	org := cluster.createOrg("SCIM Org")
	modelAllowed := cluster.uniqueID("scim-allowed")
	modelExtra := cluster.uniqueID("scim-extra")
	cluster.seedOpenAIModel(ctx, org.ID, modelAllowed, upstream.OpenAIBaseURL(), 2_000_000, 8_000_000, 0, 0)
	cluster.seedOpenAIModel(ctx, org.ID, modelExtra, upstream.OpenAIBaseURL(), 2_000_000, 8_000_000, 0, 0)

	scimKey := cluster.issueKey(map[string]any{
		"org_id": org.ID, "name": cluster.uniqueID("scim-svc"), "role": "service_account", "allowed_endpoints": []string{"/scim/v2/*"},
	})
	scimHdrs := map[string]string{
		"Authorization": "Bearer " + scimKey.RawKey,
		"Content-Type":  "application/scim+json",
	}

	// 1. SCIM v2 Users + Groups CRUD & atomic UpdateSCIMGroup stale-write conflict + post-commit cache invalidation.
	var scimUserA, scimUserB map[string]any
	resp, raw := cluster.c1.doJSON(http.MethodPost, "/scim/v2/Users", scimHdrs, map[string]any{
		"userName":    "scim-a-" + cluster.runTag + "@corp.test",
		"externalId":  "ext-a-" + cluster.runTag,
		"displayName": "SCIM A",
		"active":      true,
		"emails":      []map[string]any{{"value": "scim-a-" + cluster.runTag + "@corp.test", "primary": true}},
	}, &scimUserA)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("SCIM create user A (%d): %s", resp.StatusCode, string(raw))
	}
	userAID, _ := scimUserA["id"].(string)

	resp, raw = cluster.c1.doJSON(http.MethodPost, "/scim/v2/Users", scimHdrs, map[string]any{
		"userName":    "scim-b-" + cluster.runTag + "@corp.test",
		"externalId":  "ext-b-" + cluster.runTag,
		"displayName": "SCIM B",
		"active":      true,
		"emails":      []map[string]any{{"value": "scim-b-" + cluster.runTag + "@corp.test", "primary": true}},
	}, &scimUserB)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("SCIM create user B (%d): %s", resp.StatusCode, string(raw))
	}
	userBID, _ := scimUserB["id"].(string)

	var scimGrp map[string]any
	resp, raw = cluster.c1.doJSON(http.MethodPost, "/scim/v2/Groups", scimHdrs, map[string]any{
		"displayName": cluster.uniqueID("scim-grp"),
		"members":     []map[string]any{{"value": userAID}},
	}, &scimGrp)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("SCIM create group (%d): %s", resp.StatusCode, string(raw))
	}
	groupID, _ := scimGrp["id"].(string)

	// Issue key for userA tied to groupID so we can prove post-commit cache invalidation on node2 when SCIM updates group!
	vkUserA := cluster.issueKey(map[string]any{
		"org_id": org.ID, "team_id": groupID, "user_id": userAID, "name": cluster.uniqueID("scim-u-vk"), "key_type": "llm_api",
	})
	chatReq := map[string]any{"model": modelAllowed, "messages": []map[string]string{{"role": "user", "content": "scim"}}}
	if r, b := cluster.c2.doJSON(http.MethodPost, "/v1/chat/completions", map[string]string{"Authorization": "Bearer " + vkUserA.RawKey}, chatReq, nil); r.StatusCode != http.StatusOK {
		t.Fatalf("warm node2 key before SCIM update (%d): %s", r.StatusCode, string(b))
	}
	// Wait for the async FinOps SpendWorker flush on groupID so its UPDATE teams
	// updated_at does not race with our optimistic-lock SCIM group snapshot test.
	cluster.waitForCondition(3*time.Second, "warm-up team spend flushed before SCIM group PATCH", func() bool {
		var spent int64
		_ = cluster.pool.QueryRow(ctx, `SELECT spent_micros FROM teams WHERE id = $1`, groupID).Scan(&spent)
		return spent > 0
	})

	// Capture team UpdatedAt to verify stale-write optimistic lock conflict directly against PostgresRepository.
	teamSnapshot, err := cluster.pgRepo.GetTeam(ctx, groupID)
	if err != nil {
		t.Fatalf("GetTeam(%s): %v", groupID, err)
	}

	// Valid atomic PATCH via node1 replaces members=[userB] and renames group cleanly.
	newGrpName := cluster.uniqueID("scim-grp-renamed")
	resp, raw = cluster.c1.doJSON(http.MethodPatch, "/scim/v2/Groups/"+groupID, scimHdrs, map[string]any{
		"Operations": []map[string]any{
			{"op": "replace", "path": "displayName", "value": newGrpName},
			{"op": "replace", "path": "members", "value": []map[string]any{{"value": userBID}}},
		},
	}, nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("SCIM PATCH group (%d): %s", resp.StatusCode, string(raw))
	}

	// Stale-write check using pre-PATCH UpdatedAt must return storage.ErrConflict without corrupting members or name!
	staleCopy := *teamSnapshot
	staleCopy.Name = cluster.uniqueID("stale-should-fail")
	if err := cluster.pgRepo.UpdateSCIMGroup(ctx, &staleCopy, []string{userAID}, true); !errors.Is(err, storage.ErrConflict) {
		t.Fatalf("expected storage.ErrConflict on stale SCIM group write, got %v", err)
	}
	afterStale, _ := cluster.pgRepo.GetTeam(ctx, groupID)
	if afterStale.Name != newGrpName {
		t.Fatalf("expected team name %q preserved after stale write rejection, got %q", newGrpName, afterStale.Name)
	}

	// Deprovision userA via SCIM DELETE -> immediately invalidates key cache on node2!
	if r, b := cluster.c1.doJSON(http.MethodDelete, "/scim/v2/Users/"+userAID, scimHdrs, nil, nil); r.StatusCode != http.StatusNoContent {
		t.Fatalf("SCIM DELETE userA (%d): %s", r.StatusCode, string(b))
	}
	cluster.waitForCondition(3*time.Second, "node2 rejects deprovisioned SCIM user key", func() bool {
		r, _ := cluster.c2.doJSON(http.MethodPost, "/v1/chat/completions", map[string]string{"Authorization": "Bearer " + vkUserA.RawKey}, chatReq, nil)
		return r.StatusCode == http.StatusUnauthorized || r.StatusCode == http.StatusForbidden
	})

	// 2. Operator impersonation & audit log tracking.
	impTarget := &domain.User{
		ID: cluster.uniqueID("usr-imp-ta"), OrgID: org.ID, TeamID: groupID,
		Email: "imp-ta-" + cluster.runTag + "@corp.test", Name: "Imp Target",
		Role: domain.RoleTeamAdmin, IsActive: true, SCIMActive: true,
	}
	if err := cluster.pgRepo.CreateUser(ctx, impTarget); err != nil {
		t.Fatalf("CreateUser(impTarget): %v", err)
	}
	impKey := cluster.issueKey(map[string]any{
		"org_id": org.ID, "name": cluster.uniqueID("imp-admin-key"), "role": "org_admin", "can_impersonate": true, "key_type": "management",
	})
	noImpKey := cluster.issueKey(map[string]any{
		"org_id": org.ID, "name": cluster.uniqueID("no-imp-key"), "role": "org_admin", "can_impersonate": false, "key_type": "management",
	})

	// Allowed impersonation succeeds & writes audit log with actor_id and impersonated_by.
	rImp, bImp := cluster.c1.doJSON(http.MethodPost, "/admin/v1/projects", map[string]string{
		"Authorization":            "Bearer " + impKey.RawKey,
		auth.HeaderImpersonateUser: impTarget.ID,
	}, map[string]any{"org_id": org.ID, "team_id": groupID, "name": cluster.uniqueID("imp-proj")}, nil)
	if rImp.StatusCode != http.StatusCreated {
		t.Fatalf("impersonated project creation (%d): %s", rImp.StatusCode, string(bImp))
	}
	// Non-impersonating key cannot use HeaderImpersonateUser.
	if rDeny, _ := cluster.c1.doJSON(http.MethodPost, "/admin/v1/teams", map[string]string{
		"Authorization":            "Bearer " + noImpKey.RawKey,
		auth.HeaderImpersonateUser: impTarget.ID,
	}, map[string]any{"org_id": org.ID, "name": "blocked-imp"}, nil); rDeny.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 when CanImpersonate=false, got %d", rDeny.StatusCode)
	}

	cluster.waitForCondition(3*time.Second, "project.created audit log records impersonation", func() bool {
		logs, err := cluster.pgRepo.ListAuditLogs(ctx, org.ID, 30)
		if err != nil {
			return false
		}
		for _, l := range logs {
			if l.Action == "project.created" && l.ActorID == impTarget.ID && fmt.Sprint(l.Details["impersonated_by"]) == impKey.ID {
				return true
			}
		}
		return false
	})

	// 3. Agent caller narrowing (X-Gateway-Delegated-User-Id): agent can access modelAllowed & modelExtra,
	//    but delegated user only has team_membership allowed_models=[modelAllowed] -> intersection blocks modelExtra (403).
	cluster.c1.doJSON(http.MethodPost, "/admin/v1/teams/"+groupID+"/members", cluster.adminHdrs, map[string]any{
		"org_id": org.ID, "user_id": userBID, "role": "developer", "allowed_models": []string{modelAllowed},
	}, nil)
	// Also constrain userB's user record allowed_models or verify membership restriction on groupID.
	agentKey := cluster.issueKey(map[string]any{
		"org_id": org.ID, "team_id": groupID, "name": cluster.uniqueID("agent-wide"),
		"allowed_models": []string{modelAllowed, modelExtra}, "key_type": "llm_api",
	})
	if r, b := cluster.c1.doJSON(http.MethodPost, "/v1/chat/completions", map[string]string{
		"Authorization":            "Bearer " + agentKey.RawKey,
		auth.HeaderDelegatedUserID: userBID,
		auth.HeaderDelegatedTeamID: groupID,
	}, map[string]any{"model": modelAllowed, "messages": []map[string]string{{"role": "user", "content": "narrow ok"}}}, nil); r.StatusCode != http.StatusOK {
		t.Fatalf("agent narrowed intersection allowed model expected 200, got %d: %s", r.StatusCode, string(b))
	}
	if r, b := cluster.c2.doJSON(http.MethodPost, "/v1/chat/completions", map[string]string{
		"Authorization":            "Bearer " + agentKey.RawKey,
		auth.HeaderDelegatedUserID: userBID,
		auth.HeaderDelegatedTeamID: groupID,
	}, map[string]any{"model": modelExtra, "messages": []map[string]string{{"role": "user", "content": "narrow deny"}}}, nil); r.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 when delegated caller narrows out modelExtra, got %d: %s", r.StatusCode, string(b))
	}
}
