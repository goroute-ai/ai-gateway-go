package auth_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

func TestEvaluateAccessGroupRules_AllOperatorsAndTrustedAttributes(t *testing.T) {
	now := time.Now().UTC()
	rules := []*domain.AccessGroupRule{
		{
			ID:            "rule_jwt_nested_in_list",
			OrgID:         "org_1",
			Name:          "Research Group Tier",
			Attribute:     "jwt_claims.realm_access.roles",
			Operator:      domain.AccessRuleOperatorInList,
			Value:         "ai-research, ml-platform",
			AllowedModels: []string{"claude-opus-4", "o3"},
			AccessGroupID: "grp_frontier",
			Priority:      30,
			IsActive:      true,
			CreatedAt:     now,
		},
		{
			ID:            "rule_email_contains",
			OrgID:         "org_1",
			Name:          "Research Subdomain Email",
			Attribute:     "email",
			Operator:      domain.AccessRuleOperatorContains,
			Value:         "@research.acme.example",
			AllowedModels: []string{"gpt-4.1", "o3"},
			AccessGroupID: "grp_research_email",
			Priority:      20,
			IsActive:      true,
			CreatedAt:     now,
		},
		{
			ID:            "rule_issuer_prefix",
			OrgID:         "org_1",
			Name:          "Corporate IdP Prefix",
			Attribute:     "issuer",
			Operator:      domain.AccessRuleOperatorPrefix,
			Value:         "https://sso.acme.example/",
			AllowedModels: []string{"gpt-4o-mini"},
			AccessGroupID: "grp_corp_idp",
			Priority:      10,
			IsActive:      true,
			CreatedAt:     now,
		},
		{
			ID:            "rule_team_equals",
			OrgID:         "org_1",
			Name:          "Core ML Team",
			Attribute:     "team_id",
			Operator:      domain.AccessRuleOperatorEquals,
			Value:         "team_ml",
			AllowedModels: []string{"deepseek-r1"},
			AccessGroupID: "grp_team_ml",
			Priority:      5,
			IsActive:      true,
			CreatedAt:     now,
		},
		{
			ID:            "rule_role_equals",
			OrgID:         "org_1",
			Name:          "Team Admin Bonus Model",
			Attribute:     "user_role",
			Operator:      domain.AccessRuleOperatorEquals,
			Value:         "team_admin",
			AllowedModels: []string{"claude-sonnet-4"},
			AccessGroupID: "grp_team_admins",
			Priority:      4,
			IsActive:      true,
			CreatedAt:     now,
		},
		{
			ID:            "rule_user_in_json_list",
			OrgID:         "org_1",
			Name:          "Named Principal Allowlist",
			Attribute:     "user_id",
			Operator:      domain.AccessRuleOperatorInList,
			Value:         `["usr_special_1","usr_special_2"]`,
			AllowedModels: []string{"gemini-2.5-pro"},
			AccessGroupID: "grp_named_users",
			Priority:      3,
			IsActive:      true,
			CreatedAt:     now,
		},
		{
			ID:            "rule_namespaced_claim_equals",
			OrgID:         "org_1",
			Name:          "Namespaced OIDC Claim",
			Attribute:     "jwt_claims.https://acme.example/cost_center",
			Operator:      domain.AccessRuleOperatorEquals,
			Value:         "cc-900",
			AllowedModels: []string{"mistral-large"},
			AccessGroupID: "grp_cc_900",
			Priority:      2,
			IsActive:      true,
			CreatedAt:     now,
		},
		{
			ID:            "rule_inactive",
			OrgID:         "org_1",
			Name:          "Inactive Rule",
			Attribute:     "team_id",
			Operator:      domain.AccessRuleOperatorEquals,
			Value:         "team_ml",
			AllowedModels: []string{"should-not-grant"},
			AccessGroupID: "grp_inactive",
			Priority:      100,
			IsActive:      false,
			CreatedAt:     now,
		},
		{
			ID:            "rule_other_org",
			OrgID:         "org_2",
			Name:          "Other Org Rule",
			Attribute:     "team_id",
			Operator:      domain.AccessRuleOperatorEquals,
			Value:         "team_ml",
			AllowedModels: []string{"cross-org-model"},
			AccessGroupID: "grp_other_org",
			Priority:      100,
			IsActive:      true,
			CreatedAt:     now,
		},
		{
			ID:            "rule_untrusted_attr",
			OrgID:         "org_1",
			Name:          "Untrusted Attribute",
			Attribute:     "headers.x-admin",
			Operator:      domain.AccessRuleOperatorEquals,
			Value:         "true",
			AllowedModels: []string{"hijacked-model"},
			AccessGroupID: "grp_hijack",
			Priority:      100,
			IsActive:      true,
			CreatedAt:     now,
		},
	}

	idCtx := &domain.IdentityContext{
		OrgID:  "org_1",
		TeamID: "team_ml",
		UserID: "usr_special_2",
		Role:   domain.RoleTeamAdmin,
		Principal: &domain.Principal{
			AuthMethod:    "jwt",
			PrincipalType: "user",
			Issuer:        "https://sso.acme.example/oauth2/default",
			Subject:       "sub-special-2",
			Email:         "ada@research.acme.example",
			RawClaims: map[string]any{
				"realm_access": map[string]any{
					"roles": []any{"developer", "ml-platform"},
				},
				"https://acme.example/cost_center": "cc-900",
			},
		},
	}

	eval := auth.EvaluateAccessGroupRules(rules, idCtx)

	wantRuleIDs := []string{
		"rule_jwt_nested_in_list",
		"rule_email_contains",
		"rule_issuer_prefix",
		"rule_team_equals",
		"rule_role_equals",
		"rule_user_in_json_list",
		"rule_namespaced_claim_equals",
	}
	if !reflect.DeepEqual(eval.MatchedRuleIDs, wantRuleIDs) {
		t.Fatalf("MatchedRuleIDs = %v, want %v", eval.MatchedRuleIDs, wantRuleIDs)
	}

	wantGroups := []string{
		"grp_frontier",
		"grp_research_email",
		"grp_corp_idp",
		"grp_team_ml",
		"grp_team_admins",
		"grp_named_users",
		"grp_cc_900",
	}
	if !reflect.DeepEqual(eval.AccessGroups, wantGroups) {
		t.Fatalf("AccessGroups = %v, want %v", eval.AccessGroups, wantGroups)
	}

	// Verify deduplication and priority-ordered model list (o3 appears in both rule 1 and rule 2).
	wantModels := []string{
		"claude-opus-4",
		"o3",
		"gpt-4.1",
		"gpt-4o-mini",
		"deepseek-r1",
		"claude-sonnet-4",
		"gemini-2.5-pro",
		"mistral-large",
	}
	if !reflect.DeepEqual(eval.AllowedModels, wantModels) {
		t.Fatalf("AllowedModels = %v, want %v", eval.AllowedModels, wantModels)
	}
}

func TestValidateAccessGroupRule(t *testing.T) {
	valid := &domain.AccessGroupRule{
		OrgID:         "org_1",
		Name:          "  Engineering Rule  ",
		Attribute:     "jwt_claims.groups",
		Operator:      "IN_LIST",
		Value:         "eng, platform",
		AllowedModels: []string{" gpt-4.1 ", "gpt-4.1", ""},
		AccessGroupID: " grp_eng ",
	}
	if err := auth.ValidateAccessGroupRule(valid); err != nil {
		t.Fatalf("expected valid rule to pass, got %v", err)
	}
	if valid.Name != "Engineering Rule" || valid.Operator != domain.AccessRuleOperatorInList || len(valid.AllowedModels) != 1 || valid.AllowedModels[0] != "gpt-4.1" || valid.AccessGroupID != "grp_eng" {
		t.Fatalf("unexpected normalized rule: %+v", valid)
	}

	invalidCases := []struct {
		name string
		rule *domain.AccessGroupRule
	}{
		{name: "nil rule", rule: nil},
		{name: "missing name", rule: &domain.AccessGroupRule{Attribute: "team_id", Operator: domain.AccessRuleOperatorEquals, Value: "t1", AllowedModels: []string{"m1"}}},
		{name: "untrusted attribute", rule: &domain.AccessGroupRule{Name: "r", Attribute: "http_header.x-role", Operator: domain.AccessRuleOperatorEquals, Value: "admin", AllowedModels: []string{"m1"}}},
		{name: "empty jwt_claims path", rule: &domain.AccessGroupRule{Name: "r", Attribute: "jwt_claims.", Operator: domain.AccessRuleOperatorEquals, Value: "v", AllowedModels: []string{"m1"}}},
		{name: "double dot jwt_claims path", rule: &domain.AccessGroupRule{Name: "r", Attribute: "jwt_claims.a..b", Operator: domain.AccessRuleOperatorEquals, Value: "v", AllowedModels: []string{"m1"}}},
		{name: "unsupported operator", rule: &domain.AccessGroupRule{Name: "r", Attribute: "team_id", Operator: "regex", Value: ".*", AllowedModels: []string{"m1"}}},
		{name: "empty value", rule: &domain.AccessGroupRule{Name: "r", Attribute: "team_id", Operator: domain.AccessRuleOperatorEquals, Value: "   ", AllowedModels: []string{"m1"}}},
		{name: "empty in_list values", rule: &domain.AccessGroupRule{Name: "r", Attribute: "team_id", Operator: domain.AccessRuleOperatorInList, Value: " , , ", AllowedModels: []string{"m1"}}},
		{name: "neither allowed_models nor access_group_id", rule: &domain.AccessGroupRule{Name: "r", Attribute: "team_id", Operator: domain.AccessRuleOperatorEquals, Value: "t1"}},
	}
	for _, tc := range invalidCases {
		t.Run(tc.name, func(t *testing.T) {
			if err := auth.ValidateAccessGroupRule(tc.rule); err == nil {
				t.Fatalf("expected validation error for %s, got nil", tc.name)
			}
		})
	}
}

type countingAccessRuleRepo struct {
	*storage.MemoryRepository
	listCalls atomic.Int64
}

func (c *countingAccessRuleRepo) ListAccessGroupRules(ctx context.Context, orgID string, activeOnly bool) ([]*domain.AccessGroupRule, error) {
	c.listCalls.Add(1)
	return c.MemoryRepository.ListAccessGroupRules(ctx, orgID, activeOnly)
}

func TestRBACEngine_AccessRulesCachingL1L2AndPubSubInvalidation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mr := miniredis.RunT(t)
	redis1 := storage.NewRedisFabric(mr.Addr(), "", 0)
	redis2 := storage.NewRedisFabric(mr.Addr(), "", 0)
	defer redis1.Client().Close()
	defer redis2.Client().Close()

	baseRepo := storage.NewMemoryRepository()
	repo := &countingAccessRuleRepo{MemoryRepository: baseRepo}

	if err := repo.CreateOrganization(ctx, &domain.Organization{ID: "org_dyn", Name: "Dynamic Org", Slug: "dyn", IsActive: true}); err != nil {
		t.Fatalf("CreateOrganization: %v", err)
	}

	rule := &domain.AccessGroupRule{
		ID:            "rule_frontier_1",
		OrgID:         "org_dyn",
		Name:          "Frontier Access",
		Attribute:     "jwt_claims.groups",
		Operator:      domain.AccessRuleOperatorInList,
		Value:         "ai-research,frontier-labs",
		AllowedModels: []string{"claude-opus-4", "openai/*"},
		AccessGroupID: "frontier",
		Priority:      10,
		IsActive:      true,
	}
	if err := repo.CreateAccessGroupRule(ctx, rule); err != nil {
		t.Fatalf("CreateAccessGroupRule: %v", err)
	}

	rbac1 := auth.NewRBACEngine(repo)
	rbac1.SetRedis(redis1)
	rbac2 := auth.NewRBACEngine(repo)
	rbac2.SetRedis(redis2)
	rbac2.StartInvalidationListener(ctx)
	defer rbac2.StopInvalidationListener()
	time.Sleep(25 * time.Millisecond)

	researcherCtx := &domain.IdentityContext{
		OrgID:             "org_dyn",
		TeamID:            "team_1",
		KeyPrefix:         "oidc:usr_1",
		KeyAllowedModels:  []string{"gpt-4o-mini"},
		TeamAllowedModels: []string{"gpt-4o-mini"},
		Principal: &domain.Principal{
			AuthMethod:    "jwt",
			PrincipalType: "user",
			Subject:       "usr_1",
			RawClaims: map[string]any{
				"groups": []any{"engineering", "ai-research"},
			},
		},
	}

	nonMatchingCtx := &domain.IdentityContext{
		OrgID:             "org_dyn",
		TeamID:            "team_1",
		KeyPrefix:         "oidc:usr_2",
		KeyAllowedModels:  []string{"gpt-4o-mini"},
		TeamAllowedModels: []string{"gpt-4o-mini"},
		Principal: &domain.Principal{
			AuthMethod:    "jwt",
			PrincipalType: "user",
			Subject:       "usr_2",
			RawClaims: map[string]any{
				"groups": []any{"marketing"},
			},
		},
	}

	// 1. Cold evaluation on rbac1 queries repository once and populates L1 + L2 Redis ("gw:rbac:access_rules:org_dyn").
	if err := rbac1.AuthorizeRequestedModel(researcherCtx, "claude-opus-4"); err != nil {
		t.Fatalf("expected claude-opus-4 to be allowed via dynamic rule on rbac1: %v", err)
	}
	if err := rbac1.AuthorizeRequestedModel(researcherCtx, "openai/o3-pro"); err != nil {
		t.Fatalf("expected openai/o3-pro to be allowed via wildcard dynamic rule on rbac1: %v", err)
	}
	if err := rbac1.AuthorizeRequestedModel(researcherCtx, "gemini-2.5-pro"); err == nil {
		t.Fatal("expected unlisted gemini-2.5-pro to be rejected")
	}
	if err := rbac1.AuthorizeRequestedModel(nonMatchingCtx, "claude-opus-4"); err == nil {
		t.Fatal("expected non-matching caller to be rejected for claude-opus-4")
	}
	if got := repo.listCalls.Load(); got != 1 {
		t.Fatalf("expected 1 repository call after L1 warm hits on rbac1, got %d", got)
	}
	if !mr.Exists("gw:rbac:access_rules:org_dyn") {
		t.Fatal("expected Redis key gw:rbac:access_rules:org_dyn to be populated")
	}

	// 2. rbac2 (second replica) resolves from L2 Redis without hitting the repository!
	if err := rbac2.AuthorizeRequestedModel(researcherCtx, "claude-opus-4"); err != nil {
		t.Fatalf("expected claude-opus-4 to be allowed on rbac2 via L2 cache: %v", err)
	}
	if got := repo.listCalls.Load(); got != 1 {
		t.Fatalf("expected rbac2 to hit L2 Redis (repo calls still 1), got %d", got)
	}

	// 3. Delete rule in repository and trigger InvalidateAccessGroupRules on rbac1.
	if err := repo.DeleteAccessGroupRule(ctx, rule.ID); err != nil {
		t.Fatalf("DeleteAccessGroupRule: %v", err)
	}
	rbac1.InvalidateAccessGroupRules(ctx, "org_dyn")

	// L2 Redis key must be deleted immediately and rbac1 must immediately reject claude-opus-4.
	if mr.Exists("gw:rbac:access_rules:org_dyn") {
		t.Fatal("expected gw:rbac:access_rules:org_dyn to be evicted from Redis after InvalidateAccessGroupRules")
	}
	if err := rbac1.AuthorizeRequestedModel(researcherCtx, "claude-opus-4"); err == nil {
		t.Fatal("expected claude-opus-4 to be denied on rbac1 after rule deletion and invalidation")
	}

	// 4. Wait briefly for Pub/Sub invalidation to reach rbac2 and verify rbac2 also denies claude-opus-4.
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if err := rbac2.AuthorizeRequestedModel(researcherCtx, "claude-opus-4"); err != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := rbac2.AuthorizeRequestedModel(researcherCtx, "claude-opus-4"); err == nil {
		t.Fatal("expected claude-opus-4 to be denied on rbac2 after Pub/Sub cache invalidation")
	}
}

func TestAuthResolver_ProjectsAccessGroupsAndDynamicAllowedModels(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	_ = repo.CreateOrganization(ctx, &domain.Organization{ID: "org_proj", Name: "Proj Org", Slug: "proj", IsActive: true})
	_ = repo.CreateTeam(ctx, &domain.Team{
		ID:            "team_proj",
		OrgID:         "org_proj",
		Name:          "Proj Team",
		AllowedModels: []string{"gpt-4o-mini"},
		IsActive:      true,
	})
	_ = repo.CreateUser(ctx, &domain.User{
		ID:          "usr_proj_1",
		OrgID:       "org_proj",
		TeamID:      "team_proj",
		Email:       "ml@proj.example",
		Name:        "ML Engineer",
		Role:        domain.RoleDeveloper,
		OIDCSubject: "sub-proj-1",
		IsActive:    true,
	})
	_ = repo.CreateAccessGroupRule(ctx, &domain.AccessGroupRule{
		ID:            "rule_proj_1",
		OrgID:         "org_proj",
		Name:          "ML Department Rule",
		Attribute:     "jwt_claims.department",
		Operator:      domain.AccessRuleOperatorEquals,
		Value:         "machine-learning",
		AllowedModels: []string{"claude-opus-4"},
		AccessGroupID: "ml-tier",
		Priority:      10,
		IsActive:      true,
	})

	jwtSecret := "resolver-access-rule-secret"
	jwtVerifier := auth.NewJWTVerifier(auth.JWTConfig{
		Secret:       jwtSecret,
		Issuer:       "https://idp.proj.example",
		Audience:     "ai-gateway",
		DefaultOrgID: "org_proj",
	})
	svc := auth.NewService(repo, nil, "master-key", time.Minute, time.Minute)
	svc.SetJWTVerifier(jwtVerifier)
	rbac := auth.NewRBACEngine(repo)

	resolver := auth.NewAuthResolver(auth.ResolverConfig{
		Service:            svc,
		Repo:               repo,
		RBAC:               rbac,
		JWTVerifier:        jwtVerifier,
		EnableDataPlaneJWT: true,
		DefaultOrgID:       "org_proj",
	})

	tok, err := auth.SignHS256(jwtSecret, &auth.JWTClaims{
		Subject:   "sub-proj-1",
		Issuer:    "https://idp.proj.example",
		Audience:  auth.AudienceClaim{"ai-gateway"},
		OrgID:     "org_proj",
		ExpiresAt: time.Now().UTC().Add(5 * time.Minute).Unix(),
		RawClaims: map[string]any{
			"department": "machine-learning",
		},
	})
	if err != nil {
		t.Fatalf("SignHS256: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	req.Header.Set("Authorization", "Bearer "+tok)

	idCtx, err := resolver.ResolveRequest(ctx, req)
	if err != nil {
		t.Fatalf("ResolveRequest: %v", err)
	}
	if !reflect.DeepEqual(idCtx.AccessGroups, []string{"ml-tier"}) {
		t.Fatalf("expected AccessGroups=[ml-tier], got %v", idCtx.AccessGroups)
	}
	if !reflect.DeepEqual(idCtx.DynamicAllowedModels, []string{"claude-opus-4"}) {
		t.Fatalf("expected DynamicAllowedModels=[claude-opus-4], got %v", idCtx.DynamicAllowedModels)
	}
	if err := rbac.AuthorizeRequestedModel(idCtx, "claude-opus-4"); err != nil {
		t.Fatalf("expected AuthorizeRequestedModel(claude-opus-4) to succeed: %v", err)
	}
}

func TestAuthorizeTeamAdminAction_AndOperatorAuthentication(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	_ = repo.CreateOrganization(ctx, &domain.Organization{ID: "org_a", Name: "Org A", Slug: "org-a", IsActive: true})
	_ = repo.CreateOrganization(ctx, &domain.Organization{ID: "org_b", Name: "Org B", Slug: "org-b", IsActive: true})
	_ = repo.CreateTeam(ctx, &domain.Team{ID: "team_a1", OrgID: "org_a", Name: "Team A1", IsActive: true})
	_ = repo.CreateTeam(ctx, &domain.Team{ID: "team_a2", OrgID: "org_a", Name: "Team A2", IsActive: true})

	_ = repo.CreateUser(ctx, &domain.User{
		ID:          "usr_ta_a1",
		OrgID:       "org_a",
		TeamID:      "team_a1",
		Email:       "lead@orga.example",
		Name:        "Team A1 Lead",
		Role:        domain.RoleTeamAdmin,
		OIDCSubject: "sub-ta-a1",
		IsActive:    true,
	})

	jwtSecret := "team-admin-unit-secret"
	svc := auth.NewService(repo, nil, "sk-gw-master-admin", time.Minute, time.Minute)
	svc.SetJWTVerifier(auth.NewJWTVerifier(auth.JWTConfig{Secret: jwtSecret}))

	// 1. VirtualKey with RoleTeamAdmin maps to OperatorRoleTeamAdmin and populates TeamID.
	vkTeamAdmin, err := svc.IssueVirtualKey(ctx, &domain.VirtualKey{
		OrgID:  "org_a",
		TeamID: "team_a1",
		Name:   "ta-key",
		Role:   domain.RoleTeamAdmin,
	})
	if err != nil {
		t.Fatalf("IssueVirtualKey: %v", err)
	}
	opVK, err := svc.AuthenticateOperator(ctx, vkTeamAdmin.RawKey)
	if err != nil {
		t.Fatalf("AuthenticateOperator(vk): %v", err)
	}
	if opVK.Role != domain.OperatorRoleTeamAdmin || opVK.OrgID != "org_a" || opVK.TeamID != "team_a1" {
		t.Fatalf("unexpected OperatorContext from VirtualKey: %+v", opVK)
	}

	// 2. JWT for User with RoleTeamAdmin maps to OperatorRoleTeamAdmin and populates TeamID from User.TeamID.
	jwtTok, err := auth.SignHS256(jwtSecret, &auth.JWTClaims{
		Subject:   "sub-ta-a1",
		ExpiresAt: time.Now().UTC().Add(5 * time.Minute).Unix(),
	})
	if err != nil {
		t.Fatalf("SignHS256: %v", err)
	}
	opJWT, err := svc.AuthenticateOperator(ctx, jwtTok)
	if err != nil {
		t.Fatalf("AuthenticateOperator(jwt): %v", err)
	}
	if opJWT.Role != domain.OperatorRoleTeamAdmin || opJWT.OrgID != "org_a" || opJWT.TeamID != "team_a1" {
		t.Fatalf("unexpected OperatorContext from JWT: %+v", opJWT)
	}

	// 3. AuthorizeAdminAction blocks team_admin from org-wide and platform operations.
	for _, write := range []bool{false, true} {
		if err := auth.AuthorizeAdminAction(opVK, "org_a", write); err == nil {
			t.Fatalf("expected AuthorizeAdminAction(write=%v) to reject team_admin", write)
		}
		if err := auth.AuthorizeAdminAction(opVK, "", write); err == nil {
			t.Fatalf("expected global AuthorizeAdminAction(write=%v) to reject team_admin", write)
		}
	}

	// 4. AuthorizeTeamAdminAction matrix for team_admin.
	if err := auth.AuthorizeTeamAdminAction(opVK, "org_a", "team_a1", false); err != nil {
		t.Fatalf("expected own-team read allowed: %v", err)
	}
	if err := auth.AuthorizeTeamAdminAction(opVK, "org_a", "team_a1", true); err != nil {
		t.Fatalf("expected own-team write allowed: %v", err)
	}
	if err := auth.AuthorizeTeamAdminAction(opVK, "org_a", "team_a2", false); err == nil {
		t.Fatal("expected cross-team read to be denied")
	} else {
		var gwErr *domain.GatewayError
		if !errors.As(err, &gwErr) || gwErr.StatusCode != http.StatusForbidden || gwErr.Code != "cross_team_access_denied" {
			t.Fatalf("expected 403 cross_team_access_denied, got %+v", err)
		}
	}
	if err := auth.AuthorizeTeamAdminAction(opVK, "org_a", "", true); err == nil {
		t.Fatal("expected empty targetTeamID (org-wide) to be denied for team_admin")
	}
	if err := auth.AuthorizeTeamAdminAction(opVK, "org_b", "team_a1", false); err == nil {
		t.Fatal("expected cross-org access to be denied for team_admin")
	}

	// team_admin without assigned TeamID fails closed.
	unscopedTeamAdmin := &domain.OperatorContext{
		ActorID: "usr_unscoped",
		Role:    domain.OperatorRoleTeamAdmin,
		OrgID:   "org_a",
		TeamID:  "",
	}
	if err := auth.AuthorizeTeamAdminAction(unscopedTeamAdmin, "org_a", "team_a1", false); err == nil {
		t.Fatal("expected team_admin with empty TeamID to fail closed")
	}
}
