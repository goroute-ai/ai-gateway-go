package auth_test

import (
	"context"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

func TestResolveMappedRole_GroupMappingsAndPrivilegeCeiling(t *testing.T) {
	rules := []auth.GroupRoleMappingRule{
		{Group: "kc-developers", Role: "developer"},
		{Group: "kc-org-admins", Role: "org_admin"},
		{Group: "kc-platform-admins", Role: "platform_admin"},
	}

	t.Run("highest_privilege selects org_admin over developer", func(t *testing.T) {
		got := auth.ResolveMappedRole("", []string{"kc-developers", "kc-org-admins"}, rules, "highest_privilege", "viewer", false)
		if got != domain.RoleOrgAdmin {
			t.Fatalf("got %q, want org_admin", got)
		}
	})

	t.Run("first_match selects first matching rule in order", func(t *testing.T) {
		got := auth.ResolveMappedRole("", []string{"kc-org-admins", "kc-developers"}, rules, "first_match", "viewer", false)
		if got != domain.RoleDeveloper {
			t.Fatalf("got %q, want developer", got)
		}
	})

	t.Run("platform_admin blocked when allowPrivilegedClaims is false", func(t *testing.T) {
		got := auth.ResolveMappedRole("", []string{"kc-platform-admins", "kc-org-admins"}, rules, "highest_privilege", "viewer", false)
		if got != domain.RoleOrgAdmin {
			t.Fatalf("got %q, want org_admin (platform_admin blocked)", got)
		}
		gotOnlyPlatform := auth.ResolveMappedRole("", []string{"kc-platform-admins"}, rules, "highest_privilege", "viewer", false)
		if gotOnlyPlatform != domain.RoleViewer {
			t.Fatalf("got %q, want default fallback viewer", gotOnlyPlatform)
		}
	})

	t.Run("platform_admin allowed when allowPrivilegedClaims is true", func(t *testing.T) {
		got := auth.ResolveMappedRole("", []string{"kc-platform-admins"}, rules, "highest_privilege", "viewer", true)
		if got != domain.RolePlatformAdmin {
			t.Fatalf("got %q, want platform_admin", got)
		}
	})

	t.Run("ResolveMappedTeamID maps IdP groups deterministically", func(t *testing.T) {
		teamID := auth.ResolveMappedTeamID(nil, []string{"eng-ml"}, map[string]string{"eng-ml": "team-ml"}, "team-default")
		if teamID != "team-ml" {
			t.Fatalf("got %q, want team-ml", teamID)
		}
	})
}

func TestUnifiedAccessGroups_EnrichMCPAndA2AGrants(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	rbac := auth.NewRBACEngine(repo)

	// Create Unified Access Group granting MCP server, MCP tool, and A2A agent.
	mag := &domain.ModelAccessGroup{
		ID:                "grp-eng",
		OrgID:             "org-1",
		Name:              "eng-agents",
		AllowedMCPServers: []string{"github"},
		AllowedMCPTools:   []string{"github:get_issue"},
		AllowedA2AAgents:  []string{"code-reviewer"},
		IsActive:          true,
	}
	if err := repo.UpsertModelAccessGroup(ctx, mag); err != nil {
		t.Fatalf("UpsertModelAccessGroup: %v", err)
	}
	if err := repo.AddModelAccessGroupMember(ctx, &domain.ModelAccessGroupMember{
		OrgID:      "org-1",
		GroupID:    mag.ID,
		MemberType: domain.ModelAccessGroupMemberTeam,
		MemberID:   "team-eng",
	}); err != nil {
		t.Fatalf("AddModelAccessGroupMember: %v", err)
	}

	// Also add an AccessGroupRule granting another MCP server via JWT claim.
	if err := repo.CreateAccessGroupRule(ctx, &domain.AccessGroupRule{
		OrgID:             "org-1",
		Name:              "ml-mcp",
		Attribute:         "jwt_claims.groups",
		Operator:          domain.AccessRuleOperatorContains,
		Value:             "ml-ops",
		AllowedMCPServers: []string{"mlflow"},
		AllowedA2AAgents:  []string{"ml-runner"},
		IsActive:          true,
	}); err != nil {
		t.Fatalf("CreateAccessGroupRule: %v", err)
	}

	baseID := &domain.IdentityContext{
		OrgID:                "org-1",
		TeamID:               "team-eng",
		KeyAllowedMCPServers: []string{"docs"},
		KeyAllowedMCPTools:   []string{"docs:*"},
		KeyAllowedA2AAgents:  []string{"helper"},
		Principal: &domain.Principal{
			AuthMethod: "jwt",
			RawClaims:  map[string]any{"groups": []string{"ml-ops"}},
		},
	}

	enriched := rbac.EnrichIdentityWithAccessRules(ctx, baseID)
	if err := rbac.AuthorizeMCPServer(enriched, "github"); err != nil {
		t.Fatalf("expected unified AccessGroup to grant github MCP server: %v", err)
	}
	if err := rbac.AuthorizeMCPServer(enriched, "mlflow"); err != nil {
		t.Fatalf("expected AccessGroupRule to grant mlflow MCP server: %v", err)
	}
	if err := rbac.AuthorizeMCPTool(enriched, "github", "get_issue"); err != nil {
		t.Fatalf("expected unified AccessGroup to grant github:get_issue: %v", err)
	}
	if err := rbac.AuthorizeA2AAgent(enriched, "code-reviewer"); err != nil {
		t.Fatalf("expected unified AccessGroup to grant code-reviewer agent: %v", err)
	}
	if err := rbac.AuthorizeA2AAgent(enriched, "ml-runner"); err != nil {
		t.Fatalf("expected AccessGroupRule to grant ml-runner agent: %v", err)
	}

	// Security check: explicit key DenyAll ([]) MUST still deny even with matching AccessGroup!
	denyKeyID := *baseID
	denyKeyID.KeyAllowedMCPServers = []string{}
	denyEnriched := rbac.EnrichIdentityWithAccessRules(ctx, &denyKeyID)
	if err := rbac.AuthorizeMCPServer(denyEnriched, "github"); err == nil {
		t.Fatalf("expected explicit key DenyAll to override unified AccessGroup")
	}
}
