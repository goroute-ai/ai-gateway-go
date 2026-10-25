package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

func TestHub_UnconditionalToolPolicyAndPositiveToolAllowlists(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	rbac := auth.NewRBACEngine(repo)
	hub := NewHub(repo, nil, rbac, nil, nil)

	srv := &domain.MCPServer{
		ID:            "srv-gh",
		OrgID:         "org-1",
		Slug:          "github",
		Name:          "GitHub",
		TransportType: "http",
		EndpointURL:   "https://mcp.example.com",
		IsActive:      true,
	}
	if err := repo.CreateMCPServer(ctx, srv); err != nil {
		t.Fatalf("CreateMCPServer: %v", err)
	}
	var mcpTools []*domain.MCPTool
	for _, name := range []string{"get_issue", "delete_repo", "list_prs"} {
		mcpTools = append(mcpTools, &domain.MCPTool{
			ID:          "tool-" + name,
			ServerID:    srv.ID,
			Name:        name,
			Description: "GitHub " + name,
			InputSchema: map[string]any{"type": "object"},
			IsActive:    true,
		})
	}
	if err := repo.UpsertMCPTools(ctx, srv.ID, "org-1", mcpTools); err != nil {
		t.Fatalf("UpsertMCPTools: %v", err)
	}
	if err := repo.CreateMCPToolset(ctx, &domain.MCPToolset{
		ID:       "ts-1",
		OrgID:    "org-1",
		Slug:     "gh-ops",
		Name:     "GitHub Ops",
		ToolIDs:  []string{"tool-get_issue", "tool-delete_repo"},
		IsActive: true,
	}); err != nil {
		t.Fatalf("CreateMCPToolset: %v", err)
	}

	// Block delete_repo via ToolPolicy WITHOUT configuring any GuardrailBinding.
	if err := repo.UpsertToolPolicy(ctx, &storage.ToolPolicy{
		OrgID:        "org-1",
		ToolName:     "delete_repo",
		InputPolicy:  storage.ToolTrustBlocked,
		OutputPolicy: storage.ToolTrustUntrusted,
	}); err != nil {
		t.Fatalf("UpsertToolPolicy: %v", err)
	}

	t.Run("blocked ToolPolicy hides tool in ListTools, tools/list, SearchTools, and blocks CallTool without GuardrailBinding", func(t *testing.T) {
		idCtx := &domain.IdentityContext{
			OrgID:        "org-1",
			VirtualKeyID: "vk-1",
			KeyPrefix:    "sk-gw-1",
		}
		tools, err := hub.ListTools(ctx, idCtx, "github")
		if err != nil {
			t.Fatalf("ListTools: %v", err)
		}
		for _, tool := range tools {
			if tool.Name == "delete_repo" {
				t.Fatalf("expected delete_repo to be hidden from ListTools")
			}
		}
		if len(tools) != 2 {
			t.Fatalf("expected 2 visible tools, got %d", len(tools))
		}

		summaries, err := hub.ProgressiveDiscovery().SearchTools(ctx, idCtx, "", 10)
		if err != nil {
			t.Fatalf("SearchTools: %v", err)
		}
		for _, s := range summaries {
			if s.Name == "delete_repo" {
				t.Fatalf("expected delete_repo to be hidden from SearchTools")
			}
		}

		_, err = hub.CallTool(ctx, idCtx, ToolCallInput{
			ServerSlug: "github",
			ToolName:   "delete_repo",
		}, CallMetadata{})
		var gwErr *domain.GatewayError
		if !errors.As(err, &gwErr) || gwErr.StatusCode != http.StatusForbidden || gwErr.Code != "violated_tool_policy" {
			t.Fatalf("expected 403 violated_tool_policy, got %v", err)
		}
		logs, _ := repo.ListAuditLogs(ctx, "org-1", 10)
		foundAudit := false
		for _, l := range logs {
			if l.Action == "mcp.tool_policy.blocked" {
				foundAudit = true
				break
			}
		}
		if !foundAudit {
			t.Fatalf("expected mcp.tool_policy.blocked audit log")
		}
	})

	t.Run("positive AllowedMCPTools filters tools/list and blocks unlisted tools", func(t *testing.T) {
		idCtx := &domain.IdentityContext{
			OrgID:              "org-1",
			VirtualKeyID:       "vk-2",
			KeyPrefix:          "sk-gw-2",
			KeyAllowedMCPTools: []string{"github:get_issue"},
		}
		tools, err := hub.ListTools(ctx, idCtx, "github")
		if err != nil {
			t.Fatalf("ListTools: %v", err)
		}
		if len(tools) != 1 || tools[0].Name != "get_issue" {
			t.Fatalf("expected only [get_issue], got %+v", tools)
		}

		_, err = hub.CallTool(ctx, idCtx, ToolCallInput{
			ServerSlug: "github",
			ToolName:   "list_prs",
		}, CallMetadata{})
		var gwErr *domain.GatewayError
		if !errors.As(err, &gwErr) || gwErr.StatusCode != http.StatusForbidden || gwErr.Code != "mcp_tool_restricted" {
			t.Fatalf("expected 403 mcp_tool_restricted, got %v", err)
		}
	})

	t.Run("explicit key DenyAll overrides dynamic MCP tool grants while non-empty allowlist unions with dynamic grants", func(t *testing.T) {
		denyCtx := &domain.IdentityContext{
			OrgID:                  "org-1",
			KeyAllowedMCPTools:     []string{},
			DynamicAllowedMCPTools: []string{"github:get_issue"},
		}
		if err := rbac.AuthorizeMCPTool(denyCtx, "github", "get_issue"); err == nil {
			t.Fatalf("expected explicit key DenyAll to override DynamicAllowedMCPTools")
		}

		unionCtx := &domain.IdentityContext{
			OrgID:                  "org-1",
			KeyAllowedMCPTools:     []string{"github:get_issue"},
			DynamicAllowedMCPTools: []string{"github:list_*"},
		}
		if err := rbac.AuthorizeMCPTool(unionCtx, "github", "list_prs"); err != nil {
			t.Fatalf("expected dynamic wildcard grant to allow list_prs: %v", err)
		}
	})

	t.Run("AllowedMCPToolsets enforces toolset access on DispatchToolset", func(t *testing.T) {
		idCtx := &domain.IdentityContext{
			OrgID:                 "org-1",
			KeyPrefix:             "sk-gw-ts",
			KeyAllowedMCPToolsets: []string{"other-toolset"},
		}
		body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
		resp, _, err := hub.DispatchToolset(ctx, idCtx, "gh-ops", body, http.Header{})
		if err != nil {
			t.Fatalf("DispatchToolset unexpected err: %v", err)
		}
		if resp == nil || resp.Error == nil {
			t.Fatalf("expected JSON-RPC forbidden error for restricted toolset, got %+v", resp)
		}
	})

	t.Run("filterScopedToolsListResult filters cached tools without mutating original map", func(t *testing.T) {
		orig := map[string]any{
			"tools": []any{
				map[string]any{"name": "get_issue"},
				map[string]any{"name": "delete_repo"},
				map[string]any{"name": "list_prs"},
			},
		}
		idCtx := &domain.IdentityContext{
			OrgID:              "org-1",
			KeyAllowedMCPTools: []string{"github:get_issue"},
		}
		filtered := hub.filterScopedToolsListResult(ctx, idCtx, "github", orig).(map[string]any)
		if len(filtered["tools"].([]any)) != 1 {
			t.Fatalf("expected 1 filtered tool, got %+v", filtered["tools"])
		}
		if len(orig["tools"].([]any)) != 3 {
			t.Fatalf("cached original map was mutated: %+v", orig["tools"])
		}
	})
}
