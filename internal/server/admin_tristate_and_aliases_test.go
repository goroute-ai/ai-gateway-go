package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/server"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

func TestAdminIssueKeyTriStateAndAPIAliases(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	if err := repo.CreateOrganization(ctx, &domain.Organization{ID: "org-hard", Name: "Hardening Org", IsActive: true}); err != nil {
		t.Fatalf("create org: %v", err)
	}
	if err := repo.CreateTeam(ctx, &domain.Team{ID: "team-hard", OrgID: "org-hard", Name: "Hardening Team", IsActive: true}); err != nil {
		t.Fatalf("create team: %v", err)
	}
	if err := repo.CreateUser(ctx, &domain.User{ID: "usr-hard", OrgID: "org-hard", Email: "dev@hard.example", Name: "Dev", Role: domain.RoleDeveloper, IsActive: true}); err != nil {
		t.Fatalf("create user: %v", err)
	}

	cfg := config.Default()
	cfg.Auth.MasterAdminKey = "sk-gw-master-hardening-test"
	cfg.Auth.DefaultOrgID = "org-hard"

	gw, err := server.New(cfg, repo, nil, nil)
	if err != nil {
		t.Fatalf("server.New: %v", err)
	}
	gw.StartWorkers(ctx)
	defer gw.Shutdown(ctx)
	ts := httptest.NewServer(gw.Handler())
	defer ts.Close()

	doJSON := func(method, path string, rawBody string) (int, map[string]any) {
		t.Helper()
		req, err := http.NewRequest(method, ts.URL+path, bytes.NewBufferString(rawBody))
		if err != nil {
			t.Fatalf("new req: %v", err)
		}
		req.Header.Set("Authorization", "Bearer "+cfg.Auth.MasterAdminKey)
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("do %s %s: %v", method, path, err)
		}
		defer resp.Body.Close()
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return resp.StatusCode, out
	}

	t.Run("IssueKeyTriState single-call null vs omitted vs empty array", func(t *testing.T) {
		// 1. Omitted -> fail-closed []string{} (DenyAll)
		status, out := doJSON(http.MethodPost, "/admin/v1/keys", `{"org_id":"org-hard","team_id":"team-hard","name":"k-omitted"}`)
		if status != http.StatusCreated {
			t.Fatalf("expected 201 for omitted key, got %d (%v)", status, out)
		}
		kOmitted, err := repo.GetVirtualKeyByID(ctx, out["id"].(string))
		if err != nil {
			t.Fatalf("get omitted key: %v", err)
		}
		if kOmitted.AllowedMCPServers == nil || len(kOmitted.AllowedMCPServers) != 0 {
			t.Fatalf("expected non-nil empty AllowedMCPServers for omitted field, got %#v", kOmitted.AllowedMCPServers)
		}
		if kOmitted.AllowedA2AAgents == nil || len(kOmitted.AllowedA2AAgents) != 0 {
			t.Fatalf("expected non-nil empty AllowedA2AAgents for omitted field, got %#v", kOmitted.AllowedA2AAgents)
		}
		if kOmitted.AllowedClientApps == nil || len(kOmitted.AllowedClientApps) != 0 {
			t.Fatalf("expected non-nil empty AllowedClientApps for omitted field, got %#v", kOmitted.AllowedClientApps)
		}

		// 2. Explicit null -> SQL NULL (Inherit) in a single POST call!
		status, out = doJSON(http.MethodPost, "/admin/v1/keys", `{"org_id":"org-hard","team_id":"team-hard","name":"k-inherit","allowed_mcp_servers":null,"allowed_a2a_agents":null,"allowed_client_apps":null}`)
		if status != http.StatusCreated {
			t.Fatalf("expected 201 for inherit key, got %d (%v)", status, out)
		}
		kInherit, err := repo.GetVirtualKeyByID(ctx, out["id"].(string))
		if err != nil {
			t.Fatalf("get inherit key: %v", err)
		}
		if kInherit.AllowedMCPServers != nil || kInherit.AllowedA2AAgents != nil || kInherit.AllowedClientApps != nil {
			t.Fatalf("expected nil (Inherit) for explicit null fields, got mcp=%#v a2a=%#v apps=%#v",
				kInherit.AllowedMCPServers, kInherit.AllowedA2AAgents, kInherit.AllowedClientApps)
		}

		// 3. Explicit [] -> DenyAll, explicit ["srv"] -> allowlist
		status, out = doJSON(http.MethodPost, "/admin/v1/keys", `{"org_id":"org-hard","team_id":"team-hard","name":"k-explicit","allowed_mcp_servers":["mcp-1"],"allowed_a2a_agents":[],"allowed_client_apps":["cursor"]}`)
		if status != http.StatusCreated {
			t.Fatalf("expected 201 for explicit key, got %d (%v)", status, out)
		}
		kExp, err := repo.GetVirtualKeyByID(ctx, out["id"].(string))
		if err != nil {
			t.Fatalf("get explicit key: %v", err)
		}
		if len(kExp.AllowedMCPServers) != 1 || kExp.AllowedMCPServers[0] != "mcp-1" {
			t.Fatalf("unexpected AllowedMCPServers: %#v", kExp.AllowedMCPServers)
		}
		if kExp.AllowedA2AAgents == nil || len(kExp.AllowedA2AAgents) != 0 {
			t.Fatalf("expected non-nil empty AllowedA2AAgents, got %#v", kExp.AllowedA2AAgents)
		}
		if len(kExp.AllowedClientApps) != 1 || kExp.AllowedClientApps[0] != "cursor" {
			t.Fatalf("unexpected AllowedClientApps: %#v", kExp.AllowedClientApps)
		}
	})

	t.Run("QuotaScopeAlias virtual_key normalizes to key on quotas and budget-windows", func(t *testing.T) {
		status, qOut := doJSON(http.MethodPut, "/admin/v1/quotas", `{"org_id":"org-hard","scope_type":"virtual_key","scope_id":"vk-alias-1","rpm_limit":50}`)
		if status != http.StatusOK || qOut["scope_type"] != "key" {
			t.Fatalf("expected 200 with canonical scope_type=key, got %d (%v)", status, qOut)
		}
		status, qList := doJSON(http.MethodGet, "/admin/v1/quotas?org_id=org-hard&scope_type=virtual_key", "")
		if status != http.StatusOK {
			t.Fatalf("expected 200 listing quotas by virtual_key alias, got %d (%v)", status, qList)
		}
		data, _ := qList["data"].([]any)
		if len(data) != 1 {
			t.Fatalf("expected 1 quota returned for scope_type=virtual_key filter, got %d", len(data))
		}

		status, bwOut := doJSON(http.MethodPut, "/admin/v1/budget-windows", `{"org_id":"org-hard","scope_type":"virtual_key","scope_id":"vk-alias-1","window_type":"daily","max_budget_micros":500000}`)
		if status != http.StatusOK || bwOut["scope_type"] != "key" {
			t.Fatalf("expected 200 with canonical scope_type=key on budget-windows, got %d (%v)", status, bwOut)
		}
		status, bwList := doJSON(http.MethodGet, "/admin/v1/budget-windows?org_id=org-hard&scope_type=virtual_key", "")
		if status != http.StatusOK {
			t.Fatalf("expected 200 listing budget-windows by virtual_key alias, got %d (%v)", status, bwList)
		}
		bwData, _ := bwList["data"].([]any)
		if len(bwData) != 1 {
			t.Fatalf("expected 1 budget window returned for scope_type=virtual_key filter, got %d", len(bwData))
		}
	})

	t.Run("TeamMemberRoleAlias member normalizes to developer", func(t *testing.T) {
		status, mOut := doJSON(http.MethodPost, "/admin/v1/teams/team-hard/members", `{"org_id":"org-hard","user_id":"usr-hard","role":"member"}`)
		if status != http.StatusOK || mOut["role"] != "developer" {
			t.Fatalf("expected 200 with canonical role=developer, got %d (%v)", status, mOut)
		}
		status, bulkOut := doJSON(http.MethodPost, "/admin/v1/teams/team-hard/members/bulk", `{"org_id":"org-hard","members":[{"user_id":"usr-hard","role":"member"}]}`)
		if status != http.StatusOK {
			t.Fatalf("expected 200 for bulk member alias, got %d (%v)", status, bulkOut)
		}
	})

	t.Run("ProjectQuotaAlias enforce_model_quota accepted and conflicting values rejected", func(t *testing.T) {
		status, pOut := doJSON(http.MethodPost, "/admin/v1/projects", `{"org_id":"org-hard","team_id":"team-hard","name":"proj-alias","enforce_model_quota":true}`)
		if status != http.StatusCreated || pOut["enforce_project_model_quota"] != true {
			t.Fatalf("expected 201 with enforce_project_model_quota=true via alias, got %d (%v)", status, pOut)
		}
		projID := pOut["id"].(string)

		// Conflict between canonical and alias -> 400
		status, cOut := doJSON(http.MethodPut, "/admin/v1/projects/"+projID, `{"org_id":"org-hard","enforce_project_model_quota":true,"enforce_model_quota":false}`)
		if status != http.StatusBadRequest {
			t.Fatalf("expected 400 for conflicting enforce_project_model_quota/enforce_model_quota, got %d (%v)", status, cOut)
		}

		// Valid update via alias -> 200
		status, uOut := doJSON(http.MethodPut, "/admin/v1/projects/"+projID, `{"org_id":"org-hard","enforce_model_quota":false}`)
		if status != http.StatusOK || uOut["enforce_project_model_quota"] != false {
			t.Fatalf("expected 200 updating via enforce_model_quota alias, got %d (%v)", status, uOut)
		}
	})
}
