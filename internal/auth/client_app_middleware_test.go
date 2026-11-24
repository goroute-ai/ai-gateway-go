package auth_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

func TestDataPlaneClientAppEnforcement(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	if err := repo.CreateOrganization(ctx, &domain.Organization{ID: "org-app", Name: "Client App Org", IsActive: true}); err != nil {
		t.Fatalf("create org: %v", err)
	}
	teamRestricted := &domain.Team{
		ID:                "team-cursor-only",
		OrgID:             "org-app",
		Name:              "Cursor Team",
		IsActive:          true,
		AllowedClientApps: []string{"cursor"},
	}
	if err := repo.CreateTeam(ctx, teamRestricted); err != nil {
		t.Fatalf("create team: %v", err)
	}

	svc := auth.NewService(repo, nil, "sk-gw-master-app-test", time.Minute, time.Minute)
	rbac := auth.NewRBACEngine(repo)

	// 1. Default key (AllowedClientApps = []string{} DenyAll)
	defaultKey, err := svc.IssueVirtualKey(ctx, &domain.VirtualKey{
		OrgID: "org-app",
		Name:  "Default Key",
	})
	if err != nil {
		t.Fatalf("issue default key: %v", err)
	}

	// 2. Explicit restricted key (AllowedClientApps = ["cursor", "claude-code"])
	explicitKey, err := svc.IssueVirtualKey(ctx, &domain.VirtualKey{
		OrgID:             "org-app",
		Name:              "Explicit App Key",
		AllowedClientApps: []string{"cursor", "claude-code"},
	})
	if err != nil {
		t.Fatalf("issue explicit key: %v", err)
	}

	// 3. Inheriting key (AllowedClientApps = nil -> inherits Team ["cursor"])
	inheritKey, err := svc.IssueVirtualKeyWithOptions(ctx, &domain.VirtualKey{
		OrgID:  "org-app",
		TeamID: teamRestricted.ID,
		Name:   "Inherit Team App Key",
	}, auth.IssueVirtualKeyOptions{InheritClientApps: true})
	if err != nil {
		t.Fatalf("issue inherit key: %v", err)
	}

	// 4. Wildcard key (AllowedClientApps = ["*"])
	wildcardKey, err := svc.IssueVirtualKey(ctx, &domain.VirtualKey{
		OrgID:             "org-app",
		Name:              "Wildcard App Key",
		AllowedClientApps: []string{"*"},
	})
	if err != nil {
		t.Fatalf("issue wildcard key: %v", err)
	}

	okHandler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	handler := auth.DataPlaneMiddleware(svc, rbac)(okHandler)

	call := func(rawKey, headerName, headerVal string) (int, string) {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
		req.Header.Set("Authorization", "Bearer "+rawKey)
		if headerName != "" {
			req.Header.Set(headerName, headerVal)
		}
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		var body struct {
			Error struct {
				Code string `json:"code"`
			} `json:"error"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &body)
		return rec.Code, body.Error.Code
	}

	// Default mode: require_client_app_header = false
	if status, _ := call(defaultKey.RawKey, "", ""); status != http.StatusOK {
		t.Fatalf("expected backward-compatible 200 for default [] key without header, got %d", status)
	}
	if status, code := call(defaultKey.RawKey, auth.HeaderClientApp, "cursor"); status != http.StatusForbidden || code != "client_app_restricted" {
		t.Fatalf("expected 403 client_app_restricted for default [] key with header, got %d (%s)", status, code)
	}

	// Explicit restricted key MUST NOT allow header omission bypass!
	if status, code := call(explicitKey.RawKey, "", ""); status != http.StatusForbidden || code != "client_app_required" {
		t.Fatalf("expected 403 client_app_required when header omitted for explicit allowlist, got %d (%s)", status, code)
	}
	if status, _ := call(explicitKey.RawKey, auth.HeaderClientApp, "cursor"); status != http.StatusOK {
		t.Fatalf("expected 200 for allowed X-Gateway-Client-App: cursor, got %d", status)
	}
	if status, _ := call(explicitKey.RawKey, auth.HeaderClientAppFallback, "claude-code"); status != http.StatusOK {
		t.Fatalf("expected 200 for allowed fallback X-Client-App: claude-code, got %d", status)
	}
	if status, code := call(explicitKey.RawKey, auth.HeaderClientApp, "curl"); status != http.StatusForbidden || code != "client_app_restricted" {
		t.Fatalf("expected 403 client_app_restricted for disallowed app curl, got %d (%s)", status, code)
	}

	// Inheriting key inherits Team ["cursor"]
	if status, code := call(inheritKey.RawKey, "", ""); status != http.StatusForbidden || code != "client_app_required" {
		t.Fatalf("expected 403 client_app_required when inheriting team restricted allowlist without header, got %d (%s)", status, code)
	}
	if status, _ := call(inheritKey.RawKey, auth.HeaderClientApp, "cursor"); status != http.StatusOK {
		t.Fatalf("expected 200 for team-inherited cursor app, got %d", status)
	}
	if status, code := call(inheritKey.RawKey, auth.HeaderClientApp, "vscode"); status != http.StatusForbidden || code != "client_app_restricted" {
		t.Fatalf("expected 403 client_app_restricted for non-team app vscode, got %d (%s)", status, code)
	}

	// Wildcard key allows omitted header when require_client_app_header = false, requires header when true
	if status, _ := call(wildcardKey.RawKey, "", ""); status != http.StatusOK {
		t.Fatalf("expected 200 for wildcard key without header when require=false, got %d", status)
	}
	svc.SetRequireClientAppHeader(true)
	defer svc.SetRequireClientAppHeader(false)
	if status, code := call(wildcardKey.RawKey, "", ""); status != http.StatusForbidden || code != "client_app_required" {
		t.Fatalf("expected 403 client_app_required for wildcard key without header when require=true, got %d (%s)", status, code)
	}
	if status, _ := call(wildcardKey.RawKey, auth.HeaderClientApp, "any-app"); status != http.StatusOK {
		t.Fatalf("expected 200 for wildcard key with header when require=true, got %d", status)
	}
}
