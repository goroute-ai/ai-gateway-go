package auth_test

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

func TestVaultEnvelopeEncryptionAndVirtualKeyRBAC(t *testing.T) {
	ctx := context.Background()

	// 1. Test AES-256-GCM Envelope Encryption Vault
	vault, err := auth.NewVault("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatalf("new vault: %v", err)
	}
	cred := &domain.ProviderCredential{
		Provider: domain.ProviderOpenAI,
		Name:     "prod-openai",
	}
	secretAPIKey := "sk-proj-super-secret-openai-key-999"
	if err := vault.EncryptCredential(cred, secretAPIKey); err != nil {
		t.Fatalf("encrypt credential: %v", err)
	}
	if cred.DecryptedAPIKey != "" || len(cred.EncryptedAPIKey) == 0 || len(cred.EncryptedDEK) == 0 {
		t.Fatalf("expected encrypted envelope fields to be populated and plaintext cleared")
	}
	decrypted, err := vault.DecryptCredential(cred)
	if err != nil || decrypted != secretAPIKey {
		t.Fatalf("decrypt credential mismatch: got %q, want %q (err=%v)", decrypted, secretAPIKey, err)
	}

	// 2. Test Virtual Key Issuance, L1 Cache Lookup, Revocation, and 4-Layer RBAC
	repo := storage.NewMemoryRepository()
	org := &domain.Organization{Name: "Acme Corp", Slug: "acme", IsActive: true}
	_ = repo.CreateOrganization(ctx, org)

	// Enable OpenAI subscription, disable Anthropic
	_ = repo.SetOrgProviderSubscription(ctx, &domain.OrgProviderSubscription{
		OrgID: org.ID, Provider: domain.ProviderOpenAI, IsEnabled: true,
	})
	_ = repo.SetOrgProviderSubscription(ctx, &domain.OrgProviderSubscription{
		OrgID: org.ID, Provider: domain.ProviderAnthropic, IsEnabled: false,
	})

	authSvc := auth.NewService(repo, nil, "sk-gw-master-admin-secret-key", 10*time.Second, time.Minute)
	rbac := auth.NewRBACEngine(repo)

	vk, err := authSvc.IssueVirtualKey(ctx, &domain.VirtualKey{
		OrgID:         org.ID,
		Name:          "chatbot-key",
		AllowedModels: []string{"gpt-4.1", "auto"},
	})
	if err != nil {
		t.Fatalf("issue virtual key: %v", err)
	}
	if !strings.HasPrefix(vk.RawKey, "sk-gw-") {
		t.Fatalf("expected sk-gw- prefix, got %q", vk.RawKey)
	}

	// Authenticate (Cold -> Hydrates L1)
	idCtx, err := authSvc.AuthenticateVirtualKey(ctx, vk.RawKey)
	if err != nil || idCtx.VirtualKeyID != vk.ID {
		t.Fatalf("authenticate key failed: %v", err)
	}

	// Authenticate again (Warm L1 hit)
	idCtx2, err := authSvc.AuthenticateVirtualKey(ctx, vk.RawKey)
	if err != nil || idCtx2.OrgID != org.ID {
		t.Fatalf("warm L1 auth failed: %v", err)
	}

	// RBAC: Allowed model ("gpt-4.1") passes
	if err := rbac.AuthorizeRequestedModel(idCtx, "gpt-4.1"); err != nil {
		t.Fatalf("expected gpt-4.1 to be allowed: %v", err)
	}
	// RBAC: Disallowed model ("claude-sonnet-4") fails
	if err := rbac.AuthorizeRequestedModel(idCtx, "claude-sonnet-4"); err == nil {
		t.Fatalf("expected claude-sonnet-4 to be rejected by key allowlist")
	}

	// Layer 2 RBAC: Deployment with unsubscribed provider (Anthropic) fails
	antModel, _ := repo.GetGlobalModel(ctx, "anthropic/claude-sonnet-4-20250514")
	if err := rbac.AuthorizeDeployment(ctx, org.ID, &domain.Deployment{GlobalModel: antModel}); err == nil {
		t.Fatalf("expected unsubscribed provider deployment to be rejected")
	}

	// Revoke key -> immediate L1 eviction -> subsequent auth fails
	if err := authSvc.RevokeKey(ctx, vk.ID); err != nil {
		t.Fatalf("revoke key: %v", err)
	}
	if _, err := authSvc.AuthenticateVirtualKey(ctx, vk.RawKey); err == nil {
		t.Fatalf("expected revoked key authentication to fail immediately")
	}
}

func TestExtractGatewayCredentialsAmbiguity(t *testing.T) {
	t.Run("Single Bearer token succeeds", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, "/v1/models", nil)
		req.Header.Set("Authorization", "Bearer sk-gw-valid-token-1")
		token, err := auth.ExtractGatewayCredentials(req)
		if err != nil || token != "sk-gw-valid-token-1" {
			t.Fatalf("unexpected result: token=%q err=%v", token, err)
		}
	})

	t.Run("Single x-api-key succeeds", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, "/v1/models", nil)
		req.Header.Set("x-api-key", "sk-gw-valid-token-2")
		token, err := auth.ExtractGatewayCredentials(req)
		if err != nil || token != "sk-gw-valid-token-2" {
			t.Fatalf("unexpected result: token=%q err=%v", token, err)
		}
	})

	t.Run("Identical Bearer and x-api-key succeeds", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, "/v1/models", nil)
		req.Header.Set("Authorization", "Bearer sk-gw-same-token")
		req.Header.Set("x-api-key", "sk-gw-same-token")
		token, err := auth.ExtractGatewayCredentials(req)
		if err != nil || token != "sk-gw-same-token" {
			t.Fatalf("unexpected result: token=%q err=%v", token, err)
		}
	})

	t.Run("Conflicting Bearer and x-api-key returns 400 ambiguous_gateway_credentials", func(t *testing.T) {
		req, _ := http.NewRequest(http.MethodGet, "/v1/models", nil)
		req.Header.Set("Authorization", "Bearer sk-gw-token-a")
		req.Header.Set("x-api-key", "sk-gw-token-b")
		token, err := auth.ExtractGatewayCredentials(req)
		if err == nil {
			t.Fatalf("expected ambiguous_gateway_credentials error, got token=%q", token)
		}
		gwErr, ok := err.(*domain.GatewayError)
		if !ok || gwErr.StatusCode != http.StatusBadRequest || gwErr.Code != "ambiguous_gateway_credentials" {
			t.Fatalf("unexpected error: %+v", err)
		}
	})
}

func TestAuthenticateVirtualKeyRejectsExpiredL1Identity(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	org := &domain.Organization{Name: "Expiring key org", Slug: "expiring-key-org", IsActive: true}
	if err := repo.CreateOrganization(ctx, org); err != nil {
		t.Fatalf("create organization: %v", err)
	}

	expiresAt := time.Now().UTC().Add(30 * time.Millisecond)
	svc := auth.NewService(repo, nil, "", time.Minute, time.Minute)
	key, err := svc.IssueVirtualKey(ctx, &domain.VirtualKey{
		OrgID:     org.ID,
		Name:      "short-lived",
		ExpiresAt: &expiresAt,
	})
	if err != nil {
		t.Fatalf("issue key: %v", err)
	}
	if _, err := svc.AuthenticateVirtualKey(ctx, key.RawKey); err != nil {
		t.Fatalf("authenticate before expiration: %v", err)
	}

	time.Sleep(time.Until(expiresAt) + 5*time.Millisecond)
	_, err = svc.AuthenticateVirtualKey(ctx, key.RawKey)
	if err == nil {
		t.Fatal("expected expired cached identity to be rejected")
	}
	gwErr, ok := err.(*domain.GatewayError)
	if !ok || gwErr.Code != "expired_api_key" || gwErr.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unexpected expiration error: %+v", err)
	}
}

func TestExtractGatewayCredentialsQueryAndSubprotocolOnlyOnRealtimeWebSocket(t *testing.T) {
	tests := []struct {
		name        string
		method      string
		target      string
		upgrade     bool
		subprotocol string
		want        string
	}{
		{
			name:   "query api key is ignored on chat endpoint",
			method: http.MethodPost,
			target: "/v1/chat/completions?api_key=query-secret",
		},
		{
			name:   "query token is ignored on models endpoint",
			method: http.MethodGet,
			target: "/v1/models?token=query-secret",
		},
		{
			name:   "query credential is ignored without websocket upgrade",
			method: http.MethodGet,
			target: "/v1/realtime?api_key=query-secret",
		},
		{
			name:        "subprotocol credential is ignored on ordinary endpoint",
			method:      http.MethodGet,
			target:      "/v1/models",
			subprotocol: "realtime, openai-insecure-api-key.protocol-secret",
		},
		{
			name:    "query api key works on realtime websocket",
			method:  http.MethodGet,
			target:  "/v1/realtime?api_key=query-secret",
			upgrade: true,
			want:    "query-secret",
		},
		{
			name:    "query token works on realtime websocket alias",
			method:  http.MethodGet,
			target:  "/openai/v1/realtime?token=query-secret",
			upgrade: true,
			want:    "query-secret",
		},
		{
			name:        "subprotocol credential works on realtime websocket",
			method:      http.MethodGet,
			target:      "/realtime",
			upgrade:     true,
			subprotocol: "realtime, openai-insecure-api-key.protocol-secret",
			want:        "protocol-secret",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req, err := http.NewRequest(tt.method, tt.target, nil)
			if err != nil {
				t.Fatalf("create request: %v", err)
			}
			if tt.upgrade {
				req.Header.Set("Upgrade", "websocket")
				req.Header.Set("Connection", "keep-alive, Upgrade")
			}
			if tt.subprotocol != "" {
				req.Header.Set("Sec-WebSocket-Protocol", tt.subprotocol)
			}
			got, err := auth.ExtractGatewayCredentials(req)
			if err != nil {
				t.Fatalf("extract credentials: %v", err)
			}
			if got != tt.want {
				t.Fatalf("credential = %q, want %q", got, tt.want)
			}
		})
	}
}

func Test3StateRBACAllowlists(t *testing.T) {
	repo := storage.NewMemoryRepository()
	rbac := auth.NewRBACEngine(repo)

	t.Run("DenyAll on empty non-nil slice", func(t *testing.T) {
		idCtx := &domain.IdentityContext{
			VirtualKeyID:         "vk_deny_all",
			KeyAllowedMCPServers: []string{}, // DenyAll
			KeyAllowedA2AAgents:  []string{}, // DenyAll
		}
		if err := rbac.AuthorizeMCPServer(idCtx, "weather-server"); err == nil {
			t.Fatalf("expected AuthorizeMCPServer to fail with DenyAll, got nil")
		}
		if err := rbac.AuthorizeA2AAgent(idCtx, "assistant-agent"); err == nil {
			t.Fatalf("expected AuthorizeA2AAgent to fail with DenyAll, got nil")
		}
	})

	t.Run("Inherit on nil slice", func(t *testing.T) {
		idCtx := &domain.IdentityContext{
			VirtualKeyID:          "vk_inherit",
			KeyAllowedMCPServers:  nil, // Inherit from team/org
			TeamAllowedMCPServers: []string{"weather-server"},
		}
		if err := rbac.AuthorizeMCPServer(idCtx, "weather-server"); err != nil {
			t.Fatalf("expected AuthorizeMCPServer to succeed via team allowlist: %v", err)
		}
		if err := rbac.AuthorizeMCPServer(idCtx, "finance-server"); err == nil {
			t.Fatalf("expected AuthorizeMCPServer to fail for unlisted finance-server")
		}
	})

	t.Run("Explicit allowlist on populated slice", func(t *testing.T) {
		idCtx := &domain.IdentityContext{
			VirtualKeyID:         "vk_explicit",
			KeyAllowedMCPServers: []string{"calendar-server"},
		}
		if err := rbac.AuthorizeMCPServer(idCtx, "calendar-server"); err != nil {
			t.Fatalf("expected calendar-server to be allowed: %v", err)
		}
		if err := rbac.AuthorizeMCPServer(idCtx, "weather-server"); err == nil {
			t.Fatalf("expected weather-server to be rejected")
		}
	})

	t.Run("Newly issued virtual keys default to DenyAll for MCP and A2A", func(t *testing.T) {
		ctx := context.Background()
		org := &domain.Organization{Name: "Test Org", Slug: "test-org", IsActive: true}
		_ = repo.CreateOrganization(ctx, org)

		authSvc := auth.NewService(repo, nil, "sk-gw-master-admin-secret-key", 10*time.Second, time.Minute)
		vk, err := authSvc.IssueVirtualKey(ctx, &domain.VirtualKey{
			OrgID: org.ID,
			Name:  "default-key",
		})
		if err != nil {
			t.Fatalf("issue key failed: %v", err)
		}

		if vk.AllowedMCPServers == nil || len(vk.AllowedMCPServers) != 0 {
			t.Fatalf("expected AllowedMCPServers to default to DenyAll ([]), got: %v", vk.AllowedMCPServers)
		}
		if vk.AllowedA2AAgents == nil || len(vk.AllowedA2AAgents) != 0 {
			t.Fatalf("expected AllowedA2AAgents to default to DenyAll ([]), got: %v", vk.AllowedA2AAgents)
		}
	})
}

type failingAuthRepo struct {
	storage.Repository
	failSubs     bool
	failPols     bool
	failTeam     bool
	getTeamCalls int
}

func (f *failingAuthRepo) GetTeam(ctx context.Context, id string) (*domain.Team, error) {
	f.getTeamCalls++
	if f.failTeam {
		return nil, fmt.Errorf("simulated db connection timeout")
	}
	return f.Repository.GetTeam(ctx, id)
}

func (f *failingAuthRepo) GetOrgProviderSubscriptions(ctx context.Context, orgID string) ([]*domain.OrgProviderSubscription, error) {
	if f.failSubs {
		return nil, fmt.Errorf("simulated db connection timeout")
	}
	return f.Repository.GetOrgProviderSubscriptions(ctx, orgID)
}

func (f *failingAuthRepo) GetOrgModelPolicies(ctx context.Context, orgID string) ([]*domain.OrgModelPolicy, error) {
	if f.failPols {
		return nil, fmt.Errorf("simulated db connection timeout")
	}
	return f.Repository.GetOrgModelPolicies(ctx, orgID)
}

func TestRBACEngine_AuthorizeDeploymentFailClosed(t *testing.T) {
	ctx := context.Background()
	memRepo := storage.NewMemoryRepository()
	org := &domain.Organization{ID: "org-auth-fc", Name: "Fail Closed Org", Slug: "fail-closed-auth", IsActive: true}
	_ = memRepo.CreateOrganization(ctx, org)

	dep := &domain.Deployment{
		ID: "dep-1",
		GlobalModel: &domain.GlobalModel{
			ID:       "openai/gpt-4.1",
			Provider: domain.ProviderOpenAI,
		},
	}

	// 1. Subscription query fails with db error -> AuthorizeDeployment MUST FAIL CLOSED (return error)
	failSubsRepo := &failingAuthRepo{Repository: memRepo, failSubs: true}
	rbacSubs := auth.NewRBACEngine(failSubsRepo)
	err := rbacSubs.AuthorizeDeployment(ctx, org.ID, dep)
	if err == nil {
		t.Fatal("expected AuthorizeDeployment to fail closed on subscription repo error, got nil")
	}
	gwErr, ok := err.(*domain.GatewayError)
	if !ok || gwErr.StatusCode != http.StatusInternalServerError || gwErr.Code != "auth_repository_error" {
		t.Fatalf("expected 500 auth_repository_error, got %+v", err)
	}

	// 2. Model policy query fails with db error -> AuthorizeDeployment MUST FAIL CLOSED (return error)
	failPolsRepo := &failingAuthRepo{Repository: memRepo, failPols: true}
	rbacPols := auth.NewRBACEngine(failPolsRepo)
	err = rbacPols.AuthorizeDeployment(ctx, org.ID, dep)
	if err == nil {
		t.Fatal("expected AuthorizeDeployment to fail closed on model policy repo error, got nil")
	}
	gwErr, ok = err.(*domain.GatewayError)
	if !ok || gwErr.StatusCode != http.StatusInternalServerError || gwErr.Code != "auth_repository_error" {
		t.Fatalf("expected 500 auth_repository_error, got %+v", err)
	}
}

func TestAuthenticateVirtualKey_TeamFailClosed(t *testing.T) {
	ctx := context.Background()

	t.Run("DB failure on GetTeam rejects 503 and does not cache", func(t *testing.T) {
		memRepo := storage.NewMemoryRepository()
		org := &domain.Organization{ID: "org-team-fc", Name: "Team Fail Closed Org", Slug: "team-fc", IsActive: true}
		if err := memRepo.CreateOrganization(ctx, org); err != nil {
			t.Fatalf("create org: %v", err)
		}
		team := &domain.Team{
			ID:                "team-fc-1",
			OrgID:             org.ID,
			Name:              "eng",
			AllowedModels:     []string{"gpt-4.1"},
			AllowedMCPServers: []string{}, // DenyAll
			AllowedA2AAgents:  []string{"agent-1"},
			AllowedClientApps: nil, // Inherit
			RPMLimit:          42,
			IsActive:          true,
		}
		if err := memRepo.CreateTeam(ctx, team); err != nil {
			t.Fatalf("create team: %v", err)
		}

		repo := &failingAuthRepo{Repository: memRepo, failTeam: true}
		svc := auth.NewService(repo, nil, "sk-gw-master-admin-secret-key", 10*time.Second, time.Minute)
		vk, err := svc.IssueVirtualKey(ctx, &domain.VirtualKey{
			OrgID:  org.ID,
			TeamID: team.ID,
			Name:   "team-key",
		})
		if err != nil {
			t.Fatalf("issue virtual key: %v", err)
		}

		// 1. Transient DB error on GetTeam must fail closed with 503 team_policy_unavailable.
		_, err = svc.AuthenticateVirtualKey(ctx, vk.RawKey)
		if err == nil {
			t.Fatal("expected AuthenticateVirtualKey to fail closed on GetTeam DB error")
		}
		gwErr, ok := err.(*domain.GatewayError)
		if !ok || gwErr.StatusCode != http.StatusServiceUnavailable || gwErr.Code != "team_policy_unavailable" {
			t.Fatalf("expected 503 team_policy_unavailable, got %+v", err)
		}

		// 2. Identity must NOT have been cached: recovering DB must re-query GetTeam and resolve team policy.
		repo.failTeam = false
		idCtx, err := svc.AuthenticateVirtualKey(ctx, vk.RawKey)
		if err != nil {
			t.Fatalf("expected auth to succeed after DB recovery, got: %v", err)
		}
		if repo.getTeamCalls != 2 {
			t.Fatalf("expected GetTeam to be called twice (no caching on failure), got %d", repo.getTeamCalls)
		}
		if idCtx.TeamRPMLimit != 42 || len(idCtx.TeamAllowedModels) != 1 || idCtx.TeamAllowedModels[0] != "gpt-4.1" {
			t.Fatalf("expected resolved team policy on identity, got %+v", idCtx)
		}
		if idCtx.TeamAllowedMCPServers == nil || len(idCtx.TeamAllowedMCPServers) != 0 {
			t.Fatalf("expected non-nil empty TeamAllowedMCPServers (DenyAll), got %#v", idCtx.TeamAllowedMCPServers)
		}
		if idCtx.TeamAllowedClientApps != nil {
			t.Fatalf("expected nil TeamAllowedClientApps (Inherit), got %#v", idCtx.TeamAllowedClientApps)
		}
	})

	t.Run("Missing team rejects 403 team_not_found", func(t *testing.T) {
		memRepo := storage.NewMemoryRepository()
		org := &domain.Organization{ID: "org-team-missing", Name: "Missing Team Org", Slug: "team-missing", IsActive: true}
		if err := memRepo.CreateOrganization(ctx, org); err != nil {
			t.Fatalf("create org: %v", err)
		}

		svc := auth.NewService(memRepo, nil, "sk-gw-master-admin-secret-key", 10*time.Second, time.Minute)
		vk, err := svc.IssueVirtualKey(ctx, &domain.VirtualKey{
			OrgID:  org.ID,
			TeamID: "nonexistent-team-id",
			Name:   "orphan-team-key",
		})
		if err != nil {
			t.Fatalf("issue virtual key: %v", err)
		}

		_, err = svc.AuthenticateVirtualKey(ctx, vk.RawKey)
		if err == nil {
			t.Fatal("expected AuthenticateVirtualKey to reject missing team")
		}
		gwErr, ok := err.(*domain.GatewayError)
		if !ok || gwErr.StatusCode != http.StatusForbidden || gwErr.Code != "team_not_found" {
			t.Fatalf("expected 403 team_not_found, got %+v", err)
		}
	})

	t.Run("Inactive team rejects 403 team_inactive", func(t *testing.T) {
		memRepo := storage.NewMemoryRepository()
		org := &domain.Organization{ID: "org-team-inactive", Name: "Inactive Team Org", Slug: "team-inactive", IsActive: true}
		if err := memRepo.CreateOrganization(ctx, org); err != nil {
			t.Fatalf("create org: %v", err)
		}
		team := &domain.Team{
			ID:       "team-inactive-1",
			OrgID:    org.ID,
			Name:     "disabled-team",
			IsActive: false,
		}
		if err := memRepo.CreateTeam(ctx, team); err != nil {
			t.Fatalf("create team: %v", err)
		}

		svc := auth.NewService(memRepo, nil, "sk-gw-master-admin-secret-key", 10*time.Second, time.Minute)
		vk, err := svc.IssueVirtualKey(ctx, &domain.VirtualKey{
			OrgID:  org.ID,
			TeamID: team.ID,
			Name:   "inactive-team-key",
		})
		if err != nil {
			t.Fatalf("issue virtual key: %v", err)
		}

		_, err = svc.AuthenticateVirtualKey(ctx, vk.RawKey)
		if err == nil {
			t.Fatal("expected AuthenticateVirtualKey to reject inactive team")
		}
		gwErr, ok := err.(*domain.GatewayError)
		if !ok || gwErr.StatusCode != http.StatusForbidden || gwErr.Code != "team_inactive" {
			t.Fatalf("expected 403 team_inactive, got %+v", err)
		}
	})
}
