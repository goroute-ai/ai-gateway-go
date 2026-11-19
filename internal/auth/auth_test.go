package auth_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
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

		repo := &failingAuthRepo{Repository: memRepo, failTeam: false}
		svc := auth.NewService(repo, nil, "sk-gw-master-admin-secret-key", 10*time.Second, time.Minute)
		vk, err := svc.IssueVirtualKey(ctx, &domain.VirtualKey{
			OrgID:  org.ID,
			TeamID: team.ID,
			Name:   "team-key",
		})
		if err != nil {
			t.Fatalf("issue virtual key: %v", err)
		}
		repo.failTeam = true
		repo.getTeamCalls = 0

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
		rawKey := "sk-gw-orphaned-team-key-1234567890"
		if err := memRepo.CreateVirtualKey(ctx, &domain.VirtualKey{
			ID:        "vk-orphan-team",
			OrgID:     org.ID,
			TeamID:    "nonexistent-team-id",
			Name:      "orphan-team-key",
			KeyPrefix: "sk-gw-orphan",
			KeyHash:   auth.HashKey(rawKey),
			IsActive:  true,
		}); err != nil {
			t.Fatalf("create virtual key: %v", err)
		}

		_, err := svc.AuthenticateVirtualKey(ctx, rawKey)
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

func TestAuthenticateVirtualKey_PopulatesUserLimitsAndBudget(t *testing.T) {
	ctx := context.Background()
	memRepo := storage.NewMemoryRepository()
	org := &domain.Organization{ID: "org-user-limits", Name: "User Limits Org", Slug: "user-limits", MaxConcurrentRequests: 25, IsActive: true}
	if err := memRepo.CreateOrganization(ctx, org); err != nil {
		t.Fatalf("create org: %v", err)
	}
	team := &domain.Team{ID: "team-limits-1", OrgID: org.ID, Name: "Limits Team", MaxConcurrentRequests: 11, IsActive: true}
	if err := memRepo.CreateTeam(ctx, team); err != nil {
		t.Fatalf("create team: %v", err)
	}
	user := &domain.User{
		ID:                    "usr-limits-1",
		OrgID:                 org.ID,
		TeamID:                team.ID,
		Email:                 "limits@example.com",
		Name:                  "Limits User",
		Role:                  domain.RoleDeveloper,
		RPMLimit:              120,
		TPMLimit:              50000,
		MaxConcurrentRequests: 7,
		MaxBudgetMicros:       2500000,
		SpentMicros:           450000,
		IsActive:              true,
	}
	if err := memRepo.CreateUser(ctx, user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	svc := auth.NewService(memRepo, nil, "sk-gw-master-admin-secret-key", 10*time.Second, time.Minute)
	vk, err := svc.IssueVirtualKey(ctx, &domain.VirtualKey{
		OrgID:  org.ID,
		TeamID: team.ID,
		UserID: user.ID,
		Name:   "user-scoped-key",
	})
	if err != nil {
		t.Fatalf("issue virtual key: %v", err)
	}

	idCtx, err := svc.AuthenticateVirtualKey(ctx, vk.RawKey)
	if err != nil {
		t.Fatalf("AuthenticateVirtualKey failed: %v", err)
	}
	if idCtx.UserRPMLimit != 120 || idCtx.UserTPMLimit != 50000 || idCtx.UserMaxConcurrent != 7 ||
		idCtx.UserMaxBudgetMicros != 2500000 || idCtx.UserSpentMicros != 450000 ||
		idCtx.TeamMaxConcurrent != 11 || idCtx.OrgMaxConcurrent != 25 {
		t.Fatalf("unexpected user/team/org limits/budget on IdentityContext: %+v", idCtx)
	}
}

type getUserTrackingRepo struct {
	*storage.MemoryRepository
	getUserCalls  atomic.Int32
	listUserCalls atomic.Int32
	bundleCalls   atomic.Int32
}

func (r *getUserTrackingRepo) GetUser(ctx context.Context, id string) (*domain.User, error) {
	r.getUserCalls.Add(1)
	return r.MemoryRepository.GetUser(ctx, id)
}

func (r *getUserTrackingRepo) ListUsers(ctx context.Context, orgID string) ([]*domain.User, error) {
	r.listUserCalls.Add(1)
	return nil, errors.New("ListUsers should not be called during virtual key issuance or authentication")
}

func (r *getUserTrackingRepo) GetVirtualKeyAuthBundleByHash(ctx context.Context, keyHash string, now time.Time) (*storage.VirtualKeyAuthBundle, error) {
	r.bundleCalls.Add(1)
	return r.MemoryRepository.GetVirtualKeyAuthBundleByHash(ctx, keyHash, now)
}

func TestVirtualKeyIssueAndAuthUseGetUserNotListUsers(t *testing.T) {
	ctx := context.Background()
	repo := &getUserTrackingRepo{MemoryRepository: storage.NewMemoryRepository()}

	if err := repo.CreateOrganization(ctx, &domain.Organization{ID: "org-1", Name: "Org 1", IsActive: true}); err != nil {
		t.Fatalf("CreateOrganization org-1: %v", err)
	}
	if err := repo.CreateOrganization(ctx, &domain.Organization{ID: "org-2", Name: "Org 2", IsActive: true}); err != nil {
		t.Fatalf("CreateOrganization org-2: %v", err)
	}
	if err := repo.CreateUser(ctx, &domain.User{
		ID:       "user-1",
		OrgID:    "org-1",
		Email:    "user1@example.com",
		Role:     domain.RoleDeveloper,
		IsActive: true,
		RPMLimit: 99,
	}); err != nil {
		t.Fatalf("CreateUser user-1: %v", err)
	}
	if err := repo.CreateUser(ctx, &domain.User{
		ID:       "user-inactive",
		OrgID:    "org-1",
		Email:    "inactive@example.com",
		Role:     domain.RoleDeveloper,
		IsActive: false,
	}); err != nil {
		t.Fatalf("CreateUser user-inactive: %v", err)
	}
	if err := repo.CreateUser(ctx, &domain.User{
		ID:       "user-other-org",
		OrgID:    "org-2",
		Email:    "other@example.com",
		Role:     domain.RoleDeveloper,
		IsActive: true,
	}); err != nil {
		t.Fatalf("CreateUser user-other-org: %v", err)
	}

	svc := auth.NewService(repo, nil, "master-admin", time.Minute, time.Minute)

	// Cross-org user must fail during IssueVirtualKey without calling ListUsers.
	if _, err := svc.IssueVirtualKey(ctx, &domain.VirtualKey{
		OrgID:  "org-1",
		UserID: "user-other-org",
		Name:   "cross-org",
	}); err == nil {
		t.Fatal("expected IssueVirtualKey to reject user from another org")
	}

	// Active same-org user succeeds via GetUser.
	issued, err := svc.IssueVirtualKey(ctx, &domain.VirtualKey{
		OrgID:  "org-1",
		UserID: "user-1",
		Name:   "valid-user-key",
	})
	if err != nil {
		t.Fatalf("IssueVirtualKey failed: %v", err)
	}

	idCtx, err := svc.AuthenticateVirtualKey(ctx, issued.RawKey)
	if err != nil {
		t.Fatalf("AuthenticateVirtualKey failed: %v", err)
	}
	if idCtx.UserID != "user-1" || idCtx.UserRPMLimit != 99 {
		t.Fatalf("unexpected IdentityContext: %+v", idCtx)
	}

	// Inactive user must be rejected with user_inactive.
	inactiveIssued, err := svc.IssueVirtualKey(ctx, &domain.VirtualKey{
		OrgID:  "org-1",
		UserID: "user-inactive",
		Name:   "inactive-user-key",
	})
	if err != nil {
		t.Fatalf("IssueVirtualKey for inactive user failed: %v", err)
	}
	_, err = svc.AuthenticateVirtualKey(ctx, inactiveIssued.RawKey)
	var gwErr *domain.GatewayError
	if !errors.As(err, &gwErr) || gwErr.Code != "user_inactive" {
		t.Fatalf("expected user_inactive GatewayError, got %v", err)
	}

	if got := repo.listUserCalls.Load(); got != 0 {
		t.Fatalf("expected 0 ListUsers calls, got %d", got)
	}
	if got := repo.getUserCalls.Load(); got != 3 {
		t.Fatalf("expected 3 GetUser calls from IssueVirtualKey, got %d", got)
	}
	if got := repo.bundleCalls.Load(); got != 2 {
		t.Fatalf("expected 2 GetVirtualKeyAuthBundleByHash calls from AuthenticateVirtualKey, got %d", got)
	}
}

func TestVirtualKey_UpdateAndRotateInvalidatesL1L2PubSub(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	mr := miniredis.RunT(t)
	redis1 := storage.NewRedisFabric(mr.Addr(), "", 0)
	redis2 := storage.NewRedisFabric(mr.Addr(), "", 0)
	defer redis1.Client().Close()
	defer redis2.Client().Close()

	repo := storage.NewMemoryRepository()
	org := &domain.Organization{ID: "org-rotate", Name: "Rotate Org", Slug: "rotate-org", IsActive: true}
	if err := repo.CreateOrganization(ctx, org); err != nil {
		t.Fatalf("CreateOrganization: %v", err)
	}

	svc1 := auth.NewService(repo, redis1, "master-admin", time.Minute, time.Minute)
	svc2 := auth.NewService(repo, redis2, "master-admin", time.Minute, time.Minute)
	svc2.StartInvalidationListener(ctx)
	defer svc2.StopInvalidationListener()
	time.Sleep(25 * time.Millisecond)

	issued, err := svc1.IssueVirtualKey(ctx, &domain.VirtualKey{
		OrgID:    org.ID,
		Name:     "rotatable-key",
		RPMLimit: 25,
	})
	if err != nil {
		t.Fatalf("IssueVirtualKey: %v", err)
	}
	oldRawKey := issued.RawKey
	oldPrefix := issued.KeyPrefix

	// Warm L1 and L2 on both svc1 and svc2
	if _, err := svc1.AuthenticateVirtualKey(ctx, oldRawKey); err != nil {
		t.Fatalf("svc1 AuthenticateVirtualKey(old): %v", err)
	}
	if _, err := svc2.AuthenticateVirtualKey(ctx, oldRawKey); err != nil {
		t.Fatalf("svc2 AuthenticateVirtualKey(old): %v", err)
	}

	// UpdateVirtualKey updates limits/models and invalidates cached identity
	updatedVK := *issued
	updatedVK.RPMLimit = 120
	updatedVK.AllowedModels = []string{"gpt-4.1"}
	if err := svc1.UpdateVirtualKey(ctx, &updatedVK); err != nil {
		t.Fatalf("UpdateVirtualKey: %v", err)
	}
	idAfterUpdate, err := svc1.AuthenticateVirtualKey(ctx, oldRawKey)
	if err != nil {
		t.Fatalf("svc1 AuthenticateVirtualKey after UpdateVirtualKey: %v", err)
	}
	if idAfterUpdate.KeyRPMLimit != 120 || len(idAfterUpdate.KeyAllowedModels) != 1 || idAfterUpdate.KeyAllowedModels[0] != "gpt-4.1" {
		t.Fatalf("expected updated KeyRPMLimit=120 and KeyAllowedModels=[gpt-4.1], got %+v", idAfterUpdate)
	}

	// Warm svc2 again before rotation
	if _, err := svc2.AuthenticateVirtualKey(ctx, oldRawKey); err != nil {
		t.Fatalf("svc2 AuthenticateVirtualKey before rotate: %v", err)
	}

	// RotateVirtualKey generates a new sk-gw-... key and invalidates the old hash in L1/L2/PubSub
	rotated, err := svc1.RotateVirtualKey(ctx, issued.ID)
	if err != nil {
		t.Fatalf("RotateVirtualKey: %v", err)
	}
	if !strings.HasPrefix(rotated.RawKey, "sk-gw-") || rotated.RawKey == oldRawKey {
		t.Fatalf("expected new sk-gw-... RawKey, got %q", rotated.RawKey)
	}
	if rotated.KeyPrefix == oldPrefix || !strings.HasPrefix(rotated.KeyPrefix, "sk-gw-") {
		t.Fatalf("expected updated KeyPrefix, got %q (old %q)", rotated.KeyPrefix, oldPrefix)
	}

	// Old key must immediately fail on svc1
	if _, err := svc1.AuthenticateVirtualKey(ctx, oldRawKey); err == nil {
		t.Fatal("expected old raw key to be rejected on svc1 after RotateVirtualKey")
	}

	// Wait briefly for Pub/Sub invalidation to reach svc2 and verify old key fails on svc2
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if _, err := svc2.AuthenticateVirtualKey(ctx, oldRawKey); err != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, err := svc2.AuthenticateVirtualKey(ctx, oldRawKey); err == nil {
		t.Fatal("expected old raw key to be rejected on svc2 after RotateVirtualKey Pub/Sub invalidation")
	}

	// New rotated key must authenticate on both svc1 and svc2 and preserve updated attributes
	idNew1, err := svc1.AuthenticateVirtualKey(ctx, rotated.RawKey)
	if err != nil {
		t.Fatalf("svc1 AuthenticateVirtualKey(new): %v", err)
	}
	if idNew1.VirtualKeyID != issued.ID || idNew1.KeyPrefix != rotated.KeyPrefix || idNew1.KeyRPMLimit != 120 {
		t.Fatalf("unexpected identity for rotated key on svc1: %+v", idNew1)
	}
	idNew2, err := svc2.AuthenticateVirtualKey(ctx, rotated.RawKey)
	if err != nil {
		t.Fatalf("svc2 AuthenticateVirtualKey(new): %v", err)
	}
	if idNew2.VirtualKeyID != issued.ID || idNew2.KeyPrefix != rotated.KeyPrefix {
		t.Fatalf("unexpected identity for rotated key on svc2: %+v", idNew2)
	}
}

func TestService_UpdateVirtualKey_AllowedEndpointsNilVsEmpty(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	if err := repo.CreateOrganization(ctx, &domain.Organization{ID: "org_1", Name: "Org 1", IsActive: true}); err != nil {
		t.Fatalf("CreateOrganization: %v", err)
	}
	svc := auth.NewService(repo, nil, "master-key", time.Minute, time.Minute)
	rbac := auth.NewRBACEngine(repo)

	issued, err := svc.IssueVirtualKey(ctx, &domain.VirtualKey{
		OrgID:            "org_1",
		Name:             "scoped-key",
		AllowedEndpoints: []string{"/v1/chat/completions"},
	})
	if err != nil {
		t.Fatalf("IssueVirtualKey: %v", err)
	}

	// (a) nil AllowedEndpoints preserves existing endpoints
	if err := svc.UpdateVirtualKey(ctx, &domain.VirtualKey{
		ID:       issued.ID,
		Name:     "scoped-key-renamed",
		IsActive: true,
	}); err != nil {
		t.Fatalf("UpdateVirtualKey(nil AllowedEndpoints): %v", err)
	}
	idPreserve, err := svc.AuthenticateVirtualKey(ctx, issued.RawKey)
	if err != nil {
		t.Fatalf("AuthenticateVirtualKey after nil AllowedEndpoints: %v", err)
	}
	if len(idPreserve.AllowedEndpoints) != 1 || idPreserve.AllowedEndpoints[0] != "/v1/chat/completions" {
		t.Fatalf("expected AllowedEndpoints preserved, got %v", idPreserve.AllowedEndpoints)
	}
	if err := rbac.AuthorizeEndpoint(idPreserve, "/v1/chat/completions"); err != nil {
		t.Fatalf("expected /v1/chat/completions allowed, got %v", err)
	}

	// (b) explicit empty slice []string{} clears AllowedEndpoints and fails closed
	if err := svc.UpdateVirtualKey(ctx, &domain.VirtualKey{
		ID:               issued.ID,
		Name:             "scoped-key-cleared",
		AllowedEndpoints: []string{},
		IsActive:         true,
	}); err != nil {
		t.Fatalf("UpdateVirtualKey(empty AllowedEndpoints): %v", err)
	}
	idCleared, err := svc.AuthenticateVirtualKey(ctx, issued.RawKey)
	if err != nil {
		t.Fatalf("AuthenticateVirtualKey after empty AllowedEndpoints: %v", err)
	}
	if len(idCleared.AllowedEndpoints) != 0 {
		t.Fatalf("expected AllowedEndpoints cleared to [], got %v", idCleared.AllowedEndpoints)
	}
	if err := rbac.AuthorizeEndpoint(idCleared, "/v1/chat/completions"); err == nil {
		t.Fatal("expected AuthorizeEndpoint to fail closed when AllowedEndpoints is []")
	}
}

func TestAdminControlPlaneMiddleware_JWTSourceRestriction(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	if err := repo.CreateOrganization(ctx, &domain.Organization{ID: "org_mw", Name: "Middleware Org", IsActive: true}); err != nil {
		t.Fatalf("CreateOrganization: %v", err)
	}
	if err := repo.CreateUser(ctx, &domain.User{
		ID:          "usr_mw_admin",
		OrgID:       "org_mw",
		Email:       "admin@mw.io",
		Name:        "MW Admin",
		Role:        domain.RoleOrgAdmin,
		OIDCSubject: "sub-mw-admin",
		IsActive:    true,
	}); err != nil {
		t.Fatalf("CreateUser: %v", err)
	}

	svc := auth.NewService(repo, nil, "sk-gw-master-admin-secret", time.Minute, time.Minute)
	jwtSecret := "mw-jwt-secret"
	svc.SetJWTVerifier(auth.NewJWTVerifier(auth.JWTConfig{Secret: jwtSecret}))

	adminVK, err := svc.IssueVirtualKey(ctx, &domain.VirtualKey{
		OrgID: "org_mw",
		Name:  "MW Admin VK",
		Role:  domain.RoleOrgAdmin,
	})
	if err != nil {
		t.Fatalf("IssueVirtualKey: %v", err)
	}

	jwtTok, err := auth.SignHS256(jwtSecret, &auth.JWTClaims{
		Subject:   "sub-mw-admin",
		ExpiresAt: time.Now().UTC().Add(5 * time.Minute).Unix(),
	})
	if err != nil {
		t.Fatalf("SignHS256: %v", err)
	}

	mw := auth.AdminControlPlaneMiddleware(svc)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		op := auth.OperatorFromContext(r.Context())
		if op == nil {
			http.Error(w, "missing operator", http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))

	// 1. Authorization: Bearer <jwt> succeeds.
	reqBearerJWT := httptest.NewRequest(http.MethodGet, "/admin/v1/keys", nil)
	reqBearerJWT.Header.Set("Authorization", "Bearer "+jwtTok)
	recBearerJWT := httptest.NewRecorder()
	mw.ServeHTTP(recBearerJWT, reqBearerJWT)
	if recBearerJWT.Code != http.StatusOK {
		t.Fatalf("expected Bearer JWT to succeed, got %d (%s)", recBearerJWT.Code, recBearerJWT.Body.String())
	}

	// 2. x-api-key: <admin-vk> succeeds.
	reqHeaderVK := httptest.NewRequest(http.MethodGet, "/admin/v1/keys", nil)
	reqHeaderVK.Header.Set("x-api-key", adminVK.RawKey)
	recHeaderVK := httptest.NewRecorder()
	mw.ServeHTTP(recHeaderVK, reqHeaderVK)
	if recHeaderVK.Code != http.StatusOK {
		t.Fatalf("expected x-api-key admin VirtualKey to succeed, got %d (%s)", recHeaderVK.Code, recHeaderVK.Body.String())
	}

	// 3. x-api-key: sk-gw-master-admin-secret succeeds.
	reqHeaderMaster := httptest.NewRequest(http.MethodGet, "/admin/v1/keys", nil)
	reqHeaderMaster.Header.Set("x-api-key", "sk-gw-master-admin-secret")
	recHeaderMaster := httptest.NewRecorder()
	mw.ServeHTTP(recHeaderMaster, reqHeaderMaster)
	if recHeaderMaster.Code != http.StatusOK {
		t.Fatalf("expected x-api-key master key to succeed, got %d (%s)", recHeaderMaster.Code, recHeaderMaster.Body.String())
	}

	// 4. x-api-key: <jwt> is rejected (JWT verification is restricted to Authorization Bearer).
	reqHeaderJWT := httptest.NewRequest(http.MethodGet, "/admin/v1/keys", nil)
	reqHeaderJWT.Header.Set("x-api-key", jwtTok)
	recHeaderJWT := httptest.NewRecorder()
	mw.ServeHTTP(recHeaderJWT, reqHeaderJWT)
	if recHeaderJWT.Code != http.StatusUnauthorized {
		t.Fatalf("expected JWT in x-api-key to be rejected with 401, got %d (%s)", recHeaderJWT.Code, recHeaderJWT.Body.String())
	}
}
