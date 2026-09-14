package auth_test

import (
	"context"
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
