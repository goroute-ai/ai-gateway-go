package main

import (
	"context"

	"github.com/goroute-ai/ai-gateway-go/demo/demoutil"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/pkg/gateway"
)

func main() {
	ctx := context.Background()

	// Dual-Boundary Security, Scoped Virtual Keys & Multi-Tenant RBAC
	gw, err := gateway.New(
		gateway.WithModelList(
			gateway.ModelEntry{ModelName: "fast", Model: "gemini/gemini-2.5-flash"},
			gateway.ModelEntry{ModelName: "reasoning", Model: "anthropic/claude-sonnet-4-20250514"},
		),
		gateway.WithDemoMocksIfEnvMissing(),
	)
	if err != nil {
		demoutil.Fail("Gateway initialization failed", err)
	}
	defer gw.Close()

	demoutil.Banner("Scoped Virtual Keys, 4-Tier RBAC & Instant Revocation")

	// 1. Issue a scoped Virtual API Key restricted ONLY to the "fast" model
	demoutil.Section(1, "Issue Scoped Virtual Key (Restricted to 'fast', 60 RPM)")
	vk, err := gw.IssueVirtualKey(ctx, domain.VirtualKey{
		Name:          "checkout-service-key",
		AllowedModels: []string{"fast"},
		RPMLimit:      60,
	})
	if err != nil {
		demoutil.Fail("Failed to issue virtual key", err)
	}
	demoutil.Field("Key ID", vk.ID)
	demoutil.Fieldf("Raw Key", "%s... (Only SHA-256 hash stored in DB)", vk.KeyPrefix)
	demoutil.Field("Allowlist", vk.AllowedModels)

	scopedClient := gw.WithKey(vk.RawKey)

	// 2. Call allowed model ("fast") -> 200 OK
	demoutil.Section(2, "Authenticate with Scoped Key -> Request Allowed Model ('fast')")
	res, err := scopedClient.Chat(ctx, "fast", "Check checkout service status.")
	if err != nil {
		demoutil.Fail("Allowed model call failed", err)
	}
	demoutil.Field("Status", "200 OK")
	demoutil.Field("Model", res.Model)
	demoutil.Field("Response", res.Content)

	// 3. Call restricted model ("reasoning") -> HTTP 403 Forbidden
	demoutil.Section(3, "Authenticate with Scoped Key -> Request Restricted Model ('reasoning')")
	_, err = scopedClient.Chat(ctx, "reasoning", "Attempt unauthorized reasoning call.")
	demoutil.Field("RBAC Action", "BLOCKED (403 Forbidden)")
	demoutil.Field("Error", err)

	// 4. Revoke key and verify immediate HTTP 401 rejection
	demoutil.Section(4, "Revoke Virtual Key & Verify Immediate Multi-Pod Eviction")
	_ = gw.RevokeVirtualKey(ctx, vk.ID)
	demoutil.Fieldf("Revoked", "Key ID %s invalidated across L1/L2 caches", vk.ID)
	_, err = scopedClient.Chat(ctx, "fast", "Call after key revocation.")
	demoutil.Field("Auth Action", "REJECTED (401 Unauthorized)")
	demoutil.Field("Error", err)
}
