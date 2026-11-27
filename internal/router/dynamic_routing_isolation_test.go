// Dynamic routing isolation tests verify that untrusted data-plane model names
// for built-in catalog providers fail closed instead of polluting the shared
// cross-tenant global_models table or hijacking `<provider>/*` wildcards.

package router

import (
	"context"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRouter_DynamicModelResolution_BlocksCrossTenantCatalogPollutionAndWildcardHijack(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()

	orgA := &domain.Organization{ID: "org-sec-a", Name: "Org A", Slug: "org-sec-a", IsActive: true}
	orgB := &domain.Organization{ID: "org-sec-b", Name: "Org B", Slug: "org-sec-b", IsActive: true}
	require.NoError(t, repo.CreateOrganization(ctx, orgA))
	require.NoError(t, repo.CreateOrganization(ctx, orgB))

	for _, orgID := range []string{orgA.ID, orgB.ID} {
		require.NoError(t, repo.CreateProviderCredential(ctx, &domain.ProviderCredential{
			OrgID:           orgID,
			Provider:        domain.ProviderGemini,
			Name:            "gem-" + orgID,
			DecryptedAPIKey: "synthetic-test-key",
			IsActive:        true,
		}))
	}

	ir := NewIntelligentRouter(repo, config.RouterConfig{})
	ir.SetProviderCallable(func(p domain.ProviderType) bool {
		return p == domain.ProviderGemini
	})

	// 1. Tenant A attempts to pollute global_models with an alphabetically-first fake model
	//    and an AIP-136 colon-injected model identifier.
	for _, bogus := range []string{"gemini/000-hijack", "gemini/gemini-2.5-flash:countTokens", "gemini/../../etc/passwd"} {
		_, err := ir.ResolveGroup(ctx, orgA.ID, &domain.CanonicalChatRequest{
			Model:    bogus,
			Messages: []domain.CanonicalMessage{{Role: "user", Content: "hi"}},
		})
		require.Error(t, err, "uncatalogued or malformed model %q must fail closed", bogus)
	}

	// Verify global_models has NOT been polluted with Tenant A's bogus entry.
	gm, err := repo.GetGlobalModel(ctx, "gemini/000-hijack")
	assert.True(t, err != nil || gm == nil, "uncatalogued model must not be persisted into shared global_models")

	// 2. Even if an unverified/unknown-pricing row already exists in global_models,
	//    Tenant B's gemini/* wildcard resolution must NOT select it.
	require.NoError(t, repo.UpsertGlobalModel(ctx, &domain.GlobalModel{
		ID:                "gemini/000-unverified-rogue",
		Provider:          domain.ProviderGemini,
		ModelName:         "000-unverified-rogue",
		SupportsInference: true,
		PricingStatus:     domain.PricingStatusUnknown,
		LifecycleStatus:   domain.ModelStatusActive,
	}))

	decision, err := ir.ResolveGroup(ctx, orgB.ID, &domain.CanonicalChatRequest{
		Model:    "gemini/*",
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "hi"}},
	})
	require.NoError(t, err)
	require.NotNil(t, decision)
	assert.NotEqual(t, "gemini/000-unverified-rogue", decision.TargetGroupAlias)
	assert.NotEqual(t, "gemini/000-hijack", decision.TargetGroupAlias)

	// 3. Trusted built-in catalog model continues to auto-provision cleanly.
	catDecision, err := ir.ResolveGroup(ctx, orgA.ID, &domain.CanonicalChatRequest{
		Model:    "gemini/gemini-2.5-flash",
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "hello"}},
	})
	require.NoError(t, err)
	require.NotNil(t, catDecision)
	require.NotNil(t, catDecision.ModelGroup)
	assert.Equal(t, "gemini-2.5-flash", catDecision.TargetGroupAlias)
}
