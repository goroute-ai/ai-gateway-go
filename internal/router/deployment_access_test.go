package router

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

func testActiveDeployment(id string, tags []string) *domain.Deployment {
	return &domain.Deployment{
		ID:     id,
		Status: domain.DeploymentStatusActive,
		Tags:   tags,
		GlobalModel: &domain.GlobalModel{
			ID:                "gpt-4o",
			Provider:          domain.ProviderOpenAI,
			SupportsStreaming: true,
		},
		Credential: &domain.ProviderCredential{
			ID:       "cred-1",
			IsActive: true,
		},
	}
}

func TestFilterPipeline_MandatoryRoutingTagsAndDeployments(t *testing.T) {
	p := NewFilterPipeline(nil, nil, config.RouterConfig{})
	depEU := testActiveDeployment("dep-eu", []string{"eu-gdpr", "prod"})
	depUS := testActiveDeployment("dep-us", []string{"us-east", "prod"})
	depUntagged := testActiveDeployment("dep-untagged", nil)
	all := []*domain.Deployment{depEU, depUS, depUntagged}

	t.Run("mandatory allowed_routing_tags filters deployments even when request omits tags", func(t *testing.T) {
		ctx := auth.WithIdentity(context.Background(), &domain.IdentityContext{
			OrgID:                 "org-1",
			KeyAllowedRoutingTags: []string{"eu-gdpr"},
		})
		got, err := p.FilterEligibleDeployments(ctx, "org-1", "gpt-4o", &domain.CanonicalChatRequest{}, all, 100)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 1 || got[0].ID != "dep-eu" {
			t.Fatalf("expected only dep-eu, got %+v", got)
		}
	})

	t.Run("mandatory allowed_routing_tags returns 403 deployment_restricted when no deployments match", func(t *testing.T) {
		ctx := auth.WithIdentity(context.Background(), &domain.IdentityContext{
			OrgID:                 "org-1",
			KeyAllowedRoutingTags: []string{"apac-only"},
		})
		got, err := p.FilterEligibleDeployments(ctx, "org-1", "gpt-4o", &domain.CanonicalChatRequest{}, all, 100)
		if err == nil {
			t.Fatalf("expected DeploymentRestrictedError, got eligible=%+v", got)
		}
		var depErr *DeploymentRestrictedError
		if !errors.As(err, &depErr) {
			t.Fatalf("expected *DeploymentRestrictedError, got %T (%v)", err, err)
		}
		var gwErr *domain.GatewayError
		if !errors.As(err, &gwErr) || gwErr.StatusCode != http.StatusForbidden || gwErr.Code != "deployment_restricted" {
			t.Fatalf("expected 403 deployment_restricted, got %+v", gwErr)
		}
	})

	t.Run("allowed_deployments intersects Key, Project, and Team allowlists", func(t *testing.T) {
		ctx := auth.WithIdentity(context.Background(), &domain.IdentityContext{
			OrgID:                     "org-1",
			TeamAllowedDeployments:    []string{"dep-eu", "dep-us"},
			ProjectAllowedDeployments: []string{"dep-eu", "dep-untagged"},
			KeyAllowedDeployments:     []string{"dep-eu"},
		})
		got, err := p.FilterEligibleDeployments(ctx, "org-1", "gpt-4o", &domain.CanonicalChatRequest{}, all, 100)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 1 || got[0].ID != "dep-eu" {
			t.Fatalf("expected intersection [dep-eu], got %+v", got)
		}
	})

	t.Run("disjoint allowed_deployments returns 403 deployment_restricted", func(t *testing.T) {
		ctx := auth.WithIdentity(context.Background(), &domain.IdentityContext{
			OrgID:                  "org-1",
			TeamAllowedDeployments: []string{"dep-us"},
			KeyAllowedDeployments:  []string{"dep-eu"},
		})
		_, err := p.FilterEligibleDeployments(ctx, "org-1", "gpt-4o", &domain.CanonicalChatRequest{}, all, 100)
		var gwErr *domain.GatewayError
		if !errors.As(err, &gwErr) || gwErr.StatusCode != http.StatusForbidden || gwErr.Code != "deployment_restricted" {
			t.Fatalf("expected 403 deployment_restricted, got %v", err)
		}
	})

	t.Run("project allowed_routing_tags combines with team allowed_routing_tags", func(t *testing.T) {
		ctx := auth.WithIdentity(context.Background(), &domain.IdentityContext{
			OrgID:                     "org-1",
			TeamAllowedRoutingTags:    []string{"prod"},
			ProjectAllowedRoutingTags: []string{"eu-*"},
		})
		got, err := p.FilterEligibleDeployments(ctx, "org-1", "gpt-4o", &domain.CanonicalChatRequest{}, all, 100)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(got) != 1 || got[0].ID != "dep-eu" {
			t.Fatalf("expected only dep-eu matching prod + eu-*, got %+v", got)
		}
	})
}

func TestOrgPolicyDenied_Propagates403InsteadOf503(t *testing.T) {
	ctx := context.Background()

	setupRM := func(t *testing.T, deps []*domain.Deployment) (*ReliabilityManager, *storage.MemoryRepository, *domain.ModelGroup) {
		t.Helper()
		repo := storage.NewMemoryRepository()
		if err := repo.CreateOrganization(ctx, &domain.Organization{ID: "org-pol", Name: "Policy Org", IsActive: true}); err != nil {
			t.Fatalf("create org: %v", err)
		}
		mg := &domain.ModelGroup{ID: "mg-pol", OrgID: "org-pol", Alias: "pol-alias", IsActive: true}
		if err := repo.CreateModelGroup(ctx, mg); err != nil {
			t.Fatalf("create model group: %v", err)
		}
		for _, d := range deps {
			if d.GlobalModel != nil {
				if err := repo.UpsertGlobalModel(ctx, d.GlobalModel); err != nil {
					t.Fatalf("upsert global model: %v", err)
				}
			}
			d.ModelGroupID = mg.ID
			if err := repo.CreateDeployment(ctx, d); err != nil {
				t.Fatalf("create deployment: %v", err)
			}
		}
		rbac := auth.NewRBACEngine(repo)
		ir := NewIntelligentRouter(repo, config.RouterConfig{})
		rm := NewReliabilityManager(repo, nil, ir, NewLoadBalancer(), nil, rbac, nil, config.RouterConfig{})
		return rm, repo, mg
	}

	t.Run("provider_not_subscribed returns 403 OrgPolicyDeniedError", func(t *testing.T) {
		dep := &domain.Deployment{
			ID:             "dep-oai",
			DeploymentName: "oai-primary",
			GlobalModelID:  "openai/gpt-4o-mini",
			Status:         domain.DeploymentStatusActive,
			GlobalModel: &domain.GlobalModel{
				ID:            "openai/gpt-4o-mini",
				Provider:      domain.ProviderOpenAI,
				ModelName:     "gpt-4o-mini",
				PricingStatus: domain.PricingStatusVerified,
			},
		}
		rm, repo, mg := setupRM(t, []*domain.Deployment{dep})
		if err := repo.SetOrgProviderSubscription(ctx, &domain.OrgProviderSubscription{
			OrgID:     "org-pol",
			Provider:  domain.ProviderOpenAI,
			IsEnabled: false,
		}); err != nil {
			t.Fatalf("set org provider subscription: %v", err)
		}

		got, _, err := rm.getEligibleDeploymentsForRequest(ctx, "org-pol", mg, &domain.CanonicalChatRequest{Model: mg.Alias}, 100, nil, false)
		if err == nil {
			t.Fatalf("expected OrgPolicyDeniedError, got eligible=%+v", got)
		}
		var polErr *OrgPolicyDeniedError
		if !errors.As(err, &polErr) {
			t.Fatalf("expected *OrgPolicyDeniedError, got %T (%v)", err, err)
		}
		var gwErr *domain.GatewayError
		if !errors.As(err, &gwErr) || gwErr.StatusCode != http.StatusForbidden || gwErr.Code != "provider_not_subscribed" {
			t.Fatalf("expected 403 provider_not_subscribed, got %+v", gwErr)
		}
		if rm.classifyErr(err) != CategoryNonRetryable {
			t.Fatalf("expected CategoryNonRetryable for 403 org policy denial")
		}
	})

	t.Run("model_disabled_by_org_policy returns 403 OrgPolicyDeniedError", func(t *testing.T) {
		dep := &domain.Deployment{
			ID:             "dep-anth",
			DeploymentName: "anth-primary",
			GlobalModelID:  "anthropic/claude-haiku-4-5",
			Status:         domain.DeploymentStatusActive,
			GlobalModel: &domain.GlobalModel{
				ID:            "anthropic/claude-haiku-4-5",
				Provider:      domain.ProviderAnthropic,
				ModelName:     "claude-haiku-4-5",
				PricingStatus: domain.PricingStatusVerified,
			},
		}
		rm, repo, mg := setupRM(t, []*domain.Deployment{dep})
		if err := repo.SetOrgModelPolicy(ctx, &domain.OrgModelPolicy{
			OrgID:         "org-pol",
			GlobalModelID: "anthropic/claude-haiku-4-5",
			IsEnabled:     false,
		}); err != nil {
			t.Fatalf("set org model policy: %v", err)
		}

		_, _, err := rm.getEligibleDeploymentsForRequest(ctx, "org-pol", mg, &domain.CanonicalChatRequest{Model: mg.Alias}, 100, nil, false)
		var gwErr *domain.GatewayError
		if !errors.As(err, &gwErr) || gwErr.StatusCode != http.StatusForbidden || gwErr.Code != "model_disabled_by_org_policy" {
			t.Fatalf("expected 403 model_disabled_by_org_policy, got %v", err)
		}
	})

	t.Run("mixed group falls over cleanly to authorized deployment", func(t *testing.T) {
		depDenied := &domain.Deployment{
			ID:             "dep-denied",
			DeploymentName: "oai-denied",
			GlobalModelID:  "openai/gpt-4o-mini",
			Status:         domain.DeploymentStatusActive,
			GlobalModel: &domain.GlobalModel{
				ID:            "openai/gpt-4o-mini",
				Provider:      domain.ProviderOpenAI,
				ModelName:     "gpt-4o-mini",
				PricingStatus: domain.PricingStatusVerified,
			},
		}
		depAllowed := &domain.Deployment{
			ID:             "dep-allowed",
			DeploymentName: "anth-allowed",
			GlobalModelID:  "anthropic/claude-haiku-4-5",
			Status:         domain.DeploymentStatusActive,
			GlobalModel: &domain.GlobalModel{
				ID:            "anthropic/claude-haiku-4-5",
				Provider:      domain.ProviderAnthropic,
				ModelName:     "claude-haiku-4-5",
				PricingStatus: domain.PricingStatusVerified,
			},
		}
		rm, repo, mg := setupRM(t, []*domain.Deployment{depDenied, depAllowed})
		if err := repo.SetOrgProviderSubscription(ctx, &domain.OrgProviderSubscription{
			OrgID:     "org-pol",
			Provider:  domain.ProviderOpenAI,
			IsEnabled: false,
		}); err != nil {
			t.Fatalf("set org provider subscription: %v", err)
		}
		if err := repo.SetOrgProviderSubscription(ctx, &domain.OrgProviderSubscription{
			OrgID:     "org-pol",
			Provider:  domain.ProviderAnthropic,
			IsEnabled: true,
		}); err != nil {
			t.Fatalf("set org provider subscription anthropic: %v", err)
		}

		got, _, err := rm.getEligibleDeploymentsForRequest(ctx, "org-pol", mg, &domain.CanonicalChatRequest{Model: mg.Alias}, 100, nil, false)
		if err != nil {
			t.Fatalf("expected allowed sibling deployment without error, got %v", err)
		}
		if len(got) != 1 || got[0].ID != "dep-allowed" {
			t.Fatalf("expected only dep-allowed, got %+v", got)
		}
	})

	t.Run("zero active deployments still returns nil error so callers emit 503", func(t *testing.T) {
		depDisabled := &domain.Deployment{
			ID:             "dep-disabled",
			DeploymentName: "oai-disabled",
			GlobalModelID:  "openai/gpt-4o-mini",
			Status:         domain.DeploymentStatusDisabled,
			GlobalModel: &domain.GlobalModel{
				ID:            "openai/gpt-4o-mini",
				Provider:      domain.ProviderOpenAI,
				ModelName:     "gpt-4o-mini",
				PricingStatus: domain.PricingStatusVerified,
			},
		}
		rm, _, mg := setupRM(t, []*domain.Deployment{depDisabled})
		got, activeTotal, err := rm.getEligibleDeploymentsForRequest(ctx, "org-pol", mg, &domain.CanonicalChatRequest{Model: mg.Alias}, 100, nil, false)
		if err != nil {
			t.Fatalf("expected nil error for disabled-only deployments, got %v", err)
		}
		if len(got) != 0 || activeTotal != 0 {
			t.Fatalf("expected 0 eligible and 0 active, got eligible=%d active=%d", len(got), activeTotal)
		}
	})
}
