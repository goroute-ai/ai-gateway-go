package router

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
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
