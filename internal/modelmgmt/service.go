package modelmgmt

import (
	"context"
	"slices"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/openapi"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

// Service coordinates the 4-Layer Model Management architecture:
// Layer 1: Global Model Catalogue
// Layer 2: Organization Provider Subscriptions
// Layer 3: Organization Model Availability Policies
// Layer 4: Customer Model Groups & Deployments
type Service struct {
	repo storage.Repository
}

func NewService(repo storage.Repository) *Service {
	return &Service{repo: repo}
}

// ListVisibleModelsForIdentity computes the exact tenant-isolated model list returned by `GET /v1/models`:
// Intersection of:
// 1. Active Global Models (Layer 1)
// 2. Organization Subscribed Providers (Layer 2)
// 3. Organization Enabled Model Policies (Layer 3)
// 4. Team & Virtual Key AllowedModels (Boundary 1 RBAC)
func (s *Service) ListVisibleModelsForIdentity(ctx context.Context, idCtx *domain.IdentityContext) (*openapi.GatewayModelList, error) {
	allGlobal, err := s.repo.ListGlobalModels(ctx)
	if err != nil {
		return nil, err
	}

	var subscribedProviders map[domain.ProviderType]bool
	var orgPolicies map[string]bool

	if idCtx != nil && idCtx.OrgID != "" {
		subs, _ := s.repo.GetOrgProviderSubscriptions(ctx, idCtx.OrgID)
		if len(subs) > 0 {
			subscribedProviders = make(map[domain.ProviderType]bool, len(subs))
			for _, sub := range subs {
				if sub.IsEnabled {
					subscribedProviders[sub.Provider] = true
				}
			}
		}

		pols, _ := s.repo.GetOrgModelPolicies(ctx, idCtx.OrgID)
		if len(pols) > 0 {
			orgPolicies = make(map[string]bool, len(pols))
			for _, pol := range pols {
				orgPolicies[pol.GlobalModelID] = pol.IsEnabled
			}
		}
	}

	var cards []openapi.GatewayModelCard
	for _, gm := range allGlobal {
		if gm.LifecycleStatus != domain.ModelStatusActive && gm.LifecycleStatus != domain.ModelStatusPreview {
			continue
		}
		// Layer 2 check: if org has configured provider subscriptions, filter by enabled providers
		if subscribedProviders != nil && !subscribedProviders[gm.Provider] {
			continue
		}
		// Layer 3 check: if org has configured model policies, filter by enabled models
		if orgPolicies != nil {
			if enabled, exists := orgPolicies[gm.ID]; exists && !enabled {
				continue
			}
		}
		// Team & Virtual Key allowlist check
		if idCtx != nil {
			if len(idCtx.TeamAllowedModels) > 0 && !allowsModel(idCtx.TeamAllowedModels, gm.ModelName, gm.ID) {
				continue
			}
			if len(idCtx.KeyAllowedModels) > 0 && !allowsModel(idCtx.KeyAllowedModels, gm.ModelName, gm.ID) {
				continue
			}
		}

		var caps []string
		if gm.SupportsStreaming {
			caps = append(caps, "streaming")
		}
		if gm.SupportsTools {
			caps = append(caps, "tools")
		}
		if gm.SupportsVision {
			caps = append(caps, "vision")
		}
		if gm.SupportsReasoning {
			caps = append(caps, "reasoning")
		}
		if gm.SupportsEmbeddings {
			caps = append(caps, "embeddings")
		}

		cards = append(cards, openapi.GatewayModelCard{
			ID:                 gm.ModelName,
			Object:             "model",
			Created:            gm.DiscoveredAt.Unix(),
			OwnedBy:            string(gm.Provider),
			Provider:           string(gm.Provider),
			MaxInputTokens:     gm.MaxInputTokens,
			MaxOutputTokens:    gm.MaxOutputTokens,
			Capabilities:       caps,
			InputCostMicros1M:  gm.InputCostMicrosPer1M,
			OutputCostMicros1M: gm.OutputCostMicrosPer1M,
		})
	}

	return &openapi.GatewayModelList{
		Object: "list",
		Data:   cards,
	}, nil
}

func allowsModel(allowlist []string, modelName, globalID string) bool {
	return slices.Contains(allowlist, "*") || slices.Contains(allowlist, modelName) || slices.Contains(allowlist, globalID)
}
