package modelmgmt

import (
	"context"

	"github.com/goroute-ai/ai-gateway-go/internal/auth"
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
	rbac *auth.RBACEngine
}

func NewService(repo storage.Repository) *Service {
	return &Service{repo: repo}
}

// NewServiceWithRBAC constructs a model management service backed by a shared cached RBACEngine.
func NewServiceWithRBAC(repo storage.Repository, rbac *auth.RBACEngine) *Service {
	return &Service{repo: repo, rbac: rbac}
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
		subs, err := s.repo.GetOrgProviderSubscriptions(ctx, idCtx.OrgID)
		if err != nil {
			return nil, err
		}
		if len(subs) > 0 {
			subscribedProviders = make(map[domain.ProviderType]bool, len(subs))
			for _, sub := range subs {
				if sub.IsEnabled {
					subscribedProviders[sub.Provider] = true
				}
			}
		}

		pols, err := s.repo.GetOrgModelPolicies(ctx, idCtx.OrgID)
		if err != nil {
			return nil, err
		}
		if len(pols) > 0 {
			orgPolicies = make(map[string]bool, len(pols))
			for _, pol := range pols {
				orgPolicies[pol.GlobalModelID] = pol.IsEnabled
			}
		}
	}

	var cards []openapi.GatewayModelCard
	globalByID := make(map[string]*domain.GlobalModel, len(allGlobal))
	for _, gm := range allGlobal {
		if gm != nil {
			globalByID[gm.ID] = gm
		}
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
		// RBAC allowlists + dynamic access rules + ModelAccessGroup visibility
		if idCtx != nil && !s.isModelVisibleToIdentity(ctx, idCtx, gm.ModelName, gm.ID) {
			continue
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

	// Include org-configured ModelGroup aliases visible to the caller (deduplicated against global model names),
	// backed by at least one active deployment belonging to an org-subscribed provider.
	if idCtx != nil && idCtx.OrgID != "" {
		if mgs, mgErr := s.repo.ListModelGroups(ctx, idCtx.OrgID); mgErr == nil && len(mgs) > 0 {
			seen := make(map[string]struct{}, len(cards))
			for _, c := range cards {
				seen[c.ID] = struct{}{}
			}
			for _, mg := range mgs {
				if mg == nil || !mg.IsActive || mg.Alias == "" {
					continue
				}
				if _, exists := seen[mg.Alias]; exists {
					continue
				}
				if !s.isModelVisibleToIdentity(ctx, idCtx, mg.Alias, mg.Alias) {
					continue
				}
				deps, dErr := s.repo.ListDeploymentsByGroup(ctx, mg.ID)
				if dErr != nil || len(deps) == 0 {
					continue
				}
				var matchedProvider domain.ProviderType
				for _, dep := range deps {
					if dep == nil || dep.Status == domain.DeploymentStatusDisabled {
						continue
					}
					gm := dep.GlobalModel
					if gm == nil && dep.GlobalModelID != "" {
						gm = globalByID[dep.GlobalModelID]
					}
					if gm == nil {
						continue
					}
					if subscribedProviders != nil && !subscribedProviders[gm.Provider] {
						continue
					}
					if orgPolicies != nil {
						if enabled, exists := orgPolicies[gm.ID]; exists && !enabled {
							continue
						}
					}
					matchedProvider = gm.Provider
					break
				}
				if matchedProvider == "" {
					continue
				}
				seen[mg.Alias] = struct{}{}
				cards = append(cards, openapi.GatewayModelCard{
					ID:       mg.Alias,
					Object:   "model",
					Created:  mg.CreatedAt.Unix(),
					OwnedBy:  string(matchedProvider),
					Provider: string(matchedProvider),
				})
			}
		}
	}

	return &openapi.GatewayModelList{
		Object: "list",
		Data:   cards,
	}, nil
}

func (s *Service) isModelVisibleToIdentity(ctx context.Context, idCtx *domain.IdentityContext, modelName, globalID string) bool {
	if idCtx == nil {
		return true
	}
	allowDynamic := idCtx.DelegatedUserID == "" && idCtx.DelegatedTeamID == ""
	keyRestricted := len(idCtx.KeyAllowedModels) > 0 && !allowsModel(idCtx.KeyAllowedModels, modelName, globalID)
	projRestricted := len(idCtx.ProjectAllowedModels) > 0 && !allowsModel(idCtx.ProjectAllowedModels, modelName, globalID)
	memberRestricted := len(idCtx.TeamMemberAllowedModels) > 0 && !allowsModel(idCtx.TeamMemberAllowedModels, modelName, globalID)
	teamRestricted := len(idCtx.TeamAllowedModels) > 0 && !allowsModel(idCtx.TeamAllowedModels, modelName, globalID)

	var magEval auth.ModelAccessGroupEvaluation
	var err error
	if s.rbac != nil {
		magEval, err = s.rbac.EvaluateModelAccessGroupsWithCache(ctx, idCtx, modelName, idCtx.AccessGroups)
	} else if s.repo != nil {
		magEval, err = auth.EvaluateModelAccessGroups(ctx, s.repo, idCtx, modelName, idCtx.AccessGroups)
	}
	if err != nil {
		return false
	}
	if magEval.GatedByGroup && !magEval.MatchedGatedGroup {
		return false
	}
	if !keyRestricted && !projRestricted && !memberRestricted && !teamRestricted {
		return true
	}
	if allowDynamic && len(idCtx.DynamicAllowedModels) > 0 && allowsModel(idCtx.DynamicAllowedModels, modelName, globalID) {
		return true
	}
	return (!keyRestricted || magEval.GrantedForKey) &&
		(!projRestricted || magEval.GrantedForProject) &&
		(!memberRestricted || magEval.GrantedForAny) &&
		(!teamRestricted || magEval.GrantedForTeam) &&
		magEval.GrantedForAny
}

func allowsModel(allowlist []string, modelName, globalID string) bool {
	for _, item := range allowlist {
		if auth.MatchesModelPattern(item, modelName) || (globalID != "" && auth.MatchesModelPattern(item, globalID)) {
			return true
		}
	}
	return false
}
