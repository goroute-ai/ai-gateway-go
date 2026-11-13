package server

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/modelcatalog"
	"github.com/goroute-ai/ai-gateway-go/internal/modelmgmt"
)

// bootstrap automatically seeds the default Organization, Provider Subscriptions, Encrypted Vault Credentials,
// ModelGroups, Deployments, and Default Virtual Key from `cfg.ModelList` and/or standard environment variables
// (`GEMINI_API_KEY`, `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `MISTRAL_API_KEY`).
//
// This provides zero-boilerplate startup while preserving 4-layer enterprise isolation.
func (s *GatewayServer) bootstrap(ctx context.Context) error {
	if s.cfg == nil || s.repo == nil || s.vault == nil {
		return nil
	}

	entries := make([]config.ModelListEntry, 0, len(s.cfg.ModelList))
	for _, e := range s.cfg.ModelList {
		if strings.TrimSpace(e.ModelName) == "" || strings.TrimSpace(e.ModelParams.Model) == "" {
			continue
		}
		prov, _, _ := config.ParseProviderModel(e.ModelParams.Model)
		resolvedKey := config.ResolveEnvValue(e.ModelParams.APIKey)
		if resolvedKey == "" {
			resolvedKey = resolveProviderEnvKey(prov)
		}
		// Only bootstrap entries that have a valid API key (or Ollama local inference)
		if resolvedKey == "" && prov != domain.ProviderOllama {
			continue
		}
		eCopy := e
		eCopy.ModelParams.APIKey = resolvedKey
		entries = append(entries, eCopy)
	}

	// Also auto-discover standard provider API keys from environment if not already covered by model_list
	envEntries := discoverEnvModelEntries(entries)
	entries = append(entries, envEntries...)

	orgID := strings.TrimSpace(s.cfg.Auth.DefaultOrgID)
	if orgID == "" {
		orgID = "org_default"
	}

	// 1. Ensure Default Organization exists
	if _, err := s.repo.GetOrganization(ctx, orgID); err != nil {
		_ = s.repo.CreateOrganization(ctx, &domain.Organization{
			ID:              orgID,
			Name:            "Default Organization",
			Slug:            "default",
			MaxBudgetMicros: 0, // unlimited unless configured
			IsActive:        true,
		})
	}

	defaultVKey := config.ResolveEnvValue(s.cfg.Auth.DefaultVirtualKey)
	if len(entries) == 0 && defaultVKey == "" {
		return nil
	}

	// 2. Ensure Default Virtual Key exists (if configured)
	if defaultVKey != "" {
		keyHash := auth.HashKey(defaultVKey)
		if _, err := s.repo.GetVirtualKeyByHash(ctx, keyHash); err != nil {
			prefix := defaultVKey
			if len(prefix) > 14 {
				prefix = prefix[:14]
			}
			_ = s.repo.CreateVirtualKey(ctx, &domain.VirtualKey{
				ID:                "vk_default",
				OrgID:             orgID,
				Name:              "default-virtual-key",
				KeyPrefix:         prefix,
				KeyHash:           keyHash,
				Role:              domain.RoleOrgAdmin,
				AllowedEndpoints:  []string{"/v1/chat/completions", "/v1/embeddings", "/v1/models", "/mcp", "/mcp/*", "/a2a/*"},
				AllowedMCPServers: []string{"*"},
				AllowedA2AAgents:  []string{"*"},
				AllowedClientApps: []string{"*"},
				IsActive:          true,
			})
		}
	}

	// Track created credentials in this bootstrap pass by (provider + baseURL + apiKey) to avoid duplicates
	credCache := make(map[string]*domain.ProviderCredential)

	for idx, entry := range entries {
		alias := strings.TrimSpace(entry.ModelName)
		prov, bareModel, globalModelID := config.ParseProviderModel(entry.ModelParams.Model)
		if prov == "" || bareModel == "" {
			continue
		}

		// 3. Ensure GlobalModel exists in Layer 1 Catalogue
		if _, err := s.repo.GetGlobalModel(ctx, globalModelID); err != nil {
			var enriched *domain.GlobalModel
			if catModel, ok := catalog.LookupByProviderAndModel(prov, bareModel); ok {
				catCopy := *catModel
				catCopy.LifecycleStatus = domain.ModelStatusActive
				enriched = &catCopy
			} else {
				enriched = modelmgmt.EnrichDiscoveredModel(domain.DiscoveredModel{
					Provider:    prov,
					ModelName:   bareModel,
					DisplayName: bareModel,
				}, true)
			}
			_ = s.repo.UpsertGlobalModel(ctx, enriched)
		}

		// 4. Enable Layer 2 Organization Provider Subscription
		_ = s.repo.SetOrgProviderSubscription(ctx, &domain.OrgProviderSubscription{
			OrgID:     orgID,
			Provider:  prov,
			IsEnabled: true,
		})

		// 5. Encrypt & Store Layer 4 Provider Credential in AES-256-GCM Vault
		apiBase := config.ResolveEnvValue(entry.ModelParams.APIBase)
		apiKey := entry.ModelParams.APIKey
		azureDeploy := strings.TrimSpace(entry.ModelParams.AzureDeploymentName)
		apiVersion := strings.TrimSpace(entry.ModelParams.APIVersion)
		credCacheKey := fmt.Sprintf("%s|%s|%s|%s|%s", prov, apiBase, apiKey, azureDeploy, apiVersion)
		cred, ok := credCache[credCacheKey]
		if !ok {
			cred = &domain.ProviderCredential{
				OrgID:               orgID,
				Provider:            prov,
				Name:                fmt.Sprintf("%s-bootstrap-%d", prov, idx+1),
				BaseURL:             apiBase,
				AzureDeploymentName: azureDeploy,
				APIVersion:          apiVersion,
				Headers:             entry.ModelParams.Headers,
				IsActive:            true,
			}
			if apiKey != "" {
				if err := s.vault.EncryptCredential(cred, apiKey); err != nil {
					return err
				}
			} else {
				_ = s.vault.EncryptCredential(cred, "none")
			}
			if err := s.repo.CreateProviderCredential(ctx, cred); err != nil {
				return err
			}
			credCache[credCacheKey] = cred
		}

		// 6. Ensure Layer 4 ModelGroup exists for `alias`
		strategy := domain.RoutingStrategy(strings.TrimSpace(entry.RoutingStrategy))
		if strategy == "" {
			strategy = domain.StrategyWeightedShuffle
		}
		mg, err := s.repo.GetModelGroupByAlias(ctx, orgID, alias)
		if err != nil || mg == nil {
			mg = &domain.ModelGroup{
				OrgID:            orgID,
				Alias:            alias,
				RoutingStrategy:  strategy,
				FallbackGroupIDs: entry.Fallbacks,
				MaxRetries:       s.cfg.Router.DefaultMaxRetries,
				CooldownSeconds:  int(s.cfg.Router.DefaultCooldown.Seconds()),
				FailureThreshold: s.cfg.Router.FailureThreshold,
				IsActive:         true,
			}
			if err := s.repo.CreateModelGroup(ctx, mg); err != nil {
				return err
			}
		} else if len(entry.Fallbacks) > 0 {
			mg.FallbackGroupIDs = entry.Fallbacks
			_ = s.repo.CreateModelGroup(ctx, mg)
		}

		// 7. Create Layer 4 Deployment inside the ModelGroup (skip if already exists on restart)
		depName := fmt.Sprintf("%s-%s-%d", alias, bareModel, idx+1)
		existingDeps, _ := s.repo.ListDeploymentsByGroup(ctx, mg.ID)
		var depExists bool
		for _, ed := range existingDeps {
			if ed != nil && ed.DeploymentName == depName {
				depExists = true
				break
			}
		}
		if depExists {
			continue
		}

		weight := entry.ModelParams.Weight
		if weight <= 0 {
			weight = 100
		}
		dep := &domain.Deployment{
			ModelGroupID:   mg.ID,
			GlobalModelID:  globalModelID,
			CredentialID:   cred.ID,
			DeploymentName: depName,
			Region:         entry.ModelParams.Region,
			Weight:         weight,
			RPMCapacity:    entry.ModelParams.RPM,
			TPMCapacity:    entry.ModelParams.TPM,
			Status:         domain.DeploymentStatusActive,
		}
		if err := s.repo.CreateDeployment(ctx, dep); err != nil {
			return err
		}
	}

	return nil
}

func resolveProviderEnvKey(prov domain.ProviderType) string {
	switch prov {
	case domain.ProviderGemini:
		if k := strings.TrimSpace(os.Getenv("GEMINI_API_KEY")); k != "" {
			return k
		}
		return strings.TrimSpace(os.Getenv("GOOGLE_API_KEY"))
	case domain.ProviderAnthropic:
		return strings.TrimSpace(os.Getenv("ANTHROPIC_API_KEY"))
	case domain.ProviderOpenAI:
		return strings.TrimSpace(os.Getenv("OPENAI_API_KEY"))
	case domain.ProviderMistral:
		return strings.TrimSpace(os.Getenv("MISTRAL_API_KEY"))
	case domain.ProviderGroq:
		return strings.TrimSpace(os.Getenv("GROQ_API_KEY"))
	case domain.ProviderDeepSeek:
		return strings.TrimSpace(os.Getenv("DEEPSEEK_API_KEY"))
	case domain.ProviderTogether:
		if k := strings.TrimSpace(os.Getenv("TOGETHER_API_KEY")); k != "" {
			return k
		}
		return strings.TrimSpace(os.Getenv("TOGETHERAI_API_KEY"))
	case domain.ProviderBedrock:
		if k := strings.TrimSpace(os.Getenv("AWS_BEDROCK_API_KEY")); k != "" {
			return k
		}
		ak := strings.TrimSpace(os.Getenv("AWS_ACCESS_KEY_ID"))
		sk := strings.TrimSpace(os.Getenv("AWS_SECRET_ACCESS_KEY"))
		if ak != "" && sk != "" {
			region := strings.TrimSpace(os.Getenv("AWS_REGION"))
			if region == "" {
				region = "us-east-1"
			}
			return fmt.Sprintf("%s:%s:%s", ak, sk, region)
		}
		return ""
	case domain.ProviderVertex:
		if k := strings.TrimSpace(os.Getenv("VERTEX_API_KEY")); k != "" {
			return k
		}
		if sa := strings.TrimSpace(os.Getenv("GCP_SERVICE_ACCOUNT_KEY")); sa != "" {
			return sa
		}
		return strings.TrimSpace(os.Getenv("GOOGLE_APPLICATION_CREDENTIALS"))
	case domain.ProviderCohere:
		return strings.TrimSpace(os.Getenv("COHERE_API_KEY"))
	case domain.ProviderCerebras:
		return strings.TrimSpace(os.Getenv("CEREBRAS_API_KEY"))
	case domain.ProviderSambaNova:
		return strings.TrimSpace(os.Getenv("SAMBANOVA_API_KEY"))
	case domain.ProviderXAI:
		return strings.TrimSpace(os.Getenv("XAI_API_KEY"))
	case domain.ProviderFireworks:
		return strings.TrimSpace(os.Getenv("FIREWORKS_API_KEY"))
	case domain.ProviderPerplexity:
		return strings.TrimSpace(os.Getenv("PERPLEXITY_API_KEY"))
	case domain.ProviderAnyscale:
		return strings.TrimSpace(os.Getenv("ANYSCALE_API_KEY"))
	case domain.ProviderDeepInfra:
		return strings.TrimSpace(os.Getenv("DEEPINFRA_API_KEY"))
	case domain.ProviderNovita:
		return strings.TrimSpace(os.Getenv("NOVITA_API_KEY"))
	case domain.ProviderNebius:
		return strings.TrimSpace(os.Getenv("NEBIUS_API_KEY"))
	case domain.ProviderHyperbolic:
		return strings.TrimSpace(os.Getenv("HYPERBOLIC_API_KEY"))
	case domain.ProviderLambda:
		return strings.TrimSpace(os.Getenv("LAMBDA_API_KEY"))
	case domain.ProviderFriendli:
		if k := strings.TrimSpace(os.Getenv("FRIENDLI_TOKEN")); k != "" {
			return k
		}
		return strings.TrimSpace(os.Getenv("FRIENDLI_API_KEY"))
	case domain.ProviderOpenRouter:
		return strings.TrimSpace(os.Getenv("OPENROUTER_API_KEY"))
	case domain.ProviderVLLM:
		return strings.TrimSpace(os.Getenv("VLLM_API_KEY"))
	case domain.ProviderCloudflare:
		return strings.TrimSpace(os.Getenv("CLOUDFLARE_API_KEY"))
	case domain.ProviderDashScope:
		return strings.TrimSpace(os.Getenv("DASHSCOPE_API_KEY"))
	case domain.ProviderVolcengine:
		return strings.TrimSpace(os.Getenv("VOLCENGINE_API_KEY"))
	case domain.ProviderBigModel:
		if k := strings.TrimSpace(os.Getenv("BIGMODEL_API_KEY")); k != "" {
			return k
		}
		return strings.TrimSpace(os.Getenv("ZHIPU_API_KEY"))
	case domain.ProviderMoonshot:
		return strings.TrimSpace(os.Getenv("MOONSHOT_API_KEY"))
	case domain.ProviderMiniMax:
		return strings.TrimSpace(os.Getenv("MINIMAX_API_KEY"))
	case domain.ProviderSiliconFlow:
		return strings.TrimSpace(os.Getenv("SILICONFLOW_API_KEY"))
	case domain.ProviderVoyage:
		return strings.TrimSpace(os.Getenv("VOYAGE_API_KEY"))
	case domain.ProviderJina:
		return strings.TrimSpace(os.Getenv("JINA_API_KEY"))
	case domain.ProviderReplicate:
		return strings.TrimSpace(os.Getenv("REPLICATE_API_TOKEN"))
	case domain.ProviderAI21:
		return strings.TrimSpace(os.Getenv("AI21_API_KEY"))
	case domain.ProviderBaseten:
		return strings.TrimSpace(os.Getenv("BASETEN_API_KEY"))
	case domain.ProviderNvidia:
		return strings.TrimSpace(os.Getenv("NVIDIA_NIM_API_KEY"))
	case domain.ProviderScaleway:
		return strings.TrimSpace(os.Getenv("SCW_SECRET_KEY"))
	default:
		return ""
	}
}

func discoverEnvModelEntries(existing []config.ModelListEntry) []config.ModelListEntry {
	hasAlias := func(alias string) bool {
		for _, e := range existing {
			if strings.EqualFold(strings.TrimSpace(e.ModelName), alias) {
				return true
			}
		}
		return false
	}

	var out []config.ModelListEntry
	if gemKey := resolveProviderEnvKey(domain.ProviderGemini); gemKey != "" {
		if !hasAlias("gemini-2.5-flash") {
			out = append(out, config.ModelListEntry{
				ModelName:   "gemini-2.5-flash",
				ModelParams: config.ModelParams{Model: "gemini/gemini-2.5-flash", APIKey: gemKey},
			})
		}
		if !hasAlias("fast") {
			out = append(out, config.ModelListEntry{
				ModelName:   "fast",
				ModelParams: config.ModelParams{Model: "gemini/gemini-2.5-flash", APIKey: gemKey},
			})
		}
	}
	if antKey := resolveProviderEnvKey(domain.ProviderAnthropic); antKey != "" {
		if !hasAlias("claude-sonnet-4-20250514") {
			out = append(out, config.ModelListEntry{
				ModelName:   "claude-sonnet-4-20250514",
				ModelParams: config.ModelParams{Model: "anthropic/claude-sonnet-4-20250514", APIKey: antKey},
			})
		}
		if !hasAlias("reasoning") {
			out = append(out, config.ModelListEntry{
				ModelName:   "reasoning",
				ModelParams: config.ModelParams{Model: "anthropic/claude-sonnet-4-20250514", APIKey: antKey},
			})
		}
	}
	if oaiKey := resolveProviderEnvKey(domain.ProviderOpenAI); oaiKey != "" {
		if !hasAlias("gpt-4.1") {
			out = append(out, config.ModelListEntry{
				ModelName:   "gpt-4.1",
				ModelParams: config.ModelParams{Model: "openai/gpt-4.1", APIKey: oaiKey},
			})
		}
		if !hasAlias("fast") {
			out = append(out, config.ModelListEntry{
				ModelName:   "fast",
				ModelParams: config.ModelParams{Model: "openai/gpt-4.1-mini", APIKey: oaiKey},
			})
		}
	}
	if misKey := resolveProviderEnvKey(domain.ProviderMistral); misKey != "" {
		if !hasAlias("mistral-large-latest") {
			out = append(out, config.ModelListEntry{
				ModelName:   "mistral-large-latest",
				ModelParams: config.ModelParams{Model: "mistral/mistral-large-latest", APIKey: misKey},
			})
		}
	}
	return out
}
