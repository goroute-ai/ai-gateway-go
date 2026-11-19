package server

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/goroute-ai/ai-gateway-go/internal/a2a"
	"github.com/goroute-ai/ai-gateway-go/internal/adapter"
	"github.com/goroute-ai/ai-gateway-go/internal/adapter/anthropic"
	"github.com/goroute-ai/ai-gateway-go/internal/adapter/bedrock"
	"github.com/goroute-ai/ai-gateway-go/internal/adapter/cohere"
	"github.com/goroute-ai/ai-gateway-go/internal/adapter/gemini"
	"github.com/goroute-ai/ai-gateway-go/internal/adapter/mistral"
	"github.com/goroute-ai/ai-gateway-go/internal/adapter/ollama"
	"github.com/goroute-ai/ai-gateway-go/internal/adapter/openai"
	"github.com/goroute-ai/ai-gateway-go/internal/adapter/openaicompat"
	"github.com/goroute-ai/ai-gateway-go/internal/adapter/vertex"
	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/cache"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/finops"
	"github.com/goroute-ai/ai-gateway-go/internal/guardrails"
	"github.com/goroute-ai/ai-gateway-go/internal/health"
	"github.com/goroute-ai/ai-gateway-go/internal/logger"
	"github.com/goroute-ai/ai-gateway-go/internal/mcp"
	"github.com/goroute-ai/ai-gateway-go/internal/modelmgmt"
	"github.com/goroute-ai/ai-gateway-go/internal/observability"
	"github.com/goroute-ai/ai-gateway-go/internal/orchestrator"
	"github.com/goroute-ai/ai-gateway-go/internal/ratelimit"
	"github.com/goroute-ai/ai-gateway-go/internal/router"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/goroute-ai/ai-gateway-go/internal/ui"
	"github.com/goroute-ai/ai-gateway-go/internal/validation"
	"go.opentelemetry.io/otel/trace"
)

// GatewayServer wires together all Data Plane, Control Plane, and Cross-Cutting Platform modules on a `go-chi/chi/v5` router.
type GatewayServer struct {
	cfg                *config.Config
	netPolicy          *network.Policy
	repo               storage.Repository
	redisFabric        *storage.RedisFabric
	reg                *adapter.Registry
	vault              *auth.Vault
	authSvc            *auth.Service
	sessionMgr         *auth.SessionManager
	loginThrottle      *auth.LoginThrottle
	breachScreener     auth.BreachScreener
	ssoMgr             *auth.SSOProviderManager
	ssoStateStore      *auth.SSOStateStore
	cliLoginStore      *auth.CLILoginStore
	authResolver       *auth.AuthResolver
	keyRotation        *auth.KeyRotationManager
	keyExpiryAlerts    *auth.KeyExpiryAlertManager
	rbac               *auth.RBACEngine
	limiter            *ratelimit.Limiter
	respCache          *cache.ResponseCache
	modelMgmt          *modelmgmt.Service
	discovery          *modelmgmt.DiscoveryWorker
	intelligentRouter  *router.IntelligentRouter
	reliability        *router.ReliabilityManager
	affinityStore      *router.AffinityStore
	depBudgets         *router.DeploymentBudgetTracker
	priorityLimiter    *router.DynamicPriorityLimiter
	semanticPreRouter  *router.SemanticPreRouter
	semanticWarmed     sync.Map
	spendWorker        *finops.SpendWorker
	softBudgetNotifier *finops.SoftBudgetNotifier
	collector          *observability.Collector
	metricsExporter    *observability.OTLPMetricsExporter
	metricsStop        func()
	outboundMetrics    *network.HTTPClientMetrics
	budgetStats        *budgetLookupStats
	tracer             trace.Tracer
	tracerShutdown     func(context.Context) error
	healthMon          *health.Monitor
	validator          *validation.Validator
	guardrails         *guardrails.Engine
	mcpHub             *mcp.Hub
	a2aRouter          *a2a.RouterService
	a2aSigner          *a2a.GatewayCardSigner
	a2aStreamSub       *a2a.StreamSubscriber
	a2aPublisher       *a2a.StreamPublisher
	a2aOutboxWorker    *a2a.OutboxWorker
	a2aBridge          *a2a.OpenAIBridge
	orchestrator       *orchestrator.ToolLoopOrchestrator
	router             chi.Router
	uploadSem          chan struct{}
	uploadInFlightMu   sync.Mutex
	uploadInFlight     map[string]int64
}

// parseCustomProviderOperations maps string operation names from CustomProviderConfig
// into an openaicompat.ProviderOperations struct. Returns nil when ops is empty so
// default capability behavior is preserved.
func parseCustomProviderOperations(ops []string) *openaicompat.ProviderOperations {
	if len(ops) == 0 {
		return nil
	}
	out := &openaicompat.ProviderOperations{}
	for _, raw := range ops {
		switch strings.ToLower(strings.TrimSpace(raw)) {
		case "chat":
			out.Chat = true
		case "completion", "completions":
			out.Completion = true
		case "embeddings":
			out.Embeddings = true
		case "rerank":
			out.Rerank = true
		case "moderations":
			out.Moderations = true
		case "image_gen":
			out.ImageGen = true
		case "image_edit":
			out.ImageEdit = true
		case "image_variation":
			out.ImageVariation = true
		case "audio_stt":
			out.AudioSTT = true
		case "audio_tts":
			out.AudioTTS = true
		case "responses":
			out.Responses = true
		}
	}
	return out
}

// New constructs a fully wired GatewayServer ready to serve requests.
func New(cfg *config.Config, repo storage.Repository, redisFabric *storage.RedisFabric, httpClient *http.Client) (*GatewayServer, error) {
	if cfg == nil {
		cfg = config.Default()
	}
	if repo == nil {
		repo = storage.NewMemoryRepository()
	}

	vault, err := auth.NewVault(cfg.Auth.MasterEncryptionKey)
	if err != nil {
		return nil, err
	}

	netPolicy, err := network.NewPolicy(cfg.Security.Network.OutboundSSRF)
	if err != nil {
		return nil, fmt.Errorf("invalid outbound ssrf security policy: %w", err)
	}
	tracer, tracerShutdown, err := observability.NewOTLPTracer(context.Background(), cfg.Tracing, netPolicy)
	if err != nil {
		return nil, err
	}

	outboundMetrics := network.NewHTTPClientMetrics()
	adapterClient := httpClient
	if adapterClient == nil {
		adapterClient = network.NewHTTPClientWithOptions(netPolicy, network.HTTPClientOptions{
			RequestTimeout:        cfg.Providers.RequestTimeout,
			ResponseHeaderTimeout: cfg.Providers.ResponseHeaderTimeout,
			StreamIdleTimeout:     cfg.Providers.StreamIdleTimeout,
			MaxIdleConns:          cfg.Providers.MaxIdleConns,
			MaxIdleConnsPerHost:   cfg.Providers.MaxIdleConnsPerHost,
		}, outboundMetrics)
	} else {
		outboundMetrics = nil
	}

	mediaSSRF := config.OutboundSSRFConfig{
		AllowPrivateNetworks: false,
		AllowInsecureHTTP:    false,
		AllowedSchemes:       []string{"https"},
		BlockedIPs:           append([]string(nil), cfg.Security.Network.OutboundSSRF.BlockedIPs...),
		DialTimeout:          cfg.Security.Network.OutboundSSRF.DialTimeout,
		MaxRedirects:         cfg.Security.Network.OutboundSSRF.MaxRedirects,
		EgressProxyURL:       cfg.Security.Network.OutboundSSRF.EgressProxyURL,
	}
	mediaPolicy, err := network.NewPolicy(mediaSSRF)
	if err != nil {
		return nil, fmt.Errorf("invalid outbound media security policy: %w", err)
	}
	mediaClient := network.NewHTTPClient(mediaPolicy)

	openaiAdp := openai.NewAdapter(adapterClient)
	openaiAdp.SetSSRFPolicy(netPolicy)
	anthropicAdp := anthropic.NewAdapter(adapterClient)
	anthropicAdp.SetSSRFPolicy(netPolicy)
	geminiAdp := gemini.NewAdapter(adapterClient)
	geminiAdp.SetSSRFPolicy(netPolicy)
	mistralAdp := mistral.NewAdapter(adapterClient)
	mistralAdp.SetSSRFPolicy(netPolicy)
	ollamaAdp := ollama.NewAdapter(adapterClient)
	ollamaAdp.SetSSRFPolicy(netPolicy)
	ollamaAdp.SetMediaFetcher(mediaClient, mediaPolicy)
	vertexAdp := vertex.NewAdapter(adapterClient, netPolicy)
	vertexAdp.SetMediaFetcher(mediaClient, mediaPolicy)

	reg := adapter.NewRegistry()
	reg.Register(openaiAdp)
	reg.Register(anthropicAdp)
	reg.Register(geminiAdp)
	reg.Register(mistralAdp)
	reg.Register(ollamaAdp)
	reg.Register(bedrock.NewAdapter(adapterClient, netPolicy))
	reg.Register(vertexAdp)
	reg.Register(cohere.NewAdapter(adapterClient, netPolicy))

	profileReg := openaicompat.NewProfileRegistry(adapterClient, netPolicy)
	for _, custom := range cfg.Providers.CustomOpenAICompatible {
		opts := openaicompat.CustomProfileOptions{
			SupportedOperations: parseCustomProviderOperations(custom.SupportedOperations),
			ParamMappings:       custom.ParamMappings,
			ReasoningMapping:    custom.ReasoningMapping,
		}
		if err := profileReg.RegisterCustomWithOptions(custom, opts); err != nil {
			return nil, fmt.Errorf("failed to register custom provider %q: %w", custom.ID, err)
		}
	}
	reg.SetDynamicResolver(profileReg.DynamicResolver())

	authSvc := auth.NewService(repo, redisFabric, cfg.Auth.MasterAdminKey, cfg.Auth.L1CacheTTL, cfg.Auth.L2CacheTTL)
	authSvc.SetMasterEncryptionKey(cfg.Auth.MasterEncryptionKey)
	authSvc.SetAllowMasterKeyDataPlane(cfg.Auth.AllowMasterKeyDataPlane)
	authSvc.SetCustomAPIKeyHeader(cfg.Auth.CustomAPIKeyHeader)
	jwtVerifier := auth.NewJWTVerifier(auth.JWTConfig{
		Secret:        cfg.Auth.JWTSecret,
		Issuer:        cfg.Auth.JWTIssuer,
		Audience:      cfg.Auth.JWTAudience,
		OIDCJWKSURL:   cfg.Auth.OIDCJWKSURL,
		DefaultOrgID:  cfg.Auth.DefaultOrgID,
		Issuers:       buildOIDCIssuerConfigs(cfg.Auth.OIDCIssuers, netPolicy),
		NetworkPolicy: netPolicy,
	})
	authSvc.SetJWTVerifier(jwtVerifier)
	sessionSecret := auth.DeriveSessionSecret(cfg.Auth.SessionSecret, cfg.Auth.MasterEncryptionKey, cfg.Auth.JWTSecret, cfg.Auth.MasterAdminKey)
	sessionMgr := auth.NewSessionManager(repo, redisFabric, sessionSecret, cfg.Auth.SessionTTL)
	loginThrottle := auth.NewLoginThrottle(redisFabric)
	var breachScreener auth.BreachScreener
	if cfg.Auth.EnableHIBPCheck {
		breachScreener = auth.NewHIBPRangeClient(cfg.Auth.HIBPBaseURL, netPolicy)
	}
	authSvc.SetSessionManager(sessionMgr)
	authSvc.SetLoginThrottle(loginThrottle)

	ssoMgr, err := auth.NewSSOProviderManager(buildSSOProviderConfigs(cfg.Auth.SSOProviders), netPolicy)
	if err != nil {
		if tracerShutdown != nil {
			_ = tracerShutdown(context.Background())
		}
		return nil, fmt.Errorf("invalid sso_providers config: %w", err)
	}
	ssoStateStore := auth.NewSSOStateStore(redisFabric)
	cliLoginStore := auth.NewCLILoginStore(redisFabric, vault)

	var introspector *auth.OAuthIntrospector
	if strings.TrimSpace(cfg.Auth.Introspection.TokenInfoEndpoint) != "" {
		introspector = auth.NewOAuthIntrospector(auth.IntrospectionConfig{
			TokenInfoEndpoint: cfg.Auth.Introspection.TokenInfoEndpoint,
			ClientID:          cfg.Auth.Introspection.ClientID,
			ClientSecret:      cfg.Auth.Introspection.ClientSecret,
			Mode:              cfg.Auth.Introspection.Mode,
			UserIDField:       cfg.Auth.Introspection.UserIDField,
			EmailField:        cfg.Auth.Introspection.EmailField,
			RoleField:         cfg.Auth.Introspection.RoleField,
			OrgIDField:        cfg.Auth.Introspection.OrgIDField,
			TeamIDField:       cfg.Auth.Introspection.TeamIDField,
			CacheTTL:          cfg.Auth.Introspection.CacheTTL,
			NetworkPolicy:     netPolicy,
			Redis:             redisFabric,
		})
	}

	var proxyAuth *auth.ProxyAuthenticator
	if cfg.Auth.ProxyAuth.Enabled {
		proxyAuth, err = auth.NewProxyAuthenticator(auth.ProxyAuthConfig{
			Enabled:           cfg.Auth.ProxyAuth.Enabled,
			TrustedProxyCIDRs: cfg.Auth.ProxyAuth.TrustedProxyCIDRs,
			HeaderMapping:     cfg.Auth.ProxyAuth.HeaderMapping,
		})
		if err != nil {
			if tracerShutdown != nil {
				_ = tracerShutdown(context.Background())
			}
			return nil, fmt.Errorf("invalid proxy auth config: %w", err)
		}
	}

	rbac := auth.NewRBACEngine(repo)
	rbac.SetRedis(redisFabric)
	authSvc.AddInvalidationHandler(rbac.HandleInvalidation)

	authResolver := auth.NewAuthResolver(auth.ResolverConfig{
		Service:                    authSvc,
		Repo:                       repo,
		RBAC:                       rbac,
		JWTVerifier:                jwtVerifier,
		Introspector:               introspector,
		ProxyAuth:                  proxyAuth,
		EnableDataPlaneJWT:         cfg.Auth.EnableDataPlaneJWT,
		DefaultOrgID:               cfg.Auth.DefaultOrgID,
		IntrospectionAutoRegister:  cfg.Auth.Introspection.AutoRegister,
		IntrospectionDefaultTeamID: cfg.Auth.Introspection.DefaultTeamID,
		IntrospectionDefaultRole:   cfg.Auth.Introspection.DefaultRole,
		ProxyAutoRegister:          cfg.Auth.ProxyAuth.AutoRegister,
		ProxyDefaultTeamID:         cfg.Auth.ProxyAuth.DefaultTeamID,
		ProxyDefaultRole:           cfg.Auth.ProxyAuth.DefaultRole,
	})
	authSvc.SetDataPlaneResolver(authResolver)
	keyRotation := auth.NewKeyRotationManager(authSvc, repo, redisFabric, auth.KeyRotationConfig{
		PollInterval:  cfg.Auth.KeyRotationPollInterval,
		GracePeriod:   cfg.Auth.KeyRotationGracePeriod,
		NetworkPolicy: netPolicy,
	})
	keyExpiryAlerts := auth.NewKeyExpiryAlertManager(repo, redisFabric, auth.KeyExpiryAlertConfig{
		PollInterval:  cfg.Auth.KeyExpiryAlertPollInterval,
		NetworkPolicy: netPolicy,
	})
	limiter := ratelimit.NewLimiter(redisFabric, cfg.RateLimit.WindowSeconds, cfg.RateLimit.ConcurrencyTTLSec)
	limiter.SetEnabled(cfg.RateLimit.Enabled)
	limiter.SetFallbackToLocalOnOutage(cfg.RateLimit.FallbackToLocalOnOutage)
	limiter.SetDefaultEstimatedTPM(cfg.RateLimit.DefaultEstimatedTPM)
	limiter.SetRedisTimeout(cfg.RateLimit.RedisTimeout)
	limiter.SetGlobalLimits(cfg.RateLimit.GlobalRPMLimit, cfg.RateLimit.GlobalTPMLimit, cfg.RateLimit.GlobalMaxConcurrent)
	respCache := cache.NewResponseCacheWithL1Capacity(cfg.Cache.Enabled, cfg.Cache.DefaultTTL, cfg.Cache.MaxL1Entries, redisFabric)
	modelMgmtSvc := modelmgmt.NewServiceWithRBAC(repo, rbac)
	discWorker := modelmgmt.NewDiscoveryWorker(repo, reg, vault, redisFabric, cfg.Discovery.SyncInterval, cfg.Discovery.AutoApprove)

	collector := observability.NewCollector()
	budgetStats := &budgetLookupStats{}
	collector.SetAdditionalMetricsProvider(func() map[string]float64 {
		l1Size, l1Capacity, l1Evictions := respCache.L1Stats()
		cacheMetrics := respCache.Metrics()
		metrics := map[string]float64{
			"gateway_response_cache_l1_entries":               float64(l1Size),
			"gateway_response_cache_l1_capacity":              float64(l1Capacity),
			"gateway_response_cache_l1_evictions_total":       float64(l1Evictions),
			"gateway_response_cache_l1_hits_total":            float64(cacheMetrics.L1Hits),
			"gateway_response_cache_l1_misses_total":          float64(cacheMetrics.L1Misses),
			"gateway_response_cache_l2_hits_total":            float64(cacheMetrics.L2Hits),
			"gateway_response_cache_epoch_lookups_total":      float64(cacheMetrics.EpochChecks),
			"gateway_response_cache_epoch_lookup_seconds_sum": float64(cacheMetrics.EpochNanos) / float64(time.Second),
		}
		if outboundMetrics != nil {
			snapshot := outboundMetrics.Snapshot()
			metrics["gateway_upstream_http_requests_total"] = float64(snapshot.Requests)
			metrics["gateway_upstream_dial_attempts_total"] = float64(snapshot.DialAttempts)
			metrics["gateway_upstream_tls_handshakes_total"] = float64(snapshot.TLSHandshakes)
			metrics["gateway_upstream_connections_fresh_total"] = float64(snapshot.FreshConnections)
			metrics["gateway_upstream_connections_reused_total"] = float64(snapshot.ReusedConnections)
			metrics["gateway_upstream_responses_http1_total"] = float64(snapshot.HTTP1Responses)
			metrics["gateway_upstream_responses_http2_total"] = float64(snapshot.HTTP2Responses)
			metrics["gateway_upstream_first_byte_wait_seconds_sum"] = float64(snapshot.FirstByteWaitNanos) / float64(time.Second)
			metrics["gateway_upstream_first_byte_wait_count"] = float64(snapshot.FirstByteWaitCount)
			metrics["gateway_upstream_idle_timeouts_total"] = float64(snapshot.IdleTimeouts)
		}
		metrics["gateway_budget_indexed_model_lookups_total"] = float64(budgetStats.indexedLookups.Load())
		metrics["gateway_budget_catalog_scans_total"] = float64(budgetStats.catalogScans.Load())
		metrics["gateway_budgeted_reservation_checks_total"] = float64(budgetStats.budgetedChecks.Load())
		metrics["gateway_budget_pricing_summary_lookups_total"] = float64(budgetStats.pricingSummaries.Load())
		if recordedRequests := collector.Snapshot().TotalRequests; recordedRequests > 0 {
			metrics["gateway_budgeted_request_share"] = float64(budgetStats.budgetedChecks.Load()) / float64(recordedRequests)
		}
		if catalog, ok := repo.(storage.GlobalModelCatalogSize); ok {
			metrics["gateway_model_catalog_size"] = float64(catalog.GlobalModelCatalogSize())
		}
		if summaryStats, ok := repo.(storage.GlobalModelPricingSummaryMetrics); ok {
			metrics["gateway_budget_pricing_summary_rebuilds_total"] = float64(summaryStats.PricingSummaryRebuilds())
		}
		var mem runtime.MemStats
		runtime.ReadMemStats(&mem)
		metrics["gateway_go_heap_alloc_bytes"] = float64(mem.HeapAlloc)
		metrics["gateway_go_heap_inuse_bytes"] = float64(mem.HeapInuse)
		metrics["gateway_go_heap_objects"] = float64(mem.HeapObjects)
		metrics["gateway_go_gc_cycles_total"] = float64(mem.NumGC)
		metrics["gateway_go_gc_pause_seconds_total"] = float64(mem.PauseTotalNs) / float64(time.Second)
		if lookupStats, ok := repo.(storage.PostgresLookupMetrics); ok {
			subscriptionQueries, emptySubscriptionQueries, guardrailQueries, missingGuardrailQueries := lookupStats.LookupQueryStats()
			metrics["gateway_storage_subscription_fallback_queries_total"] = float64(subscriptionQueries)
			metrics["gateway_storage_empty_subscription_queries_total"] = float64(emptySubscriptionQueries)
			metrics["gateway_storage_guardrail_fallback_queries_total"] = float64(guardrailQueries)
			metrics["gateway_storage_missing_guardrail_queries_total"] = float64(missingGuardrailQueries)
		}
		return metrics
	})
	var metricsExporter *observability.OTLPMetricsExporter
	if cfg.Tracing.Enabled && strings.TrimSpace(cfg.Tracing.OTLPEndpoint) != "" {
		metricsExporter, err = observability.NewOTLPMetricsExporterFromTracingConfig(collector, cfg.Tracing, 0, netPolicy)
		if err != nil {
			if tracerShutdown != nil {
				_ = tracerShutdown(context.Background())
			}
			return nil, err
		}
	}
	healthMon := health.NewMonitor(repo, reg, vault, 60*time.Second, 5*time.Second)
	validator := validation.NewValidator(repo)
	validator.SetAllowDefaultFallbacks(len(cfg.Router.DefaultFallbacks) > 0)
	guardrailsEng := guardrails.NewEngine(repo)

	ir := router.NewIntelligentRouter(repo, cfg.Router)
	ir.SetProviderCallable(func(provider domain.ProviderType) bool {
		_, err := reg.Get(provider)
		return err == nil
	})
	if cfg.Router.Bandit.Enabled {
		bandit := router.NewBanditPreRouter(cfg.Router, redisFabric, router.WithBanditRepository(repo))
		ir.SetBanditPreRouter(bandit)
	}
	lb := router.NewLoadBalancer(redisFabric)
	relMgr := router.NewReliabilityManager(repo, reg, ir, lb, vault, rbac, redisFabric, cfg.Router)
	relMgr.SetCollector(collector)
	relMgr.SetHealthMonitor(healthMon)
	relMgr.SetLimiter(limiter, cfg.RateLimit.DynamicOnUpstream429)

	affinityStore := router.NewAffinityStoreFromRouterConfig(redisFabric, cfg.Router)
	affinityStore.SetCollector(collector)
	relMgr.SetAffinityStore(affinityStore)

	depBudgets := router.NewDeploymentBudgetTracker(redisFabric, router.DeploymentBudgetConfig{})
	depBudgets.SetCollector(collector)
	relMgr.SetDeploymentBudgetTracker(depBudgets)

	if cfg.Router.Scheduler.Enabled {
		maxConcurrent := cfg.RateLimit.GlobalMaxConcurrent
		if maxConcurrent <= 0 {
			maxConcurrent = 256
		}
		sched := router.NewPrioritySchedulerWithConfig(router.SchedulerConfig{
			Enabled:          true,
			MaxConcurrent:    maxConcurrent,
			MaxQueueDepth:    cfg.Router.Scheduler.MaxQueueDepth,
			QueueWaitTimeout: cfg.Router.Scheduler.MaxWaitTime,
		})
		relMgr.SetScheduler(sched)
	}

	var ptuShareRepo storage.PTUShareRepository
	if pr, ok := repo.(storage.PTUShareRepository); ok {
		ptuShareRepo = pr
	}
	priorityLimiter := router.NewDynamicPriorityLimiter(redisFabric, ptuShareRepo, router.DynamicPriorityConfig{
		Enabled:               cfg.Router.PriorityCapacity.Enabled,
		SaturationThreshold:   cfg.Router.PriorityCapacity.SaturationThreshold,
		ActiveCallerTTL:       cfg.Router.PriorityCapacity.ActiveCallerTTL,
		WindowDuration:        cfg.Router.PriorityCapacity.WindowDuration,
		DefaultWeight:         cfg.Router.PriorityCapacity.DefaultWeight,
		DefaultBorrowMultiple: cfg.Router.PriorityCapacity.DefaultBorrowMultiple,
	})
	relMgr.SetPriorityCapacityLimiter(priorityLimiter)

	var semanticPreRouter *router.SemanticPreRouter
	if cfg.Router.SemanticRouter.Enabled {
		embedFn := func(ctx context.Context, orgID, model string, inputs []string) ([][]float32, error) {
			if strings.TrimSpace(model) == "" {
				return nil, fmt.Errorf("semantic router embedding_model is required")
			}
			resp, _, err := relMgr.ExecuteEmbeddings(ctx, &domain.IdentityContext{OrgID: orgID}, &domain.CanonicalEmbeddingRequest{
				Model: model,
				Input: inputs,
			})
			if err != nil {
				return nil, err
			}
			if resp == nil || len(resp.Data) == 0 {
				return nil, fmt.Errorf("empty embeddings response")
			}
			vecs := make([][]float32, len(resp.Data))
			for i, item := range resp.Data {
				idx := item.Index
				if idx < 0 || idx >= len(vecs) || vecs[idx] != nil {
					idx = i
				}
				v := make([]float32, len(item.Embedding))
				for j, f := range item.Embedding {
					v[j] = float32(f)
				}
				vecs[idx] = v
			}
			return vecs, nil
		}
		semanticPreRouter = router.NewSemanticPreRouter(cfg.Router.SemanticRouter, cfg.Router.DefaultFastAlias, embedFn, redisFabric)
		ir.SetSemanticPreRouter(semanticPreRouter)
	}

	if cfg.Router.CacheAwareRouting {
		qual := router.NewQualityPreRouter(repo, cfg.Router, func(ctx context.Context, orgID string, req *domain.CanonicalChatRequest) (string, bool) {
			if req == nil {
				return "", false
			}
			if respCache != nil && respCache.IsCacheable(req, "") {
				if key := respCache.ComputeKey(orgID, req); key != "" {
					if cached, hit := respCache.Get(ctx, key); hit && cached != nil {
						if mg, err := repo.GetModelGroupByAlias(ctx, orgID, cached.Model); err == nil && mg != nil && mg.IsActive {
							return mg.Alias, true
						}
						if strings.TrimSpace(cfg.Router.DefaultFastAlias) != "" {
							return cfg.Router.DefaultFastAlias, true
						}
						if cached.Model != "" {
							return cached.Model, true
						}
					}
				}
			}
			if affinityStore != nil && cfg.Router.PromptCacheAffinity {
				if groups, err := repo.ListModelGroups(ctx, orgID); err == nil {
					for _, g := range groups {
						if g == nil || !g.IsActive {
							continue
						}
						if depID, _ := affinityStore.Lookup(ctx, orgID, g.Alias, req, ""); depID != "" {
							return g.Alias, true
						}
					}
				}
			}
			return "", false
		})
		ir.SetQualityPreRouter(qual)
	}

	spendWorker := finops.NewSpendWorker(repo, limiter, cfg.FinOps)
	spendWorker.SetCollector(collector)
	spendWorker.SetDeploymentSpendRecorder(depBudgets)
	softBudgetNotifier := finops.NewSoftBudgetNotifier(repo, redisFabric, netPolicy, cfg.FinOps.SoftBudgetWebhookURL, cfg.FinOps.SoftBudgetCooldownSec)
	spendWorker.SetSoftBudgetNotifier(softBudgetNotifier)

	mcpDispatcher := mcp.NewTransportDispatcher(netPolicy, redisFabric, cfg.MCP.AllowStdioServers)
	mcpAuthResolver := mcp.NewAuthResolver(vault, netPolicy)
	mcpHub := mcp.NewHub(repo, vault, rbac, mcpDispatcher, mcpAuthResolver)

	mcpSecret := cfg.MCP.CacheKeySecret
	if mcpSecret == "" {
		mcpSecret = cfg.Auth.MasterEncryptionKey
	}
	mcpHub.SetCache(mcp.NewMCPCache([]byte(mcpSecret), redisFabric))
	mcpHub.SetMRTR(mcp.NewMRTRManager(vault, redisFabric, "mrtr_v1"))
	mcpHub.SetSubscriptions(mcp.NewSubscriptionManager(redisFabric))
	mcpHub.SetGuardrails(guardrailsEng)
	mcpHub.SetLimiter(limiter)
	mcpHub.SetSpendRecorder(spendWorker)

	a2aSigner := a2a.NewGatewayCardSigner(cfg.A2A.SigningKeyID, "ES256", nil, vault)
	a2aVerifier := a2a.NewUpstreamCardVerifier(nil)
	a2aRouter := a2a.NewRouterService(repo, vault, rbac, netPolicy, redisFabric, a2aSigner, a2aVerifier)
	a2aRouter.SetGuardrails(guardrailsEng)
	a2aStreamSub := a2a.NewStreamSubscriber(repo, redisFabric)
	a2aPublisher := a2a.NewStreamPublisher(repo, redisFabric, cfg.A2A.StreamPublishInterval)
	a2aOutboxWorker := a2a.NewOutboxWorker(repo, netPolicy, cfg.A2A.MaxPushRetries, 200*time.Millisecond)
	a2aBridge := a2a.NewOpenAIBridge(a2aRouter, a2aStreamSub, repo, rbac)
	toolOrchestrator := orchestrator.NewToolLoopOrchestrator(relMgr, mcpHub, orchestrator.DefaultBudgetPolicy())

	var uploadSem chan struct{}
	if cfg.Server.MaxConcurrentFileUploads > 0 {
		uploadSem = make(chan struct{}, cfg.Server.MaxConcurrentFileUploads)
	}

	s := &GatewayServer{
		cfg:                cfg,
		netPolicy:          netPolicy,
		repo:               repo,
		redisFabric:        redisFabric,
		reg:                reg,
		vault:              vault,
		authSvc:            authSvc,
		sessionMgr:         sessionMgr,
		loginThrottle:      loginThrottle,
		breachScreener:     breachScreener,
		ssoMgr:             ssoMgr,
		ssoStateStore:      ssoStateStore,
		cliLoginStore:      cliLoginStore,
		authResolver:       authResolver,
		keyRotation:        keyRotation,
		keyExpiryAlerts:    keyExpiryAlerts,
		rbac:               rbac,
		limiter:            limiter,
		respCache:          respCache,
		modelMgmt:          modelMgmtSvc,
		discovery:          discWorker,
		intelligentRouter:  ir,
		reliability:        relMgr,
		affinityStore:      affinityStore,
		depBudgets:         depBudgets,
		priorityLimiter:    priorityLimiter,
		semanticPreRouter:  semanticPreRouter,
		spendWorker:        spendWorker,
		softBudgetNotifier: softBudgetNotifier,
		collector:          collector,
		metricsExporter:    metricsExporter,
		outboundMetrics:    outboundMetrics,
		budgetStats:        budgetStats,
		tracer:             tracer,
		tracerShutdown:     tracerShutdown,
		healthMon:          healthMon,
		validator:          validator,
		guardrails:         guardrailsEng,
		mcpHub:             mcpHub,
		a2aRouter:          a2aRouter,
		a2aSigner:          a2aSigner,
		a2aStreamSub:       a2aStreamSub,
		a2aPublisher:       a2aPublisher,
		a2aOutboxWorker:    a2aOutboxWorker,
		a2aBridge:          a2aBridge,
		orchestrator:       toolOrchestrator,
		uploadSem:          uploadSem,
		uploadInFlight:     make(map[string]int64),
	}
	s.ConfigureGuardrailScannersFromConfig(cfg.Guardrails, netPolicy)
	relMgr.SetFallbackQuotaChecker(s.checkFallbackModelQuota)
	s.setupRoutes()
	if err := s.bootstrap(context.Background()); err != nil {
		if s.tracerShutdown != nil {
			_ = s.tracerShutdown(context.Background())
		}
		return nil, err
	}
	s.warmupSemanticPreRouter(context.Background())
	if err := s.seedGuardrailsFromConfig(context.Background()); err != nil {
		if s.tracerShutdown != nil {
			_ = s.tracerShutdown(context.Background())
		}
		return nil, err
	}
	pipeline := s.GuardrailPipeline()
	mcpHub.SetGuardrailPipeline(pipeline)
	if tpRepo, ok := repo.(storage.ToolPolicyRepository); ok && tpRepo != nil {
		toolOrchestrator.SetToolPolicyRepository(tpRepo)
	}
	toolOrchestrator.SetToolGuardrails(s.newOrchestratorToolGuardrailDriver())
	return s, nil
}

func (s *GatewayServer) setupRoutes() {
	r := chi.NewRouter()
	r.Use(middleware.Recoverer)
	r.Use(trustedRealIPMiddleware(s.cfg.Security.Network.InboundCaller.TrustedProxyCIDRs))
	r.Use(inboundCallerMiddleware(s.cfg.Security.Network.InboundCaller))
	r.Use(observability.TraceMiddlewareWithTracer(s.tracer))
	r.Use(logger.HTTPMiddleware(nil))
	r.Use(SecurityHeadersMiddleware(s.cfg.Server.EnableHSTS))
	r.Use(CORSMiddleware(s.cfg.Server.CORSAllowedOrigins, s.cfg.Server.CORSAllowCredentials))

	// Health, Readiness & Prometheus Metrics endpoints
	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "service": "ai-gateway-go"})
	})
	r.Get("/readyz", func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()

		if s.repo != nil {
			if err := s.repo.Ping(ctx); err != nil {
				writeJSON(w, http.StatusServiceUnavailable, map[string]any{
					"status": "unready",
					"error":  fmt.Sprintf("storage unavailable: %v", err),
				})
				return
			}
		}
		if s.redisFabric != nil && s.redisFabric.Client() != nil {
			if err := s.redisFabric.Ping(ctx); err != nil {
				writeJSON(w, http.StatusServiceUnavailable, map[string]any{
					"status": "unready",
					"error":  fmt.Sprintf("redis unavailable: %v", err),
				})
				return
			}
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "ready"})
	})
	r.Method(http.MethodGet, "/metrics", s.metricsAuthMiddleware(s.collector.PrometheusHandler()))

	// Embedded Operator Web UI & Streaming Chat Playground (/ui/*)
	ui.RegisterRoutes(r)

	// Control Plane Authentication (/auth/*)
	r.Route("/auth", func(authRouter chi.Router) {
		authRouter.Post("/login", s.handleAuthLogin)
		authRouter.Get("/sso/providers", s.handleAuthSSOProviders)
		authRouter.Get("/sso/{provider}/login", s.handleAuthSSOLogin)
		authRouter.Get("/sso/{provider}/callback", s.handleAuthSSOCallback)
		authRouter.Post("/cli/start", s.handleAuthCLIStart)
		authRouter.Get("/cli/poll/{login_id}", s.handleAuthCLIPoll)
		authRouter.Group(func(protected chi.Router) {
			protected.Use(auth.AdminControlPlaneMiddleware(s.authSvc))
			protected.Post("/logout", s.handleAuthLogout)
			protected.Get("/me", s.handleAuthMe)
			protected.Post("/password", s.handleAuthPassword)
			protected.Post("/cli/complete/{login_id}", s.handleAuthCLIComplete)
		})
	})

	// Data Plane (/v1/* — OpenAI-Compatible Unified Inference API)
	r.Route("/v1", func(v1 chi.Router) {
		v1.Use(auth.DataPlaneMiddleware(s.authSvc, s.rbac))
		v1.Post("/chat/completions", s.handleChatCompletions)
		v1.Post("/completions", s.handleLegacyCompletions)
		v1.Post("/embeddings", s.handleEmbeddings)
		v1.Get("/models", s.handleListModels)
		v1.Post("/rerank", s.handleRerank)
		v1.Post("/moderations", s.handleModerations)
		v1.Post("/messages", s.handleAnthropicMessages)
		v1.Post("/messages/count_tokens", s.handleAnthropicCountTokens)
		v1.Post("/tokenize", s.handleTokenize)
		v1.Post("/audio/transcriptions", s.handleAudioTranscriptions)
		v1.Post("/audio/translations", s.handleAudioTranslations)
		v1.Post("/audio/speech", s.handleAudioSpeech)
		v1.Post("/images/generations", s.handleImageGenerations)
		v1.Post("/images/edits", s.handleImageEdits)
		v1.Post("/images/variations", s.handleImageVariations)

		// Files
		v1.Post("/files", s.handleUploadFile)
		v1.Get("/files", s.handleListFiles)
		v1.Get("/files/{file_id}", s.handleGetFile)
		v1.Get("/files/{file_id}/content", s.handleGetFileContent)
		v1.Delete("/files/{file_id}", s.handleDeleteFile)

		// Batches
		v1.Post("/batches", s.handleCreateBatch)
		v1.Get("/batches", s.handleListBatches)
		v1.Get("/batches/{batch_id}", s.handleGetBatch)
		v1.Post("/batches/{batch_id}/cancel", s.handleCancelBatch)

		// Responses API & Realtime WebSocket
		v1.Post("/responses", s.handleResponses)
		v1.Get("/realtime", s.handleRealtimeWebSocket)

		// Guardrails Data Plane evaluation
		v1.Post("/guardrails/apply", s.handleApplyGuardrails)

		// Data Plane Self-Inspection
		v1.Get("/key/info", s.handleKeySelfInfo)
	})

	// Governed Developer Self-Service Keys (/v1/self/*)
	r.Route("/v1/self", func(self chi.Router) {
		self.Use(auth.SelfServiceMiddleware(s.authSvc))
		self.Get("/keys", s.handleSelfListKeys)
		self.Post("/keys", s.handleSelfCreateKey)
		self.Delete("/keys/{keyID}", s.handleSelfRevokeKey)
		self.Post("/keys/{keyID}/rotate", s.handleSelfRotateKey)
	})

	// Unversioned and protocol-specific aliases for SDK compatibility
	r.Group(func(unv chi.Router) {
		unv.Use(auth.DataPlaneMiddleware(s.authSvc, s.rbac))
		unv.Post("/chat/completions", s.handleChatCompletions)
		unv.Post("/completions", s.handleLegacyCompletions)
		unv.Post("/embeddings", s.handleEmbeddings)
		unv.Get("/models", s.handleListModels)
		unv.Post("/rerank", s.handleRerank)
		unv.Post("/v2/rerank", s.handleRerank)
		unv.Post("/moderations", s.handleModerations)
		unv.Post("/messages", s.handleAnthropicMessages)
		unv.Post("/tokenize", s.handleTokenize)
		unv.Post("/audio/transcriptions", s.handleAudioTranscriptions)
		unv.Post("/audio/translations", s.handleAudioTranslations)
		unv.Post("/audio/speech", s.handleAudioSpeech)
		unv.Post("/images/generations", s.handleImageGenerations)
		unv.Post("/images/edits", s.handleImageEdits)
		unv.Post("/images/variations", s.handleImageVariations)

		// Files
		unv.Post("/files", s.handleUploadFile)
		unv.Get("/files", s.handleListFiles)
		unv.Get("/files/{file_id}", s.handleGetFile)
		unv.Get("/files/{file_id}/content", s.handleGetFileContent)
		unv.Delete("/files/{file_id}", s.handleDeleteFile)

		// Batches
		unv.Post("/batches", s.handleCreateBatch)
		unv.Get("/batches", s.handleListBatches)
		unv.Get("/batches/{batch_id}", s.handleGetBatch)
		unv.Post("/batches/{batch_id}/cancel", s.handleCancelBatch)

		// Responses & Realtime
		unv.Post("/responses", s.handleResponses)
		unv.Get("/realtime", s.handleRealtimeWebSocket)
	})

	// OpenAI Direct Wire Spec (/openai/v1/*)
	r.Route("/openai/v1", func(oai chi.Router) {
		oai.Use(auth.DataPlaneMiddleware(s.authSvc, s.rbac))
		oai.Post("/responses", s.handleResponses)
		oai.Get("/realtime", s.handleRealtimeWebSocket)
	})

	// Anthropic Native Ingress Spec (/anthropic/v1/*)
	r.Route("/anthropic/v1", func(ant chi.Router) {
		ant.Use(auth.DataPlaneMiddleware(s.authSvc, s.rbac))
		ant.Post("/messages", s.handleAnthropicMessages)
		ant.Post("/messages/count_tokens", s.handleAnthropicCountTokens)
	})

	// MCP Data Plane (/mcp/* — Model Context Protocol Virtual Hub, Scoped Server & Curated Toolsets)
	if s.cfg.MCP.Enabled {
		if s.cfg.MCP.SubscriptionsListenActive {
			r.With(auth.DataPlaneMiddleware(s.authSvc, s.rbac)).Get("/mcp/subscriptions/listen", s.handleMCPSubscriptionsListen)
		}
		r.With(auth.DataPlaneMiddleware(s.authSvc, s.rbac)).Post("/mcp", s.handleMCPVirtualHub)
		r.Route("/mcp", func(mcpRouter chi.Router) {
			mcpRouter.Use(auth.DataPlaneMiddleware(s.authSvc, s.rbac))
			mcpRouter.Post("/", s.handleMCPVirtualHub)
			mcpRouter.Post("/{serverSlug}", s.handleMCPScopedServer)
			mcpRouter.Post("/toolsets/{toolsetSlug}", s.handleMCPToolset)
		})

		// MCP REST Bridge (BL-03)
		restBridge := mcp.NewRESTBridge(s.mcpHub)
		r.Route("/mcp-rest", func(restRouter chi.Router) {
			restRouter.Use(auth.DataPlaneMiddleware(s.authSvc, s.rbac))
			restRouter.Get("/tools/list", restBridge.HandleListTools)
			restRouter.Post("/tools/call", restBridge.HandleCallTool)
		})

		// Progressive Catalog Registry Feed (BL-04)
		r.Route("/v1/goroute/mcp", func(regRouter chi.Router) {
			regRouter.Use(auth.DataPlaneMiddleware(s.authSvc, s.rbac))
			regRouter.Get("/registry", s.handleMCPRegistryFeed)
		})
	}

	// Well-known Agent Card discovery
	r.Get("/.well-known/agent-card.json", s.handleA2AWellKnownCard)

	// A2A Data Plane (/a2a/v1/* — Agent-to-Agent Protocol Service)
	if s.cfg.A2A.Enabled {
		r.Route("/a2a/v1/agents/{agentSlug}", func(a2aRouter chi.Router) {
			a2aRouter.Use(auth.DataPlaneMiddleware(s.authSvc, s.rbac))
			a2aRouter.Post("/", s.handleA2AAgentMessage)
			a2aRouter.Get("/tasks", s.handleA2AListTasks)
			a2aRouter.Get("/tasks/{taskID}", s.handleA2AGetTask)
			a2aRouter.Post("/tasks/{taskID}:cancel", s.handleA2ACancelTask)
			a2aRouter.Get("/tasks/{taskID}:subscribe", s.handleA2ASubscribeTask)
			a2aRouter.Post("/tasks/{taskID}:subscribe", s.handleA2ASubscribeTask)
		})
	}

	// SCIM v2 Provisioning (/scim/v2/*)
	r.Route("/scim/v2", func(scim chi.Router) {
		scim.Use(s.scimAuthMiddleware)
		scim.Get("/Users", s.handleSCIMListUsers)
		scim.Post("/Users", s.handleSCIMCreateUser)
		scim.Get("/Users/{id}", s.handleSCIMGetUser)
		scim.Put("/Users/{id}", s.handleSCIMReplaceUser)
		scim.Patch("/Users/{id}", s.handleSCIMPatchUser)
		scim.Delete("/Users/{id}", s.handleSCIMDeleteUser)

		scim.Get("/Groups", s.handleSCIMListGroups)
		scim.Post("/Groups", s.handleSCIMCreateGroup)
		scim.Get("/Groups/{id}", s.handleSCIMGetGroup)
		scim.Put("/Groups/{id}", s.handleSCIMReplaceGroup)
		scim.Patch("/Groups/{id}", s.handleSCIMPatchGroup)
		scim.Delete("/Groups/{id}", s.handleSCIMDeleteGroup)
	})

	// Control Plane (/admin/v1/* — Enterprise Management, Governance, Discovery, Security & FinOps API)
	r.Route("/admin/v1", func(adm chi.Router) {
		adm.Use(auth.AdminControlPlaneMiddleware(s.authSvc))

		// Organizations, 4-Layer Policies & Security Guardrails
		adm.Post("/organizations", s.handleAdminCreateOrg)
		adm.Get("/organizations", s.handleAdminListOrgs)
		adm.Put("/organizations/{orgID}", s.handleAdminUpdateOrg)
		adm.Post("/organizations/{orgID}/subscriptions", s.handleAdminSetOrgSubscription)
		adm.Get("/organizations/{orgID}/subscriptions", s.handleAdminGetOrgSubscriptions)
		adm.Post("/organizations/{orgID}/models", s.handleAdminSetOrgModelPolicy)
		adm.Get("/organizations/{orgID}/models", s.handleAdminGetOrgModelPolicies)
		adm.Post("/organizations/{orgID}/guardrails", s.handleAdminSetGuardrailPolicy)
		adm.Get("/organizations/{orgID}/guardrails", s.handleAdminGetGuardrailPolicy)
		adm.Post("/organizations/{orgID}/guardrails/simulate", s.handleAdminSimulateGuardrailsExpanded)

		// Guardrail Registry, Bindings, Tool Trust Policies, and Usage Rollups
		adm.Post("/organizations/{orgID}/guardrail-definitions", s.handleAdminCreateGuardrailDefinition)
		adm.Get("/organizations/{orgID}/guardrail-definitions", s.handleAdminListGuardrailDefinitions)
		adm.Get("/guardrail-definitions/{guardrailID}", s.handleAdminGetGuardrailDefinition)
		adm.Put("/guardrail-definitions/{guardrailID}", s.handleAdminUpdateGuardrailDefinition)
		adm.Patch("/guardrail-definitions/{guardrailID}", s.handleAdminPatchGuardrailDefinition)
		adm.Delete("/guardrail-definitions/{guardrailID}", s.handleAdminDeleteGuardrailDefinition)
		adm.Post("/guardrail-definitions/{guardrailID}/status", s.handleAdminSetGuardrailDefinitionStatus)

		adm.Post("/guardrail-bindings", s.handleAdminCreateGuardrailBinding)
		adm.Get("/organizations/{orgID}/guardrail-bindings", s.handleAdminListGuardrailBindings)
		adm.Delete("/guardrail-bindings/{bindingID}", s.handleAdminDeleteGuardrailBinding)

		adm.Post("/organizations/{orgID}/tool-policies", s.handleAdminUpsertToolPolicy)
		adm.Get("/organizations/{orgID}/tool-policies", s.handleAdminListToolPolicies)
		adm.Delete("/organizations/{orgID}/tool-policies/{policyID}", s.handleAdminDeleteToolPolicy)

		adm.Get("/organizations/{orgID}/guardrail-usage", s.handleAdminGetGuardrailUsage)

		// Teams, Memberships, Projects & Users
		adm.Post("/teams", s.handleAdminCreateTeam)
		adm.Get("/teams", s.handleAdminListTeams)
		adm.Put("/teams/{teamID}", s.handleAdminUpdateTeam)
		adm.Delete("/teams/{teamID}", s.handleAdminDeleteTeam)
		adm.Post("/teams/{teamID}/members", s.handleAdminUpsertTeamMember)
		adm.Post("/teams/{teamID}/members/bulk", s.handleAdminBulkTeamMembers)
		adm.Get("/teams/{teamID}/members", s.handleAdminListTeamMembers)
		adm.Post("/teams/{teamID}/members/{userID}/reset-spend", s.handleAdminResetTeamMemberSpend)
		adm.Delete("/teams/{teamID}/members/{userID}", s.handleAdminDeleteTeamMember)
		adm.Post("/projects", s.handleAdminCreateProject)
		adm.Get("/projects", s.handleAdminListProjects)
		adm.Put("/projects/{projectID}", s.handleAdminUpdateProject)
		adm.Delete("/projects/{projectID}", s.handleAdminDeleteProject)
		adm.Post("/users", s.handleAdminCreateUser)
		adm.Get("/users", s.handleAdminListUsers)
		adm.Put("/users/{userID}", s.handleAdminUpdateUser)
		adm.Delete("/users/{userID}", s.handleAdminDeleteUser)

		// Virtual API Keys & JWT Claim-to-Key Mappings
		adm.Post("/keys", s.handleAdminIssueKey)
		adm.Get("/keys", s.handleAdminListKeys)
		adm.Post("/keys/bulk-update", s.handleAdminBulkUpdateKeys)
		adm.Get("/keys/{keyID}", s.handleAdminGetKey)
		adm.Put("/keys/{keyID}", s.handleAdminUpdateKey)
		adm.Post("/keys/{keyID}/rotate", s.handleAdminRotateKey)
		adm.Post("/keys/{keyID}/block", s.handleAdminBlockKey)
		adm.Post("/keys/{keyID}/unblock", s.handleAdminUnblockKey)
		adm.Post("/keys/{keyID}/reset-spend", s.handleAdminResetKeySpend)
		adm.Post("/keys/{keyID}/revoke", s.handleAdminRevokeKey)
		adm.Delete("/keys/{keyID}", s.handleAdminRevokeKey)
		adm.Post("/jwt-mappings", s.handleAdminCreateJWTMapping)
		adm.Get("/jwt-mappings", s.handleAdminListJWTMappings)
		adm.Delete("/jwt-mappings/{id}", s.handleAdminDeleteJWTMapping)
		adm.Post("/access-group-rules", s.handleAdminCreateAccessGroupRule)
		adm.Get("/access-group-rules", s.handleAdminListAccessGroupRules)
		adm.Delete("/access-group-rules/{id}", s.handleAdminDeleteAccessGroupRule)

		// Provider Credentials Vault & Lifecycle (Rotation & Live Validation)
		adm.Post("/credentials", s.handleAdminCreateCredential)
		adm.Get("/credentials", s.handleAdminListCredentials)
		adm.Post("/credentials/validate", s.handleAdminPreflightValidateCredential)
		adm.Post("/credentials/{credID}/rotate", s.handleAdminRotateCredential)
		adm.Post("/credentials/{credID}/validate", s.handleAdminValidateCredential)

		// Model Groups & Deployments
		adm.Post("/model-groups", s.handleAdminCreateModelGroup)
		adm.Get("/model-groups", s.handleAdminListModelGroups)
		adm.Post("/deployments", s.handleAdminCreateDeployment)
		adm.Get("/deployments", s.handleAdminListDeployments)
		adm.Post("/deployments/{depID}/ptu-shares", s.handleAdminUpsertDeploymentPTUShare)
		adm.Get("/deployments/{depID}/ptu-shares", s.handleAdminListDeploymentPTUShares)
		adm.Delete("/deployments/{depID}/ptu-shares/{teamID}", s.handleAdminDeleteDeploymentPTUShare)
		adm.Post("/priority-classes", s.handleAdminUpsertPriorityClass)
		adm.Get("/priority-classes", s.handleAdminListPriorityClasses)

		// Automated Model Discovery, Global Catalogue & Versioned Model Pricing
		adm.Get("/catalogue", s.handleAdminListCatalogue)
		adm.Post("/catalogue/sync", s.handleAdminTriggerDiscoverySync)
		adm.Post("/catalogue/import", s.handleAdminImportCatalogue)
		adm.Post("/catalogue/pricing", s.handleAdminUpdateModelPricing)
		adm.Get("/catalogue/pricing", s.handleAdminListModelPricingHistory)

		// Observability Telemetry, Active Deployment Health Monitoring & Cache Invalidation
		adm.Get("/observability/metrics", s.handleAdminObservabilityMetrics)
		adm.Get("/health/deployments", s.handleAdminListDeploymentHealth)
		adm.Post("/health/probe", s.handleAdminProbeDeployments)
		adm.Post("/cache/invalidate", s.handleAdminInvalidateCache)

		// FinOps Spend, Quotas, Multi-Window Budgets & Governance Audit Logs
		adm.Put("/quotas", s.handleAdminUpsertQuotaPolicy)
		adm.Get("/quotas", s.handleAdminListQuotaPolicies)
		adm.Delete("/quotas/{policyID}", s.handleAdminDeleteQuotaPolicy)
		adm.Put("/budget-windows", s.handleAdminUpsertBudgetWindow)
		adm.Get("/budget-windows", s.handleAdminListBudgetWindows)
		adm.Post("/end-users", s.handleAdminUpsertEndUser)
		adm.Put("/end-users", s.handleAdminUpsertEndUser)
		adm.Get("/end-users", s.handleAdminListEndUsers)
		adm.Get("/end-users/{id}", s.handleAdminGetEndUser)
		adm.Delete("/end-users/{id}", s.handleAdminDeleteEndUser)
		adm.Post("/tags", s.handleAdminUpsertTag)
		adm.Put("/tags", s.handleAdminUpsertTag)
		adm.Get("/tags", s.handleAdminListTags)
		adm.Get("/tags/{id}", s.handleAdminGetTag)
		adm.Delete("/tags/{id}", s.handleAdminDeleteTag)
		adm.Post("/model-access-groups", s.handleAdminUpsertModelAccessGroup)
		adm.Put("/model-access-groups", s.handleAdminUpsertModelAccessGroup)
		adm.Get("/model-access-groups", s.handleAdminListModelAccessGroups)
		adm.Get("/model-access-groups/{id}", s.handleAdminGetModelAccessGroup)
		adm.Delete("/model-access-groups/{id}", s.handleAdminDeleteModelAccessGroup)
		adm.Post("/model-access-groups/{id}/members", s.handleAdminAddModelAccessGroupMember)
		adm.Get("/model-access-groups/{id}/members", s.handleAdminListModelAccessGroupMembers)
		adm.Delete("/model-access-groups/{id}/members/{memberID}", s.handleAdminRemoveModelAccessGroupMember)
		adm.Post("/keys/{keyID}/temp-budget", s.handleAdminSetKeyTempBudget)
		adm.Get("/spend/summary", s.handleAdminSpendSummary)
		adm.Get("/spend/logs", s.handleAdminSpendLogs)
		adm.Get("/audit/logs", s.handleAdminAuditLogs)
		adm.Get("/config", s.handleAdminGetConfig)
		adm.Post("/security/rotate-kek", s.handleAdminRotateKEK)

		// MCP Enterprise Management: Servers, Toolsets, Tools, Tool Sync & BYOK Credentials
		adm.Post("/mcp/servers", s.handleAdminCreateMCPServer)
		adm.Get("/mcp/servers", s.handleAdminListMCPServers)
		adm.Post("/mcp/servers/{serverID}/sync", s.handleAdminSyncMCPServer)
		adm.Post("/mcp/toolsets", s.handleAdminCreateMCPToolset)
		adm.Get("/mcp/toolsets", s.handleAdminListMCPToolsets)
		adm.Get("/mcp/tools", s.handleAdminListMCPTools)
		adm.Post("/mcp/credentials", s.handleAdminSetMCPUserCredential)

		// A2A Enterprise Management: Agents, Kill-Switch, Push Notification Configs
		adm.Post("/a2a/agents", s.handleAdminCreateA2AAgent)
		adm.Get("/a2a/agents", s.handleAdminListA2AAgents)
		adm.Get("/a2a/agents/{id}", s.handleAdminGetA2AAgent)
		adm.Post("/a2a/agents/{id}/kill-switch", s.handleAdminSetA2AKillSwitch)
		adm.Post("/a2a/push-configs", s.handleAdminSetA2APushConfig)
	})

	s.router = r
}

func (s *GatewayServer) metricsAuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := strings.TrimSpace(r.Header.Get("Authorization"))
		var token string
		if len(header) > len("Bearer ") && strings.EqualFold(header[:len("Bearer ")], "Bearer ") {
			token = strings.TrimSpace(header[len("Bearer "):])
		}
		if token == "" {
			token = strings.TrimSpace(r.Header.Get("x-api-key"))
		}
		if !s.authSvc.ValidateAdminKey(token) {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusUnauthorized,
				Type:       domain.ErrorTypeAuthentication,
				Code:       "invalid_admin_key",
				Message:    "Valid Master Admin Key is required to access /metrics",
			})
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *GatewayServer) Handler() http.Handler {
	return s.router
}

func (s *GatewayServer) persistSpendEvent(w http.ResponseWriter, r *http.Request, ev domain.SpendEvent) bool {
	if s.spendWorker == nil {
		return true
	}
	ev = enrichSpendEventFromContext(r.Context(), ev)
	if err := s.spendWorker.Record(r.Context(), ev); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: http.StatusServiceUnavailable, Type: domain.ErrorTypeServer, Code: "spend_persistence_unavailable", Message: "unable to persist request accounting"})
		return false
	}
	return true
}

func (s *GatewayServer) Limiter() *ratelimit.Limiter {
	return s.limiter
}

func (s *GatewayServer) Collector() *observability.Collector {
	return s.collector
}

func (s *GatewayServer) MetricsExporter() *observability.OTLPMetricsExporter {
	return s.metricsExporter
}

func (s *GatewayServer) HealthMonitor() *health.Monitor {
	return s.healthMon
}

// ConfigureGuardrailScanners injects optional scanners before serving traffic.
// Scanners are disabled by default; network-backed implementations must use the
// configured outbound network security policy. Call only during startup, before
// the server begins handling requests.
func (s *GatewayServer) ConfigureGuardrailScanners(timeout time.Duration, failClosed bool, scanners ...guardrails.Scanner) {
	if s != nil && s.guardrails != nil {
		s.guardrails.ConfigureScanners(timeout, failClosed, scanners...)
	}
}

func (s *GatewayServer) Reliability() *router.ReliabilityManager {
	return s.reliability
}

// ReliabilityManager returns the server's ReliabilityManager for SDK integration.
func (s *GatewayServer) ReliabilityManager() *router.ReliabilityManager {
	if s == nil {
		return nil
	}
	return s.reliability
}

// IntelligentRouter returns the server's IntelligentRouter for SDK integration.
func (s *GatewayServer) IntelligentRouter() *router.IntelligentRouter {
	if s == nil {
		return nil
	}
	return s.intelligentRouter
}

// AddRoutingPlugin appends a Stage 2 RoutingPlugin to the server's ReliabilityManager.
func (s *GatewayServer) AddRoutingPlugin(p router.RoutingPlugin) {
	if s != nil && s.reliability != nil {
		s.reliability.AddRoutingPlugin(p)
	}
}

// RegisterPreRouter registers a Stage 1 PreRouter on the server's IntelligentRouter.
func (s *GatewayServer) RegisterPreRouter(pr router.PreRouter) {
	if s != nil && s.intelligentRouter != nil {
		s.intelligentRouter.RegisterPreRouter(pr)
	}
}

func (s *GatewayServer) MCPHub() *mcp.Hub {
	return s.mcpHub
}

func (s *GatewayServer) A2ARouter() *a2a.RouterService {
	return s.a2aRouter
}

func (s *GatewayServer) AuthService() *auth.Service {
	return s.authSvc
}

func (s *GatewayServer) SessionManager() *auth.SessionManager {
	return s.sessionMgr
}

func (s *GatewayServer) LoginThrottle() *auth.LoginThrottle {
	return s.loginThrottle
}

func (s *GatewayServer) SSOProviderManager() *auth.SSOProviderManager {
	if s == nil {
		return nil
	}
	return s.ssoMgr
}

func (s *GatewayServer) SSOStateStore() *auth.SSOStateStore {
	if s == nil {
		return nil
	}
	return s.ssoStateStore
}

func (s *GatewayServer) CLILoginStore() *auth.CLILoginStore {
	if s == nil {
		return nil
	}
	return s.cliLoginStore
}

func (s *GatewayServer) AuthResolver() *auth.AuthResolver {
	return s.authResolver
}

func (s *GatewayServer) KeyRotationManager() *auth.KeyRotationManager {
	if s == nil {
		return nil
	}
	return s.keyRotation
}

// SetKeyRotationSecretSink registers an in-process sink that receives newly minted secrets
// produced by background scheduled virtual key rotations.
func (s *GatewayServer) SetKeyRotationSecretSink(sink auth.KeySecretSink) {
	if s == nil || s.keyRotation == nil {
		return
	}
	s.keyRotation.SetSecretSink(sink)
}

func (s *GatewayServer) RBAC() *auth.RBACEngine {
	return s.rbac
}

// StartWorkers starts background daemons (Async Spend Batch Writer, Key Rotation Manager, Automated Model Discovery, Active Health Monitor, A2A Stream Publisher & Outbox Worker).
func (s *GatewayServer) StartWorkers(ctx context.Context) {
	s.authSvc.StartInvalidationListener(ctx)
	if s.keyRotation != nil {
		s.keyRotation.Start(ctx)
	}
	if s.keyExpiryAlerts != nil {
		s.keyExpiryAlerts.Start(ctx)
	}
	s.spendWorker.Start(ctx)
	s.healthMon.Start(ctx)
	if s.cfg.Discovery.Enabled {
		s.discovery.Start(ctx)
	}
	if s.intelligentRouter != nil {
		if b := s.intelligentRouter.Bandit(); b != nil {
			b.Start(ctx)
		}
	}
	if s.semanticPreRouter != nil {
		go s.warmupSemanticPreRouter(ctx)
	}
	if s.a2aPublisher != nil {
		s.a2aPublisher.Start(ctx)
	}
	if s.a2aOutboxWorker != nil {
		s.a2aOutboxWorker.Start(ctx)
	}
	if s.metricsExporter != nil {
		metricsCtx, metricsCancel := context.WithCancel(ctx)
		s.metricsStop = metricsCancel
		s.metricsExporter.Start(metricsCtx)
	}
}

func (s *GatewayServer) warmupSemanticPreRouter(ctx context.Context) {
	if s == nil || s.semanticPreRouter == nil || s.repo == nil || s.intelligentRouter == nil || s.cfg == nil {
		return
	}
	semCfg := s.cfg.Router.SemanticRouter
	if !semCfg.Enabled || strings.TrimSpace(semCfg.EmbeddingModel) == "" || len(semCfg.Routes) == 0 {
		return
	}
	orgs, err := s.repo.ListOrganizations(ctx)
	if err != nil {
		return
	}
	timeout := semCfg.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	for _, org := range orgs {
		if org == nil || !org.IsActive || org.ID == "" {
			continue
		}
		if _, already := s.semanticWarmed.Load(org.ID); already {
			continue
		}
		mg, err := s.intelligentRouter.ResolveExplicitModel(ctx, org.ID, semCfg.EmbeddingModel)
		if err != nil || mg == nil {
			continue
		}
		deps, err := s.repo.ListDeploymentsByGroup(ctx, mg.ID)
		if err != nil || len(deps) == 0 {
			continue
		}
		warmCtx, cancel := context.WithTimeout(ctx, timeout)
		warmErr := s.semanticPreRouter.Warmup(warmCtx, org.ID)
		cancel()
		if warmErr == nil {
			s.semanticWarmed.Store(org.ID, true)
		} else {
			logger.WarnContext(ctx, "Semantic pre-router warmup failed; failing open to default alias",
				slog.String("component", "router"),
				slog.String("org_id", org.ID),
				slog.String("error", warmErr.Error()),
			)
		}
	}
}

// Shutdown drains background workers cleanly.
func (s *GatewayServer) Shutdown(ctx context.Context) {
	if s.keyRotation != nil {
		s.keyRotation.Stop()
	}
	if s.keyExpiryAlerts != nil {
		s.keyExpiryAlerts.Stop()
	}
	s.authSvc.StopInvalidationListener()
	if s.a2aPublisher != nil {
		s.a2aPublisher.Stop()
	}
	if s.a2aOutboxWorker != nil {
		s.a2aOutboxWorker.Stop()
	}
	if s.intelligentRouter != nil {
		if b := s.intelligentRouter.Bandit(); b != nil {
			b.Stop()
		}
	}
	if s.affinityStore != nil {
		_ = s.affinityStore.Wait(ctx)
	}
	s.healthMon.Stop()
	s.discovery.Stop()
	s.spendWorker.Stop(ctx)
	if s.metricsStop != nil {
		s.metricsStop()
	}
	if s.metricsExporter != nil {
		_ = s.metricsExporter.Shutdown(ctx)
	}
	if s.tracerShutdown != nil {
		_ = s.tracerShutdown(ctx)
	}
}

func parseCIDRList(cidrs []string) []*net.IPNet {
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, raw := range cidrs {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}
		if _, ipNet, err := net.ParseCIDR(trimmed); err == nil {
			nets = append(nets, ipNet)
		}
	}
	return nets
}

func extractRemoteIP(remoteAddr string) net.IP {
	host := strings.TrimSpace(remoteAddr)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return net.ParseIP(host)
}

func ipInNets(ip net.IP, nets []*net.IPNet) bool {
	if ip == nil {
		return false
	}
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

var testNet1CIDR = func() *net.IPNet {
	_, n, _ := net.ParseCIDR("192.0.2.0/24")
	return n
}()

func isNonPublicIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if unmapped := ip.To4(); unmapped != nil {
		ip = unmapped
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || testNet1CIDR.Contains(ip)
}

// trustedRealIPMiddleware restricts chi's RealIP header parsing to requests originating
// from configured trusted proxy CIDRs so untrusted callers cannot spoof X-Forwarded-For.
func trustedRealIPMiddleware(trustedProxyCIDRs []string) func(http.Handler) http.Handler {
	trustedNets := parseCIDRList(trustedProxyCIDRs)
	realIPHandler := middleware.RealIP
	return func(next http.Handler) http.Handler {
		wrappedNext := realIPHandler(next)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if len(trustedNets) > 0 && ipInNets(extractRemoteIP(r.RemoteAddr), trustedNets) {
				wrappedNext.ServeHTTP(w, r)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// inboundCallerMiddleware enforces config.Security.Network.InboundCaller policies.
func inboundCallerMiddleware(cfg config.InboundCallerConfig) func(http.Handler) http.Handler {
	allowedNets := parseCIDRList(cfg.AllowedClientCIDRs)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := extractRemoteIP(r.RemoteAddr)
			if len(allowedNets) > 0 {
				if !ipInNets(ip, allowedNets) {
					domain.WriteHTTPError(w, &domain.GatewayError{
						StatusCode: http.StatusForbidden,
						Type:       domain.ErrorTypePermission,
						Code:       "caller_ip_not_allowed",
						Message:    "Client IP is not in allowed_client_cidrs",
					})
					return
				}
				next.ServeHTTP(w, r)
				return
			}
			if !cfg.ExposeOnPublicInternet && strings.TrimSpace(r.RemoteAddr) != "" && !isNonPublicIP(ip) {
				domain.WriteHTTPError(w, &domain.GatewayError{
					StatusCode: http.StatusForbidden,
					Type:       domain.ErrorTypePermission,
					Code:       "public_internet_disabled",
					Message:    "Gateway is not exposed on the public internet",
				})
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func buildOIDCIssuerConfigs(issuers []config.OIDCIssuerConfig, netPolicy *network.Policy) []auth.OIDCIssuerConfig {
	if len(issuers) == 0 {
		return nil
	}
	out := make([]auth.OIDCIssuerConfig, 0, len(issuers))
	for _, iss := range issuers {
		out = append(out, auth.OIDCIssuerConfig{
			Issuer:              iss.Issuer,
			Audience:            iss.Audience,
			JWKSURL:             iss.JWKSURL,
			DiscoveryURL:        iss.DiscoveryURL,
			Algorithms:          iss.Algorithms,
			AllowedEmailDomains: iss.AllowedEmailDomains,
			ClaimMapping: auth.OIDCClaimMapping{
				UserID:  iss.ClaimMapping.UserID,
				Email:   iss.ClaimMapping.Email,
				OrgID:   iss.ClaimMapping.OrgID,
				TeamIDs: iss.ClaimMapping.TeamIDs,
				Role:    iss.ClaimMapping.Role,
				EndUser: iss.ClaimMapping.EndUser,
			},
			AutoRegister:  iss.AutoRegister,
			DefaultOrgID:  iss.DefaultOrgID,
			DefaultTeamID: iss.DefaultTeamID,
			DefaultRole:   iss.DefaultRole,
			NetworkPolicy: netPolicy,
		})
	}
	return out
}

func buildSSOProviderConfigs(providers []config.SSOProviderConfig) []auth.SSOProviderConfig {
	if len(providers) == 0 {
		return nil
	}
	out := make([]auth.SSOProviderConfig, 0, len(providers))
	for _, p := range providers {
		out = append(out, auth.SSOProviderConfig{
			ID:                    p.ID,
			Name:                  p.Name,
			Type:                  p.Type,
			DisplayName:           p.DisplayName,
			ClientID:              config.ResolveEnvValue(p.ClientID),
			ClientSecret:          config.ResolveEnvValue(p.ClientSecret),
			Issuer:                p.Issuer,
			AuthorizationEndpoint: p.AuthorizationEndpoint,
			TokenEndpoint:         p.TokenEndpoint,
			JWKSURL:               p.JWKSURL,
			DiscoveryURL:          p.DiscoveryURL,
			Scopes:                append([]string(nil), p.Scopes...),
			RedirectURL:           p.RedirectURL,
			AllowedEmailDomains:   append([]string(nil), p.AllowedEmailDomains...),
			AutoRegister:          p.AutoRegister,
			DefaultOrgID:          p.DefaultOrgID,
			DefaultTeamID:         p.DefaultTeamID,
			DefaultRole:           p.DefaultRole,
			TenantID:              p.TenantID,
			Algorithms:            append([]string(nil), p.Algorithms...),
			ClaimMapping: auth.OIDCClaimMapping{
				UserID:  p.ClaimMapping.UserID,
				Email:   p.ClaimMapping.Email,
				OrgID:   p.ClaimMapping.OrgID,
				TeamIDs: p.ClaimMapping.TeamIDs,
				Role:    p.ClaimMapping.Role,
				EndUser: p.ClaimMapping.EndUser,
			},
		})
	}
	return out
}
