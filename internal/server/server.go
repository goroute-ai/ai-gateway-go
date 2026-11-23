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
	"github.com/goroute-ai/ai-gateway-go/internal/adapter/groq"
	"github.com/goroute-ai/ai-gateway-go/internal/adapter/openai"
	"github.com/goroute-ai/ai-gateway-go/internal/adapter/openrouter"
	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/auth/upstream"
	"github.com/goroute-ai/ai-gateway-go/internal/cache"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/finops"
	"github.com/goroute-ai/ai-gateway-go/internal/guardrails"
	"github.com/goroute-ai/ai-gateway-go/internal/health"
	"github.com/goroute-ai/ai-gateway-go/internal/logger"
	"github.com/goroute-ai/ai-gateway-go/internal/mcp"
	"github.com/goroute-ai/ai-gateway-go/internal/mcp/spec"
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
	ssoMgr             *auth.SSOProviderManager
	ssoStateStore      *auth.SSOStateStore
	cliLoginStore      *auth.CLILoginStore
	authStartLimiter   *authStartRateLimiter
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
	externalAuthorizer auth.Authorizer
	customAuthorizer   auth.Authorizer
	auditSIEMSink      *AuditSIEMSink
	router             chi.Router
	uploadSem          chan struct{}
	uploadInFlightMu   sync.Mutex
	uploadInFlight     map[string]int64
	routeAuditMu       sync.Mutex
	routeAuditWindows  map[string]*routeAuditWindow
	nowMu              sync.RWMutex
	nowFunc            func() time.Time
}

func (s *GatewayServer) nowUTC() time.Time {
	if s == nil {
		return time.Now().UTC()
	}
	s.nowMu.RLock()
	fn := s.nowFunc
	s.nowMu.RUnlock()
	if fn != nil {
		return fn().UTC()
	}
	return time.Now().UTC()
}

func (s *GatewayServer) invalidateLocalRoutingCaches(ev storage.InvalidationEvent) {
	if s == nil {
		return
	}
	if s.intelligentRouter != nil {
		s.intelligentRouter.InvalidateCache(ev)
	}
	if s.priorityLimiter != nil {
		s.priorityLimiter.InvalidateCache(ev)
	}
	if ev.EntityType == "mcp_spec" && s.mcpHub != nil {
		if settingsRepo, ok := s.repo.(storage.MCPRuntimeSettingsRepository); ok && settingsRepo != nil {
			if stored, err := settingsRepo.GetMCPRuntimeSettings(context.Background()); err == nil && stored != nil && stored.ActiveProtocolVersion != "" {
				s.mcpHub.SetRuntimeSettings(*stored)
				return
			}
		}
		if spec.IsSupported(ev.EntityID) {
			cur := s.mcpHub.RuntimeSettings()
			cur.ActiveProtocolVersion = ev.EntityID
			s.mcpHub.SetRuntimeSettings(cur)
		}
	}
}

func (s *GatewayServer) invalidateRoutingCaches(ctx context.Context, ev storage.InvalidationEvent) {
	s.invalidateLocalRoutingCaches(ev)
	if s != nil && s.redisFabric != nil {
		if ctx == nil {
			ctx = context.Background()
		}
		s.redisFabric.PublishInvalidation(ctx, ev)
	}
}

// SetNowFunc overrides the wall-clock source used for quota admission and rolling windows.
func (s *GatewayServer) SetNowFunc(fn func() time.Time) {
	if s == nil {
		return
	}
	s.nowMu.Lock()
	s.nowFunc = fn
	s.nowMu.Unlock()
	if s.limiter != nil {
		s.limiter.SetNowFunc(fn)
	}
}

// New constructs and initializes a GatewayServer with all storage, security, routing, auth,
// observability, MCP, and A2A subsystems wired according to cfg.
func New(cfg *config.Config, repo storage.Repository, redisFabric *storage.RedisFabric, httpClient *http.Client) (*GatewayServer, error) {
	if cfg == nil {
		cfg = config.Default()
	}
	if repo == nil {
		repo = storage.NewMemoryRepository()
	}

	netPolicy, err := network.NewPolicy(cfg.Security.Network.OutboundSSRF)
	if err != nil {
		return nil, fmt.Errorf("invalid outbound ssrf security policy: %w", err)
	}
	tracer, tracerShutdown, err := observability.NewOTLPTracer(context.Background(), cfg.Tracing, netPolicy)
	if err != nil {
		return nil, err
	}
	cleanupOnErr := func(cause error) (*GatewayServer, error) {
		if tracerShutdown != nil {
			_ = tracerShutdown(context.Background())
		}
		return nil, cause
	}

	adapterClient, mediaClient, mediaPolicy, outboundMetrics, err := buildOutboundClients(cfg, netPolicy, httpClient)
	if err != nil {
		return cleanupOnErr(err)
	}
	reg, err := buildAdapterRegistry(cfg, netPolicy, adapterClient, mediaClient, mediaPolicy)
	if err != nil {
		return cleanupOnErr(err)
	}
	authDeps, err := buildAuthSubsystem(cfg, repo, redisFabric, netPolicy)
	if err != nil {
		return cleanupOnErr(err)
	}

	limiter := buildRateLimiter(cfg, repo, redisFabric)
	respCache := cache.NewResponseCacheWithL1Capacity(cfg.Cache.Enabled, cfg.Cache.DefaultTTL, cfg.Cache.MaxL1Entries, redisFabric)
	modelMgmtSvc := modelmgmt.NewServiceWithRBAC(repo, authDeps.rbac)
	discWorker := modelmgmt.NewDiscoveryWorker(repo, reg, authDeps.vault, redisFabric, cfg.Discovery.SyncInterval, cfg.Discovery.AutoApprove)

	collector := observability.NewCollector()
	budgetStats := &budgetLookupStats{}
	registerCollectorMetricsProvider(collector, repo, respCache, outboundMetrics, budgetStats, authDeps.keyRotation)

	var metricsExporter *observability.OTLPMetricsExporter
	if cfg.Tracing.Enabled && strings.TrimSpace(cfg.Tracing.OTLPEndpoint) != "" {
		metricsExporter, err = observability.NewOTLPMetricsExporterFromTracingConfig(collector, cfg.Tracing, 0, netPolicy)
		if err != nil {
			return cleanupOnErr(err)
		}
	}

	healthMon := health.NewMonitor(repo, reg, authDeps.vault, 60*time.Second, 5*time.Second)
	validator := validation.NewValidator(repo)
	validator.SetAllowDefaultFallbacks(len(cfg.Router.DefaultFallbacks) > 0)
	validator.SetDropUnsupportedParams(cfg.Router.DropUnsupportedParams)
	validator.SetFallbackOnUnsupportedParams(cfg.Router.FallbackOnUnsupportedParams)
	guardrailsEng := guardrails.NewEngine(repo)

	routingDeps := buildRoutingSubsystem(cfg, repo, redisFabric, reg, authDeps.vault, authDeps.rbac, limiter, collector, healthMon, respCache)

	spendWorker := finops.NewSpendWorker(repo, limiter, cfg.FinOps)
	spendWorker.SetCollector(collector)
	spendWorker.SetDeploymentSpendRecorder(routingDeps.depBudgets)
	softBudgetNotifier := finops.NewSoftBudgetNotifier(repo, redisFabric, netPolicy, cfg.FinOps.SoftBudgetWebhookURL, cfg.FinOps.SoftBudgetCooldownSec)
	spendWorker.SetSoftBudgetNotifier(softBudgetNotifier)

	protoDeps := buildMCPAndA2ASubsystem(cfg, repo, redisFabric, netPolicy, authDeps.vault, authDeps.rbac, limiter, guardrailsEng, spendWorker, routingDeps.relMgr)

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
		vault:              authDeps.vault,
		authSvc:            authDeps.authSvc,
		sessionMgr:         authDeps.sessionMgr,
		ssoMgr:             authDeps.ssoMgr,
		ssoStateStore:      authDeps.ssoStateStore,
		cliLoginStore:      authDeps.cliLoginStore,
		authStartLimiter:   newAuthStartRateLimiter(redisFabric, cfg.Auth.AuthStartRateLimitPerMin),
		authResolver:       authDeps.authResolver,
		keyRotation:        authDeps.keyRotation,
		keyExpiryAlerts:    authDeps.keyExpiryAlerts,
		rbac:               authDeps.rbac,
		limiter:            limiter,
		respCache:          respCache,
		modelMgmt:          modelMgmtSvc,
		discovery:          discWorker,
		intelligentRouter:  routingDeps.ir,
		reliability:        routingDeps.relMgr,
		affinityStore:      routingDeps.affinityStore,
		depBudgets:         routingDeps.depBudgets,
		priorityLimiter:    routingDeps.priorityLimiter,
		semanticPreRouter:  routingDeps.semanticPreRouter,
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
		mcpHub:             protoDeps.mcpHub,
		a2aRouter:          protoDeps.a2aRouter,
		a2aSigner:          protoDeps.a2aSigner,
		a2aStreamSub:       protoDeps.a2aStreamSub,
		a2aPublisher:       protoDeps.a2aPublisher,
		a2aOutboxWorker:    protoDeps.a2aOutboxWorker,
		a2aBridge:          protoDeps.a2aBridge,
		orchestrator:       protoDeps.toolOrchestrator,
		uploadSem:          uploadSem,
		uploadInFlight:     make(map[string]int64),
	}
	s.ConfigureGuardrailScannersFromConfig(cfg.Guardrails, netPolicy)
	routingDeps.relMgr.SetDeploymentSlotTTL(cfg.RateLimit.ConcurrencyTTLSec)
	routingDeps.relMgr.SetFallbackQuotaChecker(s.checkFallbackModelQuota)
	authDeps.authSvc.AddInvalidationHandler(func(ev storage.InvalidationEvent) {
		s.invalidateLocalRoutingCaches(ev)
	})
	s.setupRoutes()
	if err := s.bootstrap(context.Background()); err != nil {
		return cleanupOnErr(err)
	}
	s.warmupSemanticPreRouter(context.Background())
	if err := s.seedGuardrailsFromConfig(context.Background()); err != nil {
		return cleanupOnErr(err)
	}
	pipeline := s.GuardrailPipeline()
	protoDeps.mcpHub.SetGuardrailPipeline(pipeline)
	protoDeps.a2aRouter.SetGuardrailPipeline(pipeline)
	if tpRepo, ok := repo.(storage.ToolPolicyRepository); ok && tpRepo != nil {
		protoDeps.toolOrchestrator.SetToolPolicyRepository(tpRepo)
	}
	protoDeps.toolOrchestrator.SetToolGuardrails(s.newOrchestratorToolGuardrailDriver())
	if cfg.Auth.ExternalAuthorizer.Enabled {
		extAuthz, extErr := auth.NewExternalAuthorizer(auth.ExternalAuthorizerConfig{
			Mode:       cfg.Auth.ExternalAuthorizer.Mode,
			URL:        cfg.Auth.ExternalAuthorizer.URL,
			Timeout:    cfg.Auth.ExternalAuthorizer.Timeout,
			FailMode:   cfg.Auth.ExternalAuthorizer.FailMode,
			CacheTTL:   cfg.Auth.ExternalAuthorizer.CacheTTL,
			AuthHeader: config.ResolveEnvValue(cfg.Auth.ExternalAuthorizer.AuthHeader),
			HMACSecret: config.ResolveEnvValue(cfg.Auth.ExternalAuthorizer.HMACSecret),
		}, netPolicy)
		if extErr != nil {
			return cleanupOnErr(fmt.Errorf("initialize external authorizer: %w", extErr))
		}
		s.externalAuthorizer = extAuthz
		s.SetCustomAuthorizer(nil)
	}
	if cfg.Audit.SIEMWebhook.Enabled && strings.TrimSpace(cfg.Audit.SIEMWebhook.URL) != "" {
		s.auditSIEMSink = NewAuditSIEMSink(AuditSIEMSinkConfig{
			URL:           cfg.Audit.SIEMWebhook.URL,
			Secret:        config.ResolveEnvValue(cfg.Audit.SIEMWebhook.Secret),
			AuthHeader:    config.ResolveEnvValue(cfg.Audit.SIEMWebhook.AuthHeader),
			BatchSize:     cfg.Audit.SIEMWebhook.BatchSize,
			FlushInterval: cfg.Audit.SIEMWebhook.FlushInterval,
			Timeout:       cfg.Audit.SIEMWebhook.Timeout,
			MaxQueueSize:  cfg.Audit.SIEMWebhook.MaxQueueSize,
		}, netPolicy)
		if obsRepo, ok := repo.(storage.AuditLogObserverRepository); ok && obsRepo != nil {
			obsRepo.SetAuditLogObserver(s.auditSIEMSink.Enqueue)
		}
	}
	return s, nil
}

type serverAuthDeps struct {
	vault           *auth.Vault
	authSvc         *auth.Service
	sessionMgr      *auth.SessionManager
	ssoMgr          *auth.SSOProviderManager
	ssoStateStore   *auth.SSOStateStore
	cliLoginStore   *auth.CLILoginStore
	authResolver    *auth.AuthResolver
	rbac            *auth.RBACEngine
	keyRotation     *auth.KeyRotationManager
	keyExpiryAlerts *auth.KeyExpiryAlertManager
}

type serverRoutingDeps struct {
	ir                *router.IntelligentRouter
	relMgr            *router.ReliabilityManager
	affinityStore     *router.AffinityStore
	depBudgets        *router.DeploymentBudgetTracker
	priorityLimiter   *router.DynamicPriorityLimiter
	semanticPreRouter *router.SemanticPreRouter
}

type serverProtocolDeps struct {
	mcpHub           *mcp.Hub
	a2aRouter        *a2a.RouterService
	a2aSigner        *a2a.GatewayCardSigner
	a2aStreamSub     *a2a.StreamSubscriber
	a2aPublisher     *a2a.StreamPublisher
	a2aOutboxWorker  *a2a.OutboxWorker
	a2aBridge        *a2a.OpenAIBridge
	toolOrchestrator *orchestrator.ToolLoopOrchestrator
}

func buildOutboundClients(cfg *config.Config, netPolicy *network.Policy, httpClient *http.Client) (*http.Client, *http.Client, *network.Policy, *network.HTTPClientMetrics, error) {
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
		return nil, nil, nil, nil, fmt.Errorf("invalid outbound media security policy: %w", err)
	}
	return adapterClient, network.NewHTTPClient(mediaPolicy), mediaPolicy, outboundMetrics, nil
}

func buildAdapterRegistry(_ *config.Config, netPolicy *network.Policy, adapterClient, _ *http.Client, _ *network.Policy) (*adapter.Registry, error) {
	openaiAdp := openai.NewAdapter(adapterClient)
	openaiAdp.SetSSRFPolicy(netPolicy)
	anthropicAdp := anthropic.NewAdapter(adapterClient)
	anthropicAdp.SetSSRFPolicy(netPolicy)
	groqAdp := groq.NewAdapter(adapterClient)
	groqAdp.SetSSRFPolicy(netPolicy)
	openrouterAdp := openrouter.NewAdapter(adapterClient)
	openrouterAdp.SetSSRFPolicy(netPolicy)

	reg := adapter.NewRegistry()
	reg.Register(openaiAdp)
	reg.Register(anthropicAdp)
	reg.Register(groqAdp)
	reg.Register(openrouterAdp)
	return reg, nil
}

func buildAuthSubsystem(cfg *config.Config, repo storage.Repository, redisFabric *storage.RedisFabric, netPolicy *network.Policy) (*serverAuthDeps, error) {
	prevKEKs := make([]string, 0, len(cfg.Auth.PreviousMasterEncryptionKeys))
	for _, pk := range cfg.Auth.PreviousMasterEncryptionKeys {
		if resolved := strings.TrimSpace(config.ResolveEnvValue(pk)); resolved != "" {
			prevKEKs = append(prevKEKs, resolved)
		}
	}
	vault, err := auth.NewVaultWithPreviousKeys(config.ResolveEnvValue(cfg.Auth.MasterEncryptionKey), prevKEKs)
	if err != nil {
		return nil, err
	}

	authSvc := auth.NewService(repo, redisFabric, cfg.Auth.MasterAdminKey, cfg.Auth.L1CacheTTL, cfg.Auth.L2CacheTTL)
	authSvc.SetMasterEncryptionKey(cfg.Auth.MasterEncryptionKey)
	authSvc.SetVault(vault)
	authSvc.SetAllowMasterKeyDataPlane(cfg.Auth.AllowMasterKeyDataPlane)
	authSvc.SetCustomAPIKeyHeader(cfg.Auth.CustomAPIKeyHeader)
	jwtVerifier := auth.NewJWTVerifier(auth.JWTConfig{
		Issuer:        cfg.Auth.JWTIssuer,
		Audience:      cfg.Auth.JWTAudience,
		OIDCJWKSURL:   cfg.Auth.OIDCJWKSURL,
		DefaultOrgID:  cfg.Auth.DefaultOrgID,
		Issuers:       buildOIDCIssuerConfigs(cfg.Auth.OIDCIssuers, netPolicy),
		NetworkPolicy: netPolicy,
	})
	authSvc.SetJWTVerifier(jwtVerifier)
	sessionSecret := auth.DeriveSessionSecret(
		config.ResolveEnvValue(cfg.Auth.SessionSecret),
		config.ResolveEnvValue(cfg.Auth.MasterEncryptionKey),
		config.ResolveEnvValue(cfg.Auth.MasterAdminKey),
	)
	sessionMgr := auth.NewSessionManager(repo, redisFabric, sessionSecret, cfg.Auth.SessionTTL)
	sessionMgr.SetVault(vault)
	authSvc.SetSessionManager(sessionMgr)
	authSvc.AddInvalidationHandler(sessionMgr.HandleInvalidation)

	ssoMgr, err := auth.NewSSOProviderManager(buildSSOProviderConfigs(cfg.Auth.SSOProviders), netPolicy)
	if err != nil {
		return nil, fmt.Errorf("invalid sso_providers config: %w", err)
	}
	ssoStateStore := auth.NewSSOStateStore(redisFabric)
	cliLoginStore := auth.NewCLILoginStore(redisFabric, vault)

	var introspector *auth.OAuthIntrospector
	if strings.TrimSpace(cfg.Auth.Introspection.TokenInfoEndpoint) != "" ||
		strings.TrimSpace(cfg.Auth.Introspection.DiscoveryURL) != "" ||
		strings.TrimSpace(cfg.Auth.Introspection.Issuer) != "" {
		introspector = auth.NewOAuthIntrospector(auth.IntrospectionConfig{
			TokenInfoEndpoint: cfg.Auth.Introspection.TokenInfoEndpoint,
			Issuer:            cfg.Auth.Introspection.Issuer,
			Audience:          cfg.Auth.Introspection.Audience,
			DiscoveryURL:      cfg.Auth.Introspection.DiscoveryURL,
			ClientID:          config.ResolveEnvValue(cfg.Auth.Introspection.ClientID),
			ClientSecret:      config.ResolveEnvValue(cfg.Auth.Introspection.ClientSecret),
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

	rbac := auth.NewRBACEngine(repo)
	rbac.SetRedis(redisFabric)
	authSvc.AddInvalidationHandler(rbac.HandleInvalidation)

	authResolver := auth.NewAuthResolver(auth.ResolverConfig{
		Service:                                authSvc,
		Repo:                                   repo,
		RBAC:                                   rbac,
		JWTVerifier:                            jwtVerifier,
		Introspector:                           introspector,
		EnableDataPlaneJWT:                     cfg.Auth.EnableDataPlaneJWT,
		DefaultOrgID:                           cfg.Auth.DefaultOrgID,
		IntrospectionAutoRegister:              cfg.Auth.Introspection.AutoRegister,
		IntrospectionAllowUnverifiedEmail:      cfg.Auth.Introspection.AllowUnverifiedEmail,
		IntrospectionAllowPrivilegedRoleClaims: cfg.Auth.Introspection.AllowPrivilegedRoleClaims,
		IntrospectionDefaultTeamID:             cfg.Auth.Introspection.DefaultTeamID,
		IntrospectionDefaultRole:               cfg.Auth.Introspection.DefaultRole,
	})
	authSvc.SetDataPlaneResolver(authResolver)

	delivery, err := newKeyRotationDelivery(cfg.Auth, netPolicy)
	if err != nil {
		return nil, err
	}
	secretSink, err := newKeyRotationSecretSink(cfg.Auth, netPolicy)
	if err != nil {
		return nil, err
	}
	keyRotation := auth.NewKeyRotationManager(authSvc, repo, redisFabric, auth.KeyRotationConfig{
		Deliver:       delivery,
		SecretSink:    secretSink,
		PollInterval:  cfg.Auth.KeyRotationPollInterval,
		GracePeriod:   cfg.Auth.KeyRotationGracePeriod,
		NetworkPolicy: netPolicy,
	})
	keyExpiryAlerts := auth.NewKeyExpiryAlertManager(repo, redisFabric, auth.KeyExpiryAlertConfig{
		PollInterval:  cfg.Auth.KeyExpiryAlertPollInterval,
		NetworkPolicy: netPolicy,
	})

	return &serverAuthDeps{
		vault:           vault,
		authSvc:         authSvc,
		sessionMgr:      sessionMgr,
		ssoMgr:          ssoMgr,
		ssoStateStore:   ssoStateStore,
		cliLoginStore:   cliLoginStore,
		authResolver:    authResolver,
		rbac:            rbac,
		keyRotation:     keyRotation,
		keyExpiryAlerts: keyExpiryAlerts,
	}, nil
}

func buildRateLimiter(cfg *config.Config, repo storage.Repository, redisFabric *storage.RedisFabric) *ratelimit.Limiter {
	limiter := ratelimit.NewLimiter(redisFabric, cfg.RateLimit.WindowSeconds, cfg.RateLimit.ConcurrencyTTLSec)
	limiter.SetEnabled(cfg.RateLimit.Enabled)
	limiter.SetFallbackToLocalOnOutage(cfg.RateLimit.FallbackToLocalOnOutage)
	limiter.SetDefaultEstimatedTPM(cfg.RateLimit.DefaultEstimatedTPM)
	limiter.SetRedisTimeout(cfg.RateLimit.RedisTimeout)
	limiter.SetGlobalLimits(cfg.RateLimit.GlobalRPMLimit, cfg.RateLimit.GlobalTPMLimit, cfg.RateLimit.GlobalMaxConcurrent)
	if rHistRepo, ok := repo.(storage.RollingSpendHistoryRepository); ok && rHistRepo != nil {
		limiter.SetRollingWindowLoader(func(ctx context.Context, orgID string, d domain.RateLimitDescriptor, now time.Time) ([]domain.RollingSpendEntry, error) {
			return rHistRepo.ListRollingWindowHistory(ctx, orgID, d.ScopeType, d.ScopeID, now)
		})
	}
	return limiter
}

func registerCollectorMetricsProvider(
	collector *observability.Collector,
	repo storage.Repository,
	respCache *cache.ResponseCache,
	outboundMetrics *network.HTTPClientMetrics,
	budgetStats *budgetLookupStats,
	keyRotation *auth.KeyRotationManager,
) {
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
		rotDeliveries, rotFailures := keyRotation.DeliveryStats()
		metrics["gateway_key_rotation_deliveries_total"] = float64(rotDeliveries)
		metrics["gateway_key_rotation_delivery_failures_total"] = float64(rotFailures)
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
}

func buildRoutingSubsystem(
	cfg *config.Config,
	repo storage.Repository,
	redisFabric *storage.RedisFabric,
	reg *adapter.Registry,
	vault *auth.Vault,
	rbac *auth.RBACEngine,
	limiter *ratelimit.Limiter,
	collector *observability.Collector,
	healthMon *health.Monitor,
	respCache *cache.ResponseCache,
) *serverRoutingDeps {
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
				if groups, err := ir.ListActiveModelGroupsCached(ctx, orgID); err == nil {
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

	return &serverRoutingDeps{
		ir:                ir,
		relMgr:            relMgr,
		affinityStore:     affinityStore,
		depBudgets:        depBudgets,
		priorityLimiter:   priorityLimiter,
		semanticPreRouter: semanticPreRouter,
	}
}

func buildMCPAndA2ASubsystem(
	cfg *config.Config,
	repo storage.Repository,
	redisFabric *storage.RedisFabric,
	netPolicy *network.Policy,
	vault *auth.Vault,
	rbac *auth.RBACEngine,
	limiter *ratelimit.Limiter,
	guardrailsEng *guardrails.Engine,
	spendWorker *finops.SpendWorker,
	relMgr *router.ReliabilityManager,
) *serverProtocolDeps {
	mcpDispatcher := mcp.NewTransportDispatcher(netPolicy, redisFabric, cfg.MCP.AllowStdioServers)
	mcpAuthResolver := mcp.NewAuthResolver(vault, netPolicy)
	mcpAuthResolver.SetTokenCache(upstream.NewDistributedTokenCache(redisFabric, upstream.DistributedTokenCacheConfig{
		EncryptionKey: cfg.Auth.MasterEncryptionKey,
	}))
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

	initialMCPSpec := cfg.MCP.DefaultProtocolVersion
	if !spec.IsSupported(initialMCPSpec) {
		initialMCPSpec = spec.DefaultVersion
	}
	initialSettings := domain.MCPRuntimeSettings{
		ActiveProtocolVersion:  initialMCPSpec,
		StrictSchemaValidation: cfg.MCP.StrictSchemaValidation,
		UpdatedBy:              "config",
	}
	if settingsRepo, ok := repo.(storage.MCPRuntimeSettingsRepository); ok && settingsRepo != nil {
		if stored, err := settingsRepo.GetMCPRuntimeSettings(context.Background()); err == nil && stored != nil && !stored.UpdatedAt.IsZero() {
			initialSettings = *stored
		}
	}
	mcpHub.SetRuntimeSettings(initialSettings)

	a2aSigner := a2a.NewGatewayCardSigner(cfg.A2A.SigningKeyID, "ES256", nil, vault)
	a2aVerifier := a2a.NewUpstreamCardVerifier(nil)
	a2aRouter := a2a.NewRouterService(repo, vault, rbac, netPolicy, redisFabric, a2aSigner, a2aVerifier)
	a2aRouter.SetGuardrails(guardrailsEng)
	a2aStreamSub := a2a.NewStreamSubscriber(repo, redisFabric)
	a2aPublisher := a2a.NewStreamPublisher(repo, redisFabric, cfg.A2A.StreamPublishInterval)
	a2aOutboxWorker := a2a.NewOutboxWorker(repo, netPolicy, cfg.A2A.MaxPushRetries, 200*time.Millisecond)
	a2aBridge := a2a.NewOpenAIBridge(a2aRouter, a2aStreamSub, repo, rbac)
	toolOrchestrator := orchestrator.NewToolLoopOrchestrator(relMgr, mcpHub, orchestrator.DefaultBudgetPolicy())

	return &serverProtocolDeps{
		mcpHub:           mcpHub,
		a2aRouter:        a2aRouter,
		a2aSigner:        a2aSigner,
		a2aStreamSub:     a2aStreamSub,
		a2aPublisher:     a2aPublisher,
		a2aOutboxWorker:  a2aOutboxWorker,
		a2aBridge:        a2aBridge,
		toolOrchestrator: toolOrchestrator,
	}
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

	s.registerHealthAndMetricsRoutes(r)

	// Embedded Operator Web UI & Streaming Chat Playground (/ui/*)
	ui.RegisterRoutes(r)

	s.registerAuthRoutes(r)
	s.registerDataPlaneRoutes(r)
	s.registerMCPRoutes(r)
	s.registerA2AAndSCIMRoutes(r)
	s.registerAdminRoutes(r)

	s.router = r
}

func (s *GatewayServer) registerHealthAndMetricsRoutes(r chi.Router) {
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
}

func (s *GatewayServer) registerAuthRoutes(r chi.Router) {
	r.Route("/auth", func(authRouter chi.Router) {
		authRouter.Get("/sso/providers", s.handleAuthSSOProviders)
		authRouter.Get("/sso/{provider}/login", s.authStartLimiter.wrap(s.handleAuthSSOLogin))
		authRouter.Get("/sso/{provider}/callback", s.handleAuthSSOCallback)
		authRouter.Post("/cli/start", s.authStartLimiter.wrap(s.handleAuthCLIStart))
		authRouter.Get("/cli/poll/{login_id}", s.handleAuthCLIPoll)
		authRouter.Group(func(protected chi.Router) {
			protected.Use(auth.AdminControlPlaneMiddleware(s.authSvc))
			protected.Post("/logout", s.handleAuthLogout)
			protected.Get("/me", s.handleAuthMe)
			protected.Post("/cli/complete/{login_id}", s.handleAuthCLIComplete)
		})
	})
}

func (s *GatewayServer) registerDataPlaneRoutes(r chi.Router) {
	// Versioned OpenAI-compatible Data Plane (/v1/*).
	// Keep direct v1.<Method>(...) calls inside this r.Route("/v1", ...) block so
	// cmd/specgen AST parity checks can inspect every /v1 route directly.
	r.Route("/v1", func(v1 chi.Router) {
		v1.Use(auth.DataPlaneMiddleware(s.authSvc, s.rbac))
		v1.Post("/chat/completions", s.handleChatCompletions)
		v1.Post("/completions", s.handleLegacyCompletions)
		v1.Post("/embeddings", s.handleEmbeddings)
		v1.Get("/models", s.handleListModels)
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
		s.registerCoreInferenceRoutes(unv)
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
}

func (s *GatewayServer) registerCoreInferenceRoutes(grp chi.Router) {
	grp.Post("/chat/completions", s.handleChatCompletions)
	grp.Post("/completions", s.handleLegacyCompletions)
	grp.Post("/embeddings", s.handleEmbeddings)
	grp.Get("/models", s.handleListModels)
	grp.Post("/moderations", s.handleModerations)
	grp.Post("/messages", s.handleAnthropicMessages)
	grp.Post("/tokenize", s.handleTokenize)
	grp.Post("/audio/transcriptions", s.handleAudioTranscriptions)
	grp.Post("/audio/translations", s.handleAudioTranslations)
	grp.Post("/audio/speech", s.handleAudioSpeech)
	grp.Post("/images/generations", s.handleImageGenerations)
	grp.Post("/images/edits", s.handleImageEdits)
	grp.Post("/images/variations", s.handleImageVariations)

	// Files
	grp.Post("/files", s.handleUploadFile)
	grp.Get("/files", s.handleListFiles)
	grp.Get("/files/{file_id}", s.handleGetFile)
	grp.Get("/files/{file_id}/content", s.handleGetFileContent)
	grp.Delete("/files/{file_id}", s.handleDeleteFile)

	// Batches
	grp.Post("/batches", s.handleCreateBatch)
	grp.Get("/batches", s.handleListBatches)
	grp.Get("/batches/{batch_id}", s.handleGetBatch)
	grp.Post("/batches/{batch_id}/cancel", s.handleCancelBatch)

	// Responses API & Realtime WebSocket
	grp.Post("/responses", s.handleResponses)
	grp.Get("/realtime", s.handleRealtimeWebSocket)
}

func (s *GatewayServer) registerMCPRoutes(r chi.Router) {
	if !s.cfg.MCP.Enabled {
		return
	}
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

	restBridge := mcp.NewRESTBridge(s.mcpHub)
	r.Route("/mcp-rest", func(restRouter chi.Router) {
		restRouter.Use(auth.DataPlaneMiddleware(s.authSvc, s.rbac))
		restRouter.Get("/tools/list", restBridge.HandleListTools)
		restRouter.Post("/tools/call", restBridge.HandleCallTool)
	})

	r.Route("/v1/goroute/mcp", func(regRouter chi.Router) {
		regRouter.Use(auth.DataPlaneMiddleware(s.authSvc, s.rbac))
		regRouter.Get("/registry", s.handleMCPRegistryFeed)
	})
}

func (s *GatewayServer) registerA2AAndSCIMRoutes(r chi.Router) {
	// Well-known Agent Card discovery
	r.Get("/.well-known/agent-card.json", s.handleA2AWellKnownCard)

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
}

func (s *GatewayServer) registerAdminRoutes(r chi.Router) {
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
		adm.Get("/model-groups/{groupID}", s.handleAdminGetModelGroup)
		adm.Put("/model-groups/{groupID}", s.handleAdminUpdateModelGroup)
		adm.Delete("/model-groups/{groupID}", s.handleAdminDeleteModelGroup)
		adm.Post("/deployments", s.handleAdminCreateDeployment)
		adm.Get("/deployments", s.handleAdminListDeployments)
		adm.Get("/deployments/{depID}", s.handleAdminGetDeployment)
		adm.Patch("/deployments/{depID}", s.handleAdminPatchDeployment)
		adm.Delete("/deployments/{depID}", s.handleAdminDeleteDeployment)
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
		// Unified Access Groups alias (Models + MCP Servers + MCP Tools + A2A Agents)
		adm.Post("/access-groups", s.handleAdminUpsertModelAccessGroup)
		adm.Put("/access-groups", s.handleAdminUpsertModelAccessGroup)
		adm.Get("/access-groups", s.handleAdminListModelAccessGroups)
		adm.Get("/access-groups/{id}", s.handleAdminGetModelAccessGroup)
		adm.Delete("/access-groups/{id}", s.handleAdminDeleteModelAccessGroup)
		adm.Post("/access-groups/{id}/members", s.handleAdminAddModelAccessGroupMember)
		adm.Get("/access-groups/{id}/members", s.handleAdminListModelAccessGroupMembers)
		adm.Delete("/access-groups/{id}/members/{memberID}", s.handleAdminRemoveModelAccessGroupMember)
		adm.Post("/keys/{keyID}/temp-budget", s.handleAdminSetKeyTempBudget)
		adm.Get("/spend/summary", s.handleAdminSpendSummary)
		adm.Get("/spend/logs", s.handleAdminSpendLogs)
		adm.Get("/audit/logs", s.handleAdminAuditLogs)
		adm.Get("/config", s.handleAdminGetConfig)
		adm.Post("/security/rotate-kek", s.handleAdminRotateKEK)

		// MCP Enterprise Management: Spec Switching, Servers, Toolsets, Tools, Tool Sync & BYOK Credentials
		adm.Get("/mcp/spec", s.handleAdminGetMCPSpec)
		adm.Put("/mcp/spec", s.handleAdminUpdateMCPSpec)
		adm.Post("/mcp/servers", s.handleAdminCreateMCPServer)
		adm.Put("/mcp/servers/{serverID}", s.handleAdminUpdateMCPServer)
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

// Handler returns the root HTTP router configured with security, auth, and API middleware.
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

// Limiter returns the server's rate and budget Limiter.
func (s *GatewayServer) Limiter() *ratelimit.Limiter {
	return s.limiter
}

// Collector returns the server's telemetry Collector.
func (s *GatewayServer) Collector() *observability.Collector {
	return s.collector
}

// MetricsExporter returns the configured OTLP metrics exporter, or nil when disabled.
func (s *GatewayServer) MetricsExporter() *observability.OTLPMetricsExporter {
	return s.metricsExporter
}

// HealthMonitor returns the background active health monitor.
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

// Reliability returns the Stage 2 ReliabilityManager.
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

// MCPHub returns the server's Model Context Protocol Hub.
func (s *GatewayServer) MCPHub() *mcp.Hub {
	return s.mcpHub
}

// A2ARouter returns the Agent-to-Agent router service.
func (s *GatewayServer) A2ARouter() *a2a.RouterService {
	return s.a2aRouter
}

// AuthService returns the virtual-key and identity authentication Service.
func (s *GatewayServer) AuthService() *auth.Service {
	return s.authSvc
}

// SessionManager returns the operator UI and CLI session manager.
func (s *GatewayServer) SessionManager() *auth.SessionManager {
	return s.sessionMgr
}

// SSOProviderManager returns the configured OIDC SSO provider manager, or nil when receiver is nil.
func (s *GatewayServer) SSOProviderManager() *auth.SSOProviderManager {
	if s == nil {
		return nil
	}
	return s.ssoMgr
}

// SSOStateStore returns the transient OIDC PKCE/state store, or nil when receiver is nil.
func (s *GatewayServer) SSOStateStore() *auth.SSOStateStore {
	if s == nil {
		return nil
	}
	return s.ssoStateStore
}

// CLILoginStore returns the CLI device/PKCE login session store, or nil when receiver is nil.
func (s *GatewayServer) CLILoginStore() *auth.CLILoginStore {
	if s == nil {
		return nil
	}
	return s.cliLoginStore
}

// AuthResolver returns the federated JWT/introspection/proxy auth resolver.
func (s *GatewayServer) AuthResolver() *auth.AuthResolver {
	return s.authResolver
}

// KeyRotationManager returns the scheduled virtual-key rotation manager, or nil when receiver is nil.
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

// SetCustomAuthorizer attaches a post-authentication Authorizer (chained with any configured
// external Webhook/OPA authorizer) evaluated across inference, MCP, A2A, and Control Plane routes.
func (s *GatewayServer) SetCustomAuthorizer(authorizer auth.Authorizer) {
	if s == nil {
		return
	}
	effective := auth.NewChainAuthorizer(s.externalAuthorizer, authorizer)
	s.customAuthorizer = effective
	if s.mcpHub != nil {
		s.mcpHub.SetCustomAuthorizer(effective)
	}
}

func (s *GatewayServer) evaluateCustomAuthorizer(ctx context.Context, req *auth.AuthzRequest) error {
	if s == nil || s.customAuthorizer == nil {
		return nil
	}
	return auth.EvaluateAuthorizer(ctx, s.customAuthorizer, req)
}

func (s *GatewayServer) authorizeInferenceModel(ctx context.Context, idCtx *domain.IdentityContext, model, method, path string) error {
	if err := s.rbac.AuthorizeRequestedModel(idCtx, model); err != nil {
		return err
	}
	if s.customAuthorizer != nil {
		return s.evaluateCustomAuthorizer(ctx, &auth.AuthzRequest{
			Identity:     idCtx,
			Action:       auth.AuthzActionInference,
			ResourceType: "model",
			ResourceID:   model,
			Model:        model,
			HTTPMethod:   method,
			HTTPPath:     path,
		})
	}
	return nil
}

// RBAC returns the operator and virtual-key RBAC engine.
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
	if s.auditSIEMSink != nil {
		s.auditSIEMSink.Close(ctx)
	}
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

type trustedProxyContextKey struct{}

func isFromTrustedProxy(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	v, _ := ctx.Value(trustedProxyContextKey{}).(bool)
	return v
}

// trustedRealIPMiddleware extracts forwarded client IP headers only for requests originating
// from configured trusted proxy CIDRs so untrusted callers cannot spoof X-Forwarded-For or X-Forwarded-Proto.
func trustedRealIPMiddleware(trustedProxyCIDRs []string) func(http.Handler) http.Handler {
	trustedNets := parseCIDRList(trustedProxyCIDRs)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if len(trustedNets) > 0 && ipInNets(extractRemoteIP(r.RemoteAddr), trustedNets) {
				r = r.WithContext(context.WithValue(r.Context(), trustedProxyContextKey{}, true))
				if realIP := extractTrustedForwardedIP(r); realIP != "" {
					r.RemoteAddr = realIP
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

func extractTrustedForwardedIP(r *http.Request) string {
	for _, header := range []string{"True-Client-IP", "X-Real-IP"} {
		if candidate := strings.TrimSpace(r.Header.Get(header)); candidate != "" && net.ParseIP(candidate) != nil {
			return candidate
		}
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		for _, part := range strings.Split(xff, ",") {
			if candidate := strings.TrimSpace(part); candidate != "" && net.ParseIP(candidate) != nil {
				return candidate
			}
		}
	}
	return ""
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
			Issuer:                    iss.Issuer,
			Audience:                  iss.Audience,
			JWKSURL:                   iss.JWKSURL,
			DiscoveryURL:              iss.DiscoveryURL,
			Algorithms:                iss.Algorithms,
			AllowedEmailDomains:       iss.AllowedEmailDomains,
			AllowUnverifiedEmail:      iss.AllowUnverifiedEmail,
			AllowPrivilegedRoleClaims: iss.AllowPrivilegedRoleClaims,
			ClaimMapping: auth.OIDCClaimMapping{
				UserID:  iss.ClaimMapping.UserID,
				Email:   iss.ClaimMapping.Email,
				OrgID:   iss.ClaimMapping.OrgID,
				TeamIDs: iss.ClaimMapping.TeamIDs,
				Role:    iss.ClaimMapping.Role,
				Groups:  iss.ClaimMapping.Groups,
				EndUser: iss.ClaimMapping.EndUser,
			},
			GroupRoleMappings:   convertGroupRoleMappings(iss.GroupRoleMappings),
			RoleMappingStrategy: iss.RoleMappingStrategy,
			GroupTeamMappings:   iss.GroupTeamMappings,
			AutoRegister:        iss.AutoRegister,
			DefaultOrgID:        iss.DefaultOrgID,
			DefaultTeamID:       iss.DefaultTeamID,
			DefaultRole:         iss.DefaultRole,
			NetworkPolicy:       netPolicy,
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
			ID:                        p.ID,
			Name:                      p.Name,
			Type:                      p.Type,
			DisplayName:               p.DisplayName,
			ClientID:                  config.ResolveEnvValue(p.ClientID),
			ClientSecret:              config.ResolveEnvValue(p.ClientSecret),
			Issuer:                    p.Issuer,
			AuthorizationEndpoint:     p.AuthorizationEndpoint,
			TokenEndpoint:             p.TokenEndpoint,
			JWKSURL:                   p.JWKSURL,
			DiscoveryURL:              p.DiscoveryURL,
			Scopes:                    append([]string(nil), p.Scopes...),
			RedirectURL:               p.RedirectURL,
			AllowedEmailDomains:       append([]string(nil), p.AllowedEmailDomains...),
			AllowUnverifiedEmail:      p.AllowUnverifiedEmail,
			AllowPrivilegedRoleClaims: p.AllowPrivilegedRoleClaims,
			AutoRegister:              p.AutoRegister,
			DefaultOrgID:              p.DefaultOrgID,
			DefaultTeamID:             p.DefaultTeamID,
			DefaultRole:               p.DefaultRole,
			Algorithms:                append([]string(nil), p.Algorithms...),
			ClaimMapping: auth.OIDCClaimMapping{
				UserID:  p.ClaimMapping.UserID,
				Email:   p.ClaimMapping.Email,
				OrgID:   p.ClaimMapping.OrgID,
				TeamIDs: p.ClaimMapping.TeamIDs,
				Role:    p.ClaimMapping.Role,
				Groups:  p.ClaimMapping.Groups,
				EndUser: p.ClaimMapping.EndUser,
			},
			GroupRoleMappings:   convertGroupRoleMappings(p.GroupRoleMappings),
			RoleMappingStrategy: p.RoleMappingStrategy,
			GroupTeamMappings:   p.GroupTeamMappings,
			SyncRolesOnLogin:    p.SyncRolesOnLogin,
		})
	}
	return out
}

func convertGroupRoleMappings(in []config.GroupRoleMappingRule) []auth.GroupRoleMappingRule {
	if len(in) == 0 {
		return nil
	}
	out := make([]auth.GroupRoleMappingRule, 0, len(in))
	for _, r := range in {
		out = append(out, auth.GroupRoleMappingRule{
			Group: r.Group,
			Role:  r.Role,
		})
	}
	return out
}
