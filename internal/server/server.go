package server

import (
	"context"
	"fmt"
	"net/http"
	"strings"
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
	cfg             *config.Config
	repo            storage.Repository
	redisFabric     *storage.RedisFabric
	reg             *adapter.Registry
	vault           *auth.Vault
	authSvc         *auth.Service
	rbac            *auth.RBACEngine
	limiter         *ratelimit.Limiter
	respCache       *cache.ResponseCache
	modelMgmt       *modelmgmt.Service
	discovery       *modelmgmt.DiscoveryWorker
	reliability     *router.ReliabilityManager
	spendWorker     *finops.SpendWorker
	collector       *observability.Collector
	tracer          trace.Tracer
	tracerShutdown  func(context.Context) error
	healthMon       *health.Monitor
	validator       *validation.Validator
	guardrails      *guardrails.Engine
	mcpHub          *mcp.Hub
	a2aRouter       *a2a.RouterService
	a2aSigner       *a2a.GatewayCardSigner
	a2aStreamSub    *a2a.StreamSubscriber
	a2aPublisher    *a2a.StreamPublisher
	a2aOutboxWorker *a2a.OutboxWorker
	a2aBridge       *a2a.OpenAIBridge
	orchestrator    *orchestrator.ToolLoopOrchestrator
	router          chi.Router
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

	adapterClient := httpClient
	if adapterClient == nil {
		adapterClient = network.NewHTTPClient(netPolicy)
	}

	reg := adapter.NewRegistry()
	reg.Register(openai.NewAdapter(adapterClient))
	reg.Register(anthropic.NewAdapter(adapterClient))
	reg.Register(gemini.NewAdapter(adapterClient))
	reg.Register(mistral.NewAdapter(adapterClient))
	reg.Register(ollama.NewAdapter(adapterClient))
	reg.Register(bedrock.NewAdapter(adapterClient, netPolicy))
	reg.Register(vertex.NewAdapter(adapterClient, netPolicy))
	reg.Register(cohere.NewAdapter(adapterClient, netPolicy))

	profileReg := openaicompat.NewProfileRegistry(adapterClient, netPolicy)
	for _, custom := range cfg.Providers.CustomOpenAICompatible {
		if err := profileReg.RegisterCustom(custom); err != nil {
			return nil, fmt.Errorf("failed to register custom provider %q: %w", custom.ID, err)
		}
	}
	reg.SetDynamicResolver(profileReg.DynamicResolver())

	authSvc := auth.NewService(repo, redisFabric, cfg.Auth.MasterAdminKey, cfg.Auth.L1CacheTTL, cfg.Auth.L2CacheTTL)
	rbac := auth.NewRBACEngine(repo)
	limiter := ratelimit.NewLimiter(redisFabric, cfg.RateLimit.WindowSeconds, cfg.RateLimit.ConcurrencyTTLSec)
	respCache := cache.NewResponseCache(cfg.Cache.Enabled, cfg.Cache.DefaultTTL, redisFabric)
	modelMgmtSvc := modelmgmt.NewService(repo)
	discWorker := modelmgmt.NewDiscoveryWorker(repo, reg, vault, redisFabric, cfg.Discovery.SyncInterval, cfg.Discovery.AutoApprove)

	collector := observability.NewCollector()
	healthMon := health.NewMonitor(repo, reg, vault, 60*time.Second, 5*time.Second)
	validator := validation.NewValidator(repo)
	guardrailsEng := guardrails.NewEngine(repo)

	ir := router.NewIntelligentRouter(repo, cfg.Router)
	ir.SetProviderCallable(func(provider domain.ProviderType) bool {
		_, err := reg.Get(provider)
		return err == nil
	})
	lb := router.NewLoadBalancer(redisFabric)
	relMgr := router.NewReliabilityManager(repo, reg, ir, lb, vault, rbac, redisFabric, cfg.Router)
	relMgr.SetCollector(collector)
	relMgr.SetHealthMonitor(healthMon)

	spendWorker := finops.NewSpendWorker(repo, limiter, cfg.FinOps)

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

	s := &GatewayServer{
		cfg:             cfg,
		repo:            repo,
		redisFabric:     redisFabric,
		reg:             reg,
		vault:           vault,
		authSvc:         authSvc,
		rbac:            rbac,
		limiter:         limiter,
		respCache:       respCache,
		modelMgmt:       modelMgmtSvc,
		discovery:       discWorker,
		reliability:     relMgr,
		spendWorker:     spendWorker,
		collector:       collector,
		tracer:          tracer,
		tracerShutdown:  tracerShutdown,
		healthMon:       healthMon,
		validator:       validator,
		guardrails:      guardrailsEng,
		mcpHub:          mcpHub,
		a2aRouter:       a2aRouter,
		a2aSigner:       a2aSigner,
		a2aStreamSub:    a2aStreamSub,
		a2aPublisher:    a2aPublisher,
		a2aOutboxWorker: a2aOutboxWorker,
		a2aBridge:       a2aBridge,
		orchestrator:    toolOrchestrator,
	}
	s.setupRoutes()
	if err := s.bootstrap(context.Background()); err != nil {
		if s.tracerShutdown != nil {
			_ = s.tracerShutdown(context.Background())
		}
		return nil, err
	}
	return s, nil
}

func (s *GatewayServer) setupRoutes() {
	r := chi.NewRouter()
	r.Use(middleware.Recoverer)
	r.Use(middleware.RealIP)
	r.Use(observability.TraceMiddlewareWithTracer(s.tracer))
	r.Use(logger.HTTPMiddleware(nil))

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

	// Control Plane (/admin/v1/* — Enterprise Management, Governance, Discovery, Security & FinOps API)
	r.Route("/admin/v1", func(adm chi.Router) {
		adm.Use(auth.AdminControlPlaneMiddleware(s.authSvc))

		// Organizations, 4-Layer Policies & Security Guardrails
		adm.Post("/organizations", s.handleAdminCreateOrg)
		adm.Get("/organizations", s.handleAdminListOrgs)
		adm.Post("/organizations/{orgID}/subscriptions", s.handleAdminSetOrgSubscription)
		adm.Get("/organizations/{orgID}/subscriptions", s.handleAdminGetOrgSubscriptions)
		adm.Post("/organizations/{orgID}/models", s.handleAdminSetOrgModelPolicy)
		adm.Get("/organizations/{orgID}/models", s.handleAdminGetOrgModelPolicies)
		adm.Post("/organizations/{orgID}/guardrails", s.handleAdminSetGuardrailPolicy)
		adm.Get("/organizations/{orgID}/guardrails", s.handleAdminGetGuardrailPolicy)
		adm.Post("/organizations/{orgID}/guardrails/simulate", s.handleAdminSimulateGuardrails)

		// Teams & Users
		adm.Post("/teams", s.handleAdminCreateTeam)
		adm.Get("/teams", s.handleAdminListTeams)
		adm.Post("/users", s.handleAdminCreateUser)
		adm.Get("/users", s.handleAdminListUsers)

		// Virtual API Keys
		adm.Post("/keys", s.handleAdminIssueKey)
		adm.Get("/keys", s.handleAdminListKeys)
		adm.Post("/keys/{keyID}/revoke", s.handleAdminRevokeKey)
		adm.Delete("/keys/{keyID}", s.handleAdminRevokeKey)

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

		// FinOps Spend & Governance Audit Logs
		adm.Get("/spend/summary", s.handleAdminSpendSummary)
		adm.Get("/spend/logs", s.handleAdminSpendLogs)
		adm.Get("/audit/logs", s.handleAdminAuditLogs)

		// MCP Enterprise Management: Servers, Toolsets, Tool Sync & BYOK Credentials
		adm.Post("/mcp/servers", s.handleAdminCreateMCPServer)
		adm.Get("/mcp/servers", s.handleAdminListMCPServers)
		adm.Post("/mcp/servers/{serverID}/sync", s.handleAdminSyncMCPServer)
		adm.Post("/mcp/toolsets", s.handleAdminCreateMCPToolset)
		adm.Get("/mcp/toolsets", s.handleAdminListMCPToolsets)
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

func (s *GatewayServer) MCPHub() *mcp.Hub {
	return s.mcpHub
}

func (s *GatewayServer) A2ARouter() *a2a.RouterService {
	return s.a2aRouter
}

// StartWorkers starts background daemons (Async Spend Batch Writer, Automated Model Discovery, Active Health Monitor, A2A Stream Publisher & Outbox Worker).
func (s *GatewayServer) StartWorkers(ctx context.Context) {
	s.authSvc.StartInvalidationListener(ctx)
	s.spendWorker.Start(ctx)
	s.healthMon.Start(ctx)
	if s.cfg.Discovery.Enabled {
		s.discovery.Start(ctx)
	}
	if s.a2aPublisher != nil {
		s.a2aPublisher.Start(ctx)
	}
	if s.a2aOutboxWorker != nil {
		s.a2aOutboxWorker.Start(ctx)
	}
}

// Shutdown drains background workers cleanly.
func (s *GatewayServer) Shutdown(ctx context.Context) {
	s.authSvc.StopInvalidationListener()
	if s.a2aPublisher != nil {
		s.a2aPublisher.Stop()
	}
	if s.a2aOutboxWorker != nil {
		s.a2aOutboxWorker.Stop()
	}
	s.healthMon.Stop()
	s.discovery.Stop()
	s.spendWorker.Stop(ctx)
	if s.tracerShutdown != nil {
		_ = s.tracerShutdown(ctx)
	}
}
