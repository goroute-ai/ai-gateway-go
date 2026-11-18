package config

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"gopkg.in/yaml.v3"
)

// Config holds the complete runtime configuration for the Enterprise AI Gateway.
type Config struct {
	Server     ServerConfig     `yaml:"server"`
	Logging    LogConfig        `yaml:"logging"`
	Tracing    TracingConfig    `yaml:"tracing"`
	Security   SecurityConfig   `yaml:"security"`
	Storage    StorageConfig    `yaml:"storage"`
	Auth       AuthConfig       `yaml:"auth"`
	Router     RouterConfig     `yaml:"router"`
	RateLimit  RateLimitConfig  `yaml:"rate_limit"`
	FinOps     FinOpsConfig     `yaml:"finops"`
	Discovery  DiscoveryConfig  `yaml:"discovery"`
	Cache      CacheConfig      `yaml:"cache"`
	Guardrails GuardrailsConfig `yaml:"guardrails"`
	MCP        MCPConfig        `yaml:"mcp"`
	A2A        A2AConfig        `yaml:"a2a"`
	Providers  ProvidersConfig  `yaml:"providers"`
	ModelList  []ModelListEntry `yaml:"model_list"`
}

// SecurityConfig defines unified security, network egress/SSRF, and inbound controls.
type SecurityConfig struct {
	Network NetworkSecurityConfig `yaml:"network"`
}

// NetworkSecurityConfig defines network perimeter policies for egress SSRF and ingress caller routing.
type NetworkSecurityConfig struct {
	OutboundSSRF  OutboundSSRFConfig  `yaml:"outbound_ssrf"`
	InboundCaller InboundCallerConfig `yaml:"inbound_caller"`
}

// OutboundSSRFConfig defines egress SSRF prevention policies.
type OutboundSSRFConfig struct {
	AllowPrivateNetworks bool          `yaml:"allow_private_networks"` // default false (or true in local test/dev)
	AllowedPrivateCIDRs  []string      `yaml:"allowed_private_cidrs"`  // e.g. ["10.0.0.0/8"]
	AllowInsecureHTTP    bool          `yaml:"allow_insecure_http"`    // default false (forces https:// upstream unless true)
	AllowedSchemes       []string      `yaml:"allowed_schemes"`        // e.g. ["https", "http"]
	BlockedIPs           []string      `yaml:"blocked_ips"`            // e.g. ["169.254.169.254"]
	DialTimeout          time.Duration `yaml:"dial_timeout"`
	MaxRedirects         int           `yaml:"max_redirects"`
	EgressProxyURL       string        `yaml:"egress_proxy_url" json:"egress_proxy_url"`
}

// InboundCallerConfig defines ingress network policies for incoming requests.
type InboundCallerConfig struct {
	ExposeOnPublicInternet bool     `yaml:"expose_on_public_internet"`
	AllowedClientCIDRs     []string `yaml:"allowed_client_cidrs"`
	TrustedProxyCIDRs      []string `yaml:"trusted_proxy_cidrs"`
}

// MCPConfig defines parameters for Model Context Protocol (2026-07-28 & 2025-11-25 compat).
type MCPConfig struct {
	Enabled                   bool          `yaml:"enabled"`
	AllowStdioServers         bool          `yaml:"allow_stdio_servers"`         // default false; stdio disabled until BL-02 sandbox
	AllowedStdioBinaries      []string      `yaml:"allowed_stdio_binaries"`      // canonical path allowlist
	EnableSessionCompat2025   bool          `yaml:"enable_session_compat_2025"`  // default true for 2025-11-25 compatibility
	SessionTTL2025            time.Duration `yaml:"session_ttl_2025"`            // default 15m
	CacheKeySecret            string        `yaml:"cache_key_secret"`            // for HMAC-SHA256 cache keys (defaults to Auth.MasterEncryptionKey)
	MaxPayloadBytes           int64         `yaml:"max_payload_bytes"`           // default 10MB
	DefaultTimeout            time.Duration `yaml:"default_timeout"`             // default 30s
	SubscriptionsListenActive bool          `yaml:"subscriptions_listen_active"` // default true
}

// A2AConfig defines parameters for Agent-to-Agent Protocol (v1.0).
type A2AConfig struct {
	Enabled                   bool              `yaml:"enabled"`
	EnableJSONRPC             bool              `yaml:"enable_jsonrpc"`               // default true
	EnableHTTPJSON            bool              `yaml:"enable_http_json"`             // default true
	EnableSubscribePostCompat bool              `yaml:"enable_subscribe_post_compat"` // default false (canonical is GET :subscribe)
	AllowLegacyCardDiscovery  bool              `yaml:"allow_legacy_card_discovery"`  // default false
	MaxTaskLifespan           time.Duration     `yaml:"max_task_lifespan"`            // default 24h
	StreamBufferCapacity      int               `yaml:"stream_buffer_capacity"`       // default 256
	StreamPublishInterval     time.Duration     `yaml:"stream_publish_interval"`      // default 50ms
	MaxPushRetries            int               `yaml:"max_push_retries"`             // default 5
	SigningKeyID              string            `yaml:"signing_key_id"`               // Gateway JWS signer kid
	AllowedSigningAlgs        []string          `yaml:"allowed_signing_algs"`         // ["ES256", "RS256", "EdDSA"]
	TrustedCardJWKS           map[string]string `yaml:"trusted_card_jwks"`            // upstream agent slug -> jwks URL
}

// LogConfig defines parameters for structured application and access logging.
type LogConfig struct {
	Level     string `yaml:"level"`      // "debug", "info", "warn", "error"
	Format    string `yaml:"format"`     // "text" (human readable) or "json" (cloud-native structured)
	AddSource bool   `yaml:"add_source"` // include file:line source location in log entries
}

type TracingConfig struct {
	Enabled      bool              `yaml:"enabled" json:"enabled"`
	OTLPEndpoint string            `yaml:"otlp_endpoint" json:"otlp_endpoint"`
	ServiceName  string            `yaml:"service_name" json:"service_name"`
	Headers      map[string]string `yaml:"headers,omitempty" json:"headers,omitempty"`
}

// ModelListEntry defines a declarative model list entry in config.yaml,
// allowing developers to configure models, aliases ("fast", "reasoning"), and credentials
// without imperative Control Plane HTTP setup calls.
type ModelListEntry struct {
	ModelName              string                  `yaml:"model_name" json:"model_name"`
	ModelParams            ModelParams             `yaml:"model_params" json:"model_params"`
	RoutingStrategy        string                  `yaml:"routing_strategy,omitempty" json:"routing_strategy,omitempty"`
	Fallbacks              []string                `yaml:"fallbacks,omitempty" json:"fallbacks,omitempty"`
	ContextWindowFallbacks []domain.FallbackTarget `yaml:"context_window_fallbacks,omitempty" json:"context_window_fallbacks,omitempty"`
	ContentPolicyFallbacks []domain.FallbackTarget `yaml:"content_policy_fallbacks,omitempty" json:"content_policy_fallbacks,omitempty"`
	FallbackTargets        []domain.FallbackTarget `yaml:"fallback_targets,omitempty" json:"fallback_targets,omitempty"`
}

// ModelParams holds upstream provider and model routing parameters for a deployment entry.
type ModelParams struct {
	Model               string            `yaml:"model" json:"model"`       // e.g. "gemini/gemini-2.5-flash" or "anthropic/claude-sonnet-4-20250514"
	APIKey              string            `yaml:"api_key" json:"api_key"`   // literal key or "os.environ/GEMINI_API_KEY" or "${GEMINI_API_KEY}"
	APIBase             string            `yaml:"api_base" json:"api_base"` // optional custom upstream base URL
	Region              string            `yaml:"region,omitempty" json:"region,omitempty"`
	Weight              int               `yaml:"weight,omitempty" json:"weight,omitempty"`
	RPM                 int               `yaml:"rpm,omitempty" json:"rpm,omitempty"`
	TPM                 int               `yaml:"tpm,omitempty" json:"tpm,omitempty"`
	Priority            int               `yaml:"priority,omitempty" json:"priority,omitempty"`
	Tags                []string          `yaml:"tags,omitempty" json:"tags,omitempty"`
	MaxBudgetMicros     int64             `yaml:"max_budget_micros,omitempty" json:"max_budget_micros,omitempty"`
	BudgetResetPeriod   string            `yaml:"budget_reset_period,omitempty" json:"budget_reset_period,omitempty"`
	AzureDeploymentName string            `yaml:"azure_deployment_name,omitempty" json:"azure_deployment_name,omitempty"`
	APIVersion          string            `yaml:"api_version,omitempty" json:"api_version,omitempty"`
	Headers             map[string]string `yaml:"headers,omitempty" json:"headers,omitempty"`
}

type ProvidersConfig struct {
	RequestTimeout         time.Duration          `yaml:"request_timeout" json:"request_timeout"`
	ResponseHeaderTimeout  time.Duration          `yaml:"response_header_timeout" json:"response_header_timeout"`
	StreamIdleTimeout      time.Duration          `yaml:"stream_idle_timeout" json:"stream_idle_timeout"`
	MaxIdleConns           int                    `yaml:"max_idle_conns" json:"max_idle_conns"`
	MaxIdleConnsPerHost    int                    `yaml:"max_idle_conns_per_host" json:"max_idle_conns_per_host"`
	CustomOpenAICompatible []CustomProviderConfig `yaml:"custom_openai_compatible" json:"custom_openai_compatible"`
}

type CustomProviderConfig struct {
	ID                        string            `yaml:"id" json:"id"`
	DisplayName               string            `yaml:"display_name" json:"display_name"`
	BaseURL                   string            `yaml:"base_url" json:"base_url"`
	SupportsStreaming         string            `yaml:"supports_streaming,omitempty" json:"supports_streaming,omitempty"`
	SupportsTools             string            `yaml:"supports_tools,omitempty" json:"supports_tools,omitempty"`
	SupportsStructuredOutputs string            `yaml:"supports_structured_outputs,omitempty" json:"supports_structured_outputs,omitempty"`
	SupportsListModels        bool              `yaml:"supports_list_models" json:"supports_list_models"`
	DefaultHeaders            map[string]string `yaml:"default_headers,omitempty" json:"default_headers,omitempty"`
	SupportedOperations       []string          `yaml:"supported_operations,omitempty" json:"supported_operations,omitempty"`
	ParamMappings             map[string]string `yaml:"param_mappings,omitempty" json:"param_mappings,omitempty"`
	ReasoningMapping          string            `yaml:"reasoning_mapping,omitempty" json:"reasoning_mapping,omitempty"`
}

// GuardrailsConfig configures guardrail scanners, declarative definitions, and tool trust policies.
type GuardrailsConfig struct {
	Scanners     []GuardrailScannerConfig    `yaml:"scanners" json:"scanners"`
	Definitions  []GuardrailDefinitionConfig `yaml:"definitions,omitempty" json:"definitions,omitempty"`
	ToolPolicies []ToolPolicyConfig          `yaml:"tool_policies,omitempty" json:"tool_policies,omitempty"`
}

// GuardrailScannerConfig defines an external HTTP/webhook guardrail scanner.
type GuardrailScannerConfig struct {
	Name      string            `yaml:"name" json:"name"`
	URL       string            `yaml:"url" json:"url"`
	TimeoutMs int               `yaml:"timeout_ms" json:"timeout_ms"`
	FailOpen  bool              `yaml:"fail_open" json:"fail_open"`
	Headers   map[string]string `yaml:"headers,omitempty" json:"headers,omitempty"`
}

// GuardrailModeRuleConfig defines dynamic hook selection by request tag for a seeded guardrail.
type GuardrailModeRuleConfig struct {
	Tags    map[string][]string `yaml:"tags,omitempty" json:"tags,omitempty"`
	Default []string            `yaml:"default,omitempty" json:"default,omitempty"`
}

// GuardrailBindingConfig declares an org/team/key/model_group/tag binding seeded alongside a guardrail definition.
type GuardrailBindingConfig struct {
	ID             string         `yaml:"id,omitempty" json:"id,omitempty"`
	TeamID         string         `yaml:"team_id,omitempty" json:"team_id,omitempty"`
	VirtualKeyID   string         `yaml:"virtual_key_id,omitempty" json:"virtual_key_id,omitempty"`
	EndUserID      string         `yaml:"end_user_id,omitempty" json:"end_user_id,omitempty"`
	ModelGroupID   string         `yaml:"model_group_id,omitempty" json:"model_group_id,omitempty"`
	Tag            string         `yaml:"tag,omitempty" json:"tag,omitempty"`
	ParamOverrides map[string]any `yaml:"param_overrides,omitempty" json:"param_overrides,omitempty"`
	IsLocked       bool           `yaml:"is_locked,omitempty" json:"is_locked,omitempty"`
}

// GuardrailDefinitionConfig defines a declarative guardrail seeded into the registry on startup.
type GuardrailDefinitionConfig struct {
	ID            string                   `yaml:"id,omitempty" json:"id,omitempty"`
	OrgID         string                   `yaml:"org_id,omitempty" json:"org_id,omitempty"`
	Name          string                   `yaml:"name" json:"name"`
	Provider      string                   `yaml:"provider" json:"provider"`
	EventHooks    []string                 `yaml:"event_hooks,omitempty" json:"event_hooks,omitempty"`
	StreamScope   string                   `yaml:"stream_scope,omitempty" json:"stream_scope,omitempty"`
	DefaultOn     bool                     `yaml:"default_on,omitempty" json:"default_on,omitempty"`
	EnabledRoles  []string                 `yaml:"enabled_roles,omitempty" json:"enabled_roles,omitempty"`
	TimeoutMs     int                      `yaml:"timeout_ms,omitempty" json:"timeout_ms,omitempty"`
	FailOpen      bool                     `yaml:"fail_open,omitempty" json:"fail_open,omitempty"`
	Precedence    int                      `yaml:"precedence,omitempty" json:"precedence,omitempty"`
	Weight        int                      `yaml:"weight,omitempty" json:"weight,omitempty"`
	Status        string                   `yaml:"status,omitempty" json:"status,omitempty"`
	ModeRule      *GuardrailModeRuleConfig `yaml:"mode_rule,omitempty" json:"mode_rule,omitempty"`
	Config        map[string]any           `yaml:"config,omitempty" json:"config,omitempty"`
	Secrets       map[string]any           `yaml:"secrets,omitempty" json:"secrets,omitempty"`
	GuardrailInfo map[string]any           `yaml:"guardrail_info,omitempty" json:"guardrail_info,omitempty"`
	Bindings      []GuardrailBindingConfig `yaml:"bindings,omitempty" json:"bindings,omitempty"`
}

// ToolPolicyConfig defines a declarative tool input/output trust policy seeded on startup.
type ToolPolicyConfig struct {
	ID           string `yaml:"id,omitempty" json:"id,omitempty"`
	OrgID        string `yaml:"org_id,omitempty" json:"org_id,omitempty"`
	TeamID       string `yaml:"team_id,omitempty" json:"team_id,omitempty"`
	VirtualKeyID string `yaml:"virtual_key_id,omitempty" json:"virtual_key_id,omitempty"`
	ToolName     string `yaml:"tool_name" json:"tool_name"`
	InputPolicy  string `yaml:"input_policy,omitempty" json:"input_policy,omitempty"`
	OutputPolicy string `yaml:"output_policy,omitempty" json:"output_policy,omitempty"`
}

type ServerConfig struct {
	Environment               string        `yaml:"environment"` // "development", "staging", "production"
	Host                      string        `yaml:"host"`
	Port                      int           `yaml:"port"`
	GRPCPort                  int           `yaml:"grpc_port"` // 0 = disabled; >0 enables A2A gRPC server
	ReadTimeout               time.Duration `yaml:"read_timeout"`
	WriteTimeout              time.Duration `yaml:"write_timeout"`
	IdleTimeout               time.Duration `yaml:"idle_timeout"`
	ShutdownTimeout           time.Duration `yaml:"shutdown_timeout"`
	CORSAllowedOrigins        []string      `yaml:"cors_allowed_origins"`
	CORSAllowCredentials      bool          `yaml:"cors_allow_credentials"`
	EnableHSTS                bool          `yaml:"enable_hsts"`
	MaxFileStorageBytesPerOrg int64         `yaml:"max_file_storage_bytes_per_org"` // 0 = unlimited
	MaxConcurrentFileUploads  int           `yaml:"max_concurrent_file_uploads"`    // 0 = unlimited
}

type StorageConfig struct {
	Mode            string   `yaml:"mode"` // "memory" or "postgres"
	PostgresDSN     string   `yaml:"postgres_dsn"`
	RedisAddr       string   `yaml:"redis_addr"`
	RedisAddrs      []string `yaml:"redis_addrs"`
	RedisMasterName string   `yaml:"redis_master_name"`
	RedisPass       string   `yaml:"redis_pass"`
	RedisDB         int      `yaml:"redis_db"`
}

// OIDCClaimMapping maps custom JWT claim paths to GoRoute identity fields.
type OIDCClaimMapping struct {
	UserID  string `yaml:"user_id,omitempty"`
	Email   string `yaml:"email,omitempty"`
	OrgID   string `yaml:"org_id,omitempty"`
	TeamIDs string `yaml:"team_ids,omitempty"`
	Role    string `yaml:"role,omitempty"`
	EndUser string `yaml:"end_user,omitempty"`
}

// OIDCIssuerConfig configures a single OIDC/JWT issuer for multi-issuer verification.
type OIDCIssuerConfig struct {
	Issuer              string           `yaml:"issuer"`
	Audience            string           `yaml:"audience,omitempty"`
	JWKSURL             string           `yaml:"jwks_url,omitempty"`
	DiscoveryURL        string           `yaml:"discovery_url,omitempty"`
	Algorithms          []string         `yaml:"algorithms,omitempty"`
	AllowedEmailDomains []string         `yaml:"allowed_email_domains,omitempty"`
	ClaimMapping        OIDCClaimMapping `yaml:"claim_mapping,omitempty"`
	AutoRegister        bool             `yaml:"auto_register,omitempty"`
	DefaultOrgID        string           `yaml:"default_org_id,omitempty"`
	DefaultTeamID       string           `yaml:"default_team_id,omitempty"`
	DefaultRole         string           `yaml:"default_role,omitempty"`
}

// IntrospectionConfig configures OAuth 2.0 RFC 7662 token introspection or OIDC UserInfo verification.
type IntrospectionConfig struct {
	TokenInfoEndpoint string        `yaml:"token_info_endpoint,omitempty"`
	ClientID          string        `yaml:"client_id,omitempty"`
	ClientSecret      string        `yaml:"client_secret,omitempty"`
	Mode              string        `yaml:"mode,omitempty"`
	UserIDField       string        `yaml:"user_id_field,omitempty"`
	EmailField        string        `yaml:"email_field,omitempty"`
	RoleField         string        `yaml:"role_field,omitempty"`
	OrgIDField        string        `yaml:"org_id_field,omitempty"`
	TeamIDField       string        `yaml:"team_id_field,omitempty"`
	CacheTTL          time.Duration `yaml:"cache_ttl,omitempty"`
	AutoRegister      bool          `yaml:"auto_register,omitempty"`
	DefaultTeamID     string        `yaml:"default_team_id,omitempty"`
	DefaultRole       string        `yaml:"default_role,omitempty"`
}

// ProxyAuthConfig configures CIDR-guarded reverse-proxy identity header authentication.
type ProxyAuthConfig struct {
	Enabled           bool              `yaml:"enabled,omitempty"`
	TrustedProxyCIDRs []string          `yaml:"trusted_proxy_cidrs,omitempty"`
	HeaderMapping     map[string]string `yaml:"header_mapping,omitempty"`
	AutoRegister      bool              `yaml:"auto_register,omitempty"`
	DefaultTeamID     string            `yaml:"default_team_id,omitempty"`
	DefaultRole       string            `yaml:"default_role,omitempty"`
}

type AuthConfig struct {
	MasterAdminKey          string              `yaml:"master_admin_key"`
	MasterEncryptionKey     string              `yaml:"master_encryption_key"` // 32-byte hex or raw string for AES-256-GCM KEK
	AllowMasterKeyDataPlane bool                `yaml:"allow_master_key_data_plane"`
	EnableDataPlaneJWT      bool                `yaml:"enable_data_plane_jwt"`
	CustomAPIKeyHeader      string              `yaml:"custom_api_key_header"`
	JWTSecret               string              `yaml:"jwt_secret"`
	JWTIssuer               string              `yaml:"jwt_issuer"`
	JWTAudience             string              `yaml:"jwt_audience"`
	OIDCJWKSURL             string              `yaml:"oidc_jwks_url"`
	OIDCIssuers             []OIDCIssuerConfig  `yaml:"oidc_issuers,omitempty"`
	Introspection           IntrospectionConfig `yaml:"introspection,omitempty"`
	ProxyAuth               ProxyAuthConfig     `yaml:"proxy_auth,omitempty"`
	DefaultOrgID            string              `yaml:"default_org_id"`
	DefaultVirtualKey       string              `yaml:"default_virtual_key"`
	L1CacheTTL              time.Duration       `yaml:"l1_cache_ttl"`
	L2CacheTTL              time.Duration       `yaml:"l2_cache_ttl"`
	KeyRotationPollInterval time.Duration       `yaml:"key_rotation_poll_interval,omitempty"`
	KeyRotationGracePeriod  time.Duration       `yaml:"key_rotation_grace_period,omitempty"`
	UIUsername              string              `yaml:"ui_username,omitempty"`
	UIPassword              string              `yaml:"ui_password,omitempty"`
	SessionSecret           string              `yaml:"session_secret,omitempty"`
	SessionTTL              time.Duration       `yaml:"session_ttl,omitempty"`
	EnableHIBPCheck         bool                `yaml:"enable_hibp_check,omitempty"`
	HIBPBaseURL             string              `yaml:"hibp_base_url,omitempty"`
}

type RouterConfig struct {
	DefaultFastAlias               string                  `yaml:"default_fast_alias" json:"default_fast_alias"`
	DefaultReasoningAlias          string                  `yaml:"default_reasoning_alias" json:"default_reasoning_alias"`
	DefaultCodingAlias             string                  `yaml:"default_coding_alias" json:"default_coding_alias"`
	ComplexityThreshold            float64                 `yaml:"complexity_threshold" json:"complexity_threshold"`
	LongContextTokens              int                     `yaml:"long_context_tokens" json:"long_context_tokens"`
	DefaultMaxRetries              int                     `yaml:"default_max_retries" json:"default_max_retries"`
	BaseRetryDelay                 time.Duration           `yaml:"base_retry_delay" json:"base_retry_delay"`
	MaxRetryDelay                  time.Duration           `yaml:"max_retry_delay" json:"max_retry_delay"`
	DefaultCooldown                time.Duration           `yaml:"default_cooldown" json:"default_cooldown"`
	FailureWindow                  time.Duration           `yaml:"failure_window" json:"failure_window"`
	FailureThreshold               int                     `yaml:"failure_threshold" json:"failure_threshold"`
	DefaultFallbacks               []domain.FallbackTarget `yaml:"default_fallbacks,omitempty" json:"default_fallbacks,omitempty"`
	MaxFallbackDepth               int                     `yaml:"max_fallback_depth" json:"max_fallback_depth"`
	RetryPolicy                    domain.RetryPolicy      `yaml:"retry_policy,omitempty" json:"retry_policy,omitempty"`
	CooldownPolicy                 domain.CooldownPolicy   `yaml:"cooldown_policy,omitempty" json:"cooldown_policy,omitempty"`
	EnableMidStreamContinuation    bool                    `yaml:"enable_mid_stream_continuation" json:"enable_mid_stream_continuation"`
	MaxStreamContinuations         int                     `yaml:"max_stream_continuations" json:"max_stream_continuations"`
	HealthStalenessThreshold       time.Duration           `yaml:"health_staleness_threshold" json:"health_staleness_threshold"`
	StrictCapacityFiltering        bool                    `yaml:"strict_capacity_filtering" json:"strict_capacity_filtering"`
	ProviderBudgets                map[string]int64        `yaml:"provider_budgets,omitempty" json:"provider_budgets,omitempty"`
	SessionAffinityTTL             time.Duration           `yaml:"session_affinity_ttl" json:"session_affinity_ttl"`
	SessionAffinityRepinOnFailover bool                    `yaml:"session_affinity_repin_on_failover" json:"session_affinity_repin_on_failover"`
	PromptCacheAffinity            bool                    `yaml:"prompt_cache_affinity" json:"prompt_cache_affinity"`
	PreRouterMode                  string                  `yaml:"pre_router_mode,omitempty" json:"pre_router_mode,omitempty"`
	SemanticRouter                 SemanticRouterConfig    `yaml:"semantic_router,omitempty" json:"semantic_router,omitempty"`
	CacheAwareRouting              bool                    `yaml:"cache_aware_routing" json:"cache_aware_routing"`
	Bandit                         BanditConfig            `yaml:"bandit,omitempty" json:"bandit,omitempty"`
	HedgeDelayMs                   int                     `yaml:"hedge_delay_ms" json:"hedge_delay_ms"`
	MaxHedgeConcurrency            int                     `yaml:"max_hedge_concurrency" json:"max_hedge_concurrency"`
	Scheduler                      SchedulerConfig         `yaml:"scheduler,omitempty" json:"scheduler,omitempty"`
}

// SemanticRouterConfig configures embedding-based semantic pre-routing.
type SemanticRouterConfig struct {
	Enabled             bool                  `yaml:"enabled" json:"enabled"`
	EmbeddingModel      string                `yaml:"embedding_model,omitempty" json:"embedding_model,omitempty"`
	SimilarityThreshold float64               `yaml:"similarity_threshold,omitempty" json:"similarity_threshold,omitempty"`
	Timeout             time.Duration         `yaml:"timeout,omitempty" json:"timeout,omitempty"`
	Routes              []SemanticRouteConfig `yaml:"routes,omitempty" json:"routes,omitempty"`
}

// SemanticRouteConfig defines an intent route for semantic pre-routing.
type SemanticRouteConfig struct {
	Name        string   `yaml:"name" json:"name"`
	TargetModel string   `yaml:"target_model" json:"target_model"`
	Utterances  []string `yaml:"utterances,omitempty" json:"utterances,omitempty"`
	Description string   `yaml:"description,omitempty" json:"description,omitempty"`
}

// BanditConfig configures Thompson-sampling adaptive bandit pre-routing.
type BanditConfig struct {
	Enabled         bool          `yaml:"enabled" json:"enabled"`
	DefaultAlpha    float64       `yaml:"default_alpha,omitempty" json:"default_alpha,omitempty"`
	DefaultBeta     float64       `yaml:"default_beta,omitempty" json:"default_beta,omitempty"`
	ExplorationRate float64       `yaml:"exploration_rate,omitempty" json:"exploration_rate,omitempty"`
	DecayHalfLife   time.Duration `yaml:"decay_half_life,omitempty" json:"decay_half_life,omitempty"`
	LatencyWeight   float64       `yaml:"latency_weight,omitempty" json:"latency_weight,omitempty"`
	CostWeight      float64       `yaml:"cost_weight,omitempty" json:"cost_weight,omitempty"`
	SyncInterval    time.Duration `yaml:"sync_interval,omitempty" json:"sync_interval,omitempty"`
	CandidateModels []string      `yaml:"candidate_models,omitempty" json:"candidate_models,omitempty"`
}

// SchedulerConfig configures bounded priority-queue request scheduling.
type SchedulerConfig struct {
	Enabled         bool          `yaml:"enabled" json:"enabled"`
	MaxQueueDepth   int           `yaml:"max_queue_depth,omitempty" json:"max_queue_depth,omitempty"`
	MaxWaitTime     time.Duration `yaml:"max_wait_time,omitempty" json:"max_wait_time,omitempty"`
	DefaultPriority int           `yaml:"default_priority,omitempty" json:"default_priority,omitempty"`
}

type RateLimitConfig struct {
	Enabled                 bool          `yaml:"enabled" json:"enabled"`
	FallbackToLocalOnOutage bool          `yaml:"fallback_to_local_on_outage" json:"fallback_to_local_on_outage"`
	WindowSeconds           int           `yaml:"window_seconds" json:"window_seconds"`
	ConcurrencyTTLSec       int           `yaml:"concurrency_ttl_sec" json:"concurrency_ttl_sec"`
	DefaultEstimatedTPM     int           `yaml:"default_estimated_tpm" json:"default_estimated_tpm"`
	RedisTimeout            time.Duration `yaml:"redis_timeout" json:"redis_timeout"`
	GlobalRPMLimit          int           `yaml:"global_rpm_limit" json:"global_rpm_limit"`
	GlobalTPMLimit          int           `yaml:"global_tpm_limit" json:"global_tpm_limit"`
	GlobalMaxConcurrent     int           `yaml:"global_max_concurrent" json:"global_max_concurrent"`
}

type FinOpsConfig struct {
	ChannelBufferSize         int           `yaml:"channel_buffer_size"`
	BatchSize                 int           `yaml:"batch_size"`
	FlushInterval             time.Duration `yaml:"flush_interval"`
	WorkerCount               int           `yaml:"worker_count"`
	SoftBudgetWebhookURL      string        `yaml:"soft_budget_webhook_url,omitempty"`
	SoftBudgetCooldownSec     int           `yaml:"soft_budget_cooldown_sec,omitempty"`
	BudgetExceededThrottlePct float64       `yaml:"budget_exceeded_throttle_pct,omitempty"`
}

type DiscoveryConfig struct {
	Enabled      bool          `yaml:"enabled"`
	SyncInterval time.Duration `yaml:"sync_interval"`
	AutoApprove  bool          `yaml:"auto_approve"`
}

type CacheConfig struct {
	Enabled      bool          `yaml:"enabled"`
	DefaultTTL   time.Duration `yaml:"default_ttl"`
	MaxL1Entries int           `yaml:"max_l1_entries"`
}

// Default returns a production-ready default configuration.
func Default() *Config {
	return &Config{
		Providers: ProvidersConfig{
			RequestTimeout:        2 * time.Minute,
			ResponseHeaderTimeout: 2 * time.Minute,
			StreamIdleTimeout:     2 * time.Minute,
			MaxIdleConns:          256,
			MaxIdleConnsPerHost:   16,
		},
		Server: ServerConfig{
			Host:                      "0.0.0.0",
			Port:                      8080,
			ReadTimeout:               30 * time.Second,
			WriteTimeout:              300 * time.Second, // High write timeout for long SSE reasoning streams
			IdleTimeout:               120 * time.Second,
			ShutdownTimeout:           15 * time.Second,
			MaxFileStorageBytesPerOrg: 5 * 1024 * 1024 * 1024, // 5 GiB per org
			MaxConcurrentFileUploads:  8,
		},
		Logging: LogConfig{
			Level:     "info",
			Format:    "text",
			AddSource: false,
		},
		Tracing: TracingConfig{ServiceName: "ai-gateway-go"},
		Storage: StorageConfig{
			Mode:        "memory",
			PostgresDSN: "postgres://gateway:gateway@localhost:5432/aigateway?sslmode=disable",
			RedisAddr:   "localhost:6379",
			RedisDB:     0,
		},
		Auth: AuthConfig{
			MasterAdminKey:          "sk-gw-master-admin-default-key-change-me",
			MasterEncryptionKey:     "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			JWTSecret:               "",
			DefaultOrgID:            "org_default",
			L1CacheTTL:              15 * time.Second,
			L2CacheTTL:              5 * time.Minute,
			KeyRotationPollInterval: 1 * time.Minute,
			KeyRotationGracePeriod:  24 * time.Hour,
		},
		Router: RouterConfig{
			DefaultFastAlias:               "fast",
			DefaultReasoningAlias:          "reasoning",
			DefaultCodingAlias:             "coding",
			ComplexityThreshold:            0.40,
			LongContextTokens:              32000,
			DefaultMaxRetries:              2,
			BaseRetryDelay:                 50 * time.Millisecond,
			MaxRetryDelay:                  2 * time.Second,
			DefaultCooldown:                60 * time.Second,
			FailureWindow:                  30 * time.Second,
			FailureThreshold:               3,
			MaxFallbackDepth:               16,
			MaxStreamContinuations:         1,
			SessionAffinityTTL:             30 * time.Minute,
			SessionAffinityRepinOnFailover: true,
			MaxHedgeConcurrency:            2,
		},
		RateLimit: RateLimitConfig{
			Enabled:             true,
			WindowSeconds:       60,
			ConcurrencyTTLSec:   300,
			DefaultEstimatedTPM: 128,
			RedisTimeout:        50 * time.Millisecond,
		},
		FinOps: FinOpsConfig{
			ChannelBufferSize:         16384,
			BatchSize:                 250,
			FlushInterval:             500 * time.Millisecond,
			WorkerCount:               2,
			SoftBudgetCooldownSec:     3600,
			BudgetExceededThrottlePct: 0.10,
		},
		Discovery: DiscoveryConfig{
			Enabled:      true,
			SyncInterval: 6 * time.Hour,
			AutoApprove:  true,
		},
		Cache: CacheConfig{
			Enabled:      true,
			DefaultTTL:   1 * time.Hour,
			MaxL1Entries: 4096,
		},
		Security: SecurityConfig{
			Network: NetworkSecurityConfig{
				OutboundSSRF: OutboundSSRFConfig{
					AllowPrivateNetworks: false,
					AllowedPrivateCIDRs:  nil,
					AllowInsecureHTTP:    false,
					AllowedSchemes:       []string{"https", "http"},
					BlockedIPs:           []string{"169.254.169.254"},
					DialTimeout:          10 * time.Second,
					MaxRedirects:         3,
				},
				InboundCaller: InboundCallerConfig{
					ExposeOnPublicInternet: false,
					AllowedClientCIDRs:     nil,
				},
			},
		},
		MCP: MCPConfig{
			Enabled:                   true,
			AllowStdioServers:         false,
			AllowedStdioBinaries:      nil,
			EnableSessionCompat2025:   true,
			SessionTTL2025:            15 * time.Minute,
			CacheKeySecret:            "",
			MaxPayloadBytes:           10 * 1024 * 1024,
			DefaultTimeout:            30 * time.Second,
			SubscriptionsListenActive: true,
		},
		A2A: A2AConfig{
			Enabled:                   true,
			EnableJSONRPC:             true,
			EnableHTTPJSON:            true,
			EnableSubscribePostCompat: false,
			AllowLegacyCardDiscovery:  false,
			MaxTaskLifespan:           24 * time.Hour,
			StreamBufferCapacity:      256,
			StreamPublishInterval:     50 * time.Millisecond,
			MaxPushRetries:            5,
			SigningKeyID:              "gw-a2a-signer-v1",
			AllowedSigningAlgs:        []string{"ES256", "RS256", "EdDSA"},
			TrustedCardJWKS:           map[string]string{},
		},
	}
}

// Load loads configuration from an optional YAML file path and overrides with environment variables.
// Load reads configuration from an optional YAML file, applies environment overrides,
// and validates the resulting configuration.
func Load(path string) (*Config, error) {
	return loadWithDefaultEnv(path, "")
}

// LoadWithDefaultEnvironment loads configuration like Load, applying defaultEnv
// when neither the config file nor server.environment specifies one.
func LoadWithDefaultEnvironment(path, defaultEnv string) (*Config, error) {
	return loadWithDefaultEnv(path, defaultEnv)
}

func loadWithDefaultEnv(path, defaultEnv string) (*Config, error) {
	cfg := Default()
	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read config file %s: %w", path, err)
		}
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("parse config yaml: %w", err)
		}
	}
	if cfg.Server.Environment == "" && defaultEnv != "" {
		cfg.Server.Environment = defaultEnv
	}

	if v := os.Getenv("GATEWAY_PORT"); v != "" {
		if p, err := strconv.Atoi(v); err == nil {
			cfg.Server.Port = p
		}
	}
	if v := os.Getenv("GATEWAY_GRPC_PORT"); v != "" {
		if p, err := strconv.Atoi(v); err == nil {
			cfg.Server.GRPCPort = p
		}
	}
	if v := os.Getenv("GATEWAY_MAX_FILE_STORAGE_BYTES_PER_ORG"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			cfg.Server.MaxFileStorageBytesPerOrg = n
		}
	}
	if v := os.Getenv("GATEWAY_MAX_CONCURRENT_FILE_UPLOADS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Server.MaxConcurrentFileUploads = n
		}
	}
	if v := os.Getenv("GATEWAY_LOG_LEVEL"); v != "" {
		cfg.Logging.Level = v
	}
	if v := os.Getenv("GATEWAY_LOG_FORMAT"); v != "" {
		cfg.Logging.Format = v
	} else if os.Getenv("ENV") == "production" || os.Getenv("GATEWAY_ENV") == "production" {
		cfg.Logging.Format = "json"
	}
	if v := os.Getenv("GATEWAY_LOG_ADD_SOURCE"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.Logging.AddSource = b
		}
	}
	if v := os.Getenv("GATEWAY_STORAGE_MODE"); v != "" {
		cfg.Storage.Mode = v
	} else if os.Getenv("GATEWAY_POSTGRES_DSN") != "" {
		cfg.Storage.Mode = "postgres"
	}
	if v := os.Getenv("GATEWAY_POSTGRES_DSN"); v != "" {
		cfg.Storage.PostgresDSN = v
	}
	if v := os.Getenv("GATEWAY_REDIS_ADDR"); v != "" {
		cfg.Storage.RedisAddr = v
	}
	if v := os.Getenv("GATEWAY_REDIS_ADDRS"); v != "" {
		parts := strings.Split(v, ",")
		addrs := make([]string, 0, len(parts))
		for _, p := range parts {
			if trimmed := strings.TrimSpace(p); trimmed != "" {
				addrs = append(addrs, trimmed)
			}
		}
		if len(addrs) > 0 {
			cfg.Storage.RedisAddrs = addrs
		}
	}
	if v := os.Getenv("GATEWAY_REDIS_MASTER_NAME"); v != "" {
		cfg.Storage.RedisMasterName = v
	}
	if v := os.Getenv("GATEWAY_REDIS_PASS"); v != "" {
		cfg.Storage.RedisPass = v
	}
	if v := os.Getenv("GATEWAY_MASTER_ADMIN_KEY"); v != "" {
		cfg.Auth.MasterAdminKey = v
	}
	if v := os.Getenv("GATEWAY_MASTER_ENCRYPTION_KEY"); v != "" {
		cfg.Auth.MasterEncryptionKey = v
	}
	if v := os.Getenv("GATEWAY_ALLOW_MASTER_KEY_DATA_PLANE"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.Auth.AllowMasterKeyDataPlane = b
		}
	}
	if v := os.Getenv("GATEWAY_ENABLE_DATA_PLANE_JWT"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.Auth.EnableDataPlaneJWT = b
		}
	}
	if v := os.Getenv("GATEWAY_CUSTOM_API_KEY_HEADER"); v != "" {
		cfg.Auth.CustomAPIKeyHeader = strings.TrimSpace(v)
	}
	if v := os.Getenv("GATEWAY_JWT_SECRET"); v != "" {
		cfg.Auth.JWTSecret = v
	}
	if v := os.Getenv("GATEWAY_JWT_ISSUER"); v != "" {
		cfg.Auth.JWTIssuer = v
	}
	if v := os.Getenv("GATEWAY_JWT_AUDIENCE"); v != "" {
		cfg.Auth.JWTAudience = v
	}
	if v := os.Getenv("GATEWAY_OIDC_JWKS_URL"); v != "" {
		cfg.Auth.OIDCJWKSURL = v
	}
	if v := os.Getenv("GATEWAY_KEY_ROTATION_POLL_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.Auth.KeyRotationPollInterval = d
		}
	}
	if v := os.Getenv("GATEWAY_KEY_ROTATION_GRACE_PERIOD"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.Auth.KeyRotationGracePeriod = d
		}
	}
	if v := os.Getenv("GATEWAY_UI_USERNAME"); v != "" {
		cfg.Auth.UIUsername = strings.TrimSpace(v)
	}
	if v := os.Getenv("GATEWAY_UI_PASSWORD"); v != "" {
		cfg.Auth.UIPassword = v
	}
	if v := os.Getenv("GATEWAY_SESSION_SECRET"); v != "" {
		cfg.Auth.SessionSecret = v
	}
	if v := os.Getenv("GATEWAY_SESSION_TTL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.Auth.SessionTTL = d
		}
	}
	if v := os.Getenv("GATEWAY_ENABLE_HIBP_CHECK"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.Auth.EnableHIBPCheck = b
		}
	}
	if v := os.Getenv("GATEWAY_HIBP_BASE_URL"); v != "" {
		cfg.Auth.HIBPBaseURL = strings.TrimSpace(v)
	}
	if v := os.Getenv("GATEWAY_ROUTER_DEFAULT_COOLDOWN"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.Router.DefaultCooldown = d
		}
	}
	if v := os.Getenv("GATEWAY_ROUTER_BASE_RETRY_DELAY"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.Router.BaseRetryDelay = d
		}
	}
	if v := os.Getenv("GATEWAY_ROUTER_MAX_RETRY_DELAY"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.Router.MaxRetryDelay = d
		}
	}
	if v := os.Getenv("GATEWAY_ROUTER_MAX_FALLBACK_DEPTH"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Router.MaxFallbackDepth = n
		}
	}
	if v := os.Getenv("GATEWAY_ROUTER_ENABLE_MID_STREAM_CONTINUATION"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.Router.EnableMidStreamContinuation = b
		}
	}
	if v := os.Getenv("GATEWAY_ROUTER_MAX_STREAM_CONTINUATIONS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Router.MaxStreamContinuations = n
		}
	}
	if v := os.Getenv("GATEWAY_ROUTER_HEALTH_STALENESS_THRESHOLD"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.Router.HealthStalenessThreshold = d
		}
	}
	if v := os.Getenv("GATEWAY_ROUTER_STRICT_CAPACITY_FILTERING"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.Router.StrictCapacityFiltering = b
		}
	}
	if v := os.Getenv("GATEWAY_ROUTER_SESSION_AFFINITY_TTL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.Router.SessionAffinityTTL = d
		}
	}
	if v := os.Getenv("GATEWAY_ROUTER_SESSION_AFFINITY_REPIN_ON_FAILOVER"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.Router.SessionAffinityRepinOnFailover = b
		}
	}
	if v := os.Getenv("GATEWAY_ROUTER_PROMPT_CACHE_AFFINITY"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.Router.PromptCacheAffinity = b
		}
	}
	if v := os.Getenv("GATEWAY_ROUTER_PRE_ROUTER_MODE"); v != "" {
		cfg.Router.PreRouterMode = strings.TrimSpace(v)
	}
	if v := os.Getenv("GATEWAY_ROUTER_CACHE_AWARE_ROUTING"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.Router.CacheAwareRouting = b
		}
	}
	if v := os.Getenv("GATEWAY_ROUTER_HEDGE_DELAY_MS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Router.HedgeDelayMs = n
		}
	}
	if v := os.Getenv("GATEWAY_ROUTER_MAX_HEDGE_CONCURRENCY"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.Router.MaxHedgeConcurrency = n
		}
	}
	if v := os.Getenv("GATEWAY_FINOPS_FLUSH_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.FinOps.FlushInterval = d
		}
	}
	if v := os.Getenv("GATEWAY_FINOPS_SOFT_BUDGET_WEBHOOK_URL"); v != "" {
		cfg.FinOps.SoftBudgetWebhookURL = strings.TrimSpace(v)
	}
	if v := os.Getenv("GATEWAY_FINOPS_SOFT_BUDGET_COOLDOWN_SEC"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			cfg.FinOps.SoftBudgetCooldownSec = n
		}
	}
	if v := os.Getenv("GATEWAY_FINOPS_BUDGET_EXCEEDED_THROTTLE_PCT"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			cfg.FinOps.BudgetExceededThrottlePct = f
		}
	}
	if v := os.Getenv("GATEWAY_SECURITY_SSRF_ALLOW_PRIVATE"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.Security.Network.OutboundSSRF.AllowPrivateNetworks = b
		}
	}
	if v := os.Getenv("GATEWAY_SECURITY_SSRF_ALLOW_INSECURE_HTTP"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.Security.Network.OutboundSSRF.AllowInsecureHTTP = b
		}
	}
	if v := os.Getenv("GATEWAY_MCP_ENABLED"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.MCP.Enabled = b
		}
	}
	if v := os.Getenv("GATEWAY_MCP_ALLOW_STDIO"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.MCP.AllowStdioServers = b
		}
	}
	if v := os.Getenv("GATEWAY_A2A_ENABLED"); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			cfg.A2A.Enabled = b
		}
	}
	if v := os.Getenv("GATEWAY_A2A_SIGNING_KEY_ID"); v != "" {
		cfg.A2A.SigningKeyID = v
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Validate checks configuration invariants.
func (c *Config) Validate() error {
	if c.Providers.RequestTimeout <= 0 {
		c.Providers.RequestTimeout = 2 * time.Minute
	}
	if c.Providers.ResponseHeaderTimeout <= 0 {
		c.Providers.ResponseHeaderTimeout = 2 * time.Minute
	}
	if c.Providers.StreamIdleTimeout <= 0 {
		c.Providers.StreamIdleTimeout = 2 * time.Minute
	}
	if c.Providers.MaxIdleConns <= 0 {
		c.Providers.MaxIdleConns = 256
	}
	if c.Providers.MaxIdleConnsPerHost <= 0 {
		c.Providers.MaxIdleConnsPerHost = 16
	}
	if c.Cache.MaxL1Entries <= 0 {
		c.Cache.MaxL1Entries = 4096
	}
	if c.Cache.DefaultTTL <= 0 {
		c.Cache.DefaultTTL = time.Hour
	}
	if c.Router.MaxFallbackDepth < 0 {
		return fmt.Errorf("invalid router.max_fallback_depth: %d", c.Router.MaxFallbackDepth)
	}
	if c.Router.MaxFallbackDepth == 0 {
		c.Router.MaxFallbackDepth = 16
	}
	if c.Router.MaxStreamContinuations < 0 {
		return fmt.Errorf("invalid router.max_stream_continuations: %d", c.Router.MaxStreamContinuations)
	}
	if c.Router.MaxStreamContinuations == 0 {
		c.Router.MaxStreamContinuations = 1
	}
	if c.Router.HealthStalenessThreshold < 0 {
		return fmt.Errorf("invalid router.health_staleness_threshold: %s", c.Router.HealthStalenessThreshold)
	}
	if c.Router.SessionAffinityTTL < 0 {
		return fmt.Errorf("invalid router.session_affinity_ttl: %s", c.Router.SessionAffinityTTL)
	}
	if c.Router.SessionAffinityTTL == 0 {
		c.Router.SessionAffinityTTL = 30 * time.Minute
	}
	if c.Router.HedgeDelayMs < 0 {
		return fmt.Errorf("invalid router.hedge_delay_ms: %d", c.Router.HedgeDelayMs)
	}
	if c.Router.MaxHedgeConcurrency < 0 {
		return fmt.Errorf("invalid router.max_hedge_concurrency: %d", c.Router.MaxHedgeConcurrency)
	}
	if c.Router.MaxHedgeConcurrency == 0 {
		c.Router.MaxHedgeConcurrency = 2
	}
	for prov, budget := range c.Router.ProviderBudgets {
		if budget < 0 {
			return fmt.Errorf("invalid router.provider_budgets[%q]: %d", prov, budget)
		}
	}
	if c.Router.Scheduler.MaxQueueDepth < 0 {
		return fmt.Errorf("invalid router.scheduler.max_queue_depth: %d", c.Router.Scheduler.MaxQueueDepth)
	}
	if c.Router.Scheduler.MaxWaitTime < 0 {
		return fmt.Errorf("invalid router.scheduler.max_wait_time: %s", c.Router.Scheduler.MaxWaitTime)
	}
	if c.Router.SemanticRouter.SimilarityThreshold < 0 || c.Router.SemanticRouter.SimilarityThreshold > 1 {
		return fmt.Errorf("invalid router.semantic_router.similarity_threshold: %v", c.Router.SemanticRouter.SimilarityThreshold)
	}
	if c.Router.Bandit.DefaultAlpha < 0 || c.Router.Bandit.DefaultBeta < 0 {
		return fmt.Errorf("invalid router.bandit priors: alpha=%v beta=%v", c.Router.Bandit.DefaultAlpha, c.Router.Bandit.DefaultBeta)
	}
	if rawWebhook := strings.TrimSpace(c.FinOps.SoftBudgetWebhookURL); rawWebhook != "" {
		u, err := url.Parse(rawWebhook)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("invalid finops.soft_budget_webhook_url %q: must be a valid http or https URL", c.FinOps.SoftBudgetWebhookURL)
		}
		c.FinOps.SoftBudgetWebhookURL = rawWebhook
	}
	if c.FinOps.SoftBudgetCooldownSec < 0 {
		return fmt.Errorf("invalid finops.soft_budget_cooldown_sec: %d", c.FinOps.SoftBudgetCooldownSec)
	}
	if c.FinOps.SoftBudgetCooldownSec == 0 {
		c.FinOps.SoftBudgetCooldownSec = 3600
	}
	if c.FinOps.BudgetExceededThrottlePct < 0 || c.FinOps.BudgetExceededThrottlePct > 1 {
		return fmt.Errorf("invalid finops.budget_exceeded_throttle_pct: %v (must be in [0, 1])", c.FinOps.BudgetExceededThrottlePct)
	}
	if c.FinOps.BudgetExceededThrottlePct == 0 {
		c.FinOps.BudgetExceededThrottlePct = 0.10
	}
	if strings.TrimSpace(c.Tracing.ServiceName) == "" {
		c.Tracing.ServiceName = "ai-gateway-go"
	}
	if c.Server.Port <= 0 || c.Server.Port > 65535 {
		return fmt.Errorf("invalid server.port: %d", c.Server.Port)
	}
	if c.Server.CORSAllowCredentials {
		for _, origin := range c.Server.CORSAllowedOrigins {
			if strings.TrimSpace(origin) == "*" {
				return fmt.Errorf("security violation: server.cors_allow_credentials cannot be true when server.cors_allowed_origins contains \"*\"")
			}
		}
	}
	if c.Server.GRPCPort < 0 || c.Server.GRPCPort > 65535 {
		return fmt.Errorf("invalid server.grpc_port: %d", c.Server.GRPCPort)
	}
	if c.Server.MaxFileStorageBytesPerOrg < 0 {
		return fmt.Errorf("invalid server.max_file_storage_bytes_per_org: %d", c.Server.MaxFileStorageBytesPerOrg)
	}
	if c.Server.MaxConcurrentFileUploads < 0 {
		return fmt.Errorf("invalid server.max_concurrent_file_uploads: %d", c.Server.MaxConcurrentFileUploads)
	}
	if c.Auth.SessionTTL <= 0 {
		c.Auth.SessionTTL = 24 * time.Hour
	}
	if len(c.Auth.MasterAdminKey) < 12 {
		return fmt.Errorf("auth.master_admin_key must be at least 12 characters")
	}
	if len(c.Auth.MasterEncryptionKey) < 32 {
		return fmt.Errorf("auth.master_encryption_key must be at least 32 bytes for AES-256-GCM")
	}

	const (
		defaultMasterAdminKey      = "sk-gw-master-admin-default-key-change-me"
		defaultMasterEncryptionKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
		defaultJWTSecret           = "gateway-jwt-hmac-secret-change-me"
	)
	env := strings.ToLower(strings.TrimSpace(c.Server.Environment))
	for _, candidate := range []string{os.Getenv("ENV"), os.Getenv("GATEWAY_ENV")} {
		candidate = strings.ToLower(strings.TrimSpace(candidate))
		if candidate != "" {
			env = candidate
		}
	}
	isDevOrTest := env == "development" || env == "test"
	if !isDevOrTest {
		if c.Auth.MasterAdminKey == defaultMasterAdminKey {
			return fmt.Errorf("security violation: auth.master_admin_key cannot be the default key in %q environment", env)
		}
		if c.Auth.MasterEncryptionKey == defaultMasterEncryptionKey {
			return fmt.Errorf("security violation: auth.master_encryption_key cannot be the default key in %q environment", env)
		}
		if c.Auth.JWTSecret == defaultJWTSecret {
			return fmt.Errorf("security violation: auth.jwt_secret cannot be the default secret in %q environment", env)
		}
	}
	if strings.TrimSpace(c.Auth.JWTSecret) != "" || strings.TrimSpace(c.Auth.OIDCJWKSURL) != "" {
		if strings.TrimSpace(c.Auth.JWTIssuer) == "" {
			return fmt.Errorf("auth.jwt_issuer is required when JWT or OIDC authentication is enabled")
		}
		if strings.TrimSpace(c.Auth.JWTAudience) == "" {
			return fmt.Errorf("auth.jwt_audience is required when JWT or OIDC authentication is enabled")
		}
	}
	seenIssuers := make(map[string]struct{}, len(c.Auth.OIDCIssuers))
	for i, iss := range c.Auth.OIDCIssuers {
		trimmedIss := strings.TrimSpace(iss.Issuer)
		if trimmedIss == "" {
			return fmt.Errorf("auth.oidc_issuers[%d].issuer is required", i)
		}
		if _, exists := seenIssuers[trimmedIss]; exists {
			return fmt.Errorf("duplicate auth.oidc_issuers[%d].issuer %q", i, trimmedIss)
		}
		seenIssuers[trimmedIss] = struct{}{}
		if strings.TrimSpace(iss.JWKSURL) == "" && strings.TrimSpace(iss.DiscoveryURL) == "" {
			u, err := url.Parse(trimmedIss)
			if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
				return fmt.Errorf("auth.oidc_issuers[%d] requires jwks_url, discovery_url, or an http(s) issuer URL", i)
			}
		}
		for _, alg := range iss.Algorithms {
			trimmedAlg := strings.TrimSpace(alg)
			if trimmedAlg == "" || strings.EqualFold(trimmedAlg, "none") {
				return fmt.Errorf("auth.oidc_issuers[%d].algorithms contains invalid algorithm %q", i, alg)
			}
		}
	}
	if ep := strings.TrimSpace(c.Auth.Introspection.TokenInfoEndpoint); ep != "" {
		u, err := url.Parse(ep)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("auth.introspection.token_info_endpoint must be a valid http or https URL")
		}
		switch strings.ToLower(strings.TrimSpace(c.Auth.Introspection.Mode)) {
		case "", "auto", "introspect", "userinfo":
		default:
			return fmt.Errorf("invalid auth.introspection.mode %q", c.Auth.Introspection.Mode)
		}
	}
	for _, cidr := range c.Auth.ProxyAuth.TrustedProxyCIDRs {
		if _, _, err := net.ParseCIDR(strings.TrimSpace(cidr)); err != nil {
			return fmt.Errorf("invalid auth.proxy_auth.trusted_proxy_cidrs %q: %w", cidr, err)
		}
	}
	for hdr, target := range c.Auth.ProxyAuth.HeaderMapping {
		if strings.TrimSpace(hdr) == "" {
			return fmt.Errorf("auth.proxy_auth.header_mapping must not contain empty header names")
		}
		switch strings.ToLower(strings.TrimSpace(target)) {
		case "user_id", "user_email", "team_id", "org_id":
		default:
			return fmt.Errorf("invalid auth.proxy_auth.header_mapping target %q for header %q", target, hdr)
		}
	}

	// Security SSRF validation
	for _, cidr := range c.Security.Network.OutboundSSRF.AllowedPrivateCIDRs {
		if _, _, err := net.ParseCIDR(strings.TrimSpace(cidr)); err != nil {
			return fmt.Errorf("invalid security.network.outbound_ssrf.allowed_private_cidrs %q: %w", cidr, err)
		}
	}
	for _, ipStr := range c.Security.Network.OutboundSSRF.BlockedIPs {
		if ip := net.ParseIP(strings.TrimSpace(ipStr)); ip == nil {
			return fmt.Errorf("invalid security.network.outbound_ssrf.blocked_ips %q: must be a valid IP address", ipStr)
		}
	}
	for _, cidr := range c.Security.Network.InboundCaller.AllowedClientCIDRs {
		if _, _, err := net.ParseCIDR(strings.TrimSpace(cidr)); err != nil {
			return fmt.Errorf("invalid security.network.inbound_caller.allowed_client_cidrs %q: %w", cidr, err)
		}
	}
	for _, cidr := range c.Security.Network.InboundCaller.TrustedProxyCIDRs {
		if _, _, err := net.ParseCIDR(strings.TrimSpace(cidr)); err != nil {
			return fmt.Errorf("invalid security.network.inbound_caller.trusted_proxy_cidrs %q: %w", cidr, err)
		}
	}

	// MCP validation
	if c.MCP.Enabled {
		if c.MCP.AllowStdioServers {
			// Fail-closed in Release 1 until BL-02 verified OS sandboxing lands
			return fmt.Errorf("mcp.allow_stdio_servers is not permitted in Release 1: OS-level sandboxing (BL-02) is required before enabling subprocess execution")
		}
		if c.MCP.MaxPayloadBytes <= 0 {
			c.MCP.MaxPayloadBytes = 10 * 1024 * 1024
		}
		if c.MCP.DefaultTimeout <= 0 {
			c.MCP.DefaultTimeout = 30 * time.Second
		}
		if c.MCP.CacheKeySecret == "" {
			c.MCP.CacheKeySecret = c.Auth.MasterEncryptionKey
		}
	}

	// A2A validation
	if c.A2A.Enabled {
		if !c.A2A.EnableJSONRPC && !c.A2A.EnableHTTPJSON {
			return fmt.Errorf("a2a must enable at least one transport binding (enable_jsonrpc or enable_http_json)")
		}
		for _, alg := range c.A2A.AllowedSigningAlgs {
			upperAlg := strings.ToUpper(strings.TrimSpace(alg))
			if upperAlg == "NONE" || strings.HasPrefix(upperAlg, "HS") {
				return fmt.Errorf("unsafe a2a.allowed_signing_algs %q: symmetric/none algorithms are forbidden for AgentCard JWS verification", alg)
			}
		}
		if strings.TrimSpace(c.A2A.SigningKeyID) == "" {
			c.A2A.SigningKeyID = "gw-a2a-signer-v1"
		}
		if c.A2A.StreamBufferCapacity <= 0 {
			c.A2A.StreamBufferCapacity = 256
		}
		if c.A2A.StreamPublishInterval <= 0 {
			c.A2A.StreamPublishInterval = 50 * time.Millisecond
		}
	}

	// Custom providers validation
	for _, cp := range c.Providers.CustomOpenAICompatible {
		id := strings.ToLower(strings.TrimSpace(cp.ID))
		if id == "" {
			return fmt.Errorf("providers.custom_openai_compatible: id cannot be empty")
		}
		if strings.TrimSpace(cp.BaseURL) == "" {
			return fmt.Errorf("providers.custom_openai_compatible %q: base_url cannot be empty", id)
		}
		u, err := url.Parse(strings.TrimSpace(cp.BaseURL))
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
			return fmt.Errorf("providers.custom_openai_compatible %q: base_url must have http or https scheme", id)
		}
		if rm := strings.TrimSpace(cp.ReasoningMapping); rm != "" {
			switch rm {
			case "passthrough", "openrouter_reasoning", "dashscope_thinking", "thinking_enabled", "chat_template_thinking", "strip":
			default:
				return fmt.Errorf("providers.custom_openai_compatible %q: unsupported reasoning_mapping %q", id, cp.ReasoningMapping)
			}
		}
	}

	// Guardrails external scanner validation
	seenScanners := make(map[string]struct{}, len(c.Guardrails.Scanners))
	for i, sc := range c.Guardrails.Scanners {
		name := strings.TrimSpace(sc.Name)
		if name == "" {
			return fmt.Errorf("guardrails.scanners[%d]: name cannot be empty", i)
		}
		if _, dup := seenScanners[name]; dup {
			return fmt.Errorf("guardrails.scanners[%d]: duplicate scanner name %q", i, name)
		}
		seenScanners[name] = struct{}{}

		rawURL := strings.TrimSpace(sc.URL)
		if rawURL == "" {
			return fmt.Errorf("guardrails.scanners %q: url cannot be empty", name)
		}
		u, err := url.Parse(rawURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("guardrails.scanners %q: url must be a valid http or https URL", name)
		}
		if sc.TimeoutMs < 0 {
			return fmt.Errorf("guardrails.scanners %q: timeout_ms cannot be negative", name)
		}
	}
	for idx, def := range c.Guardrails.Definitions {
		name := strings.TrimSpace(def.Name)
		if name == "" {
			return fmt.Errorf("guardrails.definitions[%d]: name cannot be empty", idx)
		}
		if strings.TrimSpace(def.Provider) == "" {
			return fmt.Errorf("guardrails.definitions[%d] (%q): provider cannot be empty", idx, name)
		}
		if def.TimeoutMs < 0 {
			return fmt.Errorf("guardrails.definitions[%d] (%q): timeout_ms cannot be negative", idx, name)
		}
		if def.Status != "" {
			switch strings.ToLower(strings.TrimSpace(def.Status)) {
			case "active", "pending_review", "rejected":
			default:
				return fmt.Errorf("guardrails.definitions[%d] (%q): invalid status %q", idx, name, def.Status)
			}
		}
	}
	for idx, tp := range c.Guardrails.ToolPolicies {
		toolName := strings.TrimSpace(tp.ToolName)
		if toolName == "" {
			return fmt.Errorf("guardrails.tool_policies[%d]: tool_name cannot be empty", idx)
		}
		switch strings.ToLower(strings.TrimSpace(tp.InputPolicy)) {
		case "", "untrusted", "trusted", "blocked":
		default:
			return fmt.Errorf("guardrails.tool_policies[%d] (%q): invalid input_policy %q", idx, toolName, tp.InputPolicy)
		}
		switch strings.ToLower(strings.TrimSpace(tp.OutputPolicy)) {
		case "", "untrusted", "trusted":
		default:
			return fmt.Errorf("guardrails.tool_policies[%d] (%q): invalid output_policy %q", idx, toolName, tp.OutputPolicy)
		}
	}

	return nil
}

// ResolveEnvValue resolves environment variable references such as:
//   - "os.environ/GEMINI_API_KEY" -> os.Getenv("GEMINI_API_KEY")
//   - "${GEMINI_API_KEY}"         -> os.Getenv("GEMINI_API_KEY")
//   - "$GEMINI_API_KEY"          -> os.Getenv("GEMINI_API_KEY")
//
// Literal values are returned unchanged.
func ResolveEnvValue(val string) string {
	v := strings.TrimSpace(val)
	if v == "" {
		return ""
	}
	if strings.HasPrefix(v, "os.environ/") {
		envKey := strings.TrimSpace(strings.TrimPrefix(v, "os.environ/"))
		return strings.TrimSpace(os.Getenv(envKey))
	}
	if strings.HasPrefix(v, "${") && strings.HasSuffix(v, "}") && len(v) > 3 {
		envKey := strings.TrimSpace(v[2 : len(v)-1])
		return strings.TrimSpace(os.Getenv(envKey))
	}
	if strings.HasPrefix(v, "$") && len(v) > 1 && !strings.Contains(v, " ") {
		envKey := strings.TrimSpace(v[1:])
		return strings.TrimSpace(os.Getenv(envKey))
	}
	return v
}

// NormalizeProvider normalizes any vendor alias or provider identifier string into GoRoute's canonical ProviderType.
func NormalizeProvider(raw string) domain.ProviderType {
	lower := strings.ToLower(strings.TrimSpace(raw))
	switch {
	case lower == "gemini" || lower == "google" || lower == "google_ai_studio":
		return domain.ProviderGemini
	case lower == "vertex_ai" || lower == "vertex" || strings.HasPrefix(lower, "vertex_ai-") || strings.HasPrefix(lower, "vertex-"):
		return domain.ProviderVertex
	case lower == "anthropic" || lower == "claude":
		return domain.ProviderAnthropic
	case lower == "openai" || lower == "chatgpt" || lower == "text-completion-openai":
		return domain.ProviderOpenAI
	case lower == "azure" || lower == "azure_ai" || lower == "azure_text" || lower == "azure_openai":
		return domain.ProviderAzure
	case lower == "bedrock" || lower == "bedrock_converse" || lower == "bedrock_mantle" || lower == "amazon_nova" || lower == "amazon-nova":
		return domain.ProviderBedrock
	case lower == "cohere" || lower == "cohere_chat":
		return domain.ProviderCohere
	case lower == "mistral" || lower == "mistralai" || lower == "codestral" || lower == "text-completion-codestral":
		return domain.ProviderMistral
	case lower == "ollama" || lower == "ollama_chat":
		return domain.ProviderOllama
	case lower == "together" || lower == "together_ai":
		return domain.ProviderTogether
	case lower == "fireworks" || lower == "fireworks_ai" || strings.HasPrefix(lower, "fireworks_ai-"):
		return domain.ProviderFireworks
	case lower == "groq":
		return domain.ProviderGroq
	case lower == "deepseek":
		return domain.ProviderDeepSeek
	case lower == "cerebras":
		return domain.ProviderCerebras
	case lower == "sambanova":
		return domain.ProviderSambaNova
	case lower == "xai":
		return domain.ProviderXAI
	case lower == "perplexity":
		return domain.ProviderPerplexity
	case lower == "anyscale":
		return domain.ProviderAnyscale
	case lower == "deepinfra":
		return domain.ProviderDeepInfra
	case lower == "novita":
		return domain.ProviderNovita
	case lower == "nebius":
		return domain.ProviderNebius
	case lower == "hyperbolic":
		return domain.ProviderHyperbolic
	case lower == "lambda" || lower == "lambda_ai":
		return domain.ProviderLambda
	case lower == "friendli" || lower == "friendliai":
		return domain.ProviderFriendli
	case lower == "openrouter":
		return domain.ProviderOpenRouter
	case lower == "vllm":
		return domain.ProviderVLLM
	case lower == "cloudflare" || lower == "clf_ai_gateway":
		return domain.ProviderCloudflare
	case lower == "databricks":
		return domain.ProviderDatabricks
	case lower == "snowflake":
		return domain.ProviderSnowflake
	case lower == "dashscope" || lower == "qwen_ai_platform" || lower == "qwencloud":
		return domain.ProviderDashScope
	case lower == "volcengine":
		return domain.ProviderVolcengine
	case lower == "bigmodel" || lower == "zhipu":
		return domain.ProviderBigModel
	case lower == "moonshot":
		return domain.ProviderMoonshot
	case lower == "minimax":
		return domain.ProviderMiniMax
	case lower == "siliconflow":
		return domain.ProviderSiliconFlow
	case lower == "voyage":
		return domain.ProviderVoyage
	case lower == "jina" || lower == "jina_ai":
		return domain.ProviderJina
	case lower == "replicate":
		return domain.ProviderReplicate
	case lower == "ai21":
		return domain.ProviderAI21
	case lower == "baseten":
		return domain.ProviderBaseten
	case lower == "nvidia" || lower == "nvidia_nim" || lower == "nim":
		return domain.ProviderNvidia
	case lower == "scaleway":
		return domain.ProviderScaleway
	case lower == "github_copilot" || lower == "copilot":
		return domain.ProviderGitHubCopilot
	case lower == "vercel_ai_gateway" || lower == "vercel":
		return domain.ProviderVercelAIGateway
	case lower == "huggingface" || lower == "hf":
		return domain.ProviderHuggingFace
	case lower == "featherless" || lower == "featherless_ai":
		return domain.ProviderFeatherless
	case lower == "fal" || lower == "fal_ai":
		return domain.ProviderFal
	case lower == "zai" || lower == "z_ai":
		return domain.ProviderZAI
	case lower == "poe":
		return domain.ProviderPoe
	case lower == "helicone":
		return domain.ProviderHelicone
	case lower == "aihubmix":
		return domain.ProviderAIHubMix
	case lower == "venice" || lower == "veniceai":
		return domain.ProviderVenice
	case lower == "chutes":
		return domain.ProviderChutes
	case lower == "gmi":
		return domain.ProviderGMI
	case lower == "llamagate":
		return domain.ProviderLlamaGate
	case lower == "sarvam":
		return domain.ProviderSarvam
	case lower == "crusoe":
		return domain.ProviderCrusoe
	case lower == "parasail":
		return domain.ProviderParasail
	case lower == "upstage":
		return domain.ProviderUpstage
	case lower == "ovhcloud":
		return domain.ProviderOVHCloud
	case lower == "wandb":
		return domain.ProviderWandB
	case lower == "nscale":
		return domain.ProviderNscale
	case lower == "publicai":
		return domain.ProviderPublicAI
	case lower == "synthetic":
		return domain.ProviderSynthetic
	case lower == "nano_gpt" || lower == "nano-gpt":
		return domain.ProviderNanoGPT
	case lower == "xiaomi_mimo":
		return domain.ProviderXiaomiMiMo
	case lower == "reka":
		return domain.ProviderReka
	case lower == "yi" || lower == "01ai":
		return domain.ProviderYi
	case lower == "baichuan":
		return domain.ProviderBaichuan
	case lower == "stepfun":
		return domain.ProviderStepFun
	case lower == "lm_studio" || lower == "lmstudio":
		return domain.ProviderLMStudio
	case lower == "llamafile":
		return domain.ProviderLlamafile
	case lower == "xinference":
		return domain.ProviderXinference
	default:
		return domain.ProviderType(lower)
	}
}

// IsKnownProviderAlias reports whether raw matches a known canonical provider or alias.
func IsKnownProviderAlias(raw string) bool {
	lower := strings.ToLower(strings.TrimSpace(raw))
	if lower == "" {
		return false
	}
	norm := NormalizeProvider(lower)
	for _, p := range domain.AllProviders() {
		if norm == p {
			return true
		}
	}
	return false
}

// ParseProviderModel parses a model string (e.g. "gemini/gemini-2.5-flash",
// "vertex_ai/gemini-1.5-pro", or "gemini-2.5-flash") into (ProviderType, bareModelName, canonicalGlobalModelID).
func ParseProviderModel(modelSpec string) (domain.ProviderType, string, string) {
	spec := strings.TrimSpace(modelSpec)
	if spec == "" {
		return "", "", ""
	}
	if idx := strings.IndexByte(spec, '/'); idx > 0 {
		rawProv := strings.TrimSpace(spec[:idx])
		bareModel := strings.TrimSpace(spec[idx+1:])
		prov := NormalizeProvider(rawProv)
		return prov, bareModel, fmt.Sprintf("%s/%s", prov, bareModel)
	}

	lower := strings.ToLower(spec)
	switch {
	case strings.HasPrefix(lower, "gemini") || strings.HasPrefix(lower, "text-embedding-004"):
		return domain.ProviderGemini, spec, fmt.Sprintf("%s/%s", domain.ProviderGemini, spec)
	case strings.HasPrefix(lower, "claude"):
		return domain.ProviderAnthropic, spec, fmt.Sprintf("%s/%s", domain.ProviderAnthropic, spec)
	case strings.HasPrefix(lower, "gpt-") || strings.HasPrefix(lower, "o1") || strings.HasPrefix(lower, "o3") || strings.HasPrefix(lower, "o4") || strings.HasPrefix(lower, "text-embedding-3"):
		return domain.ProviderOpenAI, spec, fmt.Sprintf("%s/%s", domain.ProviderOpenAI, spec)
	case strings.HasPrefix(lower, "mistral") || strings.HasPrefix(lower, "codestral") || strings.HasPrefix(lower, "pixtral"):
		return domain.ProviderMistral, spec, fmt.Sprintf("%s/%s", domain.ProviderMistral, spec)
	case strings.HasPrefix(lower, "command"):
		return domain.ProviderCohere, spec, fmt.Sprintf("%s/%s", domain.ProviderCohere, spec)
	case strings.HasPrefix(lower, "llama") || strings.HasPrefix(lower, "qwen") || strings.HasPrefix(lower, "deepseek"):
		return domain.ProviderOllama, spec, fmt.Sprintf("%s/%s", domain.ProviderOllama, spec)
	default:
		return "", spec, spec
	}
}
