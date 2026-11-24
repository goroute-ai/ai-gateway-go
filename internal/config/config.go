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
	Audit      AuditConfig      `yaml:"audit,omitempty"`
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
	AllowLoopbackHTTP    bool          `yaml:"allow_loopback_http"`    // default false (permits http:// strictly to 127.0.0.0/8, ::1, localhost)
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

// MCPConfig defines parameters for Model Context Protocol across all UI-selectable releases.
type MCPConfig struct {
	Enabled                   bool          `yaml:"enabled"`
	DefaultProtocolVersion    string        `yaml:"default_protocol_version"`    // default "2026-07-28"
	StrictSchemaValidation    bool          `yaml:"strict_schema_validation"`    // validate incoming JSON-RPC payloads against active schema.yaml
	AllowStdioServers         bool          `yaml:"allow_stdio_servers"`         // default false; stdio disabled unless explicitly enabled
	AllowedStdioBinaries      []string      `yaml:"allowed_stdio_binaries"`      // canonical path allowlist
	EnableSessionCompat2025   bool          `yaml:"enable_session_compat_2025"`  // enables stateful Streamable HTTP upstream sessions (2025-*)
	SessionTTL2025            time.Duration `yaml:"session_ttl_2025"`            // session TTL for stateful Streamable HTTP (default 15m)
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

// TracingConfig configures OpenTelemetry OTLP trace export.
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
	SaturationFallbacks    []domain.FallbackTarget `yaml:"saturation_fallbacks,omitempty" json:"saturation_fallbacks,omitempty"`
	DropUnsupportedParams  bool                    `yaml:"drop_unsupported_params,omitempty" json:"drop_unsupported_params,omitempty"`
	DisableCooldowns       bool                    `yaml:"disable_cooldowns,omitempty" json:"disable_cooldowns,omitempty"`
}

// ModelParams holds upstream provider and model routing parameters for a deployment entry.
type ModelParams struct {
	Model               string            `yaml:"model" json:"model"`       // e.g. "openai/gpt-4o-mini" or "anthropic/claude-haiku-4-5-20251001"
	APIKey              string            `yaml:"api_key" json:"api_key"`   // literal key or "os.environ/OPENAI_API_KEY" or "${OPENAI_API_KEY}"
	APIBase             string            `yaml:"api_base" json:"api_base"` // optional custom upstream base URL
	Region              string            `yaml:"region,omitempty" json:"region,omitempty"`
	Weight              int               `yaml:"weight,omitempty" json:"weight,omitempty"`
	RPM                 int               `yaml:"rpm,omitempty" json:"rpm,omitempty"`
	TPM                 int               `yaml:"tpm,omitempty" json:"tpm,omitempty"`
	ITPM                int               `yaml:"itpm,omitempty" json:"itpm,omitempty"`
	OTPM                int               `yaml:"otpm,omitempty" json:"otpm,omitempty"`
	MaxParallelRequests int               `yaml:"max_parallel_requests,omitempty" json:"max_parallel_requests,omitempty"`
	Priority            int               `yaml:"priority,omitempty" json:"priority,omitempty"`
	Tags                []string          `yaml:"tags,omitempty" json:"tags,omitempty"`
	MaxBudgetMicros     int64             `yaml:"max_budget_micros,omitempty" json:"max_budget_micros,omitempty"`
	BudgetResetPeriod   string            `yaml:"budget_reset_period,omitempty" json:"budget_reset_period,omitempty"`
	Headers             map[string]string `yaml:"headers,omitempty" json:"headers,omitempty"`
}

// ProvidersConfig configures upstream HTTP client timeouts and connection pooling.
type ProvidersConfig struct {
	RequestTimeout        time.Duration `yaml:"request_timeout" json:"request_timeout"`
	ResponseHeaderTimeout time.Duration `yaml:"response_header_timeout" json:"response_header_timeout"`
	StreamIdleTimeout     time.Duration `yaml:"stream_idle_timeout" json:"stream_idle_timeout"`
	MaxIdleConns          int           `yaml:"max_idle_conns" json:"max_idle_conns"`
	MaxIdleConnsPerHost   int           `yaml:"max_idle_conns_per_host" json:"max_idle_conns_per_host"`
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

// ServerConfig configures HTTP/gRPC listeners, timeouts, CORS, HSTS, and per-organization file upload limits.
type ServerConfig struct {
	Environment               string        `yaml:"environment"`     // "development", "staging", "production"
	PublicBaseURL             string        `yaml:"public_base_url"` // Canonical external origin (e.g. "https://gateway.example.com") for SSO/CLI URLs
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

// RDSIAMConfig configures AWS RDS IAM database authentication (ambient cloud IAM remains opt-in).
type RDSIAMConfig struct {
	Enabled         bool   `yaml:"enabled"`
	Region          string `yaml:"region"`
	AccessKeyID     string `yaml:"access_key_id,omitempty"`
	SecretAccessKey string `yaml:"secret_access_key,omitempty"`
	SessionToken    string `yaml:"session_token,omitempty"`
	RoleARN         string `yaml:"role_arn,omitempty"`
	WebIdentityFile string `yaml:"web_identity_token_file,omitempty"`
}

// StorageConfig configures the primary metadata repository (memory or postgres) and Redis state fabric.
type StorageConfig struct {
	Mode            string       `yaml:"mode"` // "memory" or "postgres"
	PostgresDSN     string       `yaml:"postgres_dsn"`
	RDSIAM          RDSIAMConfig `yaml:"rds_iam,omitempty"`
	RedisAddr       string       `yaml:"redis_addr"`
	RedisAddrs      []string     `yaml:"redis_addrs"`
	RedisMasterName string       `yaml:"redis_master_name"`
	RedisPass       string       `yaml:"redis_pass"`
	RedisDB         int          `yaml:"redis_db"`
}

// OIDCClaimMapping maps custom JWT claim paths to GoRoute identity fields.
type OIDCClaimMapping struct {
	UserID  string `yaml:"user_id,omitempty"`
	Email   string `yaml:"email,omitempty"`
	OrgID   string `yaml:"org_id,omitempty"`
	TeamIDs string `yaml:"team_ids,omitempty"`
	Role    string `yaml:"role,omitempty"`
	Groups  string `yaml:"groups,omitempty"`
	EndUser string `yaml:"end_user,omitempty"`
}

// GroupRoleMappingRule maps an IdP group or realm-role value to a GoRoute role.
type GroupRoleMappingRule struct {
	Group string `yaml:"group" json:"group"`
	Role  string `yaml:"role" json:"role"`
}

// OIDCIssuerConfig configures a single OIDC/JWT issuer for multi-issuer verification.
type OIDCIssuerConfig struct {
	Issuer                    string                 `yaml:"issuer"`
	Audience                  string                 `yaml:"audience,omitempty"`
	JWKSURL                   string                 `yaml:"jwks_url,omitempty"`
	DiscoveryURL              string                 `yaml:"discovery_url,omitempty"`
	Algorithms                []string               `yaml:"algorithms,omitempty"`
	AllowedEmailDomains       []string               `yaml:"allowed_email_domains,omitempty"`
	AllowUnverifiedEmail      bool                   `yaml:"allow_unverified_email,omitempty"`
	AllowPrivilegedRoleClaims bool                   `yaml:"allow_privileged_role_claims,omitempty"`
	ClaimMapping              OIDCClaimMapping       `yaml:"claim_mapping,omitempty"`
	GroupRoleMappings         []GroupRoleMappingRule `yaml:"group_role_mappings,omitempty"`
	RoleMappingStrategy       string                 `yaml:"role_mapping_strategy,omitempty"`
	GroupTeamMappings         map[string]string      `yaml:"group_team_mappings,omitempty"`
	AutoRegister              bool                   `yaml:"auto_register,omitempty"`
	DefaultOrgID              string                 `yaml:"default_org_id,omitempty"`
	DefaultTeamID             string                 `yaml:"default_team_id,omitempty"`
	DefaultRole               string                 `yaml:"default_role,omitempty"`
}

// IntrospectionConfig configures OAuth 2.0 RFC 7662 token introspection or OIDC UserInfo verification.
type IntrospectionConfig struct {
	TokenInfoEndpoint         string        `yaml:"token_info_endpoint,omitempty"`
	Issuer                    string        `yaml:"issuer,omitempty"`
	Audience                  string        `yaml:"audience,omitempty"`
	DiscoveryURL              string        `yaml:"discovery_url,omitempty"`
	ClientID                  string        `yaml:"client_id,omitempty"`
	ClientSecret              string        `yaml:"client_secret,omitempty"`
	Mode                      string        `yaml:"mode,omitempty"`
	UserIDField               string        `yaml:"user_id_field,omitempty"`
	EmailField                string        `yaml:"email_field,omitempty"`
	RoleField                 string        `yaml:"role_field,omitempty"`
	OrgIDField                string        `yaml:"org_id_field,omitempty"`
	TeamIDField               string        `yaml:"team_id_field,omitempty"`
	CacheTTL                  time.Duration `yaml:"cache_ttl,omitempty"`
	AutoRegister              bool          `yaml:"auto_register,omitempty"`
	AllowUnverifiedEmail      bool          `yaml:"allow_unverified_email,omitempty"`
	AllowPrivilegedRoleClaims bool          `yaml:"allow_privileged_role_claims,omitempty"`
	DefaultTeamID             string        `yaml:"default_team_id,omitempty"`
	DefaultRole               string        `yaml:"default_role,omitempty"`
}

// SSOProviderConfig configures an interactive OIDC SSO identity provider for Control Plane and CLI login.
type SSOProviderConfig struct {
	ID                        string                 `yaml:"id,omitempty"`
	Name                      string                 `yaml:"name,omitempty"`
	Type                      string                 `yaml:"type,omitempty"`
	DisplayName               string                 `yaml:"display_name,omitempty"`
	ClientID                  string                 `yaml:"client_id"`
	ClientSecret              string                 `yaml:"client_secret,omitempty"`
	Issuer                    string                 `yaml:"issuer,omitempty"`
	AuthorizationEndpoint     string                 `yaml:"authorization_endpoint,omitempty"`
	TokenEndpoint             string                 `yaml:"token_endpoint,omitempty"`
	JWKSURL                   string                 `yaml:"jwks_url,omitempty"`
	DiscoveryURL              string                 `yaml:"discovery_url,omitempty"`
	Scopes                    []string               `yaml:"scopes,omitempty"`
	RedirectURL               string                 `yaml:"redirect_url,omitempty"`
	AllowedEmailDomains       []string               `yaml:"allowed_email_domains,omitempty"`
	AllowUnverifiedEmail      bool                   `yaml:"allow_unverified_email,omitempty"`
	AllowPrivilegedRoleClaims bool                   `yaml:"allow_privileged_role_claims,omitempty"`
	AutoRegister              bool                   `yaml:"auto_register,omitempty"`
	DefaultOrgID              string                 `yaml:"default_org_id,omitempty"`
	DefaultTeamID             string                 `yaml:"default_team_id,omitempty"`
	DefaultRole               string                 `yaml:"default_role,omitempty"`
	Algorithms                []string               `yaml:"algorithms,omitempty"`
	ClaimMapping              OIDCClaimMapping       `yaml:"claim_mapping,omitempty"`
	GroupRoleMappings         []GroupRoleMappingRule `yaml:"group_role_mappings,omitempty"`
	RoleMappingStrategy       string                 `yaml:"role_mapping_strategy,omitempty"`
	GroupTeamMappings         map[string]string      `yaml:"group_team_mappings,omitempty"`
	SyncRolesOnLogin          bool                   `yaml:"sync_roles_on_login,omitempty"`
}

// ExternalAuthorizerConfig configures an optional standalone HTTP Webhook or OPA REST API policy authorizer.
type ExternalAuthorizerConfig struct {
	Enabled    bool          `yaml:"enabled,omitempty"`
	Mode       string        `yaml:"mode,omitempty"`        // "webhook" (default) or "opa"
	URL        string        `yaml:"url,omitempty"`         // HTTPS endpoint (SSRF-validated via network.Policy)
	Timeout    time.Duration `yaml:"timeout,omitempty"`     // Default 500ms, max 5s
	FailMode   string        `yaml:"fail_mode,omitempty"`   // "closed" (default) or "open"
	CacheTTL   time.Duration `yaml:"cache_ttl,omitempty"`   // Optional short-lived L1 decision cache TTL
	AuthHeader string        `yaml:"auth_header,omitempty"` // Optional Authorization header (supports os.environ/...)
	HMACSecret string        `yaml:"hmac_secret,omitempty"` // Optional secret for X-GoRoute-Signature-256 (supports os.environ/...)
}

// AuditConfig configures administrative audit logging and optional SIEM export.
type AuditConfig struct {
	SIEMWebhook AuditSIEMWebhookConfig `yaml:"siem_webhook,omitempty"`
}

// AuditSIEMWebhookConfig configures async batched SIEM webhook delivery for audit records.
type AuditSIEMWebhookConfig struct {
	Enabled       bool          `yaml:"enabled,omitempty"`
	URL           string        `yaml:"url,omitempty"`
	Secret        string        `yaml:"secret,omitempty"`      // Optional HMAC-SHA256 signing secret
	AuthHeader    string        `yaml:"auth_header,omitempty"` // Optional Authorization header
	BatchSize     int           `yaml:"batch_size,omitempty"`
	FlushInterval time.Duration `yaml:"flush_interval,omitempty"`
	Timeout       time.Duration `yaml:"timeout,omitempty"`
	MaxQueueSize  int           `yaml:"max_queue_size,omitempty"`
}

// KeyRotationSinkConfig configures declarative external secret-manager synchronization
// for automated virtual key rotations.
type KeyRotationSinkConfig struct {
	Driver     string `yaml:"driver,omitempty"`      // "", "webhook", "vault_kv2"
	Address    string `yaml:"address,omitempty"`     // HTTPS endpoint for Webhook or Vault KV v2
	Mount      string `yaml:"mount,omitempty"`       // Vault KV v2 mount name (default "secret")
	PathPrefix string `yaml:"path_prefix,omitempty"` // Secret path prefix (default "goroute/virtual-keys")
	Token      string `yaml:"token,omitempty"`       // Vault/Webhook token (supports os.environ/...)
	Namespace  string `yaml:"namespace,omitempty"`   // Optional Vault namespace header
}

// AuthConfig configures virtual-key, OIDC/JWKS, SSO, introspection, and key rotation.
type AuthConfig struct {
	AllowAmbientCloudIAM         bool                     `yaml:"allow_ambient_cloud_iam,omitempty"`
	MasterAdminKey               string                   `yaml:"master_admin_key"`
	MasterEncryptionKey          string                   `yaml:"master_encryption_key"` // 32-byte hex or raw string for AES-256-GCM KEK
	PreviousMasterEncryptionKeys []string                 `yaml:"previous_master_encryption_keys,omitempty"`
	AllowMasterKeyDataPlane      bool                     `yaml:"allow_master_key_data_plane"`
	EnableDataPlaneJWT           bool                     `yaml:"enable_data_plane_jwt"`
	CustomAPIKeyHeader           string                   `yaml:"custom_api_key_header"`
	RequireClientAppHeader       bool                     `yaml:"require_client_app_header,omitempty"`
	AllowViewerControlPlaneRead  bool                     `yaml:"allow_viewer_control_plane_read,omitempty"`
	JWTIssuer                    string                   `yaml:"jwt_issuer"`
	JWTAudience                  string                   `yaml:"jwt_audience"`
	OIDCJWKSURL                  string                   `yaml:"oidc_jwks_url"`
	OIDCIssuers                  []OIDCIssuerConfig       `yaml:"oidc_issuers,omitempty"`
	SSOProviders                 []SSOProviderConfig      `yaml:"sso_providers,omitempty"`
	Introspection                IntrospectionConfig      `yaml:"introspection,omitempty"`
	DefaultOrgID                 string                   `yaml:"default_org_id"`
	DefaultVirtualKey            string                   `yaml:"default_virtual_key"`
	L1CacheTTL                   time.Duration            `yaml:"l1_cache_ttl"`
	L2CacheTTL                   time.Duration            `yaml:"l2_cache_ttl"`
	KeyRotationDeliveryURL       string                   `yaml:"key_rotation_delivery_url,omitempty"`
	KeyRotationDeliveryToken     string                   `yaml:"key_rotation_delivery_token,omitempty"`
	KeyRotationSink              KeyRotationSinkConfig    `yaml:"key_rotation_sink,omitempty"`
	KeyRotationPollInterval      time.Duration            `yaml:"key_rotation_poll_interval,omitempty"`
	KeyRotationGracePeriod       time.Duration            `yaml:"key_rotation_grace_period,omitempty"`
	KeyExpiryAlertPollInterval   time.Duration            `yaml:"key_expiry_alert_poll_interval,omitempty"`
	SessionSecret                string                   `yaml:"session_secret,omitempty"`
	SessionTTL                   time.Duration            `yaml:"session_ttl,omitempty"`
	CLILoginDefaultTTL           time.Duration            `yaml:"cli_login_default_ttl,omitempty"`
	CLILoginMaxTTL               time.Duration            `yaml:"cli_login_max_ttl,omitempty"`
	AuthStartRateLimitPerMin     int                      `yaml:"auth_start_rate_limit_per_min,omitempty"`
	ExternalAuthorizer           ExternalAuthorizerConfig `yaml:"external_authorizer,omitempty"`
}

// RouterConfig configures intelligent model routing, retries, cooldowns, fallbacks, hedging, and scheduling.
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
	PriorityCapacity               PriorityCapacityConfig  `yaml:"priority_capacity,omitempty" json:"priority_capacity,omitempty"`
	LatencyTolerancePct            float64                 `yaml:"latency_tolerance_pct,omitempty" json:"latency_tolerance_pct,omitempty"`
	MaxHonoredRetryAfter           time.Duration           `yaml:"max_honored_retry_after,omitempty" json:"max_honored_retry_after,omitempty"`
	DisableCooldowns               bool                    `yaml:"disable_cooldowns,omitempty" json:"disable_cooldowns,omitempty"`
	FallbackOnSaturation           bool                    `yaml:"fallback_on_saturation,omitempty" json:"fallback_on_saturation,omitempty"`
	DropUnsupportedParams          bool                    `yaml:"drop_unsupported_params,omitempty" json:"drop_unsupported_params,omitempty"`
	FallbackOnUnsupportedParams    bool                    `yaml:"fallback_on_unsupported_params,omitempty" json:"fallback_on_unsupported_params,omitempty"`
	AllowStrategyOverride          bool                    `yaml:"allow_strategy_override,omitempty" json:"allow_strategy_override,omitempty"`
	DebugRoutingHeaders            bool                    `yaml:"debug_routing_headers,omitempty" json:"debug_routing_headers,omitempty"`
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
	Enabled           bool          `yaml:"enabled" json:"enabled"`
	MaxQueueDepth     int           `yaml:"max_queue_depth,omitempty" json:"max_queue_depth,omitempty"`
	MaxWaitTime       time.Duration `yaml:"max_wait_time,omitempty" json:"max_wait_time,omitempty"`
	DefaultPriority   int           `yaml:"default_priority,omitempty" json:"default_priority,omitempty"`
	MaxParallelWaitMs int           `yaml:"max_parallel_wait_ms,omitempty" json:"max_parallel_wait_ms,omitempty"`
}

// PriorityCapacityConfig configures saturation-aware dynamic priority capacity sharing.
type PriorityCapacityConfig struct {
	Enabled               bool          `yaml:"enabled" json:"enabled"`
	SaturationThreshold   float64       `yaml:"saturation_threshold,omitempty" json:"saturation_threshold,omitempty"`
	ActiveCallerTTL       time.Duration `yaml:"active_caller_ttl,omitempty" json:"active_caller_ttl,omitempty"`
	WindowDuration        time.Duration `yaml:"window_duration,omitempty" json:"window_duration,omitempty"`
	DefaultWeight         float64       `yaml:"default_weight,omitempty" json:"default_weight,omitempty"`
	DefaultBorrowMultiple float64       `yaml:"default_borrow_multiple,omitempty" json:"default_borrow_multiple,omitempty"`
}

// RateLimitConfig configures Redis-backed RPM/TPM/concurrency rate limiting and agent session defaults.
type RateLimitConfig struct {
	Enabled                            bool          `yaml:"enabled" json:"enabled"`
	FallbackToLocalOnOutage            bool          `yaml:"fallback_to_local_on_outage" json:"fallback_to_local_on_outage"`
	WindowSeconds                      int           `yaml:"window_seconds" json:"window_seconds"`
	ConcurrencyTTLSec                  int           `yaml:"concurrency_ttl_sec" json:"concurrency_ttl_sec"`
	DefaultEstimatedTPM                int           `yaml:"default_estimated_tpm" json:"default_estimated_tpm"`
	RedisTimeout                       time.Duration `yaml:"redis_timeout" json:"redis_timeout"`
	GlobalRPMLimit                     int           `yaml:"global_rpm_limit" json:"global_rpm_limit"`
	GlobalTPMLimit                     int           `yaml:"global_tpm_limit" json:"global_tpm_limit"`
	GlobalMaxConcurrent                int           `yaml:"global_max_concurrent" json:"global_max_concurrent"`
	DefaultAgentSessionMaxIterations   int           `yaml:"default_agent_session_max_iterations" json:"default_agent_session_max_iterations"`
	DefaultAgentSessionMaxBudgetMicros int64         `yaml:"default_agent_session_max_budget_micros" json:"default_agent_session_max_budget_micros"`
	DefaultAgentSessionTTLSec          int           `yaml:"default_agent_session_ttl_sec" json:"default_agent_session_ttl_sec"`
	DynamicOnUpstream429               bool          `yaml:"dynamic_on_upstream_429" json:"dynamic_on_upstream_429"`
}

// FinOpsConfig configures asynchronous spend-outbox batching and soft-budget webhook notifications.
type FinOpsConfig struct {
	ChannelBufferSize         int           `yaml:"channel_buffer_size"`
	BatchSize                 int           `yaml:"batch_size"`
	FlushInterval             time.Duration `yaml:"flush_interval"`
	WorkerCount               int           `yaml:"worker_count"`
	SoftBudgetWebhookURL      string        `yaml:"soft_budget_webhook_url,omitempty"`
	SoftBudgetCooldownSec     int           `yaml:"soft_budget_cooldown_sec,omitempty"`
	BudgetExceededThrottlePct float64       `yaml:"budget_exceeded_throttle_pct,omitempty"`
}

// DiscoveryConfig configures background model lifecycle and pricing discovery polling.
type DiscoveryConfig struct {
	Enabled      bool          `yaml:"enabled"`
	SyncInterval time.Duration `yaml:"sync_interval"`
	AutoApprove  bool          `yaml:"auto_approve"`
}

// CacheConfig configures exact-match L1/L2 response caching defaults.
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
			LatencyTolerancePct:            0.10,
			MaxHonoredRetryAfter:           60 * time.Second,
			PriorityCapacity: PriorityCapacityConfig{
				SaturationThreshold:   0.80,
				ActiveCallerTTL:       60 * time.Second,
				WindowDuration:        60 * time.Second,
				DefaultWeight:         1.0,
				DefaultBorrowMultiple: 2.0,
			},
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
			DefaultProtocolVersion:    domain.MCPProtocolVersion20260728,
			StrictSchemaValidation:    false,
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

func envStr(key string, dst *string) {
	if v := os.Getenv(key); v != "" {
		*dst = v
	}
}

func envTrimStr(key string, dst *string) {
	if v := os.Getenv(key); v != "" {
		*dst = strings.TrimSpace(v)
	}
}

func envInt(key string, dst *int) {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			*dst = n
		}
	}
}

func envInt64(key string, dst *int64) {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil {
			*dst = n
		}
	}
}

func envFloat(key string, dst *float64) {
	if v := os.Getenv(key); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			*dst = f
		}
	}
}

func envBool(key string, dst *bool) {
	if v := os.Getenv(key); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			*dst = b
		}
	}
}

func envDuration(key string, dst *time.Duration) {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			*dst = d
		}
	}
}

func splitTrimCSV(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if trimmed := strings.TrimSpace(p); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
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

	cfg.applyServerAndStorageEnvOverrides()
	cfg.applyAuthEnvOverrides()
	cfg.applyRouterEnvOverrides()
	cfg.applyFinOpsAndProtocolEnvOverrides()
	cfg.resolveSecretEnvValues()

	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) resolveSecretEnvValues() {
	c.Storage.PostgresDSN = ResolveEnvValue(c.Storage.PostgresDSN)
	c.Storage.RedisPass = ResolveEnvValue(c.Storage.RedisPass)
	c.Auth.MasterAdminKey = ResolveEnvValue(c.Auth.MasterAdminKey)
	c.Auth.MasterEncryptionKey = ResolveEnvValue(c.Auth.MasterEncryptionKey)
	for i := range c.Auth.PreviousMasterEncryptionKeys {
		c.Auth.PreviousMasterEncryptionKeys[i] = ResolveEnvValue(c.Auth.PreviousMasterEncryptionKeys[i])
	}
	c.Auth.SessionSecret = ResolveEnvValue(c.Auth.SessionSecret)
	c.Auth.DefaultVirtualKey = ResolveEnvValue(c.Auth.DefaultVirtualKey)
	c.Auth.KeyRotationDeliveryURL = ResolveEnvValue(c.Auth.KeyRotationDeliveryURL)
	c.Auth.KeyRotationDeliveryToken = ResolveEnvValue(c.Auth.KeyRotationDeliveryToken)
	c.Auth.KeyRotationSink.Address = ResolveEnvValue(c.Auth.KeyRotationSink.Address)
	c.Auth.KeyRotationSink.Token = ResolveEnvValue(c.Auth.KeyRotationSink.Token)
	c.Auth.Introspection.ClientID = ResolveEnvValue(c.Auth.Introspection.ClientID)
	c.Auth.Introspection.ClientSecret = ResolveEnvValue(c.Auth.Introspection.ClientSecret)
	for i := range c.Auth.SSOProviders {
		c.Auth.SSOProviders[i].ClientID = ResolveEnvValue(c.Auth.SSOProviders[i].ClientID)
		c.Auth.SSOProviders[i].ClientSecret = ResolveEnvValue(c.Auth.SSOProviders[i].ClientSecret)
	}
}

func isUnresolvedEnvReference(raw string) bool {
	v := strings.TrimSpace(raw)
	if v == "" {
		return false
	}
	if strings.HasPrefix(v, "os.environ/") {
		return true
	}
	if strings.HasPrefix(v, "${") && strings.HasSuffix(v, "}") && len(v) > 3 {
		return true
	}
	return false
}

func (c *Config) applyServerAndStorageEnvOverrides() {
	envInt("GATEWAY_PORT", &c.Server.Port)
	envInt("GATEWAY_GRPC_PORT", &c.Server.GRPCPort)
	envTrimStr("GATEWAY_PUBLIC_BASE_URL", &c.Server.PublicBaseURL)
	if v := os.Getenv("GATEWAY_CORS_ALLOWED_ORIGINS"); v != "" {
		if origins := splitTrimCSV(v); len(origins) > 0 {
			c.Server.CORSAllowedOrigins = origins
		}
	}
	envBool("GATEWAY_ENABLE_HSTS", &c.Server.EnableHSTS)
	envInt64("GATEWAY_MAX_FILE_STORAGE_BYTES_PER_ORG", &c.Server.MaxFileStorageBytesPerOrg)
	envInt("GATEWAY_MAX_CONCURRENT_FILE_UPLOADS", &c.Server.MaxConcurrentFileUploads)

	envStr("GATEWAY_LOG_LEVEL", &c.Logging.Level)
	if v := os.Getenv("GATEWAY_LOG_FORMAT"); v != "" {
		c.Logging.Format = v
	} else if os.Getenv("ENV") == "production" || os.Getenv("GATEWAY_ENV") == "production" {
		c.Logging.Format = "json"
	}
	envBool("GATEWAY_LOG_ADD_SOURCE", &c.Logging.AddSource)

	if v := os.Getenv("GATEWAY_STORAGE_MODE"); v != "" {
		c.Storage.Mode = v
	} else if os.Getenv("GATEWAY_POSTGRES_DSN") != "" {
		c.Storage.Mode = "postgres"
	}
	envStr("GATEWAY_POSTGRES_DSN", &c.Storage.PostgresDSN)
	envStr("GATEWAY_REDIS_ADDR", &c.Storage.RedisAddr)
	if v := os.Getenv("GATEWAY_REDIS_ADDRS"); v != "" {
		if addrs := splitTrimCSV(v); len(addrs) > 0 {
			c.Storage.RedisAddrs = addrs
		}
	}
	envStr("GATEWAY_REDIS_MASTER_NAME", &c.Storage.RedisMasterName)
	envStr("GATEWAY_REDIS_PASS", &c.Storage.RedisPass)
}

func (c *Config) applyAuthEnvOverrides() {
	envStr("GATEWAY_MASTER_ADMIN_KEY", &c.Auth.MasterAdminKey)
	envStr("GATEWAY_MASTER_ENCRYPTION_KEY", &c.Auth.MasterEncryptionKey)
	if v := os.Getenv("GATEWAY_PREVIOUS_MASTER_ENCRYPTION_KEYS"); v != "" {
		c.Auth.PreviousMasterEncryptionKeys = splitTrimCSV(v)
	}
	envTrimStr("GATEWAY_KEY_ROTATION_DELIVERY_URL", &c.Auth.KeyRotationDeliveryURL)
	envStr("GATEWAY_KEY_ROTATION_DELIVERY_TOKEN", &c.Auth.KeyRotationDeliveryToken)
	envTrimStr("GATEWAY_KEY_ROTATION_SINK_DRIVER", &c.Auth.KeyRotationSink.Driver)
	envTrimStr("GATEWAY_KEY_ROTATION_SINK_ADDRESS", &c.Auth.KeyRotationSink.Address)
	envTrimStr("GATEWAY_KEY_ROTATION_SINK_MOUNT", &c.Auth.KeyRotationSink.Mount)
	envTrimStr("GATEWAY_KEY_ROTATION_SINK_PATH_PREFIX", &c.Auth.KeyRotationSink.PathPrefix)
	envStr("GATEWAY_KEY_ROTATION_SINK_TOKEN", &c.Auth.KeyRotationSink.Token)
	envTrimStr("GATEWAY_KEY_ROTATION_SINK_NAMESPACE", &c.Auth.KeyRotationSink.Namespace)
	envBool("GATEWAY_ALLOW_MASTER_KEY_DATA_PLANE", &c.Auth.AllowMasterKeyDataPlane)
	envBool("GATEWAY_ENABLE_DATA_PLANE_JWT", &c.Auth.EnableDataPlaneJWT)
	envTrimStr("GATEWAY_CUSTOM_API_KEY_HEADER", &c.Auth.CustomAPIKeyHeader)
	envStr("GATEWAY_JWT_ISSUER", &c.Auth.JWTIssuer)
	envStr("GATEWAY_JWT_AUDIENCE", &c.Auth.JWTAudience)
	envStr("GATEWAY_OIDC_JWKS_URL", &c.Auth.OIDCJWKSURL)
	envDuration("GATEWAY_KEY_ROTATION_POLL_INTERVAL", &c.Auth.KeyRotationPollInterval)
	envDuration("GATEWAY_KEY_ROTATION_GRACE_PERIOD", &c.Auth.KeyRotationGracePeriod)
	envStr("GATEWAY_SESSION_SECRET", &c.Auth.SessionSecret)
	envDuration("GATEWAY_SESSION_TTL", &c.Auth.SessionTTL)
	envStr("GATEWAY_INTROSPECTION_CLIENT_ID", &c.Auth.Introspection.ClientID)
	envStr("GATEWAY_INTROSPECTION_CLIENT_SECRET", &c.Auth.Introspection.ClientSecret)
	envDuration("GATEWAY_CLI_LOGIN_DEFAULT_TTL", &c.Auth.CLILoginDefaultTTL)
	envDuration("GATEWAY_CLI_LOGIN_MAX_TTL", &c.Auth.CLILoginMaxTTL)
	envInt("GATEWAY_AUTH_START_RATE_LIMIT_PER_MIN", &c.Auth.AuthStartRateLimitPerMin)
	envBool("GATEWAY_AUTH_REQUIRE_CLIENT_APP_HEADER", &c.Auth.RequireClientAppHeader)
	envBool("GATEWAY_AUTH_ALLOW_VIEWER_CONTROL_PLANE_READ", &c.Auth.AllowViewerControlPlaneRead)
}

func (c *Config) applyRouterEnvOverrides() {
	envDuration("GATEWAY_ROUTER_DEFAULT_COOLDOWN", &c.Router.DefaultCooldown)
	envDuration("GATEWAY_ROUTER_BASE_RETRY_DELAY", &c.Router.BaseRetryDelay)
	envDuration("GATEWAY_ROUTER_MAX_RETRY_DELAY", &c.Router.MaxRetryDelay)
	envInt("GATEWAY_ROUTER_MAX_FALLBACK_DEPTH", &c.Router.MaxFallbackDepth)
	envBool("GATEWAY_ROUTER_ENABLE_MID_STREAM_CONTINUATION", &c.Router.EnableMidStreamContinuation)
	envInt("GATEWAY_ROUTER_MAX_STREAM_CONTINUATIONS", &c.Router.MaxStreamContinuations)
	envDuration("GATEWAY_ROUTER_HEALTH_STALENESS_THRESHOLD", &c.Router.HealthStalenessThreshold)
	envBool("GATEWAY_ROUTER_STRICT_CAPACITY_FILTERING", &c.Router.StrictCapacityFiltering)
	envDuration("GATEWAY_ROUTER_SESSION_AFFINITY_TTL", &c.Router.SessionAffinityTTL)
	envBool("GATEWAY_ROUTER_SESSION_AFFINITY_REPIN_ON_FAILOVER", &c.Router.SessionAffinityRepinOnFailover)
	envBool("GATEWAY_ROUTER_PROMPT_CACHE_AFFINITY", &c.Router.PromptCacheAffinity)
	envTrimStr("GATEWAY_ROUTER_PRE_ROUTER_MODE", &c.Router.PreRouterMode)
	envBool("GATEWAY_ROUTER_CACHE_AWARE_ROUTING", &c.Router.CacheAwareRouting)
	envInt("GATEWAY_ROUTER_HEDGE_DELAY_MS", &c.Router.HedgeDelayMs)
	envInt("GATEWAY_ROUTER_MAX_HEDGE_CONCURRENCY", &c.Router.MaxHedgeConcurrency)
	envFloat("GATEWAY_ROUTER_LATENCY_TOLERANCE_PCT", &c.Router.LatencyTolerancePct)
	envDuration("GATEWAY_ROUTER_MAX_HONORED_RETRY_AFTER", &c.Router.MaxHonoredRetryAfter)
	envBool("GATEWAY_ROUTER_DISABLE_COOLDOWNS", &c.Router.DisableCooldowns)
	envBool("GATEWAY_ROUTER_FALLBACK_ON_SATURATION", &c.Router.FallbackOnSaturation)
	envBool("GATEWAY_ROUTER_DROP_UNSUPPORTED_PARAMS", &c.Router.DropUnsupportedParams)
	envBool("GATEWAY_ROUTER_FALLBACK_ON_UNSUPPORTED_PARAMS", &c.Router.FallbackOnUnsupportedParams)
	envBool("GATEWAY_ROUTER_ALLOW_STRATEGY_OVERRIDE", &c.Router.AllowStrategyOverride)
	envBool("GATEWAY_ROUTER_DEBUG_ROUTING_HEADERS", &c.Router.DebugRoutingHeaders)
}

func (c *Config) applyFinOpsAndProtocolEnvOverrides() {
	envDuration("GATEWAY_FINOPS_FLUSH_INTERVAL", &c.FinOps.FlushInterval)
	envTrimStr("GATEWAY_FINOPS_SOFT_BUDGET_WEBHOOK_URL", &c.FinOps.SoftBudgetWebhookURL)
	envInt("GATEWAY_FINOPS_SOFT_BUDGET_COOLDOWN_SEC", &c.FinOps.SoftBudgetCooldownSec)
	envFloat("GATEWAY_FINOPS_BUDGET_EXCEEDED_THROTTLE_PCT", &c.FinOps.BudgetExceededThrottlePct)
	envBool("GATEWAY_SECURITY_SSRF_ALLOW_PRIVATE", &c.Security.Network.OutboundSSRF.AllowPrivateNetworks)
	if v := os.Getenv("GATEWAY_SECURITY_SSRF_ALLOWED_PRIVATE_CIDRS"); v != "" {
		if cidrs := splitTrimCSV(v); len(cidrs) > 0 {
			c.Security.Network.OutboundSSRF.AllowedPrivateCIDRs = cidrs
		}
	}
	envBool("GATEWAY_SECURITY_SSRF_ALLOW_INSECURE_HTTP", &c.Security.Network.OutboundSSRF.AllowInsecureHTTP)
	envBool("GATEWAY_ALLOW_LOOPBACK_HTTP", &c.Security.Network.OutboundSSRF.AllowLoopbackHTTP)
	envBool("GATEWAY_SECURITY_SSRF_ALLOW_LOOPBACK_HTTP", &c.Security.Network.OutboundSSRF.AllowLoopbackHTTP)
	envBool("GATEWAY_MCP_ENABLED", &c.MCP.Enabled)
	envBool("GATEWAY_MCP_ALLOW_STDIO", &c.MCP.AllowStdioServers)
	envBool("GATEWAY_A2A_ENABLED", &c.A2A.Enabled)
	envStr("GATEWAY_A2A_SIGNING_KEY_ID", &c.A2A.SigningKeyID)
}

// Validate normalizes defaults and checks all configuration invariants across
// providers, routing, FinOps, server limits, authentication, network policy,
// MCP/A2A bindings, and guardrails.
func (c *Config) Validate() error {
	c.applyProviderAndCacheDefaults()

	validators := []func() error{
		c.validateRouterAndModelList,
		c.validateFinOpsAndTracing,
		c.validateServer,
		c.validateAuth,
		c.validateNetworkSecurity,
		c.validateMCPAndA2A,
		c.validateGuardrails,
	}
	for _, fn := range validators {
		if err := fn(); err != nil {
			return err
		}
	}
	return nil
}

func (c *Config) applyProviderAndCacheDefaults() {
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
}

func (c *Config) validateRouterAndModelList() error {
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
	if c.Router.Scheduler.MaxParallelWaitMs < 0 {
		return fmt.Errorf("invalid router.scheduler.max_parallel_wait_ms: %d", c.Router.Scheduler.MaxParallelWaitMs)
	}
	if c.Router.LatencyTolerancePct < 0 || c.Router.LatencyTolerancePct > 1 {
		return fmt.Errorf("invalid router.latency_tolerance_pct: %v (must be in [0, 1])", c.Router.LatencyTolerancePct)
	}
	if c.Router.MaxHonoredRetryAfter < 0 {
		return fmt.Errorf("invalid router.max_honored_retry_after: %s", c.Router.MaxHonoredRetryAfter)
	}
	if c.Router.MaxHonoredRetryAfter == 0 {
		c.Router.MaxHonoredRetryAfter = 60 * time.Second
	}
	for i, entry := range c.ModelList {
		if entry.ModelParams.ITPM < 0 || entry.ModelParams.OTPM < 0 || entry.ModelParams.MaxParallelRequests < 0 {
			return fmt.Errorf("invalid model_list[%d] (%q): itpm, otpm, and max_parallel_requests must be non-negative", i, entry.ModelName)
		}
		for j, fb := range entry.SaturationFallbacks {
			if strings.TrimSpace(fb.GroupAliasOrID) == "" {
				return fmt.Errorf("invalid model_list[%d] (%q).saturation_fallbacks[%d]: target cannot be empty", i, entry.ModelName, j)
			}
		}
	}
	if c.Router.SemanticRouter.SimilarityThreshold < 0 || c.Router.SemanticRouter.SimilarityThreshold > 1 {
		return fmt.Errorf("invalid router.semantic_router.similarity_threshold: %v", c.Router.SemanticRouter.SimilarityThreshold)
	}
	if c.Router.Bandit.DefaultAlpha < 0 || c.Router.Bandit.DefaultBeta < 0 {
		return fmt.Errorf("invalid router.bandit priors: alpha=%v beta=%v", c.Router.Bandit.DefaultAlpha, c.Router.Bandit.DefaultBeta)
	}
	return nil
}

func (c *Config) validateFinOpsAndTracing() error {
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
	return nil
}

func (c *Config) validateServer() error {
	if c.Server.Port <= 0 || c.Server.Port > 65535 {
		return fmt.Errorf("invalid server.port: %d", c.Server.Port)
	}
	if rawBase := strings.TrimSpace(c.Server.PublicBaseURL); rawBase != "" {
		u, err := url.Parse(rawBase)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
			return fmt.Errorf("invalid server.public_base_url %q: must be an http or https origin without credentials, query, or fragment", c.Server.PublicBaseURL)
		}
		if u.Path != "" && u.Path != "/" {
			return fmt.Errorf("invalid server.public_base_url %q: must not include a path", c.Server.PublicBaseURL)
		}
		c.Server.PublicBaseURL = strings.TrimRight(rawBase, "/")
	}
	for i, rawOrigin := range c.Server.CORSAllowedOrigins {
		origin := strings.TrimSpace(rawOrigin)
		if origin == "" {
			continue
		}
		if strings.EqualFold(origin, "null") {
			return fmt.Errorf("security violation: server.cors_allowed_origins cannot contain \"null\" origin")
		}
		if origin == "*" {
			if c.Server.CORSAllowCredentials {
				return fmt.Errorf("security violation: server.cors_allow_credentials cannot be true when server.cors_allowed_origins contains \"*\"")
			}
			if c.isNonDevEnvironment() {
				return fmt.Errorf("security violation: server.cors_allowed_origins cannot contain wildcard \"*\" in %q environment", c.effectiveEnvironment())
			}
			c.Server.CORSAllowedOrigins[i] = origin
			continue
		}
		u, err := url.Parse(origin)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
			return fmt.Errorf("invalid server.cors_allowed_origins entry %q: must be an http or https origin (scheme://host[:port]) without path, query, or fragment", rawOrigin)
		}
		if c.isNonDevEnvironment() && u.Scheme != "https" {
			return fmt.Errorf("security violation: server.cors_allowed_origins entry %q must use https in %q environment", rawOrigin, c.effectiveEnvironment())
		}
		c.Server.CORSAllowedOrigins[i] = origin
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
	return nil
}

func (c *Config) effectiveEnvironment() string {
	env := strings.ToLower(strings.TrimSpace(c.Server.Environment))
	for _, candidate := range []string{os.Getenv("ENV"), os.Getenv("GATEWAY_ENV")} {
		candidate = strings.ToLower(strings.TrimSpace(candidate))
		if candidate != "" {
			env = candidate
		}
	}
	return env
}

func (c *Config) isNonDevEnvironment() bool {
	env := c.effectiveEnvironment()
	return env != "development" && env != "test"
}

func (c *Config) validateAuth() error {
	if c.Auth.SessionTTL <= 0 {
		c.Auth.SessionTTL = 24 * time.Hour
	}
	if c.Auth.CLILoginDefaultTTL <= 0 {
		c.Auth.CLILoginDefaultTTL = 24 * time.Hour
	}
	if c.Auth.CLILoginMaxTTL <= 0 {
		c.Auth.CLILoginMaxTTL = 30 * 24 * time.Hour
	}
	if c.Auth.CLILoginDefaultTTL > c.Auth.CLILoginMaxTTL {
		return fmt.Errorf("auth.cli_login_default_ttl (%s) cannot exceed auth.cli_login_max_ttl (%s)", c.Auth.CLILoginDefaultTTL, c.Auth.CLILoginMaxTTL)
	}
	if c.Auth.AuthStartRateLimitPerMin < 0 {
		return fmt.Errorf("auth.auth_start_rate_limit_per_min cannot be negative")
	}
	if c.Auth.AuthStartRateLimitPerMin == 0 {
		c.Auth.AuthStartRateLimitPerMin = 30
	}
	if isUnresolvedEnvReference(c.Auth.MasterAdminKey) {
		return fmt.Errorf("auth.master_admin_key contains an unresolved environment variable reference")
	}
	if isUnresolvedEnvReference(c.Auth.MasterEncryptionKey) {
		return fmt.Errorf("auth.master_encryption_key contains an unresolved environment variable reference")
	}
	if isUnresolvedEnvReference(c.Auth.SessionSecret) {
		return fmt.Errorf("auth.session_secret contains an unresolved environment variable reference")
	}
	if isUnresolvedEnvReference(c.Auth.Introspection.ClientSecret) {
		return fmt.Errorf("auth.introspection.client_secret contains an unresolved environment variable reference")
	}
	if len(c.Auth.MasterAdminKey) < 12 {
		return fmt.Errorf("auth.master_admin_key must be at least 12 characters")
	}
	if len(c.Auth.MasterEncryptionKey) < 32 {
		return fmt.Errorf("auth.master_encryption_key must be at least 32 bytes for AES-256-GCM")
	}
	if trimmedSess := strings.TrimSpace(c.Auth.SessionSecret); trimmedSess != "" && len(trimmedSess) < 32 {
		return fmt.Errorf("auth.session_secret must be at least 32 bytes when configured")
	}
	for i, pk := range c.Auth.PreviousMasterEncryptionKeys {
		resolved := ResolveEnvValue(pk)
		if strings.TrimSpace(pk) == "" {
			continue
		}
		if len(resolved) < 32 {
			return fmt.Errorf("auth.previous_master_encryption_keys[%d] must be at least 32 bytes for AES-256-GCM", i)
		}
	}
	switch strings.ToLower(strings.TrimSpace(c.Auth.KeyRotationSink.Driver)) {
	case "", "webhook", "vault_kv2":
	default:
		return fmt.Errorf("invalid auth.key_rotation_sink.driver %q", c.Auth.KeyRotationSink.Driver)
	}
	if err := validateAuthKeyRotation(c.Auth); err != nil {
		return err
	}
	if err := c.validateProductionAuthSecrets(); err != nil {
		return err
	}
	if strings.TrimSpace(c.Auth.OIDCJWKSURL) != "" {
		if strings.TrimSpace(c.Auth.JWTIssuer) == "" {
			return fmt.Errorf("auth.jwt_issuer is required when OIDC authentication is enabled")
		}
		if strings.TrimSpace(c.Auth.JWTAudience) == "" {
			return fmt.Errorf("auth.jwt_audience is required when OIDC authentication is enabled")
		}
	}
	if err := validateOIDCIssuers(c.Auth.OIDCIssuers); err != nil {
		return err
	}
	if err := validateSSOProviders(c.Auth.SSOProviders, c.Server.PublicBaseURL, c.isNonDevEnvironment()); err != nil {
		return err
	}
	return validateIntrospectionConfig(c.Auth.Introspection)
}

func (c *Config) validateProductionAuthSecrets() error {
	const (
		defaultMasterAdminKey      = "sk-gw-master-admin-default-key-change-me"
		defaultMasterEncryptionKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	)
	env := c.effectiveEnvironment()
	if !c.isNonDevEnvironment() {
		return nil
	}
	if c.Auth.MasterAdminKey == defaultMasterAdminKey {
		return fmt.Errorf("security violation: auth.master_admin_key cannot be the default key in %q environment", env)
	}
	if c.Auth.MasterEncryptionKey == defaultMasterEncryptionKey {
		return fmt.Errorf("security violation: auth.master_encryption_key cannot be the default key in %q environment", env)
	}
	if len(strings.TrimSpace(c.Auth.SessionSecret)) < 32 {
		return fmt.Errorf("security violation: auth.session_secret (GATEWAY_SESSION_SECRET) must be at least 32 bytes in %q environment", env)
	}
	return nil
}

func isAllowedOIDCAlgorithm(alg string) bool {
	trimmed := strings.TrimSpace(alg)
	if trimmed == "" || strings.EqualFold(trimmed, "none") {
		return false
	}
	upper := strings.ToUpper(trimmed)
	return !strings.HasPrefix(upper, "HS")
}

func validateOIDCIssuers(issuers []OIDCIssuerConfig) error {
	seenIssuers := make(map[string]struct{}, len(issuers))
	for i, iss := range issuers {
		trimmedIss := strings.TrimSpace(iss.Issuer)
		if trimmedIss == "" {
			return fmt.Errorf("auth.oidc_issuers[%d].issuer is required", i)
		}
		if strings.TrimSpace(iss.Audience) == "" {
			return fmt.Errorf("auth.oidc_issuers[%d].audience is required", i)
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
			if !isAllowedOIDCAlgorithm(alg) {
				return fmt.Errorf("auth.oidc_issuers[%d].algorithms contains unsupported or symmetric algorithm %q", i, alg)
			}
		}
		if err := validateGroupRoleMappings(fmt.Sprintf("auth.oidc_issuers[%d]", i), iss.GroupRoleMappings, iss.RoleMappingStrategy); err != nil {
			return err
		}
	}
	return nil
}

func validateGroupRoleMappings(prefix string, rules []GroupRoleMappingRule, strategy string) error {
	strategyNorm := strings.ToLower(strings.TrimSpace(strategy))
	if strategyNorm != "" && strategyNorm != "highest_privilege" && strategyNorm != "first_match" {
		return fmt.Errorf("%s.role_mapping_strategy must be \"highest_privilege\" or \"first_match\"", prefix)
	}
	for idx, r := range rules {
		if strings.TrimSpace(r.Group) == "" {
			return fmt.Errorf("%s.group_role_mappings[%d].group is required", prefix, idx)
		}
		switch strings.ToLower(strings.TrimSpace(r.Role)) {
		case "platform_admin", "org_admin", "org_viewer", "team_admin", "developer", "service_account", "viewer":
		default:
			return fmt.Errorf("%s.group_role_mappings[%d].role %q is not a valid GoRoute role", prefix, idx, r.Role)
		}
	}
	return nil
}

func validateSSOProviders(providers []SSOProviderConfig, publicBaseURL string, nonDev bool) error {
	seenSSOProviders := make(map[string]struct{}, len(providers))
	for i, sso := range providers {
		id := strings.ToLower(strings.TrimSpace(sso.ID))
		if id == "" {
			id = strings.ToLower(strings.TrimSpace(sso.Name))
		}
		if id == "" {
			return fmt.Errorf("auth.sso_providers[%d]: id or name is required", i)
		}
		if _, dup := seenSSOProviders[id]; dup {
			return fmt.Errorf("duplicate auth.sso_providers[%d] id %q", i, id)
		}
		seenSSOProviders[id] = struct{}{}
		if strings.TrimSpace(sso.ClientID) == "" {
			return fmt.Errorf("auth.sso_providers[%d] (%q): client_id is required", i, id)
		}
		if isUnresolvedEnvReference(sso.ClientSecret) {
			return fmt.Errorf("auth.sso_providers[%d] (%q).client_secret contains an unresolved environment variable reference", i, id)
		}
		for _, urlField := range []struct {
			name string
			val  string
		}{
			{"discovery_url", sso.DiscoveryURL},
			{"authorization_endpoint", sso.AuthorizationEndpoint},
			{"token_endpoint", sso.TokenEndpoint},
			{"jwks_url", sso.JWKSURL},
			{"redirect_url", sso.RedirectURL},
		} {
			if raw := strings.TrimSpace(urlField.val); raw != "" {
				u, err := url.Parse(raw)
				if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
					return fmt.Errorf("auth.sso_providers[%d] (%q).%s must be a valid http or https URL", i, id, urlField.name)
				}
			}
		}
		if nonDev {
			redirect := strings.TrimSpace(sso.RedirectURL)
			if redirect != "" {
				if u, err := url.Parse(redirect); err != nil || u.Scheme != "https" {
					return fmt.Errorf("security violation: auth.sso_providers[%d] (%q).redirect_url must use https in production", i, id)
				}
			} else {
				u, err := url.Parse(strings.TrimSpace(publicBaseURL))
				if err != nil || u.Scheme != "https" || u.Hostname() == "" {
					return fmt.Errorf("security violation: auth.sso_providers[%d] (%q) requires an https redirect_url or https server.public_base_url in production", i, id)
				}
			}
		}
		ptype := strings.ToLower(strings.TrimSpace(sso.Type))
		if ptype == "" {
			ptype = "oidc"
		}
		if ptype != "oidc" {
			return fmt.Errorf("auth.sso_providers[%d] (%q): unsupported type %q (only standard \"oidc\" is supported)", i, id, sso.Type)
		}
		hasDiscovery := strings.TrimSpace(sso.DiscoveryURL) != ""
		hasManual := strings.TrimSpace(sso.AuthorizationEndpoint) != "" && strings.TrimSpace(sso.TokenEndpoint) != ""
		hasIssuerURL := false
		if iss := strings.TrimSpace(sso.Issuer); iss != "" {
			if u, err := url.Parse(iss); err == nil && (u.Scheme == "http" || u.Scheme == "https") && u.Host != "" {
				hasIssuerURL = true
			}
		}
		if !hasDiscovery && !hasManual && !hasIssuerURL {
			return fmt.Errorf("auth.sso_providers[%d] (%q) requires discovery_url, an http(s) issuer, or authorization_endpoint + token_endpoint", i, id)
		}
		for _, alg := range sso.Algorithms {
			if !isAllowedOIDCAlgorithm(alg) {
				return fmt.Errorf("auth.sso_providers[%d] (%q).algorithms contains unsupported or symmetric algorithm %q", i, id, alg)
			}
		}
		if err := validateGroupRoleMappings(fmt.Sprintf("auth.sso_providers[%d] (%q)", i, id), sso.GroupRoleMappings, sso.RoleMappingStrategy); err != nil {
			return err
		}
	}
	return nil
}

func validateIntrospectionConfig(cfg IntrospectionConfig) error {
	for _, urlField := range []struct {
		name string
		val  string
	}{
		{"token_info_endpoint", cfg.TokenInfoEndpoint},
		{"issuer", cfg.Issuer},
		{"discovery_url", cfg.DiscoveryURL},
	} {
		raw := strings.TrimSpace(urlField.val)
		if raw == "" {
			continue
		}
		u, err := url.Parse(raw)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("auth.introspection.%s must be a valid http or https URL", urlField.name)
		}
	}
	switch strings.ToLower(strings.TrimSpace(cfg.Mode)) {
	case "", "auto", "introspect", "userinfo":
		return nil
	default:
		return fmt.Errorf("invalid auth.introspection.mode %q", cfg.Mode)
	}
}

func (c *Config) validateNetworkSecurity() error {
	if c.isNonDevEnvironment() {
		env := c.effectiveEnvironment()
		ssrf := c.Security.Network.OutboundSSRF
		if ssrf.AllowLoopbackHTTP {
			return fmt.Errorf("security violation: security.network.outbound_ssrf.allow_loopback_http cannot be true in %q environment", env)
		}
		if ssrf.AllowInsecureHTTP {
			return fmt.Errorf("security violation: security.network.outbound_ssrf.allow_insecure_http cannot be true in %q environment", env)
		}
		if ssrf.AllowPrivateNetworks {
			return fmt.Errorf("security violation: security.network.outbound_ssrf.allow_private_networks cannot be true in %q environment (use explicit allowed_private_cidrs instead)", env)
		}
	}
	for _, cidr := range c.Security.Network.OutboundSSRF.AllowedPrivateCIDRs {
		_, ipNet, err := net.ParseCIDR(strings.TrimSpace(cidr))
		if err != nil {
			return fmt.Errorf("invalid security.network.outbound_ssrf.allowed_private_cidrs %q: %w", cidr, err)
		}
		if c.isNonDevEnvironment() {
			if err := validateNonDevAllowedPrivateCIDR(cidr, ipNet, c.effectiveEnvironment()); err != nil {
				return err
			}
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
	return nil
}

func validateNonDevAllowedPrivateCIDR(raw string, ipNet *net.IPNet, env string) error {
	ones, bits := ipNet.Mask.Size()
	if bits == 32 && ones < 8 {
		return fmt.Errorf("security violation: security.network.outbound_ssrf.allowed_private_cidrs %q is overly broad (IPv4 prefix must be at least /8 in %q environment)", raw, env)
	}
	if bits == 128 && ones < 7 {
		return fmt.Errorf("security violation: security.network.outbound_ssrf.allowed_private_cidrs %q is overly broad (IPv6 prefix must be at least /7 in %q environment)", raw, env)
	}
	if bits == 32 && ones >= 24 && ipNet.Contains(net.ParseIP("100.100.100.200")) {
		return fmt.Errorf("security violation: security.network.outbound_ssrf.allowed_private_cidrs %q overlaps forbidden cloud metadata IP in %q environment", raw, env)
	}
	forbiddenRanges := []string{
		"0.0.0.0/8",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"224.0.0.0/4",
		"::/128",
		"::1/128",
		"fe80::/10",
		"ff00::/8",
		"fd00:ec2::254/128",
	}
	for _, fRaw := range forbiddenRanges {
		_, fNet, err := net.ParseCIDR(fRaw)
		if err != nil {
			continue
		}
		if (ipNet.IP.To4() != nil) != (fNet.IP.To4() != nil) {
			continue
		}
		if ipNet.Contains(fNet.IP) || fNet.Contains(ipNet.IP) {
			return fmt.Errorf("security violation: security.network.outbound_ssrf.allowed_private_cidrs %q overlaps forbidden loopback, link-local, multicast, or cloud metadata range (%s) in %q environment", raw, fRaw, env)
		}
	}
	return nil
}

func (c *Config) validateMCPAndA2A() error {
	if c.MCP.Enabled {
		if c.MCP.AllowStdioServers {
			// Fail-closed until verified OS-level sandboxing is implemented.
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
	return nil
}

func (c *Config) validateGuardrails() error {
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
	case lower == "anthropic" || lower == "claude":
		return domain.ProviderAnthropic
	case lower == "openai" || lower == "chatgpt" || lower == "text-completion-openai":
		return domain.ProviderOpenAI
	case lower == "groq":
		return domain.ProviderGroq
	case lower == "openrouter":
		return domain.ProviderOpenRouter
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

// ParseProviderModel parses a model string (e.g. "openai/gpt-4o-mini",
// "anthropic/claude-haiku-4-5-20251001", "groq/llama-3.1-8b-instant",
// or "openrouter/openai/gpt-4o-mini") into (ProviderType, bareModelName, canonicalGlobalModelID).
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
	case strings.HasPrefix(lower, "claude"):
		return domain.ProviderAnthropic, spec, fmt.Sprintf("%s/%s", domain.ProviderAnthropic, spec)
	case strings.HasPrefix(lower, "gpt-") || strings.HasPrefix(lower, "o1") || strings.HasPrefix(lower, "o3") || strings.HasPrefix(lower, "o4") || strings.HasPrefix(lower, "text-embedding-3") || strings.HasPrefix(lower, "omni-moderation"):
		return domain.ProviderOpenAI, spec, fmt.Sprintf("%s/%s", domain.ProviderOpenAI, spec)
	default:
		return "", spec, spec
	}
}

// ValidateStrictHTTPSURL verifies that a non-empty endpoint is HTTPS with a hostname
// and no embedded userinfo, query parameters, or fragment, returning the trimmed base URL.
func ValidateStrictHTTPSURL(raw, errPrefix string) (string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", nil
	}
	parsed, err := url.Parse(trimmed)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("%s requires an HTTPS URL without credentials, a query, or a fragment", errPrefix)
	}
	return strings.TrimRight(trimmed, "/"), nil
}

func validateAuthKeyRotation(authCfg AuthConfig) error {
	if endpoint, err := ValidateStrictHTTPSURL(ResolveEnvValue(authCfg.KeyRotationDeliveryURL), "key rotation delivery"); err != nil {
		return err
	} else if endpoint != "" && ResolveEnvValue(authCfg.KeyRotationDeliveryToken) == "" {
		return fmt.Errorf("auth.key_rotation_delivery_token is required when auth.key_rotation_delivery_url is configured")
	}

	sink := authCfg.KeyRotationSink
	driver := strings.ToLower(strings.TrimSpace(sink.Driver))
	if driver == "" {
		return nil
	}
	switch driver {
	case "webhook":
		addr := ResolveEnvValue(sink.Address)
		if strings.TrimSpace(addr) == "" {
			if strings.TrimSpace(ResolveEnvValue(authCfg.KeyRotationDeliveryURL)) != "" {
				return nil
			}
			return fmt.Errorf("auth.key_rotation_sink.address is required for webhook driver")
		}
		if _, err := ValidateStrictHTTPSURL(addr, "key rotation sink webhook"); err != nil {
			return err
		}
		token := ResolveEnvValue(sink.Token)
		if token == "" {
			token = ResolveEnvValue(authCfg.KeyRotationDeliveryToken)
		}
		if token == "" {
			return fmt.Errorf("auth.key_rotation_sink.token is required for webhook driver")
		}
	case "vault_kv2":
		addr, err := ValidateStrictHTTPSURL(ResolveEnvValue(sink.Address), "key rotation Vault KV v2 sink")
		if err != nil {
			return err
		}
		if addr == "" {
			return fmt.Errorf("auth.key_rotation_sink.address is required for vault_kv2 driver")
		}
		if ResolveEnvValue(sink.Token) == "" {
			return fmt.Errorf("auth.key_rotation_sink.token is required for vault_kv2 driver")
		}
	}
	return nil
}
