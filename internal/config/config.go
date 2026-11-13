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
	Server    ServerConfig     `yaml:"server"`
	Logging   LogConfig        `yaml:"logging"`
	Tracing   TracingConfig    `yaml:"tracing"`
	Security  SecurityConfig   `yaml:"security"`
	Storage   StorageConfig    `yaml:"storage"`
	Auth      AuthConfig       `yaml:"auth"`
	Router    RouterConfig     `yaml:"router"`
	RateLimit RateLimitConfig  `yaml:"rate_limit"`
	FinOps    FinOpsConfig     `yaml:"finops"`
	Discovery DiscoveryConfig  `yaml:"discovery"`
	Cache     CacheConfig      `yaml:"cache"`
	MCP       MCPConfig        `yaml:"mcp"`
	A2A       A2AConfig        `yaml:"a2a"`
	Providers ProvidersConfig  `yaml:"providers"`
	ModelList []ModelListEntry `yaml:"model_list"`
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
	OTLPEndpoint string            `yaml:"otlp_endpoint"`
	ServiceName  string            `yaml:"service_name"`
	Headers      map[string]string `yaml:"headers,omitempty"`
}

// ModelListEntry defines a declarative model list entry in config.yaml,
// allowing developers to configure models, aliases ("fast", "reasoning"), and credentials
// without imperative Control Plane HTTP setup calls.
type ModelListEntry struct {
	ModelName       string      `yaml:"model_name" json:"model_name"`
	ModelParams     ModelParams `yaml:"model_params" json:"model_params"`
	RoutingStrategy string      `yaml:"routing_strategy,omitempty" json:"routing_strategy,omitempty"`
	Fallbacks       []string    `yaml:"fallbacks,omitempty" json:"fallbacks,omitempty"`
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
	AzureDeploymentName string            `yaml:"azure_deployment_name,omitempty" json:"azure_deployment_name,omitempty"`
	APIVersion          string            `yaml:"api_version,omitempty" json:"api_version,omitempty"`
	Headers             map[string]string `yaml:"headers,omitempty" json:"headers,omitempty"`
}

type ProvidersConfig struct {
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
}

type ServerConfig struct {
	Environment          string        `yaml:"environment"` // "development", "staging", "production"
	Host                 string        `yaml:"host"`
	Port                 int           `yaml:"port"`
	ReadTimeout          time.Duration `yaml:"read_timeout"`
	WriteTimeout         time.Duration `yaml:"write_timeout"`
	IdleTimeout          time.Duration `yaml:"idle_timeout"`
	ShutdownTimeout      time.Duration `yaml:"shutdown_timeout"`
	CORSAllowedOrigins   []string      `yaml:"cors_allowed_origins"`
	CORSAllowCredentials bool          `yaml:"cors_allow_credentials"`
	EnableHSTS           bool          `yaml:"enable_hsts"`
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

type AuthConfig struct {
	MasterAdminKey          string        `yaml:"master_admin_key"`
	MasterEncryptionKey     string        `yaml:"master_encryption_key"` // 32-byte hex or raw string for AES-256-GCM KEK
	AllowMasterKeyDataPlane bool          `yaml:"allow_master_key_data_plane"`
	JWTSecret               string        `yaml:"jwt_secret"`
	JWTIssuer               string        `yaml:"jwt_issuer"`
	JWTAudience             string        `yaml:"jwt_audience"`
	OIDCJWKSURL             string        `yaml:"oidc_jwks_url"`
	DefaultOrgID            string        `yaml:"default_org_id"`
	DefaultVirtualKey       string        `yaml:"default_virtual_key"`
	L1CacheTTL              time.Duration `yaml:"l1_cache_ttl"`
	L2CacheTTL              time.Duration `yaml:"l2_cache_ttl"`
}

type RouterConfig struct {
	DefaultFastAlias      string        `yaml:"default_fast_alias"`
	DefaultReasoningAlias string        `yaml:"default_reasoning_alias"`
	DefaultCodingAlias    string        `yaml:"default_coding_alias"`
	ComplexityThreshold   float64       `yaml:"complexity_threshold"`
	LongContextTokens     int           `yaml:"long_context_tokens"`
	DefaultMaxRetries     int           `yaml:"default_max_retries"`
	BaseRetryDelay        time.Duration `yaml:"base_retry_delay"`
	MaxRetryDelay         time.Duration `yaml:"max_retry_delay"`
	DefaultCooldown       time.Duration `yaml:"default_cooldown"`
	FailureWindow         time.Duration `yaml:"failure_window"`
	FailureThreshold      int           `yaml:"failure_threshold"`
}

type RateLimitConfig struct {
	Enabled             bool          `yaml:"enabled"`
	WindowSeconds       int           `yaml:"window_seconds"`
	ConcurrencyTTLSec   int           `yaml:"concurrency_ttl_sec"`
	DefaultEstimatedTPM int           `yaml:"default_estimated_tpm"`
	RedisTimeout        time.Duration `yaml:"redis_timeout"`
}

type FinOpsConfig struct {
	ChannelBufferSize int           `yaml:"channel_buffer_size"`
	BatchSize         int           `yaml:"batch_size"`
	FlushInterval     time.Duration `yaml:"flush_interval"`
	WorkerCount       int           `yaml:"worker_count"`
}

type DiscoveryConfig struct {
	Enabled      bool          `yaml:"enabled"`
	SyncInterval time.Duration `yaml:"sync_interval"`
	AutoApprove  bool          `yaml:"auto_approve"`
}

type CacheConfig struct {
	Enabled    bool          `yaml:"enabled"`
	DefaultTTL time.Duration `yaml:"default_ttl"`
}

// Default returns a production-ready default configuration.
func Default() *Config {
	return &Config{
		Server: ServerConfig{
			Host:            "0.0.0.0",
			Port:            8080,
			ReadTimeout:     30 * time.Second,
			WriteTimeout:    300 * time.Second, // High write timeout for long SSE reasoning streams
			IdleTimeout:     120 * time.Second,
			ShutdownTimeout: 15 * time.Second,
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
			MasterAdminKey:      "sk-gw-master-admin-default-key-change-me",
			MasterEncryptionKey: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			JWTSecret:           "gateway-jwt-hmac-secret-change-me",
			DefaultOrgID:        "org_default",
			L1CacheTTL:          15 * time.Second,
			L2CacheTTL:          5 * time.Minute,
		},
		Router: RouterConfig{
			DefaultFastAlias:      "fast",
			DefaultReasoningAlias: "reasoning",
			DefaultCodingAlias:    "coding",
			ComplexityThreshold:   0.40,
			LongContextTokens:     32000,
			DefaultMaxRetries:     2,
			BaseRetryDelay:        50 * time.Millisecond,
			MaxRetryDelay:         2 * time.Second,
			DefaultCooldown:       60 * time.Second,
			FailureWindow:         30 * time.Second,
			FailureThreshold:      3,
		},
		RateLimit: RateLimitConfig{
			Enabled:             true,
			WindowSeconds:       60,
			ConcurrencyTTLSec:   300,
			DefaultEstimatedTPM: 128,
			RedisTimeout:        50 * time.Millisecond,
		},
		FinOps: FinOpsConfig{
			ChannelBufferSize: 16384,
			BatchSize:         250,
			FlushInterval:     500 * time.Millisecond,
			WorkerCount:       2,
		},
		Discovery: DiscoveryConfig{
			Enabled:      true,
			SyncInterval: 6 * time.Hour,
			AutoApprove:  true,
		},
		Cache: CacheConfig{
			Enabled:    true,
			DefaultTTL: 1 * time.Hour,
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
func Load(path string) (*Config, error) {
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

	if v := os.Getenv("GATEWAY_PORT"); v != "" {
		if p, err := strconv.Atoi(v); err == nil {
			cfg.Server.Port = p
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
	if v := os.Getenv("GATEWAY_FINOPS_FLUSH_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			cfg.FinOps.FlushInterval = d
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
	if env == "" {
		env = strings.ToLower(strings.TrimSpace(os.Getenv("ENV")))
	}
	if env == "production" || env == "prod" {
		if c.Auth.MasterAdminKey == defaultMasterAdminKey {
			return fmt.Errorf("security violation: auth.master_admin_key cannot be the default key in %s environment", env)
		}
		if c.Auth.MasterEncryptionKey == defaultMasterEncryptionKey {
			return fmt.Errorf("security violation: auth.master_encryption_key cannot be the default key in %s environment", env)
		}
		if c.Auth.JWTSecret == defaultJWTSecret {
			return fmt.Errorf("security violation: auth.jwt_secret cannot be the default secret in %s environment", env)
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
	case lower == "nvidia" || lower == "nvidia_nim":
		return domain.ProviderNvidia
	case lower == "scaleway":
		return domain.ProviderScaleway
	default:
		return domain.ProviderType(lower)
	}
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
