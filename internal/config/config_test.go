package config_test

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

func TestResolveEnvValueAndParseProviderModel(t *testing.T) {
	t.Setenv("TEST_GROQ_KEY", "gsk_Test123")
	t.Setenv("TEST_CLAUDE_KEY", "sk-ant-Test456")

	if got := config.ResolveEnvValue("os.environ/TEST_GROQ_KEY"); got != "gsk_Test123" {
		t.Fatalf("expected gsk_Test123, got %q", got)
	}
	if got := config.ResolveEnvValue("${TEST_CLAUDE_KEY}"); got != "sk-ant-Test456" {
		t.Fatalf("expected sk-ant-Test456, got %q", got)
	}
	if got := config.ResolveEnvValue("$TEST_GROQ_KEY"); got != "gsk_Test123" {
		t.Fatalf("expected gsk_Test123, got %q", got)
	}
	if got := config.ResolveEnvValue("sk-literal-key"); got != "sk-literal-key" {
		t.Fatalf("expected literal key unchanged, got %q", got)
	}

	prov, bare, globalID := config.ParseProviderModel("groq/llama-3.1-8b-instant")
	if prov != domain.ProviderGroq || bare != "llama-3.1-8b-instant" || globalID != "groq/llama-3.1-8b-instant" {
		t.Fatalf("unexpected ParseProviderModel for groq/llama-3.1-8b-instant: %v %v %v", prov, bare, globalID)
	}

	prov, bare, globalID = config.ParseProviderModel("openrouter/openai/gpt-4o-mini")
	if prov != domain.ProviderOpenRouter || bare != "openai/gpt-4o-mini" || globalID != "openrouter/openai/gpt-4o-mini" {
		t.Fatalf("unexpected ParseProviderModel for openrouter/openai/gpt-4o-mini: %v %v %v", prov, bare, globalID)
	}

	prov, bare, globalID = config.ParseProviderModel("claude-sonnet-4-20250514")
	if prov != domain.ProviderAnthropic || bare != "claude-sonnet-4-20250514" || globalID != "anthropic/claude-sonnet-4-20250514" {
		t.Fatalf("unexpected ParseProviderModel for bare claude model: %v %v %v", prov, bare, globalID)
	}
}

func TestLoadModelListYAML(t *testing.T) {
	yamlContent := `
server:
  port: 8080
  environment: "test"
auth:
  master_admin_key: "sk-gw-master-admin-test-key"
  master_encryption_key: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
  default_virtual_key: "sk-gw-dev-default-key"
model_list:
  - model_name: fast
    model_params:
      model: groq/llama-3.1-8b-instant
      api_key: os.environ/GROQ_API_KEY
  - model_name: reasoning
    model_params:
      model: anthropic/claude-haiku-4-5-20251001
      api_key: os.environ/ANTHROPIC_API_KEY
`
	tmpFile := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(tmpFile, []byte(yamlContent), 0600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}

	cfg, err := config.Load(tmpFile)
	if err != nil {
		t.Fatalf("config.Load failed: %v", err)
	}
	if len(cfg.ModelList) != 2 {
		t.Fatalf("expected 2 model_list entries, got %d", len(cfg.ModelList))
	}
	if cfg.ModelList[0].ModelName != "fast" || cfg.ModelList[0].ModelParams.Model != "groq/llama-3.1-8b-instant" {
		t.Fatalf("unexpected model_list[0]: %+v", cfg.ModelList[0])
	}
	if cfg.Auth.DefaultVirtualKey != "sk-gw-dev-default-key" {
		t.Fatalf("expected DefaultVirtualKey sk-gw-dev-default-key, got %q", cfg.Auth.DefaultVirtualKey)
	}
}

func TestConfigValidationMatrix(t *testing.T) {
	t.Run("Default configuration is valid in development and test", func(t *testing.T) {
		cfg := config.Default()
		if cfg.Auth.JWTSecret != "" {
			t.Fatalf("expected default Auth.JWTSecret to be empty, got %q", cfg.Auth.JWTSecret)
		}
		if err := cfg.Validate(); err == nil {
			t.Fatalf("expected default keys to be rejected when environment is unset")
		}
		cfg.Server.Environment = "development"
		if err := cfg.Validate(); err != nil {
			t.Fatalf("expected default config to be valid in development, got: %v", err)
		}
		cfg.Server.Environment = "test"
		if err := cfg.Validate(); err != nil {
			t.Fatalf("expected default config to be valid in test, got: %v", err)
		}
	})

	t.Run("Production and staging environments reject default master keys", func(t *testing.T) {
		cfg := config.Default()
		cfg.Server.Environment = "production"
		if err := cfg.Validate(); err == nil {
			t.Fatalf("expected error when validating default keys in production, got nil")
		}
		cfg.Server.Environment = "staging"
		if err := cfg.Validate(); err == nil {
			t.Fatalf("expected error when validating default keys in staging, got nil")
		}

		// Valid custom keys in production must pass
		cfg.Server.Environment = "production"
		cfg.Auth.MasterAdminKey = "sk-gw-custom-production-super-secret-key-12345"
		cfg.Auth.MasterEncryptionKey = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
		cfg.Auth.JWTSecret = "custom-production-jwt-secret-xyz-987"
		cfg.Auth.JWTIssuer = "https://auth.example.com"
		cfg.Auth.JWTAudience = "ai-gateway"
		if err := cfg.Validate(); err != nil {
			t.Fatalf("expected custom production keys to pass validation, got: %v", err)
		}
	})

	t.Run("JWT/OIDC requires issuer and audience", func(t *testing.T) {
		cfg := config.Default()
		cfg.Server.Environment = "development"
		cfg.Auth.JWTSecret = "custom-secret"
		if err := cfg.Validate(); err == nil {
			t.Fatal("expected error when JWTSecret is set without JWTIssuer/JWTAudience")
		}
		cfg.Auth.JWTIssuer = "https://idp.example.com"
		if err := cfg.Validate(); err == nil {
			t.Fatal("expected error when JWTSecret is set without JWTAudience")
		}
		cfg.Auth.JWTAudience = "ai-gateway"
		if err := cfg.Validate(); err != nil {
			t.Fatalf("expected valid JWT config, got: %v", err)
		}

		cfg.Auth.JWTSecret = ""
		cfg.Auth.OIDCJWKSURL = "https://idp.example.com/.well-known/jwks.json"
		cfg.Auth.JWTIssuer = ""
		if err := cfg.Validate(); err == nil {
			t.Fatal("expected error when OIDCJWKSURL is set without JWTIssuer")
		}
	})

	t.Run("GATEWAY_ENV production rejects default keys even when YAML says development", func(t *testing.T) {
		t.Setenv("ENV", "")
		t.Setenv("GATEWAY_ENV", "production")
		cfg := config.Default()
		cfg.Server.Environment = "development"
		if err := cfg.Validate(); err == nil {
			t.Fatal("expected GATEWAY_ENV=production to reject default keys")
		}
	})

	t.Run("ENV production rejects default keys", func(t *testing.T) {
		t.Setenv("ENV", "production")
		t.Setenv("GATEWAY_ENV", "")
		cfg := config.Default()
		if err := cfg.Validate(); err == nil {
			t.Fatal("expected ENV=production to reject default keys")
		}
	})

	t.Run("Invalid CIDR in OutboundSSRF fails", func(t *testing.T) {
		cfg := config.Default()
		cfg.Server.Environment = "test"
		cfg.Security.Network.OutboundSSRF.AllowedPrivateCIDRs = []string{"not-a-cidr"}
		if err := cfg.Validate(); err == nil {
			t.Fatalf("expected error on invalid CIDR, got nil")
		}
	})

	t.Run("Invalid IP in BlockedIPs fails", func(t *testing.T) {
		cfg := config.Default()
		cfg.Server.Environment = "test"
		cfg.Security.Network.OutboundSSRF.BlockedIPs = []string{"999.999.999.999"}
		if err := cfg.Validate(); err == nil {
			t.Fatalf("expected error on invalid blocked IP, got nil")
		}
	})

	t.Run("MCP AllowStdioServers fails fast without BL-02 sandbox", func(t *testing.T) {
		cfg := config.Default()
		cfg.Server.Environment = "test"
		cfg.MCP.AllowStdioServers = true
		if err := cfg.Validate(); err == nil {
			t.Fatalf("expected error when MCP allow_stdio_servers is true, got nil")
		}
	})

	t.Run("A2A with zero enabled transports fails", func(t *testing.T) {
		cfg := config.Default()
		cfg.Server.Environment = "test"
		cfg.A2A.EnableJSONRPC = false
		cfg.A2A.EnableHTTPJSON = false
		if err := cfg.Validate(); err == nil {
			t.Fatalf("expected error when all A2A transports disabled, got nil")
		}
	})

	t.Run("A2A with unsafe none/HS signing algs fails", func(t *testing.T) {
		cfg := config.Default()
		cfg.Server.Environment = "test"
		cfg.A2A.AllowedSigningAlgs = []string{"ES256", "none"}
		if err := cfg.Validate(); err == nil {
			t.Fatalf("expected error on 'none' algorithm, got nil")
		}

		cfg.A2A.AllowedSigningAlgs = []string{"HS256"}
		if err := cfg.Validate(); err == nil {
			t.Fatalf("expected error on symmetric 'HS256' algorithm, got nil")
		}
	})

	t.Run("Server GRPCPort defaults to 0 and validates range", func(t *testing.T) {
		cfg := config.Default()
		cfg.Server.Environment = "test"
		if cfg.Server.GRPCPort != 0 {
			t.Fatalf("expected default GRPCPort 0, got %d", cfg.Server.GRPCPort)
		}
		cfg.Server.GRPCPort = 9090
		if err := cfg.Validate(); err != nil {
			t.Fatalf("expected valid GRPCPort 9090, got %v", err)
		}
		cfg.Server.GRPCPort = -1
		if err := cfg.Validate(); err == nil {
			t.Fatalf("expected error for negative GRPCPort, got nil")
		}
		cfg.Server.GRPCPort = 70000
		if err := cfg.Validate(); err == nil {
			t.Fatalf("expected error for GRPCPort > 65535, got nil")
		}
	})
}

func TestLoadGRPCPortEnvOverride(t *testing.T) {
	t.Setenv("GATEWAY_ENV", "test")
	t.Setenv("GATEWAY_GRPC_PORT", "9091")
	cfg, err := config.Load("")
	if err != nil {
		t.Fatalf("config.Load failed: %v", err)
	}
	if cfg.Server.GRPCPort != 9091 {
		t.Fatalf("expected GRPCPort 9091 from env, got %d", cfg.Server.GRPCPort)
	}
}

func TestLoadStorageRedisClusterConfigAndEnvOverrides(t *testing.T) {
	t.Setenv("GATEWAY_ENV", "test")
	t.Setenv("GATEWAY_REDIS_ADDRS", "redis-1:6379, redis-2:6379 ,redis-3:6379")
	t.Setenv("GATEWAY_REDIS_MASTER_NAME", "goroute-master")

	cfg, err := config.Load("")
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if len(cfg.Storage.RedisAddrs) != 3 || cfg.Storage.RedisAddrs[0] != "redis-1:6379" || cfg.Storage.RedisAddrs[1] != "redis-2:6379" || cfg.Storage.RedisAddrs[2] != "redis-3:6379" {
		t.Fatalf("unexpected RedisAddrs: %#v", cfg.Storage.RedisAddrs)
	}
	if cfg.Storage.RedisMasterName != "goroute-master" {
		t.Fatalf("unexpected RedisMasterName: %q", cfg.Storage.RedisMasterName)
	}
}

func TestGuardrailsAndCustomProviderConfigValidation(t *testing.T) {
	t.Setenv("GATEWAY_ENV", "test")

	yamlContent := `
server:
  port: 8080
  environment: "test"
guardrails:
  scanners:
    - name: "dlp-webhook"
      url: "https://guardrails.example.com/scan"
      timeout_ms: 1500
      fail_open: true
      headers:
        Authorization: "Bearer test-token"
`
	tmpFile := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(tmpFile, []byte(yamlContent), 0600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}

	cfg, err := config.Load(tmpFile)
	if err != nil {
		t.Fatalf("config.Load failed: %v", err)
	}
	if len(cfg.Guardrails.Scanners) != 1 || cfg.Guardrails.Scanners[0].Name != "dlp-webhook" || !cfg.Guardrails.Scanners[0].FailOpen || cfg.Guardrails.Scanners[0].TimeoutMs != 1500 {
		t.Fatalf("unexpected guardrails config: %+v", cfg.Guardrails)
	}

	// Verify RateLimit.FallbackToLocalOnOutage and Tracing.Enabled YAML unmarshaling
	rlYAML := `
server:
  port: 8080
  environment: "test"
tracing:
  enabled: true
  otlp_endpoint: "http://localhost:4318/v1/traces"
rate_limit:
  enabled: true
  fallback_to_local_on_outage: true
`
	rlFile := filepath.Join(t.TempDir(), "rl-config.yaml")
	if err := os.WriteFile(rlFile, []byte(rlYAML), 0600); err != nil {
		t.Fatalf("write temp rl config: %v", err)
	}
	rlCfg, err := config.Load(rlFile)
	if err != nil {
		t.Fatalf("config.Load rl config failed: %v", err)
	}
	if !rlCfg.RateLimit.FallbackToLocalOnOutage {
		t.Fatalf("expected RateLimit.FallbackToLocalOnOutage=true")
	}
	if !rlCfg.Tracing.Enabled || rlCfg.Tracing.OTLPEndpoint != "http://localhost:4318/v1/traces" {
		t.Fatalf("expected Tracing.Enabled=true and endpoint set, got %+v", rlCfg.Tracing)
	}

	// Negative cases for GuardrailsConfig
	badCfg := config.Default()
	badCfg.Server.Environment = "test"
	badCfg.Guardrails.Scanners = []config.GuardrailScannerConfig{{Name: "", URL: "https://example.com"}}
	if err := badCfg.Validate(); err == nil {
		t.Fatalf("expected error for empty scanner name")
	}
	badCfg.Guardrails.Scanners = []config.GuardrailScannerConfig{{Name: "a", URL: "ftp://example.com"}}
	if err := badCfg.Validate(); err == nil {
		t.Fatalf("expected error for invalid scanner URL scheme")
	}
	badCfg.Guardrails.Scanners = []config.GuardrailScannerConfig{{Name: "a", URL: "https://example.com", TimeoutMs: -1}}
	if err := badCfg.Validate(); err == nil {
		t.Fatalf("expected error for negative timeout_ms")
	}
	badCfg.Guardrails.Scanners = []config.GuardrailScannerConfig{
		{Name: "dup", URL: "https://example.com/1"},
		{Name: "dup", URL: "https://example.com/2"},
	}
	if err := badCfg.Validate(); err == nil {
		t.Fatalf("expected error for duplicate scanner name")
	}
}

func TestRouterFoundationDefaultsYAMLAndValidation(t *testing.T) {
	t.Setenv("GATEWAY_ENV", "test")

	def := config.Default()
	if def.Router.MaxFallbackDepth != 16 {
		t.Fatalf("MaxFallbackDepth = %d, want 16", def.Router.MaxFallbackDepth)
	}
	if def.Router.MaxStreamContinuations != 1 {
		t.Fatalf("MaxStreamContinuations = %d, want 1", def.Router.MaxStreamContinuations)
	}
	if def.Router.SessionAffinityTTL != 30*time.Minute {
		t.Fatalf("SessionAffinityTTL = %v, want 30m", def.Router.SessionAffinityTTL)
	}
	if !def.Router.SessionAffinityRepinOnFailover {
		t.Fatalf("SessionAffinityRepinOnFailover = false, want true")
	}
	if def.Router.MaxHedgeConcurrency != 2 {
		t.Fatalf("MaxHedgeConcurrency = %d, want 2", def.Router.MaxHedgeConcurrency)
	}

	yamlContent := `
server:
  port: 8080
  environment: "test"
router:
  max_fallback_depth: 8
  default_fallbacks:
    - target: "backup-fast"
      overrides:
        temperature: 0.1
  retry_policy:
    rate_limit_retries: 3
    timeout_retries: 2
    server_error_retries: 2
    auth_error_retries: 0
    not_found_retries: 0
    bad_request_retries: 0
    default_retries: 1
  cooldown_policy:
    allowed_fails:
      rate_limit: 5
      server_error: 3
    failure_rate_threshold: 0.4
    min_requests_per_minute: 20
    max_cooldown_seconds: 120
  enable_mid_stream_continuation: true
  max_stream_continuations: 2
  health_staleness_threshold: 45s
  strict_capacity_filtering: true
  provider_budgets:
    openai: 50000000
  session_affinity_ttl: 15m
  session_affinity_repin_on_failover: false
  prompt_cache_affinity: true
  pre_router_mode: "semantic"
  semantic_router:
    enabled: true
    embedding_model: "text-embedding-3-small"
    similarity_threshold: 0.82
    timeout: 2s
    routes:
      - name: "coding"
        target_model: "coding"
        utterances: ["write unit tests"]
  cache_aware_routing: true
  bandit:
    enabled: true
    default_alpha: 2.0
    default_beta: 1.0
    exploration_rate: 0.05
    decay_half_life: 12h
    latency_weight: 0.6
    cost_weight: 0.4
    sync_interval: 10s
    candidate_models: ["fast", "reasoning"]
  hedge_delay_ms: 150
  max_hedge_concurrency: 3
  scheduler:
    enabled: true
    max_queue_depth: 512
    max_wait_time: 3s
    default_priority: 5
model_list:
  - model_name: fast
    routing_strategy: fastest-response
    context_window_fallbacks:
      - target: "long-ctx"
    content_policy_fallbacks:
      - target: "safe-fallback"
    fallback_targets:
      - target: "backup-fast"
        overrides:
          max_tokens: 1024
    model_params:
      model: openai/gpt-4.1-mini
      api_key: os.environ/OPENAI_API_KEY
      priority: 2
      tags: ["tier:fast", "region:us"]
      max_budget_micros: 10000000
      budget_reset_period: "daily"
`
	tmpFile := filepath.Join(t.TempDir(), "router-config.yaml")
	if err := os.WriteFile(tmpFile, []byte(yamlContent), 0600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}

	cfg, err := config.Load(tmpFile)
	if err != nil {
		t.Fatalf("config.Load failed: %v", err)
	}
	if cfg.Router.MaxFallbackDepth != 8 {
		t.Fatalf("MaxFallbackDepth = %d, want 8", cfg.Router.MaxFallbackDepth)
	}
	if len(cfg.Router.DefaultFallbacks) != 1 || cfg.Router.DefaultFallbacks[0].GroupAliasOrID != "backup-fast" {
		t.Fatalf("unexpected DefaultFallbacks: %+v", cfg.Router.DefaultFallbacks)
	}
	if cfg.Router.RetryPolicy.RateLimitRetries != 3 || cfg.Router.RetryPolicy.TimeoutRetries != 2 || cfg.Router.RetryPolicy.DefaultRetries != 1 {
		t.Fatalf("unexpected RetryPolicy: %+v", cfg.Router.RetryPolicy)
	}
	if cfg.Router.CooldownPolicy.AllowedFails["rate_limit"] != 5 || cfg.Router.CooldownPolicy.FailureRateThreshold != 0.4 || cfg.Router.CooldownPolicy.MaxCooldownSeconds != 120 {
		t.Fatalf("unexpected CooldownPolicy: %+v", cfg.Router.CooldownPolicy)
	}
	if !cfg.Router.EnableMidStreamContinuation || cfg.Router.MaxStreamContinuations != 2 {
		t.Fatalf("unexpected mid-stream settings: %+v", cfg.Router)
	}
	if cfg.Router.HealthStalenessThreshold != 45*time.Second || !cfg.Router.StrictCapacityFiltering {
		t.Fatalf("unexpected health/capacity settings: %+v", cfg.Router)
	}
	if cfg.Router.ProviderBudgets["openai"] != 50000000 {
		t.Fatalf("unexpected ProviderBudgets: %+v", cfg.Router.ProviderBudgets)
	}
	if cfg.Router.SessionAffinityTTL != 15*time.Minute || cfg.Router.SessionAffinityRepinOnFailover || !cfg.Router.PromptCacheAffinity {
		t.Fatalf("unexpected affinity settings: %+v", cfg.Router)
	}
	if cfg.Router.PreRouterMode != "semantic" || !cfg.Router.SemanticRouter.Enabled || len(cfg.Router.SemanticRouter.Routes) != 1 {
		t.Fatalf("unexpected semantic router config: %+v", cfg.Router.SemanticRouter)
	}
	if !cfg.Router.CacheAwareRouting || !cfg.Router.Bandit.Enabled || cfg.Router.Bandit.DefaultAlpha != 2.0 {
		t.Fatalf("unexpected cache/bandit config: %+v", cfg.Router.Bandit)
	}
	if cfg.Router.HedgeDelayMs != 150 || cfg.Router.MaxHedgeConcurrency != 3 || !cfg.Router.Scheduler.Enabled || cfg.Router.Scheduler.MaxQueueDepth != 512 {
		t.Fatalf("unexpected hedge/scheduler config: %+v", cfg.Router.Scheduler)
	}
	entry := cfg.ModelList[0]
	if entry.RoutingStrategy != string(domain.StrategyFastestResponse) {
		t.Fatalf("RoutingStrategy = %q, want %q", entry.RoutingStrategy, domain.StrategyFastestResponse)
	}
	if len(entry.ContextWindowFallbacks) != 1 || entry.ContextWindowFallbacks[0].GroupAliasOrID != "long-ctx" {
		t.Fatalf("unexpected ContextWindowFallbacks: %+v", entry.ContextWindowFallbacks)
	}
	if len(entry.ContentPolicyFallbacks) != 1 || entry.ContentPolicyFallbacks[0].GroupAliasOrID != "safe-fallback" {
		t.Fatalf("unexpected ContentPolicyFallbacks: %+v", entry.ContentPolicyFallbacks)
	}
	if len(entry.FallbackTargets) != 1 || entry.FallbackTargets[0].GroupAliasOrID != "backup-fast" {
		t.Fatalf("unexpected FallbackTargets: %+v", entry.FallbackTargets)
	}
	if entry.ModelParams.Priority != 2 || !reflect.DeepEqual(entry.ModelParams.Tags, []string{"tier:fast", "region:us"}) || entry.ModelParams.MaxBudgetMicros != 10000000 || entry.ModelParams.BudgetResetPeriod != "daily" {
		t.Fatalf("unexpected ModelParams: %+v", entry.ModelParams)
	}

	// Verify env overrides
	t.Setenv("GATEWAY_ROUTER_MAX_FALLBACK_DEPTH", "24")
	t.Setenv("GATEWAY_ROUTER_ENABLE_MID_STREAM_CONTINUATION", "true")
	t.Setenv("GATEWAY_ROUTER_HEDGE_DELAY_MS", "200")
	t.Setenv("GATEWAY_ROUTER_PRE_ROUTER_MODE", "bandit")
	envCfg, err := config.Load("")
	if err != nil {
		t.Fatalf("config.Load env override failed: %v", err)
	}
	if envCfg.Router.MaxFallbackDepth != 24 || !envCfg.Router.EnableMidStreamContinuation || envCfg.Router.HedgeDelayMs != 200 || envCfg.Router.PreRouterMode != "bandit" {
		t.Fatalf("unexpected router env overrides: %+v", envCfg.Router)
	}

	// Negative validation checks
	bad := config.Default()
	bad.Server.Environment = "test"
	bad.Router.MaxFallbackDepth = -1
	if err := bad.Validate(); err == nil {
		t.Fatalf("expected error for negative max_fallback_depth")
	}
	bad = config.Default()
	bad.Server.Environment = "test"
	bad.Router.ProviderBudgets = map[string]int64{"openai": -5}
	if err := bad.Validate(); err == nil {
		t.Fatalf("expected error for negative provider budget")
	}
	bad = config.Default()
	bad.Server.Environment = "test"
	bad.Router.SemanticRouter.SimilarityThreshold = 1.5
	if err := bad.Validate(); err == nil {
		t.Fatalf("expected error for similarity_threshold > 1")
	}
}

func TestConfig_OIDCIssuersYAMLAndValidation(t *testing.T) {
	yamlContent := `
server:
  environment: test
auth:
  oidc_issuers:
    - issuer: "https://idp-a.example.com"
      audience: "gateway-api"
      discovery_url: "https://idp-a.example.com/.well-known/openid-configuration"
      algorithms: ["RS256", "EdDSA"]
      allowed_email_domains: ["acme.com", "example.org"]
      claim_mapping:
        user_id: "uid"
        email: "mail"
        org_id: "tenant.org_id"
        team_ids: "groups"
        role: "roles"
        end_user: "end_user"
      auto_register: true
      default_org_id: "org_acme"
      default_team_id: "team_eng"
      default_role: "developer"
    - issuer: "https://idp-b.example.com"
      jwks_url: "https://idp-b.example.com/keys"
`
	tmpPath := filepath.Join(t.TempDir(), "oidc_config.yaml")
	if err := os.WriteFile(tmpPath, []byte(yamlContent), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	cfg, err := config.Load(tmpPath)
	if err != nil {
		t.Fatalf("load multi-issuer config: %v", err)
	}
	if len(cfg.Auth.OIDCIssuers) != 2 {
		t.Fatalf("expected 2 oidc_issuers, got %d", len(cfg.Auth.OIDCIssuers))
	}
	issA := cfg.Auth.OIDCIssuers[0]
	if issA.Issuer != "https://idp-a.example.com" || issA.Audience != "gateway-api" || !issA.AutoRegister {
		t.Fatalf("unexpected issuer A fields: %+v", issA)
	}
	if issA.ClaimMapping.OrgID != "tenant.org_id" || issA.ClaimMapping.EndUser != "end_user" {
		t.Fatalf("unexpected claim mapping: %+v", issA.ClaimMapping)
	}
	if issA.DefaultOrgID != "org_acme" || issA.DefaultTeamID != "team_eng" || issA.DefaultRole != "developer" {
		t.Fatalf("unexpected defaults: %+v", issA)
	}

	// Negative cases
	cases := []struct {
		name string
		edit func(*config.Config)
	}{
		{
			name: "missing issuer",
			edit: func(c *config.Config) {
				c.Auth.OIDCIssuers = []config.OIDCIssuerConfig{{JWKSURL: "https://idp.example.com/jwks.json"}}
			},
		},
		{
			name: "duplicate issuer",
			edit: func(c *config.Config) {
				c.Auth.OIDCIssuers = []config.OIDCIssuerConfig{
					{Issuer: "https://idp.example.com"},
					{Issuer: "https://idp.example.com"},
				}
			},
		},
		{
			name: "non-url issuer without jwks_url or discovery_url",
			edit: func(c *config.Config) {
				c.Auth.OIDCIssuers = []config.OIDCIssuerConfig{{Issuer: "urn:corp:idp"}}
			},
		},
		{
			name: "alg none disallowed",
			edit: func(c *config.Config) {
				c.Auth.OIDCIssuers = []config.OIDCIssuerConfig{
					{Issuer: "https://idp.example.com", Algorithms: []string{"none"}},
				}
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := config.Default()
			c.Server.Environment = "test"
			tc.edit(c)
			if err := c.Validate(); err == nil {
				t.Fatalf("expected validation error for %s", tc.name)
			}
		})
	}
}

func TestConfig_FinOpsSoftBudgetYAMLAndValidation(t *testing.T) {
	yamlContent := `
server:
  environment: test
finops:
  soft_budget_webhook_url: "https://alerts.example.com/soft-budget"
  soft_budget_cooldown_sec: 900
  budget_exceeded_throttle_pct: 0.25
`
	tmpPath := filepath.Join(t.TempDir(), "finops_config.yaml")
	if err := os.WriteFile(tmpPath, []byte(yamlContent), 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}
	cfg, err := config.Load(tmpPath)
	if err != nil {
		t.Fatalf("load finops config: %v", err)
	}
	if cfg.FinOps.SoftBudgetWebhookURL != "https://alerts.example.com/soft-budget" {
		t.Fatalf("SoftBudgetWebhookURL = %q", cfg.FinOps.SoftBudgetWebhookURL)
	}
	if cfg.FinOps.SoftBudgetCooldownSec != 900 {
		t.Fatalf("SoftBudgetCooldownSec = %d, want 900", cfg.FinOps.SoftBudgetCooldownSec)
	}
	if cfg.FinOps.BudgetExceededThrottlePct != 0.25 {
		t.Fatalf("BudgetExceededThrottlePct = %v, want 0.25", cfg.FinOps.BudgetExceededThrottlePct)
	}

	cases := []struct {
		name string
		edit func(*config.Config)
	}{
		{
			name: "invalid webhook scheme",
			edit: func(c *config.Config) {
				c.FinOps.SoftBudgetWebhookURL = "ftp://alerts.example.com/hook"
			},
		},
		{
			name: "negative cooldown",
			edit: func(c *config.Config) {
				c.FinOps.SoftBudgetCooldownSec = -1
			},
		},
		{
			name: "throttle pct > 1",
			edit: func(c *config.Config) {
				c.FinOps.BudgetExceededThrottlePct = 1.5
			},
		},
		{
			name: "throttle pct < 0",
			edit: func(c *config.Config) {
				c.FinOps.BudgetExceededThrottlePct = -0.1
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := config.Default()
			c.Server.Environment = "test"
			tc.edit(c)
			if err := c.Validate(); err == nil {
				t.Fatalf("expected validation error for %s", tc.name)
			}
		})
	}
}

func TestSSOProvidersConfigYAMLAndValidation(t *testing.T) {
	t.Setenv("GATEWAY_ENV", "test")

	yamlContent := `
server:
  port: 8080
  environment: "test"
auth:
  sso_providers:
    - id: "google"
      display_name: "Google SSO"
      client_id: "google-cid"
      client_secret: "os.environ/GOOGLE_SSO_SECRET"
      allowed_email_domains: ["acme.example.com"]
      auto_register: true
      default_org_id: "org_default"
      default_role: "org_viewer"
    - name: "microsoft"
      tenant_id: "tenant-123"
      client_id: "ms-cid"
      scopes: ["openid", "email", "profile"]
    - id: "oidc"
      display_name: "Enterprise OIDC"
      client_id: "oidc-cid"
      issuer: "https://idp.example.com"
`
	tmpPath := filepath.Join(t.TempDir(), "sso-config.yaml")
	if err := os.WriteFile(tmpPath, []byte(yamlContent), 0600); err != nil {
		t.Fatalf("write sso config: %v", err)
	}
	cfg, err := config.Load(tmpPath)
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	if len(cfg.Auth.SSOProviders) != 3 {
		t.Fatalf("expected 3 sso_providers, got %d", len(cfg.Auth.SSOProviders))
	}
	if cfg.Auth.SSOProviders[1].TenantID != "tenant-123" {
		t.Fatalf("expected microsoft tenant_id=tenant-123, got %q", cfg.Auth.SSOProviders[1].TenantID)
	}

	// Negative validation cases
	invalidCases := []struct {
		name      string
		providers []config.SSOProviderConfig
	}{
		{
			name:      "missing id and name",
			providers: []config.SSOProviderConfig{{ClientID: "cid"}},
		},
		{
			name: "duplicate id/name",
			providers: []config.SSOProviderConfig{
				{ID: "google", ClientID: "c1"},
				{Name: "google", ClientID: "c2"},
			},
		},
		{
			name:      "missing client_id",
			providers: []config.SSOProviderConfig{{ID: "google"}},
		},
		{
			name:      "oidc without endpoints or issuer",
			providers: []config.SSOProviderConfig{{ID: "custom", ClientID: "cid"}},
		},
		{
			name:      "invalid discovery_url",
			providers: []config.SSOProviderConfig{{ID: "custom", ClientID: "cid", DiscoveryURL: "ftp://idp.example.com"}},
		},
		{
			name:      "disallowed none algorithm",
			providers: []config.SSOProviderConfig{{ID: "google", ClientID: "cid", Algorithms: []string{"none"}}},
		},
	}
	for _, tc := range invalidCases {
		t.Run(tc.name, func(t *testing.T) {
			c := config.Default()
			c.Server.Environment = "test"
			c.Auth.SSOProviders = tc.providers
			if err := c.Validate(); err == nil {
				t.Fatalf("expected validation error for %s", tc.name)
			}
		})
	}
}

func TestConfig_PreviousKEKsAndKeyRotationSinkValidation(t *testing.T) {
	t.Run("rejects short previous_master_encryption_keys", func(t *testing.T) {
		c := config.Default()
		c.Server.Environment = "test"
		c.Auth.MasterEncryptionKey = strings.Repeat("a", 32)
		c.Auth.PreviousMasterEncryptionKeys = []string{"too-short"}
		if err := c.Validate(); err == nil {
			t.Fatal("expected error for short previous master encryption key")
		}
	})

	t.Run("loads env overrides for previous keys and sink", func(t *testing.T) {
		t.Setenv("GATEWAY_ENV", "test")
		t.Setenv("GATEWAY_PREVIOUS_MASTER_ENCRYPTION_KEYS", "prev-key-1-012345678901234567890123, prev-key-2-012345678901234567890123")
		t.Setenv("GATEWAY_KEY_ROTATION_SINK_DRIVER", "vault_kv2")
		t.Setenv("GATEWAY_KEY_ROTATION_SINK_ADDRESS", "https://vault.internal.example:8200")
		t.Setenv("GATEWAY_KEY_ROTATION_SINK_TOKEN", "hvs.test-token")
		t.Setenv("GATEWAY_KEY_ROTATION_SINK_MOUNT", "kv")
		t.Setenv("GATEWAY_KEY_ROTATION_SINK_PATH_PREFIX", "goroute/rotated")

		cfg, err := config.Load("")
		if err != nil {
			t.Fatalf("config.Load: %v", err)
		}
		if len(cfg.Auth.PreviousMasterEncryptionKeys) != 2 {
			t.Fatalf("expected 2 previous keys from env, got %v", cfg.Auth.PreviousMasterEncryptionKeys)
		}
		if cfg.Auth.KeyRotationSink.Driver != "vault_kv2" || cfg.Auth.KeyRotationSink.Mount != "kv" || cfg.Auth.KeyRotationSink.PathPrefix != "goroute/rotated" {
			t.Fatalf("unexpected sink env override: %+v", cfg.Auth.KeyRotationSink)
		}
	})

	t.Run("rejects unsupported or incomplete sink and delivery config", func(t *testing.T) {
		cases := []struct {
			name string
			mod  func(*config.AuthConfig)
		}{
			{
				name: "unsupported driver",
				mod:  func(a *config.AuthConfig) { a.KeyRotationSink = config.KeyRotationSinkConfig{Driver: "gcp_sm"} },
			},
			{
				name: "delivery url without token",
				mod:  func(a *config.AuthConfig) { a.KeyRotationDeliveryURL = "https://vault.example.com/hook" },
			},
			{
				name: "delivery url plain http",
				mod: func(a *config.AuthConfig) {
					a.KeyRotationDeliveryURL = "http://vault.example.com/hook"
					a.KeyRotationDeliveryToken = "tok"
				},
			},
			{
				name: "webhook sink missing address",
				mod: func(a *config.AuthConfig) {
					a.KeyRotationSink = config.KeyRotationSinkConfig{Driver: "webhook", Token: "tok"}
				},
			},
			{
				name: "webhook sink missing token",
				mod: func(a *config.AuthConfig) {
					a.KeyRotationSink = config.KeyRotationSinkConfig{Driver: "webhook", Address: "https://vault.example.com/hook"}
				},
			},
			{
				name: "vault_kv2 sink missing token",
				mod: func(a *config.AuthConfig) {
					a.KeyRotationSink = config.KeyRotationSinkConfig{Driver: "vault_kv2", Address: "https://vault.example.com"}
				},
			},
			{
				name: "vault_kv2 sink http address",
				mod: func(a *config.AuthConfig) {
					a.KeyRotationSink = config.KeyRotationSinkConfig{Driver: "vault_kv2", Address: "http://vault.example.com", Token: "tok"}
				},
			},
			{
				name: "unsupported aws_secrets_manager sink driver",
				mod: func(a *config.AuthConfig) {
					a.KeyRotationSink = config.KeyRotationSinkConfig{Driver: "aws_secrets_manager"}
				},
			},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				c := config.Default()
				c.Server.Environment = "test"
				tc.mod(&c.Auth)
				if err := c.Validate(); err == nil {
					t.Fatalf("expected validation error for %s", tc.name)
				}
			})
		}

		// Valid webhook reusing legacy delivery url without duplicating sink address succeeds.
		ok := config.Default()
		ok.Server.Environment = "test"
		ok.Auth.KeyRotationDeliveryURL = "https://vault.example.com/hook"
		ok.Auth.KeyRotationDeliveryToken = "tok"
		ok.Auth.KeyRotationSink = config.KeyRotationSinkConfig{Driver: "webhook"}
		if err := ok.Validate(); err != nil {
			t.Fatalf("expected webhook inheriting delivery_url to validate, got %v", err)
		}
	})
}
