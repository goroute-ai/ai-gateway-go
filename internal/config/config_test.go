package config_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

func TestResolveEnvValueAndParseProviderModel(t *testing.T) {
	t.Setenv("TEST_GEMINI_KEY", "AIzaSyTest123")
	t.Setenv("TEST_CLAUDE_KEY", "sk-ant-Test456")

	if got := config.ResolveEnvValue("os.environ/TEST_GEMINI_KEY"); got != "AIzaSyTest123" {
		t.Fatalf("expected AIzaSyTest123, got %q", got)
	}
	if got := config.ResolveEnvValue("${TEST_CLAUDE_KEY}"); got != "sk-ant-Test456" {
		t.Fatalf("expected sk-ant-Test456, got %q", got)
	}
	if got := config.ResolveEnvValue("$TEST_GEMINI_KEY"); got != "AIzaSyTest123" {
		t.Fatalf("expected AIzaSyTest123, got %q", got)
	}
	if got := config.ResolveEnvValue("sk-literal-key"); got != "sk-literal-key" {
		t.Fatalf("expected literal key unchanged, got %q", got)
	}

	prov, bare, globalID := config.ParseProviderModel("gemini/gemini-2.5-flash")
	if prov != domain.ProviderGemini || bare != "gemini-2.5-flash" || globalID != "gemini/gemini-2.5-flash" {
		t.Fatalf("unexpected ParseProviderModel for gemini/gemini-2.5-flash: %v %v %v", prov, bare, globalID)
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
      model: gemini/gemini-2.5-flash
      api_key: os.environ/GEMINI_API_KEY
  - model_name: reasoning
    model_params:
      model: anthropic/claude-sonnet-4-20250514
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
	if cfg.ModelList[0].ModelName != "fast" || cfg.ModelList[0].ModelParams.Model != "gemini/gemini-2.5-flash" {
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
providers:
  custom_openai_compatible:
    - id: "vllm-local"
      display_name: "vLLM"
      base_url: "http://127.0.0.1:8000/v1"
      supported_operations: ["chat", "embeddings"]
      param_mappings:
        max_completion_tokens: "max_tokens"
      reasoning_mapping: "chat_template_thinking"
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
	cp := cfg.Providers.CustomOpenAICompatible[0]
	if len(cp.SupportedOperations) != 2 || cp.ParamMappings["max_completion_tokens"] != "max_tokens" || cp.ReasoningMapping != "chat_template_thinking" {
		t.Fatalf("unexpected custom provider config: %+v", cp)
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
