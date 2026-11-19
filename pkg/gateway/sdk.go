package gateway

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/goroute-ai/ai-gateway-go/internal/a2a"
	"github.com/goroute-ai/ai-gateway-go/internal/a2a/pb"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/logger"
	"github.com/goroute-ai/ai-gateway-go/internal/mcp"
	"github.com/goroute-ai/ai-gateway-go/internal/server"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/redis/go-redis/v9"
	"gopkg.in/yaml.v3"
	"nhooyr.io/websocket"
)

// ModelEntry defines a declarative model mapping item for in-code or YAML router setup.
type ModelEntry struct {
	ModelName              string           // Client-facing model name or alias (e.g. "fast", "reasoning", "gemini-2.5-flash")
	Model                  string           // Upstream provider/model (e.g. "gemini/gemini-2.5-flash", "anthropic/claude-sonnet-4-20250514")
	APIKey                 string           // Literal key or "os.environ/GEMINI_API_KEY"
	APIBase                string           // Optional custom upstream endpoint
	RoutingStrategy        string           // Optional: "weighted-shuffle", "least-busy", "latency-based", "lowest-cost", "priority-tiered", "fastest-response"
	Fallbacks              []string         // Optional: ordered fallback model group aliases (e.g. []string{"backup-claude"})
	ContextWindowFallbacks []string         // Optional: ordered fallback group aliases when input exceeds context window
	ContentPolicyFallbacks []string         // Optional: ordered fallback group aliases on content policy / safety refusals
	FallbackTargets        []FallbackTarget // Optional: structured fallback targets with parameter overrides
	Region                 string           // Optional: deployment region (e.g. "us-east-1", "eu-west-1")
	Priority               int              // Optional: priority tier (0 is highest priority; higher values are lower priority tiers)
	Tags                   []string         // Optional: deployment tags for tag-based request filtering
	MaxBudgetMicros        int64            // Optional: per-deployment spend budget cap in micro-dollars (1 USD = 1,000,000 micros)
	BudgetResetPeriod      string           // Optional: budget reset period ("hourly", "daily", "weekly", "monthly")
	Weight                 int
	RPM                    int
	TPM                    int
	SimulateStatus         int // Optional fault-injection HTTP status (e.g. 503) for local failover/circuit-breaker testing
}

// ChatResult wraps the OpenAI-compatible response together with unpacked gateway telemetry headers
// and a top-level `.Content` field for 1-line developer ergonomics.
type ChatResult struct {
	Content           string                       `json:"content"`
	ReasoningContent  string                       `json:"reasoning_content,omitempty"`
	Provider          string                       `json:"provider"`
	Model             string                       `json:"model"`
	WinningDeployment string                       `json:"winning_deployment,omitempty"`
	RequestID         string                       `json:"request_id"`
	CostMicros        int64                        `json:"cost_micros"`
	RoutingMicros     int64                        `json:"routing_micros"`
	CacheStatus       string                       `json:"cache_status,omitempty"`
	RouteReason       string                       `json:"route_reason,omitempty"`
	FallbackAttempted bool                         `json:"fallback_attempted,omitempty"`
	FallbackReason    string                       `json:"fallback_reason,omitempty"`
	TierStepdowns     int                          `json:"tier_stepdowns,omitempty"`
	StreamContinued   bool                         `json:"stream_continued,omitempty"`
	Usage             domain.TokenUsage            `json:"usage"`
	Raw               domain.CanonicalChatResponse `json:"raw"`
}

// Client provides a unified developer SDK for interacting with the Enterprise AI Gateway
// (either embedded in-process or connected to a remote gateway server).
type Client struct {
	baseURL     string
	apiKey      string
	masterKey   string
	httpClient  *http.Client
	embeddedGW  *server.GatewayServer
	embeddedTS  *httptest.Server
	repo        storage.Repository
	redisFabric *storage.RedisFabric
	mockServers []*httptest.Server
	closeFns    []func()
	borrowed    bool
}

// Option configures a Gateway Client or Embedded Router.
type Option func(*clientConfig)

type clientConfig struct {
	customAuthMode        CustomAuthMode
	customAuthenticator   CustomAuthenticator
	configPath            string
	remoteURL             string
	apiKey                string
	modelList             []ModelEntry
	httpClient            *http.Client
	demoMocksFallback     bool
	allowPrivateNetworks  bool
	customLogger          *slog.Logger
	silentLogs            bool
	logLevel              string
	guardrailScanners     []guardrailScannerEntry
	routingPlugins        []routingPluginEntry
	preRouters            []preRouterEntry
	preRouterAliases      []preRouterAliasEntry
	routerMutations       []func(*config.RouterConfig)
	keyRotationSecretSink KeySecretSink
}

// WithKeyRotationSecretSink registers a KeySecretSink for scheduled virtual key rotations in embedded mode.
func WithKeyRotationSecretSink(sink KeySecretSink) Option {
	return func(c *clientConfig) {
		c.keyRotationSecretSink = sink
	}
}

// WithLogger configures a custom slog.Logger for embedded gateway operation.
func WithLogger(l *slog.Logger) Option {
	return func(c *clientConfig) {
		c.customLogger = l
	}
}

// WithSilentLogs disables stdout logging for embedded gateway operations.
func WithSilentLogs() Option {
	return func(c *clientConfig) {
		c.silentLogs = true
	}
}

// WithLogLevel sets the minimum logging level (e.g. "debug", "info", "warn", "error") for the embedded gateway.
func WithLogLevel(level string) Option {
	return func(c *clientConfig) {
		c.logLevel = level
	}
}

// WithConfigFile loads the gateway configuration (including `model_list`) from a YAML file.
func WithConfigFile(path string) Option {
	return func(c *clientConfig) {
		c.configPath = path
	}
}

// WithModelList configures the embedded gateway router declaratively.
func WithModelList(entries ...ModelEntry) Option {
	return func(c *clientConfig) {
		c.modelList = append(c.modelList, entries...)
	}
}

// WithRemote connects the SDK client to an external running gateway server instead of starting an embedded instance.
func WithRemote(baseURL, apiKey string) Option {
	return func(c *clientConfig) {
		c.remoteURL = strings.TrimRight(strings.TrimSpace(baseURL), "/")
		c.apiKey = strings.TrimSpace(apiKey)
	}
}

// WithHTTPClient configures a custom *http.Client for remote gateway and WebSocket dialer requests.
func WithHTTPClient(hc *http.Client) Option {
	return func(c *clientConfig) {
		if hc != nil {
			c.httpClient = hc
		}
	}
}

// WithDemoMocksIfEnvMissing enables built-in local mock providers for any `ModelEntry` whose
// environment variable API key is not set, allowing demos and local quickstarts to run with zero setup.
func WithDemoMocksIfEnvMissing() Option {
	return func(c *clientConfig) {
		c.demoMocksFallback = true
	}
}

// WithAllowPrivateNetworks permits connections to local or private network addresses (e.g. for mock testing or local Ollama).
func WithAllowPrivateNetworks() Option {
	return func(c *clientConfig) {
		c.allowPrivateNetworks = true
	}
}

// WithGuardrailScanner registers an in-process custom GuardrailScanner plugin on the embedded
// gateway's unified guardrail pipeline.
func WithGuardrailScanner(name string, scanner GuardrailScanner, opts ...GuardrailOption) Option {
	return func(c *clientConfig) {
		c.guardrailScanners = append(c.guardrailScanners, guardrailScannerEntry{
			name:    name,
			scanner: scanner,
			opts:    append([]GuardrailOption(nil), opts...),
		})
	}
}

// New initializes a Gateway Client.
//   - If `WithRemote(url, key)` is provided, it connects to that remote gateway.
//   - Otherwise, it starts an embedded in-memory Gateway auto-configured from `WithModelList(...)`,
//     `WithConfigFile(...)`, and/or standard environment variables (`GEMINI_API_KEY`, `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`).
func New(opts ...Option) (*Client, error) {
	cc := &clientConfig{
		httpClient: http.DefaultClient,
	}
	for _, opt := range opts {
		opt(cc)
	}

	mode, authModeErr := ParseCustomAuthMode(string(cc.customAuthMode))
	if authModeErr != nil {
		return nil, authModeErr
	}
	if cc.silentLogs {
		logger.Init(logger.Config{Output: io.Discard})
	} else if cc.customLogger != nil {
		slog.SetDefault(cc.customLogger)
	} else if cc.logLevel != "" {
		logger.Init(logger.Config{Level: cc.logLevel})
	}

	if cc.remoteURL != "" {
		if mode != CustomAuthModeOff {
			return nil, fmt.Errorf("WithCustomAuthenticator requires an embedded gateway")
		}
		if len(cc.guardrailScanners) > 0 {
			return nil, fmt.Errorf("WithGuardrailScanner requires an embedded gateway and cannot be combined with WithRemote")
		}
		if len(cc.routingPlugins) > 0 {
			return nil, fmt.Errorf("WithRoutingPlugin requires an embedded gateway and cannot be combined with WithRemote")
		}
		if len(cc.preRouters) > 0 || len(cc.preRouterAliases) > 0 {
			return nil, fmt.Errorf("WithPreRouter requires an embedded gateway and cannot be combined with WithRemote")
		}
		client := NewClient(cc.remoteURL, cc.apiKey)
		if cc.httpClient != nil {
			client.httpClient = cc.httpClient
		}
		return client, nil
	}

	var cfg *config.Config
	var err error
	if cc.configPath != "" {
		cfg, err = config.Load(cc.configPath)
	} else {
		cfg, err = config.LoadWithDefaultEnvironment("", "development")
	}
	if err != nil {
		return nil, err
	}
	for _, mut := range cc.routerMutations {
		if mut != nil {
			mut(&cfg.Router)
		}
	}

	var mockServers []*httptest.Server
	var mockGemURL, mockClaudeURL, mockOpenAIURL string
	if cc.demoMocksFallback || cc.allowPrivateNetworks {
		cfg.Security.Network.OutboundSSRF.AllowPrivateNetworks = true
		cfg.Security.Network.OutboundSSRF.AllowInsecureHTTP = true
	}
	if cc.demoMocksFallback {
		mockGem := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, "streamGenerateContent") {
				w.Header().Set("Content-Type", "text/event-stream")
				fmt.Fprint(w, "data: {\"candidates\":[{\"index\":0,\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"GoRoute AI Gateway \"}]}}]}\n\n")
				fmt.Fprint(w, "data: {\"candidates\":[{\"index\":0,\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"streams SSE tokens with \"}]}}]}\n\n")
				fmt.Fprint(w, "data: {\"candidates\":[{\"index\":0,\"content\":{\"role\":\"model\",\"parts\":[{\"text\":\"sub-millisecond routing overhead.\"}]},\"finishReason\":\"STOP\"}],\"usageMetadata\":{\"promptTokenCount\":14,\"candidatesTokenCount\":16,\"totalTokenCount\":30}}\n\n")
				return
			}
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"candidates":[{"index":0,"content":{"role":"model","parts":[{"text":"Pure Go code compiles directly to native machine code without Cgo or external runtime dependencies."}]},"finishReason":"STOP"}],"usageMetadata":{"promptTokenCount":12,"candidatesTokenCount":18,"totalTokenCount":30}}`)
		}))
		mockClaude := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"id":"msg_demo","type":"message","role":"assistant","model":"claude-sonnet-4-20250514","content":[{"type":"text","text":"Raft guarantees election safety via monotonic term numbers and majority quorum intersection."}],"stop_reason":"end_turn","usage":{"input_tokens":28,"output_tokens":36}}`)
		}))
		mockOpenAI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			if strings.HasSuffix(r.URL.Path, "/embeddings") {
				fmt.Fprint(w, `{"object":"list","data":[{"object":"embedding","index":0,"embedding":[0.023,-0.041,0.088,0.114]}],"model":"text-embedding-3-small","usage":{"prompt_tokens":8,"total_tokens":8}}`)
				return
			}
			fmt.Fprint(w, `{"id":"chatcmpl_demo","object":"chat.completion","created":1730000000,"model":"gpt-4.1-mini","choices":[{"index":0,"message":{"role":"assistant","content":"OpenAI GPT-4.1-mini handled this request through the unified canonical gateway contract."},"finish_reason":"stop"}],"usage":{"prompt_tokens":15,"completion_tokens":19,"total_tokens":34}}`)
		}))
		mockServers = append(mockServers, mockGem, mockClaude, mockOpenAI)
		mockGemURL = mockGem.URL
		mockClaudeURL = mockClaude.URL
		mockOpenAIURL = mockOpenAI.URL
	}

	for _, e := range cc.modelList {
		rawBase := config.ResolveEnvValue(e.APIBase)
		if strings.HasPrefix(rawBase, "http://127.0.0.1") || strings.HasPrefix(rawBase, "http://localhost") || strings.HasPrefix(e.Model, "ollama/") || e.SimulateStatus >= 400 {
			cfg.Security.Network.OutboundSSRF.AllowPrivateNetworks = true
			cfg.Security.Network.OutboundSSRF.AllowInsecureHTTP = true
		}
	}

	for _, e := range cc.modelList {
		apiKey := config.ResolveEnvValue(e.APIKey)
		apiBase := config.ResolveEnvValue(e.APIBase)
		prov, _, _ := config.ParseProviderModel(e.Model)

		if e.SimulateStatus >= 400 {
			status := e.SimulateStatus
			faultSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(status)
				fmt.Fprintf(w, `{"error":{"message":"simulated upstream status %d","type":"upstream_error"}}`, status)
			}))
			mockServers = append(mockServers, faultSrv)
			apiBase = faultSrv.URL
			if apiKey == "" {
				apiKey = "simulated-fault-key"
			}
		} else if apiKey == "" && cc.demoMocksFallback {
			apiKey = "demo-mock-key"
			if apiBase == "" {
				switch prov {
				case domain.ProviderGemini:
					apiBase = mockGemURL
				case domain.ProviderAnthropic:
					apiBase = mockClaudeURL
				default:
					apiBase = mockOpenAIURL
				}
			}
		}

		cfg.ModelList = append(cfg.ModelList, config.ModelListEntry{
			ModelName:              e.ModelName,
			RoutingStrategy:        e.RoutingStrategy,
			Fallbacks:              slices.Clone(e.Fallbacks),
			ContextWindowFallbacks: toDomainFallbackTargets(e.ContextWindowFallbacks),
			ContentPolicyFallbacks: toDomainFallbackTargets(e.ContentPolicyFallbacks),
			FallbackTargets:        convertFallbackTargets(e.FallbackTargets),
			ModelParams: config.ModelParams{
				Model:             e.Model,
				APIKey:            apiKey,
				APIBase:           apiBase,
				Region:            e.Region,
				Weight:            e.Weight,
				RPM:               e.RPM,
				TPM:               e.TPM,
				Priority:          e.Priority,
				Tags:              slices.Clone(e.Tags),
				MaxBudgetMicros:   e.MaxBudgetMicros,
				BudgetResetPeriod: e.BudgetResetPeriod,
			},
		})
	}

	if cfg.Auth.DefaultVirtualKey == "" {
		cfg.Auth.DefaultVirtualKey = "sk-gw-sdk-" + uuid.NewString()
	}

	var repo storage.Repository
	var redisFabric *storage.RedisFabric
	var closeFns []func()
	cleanupOnErr := func() {
		for _, fn := range closeFns {
			fn()
		}
		for _, ms := range mockServers {
			ms.Close()
		}
	}

	var rawCfgFile struct {
		Storage struct {
			Mode        string   `yaml:"mode"`
			PostgresDSN string   `yaml:"postgres_dsn"`
			RedisAddr   string   `yaml:"redis_addr"`
			RedisAddrs  []string `yaml:"redis_addrs"`
		} `yaml:"storage"`
		Database struct {
			URL string `yaml:"url"`
			DSN string `yaml:"dsn"`
		} `yaml:"database"`
		Redis struct {
			URL   string   `yaml:"url"`
			Addr  string   `yaml:"addr"`
			Addrs []string `yaml:"addrs"`
		} `yaml:"redis"`
	}
	if cc.configPath != "" {
		if rawBytes, readErr := os.ReadFile(cc.configPath); readErr == nil {
			_ = yaml.Unmarshal(rawBytes, &rawCfgFile)
		}
		if rawCfgFile.Database.URL != "" {
			cfg.Storage.PostgresDSN = config.ResolveEnvValue(rawCfgFile.Database.URL)
			if rawCfgFile.Storage.Mode == "" {
				cfg.Storage.Mode = "postgres"
			}
		} else if rawCfgFile.Database.DSN != "" {
			cfg.Storage.PostgresDSN = config.ResolveEnvValue(rawCfgFile.Database.DSN)
			if rawCfgFile.Storage.Mode == "" {
				cfg.Storage.Mode = "postgres"
			}
		} else if rawCfgFile.Storage.PostgresDSN != "" && rawCfgFile.Storage.Mode == "" {
			cfg.Storage.Mode = "postgres"
		}
		if rawCfgFile.Redis.URL != "" {
			cfg.Storage.RedisAddr = config.ResolveEnvValue(rawCfgFile.Redis.URL)
		} else if rawCfgFile.Redis.Addr != "" {
			cfg.Storage.RedisAddr = config.ResolveEnvValue(rawCfgFile.Redis.Addr)
		}
		if len(rawCfgFile.Redis.Addrs) > 0 && len(cfg.Storage.RedisAddrs) == 0 {
			cfg.Storage.RedisAddrs = rawCfgFile.Redis.Addrs
		}
	}

	if cc.configPath != "" && cfg.Storage.Mode == "postgres" && strings.TrimSpace(cfg.Storage.PostgresDSN) != "" {
		pool, poolErr := storage.NewPostgresPool(context.Background(), cfg.Storage.PostgresDSN)
		if poolErr != nil {
			cleanupOnErr()
			return nil, fmt.Errorf("connect postgres: %w", poolErr)
		}
		closeFns = append(closeFns, pool.Close)
		if migErr := storage.RunMigrationsDir(context.Background(), pool, "migrations"); migErr != nil {
			slog.Warn("embedded sdk migration notice", slog.String("error", migErr.Error()))
		}
		pgRepo, repoErr := storage.NewPostgresRepository(context.Background(), pool)
		if repoErr != nil {
			cleanupOnErr()
			return nil, fmt.Errorf("init postgres repository: %w", repoErr)
		}
		repo = pgRepo
	} else {
		repo = storage.NewMemoryRepository()
	}

	explicitRedisConfigured := rawCfgFile.Storage.RedisAddr != "" || len(rawCfgFile.Storage.RedisAddrs) > 0 || rawCfgFile.Redis.URL != "" || rawCfgFile.Redis.Addr != "" || len(rawCfgFile.Redis.Addrs) > 0
	if cc.configPath != "" && (explicitRedisConfigured || len(cfg.Storage.RedisAddrs) > 0 || (strings.TrimSpace(cfg.Storage.RedisAddr) != "" && (cfg.Storage.Mode == "postgres" || cfg.Storage.RedisAddr != "localhost:6379"))) {
		rawAddr := strings.TrimSpace(cfg.Storage.RedisAddr)
		if len(cfg.Storage.RedisAddrs) == 0 && (strings.HasPrefix(rawAddr, "redis://") || strings.HasPrefix(rawAddr, "rediss://")) {
			opt, parseErr := redis.ParseURL(rawAddr)
			if parseErr != nil {
				cleanupOnErr()
				return nil, fmt.Errorf("parse redis url: %w", parseErr)
			}
			redisFabric = storage.NewRedisFabricWithOptions(&redis.UniversalOptions{
				Addrs:      []string{opt.Addr},
				Username:   opt.Username,
				Password:   opt.Password,
				DB:         opt.DB,
				TLSConfig:  opt.TLSConfig,
				MasterName: cfg.Storage.RedisMasterName,
			})
		} else {
			addrs := cfg.Storage.RedisAddrs
			if len(addrs) == 0 {
				addrs = []string{rawAddr}
			}
			redisFabric = storage.NewRedisFabricWithOptions(&redis.UniversalOptions{
				Addrs:      addrs,
				MasterName: cfg.Storage.RedisMasterName,
				Password:   cfg.Storage.RedisPass,
				DB:         cfg.Storage.RedisDB,
			})
		}
		if redisFabric != nil && redisFabric.Client() != nil {
			rdb := redisFabric.Client()
			closeFns = append(closeFns, func() { _ = rdb.Close() })
		}
	}

	gw, err := server.New(cfg, repo, redisFabric, nil)
	if err != nil {
		cleanupOnErr()
		return nil, err
	}
	if len(cc.guardrailScanners) > 0 {
		orgID := strings.TrimSpace(cfg.Auth.DefaultOrgID)
		if orgID == "" {
			orgID = "org_default"
		}
		for idx, entry := range cc.guardrailScanners {
			if regErr := registerSDKGuardrailScanner(context.Background(), gw, repo, orgID, idx, entry); regErr != nil {
				gw.Shutdown(context.Background())
				cleanupOnErr()
				return nil, regErr
			}
		}
	}
	if len(cc.routingPlugins) > 0 || len(cc.preRouters) > 0 || len(cc.preRouterAliases) > 0 {
		if regErr := registerSDKRoutingHooks(gw, cc.routingPlugins, cc.preRouters, cc.preRouterAliases); regErr != nil {
			gw.Shutdown(context.Background())
			cleanupOnErr()
			return nil, regErr
		}
	}
	if mode != CustomAuthModeOff {
		gw.AuthResolver().SetEmbeddedAuthenticator(func(ctx context.Context, req *http.Request) (*domain.IdentityContext, error) {
			decision, err := EvaluateCustomAuth(ctx, req, mode, cc.customAuthenticator)
			if err != nil || decision == nil {
				return nil, err
			}
			if vKey := strings.TrimSpace(decision.VirtualKey); vKey != "" {
				if !strings.HasPrefix(vKey, "sk-gw-") {
					return nil, &domain.GatewayError{
						StatusCode: http.StatusUnauthorized,
						Type:       domain.ErrorTypeAuthentication,
						Code:       "invalid_custom_auth_key",
						Message:    "Custom auth must return a gateway virtual key",
					}
				}
				return gw.AuthService().AuthenticateVirtualKey(ctx, vKey)
			}
			identity := *decision.Identity
			if !decision.RunPostChecks {
				identity = domain.IdentityContext{
					OrgID:            identity.OrgID,
					TeamID:           identity.TeamID,
					UserID:           identity.UserID,
					ProjectID:        identity.ProjectID,
					VirtualKeyID:     identity.VirtualKeyID,
					KeyPrefix:        identity.KeyPrefix,
					KeyType:          identity.KeyType,
					Role:             identity.Role,
					Principal:        identity.Principal,
					AllowedEndpoints: []string{"*"},
				}
			} else if len(identity.AllowedEndpoints) == 0 {
				identity.AllowedEndpoints = []string{"*"}
			}
			return &identity, nil
		})
	}
	if cc.keyRotationSecretSink != nil {
		gw.SetKeyRotationSecretSink(cc.keyRotationSecretSink)
	}
	gw.StartWorkers(context.Background())

	ts := httptest.NewServer(gw.Handler())
	apiKey := cfg.Auth.DefaultVirtualKey
	if apiKey == "" {
		apiKey = cfg.Auth.MasterAdminKey
	}

	return &Client{
		baseURL:     ts.URL,
		apiKey:      apiKey,
		masterKey:   cfg.Auth.MasterAdminKey,
		httpClient:  cc.httpClient,
		embeddedGW:  gw,
		embeddedTS:  ts,
		repo:        repo,
		redisFabric: redisFabric,
		mockServers: mockServers,
		closeFns:    closeFns,
	}, nil
}

// NewClient creates a lightweight SDK client pointing to an already-running Gateway URL and Virtual API Key.
func NewClient(baseURL, apiKey string) *Client {
	cleanKey := strings.TrimSpace(apiKey)
	return &Client{
		baseURL:    strings.TrimRight(strings.TrimSpace(baseURL), "/"),
		apiKey:     cleanKey,
		masterKey:  cleanKey,
		httpClient: http.DefaultClient,
	}
}

// WithKey returns a shallow copy of Client authenticated with the given Virtual API Key (`sk-gw-...`),
// preserving any embedded gateway server, repository, and Redis handles.
func (c *Client) WithKey(virtualKey string) *Client {
	return &Client{
		baseURL:     c.baseURL,
		apiKey:      strings.TrimSpace(virtualKey),
		masterKey:   c.masterKey,
		httpClient:  c.httpClient,
		embeddedGW:  c.embeddedGW,
		embeddedTS:  c.embeddedTS,
		repo:        c.repo,
		redisFabric: c.redisFabric,
		mockServers: c.mockServers,
		closeFns:    c.closeFns,
		borrowed:    true,
	}
}

// Close cleanly shuts down the embedded gateway server and workers (no-op for remote or borrowed clients).
func (c *Client) Close() {
	if c == nil || c.borrowed {
		return
	}
	if c.embeddedGW != nil {
		c.embeddedGW.Shutdown(context.Background())
	}
	if c.embeddedTS != nil {
		c.embeddedTS.Close()
	}
	for _, fn := range c.closeFns {
		fn()
	}
	for _, ms := range c.mockServers {
		ms.Close()
	}
}

// SetKeyRotationSecretSink updates the embedded gateway's KeySecretSink at runtime (no-op on remote clients).
func (c *Client) SetKeyRotationSecretSink(sink KeySecretSink) {
	if c == nil || c.embeddedGW == nil {
		return
	}
	c.embeddedGW.SetKeyRotationSecretSink(sink)
}

// BaseURL returns the HTTP base URL of the gateway (useful when exposing an embedded gateway or inspecting endpoints).
func (c *Client) BaseURL() string {
	return c.baseURL
}

// RequestOption customizes a `Chat` or `StreamChat` call.
type RequestOption func(*domain.CanonicalChatRequest)

// WithSystem prepends a system instruction message to the chat request.
func WithSystem(systemPrompt string) RequestOption {
	return func(r *domain.CanonicalChatRequest) {
		if strings.TrimSpace(systemPrompt) == "" {
			return
		}
		msgs := make([]domain.CanonicalMessage, 0, len(r.Messages)+1)
		msgs = append(msgs, domain.CanonicalMessage{Role: "system", Content: systemPrompt})
		msgs = append(msgs, r.Messages...)
		r.Messages = msgs
	}
}

// WithTemperature sets the sampling temperature (0.0 to 2.0).
func WithTemperature(temp float64) RequestOption {
	return func(r *domain.CanonicalChatRequest) {
		r.Temperature = &temp
	}
}

// WithMaxTokens sets the maximum output tokens (`max_tokens`).
func WithMaxTokens(maxTokens int) RequestOption {
	return func(r *domain.CanonicalChatRequest) {
		r.MaxTokens = &maxTokens
	}
}

// WithReasoningEffort sets the reasoning effort ("low", "medium", "high").
func WithReasoningEffort(effort string) RequestOption {
	return func(r *domain.CanonicalChatRequest) {
		r.ReasoningEffort = effort
	}
}

// Chat executes a 1-line chat completion request (supporting explicit models like "gemini-2.5-flash",
// logical aliases like "fast" or "reasoning", and smart routing "auto").
func (c *Client) Chat(ctx context.Context, model, userPrompt string, opts ...RequestOption) (*ChatResult, error) {
	req := domain.CanonicalChatRequest{
		Model: model,
		Messages: []domain.CanonicalMessage{
			{Role: "user", Content: userPrompt},
		},
	}
	for _, opt := range opts {
		opt(&req)
	}
	return c.ChatMessages(ctx, req)
}

// ChatWithMessages sends a multi-turn chat request using the pure public ChatRequest schema.
func (c *Client) ChatWithMessages(ctx context.Context, req ChatRequest, opts ...RequestOption) (*ChatResult, error) {
	cReq := domain.CanonicalChatRequest{
		Model:             req.Model,
		Temperature:       req.Temperature,
		TopP:              req.TopP,
		MaxTokens:         req.MaxTokens,
		Stop:              req.Stop,
		Stream:            req.Stream,
		ReasoningEffort:   req.ReasoningEffort,
		User:              req.User,
		Messages:          make([]domain.CanonicalMessage, 0, len(req.Messages)),
		GoRouteExtensions: toDomainGoRouteExtensions(req.RoutingHints),
	}
	for _, m := range req.Messages {
		cm := domain.CanonicalMessage{
			Role:       m.Role,
			Content:    m.Content,
			Name:       m.Name,
			ToolCallID: m.ToolCallID,
		}
		for _, tc := range m.ToolCalls {
			cm.ToolCalls = append(cm.ToolCalls, domain.CanonicalToolCall{
				ID:   tc.ID,
				Type: tc.Type,
				Function: domain.CanonicalFunctionCall{
					Name:      tc.Function.Name,
					Arguments: tc.Function.Arguments,
				},
			})
		}
		cReq.Messages = append(cReq.Messages, cm)
	}
	for _, opt := range opts {
		opt(&cReq)
	}
	return c.ChatMessages(ctx, cReq)
}

// ChatMessages executes a full multi-turn or tool-enabled `CanonicalChatRequest`.
func (c *Client) ChatMessages(ctx context.Context, req domain.CanonicalChatRequest) (*ChatResult, error) {
	req.Stream = false
	bodyBytes, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal chat request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/chat/completions", bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gateway error (HTTP %d): %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	var raw domain.CanonicalChatResponse
	if err := json.Unmarshal(respBody, &raw); err != nil {
		return nil, fmt.Errorf("decode chat response: %w", err)
	}

	res := &ChatResult{
		Provider: string(raw.Provider),
		Model:    raw.Model,
		Usage:    raw.Usage,
		Raw:      raw,
	}
	if len(raw.Choices) > 0 {
		res.Content = raw.Choices[0].Message.Content
		res.ReasoningContent = raw.Choices[0].Message.ReasoningContent
	}
	populateChatResultFromHeaders(res, resp.Header)
	return res, nil
}

// StreamChat executes a streaming SSE chat completion (`stream: true`), invoking `onDelta` for each text token
// as it arrives and returning the aggregated `ChatResult`.
func (c *Client) StreamChat(ctx context.Context, model, userPrompt string, onDelta func(delta string) error, opts ...RequestOption) (*ChatResult, error) {
	req := domain.CanonicalChatRequest{
		Model:  model,
		Stream: true,
		Messages: []domain.CanonicalMessage{
			{Role: "user", Content: userPrompt},
		},
	}
	for _, opt := range opts {
		opt(&req)
	}
	req.Stream = true

	bodyBytes, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/chat/completions", bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("gateway stream error (HTTP %d): %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}

	var fullText strings.Builder
	var lastModel string
	var usage domain.TokenUsage

	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 64*1024), 2*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if payload == "[DONE]" {
			break
		}
		var chunk domain.CanonicalStreamChunk
		if err := json.Unmarshal([]byte(payload), &chunk); err != nil {
			continue
		}
		if chunk.Model != "" {
			lastModel = chunk.Model
		}
		if chunk.Usage != nil {
			usage = *chunk.Usage
		}
		for _, ch := range chunk.Choices {
			if ch.Delta.Content != "" {
				fullText.WriteString(ch.Delta.Content)
				if onDelta != nil {
					if err := onDelta(ch.Delta.Content); err != nil {
						return nil, err
					}
				}
			}
		}
	}

	res := &ChatResult{
		Content: fullText.String(),
		Model:   lastModel,
		Usage:   usage,
	}
	populateChatResultFromHeaders(res, resp.Header)
	return res, scanner.Err()
}

// ListModels returns the IDs of all models visible to the caller's Virtual API Key via `GET /v1/models`.
func (c *Client) ListModels(ctx context.Context) ([]string, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/v1/models", nil)
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("list models error (HTTP %d): %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	var list struct {
		Data []struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(respBody, &list); err != nil {
		return nil, err
	}
	ids := make([]string, 0, len(list.Data))
	for _, m := range list.Data {
		ids = append(ids, m.ID)
	}
	return ids, nil
}

// CreateVirtualKey issues a new scoped Virtual API Key using pure public SDK types.
func (c *Client) CreateVirtualKey(ctx context.Context, req VirtualKeyRequest) (*VirtualKeyInfo, error) {
	vkReq := domain.VirtualKey{
		Name:            req.Name,
		OrgID:           req.OrgID,
		TeamID:          req.TeamID,
		UserID:          req.UserID,
		Role:            domain.Role(req.Role),
		MaxBudgetMicros: req.MaxBudgetMicros,
		RPMLimit:        req.RPMLimit,
		TPMLimit:        req.TPMLimit,
		AllowedModels:   req.AllowedModels,
	}
	vk, err := c.IssueVirtualKey(ctx, vkReq)
	if err != nil {
		return nil, err
	}
	return &VirtualKeyInfo{
		ID:              vk.ID,
		Key:             vk.RawKey,
		KeyPrefix:       vk.KeyPrefix,
		Name:            vk.Name,
		Role:            string(vk.Role),
		OrgID:           vk.OrgID,
		MaxBudgetMicros: vk.MaxBudgetMicros,
		RPMLimit:        vk.RPMLimit,
		TPMLimit:        vk.TPMLimit,
		AllowedModels:   vk.AllowedModels,
		IsActive:        vk.IsActive,
	}, nil
}

// IssueVirtualKey issues a new scoped Virtual API Key (`sk-gw-...`) via `POST /admin/v1/keys`.
func (c *Client) IssueVirtualKey(ctx context.Context, req domain.VirtualKey) (*domain.VirtualKey, error) {
	if strings.TrimSpace(req.OrgID) == "" {
		req.OrgID = "org_default"
	}
	if req.Role == "" {
		req.Role = domain.RoleDeveloper
	}
	bodyBytes, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/admin/v1/keys", bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Authorization", "Bearer "+c.adminKey())
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("issue virtual key error (HTTP %d): %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	var vk domain.VirtualKey
	if err := json.Unmarshal(respBody, &vk); err != nil {
		return nil, err
	}
	return &vk, nil
}

// RevokeVirtualKey immediately revokes a Virtual API Key across L1/L2 caches and storage via `POST /admin/v1/keys/{id}/revoke`.
func (c *Client) RevokeVirtualKey(ctx context.Context, keyID string) error {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/admin/v1/keys/"+keyID+"/revoke", nil)
	if err != nil {
		return err
	}
	httpReq.Header.Set("Authorization", "Bearer "+c.adminKey())

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("revoke virtual key error (HTTP %d): %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}
	return nil
}

// SpendSummary flushes pending async spend events and retrieves the real-time FinOps ledger summary via `GET /admin/v1/spend/summary`.
func (c *Client) SpendSummary(ctx context.Context) (*storage.SpendSummary, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/admin/v1/spend/summary", nil)
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Authorization", "Bearer "+c.adminKey())

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("spend summary error (HTTP %d): %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}

	var sum storage.SpendSummary
	if err := json.Unmarshal(respBody, &sum); err != nil {
		return nil, err
	}
	return &sum, nil
}

// CallMCP sends a raw JSON-RPC 2.0 payload to an MCP endpoint:
// pass route="" for Virtual Hub (/mcp), route="{serverSlug}" for scoped server, or route="toolsets/{toolsetSlug}".
func (c *Client) CallMCP(ctx context.Context, route string, reqBody []byte, headers http.Header) (*mcp.JSONRPCResponse, error) {
	route = strings.TrimPrefix(route, "/mcp")
	route = strings.TrimPrefix(route, "/")
	targetURL := c.baseURL + "/mcp"
	if route != "" {
		targetURL += "/" + route
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(reqBody))
	if err != nil {
		return nil, err
	}

	token := c.apiKey
	if token == "" {
		token = c.masterKey
	}
	httpReq.Header.Set("Authorization", "Bearer "+token)
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")

	if headers != nil {
		for k, v := range headers {
			httpReq.Header[k] = v
		}
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	var rpcResp mcp.JSONRPCResponse
	if err := json.Unmarshal(respBody, &rpcResp); err != nil {
		return nil, fmt.Errorf("decode json-rpc response (HTTP %d): %w (body: %s)", resp.StatusCode, err, string(respBody))
	}
	return &rpcResp, nil
}

// ListMCPTools retrieves available tools from the Virtual Hub, scoped server, or curated toolset.
func (c *Client) ListMCPTools(ctx context.Context, route string) ([]map[string]any, error) {
	reqBody := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	resp, err := c.CallMCP(ctx, route, reqBody, nil)
	if err != nil {
		return nil, err
	}
	if resp.Error != nil {
		return nil, fmt.Errorf("mcp error (%d): %s", resp.Error.Code, resp.Error.Message)
	}

	resultMap, ok := resp.Result.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("unexpected result format: %T", resp.Result)
	}
	rawTools, ok := resultMap["tools"].([]any)
	if !ok {
		return []map[string]any{}, nil
	}

	tools := make([]map[string]any, 0, len(rawTools))
	for _, t := range rawTools {
		if tm, ok := t.(map[string]any); ok {
			tools = append(tools, tm)
		}
	}
	return tools, nil
}

// CallMCPTool executes a tool on the target MCP endpoint.
func (c *Client) CallMCPTool(ctx context.Context, route, name string, args map[string]any) (*mcp.JSONRPCResponse, error) {
	payload := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "tools/call",
		"params": map[string]any{
			"name":      name,
			"arguments": args,
		},
	}
	reqBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	return c.CallMCP(ctx, route, reqBytes, nil)
}

// SendA2AMessage sends a message to an A2A agent (supporting HTTP+JSON or JSON-RPC dispatch via the gateway).
func (c *Client) SendA2AMessage(ctx context.Context, agentSlug string, req *pb.SendMessageRequest) (*pb.SendMessageResponse, error) {
	reqJSON, err := a2a.ProtoJSONMarshaler.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal a2a message request: %w", err)
	}

	url := fmt.Sprintf("%s/a2a/v1/agents/%s", c.baseURL, agentSlug)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(reqJSON))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("a2a error (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	var sendResp pb.SendMessageResponse
	if err := a2a.StrictProtoJSONUnmarshaler.Unmarshal(respBody, &sendResp); err != nil {
		return nil, fmt.Errorf("unmarshal a2a response: %w (body: %s)", err, string(respBody))
	}
	return &sendResp, nil
}

// GetA2ATask retrieves an A2A task by ID from the gateway.
func (c *Client) GetA2ATask(ctx context.Context, agentSlug, taskID string) (*pb.Task, error) {
	url := fmt.Sprintf("%s/a2a/v1/agents/%s/tasks/%s", c.baseURL, agentSlug, taskID)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if c.apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("a2a error (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	var task pb.Task
	if err := a2a.StrictProtoJSONUnmarshaler.Unmarshal(respBody, &task); err != nil {
		return nil, fmt.Errorf("unmarshal a2a task: %w (body: %s)", err, string(respBody))
	}
	return &task, nil
}

// CancelA2ATask cancels an active A2A task.
func (c *Client) CancelA2ATask(ctx context.Context, agentSlug, taskID string) (*pb.Task, error) {
	url := fmt.Sprintf("%s/a2a/v1/agents/%s/tasks/%s:cancel", c.baseURL, agentSlug, taskID)
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return nil, err
	}
	if c.apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("a2a error (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	var task pb.Task
	if err := a2a.StrictProtoJSONUnmarshaler.Unmarshal(respBody, &task); err != nil {
		return nil, fmt.Errorf("unmarshal a2a task: %w (body: %s)", err, string(respBody))
	}
	return &task, nil
}

// SetA2AAgentKillSwitch toggles an emergency kill-switch for an A2A agent via admin API.
func (c *Client) SetA2AAgentKillSwitch(ctx context.Context, agentID string, killed bool) error {
	url := fmt.Sprintf("%s/admin/v1/a2a/agents/%s/kill-switch", c.baseURL, agentID)
	payload, _ := json.Marshal(map[string]any{"killed": killed})
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+c.adminKey())

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("admin a2a error (HTTP %d): %s", resp.StatusCode, string(respBody))
	}
	return nil
}

// AddMCPServer registers an upstream MCP server using pure public SDK types.
func (c *Client) AddMCPServer(ctx context.Context, srv MCPServerConfig) (string, error) {
	mcpServer := domain.MCPServer{
		Name:          srv.Name,
		Slug:          srv.Slug,
		TransportType: srv.Transport,
		EndpointURL:   srv.URL,
		IsActive:      srv.Enabled,
	}
	if mcpServer.TransportType == "" {
		mcpServer.TransportType = "streamable_http"
	}
	return c.RegisterMCPServer(ctx, mcpServer)
}

// RegisterMCPServer registers an upstream MCP server via POST /admin/v1/mcp/servers.
func (c *Client) RegisterMCPServer(ctx context.Context, srv domain.MCPServer) (string, error) {
	if srv.OrgID == "" {
		srv.OrgID = "org_default"
	}
	bodyBytes, err := json.Marshal(srv)
	if err != nil {
		return "", err
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/admin/v1/mcp/servers", bytes.NewReader(bodyBytes))
	if err != nil {
		return "", err
	}
	httpReq.Header.Set("Authorization", "Bearer "+c.adminKey())
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("register mcp server error (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	var res struct {
		Server domain.MCPServer `json:"server"`
	}
	if err := json.Unmarshal(respBody, &res); err != nil {
		return "", err
	}
	return res.Server.ID, nil
}

// SyncMCPTools triggers a discovery sync for an MCP server via POST /admin/v1/mcp/servers/{serverID}/sync.
func (c *Client) SyncMCPTools(ctx context.Context, serverID string) (int, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, fmt.Sprintf("%s/admin/v1/mcp/servers/%s/sync", c.baseURL, serverID), nil)
	if err != nil {
		return 0, err
	}
	httpReq.Header.Set("Authorization", "Bearer "+c.adminKey())

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, err
	}
	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("sync mcp tools error (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	var res struct {
		ToolsCount int `json:"tools_count"`
	}
	if err := json.Unmarshal(respBody, &res); err != nil {
		return 0, err
	}
	return res.ToolsCount, nil
}

// AddA2AAgent registers an upstream A2A agent using pure public SDK types.
func (c *Client) AddA2AAgent(ctx context.Context, agent A2AAgentConfig) (string, error) {
	a2aAgent := domain.A2AAgent{
		Name:        agent.Name,
		Slug:        agent.Slug,
		EndpointURL: agent.EndpointURL,
		IsActive:    true,
	}
	return c.RegisterA2AAgent(ctx, a2aAgent)
}

// RegisterA2AAgent registers an upstream A2A agent via POST /admin/v1/a2a/agents.
func (c *Client) RegisterA2AAgent(ctx context.Context, agent domain.A2AAgent) (string, error) {
	if agent.OrgID == "" {
		agent.OrgID = "org_default"
	}
	bodyBytes, err := json.Marshal(agent)
	if err != nil {
		return "", err
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/admin/v1/a2a/agents", bytes.NewReader(bodyBytes))
	if err != nil {
		return "", err
	}
	httpReq.Header.Set("Authorization", "Bearer "+c.adminKey())
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("register a2a agent error (HTTP %d): %s", resp.StatusCode, string(respBody))
	}

	var res struct {
		Agent domain.A2AAgent `json:"agent"`
	}
	if err := json.Unmarshal(respBody, &res); err != nil {
		return "", err
	}
	return res.Agent.ID, nil
}

// GetWellKnownAgentCard fetches the cryptographically signed gateway agent card.
func (c *Client) GetWellKnownAgentCard(ctx context.Context) (map[string]any, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/.well-known/agent-card.json", nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var card map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&card); err != nil {
		return nil, err
	}
	return card, nil
}

func (c *Client) adminKey() string {
	if c.masterKey != "" {
		return c.masterKey
	}
	return c.apiKey
}

func parseHeaderInt64(v string) int64 {
	n, _ := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
	return n
}

func (c *Client) doRawPost(ctx context.Context, path, contentType string, body io.Reader) ([]byte, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+path, body)
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)
	if contentType != "" {
		httpReq.Header.Set("Content-Type", contentType)
	}
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("gateway error (HTTP %d): %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	return respBody, nil
}

func doJSONPost[Req any, Resp any](c *Client, ctx context.Context, path string, req Req) (*Resp, error) {
	bodyBytes, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal request for %s: %w", path, err)
	}
	raw, err := c.doRawPost(ctx, path, "application/json", bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	var out Resp
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("decode response from %s: %w", path, err)
	}
	return &out, nil
}

// Completions executes a legacy text completion via `POST /v1/completions`.
func (c *Client) Completions(ctx context.Context, req domain.CanonicalCompletionRequest) (*domain.CanonicalCompletionResponse, error) {
	req.Stream = false
	return doJSONPost[domain.CanonicalCompletionRequest, domain.CanonicalCompletionResponse](c, ctx, "/v1/completions", req)
}

// StreamCompletions executes a streaming legacy text completion via `POST /v1/completions` (`stream: true`),
// invoking `onDelta` for each text token as it arrives and returning the aggregated `CanonicalCompletionResponse`.
func (c *Client) StreamCompletions(ctx context.Context, req domain.CanonicalCompletionRequest, onDelta func(delta string) error) (*domain.CanonicalCompletionResponse, error) {
	req.Stream = true
	bodyBytes, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal completions stream request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/completions", bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("gateway stream error (HTTP %d): %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}

	var fullText strings.Builder
	var lastID, lastModel, finishReason string
	var usage domain.TokenUsage

	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 64*1024), 2*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if payload == "[DONE]" {
			break
		}
		var frame struct {
			ID      string             `json:"id"`
			Model   string             `json:"model"`
			Usage   *domain.TokenUsage `json:"usage"`
			Choices []struct {
				Index int    `json:"index"`
				Text  string `json:"text"`
				Delta struct {
					Content string `json:"content"`
				} `json:"delta"`
				FinishReason string `json:"finish_reason"`
			} `json:"choices"`
			Error *struct {
				Message string `json:"message"`
				Type    string `json:"type"`
				Code    string `json:"code"`
			} `json:"error"`
		}
		if err := json.Unmarshal([]byte(payload), &frame); err != nil {
			continue
		}
		if frame.Error != nil && frame.Error.Message != "" {
			return nil, fmt.Errorf("gateway stream error (%s): %s", frame.Error.Code, frame.Error.Message)
		}
		if frame.ID != "" {
			lastID = frame.ID
		}
		if frame.Model != "" {
			lastModel = frame.Model
		}
		if frame.Usage != nil && (frame.Usage.TotalTokens > 0 || frame.Usage.PromptTokens > 0 || frame.Usage.CompletionTokens > 0) {
			usage = *frame.Usage
		}
		for _, ch := range frame.Choices {
			if ch.FinishReason != "" {
				finishReason = ch.FinishReason
			}
			text := ch.Text
			if text == "" {
				text = ch.Delta.Content
			}
			if text != "" {
				fullText.WriteString(text)
				if onDelta != nil {
					if err := onDelta(text); err != nil {
						return nil, err
					}
				}
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if lastModel == "" {
		lastModel = req.Model
	}
	return &domain.CanonicalCompletionResponse{
		ID:    lastID,
		Model: lastModel,
		Choices: []domain.CanonicalCompletionChoice{
			{
				Index:        0,
				Text:         fullText.String(),
				FinishReason: finishReason,
			},
		},
		Usage: usage,
	}, nil
}

// Embeddings generates vector embeddings via `POST /v1/embeddings`.
func (c *Client) Embeddings(ctx context.Context, req domain.CanonicalEmbeddingRequest) (*domain.CanonicalEmbeddingResponse, error) {
	return doJSONPost[domain.CanonicalEmbeddingRequest, domain.CanonicalEmbeddingResponse](c, ctx, "/v1/embeddings", req)
}

// Rerank scores and reorders candidate documents via `POST /v1/rerank`.
func (c *Client) Rerank(ctx context.Context, req domain.CanonicalRerankRequest) (*domain.CanonicalRerankResponse, error) {
	return doJSONPost[domain.CanonicalRerankRequest, domain.CanonicalRerankResponse](c, ctx, "/v1/rerank", req)
}

// Moderations classifies content safety via `POST /v1/moderations`.
func (c *Client) Moderations(ctx context.Context, req domain.CanonicalModerationRequest) (*domain.CanonicalModerationResponse, error) {
	return doJSONPost[domain.CanonicalModerationRequest, domain.CanonicalModerationResponse](c, ctx, "/v1/moderations", req)
}

// Responses executes a non-streaming OpenAI Responses API call via `POST /v1/responses`.
func (c *Client) Responses(ctx context.Context, req domain.CanonicalResponseRequest) (*domain.CanonicalResponseOutput, error) {
	req.Stream = false
	return doJSONPost[domain.CanonicalResponseRequest, domain.CanonicalResponseOutput](c, ctx, "/v1/responses", req)
}

// StreamResponses executes a streaming OpenAI Responses API call via `POST /v1/responses` (`stream: true`),
// invoking `onDelta` for each `response.output_text.delta` token and returning the final `CanonicalResponseOutput`.
func (c *Client) StreamResponses(ctx context.Context, req domain.CanonicalResponseRequest, onDelta func(delta string) error) (*domain.CanonicalResponseOutput, error) {
	req.Stream = true
	bodyBytes, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal responses stream request: %w", err)
	}
	rawFinal, fullText, err := c.streamResponsesSSE(ctx, bodyBytes, onDelta)
	if err != nil {
		return nil, err
	}
	finalResp := &domain.CanonicalResponseOutput{
		Object: "response",
		Status: "completed",
		Model:  req.Model,
	}
	if len(rawFinal) > 0 {
		if err := json.Unmarshal(rawFinal, finalResp); err != nil {
			return nil, fmt.Errorf("decode final responses payload: %w", err)
		}
	}
	if len(finalResp.Output) == 0 && fullText != "" {
		finalResp.Output = []domain.CanonicalResponseOutputItem{
			{
				Type:   "message",
				Status: "completed",
				Role:   "assistant",
				Content: []domain.CanonicalResponseContentPart{
					{Type: "output_text", Text: fullText},
				},
			},
		}
	}
	return finalResp, nil
}

func (c *Client) streamResponsesSSE(ctx context.Context, bodyBytes []byte, onDelta func(delta string) error) (json.RawMessage, string, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/responses", bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, "", err
	}
	httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, "", fmt.Errorf("gateway stream error (HTTP %d): %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}

	var fullText strings.Builder
	var rawFinal json.RawMessage

	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 64*1024), 2*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		payload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if payload == "[DONE]" {
			break
		}
		var ev struct {
			Type     string          `json:"type"`
			Delta    string          `json:"delta"`
			Response json.RawMessage `json:"response"`
			Error    *struct {
				Message string `json:"message"`
				Type    string `json:"type"`
				Code    string `json:"code"`
			} `json:"error"`
		}
		if err := json.Unmarshal([]byte(payload), &ev); err != nil {
			continue
		}
		if ev.Error != nil && ev.Error.Message != "" {
			return nil, "", fmt.Errorf("gateway stream error (%s): %s", ev.Error.Code, ev.Error.Message)
		}
		if ev.Delta != "" {
			fullText.WriteString(ev.Delta)
			if onDelta != nil {
				if err := onDelta(ev.Delta); err != nil {
					return nil, "", err
				}
			}
		}
		if len(ev.Response) > 0 && string(ev.Response) != "null" {
			rawFinal = ev.Response
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, "", err
	}
	return rawFinal, fullText.String(), nil
}

// Messages executes a non-streaming Anthropic Messages API call via `POST /v1/messages`.
func (c *Client) Messages(ctx context.Context, req map[string]any) (map[string]any, error) {
	payload := make(map[string]any, len(req)+1)
	for k, v := range req {
		payload[k] = v
	}
	payload["stream"] = false
	out, err := doJSONPost[map[string]any, map[string]any](c, ctx, "/v1/messages", payload)
	if err != nil {
		return nil, err
	}
	return *out, nil
}

// StreamMessages executes a streaming Anthropic Messages API call via `POST /v1/messages` (`stream: true`),
// invoking `onDelta` for each text delta (`content_block_delta`) and returning the aggregated message object.
func (c *Client) StreamMessages(ctx context.Context, req map[string]any, onDelta func(delta string) error) (map[string]any, error) {
	payload := make(map[string]any, len(req)+1)
	for k, v := range req {
		payload[k] = v
	}
	payload["stream"] = true

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal messages stream request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/messages", bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("gateway stream error (HTTP %d): %s", resp.StatusCode, strings.TrimSpace(string(b)))
	}

	result := map[string]any{
		"type": "message",
		"role": "assistant",
	}
	if m, ok := req["model"].(string); ok && m != "" {
		result["model"] = m
	}
	var fullText strings.Builder

	scanner := bufio.NewScanner(resp.Body)
	scanner.Buffer(make([]byte, 64*1024), 2*1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		dataPayload := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if dataPayload == "[DONE]" {
			break
		}
		var ev struct {
			Type    string         `json:"type"`
			Message map[string]any `json:"message"`
			Delta   struct {
				Type       string `json:"type"`
				Text       string `json:"text"`
				StopReason string `json:"stop_reason"`
			} `json:"delta"`
			Usage map[string]any `json:"usage"`
			Error *struct {
				Message string `json:"message"`
				Type    string `json:"type"`
				Code    string `json:"code"`
			} `json:"error"`
		}
		if err := json.Unmarshal([]byte(dataPayload), &ev); err != nil {
			continue
		}
		if ev.Error != nil && ev.Error.Message != "" {
			return nil, fmt.Errorf("gateway stream error (%s): %s", ev.Error.Code, ev.Error.Message)
		}
		if ev.Message != nil {
			for k, v := range ev.Message {
				result[k] = v
			}
		}
		if ev.Delta.Text != "" {
			fullText.WriteString(ev.Delta.Text)
			if onDelta != nil {
				if err := onDelta(ev.Delta.Text); err != nil {
					return nil, err
				}
			}
		}
		if ev.Delta.StopReason != "" {
			result["stop_reason"] = ev.Delta.StopReason
		}
		if ev.Usage != nil {
			result["usage"] = ev.Usage
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	result["content"] = []map[string]any{
		{"type": "text", "text": fullText.String()},
	}
	result["text"] = fullText.String()
	return result, nil
}

// AudioTranscriptionRequest configures a multipart audio transcription or translation request.
type AudioTranscriptionRequest struct {
	Model          string
	FileName       string
	Audio          io.Reader
	Language       string
	Prompt         string
	ResponseFormat string
	IsTranslation  bool
}

// AudioTranscription transcribes (or translates) audio via `POST /v1/audio/transcriptions` or `/v1/audio/translations`.
func (c *Client) AudioTranscription(ctx context.Context, req AudioTranscriptionRequest) (*domain.CanonicalAudioResponse, error) {
	raw, path, err := c.postAudioTranscription(ctx, req)
	if err != nil {
		return nil, err
	}
	var out domain.CanonicalAudioResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("decode audio response from %s: %w", path, err)
	}
	return &out, nil
}

func (c *Client) postAudioTranscription(ctx context.Context, req AudioTranscriptionRequest) ([]byte, string, error) {
	if req.Audio == nil {
		return nil, "", fmt.Errorf("audio reader is required")
	}
	fileName := strings.TrimSpace(req.FileName)
	if fileName == "" {
		fileName = "audio.wav"
	}

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	part, err := mw.CreateFormFile("file", fileName)
	if err != nil {
		return nil, "", fmt.Errorf("create multipart file: %w", err)
	}
	if _, err := io.Copy(part, req.Audio); err != nil {
		return nil, "", fmt.Errorf("copy audio payload: %w", err)
	}
	_ = mw.WriteField("model", req.Model)
	if req.Language != "" {
		_ = mw.WriteField("language", req.Language)
	}
	if req.Prompt != "" {
		_ = mw.WriteField("prompt", req.Prompt)
	}
	if req.ResponseFormat != "" {
		_ = mw.WriteField("response_format", req.ResponseFormat)
	}
	if err := mw.Close(); err != nil {
		return nil, "", fmt.Errorf("close multipart writer: %w", err)
	}

	path := "/v1/audio/transcriptions"
	if req.IsTranslation {
		path = "/v1/audio/translations"
	}
	raw, err := c.doRawPost(ctx, path, mw.FormDataContentType(), &buf)
	if err != nil {
		return nil, path, err
	}
	return raw, path, nil
}

// AudioSpeech synthesizes spoken audio bytes via `POST /v1/audio/speech`.
func (c *Client) AudioSpeech(ctx context.Context, req domain.CanonicalAudioSpeechRequest) ([]byte, error) {
	bodyBytes, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal audio speech request: %w", err)
	}
	return c.doRawPost(ctx, "/v1/audio/speech", "application/json", bytes.NewReader(bodyBytes))
}

// Images generates images via `POST /v1/images/generations`.
func (c *Client) Images(ctx context.Context, req domain.CanonicalImageRequest) (*domain.CanonicalImageResponse, error) {
	return doJSONPost[domain.CanonicalImageRequest, domain.CanonicalImageResponse](c, ctx, "/v1/images/generations", req)
}

func (c *Client) doRequest(ctx context.Context, method, path, authToken, contentType string, body io.Reader) ([]byte, error) {
	httpReq, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return nil, err
	}
	if authToken != "" {
		httpReq.Header.Set("Authorization", "Bearer "+authToken)
	}
	if contentType != "" {
		httpReq.Header.Set("Content-Type", contentType)
	}
	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("gateway error (HTTP %d): %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	return respBody, nil
}

func doJSON[Resp any](c *Client, ctx context.Context, method, path, authToken string, reqBody any) (*Resp, error) {
	var bodyReader io.Reader
	var contentType string
	if reqBody != nil {
		bodyBytes, err := json.Marshal(reqBody)
		if err != nil {
			return nil, fmt.Errorf("marshal request for %s: %w", path, err)
		}
		bodyReader = bytes.NewReader(bodyBytes)
		contentType = "application/json"
	}
	raw, err := c.doRequest(ctx, method, path, authToken, contentType, bodyReader)
	if err != nil {
		return nil, err
	}
	var out Resp
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("decode response from %s: %w", path, err)
	}
	return &out, nil
}

// UploadFile uploads a multipart file via `POST /v1/files`.
func (c *Client) UploadFile(ctx context.Context, req FileUploadRequest) (*FileObject, error) {
	if req.Content == nil {
		return nil, fmt.Errorf("file content reader is required")
	}
	fileName := strings.TrimSpace(req.FileName)
	if fileName == "" {
		fileName = "upload.bin"
	}
	purpose := strings.TrimSpace(req.Purpose)
	if purpose == "" {
		purpose = "assistants"
	}

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	if err := mw.WriteField("purpose", purpose); err != nil {
		return nil, fmt.Errorf("write purpose field: %w", err)
	}
	part, err := mw.CreateFormFile("file", fileName)
	if err != nil {
		return nil, fmt.Errorf("create multipart file: %w", err)
	}
	if _, err := io.Copy(part, req.Content); err != nil {
		return nil, fmt.Errorf("copy file payload: %w", err)
	}
	if err := mw.Close(); err != nil {
		return nil, fmt.Errorf("close multipart writer: %w", err)
	}

	raw, err := c.doRequest(ctx, http.MethodPost, "/v1/files", c.apiKey, mw.FormDataContentType(), &buf)
	if err != nil {
		return nil, err
	}
	var out FileObject
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("decode file response: %w", err)
	}
	return &out, nil
}

// ListFiles lists uploaded files for the caller's organization via `GET /v1/files`.
func (c *Client) ListFiles(ctx context.Context, purpose string) ([]FileObject, error) {
	path := "/v1/files"
	if strings.TrimSpace(purpose) != "" {
		path += "?purpose=" + url.QueryEscape(strings.TrimSpace(purpose))
	}
	res, err := doJSON[struct {
		Data []FileObject `json:"data"`
	}](c, ctx, http.MethodGet, path, c.apiKey, nil)
	if err != nil {
		return nil, err
	}
	return res.Data, nil
}

// GetFile retrieves metadata for a single file via `GET /v1/files/{fileID}`.
func (c *Client) GetFile(ctx context.Context, fileID string) (*FileObject, error) {
	return doJSON[FileObject](c, ctx, http.MethodGet, "/v1/files/"+url.PathEscape(fileID), c.apiKey, nil)
}

// GetFileContent downloads the raw bytes of an uploaded file via `GET /v1/files/{fileID}/content`.
func (c *Client) GetFileContent(ctx context.Context, fileID string) ([]byte, error) {
	return c.doRequest(ctx, http.MethodGet, "/v1/files/"+url.PathEscape(fileID)+"/content", c.apiKey, "", nil)
}

// DeleteFile deletes an uploaded file via `DELETE /v1/files/{fileID}`.
func (c *Client) DeleteFile(ctx context.Context, fileID string) error {
	_, err := c.doRequest(ctx, http.MethodDelete, "/v1/files/"+url.PathEscape(fileID), c.apiKey, "", nil)
	return err
}

// CreateBatch submits an asynchronous batch job via `POST /v1/batches`.
func (c *Client) CreateBatch(ctx context.Context, req BatchCreateRequest) (*BatchObject, error) {
	return doJSON[BatchObject](c, ctx, http.MethodPost, "/v1/batches", c.apiKey, req)
}

// ListBatches lists batch jobs for the caller's organization via `GET /v1/batches`.
func (c *Client) ListBatches(ctx context.Context) ([]BatchObject, error) {
	res, err := doJSON[struct {
		Data []BatchObject `json:"data"`
	}](c, ctx, http.MethodGet, "/v1/batches", c.apiKey, nil)
	if err != nil {
		return nil, err
	}
	return res.Data, nil
}

// GetBatch retrieves a batch job by ID via `GET /v1/batches/{batchID}`.
func (c *Client) GetBatch(ctx context.Context, batchID string) (*BatchObject, error) {
	return doJSON[BatchObject](c, ctx, http.MethodGet, "/v1/batches/"+url.PathEscape(batchID), c.apiKey, nil)
}

// CancelBatch cancels an in-progress batch job via `POST /v1/batches/{batchID}/cancel`.
func (c *Client) CancelBatch(ctx context.Context, batchID string) (*BatchObject, error) {
	return doJSON[BatchObject](c, ctx, http.MethodPost, "/v1/batches/"+url.PathEscape(batchID)+"/cancel", c.apiKey, nil)
}

// Tokenize counts tokens for a prompt or message list via `POST /v1/tokenize`.
func (c *Client) Tokenize(ctx context.Context, req TokenizeRequest) (*TokenizeResponse, error) {
	return doJSON[TokenizeResponse](c, ctx, http.MethodPost, "/v1/tokenize", c.apiKey, req)
}

// CountTokens counts input tokens using the Anthropic-compatible `POST /v1/messages/count_tokens` endpoint.
func (c *Client) CountTokens(ctx context.Context, req CountTokensRequest) (*CountTokensResponse, error) {
	return doJSON[CountTokensResponse](c, ctx, http.MethodPost, "/v1/messages/count_tokens", c.apiKey, req)
}

// ImageEdit edits an image via multipart `POST /v1/images/edits`.
func (c *Client) ImageEdit(ctx context.Context, req ImageEditRequest) (*ImageResponse, error) {
	if req.Image == nil {
		return nil, fmt.Errorf("image reader is required")
	}
	imageName := strings.TrimSpace(req.ImageName)
	if imageName == "" {
		imageName = "image.png"
	}

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	imgPart, err := mw.CreateFormFile("image", imageName)
	if err != nil {
		return nil, fmt.Errorf("create multipart image: %w", err)
	}
	if _, err := io.Copy(imgPart, req.Image); err != nil {
		return nil, fmt.Errorf("copy image payload: %w", err)
	}
	if req.Mask != nil {
		maskName := strings.TrimSpace(req.MaskName)
		if maskName == "" {
			maskName = "mask.png"
		}
		maskPart, err := mw.CreateFormFile("mask", maskName)
		if err != nil {
			return nil, fmt.Errorf("create multipart mask: %w", err)
		}
		if _, err := io.Copy(maskPart, req.Mask); err != nil {
			return nil, fmt.Errorf("copy mask payload: %w", err)
		}
	}
	_ = mw.WriteField("prompt", req.Prompt)
	if strings.TrimSpace(req.Model) != "" {
		_ = mw.WriteField("model", strings.TrimSpace(req.Model))
	}
	if req.N > 0 {
		_ = mw.WriteField("n", strconv.Itoa(req.N))
	}
	if strings.TrimSpace(req.Size) != "" {
		_ = mw.WriteField("size", strings.TrimSpace(req.Size))
	}
	if err := mw.Close(); err != nil {
		return nil, fmt.Errorf("close multipart writer: %w", err)
	}

	raw, err := c.doRequest(ctx, http.MethodPost, "/v1/images/edits", c.apiKey, mw.FormDataContentType(), &buf)
	if err != nil {
		return nil, err
	}
	var out ImageResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("decode image edit response: %w", err)
	}
	return &out, nil
}

// ImageVariation creates variations of an image via multipart `POST /v1/images/variations`.
func (c *Client) ImageVariation(ctx context.Context, req ImageVariationRequest) (*ImageResponse, error) {
	if req.Image == nil {
		return nil, fmt.Errorf("image reader is required")
	}
	imageName := strings.TrimSpace(req.ImageName)
	if imageName == "" {
		imageName = "image.png"
	}

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	imgPart, err := mw.CreateFormFile("image", imageName)
	if err != nil {
		return nil, fmt.Errorf("create multipart image: %w", err)
	}
	if _, err := io.Copy(imgPart, req.Image); err != nil {
		return nil, fmt.Errorf("copy image payload: %w", err)
	}
	if strings.TrimSpace(req.Model) != "" {
		_ = mw.WriteField("model", strings.TrimSpace(req.Model))
	}
	if req.N > 0 {
		_ = mw.WriteField("n", strconv.Itoa(req.N))
	}
	if strings.TrimSpace(req.Size) != "" {
		_ = mw.WriteField("size", strings.TrimSpace(req.Size))
	}
	if err := mw.Close(); err != nil {
		return nil, fmt.Errorf("close multipart writer: %w", err)
	}

	raw, err := c.doRequest(ctx, http.MethodPost, "/v1/images/variations", c.apiKey, mw.FormDataContentType(), &buf)
	if err != nil {
		return nil, err
	}
	var out ImageResponse
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("decode image variation response: %w", err)
	}
	return &out, nil
}

// UpdateTeam updates a team's settings via `PUT /admin/v1/teams/{teamID}`.
func (c *Client) UpdateTeam(ctx context.Context, teamID string, req TeamUpdateRequest) (*TeamConfig, error) {
	return doJSON[TeamConfig](c, ctx, http.MethodPut, "/admin/v1/teams/"+url.PathEscape(teamID), c.adminKey(), req)
}

// DeleteTeam deletes a team via `DELETE /admin/v1/teams/{teamID}`.
func (c *Client) DeleteTeam(ctx context.Context, teamID string) error {
	_, err := c.doRequest(ctx, http.MethodDelete, "/admin/v1/teams/"+url.PathEscape(teamID), c.adminKey(), "", nil)
	return err
}

// UpdateUser updates a user's settings via `PUT /admin/v1/users/{userID}`.
func (c *Client) UpdateUser(ctx context.Context, userID string, req UserUpdateRequest) (*UserConfig, error) {
	return doJSON[UserConfig](c, ctx, http.MethodPut, "/admin/v1/users/"+url.PathEscape(userID), c.adminKey(), req)
}

// DeleteUser deletes a user via `DELETE /admin/v1/users/{userID}`.
func (c *Client) DeleteUser(ctx context.Context, userID string) error {
	_, err := c.doRequest(ctx, http.MethodDelete, "/admin/v1/users/"+url.PathEscape(userID), c.adminKey(), "", nil)
	return err
}

// UpdateVirtualKey updates a virtual API key's limits, scope, or status via `PUT /admin/v1/keys/{keyID}`.
func (c *Client) UpdateVirtualKey(ctx context.Context, keyID string, req VirtualKeyUpdateRequest) (*VirtualKeyConfig, error) {
	return doJSON[VirtualKeyConfig](c, ctx, http.MethodPut, "/admin/v1/keys/"+url.PathEscape(keyID), c.adminKey(), req)
}

// RotateVirtualKey rotates a virtual API key via `POST /admin/v1/keys/{keyID}/rotate`, returning the one-time RawKey.
func (c *Client) RotateVirtualKey(ctx context.Context, keyID string) (*VirtualKeyRotateResponse, error) {
	return doJSON[VirtualKeyRotateResponse](c, ctx, http.MethodPost, "/admin/v1/keys/"+url.PathEscape(keyID)+"/rotate", c.adminKey(), nil)
}

// GetConfig retrieves the sanitized runtime gateway configuration via `GET /admin/v1/config`.
func (c *Client) GetConfig(ctx context.Context) (map[string]any, error) {
	res, err := doJSON[map[string]any](c, ctx, http.MethodGet, "/admin/v1/config", c.adminKey(), nil)
	if err != nil {
		return nil, err
	}
	return *res, nil
}

// RealtimeSession wraps a live `/v1/realtime` WebSocket connection.
type RealtimeSession struct {
	conn *websocket.Conn
}

// ConnectRealtime opens a bidirectional WebSocket session to `/v1/realtime`.
func (c *Client) ConnectRealtime(ctx context.Context, model string) (*RealtimeSession, error) {
	wsURL := c.baseURL
	switch {
	case strings.HasPrefix(wsURL, "https://"):
		wsURL = "wss://" + strings.TrimPrefix(wsURL, "https://")
	case strings.HasPrefix(wsURL, "http://"):
		wsURL = "ws://" + strings.TrimPrefix(wsURL, "http://")
	default:
		return nil, fmt.Errorf("invalid gateway base URL for websocket dial: %q", c.baseURL)
	}
	endpoint := wsURL + "/v1/realtime"
	if strings.TrimSpace(model) != "" {
		endpoint += "?model=" + url.QueryEscape(model)
	}

	headers := http.Header{}
	if c.apiKey != "" {
		headers.Set("Authorization", "Bearer "+c.apiKey)
	}

	conn, _, err := websocket.Dial(ctx, endpoint, &websocket.DialOptions{
		HTTPClient:   c.httpClient,
		HTTPHeader:   headers,
		Subprotocols: []string{"realtime"},
	})
	if err != nil {
		return nil, fmt.Errorf("dial realtime websocket: %w", err)
	}
	return &RealtimeSession{conn: conn}, nil
}

// SendEvent sends a JSON RealtimeEvent over the open WebSocket session.
func (s *RealtimeSession) SendEvent(ctx context.Context, ev RealtimeEvent) error {
	if s == nil || s.conn == nil {
		return fmt.Errorf("realtime session is closed")
	}
	payload, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("marshal realtime event: %w", err)
	}
	return s.conn.Write(ctx, websocket.MessageText, payload)
}

// ReadEvent reads the next JSON RealtimeEvent frame from the WebSocket session.
func (s *RealtimeSession) ReadEvent(ctx context.Context) (*RealtimeEvent, error) {
	if s == nil || s.conn == nil {
		return nil, fmt.Errorf("realtime session is closed")
	}
	for {
		msgType, data, err := s.conn.Read(ctx)
		if err != nil {
			return nil, err
		}
		if msgType != websocket.MessageText {
			continue
		}
		var ev RealtimeEvent
		if err := json.Unmarshal(data, &ev); err != nil {
			return nil, fmt.Errorf("decode realtime event: %w", err)
		}
		return &ev, nil
	}
}

// Close terminates the Realtime WebSocket session gracefully.
func (s *RealtimeSession) Close() error {
	if s == nil || s.conn == nil {
		return nil
	}
	return s.conn.Close(websocket.StatusNormalClosure, "client closed")
}

// CreateEmbedding generates vector embeddings via `POST /v1/embeddings` using pure SDK types.
func (c *Client) CreateEmbedding(ctx context.Context, req EmbeddingRequest) (*EmbeddingResponse, error) {
	return doJSON[EmbeddingResponse](c, ctx, http.MethodPost, "/v1/embeddings", c.apiKey, req)
}

// CreateRerank scores and reorders candidate documents via `POST /v1/rerank` using pure SDK types.
func (c *Client) CreateRerank(ctx context.Context, req RerankRequest) (*RerankResponse, error) {
	return doJSON[RerankResponse](c, ctx, http.MethodPost, "/v1/rerank", c.apiKey, req)
}

// CreateModeration classifies content safety via `POST /v1/moderations` using pure SDK types.
func (c *Client) CreateModeration(ctx context.Context, req ModerationRequest) (*ModerationResponse, error) {
	return doJSON[ModerationResponse](c, ctx, http.MethodPost, "/v1/moderations", c.apiKey, req)
}

// CreateResponse executes a non-streaming OpenAI Responses API call via `POST /v1/responses` using pure SDK types.
func (c *Client) CreateResponse(ctx context.Context, req ResponseRequest) (*ResponseOutput, error) {
	req.Stream = false
	return doJSON[ResponseOutput](c, ctx, http.MethodPost, "/v1/responses", c.apiKey, req)
}

// StreamResponse executes a streaming OpenAI Responses API call via `POST /v1/responses` (`stream: true`) using pure SDK types.
func (c *Client) StreamResponse(ctx context.Context, req ResponseRequest, onDelta func(delta string) error) (*ResponseOutput, error) {
	req.Stream = true
	bodyBytes, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal response stream request: %w", err)
	}
	rawFinal, fullText, err := c.streamResponsesSSE(ctx, bodyBytes, onDelta)
	if err != nil {
		return nil, err
	}
	finalResp := &ResponseOutput{
		Object: "response",
		Status: "completed",
		Model:  req.Model,
	}
	if len(rawFinal) > 0 {
		if err := json.Unmarshal(rawFinal, finalResp); err != nil {
			return nil, fmt.Errorf("decode final response payload: %w", err)
		}
	}
	if len(finalResp.Output) == 0 && fullText != "" {
		finalResp.Output = []ResponseOutputItem{
			{
				Type:   "message",
				Status: "completed",
				Role:   "assistant",
				Content: []ResponseContentPart{
					{Type: "output_text", Text: fullText},
				},
			},
		}
	}
	return finalResp, nil
}

// CreateImage generates images via `POST /v1/images/generations` using pure SDK types.
func (c *Client) CreateImage(ctx context.Context, req ImageGenerationRequest) (*ImageResponse, error) {
	return doJSON[ImageResponse](c, ctx, http.MethodPost, "/v1/images/generations", c.apiKey, req)
}

// CreateSpeech synthesizes spoken audio bytes via `POST /v1/audio/speech` using pure SDK types.
func (c *Client) CreateSpeech(ctx context.Context, req SpeechRequest) ([]byte, error) {
	bodyBytes, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal speech request: %w", err)
	}
	return c.doRawPost(ctx, "/v1/audio/speech", "application/json", bytes.NewReader(bodyBytes))
}

// TranscribeAudio transcribes (or translates) audio via `POST /v1/audio/transcriptions` or `/v1/audio/translations` using pure SDK types.
func (c *Client) TranscribeAudio(ctx context.Context, req AudioTranscriptionRequest) (*AudioTranscriptionResult, error) {
	raw, path, err := c.postAudioTranscription(ctx, req)
	if err != nil {
		return nil, err
	}
	var out AudioTranscriptionResult
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("decode audio response from %s: %w", path, err)
	}
	return &out, nil
}

// GetSpendSummary retrieves the FinOps ledger summary via `GET /admin/v1/spend/summary` using pure SDK types.
func (c *Client) GetSpendSummary(ctx context.Context) (*SpendSummaryResponse, error) {
	return doJSON[SpendSummaryResponse](c, ctx, http.MethodGet, "/admin/v1/spend/summary", c.adminKey(), nil)
}
