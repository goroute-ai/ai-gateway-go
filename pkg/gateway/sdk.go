package gateway

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
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
)

// ModelEntry defines a declarative model mapping item for in-code or YAML router setup.
type ModelEntry struct {
	ModelName       string   // Client-facing model name or alias (e.g. "fast", "reasoning", "gemini-2.5-flash")
	Model           string   // Upstream provider/model (e.g. "gemini/gemini-2.5-flash", "anthropic/claude-sonnet-4-20250514")
	APIKey          string   // Literal key or "os.environ/GEMINI_API_KEY"
	APIBase         string   // Optional custom upstream endpoint
	RoutingStrategy string   // Optional: "weighted-shuffle", "least-busy", "latency-based", "lowest-cost"
	Fallbacks       []string // Optional: ordered fallback model group aliases (e.g. []string{"backup-claude"})
	Weight          int
	RPM             int
	TPM             int
	SimulateStatus  int // Optional fault-injection HTTP status (e.g. 503) for local failover/circuit-breaker testing
}

// ChatResult wraps the OpenAI-compatible response together with unpacked gateway telemetry headers
// and a top-level `.Content` field for 1-line developer ergonomics.
type ChatResult struct {
	Content           string                       `json:"content"`
	ReasoningContent  string                       `json:"reasoning_content,omitempty"`
	Provider          string                       `json:"provider"`
	Model             string                       `json:"model"`
	RequestID         string                       `json:"request_id"`
	CostMicros        int64                        `json:"cost_micros"`
	RoutingMicros     int64                        `json:"routing_micros"`
	CacheStatus       string                       `json:"cache_status,omitempty"`
	RouteReason       string                       `json:"route_reason,omitempty"`
	FallbackAttempted bool                         `json:"fallback_attempted,omitempty"`
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
	mockServers []*httptest.Server
}

// Option configures a Gateway Client or Embedded Router.
type Option func(*clientConfig)

type clientConfig struct {
	configPath           string
	remoteURL            string
	apiKey               string
	modelList            []ModelEntry
	httpClient           *http.Client
	demoMocksFallback    bool
	allowPrivateNetworks bool
	customLogger         *slog.Logger
	silentLogs           bool
	logLevel             string
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

	if cc.silentLogs {
		logger.Init(logger.Config{Output: io.Discard})
	} else if cc.customLogger != nil {
		slog.SetDefault(cc.customLogger)
	} else if cc.logLevel != "" {
		logger.Init(logger.Config{Level: cc.logLevel})
	}

	if cc.remoteURL != "" {
		return NewClient(cc.remoteURL, cc.apiKey), nil
	}

	cfg, err := config.Load(cc.configPath)
	if err != nil {
		return nil, err
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
			ModelName:       e.ModelName,
			RoutingStrategy: e.RoutingStrategy,
			Fallbacks:       e.Fallbacks,
			ModelParams: config.ModelParams{
				Model:   e.Model,
				APIKey:  apiKey,
				APIBase: apiBase,
				Weight:  e.Weight,
				RPM:     e.RPM,
				TPM:     e.TPM,
			},
		})
	}

	if cfg.Auth.DefaultVirtualKey == "" {
		cfg.Auth.DefaultVirtualKey = "sk-gw-sdk-" + uuid.NewString()
	}

	repo := storage.NewMemoryRepository()
	gw, err := server.New(cfg, repo, nil, nil)
	if err != nil {
		for _, ms := range mockServers {
			ms.Close()
		}
		return nil, err
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
		mockServers: mockServers,
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

// WithKey returns a shallow copy of Client authenticated with the given Virtual API Key (`sk-gw-...`).
func (c *Client) WithKey(virtualKey string) *Client {
	return &Client{
		baseURL:    c.baseURL,
		apiKey:     strings.TrimSpace(virtualKey),
		masterKey:  c.masterKey,
		httpClient: c.httpClient,
	}
}

// Close cleanly shuts down the embedded gateway server and workers (no-op for remote clients).
func (c *Client) Close() {
	if c.embeddedGW != nil {
		c.embeddedGW.Shutdown(context.Background())
	}
	if c.embeddedTS != nil {
		c.embeddedTS.Close()
	}
	for _, ms := range c.mockServers {
		ms.Close()
	}
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
		Model:           req.Model,
		Temperature:     req.Temperature,
		TopP:            req.TopP,
		MaxTokens:       req.MaxTokens,
		Stop:            req.Stop,
		Stream:          req.Stream,
		ReasoningEffort: req.ReasoningEffort,
		User:            req.User,
		Messages:        make([]domain.CanonicalMessage, 0, len(req.Messages)),
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
		Provider:          resp.Header.Get("X-Gateway-Provider"),
		Model:             resp.Header.Get("X-Gateway-Model"),
		RequestID:         resp.Header.Get("X-Gateway-Request-Id"),
		CacheStatus:       resp.Header.Get("X-Gateway-Cache"),
		RouteReason:       resp.Header.Get("X-Gateway-Route-Reason"),
		FallbackAttempted: strings.EqualFold(resp.Header.Get("X-Gateway-Fallback-Attempted"), "true"),
		CostMicros:        parseHeaderInt64(resp.Header.Get("X-Gateway-Cost-Micros")),
		RoutingMicros:     parseHeaderInt64(resp.Header.Get("X-Gateway-Routing-Micros")),
		Usage:             raw.Usage,
		Raw:               raw,
	}
	if res.Provider == "" {
		res.Provider = string(raw.Provider)
	}
	if res.Model == "" {
		res.Model = raw.Model
	}
	if len(raw.Choices) > 0 {
		res.Content = raw.Choices[0].Message.Content
		res.ReasoningContent = raw.Choices[0].Message.ReasoningContent
	}
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

	return &ChatResult{
		Content:   fullText.String(),
		Model:     lastModel,
		RequestID: resp.Header.Get("X-Gateway-Request-Id"),
		Usage:     usage,
	}, scanner.Err()
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
