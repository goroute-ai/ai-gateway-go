package domain

import "time"

// ProviderType identifies an upstream LLM vendor supported by the gateway.
type ProviderType string

const (
	ProviderOpenAI    ProviderType = "openai"
	ProviderAnthropic ProviderType = "anthropic"
	ProviderGemini    ProviderType = "gemini"
	ProviderMistral   ProviderType = "mistral"
	ProviderOllama    ProviderType = "ollama"
)

// AllProviders returns the list of supported upstream providers.
func AllProviders() []ProviderType {
	return []ProviderType{
		ProviderOpenAI,
		ProviderAnthropic,
		ProviderGemini,
		ProviderMistral,
		ProviderOllama,
	}
}

// CanonicalChatRequest is the internal normalized representation of an OpenAI-compatible
// chat completion request before provider-specific OpenAPI translation.
type CanonicalChatRequest struct {
	RequestID         string             `json:"request_id,omitempty"`
	Model             string             `json:"model"`
	ResolvedModel     string             `json:"resolved_model,omitempty"`
	Messages          []CanonicalMessage `json:"messages"`
	Tools             []CanonicalTool    `json:"tools,omitempty"`
	ToolChoice        any                `json:"tool_choice,omitempty"`
	Temperature       *float64           `json:"temperature,omitempty"`
	TopP              *float64           `json:"top_p,omitempty"`
	MaxTokens         *int               `json:"max_tokens,omitempty"`
	Stop              []string           `json:"stop,omitempty"`
	Stream            bool               `json:"stream,omitempty"`
	StreamOptions     *StreamOptions     `json:"stream_options,omitempty"`
	ResponseFormat    *ResponseFormat    `json:"response_format,omitempty"`
	ReasoningEffort   string             `json:"reasoning_effort,omitempty"` // "low", "medium", "high"
	User              string             `json:"user,omitempty"`
	Metadata          map[string]string  `json:"metadata,omitempty"`
	ExtraParams       map[string]any     `json:"extra_params,omitempty"`
	GoRouteExtensions *GoRouteExtensions `json:"goroute_extensions,omitempty"`
}

// GoRouteExtensions holds gateway-specific routing and state resumption extensions.
type GoRouteExtensions struct {
	TaskID    string `json:"task_id,omitempty"`
	ContextID string `json:"context_id,omitempty"`
}

type StreamOptions struct {
	IncludeUsage bool `json:"include_usage,omitempty"`
}

type ResponseFormat struct {
	Type       string         `json:"type"` // "text", "json_object", "json_schema"
	JSONSchema map[string]any `json:"json_schema,omitempty"`
}

// CanonicalMessage represents a single turn in a conversation.
type CanonicalMessage struct {
	Role             string              `json:"role"` // "system", "developer", "user", "assistant", "tool"
	Content          string              `json:"content"`
	Parts            []ContentPart       `json:"parts,omitempty"` // Populated for multimodal image/audio inputs
	Name             string              `json:"name,omitempty"`
	ToolCallID       string              `json:"tool_call_id,omitempty"`
	ToolCalls        []CanonicalToolCall `json:"tool_calls,omitempty"`
	ReasoningContent string              `json:"reasoning_content,omitempty"`
}

type ContentPart struct {
	Type     string    `json:"type"` // "text", "image_url"
	Text     string    `json:"text,omitempty"`
	ImageURL *ImageURL `json:"image_url,omitempty"`
}

type ImageURL struct {
	URL    string `json:"url"`
	Detail string `json:"detail,omitempty"`
}

type CanonicalTool struct {
	Type     string            `json:"type"` // "function"
	Function CanonicalFunction `json:"function"`
}

type CanonicalFunction struct {
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	Parameters  map[string]any `json:"parameters,omitempty"`
	Strict      bool           `json:"strict,omitempty"`
}

type CanonicalToolCall struct {
	Index    *int                  `json:"index,omitempty"`
	ID       string                `json:"id"`
	Type     string                `json:"type"` // "function"
	Function CanonicalFunctionCall `json:"function"`
}

type CanonicalFunctionCall struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

// CanonicalChatResponse is the standardized OpenAI-compatible response returned by all adapters.
type CanonicalChatResponse struct {
	ID                string            `json:"id"`
	Object            string            `json:"object"` // "chat.completion"
	Created           int64             `json:"created"`
	Model             string            `json:"model"`
	Provider          ProviderType      `json:"provider,omitempty"`
	Choices           []CanonicalChoice `json:"choices"`
	Usage             TokenUsage        `json:"usage"`
	SystemFingerprint string            `json:"system_fingerprint,omitempty"`
	Metadata          map[string]string `json:"metadata,omitempty"`
}

type CanonicalChoice struct {
	Index        int              `json:"index"`
	Message      CanonicalMessage `json:"message"`
	FinishReason string           `json:"finish_reason"` // "stop", "length", "tool_calls", "content_filter"
}

// CanonicalStreamChunk represents a single OpenAI-compatible SSE chunk (`chat.completion.chunk`).
type CanonicalStreamChunk struct {
	ID                string                  `json:"id"`
	Object            string                  `json:"object"` // "chat.completion.chunk"
	Created           int64                   `json:"created"`
	Model             string                  `json:"model"`
	Choices           []CanonicalStreamChoice `json:"choices"`
	Usage             *TokenUsage             `json:"usage,omitempty"`
	SystemFingerprint string                  `json:"system_fingerprint,omitempty"`
}

type CanonicalStreamChoice struct {
	Index        int                  `json:"index"`
	Delta        CanonicalStreamDelta `json:"delta"`
	FinishReason *string              `json:"finish_reason"`
}

type CanonicalStreamDelta struct {
	Role             string              `json:"role,omitempty"`
	Content          string              `json:"content,omitempty"`
	ReasoningContent string              `json:"reasoning_content,omitempty"`
	ToolCalls        []CanonicalToolCall `json:"tool_calls,omitempty"`
}

// TokenUsage tracks granular token consumption across prompt, completion, cache, and reasoning.
type TokenUsage struct {
	PromptTokens       int `json:"prompt_tokens"`
	CompletionTokens   int `json:"completion_tokens"`
	TotalTokens        int `json:"total_tokens"`
	CachedPromptTokens int `json:"cached_prompt_tokens,omitempty"`
	ReasoningTokens    int `json:"reasoning_tokens,omitempty"`
}

// CanonicalEmbeddingRequest represents a normalized `/v1/embeddings` request.
type CanonicalEmbeddingRequest struct {
	RequestID      string   `json:"request_id,omitempty"`
	Model          string   `json:"model"`
	ResolvedModel  string   `json:"resolved_model,omitempty"`
	Input          []string `json:"input"`
	EncodingFormat string   `json:"encoding_format,omitempty"` // "float", "base64"
	Dimensions     *int     `json:"dimensions,omitempty"`
	User           string   `json:"user,omitempty"`
}

// CanonicalEmbeddingResponse represents a normalized `/v1/embeddings` response.
type CanonicalEmbeddingResponse struct {
	Object   string          `json:"object"` // "list"
	Data     []EmbeddingData `json:"data"`
	Model    string          `json:"model"`
	Provider ProviderType    `json:"provider,omitempty"`
	Usage    TokenUsage      `json:"usage"`
}

type EmbeddingData struct {
	Object    string    `json:"object"` // "embedding"
	Index     int       `json:"index"`
	Embedding []float64 `json:"embedding"`
}

// SpendEvent is pushed asynchronously to the FinOps worker pool after each inference call.
type SpendEvent struct {
	ID                string       `json:"id"`
	RequestID         string       `json:"request_id"`
	TraceID           string       `json:"trace_id,omitempty"`
	Protocol          string       `json:"protocol,omitempty"`        // "inference", "mcp", "a2a"
	ProtocolTarget    string       `json:"protocol_target,omitempty"` // e.g. "mcp:github/search_repos" or "a2a:weather-agent"
	OrgID             string       `json:"org_id"`
	TeamID            string       `json:"team_id,omitempty"`
	UserID            string       `json:"user_id,omitempty"`
	VirtualKeyID      string       `json:"virtual_key_id"`
	Endpoint          string       `json:"endpoint"`
	RequestedModel    string       `json:"requested_model"`
	ResolvedModel     string       `json:"resolved_model"`
	Provider          ProviderType `json:"provider"`
	DeploymentID      string        `json:"deployment_id"`
	PricingVersion    int           `json:"pricing_version,omitempty"`
	PricingStatus     PricingStatus `json:"pricing_status,omitempty"`
	Usage             TokenUsage    `json:"usage"`
	CostMicros        int64        `json:"cost_micros"`
	LatencyMs         int64        `json:"latency_ms"`
	TTFTMs            int64        `json:"ttft_ms"`
	StatusCode        int          `json:"status_code"`
	IsStream          bool         `json:"is_stream"`
	CacheHit          bool         `json:"cache_hit"`
	FallbackAttempted bool         `json:"fallback_attempted"`
	RetryCount        int          `json:"retry_count"`
	ErrorMessage      string       `json:"error_message,omitempty"`
	CreatedAt         time.Time    `json:"created_at"`
}
