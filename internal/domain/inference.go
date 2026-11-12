package domain

import (
	"encoding/json"
	"io"
	"time"
)

// ProviderType identifies an upstream LLM vendor supported by the gateway.
type ProviderType string

const (
	ProviderOpenAI      ProviderType = "openai"
	ProviderAnthropic   ProviderType = "anthropic"
	ProviderGemini      ProviderType = "gemini"
	ProviderMistral     ProviderType = "mistral"
	ProviderOllama      ProviderType = "ollama"
	ProviderGroq        ProviderType = "groq"
	ProviderDeepSeek    ProviderType = "deepseek"
	ProviderTogether    ProviderType = "together"
	ProviderAzure       ProviderType = "azure"
	ProviderBedrock     ProviderType = "bedrock"
	ProviderVertex      ProviderType = "vertex"
	ProviderCohere      ProviderType = "cohere"
	ProviderCerebras    ProviderType = "cerebras"
	ProviderSambaNova   ProviderType = "sambanova"
	ProviderXAI         ProviderType = "xai"
	ProviderFireworks   ProviderType = "fireworks"
	ProviderPerplexity  ProviderType = "perplexity"
	ProviderAnyscale    ProviderType = "anyscale"
	ProviderDeepInfra   ProviderType = "deepinfra"
	ProviderNovita      ProviderType = "novita"
	ProviderNebius      ProviderType = "nebius"
	ProviderHyperbolic  ProviderType = "hyperbolic"
	ProviderLambda      ProviderType = "lambda"
	ProviderFriendli    ProviderType = "friendli"
	ProviderOpenRouter  ProviderType = "openrouter"
	ProviderVLLM        ProviderType = "vllm"
	ProviderCloudflare  ProviderType = "cloudflare"
	ProviderDatabricks  ProviderType = "databricks"
	ProviderSnowflake   ProviderType = "snowflake"
	ProviderDashScope   ProviderType = "dashscope"
	ProviderVolcengine  ProviderType = "volcengine"
	ProviderBigModel    ProviderType = "bigmodel"
	ProviderMoonshot    ProviderType = "moonshot"
	ProviderMiniMax     ProviderType = "minimax"
	ProviderSiliconFlow ProviderType = "siliconflow"
	ProviderVoyage      ProviderType = "voyage"
	ProviderJina        ProviderType = "jina"
	ProviderReplicate   ProviderType = "replicate"
	ProviderAI21        ProviderType = "ai21"
	ProviderBaseten     ProviderType = "baseten"
	ProviderNvidia      ProviderType = "nvidia"
	ProviderScaleway    ProviderType = "scaleway"
)

// AllProviders returns the list of supported upstream providers.
func AllProviders() []ProviderType {
	return []ProviderType{
		ProviderOpenAI,
		ProviderAnthropic,
		ProviderGemini,
		ProviderMistral,
		ProviderOllama,
		ProviderGroq,
		ProviderDeepSeek,
		ProviderTogether,
		ProviderAzure,
		ProviderBedrock,
		ProviderVertex,
		ProviderCohere,
		ProviderCerebras,
		ProviderSambaNova,
		ProviderXAI,
		ProviderFireworks,
		ProviderPerplexity,
		ProviderAnyscale,
		ProviderDeepInfra,
		ProviderNovita,
		ProviderNebius,
		ProviderHyperbolic,
		ProviderLambda,
		ProviderFriendli,
		ProviderOpenRouter,
		ProviderVLLM,
		ProviderCloudflare,
		ProviderDatabricks,
		ProviderSnowflake,
		ProviderDashScope,
		ProviderVolcengine,
		ProviderBigModel,
		ProviderMoonshot,
		ProviderMiniMax,
		ProviderSiliconFlow,
		ProviderVoyage,
		ProviderJina,
		ProviderReplicate,
		ProviderAI21,
		ProviderBaseten,
		ProviderNvidia,
		ProviderScaleway,
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

// ModalityType identifies the operational modality of a gateway request.
type ModalityType string

const (
	ModalityChat       ModalityType = "chat"
	ModalityCompletion ModalityType = "completion"
	ModalityEmbedding  ModalityType = "embedding"
	ModalityRerank     ModalityType = "rerank"
	ModalityModeration ModalityType = "moderation"
	ModalityImage      ModalityType = "image"
	ModalityAudioSTT   ModalityType = "audio_stt"
	ModalityAudioTTS   ModalityType = "audio_tts"
	ModalityBatch      ModalityType = "batch"
	ModalityResponse   ModalityType = "response"
	ModalityRealtime   ModalityType = "realtime"
)

// SpendEvent is durably enqueued before an inference call reports success, then delivered by the FinOps worker.
type SpendEvent struct {
	ID                      string         `json:"id"`
	OutboxAttempt           int            `json:"-"`
	RequestID               string         `json:"request_id"`
	TraceID                 string         `json:"trace_id,omitempty"`
	Protocol                string         `json:"protocol,omitempty"`        // "inference", "mcp", "a2a"
	ProtocolTarget          string         `json:"protocol_target,omitempty"` // e.g. "mcp:github/search_repos" or "a2a:weather-agent"
	OrgID                   string         `json:"org_id"`
	TeamID                  string         `json:"team_id,omitempty"`
	UserID                  string         `json:"user_id,omitempty"`
	VirtualKeyID            string         `json:"virtual_key_id"`
	Endpoint                string         `json:"endpoint"`
	Modality                ModalityType   `json:"modality,omitempty"`
	ModalityUnits           map[string]any `json:"modality_units,omitempty"`
	RequestedModel          string         `json:"requested_model"`
	ResolvedModel           string         `json:"resolved_model"`
	Provider                ProviderType   `json:"provider"`
	DeploymentID            string         `json:"deployment_id"`
	PricingVersion          int            `json:"pricing_version,omitempty"`
	PricingStatus           PricingStatus  `json:"pricing_status,omitempty"`
	PricingProvenanceSource string         `json:"pricing_provenance_source,omitempty"`
	Usage                   TokenUsage     `json:"usage"`
	CostMicros              int64          `json:"cost_micros"`
	LatencyMs               int64          `json:"latency_ms"`
	TTFTMs                  int64          `json:"ttft_ms"`
	StatusCode              int            `json:"status_code"`
	IsStream                bool           `json:"is_stream"`
	CacheHit                bool           `json:"cache_hit"`
	FallbackAttempted       bool           `json:"fallback_attempted"`
	RetryCount              int            `json:"retry_count"`
	ErrorMessage            string         `json:"error_message,omitempty"`
	CreatedAt               time.Time      `json:"created_at"`
}

// --- RERANK ---

// RerankDocument represents a document in a reranking request, which can be either a plain string or a structured JSON object.
type RerankDocument struct {
	Text string         `json:"text,omitempty"`
	Raw  map[string]any `json:"raw,omitempty"`
}

func (d *RerankDocument) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		d.Text = s
		return nil
	}
	return json.Unmarshal(b, &d.Raw)
}

func (d RerankDocument) MarshalJSON() ([]byte, error) {
	if d.Text != "" && len(d.Raw) == 0 {
		return json.Marshal(d.Text)
	}
	if len(d.Raw) > 0 {
		return json.Marshal(d.Raw)
	}
	return json.Marshal(d.Text)
}

type CanonicalRerankRequest struct {
	RequestID       string           `json:"request_id,omitempty"`
	Model           string           `json:"model"`
	ResolvedModel   string           `json:"resolved_model,omitempty"`
	Query           string           `json:"query"`
	Documents       []RerankDocument `json:"documents"`
	TopN            *int             `json:"top_n,omitempty"`
	RankFields      []string         `json:"rank_fields,omitempty"`
	ReturnDocuments bool             `json:"return_documents"`
	MaxTokensPerDoc *int             `json:"max_tokens_per_doc,omitempty"`
}

type RerankResultItem struct {
	Index          int            `json:"index"`
	RelevanceScore float64        `json:"relevance_score"`
	Document       map[string]any `json:"document,omitempty"`
}

type RerankUsage struct {
	SearchUnits int `json:"search_units"`
	TotalTokens int `json:"total_tokens"`
}

type CanonicalRerankResponse struct {
	ID       string             `json:"id"`
	Model    string             `json:"model"`
	Provider ProviderType       `json:"provider"`
	Results  []RerankResultItem `json:"results"`
	Meta     map[string]any     `json:"meta,omitempty"`
	Usage    RerankUsage        `json:"usage"`
}

// --- MODERATION ---

type CanonicalModerationRequest struct {
	RequestID     string   `json:"request_id,omitempty"`
	Model         string   `json:"model"`
	ResolvedModel string   `json:"resolved_model,omitempty"`
	Input         []string `json:"input"`
}

type ModerationResultItem struct {
	Flagged        bool               `json:"flagged"`
	Categories     map[string]bool    `json:"categories"`
	CategoryScores map[string]float64 `json:"category_scores"`
}

type CanonicalModerationResponse struct {
	ID       string                 `json:"id"`
	Model    string                 `json:"model"`
	Provider ProviderType           `json:"provider"`
	Results  []ModerationResultItem `json:"results"`
}

// --- COMPLETIONS (LEGACY) ---

// CompletionPrompt supports single string prompt or array of string prompts.
type CompletionPrompt struct {
	Strings []string
}

func (p *CompletionPrompt) UnmarshalJSON(b []byte) error {
	var single string
	if err := json.Unmarshal(b, &single); err == nil {
		p.Strings = []string{single}
		return nil
	}
	return json.Unmarshal(b, &p.Strings)
}

func (p CompletionPrompt) MarshalJSON() ([]byte, error) {
	if len(p.Strings) == 1 {
		return json.Marshal(p.Strings[0])
	}
	return json.Marshal(p.Strings)
}

type CanonicalCompletionRequest struct {
	RequestID     string           `json:"request_id,omitempty"`
	Model         string           `json:"model"`
	ResolvedModel string           `json:"resolved_model,omitempty"`
	Prompt        CompletionPrompt `json:"prompt"`
	MaxTokens     *int             `json:"max_tokens,omitempty"`
	Temperature   *float64         `json:"temperature,omitempty"`
	TopP          *float64         `json:"top_p,omitempty"`
	Stream        bool             `json:"stream,omitempty"`
	Stop          []string         `json:"stop,omitempty"`
	User          string           `json:"user,omitempty"`
}

type CanonicalCompletionChoice struct {
	Index        int    `json:"index"`
	Text         string `json:"text"`
	FinishReason string `json:"finish_reason"`
}

type CanonicalCompletionResponse struct {
	ID       string                      `json:"id"`
	Model    string                      `json:"model"`
	Provider ProviderType                `json:"provider"`
	Choices  []CanonicalCompletionChoice `json:"choices"`
	Usage    TokenUsage                  `json:"usage"`
}

// --- IMAGES ---

type CanonicalImageRequest struct {
	RequestID      string `json:"request_id,omitempty"`
	Prompt         string `json:"prompt"`
	Model          string `json:"model"`
	ResolvedModel  string `json:"resolved_model,omitempty"`
	N              int    `json:"n,omitempty"`
	Quality        string `json:"quality,omitempty"`
	ResponseFormat string `json:"response_format,omitempty"` // "url" or "b64_json"
	Size           string `json:"size,omitempty"`            // "1024x1024", etc.
	Style          string `json:"style,omitempty"`           // "vivid" or "natural"
	User           string `json:"user,omitempty"`
	Operation      string `json:"-"` // "edit" or "variation"; empty means generation
	ImageData      []byte `json:"-"`
	ImageFilename  string `json:"-"`
	MaskData       []byte `json:"-"`
	MaskFilename   string `json:"-"`
}

type ImageItem struct {
	URL           string `json:"url,omitempty"`
	B64JSON       string `json:"b64_json,omitempty"`
	RevisedPrompt string `json:"revised_prompt,omitempty"`
}

type CanonicalImageResponse struct {
	Created  int64        `json:"created"`
	Provider ProviderType `json:"provider"`
	Model    string       `json:"model"`
	Data     []ImageItem  `json:"data"`
}

// --- AUDIO ---

type CanonicalAudioTranscriptionRequest struct {
	RequestID              string    `json:"request_id,omitempty"`
	Model                  string    `json:"model"`
	ResolvedModel          string    `json:"resolved_model,omitempty"`
	FileName               string    `json:"file_name"`
	SpoolFilePath          string    `json:"-"`
	FileReader             io.Reader `json:"-"`
	Language               string    `json:"language,omitempty"`
	Prompt                 string    `json:"prompt,omitempty"`
	ResponseFormat         string    `json:"response_format,omitempty"` // "json", "text", "verbose_json"
	Temperature            *float64  `json:"temperature,omitempty"`
	TimestampGranularities []string  `json:"timestamp_granularities,omitempty"`
}

type CanonicalAudioResponse struct {
	Text       string         `json:"text"`
	DurationMs int64          `json:"duration_ms,omitempty"`
	Language   string         `json:"language,omitempty"`
	Words      []any          `json:"words,omitempty"`
	Segments   []any          `json:"segments,omitempty"`
	Raw        map[string]any `json:"raw,omitempty"`
}

type CanonicalAudioSpeechRequest struct {
	RequestID      string  `json:"request_id,omitempty"`
	Model          string  `json:"model"`
	ResolvedModel  string  `json:"resolved_model,omitempty"`
	Input          string  `json:"input"`
	Voice          string  `json:"voice"`
	ResponseFormat string  `json:"response_format,omitempty"` // "mp3", "opus", "aac", "flac", "wav"
	Speed          float64 `json:"speed,omitempty"`
}

// --- FILES & BATCHES ---

type CanonicalFile struct {
	ID               string     `json:"id"`
	OrgID            string     `json:"org_id"`
	TeamID           string     `json:"team_id,omitempty"`
	UserID           string     `json:"user_id,omitempty"`
	Bytes            int64      `json:"bytes"`
	CreatedAt        time.Time  `json:"created_at"`
	Filename         string     `json:"filename"`
	Purpose          string     `json:"purpose"`
	Status           string     `json:"status"`
	ContentSHA256    string     `json:"content_sha256,omitempty"`
	StoragePath      string     `json:"storage_path,omitempty"`
	UpstreamID       string     `json:"upstream_id,omitempty"`
	UpstreamProvider string     `json:"upstream_provider,omitempty"`
	ExpiresAt        *time.Time `json:"expires_at,omitempty"`
}

type BatchCounts struct {
	Total     int `json:"total"`
	Completed int `json:"completed"`
	Failed    int `json:"failed"`
}

type CanonicalBatch struct {
	ID               string         `json:"id"`
	OrgID            string         `json:"org_id"`
	TeamID           string         `json:"team_id,omitempty"`
	InputFileID      string         `json:"input_file_id"`
	OutputFileID     string         `json:"output_file_id,omitempty"`
	ErrorFileID      string         `json:"error_file_id,omitempty"`
	Endpoint         string         `json:"endpoint"`
	Status           string         `json:"status"` // "validating", "in_progress", "completed", "failed", "cancelled"
	CompletionWindow string         `json:"completion_window"`
	CreatedAt        time.Time      `json:"created_at"`
	CompletedAt      *time.Time     `json:"completed_at,omitempty"`
	Metadata         map[string]any `json:"metadata,omitempty"`
	RequestCounts    BatchCounts    `json:"request_counts"`
	UpstreamID       string         `json:"upstream_id,omitempty"`
	UpstreamProvider string         `json:"upstream_provider,omitempty"`
}

// --- RESPONSES API ---

type CanonicalResponseRequest struct {
	Model           string          `json:"model"`
	Input           json.RawMessage `json:"input"` // string or []CanonicalChatMessage or []any
	Instructions    string          `json:"instructions,omitempty"`
	Stream          bool            `json:"stream,omitempty"`
	Temperature     *float64        `json:"temperature,omitempty"`
	MaxOutputTokens *int            `json:"max_output_tokens,omitempty"`
	Tools           []any           `json:"tools,omitempty"`
	Metadata        map[string]any  `json:"metadata,omitempty"`
}

type CanonicalResponseContentPart struct {
	Type string `json:"type"` // "output_text"
	Text string `json:"text"`
}

type CanonicalResponseOutputItem struct {
	ID      string                         `json:"id"`
	Type    string                         `json:"type"`   // "message"
	Status  string                         `json:"status"` // "completed"
	Role    string                         `json:"role"`   // "assistant"
	Content []CanonicalResponseContentPart `json:"content"`
}

type CanonicalResponseOutput struct {
	ID        string                        `json:"id"`
	Object    string                        `json:"object"` // "response"
	CreatedAt int64                         `json:"created_at"`
	Model     string                        `json:"model"`
	Status    string                        `json:"status"` // "completed", "in_progress", "failed"
	Output    []CanonicalResponseOutputItem `json:"output"`
	Usage     *TokenUsage                   `json:"usage,omitempty"`
}

// --- REALTIME WEBSOCKET API ---

type CanonicalRealtimeSessionConfig struct {
	Modalities        []string `json:"modalities,omitempty"` // ["text", "audio"]
	Instructions      string   `json:"instructions,omitempty"`
	Voice             string   `json:"voice,omitempty"`
	InputAudioFormat  string   `json:"input_audio_format,omitempty"`  // "pcm16", "g711_ulaw", "g711_alaw"
	OutputAudioFormat string   `json:"output_audio_format,omitempty"` // "pcm16", "g711_ulaw", "g711_alaw"
	Temperature       *float64 `json:"temperature,omitempty"`
}

type CanonicalRealtimeClientEvent struct {
	EventID string                          `json:"event_id,omitempty"`
	Type    string                          `json:"type"` // e.g. "session.update", "input_audio_buffer.append", "response.create"
	Session *CanonicalRealtimeSessionConfig `json:"session,omitempty"`
	Audio   string                          `json:"audio,omitempty"` // base64
}

type CanonicalRealtimeServerEvent struct {
	EventID string                          `json:"event_id,omitempty"`
	Type    string                          `json:"type"`
	Session *CanonicalRealtimeSessionConfig `json:"session,omitempty"`
	Delta   string                          `json:"delta,omitempty"`
	Text    string                          `json:"text,omitempty"`
	Error   any                             `json:"error,omitempty"`
}
