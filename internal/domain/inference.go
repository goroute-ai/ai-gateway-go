package domain

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"
)

// ProviderType identifies an upstream LLM vendor supported by the gateway.
type ProviderType string

// Canonical upstream provider identifiers supported by GoRoute.
const (
	ProviderOpenAI          ProviderType = "openai"
	ProviderAnthropic       ProviderType = "anthropic"
	ProviderGemini          ProviderType = "gemini"
	ProviderMistral         ProviderType = "mistral"
	ProviderOllama          ProviderType = "ollama"
	ProviderGroq            ProviderType = "groq"
	ProviderDeepSeek        ProviderType = "deepseek"
	ProviderTogether        ProviderType = "together"
	ProviderAzure           ProviderType = "azure"
	ProviderBedrock         ProviderType = "bedrock"
	ProviderVertex          ProviderType = "vertex"
	ProviderCohere          ProviderType = "cohere"
	ProviderCerebras        ProviderType = "cerebras"
	ProviderSambaNova       ProviderType = "sambanova"
	ProviderXAI             ProviderType = "xai"
	ProviderFireworks       ProviderType = "fireworks"
	ProviderPerplexity      ProviderType = "perplexity"
	ProviderAnyscale        ProviderType = "anyscale"
	ProviderDeepInfra       ProviderType = "deepinfra"
	ProviderNovita          ProviderType = "novita"
	ProviderNebius          ProviderType = "nebius"
	ProviderHyperbolic      ProviderType = "hyperbolic"
	ProviderLambda          ProviderType = "lambda"
	ProviderFriendli        ProviderType = "friendli"
	ProviderOpenRouter      ProviderType = "openrouter"
	ProviderVLLM            ProviderType = "vllm"
	ProviderCloudflare      ProviderType = "cloudflare"
	ProviderDatabricks      ProviderType = "databricks"
	ProviderSnowflake       ProviderType = "snowflake"
	ProviderDashScope       ProviderType = "dashscope"
	ProviderVolcengine      ProviderType = "volcengine"
	ProviderBigModel        ProviderType = "bigmodel"
	ProviderMoonshot        ProviderType = "moonshot"
	ProviderMiniMax         ProviderType = "minimax"
	ProviderSiliconFlow     ProviderType = "siliconflow"
	ProviderVoyage          ProviderType = "voyage"
	ProviderJina            ProviderType = "jina"
	ProviderReplicate       ProviderType = "replicate"
	ProviderAI21            ProviderType = "ai21"
	ProviderBaseten         ProviderType = "baseten"
	ProviderNvidia          ProviderType = "nvidia"
	ProviderScaleway        ProviderType = "scaleway"
	ProviderGitHubCopilot   ProviderType = "github_copilot"
	ProviderVercelAIGateway ProviderType = "vercel_ai_gateway"
	ProviderHuggingFace     ProviderType = "huggingface"
	ProviderFeatherless     ProviderType = "featherless"
	ProviderFal             ProviderType = "fal"
	ProviderZAI             ProviderType = "zai"
	ProviderPoe             ProviderType = "poe"
	ProviderHelicone        ProviderType = "helicone"
	ProviderAIHubMix        ProviderType = "aihubmix"
	ProviderVenice          ProviderType = "venice"
	ProviderChutes          ProviderType = "chutes"
	ProviderGMI             ProviderType = "gmi"
	ProviderLlamaGate       ProviderType = "llamagate"
	ProviderSarvam          ProviderType = "sarvam"
	ProviderCrusoe          ProviderType = "crusoe"
	ProviderParasail        ProviderType = "parasail"
	ProviderUpstage         ProviderType = "upstage"
	ProviderOVHCloud        ProviderType = "ovhcloud"
	ProviderWandB           ProviderType = "wandb"
	ProviderNscale          ProviderType = "nscale"
	ProviderPublicAI        ProviderType = "publicai"
	ProviderSynthetic       ProviderType = "synthetic"
	ProviderNanoGPT         ProviderType = "nano_gpt"
	ProviderXiaomiMiMo      ProviderType = "xiaomi_mimo"
	ProviderReka            ProviderType = "reka"
	ProviderYi              ProviderType = "yi"
	ProviderBaichuan        ProviderType = "baichuan"
	ProviderStepFun         ProviderType = "stepfun"
	ProviderLMStudio        ProviderType = "lm_studio"
	ProviderLlamafile       ProviderType = "llamafile"
	ProviderXinference      ProviderType = "xinference"
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
		ProviderGitHubCopilot,
		ProviderVercelAIGateway,
		ProviderHuggingFace,
		ProviderFeatherless,
		ProviderFal,
		ProviderZAI,
		ProviderPoe,
		ProviderHelicone,
		ProviderAIHubMix,
		ProviderVenice,
		ProviderChutes,
		ProviderGMI,
		ProviderLlamaGate,
		ProviderSarvam,
		ProviderCrusoe,
		ProviderParasail,
		ProviderUpstage,
		ProviderOVHCloud,
		ProviderWandB,
		ProviderNscale,
		ProviderPublicAI,
		ProviderSynthetic,
		ProviderNanoGPT,
		ProviderXiaomiMiMo,
		ProviderReka,
		ProviderYi,
		ProviderBaichuan,
		ProviderStepFun,
		ProviderLMStudio,
		ProviderLlamafile,
		ProviderXinference,
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

// GoRouteExtensions holds gateway-specific routing, state resumption, and guardrail extensions.
type GoRouteExtensions struct {
	TaskID                string                     `json:"task_id,omitempty"`
	ContextID             string                     `json:"context_id,omitempty"`
	Guardrails            []GuardrailRequestOverride `json:"guardrails,omitempty"`
	Tags                  []string                   `json:"tags,omitempty"`
	AllowedRegion         string                     `json:"allowed_region,omitempty"`
	SessionID             string                     `json:"session_id,omitempty"`
	PreferredDeploymentID string                     `json:"preferred_deployment_id,omitempty"`
	Priority              int                        `json:"priority,omitempty"`
	HedgeAfterMs          int                        `json:"hedge_after_ms,omitempty"`
	RoutingStrategy       string                     `json:"routing_strategy,omitempty"`
	DropUnsupportedParams *bool                      `json:"drop_unsupported_params,omitempty"`
}

// Clone returns a deep copy of e, or nil if e is nil.
func (e *GoRouteExtensions) Clone() *GoRouteExtensions {
	if e == nil {
		return nil
	}
	cp := *e
	if e.Tags != nil {
		cp.Tags = append([]string(nil), e.Tags...)
	}
	if e.Guardrails != nil {
		cp.Guardrails = append([]GuardrailRequestOverride(nil), e.Guardrails...)
	}
	if e.DropUnsupportedParams != nil {
		v := *e.DropUnsupportedParams
		cp.DropUnsupportedParams = &v
	}
	return &cp
}

// StreamOptions controls optional metadata emitted on SSE chat streams.
type StreamOptions struct {
	IncludeUsage bool `json:"include_usage,omitempty"`
}

// ResponseFormat constrains the output format requested from the model (e.g. text, json_object, json_schema).
type ResponseFormat struct {
	Type       string         `json:"type"` // "text", "json_object", "json_schema"
	JSONSchema map[string]any `json:"json_schema,omitempty"`
}

// CanonicalMessage represents a single turn in a conversation.
type CanonicalMessage struct {
	Role             string              `json:"role"` // "system", "developer", "user", "assistant", "tool"
	Content          string              `json:"content"`
	Parts            []ContentPart       `json:"parts,omitempty"` // Populated for multimodal image/document/audio inputs
	Name             string              `json:"name,omitempty"`
	ToolCallID       string              `json:"tool_call_id,omitempty"`
	ToolCalls        []CanonicalToolCall `json:"tool_calls,omitempty"`
	ReasoningContent string              `json:"reasoning_content,omitempty"`
	CacheControl     *CacheControl       `json:"cache_control,omitempty"`
	Annotations      []Annotation        `json:"annotations,omitempty"`
}

// UnmarshalJSON accepts OpenAI chat message content as either a plain string or
// the standard multimodal content-part array. The canonical Content string keeps
// text available to guardrails while Parts preserve the original wire structure.
func (m *CanonicalMessage) UnmarshalJSON(data []byte) error {
	var wire struct {
		Role             string              `json:"role"`
		Content          json.RawMessage     `json:"content"`
		Parts            []ContentPart       `json:"parts"`
		Name             string              `json:"name"`
		ToolCallID       string              `json:"tool_call_id"`
		ToolCalls        []CanonicalToolCall `json:"tool_calls"`
		ReasoningContent string              `json:"reasoning_content"`
		CacheControl     *CacheControl       `json:"cache_control"`
		Annotations      []Annotation        `json:"annotations"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	*m = CanonicalMessage{
		Role:             wire.Role,
		Parts:            wire.Parts,
		Name:             wire.Name,
		ToolCallID:       wire.ToolCallID,
		ToolCalls:        wire.ToolCalls,
		ReasoningContent: wire.ReasoningContent,
		CacheControl:     wire.CacheControl,
		Annotations:      wire.Annotations,
	}
	if len(wire.Content) == 0 || string(wire.Content) == "null" {
		return nil
	}
	if wire.Content[0] == '"' {
		return json.Unmarshal(wire.Content, &m.Content)
	}
	if err := json.Unmarshal(wire.Content, &m.Parts); err != nil {
		return fmt.Errorf("decode message content parts: %w", err)
	}
	var textParts []string
	for i := range m.Parts {
		switch m.Parts[i].Type {
		case "input_text":
			m.Parts[i].Type = "text"
		case "input_image":
			m.Parts[i].Type = "image_url"
		}
		if m.Parts[i].Type == "text" && m.Parts[i].Text != "" {
			textParts = append(textParts, m.Parts[i].Text)
		}
	}
	m.Content = strings.Join(textParts, "")
	return nil
}

// CacheControl marks prompt blocks eligible for upstream prompt caching.
type CacheControl struct {
	Type string `json:"type"`          // "ephemeral"
	TTL  string `json:"ttl,omitempty"` // e.g. "5m", "1h"
}

// DocumentPart carries an inline base64 or URI-referenced document attachment in a multimodal message.
type DocumentPart struct {
	MimeType string `json:"mime_type"`          // e.g. "application/pdf", "text/plain"
	Data     string `json:"data,omitempty"`     // base64-encoded document payload
	URL      string `json:"url,omitempty"`      // HTTPS or gs:// URI
	Filename string `json:"filename,omitempty"` // optional display filename
}

// Annotation attaches citation metadata to a generated message or content part.
type Annotation struct {
	Type        string       `json:"type"` // "url_citation"
	URLCitation *URLCitation `json:"url_citation,omitempty"`
}

// URLCitation identifies a cited web source span within model output text.
type URLCitation struct {
	URL        string `json:"url"`
	Title      string `json:"title,omitempty"`
	StartIndex int    `json:"start_index,omitempty"`
	EndIndex   int    `json:"end_index,omitempty"`
}

// ContentPart represents a typed element (text, image_url, or document) inside a multimodal message.
type ContentPart struct {
	Type         string        `json:"type"` // "text", "image_url", "document"
	Text         string        `json:"text,omitempty"`
	ImageURL     *ImageURL     `json:"image_url,omitempty"`
	Document     *DocumentPart `json:"document,omitempty"`
	CacheControl *CacheControl `json:"cache_control,omitempty"`
}

// ImageURL references an image input by URL or data URI and optional detail level.
type ImageURL struct {
	URL    string `json:"url"`
	Detail string `json:"detail,omitempty"`
}

// UnmarshalJSON accepts either a bare URL string or an ImageURL JSON object.
func (i *ImageURL) UnmarshalJSON(data []byte) error {
	if len(data) > 0 && data[0] == '"' {
		return json.Unmarshal(data, &i.URL)
	}
	type imageURLAlias ImageURL
	var wire imageURLAlias
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	*i = ImageURL(wire)
	return nil
}

// CanonicalTool declares a callable tool exposed to the model in a chat request.
type CanonicalTool struct {
	Type         string            `json:"type"` // "function"
	Function     CanonicalFunction `json:"function"`
	CacheControl *CacheControl     `json:"cache_control,omitempty"`
}

// CanonicalFunction describes a function tool's name, description, and JSON Schema parameters.
type CanonicalFunction struct {
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	Parameters  map[string]any `json:"parameters,omitempty"`
	Strict      bool           `json:"strict,omitempty"`
}

// CanonicalToolCall represents a model-emitted invocation of a declared tool.
type CanonicalToolCall struct {
	Index    *int                  `json:"index,omitempty"`
	ID       string                `json:"id"`
	Type     string                `json:"type"` // "function"
	Function CanonicalFunctionCall `json:"function"`
}

// CanonicalFunctionCall holds the target function name and JSON-encoded arguments string.
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

// CanonicalChoice represents one completion choice returned in a non-streaming chat response.
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

// CanonicalStreamChoice holds the incremental delta and optional finish reason for a streamed choice.
type CanonicalStreamChoice struct {
	Index        int                  `json:"index"`
	Delta        CanonicalStreamDelta `json:"delta"`
	FinishReason *string              `json:"finish_reason"`
}

// CanonicalStreamDelta carries incremental text, reasoning, or tool-call fragments in a stream chunk.
type CanonicalStreamDelta struct {
	Role             string              `json:"role,omitempty"`
	Content          string              `json:"content,omitempty"`
	ReasoningContent string              `json:"reasoning_content,omitempty"`
	ToolCalls        []CanonicalToolCall `json:"tool_calls,omitempty"`
}

// TokenUsage tracks granular token consumption across prompt, completion, cache, and reasoning.
type TokenUsage struct {
	PromptTokens        int `json:"prompt_tokens"`
	CompletionTokens    int `json:"completion_tokens"`
	TotalTokens         int `json:"total_tokens"`
	CachedPromptTokens  int `json:"cached_prompt_tokens,omitempty"`
	CacheCreationTokens int `json:"cache_creation_tokens,omitempty"`
	ReasoningTokens     int `json:"reasoning_tokens,omitempty"`
}

// CanonicalEmbeddingRequest represents a normalized `/v1/embeddings` request.
type CanonicalEmbeddingRequest struct {
	RequestID         string             `json:"request_id,omitempty"`
	Model             string             `json:"model"`
	ResolvedModel     string             `json:"resolved_model,omitempty"`
	Input             []string           `json:"input"`
	EncodingFormat    string             `json:"encoding_format,omitempty"` // "float", "base64"
	Dimensions        *int               `json:"dimensions,omitempty"`
	InputType         string             `json:"input_type,omitempty"` // Provider-specific embedding intent, e.g. search_query.
	User              string             `json:"user,omitempty"`
	GoRouteExtensions *GoRouteExtensions `json:"goroute_extensions,omitempty"`
}

// CanonicalEmbeddingResponse represents a normalized `/v1/embeddings` response.
type CanonicalEmbeddingResponse struct {
	Object   string          `json:"object"` // "list"
	Data     []EmbeddingData `json:"data"`
	Model    string          `json:"model"`
	Provider ProviderType    `json:"provider,omitempty"`
	Usage    TokenUsage      `json:"usage"`
}

// EmbeddingData holds a single embedding vector returned by an embeddings request.
type EmbeddingData struct {
	Object    string    `json:"object"` // "embedding"
	Index     int       `json:"index"`
	Embedding []float64 `json:"embedding"`
}

// ModalityType identifies the operational modality of a gateway request.
type ModalityType string

// Supported request modalities tracked for billing and concurrency isolation.
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
	ProjectID               string         `json:"project_id,omitempty"`
	UserID                  string         `json:"user_id,omitempty"`
	VirtualKeyID            string         `json:"virtual_key_id"`
	EndUserID               string         `json:"end_user_id,omitempty"`
	Tags                    []string       `json:"tags,omitempty"`
	ModelAccessGroupIDs     []string       `json:"model_access_group_ids,omitempty"`
	MatchedQuotaPolicyIDs   []string       `json:"matched_quota_policy_ids,omitempty"`
	SessionID               string         `json:"session_id,omitempty"`
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

// UnmarshalJSON decodes a rerank document from either a plain string or an object map.
func (d *RerankDocument) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err == nil {
		d.Text = s
		return nil
	}
	return json.Unmarshal(b, &d.Raw)
}

// MarshalJSON encodes a rerank document as a string when Raw is empty, or as the Raw object.
func (d RerankDocument) MarshalJSON() ([]byte, error) {
	if d.Text != "" && len(d.Raw) == 0 {
		return json.Marshal(d.Text)
	}
	if len(d.Raw) > 0 {
		return json.Marshal(d.Raw)
	}
	return json.Marshal(d.Text)
}

// CanonicalRerankRequest is the provider-agnostic document reranking request.
type CanonicalRerankRequest struct {
	RequestID         string             `json:"request_id,omitempty"`
	Model             string             `json:"model"`
	ResolvedModel     string             `json:"resolved_model,omitempty"`
	Query             string             `json:"query"`
	Documents         []RerankDocument   `json:"documents"`
	TopN              *int               `json:"top_n,omitempty"`
	RankFields        []string           `json:"rank_fields,omitempty"`
	ReturnDocuments   bool               `json:"return_documents"`
	MaxTokensPerDoc   *int               `json:"max_tokens_per_doc,omitempty"`
	GoRouteExtensions *GoRouteExtensions `json:"goroute_extensions,omitempty"`
}

// RerankResultItem holds a single scored document entry from a reranking response.
type RerankResultItem struct {
	Index          int            `json:"index"`
	RelevanceScore float64        `json:"relevance_score"`
	Document       map[string]any `json:"document,omitempty"`
}

// RerankUsage reports search-unit and token accounting for a reranking call.
type RerankUsage struct {
	SearchUnits int `json:"search_units"`
	TotalTokens int `json:"total_tokens"`
}

// CanonicalRerankResponse is the standardized response returned by reranking adapters.
type CanonicalRerankResponse struct {
	ID       string             `json:"id"`
	Model    string             `json:"model"`
	Provider ProviderType       `json:"provider"`
	Results  []RerankResultItem `json:"results"`
	Meta     map[string]any     `json:"meta,omitempty"`
	Usage    RerankUsage        `json:"usage"`
}

// --- MODERATION ---

// CanonicalModerationRequest is the provider-agnostic content moderation request.
type CanonicalModerationRequest struct {
	RequestID         string             `json:"request_id,omitempty"`
	Model             string             `json:"model"`
	ResolvedModel     string             `json:"resolved_model,omitempty"`
	Input             []string           `json:"input"`
	GoRouteExtensions *GoRouteExtensions `json:"goroute_extensions,omitempty"`
}

// ModerationResultItem holds classification flags and category confidence scores for one input.
type ModerationResultItem struct {
	Flagged        bool               `json:"flagged"`
	Categories     map[string]bool    `json:"categories"`
	CategoryScores map[string]float64 `json:"category_scores"`
}

// CanonicalModerationResponse is the standardized response returned by moderation adapters.
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

// UnmarshalJSON decodes a legacy completion prompt from either a single string or a string slice.
func (p *CompletionPrompt) UnmarshalJSON(b []byte) error {
	var single string
	if err := json.Unmarshal(b, &single); err == nil {
		p.Strings = []string{single}
		return nil
	}
	return json.Unmarshal(b, &p.Strings)
}

// MarshalJSON encodes a single-element CompletionPrompt as a string or multi-element as an array.
func (p CompletionPrompt) MarshalJSON() ([]byte, error) {
	if len(p.Strings) == 1 {
		return json.Marshal(p.Strings[0])
	}
	return json.Marshal(p.Strings)
}

// CanonicalCompletionRequest is the provider-agnostic legacy text completion request.
type CanonicalCompletionRequest struct {
	RequestID         string             `json:"request_id,omitempty"`
	Model             string             `json:"model"`
	ResolvedModel     string             `json:"resolved_model,omitempty"`
	Prompt            CompletionPrompt   `json:"prompt"`
	MaxTokens         *int               `json:"max_tokens,omitempty"`
	Temperature       *float64           `json:"temperature,omitempty"`
	TopP              *float64           `json:"top_p,omitempty"`
	Stream            bool               `json:"stream,omitempty"`
	Stop              []string           `json:"stop,omitempty"`
	User              string             `json:"user,omitempty"`
	Metadata          map[string]string  `json:"metadata,omitempty"`
	GoRouteExtensions *GoRouteExtensions `json:"goroute_extensions,omitempty"`
}

// CanonicalCompletionChoice represents a single text completion choice.
type CanonicalCompletionChoice struct {
	Index        int    `json:"index"`
	Text         string `json:"text"`
	FinishReason string `json:"finish_reason"`
}

// CanonicalCompletionResponse is the standardized response returned by legacy completion adapters.
type CanonicalCompletionResponse struct {
	ID       string                      `json:"id"`
	Model    string                      `json:"model"`
	Provider ProviderType                `json:"provider"`
	Choices  []CanonicalCompletionChoice `json:"choices"`
	Usage    TokenUsage                  `json:"usage"`
}

// --- IMAGES ---

// CanonicalImageRequest is the provider-agnostic image generation, edit, or variation request.
type CanonicalImageRequest struct {
	RequestID         string             `json:"request_id,omitempty"`
	Prompt            string             `json:"prompt"`
	Model             string             `json:"model"`
	ResolvedModel     string             `json:"resolved_model,omitempty"`
	N                 int                `json:"n,omitempty"`
	Quality           string             `json:"quality,omitempty"`
	ResponseFormat    string             `json:"response_format,omitempty"` // "url" or "b64_json"
	Size              string             `json:"size,omitempty"`            // "1024x1024", etc.
	Style             string             `json:"style,omitempty"`           // "vivid" or "natural"
	User              string             `json:"user,omitempty"`
	GoRouteExtensions *GoRouteExtensions `json:"goroute_extensions,omitempty"`
	Operation         string             `json:"-"` // "edit" or "variation"; empty means generation
	ImageData         []byte             `json:"-"`
	ImageFilename     string             `json:"-"`
	MaskData          []byte             `json:"-"`
	MaskFilename      string             `json:"-"`
}

// ImageItem represents a generated image URL or base64 payload returned by an image adapter.
type ImageItem struct {
	URL           string `json:"url,omitempty"`
	B64JSON       string `json:"b64_json,omitempty"`
	RevisedPrompt string `json:"revised_prompt,omitempty"`
}

// CanonicalImageResponse is the standardized response returned by image generation adapters.
type CanonicalImageResponse struct {
	Created  int64        `json:"created"`
	Provider ProviderType `json:"provider"`
	Model    string       `json:"model"`
	Data     []ImageItem  `json:"data"`
}

// --- AUDIO ---

// CanonicalAudioTranscriptionRequest is the provider-agnostic speech-to-text or translation request.
type CanonicalAudioTranscriptionRequest struct {
	RequestID              string             `json:"request_id,omitempty"`
	Model                  string             `json:"model"`
	ResolvedModel          string             `json:"resolved_model,omitempty"`
	FileName               string             `json:"file_name"`
	SpoolFilePath          string             `json:"-"`
	FileReader             io.Reader          `json:"-"`
	Language               string             `json:"language,omitempty"`
	Prompt                 string             `json:"prompt,omitempty"`
	ResponseFormat         string             `json:"response_format,omitempty"` // "json", "text", "verbose_json"
	Temperature            *float64           `json:"temperature,omitempty"`
	TimestampGranularities []string           `json:"timestamp_granularities,omitempty"`
	IsTranslation          bool               `json:"is_translation,omitempty"`
	GoRouteExtensions      *GoRouteExtensions `json:"goroute_extensions,omitempty"`
}

// CanonicalAudioResponse is the standardized response returned by audio transcription adapters.
type CanonicalAudioResponse struct {
	Text       string         `json:"text"`
	DurationMs int64          `json:"duration_ms,omitempty"`
	Language   string         `json:"language,omitempty"`
	Words      []any          `json:"words,omitempty"`
	Segments   []any          `json:"segments,omitempty"`
	Raw        map[string]any `json:"raw,omitempty"`
}

// CanonicalAudioSpeechRequest is the provider-agnostic text-to-speech synthesis request.
type CanonicalAudioSpeechRequest struct {
	RequestID         string             `json:"request_id,omitempty"`
	Model             string             `json:"model"`
	ResolvedModel     string             `json:"resolved_model,omitempty"`
	Input             string             `json:"input"`
	Voice             string             `json:"voice"`
	ResponseFormat    string             `json:"response_format,omitempty"` // "mp3", "opus", "aac", "flac", "wav"
	Speed             float64            `json:"speed,omitempty"`
	GoRouteExtensions *GoRouteExtensions `json:"goroute_extensions,omitempty"`
}

// --- FILES & BATCHES ---

// CanonicalFile represents an uploaded tenant file tracked against per-organization storage quotas.
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

// BatchCounts tracks per-request completion progress within an async batch job.
type BatchCounts struct {
	Total     int `json:"total"`
	Completed int `json:"completed"`
	Failed    int `json:"failed"`
}

// CanonicalBatch represents a persisted asynchronous batch inference job.
type CanonicalBatch struct {
	ID                 string         `json:"id"`
	OrgID              string         `json:"org_id"`
	TeamID             string         `json:"team_id,omitempty"`
	InputFileID        string         `json:"input_file_id"`
	OutputFileID       string         `json:"output_file_id,omitempty"`
	ErrorFileID        string         `json:"error_file_id,omitempty"`
	Endpoint           string         `json:"endpoint"`
	Status             string         `json:"status"` // "validating", "in_progress", "completed", "failed", "cancelled"
	CompletionWindow   string         `json:"completion_window"`
	CreatedAt          time.Time      `json:"created_at"`
	CompletedAt        *time.Time     `json:"completed_at,omitempty"`
	Metadata           map[string]any `json:"metadata,omitempty"`
	RequestCounts      BatchCounts    `json:"request_counts"`
	EstimatedTokens    int64          `json:"estimated_tokens,omitempty"`
	ReservedCostMicros int64          `json:"reserved_cost_micros,omitempty"`
	UpstreamID         string         `json:"upstream_id,omitempty"`
	UpstreamProvider   string         `json:"upstream_provider,omitempty"`
}

// --- RESPONSES API ---

// ResponseReasoningConfig specifies reasoning effort hints for the Responses API.
type ResponseReasoningConfig struct {
	Effort string `json:"effort,omitempty"`
}

// ResponseTextConfig specifies structured text output formatting for the Responses API.
type ResponseTextConfig struct {
	Format *ResponseFormat `json:"format,omitempty"`
}

// CanonicalResponseRequest represents an OpenAI Responses API (`/v1/responses`) request.
type CanonicalResponseRequest struct {
	Model           string                   `json:"model"`
	Input           json.RawMessage          `json:"input"` // string or []CanonicalChatMessage or []any
	Instructions    string                   `json:"instructions,omitempty"`
	Stream          bool                     `json:"stream,omitempty"`
	Temperature     *float64                 `json:"temperature,omitempty"`
	MaxOutputTokens *int                     `json:"max_output_tokens,omitempty"`
	Tools           []any                    `json:"tools,omitempty"`
	ToolChoice      any                      `json:"tool_choice,omitempty"`
	Reasoning       *ResponseReasoningConfig `json:"reasoning,omitempty"`
	Text            *ResponseTextConfig      `json:"text,omitempty"`
	User            string                   `json:"user,omitempty"`
	Metadata        map[string]any           `json:"metadata,omitempty"`
}

// CanonicalResponseContentPart holds a single output content block inside a Responses API item.
type CanonicalResponseContentPart struct {
	Type string `json:"type"` // "output_text"
	Text string `json:"text"`
}

// CanonicalResponseOutputItem represents a message or function-call output item in a Responses API result.
type CanonicalResponseOutputItem struct {
	ID        string                         `json:"id"`
	Type      string                         `json:"type"`   // "message" or "function_call"
	Status    string                         `json:"status"` // "completed"
	Role      string                         `json:"role,omitempty"`
	Content   []CanonicalResponseContentPart `json:"content,omitempty"`
	CallID    string                         `json:"call_id,omitempty"`
	Name      string                         `json:"name,omitempty"`
	Arguments string                         `json:"arguments,omitempty"`
}

// CanonicalResponseOutput is the standardized Responses API response payload.
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

// CanonicalRealtimeSessionConfig configures modalities, voice, and audio codecs for a Realtime session.
type CanonicalRealtimeSessionConfig struct {
	Modalities        []string           `json:"modalities,omitempty"` // ["text", "audio"]
	Instructions      string             `json:"instructions,omitempty"`
	Voice             string             `json:"voice,omitempty"`
	InputAudioFormat  string             `json:"input_audio_format,omitempty"`  // "pcm16", "g711_ulaw", "g711_alaw"
	OutputAudioFormat string             `json:"output_audio_format,omitempty"` // "pcm16", "g711_ulaw", "g711_alaw"
	Temperature       *float64           `json:"temperature,omitempty"`
	GoRouteExtensions *GoRouteExtensions `json:"goroute_extensions,omitempty"`
}

// CanonicalRealtimeClientEvent represents an inbound client WebSocket event on `/v1/realtime`.
type CanonicalRealtimeClientEvent struct {
	EventID           string                          `json:"event_id,omitempty"`
	Type              string                          `json:"type"` // e.g. "session.update", "input_audio_buffer.append", "response.create"
	Session           *CanonicalRealtimeSessionConfig `json:"session,omitempty"`
	Audio             string                          `json:"audio,omitempty"` // base64
	GoRouteExtensions *GoRouteExtensions              `json:"goroute_extensions,omitempty"`
}

// CanonicalRealtimeServerEvent represents an outbound server WebSocket event on `/v1/realtime`.
type CanonicalRealtimeServerEvent struct {
	EventID string                          `json:"event_id,omitempty"`
	Type    string                          `json:"type"`
	Session *CanonicalRealtimeSessionConfig `json:"session,omitempty"`
	Delta   string                          `json:"delta,omitempty"`
	Text    string                          `json:"text,omitempty"`
	Error   any                             `json:"error,omitempty"`
}
