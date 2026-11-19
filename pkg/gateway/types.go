package gateway

import (
	"io"
	"time"
)

// Message represents a single chat turn in a ChatRequest.
type Message struct {
	Role       string     `json:"role"` // "system", "user", "assistant", "tool"
	Content    string     `json:"content"`
	Name       string     `json:"name,omitempty"`
	ToolCallID string     `json:"tool_call_id,omitempty"`
	ToolCalls  []ToolCall `json:"tool_calls,omitempty"`
}

// ToolCall represents a tool invocation requested by the model.
type ToolCall struct {
	ID       string       `json:"id"`
	Type     string       `json:"type"` // "function"
	Function FunctionCall `json:"function"`
}

// FunctionCall contains the function name and JSON arguments string.
type FunctionCall struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

// RoutingHints specifies per-request routing constraints and preferences mapped to
// `goroute_extensions` in the outgoing inference payload.
type RoutingHints struct {
	AllowedRegion         string   `json:"allowed_region,omitempty"`
	Tags                  []string `json:"tags,omitempty"`
	SessionID             string   `json:"session_id,omitempty"`
	PreferredDeploymentID string   `json:"preferred_deployment_id,omitempty"`
	Priority              int      `json:"priority,omitempty"`
	HedgeAfterMs          int      `json:"hedge_after_ms,omitempty"`
	RoutingStrategy       string   `json:"routing_strategy,omitempty"`
	DropUnsupportedParams *bool    `json:"drop_unsupported_params,omitempty"`
}

// ChatRequest specifies input parameters for a multi-turn or customized chat completion.
type ChatRequest struct {
	Model           string        `json:"model"`
	Messages        []Message     `json:"messages"`
	Temperature     *float64      `json:"temperature,omitempty"`
	TopP            *float64      `json:"top_p,omitempty"`
	MaxTokens       *int          `json:"max_tokens,omitempty"`
	Stop            []string      `json:"stop,omitempty"`
	Stream          bool          `json:"stream,omitempty"`
	ReasoningEffort string        `json:"reasoning_effort,omitempty"` // "low", "medium", "high"
	User            string        `json:"user,omitempty"`
	RoutingHints    *RoutingHints `json:"routing_hints,omitempty"`
}

// VirtualKeyRequest specifies parameters for issuing a new Gateway Virtual API Key.
type VirtualKeyRequest struct {
	Name               string   `json:"name"`
	OrgID              string   `json:"org_id,omitempty"`
	TeamID             string   `json:"team_id,omitempty"`
	UserID             string   `json:"user_id,omitempty"`
	Role               string   `json:"role,omitempty"` // "org_admin", "team_admin", "developer", "service_account"
	MaxBudgetMicros    int64    `json:"max_budget_micros,omitempty"`
	RPMLimit           int      `json:"rpm_limit,omitempty"`
	TPMLimit           int      `json:"tpm_limit,omitempty"`
	AllowedModels      []string `json:"allowed_models,omitempty"`
	MinPriorityRank    int      `json:"min_priority_rank,omitempty"`
	AllowedRoutingTags []string `json:"allowed_routing_tags,omitempty"`
}

// VirtualKeyInfo holds information about an issued virtual API key.
type VirtualKeyInfo struct {
	ID                 string   `json:"id"`
	Key                string   `json:"key,omitempty"` // Raw token (RawKey), only visible upon creation
	KeyPrefix          string   `json:"key_prefix"`
	Name               string   `json:"name"`
	Role               string   `json:"role"`
	OrgID              string   `json:"org_id"`
	MaxBudgetMicros    int64    `json:"max_budget_micros"`
	RPMLimit           int      `json:"rpm_limit"`
	TPMLimit           int      `json:"tpm_limit"`
	AllowedModels      []string `json:"allowed_models"`
	MinPriorityRank    int      `json:"min_priority_rank,omitempty"`
	AllowedRoutingTags []string `json:"allowed_routing_tags,omitempty"`
	IsActive           bool     `json:"is_active"`
}

// MCPServerConfig specifies registration parameters for a Model Context Protocol tool server.
type MCPServerConfig struct {
	Name        string `json:"name"`
	Slug        string `json:"slug"`
	Description string `json:"description,omitempty"`
	Transport   string `json:"transport,omitempty"` // "streamable_http", "http-sse"
	URL         string `json:"url"`
	Enabled     bool   `json:"enabled"`
}

// A2AAgentConfig specifies registration parameters for an Agent-to-Agent protocol agent.
type A2AAgentConfig struct {
	Name        string `json:"name"`
	Slug        string `json:"slug"`
	Description string `json:"description,omitempty"`
	EndpointURL string `json:"endpoint_url"`
	Status      string `json:"status,omitempty"`
}

// SystemIdentity represents an authenticated system or service caller identity.
type SystemIdentity struct {
	OrgID  string `json:"org_id"`
	UserID string `json:"user_id,omitempty"`
	TeamID string `json:"team_id,omitempty"`
	Role   string `json:"role,omitempty"`
}

// FileObject represents metadata for an uploaded file returned by `/v1/files`.
type FileObject struct {
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
	UpstreamID       string     `json:"upstream_id,omitempty"`
	UpstreamProvider string     `json:"upstream_provider,omitempty"`
	ExpiresAt        *time.Time `json:"expires_at,omitempty"`
}

// FileUploadRequest configures a multipart file upload to `POST /v1/files`.
type FileUploadRequest struct {
	FileName string
	Purpose  string
	Content  io.Reader
}

// BatchCreateRequest configures a batch job submission to `POST /v1/batches`.
type BatchCreateRequest struct {
	InputFileID      string         `json:"input_file_id"`
	Endpoint         string         `json:"endpoint,omitempty"`
	CompletionWindow string         `json:"completion_window,omitempty"`
	Metadata         map[string]any `json:"metadata,omitempty"`
}

// BatchCounts holds request progress counters for a BatchObject.
type BatchCounts struct {
	Total     int `json:"total"`
	Completed int `json:"completed"`
	Failed    int `json:"failed"`
}

// BatchObject represents a batch job returned by `/v1/batches`.
type BatchObject struct {
	ID               string         `json:"id"`
	OrgID            string         `json:"org_id"`
	TeamID           string         `json:"team_id,omitempty"`
	InputFileID      string         `json:"input_file_id"`
	OutputFileID     string         `json:"output_file_id,omitempty"`
	ErrorFileID      string         `json:"error_file_id,omitempty"`
	Endpoint         string         `json:"endpoint"`
	Status           string         `json:"status"`
	CompletionWindow string         `json:"completion_window"`
	CreatedAt        time.Time      `json:"created_at"`
	CompletedAt      *time.Time     `json:"completed_at,omitempty"`
	Metadata         map[string]any `json:"metadata,omitempty"`
	RequestCounts    BatchCounts    `json:"request_counts"`
	UpstreamID       string         `json:"upstream_id,omitempty"`
	UpstreamProvider string         `json:"upstream_provider,omitempty"`
}

// TokenizeRequest configures a token-counting request for `POST /v1/tokenize`.
type TokenizeRequest struct {
	Model    string    `json:"model"`
	Prompt   any       `json:"prompt,omitempty"`
	Messages []Message `json:"messages,omitempty"`
}

// TokenizeResponse holds the token count returned by `POST /v1/tokenize`.
type TokenizeResponse struct {
	Model       string `json:"model"`
	Profile     string `json:"profile"`
	Count       int    `json:"count"`
	TotalTokens int    `json:"total_tokens"`
}

// CountTokensMessage represents a message in a `CountTokensRequest`.
type CountTokensMessage struct {
	Role    string `json:"role"`
	Content any    `json:"content"`
}

// CountTokensRequest configures an Anthropic-compatible `POST /v1/messages/count_tokens` call.
type CountTokensRequest struct {
	Model    string               `json:"model"`
	System   any                  `json:"system,omitempty"`
	Messages []CountTokensMessage `json:"messages"`
}

// CountTokensResponse holds the input token count returned by `POST /v1/messages/count_tokens`.
type CountTokensResponse struct {
	InputTokens int `json:"input_tokens"`
}

// ImageEditRequest configures a multipart image edit request to `POST /v1/images/edits`.
type ImageEditRequest struct {
	Model     string
	Prompt    string
	ImageName string
	Image     io.Reader
	MaskName  string
	Mask      io.Reader
	N         int
	Size      string
}

// ImageVariationRequest configures a multipart image variation request to `POST /v1/images/variations`.
type ImageVariationRequest struct {
	Model     string
	ImageName string
	Image     io.Reader
	N         int
	Size      string
}

// ImageData represents a single generated, edited, or varied image item.
type ImageData struct {
	URL           string `json:"url,omitempty"`
	B64JSON       string `json:"b64_json,omitempty"`
	RevisedPrompt string `json:"revised_prompt,omitempty"`
}

// ImageResponse holds the response from `/v1/images/edits` or `/v1/images/variations`.
type ImageResponse struct {
	Created  int64       `json:"created"`
	Provider string      `json:"provider"`
	Model    string      `json:"model"`
	Data     []ImageData `json:"data"`
}

// TeamConfig represents an organization team returned by `/admin/v1/teams`.
type TeamConfig struct {
	ID                    string     `json:"id"`
	OrgID                 string     `json:"org_id"`
	Name                  string     `json:"name"`
	MaxBudgetMicros       int64      `json:"max_budget_micros"`
	SpentMicros           int64      `json:"spent_micros"`
	BudgetResetPeriod     string     `json:"budget_reset_period"`
	BudgetResetAt         *time.Time `json:"budget_reset_at,omitempty"`
	RPMLimit              int        `json:"rpm_limit"`
	TPMLimit              int        `json:"tpm_limit"`
	MaxConcurrentRequests int        `json:"max_concurrent_requests"`
	AllowedModels         []string   `json:"allowed_models,omitempty"`
	AllowedMCPServers     []string   `json:"allowed_mcp_servers,omitempty"`
	AllowedA2AAgents      []string   `json:"allowed_a2a_agents,omitempty"`
	AllowedClientApps     []string   `json:"allowed_client_apps,omitempty"`
	MinPriorityRank       int        `json:"min_priority_rank,omitempty"`
	AllowedRoutingTags    []string   `json:"allowed_routing_tags,omitempty"`
	IsActive              bool       `json:"is_active"`
	CreatedAt             time.Time  `json:"created_at"`
	UpdatedAt             time.Time  `json:"updated_at"`
}

// TeamUpdateRequest specifies partial updates for `PUT /admin/v1/teams/{teamID}`.
type TeamUpdateRequest struct {
	OrgID                 *string   `json:"org_id,omitempty"`
	Name                  *string   `json:"name,omitempty"`
	MaxBudgetMicros       *int64    `json:"max_budget_micros,omitempty"`
	BudgetResetPeriod     *string   `json:"budget_reset_period,omitempty"`
	RPMLimit              *int      `json:"rpm_limit,omitempty"`
	TPMLimit              *int      `json:"tpm_limit,omitempty"`
	MaxConcurrentRequests *int      `json:"max_concurrent_requests,omitempty"`
	AllowedModels         *[]string `json:"allowed_models,omitempty"`
	AllowedMCPServers     *[]string `json:"allowed_mcp_servers,omitempty"`
	AllowedA2AAgents      *[]string `json:"allowed_a2a_agents,omitempty"`
	AllowedClientApps     *[]string `json:"allowed_client_apps,omitempty"`
	MinPriorityRank       *int      `json:"min_priority_rank,omitempty"`
	AllowedRoutingTags    *[]string `json:"allowed_routing_tags,omitempty"`
	IsActive              *bool     `json:"is_active,omitempty"`
}

// UserConfig represents a gateway user returned by `/admin/v1/users`.
type UserConfig struct {
	ID                    string     `json:"id"`
	OrgID                 string     `json:"org_id"`
	TeamID                string     `json:"team_id,omitempty"`
	Email                 string     `json:"email"`
	Name                  string     `json:"name"`
	Role                  string     `json:"role"`
	OIDCSubject           string     `json:"oidc_subject,omitempty"`
	MaxBudgetMicros       int64      `json:"max_budget_micros"`
	SpentMicros           int64      `json:"spent_micros"`
	BudgetResetPeriod     string     `json:"budget_reset_period"`
	BudgetResetAt         *time.Time `json:"budget_reset_at,omitempty"`
	RPMLimit              int        `json:"rpm_limit"`
	TPMLimit              int        `json:"tpm_limit"`
	MaxConcurrentRequests int        `json:"max_concurrent_requests"`
	IsActive              bool       `json:"is_active"`
	CreatedAt             time.Time  `json:"created_at"`
	UpdatedAt             time.Time  `json:"updated_at"`
}

// UserUpdateRequest specifies partial updates for `PUT /admin/v1/users/{userID}`.
type UserUpdateRequest struct {
	OrgID                 *string `json:"org_id,omitempty"`
	TeamID                *string `json:"team_id,omitempty"`
	Email                 *string `json:"email,omitempty"`
	Name                  *string `json:"name,omitempty"`
	Role                  *string `json:"role,omitempty"`
	OIDCSubject           *string `json:"oidc_subject,omitempty"`
	MaxBudgetMicros       *int64  `json:"max_budget_micros,omitempty"`
	BudgetResetPeriod     *string `json:"budget_reset_period,omitempty"`
	RPMLimit              *int    `json:"rpm_limit,omitempty"`
	TPMLimit              *int    `json:"tpm_limit,omitempty"`
	MaxConcurrentRequests *int    `json:"max_concurrent_requests,omitempty"`
	IsActive              *bool   `json:"is_active,omitempty"`
}

// VirtualKeyConfig represents a virtual API key returned by `/admin/v1/keys/{keyID}`.
type VirtualKeyConfig struct {
	ID                    string            `json:"id"`
	KeyPrefix             string            `json:"key_prefix"`
	RawKey                string            `json:"raw_key,omitempty"`
	Name                  string            `json:"name"`
	OrgID                 string            `json:"org_id"`
	TeamID                string            `json:"team_id,omitempty"`
	UserID                string            `json:"user_id,omitempty"`
	Role                  string            `json:"role"`
	AllowedModels         []string          `json:"allowed_models,omitempty"`
	AllowedEndpoints      []string          `json:"allowed_endpoints,omitempty"`
	AllowedMCPServers     []string          `json:"allowed_mcp_servers,omitempty"`
	AllowedA2AAgents      []string          `json:"allowed_a2a_agents,omitempty"`
	AllowedClientApps     []string          `json:"allowed_client_apps,omitempty"`
	MaxBudgetMicros       int64             `json:"max_budget_micros"`
	SpentMicros           int64             `json:"spent_micros"`
	BudgetResetPeriod     string            `json:"budget_reset_period"`
	BudgetResetAt         *time.Time        `json:"budget_reset_at,omitempty"`
	RPMLimit              int               `json:"rpm_limit"`
	TPMLimit              int               `json:"tpm_limit"`
	MaxConcurrentRequests int               `json:"max_concurrent_requests"`
	MinPriorityRank       int               `json:"min_priority_rank,omitempty"`
	AllowedRoutingTags    []string          `json:"allowed_routing_tags,omitempty"`
	ExpiresAt             *time.Time        `json:"expires_at,omitempty"`
	IsActive              bool              `json:"is_active"`
	Metadata              map[string]string `json:"metadata,omitempty"`
	CreatedAt             time.Time         `json:"created_at"`
	UpdatedAt             time.Time         `json:"updated_at"`
}

// VirtualKeyUpdateRequest specifies partial updates for `PUT /admin/v1/keys/{keyID}`.
type VirtualKeyUpdateRequest struct {
	OrgID                 *string            `json:"org_id,omitempty"`
	Name                  *string            `json:"name,omitempty"`
	TeamID                *string            `json:"team_id,omitempty"`
	UserID                *string            `json:"user_id,omitempty"`
	Role                  *string            `json:"role,omitempty"`
	AllowedModels         *[]string          `json:"allowed_models,omitempty"`
	AllowedEndpoints      *[]string          `json:"allowed_endpoints,omitempty"`
	AllowedMCPServers     *[]string          `json:"allowed_mcp_servers,omitempty"`
	AllowedA2AAgents      *[]string          `json:"allowed_a2a_agents,omitempty"`
	AllowedClientApps     *[]string          `json:"allowed_client_apps,omitempty"`
	MaxBudgetMicros       *int64             `json:"max_budget_micros,omitempty"`
	BudgetResetPeriod     *string            `json:"budget_reset_period,omitempty"`
	RPMLimit              *int               `json:"rpm_limit,omitempty"`
	TPMLimit              *int               `json:"tpm_limit,omitempty"`
	MaxConcurrentRequests *int               `json:"max_concurrent_requests,omitempty"`
	MinPriorityRank       *int               `json:"min_priority_rank,omitempty"`
	AllowedRoutingTags    *[]string          `json:"allowed_routing_tags,omitempty"`
	IsActive              *bool              `json:"is_active,omitempty"`
	Metadata              *map[string]string `json:"metadata,omitempty"`
}

// VirtualKeyRotateResponse holds the rotated virtual API key including its one-time RawKey.
type VirtualKeyRotateResponse struct {
	VirtualKeyConfig
}

// RealtimeSessionConfig configures a `/v1/realtime` WebSocket session.
type RealtimeSessionConfig struct {
	ID                string        `json:"id,omitempty"`
	Object            string        `json:"object,omitempty"`
	Model             string        `json:"model,omitempty"`
	Modalities        []string      `json:"modalities,omitempty"`
	Instructions      string        `json:"instructions,omitempty"`
	Voice             string        `json:"voice,omitempty"`
	InputAudioFormat  string        `json:"input_audio_format,omitempty"`
	OutputAudioFormat string        `json:"output_audio_format,omitempty"`
	Temperature       *float64      `json:"temperature,omitempty"`
	RoutingHints      *RoutingHints `json:"goroute_extensions,omitempty"`
}

// RealtimeEvent represents a bidirectional JSON event exchanged over `/v1/realtime`.
type RealtimeEvent struct {
	EventID      string                 `json:"event_id,omitempty"`
	Type         string                 `json:"type"`
	Session      *RealtimeSessionConfig `json:"session,omitempty"`
	Item         map[string]any         `json:"item,omitempty"`
	Response     map[string]any         `json:"response,omitempty"`
	Delta        string                 `json:"delta,omitempty"`
	Audio        string                 `json:"audio,omitempty"`
	Error        map[string]any         `json:"error,omitempty"`
	RoutingHints *RoutingHints          `json:"goroute_extensions,omitempty"`
}

// UsageInfo reports token accounting returned by gateway inference endpoints.
type UsageInfo struct {
	PromptTokens        int `json:"prompt_tokens"`
	CompletionTokens    int `json:"completion_tokens"`
	TotalTokens         int `json:"total_tokens"`
	CachedPromptTokens  int `json:"cached_prompt_tokens,omitempty"`
	CacheCreationTokens int `json:"cache_creation_tokens,omitempty"`
	ReasoningTokens     int `json:"reasoning_tokens,omitempty"`
}

// EmbeddingRequest configures a vector embedding request to `POST /v1/embeddings`.
type EmbeddingRequest struct {
	Model          string        `json:"model"`
	Input          []string      `json:"input"`
	EncodingFormat string        `json:"encoding_format,omitempty"`
	Dimensions     *int          `json:"dimensions,omitempty"`
	InputType      string        `json:"input_type,omitempty"`
	User           string        `json:"user,omitempty"`
	RoutingHints   *RoutingHints `json:"goroute_extensions,omitempty"`
}

// EmbeddingData represents one embedding vector in an EmbeddingResponse.
type EmbeddingData struct {
	Object    string    `json:"object"`
	Index     int       `json:"index"`
	Embedding []float64 `json:"embedding"`
}

// EmbeddingResponse holds the response from `POST /v1/embeddings`.
type EmbeddingResponse struct {
	Object   string          `json:"object"`
	Data     []EmbeddingData `json:"data"`
	Model    string          `json:"model"`
	Provider string          `json:"provider,omitempty"`
	Usage    UsageInfo       `json:"usage"`
}

// RerankRequest configures a document reranking request to `POST /v1/rerank`.
// Elements of Documents may be strings or map[string]any objects.
type RerankRequest struct {
	Model           string        `json:"model"`
	Query           string        `json:"query"`
	Documents       []any         `json:"documents"`
	TopN            *int          `json:"top_n,omitempty"`
	RankFields      []string      `json:"rank_fields,omitempty"`
	ReturnDocuments bool          `json:"return_documents,omitempty"`
	MaxTokensPerDoc *int          `json:"max_tokens_per_doc,omitempty"`
	RoutingHints    *RoutingHints `json:"goroute_extensions,omitempty"`
}

// RerankResult represents a single ranked document in a RerankResponse.
type RerankResult struct {
	Index          int            `json:"index"`
	RelevanceScore float64        `json:"relevance_score"`
	Document       map[string]any `json:"document,omitempty"`
}

// RerankUsage reports billing units consumed by `POST /v1/rerank`.
type RerankUsage struct {
	SearchUnits int `json:"search_units"`
	TotalTokens int `json:"total_tokens"`
}

// RerankResponse holds the response from `POST /v1/rerank`.
type RerankResponse struct {
	ID       string         `json:"id"`
	Model    string         `json:"model"`
	Provider string         `json:"provider"`
	Results  []RerankResult `json:"results"`
	Meta     map[string]any `json:"meta,omitempty"`
	Usage    RerankUsage    `json:"usage"`
}

// ModerationRequest configures a content moderation check via `POST /v1/moderations`.
type ModerationRequest struct {
	Model        string        `json:"model"`
	Input        []string      `json:"input"`
	RoutingHints *RoutingHints `json:"goroute_extensions,omitempty"`
}

// ModerationResult holds classification flags and scores for one input item.
type ModerationResult struct {
	Flagged        bool               `json:"flagged"`
	Categories     map[string]bool    `json:"categories"`
	CategoryScores map[string]float64 `json:"category_scores"`
}

// ModerationResponse holds the response from `POST /v1/moderations`.
type ModerationResponse struct {
	ID       string             `json:"id"`
	Model    string             `json:"model"`
	Provider string             `json:"provider"`
	Results  []ModerationResult `json:"results"`
}

// ResponseRequest configures a request to `POST /v1/responses`.
// Input may be a string or a slice of structured message/content objects.
type ResponseRequest struct {
	Model           string         `json:"model"`
	Input           any            `json:"input"`
	Instructions    string         `json:"instructions,omitempty"`
	Stream          bool           `json:"stream,omitempty"`
	Temperature     *float64       `json:"temperature,omitempty"`
	MaxOutputTokens *int           `json:"max_output_tokens,omitempty"`
	Tools           []any          `json:"tools,omitempty"`
	ToolChoice      any            `json:"tool_choice,omitempty"`
	Reasoning       map[string]any `json:"reasoning,omitempty"`
	Text            map[string]any `json:"text,omitempty"`
	Metadata        map[string]any `json:"metadata,omitempty"`
	RoutingHints    *RoutingHints  `json:"goroute_extensions,omitempty"`
}

// ResponseContentPart represents a text output block in a ResponseOutputItem.
type ResponseContentPart struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// ResponseOutputItem represents an item in a ResponseOutput.
type ResponseOutputItem struct {
	ID        string                `json:"id"`
	Type      string                `json:"type"`
	Status    string                `json:"status"`
	Role      string                `json:"role,omitempty"`
	Content   []ResponseContentPart `json:"content,omitempty"`
	CallID    string                `json:"call_id,omitempty"`
	Name      string                `json:"name,omitempty"`
	Arguments string                `json:"arguments,omitempty"`
}

// ResponseOutput holds the response from `POST /v1/responses`.
type ResponseOutput struct {
	ID        string               `json:"id"`
	Object    string               `json:"object"`
	CreatedAt int64                `json:"created_at"`
	Model     string               `json:"model"`
	Status    string               `json:"status"`
	Output    []ResponseOutputItem `json:"output"`
	Usage     *UsageInfo           `json:"usage,omitempty"`
}

// ImageGenerationRequest configures a request to `POST /v1/images/generations`.
type ImageGenerationRequest struct {
	Prompt         string        `json:"prompt"`
	Model          string        `json:"model"`
	N              int           `json:"n,omitempty"`
	Quality        string        `json:"quality,omitempty"`
	ResponseFormat string        `json:"response_format,omitempty"`
	Size           string        `json:"size,omitempty"`
	Style          string        `json:"style,omitempty"`
	User           string        `json:"user,omitempty"`
	RoutingHints   *RoutingHints `json:"goroute_extensions,omitempty"`
}

// SpeechRequest configures a text-to-speech synthesis request to `POST /v1/audio/speech`.
type SpeechRequest struct {
	Model          string        `json:"model"`
	Input          string        `json:"input"`
	Voice          string        `json:"voice"`
	ResponseFormat string        `json:"response_format,omitempty"`
	Speed          float64       `json:"speed,omitempty"`
	RoutingHints   *RoutingHints `json:"goroute_extensions,omitempty"`
}

// AudioTranscriptionResult holds the decoded output of `POST /v1/audio/transcriptions` or `/v1/audio/translations`.
type AudioTranscriptionResult struct {
	Text       string         `json:"text"`
	DurationMs int64          `json:"duration_ms,omitempty"`
	Language   string         `json:"language,omitempty"`
	Words      []any          `json:"words,omitempty"`
	Segments   []any          `json:"segments,omitempty"`
	Raw        map[string]any `json:"raw,omitempty"`
}

// SpendSummaryResponse holds the FinOps summary returned by `GET /admin/v1/spend/summary`.
type SpendSummaryResponse struct {
	TotalRequests     int64            `json:"total_requests"`
	TotalTokens       int64            `json:"total_tokens"`
	TotalCostMicros   int64            `json:"total_cost_micros"`
	TotalCostUSD      float64          `json:"total_cost_usd"`
	UnpricedRequests  int64            `json:"unpriced_requests"`
	UnpricedTokens    int64            `json:"unpriced_tokens"`
	SpendByProvider   map[string]int64 `json:"spend_by_provider"`
	SpendByModel      map[string]int64 `json:"spend_by_model"`
	SpendByTeam       map[string]int64 `json:"spend_by_team"`
	SpendByUser       map[string]int64 `json:"spend_by_user"`
	SpendByVirtualKey map[string]int64 `json:"spend_by_virtual_key"`
}

// ModelGroupConfig represents a routing model group returned by `/admin/v1/model-groups`.
type ModelGroupConfig struct {
	ID                     string           `json:"id"`
	OrgID                  string           `json:"org_id"`
	Alias                  string           `json:"alias"`
	Description            string           `json:"description,omitempty"`
	RoutingStrategy        string           `json:"routing_strategy"`
	FallbackGroupIDs       []string         `json:"fallback_group_ids,omitempty"`
	ContextWindowFallbacks []FallbackTarget `json:"context_window_fallbacks,omitempty"`
	ContentPolicyFallbacks []FallbackTarget `json:"content_policy_fallbacks,omitempty"`
	FallbackTargets        []FallbackTarget `json:"fallback_targets,omitempty"`
	SaturationFallbacks    []FallbackTarget `json:"saturation_fallbacks,omitempty"`
	DropUnsupportedParams  bool             `json:"drop_unsupported_params,omitempty"`
	DisableCooldowns       bool             `json:"disable_cooldowns,omitempty"`
	MaxRetries             int              `json:"max_retries"`
	CooldownSeconds        int              `json:"cooldown_seconds"`
	FailureThreshold       int              `json:"failure_threshold"`
	IsActive               bool             `json:"is_active"`
	CreatedAt              time.Time        `json:"created_at"`
	UpdatedAt              time.Time        `json:"updated_at"`
}

// ModelGroupUpdateRequest specifies partial or full updates for `PUT /admin/v1/model-groups/{groupID}`.
type ModelGroupUpdateRequest struct {
	Alias                  *string           `json:"alias,omitempty"`
	Description            *string           `json:"description,omitempty"`
	RoutingStrategy        *string           `json:"routing_strategy,omitempty"`
	FallbackGroupIDs       *[]string         `json:"fallback_group_ids,omitempty"`
	ContextWindowFallbacks *[]FallbackTarget `json:"context_window_fallbacks,omitempty"`
	ContentPolicyFallbacks *[]FallbackTarget `json:"content_policy_fallbacks,omitempty"`
	FallbackTargets        *[]FallbackTarget `json:"fallback_targets,omitempty"`
	SaturationFallbacks    *[]FallbackTarget `json:"saturation_fallbacks,omitempty"`
	DropUnsupportedParams  *bool             `json:"drop_unsupported_params,omitempty"`
	DisableCooldowns       *bool             `json:"disable_cooldowns,omitempty"`
	MaxRetries             *int              `json:"max_retries,omitempty"`
	CooldownSeconds        *int              `json:"cooldown_seconds,omitempty"`
	FailureThreshold       *int              `json:"failure_threshold,omitempty"`
	IsActive               *bool             `json:"is_active,omitempty"`
}

// DeploymentConfig represents a physical model deployment returned by `/admin/v1/deployments`.
type DeploymentConfig struct {
	ID                  string    `json:"id"`
	ModelGroupID        string    `json:"model_group_id"`
	GlobalModelID       string    `json:"global_model_id"`
	CredentialID        string    `json:"credential_id"`
	DeploymentName      string    `json:"deployment_name"`
	Region              string    `json:"region"`
	Weight              int       `json:"weight"`
	RPMCapacity         int       `json:"rpm_capacity"`
	TPMCapacity         int       `json:"tpm_capacity"`
	ITPMCapacity        int       `json:"itpm_capacity,omitempty"`
	OTPMCapacity        int       `json:"otpm_capacity,omitempty"`
	MaxParallelRequests int       `json:"max_parallel_requests,omitempty"`
	TimeoutMs           int       `json:"timeout_ms"`
	Priority            int       `json:"priority"`
	Tags                []string  `json:"tags,omitempty"`
	MaxBudgetMicros     int64     `json:"max_budget_micros,omitempty"`
	BudgetResetPeriod   string    `json:"budget_reset_period,omitempty"`
	Status              string    `json:"status"`
	CreatedAt           time.Time `json:"created_at"`
	UpdatedAt           time.Time `json:"updated_at"`
}

// DeploymentPatchRequest specifies partial mutable updates for `PATCH /admin/v1/deployments/{depID}`.
type DeploymentPatchRequest struct {
	DeploymentName      *string   `json:"deployment_name,omitempty"`
	Region              *string   `json:"region,omitempty"`
	Weight              *int      `json:"weight,omitempty"`
	RPMCapacity         *int      `json:"rpm_capacity,omitempty"`
	TPMCapacity         *int      `json:"tpm_capacity,omitempty"`
	ITPMCapacity        *int      `json:"itpm_capacity,omitempty"`
	OTPMCapacity        *int      `json:"otpm_capacity,omitempty"`
	MaxParallelRequests *int      `json:"max_parallel_requests,omitempty"`
	TimeoutMs           *int      `json:"timeout_ms,omitempty"`
	Priority            *int      `json:"priority,omitempty"`
	Tags                *[]string `json:"tags,omitempty"`
	MaxBudgetMicros     *int64    `json:"max_budget_micros,omitempty"`
	BudgetResetPeriod   *string   `json:"budget_reset_period,omitempty"`
	Status              *string   `json:"status,omitempty"`
}
