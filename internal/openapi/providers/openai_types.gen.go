// Code generated from openai_api.yaml; DO NOT EDIT MANUALLY.
package providers

// OpenAIChatCompletionRequest matches CreateChatCompletionRequest in openai_api.yaml.
type OpenAIChatCompletionRequest struct {
	Model           string                `json:"model"`
	Messages        []OpenAIMessage       `json:"messages"`
	Tools           []OpenAITool          `json:"tools,omitempty"`
	ToolChoice      any                   `json:"tool_choice,omitempty"`
	Temperature     *float64              `json:"temperature,omitempty"`
	TopP            *float64              `json:"top_p,omitempty"`
	MaxTokens       *int                  `json:"max_completion_tokens,omitempty"`
	LegacyMaxTokens *int                  `json:"max_tokens,omitempty"`
	Stop            []string              `json:"stop,omitempty"`
	Stream          bool                  `json:"stream,omitempty"`
	StreamOptions   *OpenAIStreamOptions  `json:"stream_options,omitempty"`
	ResponseFormat  *OpenAIResponseFormat `json:"response_format,omitempty"`
	ReasoningEffort string                `json:"reasoning_effort,omitempty"`
	User            string                `json:"user,omitempty"`
}

type OpenAIStreamOptions struct {
	IncludeUsage bool `json:"include_usage"`
}

type OpenAIResponseFormat struct {
	Type       string         `json:"type"`
	JSONSchema map[string]any `json:"json_schema,omitempty"`
}

type OpenAIMessage struct {
	Role             string           `json:"role"`
	Content          any              `json:"content,omitempty"` // string or []OpenAIContentPart
	Name             string           `json:"name,omitempty"`
	ToolCallID       string           `json:"tool_call_id,omitempty"`
	ToolCalls        []OpenAIToolCall `json:"tool_calls,omitempty"`
	ReasoningContent string           `json:"reasoning_content,omitempty"`
	Reasoning        string           `json:"reasoning,omitempty"`
	Thought          string           `json:"thought,omitempty"`
}

type OpenAITool struct {
	Type     string         `json:"type"`
	Function OpenAIFunction `json:"function"`
}

type OpenAIFunction struct {
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	Parameters  map[string]any `json:"parameters,omitempty"`
	Strict      bool           `json:"strict,omitempty"`
}

type OpenAIToolCall struct {
	Index    *int               `json:"index,omitempty"`
	ID       string             `json:"id,omitempty"`
	Type     string             `json:"type,omitempty"`
	Function OpenAIFunctionCall `json:"function"`
}

type OpenAIFunctionCall struct {
	Name      string `json:"name,omitempty"`
	Arguments string `json:"arguments,omitempty"`
}

// OpenAIChatCompletionResponse matches CreateChatCompletionResponse in openai_api.yaml.
type OpenAIChatCompletionResponse struct {
	ID                string         `json:"id"`
	Object            string         `json:"object"`
	Created           int64          `json:"created"`
	Model             string         `json:"model"`
	Choices           []OpenAIChoice `json:"choices"`
	Usage             OpenAIUsage    `json:"usage"`
	SystemFingerprint string         `json:"system_fingerprint,omitempty"`
}

type OpenAIChoice struct {
	Index        int           `json:"index"`
	Message      OpenAIMessage `json:"message"`
	FinishReason string        `json:"finish_reason"`
}

type OpenAIUsage struct {
	PromptTokens            int                      `json:"prompt_tokens"`
	CompletionTokens        int                      `json:"completion_tokens"`
	TotalTokens             int                      `json:"total_tokens"`
	PromptTokensDetails     *OpenAIPromptDetails     `json:"prompt_tokens_details,omitempty"`
	CompletionTokensDetails *OpenAICompletionDetails `json:"completion_tokens_details,omitempty"`
}

type OpenAIPromptDetails struct {
	CachedTokens int `json:"cached_tokens,omitempty"`
}

type OpenAICompletionDetails struct {
	ReasoningTokens int `json:"reasoning_tokens,omitempty"`
}

// OpenAIEmbeddingRequest matches CreateEmbeddingRequest in openai_api.yaml.
type OpenAIEmbeddingRequest struct {
	Model          string   `json:"model"`
	Input          []string `json:"input"`
	EncodingFormat string   `json:"encoding_format,omitempty"`
	Dimensions     *int     `json:"dimensions,omitempty"`
	User           string   `json:"user,omitempty"`
}

type OpenAIEmbeddingResponse struct {
	Object string                `json:"object"`
	Data   []OpenAIEmbeddingData `json:"data"`
	Model  string                `json:"model"`
	Usage  OpenAIUsage           `json:"usage"`
}

type OpenAIEmbeddingData struct {
	Object    string    `json:"object"`
	Index     int       `json:"index"`
	Embedding []float64 `json:"embedding"`
}

type OpenAIModelsResponse struct {
	Object string        `json:"object"`
	Data   []OpenAIModel `json:"data"`
}

type OpenAIModel struct {
	ID      string `json:"id"`
	Object  string `json:"object"`
	Created int64  `json:"created"`
	OwnedBy string `json:"owned_by"`
}
