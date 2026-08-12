// Code generated from mistral_api.yaml; DO NOT EDIT MANUALLY.
package providers

// MistralChatCompletionRequest matches ChatCompletionRequest in mistral_api.yaml (/v1/chat/completions).
type MistralChatCompletionRequest struct {
	Model          string                `json:"model"`
	Messages       []MistralMessage      `json:"messages"`
	Temperature    *float64              `json:"temperature,omitempty"`
	TopP           *float64              `json:"top_p,omitempty"`
	MaxTokens      *int                  `json:"max_tokens,omitempty"`
	Stream         bool                  `json:"stream,omitempty"`
	Stop           []string              `json:"stop,omitempty"`
	Tools          []OpenAITool          `json:"tools,omitempty"`
	ToolChoice     any                   `json:"tool_choice,omitempty"`
	ResponseFormat *OpenAIResponseFormat `json:"response_format,omitempty"`
	SafePrompt     bool                  `json:"safe_prompt,omitempty"`
}

type MistralMessage struct {
	Role       string           `json:"role"`
	Content    string           `json:"content"`
	Name       string           `json:"name,omitempty"`
	ToolCallID string           `json:"tool_call_id,omitempty"`
	ToolCalls  []OpenAIToolCall `json:"tool_calls,omitempty"`
}

// MistralChatCompletionResponse matches ChatCompletionResponse in mistral_api.yaml.
type MistralChatCompletionResponse struct {
	ID      string          `json:"id"`
	Object  string          `json:"object"`
	Created int64           `json:"created"`
	Model   string          `json:"model"`
	Choices []MistralChoice `json:"choices"`
	Usage   OpenAIUsage     `json:"usage"`
}

type MistralChoice struct {
	Index        int            `json:"index"`
	Message      MistralMessage `json:"message"`
	FinishReason string         `json:"finish_reason"`
}

// MistralEmbeddingRequest matches EmbeddingRequest in mistral_api.yaml (/v1/embeddings).
type MistralEmbeddingRequest struct {
	Model          string   `json:"model"`
	Input          []string `json:"input"`
	EncodingFormat string   `json:"encoding_format,omitempty"`
}

type MistralEmbeddingResponse struct {
	ID     string                `json:"id"`
	Object string                `json:"object"`
	Data   []OpenAIEmbeddingData `json:"data"`
	Model  string                `json:"model"`
	Usage  OpenAIUsage           `json:"usage"`
}

// MistralModelList matches ModelList in mistral_api.yaml (/v1/models).
type MistralModelList struct {
	Object string             `json:"object"`
	Data   []MistralModelCard `json:"data"`
}

type MistralModelCard struct {
	ID               string `json:"id"`
	Object           string `json:"object"`
	Created          int64  `json:"created"`
	OwnedBy          string `json:"owned_by"`
	Name             string `json:"name,omitempty"`
	MaxContextLength int    `json:"max_context_length,omitempty"`
}
