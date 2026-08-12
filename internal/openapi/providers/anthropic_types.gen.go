// Code generated from anthropic_api.yaml; DO NOT EDIT MANUALLY.
package providers

// AnthropicMessageRequest matches MessageRequestBody in anthropic_api.yaml (/v1/messages).
type AnthropicMessageRequest struct {
	Model         string                  `json:"model"`
	Messages      []AnthropicInputMessage `json:"messages"`
	MaxTokens     int                     `json:"max_tokens"`
	System        string                  `json:"system,omitempty"`
	Temperature   *float64                `json:"temperature,omitempty"`
	TopP          *float64                `json:"top_p,omitempty"`
	StopSequences []string                `json:"stop_sequences,omitempty"`
	Stream        bool                    `json:"stream,omitempty"`
	Tools         []AnthropicTool         `json:"tools,omitempty"`
	ToolChoice    any                     `json:"tool_choice,omitempty"`
	Thinking      *AnthropicThinking      `json:"thinking,omitempty"`
}

type AnthropicThinking struct {
	Type         string `json:"type"` // "enabled"
	BudgetTokens int    `json:"budget_tokens"`
}

type AnthropicInputMessage struct {
	Role    string                  `json:"role"` // "user" or "assistant"
	Content []AnthropicContentBlock `json:"content"`
}

type AnthropicContentBlock struct {
	Type      string         `json:"type"` // "text", "image", "tool_use", "tool_result", "thinking"
	Text      string         `json:"text,omitempty"`
	Thinking  string         `json:"thinking,omitempty"`
	ID        string         `json:"id,omitempty"`
	Name      string         `json:"name,omitempty"`
	Input     any            `json:"input,omitempty"`
	ToolUseID string         `json:"tool_use_id,omitempty"`
	Content   string         `json:"content,omitempty"`
	Source    map[string]any `json:"source,omitempty"`
}

type AnthropicTool struct {
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	InputSchema map[string]any `json:"input_schema"`
}

// AnthropicMessageResponse matches MessageResponse in anthropic_api.yaml.
type AnthropicMessageResponse struct {
	ID           string                  `json:"id"`
	Type         string                  `json:"type"` // "message"
	Role         string                  `json:"role"` // "assistant"
	Model        string                  `json:"model"`
	Content      []AnthropicContentBlock `json:"content"`
	StopReason   string                  `json:"stop_reason"` // "end_turn", "max_tokens", "stop_sequence", "tool_use"
	StopSequence string                  `json:"stop_sequence,omitempty"`
	Usage        AnthropicUsage          `json:"usage"`
}

type AnthropicUsage struct {
	InputTokens              int `json:"input_tokens"`
	OutputTokens             int `json:"output_tokens"`
	CacheCreationInputTokens int `json:"cache_creation_input_tokens,omitempty"`
	CacheReadInputTokens     int `json:"cache_read_input_tokens,omitempty"`
}

// AnthropicStreamEvent represents SSE payloads emitted by Anthropic /v1/messages when stream=true.
type AnthropicStreamEvent struct {
	Type         string                    `json:"type"` // "message_start", "content_block_start", "content_block_delta", "message_delta", "message_stop", "error"
	Index        int                       `json:"index,omitempty"`
	Message      *AnthropicMessageResponse `json:"message,omitempty"`
	ContentBlock *AnthropicContentBlock    `json:"content_block,omitempty"`
	Delta        *AnthropicDelta           `json:"delta,omitempty"`
	Usage        *AnthropicUsage           `json:"usage,omitempty"`
}

type AnthropicDelta struct {
	Type        string `json:"type,omitempty"` // "text_delta", "input_json_delta", "thinking_delta"
	Text        string `json:"text,omitempty"`
	Thinking    string `json:"thinking,omitempty"`
	PartialJSON string `json:"partial_json,omitempty"`
	StopReason  string `json:"stop_reason,omitempty"`
}

// AnthropicModelsResponse matches GET /v1/models in anthropic_api.yaml.
type AnthropicModelsResponse struct {
	Data    []AnthropicModelInfo `json:"data"`
	FirstID string               `json:"first_id,omitempty"`
	LastID  string               `json:"last_id,omitempty"`
	HasMore bool                 `json:"has_more"`
}

type AnthropicModelInfo struct {
	ID          string `json:"id"`
	DisplayName string `json:"display_name"`
	CreatedAt   string `json:"created_at"`
	Type        string `json:"type"`
}
