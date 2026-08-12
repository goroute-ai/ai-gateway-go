// Code generated from api/openapi/providers/ollama.openapi.yaml; DO NOT EDIT MANUALLY.
package providers

// OllamaChatRequest matches OllamaChatRequest in ollama.openapi.yaml (/api/chat).
type OllamaChatRequest struct {
	Model    string          `json:"model"`
	Messages []OllamaMessage `json:"messages"`
	Tools    []OpenAITool    `json:"tools,omitempty"`
	Stream   bool            `json:"stream"`
	Format   any             `json:"format,omitempty"`
	Options  map[string]any  `json:"options,omitempty"`
}

type OllamaMessage struct {
	Role      string           `json:"role"`
	Content   string           `json:"content"`
	Images    []string         `json:"images,omitempty"`
	ToolCalls []OpenAIToolCall `json:"tool_calls,omitempty"`
}

// OllamaChatResponse matches OllamaChatResponse in ollama.openapi.yaml.
type OllamaChatResponse struct {
	Model           string        `json:"model"`
	CreatedAt       string        `json:"created_at"`
	Message         OllamaMessage `json:"message"`
	Done            bool          `json:"done"`
	DoneReason      string        `json:"done_reason,omitempty"`
	PromptEvalCount int           `json:"prompt_eval_count,omitempty"`
	EvalCount       int           `json:"eval_count,omitempty"`
}

// OllamaEmbedRequest matches OllamaEmbedRequest in ollama.openapi.yaml (/api/embed).
type OllamaEmbedRequest struct {
	Model string   `json:"model"`
	Input []string `json:"input"`
}

type OllamaEmbedResponse struct {
	Model           string      `json:"model"`
	Embeddings      [][]float64 `json:"embeddings"`
	PromptEvalCount int         `json:"prompt_eval_count,omitempty"`
}

// OllamaTagsResponse matches OllamaTagsResponse in ollama.openapi.yaml (/api/tags).
type OllamaTagsResponse struct {
	Models []OllamaModelTag `json:"models"`
}

type OllamaModelTag struct {
	Name       string `json:"name"`
	Model      string `json:"model"`
	ModifiedAt string `json:"modified_at"`
	Size       int64  `json:"size"`
}
