// Code generated from gemini_api_v1.1.0.yaml; DO NOT EDIT MANUALLY.
package providers

// GeminiGenerateContentRequest matches GenerateContentRequest in gemini_api_v1.1.0.yaml.
type GeminiGenerateContentRequest struct {
	Contents          []GeminiContent         `json:"contents"`
	SystemInstruction *GeminiContent          `json:"systemInstruction,omitempty"`
	Tools             []GeminiTool            `json:"tools,omitempty"`
	GenerationConfig  *GeminiGenerationConfig `json:"generationConfig,omitempty"`
}

type GeminiContent struct {
	Role  string       `json:"role,omitempty"` // "user", "model", "function"
	Parts []GeminiPart `json:"parts"`
}

type GeminiPart struct {
	Text             string                  `json:"text,omitempty"`
	Thought          bool                    `json:"thought,omitempty"`
	FunctionCall     *GeminiFunctionCall     `json:"functionCall,omitempty"`
	FunctionResponse *GeminiFunctionResponse `json:"functionResponse,omitempty"`
}

type GeminiFunctionCall struct {
	Name string         `json:"name"`
	Args map[string]any `json:"args,omitempty"`
}

type GeminiFunctionResponse struct {
	Name     string         `json:"name"`
	Response map[string]any `json:"response"`
}

type GeminiTool struct {
	FunctionDeclarations []GeminiFunctionDeclaration `json:"functionDeclarations,omitempty"`
}

type GeminiFunctionDeclaration struct {
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	Parameters  map[string]any `json:"parameters,omitempty"`
}

type GeminiGenerationConfig struct {
	Temperature      *float64              `json:"temperature,omitempty"`
	TopP             *float64              `json:"topP,omitempty"`
	MaxOutputTokens  *int                  `json:"maxOutputTokens,omitempty"`
	StopSequences    []string              `json:"stopSequences,omitempty"`
	ResponseMimeType string                `json:"responseMimeType,omitempty"`
	ResponseSchema   map[string]any        `json:"responseSchema,omitempty"`
	ThinkingConfig   *GeminiThinkingConfig `json:"thinkingConfig,omitempty"`
}

type GeminiThinkingConfig struct {
	ThinkingBudget int `json:"thinkingBudget"`
}

// GeminiGenerateContentResponse matches GenerateContentResponse in gemini_api_v1.1.0.yaml.
type GeminiGenerateContentResponse struct {
	Candidates     []GeminiCandidate     `json:"candidates"`
	PromptFeedback *GeminiPromptFeedback `json:"promptFeedback,omitempty"`
	UsageMetadata  *GeminiUsageMetadata  `json:"usageMetadata,omitempty"`
	ModelVersion   string                `json:"modelVersion,omitempty"`
}

type GeminiPromptFeedback struct {
	BlockReason   string               `json:"blockReason,omitempty"`
	SafetyRatings []GeminiSafetyRating `json:"safetyRatings,omitempty"`
}

type GeminiSafetyRating struct {
	Category    string `json:"category,omitempty"`
	Probability string `json:"probability,omitempty"`
}

type GeminiCandidate struct {
	Index        int           `json:"index"`
	Content      GeminiContent `json:"content"`
	FinishReason string        `json:"finishReason,omitempty"` // "STOP", "MAX_TOKENS", "SAFETY"
}

type GeminiUsageMetadata struct {
	PromptTokenCount        int `json:"promptTokenCount"`
	CandidatesTokenCount    int `json:"candidatesTokenCount"`
	TotalTokenCount         int `json:"totalTokenCount"`
	CachedContentTokenCount int `json:"cachedContentTokenCount,omitempty"`
	ThoughtsTokenCount      int `json:"thoughtsTokenCount,omitempty"`
}

// GeminiEmbedContentRequest matches EmbedContentRequest in gemini_api_v1.1.0.yaml.
type GeminiEmbedContentRequest struct {
	Model                string        `json:"model,omitempty"`
	Content              GeminiContent `json:"content"`
	OutputDimensionality *int          `json:"outputDimensionality,omitempty"`
}

type GeminiEmbedContentResponse struct {
	Embedding *GeminiContentEmbedding `json:"embedding,omitempty"`
}

type GeminiContentEmbedding struct {
	Values []float64 `json:"values"`
}

// GeminiModelsResponse matches ListModelsResponse in gemini_api_v1.1.0.yaml.
type GeminiModelsResponse struct {
	Models        []GeminiModelInfo `json:"models"`
	NextPageToken string            `json:"nextPageToken,omitempty"`
}

type GeminiModelInfo struct {
	Name                       string   `json:"name"` // e.g. "models/gemini-2.5-pro"
	DisplayName                string   `json:"displayName"`
	Description                string   `json:"description,omitempty"`
	InputTokenLimit            int      `json:"inputTokenLimit,omitempty"`
	OutputTokenLimit           int      `json:"outputTokenLimit,omitempty"`
	SupportedGenerationMethods []string `json:"supportedGenerationMethods,omitempty"`
}
