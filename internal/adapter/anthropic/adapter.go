package anthropic

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/adapter"
	"github.com/goroute-ai/ai-gateway-go/internal/adapter/sse"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/openapi/providers"
)

const (
	defaultBaseURL   = "https://api.anthropic.com"
	anthropicVersion = "2023-06-01"
	defaultMaxTokens = 4096
)

type Adapter struct {
	client *http.Client
}

func NewAdapter(client *http.Client) *Adapter {
	if client == nil {
		client = adapter.NewPooledHTTPClient(120 * time.Second)
	}
	return &Adapter{client: client}
}

func (a *Adapter) Provider() domain.ProviderType {
	return domain.ProviderAnthropic
}

func resolveBaseURL(cred *domain.ProviderCredential) string {
	if cred != nil && strings.TrimSpace(cred.BaseURL) != "" {
		return strings.TrimRight(cred.BaseURL, "/")
	}
	return defaultBaseURL
}

type wireCacheControl struct {
	Type string `json:"type"`
	TTL  string `json:"ttl,omitempty"`
}

type wireContentBlock struct {
	Type         string            `json:"type"`
	Text         string            `json:"text,omitempty"`
	Thinking     string            `json:"thinking,omitempty"`
	ID           string            `json:"id,omitempty"`
	Name         string            `json:"name,omitempty"`
	Input        any               `json:"input,omitempty"`
	ToolUseID    string            `json:"tool_use_id,omitempty"`
	Content      any               `json:"content,omitempty"`
	Source       map[string]any    `json:"source,omitempty"`
	CacheControl *wireCacheControl `json:"cache_control,omitempty"`
}

type wireInputMessage struct {
	Role    string             `json:"role"`
	Content []wireContentBlock `json:"content"`
}

type wireTool struct {
	Name         string            `json:"name"`
	Description  string            `json:"description,omitempty"`
	InputSchema  map[string]any    `json:"input_schema"`
	CacheControl *wireCacheControl `json:"cache_control,omitempty"`
}

type wireThinking struct {
	Type         string `json:"type"`
	BudgetTokens int    `json:"budget_tokens,omitempty"`
}

type wireOutputConfig struct {
	Effort string `json:"effort,omitempty"`
}

type wireOutputFormat struct {
	Type   string `json:"type"`
	Schema any    `json:"schema,omitempty"`
}

type wireMessageRequest struct {
	Model         string             `json:"model"`
	Messages      []wireInputMessage `json:"messages"`
	MaxTokens     int                `json:"max_tokens"`
	System        any                `json:"system,omitempty"`
	Temperature   *float64           `json:"temperature,omitempty"`
	TopP          *float64           `json:"top_p,omitempty"`
	StopSequences []string           `json:"stop_sequences,omitempty"`
	Stream        bool               `json:"stream,omitempty"`
	Tools         []wireTool         `json:"tools,omitempty"`
	ToolChoice    any                `json:"tool_choice,omitempty"`
	Thinking      *wireThinking      `json:"thinking,omitempty"`
	OutputConfig  *wireOutputConfig  `json:"output_config,omitempty"`
	OutputFormat  *wireOutputFormat  `json:"output_format,omitempty"`
}

func toWireCacheControl(cc *domain.CacheControl) *wireCacheControl {
	if cc == nil || cc.Type == "" {
		return nil
	}
	return &wireCacheControl{Type: cc.Type, TTL: cc.TTL}
}

// sanitizeToolName normalizes tool names to match Anthropic's ^[a-zA-Z0-9_-]{1,128}$ constraint.
func sanitizeToolName(name string) string {
	var b strings.Builder
	b.Grow(len(name))
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '-' {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
		if b.Len() >= 128 {
			break
		}
	}
	if b.Len() == 0 {
		return "tool"
	}
	return b.String()
}

func parseDataURI(uri string) (mime string, b64 string, ok bool) {
	if !strings.HasPrefix(uri, "data:") {
		return "", "", false
	}
	rest := strings.TrimPrefix(uri, "data:")
	idx := strings.Index(rest, ";base64,")
	if idx < 0 {
		return "", "", false
	}
	return rest[:idx], rest[idx+len(";base64,"):], true
}

func isAdaptiveThinkingModel(model string) bool {
	lower := strings.ToLower(model)
	return strings.Contains(lower, "4-6") ||
		strings.Contains(lower, "4.6") ||
		strings.Contains(lower, "4-7") ||
		strings.Contains(lower, "4.7")
}

func validateThinkingOutputLimit(model string, req *domain.CanonicalChatRequest) error {
	if req == nil || req.ReasoningEffort == "" || req.MaxTokens == nil || isAdaptiveThinkingModel(model) {
		return nil
	}
	if *req.MaxTokens <= 1024 {
		return &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "reasoning_budget_exceeds_max_tokens",
			Message:    "Anthropic extended thinking requires max_tokens greater than 1024; the requested output limit cannot be raised",
			Provider:   domain.ProviderAnthropic,
		}
	}
	return nil
}

func mapAnthropicEffort(effort string) string {
	switch strings.ToLower(strings.TrimSpace(effort)) {
	case "minimal":
		return "low"
	case "xhigh":
		return "max"
	case "low", "medium", "high", "max":
		return strings.ToLower(strings.TrimSpace(effort))
	default:
		return "medium"
	}
}

func buildAnthropicToolChoice(tc any, origToSanitized map[string]string) any {
	if tc == nil {
		return nil
	}
	switch v := tc.(type) {
	case string:
		switch strings.ToLower(v) {
		case "auto":
			return map[string]any{"type": "auto"}
		case "required", "any":
			return map[string]any{"type": "any"}
		case "none":
			return map[string]any{"type": "none"}
		}
	case map[string]any:
		if t, _ := v["type"].(string); t == "function" {
			if fn, ok := v["function"].(map[string]any); ok {
				if name, _ := fn["name"].(string); name != "" {
					if mapped, ok := origToSanitized[name]; ok {
						name = mapped
					} else {
						name = sanitizeToolName(name)
					}
					return map[string]any{"type": "tool", "name": name}
				}
			}
		}
		return v
	}
	return nil
}

func translateUserParts(m domain.CanonicalMessage) []wireContentBlock {
	var blocks []wireContentBlock
	if len(m.Parts) > 0 {
		for _, p := range m.Parts {
			cc := toWireCacheControl(p.CacheControl)
			switch p.Type {
			case "text":
				blocks = append(blocks, wireContentBlock{
					Type:         "text",
					Text:         p.Text,
					CacheControl: cc,
				})
			case "image_url":
				if p.ImageURL != nil && p.ImageURL.URL != "" {
					if mime, b64, ok := parseDataURI(p.ImageURL.URL); ok {
						blocks = append(blocks, wireContentBlock{
							Type: "image",
							Source: map[string]any{
								"type":       "base64",
								"media_type": mime,
								"data":       b64,
							},
							CacheControl: cc,
						})
					} else {
						blocks = append(blocks, wireContentBlock{
							Type: "image",
							Source: map[string]any{
								"type": "url",
								"url":  p.ImageURL.URL,
							},
							CacheControl: cc,
						})
					}
				}
			case "document":
				if p.Document != nil {
					if p.Document.Data != "" {
						mime := p.Document.MimeType
						if mime == "" {
							mime = "application/pdf"
						}
						blocks = append(blocks, wireContentBlock{
							Type: "document",
							Source: map[string]any{
								"type":       "base64",
								"media_type": mime,
								"data":       p.Document.Data,
							},
							CacheControl: cc,
						})
					} else if p.Document.URL != "" {
						blocks = append(blocks, wireContentBlock{
							Type: "document",
							Source: map[string]any{
								"type": "url",
								"url":  p.Document.URL,
							},
							CacheControl: cc,
						})
					}
				}
			}
		}
	}
	if len(blocks) == 0 {
		blocks = append(blocks, wireContentBlock{
			Type: "text",
			Text: m.Content,
		})
	}
	if m.CacheControl != nil && len(blocks) > 0 && blocks[len(blocks)-1].CacheControl == nil {
		blocks[len(blocks)-1].CacheControl = toWireCacheControl(m.CacheControl)
	}
	return blocks
}

// toAnthropicRequest translates CanonicalChatRequest into Anthropic's /v1/messages request body.
func toAnthropicRequest(model string, req *domain.CanonicalChatRequest, stream bool) wireMessageRequest {
	antReq, _ := toAnthropicRequestWithMap(model, req, stream)
	return antReq
}

// toAnthropicRequestWithMap translates CanonicalChatRequest into Anthropic's /v1/messages request body.
// Returns the wire payload and a map from sanitized tool names back to original names.
func toAnthropicRequestWithMap(model string, req *domain.CanonicalChatRequest, stream bool) (wireMessageRequest, map[string]string) {
	var systemBlocks []wireContentBlock
	var systemPlain []string
	hasSystemCacheControl := false
	var messages []wireInputMessage

	origToSanitized := make(map[string]string, len(req.Tools))
	sanitizedToOrig := make(map[string]string, len(req.Tools))
	for _, t := range req.Tools {
		san := sanitizeToolName(t.Function.Name)
		origToSanitized[t.Function.Name] = san
		sanitizedToOrig[san] = t.Function.Name
	}

	for _, m := range req.Messages {
		switch m.Role {
		case "system", "developer":
			if strings.TrimSpace(m.Content) != "" {
				systemPlain = append(systemPlain, m.Content)
				cc := toWireCacheControl(m.CacheControl)
				if cc != nil {
					hasSystemCacheControl = true
				}
				systemBlocks = append(systemBlocks, wireContentBlock{
					Type:         "text",
					Text:         m.Content,
					CacheControl: cc,
				})
			}
		case "tool":
			block := wireContentBlock{
				Type:         "tool_result",
				ToolUseID:    m.ToolCallID,
				Content:      m.Content,
				CacheControl: toWireCacheControl(m.CacheControl),
			}
			// Consolidate consecutive tool results into a single user message to respect Anthropic's role alternation rule
			if len(messages) > 0 && messages[len(messages)-1].Role == "user" {
				messages[len(messages)-1].Content = append(messages[len(messages)-1].Content, block)
			} else {
				messages = append(messages, wireInputMessage{
					Role:    "user",
					Content: []wireContentBlock{block},
				})
			}
		case "assistant":
			var blocks []wireContentBlock
			if m.Content != "" {
				blocks = append(blocks, wireContentBlock{
					Type: "text",
					Text: m.Content,
				})
			}
			for _, tc := range m.ToolCalls {
				var parsedInput any = map[string]any{}
				if tc.Function.Arguments != "" {
					_ = json.Unmarshal([]byte(tc.Function.Arguments), &parsedInput)
				}
				name := tc.Function.Name
				if mapped, ok := origToSanitized[name]; ok {
					name = mapped
				} else {
					name = sanitizeToolName(name)
				}
				blocks = append(blocks, wireContentBlock{
					Type:  "tool_use",
					ID:    tc.ID,
					Name:  name,
					Input: parsedInput,
				})
			}
			if len(blocks) > 0 {
				if m.CacheControl != nil && blocks[len(blocks)-1].CacheControl == nil {
					blocks[len(blocks)-1].CacheControl = toWireCacheControl(m.CacheControl)
				}
				messages = append(messages, wireInputMessage{
					Role:    "assistant",
					Content: blocks,
				})
			}
		default: // "user"
			messages = append(messages, wireInputMessage{
				Role:    "user",
				Content: translateUserParts(m),
			})
		}
	}

	maxTok := defaultMaxTokens
	if req.MaxTokens != nil && *req.MaxTokens > 0 {
		maxTok = *req.MaxTokens
	}

	var tools []wireTool
	for _, t := range req.Tools {
		schema := t.Function.Parameters
		if schema == nil {
			schema = map[string]any{"type": "object", "properties": map[string]any{}}
		}
		san := origToSanitized[t.Function.Name]
		if san == "" {
			san = sanitizeToolName(t.Function.Name)
		}
		tools = append(tools, wireTool{
			Name:         san,
			Description:  t.Function.Description,
			InputSchema:  schema,
			CacheControl: toWireCacheControl(t.CacheControl),
		})
	}

	var systemVal any
	if hasSystemCacheControl {
		systemVal = systemBlocks
	} else if len(systemPlain) > 0 {
		systemVal = strings.Join(systemPlain, "\n\n")
	}

	antReq := wireMessageRequest{
		Model:         model,
		Messages:      messages,
		MaxTokens:     maxTok,
		System:        systemVal,
		Temperature:   req.Temperature,
		TopP:          req.TopP,
		StopSequences: req.Stop,
		Stream:        stream,
		Tools:         tools,
		ToolChoice:    buildAnthropicToolChoice(req.ToolChoice, origToSanitized),
	}

	if req.ResponseFormat != nil && req.ResponseFormat.Type == "json_schema" && len(req.ResponseFormat.JSONSchema) > 0 {
		schema := any(req.ResponseFormat.JSONSchema)
		if inner, ok := req.ResponseFormat.JSONSchema["schema"]; ok {
			schema = inner
		}
		antReq.OutputFormat = &wireOutputFormat{
			Type:   "json_schema",
			Schema: schema,
		}
	}

	if req.ReasoningEffort != "" {
		if isAdaptiveThinkingModel(model) {
			antReq.Thinking = &wireThinking{Type: "adaptive"}
			antReq.OutputConfig = &wireOutputConfig{Effort: mapAnthropicEffort(req.ReasoningEffort)}
		} else {
			budget := 2048
			switch strings.ToLower(req.ReasoningEffort) {
			case "minimal":
				budget = 1024
			case "high":
				budget = 8192
			case "xhigh", "max":
				budget = 16384
			case "medium":
				budget = 4096
			}
			if req.MaxTokens != nil && *req.MaxTokens > 0 && budget >= maxTok {
				budget = maxTok - 1
			} else if req.MaxTokens == nil && maxTok <= budget {
				antReq.MaxTokens = budget + 2048
			}
			antReq.Thinking = &wireThinking{
				Type:         "enabled",
				BudgetTokens: budget,
			}
		}
		// Anthropic Messages API strictly requires temperature = 1.0 (or omitted) and top_p = nil when thinking is enabled
		antReq.Temperature = nil
		antReq.TopP = nil
	}

	return antReq, sanitizedToOrig
}

func mapStopReason(reason string) string {
	switch reason {
	case "end_turn", "stop_sequence":
		return "stop"
	case "max_tokens":
		return "length"
	case "tool_use":
		return "tool_calls"
	default:
		return "stop"
	}
}

func (a *Adapter) ChatCompletion(ctx context.Context, dep *domain.Deployment, req *domain.CanonicalChatRequest) (*domain.CanonicalChatResponse, error) {
	model := req.ResolvedModel
	if model == "" && dep != nil && dep.GlobalModel != nil {
		model = dep.GlobalModel.ModelName
	}
	if model == "" {
		model = req.Model
	}
	if err := validateThinkingOutputLimit(model, req); err != nil {
		return nil, err
	}

	payload, sanitizedToOrig := toAnthropicRequestWithMap(model, req, false)
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	endpoint := resolveBaseURL(dep.Credential) + "/v1/messages"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	setHeaders(httpReq, dep.Credential)

	resp, err := a.client.Do(httpReq)
	if err != nil {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusBadGateway,
			Type:       domain.ErrorTypeUpstream,
			Code:       "upstream_network_error",
			Message:    err.Error(),
			Provider:   domain.ProviderAnthropic,
			Retryable:  true,
		}
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, domain.ClassifyUpstreamStatus(domain.ProviderAnthropic, resp.StatusCode, string(respBody), adapter.ParseRetryAfter(resp.Header))
	}

	var antResp providers.AnthropicMessageResponse
	if err := json.Unmarshal(respBody, &antResp); err != nil {
		return nil, fmt.Errorf("decode anthropic response: %w", err)
	}

	var textParts []string
	var thinkingParts []string
	var toolCalls []domain.CanonicalToolCall

	for _, block := range antResp.Content {
		switch block.Type {
		case "text":
			textParts = append(textParts, block.Text)
		case "thinking":
			thinkingParts = append(thinkingParts, block.Thinking)
		case "tool_use":
			argsBytes, _ := json.Marshal(block.Input)
			idx := len(toolCalls)
			toolName := block.Name
			if orig, ok := sanitizedToOrig[toolName]; ok {
				toolName = orig
			}
			toolCalls = append(toolCalls, domain.CanonicalToolCall{
				Index: &idx,
				ID:    block.ID,
				Type:  "function",
				Function: domain.CanonicalFunctionCall{
					Name:      toolName,
					Arguments: string(argsBytes),
				},
			})
		}
	}

	promptTok := antResp.Usage.InputTokens + antResp.Usage.CacheReadInputTokens
	totalTok := promptTok + antResp.Usage.OutputTokens
	return &domain.CanonicalChatResponse{
		ID:       antResp.ID,
		Object:   "chat.completion",
		Created:  time.Now().Unix(),
		Model:    antResp.Model,
		Provider: domain.ProviderAnthropic,
		Choices: []domain.CanonicalChoice{
			{
				Index: 0,
				Message: domain.CanonicalMessage{
					Role:             "assistant",
					Content:          strings.Join(textParts, ""),
					ReasoningContent: strings.Join(thinkingParts, ""),
					ToolCalls:        toolCalls,
				},
				FinishReason: mapStopReason(antResp.StopReason),
			},
		},
		Usage: domain.TokenUsage{
			PromptTokens:        promptTok,
			CompletionTokens:    antResp.Usage.OutputTokens,
			TotalTokens:         totalTok,
			CachedPromptTokens:  antResp.Usage.CacheReadInputTokens,
			CacheCreationTokens: antResp.Usage.CacheCreationInputTokens,
		},
	}, nil
}

func (a *Adapter) StreamChatCompletion(ctx context.Context, dep *domain.Deployment, req *domain.CanonicalChatRequest, onChunk adapter.StreamChunkHandler) (*domain.TokenUsage, error) {
	ctx = adapter.StreamingContext(ctx)
	model := req.ResolvedModel
	if model == "" && dep != nil && dep.GlobalModel != nil {
		model = dep.GlobalModel.ModelName
	}
	if model == "" {
		model = req.Model
	}
	if err := validateThinkingOutputLimit(model, req); err != nil {
		return nil, err
	}

	payload, sanitizedToOrig := toAnthropicRequestWithMap(model, req, true)
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	endpoint := resolveBaseURL(dep.Credential) + "/v1/messages"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	setHeaders(httpReq, dep.Credential)
	httpReq.Header.Set("Accept", "text/event-stream")

	resp, err := a.client.Do(httpReq)
	if err != nil {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusBadGateway,
			Type:       domain.ErrorTypeUpstream,
			Code:       "upstream_network_error",
			Message:    err.Error(),
			Provider:   domain.ProviderAnthropic,
			Retryable:  true,
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		errBody, _ := io.ReadAll(resp.Body)
		return nil, domain.ClassifyUpstreamStatus(domain.ProviderAnthropic, resp.StatusCode, string(errBody), adapter.ParseRetryAfter(resp.Header))
	}

	msgID := fmt.Sprintf("chatcmpl-ant-%d", time.Now().UnixNano())
	created := time.Now().Unix()
	usage := &domain.TokenUsage{}
	toolIdx := -1

	err = sse.ReadEvents(resp.Body, func(ev sse.Event) error {
		if ev.Data == "" {
			return nil
		}
		var streamEv providers.AnthropicStreamEvent
		if err := json.Unmarshal([]byte(ev.Data), &streamEv); err != nil {
			return nil
		}

		switch streamEv.Type {
		case "message_start":
			if streamEv.Message != nil {
				if streamEv.Message.ID != "" {
					msgID = streamEv.Message.ID
				}
				if streamEv.Message.Model != "" {
					model = streamEv.Message.Model
				}
				usage.PromptTokens = streamEv.Message.Usage.InputTokens + streamEv.Message.Usage.CacheReadInputTokens
				usage.CachedPromptTokens = streamEv.Message.Usage.CacheReadInputTokens
				usage.CacheCreationTokens = streamEv.Message.Usage.CacheCreationInputTokens
			}
			return onChunk(&domain.CanonicalStreamChunk{
				ID:      msgID,
				Object:  "chat.completion.chunk",
				Created: created,
				Model:   model,
				Choices: []domain.CanonicalStreamChoice{
					{
						Index: 0,
						Delta: domain.CanonicalStreamDelta{Role: "assistant"},
					},
				},
			})

		case "content_block_start":
			if streamEv.ContentBlock != nil && streamEv.ContentBlock.Type == "tool_use" {
				toolIdx++
				idxCopy := toolIdx
				toolName := streamEv.ContentBlock.Name
				if orig, ok := sanitizedToOrig[toolName]; ok {
					toolName = orig
				}
				return onChunk(&domain.CanonicalStreamChunk{
					ID:      msgID,
					Object:  "chat.completion.chunk",
					Created: created,
					Model:   model,
					Choices: []domain.CanonicalStreamChoice{
						{
							Index: 0,
							Delta: domain.CanonicalStreamDelta{
								ToolCalls: []domain.CanonicalToolCall{
									{
										Index: &idxCopy,
										ID:    streamEv.ContentBlock.ID,
										Type:  "function",
										Function: domain.CanonicalFunctionCall{
											Name: toolName,
										},
									},
								},
							},
						},
					},
				})
			}

		case "content_block_delta":
			if streamEv.Delta == nil {
				return nil
			}
			switch streamEv.Delta.Type {
			case "text_delta":
				return onChunk(&domain.CanonicalStreamChunk{
					ID:      msgID,
					Object:  "chat.completion.chunk",
					Created: created,
					Model:   model,
					Choices: []domain.CanonicalStreamChoice{
						{
							Index: 0,
							Delta: domain.CanonicalStreamDelta{Content: streamEv.Delta.Text},
						},
					},
				})
			case "thinking_delta":
				return onChunk(&domain.CanonicalStreamChunk{
					ID:      msgID,
					Object:  "chat.completion.chunk",
					Created: created,
					Model:   model,
					Choices: []domain.CanonicalStreamChoice{
						{
							Index: 0,
							Delta: domain.CanonicalStreamDelta{ReasoningContent: streamEv.Delta.Thinking},
						},
					},
				})
			case "input_json_delta":
				idxCopy := toolIdx
				if idxCopy < 0 {
					idxCopy = 0
				}
				return onChunk(&domain.CanonicalStreamChunk{
					ID:      msgID,
					Object:  "chat.completion.chunk",
					Created: created,
					Model:   model,
					Choices: []domain.CanonicalStreamChoice{
						{
							Index: 0,
							Delta: domain.CanonicalStreamDelta{
								ToolCalls: []domain.CanonicalToolCall{
									{
										Index: &idxCopy,
										Function: domain.CanonicalFunctionCall{
											Arguments: streamEv.Delta.PartialJSON,
										},
									},
								},
							},
						},
					},
				})
			}

		case "message_delta":
			if streamEv.Usage != nil {
				usage.CompletionTokens = streamEv.Usage.OutputTokens
				usage.TotalTokens = usage.PromptTokens + usage.CompletionTokens
			}
			finish := "stop"
			if streamEv.Delta != nil && streamEv.Delta.StopReason != "" {
				finish = mapStopReason(streamEv.Delta.StopReason)
			}
			return onChunk(&domain.CanonicalStreamChunk{
				ID:      msgID,
				Object:  "chat.completion.chunk",
				Created: created,
				Model:   model,
				Choices: []domain.CanonicalStreamChoice{
					{
						Index:        0,
						Delta:        domain.CanonicalStreamDelta{},
						FinishReason: &finish,
					},
				},
				Usage: usage,
			})
		}
		return nil
	})

	usage.TotalTokens = usage.PromptTokens + usage.CompletionTokens
	return usage, err
}

func (a *Adapter) Embeddings(ctx context.Context, dep *domain.Deployment, req *domain.CanonicalEmbeddingRequest) (*domain.CanonicalEmbeddingResponse, error) {
	return nil, &domain.GatewayError{
		StatusCode: http.StatusBadRequest,
		Type:       domain.ErrorTypeInvalidRequest,
		Code:       "unsupported_capability",
		Message:    "Anthropic does not expose a native /v1/embeddings endpoint; configure OpenAI, Gemini, Mistral, or Ollama for embeddings",
		Provider:   domain.ProviderAnthropic,
	}
}

func (a *Adapter) ListModels(ctx context.Context, cred *domain.ProviderCredential) ([]domain.DiscoveredModel, error) {
	endpoint := resolveBaseURL(cred) + "/v1/models"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	setHeaders(httpReq, cred)

	resp, err := a.client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, domain.ClassifyUpstreamStatus(domain.ProviderAnthropic, resp.StatusCode, string(respBody), 0)
	}

	var list providers.AnthropicModelsResponse
	if err := json.Unmarshal(respBody, &list); err != nil {
		return nil, err
	}

	out := make([]domain.DiscoveredModel, 0, len(list.Data))
	for _, m := range list.Data {
		display := m.DisplayName
		if display == "" {
			display = m.ID
		}
		out = append(out, domain.DiscoveredModel{
			Provider:    domain.ProviderAnthropic,
			ModelName:   m.ID,
			DisplayName: display,
		})
	}
	return out, nil
}

func setHeaders(req *http.Request, cred *domain.ProviderCredential) {
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("anthropic-version", anthropicVersion)
	if cred != nil {
		if cred.DecryptedAPIKey != "" {
			req.Header.Set("x-api-key", cred.DecryptedAPIKey)
		}
		for k, v := range cred.Headers {
			req.Header.Set(k, v)
		}
	}
}
