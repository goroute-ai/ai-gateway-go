package anthropic

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
	"unicode"

	"github.com/goroute-ai/ai-gateway-go/internal/adapter"
	"github.com/goroute-ai/ai-gateway-go/internal/adapter/sse"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/observability"
	"github.com/goroute-ai/ai-gateway-go/internal/openapi/providers"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
)

const (
	defaultBaseURL   = "https://api.anthropic.com"
	anthropicVersion = "2023-06-01"
	defaultMaxTokens = 4096
)

// Adapter implements adapter.ProviderAdapter for the Anthropic Messages API.
type Adapter struct {
	client     *http.Client
	ssrfPolicy *network.Policy
}

// NewAdapter creates an Anthropic Adapter using client, or a default pooled HTTP client when nil.
func NewAdapter(client *http.Client) *Adapter {
	if client == nil {
		client = adapter.NewPooledHTTPClient(120 * time.Second)
	}
	return &Adapter{client: client}
}

// SetSSRFPolicy configures the outbound network policy used to validate BaseURL overrides.
func (a *Adapter) SetSSRFPolicy(policy *network.Policy) {
	a.ssrfPolicy = policy
}

func (a *Adapter) Provider() domain.ProviderType {
	return domain.ProviderAnthropic
}

// SupportsAssistantPrefill reports that Anthropic Messages supports continuing
// generation from a trailing assistant prefill message.
func (a *Adapter) SupportsAssistantPrefill() bool {
	return true
}

func (a *Adapter) resolveEndpoint(cred *domain.ProviderCredential, suffix string) (string, error) {
	base, err := adapter.ResolveCredentialBaseURL(cred, defaultBaseURL, a.ssrfPolicy, domain.ProviderAnthropic)
	if err != nil {
		return "", err
	}
	return base + suffix, nil
}

func toProviderCacheControl(cc *domain.CacheControl) *providers.AnthropicCacheControl {
	if cc == nil || cc.Type == "" {
		return nil
	}
	return &providers.AnthropicCacheControl{Type: cc.Type, TTL: cc.TTL}
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
		strings.Contains(lower, "4.7") ||
		strings.Contains(lower, "4-8") ||
		strings.Contains(lower, "4.8") ||
		strings.Contains(lower, "-5") ||
		strings.Contains(lower, ".5")
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

func translateUserParts(m domain.CanonicalMessage) []providers.AnthropicContentBlock {
	var blocks []providers.AnthropicContentBlock
	if len(m.Parts) > 0 {
		for _, p := range m.Parts {
			cc := toProviderCacheControl(p.CacheControl)
			switch p.Type {
			case "text":
				blocks = append(blocks, providers.AnthropicContentBlock{
					Type:         "text",
					Text:         p.Text,
					CacheControl: cc,
				})
			case "image_url":
				if p.ImageURL != nil && p.ImageURL.URL != "" {
					if mime, b64, ok := parseDataURI(p.ImageURL.URL); ok {
						blocks = append(blocks, providers.AnthropicContentBlock{
							Type: "image",
							Source: map[string]any{
								"type":       "base64",
								"media_type": mime,
								"data":       b64,
							},
							CacheControl: cc,
						})
					} else {
						blocks = append(blocks, providers.AnthropicContentBlock{
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
						blocks = append(blocks, providers.AnthropicContentBlock{
							Type: "document",
							Source: map[string]any{
								"type":       "base64",
								"media_type": mime,
								"data":       p.Document.Data,
							},
							CacheControl: cc,
						})
					} else if p.Document.URL != "" {
						blocks = append(blocks, providers.AnthropicContentBlock{
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
		blocks = append(blocks, providers.AnthropicContentBlock{
			Type: "text",
			Text: m.Content,
		})
	}
	if m.CacheControl != nil && len(blocks) > 0 && blocks[len(blocks)-1].CacheControl == nil {
		blocks[len(blocks)-1].CacheControl = toProviderCacheControl(m.CacheControl)
	}
	return blocks
}

// toAnthropicRequest translates CanonicalChatRequest into Anthropic's /v1/messages request body.
func toAnthropicRequest(model string, req *domain.CanonicalChatRequest, stream bool) providers.AnthropicMessageRequest {
	antReq, _ := toAnthropicRequestWithMap(model, req, stream)
	return antReq
}

// toAnthropicRequestWithMap translates CanonicalChatRequest into Anthropic's /v1/messages request body.
// Returns the OpenAPI-generated payload and a map from sanitized tool names back to original names.
func toAnthropicRequestWithMap(model string, req *domain.CanonicalChatRequest, stream bool) (providers.AnthropicMessageRequest, map[string]string) {
	var systemBlocks []providers.AnthropicContentBlock
	var systemPlain []string
	hasSystemCacheControl := false
	var messages []providers.AnthropicInputMessage

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
				cc := toProviderCacheControl(m.CacheControl)
				if cc != nil {
					hasSystemCacheControl = true
				}
				systemBlocks = append(systemBlocks, providers.AnthropicContentBlock{
					Type:         "text",
					Text:         m.Content,
					CacheControl: cc,
				})
			}
		case "tool":
			block := providers.AnthropicContentBlock{
				Type:         "tool_result",
				ToolUseID:    m.ToolCallID,
				Content:      m.Content,
				CacheControl: toProviderCacheControl(m.CacheControl),
			}
			// Consolidate consecutive tool results into a single user message to respect Anthropic's role alternation rule
			if len(messages) > 0 && messages[len(messages)-1].Role == "user" {
				messages[len(messages)-1].Content = append(messages[len(messages)-1].Content, block)
			} else {
				messages = append(messages, providers.AnthropicInputMessage{
					Role:    "user",
					Content: []providers.AnthropicContentBlock{block},
				})
			}
		case "assistant":
			var blocks []providers.AnthropicContentBlock
			if m.Content != "" {
				blocks = append(blocks, providers.AnthropicContentBlock{
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
				blocks = append(blocks, providers.AnthropicContentBlock{
					Type:  "tool_use",
					ID:    tc.ID,
					Name:  name,
					Input: parsedInput,
				})
			}
			if len(blocks) > 0 {
				if m.CacheControl != nil && blocks[len(blocks)-1].CacheControl == nil {
					blocks[len(blocks)-1].CacheControl = toProviderCacheControl(m.CacheControl)
				}
				messages = append(messages, providers.AnthropicInputMessage{
					Role:    "assistant",
					Content: blocks,
				})
			}
		default: // "user"
			messages = append(messages, providers.AnthropicInputMessage{
				Role:    "user",
				Content: translateUserParts(m),
			})
		}
	}

	// Anthropic Messages rejects trailing whitespace in the final assistant prefill block.
	if n := len(messages); n > 0 && messages[n-1].Role == "assistant" {
		last := &messages[n-1]
		if len(last.Content) > 0 {
			lastBlock := &last.Content[len(last.Content)-1]
			if lastBlock.Type == "text" {
				lastBlock.Text = strings.TrimRightFunc(lastBlock.Text, unicode.IsSpace)
				if lastBlock.Text == "" {
					last.Content = last.Content[:len(last.Content)-1]
				}
			}
		}
		if len(last.Content) == 0 {
			messages = messages[:n-1]
		}
	}

	maxTok := defaultMaxTokens
	if req.MaxTokens != nil && *req.MaxTokens > 0 {
		maxTok = *req.MaxTokens
	}

	var tools []providers.AnthropicTool
	for _, t := range req.Tools {
		schema := t.Function.Parameters
		if schema == nil {
			schema = map[string]any{"type": "object", "properties": map[string]any{}}
		}
		san := origToSanitized[t.Function.Name]
		if san == "" {
			san = sanitizeToolName(t.Function.Name)
		}
		tools = append(tools, providers.AnthropicTool{
			Name:         san,
			Description:  t.Function.Description,
			InputSchema:  schema,
			CacheControl: toProviderCacheControl(t.CacheControl),
		})
	}

	var systemVal any
	if hasSystemCacheControl {
		systemVal = systemBlocks
	} else if len(systemPlain) > 0 {
		systemVal = strings.Join(systemPlain, "\n\n")
	}

	antReq := providers.AnthropicMessageRequest{
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
		antReq.OutputFormat = &providers.AnthropicOutputFormat{
			Type:   "json_schema",
			Schema: schema,
		}
	}

	if req.ReasoningEffort != "" {
		if isAdaptiveThinkingModel(model) {
			antReq.Thinking = &providers.AnthropicThinking{Type: "adaptive"}
			antReq.OutputConfig = &providers.AnthropicOutputConfig{Effort: mapAnthropicEffort(req.ReasoningEffort)}
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
			antReq.Thinking = &providers.AnthropicThinking{
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

	endpoint, err := a.resolveEndpoint(dep.Credential, "/v1/messages")
	if err != nil {
		return nil, err
	}
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

	respBody, err := adapter.ReadBoundedBody(resp.Body, adapter.DefaultMaxResponseBytes, domain.ProviderAnthropic)
	if err != nil {
		return nil, err
	}
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

	endpoint, err := a.resolveEndpoint(dep.Credential, "/v1/messages")
	if err != nil {
		return nil, err
	}
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
		errBody, err := adapter.ReadBoundedBody(resp.Body, adapter.DefaultMaxErrorBytes, domain.ProviderAnthropic)
		if err != nil {
			return nil, err
		}
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
		Message:    "Anthropic does not expose a native /v1/embeddings endpoint; configure OpenAI for embeddings",
		Provider:   domain.ProviderAnthropic,
	}
}

func (a *Adapter) ListModels(ctx context.Context, cred *domain.ProviderCredential) ([]domain.DiscoveredModel, error) {
	endpoint, err := a.resolveEndpoint(cred, "/v1/models")
	if err != nil {
		return nil, err
	}
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

	respBody, err := adapter.ReadBoundedBody(resp.Body, adapter.DefaultMaxResponseBytes, domain.ProviderAnthropic)
	if err != nil {
		return nil, err
	}
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
	observability.InjectTraceHeaders(req.Context(), req)
	if cred != nil {
		adapter.ApplySafeCustomHeaders(req, cred.Headers)
		if cred.DecryptedAPIKey != "" {
			req.Header.Set("x-api-key", cred.DecryptedAPIKey)
		}
	}
}
