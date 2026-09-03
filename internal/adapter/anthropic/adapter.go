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

// toAnthropicRequest translates CanonicalChatRequest into Anthropic's MessageRequestBody schema (anthropic_api.yaml).
func toAnthropicRequest(model string, req *domain.CanonicalChatRequest, stream bool) providers.AnthropicMessageRequest {
	var systemPrompts []string
	var messages []providers.AnthropicInputMessage

	for _, m := range req.Messages {
		switch m.Role {
		case "system", "developer":
			if strings.TrimSpace(m.Content) != "" {
				systemPrompts = append(systemPrompts, m.Content)
			}
		case "tool":
			block := providers.AnthropicContentBlock{
				Type:      "tool_result",
				ToolUseID: m.ToolCallID,
				Content:   m.Content,
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
				blocks = append(blocks, providers.AnthropicContentBlock{
					Type:  "tool_use",
					ID:    tc.ID,
					Name:  tc.Function.Name,
					Input: parsedInput,
				})
			}
			if len(blocks) > 0 {
				messages = append(messages, providers.AnthropicInputMessage{
					Role:    "assistant",
					Content: blocks,
				})
			}
		default: // "user"
			messages = append(messages, providers.AnthropicInputMessage{
				Role: "user",
				Content: []providers.AnthropicContentBlock{
					{
						Type: "text",
						Text: m.Content,
					},
				},
			})
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
		tools = append(tools, providers.AnthropicTool{
			Name:        t.Function.Name,
			Description: t.Function.Description,
			InputSchema: schema,
		})
	}

	antReq := providers.AnthropicMessageRequest{
		Model:         model,
		Messages:      messages,
		MaxTokens:     maxTok,
		System:        strings.Join(systemPrompts, "\n\n"),
		Temperature:   req.Temperature,
		TopP:          req.TopP,
		StopSequences: req.Stop,
		Stream:        stream,
		Tools:         tools,
	}

	if req.ReasoningEffort != "" {
		budget := 2048
		switch req.ReasoningEffort {
		case "high":
			budget = 8192
		case "medium":
			budget = 4096
		}
		if maxTok <= budget {
			antReq.MaxTokens = budget + 2048
		}
		antReq.Thinking = &providers.AnthropicThinking{
			Type:         "enabled",
			BudgetTokens: budget,
		}
		// Anthropic Messages API strictly requires temperature = 1.0 (or omitted) and top_p = nil when thinking is enabled
		antReq.Temperature = nil
		antReq.TopP = nil
	}

	return antReq
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

	payload := toAnthropicRequest(model, req, false)
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
			toolCalls = append(toolCalls, domain.CanonicalToolCall{
				Index: &idx,
				ID:    block.ID,
				Type:  "function",
				Function: domain.CanonicalFunctionCall{
					Name:      block.Name,
					Arguments: string(argsBytes),
				},
			})
		}
	}

	totalTok := antResp.Usage.InputTokens + antResp.Usage.OutputTokens
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
			PromptTokens:       antResp.Usage.InputTokens,
			CompletionTokens:   antResp.Usage.OutputTokens,
			TotalTokens:        totalTok,
			CachedPromptTokens: antResp.Usage.CacheReadInputTokens,
		},
	}, nil
}

func (a *Adapter) StreamChatCompletion(ctx context.Context, dep *domain.Deployment, req *domain.CanonicalChatRequest, onChunk adapter.StreamChunkHandler) (*domain.TokenUsage, error) {
	model := req.ResolvedModel
	if model == "" && dep != nil && dep.GlobalModel != nil {
		model = dep.GlobalModel.ModelName
	}
	if model == "" {
		model = req.Model
	}

	payload := toAnthropicRequest(model, req, true)
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
				usage.PromptTokens = streamEv.Message.Usage.InputTokens
				usage.CachedPromptTokens = streamEv.Message.Usage.CacheReadInputTokens
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
											Name: streamEv.ContentBlock.Name,
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
