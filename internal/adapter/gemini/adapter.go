package gemini

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
	defaultAIStudioBaseURL  = "https://generativelanguage.googleapis.com"
	defaultVertexExpressURL = "https://aiplatform.googleapis.com"
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
	return domain.ProviderGemini
}

func isVertexExpressKey(cred *domain.ProviderCredential) bool {
	if cred == nil {
		return false
	}
	return strings.Contains(cred.BaseURL, "aiplatform.googleapis.com")
}

func buildActionEndpoint(cred *domain.ProviderCredential, model, action string) string {
	if isVertexExpressKey(cred) {
		base := defaultVertexExpressURL
		if cred != nil && strings.TrimSpace(cred.BaseURL) != "" {
			base = strings.TrimRight(cred.BaseURL, "/")
		}
		return fmt.Sprintf("%s/v1/publishers/google/models/%s:%s", base, model, action)
	}
	base := defaultAIStudioBaseURL
	if cred != nil && strings.TrimSpace(cred.BaseURL) != "" {
		base = strings.TrimRight(cred.BaseURL, "/")
	}
	return fmt.Sprintf("%s/v1beta/models/%s:%s", base, model, action)
}

func normalizeModelName(model string) string {
	model = strings.TrimPrefix(model, "models/")
	model = strings.TrimPrefix(model, "publishers/google/models/")
	return model
}

// toGeminiRequest translates CanonicalChatRequest into GenerateContentRequest (gemini_api_v1.1.0.yaml).
func toGeminiRequest(model string, req *domain.CanonicalChatRequest) providers.GeminiGenerateContentRequest {
	var sysParts []providers.GeminiPart
	var contents []providers.GeminiContent

	for _, m := range req.Messages {
		switch m.Role {
		case "system", "developer":
			if strings.TrimSpace(m.Content) != "" {
				sysParts = append(sysParts, providers.GeminiPart{Text: m.Content})
			}
		case "assistant":
			var parts []providers.GeminiPart
			if m.Content != "" {
				parts = append(parts, providers.GeminiPart{Text: m.Content})
			}
			for _, tc := range m.ToolCalls {
				var args map[string]any
				if tc.Function.Arguments != "" {
					_ = json.Unmarshal([]byte(tc.Function.Arguments), &args)
				}
				parts = append(parts, providers.GeminiPart{
					FunctionCall: &providers.GeminiFunctionCall{
						Name: tc.Function.Name,
						Args: args,
					},
				})
			}
			if len(parts) > 0 {
				contents = append(contents, providers.GeminiContent{
					Role:  "model",
					Parts: parts,
				})
			}
		case "tool":
			var respObj map[string]any
			if err := json.Unmarshal([]byte(m.Content), &respObj); err != nil {
				respObj = map[string]any{"result": m.Content}
			}
			funcName := m.Name
			if funcName == "" {
				funcName = m.ToolCallID
			}
			contents = append(contents, providers.GeminiContent{
				Role: "function",
				Parts: []providers.GeminiPart{
					{
						FunctionResponse: &providers.GeminiFunctionResponse{
							Name:     funcName,
							Response: respObj,
						},
					},
				},
			})
		default: // "user"
			contents = append(contents, providers.GeminiContent{
				Role:  "user",
				Parts: []providers.GeminiPart{{Text: m.Content}},
			})
		}
	}

	out := providers.GeminiGenerateContentRequest{
		Contents: contents,
	}
	if len(sysParts) > 0 {
		out.SystemInstruction = &providers.GeminiContent{
			Role:  "user",
			Parts: sysParts,
		}
	}
	if len(req.Tools) > 0 {
		var decls []providers.GeminiFunctionDeclaration
		for _, t := range req.Tools {
			decls = append(decls, providers.GeminiFunctionDeclaration{
				Name:        t.Function.Name,
				Description: t.Function.Description,
				Parameters:  t.Function.Parameters,
			})
		}
		out.Tools = []providers.GeminiTool{{FunctionDeclarations: decls}}
	}

	genCfg := &providers.GeminiGenerationConfig{
		Temperature:     req.Temperature,
		TopP:            req.TopP,
		MaxOutputTokens: req.MaxTokens,
		StopSequences:   req.Stop,
	}
	// When max_tokens is small (<= 16) on Gemini 2.5 Flash without explicit reasoning effort,
	// set thinkingBudget: 0 so all output tokens go to visible response text rather than internal thought tokens.
	if req.MaxTokens != nil && *req.MaxTokens <= 16 && req.ReasoningEffort == "" && model == "gemini-2.5-flash" {
		genCfg.ThinkingConfig = &providers.GeminiThinkingConfig{ThinkingBudget: 0}
	}
	if req.ResponseFormat != nil && (req.ResponseFormat.Type == "json_object" || req.ResponseFormat.Type == "json_schema") {
		genCfg.ResponseMimeType = "application/json"
	}
	out.GenerationConfig = genCfg
	return out
}

func mapFinishReason(r string, hasToolCall bool) string {
	if hasToolCall {
		return "tool_calls"
	}
	switch r {
	case "STOP":
		return "stop"
	case "MAX_TOKENS":
		return "length"
	case "SAFETY", "RECITATION":
		return "content_filter"
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
	model = normalizeModelName(model)

	payload := toGeminiRequest(model, req)
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	endpoint := buildActionEndpoint(dep.Credential, model, "generateContent")
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
			Provider:   domain.ProviderGemini,
			Retryable:  true,
		}
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, domain.ClassifyUpstreamStatus(domain.ProviderGemini, resp.StatusCode, string(respBody), adapter.ParseRetryAfter(resp.Header))
	}

	var gemResp providers.GeminiGenerateContentResponse
	if err := json.Unmarshal(respBody, &gemResp); err != nil {
		return nil, fmt.Errorf("decode gemini response: %w", err)
	}

	if len(gemResp.Candidates) == 0 {
		blockReason := "safety_filter"
		if gemResp.PromptFeedback != nil && gemResp.PromptFeedback.BlockReason != "" {
			blockReason = gemResp.PromptFeedback.BlockReason
		}
		return nil, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "safety_violation",
			Message:    fmt.Sprintf("gemini response blocked by content safety filters: %s", blockReason),
			Provider:   domain.ProviderGemini,
		}
	}

	choices := make([]domain.CanonicalChoice, 0, len(gemResp.Candidates))
	for i, c := range gemResp.Candidates {
		var textParts []string
		var thoughtParts []string
		var toolCalls []domain.CanonicalToolCall

		for _, p := range c.Content.Parts {
			if p.Thought {
				thoughtParts = append(thoughtParts, p.Text)
			} else if p.Text != "" {
				textParts = append(textParts, p.Text)
			}
			if p.FunctionCall != nil {
				argsBytes, _ := json.Marshal(p.FunctionCall.Args)
				idx := len(toolCalls)
				toolCalls = append(toolCalls, domain.CanonicalToolCall{
					Index: &idx,
					ID:    fmt.Sprintf("call_gem_%d_%d", i, idx),
					Type:  "function",
					Function: domain.CanonicalFunctionCall{
						Name:      p.FunctionCall.Name,
						Arguments: string(argsBytes),
					},
				})
			}
		}

		choices = append(choices, domain.CanonicalChoice{
			Index: i,
			Message: domain.CanonicalMessage{
				Role:             "assistant",
				Content:          strings.Join(textParts, ""),
				ReasoningContent: strings.Join(thoughtParts, ""),
				ToolCalls:        toolCalls,
			},
			FinishReason: mapFinishReason(c.FinishReason, len(toolCalls) > 0),
		})
	}

	usage := domain.TokenUsage{}
	if gemResp.UsageMetadata != nil {
		usage.PromptTokens = gemResp.UsageMetadata.PromptTokenCount
		usage.CompletionTokens = gemResp.UsageMetadata.CandidatesTokenCount
		usage.TotalTokens = gemResp.UsageMetadata.TotalTokenCount
		usage.CachedPromptTokens = gemResp.UsageMetadata.CachedContentTokenCount
		usage.ReasoningTokens = gemResp.UsageMetadata.ThoughtsTokenCount
	}

	return &domain.CanonicalChatResponse{
		ID:       fmt.Sprintf("chatcmpl-gem-%d", time.Now().UnixNano()),
		Object:   "chat.completion",
		Created:  time.Now().Unix(),
		Model:    model,
		Provider: domain.ProviderGemini,
		Choices:  choices,
		Usage:    usage,
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
	model = normalizeModelName(model)

	payload := toGeminiRequest(model, req)
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	endpoint := buildActionEndpoint(dep.Credential, model, "streamGenerateContent") + "?alt=sse"
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
			Provider:   domain.ProviderGemini,
			Retryable:  true,
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		errBody, _ := io.ReadAll(resp.Body)
		return nil, domain.ClassifyUpstreamStatus(domain.ProviderGemini, resp.StatusCode, string(errBody), adapter.ParseRetryAfter(resp.Header))
	}

	msgID := fmt.Sprintf("chatcmpl-gem-%d", time.Now().UnixNano())
	created := time.Now().Unix()
	usage := &domain.TokenUsage{}

	err = sse.ReadEvents(resp.Body, func(ev sse.Event) error {
		if ev.Data == "" || ev.Data == "[DONE]" {
			return nil
		}
		var gemResp providers.GeminiGenerateContentResponse
		if err := json.Unmarshal([]byte(ev.Data), &gemResp); err != nil {
			return nil
		}
		if gemResp.UsageMetadata != nil {
			usage.PromptTokens = gemResp.UsageMetadata.PromptTokenCount
			usage.CompletionTokens = gemResp.UsageMetadata.CandidatesTokenCount
			usage.TotalTokens = gemResp.UsageMetadata.TotalTokenCount
			usage.CachedPromptTokens = gemResp.UsageMetadata.CachedContentTokenCount
			usage.ReasoningTokens = gemResp.UsageMetadata.ThoughtsTokenCount
		}

		if len(gemResp.Candidates) == 0 && gemResp.PromptFeedback != nil && gemResp.PromptFeedback.BlockReason != "" {
			fr := "content_filter"
			return onChunk(&domain.CanonicalStreamChunk{
				ID:      msgID,
				Object:  "chat.completion.chunk",
				Created: created,
				Model:   model,
				Choices: []domain.CanonicalStreamChoice{
					{
						Index:        0,
						Delta:        domain.CanonicalStreamDelta{},
						FinishReason: &fr,
					},
				},
			})
		}

		for _, c := range gemResp.Candidates {
			var deltaText string
			var deltaThought string
			var toolCalls []domain.CanonicalToolCall
			for _, p := range c.Content.Parts {
				if p.Thought {
					deltaThought += p.Text
				} else {
					deltaText += p.Text
				}
				if p.FunctionCall != nil {
					argsBytes, _ := json.Marshal(p.FunctionCall.Args)
					idx := len(toolCalls)
					toolCalls = append(toolCalls, domain.CanonicalToolCall{
						Index: &idx,
						ID:    fmt.Sprintf("call_gem_%d", idx),
						Type:  "function",
						Function: domain.CanonicalFunctionCall{
							Name:      p.FunctionCall.Name,
							Arguments: string(argsBytes),
						},
					})
				}
			}
			var finishPtr *string
			if c.FinishReason != "" {
				fr := mapFinishReason(c.FinishReason, len(toolCalls) > 0)
				finishPtr = &fr
			}
			chunk := &domain.CanonicalStreamChunk{
				ID:      msgID,
				Object:  "chat.completion.chunk",
				Created: created,
				Model:   model,
				Choices: []domain.CanonicalStreamChoice{
					{
						Index: c.Index,
						Delta: domain.CanonicalStreamDelta{
							Content:          deltaText,
							ReasoningContent: deltaThought,
							ToolCalls:        toolCalls,
						},
						FinishReason: finishPtr,
					},
				},
			}
			if finishPtr != nil {
				chunk.Usage = usage
			}
			if err := onChunk(chunk); err != nil {
				return err
			}
		}
		return nil
	})
	return usage, err
}

func (a *Adapter) Embeddings(ctx context.Context, dep *domain.Deployment, req *domain.CanonicalEmbeddingRequest) (*domain.CanonicalEmbeddingResponse, error) {
	model := req.ResolvedModel
	if model == "" && dep != nil && dep.GlobalModel != nil {
		model = dep.GlobalModel.ModelName
	}
	if model == "" {
		model = req.Model
	}
	model = normalizeModelName(model)

	data := make([]domain.EmbeddingData, 0, len(req.Input))
	totalPromptTokens := 0

	for idx, text := range req.Input {
		payload := providers.GeminiEmbedContentRequest{
			Model: "models/" + model,
			Content: providers.GeminiContent{
				Role:  "user",
				Parts: []providers.GeminiPart{{Text: text}},
			},
			OutputDimensionality: req.Dimensions,
		}
		bodyBytes, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		endpoint := buildActionEndpoint(dep.Credential, model, "embedContent")
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
				Provider:   domain.ProviderGemini,
				Retryable:  true,
			}
		}
		respBody, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return nil, domain.ClassifyUpstreamStatus(domain.ProviderGemini, resp.StatusCode, string(respBody), adapter.ParseRetryAfter(resp.Header))
		}
		var gemEmb providers.GeminiEmbedContentResponse
		if err := json.Unmarshal(respBody, &gemEmb); err != nil {
			return nil, err
		}
		var vals []float64
		if gemEmb.Embedding != nil {
			vals = gemEmb.Embedding.Values
		}
		data = append(data, domain.EmbeddingData{
			Object:    "embedding",
			Index:     idx,
			Embedding: vals,
		})
		totalPromptTokens += (len(text) + 3) / 4
	}

	return &domain.CanonicalEmbeddingResponse{
		Object:   "list",
		Data:     data,
		Model:    model,
		Provider: domain.ProviderGemini,
		Usage: domain.TokenUsage{
			PromptTokens: totalPromptTokens,
			TotalTokens:  totalPromptTokens,
		},
	}, nil
}

func (a *Adapter) ListModels(ctx context.Context, cred *domain.ProviderCredential) ([]domain.DiscoveredModel, error) {
	if isVertexExpressKey(cred) {
		// Vertex AI Express Mode uses publisher model IDs directly without a project-scoped list endpoint
		return []domain.DiscoveredModel{
			{Provider: domain.ProviderGemini, ModelName: "gemini-2.5-flash", DisplayName: "Google Gemini 2.5 Flash (Vertex Express)"},
			{Provider: domain.ProviderGemini, ModelName: "gemini-2.5-pro", DisplayName: "Google Gemini 2.5 Pro (Vertex Express)"},
			{Provider: domain.ProviderGemini, ModelName: "gemini-2.0-flash", DisplayName: "Google Gemini 2.0 Flash (Vertex Express)"},
		}, nil
	}

	base := defaultAIStudioBaseURL
	if cred != nil && strings.TrimSpace(cred.BaseURL) != "" {
		base = strings.TrimRight(cred.BaseURL, "/")
	}
	endpoint := base + "/v1beta/models"
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
		return nil, domain.ClassifyUpstreamStatus(domain.ProviderGemini, resp.StatusCode, string(respBody), 0)
	}

	var list providers.GeminiModelsResponse
	if err := json.Unmarshal(respBody, &list); err != nil {
		return nil, err
	}
	out := make([]domain.DiscoveredModel, 0, len(list.Models))
	for _, m := range list.Models {
		name := normalizeModelName(m.Name)
		display := m.DisplayName
		if display == "" {
			display = name
		}
		out = append(out, domain.DiscoveredModel{
			Provider:    domain.ProviderGemini,
			ModelName:   name,
			DisplayName: display,
		})
	}
	return out, nil
}

func setHeaders(req *http.Request, cred *domain.ProviderCredential) {
	req.Header.Set("Content-Type", "application/json")
	if cred != nil {
		if key := strings.TrimSpace(cred.DecryptedAPIKey); key != "" {
			req.Header.Set("x-goog-api-key", key)
		}
		for k, v := range cred.Headers {
			req.Header.Set(k, v)
		}
	}
}
