package openai

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
	"github.com/goroute-ai/ai-gateway-go/internal/observability"
	"github.com/goroute-ai/ai-gateway-go/internal/openapi/providers"
)

const defaultBaseURL = "https://api.openai.com/v1"

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
	return domain.ProviderOpenAI
}

func resolveBaseURL(cred *domain.ProviderCredential) string {
	if cred != nil && strings.TrimSpace(cred.BaseURL) != "" {
		return strings.TrimRight(cred.BaseURL, "/")
	}
	return defaultBaseURL
}

func isReasoningModel(model string) bool {
	m := strings.ToLower(model)
	return strings.HasPrefix(m, "o1") || strings.HasPrefix(m, "o3")
}

func toOpenAIRequest(model string, req *domain.CanonicalChatRequest, stream bool) providers.OpenAIChatCompletionRequest {
	reasoning := isReasoningModel(model)

	msgs := make([]providers.OpenAIMessage, 0, len(req.Messages))
	for _, m := range req.Messages {
		role := m.Role
		if reasoning && (role == "system") {
			// OpenAI o1 and o3-mini reject role: "system" and require role: "developer"
			role = "developer"
		}
		om := providers.OpenAIMessage{
			Role:       role,
			Name:       m.Name,
			ToolCallID: m.ToolCallID,
		}
		if len(m.Parts) > 0 {
			om.Content = m.Parts
		} else {
			om.Content = m.Content
		}
		if len(m.ToolCalls) > 0 {
			for _, tc := range m.ToolCalls {
				om.ToolCalls = append(om.ToolCalls, providers.OpenAIToolCall{
					Index: tc.Index,
					ID:    tc.ID,
					Type:  tc.Type,
					Function: providers.OpenAIFunctionCall{
						Name:      tc.Function.Name,
						Arguments: tc.Function.Arguments,
					},
				})
			}
		}
		msgs = append(msgs, om)
	}

	var tools []providers.OpenAITool
	for _, t := range req.Tools {
		tools = append(tools, providers.OpenAITool{
			Type: t.Type,
			Function: providers.OpenAIFunction{
				Name:        t.Function.Name,
				Description: t.Function.Description,
				Parameters:  t.Function.Parameters,
				Strict:      t.Function.Strict,
			},
		})
	}

	out := providers.OpenAIChatCompletionRequest{
		Model:           model,
		Messages:        msgs,
		Tools:           tools,
		ToolChoice:      req.ToolChoice,
		Temperature:     req.Temperature,
		TopP:            req.TopP,
		MaxTokens:       req.MaxTokens,
		Stop:            req.Stop,
		Stream:          stream,
		ReasoningEffort: req.ReasoningEffort,
		User:            req.User,
	}

	// OpenAI o1, o3, and o3-mini models reject custom temperature and top_p
	if reasoning {
		out.Temperature = nil
		out.TopP = nil
	}
	if stream {
		out.StreamOptions = &providers.OpenAIStreamOptions{IncludeUsage: true}
	}
	if req.ResponseFormat != nil {
		out.ResponseFormat = &providers.OpenAIResponseFormat{
			Type:       req.ResponseFormat.Type,
			JSONSchema: req.ResponseFormat.JSONSchema,
		}
	}
	return out
}

func (a *Adapter) ChatCompletion(ctx context.Context, dep *domain.Deployment, req *domain.CanonicalChatRequest) (*domain.CanonicalChatResponse, error) {
	model := req.ResolvedModel
	if model == "" && dep != nil && dep.GlobalModel != nil {
		model = dep.GlobalModel.ModelName
	}
	if model == "" {
		model = req.Model
	}

	payload := toOpenAIRequest(model, req, false)
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	endpoint := resolveBaseURL(dep.Credential) + "/chat/completions"
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
			Provider:   domain.ProviderOpenAI,
			Retryable:  true,
		}
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, domain.ClassifyUpstreamStatus(domain.ProviderOpenAI, resp.StatusCode, string(respBody), adapter.ParseRetryAfter(resp.Header))
	}

	var oaiResp providers.OpenAIChatCompletionResponse
	if err := json.Unmarshal(respBody, &oaiResp); err != nil {
		return nil, fmt.Errorf("decode openai response: %w", err)
	}

	choices := make([]domain.CanonicalChoice, 0, len(oaiResp.Choices))
	for _, c := range oaiResp.Choices {
		contentStr, _ := c.Message.Content.(string)
		var tcs []domain.CanonicalToolCall
		for _, tc := range c.Message.ToolCalls {
			tcs = append(tcs, domain.CanonicalToolCall{
				Index: tc.Index,
				ID:    tc.ID,
				Type:  tc.Type,
				Function: domain.CanonicalFunctionCall{
					Name:      tc.Function.Name,
					Arguments: tc.Function.Arguments,
				},
			})
		}
		choices = append(choices, domain.CanonicalChoice{
			Index: c.Index,
			Message: domain.CanonicalMessage{
				Role:             c.Message.Role,
				Content:          contentStr,
				ReasoningContent: c.Message.ReasoningContent,
				ToolCalls:        tcs,
			},
			FinishReason: c.FinishReason,
		})
	}

	usage := domain.TokenUsage{
		PromptTokens:     oaiResp.Usage.PromptTokens,
		CompletionTokens: oaiResp.Usage.CompletionTokens,
		TotalTokens:      oaiResp.Usage.TotalTokens,
	}
	if oaiResp.Usage.PromptTokensDetails != nil {
		usage.CachedPromptTokens = oaiResp.Usage.PromptTokensDetails.CachedTokens
	}
	if oaiResp.Usage.CompletionTokensDetails != nil {
		usage.ReasoningTokens = oaiResp.Usage.CompletionTokensDetails.ReasoningTokens
	}

	return &domain.CanonicalChatResponse{
		ID:                oaiResp.ID,
		Object:            "chat.completion",
		Created:           oaiResp.Created,
		Model:             oaiResp.Model,
		Provider:          domain.ProviderOpenAI,
		Choices:           choices,
		Usage:             usage,
		SystemFingerprint: oaiResp.SystemFingerprint,
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

	payload := toOpenAIRequest(model, req, true)
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	endpoint := resolveBaseURL(dep.Credential) + "/chat/completions"
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
			Provider:   domain.ProviderOpenAI,
			Retryable:  true,
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		errBody, _ := io.ReadAll(resp.Body)
		return nil, domain.ClassifyUpstreamStatus(domain.ProviderOpenAI, resp.StatusCode, string(errBody), adapter.ParseRetryAfter(resp.Header))
	}

	finalUsage := &domain.TokenUsage{}
	err = sse.ReadEvents(resp.Body, func(ev sse.Event) error {
		if ev.Data == "" || ev.Data == "[DONE]" {
			return nil
		}
		var chunk domain.CanonicalStreamChunk
		if err := json.Unmarshal([]byte(ev.Data), &chunk); err != nil {
			return nil
		}
		if chunk.Usage != nil {
			*finalUsage = *chunk.Usage
		}
		return onChunk(&chunk)
	})
	return finalUsage, err
}

func (a *Adapter) Embeddings(ctx context.Context, dep *domain.Deployment, req *domain.CanonicalEmbeddingRequest) (*domain.CanonicalEmbeddingResponse, error) {
	model := req.ResolvedModel
	if model == "" && dep != nil && dep.GlobalModel != nil {
		model = dep.GlobalModel.ModelName
	}
	if model == "" {
		model = req.Model
	}

	payload := providers.OpenAIEmbeddingRequest{
		Model:          model,
		Input:          req.Input,
		EncodingFormat: req.EncodingFormat,
		Dimensions:     req.Dimensions,
		User:           req.User,
	}
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	endpoint := resolveBaseURL(dep.Credential) + "/embeddings"
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
			Provider:   domain.ProviderOpenAI,
			Retryable:  true,
		}
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, domain.ClassifyUpstreamStatus(domain.ProviderOpenAI, resp.StatusCode, string(respBody), adapter.ParseRetryAfter(resp.Header))
	}

	var oaiResp providers.OpenAIEmbeddingResponse
	if err := json.Unmarshal(respBody, &oaiResp); err != nil {
		return nil, err
	}
	data := make([]domain.EmbeddingData, 0, len(oaiResp.Data))
	for _, d := range oaiResp.Data {
		data = append(data, domain.EmbeddingData{
			Object:    "embedding",
			Index:     d.Index,
			Embedding: d.Embedding,
		})
	}
	return &domain.CanonicalEmbeddingResponse{
		Object:   "list",
		Data:     data,
		Model:    oaiResp.Model,
		Provider: domain.ProviderOpenAI,
		Usage: domain.TokenUsage{
			PromptTokens: oaiResp.Usage.PromptTokens,
			TotalTokens:  oaiResp.Usage.TotalTokens,
		},
	}, nil
}

func (a *Adapter) ListModels(ctx context.Context, cred *domain.ProviderCredential) ([]domain.DiscoveredModel, error) {
	endpoint := resolveBaseURL(cred) + "/models"
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
		return nil, domain.ClassifyUpstreamStatus(domain.ProviderOpenAI, resp.StatusCode, string(respBody), 0)
	}

	var list providers.OpenAIModelsResponse
	if err := json.Unmarshal(respBody, &list); err != nil {
		return nil, err
	}
	out := make([]domain.DiscoveredModel, 0, len(list.Data))
	for _, m := range list.Data {
		out = append(out, domain.DiscoveredModel{
			Provider:    domain.ProviderOpenAI,
			ModelName:   m.ID,
			DisplayName: m.ID,
			CreatedAt:   m.Created,
		})
	}
	return out, nil
}

func setHeaders(req *http.Request, cred *domain.ProviderCredential) {
	req.Header.Set("Content-Type", "application/json")
	if req.Context() != nil {
		observability.InjectTraceHeaders(req.Context(), req)
	}
	if cred != nil {
		if cred.DecryptedAPIKey != "" {
			req.Header.Set("Authorization", "Bearer "+cred.DecryptedAPIKey)
		}
		for k, v := range cred.Headers {
			req.Header.Set(k, v)
		}
	}
}
