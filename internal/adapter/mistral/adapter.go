package mistral

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

const defaultBaseURL = "https://api.mistral.ai/v1"

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
	return domain.ProviderMistral
}

func resolveBaseURL(cred *domain.ProviderCredential) string {
	if cred != nil && strings.TrimSpace(cred.BaseURL) != "" {
		return strings.TrimRight(cred.BaseURL, "/")
	}
	return defaultBaseURL
}

func toMistralRequest(model string, req *domain.CanonicalChatRequest, stream bool) providers.MistralChatCompletionRequest {
	msgs := make([]providers.MistralMessage, 0, len(req.Messages))
	for _, m := range req.Messages {
		role := m.Role
		if role == "developer" {
			role = "system"
		}
		mm := providers.MistralMessage{
			Role:       role,
			Content:    m.Content,
			Name:       m.Name,
			ToolCallID: m.ToolCallID,
		}
		for _, tc := range m.ToolCalls {
			mm.ToolCalls = append(mm.ToolCalls, providers.OpenAIToolCall{
				Index: tc.Index,
				ID:    tc.ID,
				Type:  tc.Type,
				Function: providers.OpenAIFunctionCall{
					Name:      tc.Function.Name,
					Arguments: tc.Function.Arguments,
				},
			})
		}
		msgs = append(msgs, mm)
	}

	var tools []providers.OpenAITool
	for _, t := range req.Tools {
		tools = append(tools, providers.OpenAITool{
			Type: t.Type,
			Function: providers.OpenAIFunction{
				Name:        t.Function.Name,
				Description: t.Function.Description,
				Parameters:  t.Function.Parameters,
			},
		})
	}

	out := providers.MistralChatCompletionRequest{
		Model:       model,
		Messages:    msgs,
		Temperature: req.Temperature,
		TopP:        req.TopP,
		MaxTokens:   req.MaxTokens,
		Stream:      stream,
		Stop:        req.Stop,
		Tools:       tools,
		ToolChoice:  req.ToolChoice,
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

	payload := toMistralRequest(model, req, false)
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
			Provider:   domain.ProviderMistral,
			Retryable:  true,
		}
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, domain.ClassifyUpstreamStatus(domain.ProviderMistral, resp.StatusCode, string(respBody), adapter.ParseRetryAfter(resp.Header))
	}

	var mResp providers.MistralChatCompletionResponse
	if err := json.Unmarshal(respBody, &mResp); err != nil {
		return nil, fmt.Errorf("decode mistral response: %w", err)
	}

	choices := make([]domain.CanonicalChoice, 0, len(mResp.Choices))
	for _, c := range mResp.Choices {
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
				Role:      c.Message.Role,
				Content:   c.Message.Content,
				ToolCalls: tcs,
			},
			FinishReason: c.FinishReason,
		})
	}

	return &domain.CanonicalChatResponse{
		ID:       mResp.ID,
		Object:   "chat.completion",
		Created:  mResp.Created,
		Model:    mResp.Model,
		Provider: domain.ProviderMistral,
		Choices:  choices,
		Usage: domain.TokenUsage{
			PromptTokens:     mResp.Usage.PromptTokens,
			CompletionTokens: mResp.Usage.CompletionTokens,
			TotalTokens:      mResp.Usage.TotalTokens,
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

	payload := toMistralRequest(model, req, true)
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
			Provider:   domain.ProviderMistral,
			Retryable:  true,
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		errBody, _ := io.ReadAll(resp.Body)
		return nil, domain.ClassifyUpstreamStatus(domain.ProviderMistral, resp.StatusCode, string(errBody), adapter.ParseRetryAfter(resp.Header))
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

	payload := providers.MistralEmbeddingRequest{
		Model:          model,
		Input:          req.Input,
		EncodingFormat: req.EncodingFormat,
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
			Provider:   domain.ProviderMistral,
			Retryable:  true,
		}
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, domain.ClassifyUpstreamStatus(domain.ProviderMistral, resp.StatusCode, string(respBody), adapter.ParseRetryAfter(resp.Header))
	}

	var mResp providers.MistralEmbeddingResponse
	if err := json.Unmarshal(respBody, &mResp); err != nil {
		return nil, err
	}
	data := make([]domain.EmbeddingData, 0, len(mResp.Data))
	for _, d := range mResp.Data {
		data = append(data, domain.EmbeddingData{
			Object:    "embedding",
			Index:     d.Index,
			Embedding: d.Embedding,
		})
	}
	return &domain.CanonicalEmbeddingResponse{
		Object:   "list",
		Data:     data,
		Model:    mResp.Model,
		Provider: domain.ProviderMistral,
		Usage: domain.TokenUsage{
			PromptTokens: mResp.Usage.PromptTokens,
			TotalTokens:  mResp.Usage.TotalTokens,
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
		return nil, domain.ClassifyUpstreamStatus(domain.ProviderMistral, resp.StatusCode, string(respBody), 0)
	}

	var list providers.MistralModelList
	if err := json.Unmarshal(respBody, &list); err != nil {
		return nil, err
	}
	out := make([]domain.DiscoveredModel, 0, len(list.Data))
	for _, m := range list.Data {
		display := m.Name
		if display == "" {
			display = m.ID
		}
		out = append(out, domain.DiscoveredModel{
			Provider:    domain.ProviderMistral,
			ModelName:   m.ID,
			DisplayName: display,
			CreatedAt:   m.Created,
		})
	}
	return out, nil
}

func setHeaders(req *http.Request, cred *domain.ProviderCredential) {
	req.Header.Set("Content-Type", "application/json")
	if cred != nil {
		if cred.DecryptedAPIKey != "" {
			req.Header.Set("Authorization", "Bearer "+cred.DecryptedAPIKey)
		}
		for k, v := range cred.Headers {
			req.Header.Set(k, v)
		}
	}
}
