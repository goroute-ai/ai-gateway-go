package ollama

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

const defaultBaseURL = "http://localhost:11434"

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
	return domain.ProviderOllama
}

func resolveBaseURL(cred *domain.ProviderCredential) string {
	if cred != nil && strings.TrimSpace(cred.BaseURL) != "" {
		return strings.TrimRight(cred.BaseURL, "/")
	}
	return defaultBaseURL
}

func toOllamaRequest(model string, req *domain.CanonicalChatRequest, stream bool) providers.OllamaChatRequest {
	msgs := make([]providers.OllamaMessage, 0, len(req.Messages))
	for _, m := range req.Messages {
		role := m.Role
		if role == "developer" {
			role = "system"
		}
		msgs = append(msgs, providers.OllamaMessage{
			Role:    role,
			Content: m.Content,
		})
	}

	opts := map[string]any{}
	if req.Temperature != nil {
		opts["temperature"] = *req.Temperature
	}
	if req.TopP != nil {
		opts["top_p"] = *req.TopP
	}
	if req.MaxTokens != nil {
		opts["num_predict"] = *req.MaxTokens
	}
	if len(req.Stop) > 0 {
		opts["stop"] = req.Stop
	}

	out := providers.OllamaChatRequest{
		Model:    model,
		Messages: msgs,
		Stream:   stream,
	}
	if len(opts) > 0 {
		out.Options = opts
	}
	if req.ResponseFormat != nil && req.ResponseFormat.Type == "json_object" {
		out.Format = "json"
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

	payload := toOllamaRequest(model, req, false)
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	endpoint := resolveBaseURL(dep.Credential) + "/api/chat"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := a.client.Do(httpReq)
	if err != nil {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusBadGateway,
			Type:       domain.ErrorTypeUpstream,
			Code:       "upstream_network_error",
			Message:    err.Error(),
			Provider:   domain.ProviderOllama,
			Retryable:  true,
		}
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, domain.ClassifyUpstreamStatus(domain.ProviderOllama, resp.StatusCode, string(respBody), 0)
	}

	var ollResp providers.OllamaChatResponse
	if err := json.Unmarshal(respBody, &ollResp); err != nil {
		return nil, fmt.Errorf("decode ollama response: %w", err)
	}

	finishReason := "stop"
	if ollResp.DoneReason == "length" {
		finishReason = "length"
	}

	return &domain.CanonicalChatResponse{
		ID:       fmt.Sprintf("chatcmpl-ollama-%d", time.Now().UnixNano()),
		Object:   "chat.completion",
		Created:  time.Now().Unix(),
		Model:    ollResp.Model,
		Provider: domain.ProviderOllama,
		Choices: []domain.CanonicalChoice{
			{
				Index: 0,
				Message: domain.CanonicalMessage{
					Role:    "assistant",
					Content: ollResp.Message.Content,
				},
				FinishReason: finishReason,
			},
		},
		Usage: domain.TokenUsage{
			PromptTokens:     ollResp.PromptEvalCount,
			CompletionTokens: ollResp.EvalCount,
			TotalTokens:      ollResp.PromptEvalCount + ollResp.EvalCount,
		},
	}, nil
}

// StreamChatCompletion reads Ollama's NDJSON stream line-by-line and emits standard OpenAI SSE chunks.
func (a *Adapter) StreamChatCompletion(ctx context.Context, dep *domain.Deployment, req *domain.CanonicalChatRequest, onChunk adapter.StreamChunkHandler) (*domain.TokenUsage, error) {
	model := req.ResolvedModel
	if model == "" && dep != nil && dep.GlobalModel != nil {
		model = dep.GlobalModel.ModelName
	}
	if model == "" {
		model = req.Model
	}

	payload := toOllamaRequest(model, req, true)
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	endpoint := resolveBaseURL(dep.Credential) + "/api/chat"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := a.client.Do(httpReq)
	if err != nil {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusBadGateway,
			Type:       domain.ErrorTypeUpstream,
			Code:       "upstream_network_error",
			Message:    err.Error(),
			Provider:   domain.ProviderOllama,
			Retryable:  true,
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		errBody, _ := io.ReadAll(resp.Body)
		return nil, domain.ClassifyUpstreamStatus(domain.ProviderOllama, resp.StatusCode, string(errBody), 0)
	}

	msgID := fmt.Sprintf("chatcmpl-ollama-%d", time.Now().UnixNano())
	created := time.Now().Unix()
	usage := &domain.TokenUsage{}

	err = sse.ReadNDJSON(resp.Body, func(line []byte) error {
		var ollChunk providers.OllamaChatResponse
		if err := json.Unmarshal(line, &ollChunk); err != nil {
			return nil
		}
		var finishPtr *string
		var chunkUsage *domain.TokenUsage
		if ollChunk.Done {
			fr := "stop"
			finishPtr = &fr
			usage.PromptTokens = ollChunk.PromptEvalCount
			usage.CompletionTokens = ollChunk.EvalCount
			usage.TotalTokens = ollChunk.PromptEvalCount + ollChunk.EvalCount
			chunkUsage = usage
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
						Content: ollChunk.Message.Content,
					},
					FinishReason: finishPtr,
				},
			},
			Usage: chunkUsage,
		})
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

	payload := providers.OllamaEmbedRequest{
		Model: model,
		Input: req.Input,
	}
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	endpoint := resolveBaseURL(dep.Credential) + "/api/embed"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	resp, err := a.client.Do(httpReq)
	if err != nil {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusBadGateway,
			Type:       domain.ErrorTypeUpstream,
			Code:       "upstream_network_error",
			Message:    err.Error(),
			Provider:   domain.ProviderOllama,
			Retryable:  true,
		}
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, domain.ClassifyUpstreamStatus(domain.ProviderOllama, resp.StatusCode, string(respBody), 0)
	}

	var ollEmb providers.OllamaEmbedResponse
	if err := json.Unmarshal(respBody, &ollEmb); err != nil {
		return nil, err
	}

	data := make([]domain.EmbeddingData, 0, len(ollEmb.Embeddings))
	for i, emb := range ollEmb.Embeddings {
		data = append(data, domain.EmbeddingData{
			Object:    "embedding",
			Index:     i,
			Embedding: emb,
		})
	}
	return &domain.CanonicalEmbeddingResponse{
		Object:   "list",
		Data:     data,
		Model:    ollEmb.Model,
		Provider: domain.ProviderOllama,
		Usage: domain.TokenUsage{
			PromptTokens: ollEmb.PromptEvalCount,
			TotalTokens:  ollEmb.PromptEvalCount,
		},
	}, nil
}

func (a *Adapter) ListModels(ctx context.Context, cred *domain.ProviderCredential) ([]domain.DiscoveredModel, error) {
	endpoint := resolveBaseURL(cred) + "/api/tags"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}

	resp, err := a.client.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, domain.ClassifyUpstreamStatus(domain.ProviderOllama, resp.StatusCode, string(respBody), 0)
	}

	var tags providers.OllamaTagsResponse
	if err := json.Unmarshal(respBody, &tags); err != nil {
		return nil, err
	}
	out := make([]domain.DiscoveredModel, 0, len(tags.Models))
	for _, m := range tags.Models {
		out = append(out, domain.DiscoveredModel{
			Provider:    domain.ProviderOllama,
			ModelName:   m.Name,
			DisplayName: m.Name,
		})
	}
	return out, nil
}
