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

type wireOllamaToolCall struct {
	Function struct {
		Name      string         `json:"name"`
		Arguments map[string]any `json:"arguments"`
	} `json:"function"`
}

type wireOllamaMessage struct {
	Role      string               `json:"role"`
	Content   string               `json:"content"`
	Images    []string             `json:"images,omitempty"`
	ToolCalls []wireOllamaToolCall `json:"tool_calls,omitempty"`
}

type wireOllamaChatRequest struct {
	Model    string              `json:"model"`
	Messages []wireOllamaMessage `json:"messages"`
	Stream   bool                `json:"stream"`
	Think    any                 `json:"think,omitempty"`
	Tools    []map[string]any    `json:"tools,omitempty"`
	Options  map[string]any      `json:"options,omitempty"`
	Format   any                 `json:"format,omitempty"`
}

type wireOllamaChatResponse struct {
	Model   string `json:"model"`
	Message struct {
		Role      string               `json:"role"`
		Content   string               `json:"content"`
		Thinking  string               `json:"thinking,omitempty"`
		ToolCalls []wireOllamaToolCall `json:"tool_calls,omitempty"`
	} `json:"message"`
	Done            bool   `json:"done"`
	DoneReason      string `json:"done_reason,omitempty"`
	PromptEvalCount int    `json:"prompt_eval_count"`
	EvalCount       int    `json:"eval_count"`
}

func parseDataURI(uri string) (b64 string, ok bool) {
	if !strings.HasPrefix(uri, "data:") {
		return "", false
	}
	idx := strings.Index(uri, ";base64,")
	if idx < 0 {
		return "", false
	}
	return uri[idx+len(";base64,"):], true
}

func toOllamaRequest(model string, req *domain.CanonicalChatRequest, stream bool) wireOllamaChatRequest {
	msgs := make([]wireOllamaMessage, 0, len(req.Messages))
	for _, m := range req.Messages {
		role := m.Role
		if role == "developer" {
			role = "system"
		}
		content := m.Content
		var images []string
		if len(m.Parts) > 0 {
			var textSB strings.Builder
			for _, p := range m.Parts {
				switch p.Type {
				case "text":
					textSB.WriteString(p.Text)
				case "image_url":
					if p.ImageURL != nil && p.ImageURL.URL != "" {
						if b64, ok := parseDataURI(p.ImageURL.URL); ok {
							images = append(images, b64)
						}
					}
				}
			}
			if textSB.Len() > 0 {
				content = textSB.String()
			}
		}
		om := wireOllamaMessage{
			Role:    role,
			Content: content,
			Images:  images,
		}
		for _, tc := range m.ToolCalls {
			var args map[string]any
			if tc.Function.Arguments != "" {
				_ = json.Unmarshal([]byte(tc.Function.Arguments), &args)
			}
			if args == nil {
				args = map[string]any{}
			}
			var otc wireOllamaToolCall
			otc.Function.Name = tc.Function.Name
			otc.Function.Arguments = args
			om.ToolCalls = append(om.ToolCalls, otc)
		}
		msgs = append(msgs, om)
	}

	opts := map[string]any{}
	if req.Temperature != nil {
		opts["temperature"] = *req.Temperature
	}
	if req.TopP != nil {
		opts["top_p"] = *req.TopP
	}
	if req.MaxTokens != nil && *req.MaxTokens > 0 {
		opts["num_predict"] = *req.MaxTokens
	}
	if len(req.Stop) > 0 {
		opts["stop"] = req.Stop
	}

	out := wireOllamaChatRequest{
		Model:    model,
		Messages: msgs,
		Stream:   stream,
	}
	if effort := strings.ToLower(strings.TrimSpace(req.ReasoningEffort)); effort != "" {
		switch effort {
		case "none":
			out.Think = false
		case "minimal", "low":
			out.Think = "low"
		case "medium":
			out.Think = "medium"
		case "high", "xhigh", "max":
			out.Think = "high"
		default:
			out.Think = effort
		}
	}
	if len(req.Tools) > 0 {
		for _, t := range req.Tools {
			out.Tools = append(out.Tools, map[string]any{
				"type": "function",
				"function": map[string]any{
					"name":        t.Function.Name,
					"description": t.Function.Description,
					"parameters":  t.Function.Parameters,
				},
			})
		}
	}
	if len(opts) > 0 {
		out.Options = opts
	}
	if req.ResponseFormat != nil {
		switch req.ResponseFormat.Type {
		case "json_object":
			out.Format = "json"
		case "json_schema":
			if len(req.ResponseFormat.JSONSchema) > 0 {
				schema := any(req.ResponseFormat.JSONSchema)
				if inner, ok := req.ResponseFormat.JSONSchema["schema"]; ok {
					schema = inner
				}
				out.Format = schema
			} else {
				out.Format = "json"
			}
		}
	}
	return out
}

func (a *Adapter) materializeImageURLs(ctx context.Context, req *domain.CanonicalChatRequest) (*domain.CanonicalChatRequest, error) {
	copyReq := *req
	copyReq.Messages = append([]domain.CanonicalMessage(nil), req.Messages...)
	for i := range copyReq.Messages {
		copyReq.Messages[i].Parts = append([]domain.ContentPart(nil), req.Messages[i].Parts...)
		for j := range copyReq.Messages[i].Parts {
			part := &copyReq.Messages[i].Parts[j]
			if part.Type != "image_url" || part.ImageURL == nil || part.ImageURL.URL == "" {
				continue
			}
			if _, isDataURI := parseDataURI(part.ImageURL.URL); isDataURI {
				continue
			}
			dataURI, err := adapter.FetchRemoteDataURI(ctx, a.client, part.ImageURL.URL, 20<<20, "image/")
			if err != nil {
				return nil, &domain.GatewayError{
					StatusCode: http.StatusBadRequest,
					Type:       domain.ErrorTypeInvalidRequest,
					Code:       "invalid_image_url",
					Message:    err.Error(),
					Provider:   domain.ProviderOllama,
				}
			}
			imageURLCopy := *part.ImageURL
			imageURLCopy.URL = dataURI
			part.ImageURL = &imageURLCopy
		}
	}
	return &copyReq, nil
}

func mapOllamaToolCalls(raw []wireOllamaToolCall) []domain.CanonicalToolCall {
	if len(raw) == 0 {
		return nil
	}
	out := make([]domain.CanonicalToolCall, 0, len(raw))
	for i, tc := range raw {
		idx := i
		argsBytes, _ := json.Marshal(tc.Function.Arguments)
		out = append(out, domain.CanonicalToolCall{
			Index: &idx,
			ID:    fmt.Sprintf("call_ollama_%d_%d", time.Now().UnixNano(), i),
			Type:  "function",
			Function: domain.CanonicalFunctionCall{
				Name:      tc.Function.Name,
				Arguments: string(argsBytes),
			},
		})
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

	preparedReq, err := a.materializeImageURLs(ctx, req)
	if err != nil {
		return nil, err
	}
	payload := toOllamaRequest(model, preparedReq, false)
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

	var ollResp wireOllamaChatResponse
	if err := json.Unmarshal(respBody, &ollResp); err != nil {
		return nil, fmt.Errorf("decode ollama response: %w", err)
	}

	toolCalls := mapOllamaToolCalls(ollResp.Message.ToolCalls)
	finishReason := "stop"
	if len(toolCalls) > 0 {
		finishReason = "tool_calls"
	} else if ollResp.DoneReason == "length" {
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
					Role:             "assistant",
					Content:          ollResp.Message.Content,
					ReasoningContent: ollResp.Message.Thinking,
					ToolCalls:        toolCalls,
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
	ctx = adapter.StreamingContext(ctx)
	model := req.ResolvedModel
	if model == "" && dep != nil && dep.GlobalModel != nil {
		model = dep.GlobalModel.ModelName
	}
	if model == "" {
		model = req.Model
	}

	preparedReq, err := a.materializeImageURLs(ctx, req)
	if err != nil {
		return nil, err
	}
	payload := toOllamaRequest(model, preparedReq, true)
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
		var ollChunk wireOllamaChatResponse
		if err := json.Unmarshal(line, &ollChunk); err != nil {
			return nil
		}
		toolCalls := mapOllamaToolCalls(ollChunk.Message.ToolCalls)
		var finishPtr *string
		var chunkUsage *domain.TokenUsage
		if ollChunk.Done {
			fr := "stop"
			if len(toolCalls) > 0 {
				fr = "tool_calls"
			}
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
						Content:          ollChunk.Message.Content,
						ReasoningContent: ollChunk.Message.Thinking,
						ToolCalls:        toolCalls,
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
