package cohere

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/adapter"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/observability"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
)

const defaultCohereBaseURL = "https://api.cohere.com"

// Adapter implements adapter.ProviderAdapter for Cohere v2 API.
type Adapter struct {
	httpClient *http.Client
	ssrfPolicy *network.Policy
}

// NewAdapter creates a new Cohere adapter.
func NewAdapter(httpClient *http.Client, ssrfPolicy *network.Policy) *Adapter {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &Adapter{
		httpClient: httpClient,
		ssrfPolicy: ssrfPolicy,
	}
}

func (a *Adapter) Provider() domain.ProviderType {
	return domain.ProviderCohere
}

func (a *Adapter) getBaseURL(dep *domain.Deployment) string {
	if dep.Credential != nil && dep.Credential.BaseURL != "" {
		return strings.TrimRight(dep.Credential.BaseURL, "/")
	}
	return defaultCohereBaseURL
}

func (a *Adapter) getAPIKey(dep *domain.Deployment) (string, error) {
	if dep.Credential == nil || dep.Credential.DecryptedAPIKey == "" {
		return "", &domain.GatewayError{
			StatusCode:  http.StatusUnauthorized,
			Type:        domain.ErrorTypeAuthentication,
			Code:        "missing_credential",
			Message:     "cohere api key is required",
			AuthFailure: true,
		}
	}
	return dep.Credential.DecryptedAPIKey, nil
}

func (a *Adapter) ChatCompletion(ctx context.Context, dep *domain.Deployment, req *domain.CanonicalChatRequest) (*domain.CanonicalChatResponse, error) {
	apiKey, err := a.getAPIKey(dep)
	if err != nil {
		return nil, err
	}

	model := req.ResolvedModel
	if model == "" {
		model = req.Model
	}

	bodyBytes, err := buildChatPayload(req, model, false)
	if err != nil {
		return nil, fmt.Errorf("build cohere payload: %w", err)
	}

	targetURL := a.getBaseURL(dep) + "/v2/chat"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+apiKey)

	resp, err := a.httpClient.Do(httpReq)
	if err != nil {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusBadGateway,
			Type:       domain.ErrorTypeUpstream,
			Code:       "cohere_connection_failed",
			Message:    err.Error(),
			Retryable:  true,
		}
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, parseCohereError(resp.StatusCode, respBytes)
	}

	return parseChatResponse(respBytes, model)
}

func (a *Adapter) StreamChatCompletion(ctx context.Context, dep *domain.Deployment, req *domain.CanonicalChatRequest, onChunk adapter.StreamChunkHandler) (*domain.TokenUsage, error) {
	apiKey, err := a.getAPIKey(dep)
	if err != nil {
		return nil, err
	}

	model := req.ResolvedModel
	if model == "" {
		model = req.Model
	}

	bodyBytes, err := buildChatPayload(req, model, true)
	if err != nil {
		return nil, fmt.Errorf("build cohere payload: %w", err)
	}

	targetURL := a.getBaseURL(dep) + "/v2/chat"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+apiKey)

	resp, err := a.httpClient.Do(httpReq)
	if err != nil {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusBadGateway,
			Type:       domain.ErrorTypeUpstream,
			Code:       "cohere_stream_failed",
			Message:    err.Error(),
			Retryable:  true,
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBytes, _ := io.ReadAll(resp.Body)
		return nil, parseCohereError(resp.StatusCode, respBytes)
	}

	var finalUsage domain.TokenUsage
	chunkID := fmt.Sprintf("cohere-%d", time.Now().UnixNano())

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		dataStr := strings.TrimSpace(strings.TrimPrefix(line, "data: "))
		if dataStr == "[DONE]" || dataStr == "" {
			continue
		}

		var event struct {
			Type  string `json:"type"`
			Delta *struct {
				Message *struct {
					Content *struct {
						Text string `json:"text,omitempty"`
					} `json:"content,omitempty"`
					ToolCalls []struct {
						ID       string `json:"id"`
						Type     string `json:"type"`
						Function struct {
							Name      string `json:"name"`
							Arguments string `json:"arguments"`
						} `json:"function"`
					} `json:"tool_calls,omitempty"`
				} `json:"message,omitempty"`
				FinishReason string `json:"finish_reason,omitempty"`
				Usage        *struct {
					BilledUnits *struct {
						InputTokens  int `json:"input_tokens"`
						OutputTokens int `json:"output_tokens"`
					} `json:"billed_units,omitempty"`
					Tokens *struct {
						InputTokens  int `json:"input_tokens"`
						OutputTokens int `json:"output_tokens"`
					} `json:"tokens,omitempty"`
				} `json:"usage,omitempty"`
			} `json:"delta,omitempty"`
		}

		if err := json.Unmarshal([]byte(dataStr), &event); err != nil {
			continue
		}

		if event.Delta == nil {
			continue
		}

		if event.Delta.Usage != nil {
			if event.Delta.Usage.Tokens != nil {
				finalUsage.PromptTokens = event.Delta.Usage.Tokens.InputTokens
				finalUsage.CompletionTokens = event.Delta.Usage.Tokens.OutputTokens
				finalUsage.TotalTokens = finalUsage.PromptTokens + finalUsage.CompletionTokens
			} else if event.Delta.Usage.BilledUnits != nil {
				finalUsage.PromptTokens = event.Delta.Usage.BilledUnits.InputTokens
				finalUsage.CompletionTokens = event.Delta.Usage.BilledUnits.OutputTokens
				finalUsage.TotalTokens = finalUsage.PromptTokens + finalUsage.CompletionTokens
			}
		}

		text := ""
		if event.Delta.Message != nil && event.Delta.Message.Content != nil {
			text = event.Delta.Message.Content.Text
		}

		var toolCalls []domain.CanonicalToolCall
		if event.Delta.Message != nil && len(event.Delta.Message.ToolCalls) > 0 {
			for _, tc := range event.Delta.Message.ToolCalls {
				toolCalls = append(toolCalls, domain.CanonicalToolCall{
					ID:   tc.ID,
					Type: "function",
					Function: domain.CanonicalFunctionCall{
						Name:      tc.Function.Name,
						Arguments: tc.Function.Arguments,
					},
				})
			}
		}

		var finishReason *string
		if event.Delta.FinishReason != "" {
			fr := mapCohereFinishReason(event.Delta.FinishReason)
			finishReason = &fr
		}

		if text != "" || len(toolCalls) > 0 || finishReason != nil {
			canonicalChunk := &domain.CanonicalStreamChunk{
				ID:      chunkID,
				Created: time.Now().Unix(),
				Model:   model,
				Choices: []domain.CanonicalStreamChoice{
					{
						Index: 0,
						Delta: domain.CanonicalStreamDelta{
							Content:   text,
							ToolCalls: toolCalls,
						},
						FinishReason: finishReason,
					},
				},
			}
			if err := onChunk(canonicalChunk); err != nil {
				return &finalUsage, err
			}
		}
	}

	return &finalUsage, nil
}

func (a *Adapter) Embeddings(ctx context.Context, dep *domain.Deployment, req *domain.CanonicalEmbeddingRequest) (*domain.CanonicalEmbeddingResponse, error) {
	apiKey, err := a.getAPIKey(dep)
	if err != nil {
		return nil, err
	}

	model := req.ResolvedModel
	if model == "" {
		model = req.Model
	}

	embedPayload := map[string]any{
		"model":           model,
		"texts":           req.Input,
		"input_type":      "search_document",
		"embedding_types": []string{"float"},
	}
	bodyBytes, _ := json.Marshal(embedPayload)

	targetURL := a.getBaseURL(dep) + "/v2/embed"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+apiKey)

	resp, err := a.httpClient.Do(httpReq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, parseCohereError(resp.StatusCode, respBytes)
	}

	var embedResp struct {
		Embeddings struct {
			Float [][]float64 `json:"float"`
		} `json:"embeddings"`
		Meta *struct {
			BilledUnits *struct {
				InputTokens int `json:"input_tokens"`
			} `json:"billed_units,omitempty"`
		} `json:"meta,omitempty"`
	}
	if err := json.Unmarshal(respBytes, &embedResp); err != nil {
		return nil, fmt.Errorf("decode cohere embedding response: %w", err)
	}

	data := make([]domain.EmbeddingData, len(embedResp.Embeddings.Float))
	for i, emb := range embedResp.Embeddings.Float {
		data[i] = domain.EmbeddingData{
			Index:     i,
			Embedding: emb,
			Object:    "embedding",
		}
	}

	promptTokens := 0
	if embedResp.Meta != nil && embedResp.Meta.BilledUnits != nil {
		promptTokens = embedResp.Meta.BilledUnits.InputTokens
	}

	return &domain.CanonicalEmbeddingResponse{
		Object: "list",
		Data:   data,
		Model:  model,
		Usage: domain.TokenUsage{
			PromptTokens: promptTokens,
			TotalTokens:  promptTokens,
		},
	}, nil
}

func (a *Adapter) ListModels(ctx context.Context, cred *domain.ProviderCredential) ([]domain.DiscoveredModel, error) {
	return []domain.DiscoveredModel{
		{Provider: domain.ProviderCohere, ModelName: "command-r-plus-08-2024", DisplayName: "Command R+ (Cohere v2)"},
		{Provider: domain.ProviderCohere, ModelName: "command-r-08-2024", DisplayName: "Command R (Cohere v2)"},
		{Provider: domain.ProviderCohere, ModelName: "embed-english-v3.0", DisplayName: "Cohere Embed English v3"},
	}, nil
}

func buildChatPayload(req *domain.CanonicalChatRequest, model string, stream bool) ([]byte, error) {
	payload := make(map[string]any)
	payload["model"] = model
	payload["stream"] = stream

	var messages []map[string]any
	for _, m := range req.Messages {
		msg := map[string]any{
			"role":    m.Role,
			"content": m.Content,
		}
		if m.ToolCallID != "" {
			msg["tool_call_id"] = m.ToolCallID
		}
		if len(m.ToolCalls) > 0 {
			var tcs []map[string]any
			for _, tc := range m.ToolCalls {
				tcs = append(tcs, map[string]any{
					"id":   tc.ID,
					"type": tc.Type,
					"function": map[string]any{
						"name":      tc.Function.Name,
						"arguments": tc.Function.Arguments,
					},
				})
			}
			msg["tool_calls"] = tcs
		}
		messages = append(messages, msg)
	}
	payload["messages"] = messages

	if req.Temperature != nil {
		payload["temperature"] = *req.Temperature
	}
	if req.MaxTokens != nil && *req.MaxTokens > 0 {
		payload["max_tokens"] = *req.MaxTokens
	}
	if len(req.Stop) > 0 {
		payload["stop_sequences"] = req.Stop
	}

	if len(req.Tools) > 0 {
		var tools []map[string]any
		for _, t := range req.Tools {
			tools = append(tools, map[string]any{
				"type": "function",
				"function": map[string]any{
					"name":        t.Function.Name,
					"description": t.Function.Description,
					"parameters":  t.Function.Parameters,
				},
			})
		}
		payload["tools"] = tools
	}

	return json.Marshal(payload)
}

func parseChatResponse(data []byte, model string) (*domain.CanonicalChatResponse, error) {
	var resp struct {
		ID      string `json:"id"`
		Message struct {
			Role    string `json:"role"`
			Content []struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
			ToolCalls []struct {
				ID       string `json:"id"`
				Type     string `json:"type"`
				Function struct {
					Name      string `json:"name"`
					Arguments string `json:"arguments"`
				} `json:"function"`
			} `json:"tool_calls"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
		Usage        struct {
			Tokens struct {
				InputTokens  int `json:"input_tokens"`
				OutputTokens int `json:"output_tokens"`
			} `json:"tokens"`
			BilledUnits struct {
				InputTokens  int `json:"input_tokens"`
				OutputTokens int `json:"output_tokens"`
			} `json:"billed_units"`
		} `json:"usage"`
	}

	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal cohere chat response: %w", err)
	}

	var sb strings.Builder
	for _, c := range resp.Message.Content {
		sb.WriteString(c.Text)
	}

	var toolCalls []domain.CanonicalToolCall
	for i, tc := range resp.Message.ToolCalls {
		idx := i
		toolCalls = append(toolCalls, domain.CanonicalToolCall{
			Index: &idx,
			ID:    tc.ID,
			Type:  tc.Type,
			Function: domain.CanonicalFunctionCall{
				Name:      tc.Function.Name,
				Arguments: tc.Function.Arguments,
			},
		})
	}

	inputTokens := resp.Usage.Tokens.InputTokens
	outputTokens := resp.Usage.Tokens.OutputTokens
	if inputTokens == 0 && outputTokens == 0 {
		inputTokens = resp.Usage.BilledUnits.InputTokens
		outputTokens = resp.Usage.BilledUnits.OutputTokens
	}

	return &domain.CanonicalChatResponse{
		ID:      resp.ID,
		Model:   model,
		Created: time.Now().Unix(),
		Choices: []domain.CanonicalChoice{
			{
				Index: 0,
				Message: domain.CanonicalMessage{
					Role:      resp.Message.Role,
					Content:   sb.String(),
					ToolCalls: toolCalls,
				},
				FinishReason: mapCohereFinishReason(resp.FinishReason),
			},
		},
		Usage: domain.TokenUsage{
			PromptTokens:     inputTokens,
			CompletionTokens: outputTokens,
			TotalTokens:      inputTokens + outputTokens,
		},
	}, nil
}

func mapCohereFinishReason(fr string) string {
	switch fr {
	case "COMPLETE":
		return "stop"
	case "TOOL_CALL":
		return "tool_calls"
	case "MAX_TOKENS":
		return "length"
	default:
		return strings.ToLower(fr)
	}
}

func parseCohereError(statusCode int, body []byte) error {
	var errResp struct {
		Message string `json:"message"`
	}
	_ = json.Unmarshal(body, &errResp)

	msg := errResp.Message
	if msg == "" {
		msg = string(body)
	}

	gwErr := &domain.GatewayError{
		StatusCode: statusCode,
		Message:    msg,
	}
	switch statusCode {
	case http.StatusUnauthorized, http.StatusForbidden:
		gwErr.Type = domain.ErrorTypeAuthentication
		gwErr.Code = "cohere_auth_failed"
		gwErr.AuthFailure = true
	case http.StatusBadRequest:
		gwErr.Type = domain.ErrorTypeInvalidRequest
		gwErr.Code = "cohere_invalid_request"
	case http.StatusTooManyRequests:
		gwErr.Type = domain.ErrorTypeRateLimit
		gwErr.Code = "cohere_rate_limited"
		gwErr.Retryable = true
	default:
		gwErr.Type = domain.ErrorTypeUpstream
		gwErr.Code = "cohere_upstream_error"
		gwErr.Retryable = true
	}
	return gwErr
}

// Rerank performs document reranking using the Cohere v2 Rerank API.
func (a *Adapter) Rerank(ctx context.Context, dep *domain.Deployment, req *domain.CanonicalRerankRequest) (*domain.CanonicalRerankResponse, error) {
	if dep == nil {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "missing_deployment",
			Message:    "deployment cannot be nil",
		}
	}
	apiKey, err := a.getAPIKey(dep)
	if err != nil {
		return nil, err
	}

	model := dep.GlobalModel.ModelName
	if req.ResolvedModel != "" {
		model = req.ResolvedModel
	}

	type cohereRerankReq struct {
		Model           string                  `json:"model"`
		Query           string                  `json:"query"`
		Documents       []domain.RerankDocument `json:"documents"`
		TopN            *int                    `json:"top_n,omitempty"`
		RankFields      []string                `json:"rank_fields,omitempty"`
		ReturnDocuments bool                    `json:"return_documents"`
		MaxTokensPerDoc *int                    `json:"max_tokens_per_doc,omitempty"`
	}

	cReq := cohereRerankReq{
		Model:           model,
		Query:           req.Query,
		Documents:       req.Documents,
		TopN:            req.TopN,
		RankFields:      req.RankFields,
		ReturnDocuments: req.ReturnDocuments,
		MaxTokensPerDoc: req.MaxTokensPerDoc,
	}

	bodyBytes, err := json.Marshal(cReq)
	if err != nil {
		return nil, fmt.Errorf("marshal cohere rerank request: %w", err)
	}

	url := fmt.Sprintf("%s/v2/rerank", a.getBaseURL(dep))
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("create cohere rerank request: %w", err)
	}
	httpReq.Header.Set("Authorization", "Bearer "+apiKey)
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")
	httpReq.Header.Set("User-Agent", "goroute-ai-gateway")

	observability.InjectTraceHeaders(ctx, httpReq)

	resp, err := a.httpClient.Do(httpReq)
	if err != nil {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusBadGateway,
			Type:       domain.ErrorTypeUpstream,
			Code:       "cohere_network_error",
			Message:    err.Error(),
			Retryable:  true,
		}
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read cohere rerank response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, parseCohereError(resp.StatusCode, respBytes)
	}

	var rawResp struct {
		ID      string `json:"id"`
		Results []struct {
			Index          int            `json:"index"`
			RelevanceScore float64        `json:"relevance_score"`
			Document       map[string]any `json:"document,omitempty"`
		} `json:"results"`
		Meta struct {
			BilledUnits struct {
				SearchUnits int `json:"search_units"`
				TotalTokens int `json:"total_tokens"`
			} `json:"billed_units"`
		} `json:"meta"`
	}
	if err := json.Unmarshal(respBytes, &rawResp); err != nil {
		return nil, fmt.Errorf("unmarshal cohere rerank response: %w", err)
	}

	results := make([]domain.RerankResultItem, len(rawResp.Results))
	for i, r := range rawResp.Results {
		results[i] = domain.RerankResultItem{
			Index:          r.Index,
			RelevanceScore: r.RelevanceScore,
			Document:       r.Document,
		}
	}

	searchUnits := rawResp.Meta.BilledUnits.SearchUnits
	if searchUnits <= 0 {
		searchUnits = 1
	}

	return &domain.CanonicalRerankResponse{
		ID:       rawResp.ID,
		Model:    req.Model,
		Provider: domain.ProviderCohere,
		Results:  results,
		Usage: domain.RerankUsage{
			SearchUnits: searchUnits,
			TotalTokens: rawResp.Meta.BilledUnits.TotalTokens,
		},
	}, nil
}
