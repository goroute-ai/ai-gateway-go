package openaicompat

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/goroute-ai/ai-gateway-go/internal/adapter"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/openapi/providers"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
)

// Adapter implements adapter.ProviderAdapter for any OpenAI-compatible dialect.
type Adapter struct {
	profile    *DialectProfile
	validator  *RequestValidator
	httpClient *http.Client
}

// NewAdapter creates an OpenAI-compatible adapter. If httpClient is nil, an SSRF-hardened client is constructed.
func NewAdapter(profile *DialectProfile, httpClient *http.Client) *Adapter {
	if httpClient == nil {
		httpClient = network.NewHTTPClient(nil)
	}
	return &Adapter{
		profile:    profile,
		validator:  NewRequestValidator(profile),
		httpClient: httpClient,
	}
}

func (a *Adapter) Provider() domain.ProviderType {
	return a.profile.ID
}

func (a *Adapter) Profile() *DialectProfile {
	return a.profile
}

func (a *Adapter) ChatCompletion(ctx context.Context, dep *domain.Deployment, req *domain.CanonicalChatRequest) (*domain.CanonicalChatResponse, error) {
	model := req.ResolvedModel
	if model == "" {
		model = req.Model
	}

	// 1. Validate constraints & capabilities
	_, _, err := a.validator.ValidateAndResolveConstraints(req, model)
	if err != nil {
		return nil, err
	}

	// 2. Build upstream target URL
	targetURL, err := a.profile.EndpointStrategy.BuildURL(dep, adapter.OperationChatCompletion)
	if err != nil {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_endpoint_url",
			Message:    err.Error(),
		}
	}

	// 3. Transform canonical request to upstream payload
	upstreamBody, err := a.buildUpstreamPayload(req, model, false)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(upstreamBody))
	if err != nil {
		return nil, fmt.Errorf("create http request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	// Apply default headers from profile
	for k, v := range a.profile.DefaultHeaders {
		httpReq.Header.Set(k, v)
	}

	// Apply authentication strategy
	if err := a.profile.AuthStrategy.ApplyAuth(httpReq, dep.Credential); err != nil {
		return nil, &domain.GatewayError{
			StatusCode:  http.StatusUnauthorized,
			Type:        domain.ErrorTypeAuthentication,
			Code:        "auth_strategy_failed",
			Message:     err.Error(),
			AuthFailure: true,
		}
	}

	resp, err := a.httpClient.Do(httpReq)
	if err != nil {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusBadGateway,
			Type:       domain.ErrorTypeUpstream,
			Code:       "upstream_connection_failed",
			Message:    err.Error(),
			Retryable:  true,
		}
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read upstream response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, a.parseUpstreamError(resp.StatusCode, bodyBytes, resp.Header)
	}

	var openAIResp providers.OpenAIChatCompletionResponse
	if err := json.Unmarshal(bodyBytes, &openAIResp); err != nil {
		return nil, fmt.Errorf("decode upstream chat response: %w", err)
	}

	return a.toCanonicalResponse(&openAIResp, model), nil
}

func (a *Adapter) StreamChatCompletion(ctx context.Context, dep *domain.Deployment, req *domain.CanonicalChatRequest, onChunk adapter.StreamChunkHandler) (*domain.TokenUsage, error) {
	model := req.ResolvedModel
	if model == "" {
		model = req.Model
	}

	_, _, err := a.validator.ValidateAndResolveConstraints(req, model)
	if err != nil {
		return nil, err
	}

	targetURL, err := a.profile.EndpointStrategy.BuildURL(dep, adapter.OperationChatCompletion)
	if err != nil {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_endpoint_url",
			Message:    err.Error(),
		}
	}

	upstreamBody, err := a.buildUpstreamPayload(req, model, true)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(upstreamBody))
	if err != nil {
		return nil, fmt.Errorf("create stream request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "text/event-stream")

	for k, v := range a.profile.DefaultHeaders {
		httpReq.Header.Set(k, v)
	}

	if err := a.profile.AuthStrategy.ApplyAuth(httpReq, dep.Credential); err != nil {
		return nil, &domain.GatewayError{
			StatusCode:  http.StatusUnauthorized,
			Type:        domain.ErrorTypeAuthentication,
			Code:        "auth_strategy_failed",
			Message:     err.Error(),
			AuthFailure: true,
		}
	}

	resp, err := a.httpClient.Do(httpReq)
	if err != nil {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusBadGateway,
			Type:       domain.ErrorTypeUpstream,
			Code:       "upstream_stream_connection_failed",
			Message:    err.Error(),
			Retryable:  true,
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		bodyBytes, _ := io.ReadAll(resp.Body)
		return nil, a.parseUpstreamError(resp.StatusCode, bodyBytes, resp.Header)
	}

	var finalUsage domain.TokenUsage
	scanner := bufio.NewScanner(resp.Body)
	// Accommodate larger SSE buffers for reasoning and tool deltas
	buf := make([]byte, 64*1024)
	scanner.Buffer(buf, 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data:") {
			continue
		}
		data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if data == "" {
			continue
		}
		if data == "[DONE]" {
			break
		}

		// Parse the chunk
		var chunk rawOpenAIStreamChunk
		if err := json.Unmarshal([]byte(data), &chunk); err != nil {
			continue
		}

		if chunk.Usage != nil {
			finalUsage.PromptTokens = chunk.Usage.PromptTokens
			finalUsage.CompletionTokens = chunk.Usage.CompletionTokens
			finalUsage.TotalTokens = chunk.Usage.TotalTokens
			if chunk.Usage.PromptTokensDetails != nil {
				finalUsage.CachedPromptTokens = chunk.Usage.PromptTokensDetails.CachedTokens
			}
			if chunk.Usage.CompletionTokensDetails != nil {
				finalUsage.ReasoningTokens = chunk.Usage.CompletionTokensDetails.ReasoningTokens
			}
		}

		canonicalChunk := a.toCanonicalStreamChunk(&chunk, model)
		if err := onChunk(canonicalChunk); err != nil {
			return &finalUsage, err
		}
	}

	if err := scanner.Err(); err != nil {
		return &finalUsage, &domain.GatewayError{
			StatusCode: http.StatusBadGateway,
			Type:       domain.ErrorTypeUpstream,
			Code:       "stream_scan_error",
			Message:    err.Error(),
			Retryable:  false,
		}
	}

	return &finalUsage, nil
}

func (a *Adapter) Embeddings(ctx context.Context, dep *domain.Deployment, req *domain.CanonicalEmbeddingRequest) (*domain.CanonicalEmbeddingResponse, error) {
	model := req.ResolvedModel
	if model == "" {
		model = req.Model
	}

	targetURL, err := a.profile.EndpointStrategy.BuildURL(dep, adapter.OperationEmbeddings)
	if err != nil {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_embeddings_url",
			Message:    err.Error(),
		}
	}

	upstreamReq := providers.OpenAIEmbeddingRequest{
		Model: model,
		Input: req.Input,
	}

	b, err := json.Marshal(upstreamReq)
	if err != nil {
		return nil, fmt.Errorf("marshal embedding request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("create embeddings request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	for k, v := range a.profile.DefaultHeaders {
		httpReq.Header.Set(k, v)
	}

	if err := a.profile.AuthStrategy.ApplyAuth(httpReq, dep.Credential); err != nil {
		return nil, &domain.GatewayError{
			StatusCode:  http.StatusUnauthorized,
			Type:        domain.ErrorTypeAuthentication,
			Code:        "auth_strategy_failed",
			Message:     err.Error(),
			AuthFailure: true,
		}
	}

	resp, err := a.httpClient.Do(httpReq)
	if err != nil {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusBadGateway,
			Type:       domain.ErrorTypeUpstream,
			Code:       "upstream_embeddings_connection_failed",
			Message:    err.Error(),
			Retryable:  true,
		}
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read embeddings response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, a.parseUpstreamError(resp.StatusCode, bodyBytes, resp.Header)
	}

	var openAIEmbResp struct {
		Object string `json:"object"`
		Data   []struct {
			Index     int       `json:"index"`
			Embedding []float64 `json:"embedding"`
		} `json:"data"`
		Model string `json:"model"`
		Usage struct {
			PromptTokens int `json:"prompt_tokens"`
			TotalTokens  int `json:"total_tokens"`
		} `json:"usage"`
	}

	if err := json.Unmarshal(bodyBytes, &openAIEmbResp); err != nil {
		return nil, fmt.Errorf("decode embeddings response: %w", err)
	}

	out := &domain.CanonicalEmbeddingResponse{
		Model: openAIEmbResp.Model,
		Data:  make([]domain.EmbeddingData, len(openAIEmbResp.Data)),
		Usage: domain.TokenUsage{
			PromptTokens: openAIEmbResp.Usage.PromptTokens,
			TotalTokens:  openAIEmbResp.Usage.TotalTokens,
		},
	}
	for i, d := range openAIEmbResp.Data {
		out.Data[i] = domain.EmbeddingData{
			Index:     d.Index,
			Embedding: d.Embedding,
		}
	}
	return out, nil
}

func (a *Adapter) ListModels(ctx context.Context, cred *domain.ProviderCredential) ([]domain.DiscoveredModel, error) {
	if !a.profile.SupportsListModels {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusNotImplemented,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "list_models_unsupported",
			Message:    fmt.Sprintf("Provider %q does not support /models listing probe", a.profile.ID),
		}
	}

	dummyDep := &domain.Deployment{
		ID:         "list-models",
		Credential: cred,
	}
	targetURL, err := a.profile.EndpointStrategy.BuildURL(dummyDep, adapter.OperationListModels)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		return nil, fmt.Errorf("create list models request: %w", err)
	}

	for k, v := range a.profile.DefaultHeaders {
		httpReq.Header.Set(k, v)
	}

	if err := a.profile.AuthStrategy.ApplyAuth(httpReq, cred); err != nil {
		return nil, &domain.GatewayError{
			StatusCode:  http.StatusUnauthorized,
			Type:        domain.ErrorTypeAuthentication,
			Code:        "auth_strategy_failed",
			Message:     err.Error(),
			AuthFailure: true,
		}
	}

	resp, err := a.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("list models request failed: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read list models response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, a.parseUpstreamError(resp.StatusCode, bodyBytes, resp.Header)
	}

	var listResp struct {
		Data []struct {
			ID      string `json:"id"`
			OwnedBy string `json:"owned_by"`
		} `json:"data"`
	}
	if err := json.Unmarshal(bodyBytes, &listResp); err != nil {
		return nil, fmt.Errorf("decode list models response: %w", err)
	}

	out := make([]domain.DiscoveredModel, 0, len(listResp.Data))
	for _, m := range listResp.Data {
		out = append(out, domain.DiscoveredModel{
			Provider:    a.profile.ID,
			ModelName:   m.ID,
			DisplayName: m.ID,
		})
	}
	return out, nil
}

// BuildUpstreamPayload marshals and adapts CanonicalChatRequest to the target upstream dialect.
func (a *Adapter) BuildUpstreamPayload(req *domain.CanonicalChatRequest, model string, stream bool) ([]byte, error) {
	return a.buildUpstreamPayload(req, model, stream)
}

// buildUpstreamPayload marshals and adapts CanonicalChatRequest to the target upstream dialect.
func (a *Adapter) buildUpstreamPayload(req *domain.CanonicalChatRequest, model string, stream bool) ([]byte, error) {
	payload := make(map[string]any)
	payload["model"] = model
	payload["stream"] = stream

	if stream {
		payload["stream_options"] = map[string]any{"include_usage": true}
	}

	// Adapt Messages
	messages := make([]any, len(req.Messages))
	for i, m := range req.Messages {
		msgMap := map[string]any{
			"role": m.Role,
		}
		if len(m.Parts) > 0 {
			if a.profile.ConvertContentListToString {
				var sb strings.Builder
				for _, p := range m.Parts {
					if p.Type == "text" {
						sb.WriteString(p.Text)
					}
				}
				msgMap["content"] = sb.String()
			} else {
				msgMap["content"] = m.Parts
			}
		} else {
			msgMap["content"] = m.Content
		}
		if m.Name != "" {
			msgMap["name"] = m.Name
		}
		if m.ToolCallID != "" {
			msgMap["tool_call_id"] = m.ToolCallID
		}
		if len(m.ToolCalls) > 0 {
			msgMap["tool_calls"] = m.ToolCalls
		}
		messages[i] = msgMap
	}
	payload["messages"] = messages

	// Adapt Sampling Parameters
	if req.Temperature != nil {
		payload["temperature"] = *req.Temperature
	}
	if req.TopP != nil {
		payload["top_p"] = *req.TopP
	}
	if len(req.Stop) > 0 {
		payload["stop"] = req.Stop
	}
	if req.ResponseFormat != nil {
		payload["response_format"] = req.ResponseFormat
	}
	if len(req.Tools) > 0 {
		payload["tools"] = req.Tools
	}
	if req.ToolChoice != nil {
		payload["tool_choice"] = req.ToolChoice
	}
	if req.User != "" {
		payload["user"] = req.User
	}

	// Adapt Token Limit Parameters
	// Check if this dialect maps max_completion_tokens -> max_tokens
	maxTokensTargetKey := "max_completion_tokens"
	if target, ok := a.profile.ParamMappings["max_completion_tokens"]; ok && target != "" {
		maxTokensTargetKey = target
	}

	if req.MaxTokens != nil && *req.MaxTokens > 0 {
		payload[maxTokensTargetKey] = *req.MaxTokens
	}

	return json.Marshal(payload)
}

func (a *Adapter) toCanonicalResponse(r *providers.OpenAIChatCompletionResponse, requestedModel string) *domain.CanonicalChatResponse {
	out := &domain.CanonicalChatResponse{
		ID:                r.ID,
		Model:             r.Model,
		Created:           r.Created,
		SystemFingerprint: r.SystemFingerprint,
		Choices:           make([]domain.CanonicalChoice, len(r.Choices)),
		Usage: domain.TokenUsage{
			PromptTokens:     r.Usage.PromptTokens,
			CompletionTokens: r.Usage.CompletionTokens,
			TotalTokens:      r.Usage.TotalTokens,
		},
	}
	if r.Usage.PromptTokensDetails != nil {
		out.Usage.CachedPromptTokens = r.Usage.PromptTokensDetails.CachedTokens
	}
	if r.Usage.CompletionTokensDetails != nil {
		out.Usage.ReasoningTokens = r.Usage.CompletionTokensDetails.ReasoningTokens
	}

	for i, c := range r.Choices {
		contentStr := ""
		if str, ok := c.Message.Content.(string); ok {
			contentStr = str
		}
		reasoning := c.Message.ReasoningContent
		if reasoning == "" {
			reasoning = c.Message.Reasoning
		}
		if reasoning == "" {
			reasoning = c.Message.Thought
		}
		msg := domain.CanonicalMessage{
			Role:             c.Message.Role,
			Content:          contentStr,
			Name:             c.Message.Name,
			ToolCallID:       c.Message.ToolCallID,
			ReasoningContent: reasoning,
		}
		if len(c.Message.ToolCalls) > 0 {
			msg.ToolCalls = make([]domain.CanonicalToolCall, len(c.Message.ToolCalls))
			for j, tc := range c.Message.ToolCalls {
				msg.ToolCalls[j] = domain.CanonicalToolCall{
					Index: tc.Index,
					ID:    tc.ID,
					Type:  tc.Type,
					Function: domain.CanonicalFunctionCall{
						Name:      tc.Function.Name,
						Arguments: tc.Function.Arguments,
					},
				}
			}
		}
		out.Choices[i] = domain.CanonicalChoice{
			Index:        c.Index,
			Message:      msg,
			FinishReason: c.FinishReason,
		}
	}
	return out
}

type rawOpenAIStreamChunk struct {
	ID      string `json:"id"`
	Created int64  `json:"created"`
	Model   string `json:"model"`
	Choices []struct {
		Index int `json:"index"`
		Delta struct {
			Role             string                     `json:"role,omitempty"`
			Content          string                     `json:"content,omitempty"`
			ReasoningContent string                     `json:"reasoning_content,omitempty"` // e.g. DeepSeek R1
			Reasoning        string                     `json:"reasoning,omitempty"`
			Thought          string                     `json:"thought,omitempty"`
			ToolCalls        []domain.CanonicalToolCall `json:"tool_calls,omitempty"`
		} `json:"delta"`
		FinishReason *string `json:"finish_reason,omitempty"`
	} `json:"choices"`
	Usage *struct {
		PromptTokens        int `json:"prompt_tokens"`
		CompletionTokens    int `json:"completion_tokens"`
		TotalTokens         int `json:"total_tokens"`
		PromptTokensDetails *struct {
			CachedTokens int `json:"cached_tokens"`
		} `json:"prompt_tokens_details,omitempty"`
		CompletionTokensDetails *struct {
			ReasoningTokens int `json:"reasoning_tokens"`
		} `json:"completion_tokens_details,omitempty"`
	} `json:"usage,omitempty"`
}

func (a *Adapter) toCanonicalStreamChunk(raw *rawOpenAIStreamChunk, model string) *domain.CanonicalStreamChunk {
	out := &domain.CanonicalStreamChunk{
		ID:      raw.ID,
		Created: raw.Created,
		Model:   raw.Model,
		Choices: make([]domain.CanonicalStreamChoice, len(raw.Choices)),
	}
	for i, c := range raw.Choices {
		delta := domain.CanonicalStreamDelta{
			Role:      c.Delta.Role,
			Content:   c.Delta.Content,
			ToolCalls: c.Delta.ToolCalls,
		}
		if a.profile.ExtractReasoningDelta {
			reasoning := c.Delta.ReasoningContent
			if reasoning == "" {
				reasoning = c.Delta.Reasoning
			}
			if reasoning == "" {
				reasoning = c.Delta.Thought
			}
			delta.ReasoningContent = reasoning
		}
		out.Choices[i] = domain.CanonicalStreamChoice{
			Index:        c.Index,
			Delta:        delta,
			FinishReason: c.FinishReason,
		}
	}
	if raw.Usage != nil {
		out.Usage = &domain.TokenUsage{
			PromptTokens:     raw.Usage.PromptTokens,
			CompletionTokens: raw.Usage.CompletionTokens,
			TotalTokens:      raw.Usage.TotalTokens,
		}
		if raw.Usage.PromptTokensDetails != nil {
			out.Usage.CachedPromptTokens = raw.Usage.PromptTokensDetails.CachedTokens
		}
		if raw.Usage.CompletionTokensDetails != nil {
			out.Usage.ReasoningTokens = raw.Usage.CompletionTokensDetails.ReasoningTokens
		}
	}
	return out
}

func (a *Adapter) parseUpstreamError(statusCode int, body []byte, headers http.Header) error {
	var errEnvelope struct {
		Error struct {
			Message string `json:"message"`
			Type    string `json:"type"`
			Code    string `json:"code"`
		} `json:"error"`
		Detail string `json:"detail"`
	}
	_ = json.Unmarshal(body, &errEnvelope)

	msg := errEnvelope.Error.Message
	if msg == "" {
		msg = errEnvelope.Detail
	}
	if msg == "" {
		msg = string(body)
	}

	errCode := errEnvelope.Error.Code
	if errCode == "" {
		errCode = fmt.Sprintf("upstream_error_%d", statusCode)
	}

	authFail := statusCode == http.StatusUnauthorized || statusCode == http.StatusForbidden
	retryable := statusCode == http.StatusTooManyRequests || statusCode >= 500

	return &domain.GatewayError{
		StatusCode:    statusCode,
		Type:          domain.ErrorTypeUpstream,
		Code:          errCode,
		Message:       fmt.Sprintf("upstream error (%d): %s", statusCode, msg),
		RetryAfterSec: adapter.ParseRetryAfter(headers),
		Retryable:     retryable,
		AuthFailure:   authFail,
	}
}
