package openaicompat

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
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

// SupportsOperation reports whether this OpenAI-compatible profile declares upstream
// wire support for the given operation, independent of per-model capabilities.
func (a *Adapter) SupportsOperation(op domain.OperationType) bool {
	if a.profile == nil {
		return false
	}
	ops := a.profile.SupportedOperations
	switch op {
	case domain.OperationChat:
		return ops == nil || ops.Chat
	case domain.OperationCompletion:
		return ops != nil && ops.Completion
	case domain.OperationResponses:
		return ops == nil || ops.Responses
	case domain.OperationEmbedding:
		if a.profile.DefaultCapabilities.Embeddings == domain.CapabilityUnsupported {
			return false
		}
		return ops == nil || ops.Embeddings
	case domain.OperationRerank:
		return ops != nil && ops.Rerank
	case domain.OperationModeration:
		return ops != nil && ops.Moderations
	case domain.OperationImageGeneration:
		return ops != nil && ops.ImageGen
	case domain.OperationImageEdit:
		return ops != nil && ops.ImageEdit
	case domain.OperationImageVariation:
		return ops != nil && ops.ImageVariation
	case domain.OperationAudioSTT:
		return ops != nil && ops.AudioSTT
	case domain.OperationAudioTTS:
		return ops != nil && ops.AudioTTS
	default:
		return false
	}
}

func (a *Adapter) ChatCompletion(ctx context.Context, dep *domain.Deployment, req *domain.CanonicalChatRequest) (*domain.CanonicalChatResponse, error) {
	model := req.ResolvedModel
	if model == "" {
		model = req.Model
	}

	// 1. Validate constraints & capabilities (with opt-in observable parameter shaping)
	shapedReq, dropped, err := a.validator.ShapeRequest(req, model)
	if err != nil {
		return nil, err
	}
	if len(dropped) > 0 {
		slog.Debug("openaicompat shaped unsupported parameters", "provider", a.profile.ID, "model", model, "dropped", dropped, "request_id", req.RequestID)
	}
	req = shapedReq

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
	ctx = adapter.StreamingContext(ctx)
	model := req.ResolvedModel
	if model == "" {
		model = req.Model
	}

	shapedReq, dropped, err := a.validator.ShapeRequest(req, model)
	if err != nil {
		return nil, err
	}
	if len(dropped) > 0 {
		slog.Debug("openaicompat shaped unsupported stream parameters", "provider", a.profile.ID, "model", model, "dropped", dropped, "request_id", req.RequestID)
	}
	req = shapedReq

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
		Model:          model,
		Input:          req.Input,
		EncodingFormat: req.EncodingFormat,
		User:           req.User,
	}
	if req.Dimensions != nil && *req.Dimensions > 0 {
		upstreamReq.Dimensions = req.Dimensions
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
// Precedence: ExtraBodyFields < req.ExtraParams < canonical protected fields < StrippedParams removal.
func (a *Adapter) buildUpstreamPayload(req *domain.CanonicalChatRequest, model string, stream bool) ([]byte, error) {
	payload := make(map[string]any, 8+len(a.profile.ExtraBodyFields)+len(req.ExtraParams))

	// 1. Low-precedence provider defaults (cannot overwrite protected canonical keys)
	for k, v := range a.profile.ExtraBodyFields {
		switch k {
		case "model", "messages", "stream", "stream_options":
			continue
		}
		payload[k] = v
	}

	payload["model"] = model
	payload["stream"] = stream

	if stream && a.profile.StreamOptionsSupported() {
		payload["stream_options"] = map[string]any{"include_usage": true}
	}

	// Adapt Messages
	messages := make([]any, len(req.Messages))
	for i, m := range req.Messages {
		messageFields := 2 // role and content
		if m.Name != "" {
			messageFields++
		}
		if m.ToolCallID != "" {
			messageFields++
		}
		if len(m.ToolCalls) > 0 {
			messageFields++
		}
		msgMap := make(map[string]any, messageFields)
		msgMap["role"] = m.Role
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

	// Adapt Reasoning Effort according to profile ReasoningMapping
	if req.ReasoningEffort != "" {
		switch a.profile.ReasoningMapping {
		case "strip":
			// Intentionally omitted for providers that reject reasoning_effort
		case "openrouter_reasoning":
			payload["reasoning"] = map[string]any{"effort": req.ReasoningEffort}
		case "dashscope_thinking":
			if strings.EqualFold(req.ReasoningEffort, "none") {
				payload["enable_thinking"] = false
			} else {
				payload["enable_thinking"] = true
			}
		case "thinking_enabled":
			if strings.EqualFold(req.ReasoningEffort, "none") {
				payload["thinking"] = map[string]any{"type": "disabled"}
			} else {
				payload["thinking"] = map[string]any{"type": "enabled"}
			}
		case "chat_template_thinking":
			enable := !strings.EqualFold(req.ReasoningEffort, "none")
			payload["chat_template_kwargs"] = map[string]any{"thinking": enable}
		default:
			payload["reasoning_effort"] = req.ReasoningEffort
		}
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

	for k, v := range req.ExtraParams {
		switch k {
		case "model", "messages", "stream", "stream_options":
			continue
		}
		if _, exists := payload[k]; exists {
			continue
		}
		payload[k] = v
	}

	// Strip explicitly unsupported parameters (protected canonical keys cannot be stripped)
	for _, k := range a.profile.StrippedParams {
		switch k {
		case "model", "messages", "stream":
			continue
		default:
			delete(payload, k)
		}
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

func (a *Adapter) resolveModelName(dep *domain.Deployment, resolved, requested string) string {
	if resolved != "" {
		return resolved
	}
	if dep != nil && dep.GlobalModel != nil && dep.GlobalModel.ModelName != "" {
		return dep.GlobalModel.ModelName
	}
	return requested
}

func (a *Adapter) unsupportedOpError(op domain.OperationType) error {
	return &domain.GatewayError{
		StatusCode: http.StatusBadRequest,
		Type:       domain.ErrorTypeInvalidRequest,
		Code:       "unsupported_capability",
		Message:    fmt.Sprintf("provider %s does not support %s", a.profile.ID, op),
		Provider:   a.profile.ID,
	}
}

func (a *Adapter) resolveEndpointBase(dep *domain.Deployment) string {
	if dep != nil && dep.Credential != nil && strings.TrimSpace(dep.Credential.BaseURL) != "" {
		return strings.TrimRight(dep.Credential.BaseURL, "/")
	}
	return strings.TrimRight(a.profile.DefaultBaseURL, "/")
}

func (a *Adapter) doJSONRequest(ctx context.Context, dep *domain.Deployment, path string, payload any) ([]byte, string, error) {
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, "", fmt.Errorf("marshal %s request: %w", path, err)
	}
	var cred *domain.ProviderCredential
	if dep != nil {
		cred = dep.Credential
	}
	targetURL := a.resolveEndpointBase(dep) + path
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, "", fmt.Errorf("create %s request: %w", path, err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	for k, v := range a.profile.DefaultHeaders {
		httpReq.Header.Set(k, v)
	}
	if err := a.profile.AuthStrategy.ApplyAuth(httpReq, cred); err != nil {
		return nil, "", &domain.GatewayError{
			StatusCode:  http.StatusUnauthorized,
			Type:        domain.ErrorTypeAuthentication,
			Code:        "auth_strategy_failed",
			Message:     err.Error(),
			AuthFailure: true,
		}
	}
	resp, err := a.httpClient.Do(httpReq)
	if err != nil {
		return nil, "", &domain.GatewayError{
			StatusCode: http.StatusBadGateway,
			Type:       domain.ErrorTypeUpstream,
			Code:       "upstream_connection_error",
			Message:    err.Error(),
			Retryable:  true,
		}
	}
	defer resp.Body.Close()
	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("read %s response: %w", path, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, "", a.parseUpstreamError(resp.StatusCode, respBytes, resp.Header)
	}
	return respBytes, resp.Header.Get("Content-Type"), nil
}

// TextCompletion implements adapter.CompletionAdapter for OpenAI-compatible /completions endpoints.
func (a *Adapter) TextCompletion(ctx context.Context, dep *domain.Deployment, req *domain.CanonicalCompletionRequest) (*domain.CanonicalCompletionResponse, error) {
	if !a.SupportsOperation(domain.OperationCompletion) {
		return nil, a.unsupportedOpError(domain.OperationCompletion)
	}
	model := a.resolveModelName(dep, req.ResolvedModel, req.Model)
	var prompt any = req.Prompt.Strings
	if len(req.Prompt.Strings) == 1 {
		prompt = req.Prompt.Strings[0]
	}
	payload := map[string]any{
		"model":  model,
		"prompt": prompt,
		"stream": false,
	}
	if req.MaxTokens != nil {
		payload["max_tokens"] = *req.MaxTokens
	}
	if req.Temperature != nil {
		payload["temperature"] = *req.Temperature
	}
	if req.TopP != nil {
		payload["top_p"] = *req.TopP
	}
	if len(req.Stop) > 0 {
		payload["stop"] = req.Stop
	}
	if req.User != "" {
		payload["user"] = req.User
	}
	respBytes, _, err := a.doJSONRequest(ctx, dep, "/completions", payload)
	if err != nil {
		return nil, err
	}
	var out domain.CanonicalCompletionResponse
	if err := json.Unmarshal(respBytes, &out); err != nil {
		return nil, fmt.Errorf("decode completion response: %w", err)
	}
	out.Provider = a.profile.ID
	if out.Model == "" {
		out.Model = model
	}
	return &out, nil
}

// Rerank implements adapter.RerankAdapter for OpenAI-compatible /rerank endpoints.
func (a *Adapter) Rerank(ctx context.Context, dep *domain.Deployment, req *domain.CanonicalRerankRequest) (*domain.CanonicalRerankResponse, error) {
	if !a.SupportsOperation(domain.OperationRerank) {
		return nil, a.unsupportedOpError(domain.OperationRerank)
	}
	model := a.resolveModelName(dep, req.ResolvedModel, req.Model)
	docs := make([]any, 0, len(req.Documents))
	for _, d := range req.Documents {
		if d.Raw != nil {
			docs = append(docs, d.Raw)
		} else {
			docs = append(docs, d.Text)
		}
	}
	payload := map[string]any{
		"model":            model,
		"query":            req.Query,
		"documents":        docs,
		"return_documents": req.ReturnDocuments,
	}
	if req.TopN != nil {
		topKey := "top_n"
		if a.profile.ID == domain.ProviderVoyage {
			topKey = "top_k"
		}
		payload[topKey] = *req.TopN
	}
	respBytes, _, err := a.doJSONRequest(ctx, dep, "/rerank", payload)
	if err != nil {
		return nil, err
	}
	var raw struct {
		ID      string `json:"id"`
		Model   string `json:"model"`
		Results []struct {
			Index          int             `json:"index"`
			RelevanceScore float64         `json:"relevance_score"`
			Document       json.RawMessage `json:"document,omitempty"`
		} `json:"results"`
		Data []struct {
			Index          int             `json:"index"`
			RelevanceScore float64         `json:"relevance_score"`
			Document       json.RawMessage `json:"document,omitempty"`
		} `json:"data,omitempty"`
		Usage *domain.RerankUsage `json:"usage,omitempty"`
	}
	if err := json.Unmarshal(respBytes, &raw); err != nil {
		return nil, fmt.Errorf("decode rerank response: %w", err)
	}
	wireResults := raw.Results
	if len(wireResults) == 0 {
		wireResults = raw.Data
	}
	results := make([]domain.RerankResultItem, len(wireResults))
	for i, r := range wireResults {
		var document map[string]any
		if len(r.Document) > 0 && string(r.Document) != "null" {
			if err := json.Unmarshal(r.Document, &document); err != nil {
				var text string
				if err := json.Unmarshal(r.Document, &text); err != nil {
					return nil, fmt.Errorf("decode rerank result document: %w", err)
				}
				document = map[string]any{"text": text}
			}
		}
		results[i] = domain.RerankResultItem{
			Index:          r.Index,
			RelevanceScore: r.RelevanceScore,
			Document:       document,
		}
	}
	out := &domain.CanonicalRerankResponse{
		ID:       raw.ID,
		Model:    model,
		Provider: a.profile.ID,
		Results:  results,
	}
	if raw.Usage != nil {
		out.Usage = *raw.Usage
	}
	return out, nil
}

// Moderate implements adapter.ModerationAdapter for OpenAI-compatible /moderations endpoints.
func (a *Adapter) Moderate(ctx context.Context, dep *domain.Deployment, req *domain.CanonicalModerationRequest) (*domain.CanonicalModerationResponse, error) {
	if !a.SupportsOperation(domain.OperationModeration) {
		return nil, a.unsupportedOpError(domain.OperationModeration)
	}
	model := a.resolveModelName(dep, req.ResolvedModel, req.Model)
	payload := map[string]any{
		"model": model,
		"input": req.Input,
	}
	respBytes, _, err := a.doJSONRequest(ctx, dep, "/moderations", payload)
	if err != nil {
		return nil, err
	}
	var out domain.CanonicalModerationResponse
	if err := json.Unmarshal(respBytes, &out); err != nil {
		return nil, fmt.Errorf("decode moderation response: %w", err)
	}
	out.Provider = a.profile.ID
	if out.Model == "" {
		out.Model = model
	}
	return &out, nil
}

// GenerateImage implements adapter.ImageAdapter for OpenAI-compatible /images/generations endpoints.
func (a *Adapter) GenerateImage(ctx context.Context, dep *domain.Deployment, req *domain.CanonicalImageRequest) (*domain.CanonicalImageResponse, error) {
	op := domain.OperationImageGeneration
	path := "/images/generations"
	if req.Operation == "edit" {
		op = domain.OperationImageEdit
		path = "/images/edits"
	} else if req.Operation == "variation" {
		op = domain.OperationImageVariation
		path = "/images/variations"
	}
	if !a.SupportsOperation(op) {
		return nil, a.unsupportedOpError(op)
	}
	model := a.resolveModelName(dep, req.ResolvedModel, req.Model)
	if op != domain.OperationImageGeneration {
		if len(req.ImageData) == 0 {
			return nil, &domain.GatewayError{
				StatusCode: http.StatusBadRequest,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "missing_image",
				Message:    "image data is required for edits and variations",
				Provider:   a.profile.ID,
			}
		}
		return a.generateMultipartImage(ctx, dep, req, model, path, op == domain.OperationImageEdit)
	}
	payload := map[string]any{
		"model":  model,
		"prompt": req.Prompt,
	}
	if req.N > 0 {
		payload["n"] = req.N
	}
	if req.Quality != "" {
		payload["quality"] = req.Quality
	}
	if req.ResponseFormat != "" {
		payload["response_format"] = req.ResponseFormat
	}
	if req.Size != "" {
		payload["size"] = req.Size
	}
	if req.Style != "" {
		payload["style"] = req.Style
	}
	if req.User != "" {
		payload["user"] = req.User
	}
	respBytes, _, err := a.doJSONRequest(ctx, dep, path, payload)
	if err != nil {
		return nil, err
	}
	var out domain.CanonicalImageResponse
	if err := json.Unmarshal(respBytes, &out); err != nil {
		return nil, fmt.Errorf("decode image response: %w", err)
	}
	out.Provider = a.profile.ID
	if out.Model == "" {
		out.Model = model
	}
	return &out, nil
}

func (a *Adapter) generateMultipartImage(ctx context.Context, dep *domain.Deployment, req *domain.CanonicalImageRequest, model, path string, includePrompt bool) (*domain.CanonicalImageResponse, error) {
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	fields := map[string]string{
		"model":           model,
		"n":               fmt.Sprint(max(req.N, 1)),
		"size":            req.Size,
		"quality":         req.Quality,
		"response_format": req.ResponseFormat,
		"style":           req.Style,
		"user":            req.User,
	}
	if includePrompt {
		fields["prompt"] = req.Prompt
	}
	for key, value := range fields {
		if value == "" {
			continue
		}
		if err := mw.WriteField(key, value); err != nil {
			return nil, fmt.Errorf("write image %s field: %w", key, err)
		}
	}
	imageName := filepath.Base(req.ImageFilename)
	if imageName == "." || imageName == "" {
		imageName = "image.png"
	}
	imagePart, err := mw.CreateFormFile("image", imageName)
	if err != nil {
		return nil, err
	}
	if _, err := imagePart.Write(req.ImageData); err != nil {
		return nil, err
	}
	if len(req.MaskData) > 0 {
		maskName := filepath.Base(req.MaskFilename)
		if maskName == "." || maskName == "" {
			maskName = "mask.png"
		}
		maskPart, err := mw.CreateFormFile("mask", maskName)
		if err != nil {
			return nil, err
		}
		if _, err := maskPart.Write(req.MaskData); err != nil {
			return nil, err
		}
	}
	if err := mw.Close(); err != nil {
		return nil, err
	}

	cred, targetURL, err := a.operationTarget(dep, path)
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, &body)
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", mw.FormDataContentType())
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
		return nil, &domain.GatewayError{
			StatusCode: http.StatusBadGateway,
			Type:       domain.ErrorTypeUpstream,
			Code:       "upstream_connection_error",
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
		return nil, a.parseUpstreamError(resp.StatusCode, respBytes, resp.Header)
	}
	var out domain.CanonicalImageResponse
	if err := json.Unmarshal(respBytes, &out); err != nil {
		return nil, fmt.Errorf("decode image response: %w", err)
	}
	out.Provider = a.profile.ID
	if out.Model == "" {
		out.Model = model
	}
	return &out, nil
}

func (a *Adapter) operationTarget(dep *domain.Deployment, path string) (*domain.ProviderCredential, string, error) {
	var cred *domain.ProviderCredential
	if dep != nil {
		cred = dep.Credential
	}
	base := a.resolveEndpointBase(dep)
	if strings.TrimSpace(base) == "" {
		return nil, "", fmt.Errorf("no base URL configured for provider %q", a.profile.ID)
	}
	return cred, strings.TrimRight(base, "/") + path, nil
}

// TranscribeAudio implements adapter.AudioAdapter for OpenAI-compatible /audio/transcriptions endpoints.
func (a *Adapter) TranscribeAudio(ctx context.Context, dep *domain.Deployment, req *domain.CanonicalAudioTranscriptionRequest) (*domain.CanonicalAudioResponse, error) {
	if !a.SupportsOperation(domain.OperationAudioSTT) {
		return nil, a.unsupportedOpError(domain.OperationAudioSTT)
	}
	model := a.resolveModelName(dep, req.ResolvedModel, req.Model)
	reader := req.FileReader
	if reader == nil && req.SpoolFilePath != "" {
		f, err := os.Open(req.SpoolFilePath)
		if err != nil {
			return nil, fmt.Errorf("open audio spool file: %w", err)
		}
		defer f.Close()
		reader = f
	}
	if reader == nil {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "missing_audio_file",
			Message:    "audio file reader is required",
			Provider:   a.profile.ID,
		}
	}
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("model", model)
	if req.Language != "" {
		_ = mw.WriteField("language", req.Language)
	}
	if req.Prompt != "" {
		_ = mw.WriteField("prompt", req.Prompt)
	}
	if req.ResponseFormat != "" {
		_ = mw.WriteField("response_format", req.ResponseFormat)
	}
	filename := req.FileName
	if filename == "" {
		filename = "audio.mp3"
	}
	fw, err := mw.CreateFormFile("file", filename)
	if err != nil {
		return nil, err
	}
	if _, err := io.Copy(fw, reader); err != nil {
		return nil, err
	}
	if err := mw.Close(); err != nil {
		return nil, err
	}
	var cred *domain.ProviderCredential
	if dep != nil {
		cred = dep.Credential
	}
	targetURL := a.resolveEndpointBase(dep) + "/audio/transcriptions"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, &buf)
	if err != nil {
		return nil, err
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
	httpReq.Header.Set("Content-Type", mw.FormDataContentType())
	resp, err := a.httpClient.Do(httpReq)
	if err != nil {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusBadGateway,
			Type:       domain.ErrorTypeUpstream,
			Code:       "upstream_connection_error",
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
		return nil, a.parseUpstreamError(resp.StatusCode, respBytes, resp.Header)
	}
	var out domain.CanonicalAudioResponse
	if err := json.Unmarshal(respBytes, &out); err != nil {
		return nil, fmt.Errorf("decode audio transcription response: %w", err)
	}
	return &out, nil
}

// GenerateSpeech implements adapter.AudioAdapter for OpenAI-compatible /audio/speech endpoints.
func (a *Adapter) GenerateSpeech(ctx context.Context, dep *domain.Deployment, req *domain.CanonicalAudioSpeechRequest) (io.ReadCloser, string, error) {
	if !a.SupportsOperation(domain.OperationAudioTTS) {
		return nil, "", a.unsupportedOpError(domain.OperationAudioTTS)
	}
	model := a.resolveModelName(dep, req.ResolvedModel, req.Model)
	payload := map[string]any{
		"model": model,
		"input": req.Input,
		"voice": req.Voice,
	}
	if req.ResponseFormat != "" {
		payload["response_format"] = req.ResponseFormat
	}
	if req.Speed > 0 {
		payload["speed"] = req.Speed
	}
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, "", err
	}
	var cred *domain.ProviderCredential
	if dep != nil {
		cred = dep.Credential
	}
	targetURL := a.resolveEndpointBase(dep) + "/audio/speech"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, "", err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	for k, v := range a.profile.DefaultHeaders {
		httpReq.Header.Set(k, v)
	}
	if err := a.profile.AuthStrategy.ApplyAuth(httpReq, cred); err != nil {
		return nil, "", &domain.GatewayError{
			StatusCode:  http.StatusUnauthorized,
			Type:        domain.ErrorTypeAuthentication,
			Code:        "auth_strategy_failed",
			Message:     err.Error(),
			AuthFailure: true,
		}
	}
	resp, err := a.httpClient.Do(httpReq)
	if err != nil {
		return nil, "", &domain.GatewayError{
			StatusCode: http.StatusBadGateway,
			Type:       domain.ErrorTypeUpstream,
			Code:       "upstream_connection_error",
			Message:    err.Error(),
			Retryable:  true,
		}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		defer resp.Body.Close()
		respBytes, _ := io.ReadAll(resp.Body)
		return nil, "", a.parseUpstreamError(resp.StatusCode, respBytes, resp.Header)
	}
	ct := resp.Header.Get("Content-Type")
	if ct == "" {
		ct = "audio/mpeg"
	}
	return resp.Body, ct, nil
}
