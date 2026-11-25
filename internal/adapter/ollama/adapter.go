package ollama

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/adapter"
	"github.com/goroute-ai/ai-gateway-go/internal/adapter/sse"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/observability"
	"github.com/goroute-ai/ai-gateway-go/internal/openapi/providers"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
)

const defaultBaseURL = "http://127.0.0.1:11434"

var (
	_ adapter.ProviderAdapter            = (*Adapter)(nil)
	_ adapter.CompletionAdapter          = (*Adapter)(nil)
	_ adapter.StreamingCompletionAdapter = (*Adapter)(nil)
	_ adapter.OperationSupportChecker    = (*Adapter)(nil)
	_ adapter.PrefillSupportChecker      = (*Adapter)(nil)
)

// Adapter implements adapter.ProviderAdapter, CompletionAdapter, StreamingCompletionAdapter,
// OperationSupportChecker, and PrefillSupportChecker for Ollama local and cloud servers.
type Adapter struct {
	client     *http.Client
	ssrfPolicy *network.Policy
}

// NewAdapter creates an Ollama Adapter using client, or an SSRF-safe pooled client when nil.
func NewAdapter(client *http.Client) *Adapter {
	if client == nil {
		client = adapter.NewPooledHTTPClient(120 * time.Second)
	}
	return &Adapter{client: client}
}

// SetSSRFPolicy configures the outbound network policy used to validate BaseURL overrides and default loopback targets.
func (a *Adapter) SetSSRFPolicy(policy *network.Policy) {
	a.ssrfPolicy = policy
}

// Provider returns domain.ProviderOllama.
func (a *Adapter) Provider() domain.ProviderType {
	return domain.ProviderOllama
}

// SupportsAssistantPrefill reports that Ollama chat completions support trailing assistant messages.
func (a *Adapter) SupportsAssistantPrefill() bool {
	return true
}

// SupportsOperation reports Ollama's supported OpenAPI endpoints.
func (a *Adapter) SupportsOperation(op domain.OperationType) bool {
	switch op {
	case domain.OperationChat,
		domain.OperationCompletion,
		domain.OperationEmbedding:
		return true
	default:
		return false
	}
}

// --- Endpoint, Auth & Error Helpers ---

func (a *Adapter) resolveBaseURL(cred *domain.ProviderCredential) (string, error) {
	rawBase := ""
	if cred != nil {
		rawBase = strings.TrimSpace(cred.BaseURL)
	}
	if rawBase == "" {
		base, err := adapter.ValidateAndResolveBaseURL(defaultBaseURL, defaultBaseURL, a.ssrfPolicy)
		if err != nil {
			return "", &domain.GatewayError{
				StatusCode: http.StatusBadRequest,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "invalid_base_url",
				Message:    fmt.Sprintf("%v (for local Ollama, enable security.network.outbound_ssrf.allow_loopback_http: true or configure an HTTPS base_url)", err),
				Provider:   domain.ProviderOllama,
			}
		}
		return base, nil
	}
	return adapter.ResolveCredentialBaseURL(cred, defaultBaseURL, a.ssrfPolicy, domain.ProviderOllama)
}

func (a *Adapter) resolveV1Endpoint(cred *domain.ProviderCredential, suffix string) (string, error) {
	base, err := a.resolveBaseURL(cred)
	if err != nil {
		return "", err
	}
	base = strings.TrimRight(base, "/")
	if strings.HasSuffix(base, "/v1") {
		return base + suffix, nil
	}
	return base + "/v1" + suffix, nil
}

func (a *Adapter) resolveRootEndpoint(cred *domain.ProviderCredential, suffix string) (string, error) {
	base, err := a.resolveBaseURL(cred)
	if err != nil {
		return "", err
	}
	base = strings.TrimRight(base, "/")
	base = strings.TrimSuffix(base, "/v1")
	return base + suffix, nil
}

func resolveModel(dep *domain.Deployment, resolved, requested string) string {
	if resolved != "" {
		return resolved
	}
	if dep != nil && dep.GlobalModel != nil && dep.GlobalModel.ModelName != "" {
		return dep.GlobalModel.ModelName
	}
	return requested
}

func applyOptionalAuthAndHeaders(req *http.Request, cred *domain.ProviderCredential) error {
	observability.InjectTraceHeaders(req.Context(), req)
	if cred == nil {
		return nil
	}
	if err := (&adapter.BearerAuthStrategy{}).ApplyAuth(req, cred); err != nil {
		return &domain.GatewayError{
			StatusCode:  http.StatusUnauthorized,
			Type:        domain.ErrorTypeAuthentication,
			Code:        "auth_strategy_failed",
			Message:     err.Error(),
			Provider:    domain.ProviderOllama,
			AuthFailure: true,
		}
	}
	return nil
}

func derefStr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func parseOllamaUpstreamError(statusCode int, body []byte, headers http.Header) error {
	var msg string
	var codeStr string

	var openAIEnv struct {
		Error struct {
			Message string `json:"message"`
			Type    string `json:"type"`
			Code    any    `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(body, &openAIEnv); err == nil && openAIEnv.Error.Message != "" {
		msg = openAIEnv.Error.Message
		if s, ok := openAIEnv.Error.Code.(string); ok && s != "" {
			codeStr = s
		}
	}
	if msg == "" {
		var nativeEnv struct {
			Error string `json:"error"`
		}
		if err := json.Unmarshal(body, &nativeEnv); err == nil && nativeEnv.Error != "" {
			msg = nativeEnv.Error
		}
	}
	if msg == "" {
		msg = strings.TrimSpace(string(body))
	}

	gwErr := domain.ClassifyUpstreamStatus(domain.ProviderOllama, statusCode, msg, adapter.ParseRetryAfter(headers))
	if codeStr != "" {
		gwErr.Code = codeStr
	}
	return gwErr
}

// --- Chat Completions ---

func toOllamaChatRequest(model string, req *domain.CanonicalChatRequest, stream bool) providers.OllamaChatCompletionRequest {
	msgs := make([]providers.OllamaMessage, 0, len(req.Messages))
	for _, m := range req.Messages {
		om := providers.OllamaMessage{
			Role: m.Role,
		}
		if len(m.Parts) > 0 {
			om.Content = m.Parts
		} else {
			om.Content = m.Content
		}
		if m.Name != "" {
			name := m.Name
			om.Name = &name
		}
		if m.ToolCallID != "" {
			id := m.ToolCallID
			om.ToolCallId = &id
		}
		if len(m.ToolCalls) > 0 {
			tcs := make([]providers.OllamaToolCall, 0, len(m.ToolCalls))
			for _, tc := range m.ToolCalls {
				id := tc.ID
				typ := tc.Type
				fnName := tc.Function.Name
				fnArgs := tc.Function.Arguments
				tcs = append(tcs, providers.OllamaToolCall{
					Index: tc.Index,
					Id:    &id,
					Type:  &typ,
					Function: providers.OllamaFunctionCall{
						Name:      &fnName,
						Arguments: &fnArgs,
					},
				})
			}
			om.ToolCalls = &tcs
		}
		msgs = append(msgs, om)
	}

	out := providers.OllamaChatCompletionRequest{
		Model:       model,
		Messages:    msgs,
		Temperature: req.Temperature,
		TopP:        req.TopP,
		MaxTokens:   req.MaxTokens,
		ToolChoice:  req.ToolChoice,
	}
	if stream {
		s := true
		out.Stream = &s
		if req.StreamOptions == nil || req.StreamOptions.IncludeUsage {
			out.StreamOptions = &providers.OllamaStreamOptions{IncludeUsage: true}
		}
	}
	if len(req.Stop) > 0 {
		stopCopy := append([]string(nil), req.Stop...)
		out.Stop = &stopCopy
	}
	if len(req.Tools) > 0 {
		tools := make([]providers.OllamaTool, 0, len(req.Tools))
		for _, t := range req.Tools {
			ot := providers.OllamaTool{
				Type: t.Type,
				Function: providers.OllamaFunction{
					Name: t.Function.Name,
				},
			}
			if t.Function.Description != "" {
				desc := t.Function.Description
				ot.Function.Description = &desc
			}
			if t.Function.Parameters != nil {
				params := t.Function.Parameters
				ot.Function.Parameters = &params
			}
			if t.Function.Strict {
				strict := true
				ot.Function.Strict = &strict
			}
			tools = append(tools, ot)
		}
		out.Tools = &tools
	}
	if req.ResponseFormat != nil {
		rf := &providers.OllamaResponseFormat{
			Type: req.ResponseFormat.Type,
		}
		if req.ResponseFormat.JSONSchema != nil {
			js := req.ResponseFormat.JSONSchema
			rf.JsonSchema = &js
		}
		out.ResponseFormat = rf
	}
	if req.ReasoningEffort != "" {
		effort := req.ReasoningEffort
		out.ReasoningEffort = &effort
	}
	if req.User != "" {
		u := req.User
		out.User = &u
	}
	return out
}

func marshalOllamaChatPayload(base providers.OllamaChatCompletionRequest, extra map[string]any) ([]byte, error) {
	raw, err := json.Marshal(base)
	if err != nil {
		return nil, fmt.Errorf("marshal ollama request: %w", err)
	}
	if len(extra) == 0 {
		return raw, nil
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, fmt.Errorf("decode ollama payload map: %w", err)
	}
	for k, v := range extra {
		switch k {
		case "model", "messages", "stream", "stream_options", "keep_alive":
			continue
		}
		if _, exists := payload[k]; !exists {
			payload[k] = v
		}
	}
	return json.Marshal(payload)
}

func extractTokenUsage(u providers.OllamaUsage) domain.TokenUsage {
	usage := domain.TokenUsage{
		PromptTokens:     u.PromptTokens,
		CompletionTokens: u.CompletionTokens,
		TotalTokens:      u.TotalTokens,
	}
	if u.PromptTokensDetails != nil && u.PromptTokensDetails.CachedTokens != nil {
		usage.CachedPromptTokens = *u.PromptTokensDetails.CachedTokens
	}
	if u.CompletionTokensDetails != nil && u.CompletionTokensDetails.ReasoningTokens != nil {
		usage.ReasoningTokens = *u.CompletionTokensDetails.ReasoningTokens
	}
	return usage
}

// ChatCompletion executes a non-streaming Ollama chat completion via POST /v1/chat/completions.
func (a *Adapter) ChatCompletion(ctx context.Context, dep *domain.Deployment, req *domain.CanonicalChatRequest) (*domain.CanonicalChatResponse, error) {
	if req == nil {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_request",
			Message:    "chat request is required",
			Provider:   domain.ProviderOllama,
		}
	}
	var cred *domain.ProviderCredential
	if dep != nil {
		cred = dep.Credential
	}
	model := resolveModel(dep, req.ResolvedModel, req.Model)
	bodyBytes, err := marshalOllamaChatPayload(toOllamaChatRequest(model, req, false), req.ExtraParams)
	if err != nil {
		return nil, err
	}
	endpoint, err := a.resolveV1Endpoint(cred, "/chat/completions")
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("create ollama chat request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if err := applyOptionalAuthAndHeaders(httpReq, cred); err != nil {
		return nil, err
	}
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

	respBytes, err := adapter.ReadBoundedBody(resp.Body, adapter.DefaultMaxResponseBytes, domain.ProviderOllama)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, parseOllamaUpstreamError(resp.StatusCode, respBytes, resp.Header)
	}

	var ollamaResp providers.OllamaChatCompletionResponse
	if err := json.Unmarshal(respBytes, &ollamaResp); err != nil {
		return nil, fmt.Errorf("decode ollama chat response: %w", err)
	}

	choices := make([]domain.CanonicalChoice, 0, len(ollamaResp.Choices))
	for _, c := range ollamaResp.Choices {
		contentStr, _ := c.Message.Content.(string)
		reasoning := derefStr(c.Message.ReasoningContent)
		if reasoning == "" {
			reasoning = derefStr(c.Message.Reasoning)
		}
		var tcs []domain.CanonicalToolCall
		if c.Message.ToolCalls != nil {
			tcs = make([]domain.CanonicalToolCall, 0, len(*c.Message.ToolCalls))
			for _, tc := range *c.Message.ToolCalls {
				tcs = append(tcs, domain.CanonicalToolCall{
					Index: tc.Index,
					ID:    derefStr(tc.Id),
					Type:  derefStr(tc.Type),
					Function: domain.CanonicalFunctionCall{
						Name:      derefStr(tc.Function.Name),
						Arguments: derefStr(tc.Function.Arguments),
					},
				})
			}
		}
		choices = append(choices, domain.CanonicalChoice{
			Index: c.Index,
			Message: domain.CanonicalMessage{
				Role:             c.Message.Role,
				Content:          contentStr,
				Name:             derefStr(c.Message.Name),
				ToolCallID:       derefStr(c.Message.ToolCallId),
				ToolCalls:        tcs,
				ReasoningContent: reasoning,
			},
			FinishReason: c.FinishReason,
		})
	}

	return &domain.CanonicalChatResponse{
		ID:                ollamaResp.Id,
		Object:            "chat.completion",
		Created:           ollamaResp.Created,
		Model:             ollamaResp.Model,
		Provider:          domain.ProviderOllama,
		Choices:           choices,
		Usage:             extractTokenUsage(ollamaResp.Usage),
		SystemFingerprint: derefStr(ollamaResp.SystemFingerprint),
	}, nil
}

// StreamChatCompletion executes a streaming Ollama chat completion via POST /v1/chat/completions.
func (a *Adapter) StreamChatCompletion(ctx context.Context, dep *domain.Deployment, req *domain.CanonicalChatRequest, onChunk adapter.StreamChunkHandler) (*domain.TokenUsage, error) {
	ctx = adapter.StreamingContext(ctx)
	if req == nil {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_request",
			Message:    "chat request is required",
			Provider:   domain.ProviderOllama,
		}
	}
	var cred *domain.ProviderCredential
	if dep != nil {
		cred = dep.Credential
	}
	model := resolveModel(dep, req.ResolvedModel, req.Model)
	bodyBytes, err := marshalOllamaChatPayload(toOllamaChatRequest(model, req, true), req.ExtraParams)
	if err != nil {
		return nil, err
	}
	endpoint, err := a.resolveV1Endpoint(cred, "/chat/completions")
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("create ollama stream request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "text/event-stream")
	if err := applyOptionalAuthAndHeaders(httpReq, cred); err != nil {
		return nil, err
	}
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

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		errBody, readErr := adapter.ReadBoundedBody(resp.Body, adapter.DefaultMaxErrorBytes, domain.ProviderOllama)
		if readErr != nil {
			return nil, readErr
		}
		return nil, parseOllamaUpstreamError(resp.StatusCode, errBody, resp.Header)
	}

	finalUsage := &domain.TokenUsage{}
	err = sse.ReadEvents(resp.Body, func(ev sse.Event) error {
		if ev.Data == "" || ev.Data == "[DONE]" {
			return nil
		}
		var raw providers.OllamaStreamChunk
		if err := json.Unmarshal([]byte(ev.Data), &raw); err != nil {
			return nil
		}
		chunk := domain.CanonicalStreamChunk{
			ID:                raw.Id,
			Object:            "chat.completion.chunk",
			Created:           raw.Created,
			Model:             raw.Model,
			SystemFingerprint: derefStr(raw.SystemFingerprint),
			Choices:           make([]domain.CanonicalStreamChoice, 0, len(raw.Choices)),
		}
		for _, c := range raw.Choices {
			reasoning := derefStr(c.Delta.ReasoningContent)
			if reasoning == "" {
				reasoning = derefStr(c.Delta.Reasoning)
			}
			var tcs []domain.CanonicalToolCall
			if c.Delta.ToolCalls != nil {
				tcs = make([]domain.CanonicalToolCall, 0, len(*c.Delta.ToolCalls))
				for _, tc := range *c.Delta.ToolCalls {
					tcs = append(tcs, domain.CanonicalToolCall{
						Index: tc.Index,
						ID:    derefStr(tc.Id),
						Type:  derefStr(tc.Type),
						Function: domain.CanonicalFunctionCall{
							Name:      derefStr(tc.Function.Name),
							Arguments: derefStr(tc.Function.Arguments),
						},
					})
				}
			}
			chunk.Choices = append(chunk.Choices, domain.CanonicalStreamChoice{
				Index: c.Index,
				Delta: domain.CanonicalStreamDelta{
					Role:             derefStr(c.Delta.Role),
					Content:          derefStr(c.Delta.Content),
					ReasoningContent: reasoning,
					ToolCalls:        tcs,
				},
				FinishReason: c.FinishReason,
			})
		}
		if raw.Usage != nil {
			u := extractTokenUsage(*raw.Usage)
			chunk.Usage = &u
			*finalUsage = u
		}
		return onChunk(&chunk)
	})
	return finalUsage, err
}

// --- Embeddings ---

// Embeddings executes vector embedding generation via POST /v1/embeddings.
func (a *Adapter) Embeddings(ctx context.Context, dep *domain.Deployment, req *domain.CanonicalEmbeddingRequest) (*domain.CanonicalEmbeddingResponse, error) {
	if req == nil {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_request",
			Message:    "embedding request is required",
			Provider:   domain.ProviderOllama,
		}
	}
	var cred *domain.ProviderCredential
	if dep != nil {
		cred = dep.Credential
	}
	model := resolveModel(dep, req.ResolvedModel, req.Model)

	var input any = req.Input
	if len(req.Input) == 1 {
		input = req.Input[0]
	}
	payload := providers.OllamaEmbeddingRequest{
		Model:      model,
		Input:      input,
		Dimensions: req.Dimensions,
	}
	if req.EncodingFormat != "" {
		ef := req.EncodingFormat
		payload.EncodingFormat = &ef
	}
	if req.User != "" {
		u := req.User
		payload.User = &u
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal ollama embedding request: %w", err)
	}
	endpoint, err := a.resolveV1Endpoint(cred, "/embeddings")
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("create ollama embedding request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if err := applyOptionalAuthAndHeaders(httpReq, cred); err != nil {
		return nil, err
	}
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

	respBytes, err := adapter.ReadBoundedBody(resp.Body, adapter.DefaultMaxResponseBytes, domain.ProviderOllama)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, parseOllamaUpstreamError(resp.StatusCode, respBytes, resp.Header)
	}

	var ollamaResp providers.OllamaEmbeddingResponse
	if err := json.Unmarshal(respBytes, &ollamaResp); err != nil {
		return nil, fmt.Errorf("decode ollama embedding response: %w", err)
	}
	data := make([]domain.EmbeddingData, 0, len(ollamaResp.Data))
	for _, d := range ollamaResp.Data {
		data = append(data, domain.EmbeddingData{
			Object:    "embedding",
			Index:     d.Index,
			Embedding: d.Embedding,
		})
	}
	return &domain.CanonicalEmbeddingResponse{
		Object:   "list",
		Data:     data,
		Model:    ollamaResp.Model,
		Provider: domain.ProviderOllama,
		Usage: domain.TokenUsage{
			PromptTokens: ollamaResp.Usage.PromptTokens,
			TotalTokens:  ollamaResp.Usage.TotalTokens,
		},
	}, nil
}

// --- Legacy Text Completions ---

// TextCompletion executes a legacy text completion via POST /v1/completions.
func (a *Adapter) TextCompletion(ctx context.Context, dep *domain.Deployment, req *domain.CanonicalCompletionRequest) (*domain.CanonicalCompletionResponse, error) {
	if req == nil {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_request",
			Message:    "completion request is required",
			Provider:   domain.ProviderOllama,
		}
	}
	var cred *domain.ProviderCredential
	if dep != nil {
		cred = dep.Credential
	}
	model := resolveModel(dep, req.ResolvedModel, req.Model)

	payload := providers.OllamaCompletionRequest{
		Model:       model,
		MaxTokens:   req.MaxTokens,
		Temperature: req.Temperature,
		TopP:        req.TopP,
	}
	if len(req.Prompt.Strings) == 1 {
		payload.Prompt = req.Prompt.Strings[0]
	} else if len(req.Prompt.Strings) > 1 {
		payload.Prompt = req.Prompt.Strings
	}
	if len(req.Stop) > 0 {
		stopCopy := append([]string(nil), req.Stop...)
		payload.Stop = &stopCopy
	}
	if req.User != "" {
		u := req.User
		payload.User = &u
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal ollama completion request: %w", err)
	}
	endpoint, err := a.resolveV1Endpoint(cred, "/completions")
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("create ollama completion request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if err := applyOptionalAuthAndHeaders(httpReq, cred); err != nil {
		return nil, err
	}
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

	respBytes, err := adapter.ReadBoundedBody(resp.Body, adapter.DefaultMaxResponseBytes, domain.ProviderOllama)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, parseOllamaUpstreamError(resp.StatusCode, respBytes, resp.Header)
	}

	var ollamaResp providers.OllamaCompletionResponse
	if err := json.Unmarshal(respBytes, &ollamaResp); err != nil {
		return nil, fmt.Errorf("decode ollama completion response: %w", err)
	}
	choices := make([]domain.CanonicalCompletionChoice, 0, len(ollamaResp.Choices))
	for _, c := range ollamaResp.Choices {
		choices = append(choices, domain.CanonicalCompletionChoice{
			Index:        c.Index,
			Text:         c.Text,
			FinishReason: c.FinishReason,
		})
	}
	return &domain.CanonicalCompletionResponse{
		ID:       ollamaResp.Id,
		Model:    ollamaResp.Model,
		Provider: domain.ProviderOllama,
		Choices:  choices,
		Usage:    extractTokenUsage(ollamaResp.Usage),
	}, nil
}

// StreamTextCompletion executes a streaming legacy text completion via POST /v1/completions.
func (a *Adapter) StreamTextCompletion(ctx context.Context, dep *domain.Deployment, req *domain.CanonicalCompletionRequest) (<-chan domain.CanonicalStreamChunk, error) {
	if req == nil {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_request",
			Message:    "completion request is required",
			Provider:   domain.ProviderOllama,
		}
	}
	ctx = adapter.StreamingContext(ctx)
	var cred *domain.ProviderCredential
	if dep != nil {
		cred = dep.Credential
	}
	model := resolveModel(dep, req.ResolvedModel, req.Model)

	streamTrue := true
	payload := providers.OllamaCompletionRequest{
		Model:         model,
		MaxTokens:     req.MaxTokens,
		Temperature:   req.Temperature,
		TopP:          req.TopP,
		Stream:        &streamTrue,
		StreamOptions: &providers.OllamaStreamOptions{IncludeUsage: true},
	}
	if len(req.Prompt.Strings) == 1 {
		payload.Prompt = req.Prompt.Strings[0]
	} else if len(req.Prompt.Strings) > 1 {
		payload.Prompt = req.Prompt.Strings
	}
	if len(req.Stop) > 0 {
		stopCopy := append([]string(nil), req.Stop...)
		payload.Stop = &stopCopy
	}
	if req.User != "" {
		u := req.User
		payload.User = &u
	}

	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal ollama stream completion request: %w", err)
	}
	endpoint, err := a.resolveV1Endpoint(cred, "/completions")
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("create ollama stream completion request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "text/event-stream")
	if err := applyOptionalAuthAndHeaders(httpReq, cred); err != nil {
		return nil, err
	}
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
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		errBody, readErr := adapter.ReadBoundedBody(resp.Body, adapter.DefaultMaxErrorBytes, domain.ProviderOllama)
		resp.Body.Close()
		if readErr != nil {
			return nil, readErr
		}
		return nil, parseOllamaUpstreamError(resp.StatusCode, errBody, resp.Header)
	}

	ch := make(chan domain.CanonicalStreamChunk, 16)
	go func() {
		defer resp.Body.Close()
		defer close(ch)
		_ = sse.ReadEvents(resp.Body, func(ev sse.Event) error {
			if ev.Data == "" || ev.Data == "[DONE]" {
				return nil
			}
			var raw providers.OllamaCompletionStreamChunk
			if err := json.Unmarshal([]byte(ev.Data), &raw); err != nil {
				return nil
			}
			choices := make([]domain.CanonicalStreamChoice, 0, len(raw.Choices))
			for _, c := range raw.Choices {
				choices = append(choices, domain.CanonicalStreamChoice{
					Index: c.Index,
					Delta: domain.CanonicalStreamDelta{
						Content: c.Text,
					},
					FinishReason: c.FinishReason,
				})
			}
			obj := raw.Object
			if obj == "" {
				obj = "text_completion"
			}
			chunk := domain.CanonicalStreamChunk{
				ID:                raw.Id,
				Object:            obj,
				Created:           raw.Created,
				Model:             raw.Model,
				SystemFingerprint: derefStr(raw.SystemFingerprint),
				Choices:           choices,
			}
			if raw.Usage != nil {
				u := extractTokenUsage(*raw.Usage)
				chunk.Usage = &u
			}
			select {
			case ch <- chunk:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		})
	}()

	return ch, nil
}

// --- Model Discovery ---

// ListModels discovers installed Ollama models via GET /api/tags, falling back to GET /v1/models on 404.
func (a *Adapter) ListModels(ctx context.Context, cred *domain.ProviderCredential) ([]domain.DiscoveredModel, error) {
	tagsEndpoint, err := a.resolveRootEndpoint(cred, "/api/tags")
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, tagsEndpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("create ollama tags request: %w", err)
	}
	if err := applyOptionalAuthAndHeaders(httpReq, cred); err != nil {
		return nil, err
	}
	resp, err := a.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("ollama list tags: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return a.listModelsV1(ctx, cred)
	}

	bodyBytes, err := adapter.ReadBoundedBody(resp.Body, adapter.DefaultMaxResponseBytes, domain.ProviderOllama)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, parseOllamaUpstreamError(resp.StatusCode, bodyBytes, resp.Header)
	}

	var tagsResp providers.OllamaTagsResponse
	if err := json.Unmarshal(bodyBytes, &tagsResp); err != nil {
		return nil, fmt.Errorf("decode ollama tags response: %w", err)
	}

	out := make([]domain.DiscoveredModel, 0, len(tagsResp.Models))
	for _, m := range tagsResp.Models {
		name := m.Name
		if name == "" {
			name = derefStr(m.Model)
		}
		if name == "" {
			continue
		}
		var createdAt int64
		if m.ModifiedAt != nil {
			if ts, parseErr := time.Parse(time.RFC3339Nano, *m.ModifiedAt); parseErr == nil {
				createdAt = ts.Unix()
			}
		}
		out = append(out, domain.DiscoveredModel{
			Provider:    domain.ProviderOllama,
			ModelName:   name,
			DisplayName: name,
			CreatedAt:   createdAt,
		})
	}
	return out, nil
}

func (a *Adapter) listModelsV1(ctx context.Context, cred *domain.ProviderCredential) ([]domain.DiscoveredModel, error) {
	endpoint, err := a.resolveV1Endpoint(cred, "/models")
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("create ollama models request: %w", err)
	}
	if err := applyOptionalAuthAndHeaders(httpReq, cred); err != nil {
		return nil, err
	}
	resp, err := a.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("ollama list models: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := adapter.ReadBoundedBody(resp.Body, adapter.DefaultMaxResponseBytes, domain.ProviderOllama)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, parseOllamaUpstreamError(resp.StatusCode, bodyBytes, resp.Header)
	}

	var listResp providers.OllamaModelsResponse
	if err := json.Unmarshal(bodyBytes, &listResp); err != nil {
		return nil, fmt.Errorf("decode ollama models response: %w", err)
	}
	out := make([]domain.DiscoveredModel, 0, len(listResp.Data))
	for _, m := range listResp.Data {
		var created int64
		if m.Created != nil {
			created = *m.Created
		}
		out = append(out, domain.DiscoveredModel{
			Provider:    domain.ProviderOllama,
			ModelName:   m.Id,
			DisplayName: m.Id,
			CreatedAt:   created,
		})
	}
	return out, nil
}
