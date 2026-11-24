package groq

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/adapter"
	"github.com/goroute-ai/ai-gateway-go/internal/adapter/sse"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/observability"
	"github.com/goroute-ai/ai-gateway-go/internal/openapi/providers"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
)

const defaultBaseURL = "https://api.groq.com/openai/v1"

// Adapter implements adapter.ProviderAdapter, CompletionAdapter, StreamingCompletionAdapter,
// AudioAdapter, OperationSupportChecker, and PrefillSupportChecker for Groq Cloud.
type Adapter struct {
	client     *http.Client
	ssrfPolicy *network.Policy
}

// NewAdapter creates a Groq Adapter using client, or an SSRF-safe pooled client when nil.
func NewAdapter(client *http.Client) *Adapter {
	if client == nil {
		client = adapter.NewPooledHTTPClient(120 * time.Second)
	}
	return &Adapter{client: client}
}

// SetSSRFPolicy configures the outbound network policy used to validate BaseURL overrides.
func (a *Adapter) SetSSRFPolicy(policy *network.Policy) {
	a.ssrfPolicy = policy
}

// Provider returns domain.ProviderGroq.
func (a *Adapter) Provider() domain.ProviderType {
	return domain.ProviderGroq
}

// SupportsAssistantPrefill reports that Groq supports trailing assistant messages.
func (a *Adapter) SupportsAssistantPrefill() bool {
	return true
}

// SupportsOperation reports Groq's supported OpenAPI endpoints.
func (a *Adapter) SupportsOperation(op domain.OperationType) bool {
	switch op {
	case domain.OperationChat,
		domain.OperationCompletion,
		domain.OperationAudioSTT,
		domain.OperationAudioTTS:
		return true
	default:
		return false
	}
}

func (a *Adapter) resolveEndpoint(cred *domain.ProviderCredential, suffix string) (string, error) {
	base, err := adapter.ResolveCredentialBaseURL(cred, defaultBaseURL, a.ssrfPolicy, domain.ProviderGroq)
	if err != nil {
		return "", err
	}
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

func applyBearerAuth(req *http.Request, dep *domain.Deployment) (*domain.ProviderCredential, error) {
	var cred *domain.ProviderCredential
	if dep != nil {
		cred = dep.Credential
	}
	if cred == nil {
		return nil, &domain.GatewayError{
			StatusCode:  http.StatusUnauthorized,
			Type:        domain.ErrorTypeAuthentication,
			Code:        "missing_credential",
			Message:     "missing provider credential",
			Provider:    domain.ProviderGroq,
			AuthFailure: true,
		}
	}
	if err := (&adapter.BearerAuthStrategy{}).ApplyAuth(req, cred); err != nil {
		return nil, &domain.GatewayError{
			StatusCode:  http.StatusUnauthorized,
			Type:        domain.ErrorTypeAuthentication,
			Code:        "auth_strategy_failed",
			Message:     err.Error(),
			Provider:    domain.ProviderGroq,
			AuthFailure: true,
		}
	}
	observability.InjectTraceHeaders(req.Context(), req)
	return cred, nil
}

func isDistillModel(model string) bool {
	return strings.Contains(strings.ToLower(model), "distill")
}

func validateAndShapeChatRequest(model string, req *domain.CanonicalChatRequest) (*domain.CanonicalChatRequest, error) {
	if req == nil {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_request",
			Message:    "chat request is required",
			Provider:   domain.ProviderGroq,
		}
	}
	if isDistillModel(model) && len(req.Tools) > 0 {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "capability_unsupported",
			Message:    fmt.Sprintf("groq model %q does not support tool calling", model),
			Provider:   domain.ProviderGroq,
		}
	}
	shaped := *req
	if isDistillModel(model) && shaped.Temperature != nil {
		if shaped.GoRouteExtensions != nil && shaped.GoRouteExtensions.DropUnsupportedParams != nil && *shaped.GoRouteExtensions.DropUnsupportedParams {
			shaped.Temperature = nil
		} else {
			return nil, &domain.GatewayError{
				StatusCode: http.StatusBadRequest,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "unsupported_parameter",
				Message:    fmt.Sprintf("groq model %q rejects custom temperature parameter", model),
				Provider:   domain.ProviderGroq,
			}
		}
	}
	return &shaped, nil
}

func toGroqChatRequest(model string, req *domain.CanonicalChatRequest, stream bool) providers.GroqChatCompletionRequest {
	msgs := make([]providers.GroqMessage, 0, len(req.Messages))
	for _, m := range req.Messages {
		gm := providers.GroqMessage{
			Role: m.Role,
		}
		if len(m.Parts) > 0 {
			gm.Content = m.Parts
		} else {
			gm.Content = m.Content
		}
		if m.Name != "" {
			name := m.Name
			gm.Name = &name
		}
		if m.ToolCallID != "" {
			id := m.ToolCallID
			gm.ToolCallId = &id
		}
		if len(m.ToolCalls) > 0 {
			tcs := make([]providers.GroqToolCall, 0, len(m.ToolCalls))
			for _, tc := range m.ToolCalls {
				id := tc.ID
				typ := tc.Type
				fnName := tc.Function.Name
				fnArgs := tc.Function.Arguments
				tcs = append(tcs, providers.GroqToolCall{
					Index: tc.Index,
					Id:    &id,
					Type:  &typ,
					Function: providers.GroqFunctionCall{
						Name:      &fnName,
						Arguments: &fnArgs,
					},
				})
			}
			gm.ToolCalls = &tcs
		}
		msgs = append(msgs, gm)
	}

	out := providers.GroqChatCompletionRequest{
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
			out.StreamOptions = &providers.GroqStreamOptions{IncludeUsage: true}
		}
	}
	if len(req.Stop) > 0 {
		stopCopy := append([]string(nil), req.Stop...)
		out.Stop = &stopCopy
	}
	if len(req.Tools) > 0 {
		tools := make([]providers.GroqTool, 0, len(req.Tools))
		for _, t := range req.Tools {
			gt := providers.GroqTool{
				Type: t.Type,
				Function: providers.GroqFunction{
					Name: t.Function.Name,
				},
			}
			if t.Function.Description != "" {
				desc := t.Function.Description
				gt.Function.Description = &desc
			}
			if t.Function.Parameters != nil {
				params := t.Function.Parameters
				gt.Function.Parameters = &params
			}
			if t.Function.Strict {
				strict := true
				gt.Function.Strict = &strict
			}
			tools = append(tools, gt)
		}
		out.Tools = &tools
	}
	if req.ResponseFormat != nil {
		rf := &providers.GroqResponseFormat{
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
		user := req.User
		out.User = &user
	}
	return out
}

func marshalGroqPayload(base any, extra map[string]any) ([]byte, error) {
	raw, err := json.Marshal(base)
	if err != nil {
		return nil, fmt.Errorf("marshal groq request: %w", err)
	}
	if len(extra) == 0 {
		return raw, nil
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, fmt.Errorf("decode groq payload map: %w", err)
	}
	for k, v := range extra {
		switch k {
		case "model", "messages", "stream", "stream_options",
			"logprobs", "top_logprobs", "logit_bias", "service_tier":
			continue
		}
		if _, exists := payload[k]; !exists {
			payload[k] = v
		}
	}
	return json.Marshal(payload)
}

func derefStr(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func parseUpstreamError(statusCode int, body []byte, headers http.Header) error {
	var errEnv struct {
		Error struct {
			Message string `json:"message"`
			Code    string `json:"code"`
		} `json:"error"`
	}
	_ = json.Unmarshal(body, &errEnv)
	msg := errEnv.Error.Message
	if msg == "" {
		msg = string(body)
	}
	gwErr := domain.ClassifyUpstreamStatus(domain.ProviderGroq, statusCode, msg, adapter.ParseRetryAfter(headers))
	if errEnv.Error.Code != "" {
		gwErr.Code = errEnv.Error.Code
	}
	return gwErr
}

// ChatCompletion executes a non-streaming Groq chat completion.
func (a *Adapter) ChatCompletion(ctx context.Context, dep *domain.Deployment, req *domain.CanonicalChatRequest) (*domain.CanonicalChatResponse, error) {
	var cred *domain.ProviderCredential
	if dep != nil {
		cred = dep.Credential
	}
	model := resolveModel(dep, req.ResolvedModel, req.Model)
	shaped, err := validateAndShapeChatRequest(model, req)
	if err != nil {
		return nil, err
	}
	bodyBytes, err := marshalGroqPayload(toGroqChatRequest(model, shaped, false), shaped.ExtraParams)
	if err != nil {
		return nil, err
	}
	endpoint, err := a.resolveEndpoint(cred, "/chat/completions")
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("create groq chat request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if _, err := applyBearerAuth(httpReq, dep); err != nil {
		return nil, err
	}
	resp, err := a.client.Do(httpReq)
	if err != nil {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusBadGateway,
			Type:       domain.ErrorTypeUpstream,
			Code:       "upstream_network_error",
			Message:    err.Error(),
			Provider:   domain.ProviderGroq,
			Retryable:  true,
		}
	}
	defer resp.Body.Close()

	respBytes, err := adapter.ReadBoundedBody(resp.Body, adapter.DefaultMaxResponseBytes, domain.ProviderGroq)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, parseUpstreamError(resp.StatusCode, respBytes, resp.Header)
	}

	var groqResp providers.GroqChatCompletionResponse
	if err := json.Unmarshal(respBytes, &groqResp); err != nil {
		return nil, fmt.Errorf("decode groq chat response: %w", err)
	}

	choices := make([]domain.CanonicalChoice, 0, len(groqResp.Choices))
	for _, c := range groqResp.Choices {
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

	usage := domain.TokenUsage{
		PromptTokens:     groqResp.Usage.PromptTokens,
		CompletionTokens: groqResp.Usage.CompletionTokens,
		TotalTokens:      groqResp.Usage.TotalTokens,
	}
	if groqResp.Usage.PromptTokensDetails != nil && groqResp.Usage.PromptTokensDetails.CachedTokens != nil {
		usage.CachedPromptTokens = *groqResp.Usage.PromptTokensDetails.CachedTokens
	}
	if groqResp.Usage.CompletionTokensDetails != nil && groqResp.Usage.CompletionTokensDetails.ReasoningTokens != nil {
		usage.ReasoningTokens = *groqResp.Usage.CompletionTokensDetails.ReasoningTokens
	}

	return &domain.CanonicalChatResponse{
		ID:                groqResp.Id,
		Object:            "chat.completion",
		Created:           groqResp.Created,
		Model:             groqResp.Model,
		Provider:          domain.ProviderGroq,
		Choices:           choices,
		Usage:             usage,
		SystemFingerprint: derefStr(groqResp.SystemFingerprint),
	}, nil
}

// StreamChatCompletion executes a streaming Groq chat completion.
func (a *Adapter) StreamChatCompletion(ctx context.Context, dep *domain.Deployment, req *domain.CanonicalChatRequest, onChunk adapter.StreamChunkHandler) (*domain.TokenUsage, error) {
	ctx = adapter.StreamingContext(ctx)
	var cred *domain.ProviderCredential
	if dep != nil {
		cred = dep.Credential
	}
	model := resolveModel(dep, req.ResolvedModel, req.Model)
	shaped, err := validateAndShapeChatRequest(model, req)
	if err != nil {
		return nil, err
	}
	bodyBytes, err := marshalGroqPayload(toGroqChatRequest(model, shaped, true), shaped.ExtraParams)
	if err != nil {
		return nil, err
	}
	endpoint, err := a.resolveEndpoint(cred, "/chat/completions")
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("create groq stream request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "text/event-stream")
	if _, err := applyBearerAuth(httpReq, dep); err != nil {
		return nil, err
	}
	resp, err := a.client.Do(httpReq)
	if err != nil {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusBadGateway,
			Type:       domain.ErrorTypeUpstream,
			Code:       "upstream_network_error",
			Message:    err.Error(),
			Provider:   domain.ProviderGroq,
			Retryable:  true,
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		errBody, readErr := adapter.ReadBoundedBody(resp.Body, adapter.DefaultMaxErrorBytes, domain.ProviderGroq)
		if readErr != nil {
			return nil, readErr
		}
		return nil, parseUpstreamError(resp.StatusCode, errBody, resp.Header)
	}

	finalUsage := &domain.TokenUsage{}
	err = sse.ReadEvents(resp.Body, func(ev sse.Event) error {
		if ev.Data == "" || ev.Data == "[DONE]" {
			return nil
		}
		var raw providers.GroqStreamChunk
		if err := json.Unmarshal([]byte(ev.Data), &raw); err != nil {
			return nil
		}
		chunk := domain.CanonicalStreamChunk{
			ID:      raw.Id,
			Object:  "chat.completion.chunk",
			Created: raw.Created,
			Model:   raw.Model,
			Choices: make([]domain.CanonicalStreamChoice, 0, len(raw.Choices)),
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
			chunk.Usage = &domain.TokenUsage{
				PromptTokens:     raw.Usage.PromptTokens,
				CompletionTokens: raw.Usage.CompletionTokens,
				TotalTokens:      raw.Usage.TotalTokens,
			}
			*finalUsage = *chunk.Usage
		}
		return onChunk(&chunk)
	})
	return finalUsage, err
}

// Embeddings returns unsupported_capability because Groq does not expose /embeddings.
func (a *Adapter) Embeddings(context.Context, *domain.Deployment, *domain.CanonicalEmbeddingRequest) (*domain.CanonicalEmbeddingResponse, error) {
	return nil, &domain.GatewayError{
		StatusCode: http.StatusBadRequest,
		Type:       domain.ErrorTypeInvalidRequest,
		Code:       "unsupported_capability",
		Message:    "Groq does not expose an /embeddings endpoint; configure OpenAI for embeddings",
		Provider:   domain.ProviderGroq,
	}
}

// ListModels queries GET /models on Groq Cloud.
func (a *Adapter) ListModels(ctx context.Context, cred *domain.ProviderCredential) ([]domain.DiscoveredModel, error) {
	endpoint, err := a.resolveEndpoint(cred, "/models")
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("create groq models request: %w", err)
	}
	if err := (&adapter.BearerAuthStrategy{}).ApplyAuth(httpReq, cred); err != nil {
		return nil, err
	}
	observability.InjectTraceHeaders(ctx, httpReq)
	resp, err := a.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("groq list models: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := adapter.ReadBoundedBody(resp.Body, adapter.DefaultMaxResponseBytes, domain.ProviderGroq)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, parseUpstreamError(resp.StatusCode, bodyBytes, resp.Header)
	}

	var listResp providers.GroqModelsResponse
	if err := json.Unmarshal(bodyBytes, &listResp); err != nil {
		return nil, fmt.Errorf("decode groq models response: %w", err)
	}

	out := make([]domain.DiscoveredModel, 0, len(listResp.Data))
	for _, m := range listResp.Data {
		created := int64(0)
		if m.Created != nil {
			created = *m.Created
		}
		out = append(out, domain.DiscoveredModel{
			Provider:    domain.ProviderGroq,
			ModelName:   m.Id,
			DisplayName: m.Id,
			CreatedAt:   created,
		})
	}
	return out, nil
}

// TextCompletion implements adapter.CompletionAdapter for Groq /completions.
func (a *Adapter) TextCompletion(ctx context.Context, dep *domain.Deployment, req *domain.CanonicalCompletionRequest) (*domain.CanonicalCompletionResponse, error) {
	var cred *domain.ProviderCredential
	if dep != nil {
		cred = dep.Credential
	}
	model := resolveModel(dep, req.ResolvedModel, req.Model)
	var prompt any = req.Prompt.Strings
	if len(req.Prompt.Strings) == 1 {
		prompt = req.Prompt.Strings[0]
	}
	streamFalse := false
	payload := providers.GroqCompletionRequest{
		Model:       model,
		Prompt:      prompt,
		MaxTokens:   req.MaxTokens,
		Temperature: req.Temperature,
		TopP:        req.TopP,
		Stream:      &streamFalse,
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
		return nil, fmt.Errorf("marshal groq completion: %w", err)
	}
	endpoint, err := a.resolveEndpoint(cred, "/completions")
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("create groq completion request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if _, err := applyBearerAuth(httpReq, dep); err != nil {
		return nil, err
	}
	resp, err := a.client.Do(httpReq)
	if err != nil {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusBadGateway,
			Type:       domain.ErrorTypeUpstream,
			Code:       "upstream_network_error",
			Message:    err.Error(),
			Provider:   domain.ProviderGroq,
			Retryable:  true,
		}
	}
	defer resp.Body.Close()

	respBytes, err := adapter.ReadBoundedBody(resp.Body, adapter.DefaultMaxResponseBytes, domain.ProviderGroq)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, parseUpstreamError(resp.StatusCode, respBytes, resp.Header)
	}
	var groqResp providers.GroqCompletionResponse
	if err := json.Unmarshal(respBytes, &groqResp); err != nil {
		return nil, fmt.Errorf("decode groq completion response: %w", err)
	}
	choices := make([]domain.CanonicalCompletionChoice, 0, len(groqResp.Choices))
	for _, c := range groqResp.Choices {
		choices = append(choices, domain.CanonicalCompletionChoice{
			Index:        c.Index,
			Text:         c.Text,
			FinishReason: c.FinishReason,
		})
	}
	return &domain.CanonicalCompletionResponse{
		ID:       groqResp.Id,
		Model:    groqResp.Model,
		Provider: domain.ProviderGroq,
		Choices:  choices,
		Usage: domain.TokenUsage{
			PromptTokens:     groqResp.Usage.PromptTokens,
			CompletionTokens: groqResp.Usage.CompletionTokens,
			TotalTokens:      groqResp.Usage.TotalTokens,
		},
	}, nil
}

// StreamTextCompletion implements adapter.StreamingCompletionAdapter for Groq /completions.
func (a *Adapter) StreamTextCompletion(ctx context.Context, dep *domain.Deployment, req *domain.CanonicalCompletionRequest) (<-chan domain.CanonicalStreamChunk, error) {
	ctx = adapter.StreamingContext(ctx)
	var cred *domain.ProviderCredential
	if dep != nil {
		cred = dep.Credential
	}
	model := resolveModel(dep, req.ResolvedModel, req.Model)
	var prompt any = req.Prompt.Strings
	if len(req.Prompt.Strings) == 1 {
		prompt = req.Prompt.Strings[0]
	}
	streamTrue := true
	payload := providers.GroqCompletionRequest{
		Model:       model,
		Prompt:      prompt,
		MaxTokens:   req.MaxTokens,
		Temperature: req.Temperature,
		TopP:        req.TopP,
		Stream:      &streamTrue,
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
		return nil, fmt.Errorf("marshal groq stream completion: %w", err)
	}
	endpoint, err := a.resolveEndpoint(cred, "/completions")
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("create groq stream completion request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "text/event-stream")
	if _, err := applyBearerAuth(httpReq, dep); err != nil {
		return nil, err
	}
	resp, err := a.client.Do(httpReq)
	if err != nil {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusBadGateway,
			Type:       domain.ErrorTypeUpstream,
			Code:       "upstream_network_error",
			Message:    err.Error(),
			Provider:   domain.ProviderGroq,
			Retryable:  true,
		}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		errBody, readErr := adapter.ReadBoundedBody(resp.Body, adapter.DefaultMaxErrorBytes, domain.ProviderGroq)
		resp.Body.Close()
		if readErr != nil {
			return nil, readErr
		}
		return nil, parseUpstreamError(resp.StatusCode, errBody, resp.Header)
	}

	ch := make(chan domain.CanonicalStreamChunk, 16)
	go func() {
		defer resp.Body.Close()
		defer close(ch)
		_ = sse.ReadEvents(resp.Body, func(ev sse.Event) error {
			if ev.Data == "" || ev.Data == "[DONE]" {
				return nil
			}
			var raw struct {
				ID      string `json:"id"`
				Created int64  `json:"created"`
				Model   string `json:"model"`
				Choices []struct {
					Index        int     `json:"index"`
					Text         string  `json:"text"`
					FinishReason *string `json:"finish_reason,omitempty"`
				} `json:"choices"`
				Usage *domain.TokenUsage `json:"usage,omitempty"`
			}
			if err := json.Unmarshal([]byte(ev.Data), &raw); err != nil {
				return nil
			}
			chunk := domain.CanonicalStreamChunk{
				ID:      raw.ID,
				Object:  "text_completion",
				Created: raw.Created,
				Model:   raw.Model,
				Choices: make([]domain.CanonicalStreamChoice, 0, len(raw.Choices)),
				Usage:   raw.Usage,
			}
			for _, c := range raw.Choices {
				chunk.Choices = append(chunk.Choices, domain.CanonicalStreamChoice{
					Index:        c.Index,
					Delta:        domain.CanonicalStreamDelta{Content: c.Text},
					FinishReason: c.FinishReason,
				})
			}
			select {
			case ch <- chunk:
			case <-ctx.Done():
				return ctx.Err()
			}
			return nil
		})
	}()
	return ch, nil
}

// TranscribeAudio implements adapter.AudioAdapter for Groq /audio/transcriptions and /audio/translations.
func (a *Adapter) TranscribeAudio(ctx context.Context, dep *domain.Deployment, req *domain.CanonicalAudioTranscriptionRequest) (*domain.CanonicalAudioResponse, error) {
	if req == nil {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_request",
			Message:    "audio transcription request is required",
			Provider:   domain.ProviderGroq,
		}
	}
	var cred *domain.ProviderCredential
	if dep != nil {
		cred = dep.Credential
	}
	model := resolveModel(dep, req.ResolvedModel, req.Model)
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
			Provider:   domain.ProviderGroq,
		}
	}

	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	if err := mw.WriteField("model", model); err != nil {
		return nil, fmt.Errorf("write audio model field: %w", err)
	}
	if req.Language != "" {
		_ = mw.WriteField("language", req.Language)
	}
	if req.Prompt != "" {
		_ = mw.WriteField("prompt", req.Prompt)
	}
	if req.ResponseFormat != "" {
		_ = mw.WriteField("response_format", req.ResponseFormat)
	}
	filename := filepath.Base(req.FileName)
	if filename == "." || filename == "" {
		filename = "audio.wav"
	}
	fw, err := mw.CreateFormFile("file", filename)
	if err != nil {
		return nil, fmt.Errorf("create multipart audio file: %w", err)
	}
	if _, err := io.Copy(fw, reader); err != nil {
		return nil, fmt.Errorf("copy audio bytes: %w", err)
	}
	if err := mw.Close(); err != nil {
		return nil, fmt.Errorf("close multipart writer: %w", err)
	}

	subPath := "/audio/transcriptions"
	if req.IsTranslation {
		subPath = "/audio/translations"
	}
	endpoint, err := a.resolveEndpoint(cred, subPath)
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, &buf)
	if err != nil {
		return nil, fmt.Errorf("create groq audio request: %w", err)
	}
	httpReq.Header.Set("Content-Type", mw.FormDataContentType())
	if _, err := applyBearerAuth(httpReq, dep); err != nil {
		return nil, err
	}
	resp, err := a.client.Do(httpReq)
	if err != nil {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusBadGateway,
			Type:       domain.ErrorTypeUpstream,
			Code:       "upstream_network_error",
			Message:    err.Error(),
			Provider:   domain.ProviderGroq,
			Retryable:  true,
		}
	}
	defer resp.Body.Close()

	respBytes, err := adapter.ReadBoundedBody(resp.Body, adapter.DefaultMaxResponseBytes, domain.ProviderGroq)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, parseUpstreamError(resp.StatusCode, respBytes, resp.Header)
	}
	var groqAudio providers.GroqAudioResponse
	if err := json.Unmarshal(respBytes, &groqAudio); err != nil {
		return nil, fmt.Errorf("decode groq audio response: %w", err)
	}
	out := &domain.CanonicalAudioResponse{
		Text:     groqAudio.Text,
		Language: derefStr(groqAudio.Language),
	}
	if groqAudio.Duration != nil {
		out.DurationMs = int64(*groqAudio.Duration * 1000)
	}
	return out, nil
}

// GenerateSpeech implements adapter.AudioAdapter for Groq /audio/speech.
func (a *Adapter) GenerateSpeech(ctx context.Context, dep *domain.Deployment, req *domain.CanonicalAudioSpeechRequest) (io.ReadCloser, string, error) {
	if req == nil {
		return nil, "", &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_request",
			Message:    "speech request is required",
			Provider:   domain.ProviderGroq,
		}
	}
	var cred *domain.ProviderCredential
	if dep != nil {
		cred = dep.Credential
	}
	model := resolveModel(dep, req.ResolvedModel, req.Model)
	payload := providers.GroqAudioSpeechRequest{
		Model: model,
		Input: req.Input,
		Voice: req.Voice,
	}
	if req.ResponseFormat != "" {
		rf := req.ResponseFormat
		payload.ResponseFormat = &rf
	}
	if req.Speed > 0 {
		sp := req.Speed
		payload.Speed = &sp
	}
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, "", fmt.Errorf("marshal groq speech request: %w", err)
	}
	endpoint, err := a.resolveEndpoint(cred, "/audio/speech")
	if err != nil {
		return nil, "", err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, "", fmt.Errorf("create groq speech request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if _, err := applyBearerAuth(httpReq, dep); err != nil {
		return nil, "", err
	}
	resp, err := a.client.Do(httpReq)
	if err != nil {
		return nil, "", &domain.GatewayError{
			StatusCode: http.StatusBadGateway,
			Type:       domain.ErrorTypeUpstream,
			Code:       "upstream_network_error",
			Message:    err.Error(),
			Provider:   domain.ProviderGroq,
			Retryable:  true,
		}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		defer resp.Body.Close()
		errBody, readErr := adapter.ReadBoundedBody(resp.Body, adapter.DefaultMaxErrorBytes, domain.ProviderGroq)
		if readErr != nil {
			return nil, "", readErr
		}
		return nil, "", parseUpstreamError(resp.StatusCode, errBody, resp.Header)
	}
	ct := resp.Header.Get("Content-Type")
	if ct == "" {
		ct = "audio/wav"
	}
	return resp.Body, ct, nil
}
