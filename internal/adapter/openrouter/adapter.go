package openrouter

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
	"github.com/goroute-ai/ai-gateway-go/internal/openapi/providers"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
)

const (
	defaultBaseURL     = "https://openrouter.ai/api/v1"
	defaultHTTPReferer = "https://github.com/goroute-ai/ai-gateway-go"
	defaultXTitle      = "GoRoute AI Gateway"
)

// Adapter implements adapter.ProviderAdapter, OperationSupportChecker, and PrefillSupportChecker for OpenRouter.
type Adapter struct {
	client     *http.Client
	ssrfPolicy *network.Policy
}

// NewAdapter creates an OpenRouter Adapter using client, or an SSRF-safe pooled client when nil.
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

// Provider returns domain.ProviderOpenRouter.
func (a *Adapter) Provider() domain.ProviderType {
	return domain.ProviderOpenRouter
}

// SupportsAssistantPrefill reports that OpenRouter supports trailing assistant messages.
func (a *Adapter) SupportsAssistantPrefill() bool {
	return true
}

// SupportsOperation reports OpenRouter's supported OpenAPI endpoints.
func (a *Adapter) SupportsOperation(op domain.OperationType) bool {
	switch op {
	case domain.OperationChat:
		return true
	default:
		return false
	}
}

func (a *Adapter) resolveEndpoint(cred *domain.ProviderCredential, suffix string) (string, error) {
	base, err := adapter.ResolveCredentialBaseURL(cred, defaultBaseURL, a.ssrfPolicy, domain.ProviderOpenRouter)
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

func applyOpenRouterAuthAndHeaders(req *http.Request, cred *domain.ProviderCredential) error {
	if cred == nil {
		return &domain.GatewayError{
			StatusCode:  http.StatusUnauthorized,
			Type:        domain.ErrorTypeAuthentication,
			Code:        "missing_credential",
			Message:     "missing provider credential",
			Provider:    domain.ProviderOpenRouter,
			AuthFailure: true,
		}
	}
	req.Header.Set("HTTP-Referer", defaultHTTPReferer)
	req.Header.Set("X-Title", defaultXTitle)
	if err := (&adapter.BearerAuthStrategy{}).ApplyAuth(req, cred); err != nil {
		return &domain.GatewayError{
			StatusCode:  http.StatusUnauthorized,
			Type:        domain.ErrorTypeAuthentication,
			Code:        "auth_strategy_failed",
			Message:     err.Error(),
			Provider:    domain.ProviderOpenRouter,
			AuthFailure: true,
		}
	}
	return nil
}

func toOpenRouterRequest(model string, req *domain.CanonicalChatRequest, stream bool) providers.OpenRouterChatCompletionRequest {
	msgs := make([]providers.OpenRouterMessage, 0, len(req.Messages))
	for _, m := range req.Messages {
		om := providers.OpenRouterMessage{
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
			tcs := make([]providers.OpenRouterToolCall, 0, len(m.ToolCalls))
			for _, tc := range m.ToolCalls {
				id := tc.ID
				typ := tc.Type
				fnName := tc.Function.Name
				fnArgs := tc.Function.Arguments
				tcs = append(tcs, providers.OpenRouterToolCall{
					Index: tc.Index,
					Id:    &id,
					Type:  &typ,
					Function: providers.OpenRouterFunctionCall{
						Name:      &fnName,
						Arguments: &fnArgs,
					},
				})
			}
			om.ToolCalls = &tcs
		}
		msgs = append(msgs, om)
	}

	out := providers.OpenRouterChatCompletionRequest{
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
			out.StreamOptions = &providers.OpenRouterStreamOptions{IncludeUsage: true}
		}
	}
	if len(req.Stop) > 0 {
		stopCopy := append([]string(nil), req.Stop...)
		out.Stop = &stopCopy
	}
	if len(req.Tools) > 0 {
		tools := make([]providers.OpenRouterTool, 0, len(req.Tools))
		for _, t := range req.Tools {
			ot := providers.OpenRouterTool{
				Type: t.Type,
				Function: providers.OpenRouterFunction{
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
		rf := &providers.OpenRouterResponseFormat{
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
		if strings.EqualFold(effort, "none") {
			exclude := true
			out.Reasoning = &providers.OpenRouterReasoningConfig{Exclude: &exclude}
		} else {
			out.Reasoning = &providers.OpenRouterReasoningConfig{Effort: &effort}
		}
	}
	if req.User != "" {
		u := req.User
		out.User = &u
	}
	return out
}

func marshalOpenRouterPayload(base providers.OpenRouterChatCompletionRequest, extra map[string]any) ([]byte, error) {
	raw, err := json.Marshal(base)
	if err != nil {
		return nil, fmt.Errorf("marshal openrouter request: %w", err)
	}
	if len(extra) == 0 {
		return raw, nil
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		return nil, fmt.Errorf("decode openrouter payload map: %w", err)
	}
	for k, v := range extra {
		switch k {
		case "model", "messages", "stream", "stream_options":
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
			Code    any    `json:"code"`
		} `json:"error"`
	}
	_ = json.Unmarshal(body, &errEnv)
	msg := errEnv.Error.Message
	if msg == "" {
		msg = string(body)
	}
	gwErr := domain.ClassifyUpstreamStatus(domain.ProviderOpenRouter, statusCode, msg, adapter.ParseRetryAfter(headers))
	if codeStr, ok := errEnv.Error.Code.(string); ok && codeStr != "" {
		gwErr.Code = codeStr
	}
	return gwErr
}

// ChatCompletion executes a non-streaming OpenRouter chat completion.
func (a *Adapter) ChatCompletion(ctx context.Context, dep *domain.Deployment, req *domain.CanonicalChatRequest) (*domain.CanonicalChatResponse, error) {
	if req == nil {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_request",
			Message:    "chat request is required",
			Provider:   domain.ProviderOpenRouter,
		}
	}
	var cred *domain.ProviderCredential
	if dep != nil {
		cred = dep.Credential
	}
	model := resolveModel(dep, req.ResolvedModel, req.Model)
	bodyBytes, err := marshalOpenRouterPayload(toOpenRouterRequest(model, req, false), req.ExtraParams)
	if err != nil {
		return nil, err
	}
	endpoint, err := a.resolveEndpoint(cred, "/chat/completions")
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("create openrouter chat request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if err := applyOpenRouterAuthAndHeaders(httpReq, cred); err != nil {
		return nil, err
	}
	resp, err := a.client.Do(httpReq)
	if err != nil {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusBadGateway,
			Type:       domain.ErrorTypeUpstream,
			Code:       "upstream_network_error",
			Message:    err.Error(),
			Provider:   domain.ProviderOpenRouter,
			Retryable:  true,
		}
	}
	defer resp.Body.Close()

	respBytes, err := adapter.ReadBoundedBody(resp.Body, adapter.DefaultMaxResponseBytes, domain.ProviderOpenRouter)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, parseUpstreamError(resp.StatusCode, respBytes, resp.Header)
	}

	var orResp providers.OpenRouterChatCompletionResponse
	if err := json.Unmarshal(respBytes, &orResp); err != nil {
		return nil, fmt.Errorf("decode openrouter chat response: %w", err)
	}

	choices := make([]domain.CanonicalChoice, 0, len(orResp.Choices))
	for _, c := range orResp.Choices {
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
		PromptTokens:     orResp.Usage.PromptTokens,
		CompletionTokens: orResp.Usage.CompletionTokens,
		TotalTokens:      orResp.Usage.TotalTokens,
	}
	if orResp.Usage.PromptTokensDetails != nil && orResp.Usage.PromptTokensDetails.CachedTokens != nil {
		usage.CachedPromptTokens = *orResp.Usage.PromptTokensDetails.CachedTokens
	}
	if orResp.Usage.CompletionTokensDetails != nil && orResp.Usage.CompletionTokensDetails.ReasoningTokens != nil {
		usage.ReasoningTokens = *orResp.Usage.CompletionTokensDetails.ReasoningTokens
	}

	return &domain.CanonicalChatResponse{
		ID:                orResp.Id,
		Object:            "chat.completion",
		Created:           orResp.Created,
		Model:             orResp.Model,
		Provider:          domain.ProviderOpenRouter,
		Choices:           choices,
		Usage:             usage,
		SystemFingerprint: derefStr(orResp.SystemFingerprint),
	}, nil
}

// StreamChatCompletion executes a streaming OpenRouter chat completion.
func (a *Adapter) StreamChatCompletion(ctx context.Context, dep *domain.Deployment, req *domain.CanonicalChatRequest, onChunk adapter.StreamChunkHandler) (*domain.TokenUsage, error) {
	ctx = adapter.StreamingContext(ctx)
	if req == nil {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_request",
			Message:    "chat request is required",
			Provider:   domain.ProviderOpenRouter,
		}
	}
	var cred *domain.ProviderCredential
	if dep != nil {
		cred = dep.Credential
	}
	model := resolveModel(dep, req.ResolvedModel, req.Model)
	bodyBytes, err := marshalOpenRouterPayload(toOpenRouterRequest(model, req, true), req.ExtraParams)
	if err != nil {
		return nil, err
	}
	endpoint, err := a.resolveEndpoint(cred, "/chat/completions")
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("create openrouter stream request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "text/event-stream")
	if err := applyOpenRouterAuthAndHeaders(httpReq, cred); err != nil {
		return nil, err
	}
	resp, err := a.client.Do(httpReq)
	if err != nil {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusBadGateway,
			Type:       domain.ErrorTypeUpstream,
			Code:       "upstream_network_error",
			Message:    err.Error(),
			Provider:   domain.ProviderOpenRouter,
			Retryable:  true,
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		errBody, readErr := adapter.ReadBoundedBody(resp.Body, adapter.DefaultMaxErrorBytes, domain.ProviderOpenRouter)
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
		var raw providers.OpenRouterStreamChunk
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

// Embeddings returns unsupported_capability because OpenRouter only routes chat inference.
func (a *Adapter) Embeddings(context.Context, *domain.Deployment, *domain.CanonicalEmbeddingRequest) (*domain.CanonicalEmbeddingResponse, error) {
	return nil, &domain.GatewayError{
		StatusCode: http.StatusBadRequest,
		Type:       domain.ErrorTypeInvalidRequest,
		Code:       "unsupported_capability",
		Message:    "OpenRouter does not expose a native /embeddings endpoint; configure OpenAI for embeddings",
		Provider:   domain.ProviderOpenRouter,
	}
}

// ListModels queries GET /models on OpenRouter.
func (a *Adapter) ListModels(ctx context.Context, cred *domain.ProviderCredential) ([]domain.DiscoveredModel, error) {
	endpoint, err := a.resolveEndpoint(cred, "/models")
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("create openrouter models request: %w", err)
	}
	if cred != nil && cred.DecryptedAPIKey != "" {
		if err := (&adapter.BearerAuthStrategy{}).ApplyAuth(httpReq, cred); err != nil {
			return nil, err
		}
	}
	resp, err := a.client.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("openrouter list models: %w", err)
	}
	defer resp.Body.Close()

	bodyBytes, err := adapter.ReadBoundedBody(resp.Body, adapter.DefaultMaxResponseBytes, domain.ProviderOpenRouter)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, parseUpstreamError(resp.StatusCode, bodyBytes, resp.Header)
	}

	var listResp providers.OpenRouterModelsResponse
	if err := json.Unmarshal(bodyBytes, &listResp); err != nil {
		return nil, fmt.Errorf("decode openrouter models response: %w", err)
	}

	out := make([]domain.DiscoveredModel, 0, len(listResp.Data))
	for _, m := range listResp.Data {
		display := derefStr(m.Name)
		if display == "" {
			display = m.Id
		}
		created := int64(0)
		if m.Created != nil {
			created = *m.Created
		}
		out = append(out, domain.DiscoveredModel{
			Provider:    domain.ProviderOpenRouter,
			ModelName:   m.Id,
			DisplayName: display,
			CreatedAt:   created,
		})
	}
	return out, nil
}
