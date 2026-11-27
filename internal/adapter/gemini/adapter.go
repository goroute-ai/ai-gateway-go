package gemini

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/adapter"
	"github.com/goroute-ai/ai-gateway-go/internal/adapter/sse"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/logger"
	"github.com/goroute-ai/ai-gateway-go/internal/observability"
	"github.com/goroute-ai/ai-gateway-go/internal/openapi/providers"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
)

const (
	defaultBaseURL                           = "https://generativelanguage.googleapis.com"
	maxRemoteMediaBytes                int64 = 20 << 20
	maxTotalRemoteMediaBytesPerRequest int64 = 25 << 20
	maxRemoteMediaPartsPerRequest            = 8
	maxInlineMediaBytes                int64 = 25 << 20
	maxListModelPages                        = 10
	maxGeminiBatchEmbedItems                 = 100
	maxGeminiEmbeddingDimensions             = 16384
	maxGeminiThinkingBudget            int32 = 24576
	maxGeminiModelIDLen                      = 128
	maxMalformedSSEFrames                    = 5
	mediaRequestTimeout                      = 15 * time.Second
	mediaResponseHeaderTimeout               = 10 * time.Second
)

var cachedContentNamePattern = regexp.MustCompile(`^cachedContents/[A-Za-z0-9_-]{1,128}$`)

// =============================================================================
// Adapter Construction & Capability Registration
// =============================================================================

// Adapter implements adapter.ProviderAdapter, adapter.OperationSupportChecker,
// and adapter.PrefillSupportChecker for the Google Gemini Generative Language API (v1beta).
type Adapter struct {
	client                      *http.Client
	mediaClient                 *http.Client
	mediaPolicy                 *network.Policy
	ssrfPolicy                  *network.Policy
	allowCachedContent          bool
	allowSafetySettingsOverride bool
}

// NewAdapter creates a Gemini Adapter using client, or a default SSRF-aware pooled HTTP client when nil.
func NewAdapter(client *http.Client) *Adapter {
	if client == nil {
		client = adapter.NewPooledHTTPClient(120 * time.Second)
	}
	mediaClient := network.NewHTTPClientWithTimeouts(
		adapter.DefaultPublicMediaPolicy(),
		mediaRequestTimeout,
		mediaResponseHeaderTimeout,
		mediaRequestTimeout,
		nil,
	)
	return &Adapter{
		client:      client,
		mediaClient: mediaClient,
	}
}

// SetSSRFPolicy configures the outbound network policy used to validate BaseURL overrides.
func (a *Adapter) SetSSRFPolicy(policy *network.Policy) {
	a.ssrfPolicy = policy
}

// SetAllowCachedContentPassthrough controls whether caller-supplied ExtraParams["cached_content"]
// is forwarded to Gemini. Defaults to false (fail-closed) to prevent cross-tenant cached context
// IDOR when multiple callers share an upstream Gemini API key.
func (a *Adapter) SetAllowCachedContentPassthrough(allow bool) {
	a.allowCachedContent = allow
}

// SetAllowSafetySettingsOverride controls whether caller-supplied ExtraParams["safety_settings"]
// is forwarded to Gemini. Defaults to false (fail-closed) to prevent end-user callers from
// weakening upstream vendor safety thresholds.
func (a *Adapter) SetAllowSafetySettingsOverride(allow bool) {
	a.allowSafetySettingsOverride = allow
}

func (a *Adapter) effectiveMediaClient() *http.Client {
	if a.mediaClient != nil {
		return a.mediaClient
	}
	pol := a.mediaPolicy
	if pol == nil {
		pol = adapter.DefaultPublicMediaPolicy()
	}
	return network.NewHTTPClientWithTimeouts(pol, mediaRequestTimeout, mediaResponseHeaderTimeout, mediaRequestTimeout, nil)
}

// Provider returns the canonical provider identifier for Google Gemini.
func (a *Adapter) Provider() domain.ProviderType {
	return domain.ProviderGemini
}

// SupportsOperation reports whether the Gemini v1beta adapter supports the given operation.
func (a *Adapter) SupportsOperation(op domain.OperationType) bool {
	switch op {
	case domain.OperationChat, domain.OperationEmbedding:
		return true
	default:
		return false
	}
}

// SupportsAssistantPrefill reports that Gemini generateContent supports continuing
// generation from a trailing model turn.
func (a *Adapter) SupportsAssistantPrefill() bool {
	return true
}

// =============================================================================
// Chat Completions (Sync & SSE Streaming)
// =============================================================================

// ChatCompletion executes a synchronous chat completion via Gemini v1beta :generateContent.
func (a *Adapter) ChatCompletion(ctx context.Context, dep *domain.Deployment, req *domain.CanonicalChatRequest) (*domain.CanonicalChatResponse, error) {
	model, err := resolveGeminiModel(dep, req)
	if err != nil {
		return nil, err
	}
	payload, err := a.buildGeminiGenerateContentRequest(ctx, model, req)
	if err != nil {
		return nil, err
	}
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	endpoint, err := a.resolveModelActionEndpoint(credentialOf(dep), model, "generateContent", "")
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	if err := applyGeminiHeaders(httpReq, credentialOf(dep)); err != nil {
		return nil, err
	}

	resp, err := a.client.Do(httpReq)
	if err != nil {
		return nil, classifyGeminiTransportError(ctx, "generateContent", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, parseGeminiUpstreamError(resp)
	}

	respBody, err := adapter.ReadBoundedBody(resp.Body, adapter.DefaultMaxResponseBytes, domain.ProviderGemini)
	if err != nil {
		return nil, err
	}

	var gemResp providers.GeminiGenerateContentResponse
	if err := json.Unmarshal(respBody, &gemResp); err != nil {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusBadGateway,
			Type:       domain.ErrorTypeUpstream,
			Code:       "invalid_upstream_json",
			Message:    fmt.Sprintf("failed to parse Gemini response: %v", err),
			Provider:   domain.ProviderGemini,
		}
	}

	return toCanonicalChatResponse(model, &gemResp), nil
}

// StreamChatCompletion executes a streaming chat completion via Gemini v1beta :streamGenerateContent?alt=sse.
func (a *Adapter) StreamChatCompletion(ctx context.Context, dep *domain.Deployment, req *domain.CanonicalChatRequest, onChunk adapter.StreamChunkHandler) (*domain.TokenUsage, error) {
	ctx = adapter.StreamingContext(ctx)
	model, err := resolveGeminiModel(dep, req)
	if err != nil {
		return nil, err
	}
	payload, err := a.buildGeminiGenerateContentRequest(ctx, model, req)
	if err != nil {
		return nil, err
	}
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	endpoint, err := a.resolveModelActionEndpoint(credentialOf(dep), model, "streamGenerateContent", "alt=sse")
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	if err := applyGeminiHeaders(httpReq, credentialOf(dep)); err != nil {
		return nil, err
	}
	httpReq.Header.Set("Accept", "text/event-stream")

	resp, err := a.client.Do(httpReq)
	if err != nil {
		return nil, classifyGeminiTransportError(ctx, "streamGenerateContent", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, parseGeminiUpstreamError(resp)
	}

	chunkID := fmt.Sprintf("chatcmpl-gem-%d", time.Now().UnixNano())
	created := time.Now().Unix()
	usage := &domain.TokenUsage{}
	roleSent := false
	toolIdx := -1
	hasToolCalls := false
	finishSent := false
	malformedFrames := 0
	respModel := model

	err = sse.ReadEvents(resp.Body, func(ev sse.Event) error {
		trimmed := strings.TrimSpace(ev.Data)
		if trimmed == "" || trimmed == "[DONE]" {
			return nil
		}

		var frame providers.GeminiGenerateContentResponse
		if unmarshalErr := json.Unmarshal([]byte(trimmed), &frame); unmarshalErr != nil {
			malformedFrames++
			logger.WarnContext(ctx, "Malformed Gemini SSE frame skipped",
				slog.String("provider", string(domain.ProviderGemini)),
				slog.Int("consecutive_malformed", malformedFrames),
				slog.String("error", logger.ScrubSecrets(unmarshalErr.Error())),
			)
			if malformedFrames >= maxMalformedSSEFrames {
				return &domain.GatewayError{
					StatusCode: http.StatusBadGateway,
					Type:       domain.ErrorTypeUpstream,
					Code:       "invalid_upstream_stream",
					Message:    "Gemini upstream returned repeated malformed SSE frames",
					Provider:   domain.ProviderGemini,
				}
			}
			return nil
		}
		malformedFrames = 0
		if frame.ResponseId != nil && *frame.ResponseId != "" {
			chunkID = *frame.ResponseId
		}
		if frame.ModelVersion != nil && *frame.ModelVersion != "" {
			respModel = *frame.ModelVersion
		}
		if frame.UsageMetadata != nil {
			*usage = extractGeminiUsage(frame.UsageMetadata)
		}

		if frame.Candidates == nil || len(*frame.Candidates) == 0 {
			if frame.PromptFeedback != nil && frame.PromptFeedback.BlockReason != nil && *frame.PromptFeedback.BlockReason != "" && !finishSent {
				finish := "content_filter"
				finishSent = true
				uCopy := *usage
				return onChunk(&domain.CanonicalStreamChunk{
					ID:      chunkID,
					Object:  "chat.completion.chunk",
					Created: created,
					Model:   respModel,
					Choices: []domain.CanonicalStreamChoice{
						{Index: 0, Delta: domain.CanonicalStreamDelta{}, FinishReason: &finish},
					},
					Usage: &uCopy,
				})
			}
			return nil
		}

		cand := (*frame.Candidates)[0]
		var contentBuf strings.Builder
		var thoughtBuf strings.Builder
		var toolDeltas []domain.CanonicalToolCall

		if cand.Content != nil && cand.Content.Parts != nil {
			for _, p := range *cand.Content.Parts {
				if p.Text != nil && *p.Text != "" {
					if p.Thought != nil && *p.Thought {
						thoughtBuf.WriteString(*p.Text)
					} else {
						contentBuf.WriteString(*p.Text)
					}
				}
				if p.FunctionCall != nil {
					hasToolCalls = true
					toolIdx++
					idxCopy := toolIdx
					callID := fmt.Sprintf("call_gemini_%d", idxCopy)
					if p.FunctionCall.Id != nil && *p.FunctionCall.Id != "" {
						callID = *p.FunctionCall.Id
					}
					argsStr := "{}"
					if p.FunctionCall.Args != nil {
						if b, mErr := json.Marshal(*p.FunctionCall.Args); mErr == nil {
							argsStr = string(b)
						}
					}
					toolDeltas = append(toolDeltas, domain.CanonicalToolCall{
						Index: &idxCopy,
						ID:    callID,
						Type:  "function",
						Function: domain.CanonicalFunctionCall{
							Name:      p.FunctionCall.Name,
							Arguments: argsStr,
						},
					})
				}
			}
		}

		delta := domain.CanonicalStreamDelta{
			Content:          contentBuf.String(),
			ReasoningContent: thoughtBuf.String(),
			ToolCalls:        toolDeltas,
		}
		if !roleSent && (delta.Content != "" || delta.ReasoningContent != "" || len(delta.ToolCalls) > 0) {
			delta.Role = "assistant"
			roleSent = true
		}

		var finishPtr *string
		var chunkUsage *domain.TokenUsage
		if cand.FinishReason != nil && *cand.FinishReason != "" {
			f := mapGeminiFinishReason(*cand.FinishReason, hasToolCalls)
			finishPtr = &f
			finishSent = true
			uCopy := *usage
			chunkUsage = &uCopy
		}

		if delta.Role == "" && delta.Content == "" && delta.ReasoningContent == "" && len(delta.ToolCalls) == 0 && finishPtr == nil {
			return nil
		}

		return onChunk(&domain.CanonicalStreamChunk{
			ID:      chunkID,
			Object:  "chat.completion.chunk",
			Created: created,
			Model:   respModel,
			Choices: []domain.CanonicalStreamChoice{
				{
					Index:        0,
					Delta:        delta,
					FinishReason: finishPtr,
				},
			},
			Usage: chunkUsage,
		})
	})
	if err != nil {
		if errors.Is(err, sse.ErrEventTooLarge) {
			return usage, &domain.GatewayError{
				StatusCode: http.StatusBadGateway,
				Type:       domain.ErrorTypeUpstream,
				Code:       "upstream_stream_too_large",
				Message:    "Gemini upstream SSE event exceeded maximum allowed size",
				Provider:   domain.ProviderGemini,
			}
		}
		return usage, err
	}

	if !finishSent && (roleSent || usage.TotalTokens > 0) {
		finish := mapGeminiFinishReason("STOP", hasToolCalls)
		uCopy := *usage
		if cbErr := onChunk(&domain.CanonicalStreamChunk{
			ID:      chunkID,
			Object:  "chat.completion.chunk",
			Created: created,
			Model:   respModel,
			Choices: []domain.CanonicalStreamChoice{
				{Index: 0, Delta: domain.CanonicalStreamDelta{}, FinishReason: &finish},
			},
			Usage: &uCopy,
		}); cbErr != nil {
			return usage, cbErr
		}
	}

	return usage, nil
}

// =============================================================================
// Embeddings (Single :embedContent & Batch :batchEmbedContents)
// =============================================================================

// Embeddings executes text embedding requests via Gemini v1beta :embedContent (single input)
// or :batchEmbedContents (multiple inputs).
func (a *Adapter) Embeddings(ctx context.Context, dep *domain.Deployment, req *domain.CanonicalEmbeddingRequest) (*domain.CanonicalEmbeddingResponse, error) {
	if req == nil || len(req.Input) == 0 {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_embedding_input",
			Message:    "at least one embedding input is required",
			Provider:   domain.ProviderGemini,
		}
	}

	if len(req.Input) > maxGeminiBatchEmbedItems {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_embedding_batch_size",
			Message:    fmt.Sprintf("Gemini embeddings support at most %d inputs per request", maxGeminiBatchEmbedItems),
			Provider:   domain.ProviderGemini,
		}
	}

	rawModel := req.ResolvedModel
	if rawModel == "" && dep != nil && dep.GlobalModel != nil {
		rawModel = dep.GlobalModel.ModelName
	}
	if rawModel == "" {
		rawModel = req.Model
	}
	model, err := normalizeGeminiModel(rawModel)
	if err != nil {
		return nil, err
	}

	fullModel := "models/" + model
	var outDim *int32
	if req.Dimensions != nil {
		if *req.Dimensions <= 0 || *req.Dimensions > maxGeminiEmbeddingDimensions {
			return nil, &domain.GatewayError{
				StatusCode: http.StatusBadRequest,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "invalid_embedding_dimensions",
				Message:    fmt.Sprintf("dimensions must be between 1 and %d", maxGeminiEmbeddingDimensions),
				Provider:   domain.ProviderGemini,
			}
		}
		if d, ok := safeIntToInt32(*req.Dimensions); ok {
			outDim = &d
		}
	}

	if len(req.Input) == 1 {
		text := req.Input[0]
		parts := []providers.GeminiPart{{Text: &text}}
		payload := providers.GeminiEmbedContentRequest{
			Model:                &fullModel,
			Content:              providers.GeminiContent{Parts: &parts},
			OutputDimensionality: outDim,
		}
		bodyBytes, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		endpoint, err := a.resolveModelActionEndpoint(credentialOf(dep), model, "embedContent", "")
		if err != nil {
			return nil, err
		}
		httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
		if err != nil {
			return nil, err
		}
		if err := applyGeminiHeaders(httpReq, credentialOf(dep)); err != nil {
			return nil, err
		}

		resp, err := a.client.Do(httpReq)
		if err != nil {
			return nil, classifyGeminiTransportError(ctx, "embedContent", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return nil, parseGeminiUpstreamError(resp)
		}
		respBody, err := adapter.ReadBoundedBody(resp.Body, adapter.DefaultMaxResponseBytes, domain.ProviderGemini)
		if err != nil {
			return nil, err
		}
		var embResp providers.GeminiEmbedContentResponse
		if err := json.Unmarshal(respBody, &embResp); err != nil {
			return nil, &domain.GatewayError{
				StatusCode: http.StatusBadGateway,
				Type:       domain.ErrorTypeUpstream,
				Code:       "invalid_upstream_json",
				Message:    fmt.Sprintf("failed to parse Gemini embedContent response: %v", err),
				Provider:   domain.ProviderGemini,
			}
		}

		var vec []float64
		if embResp.Embedding != nil && embResp.Embedding.Values != nil {
			vec = *embResp.Embedding.Values
		}
		var usage domain.TokenUsage
		if embResp.UsageMetadata != nil {
			usage = extractGeminiUsage(embResp.UsageMetadata)
		}
		return &domain.CanonicalEmbeddingResponse{
			Object:   "list",
			Model:    model,
			Provider: domain.ProviderGemini,
			Data: []domain.EmbeddingData{
				{Object: "embedding", Index: 0, Embedding: vec},
			},
			Usage: usage,
		}, nil
	}

	reqs := make([]providers.GeminiEmbedContentRequest, 0, len(req.Input))
	for _, input := range req.Input {
		text := input
		parts := []providers.GeminiPart{{Text: &text}}
		reqs = append(reqs, providers.GeminiEmbedContentRequest{
			Model:                &fullModel,
			Content:              providers.GeminiContent{Parts: &parts},
			OutputDimensionality: outDim,
		})
	}
	payload := providers.GeminiBatchEmbedContentsRequest{Requests: reqs}
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	endpoint, err := a.resolveModelActionEndpoint(credentialOf(dep), model, "batchEmbedContents", "")
	if err != nil {
		return nil, err
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	if err := applyGeminiHeaders(httpReq, credentialOf(dep)); err != nil {
		return nil, err
	}

	resp, err := a.client.Do(httpReq)
	if err != nil {
		return nil, classifyGeminiTransportError(ctx, "batchEmbedContents", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, parseGeminiUpstreamError(resp)
	}
	respBody, err := adapter.ReadBoundedBody(resp.Body, adapter.DefaultMaxResponseBytes, domain.ProviderGemini)
	if err != nil {
		return nil, err
	}
	var batchResp providers.GeminiBatchEmbedContentsResponse
	if err := json.Unmarshal(respBody, &batchResp); err != nil {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusBadGateway,
			Type:       domain.ErrorTypeUpstream,
			Code:       "invalid_upstream_json",
			Message:    fmt.Sprintf("failed to parse Gemini batchEmbedContents response: %v", err),
			Provider:   domain.ProviderGemini,
		}
	}

	var data []domain.EmbeddingData
	if batchResp.Embeddings != nil {
		data = make([]domain.EmbeddingData, 0, len(*batchResp.Embeddings))
		for i, emb := range *batchResp.Embeddings {
			var vec []float64
			if emb.Values != nil {
				vec = *emb.Values
			}
			data = append(data, domain.EmbeddingData{
				Object:    "embedding",
				Index:     i,
				Embedding: vec,
			})
		}
	}
	var usage domain.TokenUsage
	if batchResp.UsageMetadata != nil {
		usage = extractGeminiUsage(batchResp.UsageMetadata)
	}
	return &domain.CanonicalEmbeddingResponse{
		Object:   "list",
		Model:    model,
		Provider: domain.ProviderGemini,
		Data:     data,
		Usage:    usage,
	}, nil
}

// =============================================================================
// Model Discovery (/v1beta/models)
// =============================================================================

// ListModels fetches available Gemini models via GET /v1beta/models with bounded pagination.
func (a *Adapter) ListModels(ctx context.Context, cred *domain.ProviderCredential) ([]domain.DiscoveredModel, error) {
	base, err := adapter.ResolveCredentialBaseURL(cred, defaultBaseURL, a.ssrfPolicy, domain.ProviderGemini)
	if err != nil {
		return nil, err
	}

	var out []domain.DiscoveredModel
	seen := make(map[string]struct{})
	pageToken := ""

	for page := 0; page < maxListModelPages; page++ {
		endpoint := base + "/v1beta/models?pageSize=100"
		if pageToken != "" {
			endpoint += "&pageToken=" + url.QueryEscape(pageToken)
		}
		httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return nil, err
		}
		if err := applyGeminiHeaders(httpReq, cred); err != nil {
			return nil, err
		}

		resp, err := a.client.Do(httpReq)
		if err != nil {
			return nil, classifyGeminiTransportError(ctx, "listModels", err)
		}
		if resp.StatusCode != http.StatusOK {
			gwErr := parseGeminiUpstreamError(resp)
			_ = resp.Body.Close()
			return nil, gwErr
		}
		respBody, readErr := adapter.ReadBoundedBody(resp.Body, adapter.DefaultMaxResponseBytes, domain.ProviderGemini)
		_ = resp.Body.Close()
		if readErr != nil {
			return nil, readErr
		}

		var list providers.GeminiListModelsResponse
		if err := json.Unmarshal(respBody, &list); err != nil {
			return nil, &domain.GatewayError{
				StatusCode: http.StatusBadGateway,
				Type:       domain.ErrorTypeUpstream,
				Code:       "invalid_upstream_json",
				Message:    "failed to parse Gemini listModels response",
				Provider:   domain.ProviderGemini,
			}
		}
		if list.Models != nil {
			for _, m := range *list.Models {
				if !isCallableGeminiModel(m.SupportedGenerationMethods) {
					continue
				}
				name := strings.TrimPrefix(strings.TrimSpace(m.Name), "models/")
				if name == "" {
					continue
				}
				if _, dup := seen[name]; dup {
					continue
				}
				seen[name] = struct{}{}

				display := name
				if m.DisplayName != nil && strings.TrimSpace(*m.DisplayName) != "" {
					display = strings.TrimSpace(*m.DisplayName)
				}
				out = append(out, domain.DiscoveredModel{
					Provider:    domain.ProviderGemini,
					ModelName:   name,
					DisplayName: display,
				})
			}
		}

		if list.NextPageToken == nil || strings.TrimSpace(*list.NextPageToken) == "" {
			break
		}
		pageToken = strings.TrimSpace(*list.NextPageToken)
	}

	return out, nil
}

func isCallableGeminiModel(methods *[]string) bool {
	if methods == nil || len(*methods) == 0 {
		return true
	}
	for _, m := range *methods {
		if m == "generateContent" || m == "embedContent" {
			return true
		}
	}
	return false
}

// =============================================================================
// Request Translation & Wire Mapping Helpers
// =============================================================================

func (a *Adapter) buildGeminiGenerateContentRequest(ctx context.Context, model string, req *domain.CanonicalChatRequest) (*providers.GeminiGenerateContentRequest, error) {
	if req == nil {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_request",
			Message:    "chat request is nil",
			Provider:   domain.ProviderGemini,
		}
	}

	out := &providers.GeminiGenerateContentRequest{}
	var systemParts []providers.GeminiPart
	var contents []providers.GeminiContent
	toolCallNames := make(map[string]string)
	mediaBudget := newMediaFetchBudget()

	for _, msg := range req.Messages {
		role := strings.ToLower(strings.TrimSpace(msg.Role))
		switch role {
		case "system", "developer":
			parts, err := a.translateMessageParts(ctx, msg, mediaBudget)
			if err != nil {
				return nil, err
			}
			systemParts = append(systemParts, parts...)

		case "user":
			parts, err := a.translateMessageParts(ctx, msg, mediaBudget)
			if err != nil {
				return nil, err
			}
			if len(parts) > 0 {
				contents = appendMergedContent(contents, "user", parts)
			}

		case "assistant", "model":
			parts, err := a.translateMessageParts(ctx, msg, mediaBudget)
			if err != nil {
				return nil, err
			}
			for _, tc := range msg.ToolCalls {
				if tc.ID != "" && tc.Function.Name != "" {
					toolCallNames[tc.ID] = tc.Function.Name
				}
				args := parseJSONObjectOrWrap(tc.Function.Arguments, "input")
				var callID *string
				if tc.ID != "" {
					idCopy := tc.ID
					callID = &idCopy
				}
				parts = append(parts, providers.GeminiPart{
					FunctionCall: &providers.GeminiFunctionCall{
						Id:   callID,
						Name: tc.Function.Name,
						Args: &args,
					},
				})
			}
			if len(parts) > 0 {
				contents = appendMergedContent(contents, "model", parts)
			}

		case "tool":
			fnName := strings.TrimSpace(msg.Name)
			if fnName == "" && msg.ToolCallID != "" {
				fnName = toolCallNames[msg.ToolCallID]
			}
			if fnName == "" {
				fnName = "tool"
			}
			respObj := parseJSONObjectOrWrap(msg.Content, "result")
			var callID *string
			if msg.ToolCallID != "" {
				idCopy := msg.ToolCallID
				callID = &idCopy
			}
			part := providers.GeminiPart{
				FunctionResponse: &providers.GeminiFunctionResponse{
					Id:       callID,
					Name:     fnName,
					Response: respObj,
				},
			}
			contents = appendMergedContent(contents, "user", []providers.GeminiPart{part})
		}
	}

	if len(systemParts) > 0 {
		out.SystemInstruction = &providers.GeminiContent{Parts: &systemParts}
	}
	if len(contents) == 0 {
		empty := ""
		parts := []providers.GeminiPart{{Text: &empty}}
		userRole := "user"
		contents = []providers.GeminiContent{{Role: &userRole, Parts: &parts}}
	}
	out.Contents = contents

	if len(req.Tools) > 0 {
		decls := make([]providers.GeminiFunctionDeclaration, 0, len(req.Tools))
		for _, t := range req.Tools {
			decl := providers.GeminiFunctionDeclaration{
				Name: t.Function.Name,
			}
			if t.Function.Description != "" {
				desc := t.Function.Description
				decl.Description = &desc
			}
			if len(t.Function.Parameters) > 0 {
				params := t.Function.Parameters
				decl.ParametersJsonSchema = &params
			}
			decls = append(decls, decl)
		}
		tools := []providers.GeminiTool{{FunctionDeclarations: &decls}}
		out.Tools = &tools
	}

	if tc := buildGeminiToolConfig(req.ToolChoice); tc != nil {
		out.ToolConfig = tc
	}

	genCfg := buildGeminiGenerationConfig(model, req)
	if genCfg != nil {
		out.GenerationConfig = genCfg
	}

	// Sensitive top-level ExtraParams passthrough is fail-closed by default to prevent
	// cross-tenant cached_content IDOR on shared keys and end-user safety threshold downgrades.
	if len(req.ExtraParams) > 0 {
		if a.allowCachedContent {
			if v, ok := req.ExtraParams["cached_content"].(string); ok && strings.TrimSpace(v) != "" {
				trimmed := strings.TrimSpace(v)
				if !cachedContentNamePattern.MatchString(trimmed) {
					return nil, &domain.GatewayError{
						StatusCode: http.StatusBadRequest,
						Type:       domain.ErrorTypeInvalidRequest,
						Code:       "invalid_cached_content",
						Message:    "cached_content must match cachedContents/<id>",
						Provider:   domain.ProviderGemini,
					}
				}
				out.CachedContent = &trimmed
			}
		}
		if a.allowSafetySettingsOverride {
			if rawSafety, ok := req.ExtraParams["safety_settings"]; ok && rawSafety != nil {
				if b, mErr := json.Marshal(rawSafety); mErr == nil {
					var safety []providers.GeminiSafetySetting
					if uErr := json.Unmarshal(b, &safety); uErr == nil && len(safety) > 0 {
						out.SafetySettings = &safety
					}
				}
			}
		}
	}

	return out, nil
}

type mediaFetchBudget struct {
	remainingParts int
	remainingBytes int64
}

func newMediaFetchBudget() *mediaFetchBudget {
	return &mediaFetchBudget{
		remainingParts: maxRemoteMediaPartsPerRequest,
		remainingBytes: maxTotalRemoteMediaBytesPerRequest,
	}
}

func (b *mediaFetchBudget) allocateFetchLimit() (int64, error) {
	if b.remainingParts <= 0 {
		return 0, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_media_url",
			Message:    fmt.Sprintf("request exceeds maximum of %d remote media URLs", maxRemoteMediaPartsPerRequest),
			Provider:   domain.ProviderGemini,
		}
	}
	if b.remainingBytes <= 0 {
		return 0, &domain.GatewayError{
			StatusCode: http.StatusRequestEntityTooLarge,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_media_url",
			Message:    fmt.Sprintf("request exceeds aggregate %d byte remote media budget", maxTotalRemoteMediaBytesPerRequest),
			Provider:   domain.ProviderGemini,
		}
	}
	limit := maxRemoteMediaBytes
	if b.remainingBytes < limit {
		limit = b.remainingBytes
	}
	return limit, nil
}

func (b *mediaFetchBudget) consume(decodedBytes int64) {
	b.remainingParts--
	if decodedBytes > 0 {
		b.remainingBytes -= decodedBytes
	}
}

func isAllowedInlineMIME(mimeType string, allowedTypes ...string) bool {
	lower := strings.ToLower(strings.TrimSpace(mimeType))
	if lower == "" {
		return false
	}
	for _, candidate := range allowedTypes {
		if strings.HasSuffix(candidate, "/") {
			if strings.HasPrefix(lower, candidate) {
				return true
			}
		} else if lower == candidate {
			return true
		}
	}
	return false
}

func validateInlineBase64Payload(b64 string) error {
	if int64(base64.StdEncoding.DecodedLen(len(b64))) > maxInlineMediaBytes {
		return &domain.GatewayError{
			StatusCode: http.StatusRequestEntityTooLarge,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_media_url",
			Message:    fmt.Sprintf("inline media payload exceeds %d byte limit", maxInlineMediaBytes),
			Provider:   domain.ProviderGemini,
		}
	}
	if _, err := io.Copy(io.Discard, base64.NewDecoder(base64.StdEncoding, strings.NewReader(b64))); err != nil {
		return &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_media_url",
			Message:    "inline media payload is not valid base64",
			Provider:   domain.ProviderGemini,
		}
	}
	return nil
}

func (a *Adapter) translateMessageParts(ctx context.Context, msg domain.CanonicalMessage, budget *mediaFetchBudget) ([]providers.GeminiPart, error) {
	if len(msg.Parts) == 0 {
		if msg.Content == "" {
			return nil, nil
		}
		text := msg.Content
		return []providers.GeminiPart{{Text: &text}}, nil
	}
	if budget == nil {
		budget = newMediaFetchBudget()
	}

	parts := make([]providers.GeminiPart, 0, len(msg.Parts))
	for _, p := range msg.Parts {
		switch p.Type {
		case "text":
			if p.Text != "" {
				text := p.Text
				parts = append(parts, providers.GeminiPart{Text: &text})
			}
		case "image_url":
			if p.ImageURL == nil || strings.TrimSpace(p.ImageURL.URL) == "" {
				continue
			}
			rawURL := strings.TrimSpace(p.ImageURL.URL)
			if mimeType, b64, ok := parseDataURI(rawURL); ok {
				if !isAllowedInlineMIME(mimeType, "image/", "application/pdf", "audio/", "video/") {
					return nil, &domain.GatewayError{
						StatusCode: http.StatusBadRequest,
						Type:       domain.ErrorTypeInvalidRequest,
						Code:       "invalid_media_url",
						Message:    fmt.Sprintf("inline media MIME type %q is unsupported", mimeType),
						Provider:   domain.ProviderGemini,
					}
				}
				if err := validateInlineBase64Payload(b64); err != nil {
					return nil, err
				}
				parts = append(parts, providers.GeminiPart{
					InlineData: &providers.GeminiBlob{MimeType: mimeType, Data: b64},
				})
				continue
			}
			fetchLimit, err := budget.allocateFetchLimit()
			if err != nil {
				return nil, err
			}
			dataURI, err := adapter.FetchRemoteDataURIWithPolicy(
				ctx,
				a.effectiveMediaClient(),
				a.mediaPolicy,
				rawURL,
				fetchLimit,
				"image/",
				"application/pdf",
				"audio/",
				"video/",
			)
			if err != nil {
				return nil, &domain.GatewayError{
					StatusCode: http.StatusBadRequest,
					Type:       domain.ErrorTypeInvalidRequest,
					Code:       "invalid_media_url",
					Message:    fmt.Sprintf("failed to fetch remote media URL: %v", err),
					Provider:   domain.ProviderGemini,
				}
			}
			if mimeType, b64, ok := parseDataURI(dataURI); ok {
				budget.consume(int64(base64.StdEncoding.DecodedLen(len(b64))))
				parts = append(parts, providers.GeminiPart{
					InlineData: &providers.GeminiBlob{MimeType: mimeType, Data: b64},
				})
			}
		case "document":
			if p.Document == nil {
				continue
			}
			if p.Document.Data != "" {
				mimeType := strings.TrimSpace(p.Document.MimeType)
				if mimeType == "" {
					mimeType = "application/pdf"
				}
				if !isAllowedInlineMIME(mimeType, "application/pdf", "text/", "image/") {
					return nil, &domain.GatewayError{
						StatusCode: http.StatusBadRequest,
						Type:       domain.ErrorTypeInvalidRequest,
						Code:       "invalid_media_url",
						Message:    fmt.Sprintf("inline document MIME type %q is unsupported", mimeType),
						Provider:   domain.ProviderGemini,
					}
				}
				if err := validateInlineBase64Payload(p.Document.Data); err != nil {
					return nil, err
				}
				parts = append(parts, providers.GeminiPart{
					InlineData: &providers.GeminiBlob{MimeType: mimeType, Data: p.Document.Data},
				})
			} else if strings.TrimSpace(p.Document.URL) != "" {
				fetchLimit, err := budget.allocateFetchLimit()
				if err != nil {
					return nil, err
				}
				dataURI, err := adapter.FetchRemoteDataURIWithPolicy(
					ctx,
					a.effectiveMediaClient(),
					a.mediaPolicy,
					strings.TrimSpace(p.Document.URL),
					fetchLimit,
					"application/pdf",
					"text/",
					"image/",
				)
				if err != nil {
					return nil, &domain.GatewayError{
						StatusCode: http.StatusBadRequest,
						Type:       domain.ErrorTypeInvalidRequest,
						Code:       "invalid_media_url",
						Message:    fmt.Sprintf("failed to fetch remote document URL: %v", err),
						Provider:   domain.ProviderGemini,
					}
				}
				if mimeType, b64, ok := parseDataURI(dataURI); ok {
					budget.consume(int64(base64.StdEncoding.DecodedLen(len(b64))))
					parts = append(parts, providers.GeminiPart{
						InlineData: &providers.GeminiBlob{MimeType: mimeType, Data: b64},
					})
				}
			}
		}
	}
	return parts, nil
}

func appendMergedContent(contents []providers.GeminiContent, role string, parts []providers.GeminiPart) []providers.GeminiContent {
	if len(parts) == 0 {
		return contents
	}
	if n := len(contents); n > 0 && contents[n-1].Role != nil && *contents[n-1].Role == role {
		if contents[n-1].Parts == nil {
			p := append([]providers.GeminiPart(nil), parts...)
			contents[n-1].Parts = &p
		} else {
			merged := append(*contents[n-1].Parts, parts...)
			contents[n-1].Parts = &merged
		}
		return contents
	}
	roleCopy := role
	partsCopy := append([]providers.GeminiPart(nil), parts...)
	return append(contents, providers.GeminiContent{
		Role:  &roleCopy,
		Parts: &partsCopy,
	})
}

func buildGeminiToolConfig(tc any) *providers.GeminiToolConfig {
	if tc == nil {
		return nil
	}
	switch v := tc.(type) {
	case string:
		var mode providers.GeminiFunctionCallingConfigMode
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "auto":
			mode = providers.AUTO
		case "required", "any":
			mode = providers.ANY
		case "none":
			mode = providers.NONE
		default:
			return nil
		}
		return &providers.GeminiToolConfig{
			FunctionCallingConfig: &providers.GeminiFunctionCallingConfig{Mode: &mode},
		}
	case map[string]any:
		if fn, ok := v["function"].(map[string]any); ok {
			if name, _ := fn["name"].(string); strings.TrimSpace(name) != "" {
				mode := providers.ANY
				allowed := []string{strings.TrimSpace(name)}
				return &providers.GeminiToolConfig{
					FunctionCallingConfig: &providers.GeminiFunctionCallingConfig{
						Mode:                 &mode,
						AllowedFunctionNames: &allowed,
					},
				}
			}
		}
	}
	return nil
}

func buildGeminiGenerationConfig(model string, req *domain.CanonicalChatRequest) *providers.GeminiGenerationConfig {
	cfg := &providers.GeminiGenerationConfig{}
	hasField := false

	if req.Temperature != nil {
		v := *req.Temperature
		cfg.Temperature = &v
		hasField = true
	}
	if req.TopP != nil {
		v := *req.TopP
		cfg.TopP = &v
		hasField = true
	}
	if req.MaxTokens != nil && *req.MaxTokens > 0 {
		if v, ok := safeIntToInt32(*req.MaxTokens); ok {
			cfg.MaxOutputTokens = &v
			hasField = true
		}
	}
	if len(req.Stop) > 0 {
		stops := append([]string(nil), req.Stop...)
		cfg.StopSequences = &stops
		hasField = true
	}

	if req.ResponseFormat != nil {
		switch strings.ToLower(strings.TrimSpace(req.ResponseFormat.Type)) {
		case "json_object":
			mime := "application/json"
			cfg.ResponseMimeType = &mime
			hasField = true
		case "json_schema":
			mime := "application/json"
			cfg.ResponseMimeType = &mime
			if len(req.ResponseFormat.JSONSchema) > 0 {
				schema := req.ResponseFormat.JSONSchema
				if inner, ok := schema["schema"].(map[string]any); ok && len(inner) > 0 {
					schema = inner
				}
				cfg.ResponseJsonSchema = &schema
			}
			hasField = true
		}
	}

	if effort := strings.ToLower(strings.TrimSpace(req.ReasoningEffort)); effort != "" {
		include := true
		if usesGeminiThinkingLevel(model) {
			level := mapGeminiThinkingLevel(effort)
			cfg.ThinkingConfig = &providers.GeminiThinkingConfig{
				IncludeThoughts: &include,
				ThinkingLevel:   &level,
			}
		} else {
			budget := mapGeminiThinkingBudget(effort)
			cfg.ThinkingConfig = &providers.GeminiThinkingConfig{
				IncludeThoughts: &include,
				ThinkingBudget:  &budget,
			}
		}
		hasField = true
	}

	if len(req.ExtraParams) > 0 {
		if v, ok := asInt32(req.ExtraParams["top_k"]); ok && v > 0 {
			cfg.TopK = &v
			hasField = true
		}
		if v, ok := asInt32(req.ExtraParams["seed"]); ok {
			cfg.Seed = &v
			hasField = true
		}
		if v, ok := asFloat64(req.ExtraParams["presence_penalty"]); ok {
			cfg.PresencePenalty = &v
			hasField = true
		}
		if v, ok := asFloat64(req.ExtraParams["frequency_penalty"]); ok {
			cfg.FrequencyPenalty = &v
			hasField = true
		}
		if v, ok := asInt32(req.ExtraParams["thinking_budget"]); ok && v >= 0 && v <= maxGeminiThinkingBudget {
			include := true
			cfg.ThinkingConfig = &providers.GeminiThinkingConfig{
				IncludeThoughts: &include,
				ThinkingBudget:  &v,
			}
			hasField = true
		}
	}

	if !hasField {
		return nil
	}
	return cfg
}

// usesGeminiThinkingLevel reports whether model uses Gemini 3.x thinkingLevel
// instead of Gemini 2.5 thinkingBudget. Setting thinkingLevel on Gemini 2.5
// models is rejected by Google's v1beta API.
func usesGeminiThinkingLevel(model string) bool {
	lower := strings.ToLower(strings.TrimSpace(model))
	return strings.HasPrefix(lower, "gemini-3") || strings.HasPrefix(lower, "gemini-4")
}

func mapGeminiThinkingLevel(effort string) providers.GeminiThinkingConfigThinkingLevel {
	switch effort {
	case "minimal":
		return providers.MINIMAL
	case "low":
		return providers.LOW
	case "high", "xhigh", "max":
		return providers.HIGH
	default:
		return providers.MEDIUM
	}
}

func mapGeminiThinkingBudget(effort string) int32 {
	switch effort {
	case "minimal":
		return 512
	case "low":
		return 1024
	case "high", "xhigh", "max":
		return 8192
	default:
		return 4096
	}
}

func toCanonicalChatResponse(model string, gemResp *providers.GeminiGenerateContentResponse) *domain.CanonicalChatResponse {
	id := fmt.Sprintf("chatcmpl-gem-%d", time.Now().UnixNano())
	if gemResp.ResponseId != nil && *gemResp.ResponseId != "" {
		id = *gemResp.ResponseId
	}
	respModel := model
	if gemResp.ModelVersion != nil && *gemResp.ModelVersion != "" {
		respModel = *gemResp.ModelVersion
	}

	var choices []domain.CanonicalChoice
	if gemResp.Candidates != nil && len(*gemResp.Candidates) > 0 {
		choices = make([]domain.CanonicalChoice, 0, len(*gemResp.Candidates))
		for i, cand := range *gemResp.Candidates {
			var textBuf strings.Builder
			var thoughtBuf strings.Builder
			var toolCalls []domain.CanonicalToolCall

			if cand.Content != nil && cand.Content.Parts != nil {
				for _, p := range *cand.Content.Parts {
					if p.Text != nil && *p.Text != "" {
						if p.Thought != nil && *p.Thought {
							thoughtBuf.WriteString(*p.Text)
						} else {
							textBuf.WriteString(*p.Text)
						}
					}
					if p.FunctionCall != nil {
						callID := fmt.Sprintf("call_gemini_%d", len(toolCalls))
						if p.FunctionCall.Id != nil && *p.FunctionCall.Id != "" {
							callID = *p.FunctionCall.Id
						}
						argsStr := "{}"
						if p.FunctionCall.Args != nil {
							if b, err := json.Marshal(*p.FunctionCall.Args); err == nil {
								argsStr = string(b)
							}
						}
						toolCalls = append(toolCalls, domain.CanonicalToolCall{
							ID:   callID,
							Type: "function",
							Function: domain.CanonicalFunctionCall{
								Name:      p.FunctionCall.Name,
								Arguments: argsStr,
							},
						})
					}
				}
			}

			rawFinish := ""
			if cand.FinishReason != nil {
				rawFinish = *cand.FinishReason
			}
			idx := i
			if cand.Index != nil {
				idx = int(*cand.Index)
			}
			choices = append(choices, domain.CanonicalChoice{
				Index: idx,
				Message: domain.CanonicalMessage{
					Role:             "assistant",
					Content:          textBuf.String(),
					ReasoningContent: thoughtBuf.String(),
					ToolCalls:        toolCalls,
				},
				FinishReason: mapGeminiFinishReason(rawFinish, len(toolCalls) > 0),
			})
		}
	} else if gemResp.PromptFeedback != nil && gemResp.PromptFeedback.BlockReason != nil && *gemResp.PromptFeedback.BlockReason != "" {
		choices = []domain.CanonicalChoice{
			{
				Index:        0,
				Message:      domain.CanonicalMessage{Role: "assistant"},
				FinishReason: "content_filter",
			},
		}
	}

	var usage domain.TokenUsage
	if gemResp.UsageMetadata != nil {
		usage = extractGeminiUsage(gemResp.UsageMetadata)
	}

	return &domain.CanonicalChatResponse{
		ID:       id,
		Object:   "chat.completion",
		Created:  time.Now().Unix(),
		Model:    respModel,
		Provider: domain.ProviderGemini,
		Choices:  choices,
		Usage:    usage,
	}
}

// extractGeminiUsage maps Gemini's UsageMetadata to GoRoute's canonical TokenUsage.
// Because Gemini reports candidatesTokenCount excluding thoughtsTokenCount, we add
// thoughtsTokenCount into CompletionTokens so finops.CalculateCostMicros bills both
// regular output and reasoning tokens accurately without underbilling.
func extractGeminiUsage(meta *providers.GeminiUsageMetadata) domain.TokenUsage {
	if meta == nil {
		return domain.TokenUsage{}
	}
	prompt := clampNonNeg(int32Val(meta.PromptTokenCount))
	cached := clampNonNeg(int32Val(meta.CachedContentTokenCount))
	if cached > prompt {
		cached = prompt
	}
	candidates := clampNonNeg(int32Val(meta.CandidatesTokenCount))
	thoughts := clampNonNeg(int32Val(meta.ThoughtsTokenCount))
	completion := candidates + thoughts
	total := clampNonNeg(int32Val(meta.TotalTokenCount))
	if total < prompt+completion {
		total = prompt + completion
	}
	return domain.TokenUsage{
		PromptTokens:       prompt,
		CompletionTokens:   completion,
		TotalTokens:        total,
		CachedPromptTokens: cached,
		ReasoningTokens:    thoughts,
	}
}

func clampNonNeg(v int) int {
	if v < 0 {
		return 0
	}
	return v
}

func mapGeminiFinishReason(raw string, hasToolCalls bool) string {
	upper := strings.ToUpper(strings.TrimSpace(raw))
	if hasToolCalls && (upper == "" || upper == "STOP") {
		return "tool_calls"
	}
	switch upper {
	case "STOP", "":
		return "stop"
	case "MAX_TOKENS":
		return "length"
	case "SAFETY", "RECITATION", "BLOCKLIST", "PROHIBITED_CONTENT", "SPII", "IMAGE_SAFETY", "LANGUAGE":
		return "content_filter"
	default:
		return "stop"
	}
}

// =============================================================================
// Endpoint Resolution, Auth, Error Classification & Parsing Utilities
// =============================================================================

func (a *Adapter) resolveModelActionEndpoint(cred *domain.ProviderCredential, model, action, query string) (string, error) {
	base, err := adapter.ResolveCredentialBaseURL(cred, defaultBaseURL, a.ssrfPolicy, domain.ProviderGemini)
	if err != nil {
		return "", err
	}
	endpoint := fmt.Sprintf("%s/v1beta/models/%s:%s", base, url.PathEscape(model), action)
	if query != "" {
		endpoint += "?" + query
	}
	return endpoint, nil
}

func resolveGeminiModel(dep *domain.Deployment, req *domain.CanonicalChatRequest) (string, error) {
	raw := ""
	if req != nil {
		raw = req.ResolvedModel
	}
	if raw == "" && dep != nil && dep.GlobalModel != nil {
		raw = dep.GlobalModel.ModelName
	}
	if raw == "" && req != nil {
		raw = req.Model
	}
	return normalizeGeminiModel(raw)
}

func normalizeGeminiModel(raw string) (string, error) {
	m := strings.TrimSpace(raw)
	m = strings.TrimPrefix(m, "gemini/")
	m = strings.TrimPrefix(m, "models/")
	if m == "" {
		return "", &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_model",
			Message:    "Gemini model identifier is required",
			Provider:   domain.ProviderGemini,
		}
	}
	if len(m) > maxGeminiModelIDLen || strings.Contains(m, "..") {
		return "", &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_model",
			Message:    "Gemini model identifier contains invalid path characters",
			Provider:   domain.ProviderGemini,
		}
	}
	for i := 0; i < len(m); i++ {
		c := m[i]
		isAlphaNum := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		if i == 0 && !isAlphaNum {
			return "", &domain.GatewayError{
				StatusCode: http.StatusBadRequest,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "invalid_model",
				Message:    "Gemini model identifier must start with an alphanumeric character",
				Provider:   domain.ProviderGemini,
			}
		}
		if !isAlphaNum && c != '.' && c != '_' && c != '-' {
			return "", &domain.GatewayError{
				StatusCode: http.StatusBadRequest,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "invalid_model",
				Message:    "Gemini model identifier contains invalid characters",
				Provider:   domain.ProviderGemini,
			}
		}
	}
	return m, nil
}

func credentialOf(dep *domain.Deployment) *domain.ProviderCredential {
	if dep == nil {
		return nil
	}
	return dep.Credential
}

func applyGeminiHeaders(req *http.Request, cred *domain.ProviderCredential) error {
	req.Header.Set("Content-Type", "application/json")
	observability.InjectTraceHeaders(req.Context(), req)
	if cred != nil {
		adapter.ApplySafeCustomHeaders(req, cred.Headers)
		if apiKey := strings.TrimSpace(cred.DecryptedAPIKey); apiKey != "" {
			req.Header.Set("x-goog-api-key", apiKey)
		}
	}
	if req.Header.Get("x-goog-api-key") == "" && req.Header.Get("Authorization") == "" {
		return &domain.GatewayError{
			StatusCode:  http.StatusUnauthorized,
			Type:        domain.ErrorTypeAuthentication,
			Code:        "missing_api_key",
			Message:     "missing Gemini API key credential",
			Provider:    domain.ProviderGemini,
			AuthFailure: true,
		}
	}
	return nil
}

func classifyGeminiTransportError(ctx context.Context, op string, err error) *domain.GatewayError {
	logger.WarnContext(ctx, "Gemini upstream transport error",
		slog.String("provider", string(domain.ProviderGemini)),
		slog.String("operation", op),
		slog.String("error", logger.ScrubSecrets(err.Error())),
	)
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return &domain.GatewayError{
			StatusCode: http.StatusGatewayTimeout,
			Type:       domain.ErrorTypeUpstream,
			Code:       "upstream_timeout",
			Message:    "Gemini upstream request timed out",
			Provider:   domain.ProviderGemini,
			Retryable:  true,
		}
	}
	return &domain.GatewayError{
		StatusCode: http.StatusBadGateway,
		Type:       domain.ErrorTypeUpstream,
		Code:       "upstream_network_error",
		Message:    "Gemini upstream request failed",
		Provider:   domain.ProviderGemini,
		Retryable:  true,
	}
}

func parseGeminiUpstreamError(resp *http.Response) error {
	errBody, err := adapter.ReadBoundedBody(resp.Body, adapter.DefaultMaxErrorBytes, domain.ProviderGemini)
	if err != nil {
		return err
	}
	msg := strings.TrimSpace(string(errBody))
	var parsed providers.GeminiErrorResponse
	if json.Unmarshal(errBody, &parsed) == nil && parsed.Error != nil && parsed.Error.Message != nil && strings.TrimSpace(*parsed.Error.Message) != "" {
		msg = strings.TrimSpace(*parsed.Error.Message)
	}
	msg = logger.ScrubSecrets(msg)
	return domain.ClassifyUpstreamStatus(domain.ProviderGemini, resp.StatusCode, msg, adapter.ParseRetryAfter(resp.Header))
}

func parseDataURI(uri string) (mimeType, b64 string, ok bool) {
	if !strings.HasPrefix(uri, "data:") {
		return "", "", false
	}
	rest := strings.TrimPrefix(uri, "data:")
	idx := strings.Index(rest, ";base64,")
	if idx <= 0 {
		return "", "", false
	}
	return rest[:idx], rest[idx+len(";base64,"):], true
}

func parseJSONObjectOrWrap(raw, fallbackKey string) map[string]any {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return map[string]any{}
	}
	var obj map[string]any
	if err := json.Unmarshal([]byte(trimmed), &obj); err == nil && obj != nil {
		return obj
	}
	return map[string]any{fallbackKey: raw}
}

func int32Val(p *int32) int {
	if p == nil {
		return 0
	}
	return int(*p)
}

func safeIntToInt32(n int) (int32, bool) {
	if n < math.MinInt32 || n > math.MaxInt32 {
		return 0, false
	}
	return int32(n), true
}

func asInt32(v any) (int32, bool) {
	switch n := v.(type) {
	case int:
		return safeIntToInt32(n)
	case int32:
		return n, true
	case int64:
		if n < math.MinInt32 || n > math.MaxInt32 {
			return 0, false
		}
		return int32(n), true
	case float64:
		if math.IsNaN(n) || math.IsInf(n, 0) || n < float64(math.MinInt32) || n > float64(math.MaxInt32) || math.Trunc(n) != n {
			return 0, false
		}
		return int32(n), true
	default:
		return 0, false
	}
}

func asFloat64(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		if math.IsNaN(n) || math.IsInf(n, 0) {
			return 0, false
		}
		return n, true
	case float32:
		f := float64(n)
		if math.IsNaN(f) || math.IsInf(f, 0) {
			return 0, false
		}
		return f, true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	default:
		return 0, false
	}
}
