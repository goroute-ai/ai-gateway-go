package openai

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
	"strconv"
	"strings"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/adapter"
	"github.com/goroute-ai/ai-gateway-go/internal/adapter/sse"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/observability"
	"github.com/goroute-ai/ai-gateway-go/internal/openapi/providers"
)

const defaultBaseURL = "https://api.openai.com/v1"

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
	return domain.ProviderOpenAI
}

func resolveBaseURL(cred *domain.ProviderCredential) string {
	if cred != nil && strings.TrimSpace(cred.BaseURL) != "" {
		return strings.TrimRight(cred.BaseURL, "/")
	}
	return defaultBaseURL
}

func isReasoningModel(model string) bool {
	m := strings.ToLower(model)
	return strings.HasPrefix(m, "o1") ||
		strings.HasPrefix(m, "o3") ||
		strings.HasPrefix(m, "o4") ||
		strings.HasPrefix(m, "gpt-5")
}

func mapOpenAIReasoningEffort(effort string) string {
	switch strings.ToLower(strings.TrimSpace(effort)) {
	case "max":
		return "xhigh"
	default:
		return effort
	}
}

func toOpenAIRequest(model string, req *domain.CanonicalChatRequest, stream bool) providers.OpenAIChatCompletionRequest {
	reasoning := isReasoningModel(model)

	msgs := make([]providers.OpenAIMessage, 0, len(req.Messages))
	for _, m := range req.Messages {
		role := m.Role
		if reasoning && (role == "system") {
			// OpenAI o1 and o3-mini reject role: "system" and require role: "developer"
			role = "developer"
		}
		om := providers.OpenAIMessage{
			Role:       role,
			Name:       m.Name,
			ToolCallID: m.ToolCallID,
		}
		if len(m.Parts) > 0 {
			om.Content = m.Parts
		} else {
			om.Content = m.Content
		}
		if len(m.ToolCalls) > 0 {
			for _, tc := range m.ToolCalls {
				om.ToolCalls = append(om.ToolCalls, providers.OpenAIToolCall{
					Index: tc.Index,
					ID:    tc.ID,
					Type:  tc.Type,
					Function: providers.OpenAIFunctionCall{
						Name:      tc.Function.Name,
						Arguments: tc.Function.Arguments,
					},
				})
			}
		}
		msgs = append(msgs, om)
	}

	var tools []providers.OpenAITool
	for _, t := range req.Tools {
		tools = append(tools, providers.OpenAITool{
			Type: t.Type,
			Function: providers.OpenAIFunction{
				Name:        t.Function.Name,
				Description: t.Function.Description,
				Parameters:  t.Function.Parameters,
				Strict:      t.Function.Strict,
			},
		})
	}

	out := providers.OpenAIChatCompletionRequest{
		Model:           model,
		Messages:        msgs,
		Tools:           tools,
		ToolChoice:      req.ToolChoice,
		Temperature:     req.Temperature,
		TopP:            req.TopP,
		MaxTokens:       req.MaxTokens,
		Stop:            req.Stop,
		Stream:          stream,
		ReasoningEffort: mapOpenAIReasoningEffort(req.ReasoningEffort),
		User:            req.User,
	}

	// OpenAI o1, o3, and o3-mini models reject custom temperature and top_p
	if reasoning {
		out.Temperature = nil
		out.TopP = nil
	}
	if stream {
		out.StreamOptions = &providers.OpenAIStreamOptions{IncludeUsage: true}
	}
	if req.ResponseFormat != nil {
		out.ResponseFormat = &providers.OpenAIResponseFormat{
			Type:       req.ResponseFormat.Type,
			JSONSchema: req.ResponseFormat.JSONSchema,
		}
	}
	return out
}

var protectedCoreChatFields = map[string]struct{}{
	"model":          {},
	"messages":       {},
	"stream":         {},
	"stream_options": {},
}

func marshalOpenAIRequestWithExtras(payload providers.OpenAIChatCompletionRequest, extra map[string]any) ([]byte, error) {
	bodyBytes, err := json.Marshal(payload)
	if err != nil || len(extra) == 0 {
		return bodyBytes, err
	}
	var merged map[string]any
	if err := json.Unmarshal(bodyBytes, &merged); err != nil {
		return nil, err
	}
	for k, v := range extra {
		if _, protected := protectedCoreChatFields[k]; protected {
			continue
		}
		if _, exists := merged[k]; exists {
			continue
		}
		merged[k] = v
	}
	return json.Marshal(merged)
}

func (a *Adapter) ChatCompletion(ctx context.Context, dep *domain.Deployment, req *domain.CanonicalChatRequest) (*domain.CanonicalChatResponse, error) {
	model := req.ResolvedModel
	if model == "" && dep != nil && dep.GlobalModel != nil {
		model = dep.GlobalModel.ModelName
	}
	if model == "" {
		model = req.Model
	}

	payload := toOpenAIRequest(model, req, false)
	bodyBytes, err := marshalOpenAIRequestWithExtras(payload, req.ExtraParams)
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
			Provider:   domain.ProviderOpenAI,
			Retryable:  true,
		}
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, domain.ClassifyUpstreamStatus(domain.ProviderOpenAI, resp.StatusCode, string(respBody), adapter.ParseRetryAfter(resp.Header))
	}

	var oaiResp providers.OpenAIChatCompletionResponse
	if err := json.Unmarshal(respBody, &oaiResp); err != nil {
		return nil, fmt.Errorf("decode openai response: %w", err)
	}

	choices := make([]domain.CanonicalChoice, 0, len(oaiResp.Choices))
	for _, c := range oaiResp.Choices {
		contentStr, _ := c.Message.Content.(string)
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
				Role:             c.Message.Role,
				Content:          contentStr,
				ReasoningContent: c.Message.ReasoningContent,
				ToolCalls:        tcs,
			},
			FinishReason: c.FinishReason,
		})
	}

	usage := domain.TokenUsage{
		PromptTokens:     oaiResp.Usage.PromptTokens,
		CompletionTokens: oaiResp.Usage.CompletionTokens,
		TotalTokens:      oaiResp.Usage.TotalTokens,
	}
	if oaiResp.Usage.PromptTokensDetails != nil {
		usage.CachedPromptTokens = oaiResp.Usage.PromptTokensDetails.CachedTokens
	}
	if oaiResp.Usage.CompletionTokensDetails != nil {
		usage.ReasoningTokens = oaiResp.Usage.CompletionTokensDetails.ReasoningTokens
	}

	return &domain.CanonicalChatResponse{
		ID:                oaiResp.ID,
		Object:            "chat.completion",
		Created:           oaiResp.Created,
		Model:             oaiResp.Model,
		Provider:          domain.ProviderOpenAI,
		Choices:           choices,
		Usage:             usage,
		SystemFingerprint: oaiResp.SystemFingerprint,
	}, nil
}

func (a *Adapter) StreamChatCompletion(ctx context.Context, dep *domain.Deployment, req *domain.CanonicalChatRequest, onChunk adapter.StreamChunkHandler) (*domain.TokenUsage, error) {
	ctx = adapter.StreamingContext(ctx)
	model := req.ResolvedModel
	if model == "" && dep != nil && dep.GlobalModel != nil {
		model = dep.GlobalModel.ModelName
	}
	if model == "" {
		model = req.Model
	}

	payload := toOpenAIRequest(model, req, true)
	bodyBytes, err := marshalOpenAIRequestWithExtras(payload, req.ExtraParams)
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
			Provider:   domain.ProviderOpenAI,
			Retryable:  true,
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		errBody, _ := io.ReadAll(resp.Body)
		return nil, domain.ClassifyUpstreamStatus(domain.ProviderOpenAI, resp.StatusCode, string(errBody), adapter.ParseRetryAfter(resp.Header))
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

	payload := providers.OpenAIEmbeddingRequest{
		Model:          model,
		Input:          req.Input,
		EncodingFormat: req.EncodingFormat,
		Dimensions:     req.Dimensions,
		User:           req.User,
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
			Provider:   domain.ProviderOpenAI,
			Retryable:  true,
		}
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, domain.ClassifyUpstreamStatus(domain.ProviderOpenAI, resp.StatusCode, string(respBody), adapter.ParseRetryAfter(resp.Header))
	}

	var oaiResp providers.OpenAIEmbeddingResponse
	if err := json.Unmarshal(respBody, &oaiResp); err != nil {
		return nil, err
	}
	data := make([]domain.EmbeddingData, 0, len(oaiResp.Data))
	for _, d := range oaiResp.Data {
		data = append(data, domain.EmbeddingData{
			Object:    "embedding",
			Index:     d.Index,
			Embedding: d.Embedding,
		})
	}
	return &domain.CanonicalEmbeddingResponse{
		Object:   "list",
		Data:     data,
		Model:    oaiResp.Model,
		Provider: domain.ProviderOpenAI,
		Usage: domain.TokenUsage{
			PromptTokens: oaiResp.Usage.PromptTokens,
			TotalTokens:  oaiResp.Usage.TotalTokens,
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
		return nil, domain.ClassifyUpstreamStatus(domain.ProviderOpenAI, resp.StatusCode, string(respBody), 0)
	}

	var list providers.OpenAIModelsResponse
	if err := json.Unmarshal(respBody, &list); err != nil {
		return nil, err
	}
	out := make([]domain.DiscoveredModel, 0, len(list.Data))
	for _, m := range list.Data {
		out = append(out, domain.DiscoveredModel{
			Provider:    domain.ProviderOpenAI,
			ModelName:   m.ID,
			DisplayName: m.ID,
			CreatedAt:   m.Created,
		})
	}
	return out, nil
}

// Moderate dispatches a text moderation request to the OpenAI Moderations API.
func (a *Adapter) Moderate(ctx context.Context, dep *domain.Deployment, req *domain.CanonicalModerationRequest) (*domain.CanonicalModerationResponse, error) {
	if dep == nil {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "missing_deployment",
			Message:    "deployment cannot be nil",
		}
	}
	model := dep.GlobalModel.ModelName
	if req.Model != "" {
		model = req.Model
	}

	bodyMap := map[string]any{
		"model": model,
		"input": req.Input,
	}
	bodyBytes, err := json.Marshal(bodyMap)
	if err != nil {
		return nil, fmt.Errorf("marshal moderation request: %w", err)
	}

	endpoint := resolveBaseURL(dep.Credential) + "/moderations"
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
			Code:       "openai_network_error",
			Message:    err.Error(),
			Retryable:  true,
		}
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		retryAfter := adapter.ParseRetryAfter(resp.Header)
		return nil, domain.ClassifyUpstreamStatus(domain.ProviderOpenAI, resp.StatusCode, string(respBytes), retryAfter)
	}

	var rawResp struct {
		ID      string `json:"id"`
		Model   string `json:"model"`
		Results []struct {
			Flagged        bool               `json:"flagged"`
			Categories     map[string]bool    `json:"categories"`
			CategoryScores map[string]float64 `json:"category_scores"`
		} `json:"results"`
	}
	if err := json.Unmarshal(respBytes, &rawResp); err != nil {
		return nil, fmt.Errorf("unmarshal moderation response: %w", err)
	}

	results := make([]domain.ModerationResultItem, len(rawResp.Results))
	for i, r := range rawResp.Results {
		results[i] = domain.ModerationResultItem{
			Flagged:        r.Flagged,
			Categories:     r.Categories,
			CategoryScores: r.CategoryScores,
		}
	}

	return &domain.CanonicalModerationResponse{
		ID:       rawResp.ID,
		Model:    rawResp.Model,
		Provider: domain.ProviderOpenAI,
		Results:  results,
	}, nil
}

// TextCompletion executes a legacy text completion request against OpenAI /v1/completions.
func (a *Adapter) TextCompletion(ctx context.Context, dep *domain.Deployment, req *domain.CanonicalCompletionRequest) (*domain.CanonicalCompletionResponse, error) {
	if dep == nil {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "missing_deployment",
			Message:    "deployment cannot be nil",
		}
	}

	model := dep.GlobalModel.ModelName
	if req.ResolvedModel != "" {
		model = req.ResolvedModel
	} else if req.Model != "" {
		model = req.Model
	}

	bodyMap := map[string]any{
		"model": model,
	}
	if len(req.Prompt.Strings) == 1 {
		bodyMap["prompt"] = req.Prompt.Strings[0]
	} else if len(req.Prompt.Strings) > 1 {
		bodyMap["prompt"] = req.Prompt.Strings
	}
	if req.MaxTokens != nil {
		bodyMap["max_tokens"] = *req.MaxTokens
	}
	if req.Temperature != nil {
		bodyMap["temperature"] = *req.Temperature
	}
	if req.TopP != nil {
		bodyMap["top_p"] = *req.TopP
	}
	if len(req.Stop) > 0 {
		bodyMap["stop"] = req.Stop
	}
	if req.User != "" {
		bodyMap["user"] = req.User
	}

	bodyBytes, err := json.Marshal(bodyMap)
	if err != nil {
		return nil, fmt.Errorf("marshal completion request: %w", err)
	}

	endpoint := resolveBaseURL(dep.Credential) + "/completions"
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
			Code:       "openai_network_error",
			Message:    err.Error(),
			Retryable:  true,
		}
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		retryAfter := adapter.ParseRetryAfter(resp.Header)
		return nil, domain.ClassifyUpstreamStatus(domain.ProviderOpenAI, resp.StatusCode, string(respBytes), retryAfter)
	}

	var rawResp struct {
		ID      string `json:"id"`
		Model   string `json:"model"`
		Choices []struct {
			Index        int    `json:"index"`
			Text         string `json:"text"`
			FinishReason string `json:"finish_reason"`
		} `json:"choices"`
		Usage struct {
			PromptTokens     int `json:"prompt_tokens"`
			CompletionTokens int `json:"completion_tokens"`
			TotalTokens      int `json:"total_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(respBytes, &rawResp); err != nil {
		return nil, fmt.Errorf("unmarshal completion response: %w", err)
	}

	choices := make([]domain.CanonicalCompletionChoice, len(rawResp.Choices))
	for i, c := range rawResp.Choices {
		choices[i] = domain.CanonicalCompletionChoice{
			Index:        c.Index,
			Text:         c.Text,
			FinishReason: c.FinishReason,
		}
	}

	return &domain.CanonicalCompletionResponse{
		ID:       rawResp.ID,
		Model:    rawResp.Model,
		Provider: domain.ProviderOpenAI,
		Choices:  choices,
		Usage: domain.TokenUsage{
			PromptTokens:     rawResp.Usage.PromptTokens,
			CompletionTokens: rawResp.Usage.CompletionTokens,
			TotalTokens:      rawResp.Usage.TotalTokens,
		},
	}, nil
}

// TranscribeAudio sends an audio file to OpenAI's transcriptions/translations endpoint.
func (a *Adapter) TranscribeAudio(ctx context.Context, dep *domain.Deployment, req *domain.CanonicalAudioTranscriptionRequest) (*domain.CanonicalAudioResponse, error) {
	if dep == nil {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "missing_deployment",
			Message:    "deployment cannot be nil",
		}
	}

	model := dep.GlobalModel.ModelName
	if req.ResolvedModel != "" {
		model = req.ResolvedModel
	} else if req.Model != "" {
		model = req.Model
	}

	bodyBuf := &bytes.Buffer{}
	mpWriter := multipart.NewWriter(bodyBuf)

	_ = mpWriter.WriteField("model", model)
	if req.Language != "" {
		_ = mpWriter.WriteField("language", req.Language)
	}
	if req.Prompt != "" {
		_ = mpWriter.WriteField("prompt", req.Prompt)
	}
	if req.ResponseFormat != "" {
		_ = mpWriter.WriteField("response_format", req.ResponseFormat)
	}
	if req.Temperature != nil {
		_ = mpWriter.WriteField("temperature", fmt.Sprintf("%f", *req.Temperature))
	}
	for _, tg := range req.TimestampGranularities {
		_ = mpWriter.WriteField("timestamp_granularities[]", tg)
	}

	fileName := req.FileName
	if fileName == "" {
		fileName = "audio.mp3"
	}
	part, err := mpWriter.CreateFormFile("file", fileName)
	if err != nil {
		return nil, fmt.Errorf("create form file: %w", err)
	}

	if req.SpoolFilePath != "" {
		f, err := os.Open(req.SpoolFilePath)
		if err != nil {
			return nil, fmt.Errorf("open audio spool file: %w", err)
		}
		defer f.Close()
		if _, err := io.Copy(part, f); err != nil {
			return nil, fmt.Errorf("copy spool file to form: %w", err)
		}
	} else if req.FileReader != nil {
		if _, err := io.Copy(part, req.FileReader); err != nil {
			return nil, fmt.Errorf("copy file reader to form: %w", err)
		}
	} else {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "missing_audio_data",
			Message:    "no audio file reader or spool file provided",
		}
	}

	if err := mpWriter.Close(); err != nil {
		return nil, fmt.Errorf("close multipart writer: %w", err)
	}

	subPath := "/audio/transcriptions"
	if strings.Contains(req.RequestID, "translation") {
		subPath = "/audio/translations"
	}
	endpoint := resolveBaseURL(dep.Credential) + subPath
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bodyBuf)
	if err != nil {
		return nil, err
	}
	setHeaders(httpReq, dep.Credential)
	httpReq.Header.Set("Content-Type", mpWriter.FormDataContentType())

	resp, err := a.client.Do(httpReq)
	if err != nil {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusBadGateway,
			Type:       domain.ErrorTypeUpstream,
			Code:       "openai_network_error",
			Message:    err.Error(),
			Retryable:  true,
		}
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		retryAfter := adapter.ParseRetryAfter(resp.Header)
		return nil, domain.ClassifyUpstreamStatus(domain.ProviderOpenAI, resp.StatusCode, string(respBytes), retryAfter)
	}

	if req.ResponseFormat == "text" {
		return &domain.CanonicalAudioResponse{
			Text: strings.TrimSpace(string(respBytes)),
		}, nil
	}

	var jsonMap map[string]any
	if err := json.Unmarshal(respBytes, &jsonMap); err != nil {
		return &domain.CanonicalAudioResponse{Text: string(respBytes)}, nil
	}

	out := &domain.CanonicalAudioResponse{Raw: jsonMap}
	if txt, ok := jsonMap["text"].(string); ok {
		out.Text = txt
	}
	if durSec, ok := jsonMap["duration"].(float64); ok {
		out.DurationMs = int64(durSec * 1000)
	}
	if lang, ok := jsonMap["language"].(string); ok {
		out.Language = lang
	}
	if words, ok := jsonMap["words"].([]any); ok {
		out.Words = words
	}
	if segments, ok := jsonMap["segments"].([]any); ok {
		out.Segments = segments
	}
	return out, nil
}

// GenerateSpeech generates audio from text using OpenAI's /v1/audio/speech endpoint.
func (a *Adapter) GenerateSpeech(ctx context.Context, dep *domain.Deployment, req *domain.CanonicalAudioSpeechRequest) (io.ReadCloser, string, error) {
	if dep == nil {
		return nil, "", &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "missing_deployment",
			Message:    "deployment cannot be nil",
		}
	}

	model := dep.GlobalModel.ModelName
	if req.ResolvedModel != "" {
		model = req.ResolvedModel
	} else if req.Model != "" {
		model = req.Model
	}

	bodyMap := map[string]any{
		"model": model,
		"input": req.Input,
		"voice": req.Voice,
	}
	if req.ResponseFormat != "" {
		bodyMap["response_format"] = req.ResponseFormat
	}
	if req.Speed > 0 {
		bodyMap["speed"] = req.Speed
	}

	b, err := json.Marshal(bodyMap)
	if err != nil {
		return nil, "", fmt.Errorf("marshal speech request: %w", err)
	}

	endpoint := resolveBaseURL(dep.Credential) + "/audio/speech"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(b))
	if err != nil {
		return nil, "", err
	}
	setHeaders(httpReq, dep.Credential)

	resp, err := a.client.Do(httpReq)
	if err != nil {
		return nil, "", &domain.GatewayError{
			StatusCode: http.StatusBadGateway,
			Type:       domain.ErrorTypeUpstream,
			Code:       "openai_network_error",
			Message:    err.Error(),
			Retryable:  true,
		}
	}

	if resp.StatusCode != http.StatusOK {
		defer resp.Body.Close()
		respBytes, _ := io.ReadAll(resp.Body)
		retryAfter := adapter.ParseRetryAfter(resp.Header)
		return nil, "", domain.ClassifyUpstreamStatus(domain.ProviderOpenAI, resp.StatusCode, string(respBytes), retryAfter)
	}

	contentType := resp.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "audio/mpeg"
	}
	return resp.Body, contentType, nil
}

// GenerateImage generates images using OpenAI's /v1/images/generations endpoint.
func (a *Adapter) GenerateImage(ctx context.Context, dep *domain.Deployment, req *domain.CanonicalImageRequest) (*domain.CanonicalImageResponse, error) {
	if dep == nil {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "missing_deployment",
			Message:    "deployment cannot be nil",
		}
	}

	model := dep.GlobalModel.ModelName
	if req.ResolvedModel != "" {
		model = req.ResolvedModel
	} else if req.Model != "" {
		model = req.Model
	}

	bodyMap := map[string]any{
		"prompt": req.Prompt,
		"model":  model,
	}
	if req.N > 0 {
		bodyMap["n"] = req.N
	}
	if req.Quality != "" {
		bodyMap["quality"] = req.Quality
	}
	if req.ResponseFormat != "" {
		bodyMap["response_format"] = req.ResponseFormat
	}
	if req.Size != "" {
		bodyMap["size"] = req.Size
	}
	if req.Style != "" {
		bodyMap["style"] = req.Style
	}
	if req.User != "" {
		bodyMap["user"] = req.User
	}

	endpoint := resolveBaseURL(dep.Credential) + "/images/generations"
	var requestBody io.Reader
	contentType := "application/json"
	if req.Operation == "edit" || req.Operation == "variation" {
		if len(req.ImageData) == 0 {
			return nil, &domain.GatewayError{StatusCode: http.StatusBadRequest, Type: domain.ErrorTypeInvalidRequest, Code: "missing_image", Message: "image is required"}
		}
		var body bytes.Buffer
		writer := multipart.NewWriter(&body)
		if req.Operation == "edit" {
			endpoint = resolveBaseURL(dep.Credential) + "/images/edits"
			_ = writer.WriteField("prompt", req.Prompt)
		} else {
			endpoint = resolveBaseURL(dep.Credential) + "/images/variations"
		}
		for key, value := range map[string]string{"model": model, "n": strconv.Itoa(req.N), "size": req.Size} {
			if value != "" && value != "0" {
				if err := writer.WriteField(key, value); err != nil {
					return nil, err
				}
			}
		}
		if req.Quality != "" {
			_ = writer.WriteField("quality", req.Quality)
		}
		if req.ResponseFormat != "" {
			_ = writer.WriteField("response_format", req.ResponseFormat)
		}
		if req.Style != "" {
			_ = writer.WriteField("style", req.Style)
		}
		if req.User != "" {
			_ = writer.WriteField("user", req.User)
		}
		imagePart, err := writer.CreateFormFile("image", safeImageFilename(req.ImageFilename))
		if err != nil {
			return nil, err
		}
		if _, err := imagePart.Write(req.ImageData); err != nil {
			return nil, err
		}
		if len(req.MaskData) > 0 {
			maskPart, err := writer.CreateFormFile("mask", safeImageFilename(req.MaskFilename))
			if err != nil {
				return nil, err
			}
			if _, err := maskPart.Write(req.MaskData); err != nil {
				return nil, err
			}
		}
		if err := writer.Close(); err != nil {
			return nil, err
		}
		requestBody = &body
		contentType = writer.FormDataContentType()
	} else {
		b, err := json.Marshal(bodyMap)
		if err != nil {
			return nil, fmt.Errorf("marshal image request: %w", err)
		}
		requestBody = bytes.NewReader(b)
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, requestBody)
	if err != nil {
		return nil, err
	}
	setHeaders(httpReq, dep.Credential)
	httpReq.Header.Set("Content-Type", contentType)

	resp, err := a.client.Do(httpReq)
	if err != nil {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusBadGateway,
			Type:       domain.ErrorTypeUpstream,
			Code:       "openai_network_error",
			Message:    err.Error(),
			Retryable:  true,
		}
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read response body: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		retryAfter := adapter.ParseRetryAfter(resp.Header)
		return nil, domain.ClassifyUpstreamStatus(domain.ProviderOpenAI, resp.StatusCode, string(respBytes), retryAfter)
	}

	var rawResp struct {
		Created int64 `json:"created"`
		Data    []struct {
			URL           string `json:"url"`
			B64JSON       string `json:"b64_json"`
			RevisedPrompt string `json:"revised_prompt"`
		} `json:"data"`
	}
	if err := json.Unmarshal(respBytes, &rawResp); err != nil {
		return nil, fmt.Errorf("unmarshal image response: %w", err)
	}

	items := make([]domain.ImageItem, len(rawResp.Data))
	for i, d := range rawResp.Data {
		items[i] = domain.ImageItem{
			URL:           d.URL,
			B64JSON:       d.B64JSON,
			RevisedPrompt: d.RevisedPrompt,
		}
	}

	return &domain.CanonicalImageResponse{
		Created:  rawResp.Created,
		Provider: domain.ProviderOpenAI,
		Model:    model,
		Data:     items,
	}, nil
}

func safeImageFilename(name string) string {
	name = strings.ReplaceAll(filepath.Base(name), `\`, "_")
	if name == "." || name == "" {
		return "image.png"
	}
	return name
}

func setHeaders(req *http.Request, cred *domain.ProviderCredential) {
	req.Header.Set("Content-Type", "application/json")
	if req.Context() != nil {
		observability.InjectTraceHeaders(req.Context(), req)
	}
	if cred != nil {
		if cred.DecryptedAPIKey != "" {
			req.Header.Set("Authorization", "Bearer "+cred.DecryptedAPIKey)
		}
		for k, v := range cred.Headers {
			req.Header.Set(k, v)
		}
	}
}
