package mistral

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/adapter"
	"github.com/goroute-ai/ai-gateway-go/internal/adapter/sse"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/openapi/providers"
)

const defaultBaseURL = "https://api.mistral.ai/v1"

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
	return domain.ProviderMistral
}

func resolveBaseURL(cred *domain.ProviderCredential) string {
	if cred != nil && strings.TrimSpace(cred.BaseURL) != "" {
		return strings.TrimRight(cred.BaseURL, "/")
	}
	return defaultBaseURL
}

type wireMistralMessage struct {
	Role       string                     `json:"role"`
	Content    any                        `json:"content"`
	Name       string                     `json:"name,omitempty"`
	ToolCallID string                     `json:"tool_call_id,omitempty"`
	ToolCalls  []providers.OpenAIToolCall `json:"tool_calls,omitempty"`
}

type wireMistralChatRequest struct {
	Model          string                          `json:"model"`
	Messages       []wireMistralMessage            `json:"messages"`
	Temperature    *float64                        `json:"temperature,omitempty"`
	TopP           *float64                        `json:"top_p,omitempty"`
	MaxTokens      *int                            `json:"max_tokens,omitempty"`
	Stream         bool                            `json:"stream,omitempty"`
	Stop           []string                        `json:"stop,omitempty"`
	Tools          []providers.OpenAITool          `json:"tools,omitempty"`
	ToolChoice     any                             `json:"tool_choice,omitempty"`
	ResponseFormat *providers.OpenAIResponseFormat `json:"response_format,omitempty"`
}

func (a *Adapter) SupportsOperation(op domain.OperationType) bool {
	switch op {
	case domain.OperationChat, domain.OperationEmbedding, domain.OperationModeration, domain.OperationAudioSTT:
		return true
	default:
		return false
	}
}

func toMistralRequest(model string, req *domain.CanonicalChatRequest, stream bool) wireMistralChatRequest {
	msgs := make([]wireMistralMessage, 0, len(req.Messages))
	for _, m := range req.Messages {
		role := m.Role
		if role == "developer" {
			role = "system"
		}
		var content any = m.Content
		if len(m.Parts) > 0 {
			var parts []map[string]any
			for _, p := range m.Parts {
				switch p.Type {
				case "text":
					parts = append(parts, map[string]any{"type": "text", "text": p.Text})
				case "image_url":
					if p.ImageURL != nil && p.ImageURL.URL != "" {
						parts = append(parts, map[string]any{
							"type":      "image_url",
							"image_url": map[string]any{"url": p.ImageURL.URL},
						})
					}
				}
			}
			if len(parts) > 0 {
				content = parts
			}
		}
		mm := wireMistralMessage{
			Role:       role,
			Content:    content,
			Name:       m.Name,
			ToolCallID: m.ToolCallID,
		}
		for _, tc := range m.ToolCalls {
			mm.ToolCalls = append(mm.ToolCalls, providers.OpenAIToolCall{
				Index: tc.Index,
				ID:    tc.ID,
				Type:  tc.Type,
				Function: providers.OpenAIFunctionCall{
					Name:      tc.Function.Name,
					Arguments: tc.Function.Arguments,
				},
			})
		}
		msgs = append(msgs, mm)
	}

	var tools []providers.OpenAITool
	for _, t := range req.Tools {
		tools = append(tools, providers.OpenAITool{
			Type: t.Type,
			Function: providers.OpenAIFunction{
				Name:        t.Function.Name,
				Description: t.Function.Description,
				Parameters:  t.Function.Parameters,
			},
		})
	}

	out := wireMistralChatRequest{
		Model:       model,
		Messages:    msgs,
		Temperature: req.Temperature,
		TopP:        req.TopP,
		MaxTokens:   req.MaxTokens,
		Stream:      stream,
		Stop:        req.Stop,
		Tools:       tools,
		ToolChoice:  req.ToolChoice,
	}
	if req.ResponseFormat != nil {
		out.ResponseFormat = &providers.OpenAIResponseFormat{
			Type:       req.ResponseFormat.Type,
			JSONSchema: req.ResponseFormat.JSONSchema,
		}
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

	payload := toMistralRequest(model, req, false)
	bodyBytes, err := json.Marshal(payload)
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
			Provider:   domain.ProviderMistral,
			Retryable:  true,
		}
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, domain.ClassifyUpstreamStatus(domain.ProviderMistral, resp.StatusCode, string(respBody), adapter.ParseRetryAfter(resp.Header))
	}

	var mResp providers.MistralChatCompletionResponse
	if err := json.Unmarshal(respBody, &mResp); err != nil {
		return nil, fmt.Errorf("decode mistral response: %w", err)
	}

	choices := make([]domain.CanonicalChoice, 0, len(mResp.Choices))
	for _, c := range mResp.Choices {
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
				Role:      c.Message.Role,
				Content:   c.Message.Content,
				ToolCalls: tcs,
			},
			FinishReason: c.FinishReason,
		})
	}

	return &domain.CanonicalChatResponse{
		ID:       mResp.ID,
		Object:   "chat.completion",
		Created:  mResp.Created,
		Model:    mResp.Model,
		Provider: domain.ProviderMistral,
		Choices:  choices,
		Usage: domain.TokenUsage{
			PromptTokens:     mResp.Usage.PromptTokens,
			CompletionTokens: mResp.Usage.CompletionTokens,
			TotalTokens:      mResp.Usage.TotalTokens,
		},
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

	payload := toMistralRequest(model, req, true)
	bodyBytes, err := json.Marshal(payload)
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
			Provider:   domain.ProviderMistral,
			Retryable:  true,
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		errBody, _ := io.ReadAll(resp.Body)
		return nil, domain.ClassifyUpstreamStatus(domain.ProviderMistral, resp.StatusCode, string(errBody), adapter.ParseRetryAfter(resp.Header))
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

	payload := providers.MistralEmbeddingRequest{
		Model:          model,
		Input:          req.Input,
		EncodingFormat: req.EncodingFormat,
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
			Provider:   domain.ProviderMistral,
			Retryable:  true,
		}
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, domain.ClassifyUpstreamStatus(domain.ProviderMistral, resp.StatusCode, string(respBody), adapter.ParseRetryAfter(resp.Header))
	}

	var mResp providers.MistralEmbeddingResponse
	if err := json.Unmarshal(respBody, &mResp); err != nil {
		return nil, err
	}
	data := make([]domain.EmbeddingData, 0, len(mResp.Data))
	for _, d := range mResp.Data {
		data = append(data, domain.EmbeddingData{
			Object:    "embedding",
			Index:     d.Index,
			Embedding: d.Embedding,
		})
	}
	return &domain.CanonicalEmbeddingResponse{
		Object:   "list",
		Data:     data,
		Model:    mResp.Model,
		Provider: domain.ProviderMistral,
		Usage: domain.TokenUsage{
			PromptTokens: mResp.Usage.PromptTokens,
			TotalTokens:  mResp.Usage.TotalTokens,
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
		return nil, domain.ClassifyUpstreamStatus(domain.ProviderMistral, resp.StatusCode, string(respBody), 0)
	}

	var list providers.MistralModelList
	if err := json.Unmarshal(respBody, &list); err != nil {
		return nil, err
	}
	out := make([]domain.DiscoveredModel, 0, len(list.Data))
	for _, m := range list.Data {
		display := m.Name
		if display == "" {
			display = m.ID
		}
		out = append(out, domain.DiscoveredModel{
			Provider:    domain.ProviderMistral,
			ModelName:   m.ID,
			DisplayName: display,
			CreatedAt:   m.Created,
		})
	}
	return out, nil
}

func setHeaders(req *http.Request, cred *domain.ProviderCredential) {
	req.Header.Set("Content-Type", "application/json")
	if cred != nil {
		if cred.DecryptedAPIKey != "" {
			req.Header.Set("Authorization", "Bearer "+cred.DecryptedAPIKey)
		}
		for k, v := range cred.Headers {
			req.Header.Set(k, v)
		}
	}
}

// Moderate implements adapter.ModerationAdapter for Mistral's /v1/moderations endpoint.
func (a *Adapter) Moderate(ctx context.Context, dep *domain.Deployment, req *domain.CanonicalModerationRequest) (*domain.CanonicalModerationResponse, error) {
	model := req.ResolvedModel
	if model == "" && dep != nil && dep.GlobalModel != nil {
		model = dep.GlobalModel.ModelName
	}
	if model == "" {
		model = req.Model
	}

	payload := map[string]any{
		"model": model,
		"input": req.Input,
	}
	bodyBytes, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	var cred *domain.ProviderCredential
	if dep != nil {
		cred = dep.Credential
	}
	endpoint := resolveBaseURL(cred) + "/moderations"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	setHeaders(httpReq, cred)

	resp, err := a.client.Do(httpReq)
	if err != nil {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusBadGateway,
			Type:       domain.ErrorTypeUpstream,
			Code:       "upstream_network_error",
			Message:    err.Error(),
			Provider:   domain.ProviderMistral,
			Retryable:  true,
		}
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, domain.ClassifyUpstreamStatus(domain.ProviderMistral, resp.StatusCode, string(respBody), adapter.ParseRetryAfter(resp.Header))
	}

	var raw struct {
		ID      string `json:"id"`
		Model   string `json:"model"`
		Results []struct {
			Categories     map[string]bool    `json:"categories"`
			CategoryScores map[string]float64 `json:"category_scores"`
		} `json:"results"`
	}
	if err := json.Unmarshal(respBody, &raw); err != nil {
		return nil, fmt.Errorf("decode mistral moderation response: %w", err)
	}

	results := make([]domain.ModerationResultItem, len(raw.Results))
	for i, r := range raw.Results {
		flagged := false
		for _, v := range r.Categories {
			if v {
				flagged = true
				break
			}
		}
		results[i] = domain.ModerationResultItem{
			Flagged:        flagged,
			Categories:     r.Categories,
			CategoryScores: r.CategoryScores,
		}
	}
	return &domain.CanonicalModerationResponse{
		ID:       raw.ID,
		Model:    raw.Model,
		Provider: domain.ProviderMistral,
		Results:  results,
	}, nil
}

// TranscribeAudio implements adapter.AudioAdapter for Mistral's /v1/audio/transcriptions endpoint.
func (a *Adapter) TranscribeAudio(ctx context.Context, dep *domain.Deployment, req *domain.CanonicalAudioTranscriptionRequest) (*domain.CanonicalAudioResponse, error) {
	model := req.ResolvedModel
	if model == "" && dep != nil && dep.GlobalModel != nil {
		model = dep.GlobalModel.ModelName
	}
	if model == "" {
		model = req.Model
	}

	var reader io.Reader = req.FileReader
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
			Provider:   domain.ProviderMistral,
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
	endpoint := resolveBaseURL(cred) + "/audio/transcriptions"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, &buf)
	if err != nil {
		return nil, err
	}
	setHeaders(httpReq, cred)
	httpReq.Header.Set("Content-Type", mw.FormDataContentType())

	resp, err := a.client.Do(httpReq)
	if err != nil {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusBadGateway,
			Type:       domain.ErrorTypeUpstream,
			Code:       "upstream_network_error",
			Message:    err.Error(),
			Provider:   domain.ProviderMistral,
			Retryable:  true,
		}
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, domain.ClassifyUpstreamStatus(domain.ProviderMistral, resp.StatusCode, string(respBody), adapter.ParseRetryAfter(resp.Header))
	}

	var out domain.CanonicalAudioResponse
	if err := json.Unmarshal(respBody, &out); err != nil {
		return nil, fmt.Errorf("decode mistral transcription response: %w", err)
	}
	return &out, nil
}

// GenerateSpeech implements adapter.AudioAdapter; Mistral does not expose a native TTS endpoint.
func (a *Adapter) GenerateSpeech(ctx context.Context, dep *domain.Deployment, req *domain.CanonicalAudioSpeechRequest) (io.ReadCloser, string, error) {
	return nil, "", &domain.GatewayError{
		StatusCode: http.StatusBadRequest,
		Type:       domain.ErrorTypeInvalidRequest,
		Code:       "unsupported_capability",
		Message:    "Mistral does not expose a text-to-speech endpoint",
		Provider:   domain.ProviderMistral,
	}
}
