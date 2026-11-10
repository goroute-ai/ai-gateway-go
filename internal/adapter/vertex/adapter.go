package vertex

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/adapter"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
)

// Adapter implements adapter.ProviderAdapter for Google Cloud Vertex AI.
type Adapter struct {
	httpClient *http.Client
	ssrfPolicy *network.Policy
}

// NewAdapter creates a new Google Cloud Vertex AI adapter.
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
	return domain.ProviderVertex
}

func (a *Adapter) resolveVertexConfig(dep *domain.Deployment) (baseURL, projectID, region string, ts *TokenSource, err error) {
	if dep.Credential == nil {
		return "", "", "", nil, &domain.GatewayError{
			StatusCode:  http.StatusUnauthorized,
			Type:        domain.ErrorTypeAuthentication,
			Code:        "missing_credential",
			Message:     "vertex ai credentials missing",
			AuthFailure: true,
		}
	}

	rawCred := strings.TrimSpace(dep.Credential.DecryptedAPIKey)
	ts, err = NewTokenSource(a.httpClient, rawCred)
	if err != nil {
		return "", "", "", nil, &domain.GatewayError{
			StatusCode:  http.StatusUnauthorized,
			Type:        domain.ErrorTypeAuthentication,
			Code:        "invalid_vertex_credential",
			Message:     fmt.Sprintf("invalid vertex credentials: %v", err),
			AuthFailure: true,
		}
	}

	region = os.Getenv("VERTEX_LOCATION")
	if region == "" {
		region = os.Getenv("GCP_REGION")
	}
	if region == "" {
		region = "us-central1"
	}

	projectID = os.Getenv("VERTEX_PROJECT_ID")
	if projectID == "" {
		projectID = os.Getenv("GCP_PROJECT_ID")
	}
	if ts.saKey != nil && ts.saKey.ProjectID != "" {
		projectID = ts.saKey.ProjectID
	}
	if projectID == "" {
		projectID = "default"
	}

	if dep.Credential.BaseURL != "" {
		baseURL = strings.TrimRight(dep.Credential.BaseURL, "/")
	} else {
		baseURL = fmt.Sprintf("https://%s-aiplatform.googleapis.com", region)
	}

	return baseURL, projectID, region, ts, nil
}

func (a *Adapter) ChatCompletion(ctx context.Context, dep *domain.Deployment, req *domain.CanonicalChatRequest) (*domain.CanonicalChatResponse, error) {
	baseURL, projectID, region, ts, err := a.resolveVertexConfig(dep)
	if err != nil {
		return nil, err
	}

	token, err := ts.GetToken(ctx)
	if err != nil {
		return nil, &domain.GatewayError{
			StatusCode:  http.StatusUnauthorized,
			Type:        domain.ErrorTypeAuthentication,
			Code:        "vertex_auth_token_failed",
			Message:     err.Error(),
			AuthFailure: true,
		}
	}

	model := req.ResolvedModel
	if model == "" {
		model = req.Model
	}
	model = strings.TrimPrefix(model, "publishers/google/models/")

	bodyBytes, err := buildVertexPayload(req)
	if err != nil {
		return nil, fmt.Errorf("build vertex payload: %w", err)
	}

	targetURL := fmt.Sprintf("%s/v1/projects/%s/locations/%s/publishers/google/models/%s:generateContent",
		baseURL, projectID, region, url.PathEscape(model))

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+token)

	resp, err := a.httpClient.Do(httpReq)
	if err != nil {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusBadGateway,
			Type:       domain.ErrorTypeUpstream,
			Code:       "vertex_connection_failed",
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
		return nil, parseVertexError(resp.StatusCode, respBytes)
	}

	return parseVertexResponse(respBytes, model)
}

func (a *Adapter) StreamChatCompletion(ctx context.Context, dep *domain.Deployment, req *domain.CanonicalChatRequest, onChunk adapter.StreamChunkHandler) (*domain.TokenUsage, error) {
	baseURL, projectID, region, ts, err := a.resolveVertexConfig(dep)
	if err != nil {
		return nil, err
	}

	token, err := ts.GetToken(ctx)
	if err != nil {
		return nil, &domain.GatewayError{
			StatusCode:  http.StatusUnauthorized,
			Type:        domain.ErrorTypeAuthentication,
			Code:        "vertex_auth_token_failed",
			Message:     err.Error(),
			AuthFailure: true,
		}
	}

	model := req.ResolvedModel
	if model == "" {
		model = req.Model
	}
	model = strings.TrimPrefix(model, "publishers/google/models/")

	bodyBytes, err := buildVertexPayload(req)
	if err != nil {
		return nil, fmt.Errorf("build vertex payload: %w", err)
	}

	targetURL := fmt.Sprintf("%s/v1/projects/%s/locations/%s/publishers/google/models/%s:streamGenerateContent?alt=sse",
		baseURL, projectID, region, url.PathEscape(model))

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+token)

	resp, err := a.httpClient.Do(httpReq)
	if err != nil {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusBadGateway,
			Type:       domain.ErrorTypeUpstream,
			Code:       "vertex_stream_failed",
			Message:    err.Error(),
			Retryable:  true,
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBytes, _ := io.ReadAll(resp.Body)
		return nil, parseVertexError(resp.StatusCode, respBytes)
	}

	var finalUsage domain.TokenUsage
	chunkID := fmt.Sprintf("vertex-%d", time.Now().UnixNano())

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

		var geminiResp struct {
			Candidates []struct {
				Content struct {
					Role  string `json:"role"`
					Parts []struct {
						Text         string `json:"text,omitempty"`
						FunctionCall *struct {
							Name string         `json:"name"`
							Args map[string]any `json:"args"`
						} `json:"functionCall,omitempty"`
					} `json:"parts"`
				} `json:"content"`
				FinishReason string `json:"finishReason,omitempty"`
			} `json:"candidates"`
			UsageMetadata struct {
				PromptTokenCount     int `json:"promptTokenCount"`
				CandidatesTokenCount int `json:"candidatesTokenCount"`
				TotalTokenCount      int `json:"totalTokenCount"`
			} `json:"usageMetadata"`
		}

		if err := json.Unmarshal([]byte(dataStr), &geminiResp); err != nil {
			continue
		}

		if geminiResp.UsageMetadata.TotalTokenCount > 0 {
			finalUsage.PromptTokens = geminiResp.UsageMetadata.PromptTokenCount
			finalUsage.CompletionTokens = geminiResp.UsageMetadata.CandidatesTokenCount
			finalUsage.TotalTokens = geminiResp.UsageMetadata.TotalTokenCount
		}

		for _, cand := range geminiResp.Candidates {
			var sb strings.Builder
			var toolCalls []domain.CanonicalToolCall
			for _, p := range cand.Content.Parts {
				if p.Text != "" {
					sb.WriteString(p.Text)
				}
				if p.FunctionCall != nil {
					argBytes, _ := json.Marshal(p.FunctionCall.Args)
					toolCalls = append(toolCalls, domain.CanonicalToolCall{
						Type: "function",
						Function: domain.CanonicalFunctionCall{
							Name:      p.FunctionCall.Name,
							Arguments: string(argBytes),
						},
					})
				}
			}

			finishReason := ""
			if cand.FinishReason != "" {
				finishReason = mapVertexFinishReason(cand.FinishReason)
			}

			canonicalChunk := &domain.CanonicalStreamChunk{
				ID:      chunkID,
				Created: time.Now().Unix(),
				Model:   model,
				Choices: []domain.CanonicalStreamChoice{
					{
						Index: 0,
						Delta: domain.CanonicalStreamDelta{
							Content:   sb.String(),
							ToolCalls: toolCalls,
						},
						FinishReason: func() *string {
							if finishReason != "" {
								return &finishReason
							}
							return nil
						}(),
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
	baseURL, projectID, region, ts, err := a.resolveVertexConfig(dep)
	if err != nil {
		return nil, err
	}

	token, err := ts.GetToken(ctx)
	if err != nil {
		return nil, err
	}

	model := req.ResolvedModel
	if model == "" {
		model = req.Model
	}
	model = strings.TrimPrefix(model, "publishers/google/models/")

	instances := make([]map[string]any, len(req.Input))
	for i, inp := range req.Input {
		instances[i] = map[string]any{"content": inp}
	}
	reqPayload := map[string]any{
		"instances": instances,
	}
	bodyBytes, _ := json.Marshal(reqPayload)

	targetURL := fmt.Sprintf("%s/v1/projects/%s/locations/%s/publishers/google/models/%s:predict",
		baseURL, projectID, region, url.PathEscape(model))

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+token)

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
		return nil, parseVertexError(resp.StatusCode, respBytes)
	}

	var predResp struct {
		Predictions []struct {
			Embeddings struct {
				Values []float64 `json:"values"`
			} `json:"embeddings"`
		} `json:"predictions"`
	}
	if err := json.Unmarshal(respBytes, &predResp); err != nil {
		return nil, fmt.Errorf("decode vertex embedding response: %w", err)
	}

	data := make([]domain.EmbeddingData, len(predResp.Predictions))
	for i, p := range predResp.Predictions {
		data[i] = domain.EmbeddingData{
			Index:     i,
			Embedding: p.Embeddings.Values,
			Object:    "embedding",
		}
	}

	return &domain.CanonicalEmbeddingResponse{
		Object: "list",
		Data:   data,
		Model:  model,
	}, nil
}

func (a *Adapter) ListModels(ctx context.Context, cred *domain.ProviderCredential) ([]domain.DiscoveredModel, error) {
	return []domain.DiscoveredModel{
		{Provider: domain.ProviderVertex, ModelName: "gemini-1.5-pro", DisplayName: "Gemini 1.5 Pro (Vertex AI)"},
		{Provider: domain.ProviderVertex, ModelName: "gemini-1.5-flash", DisplayName: "Gemini 1.5 Flash (Vertex AI)"},
		{Provider: domain.ProviderVertex, ModelName: "gemini-2.0-flash-exp", DisplayName: "Gemini 2.0 Flash (Vertex AI)"},
	}, nil
}

func buildVertexPayload(req *domain.CanonicalChatRequest) ([]byte, error) {
	var contents []map[string]any
	var systemParts []map[string]any

	for _, m := range req.Messages {
		if m.Role == "system" {
			systemParts = append(systemParts, map[string]any{"text": m.Content})
			continue
		}

		role := m.Role
		if role == "assistant" {
			role = "model"
		} else {
			role = "user"
		}

		var parts []map[string]any
		if m.Content != "" {
			parts = append(parts, map[string]any{"text": m.Content})
		}
		for _, tc := range m.ToolCalls {
			var args map[string]any
			_ = json.Unmarshal([]byte(tc.Function.Arguments), &args)
			parts = append(parts, map[string]any{
				"functionCall": map[string]any{
					"name": tc.Function.Name,
					"args": args,
				},
			})
		}

		if len(parts) > 0 {
			contents = append(contents, map[string]any{
				"role":  role,
				"parts": parts,
			})
		}
	}

	payload := map[string]any{
		"contents": contents,
	}

	if len(systemParts) > 0 {
		payload["systemInstruction"] = map[string]any{
			"role":  "user",
			"parts": systemParts,
		}
	}

	genConfig := make(map[string]any)
	if req.Temperature != nil {
		genConfig["temperature"] = *req.Temperature
	}
	if req.TopP != nil {
		genConfig["topP"] = *req.TopP
	}
	if req.MaxTokens != nil && *req.MaxTokens > 0 {
		genConfig["maxOutputTokens"] = *req.MaxTokens
	}
	if len(req.Stop) > 0 {
		genConfig["stopSequences"] = req.Stop
	}
	if len(genConfig) > 0 {
		payload["generationConfig"] = genConfig
	}

	if len(req.Tools) > 0 {
		var decls []map[string]any
		for _, t := range req.Tools {
			decls = append(decls, map[string]any{
				"name":        t.Function.Name,
				"description": t.Function.Description,
				"parameters":  t.Function.Parameters,
			})
		}
		payload["tools"] = []map[string]any{
			{"functionDeclarations": decls},
		}
	}

	return json.Marshal(payload)
}

func parseVertexResponse(data []byte, model string) (*domain.CanonicalChatResponse, error) {
	var resp struct {
		Candidates []struct {
			Content struct {
				Role  string `json:"role"`
				Parts []struct {
					Text         string `json:"text,omitempty"`
					FunctionCall *struct {
						Name string         `json:"name"`
						Args map[string]any `json:"args"`
					} `json:"functionCall,omitempty"`
				} `json:"parts"`
			} `json:"content"`
			FinishReason string `json:"finishReason"`
		} `json:"candidates"`
		UsageMetadata struct {
			PromptTokenCount     int `json:"promptTokenCount"`
			CandidatesTokenCount int `json:"candidatesTokenCount"`
			TotalTokenCount      int `json:"totalTokenCount"`
		} `json:"usageMetadata"`
	}

	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal vertex response: %w", err)
	}

	var choices []domain.CanonicalChoice
	for i, cand := range resp.Candidates {
		var sb strings.Builder
		var toolCalls []domain.CanonicalToolCall

		for j, p := range cand.Content.Parts {
			if p.Text != "" {
				sb.WriteString(p.Text)
			}
			if p.FunctionCall != nil {
				args, _ := json.Marshal(p.FunctionCall.Args)
				idx := j
				toolCalls = append(toolCalls, domain.CanonicalToolCall{
					Index: &idx,
					Type:  "function",
					Function: domain.CanonicalFunctionCall{
						Name:      p.FunctionCall.Name,
						Arguments: string(args),
					},
				})
			}
		}

		choices = append(choices, domain.CanonicalChoice{
			Index: i,
			Message: domain.CanonicalMessage{
				Role:      "assistant",
				Content:   sb.String(),
				ToolCalls: toolCalls,
			},
			FinishReason: mapVertexFinishReason(cand.FinishReason),
		})
	}

	return &domain.CanonicalChatResponse{
		ID:      fmt.Sprintf("vertex-%d", time.Now().UnixNano()),
		Model:   model,
		Created: time.Now().Unix(),
		Choices: choices,
		Usage: domain.TokenUsage{
			PromptTokens:     resp.UsageMetadata.PromptTokenCount,
			CompletionTokens: resp.UsageMetadata.CandidatesTokenCount,
			TotalTokens:      resp.UsageMetadata.TotalTokenCount,
		},
	}, nil
}

func mapVertexFinishReason(fr string) string {
	switch fr {
	case "STOP":
		return "stop"
	case "MAX_TOKENS":
		return "length"
	case "SAFETY", "RECITATION":
		return "content_filter"
	default:
		return strings.ToLower(fr)
	}
}

func parseVertexError(statusCode int, body []byte) error {
	var errResp struct {
		Error struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
			Status  string `json:"status"`
		} `json:"error"`
	}
	_ = json.Unmarshal(body, &errResp)

	msg := errResp.Error.Message
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
		gwErr.Code = "vertex_auth_failed"
		gwErr.AuthFailure = true
	case http.StatusBadRequest:
		gwErr.Type = domain.ErrorTypeInvalidRequest
		gwErr.Code = "vertex_invalid_request"
	case http.StatusTooManyRequests:
		gwErr.Type = domain.ErrorTypeRateLimit
		gwErr.Code = "vertex_quota_exceeded"
		gwErr.Retryable = true
	default:
		gwErr.Type = domain.ErrorTypeUpstream
		gwErr.Code = "vertex_upstream_error"
		gwErr.Retryable = true
	}
	return gwErr
}
