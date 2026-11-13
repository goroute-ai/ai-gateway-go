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
	"github.com/goroute-ai/ai-gateway-go/internal/adapter/sse"
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

	region = strings.TrimSpace(dep.Region)
	if region == "" {
		region = os.Getenv("VERTEX_LOCATION")
	}
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
	} else if region == "global" {
		baseURL = "https://aiplatform.googleapis.com"
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
	model = strings.TrimPrefix(model, "publishers/anthropic/models/")

	if isVertexClaudeModel(model) {
		return a.chatCompletionClaude(ctx, baseURL, projectID, region, token, model, req)
	}

	bodyBytes, err := buildVertexPayload(model, req)
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
	ctx = adapter.StreamingContext(ctx)
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
	model = strings.TrimPrefix(model, "publishers/anthropic/models/")

	if isVertexClaudeModel(model) {
		return a.streamChatCompletionClaude(ctx, baseURL, projectID, region, token, model, req, onChunk)
	}

	bodyBytes, err := buildVertexPayload(model, req)
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
						Thought      bool   `json:"thought,omitempty"`
						FunctionCall *struct {
							Name string         `json:"name"`
							Args map[string]any `json:"args"`
						} `json:"functionCall,omitempty"`
					} `json:"parts"`
				} `json:"content"`
				FinishReason string `json:"finishReason,omitempty"`
			} `json:"candidates"`
			UsageMetadata struct {
				PromptTokenCount        int `json:"promptTokenCount"`
				CandidatesTokenCount    int `json:"candidatesTokenCount"`
				TotalTokenCount         int `json:"totalTokenCount"`
				ThoughtsTokenCount      int `json:"thoughtsTokenCount"`
				CachedContentTokenCount int `json:"cachedContentTokenCount"`
			} `json:"usageMetadata"`
		}

		if err := json.Unmarshal([]byte(dataStr), &geminiResp); err != nil {
			continue
		}

		if geminiResp.UsageMetadata.TotalTokenCount > 0 || geminiResp.UsageMetadata.PromptTokenCount > 0 {
			finalUsage.PromptTokens = geminiResp.UsageMetadata.PromptTokenCount
			finalUsage.CompletionTokens = geminiResp.UsageMetadata.CandidatesTokenCount + geminiResp.UsageMetadata.ThoughtsTokenCount
			finalUsage.TotalTokens = geminiResp.UsageMetadata.TotalTokenCount
			finalUsage.ReasoningTokens = geminiResp.UsageMetadata.ThoughtsTokenCount
			finalUsage.CachedPromptTokens = geminiResp.UsageMetadata.CachedContentTokenCount
		}

		for _, cand := range geminiResp.Candidates {
			var sb strings.Builder
			var thoughtSB strings.Builder
			var toolCalls []domain.CanonicalToolCall
			for _, p := range cand.Content.Parts {
				if p.Thought {
					thoughtSB.WriteString(p.Text)
				} else if p.Text != "" {
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
							Content:          sb.String(),
							ReasoningContent: thoughtSB.String(),
							ToolCalls:        toolCalls,
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

func parseDataURI(uri string) (mime string, b64 string, ok bool) {
	if !strings.HasPrefix(uri, "data:") {
		return "", "", false
	}
	rest := strings.TrimPrefix(uri, "data:")
	idx := strings.Index(rest, ";base64,")
	if idx < 0 {
		return "", "", false
	}
	return rest[:idx], rest[idx+len(";base64,"):], true
}

func buildVertexUserParts(m domain.CanonicalMessage) []map[string]any {
	var parts []map[string]any
	if len(m.Parts) > 0 {
		for _, p := range m.Parts {
			switch p.Type {
			case "text":
				parts = append(parts, map[string]any{"text": p.Text})
			case "image_url":
				if p.ImageURL != nil && p.ImageURL.URL != "" {
					if mime, b64, ok := parseDataURI(p.ImageURL.URL); ok {
						parts = append(parts, map[string]any{
							"inlineData": map[string]any{"mimeType": mime, "data": b64},
						})
					} else {
						parts = append(parts, map[string]any{
							"fileData": map[string]any{"mimeType": "image/jpeg", "fileUri": p.ImageURL.URL},
						})
					}
				}
			case "document":
				if p.Document != nil {
					mime := p.Document.MimeType
					if mime == "" {
						mime = "application/pdf"
					}
					if p.Document.Data != "" {
						parts = append(parts, map[string]any{
							"inlineData": map[string]any{"mimeType": mime, "data": p.Document.Data},
						})
					} else if p.Document.URL != "" {
						parts = append(parts, map[string]any{
							"fileData": map[string]any{"mimeType": mime, "fileUri": p.Document.URL},
						})
					}
				}
			}
		}
	}
	if len(parts) == 0 && m.Content != "" {
		parts = append(parts, map[string]any{"text": m.Content})
	}
	return parts
}

func buildVertexPayload(model string, req *domain.CanonicalChatRequest) ([]byte, error) {
	var contents []map[string]any
	var systemParts []map[string]any

	for _, m := range req.Messages {
		if m.Role == "system" || m.Role == "developer" {
			if strings.TrimSpace(m.Content) != "" {
				systemParts = append(systemParts, map[string]any{"text": m.Content})
			}
			continue
		}

		if m.Role == "tool" {
			var respObj map[string]any
			if err := json.Unmarshal([]byte(m.Content), &respObj); err != nil {
				respObj = map[string]any{"result": m.Content}
			}
			funcName := m.Name
			if funcName == "" {
				funcName = m.ToolCallID
			}
			contents = append(contents, map[string]any{
				"role": "function",
				"parts": []map[string]any{
					{
						"functionResponse": map[string]any{
							"name":     funcName,
							"response": respObj,
						},
					},
				},
			})
			continue
		}

		role := "user"
		if m.Role == "assistant" {
			role = "model"
		}

		parts := buildVertexUserParts(m)
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
	if req.ReasoningEffort != "" {
		lowerModel := strings.ToLower(model)
		effort := strings.ToLower(strings.TrimSpace(req.ReasoningEffort))
		if strings.Contains(lowerModel, "gemini-3") {
			level := "MEDIUM"
			switch effort {
			case "none":
				level = "MINIMAL"
			case "minimal", "low":
				level = "LOW"
			case "high", "xhigh", "max":
				level = "HIGH"
			}
			genConfig["thinkingConfig"] = map[string]any{"thinkingLevel": level}
		} else {
			budget := 4096
			switch effort {
			case "none":
				budget = 0
			case "minimal":
				budget = 512
			case "low":
				budget = 1024
			case "high":
				budget = 8192
			case "xhigh", "max":
				budget = 16384
			}
			genConfig["thinkingConfig"] = map[string]any{"thinkingBudget": budget}
		}
	}
	if req.ResponseFormat != nil && (req.ResponseFormat.Type == "json_object" || req.ResponseFormat.Type == "json_schema") {
		genConfig["responseMimeType"] = "application/json"
		if req.ResponseFormat.Type == "json_schema" && len(req.ResponseFormat.JSONSchema) > 0 {
			schema := any(req.ResponseFormat.JSONSchema)
			if inner, ok := req.ResponseFormat.JSONSchema["schema"]; ok {
				schema = inner
			}
			genConfig["responseJsonSchema"] = schema
		}
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

	if req.ToolChoice != nil {
		switch tc := req.ToolChoice.(type) {
		case string:
			switch strings.ToLower(strings.TrimSpace(tc)) {
			case "auto":
				payload["toolConfig"] = map[string]any{"functionCallingConfig": map[string]any{"mode": "AUTO"}}
			case "required", "any":
				payload["toolConfig"] = map[string]any{"functionCallingConfig": map[string]any{"mode": "ANY"}}
			case "none":
				payload["toolConfig"] = map[string]any{"functionCallingConfig": map[string]any{"mode": "NONE"}}
			}
		case map[string]any:
			if t, _ := tc["type"].(string); t == "function" {
				if fn, ok := tc["function"].(map[string]any); ok {
					if name, _ := fn["name"].(string); name != "" {
						payload["toolConfig"] = map[string]any{
							"functionCallingConfig": map[string]any{
								"mode":                 "ANY",
								"allowedFunctionNames": []string{name},
							},
						}
					}
				}
			}
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
					Thought      bool   `json:"thought,omitempty"`
					FunctionCall *struct {
						Name string         `json:"name"`
						Args map[string]any `json:"args"`
					} `json:"functionCall,omitempty"`
				} `json:"parts"`
			} `json:"content"`
			FinishReason string `json:"finishReason"`
		} `json:"candidates"`
		UsageMetadata struct {
			PromptTokenCount        int `json:"promptTokenCount"`
			CandidatesTokenCount    int `json:"candidatesTokenCount"`
			TotalTokenCount         int `json:"totalTokenCount"`
			ThoughtsTokenCount      int `json:"thoughtsTokenCount"`
			CachedContentTokenCount int `json:"cachedContentTokenCount"`
		} `json:"usageMetadata"`
	}

	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal vertex response: %w", err)
	}

	var choices []domain.CanonicalChoice
	for i, cand := range resp.Candidates {
		var sb strings.Builder
		var thoughtSB strings.Builder
		var toolCalls []domain.CanonicalToolCall

		for j, p := range cand.Content.Parts {
			if p.Thought {
				thoughtSB.WriteString(p.Text)
			} else if p.Text != "" {
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
				Role:             "assistant",
				Content:          sb.String(),
				ReasoningContent: thoughtSB.String(),
				ToolCalls:        toolCalls,
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
			PromptTokens:       resp.UsageMetadata.PromptTokenCount,
			CompletionTokens:   resp.UsageMetadata.CandidatesTokenCount + resp.UsageMetadata.ThoughtsTokenCount,
			TotalTokens:        resp.UsageMetadata.TotalTokenCount,
			ReasoningTokens:    resp.UsageMetadata.ThoughtsTokenCount,
			CachedPromptTokens: resp.UsageMetadata.CachedContentTokenCount,
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

func isVertexClaudeModel(model string) bool {
	return strings.Contains(strings.ToLower(model), "claude")
}

func (a *Adapter) materializeClaudeMedia(ctx context.Context, req *domain.CanonicalChatRequest) (*domain.CanonicalChatRequest, error) {
	copyReq := *req
	copyReq.Messages = append([]domain.CanonicalMessage(nil), req.Messages...)
	for i := range copyReq.Messages {
		copyReq.Messages[i].Parts = append([]domain.ContentPart(nil), req.Messages[i].Parts...)
		for j := range copyReq.Messages[i].Parts {
			part := &copyReq.Messages[i].Parts[j]
			switch part.Type {
			case "image_url":
				if part.ImageURL == nil || part.ImageURL.URL == "" {
					continue
				}
				if _, _, dataURI := parseDataURI(part.ImageURL.URL); dataURI {
					continue
				}
				dataURI, err := adapter.FetchRemoteDataURI(ctx, a.httpClient, part.ImageURL.URL, 20<<20, "image/")
				if err != nil {
					return nil, unsupportedVertexMediaInput(err)
				}
				urlCopy := *part.ImageURL
				urlCopy.URL = dataURI
				part.ImageURL = &urlCopy
			case "document":
				if part.Document == nil || part.Document.Data != "" || part.Document.URL == "" {
					continue
				}
				dataURI, err := adapter.FetchRemoteDataURI(ctx, a.httpClient, part.Document.URL, 20<<20,
					"application/pdf", "text/plain", "text/csv", "text/markdown", "text/html")
				if err != nil {
					return nil, unsupportedVertexMediaInput(err)
				}
				mimeType, encoded, ok := parseDataURI(dataURI)
				if !ok {
					return nil, unsupportedVertexMediaInput(fmt.Errorf("remote document could not be encoded"))
				}
				docCopy := *part.Document
				docCopy.MimeType = mimeType
				docCopy.Data = encoded
				docCopy.URL = ""
				part.Document = &docCopy
			}
		}
	}
	return &copyReq, nil
}

func unsupportedVertexMediaInput(err error) error {
	return &domain.GatewayError{
		StatusCode: http.StatusBadRequest,
		Type:       domain.ErrorTypeInvalidRequest,
		Code:       "invalid_multimodal_input",
		Message:    err.Error(),
		Provider:   domain.ProviderVertex,
	}
}

func buildVertexClaudePayload(req *domain.CanonicalChatRequest, stream bool) ([]byte, error) {
	var systemPlain []string
	var messages []map[string]any

	for _, m := range req.Messages {
		switch m.Role {
		case "system", "developer":
			if strings.TrimSpace(m.Content) != "" {
				systemPlain = append(systemPlain, m.Content)
			}
		case "tool":
			blk := map[string]any{
				"type":        "tool_result",
				"tool_use_id": m.ToolCallID,
				"content":     m.Content,
			}
			if len(messages) > 0 && messages[len(messages)-1]["role"] == "user" {
				existing := messages[len(messages)-1]["content"].([]map[string]any)
				messages[len(messages)-1]["content"] = append(existing, blk)
			} else {
				messages = append(messages, map[string]any{
					"role":    "user",
					"content": []map[string]any{blk},
				})
			}
		case "assistant":
			var blocks []map[string]any
			if m.Content != "" {
				blocks = append(blocks, map[string]any{"type": "text", "text": m.Content})
			}
			for _, tc := range m.ToolCalls {
				var parsedInput any = map[string]any{}
				if tc.Function.Arguments != "" {
					_ = json.Unmarshal([]byte(tc.Function.Arguments), &parsedInput)
				}
				blocks = append(blocks, map[string]any{
					"type":  "tool_use",
					"id":    tc.ID,
					"name":  tc.Function.Name,
					"input": parsedInput,
				})
			}
			if len(blocks) > 0 {
				messages = append(messages, map[string]any{"role": "assistant", "content": blocks})
			}
		default:
			var blocks []map[string]any
			if len(m.Parts) > 0 {
				for _, p := range m.Parts {
					switch p.Type {
					case "text":
						blocks = append(blocks, map[string]any{"type": "text", "text": p.Text})
					case "image_url":
						if p.ImageURL != nil && p.ImageURL.URL != "" {
							mime, b64, ok := parseDataURI(p.ImageURL.URL)
							if !ok {
								return nil, fmt.Errorf("Vertex Claude image input must be materialized as base64 before request construction")
							}
							blocks = append(blocks, map[string]any{
								"type":   "image",
								"source": map[string]any{"type": "base64", "media_type": mime, "data": b64},
							})
						}
					case "document":
						if p.Document != nil && p.Document.URL != "" && p.Document.Data == "" {
							return nil, fmt.Errorf("Vertex Claude document input must be materialized as base64 before request construction")
						}
						if p.Document != nil && p.Document.Data != "" {
							mime := p.Document.MimeType
							if mime == "" {
								mime = "application/pdf"
							}
							blocks = append(blocks, map[string]any{
								"type":   "document",
								"source": map[string]any{"type": "base64", "media_type": mime, "data": p.Document.Data},
							})
						}
					}
				}
			}
			if len(blocks) == 0 {
				blocks = append(blocks, map[string]any{"type": "text", "text": m.Content})
			}
			messages = append(messages, map[string]any{"role": "user", "content": blocks})
		}
	}

	maxTokens := 4096
	if req.MaxTokens != nil && *req.MaxTokens > 0 {
		maxTokens = *req.MaxTokens
	}
	payload := map[string]any{
		"anthropic_version": "vertex-2023-10-16",
		"messages":          messages,
		"max_tokens":        maxTokens,
		"stream":            stream,
	}
	if len(systemPlain) > 0 {
		payload["system"] = strings.Join(systemPlain, "\n\n")
	}
	if req.Temperature != nil {
		payload["temperature"] = *req.Temperature
	}
	if req.TopP != nil {
		payload["top_p"] = *req.TopP
	}
	if len(req.Stop) > 0 {
		payload["stop_sequences"] = req.Stop
	}
	if len(req.Tools) > 0 {
		var tools []map[string]any
		for _, t := range req.Tools {
			tools = append(tools, map[string]any{
				"name":         t.Function.Name,
				"description":  t.Function.Description,
				"input_schema": t.Function.Parameters,
			})
		}
		payload["tools"] = tools
	}
	if req.ReasoningEffort != "" {
		budget := 4096
		switch strings.ToLower(req.ReasoningEffort) {
		case "minimal":
			budget = 1024
		case "low":
			budget = 2048
		case "high":
			budget = 8192
		case "xhigh", "max":
			budget = 16384
		}
		payload["thinking"] = map[string]any{"type": "enabled", "budget_tokens": budget}
		delete(payload, "temperature")
		delete(payload, "top_p")
	}
	return json.Marshal(payload)
}

func (a *Adapter) chatCompletionClaude(ctx context.Context, baseURL, projectID, region, token, model string, req *domain.CanonicalChatRequest) (*domain.CanonicalChatResponse, error) {
	preparedReq, err := a.materializeClaudeMedia(ctx, req)
	if err != nil {
		return nil, err
	}
	bodyBytes, err := buildVertexClaudePayload(preparedReq, false)
	if err != nil {
		return nil, err
	}
	targetURL := fmt.Sprintf("%s/v1/projects/%s/locations/%s/publishers/anthropic/models/%s:rawPredict",
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

	var antResp struct {
		ID         string `json:"id"`
		Model      string `json:"model"`
		StopReason string `json:"stop_reason"`
		Content    []struct {
			Type     string         `json:"type"`
			Text     string         `json:"text,omitempty"`
			Thinking string         `json:"thinking,omitempty"`
			ID       string         `json:"id,omitempty"`
			Name     string         `json:"name,omitempty"`
			Input    map[string]any `json:"input,omitempty"`
		} `json:"content"`
		Usage struct {
			InputTokens              int `json:"input_tokens"`
			OutputTokens             int `json:"output_tokens"`
			CacheReadInputTokens     int `json:"cache_read_input_tokens"`
			CacheCreationInputTokens int `json:"cache_creation_input_tokens"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(respBytes, &antResp); err != nil {
		return nil, fmt.Errorf("decode vertex claude response: %w", err)
	}

	var textSB, thinkSB strings.Builder
	var toolCalls []domain.CanonicalToolCall
	for _, b := range antResp.Content {
		switch b.Type {
		case "text":
			textSB.WriteString(b.Text)
		case "thinking":
			thinkSB.WriteString(b.Thinking)
		case "tool_use":
			args, _ := json.Marshal(b.Input)
			idx := len(toolCalls)
			toolCalls = append(toolCalls, domain.CanonicalToolCall{
				Index: &idx,
				ID:    b.ID,
				Type:  "function",
				Function: domain.CanonicalFunctionCall{
					Name:      b.Name,
					Arguments: string(args),
				},
			})
		}
	}
	finish := "stop"
	switch antResp.StopReason {
	case "max_tokens":
		finish = "length"
	case "tool_use":
		finish = "tool_calls"
	}
	promptTok := antResp.Usage.InputTokens + antResp.Usage.CacheReadInputTokens
	return &domain.CanonicalChatResponse{
		ID:       antResp.ID,
		Object:   "chat.completion",
		Created:  time.Now().Unix(),
		Model:    model,
		Provider: domain.ProviderVertex,
		Choices: []domain.CanonicalChoice{
			{
				Index: 0,
				Message: domain.CanonicalMessage{
					Role:             "assistant",
					Content:          textSB.String(),
					ReasoningContent: thinkSB.String(),
					ToolCalls:        toolCalls,
				},
				FinishReason: finish,
			},
		},
		Usage: domain.TokenUsage{
			PromptTokens:        promptTok,
			CompletionTokens:    antResp.Usage.OutputTokens,
			TotalTokens:         promptTok + antResp.Usage.OutputTokens,
			CachedPromptTokens:  antResp.Usage.CacheReadInputTokens,
			CacheCreationTokens: antResp.Usage.CacheCreationInputTokens,
		},
	}, nil
}

func (a *Adapter) streamChatCompletionClaude(ctx context.Context, baseURL, projectID, region, token, model string, req *domain.CanonicalChatRequest, onChunk adapter.StreamChunkHandler) (*domain.TokenUsage, error) {
	preparedReq, err := a.materializeClaudeMedia(ctx, req)
	if err != nil {
		return nil, err
	}
	bodyBytes, err := buildVertexClaudePayload(preparedReq, true)
	if err != nil {
		return nil, err
	}
	targetURL := fmt.Sprintf("%s/v1/projects/%s/locations/%s/publishers/anthropic/models/%s:streamRawPredict",
		baseURL, projectID, region, url.PathEscape(model))
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "text/event-stream")
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

	msgID := fmt.Sprintf("vertex-claude-%d", time.Now().UnixNano())
	created := time.Now().Unix()
	usage := &domain.TokenUsage{}
	toolIdx := -1

	err = sse.ReadEvents(resp.Body, func(ev sse.Event) error {
		if ev.Data == "" {
			return nil
		}
		var streamEv struct {
			Type    string `json:"type"`
			Message *struct {
				ID    string `json:"id"`
				Usage struct {
					InputTokens              int `json:"input_tokens"`
					CacheReadInputTokens     int `json:"cache_read_input_tokens"`
					CacheCreationInputTokens int `json:"cache_creation_input_tokens"`
				} `json:"usage"`
			} `json:"message,omitempty"`
			ContentBlock *struct {
				Type string `json:"type"`
				ID   string `json:"id"`
				Name string `json:"name"`
			} `json:"content_block,omitempty"`
			Delta *struct {
				Type        string `json:"type"`
				Text        string `json:"text"`
				Thinking    string `json:"thinking"`
				PartialJSON string `json:"partial_json"`
				StopReason  string `json:"stop_reason"`
			} `json:"delta,omitempty"`
			Usage *struct {
				OutputTokens int `json:"output_tokens"`
			} `json:"usage,omitempty"`
		}
		if err := json.Unmarshal([]byte(ev.Data), &streamEv); err != nil {
			return nil
		}
		switch streamEv.Type {
		case "message_start":
			if streamEv.Message != nil {
				if streamEv.Message.ID != "" {
					msgID = streamEv.Message.ID
				}
				usage.PromptTokens = streamEv.Message.Usage.InputTokens + streamEv.Message.Usage.CacheReadInputTokens
				usage.CachedPromptTokens = streamEv.Message.Usage.CacheReadInputTokens
				usage.CacheCreationTokens = streamEv.Message.Usage.CacheCreationInputTokens
			}
			return onChunk(&domain.CanonicalStreamChunk{
				ID:      msgID,
				Object:  "chat.completion.chunk",
				Created: created,
				Model:   model,
				Choices: []domain.CanonicalStreamChoice{{Index: 0, Delta: domain.CanonicalStreamDelta{Role: "assistant"}}},
			})
		case "content_block_start":
			if streamEv.ContentBlock != nil && streamEv.ContentBlock.Type == "tool_use" {
				toolIdx++
				idxCopy := toolIdx
				return onChunk(&domain.CanonicalStreamChunk{
					ID:      msgID,
					Object:  "chat.completion.chunk",
					Created: created,
					Model:   model,
					Choices: []domain.CanonicalStreamChoice{{
						Index: 0,
						Delta: domain.CanonicalStreamDelta{
							ToolCalls: []domain.CanonicalToolCall{{
								Index:    &idxCopy,
								ID:       streamEv.ContentBlock.ID,
								Type:     "function",
								Function: domain.CanonicalFunctionCall{Name: streamEv.ContentBlock.Name},
							}},
						},
					}},
				})
			}
		case "content_block_delta":
			if streamEv.Delta == nil {
				return nil
			}
			switch streamEv.Delta.Type {
			case "text_delta":
				return onChunk(&domain.CanonicalStreamChunk{
					ID: msgID, Object: "chat.completion.chunk", Created: created, Model: model,
					Choices: []domain.CanonicalStreamChoice{{Index: 0, Delta: domain.CanonicalStreamDelta{Content: streamEv.Delta.Text}}},
				})
			case "thinking_delta":
				return onChunk(&domain.CanonicalStreamChunk{
					ID: msgID, Object: "chat.completion.chunk", Created: created, Model: model,
					Choices: []domain.CanonicalStreamChoice{{Index: 0, Delta: domain.CanonicalStreamDelta{ReasoningContent: streamEv.Delta.Thinking}}},
				})
			case "input_json_delta":
				idxCopy := toolIdx
				if idxCopy < 0 {
					idxCopy = 0
				}
				return onChunk(&domain.CanonicalStreamChunk{
					ID: msgID, Object: "chat.completion.chunk", Created: created, Model: model,
					Choices: []domain.CanonicalStreamChoice{{
						Index: 0,
						Delta: domain.CanonicalStreamDelta{
							ToolCalls: []domain.CanonicalToolCall{{
								Index:    &idxCopy,
								Function: domain.CanonicalFunctionCall{Arguments: streamEv.Delta.PartialJSON},
							}},
						},
					}},
				})
			}
		case "message_delta":
			if streamEv.Usage != nil {
				usage.CompletionTokens = streamEv.Usage.OutputTokens
				usage.TotalTokens = usage.PromptTokens + usage.CompletionTokens
			}
			finish := "stop"
			if streamEv.Delta != nil && streamEv.Delta.StopReason != "" {
				switch streamEv.Delta.StopReason {
				case "max_tokens":
					finish = "length"
				case "tool_use":
					finish = "tool_calls"
				}
			}
			return onChunk(&domain.CanonicalStreamChunk{
				ID: msgID, Object: "chat.completion.chunk", Created: created, Model: model,
				Choices: []domain.CanonicalStreamChoice{{Index: 0, FinishReason: &finish}},
				Usage:   usage,
			})
		}
		return nil
	})
	usage.TotalTokens = usage.PromptTokens + usage.CompletionTokens
	return usage, err
}
