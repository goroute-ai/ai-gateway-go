package bedrock

import (
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

// Adapter implements adapter.ProviderAdapter for AWS Bedrock using the unified Converse API.
type Adapter struct {
	httpClient *http.Client
	ssrfPolicy *network.Policy
}

// NewAdapter creates a new AWS Bedrock adapter.
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
	return domain.ProviderBedrock
}

// Credentials holds AWS authentication details.
type Credentials struct {
	AccessKeyID     string `json:"aws_access_key_id"`
	SecretAccessKey string `json:"aws_secret_access_key"`
	Region          string `json:"aws_region"`
	SessionToken    string `json:"aws_session_token"`
}

func parseCredentials(cred *domain.ProviderCredential) (*Credentials, error) {
	if cred == nil {
		return nil, &domain.GatewayError{
			StatusCode:  http.StatusUnauthorized,
			Type:        domain.ErrorTypeAuthentication,
			Code:        "missing_credential",
			Message:     "bedrock credentials missing",
			AuthFailure: true,
		}
	}

	raw := strings.TrimSpace(cred.DecryptedAPIKey)
	var c Credentials

	// Check if JSON
	if strings.HasPrefix(raw, "{") {
		if err := json.Unmarshal([]byte(raw), &c); err == nil && c.AccessKeyID != "" && c.SecretAccessKey != "" {
			if c.Region == "" {
				c.Region = "us-east-1"
			}
			return &c, nil
		}
	}

	// Check if colon separated (key:secret or key:secret:region)
	if strings.Contains(raw, ":") {
		parts := strings.Split(raw, ":")
		if len(parts) >= 2 {
			c.AccessKeyID = parts[0]
			c.SecretAccessKey = parts[1]
			if len(parts) >= 3 {
				c.Region = parts[2]
			}
			if len(parts) >= 4 {
				c.SessionToken = parts[3]
			}
			if c.Region == "" {
				c.Region = "us-east-1"
			}
			return &c, nil
		}
	}

	// Fallback to single token or environment variable fallback for default credentials
	if raw != "" {
		c.AccessKeyID = raw
		c.SecretAccessKey = os.Getenv("AWS_SECRET_ACCESS_KEY")
		c.SessionToken = os.Getenv("AWS_SESSION_TOKEN")
		c.Region = os.Getenv("AWS_REGION")
		if c.Region == "" {
			c.Region = "us-east-1"
		}
		if c.SecretAccessKey != "" {
			return &c, nil
		}
	}

	return nil, &domain.GatewayError{
		StatusCode:  http.StatusUnauthorized,
		Type:        domain.ErrorTypeAuthentication,
		Code:        "invalid_aws_credential",
		Message:     "bedrock credentials require aws_access_key_id and aws_secret_access_key",
		AuthFailure: true,
	}
}

func (a *Adapter) getEndpointURL(dep *domain.Deployment, creds *Credentials, path string) (string, error) {
	if dep.Credential != nil && dep.Credential.BaseURL != "" {
		baseURL := strings.TrimRight(dep.Credential.BaseURL, "/")
		return baseURL + path, nil
	}
	region := creds.Region
	if region == "" {
		region = "us-east-1"
	}
	return fmt.Sprintf("https://bedrock-runtime.%s.amazonaws.com%s", region, path), nil
}

func (a *Adapter) ChatCompletion(ctx context.Context, dep *domain.Deployment, req *domain.CanonicalChatRequest) (*domain.CanonicalChatResponse, error) {
	creds, err := parseCredentials(dep.Credential)
	if err != nil {
		return nil, err
	}

	model := req.ResolvedModel
	if model == "" {
		model = req.Model
	}

	body, err := buildConversePayload(req)
	if err != nil {
		return nil, fmt.Errorf("build bedrock converse payload: %w", err)
	}

	path := fmt.Sprintf("/model/%s/converse", url.PathEscape(model))
	targetURL, err := a.getEndpointURL(dep, creds, path)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create converse request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	signer := &SigV4Signer{
		AccessKeyID:     creds.AccessKeyID,
		SecretAccessKey: creds.SecretAccessKey,
		SessionToken:    creds.SessionToken,
		Region:          creds.Region,
		Service:         "bedrock",
	}
	if err := signer.Sign(httpReq, body, time.Now()); err != nil {
		return nil, fmt.Errorf("sign converse request: %w", err)
	}

	resp, err := a.httpClient.Do(httpReq)
	if err != nil {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusBadGateway,
			Type:       domain.ErrorTypeUpstream,
			Code:       "bedrock_connection_failed",
			Message:    err.Error(),
			Retryable:  true,
		}
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read converse response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, parseBedrockError(resp.StatusCode, respBytes)
	}

	return parseConverseResponse(respBytes, model)
}

func (a *Adapter) StreamChatCompletion(ctx context.Context, dep *domain.Deployment, req *domain.CanonicalChatRequest, onChunk adapter.StreamChunkHandler) (*domain.TokenUsage, error) {
	creds, err := parseCredentials(dep.Credential)
	if err != nil {
		return nil, err
	}

	model := req.ResolvedModel
	if model == "" {
		model = req.Model
	}

	body, err := buildConversePayload(req)
	if err != nil {
		return nil, fmt.Errorf("build bedrock converse payload: %w", err)
	}

	path := fmt.Sprintf("/model/%s/converse-stream", url.PathEscape(model))
	targetURL, err := a.getEndpointURL(dep, creds, path)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create converse-stream request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")

	signer := &SigV4Signer{
		AccessKeyID:     creds.AccessKeyID,
		SecretAccessKey: creds.SecretAccessKey,
		SessionToken:    creds.SessionToken,
		Region:          creds.Region,
		Service:         "bedrock",
	}
	if err := signer.Sign(httpReq, body, time.Now()); err != nil {
		return nil, fmt.Errorf("sign converse-stream request: %w", err)
	}

	resp, err := a.httpClient.Do(httpReq)
	if err != nil {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusBadGateway,
			Type:       domain.ErrorTypeUpstream,
			Code:       "bedrock_stream_failed",
			Message:    err.Error(),
			Retryable:  true,
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBytes, _ := io.ReadAll(resp.Body)
		return nil, parseBedrockError(resp.StatusCode, respBytes)
	}

	var finalUsage domain.TokenUsage
	chunkID := fmt.Sprintf("bedrock-%d", time.Now().UnixNano())

	for {
		msg, err := DecodeEventStreamMessage(resp.Body)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("decode eventstream message: %w", err)
		}

		if msg.Headers[":message-type"] == "exception" {
			return nil, parseBedrockError(http.StatusBadRequest, msg.Payload)
		}

		var chunkData map[string]any
		if err := json.Unmarshal(msg.Payload, &chunkData); err != nil {
			continue
		}

		canonicalChunk := &domain.CanonicalStreamChunk{
			ID:      chunkID,
			Created: time.Now().Unix(),
			Model:   model,
		}

		if deltaBlock, ok := chunkData["contentBlockDelta"].(map[string]any); ok {
			if delta, ok := deltaBlock["delta"].(map[string]any); ok {
				if text, ok := delta["text"].(string); ok {
					canonicalChunk.Choices = []domain.CanonicalStreamChoice{
						{
							Index: 0,
							Delta: domain.CanonicalStreamDelta{
								Content: text,
							},
						},
					}
					if err := onChunk(canonicalChunk); err != nil {
						return &finalUsage, err
					}
				} else if toolUse, ok := delta["toolUse"].(map[string]any); ok {
					if inputStr, ok := toolUse["input"].(string); ok {
						canonicalChunk.Choices = []domain.CanonicalStreamChoice{
							{
								Index: 0,
								Delta: domain.CanonicalStreamDelta{
									ToolCalls: []domain.CanonicalToolCall{
										{
											Function: domain.CanonicalFunctionCall{
												Arguments: inputStr,
											},
										},
									},
								},
							},
						}
						if err := onChunk(canonicalChunk); err != nil {
							return &finalUsage, err
						}
					}
				}
			}
		} else if stopBlock, ok := chunkData["messageStop"].(map[string]any); ok {
			stopReason := ""
			if sr, ok := stopBlock["stopReason"].(string); ok {
				stopReason = mapBedrockStopReason(sr)
			}
			canonicalChunk.Choices = []domain.CanonicalStreamChoice{
				{
					Index:        0,
					FinishReason: &stopReason,
				},
			}
			_ = onChunk(canonicalChunk)
		} else if metaBlock, ok := chunkData["metadata"].(map[string]any); ok {
			if usageMap, ok := metaBlock["usage"].(map[string]any); ok {
				if in, ok := usageMap["inputTokens"].(float64); ok {
					finalUsage.PromptTokens = int(in)
					if cr, ok := usageMap["cacheReadInputTokens"].(float64); ok {
						finalUsage.PromptTokens += int(cr)
					}
				}
				if out, ok := usageMap["outputTokens"].(float64); ok {
					finalUsage.CompletionTokens = int(out)
				}
				if tot, ok := usageMap["totalTokens"].(float64); ok {
					finalUsage.TotalTokens = int(tot)
				}
			}
		}
	}

	return &finalUsage, nil
}

func (a *Adapter) Embeddings(ctx context.Context, dep *domain.Deployment, req *domain.CanonicalEmbeddingRequest) (*domain.CanonicalEmbeddingResponse, error) {
	creds, err := parseCredentials(dep.Credential)
	if err != nil {
		return nil, err
	}

	model := req.ResolvedModel
	if model == "" {
		model = req.Model
	}

	inputText := ""
	if len(req.Input) > 0 {
		inputText = req.Input[0]
	}

	reqPayload := map[string]any{
		"inputText": inputText,
	}
	body, _ := json.Marshal(reqPayload)

	path := fmt.Sprintf("/model/%s/invoke", url.PathEscape(model))
	targetURL, err := a.getEndpointURL(dep, creds, path)
	if err != nil {
		return nil, err
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	httpReq.Header.Set("Content-Type", "application/json")

	signer := &SigV4Signer{
		AccessKeyID:     creds.AccessKeyID,
		SecretAccessKey: creds.SecretAccessKey,
		SessionToken:    creds.SessionToken,
		Region:          creds.Region,
		Service:         "bedrock",
	}
	if err := signer.Sign(httpReq, body, time.Now()); err != nil {
		return nil, err
	}

	resp, err := a.httpClient.Do(httpReq)
	if err != nil {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusBadGateway,
			Type:       domain.ErrorTypeUpstream,
			Code:       "bedrock_embeddings_failed",
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
		return nil, parseBedrockError(resp.StatusCode, respBytes)
	}

	var invokeResp struct {
		Embedding           []float64 `json:"embedding"`
		InputTextTokenCount int       `json:"inputTextTokenCount"`
	}
	if err := json.Unmarshal(respBytes, &invokeResp); err != nil {
		return nil, fmt.Errorf("decode bedrock embedding response: %w", err)
	}

	return &domain.CanonicalEmbeddingResponse{
		Object: "list",
		Data: []domain.EmbeddingData{
			{
				Index:     0,
				Embedding: invokeResp.Embedding,
				Object:    "embedding",
			},
		},
		Model: model,
		Usage: domain.TokenUsage{
			PromptTokens: invokeResp.InputTextTokenCount,
			TotalTokens:  invokeResp.InputTextTokenCount,
		},
	}, nil
}

func (a *Adapter) ValidateCredential(ctx context.Context, cred *domain.ProviderCredential) error {
	creds, err := parseCredentials(cred)
	if err != nil {
		return err
	}
	if creds.AccessKeyID == "" || creds.SecretAccessKey == "" {
		return fmt.Errorf("missing aws access key or secret key")
	}
	return nil
}

func (a *Adapter) ListModels(ctx context.Context, cred *domain.ProviderCredential) ([]domain.DiscoveredModel, error) {
	// Bedrock model discovery through catalog
	return []domain.DiscoveredModel{
		{Provider: domain.ProviderBedrock, ModelName: "anthropic.claude-3-5-sonnet-20241022-v2:0", DisplayName: "Claude 3.5 Sonnet v2 (Bedrock)"},
		{Provider: domain.ProviderBedrock, ModelName: "amazon.nova-pro-v1:0", DisplayName: "Amazon Nova Pro"},
		{Provider: domain.ProviderBedrock, ModelName: "meta.llama3-3-70b-instruct-v1:0", DisplayName: "Llama 3.3 70B (Bedrock)"},
	}, nil
}

func buildConversePayload(req *domain.CanonicalChatRequest) ([]byte, error) {
	payload := make(map[string]any)

	var messages []map[string]any
	var systemList []map[string]string

	for _, m := range req.Messages {
		if m.Role == "system" {
			systemList = append(systemList, map[string]string{"text": m.Content})
			continue
		}

		bedrockRole := m.Role
		if bedrockRole != "user" && bedrockRole != "assistant" {
			bedrockRole = "user"
		}

		var content []map[string]any
		if m.Content != "" {
			content = append(content, map[string]any{"text": m.Content})
		}
		if m.ToolCallID != "" {
			content = append(content, map[string]any{
				"toolResult": map[string]any{
					"toolUseId": m.ToolCallID,
					"content":   []map[string]any{{"text": m.Content}},
					"status":    "success",
				},
			})
		}
		for _, tc := range m.ToolCalls {
			var inputMap map[string]any
			_ = json.Unmarshal([]byte(tc.Function.Arguments), &inputMap)
			if inputMap == nil {
				inputMap = make(map[string]any)
			}
			content = append(content, map[string]any{
				"toolUse": map[string]any{
					"toolUseId": tc.ID,
					"name":      tc.Function.Name,
					"input":     inputMap,
				},
			})
		}

		if len(content) > 0 {
			messages = append(messages, map[string]any{
				"role":    bedrockRole,
				"content": content,
			})
		}
	}

	payload["messages"] = messages
	if len(systemList) > 0 {
		payload["system"] = systemList
	}

	// Inference Config
	infConfig := make(map[string]any)
	if req.MaxTokens != nil && *req.MaxTokens > 0 {
		infConfig["maxTokens"] = *req.MaxTokens
	}
	if req.Temperature != nil {
		infConfig["temperature"] = *req.Temperature
	}
	if req.TopP != nil {
		infConfig["topP"] = *req.TopP
	}
	if len(req.Stop) > 0 {
		infConfig["stopSequences"] = req.Stop
	}
	if len(infConfig) > 0 {
		payload["inferenceConfig"] = infConfig
	}

	// Tool Config
	if len(req.Tools) > 0 {
		var tools []map[string]any
		for _, t := range req.Tools {
			spec := map[string]any{
				"name":        t.Function.Name,
				"description": t.Function.Description,
				"inputSchema": map[string]any{
					"json": t.Function.Parameters,
				},
			}
			tools = append(tools, map[string]any{"toolSpec": spec})
		}
		payload["toolConfig"] = map[string]any{
			"tools": tools,
		}
	}

	return json.Marshal(payload)
}

func parseConverseResponse(data []byte, model string) (*domain.CanonicalChatResponse, error) {
	var resp struct {
		Output struct {
			Message struct {
				Role    string `json:"role"`
				Content []struct {
					Text    string `json:"text,omitempty"`
					ToolUse *struct {
						ToolUseID string         `json:"toolUseId"`
						Name      string         `json:"name"`
						Input     map[string]any `json:"input"`
					} `json:"toolUse,omitempty"`
				} `json:"content"`
			} `json:"message"`
		} `json:"output"`
		StopReason string `json:"stopReason"`
		Usage      struct {
			InputTokens  int `json:"inputTokens"`
			OutputTokens int `json:"outputTokens"`
			TotalTokens  int `json:"totalTokens"`
		} `json:"usage"`
	}

	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal converse response: %w", err)
	}

	var sb strings.Builder
	var toolCalls []domain.CanonicalToolCall

	for i, c := range resp.Output.Message.Content {
		if c.Text != "" {
			sb.WriteString(c.Text)
		}
		if c.ToolUse != nil {
			args, _ := json.Marshal(c.ToolUse.Input)
			idx := i
			toolCalls = append(toolCalls, domain.CanonicalToolCall{
				Index: &idx,
				ID:    c.ToolUse.ToolUseID,
				Type:  "function",
				Function: domain.CanonicalFunctionCall{
					Name:      c.ToolUse.Name,
					Arguments: string(args),
				},
			})
		}
	}

	out := &domain.CanonicalChatResponse{
		ID:      fmt.Sprintf("bedrock-%d", time.Now().UnixNano()),
		Model:   model,
		Created: time.Now().Unix(),
		Choices: []domain.CanonicalChoice{
			{
				Index: 0,
				Message: domain.CanonicalMessage{
					Role:      "assistant",
					Content:   sb.String(),
					ToolCalls: toolCalls,
				},
				FinishReason: mapBedrockStopReason(resp.StopReason),
			},
		},
		Usage: domain.TokenUsage{
			PromptTokens:     resp.Usage.InputTokens,
			CompletionTokens: resp.Usage.OutputTokens,
			TotalTokens:      resp.Usage.TotalTokens,
		},
	}

	return out, nil
}

func mapBedrockStopReason(sr string) string {
	switch sr {
	case "end_turn":
		return "stop"
	case "tool_use":
		return "tool_calls"
	case "max_tokens":
		return "length"
	case "stop_sequence":
		return "stop"
	default:
		return sr
	}
}

func parseBedrockError(statusCode int, body []byte) error {
	var errResp struct {
		Message string `json:"message"`
	}
	_ = json.Unmarshal(body, &errResp)
	msg := errResp.Message
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
		gwErr.Code = "bedrock_auth_failed"
		gwErr.AuthFailure = true
	case http.StatusBadRequest:
		gwErr.Type = domain.ErrorTypeInvalidRequest
		gwErr.Code = "bedrock_invalid_request"
	case http.StatusTooManyRequests:
		gwErr.Type = domain.ErrorTypeRateLimit
		gwErr.Code = "bedrock_throttled"
		gwErr.Retryable = true
	default:
		gwErr.Type = domain.ErrorTypeUpstream
		gwErr.Code = "bedrock_upstream_error"
		gwErr.Retryable = true
	}
	return gwErr
}
