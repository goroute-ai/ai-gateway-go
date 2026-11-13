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
	ctx = adapter.StreamingContext(ctx)
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
	toolCallIndexes := make(map[int]int)
	nextToolCallIndex := 0

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

		if startBlock, ok := chunkData["contentBlockStart"].(map[string]any); ok {
			blockIdx := 0
			if idxVal, ok := startBlock["contentBlockIndex"].(float64); ok {
				blockIdx = int(idxVal)
			}
			if start, ok := startBlock["start"].(map[string]any); ok {
				if toolUse, ok := start["toolUse"].(map[string]any); ok {
					toolIndex, exists := toolCallIndexes[blockIdx]
					if !exists {
						toolIndex = nextToolCallIndex
						toolCallIndexes[blockIdx] = toolIndex
						nextToolCallIndex++
					}
					idStr, _ := toolUse["toolUseId"].(string)
					nameStr, _ := toolUse["name"].(string)
					idxCopy := toolIndex
					canonicalChunk.Choices = []domain.CanonicalStreamChoice{
						{
							Index: 0,
							Delta: domain.CanonicalStreamDelta{
								ToolCalls: []domain.CanonicalToolCall{
									{
										Index: &idxCopy,
										ID:    idStr,
										Type:  "function",
										Function: domain.CanonicalFunctionCall{
											Name: nameStr,
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
		} else if deltaBlock, ok := chunkData["contentBlockDelta"].(map[string]any); ok {
			blockIdx := 0
			if idxVal, ok := deltaBlock["contentBlockIndex"].(float64); ok {
				blockIdx = int(idxVal)
			}
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
				} else if rc, ok := delta["reasoningContent"].(map[string]any); ok {
					if rText, ok := rc["text"].(string); ok && rText != "" {
						canonicalChunk.Choices = []domain.CanonicalStreamChoice{
							{
								Index: 0,
								Delta: domain.CanonicalStreamDelta{
									ReasoningContent: rText,
								},
							},
						}
						if err := onChunk(canonicalChunk); err != nil {
							return &finalUsage, err
						}
					}
				} else if toolUse, ok := delta["toolUse"].(map[string]any); ok {
					if inputStr, ok := toolUse["input"].(string); ok {
						toolIndex, exists := toolCallIndexes[blockIdx]
						if !exists {
							toolIndex = nextToolCallIndex
							toolCallIndexes[blockIdx] = toolIndex
							nextToolCallIndex++
						}
						idxCopy := toolIndex
						canonicalChunk.Choices = []domain.CanonicalStreamChoice{
							{
								Index: 0,
								Delta: domain.CanonicalStreamDelta{
									ToolCalls: []domain.CanonicalToolCall{
										{
											Index: &idxCopy,
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
				if cr, ok := usageMap["cacheReadInputTokens"].(float64); ok {
					finalUsage.CachedPromptTokens = int(cr)
				}
				if cw, ok := usageMap["cacheWriteInputTokens"].(float64); ok {
					finalUsage.CacheCreationTokens = int(cw)
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

	if len(req.Input) == 0 {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_embedding_request",
			Message:    "at least one input is required",
			Provider:   domain.ProviderBedrock,
		}
	}
	lowerModel := strings.ToLower(model)
	isCohere := strings.Contains(lowerModel, "cohere.embed")
	isCohereV4 := isCohere && strings.Contains(lowerModel, "v4")
	isTitanV2 := strings.Contains(lowerModel, "titan-embed-text-v2")
	if req.Dimensions != nil && *req.Dimensions > 0 && !isTitanV2 && !isCohereV4 {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "unsupported_embedding_dimensions",
			Message:    "requested embedding dimensions are unsupported by this Bedrock model",
			Provider:   domain.ProviderBedrock,
		}
	}
	if req.EncodingFormat != "" && req.EncodingFormat != "float" {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "unsupported_embedding_format",
			Message:    "Bedrock embedding adapter currently returns float vectors only",
			Provider:   domain.ProviderBedrock,
		}
	}

	invoke := func(payload map[string]any) ([]byte, error) {
		body, err := json.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("marshal bedrock embedding request: %w", err)
		}
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
		return respBytes, nil
	}

	var data []domain.EmbeddingData
	totalTokens := 0
	if isCohere {
		inputType := req.InputType
		if inputType == "" {
			inputType = "search_document"
		}
		payload := map[string]any{"texts": req.Input, "input_type": inputType, "truncate": "END"}
		if req.Dimensions != nil && *req.Dimensions > 0 && isCohereV4 {
			payload["output_dimension"] = *req.Dimensions
		}
		payload["embedding_types"] = []string{"float"}
		respBytes, err := invoke(payload)
		if err != nil {
			return nil, err
		}
		var wire struct {
			Embeddings          json.RawMessage `json:"embeddings"`
			InputTextTokenCount int             `json:"inputTextTokenCount"`
		}
		if err := json.Unmarshal(respBytes, &wire); err != nil {
			return nil, fmt.Errorf("decode bedrock Cohere embedding response: %w", err)
		}
		var vectors [][]float64
		if err := json.Unmarshal(wire.Embeddings, &vectors); err != nil {
			var typed struct {
				Float [][]float64 `json:"float"`
			}
			if typedErr := json.Unmarshal(wire.Embeddings, &typed); typedErr != nil {
				return nil, fmt.Errorf("decode bedrock Cohere embedding vectors: %w", typedErr)
			}
			vectors = typed.Float
		}
		for i, vector := range vectors {
			data = append(data, domain.EmbeddingData{Index: i, Embedding: vector, Object: "embedding"})
		}
		totalTokens = wire.InputTextTokenCount
	} else {
		for i, inputText := range req.Input {
			payload := map[string]any{"inputText": inputText}
			if strings.Contains(strings.ToLower(model), "titan-embed-text-v2") {
				if req.Dimensions != nil && *req.Dimensions > 0 {
					payload["dimensions"] = *req.Dimensions
				}
				payload["normalize"] = true
			}
			respBytes, err := invoke(payload)
			if err != nil {
				return nil, err
			}
			var wire struct {
				Embedding           []float64 `json:"embedding"`
				InputTextTokenCount int       `json:"inputTextTokenCount"`
			}
			if err := json.Unmarshal(respBytes, &wire); err != nil {
				return nil, fmt.Errorf("decode bedrock embedding response: %w", err)
			}
			data = append(data, domain.EmbeddingData{Index: i, Embedding: wire.Embedding, Object: "embedding"})
			totalTokens += wire.InputTextTokenCount
		}
	}
	if len(data) != len(req.Input) {
		return nil, fmt.Errorf("bedrock returned %d embeddings for %d inputs", len(data), len(req.Input))
	}
	return &domain.CanonicalEmbeddingResponse{
		Object:   "list",
		Data:     data,
		Model:    model,
		Provider: domain.ProviderBedrock,
		Usage:    domain.TokenUsage{PromptTokens: totalTokens, TotalTokens: totalTokens},
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

// Rerank translates the shared rerank contract to the Bedrock Agent Runtime API.
func (a *Adapter) Rerank(ctx context.Context, dep *domain.Deployment, req *domain.CanonicalRerankRequest) (*domain.CanonicalRerankResponse, error) {
	creds, err := parseCredentials(dep.Credential)
	if err != nil {
		return nil, err
	}
	model := req.ResolvedModel
	if model == "" {
		model = req.Model
	}
	if model == "" || len(req.Documents) == 0 || strings.TrimSpace(req.Query) == "" {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_rerank_request",
			Message:    "model, query, and at least one document are required",
			Provider:   domain.ProviderBedrock,
		}
	}

	sources := make([]map[string]any, 0, len(req.Documents))
	for _, document := range req.Documents {
		if document.Raw != nil {
			sources = append(sources, map[string]any{
				"type": "INLINE",
				"inlineDocumentSource": map[string]any{
					"type":         "JSON",
					"jsonDocument": document.Raw,
				},
			})
			continue
		}
		sources = append(sources, map[string]any{
			"type": "INLINE",
			"inlineDocumentSource": map[string]any{
				"type":         "TEXT",
				"textDocument": map[string]any{"text": document.Text},
			},
		})
	}
	resultCount := len(req.Documents)
	if req.TopN != nil && *req.TopN > 0 {
		resultCount = *req.TopN
	}
	payload := map[string]any{
		"queries": []map[string]any{{
			"type":      "TEXT",
			"textQuery": map[string]any{"text": req.Query},
		}},
		"rerankingConfiguration": map[string]any{
			"type": "BEDROCK_RERANKING_MODEL",
			"bedrockRerankingConfiguration": map[string]any{
				"modelConfiguration": map[string]any{"modelArn": model},
				"numberOfResults":    resultCount,
			},
		},
		"sources": sources,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("marshal bedrock rerank request: %w", err)
	}

	targetURL := ""
	if dep.Credential.BaseURL != "" {
		targetURL = strings.TrimRight(dep.Credential.BaseURL, "/") + "/rerank"
	} else {
		runtimeURL, err := a.getEndpointURL(dep, creds, "/rerank")
		if err != nil {
			return nil, err
		}
		targetURL = strings.Replace(runtimeURL, "bedrock-runtime.", "bedrock-agent-runtime.", 1)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("create bedrock rerank request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	signer := &SigV4Signer{
		AccessKeyID:     creds.AccessKeyID,
		SecretAccessKey: creds.SecretAccessKey,
		SessionToken:    creds.SessionToken,
		Region:          creds.Region,
		Service:         "bedrock-agent-runtime",
	}
	if err := signer.Sign(httpReq, body, time.Now()); err != nil {
		return nil, fmt.Errorf("sign bedrock rerank request: %w", err)
	}
	resp, err := a.httpClient.Do(httpReq)
	if err != nil {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusBadGateway,
			Type:       domain.ErrorTypeUpstream,
			Code:       "bedrock_rerank_connection_failed",
			Message:    err.Error(),
			Retryable:  true,
		}
	}
	defer resp.Body.Close()
	respBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read bedrock rerank response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, parseBedrockError(resp.StatusCode, respBytes)
	}
	var wire struct {
		ID      string `json:"id"`
		Results []struct {
			Index               int     `json:"index"`
			RelevanceScore      float64 `json:"relevanceScore"`
			SnakeRelevanceScore float64 `json:"relevance_score"`
		} `json:"results"`
		Usage struct {
			SearchUnits      int `json:"search_units"`
			CamelSearchUnits int `json:"searchUnits"`
		} `json:"usage"`
	}
	if err := json.Unmarshal(respBytes, &wire); err != nil {
		return nil, fmt.Errorf("decode bedrock rerank response: %w", err)
	}
	results := make([]domain.RerankResultItem, len(wire.Results))
	for i, result := range wire.Results {
		score := result.RelevanceScore
		if score == 0 {
			score = result.SnakeRelevanceScore
		}
		results[i] = domain.RerankResultItem{Index: result.Index, RelevanceScore: score}
	}
	searchUnits := wire.Usage.SearchUnits
	if searchUnits == 0 {
		searchUnits = wire.Usage.CamelSearchUnits
	}
	return &domain.CanonicalRerankResponse{
		ID:       wire.ID,
		Model:    model,
		Provider: domain.ProviderBedrock,
		Results:  results,
		Usage:    domain.RerankUsage{SearchUnits: searchUnits},
	}, nil
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
	var systemList []map[string]any

	for _, m := range req.Messages {
		if m.Role == "system" || m.Role == "developer" {
			if m.Content != "" {
				systemList = append(systemList, map[string]any{"text": m.Content})
			}
			for _, p := range m.Parts {
				if p.Type == "text" && p.Text != "" {
					systemList = append(systemList, map[string]any{"text": p.Text})
				}
			}
			if m.CacheControl != nil {
				systemList = append(systemList, map[string]any{"cachePoint": map[string]any{"type": "default"}})
			}
			continue
		}

		bedrockRole := m.Role
		if bedrockRole != "user" && bedrockRole != "assistant" {
			bedrockRole = "user"
		}

		var content []map[string]any
		if m.ToolCallID != "" {
			content = append(content, map[string]any{
				"toolResult": map[string]any{
					"toolUseId": m.ToolCallID,
					"content":   []map[string]any{{"text": m.Content}},
					"status":    "success",
				},
			})
		} else if len(m.Parts) > 0 {
			for _, p := range m.Parts {
				switch p.Type {
				case "text":
					if p.Text != "" {
						content = append(content, map[string]any{"text": p.Text})
					}
				case "image_url":
					if p.ImageURL != nil {
						if fmtName, b64Data, ok := parseDataURI(p.ImageURL.URL); ok {
							content = append(content, map[string]any{
								"image": map[string]any{
									"format": strings.TrimPrefix(fmtName, "image/"),
									"source": map[string]any{"bytes": b64Data},
								},
							})
						}
					}
				case "document":
					if p.Document != nil && p.Document.Data != "" {
						docName := p.Document.Filename
						if docName == "" {
							docName = "document"
						}
						docFmt := "pdf"
						if strings.Contains(p.Document.MimeType, "csv") {
							docFmt = "csv"
						} else if strings.Contains(p.Document.MimeType, "html") {
							docFmt = "html"
						} else if strings.Contains(p.Document.MimeType, "markdown") {
							docFmt = "md"
						} else if strings.Contains(p.Document.MimeType, "plain") {
							docFmt = "txt"
						}
						content = append(content, map[string]any{
							"document": map[string]any{
								"format": docFmt,
								"name":   docName,
								"source": map[string]any{"bytes": p.Document.Data},
							},
						})
					}
				}
				if p.CacheControl != nil {
					content = append(content, map[string]any{"cachePoint": map[string]any{"type": "default"}})
				}
			}
		} else if m.Content != "" {
			content = append(content, map[string]any{"text": m.Content})
		}
		if m.CacheControl != nil {
			content = append(content, map[string]any{"cachePoint": map[string]any{"type": "default"}})
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
			// Merge consecutive tool-result user turns into a single Bedrock user message
			if m.Role == "tool" && len(messages) > 0 && messages[len(messages)-1]["role"] == "user" {
				if prevContent, ok := messages[len(messages)-1]["content"].([]map[string]any); ok {
					messages[len(messages)-1]["content"] = append(prevContent, content...)
					continue
				}
			}
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
			if t.CacheControl != nil {
				tools = append(tools, map[string]any{"cachePoint": map[string]any{"type": "default"}})
			}
		}
		tcMap := map[string]any{"tools": tools}
		if req.ToolChoice != nil {
			switch tc := req.ToolChoice.(type) {
			case string:
				switch tc {
				case "auto":
					tcMap["toolChoice"] = map[string]any{"auto": map[string]any{}}
				case "required":
					tcMap["toolChoice"] = map[string]any{"any": map[string]any{}}
				}
			case map[string]any:
				if fn, ok := tc["function"].(map[string]any); ok {
					if name, ok := fn["name"].(string); ok && name != "" {
						tcMap["toolChoice"] = map[string]any{"tool": map[string]any{"name": name}}
					}
				}
			}
		}
		payload["toolConfig"] = tcMap
	}

	// Structured Outputs (Converse outputConfig)
	if req.ResponseFormat != nil && req.ResponseFormat.Type == "json_schema" && len(req.ResponseFormat.JSONSchema) > 0 {
		schemaBytes, _ := json.Marshal(req.ResponseFormat.JSONSchema)
		payload["outputConfig"] = map[string]any{
			"textFormat": map[string]any{
				"type": "json_schema",
				"structure": map[string]any{
					"jsonSchema": map[string]any{
						"schema": string(schemaBytes),
					},
				},
			},
		}
	}

	// Reasoning Effort (additionalModelRequestFields)
	if req.ReasoningEffort != "" && !strings.EqualFold(req.ReasoningEffort, "none") {
		modelLower := strings.ToLower(req.ResolvedModel + " " + req.Model)
		switch {
		case strings.Contains(modelLower, "claude"):
			budget := 4096
			switch strings.ToLower(req.ReasoningEffort) {
			case "minimal", "low":
				budget = 2048
			case "high", "xhigh", "max":
				budget = 8192
			}
			payload["additionalModelRequestFields"] = map[string]any{
				"thinking": map[string]any{"type": "enabled", "budget_tokens": budget},
			}
		case strings.Contains(modelLower, "nova"):
			payload["additionalModelRequestFields"] = map[string]any{
				"reasoningConfig": map[string]any{"type": "enabled", "maxReasoningEffort": strings.ToLower(req.ReasoningEffort)},
			}
		}
	}

	return json.Marshal(payload)
}

func parseDataURI(uri string) (mime string, b64 string, ok bool) {
	if !strings.HasPrefix(uri, "data:") {
		return "", "", false
	}
	rest := strings.TrimPrefix(uri, "data:")
	semi := strings.Index(rest, ";base64,")
	if semi <= 0 {
		return "", "", false
	}
	return rest[:semi], rest[semi+len(";base64,"):], true
}

func parseConverseResponse(data []byte, model string) (*domain.CanonicalChatResponse, error) {
	var resp struct {
		Output struct {
			Message struct {
				Role    string `json:"role"`
				Content []struct {
					Text             string `json:"text,omitempty"`
					ReasoningContent *struct {
						ReasoningText *struct {
							Text string `json:"text"`
						} `json:"reasoningText,omitempty"`
					} `json:"reasoningContent,omitempty"`
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
			InputTokens           int `json:"inputTokens"`
			OutputTokens          int `json:"outputTokens"`
			TotalTokens           int `json:"totalTokens"`
			CacheReadInputTokens  int `json:"cacheReadInputTokens"`
			CacheWriteInputTokens int `json:"cacheWriteInputTokens"`
		} `json:"usage"`
	}

	if err := json.Unmarshal(data, &resp); err != nil {
		return nil, fmt.Errorf("unmarshal converse response: %w", err)
	}

	var sb strings.Builder
	var rsb strings.Builder
	var toolCalls []domain.CanonicalToolCall

	for i, c := range resp.Output.Message.Content {
		if c.Text != "" {
			sb.WriteString(c.Text)
		}
		if c.ReasoningContent != nil && c.ReasoningContent.ReasoningText != nil {
			rsb.WriteString(c.ReasoningContent.ReasoningText.Text)
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
					Role:             "assistant",
					Content:          sb.String(),
					ReasoningContent: rsb.String(),
					ToolCalls:        toolCalls,
				},
				FinishReason: mapBedrockStopReason(resp.StopReason),
			},
		},
		Usage: domain.TokenUsage{
			PromptTokens:        resp.Usage.InputTokens + resp.Usage.CacheReadInputTokens,
			CompletionTokens:    resp.Usage.OutputTokens,
			TotalTokens:         resp.Usage.TotalTokens,
			CachedPromptTokens:  resp.Usage.CacheReadInputTokens,
			CacheCreationTokens: resp.Usage.CacheWriteInputTokens,
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
