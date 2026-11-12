package server

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/finops"
	"github.com/goroute-ai/ai-gateway-go/internal/logger"
	"github.com/goroute-ai/ai-gateway-go/internal/observability"
	"github.com/goroute-ai/ai-gateway-go/internal/ratelimit"
)

type anthropicMessagesPayload struct {
	Model         string             `json:"model"`
	Messages      []anthropicMsg     `json:"messages"`
	System        any                `json:"system,omitempty"`
	MaxTokens     int                `json:"max_tokens"`
	Temperature   *float64           `json:"temperature,omitempty"`
	TopP          *float64           `json:"top_p,omitempty"`
	TopK          *int               `json:"top_k,omitempty"`
	Stream        bool               `json:"stream,omitempty"`
	StopSequences []string           `json:"stop_sequences,omitempty"`
	Tools         []anthropicToolDef `json:"tools,omitempty"`
	ToolChoice    any                `json:"tool_choice,omitempty"`
	Thinking      map[string]any     `json:"thinking,omitempty"`
}

type anthropicMsg struct {
	Role    string `json:"role"`
	Content any    `json:"content"`
}

type anthropicToolDef struct {
	Name        string         `json:"name"`
	Description string         `json:"description,omitempty"`
	InputSchema map[string]any `json:"input_schema"`
}

// handleAnthropicMessages serves `POST /v1/messages` and `POST /anthropic/v1/messages`.
func (s *GatewayServer) handleAnthropicMessages(w http.ResponseWriter, r *http.Request) {
	reqID := r.Header.Get("X-Request-Id")
	if reqID == "" {
		reqID = "msg_" + uuid.NewString()
	}
	w.Header().Set("X-Gateway-Request-Id", reqID)
	traceID := observability.TraceFromContext(r.Context()).TraceID

	idCtx := auth.IdentityFromContext(r.Context())
	if idCtx == nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusUnauthorized,
			Type:       domain.ErrorTypeAuthentication,
			Code:       "unauthenticated",
			Message:    "Missing virtual key identity context",
		})
		return
	}

	var payload anthropicMessagesPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_json_body",
			Message:    "Failed to parse Anthropic Messages request: " + err.Error(),
		})
		return
	}

	payload.Model = strings.TrimSpace(payload.Model)
	if payload.Model == "" {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "missing_model",
			Message:    "model parameter is required",
		})
		return
	}

	if len(payload.Messages) == 0 {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "missing_messages",
			Message:    "messages array cannot be empty",
		})
		return
	}

	// 1. RBAC Model Allowlist Check
	if err := s.rbac.AuthorizeRequestedModel(idCtx, payload.Model); err != nil {
		s.collector.Record(observability.RequestObservation{StatusCode: http.StatusForbidden})
		domain.WriteHTTPError(w, err)
		return
	}

	// 2. Translate Anthropic Messages payload into CanonicalChatRequest
	chatReq := domain.CanonicalChatRequest{
		RequestID:   reqID,
		Model:       payload.Model,
		Stream:      payload.Stream,
		Temperature: payload.Temperature,
		TopP:        payload.TopP,
		Stop:        payload.StopSequences,
	}
	if payload.MaxTokens > 0 {
		chatReq.MaxTokens = &payload.MaxTokens
	}

	// Translate System
	if payload.System != nil {
		sysText := parseAnthropicSystem(payload.System)
		if sysText != "" {
			chatReq.Messages = append(chatReq.Messages, domain.CanonicalMessage{
				Role:    "system",
				Content: sysText,
			})
		}
	}

	// Translate Messages
	for _, m := range payload.Messages {
		convMsgs := parseAnthropicMessage(m)
		chatReq.Messages = append(chatReq.Messages, convMsgs...)
	}

	// Translate Tools
	for _, t := range payload.Tools {
		chatReq.Tools = append(chatReq.Tools, domain.CanonicalTool{
			Type: "function",
			Function: domain.CanonicalFunction{
				Name:        t.Name,
				Description: t.Description,
				Parameters:  t.InputSchema,
			},
		})
	}

	// 3. Rate Limiting Quota
	estTokens := ratelimit.EstimateRequestTokens(&chatReq)
	releaseQuota, err := s.limiter.Acquire(r.Context(), idCtx, estTokens)
	if err != nil {
		s.collector.Record(admissionFailureObservation(err))
		domain.WriteHTTPError(w, err)
		return
	}

	// 4. Dispatch Execution
	if payload.Stream {
		s.streamAnthropicMessages(w, r, idCtx, &chatReq, estTokens, releaseQuota, traceID, reqID)
		return
	}

	resp, meta, err := s.reliability.ExecuteChat(r.Context(), idCtx, &chatReq)
	if err != nil {
		releaseQuota(0)
		s.collector.Record(observability.RequestObservation{StatusCode: http.StatusBadGateway})
		domain.WriteHTTPError(w, err)
		return
	}
	releaseQuota(resp.Usage.TotalTokens)

	var gm *domain.GlobalModel
	var depID, depName string
	var pricingVer int
	if meta != nil && meta.WinningDeployment != nil {
		depID = meta.WinningDeployment.ID
		depName = meta.WinningDeployment.DeploymentName
		gm = meta.WinningDeployment.GlobalModel
		if gm != nil {
			pricingVer = gm.PricingVersion
		}
	}

	costMicros := finops.CalculateCostMicros(gm, resp.Usage)
	pricingStatus := domain.ResolvePricingStatus(gm)

	s.collector.Record(observability.RequestObservation{
		Provider:         string(resp.Provider),
		DeploymentID:     depID,
		DeploymentName:   depName,
		Model:            resp.Model,
		StatusCode:       http.StatusOK,
		LatencyMs:        meta.LatencyMs,
		RoutingMicros:    meta.RoutingMicros,
		PromptTokens:     resp.Usage.PromptTokens,
		CompletionTokens: resp.Usage.CompletionTokens,
		CostMicros:       costMicros,
	})

	w.Header().Set("X-Gateway-Provider", string(resp.Provider))
	w.Header().Set("X-Gateway-Cost-Micros", strconv.FormatInt(costMicros, 10))
	w.Header().Set("X-Gateway-Pricing-Status", string(pricingStatus))
	w.Header().Set("Content-Type", "application/json")

	// Convert CanonicalChatResponse to Anthropic JSON response
	anthropicResp := toAnthropicResponse(resp, reqID)

	var provenance string
	if gm != nil {
		provenance = gm.PricingProvenanceSource
	}

	if !s.persistSpendEvent(w, r, domain.SpendEvent{
		RequestID:               reqID,
		TraceID:                 traceID,
		OrgID:                   idCtx.OrgID,
		TeamID:                  idCtx.TeamID,
		UserID:                  idCtx.UserID,
		VirtualKeyID:            idCtx.VirtualKeyID,
		Endpoint:                r.URL.Path,
		RequestedModel:          payload.Model,
		ResolvedModel:           resp.Model,
		Provider:                resp.Provider,
		DeploymentID:            depID,
		PricingVersion:          pricingVer,
		PricingStatus:           pricingStatus,
		PricingProvenanceSource: provenance,
		Usage:                   resp.Usage,
		CostMicros:              costMicros,
		LatencyMs:               meta.LatencyMs,
		StatusCode:              http.StatusOK,
		Modality:                domain.ModalityChat,
		CreatedAt:               time.Now().UTC(),
	}) {
		return
	}
	_ = json.NewEncoder(w).Encode(anthropicResp)

	logger.InfoContext(r.Context(), "Anthropic Messages request completed",
		slog.String("component", "messages_bridge"),
		slog.String("request_id", reqID),
		slog.String("provider", string(resp.Provider)),
		slog.String("model", resp.Model),
		slog.Int("prompt_tokens", resp.Usage.PromptTokens),
		slog.Int("completion_tokens", resp.Usage.CompletionTokens),
		slog.Int64("cost_micros", costMicros),
		slog.Int64("latency_ms", meta.LatencyMs),
	)
}

func (s *GatewayServer) streamAnthropicMessages(
	w http.ResponseWriter,
	r *http.Request,
	idCtx *domain.IdentityContext,
	chatReq *domain.CanonicalChatRequest,
	estTokens int,
	releaseQuota func(int),
	traceID, reqID string,
) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		releaseQuota(0)
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusInternalServerError,
			Type:       domain.ErrorTypeServer,
			Code:       "streaming_not_supported",
			Message:    "ResponseWriter does not support SSE flushing",
		})
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)

	// Send message_start
	fmt.Fprintf(w, "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"id\":%q,\"type\":\"message\",\"role\":\"assistant\",\"model\":%q,\"content\":[],\"stop_reason\":null,\"stop_sequence\":null,\"usage\":{\"input_tokens\":%d,\"output_tokens\":0}}}\n\n",
		reqID, chatReq.Model, estTokens)
	// Send content_block_start
	fmt.Fprintf(w, "event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"text\",\"text\":\"\"}}\n\n")
	flusher.Flush()

	var outputTokens int
	var winningDep *domain.Deployment

	usage, meta, err := s.reliability.ExecuteStream(r.Context(), idCtx, chatReq, func(chunk *domain.CanonicalStreamChunk) error {
		if chunk == nil {
			return nil
		}
		for _, choice := range chunk.Choices {
			if choice.Delta.Content != "" {
				outputTokens++
				deltaBytes, _ := json.Marshal(map[string]any{
					"type":  "content_block_delta",
					"index": 0,
					"delta": map[string]string{
						"type": "text_delta",
						"text": choice.Delta.Content,
					},
				})
				fmt.Fprintf(w, "event: content_block_delta\ndata: %s\n\n", string(deltaBytes))
				flusher.Flush()
			}
		}
		return nil
	}, func(dep *domain.Deployment) {
		winningDep = dep
	})

	if err != nil {
		releaseQuota(0)
		errBytes, _ := json.Marshal(map[string]any{
			"type": "error",
			"error": map[string]string{
				"type":    "api_error",
				"message": err.Error(),
			},
		})
		fmt.Fprintf(w, "event: error\ndata: %s\n\n", string(errBytes))
		flusher.Flush()
		return
	}

	totalTokens := estTokens + outputTokens
	if usage != nil && usage.TotalTokens > 0 {
		totalTokens = usage.TotalTokens
		outputTokens = usage.CompletionTokens
	}
	releaseQuota(totalTokens)

	var gm *domain.GlobalModel
	var depID string
	var pricingVer int
	if winningDep != nil {
		depID = winningDep.ID
		gm = winningDep.GlobalModel
		if gm != nil {
			pricingVer = gm.PricingVersion
		}
	}
	finalUsage := domain.TokenUsage{
		PromptTokens:     estTokens,
		CompletionTokens: outputTokens,
		TotalTokens:      totalTokens,
	}
	costMicros := finops.CalculateCostMicros(gm, finalUsage)

	if err := s.spendWorker.Record(r.Context(), domain.SpendEvent{
		RequestID:      reqID,
		TraceID:        traceID,
		OrgID:          idCtx.OrgID,
		TeamID:         idCtx.TeamID,
		UserID:         idCtx.UserID,
		VirtualKeyID:   idCtx.VirtualKeyID,
		Endpoint:       r.URL.Path,
		RequestedModel: chatReq.Model,
		ResolvedModel:  chatReq.ResolvedModel,
		DeploymentID:   depID,
		PricingVersion: pricingVer,
		Usage:          finalUsage,
		CostMicros:     costMicros,
		LatencyMs:      meta.LatencyMs,
		StatusCode:     http.StatusOK,
		Modality:       domain.ModalityChat,
		CreatedAt:      time.Now().UTC(),
	}); err != nil {
		fmt.Fprintf(w, "event: error\ndata: {\"type\":\"error\",\"error\":{\"type\":\"server_error\",\"message\":\"unable to persist request accounting\"}}\n\n")
		flusher.Flush()
		return
	}
	fmt.Fprintf(w, "event: content_block_stop\ndata: {\"type\":\"content_block_stop\",\"index\":0}\n\n")
	fmt.Fprintf(w, "event: message_delta\ndata: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\",\"stop_sequence\":null},\"usage\":{\"output_tokens\":%d}}\n\n", outputTokens)
	fmt.Fprintf(w, "event: message_stop\ndata: {\"type\":\"message_stop\"}\n\n")
	flusher.Flush()
}

func parseAnthropicSystem(sys any) string {
	switch v := sys.(type) {
	case string:
		return v
	case []any:
		var sb strings.Builder
		for _, item := range v {
			if m, ok := item.(map[string]any); ok {
				if t, ok := m["text"].(string); ok {
					if sb.Len() > 0 {
						sb.WriteString("\n\n")
					}
					sb.WriteString(t)
				}
			}
		}
		return sb.String()
	default:
		return ""
	}
}

func parseAnthropicMessage(m anthropicMsg) []domain.CanonicalMessage {
	switch v := m.Content.(type) {
	case string:
		return []domain.CanonicalMessage{{
			Role:    m.Role,
			Content: v,
		}}
	case []any:
		var textParts []string
		var parts []domain.ContentPart
		var toolCalls []domain.CanonicalToolCall
		var separateToolResults []domain.CanonicalMessage

		for _, item := range v {
			block, ok := item.(map[string]any)
			if !ok {
				continue
			}
			blockType, _ := block["type"].(string)
			switch blockType {
			case "text":
				if txt, ok := block["text"].(string); ok {
					textParts = append(textParts, txt)
					parts = append(parts, domain.ContentPart{Type: "text", Text: txt})
				}
			case "image":
				if src, ok := block["source"].(map[string]any); ok {
					mediaType, _ := src["media_type"].(string)
					data, _ := src["data"].(string)
					url := fmt.Sprintf("data:%s;base64,%s", mediaType, data)
					parts = append(parts, domain.ContentPart{
						Type:     "image_url",
						ImageURL: &domain.ImageURL{URL: url},
					})
				}
			case "tool_use":
				callID, _ := block["id"].(string)
				name, _ := block["name"].(string)
				input := block["input"]
				argBytes, _ := json.Marshal(input)
				toolCalls = append(toolCalls, domain.CanonicalToolCall{
					ID:   callID,
					Type: "function",
					Function: domain.CanonicalFunctionCall{
						Name:      name,
						Arguments: string(argBytes),
					},
				})
			case "tool_result":
				toolUseID, _ := block["tool_use_id"].(string)
				content := block["content"]
				contentStr := ""
				switch cv := content.(type) {
				case string:
					contentStr = cv
				default:
					b, _ := json.Marshal(cv)
					contentStr = string(b)
				}
				separateToolResults = append(separateToolResults, domain.CanonicalMessage{
					Role:       "tool",
					ToolCallID: toolUseID,
					Content:    contentStr,
				})
			}
		}

		var out []domain.CanonicalMessage
		if len(separateToolResults) > 0 {
			out = append(out, separateToolResults...)
		}
		if len(textParts) > 0 || len(parts) > 0 || len(toolCalls) > 0 {
			out = append(out, domain.CanonicalMessage{
				Role:      m.Role,
				Content:   strings.Join(textParts, "\n\n"),
				Parts:     parts,
				ToolCalls: toolCalls,
			})
		}
		return out
	default:
		return nil
	}
}

func toAnthropicResponse(resp *domain.CanonicalChatResponse, reqID string) map[string]any {
	var contentBlocks []map[string]any
	stopReason := "end_turn"

	if len(resp.Choices) > 0 {
		choice := resp.Choices[0]
		if choice.Message.Content != "" {
			contentBlocks = append(contentBlocks, map[string]any{
				"type": "text",
				"text": choice.Message.Content,
			})
		}
		for _, tc := range choice.Message.ToolCalls {
			var inputMap map[string]any
			_ = json.Unmarshal([]byte(tc.Function.Arguments), &inputMap)
			if inputMap == nil {
				inputMap = map[string]any{}
			}
			contentBlocks = append(contentBlocks, map[string]any{
				"type":  "tool_use",
				"id":    tc.ID,
				"name":  tc.Function.Name,
				"input": inputMap,
			})
			stopReason = "tool_use"
		}
		switch choice.FinishReason {
		case "length":
			stopReason = "max_tokens"
		case "tool_calls":
			stopReason = "tool_use"
		case "content_filter":
			stopReason = "stop_sequence"
		}
	}

	return map[string]any{
		"id":            "msg_" + strings.TrimPrefix(resp.ID, "chatcmpl-"),
		"type":          "message",
		"role":          "assistant",
		"model":         resp.Model,
		"content":       contentBlocks,
		"stop_reason":   stopReason,
		"stop_sequence": nil,
		"usage": map[string]int{
			"input_tokens":  resp.Usage.PromptTokens,
			"output_tokens": resp.Usage.CompletionTokens,
		},
	}
}
