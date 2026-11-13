package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/finops"
	"github.com/goroute-ai/ai-gateway-go/internal/guardrails"
)

// handleResponses serves `POST /v1/responses`, `POST /responses`, and `POST /openai/v1/responses`.
// It implements OpenAI's next-generation Responses API specification.
func (s *GatewayServer) handleResponses(w http.ResponseWriter, r *http.Request) {
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
	if rejectBudgetedUnsupported(w, idCtx) {
		return
	}

	var req domain.CanonicalResponseRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 10<<20)).Decode(&req); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_json",
			Message:    fmt.Sprintf("Failed to decode response request: %v", err),
		})
		return
	}

	if req.Model == "" {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "missing_required_field",
			Message:    "Field 'model' is required",
		})
		return
	}

	if err := s.rbac.AuthorizeRequestedModel(idCtx, req.Model); err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	if req.MaxOutputTokens != nil && *req.MaxOutputTokens < 1 {
		domain.WriteHTTPError(w, &domain.GatewayError{StatusCode: http.StatusBadRequest, Type: domain.ErrorTypeInvalidRequest, Code: "invalid_max_output_tokens", Message: "max_output_tokens must be greater than zero"})
		return
	}

	// Translate input and instructions to canonical chat messages
	messages := make([]domain.CanonicalMessage, 0)
	if strings.TrimSpace(req.Instructions) != "" {
		messages = append(messages, domain.CanonicalMessage{
			Role:    "system",
			Content: req.Instructions,
		})
	}

	if len(req.Input) > 0 {
		var strInput string
		if err := json.Unmarshal(req.Input, &strInput); err == nil {
			messages = append(messages, domain.CanonicalMessage{
				Role:    "user",
				Content: strInput,
			})
		} else {
			var msgArray []domain.CanonicalMessage
			if err := json.Unmarshal(req.Input, &msgArray); err == nil && len(msgArray) > 0 {
				messages = append(messages, msgArray...)
			} else {
				var rawArray []map[string]any
				if err := json.Unmarshal(req.Input, &rawArray); err == nil {
					for _, it := range rawArray {
						role, _ := it["role"].(string)
						if role == "" {
							role = "user"
						}
						content, _ := it["content"].(string)
						if content == "" {
							if parts, ok := it["content"].([]any); ok {
								for _, p := range parts {
									if pm, ok := p.(map[string]any); ok {
										if t, ok := pm["text"].(string); ok {
											content += t
										}
									}
								}
							}
						}
						messages = append(messages, domain.CanonicalMessage{
							Role:    role,
							Content: content,
						})
					}
				}
			}
		}
	}

	if len(messages) == 0 {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "missing_input",
			Message:    "At least one message or input item is required",
		})
		return
	}

	chatReq := &domain.CanonicalChatRequest{
		Model:       req.Model,
		Messages:    messages,
		Tools:       mapResponsesTools(req.Tools),
		ToolChoice:  mapResponsesToolChoice(req.ToolChoice),
		Stream:      req.Stream,
		Temperature: req.Temperature,
		MaxTokens:   req.MaxOutputTokens,
	}
	if _, err := s.guardrails.EvaluateInput(r.Context(), idCtx.OrgID, chatReq); err != nil {
		domain.WriteHTTPError(w, err)
		return
	}

	if !req.Stream {
		resp, meta, err := s.reliability.ExecuteChat(r.Context(), idCtx, chatReq)
		if err != nil {
			domain.WriteHTTPError(w, err)
			return
		}
		guardrailResp := &domain.CanonicalChatResponse{Choices: resp.Choices}
		redacted, sanitizeErr := s.guardrails.SanitizeOutputStrict(r.Context(), idCtx.OrgID, guardrailResp)
		if sanitizeErr != nil {
			domain.WriteHTTPError(w, sanitizeErr)
			return
		}
		resp.Choices = guardrailResp.Choices
		if redacted {
			w.Header().Set("X-Gateway-Output-Redacted", "true")
		}

		respID := "resp_" + uuid.NewString()
		created := resp.Created
		if created == 0 {
			created = time.Now().Unix()
		}

		out := &domain.CanonicalResponseOutput{
			ID:        respID,
			Object:    "response",
			CreatedAt: created,
			Model:     resp.Model,
			Status:    "completed",
			Usage:     &resp.Usage,
			Output:    make([]domain.CanonicalResponseOutputItem, 0),
		}

		for i, choice := range resp.Choices {
			if choice.Message.Content != "" || len(choice.Message.ToolCalls) == 0 {
				itemID := fmt.Sprintf("msg_%s_%d", resp.ID, i)
				out.Output = append(out.Output, domain.CanonicalResponseOutputItem{
					ID:     itemID,
					Type:   "message",
					Status: "completed",
					Role:   choice.Message.Role,
					Content: []domain.CanonicalResponseContentPart{
						{
							Type: "output_text",
							Text: choice.Message.Content,
						},
					},
				})
			}
			for j, tc := range choice.Message.ToolCalls {
				fcID := tc.ID
				if fcID == "" {
					fcID = fmt.Sprintf("fc_%s_%d_%d", resp.ID, i, j)
				}
				out.Output = append(out.Output, domain.CanonicalResponseOutputItem{
					ID:        fcID,
					Type:      "function_call",
					Status:    "completed",
					CallID:    tc.ID,
					Name:      tc.Function.Name,
					Arguments: tc.Function.Arguments,
				})
			}
		}

		var gm *domain.GlobalModel
		var depID string
		var pricingVer int
		if meta != nil && meta.WinningDeployment != nil {
			depID = meta.WinningDeployment.ID
			gm = meta.WinningDeployment.GlobalModel
			if gm != nil {
				pricingVer = gm.PricingVersion
			}
		}
		costMicros := finops.CalculateCostMicros(gm, resp.Usage)
		if !s.persistSpendEvent(w, r, domain.SpendEvent{
			ID:             "sp_" + uuid.NewString(),
			RequestID:      respID,
			OrgID:          idCtx.OrgID,
			TeamID:         idCtx.TeamID,
			UserID:         idCtx.UserID,
			VirtualKeyID:   idCtx.VirtualKeyID,
			Endpoint:       "/v1/responses",
			Modality:       domain.ModalityResponse,
			RequestedModel: req.Model,
			ResolvedModel:  resp.Model,
			DeploymentID:   depID,
			PricingVersion: pricingVer,
			Usage:          resp.Usage,
			CostMicros:     costMicros,
			StatusCode:     http.StatusOK,
			CreatedAt:      time.Now().UTC(),
		}) {
			return
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(out)
		return
	}

	// Streaming response
	flusher, ok := w.(http.Flusher)
	if !ok {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusInternalServerError,
			Type:       domain.ErrorTypeServer,
			Code:       "streaming_unsupported",
			Message:    "Streaming unsupported by HTTP connection",
		})
		return
	}
	policy, policyErr := s.guardrails.Policy(r.Context(), idCtx.OrgID)
	if policyErr != nil {
		domain.WriteHTTPError(w, policyErr)
		return
	}
	streamRedactor := guardrails.NewStreamRedactor(policy)

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")

	respID := "resp_" + uuid.NewString()
	msgID := "msg_" + uuid.NewString()
	now := time.Now().Unix()

	// 1. response.created
	initialResp := map[string]any{
		"response": map[string]any{
			"id":         respID,
			"object":     "response",
			"status":     "in_progress",
			"model":      req.Model,
			"created_at": now,
		},
	}
	b, _ := json.Marshal(initialResp)
	fmt.Fprintf(w, "event: response.created\ndata: %s\n\n", string(b))
	flusher.Flush()

	// 2. response.output_item.added
	itemAdded := map[string]any{
		"output_index": 0,
		"item": map[string]any{
			"id":      msgID,
			"type":    "message",
			"status":  "in_progress",
			"role":    "assistant",
			"content": []any{},
		},
	}
	b, _ = json.Marshal(itemAdded)
	fmt.Fprintf(w, "event: response.output_item.added\ndata: %s\n\n", string(b))
	flusher.Flush()

	// 3. response.content_part.added
	partAdded := map[string]any{
		"output_index":  0,
		"content_index": 0,
		"part": map[string]any{
			"type": "output_text",
			"text": "",
		},
	}
	b, _ = json.Marshal(partAdded)
	fmt.Fprintf(w, "event: response.content_part.added\ndata: %s\n\n", string(b))
	flusher.Flush()

	fullText := strings.Builder{}

	emitDelta := func(txt string) {
		if txt == "" {
			return
		}
		fullText.WriteString(txt)
		deltaEv := map[string]any{
			"output_index":  0,
			"content_index": 0,
			"delta":         txt,
		}
		db, _ := json.Marshal(deltaEv)
		fmt.Fprintf(w, "event: response.output_text.delta\ndata: %s\n\n", string(db))
		flusher.Flush()
	}

	onChunk := func(chunk *domain.CanonicalStreamChunk) error {
		if chunk == nil {
			return nil
		}
		if len(chunk.Choices) > 0 && chunk.Choices[0].Delta.Content != "" {
			txt := chunk.Choices[0].Delta.Content
			if streamRedactor != nil {
				txt = streamRedactor.Process(txt)
			}
			emitDelta(txt)
		}
		return nil
	}

	onSelected := func(dep *domain.Deployment) {}

	usage, meta, err := s.reliability.ExecuteStream(r.Context(), idCtx, chatReq, onChunk, onSelected)
	if err != nil {
		errEv := map[string]any{
			"error": map[string]any{
				"message": err.Error(),
				"code":    "stream_error",
			},
		}
		eb, _ := json.Marshal(errEv)
		fmt.Fprintf(w, "event: error\ndata: %s\n\n", string(eb))
		flusher.Flush()
		return
	}
	if streamRedactor != nil {
		emitDelta(streamRedactor.Flush())
	}

	var streamUsage domain.TokenUsage
	if usage != nil {
		streamUsage = *usage
	}
	var gm *domain.GlobalModel
	var depID string
	var pricingVer int
	resolved := req.Model
	if meta != nil && meta.WinningDeployment != nil {
		depID = meta.WinningDeployment.ID
		gm = meta.WinningDeployment.GlobalModel
		if gm != nil {
			pricingVer = gm.PricingVersion
			if gm.ModelName != "" {
				resolved = gm.ModelName
			}
		}
	}
	costMicros := finops.CalculateCostMicros(gm, streamUsage)
	if s.spendWorker != nil {
		if err := s.spendWorker.Record(r.Context(), domain.SpendEvent{
			ID:             "sp_" + uuid.NewString(),
			RequestID:      respID,
			OrgID:          idCtx.OrgID,
			TeamID:         idCtx.TeamID,
			UserID:         idCtx.UserID,
			VirtualKeyID:   idCtx.VirtualKeyID,
			Endpoint:       "/v1/responses",
			Modality:       domain.ModalityResponse,
			RequestedModel: req.Model,
			ResolvedModel:  resolved,
			DeploymentID:   depID,
			PricingVersion: pricingVer,
			Usage:          streamUsage,
			CostMicros:     costMicros,
			StatusCode:     http.StatusOK,
			IsStream:       true,
			CreatedAt:      time.Now().UTC(),
		}); err != nil {
			failure := map[string]any{"error": map[string]any{"code": "spend_persistence_unavailable", "message": "unable to persist request accounting"}}
			failedBytes, _ := json.Marshal(failure)
			fmt.Fprintf(w, "event: error\ndata: %s\n\n", string(failedBytes))
			flusher.Flush()
			return
		}
	}

	// 4. response.output_text.done
	textDone := map[string]any{
		"output_index":  0,
		"content_index": 0,
		"text":          fullText.String(),
	}
	b, _ = json.Marshal(textDone)
	fmt.Fprintf(w, "event: response.output_text.done\ndata: %s\n\n", string(b))
	flusher.Flush()

	// 5. response.output_item.done
	itemDone := map[string]any{
		"output_index": 0,
		"item": map[string]any{
			"id":     msgID,
			"type":   "message",
			"status": "completed",
			"role":   "assistant",
			"content": []map[string]any{
				{
					"type": "output_text",
					"text": fullText.String(),
				},
			},
		},
	}
	b, _ = json.Marshal(itemDone)
	fmt.Fprintf(w, "event: response.output_item.done\ndata: %s\n\n", string(b))
	flusher.Flush()

	// 6. response.completed
	compEv := map[string]any{
		"response": map[string]any{
			"id":         respID,
			"object":     "response",
			"status":     "completed",
			"model":      req.Model,
			"created_at": now,
			"output": []map[string]any{
				{
					"id":     msgID,
					"type":   "message",
					"status": "completed",
					"role":   "assistant",
					"content": []map[string]any{
						{
							"type": "output_text",
							"text": fullText.String(),
						},
					},
				},
			},
		},
	}
	b, _ = json.Marshal(compEv)
	fmt.Fprintf(w, "event: response.completed\ndata: %s\n\n", string(b))
	flusher.Flush()

	// 7. response.done
	fmt.Fprintf(w, "event: response.done\ndata: {}\n\n")
	flusher.Flush()
}

func mapResponsesTools(rawTools []any) []domain.CanonicalTool {
	if len(rawTools) == 0 {
		return nil
	}
	tools := make([]domain.CanonicalTool, 0, len(rawTools))
	for _, raw := range rawTools {
		m, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		toolType, _ := m["type"].(string)
		if toolType == "" {
			toolType = "function"
		}
		fnMap := m
		if nested, ok := m["function"].(map[string]any); ok {
			fnMap = nested
		}
		name, _ := fnMap["name"].(string)
		if name == "" {
			continue
		}
		desc, _ := fnMap["description"].(string)
		params, _ := fnMap["parameters"].(map[string]any)
		strict, _ := fnMap["strict"].(bool)
		tools = append(tools, domain.CanonicalTool{
			Type: toolType,
			Function: domain.CanonicalFunction{
				Name:        name,
				Description: desc,
				Parameters:  params,
				Strict:      strict,
			},
		})
	}
	return tools
}

func mapResponsesToolChoice(raw any) any {
	if raw == nil {
		return nil
	}
	m, ok := raw.(map[string]any)
	if !ok {
		return raw
	}
	if _, hasFn := m["function"]; hasFn {
		return m
	}
	if toolType, _ := m["type"].(string); toolType == "function" {
		if name, _ := m["name"].(string); name != "" {
			return map[string]any{
				"type": "function",
				"function": map[string]any{
					"name": name,
				},
			}
		}
	}
	return raw
}
