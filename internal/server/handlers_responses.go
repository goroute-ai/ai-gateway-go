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
	"github.com/goroute-ai/ai-gateway-go/internal/ratelimit"
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
	messages := parseResponsesInputMessages(req.Instructions, req.Input)

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
	if req.Reasoning != nil && req.Reasoning.Effort != "" {
		chatReq.ReasoningEffort = req.Reasoning.Effort
	}
	if req.Text != nil && req.Text.Format != nil {
		chatReq.ResponseFormat = req.Text.Format
	}
	if _, err := s.guardrails.EvaluateInput(r.Context(), idCtx.OrgID, chatReq); err != nil {
		domain.WriteHTTPError(w, err)
		return
	}

	respReqID := gatewayRequestID(r)
	estInputTokens := ratelimit.EstimateRequestTokens(chatReq)
	maxOut := 0
	if req.MaxOutputTokens != nil {
		maxOut = *req.MaxOutputTokens
	}
	releaseQuota, quotaErr := s.acquireRequestQuota(r.Context(), idCtx, req.Model, estInputTokens, maxOut, respReqID)
	if quotaErr != nil {
		s.collector.Record(admissionFailureObservation(quotaErr))
		domain.WriteHTTPError(w, quotaErr)
		return
	}

	if !req.Stream {
		resp, meta, err := s.reliability.ExecuteChat(r.Context(), idCtx, chatReq)
		if err != nil {
			releaseQuota(-1)
			domain.WriteHTTPError(w, err)
			return
		}
		releaseQuota(resp.Usage.TotalTokens)
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

	fullText := strings.Builder{}
	type streamToolItem struct {
		outputIndex int
		itemID      string
		callID      string
		name        string
		args        strings.Builder
	}
	toolItems := make(map[int]*streamToolItem)
	var toolOrder []int
	nextOutputIndex := 0
	msgStarted := false
	msgOutputIndex := 0

	ensureMessageStarted := func() {
		if msgStarted {
			return
		}
		msgStarted = true
		msgOutputIndex = nextOutputIndex
		nextOutputIndex++

		itemAdded := map[string]any{
			"output_index": msgOutputIndex,
			"item": map[string]any{
				"id":      msgID,
				"type":    "message",
				"status":  "in_progress",
				"role":    "assistant",
				"content": []any{},
			},
		}
		ib, _ := json.Marshal(itemAdded)
		fmt.Fprintf(w, "event: response.output_item.added\ndata: %s\n\n", string(ib))

		partAdded := map[string]any{
			"output_index":  msgOutputIndex,
			"content_index": 0,
			"part": map[string]any{
				"type": "output_text",
				"text": "",
			},
		}
		pb, _ := json.Marshal(partAdded)
		fmt.Fprintf(w, "event: response.content_part.added\ndata: %s\n\n", string(pb))
		flusher.Flush()
	}

	emitDelta := func(txt string) {
		if txt == "" {
			return
		}
		ensureMessageStarted()
		fullText.WriteString(txt)
		deltaEv := map[string]any{
			"output_index":  msgOutputIndex,
			"content_index": 0,
			"delta":         txt,
		}
		db, _ := json.Marshal(deltaEv)
		fmt.Fprintf(w, "event: response.output_text.delta\ndata: %s\n\n", string(db))
		flusher.Flush()
	}

	onChunk := func(chunk *domain.CanonicalStreamChunk) error {
		if chunk == nil || len(chunk.Choices) == 0 {
			return nil
		}
		delta := chunk.Choices[0].Delta
		if delta.Content != "" {
			txt := delta.Content
			if streamRedactor != nil {
				txt = streamRedactor.Process(txt)
			}
			emitDelta(txt)
		}
		for _, tc := range delta.ToolCalls {
			idx := 0
			if tc.Index != nil {
				idx = *tc.Index
			}
			item, exists := toolItems[idx]
			if !exists {
				callID := tc.ID
				if callID == "" {
					callID = fmt.Sprintf("call_%s_%d", respID, idx)
				}
				fcID := fmt.Sprintf("fc_%s_%d", respID, idx)
				item = &streamToolItem{
					outputIndex: nextOutputIndex,
					itemID:      fcID,
					callID:      callID,
					name:        tc.Function.Name,
				}
				nextOutputIndex++
				toolItems[idx] = item
				toolOrder = append(toolOrder, idx)

				fcAdded := map[string]any{
					"output_index": item.outputIndex,
					"item": map[string]any{
						"id":        item.itemID,
						"type":      "function_call",
						"status":    "in_progress",
						"call_id":   item.callID,
						"name":      item.name,
						"arguments": "",
					},
				}
				fb, _ := json.Marshal(fcAdded)
				fmt.Fprintf(w, "event: response.output_item.added\ndata: %s\n\n", string(fb))
				flusher.Flush()
			} else if tc.Function.Name != "" && item.name == "" {
				item.name = tc.Function.Name
			}
			if tc.Function.Arguments != "" {
				item.args.WriteString(tc.Function.Arguments)
				argDelta := map[string]any{
					"output_index": item.outputIndex,
					"item_id":      item.itemID,
					"delta":        tc.Function.Arguments,
				}
				ab, _ := json.Marshal(argDelta)
				fmt.Fprintf(w, "event: response.function_call_arguments.delta\ndata: %s\n\n", string(ab))
				flusher.Flush()
			}
		}
		return nil
	}

	onSelected := func(dep *domain.Deployment) {}

	streamStarted := time.Now()
	usage, meta, err := s.reliability.ExecuteStream(r.Context(), idCtx, chatReq, onChunk, onSelected)
	var streamTTFT time.Duration
	if meta != nil && meta.TTFTMs > 0 {
		streamTTFT = time.Duration(meta.TTFTMs) * time.Millisecond
	}
	s.collector.RecordStream(time.Since(streamStarted), streamTTFT, err != nil)
	if err != nil {
		releaseQuota(-1)
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
	releaseQuota(streamUsage.TotalTokens)
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

	if !msgStarted && len(toolOrder) == 0 {
		ensureMessageStarted()
	}

	var completedOutput []map[string]any
	setCompletedOutput := func(index int, item map[string]any) {
		for len(completedOutput) <= index {
			completedOutput = append(completedOutput, nil)
		}
		completedOutput[index] = item
	}
	if msgStarted {
		// 4. response.output_text.done
		textDone := map[string]any{
			"output_index":  msgOutputIndex,
			"content_index": 0,
			"text":          fullText.String(),
		}
		b, _ = json.Marshal(textDone)
		fmt.Fprintf(w, "event: response.output_text.done\ndata: %s\n\n", string(b))
		flusher.Flush()

		// 5. response.output_item.done (message)
		msgItem := map[string]any{
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
		}
		itemDone := map[string]any{
			"output_index": msgOutputIndex,
			"item":         msgItem,
		}
		b, _ = json.Marshal(itemDone)
		fmt.Fprintf(w, "event: response.output_item.done\ndata: %s\n\n", string(b))
		flusher.Flush()
		setCompletedOutput(msgOutputIndex, msgItem)
	}
	for _, idx := range toolOrder {
		item := toolItems[idx]
		argsStr := item.args.String()
		argDone := map[string]any{
			"output_index": item.outputIndex,
			"item_id":      item.itemID,
			"arguments":    argsStr,
		}
		ab, _ := json.Marshal(argDone)
		fmt.Fprintf(w, "event: response.function_call_arguments.done\ndata: %s\n\n", string(ab))

		fcItem := map[string]any{
			"id":        item.itemID,
			"type":      "function_call",
			"status":    "completed",
			"call_id":   item.callID,
			"name":      item.name,
			"arguments": argsStr,
		}
		fcDone := map[string]any{
			"output_index": item.outputIndex,
			"item":         fcItem,
		}
		fb, _ := json.Marshal(fcDone)
		fmt.Fprintf(w, "event: response.output_item.done\ndata: %s\n\n", string(fb))
		flusher.Flush()
		setCompletedOutput(item.outputIndex, fcItem)
	}

	// 6. response.completed
	compEv := map[string]any{
		"response": map[string]any{
			"id":         respID,
			"object":     "response",
			"status":     "completed",
			"model":      req.Model,
			"created_at": now,
			"output":     completedOutput,
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

func parseResponsesInputMessages(instructions string, rawInput json.RawMessage) []domain.CanonicalMessage {
	messages := make([]domain.CanonicalMessage, 0)
	if strings.TrimSpace(instructions) != "" {
		messages = append(messages, domain.CanonicalMessage{
			Role:    "system",
			Content: instructions,
		})
	}
	if len(rawInput) == 0 {
		return messages
	}

	var strInput string
	if err := json.Unmarshal(rawInput, &strInput); err == nil {
		return append(messages, domain.CanonicalMessage{
			Role:    "user",
			Content: strInput,
		})
	}

	var rawArray []map[string]any
	if err := json.Unmarshal(rawInput, &rawArray); err == nil {
		for _, it := range rawArray {
			itemType, _ := it["type"].(string)
			switch itemType {
			case "function_call":
				callID, _ := it["call_id"].(string)
				name, _ := it["name"].(string)
				arguments, _ := it["arguments"].(string)
				messages = append(messages, domain.CanonicalMessage{
					Role: "assistant",
					ToolCalls: []domain.CanonicalToolCall{{
						ID:   callID,
						Type: "function",
						Function: domain.CanonicalFunctionCall{
							Name:      name,
							Arguments: arguments,
						},
					}},
				})
				continue
			case "function_call_output":
				callID, _ := it["call_id"].(string)
				output := responseToolOutputText(it["output"])
				messages = append(messages, domain.CanonicalMessage{
					Role:       "tool",
					ToolCallID: callID,
					Content:    output,
				})
				continue
			}
			role, _ := it["role"].(string)
			if role == "" {
				role = "user"
			}
			msg := domain.CanonicalMessage{Role: role}
			if rawToolCalls, ok := it["tool_calls"].([]any); ok {
				for _, rawToolCall := range rawToolCalls {
					call, ok := rawToolCall.(map[string]any)
					if !ok {
						continue
					}
					function, _ := call["function"].(map[string]any)
					name, _ := function["name"].(string)
					arguments, _ := function["arguments"].(string)
					id, _ := call["id"].(string)
					if name == "" {
						continue
					}
					msg.ToolCalls = append(msg.ToolCalls, domain.CanonicalToolCall{
						ID:   id,
						Type: "function",
						Function: domain.CanonicalFunctionCall{
							Name:      name,
							Arguments: arguments,
						},
					})
				}
			}
			switch cv := it["content"].(type) {
			case string:
				msg.Content = cv
			case []any:
				var textSB strings.Builder
				for _, p := range cv {
					pm, ok := p.(map[string]any)
					if !ok {
						continue
					}
					ptype, _ := pm["type"].(string)
					switch ptype {
					case "text", "input_text", "output_text":
						txt, _ := pm["text"].(string)
						textSB.WriteString(txt)
						msg.Parts = append(msg.Parts, domain.ContentPart{Type: "text", Text: txt})
					case "image_url", "input_image":
						var imgURL, detail string
						if iu, ok := pm["image_url"].(map[string]any); ok {
							imgURL, _ = iu["url"].(string)
							detail, _ = iu["detail"].(string)
						} else if u, ok := pm["image_url"].(string); ok {
							imgURL = u
						} else if u, ok := pm["url"].(string); ok {
							imgURL = u
						}
						if imgURL != "" {
							msg.Parts = append(msg.Parts, domain.ContentPart{
								Type:     "image_url",
								ImageURL: &domain.ImageURL{URL: imgURL, Detail: detail},
							})
						}
					case "document", "input_file":
						doc := &domain.DocumentPart{}
						if dm, ok := pm["document"].(map[string]any); ok {
							doc.MimeType, _ = dm["mime_type"].(string)
							doc.Data, _ = dm["data"].(string)
							doc.URL, _ = dm["url"].(string)
							doc.Filename, _ = dm["filename"].(string)
						} else {
							doc.MimeType, _ = pm["mime_type"].(string)
							doc.Data, _ = pm["file_data"].(string)
							doc.URL, _ = pm["file_url"].(string)
							doc.Filename, _ = pm["filename"].(string)
							if doc.MimeType == "" {
								doc.MimeType = "application/pdf"
							}
						}
						if doc.Data != "" || doc.URL != "" {
							msg.Parts = append(msg.Parts, domain.ContentPart{
								Type:     "document",
								Document: doc,
							})
						}
					}
				}
				msg.Content = textSB.String()
			}
			messages = append(messages, msg)
		}
		return messages
	}

	var msgArray []domain.CanonicalMessage
	if err := json.Unmarshal(rawInput, &msgArray); err == nil && len(msgArray) > 0 {
		messages = append(messages, msgArray...)
	}
	return messages
}

func responseToolOutputText(value any) string {
	if text, ok := value.(string); ok {
		return text
	}
	if parts, ok := value.([]any); ok {
		var sb strings.Builder
		for _, rawPart := range parts {
			part, ok := rawPart.(map[string]any)
			if !ok {
				continue
			}
			if text, ok := part["text"].(string); ok {
				sb.WriteString(text)
			}
		}
		if sb.Len() > 0 {
			return sb.String()
		}
	}
	encoded, err := json.Marshal(value)
	if err == nil {
		return string(encoded)
	}
	return ""
}
