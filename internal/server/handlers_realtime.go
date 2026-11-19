package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/finops"
	"github.com/goroute-ai/ai-gateway-go/internal/guardrails"
	"github.com/goroute-ai/ai-gateway-go/internal/logger"
	"github.com/goroute-ai/ai-gateway-go/internal/ratelimit"
	"nhooyr.io/websocket"
)

// handleRealtimeWebSocket serves `GET /v1/realtime`, `GET /realtime`, and `GET /openai/v1/realtime`.
// It implements OpenAI's Realtime WebSocket bidirectional session protocol.
func (s *GatewayServer) handleRealtimeWebSocket(w http.ResponseWriter, r *http.Request) {
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

	model := r.URL.Query().Get("model")
	if model == "" {
		model = "gpt-4o-realtime-preview"
	}

	if err := s.rbac.AuthorizeRequestedModel(idCtx, model); err != nil {
		domain.WriteHTTPError(w, err)
		return
	}

	var baseSessionExt *domain.GoRouteExtensions
	if gwErr := s.applyRoutingHints(r, idCtx, &baseSessionExt); gwErr != nil {
		s.collector.Record(admissionFailureObservation(gwErr))
		domain.WriteHTTPError(w, gwErr)
		return
	}

	if s.limiter != nil {
		releaseSession, rlMeta, err := s.limiter.AcquireSessionWithMeta(r.Context(), idCtx)
		if err != nil {
			domain.WriteHTTPError(w, err)
			return
		}
		domain.WriteRateLimitHeaders(w, rlMeta)
		defer releaseSession()
	}

	subprotocols := make([]string, 0)
	for _, p := range strings.Split(r.Header.Get("Sec-WebSocket-Protocol"), ",") {
		p = strings.TrimSpace(p)
		if p == "realtime" {
			subprotocols = append(subprotocols, "realtime")
		}
	}

	acceptOpts := &websocket.AcceptOptions{}
	if len(subprotocols) > 0 {
		acceptOpts.Subprotocols = subprotocols
	}

	conn, err := websocket.Accept(w, r, acceptOpts)
	if err != nil {
		logger.Error("Failed to accept realtime websocket connection", "err", err)
		return
	}
	defer conn.Close(websocket.StatusNormalClosure, "session closed")

	sessionID := "sess_" + uuid.NewString()
	startTime := time.Now()

	// Default session state
	sessionConfig := &domain.CanonicalRealtimeSessionConfig{
		Modalities:        []string{"text"},
		Instructions:      "You are a helpful AI assistant.",
		Voice:             "alloy",
		InputAudioFormat:  "pcm16",
		OutputAudioFormat: "pcm16",
		GoRouteExtensions: baseSessionExt.Clone(),
	}
	if sessionConfig.GoRouteExtensions == nil {
		sessionConfig.GoRouteExtensions = &domain.GoRouteExtensions{}
	}
	if strings.TrimSpace(sessionConfig.GoRouteExtensions.SessionID) == "" {
		sessionConfig.GoRouteExtensions.SessionID = sessionID
	}

	var sessionMu sync.Mutex
	var writeMu sync.Mutex
	history := make([]domain.CanonicalMessage, 0)

	rtQCtx, _ := withRequestQuotaState(r.Context(), r, idCtx, r.URL.Query().Get("user"), nil, sessionConfig.GoRouteExtensions)
	sessionCtx, sessionCancel := context.WithCancel(rtQCtx)
	defer sessionCancel()

	// Helper to send JSON event to client
	sendEvent := func(ctx context.Context, ev map[string]any) error {
		b, err := json.Marshal(ev)
		if err != nil {
			return err
		}
		writeMu.Lock()
		defer writeMu.Unlock()
		return conn.Write(ctx, websocket.MessageText, b)
	}

	// 1. Send initial session.created event
	_ = sendEvent(sessionCtx, map[string]any{
		"event_id": "event_" + uuid.NewString(),
		"type":     "session.created",
		"session": map[string]any{
			"id":                  sessionID,
			"object":              "realtime.session",
			"model":               model,
			"modalities":          sessionConfig.Modalities,
			"instructions":        sessionConfig.Instructions,
			"voice":               sessionConfig.Voice,
			"input_audio_format":  sessionConfig.InputAudioFormat,
			"output_audio_format": sessionConfig.OutputAudioFormat,
		},
	})

	// Read frames in a dedicated reader goroutine so client close/disconnect
	// cancels sessionCtx even while an upstream response.create turn is in flight.
	msgCh := make(chan []byte, 16)
	go func() {
		defer close(msgCh)
		for {
			msgType, data, readErr := conn.Read(sessionCtx)
			if readErr != nil {
				sessionCancel()
				return
			}
			if msgType != websocket.MessageText {
				continue
			}
			select {
			case msgCh <- data:
			case <-sessionCtx.Done():
				return
			}
		}
	}()

	// Message frame pump loop
	for data := range msgCh {
		if sessionCtx.Err() != nil {
			break
		}

		var clientEv struct {
			EventID string                                 `json:"event_id"`
			Type    string                                 `json:"type"`
			Session *domain.CanonicalRealtimeSessionConfig `json:"session,omitempty"`
			Item    *struct {
				ID      string `json:"id"`
				Type    string `json:"type"`
				Role    string `json:"role"`
				Content []struct {
					Type string `json:"type"`
					Text string `json:"text"`
				} `json:"content"`
			} `json:"item,omitempty"`
			Response *struct {
				MaxOutputTokens   *int                      `json:"max_output_tokens,omitempty"`
				MaxTokens         *int                      `json:"max_tokens,omitempty"`
				GoRouteExtensions *domain.GoRouteExtensions `json:"goroute_extensions,omitempty"`
			} `json:"response,omitempty"`
			Audio             string                    `json:"audio,omitempty"`
			GoRouteExtensions *domain.GoRouteExtensions `json:"goroute_extensions,omitempty"`
		}

		if err := json.Unmarshal(data, &clientEv); err != nil {
			_ = sendEvent(r.Context(), map[string]any{
				"event_id": "event_" + uuid.NewString(),
				"type":     "error",
				"error": map[string]any{
					"type":    "invalid_request_error",
					"message": fmt.Sprintf("Failed to parse client event: %v", err),
				},
			})
			continue
		}

		switch clientEv.Type {
		case "session.update":
			unsupportedModality := false
			if clientEv.Session != nil {
				for _, modality := range clientEv.Session.Modalities {
					if modality != "text" {
						unsupportedModality = true
						break
					}
				}
			}
			if unsupportedModality {
				_ = sendEvent(r.Context(), map[string]any{"event_id": "event_" + uuid.NewString(), "type": "error", "error": map[string]any{"type": "unsupported_feature", "message": "This gateway Realtime endpoint currently supports text modality only"}})
				continue
			}
			var hintErr *domain.GatewayError
			sessionMu.Lock()
			if clientEv.Session != nil && clientEv.Session.GoRouteExtensions != nil {
				merged := mergeGoRouteExtensions(sessionConfig.GoRouteExtensions, clientEv.Session.GoRouteExtensions)
				if gwErr := s.applyRoutingHints(r, idCtx, &merged); gwErr != nil {
					hintErr = gwErr
				} else {
					sessionConfig.GoRouteExtensions = merged
				}
			}
			if hintErr == nil && clientEv.Session != nil {
				if len(clientEv.Session.Modalities) > 0 {
					textOnly := true
					for _, modality := range clientEv.Session.Modalities {
						if modality != "text" {
							textOnly = false
						}
					}
					if textOnly {
						sessionConfig.Modalities = []string{"text"}
					}
				}
				if clientEv.Session.Instructions != "" {
					sessionConfig.Instructions = clientEv.Session.Instructions
				}
				if clientEv.Session.Voice != "" {
					sessionConfig.Voice = clientEv.Session.Voice
				}
				if clientEv.Session.Temperature != nil {
					sessionConfig.Temperature = clientEv.Session.Temperature
				}
			}
			sessionMu.Unlock()
			if hintErr != nil {
				_ = sendEvent(r.Context(), realtimeGatewayErrorEvent(hintErr))
				continue
			}

			_ = sendEvent(r.Context(), map[string]any{
				"event_id": "event_" + uuid.NewString(),
				"type":     "session.updated",
				"session": map[string]any{
					"id":                  sessionID,
					"object":              "realtime.session",
					"model":               model,
					"modalities":          sessionConfig.Modalities,
					"instructions":        sessionConfig.Instructions,
					"voice":               sessionConfig.Voice,
					"input_audio_format":  sessionConfig.InputAudioFormat,
					"output_audio_format": sessionConfig.OutputAudioFormat,
				},
			})

		case "input_audio_buffer.append":
			_ = sendEvent(r.Context(), map[string]any{
				"event_id": "event_" + uuid.NewString(),
				"type":     "error",
				"error":    map[string]any{"type": "unsupported_feature", "message": "This gateway Realtime endpoint currently supports text input only"},
			})

		case "input_audio_buffer.commit":
			_ = sendEvent(r.Context(), map[string]any{
				"event_id": "event_" + uuid.NewString(),
				"type":     "error",
				"error":    map[string]any{"type": "unsupported_feature", "message": "This gateway Realtime endpoint currently supports text input only"},
			})

		case "conversation.item.create":
			sessionMu.Lock()
			if clientEv.Item != nil {
				role := clientEv.Item.Role
				if role == "" {
					role = "user"
				}
				text := ""
				for _, c := range clientEv.Item.Content {
					text += c.Text
				}
				history = append(history, domain.CanonicalMessage{
					Role:    role,
					Content: text,
				})
			}
			sessionMu.Unlock()

			itemID := "item_" + uuid.NewString()
			if clientEv.Item != nil && clientEv.Item.ID != "" {
				itemID = clientEv.Item.ID
			}

			_ = sendEvent(r.Context(), map[string]any{
				"event_id": "event_" + uuid.NewString(),
				"type":     "conversation.item.created",
				"item": map[string]any{
					"id":   itemID,
					"type": "message",
					"role": "user",
				},
			})

		case "response.create":
			sessionMu.Lock()
			reqMsgs := make([]domain.CanonicalMessage, 0, len(history)+1)
			if sessionConfig.Instructions != "" {
				reqMsgs = append(reqMsgs, domain.CanonicalMessage{
					Role:    "system",
					Content: sessionConfig.Instructions,
				})
			}
			reqMsgs = append(reqMsgs, history...)
			temp := sessionConfig.Temperature
			sessionExt := sessionConfig.GoRouteExtensions.Clone()
			sessionMu.Unlock()
			if len(reqMsgs) == 0 {
				_ = sendEvent(r.Context(), map[string]any{"event_id": "event_" + uuid.NewString(), "type": "error", "error": map[string]any{"type": "invalid_request_error", "message": "response.create requires text input"}})
				continue
			}

			var turnExt *domain.GoRouteExtensions
			if clientEv.GoRouteExtensions != nil {
				turnExt = clientEv.GoRouteExtensions
			}
			if clientEv.Response != nil && clientEv.Response.GoRouteExtensions != nil {
				turnExt = mergeGoRouteExtensions(turnExt, clientEv.Response.GoRouteExtensions)
			}
			mergedExt := mergeGoRouteExtensions(sessionExt, turnExt)
			turnReqID := sessionID + "_turn_" + uuid.NewString()
			chatReq := &domain.CanonicalChatRequest{
				RequestID:         turnReqID,
				Model:             model,
				Messages:          reqMsgs,
				Temperature:       temp,
				GoRouteExtensions: mergedExt,
			}
			maxOutput := 0
			if clientEv.Response != nil {
				if clientEv.Response.MaxOutputTokens != nil {
					maxOutput = *clientEv.Response.MaxOutputTokens
				} else if clientEv.Response.MaxTokens != nil {
					maxOutput = *clientEv.Response.MaxTokens
				}
			}
			if maxOutput < 0 {
				_ = sendEvent(r.Context(), map[string]any{"event_id": "event_" + uuid.NewString(), "type": "error", "error": map[string]any{"type": "invalid_request_error", "message": "max_output_tokens cannot be negative"}})
				continue
			}
			if maxOutput > 0 {
				chatReq.MaxTokens = &maxOutput
			}

			if gwErr := s.applyChatRoutingHints(r, idCtx, chatReq); gwErr != nil {
				s.collector.Record(admissionFailureObservation(gwErr))
				_ = sendEvent(r.Context(), realtimeGatewayErrorEvent(gwErr))
				continue
			}
			origTurnModel := chatReq.Model
			prc, _, guardrailErr := s.evaluateChatInputGuardrails(sessionCtx, nil, r, idCtx, chatReq, "realtime")
			if guardrailErr != nil {
				var gwErr *domain.GatewayError
				if errors.As(guardrailErr, &gwErr) {
					_ = sendEvent(r.Context(), realtimeGatewayErrorEvent(gwErr))
				} else {
					_ = sendEvent(r.Context(), map[string]any{"event_id": "event_" + uuid.NewString(), "type": "error", "error": map[string]any{"type": "guardrail_error", "message": "Request rejected by organization guardrail policy"}})
				}
				continue
			}

			estTokens := ratelimit.EstimateRequestTokens(chatReq)
			budgetInputTokens := estTokens
			if s.requestHasBudget(sessionCtx, idCtx, chatReq.Model) {
				if encoded, encodeErr := json.Marshal(chatReq); encodeErr != nil {
					_ = sendEvent(r.Context(), map[string]any{
						"event_id": "event_" + uuid.NewString(),
						"type":     "error",
						"error": map[string]any{
							"type":    string(domain.ErrorTypeBudgetExceeded),
							"code":    "budget_estimate_unavailable",
							"message": "A safe upper-bound cost could not be calculated before dispatch",
						},
					})
					continue
				} else if len(encoded) > budgetInputTokens {
					budgetInputTokens = len(encoded)
				}
			}

			respID := "resp_" + uuid.NewString()
			itemMsgID := "msg_" + uuid.NewString()

			onAdmitted := func() {
				// response.created
				_ = sendEvent(r.Context(), map[string]any{
					"event_id": "event_" + uuid.NewString(),
					"type":     "response.created",
					"response": map[string]any{
						"id":     respID,
						"object": "realtime.response",
						"status": "in_progress",
					},
				})

				// response.output_item.added
				_ = sendEvent(r.Context(), map[string]any{
					"event_id":     "event_" + uuid.NewString(),
					"type":         "response.output_item.added",
					"output_index": 0,
					"item": map[string]any{
						"id":      itemMsgID,
						"type":    "message",
						"status":  "in_progress",
						"role":    "assistant",
						"content": []any{},
					},
				})

				// response.content_part.added
				_ = sendEvent(r.Context(), map[string]any{
					"event_id":      "event_" + uuid.NewString(),
					"type":          "response.content_part.added",
					"output_index":  0,
					"content_index": 0,
					"part": map[string]any{
						"type": "text",
						"text": "",
					},
				})
			}

			turnIDCtx := *idCtx
			// The WebSocket session already holds the connection-level concurrency slot
			// and executes turns sequentially, so per-turn quota must not double-count concurrency.
			turnIDCtx.KeyMaxConcurrent = 0
			turnIDCtx.TeamMaxConcurrent = 0
			turnIDCtx.UserMaxConcurrent = 0
			turnIDCtx.OrgMaxConcurrent = 0

			turnCtx, _ := withRequestQuotaState(sessionCtx, r, idCtx, r.URL.Query().Get("user"), nil, chatReq.GoRouteExtensions)
			resp, err := s.executeRealtimeTurn(turnCtx, &turnIDCtx, sessionID, origTurnModel, turnReqID, prc, chatReq, estTokens, budgetInputTokens, maxOutput, onAdmitted)
			if err != nil {
				errPayload := map[string]any{
					"type":    "execution_error",
					"message": err.Error(),
				}
				var gwErr *domain.GatewayError
				if errors.As(err, &gwErr) {
					if gwErr.Type != "" {
						errPayload["type"] = string(gwErr.Type)
					}
					if gwErr.Code != "" {
						errPayload["code"] = gwErr.Code
					}
					if gwErr.Message != "" {
						errPayload["message"] = gwErr.Message
					}
				}
				_ = sendEvent(r.Context(), map[string]any{
					"event_id": "event_" + uuid.NewString(),
					"type":     "error",
					"error":    errPayload,
				})
				continue
			}

			if _, sanitizeErr := s.evaluateChatOutputGuardrails(r.Context(), nil, prc, resp, "realtime"); sanitizeErr != nil {
				var gwErr *domain.GatewayError
				if errors.As(sanitizeErr, &gwErr) {
					_ = sendEvent(r.Context(), realtimeGatewayErrorEvent(gwErr))
				} else {
					_ = sendEvent(r.Context(), map[string]any{"event_id": "event_" + uuid.NewString(), "type": "error", "error": map[string]any{"type": "guardrail_error", "message": "Response withheld by organization guardrail policy"}})
				}
				continue
			}
			s.GuardrailPipeline().EvaluateLoggingOnly(r.Context(), prc, chatReq, resp)
			replyContent := ""
			if len(resp.Choices) > 0 {
				replyContent = resp.Choices[0].Message.Content
			}

			// response.text.delta
			_ = sendEvent(r.Context(), map[string]any{
				"event_id":      "event_" + uuid.NewString(),
				"type":          "response.text.delta",
				"output_index":  0,
				"content_index": 0,
				"delta":         replyContent,
			})

			// response.text.done
			_ = sendEvent(r.Context(), map[string]any{
				"event_id":      "event_" + uuid.NewString(),
				"type":          "response.text.done",
				"output_index":  0,
				"content_index": 0,
				"text":          replyContent,
			})

			// response.output_item.done
			_ = sendEvent(r.Context(), map[string]any{
				"event_id":     "event_" + uuid.NewString(),
				"type":         "response.output_item.done",
				"output_index": 0,
				"item": map[string]any{
					"id":      itemMsgID,
					"type":    "message",
					"status":  "completed",
					"role":    "assistant",
					"content": []map[string]any{{"type": "text", "text": replyContent}},
				},
			})

			// response.done
			_ = sendEvent(r.Context(), map[string]any{
				"event_id": "event_" + uuid.NewString(),
				"type":     "response.done",
				"response": map[string]any{
					"id":     respID,
					"status": "completed",
					"output": []map[string]any{
						{
							"id":      itemMsgID,
							"type":    "message",
							"status":  "completed",
							"role":    "assistant",
							"content": []map[string]any{{"type": "text", "text": replyContent}},
						},
					},
				},
			})

			sessionMu.Lock()
			history = append(history, domain.CanonicalMessage{
				Role:    "assistant",
				Content: replyContent,
			})
			sessionMu.Unlock()

		default:
			_ = sendEvent(r.Context(), map[string]any{"event_id": "event_" + uuid.NewString(), "type": "error", "error": map[string]any{"type": "unsupported_event", "message": "Unsupported Realtime event type: " + clientEv.Type}})
		}
	}

	sessionDuration := time.Since(startTime)
	logger.Info("Realtime websocket session completed",
		"session_id", sessionID,
		"model", model,
		"duration", sessionDuration.String(),
	)
}

func (s *GatewayServer) executeRealtimeTurn(
	ctx context.Context,
	idCtx *domain.IdentityContext,
	sessionID string,
	requestedModel string,
	turnReqID string,
	prc guardrails.PipelineRequestContext,
	chatReq *domain.CanonicalChatRequest,
	estTokens int,
	budgetInputTokens int,
	maxOutput int,
	onAdmitted func(),
) (*domain.CanonicalChatResponse, error) {
	if state := requestQuotaStateFromContext(ctx); state != nil {
		turnState := *state
		turnState.Tags = append([]string(nil), state.Tags...)
		ctx = context.WithValue(ctx, requestQuotaStateContextKey{}, &turnState)
	}
	if strings.TrimSpace(turnReqID) == "" {
		turnReqID = sessionID + "_turn_" + uuid.NewString()
	}
	effectiveModel := requestedModel
	if chatReq != nil && strings.TrimSpace(chatReq.Model) != "" {
		effectiveModel = chatReq.Model
	}
	var releaseTurnQuota func(actualInput, actualOutput int, overrideCostMicros int64)
	if s.limiter != nil {
		var quotaErr error
		releaseTurnQuota, quotaErr = s.acquireRequestQuotaWithUsage(ctx, idCtx, effectiveModel, estTokens, budgetInputTokens, maxOutput, turnReqID)
		if quotaErr != nil {
			return nil, quotaErr
		}
	}

	quotaSettlement := &postDispatchSettlement{
		idCtx:          idCtx,
		reqID:          turnReqID,
		endpoint:       "/v1/realtime",
		modality:       domain.ModalityRealtime,
		requestedModel: requestedModel,
		estTokens:      estTokens,
		reqCtx:         ctx,
		releaseUsage:   releaseTurnQuota,
	}
	defer s.settleQuotaOnReturn(quotaSettlement)

	upstreamCtx, duringHandle, duringInitErr := s.startDuringCallGuardrails(ctx, prc, chatReq)
	if duringInitErr != nil {
		return nil, duringInitErr
	}
	if duringHandle != nil {
		defer duringHandle.Close()
	}

	if onAdmitted != nil {
		onAdmitted()
	}

	upstreamCtx = quotaSettlement.trackDispatch(upstreamCtx)
	resp, meta, err := s.reliability.ExecuteChat(upstreamCtx, idCtx, chatReq)
	quotaSettlement.meta = meta
	quotaSettlement.dispatchErr = err
	if _, duringErr := duringHandle.Wait(ctx); duringErr != nil {
		if quotaSettlement.dispatchErr == nil {
			quotaSettlement.dispatchErr = duringErr
		}
		return nil, duringErr
	}
	if err != nil {
		return nil, err
	}

	var gm *domain.GlobalModel
	var depID string
	var provider domain.ProviderType
	var pricingVer int
	resolvedModel := effectiveModel
	if meta != nil && meta.WinningDeployment != nil {
		depID = meta.WinningDeployment.ID
		gm = meta.WinningDeployment.GlobalModel
		if gm != nil {
			provider = gm.Provider
			pricingVer = gm.PricingVersion
			if gm.ModelName != "" {
				resolvedModel = gm.ModelName
			}
		}
	}

	turnCost := finops.CalculateCostMicros(gm, resp.Usage)
	actualInput := resp.Usage.PromptTokens
	actualOutput := resp.Usage.CompletionTokens
	if actualInput+actualOutput <= 0 {
		actualInput = estTokens
	}
	quotaSettlement.actualTokensReconciled = true
	if releaseTurnQuota != nil {
		releaseTurnQuota(actualInput, actualOutput, turnCost)
	}

	if s.spendWorker != nil {
		var provenance string
		if gm != nil {
			provenance = gm.PricingProvenanceSource
		}
		var latMs, ttftMs int64
		var retries int
		var fb bool
		if meta != nil {
			latMs = meta.LatencyMs
			ttftMs = meta.TTFTMs
			retries = meta.RetryCount
			fb = meta.FallbackAttempted
		}
		if recErr := s.spendWorker.Record(context.WithoutCancel(ctx), enrichSpendEventFromContext(ctx, domain.SpendEvent{
			ID:                      "sp_" + uuid.NewString(),
			RequestID:               turnReqID,
			OrgID:                   idCtx.OrgID,
			TeamID:                  idCtx.TeamID,
			UserID:                  idCtx.UserID,
			VirtualKeyID:            idCtx.VirtualKeyID,
			Endpoint:                "/v1/realtime",
			Modality:                domain.ModalityRealtime,
			RequestedModel:          requestedModel,
			ResolvedModel:           resolvedModel,
			Provider:                provider,
			DeploymentID:            depID,
			PricingVersion:          pricingVer,
			PricingStatus:           domain.ResolvePricingStatus(gm),
			PricingProvenanceSource: provenance,
			Usage:                   resp.Usage,
			CostMicros:              turnCost,
			LatencyMs:               latMs,
			TTFTMs:                  ttftMs,
			StatusCode:              http.StatusOK,
			FallbackAttempted:       fb,
			RetryCount:              retries,
			CreatedAt:               time.Now().UTC(),
		})); recErr != nil {
			logger.Error("Realtime turn spend event persistence failed", "session_id", sessionID, "turn_request_id", turnReqID, "error", recErr.Error())
			return nil, &domain.GatewayError{
				StatusCode: http.StatusServiceUnavailable,
				Type:       domain.ErrorTypeServer,
				Code:       "spend_persistence_unavailable",
				Message:    "Failed to persist realtime turn spend accounting",
			}
		}
	}

	return resp, nil
}

func mergeGoRouteExtensions(base, override *domain.GoRouteExtensions) *domain.GoRouteExtensions {
	out := base.Clone()
	if override == nil {
		return out
	}
	if out == nil {
		return override.Clone()
	}
	if override.TaskID != "" {
		out.TaskID = override.TaskID
	}
	if override.ContextID != "" {
		out.ContextID = override.ContextID
	}
	if len(override.Guardrails) > 0 {
		out.Guardrails = append(out.Guardrails, override.Guardrails...)
	}
	if len(override.Tags) > 0 {
		for _, tag := range override.Tags {
			out.Tags = appendUniqueRoutingTag(out.Tags, tag)
		}
	}
	if override.AllowedRegion != "" {
		out.AllowedRegion = override.AllowedRegion
	}
	if override.SessionID != "" {
		out.SessionID = override.SessionID
	}
	if override.PreferredDeploymentID != "" {
		out.PreferredDeploymentID = override.PreferredDeploymentID
	}
	if override.Priority != 0 {
		out.Priority = override.Priority
	}
	if override.HedgeAfterMs > 0 {
		out.HedgeAfterMs = override.HedgeAfterMs
	}
	if override.RoutingStrategy != "" {
		out.RoutingStrategy = override.RoutingStrategy
	}
	if override.DropUnsupportedParams != nil {
		v := *override.DropUnsupportedParams
		out.DropUnsupportedParams = &v
	}
	return out
}

func realtimeGatewayErrorEvent(gwErr *domain.GatewayError) map[string]any {
	errType := "invalid_request_error"
	code := ""
	msg := "Request failed"
	if gwErr != nil {
		if gwErr.Type != "" {
			errType = string(gwErr.Type)
		}
		code = gwErr.Code
		if gwErr.Message != "" {
			msg = gwErr.Message
		}
	}
	errBody := map[string]any{
		"type":    errType,
		"message": msg,
	}
	if code != "" {
		errBody["code"] = code
	}
	return map[string]any{
		"event_id": "event_" + uuid.NewString(),
		"type":     "error",
		"error":    errBody,
	}
}
