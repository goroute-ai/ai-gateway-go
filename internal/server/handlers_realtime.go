package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/finops"
	"github.com/goroute-ai/ai-gateway-go/internal/logger"
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
	if rejectBudgetedUnsupported(w, idCtx) {
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
	}

	var sessionMu sync.Mutex
	history := make([]domain.CanonicalMessage, 0)
	var totalUsage domain.TokenUsage
	var totalCostMicros int64

	// Helper to send JSON event to client
	sendEvent := func(ctx context.Context, ev map[string]any) error {
		b, err := json.Marshal(ev)
		if err != nil {
			return err
		}
		return conn.Write(ctx, websocket.MessageText, b)
	}

	// 1. Send initial session.created event
	_ = sendEvent(r.Context(), map[string]any{
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

	// Message frame pump loop
	for {
		msgType, data, err := conn.Read(r.Context())
		if err != nil {
			// Client disconnected
			break
		}
		if msgType != websocket.MessageText {
			continue
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
			Audio string `json:"audio,omitempty"`
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
			sessionMu.Lock()
			if clientEv.Session != nil {
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
			sessionMu.Unlock()
			if len(reqMsgs) == 0 {
				_ = sendEvent(r.Context(), map[string]any{"event_id": "event_" + uuid.NewString(), "type": "error", "error": map[string]any{"type": "invalid_request_error", "message": "response.create requires text input"}})
				continue
			}

			chatReq := &domain.CanonicalChatRequest{
				Model:       model,
				Messages:    reqMsgs,
				Temperature: temp,
			}

			respID := "resp_" + uuid.NewString()
			itemMsgID := "msg_" + uuid.NewString()

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

			resp, meta, err := s.reliability.ExecuteChat(r.Context(), idCtx, chatReq)
			if err != nil {
				_ = sendEvent(r.Context(), map[string]any{
					"event_id": "event_" + uuid.NewString(),
					"type":     "error",
					"error": map[string]any{
						"type":    "execution_error",
						"message": err.Error(),
					},
				})
				continue
			}

			var gm *domain.GlobalModel
			if meta != nil && meta.WinningDeployment != nil {
				gm = meta.WinningDeployment.GlobalModel
			}
			turnCost := finops.CalculateCostMicros(gm, resp.Usage)
			sessionMu.Lock()
			totalUsage.PromptTokens += resp.Usage.PromptTokens
			totalUsage.CompletionTokens += resp.Usage.CompletionTokens
			totalUsage.TotalTokens += resp.Usage.TotalTokens
			totalCostMicros += turnCost
			sessionMu.Unlock()

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

	// Session finished - record FinOps spend event
	sessionDuration := time.Since(startTime)
	if s.spendWorker != nil {
		sessionMu.Lock()
		finalUsage := totalUsage
		finalCost := totalCostMicros
		sessionMu.Unlock()

		if err := s.spendWorker.Record(r.Context(), domain.SpendEvent{
			ID:             "sp_" + uuid.NewString(),
			RequestID:      sessionID,
			OrgID:          idCtx.OrgID,
			TeamID:         idCtx.TeamID,
			UserID:         idCtx.UserID,
			VirtualKeyID:   idCtx.VirtualKeyID,
			Endpoint:       "/v1/realtime",
			RequestedModel: model,
			ResolvedModel:  model,
			Modality:       domain.ModalityRealtime,
			Usage:          finalUsage,
			CostMicros:     finalCost,
			CreatedAt:      time.Now().UTC(),
		}); err != nil {
			logger.Error("Realtime session spend event persistence failed", "session_id", sessionID, "error", err.Error())
			_ = sendEvent(r.Context(), map[string]any{"event_id": "event_" + uuid.NewString(), "type": "error", "error": map[string]any{"type": "server_error", "code": "spend_persistence_unavailable"}})
		}
	}

	logger.Info("Realtime websocket session completed",
		"session_id", sessionID,
		"model", model,
		"duration", sessionDuration.String(),
	)
}
