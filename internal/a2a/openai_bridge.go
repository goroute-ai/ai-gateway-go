package a2a

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/goroute-ai/ai-gateway-go/internal/a2a/pb"
	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

// OpenAIBridge provides compatibility translation allowing any standard OpenAI
// client to interact with registered A2A agents via `model: "a2a/{slug}"`.
type OpenAIBridge struct {
	router  *RouterService
	streams *StreamSubscriber
	repo    storage.Repository
	rbac    *auth.RBACEngine
}

// NewOpenAIBridge constructs a new A2A OpenAI bridge instance.
func NewOpenAIBridge(
	router *RouterService,
	streams *StreamSubscriber,
	repo storage.Repository,
	rbac *auth.RBACEngine,
) *OpenAIBridge {
	return &OpenAIBridge{
		router:  router,
		streams: streams,
		repo:    repo,
		rbac:    rbac,
	}
}

// HandleChatCompletion handles an OpenAI chat completion request targeted at an A2A agent.
func (b *OpenAIBridge) HandleChatCompletion(
	w http.ResponseWriter,
	r *http.Request,
	idCtx *domain.IdentityContext,
	agentSlug string,
	chatReq *domain.CanonicalChatRequest,
) {
	ctx := r.Context()

	// 1. RBAC check for the requested A2A agent
	if b.rbac != nil {
		if err := b.rbac.AuthorizeA2AAgent(idCtx, agentSlug); err != nil {
			domain.WriteHTTPError(w, err)
			return
		}
	}

	taskID, contextID := extractResumptionParams(r, chatReq)

	// 2. Build A2A message from conversation history
	pbMsg, err := b.buildA2AMessage(chatReq, contextID, taskID)
	if err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_messages",
			Message:    err.Error(),
		})
		return
	}

	sendReq := &pb.SendMessageRequest{
		Message: pbMsg,
	}

	// 3. Dispatch to RouterService
	resp, err := b.router.SendMessage(ctx, idCtx, agentSlug, sendReq)
	if err != nil {
		var a2aErr *A2AError
		if errors.As(err, &a2aErr) {
			statusCode := http.StatusInternalServerError
			if a2aErr.Code == CodeTaskNotFound {
				statusCode = http.StatusNotFound
			} else if a2aErr.Code == CodeAgentKilled {
				statusCode = http.StatusServiceUnavailable
			} else if a2aErr.Code == CodeInvalidTaskPayload || a2aErr.Code == CodeTaskStateTransitionInvalid {
				statusCode = http.StatusBadRequest
			}
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: statusCode,
				Type:       domain.ErrorTypeServer,
				Code:       fmt.Sprintf("a2a_error_%d", a2aErr.Code),
				Message:    a2aErr.Message,
			})
			return
		}
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadGateway,
			Type:       domain.ErrorTypeServer,
			Code:       "a2a_dispatch_error",
			Message:    err.Error(),
		})
		return
	}

	// 4. Return sync or streaming response
	if chatReq.Stream {
		flusher, ok := w.(http.Flusher)
		if !ok {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusInternalServerError,
				Type:       domain.ErrorTypeServer,
				Code:       "streaming_unsupported",
				Message:    "HTTP response writer does not support streaming",
			})
			return
		}
		b.handleStream(w, flusher, idCtx, agentSlug, resp, contextID, taskID)
	} else {
		b.handleSync(w, idCtx, agentSlug, resp, contextID, taskID)
	}
}

func (b *OpenAIBridge) buildA2AMessage(
	chatReq *domain.CanonicalChatRequest,
	contextID string,
	taskID string,
) (*pb.Message, error) {
	var systemInstructions []string
	var parts []*pb.Part

	for _, msg := range chatReq.Messages {
		roleLower := strings.ToLower(strings.TrimSpace(msg.Role))
		switch roleLower {
		case "system", "developer":
			if strings.TrimSpace(msg.Content) != "" {
				systemInstructions = append(systemInstructions, msg.Content)
			}
		case "user":
			if msg.Content != "" {
				parts = append(parts, &pb.Part{
					Content: &pb.Part_Text{
						Text: msg.Content,
					},
				})
			}
			for _, p := range msg.Parts {
				if p.Type == "text" && p.Text != "" {
					parts = append(parts, &pb.Part{
						Content: &pb.Part_Text{
							Text: p.Text,
						},
					})
				} else if p.Type == "image_url" && p.ImageURL != nil {
					parts = append(parts, &pb.Part{
						Content: &pb.Part_Url{
							Url: p.ImageURL.URL,
						},
					})
				}
			}
		}
	}

	if len(parts) == 0 {
		return nil, fmt.Errorf("no user content provided in chat completion messages")
	}

	// Prepend system instructions to the first turn if present
	if len(systemInstructions) > 0 {
		combinedInstructions := strings.Join(systemInstructions, "\n\n")
		firstPartText := parts[0].GetText()
		parts[0] = &pb.Part{
			Content: &pb.Part_Text{
				Text: fmt.Sprintf("[Instructions: %s]\n\n%s", combinedInstructions, firstPartText),
			},
		}
	}

	return &pb.Message{
		Role:      pb.Role_ROLE_USER,
		Parts:     parts,
		ContextId: contextID,
		TaskId:    taskID,
	}, nil
}

func extractResumptionParams(r *http.Request, chatReq *domain.CanonicalChatRequest) (string, string) {
	taskID := ""
	contextID := ""

	// 1. From GoRouteExtensions struct
	if chatReq.GoRouteExtensions != nil {
		taskID = strings.TrimSpace(chatReq.GoRouteExtensions.TaskID)
		contextID = strings.TrimSpace(chatReq.GoRouteExtensions.ContextID)
	}

	// 2. From ExtraParams map
	if chatReq.ExtraParams != nil {
		if taskID == "" {
			if t, ok := chatReq.ExtraParams["task_id"].(string); ok {
				taskID = strings.TrimSpace(t)
			}
		}
		if contextID == "" {
			if c, ok := chatReq.ExtraParams["context_id"].(string); ok {
				contextID = strings.TrimSpace(c)
			}
		}
		if ext, ok := chatReq.ExtraParams["goroute_extensions"].(map[string]any); ok {
			if taskID == "" {
				if t, ok := ext["task_id"].(string); ok {
					taskID = strings.TrimSpace(t)
				}
			}
			if contextID == "" {
				if c, ok := ext["context_id"].(string); ok {
					contextID = strings.TrimSpace(c)
				}
			}
		}
	}

	// 3. From HTTP request headers
	if taskID == "" && r != nil {
		taskID = strings.TrimSpace(r.Header.Get("X-Gateway-A2A-Task-Id"))
	}
	if contextID == "" && r != nil {
		contextID = strings.TrimSpace(r.Header.Get("X-Gateway-A2A-Context-Id"))
	}

	if contextID == "" {
		contextID = "ctx_" + uuid.NewString()
	}

	return taskID, contextID
}

func (b *OpenAIBridge) handleSync(
	w http.ResponseWriter,
	idCtx *domain.IdentityContext,
	agentSlug string,
	resp *pb.SendMessageResponse,
	contextID string,
	taskID string,
) {
	if resp == nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadGateway,
			Type:       domain.ErrorTypeServer,
			Code:       "a2a_empty_response",
			Message:    "Upstream A2A agent returned empty response",
		})
		return
	}

	content := ""
	taskState := "completed"

	if task := resp.GetTask(); task != nil {
		if task.GetId() != "" {
			taskID = task.GetId()
		}
		if task.GetContextId() != "" {
			contextID = task.GetContextId()
		}

		status := task.GetStatus()
		if status != nil {
			switch status.GetState() {
			case pb.TaskState_TASK_STATE_COMPLETED:
				taskState = "completed"
				content = extractTaskContent(task)
			case pb.TaskState_TASK_STATE_INPUT_REQUIRED:
				taskState = "input_required"
				content = extractTaskContent(task)
			case pb.TaskState_TASK_STATE_AUTH_REQUIRED:
				taskState = "auth_required"
				content = extractTaskContent(task)
			case pb.TaskState_TASK_STATE_FAILED, pb.TaskState_TASK_STATE_CANCELED, pb.TaskState_TASK_STATE_REJECTED:
				domain.WriteHTTPError(w, &domain.GatewayError{
					StatusCode: http.StatusBadGateway,
					Type:       domain.ErrorTypeServer,
					Code:       "a2a_task_failed",
					Message:    fmt.Sprintf("A2A task reached terminal failure state: %s", status.GetState().String()),
				})
				return
			default:
				content = extractTaskContent(task)
			}
		} else {
			content = extractTaskContent(task)
		}
	} else if msg := resp.GetMessage(); msg != nil {
		content = extractMessageText(msg)
		if msg.GetTaskId() != "" {
			taskID = msg.GetTaskId()
		}
		if msg.GetContextId() != "" {
			contextID = msg.GetContextId()
		}
	}

	completionID := "chatcmpl_" + uuid.NewString()
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("X-Gateway-A2A-Task-Id", taskID)
	w.Header().Set("X-Gateway-A2A-Context-Id", contextID)
	w.Header().Set("X-Gateway-A2A-Task-State", taskState)

	result := map[string]any{
		"id":      completionID,
		"object":  "chat.completion",
		"created": time.Now().Unix(),
		"model":   "a2a/" + agentSlug,
		"choices": []map[string]any{
			{
				"index": 0,
				"message": map[string]any{
					"role":    "assistant",
					"content": content,
				},
				"finish_reason": "stop",
			},
		},
		"goroute_a2a": map[string]any{
			"task_id":    taskID,
			"context_id": contextID,
			"task_state": taskState,
		},
	}

	_ = json.NewEncoder(w).Encode(result)
}

func (b *OpenAIBridge) handleStream(
	w http.ResponseWriter,
	flusher http.Flusher,
	idCtx *domain.IdentityContext,
	agentSlug string,
	resp *pb.SendMessageResponse,
	contextID string,
	taskID string,
) {
	completionID := "chatcmpl_" + uuid.NewString()
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no")
	w.Header().Set("X-Gateway-A2A-Task-Id", taskID)
	w.Header().Set("X-Gateway-A2A-Context-Id", contextID)

	flusher.Flush()

	if resp == nil {
		emitSSEError(w, flusher, "a2a_task_failed", "upstream returned empty response")
		return
	}

	if task := resp.GetTask(); task != nil {
		if task.GetId() != "" {
			taskID = task.GetId()
		}
		if task.GetContextId() != "" {
			contextID = task.GetContextId()
		}
		status := task.GetStatus()
		if status != nil {
			switch status.GetState() {
			case pb.TaskState_TASK_STATE_FAILED, pb.TaskState_TASK_STATE_CANCELED, pb.TaskState_TASK_STATE_REJECTED:
				emitSSEError(w, flusher, "a2a_task_failed", fmt.Sprintf("A2A task reached failure state: %s", status.GetState().String()))
				return
			case pb.TaskState_TASK_STATE_INPUT_REQUIRED, pb.TaskState_TASK_STATE_AUTH_REQUIRED:
				content := extractTaskContent(task)
				stateStr := "input_required"
				if status.GetState() == pb.TaskState_TASK_STATE_AUTH_REQUIRED {
					stateStr = "auth_required"
				}
				chunk := map[string]any{
					"id":      completionID,
					"object":  "chat.completion.chunk",
					"created": time.Now().Unix(),
					"model":   "a2a/" + agentSlug,
					"choices": []map[string]any{
						{
							"index": 0,
							"delta": map[string]any{
								"content": content,
							},
							"finish_reason": "stop",
						},
					},
					"goroute_a2a": map[string]any{
						"task_id":    taskID,
						"context_id": contextID,
						"task_state": stateStr,
					},
				}
				chunkBytes, _ := json.Marshal(chunk)
				fmt.Fprintf(w, "data: %s\n\n", chunkBytes)
				fmt.Fprintf(w, "data: [DONE]\n\n")
				flusher.Flush()
				return
			}
		}
		content := extractTaskContent(task)
		emitSSEChunks(w, flusher, completionID, agentSlug, content, taskID, contextID)
		return
	} else if msg := resp.GetMessage(); msg != nil {
		content := extractMessageText(msg)
		emitSSEChunks(w, flusher, completionID, agentSlug, content, taskID, contextID)
		return
	}

	fmt.Fprintf(w, "data: [DONE]\n\n")
	flusher.Flush()
}

func emitSSEError(w http.ResponseWriter, flusher http.Flusher, code, message string) {
	errPayload, _ := json.Marshal(map[string]any{
		"error": map[string]any{
			"code":    code,
			"message": message,
		},
	})
	fmt.Fprintf(w, "event: error\ndata: %s\n\n", errPayload)
	fmt.Fprintf(w, "data: [DONE]\n\n")
	flusher.Flush()
}

func emitSSEChunks(w http.ResponseWriter, flusher http.Flusher, completionID, agentSlug, content, taskID, contextID string) {
	words := strings.Fields(content)
	if len(words) == 0 && content != "" {
		words = []string{content}
	}
	for i, word := range words {
		deltaText := word
		if i > 0 {
			deltaText = " " + word
		}
		chunk := map[string]any{
			"id":      completionID,
			"object":  "chat.completion.chunk",
			"created": time.Now().Unix(),
			"model":   "a2a/" + agentSlug,
			"choices": []map[string]any{
				{
					"index": 0,
					"delta": map[string]any{
						"content": deltaText,
					},
					"finish_reason": nil,
				},
			},
		}
		chunkBytes, _ := json.Marshal(chunk)
		fmt.Fprintf(w, "data: %s\n\n", chunkBytes)
		flusher.Flush()
	}

	stopChunk := map[string]any{
		"id":      completionID,
		"object":  "chat.completion.chunk",
		"created": time.Now().Unix(),
		"model":   "a2a/" + agentSlug,
		"choices": []map[string]any{
			{
				"index":         0,
				"delta":         map[string]any{},
				"finish_reason": "stop",
			},
		},
		"goroute_a2a": map[string]any{
			"task_id":    taskID,
			"context_id": contextID,
			"task_state": "completed",
		},
	}
	stopBytes, _ := json.Marshal(stopChunk)
	fmt.Fprintf(w, "data: %s\n\n", stopBytes)
	fmt.Fprintf(w, "data: [DONE]\n\n")
	flusher.Flush()
}

func extractMessageText(msg *pb.Message) string {
	if msg == nil {
		return ""
	}
	var sb strings.Builder
	for _, p := range msg.Parts {
		if txt := p.GetText(); txt != "" {
			if sb.Len() > 0 {
				sb.WriteString("\n")
			}
			sb.WriteString(txt)
		}
	}
	return sb.String()
}

func extractTaskContent(task *pb.Task) string {
	if task == nil {
		return ""
	}
	if task.GetStatus() != nil && task.GetStatus().GetMessage() != nil {
		if txt := extractMessageText(task.GetStatus().GetMessage()); txt != "" {
			return txt
		}
	}
	for _, art := range task.GetArtifacts() {
		for _, p := range art.GetParts() {
			if txt := p.GetText(); txt != "" {
				return txt
			}
		}
	}
	return ""
}
