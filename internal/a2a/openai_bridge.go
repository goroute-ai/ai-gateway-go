package a2a

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	a2aspec "github.com/goroute-ai/ai-gateway-go/internal/a2a/spec"
	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

// OpenAIBridge translates OpenAI `/v1/chat/completions` (`model: "a2a/{slug}"`) requests
// into OpenAPI-first A2A v1.0 SendMessage / SendStreamingMessage calls.
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

	if b.rbac != nil {
		if err := b.rbac.AuthorizeA2AAgent(idCtx, agentSlug); err != nil {
			domain.WriteHTTPError(w, err)
			return
		}
	}

	taskID, contextID := extractResumptionParams(r, chatReq)
	specMsg, err := b.buildA2AMessage(chatReq, contextID, taskID)
	if err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_messages",
			Message:    err.Error(),
		})
		return
	}

	sendReq := &a2aspec.SendMessageRequest{
		Message: *specMsg,
	}

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
		b.handleStream(w, r, flusher, idCtx, agentSlug, sendReq, contextID, taskID)
		return
	}

	resp, err := b.router.SendMessage(ctx, idCtx, agentSlug, sendReq)
	if err != nil {
		b.writeBridgeError(w, err)
		return
	}
	b.handleSync(w, agentSlug, resp, contextID, taskID)
}

func (b *OpenAIBridge) buildA2AMessage(
	chatReq *domain.CanonicalChatRequest,
	contextID string,
	taskID string,
) (*a2aspec.Message, error) {
	var systemInstructions []string
	var transcript []map[string]any
	var parts []a2aspec.Part

	lastUserIdx := -1
	for i := len(chatReq.Messages) - 1; i >= 0; i-- {
		if strings.EqualFold(strings.TrimSpace(chatReq.Messages[i].Role), "user") {
			lastUserIdx = i
			break
		}
	}
	if lastUserIdx < 0 {
		return nil, fmt.Errorf("no user content provided in chat completion messages")
	}

	for i, msg := range chatReq.Messages {
		roleLower := strings.ToLower(strings.TrimSpace(msg.Role))
		switch roleLower {
		case "system", "developer":
			if strings.TrimSpace(msg.Content) != "" {
				systemInstructions = append(systemInstructions, msg.Content)
			}
		case "user":
			if i == lastUserIdx {
				if msg.Content != "" {
					parts = append(parts, a2aspec.NewTextPart(msg.Content))
				}
				for _, p := range msg.Parts {
					if p.Type == "text" && p.Text != "" {
						parts = append(parts, a2aspec.NewTextPart(p.Text))
					} else if p.Type == "image_url" && p.ImageURL != nil && p.ImageURL.URL != "" {
						u := p.ImageURL.URL
						parts = append(parts, a2aspec.Part{Url: &u})
					}
				}
			} else {
				transcript = append(transcript, map[string]any{
					"role":    "user",
					"content": canonicalMessageText(msg),
				})
			}
		case "assistant", "tool":
			entry := map[string]any{
				"role":    roleLower,
				"content": canonicalMessageText(msg),
			}
			if msg.ToolCallID != "" {
				entry["tool_call_id"] = msg.ToolCallID
			}
			transcript = append(transcript, entry)
		}
	}

	if len(parts) == 0 {
		return nil, fmt.Errorf("no user content provided in chat completion messages")
	}

	if len(systemInstructions) > 0 && parts[0].Text != nil {
		combined := strings.Join(systemInstructions, "\n\n")
		a2aspec.SetPartText(&parts[0], fmt.Sprintf("[Instructions: %s]\n\n%s", combined, *parts[0].Text))
	}

	var meta *a2aspec.Metadata
	if len(transcript) > 0 {
		m := a2aspec.Metadata{
			"conversation_history": transcript,
		}
		meta = &m
	}

	msg := &a2aspec.Message{
		MessageId: "msg_" + uuid.NewString(),
		Role:      a2aspec.ROLEUSER,
		Parts:     parts,
		Metadata:  meta,
	}
	if contextID != "" {
		msg.ContextId = &contextID
	}
	if taskID != "" {
		msg.TaskId = &taskID
	}
	return msg, nil
}

func canonicalMessageText(msg domain.CanonicalMessage) string {
	if msg.Content != "" {
		return msg.Content
	}
	var sb strings.Builder
	for _, p := range msg.Parts {
		if p.Type == "text" && p.Text != "" {
			if sb.Len() > 0 {
				sb.WriteString("\n")
			}
			sb.WriteString(p.Text)
		}
	}
	return sb.String()
}

func extractResumptionParams(r *http.Request, chatReq *domain.CanonicalChatRequest) (string, string) {
	taskID := ""
	contextID := ""

	if chatReq.GoRouteExtensions != nil {
		taskID = strings.TrimSpace(chatReq.GoRouteExtensions.TaskID)
		contextID = strings.TrimSpace(chatReq.GoRouteExtensions.ContextID)
	}

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
	agentSlug string,
	resp *a2aspec.SendMessageResponse,
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
	taskState := domain.A2ATaskStateCompleted

	if task := resp.Task; task != nil {
		if task.Id != "" {
			taskID = task.Id
		}
		if task.ContextId != nil && *task.ContextId != "" {
			contextID = *task.ContextId
		}
		taskState = a2aspec.TaskStateToDomain(task.Status.State)
		if task.Status.State == a2aspec.TASKSTATEFAILED ||
			task.Status.State == a2aspec.TASKSTATECANCELED ||
			task.Status.State == a2aspec.TASKSTATEREJECTED {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusBadGateway,
				Type:       domain.ErrorTypeServer,
				Code:       "a2a_task_failed",
				Message:    fmt.Sprintf("A2A task reached terminal failure state: %s", task.Status.State),
			})
			return
		}
		content = extractSpecTaskContent(task)
	} else if msg := resp.Message; msg != nil {
		content = extractSpecMessageText(msg)
		if msg.TaskId != nil && *msg.TaskId != "" {
			taskID = *msg.TaskId
		}
		if msg.ContextId != nil && *msg.ContextId != "" {
			contextID = *msg.ContextId
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
	r *http.Request,
	flusher http.Flusher,
	idCtx *domain.IdentityContext,
	agentSlug string,
	sendReq *a2aspec.SendMessageRequest,
	contextID string,
	taskID string,
) {
	completionID := "chatcmpl_" + uuid.NewString()
	headersWritten := false
	resolvedTaskID := taskID
	resolvedContextID := contextID
	finalState := domain.A2ATaskStateCompleted

	initSSEHeaders := func(tid, cid string) {
		if headersWritten {
			return
		}
		headersWritten = true
		if tid != "" {
			resolvedTaskID = tid
		}
		if cid != "" {
			resolvedContextID = cid
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("X-Accel-Buffering", "no")
		w.Header().Set("X-Gateway-A2A-Task-Id", resolvedTaskID)
		w.Header().Set("X-Gateway-A2A-Context-Id", resolvedContextID)
		w.WriteHeader(http.StatusOK)
		flusher.Flush()
	}

	err := b.router.SendStreamingMessage(r.Context(), idCtx, agentSlug, sendReq, func(frame *a2aspec.StreamResponse, _ int64) error {
		if frame == nil {
			return nil
		}
		var deltaContent string
		switch {
		case frame.Task != nil:
			cid := resolvedContextID
			if frame.Task.ContextId != nil && *frame.Task.ContextId != "" {
				cid = *frame.Task.ContextId
			}
			initSSEHeaders(frame.Task.Id, cid)
			finalState = a2aspec.TaskStateToDomain(frame.Task.Status.State)
			if frame.Task.Status.State == a2aspec.TASKSTATEFAILED ||
				frame.Task.Status.State == a2aspec.TASKSTATECANCELED ||
				frame.Task.Status.State == a2aspec.TASKSTATEREJECTED {
				emitSSEError(w, flusher, "a2a_task_failed", fmt.Sprintf("A2A task reached failure state: %s", frame.Task.Status.State))
				return fmt.Errorf("a2a task failed: %s", frame.Task.Status.State)
			}
			deltaContent = extractSpecTaskContent(frame.Task)
		case frame.StatusUpdate != nil:
			initSSEHeaders(frame.StatusUpdate.TaskId, frame.StatusUpdate.ContextId)
			finalState = a2aspec.TaskStateToDomain(frame.StatusUpdate.Status.State)
			if frame.StatusUpdate.Status.Message != nil {
				deltaContent = extractSpecMessageText(frame.StatusUpdate.Status.Message)
			}
			if frame.StatusUpdate.Status.State == a2aspec.TASKSTATEFAILED ||
				frame.StatusUpdate.Status.State == a2aspec.TASKSTATECANCELED ||
				frame.StatusUpdate.Status.State == a2aspec.TASKSTATEREJECTED {
				emitSSEError(w, flusher, "a2a_task_failed", fmt.Sprintf("A2A task reached failure state: %s", frame.StatusUpdate.Status.State))
				return fmt.Errorf("a2a task failed: %s", frame.StatusUpdate.Status.State)
			}
		case frame.ArtifactUpdate != nil:
			initSSEHeaders(frame.ArtifactUpdate.TaskId, frame.ArtifactUpdate.ContextId)
			deltaContent = extractArtifactPartsText(frame.ArtifactUpdate.Artifact.Parts)
		case frame.Message != nil:
			tid := resolvedTaskID
			if frame.Message.TaskId != nil && *frame.Message.TaskId != "" {
				tid = *frame.Message.TaskId
			}
			cid := resolvedContextID
			if frame.Message.ContextId != nil && *frame.Message.ContextId != "" {
				cid = *frame.Message.ContextId
			}
			initSSEHeaders(tid, cid)
			deltaContent = extractSpecMessageText(frame.Message)
		}

		if deltaContent != "" {
			chunk := map[string]any{
				"id":      completionID,
				"object":  "chat.completion.chunk",
				"created": time.Now().Unix(),
				"model":   "a2a/" + agentSlug,
				"choices": []map[string]any{
					{
						"index": 0,
						"delta": map[string]any{
							"content": deltaContent,
						},
						"finish_reason": nil,
					},
				},
			}
			chunkBytes, _ := json.Marshal(chunk)
			_, _ = fmt.Fprintf(w, "data: %s\n\n", chunkBytes)
			flusher.Flush()
		}
		return nil
	})
	if err != nil {
		if !headersWritten {
			b.writeBridgeError(w, err)
			return
		}
		return
	}

	initSSEHeaders(resolvedTaskID, resolvedContextID)
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
			"task_id":    resolvedTaskID,
			"context_id": resolvedContextID,
			"task_state": finalState,
		},
	}
	stopBytes, _ := json.Marshal(stopChunk)
	_, _ = fmt.Fprintf(w, "data: %s\n\n", stopBytes)
	_, _ = fmt.Fprintf(w, "data: [DONE]\n\n")
	flusher.Flush()
}

func (b *OpenAIBridge) writeBridgeError(w http.ResponseWriter, err error) {
	norm := NormalizeA2AError(err)
	domain.WriteHTTPError(w, &domain.GatewayError{
		StatusCode: norm.HTTPStatus,
		Type:       domain.ErrorTypeServer,
		Code:       fmt.Sprintf("a2a_error_%d", norm.JSONRPCCode),
		Message:    norm.Message,
	})
}

func emitSSEError(w http.ResponseWriter, flusher http.Flusher, code, message string) {
	errPayload, _ := json.Marshal(map[string]any{
		"error": map[string]any{
			"code":    code,
			"message": message,
		},
	})
	_, _ = fmt.Fprintf(w, "event: error\ndata: %s\n\n", errPayload)
	_, _ = fmt.Fprintf(w, "data: [DONE]\n\n")
	flusher.Flush()
}

func extractSpecMessageText(msg *a2aspec.Message) string {
	if msg == nil {
		return ""
	}
	var sb strings.Builder
	for _, p := range msg.Parts {
		if txt, ok := a2aspec.PartText(p); ok && txt != "" {
			if sb.Len() > 0 {
				sb.WriteString("\n")
			}
			sb.WriteString(txt)
		}
	}
	return sb.String()
}

func extractArtifactPartsText(parts []a2aspec.Part) string {
	var sb strings.Builder
	for _, p := range parts {
		if txt, ok := a2aspec.PartText(p); ok && txt != "" {
			if sb.Len() > 0 {
				sb.WriteString("\n")
			}
			sb.WriteString(txt)
		}
	}
	return sb.String()
}

func extractSpecTaskContent(task *a2aspec.Task) string {
	if task == nil {
		return ""
	}
	if task.Status.Message != nil {
		if txt := extractSpecMessageText(task.Status.Message); txt != "" {
			return txt
		}
	}
	if task.Artifacts != nil {
		for _, art := range *task.Artifacts {
			if txt := extractArtifactPartsText(art.Parts); txt != "" {
				return txt
			}
		}
	}
	return ""
}
