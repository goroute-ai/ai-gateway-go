package a2a

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/goroute-ai/ai-gateway-go/internal/a2a/pb"
	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/guardrails"
	"github.com/goroute-ai/ai-gateway-go/internal/observability"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"google.golang.org/protobuf/encoding/protojson"
)

// RouterService orchestrates A2A protocol message routing, state machine validation,
// durable event sequencing, and push notification outbox management.
type RouterService struct {
	repo        storage.Repository
	vault       *auth.Vault
	rbac        *auth.RBACEngine
	netPolicy   *network.Policy
	httpClient  *http.Client
	redisFabric *storage.RedisFabric
	signer      *GatewayCardSigner
	verifier    *UpstreamCardVerifier
	guardrails  *guardrails.Engine
}

// NewRouterService constructs a new A2A RouterService.
func NewRouterService(
	repo storage.Repository,
	vault *auth.Vault,
	rbac *auth.RBACEngine,
	netPolicy *network.Policy,
	redisFabric *storage.RedisFabric,
	signer *GatewayCardSigner,
	verifier *UpstreamCardVerifier,
) *RouterService {
	client := network.NewHTTPClient(netPolicy)
	client.Timeout = 60 * time.Second

	return &RouterService{
		repo:        repo,
		vault:       vault,
		rbac:        rbac,
		netPolicy:   netPolicy,
		httpClient:  client,
		redisFabric: redisFabric,
		signer:      signer,
		verifier:    verifier,
	}
}

// SetGuardrails attaches a guardrails engine to evaluate inbound and outbound A2A messages.
func (s *RouterService) SetGuardrails(g *guardrails.Engine) {
	if s != nil {
		s.guardrails = g
	}
}

// SendMessage routes a message to an A2A agent, enforcing kill-switches, RBAC,
// state transitions, and monotonic durable event sequencing.
func (s *RouterService) SendMessage(
	ctx context.Context,
	idCtx *domain.IdentityContext,
	agentSlug string,
	req *pb.SendMessageRequest,
) (*pb.SendMessageResponse, error) {
	if req == nil || req.Message == nil {
		return nil, &A2AError{
			Code:    CodeInvalidTaskPayload,
			Message: "SendMessageRequest must include a valid message",
		}
	}

	// 1. RBAC check
	if s.rbac != nil {
		if err := s.rbac.AuthorizeA2AAgent(idCtx, agentSlug); err != nil {
			return nil, &A2AError{
				Code:    CodeTaskNotFound, // Hide agent existence on forbidden
				Message: fmt.Sprintf("Forbidden: %v", err),
			}
		}
	}

	orgID := ""
	if idCtx != nil {
		orgID = idCtx.OrgID
	}

	// 2. Retrieve agent
	agent, err := s.repo.GetA2AAgentBySlug(ctx, orgID, agentSlug)
	if err != nil || agent == nil || !agent.IsActive {
		return nil, &A2AError{
			Code:    CodeTaskNotFound,
			Message: fmt.Sprintf("Agent %q not found or inactive", agentSlug),
		}
	}

	// 3. Emergency Kill-Switch Check
	if agent.IsKilled {
		return nil, &A2AError{
			Code:    CodeAgentKilled,
			Message: fmt.Sprintf("Agent %q is disabled by administrator emergency kill-switch", agentSlug),
		}
	}

	// 3b. Inbound Guardrails Evaluation on text parts
	if s.guardrails != nil {
		if err := s.evaluateInboundMessage(ctx, orgID, req.Message); err != nil {
			return nil, err
		}
	}

	now := time.Now().UTC()
	var task *domain.A2ATask

	// 4. Resolve or create task
	if req.Message.TaskId != "" {
		existingTask, err := s.repo.GetA2ATask(ctx, req.Message.TaskId)
		if err != nil || existingTask == nil {
			return nil, &A2AError{
				Code:    CodeTaskNotFound,
				Message: fmt.Sprintf("Task %q not found", req.Message.TaskId),
			}
		}

		// Visibility check
		if !CheckTaskVisibility(existingTask, idCtx, agent.TaskVisibilityMode) {
			return nil, &A2AError{
				Code:    CodeTaskNotFound,
				Message: fmt.Sprintf("Task %q not found", req.Message.TaskId),
			}
		}

		// State machine validation
		currentState := StringToTaskState(existingTask.State)
		if err := ValidateStateTransition(currentState, pb.TaskState_TASK_STATE_WORKING); err != nil {
			return nil, err
		}

		// Budget and iteration limit checks
		if agent.MaxTaskBudgetMicros > 0 && existingTask.TotalCostMicros >= agent.MaxTaskBudgetMicros {
			return nil, &A2AError{
				Code:    CodeBudgetExceeded,
				Message: fmt.Sprintf("Task %q has exceeded agent budget limit of %d micros (current: %d micros)", req.Message.TaskId, agent.MaxTaskBudgetMicros, existingTask.TotalCostMicros),
			}
		}
		if agent.MaxTaskIterations > 0 && existingTask.LastEventSeq >= int64(agent.MaxTaskIterations) {
			return nil, &A2AError{
				Code:    CodeBudgetExceeded,
				Message: fmt.Sprintf("Task %q has reached maximum iteration cap (%d)", req.Message.TaskId, agent.MaxTaskIterations),
			}
		}

		task = existingTask
	} else {
		// Create new task
		taskID := "task_" + uuid.NewString()
		inputMsgJSON, _ := protojson.Marshal(req.Message)

		task = &domain.A2ATask{
			ID:               taskID,
			AgentID:          agent.ID,
			OrgID:            agent.OrgID,
			TeamID:           idCtx.TeamID,
			VirtualKeyID:     idCtx.VirtualKeyID,
			UserID:           idCtx.UserID,
			State:            domain.A2ATaskStateSubmitted,
			LastEventSeq:     0,
			InputMessageJSON: string(inputMsgJSON),
			CreatedAt:        now,
			UpdatedAt:        now,
		}

		if err := s.repo.CreateA2ATask(ctx, task); err != nil {
			return nil, fmt.Errorf("a2a: store task: %w", err)
		}
	}

	// 5. Monotonically record message event in transaction
	msgJSON, _ := protojson.Marshal(req.Message)
	taskEvent, err := s.repo.AppendA2ATaskEvent(ctx, task.ID, "message", string(msgJSON))
	if err != nil {
		return nil, fmt.Errorf("a2a: record task event: %w", err)
	}
	task.LastEventSeq = taskEvent.EventSeq
	task.State = domain.A2ATaskStateWorking
	task.UpdatedAt = now
	_ = s.repo.UpdateA2ATaskState(ctx, task.ID, task.State, task.OutputMessageJSON, task.TotalCostMicros)

	// 6. Upstream agent invocation
	upstreamResp, err := s.invokeUpstreamAgent(ctx, agent, req)
	if err != nil {
		// Mark task failed
		task.State = domain.A2ATaskStateFailed
		task.UpdatedAt = time.Now().UTC()
		_ = s.repo.UpdateA2ATaskState(ctx, task.ID, task.State, task.OutputMessageJSON, task.TotalCostMicros)
		return nil, err
	}

	// 6b. Outbound Guardrails Sanitization on text parts
	if s.guardrails != nil && upstreamResp != nil {
		if err := s.sanitizeOutboundResponse(ctx, orgID, upstreamResp); err != nil {
			task.State = domain.A2ATaskStateFailed
			task.UpdatedAt = time.Now().UTC()
			_ = s.repo.UpdateA2ATaskState(ctx, task.ID, task.State, task.OutputMessageJSON, task.TotalCostMicros)
			return nil, err
		}
	}

	// 7. Record upstream response event & update task state
	if upstreamResp.GetTask() != nil {
		upTask := upstreamResp.GetTask()
		upTask.Id = task.ID
		if upTask.ContextId == "" && req.Message != nil {
			upTask.ContextId = req.Message.ContextId
		}
		task.State = TaskStateToString(upTask.Status.State)
		if upTask.Status.State == pb.TaskState_TASK_STATE_COMPLETED {
			cTime := time.Now().UTC()
			task.CompletedAt = &cTime
		}
	} else if upstreamResp.GetMessage() != nil {
		outMsgJSON, _ := protojson.Marshal(upstreamResp.GetMessage())
		task.OutputMessageJSON = string(outMsgJSON)
		task.State = domain.A2ATaskStateCompleted
		cTime := time.Now().UTC()
		task.CompletedAt = &cTime
	}

	task.UpdatedAt = time.Now().UTC()
	_ = s.repo.UpdateA2ATaskState(ctx, task.ID, task.State, task.OutputMessageJSON, task.TotalCostMicros)

	// 8. Queue outbox notifications if registered
	cfg, _ := s.repo.GetA2APushNotificationConfig(ctx, task.ID)
	if cfg != nil && cfg.TargetURL != "" {
		outboxPayload, _ := json.Marshal(map[string]any{
			"task_id":   task.ID,
			"event_seq": task.LastEventSeq,
			"state":     task.State,
		})
		outboxEv := &domain.A2AOutboxEvent{
			ID:            "outbox_" + uuid.NewString(),
			TaskID:        task.ID,
			EventType:     "status",
			TargetURL:     cfg.TargetURL,
			PayloadJSON:   string(outboxPayload),
			Status:        domain.OutboxStatusPending,
			AttemptCount:  0,
			NextAttemptAt: time.Now().UTC(),
			CreatedAt:     time.Now().UTC(),
		}
		_ = s.repo.CreateA2AOutboxEvent(ctx, outboxEv)
	}

	return upstreamResp, nil
}

// GetTask returns a task by ID, enforcing visibility isolation.
func (s *RouterService) GetTask(
	ctx context.Context,
	idCtx *domain.IdentityContext,
	agentSlug string,
	taskID string,
) (*pb.Task, error) {
	if s.rbac != nil {
		if err := s.rbac.AuthorizeA2AAgent(idCtx, agentSlug); err != nil {
			return nil, &A2AError{Code: CodeTaskNotFound, Message: "Forbidden"}
		}
	}

	agent, err := s.repo.GetA2AAgentBySlug(ctx, idCtx.OrgID, agentSlug)
	if err != nil || agent == nil {
		return nil, &A2AError{Code: CodeTaskNotFound, Message: "Agent not found"}
	}

	task, err := s.repo.GetA2ATask(ctx, taskID)
	if err != nil || task == nil {
		return nil, &A2AError{Code: CodeTaskNotFound, Message: fmt.Sprintf("Task %q not found", taskID)}
	}

	if !CheckTaskVisibility(task, idCtx, agent.TaskVisibilityMode) {
		return nil, &A2AError{Code: CodeTaskNotFound, Message: fmt.Sprintf("Task %q not found", taskID)}
	}

	return s.domainTaskToProto(ctx, task), nil
}

// ListTasks returns tasks for an agent filtered strictly by visibility mode.
func (s *RouterService) ListTasks(
	ctx context.Context,
	idCtx *domain.IdentityContext,
	agentSlug string,
	req *pb.ListTasksRequest,
) (*pb.ListTasksResponse, error) {
	if s.rbac != nil {
		if err := s.rbac.AuthorizeA2AAgent(idCtx, agentSlug); err != nil {
			return nil, &A2AError{Code: CodeTaskNotFound, Message: "Forbidden"}
		}
	}

	agent, err := s.repo.GetA2AAgentBySlug(ctx, idCtx.OrgID, agentSlug)
	if err != nil || agent == nil {
		return nil, &A2AError{Code: CodeTaskNotFound, Message: "Agent not found"}
	}

	tasks, err := s.repo.ListA2ATasks(ctx, agent.ID, idCtx.VirtualKeyID, 100)
	if err != nil {
		return nil, fmt.Errorf("a2a: list tasks: %w", err)
	}

	var visibleTasks []*pb.Task
	for _, t := range tasks {
		if CheckTaskVisibility(t, idCtx, agent.TaskVisibilityMode) {
			visibleTasks = append(visibleTasks, s.domainTaskToProto(ctx, t))
		}
	}

	return &pb.ListTasksResponse{
		Tasks: visibleTasks,
	}, nil
}

// CancelTask cancels an active task, rejecting cancellation on completed tasks.
func (s *RouterService) CancelTask(
	ctx context.Context,
	idCtx *domain.IdentityContext,
	agentSlug string,
	taskID string,
) (*pb.Task, error) {
	if s.rbac != nil {
		if err := s.rbac.AuthorizeA2AAgent(idCtx, agentSlug); err != nil {
			return nil, &A2AError{Code: CodeTaskNotFound, Message: "Forbidden"}
		}
	}

	agent, err := s.repo.GetA2AAgentBySlug(ctx, idCtx.OrgID, agentSlug)
	if err != nil || agent == nil {
		return nil, &A2AError{Code: CodeTaskNotFound, Message: "Agent not found"}
	}

	task, err := s.repo.GetA2ATask(ctx, taskID)
	if err != nil || task == nil {
		return nil, &A2AError{Code: CodeTaskNotFound, Message: fmt.Sprintf("Task %q not found", taskID)}
	}

	if !CheckTaskVisibility(task, idCtx, agent.TaskVisibilityMode) {
		return nil, &A2AError{Code: CodeTaskNotFound, Message: fmt.Sprintf("Task %q not found", taskID)}
	}

	currentState := StringToTaskState(task.State)
	if currentState == pb.TaskState_TASK_STATE_COMPLETED {
		return nil, &A2AError{
			Code:    CodeTaskAlreadyCompleted,
			Message: fmt.Sprintf("Task %q has already completed and cannot be cancelled", taskID),
		}
	}

	if err := ValidateStateTransition(currentState, pb.TaskState_TASK_STATE_CANCELED); err != nil {
		return nil, err
	}

	task.State = domain.A2ATaskStateCanceled
	task.UpdatedAt = time.Now().UTC()
	cTime := time.Now().UTC()
	task.CompletedAt = &cTime
	_ = s.repo.UpdateA2ATaskState(ctx, task.ID, task.State, task.OutputMessageJSON, task.TotalCostMicros)

	// Record cancellation event
	cancelEvent, _ := s.repo.AppendA2ATaskEvent(ctx, task.ID, "status", `{"state":"canceled"}`)
	if cancelEvent != nil {
		task.LastEventSeq = cancelEvent.EventSeq
	}

	return s.domainTaskToProto(ctx, task), nil
}

// DispatchJSONRPC handles JSON-RPC 2.0 enveloped A2A requests.
func (s *RouterService) DispatchJSONRPC(
	ctx context.Context,
	idCtx *domain.IdentityContext,
	agentSlug string,
	body []byte,
) (*JSONRPCResponse, error) {
	var rpcReq JSONRPCRequest
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.UseNumber()
	if err := dec.Decode(&rpcReq); err != nil {
		return &JSONRPCResponse{
			JSONRPC: "2.0",
			Error: &JSONRPCError{
				Code:    -32700,
				Message: fmt.Sprintf("Invalid JSON-RPC: %v", err),
			},
		}, nil
	}

	switch rpcReq.Method {
	case "tasks/send":
		var sendReq pb.SendMessageRequest
		if err := StrictProtoJSONUnmarshaler.Unmarshal(rpcReq.Params, &sendReq); err != nil {
			return &JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      rpcReq.ID,
				Error: &JSONRPCError{
					Code:    -32600,
					Message: fmt.Sprintf("Strict protobuf validation error: %v", err),
				},
			}, nil
		}
		resp, err := s.SendMessage(ctx, idCtx, agentSlug, &sendReq)
		if err != nil {
			return s.formatError(rpcReq.ID, err), nil
		}
		var outMap map[string]any
		b, _ := ProtoJSONMarshaler.Marshal(resp)
		_ = json.Unmarshal(b, &outMap)
		return &JSONRPCResponse{JSONRPC: "2.0", ID: rpcReq.ID, Result: outMap}, nil

	case "tasks/get":
		var getReq pb.GetTaskRequest
		if err := StrictProtoJSONUnmarshaler.Unmarshal(rpcReq.Params, &getReq); err != nil {
			return &JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      rpcReq.ID,
				Error: &JSONRPCError{
					Code:    -32600,
					Message: fmt.Sprintf("Strict protobuf validation error: %v", err),
				},
			}, nil
		}
		task, err := s.GetTask(ctx, idCtx, agentSlug, getReq.Id)
		if err != nil {
			return s.formatError(rpcReq.ID, err), nil
		}
		var outMap map[string]any
		b, _ := ProtoJSONMarshaler.Marshal(task)
		_ = json.Unmarshal(b, &outMap)
		return &JSONRPCResponse{JSONRPC: "2.0", ID: rpcReq.ID, Result: outMap}, nil

	case "tasks/list":
		var listReq pb.ListTasksRequest
		if len(rpcReq.Params) > 0 {
			_ = StrictProtoJSONUnmarshaler.Unmarshal(rpcReq.Params, &listReq)
		}
		listResp, err := s.ListTasks(ctx, idCtx, agentSlug, &listReq)
		if err != nil {
			return s.formatError(rpcReq.ID, err), nil
		}
		var outMap map[string]any
		b, _ := ProtoJSONMarshaler.Marshal(listResp)
		_ = json.Unmarshal(b, &outMap)
		return &JSONRPCResponse{JSONRPC: "2.0", ID: rpcReq.ID, Result: outMap}, nil

	case "tasks/cancel":
		var cancelReq pb.CancelTaskRequest
		if err := StrictProtoJSONUnmarshaler.Unmarshal(rpcReq.Params, &cancelReq); err != nil {
			return &JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      rpcReq.ID,
				Error:   &JSONRPCError{Code: -32600, Message: err.Error()},
			}, nil
		}
		task, err := s.CancelTask(ctx, idCtx, agentSlug, cancelReq.Id)
		if err != nil {
			return s.formatError(rpcReq.ID, err), nil
		}
		var outMap map[string]any
		b, _ := ProtoJSONMarshaler.Marshal(task)
		_ = json.Unmarshal(b, &outMap)
		return &JSONRPCResponse{JSONRPC: "2.0", ID: rpcReq.ID, Result: outMap}, nil

	default:
		return &JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      rpcReq.ID,
			Error: &JSONRPCError{
				Code:    -32601,
				Message: fmt.Sprintf("Method %q not supported on A2A agent route", rpcReq.Method),
			},
		}, nil
	}
}

func (s *RouterService) formatError(id any, err error) *JSONRPCResponse {
	var a2aErr *A2AError
	if errors.As(err, &a2aErr) {
		return &JSONRPCResponse{
			JSONRPC: "2.0",
			ID:      id,
			Error: &JSONRPCError{
				Code:    a2aErr.Code,
				Message: a2aErr.Message,
				Data:    a2aErr.Data,
			},
		}
	}
	return &JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error: &JSONRPCError{
			Code:    -32603,
			Message: err.Error(),
		},
	}
}

func (s *RouterService) invokeUpstreamAgent(
	ctx context.Context,
	agent *domain.A2AAgent,
	req *pb.SendMessageRequest,
) (*pb.SendMessageResponse, error) {
	reqJSON, err := ProtoJSONMarshaler.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("marshal upstream request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, agent.EndpointURL, bytes.NewReader(reqJSON))
	if err != nil {
		return nil, fmt.Errorf("create upstream request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")

	// Inject W3C distributed tracing context
	observability.InjectTraceHeaders(ctx, httpReq)

	resp, err := s.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("upstream agent call failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("upstream agent returned HTTP %d: %s", resp.StatusCode, string(b))
	}

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return nil, fmt.Errorf("read upstream response: %w", err)
	}

	var a2aResp pb.SendMessageResponse
	if err := StrictProtoJSONUnmarshaler.Unmarshal(respBody, &a2aResp); err != nil {
		return nil, fmt.Errorf("parse upstream agent response: %w", err)
	}

	return &a2aResp, nil
}

func (s *RouterService) domainTaskToProto(ctx context.Context, t *domain.A2ATask) *pb.Task {
	protoTask := &pb.Task{
		Id: t.ID,
		Status: &pb.TaskStatus{
			State: StringToTaskState(t.State),
		},
	}

	if t.InputMessageJSON != "" {
		var inMsg pb.Message
		if err := protojson.Unmarshal([]byte(t.InputMessageJSON), &inMsg); err == nil {
			protoTask.Status.Message = &inMsg
		}
	}

	return protoTask
}

func (s *RouterService) evaluateInboundMessage(ctx context.Context, orgID string, msg *pb.Message) error {
	if msg == nil {
		return nil
	}
	var textRefs []*pb.Part_Text
	var contentParts []domain.ContentPart
	for _, p := range msg.Parts {
		if tp, ok := p.Content.(*pb.Part_Text); ok && tp.Text != "" {
			textRefs = append(textRefs, tp)
			contentParts = append(contentParts, domain.ContentPart{Type: "text", Text: tp.Text})
		}
	}
	if len(textRefs) == 0 {
		return nil
	}

	chatReq := &domain.CanonicalChatRequest{
		Messages: []domain.CanonicalMessage{{
			Role:  "user",
			Parts: contentParts,
		}},
	}
	if _, err := s.guardrails.EvaluateInput(ctx, orgID, chatReq); err != nil {
		var gwErr *domain.GatewayError
		if errors.As(err, &gwErr) {
			if gwErr.StatusCode >= 500 {
				return gwErr
			}
			return &A2AError{
				Code:    CodeInvalidTaskPayload,
				Message: gwErr.Message,
			}
		}
		return &A2AError{
			Code:    CodeInvalidTaskPayload,
			Message: err.Error(),
		}
	}

	for i, tp := range textRefs {
		tp.Text = chatReq.Messages[0].Parts[i].Text
	}
	return nil
}

func (s *RouterService) sanitizeOutboundResponse(ctx context.Context, orgID string, resp *pb.SendMessageResponse) error {
	if resp == nil {
		return nil
	}
	if msg := resp.GetMessage(); msg != nil {
		if err := s.sanitizeParts(ctx, orgID, msg.Parts); err != nil {
			return err
		}
	}
	if task := resp.GetTask(); task != nil {
		if status := task.GetStatus(); status != nil && status.GetMessage() != nil {
			if err := s.sanitizeParts(ctx, orgID, status.GetMessage().Parts); err != nil {
				return err
			}
		}
		for _, histMsg := range task.GetHistory() {
			if histMsg != nil {
				if err := s.sanitizeParts(ctx, orgID, histMsg.Parts); err != nil {
					return err
				}
			}
		}
		for _, art := range task.GetArtifacts() {
			if art != nil {
				if err := s.sanitizeParts(ctx, orgID, art.Parts); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (s *RouterService) sanitizeParts(ctx context.Context, orgID string, parts []*pb.Part) error {
	for _, p := range parts {
		if p == nil {
			continue
		}
		if tp, ok := p.Content.(*pb.Part_Text); ok && tp.Text != "" {
			sanitized, _, err := s.guardrails.SanitizeTextOutput(ctx, orgID, tp.Text)
			if err != nil {
				return err
			}
			tp.Text = sanitized
		}
	}
	return nil
}
