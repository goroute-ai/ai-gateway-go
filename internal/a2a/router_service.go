package a2a

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
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
	pipeline    *guardrails.Pipeline
	instruments *observability.Instruments
}

// SetInstruments attaches OpenTelemetry metric instruments to the A2A RouterService.
func (s *RouterService) SetInstruments(inst *observability.Instruments) {
	if s != nil {
		s.instruments = inst
	}
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

// SetGuardrailPipeline attaches a unified v2 guardrail pipeline to the A2A RouterService.
func (s *RouterService) SetGuardrailPipeline(p *guardrails.Pipeline) {
	if s != nil {
		s.pipeline = p
		if s.guardrails == nil && p != nil && p.Engine() != nil {
			s.guardrails = p.Engine()
		}
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
	if idCtx == nil {
		return nil, &A2AError{
			Code:    CodeTaskNotFound,
			Message: "Forbidden",
		}
	}

	if req == nil || req.Message == nil {
		return nil, &A2AError{
			Code:    CodeInvalidTaskPayload,
			Message: "SendMessageRequest must include a valid message",
		}
	}

	// 1. RBAC check
	if s.rbac != nil {
		if err := s.rbac.AuthorizeA2AAgent(idCtx, agentSlug); err != nil {
			s.recordAudit(ctx, idCtx, "a2a.rbac.denied", "a2a_agent", agentSlug, map[string]any{
				"operation": "message/send",
				"reason":    err.Error(),
			})
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
	prc := buildA2APipelineContext(ctx, idCtx, orgID, agentSlug, req.Message.TaskId)
	if s.pipeline != nil || s.guardrails != nil {
		if err := s.evaluateInboundMessage(ctx, prc, orgID, agentSlug, req.Message); err != nil {
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

	task.TotalCostMicros += extractA2AInvocationCostMicros(upstreamResp)

	// 6b. Outbound Guardrails Sanitization on text parts
	if (s.pipeline != nil || s.guardrails != nil) && upstreamResp != nil {
		if err := s.sanitizeOutboundResponse(ctx, prc, orgID, upstreamResp); err != nil {
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

	s.recordAudit(ctx, idCtx, "a2a.task.dispatch", "a2a_task", task.ID, map[string]any{
		"agent_slug": agentSlug,
		"state":      task.State,
	})

	return upstreamResp, nil
}

// GetTask returns a task by ID, enforcing visibility isolation.
func (s *RouterService) GetTask(
	ctx context.Context,
	idCtx *domain.IdentityContext,
	agentSlug string,
	taskID string,
) (*pb.Task, error) {
	if idCtx == nil {
		return nil, &A2AError{Code: CodeTaskNotFound, Message: "Forbidden"}
	}
	if s.rbac != nil {
		if err := s.rbac.AuthorizeA2AAgent(idCtx, agentSlug); err != nil {
			s.recordAudit(ctx, idCtx, "a2a.rbac.denied", "a2a_agent", agentSlug, map[string]any{
				"operation": "tasks/get",
				"task_id":   taskID,
				"reason":    err.Error(),
			})
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
	if idCtx == nil {
		return nil, &A2AError{Code: CodeTaskNotFound, Message: "Forbidden"}
	}
	if s.rbac != nil {
		if err := s.rbac.AuthorizeA2AAgent(idCtx, agentSlug); err != nil {
			s.recordAudit(ctx, idCtx, "a2a.rbac.denied", "a2a_agent", agentSlug, map[string]any{
				"operation": "tasks/list",
				"reason":    err.Error(),
			})
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
	if idCtx == nil {
		return nil, &A2AError{Code: CodeTaskNotFound, Message: "Forbidden"}
	}
	if s.rbac != nil {
		if err := s.rbac.AuthorizeA2AAgent(idCtx, agentSlug); err != nil {
			s.recordAudit(ctx, idCtx, "a2a.rbac.denied", "a2a_agent", agentSlug, map[string]any{
				"operation": "tasks/cancel",
				"task_id":   taskID,
				"reason":    err.Error(),
			})
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
	spanCtx, agentSpan := observability.StartGenAISpan(ctx, nil, observability.GenAISpanStart{
		Operation:     "invoke_agent",
		AgentName:     agent.Slug,
		ServerAddress: agent.EndpointURL,
		OrgID:         agent.OrgID,
	})
	finishAgent := func(err error, errType string) {
		observability.FinishGenAISpan(agentSpan, observability.GenAISpanEnd{Err: err, ErrorType: errType})
		if s.instruments != nil {
			status := "ok"
			if err != nil {
				status = "error"
			}
			s.instruments.RecordA2ARequest(spanCtx, "message/send", status)
		}
	}

	reqJSON, err := ProtoJSONMarshaler.Marshal(req)
	if err != nil {
		mErr := fmt.Errorf("marshal upstream request: %w", err)
		finishAgent(mErr, "a2a_marshal_error")
		return nil, mErr
	}

	httpReq, err := http.NewRequestWithContext(spanCtx, http.MethodPost, agent.EndpointURL, bytes.NewReader(reqJSON))
	if err != nil {
		rErr := fmt.Errorf("create upstream request: %w", err)
		finishAgent(rErr, "a2a_request_error")
		return nil, rErr
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")

	// Inject W3C distributed tracing context
	observability.InjectTraceHeaders(spanCtx, httpReq)

	resp, err := s.httpClient.Do(httpReq)
	if err != nil {
		uErr := fmt.Errorf("upstream agent call failed: %w", err)
		finishAgent(uErr, "a2a_upstream_error")
		return nil, uErr
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		hErr := fmt.Errorf("upstream agent returned HTTP %d: %s", resp.StatusCode, string(b))
		finishAgent(hErr, fmt.Sprintf("http_%d", resp.StatusCode))
		return nil, hErr
	}

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		bErr := fmt.Errorf("read upstream response: %w", err)
		finishAgent(bErr, "a2a_read_error")
		return nil, bErr
	}

	var a2aResp pb.SendMessageResponse
	if err := StrictProtoJSONUnmarshaler.Unmarshal(respBody, &a2aResp); err != nil {
		pErr := fmt.Errorf("parse upstream agent response: %w", err)
		finishAgent(pErr, "a2a_parse_error")
		return nil, pErr
	}

	finishAgent(nil, "")
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

func buildA2APipelineContext(
	ctx context.Context,
	idCtx *domain.IdentityContext,
	orgID, agentSlug, taskID string,
) guardrails.PipelineRequestContext {
	prc := guardrails.PipelineRequestContext{
		OrgID:     orgID,
		RequestID: taskID,
		Model:     agentSlug,
		Metadata: map[string]any{
			"agent_slug": agentSlug,
		},
	}
	if idCtx != nil {
		if prc.OrgID == "" {
			prc.OrgID = idCtx.OrgID
		}
		prc.TeamID = idCtx.TeamID
		prc.VirtualKeyID = idCtx.VirtualKeyID
		prc.EndUserID = idCtx.UserID
		if role := strings.TrimSpace(string(idCtx.Role)); role != "" {
			prc.CallerRoles = []string{role}
		}
	}
	prc.TraceID = observability.TraceFromContext(ctx).TraceID
	return prc
}

func (s *RouterService) evaluateInboundMessage(
	ctx context.Context,
	prc guardrails.PipelineRequestContext,
	orgID, agentSlug string,
	msg *pb.Message,
) error {
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
		Model: agentSlug,
		Messages: []domain.CanonicalMessage{{
			Role:  "user",
			Parts: contentParts,
		}},
	}
	if s.pipeline != nil {
		out, err := s.pipeline.EvaluatePreCall(ctx, prc, chatReq)
		if err != nil {
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
		if out != nil && strings.TrimSpace(out.RouteTarget) != "" {
			return &A2AError{
				Code:    CodeInvalidTaskPayload,
				Message: fmt.Sprintf("agent %q invocation blocked by sensitive routing guardrail policy", agentSlug),
			}
		}
	} else if s.guardrails != nil {
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
	}

	for i, tp := range textRefs {
		tp.Text = chatReq.Messages[0].Parts[i].Text
	}
	return nil
}

func (s *RouterService) sanitizeOutboundResponse(
	ctx context.Context,
	prc guardrails.PipelineRequestContext,
	orgID string,
	resp *pb.SendMessageResponse,
) error {
	if resp == nil {
		return nil
	}
	if msg := resp.GetMessage(); msg != nil {
		if err := s.sanitizeParts(ctx, prc, orgID, msg.Parts); err != nil {
			return err
		}
	}
	if task := resp.GetTask(); task != nil {
		if status := task.GetStatus(); status != nil && status.GetMessage() != nil {
			if err := s.sanitizeParts(ctx, prc, orgID, status.GetMessage().Parts); err != nil {
				return err
			}
		}
		for _, histMsg := range task.GetHistory() {
			if histMsg != nil {
				if err := s.sanitizeParts(ctx, prc, orgID, histMsg.Parts); err != nil {
					return err
				}
			}
		}
		for _, art := range task.GetArtifacts() {
			if art != nil {
				if err := s.sanitizeParts(ctx, prc, orgID, art.Parts); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (s *RouterService) sanitizeParts(
	ctx context.Context,
	prc guardrails.PipelineRequestContext,
	orgID string,
	parts []*pb.Part,
) error {
	if s.pipeline != nil {
		var textRefs []*pb.Part_Text
		var choices []domain.CanonicalChoice
		for _, p := range parts {
			if p == nil {
				continue
			}
			if tp, ok := p.Content.(*pb.Part_Text); ok && tp.Text != "" {
				idx := len(choices)
				textRefs = append(textRefs, tp)
				choices = append(choices, domain.CanonicalChoice{
					Index:   idx,
					Message: domain.CanonicalMessage{Role: "assistant", Content: tp.Text},
				})
			}
		}
		if len(choices) == 0 {
			return nil
		}
		chatResp := &domain.CanonicalChatResponse{
			Model:   prc.Model,
			Choices: choices,
		}
		if _, err := s.pipeline.EvaluatePostCall(ctx, prc, chatResp); err != nil {
			return err
		}
		s.pipeline.EvaluateLoggingOnly(ctx, prc, &domain.CanonicalChatRequest{Model: prc.Model}, chatResp)
		for i, tp := range textRefs {
			if i < len(chatResp.Choices) {
				tp.Text = chatResp.Choices[i].Message.Content
			}
		}
		return nil
	}
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

const defaultA2AInvocationCostMicros int64 = 100

func extractA2AInvocationCostMicros(resp *pb.SendMessageResponse) int64 {
	if resp == nil {
		return defaultA2AInvocationCostMicros
	}
	if t := resp.GetTask(); t != nil && t.GetMetadata() != nil {
		if v, ok := t.GetMetadata().AsMap()["cost_micros"].(float64); ok && v > 0 {
			return int64(v)
		}
	}
	if m := resp.GetMessage(); m != nil && m.GetMetadata() != nil {
		if v, ok := m.GetMetadata().AsMap()["cost_micros"].(float64); ok && v > 0 {
			return int64(v)
		}
	}
	return defaultA2AInvocationCostMicros
}

func (s *RouterService) recordAudit(ctx context.Context, idCtx *domain.IdentityContext, action, resource, resourceID string, details map[string]any) {
	if s == nil || s.repo == nil {
		return
	}
	orgID := ""
	actorID := ""
	if idCtx != nil {
		orgID = idCtx.OrgID
		switch {
		case idCtx.VirtualKeyID != "":
			actorID = idCtx.VirtualKeyID
		case idCtx.UserID != "":
			actorID = idCtx.UserID
		default:
			actorID = idCtx.KeyPrefix
		}
	}
	_ = s.repo.RecordAuditLog(ctx, &domain.AuditLog{
		OrgID:      orgID,
		ActorID:    actorID,
		Action:     action,
		Resource:   resource,
		ResourceID: resourceID,
		Details:    details,
	})
}
