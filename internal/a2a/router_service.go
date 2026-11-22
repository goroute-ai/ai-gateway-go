package a2a

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"math"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	a2aspec "github.com/goroute-ai/ai-gateway-go/internal/a2a/spec"
	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/guardrails"
	"github.com/goroute-ai/ai-gateway-go/internal/logger"
	"github.com/goroute-ai/ai-gateway-go/internal/observability"
	"github.com/goroute-ai/ai-gateway-go/internal/ratelimit"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

const defaultA2AInvocationCostMicros int64 = 100

// SpendRecorder records durable A2A FinOps spend events (matching internal/mcp.SpendRecorder).
type SpendRecorder interface {
	Record(ctx context.Context, ev domain.SpendEvent) error
}

// RouterService orchestrates A2A v1.0 protocol message routing, state machine validation,
// durable event sequencing, FinOps accounting, Vault auth, and push notification management
// against OpenAPI-generated internal/a2a/spec models.
type RouterService struct {
	repo          storage.Repository
	vault         *auth.Vault
	rbac          *auth.RBACEngine
	netPolicy     *network.Policy
	httpClient    *http.Client
	redisFabric   *storage.RedisFabric
	signer        *GatewayCardSigner
	verifier      *UpstreamCardVerifier
	guardrails    *guardrails.Engine
	pipeline      *guardrails.Pipeline
	limiter       *ratelimit.Limiter
	spendRecorder SpendRecorder
	cfg           config.A2AConfig

	tasksDispatchedTotal  atomic.Int64
	tasksCompletedTotal   atomic.Int64
	tasksFailedTotal      atomic.Int64
	tasksCanceledTotal    atomic.Int64
	upstreamHTTPJSONTotal atomic.Int64
	upstreamJSONRPCTotal  atomic.Int64
	upstreamGRPCTotal     atomic.Int64
}

// RouterMetrics holds point-in-time A2A RouterService telemetry counters.
type RouterMetrics struct {
	TasksDispatchedTotal  int64
	TasksCompletedTotal   int64
	TasksFailedTotal      int64
	TasksCanceledTotal    int64
	UpstreamHTTPJSONTotal int64
	UpstreamJSONRPCTotal  int64
	UpstreamGRPCTotal     int64
}

// Metrics returns an immutable snapshot of A2A router execution and binding counters.
func (s *RouterService) Metrics() RouterMetrics {
	if s == nil {
		return RouterMetrics{}
	}
	return RouterMetrics{
		TasksDispatchedTotal:  s.tasksDispatchedTotal.Load(),
		TasksCompletedTotal:   s.tasksCompletedTotal.Load(),
		TasksFailedTotal:      s.tasksFailedTotal.Load(),
		TasksCanceledTotal:    s.tasksCanceledTotal.Load(),
		UpstreamHTTPJSONTotal: s.upstreamHTTPJSONTotal.Load(),
		UpstreamJSONRPCTotal:  s.upstreamJSONRPCTotal.Load(),
		UpstreamGRPCTotal:     s.upstreamGRPCTotal.Load(),
	}
}

// NewRouterService constructs an OpenAPI-first A2A RouterService.
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
		cfg: config.A2AConfig{
			Enabled:              true,
			EnableJSONRPC:        true,
			EnableHTTPJSON:       true,
			MaxTaskLifespan:      24 * time.Hour,
			StreamBufferCapacity: 256,
		},
	}
}

// SetGuardrails attaches a legacy guardrails engine.
func (s *RouterService) SetGuardrails(g *guardrails.Engine) {
	if s != nil {
		s.guardrails = g
	}
}

// SetGuardrailPipeline attaches a unified v2 guardrail pipeline.
func (s *RouterService) SetGuardrailPipeline(p *guardrails.Pipeline) {
	if s != nil {
		s.pipeline = p
		if s.guardrails == nil && p != nil && p.Engine() != nil {
			s.guardrails = p.Engine()
		}
	}
}

// SetLimiter attaches a FinOps rate/budget limiter for A2A invocations.
func (s *RouterService) SetLimiter(l *ratelimit.Limiter) {
	if s != nil {
		s.limiter = l
	}
}

// SetSpendRecorder attaches a FinOps SpendRecorder (`protocol = "a2a"`).
func (s *RouterService) SetSpendRecorder(sr SpendRecorder) {
	if s != nil {
		s.spendRecorder = sr
	}
}

// SetConfig attaches runtime A2AConfig settings.
func (s *RouterService) SetConfig(cfg config.A2AConfig) {
	if s != nil {
		s.cfg = cfg
	}
}

// Config returns the active A2AConfig.
func (s *RouterService) Config() config.A2AConfig {
	if s == nil {
		return config.A2AConfig{}
	}
	return s.cfg
}

// Repo exposes the underlying storage repository.
func (s *RouterService) Repo() storage.Repository {
	if s == nil {
		return nil
	}
	return s.repo
}

// Verifier exposes the upstream card verifier.
func (s *RouterService) Verifier() *UpstreamCardVerifier {
	if s == nil {
		return nil
	}
	return s.verifier
}

type preparedDispatch struct {
	agent       *domain.A2AAgent
	task        *domain.A2ATask
	prc         guardrails.PipelineRequestContext
	reqID       string
	settleQuota func(actualTokens int, actualCostMicros int64)
}

func (s *RouterService) prepareMessageDispatch(
	ctx context.Context,
	idCtx *domain.IdentityContext,
	agentSlug string,
	req *a2aspec.SendMessageRequest,
	operation string,
) (*preparedDispatch, error) {
	if idCtx == nil {
		return nil, ErrTaskNotFound("forbidden", "")
	}
	if req == nil || req.Message.MessageId == "" && len(req.Message.Parts) == 0 {
		return nil, ErrInvalidParams("SendMessageRequest must include a valid message with parts")
	}
	if len(req.Message.Parts) == 0 {
		return nil, ErrInvalidParams("message.parts must not be empty", a2aspec.FieldViolation{
			Field:       "message.parts",
			Description: "at least one part is required",
		})
	}

	if opts := CallOptionsFromContext(ctx); opts.Tenant != "" && idCtx.OrgID != "" && opts.Tenant != idCtx.OrgID {
		return nil, ErrTaskNotFound("forbidden", "")
	}

	if s.rbac != nil {
		if err := s.rbac.AuthorizeA2AAgent(idCtx, agentSlug); err != nil {
			s.recordAudit(ctx, idCtx, "a2a.rbac.denied", "a2a_agent", agentSlug, map[string]any{
				"operation": operation,
				"reason":    err.Error(),
			})
			return nil, ErrTaskNotFound(fmt.Sprintf("forbidden: %v", err), "")
		}
	}

	agent, err := s.repo.GetA2AAgentBySlug(ctx, idCtx.OrgID, agentSlug)
	if err != nil || agent == nil || !agent.IsActive {
		return nil, ErrTaskNotFound(fmt.Sprintf("agent %q not found or inactive", agentSlug), "")
	}
	if agent.IsKilled {
		return nil, ErrAgentKilled(fmt.Sprintf("agent %q is disabled by administrator emergency kill-switch", agentSlug))
	}

	// Validate requested & required extensions (from A2A-Extensions header + message.extensions).
	card := decodeAgentCardOrDefault(agent)
	var requestedExts []string
	requestedExts = append(requestedExts, CallOptionsFromContext(ctx).Extensions...)
	if req.Message.Extensions != nil {
		requestedExts = append(requestedExts, *req.Message.Extensions...)
	}
	if err := ValidateExtensions(requestedExts, card); err != nil {
		return nil, err
	}

	reqID := uuid.NewString()
	settleQuota := func(int, int64) {}
	if s.limiter != nil {
		settle, lErr := s.limiter.AcquireWithBudget(ctx, idCtx, 0, defaultA2AInvocationCostMicros, reqID)
		if lErr != nil {
			return nil, NormalizeA2AError(lErr)
		}
		settleQuota = settle
	}

	taskIDForLog := ""
	if req.Message.TaskId != nil {
		taskIDForLog = strings.TrimSpace(*req.Message.TaskId)
	}
	prc := buildA2APipelineContext(ctx, idCtx, idCtx.OrgID, agentSlug, taskIDForLog)
	if s.pipeline != nil || s.guardrails != nil {
		if err := s.evaluateInboundMessage(ctx, prc, idCtx.OrgID, agentSlug, &req.Message); err != nil {
			settleQuota(0, 0)
			return nil, err
		}
	}

	now := time.Now().UTC()
	var task *domain.A2ATask

	if taskIDForLog != "" {
		existingTask, err := s.repo.GetA2ATask(ctx, taskIDForLog)
		if err != nil || existingTask == nil {
			settleQuota(0, 0)
			return nil, ErrTaskNotFound(fmt.Sprintf("task %q not found", taskIDForLog), taskIDForLog)
		}
		if !CheckTaskVisibility(existingTask, agent, idCtx) {
			settleQuota(0, 0)
			return nil, ErrTaskNotFound(fmt.Sprintf("task %q not found", taskIDForLog), taskIDForLog)
		}
		if s.cfg.MaxTaskLifespan > 0 && time.Since(existingTask.CreatedAt) > s.cfg.MaxTaskLifespan {
			settleQuota(0, 0)
			return nil, ErrBudgetExceeded(fmt.Sprintf("task %q exceeded maximum lifespan (%s)", taskIDForLog, s.cfg.MaxTaskLifespan))
		}
		currentState := a2aspec.DomainToTaskState(existingTask.State)
		if err := ValidateStateTransition(currentState, a2aspec.TASKSTATEWORKING); err != nil {
			settleQuota(0, 0)
			return nil, err
		}
		if agent.MaxTaskBudgetMicros > 0 && existingTask.TotalCostMicros >= agent.MaxTaskBudgetMicros {
			settleQuota(0, 0)
			return nil, ErrBudgetExceeded(fmt.Sprintf("task %q exceeded agent budget limit (%d micros)", taskIDForLog, agent.MaxTaskBudgetMicros))
		}
		if agent.MaxTaskIterations > 0 && existingTask.LastEventSeq >= int64(agent.MaxTaskIterations) {
			settleQuota(0, 0)
			return nil, ErrBudgetExceeded(fmt.Sprintf("task %q reached maximum iteration cap (%d)", taskIDForLog, agent.MaxTaskIterations))
		}
		task = existingTask
	} else {
		if agent.MaxTaskBudgetMicros > 0 && defaultA2AInvocationCostMicros > agent.MaxTaskBudgetMicros {
			settleQuota(0, 0)
			return nil, ErrBudgetExceeded(fmt.Sprintf("agent budget limit (%d micros) is below invocation floor", agent.MaxTaskBudgetMicros))
		}
		if agent.MaxTaskIterations < 0 {
			settleQuota(0, 0)
			return nil, ErrBudgetExceeded("agent iteration limit is exhausted")
		}
		contextID := "ctx_" + uuid.NewString()
		if req.Message.ContextId != nil && strings.TrimSpace(*req.Message.ContextId) != "" {
			contextID = strings.TrimSpace(*req.Message.ContextId)
		}
		inputMsgJSON, _ := json.Marshal(req.Message)
		history := []a2aspec.Message{req.Message}
		historyJSON, _ := json.Marshal(history)

		task = &domain.A2ATask{
			ID:               "task_" + uuid.NewString(),
			AgentID:          agent.ID,
			OrgID:            agent.OrgID,
			TeamID:           idCtx.TeamID,
			VirtualKeyID:     idCtx.VirtualKeyID,
			UserID:           idCtx.UserID,
			ContextID:        contextID,
			State:            domain.A2ATaskStateSubmitted,
			LastEventSeq:     0,
			InputMessageJSON: string(inputMsgJSON),
			HistoryJSON:      string(historyJSON),
			CreatedAt:        now,
			UpdatedAt:        now,
		}
		if err := s.repo.CreateA2ATask(ctx, task); err != nil {
			settleQuota(0, 0)
			return nil, ErrInternal(fmt.Sprintf("store task: %v", err))
		}
	}

	// Register inline push notification configuration if supplied in SendMessageConfiguration.
	if req.Configuration != nil && req.Configuration.TaskPushNotificationConfig != nil {
		if err := s.persistPushConfig(ctx, task, req.Configuration.TaskPushNotificationConfig); err != nil {
			settleQuota(0, 0)
			return nil, err
		}
	}

	// Record initial user message event and move task to working state.
	msgForEvent := req.Message
	msgForEvent.TaskId = &task.ID
	if msgForEvent.ContextId == nil || *msgForEvent.ContextId == "" {
		cid := task.ContextID
		msgForEvent.ContextId = &cid
	}
	task.State = domain.A2ATaskStateWorking
	task.StatusTimestamp = &now
	_ = s.repo.UpdateA2ATask(ctx, task, 0)

	initialStreamBytes, _ := json.Marshal(&a2aspec.StreamResponse{Message: &msgForEvent})
	if ev, evErr := s.repo.AppendA2ATaskEvent(ctx, task.ID, "message", string(initialStreamBytes)); evErr == nil && ev != nil {
		task.LastEventSeq = ev.EventSeq
	}
	s.tasksDispatchedTotal.Add(1)

	return &preparedDispatch{
		agent:       agent,
		task:        task,
		prc:         prc,
		reqID:       reqID,
		settleQuota: settleQuota,
	}, nil
}

// SendMessage dispatches a synchronous or returnImmediately A2A v1.0 SendMessage request.
func (s *RouterService) SendMessage(
	ctx context.Context,
	idCtx *domain.IdentityContext,
	agentSlug string,
	req *a2aspec.SendMessageRequest,
) (*a2aspec.SendMessageResponse, error) {
	prep, err := s.prepareMessageDispatch(ctx, idCtx, agentSlug, req, "SendMessage")
	if err != nil {
		return nil, err
	}

	// Non-blocking returnImmediately support per SendMessageConfiguration:
	if req.Configuration != nil && req.Configuration.ReturnImmediately != nil && *req.Configuration.ReturnImmediately {
		bgReq := cloneSendMessageRequest(req)
		go func() {
			bgCtx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			_, _ = s.completeUpstreamSync(bgCtx, idCtx, agentSlug, prep, bgReq)
		}()
		histLen := historyLengthFromConfig(req.Configuration)
		return a2aspec.NewSendMessageResponseTask(s.domainTaskToSpec(prep.task, histLen, true)), nil
	}

	return s.completeUpstreamSync(ctx, idCtx, agentSlug, prep, req)
}

func (s *RouterService) completeUpstreamSync(
	ctx context.Context,
	idCtx *domain.IdentityContext,
	agentSlug string,
	prep *preparedDispatch,
	req *a2aspec.SendMessageRequest,
) (*a2aspec.SendMessageResponse, error) {
	upstreamResp, err := s.invokeUpstreamAgentSync(ctx, prep.agent, req)
	if err != nil {
		prep.settleQuota(0, 0)
		s.failTaskAndEmitEvent(ctx, prep.task, err.Error())
		return nil, err
	}

	costDelta := extractA2AInvocationCostMicros(upstreamResp)
	defer func() {
		prep.settleQuota(0, costDelta)
	}()

	// Enforce post-invocation budget limit if exceeded.
	if prep.agent.MaxTaskBudgetMicros > 0 && prep.task.TotalCostMicros+costDelta > prep.agent.MaxTaskBudgetMicros {
		s.failTaskAndEmitEvent(ctx, prep.task, "task budget exceeded after invocation")
		return nil, ErrBudgetExceeded(fmt.Sprintf("task %q exceeded agent budget limit (%d micros)", prep.task.ID, prep.agent.MaxTaskBudgetMicros))
	}

	if (s.pipeline != nil || s.guardrails != nil) && upstreamResp != nil {
		if gErr := s.sanitizeOutboundResponse(ctx, prep.prc, idCtx.OrgID, upstreamResp); gErr != nil {
			s.failTaskAndEmitEvent(ctx, prep.task, gErr.Error())
			return nil, gErr
		}
	}

	if err := s.applyAndPersistUpstreamResponse(ctx, prep.task, upstreamResp, costDelta); err != nil {
		return nil, err
	}

	s.recordFinOpsSpend(ctx, idCtx, agentSlug, prep.reqID, costDelta)
	s.recordAudit(ctx, idCtx, "a2a.task.dispatch", "a2a_task", prep.task.ID, map[string]any{
		"agent_slug":  agentSlug,
		"state":       prep.task.State,
		"cost_micros": costDelta,
	})

	if upstreamResp.Task != nil && req.Configuration != nil && req.Configuration.HistoryLength != nil {
		upstreamResp.Task = applyHistoryLength(upstreamResp.Task, req.Configuration.HistoryLength)
		upstreamResp.ClearUnion()
	}
	return upstreamResp, nil
}

// SendStreamingMessage executes a streaming message turn (`POST /message:stream`), emitting
// real-time OpenAPI StreamResponse frames as they arrive (or converting sync fallback responses).
func (s *RouterService) SendStreamingMessage(
	ctx context.Context,
	idCtx *domain.IdentityContext,
	agentSlug string,
	req *a2aspec.SendMessageRequest,
	emit func(*a2aspec.StreamResponse, int64) error,
) error {
	prep, err := s.prepareMessageDispatch(ctx, idCtx, agentSlug, req, "SendStreamingMessage")
	if err != nil {
		return err
	}

	var totalCost int64
	handledStream, err := s.invokeUpstreamAgentStream(ctx, prep.agent, req, func(frame *a2aspec.StreamResponse) error {
		if frame == nil {
			return nil
		}
		if s.pipeline != nil || s.guardrails != nil {
			if gErr := s.sanitizeStreamResponse(ctx, prep.prc, idCtx.OrgID, frame); gErr != nil {
				return gErr
			}
		}
		seq, pErr := s.persistStreamFrame(ctx, prep.task, frame)
		if pErr != nil {
			return pErr
		}
		totalCost = max(totalCost, extractStreamFrameCost(frame))
		if emit != nil {
			return emit(frame, seq)
		}
		return nil
	})
	if err != nil {
		prep.settleQuota(0, 0)
		s.failTaskAndEmitEvent(ctx, prep.task, err.Error())
		return err
	}

	if handledStream {
		if totalCost <= 0 {
			totalCost = defaultA2AInvocationCostMicros
		}
		_ = s.repo.UpdateA2ATask(ctx, prep.task, totalCost)
		prep.settleQuota(0, totalCost)
		s.recordFinOpsSpend(ctx, idCtx, agentSlug, prep.reqID, totalCost)
		return nil
	}

	// Upstream returned a synchronous SendMessageResponse JSON payload instead of SSE.
	resp, err := s.completeUpstreamSync(ctx, idCtx, agentSlug, prep, req)
	if err != nil {
		return err
	}
	if emit != nil {
		frame := &a2aspec.StreamResponse{}
		if resp.Task != nil {
			frame.Task = resp.Task
		} else if resp.Message != nil {
			frame.Message = resp.Message
		}
		return emit(frame, prep.task.LastEventSeq)
	}
	return nil
}

// GetTask retrieves a task by ID, enforcing RBAC, agent isolation (`C1`), and visibility policy.
func (s *RouterService) GetTask(
	ctx context.Context,
	idCtx *domain.IdentityContext,
	agentSlug string,
	taskID string,
	historyLength *int32,
) (*a2aspec.Task, error) {
	if idCtx == nil {
		return nil, ErrTaskNotFound("forbidden", taskID)
	}
	if s.rbac != nil {
		if err := s.rbac.AuthorizeA2AAgent(idCtx, agentSlug); err != nil {
			s.recordAudit(ctx, idCtx, "a2a.rbac.denied", "a2a_agent", agentSlug, map[string]any{
				"operation": "GetTask",
				"task_id":   taskID,
				"reason":    err.Error(),
			})
			return nil, ErrTaskNotFound("forbidden", taskID)
		}
	}

	agent, err := s.repo.GetA2AAgentBySlug(ctx, idCtx.OrgID, agentSlug)
	if err != nil || agent == nil {
		return nil, ErrTaskNotFound("agent not found", taskID)
	}

	task, err := s.repo.GetA2ATask(ctx, taskID)
	if err != nil || task == nil {
		return nil, ErrTaskNotFound(fmt.Sprintf("task %q not found", taskID), taskID)
	}

	if !CheckTaskVisibility(task, agent, idCtx) {
		return nil, ErrTaskNotFound(fmt.Sprintf("task %q not found", taskID), taskID)
	}

	return s.domainTaskToSpec(task, historyLength, true), nil
}

// ListTasks returns filtered, paginated tasks visible to the caller across all visibility modes (`H4`, `M1`).
func (s *RouterService) ListTasks(
	ctx context.Context,
	idCtx *domain.IdentityContext,
	agentSlug string,
	req *a2aspec.ListTasksRequest,
) (*a2aspec.ListTasksResponse, error) {
	if idCtx == nil {
		return nil, ErrTaskNotFound("forbidden", "")
	}
	if s.rbac != nil {
		if err := s.rbac.AuthorizeA2AAgent(idCtx, agentSlug); err != nil {
			s.recordAudit(ctx, idCtx, "a2a.rbac.denied", "a2a_agent", agentSlug, map[string]any{
				"operation": "ListTasks",
				"reason":    err.Error(),
			})
			return nil, ErrTaskNotFound("forbidden", "")
		}
	}

	agent, err := s.repo.GetA2AAgentBySlug(ctx, idCtx.OrgID, agentSlug)
	if err != nil || agent == nil {
		return nil, ErrTaskNotFound("agent not found", "")
	}

	pageSize := 50
	offset := 0
	var historyLen *int32
	includeArtifacts := false
	filter := domain.A2ATaskListFilter{
		AgentID: agent.ID,
		OrgID:   idCtx.OrgID,
	}
	// Only push virtual_key_id filter into SQL when mode is strictly key_strict (fixes H4 / AUTH-11).
	if agent.TaskVisibilityMode == "" || agent.TaskVisibilityMode == domain.TaskVisibilityKeyStrict {
		filter.VirtualKeyID = idCtx.VirtualKeyID
	}

	if req != nil {
		if req.ContextId != nil {
			filter.ContextID = strings.TrimSpace(*req.ContextId)
		}
		if req.Status != nil && *req.Status != a2aspec.TASKSTATEUNSPECIFIED {
			filter.State = a2aspec.TaskStateToDomain(*req.Status)
		}
		if req.StatusTimestampAfter != nil {
			t := *req.StatusTimestampAfter
			filter.UpdatedAfter = &t
		}
		if req.PageSize != nil && *req.PageSize > 0 {
			pageSize = min(int(*req.PageSize), 100)
		}
		if req.PageToken != nil && *req.PageToken != "" {
			if parsedOffset, err := decodePageToken(*req.PageToken); err == nil && parsedOffset >= 0 {
				offset = parsedOffset
			} else {
				return nil, ErrInvalidParams("invalid pageToken")
			}
		}
		if req.HistoryLength != nil {
			historyLen = req.HistoryLength
		}
		if req.IncludeArtifacts != nil {
			includeArtifacts = *req.IncludeArtifacts
		}
	}

	// Fetch candidate set (if non-key_strict mode, filter visibility cleanly before pagination).
	if filter.VirtualKeyID != "" {
		filter.Limit = pageSize
		filter.Offset = offset
		tasks, total, err := s.repo.ListA2ATasks(ctx, filter)
		if err != nil {
			return nil, ErrInternal(fmt.Sprintf("list tasks: %v", err))
		}
		outTasks := make([]a2aspec.Task, 0, len(tasks))
		for _, t := range tasks {
			if CheckTaskVisibility(t, agent, idCtx) {
				outTasks = append(outTasks, *s.domainTaskToSpec(t, historyLen, includeArtifacts))
			}
		}
		nextToken := ""
		if offset+len(outTasks) < total {
			nextToken = encodePageToken(offset + len(outTasks))
		}
		return &a2aspec.ListTasksResponse{
			Tasks:         outTasks,
			NextPageToken: nextToken,
			PageSize:      clampInt32(pageSize),
			TotalSize:     clampInt32(total),
		}, nil
	}

	// For user_strict / team / org_admin: filter strictly by CheckTaskVisibility then paginate accurately.
	allCandidates, _, err := s.repo.ListA2ATasks(ctx, filter)
	if err != nil {
		return nil, ErrInternal(fmt.Sprintf("list tasks: %v", err))
	}
	visible := make([]*domain.A2ATask, 0, len(allCandidates))
	for _, t := range allCandidates {
		if CheckTaskVisibility(t, agent, idCtx) {
			visible = append(visible, t)
		}
	}
	total := len(visible)
	start := min(offset, total)
	end := min(start+pageSize, total)
	pageSlice := visible[start:end]

	outTasks := make([]a2aspec.Task, 0, len(pageSlice))
	for _, t := range pageSlice {
		outTasks = append(outTasks, *s.domainTaskToSpec(t, historyLen, includeArtifacts))
	}
	nextToken := ""
	if end < total {
		nextToken = encodePageToken(end)
	}
	return &a2aspec.ListTasksResponse{
		Tasks:         outTasks,
		NextPageToken: nextToken,
		PageSize:      clampInt32(pageSize),
		TotalSize:     clampInt32(total),
	}, nil
}

func clampInt32(n int) int32 {
	if n > math.MaxInt32 {
		return math.MaxInt32
	}
	if n < math.MinInt32 {
		return math.MinInt32
	}
	return int32(n)
}

// CancelTask cancels an active task, forwarding best-effort cancellation upstream and recording a final event.
func (s *RouterService) CancelTask(
	ctx context.Context,
	idCtx *domain.IdentityContext,
	agentSlug string,
	taskID string,
) (*a2aspec.Task, error) {
	if idCtx == nil {
		return nil, ErrTaskNotFound("forbidden", taskID)
	}
	if s.rbac != nil {
		if err := s.rbac.AuthorizeA2AAgent(idCtx, agentSlug); err != nil {
			s.recordAudit(ctx, idCtx, "a2a.rbac.denied", "a2a_agent", agentSlug, map[string]any{
				"operation": "CancelTask",
				"task_id":   taskID,
				"reason":    err.Error(),
			})
			return nil, ErrTaskNotFound("forbidden", taskID)
		}
	}

	agent, err := s.repo.GetA2AAgentBySlug(ctx, idCtx.OrgID, agentSlug)
	if err != nil || agent == nil {
		return nil, ErrTaskNotFound("agent not found", taskID)
	}

	task, err := s.repo.GetA2ATask(ctx, taskID)
	if err != nil || task == nil {
		return nil, ErrTaskNotFound(fmt.Sprintf("task %q not found", taskID), taskID)
	}

	if !CheckTaskVisibility(task, agent, idCtx) {
		return nil, ErrTaskNotFound(fmt.Sprintf("task %q not found", taskID), taskID)
	}

	currentState := a2aspec.DomainToTaskState(task.State)
	if a2aspec.IsTerminalTaskState(currentState) {
		return nil, ErrTaskNotCancelable(
			fmt.Sprintf("task %q is already in terminal state %s and cannot be canceled", taskID, currentState),
			taskID,
		)
	}

	// Best-effort upstream cancellation when upstream task ID is known.
	if task.ClientTaskID != "" && agent.EndpointURL != "" {
		s.cancelUpstreamTask(ctx, agent, task.ClientTaskID)
	}

	now := time.Now().UTC()
	task.State = domain.A2ATaskStateCanceled
	task.StatusTimestamp = &now
	task.CompletedAt = &now
	task.UpdatedAt = now
	if err := s.repo.UpdateA2ATask(ctx, task, 0); err != nil {
		return nil, ErrInternal(fmt.Sprintf("cancel task: %v", err))
	}
	s.tasksCanceledTotal.Add(1)

	cancelStatusEv := &a2aspec.StreamResponse{
		StatusUpdate: &a2aspec.TaskStatusUpdateEvent{
			TaskId:    task.ID,
			ContextId: task.ContextID,
			Status: a2aspec.TaskStatus{
				State:     a2aspec.TASKSTATECANCELED,
				Timestamp: &now,
			},
		},
	}
	evBytes, _ := json.Marshal(cancelStatusEv)
	if cancelEv, _ := s.repo.AppendA2ATaskEvent(ctx, task.ID, "status", string(evBytes)); cancelEv != nil {
		task.LastEventSeq = cancelEv.EventSeq
	}

	return s.domainTaskToSpec(task, nil, true), nil
}

// CreateTaskPushNotificationConfig registers a push webhook configuration on an authorized task.
func (s *RouterService) CreateTaskPushNotificationConfig(
	ctx context.Context,
	idCtx *domain.IdentityContext,
	agentSlug string,
	taskID string,
	cfg *a2aspec.TaskPushNotificationConfig,
) (*a2aspec.TaskPushNotificationConfig, error) {
	if cfg == nil {
		return nil, ErrInvalidParams("push notification config is required")
	}
	if taskID == "" && cfg.TaskId != nil {
		taskID = strings.TrimSpace(*cfg.TaskId)
	}
	if taskID == "" {
		return nil, ErrInvalidParams("taskId is required")
	}

	agent, task, err := s.authorizeTaskAccess(ctx, idCtx, agentSlug, taskID, "CreateTaskPushNotificationConfig")
	if err != nil {
		return nil, err
	}
	_ = agent

	domainCfg, err := s.buildDomainPushConfig(task, cfg)
	if err != nil {
		return nil, err
	}
	if err := s.repo.SetA2APushNotificationConfig(ctx, domainCfg); err != nil {
		return nil, ErrInternal(fmt.Sprintf("store push config: %v", err))
	}
	return domainPushConfigToSpec(domainCfg), nil
}

// GetTaskPushNotificationConfig retrieves a registered push webhook configuration.
func (s *RouterService) GetTaskPushNotificationConfig(
	ctx context.Context,
	idCtx *domain.IdentityContext,
	agentSlug string,
	taskID string,
	configID string,
) (*a2aspec.TaskPushNotificationConfig, error) {
	if taskID == "" || configID == "" {
		return nil, ErrInvalidParams("taskId and id are required")
	}
	if _, _, err := s.authorizeTaskAccess(ctx, idCtx, agentSlug, taskID, "GetTaskPushNotificationConfig"); err != nil {
		return nil, err
	}
	cfg, err := s.repo.GetA2APushNotificationConfig(ctx, taskID, configID)
	if err != nil || cfg == nil {
		return nil, ErrTaskNotFound(fmt.Sprintf("push notification config %q not found", configID), taskID)
	}
	return domainPushConfigToSpec(cfg), nil
}

// ListTaskPushNotificationConfigs lists all push webhook configurations for a task.
func (s *RouterService) ListTaskPushNotificationConfigs(
	ctx context.Context,
	idCtx *domain.IdentityContext,
	agentSlug string,
	taskID string,
	pageSize *int32,
	pageToken *string,
) (*a2aspec.ListTaskPushNotificationConfigsResponse, error) {
	if taskID == "" {
		return nil, ErrInvalidParams("taskId is required")
	}
	if _, _, err := s.authorizeTaskAccess(ctx, idCtx, agentSlug, taskID, "ListTaskPushNotificationConfigs"); err != nil {
		return nil, err
	}

	limit := 50
	offset := 0
	if pageSize != nil && *pageSize > 0 {
		limit = min(int(*pageSize), 100)
	}
	if pageToken != nil && *pageToken != "" {
		parsed, err := decodePageToken(*pageToken)
		if err != nil || parsed < 0 {
			return nil, ErrInvalidParams("invalid pageToken")
		}
		offset = parsed
	}

	cfgs, total, err := s.repo.ListA2APushNotificationConfigs(ctx, taskID, limit, offset)
	if err != nil {
		return nil, ErrInternal(fmt.Sprintf("list push configs: %v", err))
	}
	specCfgs := make([]a2aspec.TaskPushNotificationConfig, 0, len(cfgs))
	for _, c := range cfgs {
		specCfgs = append(specCfgs, *domainPushConfigToSpec(c))
	}
	var nextTok *string
	if offset+len(specCfgs) < total {
		t := encodePageToken(offset + len(specCfgs))
		nextTok = &t
	}
	return &a2aspec.ListTaskPushNotificationConfigsResponse{
		Configs:       &specCfgs,
		NextPageToken: nextTok,
	}, nil
}

// DeleteTaskPushNotificationConfig deletes a registered push webhook configuration.
func (s *RouterService) DeleteTaskPushNotificationConfig(
	ctx context.Context,
	idCtx *domain.IdentityContext,
	agentSlug string,
	taskID string,
	configID string,
) error {
	if taskID == "" || configID == "" {
		return ErrInvalidParams("taskId and id are required")
	}
	if _, _, err := s.authorizeTaskAccess(ctx, idCtx, agentSlug, taskID, "DeleteTaskPushNotificationConfig"); err != nil {
		return err
	}
	if err := s.repo.DeleteA2APushNotificationConfig(ctx, taskID, configID); err != nil {
		return ErrTaskNotFound(fmt.Sprintf("push notification config %q not found", configID), taskID)
	}
	return nil
}

// GetExtendedAgentCard returns the authenticated extended AgentCard when configured for an agent.
func (s *RouterService) GetExtendedAgentCard(
	ctx context.Context,
	idCtx *domain.IdentityContext,
	agentSlug string,
	gatewayBaseURL string,
) (*a2aspec.AgentCard, error) {
	if idCtx == nil {
		return nil, ErrTaskNotFound("forbidden", "")
	}
	if s.rbac != nil {
		if err := s.rbac.AuthorizeA2AAgent(idCtx, agentSlug); err != nil {
			s.recordAudit(ctx, idCtx, "a2a.rbac.denied", "a2a_agent", agentSlug, map[string]any{
				"operation": "GetExtendedAgentCard",
				"reason":    err.Error(),
			})
			return nil, ErrTaskNotFound("forbidden", "")
		}
	}

	agent, err := s.repo.GetA2AAgentBySlug(ctx, idCtx.OrgID, agentSlug)
	if err != nil || agent == nil || !agent.IsActive {
		return nil, ErrTaskNotFound(fmt.Sprintf("agent %q not found", agentSlug), "")
	}
	if strings.TrimSpace(agent.ExtendedAgentCardJSON) == "" {
		return nil, ErrExtendedAgentCardNotConfigured(fmt.Sprintf("agent %q does not configure an extended agent card", agentSlug))
	}

	var card a2aspec.AgentCard
	if err := json.Unmarshal([]byte(agent.ExtendedAgentCardJSON), &card); err != nil {
		return nil, ErrInternal(fmt.Sprintf("invalid extended_agent_card_json: %v", err))
	}
	if card.DefaultInputModes == nil {
		card.DefaultInputModes = []string{"text/plain"}
	}
	if card.DefaultOutputModes == nil {
		card.DefaultOutputModes = []string{"text/plain"}
	}
	if card.Skills == nil {
		card.Skills = []a2aspec.AgentSkill{}
	}

	if s.signer == nil {
		return &card, nil
	}
	signed, _, err := s.signer.RewriteAndSignAgentCard(&card, gatewayBaseURL, agent.Slug)
	if err != nil {
		return nil, ErrInternal(fmt.Sprintf("sign extended card: %v", err))
	}
	return signed, nil
}

func (s *RouterService) authorizeTaskAccess(
	ctx context.Context,
	idCtx *domain.IdentityContext,
	agentSlug string,
	taskID string,
	operation string,
) (*domain.A2AAgent, *domain.A2ATask, error) {
	if idCtx == nil {
		return nil, nil, ErrTaskNotFound("forbidden", taskID)
	}
	if agentSlug != "" && s.rbac != nil {
		if err := s.rbac.AuthorizeA2AAgent(idCtx, agentSlug); err != nil {
			s.recordAudit(ctx, idCtx, "a2a.rbac.denied", "a2a_agent", agentSlug, map[string]any{
				"operation": operation,
				"task_id":   taskID,
				"reason":    err.Error(),
			})
			return nil, nil, ErrTaskNotFound("forbidden", taskID)
		}
	}

	task, err := s.repo.GetA2ATask(ctx, taskID)
	if err != nil || task == nil {
		return nil, nil, ErrTaskNotFound(fmt.Sprintf("task %q not found", taskID), taskID)
	}

	var agent *domain.A2AAgent
	if agentSlug != "" {
		agent, err = s.repo.GetA2AAgentBySlug(ctx, idCtx.OrgID, agentSlug)
	} else {
		agent, err = s.repo.GetA2AAgent(ctx, task.AgentID)
	}
	if err != nil || agent == nil {
		return nil, nil, ErrTaskNotFound(fmt.Sprintf("task %q not found", taskID), taskID)
	}

	if agentSlug == "" && s.rbac != nil {
		if err := s.rbac.AuthorizeA2AAgent(idCtx, agent.Slug); err != nil {
			return nil, nil, ErrTaskNotFound("forbidden", taskID)
		}
	}

	if !CheckTaskVisibility(task, agent, idCtx) {
		return nil, nil, ErrTaskNotFound(fmt.Sprintf("task %q not found", taskID), taskID)
	}
	return agent, task, nil
}

func (s *RouterService) persistPushConfig(ctx context.Context, task *domain.A2ATask, cfg *a2aspec.TaskPushNotificationConfig) error {
	domainCfg, err := s.buildDomainPushConfig(task, cfg)
	if err != nil {
		return err
	}
	if err := s.repo.SetA2APushNotificationConfig(ctx, domainCfg); err != nil {
		return ErrInternal(fmt.Sprintf("store push config: %v", err))
	}
	return nil
}

func (s *RouterService) buildDomainPushConfig(task *domain.A2ATask, cfg *a2aspec.TaskPushNotificationConfig) (*domain.A2APushNotificationConfig, error) {
	rawURL := strings.TrimSpace(cfg.Url)
	if rawURL == "" {
		return nil, ErrInvalidParams("push notification url is required")
	}
	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		return nil, ErrInvalidParams(fmt.Sprintf("invalid push notification url %q: %v", rawURL, err))
	}
	if s.netPolicy != nil {
		if err := s.netPolicy.ValidateURL(parsedURL); err != nil {
			return nil, ErrInvalidParams(fmt.Sprintf("push notification url blocked by SSRF policy: %v", err))
		}
	}

	id := "push_cfg_" + uuid.NewString()
	if cfg.Id != nil && strings.TrimSpace(*cfg.Id) != "" {
		id = strings.TrimSpace(*cfg.Id)
	}
	tok := ""
	if cfg.Token != nil {
		tok = strings.TrimSpace(*cfg.Token)
	}
	tenant := task.OrgID
	if cfg.Tenant != nil && strings.TrimSpace(*cfg.Tenant) != "" {
		tenant = strings.TrimSpace(*cfg.Tenant)
	}

	out := &domain.A2APushNotificationConfig{
		ID:        id,
		TaskID:    task.ID,
		Tenant:    tenant,
		TargetURL: strings.TrimSpace(cfg.Url),
		Token:     tok,
	}

	if cfg.Authentication != nil {
		out.AuthScheme = strings.TrimSpace(cfg.Authentication.Scheme)
		if cfg.Authentication.Credentials != nil && strings.TrimSpace(*cfg.Authentication.Credentials) != "" {
			plainCreds := strings.TrimSpace(*cfg.Authentication.Credentials)
			if s.vault != nil {
				cipherHex, dekHex, err := s.vault.EncryptString(plainCreds)
				if err != nil {
					return nil, ErrInternal(fmt.Sprintf("encrypt push notification credentials: %v", err))
				}
				out.EncryptedAuthCreds = cipherHex
				out.EncryptedAuthDEK = dekHex
			} else {
				out.AuthToken = plainCreds
			}
		}
	}
	return out, nil
}

func domainPushConfigToSpec(cfg *domain.A2APushNotificationConfig) *a2aspec.TaskPushNotificationConfig {
	id := cfg.ID
	taskID := cfg.TaskID
	out := &a2aspec.TaskPushNotificationConfig{
		Id:     &id,
		TaskId: &taskID,
		Url:    cfg.TargetURL,
	}
	if cfg.Tenant != "" {
		t := cfg.Tenant
		out.Tenant = &t
	}
	if cfg.AuthScheme != "" {
		out.Authentication = &a2aspec.AuthenticationInfo{
			Scheme: cfg.AuthScheme,
		}
	}
	return out
}

func (s *RouterService) applyUpstreamAuth(agent *domain.A2AAgent, httpReq *http.Request) error {
	if agent == nil || httpReq == nil {
		return nil
	}
	headerName := strings.TrimSpace(agent.AuthHeaderName)
	if headerName == "" {
		headerName = "Authorization"
	}

	switch strings.ToLower(strings.TrimSpace(agent.AuthType)) {
	case "", "none":
		return nil
	case "static":
		if agent.EncryptedAuthSecret == "" || agent.EncryptedAuthDEK == "" {
			return nil
		}
		if s.vault == nil {
			return ErrInternal("vault not configured to decrypt upstream agent secret")
		}
		secret, err := s.vault.DecryptString(agent.EncryptedAuthSecret, agent.EncryptedAuthDEK)
		if err != nil {
			return ErrInternal(fmt.Sprintf("decrypt upstream agent auth secret: %v", err))
		}
		secret = strings.TrimSpace(secret)
		if secret == "" {
			return nil
		}
		if strings.EqualFold(headerName, "Authorization") && !strings.Contains(secret, " ") {
			httpReq.Header.Set("Authorization", "Bearer "+secret)
		} else {
			httpReq.Header.Set(headerName, secret)
		}
		return nil
	case "vault_jwt":
		if s.signer == nil {
			return ErrInternal("signer not configured for vault_jwt upstream authentication")
		}
		jwtStr, err := s.signer.MintVaultJWT(agent.OrgID, agent.Slug)
		if err != nil {
			return ErrInternal(fmt.Sprintf("mint vault_jwt assertion: %v", err))
		}
		httpReq.Header.Set(headerName, "Bearer "+jwtStr)
		return nil
	default:
		return ErrInvalidParams(fmt.Sprintf("unsupported upstream auth_type %q", agent.AuthType))
	}
}

func resolveUpstreamActionURL(baseURL string, suffix string) string {
	trimmed := strings.TrimRight(strings.TrimSpace(baseURL), "/")
	if suffix == "" {
		return trimmed
	}
	parsed, err := url.Parse(trimmed)
	if err == nil && (parsed.Path == "" || parsed.Path == "/" || strings.HasSuffix(parsed.Path, "/a2a/v1")) {
		return trimmed + suffix
	}
	// If registered endpoint_url already points to a concrete endpoint or mock root, post directly unless standard suffix is expected.
	if strings.HasSuffix(trimmed, ":send") || strings.HasSuffix(trimmed, ":stream") {
		if suffix == ":stream" && strings.HasSuffix(trimmed, ":send") {
			return strings.TrimSuffix(trimmed, ":send") + ":stream"
		}
		return trimmed
	}
	if suffix == "/message:send" {
		return trimmed
	}
	return trimmed + suffix
}

func (s *RouterService) invokeUpstreamAgentSync(
	ctx context.Context,
	agent *domain.A2AAgent,
	req *a2aspec.SendMessageRequest,
) (*a2aspec.SendMessageResponse, error) {
	if strings.EqualFold(agent.ProtocolBinding, domain.A2AProtocolBindingGRPC) {
		s.upstreamGRPCTotal.Add(1)
		return s.invokeUpstreamGRPCSync(ctx, agent, req)
	}

	reqJSON, err := json.Marshal(req)
	if err != nil {
		return nil, ErrInternal(fmt.Sprintf("marshal upstream request: %v", err))
	}

	targetURL := agent.EndpointURL
	var bodyBytes []byte
	if strings.EqualFold(agent.ProtocolBinding, domain.A2AProtocolBindingJSONRPC) {
		s.upstreamJSONRPCTotal.Add(1)
		rpcReq := map[string]any{
			"jsonrpc": "2.0",
			"id":      uuid.NewString(),
			"method":  string(a2aspec.SendMessage),
			"params":  json.RawMessage(reqJSON),
		}
		bodyBytes, _ = json.Marshal(rpcReq)
	} else {
		s.upstreamHTTPJSONTotal.Add(1)
		targetURL = resolveUpstreamActionURL(agent.EndpointURL, "/message:send")
		bodyBytes = reqJSON
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, ErrInternal(fmt.Sprintf("create upstream request: %v", err))
	}
	httpReq.Header.Set("Content-Type", MediaTypeA2AJSON)
	httpReq.Header.Set("Accept", MediaTypeA2AJSON+", "+MediaTypeJSON)
	httpReq.Header.Set(HeaderA2AVersion, a2aspec.SupportedA2AVersion)
	if opts := CallOptionsFromContext(ctx); len(opts.Extensions) > 0 {
		httpReq.Header.Set(HeaderA2AExtensions, strings.Join(opts.Extensions, ", "))
	}

	if err := s.applyUpstreamAuth(agent, httpReq); err != nil {
		return nil, err
	}
	observability.InjectTraceHeaders(ctx, httpReq)

	resp, err := s.httpClient.Do(httpReq)
	if err != nil {
		return nil, ErrInvalidAgentResponse(fmt.Sprintf("upstream agent call failed: %v", err))
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 10*1024*1024))
	if err != nil {
		return nil, ErrInvalidAgentResponse(fmt.Sprintf("read upstream response: %v", err))
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, ErrInvalidAgentResponse(fmt.Sprintf("upstream agent returned HTTP %d", resp.StatusCode))
	}

	if strings.EqualFold(agent.ProtocolBinding, domain.A2AProtocolBindingJSONRPC) {
		var rpcResp JSONRPCResponse
		if err := json.Unmarshal(respBody, &rpcResp); err != nil {
			return nil, ErrInvalidAgentResponse(fmt.Sprintf("parse upstream JSON-RPC response: %v", err))
		}
		if rpcResp.Error != nil {
			return nil, ErrInvalidAgentResponse(fmt.Sprintf("upstream JSON-RPC error %v: %v", rpcResp.Error["code"], rpcResp.Error["message"]))
		}
		resBytes, _ := json.Marshal(rpcResp.Result)
		respBody = resBytes
	}

	a2aResp, err := a2aspec.DecodeStrict[a2aspec.SendMessageResponse]("SendMessageResponse", respBody)
	if err != nil {
		return nil, ErrInvalidAgentResponse(fmt.Sprintf("upstream response violated A2A v1.0 schema: %v", err))
	}
	return a2aResp, nil
}

func (s *RouterService) invokeUpstreamAgentStream(
	ctx context.Context,
	agent *domain.A2AAgent,
	req *a2aspec.SendMessageRequest,
	onFrame func(*a2aspec.StreamResponse) error,
) (bool, error) {
	if strings.EqualFold(agent.ProtocolBinding, domain.A2AProtocolBindingGRPC) {
		s.upstreamGRPCTotal.Add(1)
		return s.invokeUpstreamGRPCStream(ctx, agent, req, onFrame)
	}

	reqJSON, err := json.Marshal(req)
	if err != nil {
		return false, ErrInternal(fmt.Sprintf("marshal upstream stream request: %v", err))
	}

	targetURL := agent.EndpointURL
	var bodyBytes []byte
	if strings.EqualFold(agent.ProtocolBinding, domain.A2AProtocolBindingJSONRPC) {
		s.upstreamJSONRPCTotal.Add(1)
		rpcReq := map[string]any{
			"jsonrpc": "2.0",
			"id":      uuid.NewString(),
			"method":  string(a2aspec.SendStreamingMessage),
			"params":  json.RawMessage(reqJSON),
		}
		bodyBytes, _ = json.Marshal(rpcReq)
	} else {
		s.upstreamHTTPJSONTotal.Add(1)
		targetURL = resolveUpstreamActionURL(agent.EndpointURL, "/message:stream")
		bodyBytes = reqJSON
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(bodyBytes))
	if err != nil {
		return false, ErrInternal(fmt.Sprintf("create upstream stream request: %v", err))
	}
	httpReq.Header.Set("Content-Type", MediaTypeA2AJSON)
	httpReq.Header.Set("Accept", MediaTypeSSE+", "+MediaTypeA2AJSON+", "+MediaTypeJSON)
	httpReq.Header.Set(HeaderA2AVersion, a2aspec.SupportedA2AVersion)
	if err := s.applyUpstreamAuth(agent, httpReq); err != nil {
		return false, err
	}
	observability.InjectTraceHeaders(ctx, httpReq)

	resp, err := s.httpClient.Do(httpReq)
	if err != nil {
		return false, ErrInvalidAgentResponse(fmt.Sprintf("upstream stream call failed: %v", err))
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return false, ErrInvalidAgentResponse(fmt.Sprintf("upstream stream returned HTTP %d", resp.StatusCode))
	}

	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	if !strings.Contains(ct, MediaTypeSSE) {
		return false, nil
	}

	scanner := bufio.NewScanner(io.LimitReader(resp.Body, 32*1024*1024))
	scanner.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	var dataLines []string
	flushSSEData := func() error {
		if len(dataLines) == 0 {
			return nil
		}
		payload := strings.TrimSpace(strings.Join(dataLines, "\n"))
		dataLines = nil
		if payload == "" || payload == "[DONE]" {
			return nil
		}
		if strings.EqualFold(agent.ProtocolBinding, domain.A2AProtocolBindingJSONRPC) {
			var rpcResp JSONRPCResponse
			if err := json.Unmarshal([]byte(payload), &rpcResp); err == nil {
				if rpcResp.Error != nil {
					return ErrInvalidAgentResponse(fmt.Sprintf("upstream stream error %v: %v", rpcResp.Error["code"], rpcResp.Error["message"]))
				}
				if rpcResp.Result != nil {
					if rb, mErr := json.Marshal(rpcResp.Result); mErr == nil {
						payload = string(rb)
					}
				}
			}
		}
		frame, dErr := a2aspec.DecodeStrict[a2aspec.StreamResponse]("StreamResponse", []byte(payload))
		if dErr != nil {
			return ErrInvalidAgentResponse(fmt.Sprintf("invalid upstream SSE StreamResponse: %v", dErr))
		}
		return onFrame(frame)
	}

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			if err := flushSSEData(); err != nil {
				return true, err
			}
			continue
		}
		if strings.HasPrefix(line, ":") {
			continue
		}
		if after, ok := strings.CutPrefix(line, "data:"); ok {
			dataLines = append(dataLines, strings.TrimSpace(after))
		}
	}
	if err := flushSSEData(); err != nil {
		return true, err
	}
	if err := scanner.Err(); err != nil {
		return true, ErrInvalidAgentResponse(fmt.Sprintf("read upstream SSE stream: %v", err))
	}
	return true, nil
}

func (s *RouterService) cancelUpstreamTask(ctx context.Context, agent *domain.A2AAgent, upstreamTaskID string) {
	if strings.EqualFold(agent.ProtocolBinding, domain.A2AProtocolBindingGRPC) {
		s.cancelUpstreamGRPCTask(ctx, agent, upstreamTaskID)
		return
	}
	cancelURL := resolveUpstreamActionURL(agent.EndpointURL, "/tasks/"+url.PathEscape(upstreamTaskID)+":cancel")
	var body io.Reader = strings.NewReader("{}")
	if strings.EqualFold(agent.ProtocolBinding, domain.A2AProtocolBindingJSONRPC) {
		cancelURL = agent.EndpointURL
		rpcBytes, _ := json.Marshal(map[string]any{
			"jsonrpc": "2.0",
			"id":      uuid.NewString(),
			"method":  string(a2aspec.CancelTask),
			"params":  map[string]string{"id": upstreamTaskID},
		})
		body = bytes.NewReader(rpcBytes)
	}

	cCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(cCtx, http.MethodPost, cancelURL, body)
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", MediaTypeA2AJSON)
	req.Header.Set(HeaderA2AVersion, a2aspec.SupportedA2AVersion)
	_ = s.applyUpstreamAuth(agent, req)
	resp, err := s.httpClient.Do(req)
	if err == nil && resp != nil {
		_ = resp.Body.Close()
	}
}

func (s *RouterService) applyAndPersistUpstreamResponse(
	ctx context.Context,
	task *domain.A2ATask,
	upstreamResp *a2aspec.SendMessageResponse,
	costDelta int64,
) error {
	now := time.Now().UTC()
	var frameBytes []byte
	eventType := "status"

	if upstreamResp.Task != nil {
		upTask := upstreamResp.Task
		// Preserve upstream task ID cleanly in ClientTaskID when distinct from gateway task ID.
		if upTask.Id != "" && upTask.Id != task.ID {
			task.ClientTaskID = upTask.Id
		}
		upTask.Id = task.ID
		if upTask.ContextId == nil || *upTask.ContextId == "" {
			cid := task.ContextID
			upTask.ContextId = &cid
		} else {
			task.ContextID = *upTask.ContextId
		}

		// Fix C3: inspect upTask.Status without dereferencing an uninitialized zero Status blindly.
		nextState := upTask.Status.State
		if nextState == "" || nextState == a2aspec.TASKSTATEUNSPECIFIED {
			nextState = a2aspec.TASKSTATESUBMITTED
			upTask.Status.State = nextState
		}
		if upTask.Status.Timestamp == nil {
			upTask.Status.Timestamp = &now
		}
		task.State = a2aspec.TaskStateToDomain(nextState)
		task.StatusTimestamp = upTask.Status.Timestamp

		if upTask.Status.Message != nil {
			b, _ := json.Marshal(upTask.Status.Message)
			task.StatusMessageJSON = string(b)
			task.OutputMessageJSON = string(b)
		}
		if upTask.Artifacts != nil {
			b, _ := json.Marshal(upTask.Artifacts)
			task.ArtifactsJSON = string(b)
		}
		if upTask.History != nil {
			b, _ := json.Marshal(upTask.History)
			task.HistoryJSON = string(b)
		}
		if upTask.Metadata != nil {
			b, _ := json.Marshal(upTask.Metadata)
			task.MetadataJSON = string(b)
		}
		if a2aspec.IsTerminalTaskState(nextState) {
			task.CompletedAt = &now
		}

		upstreamResp.ClearUnion()
		frameBytes, _ = json.Marshal(&a2aspec.StreamResponse{Task: upTask})
	} else if upstreamResp.Message != nil {
		msg := upstreamResp.Message
		msg.TaskId = &task.ID
		if msg.ContextId == nil || *msg.ContextId == "" {
			cid := task.ContextID
			msg.ContextId = &cid
		}
		b, _ := json.Marshal(msg)
		task.OutputMessageJSON = string(b)
		task.StatusMessageJSON = string(b)
		task.State = domain.A2ATaskStateCompleted
		task.StatusTimestamp = &now
		task.CompletedAt = &now
		eventType = "message"

		// Append assistant message to task history.
		hist := decodeHistorySlice(task.HistoryJSON)
		hist = append(hist, *msg)
		hb, _ := json.Marshal(hist)
		task.HistoryJSON = string(hb)

		upstreamResp.ClearUnion()
		frameBytes, _ = json.Marshal(&a2aspec.StreamResponse{Message: msg})
	}

	if err := s.repo.UpdateA2ATask(ctx, task, costDelta); err != nil {
		return ErrInternal(fmt.Sprintf("update task state: %v", err))
	}
	switch task.State {
	case domain.A2ATaskStateCompleted:
		s.tasksCompletedTotal.Add(1)
	case domain.A2ATaskStateFailed, domain.A2ATaskStateRejected:
		s.tasksFailedTotal.Add(1)
	case domain.A2ATaskStateCanceled:
		s.tasksCanceledTotal.Add(1)
	}
	if len(frameBytes) > 0 {
		if ev, evErr := s.repo.AppendA2ATaskEvent(ctx, task.ID, eventType, string(frameBytes)); evErr == nil && ev != nil {
			task.LastEventSeq = ev.EventSeq
		}
	}
	return nil
}

func (s *RouterService) persistStreamFrame(ctx context.Context, task *domain.A2ATask, frame *a2aspec.StreamResponse) (int64, error) {
	now := time.Now().UTC()
	eventType := "message"

	switch {
	case frame.Task != nil:
		eventType = "task"
		if frame.Task.Id != "" && frame.Task.Id != task.ID {
			task.ClientTaskID = frame.Task.Id
		}
		frame.Task.Id = task.ID
		if frame.Task.ContextId == nil || *frame.Task.ContextId == "" {
			cid := task.ContextID
			frame.Task.ContextId = &cid
		}
		if frame.Task.Status.State != "" {
			task.State = a2aspec.TaskStateToDomain(frame.Task.Status.State)
		}
		if frame.Task.Artifacts != nil {
			b, _ := json.Marshal(frame.Task.Artifacts)
			task.ArtifactsJSON = string(b)
		}
	case frame.StatusUpdate != nil:
		eventType = "status"
		if frame.StatusUpdate.TaskId != "" && frame.StatusUpdate.TaskId != task.ID {
			task.ClientTaskID = frame.StatusUpdate.TaskId
		}
		frame.StatusUpdate.TaskId = task.ID
		if frame.StatusUpdate.ContextId == "" {
			frame.StatusUpdate.ContextId = task.ContextID
		}
		if frame.StatusUpdate.Status.Timestamp == nil {
			frame.StatusUpdate.Status.Timestamp = &now
		}
		task.State = a2aspec.TaskStateToDomain(frame.StatusUpdate.Status.State)
		task.StatusTimestamp = frame.StatusUpdate.Status.Timestamp
		if frame.StatusUpdate.Status.Message != nil {
			b, _ := json.Marshal(frame.StatusUpdate.Status.Message)
			task.StatusMessageJSON = string(b)
			task.OutputMessageJSON = string(b)
		}
		if a2aspec.IsTerminalTaskState(frame.StatusUpdate.Status.State) {
			task.CompletedAt = &now
		}
	case frame.ArtifactUpdate != nil:
		eventType = "artifact"
		if frame.ArtifactUpdate.TaskId != "" && frame.ArtifactUpdate.TaskId != task.ID {
			task.ClientTaskID = frame.ArtifactUpdate.TaskId
		}
		frame.ArtifactUpdate.TaskId = task.ID
		if frame.ArtifactUpdate.ContextId == "" {
			frame.ArtifactUpdate.ContextId = task.ContextID
		}
		arts := mergeArtifactIntoSlice(decodeArtifactsSlice(task.ArtifactsJSON), frame.ArtifactUpdate)
		ab, _ := json.Marshal(arts)
		task.ArtifactsJSON = string(ab)
	case frame.Message != nil:
		eventType = "message"
		frame.Message.TaskId = &task.ID
		if frame.Message.ContextId == nil || *frame.Message.ContextId == "" {
			cid := task.ContextID
			frame.Message.ContextId = &cid
		}
		b, _ := json.Marshal(frame.Message)
		task.OutputMessageJSON = string(b)
		hist := append(decodeHistorySlice(task.HistoryJSON), *frame.Message)
		hb, _ := json.Marshal(hist)
		task.HistoryJSON = string(hb)
	}

	frame.ClearUnion()
	if err := s.repo.UpdateA2ATask(ctx, task, 0); err != nil {
		return 0, ErrInternal(fmt.Sprintf("update streamed task: %v", err))
	}
	if eventType == "status" || eventType == "task" {
		switch task.State {
		case domain.A2ATaskStateCompleted:
			s.tasksCompletedTotal.Add(1)
		case domain.A2ATaskStateFailed, domain.A2ATaskStateRejected:
			s.tasksFailedTotal.Add(1)
		case domain.A2ATaskStateCanceled:
			s.tasksCanceledTotal.Add(1)
		}
	}
	frameBytes, _ := json.Marshal(frame)
	ev, err := s.repo.AppendA2ATaskEvent(ctx, task.ID, eventType, string(frameBytes))
	if err != nil {
		return 0, ErrInternal(fmt.Sprintf("append stream event: %v", err))
	}
	task.LastEventSeq = ev.EventSeq
	return ev.EventSeq, nil
}

func (s *RouterService) failTaskAndEmitEvent(ctx context.Context, task *domain.A2ATask, reason string) {
	if task == nil || task.ID == "" {
		return
	}
	s.tasksFailedTotal.Add(1)
	now := time.Now().UTC()
	task.State = domain.A2ATaskStateFailed
	task.StatusTimestamp = &now
	task.CompletedAt = &now
	msg := &a2aspec.Message{
		MessageId: "msg_err_" + uuid.NewString(),
		Role:      a2aspec.ROLEAGENT,
		Parts:     []a2aspec.Part{a2aspec.NewTextPart(reason)},
		TaskId:    &task.ID,
	}
	if b, err := json.Marshal(msg); err == nil {
		task.StatusMessageJSON = string(b)
	}
	_ = s.repo.UpdateA2ATask(ctx, task, 0)

	evPayload, _ := json.Marshal(&a2aspec.StreamResponse{
		StatusUpdate: &a2aspec.TaskStatusUpdateEvent{
			TaskId:    task.ID,
			ContextId: task.ContextID,
			Status: a2aspec.TaskStatus{
				State:     a2aspec.TASKSTATEFAILED,
				Message:   msg,
				Timestamp: &now,
			},
		},
	})
	if ev, err := s.repo.AppendA2ATaskEvent(ctx, task.ID, "status", string(evPayload)); err == nil && ev != nil {
		task.LastEventSeq = ev.EventSeq
	}
}

func (s *RouterService) recordFinOpsSpend(ctx context.Context, idCtx *domain.IdentityContext, agentSlug, reqID string, costMicros int64) {
	if s.spendRecorder == nil || costMicros <= 0 || idCtx == nil {
		return
	}
	if err := s.spendRecorder.Record(ctx, domain.SpendEvent{
		ID:             "spend_" + uuid.NewString(),
		RequestID:      reqID,
		Protocol:       "a2a",
		ProtocolTarget: "a2a:" + agentSlug,
		OrgID:          idCtx.OrgID,
		TeamID:         idCtx.TeamID,
		UserID:         idCtx.UserID,
		VirtualKeyID:   idCtx.VirtualKeyID,
		RequestedModel: "a2a/" + agentSlug,
		ResolvedModel:  agentSlug,
		Endpoint:       "/a2a/v1/agents/" + agentSlug,
		CostMicros:     costMicros,
		CreatedAt:      time.Now().UTC(),
	}); err != nil {
		logger.WarnContext(ctx, "failed to persist A2A spend log", slog.String("agent", agentSlug), slog.Any("error", err))
	}
}

func (s *RouterService) domainTaskToSpec(t *domain.A2ATask, historyLength *int32, includeArtifacts bool) *a2aspec.Task {
	ts := t.UpdatedAt
	if t.StatusTimestamp != nil {
		ts = *t.StatusTimestamp
	}
	specTask := &a2aspec.Task{
		Id: t.ID,
		Status: a2aspec.TaskStatus{
			State:     a2aspec.DomainToTaskState(t.State),
			Timestamp: &ts,
		},
	}
	if t.ContextID != "" {
		cid := t.ContextID
		specTask.ContextId = &cid
	}

	statusMsgJSON := t.StatusMessageJSON
	if statusMsgJSON == "" {
		statusMsgJSON = t.OutputMessageJSON
	}
	if statusMsgJSON == "" {
		statusMsgJSON = t.InputMessageJSON
	}
	if statusMsgJSON != "" {
		var m a2aspec.Message
		if err := json.Unmarshal([]byte(statusMsgJSON), &m); err == nil {
			specTask.Status.Message = &m
		}
	}

	if includeArtifacts && t.ArtifactsJSON != "" {
		arts := decodeArtifactsSlice(t.ArtifactsJSON)
		if len(arts) > 0 {
			specTask.Artifacts = &arts
		}
	}

	if t.HistoryJSON != "" {
		hist := decodeHistorySlice(t.HistoryJSON)
		if len(hist) > 0 {
			specTask.History = &hist
		}
	}
	if t.MetadataJSON != "" {
		var meta a2aspec.Metadata
		if err := json.Unmarshal([]byte(t.MetadataJSON), &meta); err == nil && len(meta) > 0 {
			specTask.Metadata = &meta
		}
	}

	return applyHistoryLength(specTask, historyLength)
}

func applyHistoryLength(t *a2aspec.Task, historyLength *int32) *a2aspec.Task {
	if t == nil || historyLength == nil || t.History == nil {
		return t
	}
	limit := int(*historyLength)
	if limit <= 0 {
		t.History = nil
		return t
	}
	hist := *t.History
	if len(hist) > limit {
		trimmed := append([]a2aspec.Message(nil), hist[len(hist)-limit:]...)
		t.History = &trimmed
	}
	return t
}

func historyLengthFromConfig(cfg *a2aspec.SendMessageConfiguration) *int32 {
	if cfg == nil {
		return nil
	}
	return cfg.HistoryLength
}

func decodeHistorySlice(raw string) []a2aspec.Message {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var out []a2aspec.Message
	_ = json.Unmarshal([]byte(raw), &out)
	return out
}

func decodeArtifactsSlice(raw string) []a2aspec.Artifact {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	var out []a2aspec.Artifact
	_ = json.Unmarshal([]byte(raw), &out)
	return out
}

func mergeArtifactIntoSlice(existing []a2aspec.Artifact, ev *a2aspec.TaskArtifactUpdateEvent) []a2aspec.Artifact {
	if ev == nil {
		return existing
	}
	appendMode := ev.Append != nil && *ev.Append
	if appendMode {
		for i := range existing {
			if existing[i].ArtifactId == ev.Artifact.ArtifactId {
				existing[i].Parts = append(existing[i].Parts, ev.Artifact.Parts...)
				return existing
			}
		}
	}
	for i := range existing {
		if existing[i].ArtifactId == ev.Artifact.ArtifactId {
			existing[i] = ev.Artifact
			return existing
		}
	}
	return append(existing, ev.Artifact)
}

func cloneSendMessageRequest(req *a2aspec.SendMessageRequest) *a2aspec.SendMessageRequest {
	if req == nil {
		return nil
	}
	b, _ := json.Marshal(req)
	var cp a2aspec.SendMessageRequest
	_ = json.Unmarshal(b, &cp)
	if cp.Configuration != nil {
		f := false
		cp.Configuration.ReturnImmediately = &f
	}
	return &cp
}

func encodePageToken(offset int) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strconv.Itoa(offset)))
}

func decodePageToken(tok string) (int, error) {
	b, err := base64.RawURLEncoding.DecodeString(tok)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(string(b))
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
	msg *a2aspec.Message,
) error {
	if msg == nil {
		return nil
	}
	var textPartIndices []int
	var contentParts []domain.ContentPart
	for i := range msg.Parts {
		if txt, ok := a2aspec.PartText(msg.Parts[i]); ok && txt != "" {
			textPartIndices = append(textPartIndices, i)
			contentParts = append(contentParts, domain.ContentPart{Type: "text", Text: txt})
		}
	}
	if len(textPartIndices) == 0 {
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
				return ErrInvalidParams(gwErr.Message)
			}
			return ErrInvalidParams(err.Error())
		}
		if out != nil && strings.TrimSpace(out.RouteTarget) != "" {
			return ErrInvalidParams(fmt.Sprintf("agent %q invocation blocked by sensitive routing guardrail policy", agentSlug))
		}
	} else if s.guardrails != nil {
		if _, err := s.guardrails.EvaluateInput(ctx, orgID, chatReq); err != nil {
			var gwErr *domain.GatewayError
			if errors.As(err, &gwErr) {
				if gwErr.StatusCode >= 500 {
					return gwErr
				}
				return ErrInvalidParams(gwErr.Message)
			}
			return ErrInvalidParams(err.Error())
		}
	}

	for i, partIdx := range textPartIndices {
		if i < len(chatReq.Messages[0].Parts) {
			a2aspec.SetPartText(&msg.Parts[partIdx], chatReq.Messages[0].Parts[i].Text)
			msg.Parts[partIdx].ClearUnion()
		}
	}
	return nil
}

func (s *RouterService) sanitizeOutboundResponse(
	ctx context.Context,
	prc guardrails.PipelineRequestContext,
	orgID string,
	resp *a2aspec.SendMessageResponse,
) error {
	if resp == nil {
		return nil
	}
	if resp.Message != nil {
		if err := s.sanitizeParts(ctx, prc, orgID, resp.Message.Parts); err != nil {
			return err
		}
	}
	if resp.Task != nil {
		if resp.Task.Status.Message != nil {
			if err := s.sanitizeParts(ctx, prc, orgID, resp.Task.Status.Message.Parts); err != nil {
				return err
			}
		}
		if resp.Task.History != nil {
			hist := *resp.Task.History
			for i := range hist {
				if err := s.sanitizeParts(ctx, prc, orgID, hist[i].Parts); err != nil {
					return err
				}
			}
		}
		if resp.Task.Artifacts != nil {
			arts := *resp.Task.Artifacts
			for i := range arts {
				if err := s.sanitizeParts(ctx, prc, orgID, arts[i].Parts); err != nil {
					return err
				}
			}
		}
	}
	resp.ClearUnion()
	return nil
}

func (s *RouterService) sanitizeStreamResponse(
	ctx context.Context,
	prc guardrails.PipelineRequestContext,
	orgID string,
	frame *a2aspec.StreamResponse,
) error {
	if frame == nil {
		return nil
	}
	if frame.Task != nil {
		if err := s.sanitizeOutboundResponse(ctx, prc, orgID, &a2aspec.SendMessageResponse{Task: frame.Task}); err != nil {
			return err
		}
	}
	if frame.Message != nil {
		if err := s.sanitizeParts(ctx, prc, orgID, frame.Message.Parts); err != nil {
			return err
		}
	}
	if frame.StatusUpdate != nil && frame.StatusUpdate.Status.Message != nil {
		if err := s.sanitizeParts(ctx, prc, orgID, frame.StatusUpdate.Status.Message.Parts); err != nil {
			return err
		}
	}
	if frame.ArtifactUpdate != nil {
		if err := s.sanitizeParts(ctx, prc, orgID, frame.ArtifactUpdate.Artifact.Parts); err != nil {
			return err
		}
	}
	frame.ClearUnion()
	return nil
}

func (s *RouterService) sanitizeParts(
	ctx context.Context,
	prc guardrails.PipelineRequestContext,
	orgID string,
	parts []a2aspec.Part,
) error {
	if len(parts) == 0 {
		return nil
	}
	if s.pipeline != nil {
		var textPartIndices []int
		var choices []domain.CanonicalChoice
		for i := range parts {
			if txt, ok := a2aspec.PartText(parts[i]); ok && txt != "" {
				idx := len(choices)
				textPartIndices = append(textPartIndices, i)
				choices = append(choices, domain.CanonicalChoice{
					Index:   idx,
					Message: domain.CanonicalMessage{Role: "assistant", Content: txt},
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
		for i, partIdx := range textPartIndices {
			if i < len(chatResp.Choices) {
				a2aspec.SetPartText(&parts[partIdx], chatResp.Choices[i].Message.Content)
				parts[partIdx].ClearUnion()
			}
		}
		return nil
	}
	if s.guardrails == nil {
		return nil
	}
	for i := range parts {
		if txt, ok := a2aspec.PartText(parts[i]); ok && txt != "" {
			sanitized, _, err := s.guardrails.SanitizeTextOutput(ctx, orgID, txt)
			if err != nil {
				return err
			}
			a2aspec.SetPartText(&parts[i], sanitized)
			parts[i].ClearUnion()
		}
	}
	return nil
}

func extractCostFromMetadata(meta *a2aspec.Metadata) int64 {
	if meta == nil {
		return 0
	}
	switch v := (*meta)["cost_micros"].(type) {
	case float64:
		if v > 0 {
			return int64(v)
		}
	case int64:
		if v > 0 {
			return v
		}
	case int:
		if v > 0 {
			return int64(v)
		}
	}
	return 0
}

func extractA2AInvocationCostMicros(resp *a2aspec.SendMessageResponse) int64 {
	if resp == nil {
		return defaultA2AInvocationCostMicros
	}
	if resp.Task != nil {
		if c := extractCostFromMetadata(resp.Task.Metadata); c > 0 {
			return c
		}
	}
	if resp.Message != nil {
		if c := extractCostFromMetadata(resp.Message.Metadata); c > 0 {
			return c
		}
	}
	return defaultA2AInvocationCostMicros
}

func extractStreamFrameCost(frame *a2aspec.StreamResponse) int64 {
	if frame == nil {
		return 0
	}
	if frame.Task != nil {
		if c := extractCostFromMetadata(frame.Task.Metadata); c > 0 {
			return c
		}
	}
	if frame.StatusUpdate != nil {
		if c := extractCostFromMetadata(frame.StatusUpdate.Metadata); c > 0 {
			return c
		}
	}
	if frame.ArtifactUpdate != nil {
		if c := extractCostFromMetadata(frame.ArtifactUpdate.Metadata); c > 0 {
			return c
		}
	}
	if frame.Message != nil {
		if c := extractCostFromMetadata(frame.Message.Metadata); c > 0 {
			return c
		}
	}
	return 0
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
	cp := maps.Clone(details)
	_ = s.repo.RecordAuditLog(ctx, &domain.AuditLog{
		OrgID:      orgID,
		ActorID:    actorID,
		Action:     action,
		Resource:   resource,
		ResourceID: resourceID,
		Details:    cp,
	})
}
