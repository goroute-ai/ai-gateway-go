package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/goroute-ai/ai-gateway-go/internal/a2a"
	"github.com/goroute-ai/ai-gateway-go/internal/a2a/pb"
	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/mcp"
)

// handleA2AWellKnownCard serves `GET /.well-known/agent-card.json`.
func (s *GatewayServer) handleA2AWellKnownCard(w http.ResponseWriter, r *http.Request) {
	a2a.ServeWellKnownAgentCard(w, r, s.repo, s.a2aSigner, s.serverBaseURL(r), "")
}

// handleA2AAgentMessage serves `POST /a2a/v1/agents/{agentSlug}`
// (supporting both JSON-RPC 2.0 and HTTP+JSON SendMessage).
func (s *GatewayServer) handleA2AAgentMessage(w http.ResponseWriter, r *http.Request) {
	reqID := r.Header.Get("X-Request-Id")
	if reqID == "" {
		reqID = "req_" + uuid.NewString()
	}
	w.Header().Set("X-Gateway-Request-Id", reqID)

	agentSlug := chi.URLParam(r, "agentSlug")
	if agentSlug == "" {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "missing_agent_slug",
			Message:    "agentSlug is required in URL path",
		})
		return
	}

	idCtx := auth.IdentityFromContext(r.Context())
	if idCtx == nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusUnauthorized,
			Type:       domain.ErrorTypeAuthentication,
			Code:       "unauthenticated",
			Message:    "Identity context required for A2A communication",
		})
		return
	}

	bodyBytes, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 10*1024*1024))
	if err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusRequestEntityTooLarge,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "payload_too_large",
			Message:    err.Error(),
		})
		return
	}

	// 1. JSON-RPC 2.0 Dispatch
	if a2a.IsJSONRPC(bodyBytes) {
		resp, err := s.a2aRouter.DispatchJSONRPC(r.Context(), idCtx, agentSlug, bodyBytes)
		if err != nil {
			writeJSONRPC(w, http.StatusOK, &mcp.JSONRPCResponse{
				JSONRPC: "2.0",
				Error: &mcp.JSONRPCError{
					Code:    -32603,
					Message: err.Error(),
				},
			}, nil)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
		return
	}

	// 2. HTTP+JSON REST SendMessage
	var sendReq pb.SendMessageRequest
	if err := a2a.StrictProtoJSONUnmarshaler.Unmarshal(bodyBytes, &sendReq); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_protojson",
			Message:    fmt.Sprintf("Strict protobuf validation error: %v", err),
		})
		return
	}

	sendResp, err := s.a2aRouter.SendMessage(r.Context(), idCtx, agentSlug, &sendReq)
	if err != nil {
		s.writeA2AError(w, err)
		return
	}

	respJSON, err := a2a.ProtoJSONMarshaler.Marshal(sendResp)
	if err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusInternalServerError,
			Type:       domain.ErrorTypeServer,
			Code:       "marshal_error",
			Message:    err.Error(),
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(respJSON)
}

// handleA2AGetTask serves `GET /a2a/v1/agents/{agentSlug}/tasks/{taskID}`.
func (s *GatewayServer) handleA2AGetTask(w http.ResponseWriter, r *http.Request) {
	agentSlug := chi.URLParam(r, "agentSlug")
	taskID := chi.URLParam(r, "taskID")
	idCtx := auth.IdentityFromContext(r.Context())

	task, err := s.a2aRouter.GetTask(r.Context(), idCtx, agentSlug, taskID)
	if err != nil {
		s.writeA2AError(w, err)
		return
	}

	respJSON, _ := a2a.ProtoJSONMarshaler.Marshal(task)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(respJSON)
}

// handleA2AListTasks serves `GET /a2a/v1/agents/{agentSlug}/tasks`.
func (s *GatewayServer) handleA2AListTasks(w http.ResponseWriter, r *http.Request) {
	agentSlug := chi.URLParam(r, "agentSlug")
	idCtx := auth.IdentityFromContext(r.Context())

	listResp, err := s.a2aRouter.ListTasks(r.Context(), idCtx, agentSlug, &pb.ListTasksRequest{})
	if err != nil {
		s.writeA2AError(w, err)
		return
	}

	respJSON, _ := a2a.ProtoJSONMarshaler.Marshal(listResp)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(respJSON)
}

// handleA2ACancelTask serves `POST /a2a/v1/agents/{agentSlug}/tasks/{taskID}:cancel`.
func (s *GatewayServer) handleA2ACancelTask(w http.ResponseWriter, r *http.Request) {
	agentSlug := chi.URLParam(r, "agentSlug")
	taskID := chi.URLParam(r, "taskID")
	idCtx := auth.IdentityFromContext(r.Context())

	task, err := s.a2aRouter.CancelTask(r.Context(), idCtx, agentSlug, taskID)
	if err != nil {
		s.writeA2AError(w, err)
		return
	}

	respJSON, _ := a2a.ProtoJSONMarshaler.Marshal(task)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(respJSON)
}

// handleA2ASubscribeTask serves canonical `GET /a2a/v1/agents/{agentSlug}/tasks/{taskID}:subscribe` (and optional POST compat).
func (s *GatewayServer) handleA2ASubscribeTask(w http.ResponseWriter, r *http.Request) {
	agentSlug := chi.URLParam(r, "agentSlug")
	taskID := chi.URLParam(r, "taskID")
	idCtx := auth.IdentityFromContext(r.Context())

	orgID := ""
	if idCtx != nil {
		orgID = idCtx.OrgID
	}

	agent, err := s.repo.GetA2AAgentBySlug(r.Context(), orgID, agentSlug)
	if err != nil || agent == nil {
		http.Error(w, fmt.Sprintf("Agent %q not found", agentSlug), http.StatusNotFound)
		return
	}

	if s.a2aStreamSub != nil {
		s.a2aStreamSub.SubscribeTaskStream(w, r, idCtx, agentSlug, taskID, agent.TaskVisibilityMode)
		return
	}

	http.Error(w, "A2A Streaming unsupported", http.StatusServiceUnavailable)
}

func (s *GatewayServer) writeA2AError(w http.ResponseWriter, err error) {
	var gwErr *domain.GatewayError
	if errors.As(err, &gwErr) {
		domain.WriteHTTPError(w, gwErr)
		return
	}

	var a2aErr *a2a.A2AError
	statusCode := http.StatusInternalServerError
	errCode := "internal_error"

	if errors.As(err, &a2aErr) {
		switch a2aErr.Code {
		case a2a.CodeBudgetExceeded:
			statusCode = http.StatusBadRequest
			errCode = "budget_exceeded"
		case a2a.CodeTaskNotFound:
			statusCode = http.StatusNotFound
			errCode = "task_not_found"
		case a2a.CodeTaskAlreadyCompleted:
			statusCode = http.StatusConflict
			errCode = "task_already_completed"
		case a2a.CodeTaskStateTransitionInvalid:
			statusCode = http.StatusBadRequest
			errCode = "invalid_state_transition"
		case a2a.CodeAgentKilled:
			statusCode = http.StatusServiceUnavailable
			errCode = "agent_killed"
		default:
			statusCode = http.StatusBadRequest
			errCode = "a2a_error"
		}
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: statusCode,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       errCode,
			Message:    a2aErr.Message,
		})
		return
	}

	domain.WriteHTTPError(w, &domain.GatewayError{
		StatusCode: http.StatusInternalServerError,
		Type:       domain.ErrorTypeServer,
		Code:       "server_error",
		Message:    err.Error(),
	})
}

func (s *GatewayServer) serverBaseURL(r *http.Request) string {
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s", scheme, r.Host)
}
