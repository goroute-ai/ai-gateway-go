package a2a

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	a2aspec "github.com/goroute-ai/ai-gateway-go/internal/a2a/spec"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

// DispatchJSONRPC handles A2A v1.0 JSON-RPC 2.0 requests (Section 9) for unary RPCs.
// Streaming methods (`SendStreamingMessage`, `SubscribeToTask`) are handled via DispatchJSONRPCHTTP
// so they can upgrade seamlessly to `text/event-stream`.
func (s *RouterService) DispatchJSONRPC(
	ctx context.Context,
	idCtx *domain.IdentityContext,
	agentSlug string,
	body []byte,
	gatewayBaseURL string,
) *JSONRPCResponse {
	rpcReq, parseErr := decodeJSONRPCRequest(body)
	if parseErr != nil {
		return rpcErrResponse(nil, parseErr)
	}

	switch a2aspec.JSONRPCMethod(rpcReq.Method) {
	case a2aspec.SendMessage:
		req, err := decodeRPCParams[a2aspec.SendMessageRequest]("SendMessageRequest", rpcReq.Params)
		if err != nil {
			return rpcErrResponse(rpcReq.ID, err)
		}
		resp, err := s.SendMessage(ctx, idCtx, agentSlug, req)
		if err != nil {
			return rpcErrResponse(rpcReq.ID, err)
		}
		return rpcOKResponse(rpcReq.ID, resp)

	case a2aspec.GetTask:
		req, err := decodeRPCParams[a2aspec.GetTaskRequest]("GetTaskRequest", rpcReq.Params)
		if err != nil {
			return rpcErrResponse(rpcReq.ID, err)
		}
		resp, err := s.GetTask(ctx, idCtx, agentSlug, req.Id, req.HistoryLength)
		if err != nil {
			return rpcErrResponse(rpcReq.ID, err)
		}
		return rpcOKResponse(rpcReq.ID, resp)

	case a2aspec.ListTasks:
		var req a2aspec.ListTasksRequest
		if len(bytes.TrimSpace(rpcReq.Params)) > 0 {
			decoded, err := decodeRPCParams[a2aspec.ListTasksRequest]("ListTasksRequest", rpcReq.Params)
			if err != nil {
				return rpcErrResponse(rpcReq.ID, err)
			}
			req = *decoded
		}
		resp, err := s.ListTasks(ctx, idCtx, agentSlug, &req)
		if err != nil {
			return rpcErrResponse(rpcReq.ID, err)
		}
		return rpcOKResponse(rpcReq.ID, resp)

	case a2aspec.CancelTask:
		req, err := decodeRPCParams[a2aspec.CancelTaskRequest]("CancelTaskRequest", rpcReq.Params)
		if err != nil {
			return rpcErrResponse(rpcReq.ID, err)
		}
		resp, err := s.CancelTask(ctx, idCtx, agentSlug, req.Id)
		if err != nil {
			return rpcErrResponse(rpcReq.ID, err)
		}
		return rpcOKResponse(rpcReq.ID, resp)

	case a2aspec.CreateTaskPushNotificationConfig:
		req, err := decodeRPCParams[a2aspec.TaskPushNotificationConfig]("TaskPushNotificationConfig", rpcReq.Params)
		if err != nil {
			return rpcErrResponse(rpcReq.ID, err)
		}
		taskID := ""
		if req.TaskId != nil {
			taskID = *req.TaskId
		}
		resp, err := s.CreateTaskPushNotificationConfig(ctx, idCtx, agentSlug, taskID, req)
		if err != nil {
			return rpcErrResponse(rpcReq.ID, err)
		}
		return rpcOKResponse(rpcReq.ID, resp)

	case a2aspec.GetTaskPushNotificationConfig:
		req, err := decodeRPCParams[a2aspec.GetTaskPushNotificationConfigRequest]("GetTaskPushNotificationConfigRequest", rpcReq.Params)
		if err != nil {
			return rpcErrResponse(rpcReq.ID, err)
		}
		resp, err := s.GetTaskPushNotificationConfig(ctx, idCtx, agentSlug, req.TaskId, req.Id)
		if err != nil {
			return rpcErrResponse(rpcReq.ID, err)
		}
		return rpcOKResponse(rpcReq.ID, resp)

	case a2aspec.ListTaskPushNotificationConfigs:
		req, err := decodeRPCParams[a2aspec.ListTaskPushNotificationConfigsRequest]("ListTaskPushNotificationConfigsRequest", rpcReq.Params)
		if err != nil {
			return rpcErrResponse(rpcReq.ID, err)
		}
		resp, err := s.ListTaskPushNotificationConfigs(ctx, idCtx, agentSlug, req.TaskId, req.PageSize, req.PageToken)
		if err != nil {
			return rpcErrResponse(rpcReq.ID, err)
		}
		return rpcOKResponse(rpcReq.ID, resp)

	case a2aspec.DeleteTaskPushNotificationConfig:
		req, err := decodeRPCParams[a2aspec.DeleteTaskPushNotificationConfigRequest]("DeleteTaskPushNotificationConfigRequest", rpcReq.Params)
		if err != nil {
			return rpcErrResponse(rpcReq.ID, err)
		}
		if err := s.DeleteTaskPushNotificationConfig(ctx, idCtx, agentSlug, req.TaskId, req.Id); err != nil {
			return rpcErrResponse(rpcReq.ID, err)
		}
		return rpcOKResponse(rpcReq.ID, map[string]any{})

	case a2aspec.GetExtendedAgentCard:
		if len(bytes.TrimSpace(rpcReq.Params)) > 0 {
			if _, err := decodeRPCParams[a2aspec.GetExtendedAgentCardRequest]("GetExtendedAgentCardRequest", rpcReq.Params); err != nil {
				return rpcErrResponse(rpcReq.ID, err)
			}
		}
		resp, err := s.GetExtendedAgentCard(ctx, idCtx, agentSlug, gatewayBaseURL)
		if err != nil {
			return rpcErrResponse(rpcReq.ID, err)
		}
		return rpcOKResponse(rpcReq.ID, resp)

	case a2aspec.SendStreamingMessage, a2aspec.SubscribeToTask:
		return rpcErrResponse(rpcReq.ID, ErrUnsupportedOperation(
			fmt.Sprintf("streaming JSON-RPC method %q requires DispatchJSONRPCHTTP", rpcReq.Method),
		))

	default:
		return rpcErrResponse(rpcReq.ID, ErrMethodNotFound(
			fmt.Sprintf("JSON-RPC method %q is not defined in A2A v1.0", rpcReq.Method),
		))
	}
}

// DispatchJSONRPCHTTP handles all 11 A2A v1.0 JSON-RPC 2.0 methods over HTTP, including
// SSE-wrapped JSONRPCResponse streaming for `SendStreamingMessage` and `SubscribeToTask`.
func (s *RouterService) DispatchJSONRPCHTTP(
	w http.ResponseWriter,
	r *http.Request,
	idCtx *domain.IdentityContext,
	agentSlug string,
	body []byte,
	streamSub *StreamSubscriber,
	gatewayBaseURL string,
) {
	ctx := r.Context()
	rpcReq, parseErr := decodeJSONRPCRequest(body)
	if parseErr != nil {
		writeJSONRPCHTTP(w, http.StatusOK, rpcErrResponse(nil, parseErr))
		return
	}

	switch a2aspec.JSONRPCMethod(rpcReq.Method) {
	case a2aspec.SendStreamingMessage:
		req, err := decodeRPCParams[a2aspec.SendMessageRequest]("SendMessageRequest", rpcReq.Params)
		if err != nil {
			writeJSONRPCHTTP(w, http.StatusOK, rpcErrResponse(rpcReq.ID, err))
			return
		}
		flusher, ok := w.(http.Flusher)
		if !ok {
			writeJSONRPCHTTP(w, http.StatusOK, rpcErrResponse(rpcReq.ID, ErrInternal("streaming unsupported")))
			return
		}

		headersStarted := false
		startSSE := func() {
			if headersStarted {
				return
			}
			headersStarted = true
			w.Header().Set("Content-Type", MediaTypeSSE)
			w.Header().Set("Cache-Control", "no-cache")
			w.Header().Set("Connection", "keep-alive")
			w.Header().Set("X-Accel-Buffering", "no")
			w.Header().Set(HeaderA2AVersion, a2aspec.SupportedA2AVersion)
			w.WriteHeader(http.StatusOK)
			flusher.Flush()
		}

		streamErr := s.SendStreamingMessage(ctx, idCtx, agentSlug, req, func(frame *a2aspec.StreamResponse, seq int64) error {
			startSSE()
			payload, _ := json.Marshal(rpcOKResponse(rpcReq.ID, frame))
			writeSSEStreamFrame(w, seq, string(payload))
			flusher.Flush()
			return nil
		})
		if streamErr != nil {
			if !headersStarted {
				writeJSONRPCHTTP(w, http.StatusOK, rpcErrResponse(rpcReq.ID, streamErr))
				return
			}
			payload, _ := json.Marshal(rpcErrResponse(rpcReq.ID, streamErr))
			writeSSEStreamFrame(w, 0, string(payload))
			flusher.Flush()
		}

	case a2aspec.SubscribeToTask:
		req, err := decodeRPCParams[a2aspec.SubscribeToTaskRequest]("SubscribeToTaskRequest", rpcReq.Params)
		if err != nil {
			writeJSONRPCHTTP(w, http.StatusOK, rpcErrResponse(rpcReq.ID, err))
			return
		}
		if streamSub == nil {
			writeJSONRPCHTTP(w, http.StatusOK, rpcErrResponse(rpcReq.ID, ErrUnsupportedOperation("streaming subscriber is not configured")))
			return
		}
		flusher, ok := w.(http.Flusher)
		if !ok {
			writeJSONRPCHTTP(w, http.StatusOK, rpcErrResponse(rpcReq.ID, ErrInternal("streaming unsupported")))
			return
		}
		ch, err := streamSub.SubscribeChannel(ctx, idCtx, agentSlug, req.Id, 0)
		if err != nil {
			writeJSONRPCHTTP(w, http.StatusOK, rpcErrResponse(rpcReq.ID, err))
			return
		}
		w.Header().Set("Content-Type", MediaTypeSSE)
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("X-Accel-Buffering", "no")
		w.Header().Set(HeaderA2AVersion, a2aspec.SupportedA2AVersion)
		w.WriteHeader(http.StatusOK)
		flusher.Flush()

		for env := range ch {
			payload, _ := json.Marshal(&JSONRPCResponse{
				JSONRPC: "2.0",
				ID:      rpcReq.ID,
				Result:  env.StreamResponse,
			})
			writeSSEStreamFrame(w, env.EventSeq, string(payload))
			flusher.Flush()
		}

	default:
		resp := s.DispatchJSONRPC(ctx, idCtx, agentSlug, body, gatewayBaseURL)
		writeJSONRPCHTTP(w, http.StatusOK, resp)
	}
}

func decodeJSONRPCRequest(body []byte) (*JSONRPCRequest, error) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return nil, ErrParse("empty JSON-RPC request body")
	}
	var rpcReq JSONRPCRequest
	if err := json.Unmarshal(trimmed, &rpcReq); err != nil {
		return nil, ErrParse(fmt.Sprintf("invalid JSON-RPC payload: %v", err))
	}
	if rpcReq.JSONRPC != "2.0" {
		return nil, ErrInvalidRequest("jsonrpc field MUST equal \"2.0\"")
	}
	if rpcReq.Method == "" {
		return nil, ErrInvalidRequest("JSON-RPC method is required")
	}
	return &rpcReq, nil
}

func decodeRPCParams[T any](schemaName string, rawParams json.RawMessage) (*T, error) {
	trimmed := bytes.TrimSpace(rawParams)
	if len(trimmed) == 0 {
		trimmed = []byte("{}")
	}
	decoded, err := a2aspec.DecodeStrict[T](schemaName, trimmed)
	if err != nil {
		return nil, ErrInvalidParams(fmt.Sprintf("invalid %s params: %v", schemaName, err))
	}
	return decoded, nil
}

func rpcOKResponse(id json.RawMessage, result any) *JSONRPCResponse {
	return &JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	}
}

func rpcErrResponse(id json.RawMessage, err error) *JSONRPCResponse {
	a2aErr := NormalizeA2AError(err)
	return &JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error:   a2aErr.ToJSONRPCErrorMap(),
	}
}

func writeJSONRPCHTTP(w http.ResponseWriter, statusCode int, resp *JSONRPCResponse) {
	w.Header().Set("Content-Type", MediaTypeJSON)
	w.Header().Set(HeaderA2AVersion, a2aspec.SupportedA2AVersion)
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(resp)
}
