package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/goroute-ai/ai-gateway-go/internal/a2a"
	a2aspec "github.com/goroute-ai/ai-gateway-go/internal/a2a/spec"
	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

const maxA2ARequestBodyBytes int64 = 10 * 1024 * 1024

// a2aHTTPAdapter implements every operation generated from docs/openapi/a2a.openapi.yaml
// (a2aspec.ServerInterface), translating OpenAPI parameters into a2a.RouterService calls.
type a2aHTTPAdapter struct {
	srv *GatewayServer
}

var _ a2aspec.ServerInterface = (*a2aHTTPAdapter)(nil)

func (s *GatewayServer) newA2AHTTPAdapter() *a2aHTTPAdapter {
	return &a2aHTTPAdapter{srv: s}
}

// a2aDataPlaneAuthMiddleware enforces full DataPlaneMiddleware on all A2A execution routes
// while allowing optional authentication on per-agent /.well-known/agent-card.json discovery
// (where IsPublicCard agents remain discoverable and private agents fail closed).
func (s *GatewayServer) a2aDataPlaneAuthMiddleware() func(http.Handler) http.Handler {
	dp := auth.DataPlaneMiddleware(s.authSvc, s.rbac)
	return func(next http.Handler) http.Handler {
		protected := dp(next)
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/.well-known/agent-card.json") {
				next.ServeHTTP(w, r)
				return
			}
			protected.ServeHTTP(w, r)
		})
	}
}

// handleA2AWellKnownCard serves `GET /.well-known/agent-card.json` (and optional legacy discovery).
func (s *GatewayServer) handleA2AWellKnownCard(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Gateway-Request-Id", gatewayRequestID(r))
	if !s.cfg.A2A.Enabled {
		a2a.WriteHTTPError(w, a2a.ErrUnsupportedOperation("A2A protocol is disabled"))
		return
	}
	idCtx, err := s.resolveOptionalA2AIdentity(r)
	if err != nil {
		domain.WriteHTTPError(w, err)
		return
	}
	defaultSlug := chi.URLParam(r, "agentSlug")
	a2a.ServeWellKnownAgentCard(w, r, s.repo, s.a2aSigner, s.rbac, idCtx, s.serverBaseURL(r), defaultSlug)
}

func (s *GatewayServer) resolveOptionalA2AIdentity(r *http.Request) (*domain.IdentityContext, error) {
	if s == nil || s.authSvc == nil {
		return nil, nil
	}
	cred, err := auth.ExtractCredentials(r, s.authSvc.ExtractorOptions())
	if err != nil {
		return nil, err
	}
	if cred.Token == "" {
		return nil, nil
	}
	var idCtx *domain.IdentityContext
	if s.authSvc.DataPlaneResolver() != nil {
		idCtx, err = s.authSvc.DataPlaneResolver().ResolveRequest(r.Context(), r)
		if err != nil {
			return nil, err
		}
	} else {
		idCtx, err = s.authSvc.AuthenticateVirtualKey(r.Context(), cred.Token)
		if err != nil {
			return nil, err
		}
		if s.rbac != nil {
			idCtx = s.rbac.EnrichIdentityWithAccessRules(r.Context(), idCtx)
		}
	}
	if idCtx != nil {
		idCtx, err = auth.ApplyDelegatedCallerNarrowing(r.Context(), s.repo, idCtx, r)
		if err != nil {
			return nil, err
		}
	}
	return idCtx, nil
}

func a2aChiErrorHandler(w http.ResponseWriter, _ *http.Request, err error) {
	a2a.WriteHTTPError(w, a2a.ErrInvalidParams(err.Error()))
}

func (a *a2aHTTPAdapter) prepareCall(
	w http.ResponseWriter,
	r *http.Request,
	tenant string,
	requireBodyMediaType bool,
	requireHTTPJSON bool,
) (context.Context, *domain.IdentityContext, string, bool) {
	w.Header().Set("X-Gateway-Request-Id", gatewayRequestID(r))
	if !a.srv.cfg.A2A.Enabled {
		a2a.WriteHTTPError(w, a2a.ErrUnsupportedOperation("A2A protocol is disabled"))
		return nil, nil, "", false
	}
	if requireHTTPJSON && !a.srv.cfg.A2A.EnableHTTPJSON {
		a2a.WriteHTTPError(w, a2a.ErrUnsupportedOperation("HTTP+JSON binding is disabled"))
		return nil, nil, "", false
	}

	callOpts, err := a2a.ParseAndValidateHeaders(r, tenant, requireBodyMediaType)
	if err != nil {
		a2a.WriteHTTPError(w, err)
		return nil, nil, "", false
	}

	agentSlug := chi.URLParam(r, "agentSlug")
	if strings.TrimSpace(agentSlug) == "" {
		a2a.WriteHTTPError(w, a2a.ErrInvalidParams("agentSlug is required in URL path"))
		return nil, nil, "", false
	}

	idCtx := auth.IdentityFromContext(r.Context())
	if idCtx == nil {
		a2a.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusUnauthorized,
			Type:       domain.ErrorTypeAuthentication,
			Code:       "unauthenticated",
			Message:    "Identity context required for A2A communication",
		})
		return nil, nil, "", false
	}

	ctx := a2a.ContextWithCallOptions(r.Context(), callOpts)
	return ctx, idCtx, agentSlug, true
}

func (a *a2aHTTPAdapter) GetWellKnownAgentCard(w http.ResponseWriter, r *http.Request) {
	a.srv.handleA2AWellKnownCard(w, r)
}

func (a *a2aHTTPAdapter) DispatchJsonRpc(w http.ResponseWriter, r *http.Request, _ a2aspec.DispatchJsonRpcParams) {
	a.dispatchJSONRPC(w, r, "")
}

func (a *a2aHTTPAdapter) DispatchTenantJsonRpc(w http.ResponseWriter, r *http.Request, tenant a2aspec.TenantPathParam, _ a2aspec.DispatchTenantJsonRpcParams) {
	a.dispatchJSONRPC(w, r, tenant)
}

func (a *a2aHTTPAdapter) dispatchJSONRPC(w http.ResponseWriter, r *http.Request, tenant string) {
	w.Header().Set("X-Gateway-Request-Id", gatewayRequestID(r))
	if !a.srv.cfg.A2A.Enabled {
		a2a.WriteHTTPError(w, a2a.ErrUnsupportedOperation("A2A protocol is disabled"))
		return
	}
	if !a.srv.cfg.A2A.EnableJSONRPC {
		a2a.WriteHTTPError(w, a2a.ErrUnsupportedOperation("JSON-RPC 2.0 binding is disabled"))
		return
	}

	ctx, idCtx, agentSlug, ok := a.prepareCall(w, r, tenant, true, false)
	if !ok {
		return
	}
	r = r.WithContext(ctx)

	bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, maxA2ARequestBodyBytes+1))
	if err != nil {
		a2a.WriteHTTPError(w, a2a.ErrInvalidRequest(fmt.Sprintf("read request body: %v", err)))
		return
	}
	if int64(len(bodyBytes)) > maxA2ARequestBodyBytes {
		a2a.WriteHTTPError(w, &a2a.A2AError{
			HTTPStatus:  http.StatusRequestEntityTooLarge,
			RPCStatus:   "INVALID_ARGUMENT",
			JSONRPCCode: a2a.CodeInvalidParams,
			Message:     fmt.Sprintf("request body exceeds %d bytes", maxA2ARequestBodyBytes),
		})
		return
	}

	a.srv.a2aRouter.DispatchJSONRPCHTTP(w, r, idCtx, agentSlug, bodyBytes, a.srv.a2aStreamSub, a.srv.serverBaseURL(r))
}

func (a *a2aHTTPAdapter) SendMessage(w http.ResponseWriter, r *http.Request, _ a2aspec.SendMessageParams) {
	a.sendMessage(w, r, "")
}

func (a *a2aHTTPAdapter) SendTenantMessage(w http.ResponseWriter, r *http.Request, tenant a2aspec.TenantPathParam, _ a2aspec.SendTenantMessageParams) {
	a.sendMessage(w, r, tenant)
}

func (a *a2aHTTPAdapter) sendMessage(w http.ResponseWriter, r *http.Request, tenant string) {
	ctx, idCtx, agentSlug, ok := a.prepareCall(w, r, tenant, true, true)
	if !ok {
		return
	}

	req, err := a2a.ReadStrictJSONBody[a2aspec.SendMessageRequest](r, maxA2ARequestBodyBytes, "SendMessageRequest")
	if err != nil {
		a2a.WriteHTTPError(w, err)
		return
	}
	if err := bindTenantToSendRequest(req, tenant); err != nil {
		a2a.WriteHTTPError(w, err)
		return
	}

	resp, err := a.srv.a2aRouter.SendMessage(ctx, idCtx, agentSlug, req)
	if err != nil {
		a2a.WriteHTTPError(w, err)
		return
	}
	if err := a2a.WriteJSONResponse(w, r, http.StatusOK, resp); err != nil {
		a2a.WriteHTTPError(w, err)
	}
}

func (a *a2aHTTPAdapter) SendStreamingMessage(w http.ResponseWriter, r *http.Request, _ a2aspec.SendStreamingMessageParams) {
	a.sendStreamingMessage(w, r, "")
}

func (a *a2aHTTPAdapter) SendTenantStreamingMessage(w http.ResponseWriter, r *http.Request, tenant a2aspec.TenantPathParam, _ a2aspec.SendTenantStreamingMessageParams) {
	a.sendStreamingMessage(w, r, tenant)
}

func (a *a2aHTTPAdapter) sendStreamingMessage(w http.ResponseWriter, r *http.Request, tenant string) {
	ctx, idCtx, agentSlug, ok := a.prepareCall(w, r, tenant, true, true)
	if !ok {
		return
	}

	req, err := a2a.ReadStrictJSONBody[a2aspec.SendMessageRequest](r, maxA2ARequestBodyBytes, "SendMessageRequest")
	if err != nil {
		a2a.WriteHTTPError(w, err)
		return
	}
	if err := bindTenantToSendRequest(req, tenant); err != nil {
		a2a.WriteHTTPError(w, err)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		a2a.WriteHTTPError(w, a2a.ErrInternal("streaming unsupported by response writer"))
		return
	}

	headersStarted := false
	startSSE := func() {
		if headersStarted {
			return
		}
		headersStarted = true
		w.Header().Set("Content-Type", a2a.MediaTypeSSE)
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("X-Accel-Buffering", "no")
		w.Header().Set(a2a.HeaderA2AVersion, a2aspec.SupportedA2AVersion)
		w.WriteHeader(http.StatusOK)
		flusher.Flush()
	}

	streamErr := a.srv.a2aRouter.SendStreamingMessage(ctx, idCtx, agentSlug, req, func(frame *a2aspec.StreamResponse, seq int64) error {
		startSSE()
		payload, mErr := json.Marshal(frame)
		if mErr != nil {
			return mErr
		}
		if seq > 0 {
			_, _ = fmt.Fprintf(w, "id: %d\n", seq)
		}
		_, _ = fmt.Fprintf(w, "data: %s\n\n", string(payload))
		flusher.Flush()
		return nil
	})
	if streamErr != nil {
		if !headersStarted {
			a2a.WriteHTTPError(w, streamErr)
			return
		}
		errBody := a2a.NormalizeA2AError(streamErr).MarshalHTTPBody()
		_, _ = fmt.Fprintf(w, "event: error\ndata: %s\n\n", string(errBody))
		flusher.Flush()
	}
}

func (a *a2aHTTPAdapter) ListTasks(w http.ResponseWriter, r *http.Request, params a2aspec.ListTasksParams) {
	a.listTasks(w, r, "", params)
}

func (a *a2aHTTPAdapter) ListTenantTasks(w http.ResponseWriter, r *http.Request, tenant a2aspec.TenantPathParam, params a2aspec.ListTenantTasksParams) {
	a.listTasks(w, r, tenant, a2aspec.ListTasksParams(params))
}

func (a *a2aHTTPAdapter) listTasks(w http.ResponseWriter, r *http.Request, tenant string, params a2aspec.ListTasksParams) {
	ctx, idCtx, agentSlug, ok := a.prepareCall(w, r, tenant, false, true)
	if !ok {
		return
	}

	req := &a2aspec.ListTasksRequest{
		ContextId:            params.ContextId,
		Status:               params.Status,
		PageSize:             params.PageSize,
		PageToken:            params.PageToken,
		HistoryLength:        params.HistoryLength,
		StatusTimestampAfter: params.StatusTimestampAfter,
		IncludeArtifacts:     params.IncludeArtifacts,
	}
	if tenant != "" {
		req.Tenant = &tenant
	}

	resp, err := a.srv.a2aRouter.ListTasks(ctx, idCtx, agentSlug, req)
	if err != nil {
		a2a.WriteHTTPError(w, err)
		return
	}
	if err := a2a.WriteJSONResponse(w, r, http.StatusOK, resp); err != nil {
		a2a.WriteHTTPError(w, err)
	}
}

func (a *a2aHTTPAdapter) GetTask(w http.ResponseWriter, r *http.Request, id a2aspec.TaskIdParam, params a2aspec.GetTaskParams) {
	a.getTask(w, r, "", id, params.HistoryLength)
}

func (a *a2aHTTPAdapter) GetTenantTask(w http.ResponseWriter, r *http.Request, tenant a2aspec.TenantPathParam, id a2aspec.TaskIdParam, params a2aspec.GetTenantTaskParams) {
	a.getTask(w, r, tenant, id, params.HistoryLength)
}

func (a *a2aHTTPAdapter) getTask(w http.ResponseWriter, r *http.Request, tenant, taskID string, historyLen *int32) {
	ctx, idCtx, agentSlug, ok := a.prepareCall(w, r, tenant, false, true)
	if !ok {
		return
	}

	task, err := a.srv.a2aRouter.GetTask(ctx, idCtx, agentSlug, taskID, historyLen)
	if err != nil {
		a2a.WriteHTTPError(w, err)
		return
	}
	if err := a2a.WriteJSONResponse(w, r, http.StatusOK, task); err != nil {
		a2a.WriteHTTPError(w, err)
	}
}

func (a *a2aHTTPAdapter) CancelTask(w http.ResponseWriter, r *http.Request, id a2aspec.TaskIdParam, _ a2aspec.CancelTaskParams) {
	a.cancelTask(w, r, "", id)
}

func (a *a2aHTTPAdapter) CancelTenantTask(w http.ResponseWriter, r *http.Request, tenant a2aspec.TenantPathParam, id a2aspec.TaskIdParam, _ a2aspec.CancelTenantTaskParams) {
	a.cancelTask(w, r, tenant, id)
}

func (a *a2aHTTPAdapter) cancelTask(w http.ResponseWriter, r *http.Request, tenant, taskID string) {
	ctx, idCtx, agentSlug, ok := a.prepareCall(w, r, tenant, true, true)
	if !ok {
		return
	}

	task, err := a.srv.a2aRouter.CancelTask(ctx, idCtx, agentSlug, taskID)
	if err != nil {
		a2a.WriteHTTPError(w, err)
		return
	}
	if err := a2a.WriteJSONResponse(w, r, http.StatusOK, task); err != nil {
		a2a.WriteHTTPError(w, err)
	}
}

func (a *a2aHTTPAdapter) SubscribeToTask(w http.ResponseWriter, r *http.Request, id a2aspec.TaskIdParam, _ a2aspec.SubscribeToTaskParams) {
	a.subscribeToTask(w, r, "", id, false)
}

func (a *a2aHTTPAdapter) SubscribeToTaskPost(w http.ResponseWriter, r *http.Request, id a2aspec.TaskIdParam, _ a2aspec.SubscribeToTaskPostParams) {
	a.subscribeToTask(w, r, "", id, true)
}

func (a *a2aHTTPAdapter) SubscribeToTenantTask(w http.ResponseWriter, r *http.Request, tenant a2aspec.TenantPathParam, id a2aspec.TaskIdParam, _ a2aspec.SubscribeToTenantTaskParams) {
	a.subscribeToTask(w, r, tenant, id, false)
}

func (a *a2aHTTPAdapter) SubscribeToTenantTaskPost(w http.ResponseWriter, r *http.Request, tenant a2aspec.TenantPathParam, id a2aspec.TaskIdParam, _ a2aspec.SubscribeToTenantTaskPostParams) {
	a.subscribeToTask(w, r, tenant, id, true)
}

func (a *a2aHTTPAdapter) subscribeToTask(w http.ResponseWriter, r *http.Request, tenant, taskID string, isPostCompat bool) {
	if isPostCompat && !a.srv.cfg.A2A.EnableSubscribePostCompat {
		w.Header().Set("X-Gateway-Request-Id", gatewayRequestID(r))
		a2a.WriteHTTPError(w, a2a.ErrUnsupportedOperation("POST :subscribe compat is disabled; use GET /tasks/{id}:subscribe"))
		return
	}

	ctx, idCtx, agentSlug, ok := a.prepareCall(w, r, tenant, isPostCompat, true)
	if !ok {
		return
	}
	if a.srv.a2aStreamSub == nil {
		a2a.WriteHTTPError(w, a2a.ErrUnsupportedOperation("A2A task stream subscriber is not configured"))
		return
	}

	a.srv.a2aStreamSub.SubscribeTaskStream(w, r.WithContext(ctx), idCtx, agentSlug, taskID)
}

func (a *a2aHTTPAdapter) CreateTaskPushNotificationConfig(w http.ResponseWriter, r *http.Request, taskID a2aspec.TaskIdParentParam, _ a2aspec.CreateTaskPushNotificationConfigParams) {
	a.createPushConfig(w, r, "", taskID)
}

func (a *a2aHTTPAdapter) CreateTenantTaskPushNotificationConfig(w http.ResponseWriter, r *http.Request, tenant a2aspec.TenantPathParam, taskID a2aspec.TaskIdParentParam, _ a2aspec.CreateTenantTaskPushNotificationConfigParams) {
	a.createPushConfig(w, r, tenant, taskID)
}

func (a *a2aHTTPAdapter) createPushConfig(w http.ResponseWriter, r *http.Request, tenant, taskID string) {
	ctx, idCtx, agentSlug, ok := a.prepareCall(w, r, tenant, true, true)
	if !ok {
		return
	}

	reqCfg, err := a2a.ReadStrictJSONBody[a2aspec.TaskPushNotificationConfig](r, maxA2ARequestBodyBytes, "TaskPushNotificationConfig")
	if err != nil {
		a2a.WriteHTTPError(w, err)
		return
	}
	if reqCfg.TaskId != nil && strings.TrimSpace(*reqCfg.TaskId) != "" && *reqCfg.TaskId != taskID {
		a2a.WriteHTTPError(w, a2a.ErrInvalidParams(fmt.Sprintf("body taskId %q does not match path taskId %q", *reqCfg.TaskId, taskID)))
		return
	}
	if tenant != "" {
		if reqCfg.Tenant != nil && strings.TrimSpace(*reqCfg.Tenant) != "" && *reqCfg.Tenant != tenant {
			a2a.WriteHTTPError(w, a2a.ErrInvalidParams(fmt.Sprintf("body tenant %q does not match path tenant %q", *reqCfg.Tenant, tenant)))
			return
		}
		t := tenant
		reqCfg.Tenant = &t
	}

	created, err := a.srv.a2aRouter.CreateTaskPushNotificationConfig(ctx, idCtx, agentSlug, taskID, reqCfg)
	if err != nil {
		a2a.WriteHTTPError(w, err)
		return
	}
	if err := a2a.WriteJSONResponse(w, r, http.StatusCreated, created); err != nil {
		a2a.WriteHTTPError(w, err)
	}
}

func (a *a2aHTTPAdapter) ListTaskPushNotificationConfigs(w http.ResponseWriter, r *http.Request, taskID a2aspec.TaskIdParentParam, params a2aspec.ListTaskPushNotificationConfigsParams) {
	a.listPushConfigs(w, r, "", taskID, params.PageSize, params.PageToken)
}

func (a *a2aHTTPAdapter) ListTenantTaskPushNotificationConfigs(w http.ResponseWriter, r *http.Request, tenant a2aspec.TenantPathParam, taskID a2aspec.TaskIdParentParam, params a2aspec.ListTenantTaskPushNotificationConfigsParams) {
	a.listPushConfigs(w, r, tenant, taskID, params.PageSize, params.PageToken)
}

func (a *a2aHTTPAdapter) listPushConfigs(w http.ResponseWriter, r *http.Request, tenant, taskID string, pageSize *int32, pageToken *string) {
	ctx, idCtx, agentSlug, ok := a.prepareCall(w, r, tenant, false, true)
	if !ok {
		return
	}

	resp, err := a.srv.a2aRouter.ListTaskPushNotificationConfigs(ctx, idCtx, agentSlug, taskID, pageSize, pageToken)
	if err != nil {
		a2a.WriteHTTPError(w, err)
		return
	}
	if err := a2a.WriteJSONResponse(w, r, http.StatusOK, resp); err != nil {
		a2a.WriteHTTPError(w, err)
	}
}

func (a *a2aHTTPAdapter) GetTaskPushNotificationConfig(w http.ResponseWriter, r *http.Request, taskID a2aspec.TaskIdParentParam, id a2aspec.PushConfigIdParam, _ a2aspec.GetTaskPushNotificationConfigParams) {
	a.getPushConfig(w, r, "", taskID, id)
}

func (a *a2aHTTPAdapter) GetTenantTaskPushNotificationConfig(w http.ResponseWriter, r *http.Request, tenant a2aspec.TenantPathParam, taskID a2aspec.TaskIdParentParam, id a2aspec.PushConfigIdParam, _ a2aspec.GetTenantTaskPushNotificationConfigParams) {
	a.getPushConfig(w, r, tenant, taskID, id)
}

func (a *a2aHTTPAdapter) getPushConfig(w http.ResponseWriter, r *http.Request, tenant, taskID, configID string) {
	ctx, idCtx, agentSlug, ok := a.prepareCall(w, r, tenant, false, true)
	if !ok {
		return
	}

	cfg, err := a.srv.a2aRouter.GetTaskPushNotificationConfig(ctx, idCtx, agentSlug, taskID, configID)
	if err != nil {
		a2a.WriteHTTPError(w, err)
		return
	}
	if err := a2a.WriteJSONResponse(w, r, http.StatusOK, cfg); err != nil {
		a2a.WriteHTTPError(w, err)
	}
}

func (a *a2aHTTPAdapter) DeleteTaskPushNotificationConfig(w http.ResponseWriter, r *http.Request, taskID a2aspec.TaskIdParentParam, id a2aspec.PushConfigIdParam, _ a2aspec.DeleteTaskPushNotificationConfigParams) {
	a.deletePushConfig(w, r, "", taskID, id)
}

func (a *a2aHTTPAdapter) DeleteTenantTaskPushNotificationConfig(w http.ResponseWriter, r *http.Request, tenant a2aspec.TenantPathParam, taskID a2aspec.TaskIdParentParam, id a2aspec.PushConfigIdParam, _ a2aspec.DeleteTenantTaskPushNotificationConfigParams) {
	a.deletePushConfig(w, r, tenant, taskID, id)
}

func (a *a2aHTTPAdapter) deletePushConfig(w http.ResponseWriter, r *http.Request, tenant, taskID, configID string) {
	ctx, idCtx, agentSlug, ok := a.prepareCall(w, r, tenant, false, true)
	if !ok {
		return
	}

	if err := a.srv.a2aRouter.DeleteTaskPushNotificationConfig(ctx, idCtx, agentSlug, taskID, configID); err != nil {
		a2a.WriteHTTPError(w, err)
		return
	}
	if err := a2a.WriteJSONResponse(w, r, http.StatusOK, map[string]any{}); err != nil {
		a2a.WriteHTTPError(w, err)
	}
}

func (a *a2aHTTPAdapter) GetExtendedAgentCard(w http.ResponseWriter, r *http.Request, _ a2aspec.GetExtendedAgentCardParams) {
	a.getExtendedAgentCard(w, r, "")
}

func (a *a2aHTTPAdapter) GetTenantExtendedAgentCard(w http.ResponseWriter, r *http.Request, tenant a2aspec.TenantPathParam, _ a2aspec.GetTenantExtendedAgentCardParams) {
	a.getExtendedAgentCard(w, r, tenant)
}

func (a *a2aHTTPAdapter) getExtendedAgentCard(w http.ResponseWriter, r *http.Request, tenant string) {
	ctx, idCtx, agentSlug, ok := a.prepareCall(w, r, tenant, false, true)
	if !ok {
		return
	}

	card, err := a.srv.a2aRouter.GetExtendedAgentCard(ctx, idCtx, agentSlug, a.srv.serverBaseURL(r))
	if err != nil {
		a2a.WriteHTTPError(w, err)
		return
	}
	if err := a2a.WriteJSONResponse(w, r, http.StatusOK, card); err != nil {
		a2a.WriteHTTPError(w, err)
	}
}

func bindTenantToSendRequest(req *a2aspec.SendMessageRequest, pathTenant string) error {
	if req == nil || strings.TrimSpace(pathTenant) == "" {
		return nil
	}
	if req.Tenant != nil && strings.TrimSpace(*req.Tenant) != "" && *req.Tenant != pathTenant {
		return a2a.ErrInvalidParams(fmt.Sprintf("body tenant %q does not match path tenant %q", *req.Tenant, pathTenant))
	}
	t := pathTenant
	req.Tenant = &t
	return nil
}

func (s *GatewayServer) serverBaseURL(r *http.Request) string {
	return s.canonicalBaseURL(r)
}

// Keep time import referenced only if needed by future helpers.
var _ = time.RFC3339
