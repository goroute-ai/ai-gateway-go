package server

import (
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"runtime"
	"slices"
	"strings"
	"sync"
	"time"
	"weak"

	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/guardrails"
	"github.com/goroute-ai/ai-gateway-go/internal/guardrails/drivers"
	"github.com/goroute-ai/ai-gateway-go/internal/observability"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

var serverPipelines sync.Map

type serverPipelineEntry struct {
	server   weak.Pointer[GatewayServer]
	pipeline *guardrails.Pipeline
}

// GuardrailPipeline returns the unified multi-guardrail pipeline for this GatewayServer,
// initializing it lazily on first use and binding Vault decryption and audit logging hooks.
func (s *GatewayServer) GuardrailPipeline() *guardrails.Pipeline {
	if s == nil {
		return nil
	}
	key := reflect.ValueOf(s).Pointer()
	if existing, ok := serverPipelines.Load(key); ok {
		if entry, ok := existing.(*serverPipelineEntry); ok && entry.server.Value() == s && entry.pipeline != nil {
			return entry.pipeline
		}
	}

	opts := []guardrails.PipelineOption{
		guardrails.WithAuditHook(func(ctx context.Context, hook domain.GuardrailHook, prc guardrails.PipelineRequestContext, res *domain.GuardrailEvalResult) {
			s.recordGuardrailAuditHook(ctx, hook, prc, res)
		}),
	}
	if s.vault != nil {
		opts = append(opts, guardrails.WithSecretDecryptor(func(_ context.Context, def *domain.GuardrailDefinition) (map[string]any, error) {
			if def == nil || strings.TrimSpace(def.EncryptedSecrets) == "" {
				return nil, nil
			}
			plain, err := s.vault.DecryptString(def.EncryptedSecrets, def.EncryptedDEK)
			if err != nil {
				return nil, err
			}
			var decoded map[string]any
			if err := json.Unmarshal([]byte(plain), &decoded); err == nil && decoded != nil {
				return decoded, nil
			}
			return map[string]any{"secret": plain}, nil
		}))
	}

	registryOpts := make([]drivers.RegistryOption, 0, 4)
	if s.netPolicy != nil {
		registryOpts = append(registryOpts, drivers.WithSSRFPolicy(s.netPolicy))
	}
	if tpRepo, ok := s.repo.(storage.ToolPolicyRepository); ok && tpRepo != nil {
		registryOpts = append(registryOpts, drivers.WithToolPolicyRepository(tpRepo))
	}
	if s.repo != nil {
		registryOpts = append(registryOpts, drivers.WithMCPServerRegistry(s.repo))
	}
	if s.reliability != nil {
		registryOpts = append(registryOpts, drivers.WithChatExecutor(drivers.ChatExecutorFunc(
			func(ctx context.Context, idCtx *domain.IdentityContext, req *domain.CanonicalChatRequest) (*domain.CanonicalChatResponse, error) {
				resp, _, err := s.reliability.ExecuteChat(ctx, idCtx, req)
				return resp, err
			},
		)))
	}
	driverRegistry := drivers.NewRegistry(registryOpts...)

	created := guardrails.NewPipeline(s.guardrails, s.repo, opts...)
	created.SetDriverLookup(s.wrapGuardrailDriverLookup(driverRegistry.Build))
	entry := &serverPipelineEntry{
		server:   weak.Make(s),
		pipeline: created,
	}
	actual, loaded := serverPipelines.LoadOrStore(key, entry)
	if loaded {
		if existing, ok := actual.(*serverPipelineEntry); ok && existing.server.Value() == s && existing.pipeline != nil {
			return existing.pipeline
		}
		serverPipelines.Store(key, entry)
	}
	runtime.AddCleanup(s, func(k uintptr) {
		if cur, ok := serverPipelines.Load(k); ok {
			if ce, ok := cur.(*serverPipelineEntry); ok && ce == entry {
				serverPipelines.Delete(k)
			}
		}
	}, key)
	return created
}

func guardrailStreamBlockedError() *domain.GatewayError {
	return &domain.GatewayError{
		StatusCode: http.StatusBadGateway,
		Type:       domain.ErrorTypeServer,
		Code:       "guardrail_blocked",
		Message:    "Stream output blocked by security guardrail policy",
	}
}

func buildGuardrailRequestContext(r *http.Request, idCtx *domain.IdentityContext, req *domain.CanonicalChatRequest) guardrails.PipelineRequestContext {
	prc := guardrails.PipelineRequestContext{
		RequestHeaders: sanitizeGuardrailHeaders(r),
	}
	if idCtx != nil {
		prc.OrgID = idCtx.OrgID
		prc.TeamID = idCtx.TeamID
		prc.VirtualKeyID = idCtx.VirtualKeyID
		prc.EndUserID = idCtx.UserID
		if role := strings.TrimSpace(string(idCtx.Role)); role != "" {
			prc.CallerRoles = []string{role}
		}
	}
	if req != nil {
		// Strip any caller-spoofed internal guardrail origin marker from inbound request metadata.
		drivers.StripInternalGuardrailOriginStringMetadata(req.Metadata)
		drivers.StripInternalGuardrailOriginMetadata(req.ExtraParams)
		prc.RequestID = req.RequestID
		prc.Model = req.Model
		prc.IsStreaming = req.Stream
		if req.User != "" && prc.EndUserID == "" {
			prc.EndUserID = req.User
		}
		if req.GoRouteExtensions != nil {
			prc.TraceID = req.GoRouteExtensions.ContextID
			prc.Tags = append([]string(nil), req.GoRouteExtensions.Tags...)
			prc.RequestOverrides = append([]domain.GuardrailRequestOverride(nil), req.GoRouteExtensions.Guardrails...)
			if req.GoRouteExtensions.TaskID != "" {
				prc.Metadata = map[string]any{"task_id": req.GoRouteExtensions.TaskID}
			}
		}
	}
	drivers.StripInternalGuardrailOriginMetadata(prc.Metadata)
	if r != nil && prc.TraceID == "" {
		prc.TraceID = observability.TraceFromContext(r.Context()).TraceID
	}
	return prc
}

func sanitizeGuardrailHeaders(r *http.Request) map[string]string {
	if r == nil || len(r.Header) == 0 {
		return nil
	}
	out := make(map[string]string)
	for k, vals := range r.Header {
		lk := strings.ToLower(k)
		if lk == "authorization" || lk == "x-api-key" || lk == "cookie" || lk == "proxy-authorization" {
			continue
		}
		if len(vals) > 0 {
			out[k] = vals[0]
		}
	}
	return out
}

func (s *GatewayServer) evaluateChatInputGuardrails(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	idCtx *domain.IdentityContext,
	req *domain.CanonicalChatRequest,
	resource string,
) (guardrails.PipelineRequestContext, bool, error) {
	prc := buildGuardrailRequestContext(r, idCtx, req)
	if drivers.IsInternalGuardrailOrigin(ctx) {
		return prc, false, nil
	}
	return s.evaluatePreCallWithRoute(ctx, w, r, idCtx, req, prc, resource)
}

func (s *GatewayServer) evaluatePreCallWithRoute(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	idCtx *domain.IdentityContext,
	req *domain.CanonicalChatRequest,
	prc guardrails.PipelineRequestContext,
	resource string,
) (guardrails.PipelineRequestContext, bool, error) {
	var sessionID string
	if req != nil && req.GoRouteExtensions != nil {
		sessionID = strings.TrimSpace(req.GoRouteExtensions.SessionID)
	}
	aff := s.affinityStore
	if aff == nil && s.reliability != nil {
		aff = s.reliability.AffinityStore()
	}
	var pinnedRoute string
	if sessionID != "" && aff != nil && prc.OrgID != "" {
		pinnedRoute = aff.GetSensitiveRoute(ctx, prc.OrgID, sessionID)
	}
	pipeline := s.GuardrailPipeline()
	out, err := pipeline.EvaluatePreCall(ctx, prc, req)
	redacted := false
	if out != nil {
		redacted = out.Redacted
	}
	routeTarget := ""
	if out != nil {
		routeTarget = strings.TrimSpace(out.RouteTarget)
	}
	if routeTarget == "" {
		routeTarget = strings.TrimSpace(pinnedRoute)
	}
	if err == nil && routeTarget != "" {
		if idCtx != nil && s.rbac != nil {
			if rbacErr := s.rbac.AuthorizeRequestedModel(idCtx, routeTarget); rbacErr != nil {
				status := http.StatusForbidden
				if ge, ok := rbacErr.(*domain.GatewayError); ok && ge.StatusCode != 0 {
					status = ge.StatusCode
				}
				if s.collector != nil {
					s.collector.Record(observability.RequestObservation{
						StatusCode:       status,
						GuardrailBlocked: true,
					})
				}
				return prc, redacted, rbacErr
			}
		}
		if req != nil {
			req.Model = routeTarget
		}
		prc.Model = routeTarget
		if w != nil {
			w.Header().Set("X-Gateway-Guardrail-Action", string(domain.GuardrailActionRoute))
			w.Header().Set("X-Gateway-Sensitive-Route", routeTarget)
		}
		sessionPinned := false
		if sessionID != "" && aff != nil && prc.OrgID != "" {
			aff.SetSensitiveRoute(ctx, prc.OrgID, sessionID, routeTarget)
			sessionPinned = true
		}
		var violations []string
		if out != nil {
			violations = out.Violations
		}
		s.emitThrottledGuardrailRouteAudit(ctx, prc, resource, routeTarget, sessionPinned, violations)
		return prc, redacted, nil
	}
	if out != nil && (len(out.Violations) > 0 || out.Redacted || err != nil) {
		redacted = out.Redacted
		action := out.AppliedAction
		if action == "" && err != nil {
			action = domain.GuardrailActionBlock
		}
		if w != nil && action != "" {
			w.Header().Set("X-Gateway-Guardrail-Action", string(action))
		}
		if s.repo != nil && prc.OrgID != "" {
			_ = s.repo.RecordAuditLog(ctx, &domain.AuditLog{
				OrgID:      prc.OrgID,
				ActorID:    prc.VirtualKeyID,
				Action:     "guardrail.triggered",
				Resource:   resource,
				ResourceID: prc.RequestID,
				Details: map[string]any{
					"action":     action,
					"violations": out.Violations,
					"redacted":   out.Redacted,
					"trace_id":   prc.TraceID,
				},
			})
		}
	}
	if err != nil {
		status := http.StatusBadRequest
		if ge, ok := err.(*domain.GatewayError); ok && ge.StatusCode != 0 {
			status = ge.StatusCode
		}
		if s.collector != nil {
			s.collector.Record(observability.RequestObservation{
				StatusCode:       status,
				GuardrailBlocked: true,
			})
		}
		return prc, redacted, err
	}
	return prc, redacted, nil
}

const guardrailRouteAuditWindow = 60 * time.Second

type routeAuditWindow struct {
	windowStart time.Time
	suppressed  int
}

func (s *GatewayServer) emitThrottledGuardrailRouteAudit(
	ctx context.Context,
	prc guardrails.PipelineRequestContext,
	resource string,
	targetModel string,
	sessionPinned bool,
	violations []string,
) {
	if s == nil || s.repo == nil || prc.OrgID == "" {
		return
	}
	now := s.nowUTC()
	key := prc.OrgID + ":" + prc.VirtualKeyID + ":" + targetModel

	s.routeAuditMu.Lock()
	if s.routeAuditWindows == nil {
		s.routeAuditWindows = make(map[string]*routeAuditWindow)
	}
	win := s.routeAuditWindows[key]
	if win != nil && now.Sub(win.windowStart) < guardrailRouteAuditWindow {
		win.suppressed++
		s.routeAuditMu.Unlock()
		return
	}
	suppressedCount := 0
	if win != nil {
		suppressedCount = win.suppressed
	}
	if len(s.routeAuditWindows) > 1000 {
		for k, w := range s.routeAuditWindows {
			if now.Sub(w.windowStart) >= guardrailRouteAuditWindow {
				delete(s.routeAuditWindows, k)
			}
		}
	}
	s.routeAuditWindows[key] = &routeAuditWindow{windowStart: now}
	s.routeAuditMu.Unlock()

	_ = s.repo.RecordAuditLog(ctx, &domain.AuditLog{
		OrgID:      prc.OrgID,
		ActorID:    prc.VirtualKeyID,
		Action:     "guardrail.routed",
		Resource:   resource,
		ResourceID: prc.RequestID,
		Details: map[string]any{
			"action":           domain.GuardrailActionRoute,
			"target_model":     targetModel,
			"session_pinned":   sessionPinned,
			"violations":       violations,
			"suppressed_count": suppressedCount,
			"trace_id":         prc.TraceID,
		},
	})
}

func (s *GatewayServer) evaluateChatOutputGuardrails(
	ctx context.Context,
	w http.ResponseWriter,
	prc guardrails.PipelineRequestContext,
	resp *domain.CanonicalChatResponse,
	resource string,
) (bool, error) {
	if drivers.IsInternalGuardrailOrigin(ctx) {
		return false, nil
	}
	pipeline := s.GuardrailPipeline()
	out, err := pipeline.EvaluatePostCall(ctx, prc, resp)
	redacted := false
	if out != nil {
		redacted = out.Redacted
		if w != nil && redacted {
			w.Header().Set("X-Gateway-Output-Redacted", "true")
		}
		if err != nil || len(out.Violations) > 0 || redacted {
			action := out.AppliedAction
			if action == "" && err != nil {
				action = domain.GuardrailActionBlock
			}
			if w != nil && action != "" {
				w.Header().Set("X-Gateway-Guardrail-Action", string(action))
			}
			if s.repo != nil && prc.OrgID != "" && (err != nil || len(out.Violations) > 0) {
				_ = s.repo.RecordAuditLog(ctx, &domain.AuditLog{
					OrgID:      prc.OrgID,
					ActorID:    prc.VirtualKeyID,
					Action:     "guardrail.triggered",
					Resource:   resource,
					ResourceID: prc.RequestID,
					Details: map[string]any{
						"hook":       domain.GuardrailHookPostCall,
						"action":     action,
						"violations": out.Violations,
						"redacted":   redacted,
						"trace_id":   prc.TraceID,
					},
				})
			}
		}
	}
	if err != nil {
		status := http.StatusBadRequest
		if ge, ok := err.(*domain.GatewayError); ok && ge.StatusCode != 0 {
			status = ge.StatusCode
		}
		if s.collector != nil {
			s.collector.Record(observability.RequestObservation{
				StatusCode:       status,
				GuardrailBlocked: true,
			})
		}
		return redacted, err
	}
	return redacted, nil
}

func (s *GatewayServer) startDuringCallGuardrails(
	parentCtx context.Context,
	prc guardrails.PipelineRequestContext,
	req *domain.CanonicalChatRequest,
) (context.Context, *guardrails.DuringCallHandle, error) {
	if drivers.IsInternalGuardrailOrigin(parentCtx) {
		return parentCtx, nil, nil
	}
	return s.GuardrailPipeline().StartDuringCall(parentCtx, prc, req)
}

func (s *GatewayServer) recordDuringCallBlock(
	ctx context.Context,
	w http.ResponseWriter,
	prc guardrails.PipelineRequestContext,
	out *guardrails.PipelineOutcome,
	err error,
	resource string,
) {
	if w != nil {
		w.Header().Set("X-Gateway-Guardrail-Action", string(domain.GuardrailActionBlock))
	}
	status := http.StatusBadRequest
	if ge, ok := err.(*domain.GatewayError); ok && ge.StatusCode != 0 {
		status = ge.StatusCode
	}
	if s.collector != nil {
		s.collector.Record(observability.RequestObservation{
			StatusCode:       status,
			GuardrailBlocked: true,
		})
	}
	if s.repo != nil && prc.OrgID != "" {
		var violations []string
		if out != nil {
			violations = out.Violations
		}
		_ = s.repo.RecordAuditLog(ctx, &domain.AuditLog{
			OrgID:      prc.OrgID,
			ActorID:    prc.VirtualKeyID,
			Action:     "guardrail.triggered",
			Resource:   resource,
			ResourceID: prc.RequestID,
			Details: map[string]any{
				"hook":       domain.GuardrailHookDuringCall,
				"action":     domain.GuardrailActionBlock,
				"violations": violations,
				"trace_id":   prc.TraceID,
			},
		})
	}
}

type streamGuardrailSession struct {
	server           *GatewayServer
	pipeline         *guardrails.Pipeline
	prc              guardrails.PipelineRequestContext
	redactor         *guardrails.StreamRedactor
	windowEval       *guardrails.StreamWindowEvaluator
	resolvedPost     []guardrails.ResolvedGuardrail
	duringHandle     *guardrails.DuringCallHandle
	duringDone       bool
	sseStarted       bool
	redacted         bool
	blocked          bool
	toolCallBufs     map[int]*streamToolCallBuffer
	toolCallChecked  map[int]bool
	toolCallLastArgs map[int]string
}

type streamToolCallBuffer struct {
	id         string
	typ        string
	name       string
	args       strings.Builder
	nameTested bool
}

func (s *GatewayServer) newOrchestratorToolGuardrailDriver() guardrails.Driver {
	return &orchestratorPipelineDriver{server: s}
}

type orchestratorPipelineDriver struct {
	server *GatewayServer
}

func (d *orchestratorPipelineDriver) Name() string { return "gateway_orchestrator_pipeline" }

func (d *orchestratorPipelineDriver) SupportedHooks() []domain.GuardrailHook {
	return []domain.GuardrailHook{
		domain.GuardrailHookPreMCPCall,
		domain.GuardrailHookPostCall,
	}
}

func (d *orchestratorPipelineDriver) Evaluate(ctx context.Context, input *domain.GuardrailEvalInput) (*domain.GuardrailEvalResult, error) {
	if d == nil || d.server == nil || input == nil {
		return &domain.GuardrailEvalResult{Decision: domain.GuardrailDecisionAllow}, nil
	}
	// PreCall is already evaluated once at request entry by the inference handler before entering ToolLoopOrchestrator.
	if input.Hook == domain.GuardrailHookPreCall {
		return &domain.GuardrailEvalResult{Decision: domain.GuardrailDecisionAllow}, nil
	}
	pipeline := d.server.GuardrailPipeline()
	if pipeline == nil {
		return &domain.GuardrailEvalResult{Decision: domain.GuardrailDecisionAllow}, nil
	}
	prc := guardrails.PipelineRequestContext{
		RequestID:    input.RequestID,
		TraceID:      input.TraceID,
		OrgID:        input.OrgID,
		TeamID:       input.TeamID,
		VirtualKeyID: input.VirtualKeyID,
		EndUserID:    input.EndUserID,
		Model:        input.Model,
		Tags:         slices.Clone(input.Tags),
		Metadata:     input.Metadata,
	}
	hook := input.Hook
	if hook == "" {
		hook = domain.GuardrailHookPreMCPCall
	}
	res, err := pipeline.EvaluateResolvedInput(ctx, prc, hook, input)
	if err != nil {
		return nil, err
	}
	if res != nil && res.Decision == domain.GuardrailDecisionModify && res.ModifiedToolCalls != nil {
		return res, nil
	}
	// If orchestrator queries pre_mcp_call, also honor org tool_permission/tool_policy/block_code_execution
	// definitions attached to post_call/pre_call so admins don't have to duplicate hooks.
	if hook == domain.GuardrailHookPreMCPCall && len(input.ToolCalls) > 0 {
		seen := make(map[string]struct{})
		if existing, rErr := pipeline.ResolveForHook(ctx, prc, hook); rErr == nil {
			for _, g := range existing {
				seen[g.Name] = struct{}{}
			}
		}
		for _, fallbackHook := range []domain.GuardrailHook{domain.GuardrailHookPostCall, domain.GuardrailHookPreCall} {
			extraGroups, rErr := pipeline.ResolveForHook(ctx, prc, fallbackHook)
			if rErr != nil {
				continue
			}
			for _, g := range extraGroups {
				if _, already := seen[g.Name]; already {
					continue
				}
				seen[g.Name] = struct{}{}
				isToolGov := false
				for _, c := range g.Candidates {
					if c.Definition != nil {
						switch strings.ToLower(strings.TrimSpace(c.Definition.Provider)) {
						case drivers.ProviderToolPermission, drivers.ProviderToolPolicy, drivers.ProviderCodeExecution:
							isToolGov = true
						}
					}
				}
				if !isToolGov {
					continue
				}
				adapter := pipeline.NewResolvedDriverAdapter(prc, fallbackHook, g)
				stepIn := *input
				stepIn.Hook = fallbackHook
				stepRes, stepErr := adapter.Evaluate(ctx, &stepIn)
				if stepErr != nil {
					return nil, stepErr
				}
				if stepRes != nil && stepRes.Decision == domain.GuardrailDecisionBlock {
					return stepRes, nil
				}
				if stepRes != nil && stepRes.Decision == domain.GuardrailDecisionModify && stepRes.ModifiedToolCalls != nil {
					return stepRes, nil
				}
			}
		}
	}
	return res, nil
}

func (s *GatewayServer) newStreamGuardrailSession(
	ctx context.Context,
	prc guardrails.PipelineRequestContext,
	duringHandle *guardrails.DuringCallHandle,
) (*streamGuardrailSession, error) {
	if drivers.IsInternalGuardrailOrigin(ctx) {
		return &streamGuardrailSession{
			server: s,
			prc:    prc,
		}, nil
	}
	var redactor *guardrails.StreamRedactor
	if s.guardrails != nil && prc.OrgID != "" {
		policy, err := s.guardrails.Policy(ctx, prc.OrgID)
		if err != nil {
			return nil, err
		}
		redactor = s.guardrails.NewStreamRedactor(policy)
	}
	pipeline := s.GuardrailPipeline()
	resolvedPost, err := pipeline.ResolveForHook(ctx, prc, domain.GuardrailHookPostCall)
	if err != nil {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusServiceUnavailable,
			Code:       "guardrail_policy_unavailable",
			Message:    "guardrail policy evaluation unavailable",
			Type:       domain.ErrorTypeServer,
		}
	}
	var windowEval *guardrails.StreamWindowEvaluator
	if len(resolvedPost) > 0 {
		winCfg := buildStreamWindowConfig(resolvedPost)
		windowDrivers := make([]guardrails.Driver, 0, len(resolvedPost))
		for _, rg := range resolvedPost {
			if drv := pipeline.NewResolvedDriverAdapter(prc, domain.GuardrailHookPostCall, rg); drv != nil {
				windowDrivers = append(windowDrivers, drv)
			}
		}
		windowEval = guardrails.NewStreamWindowEvaluator(winCfg, windowDrivers...)
	}
	return &streamGuardrailSession{
		server:       s,
		pipeline:     pipeline,
		prc:          prc,
		redactor:     redactor,
		windowEval:   windowEval,
		resolvedPost: resolvedPost,
		duringHandle: duringHandle,
	}, nil
}

func buildStreamWindowConfig(resolvedPost []guardrails.ResolvedGuardrail) guardrails.StreamWindowConfig {
	cfg := guardrails.StreamWindowConfig{
		Unit:           guardrails.StreamWindowBytes,
		WindowSize:     64,
		OverlapSize:    24,
		MaxBufferBytes: 1 << 20,
	}
	for _, rg := range resolvedPost {
		for _, c := range rg.Candidates {
			if len(c.EffectiveConfig) == 0 {
				continue
			}
			if raw, ok := c.EffectiveConfig["stream_window_bytes"]; ok {
				if v := configInt(raw); v > 0 {
					cfg.WindowSize = v
				}
			}
			if raw, ok := c.EffectiveConfig["stream_overlap_bytes"]; ok {
				if v := configInt(raw); v >= 0 {
					cfg.OverlapSize = v
				}
			}
		}
	}
	if cfg.OverlapSize >= cfg.WindowSize && cfg.WindowSize > 1 {
		cfg.OverlapSize = cfg.WindowSize / 2
	}
	return cfg
}

func configInt(raw any) int {
	switch v := raw.(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	case json.Number:
		n, _ := v.Int64()
		return int(n)
	}
	return 0
}

func (ss *streamGuardrailSession) HasDuringCall() bool {
	return ss != nil && ss.duringHandle != nil
}

func (ss *streamGuardrailSession) MarkSSEStarted() {
	if ss != nil {
		ss.sseStarted = true
	}
}

func (ss *streamGuardrailSession) SSEStarted() bool {
	return ss != nil && ss.sseStarted
}

func (ss *streamGuardrailSession) CheckBeforeFirstEmit(ctx context.Context) error {
	if ss == nil || ss.duringHandle == nil {
		return nil
	}
	if !ss.duringDone {
		out, err := ss.duringHandle.Wait(ctx)
		ss.duringDone = true
		if err != nil {
			ss.blocked = true
			if out != nil && out.Redacted {
				ss.redacted = true
			}
			return err
		}
		return nil
	}
	if err := ss.duringHandle.Blocked(); err != nil {
		ss.blocked = true
		return err
	}
	return nil
}

func (ss *streamGuardrailSession) WaitDuring(ctx context.Context) (*guardrails.PipelineOutcome, error) {
	if ss == nil || ss.duringHandle == nil {
		return nil, nil
	}
	out, err := ss.duringHandle.Wait(ctx)
	ss.duringDone = true
	if err != nil {
		ss.blocked = true
	}
	if out != nil && out.Redacted {
		ss.redacted = true
	}
	return out, err
}

func (ss *streamGuardrailSession) ProcessText(ctx context.Context, text string) (string, error) {
	if ss == nil {
		return text, nil
	}
	if ss.redactor != nil {
		if ss.redactor.Blocked() {
			ss.blocked = true
			return "", guardrailStreamBlockedError()
		}
		text = ss.redactor.Process(text)
		if ss.redactor.Redacted() {
			ss.redacted = true
		}
		if ss.redactor.Blocked() {
			ss.blocked = true
			return "", guardrailStreamBlockedError()
		}
	}
	if ss.windowEval != nil && text != "" {
		next, err := ss.windowEval.Process(ctx, text)
		if ss.windowEval.Redacted() {
			ss.redacted = true
		}
		if err != nil || ss.windowEval.Blocked() {
			ss.blocked = true
			if err != nil {
				return "", err
			}
			return "", guardrailStreamBlockedError()
		}
		text = next
	}
	return text, nil
}

// ProcessToolCalls accumulates incremental SSE tool call deltas per index and evaluates
// resolved post_call guardrails (such as tool_permission, block_code_execution, and tool_policy)
// before deltas are flushed downstream.
func (ss *streamGuardrailSession) ProcessToolCalls(ctx context.Context, deltas []domain.CanonicalToolCall) ([]domain.CanonicalToolCall, error) {
	if ss == nil || len(deltas) == 0 || len(ss.resolvedPost) == 0 || ss.pipeline == nil {
		return deltas, nil
	}
	if ss.toolCallBufs == nil {
		ss.toolCallBufs = make(map[int]*streamToolCallBuffer)
		ss.toolCallChecked = make(map[int]bool)
		ss.toolCallLastArgs = make(map[int]string)
	}
	toValidate := make([]int, 0, len(deltas))
	for pos, delta := range deltas {
		idx := pos
		if delta.Index != nil {
			idx = *delta.Index
		}
		buf := ss.toolCallBufs[idx]
		if buf == nil {
			buf = &streamToolCallBuffer{}
			ss.toolCallBufs[idx] = buf
		}
		if delta.ID != "" {
			buf.id = delta.ID
		}
		if delta.Type != "" {
			buf.typ = delta.Type
		}
		if delta.Function.Name != "" {
			buf.name += delta.Function.Name
		}
		if delta.Function.Arguments != "" {
			buf.args.WriteString(delta.Function.Arguments)
		}
		toValidate = append(toValidate, idx)
	}

	filtered := make([]domain.CanonicalToolCall, 0, len(deltas))
	for pos, delta := range deltas {
		idx := toValidate[pos]
		buf := ss.toolCallBufs[idx]
		fullArgs := buf.args.String()
		isValidJSON := fullArgs == "" || json.Valid([]byte(fullArgs))

		// Always validate tool identity immediately when the name arrives so disallowed
		// tools (e.g. bash / blocked policy / tainted trusted tool) fail fast on chunk 1.
		if buf.name != "" && !buf.nameTested {
			buf.nameTested = true
			probe := domain.CanonicalToolCall{
				Index: &idx,
				ID:    buf.id,
				Type:  firstNonEmpty(buf.typ, "function"),
				Function: domain.CanonicalFunctionCall{
					Name: buf.name,
				},
			}
			kept, err := ss.evalToolCallSnapshot(ctx, probe)
			if err != nil {
				return nil, err
			}
			if !kept {
				ss.redacted = true
				continue
			}
		}

		// Re-validate full arguments whenever accumulated JSON is valid (or changed and valid).
		if fullArgs != "" && isValidJSON && ss.toolCallLastArgs[idx] != fullArgs {
			ss.toolCallLastArgs[idx] = fullArgs
			ss.toolCallChecked[idx] = true
			probe := domain.CanonicalToolCall{
				Index: &idx,
				ID:    buf.id,
				Type:  firstNonEmpty(buf.typ, "function"),
				Function: domain.CanonicalFunctionCall{
					Name:      buf.name,
					Arguments: fullArgs,
				},
			}
			kept, err := ss.evalToolCallSnapshot(ctx, probe)
			if err != nil {
				return nil, err
			}
			if !kept {
				ss.redacted = true
				continue
			}
		} else if fullArgs == "" {
			ss.toolCallChecked[idx] = true
		}

		filtered = append(filtered, delta)
	}
	return filtered, nil
}

func (ss *streamGuardrailSession) evalToolCallSnapshot(ctx context.Context, probe domain.CanonicalToolCall) (bool, error) {
	evalIn := &domain.GuardrailEvalInput{
		Direction:    domain.GuardrailDirectionOutput,
		Hook:         domain.GuardrailHookPostCall,
		RequestID:    ss.prc.RequestID,
		TraceID:      ss.prc.TraceID,
		OrgID:        ss.prc.OrgID,
		TeamID:       ss.prc.TeamID,
		VirtualKeyID: ss.prc.VirtualKeyID,
		EndUserID:    ss.prc.EndUserID,
		Model:        ss.prc.Model,
		Tags:         slices.Clone(ss.prc.Tags),
		ToolCalls:    []domain.CanonicalToolCall{probe},
		Metadata:     ss.prc.Metadata,
	}
	res, err := ss.pipeline.EvaluateResolvedInput(ctx, ss.prc, domain.GuardrailHookPostCall, evalIn)
	if err != nil {
		ss.blocked = true
		return false, err
	}
	if res != nil && res.Decision == domain.GuardrailDecisionModify && res.ModifiedToolCalls != nil && len(res.ModifiedToolCalls) == 0 {
		return false, nil
	}
	return true, nil
}

func (ss *streamGuardrailSession) flushToolCalls(ctx context.Context) error {
	if ss == nil || len(ss.toolCallBufs) == 0 || ss.pipeline == nil {
		return nil
	}
	for idx, buf := range ss.toolCallBufs {
		fullArgs := buf.args.String()
		if fullArgs != "" && (!ss.toolCallChecked[idx] || ss.toolCallLastArgs[idx] != fullArgs) {
			ss.toolCallChecked[idx] = true
			ss.toolCallLastArgs[idx] = fullArgs
			probe := domain.CanonicalToolCall{
				Index: &idx,
				ID:    buf.id,
				Type:  firstNonEmpty(buf.typ, "function"),
				Function: domain.CanonicalFunctionCall{
					Name:      buf.name,
					Arguments: fullArgs,
				},
			}
			if _, err := ss.evalToolCallSnapshot(ctx, probe); err != nil {
				return err
			}
		}
	}
	return nil
}

func firstNonEmpty(val, fallback string) string {
	if strings.TrimSpace(val) != "" {
		return val
	}
	return fallback
}

func (ss *streamGuardrailSession) Flush(ctx context.Context, streamErr error) (string, error) {
	if ss == nil {
		return "", streamErr
	}
	var rem string
	if streamErr == nil {
		if ss.redactor != nil {
			rem = ss.redactor.Flush()
			if ss.redactor.Redacted() {
				ss.redacted = true
			}
			if ss.redactor.Blocked() {
				ss.blocked = true
				return "", guardrailStreamBlockedError()
			}
		}
		if ss.windowEval != nil {
			var winPart string
			if rem != "" {
				processed, pErr := ss.windowEval.Process(ctx, rem)
				if ss.windowEval.Redacted() {
					ss.redacted = true
				}
				if pErr != nil || ss.windowEval.Blocked() {
					ss.blocked = true
					if pErr != nil {
						return "", pErr
					}
					return "", guardrailStreamBlockedError()
				}
				winPart = processed
			}
			flushed, fErr := ss.windowEval.Flush(ctx)
			if ss.windowEval.Redacted() {
				ss.redacted = true
			}
			if fErr != nil || ss.windowEval.Blocked() {
				ss.blocked = true
				if fErr != nil {
					return "", fErr
				}
				return "", guardrailStreamBlockedError()
			}
			rem = winPart + flushed
		}
		if tcErr := ss.flushToolCalls(ctx); tcErr != nil {
			ss.blocked = true
			return "", tcErr
		}
		return rem, nil
	}
	if ss.redactor != nil {
		if ss.redactor.Blocked() {
			_ = ss.redactor.Flush()
			ss.blocked = true
		}
		if ss.redactor.Redacted() {
			ss.redacted = true
		}
	}
	if ss.windowEval != nil {
		if ss.windowEval.Blocked() {
			ss.blocked = true
		}
		if ss.windowEval.Redacted() {
			ss.redacted = true
		}
	}
	return "", streamErr
}

func (ss *streamGuardrailSession) Redacted() bool {
	if ss == nil {
		return false
	}
	return ss.redacted || (ss.redactor != nil && ss.redactor.Redacted()) || (ss.windowEval != nil && ss.windowEval.Redacted())
}

func (ss *streamGuardrailSession) Blocked() bool {
	if ss == nil {
		return false
	}
	return ss.blocked || (ss.redactor != nil && ss.redactor.Blocked()) || (ss.windowEval != nil && ss.windowEval.Blocked())
}

func (ss *streamGuardrailSession) Close() {
	if ss != nil && ss.duringHandle != nil {
		ss.duringHandle.Close()
	}
}

func (s *GatewayServer) evaluateGuardrailText(ctx context.Context, orgID string, texts ...string) error {
	_, err := s.guardrailTextValues(ctx, orgID, texts...)
	return err
}

func (s *GatewayServer) guardrailTextValues(ctx context.Context, orgID string, values ...string) ([]string, error) {
	return s.guardrailTextValuesWithExtensions(ctx, orgID, "", nil, values...)
}

func (s *GatewayServer) guardrailTextValuesWithExtensions(
	ctx context.Context,
	orgID, model string,
	ext *domain.GoRouteExtensions,
	values ...string,
) ([]string, error) {
	m := model
	idCtx := auth.IdentityFromContext(ctx)
	if idCtx == nil {
		idCtx = &domain.IdentityContext{OrgID: orgID}
	} else if idCtx.OrgID == "" && orgID != "" {
		cp := *idCtx
		cp.OrgID = orgID
		idCtx = &cp
	}
	return s.evaluateNonChatTextGuardrails(ctx, nil, nil, idCtx, &m, ext, "non_chat", values...)
}

// evaluateNonChatTextGuardrails evaluates pre-call guardrails for non-chat text inputs,
// enforcing sensitive route rewrites (RBAC, model rewrite, session pinning, headers, and audit).
func (s *GatewayServer) evaluateNonChatTextGuardrails(
	ctx context.Context,
	w http.ResponseWriter,
	r *http.Request,
	idCtx *domain.IdentityContext,
	model *string,
	ext *domain.GoRouteExtensions,
	resource string,
	values ...string,
) ([]string, error) {
	out := append([]string(nil), values...)
	if drivers.IsInternalGuardrailOrigin(ctx) {
		return out, nil
	}
	var msgs []domain.CanonicalMessage
	var indices []int
	for i, val := range values {
		if val != "" {
			msgs = append(msgs, domain.CanonicalMessage{Role: "user", Content: val})
			indices = append(indices, i)
		}
	}
	hasSession := ext != nil && strings.TrimSpace(ext.SessionID) != ""
	if len(msgs) == 0 && !hasSession {
		return out, nil
	}
	targetModel := ""
	if model != nil {
		targetModel = *model
	}
	reqID := ""
	if r != nil {
		reqID = gatewayRequestID(r)
	}
	probe := &domain.CanonicalChatRequest{
		RequestID:         reqID,
		Model:             targetModel,
		Messages:          msgs,
		GoRouteExtensions: ext,
	}
	prc := buildGuardrailRequestContext(r, idCtx, probe)
	if _, _, err := s.evaluatePreCallWithRoute(ctx, w, r, idCtx, probe, prc, resource); err != nil {
		return nil, err
	}
	if model != nil && strings.TrimSpace(probe.Model) != "" {
		*model = probe.Model
	}
	for msgIdx, origIdx := range indices {
		if msgIdx < len(probe.Messages) {
			out[origIdx] = probe.Messages[msgIdx].Content
		}
	}
	return out, nil
}

func (s *GatewayServer) sanitizeGuardrailValue(ctx context.Context, orgID string, raw any) (any, bool, error) {
	if s == nil || drivers.IsInternalGuardrailOrigin(ctx) {
		return raw, false, nil
	}
	switch v := raw.(type) {
	case nil:
		return nil, false, nil
	case string:
		return s.sanitizeGuardrailTextOutcome(ctx, orgID, v)
	case []string:
		out := make([]string, len(v))
		anyRedacted := false
		for i, item := range v {
			next, redacted, err := s.sanitizeGuardrailTextOutcome(ctx, orgID, item)
			if err != nil {
				return nil, anyRedacted, err
			}
			out[i] = next
			if redacted {
				anyRedacted = true
			}
		}
		return out, anyRedacted, nil
	case []any:
		out := make([]any, len(v))
		anyRedacted := false
		for i, item := range v {
			next, redacted, err := s.sanitizeGuardrailValue(ctx, orgID, item)
			if err != nil {
				return nil, anyRedacted, err
			}
			out[i] = next
			if redacted {
				anyRedacted = true
			}
		}
		return out, anyRedacted, nil
	case map[string]any:
		out := make(map[string]any, len(v))
		anyRedacted := false
		for k, item := range v {
			next, redacted, err := s.sanitizeGuardrailValue(ctx, orgID, item)
			if err != nil {
				return nil, anyRedacted, err
			}
			out[k] = next
			if redacted {
				anyRedacted = true
			}
		}
		return out, anyRedacted, nil
	default:
		return raw, false, nil
	}
}

func (s *GatewayServer) sanitizeGuardrailTextOutcome(ctx context.Context, orgID, text string) (string, bool, error) {
	if s == nil || drivers.IsInternalGuardrailOrigin(ctx) {
		return text, false, nil
	}
	pipeline := s.GuardrailPipeline()
	if pipeline == nil {
		if s.guardrails == nil {
			return text, false, nil
		}
		return s.guardrails.SanitizeTextOutput(ctx, orgID, text)
	}
	idCtx := auth.IdentityFromContext(ctx)
	if idCtx == nil {
		idCtx = &domain.IdentityContext{OrgID: orgID}
	} else if idCtx.OrgID == "" && orgID != "" {
		cp := *idCtx
		cp.OrgID = orgID
		idCtx = &cp
	}
	prc := buildGuardrailRequestContext(nil, idCtx, nil)
	probe := &domain.CanonicalChatResponse{
		Choices: []domain.CanonicalChoice{
			{Message: domain.CanonicalMessage{Role: "assistant", Content: text}},
		},
	}
	out, err := pipeline.EvaluatePostCall(ctx, prc, probe)
	if err != nil {
		redacted := out != nil && out.Redacted
		return "", redacted, err
	}
	redacted := out != nil && out.Redacted
	if len(probe.Choices) > 0 {
		return probe.Choices[0].Message.Content, redacted, nil
	}
	return text, redacted, nil
}

func (s *GatewayServer) sanitizeGuardrailText(ctx context.Context, orgID, text string) (string, error) {
	updated, _, err := s.sanitizeGuardrailTextOutcome(ctx, orgID, text)
	return updated, err
}
