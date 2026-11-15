package server

import (
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"weak"

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
			if s.repo == nil || prc.OrgID == "" || res == nil {
				return
			}
			_ = s.repo.RecordAuditLog(ctx, &domain.AuditLog{
				OrgID:      prc.OrgID,
				ActorID:    prc.VirtualKeyID,
				Action:     "guardrail.evaluated",
				Resource:   string(hook),
				ResourceID: prc.RequestID,
				Details: map[string]any{
					"hook":          hook,
					"decision":      res.Decision,
					"error_message": res.ErrorMessage,
					"violations":    res.Violations,
					"trace_id":      prc.TraceID,
					"model":         prc.Model,
					"model_group":   prc.ModelGroupID,
				},
			})
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
	created.SetDriverLookup(driverRegistry.Build)
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
	pipeline := s.GuardrailPipeline()
	out, err := pipeline.EvaluatePreCall(ctx, prc, req)
	redacted := false
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
	server       *GatewayServer
	pipeline     *guardrails.Pipeline
	prc          guardrails.PipelineRequestContext
	redactor     *guardrails.StreamRedactor
	resolvedPost []guardrails.ResolvedGuardrail
	duringHandle *guardrails.DuringCallHandle
	duringDone   bool
	sseStarted   bool
	redacted     bool
	blocked      bool
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
	return &streamGuardrailSession{
		server:       s,
		pipeline:     pipeline,
		prc:          prc,
		redactor:     redactor,
		resolvedPost: resolvedPost,
		duringHandle: duringHandle,
	}, nil
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
	if len(ss.resolvedPost) > 0 && text != "" {
		next, out, err := ss.pipeline.EvaluatePostCallText(ctx, ss.prc, ss.resolvedPost, text)
		if out != nil && out.Redacted {
			ss.redacted = true
		}
		if err != nil {
			ss.blocked = true
			return "", err
		}
		text = next
	}
	return text, nil
}

func (ss *streamGuardrailSession) Flush(ctx context.Context, streamErr error) (string, error) {
	if ss == nil {
		return "", streamErr
	}
	var rem string
	if streamErr == nil && ss.redactor != nil {
		rem = ss.redactor.Flush()
		if ss.redactor.Redacted() {
			ss.redacted = true
		}
		if ss.redactor.Blocked() {
			ss.blocked = true
			return "", guardrailStreamBlockedError()
		}
		if rem != "" && len(ss.resolvedPost) > 0 {
			next, out, postErr := ss.pipeline.EvaluatePostCallText(ctx, ss.prc, ss.resolvedPost, rem)
			if out != nil && out.Redacted {
				ss.redacted = true
			}
			if postErr != nil {
				ss.blocked = true
				return "", postErr
			}
			rem = next
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
	return "", streamErr
}

func (ss *streamGuardrailSession) Redacted() bool {
	if ss == nil {
		return false
	}
	return ss.redacted || (ss.redactor != nil && ss.redactor.Redacted())
}

func (ss *streamGuardrailSession) Blocked() bool {
	if ss == nil {
		return false
	}
	return ss.blocked || (ss.redactor != nil && ss.redactor.Blocked())
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
	if len(values) == 0 {
		return nil, nil
	}
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
	if len(msgs) == 0 {
		return out, nil
	}
	probe := &domain.CanonicalChatRequest{
		Model:             model,
		Messages:          msgs,
		GoRouteExtensions: ext,
	}
	prc := buildGuardrailRequestContext(nil, &domain.IdentityContext{OrgID: orgID}, probe)
	pipeline := s.GuardrailPipeline()
	if _, err := pipeline.EvaluatePreCall(ctx, prc, probe); err != nil {
		return nil, err
	}
	for msgIdx, origIdx := range indices {
		if msgIdx < len(probe.Messages) {
			out[origIdx] = probe.Messages[msgIdx].Content
		}
	}
	return out, nil
}

func (s *GatewayServer) guardrailInputValue(ctx context.Context, orgID string, raw any) (any, error) {
	switch v := raw.(type) {
	case nil:
		return nil, nil
	case string:
		vals, err := s.guardrailTextValues(ctx, orgID, v)
		if err != nil {
			return nil, err
		}
		if len(vals) == 0 {
			return v, nil
		}
		return vals[0], nil
	case []string:
		return s.guardrailTextValues(ctx, orgID, v...)
	case []any:
		out := make([]any, len(v))
		for i, item := range v {
			next, err := s.guardrailInputValue(ctx, orgID, item)
			if err != nil {
				return nil, err
			}
			out[i] = next
		}
		return out, nil
	case map[string]any:
		out := make(map[string]any, len(v))
		for k, item := range v {
			next, err := s.guardrailInputValue(ctx, orgID, item)
			if err != nil {
				return nil, err
			}
			out[k] = next
		}
		return out, nil
	default:
		return raw, nil
	}
}

func (s *GatewayServer) sanitizeGuardrailValue(ctx context.Context, orgID string, raw any) (any, bool, error) {
	if s.guardrails == nil || drivers.IsInternalGuardrailOrigin(ctx) {
		return raw, false, nil
	}
	switch v := raw.(type) {
	case nil:
		return nil, false, nil
	case string:
		next, redacted, err := s.guardrails.SanitizeTextOutput(ctx, orgID, v)
		return next, redacted, err
	case []string:
		out := make([]string, len(v))
		anyRedacted := false
		for i, item := range v {
			next, redacted, err := s.guardrails.SanitizeTextOutput(ctx, orgID, item)
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

func (s *GatewayServer) sanitizeGuardrailText(ctx context.Context, orgID, text string) (string, error) {
	if s.guardrails == nil || drivers.IsInternalGuardrailOrigin(ctx) {
		return text, nil
	}
	updated, _, err := s.guardrails.SanitizeTextOutput(ctx, orgID, text)
	return updated, err
}
