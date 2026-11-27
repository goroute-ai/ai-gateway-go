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

	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/guardrails"
	"github.com/goroute-ai/ai-gateway-go/internal/guardrails/drivers"
	"github.com/goroute-ai/ai-gateway-go/internal/observability"
)

var serverPipelines sync.Map

type serverPipelineEntry struct {
	server   weak.Pointer[GatewayServer]
	pipeline *guardrails.Pipeline
}

// GuardrailPipeline returns the unified guardrail pipeline for this GatewayServer,
// initializing it lazily on first use with Vault decryption, SSRF-enforced driver lookup,
// and OTEL/audit hooks.
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

	driverRegistry := s.newGuardrailDriverRegistry()
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

func (s *GatewayServer) newGuardrailDriverRegistry() *drivers.Registry {
	var opts []drivers.RegistryOption
	if s != nil && s.netPolicy != nil {
		opts = append(opts, drivers.WithSSRFPolicy(s.netPolicy))
	}
	return drivers.NewRegistry(opts...)
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
	}
	if req != nil {
		prc.RequestID = req.RequestID
		prc.Model = req.Model
		if req.User != "" && prc.EndUserID == "" {
			prc.EndUserID = req.User
		}
		if req.GoRouteExtensions != nil {
			prc.TraceID = req.GoRouteExtensions.ContextID
			prc.Tags = append([]string(nil), req.GoRouteExtensions.Tags...)
			if req.GoRouteExtensions.TaskID != "" {
				prc.Metadata = map[string]any{"task_id": req.GoRouteExtensions.TaskID}
			}
		}
	}
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
	pipeline := s.GuardrailPipeline()
	out, err := pipeline.EvaluatePreCall(ctx, prc, req)
	redacted := false
	if out != nil {
		redacted = out.Redacted
	}
	if out != nil && (len(out.Violations) > 0 || out.Redacted || err != nil) {
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
		status := http.StatusBadGateway
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

type streamGuardrailSession struct {
	redactor   *guardrails.StreamRedactor
	sseStarted bool
	redacted   bool
	blocked    bool
}

func (s *GatewayServer) newStreamGuardrailSession(
	ctx context.Context,
	prc guardrails.PipelineRequestContext,
) (*streamGuardrailSession, error) {
	var redactor *guardrails.StreamRedactor
	if s.guardrails != nil && prc.OrgID != "" {
		policy, err := s.guardrails.Policy(ctx, prc.OrgID)
		if err != nil {
			return nil, err
		}
		redactor = s.guardrails.NewStreamRedactor(policy)
	}
	return &streamGuardrailSession{
		redactor: redactor,
	}, nil
}

func (ss *streamGuardrailSession) MarkSSEStarted() {
	if ss != nil {
		ss.sseStarted = true
	}
}

func (ss *streamGuardrailSession) SSEStarted() bool {
	return ss != nil && ss.sseStarted
}

func (ss *streamGuardrailSession) ProcessText(_ context.Context, text string) (string, error) {
	if ss == nil || ss.redactor == nil {
		return text, nil
	}
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
	return text, nil
}

func (ss *streamGuardrailSession) Flush(_ context.Context, streamErr error) (string, error) {
	if ss == nil || ss.redactor == nil {
		return "", streamErr
	}
	if streamErr == nil {
		rem := ss.redactor.Flush()
		if ss.redactor.Redacted() {
			ss.redacted = true
		}
		if ss.redactor.Blocked() {
			ss.blocked = true
			return "", guardrailStreamBlockedError()
		}
		return rem, nil
	}
	if ss.redactor.Blocked() {
		_ = ss.redactor.Flush()
		ss.blocked = true
	}
	if ss.redactor.Redacted() {
		ss.redacted = true
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

func (ss *streamGuardrailSession) Close() {}

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
	if _, _, err := s.evaluateChatInputGuardrails(ctx, w, r, idCtx, probe, resource); err != nil {
		return nil, err
	}
	for msgIdx, origIdx := range indices {
		if msgIdx < len(probe.Messages) {
			out[origIdx] = probe.Messages[msgIdx].Content
		}
	}
	return out, nil
}

func (s *GatewayServer) sanitizeGuardrailValue(ctx context.Context, orgID string, raw any) (any, bool, error) {
	if s == nil {
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
	if s == nil {
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
