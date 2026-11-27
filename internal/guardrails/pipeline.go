package guardrails

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/logger"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

// Driver evaluates a single external or SDK guardrail against a structured input envelope.
type Driver interface {
	Name() string
	SupportedHooks() []domain.GuardrailHook
	Evaluate(ctx context.Context, input *domain.GuardrailEvalInput) (*domain.GuardrailEvalResult, error)
}

// DriverConfig provides resolved definition metadata, config, and decrypted Vault secrets
// to construct a Driver instance.
type DriverConfig struct {
	Definition       *domain.GuardrailDefinition
	EffectiveConfig  map[string]any
	DecryptedSecrets map[string]any
}

// DriverFactory constructs a Driver for a GuardrailDefinition.
type DriverFactory func(ctx context.Context, cfg DriverConfig) (Driver, error)

// DriverLookup resolves a Driver dynamically when no static DriverFactory is registered.
type DriverLookup func(ctx context.Context, cfg DriverConfig) (Driver, error)

// SecretDecryptor decrypts Vault-encrypted GuardrailDefinition secrets before Driver construction.
type SecretDecryptor func(ctx context.Context, def *domain.GuardrailDefinition) (map[string]any, error)

// AuditHook receives structured guardrail evaluation outcomes when violations occur.
type AuditHook func(ctx context.Context, hook domain.GuardrailHook, prc PipelineRequestContext, res *domain.GuardrailEvalResult)

// PipelineRequestContext carries tenant and request metadata for guardrail evaluation.
type PipelineRequestContext struct {
	RequestID      string
	TraceID        string
	OrgID          string
	TeamID         string
	VirtualKeyID   string
	EndUserID      string
	Model          string
	Tags           []string
	RequestHeaders map[string]string
	Metadata       map[string]any
}

// PipelineOutcome combines built-in GuardrailPolicy outcomes and external/SDK Driver results.
type PipelineOutcome struct {
	Result        *domain.GuardrailEvalResult
	LegacyOutcome *CheckOutcome
	Redacted      bool
	AppliedAction domain.GuardrailAction
	Violations    []string
}

// PipelineOption configures optional behavior on a Pipeline.
type PipelineOption func(*Pipeline)

// WithAuditHook registers a callback invoked when guardrails produce findings.
func WithAuditHook(fn AuditHook) PipelineOption {
	return func(p *Pipeline) {
		p.auditHook = fn
	}
}

// WithSecretDecryptor registers a Vault secret decryption hook for GuardrailDefinition instances.
func WithSecretDecryptor(fn SecretDecryptor) PipelineOption {
	return func(p *Pipeline) {
		p.secretDecryptor = fn
	}
}

// Pipeline orchestrates the built-in organization GuardrailPolicy (Engine) and configured
// external/SDK Drivers across pre_call, post_call, and logging_only hooks.
type Pipeline struct {
	engine          *Engine
	repo            storage.Repository
	mu              sync.RWMutex
	factories       map[string]DriverFactory
	lookup          DriverLookup
	secretDecryptor SecretDecryptor
	auditHook       AuditHook
}

// NewPipeline constructs a unified guardrail pipeline wrapping engine and repo.
func NewPipeline(engine *Engine, repo storage.Repository, opts ...PipelineOption) *Pipeline {
	p := &Pipeline{
		engine:    engine,
		repo:      repo,
		factories: make(map[string]DriverFactory),
	}
	for _, opt := range opts {
		if opt != nil {
			opt(p)
		}
	}
	return p
}

// Engine returns the built-in local Engine bound to this Pipeline.
func (p *Pipeline) Engine() *Engine {
	if p == nil {
		return nil
	}
	return p.engine
}

// RegisterDriver registers a DriverFactory for a provider identifier (case-insensitive).
func (p *Pipeline) RegisterDriver(provider string, factory DriverFactory) {
	if p == nil || factory == nil {
		return
	}
	key := strings.ToLower(strings.TrimSpace(provider))
	if key == "" {
		return
	}
	p.mu.Lock()
	p.factories[key] = factory
	p.mu.Unlock()
}

// SetDriverLookup registers a fallback lookup hook for resolving Drivers dynamically.
func (p *Pipeline) SetDriverLookup(lookup DriverLookup) {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.lookup = lookup
	p.mu.Unlock()
}

// ResolveForHook resolves enabled external/SDK guardrails matching hook ordered by precedence.
func (p *Pipeline) ResolveForHook(ctx context.Context, prc PipelineRequestContext, hook domain.GuardrailHook) ([]ResolvedGuardrail, error) {
	if p == nil || p.repo == nil || prc.OrgID == "" {
		return nil, nil
	}
	return ResolveEffectiveGuardrails(ctx, p.repo, ResolveContext{
		OrgID: prc.OrgID,
		Hook:  hook,
	})
}

// EvaluatePreCall evaluates the organization's built-in policy followed by enabled pre_call drivers.
func (p *Pipeline) EvaluatePreCall(ctx context.Context, prc PipelineRequestContext, req *domain.CanonicalChatRequest) (*PipelineOutcome, error) {
	outcome := &PipelineOutcome{
		Result: &domain.GuardrailEvalResult{Decision: domain.GuardrailDecisionAllow},
	}
	if p == nil || req == nil {
		return outcome, nil
	}

	// 1. Built-in organization policy.
	if p.engine != nil {
		legacyOut, err := p.engine.EvaluateInput(ctx, prc.OrgID, req)
		mergeLegacyOutcome(outcome, legacyOut)
		if err != nil {
			outcome.Result.Decision = domain.GuardrailDecisionBlock
			outcome.Result.ErrorMessage = err.Error()
			return outcome, err
		}
	}

	// 2. Enabled external / SDK drivers.
	resolved, err := p.ResolveForHook(ctx, prc, domain.GuardrailHookPreCall)
	if err != nil {
		return outcome, guardrailUnavailableError("failed to resolve active guardrails")
	}
	for _, rg := range resolved {
		evalIn := BuildChatInputEvalInput(domain.GuardrailHookPreCall, prc, req)
		res, evalErr := p.evaluateResolvedDriver(ctx, prc, domain.GuardrailHookPreCall, rg, evalIn)
		if evalErr != nil {
			outcome.Result.Decision = domain.GuardrailDecisionBlock
			outcome.Result.ErrorMessage = evalErr.Error()
			return outcome, evalErr
		}
		if res == nil {
			continue
		}
		shadow := isLoggingOnlyDefinition(rg.Definition, domain.GuardrailHookPreCall)
		mergeDriverResult(outcome, res, shadow)
		if p.auditHook != nil && len(res.Violations) > 0 {
			p.auditHook(ctx, domain.GuardrailHookPreCall, prc, res)
		}
		if shadow {
			continue
		}
		switch res.Decision {
		case domain.GuardrailDecisionBlock:
			return outcome, newBlockedGatewayError(domain.GuardrailHookPreCall, rg.Definition.Name, res)
		case domain.GuardrailDecisionModify:
			if applyMutationsToChatRequest(req, res) {
				outcome.Redacted = true
				outcome.AppliedAction = domain.GuardrailActionRedact
			}
		}
	}
	return outcome, nil
}

// EvaluatePostCall evaluates the organization's built-in output policy followed by enabled post_call drivers.
func (p *Pipeline) EvaluatePostCall(ctx context.Context, prc PipelineRequestContext, resp *domain.CanonicalChatResponse) (*PipelineOutcome, error) {
	outcome := &PipelineOutcome{
		Result: &domain.GuardrailEvalResult{Decision: domain.GuardrailDecisionAllow},
	}
	if p == nil || resp == nil {
		return outcome, nil
	}

	// 1. Built-in organization output policy.
	if p.engine != nil {
		pol, err := p.engine.Policy(ctx, prc.OrgID)
		if err != nil {
			return outcome, err
		}
		if pol != nil {
			legacyOut, evalErr := p.engine.EvaluateOutputWithPolicy(ctx, pol, resp)
			mergeLegacyOutcome(outcome, legacyOut)
			if evalErr != nil {
				outcome.Result.Decision = domain.GuardrailDecisionBlock
				outcome.Result.ErrorMessage = evalErr.Error()
				return outcome, evalErr
			}
		}
	}

	// 2. Enabled external / SDK drivers.
	resolved, err := p.ResolveForHook(ctx, prc, domain.GuardrailHookPostCall)
	if err != nil {
		return outcome, guardrailUnavailableError("failed to resolve active output guardrails")
	}
	for _, rg := range resolved {
		evalIn := BuildChatOutputEvalInput(domain.GuardrailHookPostCall, prc, resp)
		res, evalErr := p.evaluateResolvedDriver(ctx, prc, domain.GuardrailHookPostCall, rg, evalIn)
		if evalErr != nil {
			outcome.Result.Decision = domain.GuardrailDecisionBlock
			outcome.Result.ErrorMessage = evalErr.Error()
			return outcome, evalErr
		}
		if res == nil {
			continue
		}
		shadow := isLoggingOnlyDefinition(rg.Definition, domain.GuardrailHookPostCall)
		mergeDriverResult(outcome, res, shadow)
		if p.auditHook != nil && len(res.Violations) > 0 {
			p.auditHook(ctx, domain.GuardrailHookPostCall, prc, res)
		}
		if shadow {
			continue
		}
		switch res.Decision {
		case domain.GuardrailDecisionBlock:
			return outcome, newBlockedGatewayError(domain.GuardrailHookPostCall, rg.Definition.Name, res)
		case domain.GuardrailDecisionModify:
			if applyMutationsToChatResponse(resp, res) {
				outcome.Redacted = true
				outcome.AppliedAction = domain.GuardrailActionRedact
			}
		}
	}
	return outcome, nil
}

// EvaluateTexts evaluates plain text inputs through the built-in policy and enabled drivers for hook.
func (p *Pipeline) EvaluateTexts(ctx context.Context, prc PipelineRequestContext, hook domain.GuardrailHook, texts []string) ([]string, *PipelineOutcome, error) {
	outTexts := slices.Clone(texts)
	outcome := &PipelineOutcome{
		Result: &domain.GuardrailEvalResult{Decision: domain.GuardrailDecisionAllow},
	}
	if p == nil || len(outTexts) == 0 {
		return outTexts, outcome, nil
	}

	// 1. Built-in policy via synthetic chat envelope.
	if p.engine != nil {
		if hook == domain.GuardrailHookPostCall {
			for i := range outTexts {
				sanitized, redacted, err := p.engine.SanitizeTextOutput(ctx, prc.OrgID, outTexts[i])
				if err != nil {
					outcome.Result.Decision = domain.GuardrailDecisionBlock
					outcome.Result.ErrorMessage = err.Error()
					return outTexts, outcome, err
				}
				if redacted {
					outTexts[i] = sanitized
					outcome.Redacted = true
					outcome.AppliedAction = domain.GuardrailActionRedact
				}
			}
		} else {
			msgs := make([]domain.CanonicalMessage, len(outTexts))
			for i, t := range outTexts {
				msgs[i] = domain.CanonicalMessage{Role: "user", Content: t}
			}
			probe := &domain.CanonicalChatRequest{Model: prc.Model, Messages: msgs}
			legacyOut, err := p.engine.EvaluateInput(ctx, prc.OrgID, probe)
			mergeLegacyOutcome(outcome, legacyOut)
			if err != nil {
				outcome.Result.Decision = domain.GuardrailDecisionBlock
				outcome.Result.ErrorMessage = err.Error()
				return outTexts, outcome, err
			}
			for i := range probe.Messages {
				outTexts[i] = probe.Messages[i].Content
			}
		}
	}

	// 2. Enabled external / SDK drivers.
	resolved, err := p.ResolveForHook(ctx, prc, hook)
	if err != nil {
		return outTexts, outcome, guardrailUnavailableError("failed to resolve active guardrails")
	}
	direction := domain.GuardrailDirectionInput
	if hook == domain.GuardrailHookPostCall {
		direction = domain.GuardrailDirectionOutput
	}
	for _, rg := range resolved {
		evalIn := &domain.GuardrailEvalInput{
			Direction:      direction,
			Hook:           hook,
			RequestID:      prc.RequestID,
			TraceID:        prc.TraceID,
			OrgID:          prc.OrgID,
			TeamID:         prc.TeamID,
			VirtualKeyID:   prc.VirtualKeyID,
			EndUserID:      prc.EndUserID,
			Model:          prc.Model,
			Tags:           slices.Clone(prc.Tags),
			Texts:          slices.Clone(outTexts),
			RequestHeaders: cloneStringMap(prc.RequestHeaders),
			Metadata:       cloneConfigMap(prc.Metadata),
		}
		res, evalErr := p.evaluateResolvedDriver(ctx, prc, hook, rg, evalIn)
		if evalErr != nil {
			outcome.Result.Decision = domain.GuardrailDecisionBlock
			outcome.Result.ErrorMessage = evalErr.Error()
			return outTexts, outcome, evalErr
		}
		if res == nil {
			continue
		}
		shadow := isLoggingOnlyDefinition(rg.Definition, hook)
		mergeDriverResult(outcome, res, shadow)
		if p.auditHook != nil && len(res.Violations) > 0 {
			p.auditHook(ctx, hook, prc, res)
		}
		if shadow {
			continue
		}
		switch res.Decision {
		case domain.GuardrailDecisionBlock:
			return outTexts, outcome, newBlockedGatewayError(hook, rg.Definition.Name, res)
		case domain.GuardrailDecisionModify:
			if len(res.ModifiedTexts) > 0 {
				for i := 0; i < len(outTexts) && i < len(res.ModifiedTexts); i++ {
					if outTexts[i] != res.ModifiedTexts[i] {
						outTexts[i] = res.ModifiedTexts[i]
						outcome.Redacted = true
						outcome.AppliedAction = domain.GuardrailActionRedact
					}
				}
			}
		}
	}
	return outTexts, outcome, nil
}

// EvaluateDriver executes a single ResolvedGuardrail against evalIn (used by admin simulator and pipeline).
func (p *Pipeline) EvaluateDriver(
	ctx context.Context,
	prc PipelineRequestContext,
	hook domain.GuardrailHook,
	rg ResolvedGuardrail,
	evalIn *domain.GuardrailEvalInput,
) (*domain.GuardrailEvalResult, error) {
	return p.evaluateResolvedDriver(ctx, prc, hook, rg, evalIn)
}

func (p *Pipeline) evaluateResolvedDriver(
	ctx context.Context,
	prc PipelineRequestContext,
	hook domain.GuardrailHook,
	rg ResolvedGuardrail,
	evalIn *domain.GuardrailEvalInput,
) (*domain.GuardrailEvalResult, error) {
	if rg.Definition == nil {
		return nil, nil
	}
	drv, err := p.buildDriver(ctx, rg)
	if err != nil {
		logger.WarnContext(ctx, "Guardrail driver initialization failed",
			slog.String("component", "guardrails"),
			slog.String("org_id", prc.OrgID),
			slog.String("guardrail", rg.Definition.Name),
			slog.String("provider", rg.Definition.Provider),
			slog.Bool("fail_open", rg.FailOpen),
			slog.String("error", err.Error()),
		)
		if rg.FailOpen || isLoggingOnlyDefinition(rg.Definition, hook) {
			return nil, nil
		}
		return nil, guardrailUnavailableError(fmt.Sprintf("guardrail %q could not be initialized", rg.Definition.Name))
	}

	evalCtx := ctx
	var cancel context.CancelFunc
	if rg.TimeoutMs > 0 {
		evalCtx, cancel = context.WithTimeout(ctx, time.Duration(rg.TimeoutMs)*time.Millisecond)
		defer cancel()
	}

	res, err := drv.Evaluate(evalCtx, evalIn)
	if err != nil {
		logger.WarnContext(ctx, "Guardrail driver evaluation failed",
			slog.String("component", "guardrails"),
			slog.String("org_id", prc.OrgID),
			slog.String("guardrail", rg.Definition.Name),
			slog.String("provider", rg.Definition.Provider),
			slog.Bool("fail_open", rg.FailOpen),
			slog.String("error", err.Error()),
		)
		if rg.FailOpen || isLoggingOnlyDefinition(rg.Definition, hook) {
			return nil, nil
		}
		return nil, guardrailUnavailableError(fmt.Sprintf("guardrail %q evaluation failed", rg.Definition.Name))
	}
	return res, nil
}

func (p *Pipeline) buildDriver(ctx context.Context, rg ResolvedGuardrail) (Driver, error) {
	var secrets map[string]any
	if p.secretDecryptor != nil && rg.Definition != nil && rg.Definition.EncryptedSecrets != "" {
		dec, err := p.secretDecryptor(ctx, rg.Definition)
		if err != nil {
			return nil, fmt.Errorf("decrypt guardrail secrets: %w", err)
		}
		secrets = dec
	}
	cfg := DriverConfig{
		Definition:       rg.Definition,
		EffectiveConfig:  rg.EffectiveConfig,
		DecryptedSecrets: secrets,
	}
	key := strings.ToLower(strings.TrimSpace(rg.Definition.Provider))
	p.mu.RLock()
	factory := p.factories[key]
	lookup := p.lookup
	p.mu.RUnlock()

	if factory != nil {
		return factory(ctx, cfg)
	}
	if lookup != nil {
		return lookup(ctx, cfg)
	}
	return nil, fmt.Errorf("no guardrail driver registered for provider %q", rg.Definition.Provider)
}

// BuildChatInputEvalInput builds a canonical GuardrailEvalInput from a chat request.
func BuildChatInputEvalInput(hook domain.GuardrailHook, prc PipelineRequestContext, req *domain.CanonicalChatRequest) *domain.GuardrailEvalInput {
	in := &domain.GuardrailEvalInput{
		Direction:      domain.GuardrailDirectionInput,
		Hook:           hook,
		RequestID:      prc.RequestID,
		TraceID:        prc.TraceID,
		OrgID:          prc.OrgID,
		TeamID:         prc.TeamID,
		VirtualKeyID:   prc.VirtualKeyID,
		EndUserID:      prc.EndUserID,
		Model:          prc.Model,
		Tags:           slices.Clone(prc.Tags),
		RequestHeaders: cloneStringMap(prc.RequestHeaders),
		Metadata:       cloneConfigMap(prc.Metadata),
	}
	if req == nil {
		return in
	}
	if in.Model == "" {
		in.Model = req.Model
	}
	in.StructuredMessages = slices.Clone(req.Messages)
	for _, msg := range req.Messages {
		if msg.Content != "" {
			in.Texts = append(in.Texts, msg.Content)
		} else {
			var sb strings.Builder
			for _, part := range msg.Parts {
				switch part.Type {
				case "text":
					sb.WriteString(part.Text)
				case "image_url":
					if part.ImageURL != nil && part.ImageURL.URL != "" {
						in.Images = append(in.Images, *part.ImageURL)
					}
				}
			}
			in.Texts = append(in.Texts, sb.String())
		}
		for _, part := range msg.Parts {
			if part.Type == "image_url" && part.ImageURL != nil && part.ImageURL.URL != "" && msg.Content != "" {
				in.Images = append(in.Images, *part.ImageURL)
			}
		}
	}
	return in
}

// BuildChatOutputEvalInput builds a canonical GuardrailEvalInput from a chat response.
func BuildChatOutputEvalInput(hook domain.GuardrailHook, prc PipelineRequestContext, resp *domain.CanonicalChatResponse) *domain.GuardrailEvalInput {
	in := &domain.GuardrailEvalInput{
		Direction:      domain.GuardrailDirectionOutput,
		Hook:           hook,
		RequestID:      prc.RequestID,
		TraceID:        prc.TraceID,
		OrgID:          prc.OrgID,
		TeamID:         prc.TeamID,
		VirtualKeyID:   prc.VirtualKeyID,
		EndUserID:      prc.EndUserID,
		Model:          prc.Model,
		Tags:           slices.Clone(prc.Tags),
		RequestHeaders: cloneStringMap(prc.RequestHeaders),
		Metadata:       cloneConfigMap(prc.Metadata),
	}
	if resp == nil {
		return in
	}
	for _, ch := range resp.Choices {
		in.StructuredMessages = append(in.StructuredMessages, ch.Message)
		in.Texts = append(in.Texts, ch.Message.Content)
	}
	return in
}

func applyMutationsToChatRequest(req *domain.CanonicalChatRequest, res *domain.GuardrailEvalResult) bool {
	if req == nil || res == nil {
		return false
	}
	changed := false
	if len(res.ModifiedMessages) > 0 {
		req.Messages = slices.Clone(res.ModifiedMessages)
		return true
	}
	if len(res.ModifiedTexts) > 0 {
		for i := 0; i < len(req.Messages) && i < len(res.ModifiedTexts); i++ {
			if req.Messages[i].Content != res.ModifiedTexts[i] {
				req.Messages[i].Content = res.ModifiedTexts[i]
				changed = true
			}
		}
	}
	return changed
}

func applyMutationsToChatResponse(resp *domain.CanonicalChatResponse, res *domain.GuardrailEvalResult) bool {
	if resp == nil || res == nil {
		return false
	}
	changed := false
	if len(res.ModifiedMessages) > 0 {
		for i := 0; i < len(resp.Choices) && i < len(res.ModifiedMessages); i++ {
			resp.Choices[i].Message = res.ModifiedMessages[i]
			changed = true
		}
		return changed
	}
	if len(res.ModifiedTexts) > 0 {
		for i := 0; i < len(resp.Choices) && i < len(res.ModifiedTexts); i++ {
			if resp.Choices[i].Message.Content != res.ModifiedTexts[i] {
				resp.Choices[i].Message.Content = res.ModifiedTexts[i]
				changed = true
			}
		}
	}
	return changed
}

func mergeLegacyOutcome(dst *PipelineOutcome, legacy *CheckOutcome) {
	if dst == nil || legacy == nil {
		return
	}
	dst.LegacyOutcome = legacy
	if legacy.Redacted {
		dst.Redacted = true
	}
	if legacy.AppliedAction != "" {
		dst.AppliedAction = legacy.AppliedAction
	}
	if len(legacy.Violations) > 0 {
		dst.Violations = append(dst.Violations, legacy.Violations...)
		for _, v := range legacy.Violations {
			dst.Result.Violations = append(dst.Result.Violations, domain.GuardrailViolation{
				GuardrailName: "builtin",
				Provider:      "builtin",
				Rule:          v,
				Message:       v,
				Action:        legacy.AppliedAction,
			})
		}
	}
}

func mergeDriverResult(dst *PipelineOutcome, res *domain.GuardrailEvalResult, shadow bool) {
	if dst == nil || res == nil {
		return
	}
	dst.Result.AppliedGuardrails = append(dst.Result.AppliedGuardrails, res.AppliedGuardrails...)
	dst.Result.Violations = append(dst.Result.Violations, res.Violations...)
	for _, v := range res.Violations {
		label := v.Rule
		if label == "" {
			label = v.Message
		}
		if label != "" {
			dst.Violations = append(dst.Violations, label)
		}
	}
	if shadow {
		if len(res.Violations) > 0 && dst.AppliedAction == "" {
			dst.AppliedAction = domain.GuardrailActionAudit
		}
		return
	}
	switch res.Decision {
	case domain.GuardrailDecisionBlock:
		dst.Result.Decision = domain.GuardrailDecisionBlock
		dst.Result.ErrorMessage = res.ErrorMessage
		dst.AppliedAction = domain.GuardrailActionBlock
	case domain.GuardrailDecisionModify:
		if dst.Result.Decision != domain.GuardrailDecisionBlock {
			dst.Result.Decision = domain.GuardrailDecisionModify
		}
		dst.AppliedAction = domain.GuardrailActionRedact
	case domain.GuardrailDecisionFlag:
		if dst.Result.Decision == domain.GuardrailDecisionAllow {
			dst.Result.Decision = domain.GuardrailDecisionFlag
		}
		if dst.AppliedAction == "" {
			dst.AppliedAction = domain.GuardrailActionAudit
		}
	}
}

func newBlockedGatewayError(hook domain.GuardrailHook, name string, res *domain.GuardrailEvalResult) *domain.GatewayError {
	msg := fmt.Sprintf("Request blocked by guardrail %q", name)
	status := http.StatusBadRequest
	errType := domain.ErrorTypeInvalidRequest
	code := "guardrail_blocked"
	if hook == domain.GuardrailHookPostCall {
		msg = fmt.Sprintf("Response blocked by guardrail %q", name)
		status = http.StatusBadGateway
		errType = domain.ErrorTypeServer
		code = "guardrail_output_blocked"
	}
	if res != nil && strings.TrimSpace(res.ErrorMessage) != "" {
		msg = res.ErrorMessage
	}
	return &domain.GatewayError{
		StatusCode: status,
		Type:       errType,
		Code:       code,
		Message:    msg,
	}
}

func guardrailUnavailableError(msg string) *domain.GatewayError {
	return &domain.GatewayError{
		StatusCode: http.StatusServiceUnavailable,
		Type:       domain.ErrorTypeServer,
		Code:       "guardrail_unavailable",
		Message:    msg,
	}
}

func cloneStringMap(src map[string]string) map[string]string {
	if len(src) == 0 {
		return nil
	}
	dst := make(map[string]string, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}
