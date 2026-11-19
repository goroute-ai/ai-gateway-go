package guardrails

import (
	"context"
	"errors"
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

const defaultLoggingOnlyTimeout = 5 * time.Second

// Driver evaluates a single named guardrail provider implementation against a structured input.
// Implementations live in subpackages (such as internal/guardrails/drivers) or SDK adapters
// without introducing circular dependencies on package guardrails.
type Driver interface {
	Name() string
	SupportedHooks() []domain.GuardrailHook
	Evaluate(ctx context.Context, input *domain.GuardrailEvalInput) (*domain.GuardrailEvalResult, error)
}

// DriverConfig provides resolved definition metadata, effective action/config, and optional
// decrypted Vault secrets to construct a Driver instance.
type DriverConfig struct {
	Definition       *domain.GuardrailDefinition
	EffectiveAction  domain.GuardrailAction
	EffectiveConfig  map[string]any
	DecryptedSecrets map[string]any
}

// DriverFactory constructs a Driver for a resolved GuardrailDefinition candidate.
type DriverFactory func(ctx context.Context, cfg DriverConfig) (Driver, error)

// DriverLookup resolves a Driver dynamically when no static DriverFactory is registered
// for a provider name.
type DriverLookup func(ctx context.Context, cfg DriverConfig) (Driver, error)

// SecretDecryptor optionally decrypts Vault-encrypted GuardrailDefinition secrets before
// Driver construction.
type SecretDecryptor func(ctx context.Context, def *domain.GuardrailDefinition) (map[string]any, error)

// AuditHook receives structured guardrail evaluation outcomes (including async logging_only runs).
type AuditHook func(ctx context.Context, hook domain.GuardrailHook, prc PipelineRequestContext, res *domain.GuardrailEvalResult)

// PipelineRequestContext carries tenant, routing, caller role, tag, and request override metadata
// for evaluating all lifecycle hooks in Pipeline.
type PipelineRequestContext struct {
	RequestID        string
	TraceID          string
	OrgID            string
	TeamID           string
	VirtualKeyID     string
	EndUserID        string
	Model            string
	ModelGroupID     string
	CallerRoles      []string
	Tags             []string
	RequestOverrides []domain.GuardrailRequestOverride
	IsStreaming      bool
	RequestHeaders   map[string]string
	Metadata         map[string]any
}

// PipelineOutcome combines Layer 0 GuardrailPolicy outcomes and Layer 1 Driver evaluations.
type PipelineOutcome struct {
	Result        *domain.GuardrailEvalResult
	LegacyOutcome *CheckOutcome
	Redacted      bool
	AppliedAction domain.GuardrailAction
	RouteTarget   string
	Violations    []string
}

// PipelineOption configures optional behavior on a Pipeline.
type PipelineOption func(*Pipeline)

// WithRouterLB overrides the default RouterLB used for weighted load balancing and cooldowns.
func WithRouterLB(lb *RouterLB) PipelineOption {
	return func(p *Pipeline) {
		if lb != nil {
			p.lb = lb
		}
	}
}

// WithAuditHook registers a callback invoked when guardrails produce findings, notably in logging_only.
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

// Pipeline orchestrates Layer 0 legacy GuardrailPolicy (Engine) checks and Layer 1 resolved
// multi-hook named guardrail Drivers across pre_call, parallel during_call, post_call, and logging_only.
type Pipeline struct {
	engine          *Engine
	repo            storage.Repository
	lb              *RouterLB
	mu              sync.RWMutex
	factories       map[string]DriverFactory
	lookup          DriverLookup
	secretDecryptor SecretDecryptor
	auditHook       AuditHook
	bgSem           chan struct{}
	bgWG            sync.WaitGroup
}

// NewPipeline constructs a unified v2 guardrail pipeline wrapping engine and repo.
func NewPipeline(engine *Engine, repo storage.Repository, opts ...PipelineOption) *Pipeline {
	p := &Pipeline{
		engine:    engine,
		repo:      repo,
		lb:        NewRouterLB(LBConfig{}),
		factories: make(map[string]DriverFactory),
		bgSem:     make(chan struct{}, 256),
	}
	for _, opt := range opts {
		if opt != nil {
			opt(p)
		}
	}
	return p
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

// RouterLB returns the pipeline's load balancer and circuit-breaker router.
func (p *Pipeline) RouterLB() *RouterLB {
	if p == nil {
		return nil
	}
	return p.lb
}

// ResolveForHook resolves active guardrails for the requested hook without executing them.
func (p *Pipeline) ResolveForHook(ctx context.Context, prc PipelineRequestContext, hook domain.GuardrailHook) ([]ResolvedGuardrail, error) {
	if p == nil || p.repo == nil || prc.OrgID == "" {
		return nil, nil
	}
	rc := prc.toResolveContext(hook)
	return ResolveEffectiveGuardrails(ctx, p.repo, rc)
}

// EvaluatePreCall runs Layer 0 Engine input checks followed by resolved pre_call Drivers,
// applying modify mutations onto req and blocking/failing-closed as configured.
func (p *Pipeline) EvaluatePreCall(ctx context.Context, prc PipelineRequestContext, req *domain.CanonicalChatRequest) (*PipelineOutcome, error) {
	outcome := &PipelineOutcome{
		Result: &domain.GuardrailEvalResult{Decision: domain.GuardrailDecisionAllow},
	}
	if p == nil || req == nil {
		return outcome, nil
	}

	// Layer 0: Legacy per-org GuardrailPolicy + configured Scanners.
	if p.engine != nil && prc.OrgID != "" {
		legacyOut, err := p.engine.EvaluateInput(ctx, prc.OrgID, req)
		outcome.mergeLegacyOutcome(legacyOut)
		if err != nil {
			outcome.Result.Decision = domain.GuardrailDecisionBlock
			outcome.Result.ErrorMessage = err.Error()
			if outcome.AppliedAction == "" {
				outcome.AppliedAction = domain.GuardrailActionBlock
			}
			return outcome, err
		}
	}

	// Layer 1: Resolved pre_call named guardrails.
	resolved, err := p.ResolveForHook(ctx, prc, domain.GuardrailHookPreCall)
	if err != nil {
		return outcome, policyUnavailableError()
	}
	for _, rg := range resolved {
		evalInput := BuildInputEvalInput(domain.GuardrailHookPreCall, prc, req)
		res, cand, evalErr := p.executeGroup(ctx, rg, evalInput)
		if evalErr != nil {
			outcome.Result.Decision = domain.GuardrailDecisionBlock
			outcome.Result.ErrorMessage = evalErr.Error()
			if outcome.AppliedAction == "" {
				outcome.AppliedAction = domain.GuardrailActionBlock
			}
			return outcome, wrapDriverUnavailableError(rg.Name, evalErr)
		}

		loggingOnly := isCandidateLoggingOnly(cand, res)
		if !loggingOnly && res != nil && strings.TrimSpace(res.RouteTarget) == "" &&
			cand != nil && cand.Definition != nil && strings.TrimSpace(cand.Definition.SensitiveRouteTarget) != "" &&
			res.Decision != domain.GuardrailDecisionAllow && res.Decision != domain.GuardrailDecisionBlock {
			res.RouteTarget = strings.TrimSpace(cand.Definition.SensitiveRouteTarget)
		}
		outcome.mergeDriverResult(rg.Name, res, loggingOnly)
		if loggingOnly {
			continue
		}

		switch res.Decision {
		case domain.GuardrailDecisionModify:
			if applyEvalMutationsToRequest(req, res) {
				outcome.Redacted = true
				if outcome.AppliedAction == "" {
					outcome.AppliedAction = domain.GuardrailActionRedact
				}
			}
		case domain.GuardrailDecisionBlock:
			outcome.AppliedAction = domain.GuardrailActionBlock
			outcome.Result.Decision = domain.GuardrailDecisionBlock
			return outcome, newBlockedGatewayError(domain.GuardrailHookPreCall, rg.Name, res)
		case domain.GuardrailDecisionFlag:
			if outcome.AppliedAction == "" {
				outcome.AppliedAction = domain.GuardrailActionAudit
			}
		}
	}

	return outcome, nil
}

// DuringCallHandle tracks concurrent during_call guardrail evaluation running alongside
// upstream inference and provides Wait/Blocked/Close synchronization.
type DuringCallHandle struct {
	cancelGuardrails context.CancelFunc
	done             chan struct{}
	closeOnce        sync.Once
	mu               sync.Mutex
	outcome          *PipelineOutcome
	err              error
}

// Wait blocks until all during_call guardrails complete or ctx is canceled.
// If a during_call guardrail blocked or failed closed, Wait returns the guardrail GatewayError.
func (h *DuringCallHandle) Wait(ctx context.Context) (*PipelineOutcome, error) {
	if h == nil {
		return &PipelineOutcome{Result: &domain.GuardrailEvalResult{Decision: domain.GuardrailDecisionAllow}}, nil
	}
	select {
	case <-h.done:
		h.mu.Lock()
		defer h.mu.Unlock()
		return h.outcome, h.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// Blocked performs a non-blocking check returning the guardrail block/failure error if
// during_call evaluation has already terminated with an error.
func (h *DuringCallHandle) Blocked() error {
	if h == nil {
		return nil
	}
	select {
	case <-h.done:
		h.mu.Lock()
		defer h.mu.Unlock()
		return h.err
	default:
		return nil
	}
}

// Done returns a channel closed once all during_call guardrails have finished.
func (h *DuringCallHandle) Done() <-chan struct{} {
	if h == nil {
		ch := make(chan struct{})
		close(ch)
		return ch
	}
	return h.done
}

// Close cancels any still-running during_call guardrail contexts and waits for goroutine exit.
func (h *DuringCallHandle) Close() {
	if h == nil {
		return
	}
	h.closeOnce.Do(func() {
		if h.cancelGuardrails != nil {
			h.cancelGuardrails()
		}
		<-h.done
	})
}

// StartDuringCall resolves active during_call guardrails for prc and launches them
// concurrently with upstream inference. If any during_call guardrail blocks or fails closed,
// upstreamCtx is canceled immediately so slow upstream calls abort early.
// When no during_call guardrails apply, parentCtx and a nil handle are returned with zero overhead.
func (p *Pipeline) StartDuringCall(parentCtx context.Context, prc PipelineRequestContext, req *domain.CanonicalChatRequest) (context.Context, *DuringCallHandle, error) {
	if p == nil || req == nil {
		return parentCtx, nil, nil
	}
	resolved, err := p.ResolveForHook(parentCtx, prc, domain.GuardrailHookDuringCall)
	if err != nil {
		return parentCtx, nil, policyUnavailableError()
	}
	if len(resolved) == 0 {
		return parentCtx, nil, nil
	}

	// Snapshot immutable input before spawning concurrent goroutines to prevent races with upstream.
	snapshotInput := BuildInputEvalInput(domain.GuardrailHookDuringCall, prc, req)

	upstreamCtx, cancelUpstream := context.WithCancelCause(parentCtx)
	guardrailCtx, cancelGuardrails := context.WithCancel(parentCtx)

	handle := &DuringCallHandle{
		cancelGuardrails: cancelGuardrails,
		done:             make(chan struct{}),
		outcome: &PipelineOutcome{
			Result: &domain.GuardrailEvalResult{Decision: domain.GuardrailDecisionAllow},
		},
	}

	go func() {
		defer close(handle.done)
		defer cancelGuardrails()

		type groupOutcome struct {
			idx         int
			name        string
			res         *domain.GuardrailEvalResult
			cand        *ResolvedCandidate
			err         error
			loggingOnly bool
		}

		results := make([]groupOutcome, len(resolved))
		var wg sync.WaitGroup
		var firstBlockOnce sync.Once

		for i, rg := range resolved {
			wg.Add(1)
			go func(idx int, group ResolvedGuardrail) {
				defer wg.Done()
				inputCopy := cloneGuardrailEvalInput(snapshotInput)
				res, cand, evalErr := p.executeGroup(guardrailCtx, group, inputCopy)
				if evalErr != nil {
					if guardrailCtx.Err() != nil && parentCtx.Err() == nil {
						// Canceled because another parallel during_call guardrail already blocked.
						return
					}
					gwErr := wrapDriverUnavailableError(group.Name, evalErr)
					results[idx] = groupOutcome{idx: idx, name: group.Name, err: gwErr}
					firstBlockOnce.Do(func() {
						cancelUpstream(gwErr)
						cancelGuardrails()
					})
					return
				}

				loggingOnly := isCandidateLoggingOnly(cand, res)
				results[idx] = groupOutcome{
					idx:         idx,
					name:        group.Name,
					res:         res,
					cand:        cand,
					loggingOnly: loggingOnly,
				}
				if !loggingOnly && res.Decision == domain.GuardrailDecisionBlock {
					gwErr := newBlockedGatewayError(domain.GuardrailHookDuringCall, group.Name, res)
					results[idx].err = gwErr
					firstBlockOnce.Do(func() {
						cancelUpstream(gwErr)
						cancelGuardrails()
					})
				}
			}(i, rg)
		}

		wg.Wait()

		handle.mu.Lock()
		defer handle.mu.Unlock()
		for _, item := range results {
			if item.name == "" && item.err == nil {
				continue
			}
			if item.res != nil {
				handle.outcome.mergeDriverResult(item.name, item.res, item.loggingOnly)
			}
			if item.err != nil && handle.err == nil {
				handle.err = item.err
				handle.outcome.Result.Decision = domain.GuardrailDecisionBlock
				handle.outcome.Result.ErrorMessage = item.err.Error()
				handle.outcome.AppliedAction = domain.GuardrailActionBlock
			}
		}
		if handle.err == nil {
			// Ensure upstreamCtx cancel function is released cleanly on success path when handle closes
			// without canceling parent work; upstream finishes normally and Close/Done clean up.
			_ = cancelUpstream
		}
	}()

	return upstreamCtx, handle, nil
}

// EvaluatePostCall runs Layer 0 Engine output sanitization followed by resolved post_call Drivers,
// applying modify mutations onto resp (content, parts, tool_calls) and blocking/failing-closed.
func (p *Pipeline) EvaluatePostCall(ctx context.Context, prc PipelineRequestContext, resp *domain.CanonicalChatResponse) (*PipelineOutcome, error) {
	outcome := &PipelineOutcome{
		Result: &domain.GuardrailEvalResult{Decision: domain.GuardrailDecisionAllow},
	}
	if p == nil || resp == nil {
		return outcome, nil
	}

	// Layer 0: Legacy GuardrailPolicy + configured Scanners.
	if p.engine != nil && prc.OrgID != "" {
		pol, err := p.engine.Policy(ctx, prc.OrgID)
		if err != nil {
			return outcome, err
		}
		if pol != nil || len(p.engine.scanners) > 0 {
			if pol == nil {
				pol = &domain.GuardrailPolicy{OrgID: prc.OrgID}
			}
			legacyOut, evalErr := p.engine.EvaluateOutputWithPolicy(ctx, pol, resp)
			outcome.mergeLegacyOutcome(legacyOut)
			if evalErr != nil {
				outcome.Result.Decision = domain.GuardrailDecisionBlock
				outcome.Result.ErrorMessage = evalErr.Error()
				if outcome.AppliedAction == "" {
					outcome.AppliedAction = domain.GuardrailActionBlock
				}
				return outcome, evalErr
			}
		}
	}

	// Layer 1: Resolved post_call named guardrails.
	resolved, err := p.ResolveForHook(ctx, prc, domain.GuardrailHookPostCall)
	if err != nil {
		return outcome, policyUnavailableError()
	}
	for _, rg := range resolved {
		evalInput := BuildOutputEvalInput(domain.GuardrailHookPostCall, prc, resp)
		res, cand, evalErr := p.executeGroup(ctx, rg, evalInput)
		if evalErr != nil {
			outcome.Result.Decision = domain.GuardrailDecisionBlock
			outcome.Result.ErrorMessage = evalErr.Error()
			if outcome.AppliedAction == "" {
				outcome.AppliedAction = domain.GuardrailActionBlock
			}
			return outcome, wrapDriverUnavailableError(rg.Name, evalErr)
		}

		loggingOnly := isCandidateLoggingOnly(cand, res)
		outcome.mergeDriverResult(rg.Name, res, loggingOnly)
		if loggingOnly {
			continue
		}

		switch res.Decision {
		case domain.GuardrailDecisionModify:
			if applyEvalMutationsToResponse(resp, res) {
				outcome.Redacted = true
				if outcome.AppliedAction == "" {
					outcome.AppliedAction = domain.GuardrailActionRedact
				}
			}
		case domain.GuardrailDecisionBlock:
			outcome.AppliedAction = domain.GuardrailActionBlock
			outcome.Result.Decision = domain.GuardrailDecisionBlock
			return outcome, newBlockedGatewayError(domain.GuardrailHookPostCall, rg.Name, res)
		case domain.GuardrailDecisionFlag:
			if outcome.AppliedAction == "" {
				outcome.AppliedAction = domain.GuardrailActionAudit
			}
		}
	}

	return outcome, nil
}

// EvaluatePostCallText evaluates pre-resolved post_call guardrails against a single text segment
// (for example, flushed SSE stream segments), returning updated text or an error on block.
func (p *Pipeline) EvaluatePostCallText(ctx context.Context, prc PipelineRequestContext, resolved []ResolvedGuardrail, text string) (string, *PipelineOutcome, error) {
	outcome := &PipelineOutcome{
		Result: &domain.GuardrailEvalResult{Decision: domain.GuardrailDecisionAllow},
	}
	if p == nil || len(resolved) == 0 || text == "" {
		return text, outcome, nil
	}
	probe := &domain.CanonicalChatResponse{
		Model: prc.Model,
		Choices: []domain.CanonicalChoice{
			{Index: 0, Message: domain.CanonicalMessage{Role: "assistant", Content: text}},
		},
	}
	for _, rg := range resolved {
		evalInput := BuildOutputEvalInput(domain.GuardrailHookPostCall, prc, probe)
		res, cand, evalErr := p.executeGroup(ctx, rg, evalInput)
		if evalErr != nil {
			outcome.Result.Decision = domain.GuardrailDecisionBlock
			return "", outcome, wrapDriverUnavailableError(rg.Name, evalErr)
		}
		loggingOnly := isCandidateLoggingOnly(cand, res)
		outcome.mergeDriverResult(rg.Name, res, loggingOnly)
		if loggingOnly {
			continue
		}
		switch res.Decision {
		case domain.GuardrailDecisionModify:
			if applyEvalMutationsToResponse(probe, res) {
				outcome.Redacted = true
			}
		case domain.GuardrailDecisionBlock:
			outcome.AppliedAction = domain.GuardrailActionBlock
			outcome.Result.Decision = domain.GuardrailDecisionBlock
			return "", outcome, newBlockedGatewayError(domain.GuardrailHookPostCall, rg.Name, res)
		}
	}
	return probe.Choices[0].Message.Content, outcome, nil
}

// EvaluateLoggingOnly resolves and dispatches logging_only guardrails asynchronously on a
// non-blocking background goroutine. It never blocks, fails, or mutates the request or response.
func (p *Pipeline) EvaluateLoggingOnly(ctx context.Context, prc PipelineRequestContext, req *domain.CanonicalChatRequest, resp *domain.CanonicalChatResponse) {
	if p == nil || p.repo == nil || prc.OrgID == "" {
		return
	}
	resolved, err := p.ResolveForHook(ctx, prc, domain.GuardrailHookLoggingOnly)
	if err != nil || len(resolved) == 0 {
		return
	}

	var snapshot *domain.GuardrailEvalInput
	if resp != nil {
		snapshot = BuildOutputEvalInput(domain.GuardrailHookLoggingOnly, prc, resp)
	} else if req != nil {
		snapshot = BuildInputEvalInput(domain.GuardrailHookLoggingOnly, prc, req)
	} else {
		snapshot = &domain.GuardrailEvalInput{
			Direction:    domain.GuardrailDirectionInput,
			Hook:         domain.GuardrailHookLoggingOnly,
			RequestID:    prc.RequestID,
			TraceID:      prc.TraceID,
			OrgID:        prc.OrgID,
			TeamID:       prc.TeamID,
			VirtualKeyID: prc.VirtualKeyID,
			EndUserID:    prc.EndUserID,
			Model:        prc.Model,
			Tags:         slices.Clone(prc.Tags),
		}
	}

	select {
	case p.bgSem <- struct{}{}:
	default:
		logger.WarnContext(ctx, "Skipping async logging_only guardrail evaluation because background queue is saturated",
			slog.String("component", "guardrails"),
			slog.String("org_id", prc.OrgID),
			slog.String("request_id", prc.RequestID),
		)
		return
	}

	bgCtx := context.WithoutCancel(ctx)
	p.bgWG.Add(1)
	go func() {
		defer p.bgWG.Done()
		defer func() { <-p.bgSem }()

		agg := &domain.GuardrailEvalResult{Decision: domain.GuardrailDecisionAllow}
		for _, rg := range resolved {
			evalCtx := bgCtx
			if rg.TimeoutMs <= 0 {
				var cancel context.CancelFunc
				evalCtx, cancel = context.WithTimeout(bgCtx, defaultLoggingOnlyTimeout)
				res, _, evalErr := p.executeGroup(evalCtx, rg, cloneGuardrailEvalInput(snapshot))
				cancel()
				if evalErr != nil {
					logger.WarnContext(bgCtx, "Async logging_only guardrail failed",
						slog.String("component", "guardrails"),
						slog.String("org_id", prc.OrgID),
						slog.String("guardrail", rg.Name),
						slog.String("error", evalErr.Error()),
					)
					continue
				}
				agg.AppliedGuardrails = append(agg.AppliedGuardrails, rg.Name)
				if res != nil && len(res.Violations) > 0 {
					agg.Violations = append(agg.Violations, res.Violations...)
				}
				continue
			}

			res, _, evalErr := p.executeGroup(evalCtx, rg, cloneGuardrailEvalInput(snapshot))
			if evalErr != nil {
				logger.WarnContext(bgCtx, "Async logging_only guardrail failed",
					slog.String("component", "guardrails"),
					slog.String("org_id", prc.OrgID),
					slog.String("guardrail", rg.Name),
					slog.String("error", evalErr.Error()),
				)
				continue
			}
			agg.AppliedGuardrails = append(agg.AppliedGuardrails, rg.Name)
			if res != nil && len(res.Violations) > 0 {
				agg.Violations = append(agg.Violations, res.Violations...)
			}
		}

		if len(agg.Violations) > 0 {
			logger.WarnContext(bgCtx, "Async logging_only guardrail violations observed",
				slog.String("component", "guardrails"),
				slog.String("org_id", prc.OrgID),
				slog.String("request_id", prc.RequestID),
				slog.Any("guardrails", agg.AppliedGuardrails),
				slog.Int("violation_count", len(agg.Violations)),
			)
		}
		if p.auditHook != nil && (len(agg.Violations) > 0 || len(agg.AppliedGuardrails) > 0) {
			p.auditHook(bgCtx, domain.GuardrailHookLoggingOnly, prc, agg)
		}
	}()
}

// WaitLoggingOnly waits for any in-flight async logging_only evaluations to complete.
func (p *Pipeline) WaitLoggingOnly(ctx context.Context) error {
	if p == nil {
		return nil
	}
	done := make(chan struct{})
	go func() {
		p.bgWG.Wait()
		close(done)
	}()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (p *Pipeline) executeGroup(
	ctx context.Context,
	rg ResolvedGuardrail,
	evalInput *domain.GuardrailEvalInput,
) (*domain.GuardrailEvalResult, *ResolvedCandidate, error) {
	if p.lb == nil {
		p.lb = NewRouterLB(LBConfig{})
	}
	return p.lb.Execute(ctx, rg, func(candCtx context.Context, cand *ResolvedCandidate) (*domain.GuardrailEvalResult, error) {
		if cand.TimeoutMs > 0 {
			var cancel context.CancelFunc
			candCtx, cancel = context.WithTimeout(candCtx, time.Duration(cand.TimeoutMs)*time.Millisecond)
			defer cancel()
		}

		drv, err := p.resolveDriver(candCtx, cand)
		if err != nil {
			return nil, err
		}
		if hooks := drv.SupportedHooks(); len(hooks) > 0 && evalInput.Hook != "" {
			if !slices.Contains(hooks, evalInput.Hook) {
				return &domain.GuardrailEvalResult{
					Decision:          domain.GuardrailDecisionAllow,
					AppliedGuardrails: []string{cand.Definition.Name},
				}, nil
			}
		}
		res, err := drv.Evaluate(candCtx, evalInput)
		if err != nil {
			return nil, err
		}
		if res == nil {
			res = &domain.GuardrailEvalResult{Decision: domain.GuardrailDecisionAllow}
		}
		if res.Decision == "" {
			res.Decision = domain.GuardrailDecisionAllow
		}
		return res, nil
	})
}

func (p *Pipeline) resolveDriver(ctx context.Context, cand *ResolvedCandidate) (Driver, error) {
	if cand == nil || cand.Definition == nil {
		return nil, fmt.Errorf("missing guardrail definition candidate")
	}

	var secrets map[string]any
	if p.secretDecryptor != nil && cand.Definition.EncryptedSecrets != "" {
		dec, err := p.secretDecryptor(ctx, cand.Definition)
		if err != nil {
			return nil, fmt.Errorf("decrypt guardrail secrets for %q: %w", cand.Definition.Name, err)
		}
		secrets = dec
	}

	cfg := DriverConfig{
		Definition:       cand.Definition,
		EffectiveAction:  cand.EffectiveAction,
		EffectiveConfig:  cloneConfigMap(cand.EffectiveConfig),
		DecryptedSecrets: secrets,
	}

	providerKey := strings.ToLower(strings.TrimSpace(cand.Definition.Provider))
	p.mu.RLock()
	factory := p.factories[providerKey]
	lookup := p.lookup
	p.mu.RUnlock()

	if factory != nil {
		return factory(ctx, cfg)
	}
	if lookup != nil {
		drv, err := lookup(ctx, cfg)
		if err == nil && drv != nil {
			return drv, nil
		}
		if err != nil {
			return nil, err
		}
	}
	return nil, fmt.Errorf("no guardrail driver registered for provider %q", cand.Definition.Provider)
}

func (prc PipelineRequestContext) toResolveContext(hook domain.GuardrailHook) ResolveContext {
	return ResolveContext{
		OrgID:            prc.OrgID,
		TeamID:           prc.TeamID,
		VirtualKeyID:     prc.VirtualKeyID,
		EndUserID:        prc.EndUserID,
		Model:            prc.Model,
		ModelGroupID:     prc.ModelGroupID,
		CallerRoles:      prc.CallerRoles,
		Tags:             prc.Tags,
		RequestOverrides: prc.RequestOverrides,
		Hook:             hook,
		IsStreaming:      prc.IsStreaming,
	}
}

// BuildInputEvalInput constructs a structured GuardrailEvalInput from a CanonicalChatRequest.
func BuildInputEvalInput(hook domain.GuardrailHook, prc PipelineRequestContext, req *domain.CanonicalChatRequest) *domain.GuardrailEvalInput {
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
	if in.RequestID == "" {
		in.RequestID = req.RequestID
	}
	if in.Model == "" {
		in.Model = req.Model
	}
	if len(req.Tools) > 0 {
		in.Tools = slices.Clone(req.Tools)
	}
	in.StructuredMessages = cloneCanonicalMessages(req.Messages)
	in.Texts = make([]string, len(req.Messages))
	for i := range req.Messages {
		msg := &req.Messages[i]
		if msg.Content != "" {
			in.Texts[i] = msg.Content
		} else {
			in.Texts[i] = collectMessagePartsText(msg.Parts)
		}
		for _, part := range msg.Parts {
			if part.Type == "image_url" && part.ImageURL != nil {
				in.Images = append(in.Images, *part.ImageURL)
			}
		}
		for _, tc := range msg.ToolCalls {
			in.ToolCalls = append(in.ToolCalls, cloneToolCall(tc))
		}
	}
	return in
}

// BuildOutputEvalInput constructs a structured GuardrailEvalInput from a CanonicalChatResponse.
func BuildOutputEvalInput(hook domain.GuardrailHook, prc PipelineRequestContext, resp *domain.CanonicalChatResponse) *domain.GuardrailEvalInput {
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
	if in.Model == "" {
		in.Model = resp.Model
	}
	in.StructuredMessages = make([]domain.CanonicalMessage, len(resp.Choices))
	in.Texts = make([]string, len(resp.Choices))
	for i := range resp.Choices {
		msg := resp.Choices[i].Message
		in.StructuredMessages[i] = cloneCanonicalMessage(msg)
		if msg.Content != "" {
			in.Texts[i] = msg.Content
		} else {
			in.Texts[i] = collectMessagePartsText(msg.Parts)
		}
		for _, part := range msg.Parts {
			if part.Type == "image_url" && part.ImageURL != nil {
				in.Images = append(in.Images, *part.ImageURL)
			}
		}
		for _, tc := range msg.ToolCalls {
			in.ToolCalls = append(in.ToolCalls, cloneToolCall(tc))
		}
	}
	return in
}

func applyEvalMutationsToRequest(req *domain.CanonicalChatRequest, res *domain.GuardrailEvalResult) bool {
	if req == nil || res == nil || res.Decision != domain.GuardrailDecisionModify {
		return false
	}
	changed := false

	if len(res.ModifiedMessages) > 0 {
		orig := req.Messages
		updated := cloneCanonicalMessages(res.ModifiedMessages)
		for i := range updated {
			var origMsg *domain.CanonicalMessage
			if i < len(orig) {
				origMsg = &orig[i]
				if len(updated[i].ToolCalls) == 0 && len(orig[i].ToolCalls) > 0 && len(res.ModifiedToolCalls) > 0 {
					updated[i].ToolCalls = cloneToolCalls(orig[i].ToolCalls)
				}
			}
			syncModifiedMessageContentAndParts(&updated[i], origMsg)
		}
		req.Messages = updated
		changed = true
	} else if len(res.ModifiedTexts) > 0 {
		if applyModifiedTextsToMessages(req.Messages, res.ModifiedTexts) {
			changed = true
		}
	}

	if len(res.ModifiedToolCalls) > 0 {
		if applyModifiedToolCallsToMessages(req.Messages, res.ModifiedToolCalls) {
			changed = true
		}
	}
	return changed
}

func applyEvalMutationsToResponse(resp *domain.CanonicalChatResponse, res *domain.GuardrailEvalResult) bool {
	if resp == nil || res == nil || res.Decision != domain.GuardrailDecisionModify {
		return false
	}
	changed := false

	if len(res.ModifiedMessages) > 0 {
		for i := 0; i < len(resp.Choices) && i < len(res.ModifiedMessages); i++ {
			orig := resp.Choices[i].Message
			updated := cloneCanonicalMessage(res.ModifiedMessages[i])
			if len(updated.ToolCalls) == 0 && len(orig.ToolCalls) > 0 && len(res.ModifiedToolCalls) > 0 {
				updated.ToolCalls = cloneToolCalls(orig.ToolCalls)
			}
			syncModifiedMessageContentAndParts(&updated, &orig)
			resp.Choices[i].Message = updated
			changed = true
		}
	} else if len(res.ModifiedTexts) > 0 {
		for i := 0; i < len(resp.Choices) && i < len(res.ModifiedTexts); i++ {
			msg := &resp.Choices[i].Message
			if msg.Content != res.ModifiedTexts[i] {
				changed = true
			}
			msg.Content = res.ModifiedTexts[i]
			if syncTextIntoParts(&msg.Parts, res.ModifiedTexts[i]) {
				changed = true
			}
		}
	}

	if len(res.ModifiedToolCalls) > 0 {
		msgs := make([]domain.CanonicalMessage, len(resp.Choices))
		for i := range resp.Choices {
			msgs[i] = resp.Choices[i].Message
		}
		if applyModifiedToolCallsToMessages(msgs, res.ModifiedToolCalls) {
			for i := range resp.Choices {
				resp.Choices[i].Message = msgs[i]
			}
			changed = true
		}
	}
	return changed
}

func applyModifiedTextsToMessages(msgs []domain.CanonicalMessage, modified []string) bool {
	if len(msgs) == 0 || len(modified) == 0 {
		return false
	}
	changed := false
	if len(modified) == len(msgs) {
		for i := range msgs {
			if msgs[i].Content != modified[i] {
				changed = true
			}
			msgs[i].Content = modified[i]
			if syncTextIntoParts(&msgs[i].Parts, modified[i]) {
				changed = true
			}
		}
		return changed
	}

	// Support drivers that return ModifiedTexts only for non-empty messages.
	var nonEmpty []int
	for i := range msgs {
		if msgs[i].Content != "" || collectMessagePartsText(msgs[i].Parts) != "" {
			nonEmpty = append(nonEmpty, i)
		}
	}
	if len(modified) == len(nonEmpty) {
		for idx, msgIdx := range nonEmpty {
			if msgs[msgIdx].Content != modified[idx] {
				changed = true
			}
			msgs[msgIdx].Content = modified[idx]
			if syncTextIntoParts(&msgs[msgIdx].Parts, modified[idx]) {
				changed = true
			}
		}
		return changed
	}

	// Single-string fallback targets the last user message (or last message).
	if len(modified) == 1 {
		target := len(msgs) - 1
		for i := len(msgs) - 1; i >= 0; i-- {
			if strings.EqualFold(msgs[i].Role, "user") {
				target = i
				break
			}
		}
		if msgs[target].Content != modified[0] {
			changed = true
		}
		msgs[target].Content = modified[0]
		if syncTextIntoParts(&msgs[target].Parts, modified[0]) {
			changed = true
		}
	}
	return changed
}

func applyModifiedToolCallsToMessages(msgs []domain.CanonicalMessage, modified []domain.CanonicalToolCall) bool {
	if len(msgs) == 0 || len(modified) == 0 {
		return false
	}
	type tcLoc struct {
		msgIdx int
		tcIdx  int
	}
	var locs []tcLoc
	msgsWithTools := make(map[int]struct{})
	byID := make(map[string]tcLoc)
	for mi := range msgs {
		for ti := range msgs[mi].ToolCalls {
			loc := tcLoc{msgIdx: mi, tcIdx: ti}
			locs = append(locs, loc)
			msgsWithTools[mi] = struct{}{}
			if id := msgs[mi].ToolCalls[ti].ID; id != "" {
				byID[id] = loc
			}
		}
	}
	if len(locs) == 0 {
		return false
	}

	if len(msgsWithTools) == 1 && len(modified) != len(locs) {
		for mi := range msgsWithTools {
			msgs[mi].ToolCalls = cloneToolCalls(modified)
			return true
		}
	}

	changed := false
	for i, mtc := range modified {
		var loc tcLoc
		var ok bool
		if mtc.ID != "" {
			loc, ok = byID[mtc.ID]
		}
		if !ok && i < len(locs) {
			loc = locs[i]
			ok = true
		}
		if ok {
			msgs[loc.msgIdx].ToolCalls[loc.tcIdx] = cloneToolCall(mtc)
			changed = true
		}
	}
	return changed
}

func syncModifiedMessageContentAndParts(updated *domain.CanonicalMessage, orig *domain.CanonicalMessage) {
	if updated == nil || len(updated.Parts) == 0 {
		return
	}
	updatedPartsText := collectMessagePartsText(updated.Parts)
	if orig != nil {
		origPartsText := collectMessagePartsText(orig.Parts)
		contentChanged := updated.Content != orig.Content
		partsChanged := updatedPartsText != origPartsText
		switch {
		case partsChanged && !contentChanged:
			updated.Content = updatedPartsText
			return
		case contentChanged && !partsChanged:
			syncTextIntoParts(&updated.Parts, updated.Content)
			return
		case contentChanged && partsChanged:
			// Driver intentionally updated both Content and Parts; preserve both as returned.
			return
		}
	}
	if updated.Content == "" && updatedPartsText != "" {
		updated.Content = updatedPartsText
	} else if orig == nil && updated.Content != "" && updatedPartsText != "" && updated.Content != updatedPartsText {
		syncTextIntoParts(&updated.Parts, updated.Content)
	}
}

func syncTextIntoParts(parts *[]domain.ContentPart, newText string) bool {
	if parts == nil || len(*parts) == 0 {
		return false
	}
	firstTextIdx := -1
	changed := false
	for i := range *parts {
		if (*parts)[i].Type == "text" {
			if firstTextIdx < 0 {
				firstTextIdx = i
				if (*parts)[i].Text != newText {
					(*parts)[i].Text = newText
					changed = true
				}
			} else if (*parts)[i].Text != "" {
				(*parts)[i].Text = ""
				changed = true
			}
		}
	}
	return changed
}

func collectMessagePartsText(parts []domain.ContentPart) string {
	var sb strings.Builder
	for i := range parts {
		if parts[i].Type == "text" {
			sb.WriteString(parts[i].Text)
		}
	}
	return sb.String()
}

func isCandidateLoggingOnly(cand *ResolvedCandidate, res *domain.GuardrailEvalResult) bool {
	if cand != nil {
		if mode, ok := cand.EffectiveConfig["mode"].(string); ok && strings.EqualFold(strings.TrimSpace(mode), string(domain.GuardrailModeLoggingOnly)) {
			return true
		}
		if lo, ok := cand.EffectiveConfig["logging_only"].(bool); ok && lo {
			return true
		}
		if cand.EffectiveAction == domain.GuardrailActionAudit && res != nil && res.Decision == domain.GuardrailDecisionBlock {
			return true
		}
	}
	return false
}

func newBlockedGatewayError(hook domain.GuardrailHook, guardrailName string, res *domain.GuardrailEvalResult) *domain.GatewayError {
	msg := fmt.Sprintf("Request blocked by security guardrail %q", guardrailName)
	code := "guardrail_blocked"
	status := http.StatusBadRequest
	errType := domain.ErrorTypeInvalidRequest

	if hook == domain.GuardrailHookPostCall {
		status = http.StatusBadGateway
		errType = domain.ErrorTypeServer
		code = "guardrail_output_blocked"
		msg = fmt.Sprintf("Response blocked by security guardrail %q", guardrailName)
	}

	if res != nil {
		if res.ErrorMessage != "" {
			msg = res.ErrorMessage
		} else if len(res.Violations) > 0 && res.Violations[0].Message != "" {
			msg = res.Violations[0].Message
		}
	}

	return &domain.GatewayError{
		StatusCode: status,
		Type:       errType,
		Code:       code,
		Message:    msg,
	}
}

func wrapDriverUnavailableError(guardrailName string, err error) error {
	var gwErr *domain.GatewayError
	if errors.As(err, &gwErr) {
		return gwErr
	}
	return &domain.GatewayError{
		StatusCode: http.StatusServiceUnavailable,
		Type:       domain.ErrorTypeServer,
		Code:       "guardrail_unavailable",
		Message:    fmt.Sprintf("Security guardrail %q could not evaluate request: %v", guardrailName, err),
	}
}

func (o *PipelineOutcome) mergeLegacyOutcome(legacy *CheckOutcome) {
	if o == nil || legacy == nil {
		return
	}
	o.LegacyOutcome = legacy
	if legacy.Redacted {
		o.Redacted = true
	}
	if legacy.AppliedAction != "" {
		o.AppliedAction = legacy.AppliedAction
	}
	if strings.TrimSpace(legacy.RouteTarget) != "" {
		o.RouteTarget = strings.TrimSpace(legacy.RouteTarget)
	}
	o.Violations = append(o.Violations, legacy.Violations...)
}

func (o *PipelineOutcome) mergeDriverResult(guardrailName string, res *domain.GuardrailEvalResult, loggingOnly bool) {
	if o == nil || res == nil {
		return
	}
	if o.Result == nil {
		o.Result = &domain.GuardrailEvalResult{Decision: domain.GuardrailDecisionAllow}
	}
	if len(res.AppliedGuardrails) > 0 {
		o.Result.AppliedGuardrails = append(o.Result.AppliedGuardrails, res.AppliedGuardrails...)
	} else if guardrailName != "" {
		o.Result.AppliedGuardrails = append(o.Result.AppliedGuardrails, guardrailName)
	}
	o.Result.UsageUnits += res.UsageUnits
	if len(res.Violations) > 0 {
		o.Result.Violations = append(o.Result.Violations, res.Violations...)
		for _, v := range res.Violations {
			label := v.Rule
			if label == "" {
				label = v.Category
			}
			if label == "" {
				label = v.GuardrailName
			}
			if label == "" {
				label = guardrailName
			}
			o.Violations = append(o.Violations, label)
		}
	}
	if loggingOnly {
		if len(res.Violations) > 0 && o.AppliedAction == "" {
			o.AppliedAction = domain.GuardrailActionAudit
		}
		return
	}
	if o.Result.Decision == "" || o.Result.Decision == domain.GuardrailDecisionAllow {
		o.Result.Decision = res.Decision
	} else if res.Decision == domain.GuardrailDecisionBlock {
		o.Result.Decision = domain.GuardrailDecisionBlock
	} else if res.Decision == domain.GuardrailDecisionModify && o.Result.Decision != domain.GuardrailDecisionBlock {
		o.Result.Decision = domain.GuardrailDecisionModify
	}
	if len(res.ModifiedTexts) > 0 {
		o.Result.ModifiedTexts = slices.Clone(res.ModifiedTexts)
	}
	if len(res.ModifiedMessages) > 0 {
		o.Result.ModifiedMessages = cloneCanonicalMessages(res.ModifiedMessages)
	}
	if len(res.ModifiedToolCalls) > 0 {
		o.Result.ModifiedToolCalls = cloneToolCalls(res.ModifiedToolCalls)
	}
	if target := strings.TrimSpace(res.RouteTarget); target != "" && res.Decision != domain.GuardrailDecisionBlock {
		o.RouteTarget = target
		o.Result.RouteTarget = target
		if o.AppliedAction == "" {
			o.AppliedAction = domain.GuardrailActionRoute
		}
	}
}

func cloneGuardrailEvalInput(in *domain.GuardrailEvalInput) *domain.GuardrailEvalInput {
	if in == nil {
		return nil
	}
	cp := *in
	cp.Tags = slices.Clone(in.Tags)
	cp.Texts = slices.Clone(in.Texts)
	cp.StructuredMessages = cloneCanonicalMessages(in.StructuredMessages)
	cp.Images = slices.Clone(in.Images)
	cp.Tools = slices.Clone(in.Tools)
	cp.ToolCalls = cloneToolCalls(in.ToolCalls)
	cp.RequestHeaders = cloneStringMap(in.RequestHeaders)
	cp.Metadata = cloneConfigMap(in.Metadata)
	return &cp
}

func cloneCanonicalMessages(msgs []domain.CanonicalMessage) []domain.CanonicalMessage {
	if msgs == nil {
		return nil
	}
	out := make([]domain.CanonicalMessage, len(msgs))
	for i := range msgs {
		out[i] = cloneCanonicalMessage(msgs[i])
	}
	return out
}

func cloneCanonicalMessage(m domain.CanonicalMessage) domain.CanonicalMessage {
	cp := m
	if m.Parts != nil {
		cp.Parts = make([]domain.ContentPart, len(m.Parts))
		for i, p := range m.Parts {
			cp.Parts[i] = p
			if p.ImageURL != nil {
				img := *p.ImageURL
				cp.Parts[i].ImageURL = &img
			}
			if p.Document != nil {
				doc := *p.Document
				cp.Parts[i].Document = &doc
			}
		}
	}
	cp.ToolCalls = cloneToolCalls(m.ToolCalls)
	cp.Annotations = slices.Clone(m.Annotations)
	return cp
}

func cloneToolCalls(tcs []domain.CanonicalToolCall) []domain.CanonicalToolCall {
	if tcs == nil {
		return nil
	}
	out := make([]domain.CanonicalToolCall, len(tcs))
	for i, tc := range tcs {
		out[i] = cloneToolCall(tc)
	}
	return out
}

func cloneToolCall(tc domain.CanonicalToolCall) domain.CanonicalToolCall {
	cp := tc
	if tc.Index != nil {
		idx := *tc.Index
		cp.Index = &idx
	}
	return cp
}

func cloneStringMap(src map[string]string) map[string]string {
	if src == nil {
		return nil
	}
	out := make(map[string]string, len(src))
	for k, v := range src {
		out[k] = v
	}
	return out
}

// NewResolvedDriverAdapter wraps a ResolvedGuardrail group as a single Driver executed
// through Pipeline load balancing, cooldowns, Vault decryption, and audit hooks.
func (p *Pipeline) NewResolvedDriverAdapter(prc PipelineRequestContext, hook domain.GuardrailHook, rg ResolvedGuardrail) Driver {
	if p == nil {
		return nil
	}
	return &resolvedDriverAdapter{
		pipeline: p,
		prc:      prc,
		hook:     hook,
		rg:       rg,
	}
}

type resolvedDriverAdapter struct {
	pipeline *Pipeline
	prc      PipelineRequestContext
	hook     domain.GuardrailHook
	rg       ResolvedGuardrail
}

func (a *resolvedDriverAdapter) Name() string { return a.rg.Name }

func (a *resolvedDriverAdapter) SupportedHooks() []domain.GuardrailHook {
	if a.hook == "" {
		return nil
	}
	return []domain.GuardrailHook{a.hook}
}

func (a *resolvedDriverAdapter) Evaluate(ctx context.Context, input *domain.GuardrailEvalInput) (*domain.GuardrailEvalResult, error) {
	in := cloneGuardrailEvalInput(input)
	if in == nil {
		in = &domain.GuardrailEvalInput{}
	}
	if in.Hook == "" {
		in.Hook = a.hook
	}
	if in.OrgID == "" {
		in.OrgID = a.prc.OrgID
	}
	if in.TeamID == "" {
		in.TeamID = a.prc.TeamID
	}
	if in.VirtualKeyID == "" {
		in.VirtualKeyID = a.prc.VirtualKeyID
	}
	if in.EndUserID == "" {
		in.EndUserID = a.prc.EndUserID
	}
	if in.Model == "" {
		in.Model = a.prc.Model
	}
	if len(in.Tags) == 0 && len(a.prc.Tags) > 0 {
		in.Tags = slices.Clone(a.prc.Tags)
	}
	res, cand, err := a.pipeline.executeGroup(ctx, a.rg, in)
	if err != nil {
		return nil, err
	}
	if res == nil {
		res = &domain.GuardrailEvalResult{Decision: domain.GuardrailDecisionAllow}
	}
	if a.pipeline.auditHook != nil {
		a.pipeline.auditHook(ctx, in.Hook, a.prc, res)
	}
	if isCandidateLoggingOnly(cand, res) {
		return &domain.GuardrailEvalResult{
			Decision:          domain.GuardrailDecisionAllow,
			Violations:        append([]domain.GuardrailViolation(nil), res.Violations...),
			AppliedGuardrails: append([]string(nil), res.AppliedGuardrails...),
			UsageUnits:        res.UsageUnits,
		}, nil
	}
	return res, nil
}

// EvaluateResolvedInput resolves and executes all active Layer 1 guardrails for hook
// against an arbitrary structured GuardrailEvalInput (preserving modify chains and locks).
func (p *Pipeline) EvaluateResolvedInput(
	ctx context.Context,
	prc PipelineRequestContext,
	hook domain.GuardrailHook,
	input *domain.GuardrailEvalInput,
) (*domain.GuardrailEvalResult, error) {
	agg := &domain.GuardrailEvalResult{Decision: domain.GuardrailDecisionAllow}
	if p == nil || input == nil {
		return agg, nil
	}
	resolved, err := p.ResolveForHook(ctx, prc, hook)
	if err != nil {
		return agg, policyUnavailableError()
	}
	cur := cloneGuardrailEvalInput(input)
	cur.Hook = hook

	outcome := &PipelineOutcome{Result: agg}
	for _, rg := range resolved {
		res, cand, evalErr := p.executeGroup(ctx, rg, cloneGuardrailEvalInput(cur))
		if evalErr != nil {
			agg.Decision = domain.GuardrailDecisionBlock
			agg.ErrorMessage = evalErr.Error()
			return agg, wrapDriverUnavailableError(rg.Name, evalErr)
		}
		if p.auditHook != nil && res != nil {
			p.auditHook(ctx, hook, prc, res)
		}
		loggingOnly := isCandidateLoggingOnly(cand, res)
		if !loggingOnly && res != nil && hook == domain.GuardrailHookPreCall && strings.TrimSpace(res.RouteTarget) == "" &&
			cand != nil && cand.Definition != nil && strings.TrimSpace(cand.Definition.SensitiveRouteTarget) != "" &&
			res.Decision != domain.GuardrailDecisionAllow && res.Decision != domain.GuardrailDecisionBlock {
			res.RouteTarget = strings.TrimSpace(cand.Definition.SensitiveRouteTarget)
		}
		outcome.mergeDriverResult(rg.Name, res, loggingOnly)
		if loggingOnly || res == nil {
			continue
		}
		switch res.Decision {
		case domain.GuardrailDecisionBlock:
			agg.Decision = domain.GuardrailDecisionBlock
			agg.ErrorMessage = res.ErrorMessage
			return agg, newBlockedGatewayError(hook, rg.Name, res)
		case domain.GuardrailDecisionModify:
			agg.Decision = domain.GuardrailDecisionModify
			if len(res.ModifiedTexts) > 0 {
				cur.Texts = slices.Clone(res.ModifiedTexts)
				agg.ModifiedTexts = slices.Clone(res.ModifiedTexts)
			}
			if len(res.ModifiedMessages) > 0 {
				cur.StructuredMessages = cloneCanonicalMessages(res.ModifiedMessages)
				agg.ModifiedMessages = cloneCanonicalMessages(res.ModifiedMessages)
			}
			if res.ModifiedToolCalls != nil {
				cur.ToolCalls = cloneToolCalls(res.ModifiedToolCalls)
				agg.ModifiedToolCalls = cloneToolCalls(res.ModifiedToolCalls)
			}
		case domain.GuardrailDecisionFlag:
			if agg.Decision == domain.GuardrailDecisionAllow {
				agg.Decision = domain.GuardrailDecisionFlag
			}
		}
	}
	return agg, nil
}
