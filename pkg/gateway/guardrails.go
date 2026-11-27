package gateway

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/guardrails"
	"github.com/goroute-ai/ai-gateway-go/internal/server"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

// GuardrailDecision identifies the outcome returned by a custom SDK GuardrailScanner.
type GuardrailDecision string

// Custom SDK guardrail evaluation decisions.
const (
	GuardrailDecisionAllow  GuardrailDecision = "allow"
	GuardrailDecisionBlock  GuardrailDecision = "block"
	GuardrailDecisionFlag   GuardrailDecision = "flag"
	GuardrailDecisionModify GuardrailDecision = "modify"
)

// GuardrailHook identifies the gateway lifecycle stage at which a guardrail scanner runs.
type GuardrailHook string

// Supported custom SDK guardrail lifecycle hooks.
const (
	GuardrailHookPreCall     GuardrailHook = "pre_call"
	GuardrailHookPostCall    GuardrailHook = "post_call"
	GuardrailHookLoggingOnly GuardrailHook = "logging_only"
)

// GuardrailScanRequest carries the structured request or response envelope passed to a GuardrailScanner.
type GuardrailScanRequest struct {
	Direction    string         `json:"direction"`
	Hook         GuardrailHook  `json:"hook,omitempty"`
	RequestID    string         `json:"request_id,omitempty"`
	TraceID      string         `json:"trace_id,omitempty"`
	OrgID        string         `json:"org_id,omitempty"`
	TeamID       string         `json:"team_id,omitempty"`
	VirtualKeyID string         `json:"virtual_key_id,omitempty"`
	EndUserID    string         `json:"end_user_id,omitempty"`
	Model        string         `json:"model,omitempty"`
	Texts        []string       `json:"texts,omitempty"`
	Metadata     map[string]any `json:"metadata,omitempty"`
}

// GuardrailScanResult carries the decision and optional mutations returned by a GuardrailScanner.
type GuardrailScanResult struct {
	Decision      GuardrailDecision `json:"decision"`
	ModifiedTexts []string          `json:"modified_texts,omitempty"`
	Violations    []string          `json:"violations,omitempty"`
	Reason        string            `json:"reason,omitempty"`
}

// GuardrailScanner evaluates requests or responses in-process inside an embedded GoRoute gateway.
type GuardrailScanner interface {
	Scan(ctx context.Context, req GuardrailScanRequest) (GuardrailScanResult, error)
}

// GuardrailScannerFunc adapts a Go function into a GuardrailScanner.
type GuardrailScannerFunc func(ctx context.Context, req GuardrailScanRequest) (GuardrailScanResult, error)

// Scan invokes f(ctx, req).
func (f GuardrailScannerFunc) Scan(ctx context.Context, req GuardrailScanRequest) (GuardrailScanResult, error) {
	return f(ctx, req)
}

type sdkGuardrailConfig struct {
	timeout    time.Duration
	failOpen   bool
	hooks      []GuardrailHook
	precedence int
}

// GuardrailOption customizes how an SDK-registered GuardrailScanner executes in the pipeline.
type GuardrailOption func(*sdkGuardrailConfig)

// WithGuardrailTimeout sets the per-invocation execution deadline for the guardrail scanner.
func WithGuardrailTimeout(d time.Duration) GuardrailOption {
	return func(c *sdkGuardrailConfig) {
		if d > 0 {
			c.timeout = d
		}
	}
}

// WithGuardrailFailOpen controls whether errors or timeouts from this scanner allow the request
// (true) or fail closed with HTTP 503 (false, default).
func WithGuardrailFailOpen(failOpen bool) GuardrailOption {
	return func(c *sdkGuardrailConfig) {
		c.failOpen = failOpen
	}
}

// WithGuardrailHooks specifies which pipeline lifecycle hooks invoke this scanner.
// By default, SDK scanners run on pre_call and post_call.
func WithGuardrailHooks(hooks ...GuardrailHook) GuardrailOption {
	return func(c *sdkGuardrailConfig) {
		if len(hooks) > 0 {
			c.hooks = append([]GuardrailHook(nil), hooks...)
		}
	}
}

// WithGuardrailPrecedence sets the execution order precedence (lower values run earlier).
func WithGuardrailPrecedence(precedence int) GuardrailOption {
	return func(c *sdkGuardrailConfig) {
		c.precedence = precedence
	}
}

type guardrailScannerEntry struct {
	name    string
	scanner GuardrailScanner
	opts    []GuardrailOption
}

type sdkGuardrailDriver struct {
	name    string
	defID   string
	scanner GuardrailScanner
	hooks   []domain.GuardrailHook
	timeout time.Duration
}

func (d *sdkGuardrailDriver) Name() string {
	return d.name
}

func (d *sdkGuardrailDriver) SupportedHooks() []domain.GuardrailHook {
	return slices.Clone(d.hooks)
}

func (d *sdkGuardrailDriver) Evaluate(ctx context.Context, input *domain.GuardrailEvalInput) (*domain.GuardrailEvalResult, error) {
	if d.timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, d.timeout)
		defer cancel()
	}

	req := toSDKGuardrailRequest(input)
	res, err := d.scanner.Scan(ctx, req)
	if err != nil {
		return nil, err
	}
	return fromSDKGuardrailResult(d.name, d.defID, res)
}

func registerSDKGuardrailScanner(
	ctx context.Context,
	gw *server.GatewayServer,
	repo storage.Repository,
	orgID string,
	idx int,
	entry guardrailScannerEntry,
) error {
	cleanName := strings.TrimSpace(entry.name)
	if cleanName == "" {
		return fmt.Errorf("guardrail scanner name must not be empty")
	}
	if entry.scanner == nil {
		return fmt.Errorf("guardrail scanner %q must not be nil", cleanName)
	}

	gcfg := sdkGuardrailConfig{
		hooks: []GuardrailHook{GuardrailHookPreCall, GuardrailHookPostCall},
	}
	for _, opt := range entry.opts {
		if opt != nil {
			opt(&gcfg)
		}
	}

	domHooks := make([]domain.GuardrailHook, 0, len(gcfg.hooks))
	for _, h := range gcfg.hooks {
		dh := domain.GuardrailHook(h)
		if !dh.IsValid() {
			return fmt.Errorf("guardrail scanner %q has invalid hook %q", cleanName, h)
		}
		if !slices.Contains(domHooks, dh) {
			domHooks = append(domHooks, dh)
		}
	}

	timeoutMs := 0
	if gcfg.timeout > 0 {
		timeoutMs = int(gcfg.timeout.Milliseconds())
		if timeoutMs <= 0 {
			timeoutMs = 1
		}
	}

	slug := strings.ToLower(strings.ReplaceAll(cleanName, " ", "-"))
	provider := fmt.Sprintf("sdk:%s:%d", slug, idx)
	defID := fmt.Sprintf("sdk-guard-%d-%s", idx, slug)

	pipeline := gw.GuardrailPipeline()
	if pipeline == nil {
		return fmt.Errorf("gateway guardrail pipeline is unavailable")
	}
	pipeline.RegisterDriver(provider, func(_ context.Context, _ guardrails.DriverConfig) (guardrails.Driver, error) {
		return &sdkGuardrailDriver{
			name:    cleanName,
			defID:   defID,
			scanner: entry.scanner,
			hooks:   domHooks,
			timeout: gcfg.timeout,
		}, nil
	})

	def := &domain.GuardrailDefinition{
		ID:         defID,
		OrgID:      orgID,
		Name:       cleanName,
		Provider:   provider,
		EventHooks: domHooks,
		Enabled:    true,
		TimeoutMs:  timeoutMs,
		FailOpen:   gcfg.failOpen,
		Precedence: gcfg.precedence,
	}
	if _, err := repo.GetGuardrailDefinition(ctx, defID); err == nil {
		return repo.UpdateGuardrailDefinition(ctx, def)
	}
	return repo.CreateGuardrailDefinition(ctx, def)
}

func toSDKGuardrailRequest(input *domain.GuardrailEvalInput) GuardrailScanRequest {
	if input == nil {
		return GuardrailScanRequest{}
	}
	req := GuardrailScanRequest{
		Direction:    input.Direction,
		Hook:         GuardrailHook(input.Hook),
		RequestID:    input.RequestID,
		TraceID:      input.TraceID,
		OrgID:        input.OrgID,
		TeamID:       input.TeamID,
		VirtualKeyID: input.VirtualKeyID,
		EndUserID:    input.EndUserID,
		Model:        input.Model,
		Texts:        slices.Clone(input.Texts),
	}
	if len(input.Metadata) > 0 {
		req.Metadata = maps.Clone(input.Metadata)
	}
	return req
}

func fromSDKGuardrailResult(name, defID string, res GuardrailScanResult) (*domain.GuardrailEvalResult, error) {
	var decision domain.GuardrailDecision
	switch strings.ToLower(strings.TrimSpace(string(res.Decision))) {
	case "", string(GuardrailDecisionAllow):
		decision = domain.GuardrailDecisionAllow
	case string(GuardrailDecisionBlock):
		decision = domain.GuardrailDecisionBlock
	case string(GuardrailDecisionFlag):
		decision = domain.GuardrailDecisionFlag
	case string(GuardrailDecisionModify):
		decision = domain.GuardrailDecisionModify
	default:
		return nil, fmt.Errorf("sdk guardrail scanner %q returned invalid decision %q", name, res.Decision)
	}

	out := &domain.GuardrailEvalResult{
		Decision:          decision,
		ModifiedTexts:     slices.Clone(res.ModifiedTexts),
		AppliedGuardrails: []string{name},
		ErrorMessage:      res.Reason,
	}
	for _, label := range res.Violations {
		if label == "" {
			continue
		}
		out.Violations = append(out.Violations, domain.GuardrailViolation{
			GuardrailName: name,
			GuardrailID:   defID,
			Provider:      "sdk",
			Rule:          label,
			Message:       label,
			Decision:      decision,
		})
	}
	if len(out.Violations) == 0 && res.Reason != "" && (decision == domain.GuardrailDecisionBlock || decision == domain.GuardrailDecisionFlag) {
		out.Violations = append(out.Violations, domain.GuardrailViolation{
			GuardrailName: name,
			GuardrailID:   defID,
			Provider:      "sdk",
			Message:       res.Reason,
			Decision:      decision,
		})
	}
	return out, nil
}
