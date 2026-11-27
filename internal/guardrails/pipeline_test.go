package guardrails_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/guardrails"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

type stubDriver struct {
	name  string
	hooks []domain.GuardrailHook
	fn    func(ctx context.Context, input *domain.GuardrailEvalInput) (*domain.GuardrailEvalResult, error)
}

func (d *stubDriver) Name() string                           { return d.name }
func (d *stubDriver) SupportedHooks() []domain.GuardrailHook { return d.hooks }
func (d *stubDriver) Evaluate(ctx context.Context, input *domain.GuardrailEvalInput) (*domain.GuardrailEvalResult, error) {
	return d.fn(ctx, input)
}

func seedOrg(t *testing.T, repo storage.Repository, orgID string) {
	t.Helper()
	if err := repo.CreateOrganization(context.Background(), &domain.Organization{
		ID:   orgID,
		Name: orgID,
	}); err != nil {
		t.Fatalf("CreateOrganization: %v", err)
	}
}

func TestResolverEnabledHookAndPrecedenceOrdering(t *testing.T) {
	defs := []*domain.GuardrailDefinition{
		{
			ID:         "g-disabled",
			OrgID:      "org-1",
			Name:       "disabled-guard",
			Provider:   "stub",
			EventHooks: []domain.GuardrailHook{domain.GuardrailHookPreCall},
			Precedence: 1,
			Enabled:    false,
		},
		{
			ID:         "g-post-only",
			OrgID:      "org-1",
			Name:       "post-only",
			Provider:   "stub",
			EventHooks: []domain.GuardrailHook{domain.GuardrailHookPostCall},
			Precedence: 2,
			Enabled:    true,
		},
		{
			ID:         "g-zeta",
			OrgID:      "org-1",
			Name:       "zeta-tie",
			Provider:   "stub",
			EventHooks: []domain.GuardrailHook{domain.GuardrailHookPreCall},
			Precedence: 10,
			Enabled:    true,
		},
		{
			ID:         "g-alpha",
			OrgID:      "org-1",
			Name:       "alpha-tie",
			Provider:   "stub",
			EventHooks: []domain.GuardrailHook{domain.GuardrailHookPreCall},
			Precedence: 10,
			Enabled:    true,
		},
		{
			ID:         "g-shadow",
			OrgID:      "org-1",
			Name:       "shadow-audit",
			Provider:   "stub",
			EventHooks: []domain.GuardrailHook{domain.GuardrailHookLoggingOnly},
			Precedence: 5,
			Enabled:    true,
		},
	}

	gotPre := guardrails.Resolve(defs, guardrails.ResolveContext{
		OrgID: "org-1",
		Hook:  domain.GuardrailHookPreCall,
	})
	if len(gotPre) != 3 {
		t.Fatalf("gotPre len = %d, want 3 (%+v)", len(gotPre), gotPre)
	}
	wantNames := []string{"shadow-audit", "alpha-tie", "zeta-tie"}
	for i, want := range wantNames {
		if gotPre[i].Definition.Name != want {
			t.Fatalf("gotPre[%d].Definition.Name = %q, want %q", i, gotPre[i].Definition.Name, want)
		}
	}

	gotPost := guardrails.Resolve(defs, guardrails.ResolveContext{
		OrgID: "org-1",
		Hook:  domain.GuardrailHookPostCall,
	})
	if len(gotPost) != 2 || gotPost[0].Definition.Name != "post-only" || gotPost[1].Definition.Name != "shadow-audit" {
		t.Fatalf("unexpected gotPost: %+v", gotPost)
	}
}

func TestPipelinePreAndPostModifyAndLayer0Ordering(t *testing.T) {
	repo := storage.NewMemoryRepository()
	seedOrg(t, repo, "org-1")

	// Built-in org policy redacts PII emails before external drivers execute.
	if err := repo.SetGuardrailPolicy(context.Background(), &domain.GuardrailPolicy{
		OrgID:              "org-1",
		EnablePIIDetection: true,
		PIIAction:          domain.GuardrailActionRedact,
		Mode:               domain.GuardrailModeEnforce,
	}); err != nil {
		t.Fatalf("SetGuardrailPolicy: %v", err)
	}

	if err := repo.CreateGuardrailDefinition(context.Background(), &domain.GuardrailDefinition{
		ID:         "g-mod-pre",
		OrgID:      "org-1",
		Name:       "pre-rewriter",
		Provider:   "rewriter",
		EventHooks: []domain.GuardrailHook{domain.GuardrailHookPreCall},
		Precedence: 1,
		Enabled:    true,
	}); err != nil {
		t.Fatalf("CreateGuardrailDefinition pre: %v", err)
	}
	if err := repo.CreateGuardrailDefinition(context.Background(), &domain.GuardrailDefinition{
		ID:         "g-mod-post",
		OrgID:      "org-1",
		Name:       "post-rewriter",
		Provider:   "rewriter",
		EventHooks: []domain.GuardrailHook{domain.GuardrailHookPostCall},
		Precedence: 1,
		Enabled:    true,
	}); err != nil {
		t.Fatalf("CreateGuardrailDefinition post: %v", err)
	}

	pipeline := guardrails.NewPipeline(guardrails.NewEngine(repo), repo)
	var preSawRedactedPII bool
	pipeline.RegisterDriver("rewriter", func(_ context.Context, cfg guardrails.DriverConfig) (guardrails.Driver, error) {
		return &stubDriver{
			name:  "rewriter",
			hooks: cfg.Definition.EventHooks,
			fn: func(_ context.Context, input *domain.GuardrailEvalInput) (*domain.GuardrailEvalResult, error) {
				if input.Hook == domain.GuardrailHookPreCall {
					preSawRedactedPII = input.StructuredMessages[0].Content == "hello [REDACTED_EMAIL]"
					return &domain.GuardrailEvalResult{
						Decision: domain.GuardrailDecisionModify,
						ModifiedMessages: []domain.CanonicalMessage{
							{
								Role:    "user",
								Content: "rewritten pre",
								Parts:   []domain.ContentPart{{Type: "text", Text: "part-pre"}},
							},
						},
					}, nil
				}
				return &domain.GuardrailEvalResult{
					Decision: domain.GuardrailDecisionModify,
					ModifiedMessages: []domain.CanonicalMessage{
						{
							Role:    "assistant",
							Content: "rewritten post",
							Parts:   []domain.ContentPart{{Type: "text", Text: "part-post"}},
						},
					},
				}, nil
			},
		}, nil
	})

	prc := guardrails.PipelineRequestContext{RequestID: "req-1", OrgID: "org-1", Model: "gpt-4o"}
	req := &domain.CanonicalChatRequest{
		Model: "gpt-4o",
		Messages: []domain.CanonicalMessage{
			{Role: "user", Content: "hello alice@example.com"},
		},
	}
	preOut, err := pipeline.EvaluatePreCall(context.Background(), prc, req)
	if err != nil {
		t.Fatalf("EvaluatePreCall err = %v", err)
	}
	if !preSawRedactedPII {
		t.Fatal("expected built-in PII redaction to run before external driver")
	}
	if !preOut.Redacted || req.Messages[0].Content != "rewritten pre" ||
		len(req.Messages[0].Parts) != 1 || req.Messages[0].Parts[0].Text != "part-pre" {
		t.Fatalf("unexpected mutated req: %+v", req.Messages[0])
	}

	resp := &domain.CanonicalChatResponse{
		Model: "gpt-4o",
		Choices: []domain.CanonicalChoice{
			{
				Index: 0,
				Message: domain.CanonicalMessage{
					Role:    "assistant",
					Content: "contact bob@example.com",
				},
			},
		},
	}
	postOut, err := pipeline.EvaluatePostCall(context.Background(), prc, resp)
	if err != nil {
		t.Fatalf("EvaluatePostCall err = %v", err)
	}
	if !postOut.Redacted || resp.Choices[0].Message.Content != "rewritten post" ||
		len(resp.Choices[0].Message.Parts) != 1 || resp.Choices[0].Message.Parts[0].Text != "part-post" {
		t.Fatalf("unexpected mutated resp: %+v", resp.Choices[0].Message)
	}
}

func TestPipelineTimeoutFailClosedFailOpenAndLoggingOnly(t *testing.T) {
	repo := storage.NewMemoryRepository()
	seedOrg(t, repo, "org-timeout")

	// 1. Fail-closed timeout test: 20ms timeout on a 200ms driver.
	if err := repo.CreateGuardrailDefinition(context.Background(), &domain.GuardrailDefinition{
		ID:         "g-timeout",
		OrgID:      "org-timeout",
		Name:       "slow-guard",
		Provider:   "slow",
		EventHooks: []domain.GuardrailHook{domain.GuardrailHookPreCall},
		TimeoutMs:  20,
		FailOpen:   false,
		Enabled:    true,
	}); err != nil {
		t.Fatalf("CreateGuardrailDefinition slow: %v", err)
	}

	pipeline := guardrails.NewPipeline(nil, repo)
	pipeline.RegisterDriver("slow", func(_ context.Context, _ guardrails.DriverConfig) (guardrails.Driver, error) {
		return &stubDriver{
			name:  "slow",
			hooks: []domain.GuardrailHook{domain.GuardrailHookPreCall},
			fn: func(ctx context.Context, _ *domain.GuardrailEvalInput) (*domain.GuardrailEvalResult, error) {
				select {
				case <-ctx.Done():
					return nil, ctx.Err()
				case <-time.After(200 * time.Millisecond):
					return &domain.GuardrailEvalResult{Decision: domain.GuardrailDecisionAllow}, nil
				}
			},
		}, nil
	})

	prc := guardrails.PipelineRequestContext{RequestID: "req-to", OrgID: "org-timeout", Model: "gpt-4o"}
	req := &domain.CanonicalChatRequest{
		Model:    "gpt-4o",
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "hello"}},
	}
	started := time.Now()
	_, err := pipeline.EvaluatePreCall(context.Background(), prc, req)
	var gwErr *domain.GatewayError
	if !errors.As(err, &gwErr) || gwErr.StatusCode != 503 {
		t.Fatalf("expected 503 fail-closed timeout error, got %v", err)
	}
	if time.Since(started) > 150*time.Millisecond {
		t.Fatalf("timeout took too long: %v", time.Since(started))
	}

	// 2. Logging-only shadow guardrail must record violations via audit hook without blocking or mutating.
	repoShadow := storage.NewMemoryRepository()
	seedOrg(t, repoShadow, "org-shadow")
	if err := repoShadow.CreateGuardrailDefinition(context.Background(), &domain.GuardrailDefinition{
		ID:         "g-log-only",
		OrgID:      "org-shadow",
		Name:       "shadow-guard",
		Provider:   "shadow",
		EventHooks: []domain.GuardrailHook{domain.GuardrailHookLoggingOnly},
		Enabled:    true,
	}); err != nil {
		t.Fatalf("CreateGuardrailDefinition shadow: %v", err)
	}

	var mu sync.Mutex
	var auditedHook domain.GuardrailHook
	var auditedViolations int
	shadowPipe := guardrails.NewPipeline(nil, repoShadow, guardrails.WithAuditHook(func(_ context.Context, hook domain.GuardrailHook, _ guardrails.PipelineRequestContext, res *domain.GuardrailEvalResult) {
		mu.Lock()
		defer mu.Unlock()
		auditedHook = hook
		auditedViolations += len(res.Violations)
	}))
	shadowPipe.RegisterDriver("shadow", func(_ context.Context, _ guardrails.DriverConfig) (guardrails.Driver, error) {
		return &stubDriver{
			name:  "shadow",
			hooks: []domain.GuardrailHook{domain.GuardrailHookLoggingOnly},
			fn: func(_ context.Context, _ *domain.GuardrailEvalInput) (*domain.GuardrailEvalResult, error) {
				return &domain.GuardrailEvalResult{
					Decision: domain.GuardrailDecisionBlock,
					Violations: []domain.GuardrailViolation{{
						GuardrailName: "shadow-guard",
						Category:      "policy",
						Message:       "shadow finding",
					}},
				}, nil
			},
		}, nil
	})

	shadowReq := &domain.CanonicalChatRequest{
		Model:    "gpt-4o",
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "unchanged input"}},
	}
	out, err := shadowPipe.EvaluatePreCall(context.Background(), guardrails.PipelineRequestContext{
		RequestID: "req-shadow",
		OrgID:     "org-shadow",
		Model:     "gpt-4o",
	}, shadowReq)
	if err != nil {
		t.Fatalf("logging_only guardrail must not block, got %v", err)
	}
	if shadowReq.Messages[0].Content != "unchanged input" || out.Redacted {
		t.Fatalf("logging_only guardrail must not mutate content: content=%q out=%+v", shadowReq.Messages[0].Content, out)
	}
	mu.Lock()
	defer mu.Unlock()
	if auditedHook != domain.GuardrailHookPreCall || auditedViolations != 1 {
		t.Fatalf("expected audit hook on pre_call shadow with 1 violation, got hook=%q count=%d", auditedHook, auditedViolations)
	}
}
