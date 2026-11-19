package guardrails_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/guardrails"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
	"github.com/sony/gobreaker/v2"
)

type stubDriver struct {
	name  string
	hooks []domain.GuardrailHook
	fn    func(ctx context.Context, input *domain.GuardrailEvalInput) (*domain.GuardrailEvalResult, error)
}

func (d *stubDriver) Name() string { return d.name }
func (d *stubDriver) SupportedHooks() []domain.GuardrailHook {
	return d.hooks
}
func (d *stubDriver) Evaluate(ctx context.Context, input *domain.GuardrailEvalInput) (*domain.GuardrailEvalResult, error) {
	return d.fn(ctx, input)
}

func boolPtr(v bool) *bool { return &v }

func seedOrg(t *testing.T, repo storage.Repository, orgID string) {
	t.Helper()
	if err := repo.CreateOrganization(context.Background(), &domain.Organization{
		ID:   orgID,
		Name: orgID,
	}); err != nil {
		t.Fatalf("CreateOrganization: %v", err)
	}
}

func TestResolverPrecedenceStatusRolesScopeAndModeRule(t *testing.T) {
	eff := &storage.EffectiveGuardrails{
		Definitions: []*domain.GuardrailDefinition{
			{
				ID:         "g-pending",
				OrgID:      "org-1",
				Name:       "pending-guard",
				Provider:   "stub",
				EventHooks: []domain.GuardrailHook{domain.GuardrailHookPreCall},
				DefaultOn:  true,
				Precedence: 1,
				Status:     domain.GuardrailStatusPendingReview,
			},
			{
				ID:           "g-admin-only",
				OrgID:        "org-1",
				Name:         "admin-only",
				Provider:     "stub",
				EventHooks:   []domain.GuardrailHook{domain.GuardrailHookPreCall},
				DefaultOn:    true,
				EnabledRoles: []string{"org_admin"},
				Precedence:   2,
				Status:       domain.GuardrailStatusActive,
			},
			{
				ID:          "g-stream-only",
				OrgID:       "org-1",
				Name:        "stream-only",
				Provider:    "stub",
				EventHooks:  []domain.GuardrailHook{domain.GuardrailHookPostCall},
				StreamScope: domain.StreamScopeStreaming,
				DefaultOn:   true,
				Precedence:  3,
				Status:      domain.GuardrailStatusActive,
			},
			{
				ID:         "g-mode-rule",
				OrgID:      "org-1",
				Name:       "mode-rule",
				Provider:   "stub",
				DefaultOn:  true,
				Precedence: 20,
				StreamScopeByHook: domain.StreamScopeByHook{
					domain.GuardrailHookPreCall:     domain.StreamScopeNonStreaming,
					domain.GuardrailHookLoggingOnly: domain.StreamScopeBoth,
				},
				ModeRule: &domain.GuardrailModeRule{
					Tags: map[string][]domain.GuardrailHook{
						"shadow": {domain.GuardrailHookLoggingOnly},
					},
					Default: []domain.GuardrailHook{domain.GuardrailHookPreCall},
				},
				Status: domain.GuardrailStatusActive,
			},
			{
				ID:         "g-beta",
				OrgID:      "org-1",
				Name:       "alpha-tie",
				Provider:   "stub",
				EventHooks: []domain.GuardrailHook{domain.GuardrailHookPreCall},
				DefaultOn:  true,
				Precedence: 10,
				Status:     domain.GuardrailStatusActive,
			},
			{
				ID:         "g-alpha",
				OrgID:      "org-1",
				Name:       "zeta-tie",
				Provider:   "stub",
				EventHooks: []domain.GuardrailHook{domain.GuardrailHookPreCall},
				DefaultOn:  true,
				Precedence: 10,
				Status:     domain.GuardrailStatusActive,
			},
		},
	}

	// Non-streaming, caller role "developer", no tags:
	// - g-pending excluded (pending_review)
	// - g-admin-only excluded (EnabledRoles mismatch)
	// - g-mode-rule uses Default (pre_call) and StreamScopeByHook[pre_call] = non_streaming -> included
	// - tie at Precedence=10 ordered alpha-tie before zeta-tie
	gotPre := guardrails.Resolve(eff, guardrails.ResolveContext{
		OrgID:       "org-1",
		CallerRoles: []string{"developer"},
		Hook:        domain.GuardrailHookPreCall,
		IsStreaming: false,
	})
	if len(gotPre) != 3 {
		t.Fatalf("gotPre len = %d, want 3 (%+v)", len(gotPre), gotPre)
	}
	wantNames := []string{"alpha-tie", "zeta-tie", "mode-rule"}
	for i, want := range wantNames {
		if gotPre[i].Name != want {
			t.Fatalf("gotPre[%d].Name = %q, want %q", i, gotPre[i].Name, want)
		}
	}

	// Streaming disables mode-rule on pre_call (StreamScopeByHook=non_streaming),
	// while admin role activates admin-only.
	gotPreStreamAdmin := guardrails.Resolve(eff, guardrails.ResolveContext{
		OrgID:       "org-1",
		CallerRoles: []string{"ORG_ADMIN"},
		Hook:        domain.GuardrailHookPreCall,
		IsStreaming: true,
	})
	if len(gotPreStreamAdmin) != 3 || gotPreStreamAdmin[0].Name != "admin-only" {
		t.Fatalf("unexpected gotPreStreamAdmin: %+v", gotPreStreamAdmin)
	}

	// PostCall streaming includes stream-only; non-streaming excludes it.
	if got := guardrails.Resolve(eff, guardrails.ResolveContext{
		OrgID:       "org-1",
		Hook:        domain.GuardrailHookPostCall,
		IsStreaming: false,
	}); len(got) != 0 {
		t.Fatalf("expected 0 non-streaming post_call guardrails, got %d", len(got))
	}
	if got := guardrails.Resolve(eff, guardrails.ResolveContext{
		OrgID:       "org-1",
		Hook:        domain.GuardrailHookPostCall,
		IsStreaming: true,
	}); len(got) != 1 || got[0].Name != "stream-only" {
		t.Fatalf("expected stream-only on streaming post_call, got %+v", got)
	}

	// Tag "shadow" routes mode-rule dynamically to logging_only instead of pre_call.
	if got := guardrails.Resolve(eff, guardrails.ResolveContext{
		OrgID:       "org-1",
		Tags:        []string{"shadow"},
		Hook:        domain.GuardrailHookPreCall,
		IsStreaming: false,
	}); len(got) != 2 {
		t.Fatalf("expected mode-rule omitted from pre_call when shadow tag set, got %+v", got)
	}
	if got := guardrails.Resolve(eff, guardrails.ResolveContext{
		OrgID:       "org-1",
		Tags:        []string{"shadow"},
		Hook:        domain.GuardrailHookLoggingOnly,
		IsStreaming: true,
	}); len(got) != 1 || got[0].Name != "mode-rule" {
		t.Fatalf("expected mode-rule on logging_only when shadow tag set, got %+v", got)
	}
}

func TestResolverHierarchicalBindingsParamMergeAndAntiBypass(t *testing.T) {
	eff := &storage.EffectiveGuardrails{
		Definitions: []*domain.GuardrailDefinition{
			{
				ID:         "g-locked",
				OrgID:      "org-1",
				Name:       "locked-pii",
				Provider:   "stub",
				EventHooks: []domain.GuardrailHook{domain.GuardrailHookPreCall},
				DefaultOn:  false,
				Precedence: 1,
				Config: map[string]any{
					"action":    "redact",
					"threshold": 0.5,
				},
				Status: domain.GuardrailStatusActive,
			},
			{
				ID:         "g-default-on",
				OrgID:      "org-1",
				Name:       "default-safety",
				Provider:   "stub",
				EventHooks: []domain.GuardrailHook{domain.GuardrailHookPreCall},
				DefaultOn:  true,
				Precedence: 2,
				Config: map[string]any{
					"action": "redact",
				},
				Status: domain.GuardrailStatusActive,
			},
			{
				ID:         "g-opt-in",
				OrgID:      "org-1",
				Name:       "optional-topic",
				Provider:   "stub",
				EventHooks: []domain.GuardrailHook{domain.GuardrailHookPreCall},
				DefaultOn:  false,
				Precedence: 3,
				Config: map[string]any{
					"action": "block",
					"strict": false,
				},
				Status: domain.GuardrailStatusActive,
			},
		},
		Bindings: []*domain.GuardrailBinding{
			// Team-wide binding locks g-locked with threshold 0.6.
			{
				ID:            "b-team",
				OrgID:         "org-1",
				GuardrailID:   "g-locked",
				GuardrailName: "locked-pii",
				TeamID:        "team-1",
				IsLocked:      true,
				ParamOverrides: map[string]any{
					"threshold": 0.6,
				},
			},
			// More specific virtual-key + model_group binding tightens action to block and threshold to 0.85.
			{
				ID:            "b-vk-mg",
				OrgID:         "org-1",
				GuardrailID:   "g-locked",
				GuardrailName: "locked-pii",
				TeamID:        "team-1",
				VirtualKeyID:  "vk-1",
				ModelGroupID:  "mg-prod",
				ParamOverrides: map[string]any{
					"action":    "block",
					"threshold": 0.85,
				},
			},
			// Non-matching end-user binding must be ignored.
			{
				ID:            "b-other-user",
				OrgID:         "org-1",
				GuardrailID:   "g-locked",
				GuardrailName: "locked-pii",
				EndUserID:     "user-other",
				ParamOverrides: map[string]any{
					"threshold": 0.1,
				},
			},
		},
	}

	// Attempt to bypass locked-pii (disable + downgrade action to audit)
	// Attempt to bypass default-safety (disable + downgrade action to audit)
	// Opt in optional-topic and override strict=true
	got := guardrails.Resolve(eff, guardrails.ResolveContext{
		OrgID:        "org-1",
		TeamID:       "team-1",
		VirtualKeyID: "vk-1",
		EndUserID:    "user-1",
		ModelGroupID: "mg-prod",
		Hook:         domain.GuardrailHookPreCall,
		RequestOverrides: []domain.GuardrailRequestOverride{
			{
				Name:    "locked-pii",
				Enabled: boolPtr(false),
				Action:  domain.GuardrailActionAudit,
				Config:  map[string]any{"threshold": 0.01},
			},
			{
				Name:    "default-safety",
				Enabled: boolPtr(false),
				Action:  domain.GuardrailActionAudit,
			},
			{
				Name:    "optional-topic",
				Enabled: boolPtr(true),
				Action:  domain.GuardrailActionRedact,
				Config:  map[string]any{"strict": true},
			},
		},
	})

	if len(got) != 3 {
		t.Fatalf("got %d guardrails, want 3: %+v", len(got), got)
	}

	// locked-pii: cannot be disabled or downgraded from block -> audit, nor have params weakened when locked.
	if got[0].Name != "locked-pii" || !got[0].IsLocked {
		t.Fatalf("unexpected locked-pii resolution: %+v", got[0])
	}
	if got[0].EffectiveAction != domain.GuardrailActionBlock {
		t.Fatalf("locked-pii action = %q, want block (must not downgrade)", got[0].EffectiveAction)
	}
	if thresh, ok := got[0].EffectiveConfig["threshold"].(float64); !ok || thresh != 0.85 {
		t.Fatalf("locked-pii threshold = %v, want 0.85 from most-specific binding", got[0].EffectiveConfig["threshold"])
	}

	// default-safety: cannot be disabled or downgraded from redact -> audit.
	if got[1].Name != "default-safety" || got[1].EffectiveAction != domain.GuardrailActionRedact {
		t.Fatalf("default-safety was bypassed: %+v", got[1])
	}

	// optional-topic: enabled by request and customized to redact / strict=true.
	if got[2].Name != "optional-topic" || got[2].EffectiveAction != domain.GuardrailActionRedact {
		t.Fatalf("optional-topic override failed: %+v", got[2])
	}
	if got[2].EffectiveConfig["strict"] != true {
		t.Fatalf("optional-topic strict = %v, want true", got[2].EffectiveConfig["strict"])
	}

	// Request upgrading default-safety redact -> block IS permitted.
	upgraded := guardrails.Resolve(eff, guardrails.ResolveContext{
		OrgID: "org-1",
		Hook:  domain.GuardrailHookPreCall,
		RequestOverrides: []domain.GuardrailRequestOverride{
			{Name: "default-safety", Action: domain.GuardrailActionBlock},
		},
	})
	if len(upgraded) != 1 || upgraded[0].EffectiveAction != domain.GuardrailActionBlock {
		t.Fatalf("expected upgrade redact->block to succeed, got %+v", upgraded)
	}
}

func TestRouterLBWeightedShuffleAndGobreakerFailoverCooldown(t *testing.T) {
	var stateMu sync.Mutex
	var transitions []string
	lb := guardrails.NewRouterLB(guardrails.LBConfig{
		FailureThreshold:    2,
		Cooldown:            60 * time.Millisecond,
		HalfOpenMaxRequests: 1,
		OnStateChange: func(name string, from, to gobreaker.State) {
			stateMu.Lock()
			transitions = append(transitions, name+":"+from.String()+"->"+to.String())
			stateMu.Unlock()
		},
	})

	heavy := &guardrails.ResolvedCandidate{
		Definition: &domain.GuardrailDefinition{ID: "heavy", Name: "shared", Weight: 9},
		Weight:     9,
	}
	light := &guardrails.ResolvedCandidate{
		Definition: &domain.GuardrailDefinition{ID: "light", Name: "shared", Weight: 1},
		Weight:     1,
	}

	heavyFirst := 0
	for range 200 {
		ordered := lb.WeightedShuffle([]*guardrails.ResolvedCandidate{heavy, light})
		if ordered[0].Definition.ID == "heavy" {
			heavyFirst++
		}
	}
	if heavyFirst < 140 {
		t.Fatalf("expected heavy (w=9) to lead >=140/200 times, got %d", heavyFirst)
	}

	// Failover + cooldown test: c1 fails twice, trips to open, c2 handles subsequent calls.
	c1 := &guardrails.ResolvedCandidate{
		Definition: &domain.GuardrailDefinition{ID: "inst-1", Name: "shared", Weight: 1},
		Weight:     1,
	}
	c2 := &guardrails.ResolvedCandidate{
		Definition: &domain.GuardrailDefinition{ID: "inst-2", Name: "shared", Weight: 1},
		Weight:     1,
	}

	// Force deterministic c1-first ordering (largest u => smallest -ln(u)/w) for test stability.
	detIdx := 0
	detVals := []float64{0.99, 0.01}
	detLB := guardrails.NewRouterLB(guardrails.LBConfig{
		FailureThreshold:    2,
		Cooldown:            60 * time.Millisecond,
		HalfOpenMaxRequests: 1,
		RandFloat64: func() float64 {
			v := detVals[detIdx%len(detVals)]
			detIdx++
			return v
		},
		OnStateChange: func(name string, from, to gobreaker.State) {
			stateMu.Lock()
			transitions = append(transitions, name+":"+from.String()+"->"+to.String())
			stateMu.Unlock()
		},
	})

	var c1Calls, c2Calls atomic.Int32
	c1ShouldFail := atomic.Bool{}
	c1ShouldFail.Store(true)

	evalFn := func(_ context.Context, cand *guardrails.ResolvedCandidate) (*domain.GuardrailEvalResult, error) {
		if cand.Definition.ID == "inst-1" {
			c1Calls.Add(1)
			if c1ShouldFail.Load() {
				return nil, errors.New("upstream guardrail 503")
			}
			return &domain.GuardrailEvalResult{Decision: domain.GuardrailDecisionAllow}, nil
		}
		c2Calls.Add(1)
		return &domain.GuardrailEvalResult{Decision: domain.GuardrailDecisionAllow}, nil
	}

	group := guardrails.ResolvedGuardrail{
		Name:       "shared",
		Candidates: []*guardrails.ResolvedCandidate{c1, c2},
	}

	// Calls 1 & 2: c1 fails -> immediately fails over to c2 within same Execute call!
	for i := range 2 {
		res, chosen, err := detLB.Execute(context.Background(), group, evalFn)
		if err != nil || res == nil || chosen.Definition.ID != "inst-2" {
			t.Fatalf("call %d expected failover to inst-2, got res=%v chosen=%v err=%v", i+1, res, chosen, err)
		}
	}
	if detLB.State("inst-1") != gobreaker.StateOpen {
		t.Fatalf("expected inst-1 breaker open after 2 failures, got %s", detLB.State("inst-1"))
	}

	// Call 3: c1 breaker is open -> inst-1 is skipped completely (c1Calls stays 2).
	_, chosen, err := detLB.Execute(context.Background(), group, evalFn)
	if err != nil || chosen.Definition.ID != "inst-2" || c1Calls.Load() != 2 {
		t.Fatalf("call 3 expected inst-1 skipped and inst-2 selected, c1Calls=%d err=%v", c1Calls.Load(), err)
	}

	// Wait for cooldown and verify half-open recovery when c1 becomes healthy.
	time.Sleep(80 * time.Millisecond)
	c1ShouldFail.Store(false)
	res, chosen, err := detLB.Execute(context.Background(), group, evalFn)
	if err != nil || res.Decision != domain.GuardrailDecisionAllow || chosen.Definition.ID != "inst-1" {
		t.Fatalf("expected inst-1 recovery after cooldown, got chosen=%v err=%v", chosen, err)
	}
	if detLB.State("inst-1") != gobreaker.StateClosed {
		t.Fatalf("expected inst-1 breaker closed after half-open success, got %s", detLB.State("inst-1"))
	}

	// Parent context cancellation must NOT trip circuit breaker.
	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	for range 3 {
		_, _, err := detLB.Execute(canceledCtx, guardrails.ResolvedGuardrail{
			Name:       "shared",
			Candidates: []*guardrails.ResolvedCandidate{c1},
		}, func(ctx context.Context, _ *guardrails.ResolvedCandidate) (*domain.GuardrailEvalResult, error) {
			return nil, ctx.Err()
		})
		if err == nil {
			t.Fatal("expected error on canceled ctx")
		}
	}
	if detLB.State("inst-1") != gobreaker.StateClosed {
		t.Fatalf("parent cancellation should not trip breaker, got %s", detLB.State("inst-1"))
	}
}

func TestRouterLBFailOpenWhenAllInstancesFail(t *testing.T) {
	lb := guardrails.NewRouterLB(guardrails.LBConfig{FailureThreshold: 1, Cooldown: time.Minute})
	candFailOpen := &guardrails.ResolvedCandidate{
		Definition: &domain.GuardrailDefinition{ID: "fo-1", Name: "fo"},
		FailOpen:   true,
	}
	res, _, err := lb.Execute(context.Background(), guardrails.ResolvedGuardrail{
		Name:       "fo",
		FailOpen:   true,
		Candidates: []*guardrails.ResolvedCandidate{candFailOpen},
	}, func(_ context.Context, _ *guardrails.ResolvedCandidate) (*domain.GuardrailEvalResult, error) {
		return nil, errors.New("boom")
	})
	if err != nil || res == nil || res.Decision != domain.GuardrailDecisionAllow {
		t.Fatalf("expected fail-open allow, got res=%+v err=%v", res, err)
	}

	candFailClosed := &guardrails.ResolvedCandidate{
		Definition: &domain.GuardrailDefinition{ID: "fc-1", Name: "fc"},
		FailOpen:   false,
	}
	_, _, err = lb.Execute(context.Background(), guardrails.ResolvedGuardrail{
		Name:       "fc",
		FailOpen:   false,
		Candidates: []*guardrails.ResolvedCandidate{candFailClosed},
	}, func(_ context.Context, _ *guardrails.ResolvedCandidate) (*domain.GuardrailEvalResult, error) {
		return nil, errors.New("boom")
	})
	if err == nil {
		t.Fatal("expected fail-closed error when all candidates fail")
	}
}

func TestPipelinePreAndPostModifyAndLayer0Ordering(t *testing.T) {
	repo := storage.NewMemoryRepository()
	seedOrg(t, repo, "org-1")

	// Layer 0 legacy policy redacts PII emails.
	if err := repo.SetGuardrailPolicy(context.Background(), &domain.GuardrailPolicy{
		OrgID:              "org-1",
		EnablePIIDetection: true,
		PIIAction:          domain.GuardrailActionRedact,
		Mode:               domain.GuardrailModeEnforce,
	}); err != nil {
		t.Fatalf("SetGuardrailPolicy: %v", err)
	}

	// Layer 1 pre_call and post_call modify drivers mutate content, parts, and tool_calls.
	if err := repo.CreateGuardrailDefinition(context.Background(), &domain.GuardrailDefinition{
		ID:         "g-mod-pre",
		OrgID:      "org-1",
		Name:       "pre-rewriter",
		Provider:   "rewriter",
		EventHooks: []domain.GuardrailHook{domain.GuardrailHookPreCall},
		DefaultOn:  true,
		Precedence: 1,
		Status:     domain.GuardrailStatusActive,
	}); err != nil {
		t.Fatalf("CreateGuardrailDefinition pre: %v", err)
	}
	if err := repo.CreateGuardrailDefinition(context.Background(), &domain.GuardrailDefinition{
		ID:         "g-mod-post",
		OrgID:      "org-1",
		Name:       "post-rewriter",
		Provider:   "rewriter",
		EventHooks: []domain.GuardrailHook{domain.GuardrailHookPostCall},
		DefaultOn:  true,
		Precedence: 1,
		Status:     domain.GuardrailStatusActive,
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
								ToolCalls: []domain.CanonicalToolCall{
									{ID: "tc-1", Type: "function", Function: domain.CanonicalFunctionCall{Name: "safe_fn", Arguments: `{"x":1}`}},
								},
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
					ModifiedToolCalls: []domain.CanonicalToolCall{
						{ID: "tc-out", Type: "function", Function: domain.CanonicalFunctionCall{Name: "sanitized_tool", Arguments: `{"ok":true}`}},
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
		t.Fatal("expected Layer 0 PII redaction to run before Layer 1 driver")
	}
	if !preOut.Redacted || req.Messages[0].Content != "rewritten pre" ||
		len(req.Messages[0].Parts) != 1 || req.Messages[0].Parts[0].Text != "part-pre" ||
		len(req.Messages[0].ToolCalls) != 1 || req.Messages[0].ToolCalls[0].Function.Name != "safe_fn" {
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
					ToolCalls: []domain.CanonicalToolCall{
						{ID: "tc-out", Type: "function", Function: domain.CanonicalFunctionCall{Name: "raw_tool", Arguments: `{"raw":true}`}},
					},
				},
			},
		},
	}
	postOut, err := pipeline.EvaluatePostCall(context.Background(), prc, resp)
	if err != nil {
		t.Fatalf("EvaluatePostCall err = %v", err)
	}
	if !postOut.Redacted || resp.Choices[0].Message.Content != "rewritten post" ||
		len(resp.Choices[0].Message.Parts) != 1 || resp.Choices[0].Message.Parts[0].Text != "part-post" ||
		len(resp.Choices[0].Message.ToolCalls) != 1 || resp.Choices[0].Message.ToolCalls[0].Function.Name != "sanitized_tool" {
		t.Fatalf("unexpected mutated resp: %+v", resp.Choices[0].Message)
	}
}

func TestPipelineDuringCallParallelEarlyCancelAndTimeout(t *testing.T) {
	repo := storage.NewMemoryRepository()
	seedOrg(t, repo, "org-during")

	if err := repo.CreateGuardrailDefinition(context.Background(), &domain.GuardrailDefinition{
		ID:         "g-during-block",
		OrgID:      "org-during",
		Name:       "during-blocker",
		Provider:   "blocker",
		EventHooks: []domain.GuardrailHook{domain.GuardrailHookDuringCall},
		DefaultOn:  true,
		TimeoutMs:  200,
		Status:     domain.GuardrailStatusActive,
	}); err != nil {
		t.Fatalf("CreateGuardrailDefinition: %v", err)
	}

	pipeline := guardrails.NewPipeline(nil, repo)
	pipeline.RegisterDriver("blocker", func(_ context.Context, _ guardrails.DriverConfig) (guardrails.Driver, error) {
		return &stubDriver{
			name:  "blocker",
			hooks: []domain.GuardrailHook{domain.GuardrailHookDuringCall},
			fn: func(_ context.Context, input *domain.GuardrailEvalInput) (*domain.GuardrailEvalResult, error) {
				if len(input.Texts) > 0 && input.Texts[0] == "block-me" {
					time.Sleep(15 * time.Millisecond)
					return &domain.GuardrailEvalResult{
						Decision: domain.GuardrailDecisionBlock,
						Violations: []domain.GuardrailViolation{{
							GuardrailName: "during-blocker",
							Category:      "policy",
							Message:       "blocked in parallel",
						}},
					}, nil
				}
				return &domain.GuardrailEvalResult{Decision: domain.GuardrailDecisionAllow}, nil
			},
		}, nil
	})

	prc := guardrails.PipelineRequestContext{RequestID: "req-d", OrgID: "org-during", Model: "gpt-4o"}
	req := &domain.CanonicalChatRequest{
		Model:    "gpt-4o",
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "block-me"}},
	}

	started := time.Now()
	upstreamCtx, handle, err := pipeline.StartDuringCall(context.Background(), prc, req)
	if err != nil {
		t.Fatalf("StartDuringCall: %v", err)
	}
	defer handle.Close()

	// Simulate a slow upstream waiting on upstreamCtx (would take 500ms if not canceled).
	select {
	case <-upstreamCtx.Done():
	case <-time.After(300 * time.Millisecond):
		t.Fatal("upstreamCtx was not canceled early by during_call blocker")
	}
	if elapsed := time.Since(started); elapsed > 150*time.Millisecond {
		t.Fatalf("expected early cancel <150ms, took %v", elapsed)
	}

	_, waitErr := handle.Wait(context.Background())
	var gwErr *domain.GatewayError
	if !errors.As(waitErr, &gwErr) || gwErr.Code != "guardrail_blocked" {
		t.Fatalf("expected guardrail_blocked error, got %v", waitErr)
	}

	// Allowed case finishes without canceling upstreamCtx.
	reqAllow := &domain.CanonicalChatRequest{
		Model:    "gpt-4o",
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "hello"}},
	}
	upstreamAllowCtx, allowHandle, err := pipeline.StartDuringCall(context.Background(), prc, reqAllow)
	if err != nil {
		t.Fatalf("StartDuringCall allow: %v", err)
	}
	defer allowHandle.Close()
	if _, err := allowHandle.Wait(context.Background()); err != nil {
		t.Fatalf("expected nil wait error, got %v", err)
	}
	if upstreamAllowCtx.Err() != nil {
		t.Fatalf("upstreamAllowCtx should stay uncanceled on allow, got %v", upstreamAllowCtx.Err())
	}
}

func TestPipelineTimeoutAndAsyncNonBlockingLoggingOnly(t *testing.T) {
	repo := storage.NewMemoryRepository()
	seedOrg(t, repo, "org-async")

	// Timeout test: 20ms timeout on a 200ms driver with FailOpen=false.
	if err := repo.CreateGuardrailDefinition(context.Background(), &domain.GuardrailDefinition{
		ID:         "g-timeout",
		OrgID:      "org-async",
		Name:       "slow-guard",
		Provider:   "slow",
		EventHooks: []domain.GuardrailHook{domain.GuardrailHookPreCall},
		DefaultOn:  true,
		TimeoutMs:  20,
		FailOpen:   false,
		Status:     domain.GuardrailStatusActive,
	}); err != nil {
		t.Fatalf("CreateGuardrailDefinition slow: %v", err)
	}

	// Logging-only guardrail taking 40ms with a violation: must NOT block or delay caller.
	if err := repo.CreateGuardrailDefinition(context.Background(), &domain.GuardrailDefinition{
		ID:         "g-log-only",
		OrgID:      "org-async",
		Name:       "async-shadow",
		Provider:   "shadow",
		EventHooks: []domain.GuardrailHook{domain.GuardrailHookLoggingOnly},
		DefaultOn:  true,
		Status:     domain.GuardrailStatusActive,
	}); err != nil {
		t.Fatalf("CreateGuardrailDefinition shadow: %v", err)
	}

	var auditDone sync.WaitGroup
	auditDone.Add(1)
	var auditHook domain.GuardrailHook
	var auditViolations int
	var auditOnce sync.Once

	pipeline := guardrails.NewPipeline(nil, repo, guardrails.WithAuditHook(func(_ context.Context, hook domain.GuardrailHook, _ guardrails.PipelineRequestContext, res *domain.GuardrailEvalResult) {
		auditOnce.Do(func() {
			auditHook = hook
			auditViolations = len(res.Violations)
			auditDone.Done()
		})
	}))
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
	pipeline.RegisterDriver("shadow", func(_ context.Context, _ guardrails.DriverConfig) (guardrails.Driver, error) {
		return &stubDriver{
			name:  "shadow",
			hooks: []domain.GuardrailHook{domain.GuardrailHookLoggingOnly},
			fn: func(ctx context.Context, _ *domain.GuardrailEvalInput) (*domain.GuardrailEvalResult, error) {
				if ctx.Err() != nil {
					return nil, ctx.Err()
				}
				time.Sleep(35 * time.Millisecond)
				return &domain.GuardrailEvalResult{
					Decision: domain.GuardrailDecisionBlock,
					Violations: []domain.GuardrailViolation{{
						GuardrailName: "async-shadow",
						Message:       "shadow finding",
					}},
				}, nil
			},
		}, nil
	})

	prc := guardrails.PipelineRequestContext{RequestID: "req-t", OrgID: "org-async", Model: "gpt-4o"}
	req := &domain.CanonicalChatRequest{
		Model:    "gpt-4o",
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "hi"}},
	}

	startTimeout := time.Now()
	_, err := pipeline.EvaluatePreCall(context.Background(), prc, req)
	if err == nil {
		t.Fatal("expected timeout fail-closed error")
	}
	if elapsed := time.Since(startTimeout); elapsed > 120*time.Millisecond {
		t.Fatalf("expected timeout around 20ms, took %v", elapsed)
	}

	// Cancel parent context immediately after EvaluateLoggingOnly to prove context.WithoutCancel keeps it running.
	parentCtx, cancelParent := context.WithCancel(context.Background())
	startAsync := time.Now()
	pipeline.EvaluateLoggingOnly(parentCtx, prc, req, nil)
	cancelParent()
	if elapsed := time.Since(startAsync); elapsed > 15*time.Millisecond {
		t.Fatalf("EvaluateLoggingOnly must be non-blocking, took %v", elapsed)
	}
	if req.Messages[0].Content != "hi" {
		t.Fatalf("logging_only mutated req: %q", req.Messages[0].Content)
	}

	pipeline.WaitLoggingOnly(context.Background())
	auditDone.Wait()
	if auditHook != domain.GuardrailHookLoggingOnly || auditViolations != 1 {
		t.Fatalf("unexpected audit hook result: hook=%q violations=%d", auditHook, auditViolations)
	}
}
