package drivers

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync/atomic"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/guardrails"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

func TestRegistryAll19ProvidersAndWave23Build(t *testing.T) {
	memRepo := storage.NewMemoryRepository()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	exec := ChatExecutorFunc(func(_ context.Context, _ *domain.IdentityContext, _ *domain.CanonicalChatRequest) (*domain.CanonicalChatResponse, error) {
		return &domain.CanonicalChatResponse{
			Choices: []domain.CanonicalChoice{{Message: domain.CanonicalMessage{Role: "assistant", Content: `{"score":95,"passed":true}`}}},
		}, nil
	})

	reg := NewRegistry(
		WithHTTPClient(srv.Client()),
		WithSSRFPolicy(&network.Policy{}),
		WithChatExecutor(exec),
		WithToolPolicyRepository(memRepo),
		WithMCPServerRegistry(memRepo),
	)

	expected := []string{
		ProviderAzurePromptShield,
		ProviderAzureTextModerations,
		ProviderBedrock,
		ProviderCodeExecution,
		CustomCodeProvider,
		ProviderDecisionModel,
		DriverNameGenericHTTP,
		ProviderGuardrailsAI,
		ProviderLakeraV2,
		ProviderLLMJudge,
		ProviderLocalContentFilter,
		ProviderMCPEndUserPermission,
		ProviderMCPSecurity,
		ProviderModelArmor,
		ProviderOpenAIModeration,
		ProviderPangea,
		ProviderPresidio,
		ProviderToolPermission,
		ProviderToolPolicy,
	}
	slices.Sort(expected)

	got := reg.Providers()
	if len(got) != 19 {
		t.Fatalf("expected 19 registered providers, got %d (%v)", len(got), got)
	}
	if !slices.Equal(got, expected) {
		t.Fatalf("Providers() = %v, want %v", got, expected)
	}

	buildCases := []struct {
		provider string
		cfg      map[string]any
	}{
		{provider: DriverNameGenericHTTP, cfg: map[string]any{"url": srv.URL + "/hook"}},
		{provider: CustomCodeProvider, cfg: map[string]any{"code": "def apply_guardrail(inputs, request_data, input_type):\n  return {'action': 'none'}"}},
		{provider: ProviderToolPermission, cfg: map[string]any{"default_action": "allow"}},
		{provider: ProviderToolPolicy, cfg: map[string]any{"default_input_policy": "untrusted"}},
		{provider: ProviderCodeExecution, cfg: map[string]any{"action": "block"}},
		{provider: ProviderMCPSecurity, cfg: map[string]any{"action": "block"}},
		{provider: ProviderMCPEndUserPermission, cfg: map[string]any{"default_action": "allow"}},
		{provider: ProviderLLMJudge, cfg: map[string]any{"model": "judge-gpt"}},
		{provider: ProviderDecisionModel, cfg: map[string]any{"model": "decision-gpt", "checks": []map[string]any{{"name": "safe", "question": "Is it safe?"}}}},
	}

	for _, tc := range buildCases {
		drv, err := reg.Build(context.Background(), guardrails.DriverConfig{
			Definition: &domain.GuardrailDefinition{
				ID:       "def-" + tc.provider,
				Name:     tc.provider,
				Provider: tc.provider,
				Config:   tc.cfg,
			},
			EffectiveConfig: tc.cfg,
		})
		if err != nil {
			t.Fatalf("Build(%s) failed: %v", tc.provider, err)
		}
		if drv == nil {
			t.Fatalf("Build(%s) returned nil driver", tc.provider)
		}
	}
}

func TestLLMJudgeWeightedRubricScoringAndActions(t *testing.T) {
	var capturedReq *domain.CanonicalChatRequest
	var nextContent string
	var nextUsage domain.TokenUsage

	exec := ChatExecutorFunc(func(ctx context.Context, _ *domain.IdentityContext, req *domain.CanonicalChatRequest) (*domain.CanonicalChatResponse, error) {
		if !IsInternalGuardrailOrigin(ctx) {
			t.Fatalf("expected ChatExecutor ctx to carry internal guardrail origin marker")
		}
		capturedReq = req
		return &domain.CanonicalChatResponse{
			Model:   req.Model,
			Choices: []domain.CanonicalChoice{{Index: 0, Message: domain.CanonicalMessage{Role: "assistant", Content: nextContent}}},
			Usage:   nextUsage,
		}, nil
	})

	baseCfg := func(action domain.GuardrailAction, extra map[string]any) guardrails.DriverConfig {
		cfgMap := map[string]any{
			"model":         "judge-model-v1",
			"system_prompt": "Score safety and helpfulness strictly.",
			"threshold":     75,
			"temperature":   0.1,
			"max_tokens":    256,
			"criteria": []map[string]any{
				{"name": "safety", "description": "No harmful instructions", "weight": 0.7},
				{"name": "helpfulness", "description": "Useful answer", "weight": 0.3},
			},
		}
		for k, v := range extra {
			cfgMap[k] = v
		}
		return guardrails.DriverConfig{
			Definition: &domain.GuardrailDefinition{
				ID:       "def-judge",
				Name:     "rubric-judge",
				Provider: ProviderLLMJudge,
				Config:   cfgMap,
			},
			EffectiveAction: action,
			EffectiveConfig: cfgMap,
		}
	}

	input := &domain.GuardrailEvalInput{
		Direction: domain.GuardrailDirectionOutput,
		Hook:      domain.GuardrailHookPostCall,
		OrgID:     "org-1",
		RequestID: "req-123",
		Model:     "gpt-4o",
		Texts:     []string{"Here is a detailed response."},
	}

	// 1. Weighted score passes: 0.7*90 + 0.3*70 = 63 + 21 = 84 >= 75.
	nextContent = "```json\n{\"score\": 50, \"criteria_scores\": {\"safety\": 90, \"helpfulness\": 70}, \"reason\": \"weighted pass\"}\n```"
	nextUsage = domain.TokenUsage{PromptTokens: 40, CompletionTokens: 25, TotalTokens: 65}

	drv, err := NewLLMJudgeDriver(baseCfg(domain.GuardrailActionBlock, nil), exec)
	if err != nil {
		t.Fatalf("NewLLMJudgeDriver: %v", err)
	}
	res, err := drv.Evaluate(context.Background(), input)
	if err != nil {
		t.Fatalf("Evaluate pass: %v", err)
	}
	if res.Decision != domain.GuardrailDecisionAllow {
		t.Fatalf("Decision = %q, want allow", res.Decision)
	}
	if res.UsageUnits != 65 {
		t.Fatalf("UsageUnits = %d, want 65", res.UsageUnits)
	}
	if capturedReq == nil || capturedReq.Model != "judge-model-v1" {
		t.Fatalf("unexpected judge request: %+v", capturedReq)
	}
	if capturedReq.Temperature == nil || *capturedReq.Temperature != 0.1 {
		t.Fatalf("expected temperature override 0.1, got %v", capturedReq.Temperature)
	}
	if capturedReq.MaxTokens == nil || *capturedReq.MaxTokens != 256 {
		t.Fatalf("expected max_tokens override 256, got %v", capturedReq.MaxTokens)
	}

	// 2. Weighted score fails: 0.7*40 + 0.3*100 = 28 + 30 = 58 < 75 -> Block.
	nextContent = `{"criteria_scores": {"safety": 40, "helpfulness": 100}, "reason": "unsafe content"}`
	nextUsage = domain.TokenUsage{PromptTokens: 30, CompletionTokens: 15}
	res, err = drv.Evaluate(context.Background(), input)
	if err != nil {
		t.Fatalf("Evaluate block: %v", err)
	}
	if res.Decision != domain.GuardrailDecisionBlock {
		t.Fatalf("Decision = %q, want block", res.Decision)
	}
	if res.UsageUnits != 45 {
		t.Fatalf("UsageUnits = %d, want 45", res.UsageUnits)
	}
	if len(res.Violations) != 1 || res.Violations[0].Score == nil || *res.Violations[0].Score != 58 {
		t.Fatalf("expected score=58 violation, got %+v", res.Violations)
	}

	// 3. Action=audit -> Flag.
	flagDrv, err := NewLLMJudgeDriver(baseCfg(domain.GuardrailActionAudit, nil), exec)
	if err != nil {
		t.Fatalf("NewLLMJudgeDriver flag: %v", err)
	}
	flagRes, err := flagDrv.Evaluate(context.Background(), input)
	if err != nil {
		t.Fatalf("Evaluate flag: %v", err)
	}
	if flagRes.Decision != domain.GuardrailDecisionFlag {
		t.Fatalf("Decision = %q, want flag", flagRes.Decision)
	}

	// 4. Action=redact/modify with revised_output -> Modify.
	nextContent = `{"score": 35, "passed": false, "reason": "redacted unsafe phrasing", "revised_output": "Safe rewritten answer."}`
	modDrv, err := NewLLMJudgeDriver(baseCfg(domain.GuardrailActionRedact, nil), exec)
	if err != nil {
		t.Fatalf("NewLLMJudgeDriver modify: %v", err)
	}
	modRes, err := modDrv.Evaluate(context.Background(), input)
	if err != nil {
		t.Fatalf("Evaluate modify: %v", err)
	}
	if modRes.Decision != domain.GuardrailDecisionModify {
		t.Fatalf("Decision = %q, want modify", modRes.Decision)
	}
	if len(modRes.ModifiedTexts) != 1 || modRes.ModifiedTexts[0] != "Safe rewritten answer." {
		t.Fatalf("ModifiedTexts = %v, want [Safe rewritten answer.]", modRes.ModifiedTexts)
	}

	// 5. Risk scoring mode (threshold_direction: "lte", threshold: 30).
	riskDrv, err := NewLLMJudgeDriver(baseCfg(domain.GuardrailActionBlock, map[string]any{
		"threshold":           30,
		"threshold_direction": "lte",
		"criteria":            nil,
	}), exec)
	if err != nil {
		t.Fatalf("NewLLMJudgeDriver risk: %v", err)
	}
	nextContent = `{"score": 25, "reason": "low risk"}`
	riskPass, err := riskDrv.Evaluate(context.Background(), input)
	if err != nil || riskPass.Decision != domain.GuardrailDecisionAllow {
		t.Fatalf("expected low risk score 25 <= 30 to allow, got res=%+v err=%v", riskPass, err)
	}
	nextContent = `{"score": 60, "reason": "high risk"}`
	riskBlock, err := riskDrv.Evaluate(context.Background(), input)
	if err != nil || riskBlock.Decision != domain.GuardrailDecisionBlock {
		t.Fatalf("expected high risk score 60 > 30 to block, got res=%+v err=%v", riskBlock, err)
	}
}

func TestLLMJudgeParseFailureFailOpenAndFailClosed(t *testing.T) {
	ctx := context.Background()
	var returnMalformed atomic.Bool
	returnMalformed.Store(true)

	exec := ChatExecutorFunc(func(_ context.Context, _ *domain.IdentityContext, _ *domain.CanonicalChatRequest) (*domain.CanonicalChatResponse, error) {
		if returnMalformed.Load() {
			return &domain.CanonicalChatResponse{
				Choices: []domain.CanonicalChoice{{Message: domain.CanonicalMessage{Role: "assistant", Content: "not valid json at all"}}},
			}, nil
		}
		return nil, errors.New("upstream judge timeout")
	})

	runWithFailOpen := func(failOpen bool) error {
		repo := storage.NewMemoryRepository()
		if err := repo.CreateOrganization(ctx, &domain.Organization{ID: "org-1", Name: "Org 1"}); err != nil {
			t.Fatalf("CreateOrganization: %v", err)
		}
		if err := repo.CreateGuardrailDefinition(ctx, &domain.GuardrailDefinition{
			ID:         "def-judge-fo",
			OrgID:      "org-1",
			Name:       "judge-fo",
			Provider:   ProviderLLMJudge,
			EventHooks: []domain.GuardrailHook{domain.GuardrailHookPreCall},
			DefaultOn:  true,
			FailOpen:   failOpen,
			Status:     domain.GuardrailStatusActive,
			Config:     map[string]any{"model": "judge-model"},
		}); err != nil {
			t.Fatalf("CreateGuardrailDefinition: %v", err)
		}

		reg := NewRegistry(WithChatExecutor(exec))
		pipeline := guardrails.NewPipeline(nil, repo)
		pipeline.SetDriverLookup(reg.Build)

		req := &domain.CanonicalChatRequest{
			Model:    "gpt-4o",
			Messages: []domain.CanonicalMessage{{Role: "user", Content: "evaluate this"}},
		}
		_, err := pipeline.EvaluatePreCall(ctx, guardrails.PipelineRequestContext{OrgID: "org-1"}, req)
		return err
	}

	// Malformed JSON: fail-closed errors, fail-open allows.
	if err := runWithFailOpen(false); err == nil {
		t.Fatalf("expected fail-closed error on malformed judge JSON")
	}
	if err := runWithFailOpen(true); err != nil {
		t.Fatalf("expected fail-open allow on malformed judge JSON, got: %v", err)
	}

	// Executor error: fail-closed errors, fail-open allows.
	returnMalformed.Store(false)
	if err := runWithFailOpen(false); err == nil {
		t.Fatalf("expected fail-closed error on executor failure")
	}
	if err := runWithFailOpen(true); err != nil {
		t.Fatalf("expected fail-open allow on executor failure, got: %v", err)
	}
}

func TestDecisionModelMultiPredicateChecks(t *testing.T) {
	var mockReply string
	exec := ChatExecutorFunc(func(ctx context.Context, _ *domain.IdentityContext, req *domain.CanonicalChatRequest) (*domain.CanonicalChatResponse, error) {
		if !IsInternalGuardrailOrigin(ctx) {
			t.Fatalf("expected internal origin context on decision_model sub-call")
		}
		return &domain.CanonicalChatResponse{
			Model:   req.Model,
			Choices: []domain.CanonicalChoice{{Message: domain.CanonicalMessage{Role: "assistant", Content: mockReply}}},
			Usage:   domain.TokenUsage{TotalTokens: 42},
		}, nil
	})

	expectedFalse := false
	expectedTrue := true
	cfgMap := map[string]any{
		"model":         "decision-mini",
		"all_must_pass": true,
		"checks": []DecisionCheck{
			{Name: "contains_secret", Description: "Does the text contain API keys?", Expected: &expectedFalse, Action: "block", Severity: "critical"},
			{Name: "polite_tone", Question: "Is the tone respectful?", Expected: &expectedTrue, Action: "flag", Severity: "low"},
		},
	}

	drv, err := NewDecisionModelDriver(guardrails.DriverConfig{
		Definition: &domain.GuardrailDefinition{
			ID:       "def-dm",
			Name:     "policy-checks",
			Provider: ProviderDecisionModel,
			Config:   cfgMap,
		},
		EffectiveConfig: cfgMap,
	}, exec)
	if err != nil {
		t.Fatalf("NewDecisionModelDriver: %v", err)
	}

	input := &domain.GuardrailEvalInput{
		Direction: domain.GuardrailDirectionInput,
		Hook:      domain.GuardrailHookPreCall,
		Texts:     []string{"Please summarize this public article."},
	}

	// 1. All checks match expected -> Allow.
	mockReply = `{"checks": {"contains_secret": {"result": false, "reason": "no keys"}, "polite_tone": {"result": true, "reason": "polite"}}}`
	res, err := drv.Evaluate(context.Background(), input)
	if err != nil {
		t.Fatalf("Evaluate allow: %v", err)
	}
	if res.Decision != domain.GuardrailDecisionAllow || res.UsageUnits != 42 {
		t.Fatalf("expected allow with 42 usage units, got %+v", res)
	}

	// 2. Only flag check fails -> Flag.
	mockReply = `{"checks": {"contains_secret": false, "polite_tone": false}}`
	res, err = drv.Evaluate(context.Background(), input)
	if err != nil {
		t.Fatalf("Evaluate flag: %v", err)
	}
	if res.Decision != domain.GuardrailDecisionFlag {
		t.Fatalf("Decision = %q, want flag", res.Decision)
	}
	if len(res.Violations) != 1 || res.Violations[0].Rule != "polite_tone" || res.Violations[0].Severity != "low" {
		t.Fatalf("unexpected violations: %+v", res.Violations)
	}

	// 3. Block check fails -> Block (even if flag check also fails, both violations recorded).
	mockReply = `{"checks": [{"name": "contains_secret", "result": true, "reason": "API key detected"}, {"name": "polite_tone", "result": false, "reason": "rude"}]}`
	res, err = drv.Evaluate(context.Background(), input)
	if err != nil {
		t.Fatalf("Evaluate block: %v", err)
	}
	if res.Decision != domain.GuardrailDecisionBlock {
		t.Fatalf("Decision = %q, want block", res.Decision)
	}
	if len(res.Violations) != 2 {
		t.Fatalf("expected 2 violations, got %+v", res.Violations)
	}

	// 4. all_must_pass: false (OR mode) -> 1 passing check allows.
	orCfgMap := map[string]any{
		"model":         "decision-mini",
		"all_must_pass": false,
		"checks": []DecisionCheck{
			{Name: "lang_en", Question: "Is it English?", Expected: &expectedTrue, Action: "block"},
			{Name: "lang_es", Question: "Is it Spanish?", Expected: &expectedTrue, Action: "block"},
		},
	}
	orDrv, err := NewDecisionModelDriver(guardrails.DriverConfig{
		Definition:      &domain.GuardrailDefinition{ID: "def-or", Name: "lang-or", Provider: ProviderDecisionModel, Config: orCfgMap},
		EffectiveConfig: orCfgMap,
	}, exec)
	if err != nil {
		t.Fatalf("NewDecisionModelDriver OR: %v", err)
	}
	mockReply = `{"results": {"lang_en": true, "lang_es": false}}`
	orRes, err := orDrv.Evaluate(context.Background(), input)
	if err != nil || orRes.Decision != domain.GuardrailDecisionAllow {
		t.Fatalf("expected OR-mode allow when one check passes, got res=%+v err=%v", orRes, err)
	}
	mockReply = `{"results": {"lang_en": false, "lang_es": false}}`
	orBlock, err := orDrv.Evaluate(context.Background(), input)
	if err != nil || orBlock.Decision != domain.GuardrailDecisionBlock {
		t.Fatalf("expected OR-mode block when all checks fail, got res=%+v err=%v", orBlock, err)
	}
}

func TestLoopProtectionInPipelineAndSpoofedMetadata(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	if err := repo.CreateOrganization(ctx, &domain.Organization{ID: "org-loop", Name: "Loop Org"}); err != nil {
		t.Fatalf("CreateOrganization: %v", err)
	}
	if err := repo.CreateGuardrailDefinition(ctx, &domain.GuardrailDefinition{
		ID:         "def-loop-judge",
		OrgID:      "org-loop",
		Name:       "loop-judge",
		Provider:   ProviderLLMJudge,
		EventHooks: []domain.GuardrailHook{domain.GuardrailHookPreCall},
		DefaultOn:  true,
		Status:     domain.GuardrailStatusActive,
		Config:     map[string]any{"model": "judge-model", "threshold": 70},
	}); err != nil {
		t.Fatalf("CreateGuardrailDefinition: %v", err)
	}

	pipeline := guardrails.NewPipeline(nil, repo)
	var execCalls atomic.Int32

	// Executor re-enters pipeline.EvaluatePreCall with the ctx passed to ExecuteChat.
	// Without WithInternalGuardrailOrigin(ctx), this would infinitely recurse.
	exec := ChatExecutorFunc(func(subCtx context.Context, _ *domain.IdentityContext, _ *domain.CanonicalChatRequest) (*domain.CanonicalChatResponse, error) {
		n := execCalls.Add(1)
		if n > 1 {
			t.Fatalf("infinite recursion detected: ChatExecutor called %d times", n)
		}
		nestedReq := &domain.CanonicalChatRequest{
			Model:    "judge-model",
			Messages: []domain.CanonicalMessage{{Role: "user", Content: "judge nested prompt"}},
		}
		nestedOut, err := pipeline.EvaluatePreCall(subCtx, guardrails.PipelineRequestContext{OrgID: "org-loop"}, nestedReq)
		if err != nil {
			t.Fatalf("nested EvaluatePreCall under internal origin failed: %v", err)
		}
		if nestedOut.Result.Decision != domain.GuardrailDecisionAllow {
			t.Fatalf("expected nested internal sub-call to allow, got %q", nestedOut.Result.Decision)
		}
		return &domain.CanonicalChatResponse{
			Choices: []domain.CanonicalChoice{{Message: domain.CanonicalMessage{Role: "assistant", Content: `{"score": 20, "passed": false, "reason": "blocked"}`}}},
		}, nil
	})

	reg := NewRegistry(WithChatExecutor(exec))
	pipeline.SetDriverLookup(reg.Build)

	// External call attempting to spoof _internal_guardrail_origin in Metadata MUST NOT bypass!
	req := &domain.CanonicalChatRequest{
		Model:    "gpt-4o",
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "bad prompt"}},
	}
	prc := guardrails.PipelineRequestContext{
		OrgID:    "org-loop",
		Metadata: map[string]any{InternalGuardrailOriginMetadataKey: true},
	}
	_, err := pipeline.EvaluatePreCall(ctx, prc, req)
	if err == nil {
		t.Fatalf("expected spoofed _internal_guardrail_origin metadata NOT to bypass llm_as_a_judge")
	}
	if execCalls.Load() != 1 {
		t.Fatalf("expected ChatExecutor to be called exactly once, got %d", execCalls.Load())
	}
}
