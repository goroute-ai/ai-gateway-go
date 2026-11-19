package guardrails_test

import (
	"context"
	"strings"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/guardrails"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

func TestGuardrailActionRoute_EngineAndPipeline(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	seedOrg(t, repo, "org-route")

	// Missing sensitive_route_target must fail closed.
	if err := repo.SetGuardrailPolicy(ctx, &domain.GuardrailPolicy{
		OrgID:              "org-route",
		EnablePIIDetection: true,
		PIIAction:          domain.GuardrailActionRoute,
		Mode:               domain.GuardrailModeEnforce,
	}); err != nil {
		t.Fatalf("SetGuardrailPolicy: %v", err)
	}
	eng := guardrails.NewEngine(repo)
	if _, err := eng.EvaluateInput(ctx, "org-route", &domain.CanonicalChatRequest{
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "Email alice@example.com"}},
	}); err == nil {
		t.Fatal("expected error when PII route action has no sensitive_route_target")
	}

	// Configured sensitive_route_target routes without blocking or redacting PII/secrets.
	if err := repo.SetGuardrailPolicy(ctx, &domain.GuardrailPolicy{
		OrgID:                 "org-route",
		EnablePIIDetection:    true,
		PIIAction:             domain.GuardrailActionRoute,
		EnableSecretDetection: true,
		SecretAction:          domain.GuardrailActionRoute,
		SensitiveRouteTarget:  "private-vllm",
		Mode:                  domain.GuardrailModeEnforce,
	}); err != nil {
		t.Fatalf("SetGuardrailPolicy: %v", err)
	}

	req := &domain.CanonicalChatRequest{
		Model: "public-cloud",
		Messages: []domain.CanonicalMessage{
			{Role: "user", Content: "Reach alice@example.com with key sk-proj-1234567890abcdef"},
		},
	}
	outcome, err := eng.EvaluateInput(ctx, "org-route", req)
	if err != nil {
		t.Fatalf("EvaluateInput error: %v", err)
	}
	if outcome.AppliedAction != domain.GuardrailActionRoute || outcome.RouteTarget != "private-vllm" {
		t.Fatalf("unexpected outcome: %+v", outcome)
	}
	if outcome.Redacted || !strings.Contains(req.Messages[0].Content, "alice@example.com") {
		t.Fatalf("expected original content preserved under route action, got %q", req.Messages[0].Content)
	}

	// Pipeline propagates Layer 0 RouteTarget as well as Layer 1 GuardrailDefinition.SensitiveRouteTarget.
	pipeline := guardrails.NewPipeline(eng, repo)
	pOut, pErr := pipeline.EvaluatePreCall(ctx, guardrails.PipelineRequestContext{
		OrgID: "org-route",
		Model: "public-cloud",
	}, req)
	if pErr != nil {
		t.Fatalf("Pipeline EvaluatePreCall error: %v", pErr)
	}
	if pOut.RouteTarget != "private-vllm" || pOut.AppliedAction != domain.GuardrailActionRoute {
		t.Fatalf("unexpected pipeline outcome: %+v", pOut)
	}
}

func TestGuardrailActionRoute_Layer1DefinitionTarget(t *testing.T) {
	ctx := context.Background()
	repo := storage.NewMemoryRepository()
	seedOrg(t, repo, "org-l1-route")

	if err := repo.CreateGuardrailDefinition(ctx, &domain.GuardrailDefinition{
		ID:                   "g-l1-route",
		OrgID:                "org-l1-route",
		Name:                 "compliance-router",
		Provider:             "custom-classifier",
		EventHooks:           []domain.GuardrailHook{domain.GuardrailHookPreCall},
		DefaultOn:            true,
		Precedence:           1,
		Status:               domain.GuardrailStatusActive,
		SensitiveRouteTarget: "sovereign-llm",
	}); err != nil {
		t.Fatalf("CreateGuardrailDefinition: %v", err)
	}

	pipeline := guardrails.NewPipeline(guardrails.NewEngine(repo), repo)
	pipeline.RegisterDriver("custom-classifier", func(_ context.Context, cfg guardrails.DriverConfig) (guardrails.Driver, error) {
		return &stubDriver{
			name:  "custom-classifier",
			hooks: cfg.Definition.EventHooks,
			fn: func(_ context.Context, _ *domain.GuardrailEvalInput) (*domain.GuardrailEvalResult, error) {
				return &domain.GuardrailEvalResult{
					Decision: domain.GuardrailDecisionFlag,
					Violations: []domain.GuardrailViolation{{
						Rule: "sensitive_financial",
					}},
				}, nil
			},
		}, nil
	})

	req := &domain.CanonicalChatRequest{
		Model:    "cloud-default",
		Messages: []domain.CanonicalMessage{{Role: "user", Content: "Account 12345 balance"}},
	}
	out, err := pipeline.EvaluatePreCall(ctx, guardrails.PipelineRequestContext{
		OrgID: "org-l1-route",
		Model: "cloud-default",
	}, req)
	if err != nil {
		t.Fatalf("EvaluatePreCall: %v", err)
	}
	if out.RouteTarget != "sovereign-llm" {
		t.Fatalf("expected Layer 1 RouteTarget=sovereign-llm, got %q", out.RouteTarget)
	}
}
