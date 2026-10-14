package guardrails

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/logger"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

var (
	reEmail  = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)
	reSSN    = regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)
	reCard   = regexp.MustCompile(`\b(?:\d{4}[-\s]?){3}\d{4}\b`)
	reSecret = regexp.MustCompile(`\b(?:sk-[a-zA-Z0-9_\-]{12,}|AQ\.[a-zA-Z0-9_\-]{16,}|AKIA[0-9A-Z]{16})\b`)

	promptInjectionSignatures = []string{
		"ignore previous instructions",
		"ignore all prior instructions",
		"disregard your system prompt",
		"reveal your system prompt",
		"print your system instructions",
		"bypass all safety",
		"<|im_start|>system",
		"you are now dan",
	}
)

// CheckOutcome reports whether guardrails modified (redacted) or audited the request.
type CheckOutcome struct {
	Redacted      bool
	Violations    []string
	AppliedAction domain.GuardrailAction
}

// Engine evaluates input prompts and output completions against an Organization's GuardrailPolicy.
type Engine struct {
	repo storage.Repository
}

func NewEngine(repo storage.Repository) *Engine {
	return &Engine{repo: repo}
}

// EvaluateInput inspects and optionally mutates (redacts) or blocks a CanonicalChatRequest before upstream execution.
func (e *Engine) EvaluateInput(ctx context.Context, orgID string, req *domain.CanonicalChatRequest) (*CheckOutcome, error) {
	outcome := &CheckOutcome{}
	if e == nil || e.repo == nil || orgID == "" || req == nil {
		return outcome, nil
	}

	pol, err := e.repo.GetGuardrailPolicy(ctx, orgID)
	if err != nil || pol == nil {
		return outcome, nil
	}

	for idx := range req.Messages {
		msg := &req.Messages[idx]
		if msg.Role != "user" {
			continue
		}
		lower := strings.ToLower(msg.Content)

		// 1. Prompt Injection Check
		if pol.EnablePromptInjection {
			for _, sig := range promptInjectionSignatures {
				if strings.Contains(lower, sig) {
					outcome.Violations = append(outcome.Violations, "prompt_injection:"+sig)
					action := pol.PromptInjectionAction
					if action == "" {
						action = domain.GuardrailActionBlock
					}
					outcome.AppliedAction = action
					if action == domain.GuardrailActionBlock {
						return outcome, &domain.GatewayError{
							StatusCode: http.StatusBadRequest,
							Type:       domain.ErrorTypeInvalidRequest,
							Code:       "guardrail_prompt_injection",
							Message:    fmt.Sprintf("Request blocked by organization security guardrail (prompt injection signature detected: %q)", sig),
						}
					}
				}
			}
		}

		// 2. Custom Blocked Keywords
		for _, kw := range pol.BlockedKeywords {
			kwTrim := strings.TrimSpace(kw)
			if kwTrim != "" && strings.Contains(lower, strings.ToLower(kwTrim)) {
				outcome.Violations = append(outcome.Violations, "blocked_keyword:"+kwTrim)
				return outcome, &domain.GatewayError{
					StatusCode: http.StatusBadRequest,
					Type:       domain.ErrorTypeInvalidRequest,
					Code:       "guardrail_blocked_keyword",
					Message:    fmt.Sprintf("Request blocked by organization guardrail policy (restricted keyword: %q)", kwTrim),
				}
			}
		}

		// 3. Secret / API Key Leak Check
		if pol.EnableSecretDetection && reSecret.MatchString(msg.Content) {
			outcome.Violations = append(outcome.Violations, "secret_detected")
			action := pol.SecretAction
			if action == "" {
				action = domain.GuardrailActionRedact
			}
			outcome.AppliedAction = action
			if action == domain.GuardrailActionBlock {
				return outcome, &domain.GatewayError{
					StatusCode: http.StatusBadRequest,
					Type:       domain.ErrorTypeInvalidRequest,
					Code:       "guardrail_secret_detected",
					Message:    "Request blocked by security guardrail: sensitive API key or credential detected in prompt",
				}
			}
			if action == domain.GuardrailActionRedact {
				msg.Content = reSecret.ReplaceAllString(msg.Content, "[REDACTED_SECRET]")
				outcome.Redacted = true
			}
		}

		// 4. PII Detection (Emails, SSNs, Credit Cards)
		if pol.EnablePIIDetection {
			hasPII := reEmail.MatchString(msg.Content) || reSSN.MatchString(msg.Content) || reCard.MatchString(msg.Content)
			if hasPII {
				outcome.Violations = append(outcome.Violations, "pii_detected")
				action := pol.PIIAction
				if action == "" {
					action = domain.GuardrailActionRedact
				}
				outcome.AppliedAction = action
				if action == domain.GuardrailActionBlock {
					return outcome, &domain.GatewayError{
						StatusCode: http.StatusBadRequest,
						Type:       domain.ErrorTypeInvalidRequest,
						Code:       "guardrail_pii_detected",
						Message:    "Request blocked by security guardrail: PII (email, SSN, or payment card) detected in prompt",
					}
				}
				if action == domain.GuardrailActionRedact {
					msg.Content = reEmail.ReplaceAllString(msg.Content, "[REDACTED_EMAIL]")
					msg.Content = reSSN.ReplaceAllString(msg.Content, "[REDACTED_SSN]")
					msg.Content = reCard.ReplaceAllString(msg.Content, "[REDACTED_CARD]")
					outcome.Redacted = true
				}
			}
		}
	}

	if len(outcome.Violations) > 0 {
		logger.WarnContext(ctx, "Input guardrail violations detected",
			slog.String("component", "guardrails"),
			slog.String("org_id", orgID),
			slog.String("applied_action", string(outcome.AppliedAction)),
			slog.Bool("redacted", outcome.Redacted),
			slog.Any("violations", outcome.Violations),
		)
	}

	return outcome, nil
}

// SanitizeOutput redacts PII and secrets from model output completions if configured on the Organization's GuardrailPolicy.
func (e *Engine) SanitizeOutput(ctx context.Context, orgID string, resp *domain.CanonicalChatResponse) bool {
	if e == nil || e.repo == nil || orgID == "" || resp == nil {
		return false
	}
	pol, err := e.repo.GetGuardrailPolicy(ctx, orgID)
	if err != nil || pol == nil || !pol.RedactOutputPII {
		return false
	}

	redacted := false
	for i := range resp.Choices {
		c := &resp.Choices[i].Message.Content
		orig := *c
		updated := reEmail.ReplaceAllString(orig, "[REDACTED_EMAIL]")
		updated = reSSN.ReplaceAllString(updated, "[REDACTED_SSN]")
		updated = reCard.ReplaceAllString(updated, "[REDACTED_CARD]")
		updated = reSecret.ReplaceAllString(updated, "[REDACTED_SECRET]")
		if updated != orig {
			*c = updated
			redacted = true
		}
	}

	if redacted {
		logger.WarnContext(ctx, "Output guardrail redacted sensitive content from completion",
			slog.String("component", "guardrails"),
			slog.String("org_id", orgID),
		)
	}

	return redacted
}
