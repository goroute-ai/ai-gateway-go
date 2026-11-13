package guardrails

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"time"

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
	repo              storage.Repository
	scanners          []Scanner
	scannerTimeout    time.Duration
	scannerFailClosed bool
}

func NewEngine(repo storage.Repository) *Engine {
	return &Engine{repo: repo, scannerTimeout: 2 * time.Second, scannerFailClosed: true}
}

// ConfigureScanners injects optional provider-neutral scanners. Configure the engine
// before serving traffic; passing no scanners preserves local-only behavior and
// performs no network calls.
func (e *Engine) ConfigureScanners(timeout time.Duration, failClosed bool, scanners ...Scanner) {
	if e == nil {
		return
	}
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	e.scannerTimeout = timeout
	e.scannerFailClosed = failClosed
	e.scanners = append([]Scanner(nil), scanners...)
}

func (e *Engine) Policy(ctx context.Context, orgID string) (*domain.GuardrailPolicy, error) {
	if e == nil || e.repo == nil || orgID == "" {
		return nil, policyUnavailableError()
	}
	pol, err := e.repo.GetGuardrailPolicy(ctx, orgID)
	if err != nil {
		return nil, policyUnavailableError()
	}
	return pol, nil
}

func policyUnavailableError() error {
	return &domain.GatewayError{
		StatusCode: http.StatusServiceUnavailable,
		Type:       domain.ErrorTypeServer,
		Code:       "guardrail_policy_unavailable",
		Message:    "Security policy could not be loaded; request was rejected",
	}
}

// EvaluateInput inspects and optionally mutates (redacts) or blocks a CanonicalChatRequest before upstream execution.
func (e *Engine) EvaluateInput(ctx context.Context, orgID string, req *domain.CanonicalChatRequest) (*CheckOutcome, error) {
	if req == nil {
		return &CheckOutcome{}, nil
	}
	if e == nil || e.repo == nil || orgID == "" {
		return nil, policyUnavailableError()
	}
	pol, err := e.Policy(ctx, orgID)
	if err != nil {
		return nil, err
	}
	if pol == nil && len(e.scanners) == 0 {
		return &CheckOutcome{}, nil
	}
	if pol == nil {
		pol = &domain.GuardrailPolicy{OrgID: orgID}
	}
	return e.EvaluateInputWithPolicy(ctx, pol, req)
}

// EvaluateInputWithPolicy evaluates a CanonicalChatRequest directly against an explicit GuardrailPolicy.
func (e *Engine) EvaluateInputWithPolicy(ctx context.Context, pol *domain.GuardrailPolicy, req *domain.CanonicalChatRequest) (*CheckOutcome, error) {
	outcome := &CheckOutcome{}
	if e == nil || pol == nil || req == nil {
		return outcome, nil
	}

	// Apply the same policy to text carried in multimodal fields and tool arguments.
	// Images and other binary payloads remain untouched.
	for mi := range req.Messages {
		msg := &req.Messages[mi]
		if msg.Role != "user" {
			continue
		}
		texts := []*string{&msg.ReasoningContent}
		for ci := range msg.ToolCalls {
			texts = append(texts, &msg.ToolCalls[ci].Function.Arguments)
		}
		for pi := range msg.Parts {
			if msg.Parts[pi].Type == "text" {
				texts = append(texts, &msg.Parts[pi].Text)
			}
		}
		for _, field := range texts {
			if *field == "" {
				continue
			}
			probe := &domain.CanonicalChatRequest{Messages: []domain.CanonicalMessage{{Role: "user", Content: *field}}}
			partOutcome, err := e.EvaluateInputWithPolicy(ctx, pol, probe)
			if partOutcome != nil {
				outcome.Violations = append(outcome.Violations, partOutcome.Violations...)
				if partOutcome.AppliedAction != "" {
					outcome.AppliedAction = partOutcome.AppliedAction
				}
				outcome.Redacted = outcome.Redacted || partOutcome.Redacted
			}
			if err != nil {
				return outcome, err
			}
			*field = probe.Messages[0].Content
		}
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

	for idx := range req.Messages {
		msg := &req.Messages[idx]
		if msg.Role != "user" {
			continue
		}
		for _, scanner := range e.scanners {
			scanCtx, cancel := context.WithTimeout(ctx, e.scannerTimeout)
			result, err := scanner.Scan(scanCtx, ScanRequest{OrgID: pol.OrgID, Direction: ScanInput, Content: msg.Content})
			cancel()
			if err != nil {
				logger.WarnContext(ctx, "Optional guardrail scanner failed", slog.String("component", "guardrails"), slog.String("org_id", pol.OrgID), slog.String("error_kind", scannerErrorKind(err)), slog.Bool("fail_closed", e.scannerFailClosed))
				if e.scannerFailClosed {
					return outcome, &domain.GatewayError{StatusCode: http.StatusServiceUnavailable, Type: domain.ErrorTypeServer, Code: "guardrail_scanner_unavailable", Message: "request could not be scanned by the configured security scanner"}
				}
				continue
			}
			if result.Decision == ScannerDecisionBlock {
				outcome.AppliedAction = domain.GuardrailActionBlock
				outcome.Violations = append(outcome.Violations, result.Violations...)
				if len(result.Violations) == 0 {
					outcome.Violations = append(outcome.Violations, "external_scanner_blocked")
				}
				return outcome, &domain.GatewayError{StatusCode: http.StatusBadRequest, Type: domain.ErrorTypeInvalidRequest, Code: "guardrail_scanner_blocked", Message: "request blocked by configured security scanner"}
			}
			if result.Decision != ScannerDecisionAllow {
				logger.WarnContext(ctx, "Optional guardrail scanner returned invalid decision", slog.String("component", "guardrails"), slog.String("org_id", pol.OrgID), slog.String("error_kind", "invalid_decision"), slog.Bool("fail_closed", e.scannerFailClosed))
				if e.scannerFailClosed {
					return outcome, &domain.GatewayError{StatusCode: http.StatusServiceUnavailable, Type: domain.ErrorTypeServer, Code: "guardrail_scanner_unavailable", Message: "request could not be scanned by the configured security scanner"}
				}
			}
			outcome.Violations = append(outcome.Violations, result.Violations...)
		}
	}

	if len(outcome.Violations) > 0 {
		logger.WarnContext(ctx, "Input guardrail violations detected",
			slog.String("component", "guardrails"),
			slog.String("org_id", pol.OrgID),
			slog.String("applied_action", string(outcome.AppliedAction)),
			slog.Bool("redacted", outcome.Redacted),
			slog.Any("violations", outcome.Violations),
		)
	}

	return outcome, nil
}

// SanitizeOutput redacts sensitive data and scans every textual output field.
// Callers must withhold output when this method returns an error.
func (e *Engine) SanitizeOutput(ctx context.Context, orgID string, resp *domain.CanonicalChatResponse) (bool, error) {
	if resp == nil {
		return false, nil
	}
	pol, err := e.Policy(ctx, orgID)
	if err != nil {
		return false, err
	}
	if pol == nil && len(e.scanners) == 0 {
		return false, nil
	}
	if pol == nil {
		pol = &domain.GuardrailPolicy{OrgID: orgID}
	}
	redacted := false
	for i := range resp.Choices {
		msg := &resp.Choices[i].Message
		fields := []*string{&msg.Content, &msg.ReasoningContent}
		for pi := range msg.Parts {
			if msg.Parts[pi].Type == "text" {
				fields = append(fields, &msg.Parts[pi].Text)
			}
		}
		for ci := range msg.ToolCalls {
			fields = append(fields, &msg.ToolCalls[ci].Function.Arguments)
		}
		for _, field := range fields {
			if pol.RedactOutputPII {
				updated := sanitizeText(*field)
				if updated != *field {
					*field = updated
					redacted = true
				}
			}
			if err := e.scanText(ctx, orgID, ScanOutput, *field); err != nil {
				return redacted, err
			}
		}
	}
	if redacted {
		logger.WarnContext(ctx, "Output guardrail redacted sensitive content from completion", slog.String("component", "guardrails"), slog.String("org_id", orgID))
	}
	return redacted, nil
}

// SanitizeOutputStrict is retained for callers that require the policy error explicitly.
func (e *Engine) SanitizeOutputStrict(ctx context.Context, orgID string, resp *domain.CanonicalChatResponse) (bool, error) {
	return e.SanitizeOutput(ctx, orgID, resp)
}

func (e *Engine) SanitizeTextOutput(ctx context.Context, orgID, text string) (string, bool, error) {
	pol, err := e.Policy(ctx, orgID)
	if err != nil {
		return "", false, err
	}
	if pol == nil && len(e.scanners) == 0 {
		return text, false, nil
	}
	redacted := false
	if pol != nil && pol.RedactOutputPII {
		updated := sanitizeText(text)
		redacted = updated != text
		text = updated
	}
	if err := e.scanText(ctx, orgID, ScanOutput, text); err != nil {
		return "", redacted, err
	}
	return text, redacted, nil
}

func sanitizeText(text string) string {
	updated := reEmail.ReplaceAllString(text, "[REDACTED_EMAIL]")
	updated = reSSN.ReplaceAllString(updated, "[REDACTED_SSN]")
	updated = reCard.ReplaceAllString(updated, "[REDACTED_CARD]")
	return reSecret.ReplaceAllString(updated, "[REDACTED_SECRET]")
}

func (e *Engine) scanText(ctx context.Context, orgID string, direction ScanDirection, content string) error {
	for _, scanner := range e.scanners {
		scanCtx, cancel := context.WithTimeout(ctx, e.scannerTimeout)
		result, err := scanner.Scan(scanCtx, ScanRequest{OrgID: orgID, Direction: direction, Content: content})
		cancel()
		if err != nil {
			logger.WarnContext(ctx, "Optional guardrail scanner failed", slog.String("component", "guardrails"), slog.String("org_id", orgID), slog.String("error_kind", scannerErrorKind(err)), slog.Bool("fail_closed", e.scannerFailClosed))
			if e.scannerFailClosed {
				return &domain.GatewayError{StatusCode: http.StatusServiceUnavailable, Type: domain.ErrorTypeServer, Code: "guardrail_scanner_unavailable", Message: "content could not be scanned by the configured security scanner"}
			}
			continue
		}
		if result.Decision == ScannerDecisionBlock {
			status := http.StatusBadRequest
			message := "content blocked by configured security scanner"
			code := "guardrail_scanner_blocked"
			if direction == ScanOutput {
				status = http.StatusBadGateway
				message = "response withheld by configured security scanner"
			}
			return &domain.GatewayError{StatusCode: status, Type: domain.ErrorTypeServer, Code: code, Message: message}
		}
		if result.Decision != ScannerDecisionAllow {
			logger.WarnContext(ctx, "Optional guardrail scanner returned invalid decision", slog.String("component", "guardrails"), slog.String("org_id", orgID), slog.String("error_kind", "invalid_decision"), slog.Bool("fail_closed", e.scannerFailClosed))
			if e.scannerFailClosed {
				return &domain.GatewayError{StatusCode: http.StatusServiceUnavailable, Type: domain.ErrorTypeServer, Code: "guardrail_scanner_unavailable", Message: "content could not be scanned by the configured security scanner"}
			}
		}
	}
	return nil
}

func scannerErrorKind(err error) string {
	switch {
	case errors.Is(err, context.DeadlineExceeded):
		return "timeout"
	case errors.Is(err, context.Canceled):
		return "canceled"
	default:
		return "scanner_error"
	}
}
