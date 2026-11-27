package guardrails

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"sync"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/logger"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

var (
	reEmail  = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)
	reSSN    = regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)
	reCard   = regexp.MustCompile(`\b(?:(?:\d{4}[-\s]?){3}\d{4}|3[47]\d{2}[-\s]?\d{6}[-\s]?\d{5})\b`)
	rePhone  = regexp.MustCompile(`(?:\+\d{1,3}[-.\s])?(?:\(\d{3}\)\s*|\b\d{3}[-.\s])\d{3}[-.\s]\d{4}\b`)
	reIPv4   = regexp.MustCompile(`\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b`)
	reSecret = regexp.MustCompile(`\b(?:sk-[a-zA-Z0-9_\-]{12,}|AQ\.[a-zA-Z0-9_\-]{16,}|AKIA[0-9A-Z]{16}|ghp_[a-zA-Z0-9]{20,}|xoxb-[a-zA-Z0-9\-]{10,}|AIza[0-9A-Za-z\-_]{20,})\b|-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----`)

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

	compiledPatternCache sync.Map // string -> *regexp.Regexp
)

// ValidateBlockedPatterns verifies that every configured regex pattern compiles cleanly.
func ValidateBlockedPatterns(patterns []string) error {
	for _, raw := range patterns {
		pat := strings.TrimSpace(raw)
		if pat == "" {
			continue
		}
		if len(pat) > 512 {
			return fmt.Errorf("blocked pattern exceeds maximum length of 512 characters")
		}
		if _, err := compileCachedPattern(pat); err != nil {
			return fmt.Errorf("invalid blocked pattern %q: %w", pat, err)
		}
	}
	return nil
}

func compileCachedPattern(pat string) (*regexp.Regexp, error) {
	if cached, ok := compiledPatternCache.Load(pat); ok {
		return cached.(*regexp.Regexp), nil
	}
	re, err := regexp.Compile(pat)
	if err != nil {
		return nil, err
	}
	compiledPatternCache.Store(pat, re)
	return re, nil
}

// CheckOutcome reports whether guardrails modified (redacted) or audited the request.
type CheckOutcome struct {
	Redacted      bool
	Violations    []string
	AppliedAction domain.GuardrailAction
	RiskScore     float64
}

// Engine evaluates input prompts and output completions against an Organization's GuardrailPolicy.
type Engine struct {
	repo storage.Repository
}

// NewEngine creates a guardrail Engine backed by repo.
func NewEngine(repo storage.Repository) *Engine {
	return &Engine{repo: repo}
}

// NewStreamRedactor returns a StreamRedactor configured for pol.
func (e *Engine) NewStreamRedactor(pol *domain.GuardrailPolicy) *StreamRedactor {
	return NewStreamRedactor(pol)
}

// Policy loads the active GuardrailPolicy for orgID, returning a fail-closed error on storage failure.
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

// EvaluateInput inspects and optionally redacts or blocks a CanonicalChatRequest before upstream execution.
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
	if pol == nil {
		return &CheckOutcome{}, nil
	}
	return e.EvaluateInputWithPolicy(ctx, pol, req)
}

func shouldScanRole(pol *domain.GuardrailPolicy, role string) bool {
	if pol != nil && pol.ScanAllRoles {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(role), "user")
}

func messageTextFields(msg *domain.CanonicalMessage) []*string {
	fields := []*string{&msg.Content, &msg.ReasoningContent}
	for ci := range msg.ToolCalls {
		fields = append(fields, &msg.ToolCalls[ci].Function.Arguments)
	}
	for pi := range msg.Parts {
		if msg.Parts[pi].Type == "text" {
			fields = append(fields, &msg.Parts[pi].Text)
		}
	}
	return fields
}

func checkPromptInjection(pol *domain.GuardrailPolicy, loggingOnly bool, text string, outcome *CheckOutcome) error {
	if !pol.EnablePromptInjection || text == "" {
		return nil
	}
	normalized := normalizeTextForSignatureCheck(text)
	for _, sig := range promptInjectionSignatures {
		if strings.Contains(normalized, sig) {
			outcome.Violations = append(outcome.Violations, "prompt_injection:"+sig)
			action := pol.PromptInjectionAction
			if action == "" {
				action = domain.GuardrailActionBlock
			}
			if loggingOnly {
				outcome.AppliedAction = domain.GuardrailActionAudit
				continue
			}
			outcome.AppliedAction = action
			if action == domain.GuardrailActionBlock {
				return &domain.GatewayError{
					StatusCode: http.StatusBadRequest,
					Type:       domain.ErrorTypeInvalidRequest,
					Code:       "guardrail_prompt_injection",
					Message:    fmt.Sprintf("Request blocked by organization security guardrail (prompt injection signature detected: %q)", sig),
				}
			}
		}
	}
	return nil
}

func checkBlockedPatterns(pol *domain.GuardrailPolicy, loggingOnly bool, text string, isOutput bool, outcome *CheckOutcome) error {
	for _, raw := range pol.BlockedPatterns {
		pat := strings.TrimSpace(raw)
		if pat == "" {
			continue
		}
		re, err := compileCachedPattern(pat)
		if err != nil {
			continue
		}
		if re.MatchString(text) {
			outcome.Violations = append(outcome.Violations, "blocked_pattern:"+pat)
			if loggingOnly {
				outcome.AppliedAction = domain.GuardrailActionAudit
				continue
			}
			outcome.AppliedAction = domain.GuardrailActionBlock
			if isOutput {
				return &domain.GatewayError{
					StatusCode: http.StatusBadGateway,
					Type:       domain.ErrorTypeServer,
					Code:       "guardrail_output_blocked",
					Message:    "Response blocked by organization guardrail policy (restricted pattern matched)",
				}
			}
			return &domain.GatewayError{
				StatusCode: http.StatusBadRequest,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "guardrail_blocked_pattern",
				Message:    "Request blocked by organization guardrail policy (restricted pattern matched)",
			}
		}
	}
	return nil
}

func containsPII(text string) bool {
	return reEmail.MatchString(text) ||
		reSSN.MatchString(text) ||
		containsValidCard(text) ||
		rePhone.MatchString(text) ||
		reIPv4.MatchString(text)
}

func redactPII(text string) (string, bool) {
	orig := text
	text = reEmail.ReplaceAllString(text, "[REDACTED_EMAIL]")
	text = reSSN.ReplaceAllString(text, "[REDACTED_SSN]")
	if next, changed := redactValidCards(text); changed {
		text = next
	}
	text = rePhone.ReplaceAllString(text, "[REDACTED_PHONE]")
	text = reIPv4.ReplaceAllString(text, "[REDACTED_IP]")
	return text, text != orig
}

func evaluateLocalInputField(pol *domain.GuardrailPolicy, loggingOnly bool, field *string, outcome *CheckOutcome) error {
	if *field == "" {
		return nil
	}
	lower := strings.ToLower(*field)

	// 1. Prompt Injection Check (Unicode & whitespace normalized)
	if err := checkPromptInjection(pol, loggingOnly, *field, outcome); err != nil {
		return err
	}

	// 2. Custom Blocked Keywords
	for _, kw := range pol.BlockedKeywords {
		kwTrim := strings.TrimSpace(kw)
		if kwTrim != "" && strings.Contains(lower, strings.ToLower(kwTrim)) {
			outcome.Violations = append(outcome.Violations, "blocked_keyword:"+kwTrim)
			if loggingOnly {
				outcome.AppliedAction = domain.GuardrailActionAudit
				continue
			}
			outcome.AppliedAction = domain.GuardrailActionBlock
			return &domain.GatewayError{
				StatusCode: http.StatusBadRequest,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "guardrail_blocked_keyword",
				Message:    fmt.Sprintf("Request blocked by organization guardrail policy (restricted keyword: %q)", kwTrim),
			}
		}
	}

	// 3. Custom Blocked Regex Patterns
	if err := checkBlockedPatterns(pol, loggingOnly, *field, false, outcome); err != nil {
		return err
	}

	// 4. Built-in Toxicity & Content Filtering
	if err := evaluateToxicity(pol, loggingOnly, field, false, outcome); err != nil {
		return err
	}

	// 5. Secret / API Key Leak Check
	if pol.EnableSecretDetection && reSecret.MatchString(*field) {
		outcome.Violations = append(outcome.Violations, "secret_detected")
		action := pol.SecretAction
		if action == "" {
			action = domain.GuardrailActionRedact
		}
		if loggingOnly {
			outcome.AppliedAction = domain.GuardrailActionAudit
		} else {
			outcome.AppliedAction = action
			if action == domain.GuardrailActionBlock {
				return &domain.GatewayError{
					StatusCode: http.StatusBadRequest,
					Type:       domain.ErrorTypeInvalidRequest,
					Code:       "guardrail_secret_detected",
					Message:    "Request blocked by security guardrail: sensitive API key or credential detected in prompt",
				}
			}
			if action == domain.GuardrailActionRedact {
				*field = reSecret.ReplaceAllString(*field, "[REDACTED_SECRET]")
				outcome.Redacted = true
			}
		}
	}

	// 6. PII Detection (Emails, SSNs, Luhn-valid Credit Cards, Phone Numbers, IPv4)
	if pol.EnablePIIDetection && containsPII(*field) {
		outcome.Violations = append(outcome.Violations, "pii_detected")
		action := pol.PIIAction
		if action == "" {
			action = domain.GuardrailActionRedact
		}
		if loggingOnly {
			outcome.AppliedAction = domain.GuardrailActionAudit
		} else {
			outcome.AppliedAction = action
			if action == domain.GuardrailActionBlock {
				return &domain.GatewayError{
					StatusCode: http.StatusBadRequest,
					Type:       domain.ErrorTypeInvalidRequest,
					Code:       "guardrail_pii_detected",
					Message:    "Request blocked by security guardrail: PII (email, SSN, payment card, phone, or IP address) detected in prompt",
				}
			}
			if action == domain.GuardrailActionRedact {
				if next, changed := redactPII(*field); changed {
					*field = next
					outcome.Redacted = true
				}
			}
		}
	}

	return nil
}

// EvaluateInputWithPolicy evaluates a CanonicalChatRequest directly against an explicit GuardrailPolicy.
func (e *Engine) EvaluateInputWithPolicy(ctx context.Context, pol *domain.GuardrailPolicy, req *domain.CanonicalChatRequest) (*CheckOutcome, error) {
	outcome := &CheckOutcome{}
	if e == nil || pol == nil || req == nil {
		return outcome, nil
	}
	loggingOnly := pol.EffectiveMode() == domain.GuardrailModeLoggingOnly

	for mi := range req.Messages {
		msg := &req.Messages[mi]
		scanAll := shouldScanRole(pol, msg.Role)
		scanToolInjection := !scanAll && strings.EqualFold(strings.TrimSpace(msg.Role), "tool") && pol.EnablePromptInjection
		if !scanAll && !scanToolInjection {
			continue
		}
		for _, field := range messageTextFields(msg) {
			if *field == "" {
				continue
			}
			if scanToolInjection {
				if err := checkPromptInjection(pol, loggingOnly, *field, outcome); err != nil {
					return outcome, err
				}
				continue
			}
			if err := evaluateLocalInputField(pol, loggingOnly, field, outcome); err != nil {
				return outcome, err
			}
		}
	}

	if len(outcome.Violations) > 0 {
		logger.WarnContext(ctx, "Input guardrail violations detected",
			slog.String("component", "guardrails"),
			slog.String("org_id", pol.OrgID),
			slog.String("mode", string(pol.EffectiveMode())),
			slog.String("applied_action", string(outcome.AppliedAction)),
			slog.Bool("redacted", outcome.Redacted),
			slog.Any("violations", outcome.Violations),
		)
	}

	return outcome, nil
}

func evaluateLocalOutputField(pol *domain.GuardrailPolicy, loggingOnly bool, field *string, outcome *CheckOutcome) error {
	if *field == "" {
		return nil
	}
	lower := strings.ToLower(*field)

	// 1. Custom Blocked Keywords
	for _, kw := range pol.BlockedKeywords {
		kwTrim := strings.TrimSpace(kw)
		if kwTrim != "" && strings.Contains(lower, strings.ToLower(kwTrim)) {
			outcome.Violations = append(outcome.Violations, "blocked_keyword:"+kwTrim)
			if loggingOnly {
				outcome.AppliedAction = domain.GuardrailActionAudit
				continue
			}
			outcome.AppliedAction = domain.GuardrailActionBlock
			return &domain.GatewayError{
				StatusCode: http.StatusBadGateway,
				Type:       domain.ErrorTypeServer,
				Code:       "guardrail_output_blocked",
				Message:    fmt.Sprintf("Response blocked by organization guardrail policy (restricted keyword: %q)", kwTrim),
			}
		}
	}

	// 2. Custom Blocked Regex Patterns
	if err := checkBlockedPatterns(pol, loggingOnly, *field, true, outcome); err != nil {
		return err
	}

	// 3. Built-in Toxicity & Content Filtering
	if err := evaluateToxicity(pol, loggingOnly, field, true, outcome); err != nil {
		return err
	}

	// 4. Secret / API Key Leak Check
	if (pol.EnableSecretDetection || pol.RedactOutputPII) && reSecret.MatchString(*field) {
		outcome.Violations = append(outcome.Violations, "secret_detected")
		action := domain.GuardrailActionRedact
		if pol.EnableSecretDetection && pol.SecretAction != "" {
			action = pol.SecretAction
		}
		if pol.RedactOutputPII && action == domain.GuardrailActionAudit {
			action = domain.GuardrailActionRedact
		}
		if loggingOnly {
			outcome.AppliedAction = domain.GuardrailActionAudit
		} else {
			outcome.AppliedAction = action
			if action == domain.GuardrailActionBlock {
				return &domain.GatewayError{
					StatusCode: http.StatusBadGateway,
					Type:       domain.ErrorTypeServer,
					Code:       "guardrail_output_secret_detected",
					Message:    "Response blocked by security guardrail: sensitive API key or credential detected in output",
				}
			}
			if action == domain.GuardrailActionRedact {
				*field = reSecret.ReplaceAllString(*field, "[REDACTED_SECRET]")
				outcome.Redacted = true
			}
		}
	}

	// 5. PII Detection (Emails, SSNs, Luhn-valid Credit Cards, Phone Numbers, IPv4)
	if (pol.EnablePIIDetection || pol.RedactOutputPII) && containsPII(*field) {
		outcome.Violations = append(outcome.Violations, "pii_detected")
		action := domain.GuardrailActionRedact
		if pol.EnablePIIDetection && pol.PIIAction != "" {
			action = pol.PIIAction
		}
		if pol.RedactOutputPII && action == domain.GuardrailActionAudit {
			action = domain.GuardrailActionRedact
		}
		if loggingOnly {
			outcome.AppliedAction = domain.GuardrailActionAudit
		} else {
			outcome.AppliedAction = action
			if action == domain.GuardrailActionBlock {
				return &domain.GatewayError{
					StatusCode: http.StatusBadGateway,
					Type:       domain.ErrorTypeServer,
					Code:       "guardrail_output_pii_detected",
					Message:    "Response blocked by security guardrail: PII (email, SSN, payment card, phone, or IP address) detected in output",
				}
			}
			if action == domain.GuardrailActionRedact {
				if next, changed := redactPII(*field); changed {
					*field = next
					outcome.Redacted = true
				}
			}
		}
	}

	return nil
}

// EvaluateOutputWithPolicy evaluates and optionally redacts or blocks a CanonicalChatResponse
// against an explicit GuardrailPolicy. Callers must withhold output when this method returns an error.
func (e *Engine) EvaluateOutputWithPolicy(ctx context.Context, pol *domain.GuardrailPolicy, resp *domain.CanonicalChatResponse) (*CheckOutcome, error) {
	outcome := &CheckOutcome{}
	if e == nil || pol == nil || resp == nil {
		return outcome, nil
	}
	loggingOnly := pol.EffectiveMode() == domain.GuardrailModeLoggingOnly

	for i := range resp.Choices {
		msg := &resp.Choices[i].Message
		for _, field := range messageTextFields(msg) {
			if err := evaluateLocalOutputField(pol, loggingOnly, field, outcome); err != nil {
				return outcome, err
			}
		}
	}

	if len(outcome.Violations) > 0 {
		logger.WarnContext(ctx, "Output guardrail violations detected",
			slog.String("component", "guardrails"),
			slog.String("org_id", pol.OrgID),
			slog.String("mode", string(pol.EffectiveMode())),
			slog.String("applied_action", string(outcome.AppliedAction)),
			slog.Bool("redacted", outcome.Redacted),
			slog.Any("violations", outcome.Violations),
		)
	} else if outcome.Redacted {
		logger.WarnContext(ctx, "Output guardrail redacted sensitive content from completion", slog.String("component", "guardrails"), slog.String("org_id", pol.OrgID))
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
	if pol == nil {
		return false, nil
	}
	outcome, err := e.EvaluateOutputWithPolicy(ctx, pol, resp)
	if outcome == nil {
		return false, err
	}
	return outcome.Redacted, err
}

// SanitizeOutputStrict is retained for callers that require the policy error explicitly.
func (e *Engine) SanitizeOutputStrict(ctx context.Context, orgID string, resp *domain.CanonicalChatResponse) (bool, error) {
	return e.SanitizeOutput(ctx, orgID, resp)
}

// SanitizeTextOutput evaluates output guardrails against plain text and returns the sanitized string and redaction flag.
func (e *Engine) SanitizeTextOutput(ctx context.Context, orgID, text string) (string, bool, error) {
	pol, err := e.Policy(ctx, orgID)
	if err != nil {
		return "", false, err
	}
	if pol == nil {
		return text, false, nil
	}
	probe := &domain.CanonicalChatResponse{
		Choices: []domain.CanonicalChoice{
			{Message: domain.CanonicalMessage{Role: "assistant", Content: text}},
		},
	}
	outcome, err := e.EvaluateOutputWithPolicy(ctx, pol, probe)
	if err != nil {
		redacted := outcome != nil && outcome.Redacted
		return "", redacted, err
	}
	redacted := outcome != nil && outcome.Redacted
	return probe.Choices[0].Message.Content, redacted, nil
}

func isValidLuhn(card string) bool {
	var digits [20]int
	n := 0
	for i := 0; i < len(card); i++ {
		c := card[i]
		if c == '-' || c == ' ' {
			continue
		}
		if c < '0' || c > '9' {
			return false
		}
		if n >= len(digits) {
			return false
		}
		digits[n] = int(c - '0')
		n++
	}
	if n < 13 || n > 19 {
		return false
	}
	sum := 0
	alt := false
	for i := n - 1; i >= 0; i-- {
		d := digits[i]
		if alt {
			d *= 2
			if d > 9 {
				d -= 9
			}
		}
		sum += d
		alt = !alt
	}
	return sum%10 == 0
}

func containsValidCard(text string) bool {
	for _, match := range reCard.FindAllString(text, -1) {
		if isValidLuhn(match) {
			return true
		}
	}
	return false
}

func redactValidCards(text string) (string, bool) {
	changed := false
	updated := reCard.ReplaceAllStringFunc(text, func(match string) string {
		if isValidLuhn(match) {
			changed = true
			return "[REDACTED_CARD]"
		}
		return match
	})
	return updated, changed
}
