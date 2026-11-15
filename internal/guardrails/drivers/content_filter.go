package drivers

import (
	"context"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/guardrails"
)

type localFilterRule struct {
	name        string
	category    string
	re          *regexp.Regexp
	action      domain.GuardrailAction
	replacement string
	severity    string
}

type localFilterMatch struct {
	start       int
	end         int
	category    string
	rule        string
	severity    string
	action      domain.GuardrailAction
	replacement string
}

// LocalContentFilterDriver evaluates text in-process using configurable built-in categories
// (secrets, pii, prompt_injection, toxicity, banned_phrases), blocked wordlists, and regex rules
// with zero external network calls.
type LocalContentFilterDriver struct {
	name       string
	id         string
	action     domain.GuardrailAction
	rules      []localFilterRule
	exceptions []string
}

var builtInCategoryPatterns = map[string][]struct {
	name        string
	pattern     string
	replacement string
	severity    string
}{
	"secrets": {
		{name: "openai_key", pattern: `\bsk-[a-zA-Z0-9_\-]{12,}\b`, replacement: "[REDACTED_SECRET]", severity: "high"},
		{name: "aws_access_key", pattern: `\bAKIA[0-9A-Z]{16}\b`, replacement: "[REDACTED_SECRET]", severity: "high"},
		{name: "github_token", pattern: `\bghp_[a-zA-Z0-9]{20,}\b`, replacement: "[REDACTED_SECRET]", severity: "high"},
		{name: "slack_token", pattern: `\bxoxb-[a-zA-Z0-9\-]{10,}\b`, replacement: "[REDACTED_SECRET]", severity: "high"},
		{name: "google_api_key", pattern: `\bAIza[0-9A-Za-z\-_]{20,}\b`, replacement: "[REDACTED_SECRET]", severity: "high"},
		{name: "private_key_pem", pattern: `-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----`, replacement: "[REDACTED_PRIVATE_KEY]", severity: "high"},
	},
	"pii": {
		{name: "email", pattern: `[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`, replacement: "[REDACTED_EMAIL]", severity: "medium"},
		{name: "us_ssn", pattern: `\b\d{3}-\d{2}-\d{4}\b`, replacement: "[REDACTED_SSN]", severity: "high"},
		{name: "payment_card", pattern: `\b(?:(?:\d{4}[-\s]?){3}\d{4}|3[47]\d{2}[-\s]?\d{6}[-\s]?\d{5})\b`, replacement: "[REDACTED_CARD]", severity: "high"},
	},
	"prompt_injection": {
		{name: "ignore_previous", pattern: `(?i)\bignore\s+(?:all\s+)?(?:previous|prior)\s+instructions\b`, replacement: "[REDACTED_INJECTION]", severity: "high"},
		{name: "disregard_system", pattern: `(?i)\bdisregard\s+(?:your\s+)?system\s+prompt\b`, replacement: "[REDACTED_INJECTION]", severity: "high"},
		{name: "reveal_system", pattern: `(?i)\b(?:reveal|print)\s+your\s+system\s+(?:prompt|instructions)\b`, replacement: "[REDACTED_INJECTION]", severity: "high"},
		{name: "bypass_safety", pattern: `(?i)\bbypass\s+all\s+safety\b`, replacement: "[REDACTED_INJECTION]", severity: "high"},
	},
	"banned_phrases": {
		{name: "self_harm_instruction", pattern: `(?i)\bhow\s+to\s+build\s+a\s+bomb\b`, replacement: "[REDACTED_BANNED]", severity: "high"},
		{name: "malware_dropper", pattern: `(?i)\bdisable\s+antivirus\s+and\s+exfiltrate\b`, replacement: "[REDACTED_BANNED]", severity: "high"},
	},
}

// NewLocalContentFilterDriver constructs an in-process LocalContentFilterDriver.
// The httpClient parameter is ignored because local_content_filter performs zero network calls.
func NewLocalContentFilterDriver(cfg guardrails.DriverConfig, _ *http.Client) (guardrails.Driver, error) {
	defaultAction := effectiveAction(cfg, domain.GuardrailActionBlock)
	defaultRepl := configString(cfg, "redact_replacement", "replacement")
	if defaultRepl == "" {
		defaultRepl = "[REDACTED]"
	}
	caseSensitive := configBool(cfg, false, "case_sensitive")
	wholeWord := configBool(cfg, false, "whole_word")

	categories := configStringSlice(cfg, "categories", "enabled_categories", "enabled_content_categories")
	blockedWords := configStringSlice(cfg, "blocked_words", "keywords", "blocked_keywords")
	rawPatterns := configStringSlice(cfg, "patterns", "regexes", "blocked_patterns")
	customRulesRaw := configAnySlice(cfg, "rules")

	if len(categories) == 0 && len(blockedWords) == 0 && len(rawPatterns) == 0 && len(customRulesRaw) == 0 {
		categories = []string{"secrets", "pii", "prompt_injection"}
	}

	var rules []localFilterRule

	// 1. Built-in category packs
	for _, rawCat := range categories {
		cat := strings.ToLower(strings.TrimSpace(rawCat))
		pack, ok := builtInCategoryPatterns[cat]
		if !ok {
			continue
		}
		for _, item := range pack {
			re, err := regexp.Compile(item.pattern)
			if err != nil {
				return nil, fmt.Errorf("compile built-in category %q rule %q: %w", cat, item.name, err)
			}
			repl := item.replacement
			if repl == "" {
				repl = defaultRepl
			}
			rules = append(rules, localFilterRule{
				name:        item.name,
				category:    cat,
				re:          re,
				action:      defaultAction,
				replacement: repl,
				severity:    item.severity,
			})
		}
	}

	// 2. Blocked words / keywords
	for _, kw := range blockedWords {
		if kw == "" {
			continue
		}
		pat := regexp.QuoteMeta(kw)
		if wholeWord {
			pat = `\b` + pat + `\b`
		}
		if !caseSensitive {
			pat = `(?i)` + pat
		}
		re, err := regexp.Compile(pat)
		if err != nil {
			return nil, fmt.Errorf("compile blocked word %q: %w", kw, err)
		}
		rules = append(rules, localFilterRule{
			name:        kw,
			category:    "blocked_keyword",
			re:          re,
			action:      defaultAction,
			replacement: defaultRepl,
			severity:    "medium",
		})
	}

	// 3. Raw regex patterns
	for i, pat := range rawPatterns {
		if pat == "" {
			continue
		}
		if !caseSensitive && !strings.HasPrefix(pat, "(?i)") {
			pat = "(?i)" + pat
		}
		re, err := regexp.Compile(pat)
		if err != nil {
			return nil, fmt.Errorf("compile pattern[%d] %q: %w", i, pat, err)
		}
		rules = append(rules, localFilterRule{
			name:        fmt.Sprintf("pattern_%d", i),
			category:    "custom_pattern",
			re:          re,
			action:      defaultAction,
			replacement: defaultRepl,
			severity:    "medium",
		})
	}

	// 4. Structured custom rules
	for i, item := range customRulesRaw {
		ruleMap, ok := item.(map[string]any)
		if !ok {
			continue
		}
		ruleName := stringFromAny(ruleMap["name"])
		cat := stringFromAny(ruleMap["category"])
		if cat == "" {
			cat = "custom_rule"
		}
		pat := stringFromAny(ruleMap["pattern"])
		if pat == "" {
			if kw := stringFromAny(ruleMap["keyword"]); kw != "" {
				pat = regexp.QuoteMeta(kw)
				if b, ok := boolFromAny(ruleMap["whole_word"]); ok && b {
					pat = `\b` + pat + `\b`
				} else if wholeWord {
					pat = `\b` + pat + `\b`
				}
				if ruleName == "" {
					ruleName = kw
				}
			}
		}
		if pat == "" {
			continue
		}
		cs := caseSensitive
		if b, ok := boolFromAny(ruleMap["case_sensitive"]); ok {
			cs = b
		}
		if !cs && !strings.HasPrefix(pat, "(?i)") {
			pat = "(?i)" + pat
		}
		re, err := regexp.Compile(pat)
		if err != nil {
			return nil, fmt.Errorf("compile custom rule[%d] %q: %w", i, ruleName, err)
		}
		if ruleName == "" {
			ruleName = fmt.Sprintf("rule_%d", i)
		}
		act := normalizeActionString(stringFromAny(ruleMap["action"]))
		if act == "" {
			act = defaultAction
		}
		repl := stringFromAny(ruleMap["replacement"])
		if repl == "" {
			repl = defaultRepl
		}
		sev := stringFromAny(ruleMap["severity"])
		if sev == "" {
			sev = "medium"
		}
		rules = append(rules, localFilterRule{
			name:        ruleName,
			category:    cat,
			re:          re,
			action:      act,
			replacement: repl,
			severity:    sev,
		})
	}

	rawExceptions := configStringSlice(cfg, "exceptions", "allowlist", "content_exceptions")
	exceptions := make([]string, 0, len(rawExceptions))
	for _, exc := range rawExceptions {
		if lower := strings.ToLower(strings.TrimSpace(exc)); lower != "" {
			exceptions = append(exceptions, lower)
		}
	}

	return &LocalContentFilterDriver{
		name:       guardrailName(cfg, ProviderLocalContentFilter),
		id:         guardrailID(cfg),
		action:     defaultAction,
		rules:      rules,
		exceptions: exceptions,
	}, nil
}

func configAnySlice(cfg guardrails.DriverConfig, keys ...string) []any {
	cm := configMap(cfg)
	for _, key := range keys {
		if raw, ok := lookupAnyCaseInsensitive(cm, key); ok {
			if s, ok := raw.([]any); ok {
				return s
			}
		}
	}
	return nil
}

func (d *LocalContentFilterDriver) Name() string {
	return d.name
}

func (d *LocalContentFilterDriver) SupportedHooks() []domain.GuardrailHook {
	return defaultTextHooks()
}

func (d *LocalContentFilterDriver) Evaluate(_ context.Context, input *domain.GuardrailEvalInput) (*domain.GuardrailEvalResult, error) {
	texts := extractTexts(input)
	if !hasNonEmptyText(texts) || len(d.rules) == 0 {
		return &domain.GuardrailEvalResult{
			Decision:          domain.GuardrailDecisionAllow,
			AppliedGuardrails: []string{d.name},
		}, nil
	}

	modified := make([]string, len(texts))
	copy(modified, texts)

	var violations []domain.GuardrailViolation
	hasBlock := false
	hasRedact := false

	for idx, text := range texts {
		if text == "" {
			continue
		}
		excSpans := findLocalExceptionSpans(text, d.exceptions)
		var matches []localFilterMatch

		for _, rule := range d.rules {
			locs := rule.re.FindAllStringIndex(text, -1)
			for _, loc := range locs {
				start, end := loc[0], loc[1]
				if end <= start {
					continue
				}
				if isWithinLocalSpans(start, end, excSpans) {
					continue
				}
				matches = append(matches, localFilterMatch{
					start:       start,
					end:         end,
					category:    rule.category,
					rule:        rule.name,
					severity:    rule.severity,
					action:      rule.action,
					replacement: rule.replacement,
				})
				if rule.action == domain.GuardrailActionBlock {
					hasBlock = true
				} else if rule.action == domain.GuardrailActionRedact {
					hasRedact = true
				}
				violations = append(violations, domain.GuardrailViolation{
					GuardrailName: d.name,
					GuardrailID:   d.id,
					Provider:      ProviderLocalContentFilter,
					Category:      rule.category,
					Rule:          rule.name,
					Severity:      rule.severity,
					Action:        rule.action,
					Message:       fmt.Sprintf("Local content filter matched %s:%s", rule.category, rule.name),
				})
			}
		}

		if len(matches) > 0 && !hasBlock && hasRedact {
			modified[idx] = applyLocalRedactions(text, matches)
		}
	}

	if len(violations) == 0 {
		return &domain.GuardrailEvalResult{
			Decision:          domain.GuardrailDecisionAllow,
			AppliedGuardrails: []string{d.name},
			UsageUnits:        1,
		}, nil
	}

	decision := domain.GuardrailDecisionFlag
	switch {
	case hasBlock:
		decision = domain.GuardrailDecisionBlock
	case hasRedact:
		decision = domain.GuardrailDecisionModify
	}

	for i := range violations {
		violations[i].Decision = decision
	}

	res := &domain.GuardrailEvalResult{
		Decision:          decision,
		Violations:        violations,
		AppliedGuardrails: []string{d.name},
		UsageUnits:        1,
		ErrorMessage:      violations[0].Message,
	}
	if decision == domain.GuardrailDecisionModify {
		res.ModifiedTexts = modified
	}
	return res, nil
}

type localByteSpan struct {
	start int
	end   int
}

func findLocalExceptionSpans(text string, exceptions []string) []localByteSpan {
	if len(exceptions) == 0 || text == "" {
		return nil
	}
	lower := strings.ToLower(text)
	if len(lower) != len(text) {
		return nil
	}
	var spans []localByteSpan
	for _, exc := range exceptions {
		offset := 0
		for offset < len(lower) {
			idx := strings.Index(lower[offset:], exc)
			if idx < 0 {
				break
			}
			s := offset + idx
			spans = append(spans, localByteSpan{start: s, end: s + len(exc)})
			offset = s + 1
		}
	}
	return spans
}

func isWithinLocalSpans(start, end int, spans []localByteSpan) bool {
	for _, sp := range spans {
		if start >= sp.start && end <= sp.end {
			return true
		}
	}
	return false
}

func applyLocalRedactions(text string, matches []localFilterMatch) string {
	var redactMatches []localFilterMatch
	for _, m := range matches {
		if m.action == domain.GuardrailActionRedact {
			redactMatches = append(redactMatches, m)
		}
	}
	if len(redactMatches) == 0 {
		return text
	}

	sort.Slice(redactMatches, func(i, j int) bool {
		if redactMatches[i].start != redactMatches[j].start {
			return redactMatches[i].start < redactMatches[j].start
		}
		return redactMatches[i].end > redactMatches[j].end
	})

	var nonOverlapping []localFilterMatch
	for _, m := range redactMatches {
		if len(nonOverlapping) > 0 && m.start < nonOverlapping[len(nonOverlapping)-1].end {
			continue
		}
		nonOverlapping = append(nonOverlapping, m)
	}

	var b strings.Builder
	cursor := 0
	for _, m := range nonOverlapping {
		if m.start > cursor {
			b.WriteString(text[cursor:m.start])
		}
		b.WriteString(m.replacement)
		cursor = m.end
	}
	if cursor < len(text) {
		b.WriteString(text[cursor:])
	}
	return b.String()
}
