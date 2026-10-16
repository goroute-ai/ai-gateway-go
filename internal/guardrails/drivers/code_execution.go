package drivers

import (
	"context"
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/guardrails"
)

const (
	// ProviderCodeExecution is the guardrail provider identifier for blocking or stripping
	// unsafe code-execution tool calls and optional fenced executable code blocks.
	ProviderCodeExecution = "block_code_execution"

	defaultCodeStripReplacement = "[CODE_EXECUTION_STRIPPED]"
)

var defaultBlockedCodeTools = []string{
	"bash",
	"shell",
	"sh",
	"python",
	"python_exec",
	"node",
	"exec",
	"eval",
	"run_command",
	"code_interpreter",
	"computer",
}

var defaultExecutableFencedLangs = []string{
	"bash",
	"sh",
	"shell",
	"zsh",
	"python",
	"python3",
	"py",
	"node",
	"js",
	"javascript",
	"ts",
	"typescript",
	"powershell",
	"ps1",
	"cmd",
	"bat",
	"ruby",
	"perl",
	"php",
	"exec",
	"eval",
}

// CodeExecutionDriver blocks, strips, or flags unsafe code-execution tool calls
// and optional fenced executable code blocks across pre_call, post_call, and pre_mcp_call.
type CodeExecutionDriver struct {
	guardrailName       string
	action              string // "block", "strip", "flag"
	blockedExact        map[string]struct{}
	blockedGlobs        []string
	blockedRegexes      []*regexp.Regexp
	allowedPatterns     []string
	detectFencedCode    bool
	detectAllFencedCode bool
	fencedRegex         *regexp.Regexp
	checkDeclaredTools  bool
	stripReplacement    string
}

// NewCodeExecutionDriver constructs a CodeExecutionDriver from resolved guardrail config.
func NewCodeExecutionDriver(cfg guardrails.DriverConfig) (*CodeExecutionDriver, error) {
	action, err := resolveDriverAction(cfg, "block", true)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ProviderCodeExecution, err)
	}

	d := &CodeExecutionDriver{
		guardrailName:      definitionName(cfg, ProviderCodeExecution),
		action:             action,
		blockedExact:       make(map[string]struct{}),
		checkDeclaredTools: true,
		stripReplacement:   defaultCodeStripReplacement,
	}

	rawCfg := cfg.EffectiveConfig
	replaceDefaults := boolFromAnyOrDefault(rawCfg["replace_default_tools"], false)
	if !replaceDefaults {
		for _, name := range defaultBlockedCodeTools {
			d.addBlockedToolPattern(name)
		}
	}

	for _, name := range execStringSliceFromAny(rawCfg["blocked_tools"]) {
		d.addBlockedToolPattern(name)
	}
	for _, rawPattern := range execStringSliceFromAny(rawCfg["blocked_patterns"]) {
		trimmed := strings.TrimSpace(rawPattern)
		if trimmed == "" {
			continue
		}
		re, err := regexp.Compile("(?i)" + trimmed)
		if err != nil {
			return nil, fmt.Errorf("%s: invalid blocked_patterns regex %q: %w", ProviderCodeExecution, rawPattern, err)
		}
		d.blockedRegexes = append(d.blockedRegexes, re)
	}
	for _, allowed := range execStringSliceFromAny(rawCfg["allowed_tools"]) {
		norm := strings.ToLower(strings.TrimSpace(allowed))
		if norm != "" {
			d.allowedPatterns = append(d.allowedPatterns, norm)
		}
	}

	if v, ok := rawCfg["check_declared_tools"]; ok {
		d.checkDeclaredTools = boolFromAnyOrDefault(v, true)
	}
	if repl, ok := rawCfg["strip_replacement"].(string); ok && repl != "" {
		d.stripReplacement = repl
	}

	d.detectFencedCode = boolFromAnyOrDefault(rawCfg["detect_fenced_code"], false)
	d.detectAllFencedCode = boolFromAnyOrDefault(rawCfg["detect_all_fenced_code"], false)
	if d.detectFencedCode {
		if d.detectAllFencedCode {
			d.fencedRegex = regexp.MustCompile("(?is)```[^\\n]*\\n[\\s\\S]*?```")
		} else {
			langs := append([]string(nil), defaultExecutableFencedLangs...)
			for _, extra := range execStringSliceFromAny(rawCfg["fenced_languages"]) {
				norm := strings.ToLower(strings.TrimSpace(extra))
				if norm != "" {
					langs = append(langs, regexp.QuoteMeta(norm))
				}
			}
			pattern := fmt.Sprintf("(?is)```\\s*(?:%s)\\b[^\\n]*(?:\\n[\\s\\S]*?|\\s+[^`\\n]*)```", strings.Join(langs, "|"))
			re, err := regexp.Compile(pattern)
			if err != nil {
				return nil, fmt.Errorf("%s: compile fenced code regex: %w", ProviderCodeExecution, err)
			}
			d.fencedRegex = re
		}
	}

	return d, nil
}

func (d *CodeExecutionDriver) addBlockedToolPattern(raw string) {
	norm := strings.ToLower(strings.TrimSpace(raw))
	if norm == "" {
		return
	}
	if strings.ContainsAny(norm, "*?[") {
		d.blockedGlobs = append(d.blockedGlobs, norm)
		return
	}
	d.blockedExact[norm] = struct{}{}
}

// Name returns the provider identifier for this driver.
func (d *CodeExecutionDriver) Name() string {
	return ProviderCodeExecution
}

// SupportedHooks returns the lifecycle hooks evaluated by CodeExecutionDriver.
func (d *CodeExecutionDriver) SupportedHooks() []domain.GuardrailHook {
	return []domain.GuardrailHook{
		domain.GuardrailHookPreCall,
		domain.GuardrailHookPostCall,
		domain.GuardrailHookPreMCPCall,
	}
}

// Evaluate inspects tool declarations, tool calls, MCP invocations, and optional fenced code blocks.
func (d *CodeExecutionDriver) Evaluate(ctx context.Context, input *domain.GuardrailEvalInput) (*domain.GuardrailEvalResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if input == nil {
		return &domain.GuardrailEvalResult{Decision: domain.GuardrailDecisionAllow}, nil
	}

	var violations []domain.GuardrailViolation
	seenToolCallViolation := make(map[string]struct{})
	addViolation := func(rule, msg string, details map[string]any) {
		violations = append(violations, domain.GuardrailViolation{
			GuardrailName: d.guardrailName,
			Provider:      ProviderCodeExecution,
			Category:      "code_execution",
			Rule:          rule,
			Severity:      "high",
			Message:       msg,
			Action:        d.mappedDomainAction(),
			Details:       details,
		})
	}

	// 1. Check declared tools (e.g., code_interpreter, computer, or function names matching blocked list).
	if d.checkDeclaredTools {
		for _, tool := range input.Tools {
			if tool.Type != "" && !strings.EqualFold(tool.Type, "function") && d.isBlockedToolName(tool.Type) {
				addViolation("blocked_tool_declaration",
					fmt.Sprintf("Code-execution tool type %q is not permitted", tool.Type),
					map[string]any{"tool_type": tool.Type, "tool_name": tool.Function.Name},
				)
			}
			if tool.Function.Name != "" && d.isBlockedToolName(tool.Function.Name) {
				addViolation("blocked_tool_declaration",
					fmt.Sprintf("Code-execution tool %q is not permitted", tool.Function.Name),
					map[string]any{"tool_name": tool.Function.Name},
				)
			}
		}
	}

	// 2. Check ToolCalls and StructuredMessages tool calls.
	var remainingTopLevelToolCalls []domain.CanonicalToolCall
	topLevelModified := false
	for _, tc := range input.ToolCalls {
		if d.isBlockedToolName(tc.Function.Name) {
			key := "tc:" + strings.ToLower(strings.TrimSpace(tc.Function.Name)) + ":" + tc.ID
			if _, ok := seenToolCallViolation[key]; !ok {
				seenToolCallViolation[key] = struct{}{}
				addViolation("blocked_code_execution_tool",
					fmt.Sprintf("Code-execution tool call %q is not permitted", tc.Function.Name),
					map[string]any{"tool_name": tc.Function.Name, "tool_call_id": tc.ID},
				)
			}
			topLevelModified = true
			continue
		}
		remainingTopLevelToolCalls = append(remainingTopLevelToolCalls, cloneDriverToolCall(tc))
	}

	var modifiedMessages []domain.CanonicalMessage
	messagesModified := false
	if len(input.StructuredMessages) > 0 {
		modifiedMessages = make([]domain.CanonicalMessage, len(input.StructuredMessages))
		for i, msg := range input.StructuredMessages {
			cp := cloneDriverMessage(msg)
			if len(msg.ToolCalls) > 0 {
				var kept []domain.CanonicalToolCall
				for _, tc := range msg.ToolCalls {
					if d.isBlockedToolName(tc.Function.Name) {
						key := "tc:" + strings.ToLower(strings.TrimSpace(tc.Function.Name)) + ":" + tc.ID
						if _, ok := seenToolCallViolation[key]; !ok {
							seenToolCallViolation[key] = struct{}{}
							addViolation("blocked_code_execution_tool",
								fmt.Sprintf("Code-execution tool call %q is not permitted", tc.Function.Name),
								map[string]any{"tool_name": tc.Function.Name, "tool_call_id": tc.ID},
							)
						}
						messagesModified = true
						continue
					}
					kept = append(kept, cloneDriverToolCall(tc))
				}
				cp.ToolCalls = kept
			}

			if d.detectFencedCode && d.fencedRegex != nil {
				if cp.Content != "" && d.fencedRegex.MatchString(cp.Content) {
					addViolation("fenced_code_block",
						"Executable fenced code block detected in message content",
						map[string]any{"message_index": i, "role": cp.Role},
					)
					cp.Content = d.fencedRegex.ReplaceAllString(cp.Content, d.stripReplacement)
					messagesModified = true
				}
				for j := range cp.Parts {
					if cp.Parts[j].Type == "text" && cp.Parts[j].Text != "" && d.fencedRegex.MatchString(cp.Parts[j].Text) {
						if cp.Content == "" {
							addViolation("fenced_code_block",
								"Executable fenced code block detected in message content part",
								map[string]any{"message_index": i, "part_index": j},
							)
						}
						cp.Parts[j].Text = d.fencedRegex.ReplaceAllString(cp.Parts[j].Text, d.stripReplacement)
						messagesModified = true
					}
				}
			}
			modifiedMessages[i] = cp
		}
	}

	// 3. Check MCP metadata tool name if not already covered by input.ToolCalls.
	if metaTool := extractStringFromMetadata(input.Metadata, "mcp_tool_name", "tool_name"); metaTool != "" && len(input.ToolCalls) == 0 {
		if d.isBlockedToolName(metaTool) {
			addViolation("blocked_code_execution_tool",
				fmt.Sprintf("Code-execution MCP tool %q is not permitted", metaTool),
				map[string]any{"tool_name": metaTool},
			)
		}
	}

	// 4. Check input.Texts for fenced code blocks if not already flagged via StructuredMessages (or when StructuredMessages is absent).
	var modifiedTexts []string
	textsModified := false
	if d.detectFencedCode && d.fencedRegex != nil && len(input.Texts) > 0 {
		modifiedTexts = make([]string, len(input.Texts))
		for i, txt := range input.Texts {
			if txt != "" && d.fencedRegex.MatchString(txt) {
				if len(input.StructuredMessages) == 0 {
					addViolation("fenced_code_block",
						"Executable fenced code block detected in text payload",
						map[string]any{"text_index": i},
					)
				}
				modifiedTexts[i] = d.fencedRegex.ReplaceAllString(txt, d.stripReplacement)
				textsModified = true
				continue
			}
			modifiedTexts[i] = txt
		}
	}

	if len(violations) == 0 {
		return &domain.GuardrailEvalResult{
			Decision:          domain.GuardrailDecisionAllow,
			AppliedGuardrails: []string{d.guardrailName},
		}, nil
	}

	switch d.action {
	case "flag":
		return &domain.GuardrailEvalResult{
			Decision:          domain.GuardrailDecisionFlag,
			Violations:        violations,
			AppliedGuardrails: []string{d.guardrailName},
		}, nil

	case "strip":
		if messagesModified || textsModified || topLevelModified {
			res := &domain.GuardrailEvalResult{
				Decision:          domain.GuardrailDecisionModify,
				Violations:        violations,
				AppliedGuardrails: []string{d.guardrailName},
			}
			if textsModified {
				res.ModifiedTexts = modifiedTexts
			}
			if messagesModified {
				res.ModifiedMessages = modifiedMessages
			}
			if topLevelModified && (len(input.StructuredMessages) == 0 || len(remainingTopLevelToolCalls) > 0) {
				res.ModifiedToolCalls = remainingTopLevelToolCalls
			}
			return res, nil
		}
		// Direct pre_mcp_call invocation or tool-only declaration cannot strip a single call in-place; block fail-closed.
		if input.Hook == domain.GuardrailHookPreMCPCall {
			return &domain.GuardrailEvalResult{
				Decision:          domain.GuardrailDecisionBlock,
				Violations:        violations,
				AppliedGuardrails: []string{d.guardrailName},
				ErrorMessage:      violations[0].Message,
			}, nil
		}
		return &domain.GuardrailEvalResult{
			Decision:          domain.GuardrailDecisionFlag,
			Violations:        violations,
			AppliedGuardrails: []string{d.guardrailName},
		}, nil

	default:
		return &domain.GuardrailEvalResult{
			Decision:          domain.GuardrailDecisionBlock,
			Violations:        violations,
			AppliedGuardrails: []string{d.guardrailName},
			ErrorMessage:      violations[0].Message,
		}, nil
	}
}

func (d *CodeExecutionDriver) isBlockedToolName(name string) bool {
	norm := strings.ToLower(strings.TrimSpace(name))
	if norm == "" {
		return false
	}
	for _, allowPat := range d.allowedPatterns {
		if matchGlobPattern(allowPat, norm) {
			return false
		}
	}
	if _, ok := d.blockedExact[norm]; ok {
		return true
	}
	for _, globPat := range d.blockedGlobs {
		if matchGlobPattern(globPat, norm) {
			return true
		}
	}
	for _, re := range d.blockedRegexes {
		if re.MatchString(norm) {
			return true
		}
	}
	return false
}

func (d *CodeExecutionDriver) mappedDomainAction() domain.GuardrailAction {
	switch d.action {
	case "strip":
		return domain.GuardrailActionRedact
	case "flag":
		return domain.GuardrailActionAudit
	default:
		return domain.GuardrailActionBlock
	}
}

func resolveDriverAction(cfg guardrails.DriverConfig, defaultAction string, allowStrip bool) (string, error) {
	if cfg.EffectiveAction != "" {
		switch cfg.EffectiveAction {
		case domain.GuardrailActionBlock:
			return "block", nil
		case domain.GuardrailActionAudit:
			return "flag", nil
		case domain.GuardrailActionRedact:
			if allowStrip {
				return "strip", nil
			}
			return "", fmt.Errorf("unsupported action %q", cfg.EffectiveAction)
		}
	}

	rawAction, _ := cfg.EffectiveConfig["action"].(string)
	norm := strings.ToLower(strings.TrimSpace(rawAction))
	if norm == "" {
		return defaultAction, nil
	}
	switch norm {
	case "block", "deny":
		return "block", nil
	case "flag", "audit", "log":
		return "flag", nil
	case "strip", "redact", "modify":
		if allowStrip {
			return "strip", nil
		}
		return "", fmt.Errorf("unsupported action %q", rawAction)
	default:
		return "", fmt.Errorf("unsupported action %q", rawAction)
	}
}

func definitionName(cfg guardrails.DriverConfig, fallback string) string {
	if cfg.Definition != nil && strings.TrimSpace(cfg.Definition.Name) != "" {
		return strings.TrimSpace(cfg.Definition.Name)
	}
	return fallback
}

func matchGlobPattern(pattern, value string) bool {
	if pattern == "*" {
		return true
	}
	if !strings.ContainsAny(pattern, "*?[") {
		return pattern == value
	}
	matched, err := path.Match(pattern, value)
	if err != nil {
		return pattern == value
	}
	return matched
}

func execStringSliceFromAny(v any) []string {
	switch typed := v.(type) {
	case []string:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			if s := strings.TrimSpace(item); s != "" {
				out = append(out, s)
			}
		}
		return out
	case []any:
		out := make([]string, 0, len(typed))
		for _, item := range typed {
			if s, ok := item.(string); ok {
				if trimmed := strings.TrimSpace(s); trimmed != "" {
					out = append(out, trimmed)
				}
			}
		}
		return out
	case string:
		if trimmed := strings.TrimSpace(typed); trimmed != "" {
			return []string{trimmed}
		}
	}
	return nil
}

func boolFromAnyOrDefault(v any, fallback bool) bool {
	if b, ok := v.(bool); ok {
		return b
	}
	return fallback
}

func extractStringFromMetadata(meta map[string]any, keys ...string) string {
	if len(meta) == 0 {
		return ""
	}
	for _, k := range keys {
		if v, ok := meta[k].(string); ok && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func cloneDriverMessage(m domain.CanonicalMessage) domain.CanonicalMessage {
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
	if m.ToolCalls != nil {
		cp.ToolCalls = make([]domain.CanonicalToolCall, len(m.ToolCalls))
		for i, tc := range m.ToolCalls {
			cp.ToolCalls[i] = cloneDriverToolCall(tc)
		}
	}
	if m.Annotations != nil {
		cp.Annotations = append([]domain.Annotation(nil), m.Annotations...)
	}
	return cp
}

func cloneDriverToolCall(tc domain.CanonicalToolCall) domain.CanonicalToolCall {
	cp := tc
	if tc.Index != nil {
		idx := *tc.Index
		cp.Index = &idx
	}
	return cp
}
