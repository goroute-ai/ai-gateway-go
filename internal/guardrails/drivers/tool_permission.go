package drivers

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/guardrails"
)

const ProviderToolPermission = "tool_permission"

// ToolPermissionAction specifies whether a matched rule allows or denies a tool.
type ToolPermissionAction string

const (
	ToolPermissionAllow ToolPermissionAction = "allow"
	ToolPermissionDeny  ToolPermissionAction = "deny"
)

// ToolPermissionViolationMode determines how denied tools or tool calls are handled.
type ToolPermissionViolationMode string

const (
	ToolPermissionViolationBlock ToolPermissionViolationMode = "block"
	ToolPermissionViolationStrip ToolPermissionViolationMode = "strip"
	ToolPermissionViolationAudit ToolPermissionViolationMode = "audit"
)

// ArgRegexMap accepts either a map of argument-key -> regex or a single raw-JSON regex string.
type ArgRegexMap map[string]string

// UnmarshalJSON decodes either a JSON object (`{"arg": "regex"}`) or a single string (`"regex"` -> key `"*"`).
func (m *ArgRegexMap) UnmarshalJSON(data []byte) error {
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" || trimmed == "null" {
		*m = nil
		return nil
	}
	if strings.HasPrefix(trimmed, "\"") {
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return err
		}
		if s == "" {
			*m = nil
			return nil
		}
		*m = ArgRegexMap{"*": s}
		return nil
	}
	var obj map[string]string
	if err := json.Unmarshal(data, &obj); err != nil {
		return err
	}
	*m = ArgRegexMap(obj)
	return nil
}

// ToolPermissionRule defines an ordered allow/deny rule matching tool declarations and invocations.
type ToolPermissionRule struct {
	ID              string               `json:"id,omitempty"`
	NamePattern     string               `json:"name_pattern,omitempty"`
	ToolName        string               `json:"tool_name,omitempty"`
	ToolType        string               `json:"tool_type,omitempty"`
	AllowedArgRegex ArgRegexMap          `json:"allowed_arg_regex,omitempty"`
	BlockedArgRegex ArgRegexMap          `json:"blocked_arg_regex,omitempty"`
	Action          ToolPermissionAction `json:"action"`
	Description     string               `json:"description,omitempty"`
}

type toolPermissionConfig struct {
	Rules           []ToolPermissionRule        `json:"rules,omitempty"`
	DefaultAction   ToolPermissionAction        `json:"default_action,omitempty"`
	OnViolation     ToolPermissionViolationMode `json:"on_violation,omitempty"`
	ViolationAct    ToolPermissionViolationMode `json:"violation_action,omitempty"`
	StripDisallowed bool                        `json:"strip_disallowed,omitempty"`
}

type compiledRule struct {
	raw             ToolPermissionRule
	label           string
	nameRegex       *regexp.Regexp
	toolType        string
	allowedArgRegex map[string]*regexp.Regexp
	blockedArgRegex map[string]*regexp.Regexp
	action          ToolPermissionAction
}

// ToolPermissionDriver enforces ordered allow/deny permission rules over declared tools,
// tool_choice directives, emitted tool_calls, and streaming tool deltas.
type ToolPermissionDriver struct {
	guardrailName string
	guardrailID   string
	hooks         []domain.GuardrailHook
	rules         []compiledRule
	defaultAction ToolPermissionAction
	violationMode ToolPermissionViolationMode
}

// NewToolPermissionDriver constructs a ToolPermissionDriver from DriverConfig.
func NewToolPermissionDriver(cfg guardrails.DriverConfig) (*ToolPermissionDriver, error) {
	var parsed toolPermissionConfig
	if len(cfg.EffectiveConfig) > 0 {
		rawBytes, err := json.Marshal(cfg.EffectiveConfig)
		if err != nil {
			return nil, fmt.Errorf("marshal tool_permission config: %w", err)
		}
		if err := json.Unmarshal(rawBytes, &parsed); err != nil {
			return nil, fmt.Errorf("decode tool_permission config: %w", err)
		}
	}

	defaultAct := ToolPermissionAction(strings.ToLower(strings.TrimSpace(string(parsed.DefaultAction))))
	if defaultAct == "" {
		defaultAct = ToolPermissionAllow
	}
	if defaultAct != ToolPermissionAllow && defaultAct != ToolPermissionDeny {
		return nil, fmt.Errorf("invalid tool_permission default_action %q: must be allow or deny", defaultAct)
	}

	violationMode := determineViolationMode(parsed, cfg.EffectiveAction)

	compiled := make([]compiledRule, 0, len(parsed.Rules))
	for i, rule := range parsed.Rules {
		cr, err := compilePermissionRule(i, rule)
		if err != nil {
			return nil, err
		}
		compiled = append(compiled, cr)
	}

	name := ProviderToolPermission
	var id string
	var hooks []domain.GuardrailHook
	if cfg.Definition != nil {
		if strings.TrimSpace(cfg.Definition.Name) != "" {
			name = cfg.Definition.Name
		}
		id = cfg.Definition.ID
		hooks = slices.Clone(cfg.Definition.EventHooks)
	}

	return &ToolPermissionDriver{
		guardrailName: name,
		guardrailID:   id,
		hooks:         hooks,
		rules:         compiled,
		defaultAction: defaultAct,
		violationMode: violationMode,
	}, nil
}

func determineViolationMode(parsed toolPermissionConfig, effectiveAction domain.GuardrailAction) ToolPermissionViolationMode {
	modeStr := strings.ToLower(strings.TrimSpace(string(parsed.OnViolation)))
	if modeStr == "" {
		modeStr = strings.ToLower(strings.TrimSpace(string(parsed.ViolationAct)))
	}
	if modeStr == "" && parsed.StripDisallowed {
		modeStr = string(ToolPermissionViolationStrip)
	}
	switch modeStr {
	case "strip", "modify":
		return ToolPermissionViolationStrip
	case "audit", "flag":
		return ToolPermissionViolationAudit
	case "block":
		return ToolPermissionViolationBlock
	}
	switch effectiveAction {
	case domain.GuardrailActionRedact:
		return ToolPermissionViolationStrip
	case domain.GuardrailActionAudit:
		return ToolPermissionViolationAudit
	default:
		return ToolPermissionViolationBlock
	}
}

func compilePermissionRule(idx int, rule ToolPermissionRule) (compiledRule, error) {
	act := ToolPermissionAction(strings.ToLower(strings.TrimSpace(string(rule.Action))))
	if act == "" {
		if len(rule.BlockedArgRegex) > 0 && len(rule.AllowedArgRegex) == 0 {
			act = ToolPermissionDeny
		} else {
			act = ToolPermissionAllow
		}
	}
	if act != ToolPermissionAllow && act != ToolPermissionDeny {
		return compiledRule{}, fmt.Errorf("tool_permission rule %d: invalid action %q", idx, rule.Action)
	}

	pat := strings.TrimSpace(rule.NamePattern)
	if pat == "" {
		pat = strings.TrimSpace(rule.ToolName)
	}
	nameRe, err := compileToolNamePattern(pat)
	if err != nil {
		return compiledRule{}, fmt.Errorf("tool_permission rule %d: invalid name_pattern %q: %w", idx, pat, err)
	}

	allowedRes, err := compileArgRegexMap(idx, "allowed_arg_regex", rule.AllowedArgRegex)
	if err != nil {
		return compiledRule{}, err
	}
	blockedRes, err := compileArgRegexMap(idx, "blocked_arg_regex", rule.BlockedArgRegex)
	if err != nil {
		return compiledRule{}, err
	}

	label := strings.TrimSpace(rule.ID)
	if label == "" {
		if pat != "" {
			label = pat
		} else {
			label = fmt.Sprintf("rule_%d", idx)
		}
	}

	return compiledRule{
		raw:             rule,
		label:           label,
		nameRegex:       nameRe,
		toolType:        strings.ToLower(strings.TrimSpace(rule.ToolType)),
		allowedArgRegex: allowedRes,
		blockedArgRegex: blockedRes,
		action:          act,
	}, nil
}

func compileToolNamePattern(pattern string) (*regexp.Regexp, error) {
	if pattern == "" || pattern == "*" {
		return nil, nil
	}
	if strings.HasPrefix(pattern, "regex:") {
		return regexp.Compile(strings.TrimPrefix(pattern, "regex:"))
	}
	if strings.HasPrefix(pattern, "re:") {
		return regexp.Compile(strings.TrimPrefix(pattern, "re:"))
	}
	if len(pattern) >= 2 && strings.HasPrefix(pattern, "/") && strings.HasSuffix(pattern, "/") {
		return regexp.Compile(pattern[1 : len(pattern)-1])
	}
	if strings.HasPrefix(pattern, "^") || strings.HasSuffix(pattern, "$") ||
		strings.ContainsAny(pattern, "()[]+|{}\\") {
		return regexp.Compile(pattern)
	}

	// Glob pattern: * -> .*, ? -> .
	var b strings.Builder
	b.WriteByte('^')
	for i := 0; i < len(pattern); i++ {
		switch pattern[i] {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteByte('.')
		default:
			b.WriteString(regexp.QuoteMeta(pattern[i : i+1]))
		}
	}
	b.WriteByte('$')
	return regexp.Compile(b.String())
}

func compileArgRegexMap(ruleIdx int, field string, m ArgRegexMap) (map[string]*regexp.Regexp, error) {
	if len(m) == 0 {
		return nil, nil
	}
	out := make(map[string]*regexp.Regexp, len(m))
	for k, expr := range m {
		if strings.TrimSpace(expr) == "" {
			continue
		}
		re, err := regexp.Compile(expr)
		if err != nil {
			return nil, fmt.Errorf("tool_permission rule %d %s[%q]: %w", ruleIdx, field, k, err)
		}
		out[k] = re
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

func (d *ToolPermissionDriver) Name() string {
	if d != nil && d.guardrailName != "" {
		return d.guardrailName
	}
	return ProviderToolPermission
}

func (d *ToolPermissionDriver) SupportedHooks() []domain.GuardrailHook {
	if d != nil && len(d.hooks) > 0 {
		return slices.Clone(d.hooks)
	}
	return []domain.GuardrailHook{
		domain.GuardrailHookPreCall,
		domain.GuardrailHookDuringCall,
		domain.GuardrailHookPostCall,
		domain.GuardrailHookLoggingOnly,
		domain.GuardrailHookPreMCPCall,
	}
}

type ruleEvalOutcome struct {
	allowed bool
	rule    string
	reason  string
}

func (d *ToolPermissionDriver) evaluateTool(toolName, toolType string, hasArgs bool, rawArgs string) ruleEvalOutcome {
	normType := strings.ToLower(strings.TrimSpace(toolType))
	if normType == "" {
		normType = "function"
	}

	var argsMap map[string]any
	var argsParsed bool
	if hasArgs && strings.TrimSpace(rawArgs) != "" {
		if err := json.Unmarshal([]byte(rawArgs), &argsMap); err == nil && argsMap != nil {
			argsParsed = true
		}
	}

	var failedAllowConstraint string

	for _, rule := range d.rules {
		if rule.toolType != "" && rule.toolType != "*" && rule.toolType != normType {
			continue
		}
		if rule.nameRegex != nil && !rule.nameRegex.MatchString(toolName) {
			continue
		}

		// When evaluating a tool declaration (no arguments), argument-scoped rules cannot block
		// on missing arguments, though allow rules with allowed_arg_regex permit declaration
		// so that individual invocations are checked at call time.
		if !hasArgs {
			if len(rule.blockedArgRegex) > 0 && rule.action == ToolPermissionDeny {
				continue
			}
			return ruleEvalOutcome{
				allowed: rule.action == ToolPermissionAllow,
				rule:    rule.label,
				reason:  fmt.Sprintf("tool %q matched rule %q (%s)", toolName, rule.label, rule.action),
			}
		}

		// Evaluating an actual tool invocation (hasArgs == true).
		if len(rule.blockedArgRegex) > 0 {
			if matchedKey, matched := matchBlockedArgs(rule.blockedArgRegex, rawArgs, argsMap, argsParsed); matched {
				return ruleEvalOutcome{
					allowed: false,
					rule:    rule.label,
					reason:  fmt.Sprintf("tool %q argument %q matched blocked_arg_regex in rule %q", toolName, matchedKey, rule.label),
				}
			}
			// If this is a pure blocked_arg_regex deny rule and nothing matched, continue to next rule.
			if rule.action == ToolPermissionDeny && len(rule.allowedArgRegex) == 0 {
				continue
			}
		}

		if len(rule.allowedArgRegex) > 0 {
			failedKey, ok := matchAllowedArgs(rule.allowedArgRegex, rawArgs, argsMap, argsParsed)
			if !ok {
				if rule.action == ToolPermissionAllow {
					failedAllowConstraint = fmt.Sprintf("tool %q argument %q failed allowed_arg_regex in rule %q", toolName, failedKey, rule.label)
					continue
				}
				continue
			}
			return ruleEvalOutcome{
				allowed: rule.action == ToolPermissionAllow,
				rule:    rule.label,
				reason:  fmt.Sprintf("tool %q matched rule %q (%s)", toolName, rule.label, rule.action),
			}
		}

		return ruleEvalOutcome{
			allowed: rule.action == ToolPermissionAllow,
			rule:    rule.label,
			reason:  fmt.Sprintf("tool %q matched rule %q (%s)", toolName, rule.label, rule.action),
		}
	}

	if failedAllowConstraint != "" {
		return ruleEvalOutcome{
			allowed: false,
			rule:    "allowed_arg_regex",
			reason:  failedAllowConstraint,
		}
	}

	return ruleEvalOutcome{
		allowed: d.defaultAction == ToolPermissionAllow,
		rule:    "default_action",
		reason:  fmt.Sprintf("tool %q fell back to default_action (%s)", toolName, d.defaultAction),
	}
}

func matchBlockedArgs(patterns map[string]*regexp.Regexp, rawArgs string, argsMap map[string]any, argsParsed bool) (string, bool) {
	for k, re := range patterns {
		if k == "*" || k == "__raw__" {
			if re.MatchString(rawArgs) {
				return k, true
			}
			continue
		}
		if argsParsed {
			if val, ok := argsMap[k]; ok {
				if re.MatchString(stringifyToolArg(val)) {
					return k, true
				}
			}
		}
	}
	return "", false
}

func matchAllowedArgs(patterns map[string]*regexp.Regexp, rawArgs string, argsMap map[string]any, argsParsed bool) (string, bool) {
	for k, re := range patterns {
		if k == "*" || k == "__raw__" {
			if !re.MatchString(rawArgs) {
				return k, false
			}
			continue
		}
		if !argsParsed {
			return k, false
		}
		val, ok := argsMap[k]
		if !ok {
			return k, false
		}
		if !re.MatchString(stringifyToolArg(val)) {
			return k, false
		}
	}
	return "", true
}

func stringifyToolArg(v any) string {
	switch tv := v.(type) {
	case string:
		return tv
	case nil:
		return ""
	case bool, float64, int, int64:
		return fmt.Sprintf("%v", tv)
	default:
		b, err := json.Marshal(tv)
		if err != nil {
			return fmt.Sprintf("%v", tv)
		}
		return string(b)
	}
}

// Evaluate inspects declared tools, tool_choice directives, emitted tool_calls, and streaming deltas.
func (d *ToolPermissionDriver) Evaluate(_ context.Context, input *domain.GuardrailEvalInput) (*domain.GuardrailEvalResult, error) {
	res := &domain.GuardrailEvalResult{
		Decision:          domain.GuardrailDecisionAllow,
		AppliedGuardrails: []string{d.Name()},
	}
	if d == nil || input == nil {
		return res, nil
	}

	var violations []domain.GuardrailViolation

	// 1. Evaluate declared tools.
	allowedTools := make([]domain.CanonicalTool, 0, len(input.Tools))
	for _, tool := range input.Tools {
		toolType := tool.Type
		if toolType == "" {
			toolType = "function"
		}
		out := d.evaluateTool(tool.Function.Name, toolType, false, "")
		if !out.allowed {
			violations = append(violations, d.newViolation(out.rule, out.reason, map[string]any{
				"surface":   "tools",
				"tool_name": tool.Function.Name,
				"tool_type": toolType,
			}))
		} else {
			allowedTools = append(allowedTools, tool)
		}
	}

	// 2. Evaluate tool_choice from Metadata (supports string, function object, Anthropic tool object, allowed_tools).
	var modifiedToolChoice any
	var toolChoiceModified bool
	if tcRaw, ok := extractToolChoice(input.Metadata); ok {
		tcViolations, modTC, mod := d.evaluateToolChoice(tcRaw, input.Tools, allowedTools)
		violations = append(violations, tcViolations...)
		if mod {
			modifiedToolChoice = modTC
			toolChoiceModified = true
		}
	}

	// 3. Evaluate ToolCalls inside StructuredMessages and top-level input.ToolCalls.
	// For pre_mcp_call, only evaluate the active input.ToolCalls (avoiding re-evaluating prior history).
	deniedCallIDs := make(map[string]bool)
	deniedTopIndices := make(map[int]bool)
	checkedCallIDs := make(map[string]bool)

	var modifiedMessages []domain.CanonicalMessage
	messagesChanged := false
	if input.Hook != domain.GuardrailHookPreMCPCall && len(input.StructuredMessages) > 0 {
		modifiedMessages = make([]domain.CanonicalMessage, len(input.StructuredMessages))
		for mi, msg := range input.StructuredMessages {
			cpMsg := msg
			if len(msg.ToolCalls) > 0 {
				kept := make([]domain.CanonicalToolCall, 0, len(msg.ToolCalls))
				for _, tc := range msg.ToolCalls {
					if tc.ID != "" {
						checkedCallIDs[tc.ID] = true
					}
					out := d.evaluateTool(tc.Function.Name, tc.Type, true, tc.Function.Arguments)
					if !out.allowed {
						if tc.ID != "" {
							deniedCallIDs[tc.ID] = true
						}
						messagesChanged = true
						violations = append(violations, d.newViolation(out.rule, out.reason, map[string]any{
							"surface":      "tool_calls",
							"tool_call_id": tc.ID,
							"tool_name":    tc.Function.Name,
							"tool_type":    tc.Type,
						}))
					} else {
						kept = append(kept, tc)
					}
				}
				cpMsg.ToolCalls = kept
			}
			modifiedMessages[mi] = cpMsg
		}
	}

	// Also evaluate input.ToolCalls not already represented by ID in StructuredMessages.
	nameByIndex := extractToolNamesByIndex(input.Metadata)
	allowedTopToolCalls := make([]domain.CanonicalToolCall, 0, len(input.ToolCalls))
	topToolCallsChanged := false
	for ti, tc := range input.ToolCalls {
		if tc.ID != "" && checkedCallIDs[tc.ID] {
			if !deniedCallIDs[tc.ID] {
				allowedTopToolCalls = append(allowedTopToolCalls, tc)
			} else {
				topToolCallsChanged = true
			}
			continue
		}
		toolName := tc.Function.Name
		if toolName == "" && tc.Index != nil {
			toolName = nameByIndex[*tc.Index]
		}
		// Streaming delta chunk with only partial arguments and no name yet: check unconditional blocked_arg_regex if name is unknown.
		var out ruleEvalOutcome
		if toolName == "" && tc.Function.Arguments != "" {
			out = d.evaluateAnonymousDeltaArgs(tc.Function.Arguments)
		} else {
			out = d.evaluateTool(toolName, tc.Type, true, tc.Function.Arguments)
		}
		if !out.allowed {
			deniedTopIndices[ti] = true
			topToolCallsChanged = true
			violations = append(violations, d.newViolation(out.rule, out.reason, map[string]any{
				"surface":      "tool_calls",
				"tool_call_id": tc.ID,
				"tool_name":    toolName,
				"tool_type":    tc.Type,
			}))
		} else {
			allowedTopToolCalls = append(allowedTopToolCalls, tc)
		}
	}

	// 4. Evaluate explicit streaming delta if supplied in Metadata["stream_delta"].
	if delta, ok := extractStreamDelta(input.Metadata); ok {
		for _, tc := range delta.ToolCalls {
			toolName := tc.Function.Name
			if toolName == "" && tc.Index != nil {
				toolName = nameByIndex[*tc.Index]
			}
			var out ruleEvalOutcome
			if toolName == "" && tc.Function.Arguments != "" {
				out = d.evaluateAnonymousDeltaArgs(tc.Function.Arguments)
			} else {
				out = d.evaluateTool(toolName, tc.Type, true, tc.Function.Arguments)
			}
			if !out.allowed {
				violations = append(violations, d.newViolation(out.rule, out.reason, map[string]any{
					"surface":      "stream_delta",
					"tool_call_id": tc.ID,
					"tool_name":    toolName,
					"tool_type":    tc.Type,
				}))
			}
		}
	}

	if len(violations) == 0 {
		return res, nil
	}

	res.Violations = violations
	switch d.violationMode {
	case ToolPermissionViolationAudit:
		res.Decision = domain.GuardrailDecisionFlag
		return res, nil
	case ToolPermissionViolationStrip:
		res.Decision = domain.GuardrailDecisionModify
		if messagesChanged {
			res.ModifiedMessages = modifiedMessages
		}
		if topToolCallsChanged || len(allowedTopToolCalls) != len(input.ToolCalls) {
			res.ModifiedToolCalls = allowedTopToolCalls
		}
		if len(input.Tools) > 0 && len(allowedTools) != len(input.Tools) {
			if violations[0].Details == nil {
				violations[0].Details = make(map[string]any)
			}
			violations[0].Details["modified_tools"] = allowedTools
		}
		if toolChoiceModified {
			if violations[0].Details == nil {
				violations[0].Details = make(map[string]any)
			}
			violations[0].Details["modified_tool_choice"] = modifiedToolChoice
		}
		return res, nil
	default:
		res.Decision = domain.GuardrailDecisionBlock
		res.ErrorMessage = violations[0].Message
		return res, nil
	}
}

func (d *ToolPermissionDriver) evaluateAnonymousDeltaArgs(rawArgs string) ruleEvalOutcome {
	var argsMap map[string]any
	var parsed bool
	if err := json.Unmarshal([]byte(rawArgs), &argsMap); err == nil && argsMap != nil {
		parsed = true
	}
	for _, rule := range d.rules {
		if rule.nameRegex != nil {
			continue
		}
		if len(rule.blockedArgRegex) > 0 {
			if matchedKey, matched := matchBlockedArgs(rule.blockedArgRegex, rawArgs, argsMap, parsed); matched {
				return ruleEvalOutcome{
					allowed: false,
					rule:    rule.label,
					reason:  fmt.Sprintf("streaming tool delta argument %q matched blocked_arg_regex in rule %q", matchedKey, rule.label),
				}
			}
		}
	}
	return ruleEvalOutcome{allowed: true}
}

// EvaluateStreamDelta evaluates a single CanonicalStreamDelta directly for streaming tool-call enforcement.
func (d *ToolPermissionDriver) EvaluateStreamDelta(ctx context.Context, delta *domain.CanonicalStreamDelta, toolNamesByIndex map[int]string) (*domain.GuardrailEvalResult, error) {
	if delta == nil || len(delta.ToolCalls) == 0 {
		return &domain.GuardrailEvalResult{
			Decision:          domain.GuardrailDecisionAllow,
			AppliedGuardrails: []string{d.Name()},
		}, nil
	}
	var meta map[string]any
	if len(toolNamesByIndex) > 0 {
		meta = map[string]any{"tool_names_by_index": toolNamesByIndex}
	}
	return d.Evaluate(ctx, &domain.GuardrailEvalInput{
		Direction: domain.GuardrailDirectionOutput,
		Hook:      domain.GuardrailHookPostCall,
		ToolCalls: delta.ToolCalls,
		Metadata:  meta,
	})
}

func (d *ToolPermissionDriver) evaluateToolChoice(raw any, declaredTools []domain.CanonicalTool, allowedTools []domain.CanonicalTool) ([]domain.GuardrailViolation, any, bool) {
	if raw == nil {
		return nil, nil, false
	}
	switch tc := raw.(type) {
	case string:
		norm := strings.ToLower(strings.TrimSpace(tc))
		switch norm {
		case "", "none", "auto":
			return nil, nil, false
		case "any", "required":
			if (len(declaredTools) > 0 && len(allowedTools) == 0) || (len(declaredTools) == 0 && d.defaultAction == ToolPermissionDeny) {
				return []domain.GuardrailViolation{
					d.newViolation("tool_choice", fmt.Sprintf("tool_choice %q requires a tool call but no tools are permitted", norm), map[string]any{
						"surface":     "tool_choice",
						"tool_choice": norm,
					}),
				}, "none", true
			}
			return nil, nil, false
		default:
			out := d.evaluateTool(tc, "function", false, "")
			if !out.allowed {
				return []domain.GuardrailViolation{
					d.newViolation(out.rule, out.reason, map[string]any{
						"surface":     "tool_choice",
						"tool_choice": tc,
						"tool_name":   tc,
					}),
				}, "none", true
			}
			return nil, nil, false
		}
	case map[string]any:
		tcType, _ := tc["type"].(string)
		normType := strings.ToLower(strings.TrimSpace(tcType))
		switch normType {
		case "none", "auto":
			return nil, nil, false
		case "any", "required":
			if (len(declaredTools) > 0 && len(allowedTools) == 0) || (len(declaredTools) == 0 && d.defaultAction == ToolPermissionDeny) {
				return []domain.GuardrailViolation{
					d.newViolation("tool_choice", fmt.Sprintf("tool_choice %q requires a tool call but no tools are permitted", normType), map[string]any{
						"surface":     "tool_choice",
						"tool_choice": normType,
					}),
				}, "none", true
			}
			return nil, nil, false
		case "allowed_tools":
			return d.evaluateAllowedToolsChoice(tc)
		}

		name, toolType := extractNamedToolFromChoiceMap(tc)
		if name != "" {
			out := d.evaluateTool(name, toolType, false, "")
			if !out.allowed {
				return []domain.GuardrailViolation{
					d.newViolation(out.rule, out.reason, map[string]any{
						"surface":     "tool_choice",
						"tool_name":   name,
						"tool_type":   toolType,
						"tool_choice": tc,
					}),
				}, "none", true
			}
		}
	}
	return nil, nil, false
}

func (d *ToolPermissionDriver) evaluateAllowedToolsChoice(tc map[string]any) ([]domain.GuardrailViolation, any, bool) {
	rawList, ok := tc["tools"].([]any)
	if !ok {
		if typedList, ok2 := tc["tools"].([]map[string]any); ok2 {
			rawList = make([]any, len(typedList))
			for i, item := range typedList {
				rawList[i] = item
			}
		}
	}
	var violations []domain.GuardrailViolation
	kept := make([]any, 0, len(rawList))
	changed := false

	for _, item := range rawList {
		itemMap, ok := item.(map[string]any)
		if !ok {
			if nameStr, ok2 := item.(string); ok2 && nameStr != "" {
				out := d.evaluateTool(nameStr, "function", false, "")
				if !out.allowed {
					changed = true
					violations = append(violations, d.newViolation(out.rule, out.reason, map[string]any{
						"surface":   "tool_choice.allowed_tools",
						"tool_name": nameStr,
					}))
				} else {
					kept = append(kept, item)
				}
			}
			continue
		}
		name, toolType := extractNamedToolFromChoiceMap(itemMap)
		if name == "" {
			kept = append(kept, item)
			continue
		}
		out := d.evaluateTool(name, toolType, false, "")
		if !out.allowed {
			changed = true
			violations = append(violations, d.newViolation(out.rule, out.reason, map[string]any{
				"surface":   "tool_choice.allowed_tools",
				"tool_name": name,
				"tool_type": toolType,
			}))
		} else {
			kept = append(kept, item)
		}
	}

	if !changed {
		return nil, nil, false
	}
	mod := make(map[string]any, len(tc))
	for k, v := range tc {
		mod[k] = v
	}
	mod["tools"] = kept
	return violations, mod, true
}

func extractNamedToolFromChoiceMap(tc map[string]any) (string, string) {
	toolType, _ := tc["type"].(string)
	if fn, ok := tc["function"].(map[string]any); ok {
		if name, ok := fn["name"].(string); ok && name != "" {
			if toolType == "" {
				toolType = "function"
			}
			return name, toolType
		}
	}
	if name, ok := tc["name"].(string); ok && name != "" {
		if toolType == "" || toolType == "tool" {
			toolType = "function"
		}
		return name, toolType
	}
	return "", toolType
}

func extractToolChoice(meta map[string]any) (any, bool) {
	if len(meta) == 0 {
		return nil, false
	}
	if v, ok := meta["tool_choice"]; ok && v != nil {
		return v, true
	}
	if v, ok := meta["ToolChoice"]; ok && v != nil {
		return v, true
	}
	return nil, false
}

func extractToolNamesByIndex(meta map[string]any) map[int]string {
	out := make(map[int]string)
	if len(meta) == 0 {
		return out
	}
	raw, ok := meta["tool_names_by_index"]
	if !ok || raw == nil {
		return out
	}
	switch m := raw.(type) {
	case map[int]string:
		for k, v := range m {
			out[k] = v
		}
	case map[string]string:
		for k, v := range m {
			var idx int
			if _, err := fmt.Sscanf(k, "%d", &idx); err == nil {
				out[idx] = v
			}
		}
	case map[string]any:
		for k, v := range m {
			var idx int
			if _, err := fmt.Sscanf(k, "%d", &idx); err == nil {
				if s, ok := v.(string); ok {
					out[idx] = s
				}
			}
		}
	}
	return out
}

func extractStreamDelta(meta map[string]any) (*domain.CanonicalStreamDelta, bool) {
	if len(meta) == 0 {
		return nil, false
	}
	raw, ok := meta["stream_delta"]
	if !ok || raw == nil {
		return nil, false
	}
	switch d := raw.(type) {
	case *domain.CanonicalStreamDelta:
		if d != nil {
			return d, true
		}
	case domain.CanonicalStreamDelta:
		return &d, true
	case map[string]any:
		b, err := json.Marshal(d)
		if err != nil {
			return nil, false
		}
		var parsed domain.CanonicalStreamDelta
		if err := json.Unmarshal(b, &parsed); err != nil {
			return nil, false
		}
		return &parsed, true
	}
	return nil, false
}

func (d *ToolPermissionDriver) newViolation(rule, message string, details map[string]any) domain.GuardrailViolation {
	action := domain.GuardrailActionBlock
	decision := domain.GuardrailDecisionBlock
	switch d.violationMode {
	case ToolPermissionViolationStrip:
		action = domain.GuardrailActionRedact
		decision = domain.GuardrailDecisionModify
	case ToolPermissionViolationAudit:
		action = domain.GuardrailActionAudit
		decision = domain.GuardrailDecisionFlag
	}
	return domain.GuardrailViolation{
		GuardrailName: d.Name(),
		GuardrailID:   d.guardrailID,
		Provider:      ProviderToolPermission,
		Category:      "tool_permission",
		Rule:          rule,
		Severity:      "high",
		Message:       message,
		Action:        action,
		Decision:      decision,
		Details:       details,
	}
}
