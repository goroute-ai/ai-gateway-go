package drivers

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/guardrails"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
)

const (
	ProviderToolPolicy        = "tool_policy"
	CodeViolatedToolPolicy    = "violated_tool_policy"
	MetaExecutedUntrustedTool = "executed_untrusted_tools"
)

type toolPolicyConfig struct {
	DefaultInputPolicy  storage.ToolTrustLevel `json:"default_input_policy,omitempty"`
	DefaultOutputPolicy storage.ToolTrustLevel `json:"default_output_policy,omitempty"`
	Policies            any                    `json:"policies,omitempty"`
}

// ToolPolicyDriver enforces tool trust policies (blocked tools) and multi-turn
// trust-chain taint tracking across pre_call, post_call, and orchestrator tool execution.
type ToolPolicyDriver struct {
	guardrailName       string
	guardrailID         string
	hooks               []domain.GuardrailHook
	store               storage.ToolPolicyRepository
	inlinePolicies      map[string]*storage.ToolPolicy
	defaultInputPolicy  storage.ToolTrustLevel
	defaultOutputPolicy storage.ToolTrustLevel
}

// NewToolPolicyDriver constructs a ToolPolicyDriver backed by store and/or inline config policies.
func NewToolPolicyDriver(cfg guardrails.DriverConfig, store storage.ToolPolicyRepository) (*ToolPolicyDriver, error) {
	var parsed toolPolicyConfig
	if len(cfg.EffectiveConfig) > 0 {
		rawBytes, err := json.Marshal(cfg.EffectiveConfig)
		if err != nil {
			return nil, fmt.Errorf("marshal tool_policy config: %w", err)
		}
		if err := json.Unmarshal(rawBytes, &parsed); err != nil {
			return nil, fmt.Errorf("decode tool_policy config: %w", err)
		}
	}

	defIn := storage.ToolTrustLevel(strings.ToLower(strings.TrimSpace(string(parsed.DefaultInputPolicy))))
	if defIn == "" {
		defIn = storage.ToolTrustUntrusted
	}
	if !defIn.IsValidInput() {
		return nil, fmt.Errorf("invalid tool_policy default_input_policy %q", defIn)
	}

	defOut := storage.ToolTrustLevel(strings.ToLower(strings.TrimSpace(string(parsed.DefaultOutputPolicy))))
	if defOut == "" {
		defOut = storage.ToolTrustUntrusted
	}
	if !defOut.IsValidOutput() {
		return nil, fmt.Errorf("invalid tool_policy default_output_policy %q", defOut)
	}

	inlinePolicies, err := parseInlineToolPolicies(parsed.Policies)
	if err != nil {
		return nil, err
	}

	name := ProviderToolPolicy
	var id string
	var hooks []domain.GuardrailHook
	if cfg.Definition != nil {
		if strings.TrimSpace(cfg.Definition.Name) != "" {
			name = cfg.Definition.Name
		}
		id = cfg.Definition.ID
		hooks = slices.Clone(cfg.Definition.EventHooks)
	}

	return &ToolPolicyDriver{
		guardrailName:       name,
		guardrailID:         id,
		hooks:               hooks,
		store:               store,
		inlinePolicies:      inlinePolicies,
		defaultInputPolicy:  defIn,
		defaultOutputPolicy: defOut,
	}, nil
}

func parseInlineToolPolicies(raw any) (map[string]*storage.ToolPolicy, error) {
	out := make(map[string]*storage.ToolPolicy)
	if raw == nil {
		return out, nil
	}

	b, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("marshal inline tool policies: %w", err)
	}

	var byName map[string]struct {
		InputPolicy  storage.ToolTrustLevel `json:"input_policy"`
		OutputPolicy storage.ToolTrustLevel `json:"output_policy"`
	}
	if err := json.Unmarshal(b, &byName); err == nil && byName != nil {
		for toolName, spec := range byName {
			p, err := normalizeInlineToolPolicy(toolName, spec.InputPolicy, spec.OutputPolicy)
			if err != nil {
				return nil, err
			}
			out[p.ToolName] = p
		}
		return out, nil
	}

	var list []storage.ToolPolicy
	if err := json.Unmarshal(b, &list); err == nil {
		for _, item := range list {
			p, err := normalizeInlineToolPolicy(item.ToolName, item.InputPolicy, item.OutputPolicy)
			if err != nil {
				return nil, err
			}
			out[p.ToolName] = p
		}
		return out, nil
	}

	return nil, fmt.Errorf("tool_policy config policies must be a map or list")
}

func normalizeInlineToolPolicy(toolName string, inPol, outPol storage.ToolTrustLevel) (*storage.ToolPolicy, error) {
	toolName = strings.TrimSpace(toolName)
	if toolName == "" {
		return nil, fmt.Errorf("inline tool policy requires non-empty tool_name")
	}
	inNorm := storage.ToolTrustLevel(strings.ToLower(strings.TrimSpace(string(inPol))))
	if inNorm == "" {
		inNorm = storage.ToolTrustUntrusted
	}
	if !inNorm.IsValidInput() {
		return nil, fmt.Errorf("inline tool policy %q invalid input_policy %q", toolName, inPol)
	}
	outNorm := storage.ToolTrustLevel(strings.ToLower(strings.TrimSpace(string(outPol))))
	if outNorm == "" {
		outNorm = storage.ToolTrustUntrusted
	}
	if !outNorm.IsValidOutput() {
		return nil, fmt.Errorf("inline tool policy %q invalid output_policy %q", toolName, outPol)
	}
	return &storage.ToolPolicy{
		ToolName:     toolName,
		InputPolicy:  inNorm,
		OutputPolicy: outNorm,
	}, nil
}

func (d *ToolPolicyDriver) Name() string {
	if d != nil && d.guardrailName != "" {
		return d.guardrailName
	}
	return ProviderToolPolicy
}

func (d *ToolPolicyDriver) SupportedHooks() []domain.GuardrailHook {
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

func (d *ToolPolicyDriver) resolvePolicies(ctx context.Context, input *domain.GuardrailEvalInput) (map[string]*storage.ToolPolicy, error) {
	merged := make(map[string]*storage.ToolPolicy, len(d.inlinePolicies))
	for k, v := range d.inlinePolicies {
		cp := *v
		merged[k] = &cp
	}
	if d.store != nil && input != nil && strings.TrimSpace(input.OrgID) != "" {
		stored, err := d.store.ResolveEffectiveToolPolicies(ctx, input.OrgID, input.TeamID, input.VirtualKeyID)
		if err != nil {
			return nil, err
		}
		for k, v := range stored {
			cp := *v
			merged[k] = &cp
		}
	}
	return merged, nil
}

func (d *ToolPolicyDriver) policyForTool(policies map[string]*storage.ToolPolicy, toolName string) (storage.ToolTrustLevel, storage.ToolTrustLevel) {
	if p, ok := lookupToolPolicy(policies, toolName); ok {
		return p.InputPolicy, p.OutputPolicy
	}
	return d.defaultInputPolicy, d.defaultOutputPolicy
}

func lookupToolPolicy(policies map[string]*storage.ToolPolicy, toolName string) (*storage.ToolPolicy, bool) {
	if len(policies) == 0 || toolName == "" {
		return nil, false
	}
	if p, ok := policies[toolName]; ok && p != nil {
		return p, true
	}
	clean := strings.TrimPrefix(toolName, "mcp__")
	clean = strings.TrimPrefix(clean, "mcp_")
	if clean != toolName {
		if p, ok := policies[clean]; ok && p != nil {
			return p, true
		}
	} else {
		if p, ok := policies["mcp_"+toolName]; ok && p != nil {
			return p, true
		}
		if p, ok := policies["mcp__"+toolName]; ok && p != nil {
			return p, true
		}
	}
	return nil, false
}

// OutputPolicyForTool returns the resolved output_policy for toolName under the given tenant scope.
func (d *ToolPolicyDriver) OutputPolicyForTool(ctx context.Context, orgID, teamID, virtualKeyID, toolName string) (storage.ToolTrustLevel, error) {
	if d == nil {
		return storage.ToolTrustUntrusted, nil
	}
	policies, err := d.resolvePolicies(ctx, &domain.GuardrailEvalInput{
		OrgID:        orgID,
		TeamID:       teamID,
		VirtualKeyID: virtualKeyID,
	})
	if err != nil {
		return "", err
	}
	_, outPol := d.policyForTool(policies, toolName)
	return outPol, nil
}

// Evaluate runs Stage 1 (blocked tool enforcement) and Stage 2 (trust-chain taint tracking).
func (d *ToolPolicyDriver) Evaluate(ctx context.Context, input *domain.GuardrailEvalInput) (*domain.GuardrailEvalResult, error) {
	res := &domain.GuardrailEvalResult{
		Decision:          domain.GuardrailDecisionAllow,
		AppliedGuardrails: []string{d.Name()},
	}
	if d == nil || input == nil {
		return res, nil
	}

	policies, err := d.resolvePolicies(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("resolve tool policies: %w", err)
	}

	// Stage 1: Block any declared tool, tool_choice target, or tool_call whose input_policy == 'blocked'.
	for _, tool := range input.Tools {
		inPol, _ := d.policyForTool(policies, tool.Function.Name)
		if inPol == storage.ToolTrustBlocked {
			return d.blockedResult(tool.Function.Name, "blocked_tool",
				fmt.Sprintf("%s: tool %q is blocked by tool policy", CodeViolatedToolPolicy, tool.Function.Name),
				map[string]any{"surface": "tools", "tool_name": tool.Function.Name, "input_policy": string(inPol)},
			), nil
		}
	}

	var forcedToolChoiceTargets []string
	if tcRaw, ok := extractToolChoice(input.Metadata); ok {
		allChoiceTargets := extractToolChoiceTargetNames(tcRaw)
		for _, target := range allChoiceTargets {
			inPol, _ := d.policyForTool(policies, target)
			if inPol == storage.ToolTrustBlocked {
				return d.blockedResult(target, "blocked_tool",
					fmt.Sprintf("%s: tool_choice target %q is blocked by tool policy", CodeViolatedToolPolicy, target),
					map[string]any{"surface": "tool_choice", "tool_name": target, "input_policy": string(inPol)},
				), nil
			}
		}
		forcedToolChoiceTargets = extractForcedToolChoiceTargets(tcRaw)
	}

	if directTool, _ := input.Metadata["tool_name"].(string); strings.TrimSpace(directTool) != "" {
		inPol, _ := d.policyForTool(policies, strings.TrimSpace(directTool))
		if inPol == storage.ToolTrustBlocked {
			return d.blockedResult(directTool, "blocked_tool",
				fmt.Sprintf("%s: tool %q is blocked by tool policy", CodeViolatedToolPolicy, directTool),
				map[string]any{"surface": "tool_execution", "tool_name": directTool, "input_policy": string(inPol)},
			), nil
		}
	}

	// Stage 2: Scan conversation history and metadata for prior untrusted tool outputs.
	taintSources := extractMetadataUntrustedTools(input.Metadata)
	priorTainted := len(taintSources) > 0
	if b, ok := input.Metadata["tainted"].(bool); ok && b {
		priorTainted = true
	}

	allMessages := collectHistoryMessages(input)
	callIDToName := make(map[string]string)
	respondedCallIDs := make(map[string]bool)
	firstTaintMsgIdx := -1

	for i, msg := range allMessages {
		for _, tc := range msg.ToolCalls {
			if tc.ID != "" && tc.Function.Name != "" {
				callIDToName[tc.ID] = tc.Function.Name
			}
		}
		if strings.EqualFold(msg.Role, "tool") {
			if msg.ToolCallID != "" {
				respondedCallIDs[msg.ToolCallID] = true
			}
			originTool := callIDToName[msg.ToolCallID]
			if originTool == "" {
				originTool = msg.Name
			}
			if originTool != "" {
				_, outPol := d.policyForTool(policies, originTool)
				if outPol == storage.ToolTrustUntrusted {
					taintSources = appendUniqueString(taintSources, originTool)
					if firstTaintMsgIdx < 0 {
						firstTaintMsgIdx = i
					}
				}
			}
		}
	}

	tainted := priorTainted || firstTaintMsgIdx >= 0

	// Check StructuredMessages tool_calls (both Stage 1 blocked and Stage 2 taint-after-untrusted).
	// Also record already-responded calls that occurred BEFORE taint so top-level input.ToolCalls
	// (populated by BuildInputEvalInput from all history messages) doesn't false-positive on pre-taint calls.
	preTaintCompletedIDs := make(map[string]bool)
	for i, msg := range allMessages {
		for _, tc := range msg.ToolCalls {
			inPol, _ := d.policyForTool(policies, tc.Function.Name)
			if inPol == storage.ToolTrustBlocked {
				return d.blockedResult(tc.Function.Name, "blocked_tool",
					fmt.Sprintf("%s: tool %q is blocked by tool policy", CodeViolatedToolPolicy, tc.Function.Name),
					map[string]any{"surface": "tool_calls", "tool_name": tc.Function.Name, "input_policy": string(inPol)},
				), nil
			}
			alreadyResponded := tc.ID != "" && respondedCallIDs[tc.ID]
			occurredAfterTaint := priorTainted || (firstTaintMsgIdx >= 0 && i > firstTaintMsgIdx)
			if alreadyResponded && !occurredAfterTaint {
				preTaintCompletedIDs[tc.ID] = true
				continue
			}
			if tainted && inPol == storage.ToolTrustTrusted {
				return d.blockedTaintResult(tc.Function.Name, "tool_calls", taintSources), nil
			}
		}
	}

	// Check top-level input.ToolCalls (post_call emissions, direct evaluations, or unresponded calls).
	for _, tc := range input.ToolCalls {
		inPol, _ := d.policyForTool(policies, tc.Function.Name)
		if inPol == storage.ToolTrustBlocked {
			return d.blockedResult(tc.Function.Name, "blocked_tool",
				fmt.Sprintf("%s: tool %q is blocked by tool policy", CodeViolatedToolPolicy, tc.Function.Name),
				map[string]any{"surface": "tool_calls", "tool_name": tc.Function.Name, "input_policy": string(inPol)},
			), nil
		}
		if tc.ID != "" && preTaintCompletedIDs[tc.ID] {
			continue
		}
		if tainted && inPol == storage.ToolTrustTrusted {
			return d.blockedTaintResult(tc.Function.Name, "tool_calls", taintSources), nil
		}
	}

	// Check explicit forced tool_choice target(s) if conversation is already tainted.
	if tainted {
		for _, target := range forcedToolChoiceTargets {
			inPol, _ := d.policyForTool(policies, target)
			if inPol == storage.ToolTrustTrusted {
				return d.blockedTaintResult(target, "tool_choice", taintSources), nil
			}
		}
		if directTool, _ := input.Metadata["tool_name"].(string); strings.TrimSpace(directTool) != "" {
			inPol, _ := d.policyForTool(policies, strings.TrimSpace(directTool))
			if inPol == storage.ToolTrustTrusted {
				return d.blockedTaintResult(strings.TrimSpace(directTool), "tool_execution", taintSources), nil
			}
		}
	}

	return res, nil
}

func collectHistoryMessages(input *domain.GuardrailEvalInput) []domain.CanonicalMessage {
	var prior []domain.CanonicalMessage
	if len(input.Metadata) > 0 {
		if rawPrior, ok := input.Metadata["prior_messages"]; ok && rawPrior != nil {
			switch pm := rawPrior.(type) {
			case []domain.CanonicalMessage:
				prior = pm
			default:
				if b, err := json.Marshal(pm); err == nil {
					var decoded []domain.CanonicalMessage
					if err := json.Unmarshal(b, &decoded); err == nil {
						prior = decoded
					}
				}
			}
		}
	}
	if len(prior) == 0 {
		return input.StructuredMessages
	}
	return slices.Concat(prior, input.StructuredMessages)
}

func extractMetadataUntrustedTools(meta map[string]any) []string {
	if len(meta) == 0 {
		return nil
	}
	raw, ok := meta[MetaExecutedUntrustedTool]
	if !ok || raw == nil {
		return nil
	}
	var out []string
	switch v := raw.(type) {
	case []string:
		for _, s := range v {
			if s = strings.TrimSpace(s); s != "" {
				out = appendUniqueString(out, s)
			}
		}
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok {
				if s = strings.TrimSpace(s); s != "" {
					out = appendUniqueString(out, s)
				}
			}
		}
	case map[string]bool:
		keys := make([]string, 0, len(v))
		for k, tainted := range v {
			if tainted && strings.TrimSpace(k) != "" {
				keys = append(keys, strings.TrimSpace(k))
			}
		}
		sort.Strings(keys)
		out = append(out, keys...)
	case string:
		if s := strings.TrimSpace(v); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func appendUniqueString(dst []string, val string) []string {
	if slices.Contains(dst, val) {
		return dst
	}
	return append(dst, val)
}

func extractToolChoiceTargetNames(raw any) []string {
	switch tc := raw.(type) {
	case string:
		norm := strings.ToLower(strings.TrimSpace(tc))
		if norm == "" || norm == "none" || norm == "auto" || norm == "any" || norm == "required" {
			return nil
		}
		return []string{tc}
	case map[string]any:
		tcType, _ := tc["type"].(string)
		normType := strings.ToLower(strings.TrimSpace(tcType))
		if normType == "allowed_tools" {
			// allowed_tools lists candidate tools; only block explicitly blocked tools in Stage 1,
			// or if it names a single forced tool? Return them for Stage 1 blocked check,
			// wait: if allowed_tools restricts to [trusted_tool] when tainted, only block if mode == required?
			// Returning nil for Stage 2 and handling Stage 1 separately? Actually if mode is required and
			// all allowed_tools are trusted while tainted, let's check; for single named tool_choice return it.
			var targets []string
			if rawList, ok := tc["tools"].([]any); ok {
				for _, item := range rawList {
					if m, ok := item.(map[string]any); ok {
						if name, _ := extractNamedToolFromChoiceMap(m); name != "" {
							targets = append(targets, name)
						}
					} else if s, ok := item.(string); ok && s != "" {
						targets = append(targets, s)
					}
				}
			}
			return targets
		}
		if name, _ := extractNamedToolFromChoiceMap(tc); name != "" {
			return []string{name}
		}
	}
	return nil
}

func extractForcedToolChoiceTargets(raw any) []string {
	switch tc := raw.(type) {
	case string:
		norm := strings.ToLower(strings.TrimSpace(tc))
		if norm == "" || norm == "none" || norm == "auto" || norm == "any" || norm == "required" {
			return nil
		}
		return []string{tc}
	case map[string]any:
		tcType, _ := tc["type"].(string)
		if strings.EqualFold(strings.TrimSpace(tcType), "allowed_tools") {
			return nil
		}
		if name, _ := extractNamedToolFromChoiceMap(tc); name != "" {
			return []string{name}
		}
	}
	return nil
}

func (d *ToolPolicyDriver) blockedTaintResult(toolName, surface string, taintSources []string) *domain.GuardrailEvalResult {
	srcDesc := "prior untrusted tool output"
	if len(taintSources) > 0 {
		srcDesc = strings.Join(taintSources, ", ")
	}
	msg := fmt.Sprintf("%s: tool %q requires trusted input, but conversation is tainted by untrusted tool output (%s)",
		CodeViolatedToolPolicy, toolName, srcDesc)
	return d.blockedResult(toolName, CodeViolatedToolPolicy, msg, map[string]any{
		"surface":       surface,
		"tool_name":     toolName,
		"input_policy":  string(storage.ToolTrustTrusted),
		"taint_sources": slices.Clone(taintSources),
	})
}

func (d *ToolPolicyDriver) blockedResult(toolName, rule, msg string, details map[string]any) *domain.GuardrailEvalResult {
	return &domain.GuardrailEvalResult{
		Decision:          domain.GuardrailDecisionBlock,
		AppliedGuardrails: []string{d.Name()},
		ErrorMessage:      msg,
		Violations: []domain.GuardrailViolation{{
			GuardrailName: d.Name(),
			GuardrailID:   d.guardrailID,
			Provider:      ProviderToolPolicy,
			Category:      CodeViolatedToolPolicy,
			Rule:          rule,
			Severity:      "high",
			Message:       msg,
			Action:        domain.GuardrailActionBlock,
			Decision:      domain.GuardrailDecisionBlock,
			Details:       details,
		}},
	}
}
