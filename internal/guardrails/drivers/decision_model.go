package drivers

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/guardrails"
)

const (
	// ProviderDecisionModel identifies the structured boolean-predicate decision model guardrail driver.
	ProviderDecisionModel = "decision_model"
)

// DecisionCheck defines a single structured boolean predicate evaluated by DecisionModelDriver.
type DecisionCheck struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Question    string `json:"question,omitempty"`
	Expected    *bool  `json:"expected,omitempty"`
	Action      string `json:"action,omitempty"`
	Severity    string `json:"severity,omitempty"`
}

type normalizedDecisionCheck struct {
	name        string
	description string
	question    string
	expected    bool
	action      domain.GuardrailAction
	severity    string
}

// DecisionModelDriver evaluates content against structured boolean predicate checks[] using
// an internal ChatExecutor model call with non-spoofable loop prevention.
type DecisionModelDriver struct {
	guardrailName string
	guardrailID   string
	hooks         []domain.GuardrailHook
	model         string
	systemPrompt  string
	checks        []normalizedDecisionCheck
	allMustPass   bool
	temperature   float64
	maxTokens     int
	defaultAction domain.GuardrailAction
	executor      ChatExecutor
}

// NewDecisionModelDriver constructs a DecisionModelDriver from cfg and an injected ChatExecutor.
func NewDecisionModelDriver(cfg guardrails.DriverConfig, executor ChatExecutor) (*DecisionModelDriver, error) {
	model := configString(cfg, "model", "decision_model", "model_name")
	if model == "" {
		return nil, fmt.Errorf("%s driver requires model", ProviderDecisionModel)
	}

	defaultAct := effectiveAction(cfg, domain.GuardrailActionBlock)
	if defaultAct != domain.GuardrailActionBlock && defaultAct != domain.GuardrailActionAudit {
		defaultAct = domain.GuardrailActionBlock
	}

	checks, err := parseDecisionChecks(cfg, defaultAct)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ProviderDecisionModel, err)
	}
	if len(checks) == 0 {
		return nil, fmt.Errorf("%s driver requires at least one check in checks[]", ProviderDecisionModel)
	}

	temperature := configFloat(cfg, defaultJudgeTemperature, "temperature")
	maxTokens := configInt(cfg, defaultJudgeMaxTokens, "max_tokens")
	if maxTokens <= 0 {
		maxTokens = defaultJudgeMaxTokens
	}

	return &DecisionModelDriver{
		guardrailName: guardrailName(cfg, ProviderDecisionModel),
		guardrailID:   guardrailID(cfg),
		hooks:         resolveJudgeHooks(cfg),
		model:         model,
		systemPrompt:  configString(cfg, "system_prompt", "prompt", "instructions"),
		checks:        checks,
		allMustPass:   configBool(cfg, true, "all_must_pass"),
		temperature:   temperature,
		maxTokens:     maxTokens,
		defaultAction: defaultAct,
		executor:      executor,
	}, nil
}

// Name returns the configured guardrail name or provider identifier.
func (d *DecisionModelDriver) Name() string {
	return d.guardrailName
}

// SupportedHooks returns the lifecycle hooks evaluated by this decision model driver.
func (d *DecisionModelDriver) SupportedHooks() []domain.GuardrailHook {
	return slices.Clone(d.hooks)
}

type parsedCheckOutcome struct {
	result bool
	reason string
}

// Evaluate runs all configured boolean predicate checks against the input.
func (d *DecisionModelDriver) Evaluate(ctx context.Context, input *domain.GuardrailEvalInput) (*domain.GuardrailEvalResult, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if IsInternalGuardrailOrigin(ctx) {
		return &domain.GuardrailEvalResult{
			Decision:          domain.GuardrailDecisionAllow,
			AppliedGuardrails: []string{d.guardrailName},
		}, nil
	}
	if d.executor == nil {
		return nil, fmt.Errorf("%s driver requires a configured ChatExecutor", ProviderDecisionModel)
	}
	if !hasJudgeableContent(input) {
		return &domain.GuardrailEvalResult{
			Decision:          domain.GuardrailDecisionAllow,
			AppliedGuardrails: []string{d.guardrailName},
		}, nil
	}

	resp, usageUnits, err := executeJudgeChat(
		ctx,
		d.executor,
		d.model,
		d.temperature,
		d.maxTokens,
		d.buildSystemPrompt(),
		formatEvalInputForJudge(input),
		input,
	)
	if err != nil {
		return nil, fmt.Errorf("%s execution failed: %w", ProviderDecisionModel, err)
	}

	rawText := extractChatResponseText(resp)
	jsonBytes, err := extractJSONObject(rawText)
	if err != nil {
		return nil, fmt.Errorf("%s invalid response: %w", ProviderDecisionModel, err)
	}

	outcomes, err := parseDecisionCheckOutcomes(jsonBytes)
	if err != nil {
		return nil, fmt.Errorf("%s parse check outcomes: %w", ProviderDecisionModel, err)
	}

	passedCount := 0
	var failedViolations []domain.GuardrailViolation
	hasBlock := false
	firstBlockMsg := ""

	for _, chk := range d.checks {
		out, ok := lookupCheckOutcome(outcomes, chk.name)
		if !ok {
			return nil, fmt.Errorf("%s response missing boolean result for check %q", ProviderDecisionModel, chk.name)
		}
		if out.result == chk.expected {
			passedCount++
			continue
		}

		reason := strings.TrimSpace(out.reason)
		if reason == "" {
			reason = fmt.Sprintf("Decision check %q returned %t (expected %t)", chk.name, out.result, chk.expected)
		}

		vDecision := domain.GuardrailDecisionFlag
		if chk.action == domain.GuardrailActionBlock {
			vDecision = domain.GuardrailDecisionBlock
			hasBlock = true
			if firstBlockMsg == "" {
				firstBlockMsg = reason
			}
		}

		failedViolations = append(failedViolations, domain.GuardrailViolation{
			GuardrailName: d.guardrailName,
			GuardrailID:   d.guardrailID,
			Provider:      ProviderDecisionModel,
			Category:      "decision_model",
			Rule:          chk.name,
			Severity:      chk.severity,
			Message:       reason,
			Action:        chk.action,
			Decision:      vDecision,
			Details: map[string]any{
				"model":    d.model,
				"check":    chk.name,
				"expected": chk.expected,
				"actual":   out.result,
			},
		})
	}

	if len(failedViolations) == 0 || (!d.allMustPass && passedCount > 0) {
		return &domain.GuardrailEvalResult{
			Decision:          domain.GuardrailDecisionAllow,
			AppliedGuardrails: []string{d.guardrailName},
			UsageUnits:        usageUnits,
		}, nil
	}

	if hasBlock {
		return &domain.GuardrailEvalResult{
			Decision:          domain.GuardrailDecisionBlock,
			Violations:        failedViolations,
			AppliedGuardrails: []string{d.guardrailName},
			UsageUnits:        usageUnits,
			ErrorMessage:      firstBlockMsg,
		}, nil
	}

	return &domain.GuardrailEvalResult{
		Decision:          domain.GuardrailDecisionFlag,
		Violations:        failedViolations,
		AppliedGuardrails: []string{d.guardrailName},
		UsageUnits:        usageUnits,
	}, nil
}

func (d *DecisionModelDriver) buildSystemPrompt() string {
	var sb strings.Builder
	if d.systemPrompt != "" {
		sb.WriteString(d.systemPrompt)
		sb.WriteString("\n\n")
	} else {
		sb.WriteString("You are a strict binary policy decision classifier. Evaluate each predicate check independently as true or false.\n\n")
	}

	sb.WriteString("Predicate checks to evaluate:\n")
	for _, chk := range d.checks {
		prompt := chk.question
		if prompt == "" {
			prompt = chk.description
		}
		sb.WriteString(fmt.Sprintf("- %s", chk.name))
		if prompt != "" {
			sb.WriteString(": " + prompt)
		}
		sb.WriteString(fmt.Sprintf(" (expected=%t)\n", chk.expected))
	}

	sb.WriteString("\nRespond ONLY with a single valid JSON object matching this schema:\n")
	sb.WriteString(`{"checks": {"<check_name>": {"result": <boolean>, "reason": "<brief explanation>"}}}`)
	return sb.String()
}

func parseDecisionChecks(cfg guardrails.DriverConfig, defaultAct domain.GuardrailAction) ([]normalizedDecisionCheck, error) {
	cm := configMap(cfg)
	raw, ok := lookupAnyCaseInsensitive(cm, "checks")
	if !ok {
		raw, ok = lookupAnyCaseInsensitive(cm, "predicates")
	}
	if !ok {
		raw, ok = lookupAnyCaseInsensitive(cm, "rules")
	}
	if !ok || raw == nil {
		return nil, nil
	}

	var rawChecks []DecisionCheck
	switch v := raw.(type) {
	case []DecisionCheck:
		rawChecks = v
	default:
		b, err := json.Marshal(raw)
		if err != nil {
			return nil, fmt.Errorf("marshal checks: %w", err)
		}
		if err := json.Unmarshal(b, &rawChecks); err != nil {
			return nil, fmt.Errorf("decode checks: %w", err)
		}
	}

	out := make([]normalizedDecisionCheck, 0, len(rawChecks))
	for i, c := range rawChecks {
		name := strings.TrimSpace(c.Name)
		if name == "" {
			return nil, fmt.Errorf("checks[%d] requires non-empty name", i)
		}
		expected := true
		if c.Expected != nil {
			expected = *c.Expected
		}

		act := defaultAct
		if strings.TrimSpace(c.Action) != "" {
			switch normalized := normalizeActionString(c.Action); normalized {
			case domain.GuardrailActionBlock:
				act = domain.GuardrailActionBlock
			case domain.GuardrailActionAudit:
				act = domain.GuardrailActionAudit
			default:
				return nil, fmt.Errorf("checks[%d] (%q) has invalid action %q (expected block or flag)", i, name, c.Action)
			}
		}

		sev := strings.ToLower(strings.TrimSpace(c.Severity))
		if sev == "" {
			if act == domain.GuardrailActionAudit {
				sev = "medium"
			} else {
				sev = "high"
			}
		}

		out = append(out, normalizedDecisionCheck{
			name:        name,
			description: strings.TrimSpace(c.Description),
			question:    strings.TrimSpace(c.Question),
			expected:    expected,
			action:      act,
			severity:    sev,
		})
	}
	return out, nil
}

func parseDecisionCheckOutcomes(jsonBytes []byte) (map[string]parsedCheckOutcome, error) {
	var root map[string]any
	if err := json.Unmarshal(jsonBytes, &root); err != nil {
		return nil, err
	}

	var target any
	if v, ok := lookupAnyCaseInsensitive(root, "checks"); ok {
		target = v
	} else if v, ok := lookupAnyCaseInsensitive(root, "results"); ok {
		target = v
	} else {
		target = root
	}

	out := make(map[string]parsedCheckOutcome)
	switch typed := target.(type) {
	case map[string]any:
		for k, v := range typed {
			if outcome, ok := parseSingleCheckOutcomeValue(v); ok {
				out[strings.TrimSpace(k)] = outcome
			}
		}
	case []any:
		for _, item := range typed {
			obj, ok := item.(map[string]any)
			if !ok {
				continue
			}
			name, _ := lookupStringCaseInsensitive(obj, "name")
			if name == "" {
				name, _ = lookupStringCaseInsensitive(obj, "check")
			}
			if name == "" {
				continue
			}
			if outcome, ok := parseSingleCheckOutcomeValue(obj); ok {
				out[name] = outcome
			}
		}
	default:
		return nil, fmt.Errorf("unexpected checks payload type %T", target)
	}

	if len(out) == 0 {
		return nil, fmt.Errorf("no valid boolean check results found in response")
	}
	return out, nil
}

func parseSingleCheckOutcomeValue(v any) (parsedCheckOutcome, bool) {
	switch x := v.(type) {
	case bool:
		return parsedCheckOutcome{result: x}, true
	case map[string]any:
		var boolVal bool
		found := false
		for _, key := range []string{"result", "passed", "value", "matched", "answer", "compliant"} {
			if raw, ok := lookupAnyCaseInsensitive(x, key); ok {
				if b, ok := raw.(bool); ok {
					boolVal = b
					found = true
					break
				}
			}
		}
		if !found {
			return parsedCheckOutcome{}, false
		}
		reason, _ := lookupStringCaseInsensitive(x, "reason")
		if reason == "" {
			reason, _ = lookupStringCaseInsensitive(x, "explanation")
		}
		if reason == "" {
			reason, _ = lookupStringCaseInsensitive(x, "message")
		}
		return parsedCheckOutcome{result: boolVal, reason: reason}, true
	default:
		return parsedCheckOutcome{}, false
	}
}

func lookupCheckOutcome(outcomes map[string]parsedCheckOutcome, name string) (parsedCheckOutcome, bool) {
	if v, ok := outcomes[name]; ok {
		return v, true
	}
	for k, v := range outcomes {
		if strings.EqualFold(strings.TrimSpace(k), strings.TrimSpace(name)) {
			return v, true
		}
	}
	return parsedCheckOutcome{}, false
}

// Compile-time interface assertion.
var _ guardrails.Driver = (*DecisionModelDriver)(nil)
