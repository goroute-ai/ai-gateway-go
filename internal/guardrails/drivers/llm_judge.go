package drivers

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"slices"
	"strings"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/guardrails"
)

const (
	// ProviderLLMJudge identifies the LLM-as-a-judge rubric evaluation guardrail driver.
	ProviderLLMJudge = "llm_as_a_judge"

	// InternalGuardrailOriginMetadataKey is the reserved metadata key stripped from external
	// HTTP requests at ingress so callers cannot spoof internal guardrail sub-call origin.
	InternalGuardrailOriginMetadataKey = "_internal_guardrail_origin"

	defaultJudgeThreshold   = 70.0
	defaultJudgeTemperature = 0.0
	defaultJudgeMaxTokens   = 512
)

type internalGuardrailOriginContextKey struct{}

// WithInternalGuardrailOrigin returns a child context carrying an unexported, non-spoofable
// marker indicating the call originated from an internal guardrail driver sub-call.
func WithInternalGuardrailOrigin(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, internalGuardrailOriginContextKey{}, true)
}

// IsInternalGuardrailOrigin reports whether ctx carries the unexported internal guardrail
// origin marker. External request metadata is never trusted for this check.
func IsInternalGuardrailOrigin(ctx context.Context) bool {
	if ctx == nil {
		return false
	}
	v, ok := ctx.Value(internalGuardrailOriginContextKey{}).(bool)
	return ok && v
}

// StripInternalGuardrailOriginMetadata removes any caller-supplied _internal_guardrail_origin
// key (case-insensitively) from a map[string]any metadata map.
func StripInternalGuardrailOriginMetadata(meta map[string]any) {
	for k := range meta {
		if strings.EqualFold(strings.TrimSpace(k), InternalGuardrailOriginMetadataKey) {
			delete(meta, k)
		}
	}
}

// StripInternalGuardrailOriginStringMetadata removes any caller-supplied _internal_guardrail_origin
// key (case-insensitively) from a map[string]string metadata map.
func StripInternalGuardrailOriginStringMetadata(meta map[string]string) {
	for k := range meta {
		if strings.EqualFold(strings.TrimSpace(k), InternalGuardrailOriginMetadataKey) {
			delete(meta, k)
		}
	}
}

// ChatExecutor executes an internal canonical chat completion request on behalf of
// model-backed guardrail drivers such as llm_as_a_judge and decision_model.
type ChatExecutor interface {
	ExecuteChat(ctx context.Context, idCtx *domain.IdentityContext, req *domain.CanonicalChatRequest) (*domain.CanonicalChatResponse, error)
}

// ChatExecutorFunc adapts a function into a ChatExecutor.
type ChatExecutorFunc func(ctx context.Context, idCtx *domain.IdentityContext, req *domain.CanonicalChatRequest) (*domain.CanonicalChatResponse, error)

// ExecuteChat invokes f(ctx, idCtx, req).
func (f ChatExecutorFunc) ExecuteChat(ctx context.Context, idCtx *domain.IdentityContext, req *domain.CanonicalChatRequest) (*domain.CanonicalChatResponse, error) {
	return f(ctx, idCtx, req)
}

// JudgeCriterion defines a weighted rubric criterion evaluated by LLMJudgeDriver on a 0-100 scale.
type JudgeCriterion struct {
	Name        string  `json:"name"`
	Description string  `json:"description,omitempty"`
	Weight      float64 `json:"weight,omitempty"`
	Threshold   float64 `json:"threshold,omitempty"`
}

type judgeThresholdDirection string

const (
	thresholdGTE judgeThresholdDirection = "gte"
	thresholdGT  judgeThresholdDirection = "gt"
	thresholdLTE judgeThresholdDirection = "lte"
	thresholdLT  judgeThresholdDirection = "lt"
)

// LLMJudgeDriver evaluates prompts and responses against a configurable rubric using an
// internal ChatExecutor model call with non-spoofable loop prevention.
type LLMJudgeDriver struct {
	guardrailName      string
	guardrailID        string
	hooks              []domain.GuardrailHook
	model              string
	systemPrompt       string
	criteria           []JudgeCriterion
	threshold          float64
	thresholdDirection judgeThresholdDirection
	temperature        float64
	maxTokens          int
	action             domain.GuardrailAction
	executor           ChatExecutor
}

// NewLLMJudgeDriver constructs an LLMJudgeDriver from cfg and an injected ChatExecutor.
func NewLLMJudgeDriver(cfg guardrails.DriverConfig, executor ChatExecutor) (*LLMJudgeDriver, error) {
	model := configString(cfg, "model", "judge_model", "model_name")
	if model == "" {
		return nil, fmt.Errorf("%s driver requires model", ProviderLLMJudge)
	}

	criteria, err := parseJudgeCriteria(cfg)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ProviderLLMJudge, err)
	}

	threshold := configFloat(cfg, defaultJudgeThreshold, "threshold", "score_threshold", "min_score", "pass_threshold")
	if math.IsNaN(threshold) || math.IsInf(threshold, 0) || threshold < 0 || threshold > 100 {
		return nil, fmt.Errorf("%s: threshold must be between 0 and 100, got %v", ProviderLLMJudge, threshold)
	}

	dir, err := parseThresholdDirection(configString(cfg, "threshold_direction", "pass_condition", "score_direction", "score_mode"))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ProviderLLMJudge, err)
	}

	temperature := configFloat(cfg, defaultJudgeTemperature, "temperature")
	maxTokens := configInt(cfg, defaultJudgeMaxTokens, "max_tokens")
	if maxTokens <= 0 {
		maxTokens = defaultJudgeMaxTokens
	}

	return &LLMJudgeDriver{
		guardrailName:      guardrailName(cfg, ProviderLLMJudge),
		guardrailID:        guardrailID(cfg),
		hooks:              resolveJudgeHooks(cfg),
		model:              model,
		systemPrompt:       configString(cfg, "system_prompt", "prompt", "instructions"),
		criteria:           criteria,
		threshold:          threshold,
		thresholdDirection: dir,
		temperature:        temperature,
		maxTokens:          maxTokens,
		action:             effectiveAction(cfg, domain.GuardrailActionBlock),
		executor:           executor,
	}, nil
}

// Name returns the configured guardrail name or provider identifier.
func (d *LLMJudgeDriver) Name() string {
	return d.guardrailName
}

// SupportedHooks returns the lifecycle hooks evaluated by this judge driver.
func (d *LLMJudgeDriver) SupportedHooks() []domain.GuardrailHook {
	return slices.Clone(d.hooks)
}

type llmJudgeVerdict struct {
	Score          *float64           `json:"score"`
	Passed         *bool              `json:"passed"`
	Blocked        *bool              `json:"blocked"`
	Reason         string             `json:"reason"`
	CriteriaScores map[string]float64 `json:"criteria_scores"`
	RevisedOutput  string             `json:"revised_output"`
}

// Evaluate scores the input using the configured judge model and rubric criteria.
func (d *LLMJudgeDriver) Evaluate(ctx context.Context, input *domain.GuardrailEvalInput) (*domain.GuardrailEvalResult, error) {
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
		return nil, fmt.Errorf("%s driver requires a configured ChatExecutor", ProviderLLMJudge)
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
		return nil, fmt.Errorf("%s execution failed: %w", ProviderLLMJudge, err)
	}

	rawText := extractChatResponseText(resp)
	jsonBytes, err := extractJSONObject(rawText)
	if err != nil {
		return nil, fmt.Errorf("%s invalid judge response: %w", ProviderLLMJudge, err)
	}

	var verdict llmJudgeVerdict
	if err := json.Unmarshal(jsonBytes, &verdict); err != nil {
		return nil, fmt.Errorf("%s decode verdict JSON: %w", ProviderLLMJudge, err)
	}

	finalScore, hasScore, failedCriterion, err := d.computeVerdictScore(&verdict)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", ProviderLLMJudge, err)
	}

	var passed bool
	switch {
	case failedCriterion != "":
		passed = false
	case hasScore:
		passed = compareThreshold(finalScore, d.threshold, d.thresholdDirection)
	case verdict.Passed != nil:
		passed = *verdict.Passed
	case verdict.Blocked != nil:
		passed = !*verdict.Blocked
	default:
		return nil, fmt.Errorf("%s verdict JSON missing score and pass/block boolean", ProviderLLMJudge)
	}

	if passed {
		return &domain.GuardrailEvalResult{
			Decision:          domain.GuardrailDecisionAllow,
			AppliedGuardrails: []string{d.guardrailName},
			UsageUnits:        usageUnits,
		}, nil
	}

	reason := strings.TrimSpace(verdict.Reason)
	if reason == "" {
		if failedCriterion != "" {
			reason = fmt.Sprintf("LLM judge criterion %q fell below required threshold", failedCriterion)
		} else if hasScore {
			reason = fmt.Sprintf("LLM judge score %.2f failed threshold %.2f", finalScore, d.threshold)
		} else {
			reason = "Content rejected by LLM judge policy"
		}
	}

	var scorePtr *float64
	if hasScore {
		s := finalScore
		scorePtr = &s
	}

	severity := "high"
	if d.action == domain.GuardrailActionAudit {
		severity = "medium"
	}

	details := map[string]any{
		"model":     d.model,
		"threshold": d.threshold,
	}
	if hasScore {
		details["score"] = finalScore
	}
	if len(verdict.CriteriaScores) > 0 {
		details["criteria_scores"] = verdict.CriteriaScores
	}
	if failedCriterion != "" {
		details["failed_criterion"] = failedCriterion
	}

	ruleName := "rubric_threshold"
	if failedCriterion != "" {
		ruleName = failedCriterion
	}

	violation := domain.GuardrailViolation{
		GuardrailName: d.guardrailName,
		GuardrailID:   d.guardrailID,
		Provider:      ProviderLLMJudge,
		Category:      "llm_judge",
		Rule:          ruleName,
		Severity:      severity,
		Message:       reason,
		Score:         scorePtr,
		Action:        d.action,
		Details:       details,
	}

	switch d.action {
	case domain.GuardrailActionAudit:
		violation.Decision = domain.GuardrailDecisionFlag
		return &domain.GuardrailEvalResult{
			Decision:          domain.GuardrailDecisionFlag,
			Violations:        []domain.GuardrailViolation{violation},
			AppliedGuardrails: []string{d.guardrailName},
			UsageUnits:        usageUnits,
		}, nil
	case domain.GuardrailActionRedact:
		if strings.TrimSpace(verdict.RevisedOutput) != "" {
			violation.Decision = domain.GuardrailDecisionModify
			return &domain.GuardrailEvalResult{
				Decision:          domain.GuardrailDecisionModify,
				ModifiedTexts:     buildJudgeModifiedTexts(input, verdict.RevisedOutput),
				Violations:        []domain.GuardrailViolation{violation},
				AppliedGuardrails: []string{d.guardrailName},
				UsageUnits:        usageUnits,
			}, nil
		}
		// Fall through to block when modify action is configured but no revised output was supplied.
		fallthrough
	default:
		violation.Decision = domain.GuardrailDecisionBlock
		return &domain.GuardrailEvalResult{
			Decision:          domain.GuardrailDecisionBlock,
			Violations:        []domain.GuardrailViolation{violation},
			AppliedGuardrails: []string{d.guardrailName},
			UsageUnits:        usageUnits,
			ErrorMessage:      reason,
		}, nil
	}
}

func (d *LLMJudgeDriver) buildSystemPrompt() string {
	var sb strings.Builder
	if d.systemPrompt != "" {
		sb.WriteString(d.systemPrompt)
		sb.WriteString("\n\n")
	} else {
		sb.WriteString("You are a strict AI safety and policy compliance judge. Evaluate the provided content against the rubric below.\n\n")
	}

	if len(d.criteria) > 0 {
		sb.WriteString("Evaluation rubric criteria (score each 0 to 100):\n")
		for _, c := range d.criteria {
			sb.WriteString(fmt.Sprintf("- %s (weight=%.2f)", c.Name, c.Weight))
			if c.Description != "" {
				sb.WriteString(": " + c.Description)
			}
			if c.Threshold > 0 {
				sb.WriteString(fmt.Sprintf(" [min_threshold=%.2f]", c.Threshold))
			}
			sb.WriteString("\n")
		}
		sb.WriteString("\n")
	}

	sb.WriteString(fmt.Sprintf("Overall passing threshold: %.2f on a 0-100 scale (condition: %s).\n", d.threshold, d.thresholdDirection))
	sb.WriteString(`Respond ONLY with a single valid JSON object matching this schema:
{"score": <number 0-100>, "passed": <boolean>, "blocked": <boolean>, "reason": "<brief explanation>", "criteria_scores": {"<criterion_name>": <number 0-100>}, "revised_output": "<optional safe rewritten text>"}`)
	return sb.String()
}

func (d *LLMJudgeDriver) computeVerdictScore(verdict *llmJudgeVerdict) (score float64, hasScore bool, failedCriterion string, err error) {
	if verdict == nil {
		return 0, false, "", fmt.Errorf("empty verdict")
	}

	if verdict.Score != nil {
		if math.IsNaN(*verdict.Score) || math.IsInf(*verdict.Score, 0) {
			return 0, false, "", fmt.Errorf("judge returned non-finite score")
		}
	}

	if len(d.criteria) > 0 && len(verdict.CriteriaScores) > 0 {
		var weightedSum, totalWeight float64
		matched := 0
		for _, c := range d.criteria {
			cs, ok := lookupScoreCaseInsensitive(verdict.CriteriaScores, c.Name)
			if !ok {
				continue
			}
			if math.IsNaN(cs) || math.IsInf(cs, 0) {
				return 0, false, "", fmt.Errorf("judge returned non-finite score for criterion %q", c.Name)
			}
			cs = clampScore0To100(cs)
			if c.Threshold > 0 && !compareThreshold(cs, c.Threshold, d.thresholdDirection) && failedCriterion == "" {
				failedCriterion = c.Name
			}
			w := c.Weight
			if w <= 0 {
				w = 1.0
			}
			weightedSum += cs * w
			totalWeight += w
			matched++
		}
		if matched > 0 && totalWeight > 0 && (matched == len(d.criteria) || verdict.Score == nil) {
			return clampScore0To100(weightedSum / totalWeight), true, failedCriterion, nil
		}
	}

	if verdict.Score != nil {
		return clampScore0To100(*verdict.Score), true, failedCriterion, nil
	}
	return 0, false, failedCriterion, nil
}

func clampScore0To100(s float64) float64 {
	if s < 0 {
		return 0
	}
	if s > 100 {
		return 100
	}
	return s
}

func parseJudgeCriteria(cfg guardrails.DriverConfig) ([]JudgeCriterion, error) {
	cm := configMap(cfg)
	raw, ok := lookupAnyCaseInsensitive(cm, "criteria")
	if !ok {
		raw, ok = lookupAnyCaseInsensitive(cm, "rubric")
	}
	if !ok || raw == nil {
		return nil, nil
	}

	var out []JudgeCriterion
	switch items := raw.(type) {
	case []JudgeCriterion:
		out = slices.Clone(items)
	case []string:
		for _, s := range items {
			if name := strings.TrimSpace(s); name != "" {
				out = append(out, JudgeCriterion{Name: name, Weight: 1.0})
			}
		}
	default:
		b, err := json.Marshal(raw)
		if err != nil {
			return nil, fmt.Errorf("marshal criteria: %w", err)
		}
		if err := json.Unmarshal(b, &out); err != nil {
			var names []string
			if errStr := json.Unmarshal(b, &names); errStr == nil {
				for _, s := range names {
					if name := strings.TrimSpace(s); name != "" {
						out = append(out, JudgeCriterion{Name: name, Weight: 1.0})
					}
				}
			} else {
				return nil, fmt.Errorf("decode criteria: %w", err)
			}
		}
	}

	for i := range out {
		out[i].Name = strings.TrimSpace(out[i].Name)
		out[i].Description = strings.TrimSpace(out[i].Description)
		if out[i].Name == "" {
			return nil, fmt.Errorf("criteria[%d] requires non-empty name", i)
		}
		if out[i].Weight < 0 || math.IsNaN(out[i].Weight) || math.IsInf(out[i].Weight, 0) {
			return nil, fmt.Errorf("criteria[%d] (%q) weight must be non-negative", i, out[i].Name)
		}
		if out[i].Weight == 0 {
			out[i].Weight = 1.0
		}
	}
	return out, nil
}

func parseThresholdDirection(raw string) (judgeThresholdDirection, error) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "", "gte", ">=", "min", "at_least":
		return thresholdGTE, nil
	case "gt", ">", "above":
		return thresholdGT, nil
	case "lte", "<=", "max", "at_most", "risk":
		return thresholdLTE, nil
	case "lt", "<", "below":
		return thresholdLT, nil
	default:
		return "", fmt.Errorf("unsupported threshold_direction %q", raw)
	}
}

func compareThreshold(score, threshold float64, dir judgeThresholdDirection) bool {
	switch dir {
	case thresholdGT:
		return score > threshold
	case thresholdLTE:
		return score <= threshold
	case thresholdLT:
		return score < threshold
	default:
		return score >= threshold
	}
}

func resolveJudgeHooks(cfg guardrails.DriverConfig) []domain.GuardrailHook {
	if cfg.Definition != nil && len(cfg.Definition.EventHooks) > 0 {
		return slices.Clone(cfg.Definition.EventHooks)
	}
	return defaultTextHooks()
}

func hasJudgeableContent(input *domain.GuardrailEvalInput) bool {
	if input == nil {
		return false
	}
	return hasNonEmptyText(extractTexts(input)) || len(input.ToolCalls) > 0
}

func buildJudgeModifiedTexts(input *domain.GuardrailEvalInput, revised string) []string {
	if input == nil || len(input.Texts) <= 1 {
		return []string{revised}
	}
	out := slices.Clone(input.Texts)
	for i := len(out) - 1; i >= 0; i-- {
		if strings.TrimSpace(out[i]) != "" {
			out[i] = revised
			return out
		}
	}
	out[len(out)-1] = revised
	return out
}

func executeJudgeChat(
	ctx context.Context,
	executor ChatExecutor,
	model string,
	temperature float64,
	maxTokens int,
	systemPrompt string,
	userPrompt string,
	input *domain.GuardrailEvalInput,
) (*domain.CanonicalChatResponse, int64, error) {
	if executor == nil {
		return nil, 0, fmt.Errorf("chat executor is nil")
	}

	subCtx := WithInternalGuardrailOrigin(ctx)
	var idCtx *domain.IdentityContext
	var reqID string
	if input != nil {
		idCtx = &domain.IdentityContext{
			OrgID:        input.OrgID,
			TeamID:       input.TeamID,
			VirtualKeyID: input.VirtualKeyID,
			UserID:       input.EndUserID,
		}
		if input.RequestID != "" {
			reqID = input.RequestID + "-guardrail-judge"
		}
	}

	temp := temperature
	maxTok := maxTokens
	req := &domain.CanonicalChatRequest{
		RequestID: reqID,
		Model:     model,
		Messages: []domain.CanonicalMessage{
			{Role: "system", Content: systemPrompt},
			{Role: "user", Content: userPrompt},
		},
		Temperature:    &temp,
		MaxTokens:      &maxTok,
		ResponseFormat: &domain.ResponseFormat{Type: "json_object"},
	}

	resp, err := executor.ExecuteChat(subCtx, idCtx, req)
	if err != nil {
		return nil, 0, err
	}
	return resp, extractChatUsageUnits(resp), nil
}

func formatEvalInputForJudge(input *domain.GuardrailEvalInput) string {
	if input == nil {
		return ""
	}
	var sb strings.Builder
	dir := input.Direction
	if dir == "" {
		if isOutputDirection(input) {
			dir = domain.GuardrailDirectionOutput
		} else {
			dir = domain.GuardrailDirectionInput
		}
	}
	sb.WriteString(fmt.Sprintf("Direction: %s\n", dir))
	if input.Hook != "" {
		sb.WriteString(fmt.Sprintf("Hook: %s\n", input.Hook))
	}
	if input.Model != "" {
		sb.WriteString(fmt.Sprintf("Target Model: %s\n", input.Model))
	}

	if len(input.StructuredMessages) > 0 {
		sb.WriteString("Messages:\n")
		for _, msg := range input.StructuredMessages {
			text := msg.Content
			if text == "" {
				var partsSB strings.Builder
				for _, p := range msg.Parts {
					if p.Type == "text" {
						partsSB.WriteString(p.Text)
					}
				}
				text = partsSB.String()
			}
			role := msg.Role
			if role == "" {
				role = "user"
			}
			sb.WriteString(fmt.Sprintf("[%s]: %s\n", role, text))
		}
	} else if texts := extractTexts(input); len(texts) > 0 {
		sb.WriteString("Content:\n")
		sb.WriteString(joinedNonEmptyText(texts))
		sb.WriteString("\n")
	}

	if len(input.ToolCalls) > 0 {
		if b, err := json.Marshal(input.ToolCalls); err == nil {
			sb.WriteString("Tool Calls:\n")
			sb.Write(b)
			sb.WriteString("\n")
		}
	}
	return sb.String()
}

func extractChatResponseText(resp *domain.CanonicalChatResponse) string {
	if resp == nil || len(resp.Choices) == 0 {
		return ""
	}
	msg := resp.Choices[0].Message
	if strings.TrimSpace(msg.Content) != "" {
		return msg.Content
	}
	var sb strings.Builder
	for _, p := range msg.Parts {
		if p.Type == "text" {
			sb.WriteString(p.Text)
		}
	}
	return sb.String()
}

func extractChatUsageUnits(resp *domain.CanonicalChatResponse) int64 {
	if resp != nil {
		if resp.Usage.TotalTokens > 0 {
			return int64(resp.Usage.TotalTokens)
		}
		if sum := resp.Usage.PromptTokens + resp.Usage.CompletionTokens; sum > 0 {
			return int64(sum)
		}
	}
	return 1
}

func extractJSONObject(raw string) ([]byte, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return nil, fmt.Errorf("empty model response")
	}

	// Strip surrounding markdown code fences if the model wrapped JSON.
	if strings.HasPrefix(trimmed, "```") {
		if idx := strings.Index(trimmed, "\n"); idx >= 0 {
			trimmed = trimmed[idx+1:]
		} else {
			trimmed = strings.TrimPrefix(trimmed, "```json")
			trimmed = strings.TrimPrefix(trimmed, "```")
		}
		if end := strings.LastIndex(trimmed, "```"); end >= 0 {
			trimmed = trimmed[:end]
		}
		trimmed = strings.TrimSpace(trimmed)
	}

	if json.Valid([]byte(trimmed)) && strings.HasPrefix(trimmed, "{") {
		return []byte(trimmed), nil
	}

	start := strings.IndexByte(trimmed, '{')
	end := strings.LastIndexByte(trimmed, '}')
	if start >= 0 && end > start {
		candidate := trimmed[start : end+1]
		if json.Valid([]byte(candidate)) {
			return []byte(candidate), nil
		}
	}
	return nil, fmt.Errorf("response does not contain valid JSON object")
}

// Compile-time interface assertion.
var _ guardrails.Driver = (*LLMJudgeDriver)(nil)
