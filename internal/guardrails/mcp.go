package guardrails

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"sync"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

var mcpPoisonSignatures = []string{
	"ignore previous instructions",
	"ignore all prior instructions",
	"system prompt override",
	"disregard your system prompt",
	"reveal your system prompt",
	"bypass all safety",
	"<|im_start|>system",
	"you are now dan",
	"<script",
	"javascript:",
	"\u202e", // Right-to-Left Override (Trojan Source attack)
	"\u202b", // Right-to-Left Embedding
}

// ComputeToolDefinitionHash generates a deterministic SHA-256 digest of an MCP tool definition.
func ComputeToolDefinitionHash(name, description string, inputSchema map[string]any) string {
	schemaBytes, _ := json.Marshal(inputSchema)
	h := sha256.New()
	fmt.Fprintf(h, "name:%s|desc:%s|schema:%s", name, description, string(schemaBytes))
	return hex.EncodeToString(h.Sum(nil))
}

// VerifyToolPinning verifies that an active tool's definition matches the pinned SHA-256 hash.
func (e *Engine) VerifyToolPinning(tool *domain.MCPTool, pinnedHash string) error {
	if tool == nil || pinnedHash == "" {
		return nil
	}

	actualHash := ComputeToolDefinitionHash(tool.Name, tool.Description, tool.InputSchema)
	if actualHash != pinnedHash {
		return &domain.GatewayError{
			StatusCode: http.StatusForbidden,
			Type:       domain.ErrorTypePermission,
			Code:       "tool_hash_mismatch",
			Message:    fmt.Sprintf("Tool %q definition hash (%s) does not match pinned security hash (%s)", tool.Name, actualHash, pinnedHash),
		}
	}
	return nil
}

// ScanMCPToolDiscovery scans an incoming tool definition for adversarial poisoning, prompt injection,
// and excessive context flooding during discovery sync.
func (e *Engine) ScanMCPToolDiscovery(tool *domain.MCPTool) error {
	if tool == nil {
		return nil
	}

	// 1. Length checks (anti-context flooding)
	if len(tool.Name) > 256 {
		return &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "tool_poisoning_detected",
			Message:    "Tool name exceeds maximum permitted length of 256 bytes",
		}
	}
	if len(tool.Description) > 16384 { // 16KB max description
		return &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "tool_poisoning_detected",
			Message:    "Tool description exceeds maximum permitted length of 16KB (context flooding protection)",
		}
	}

	schemaBytes, _ := json.Marshal(tool.InputSchema)
	if len(schemaBytes) > 65536 { // 64KB max inputSchema
		return &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "tool_poisoning_detected",
			Message:    "Tool input schema exceeds maximum permitted length of 64KB",
		}
	}

	// 2. Anti-Tool-Poisoning & Prompt Injection scanning
	contentToScan := strings.ToLower(tool.Name + " " + tool.Description + " " + string(schemaBytes))
	for _, sig := range mcpPoisonSignatures {
		if strings.Contains(contentToScan, sig) {
			return &domain.GatewayError{
				StatusCode: http.StatusForbidden,
				Type:       domain.ErrorTypePermission,
				Code:       "tool_poisoning_detected",
				Message:    fmt.Sprintf("Adversarial signature %q detected in tool %q definition", sig, tool.Name),
			}
		}
	}

	return nil
}

// EvaluateMCPToolCall inspects tool invocation arguments against organization guardrails.
func (e *Engine) EvaluateMCPToolCall(
	ctx context.Context,
	orgID string,
	toolName string,
	arguments map[string]any,
) (*CheckOutcome, error) {
	outcome := &CheckOutcome{}
	if e == nil || e.repo == nil || orgID == "" {
		return nil, policyUnavailableError()
	}

	pol, err := e.repo.GetGuardrailPolicy(ctx, orgID)
	if err != nil {
		return nil, policyUnavailableError()
	}
	if pol == nil && len(e.scanners) == 0 {
		return outcome, nil
	}
	if pol == nil {
		pol = &domain.GuardrailPolicy{OrgID: orgID}
	}

	argsBytes, err := json.Marshal(arguments)
	if err != nil {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "guardrail_invalid_payload",
			Message:    fmt.Sprintf("Failed to serialize arguments for tool %q for guardrail evaluation", toolName),
		}
	}

	probe := &domain.CanonicalChatRequest{
		Messages: []domain.CanonicalMessage{{
			Role:    "user",
			Content: string(argsBytes),
		}},
	}
	outcome, err = e.EvaluateInputWithPolicy(ctx, pol, probe)
	if err != nil {
		return outcome, err
	}

	if outcome != nil && outcome.Redacted && arguments != nil {
		var redactedMap map[string]any
		if err := json.Unmarshal([]byte(probe.Messages[0].Content), &redactedMap); err != nil {
			return outcome, &domain.GatewayError{
				StatusCode: http.StatusBadRequest,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "guardrail_redaction_failed",
				Message:    fmt.Sprintf("Failed to apply guardrail redaction to arguments for tool %q", toolName),
			}
		}
		for k := range arguments {
			delete(arguments, k)
		}
		for k, v := range redactedMap {
			arguments[k] = v
		}
	}

	return outcome, nil
}

// EvaluateMCPToolResult inspects and optionally redacts sensitive tool execution results.
func (e *Engine) EvaluateMCPToolResult(
	ctx context.Context,
	orgID string,
	result any,
) (*CheckOutcome, any, error) {
	outcome := &CheckOutcome{}
	if result == nil {
		return outcome, result, nil
	}
	if e == nil || e.repo == nil || orgID == "" {
		return nil, nil, policyUnavailableError()
	}

	pol, err := e.repo.GetGuardrailPolicy(ctx, orgID)
	if err != nil {
		return nil, nil, policyUnavailableError()
	}
	if pol == nil && len(e.scanners) == 0 {
		return outcome, result, nil
	}
	if pol == nil {
		pol = &domain.GuardrailPolicy{OrgID: orgID}
	}

	resultBytes, err := json.Marshal(result)
	if err != nil {
		return nil, nil, &domain.GatewayError{
			StatusCode: http.StatusBadGateway,
			Type:       domain.ErrorTypeServer,
			Code:       "guardrail_invalid_payload",
			Message:    "Failed to serialize tool result for guardrail evaluation",
		}
	}
	resultStr := string(resultBytes)
	lower := strings.ToLower(resultStr)
	loggingOnly := pol.EffectiveMode() == domain.GuardrailModeLoggingOnly

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
			return outcome, nil, &domain.GatewayError{
				StatusCode: http.StatusBadGateway,
				Type:       domain.ErrorTypeServer,
				Code:       "guardrail_blocked_keyword",
				Message:    fmt.Sprintf("Tool result blocked by organization guardrail policy (restricted keyword: %q)", kwTrim),
			}
		}
	}

	// 2. Built-in Toxicity & Content Filtering
	if err := evaluateToxicity(pol, loggingOnly, &resultStr, true, outcome); err != nil {
		return outcome, nil, err
	}
	mutated := outcome.Redacted

	// 3. Secret detection (block, redact, or audit)
	if (pol.RedactOutputPII || pol.EnableSecretDetection) && reSecret.MatchString(resultStr) {
		outcome.Violations = append(outcome.Violations, "secret_leakage")
		if loggingOnly {
			outcome.AppliedAction = domain.GuardrailActionAudit
		} else if pol.EnableSecretDetection && pol.SecretAction == domain.GuardrailActionBlock {
			outcome.AppliedAction = domain.GuardrailActionBlock
			return outcome, nil, &domain.GatewayError{
				StatusCode: http.StatusBadGateway,
				Type:       domain.ErrorTypeServer,
				Code:       "guardrail_secret_detected",
				Message:    "Tool result blocked by security guardrail: sensitive API key or credential detected",
			}
		} else if pol.RedactOutputPII || pol.SecretAction == "" || pol.SecretAction == domain.GuardrailActionRedact {
			resultStr = reSecret.ReplaceAllString(resultStr, "[REDACTED_SECRET]")
			mutated = true
		} else {
			outcome.AppliedAction = pol.SecretAction
		}
	}

	// 4. PII detection (block, redact, or audit)
	if pol.RedactOutputPII || pol.EnablePIIDetection {
		hasEmail := reEmail.MatchString(resultStr)
		hasSSN := reSSN.MatchString(resultStr)
		hasCard := containsValidCard(resultStr)
		if hasEmail {
			outcome.Violations = append(outcome.Violations, "pii:email")
		}
		if hasSSN {
			outcome.Violations = append(outcome.Violations, "pii:ssn")
		}
		if hasCard {
			outcome.Violations = append(outcome.Violations, "pii:credit_card")
		}
		if hasEmail || hasSSN || hasCard {
			if loggingOnly {
				outcome.AppliedAction = domain.GuardrailActionAudit
			} else if pol.EnablePIIDetection && pol.PIIAction == domain.GuardrailActionBlock {
				outcome.AppliedAction = domain.GuardrailActionBlock
				return outcome, nil, &domain.GatewayError{
					StatusCode: http.StatusBadGateway,
					Type:       domain.ErrorTypeServer,
					Code:       "guardrail_pii_detected",
					Message:    "Tool result blocked by security guardrail: PII (email, SSN, or payment card) detected",
				}
			} else if pol.RedactOutputPII || pol.PIIAction == "" || pol.PIIAction == domain.GuardrailActionRedact {
				resultStr = reEmail.ReplaceAllString(resultStr, "[REDACTED_EMAIL]")
				resultStr = reSSN.ReplaceAllString(resultStr, "[REDACTED_SSN]")
				if next, changed := redactValidCards(resultStr); changed {
					resultStr = next
				}
				mutated = true
			} else {
				outcome.AppliedAction = pol.PIIAction
			}
		}
	}

	// 5. Optional external scanners
	if err := e.scanOutputField(ctx, pol, loggingOnly, resultStr, outcome); err != nil {
		return outcome, nil, err
	}

	if mutated {
		outcome.Redacted = true
		outcome.AppliedAction = domain.GuardrailActionRedact
		var unmarshaled any
		if err := json.Unmarshal([]byte(resultStr), &unmarshaled); err != nil {
			return outcome, nil, &domain.GatewayError{
				StatusCode: http.StatusBadGateway,
				Type:       domain.ErrorTypeServer,
				Code:       "guardrail_redaction_failed",
				Message:    "Failed to reconstruct tool result after guardrail redaction",
			}
		}
		return outcome, unmarshaled, nil
	}

	return outcome, result, nil
}

type oidcClaimsContextKey struct{}

// ContextWithOIDCClaims attaches caller OIDC claims to ctx for downstream MCP permission guardrails.
func ContextWithOIDCClaims(ctx context.Context, claims map[string]any) context.Context {
	if ctx == nil || len(claims) == 0 {
		return ctx
	}
	return context.WithValue(ctx, oidcClaimsContextKey{}, cloneConfigMap(claims))
}

// OIDCClaimsFromContext extracts caller OIDC claims previously attached via ContextWithOIDCClaims.
func OIDCClaimsFromContext(ctx context.Context) map[string]any {
	if ctx == nil {
		return nil
	}
	if claims, ok := ctx.Value(oidcClaimsContextKey{}).(map[string]any); ok {
		return cloneConfigMap(claims)
	}
	return nil
}

// MCPCallContext carries MCP server, tool, and argument metadata for pipeline MCP hook evaluation.
type MCPCallContext struct {
	ServerID    string
	ServerSlug  string
	ServerURL   string
	ToolName    string
	ToolID      string
	ToolDefHash string
	Arguments   map[string]any
}

// Engine returns the legacy Layer 0 Engine bound to this Pipeline, if any.
func (p *Pipeline) Engine() *Engine {
	if p == nil {
		return nil
	}
	return p.engine
}

// BuildMCPInputEvalInput constructs a structured GuardrailEvalInput for pre_mcp_call or during_mcp_call.
func BuildMCPInputEvalInput(hook domain.GuardrailHook, prc PipelineRequestContext, mcpCtx MCPCallContext) *domain.GuardrailEvalInput {
	meta := cloneConfigMap(prc.Metadata)
	if meta == nil {
		meta = make(map[string]any)
	}
	if mcpCtx.ServerID != "" {
		meta["mcp_server_id"] = mcpCtx.ServerID
	}
	if mcpCtx.ServerSlug != "" {
		meta["mcp_server_slug"] = mcpCtx.ServerSlug
		meta["server_label"] = mcpCtx.ServerSlug
	}
	if mcpCtx.ServerURL != "" {
		meta["mcp_server_url"] = mcpCtx.ServerURL
		meta["server_url"] = mcpCtx.ServerURL
	}
	if mcpCtx.ToolName != "" {
		meta["mcp_tool_name"] = mcpCtx.ToolName
		meta["tool_name"] = mcpCtx.ToolName
	}
	if mcpCtx.ToolID != "" {
		meta["mcp_tool_id"] = mcpCtx.ToolID
	}
	if len(prc.CallerRoles) > 0 {
		if _, exists := meta["caller_roles"]; !exists {
			meta["caller_roles"] = slices.Clone(prc.CallerRoles)
		}
	}

	argsMap := mcpCtx.Arguments
	if argsMap == nil {
		argsMap = map[string]any{}
	}
	argsBytes, err := json.Marshal(argsMap)
	argsJSON := "{}"
	if err == nil {
		argsJSON = string(argsBytes)
	}

	return &domain.GuardrailEvalInput{
		Direction:      domain.GuardrailDirectionInput,
		Hook:           hook,
		RequestID:      prc.RequestID,
		TraceID:        prc.TraceID,
		OrgID:          prc.OrgID,
		TeamID:         prc.TeamID,
		VirtualKeyID:   prc.VirtualKeyID,
		EndUserID:      prc.EndUserID,
		Model:          prc.Model,
		Tags:           slices.Clone(prc.Tags),
		Texts:          []string{argsJSON},
		RequestHeaders: cloneStringMap(prc.RequestHeaders),
		Metadata:       meta,
		ToolCalls: []domain.CanonicalToolCall{{
			ID:   prc.RequestID,
			Type: "mcp",
			Function: domain.CanonicalFunctionCall{
				Name:      mcpCtx.ToolName,
				Arguments: argsJSON,
			},
		}},
	}
}

// BuildMCPOutputEvalInput constructs a structured GuardrailEvalInput for post_mcp_call.
func BuildMCPOutputEvalInput(hook domain.GuardrailHook, prc PipelineRequestContext, mcpCtx MCPCallContext, result any) (*domain.GuardrailEvalInput, error) {
	in := BuildMCPInputEvalInput(hook, prc, mcpCtx)
	in.Direction = domain.GuardrailDirectionOutput
	in.ToolCalls = nil

	if result == nil {
		in.Texts = nil
		return in, nil
	}

	resultBytes, err := json.Marshal(result)
	if err != nil {
		return nil, &domain.GatewayError{
			StatusCode: http.StatusBadGateway,
			Type:       domain.ErrorTypeServer,
			Code:       "guardrail_invalid_payload",
			Message:    "Failed to serialize tool result for guardrail evaluation",
		}
	}
	resultStr := string(resultBytes)
	in.Texts = []string{resultStr}
	in.StructuredMessages = []domain.CanonicalMessage{{
		Role:    "tool",
		Name:    mcpCtx.ToolName,
		Content: resultStr,
	}}
	return in, nil
}

// EvaluatePreMCPCall runs Layer 0 Engine MCP call checks followed by resolved pre_mcp_call Drivers.
func (p *Pipeline) EvaluatePreMCPCall(ctx context.Context, prc PipelineRequestContext, mcpCtx *MCPCallContext) (*PipelineOutcome, error) {
	outcome := &PipelineOutcome{
		Result: &domain.GuardrailEvalResult{Decision: domain.GuardrailDecisionAllow},
	}
	if p == nil || mcpCtx == nil {
		return outcome, nil
	}

	// Layer 0: Legacy per-org GuardrailPolicy MCP tool call checks.
	if p.engine != nil && prc.OrgID != "" {
		legacyOut, err := p.engine.EvaluateMCPToolCall(ctx, prc.OrgID, mcpCtx.ToolName, mcpCtx.Arguments)
		outcome.mergeLegacyOutcome(legacyOut)
		if err != nil {
			outcome.Result.Decision = domain.GuardrailDecisionBlock
			outcome.Result.ErrorMessage = err.Error()
			if outcome.AppliedAction == "" {
				outcome.AppliedAction = domain.GuardrailActionBlock
			}
			return outcome, err
		}
	}

	// Layer 1: Resolved pre_mcp_call named guardrails.
	resolved, err := p.ResolveForHook(ctx, prc, domain.GuardrailHookPreMCPCall)
	if err != nil {
		return outcome, policyUnavailableError()
	}
	for _, rg := range resolved {
		evalInput := BuildMCPInputEvalInput(domain.GuardrailHookPreMCPCall, prc, *mcpCtx)
		res, cand, evalErr := p.executeGroup(ctx, rg, evalInput)
		if evalErr != nil {
			outcome.Result.Decision = domain.GuardrailDecisionBlock
			outcome.Result.ErrorMessage = evalErr.Error()
			if outcome.AppliedAction == "" {
				outcome.AppliedAction = domain.GuardrailActionBlock
			}
			return outcome, wrapDriverUnavailableError(rg.Name, evalErr)
		}

		loggingOnly := isCandidateLoggingOnly(cand, res)
		outcome.mergeDriverResult(rg.Name, res, loggingOnly)
		if loggingOnly {
			continue
		}

		switch res.Decision {
		case domain.GuardrailDecisionModify:
			if applyEvalMutationsToMCPArgs(mcpCtx, res) {
				outcome.Redacted = true
				if outcome.AppliedAction == "" {
					outcome.AppliedAction = domain.GuardrailActionRedact
				}
			}
		case domain.GuardrailDecisionBlock:
			outcome.AppliedAction = domain.GuardrailActionBlock
			outcome.Result.Decision = domain.GuardrailDecisionBlock
			return outcome, newMCPBlockedGatewayError(domain.GuardrailHookPreMCPCall, rg.Name, res)
		case domain.GuardrailDecisionFlag:
			if outcome.AppliedAction == "" {
				outcome.AppliedAction = domain.GuardrailActionAudit
			}
		}
	}

	return outcome, nil
}

// StartDuringMCPCall resolves active during_mcp_call guardrails for prc and launches them
// concurrently with upstream MCP dispatch. If any during_mcp_call guardrail blocks or fails closed,
// upstreamCtx is canceled immediately. Returns parentCtx and nil handle if none apply.
func (p *Pipeline) StartDuringMCPCall(parentCtx context.Context, prc PipelineRequestContext, mcpCtx *MCPCallContext) (context.Context, *DuringCallHandle, error) {
	if p == nil || mcpCtx == nil {
		return parentCtx, nil, nil
	}
	resolved, err := p.ResolveForHook(parentCtx, prc, domain.GuardrailHookDuringMCPCall)
	if err != nil {
		return parentCtx, nil, policyUnavailableError()
	}
	if len(resolved) == 0 {
		return parentCtx, nil, nil
	}

	snapshotInput := BuildMCPInputEvalInput(domain.GuardrailHookDuringMCPCall, prc, *mcpCtx)
	upstreamCtx, cancelUpstream := context.WithCancelCause(parentCtx)
	guardrailCtx, cancelGuardrails := context.WithCancel(parentCtx)

	handle := &DuringCallHandle{
		cancelGuardrails: cancelGuardrails,
		done:             make(chan struct{}),
		outcome: &PipelineOutcome{
			Result: &domain.GuardrailEvalResult{Decision: domain.GuardrailDecisionAllow},
		},
	}

	go func() {
		defer close(handle.done)
		defer cancelGuardrails()

		type groupOutcome struct {
			name        string
			res         *domain.GuardrailEvalResult
			err         error
			loggingOnly bool
		}

		results := make([]groupOutcome, len(resolved))
		var wg sync.WaitGroup
		var firstBlockOnce sync.Once

		for i, rg := range resolved {
			wg.Add(1)
			go func(idx int, group ResolvedGuardrail) {
				defer wg.Done()
				res, cand, evalErr := p.executeGroup(guardrailCtx, group, cloneGuardrailEvalInput(snapshotInput))
				if evalErr != nil {
					if guardrailCtx.Err() != nil && parentCtx.Err() == nil {
						return
					}
					gwErr := wrapDriverUnavailableError(group.Name, evalErr)
					results[idx] = groupOutcome{name: group.Name, err: gwErr}
					firstBlockOnce.Do(func() {
						cancelUpstream(gwErr)
						cancelGuardrails()
					})
					return
				}

				loggingOnly := isCandidateLoggingOnly(cand, res)
				results[idx] = groupOutcome{
					name:        group.Name,
					res:         res,
					loggingOnly: loggingOnly,
				}
				if !loggingOnly && res.Decision == domain.GuardrailDecisionBlock {
					gwErr := newMCPBlockedGatewayError(domain.GuardrailHookDuringMCPCall, group.Name, res)
					results[idx].err = gwErr
					firstBlockOnce.Do(func() {
						cancelUpstream(gwErr)
						cancelGuardrails()
					})
				}
			}(i, rg)
		}

		wg.Wait()

		handle.mu.Lock()
		defer handle.mu.Unlock()
		for _, item := range results {
			if item.name == "" && item.err == nil {
				continue
			}
			if item.res != nil {
				handle.outcome.mergeDriverResult(item.name, item.res, item.loggingOnly)
			}
			if item.err != nil && handle.err == nil {
				handle.err = item.err
				handle.outcome.Result.Decision = domain.GuardrailDecisionBlock
				handle.outcome.Result.ErrorMessage = item.err.Error()
				handle.outcome.AppliedAction = domain.GuardrailActionBlock
			}
		}
		if handle.err == nil {
			_ = cancelUpstream
		}
	}()

	return upstreamCtx, handle, nil
}

// EvaluatePostMCPCall runs Layer 0 Engine MCP result checks followed by resolved post_mcp_call Drivers.
func (p *Pipeline) EvaluatePostMCPCall(ctx context.Context, prc PipelineRequestContext, mcpCtx *MCPCallContext, result any) (*PipelineOutcome, any, error) {
	outcome := &PipelineOutcome{
		Result: &domain.GuardrailEvalResult{Decision: domain.GuardrailDecisionAllow},
	}
	if p == nil || result == nil {
		return outcome, result, nil
	}
	var callCtx MCPCallContext
	if mcpCtx != nil {
		callCtx = *mcpCtx
	}

	// Layer 0: Legacy per-org GuardrailPolicy MCP tool result checks.
	if p.engine != nil && prc.OrgID != "" {
		legacyOut, updated, err := p.engine.EvaluateMCPToolResult(ctx, prc.OrgID, result)
		outcome.mergeLegacyOutcome(legacyOut)
		if err != nil {
			outcome.Result.Decision = domain.GuardrailDecisionBlock
			outcome.Result.ErrorMessage = err.Error()
			if outcome.AppliedAction == "" {
				outcome.AppliedAction = domain.GuardrailActionBlock
			}
			return outcome, nil, err
		}
		result = updated
	}

	// Layer 1: Resolved post_mcp_call named guardrails.
	resolved, err := p.ResolveForHook(ctx, prc, domain.GuardrailHookPostMCPCall)
	if err != nil {
		return outcome, nil, policyUnavailableError()
	}
	for _, rg := range resolved {
		evalInput, err := BuildMCPOutputEvalInput(domain.GuardrailHookPostMCPCall, prc, callCtx, result)
		if err != nil {
			return outcome, nil, err
		}
		res, cand, evalErr := p.executeGroup(ctx, rg, evalInput)
		if evalErr != nil {
			outcome.Result.Decision = domain.GuardrailDecisionBlock
			outcome.Result.ErrorMessage = evalErr.Error()
			if outcome.AppliedAction == "" {
				outcome.AppliedAction = domain.GuardrailActionBlock
			}
			return outcome, nil, wrapDriverUnavailableError(rg.Name, evalErr)
		}

		loggingOnly := isCandidateLoggingOnly(cand, res)
		outcome.mergeDriverResult(rg.Name, res, loggingOnly)
		if loggingOnly {
			continue
		}

		switch res.Decision {
		case domain.GuardrailDecisionModify:
			if nextRes, changed := applyEvalMutationsToMCPResult(result, res); changed {
				result = nextRes
				outcome.Redacted = true
				if outcome.AppliedAction == "" {
					outcome.AppliedAction = domain.GuardrailActionRedact
				}
			}
		case domain.GuardrailDecisionBlock:
			outcome.AppliedAction = domain.GuardrailActionBlock
			outcome.Result.Decision = domain.GuardrailDecisionBlock
			return outcome, nil, newMCPBlockedGatewayError(domain.GuardrailHookPostMCPCall, rg.Name, res)
		case domain.GuardrailDecisionFlag:
			if outcome.AppliedAction == "" {
				outcome.AppliedAction = domain.GuardrailActionAudit
			}
		}
	}

	return outcome, result, nil
}

func applyEvalMutationsToMCPArgs(mcpCtx *MCPCallContext, res *domain.GuardrailEvalResult) bool {
	if mcpCtx == nil || res == nil || res.Decision != domain.GuardrailDecisionModify {
		return false
	}
	rawJSON := ""
	if len(res.ModifiedToolCalls) > 0 && strings.TrimSpace(res.ModifiedToolCalls[0].Function.Arguments) != "" {
		rawJSON = res.ModifiedToolCalls[0].Function.Arguments
	} else if len(res.ModifiedTexts) > 0 && strings.TrimSpace(res.ModifiedTexts[0]) != "" {
		rawJSON = res.ModifiedTexts[0]
	}
	if rawJSON == "" {
		return false
	}
	var updated map[string]any
	if err := json.Unmarshal([]byte(rawJSON), &updated); err != nil {
		return false
	}
	if mcpCtx.Arguments == nil {
		mcpCtx.Arguments = updated
		return true
	}
	for k := range mcpCtx.Arguments {
		delete(mcpCtx.Arguments, k)
	}
	for k, v := range updated {
		mcpCtx.Arguments[k] = v
	}
	return true
}

func applyEvalMutationsToMCPResult(orig any, res *domain.GuardrailEvalResult) (any, bool) {
	if res == nil || res.Decision != domain.GuardrailDecisionModify {
		return orig, false
	}
	var raw string
	if len(res.ModifiedMessages) > 0 && res.ModifiedMessages[0].Content != "" {
		raw = res.ModifiedMessages[0].Content
	} else if len(res.ModifiedTexts) > 0 && res.ModifiedTexts[0] != "" {
		raw = res.ModifiedTexts[0]
	}
	if raw == "" {
		return orig, false
	}
	var parsed any
	if err := json.Unmarshal([]byte(raw), &parsed); err == nil {
		return parsed, true
	}
	return raw, true
}

func newMCPBlockedGatewayError(hook domain.GuardrailHook, guardrailName string, res *domain.GuardrailEvalResult) *domain.GatewayError {
	if hook == domain.GuardrailHookPostMCPCall {
		gwErr := newBlockedGatewayError(domain.GuardrailHookPostCall, guardrailName, res)
		gwErr.Message = strings.Replace(gwErr.Message, "Response blocked", "MCP tool result blocked", 1)
		return gwErr
	}
	return newBlockedGatewayError(hook, guardrailName, res)
}
