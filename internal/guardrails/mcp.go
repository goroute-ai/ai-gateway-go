package guardrails

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

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

	// 1. Custom Blocked Keywords
	for _, kw := range pol.BlockedKeywords {
		kwTrim := strings.TrimSpace(kw)
		if kwTrim != "" && strings.Contains(lower, strings.ToLower(kwTrim)) {
			outcome.Violations = append(outcome.Violations, "blocked_keyword:"+kwTrim)
			outcome.AppliedAction = domain.GuardrailActionBlock
			return outcome, nil, &domain.GatewayError{
				StatusCode: http.StatusBadGateway,
				Type:       domain.ErrorTypeServer,
				Code:       "guardrail_blocked_keyword",
				Message:    fmt.Sprintf("Tool result blocked by organization guardrail policy (restricted keyword: %q)", kwTrim),
			}
		}
	}

	mutated := false

	// 2. Secret detection (block, redact, or audit)
	if (pol.RedactOutputPII || pol.EnableSecretDetection) && reSecret.MatchString(resultStr) {
		outcome.Violations = append(outcome.Violations, "secret_leakage")
		if pol.EnableSecretDetection && pol.SecretAction == domain.GuardrailActionBlock {
			outcome.AppliedAction = domain.GuardrailActionBlock
			return outcome, nil, &domain.GatewayError{
				StatusCode: http.StatusBadGateway,
				Type:       domain.ErrorTypeServer,
				Code:       "guardrail_secret_detected",
				Message:    "Tool result blocked by security guardrail: sensitive API key or credential detected",
			}
		}
		if pol.RedactOutputPII || pol.SecretAction == "" || pol.SecretAction == domain.GuardrailActionRedact {
			resultStr = reSecret.ReplaceAllString(resultStr, "[REDACTED_SECRET]")
			mutated = true
		} else {
			outcome.AppliedAction = pol.SecretAction
		}
	}

	// 3. PII detection (block, redact, or audit)
	if pol.RedactOutputPII || pol.EnablePIIDetection {
		hasEmail := reEmail.MatchString(resultStr)
		hasSSN := reSSN.MatchString(resultStr)
		hasCard := reCard.MatchString(resultStr)
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
			if pol.EnablePIIDetection && pol.PIIAction == domain.GuardrailActionBlock {
				outcome.AppliedAction = domain.GuardrailActionBlock
				return outcome, nil, &domain.GatewayError{
					StatusCode: http.StatusBadGateway,
					Type:       domain.ErrorTypeServer,
					Code:       "guardrail_pii_detected",
					Message:    "Tool result blocked by security guardrail: PII (email, SSN, or payment card) detected",
				}
			}
			if pol.RedactOutputPII || pol.PIIAction == "" || pol.PIIAction == domain.GuardrailActionRedact {
				resultStr = reEmail.ReplaceAllString(resultStr, "[REDACTED_EMAIL]")
				resultStr = reSSN.ReplaceAllString(resultStr, "[REDACTED_SSN]")
				resultStr = reCard.ReplaceAllString(resultStr, "[REDACTED_CARD]")
				mutated = true
			} else {
				outcome.AppliedAction = pol.PIIAction
			}
		}
	}

	// 4. Optional external scanners
	if err := e.scanText(ctx, orgID, ScanOutput, resultStr); err != nil {
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
