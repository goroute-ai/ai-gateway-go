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
	if len(tool.Description) > 16384 {
		return &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "tool_poisoning_detected",
			Message:    "Tool description exceeds maximum permitted length of 16KB (context flooding protection)",
		}
	}

	schemaBytes, _ := json.Marshal(tool.InputSchema)
	if len(schemaBytes) > 65536 {
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
	if pol == nil {
		return outcome, nil
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
	if pol == nil {
		return outcome, result, nil
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
	loggingOnly := pol.EffectiveMode() == domain.GuardrailModeLoggingOnly

	if err := evaluateLocalOutputField(pol, loggingOnly, &resultStr, outcome); err != nil {
		return outcome, nil, err
	}

	if outcome.Redacted {
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
