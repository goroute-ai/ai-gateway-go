// Package guardrails provides security scanners, content filters, and payload sanitizers
// for the GoRoute AI Gateway.
//
// Capabilities:
//   - Anti-Tool-Poisoning Discovery Scanner: Analyzes discovered MCP tool schemas during
//     registration and sync, blocking hidden prompt injection payloads, script tags,
//     and Unicode bidirectional override Trojans (\u202E).
//   - Cryptographic Tool Pinning: Generates deterministic SHA-256 digests of approved tool definitions
//     and halts invocation if an upstream server modifies tool schemas without administrative re-approval.
//   - Input & Output Sanitization: Validates tool invocation arguments, redacts PII from model completions,
//     and scrubs sensitive secrets from outbound request logs.
package guardrails
