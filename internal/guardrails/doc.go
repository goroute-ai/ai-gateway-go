// Package guardrails implements GoRoute's built-in content safety engine, streaming
// redactor, MCP tool poisoning/pinning checks, and unified external guardrail pipeline.
//
// Core responsibilities:
//   - Built-in local Engine (prompt injection, PII detection & masking, secret leak
//     prevention, blocked keywords/regex patterns, and embedded toxicity packs).
//   - Bounded rolling-overlap SSE StreamRedactor for safe streaming output redaction.
//   - Unified Pipeline executing organization policies and enabled external/SDK drivers
//     across pre_call, post_call, and logging_only hooks with fail-closed defaults.
package guardrails
