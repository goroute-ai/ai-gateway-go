// Package guardrails provides GoRoute's two-layer AI safety engine, multi-provider
// guardrail pipeline, streaming window sanitizers, and MCP/tool governance controls.
//
// Capabilities:
//   - Layer 0 Baseline Policy (Engine): Local prompt injection, PII (email, SSN, Luhn card),
//     secret leak, blocked keyword, and 5-category toxicity filtering with enforce/logging_only modes.
//   - Layer 1 Pipeline v2 (Pipeline, Resolver, RouterLB): Named multi-tenant guardrail registry
//     with Org/Team/Key/EndUser/ModelGroup/Tag bindings, anti-bypass locks, ModeRule tag routing,
//     weighted load balancing with circuit cooldowns, and all 7 lifecycle hooks (pre_call,
//     parallel during_call cancellation, post_call, logging_only, pre_mcp_call, during_mcp_call,
//     and post_mcp_call).
//   - Extensible Driver Registry (internal/guardrails/drivers): Built-in drivers covering
//     local/regex filters, sandboxed Starlark custom_code, SSRF-enforced generic_http webhooks,
//     external/OSS engines (OpenAI Moderation, Microsoft Presidio, Lakera v2, Guardrails AI,
//     Pangea), internal llm_as_a_judge / decision_model, and tool/MCP governance
//     (tool_permission, tool_policy cross-turn taint tracking, block_code_execution, mcp_security,
//     mcp_end_user_permission).
//   - Streaming Protection (StreamRedactor, StreamWindowEvaluator): Bounded rolling-overlap SSE
//     chunk sanitization and streamed tool_calls JSON delta scanning.
//   - MCP Hardening: Anti-tool-poisoning discovery scanning, SHA-256 tool pinning, and argument/result
//     sanitization.
package guardrails
