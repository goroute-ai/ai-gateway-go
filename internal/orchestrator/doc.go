// Package orchestrator coordinates multi-turn model tool execution server-side.
//
// In autonomous AI agent workflows, models emit function call requests that require
// tool invocation, result capture, message history expansion, and recursive re-invocation
// until a terminal completion response is generated. The ToolLoopOrchestrator automates
// this entire lifecycle server-side while enforcing strict enterprise safety budgets
// and single-billing FinOps ledger consolidation.
//
// Key Responsibilities:
//   - Multi-Turn Autonomous Tool Loop: Intercepts tool_calls in model responses, executes
//     requested tools via the MCP Hub, formats tool outputs into canonical role_tool messages,
//     and continues inference recursively up to a configurable maximum round ceiling.
//   - Strict Safety & Budget Guards: Enforces max loop rounds (default: 5), cumulative timeout
//     (default: 60s), per-tool timeout (default: 10s), tool output truncation (default: 512 KB),
//     and optional spend caps (MaxSpendMicros).
//   - Anti-Double-Billing FinOps Accounting: Accurately accumulates token counts across all
//     inference turns and debits the organization ledger in PostgreSQL as a single consolidated
//     spend transaction, guaranteeing zero float drift and zero double-charging.
//   - Zero-Buffer Streaming Support: Transparently pipes intermediate tool execution events
//     and final synthesized response chunks across active HTTP SSE streams.
package orchestrator
