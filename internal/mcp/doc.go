// Package mcp implements the Model Context Protocol (MCP) gateway engine.
//
// The engine is code-generated from all 5 official MCP JSON Schema releases
// (2024-11-05, 2025-03-26, 2025-06-18, 2025-11-25, and 2026-07-28) via cmd/mcpgen
// into internal/mcp/spec, with runtime SpecProfile switching controlled via
// GET/PUT /admin/v1/mcp/spec and persisted in mcp_runtime_settings.
//
// Key Subsystems:
//   - Spec-Generated Profiles (SpecProfile & internal/mcp/spec): Embedded Draft-07 and
//     Draft 2020-12 JSON Schema validators, method allowlists, header rules, and result shaping.
//   - Stateless Streamable HTTP Transport (2026-07-28): Zero protocol-level initialization handshake,
//     zero Mcp-Session-Id affinity requirements, server/discover, subscriptions/listen POST SSE, and mirrored headers.
//   - Stateful Streamable Transport (2025-03-26, 2025-06-18, 2025-11-25): Unified session management
//     via Redis session maps (StatefulStreamableTransport), batching rules, TTL enforcement, and principal digest validation.
//   - Legacy 2024-11-05 HTTP+SSE Adapter: Full bidirectional Server-Sent Events transport support
//     for legacy MCP implementations.
//   - Stdio Process Transport & Sandboxing: Secure local subprocess execution with resource limits,
//     environment scrubbing, and strict I/O timeouts.
//   - Virtual Hub Aggregation: Exposes POST /mcp for unified tool discovery across all registered
//     servers with parallel fan-out, namespace prefixing, and partial failure isolation.
//   - Plain MCP REST Bridge: Exposes GET /mcp-rest/tools/list and POST /mcp-rest/tools/call for plain
//     JSON REST clients, decoupling caller architectures from JSON-RPC protocol details.
//   - Progressive Discovery & Opaque Handles: Reduces token consumption by issuing compact 256-bit
//     cryptographic handles (tool_hdl_...) on GET /v1/goroute/mcp/registry, with on-demand schema hydration
//     via search_tools and get_tool_schema meta-tools.
//   - Governed OpenAPI Transport: Dynamically synthesizes MCP tools from standard OpenAPI 3.0/3.1 specs
//     with path parameter interpolation and request schema validation.
//   - Scoped Server & Curated Toolset Routes: Dedicated execution paths via POST /mcp/{serverSlug}
//     and POST /mcp/toolsets/{toolsetSlug}.
//   - Arbitrary Decimal Precision: Preserves high-precision floating point numbers and integer values
//     beyond IEEE-754 53-bit limits using big.Rat and json.Number.
//   - Model-Result-Token-Resumption (MRTR): Single-use AEAD-encrypted continuation tokens bound to
//     caller identity, operation parameters, and execution TTL.
//   - Anti-Poisoning & Tool Pinning: Validates discovered schemas against prompt injection patterns
//     and enforces cryptographic SHA-256 fingerprint matching on tools.
//   - Caching Engine: High-speed HMAC-SHA256 cache with post-cache policy and RBAC re-evaluation.
package mcp
