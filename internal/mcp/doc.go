// Package mcp implements the Model Context Protocol (MCP) gateway engine.
//
// The engine supports the modern MCP 2026-07-28 stateless Streamable HTTP protocol specification,
// alongside a stateful compatibility adapter for legacy 2025-11-25 streamable servers.
//
// Key Subsystems:
//   - Stateless Streamable HTTP Transport (2026-07-28): Zero protocol-level initialization handshake,
//     zero Mcp-Session-Id affinity requirements, and direct POST routing.
//   - Stateful Compatibility Adapter (2025-11-25): Session management via Redis session maps,
//     heartbeat tracking, TTL enforcement, and principal digest validation.
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
