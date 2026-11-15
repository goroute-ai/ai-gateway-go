// Command gateway runs the GoRoute AI Gateway HTTP and gRPC server.
//
// It loads configuration, validates production security settings, wires storage,
// Redis, provider adapters, routing, guardrails, MCP, and A2A subsystems, and
// manages graceful shutdown or one-shot database migrations (-migrate-only) and
// readiness healthchecks (-healthcheck).
package main
