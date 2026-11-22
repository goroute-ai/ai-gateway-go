// Package a2a implements the OpenAPI-first Linux Foundation Agent-to-Agent (A2A v1.0)
// protocol gateway service backed by docs/openapi/a2a.openapi.yaml and internal/a2a/spec.
//
// Architecture:
//   - Authoritative OpenAPI 3.1.0 Contract (internal/a2a/spec): Provides strongly typed models,
//     Chi ServerInterface routing across all 21 paths / 27 operations, and embedded JSON Schema
//     Draft 2020-12 strict payload validation (`ValidateSchemaStrict` / `DecodeStrict`).
//   - Complete A2A v1.0 Surface: Implements all 11 protocol operations (`SendMessage`,
//     `SendStreamingMessage`, `GetTask`, `ListTasks`, `CancelTask`, `SubscribeToTask`,
//     `CreateTaskPushNotificationConfig`, `GetTaskPushNotificationConfig`,
//     `ListTaskPushNotificationConfigs`, `DeleteTaskPushNotificationConfig`, `GetExtendedAgentCard`)
//     across HTTP+JSON/REST (root and `{tenant}` paths), JSON-RPC 2.0, SSE, push webhooks, and
//     a thin optional gRPC adapter (`GRPCServer`).
//   - Cryptographic Agent Card Discovery & Trust Boundaries: Serves fail-closed
//     `GET /.well-known/agent-card.json` canonicalized via RFC 8785 JCS and JWS-signed with
//     Vault-derived keys, including the required `protected` field in `AgentCardSignature`.
//   - Governance, FinOps & Durability: Enforces RBAC, `task.AgentID == agent.ID` visibility isolation,
//     guardrails v2 pipelines, Vault upstream/webhook authentication, FinOps quota & spend logging,
//     subscribe-first Redis Pub/Sub SSE streaming, and PostgreSQL transactional outbox delivery.
package a2a
