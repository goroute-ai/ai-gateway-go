// Package a2a implements the Linux Foundation Agent-to-Agent (A2A v1.0) protocol gateway service.
//
// The A2A protocol standardizes inter-agent communication, discovery, stateful task execution,
// and real-time event streaming across multi-agent systems.
//
// Subsystem Capabilities:
//   - Cryptographic Agent Card Discovery: Exposes GET /.well-known/agent-card.json canonicalized
//     via RFC 8785 JSON Canonicalization Scheme (JCS) and signed with RFC 7515 JWS (ES256, RS256, EdDSA).
//   - Trust Boundary Separation: Verifies upstream agent card signatures against trusted public keys,
//     strips external signatures, rewrites endpoint URLs to the gateway's namespace, and re-signs cards
//     using the gateway's managed Vault/KMS signing key.
//   - Dual-Binding Protocol Engine: Transparently unmarshals and dispatches both HTTP+JSON
//     (application/json) and JSON-RPC 2.0 requests over POST /a2a/v1/agents/{agentSlug}.
//   - Native gRPC Service (lf.a2a.v1.A2AService): Serves high-performance RPC callers with full
//     gRPC methods (SendMessage, GetTask, ListTasks, CancelTask, SubscribeToTask) and metadata Bearer authentication.
//   - A2A-to-OpenAI Compatibility Bridge: Allows standard OpenAI SDK clients to invoke complex multi-agent
//     workflows via POST /v1/chat/completions with model: "a2a/{agent_slug}", mapping user prompts into A2A messages
//     and supporting multi-turn conversational resumption when tasks enter TASK_STATE_INPUT_REQUIRED.
//   - Protobuf Validation: Enforces strict ProtoJSON serialization (protojson.UnmarshalOptions{DiscardUnknown: false})
//     against generated lf.a2a.v1 types.
//   - Durable State Machine: Persists tasks and event logs in PostgreSQL with strictly monotonic sequence numbers
//     (SET last_event_seq = last_event_seq + 1 ... RETURNING last_event_seq) and enforces legal state transitions.
//   - Subscribe-First SSE Streaming: Guarantees zero lost and zero duplicate events across disconnects by
//     subscribing to Redis Pub/Sub FIRST, snapshotting/backfilling from PostgreSQL, and deduplicating sequence numbers.
//   - Transactional Outbox: Drains pending webhook notifications asynchronously using FOR UPDATE SKIP LOCKED
//     with exponential backoff and dead-letter queue (DLQ) support.
//   - Administrative Controls: Supports immediate emergency kill-switch activation to disable rogue agents across all pods.
package a2a
