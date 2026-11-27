# Guardrails Test Module (`tests/guardrails`)

An isolated, dependency-free Go test harness (`MemoryRepository` + `miniredis` + mock upstreams + mock HTTP webhook servers) for validating GoRoute AI Gateway guardrails without running PostgreSQL, Redis, or live upstream LLM providers.

## Running Only Guardrails Tests

```bash
# Run the dedicated guardrails suite
go test -v -race -count=1 ./tests/guardrails/...

# Or run both unit guardrail tests and this suite together via Makefile
make test-guardrails
```

## Suite Layout

- `harness_test.go`: Self-contained `newGuardrailLab` fixture provisioning org, subscriptions, credentials, model groups (`fast`, `emb-small`, `modr`), team, and virtual API key, plus `newMockWebhookScanner` and `buildMCPUpstreamMock`.
- `http_flow_test.go`: Tests built-in input/output rules across `/v1/chat/completions`, `/v1/messages`, `/v1/responses`, `/v1/embeddings`, and `/v1/moderations`, `/admin/v1/organizations/{orgID}/guardrails/simulate` parity, non-streaming + cached response sanitization (PII, secrets, toxicity, exceptions), and an SSE streaming split-chunk redaction matrix across 2B/3B/16B chunk boundaries.
- `external_drivers_test.go`: Tests external `generic_http` guardrail definitions (`pre_call`, `post_call`, `logging_only`), Admin CRUD + Vault secret storage, declarative YAML startup seeding (`guardrails.definitions[]`), and `fail_open` vs fail-closed behavior.
- `tool_and_protocol_test.go`: Tests LLM `ToolCalls[].Function.Arguments` scanning, MCP discovery poisoning caps & SHA-256 anti-rug-pull pinning, HTTP MCP `tools/call` + `/sync` enforcement, and A2A inbound/outbound filtering.
