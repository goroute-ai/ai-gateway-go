# Guardrails Test Module (`tests/guardrails`)

An isolated, dependency-free Go test harness (`MemoryRepository` + `miniredis` + mock upstreams + mock HTTP webhook scanners) for validating GoRoute AI Gateway guardrails without running PostgreSQL, Redis, or live upstream LLM providers.

## Running Only Guardrails Tests

```bash
# Run the dedicated guardrails suite
go test -v -race -count=1 ./tests/guardrails/...

# Or run both unit guardrail tests and this suite together via Makefile
make test-guardrails
```

## Suite Layout

- `harness_test.go`: Self-contained `newGuardrailLab` fixture provisioning org, subscriptions, credentials, model groups (`fast`, `emb-small`, `modr`, `rerank`), team, and virtual API key, plus `newMockWebhookScanner` and `buildMCPUpstreamMock`.
- `custom_scanners_test.go`: Tests Go `guardrails.Scanner` interface (`ScanInput` / `ScanOutput`, timeouts, `failClosed` vs `failOpen`), `HTTPGuardrailScanner` (`guardrails.scanners` config, env-resolved auth headers, SSRF checks), and `enforce` vs `logging_only` + audit log emission.
- `http_flow_test.go`: Tests incoming rules across `/v1/chat/completions`, `/v1/messages`, `/v1/responses`, `/v1/embeddings`, `/v1/moderations`, and `/v1/rerank`, `/admin/v1/organizations/{orgID}/guardrails/simulate` parity, non-streaming + cached response sanitization (`ContentExceptions`, PII, secrets, toxicity), and an SSE streaming split-chunk redaction matrix across 2B/3B/16B chunk boundaries.
- `tool_and_protocol_test.go`: Tests LLM `ToolCalls[].Function.Arguments` scanning, MCP discovery poisoning caps & SHA-256 anti-rug-pull pinning, HTTP MCP `tools/call` + `/sync` enforcement, and A2A inbound/outbound filtering.
