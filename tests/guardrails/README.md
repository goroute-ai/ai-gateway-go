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

- `harness_test.go`: Self-contained `newGuardrailLab` fixture provisioning org, subscriptions, credentials, model groups (`fast`, `emb-small`, `modr`), team, and virtual API key, plus `newMockWebhookScanner` and `buildMCPUpstreamMock`.
- `custom_scanners_test.go`: Tests Go `guardrails.Scanner` & SDK `pkg/gateway.GuardrailScanner` interfaces (`allow`/`block`/`flag`/`modify`), per-scanner `TimeoutMs`/`FailOpen` isolation, `generic_http` rich payloads + SSRF enforcement, and `enforce` vs `logging_only` audit log emission.
- `http_flow_test.go`: Tests incoming rules across `/v1/chat/completions`, `/v1/messages`, `/v1/responses`, `/v1/embeddings`, and `/v1/moderations`, `/admin/v1/organizations/{orgID}/guardrails/simulate` parity, non-streaming + cached response sanitization (`ContentExceptions`, PII, secrets, toxicity), and an SSE streaming split-chunk redaction matrix across 2B/3B/16B chunk boundaries.
- `pipeline_v2_test.go`: Tests hierarchical bindings, anti-bypass locks (`default_on` / `is_locked`), `during_call` parallel cancellation, `ModeRule` tag routing, `RouterLB` weighted selection + cooldowns, `StreamWindowEvaluator` cross-chunk masking, and streamed `tool_calls` delta scanning.
- `custom_code_test.go`: Tests the sandboxed Starlark `custom_code` runtime (`apply_guardrail(inputs, request_data, input_type)`), step/timeout caps, disallowed filesystem/import sandboxing, and SSRF-protected `http_get`/`http_post`.
- `tool_and_protocol_test.go`: Tests LLM `ToolCalls[].Function.Arguments` scanning, MCP discovery poisoning caps & SHA-256 anti-rug-pull pinning, HTTP MCP `tools/call` + `/sync` enforcement (`pre_mcp_call`/`during_mcp_call`/`post_mcp_call`), and A2A inbound/outbound filtering.
- `tool_governance_test.go`: Tests `tool_permission` rules, `block_code_execution`, `mcp_security`, `mcp_end_user_permission`, and cross-turn `tool_policy` trust-chain taint blocking inside `ToolLoopOrchestrator`.
- `llm_judge_test.go`: Tests `llm_as_a_judge`, `decision_model`, and `_internal_guardrail_origin` recursion-loop guard.
- `apply_and_usage_test.go`: Tests `POST /v1/guardrails/apply`, expanded `/guardrails/simulate`, declarative YAML startup seeding (`guardrails.definitions[]` and `guardrails.tool_policies[]`), micro-dollar guardrail usage rollups, OTEL span scrubbing, and OTLP/UI observability metrics.
