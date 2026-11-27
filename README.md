<p align="center">
  <img src="./assets/logo-dark.png" width="140" alt="GoRoute AI Gateway Logo" style="border-radius: 20px;" />
</p>

# GoRoute AI Gateway

**One simple, secure hub for all your AI models, safety checks, and spending controls.**

[![Release](https://img.shields.io/badge/Release-v0.2.0-success)](https://github.com/goroute-ai/ai-gateway-go/releases/tag/v0.2.0)
[![Docker Hub](https://img.shields.io/badge/Docker%20Hub-qaadir%2Fai--gateway-2496ED?logo=docker&logoColor=white)](https://hub.docker.com/r/qaadir/ai-gateway)
[![GHCR](https://img.shields.io/badge/GHCR-ghcr.io%2Fgoroute--ai%2Fai--gateway--go-2496ED?logo=docker&logoColor=white)](https://github.com/goroute-ai/ai-gateway-go/pkgs/container/ai-gateway-go)
[![Go Version](https://img.shields.io/badge/Go-1.26%2B-00ADD8?logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](./LICENSE)

---

## What Is GoRoute?

GoRoute sits between your apps and major AI providers (**OpenAI**, **Anthropic**, **Groq**, **OpenRouter**, **Ollama**, and **Google Gemini**). Instead of managing separate API keys, billing dashboards, and safety rules for every provider, your team connects to GoRoute once and manages everything from one place.

---

## Why Teams Use GoRoute

- **One Connection for Every AI Model** — Switch or combine OpenAI, Anthropic, Groq, OpenRouter, local or cloud Ollama, and Google Gemini models without rewriting your apps.
- **Automatic Backup & Reliability** — If one AI provider slows down or goes offline, GoRoute automatically routes requests to a healthy backup.
- **Built-In Spending & Usage Limits** — Set clear daily, weekly, or monthly budgets per team, project, or user so AI bills never surprise you.
- **Built-In Exact & Semantic Response Caching** — Cut latency and LLM spend to `$0` on repeated or paraphrased prompts using in-memory `local` LRU, shared `redis` KV, or Redis 8 `redis-semantic` vector similarity search.
- **Pure OpenTelemetry (OTLP/HTTP) Observability** — Exports GenAI semantic convention traces (`gen_ai.*`), pure dot-separated OTel metrics (`gen_ai.*`, `gateway.*`), and opt-in post-scrub logs exclusively over standard OTLP/HTTP, letting you connect any OpenTelemetry Collector or OTLP-compatible backend on top without vendor lock-in.
- **Company Login & Safety Guardrails** — Works with your organization's Single Sign-On (SSO) and automatically blocks sensitive data leaks or unsafe prompts.
- **Built-In Web Dashboard** — Includes an easy-to-use admin console and chat playground (with streaming SSE and cacheable JSON modes) right out of the box—no extra tools required.

---

## Quick Start

### Option A: Run with Docker (Fastest)

```bash
docker run --rm -p 8080:8080 \
  -e GATEWAY_MASTER_ADMIN_KEY="sk-gw-change-me" \
  -e OPENAI_API_KEY="sk-..." \
  qaadir/ai-gateway:0.2.0
```

### Option B: Install the Standalone Binary

```bash
curl -fsSL https://raw.githubusercontent.com/goroute-ai/ai-gateway-go/main/install.sh | bash
ai-gateway -config configs/config.yaml
```

Once running, open the **Operator Web Dashboard** in your browser at **`http://localhost:8080/ui/`**.

### Send Your First Request

```bash
curl http://localhost:8080/v1/chat/completions \
  -H "Authorization: Bearer $GATEWAY_DEFAULT_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model": "auto", "messages": [{"role": "user", "content": "Hello!"}]}'
```

---

## Documentation

Looking for technical setup, API details, or architecture guides? Everything lives in [`docs/`](./docs/README.md):

| Guide | What It Covers |
| :--- | :--- |
| **[Documentation Index](./docs/README.md)** | Full map of all technical guides and protocol specifications. |
| **[Configuration Guide](./docs/CONFIGURATION_GUIDE.md)** | YAML setup, environment variables, SSO login, and Go SDK examples. |
| **[API Reference](./docs/API_REFERENCE.md)** | REST endpoints, team keys, MCP tools, A2A agents, and metrics. |
| **[Authorization & Access Control](./docs/AUTHORIZATION_AND_ACCESS_CONTROL.md)** | 19-capability RBAC, tri-state allowlists, SSO/JWT, quotas, and audit guide. |
| **[System Architecture](./docs/ARCHITECTURE.md)** | System design, database schema, and scaling model. |
| **[Testing Guide](./docs/TESTING.md)** | Unit, database, browser UI, and Docker verification suites. |
| **[Security Policy](./SECURITY.md)** | Vulnerability reporting and security architecture guarantees. |
| **[Contributing Guide](./CONTRIBUTING.md)** | How to build, test, and submit pull requests. |

---

## License

Licensed under the [Apache License, Version 2.0](./LICENSE).
