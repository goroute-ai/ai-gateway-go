<p align="center">
  <img src="./assets/logo-dark.png" width="140" alt="GoRoute AI Gateway Logo" style="border-radius: 20px;" />
</p>

# GoRoute AI Gateway

**One simple, secure hub for all your AI models, safety checks, and spending controls.**

[![Version](https://img.shields.io/badge/Version-v0.1.0-00ADD8)](./CHANGELOG.md)
[![Go Version](https://img.shields.io/badge/Go-1.26%2B-00ADD8?logo=go)](https://go.dev/)
[![License](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](./LICENSE)

---

## What Is GoRoute?

GoRoute sits between your apps and major AI providers (**OpenAI**, **Anthropic**, **Groq**, and **OpenRouter**). Instead of managing separate API keys, billing dashboards, and safety rules for every provider, your team connects to GoRoute once and manages everything from one place.

---

## Why Teams Use GoRoute

- **One Connection for Every AI Model** — Switch or combine OpenAI, Anthropic, Groq, and OpenRouter without rewriting your apps.
- **Automatic Backup & Reliability** — If one AI provider slows down or goes offline, GoRoute automatically routes requests to a healthy backup.
- **Built-In Spending & Usage Limits** — Set clear daily, weekly, or monthly budgets per team, project, or user so AI bills never surprise you.
- **Company Login & Safety Guardrails** — Works with your organization's Single Sign-On (SSO) and automatically blocks sensitive data leaks or unsafe prompts.
- **Built-In Web Dashboard** — Includes an easy-to-use admin console and chat playground right out of the box—no extra tools required.

---

## Quick Start

### Option A: Run with Docker (Recommended)

```bash
git clone https://github.com/goroute-ai/ai-gateway-go.git
cd ai-gateway-go
docker compose -f deployments/docker-compose.yml up -d --build
```

### Option B: Run the Go Binary Locally

```bash
make build
./bin/ai-gateway -config configs/config.yaml
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
| **[System Architecture](./docs/ARCHITECTURE.md)** | System design, database schema, and scaling model. |
| **[Testing Guide](./docs/TESTING.md)** | Unit, database, browser UI, and Docker verification suites. |
| **[Security Policy](./SECURITY.md)** | Vulnerability reporting and security architecture guarantees. |
| **[Contributing Guide](./CONTRIBUTING.md)** | How to build, test, and submit pull requests. |

---

## License

Licensed under the [Apache License, Version 2.0](./LICENSE).
