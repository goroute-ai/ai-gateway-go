# GoRoute AI Gateway Container & Deployment Guide

Ultra-fast, lightweight AI Gateway, MCP Virtual Hub, and Agent-to-Agent (A2A) Router in 100% Pure Go with an embedded Operator Web UI.

GoRoute sits between client applications and OpenAPI-first model providers (OpenAI, Anthropic, Groq, OpenRouter), exposing one unified OpenAI-compatible API (`/v1/*`), UI-selectable multi-release MCP (`2024-11-05` through `2026-07-28`) tool routing, Linux Foundation A2A v1.0 task execution, Redis Lua sliding-window rate limits, circuit breakers, and exact integer micro-dollar FinOps.

- **GitHub Repository**: https://github.com/goroute-ai/ai-gateway-go
- **License**: Apache-2.0

---

## Supported Architectures

The multi-stage [`Dockerfile`](./Dockerfile) builds a minimal Distroless non-root image (`gcr.io/distroless/static-debian12:nonroot`, supporting `linux/amd64` and `linux/arm64`) with zero Node.js runtime dependencies—the Operator Web UI is embedded directly inside the compiled Go binary.

> [!NOTE]
> While GoRoute is in `v0.1.0` pre-release testing, public container registries (Docker Hub `qaadir/ai-gateway` and GHCR `ghcr.io/goroute-ai/ai-gateway-go`) do not host prebuilt tags yet. Build locally from source using the commands below.

---

## Quick Start

### 1. Build & Run Locally with Docker

```bash
docker build -f deployments/Dockerfile -t goroute-ai-gateway:0.1.0 .
docker run --rm -p 8080:8080 \
  -e GATEWAY_MASTER_ADMIN_KEY="sk-gw-change-me" \
  -e OPENAI_API_KEY="sk-..." \
  goroute-ai-gateway:0.1.0
```

Open the embedded Operator Web UI at `http://localhost:8080/ui/`.

### 2. Full Production Stack (Docker Compose + PostgreSQL 16 + Redis 7)

```bash
docker compose -f deployments/docker-compose.yml up -d --build
```

### 3. Kubernetes (Helm Chart)

```bash
helm install goroute ./deployments/helm/goroute
```

---

## Key Environment Variables

| Variable | Description |
| :--- | :--- |
| `GATEWAY_PORT` | HTTP listener port (default `8080`) |
| `GATEWAY_POSTGRES_DSN` | PostgreSQL DSN for persistence, migrations, audit logs, and FinOps ledgers |
| `GATEWAY_REDIS_ADDR` | Redis `host:port` for distributed sliding-window rate limits, quotas, and L2 cache |
| `GATEWAY_MASTER_ADMIN_KEY` | Control plane bootstrap admin bearer token |
| `GATEWAY_MASTER_ENCRYPTION_KEY` | 32-byte hex key for encrypted provider credentials & staged key rotation |
| `GATEWAY_SESSION_SECRET` | `>= 32`-byte secret used to sign `goroute_session` operator cookies |

Health endpoints for container orchestrators: `GET /healthz`, `GET /readyz`, or `ai-gateway -healthcheck`.

---

## Verifying Published Release Signatures

Once official release images are published via the manual `docker-publish.yml` workflow, each image digest is signed with Sigstore Cosign keyless OIDC and backed by BuildKit provenance & SPDX SBOM attestations:

```bash
cosign verify docker.io/qaadir/ai-gateway:0.1.0 \
  --certificate-identity-regexp="^https://github.com/goroute-ai/ai-gateway-go/.github/workflows/docker-publish.yml@" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com"
```
