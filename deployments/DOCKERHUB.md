# GoRoute AI Gateway

Ultra-fast, lightweight AI Gateway, MCP Virtual Hub, and Agent-to-Agent (A2A) Router in 100% Pure Go with an embedded Operator Web UI.

GoRoute sits between client applications and OpenAPI-first model providers (OpenAI, Anthropic, Groq, OpenRouter), exposing one unified OpenAI-compatible API (`/v1/*`), UI-selectable multi-release MCP (`2024-11-05` through `2026-07-28`) tool routing, Linux Foundation A2A v1.0 task execution, Redis Lua sliding-window rate limits, circuit breakers, and exact integer micro-dollar FinOps.

- **GitHub Repository**: https://github.com/goroute-ai/ai-gateway-go
- **Go SDK (`pkg/gateway`)**: https://pkg.go.dev/github.com/goroute-ai/ai-gateway-go/pkg/gateway
- **GHCR Mirror**: `ghcr.io/goroute-ai/ai-gateway-go`
- **Helm Chart (OCI)**: `oci://ghcr.io/goroute-ai/charts/goroute`
- **License**: Apache-2.0

---

## Supported Architectures & Tags

Multi-arch Distroless nonroot images (`gcr.io/distroless/static-debian12:nonroot`, `linux/amd64` + `linux/arm64`) are published to Docker Hub (`docker.io/qaadir/ai-gateway`) and GitHub Container Registry (`ghcr.io/goroute-ai/ai-gateway-go`).

- `latest` — Latest stable release
- `0.1.0` / `v0.1.0` — Pinned feature release (both bare and `v`-prefixed tags supported)
- `0.1` / `0` — Minor and major rolling release channels

```bash
docker pull qaadir/ai-gateway:0.1.0
# or
docker pull qaadir/ai-gateway:latest
```

---

## Quick Start

### 1. Docker Run (Minimal Standalone Mode)

```bash
docker run --rm -p 8080:8080 \
  -e GATEWAY_MASTER_ADMIN_KEY="sk-gw-change-me" \
  -e OPENAI_API_KEY="sk-..." \
  qaadir/ai-gateway:0.1.0
```

Open the embedded Operator Web UI at `http://localhost:8080/ui/`.

### 2. Full Production Stack (Docker Compose + PostgreSQL 16 + Redis 7)

```bash
curl -O https://raw.githubusercontent.com/goroute-ai/ai-gateway-go/main/deployments/docker-compose.yml
docker compose up -d
```

To pull the prebuilt image instead of building from source, replace `build:` with `image: qaadir/ai-gateway:0.1.0` (or `ghcr.io/goroute-ai/ai-gateway-go:0.1.0`).

### 3. Kubernetes (Helm OCI)

```bash
helm install goroute oci://ghcr.io/goroute-ai/charts/goroute --version 0.1.0
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
| `GATEWAY_JWT_ISSUER` / `GATEWAY_JWT_AUDIENCE` | Operator UI & control plane JWT configuration |

Health endpoints for container orchestrators: `GET /healthz`, `GET /readyz`, or `ai-gateway -healthcheck`.

---

## Verifying Supply-Chain Signatures

Every release image digest is signed with Sigstore Cosign keyless OIDC and backed by BuildKit provenance & SPDX SBOM attestations:

```bash
cosign verify docker.io/qaadir/ai-gateway:0.1.0 \
  --certificate-identity-regexp="^https://github.com/goroute-ai/ai-gateway-go/.github/workflows/docker-publish.yml@" \
  --certificate-oidc-issuer="https://token.actions.githubusercontent.com"
```
