# Security Policy

The GoRoute team takes the security of GoRoute AI Gateway seriously. We appreciate the efforts of security researchers and community members who help keep our project and its users safe.

---

## Supported Versions

Only the latest minor release branch receives active security updates and vulnerability patches.

| Version | Supported          | Status         |
| :------ | :----------------- | :------------- |
| 1.20.x  | :white_check_mark: | Active Support |
| 1.8.x   | :x:                | End of Life    |
| 1.7.x   | :x:                | End of Life    |
| <= 1.6  | :x:                | End of Life    |

---

## Reporting a Vulnerability

If you discover a potential security vulnerability in GoRoute AI Gateway, **please do not disclose it publicly in GitHub issues, discussions, or social media**.

Instead, report it privately through one of the following channels:

1. **GitHub Private Vulnerability Reporting**: Navigate to the [Security Advisories](https://github.com/goroute-ai/ai-gateway-go/security/advisories) tab of this repository and click **"Report a vulnerability"**.
2. **Email**: Send details to **`security@goroute.ai`** with the subject line `[SECURITY VULNERABILITY] <Brief Description>`.

### What to Include in Your Report

To help us triage and resolve the issue quickly, please include:
- A clear description of the vulnerability and its potential impact.
- Step-by-step instructions or a Minimal Reproducible Example (curl command, script, or configuration).
- The affected component (e.g., SSRF firewall, media fetcher, auth vault, FinOps spend worker, MCP/A2A transport, Web UI).
- Any proposed remediations or patches if you have developed one.

---

## Response & Disclosure Process

1. **Acknowledgment**: We will acknowledge receipt of your vulnerability report within **48 business hours**.
2. **Investigation & Assessment**: Our engineering team will assess severity, verify exploitability, and determine affected versions.
3. **Patch Development**: We will prepare and test an emergency patch cleanly against the supported release branch.
4. **Coordinated Release**: We adhere to standard 90-day coordinated vulnerability disclosure guidelines. A patched release (e.g., `v1.21.1`) will be published alongside an official GitHub Security Advisory crediting the finder.

---

## Verifying Releases

- **Binary & Bundle Checksums**: Every release from `v1.7.0` onward publishes `checksums.txt` on [GitHub Releases](https://github.com/goroute-ai/ai-gateway-go/releases). Verify downloaded archives (`tar.gz`, `zip`, Helm `.tgz`, Kubernetes manifests) with `sha256sum -c checksums.txt` (or `shasum -a 256 -c checksums.txt` on macOS).
- **Container Images**: Official multi-architecture (`linux/amd64`, `linux/arm64`) non-root Distroless images are published to GitHub Container Registry at `ghcr.io/goroute-ai/ai-gateway-go`.

---

## Core Security Architecture & Invariants

When contributing security fixes or reviewing code, please observe GoRoute's core security invariants:

- **Egress SSRF, BaseURL & Media Isolation**: All outbound HTTP/HTTPS calls to upstream provider endpoints must pass through the `internal/security/network` dialer with IP pinning, DNS rebinding defense, RFC 1918 private network blocking, and link-local metadata (`169.254.169.254`) blocking. Admin credential `BaseURL` mutations (`Create`, `Rotate`, `Validate`, `PreflightValidate`, with `platform_admin` scoping when `AllowPrivateNetworks` is enabled) and adapter `ListModels` endpoints validate canonical URLs via `adapter.ValidateAndResolveBaseURL`, while remote media fetches run behind an isolated HTTPS-only public `mediaPolicy` (`AllowPrivateNetworks: false`, no embedded URL userinfo).
- **Dual-Boundary Auth, RBAC & Fail-Closed Gates**: Client applications use SHA-256 hashed Virtual Keys (`sk-gw-...`) synced across replicas via Redis Pub/Sub or inbound JWT/OIDC tokens, while upstream provider credentials remain isolated inside the AES-256-GCM encrypted vault. Control-plane routes enforce scoped RBAC roles (`platform_admin`, `org_admin`, `org_viewer`, `team_admin`, `service_account`), disable master-key data-plane fallback by default, fail closed on storage/team lookup errors and Redis quota outages, and reject query-parameter credentials on non-WebSocket HTTP routes.
- **HTTP Security Headers & In-Memory Web UI Isolation**: `SecurityHeadersMiddleware` in `internal/server/security_headers.go` enforces `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, optional HSTS, strict Content Security Policy (`default-src 'self'; script-src 'self'; frame-ancestors 'none'` on `/ui/*` and `/admin/v1/*`; `default-src 'none'` on non-UI endpoints), and safe-by-default CORS. The embedded React Operator UI keeps admin and virtual keys exclusively in React state (`AuthContext`) and clears cached queries on lock.
- **MCP, A2A & Guardrail Isolation**: Multi-tenant tri-state allowlists (`AllowedMCPServers`, `AllowedA2AAgents` preserving `null` *inherit* vs `[]` *deny all*) isolate tool and agent access. Local `stdio` MCP servers scrub subprocess environments and enforce process timeouts; MCP MRTR continuation tokens use AEAD encryption and tool schema fingerprinting; A2A Agent Cards are signed (`RFC 8785` JCS + `RFC 7515` JWS); and guardrail scanning covers all message roles, streaming responses, and MCP/A2A bridges with fail-closed policy enforcement.
- **FinOps Integer Accounting & Secret Hygiene**: Token and cost ledgers use exact 64-bit integer micro-dollars (`$1 = 1,000,000 µ$`) with idempotent atomic reservations to prevent floating-point drift or oversubscription. `internal/logger` redacts secrets and PII from logs and spans, while repository hygiene is continuously checked with weekly and PR `CodeQL` scans (`go`, `javascript-typescript`), `.gitleaks.toml` / GitHub Push Protection, and SHA-pinned GitHub Actions.
