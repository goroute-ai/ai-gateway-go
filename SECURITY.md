# Security Policy

The GoRoute team takes the security of GoRoute AI Gateway seriously. We appreciate the efforts of security researchers and community members who help keep our project and its users safe.

---

## Supported Versions

Only the latest minor release branch receives active security updates and vulnerability patches.

| Version | Supported          | Status             |
| :------ | :----------------- | :----------------- |
| 1.3.x   | :white_check_mark: | Active Development |
| 1.2.x   | :x:                | End of Life        |
| 1.1.x   | :x:                | End of Life        |
| 1.0.x   | :x:                | End of Life        |

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
- The affected component (e.g., SSRF firewall, auth vault, FinOps spend worker, MCP transport).
- Any proposed remediations or patches if you have developed one.

---

## Response & Disclosure Process

1. **Acknowledgment**: We will acknowledge receipt of your vulnerability report within **48 business hours**.
2. **Investigation & Assessment**: Our engineering team will assess severity, verify exploitability, and determine affected versions.
3. **Patch Development**: We will prepare and test an emergency patch in a private fork.
4. **Coordinated Release**: We adhere to standard 90-day coordinated vulnerability disclosure guidelines. A patched release (e.g., `v1.3.1`) will be published alongside an official GitHub Security Advisory crediting the finder.

---

## Core Security Architecture & Invariants

When contributing security fixes or reviewing code, please observe GoRoute's core security invariants:

- **Egress SSRF Protection**: All outbound HTTP/HTTPS calls to provider endpoints must pass through the `internal/security/network` dialer with IP pinning, DNS rebinding defense, RFC 1918 private network blocking, and cloud metadata (`169.254.169.254`) blocking.
- **Dual-Boundary Auth Isolation**: Client applications only receive virtual API keys (`sk-gw-...`). Upstream provider API keys and cloud secrets must remain inside the AES-256-GCM encrypted vault and never leak to client responses.
- **FinOps Micro-Dollar Integrity**: Token and cost ledgers must use exact 64-bit integer micro-dollars ($1 = 1,000,000 µ$) to prevent floating-point rounding drift.
