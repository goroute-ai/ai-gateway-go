---
trigger: glob
globs: "internal/auth/**, internal/security/**, internal/server/**, internal/guardrails/**"
description: "Security boundaries, OIDC-only federation, RBAC tri-state allowlists, Vault KEKs, SSRF policy, and guardrail invariants."
---

# Security, Auth & Guardrails Rules

- **Vendor-Neutral OIDC-Only Federation**:
  - Never reintroduce local operator passwords (`user_credentials`, `/auth/login`, `/auth/password`), symmetric `HS256` `auth.jwt_secret`, reverse-proxy header auth, or proprietary SSO presets.
  - Preserve issuer-bound federated identities `(org_id, oidc_issuer, oidc_subject)`, PKCE `S256` browser/CLI flows, RP-Initiated Logout (`id_token_hint`), and emergency break-glass access (`GATEWAY_MASTER_ADMIN_KEY`).
  - Production startup (`ENV=production` or `GATEWAY_ENV=production`) must reject default admin/encryption keys, weak `< 32`-byte `auth.session_secret`, missing `audience` on `auth.oidc_issuers[]`, wildcard/HTTP CORS origins, and global `allow_private_networks` / `allow_insecure_http` / `allow_loopback_http`.
- **Tri-State Allowlists & Fail-Closed Authorization**:
  - Preserve tri-state JSON allowlist semantics (`null` = Inherit vs `[]` = Deny All) using `optionalStringSlice` and explicit JSON tags **without `,omitempty`** on `IdentityContext`, `Team`, `Project`, and `VirtualKey`.
  - Keep `ExternalAuthorizer` (`auth.external_authorizer` / `WithCustomAuthorizer`), `team_admin` role-hierarchy boundaries, `allowed_routing_tags` / `allowed_deployments` filtering, and direct `/mcp` `ToolPolicy` checks fail-closed.
- **Egress SSRF, BaseURL & Media Isolation**:
  - Validate admin credential `BaseURL` inputs and adapter `ListModels` targets via `adapter.ValidateAndResolveBaseURL`.
  - Keep private-network preflight probes restricted to `platform_admin`.
  - Route untrusted user media fetches strictly through the isolated HTTPS-only `DefaultPublicMediaPolicy` (`mediaPolicy`/`mediaClient`).
- **Vault, KEKs & HTTP Headers**:
  - Keep provider secrets, staged rotation keys, and operator `id_token` metadata AES-256-GCM envelope-encrypted with rolling KEK support (`auth.previous_master_encryption_keys`).
  - Preserve `SecurityHeadersMiddleware` strict CSP (`default-src 'self'; script-src 'self'; frame-ancestors 'none'` on `/ui/*` & `/admin/v1/*`), CSRF `X-CSRF-Token` checks on cookie mutations, and pre-first-chunk `X-Gateway-*` CORS exposure headers.
- **Guardrails**: Preserve streaming split-chunk inspection/redaction (`StreamWindowEvaluator`), `default_on` / `is_locked` anti-bypass locks, `logging_only` audit emission, and `GuardrailActionRoute` (`sensitive_route_target`).
