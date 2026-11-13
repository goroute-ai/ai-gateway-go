# Security Audit Report

**Audit date:** 2026-11-13  
**Repository revision reviewed:** `6a07a47` (`main` after PR #65)  
**Audit changes:** production environment validation, multipart temporary-file cleanup, and Go dependency updates are prepared on `codex/security-audit-hardening`.

## Scope

Reviewed authentication and tenant authorization, production configuration, secret handling, provider and tool egress controls, file upload handling, SQL access patterns, UI source sinks, GitHub Actions permissions, dependency advisories, repository security settings, and the merged remediation changes. Checked source and tests with Go security scanners and reviewed flagged cases for exploitability.

## Findings and status

### Fixed in the audit change set

1. **Production mode could accept default keys when only `GATEWAY_ENV=production` was set.**
   The config validator previously considered the config's environment and `ENV`, but not `GATEWAY_ENV`. Deployments using the documented environment variable could therefore retain the known default admin, encryption, or JWT keys despite running in production mode. Validation now treats either production environment variable as a production signal even when YAML says `development`; regression cases cover both environment variables. Estimated severity for an exposed deployment using the default admin key is **Critical (CVSS 3.1: 9.8)**.

2. **Multipart spill files were not explicitly removed after file uploads.**
   Multipart parsing can write parts larger than its memory threshold to temporary disk. The upload handler now defers `MultipartForm.RemoveAll()` after successful parsing so temporary files are removed on success and error paths.

3. **Two module advisories affected the pinned `golang.org/x/net` version.**
   Updated `golang.org/x/net` from `v0.60.0` to `v0.62.0`, with compatible indirect updates. `govulncheck ./...` now reports no known vulnerabilities.

### Remaining recommendations

1. **File storage has no per-organization quota or upload concurrency limit.**
   Each authenticated upload may be up to 512 MiB. Authentication, body-size enforcement, generated storage names, and organization-scoped database access are present, but sustained authorized uploads can consume disk capacity. Add tenant storage quotas and a bounded concurrent upload limit before offering large uploads to untrusted tenants.

2. **GitHub security monitoring is not fully enabled.**
   Secret scanning and push protection are disabled; CodeQL default setup is not configured; Dependabot security updates are disabled. Dependabot alerts are enabled. Enable these repository controls and review existing alerts before release.

3. **GitHub Actions use version tags rather than immutable commit pins.**
   Workflow permissions are read-only by default and the publishing workflow grants only package write access, but pin third-party actions to verified commit SHAs to reduce supply-chain risk.

4. **Repository secret scanning reports 23 heuristic matches.**
   Manual review located them in development defaults, test fixtures, guardrail examples, and generated UI content. No live credential was confirmed. Keep the production default-key rejection in place and consider adding narrow scanner allow rules for synthetic fixtures so future real leaks are easier to spot.

## Verified controls

- Admin routes use admin authorization; data-plane routes require an authenticated identity, and file lookups scope records to the caller's organization.
- Vault credentials use AES-256-GCM envelope encryption with cryptographically secure random nonces. Virtual key lookup uses a one-way hash.
- Outbound provider and tool traffic uses the shared network policy, including private-address checks and redirect revalidation.
- MCP stdio servers are disabled by default and rejected by release configuration until an OS sandbox is available.
- No unsafe HTML injection or dynamic code execution sink was found in `web/src`.
- No SQL injection path was identified in the reviewed query construction.

## Checks run

- `go test -race -count=1 ./internal/... ./pkg/...` — passed.
- `go test -race -count=1 ./tests/e2e` with local PostgreSQL and Redis — passed.
- `go vet ./...` — passed.
- `go build ./cmd/gateway` — passed.
- `gofmt -l .` — clean.
- `govulncheck ./...` — no known vulnerabilities.
- Gitleaks current-tree scan — 23 heuristic matches, manually triaged as described above.

## Release decision

The confirmed production-key bypass and multipart temporary-file cleanup are addressed in the accompanying change set, and tested dependency versions have no known advisories. Before release, enable the GitHub monitoring controls and decide whether the service's 512 MiB upload ceiling is acceptable without tenant quotas. This audit does not certify external infrastructure, deployed secrets, or GitHub's cached pull-request views and forks.
