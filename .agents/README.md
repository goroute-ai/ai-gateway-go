# `.agents/` — GoRoute AI Gateway Coding-Agent Configuration

This directory follows the open **`.agents/` + `AGENTS.md` + Agent Skills (`agentskills.io`)** progressive-disclosure standard for AI coding assistants (Google Antigravity, OpenAI Codex, Claude Code, Cursor, and GitHub Copilot).

## Structure

```text
.agents/
├── README.md                          # This orientation guide
├── rules/                             # Scoped invariants (loaded by trigger)
│   ├── core-invariants.md             # [always_on] Non-negotiable global guardrails
│   ├── go-backend.md                  # [glob: **/*.go, go.mod] Go architecture & SDK rules
│   ├── security-and-auth.md           # [glob: auth, security, server, guardrails] OIDC, SSRF, Vault
│   ├── contracts-and-migrations.md    # [glob: openapi, specs, migrations, storage, ratelimit]
│   └── operator-web-ui.md             # [glob: web/**, internal/ui/**, tests/ui-e2e/**]
└── skills/                            # On-demand procedural runbooks (Agent Skills spec)
    ├── goroute-codebase-navigator/    # Fast subsystem routing + references/subsystem-map.md
    ├── goroute-go-quality/            # Go 1.26 code quality, safety, concurrency, testing & lint
    ├── goroute-go-docs/               # Go godoc, package docs, Example tests & docs alignment
    ├── goroute-openapi-contract/      # OpenAPI 3.1 + MCP/A2A contract generation runbook
    ├── goroute-add-provider/          # OpenAPI-first upstream provider integration runbook & checklist
    ├── goroute-db-migration/          # PostgreSQL migrations, repo parity & Redis cluster slots
    ├── goroute-operator-ui/           # React SPA build, CSP, bundle budget & Playwright E2E
    └── goroute-verification-gate/     # 4-tier test & CI gate + scripts/verify_tier0.sh
```

## Progressive Disclosure Design

1. **Root Routers (`AGENTS.md`, `CLAUDE.md`)**: Stay concise and point agents here and to [`docs/CODEBASE_MAP.md`](../docs/CODEBASE_MAP.md).
2. **Scoped Rules (`.agents/rules/`)**: Only `core-invariants.md` is `always_on`. Domain rules load only when touching matching file globs, keeping context windows clean.
3. **On-Demand Skills (`.agents/skills/`)**: Agents see only skill `name` and `description` at startup and read the full `SKILL.md` (plus `references/` or `scripts/`) only when performing that task.
4. **Local-Only Overrides**: Put machine-local overrides in `.agents/local/` or `.agents/*.local.md` (gitignored via [`.gitignore`](../.gitignore)).
