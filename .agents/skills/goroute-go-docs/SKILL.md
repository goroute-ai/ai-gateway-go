---
name: goroute-go-docs
description: Write and review Go godoc comments, package docs, Example tests, and repository documentation for GoRoute AI Gateway in compliance with revive exported and godot linters. Use when documenting pkg/gateway public SDK APIs, internal Go packages, or updating docs/ and CHANGELOG.md. Do not use for non-documentation code refactors.
---

# GoRoute Go Documentation & Godoc Standards

Curated Go documentation standards aligned with [`.golangci.yml`](../../../.golangci.yml) (`revive: exported`, `godot`, `misspell`, `dupword`) and GoRoute's public SDK + gateway architecture. Adapted from [`samber/cc-skills-golang`](https://github.com/samber/cc-skills-golang) (`golang-documentation`, MIT License).

---

## 1. Writing Principles

Apply to every godoc comment and markdown doc you write or review:

- **Concision**: Use the shortest accurate sentence that carries the full meaning. Remove filler transitions (`it's worth noting that`, `in order to`).
- **Intent over paraphrase**: Code shows *what* happens; docs explain *why* it exists, *when* to use it, *what constraints* apply, and *what errors* it returns. Never write a comment that merely restates the function signature.
- **No invented claims**: Never add marketing buzzwords (`seamlessly`, `robust`, `enterprise-grade`) or promises about future behavior. Document actual, verified behavior.
- **Preserve obligation strength**: Keep `must`, `should`, and `may` accurate when editing existing docs; never soften a required security or accounting constraint.

## 2. Godoc & Linter Requirements

- **Exported APIs (`revive: exported`)**: Every exported package, type, function, method, constant, and variable in `pkg/gateway/` (public embeddable SDK) and `internal/*` must have a doc comment starting with the exact identifier name.
  - Note: `.golangci.yml` exempts `_test.go` and storage implementation method boilerplate in `internal/storage/(memory|postgres)*.go`, but public interfaces in `internal/domain/` and `pkg/gateway/` must be documented.
- **Complete sentences with trailing periods (`godot`)**: End top-level doc comment sentences with a period (`.`).
- **Package comments**: Multi-file packages—especially `pkg/gateway/` and core `internal/*` packages—should have a `doc.go` starting with `// Package <name> ...` explaining the package's responsibility and key entry points.
- **Document GoRoute-specific semantics explicitly** where applicable:
  - **Tri-state allowlists**: Clarify `nil` (inherit) vs empty slice `[]` (deny all).
  - **Financial units**: State explicitly when values are integer micro-dollars (`µ$`, `$1.00 = 1,000,000`).
  - **Concurrency & lifecycle**: Note whether a type is safe for concurrent use and whether callers must call `Close()`.
  - **Error conditions**: Mention sentinel errors (`Err*`) callers can inspect with `errors.Is`.

## 3. Public SDK (`pkg/gateway/`) & Docs Alignment

- **Self-contained SDK docs**: `pkg/gateway/` godoc must never reference `internal/*` types or paths in exported documentation.
- **Runnable `Example` tests**: Add `ExampleXxx()` functions in `example_test.go` for major `pkg/gateway/` entry points so examples are compile-checked by `go test`.
- **Keep repo docs in sync**:
  - Adding/renaming subsystems or entry points → update [`docs/CODEBASE_MAP.md`](../../../docs/CODEBASE_MAP.md).
  - Adding guides or API docs → update [`docs/README.md`](../../../docs/README.md).
  - Changing migrations, config flags, or rolling upgrade behavior → update [`docs/UPGRADING.md`](../../../docs/UPGRADING.md) and config examples.

## 4. Verification Checklist

Before finishing documentation edits:
1. Run `go doc ./pkg/gateway` (or the modified package) to verify rendered godoc readability.
2. Run `gofmt -l .` and `go vet ./...` (plus `golangci-lint run ./...` if installed) to verify `revive`, `godot`, `misspell`, and `dupword`.
3. Verify any new `ExampleXxx` tests compile and pass with `go test -count=1 ./pkg/gateway/...`.

## 5. Templates & Examples (Load On Demand)

- **Good vs. Bad godoc patterns, `doc.go` template, `ExampleXxx` tests, and review checklist** → Read [references/godoc-and-examples.md](./references/godoc-and-examples.md).
