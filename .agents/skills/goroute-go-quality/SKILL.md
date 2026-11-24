---
name: goroute-go-quality
description: Apply Go 1.26 code quality, naming, error handling, nil/slice/numeric safety, concurrency, testing, and golangci-lint v2 standards tailored to GoRoute AI Gateway. Use when writing, reviewing, or refactoring Go code in internal/, pkg/, cmd/, or tests/. Do not use for frontend-only or SQL-only edits.
---

# GoRoute Go Code Quality Standards

Curated Go engineering standards aligned with Go `1.26.0`, [`.golangci.yml`](../../../.golangci.yml), and GoRoute's core invariants. Adapted from [`samber/cc-skills-golang`](https://github.com/samber/cc-skills-golang) (MIT License).

> **Repo Invariants Always Win:** Never violate [`.agents/rules/core-invariants.md`](../../rules/core-invariants.md) or [`.agents/rules/security-and-auth.md`](../../rules/security-and-auth.md) (especially tri-state `nil` vs `[]` allowlists, exact `int64` micro-dollar accounting, and SSRF-protected egress).

---

## 1. Control Flow & Code Clarity

- **Early returns first**: Handle errors and guard clauses at the top; keep the happy path unindented.
- **Drop redundant `else`**: Omit `else` whenever the `if` branch ends in `return`, `break`, or `continue` (`revive: superfluous-else`, `if-return`).
- **Stay within `.golangci.yml` complexity bounds**:
  - Cyclomatic complexity: `gocyclo <= 18`
  - Nested `if` depth: `nestif <= 6`
  - Function length: `funlen <= 140` lines and `<= 90` statements
  - Duplicate code blocks: `dupl` threshold `120`
- **Explicit declarations**: Use `var` for zero-value initialization (`var count int`, `var buf bytes.Buffer`) and `:=` for non-zero values.
- **Named struct fields**: Always use keyed fields in composite literals so struct changes never silently misalign values.
- **Readable long calls**: Break calls with 4+ arguments or lines exceeding ~120 chars at semantic boundaries; if a signature grows too wide, introduce an options/config struct.
- **Slice & map initialization**:
  - Always initialize maps before writing (`make(map[K]V)` or `map[K]V{}`).
  - Initialize slices explicitly when JSON callers expect `[]` rather than `null`, **EXCEPT** for GoRoute's tri-state allowlists (`IdentityContext`, `Team`, `Project`, `VirtualKey`), where `nil` (`null`) = **Inherit** and `[]` = **Deny All**.

## 2. Naming Conventions

- **Packages**: Short, lowercase, singular nouns (`router`, `finops`, `vault`) — never `util`, `common`, or `helpers`. Avoid stuttering (`vault.Client`, not `vault.VaultClient`).
- **Receivers**: Short (1–2 letters), consistent across all methods of a type, never `this` or `self` (`revive: receiver-naming`).
- **Getters & booleans**: Drop the `Get` prefix (`cfg.Timeout()`, not `cfg.GetTimeout()`). Prefix booleans with `Is`, `Has`, `Can`, `Should`, or `Allow`.
- **Errors**: Sentinel errors start with `Err` (`ErrBudgetExceeded`); custom error types end with `Error` (`PolicyError`) (`errname`, `revive: error-naming`).
- **Error strings**: Lowercase, no trailing punctuation (`revive: error-strings`).
- **Context first**: Always pass `ctx context.Context` as the first parameter (`revive: context-as-argument`).

## 3. Error Handling

- **Wrap with `%w`**: Always add operation context when propagating errors (`fmt.Errorf("load deployment %s: %w", id, err)`).
- **Inspect with `errors.Is` / `errors.As`**: Never compare wrapped errors with `==` or bare type assertions (`errorlint`).
- **Never return `nil` on non-nil `err`**: If an error is checked and non-nil, propagate it, wrap it, or log/handle it explicitly with a clear reason (`nilerr`).
- **Aggregate multiple errors**: Use `errors.Join(errs...)` instead of concatenating error strings.
- **No panics in production paths**: Return errors; reserve `panic` strictly for programmer-invariant bugs at startup or `Must*` constructors.

## 4. Linting & `//nolint` Discipline

Run read-only checks before finishing Go edits:

```bash
gofmt -l .
go vet ./...
golangci-lint run ./...   # when golangci-lint v2 is installed
```

- **Fix root causes first** before adding any `//nolint` directive.
- **Specific linter + reason required** (`nolintlint` enforces both):
  ```go
  //nolint:errcheck // best-effort cleanup on shutdown; error is not actionable
  _ = conn.Close()
  ```
- **Never suppress security or resource-leak linters** (`gosec`, `bodyclose`, `noctx`, `sqlclosecheck`, `rowserrcheck`) without a documented, reviewed safety justification.

## 5. Deep-Dive References (Load On Demand)

- **Nil safety, slice/map aliasing, `int64` overflow, goroutine leaks, `context.Context`, and resource closing** → Read [references/safety-and-concurrency.md](./references/safety-and-concurrency.md).
- **Table-driven tests, `t.Helper()` / `t.Context()`, `-race` hygiene, and Go 1.26 `modernize` idioms** → Read [references/testing-and-modernize.md](./references/testing-and-modernize.md).
