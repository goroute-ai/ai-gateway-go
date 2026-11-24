# Go Godoc Templates, Examples & Review Checklist

Adapted from `samber/cc-skills-golang` (`golang-documentation`, MIT License) for GoRoute AI Gateway.

---

## 1. Function & Method Doc Comments

Start with the exact identifier name, end sentences with a period (`godot`), and explain **intent, constraints, and failure modes** rather than paraphrasing the signature:

```go
// Bad — paraphrases the signature and adds zero information:
// ResolveBudget resolves the budget for a key.
func ResolveBudget(ctx context.Context, keyID string) (int64, error)

// Good — explains units, inheritance semantics, and error behavior:
// ResolveBudget returns the effective spend limit in integer micro-dollars
// ($1.00 = 1,000,000) for keyID after evaluating virtual-key, project, and
// team overrides. It returns ErrKeyNotFound if keyID does not exist.
func ResolveBudget(ctx context.Context, keyID string) (int64, error)
```

## 2. Package Comment (`doc.go`)

Place a `doc.go` in multi-file packages (especially `pkg/gateway/`):

```go
// Package gateway provides the embeddable GoRoute AI Gateway SDK.
//
// Callers construct a Gateway via New with functional Option values to route
// inference requests across configured providers, enforce tenant budgets, and
// attach custom authenticators or routing plugins.
package gateway
```

## 3. Types, Options & Concurrency Guarantees

Document concurrency safety, lifecycle (`Close`), and zero-value or tri-state semantics:

```go
// Policy controls model allowlists for a tenant scope.
//
// A nil AllowedModels slice inherits the parent scope's allowlist, whereas a
// non-nil empty slice denies all models. Policy values are immutable once
// constructed and safe for concurrent reads.
type Policy struct {
	AllowedModels []string
}
```

## 4. Runnable `ExampleXxx` Tests

Prefer compile-checked `Example` functions in `*_test.go` over stale prose snippets in comments:

```go
func ExampleWithCustomAuthorizer() {
	// Demonstrate minimal, self-contained setup without network calls or real keys.
}
```

Include an `// Output:` comment when the example produces deterministic stdout so `go test` verifies the output.

## 5. Documentation Review Checklist

- [ ] Every exported symbol in modified `pkg/gateway/` and `internal/domain/` files starts its comment with the symbol name (`revive: exported`).
- [ ] All doc comment sentences end with a period (`godot`) and have no typos or duplicated words (`misspell`, `dupword`).
- [ ] Comments explain *why*, units (e.g., micro-dollars, milliseconds), nil/tri-state semantics, and returned sentinel errors (`Err*`).
- [ ] No `internal/*` types or paths leak into `pkg/gateway/` godoc.
- [ ] `go doc <pkg>` renders cleanly and `go test -count=1 <pkg>` passes any `ExampleXxx` tests.
