# Go Safety & Concurrency Deep Dive

Adapted from `samber/cc-skills-golang` (`golang-safety`, `golang-concurrency`, `golang-context`, MIT License) for GoRoute AI Gateway.

---

## 1. Nil & Type Safety

- **Avoid the typed-nil interface trap**: An interface holding `(*MyType)(nil)` is **not** `== nil`. Always return literal `nil` when returning an interface type:
  ```go
  // Bad: returns (*ProviderError)(nil) as error != nil
  var pErr *ProviderError
  return pErr

  // Good: returns untyped nil interface
  if pErr == nil {
      return nil
  }
  return pErr
  ```
- **Safe type assertions**: Always use comma-ok (`v, ok := x.(T)`) unless the type is guaranteed by construction.
- **Usable zero values**: Lazy-initialize internal maps (`if s.items == nil { s.items = make(...) }`) or require a constructor (`NewXxx`) so callers cannot trigger nil-map write panics.

## 2. Slice & Map Aliasing Safety

- **`append` backing-array aliasing**: `append(a, x)` mutates `a`'s backing array if `cap(a) > len(a)`. Force a copy with full slice expression (`append(a[:len(a):len(a)], x)`) or `slices.Clone(a)` before mutating shared slices.
- **Defensive copies on boundaries**: Clone slices and maps (`slices.Clone`, `maps.Clone`) when returning internal state from exported methods or storing caller-owned mutable collections.
- **Tri-state allowlist reminder**: In `ai-gateway-go`, `nil` slices represent `null` (Inherit) while `[]string{}` represents `[]` (Deny All) on auth/RBAC allowlists. Preserve `nil` vs empty when cloning (`slices.Clone(nil)` returns `nil`, `slices.Clone([]string{})` returns non-nil empty slice — safe!).

## 3. Numeric & Financial Safety

- **Exact integer micro-dollars**: Financial values use `int64` micro-dollars (`$1.00 = 1,000,000 µ$`) and integer pico-dollar intermediates in `internal/finops/`. Never introduce `float64` for spend, budgets, or pricing.
- **Checked integer narrowing**: Narrowing conversions (`int64` → `int32` or `int` → `uint32`) silently wrap. Validate bounds against `math.MaxInt32` / `math.MinInt32` before casting.
- **Duration arithmetic**: Watch for `durationcheck` pitfalls (never multiply two `time.Duration` values).

## 4. Resource Lifecycle & `defer`

- **Never `defer` inside a loop**: `defer` executes at function exit, not loop iteration end, leaking file descriptors, HTTP response bodies, or locks. Extract the loop body into a helper function.
- **Always close HTTP bodies and SQL rows** (`bodyclose`, `sqlclosecheck`, `rowserrcheck`):
  ```go
  resp, err := client.Do(req)
  if err != nil {
      return err
  }
  defer resp.Body.Close()
  ```
  For `pgx` / `database/sql` rows, always `defer rows.Close()` and check `rows.Err()` after iteration.

## 5. Concurrency & Goroutine Lifecycle

- **Every goroutine must have a clear owner and exit path**: Never spawn a fire-and-forget goroutine without a cancellation signal (`ctx.Done()`) or wait mechanism (`sync.WaitGroup` / `errgroup.Group`).
- **Context propagation** (`noctx`, `revive: context-as-argument`):
  - Pass `ctx context.Context` as the first parameter; never store a `context.Context` inside a long-lived struct.
  - Always `defer cancel()` immediately after `context.WithCancel` / `WithTimeout` / `WithDeadline`.
  - Use `http.NewRequestWithContext(ctx, ...)` for every outbound HTTP call (through `internal/security/network`).
- **Lock discipline**:
  - Keep critical sections minimal; never perform network I/O, disk I/O, or call unknown callbacks/plugins while holding a `sync.Mutex` or `sync.RWMutex`.
  - Never copy a struct containing a `sync.Mutex`, `sync.RWMutex`, `sync.Once`, or `sync.WaitGroup` (pass by pointer).
  - Never upgrade an `RLock` to `Lock` without releasing `RUnlock` first and re-checking state.
- **Channel ownership**: The sender closes channels; never close a channel from the receiver side or from multiple concurrent senders without synchronization.
- **Verify with `-race`**: Run `go test -race -count=1 ./...` on any concurrent code change.
