# Go Testing & Go 1.26 Modernization Reference

Adapted from `samber/cc-skills-golang` (`golang-testing`, `golang-modernize`, MIT License) for GoRoute AI Gateway (`go 1.26.0`, `.golangci.yml` v2).

---

## 1. Production-Ready Go Testing

- **Stdlib `testing` first**: Match the repository's convention using stdlib `testing` (`t.Fatalf`, `t.Errorf`, `t.Run`) without pulling in unnecessary test frameworks.
- **Table-driven subtests**: Group input/output/error matrices cleanly using `t.Run(tc.name, func(t *testing.T) { ... })`.
- **Mark helpers with `t.Helper()`** (`thelper` linter): Every test helper function accepting `*testing.T` or `testing.TB` must call `t.Helper()` as its first statement so failure lines point to the caller.
- **Use modern testing primitives** (`usetesting` linter):
  - `t.TempDir()` instead of `os.MkdirTemp` + manual cleanup.
  - `t.Setenv(key, val)` instead of `os.Setenv` + `defer`.
  - `t.Context()` instead of `context.Background()` for request/operation contexts in tests.
  - `t.Cleanup(fn)` for deterministic teardown even on `t.Fatal`.
- **No flaky sleeps**: Avoid `time.Sleep` for synchronization in concurrent tests; use channels, `sync.WaitGroup`, or short bounded polling with `t.Context()`.
- **Synthetic test secrets**: Never hardcode realistic API keys or tokens in tests (construct synthetic fixtures dynamically to pass `.gitleaks.toml`).
- **Always run race detector & disable test cache**:
  ```bash
  go test -race -count=1 ./internal/<pkg>/...
  ```

## 2. Go 1.26 Modernization Idioms (`modernize`, `intrange`, `usestdlibvars`)

Prefer modern standard-library constructs enforced by `.golangci.yml`:

| Legacy Pattern | Modern Go 1.26 Idiom |
| --- | --- |
| `interface{}` | `any` |
| `for i := 0; i < n; i++` | `for i := range n` (`intrange`) |
| Manual slice contains / clone / sort | `slices.Contains`, `slices.Clone`, `slices.SortFunc` |
| Manual map keys / clone / copy | `maps.Keys`, `maps.Clone`, `maps.Copy` |
| Manual `if a < b { return a }` | Built-in `min(a, b)` / `max(a, b)` |
| `strings.Index` + manual slicing | `before, after, found := strings.Cut(s, sep)` |
| `fmt.Sprintf("%s", s)` / `fmt.Sprintf("%d", n)` | Direct `s` / `strconv.Itoa(n)` (`perfsprint`) |
| `"GET"`, `200`, `"application/json"` | `http.MethodGet`, `http.StatusOK` (`usestdlibvars`) |
| `wg.Add(1); go func() { defer wg.Done(); ... }()` | `wg.Go(func() { ... })` (Go 1.25+) |
| `v := new(T); *v = x` or helper `ptr(x)` | `new(x)` where supported or typed helper |
| `strings.Split` in `for range` | `strings.SplitSeq` when only iterating |
