---
paths:
  - "cmd/**/*.go"
  - "internal/**/*.go"
  - "pkg/**/*.go"
  - "tests/**/*.go"
---
# Go Code Quality Skills (`samber/cc-skills-golang`)

This repository enforces `samber/cc-skills-golang` quality conventions alongside `.golangci.yml`.

- Load `golang-documentation` and `golang-naming` when adding `doc.go`, godoc comments, or `Example` tests.
- Load `golang-refactoring`, `golang-code-style`, and `golang-gopls` before splitting oversized handlers/files or removing dead code.
- Load `golang-safety`, `golang-error-handling`, and `golang-security` when changing control flow, error wrapping, concurrency, or HTTP egress.
- Verify with `gofmt -l .`, `go vet ./...`, `golangci-lint run ./...`, `staticcheck ./...`, `deadcode ./cmd/... ./internal/... ./pkg/...`, and `go test -race`.
