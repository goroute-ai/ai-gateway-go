# Go Code Quality & Skill Routing

Use the installed `samber/cc-skills-golang` skills (`~/.gemini/config/plugins/cc-skills-golang/skills/`) for every Go task in this repository:

- **Documentation (`golang-documentation`)**: Every package has a `doc.go`; every exported type, function, method, constant, and config struct has an accurate godoc comment explaining *why* and constraints; public SDK APIs under `pkg/gateway` include `Example` tests.
- **Refactoring (`golang-refactoring`, `golang-code-style`)**: Keep functions focused with early returns, shallow nesting, explicit composite literal field names, and non-nil slice/map initialization. Break oversized handlers/orchestrators into cohesive helpers without altering OpenAPI contracts or router fast-path allocations.
- **Safety & Errors (`golang-safety`, `golang-error-handling`, `golang-security`)**: Always check errors, wrap with `%w`, follow the single-handling rule (log OR return, never both), avoid bare type assertions, and keep outbound egress behind `internal/security/network`.
- **Static Analysis (`golang-lint`, `golang-gopls`)**: Run `$(go env GOPATH)/bin/golangci-lint run ./...`, `$(go env GOPATH)/bin/staticcheck ./...`, `$(go env GOPATH)/bin/deadcode ./cmd/... ./internal/... ./pkg/...`, and `go vet ./...` before concluding changes.
