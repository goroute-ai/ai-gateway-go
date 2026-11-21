## Summary of Changes

Provide a concise overview of what this pull request modifies, fixes, or adds.

Fixes #(issue)

---

## Type of Change

- [ ] 🐛 Bug fix (non-breaking change fixing an issue)
- [ ] ✨ New feature (non-breaking change adding functionality)
- [ ] 💥 Breaking change (fix or feature causing existing behavior to change)
- [ ] 📚 Documentation update
- [ ] ⚡ Performance optimization
- [ ] 🧪 Test suite enhancement / refactor

---

## Verification & Quality Checklist

Before submitting your pull request, please verify that you have completed the following checks locally:

- [ ] Code is formatted with `gofmt -s -w .` (or verified via `gofmt -l .`)
- [ ] Static analysis passes with `go vet ./...`
- [ ] Unit tests pass with race detector: `go test -race -count=1 ./internal/... ./pkg/...`
- [ ] If modifying API endpoints or schemas, generated contracts and validation pass via `make specgen`
- [ ] If modifying the frontend (`web/`), assets are built and verified via `make ui-build` and `node web/scripts/check-budget.mjs`
- [ ] Relevant documentation in `docs/` or `README.md` is updated
- [ ] No temporary files, debug prints, or sensitive API credentials committed
