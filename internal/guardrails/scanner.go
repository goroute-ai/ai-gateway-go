package guardrails

import "context"

// ScanDirection indicates whether a scanner is inspecting request input or model output.
type ScanDirection string

const (
	ScanInput  ScanDirection = "input"
	ScanOutput ScanDirection = "output"
)

// ScannerDecision represents the allow or block outcome returned by a Scanner.
type ScannerDecision string

const (
	ScannerDecisionAllow ScannerDecision = "allow"
	ScannerDecisionBlock ScannerDecision = "block"
)

// ScanRequest contains tenant-scoped text for an optional, provider-neutral scanner.
// Implementations must honor context cancellation and should avoid retaining content.
type ScanRequest struct {
	OrgID     string
	Direction ScanDirection
	Content   string
}

// ScanResult carries a Scanner's allow/block decision and any matched violation labels.
type ScanResult struct {
	Decision   ScannerDecision
	Violations []string
}

// Scanner extends local guardrail checks. No implementation is enabled by default.
// Network-backed implementations must route egress through the gateway network policy.
type Scanner interface {
	Scan(ctx context.Context, request ScanRequest) (ScanResult, error)
}
