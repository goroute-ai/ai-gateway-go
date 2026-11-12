package guardrails

import "context"

type ScanDirection string

const (
	ScanInput  ScanDirection = "input"
	ScanOutput ScanDirection = "output"
)

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

type ScanResult struct {
	Decision   ScannerDecision
	Violations []string
}

// Scanner extends local guardrail checks. No implementation is enabled by default.
// Network-backed implementations must route egress through the gateway network policy.
type Scanner interface {
	Scan(ctx context.Context, request ScanRequest) (ScanResult, error)
}
