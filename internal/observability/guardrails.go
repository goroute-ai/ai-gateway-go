package observability

import (
	"context"
	"regexp"
	"strings"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

var safeCategoryTokenRe = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.:-]{0,47}$`)

// GuardrailObservation records one guardrail evaluation for OTLP and UI telemetry.
type GuardrailObservation struct {
	GuardrailName string
	Hook          string
	Decision      string
	LatencyMs     int64
	IsError       bool
}

// GuardrailMetricKey identifies a guardrail+hook combination for bounded telemetry aggregation.
type GuardrailMetricKey struct {
	Guardrail string `json:"guardrail"`
	Hook      string `json:"hook"`
}

// GuardrailMetricSummary holds bounded telemetry summary stats for one guardrail+hook pair.
type GuardrailMetricSummary struct {
	Guardrail        string           `json:"guardrail"`
	Hook             string           `json:"hook"`
	Evaluations      int64            `json:"evaluations"`
	Errors           int64            `json:"errors"`
	DecisionCounts   map[string]int64 `json:"decision_counts"`
	DurationSumMs    int64            `json:"duration_sum_ms"`
	DurationCount    int64            `json:"duration_count"`
	HistogramBuckets []int64          `json:"histogram_buckets"`
	HistogramBoundMs []int64          `json:"histogram_bound_ms"`
}

const guardrailDecisionError = "error"

var guardrailLatencyBoundsMs = []int64{5, 10, 25, 50, 100, 250, 500, 1000}

// NormalizeGuardrailDecision maps guardrail decisions into safe low-cardinality labels:
// allow | block | flag | modify | error.
func NormalizeGuardrailDecision(decision string, isError bool) string {
	if isError {
		return guardrailDecisionError
	}
	switch strings.ToLower(strings.TrimSpace(decision)) {
	case "allow":
		return "allow"
	case "block":
		return "block"
	case "flag":
		return "flag"
	case "modify", "redact", "mask":
		return "modify"
	case guardrailDecisionError:
		return guardrailDecisionError
	default:
		return "allow"
	}
}

// ScrubViolationCategories sanitizes violation category tags before emitting them
// on OTEL spans so raw prompts, responses, PII, or secrets are never exposed.
func ScrubViolationCategories(categories []string) []string {
	if len(categories) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(categories))
	out := make([]string, 0, len(categories))
	for _, raw := range categories {
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" {
			continue
		}
		lower := strings.ToLower(trimmed)
		// Reject values containing whitespace, email/secret shapes, or non-token punctuation.
		if strings.ContainsAny(trimmed, " \t\r\n@'\"=/?&") ||
			strings.HasPrefix(lower, "sk-") ||
			strings.HasPrefix(lower, "bearer") ||
			strings.Contains(lower, "password") ||
			strings.Contains(lower, "secret") ||
			strings.Contains(lower, "token") ||
			!safeCategoryTokenRe.MatchString(trimmed) {
			lower = "policy_violation"
		}
		if _, exists := seen[lower]; exists {
			continue
		}
		seen[lower] = struct{}{}
		out = append(out, lower)
		if len(out) >= 16 {
			break
		}
	}
	return out
}

// StartGuardrailEvaluateSpan opens an OTEL child span named `guardrail.evaluate`
// with only safe non-PII attributes.
func StartGuardrailEvaluateSpan(ctx context.Context, tracer trace.Tracer, guardrailName, hook string) (context.Context, trace.Span) {
	if tracer == nil {
		tracer = otel.Tracer("github.com/goroute-ai/ai-gateway-go")
	}
	return tracer.Start(ctx, "guardrail.evaluate",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			attribute.String("guardrail.name", sanitizeGuardrailLabel(guardrailName)),
			attribute.String("guardrail.hook", sanitizeGuardrailLabel(hook)),
		),
	)
}

// FinishGuardrailEvaluateSpan completes a `guardrail.evaluate` span with decision,
// scrubbed violation category tags, and latency_ms (never raw prompts or secrets).
func FinishGuardrailEvaluateSpan(span trace.Span, decision string, violationCategories []string, latencyMs int64, isError bool) {
	if span == nil {
		return
	}
	latencyMs = max(latencyMs, 0)
	normDecision := NormalizeGuardrailDecision(decision, isError)
	attrs := []attribute.KeyValue{
		attribute.String("guardrail.decision", normDecision),
		attribute.Int64("guardrail.latency_ms", latencyMs),
	}
	if cats := ScrubViolationCategories(violationCategories); len(cats) > 0 {
		attrs = append(attrs, attribute.StringSlice("guardrail.violation_categories", cats))
	}
	span.SetAttributes(attrs...)
	if isError || normDecision == guardrailDecisionError {
		span.SetStatus(codes.Error, "guardrail evaluation error")
	}
	span.End()
}

func sanitizeGuardrailLabel(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "unknown"
	}
	if len(s) > 64 {
		s = s[:64]
	}
	return s
}
