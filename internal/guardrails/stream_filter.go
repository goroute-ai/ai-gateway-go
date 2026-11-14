package guardrails

import (
	"context"
	"log/slog"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/logger"
)

const (
	defaultStreamOverlapBytes = 128
	maxStreamBufferBytes      = 4096
)

var streamRedactPatterns = []*regexp.Regexp{
	reEmail,
	reSSN,
	reCard,
	reSecret,
}

// StreamRedactor applies bounded rolling-overlap output guardrails (PII, secrets,
// blocked keywords, toxicity, and optional external scanners) across streamed SSE
// text chunks, ensuring split tokens/patterns are buffered until complete and
// flushed with end-of-stream boundary handling.
type StreamRedactor struct {
	pol               *domain.GuardrailPolicy
	scanners          []Scanner
	scannerTimeout    time.Duration
	scannerFailClosed bool
	buf               string
	overlapBytes      int
	maxBufBytes       int
	loggingOnly       bool
	redacted          bool
	blocked           bool
	outcome           CheckOutcome
}

// NewStreamRedactor returns a StreamRedactor when any output guardrail policy is
// active, or nil when streaming inspection is not needed.
func NewStreamRedactor(pol *domain.GuardrailPolicy) *StreamRedactor {
	return NewStreamRedactorWithScanners(pol, 2*time.Second, true)
}

// NewStreamRedactorWithScanners returns a StreamRedactor configured with optional
// external scanners alongside the organization's GuardrailPolicy.
func NewStreamRedactorWithScanners(
	pol *domain.GuardrailPolicy,
	timeout time.Duration,
	failClosed bool,
	scanners ...Scanner,
) *StreamRedactor {
	if !hasActiveOutputPolicy(pol, scanners) {
		return nil
	}
	if pol == nil {
		pol = &domain.GuardrailPolicy{}
	}
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	overlap := computeStreamHoldback(pol)
	maxBuf := maxStreamBufferBytes
	if overlap*2 > maxBuf {
		maxBuf = overlap * 2
	}
	return &StreamRedactor{
		pol:               pol,
		scanners:          append([]Scanner(nil), scanners...),
		scannerTimeout:    timeout,
		scannerFailClosed: failClosed,
		overlapBytes:      overlap,
		maxBufBytes:       maxBuf,
		loggingOnly:       pol.EffectiveMode() == domain.GuardrailModeLoggingOnly,
	}
}

// NewStreamRedactorWithOverlap constructs a StreamRedactor with an explicit
// bounded overlap window (primarily for testing split-chunk boundaries).
func NewStreamRedactorWithOverlap(overlapBytes int) *StreamRedactor {
	if overlapBytes <= 0 {
		overlapBytes = defaultStreamOverlapBytes
	}
	maxBuf := maxStreamBufferBytes
	if overlapBytes*2 > maxBuf {
		maxBuf = overlapBytes * 2
	}
	return &StreamRedactor{
		pol: &domain.GuardrailPolicy{
			Mode:                  domain.GuardrailModeEnforce,
			RedactOutputPII:       true,
			EnablePIIDetection:    true,
			PIIAction:             domain.GuardrailActionRedact,
			EnableSecretDetection: true,
			SecretAction:          domain.GuardrailActionRedact,
		},
		overlapBytes: overlapBytes,
		maxBufBytes:  maxBuf,
	}
}

func hasActiveOutputPolicy(pol *domain.GuardrailPolicy, scanners []Scanner) bool {
	if len(scanners) > 0 {
		return true
	}
	if pol == nil {
		return false
	}
	return pol.RedactOutputPII ||
		pol.EnablePIIDetection ||
		pol.EnableSecretDetection ||
		len(pol.BlockedKeywords) > 0 ||
		pol.EnableToxicityFilter
}

func computeStreamHoldback(pol *domain.GuardrailPolicy) int {
	longest := defaultStreamOverlapBytes
	if pol == nil {
		return longest
	}
	for _, kw := range pol.BlockedKeywords {
		if n := len(strings.TrimSpace(kw)); n > longest {
			longest = n
		}
	}
	if n := longestToxicityPatternLen(pol); n > longest {
		longest = n
	}
	return longest
}

// Process ingests a streamed text chunk and returns the safe, processed prefix
// ready to emit downstream, holding back at most a bounded trailing overlap.
func (r *StreamRedactor) Process(chunk string) string {
	if r == nil || chunk == "" {
		return chunk
	}
	if r.blocked && !r.loggingOnly {
		return ""
	}

	r.buf += chunk
	if len(r.buf) <= r.overlapBytes {
		if r.loggingOnly {
			return chunk
		}
		return ""
	}

	emitEnd := r.computeEmitEnd()
	if emitEnd <= 0 {
		if r.loggingOnly {
			return chunk
		}
		return ""
	}

	prefix := r.buf[:emitEnd]
	r.buf = r.buf[emitEnd:]

	processed := r.evaluateSegment(prefix)
	if r.loggingOnly {
		return chunk
	}
	if r.blocked {
		return ""
	}
	return processed
}

// Flush evaluates and returns any remaining buffered text at stream end.
func (r *StreamRedactor) Flush() string {
	if r == nil {
		return ""
	}
	if r.loggingOnly {
		if r.buf != "" {
			r.evaluateSegment(r.buf)
			r.buf = ""
		}
		r.logAuditOutcome()
		return ""
	}
	if r.blocked {
		r.buf = ""
		r.logAuditOutcome()
		return ""
	}
	if r.buf == "" {
		r.logAuditOutcome()
		return ""
	}
	tail := r.buf
	r.buf = ""
	processed := r.evaluateSegment(tail)
	r.logAuditOutcome()
	if r.blocked {
		return ""
	}
	return processed
}

// Redacted reports whether any streamed content was modified by the redactor.
func (r *StreamRedactor) Redacted() bool {
	return r != nil && r.redacted
}

// Blocked reports whether the stream was blocked by an output guardrail policy.
func (r *StreamRedactor) Blocked() bool {
	return r != nil && r.blocked
}

// Violations returns a copy of all guardrail violations recorded during streaming.
func (r *StreamRedactor) Violations() []string {
	if r == nil || len(r.outcome.Violations) == 0 {
		return nil
	}
	out := make([]string, len(r.outcome.Violations))
	copy(out, r.outcome.Violations)
	return out
}

// Outcome returns a snapshot of the CheckOutcome accumulated across the stream.
func (r *StreamRedactor) Outcome() CheckOutcome {
	if r == nil {
		return CheckOutcome{}
	}
	out := r.outcome
	if len(r.outcome.Violations) > 0 {
		out.Violations = append([]string(nil), r.outcome.Violations...)
	}
	return out
}

func (r *StreamRedactor) computeEmitEnd() int {
	emitEnd := len(r.buf) - r.overlapBytes
	for emitEnd > 0 && !utf8.RuneStart(r.buf[emitEnd]) {
		emitEnd--
	}

	// Do not split inside an active token unless the buffer has reached its safety cap.
	if len(r.buf) < r.maxBufBytes {
		for emitEnd > 0 && isTokenByte(r.buf[emitEnd-1]) && isTokenByte(r.buf[emitEnd]) {
			emitEnd--
		}
		// Hold back an unclosed PEM private key block until END or maxBufBytes.
		if beginIdx := strings.LastIndex(r.buf, "-----BEGIN "); beginIdx >= 0 && !strings.Contains(r.buf[beginIdx:], "-----END ") {
			if beginIdx < emitEnd {
				emitEnd = beginIdx
			}
		}
	}

	// Extend emitEnd past any complete match that straddles the boundary,
	// or shrink emitEnd before any match that reaches the buffer tail and
	// could still be growing in the next chunk.
	for _, re := range streamRedactPatterns {
		for _, m := range re.FindAllStringIndex(r.buf, -1) {
			start, end := m[0], m[1]
			if start < emitEnd && end > emitEnd {
				if end == len(r.buf) && len(r.buf) < r.maxBufBytes {
					if start < emitEnd {
						emitEnd = start
					}
				} else if end > emitEnd {
					emitEnd = end
				}
			}
		}
	}

	return emitEnd
}

func (r *StreamRedactor) evaluateSegment(segment string) string {
	if segment == "" {
		return segment
	}
	pol := r.pol
	if pol == nil {
		pol = &domain.GuardrailPolicy{RedactOutputPII: true}
	}

	segOutcome := &CheckOutcome{}
	text := segment

	if err := evaluateLocalOutputField(pol, r.loggingOnly, &text, segOutcome); err != nil {
		r.mergeOutcome(segOutcome)
		if !r.loggingOnly {
			r.blocked = true
			return ""
		}
	}
	r.mergeOutcome(segOutcome)

	if len(r.scanners) > 0 {
		eng := &Engine{
			scanners:          r.scanners,
			scannerTimeout:    r.scannerTimeout,
			scannerFailClosed: r.scannerFailClosed,
		}
		scanOutcome := &CheckOutcome{}
		if err := eng.scanOutputField(context.Background(), pol, r.loggingOnly, text, scanOutcome); err != nil {
			r.mergeOutcome(scanOutcome)
			if !r.loggingOnly {
				r.blocked = true
				return ""
			}
		}
		r.mergeOutcome(scanOutcome)
	}

	if r.loggingOnly {
		return segment
	}
	if text != segment {
		r.redacted = true
	}
	return text
}

func (r *StreamRedactor) mergeOutcome(sub *CheckOutcome) {
	if sub == nil {
		return
	}
	r.outcome.Violations = append(r.outcome.Violations, sub.Violations...)
	if sub.AppliedAction != "" {
		r.outcome.AppliedAction = sub.AppliedAction
	}
	if sub.Redacted && !r.loggingOnly {
		r.outcome.Redacted = true
	}
	if sub.RiskScore > r.outcome.RiskScore {
		r.outcome.RiskScore = sub.RiskScore
	}
}

func (r *StreamRedactor) logAuditOutcome() {
	if len(r.outcome.Violations) == 0 {
		return
	}
	orgID := ""
	mode := domain.GuardrailModeEnforce
	if r.pol != nil {
		orgID = r.pol.OrgID
		mode = r.pol.EffectiveMode()
	}
	logger.WarnContext(context.Background(), "Stream guardrail violations detected",
		slog.String("component", "guardrails"),
		slog.String("org_id", orgID),
		slog.String("mode", string(mode)),
		slog.String("applied_action", string(r.outcome.AppliedAction)),
		slog.Bool("redacted", r.redacted),
		slog.Bool("blocked", r.blocked),
		slog.Any("violations", r.outcome.Violations),
	)
}

func isTokenByte(b byte) bool {
	switch {
	case b >= 'a' && b <= 'z',
		b >= 'A' && b <= 'Z',
		b >= '0' && b <= '9':
		return true
	case b == '.', b == '_', b == '%', b == '+', b == '-', b == '@':
		return true
	default:
		return false
	}
}
