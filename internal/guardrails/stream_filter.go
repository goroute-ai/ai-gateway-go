package guardrails

import (
	"regexp"
	"unicode/utf8"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
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

// StreamRedactor applies bounded rolling-overlap PII and secret redaction across
// streamed SSE text chunks, ensuring tokens split across chunk boundaries are
// buffered until complete and flushed at stream end.
type StreamRedactor struct {
	buf          string
	overlapBytes int
	maxBufBytes  int
	loggingOnly  bool
	redacted     bool
}

// NewStreamRedactor returns a StreamRedactor when output redaction is enabled
// on the policy, or nil when streaming redaction is not needed.
func NewStreamRedactor(pol *domain.GuardrailPolicy) *StreamRedactor {
	if pol == nil || !pol.RedactOutputPII {
		return nil
	}
	return &StreamRedactor{
		overlapBytes: defaultStreamOverlapBytes,
		maxBufBytes:  maxStreamBufferBytes,
		loggingOnly:  pol.EffectiveMode() == domain.GuardrailModeLoggingOnly,
	}
}

// NewStreamRedactorWithOverlap constructs a StreamRedactor with an explicit
// bounded overlap window (primarily for testing split-chunk boundaries).
func NewStreamRedactorWithOverlap(overlapBytes int) *StreamRedactor {
	if overlapBytes <= 0 {
		overlapBytes = defaultStreamOverlapBytes
	}
	return &StreamRedactor{
		overlapBytes: overlapBytes,
		maxBufBytes:  maxStreamBufferBytes,
	}
}

// Process ingests a streamed text chunk and returns the safe, redacted prefix
// ready to emit downstream, holding back at most a bounded trailing overlap.
func (r *StreamRedactor) Process(chunk string) string {
	if r == nil || chunk == "" {
		return chunk
	}
	if r.loggingOnly {
		return chunk
	}

	r.buf += chunk
	if len(r.buf) <= r.overlapBytes {
		return ""
	}

	emitEnd := len(r.buf) - r.overlapBytes
	for emitEnd > 0 && !utf8.RuneStart(r.buf[emitEnd]) {
		emitEnd--
	}

	// Do not split inside an active token (email, secret, SSN, or card) unless
	// the buffer has reached its safety cap.
	if len(r.buf) < r.maxBufBytes {
		for emitEnd > 0 && isTokenByte(r.buf[emitEnd-1]) && isTokenByte(r.buf[emitEnd]) {
			emitEnd--
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

	if emitEnd <= 0 {
		return ""
	}

	prefix := r.buf[:emitEnd]
	r.buf = r.buf[emitEnd:]

	redacted := sanitizeText(prefix)
	if redacted != prefix {
		r.redacted = true
	}
	return redacted
}

// Flush redacts and returns any remaining buffered text at stream end.
func (r *StreamRedactor) Flush() string {
	if r == nil || r.buf == "" {
		return ""
	}
	tail := r.buf
	r.buf = ""
	if r.loggingOnly {
		return tail
	}
	redacted := sanitizeText(tail)
	if redacted != tail {
		r.redacted = true
	}
	return redacted
}

// Redacted reports whether any streamed content was modified by the redactor.
func (r *StreamRedactor) Redacted() bool {
	return r != nil && r.redacted
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
