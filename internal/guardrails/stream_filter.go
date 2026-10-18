package guardrails

import (
	"context"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode"
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
	localActive       bool
	windowEval        *StreamWindowEvaluator
	err               error
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
		localActive:       true,
	}
}

// NewStreamRedactorWithDrivers constructs a StreamRedactor backed by optional local
// GuardrailPolicy rules and/or driver-based buffered window evaluation (StreamWindowEvaluator).
// Returns nil when neither local output policies nor drivers are configured.
func NewStreamRedactorWithDrivers(
	pol *domain.GuardrailPolicy,
	winCfg StreamWindowConfig,
	drivers ...Driver,
) *StreamRedactor {
	localActive := hasActiveOutputPolicy(pol, nil)
	if !localActive && len(drivers) == 0 {
		return nil
	}
	if pol == nil {
		pol = &domain.GuardrailPolicy{}
	}
	loggingOnly := pol.EffectiveMode() == domain.GuardrailModeLoggingOnly || winCfg.LoggingOnly
	if loggingOnly {
		winCfg.LoggingOnly = true
	}

	overlap := computeStreamHoldback(pol)
	maxBuf := maxStreamBufferBytes
	if overlap*2 > maxBuf {
		maxBuf = overlap * 2
	}

	return &StreamRedactor{
		pol:          pol,
		overlapBytes: overlap,
		maxBufBytes:  maxBuf,
		loggingOnly:  loggingOnly,
		localActive:  localActive,
		windowEval:   NewStreamWindowEvaluator(winCfg, drivers...),
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
		localActive:  true,
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
	out, _ := r.ProcessContext(context.Background(), chunk)
	return out
}

// ProcessContext ingests a streamed text chunk under ctx, evaluating local policies
// and any attached StreamWindowEvaluator drivers, returning the safe prefix or an error.
func (r *StreamRedactor) ProcessContext(ctx context.Context, chunk string) (string, error) {
	if r == nil || chunk == "" {
		return chunk, nil
	}
	if r.blocked && !r.loggingOnly {
		return "", r.err
	}

	var stageOut string
	if r.localActive {
		r.buf += chunk
		if len(r.buf) <= r.overlapBytes {
			if r.loggingOnly {
				stageOut = chunk
			} else {
				return "", nil
			}
		} else {
			emitEnd := r.computeEmitEnd()
			if emitEnd <= 0 {
				if r.loggingOnly {
					stageOut = chunk
				} else {
					return "", nil
				}
			} else {
				prefix := r.buf[:emitEnd]
				r.buf = r.buf[emitEnd:]
				processed := r.evaluateSegment(prefix)
				if r.loggingOnly {
					stageOut = chunk
				} else if r.blocked {
					return "", r.err
				} else {
					stageOut = processed
				}
			}
		}
	} else {
		stageOut = chunk
	}

	if r.windowEval != nil && stageOut != "" {
		winOut, err := r.windowEval.Process(ctx, stageOut)
		r.syncWindowState(err)
		if err != nil {
			return "", err
		}
		return winOut, nil
	}
	return stageOut, nil
}

// Flush evaluates and returns any remaining buffered text at stream end.
func (r *StreamRedactor) Flush() string {
	out, _ := r.FlushContext(context.Background())
	return out
}

// FlushContext evaluates and returns any remaining buffered text at stream end under ctx.
func (r *StreamRedactor) FlushContext(ctx context.Context) (string, error) {
	if r == nil {
		return "", nil
	}

	var tailOut string
	if r.localActive {
		if r.loggingOnly {
			if r.buf != "" {
				r.evaluateSegment(r.buf)
				r.buf = ""
			}
		} else if r.blocked {
			r.buf = ""
			r.logAuditOutcome()
			return "", r.err
		} else if r.buf != "" {
			tail := r.buf
			r.buf = ""
			tailOut = r.evaluateSegment(tail)
			if r.blocked {
				r.logAuditOutcome()
				return "", r.err
			}
		}
	}

	if r.windowEval != nil {
		if tailOut != "" && !r.loggingOnly {
			winOut, err := r.windowEval.Process(ctx, tailOut)
			r.syncWindowState(err)
			if err != nil {
				r.logAuditOutcome()
				return "", err
			}
			flushed, flushErr := r.windowEval.Flush(ctx)
			r.syncWindowState(flushErr)
			if flushErr != nil {
				r.logAuditOutcome()
				return "", flushErr
			}
			tailOut = winOut + flushed
		} else {
			flushed, flushErr := r.windowEval.Flush(ctx)
			r.syncWindowState(flushErr)
			if flushErr != nil {
				r.logAuditOutcome()
				return "", flushErr
			}
			if !r.loggingOnly {
				tailOut = flushed
			}
		}
	}

	r.logAuditOutcome()
	if r.loggingOnly || r.blocked {
		return "", r.err
	}
	return tailOut, nil
}

func (r *StreamRedactor) syncWindowState(err error) {
	if r.windowEval == nil {
		return
	}
	if err != nil && r.err == nil {
		r.err = err
	}
	if r.windowEval.Blocked() {
		r.blocked = true
	}
	if r.windowEval.Redacted() {
		r.redacted = true
	}
	winOut := r.windowEval.Outcome()
	r.outcome = mergeCheckOutcomes(r.outcome, winOut)
}

func mergeCheckOutcomes(base, add CheckOutcome) CheckOutcome {
	// Keep base violations plus any additional window violations not already captured.
	out := base
	if len(add.Violations) > 0 {
		existing := make(map[string]int, len(base.Violations))
		for _, v := range base.Violations {
			existing[v]++
		}
		incoming := make(map[string]int, len(add.Violations))
		for _, v := range add.Violations {
			incoming[v]++
			if incoming[v] > existing[v] {
				out.Violations = append(out.Violations, v)
			}
		}
	}
	if add.AppliedAction != "" {
		out.AppliedAction = add.AppliedAction
	}
	if add.Redacted {
		out.Redacted = true
	}
	if add.RiskScore > out.RiskScore {
		out.RiskScore = add.RiskScore
	}
	return out
}

// Err returns any blocking or driver evaluation error recorded during streaming.
func (r *StreamRedactor) Err() error {
	if r == nil {
		return nil
	}
	return r.err
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

	if r.pol != nil && len(r.pol.BlockedKeywords) > 0 {
		lowerBuf := strings.ToLower(r.buf)
		if len(lowerBuf) == len(r.buf) {
			for _, kw := range r.pol.BlockedKeywords {
				kwLower := strings.ToLower(strings.TrimSpace(kw))
				if kwLower == "" {
					continue
				}
				searchFrom := 0
				for searchFrom < len(lowerBuf) {
					idx := strings.Index(lowerBuf[searchFrom:], kwLower)
					if idx < 0 {
						break
					}
					start := searchFrom + idx
					end := start + len(kwLower)
					if start < emitEnd && end > emitEnd {
						if end == len(r.buf) && len(r.buf) < r.maxBufBytes {
							emitEnd = start
						} else if end > emitEnd {
							emitEnd = end
						}
					}
					searchFrom = end
				}
			}
		}
	}

	for emitEnd < len(r.buf) && !utf8.RuneStart(r.buf[emitEnd]) {
		emitEnd++
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
			r.err = err
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
				r.err = err
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

// StreamWindowUnit selects whether StreamWindowEvaluator measures window/overlap
// thresholds in bytes, Unicode runes (chars), or whitespace-delimited tokens.
type StreamWindowUnit string

const (
	StreamWindowBytes  StreamWindowUnit = "bytes"
	StreamWindowRunes  StreamWindowUnit = "runes"
	StreamWindowTokens StreamWindowUnit = "tokens"
)

// StreamWindowConfig configures overlapping buffered window evaluation for
// driver-based streaming guardrails.
type StreamWindowConfig struct {
	Unit           StreamWindowUnit
	WindowSize     int
	OverlapSize    int
	MaxBufferBytes int
	DriverTimeout  time.Duration
	FailOpen       bool
	LoggingOnly    bool
	InputTemplate  *domain.GuardrailEvalInput
}

// StreamWindowEvaluator buffers streamed chunks and evaluates overlapping N-byte,
// N-rune, or N-token windows against one or more Guardrail Drivers before releasing
// the non-overlapping prefix downstream. Any violation or PII spanning a chunk
// boundary remains held back in the overlap tail until evaluated and either blocked
// or masked.
type StreamWindowEvaluator struct {
	mu             sync.Mutex
	cfg            StreamWindowConfig
	drivers        []Driver
	buf            string
	blocked        bool
	redacted       bool
	lastErr        error
	violations     []string
	evalViolations []domain.GuardrailViolation
	appliedAction  domain.GuardrailAction
	lastTailKeys   map[string]struct{}
}

// NewStreamWindowEvaluator constructs a StreamWindowEvaluator for drivers.
// Returns nil when no drivers are provided.
func NewStreamWindowEvaluator(cfg StreamWindowConfig, drivers ...Driver) *StreamWindowEvaluator {
	active := make([]Driver, 0, len(drivers))
	for _, d := range drivers {
		if d != nil {
			active = append(active, d)
		}
	}
	if len(active) == 0 {
		return nil
	}

	if cfg.Unit == "" {
		cfg.Unit = StreamWindowBytes
	}
	if cfg.DriverTimeout <= 0 {
		cfg.DriverTimeout = 5 * time.Second
	}

	switch cfg.Unit {
	case StreamWindowTokens:
		if cfg.WindowSize <= 0 && cfg.OverlapSize <= 0 {
			cfg.WindowSize = 32
			cfg.OverlapSize = 8
		} else if cfg.WindowSize <= 0 {
			cfg.WindowSize = cfg.OverlapSize * 2
		} else if cfg.OverlapSize < 0 {
			cfg.OverlapSize = 0
		} else if cfg.OverlapSize >= cfg.WindowSize {
			cfg.OverlapSize = cfg.WindowSize / 2
		}
	default:
		if cfg.WindowSize <= 0 && cfg.OverlapSize <= 0 {
			cfg.WindowSize = 256
			cfg.OverlapSize = defaultStreamOverlapBytes
		} else if cfg.WindowSize <= 0 {
			cfg.WindowSize = cfg.OverlapSize * 2
		} else if cfg.OverlapSize < 0 {
			cfg.OverlapSize = 0
		} else if cfg.OverlapSize >= cfg.WindowSize {
			cfg.OverlapSize = cfg.WindowSize / 2
		}
	}

	if cfg.MaxBufferBytes <= 0 {
		cfg.MaxBufferBytes = maxStreamBufferBytes * 2
	}
	if cfg.Unit != StreamWindowTokens && cfg.WindowSize*2 > cfg.MaxBufferBytes {
		cfg.MaxBufferBytes = cfg.WindowSize * 2
	}

	return &StreamWindowEvaluator{
		cfg:     cfg,
		drivers: active,
	}
}

// Process buffers chunk and, once the configured window threshold is reached,
// evaluates the buffered window against all drivers, emitting only the safe prefix
// outside the trailing overlap holdback.
func (e *StreamWindowEvaluator) Process(ctx context.Context, chunk string) (string, error) {
	if e == nil || chunk == "" {
		return chunk, nil
	}
	if ctx == nil {
		ctx = context.Background()
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	if e.blocked && !e.cfg.LoggingOnly {
		return "", e.lastErr
	}

	e.buf += chunk
	if !e.shouldEvaluateLocked() {
		if e.cfg.LoggingOnly {
			return chunk, nil
		}
		return "", nil
	}

	evaluated, err := e.evaluateLocked(ctx, e.buf)
	if err != nil {
		return "", err
	}

	if e.cfg.LoggingOnly {
		emitEnd := e.computeEmitEndLocked(e.buf)
		if emitEnd > 0 {
			e.buf = e.buf[emitEnd:]
		}
		return chunk, nil
	}

	e.buf = evaluated
	emitEnd := e.computeEmitEndLocked(e.buf)
	if emitEnd <= 0 {
		return "", nil
	}

	out := e.buf[:emitEnd]
	e.buf = e.buf[emitEnd:]
	return out, nil
}

// Flush evaluates any remaining buffered tail at end-of-stream and returns it
// (masked if modified, or empty with an error if blocked).
func (e *StreamWindowEvaluator) Flush(ctx context.Context) (string, error) {
	if e == nil {
		return "", nil
	}
	if ctx == nil {
		ctx = context.Background()
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	if e.blocked && !e.cfg.LoggingOnly {
		e.buf = ""
		return "", e.lastErr
	}
	if e.buf == "" {
		return "", nil
	}

	tail := e.buf
	e.buf = ""

	evaluated, err := e.evaluateLocked(ctx, tail)
	if err != nil {
		return "", err
	}
	if e.cfg.LoggingOnly {
		return "", nil
	}
	return evaluated, nil
}

// Blocked reports whether the stream was terminated by a blocking driver verdict or fail-closed error.
func (e *StreamWindowEvaluator) Blocked() bool {
	if e == nil {
		return false
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.blocked
}

// Redacted reports whether any streamed text was modified/masked by a driver.
func (e *StreamWindowEvaluator) Redacted() bool {
	if e == nil {
		return false
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.redacted
}

// Err returns the blocking or driver error if evaluation terminated the stream.
func (e *StreamWindowEvaluator) Err() error {
	if e == nil {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.lastErr
}

// Violations returns a copy of violation labels observed during stream evaluation.
func (e *StreamWindowEvaluator) Violations() []string {
	if e == nil {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.violations) == 0 {
		return nil
	}
	out := make([]string, len(e.violations))
	copy(out, e.violations)
	return out
}

// EvalViolations returns a copy of structured GuardrailViolation records observed during streaming.
func (e *StreamWindowEvaluator) EvalViolations() []domain.GuardrailViolation {
	if e == nil {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.evalViolations) == 0 {
		return nil
	}
	out := make([]domain.GuardrailViolation, len(e.evalViolations))
	copy(out, e.evalViolations)
	return out
}

// Outcome returns a CheckOutcome summary compatible with StreamRedactor.
func (e *StreamWindowEvaluator) Outcome() CheckOutcome {
	if e == nil {
		return CheckOutcome{}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	var vCopy []string
	if len(e.violations) > 0 {
		vCopy = make([]string, len(e.violations))
		copy(vCopy, e.violations)
	}
	return CheckOutcome{
		Redacted:      e.redacted,
		Violations:    vCopy,
		AppliedAction: e.appliedAction,
	}
}

func (e *StreamWindowEvaluator) shouldEvaluateLocked() bool {
	if len(e.buf) >= e.cfg.MaxBufferBytes {
		return true
	}
	switch e.cfg.Unit {
	case StreamWindowTokens:
		return countStreamTokens(e.buf) >= e.cfg.WindowSize
	case StreamWindowRunes:
		return utf8.RuneCountInString(e.buf) >= e.cfg.WindowSize
	default:
		return len(e.buf) >= e.cfg.WindowSize
	}
}

func (e *StreamWindowEvaluator) computeEmitEndLocked(text string) int {
	if text == "" {
		return 0
	}
	if e.cfg.OverlapSize <= 0 {
		return len(text)
	}

	var emitEnd int
	switch e.cfg.Unit {
	case StreamWindowTokens:
		spans := findStreamTokenSpans(text)
		if len(spans) <= e.cfg.OverlapSize {
			if len(text) >= e.cfg.MaxBufferBytes {
				return len(text) / 2
			}
			return 0
		}
		emitEnd = spans[len(spans)-e.cfg.OverlapSize].start
		for emitEnd > 0 && !utf8.RuneStart(text[emitEnd]) {
			emitEnd--
		}
		return emitEnd

	case StreamWindowRunes:
		totalRunes := utf8.RuneCountInString(text)
		if totalRunes <= e.cfg.OverlapSize {
			return 0
		}
		targetRunes := totalRunes - e.cfg.OverlapSize
		runesSeen := 0
		for byteIdx := range text {
			if runesSeen == targetRunes {
				emitEnd = byteIdx
				break
			}
			runesSeen++
		}
		if emitEnd == 0 {
			return 0
		}

	default:
		if len(text) <= e.cfg.OverlapSize {
			return 0
		}
		emitEnd = len(text) - e.cfg.OverlapSize
		for emitEnd > 0 && !utf8.RuneStart(text[emitEnd]) {
			emitEnd--
		}
	}

	// Avoid splitting an active token unless the buffer reached its hard cap.
	if len(text) < e.cfg.MaxBufferBytes {
		origEmit := emitEnd
		for emitEnd > 0 && isTokenByte(text[emitEnd-1]) && isTokenByte(text[emitEnd]) {
			emitEnd--
		}
		// If a single uninterrupted token fills the prefix, fall back to origEmit at max cap
		// or wait if not at cap.
		if emitEnd == 0 && origEmit > 0 && len(text) >= e.cfg.MaxBufferBytes {
			emitEnd = origEmit
		}
	}

	for emitEnd < len(text) && !utf8.RuneStart(text[emitEnd]) {
		emitEnd++
	}
	return emitEnd
}

func (e *StreamWindowEvaluator) evaluateLocked(ctx context.Context, text string) (string, error) {
	if text == "" {
		return text, nil
	}

	current := text
	currentWindowKeys := make(map[string]struct{})

	for _, drv := range e.drivers {
		evalIn := e.buildEvalInputLocked(current)
		drvCtx := ctx
		var cancel context.CancelFunc
		if e.cfg.DriverTimeout > 0 {
			drvCtx, cancel = context.WithTimeout(ctx, e.cfg.DriverTimeout)
		}
		res, err := drv.Evaluate(drvCtx, evalIn)
		if cancel != nil {
			cancel()
		}

		if err != nil {
			if e.cfg.FailOpen || e.cfg.LoggingOnly {
				continue
			}
			e.blocked = true
			e.buf = ""
			e.appliedAction = domain.GuardrailActionBlock
			e.lastErr = wrapDriverUnavailableError(drv.Name(), err)
			return "", e.lastErr
		}
		if res == nil {
			continue
		}

		for _, v := range res.Violations {
			label := streamViolationLabel(drv.Name(), v)
			key := fmt.Sprintf("%s|%s|%s|%s", drv.Name(), v.Category, v.Rule, v.Message)
			currentWindowKeys[key] = struct{}{}
			if _, seen := e.lastTailKeys[key]; seen {
				continue
			}
			e.violations = append(e.violations, label)
			e.evalViolations = append(e.evalViolations, v)
		}

		switch res.Decision {
		case domain.GuardrailDecisionBlock:
			if e.cfg.LoggingOnly {
				if e.appliedAction == "" {
					e.appliedAction = domain.GuardrailActionAudit
				}
				continue
			}
			e.blocked = true
			e.buf = ""
			e.appliedAction = domain.GuardrailActionBlock
			e.lastErr = newBlockedGatewayError(evalIn.Hook, drv.Name(), res)
			return "", e.lastErr

		case domain.GuardrailDecisionModify:
			if e.cfg.LoggingOnly {
				if e.appliedAction == "" {
					e.appliedAction = domain.GuardrailActionAudit
				}
				continue
			}
			if len(res.ModifiedTexts) > 0 && res.ModifiedTexts[0] != current {
				current = res.ModifiedTexts[0]
				e.redacted = true
				if e.appliedAction == "" {
					e.appliedAction = domain.GuardrailActionRedact
				}
			}

		case domain.GuardrailDecisionFlag:
			if e.appliedAction == "" {
				e.appliedAction = domain.GuardrailActionAudit
			}
		}
	}

	e.lastTailKeys = currentWindowKeys
	return current, nil
}

func (e *StreamWindowEvaluator) buildEvalInputLocked(text string) *domain.GuardrailEvalInput {
	if e.cfg.InputTemplate != nil {
		cp := cloneGuardrailEvalInput(e.cfg.InputTemplate)
		if cp.Direction == "" {
			cp.Direction = domain.GuardrailDirectionOutput
		}
		if cp.Hook == "" {
			cp.Hook = domain.GuardrailHookPostCall
		}
		cp.Texts = []string{text}
		cp.StructuredMessages = nil
		return cp
	}
	return &domain.GuardrailEvalInput{
		Direction: domain.GuardrailDirectionOutput,
		Hook:      domain.GuardrailHookPostCall,
		Texts:     []string{text},
	}
}

func streamViolationLabel(driverName string, v domain.GuardrailViolation) string {
	switch {
	case v.Category != "" && v.Rule != "":
		return v.Category + ":" + v.Rule
	case v.Rule != "":
		return v.Rule
	case v.Category != "":
		return v.Category
	case v.GuardrailName != "":
		return v.GuardrailName
	default:
		return driverName
	}
}

type streamTokenSpan struct {
	start int
	end   int
}

func findStreamTokenSpans(s string) []streamTokenSpan {
	var spans []streamTokenSpan
	inTok := false
	tokStart := 0
	for i, r := range s {
		if unicode.IsSpace(r) {
			if inTok {
				spans = append(spans, streamTokenSpan{start: tokStart, end: i})
				inTok = false
			}
		} else if !inTok {
			tokStart = i
			inTok = true
		}
	}
	if inTok {
		spans = append(spans, streamTokenSpan{start: tokStart, end: len(s)})
	}
	return spans
}

func countStreamTokens(s string) int {
	return len(findStreamTokenSpans(s))
}
