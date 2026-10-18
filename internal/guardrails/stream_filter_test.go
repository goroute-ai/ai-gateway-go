package guardrails

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

func TestStreamRedactorSplitChunkEmailAndSSN(t *testing.T) {
	redactor := NewStreamRedactorWithOverlap(32)
	chunks := []string{
		"Please contact ",
		"alice@ex",
		"ample.com",
		" or use SSN 123-4",
		"5-6789 for verification.",
	}
	var out strings.Builder
	for _, c := range chunks {
		out.WriteString(redactor.Process(c))
	}
	out.WriteString(redactor.Flush())

	got := out.String()
	if strings.Contains(got, "alice@example.com") {
		t.Fatalf("email was not redacted across split chunks: %q", got)
	}
	if strings.Contains(got, "123-45-6789") {
		t.Fatalf("SSN was not redacted across split chunks: %q", got)
	}
	if !strings.Contains(got, "[REDACTED_EMAIL]") || !strings.Contains(got, "[REDACTED_SSN]") {
		t.Fatalf("expected redaction placeholders, got %q", got)
	}
	if !redactor.Redacted() {
		t.Fatal("expected Redacted() == true")
	}
}

func TestStreamRedactorSplitSecretBeyondMinimumMatch(t *testing.T) {
	// First chunk already contains 15 chars after sk- (which matches reSecret on its own),
	// and the remainder arrives in the next chunk. Bounded rolling overlap must hold it
	// until complete so no trailing characters of the secret leak.
	redactor := NewStreamRedactorWithOverlap(64)
	chunks := []string{
		"Here is a long prefix so we exceed the overlap window easily without any issue. ",
		"Your key is sk-proj-12345678",
		"90abcdef123456.",
	}
	var out strings.Builder
	for _, c := range chunks {
		out.WriteString(redactor.Process(c))
	}
	out.WriteString(redactor.Flush())

	got := out.String()
	if strings.Contains(got, "sk-proj-") || strings.Contains(got, "90abcdef123456") {
		t.Fatalf("secret leaked across split chunks: %q", got)
	}
	if !strings.Contains(got, "[REDACTED_SECRET]") {
		t.Fatalf("expected [REDACTED_SECRET], got %q", got)
	}
}

func TestStreamRedactorPreservesUTF8Boundaries(t *testing.T) {
	redactor := NewStreamRedactorWithOverlap(8)
	input := "Hello 世界🌍 alice@example.com done"
	var out strings.Builder
	// Feed 3 bytes at a time, splitting multi-byte UTF-8 runes and email
	for i := 0; i < len(input); i += 3 {
		end := i + 3
		if end > len(input) {
			end = len(input)
		}
		out.WriteString(redactor.Process(input[i:end]))
	}
	out.WriteString(redactor.Flush())

	got := out.String()
	want := "Hello 世界🌍 [REDACTED_EMAIL] done"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestStreamRedactorLoggingOnlyDoesNotMutateOrBuffer(t *testing.T) {
	redactor := NewStreamRedactor(&domain.GuardrailPolicy{
		OrgID:           "org",
		Mode:            domain.GuardrailModeLoggingOnly,
		RedactOutputPII: true,
	})
	if redactor == nil {
		t.Fatal("expected non-nil redactor")
	}
	chunk := "email alice@example.com"
	got := redactor.Process(chunk) + redactor.Flush()
	if got != chunk {
		t.Fatalf("logging_only mode mutated stream: got %q, want %q", got, chunk)
	}
	if redactor.Redacted() {
		t.Fatal("logging_only mode should report Redacted() == false")
	}
}

func TestStreamRedactorEnabledForAllOutputPolicies(t *testing.T) {
	if r := NewStreamRedactor(nil); r != nil {
		t.Fatal("expected nil redactor for nil policy without scanners")
	}
	if r := NewStreamRedactor(&domain.GuardrailPolicy{OrgID: "org"}); r != nil {
		t.Fatal("expected nil redactor when no output policy is enabled")
	}

	policies := []struct {
		name string
		pol  *domain.GuardrailPolicy
	}{
		{"pii_detection", &domain.GuardrailPolicy{OrgID: "org", EnablePIIDetection: true, PIIAction: domain.GuardrailActionBlock}},
		{"secret_detection", &domain.GuardrailPolicy{OrgID: "org", EnableSecretDetection: true, SecretAction: domain.GuardrailActionBlock}},
		{"blocked_keywords", &domain.GuardrailPolicy{OrgID: "org", BlockedKeywords: []string{"secret-phrase"}}},
		{"toxicity_filter", &domain.GuardrailPolicy{OrgID: "org", EnableToxicityFilter: true}},
	}
	for _, tc := range policies {
		if r := NewStreamRedactor(tc.pol); r == nil {
			t.Fatalf("expected non-nil StreamRedactor for %s", tc.name)
		}
	}

	scannerRedactor := NewStreamRedactorWithScanners(&domain.GuardrailPolicy{OrgID: "org"}, time.Second, true,
		scannerFunc(func(_ context.Context, req ScanRequest) (ScanResult, error) {
			if strings.Contains(req.Content, "bad-output") {
				return ScanResult{Decision: ScannerDecisionBlock, Violations: []string{"ext:bad"}}, nil
			}
			return ScanResult{Decision: ScannerDecisionAllow}, nil
		}),
	)
	if scannerRedactor == nil {
		t.Fatal("expected non-nil StreamRedactor when external scanners are configured")
	}
	out := scannerRedactor.Process("this is bad-output here") + scannerRedactor.Flush()
	if out != "" || !scannerRedactor.Blocked() {
		t.Fatalf("expected external scanner to block stream, got out=%q blocked=%v", out, scannerRedactor.Blocked())
	}
}

func TestStreamRedactorHoldbackAcrossSplitKeywordsAndToxicity(t *testing.T) {
	pol := &domain.GuardrailPolicy{
		OrgID:                "org",
		Mode:                 domain.GuardrailModeEnforce,
		BlockedKeywords:      []string{"confidential-internal-project-codename"},
		EnableToxicityFilter: true,
		ToxicityAction:       domain.GuardrailActionBlock,
		ToxicityThreshold:    "high",
	}
	redactor := NewStreamRedactor(pol)
	if redactor == nil {
		t.Fatal("expected non-nil redactor")
	}

	chunks := []string{
		"Safe intro text. ",
		"The secret is confidential-inter",
		"nal-project-codename and more.",
	}
	var out strings.Builder
	for _, c := range chunks {
		out.WriteString(redactor.Process(c))
	}
	out.WriteString(redactor.Flush())
	if !redactor.Blocked() {
		t.Fatal("expected split blocked keyword to block stream")
	}
	if strings.Contains(out.String(), "confidential-internal-project-codename") {
		t.Fatalf("blocked keyword leaked across chunks: %q", out.String())
	}

	// Test split toxicity term right at end of stream (Flush boundary).
	toxRedactor := NewStreamRedactor(&domain.GuardrailPolicy{
		OrgID:                "org",
		Mode:                 domain.GuardrailModeEnforce,
		EnableToxicityFilter: true,
		ToxicityAction:       domain.GuardrailActionRedact,
		ToxicityThreshold:    "high",
	})
	var toxOut strings.Builder
	toxOut.WriteString(toxRedactor.Process("You should not build "))
	toxOut.WriteString(toxRedactor.Process("a bo"))
	toxOut.WriteString(toxRedactor.Process("mb"))
	toxOut.WriteString(toxRedactor.Flush())
	if strings.Contains(toxOut.String(), "build a bomb") {
		t.Fatalf("toxicity term leaked at Flush boundary: %q", toxOut.String())
	}
	if !strings.Contains(toxOut.String(), "[REDACTED_TOXICITY]") || !toxRedactor.Redacted() {
		t.Fatalf("expected toxicity redaction, got %q redacted=%v", toxOut.String(), toxRedactor.Redacted())
	}
}

func TestStreamRedactorLoggingOnlyAuditsWithoutBlockingOrMutating(t *testing.T) {
	redactor := NewStreamRedactor(&domain.GuardrailPolicy{
		OrgID:                 "org",
		Mode:                  domain.GuardrailModeLoggingOnly,
		RedactOutputPII:       true,
		EnableSecretDetection: true,
		SecretAction:          domain.GuardrailActionBlock,
		BlockedKeywords:       []string{"restricted-word"},
		EnableToxicityFilter:  true,
		ToxicityAction:        domain.GuardrailActionBlock,
		ToxicityThreshold:     "high",
	})
	if redactor == nil {
		t.Fatal("expected non-nil redactor")
	}

	chunks := []string{
		"restricted-word ",
		"ghp_1234567890abcdefghij1234567890 ",
		"alice@example.com ",
		"build a bomb",
	}
	var out strings.Builder
	for _, c := range chunks {
		out.WriteString(redactor.Process(c))
	}
	out.WriteString(redactor.Flush())

	want := strings.Join(chunks, "")
	if out.String() != want {
		t.Fatalf("logging_only mutated stream: got %q, want %q", out.String(), want)
	}
	if redactor.Redacted() || redactor.Blocked() {
		t.Fatalf("logging_only must not redact or block: redacted=%v blocked=%v", redactor.Redacted(), redactor.Blocked())
	}
	outcome := redactor.Outcome()
	if outcome.AppliedAction != domain.GuardrailActionAudit {
		t.Fatalf("expected AppliedAction=audit, got %q", outcome.AppliedAction)
	}
	if len(outcome.Violations) < 4 {
		t.Fatalf("expected violations for keyword, secret, PII, and toxicity, got %v", outcome.Violations)
	}
}

func TestStreamRedactorBlockedKeywordsAcrossLargeStreamBoundary(t *testing.T) {
	// Place a multi-word / hyphenated blocked keyword right at the 128-byte
	// rolling holdback boundary so it would be missed if split across emitEnd.
	pad := strings.Repeat("a", 65) + " "
	tail := strings.Repeat("b ", 70)
	chunks := []string{
		pad + "forbidden",
		"-phrase here " + tail,
	}

	enforcing := NewStreamRedactor(&domain.GuardrailPolicy{
		OrgID:           "org",
		Mode:            domain.GuardrailModeEnforce,
		BlockedKeywords: []string{"forbidden-phrase"},
	})
	var enforceOut strings.Builder
	for _, c := range chunks {
		enforceOut.WriteString(enforcing.Process(c))
	}
	enforceOut.WriteString(enforcing.Flush())
	if !enforcing.Blocked() {
		t.Fatalf("expected cross-chunk blocked keyword to block stream, outcome=%+v", enforcing.Outcome())
	}
	if strings.Contains(enforceOut.String(), "forbidden-phrase") {
		t.Fatalf("blocked keyword leaked in enforced output: %q", enforceOut.String())
	}

	loggingOnly := NewStreamRedactor(&domain.GuardrailPolicy{
		OrgID:           "org",
		Mode:            domain.GuardrailModeLoggingOnly,
		BlockedKeywords: []string{"forbidden-phrase"},
	})
	var logOut strings.Builder
	for _, c := range chunks {
		logOut.WriteString(loggingOnly.Process(c))
	}
	logOut.WriteString(loggingOnly.Flush())
	if logOut.String() != strings.Join(chunks, "") {
		t.Fatalf("logging_only mutated stream: got %q", logOut.String())
	}
	if loggingOnly.Blocked() || loggingOnly.Redacted() {
		t.Fatalf("logging_only must not block or redact: blocked=%v redacted=%v", loggingOnly.Blocked(), loggingOnly.Redacted())
	}
	outcome := loggingOnly.Outcome()
	if outcome.AppliedAction != domain.GuardrailActionAudit || len(outcome.Violations) != 1 || outcome.Violations[0] != "blocked_keyword:forbidden-phrase" {
		t.Fatalf("expected audit violation for blocked_keyword:forbidden-phrase, got %+v", outcome)
	}
}

type stubStreamScanner struct {
	block bool
}

func (s stubStreamScanner) Scan(_ context.Context, req ScanRequest) (ScanResult, error) {
	if s.block && req.Direction == ScanOutput && strings.Contains(req.Content, "scanner-trigger") {
		return ScanResult{Decision: ScannerDecisionBlock, Violations: []string{"ext_blocked"}}, nil
	}
	return ScanResult{Decision: ScannerDecisionAllow}, nil
}

func TestEngineNewStreamRedactorInheritsConfiguredScanners(t *testing.T) {
	eng := NewEngine(nil)
	eng.ConfigureScanners(500*time.Millisecond, true, stubStreamScanner{block: true})

	redactor := eng.NewStreamRedactor(nil)
	if redactor == nil {
		t.Fatal("expected non-nil StreamRedactor when external scanners are configured")
	}
	_ = redactor.Process("hello scanner-trigger")
	_ = redactor.Flush()
	if !redactor.Blocked() {
		t.Fatalf("expected StreamRedactor from Engine.NewStreamRedactor to block on scanner violation")
	}
}

type stubWindowDriver struct {
	name  string
	hooks []domain.GuardrailHook
	fn    func(ctx context.Context, input *domain.GuardrailEvalInput) (*domain.GuardrailEvalResult, error)
}

func (d *stubWindowDriver) Name() string                           { return d.name }
func (d *stubWindowDriver) SupportedHooks() []domain.GuardrailHook { return d.hooks }
func (d *stubWindowDriver) Evaluate(ctx context.Context, input *domain.GuardrailEvalInput) (*domain.GuardrailEvalResult, error) {
	return d.fn(ctx, input)
}

func TestStreamWindowEvaluatorCrossChunkPIIMaskingAndHoldback(t *testing.T) {
	piiDriver := &stubWindowDriver{
		name: "pii-masker",
		fn: func(_ context.Context, input *domain.GuardrailEvalInput) (*domain.GuardrailEvalResult, error) {
			txt := input.Texts[0]
			if strings.Contains(txt, "john.doe@example.com") {
				masked := strings.ReplaceAll(txt, "john.doe@example.com", "<EMAIL_ADDRESS>")
				return &domain.GuardrailEvalResult{
					Decision:      domain.GuardrailDecisionModify,
					ModifiedTexts: []string{masked},
					Violations: []domain.GuardrailViolation{{
						GuardrailName: "pii-masker",
						Category:      "pii",
						Rule:          "EMAIL_ADDRESS",
						Message:       "email detected",
					}},
				}, nil
			}
			return &domain.GuardrailEvalResult{Decision: domain.GuardrailDecisionAllow}, nil
		},
	}

	eval := NewStreamWindowEvaluator(StreamWindowConfig{
		Unit:        StreamWindowBytes,
		WindowSize:  32,
		OverlapSize: 20,
	}, piiDriver)
	if eval == nil {
		t.Fatal("expected non-nil StreamWindowEvaluator")
	}

	chunks := []string{
		"Hello there, please ",
		"contact john.do",
		"e@exam",
		"ple.com for support ",
		"and have a great day!",
	}

	ctx := context.Background()
	var out strings.Builder
	for _, c := range chunks {
		part, err := eval.Process(ctx, c)
		if err != nil {
			t.Fatalf("Process(%q): %v", c, err)
		}
		if strings.Contains(part, "john.do") {
			t.Fatalf("unmasked email prefix leaked early: %q", part)
		}
		out.WriteString(part)
	}
	tail, err := eval.Flush(ctx)
	if err != nil {
		t.Fatalf("Flush: %v", err)
	}
	out.WriteString(tail)

	got := out.String()
	want := "Hello there, please contact <EMAIL_ADDRESS> for support and have a great day!"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	if !eval.Redacted() || eval.Blocked() {
		t.Fatalf("expected Redacted=true Blocked=false, got redacted=%v blocked=%v", eval.Redacted(), eval.Blocked())
	}
	if len(eval.Violations()) == 0 {
		t.Fatal("expected recorded violation")
	}
}

func TestStreamWindowEvaluatorTokenWindowBlocksBeforeLeak(t *testing.T) {
	blockDriver := &stubWindowDriver{
		name: "phrase-blocker",
		fn: func(_ context.Context, input *domain.GuardrailEvalInput) (*domain.GuardrailEvalResult, error) {
			if strings.Contains(input.Texts[0], "secret launch code alpha") {
				return &domain.GuardrailEvalResult{
					Decision: domain.GuardrailDecisionBlock,
					Violations: []domain.GuardrailViolation{{
						GuardrailName: "phrase-blocker",
						Category:      "banned",
						Rule:          "launch_code",
						Message:       "blocked forbidden multi-token phrase",
					}},
				}, nil
			}
			return &domain.GuardrailEvalResult{Decision: domain.GuardrailDecisionAllow}, nil
		},
	}

	eval := NewStreamWindowEvaluator(StreamWindowConfig{
		Unit:        StreamWindowTokens,
		WindowSize:  8,
		OverlapSize: 4,
	}, blockDriver)

	chunks := []string{
		"one two three four ",
		"five six secret ",
		"launch code ",
		"alpha seven eight.",
	}
	ctx := context.Background()
	var emitted strings.Builder
	var blockErr error
	for _, c := range chunks {
		part, err := eval.Process(ctx, c)
		emitted.WriteString(part)
		if err != nil {
			blockErr = err
			break
		}
	}
	if blockErr == nil {
		tail, err := eval.Flush(ctx)
		emitted.WriteString(tail)
		blockErr = err
	}
	if blockErr == nil {
		t.Fatal("expected blocking error on multi-token phrase spanning chunks")
	}
	if !eval.Blocked() {
		t.Fatal("expected Blocked() == true")
	}
	if strings.Contains(emitted.String(), "secret") || strings.Contains(emitted.String(), "launch") {
		t.Fatalf("blocked phrase tokens leaked before detection: %q", emitted.String())
	}
}

func TestStreamWindowEvaluatorRunesLoggingOnlyAndFailOpen(t *testing.T) {
	// LoggingOnly passes through chunks unmodified while catching cross-chunk violations without duplicate spam.
	flagDriver := &stubWindowDriver{
		name: "audit-driver",
		fn: func(_ context.Context, input *domain.GuardrailEvalInput) (*domain.GuardrailEvalResult, error) {
			if strings.Contains(input.Texts[0], "世界secret") {
				return &domain.GuardrailEvalResult{
					Decision: domain.GuardrailDecisionBlock,
					Violations: []domain.GuardrailViolation{{
						GuardrailName: "audit-driver",
						Category:      "audit",
						Rule:          "unicode_secret",
						Message:       "matched",
					}},
				}, nil
			}
			return &domain.GuardrailEvalResult{Decision: domain.GuardrailDecisionAllow}, nil
		},
	}

	logEval := NewStreamWindowEvaluator(StreamWindowConfig{
		Unit:        StreamWindowRunes,
		WindowSize:  10,
		OverlapSize: 5,
		LoggingOnly: true,
	}, flagDriver)

	ctx := context.Background()
	chunks := []string{"Hello 世界", "sec", "ret world!"}
	var out strings.Builder
	for _, c := range chunks {
		part, err := logEval.Process(ctx, c)
		if err != nil {
			t.Fatalf("logging_only Process error: %v", err)
		}
		out.WriteString(part)
	}
	tail, err := logEval.Flush(ctx)
	if err != nil {
		t.Fatalf("logging_only Flush error: %v", err)
	}
	out.WriteString(tail)
	if out.String() != strings.Join(chunks, "") {
		t.Fatalf("logging_only mutated output: %q", out.String())
	}
	if logEval.Blocked() || logEval.Redacted() {
		t.Fatalf("logging_only must not block or redact")
	}
	if len(logEval.Violations()) != 1 {
		t.Fatalf("expected 1 deduplicated violation, got %v", logEval.Violations())
	}

	// FailOpen vs FailClosed on driver error.
	errDrv := &stubWindowDriver{
		name: "flaky",
		fn: func(_ context.Context, _ *domain.GuardrailEvalInput) (*domain.GuardrailEvalResult, error) {
			return nil, context.DeadlineExceeded
		},
	}
	failOpenEval := NewStreamWindowEvaluator(StreamWindowConfig{
		WindowSize: 8, OverlapSize: 4, FailOpen: true,
	}, errDrv)
	p, err := failOpenEval.Process(ctx, "hello world!")
	if err != nil {
		t.Fatalf("fail-open should not error: %v", err)
	}
	f, err := failOpenEval.Flush(ctx)
	if err != nil {
		t.Fatalf("fail-open flush should not error: %v", err)
	}
	if p+f != "hello world!" {
		t.Fatalf("fail-open dropped text: %q", p+f)
	}

	failClosedEval := NewStreamWindowEvaluator(StreamWindowConfig{
		WindowSize: 8, OverlapSize: 4, FailOpen: false,
	}, errDrv)
	if _, err := failClosedEval.Process(ctx, "hello world!"); err == nil || !failClosedEval.Blocked() {
		t.Fatalf("fail-closed should block and return error, got err=%v blocked=%v", err, failClosedEval.Blocked())
	}
}

func TestStreamRedactorWithDriversIntegration(t *testing.T) {
	drv := &stubWindowDriver{
		name: "mask-driver",
		fn: func(_ context.Context, input *domain.GuardrailEvalInput) (*domain.GuardrailEvalResult, error) {
			txt := input.Texts[0]
			if strings.Contains(txt, "TOKEN-9999") {
				return &domain.GuardrailEvalResult{
					Decision:      domain.GuardrailDecisionModify,
					ModifiedTexts: []string{strings.ReplaceAll(txt, "TOKEN-9999", "[MASKED]")},
					Violations:    []domain.GuardrailViolation{{Category: "secret", Rule: "token"}},
				}, nil
			}
			return &domain.GuardrailEvalResult{Decision: domain.GuardrailDecisionAllow}, nil
		},
	}

	redactor := NewStreamRedactorWithDrivers(
		&domain.GuardrailPolicy{OrgID: "org", Mode: domain.GuardrailModeEnforce},
		StreamWindowConfig{WindowSize: 20, OverlapSize: 12},
		drv,
	)
	if redactor == nil {
		t.Fatal("expected non-nil StreamRedactorWithDrivers")
	}

	var out strings.Builder
	for _, c := range []string{"Here is TOK", "EN-9999 inside ", "the stream."} {
		out.WriteString(redactor.Process(c))
	}
	out.WriteString(redactor.Flush())

	if out.String() != "Here is [MASKED] inside the stream." {
		t.Fatalf("unexpected output: %q", out.String())
	}
	if !redactor.Redacted() || redactor.Blocked() {
		t.Fatalf("expected redacted=true blocked=false, got redacted=%v blocked=%v", redactor.Redacted(), redactor.Blocked())
	}
}
