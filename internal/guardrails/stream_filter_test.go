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
