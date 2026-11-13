package guardrails

import (
	"strings"
	"testing"

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
