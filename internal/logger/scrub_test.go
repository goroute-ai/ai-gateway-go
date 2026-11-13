package logger_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/logger"
)

func TestScrubSecretsPatterns(t *testing.T) {
	cases := []struct {
		name   string
		input  string
		secret string
		want   string
	}{
		{
			name:   "gateway virtual key",
			input:  "auth failed for key sk-gw-12345678-abcdef0123456789",
			secret: "sk-gw-12345678-abcdef0123456789",
			want:   "sk-gw-[REDACTED]",
		},
		{
			name:   "provider sk key",
			input:  "upstream key=sk-proj-secretValue987654321",
			secret: "sk-proj-secretValue987654321",
			want:   "sk-[REDACTED]",
		},
		{
			name:   "bearer token",
			input:  "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig",
			secret: "eyJhbGciOiJIUzI1NiJ9.payload.sig",
			want:   "Bearer [REDACTED]",
		},
		{
			name:   "AQ token",
			input:  "token=AQ.Ab8RN6L_superSecretTokenValue",
			secret: "Ab8RN6L_superSecretTokenValue",
			want:   "AQ.[REDACTED]",
		},
		{
			name:   "AWS AKIA key",
			input:  "aws_access_key_id=AKIAIOSFODNN7EXAMPLE",
			secret: "AKIAIOSFODNN7EXAMPLE",
			want:   "AKIA[REDACTED]",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := logger.ScrubSecrets(tc.input)
			if strings.Contains(got, tc.secret) {
				t.Fatalf("secret %q leaked in %q", tc.secret, got)
			}
			if !strings.Contains(got, tc.want) {
				t.Fatalf("expected %q in scrubbed output %q", tc.want, got)
			}
		})
	}
}

func TestLoggerReplaceAttrScrubsStructuredLogs(t *testing.T) {
	var buf bytes.Buffer
	l := logger.New(logger.Config{
		Level:  "info",
		Format: "json",
		Output: &buf,
	})

	l.Error("request failed with Bearer my-secret-jwt-token",
		slog.String("api_key", "sk-gw-abcd1234-secretpart"),
		slog.String("provider_key", "sk-ant-api03-secretvalue"),
		slog.String("google_token", "AQ.SomeSecretToken123"),
		slog.Any("err", errors.New("rejected AKIAIOSFODNN7EXAMPLE")),
		slog.Group("upstream", slog.String("auth", "Bearer upstream-secret-token")),
	)

	raw := buf.String()
	for _, secret := range []string{
		"my-secret-jwt-token",
		"abcd1234-secretpart",
		"api03-secretvalue",
		"SomeSecretToken123",
		"AKIAIOSFODNN7EXAMPLE",
		"upstream-secret-token",
	} {
		if strings.Contains(raw, secret) {
			t.Fatalf("secret %q leaked in JSON log: %s", secret, raw)
		}
	}

	var parsed map[string]any
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid JSON log output: %v", err)
	}
	if parsed["api_key"] != "sk-gw-[REDACTED]" {
		t.Fatalf("api_key = %v, want sk-gw-[REDACTED]", parsed["api_key"])
	}
	if parsed["provider_key"] != "sk-[REDACTED]" {
		t.Fatalf("provider_key = %v, want sk-[REDACTED]", parsed["provider_key"])
	}
	if parsed["google_token"] != "AQ.[REDACTED]" {
		t.Fatalf("google_token = %v, want AQ.[REDACTED]", parsed["google_token"])
	}
	if parsed["err"] != "rejected AKIA[REDACTED]" {
		t.Fatalf("err = %v, want 'rejected AKIA[REDACTED]'", parsed["err"])
	}
}
