package logger

import (
	"log/slog"
	"regexp"
	"strings"
)

// secretPattern matches known credential and token formats in structured log values:
//   - Bearer <token> (case-insensitive)
//   - sk-gw-<...> (gateway virtual keys)
//   - sk-<...> (provider API keys such as OpenAI/Anthropic)
//   - AQ.<...> (Google/GCP/Gemini API tokens)
//   - AKIA<...> (AWS IAM access key IDs)
var secretPattern = regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+|\bsk-gw-[A-Za-z0-9_-]+|\bsk-[A-Za-z0-9_-]{4,}|\bAQ\.[A-Za-z0-9._-]+|\bAKIA[0-9A-Za-z]{8,}`)

// ScrubSecrets masks recognized credential and secret patterns in s.
func ScrubSecrets(s string) string {
	if s == "" {
		return s
	}
	return secretPattern.ReplaceAllStringFunc(s, func(match string) string {
		lower := strings.ToLower(match)
		switch {
		case strings.HasPrefix(lower, "bearer"):
			return "Bearer [REDACTED]"
		case strings.HasPrefix(lower, "sk-gw-"):
			return "sk-gw-[REDACTED]"
		case strings.HasPrefix(lower, "sk-"):
			return "sk-[REDACTED]"
		case strings.HasPrefix(match, "AQ.") || strings.HasPrefix(match, "aq."):
			return "AQ.[REDACTED]"
		case strings.HasPrefix(strings.ToUpper(match), "AKIA"):
			return "AKIA[REDACTED]"
		default:
			return "[REDACTED]"
		}
	})
}

// scrubAttr is an slog.HandlerOptions.ReplaceAttr function that masks credentials
// in string and error attributes while preserving safe non-secret metadata like key_prefix.
func scrubAttr(groups []string, a slog.Attr) slog.Attr {
	if len(groups) == 0 && a.Key == "key_prefix" {
		return a
	}
	switch a.Value.Kind() {
	case slog.KindString:
		if scrubbed := ScrubSecrets(a.Value.String()); scrubbed != a.Value.String() {
			return slog.String(a.Key, scrubbed)
		}
	case slog.KindAny:
		if err, ok := a.Value.Any().(error); ok && err != nil {
			orig := err.Error()
			if scrubbed := ScrubSecrets(orig); scrubbed != orig {
				return slog.String(a.Key, scrubbed)
			}
		}
	case slog.KindGroup:
		attrs := a.Value.Group()
		changed := false
		out := make([]slog.Attr, len(attrs))
		subGroups := append(groups, a.Key)
		for i, sub := range attrs {
			out[i] = scrubAttr(subGroups, sub)
			if !out[i].Equal(sub) {
				changed = true
			}
		}
		if changed {
			return slog.Attr{Key: a.Key, Value: slog.GroupValue(out...)}
		}
	}
	return a
}
