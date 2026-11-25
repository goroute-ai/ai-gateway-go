package logger

import (
	"fmt"
	"log/slog"
	"regexp"
	"strings"
)

// secretPattern matches known credential and token formats in structured log values:
//   - Bearer <token> / Basic <credentials> (case-insensitive)
//   - ?key=<val> / &key=<val> / x-goog-api-key[:=] <val> (Google/Gemini query & header keys)
//   - sk-gw-<...> (gateway virtual keys)
//   - sk-<...> (provider API keys such as OpenAI/Anthropic)
//   - AQ.<...> / AIza<...> (Google/GCP/Gemini API tokens)
//   - AKIA<...> (AWS IAM access key IDs)
//   - gh[pousr]_<...> / github_pat_<...> (GitHub tokens)
//   - xox[baprs]-<...> (Slack tokens)
//   - PEM private key blocks
//   - JWT tokens (eyJ...)
//   - Database/broker DSNs with embedded credentials (scheme://user:pass@host)
var secretPattern = regexp.MustCompile(`(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+|\bBasic\s+[A-Za-z0-9+/=]{8,}|(?:[?&]key=|x-goog-api-key\s*[:=]\s*)[^\s&"']+|\bsk-gw-[A-Za-z0-9_-]+|\bsk-[A-Za-z0-9_-]{4,}|\bAQ\.[A-Za-z0-9._-]+|\bAIza[0-9A-Za-z_-]{20,}|\bAKIA[0-9A-Za-z]{8,}|\bgh[pousr]_[A-Za-z0-9_]{16,}|\bgithub_pat_[A-Za-z0-9_]{20,}|\bxox[baprs]-[A-Za-z0-9-]{10,}|-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----|\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b|\b(?:postgres(?:ql)?|mysql|redis|rediss|mongodb(?:\+srv)?|amqp|amqps)://[^:\s/@]+:[^@\s]+@`)

var (
	emailPattern = regexp.MustCompile(`\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b`)
	ssnPattern   = regexp.MustCompile(`\b\d{3}-\d{2}-\d{4}\b`)
)

// ScrubSecrets masks recognized credential, secret, and PII patterns in s.
func ScrubSecrets(s string) string {
	if s == "" {
		return s
	}
	s = secretPattern.ReplaceAllStringFunc(s, func(match string) string {
		lower := strings.ToLower(match)
		switch {
		case strings.HasPrefix(lower, "bearer"):
			return "Bearer [REDACTED]"
		case strings.HasPrefix(lower, "basic"):
			return "Basic [REDACTED]"
		case strings.HasPrefix(lower, "?key="):
			return "?key=[REDACTED]"
		case strings.HasPrefix(lower, "&key="):
			return "&key=[REDACTED]"
		case strings.HasPrefix(lower, "x-goog-api-key"):
			if strings.Contains(match, ":") {
				return "x-goog-api-key: [REDACTED]"
			}
			return "x-goog-api-key=[REDACTED]"
		case strings.HasPrefix(lower, "sk-gw-"):
			return "sk-gw-[REDACTED]"
		case strings.HasPrefix(lower, "sk-"):
			return "sk-[REDACTED]"
		case strings.HasPrefix(lower, "aq."):
			return "AQ.[REDACTED]"
		case strings.HasPrefix(match, "AIza"):
			return "AIza[REDACTED]"
		case strings.HasPrefix(strings.ToUpper(match), "AKIA"):
			return "AKIA[REDACTED]"
		case strings.HasPrefix(match, "gh") || strings.HasPrefix(match, "github_pat_"):
			return "[REDACTED_GITHUB_TOKEN]"
		case strings.HasPrefix(match, "xox"):
			return "[REDACTED_SLACK_TOKEN]"
		case strings.HasPrefix(match, "-----BEGIN"):
			return "[REDACTED_PRIVATE_KEY]"
		case strings.HasPrefix(match, "eyJ"):
			return "[REDACTED_JWT]"
		case strings.Contains(match, "://") && strings.HasSuffix(match, "@"):
			if idx := strings.Index(match, "://"); idx >= 0 {
				rest := match[idx+3:]
				if colon := strings.Index(rest, ":"); colon >= 0 {
					return match[:idx+3] + rest[:colon] + ":[REDACTED]@"
				}
			}
			return "[REDACTED_DSN]"
		default:
			return "[REDACTED]"
		}
	})
	s = emailPattern.ReplaceAllString(s, "[REDACTED_EMAIL]")
	s = ssnPattern.ReplaceAllString(s, "[REDACTED_SSN]")
	return s
}

// scrubAttr is an slog.HandlerOptions.ReplaceAttr function that masks credentials and PII
// in string, error, and arbitrary slog.KindAny attributes while preserving safe non-secret metadata like key_prefix.
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
		val := a.Value.Any()
		if val == nil {
			return a
		}
		var orig string
		switch v := val.(type) {
		case error:
			orig = v.Error()
		case fmt.Stringer:
			orig = v.String()
		default:
			orig = fmt.Sprintf("%+v", v)
		}
		if scrubbed := ScrubSecrets(orig); scrubbed != orig {
			return slog.String(a.Key, scrubbed)
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
