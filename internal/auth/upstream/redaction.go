package upstream

import (
	"net/http"
	"strings"
)

var sensitiveHeaders = map[string]bool{
	"authorization":                true,
	"x-api-key":                    true,
	"api-key":                      true,
	"proxy-authorization":          true,
	"mcp-session-id":               true,
	"cookie":                       true,
	"set-cookie":                   true,
	"x-upstream-token":             true,
	"x-gateway-master-admin-key":   true,
	"x-gateway-master-encrypt-key": true,
}

// RedactSecret safely masks a credential string so only a short prefix/suffix remains.
func RedactSecret(secret string) string {
	s := strings.TrimSpace(secret)
	if s == "" {
		return ""
	}
	if len(s) <= 8 {
		return "[REDACTED]"
	}
	return s[:4] + "..." + s[len(s)-4:]
}

// IsSensitiveHeader returns true if the header name represents sensitive credentials.
func IsSensitiveHeader(name string) bool {
	return sensitiveHeaders[strings.ToLower(strings.TrimSpace(name))]
}

// MaskHeader masks a header value if the header name is deemed sensitive.
func MaskHeader(name, value string) string {
	if IsSensitiveHeader(name) {
		return RedactSecret(value)
	}
	return value
}

// SanitizeHeaders returns a safe map of HTTP headers with all sensitive values redacted.
func SanitizeHeaders(h http.Header) map[string]string {
	sanitized := make(map[string]string)
	for k, v := range h {
		if len(v) == 0 {
			continue
		}
		joined := strings.Join(v, ", ")
		sanitized[k] = MaskHeader(k, joined)
	}
	return sanitized
}
