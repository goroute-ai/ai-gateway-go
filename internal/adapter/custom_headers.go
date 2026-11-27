// Custom header helpers enforce a uniform allowlist and CRLF filter across all
// upstream provider adapters so tenant-configured credential headers can never
// spoof framing, hop-by-hop, W3C trace, or vault auth headers.

package adapter

import (
	"net/http"
	"strings"
)

// IsReservedCustomHeader reports whether name is a framing, hop-by-hop, trace,
// or provider authentication header that must not be overridden by credential Headers.
func IsReservedCustomHeader(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "host", "content-length", "transfer-encoding", "connection",
		"keep-alive", "te", "trailer", "upgrade", "proxy-authenticate",
		"content-type", "traceparent", "tracestate",
		"x-goog-api-key", "x-api-key", "api-key":
		return true
	default:
		return false
	}
}

// HasUnsafeHeaderChars reports whether s contains CR, LF, or NUL bytes.
func HasUnsafeHeaderChars(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == '\r' || s[i] == '\n' || s[i] == 0 {
			return true
		}
	}
	return false
}

// ApplySafeCustomHeaders copies non-reserved, control-character-free custom
// credential headers onto req. Adapters should invoke this before applying
// vault-decrypted provider authentication headers so vault keys always take precedence.
func ApplySafeCustomHeaders(req *http.Request, headers map[string]string) {
	if req == nil || len(headers) == 0 {
		return
	}
	for k, v := range headers {
		kTrim := strings.TrimSpace(k)
		vTrim := strings.TrimSpace(v)
		if kTrim == "" || vTrim == "" || HasUnsafeHeaderChars(kTrim) || HasUnsafeHeaderChars(vTrim) || IsReservedCustomHeader(kTrim) {
			continue
		}
		req.Header.Set(kTrim, vTrim)
	}
}
