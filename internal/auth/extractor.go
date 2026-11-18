package auth

import (
	"encoding/base64"
	"net/http"
	"strings"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

const (
	// DefaultGatewayAPIKeyHeader is the explicit GoRoute override header that takes
	// precedence over Authorization and provider-native headers.
	DefaultGatewayAPIKeyHeader = "x-goroute-api-key"
)

var providerNativeHeaders = []string{
	"x-api-key",
	"x-goog-api-key",
	"api-key",
	"Ocp-Apim-Subscription-Key",
}

// CredentialSource identifies which HTTP request field supplied a gateway credential.
type CredentialSource string

const (
	CredentialSourceNone          CredentialSource = ""
	CredentialSourceCustomHeader  CredentialSource = "custom_header"
	CredentialSourceGatewayHeader CredentialSource = "gateway_header"
	CredentialSourceBearer        CredentialSource = "bearer"
	CredentialSourceBasic         CredentialSource = "basic"
	CredentialSourceSigV4         CredentialSource = "sigv4"
	CredentialSourceHeaderKey     CredentialSource = "header_key"
	CredentialSourceQuery         CredentialSource = "query"
	CredentialSourceWebSocket     CredentialSource = "websocket"
)

// ExtractedCredentials carries a trimmed credential token alongside its transport source.
type ExtractedCredentials struct {
	Token  string
	Source CredentialSource
}

// ExtractorOptions configures inbound credential extraction behavior.
type ExtractorOptions struct {
	// CustomHeaderName specifies an optional configured gateway header name checked
	// with highest precedence before default gateway and provider-native headers.
	CustomHeaderName string
}

// ExtractCredentials extracts inbound gateway credentials using the following precedence:
//  1. Configured CustomHeaderName (explicit gateway override header)
//  2. x-goroute-api-key (explicit gateway override header)
//  3. Authorization (Bearer, Basic, or AWS4-HMAC-SHA256 Credential=...)
//  4. Provider-native headers (x-api-key, x-goog-api-key, api-key, Ocp-Apim-Subscription-Key)
//  5. Query ?key= on Gemini-compatible routes, or WebSocket subprotocol/query on realtime routes.
//
// Conflicting primary credentials (Authorization vs provider-native headers, or conflicting
// provider-native headers) without an explicit gateway override header return HTTP 400
// ambiguous_gateway_credentials.
func ExtractCredentials(r *http.Request, opts ExtractorOptions) (ExtractedCredentials, error) {
	if r == nil {
		return ExtractedCredentials{}, nil
	}

	if customHeader := strings.TrimSpace(opts.CustomHeaderName); customHeader != "" {
		if token := strings.TrimSpace(r.Header.Get(customHeader)); token != "" {
			return ExtractedCredentials{Token: token, Source: CredentialSourceCustomHeader}, nil
		}
	}

	if token := strings.TrimSpace(r.Header.Get(DefaultGatewayAPIKeyHeader)); token != "" {
		return ExtractedCredentials{Token: token, Source: CredentialSourceGatewayHeader}, nil
	}

	var primary []ExtractedCredentials
	if authCred := extractAuthorizationHeader(r.Header.Get("Authorization")); authCred.Token != "" {
		primary = append(primary, authCred)
	}
	for _, hdr := range providerNativeHeaders {
		if token := strings.TrimSpace(r.Header.Get(hdr)); token != "" {
			primary = append(primary, ExtractedCredentials{
				Token:  token,
				Source: CredentialSourceHeaderKey,
			})
		}
	}

	if len(primary) > 0 {
		first := primary[0]
		for _, candidate := range primary[1:] {
			if candidate.Token != first.Token {
				return ExtractedCredentials{}, &domain.GatewayError{
					StatusCode: http.StatusBadRequest,
					Type:       domain.ErrorTypeAuthentication,
					Code:       "ambiguous_gateway_credentials",
					Message:    "Conflicting authentication credentials: multiple primary credential headers were provided with different values without an explicit gateway override header",
				}
			}
		}
		return first, nil
	}

	if r.URL != nil && isGeminiCompatibleRoute(r.URL.Path) {
		if qKey := strings.TrimSpace(r.URL.Query().Get("key")); qKey != "" {
			return ExtractedCredentials{Token: qKey, Source: CredentialSourceQuery}, nil
		}
	}

	if isRealtimeWebSocketRequest(r) {
		// Browser WebSocket clients can use the OpenAI-compatible subprotocol or query authentication.
		for _, proto := range strings.Split(r.Header.Get("Sec-WebSocket-Protocol"), ",") {
			proto = strings.TrimSpace(proto)
			if strings.HasPrefix(proto, "openai-insecure-api-key.") {
				if tok := strings.TrimSpace(strings.TrimPrefix(proto, "openai-insecure-api-key.")); tok != "" {
					return ExtractedCredentials{
						Token:  tok,
						Source: CredentialSourceWebSocket,
					}, nil
				}
			}
		}

		if qKey := strings.TrimSpace(r.URL.Query().Get("api_key")); qKey != "" {
			return ExtractedCredentials{Token: qKey, Source: CredentialSourceWebSocket}, nil
		}
		if qToken := strings.TrimSpace(r.URL.Query().Get("token")); qToken != "" {
			return ExtractedCredentials{Token: qToken, Source: CredentialSourceWebSocket}, nil
		}
	}

	return ExtractedCredentials{}, nil
}

func extractAuthorizationHeader(raw string) ExtractedCredentials {
	scheme, rest, ok := splitAuthScheme(raw)
	if !ok || rest == "" {
		return ExtractedCredentials{}
	}
	switch {
	case strings.EqualFold(scheme, "Bearer"):
		return ExtractedCredentials{Token: rest, Source: CredentialSourceBearer}
	case strings.EqualFold(scheme, "Basic"):
		if tok := extractBasicToken(rest); tok != "" {
			return ExtractedCredentials{Token: tok, Source: CredentialSourceBasic}
		}
	case strings.EqualFold(scheme, "AWS4-HMAC-SHA256"):
		if tok := extractSigV4Token(rest); tok != "" {
			return ExtractedCredentials{Token: tok, Source: CredentialSourceSigV4}
		}
	}
	return ExtractedCredentials{}
}

func splitAuthScheme(header string) (scheme, rest string, ok bool) {
	header = strings.TrimSpace(header)
	idx := strings.IndexAny(header, " \t")
	if idx < 0 {
		return "", "", false
	}
	return header[:idx], strings.TrimSpace(header[idx+1:]), true
}

func extractBasicToken(encoded string) string {
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(encoded)
		if err != nil {
			return ""
		}
	}
	user, secret, hasColon := strings.Cut(string(decoded), ":")
	if !hasColon {
		return strings.TrimSpace(user)
	}
	if secret = strings.TrimSpace(secret); secret != "" {
		return secret
	}
	return strings.TrimSpace(user)
}

func extractSigV4Token(params string) string {
	for _, part := range strings.Split(params, ",") {
		part = strings.TrimSpace(part)
		const prefix = "Credential="
		if len(part) < len(prefix) || !strings.EqualFold(part[:len(prefix)], prefix) {
			continue
		}
		credVal := part[len(prefix):]
		if slashIdx := strings.IndexByte(credVal, '/'); slashIdx >= 0 {
			credVal = credVal[:slashIdx]
		}
		credVal = strings.TrimLeft(credVal, " \t")
		const bearerPrefix = "Bearer"
		if len(credVal) > len(bearerPrefix) && strings.EqualFold(credVal[:len(bearerPrefix)], bearerPrefix) &&
			(credVal[len(bearerPrefix)] == ' ' || credVal[len(bearerPrefix)] == '\t') {
			credVal = credVal[len(bearerPrefix)+1:]
		}
		return strings.TrimSpace(credVal)
	}
	return ""
}

func isGeminiCompatibleRoute(path string) bool {
	if strings.HasSuffix(path, ":generateContent") ||
		strings.HasSuffix(path, ":streamGenerateContent") ||
		strings.HasSuffix(path, ":countTokens") {
		return true
	}
	return path == "/v1beta" || strings.HasPrefix(path, "/v1beta/") || strings.Contains(path, "/v1beta/")
}

func isRealtimeWebSocketRequest(r *http.Request) bool {
	if r == nil || r.URL == nil || r.Method != http.MethodGet {
		return false
	}
	switch r.URL.Path {
	case "/v1/realtime", "/realtime", "/openai/v1/realtime":
	default:
		return false
	}
	if !strings.EqualFold(strings.TrimSpace(r.Header.Get("Upgrade")), "websocket") {
		return false
	}
	for _, token := range strings.Split(r.Header.Get("Connection"), ",") {
		if strings.EqualFold(strings.TrimSpace(token), "upgrade") {
			return true
		}
	}
	return false
}
