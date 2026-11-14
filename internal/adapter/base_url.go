package adapter

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
)

// ValidateAndResolveBaseURL validates a provider BaseURL override against URL syntax
// invariants (HTTP/HTTPS scheme, non-empty host, no userinfo, no query or fragment) and,
// when policy is non-nil, the active outbound network SSRF policy. When rawBaseURL is
// blank, it returns the canonicalized defaultBaseURL.
func ValidateAndResolveBaseURL(rawBaseURL, defaultBaseURL string, policy *network.Policy) (string, error) {
	trimmed := strings.TrimSpace(rawBaseURL)
	if trimmed == "" {
		return strings.TrimRight(strings.TrimSpace(defaultBaseURL), "/"), nil
	}

	u, err := url.Parse(trimmed)
	if err != nil {
		return "", fmt.Errorf("invalid base URL: %w", err)
	}
	scheme := strings.ToLower(strings.TrimSpace(u.Scheme))
	if scheme != "https" && scheme != "http" {
		return "", fmt.Errorf("base URL must use http or https scheme")
	}
	if strings.TrimSpace(u.Hostname()) == "" {
		return "", fmt.Errorf("base URL must include a hostname")
	}
	if u.User != nil {
		return "", fmt.Errorf("base URL must not include embedded credentials")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("base URL must not include query parameters or fragments")
	}
	if policy != nil {
		if err := policy.ValidateURL(u); err != nil {
			return "", fmt.Errorf("base URL blocked by outbound network policy: %w", err)
		}
	}

	clean := url.URL{
		Scheme: scheme,
		Host:   u.Host,
		Path:   strings.TrimRight(u.Path, "/"),
	}
	return strings.TrimRight(clean.String(), "/"), nil
}
