package adapter

import (
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
)

func containsASCIIControl(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			return true
		}
	}
	return false
}

// ValidateAndResolveBaseURL validates a provider BaseURL override against URL syntax
// invariants (HTTP/HTTPS scheme, non-empty host, no userinfo, no query or fragment, no
// path traversal or ASCII control characters) and the active outbound network SSRF policy
// (defaulting to strict public-HTTPS enforcement when policy is nil). When rawBaseURL is
// blank, it returns the canonicalized defaultBaseURL.
func ValidateAndResolveBaseURL(rawBaseURL, defaultBaseURL string, policy *network.Policy) (string, error) {
	if containsASCIIControl(rawBaseURL) {
		return "", fmt.Errorf("base URL must not contain control characters")
	}
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
	if containsASCIIControl(u.Host) || containsASCIIControl(u.Path) {
		return "", fmt.Errorf("base URL must not contain control characters")
	}
	for _, seg := range strings.Split(u.Path, "/") {
		if seg == ".." {
			return "", fmt.Errorf("base URL must not contain path traversal segments")
		}
	}
	if policy == nil {
		strictPol, err := network.NewPolicy(config.OutboundSSRFConfig{})
		if err != nil {
			return "", fmt.Errorf("default outbound network policy: %w", err)
		}
		policy = strictPol
	}
	if err := policy.ValidateURL(u); err != nil {
		return "", fmt.Errorf("base URL blocked by outbound network policy: %w", err)
	}

	cleanPath := strings.TrimRight(u.Path, "/")
	if cleanPath != "" {
		cleaned := path.Clean("/" + strings.TrimLeft(cleanPath, "/"))
		if cleaned == "/" {
			cleanPath = ""
		} else {
			cleanPath = strings.TrimRight(cleaned, "/")
		}
	}

	clean := url.URL{
		Scheme: scheme,
		Host:   u.Host,
		Path:   cleanPath,
	}
	return strings.TrimRight(clean.String(), "/"), nil
}

// ResolveCredentialBaseURL resolves and validates a credential's BaseURL override against
// policy, returning a structured invalid_base_url GatewayError on validation failure.
func ResolveCredentialBaseURL(cred *domain.ProviderCredential, defaultBaseURL string, policy *network.Policy, provider domain.ProviderType) (string, error) {
	rawBase := ""
	if cred != nil {
		rawBase = cred.BaseURL
	}
	base, err := ValidateAndResolveBaseURL(rawBase, defaultBaseURL, policy)
	if err != nil {
		return "", &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_base_url",
			Message:    err.Error(),
			Provider:   provider,
		}
	}
	return base, nil
}
