package adapter

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"

	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
)

// DefaultPublicMediaPolicy returns a strict public-HTTPS outbound policy for
// fetching untrusted end-user media URLs. Private/local networks and metadata IPs
// are unconditionally blocked even if provider LLM routing allows private networks.
func DefaultPublicMediaPolicy() *network.Policy {
	p, _ := network.NewPolicy(config.OutboundSSRFConfig{
		AllowPrivateNetworks: false,
		AllowInsecureHTTP:    false,
		AllowedSchemes:       []string{"https"},
		BlockedIPs:           []string{"169.254.169.254"},
	})
	return p
}

// FetchRemoteDataURI fetches user-supplied HTTPS media using the strict public-HTTPS
// media policy and returns a bounded base64 data URI.
func FetchRemoteDataURI(ctx context.Context, client *http.Client, rawURL string, maxBytes int64, allowedTypes ...string) (string, error) {
	return FetchRemoteDataURIWithPolicy(ctx, client, nil, rawURL, maxBytes, allowedTypes...)
}

func validateStrictMediaPort(policy *network.Policy, u *url.URL) error {
	if u == nil {
		return fmt.Errorf("media URL is nil")
	}
	if policy != nil && !policy.AllowPrivateNetworks && len(policy.AllowedPrivateCIDRs) == 0 {
		if port := u.Port(); port != "" && port != "443" {
			return fmt.Errorf("media URL port %q is not permitted by strict public HTTPS policy", port)
		}
	}
	return nil
}

// ValidateAndSanitizeMediaURL validates a remote media URL against strict HTTPS,
// syntax, port, and outbound network SSRF policy rules (defaulting to
// DefaultPublicMediaPolicy when policy is nil) and returns a canonicalized HTTPS URL.
func ValidateAndSanitizeMediaURL(rawURL string, policy *network.Policy) (string, error) {
	if containsUnsafeURLChars(rawURL) {
		return "", fmt.Errorf("media URL must not contain control characters or backslashes")
	}
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || strings.ToLower(u.Scheme) != "https" || u.User != nil {
		return "", fmt.Errorf("media URL must be an absolute HTTPS URL without embedded credentials")
	}
	cleanHost, err := canonicalHostPort(u)
	if err != nil {
		return "", fmt.Errorf("media %w", err)
	}
	if containsUnsafeURLChars(u.Host) || containsUnsafeURLChars(u.Path) {
		return "", fmt.Errorf("media URL must not contain control characters or backslashes")
	}
	if policy == nil {
		policy = DefaultPublicMediaPolicy()
	}
	if err := policy.ValidateURL(u); err != nil {
		return "", fmt.Errorf("media URL rejected by security policy: %w", err)
	}
	if err := validateStrictMediaPort(policy, u); err != nil {
		return "", err
	}
	return (&url.URL{
		Scheme:   "https",
		Host:     cleanHost,
		Path:     u.Path,
		RawPath:  u.RawPath,
		RawQuery: u.RawQuery,
	}).String(), nil
}

// FetchRemoteDataURIWithPolicy fetches user-supplied HTTPS media validated against
// policy (defaulting to DefaultPublicMediaPolicy when nil) and returns a bounded
// base64 data URI. When client is nil, an SSRF-enforcing HTTP client is built from policy.
// When client is non-nil, a shallow clone is used with policy-enforcing transport and
// redirect validation.
func FetchRemoteDataURIWithPolicy(ctx context.Context, client *http.Client, policy *network.Policy, rawURL string, maxBytes int64, allowedTypes ...string) (string, error) {
	if maxBytes <= 0 {
		return "", fmt.Errorf("media fetch is not configured")
	}
	if policy == nil {
		policy = DefaultPublicMediaPolicy()
	}
	cleanURL, err := ValidateAndSanitizeMediaURL(rawURL, policy)
	if err != nil {
		return "", err
	}
	if client == nil {
		client = network.NewHTTPClient(policy)
	} else {
		cloned := *client
		cloned.Transport = network.WrapTransport(policy, cloned.Transport)
		baseCheck := cloned.CheckRedirect
		cloned.CheckRedirect = network.WrapCheckRedirect(policy, func(req *http.Request, via []*http.Request) error {
			if err := validateStrictMediaPort(policy, req.URL); err != nil {
				return err
			}
			if baseCheck != nil {
				return baseCheck(req, via)
			}
			return nil
		})
		client = &cloned
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, cleanURL, nil)
	if err != nil {
		return "", fmt.Errorf("create media request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch remote media: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return "", fmt.Errorf("remote media returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBytes+1))
	if err != nil {
		return "", fmt.Errorf("read remote media: %w", err)
	}
	if int64(len(body)) > maxBytes {
		return "", fmt.Errorf("remote media exceeds %d byte limit", maxBytes)
	}
	mediaType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if err != nil || mediaType == "" {
		mediaType = http.DetectContentType(body)
		mediaType, _, _ = mime.ParseMediaType(mediaType)
	}
	allowed := false
	for _, candidate := range allowedTypes {
		if strings.HasSuffix(candidate, "/") {
			allowed = allowed || strings.HasPrefix(mediaType, candidate)
		} else {
			allowed = allowed || strings.EqualFold(mediaType, candidate)
		}
	}
	if !allowed {
		return "", fmt.Errorf("remote media type %q is unsupported", mediaType)
	}
	return "data:" + mediaType + ";base64," + base64.StdEncoding.EncodeToString(body), nil
}
