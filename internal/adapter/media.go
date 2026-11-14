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

// FetchRemoteDataURIWithPolicy fetches user-supplied HTTPS media validated against
// policy (defaulting to DefaultPublicMediaPolicy when nil) and returns a bounded
// base64 data URI. When client is nil, an SSRF-enforcing HTTP client is built from policy.
// Callers supplying a non-nil client MUST ensure its Transport/CheckRedirect enforces
// the same policy (e.g., via network.NewHTTPClient(policy)).
func FetchRemoteDataURIWithPolicy(ctx context.Context, client *http.Client, policy *network.Policy, rawURL string, maxBytes int64, allowedTypes ...string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || strings.ToLower(u.Scheme) != "https" || u.Hostname() == "" || u.User != nil {
		return "", fmt.Errorf("media URL must be an absolute HTTPS URL without embedded credentials")
	}
	if maxBytes <= 0 {
		return "", fmt.Errorf("media fetch is not configured")
	}
	if policy == nil {
		policy = DefaultPublicMediaPolicy()
	}
	if err := policy.ValidateURL(u); err != nil {
		return "", fmt.Errorf("media URL rejected by security policy: %w", err)
	}
	if client == nil {
		client = network.NewHTTPClient(policy)
	}
	cleanURL := (&url.URL{
		Scheme:   "https",
		Host:     u.Host,
		Path:     u.Path,
		RawPath:  u.RawPath,
		RawQuery: u.RawQuery,
	}).String()
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
