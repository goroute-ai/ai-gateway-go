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
)

// FetchRemoteDataURI fetches user-supplied HTTPS media through the adapter's
// configured HTTP client and returns a bounded base64 data URI. In the gateway,
// adapter clients use the outbound network policy, which validates DNS, IPs, and
// redirect targets before connecting.
func FetchRemoteDataURI(ctx context.Context, client *http.Client, rawURL string, maxBytes int64, allowedTypes ...string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return "", fmt.Errorf("media URL must be an absolute HTTPS URL")
	}
	if client == nil || maxBytes <= 0 {
		return "", fmt.Errorf("media fetch is not configured")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
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
