package network

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"syscall"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/config"
)

// NewHTTPClient returns an *http.Client configured with strict outbound SSRF controls,
// disabled ambient proxying (Proxy: nil), DNS rebinding pinning, and redirect re-validation.
func NewHTTPClient(policy *Policy) *http.Client {
	if policy == nil {
		policy, _ = NewPolicy(config.OutboundSSRFConfig{})
	}

	resolver := NewSafeResolver(policy)

	dialer := &net.Dialer{
		Timeout:   policy.DialTimeout,
		KeepAlive: 30 * time.Second,
		Control: func(network, address string, c syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				host = address
			}
			if ip := net.ParseIP(host); ip != nil {
				return policy.ValidateIP(ip)
			}
			return nil
		},
	}

	var proxyFunc func(*http.Request) (*url.URL, error)
	if policy.EgressProxyURL != "" {
		if proxyURL, err := url.Parse(policy.EgressProxyURL); err == nil {
			proxyFunc = http.ProxyURL(proxyURL)
		}
	}

	transport := &http.Transport{
		// Ambient proxies (HTTP_PROXY, HTTPS_PROXY) are disabled to prevent proxy-based SSRF bypass;
		// explicit egress proxy can be configured via policy.EgressProxyURL
		Proxy: proxyFunc,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, fmt.Errorf("network: split addr %q: %w", addr, err)
			}

			validIPs, err := resolver.LookupAndValidate(ctx, host)
			if err != nil {
				return nil, err
			}

			// Connect to the first validated IP to prevent DNS rebinding races
			var lastErr error
			for _, ip := range validIPs {
				targetAddr := net.JoinHostPort(ip.String(), port)
				conn, err := dialer.DialContext(ctx, network, targetAddr)
				if err == nil {
					return conn, nil
				}
				lastErr = err
			}
			return nil, fmt.Errorf("network: dial failed: %w", lastErr)
		},
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= policy.MaxRedirects {
				return ErrTooManyRedirects
			}
			// Re-validate the target URL on every redirect
			if err := policy.ValidateURL(req.URL); err != nil {
				return fmt.Errorf("network: redirect target forbidden: %w", err)
			}
			return nil
		},
	}

	return client
}
