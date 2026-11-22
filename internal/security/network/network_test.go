package network_test

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
)

func TestPolicyValidateURL(t *testing.T) {
	t.Run("Scheme enforcement", func(t *testing.T) {
		p, err := network.NewPolicy(config.OutboundSSRFConfig{
			AllowInsecureHTTP: false,
		})
		if err != nil {
			t.Fatalf("NewPolicy failed: %v", err)
		}

		u, _ := url.Parse("ftp://example.com/file")
		if err := p.ValidateURL(u); err == nil {
			t.Fatalf("expected error for ftp scheme, got nil")
		}

		uHTTP, _ := url.Parse("http://example.com/api")
		if err := p.ValidateURL(uHTTP); err == nil {
			t.Fatalf("expected error for http when AllowInsecureHTTP is false, got nil")
		}

		uHTTPS, _ := url.Parse("https://example.com/api")
		if err := p.ValidateURL(uHTTPS); err != nil {
			t.Fatalf("expected https to be valid, got: %v", err)
		}
	})

	t.Run("Cloud metadata hostnames strictly blocked", func(t *testing.T) {
		p, _ := network.NewPolicy(config.OutboundSSRFConfig{
			AllowInsecureHTTP:    true,
			AllowPrivateNetworks: true, // Even if private networks allowed, cloud metadata must be blocked
		})

		for _, badHost := range []string{
			"http://metadata.google.internal/computeMetadata/v1",
			"http://metadata/v1",
			"http://instance-data/latest/meta-data",
			"http://169.254.169.254/latest/meta-data",
		} {
			u, _ := url.Parse(badHost)
			if err := p.ValidateURL(u); err == nil {
				t.Fatalf("expected metadata URL %s to be blocked, got nil error", badHost)
			}
		}
	})
}

func TestPolicyValidateIP(t *testing.T) {
	t.Run("Private networks blocked by default", func(t *testing.T) {
		p, _ := network.NewPolicy(config.OutboundSSRFConfig{
			AllowPrivateNetworks: false,
		})

		testIPs := []string{
			"127.0.0.1",
			"10.0.0.1",
			"172.16.10.20",
			"192.168.1.1",
			"::1",
			"fc00::1",
			"::ffff:127.0.0.1", // IPv4-mapped IPv6
		}

		for _, ipStr := range testIPs {
			ip := net.ParseIP(ipStr)
			if err := p.ValidateIP(ip); err == nil {
				t.Fatalf("expected private IP %s to be blocked, got nil error", ipStr)
			}
		}

		// Public IP allowed
		pubIP := net.ParseIP("8.8.8.8")
		if err := p.ValidateIP(pubIP); err != nil {
			t.Fatalf("expected public IP 8.8.8.8 to be allowed, got: %v", err)
		}
	})

	t.Run("Explicit allowed private CIDR overrides general block", func(t *testing.T) {
		p, _ := network.NewPolicy(config.OutboundSSRFConfig{
			AllowPrivateNetworks: false,
			AllowedPrivateCIDRs:  []string{"10.0.0.0/8"},
		})

		allowedIP := net.ParseIP("10.5.2.1")
		if err := p.ValidateIP(allowedIP); err != nil {
			t.Fatalf("expected 10.5.2.1 to be allowed via AllowedPrivateCIDRs, got: %v", err)
		}

		deniedIP := net.ParseIP("192.168.1.50")
		if err := p.ValidateIP(deniedIP); err == nil {
			t.Fatalf("expected 192.168.1.50 to remain blocked, got nil error")
		}
	})

	t.Run("Blocked IPs list strictly honored", func(t *testing.T) {
		p, _ := network.NewPolicy(config.OutboundSSRFConfig{
			BlockedIPs: []string{"8.8.8.8"},
		})

		if err := p.ValidateIP(net.ParseIP("8.8.8.8")); err == nil {
			t.Fatalf("expected explicitly blocked IP 8.8.8.8 to be blocked, got nil error")
		}
	})
}

func TestHTTPClientRedirectSecurity(t *testing.T) {
	// Setup test server that redirects to a forbidden IP / URL
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect-to-metadata" {
			http.Redirect(w, r, "http://169.254.169.254/secret", http.StatusFound)
			return
		}
		if r.URL.Path == "/redirect-loop" {
			http.Redirect(w, r, "/redirect-loop", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}))
	defer ts.Close()

	p, _ := network.NewPolicy(config.OutboundSSRFConfig{
		AllowInsecureHTTP:    true,
		AllowPrivateNetworks: true, // Allow local test server IP
		MaxRedirects:         2,
	})

	client := network.NewHTTPClient(p)

	t.Run("Redirect to cloud metadata is intercepted and blocked", func(t *testing.T) {
		_, err := client.Get(ts.URL + "/redirect-to-metadata")
		if err == nil {
			t.Fatalf("expected redirect to metadata to fail, got nil error")
		}
	})

	t.Run("Redirect loop exceeds MaxRedirects", func(t *testing.T) {
		_, err := client.Get(ts.URL + "/redirect-loop")
		if err == nil {
			t.Fatalf("expected redirect loop to fail, got nil error")
		}
	})
}

func TestPolicyAllowLoopbackHTTP(t *testing.T) {
	p, err := network.NewPolicy(config.OutboundSSRFConfig{
		AllowPrivateNetworks: false,
		AllowInsecureHTTP:    false,
		AllowLoopbackHTTP:    true,
		AllowedPrivateCIDRs:  []string{"127.0.0.1/32", "::1/128"},
	})
	if err != nil {
		t.Fatalf("NewPolicy: %v", err)
	}

	allowedURLs := []string{
		"http://127.0.0.1:8080/v1/chat/completions",
		"http://localhost:11434/v1/chat/completions",
		"http://[::1]:8080/v1/chat/completions",
		"https://api.openai.com/v1/chat/completions",
	}
	for _, raw := range allowedURLs {
		u, _ := url.Parse(raw)
		if err := p.ValidateURL(u); err != nil {
			t.Fatalf("expected %s to be permitted under loopback-only HTTP, got %v", raw, err)
		}
	}

	blockedURLs := []string{
		"http://api.openai.com/v1/chat/completions",
		"http://localhost.evil.com/v1/chat/completions",
		"http://10.0.0.1:8080/secret",
		"https://10.0.0.1:8080/secret",
		"http://169.254.169.254/latest/meta-data",
	}
	for _, raw := range blockedURLs {
		u, _ := url.Parse(raw)
		if err := p.ValidateURL(u); err == nil {
			t.Fatalf("expected %s to remain blocked under loopback-only HTTP, got nil", raw)
		}
	}

	// Non-loopback private CIDR must not implicitly unblock localhost URL validation.
	rfc1918Only, err := network.NewPolicy(config.OutboundSSRFConfig{
		AllowPrivateNetworks: false,
		AllowInsecureHTTP:    true,
		AllowedPrivateCIDRs:  []string{"10.0.0.0/8"},
	})
	if err != nil {
		t.Fatalf("NewPolicy rfc1918: %v", err)
	}
	uLocal, _ := url.Parse("http://localhost:8080/admin")
	if err := rfc1918Only.ValidateURL(uLocal); err == nil {
		t.Fatalf("expected localhost to stay blocked when only 10.0.0.0/8 is allowlisted")
	}
}

func TestPolicyLoopbackDNSRebindingAndSchemeHarmonization(t *testing.T) {
	mixedPolicy, err := network.NewPolicy(config.OutboundSSRFConfig{
		AllowPrivateNetworks: false,
		AllowInsecureHTTP:    false,
		AllowLoopbackHTTP:    true,
		AllowedPrivateCIDRs:  []string{"127.0.0.1/32", "::1/128", "10.0.0.0/8"},
	})
	if err != nil {
		t.Fatalf("NewPolicy mixed: %v", err)
	}

	uHTTP, _ := url.Parse("http://rebind.localhost:8080/mcp")
	if !mixedPolicy.RequiresLoopbackIPForURL(uHTTP) {
		t.Fatalf("expected RequiresLoopbackIPForURL=true for plain http when AllowLoopbackHTTP=true and AllowInsecureHTTP=false")
	}
	uHTTPS, _ := url.Parse("https://api.openai.com/v1/models")
	if mixedPolicy.RequiresLoopbackIPForURL(uHTTPS) {
		t.Fatalf("expected RequiresLoopbackIPForURL=false for https URL")
	}

	ipCases := []struct {
		name    string
		ip      net.IP
		wantErr bool
	}{
		{name: "IPv4 loopback permitted", ip: net.ParseIP("127.0.0.1"), wantErr: false},
		{name: "IPv6 loopback permitted", ip: net.ParseIP("::1"), wantErr: false},
		{name: "IPv4-mapped IPv6 loopback permitted", ip: net.ParseIP("::ffff:127.0.0.1"), wantErr: false},
		{name: "allowlisted RFC1918 rejected for loopback-only HTTP", ip: net.ParseIP("10.0.0.5"), wantErr: true},
		{name: "IPv4-mapped IPv6 RFC1918 rejected", ip: net.ParseIP("::ffff:10.0.0.5"), wantErr: true},
		{name: "public IP rejected for loopback-only HTTP", ip: net.ParseIP("8.8.8.8"), wantErr: true},
		{name: "nil IP rejected", ip: nil, wantErr: true},
	}
	for _, tc := range ipCases {
		t.Run(tc.name, func(t *testing.T) {
			err := mixedPolicy.ValidateLoopbackIP(tc.ip)
			if tc.wantErr && err == nil {
				t.Fatalf("expected error for IP %v, got nil", tc.ip)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected error for IP %v: %v", tc.ip, err)
			}
		})
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("loopback ok"))
	}))
	defer ts.Close()

	client := network.NewHTTPClient(mixedPolicy)
	resp, err := client.Get(ts.URL)
	if err != nil {
		t.Fatalf("expected loopback httptest server GET %s to succeed, got %v", ts.URL, err)
	}
	_ = resp.Body.Close()

	// Even though 10.0.0.0/8 is in AllowedPrivateCIDRs, plain HTTP to 10.0.0.5 is blocked.
	blockedResp, blockedErr := client.Get("http://10.0.0.5:8080/internal")
	if blockedResp != nil && blockedResp.Body != nil {
		_ = blockedResp.Body.Close()
	}
	if !errors.Is(blockedErr, network.ErrInsecureHTTPBlocked) {
		t.Fatalf("expected ErrInsecureHTTPBlocked for http://10.0.0.5, got %v", blockedErr)
	}
}

func TestPolicyLoopbackSchemeHarmonization(t *testing.T) {
	// When allowed_schemes is restricted to ["https"] (config.example.yaml default),
	// enabling AllowLoopbackHTTP must still permit loopback HTTP without permitting external HTTP or ftp.
	httpsTemplatePolicy, err := network.NewPolicy(config.OutboundSSRFConfig{
		AllowPrivateNetworks: false,
		AllowInsecureHTTP:    false,
		AllowLoopbackHTTP:    true,
		AllowedSchemes:       []string{"https"},
		AllowedPrivateCIDRs:  []string{"127.0.0.1/32", "::1/128"},
	})
	if err != nil {
		t.Fatalf("NewPolicy httpsTemplatePolicy: %v", err)
	}
	for _, tc := range []struct {
		raw     string
		wantErr error
	}{
		{raw: "http://127.0.0.1:8080/mcp", wantErr: nil},
		{raw: "http://localhost:11434/v1/models", wantErr: nil},
		{raw: "https://api.openai.com/v1/models", wantErr: nil},
		{raw: "http://example.com/mcp", wantErr: network.ErrInsecureHTTPBlocked},
		{raw: "http://10.0.0.5:8080/mcp", wantErr: network.ErrInsecureHTTPBlocked},
		{raw: "ftp://127.0.0.1/file", wantErr: network.ErrBlockedScheme},
	} {
		u, _ := url.Parse(tc.raw)
		got := httpsTemplatePolicy.ValidateURL(u)
		if tc.wantErr == nil && got != nil {
			t.Fatalf("expected %s to be allowed, got %v", tc.raw, got)
		}
		if tc.wantErr != nil && !errors.Is(got, tc.wantErr) {
			t.Fatalf("expected %s error %v, got %v", tc.raw, tc.wantErr, got)
		}
	}
}
