package network_test

import (
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
		AllowedSchemes:       []string{"https"},
	})
	if err != nil {
		t.Fatalf("NewPolicy failed: %v", err)
	}

	allowed := []string{
		"http://127.0.0.1:18081/realms/goroute/.well-known/openid-configuration",
		"http://localhost:18081/realms/goroute",
		"http://[::1]:18081/realms/goroute",
		"https://idp.example.com/.well-known/openid-configuration",
	}
	for _, raw := range allowed {
		u, _ := url.Parse(raw)
		if err := p.ValidateURL(u); err != nil {
			t.Fatalf("expected URL %s to be allowed when AllowLoopbackHTTP=true, got: %v", raw, err)
		}
	}

	blocked := []string{
		"http://example.com/.well-known/openid-configuration",
		"http://10.0.0.5:8080/token",
		"http://192.168.1.10:8080/token",
		"http://169.254.169.254/latest/meta-data",
		"http://metadata.google.internal/computeMetadata/v1",
		"https://10.0.0.5/token",
	}
	for _, raw := range blocked {
		u, _ := url.Parse(raw)
		if err := p.ValidateURL(u); err == nil {
			t.Fatalf("expected non-loopback/private/IMDS URL %s to remain blocked, got nil error", raw)
		}
	}

	// RequiresLoopbackDial must be true for http://*.localhost when AllowInsecureHTTP=false
	uLoop, _ := url.Parse("http://evil.localhost:8080/token")
	if !p.RequiresLoopbackDial(uLoop) {
		t.Fatal("expected RequiresLoopbackDial=true for http://evil.localhost when AllowInsecureHTTP=false and AllowLoopbackHTTP=true")
	}
	uHTTPS, _ := url.Parse("https://idp.example.com/token")
	if p.RequiresLoopbackDial(uHTTPS) {
		t.Fatal("expected RequiresLoopbackDial=false for https:// URL")
	}

	// SEC-04: Cloud metadata IPs (AWS IMDS, IPv6 IMDS, ECS task metadata, Alibaba IMDS)
	// remain unconditionally blocked even if broad link-local / CGNAT CIDRs are passed to AllowedPrivateCIDRs.
	pWithCIDRs, err := network.NewPolicy(config.OutboundSSRFConfig{
		AllowPrivateNetworks: false,
		AllowedPrivateCIDRs:  []string{"169.254.0.0/16", "100.64.0.0/10", "fd00::/8"},
	})
	if err != nil {
		t.Fatalf("NewPolicy with CIDRs failed: %v", err)
	}
	for _, metaIP := range []string{
		"169.254.169.254",
		"169.254.170.2",
		"169.254.170.23",
		"100.100.100.200",
		"fd00:ec2::254",
	} {
		if err := pWithCIDRs.ValidateIP(net.ParseIP(metaIP)); err == nil {
			t.Fatalf("expected cloud metadata IP %s to remain blocked even when covered by AllowedPrivateCIDRs", metaIP)
		}
	}
}
