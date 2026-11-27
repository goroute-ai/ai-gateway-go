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

func TestRoundTrip_ValidatesURLWithEgressProxy(t *testing.T) {
	proxySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("proxy should not be contacted when target URL violates policy")
	}))
	defer proxySrv.Close()

	pol, err := network.NewPolicy(config.OutboundSSRFConfig{
		AllowPrivateNetworks: false,
		AllowInsecureHTTP:    false,
		EgressProxyURL:       proxySrv.URL,
	})
	if err != nil {
		t.Fatalf("new policy: %v", err)
	}
	client := network.NewHTTPClient(pol)

	if _, err := client.Get("http://example.com/v1/test"); err == nil {
		t.Fatal("expected http:// to be rejected at RoundTrip even with EgressProxyURL set")
	}
	if _, err := client.Get("https://169.254.169.254/latest/meta-data"); err == nil {
		t.Fatal("expected metadata IP to be rejected at RoundTrip even with EgressProxyURL set")
	}
	if _, err := client.Get("https://metadata.google.internal./computeMetadata/v1/"); err == nil {
		t.Fatal("expected trailing-dot metadata hostname to be rejected")
	}
}

func TestCheckRedirect_StripsAPIKeyHeadersCrossOrigin(t *testing.T) {
	var seenXAPIKey, seenAPIKey, seenXGoogAPIKey, seenProxyAuth string
	targetSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenXAPIKey = r.Header.Get("X-Api-Key")
		seenAPIKey = r.Header.Get("Api-Key")
		seenXGoogAPIKey = r.Header.Get("X-Goog-Api-Key")
		seenProxyAuth = r.Header.Get("Proxy-Authorization")
		w.WriteHeader(http.StatusOK)
	}))
	defer targetSrv.Close()

	originSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, targetSrv.URL+"/dest", http.StatusFound)
	}))
	defer originSrv.Close()

	pol, err := network.NewPolicy(config.OutboundSSRFConfig{
		AllowPrivateNetworks: true,
		AllowInsecureHTTP:    true,
		MaxRedirects:         3,
	})
	if err != nil {
		t.Fatalf("new policy: %v", err)
	}
	client := network.NewHTTPClient(pol)

	req, err := http.NewRequest(http.MethodGet, originSrv.URL+"/start", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("X-Api-Key", "secret-1")
	req.Header.Set("Api-Key", "secret-2")
	req.Header.Set("X-Goog-Api-Key", "secret-3")
	req.Header.Set("Proxy-Authorization", "Basic secret-4")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("client.Do: %v", err)
	}
	resp.Body.Close()

	if seenXAPIKey != "" || seenAPIKey != "" || seenXGoogAPIKey != "" || seenProxyAuth != "" {
		t.Fatalf("expected credential headers to be stripped on cross-origin redirect, got X-Api-Key=%q Api-Key=%q X-Goog-Api-Key=%q Proxy-Authorization=%q",
			seenXAPIKey, seenAPIKey, seenXGoogAPIKey, seenProxyAuth)
	}
}

func TestPolicyValidateURL_IPv6UnspecifiedNAT64AndTrailingDot(t *testing.T) {
	p, err := network.NewPolicy(config.OutboundSSRFConfig{})
	if err != nil {
		t.Fatalf("new policy: %v", err)
	}
	cases := []string{
		"https://[::]/",
		"https://[64:ff9b::127.0.0.1]/",
		"https://metadata.google.internal./",
		"https://metadata./",
	}
	for _, raw := range cases {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("parse %q: %v", raw, err)
		}
		if err := p.ValidateURL(u); err == nil {
			t.Fatalf("expected ValidateURL to block %q", raw)
		}
	}
}

func TestPolicyValidateURL_LocalhostAndAzureMetadata(t *testing.T) {
	strictPol, err := network.NewPolicy(config.OutboundSSRFConfig{})
	if err != nil {
		t.Fatalf("new strict policy: %v", err)
	}
	for _, raw := range []string{
		"https://localhost/v1",
		"https://sub.localhost/v1",
		"https://internal.local/v1",
		"https://metadata.azure.internal/metadata/instance",
	} {
		u, err := url.Parse(raw)
		if err != nil {
			t.Fatalf("parse %q: %v", raw, err)
		}
		if err := strictPol.ValidateURL(u); err == nil {
			t.Fatalf("expected strict ValidateURL to block %q", raw)
		}
	}

	privatePol, err := network.NewPolicy(config.OutboundSSRFConfig{
		AllowPrivateNetworks: true,
		AllowInsecureHTTP:    true,
	})
	if err != nil {
		t.Fatalf("new private policy: %v", err)
	}
	azureMeta, _ := url.Parse("https://metadata.azure.internal/metadata/instance")
	if err := privatePol.ValidateURL(azureMeta); err == nil {
		t.Fatal("expected metadata.azure.internal to remain blocked even when AllowPrivateNetworks is true")
	}
}

func TestPolicyValidateIP_MulticastUnspecifiedAndNonGlobalUnicast(t *testing.T) {
	strictPol, err := network.NewPolicy(config.OutboundSSRFConfig{})
	if err != nil {
		t.Fatalf("new strict policy: %v", err)
	}
	for _, rawIP := range []string{"224.0.0.1", "ff02::1", "0.0.0.0", "::", "255.255.255.255"} {
		ip := net.ParseIP(rawIP)
		if ip == nil {
			t.Fatalf("ParseIP(%q) failed", rawIP)
		}
		if err := strictPol.ValidateIP(ip); err == nil {
			t.Fatalf("expected strict ValidateIP to reject %s", rawIP)
		}
	}

	privatePol, err := network.NewPolicy(config.OutboundSSRFConfig{AllowPrivateNetworks: true})
	if err != nil {
		t.Fatalf("new private policy: %v", err)
	}
	for _, rawIP := range []string{"224.0.0.1", "ff02::1", "0.0.0.0", "::"} {
		if err := privatePol.ValidateIP(net.ParseIP(rawIP)); err == nil {
			t.Fatalf("expected ValidateIP with AllowPrivateNetworks=true to still reject %s", rawIP)
		}
	}
}

func TestWrapTransport_NilBaseAndCustomTransportPolicyEnforcement(t *testing.T) {
	strictPol, err := network.NewPolicy(config.OutboundSSRFConfig{
		AllowPrivateNetworks: false,
		AllowInsecureHTTP:    false,
	})
	if err != nil {
		t.Fatalf("new strict policy: %v", err)
	}

	nilWrapped := &http.Client{Transport: network.WrapTransport(strictPol, nil)}
	if _, err := nilWrapped.Get("http://127.0.0.1:1/blocked"); err == nil {
		t.Fatal("expected WrapTransport(strictPol, nil) to reject loopback HTTP target")
	}

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("custom transport should not dial when RoundTrip URL violates policy")
	}))
	defer srv.Close()

	customClient := srv.Client()
	customClient.Transport = network.WrapTransport(strictPol, customClient.Transport)
	if _, err := customClient.Get(srv.URL + "/blocked"); err == nil {
		t.Fatal("expected WrapTransport(strictPol, customTransport) to reject loopback URL before dialing")
	}
}
