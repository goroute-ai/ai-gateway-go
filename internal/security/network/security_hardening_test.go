package network_test

import (
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
	var seenXAPIKey, seenAPIKey string
	targetSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenXAPIKey = r.Header.Get("X-Api-Key")
		seenAPIKey = r.Header.Get("Api-Key")
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

	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("client.Do: %v", err)
	}
	resp.Body.Close()

	if seenXAPIKey != "" || seenAPIKey != "" {
		t.Fatalf("expected X-Api-Key and Api-Key to be stripped on cross-origin redirect, got %q / %q", seenXAPIKey, seenAPIKey)
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
