package network_test

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
)

func TestAmbientIAMPolicy_DefaultBlocked(t *testing.T) {
	basePol, err := network.NewPolicy(config.OutboundSSRFConfig{
		AllowPrivateNetworks: true,
		AllowInsecureHTTP:    true,
	})
	if err != nil {
		t.Fatalf("new base policy: %v", err)
	}

	// Default policy must continue blocking metadata endpoints even when AllowPrivateNetworks is true.
	for _, raw := range []string{
		"http://169.254.169.254/latest/meta-data/",
		"http://[fd00:ec2::254]/latest/meta-data/",
		"http://metadata.google.internal/computeMetadata/v1/",
		"http://metadata.azure.internal/metadata/identity/oauth2/token",
	} {
		u, _ := url.Parse(raw)
		if err := basePol.ValidateURL(u); !errors.Is(err, network.ErrCloudMetadataBlocked) {
			t.Fatalf("expected ErrCloudMetadataBlocked for %s on default policy, got %v", raw, err)
		}
	}

	// Opt-in constructor with false must refuse.
	if _, err := network.NewAmbientIAMPolicy(basePol, false); !errors.Is(err, network.ErrCloudMetadataBlocked) {
		t.Fatalf("expected ErrCloudMetadataBlocked when allowAmbientCloudIAM=false, got %v", err)
	}
	if _, err := network.NewAmbientIAMHTTPClient(basePol, false); !errors.Is(err, network.ErrCloudMetadataBlocked) {
		t.Fatalf("expected ErrCloudMetadataBlocked from NewAmbientIAMHTTPClient when false, got %v", err)
	}
}

func TestAmbientIAMPolicy_OptInAllowsMetadataAndBlocksArbitraryPrivateAndRedirects(t *testing.T) {
	strictBase, err := network.NewPolicy(config.OutboundSSRFConfig{})
	if err != nil {
		t.Fatalf("new strict base policy: %v", err)
	}

	metaPol, err := network.NewAmbientIAMPolicy(strictBase, true)
	if err != nil {
		t.Fatalf("NewAmbientIAMPolicy(true) failed: %v", err)
	}

	for _, allowed := range []string{
		"http://169.254.169.254/latest/api/token",
		"http://[fd00:ec2::254]/latest/api/token",
		"http://169.254.170.2/v2/credentials/abc",
		"http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
		"http://metadata.azure.internal/metadata/identity/oauth2/token",
		"http://127.0.0.1:8081/MSI/token",
		"https://sts.us-east-1.amazonaws.com/",
	} {
		u, _ := url.Parse(allowed)
		if err := metaPol.ValidateURL(u); err != nil {
			t.Fatalf("expected %s to be allowed by ambient IAM policy, got %v", allowed, err)
		}
	}

	// Arbitrary RFC1918 must still be blocked when strictBase disallows private networks.
	rfc1918, _ := url.Parse("http://10.20.30.40/secret")
	if err := metaPol.ValidateURL(rfc1918); !errors.Is(err, network.ErrPrivateNetworkBlocked) {
		t.Fatalf("expected ErrPrivateNetworkBlocked for RFC1918 IP, got %v", err)
	}

	// Redirects from metadata client must be rejected (MaxRedirects == 0).
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer target.Close()

	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusFound)
	}))
	defer redirector.Close()

	client, err := network.NewAmbientIAMHTTPClient(strictBase, true)
	if err != nil {
		t.Fatalf("NewAmbientIAMHTTPClient(true) failed: %v", err)
	}
	if _, err := client.Get(redirector.URL); err == nil {
		t.Fatal("expected metadata HTTP client to reject redirects")
	}
}
