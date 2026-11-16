package adapter_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/adapter"
	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
)

func TestFetchRemoteDataURI_SecurityControls(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "https://127.0.0.1/secret.png", http.StatusFound)
			return
		}
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write([]byte("ok-bytes"))
	}))
	defer srv.Close()

	ctx := context.Background()
	for _, blockedURL := range []string{
		"http://example.com/image.png",
		"https://127.0.0.1/image.png",
		"https://10.0.0.1/image.png",
		"https://169.254.169.254/latest/meta-data",
		"https://user:pass@example.com/image.png",
		srv.URL + "/img.png",
	} {
		if _, err := adapter.FetchRemoteDataURI(ctx, nil, blockedURL, 1024, "image/"); err == nil {
			t.Fatalf("expected FetchRemoteDataURI to reject %q", blockedURL)
		}
	}

	// Default media policy blocks redirects to private IPs at dial/redirect time when using a policy-backed client.
	strictClient := network.NewHTTPClient(adapter.DefaultPublicMediaPolicy())
	if _, err := adapter.FetchRemoteDataURIWithPolicy(ctx, strictClient, nil, srv.URL+"/redirect", 1024, "image/"); err == nil {
		t.Fatal("expected strict policy/client to block private redirect target")
	}
}

func TestValidateAndResolveBaseURL(t *testing.T) {
	pol, err := network.NewPolicy(config.OutboundSSRFConfig{
		AllowPrivateNetworks: false,
		AllowInsecureHTTP:    false,
	})
	if err != nil {
		t.Fatalf("NewPolicy: %v", err)
	}

	resolved, err := adapter.ValidateAndResolveBaseURL("", "https://api.openai.com/v1/", pol)
	if err != nil || resolved != "https://api.openai.com/v1" {
		t.Fatalf("default resolve failed: resolved=%q err=%v", resolved, err)
	}

	resolved, err = adapter.ValidateAndResolveBaseURL("https://api.openai.com/v1/", "https://api.openai.com/v1", pol)
	if err != nil || resolved != "https://api.openai.com/v1" {
		t.Fatalf("override resolve failed: resolved=%q err=%v", resolved, err)
	}

	for _, bad := range []string{
		"ftp://example.com/v1",
		"https://user:pass@api.openai.com/v1",
		"https://api.openai.com/v1?foo=bar",
		"https://api.openai.com/v1#frag",
		"http://api.openai.com/v1",
		"https://169.254.169.254/v1",
		"https://127.0.0.1/v1",
		"https://metadata.google.internal/v1",
		"https://metadata.azure.internal/v1",
		"https://localhost/v1",
		"https://localhost./v1",
		"https://api.openai.com./v1",
		"https://api.openai.com\\evil.com/v1",
		"https://api.openai.com/v1/../admin",
		"https://api.openai.com/v1/%2e%2e/admin",
		"https://api.openai.com/v1\r\n",
	} {
		if _, err := adapter.ValidateAndResolveBaseURL(bad, "https://api.openai.com/v1", pol); err == nil {
			t.Fatalf("expected ValidateAndResolveBaseURL to reject %q", bad)
		}
		// Nil policy must also enforce strict defaults rather than bypassing ValidateURL.
		if _, err := adapter.ValidateAndResolveBaseURL(bad, "https://api.openai.com/v1", nil); err == nil {
			t.Fatalf("expected ValidateAndResolveBaseURL(nil policy) to reject %q", bad)
		}
	}
}

func TestFetchRemoteDataURIWithPolicy_Non443PortAndNonNilClientRedirect(t *testing.T) {
	targetSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write([]byte("ok-bytes"))
	}))
	defer targetSrv.Close()

	redirectSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://127.0.0.1/secret.png", http.StatusFound)
	}))
	defer redirectSrv.Close()

	ctx := context.Background()
	// Strict public policy rejects non-443 port before dialing.
	if _, err := adapter.FetchRemoteDataURI(ctx, nil, "https://example.com:8443/image.png", 1024, "image/"); err == nil {
		t.Fatal("expected strict media policy to reject non-443 port")
	}

	// Caller-supplied http.Client (without CheckRedirect) must still be hardened without mutating caller client.
	loopbackAllowPublicRedirectPol, err := network.NewPolicy(config.OutboundSSRFConfig{
		AllowedSchemes: []string{"https"},
		AllowedPrivateCIDRs: []string{
			"10.0.0.0/8", // allow non-loopback CIDR so redirectSrv itself requires loopbackPol -> test port & redirect block cleanly
		},
	})
	if err != nil {
		t.Fatalf("NewPolicy: %v", err)
	}
	_ = loopbackAllowPublicRedirectPol

	customClient := redirectSrv.Client()
	customClient.CheckRedirect = nil
	if _, err := adapter.FetchRemoteDataURIWithPolicy(ctx, customClient, nil, redirectSrv.URL+"/redir", 1024, "image/"); err == nil {
		t.Fatal("expected non-nil client to reject loopback media target")
	}
	if customClient.CheckRedirect != nil {
		t.Fatal("FetchRemoteDataURIWithPolicy must not mutate caller-supplied http.Client")
	}

	// Test redirect enforcement on a caller-supplied client whose initial policy permits custom CIDRs, redirecting to 169.254.169.254.
	metaRedirectSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://169.254.169.254/latest/meta-data", http.StatusFound)
	}))
	defer metaRedirectSrv.Close()

	loopbackPol, err := network.NewPolicy(config.OutboundSSRFConfig{
		AllowedPrivateCIDRs: []string{"127.0.0.1/32", "::1/128"},
		AllowedSchemes:      []string{"https"},
	})
	if err != nil {
		t.Fatalf("NewPolicy loopbackPol: %v", err)
	}
	nonNilClient := metaRedirectSrv.Client()
	nonNilClient.CheckRedirect = nil
	if _, err := adapter.FetchRemoteDataURIWithPolicy(ctx, nonNilClient, loopbackPol, metaRedirectSrv.URL+"/start", 1024, "image/"); err == nil {
		t.Fatal("expected cloned non-nil client CheckRedirect to block redirect to 169.254.169.254")
	}
	if nonNilClient.CheckRedirect != nil {
		t.Fatal("expected caller CheckRedirect to remain unmodified")
	}

	// Non-nil client with Transport == nil must still wrap Transport safely without mutating caller client.
	bareClient := &http.Client{}
	if _, err := adapter.FetchRemoteDataURIWithPolicy(ctx, bareClient, nil, redirectSrv.URL+"/img.png", 1024, "image/"); err == nil {
		t.Fatal("expected bare non-nil client to reject loopback media target")
	}
	if bareClient.Transport != nil || bareClient.CheckRedirect != nil {
		t.Fatal("FetchRemoteDataURIWithPolicy must not mutate caller-supplied bare http.Client")
	}
}

func TestValidateAndSanitizeMediaURL(t *testing.T) {
	clean, err := adapter.ValidateAndSanitizeMediaURL("https://CDN.Example.COM/assets/img.png?size=large#frag", nil)
	if err != nil {
		t.Fatalf("expected valid public HTTPS media URL, got err=%v", err)
	}
	if clean != "https://cdn.example.com/assets/img.png?size=large" {
		t.Fatalf("unexpected sanitized media URL: %q", clean)
	}

	for _, bad := range []string{
		"http://cdn.example.com/img.png",
		"https://cdn.example.com./img.png",
		"https://cdn.example.com\\evil.com/img.png",
		"https://user:pass@cdn.example.com/img.png",
		"https://cdn.example.com:8443/img.png",
		"https://169.254.169.254./latest/meta-data",
		"https://metadata.google.internal./computeMetadata/v1/",
	} {
		if _, err := adapter.ValidateAndSanitizeMediaURL(bad, nil); err == nil {
			t.Fatalf("expected ValidateAndSanitizeMediaURL to reject %q", bad)
		}
	}
}
