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
	} {
		if _, err := adapter.ValidateAndResolveBaseURL(bad, "https://api.openai.com/v1", pol); err == nil {
			t.Fatalf("expected ValidateAndResolveBaseURL to reject %q", bad)
		}
	}
}
