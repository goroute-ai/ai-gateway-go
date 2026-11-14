package ollama

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
)

func TestMaterializeImageURLs_FetchesRemoteImageBytes(t *testing.T) {
	media := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write([]byte("png-image-bytes"))
	}))
	defer media.Close()

	loopbackPol, err := network.NewPolicy(config.OutboundSSRFConfig{
		AllowedPrivateCIDRs: []string{"127.0.0.1/32", "::1/128"},
		AllowedSchemes:      []string{"https"},
	})
	if err != nil {
		t.Fatalf("NewPolicy: %v", err)
	}

	adp := NewAdapter(media.Client())
	adp.SetMediaFetcher(media.Client(), loopbackPol)
	prepared, err := adp.materializeImageURLs(context.Background(), &domain.CanonicalChatRequest{
		Messages: []domain.CanonicalMessage{{Role: "user", Parts: []domain.ContentPart{{
			Type: "image_url", ImageURL: &domain.ImageURL{URL: media.URL},
		}}}},
	})
	if err != nil {
		t.Fatalf("materializeImageURLs: %v", err)
	}
	url := prepared.Messages[0].Parts[0].ImageURL.URL
	if !strings.HasPrefix(url, "data:image/png;base64,") {
		t.Fatalf("materialized image URL = %q, want PNG data URI", url)
	}
	encoded, ok := parseDataURI(url)
	if !ok || encoded == "" {
		t.Fatalf("materialized image is not a valid base64 data URI: %q", url)
	}
}

func TestMaterializeImageURLs_DefaultPolicyBlocksPrivateLoopbackEvenWithPermissiveClient(t *testing.T) {
	media := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write([]byte("png-image-bytes"))
	}))
	defer media.Close()

	// Permissive provider client simulating allow_private_networks=true for local Ollama
	adp := NewAdapter(media.Client())
	for _, target := range []string{
		media.URL + "/img.png",
		"https://169.254.169.254/latest/meta-data",
		"http://example.com/img.png",
		"https://user:pass@example.com/img.png",
	} {
		_, err := adp.materializeImageURLs(context.Background(), &domain.CanonicalChatRequest{
			Messages: []domain.CanonicalMessage{{Role: "user", Parts: []domain.ContentPart{{
				Type: "image_url", ImageURL: &domain.ImageURL{URL: target},
			}}}},
		})
		if err == nil {
			t.Fatalf("expected error blocking untrusted media URL %q", target)
		}
	}
}
