package ollama

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

func TestMaterializeImageURLs_FetchesRemoteImageBytes(t *testing.T) {
	media := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write([]byte("png-image-bytes"))
	}))
	defer media.Close()

	adp := NewAdapter(media.Client())
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
