package vertex

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

func TestMaterializeClaudeMedia_FetchesRemoteImagesAndDocuments(t *testing.T) {
	media := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/document.pdf" {
			w.Header().Set("Content-Type", "application/pdf")
			_, _ = w.Write([]byte("%PDF-1.7 sample"))
			return
		}
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write([]byte("png-image-bytes"))
	}))
	defer media.Close()

	adp := NewAdapter(media.Client(), nil)
	prepared, err := adp.materializeClaudeMedia(context.Background(), &domain.CanonicalChatRequest{
		Messages: []domain.CanonicalMessage{{Role: "user", Parts: []domain.ContentPart{
			{Type: "image_url", ImageURL: &domain.ImageURL{URL: media.URL + "/image.png"}},
			{Type: "document", Document: &domain.DocumentPart{URL: media.URL + "/document.pdf"}},
		}}},
	})
	if err != nil {
		t.Fatalf("materializeClaudeMedia: %v", err)
	}
	imageURI := prepared.Messages[0].Parts[0].ImageURL.URL
	if mime, encoded, ok := parseDataURI(imageURI); !ok || mime != "image/png" || encoded == "" {
		t.Fatalf("image input was not materialized as PNG base64: %q", imageURI)
	}
	doc := prepared.Messages[0].Parts[1].Document
	if doc == nil || doc.URL != "" || doc.Data == "" || doc.MimeType != "application/pdf" {
		t.Fatalf("document input was not materialized as PDF base64: %#v", doc)
	}
}
