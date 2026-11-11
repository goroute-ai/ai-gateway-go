package ui_test

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/goroute-ai/ai-gateway-go/internal/ui"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUI_RouteDeliveryAndSPAFallback(t *testing.T) {
	r := chi.NewRouter()
	ui.RegisterRoutes(r)

	// 1. Test GET /ui redirects to /ui/
	req := httptest.NewRequest(http.MethodGet, "/ui", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusMovedPermanently, rec.Code)
	assert.Equal(t, "/ui/", rec.Header().Get("Location"))

	// 2. Test GET /ui/ serves index.html with 200 OK
	req = httptest.NewRequest(http.MethodGet, "/ui/", nil)
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "text/html")
	assert.Contains(t, rec.Body.String(), "GoRoute AI Gateway")

	// 3. Test GET /ui/index.html serves index.html with 200 OK
	req = httptest.NewRequest(http.MethodGet, "/ui/index.html", nil)
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "text/html")
	assert.Contains(t, rec.Body.String(), "GoRoute AI Gateway")

	// 4. Test HTML5 History API fallback: /ui/keys serves index.html
	req = httptest.NewRequest(http.MethodGet, "/ui/keys", nil)
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "text/html")
	assert.Contains(t, rec.Body.String(), "GoRoute AI Gateway")

	// 5. Test nested client-side route: /ui/playground/deep/test serves index.html
	req = httptest.NewRequest(http.MethodGet, "/ui/playground/deep/test", nil)
	rec = httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "text/html")
	assert.Contains(t, rec.Body.String(), "GoRoute AI Gateway")

	// 6. Test Cache-Control headers
	assert.Equal(t, "no-cache", rec.Header().Get("Cache-Control"))
}

func TestUI_StaticAssetMimeAndCaching(t *testing.T) {
	r := chi.NewRouter()
	ui.RegisterRoutes(r)

	// 1. Verify index.html cache policy is no-cache
	req := httptest.NewRequest(http.MethodGet, "/ui/", nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "no-cache", rec.Header().Get("Cache-Control"))
	assert.True(t, strings.HasPrefix(rec.Header().Get("Content-Type"), "text/html"))

	// 2. Discover actual compiled assets from the embedded distribution
	distFS, err := ui.DistFS()
	require.NoError(t, err)

	entries, err := fs.ReadDir(distFS, "assets")
	require.NoError(t, err)
	require.NotEmpty(t, entries, "embedded assets directory should contain compiled bundles")

	var testedCSS, testedJS bool

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasSuffix(name, ".css") && !testedCSS {
			reqAsset := httptest.NewRequest(http.MethodGet, "/ui/assets/"+name, nil)
			recAsset := httptest.NewRecorder()
			r.ServeHTTP(recAsset, reqAsset)

			assert.Equal(t, http.StatusOK, recAsset.Code)
			assert.Equal(t, "public, max-age=31536000, immutable", recAsset.Header().Get("Cache-Control"))
			assert.True(t, strings.HasPrefix(recAsset.Header().Get("Content-Type"), "text/css"), "CSS file should have text/css MIME, got %q", recAsset.Header().Get("Content-Type"))
			testedCSS = true
		}
		if strings.HasSuffix(name, ".js") && !testedJS {
			reqAsset := httptest.NewRequest(http.MethodGet, "/ui/assets/"+name, nil)
			recAsset := httptest.NewRecorder()
			r.ServeHTTP(recAsset, reqAsset)

			assert.Equal(t, http.StatusOK, recAsset.Code)
			assert.Equal(t, "public, max-age=31536000, immutable", recAsset.Header().Get("Cache-Control"))
			contentType := recAsset.Header().Get("Content-Type")
			assert.True(t, strings.Contains(contentType, "javascript"), "JS file should have javascript MIME, got %q", contentType)
			testedJS = true
		}
	}

	assert.True(t, testedCSS, "at least one CSS bundle was tested")
	assert.True(t, testedJS, "at least one JS bundle was tested")
}
