package ui

import (
	"embed"
	"io"
	"io/fs"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
)

//go:embed all:dist
var embeddedDist embed.FS

// DistFS returns the sub-filesystem for the embedded dist directory.
func DistFS() (fs.FS, error) {
	return fs.Sub(embeddedDist, "dist")
}

// RegisterRoutes mounts the embedded operator dashboard on the Chi router at /ui.
func RegisterRoutes(r chi.Router) {
	distFS, err := fs.Sub(embeddedDist, "dist")
	if err != nil {
		return
	}

	fileServer := http.FileServer(http.FS(distFS))

	// Redirect /ui to /ui/ with trailing slash for proper relative asset resolution
	r.Get("/ui", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "/ui/", http.StatusMovedPermanently)
	})

	// Serve static assets or fallback to index.html for SPA client-side routing
	r.Get("/ui/*", func(w http.ResponseWriter, r *http.Request) {
		trimmedPath := strings.TrimPrefix(r.URL.Path, "/ui")
		if trimmedPath == "" || trimmedPath == "/" {
			trimmedPath = "/index.html"
		}

		cleanPath := strings.TrimPrefix(trimmedPath, "/")

		// If the specific file exists (and is not index.html, which FileServer would 301-redirect to ./),
		// serve it with standard caching headers.
		if cleanPath != "index.html" {
			if f, err := distFS.Open(cleanPath); err == nil {
				_ = f.Close()
				if strings.HasPrefix(trimmedPath, "/assets/") {
					w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
				}
				http.StripPrefix("/ui", fileServer).ServeHTTP(w, r)
				return
			}
		}

		// HTML5 History API fallback: serve index.html for client-side routing
		indexFile, err := distFS.Open("index.html")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		defer indexFile.Close()

		stat, err := indexFile.Stat()
		if err != nil {
			http.NotFound(w, r)
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-cache")
		http.ServeContent(w, r, "index.html", stat.ModTime(), indexFile.(io.ReadSeeker))
	})
}
