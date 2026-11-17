package ui_test

import (
	"net/http"
	"net/http/httptest"
	"runtime"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/goroute-ai/ai-gateway-go/internal/ui"
)

func BenchmarkUIServing_IndexHTML(b *testing.B) {
	r := chi.NewRouter()
	ui.RegisterRoutes(r)

	req := httptest.NewRequest(http.MethodGet, "/ui/", nil)
	rec := httptest.NewRecorder()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		rec.Body.Reset()
		r.ServeHTTP(rec, req)
	}
}

func BenchmarkUIServing_SPAFallback(b *testing.B) {
	r := chi.NewRouter()
	ui.RegisterRoutes(r)

	req := httptest.NewRequest(http.MethodGet, "/ui/keys", nil)
	rec := httptest.NewRecorder()

	b.ResetTimer()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		rec.Body.Reset()
		r.ServeHTTP(rec, req)
	}
}

func TestUI_HeapAllocationMeasurement(t *testing.T) {
	var mBefore, mAfter runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&mBefore)

	r := chi.NewRouter()
	ui.RegisterRoutes(r)

	for i := 0; i < 1000; i++ {
		req := httptest.NewRequest(http.MethodGet, "/ui/playground", nil)
		rec := httptest.NewRecorder()
		r.ServeHTTP(rec, req)
	}

	runtime.ReadMemStats(&mAfter)
	t.Logf("HeapAlloc: before=%d bytes, after=%d bytes, diff=%d bytes",
		mBefore.HeapAlloc, mAfter.HeapAlloc, int64(mAfter.HeapAlloc)-int64(mBefore.HeapAlloc))
}
