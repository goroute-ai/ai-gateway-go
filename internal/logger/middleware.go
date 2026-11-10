package logger

import (
	"bufio"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/goroute-ai/ai-gateway-go/internal/observability"
)

type responseRecorder struct {
	http.ResponseWriter
	statusCode int
	bytes      int
}

func (r *responseRecorder) WriteHeader(statusCode int) {
	r.statusCode = statusCode
	r.ResponseWriter.WriteHeader(statusCode)
}

func (r *responseRecorder) Write(b []byte) (int, error) {
	if r.statusCode == 0 {
		r.statusCode = http.StatusOK
	}
	n, err := r.ResponseWriter.Write(b)
	r.bytes += n
	return n, err
}

func (r *responseRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (r *responseRecorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hj, ok := r.ResponseWriter.(http.Hijacker); ok {
		return hj.Hijack()
	}
	return nil, nil, errors.New("underlying ResponseWriter does not implement http.Hijacker")
}

// HTTPMiddleware constructs a production-grade structured logging middleware for http.Handler routers.
// It intercepts requests, records duration, status, and payload size, extracts tracing metadata,
// and automatically filters noisy Kubernetes health probes (/healthz, /readyz, /metrics) to DEBUG level.
func HTTPMiddleware(l *slog.Logger) func(http.Handler) http.Handler {
	if l == nil {
		l = L()
	}
	httpLogger := l.With(slog.String("component", "http"))

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			// Extract or generate unique Request ID
			reqID := strings.TrimSpace(r.Header.Get("X-Request-Id"))
			if reqID == "" {
				reqID = "req_" + uuid.NewString()
			}
			w.Header().Set("X-Gateway-Request-Id", reqID)

			// Enrich request context with request ID and tracing context
			ctx := WithRequestID(r.Context(), reqID)
			r = r.WithContext(ctx)

			rec := &responseRecorder{
				ResponseWriter: w,
				statusCode:     http.StatusOK,
			}

			next.ServeHTTP(rec, r)

			duration := time.Since(start)
			durMs := float64(duration.Microseconds()) / 1000.0

			path := r.URL.Path

			// Check if this is a high-frequency probe endpoint
			isProbe := path == "/healthz" || path == "/readyz" || path == "/metrics"

			attrs := []any{
				slog.String("method", r.Method),
				slog.String("path", path),
				slog.Int("status", rec.statusCode),
				slog.Float64("duration_ms", durMs),
				slog.Int("bytes", rec.bytes),
				slog.String("remote_ip", r.RemoteAddr),
			}

			// Add W3C Trace ID if available
			tc := observability.TraceFromContext(r.Context())
			if tc.TraceID != "" {
				attrs = append(attrs, slog.String("trace_id", tc.TraceID))
			}
			attrs = append(attrs, slog.String("request_id", reqID))

			// Log level selection based on status and path
			if isProbe {
				httpLogger.DebugContext(ctx, "health probe", attrs...)
				return
			}

			msg := "http request completed"
			switch {
			case rec.statusCode >= http.StatusInternalServerError:
				httpLogger.ErrorContext(ctx, msg, attrs...)
			case rec.statusCode >= http.StatusBadRequest:
				httpLogger.WarnContext(ctx, msg, attrs...)
			default:
				httpLogger.InfoContext(ctx, msg, attrs...)
			}
		})
	}
}
