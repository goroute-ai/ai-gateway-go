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

			// Extract, sanitize, and bound Request ID
			reqID := sanitizeRequestID(r.Header.Get("X-Request-Id"))
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

			// Note: trace_id and request_id are injected automatically by contextHandler from ctx.

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

const maxRequestIDLen = 128

func sanitizeRequestID(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > maxRequestIDLen {
		if len(raw) > maxRequestIDLen {
			raw = raw[:maxRequestIDLen]
		} else {
			return ""
		}
	}
	var b strings.Builder
	b.Grow(len(raw))
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == ':' {
			b.WriteByte(c)
		} else {
			return ""
		}
	}
	return b.String()
}
