package logger

import (
	"bufio"
	"context"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

// InferenceMeta holds structured inference telemetry recorded by downstream handlers
// so HTTPMiddleware can include model, provider, token, cost, and cache attributes.
type InferenceMeta struct {
	Model            string
	Provider         string
	PromptTokens     int
	CompletionTokens int
	CostMicros       int64
	CacheHit         bool
}

// RequestIdentity holds tenant identity recorded by downstream auth middleware so
// HTTPMiddleware (which wraps auth middleware) emits org_id, team_id, virtual_key_id,
// and key_prefix on completed HTTP access logs.
type RequestIdentity struct {
	OrgID        string
	TeamID       string
	VirtualKeyID string
	KeyPrefix    string
}

type inferenceMetaKey struct{}
type requestIdentityKey struct{}

type inferenceMetaHolder struct {
	mu   sync.Mutex
	meta InferenceMeta
	set  bool
}

type requestIdentityHolder struct {
	mu   sync.Mutex
	meta RequestIdentity
	set  bool
}

// SetInferenceMeta populates the mutable InferenceMeta holder attached to ctx by HTTPMiddleware.
// It is a no-op if ctx is nil or does not carry an inference metadata holder.
func SetInferenceMeta(ctx context.Context, meta InferenceMeta) {
	if ctx == nil {
		return
	}
	holder, ok := ctx.Value(inferenceMetaKey{}).(*inferenceMetaHolder)
	if !ok || holder == nil {
		return
	}
	holder.mu.Lock()
	holder.meta = meta
	holder.set = true
	holder.mu.Unlock()
}

// SetRequestIdentity populates the mutable RequestIdentity holder attached to ctx by HTTPMiddleware
// so completed HTTP access logs include tenant identity resolved by downstream auth middleware.
func SetRequestIdentity(ctx context.Context, id RequestIdentity) {
	if ctx == nil {
		return
	}
	holder, ok := ctx.Value(requestIdentityKey{}).(*requestIdentityHolder)
	if !ok || holder == nil {
		return
	}
	holder.mu.Lock()
	holder.meta = id
	holder.set = true
	holder.mu.Unlock()
}

func requestIdentityFromContext(ctx context.Context) (RequestIdentity, bool) {
	if ctx == nil {
		return RequestIdentity{}, false
	}
	holder, ok := ctx.Value(requestIdentityKey{}).(*requestIdentityHolder)
	if !ok || holder == nil {
		return RequestIdentity{}, false
	}
	holder.mu.Lock()
	meta := holder.meta
	set := holder.set
	holder.mu.Unlock()
	return meta, set
}

type responseRecorder struct {
	http.ResponseWriter
	statusCode  int
	bytes       int
	wroteHeader bool
}

func (r *responseRecorder) WriteHeader(statusCode int) {
	if !r.wroteHeader {
		r.statusCode = statusCode
		r.wroteHeader = true
	}
	r.ResponseWriter.WriteHeader(statusCode)
}

func (r *responseRecorder) Write(b []byte) (int, error) {
	if !r.wroteHeader {
		if r.Header().Get("Content-Type") == "" {
			// Prevent net/http from sniffing body bytes as text/html on generic responses.
			r.Header().Set("Content-Type", "application/octet-stream")
		}
		if r.statusCode == 0 {
			r.statusCode = http.StatusOK
		}
		r.wroteHeader = true
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

func (r *responseRecorder) Unwrap() http.ResponseWriter {
	return r.ResponseWriter
}

// HTTPMiddleware constructs a production-grade structured logging middleware for http.Handler routers.
// It intercepts requests, records duration, status, and payload size, enriches logs with trace IDs,
// request IDs, tenant identity, and inference telemetry, and downgrades Kubernetes health probes
// (/healthz, /readyz) to DEBUG level.
func HTTPMiddleware(l *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			base := l
			if base == nil {
				base = L()
			}
			httpLogger := base.With(slog.String("component", "http"))

			// Extract, sanitize, and bound Request ID
			reqID := sanitizeRequestID(r.Header.Get("X-Request-Id"))
			if reqID == "" {
				reqID = "req_" + uuid.NewString()
			}
			w.Header().Set("X-Gateway-Request-Id", reqID)

			// Enrich request context with request ID and mutable inference/identity holders
			holder := &inferenceMetaHolder{}
			idHolder := &requestIdentityHolder{}
			ctx := WithRequestID(r.Context(), reqID)
			ctx = context.WithValue(ctx, inferenceMetaKey{}, holder)
			ctx = context.WithValue(ctx, requestIdentityKey{}, idHolder)
			r = r.WithContext(ctx)

			rec := &responseRecorder{
				ResponseWriter: w,
				statusCode:     http.StatusOK,
			}

			next.ServeHTTP(rec, r)

			duration := time.Since(start)
			durMs := float64(duration.Microseconds()) / 1000.0

			path := r.URL.Path

			// Downgrade high-frequency Kubernetes liveness/readiness probes to DEBUG.
			isProbe := path == "/healthz" || path == "/readyz"

			attrs := []any{
				slog.String("method", r.Method),
				slog.String("path", path),
				slog.Int("status", rec.statusCode),
				slog.Float64("duration_ms", durMs),
				slog.Int("bytes", rec.bytes),
				slog.String("remote_ip", r.RemoteAddr),
			}

			holder.mu.Lock()
			meta := holder.meta
			hasMeta := holder.set
			holder.mu.Unlock()
			if hasMeta {
				if meta.Model != "" {
					attrs = append(attrs, slog.String("model", meta.Model))
				}
				if meta.Provider != "" {
					attrs = append(attrs, slog.String("provider", meta.Provider))
				}
				if meta.PromptTokens > 0 {
					attrs = append(attrs, slog.Int("prompt_tokens", meta.PromptTokens))
				}
				if meta.CompletionTokens > 0 {
					attrs = append(attrs, slog.Int("completion_tokens", meta.CompletionTokens))
				}
				if meta.CostMicros > 0 {
					attrs = append(attrs, slog.Int64("cost_micros", meta.CostMicros))
				}
				if meta.CacheHit {
					attrs = append(attrs, slog.Bool("cache_hit", true))
				}
			}

			// Note: trace_id, span_id, request_id, org_id, team_id, virtual_key_id, and key_prefix
			// are injected automatically by ContextHandler from ctx (including idHolder).

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
