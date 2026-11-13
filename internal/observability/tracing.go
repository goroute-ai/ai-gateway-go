package observability

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/trace"
)

type traceContextKey struct{}

// TraceContext holds W3C Distributed Tracing identifiers (`traceparent`).
type TraceContext struct {
	TraceID     string `json:"trace_id"`
	SpanID      string `json:"span_id"`
	TraceParent string `json:"traceparent"`
}

// Logger returns the globally registered *slog.Logger for the gateway.
func Logger() *slog.Logger {
	return slog.Default()
}

// ParseOrGenerateTrace extracts a W3C `traceparent` or `X-Trace-Id` from the request, or generates a fresh 128-bit TraceID + 64-bit SpanID.
func ParseOrGenerateTrace(r *http.Request) TraceContext {
	var traceID string
	if tp := strings.TrimSpace(r.Header.Get("traceparent")); tp != "" {
		parts := strings.Split(tp, "-")
		if len(parts) == 4 && len(parts[1]) == 32 {
			traceID = parts[1]
		}
	}
	if traceID == "" {
		if xtid := strings.TrimSpace(r.Header.Get("X-Trace-Id")); len(xtid) == 32 {
			traceID = xtid
		}
	}
	if traceID == "" {
		b := make([]byte, 16)
		_, _ = rand.Read(b)
		traceID = hex.EncodeToString(b)
	}

	sb := make([]byte, 8)
	_, _ = rand.Read(sb)
	spanID := hex.EncodeToString(sb)

	return TraceContext{
		TraceID:     traceID,
		SpanID:      spanID,
		TraceParent: fmt.Sprintf("00-%s-%s-01", traceID, spanID),
	}
}

// WithTraceContext attaches a TraceContext to ctx.
func WithTraceContext(ctx context.Context, tc TraceContext) context.Context {
	return context.WithValue(ctx, traceContextKey{}, tc)
}

// TraceFromContext retrieves the TraceContext from ctx.
func TraceFromContext(ctx context.Context) TraceContext {
	if val, ok := ctx.Value(traceContextKey{}).(TraceContext); ok {
		return val
	}
	return TraceContext{}
}

// TraceMiddleware injects W3C `traceparent` and `X-Trace-Id` headers on every request and response.
func TraceMiddleware(next http.Handler) http.Handler {
	return TraceMiddlewareWithTracer(trace.NewNoopTracerProvider().Tracer("ai-gateway-go"))(next)
}

type statusResponseWriter struct {
	http.ResponseWriter
	statusCode  int
	wroteHeader bool
}

func (w *statusResponseWriter) WriteHeader(code int) {
	if !w.wroteHeader {
		w.statusCode = code
		w.wroteHeader = true
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusResponseWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.statusCode = http.StatusOK
		w.wroteHeader = true
	}
	return w.ResponseWriter.Write(b)
}

func (w *statusResponseWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (w *statusResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hj, ok := w.ResponseWriter.(http.Hijacker); ok {
		return hj.Hijack()
	}
	return nil, nil, errors.New("underlying ResponseWriter does not implement http.Hijacker")
}

func (w *statusResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func TraceMiddlewareWithTracer(tracer trace.Tracer) func(http.Handler) http.Handler {
	if tracer == nil {
		tracer = trace.NewNoopTracerProvider().Tracer("ai-gateway-go")
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			parentCtx := propagation.TraceContext{}.Extract(r.Context(), propagation.HeaderCarrier(r.Header))
			ctx, span := tracer.Start(parentCtx, "HTTP "+r.Method,
				trace.WithSpanKind(trace.SpanKindServer),
				trace.WithAttributes(attribute.String("http.request.method", r.Method), attribute.String("url.path", r.URL.Path)),
			)
			sw := &statusResponseWriter{
				ResponseWriter: w,
				statusCode:     http.StatusOK,
			}
			defer func() {
				span.SetAttributes(attribute.Int("http.response.status_code", sw.statusCode))
				if sw.statusCode >= http.StatusInternalServerError {
					span.SetStatus(codes.Error, http.StatusText(sw.statusCode))
				}
				span.End()
			}()
			tc := ParseOrGenerateTrace(r)
			if spanContext := span.SpanContext(); span.IsRecording() && spanContext.IsValid() {
				tc = TraceContext{
					TraceID:     spanContext.TraceID().String(),
					SpanID:      spanContext.SpanID().String(),
					TraceParent: fmt.Sprintf("00-%s-%s-01", spanContext.TraceID(), spanContext.SpanID()),
				}
			}
			sw.Header().Set("X-Trace-Id", tc.TraceID)
			sw.Header().Set("traceparent", tc.TraceParent)
			if reqID := r.Header.Get("X-Request-Id"); reqID != "" {
				sw.Header().Set("X-Request-Id", reqID)
			}
			ctx = WithTraceContext(ctx, tc)
			next.ServeHTTP(sw, r.WithContext(ctx))
		})
	}
}

// InjectTraceHeaders injects W3C traceparent and X-Trace-Id from ctx into outgoing http.Request headers.
func InjectTraceHeaders(ctx context.Context, req *http.Request) {
	if req == nil {
		return
	}
	tc := TraceFromContext(ctx)
	if tc.TraceParent != "" {
		req.Header.Set("traceparent", tc.TraceParent)
		req.Header.Set("X-Trace-Id", tc.TraceID)
	}
}
