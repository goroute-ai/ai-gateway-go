package observability

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
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
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tc := ParseOrGenerateTrace(r)
		w.Header().Set("X-Trace-Id", tc.TraceID)
		w.Header().Set("traceparent", tc.TraceParent)
		if reqID := r.Header.Get("X-Request-Id"); reqID != "" {
			w.Header().Set("X-Request-Id", reqID)
		}
		ctx := WithTraceContext(r.Context(), tc)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
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
