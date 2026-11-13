package logger

import (
	"context"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"

	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/observability"
)

type requestIDContextKey struct{}

// WithRequestID returns a new context with the given request ID attached.
func WithRequestID(ctx context.Context, reqID string) context.Context {
	return context.WithValue(ctx, requestIDContextKey{}, reqID)
}

// RequestIDFromContext extracts the request ID from ctx, if present.
func RequestIDFromContext(ctx context.Context) string {
	if val, ok := ctx.Value(requestIDContextKey{}).(string); ok {
		return val
	}
	return ""
}

// Config specifies the runtime configuration for the structured logging subsystem.
type Config struct {
	Level     string    `yaml:"level" json:"level"`           // "debug", "info", "warn", "error"
	Format    string    `yaml:"format" json:"format"`         // "text" or "json"
	AddSource bool      `yaml:"add_source" json:"add_source"` // include file:line in output
	Output    io.Writer `yaml:"-" json:"-"`                   // custom writer, defaults to os.Stdout
}

// ContextHandler wraps an slog.Handler to automatically inject distributed trace IDs,
// request IDs, and multi-tenant identity attributes from context.Context into every log record.
type ContextHandler struct {
	slog.Handler
}

func (h *ContextHandler) Handle(ctx context.Context, r slog.Record) error {
	if ctx != nil {
		// 1. W3C Distributed Tracing Attributes
		tc := observability.TraceFromContext(ctx)
		if tc.TraceID != "" {
			r.AddAttrs(slog.String("trace_id", tc.TraceID))
		}
		if tc.SpanID != "" {
			r.AddAttrs(slog.String("span_id", tc.SpanID))
		}

		// 2. Correlation Request ID
		if reqID := RequestIDFromContext(ctx); reqID != "" {
			r.AddAttrs(slog.String("request_id", reqID))
		}

		// 3. Multi-Tenant Identity Context
		if idCtx := auth.IdentityFromContext(ctx); idCtx != nil {
			if idCtx.OrgID != "" {
				r.AddAttrs(slog.String("org_id", idCtx.OrgID))
			}
			if idCtx.TeamID != "" {
				r.AddAttrs(slog.String("team_id", idCtx.TeamID))
			}
			if idCtx.VirtualKeyID != "" {
				r.AddAttrs(slog.String("virtual_key_id", idCtx.VirtualKeyID))
			}
			if idCtx.KeyPrefix != "" {
				r.AddAttrs(slog.String("key_prefix", idCtx.KeyPrefix))
			}
		}
	}
	return h.Handler.Handle(ctx, r)
}

func (h *ContextHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &ContextHandler{Handler: h.Handler.WithAttrs(attrs)}
}

func (h *ContextHandler) WithGroup(name string) slog.Handler {
	return &ContextHandler{Handler: h.Handler.WithGroup(name)}
}

var (
	mu           sync.RWMutex
	globalLogger *slog.Logger
)

func init() {
	// Initialize default human-readable text logger
	globalLogger = New(Config{
		Level:  "info",
		Format: "text",
	})
}

// ParseLevel parses a level string ("debug", "info", "warn", "error") into an slog.Level.
func ParseLevel(lvl string) slog.Level {
	switch strings.ToLower(strings.TrimSpace(lvl)) {
	case "debug":
		return slog.LevelDebug
	case "warn", "warning":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// New creates a new isolated *slog.Logger with context enrichment.
func New(cfg Config) *slog.Logger {
	out := cfg.Output
	if out == nil {
		out = os.Stdout
	}

	level := ParseLevel(cfg.Level)
	opts := &slog.HandlerOptions{
		Level:       level,
		AddSource:   cfg.AddSource,
		ReplaceAttr: scrubAttr,
	}

	var baseHandler slog.Handler
	format := strings.ToLower(strings.TrimSpace(cfg.Format))

	// In cloud-native production environments, default to JSON if unspecified or requested
	env := strings.ToLower(os.Getenv("ENV"))
	if format == "json" || (format == "" && (env == "production" || env == "prod")) {
		baseHandler = slog.NewJSONHandler(out, opts)
	} else {
		baseHandler = slog.NewTextHandler(out, opts)
	}

	return slog.New(&ContextHandler{Handler: baseHandler})
}

// Init initializes and replaces the global singleton logger.
func Init(cfg Config) *slog.Logger {
	l := New(cfg)
	mu.Lock()
	globalLogger = l
	slog.SetDefault(l)
	mu.Unlock()
	return l
}

// L returns the active global singleton logger.
func L() *slog.Logger {
	mu.RLock()
	defer mu.RUnlock()
	return globalLogger
}

// Default is an alias for L().
func Default() *slog.Logger {
	return L()
}

// WithComponent returns a child logger scoped with a component attribute (e.g. "router", "finops").
func WithComponent(name string) *slog.Logger {
	return L().With(slog.String("component", name))
}

// Top-level convenience logging helpers
func Debug(msg string, args ...any) {
	L().Debug(msg, args...)
}

func DebugContext(ctx context.Context, msg string, args ...any) {
	L().DebugContext(ctx, msg, args...)
}

func Info(msg string, args ...any) {
	L().Info(msg, args...)
}

func InfoContext(ctx context.Context, msg string, args ...any) {
	L().InfoContext(ctx, msg, args...)
}

func Warn(msg string, args ...any) {
	L().Warn(msg, args...)
}

func WarnContext(ctx context.Context, msg string, args ...any) {
	L().WarnContext(ctx, msg, args...)
}

func Error(msg string, args ...any) {
	L().Error(msg, args...)
}

func ErrorContext(ctx context.Context, msg string, args ...any) {
	L().ErrorContext(ctx, msg, args...)
}
