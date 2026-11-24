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

// ContextHandler wraps an slog.Handler to automatically attach trace, request,
// and tenant identity attributes extracted from context.Context, scrub secrets/PII
// on every attribute and message, and optionally fan out scrubbed records to an
// OTLP slog.Handler (via otelslog) when OTLP log export is enabled.
type ContextHandler struct {
	slog.Handler
	useGlobalOTLP bool
	explicitOTLP  slog.Handler
	preAttrs      []slog.Attr
	groups        []string
}

// Enabled reports whether the wrapped handler handles records at the given level.
func (h *ContextHandler) Enabled(ctx context.Context, level slog.Level) bool {
	if h.Handler != nil && h.Handler.Enabled(ctx, level) {
		return true
	}
	if otlp := h.resolveOTLPHandler(); otlp != nil {
		return otlp.Enabled(ctx, level)
	}
	return false
}

func (h *ContextHandler) resolveOTLPHandler() slog.Handler {
	if h.explicitOTLP != nil {
		return h.explicitOTLP
	}
	if h.useGlobalOTLP {
		otlpMu.RLock()
		oh := globalOTLPHandler
		otlpMu.RUnlock()
		return oh
	}
	return nil
}

// Handle enriches r with trace, request, and identity context fields, scrubs secrets/PII,
// and dispatches to stdout and (when configured) the OTLP log bridge.
func (h *ContextHandler) Handle(ctx context.Context, r slog.Record) error {
	var extraAttrs []slog.Attr
	if ctx != nil {
		// 1. W3C Distributed Tracing Attributes
		tc := observability.TraceFromContext(ctx)
		if tc.TraceID != "" {
			extraAttrs = append(extraAttrs, slog.String("trace_id", tc.TraceID))
		}
		if tc.SpanID != "" {
			extraAttrs = append(extraAttrs, slog.String("span_id", tc.SpanID))
		}

		// 2. Correlation Request ID
		if reqID := RequestIDFromContext(ctx); reqID != "" {
			extraAttrs = append(extraAttrs, slog.String("request_id", reqID))
		}

		// 3. Multi-Tenant Identity Context (direct context OR mutable middleware holder)
		var orgID, teamID, vkID, keyPrefix string
		if idCtx := auth.IdentityFromContext(ctx); idCtx != nil {
			orgID = idCtx.OrgID
			teamID = idCtx.TeamID
			vkID = idCtx.VirtualKeyID
			keyPrefix = idCtx.KeyPrefix
		} else if idMeta, ok := requestIdentityFromContext(ctx); ok {
			orgID = idMeta.OrgID
			teamID = idMeta.TeamID
			vkID = idMeta.VirtualKeyID
			keyPrefix = idMeta.KeyPrefix
		}
		if orgID != "" {
			extraAttrs = append(extraAttrs, slog.String("org_id", orgID))
		}
		if teamID != "" {
			extraAttrs = append(extraAttrs, slog.String("team_id", teamID))
		}
		if vkID != "" {
			extraAttrs = append(extraAttrs, slog.String("virtual_key_id", vkID))
		}
		if keyPrefix != "" {
			extraAttrs = append(extraAttrs, slog.String("key_prefix", keyPrefix))
		}
	}

	// Build scrubbed record for primary handler (stdout) + optional OTLP handler.
	primaryRec := r.Clone()
	primaryRec.Message = ScrubSecrets(primaryRec.Message)
	if len(extraAttrs) > 0 {
		primaryRec.AddAttrs(extraAttrs...)
	}

	var firstErr error
	if h.Handler != nil && h.Handler.Enabled(ctx, primaryRec.Level) {
		firstErr = h.Handler.Handle(ctx, primaryRec)
	}

	if otlp := h.resolveOTLPHandler(); otlp != nil && otlp.Enabled(ctx, primaryRec.Level) {
		otlpRec := slog.NewRecord(primaryRec.Time, primaryRec.Level, primaryRec.Message, primaryRec.PC)
		for _, a := range h.preAttrs {
			otlpRec.AddAttrs(scrubAttr(h.groups, a))
		}
		r.Attrs(func(a slog.Attr) bool {
			otlpRec.AddAttrs(scrubAttr(h.groups, a))
			return true
		})
		for _, a := range extraAttrs {
			otlpRec.AddAttrs(scrubAttr(nil, a))
		}
		if err := otlp.Handle(ctx, otlpRec); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// WithAttrs returns a new ContextHandler wrapping the underlying handler with attrs.
func (h *ContextHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	scrubbed := make([]slog.Attr, len(attrs))
	for i, a := range attrs {
		scrubbed[i] = scrubAttr(h.groups, a)
	}
	combined := make([]slog.Attr, 0, len(h.preAttrs)+len(scrubbed))
	combined = append(combined, h.preAttrs...)
	combined = append(combined, scrubbed...)
	var nextBase slog.Handler
	if h.Handler != nil {
		nextBase = h.Handler.WithAttrs(scrubbed)
	}
	return &ContextHandler{
		Handler:       nextBase,
		useGlobalOTLP: h.useGlobalOTLP,
		explicitOTLP:  h.explicitOTLP,
		preAttrs:      combined,
		groups:        h.groups,
	}
}

// WithGroup returns a new ContextHandler wrapping the underlying handler scoped to name.
func (h *ContextHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	nextGroups := append(append([]string(nil), h.groups...), name)
	var nextBase slog.Handler
	if h.Handler != nil {
		nextBase = h.Handler.WithGroup(name)
	}
	return &ContextHandler{
		Handler:       nextBase,
		useGlobalOTLP: h.useGlobalOTLP,
		explicitOTLP:  h.explicitOTLP,
		preAttrs:      h.preAttrs,
		groups:        nextGroups,
	}
}

var (
	mu                sync.RWMutex
	globalLogger      *slog.Logger
	otlpMu            sync.RWMutex
	globalOTLPHandler slog.Handler
)

func init() {
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

// New creates a new isolated *slog.Logger with context enrichment and secret/PII scrubbing.
func New(cfg Config) *slog.Logger {
	return newLogger(cfg, false, nil)
}

// NewWithOTLPHandler creates an isolated *slog.Logger that fans out scrubbed records to stdout and otlpHandler.
func NewWithOTLPHandler(cfg Config, otlpHandler slog.Handler) *slog.Logger {
	return newLogger(cfg, false, otlpHandler)
}

func newLogger(cfg Config, useGlobalOTLP bool, explicitOTLP slog.Handler) *slog.Logger {
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

	env := strings.ToLower(strings.TrimSpace(os.Getenv("GATEWAY_ENV")))
	if env == "" {
		env = strings.ToLower(strings.TrimSpace(os.Getenv("ENV")))
	}
	if format == "json" || (format == "" && (env == "production" || env == "prod")) {
		baseHandler = slog.NewJSONHandler(out, opts)
	} else {
		baseHandler = slog.NewTextHandler(out, opts)
	}

	return slog.New(&ContextHandler{
		Handler:       baseHandler,
		useGlobalOTLP: useGlobalOTLP,
		explicitOTLP:  explicitOTLP,
	})
}

// Init initializes and replaces the global singleton logger (enabling global OTLP fan-out when attached).
func Init(cfg Config) *slog.Logger {
	l := newLogger(cfg, true, nil)
	SetGlobal(l)
	return l
}

// SetGlobal sets both the internal/logger singleton and slog.Default() so embedded SDK callers
// using gateway.WithLogger receive consistent routing across all internal packages.
func SetGlobal(l *slog.Logger) {
	if l == nil {
		return
	}
	mu.Lock()
	globalLogger = l
	slog.SetDefault(l)
	mu.Unlock()
}

// SetOTLPHandler attaches (or clears when nil) the global OTLP slog.Handler (e.g. otelslog.NewHandler)
// that receives post-scrubbed, context-enriched structured log records.
func SetOTLPHandler(h slog.Handler) {
	otlpMu.Lock()
	globalOTLPHandler = h
	otlpMu.Unlock()
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

// Debug logs a debug-level message using the global logger.
func Debug(msg string, args ...any) {
	L().Debug(msg, args...)
}

// DebugContext logs a debug-level message enriched with attributes from ctx.
func DebugContext(ctx context.Context, msg string, args ...any) {
	L().DebugContext(ctx, msg, args...)
}

// Info logs an info-level message using the global logger.
func Info(msg string, args ...any) {
	L().Info(msg, args...)
}

// InfoContext logs an info-level message enriched with attributes from ctx.
func InfoContext(ctx context.Context, msg string, args ...any) {
	L().InfoContext(ctx, msg, args...)
}

// Warn logs a warning-level message using the global logger.
func Warn(msg string, args ...any) {
	L().Warn(msg, args...)
}

// WarnContext logs a warning-level message enriched with attributes from ctx.
func WarnContext(ctx context.Context, msg string, args ...any) {
	L().WarnContext(ctx, msg, args...)
}

// Error logs an error-level message using the global logger.
func Error(msg string, args ...any) {
	L().Error(msg, args...)
}

// ErrorContext logs an error-level message enriched with attributes from ctx.
func ErrorContext(ctx context.Context, msg string, args ...any) {
	L().ErrorContext(ctx, msg, args...)
}
