package observability

import (
	"context"
	"strings"
	"time"
	"unicode/utf8"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

const maxCapturedSpanContentChars = 2048

// GenAISpanStart holds standard OpenTelemetry GenAI semantic convention attributes
// attached when opening a client LLM, embedding, tool, or agent span.
type GenAISpanStart struct {
	Operation     string // "chat", "embeddings", "text_completion", "audio_transcription", "audio_speech", "generate_image", "moderation", "execute_tool", "invoke_agent"
	Provider      string // "openai", "anthropic", "groq", "openrouter"
	RequestModel  string
	ToolName      string
	MCPServerSlug string
	AgentName     string
	ServerAddress string
	DeploymentID  string
	OrgID         string
	Temperature   *float64
	TopP          *float64
	MaxTokens     *int
}

// GenAISpanEnd holds standard OpenTelemetry GenAI completion attributes recorded when closing a span.
type GenAISpanEnd struct {
	ResponseModel     string
	ResponseID        string
	FinishReasons     []string
	InputTokens       int64
	OutputTokens      int64
	CachedInputTokens int64
	CostMicros        int64
	RetryCount        int
	FallbackAttempted bool
	Err               error
	ErrorType         string
	CaptureContent    bool
	ScrubbedInput     string
	ScrubbedOutput    string
}

// StartGenAISpan starts an OpenTelemetry SpanKindClient span named "{operation} {model|tool|agent}"
// following OpenTelemetry GenAI Semantic Conventions.
func StartGenAISpan(ctx context.Context, tracer trace.Tracer, in GenAISpanStart) (context.Context, trace.Span) {
	if tracer == nil {
		tracer = otel.Tracer(instrumentationScopeName)
	}
	op := strings.TrimSpace(in.Operation)
	if op == "" {
		op = "chat"
	}
	target := strings.TrimSpace(in.RequestModel)
	if target == "" {
		target = strings.TrimSpace(in.ToolName)
	}
	if target == "" {
		target = strings.TrimSpace(in.AgentName)
	}
	spanName := op
	if target != "" {
		spanName = op + " " + target
	}

	attrs := make([]attribute.KeyValue, 0, 10)
	attrs = append(attrs, attribute.String("gen_ai.operation.name", op))
	if p := strings.TrimSpace(in.Provider); p != "" {
		attrs = append(attrs, attribute.String("gen_ai.provider.name", p))
	}
	if m := strings.TrimSpace(in.RequestModel); m != "" {
		attrs = append(attrs, attribute.String("gen_ai.request.model", m))
	}
	if tn := strings.TrimSpace(in.ToolName); tn != "" {
		attrs = append(attrs, attribute.String("gen_ai.tool.name", tn))
	}
	if slug := strings.TrimSpace(in.MCPServerSlug); slug != "" {
		attrs = append(attrs, attribute.String("goroute.mcp.server_slug", slug))
	}
	if an := strings.TrimSpace(in.AgentName); an != "" {
		attrs = append(attrs, attribute.String("gen_ai.agent.name", an))
	}
	if sa := strings.TrimSpace(in.ServerAddress); sa != "" {
		attrs = append(attrs, attribute.String("server.address", sa))
	}
	if dep := strings.TrimSpace(in.DeploymentID); dep != "" {
		attrs = append(attrs, attribute.String("goroute.deployment_id", dep))
	}
	if org := strings.TrimSpace(in.OrgID); org != "" {
		attrs = append(attrs, attribute.String("goroute.org_id", org))
	}
	if in.Temperature != nil {
		attrs = append(attrs, attribute.Float64("gen_ai.request.temperature", *in.Temperature))
	}
	if in.TopP != nil {
		attrs = append(attrs, attribute.Float64("gen_ai.request.top_p", *in.TopP))
	}
	if in.MaxTokens != nil && *in.MaxTokens > 0 {
		attrs = append(attrs, attribute.Int("gen_ai.request.max_tokens", *in.MaxTokens))
	}

	return tracer.Start(ctx, spanName,
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(attrs...),
	)
}

// RecordGenAIFirstToken attaches a "gen_ai.first_token" event and TTFT attribute on an active streaming span.
func RecordGenAIFirstToken(span trace.Span, ttft time.Duration) {
	if span == nil || ttft <= 0 {
		return
	}
	sec := ttft.Seconds()
	span.SetAttributes(attribute.Float64("gen_ai.server.time_to_first_token", sec))
	span.AddEvent("gen_ai.first_token", trace.WithAttributes(attribute.Float64("ttft_seconds", sec)))
}

// FinishGenAISpan finalizes a GenAI client span with response metadata, token usage, cost, and error status.
// Raw prompt/completion content is never recorded unless CaptureContent is true (privacy-first OTel GenAI default).
func FinishGenAISpan(span trace.Span, out GenAISpanEnd) {
	if span == nil {
		return
	}
	attrs := make([]attribute.KeyValue, 0, 10)
	if m := strings.TrimSpace(out.ResponseModel); m != "" {
		attrs = append(attrs, attribute.String("gen_ai.response.model", m))
	}
	if id := strings.TrimSpace(out.ResponseID); id != "" {
		attrs = append(attrs, attribute.String("gen_ai.response.id", id))
	}
	if len(out.FinishReasons) > 0 {
		attrs = append(attrs, attribute.StringSlice("gen_ai.response.finish_reasons", out.FinishReasons))
	}
	if out.InputTokens > 0 {
		attrs = append(attrs, attribute.Int64("gen_ai.usage.input_tokens", out.InputTokens))
	}
	if out.OutputTokens > 0 {
		attrs = append(attrs, attribute.Int64("gen_ai.usage.output_tokens", out.OutputTokens))
	}
	if out.CachedInputTokens > 0 {
		attrs = append(attrs, attribute.Int64("gen_ai.usage.cached_input_tokens", out.CachedInputTokens))
	}
	if out.CostMicros > 0 {
		attrs = append(attrs, attribute.Int64("goroute.cost_micros", out.CostMicros))
	}
	if out.RetryCount > 0 {
		attrs = append(attrs, attribute.Int("goroute.retry_count", out.RetryCount))
	}
	if out.FallbackAttempted {
		attrs = append(attrs, attribute.Bool("goroute.fallback_attempted", true))
	}
	if out.CaptureContent {
		if inText := truncateSpanUTF8(out.ScrubbedInput, maxCapturedSpanContentChars); inText != "" {
			attrs = append(attrs, attribute.String("gen_ai.input.messages", inText))
		}
		if outText := truncateSpanUTF8(out.ScrubbedOutput, maxCapturedSpanContentChars); outText != "" {
			attrs = append(attrs, attribute.String("gen_ai.output.messages", outText))
		}
	}
	if out.Err != nil {
		errType := strings.TrimSpace(out.ErrorType)
		if errType == "" {
			errType = "upstream_error"
		}
		attrs = append(attrs, attribute.String("error.type", errType))
		span.RecordError(out.Err)
		span.SetStatus(codes.Error, errType)
	}
	if len(attrs) > 0 {
		span.SetAttributes(attrs...)
	}
	span.End()
}

// StartCacheLookupSpan starts an internal child span for response cache lookups.
func StartCacheLookupSpan(ctx context.Context, tracer trace.Tracer, backendType, model string) (context.Context, trace.Span) {
	if tracer == nil {
		tracer = otel.Tracer(instrumentationScopeName)
	}
	return tracer.Start(ctx, "cache.lookup",
		trace.WithSpanKind(trace.SpanKindInternal),
		trace.WithAttributes(
			attribute.String("goroute.cache.backend", sanitizeMetricLabel(backendType)),
			attribute.String("gen_ai.request.model", sanitizeMetricLabel(model)),
		),
	)
}

// FinishCacheLookupSpan completes a cache.lookup child span with hit/miss, cache type, and semantic similarity.
func FinishCacheLookupSpan(span trace.Span, hit bool, cacheType string, similarity float64, err error) {
	if span == nil {
		return
	}
	attrs := []attribute.KeyValue{
		attribute.Bool("goroute.cache.hit", hit),
	}
	if ct := strings.TrimSpace(cacheType); ct != "" {
		attrs = append(attrs, attribute.String("goroute.cache.type", ct))
	}
	if similarity > 0 {
		attrs = append(attrs, attribute.Float64("goroute.cache.similarity", similarity))
	}
	span.SetAttributes(attrs...)
	if err != nil {
		span.RecordError(err)
		span.SetStatus(codes.Error, "cache_lookup_error")
	}
	span.End()
}

func truncateSpanUTF8(s string, maxChars int) string {
	s = strings.TrimSpace(s)
	if s == "" || maxChars <= 0 {
		return ""
	}
	if utf8.RuneCountInString(s) <= maxChars {
		return s
	}
	var b strings.Builder
	count := 0
	for _, r := range s {
		if count >= maxChars {
			break
		}
		b.WriteRune(r)
		count++
	}
	return b.String()
}
