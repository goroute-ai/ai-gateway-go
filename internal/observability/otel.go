package observability

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
	"go.opentelemetry.io/contrib/bridges/otelslog"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
	"go.opentelemetry.io/otel/trace/noop"
)

const instrumentationScopeName = "github.com/goroute-ai/ai-gateway-go"

// OTelStatus summarizes which OTLP signals are active on this gateway instance.
type OTelStatus struct {
	Enabled       bool
	TracesActive  bool
	MetricsActive bool
	LogsActive    bool
}

// ActiveSignals returns the ordered list of active OTLP signal names.
func (s OTelStatus) ActiveSignals() []string {
	out := make([]string, 0, 3)
	if s.TracesActive {
		out = append(out, "traces")
	}
	if s.MetricsActive {
		out = append(out, "metrics")
	}
	if s.LogsActive {
		out = append(out, "logs")
	}
	return out
}

// RuntimeOptions configures optional build metadata and extra SDK readers/processors
// (primarily used by deterministic unit and integration tests).
type RuntimeOptions struct {
	ServiceVersion      string
	Sampler             sdktrace.Sampler
	ExtraSpanProcessors []sdktrace.SpanProcessor
	ExtraMetricReaders  []sdkmetric.Reader
	ExtraLogProcessors  []sdklog.Processor
}

// TelemetryRuntime owns the lifecycle of GoRoute's unified 3-signal OpenTelemetry
// providers (Traces, Metrics, and opt-in Logs) exporting exclusively over OTLP/HTTP.
type TelemetryRuntime struct {
	tracer         trace.Tracer
	tracerProvider *sdktrace.TracerProvider
	meterProvider  *sdkmetric.MeterProvider
	loggerProvider *sdklog.LoggerProvider
	instruments    *Instruments
	logHandler     slog.Handler
	status         OTelStatus
	captureContent bool
}

// NewTelemetryRuntime initializes OpenTelemetry Trace, Metric, and opt-in Log providers
// strictly enforcing cfg.Enabled and validating every OTLP/HTTP endpoint against policy.
func NewTelemetryRuntime(
	ctx context.Context,
	cfg config.OTelConfig,
	policy *network.Policy,
	opts RuntimeOptions,
) (*TelemetryRuntime, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	serviceName := strings.TrimSpace(cfg.ServiceName)
	if serviceName == "" {
		serviceName = "ai-gateway-go"
	}

	resAttrs := []attribute.KeyValue{
		attribute.String("service.name", serviceName),
	}
	if v := strings.TrimSpace(opts.ServiceVersion); v != "" {
		resAttrs = append(resAttrs, attribute.String("service.version", v))
	}
	if env := strings.TrimSpace(cfg.DeploymentEnvironment); env != "" {
		resAttrs = append(resAttrs, attribute.String("deployment.environment.name", env))
	}
	res, err := resource.New(ctx, resource.WithAttributes(resAttrs...))
	if err != nil {
		return nil, fmt.Errorf("create OpenTelemetry resource: %w", err)
	}

	// Register standard W3C TraceContext + Baggage propagators globally.
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	rt := &TelemetryRuntime{
		tracer:         noop.NewTracerProvider().Tracer(instrumentationScopeName),
		captureContent: cfg.Traces.CaptureContent,
		status: OTelStatus{
			Enabled: cfg.Enabled,
		},
	}

	cleanupOnErr := func(cause error) (*TelemetryRuntime, error) {
		_ = rt.Shutdown(context.Background())
		return nil, cause
	}

	headers := maps.Clone(cfg.Headers)

	if err := rt.initTraceProvider(ctx, cfg, policy, res, headers, opts); err != nil {
		return cleanupOnErr(err)
	}
	if err := rt.initMeterProvider(ctx, cfg, policy, res, headers, opts); err != nil {
		return cleanupOnErr(err)
	}
	if err := rt.initLoggerProvider(ctx, cfg, policy, res, headers, opts); err != nil {
		return cleanupOnErr(err)
	}

	return rt, nil
}

func (rt *TelemetryRuntime) initTraceProvider(
	ctx context.Context,
	cfg config.OTelConfig,
	policy *network.Policy,
	res *resource.Resource,
	headers map[string]string,
	opts RuntimeOptions,
) error {
	var spanProcessors []sdktrace.SpanProcessor
	if raw := cfg.ResolvedTracesEndpoint(); cfg.TracesEnabled() && raw != "" {
		endpoint, err := validateOTLPEndpoint("otel.traces.endpoint", raw, "/v1/traces", policy)
		if err != nil {
			return err
		}
		exp, err := otlptracehttp.New(ctx,
			otlptracehttp.WithEndpointURL(endpoint),
			otlptracehttp.WithHTTPClient(network.NewHTTPClient(policy)),
			otlptracehttp.WithHeaders(headers),
		)
		if err != nil {
			return fmt.Errorf("create OTLP trace exporter: %w", err)
		}
		spanProcessors = append(spanProcessors, sdktrace.NewBatchSpanProcessor(exp))
		rt.status.TracesActive = true
	}
	spanProcessors = append(spanProcessors, opts.ExtraSpanProcessors...)
	if len(spanProcessors) == 0 {
		return nil
	}

	sampler := opts.Sampler
	if sampler == nil {
		sampler = resolveOTLPSampler(cfg.Traces.Sampler, cfg.Traces.SamplerArg)
	}
	tpOpts := []sdktrace.TracerProviderOption{
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sampler),
	}
	for _, sp := range spanProcessors {
		tpOpts = append(tpOpts, sdktrace.WithSpanProcessor(sp))
	}
	tp := sdktrace.NewTracerProvider(tpOpts...)
	rt.tracerProvider = tp
	rt.tracer = tp.Tracer(instrumentationScopeName)
	otel.SetTracerProvider(tp)
	return nil
}

func (rt *TelemetryRuntime) initMeterProvider(
	ctx context.Context,
	cfg config.OTelConfig,
	policy *network.Policy,
	res *resource.Resource,
	headers map[string]string,
	opts RuntimeOptions,
) error {
	var metricReaders []sdkmetric.Reader
	if raw := cfg.ResolvedMetricsEndpoint(); cfg.MetricsEnabled() && raw != "" {
		endpoint, err := validateOTLPEndpoint("otel.metrics.endpoint", raw, "/v1/metrics", policy)
		if err != nil {
			return err
		}
		exp, err := otlpmetrichttp.New(ctx,
			otlpmetrichttp.WithEndpointURL(endpoint),
			otlpmetrichttp.WithHTTPClient(network.NewHTTPClient(policy)),
			otlpmetrichttp.WithHeaders(headers),
		)
		if err != nil {
			return fmt.Errorf("create OTLP metric exporter: %w", err)
		}
		interval := cfg.Metrics.ExportInterval
		if interval <= 0 {
			interval = 60 * time.Second
		}
		metricReaders = append(metricReaders, sdkmetric.NewPeriodicReader(exp, sdkmetric.WithInterval(interval)))
		rt.status.MetricsActive = true
	}
	metricReaders = append(metricReaders, opts.ExtraMetricReaders...)

	mpOpts := []sdkmetric.Option{sdkmetric.WithResource(res)}
	for _, reader := range metricReaders {
		mpOpts = append(mpOpts, sdkmetric.WithReader(reader))
	}
	mp := sdkmetric.NewMeterProvider(mpOpts...)
	rt.meterProvider = mp
	otel.SetMeterProvider(mp)

	inst, err := NewInstruments(mp.Meter(instrumentationScopeName))
	if err != nil {
		return fmt.Errorf("initialize OpenTelemetry metric instruments: %w", err)
	}
	rt.instruments = inst
	return nil
}

func (rt *TelemetryRuntime) initLoggerProvider(
	ctx context.Context,
	cfg config.OTelConfig,
	policy *network.Policy,
	res *resource.Resource,
	headers map[string]string,
	opts RuntimeOptions,
) error {
	var logProcessors []sdklog.Processor
	if raw := cfg.ResolvedLogsEndpoint(); cfg.LogsEnabled() && raw != "" {
		endpoint, err := validateOTLPEndpoint("otel.logs.endpoint", raw, "/v1/logs", policy)
		if err != nil {
			return err
		}
		exp, err := otlploghttp.New(ctx,
			otlploghttp.WithEndpointURL(endpoint),
			otlploghttp.WithHTTPClient(network.NewHTTPClient(policy)),
			otlploghttp.WithHeaders(headers),
		)
		if err != nil {
			return fmt.Errorf("create OTLP log exporter: %w", err)
		}
		logProcessors = append(logProcessors, sdklog.NewBatchProcessor(exp))
		rt.status.LogsActive = true
	}
	logProcessors = append(logProcessors, opts.ExtraLogProcessors...)
	if len(logProcessors) == 0 {
		return nil
	}

	lpOpts := []sdklog.LoggerProviderOption{sdklog.WithResource(res)}
	for _, proc := range logProcessors {
		lpOpts = append(lpOpts, sdklog.WithProcessor(proc))
	}
	lp := sdklog.NewLoggerProvider(lpOpts...)
	rt.loggerProvider = lp
	otel.SetLoggerProvider(lp)
	rt.logHandler = otelslog.NewHandler(instrumentationScopeName, otelslog.WithLoggerProvider(lp))
	return nil
}

// Tracer returns the configured OpenTelemetry tracer (or a no-op tracer when tracing is disabled).
func (rt *TelemetryRuntime) Tracer() trace.Tracer {
	if rt == nil || rt.tracer == nil {
		return noop.NewTracerProvider().Tracer(instrumentationScopeName)
	}
	return rt.tracer
}

// Instruments returns the registered OpenTelemetry metric instruments.
func (rt *TelemetryRuntime) Instruments() *Instruments {
	if rt == nil {
		return nil
	}
	return rt.instruments
}

// LogHandler returns the optional otelslog.Handler for OTLP log fan-out, or nil when OTLP logs are disabled.
func (rt *TelemetryRuntime) LogHandler() slog.Handler {
	if rt == nil {
		return nil
	}
	return rt.logHandler
}

// Status reports which OTLP signals are active.
func (rt *TelemetryRuntime) Status() OTelStatus {
	if rt == nil {
		return OTelStatus{}
	}
	return rt.status
}

// CaptureContent reports whether privacy opt-in prompt/completion capture on spans is enabled.
func (rt *TelemetryRuntime) CaptureContent() bool {
	return rt != nil && rt.captureContent
}

// Shutdown flushes and shuts down all active OpenTelemetry signal providers cleanly.
func (rt *TelemetryRuntime) Shutdown(ctx context.Context) error {
	if rt == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}
	var errs error
	if rt.loggerProvider != nil {
		errs = errors.Join(errs, rt.loggerProvider.Shutdown(ctx))
	}
	if rt.meterProvider != nil {
		errs = errors.Join(errs, rt.meterProvider.Shutdown(ctx))
	}
	if rt.tracerProvider != nil {
		errs = errors.Join(errs, rt.tracerProvider.Shutdown(ctx))
	}
	return errs
}

func validateOTLPEndpoint(field, raw, defaultPath string, policy *network.Policy) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return "", fmt.Errorf("invalid %s", field)
	}
	if u.Path == "" || u.Path == "/" {
		u.Path = defaultPath
	}
	if policy == nil {
		return "", fmt.Errorf("%s requires an outbound network policy", field)
	}
	if err := policy.ValidateURL(u); err != nil {
		return "", fmt.Errorf("%s is blocked by outbound network policy: %w", field, err)
	}
	return u.String(), nil
}

func resolveOTLPSampler(configured string, configuredArg float64) sdktrace.Sampler {
	samplerName := strings.ToLower(strings.TrimSpace(configured))
	if samplerName == "" {
		samplerName = strings.ToLower(strings.TrimSpace(os.Getenv("OTEL_TRACES_SAMPLER")))
	}
	ratio := configuredArg
	if ratio == 0 && samplerName != "traceidratio" && samplerName != "parentbased_traceidratio" {
		ratio = 1.0
	}
	if configured == "" {
		ratio = 1.0
		if rawArg := strings.TrimSpace(os.Getenv("OTEL_TRACES_SAMPLER_ARG")); rawArg != "" {
			if parsed, err := strconv.ParseFloat(rawArg, 64); err == nil && parsed >= 0 && parsed <= 1 {
				ratio = parsed
			}
		}
	}
	switch samplerName {
	case "always_on":
		return sdktrace.AlwaysSample()
	case "always_off":
		return sdktrace.NeverSample()
	case "traceidratio":
		return sdktrace.TraceIDRatioBased(ratio)
	case "parentbased_always_off":
		return sdktrace.ParentBased(sdktrace.NeverSample())
	case "parentbased_traceidratio":
		return sdktrace.ParentBased(sdktrace.TraceIDRatioBased(ratio))
	default:
		return sdktrace.ParentBased(sdktrace.AlwaysSample())
	}
}
