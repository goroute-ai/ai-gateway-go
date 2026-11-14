package observability

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

func resolveOTLPSamplerFromEnv() sdktrace.Sampler {
	samplerName := strings.ToLower(strings.TrimSpace(os.Getenv("OTEL_TRACES_SAMPLER")))
	ratio := 1.0
	if rawArg := strings.TrimSpace(os.Getenv("OTEL_TRACES_SAMPLER_ARG")); rawArg != "" {
		if parsed, err := strconv.ParseFloat(rawArg, 64); err == nil && parsed >= 0 && parsed <= 1 {
			ratio = parsed
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

func NewOTLPTracer(ctx context.Context, cfg config.TracingConfig, policy *network.Policy) (trace.Tracer, func(context.Context) error, error) {
	return NewOTLPTracerWithSampler(ctx, cfg, policy, resolveOTLPSamplerFromEnv())
}

func NewOTLPTracerWithSampler(ctx context.Context, cfg config.TracingConfig, policy *network.Policy, sampler sdktrace.Sampler) (trace.Tracer, func(context.Context) error, error) {
	if sampler == nil {
		sampler = resolveOTLPSamplerFromEnv()
	}
	if strings.TrimSpace(cfg.OTLPEndpoint) == "" {
		return trace.NewNoopTracerProvider().Tracer("ai-gateway-go"), func(context.Context) error { return nil }, nil
	}
	endpoint, err := url.Parse(strings.TrimSpace(cfg.OTLPEndpoint))
	if err != nil || endpoint.Host == "" {
		return nil, nil, fmt.Errorf("invalid tracing.otlp_endpoint")
	}
	if endpoint.Path == "" || endpoint.Path == "/" {
		endpoint.Path = "/v1/traces"
	}
	if policy == nil {
		return nil, nil, fmt.Errorf("tracing.otlp_endpoint requires an outbound network policy")
	}
	if err := policy.ValidateURL(endpoint); err != nil {
		return nil, nil, fmt.Errorf("tracing.otlp_endpoint is blocked by outbound network policy: %w", err)
	}

	exporter, err := otlptracehttp.New(ctx,
		otlptracehttp.WithEndpointURL(endpoint.String()),
		otlptracehttp.WithHTTPClient(network.NewHTTPClient(policy)),
		otlptracehttp.WithHeaders(cfg.Headers),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("create OTLP trace exporter: %w", err)
	}
	serviceName := strings.TrimSpace(cfg.ServiceName)
	if serviceName == "" {
		serviceName = "ai-gateway-go"
	}
	res, err := resource.New(ctx, resource.WithAttributes(attribute.String("service.name", serviceName)))
	if err != nil {
		_ = exporter.Shutdown(ctx)
		return nil, nil, fmt.Errorf("create tracing resource: %w", err)
	}
	provider := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sampler),
	)
	return provider.Tracer("github.com/goroute-ai/ai-gateway-go"), provider.Shutdown, nil
}
