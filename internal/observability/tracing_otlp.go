package observability

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

func NewOTLPTracer(ctx context.Context, cfg config.TracingConfig, policy *network.Policy) (trace.Tracer, func(context.Context) error, error) {
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
	provider := sdktrace.NewTracerProvider(sdktrace.WithBatcher(exporter), sdktrace.WithResource(res))
	return provider.Tracer("github.com/goroute-ai/ai-gateway-go"), provider.Shutdown, nil
}
