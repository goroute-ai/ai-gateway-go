package observability

import (
	"context"

	"github.com/goroute-ai/ai-gateway-go/internal/config"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

func resolveOTLPSamplerFromEnv() sdktrace.Sampler {
	return resolveOTLPSampler("", 1.0)
}

// NewOTLPTracer creates an OTLP/HTTP tracer configured from legacy TracingConfig and validated against policy.
func NewOTLPTracer(ctx context.Context, cfg config.TracingConfig, policy *network.Policy) (trace.Tracer, func(context.Context) error, error) {
	return NewOTLPTracerWithSampler(ctx, cfg, policy, resolveOTLPSamplerFromEnv())
}

// NewOTLPTracerWithSampler creates an OTLP/HTTP tracer with an explicit sampler.
// Export is strictly disabled unless cfg.Enabled is true and cfg.OTLPEndpoint is non-empty.
func NewOTLPTracerWithSampler(ctx context.Context, cfg config.TracingConfig, policy *network.Policy, sampler sdktrace.Sampler) (trace.Tracer, func(context.Context) error, error) {
	metricsDisabled := false
	otelCfg := config.OTelConfig{
		Enabled:     cfg.Enabled,
		Endpoint:    cfg.OTLPEndpoint,
		ServiceName: cfg.ServiceName,
		Headers:     cfg.Headers,
		Metrics: config.OTelMetricsConfig{
			Enabled: &metricsDisabled,
		},
	}
	rt, err := NewTelemetryRuntime(ctx, otelCfg, policy, RuntimeOptions{Sampler: sampler})
	if err != nil {
		return nil, nil, err
	}
	return rt.Tracer(), rt.Shutdown, nil
}
