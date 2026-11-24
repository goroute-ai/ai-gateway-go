package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestOTelConfigLegacyTracingAliasAndEnvOverrides(t *testing.T) {
	t.Setenv("TEST_OTEL_TOKEN", "resolved-otel-secret")
	t.Setenv("TEST_SIEM_SECRET", "resolved-siem-secret")

	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "config.yaml")
	yamlBody := `
server:
  environment: "development"
tracing:
  enabled: true
  otlp_endpoint: "https://collector.example.com:4318/v1/traces"
  service_name: "legacy-gateway"
  headers:
    Authorization: "os.environ/TEST_OTEL_TOKEN"
audit:
  siem_webhook:
    enabled: true
    url: "https://siem.example.com/events"
    secret: "os.environ/TEST_SIEM_SECRET"
`
	if err := os.WriteFile(cfgPath, []byte(yamlBody), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := Load(cfgPath)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !cfg.OTel.Enabled || !cfg.OTel.TracesEnabled() || !cfg.OTel.MetricsEnabled() || cfg.OTel.LogsEnabled() {
		t.Fatalf("unexpected OTel flags: %+v", cfg.OTel)
	}
	if cfg.OTel.ServiceName != "legacy-gateway" {
		t.Fatalf("expected service_name legacy-gateway, got %q", cfg.OTel.ServiceName)
	}
	if cfg.OTel.Headers["Authorization"] != "resolved-otel-secret" {
		t.Fatalf("expected resolved OTel header, got %q", cfg.OTel.Headers["Authorization"])
	}
	if cfg.OTel.ResolvedMetricsEndpoint() != "https://collector.example.com:4318/v1/metrics" {
		t.Fatalf("unexpected metrics endpoint: %q", cfg.OTel.ResolvedMetricsEndpoint())
	}
	if cfg.Audit.SIEMWebhook.Secret != "resolved-siem-secret" {
		t.Fatalf("expected resolved SIEM secret, got %q", cfg.Audit.SIEMWebhook.Secret)
	}

	// Standard OTEL_* + GATEWAY_OTEL_* + GATEWAY_HEALTH_PROBE_* overrides
	t.Setenv("GATEWAY_ENV", "development")
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "https://otel-env.example.com:4318")
	t.Setenv("OTEL_METRIC_EXPORT_INTERVAL", "15000")
	t.Setenv("GATEWAY_OTEL_ENABLED", "true")
	t.Setenv("GATEWAY_OTEL_LOGS_ENABLED", "true")
	t.Setenv("GATEWAY_OTEL_TRACES_SAMPLER", "traceidratio")
	t.Setenv("GATEWAY_OTEL_TRACES_SAMPLER_ARG", "0.5")
	t.Setenv("GATEWAY_HEALTH_PROBE_ENABLED", "false")
	t.Setenv("GATEWAY_HEALTH_PROBE_INTERVAL", "30s")

	cfgEnv, err := Load("")
	if err != nil {
		t.Fatalf("Load env: %v", err)
	}
	if !cfgEnv.OTel.LogsEnabled() || cfgEnv.OTel.Metrics.ExportInterval != 15*time.Second {
		t.Fatalf("unexpected env OTel config: %+v", cfgEnv.OTel)
	}
	if cfgEnv.OTel.ResolvedLogsEndpoint() != "https://otel-env.example.com:4318/v1/logs" {
		t.Fatalf("unexpected logs endpoint: %q", cfgEnv.OTel.ResolvedLogsEndpoint())
	}
	if cfgEnv.Health.IsProbeEnabled() || cfgEnv.Health.ProbeInterval != 30*time.Second {
		t.Fatalf("unexpected health probe config: %+v", cfgEnv.Health)
	}
}

func TestOTelConfigRejectsUnresolvedHeaderAndInvalidSampler(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "bad-otel.yaml")
	if err := os.WriteFile(cfgPath, []byte(`
server:
  environment: "development"
otel:
  enabled: true
  endpoint: "https://collector.example.com:4318"
  headers:
    Authorization: "os.environ/MISSING_OTEL_TOKEN_FOR_TEST"
`), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if _, err := Load(cfgPath); err == nil {
		t.Fatal("expected Load to fail closed on unresolved os.environ/ in otel.headers")
	}

	cfg2 := Default()
	cfg2.OTel.Traces.Sampler = "bogus_sampler"
	if err := cfg2.Validate(); err == nil {
		t.Fatal("expected invalid otel.traces.sampler to fail validation")
	}
}
