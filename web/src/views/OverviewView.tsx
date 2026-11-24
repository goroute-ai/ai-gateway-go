import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { adminApi } from '../api/admin';
import { useAuth } from '../context/AuthContext';
import { Badge } from '../components/common/Badge';
import { Modal, INPUT_CLS, BTN_CANCEL, BTN_ACC, THEAD_CLS } from '../components/common/Modal';
import { ErrorAlert, isPlatformAdminForbidden, ScopedRoleNotice } from '../components/common/ErrorAlert';
import {
  Activity,
  RefreshCw,
  Zap,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Clock,
  Trash2,
} from 'lucide-react';

export const OverviewView: React.FC<{
  onNavigateToPlayground: () => void;
  onNavigateToConfig?: () => void;
}> = ({ onNavigateToPlayground, onNavigateToConfig }) => {
  const { adminKey, isUnlocked, activeOrgId, operator } = useAuth();
  const isPlatformAdmin = operator?.role === 'platform_admin';
  const queryClient = useQueryClient();
  const [showPurgeModal, setShowPurgeModal] = useState(false);
  const [purgeScope, setPurgeScope] = useState<'org' | 'global'>('org');
  const [purgeModel, setPurgeModel] = useState('');
  const [purgeResult, setPurgeResult] = useState<{ purged_entries: number; namespace_version: number } | null>(null);

  // 1. Fetch in-process telemetry snapshot
  const {
    data: telemetry,
    isLoading: isTelemetryLoading,
    isError: isTelemetryError,
    error: telemetryError,
    refetch: refetchTelemetry,
  } = useQuery({
    queryKey: ['admin', 'telemetry', adminKey],
    queryFn: () => adminApi.getTelemetryMetrics(adminKey),
    enabled: isUnlocked,
    refetchInterval: 10000,
  });

  // 2. Fetch deployment health reports
  const {
    data: healthData,
    isLoading: isHealthLoading,
    isError: isHealthError,
    error: healthError,
    refetch: refetchHealth,
  } = useQuery({
    queryKey: ['admin', 'health', adminKey],
    queryFn: () => adminApi.listDeploymentHealth(adminKey),
    enabled: isUnlocked,
    refetchInterval: 15000,
  });

  // Probe mutation
  const probeMutation = useMutation({
    mutationFn: () => adminApi.probeHealth(adminKey),
    onSuccess: (data) => {
      queryClient.setQueryData(['admin', 'health', adminKey], data);
    },
  });

  // Cache invalidate mutation
  const invalidateMutation = useMutation({
    mutationFn: (data: { org_id?: string; model?: string }) => adminApi.invalidateCache(adminKey, data),
    onSuccess: (res) => {
      setPurgeResult(res);
      queryClient.invalidateQueries({ queryKey: ['admin', 'telemetry', adminKey] });
    },
  });

  const handlePurgeSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    invalidateMutation.mutate({
      org_id: purgeScope === 'global' && isPlatformAdmin ? undefined : activeOrgId || undefined,
      model: purgeModel.trim() || undefined,
    });
  };

  const telemetryForbidden = isTelemetryError && isPlatformAdminForbidden(telemetryError);
  const healthForbidden = isHealthError && isPlatformAdminForbidden(healthError);

  return (
    <div className="space-y-6">
      {/* Title & Actions Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-brand-title tracking-tight flex items-center gap-2">
            Telemetry & Upstream Health
          </h1>
          <p className="text-xs text-brand-muted mt-1 flex items-center gap-1.5">
            <Activity className="w-3.5 h-3.5 text-accent-primary animate-pulse" />
            Live sliding-window pod snapshot (latest 1,024 samples) · Cluster telemetry via OTLP
            {telemetry?.generated_at && (
              <span className="font-mono text-[10px]">
                · Updated {new Date(telemetry.generated_at).toLocaleTimeString()}
              </span>
            )}
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => {
              refetchTelemetry();
              refetchHealth();
            }}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-border-subtle hover:border-border-strong bg-surface-elevated text-xs font-medium text-brand-body hover:text-brand-title transition-colors"
          >
            <RefreshCw className="w-3.5 h-3.5 text-brand-muted" />
            <span>Refresh</span>
          </button>

          <button
            onClick={() => probeMutation.mutate()}
            disabled={probeMutation.isPending}
            className={BTN_ACC}
          >
            <Zap className={`w-3.5 h-3.5 ${probeMutation.isPending ? 'animate-spin' : ''}`} />
            <span>{probeMutation.isPending ? 'Probing...' : 'Probe Upstreams'}</span>
          </button>

          <button
            onClick={() => {
              setPurgeResult(null);
              setPurgeScope('org');
              setShowPurgeModal(true);
            }}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-border-subtle hover:border-status-danger/40 bg-surface-elevated hover:bg-status-danger/10 text-xs font-medium text-brand-body hover:text-status-danger transition-colors"
          >
            <Trash2 className="w-3.5 h-3.5" />
            <span>Purge Cache</span>
          </button>

          <button
            onClick={onNavigateToPlayground}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-accent-primary hover:bg-accent-dark text-xs font-semibold text-accent-contrast transition-colors"
          >
            <span>Open Playground ↗</span>
          </button>
        </div>
      </div>

      {/* Error Alerts */}
      {(telemetryForbidden || healthForbidden) && (
        <ScopedRoleNotice subject="telemetry and deployment health" />
      )}
      {isTelemetryError && !telemetryForbidden && (
        <ErrorAlert error={telemetryError} title="Failed to load telemetry metrics" onRetry={() => refetchTelemetry()} />
      )}
      {isHealthError && !healthForbidden && (
        <ErrorAlert error={healthError} title="Failed to load deployment health" onRetry={() => refetchHealth()} />
      )}
      {probeMutation.isError && (
        <ErrorAlert error={probeMutation.error} title="Failed to probe upstream deployments" />
      )}

      {/* KPI Stat Cards Grid */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="p-4 rounded-xl border border-border-subtle bg-surface-base/80">
          <div className="flex items-center justify-between text-brand-muted mb-2">
            <span className="text-xs font-medium">Total Inferences</span>
            <Activity className="w-4 h-4 text-accent-primary" />
          </div>
          <div className="text-2xl font-bold font-mono text-brand-title tracking-tight">
            {isTelemetryLoading ? '...' : telemetry?.total_requests?.toLocaleString() ?? 0}
          </div>
          <div className="text-[11px] text-brand-muted mt-1 flex items-center justify-between">
            <span>Errors: {telemetry?.total_errors ?? 0}</span>
            <span className={(telemetry?.global_error_rate ?? 0) > 0.05 ? 'text-status-danger font-mono' : 'text-status-success font-mono'}>
              {((telemetry?.global_error_rate ?? 0) * 100).toFixed(2)}% err
            </span>
          </div>
        </div>

        <div className="p-4 rounded-xl border border-border-subtle bg-surface-base/80">
          <div className="flex items-center justify-between text-brand-muted mb-2">
            <span className="text-xs font-medium">P95 Latency</span>
            <Clock className="w-4 h-4 text-accent-primary" />
          </div>
          <div className="text-2xl font-bold font-mono text-brand-title tracking-tight">
            {isTelemetryLoading ? '...' : `${telemetry?.p95_latency_ms ?? 0} ms`}
          </div>
          <div className="text-[11px] text-brand-muted mt-1 flex items-center justify-between font-mono">
            <span>Avg: {(telemetry?.avg_latency_ms ?? 0).toFixed(1)} ms</span>
            <span>P50: {telemetry?.p50_latency_ms ?? 0} · P99: {telemetry?.p99_latency_ms ?? 0} ms</span>
          </div>
        </div>

        <div className="p-4 rounded-xl border border-border-subtle bg-surface-base/80">
          <div className="flex items-center justify-between text-brand-muted mb-2">
            <span className="text-xs font-medium">Gateway Routing</span>
            <Activity className="w-4 h-4 text-status-warning" />
          </div>
          <div className="text-2xl font-bold font-mono text-brand-title tracking-tight">
            {isTelemetryLoading ? '...' : `${telemetry?.p95_routing_overhead_micros ?? 0} µs`}
          </div>
          <div className="text-[11px] text-brand-muted font-mono mt-1 flex items-center justify-between">
            <span>Avg: {(telemetry?.avg_routing_overhead_micros ?? 0).toFixed(1)} µs</span>
            {(telemetry?.routing_signal_degraded_total ?? 0) > 0 ? (
              <span className="text-status-warning font-semibold">
                Degraded: {telemetry?.routing_signal_degraded_total}
              </span>
            ) : (
              <span>Fallback: {((telemetry?.fallback_rate ?? 0) * 100).toFixed(1)}%</span>
            )}
          </div>
        </div>

        <div className="p-4 rounded-xl border border-border-subtle bg-surface-base/80">
          <div className="flex items-center justify-between text-brand-muted mb-2 gap-1">
            <span className="text-xs font-medium">Response Cache</span>
            <div className="flex items-center gap-1.5">
              {telemetry?.cache_type && (
                <Badge
                  variant={
                    telemetry.cache_status === 'degraded'
                      ? 'warning'
                      : telemetry.cache_enabled === false
                        ? 'neutral'
                        : 'primary'
                  }
                  size="sm"
                >
                  {telemetry.cache_enabled === false ? 'disabled' : telemetry.cache_type}
                </Badge>
              )}
              {telemetry?.cache_status === 'degraded' ? (
                <AlertTriangle className="w-4 h-4 text-status-warning shrink-0" />
              ) : (
                <CheckCircle2 className="w-4 h-4 text-status-success shrink-0" />
              )}
            </div>
          </div>
          <div className="text-2xl font-bold font-mono text-brand-title tracking-tight">
            {isTelemetryLoading
              ? '...'
              : telemetry?.cache_enabled === false
                ? 'Off'
                : `${((telemetry?.cache_hit_rate ?? 0) * 100).toFixed(1)}%`}
          </div>
          <div className="text-[11px] text-brand-muted mt-1 flex items-center justify-between font-mono">
            <span>
              Hits: {telemetry?.cache_hits ?? 0}
              {(telemetry?.cache_semantic_hits ?? 0) > 0 && ` (sem: ${telemetry?.cache_semantic_hits})`}
            </span>
            <span>Misses: {telemetry?.cache_misses ?? 0}</span>
          </div>
          {(telemetry?.cache_status === 'degraded' ||
            (telemetry?.cache_errors ?? 0) > 0 ||
            (telemetry?.cache_type === 'local' && telemetry?.cache_entries !== undefined)) && (
            <div className="text-[10px] font-mono mt-1 flex items-center justify-between text-brand-muted">
              {telemetry?.cache_status === 'degraded' ? (
                <span className="text-status-warning font-semibold">Cache Redis degraded (fail-open)</span>
              ) : telemetry?.cache_type === 'local' ? (
                <span>
                  Entries: {telemetry?.cache_entries ?? 0}
                  {(telemetry?.cache_evictions ?? 0) > 0 ? ` · Evict: ${telemetry?.cache_evictions}` : ''}
                </span>
              ) : (
                <span />
              )}
              {(telemetry?.cache_errors ?? 0) > 0 && (
                <span className="text-status-warning">Err: {telemetry?.cache_errors}</span>
              )}
            </div>
          )}
        </div>
      </div>

      {/* OTLP & Platform Resilience Status Strip */}
      <div className="p-4 rounded-xl border border-border-subtle bg-surface-base/80 flex flex-wrap items-center justify-between gap-3 text-xs">
        <div className="flex flex-wrap items-center gap-2">
          <button
            type="button"
            onClick={() => onNavigateToConfig?.()}
            disabled={!onNavigateToConfig}
            title="Inspect OpenTelemetry (OTLP) runtime configuration"
            className={onNavigateToConfig ? 'cursor-pointer hover:opacity-85 transition-opacity' : ''}
          >
            <Badge
              variant={
                telemetry?.otel_enabled
                  ? (telemetry.otel_signals?.length ?? 0) > 0
                    ? 'success'
                    : 'warning'
                  : 'neutral'
              }
              size="sm"
            >
              {telemetry?.otel_enabled
                ? (telemetry.otel_signals?.length ?? 0) > 0
                  ? `OTLP: ${telemetry.otel_signals?.join(' · ')}`
                  : 'OTLP: Enabled (No Endpoint)'
                : 'OTLP: Disabled (UI Snapshot Only)'}
            </Badge>
          </button>
          <Badge
            variant={
              (telemetry?.redis_cb_state ?? 0) === 2
                ? 'danger'
                : (telemetry?.redis_cb_state ?? 0) === 1
                  ? 'warning'
                  : 'success'
            }
            size="sm"
          >
            Redis CB: {(telemetry?.redis_cb_state ?? 0) === 2 ? 'Open' : (telemetry?.redis_cb_state ?? 0) === 1 ? 'Half-Open' : 'Closed'}
          </Badge>
          {telemetry?.slowest_provider && (
            <Badge variant="neutral" size="sm">
              Slowest: {telemetry.slowest_provider}
            </Badge>
          )}
          {telemetry?.highest_failure_deployment && (
            <Badge variant="warning" size="sm">
              Top Errors: {telemetry.highest_failure_deployment}
            </Badge>
          )}
        </div>
        <div className="flex flex-wrap items-center gap-x-4 gap-y-1 font-mono text-[11px] text-brand-muted">
          <span>
            TTFT: <strong className="text-brand-title">{(telemetry?.avg_ttft_ms ?? 0).toFixed(0)} / {telemetry?.p95_ttft_ms ?? 0} ms</strong>
          </span>
          {(telemetry?.stream_requests ?? 0) > 0 && (
            <span>
              Streams:{' '}
              <strong className={(telemetry?.stream_errors ?? 0) > 0 ? 'text-status-warning' : 'text-brand-title'}>
                {telemetry?.stream_requests}
                {(telemetry?.stream_errors ?? 0) > 0 ? ` (${telemetry?.stream_errors} err)` : ''}
              </strong>
            </span>
          )}
          <span>Fallbacks: <strong className="text-brand-title">{telemetry?.total_fallbacks ?? 0}</strong></span>
          <span>Retries: <strong className="text-brand-title">{telemetry?.total_retries ?? 0}</strong></span>
          <span>429s: <strong className="text-brand-title">{telemetry?.rate_limit_rejections ?? 0}</strong></span>
          <span>Guardrail Blocks: <strong className="text-brand-title">{telemetry?.guardrail_blocks ?? 0}</strong></span>
          <span>Redactions: <strong className="text-brand-title">{telemetry?.guardrail_redactions ?? 0}</strong></span>
          <span>
            Outbox:{' '}
            <strong
              className={
                (telemetry?.finops_outbox_dead_letter ?? 0) > 0
                  ? 'text-status-danger'
                  : (telemetry?.finops_outbox_backpressure ?? 0) > 0
                    ? 'text-status-warning'
                    : 'text-brand-title'
              }
            >
              {telemetry?.finops_outbox_pending ?? 0} pending
              {(telemetry?.finops_outbox_dead_letter ?? 0) > 0 ? ` (${telemetry?.finops_outbox_dead_letter} DLQ)` : ''}
              {(telemetry?.finops_outbox_backpressure ?? 0) > 0 ? ` · ${telemetry?.finops_outbox_backpressure} bp` : ''}
            </strong>
          </span>
          {(telemetry?.spend_redis_drift_total ?? 0) > 0 && (
            <span>
              Redis Drift: <strong className="text-status-warning">{telemetry?.spend_redis_drift_total}</strong>
            </span>
          )}
          {((telemetry?.audit_siem_delivered ?? 0) > 0 ||
            (telemetry?.audit_siem_failed ?? 0) > 0 ||
            (telemetry?.audit_siem_dropped ?? 0) > 0) && (
            <span>
              SIEM:{' '}
              <strong
                className={
                  (telemetry?.audit_siem_failed ?? 0) > 0 || (telemetry?.audit_siem_dropped ?? 0) > 0
                    ? 'text-status-warning'
                    : 'text-brand-title'
                }
              >
                {telemetry?.audit_siem_delivered ?? 0} ok / {telemetry?.audit_siem_failed ?? 0} err
                {(telemetry?.audit_siem_dropped ?? 0) > 0 ? ` / ${telemetry?.audit_siem_dropped} drop` : ''}
              </strong>
            </span>
          )}
        </div>
      </div>

      {/* Per-Provider Telemetry Breakdown */}
      {telemetry?.providers && Object.keys(telemetry.providers).length > 0 && (
        <div className="rounded-xl border border-border-subtle bg-surface-base/90 overflow-hidden">
          <div className="px-6 py-4 border-b border-border-subtle flex items-center justify-between bg-surface-elevated/30">
            <div>
              <h2 className="text-sm font-semibold text-brand-title">Provider Telemetry</h2>
              <p className="text-xs text-brand-muted mt-0.5">
                Per-provider request volume, latency percentiles, TTFT, tokens, and spend on this pod
              </p>
            </div>
            <div className="text-xs text-brand-muted font-mono">
              Active providers: {Object.keys(telemetry.providers).length}
            </div>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className={THEAD_CLS}>
                <tr>
                  <th className="px-6 py-3">Provider</th>
                  <th className="px-6 py-3">Requests</th>
                  <th className="px-6 py-3">Error Rate</th>
                  <th className="px-6 py-3">Avg / P95 / P99</th>
                  <th className="px-6 py-3">Avg TTFT</th>
                  <th className="px-6 py-3">Tokens</th>
                  <th className="px-6 py-3">Spend (USD)</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border-subtle/40">
                {Object.values(telemetry.providers)
                  .sort((a, b) => b.total_requests - a.total_requests)
                  .map((p) => (
                    <tr key={p.provider} className="hover:bg-surface-hover/30 transition-colors">
                      <td className="px-6 py-3">
                        <Badge variant="provider" provider={p.provider} size="sm">
                          {p.provider}
                        </Badge>
                      </td>
                      <td className="px-6 py-3 font-mono text-brand-title">{p.total_requests.toLocaleString()}</td>
                      <td className="px-6 py-3 font-mono">
                        <span className={p.error_rate > 0.05 ? 'text-status-danger' : 'text-status-success'}>
                          {(p.error_rate * 100).toFixed(2)}% ({p.error_count})
                        </span>
                      </td>
                      <td className="px-6 py-3 font-mono text-brand-body">
                        {p.avg_latency_ms.toFixed(0)} / {p.p95_latency_ms} / {p.p99_latency_ms} ms
                      </td>
                      <td className="px-6 py-3 font-mono text-brand-muted">{p.avg_ttft_ms.toFixed(0)} ms</td>
                      <td className="px-6 py-3 font-mono text-brand-body">{p.total_tokens.toLocaleString()}</td>
                      <td className="px-6 py-3 font-mono text-brand-title">
                        ${(p.total_cost_micros / 1_000_000).toFixed(4)}
                      </td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Deployment Health & Live Traffic Grid */}
      {(() => {
        const probed = healthData?.data ?? [];
        const liveMap = telemetry?.deployments ?? {};
        const seenIds = new Set(probed.map((h) => h.deployment_id));
        const liveOnly = Object.values(liveMap).filter((d) => !seenIds.has(d.deployment_id));
        const totalRows = probed.length + liveOnly.length;

        return (
          <div className="rounded-xl border border-border-subtle bg-surface-base/90 overflow-hidden">
            <div className="px-6 py-4 border-b border-border-subtle flex items-center justify-between bg-surface-elevated/30">
              <div>
                <h2 className="text-sm font-semibold text-brand-title">Upstream Deployment Health & Live Traffic</h2>
                <p className="text-xs text-brand-muted mt-0.5">
                  Synthetic liveness probes merged with sliding-window pod traffic per deployment
                </p>
              </div>
              <div className="text-xs text-brand-muted font-mono">
                Deployments monitored: {totalRows}
              </div>
            </div>

            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className={THEAD_CLS}>
                  <tr>
                    <th className="px-6 py-3">Deployment</th>
                    <th className="px-6 py-3">Provider & Model</th>
                    <th className="px-6 py-3">Probe Status</th>
                    <th className="px-6 py-3">Probe / Fails</th>
                    <th className="px-6 py-3">Live Reqs / Err%</th>
                    <th className="px-6 py-3">Live P95 / Avg</th>
                    <th className="px-6 py-3">Last Checked</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border-subtle/40">
                  {isHealthLoading ? (
                    <tr>
                      <td colSpan={7} className="px-6 py-8 text-center text-brand-muted">
                        Loading health reports...
                      </td>
                    </tr>
                  ) : totalRows > 0 ? (
                    <>
                      {probed.map((h) => {
                        const live = liveMap[h.deployment_id];
                        return (
                          <tr key={h.deployment_id} className="hover:bg-surface-hover/30 transition-colors">
                            <td className="px-6 py-3 font-medium text-brand-title">
                              <div>{h.deployment_name || h.deployment_id}</div>
                              <div className="text-[10px] font-mono text-brand-muted">{h.deployment_id}</div>
                            </td>
                            <td className="px-6 py-3">
                              <div className="flex items-center gap-1.5">
                                <Badge variant="provider" provider={h.provider} size="sm">
                                  {h.provider}
                                </Badge>
                                <span className="font-mono text-brand-body">{h.model}</span>
                              </div>
                            </td>
                            <td className="px-6 py-3">
                              {h.status === 'healthy' ? (
                                <span className="inline-flex items-center gap-1.5 text-status-success font-medium">
                                  <CheckCircle2 className="w-3.5 h-3.5" />
                                  Healthy
                                </span>
                              ) : h.status === 'degraded' ? (
                                <span className="inline-flex items-center gap-1.5 text-status-warning font-medium">
                                  <AlertTriangle className="w-3.5 h-3.5" />
                                  Degraded
                                </span>
                              ) : (
                                <span className="inline-flex items-center gap-1.5 text-status-danger font-medium">
                                  <XCircle className="w-3.5 h-3.5" />
                                  Unhealthy
                                </span>
                              )}
                              {h.last_error && (
                                <div className="text-[10px] text-status-danger font-mono mt-0.5 max-w-xs truncate" title={h.last_error}>
                                  {h.last_error}
                                </div>
                              )}
                            </td>
                            <td className="px-6 py-3 font-mono text-brand-body">
                              <span>{h.probe_latency_ms} ms</span>
                              <span className={h.consecutive_failures > 0 ? ' text-status-danger font-bold' : ' text-brand-muted'}>
                                {' '}· {h.consecutive_failures} fail
                              </span>
                            </td>
                            <td className="px-6 py-3 font-mono">
                              {live ? (
                                <span>
                                  <span className="text-brand-title">{live.total_requests.toLocaleString()}</span>
                                  {' · '}
                                  <span className={live.error_rate > 0.05 ? 'text-status-danger' : 'text-status-success'}>
                                    {(live.error_rate * 100).toFixed(1)}%
                                  </span>
                                </span>
                              ) : (
                                <span className="text-brand-muted">—</span>
                              )}
                            </td>
                            <td className="px-6 py-3 font-mono text-brand-body">
                              {live ? `${live.p95_latency_ms} / ${live.avg_latency_ms.toFixed(0)} ms` : <span className="text-brand-muted">—</span>}
                            </td>
                            <td className="px-6 py-3 font-mono text-brand-muted text-[11px]">
                              {new Date(h.last_checked_at).toLocaleTimeString()}
                            </td>
                          </tr>
                        );
                      })}
                      {liveOnly.map((live) => (
                        <tr key={live.deployment_id} className="hover:bg-surface-hover/30 transition-colors">
                          <td className="px-6 py-3 font-medium text-brand-title">
                            <div>{live.deployment_name || live.deployment_id}</div>
                            <div className="text-[10px] font-mono text-brand-muted">{live.deployment_id}</div>
                          </td>
                          <td className="px-6 py-3">
                            <div className="flex items-center gap-1.5">
                              <Badge variant="provider" provider={live.provider} size="sm">
                                {live.provider}
                              </Badge>
                              <span className="font-mono text-brand-body">{live.model}</span>
                            </div>
                          </td>
                          <td className="px-6 py-3">
                            <Badge variant="neutral" size="sm">Traffic Only</Badge>
                          </td>
                          <td className="px-6 py-3 font-mono text-brand-muted">—</td>
                          <td className="px-6 py-3 font-mono">
                            <span className="text-brand-title">{live.total_requests.toLocaleString()}</span>
                            {' · '}
                            <span className={live.error_rate > 0.05 ? 'text-status-danger' : 'text-status-success'}>
                              {(live.error_rate * 100).toFixed(1)}%
                            </span>
                          </td>
                          <td className="px-6 py-3 font-mono text-brand-body">
                            {live.p95_latency_ms} / {live.avg_latency_ms.toFixed(0)} ms
                          </td>
                          <td className="px-6 py-3 font-mono text-brand-muted text-[11px]">—</td>
                        </tr>
                      ))}
                    </>
                  ) : (
                    <tr>
                      <td colSpan={7} className="px-6 py-8 text-center text-brand-muted">
                        No deployments configured or probed yet. Click "Probe Upstreams" to trigger health checks.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        );
      })()}

      {/* Cache Purge Modal */}
      <Modal
        isOpen={showPurgeModal}
        onClose={() => setShowPurgeModal(false)}
        title="Invalidate Response Cache"
        description="Purges cached responses from the active cache backend (local, Redis KV, or Redis semantic vector cache)."
        maxWidth="md"
      >
        <form onSubmit={handlePurgeSubmit} className="space-y-4">
          {invalidateMutation.isError && (
            <ErrorAlert error={invalidateMutation.error} title="Failed to purge response cache" />
          )}
          <div>
            <label className="block text-xs font-medium text-brand-body mb-1">
              Invalidation Scope
            </label>
            <select
              aria-label="Invalidation Scope"
              value={purgeScope}
              onChange={(e) => setPurgeScope(e.target.value as 'org' | 'global')}
              className={`${INPUT_CLS} font-mono`}
            >
              <option value="org">Current Organization ({activeOrgId})</option>
              {isPlatformAdmin && <option value="global">All Organizations (Global)</option>}
            </select>
            {purgeScope === 'global' && isPlatformAdmin && (
              <p className="text-[11px] text-status-warning mt-1">
                Purges cached responses across every organization on this gateway cluster.
              </p>
            )}
          </div>

          <div>
            <label className="block text-xs font-medium text-brand-body mb-1">
              Target Model (Optional)
            </label>
            <input
              type="text"
              value={purgeModel}
              onChange={(e) => setPurgeModel(e.target.value)}
              placeholder="e.g. gpt-4o (Leave blank to purge all models)"
              className={`${INPUT_CLS} font-mono`}
            />
          </div>

          {purgeResult && (
            <div className="p-3 rounded-lg status-success border text-xs font-mono">
              ✓ Cache purged successfully! Entries purged: {purgeResult.purged_entries}, Invalidation revision: {purgeResult.namespace_version}
            </div>
          )}

          <div className="flex justify-end gap-2 pt-2">
            <button
              type="button"
              onClick={() => setShowPurgeModal(false)}
              className={BTN_CANCEL}
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={invalidateMutation.isPending}
              className="px-4 py-1.5 rounded-md text-xs font-medium bg-rose-600 hover:bg-rose-500 text-white transition-colors disabled:opacity-50"
            >
              {invalidateMutation.isPending ? 'Purging...' : 'Confirm Purge'}
            </button>
          </div>
        </form>
      </Modal>
    </div>
  );
};
