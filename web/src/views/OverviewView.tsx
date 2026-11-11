import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { adminApi } from '../api/admin';
import { useAuth } from '../context/AuthContext';
import { Badge } from '../components/common/Badge';
import { Modal } from '../components/common/Modal';
import {
  Activity,
  RefreshCw,
  Zap,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Clock,
  Trash2,
  Radio,
  Cpu,
} from 'lucide-react';

export const OverviewView: React.FC<{ onNavigateToPlayground: () => void }> = ({ onNavigateToPlayground }) => {
  const { adminKey, activeOrgId } = useAuth();
  const queryClient = useQueryClient();
  const [showPurgeModal, setShowPurgeModal] = useState(false);
  const [purgeModel, setPurgeModel] = useState('');
  const [purgeResult, setPurgeResult] = useState<{ purged_entries: number; namespace_version: number } | null>(null);

  // 1. Fetch in-process telemetry snapshot
  const {
    data: telemetry,
    isLoading: isTelemetryLoading,
    refetch: refetchTelemetry,
  } = useQuery({
    queryKey: ['admin', 'telemetry', adminKey],
    queryFn: () => adminApi.getTelemetryMetrics(adminKey),
    enabled: !!adminKey,
    refetchInterval: 10000,
  });

  // 2. Fetch deployment health reports
  const {
    data: healthData,
    isLoading: isHealthLoading,
    refetch: refetchHealth,
  } = useQuery({
    queryKey: ['admin', 'health', adminKey],
    queryFn: () => adminApi.listDeploymentHealth(adminKey),
    enabled: !!adminKey,
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
      org_id: activeOrgId !== 'org_default' ? activeOrgId : undefined,
      model: purgeModel.trim() || undefined,
    });
  };

  return (
    <div className="space-y-6">
      {/* Title & Actions Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-white tracking-tight flex items-center gap-2">
            Telemetry & Upstream Health
          </h1>
          <p className="text-xs text-slate-400 mt-1 flex items-center gap-1.5">
            <Radio className="w-3.5 h-3.5 text-accent-primary animate-pulse" />
            Live in-process reservoir snapshot generated since gateway launch
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => {
              refetchTelemetry();
              refetchHealth();
            }}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-border-subtle hover:border-border-strong bg-surface-elevated text-xs font-medium text-slate-300 hover:text-white transition-colors"
          >
            <RefreshCw className="w-3.5 h-3.5 text-slate-400" />
            <span>Refresh</span>
          </button>

          <button
            onClick={() => probeMutation.mutate()}
            disabled={probeMutation.isPending}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-cyan-500/30 bg-cyan-950/40 hover:bg-cyan-900/50 text-xs font-medium text-cyan-300 transition-colors disabled:opacity-50"
          >
            <Zap className={`w-3.5 h-3.5 ${probeMutation.isPending ? 'animate-spin' : ''}`} />
            <span>{probeMutation.isPending ? 'Probing...' : 'Probe Upstreams'}</span>
          </button>

          <button
            onClick={() => {
              setPurgeResult(null);
              setShowPurgeModal(true);
            }}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-border-subtle hover:border-rose-500/30 bg-surface-elevated hover:bg-rose-950/30 text-xs font-medium text-slate-300 hover:text-rose-400 transition-colors"
          >
            <Trash2 className="w-3.5 h-3.5" />
            <span>Purge Cache</span>
          </button>

          <button
            onClick={onNavigateToPlayground}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-accent-primary hover:bg-accent-glow text-xs font-semibold text-black transition-colors"
          >
            <span>Open Playground ↗</span>
          </button>
        </div>
      </div>

      {/* KPI Stat Cards Grid */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="p-4 rounded-xl border border-border-subtle bg-surface-base/80">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-medium">Total Inferences</span>
            <Activity className="w-4 h-4 text-cyan-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-white tracking-tight">
            {isTelemetryLoading ? '...' : telemetry?.total_requests?.toLocaleString() ?? 0}
          </div>
          <div className="text-[11px] text-slate-500 mt-1 flex items-center justify-between">
            <span>Errors: {telemetry?.total_errors ?? 0}</span>
            <span className={(telemetry?.global_error_rate ?? 0) > 0.05 ? 'text-rose-400' : 'text-emerald-400 font-mono'}>
              {((telemetry?.global_error_rate ?? 0) * 100).toFixed(2)}% err
            </span>
          </div>
        </div>

        <div className="p-4 rounded-xl border border-border-subtle bg-surface-base/80">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-medium">P95 Latency</span>
            <Clock className="w-4 h-4 text-indigo-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-white tracking-tight">
            {isTelemetryLoading ? '...' : `${telemetry?.p95_latency_ms ?? 0} ms`}
          </div>
          <div className="text-[11px] text-slate-500 mt-1 flex items-center justify-between font-mono">
            <span>Avg: {(telemetry?.avg_latency_ms ?? 0).toFixed(1)} ms</span>
            <span>P50: {telemetry?.p50_latency_ms ?? 0} ms</span>
          </div>
        </div>

        <div className="p-4 rounded-xl border border-border-subtle bg-surface-base/80">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-medium">Gateway Routing</span>
            <Cpu className="w-4 h-4 text-amber-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-white tracking-tight">
            {isTelemetryLoading ? '...' : `${telemetry?.p95_routing_overhead_micros ?? 0} µs`}
          </div>
          <div className="text-[11px] text-emerald-400 font-mono mt-1">
            Avg: {(telemetry?.avg_routing_overhead_micros ?? 0).toFixed(1)} µs (&lt; 0.1ms)
          </div>
        </div>

        <div className="p-4 rounded-xl border border-border-subtle bg-surface-base/80">
          <div className="flex items-center justify-between text-slate-400 mb-2">
            <span className="text-xs font-medium">Exact Response Cache</span>
            <CheckCircle2 className="w-4 h-4 text-emerald-400" />
          </div>
          <div className="text-2xl font-bold font-mono text-white tracking-tight">
            {isTelemetryLoading ? '...' : `${((telemetry?.cache_hit_rate ?? 0) * 100).toFixed(1)}%`}
          </div>
          <div className="text-[11px] text-slate-500 mt-1 flex items-center justify-between font-mono">
            <span>Hits: {telemetry?.cache_hits ?? 0}</span>
            <span>Misses: {telemetry?.cache_misses ?? 0}</span>
          </div>
        </div>
      </div>

      {/* Deployment Health Reports Grid */}
      <div className="rounded-xl border border-border-subtle bg-surface-base/90 overflow-hidden">
        <div className="px-6 py-4 border-b border-border-subtle flex items-center justify-between bg-surface-elevated/30">
          <div>
            <h2 className="text-sm font-semibold text-white">Upstream Deployment Health Status</h2>
            <p className="text-xs text-slate-400 mt-0.5">
              Synthetic probe health reports from background liveness monitor
            </p>
          </div>
          <div className="text-xs text-slate-400 font-mono">
            Deployments monitored: {healthData?.data?.length ?? 0}
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-surface-elevated/60 text-slate-400 uppercase text-[10px] tracking-wider border-b border-border-subtle">
              <tr>
                <th className="px-6 py-3">Deployment</th>
                <th className="px-6 py-3">Provider & Model</th>
                <th className="px-6 py-3">Probe Status</th>
                <th className="px-6 py-3">Probe Latency</th>
                <th className="px-6 py-3">Consecutive Failures</th>
                <th className="px-6 py-3">Last Checked</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border-subtle/40">
              {isHealthLoading ? (
                <tr>
                  <td colSpan={6} className="px-6 py-8 text-center text-slate-500">
                    Loading health reports...
                  </td>
                </tr>
              ) : healthData?.data && healthData.data.length > 0 ? (
                healthData.data.map((h) => (
                  <tr key={h.deployment_id} className="hover:bg-surface-hover/30 transition-colors">
                    <td className="px-6 py-3 font-medium text-slate-200">
                      <div>{h.deployment_name || h.deployment_id}</div>
                      <div className="text-[10px] font-mono text-slate-500">{h.deployment_id}</div>
                    </td>
                    <td className="px-6 py-3">
                      <div className="flex items-center gap-1.5">
                        <Badge variant="provider" provider={h.provider} size="sm">
                          {h.provider}
                        </Badge>
                        <span className="font-mono text-slate-300">{h.model}</span>
                      </div>
                    </td>
                    <td className="px-6 py-3">
                      {h.status === 'healthy' ? (
                        <span className="inline-flex items-center gap-1.5 text-emerald-400 font-medium">
                          <CheckCircle2 className="w-3.5 h-3.5" />
                          Healthy
                        </span>
                      ) : h.status === 'degraded' ? (
                        <span className="inline-flex items-center gap-1.5 text-amber-400 font-medium">
                          <AlertTriangle className="w-3.5 h-3.5" />
                          Degraded
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1.5 text-rose-400 font-medium">
                          <XCircle className="w-3.5 h-3.5" />
                          Unhealthy
                        </span>
                      )}
                      {h.last_error && (
                        <div className="text-[10px] text-rose-400 font-mono mt-0.5 max-w-xs truncate" title={h.last_error}>
                          {h.last_error}
                        </div>
                      )}
                    </td>
                    <td className="px-6 py-3 font-mono text-slate-300">
                      {h.probe_latency_ms} ms
                    </td>
                    <td className="px-6 py-3 font-mono">
                      <span className={h.consecutive_failures > 0 ? 'text-rose-400 font-bold' : 'text-slate-400'}>
                        {h.consecutive_failures}
                      </span>
                    </td>
                    <td className="px-6 py-3 font-mono text-slate-500 text-[11px]">
                      {new Date(h.last_checked_at).toLocaleTimeString()}
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={6} className="px-6 py-8 text-center text-slate-500">
                    No deployments configured or probed yet. Click "Probe Upstreams" to trigger health checks.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Cache Purge Modal */}
      <Modal
        isOpen={showPurgeModal}
        onClose={() => setShowPurgeModal(false)}
        title="Invalidate Response Cache"
        description="Purges cached exact-match completions and increments the cache epoch namespace version across the cluster."
        maxWidth="md"
      >
        <form onSubmit={handlePurgeSubmit} className="space-y-4">
          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">
              Target Model (Optional)
            </label>
            <input
              type="text"
              value={purgeModel}
              onChange={(e) => setPurgeModel(e.target.value)}
              placeholder="e.g. gpt-4o (Leave blank to purge all models)"
              className="w-full bg-black/60 border border-border-strong rounded-lg px-3 py-2 text-xs font-mono text-slate-200 placeholder-slate-600 focus:outline-none focus:border-accent-primary"
            />
          </div>

          {purgeResult && (
            <div className="p-3 rounded-lg bg-emerald-950/40 border border-emerald-500/30 text-xs text-emerald-400 font-mono">
              ✓ Cache purged successfully! Entries purged: {purgeResult.purged_entries}, New epoch version: {purgeResult.namespace_version}
            </div>
          )}

          <div className="flex justify-end gap-2 pt-2">
            <button
              type="button"
              onClick={() => setShowPurgeModal(false)}
              className="px-3 py-1.5 rounded-md text-xs text-slate-400 hover:text-slate-200 hover:bg-surface-elevated transition-colors"
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
