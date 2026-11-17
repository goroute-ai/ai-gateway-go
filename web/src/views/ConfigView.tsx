import React, { useState } from 'react';
import { useQuery } from '@tanstack/react-query';
import { Settings, ShieldCheck, RefreshCw, Lock } from 'lucide-react';
import { adminApi } from '../api/admin';
import { useAuth } from '../context/AuthContext';
import { ErrorAlert, isPlatformAdminForbidden, ScopedRoleNotice } from '../components/common/ErrorAlert';
import { Badge } from '../components/common/Badge';
import type { GatewayConfig } from '../types';

const SECTIONS: [string, string][] = [
  ['server', 'Server & Transport'], ['logging', 'Logging'], ['tracing', 'Tracing'],
  ['security', 'Network Security'], ['storage', 'Storage & Redis'], ['auth', 'Authentication'],
  ['router', 'Router & Reliability'], ['rate_limit', 'Rate Limits'], ['finops', 'FinOps Accounting'],
  ['discovery', 'Model Discovery'], ['cache', 'Response Cache'], ['guardrails', 'Guardrails'],
  ['mcp', 'MCP Protocol'], ['a2a', 'A2A Agents'], ['providers', 'Providers'], ['model_list', 'Static Models'],
];

function formatKey(key: string): string {
  return key.replace(/_/g, ' ');
}

function isRedactedValue(val: unknown): boolean {
  if (typeof val !== 'string') return false;
  const upper = val.toUpperCase();
  return upper.includes('REDACTED') || val === '***' || val === '********';
}

const ConfigValue: React.FC<{ value: unknown }> = ({ value }) => {
  if (value === null || value === undefined || value === '') {
    return <span className="text-brand-muted italic">—</span>;
  }
  if (typeof value === 'boolean') {
    return (
      <Badge variant={value ? 'success' : 'neutral'}>
        {value ? 'enabled' : 'disabled'}
      </Badge>
    );
  }
  if (typeof value === 'number') {
    return <span className="text-brand-title font-mono">{value.toLocaleString()}</span>;
  }
  if (typeof value === 'string') {
    if (isRedactedValue(value)) {
      return (
        <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded border status-warning font-mono text-[10px]">
          <Lock className="w-2.5 h-2.5" />
          {value}
        </span>
      );
    }
    return <span className="text-brand-title font-mono break-all">{value}</span>;
  }
  if (Array.isArray(value)) {
    if (value.length === 0) {
      return <span className="text-brand-muted italic">[]</span>;
    }
    return (
      <div className="flex flex-wrap gap-1 justify-end">
        {value.map((item, idx) => (
          <span
            key={idx}
            className="px-1.5 py-0.5 rounded bg-surface-elevated border border-border text-[10px] font-mono text-brand-body break-all"
          >
            {typeof item === 'object' ? JSON.stringify(item) : String(item)}
          </span>
        ))}
      </div>
    );
  }
  if (typeof value === 'object') {
    const entries = Object.entries(value as Record<string, unknown>);
    if (entries.length === 0) {
      return <span className="text-brand-muted italic">{'{}'}</span>;
    }
    return (
      <div className="w-full mt-1.5 pl-3 border-l border-border/70 space-y-1">
        {entries.map(([k, v]) => (
          <div key={k} className="flex items-start justify-between gap-3 text-[11px]">
            <span className="text-brand-muted font-mono shrink-0">{formatKey(k)}</span>
            <div className="text-right">
              <ConfigValue value={v} />
            </div>
          </div>
        ))}
      </div>
    );
  }
  return <span className="text-brand-body font-mono">{String(value)}</span>;
};

const ConfigSectionCard: React.FC<{ title: string; data: any }> = ({ title, data }) => {
  const isArr = Array.isArray(data);
  const entries: [string, unknown][] = isArr
    ? data.map((m, i) => [m?.model_name ? String(m.model_name) : `#${i + 1}`, m])
    : data
      ? Object.entries(data)
      : [];

  return (
    <div className="bg-surface-base border border-border rounded-xl p-4 space-y-3">
      <div className="flex items-center justify-between border-b border-border pb-2">
        <div className="flex items-center gap-2">
          <ShieldCheck className="w-4 h-4 text-accent-primary" />
          <h3 className="text-xs font-bold text-brand-title">{title}</h3>
        </div>
        <Badge variant="neutral">{entries.length} {isArr ? 'items' : 'keys'}</Badge>
      </div>
      {entries.length === 0 ? (
        <div className="text-xs text-brand-muted font-mono py-3 text-center">No fields configured.</div>
      ) : (
        <div className="divide-y divide-border/50">
          {entries.map(([key, val]) => {
            const nested = val !== null && typeof val === 'object' && !Array.isArray(val) && Object.keys(val).length > 0;
            return (
              <div key={key} className={`py-2 text-xs ${nested ? 'flex flex-col gap-1' : 'flex items-start justify-between gap-4'}`}>
                <span className="text-brand-muted font-mono text-[11px] shrink-0">{formatKey(key)}</span>
                <div className={nested ? 'w-full' : 'text-right'}><ConfigValue value={val} /></div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};

const btn = 'inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-surface-elevated border border-border text-xs font-mono text-brand-title';

export const ConfigView: React.FC = () => {
  const { adminKey, isUnlocked, operator } = useAuth();
  const canRotateKEK = operator?.role === 'platform_admin';
  const { data: config, isLoading, isFetching, isError, error, refetch } = useQuery<GatewayConfig>({
    queryKey: ['admin', 'config', adminKey],
    queryFn: () => adminApi.getConfig(adminKey),
    enabled: isUnlocked,
    staleTime: 30000,
  });

  const [kekOpen, setKekOpen] = useState(false);
  const [newKek, setNewKek] = useState('');
  const [kekBusy, setKekBusy] = useState(false);
  const [kekErr, setKekErr] = useState<unknown>(null);
  const [kekMsg, setKekMsg] = useState<string | null>(null);
  const submitKek = async (e: React.FormEvent) => {
    e.preventDefault();
    setKekBusy(true); setKekErr(null);
    try {
      const r = await adminApi.rotateMasterKEK(adminKey, newKek.trim());
      setNewKek(''); setKekOpen(false); setKekMsg(r.multi_pod_notice || 'Rotated.');
    } catch (err) { setKekErr(err); } finally { setKekBusy(false); }
  };

  const sections = SECTIONS.map(([id, title]) => ({
    id, title,
    data: id === 'rate_limit' ? config?.rate_limit ?? config?.rate_limits : id === 'router' ? config?.router ?? config?.routing : config?.[id],
  }));

  return (
    <div className="max-w-7xl mx-auto space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-lg font-bold text-brand-title flex items-center gap-2">
            <Settings className="w-5 h-5 text-accent-primary" />Gateway Configuration
          </h2>
          <p className="text-xs text-brand-muted">Snapshot from <code className="font-mono text-accent-primary">/admin/v1/config</code></p>
        </div>
        <div className="flex items-center gap-2">
          {canRotateKEK && (
            <button onClick={() => setKekOpen((v) => !v)} className={btn}><Lock className="w-3.5 h-3.5" />Rotate KEK</button>
          )}
          <button onClick={() => refetch()} disabled={isFetching} className={btn}><RefreshCw className={`w-3.5 h-3.5 ${isFetching ? 'animate-spin' : ''}`} />Refresh</button>
        </div>
      </div>

      {canRotateKEK && kekOpen && (
        <form onSubmit={submitKek} className="flex flex-col sm:flex-row gap-2 p-3 rounded-lg bg-surface-base border border-border text-xs">
          <input type="password" minLength={32} required value={newKek} onChange={(e) => setNewKek(e.target.value)} placeholder="New master KEK (>=32 chars)" className="flex-1 px-2 py-1 rounded bg-surface-elevated border border-border font-mono text-brand-title" />
          <button type="submit" disabled={kekBusy} className="px-3 py-1 rounded bg-accent-primary text-white font-semibold">{kekBusy ? 'Rotating...' : 'Confirm'}</button>
        </form>
      )}
      {!!kekErr && <ErrorAlert error={kekErr} title="KEK rotation failed" />}
      {kekMsg && <div className="p-2.5 rounded-lg bg-surface-base border border-status-success/40 text-xs text-status-success">{kekMsg}</div>}
      <div className="flex items-center gap-2 p-3 rounded-lg bg-surface-base border border-border text-xs text-brand-muted">
        <Lock className="w-4 h-4 text-status-warning shrink-0" />Read-only view. Secrets are redacted server-side.
      </div>

      {isError ? (
        isPlatformAdminForbidden(error) || (error as { status?: number } | null)?.status === 403 ? (
          <ScopedRoleNotice subject="gateway runtime configuration" />
        ) : (
          <ErrorAlert error={error} title="Failed to load runtime configuration" />
        )
      ) : isLoading ? (
        <div className="flex items-center justify-center h-48 text-brand-muted font-mono text-xs gap-2">
          <RefreshCw className="w-4 h-4 animate-spin text-accent-primary" />
          <span>Fetching sanitized gateway configuration...</span>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
          {sections.map((s) => <ConfigSectionCard key={s.id} title={s.title} data={s.data} />)}
        </div>
      )}
    </div>
  );
};
