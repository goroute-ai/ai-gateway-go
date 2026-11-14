import React from 'react';
import { useQuery } from '@tanstack/react-query';
import {
  Settings,
  Server,
  Gauge,
  Database,
  ShieldCheck,
  GitBranch,
  Activity,
  RefreshCw,
  Lock,
} from 'lucide-react';
import { adminApi } from '../api/admin';
import { useAuth } from '../context/AuthContext';
import { ErrorAlert } from '../components/common/ErrorAlert';
import { Badge } from '../components/common/Badge';
import type { GatewayConfig } from '../types';

interface SectionDef {
  id: string;
  title: string;
  subtitle: string;
  icon: React.ReactNode;
  data: Record<string, any> | undefined;
}

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
    return <span className="text-zinc-500 italic">—</span>;
  }
  if (typeof value === 'boolean') {
    return (
      <Badge variant={value ? 'success' : 'neutral'}>
        {value ? 'enabled' : 'disabled'}
      </Badge>
    );
  }
  if (typeof value === 'number') {
    return <span className="text-[#f5f3ff] font-mono">{value.toLocaleString()}</span>;
  }
  if (typeof value === 'string') {
    if (isRedactedValue(value)) {
      return (
        <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded bg-amber-950/40 border border-amber-500/30 text-amber-300 font-mono text-[10px]">
          <Lock className="w-2.5 h-2.5" />
          {value}
        </span>
      );
    }
    return <span className="text-[#f5f3ff] font-mono break-all">{value}</span>;
  }
  if (Array.isArray(value)) {
    if (value.length === 0) {
      return <span className="text-zinc-500 italic">[]</span>;
    }
    return (
      <div className="flex flex-wrap gap-1 justify-end">
        {value.map((item, idx) => (
          <span
            key={idx}
            className="px-1.5 py-0.5 rounded bg-surface-elevated border border-border text-[10px] font-mono text-zinc-200 break-all"
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
      return <span className="text-zinc-500 italic">{'{}'}</span>;
    }
    return (
      <div className="w-full mt-1.5 pl-3 border-l border-border/70 space-y-1">
        {entries.map(([k, v]) => (
          <div key={k} className="flex items-start justify-between gap-3 text-[11px]">
            <span className="text-[#9696a4] font-mono shrink-0">{formatKey(k)}</span>
            <div className="text-right">
              <ConfigValue value={v} />
            </div>
          </div>
        ))}
      </div>
    );
  }
  return <span className="text-zinc-300 font-mono">{String(value)}</span>;
}

const ConfigSectionCard: React.FC<{ section: SectionDef }> = ({ section }) => {
  const entries = section.data ? Object.entries(section.data) : [];

  return (
    <div className="bg-surface-base border border-border rounded-xl p-5 space-y-4">
      <div className="flex items-center justify-between border-b border-border pb-3">
        <div className="flex items-center gap-2.5">
          <div className="p-2 rounded-lg bg-[rgba(124,58,237,0.1)] border border-accent-primary/25 text-accent-primary">
            {section.icon}
          </div>
          <div>
            <h3 className="text-xs font-bold text-[#f5f3ff] tracking-tight">{section.title}</h3>
            <p className="text-[11px] text-[#9696a4]">{section.subtitle}</p>
          </div>
        </div>
        <Badge variant="neutral">{entries.length} keys</Badge>
      </div>

      {entries.length === 0 ? (
        <div className="text-xs text-[#9696a4] font-mono py-4 text-center">
          No configuration fields reported for this section.
        </div>
      ) : (
        <div className="divide-y divide-border/50">
          {entries.map(([key, val]) => {
            const isNestedObj =
              val !== null && typeof val === 'object' && !Array.isArray(val) && Object.keys(val).length > 0;
            return (
              <div
                key={key}
                className={`py-2 text-xs ${
                  isNestedObj ? 'flex flex-col gap-1' : 'flex items-start justify-between gap-4'
                }`}
              >
                <span className="text-[#9696a4] font-mono text-[11px] shrink-0">{formatKey(key)}</span>
                <div className={isNestedObj ? 'w-full' : 'text-right'}>
                  <ConfigValue value={val} />
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
};

export const ConfigView: React.FC = () => {
  const { adminKey, isUnlocked } = useAuth();

  const {
    data: config,
    isLoading,
    isFetching,
    isError,
    error,
    refetch,
  } = useQuery<GatewayConfig>({
    queryKey: ['admin', 'config', adminKey],
    queryFn: () => adminApi.getConfig(adminKey),
    enabled: isUnlocked,
    staleTime: 30000,
  });

  const observabilityData = config
    ? config.observability ??
      (config.logging || config.tracing
        ? {
            ...(config.logging ? { logging: config.logging } : {}),
            ...(config.tracing ? { tracing: config.tracing } : {}),
          }
        : undefined)
    : undefined;

  const sections: SectionDef[] = [
    {
      id: 'server',
      title: 'Server & Transport',
      subtitle: 'HTTP listener, gRPC, timeouts & CORS',
      icon: <Server className="w-4 h-4" />,
      data: config?.server,
    },
    {
      id: 'rate_limit',
      title: 'Rate Limits',
      subtitle: 'Global RPM/TPM caps & Redis windowing',
      icon: <Gauge className="w-4 h-4" />,
      data: config?.rate_limit ?? config?.rate_limits,
    },
    {
      id: 'cache',
      title: 'Response Cache',
      subtitle: 'L1/L2 caching & TTL defaults',
      icon: <Database className="w-4 h-4" />,
      data: config?.cache,
    },
    {
      id: 'guardrails',
      title: 'Guardrails',
      subtitle: 'Content filtering & external scanners',
      icon: <ShieldCheck className="w-4 h-4" />,
      data: config?.guardrails,
    },
    {
      id: 'routing',
      title: 'Routing & Reliability',
      subtitle: 'Aliases, retries & circuit-breaker thresholds',
      icon: <GitBranch className="w-4 h-4" />,
      data: config?.router ?? config?.routing,
    },
    {
      id: 'observability',
      title: 'Observability',
      subtitle: 'Structured logging & OTLP tracing',
      icon: <Activity className="w-4 h-4" />,
      data: observabilityData,
    },
  ];

  return (
    <div className="max-w-7xl mx-auto space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-lg font-bold text-[#f5f3ff] flex items-center gap-2 tracking-tight">
            <Settings className="w-5 h-5 text-accent-primary" />
            Gateway Runtime Configuration
          </h2>
          <p className="text-xs text-[#9696a4] mt-1">
            Sanitized read-only snapshot of active gateway configuration from <code className="font-mono text-accent-primary">/admin/v1/config</code>.
          </p>
        </div>

        <button
          onClick={() => refetch()}
          disabled={isFetching}
          className="inline-flex items-center gap-2 px-3 py-1.5 rounded-lg bg-surface-elevated border border-border text-xs font-mono text-[#f5f3ff] hover:border-accent-primary/40 transition-colors disabled:opacity-50 self-start sm:self-auto"
        >
          <RefreshCw className={`w-3.5 h-3.5 ${isFetching ? 'animate-spin text-accent-primary' : ''}`} />
          <span>Refresh</span>
        </button>
      </div>

      <div className="flex items-center gap-2.5 px-4 py-2.5 rounded-lg bg-surface-base border border-border text-xs text-[#9696a4]">
        <Lock className="w-4 h-4 text-amber-400 shrink-0" />
        <span>
          Read-only view. Master keys, JWT secrets, and database or Redis credentials are redacted server-side before leaving the control plane.
        </span>
      </div>

      {isError && (
        <ErrorAlert error={error} title="Failed to load runtime configuration" />
      )}

      {isLoading ? (
        <div className="flex items-center justify-center h-48 text-[#9696a4] font-mono text-xs gap-2">
          <RefreshCw className="w-4 h-4 animate-spin text-accent-primary" />
          <span>Fetching sanitized gateway configuration...</span>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
          {sections.map((section) => (
            <ConfigSectionCard key={section.id} section={section} />
          ))}
        </div>
      )}
    </div>
  );
};
