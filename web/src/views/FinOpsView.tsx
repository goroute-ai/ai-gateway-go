import React, { useState, Suspense, lazy } from 'react';
import { useQuery } from '@tanstack/react-query';
import { adminApi } from '../api/admin';
import { useAuth } from '../context/AuthContext';
import { Badge } from '../components/common/Badge';
import { Modal, CARD_CLS, THEAD_CLS } from '../components/common/Modal';
import { CodeBlock } from '../components/common/CodeBlock';
import { ErrorAlert } from '../components/common/ErrorAlert';
import { SpendEvent, AuditLog } from '../types';
import {
  DollarSign,
  Activity,
  AlertTriangle,
  Clock,
  Layers,
  RefreshCw,
  Search,
} from 'lucide-react';

const QuotasTab = lazy(() => import('./finops/QuotasTab').then((m) => ({ default: m.QuotasTab })));

const SpendBreakdownCard: React.FC<{
  title: string;
  icon: React.ReactNode;
  entries?: Record<string, number>;
  totalCostMicros: number;
  barClass: string;
  emptyText: string;
  limit?: number;
  formatMicroDollars: (m?: number) => string;
}> = ({ title, icon, entries, totalCostMicros, barClass, emptyText, limit, formatMicroDollars }) => {
  const items = entries ? Object.entries(entries).sort(([, a], [, b]) => b - a) : [];
  const visible = limit ? items.slice(0, limit) : items;
  return (
    <div className={`${CARD_CLS} p-4`}>
      <h3 className="text-xs font-mono uppercase tracking-wider text-brand-muted mb-3 flex items-center gap-2">
        {icon}
        {title}
      </h3>
      {visible.length > 0 ? (
        <div className="space-y-2 max-h-48 overflow-y-auto pr-1">
          {visible.map(([label, micros]) => {
            const pct = totalCostMicros > 0 ? (micros / totalCostMicros) * 100 : 0;
            return (
              <div key={label} className="text-xs font-mono">
                <div className="flex justify-between text-brand-body mb-1">
                  <span className="truncate max-w-[200px]" title={label}>
                    {label || 'unassigned'}
                  </span>
                  <span>
                    {formatMicroDollars(micros)} ({pct.toFixed(1)}%)
                  </span>
                </div>
                <div className="w-full bg-surface-elevated rounded-full h-1.5 overflow-hidden">
                  <div
                    className={`${barClass} h-1.5 rounded-full`}
                    style={{ width: `${Math.min(100, Math.max(2, pct))}%` }}
                  />
                </div>
              </div>
            );
          })}
        </div>
      ) : (
        <div className="text-xs text-brand-muted font-mono py-4 text-center">{emptyText}</div>
      )}
    </div>
  );
};

export const FinOpsView: React.FC = () => {
  const { adminKey, isUnlocked, activeOrgId } = useAuth();
  const [activeTab, setActiveTab] = useState<'spend' | 'quotas' | 'audit'>('spend');
  const [selectedSpendEvent, setSelectedSpendEvent] = useState<SpendEvent | null>(null);
  const [selectedAuditLog, setSelectedAuditLog] = useState<AuditLog | null>(null);
  const [searchFilter, setSearchFilter] = useState('');
  const [logLimit, setLogLimit] = useState(50);

  // Spend summary query
  const {
    data: summary,
    isLoading: isSummaryLoading,
    isError: isSummaryError,
    error: summaryError,
    refetch: refetchSummary,
  } = useQuery({
    queryKey: ['admin', 'spend-summary', adminKey, activeOrgId],
    queryFn: () => adminApi.getSpendSummary(adminKey, activeOrgId || undefined),
    enabled: isUnlocked,
    refetchInterval: 15000,
  });

  // Spend event logs query
  const {
    data: spendLogsData,
    isLoading: isLogsLoading,
    isError: isLogsError,
    error: logsError,
    refetch: refetchLogs,
  } = useQuery({
    queryKey: ['admin', 'spend-logs', adminKey, activeOrgId, logLimit],
    queryFn: () => adminApi.listSpendLogs(adminKey, activeOrgId || undefined, logLimit),
    enabled: isUnlocked && activeTab === 'spend',
    refetchInterval: 10000,
  });

  // Audit logs query
  const {
    data: auditLogsData,
    isLoading: isAuditLoading,
    isError: isAuditError,
    error: auditError,
    refetch: refetchAudit,
  } = useQuery({
    queryKey: ['admin', 'audit-logs', adminKey, activeOrgId, logLimit],
    queryFn: () => adminApi.listAuditLogs(adminKey, activeOrgId || undefined, logLimit),
    enabled: isUnlocked && activeTab === 'audit',
    refetchInterval: 10000,
  });

  const spendLogs = spendLogsData?.data || [];
  const auditLogs = auditLogsData?.data || [];

  const filteredSpendLogs = spendLogs.filter((evt) => {
    if (!searchFilter.trim()) return true;
    const term = searchFilter.toLowerCase();
    return (
      evt.request_id?.toLowerCase().includes(term) ||
      evt.provider?.toLowerCase().includes(term) ||
      evt.resolved_model?.toLowerCase().includes(term) ||
      evt.virtual_key_id?.toLowerCase().includes(term)
    );
  });

  const filteredAuditLogs = auditLogs.filter((log) => {
    if (!searchFilter.trim()) return true;
    const term = searchFilter.toLowerCase();
    return (
      log.action?.toLowerCase().includes(term) ||
      log.resource?.toLowerCase().includes(term) ||
      log.resource_id?.toLowerCase().includes(term) ||
      log.actor_id?.toLowerCase().includes(term)
    );
  });

  // Format integer micro-dollars ($1 = 1,000,000 micros)
  const formatMicroDollars = (micros?: number) => {
    if (micros === undefined || micros === null) return '$0.00';
    const usd = micros / 1000000;
    return `$${usd.toLocaleString('en-US', { minimumFractionDigits: 4, maximumFractionDigits: 6 })}`;
  };

  const totalCostMicros = summary?.total_cost_micros ?? 0;
  const totalRequests = summary?.total_requests ?? 0;
  const totalTokens = summary?.total_tokens ?? 0;
  const avgCostPerReqMicros = totalRequests > 0 ? Math.round(totalCostMicros / totalRequests) : 0;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h2 className="text-xl font-semibold text-brand-title flex items-center gap-2">
            <DollarSign className="w-5 h-5 text-accent-primary" />
            FinOps & Spend Governance
          </h2>
          <p className="text-xs text-brand-muted mt-1">
            Real-time micro-dollar ($1 = 1,000,000 µ$) ledger accounting and administrative audit trail.
          </p>
        </div>

        <div className="flex items-center gap-3">
          <button
            onClick={() => {
              refetchSummary();
              if (activeTab === 'spend') refetchLogs();
              else refetchAudit();
            }}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-surface-base border border-border-subtle hover:border-border-strong text-brand-body hover:text-brand-title rounded text-xs transition"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            Refresh
          </button>
        </div>
      </div>

      {/* Aggregate FinOps Metrics Grid */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        {[
          { label: 'Cumulative Spend', icon: <DollarSign className="w-4 h-4 text-status-success" />, val: formatMicroDollars(totalCostMicros), sub: `${totalCostMicros.toLocaleString()} µ$ ledger balance` },
          { label: 'Total Invocations', icon: <Activity className="w-4 h-4 text-accent-primary" />, val: totalRequests.toLocaleString(), sub: 'Processed via active keys' },
          { label: 'Total Tokens', icon: <Layers className="w-4 h-4 text-accent-glow" />, val: totalTokens.toLocaleString(), sub: 'Prompt + Completion tokens' },
          { label: 'Avg Cost / Req', icon: <DollarSign className="w-4 h-4 text-status-warning" />, val: formatMicroDollars(avgCostPerReqMicros), sub: `${avgCostPerReqMicros.toLocaleString()} µ$ per request` },
        ].map((kpi) => (
          <div key={kpi.label} className={`${CARD_CLS} p-4`}>
            <div className="flex items-center justify-between text-brand-muted mb-1">
              <span className="text-xs font-mono uppercase tracking-wider">{kpi.label}</span>
              {kpi.icon}
            </div>
            <div className="text-2xl font-bold font-mono text-brand-title">{isSummaryLoading ? '...' : kpi.val}</div>
            <div className="text-[11px] text-brand-muted font-mono mt-1">{kpi.sub}</div>
          </div>
        ))}
      </div>

      {!!summary?.unpriced_requests && (
        <div role="alert" className="flex items-start gap-3 rounded-lg border status-warning p-4">
          <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0" />
          <div>
            <p className="text-sm font-medium">Some usage has no verified price</p>
            <p className="mt-1 text-xs opacity-85">
              {summary.unpriced_requests.toLocaleString()} requests covering {summary.unpriced_tokens.toLocaleString()} tokens are excluded from the cost total. Review model pricing before using this total for billing.
            </p>
          </div>
        </div>
      )}

      {/* Error Alerts */}
      {isSummaryError && (
        <ErrorAlert error={summaryError} title="Failed to load spend summary" onRetry={() => refetchSummary()} />
      )}
      {activeTab === 'spend' && isLogsError && (
        <ErrorAlert error={logsError} title="Failed to load spend logs" onRetry={() => refetchLogs()} />
      )}
      {activeTab === 'audit' && isAuditError && (
        <ErrorAlert error={auditError} title="Failed to load audit logs" onRetry={() => refetchAudit()} />
      )}

      {/* Spend Breakdowns (Provider, Model, Team & Virtual Key) */}
      {summary && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {[
            { title: 'Spend by Provider', icon: <DollarSign className="w-4 h-4 text-accent-primary" />, entries: summary.spend_by_provider, barClass: 'bg-accent-primary', emptyText: 'No provider spend yet' },
            { title: 'Top Models by Spend', icon: <Layers className="w-4 h-4 text-accent-glow" />, entries: summary.spend_by_model, barClass: 'bg-accent-dark', emptyText: 'No model spend yet', limit: 5 },
            { title: 'Spend by Team', icon: <Layers className="w-4 h-4 text-status-success" />, entries: summary.spend_by_team, barClass: 'bg-status-success', emptyText: 'No team spend yet' },
            { title: 'Top Virtual Keys by Spend', icon: <DollarSign className="w-4 h-4 text-status-info" />, entries: summary.spend_by_virtual_key, barClass: 'bg-status-info', emptyText: 'No virtual key spend yet', limit: 5 },
          ].map((b) => (
            <SpendBreakdownCard key={b.title} {...b} totalCostMicros={totalCostMicros} formatMicroDollars={formatMicroDollars} />
          ))}
        </div>
      )}

      {/* Navigation Tabs (Spend Logs, Quotas & Budgets, Audit Trail) */}
      <div className="border-b border-border-subtle">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div className="flex gap-4">
            <button
              onClick={() => setActiveTab('spend')}
              className={`pb-3 text-xs font-medium border-b-2 flex items-center gap-2 transition ${
                activeTab === 'spend'
                  ? 'border-accent-primary text-accent-primary font-semibold'
                  : 'border-transparent text-brand-muted hover:text-brand-title'
              }`}
            >
              <Layers className="w-4 h-4" />
              Recent Spend Events ({spendLogs.length})
            </button>
            <button
              onClick={() => setActiveTab('quotas')}
              className={`pb-3 text-xs font-medium border-b-2 flex items-center gap-2 transition ${
                activeTab === 'quotas'
                  ? 'border-accent-primary text-accent-primary font-semibold'
                  : 'border-transparent text-brand-muted hover:text-brand-title'
              }`}
            >
              <Clock className="w-4 h-4" />
              Quotas &amp; Multi-Window Budgets
            </button>
            <button
              onClick={() => setActiveTab('audit')}
              className={`pb-3 text-xs font-medium border-b-2 flex items-center gap-2 transition ${
                activeTab === 'audit'
                  ? 'border-accent-primary text-accent-primary font-semibold'
                  : 'border-transparent text-brand-muted hover:text-brand-title'
              }`}
            >
              <AlertTriangle className="w-4 h-4" />
              Administrative Audit Log ({auditLogs.length})
            </button>
          </div>

          {activeTab !== 'quotas' && (
            <div className="flex items-center gap-3 pb-2">
              <div className="relative">
                <Search className="w-3.5 h-3.5 text-brand-muted absolute left-2.5 top-1/2 -translate-y-1/2" />
                <input
                  type="text"
                  value={searchFilter}
                  onChange={(e) => setSearchFilter(e.target.value)}
                  placeholder={activeTab === 'spend' ? 'Filter by request, model...' : 'Filter by action, resource...'}
                  className="pl-8 pr-3 py-1 text-xs bg-surface-input border border-border-subtle rounded text-brand-body placeholder-brand-muted focus:outline-none focus:border-accent-primary font-mono w-56"
                />
              </div>
              <select
                value={logLimit}
                onChange={(e) => setLogLimit(Number(e.target.value))}
                aria-label="Records per page"
                className="bg-surface-input border border-border-subtle text-brand-body text-xs rounded px-2 py-1 font-mono focus:outline-none"
              >
                <option value={25}>25 rows</option>
                <option value={50}>50 rows</option>
                <option value={100}>100 rows</option>
              </select>
            </div>
          )}
        </div>
      </div>

      {/* Tab 2: Quotas & Multi-Window Budgets (Lazy-Loaded) */}
      {activeTab === 'quotas' && (
        <Suspense
          fallback={
            <div className="flex items-center justify-center py-12 text-brand-muted font-mono text-xs gap-2">
              <RefreshCw className="w-4 h-4 animate-spin text-accent-primary" />
              <span>Loading quotas &amp; multi-window budgets...</span>
            </div>
          }
        >
          <QuotasTab />
        </Suspense>
      )}

      {/* Tab 1: Spend Event Logs Table */}
      {activeTab === 'spend' && (
        <div className={`${CARD_CLS} overflow-hidden`}>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className={THEAD_CLS}>
                <tr>
                  <th className="px-4 py-3">Timestamp</th>
                  <th className="px-4 py-3">Request ID</th>
                  <th className="px-4 py-3">Resolved Model</th>
                  <th className="px-4 py-3">Provider</th>
                  <th className="px-4 py-3">Tokens (P/C/Total)</th>
                  <th className="px-4 py-3">Cost (USD / µ$)</th>
                  <th className="px-4 py-3">Latency</th>
                  <th className="px-4 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border-subtle">
                {isLogsLoading ? (
                  <tr>
                    <td colSpan={8} className="px-4 py-8 text-center text-brand-muted">
                      Loading spend events...
                    </td>
                  </tr>
                ) : filteredSpendLogs.length === 0 ? (
                  <tr>
                    <td colSpan={8} className="px-4 py-8 text-center text-brand-muted">
                      No spend events recorded matching the criteria.
                    </td>
                  </tr>
                ) : (
                  filteredSpendLogs.map((evt) => (
                    <tr key={evt.id || evt.request_id} className="hover:bg-surface-elevated/40 transition">
                      <td className="px-4 py-3 text-brand-muted whitespace-nowrap">
                        <span className="flex items-center gap-1.5">
                          <Clock className="w-3 h-3 text-brand-muted" />
                          {evt.created_at ? new Date(evt.created_at).toLocaleTimeString() : 'N/A'}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-brand-body font-semibold truncate max-w-[140px]" title={evt.request_id}>
                        {evt.request_id ? evt.request_id.slice(0, 12) + '...' : 'N/A'}
                      </td>
                      <td className="px-4 py-3 text-brand-body">
                        <span className="font-medium text-accent-primary">{evt.resolved_model || evt.requested_model}</span>
                        {evt.requested_model && evt.requested_model !== evt.resolved_model && (
                          <span className="block text-[10px] text-brand-muted">via {evt.requested_model}</span>
                        )}
                      </td>
                      <td className="px-4 py-3 text-brand-muted capitalize">
                        <Badge variant="neutral">{evt.provider || 'unknown'}</Badge>
                      </td>
                      <td className="px-4 py-3 text-brand-body whitespace-nowrap">
                        {evt.usage?.prompt_tokens ?? 0} / {evt.usage?.completion_tokens ?? 0}
                        <span className="block text-[10px] text-brand-muted font-bold">
                          {(evt.usage?.total_tokens ?? 0).toLocaleString()} tot
                        </span>
                      </td>
                      <td className="px-4 py-3 text-status-success whitespace-nowrap">
                        <span className="font-bold">{formatMicroDollars(evt.cost_micros)}</span>
                        <span className="block text-[10px] text-brand-muted">
                          {evt.cost_micros?.toLocaleString() || 0} µ$
                        </span>
                      </td>
                      <td className="px-4 py-3 text-brand-muted whitespace-nowrap">
                        {evt.latency_ms ? `${evt.latency_ms.toFixed(0)} ms` : '-'}
                      </td>
                      <td className="px-4 py-3 text-right">
                        <button
                          onClick={() => setSelectedSpendEvent(evt)}
                          className="px-2 py-1 bg-surface-elevated hover:bg-surface-hover border border-border-subtle text-brand-body hover:text-brand-title rounded text-[11px] transition inline-flex items-center gap-1"
                        >
                          <Search className="w-3 h-3" />
                          Inspect
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Tab 2: Administrative Audit Trail Table */}
      {activeTab === 'audit' && (
        <div className={`${CARD_CLS} overflow-hidden`}>
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead className={THEAD_CLS}>
                <tr>
                  <th className="px-4 py-3">Timestamp</th>
                  <th className="px-4 py-3">Action</th>
                  <th className="px-4 py-3">Resource</th>
                  <th className="px-4 py-3">Resource ID</th>
                  <th className="px-4 py-3">Actor</th>
                  <th className="px-4 py-3 text-right">Payload</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border-subtle">
                {isAuditLoading ? (
                  <tr>
                    <td colSpan={6} className="px-4 py-8 text-center text-brand-muted">
                      Loading audit log trail...
                    </td>
                  </tr>
                ) : filteredAuditLogs.length === 0 ? (
                  <tr>
                    <td colSpan={6} className="px-4 py-8 text-center text-brand-muted">
                      No administrative audit records found.
                    </td>
                  </tr>
                ) : (
                  filteredAuditLogs.map((log) => (
                    <tr key={log.id} className="hover:bg-surface-elevated/40 transition">
                      <td className="px-4 py-3 text-brand-muted whitespace-nowrap">
                        <span className="flex items-center gap-1.5">
                          <Clock className="w-3 h-3 text-brand-muted" />
                          {log.created_at ? new Date(log.created_at).toLocaleString() : 'N/A'}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <Badge
                          variant={
                            log.action.includes('delete') || log.action.includes('revoke')
                              ? 'danger'
                              : log.action.includes('create')
                              ? 'success'
                              : 'primary'
                          }
                        >
                          {log.action}
                        </Badge>
                      </td>
                      <td className="px-4 py-3 text-brand-body font-semibold">{log.resource}</td>
                      <td className="px-4 py-3 text-brand-muted truncate max-w-[160px]" title={log.resource_id}>
                        {log.resource_id}
                      </td>
                      <td className="px-4 py-3 text-brand-muted">
                        {log.actor_id || 'master-admin'}
                      </td>
                      <td className="px-4 py-3 text-right">
                        <button
                          onClick={() => setSelectedAuditLog(log)}
                          className="px-2 py-1 bg-surface-elevated hover:bg-surface-hover border border-border-subtle text-brand-body hover:text-brand-title rounded text-[11px] transition inline-flex items-center gap-1"
                        >
                          <Search className="w-3 h-3" />
                          Details
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Spend Event / Audit Log Inspector Modal */}
      {(selectedSpendEvent || selectedAuditLog) && (() => {
        const isSpend = !!selectedSpendEvent;
        const fields: Array<[string, string | number]> = isSpend
          ? [
              ['Total Tokens:', (selectedSpendEvent!.usage?.total_tokens ?? 0).toLocaleString()],
              ['Cost (Micros):', `${selectedSpendEvent!.cost_micros?.toLocaleString() || 0} µ$`],
              ['Cost (USD):', formatMicroDollars(selectedSpendEvent!.cost_micros)],
              ['Provider:', selectedSpendEvent!.provider],
              ['Resolved Model:', selectedSpendEvent!.resolved_model],
              ['Latency:', selectedSpendEvent!.latency_ms ? `${selectedSpendEvent!.latency_ms.toFixed(1)} ms` : '-'],
            ]
          : [
              ['Actor:', selectedAuditLog!.actor_id || 'master-admin'],
              ['Timestamp:', new Date(selectedAuditLog!.created_at).toLocaleString()],
              ['Target Resource:', selectedAuditLog!.resource],
              ['Resource ID:', selectedAuditLog!.resource_id],
            ];
        return (
          <Modal
            title={
              isSpend
                ? `Spend Event: ${selectedSpendEvent!.request_id || selectedSpendEvent!.id}`
                : `Audit Record: ${selectedAuditLog!.action} (${selectedAuditLog!.resource})`
            }
            isOpen
            onClose={() => { setSelectedSpendEvent(null); setSelectedAuditLog(null); }}
            size="lg"
          >
            <div className="space-y-4">
              <div className={`grid grid-cols-2 ${isSpend ? 'sm:grid-cols-3' : ''} gap-3 bg-surface-code border border-border-subtle rounded p-3 text-xs font-mono`}>
                {fields.map(([k, v]) => (
                  <div key={k}>
                    <span className="text-brand-muted block">{k}</span>
                    <span className="text-brand-title font-semibold truncate block">{v}</span>
                  </div>
                ))}
              </div>
              <div>
                <label className="text-xs text-brand-muted font-mono block mb-1">
                  {isSpend ? 'Raw Ledger Record:' : 'Audit Details / Payload:'}
                </label>
                <CodeBlock
                  code={JSON.stringify(isSpend ? selectedSpendEvent : selectedAuditLog!.details || {}, null, 2)}
                  language="json"
                />
              </div>
            </div>
          </Modal>
        );
      })()}
    </div>
  );
};
