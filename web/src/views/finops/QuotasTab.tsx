import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { adminApi } from '../../api/admin';
import { useAuth } from '../../context/AuthContext';
import { Badge } from '../../components/common/Badge';
import { FormModal, Field, INPUT_CLS, MONO_INPUT_CLS, BTN_PRIMARY } from '../../components/common/Modal';
import { TempBudgetModal } from '../../components/common/TempBudgetModal';
import { ErrorAlert } from '../../components/common/ErrorAlert';
import { formatUSD, microsToUsdInput, usdToMicros } from '../../utils/budget';
import type { QuotaPolicy, QuotaScopeType, BudgetWindowLimit, BudgetWindowType, BudgetResetPeriod, VirtualKey } from '../../types';
import { Plus, Trash2, Pencil, Zap, Clock, Layers } from 'lucide-react';

const SCOPES: QuotaScopeType[] = [
  'model_per_key', 'model_per_team', 'model_per_org', 'model_per_project', 'model_per_user', 'model_per_end_user',
  'org', 'team', 'team_member', 'project', 'user', 'key', 'end_user', 'tag', 'model_access_group', 'agent_session', 'mcp_server',
];
const WINDOWS: BudgetWindowType[] = ['daily', 'weekly', 'monthly', 'rolling_24h'];
const card = 'bg-surface-base border border-border-subtle rounded-lg p-4 space-y-3';
const tbl = 'w-full text-left text-xs font-mono';
const thead = 'bg-surface-elevated/60 text-brand-muted uppercase text-[10px] border-b border-border-subtle';
const th = 'px-3 py-2';

export const QuotasTab: React.FC = () => {
  const { adminKey, isUnlocked, activeOrgId } = useAuth();
  const qc = useQueryClient();
  const [scopeFilter, setScopeFilter] = useState('');
  const [modelFilter, setModelFilter] = useState('');
  const [quotaModal, setQuotaModal] = useState(false);
  const [qf, setQf] = useState<Record<string, any>>({ scope_type: 'model_per_key', model_pattern: '*', reset: 'monthly', active: true });
  const setQ = (k: string, v: any) => setQf((p) => ({ ...p, [k]: v }));
  const [bwModal, setBwModal] = useState(false);
  const [bf, setBf] = useState<Record<string, any>>({ scope_type: 'key', window_type: 'daily' });
  const setB = (k: string, v: any) => setBf((p) => ({ ...p, [k]: v }));
  const [boostKey, setBoostKey] = useState<VirtualKey | null>(null);

  const quotasQ = useQuery({
    queryKey: ['admin', 'quotas', adminKey, activeOrgId, scopeFilter, modelFilter],
    queryFn: () => adminApi.listQuotas(adminKey, { org_id: activeOrgId || undefined, scope_type: scopeFilter || undefined, model_pattern: modelFilter.trim() || undefined }),
    enabled: isUnlocked,
  });
  const windowsQ = useQuery({
    queryKey: ['admin', 'budget-windows', adminKey, activeOrgId],
    queryFn: () => adminApi.listBudgetWindows(adminKey, { org_id: activeOrgId || undefined }),
    enabled: isUnlocked,
  });
  const keysQ = useQuery({
    queryKey: ['admin', 'keys', adminKey, activeOrgId],
    queryFn: () => adminApi.listKeys(adminKey, activeOrgId),
    enabled: isUnlocked && !!activeOrgId,
  });

  const upsertQuotaMut = useMutation({
    mutationFn: (p: Partial<QuotaPolicy>) => adminApi.upsertQuota(adminKey, p),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['admin', 'quotas', adminKey] }); setQuotaModal(false); },
  });
  const deleteQuotaMut = useMutation({
    mutationFn: (id: string) => adminApi.deleteQuota(adminKey, id, activeOrgId || undefined),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['admin', 'quotas', adminKey] }),
  });
  const upsertWindowMut = useMutation({
    mutationFn: (p: Partial<BudgetWindowLimit>) => adminApi.upsertBudgetWindow(adminKey, p),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['admin', 'budget-windows', adminKey] }); setBwModal(false); },
  });

  const openQuota = (p?: QuotaPolicy) => {
    upsertQuotaMut.reset();
    setQf({
      id: p?.id || '', scope_type: p?.scope_type || 'model_per_key', scope_id: p?.scope_id || '', model_pattern: p?.model_pattern || '*',
      rpm: p?.rpm_limit ? String(p.rpm_limit) : '', tpm: p?.tpm_limit ? String(p.tpm_limit) : '',
      itpm: p?.itpm_limit ? String(p.itpm_limit) : '', otpm: p?.otpm_limit ? String(p.otpm_limit) : '',
      tpd: p?.tpd_limit ? String(p.tpd_limit) : '', conc: p?.max_concurrent ? String(p.max_concurrent) : '',
      budget: microsToUsdInput(p?.max_budget_micros), reset: p?.budget_reset_period || 'monthly',
      iter: p?.max_iterations ? String(p.max_iterations) : '', ttl: p?.window_ttl_sec ? String(p.window_ttl_sec) : '', active: p ? p.is_active : true,
    });
    setQuotaModal(true);
  };

  const openWindow = (w?: BudgetWindowLimit) => {
    upsertWindowMut.reset();
    setBf({
      id: w?.id || '', scope_type: w?.scope_type || 'key', scope_id: w?.scope_id || '',
      window_type: w?.window_type || 'daily', budget: microsToUsdInput(w?.max_budget_micros),
      reset_at: w?.window_reset_at ? w.window_reset_at.slice(0, 16) : '',
    });
    setBwModal(true);
  };

  const quotas = quotasQ.data?.data || [];
  const windows = windowsQ.data?.data || [];
  const keys = (keysQ.data?.data || []).filter((k) => k.is_active);
  const num = (v: any) => parseInt(v, 10) || 0;

  return (
    <div className="space-y-6">
      <div className={card}>
        <div className="flex flex-wrap items-center justify-between gap-2">
          <h3 className="text-sm font-semibold text-brand-title flex items-center gap-2"><Layers className="w-4 h-4 text-accent-primary" />Per-Model &amp; Multi-Dimensional Quotas (ITPM / OTPM / TPD)</h3>
          <div className="flex flex-wrap items-center gap-2">
            <select value={scopeFilter} onChange={(e) => setScopeFilter(e.target.value)} className="bg-surface-input border border-border-subtle text-brand-body text-xs rounded px-2 py-1 font-mono">
              <option value="">All scopes</option>
              {SCOPES.map((s) => <option key={s} value={s}>{s}</option>)}
            </select>
            <input value={modelFilter} onChange={(e) => setModelFilter(e.target.value)} placeholder="Model..." className="bg-surface-input border border-border-subtle text-brand-body text-xs rounded px-2 py-1 font-mono w-28" />
            <button onClick={() => openQuota()} className={`${BTN_PRIMARY} flex items-center gap-1`}><Plus className="w-3.5 h-3.5" />Upsert Quota</button>
          </div>
        </div>
        {quotasQ.isError && <ErrorAlert error={quotasQ.error} title="Failed to load quotas" />}
        {deleteQuotaMut.isError && <ErrorAlert error={deleteQuotaMut.error} title="Failed to delete quota" />}
        <div className="overflow-x-auto">
          <table className={tbl}>
            <thead className={thead}><tr>{['Scope', 'Model', 'RPM / TPM', 'ITPM / OTPM / TPD', 'Budget', 'Status', 'Actions'].map((h) => <th key={h} className={th}>{h}</th>)}</tr></thead>
            <tbody className="divide-y divide-border-subtle">
              {quotasQ.isLoading ? <tr><td colSpan={7} className="px-3 py-5 text-center text-brand-muted">Loading...</td></tr>
                : quotas.length === 0 ? <tr><td colSpan={7} className="px-3 py-5 text-center text-brand-muted">No quota policies.</td></tr>
                : quotas.map((q) => (
                  <tr key={q.id}>
                    <td className={th}><Badge variant="info" size="sm">{q.scope_type}</Badge><div className="text-brand-title">{q.scope_id}</div></td>
                    <td className={`${th} text-accent-primary`}>{q.model_pattern || '*'}</td>
                    <td className={th}>RPM:{q.rpm_limit || '∞'} TPM:{q.tpm_limit || '∞'}</td>
                    <td className={th}>I:{q.itpm_limit || '∞'} O:{q.otpm_limit || '∞'} D:{q.tpd_limit || '∞'}</td>
                    <td className={th}>{q.max_budget_micros > 0 ? `${formatUSD(q.spent_micros)}/${formatUSD(q.max_budget_micros)}` : '∞'}</td>
                    <td className={th}><Badge variant={q.is_active ? 'success' : 'danger'} size="sm">{q.is_active ? 'Active' : 'Off'}</Badge></td>
                    <td className={`${th} space-x-1`}>
                      <button onClick={() => openQuota(q)} className="p-1 text-brand-muted hover:text-brand-title"><Pencil className="w-3.5 h-3.5" /></button>
                      <button onClick={() => { if (confirm('Delete quota policy?')) deleteQuotaMut.mutate(q.id); }} className="p-1 text-brand-muted hover:text-status-danger"><Trash2 className="w-3.5 h-3.5" /></button>
                    </td>
                  </tr>
                ))}
            </tbody>
          </table>
        </div>
      </div>

      <div className={card}>
        <div className="flex items-center justify-between">
          <h3 className="text-sm font-semibold text-brand-title flex items-center gap-2"><Clock className="w-4 h-4 text-accent-primary" />Multi-Window Budgets (Daily, Weekly, Monthly, Rolling 24h)</h3>
          <button onClick={() => openWindow()} className={`${BTN_PRIMARY} flex items-center gap-1`}><Plus className="w-3.5 h-3.5" />Upsert Window</button>
        </div>
        {windowsQ.isError && <ErrorAlert error={windowsQ.error} title="Failed to load windows" />}
        <div className="overflow-x-auto">
          <table className={tbl}>
            <thead className={thead}><tr>{['Scope', 'Window', 'Spent / Cap', 'Reset At', 'Actions'].map((h) => <th key={h} className={th}>{h}</th>)}</tr></thead>
            <tbody className="divide-y divide-border-subtle">
              {windows.length === 0 ? <tr><td colSpan={5} className="px-3 py-4 text-center text-brand-muted">No budget windows configured.</td></tr>
                : windows.map((w) => (
                  <tr key={w.id}>
                    <td className={th}><Badge variant="info" size="sm">{w.scope_type}</Badge> {w.scope_id}</td>
                    <td className={th}><Badge variant="primary" size="sm">{w.window_type}</Badge></td>
                    <td className={th}>{formatUSD(w.spent_micros)} / {formatUSD(w.max_budget_micros)}</td>
                    <td className={`${th} text-brand-muted`}>{w.window_reset_at ? new Date(w.window_reset_at).toLocaleString() : 'Rolling'}</td>
                    <td className={th}><button onClick={() => openWindow(w)} className="p-1 text-brand-muted hover:text-brand-title"><Pencil className="w-3.5 h-3.5" /></button></td>
                  </tr>
                ))}
            </tbody>
          </table>
        </div>
      </div>

      <div className={card}>
        <h3 className="text-sm font-semibold text-brand-title flex items-center gap-2"><Zap className="w-4 h-4 text-accent-primary" />Temporary Key Budget Boosts</h3>
        <div className="overflow-x-auto">
          <table className={tbl}>
            <thead className={thead}><tr>{['Key', 'Base Cap', 'Active Boost', 'Action'].map((h) => <th key={h} className={th}>{h}</th>)}</tr></thead>
            <tbody className="divide-y divide-border-subtle">
              {keys.length === 0 ? <tr><td colSpan={4} className="px-3 py-4 text-center text-brand-muted">No active keys in {activeOrgId}.</td></tr>
                : keys.map((k) => {
                  const active = !!k.temp_budget_increase_micros && k.temp_budget_increase_micros > 0 && !!k.temp_budget_expires_at && new Date(k.temp_budget_expires_at).getTime() > Date.now();
                  return (
                    <tr key={k.id}>
                      <td className={th}>{k.name} ({k.key_prefix})</td>
                      <td className={th}>{k.max_budget_micros ? formatUSD(k.max_budget_micros) : 'Unlimited'}</td>
                      <td className={th}>{active ? <Badge variant="success" size="sm">+{formatUSD(k.temp_budget_increase_micros)} until {new Date(k.temp_budget_expires_at!).toLocaleString()}</Badge> : 'None'}</td>
                      <td className={th}><button onClick={() => setBoostKey(k)} className="px-2 py-1 rounded bg-surface-elevated border border-border-subtle text-accent-primary text-[11px]">Set Boost</button></td>
                    </tr>
                  );
                })}
            </tbody>
          </table>
        </div>
      </div>

      <FormModal
        open={quotaModal}
        onClose={() => setQuotaModal(false)}
        title={qf.id ? 'Edit Quota Policy' : 'Upsert Quota Policy'}
        maxWidth="lg"
        onSubmit={() => upsertQuotaMut.mutate({
          ...(qf.id ? { id: qf.id } : {}), org_id: activeOrgId, scope_type: qf.scope_type, scope_id: (qf.scope_id || '').trim(),
          model_pattern: (qf.model_pattern || '').trim() || '*', rpm_limit: num(qf.rpm), tpm_limit: num(qf.tpm),
          itpm_limit: num(qf.itpm), otpm_limit: num(qf.otpm), tpd_limit: num(qf.tpd), max_concurrent: num(qf.conc),
          max_budget_micros: usdToMicros(qf.budget || '') ?? 0, budget_reset_period: qf.reset as BudgetResetPeriod,
          max_iterations: num(qf.iter), window_ttl_sec: num(qf.ttl), is_active: !!qf.active,
        })}
        pending={upsertQuotaMut.isPending}
      >
        {upsertQuotaMut.isError && <ErrorAlert error={upsertQuotaMut.error} title="Save failed" />}
        <div className="grid grid-cols-3 gap-2">
          <Field label="Scope Type"><select value={qf.scope_type} onChange={(e) => setQ('scope_type', e.target.value)} className={INPUT_CLS}>{SCOPES.map((s) => <option key={s} value={s}>{s}</option>)}</select></Field>
          <Field label="Scope ID *"><input required value={qf.scope_id || ''} onChange={(e) => setQ('scope_id', e.target.value)} placeholder={activeOrgId} className={MONO_INPUT_CLS} /></Field>
          <Field label="Model Pattern"><input value={qf.model_pattern || ''} onChange={(e) => setQ('model_pattern', e.target.value)} placeholder="*" className={MONO_INPUT_CLS} /></Field>
        </div>
        <div className="grid grid-cols-5 gap-2">
          {[['RPM', 'rpm'], ['TPM', 'tpm'], ['ITPM', 'itpm'], ['OTPM', 'otpm'], ['TPD', 'tpd']].map(([l, k]) => (
            <Field key={k} label={l}><input type="number" min="0" value={qf[k] || ''} onChange={(e) => setQ(k, e.target.value)} className={MONO_INPUT_CLS} /></Field>
          ))}
        </div>
        <div className="grid grid-cols-5 gap-2">
          <Field label="Conc"><input type="number" min="0" value={qf.conc || ''} onChange={(e) => setQ('conc', e.target.value)} className={MONO_INPUT_CLS} /></Field>
          <Field label="Budget ($)"><input type="number" step="0.01" min="0" value={qf.budget || ''} onChange={(e) => setQ('budget', e.target.value)} className={MONO_INPUT_CLS} /></Field>
          <Field label="Reset"><select value={qf.reset} onChange={(e) => setQ('reset', e.target.value)} className={INPUT_CLS}><option value="daily">daily</option><option value="monthly">monthly</option><option value="never">never</option></select></Field>
          <Field label="Max Iter"><input type="number" min="0" value={qf.iter || ''} onChange={(e) => setQ('iter', e.target.value)} className={MONO_INPUT_CLS} /></Field>
          <Field label="TTL (s)"><input type="number" min="0" value={qf.ttl || ''} onChange={(e) => setQ('ttl', e.target.value)} className={MONO_INPUT_CLS} /></Field>
        </div>
        <label className="flex items-center gap-2 text-xs text-brand-body"><input type="checkbox" checked={!!qf.active} onChange={(e) => setQ('active', e.target.checked)} />Active</label>
      </FormModal>

      <FormModal
        open={bwModal}
        onClose={() => setBwModal(false)}
        title={bf.id ? 'Edit Budget Window' : 'Upsert Budget Window'}
        onSubmit={() => {
          const d = bf.reset_at ? new Date(bf.reset_at) : null;
          upsertWindowMut.mutate({
            ...(bf.id ? { id: bf.id } : {}), org_id: activeOrgId, scope_type: bf.scope_type, scope_id: (bf.scope_id || '').trim(),
            window_type: bf.window_type, max_budget_micros: usdToMicros(bf.budget || '') ?? 0,
            ...(d && !isNaN(d.getTime()) ? { window_reset_at: d.toISOString() } : {}),
          });
        }}
        pending={upsertWindowMut.isPending}
      >
        {upsertWindowMut.isError && <ErrorAlert error={upsertWindowMut.error} title="Save failed" />}
        <div className="grid grid-cols-2 gap-3">
          <Field label="Scope Type"><select value={bf.scope_type} onChange={(e) => setB('scope_type', e.target.value)} className={INPUT_CLS}>{SCOPES.map((s) => <option key={s} value={s}>{s}</option>)}</select></Field>
          <Field label="Scope ID *"><input required value={bf.scope_id || ''} onChange={(e) => setB('scope_id', e.target.value)} className={MONO_INPUT_CLS} /></Field>
          <Field label="Window"><select value={bf.window_type} onChange={(e) => setB('window_type', e.target.value)} className={INPUT_CLS}>{WINDOWS.map((w) => <option key={w} value={w}>{w}</option>)}</select></Field>
          <Field label="Max Budget ($) *"><input required type="number" step="0.01" min="0" value={bf.budget || ''} onChange={(e) => setB('budget', e.target.value)} className={MONO_INPUT_CLS} /></Field>
        </div>
        <Field label="Reset At"><input type="datetime-local" value={bf.reset_at || ''} onChange={(e) => setB('reset_at', e.target.value)} className={MONO_INPUT_CLS} /></Field>
      </FormModal>

      <TempBudgetModal target={boostKey} onClose={() => setBoostKey(null)} />
    </div>
  );
};
