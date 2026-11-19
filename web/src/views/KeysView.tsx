import React, { useMemo, useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { adminApi } from '../api/admin';
import { useAuth } from '../context/AuthContext';
import { Modal, FormModal, Field, INPUT_CLS, MONO_INPUT_CLS, BTN_PRIMARY, THEAD_CLS } from '../components/common/Modal';
import { CodeBlock } from '../components/common/CodeBlock';
import { TempBudgetModal } from '../components/common/TempBudgetModal';
import { Badge } from '../components/common/Badge';
import { ErrorAlert } from '../components/common/ErrorAlert';
import {
  formatBudgetFallbacks,
  formatUSD,
  microsToUsdInput,
  parseBudgetFallbacks,
  usdToMicros,
} from '../utils/budget';
import type { VirtualKey, Role, BudgetResetPeriod, KeyType } from '../types';
import { Key, Plus, Pencil, RotateCw, AlertTriangle, Zap } from 'lucide-react';

type AllowMode = 'inherit' | 'deny' | 'allowlist';
type AllowState = { mode: AllowMode; text: string };
const INHERIT: AllowState = { mode: 'inherit', text: '' };
const ROLES: Role[] = ['developer', 'service_account', 'team_admin', 'org_admin', 'org_viewer', 'viewer', 'platform_admin'];
const KEY_TYPES: Array<[KeyType, string]> = [
  ['default', 'default'],
  ['llm_api', 'llm_api'],
  ['management', 'management'],
  ['read_only', 'read_only'],
  ['service_account', 'service_account'],
];
const td = 'px-5 py-3';
const RESET_PERIODS: BudgetResetPeriod[] = ['daily', 'monthly', 'never'];
const parseCSV = (s: string) => s.split(',').map((x) => x.trim()).filter(Boolean);
const initAllow = (v?: string[] | null): AllowState =>
  v == null ? INHERIT : v.length === 0 ? { mode: 'deny', text: '' } : { mode: 'allowlist', text: v.join(', ') };
const encodeAllow = (s: AllowState, isEdit: boolean): string[] | null | undefined =>
  s.mode === 'inherit' ? (isEdit ? null : undefined) : s.mode === 'deny' ? [] : parseCSV(s.text);

const fmtDuration = (sec?: number) => {
  if (!sec || sec <= 0) return 'Off';
  if (sec % 86400 === 0) return `${sec / 86400}d`;
  if (sec % 3600 === 0) return `${sec / 3600}h`;
  if (sec % 60 === 0) return `${sec / 60}m`;
  return `${sec}s`;
};

const AllowlistField: React.FC<{
  label: string;
  state: AllowState;
  onChange: (next: AllowState) => void;
  placeholder: string;
}> = ({ label, state, onChange, placeholder }) => (
  <Field label={label}>
    <div className="flex gap-2">
      <select
        value={state.mode}
        onChange={(e) => onChange({ ...state, mode: e.target.value as AllowMode })}
        className={`${INPUT_CLS} w-40 shrink-0`}
      >
        <option value="inherit">Inherit</option>
        <option value="deny">Deny</option>
        <option value="allowlist">Allowlist</option>
      </select>
      {state.mode === 'allowlist' && (
        <input type="text" value={state.text} onChange={(e) => onChange({ ...state, text: e.target.value })} placeholder={placeholder} className={MONO_INPUT_CLS} />
      )}
    </div>
  </Field>
);

export const KeysView: React.FC<{ onNavigateToPlayground: () => void }> = ({ onNavigateToPlayground }) => {
  const { adminKey, isUnlocked, activeOrgId, setCapturedVirtualKey } = useAuth();
  const qc = useQueryClient();

  const [showIssueModal, setShowIssueModal] = useState(false);
  const [editingKeyId, setEditingKeyId] = useState<string | null>(null);
  const [newKeySecret, setNewKeySecret] = useState<string | null>(null);
  const [newKeyGraceUntil, setNewKeyGraceUntil] = useState<string | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [rotateTarget, setRotateTarget] = useState<VirtualKey | null>(null);
  const [gracePeriodSec, setGracePeriodSec] = useState('3600');
  const [localGraceByKeyId, setLocalGraceByKeyId] = useState<Record<string, string>>({});
  const [boostTarget, setBoostTarget] = useState<VirtualKey | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [selectedIds, setSelectedIds] = useState<string[]>([]);

  const INIT_KF = {
    name: '', teamId: '', userId: '', role: 'developer' as Role, keyType: 'default' as KeyType,
    rotationIntervalSec: '0', keyRotationAt: '', expiresAt: '',
    maxBudgetUSD: '', softBudgetUSD: '', throttleOnBudget: false, budgetFallbacksText: '',
    budgetResetPeriod: 'monthly' as BudgetResetPeriod, rpmLimit: '', tpmLimit: '', maxConcurrent: '',
    minPriorityRank: '', allowedRoutingTags: '',
    allowedModels: '', allowedEndpoints: '', mcpAllow: INHERIT, a2aAllow: INHERIT, clientAppAllow: INHERIT,
  };
  const [kf, setKf] = useState(INIT_KF);
  const setK = <K extends keyof typeof INIT_KF>(k: K, v: (typeof INIT_KF)[K]) => setKf((p) => ({ ...p, [k]: v }));
  const inp = (l: string, k: 'name' | 'expiresAt' | 'keyRotationAt' | 'allowedModels' | 'allowedEndpoints' | 'maxBudgetUSD' | 'softBudgetUSD' | 'rpmLimit' | 'tpmLimit' | 'maxConcurrent' | 'minPriorityRank' | 'allowedRoutingTags', t = 'text', ph?: string, mono = true) => (
    <Field key={k} label={l}><input type={t} min={t === 'number' ? '0' : undefined} step={ph?.includes('.') ? '0.01' : undefined} value={kf[k]} onChange={(e) => setK(k, e.target.value)} placeholder={ph} className={mono ? MONO_INPUT_CLS : INPUT_CLS} /></Field>
  );

  const { data: keysData, isLoading, isError, error, refetch } = useQuery({
    queryKey: ['admin', 'keys', adminKey, activeOrgId, statusFilter, searchQuery],
    queryFn: () => adminApi.listKeys(adminKey, {
      org_id: activeOrgId,
      ...(statusFilter ? { status: statusFilter } : {}),
      ...(searchQuery.trim() ? { search: searchQuery.trim() } : {}),
    }),
    enabled: isUnlocked,
  });
  const { data: teamsData } = useQuery({
    queryKey: ['admin', 'teams', adminKey, activeOrgId],
    queryFn: () => adminApi.listTeams(adminKey, activeOrgId),
    enabled: isUnlocked && !!activeOrgId,
  });
  const { data: usersData } = useQuery({
    queryKey: ['admin', 'users', adminKey, activeOrgId],
    queryFn: () => adminApi.listUsers(adminKey, activeOrgId),
    enabled: isUnlocked && !!activeOrgId,
  });
  const { data: auditData } = useQuery({
    queryKey: ['admin', 'audit-logs', adminKey, activeOrgId, 'keys-grace'],
    queryFn: () => adminApi.listAuditLogs(adminKey, activeOrgId || undefined, 100),
    enabled: isUnlocked && !!activeOrgId,
    staleTime: 15000,
  });

  const graceRevokeByKeyId = useMemo(() => {
    const out: Record<string, string> = {};
    const nowMs = Date.now();
    const logs = [...(auditData?.data || [])].sort(
      (a, b) => new Date(a.created_at).getTime() - new Date(b.created_at).getTime()
    );
    for (const log of logs) {
      if (log.resource !== 'virtual_key' || !log.resource_id) continue;
      if (log.action === 'virtual_key.revoked') { delete out[log.resource_id]; continue; }
      if (log.action === 'virtual_key.rotated' || log.action === 'virtual_key.auto_rotated') {
        const exp = log.details?.deprecated_key_revoke_at;
        const iso = typeof exp === 'string' && exp
          ? exp
          : typeof log.details?.grace_period_seconds === 'number' && log.details.grace_period_seconds > 0
            ? new Date(new Date(log.created_at).getTime() + log.details.grace_period_seconds * 1000).toISOString()
            : null;
        if (iso && new Date(iso).getTime() > nowMs) out[log.resource_id] = iso;
        else delete out[log.resource_id];
      }
    }
    for (const [kid, iso] of Object.entries(localGraceByKeyId)) {
      if (new Date(iso).getTime() > nowMs) out[kid] = iso;
    }
    return out;
  }, [auditData, localGraceByKeyId]);

  const issueMutation = useMutation({
    mutationFn: (data: Partial<VirtualKey>) =>
      editingKeyId ? adminApi.updateKey(adminKey, editingKeyId, data) : adminApi.issueKey(adminKey, data),
    onSuccess: (resKey) => {
      qc.invalidateQueries({ queryKey: ['admin', 'keys', adminKey] });
      setShowIssueModal(false);
      setEditingKeyId(null);
      if (resKey.raw_key) {
        setNewKeySecret(resKey.raw_key);
        setNewKeyGraceUntil(null);
        setCapturedVirtualKey(resKey.raw_key);
      }
      resetForm();
    },
  });

  const invKeys = () => qc.invalidateQueries({ queryKey: ['admin', 'keys', adminKey] });
  const actionMut = useMutation({
    mutationFn: (fn: () => Promise<unknown>) => fn(),
    onSuccess: () => { setSelectedIds([]); invKeys(); },
  });

  const runRotate = (keyId: string, graceSec: number) =>
    actionMut.mutate(async () => {
      const rotatedKey = await adminApi.rotateKey(adminKey, keyId, { org_id: activeOrgId, grace_period_seconds: graceSec });
      qc.invalidateQueries({ queryKey: ['admin', 'audit-logs', adminKey] });
      const graceUntil = graceSec > 0 ? new Date(Date.now() + graceSec * 1000).toISOString() : null;
      setLocalGraceByKeyId((p) => { const n = { ...p }; if (graceUntil) n[keyId] = graceUntil; else delete n[keyId]; return n; });
      setRotateTarget(null);
      if (rotatedKey.raw_key) {
        setNewKeySecret(rotatedKey.raw_key);
        setNewKeyGraceUntil(graceUntil);
        setCapturedVirtualKey(rotatedKey.raw_key);
      }
      return rotatedKey;
    });

  const resetForm = () => { setFormError(null); setKf(INIT_KF); };

  const openEditModal = (k: VirtualKey) => {
    issueMutation.reset();
    setFormError(null);
    setEditingKeyId(k.id);
    setKf({
      name: k.name, teamId: k.team_id || '', userId: k.user_id || '',
      role: k.role || 'developer', keyType: k.key_type || 'default',
      rotationIntervalSec: k.rotation_interval_sec ? String(k.rotation_interval_sec) : '0',
      keyRotationAt: k.key_rotation_at ? k.key_rotation_at.slice(0, 16) : '',
      expiresAt: k.expires_at ? k.expires_at.slice(0, 16) : '',
      maxBudgetUSD: microsToUsdInput(k.max_budget_micros),
      softBudgetUSD: microsToUsdInput(k.soft_budget_micros),
      throttleOnBudget: !!k.throttle_on_budget_exceeded,
      budgetFallbacksText: formatBudgetFallbacks(k.budget_fallbacks),
      budgetResetPeriod: k.budget_reset_period || 'monthly',
      rpmLimit: k.rpm_limit ? String(k.rpm_limit) : '',
      tpmLimit: k.tpm_limit ? String(k.tpm_limit) : '',
      maxConcurrent: k.max_concurrent_requests ? String(k.max_concurrent_requests) : '',
      minPriorityRank: k.min_priority_rank ? String(k.min_priority_rank) : '',
      allowedRoutingTags: (k.allowed_routing_tags || []).join(', '),
      allowedModels: (k.allowed_models || []).join(', '),
      allowedEndpoints: (k.allowed_endpoints || []).join(', '),
      mcpAllow: initAllow(k.allowed_mcp_servers),
      a2aAllow: initAllow(k.allowed_a2a_agents),
      clientAppAllow: initAllow(k.allowed_client_apps),
    });
    setShowIssueModal(true);
  };

  const handleIssueSubmit = () => {
    if (!kf.name.trim()) return;
    setFormError(null);
    let fb: Record<string, string[]> = {};
    try { fb = parseBudgetFallbacks(kf.budgetFallbacksText); }
    catch (err: any) { setFormError(err?.message || 'Invalid fallbacks'); return; }

    const isEdit = !!editingKeyId;
    const payload: Partial<VirtualKey> = {
      org_id: activeOrgId, name: kf.name.trim(), team_id: kf.teamId.trim(), user_id: kf.userId.trim(),
      role: kf.role, key_type: kf.keyType, rotation_interval_sec: Math.max(0, parseInt(kf.rotationIntervalSec, 10) || 0),
      budget_reset_period: kf.budgetResetPeriod, throttle_on_budget_exceeded: kf.throttleOnBudget,
      rpm_limit: kf.rpmLimit ? parseInt(kf.rpmLimit, 10) : 0,
      tpm_limit: kf.tpmLimit ? parseInt(kf.tpmLimit, 10) : 0,
      max_concurrent_requests: kf.maxConcurrent ? parseInt(kf.maxConcurrent, 10) : 0,
      min_priority_rank: kf.minPriorityRank ? Math.max(0, parseInt(kf.minPriorityRank, 10) || 0) : 0,
      allowed_routing_tags: kf.allowedRoutingTags.trim() ? parseCSV(kf.allowedRoutingTags) : [],
      allowed_models: kf.allowedModels.trim() ? parseCSV(kf.allowedModels) : [],
    };
    if (kf.keyRotationAt) { const d = new Date(kf.keyRotationAt); if (!isNaN(d.getTime())) payload.key_rotation_at = d.toISOString(); }
    if (kf.expiresAt) { const d = new Date(kf.expiresAt); if (!isNaN(d.getTime())) payload.expires_at = d.toISOString(); }
    const maxM = usdToMicros(kf.maxBudgetUSD);
    if (maxM !== undefined) payload.max_budget_micros = maxM; else if (isEdit) payload.max_budget_micros = 0;
    const softM = usdToMicros(kf.softBudgetUSD);
    if (softM !== undefined) payload.soft_budget_micros = softM; else if (isEdit) payload.soft_budget_micros = 0;
    if (Object.keys(fb).length > 0 || isEdit) payload.budget_fallbacks = fb;
    if (kf.allowedEndpoints.trim() || isEdit) payload.allowed_endpoints = kf.allowedEndpoints.trim() ? parseCSV(kf.allowedEndpoints) : [];
    const mcpVal = encodeAllow(kf.mcpAllow, isEdit); if (mcpVal !== undefined) payload.allowed_mcp_servers = mcpVal;
    const a2aVal = encodeAllow(kf.a2aAllow, isEdit); if (a2aVal !== undefined) payload.allowed_a2a_agents = a2aVal;
    const appVal = encodeAllow(kf.clientAppAllow, isEdit); if (appVal !== undefined) payload.allowed_client_apps = appVal;
    issueMutation.mutate(payload);
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-brand-title tracking-tight">Virtual API Keys</h1>
          <p className="text-xs text-brand-muted mt-1">Keys, budgets &amp; limits</p>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={() => refetch()} className="px-3 py-1.5 rounded-lg border border-border-subtle bg-surface-elevated text-xs text-brand-body">Refresh</button>
          <button onClick={() => { issueMutation.reset(); setEditingKeyId(null); resetForm(); setShowIssueModal(true); }} className={`${BTN_PRIMARY} flex items-center gap-1.5`}>
            <Plus className="w-3.5 h-3.5" /><span>Issue Key</span>
          </button>
        </div>
      </div>

      {isError && <ErrorAlert error={error} title="Failed to load virtual keys" onRetry={() => refetch()} />}
      {actionMut.isError && <ErrorAlert error={actionMut.error} title="Key action failed" />}

      <div className="flex flex-wrap items-center justify-between gap-2 text-xs">
        <div className="flex items-center gap-2">
          <input value={searchQuery} onChange={(e) => setSearchQuery(e.target.value)} placeholder="Search..." className={`${INPUT_CLS} w-40`} />
          <select value={statusFilter} onChange={(e) => setStatusFilter(e.target.value)} className={`${INPUT_CLS} w-40`}>
            {[['', 'All'], ['active', 'Active'], ['revoked', 'Blocked'], ['expired', 'Expired']].map(([v, l]) => <option key={v} value={v}>{l}</option>)}
          </select>
        </div>
        {selectedIds.length > 0 && (
          <div className="flex items-center gap-2">
            <span className="text-brand-muted font-mono">{selectedIds.length}</span>
            {([['Block', false, 'text-status-danger'], ['Unblock', true, 'text-status-success']] as const).map(([lbl, act, cls]) => (
              <button key={lbl} onClick={() => actionMut.mutate(() => adminApi.bulkUpdateKeys(adminKey, { org_id: activeOrgId, key_ids: selectedIds, is_active: act }))} disabled={actionMut.isPending} className={`px-2 py-1 rounded border border-border-subtle ${cls}`}>{lbl}</button>
            ))}
            <button onClick={() => setSelectedIds([])} className="text-brand-muted">Clear</button>
          </div>
        )}
      </div>

      <div className="rounded-xl border border-border-subtle bg-surface-base/90 overflow-x-auto">
        <table className="w-full text-left text-xs">
          <thead className={THEAD_CLS}>
            <tr>
              <th className="px-3 py-3 w-8">
                <input
                  type="checkbox"
                  checked={!!keysData?.data?.length && selectedIds.length === keysData.data.length}
                  onChange={(e) => setSelectedIds(e.target.checked ? (keysData?.data || []).map((k) => k.id) : [])}
                />
              </th>
              {['Key', 'Prefix', 'Budget', 'Limits', 'Models', 'Status'].map((h) => (
                <th key={h} className={td}>{h}</th>
              ))}
              <th className={`${td} text-right`}>Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border-subtle/40">
            {isLoading ? (
              <tr><td colSpan={8} className="px-6 py-8 text-center text-brand-muted">Loading...</td></tr>
            ) : keysData?.data?.length ? keysData.data.map((k) => {
              const isRevoked = !k.is_active;
              const graceIso = k.deprecated_key_revoke_at || graceRevokeByKeyId[k.id];
              const hasBoost = !!k.temp_budget_increase_micros && k.temp_budget_increase_micros > 0 && !!k.temp_budget_expires_at && new Date(k.temp_budget_expires_at).getTime() > Date.now();
              const softHit = !!k.soft_budget_micros && k.soft_budget_micros > 0 && (k.spent_micros ?? 0) >= k.soft_budget_micros;
              const isChecked = selectedIds.includes(k.id);
              return (
                <tr key={k.id} className="hover:bg-surface-hover/30 transition-colors">
                  <td className="px-3 py-3">
                    <input
                      type="checkbox"
                      checked={isChecked}
                      onChange={(e) => setSelectedIds((p) => e.target.checked ? [...p, k.id] : p.filter((x) => x !== k.id))}
                    />
                  </td>
                  <td className={`${td} font-medium text-brand-title`}>
                    <div className="flex items-center gap-2 flex-wrap">
                      <Key className="w-3.5 h-3.5 text-accent-primary shrink-0" />
                      <span>{k.name}</span>
                      <Badge variant="info" size="sm">{k.key_type || 'default'}</Badge>
                    </div>
                    {(k.team_id || k.user_id || k.expires_at) && (
                      <div className="text-[10px] font-mono text-brand-muted mt-0.5 space-x-2">
                        {k.team_id && <span>team:{k.team_id}</span>}
                        {k.user_id && <span>user:{k.user_id}</span>}
                        {k.expires_at && <span>exp:{new Date(k.expires_at).toLocaleDateString()}</span>}
                      </div>
                    )}
                  </td>
                  <td className={`${td} font-mono text-brand-body`}>
                    <span className="bg-surface-code px-2 py-0.5 rounded border border-border-subtle">{k.key_prefix}••••</span>
                    {(k.rotation_interval_sec || k.key_rotation_at) && (
                      <div className="text-[10px] text-brand-muted mt-1">
                        {k.rotation_interval_sec ? `Every ${fmtDuration(k.rotation_interval_sec)}` : 'Scheduled'}{k.key_rotation_at ? ` · ${new Date(k.key_rotation_at).toLocaleDateString()}` : ''}
                      </div>
                    )}
                  </td>
                  <td className={`${td} font-mono`}>
                    <div className="text-brand-title font-semibold">{formatUSD(k.spent_micros, 4)}</div>
                    <div className="text-[10px] text-brand-muted">{k.max_budget_micros ? `Cap: ${formatUSD(k.max_budget_micros)}` : 'Unlimited'}</div>
                    {hasBoost && <div className="text-[10px] text-accent-primary">+{formatUSD(k.temp_budget_increase_micros)} until {new Date(k.temp_budget_expires_at!).toLocaleTimeString()}</div>}
                    {softHit && <div className="mt-1"><Badge variant="warning" size="sm">Soft Cap</Badge></div>}
                    {(k.throttle_on_budget_exceeded || (k.budget_fallbacks && Object.keys(k.budget_fallbacks).length > 0)) && (
                      <div className="text-[10px] text-brand-muted">{k.throttle_on_budget_exceeded ? 'Throttle ' : ''}{k.budget_fallbacks && Object.keys(k.budget_fallbacks).length > 0 ? `FB(${Object.keys(k.budget_fallbacks).length})` : ''}</div>
                    )}
                  </td>
                  <td className={`${td} font-mono text-[11px] text-brand-muted`}>
                    <div>RPM:{k.rpm_limit ?? '∞'} TPM:{k.tpm_limit ? k.tpm_limit.toLocaleString() : '∞'}</div>
                  </td>
                  <td className={td}>
                    {k.allowed_models?.length ? <div className="flex flex-wrap gap-1 max-w-xs">{k.allowed_models.map((m) => <Badge key={m} size="sm">{m}</Badge>)}</div> : <span className="text-brand-muted font-mono text-[11px]">All</span>}
                  </td>
                  <td className={`${td} space-y-1`}>
                    <Badge variant={isRevoked ? 'danger' : 'success'} size="sm">{isRevoked ? 'Revoked' : 'Active'}</Badge>
                    {!isRevoked && graceIso && (
                      <div className="text-[10px] font-mono">
                        <Badge variant="warning" size="sm">Grace</Badge>
                        <div className="text-brand-muted mt-0.5">{new Date(graceIso).toLocaleTimeString()}</div>
                      </div>
                    )}
                  </td>
                  <td className={`${td} text-right`}>
                    <div className="inline-flex items-center gap-1">
                      {!isRevoked ? (
                        <>
                          <button onClick={() => openEditModal(k)} className="text-brand-muted p-1" title="Edit"><Pencil className="w-3.5 h-3.5" /></button>
                          <button onClick={() => setBoostTarget(k)} className="text-brand-muted p-1" title="Temp budget"><Zap className="w-3.5 h-3.5" /></button>
                          <button onClick={() => { actionMut.reset(); setRotateTarget(k); setGracePeriodSec('3600'); }} className="text-brand-muted p-1" title="Rotate"><RotateCw className="w-3.5 h-3.5" /></button>
                          <button onClick={() => { if (confirm(`Reset spend for "${k.name}"?`)) actionMut.mutate(() => adminApi.resetKeySpend(adminKey, k.id)); }} className="text-brand-muted px-1 font-mono text-[10px]" title="Reset spend">$0</button>
                          <button onClick={() => { if (confirm(`Block "${k.name}"?`)) actionMut.mutate(async () => { const r = await adminApi.blockKey(adminKey, k.id, 'revoked'); setLocalGraceByKeyId((p) => { const n = { ...p }; delete n[k.id]; return n; }); return r; }); }} disabled={actionMut.isPending} className="text-status-danger px-1 text-[10px]" title="Block">Block</button>
                        </>
                      ) : (
                        <button onClick={() => actionMut.mutate(() => adminApi.unblockKey(adminKey, k.id))} disabled={actionMut.isPending} className="text-status-success px-1 text-[10px]">Unblock</button>
                      )}
                    </div>
                  </td>
                </tr>
              );
            }) : (
              <tr><td colSpan={8} className="px-6 py-8 text-center text-brand-muted">None for {activeOrgId}.</td></tr>
            )}
          </tbody>
        </table>
      </div>

      <FormModal
        open={showIssueModal}
        onClose={() => { setShowIssueModal(false); setEditingKeyId(null); }}
        title={editingKeyId ? 'Edit Key' : 'Issue Key'}
        maxWidth="lg"
        onSubmit={handleIssueSubmit}
        pending={issueMutation.isPending || !kf.name.trim()}
        submitLabel={editingKeyId ? 'Save' : 'Issue'}
      >
        {formError && <ErrorAlert error={formError} title="Validation Error" />}
        {issueMutation.isError && <ErrorAlert error={issueMutation.error} title={editingKeyId ? 'Update failed' : 'Issue failed'} />}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          {inp('Key Name *', 'name', 'text', 'production-backend', false)}
          <Field label="Key Type"><select value={kf.keyType} onChange={(e) => setK('keyType', e.target.value as KeyType)} className={INPUT_CLS}>{KEY_TYPES.map(([v, l]) => <option key={v} value={v}>{l}</option>)}</select></Field>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          <Field label="Team"><select value={kf.teamId} onChange={(e) => setK('teamId', e.target.value)} className={INPUT_CLS}><option value="">Org-wide</option>{(teamsData?.data || []).map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}</select></Field>
          <Field label="User"><select value={kf.userId} onChange={(e) => setK('userId', e.target.value)} className={INPUT_CLS}><option value="">Unassigned</option>{(usersData?.data || []).map((u) => <option key={u.id} value={u.id}>{u.email}</option>)}</select></Field>
          {inp('Expires At', 'expiresAt', 'datetime-local')}
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          <Field label="Role"><select value={kf.role} onChange={(e) => setK('role', e.target.value as Role)} className={INPUT_CLS}>{ROLES.map((r) => <option key={r} value={r}>{r}</option>)}</select></Field>
          <Field label="Rotation (sec)">
            <div className="flex gap-1.5">
              <input type="number" min="0" value={kf.rotationIntervalSec} onChange={(e) => setK('rotationIntervalSec', e.target.value)} className={MONO_INPUT_CLS} />
              <select value="" onChange={(e) => { if (e.target.value) setK('rotationIntervalSec', e.target.value); }} className={`${INPUT_CLS} w-20 shrink-0`}>
                <option value="">Set</option><option value="0">Off</option><option value="86400">1d</option><option value="604800">7d</option><option value="2592000">30d</option>
              </select>
            </div>
          </Field>
          {inp('Next Rotation', 'keyRotationAt', 'datetime-local')}
        </div>
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-2">
          {inp('Cap ($)', 'maxBudgetUSD', 'number', '50.00')}
          {inp('Soft ($)', 'softBudgetUSD', 'number', '40.00')}
          <Field label="Reset"><select value={kf.budgetResetPeriod} onChange={(e) => setK('budgetResetPeriod', e.target.value as BudgetResetPeriod)} className={INPUT_CLS}>{RESET_PERIODS.map((p) => <option key={p} value={p}>{p}</option>)}</select></Field>
          <label className="flex items-end pb-2 gap-1.5 text-xs"><input type="checkbox" checked={kf.throttleOnBudget} onChange={(e) => setK('throttleOnBudget', e.target.checked)} />Throttle</label>
        </div>
        <div className="grid grid-cols-3 gap-2">
          {inp('RPM', 'rpmLimit', 'number')}{inp('TPM', 'tpmLimit', 'number')}{inp('Conc', 'maxConcurrent', 'number')}
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
          {inp('Models', 'allowedModels', 'text', 'fast, openai/gpt-4o')}{inp('Endpoints', 'allowedEndpoints', 'text', '/v1/*')}
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
          {inp('Min Priority Rank', 'minPriorityRank', 'number', '0')}{inp('Allowed Routing Tags', 'allowedRoutingTags', 'text', 'tier:*, eu')}
        </div>
        {([['MCP', 'mcpAllow', 'mcp_github'], ['A2A', 'a2aAllow', 'agent_1'], ['Apps', 'clientAppAllow', 'cursor']] as const).map(([l, k, ph]) => (
          <AllowlistField key={l} label={l} state={kf[k]} onChange={(v) => setK(k, v)} placeholder={ph} />
        ))}
        <Field label="Fallbacks">
          <textarea rows={2} value={kf.budgetFallbacksText} onChange={(e) => setK('budgetFallbacksText', e.target.value)} placeholder="gpt-4o: gpt-4o-mini" className={MONO_INPUT_CLS} />
        </Field>
      </FormModal>

      <FormModal open={!!rotateTarget} onClose={() => setRotateTarget(null)} title={`Rotate: ${rotateTarget?.name || ''}`} onSubmit={() => { if (rotateTarget) runRotate(rotateTarget.id, Math.max(0, parseInt(gracePeriodSec, 10) || 0)); }} pending={actionMut.isPending} submitLabel="Rotate">
        {actionMut.isError && <ErrorAlert error={actionMut.error} title="Rotation failed" />}
        <Field label="Grace (s)"><input type="number" min="0" value={gracePeriodSec} onChange={(e) => setGracePeriodSec(e.target.value)} className={MONO_INPUT_CLS} /></Field>
        <div className="flex gap-1.5">
          {[['0', '0s'], ['300', '5m'], ['3600', '1h'], ['86400', '24h']].map(([v, l]) => (
            <button key={v} type="button" onClick={() => setGracePeriodSec(v)} className={`px-2 py-1 rounded text-[11px] font-mono border ${gracePeriodSec === v ? 'bg-accent-soft text-accent-primary border-accent-primary/30' : 'bg-surface-elevated text-brand-muted border-border'}`}>{l}</button>
          ))}
        </div>
      </FormModal>

      <TempBudgetModal target={boostTarget} onClose={() => setBoostTarget(null)} />

      <Modal isOpen={!!newKeySecret} onClose={() => setNewKeySecret(null)} title="API Key Secret" description="Shown once." maxWidth="md">
        <div className="space-y-3">
          <div className="p-2.5 rounded-lg border status-warning flex items-start gap-2 text-xs">
            <AlertTriangle className="w-4 h-4 shrink-0 text-status-warning mt-0.5" />
            <div className="text-[11px]">Only the SHA-256 hash is stored.{newKeyGraceUntil && ` Grace until ${new Date(newKeyGraceUntil).toLocaleString()}.`}</div>
          </div>
          {newKeySecret && <CodeBlock code={newKeySecret} language="api-key" />}
          <div className="flex items-center justify-between">
            <button onClick={() => { setNewKeySecret(null); onNavigateToPlayground(); }} className="flex items-center gap-1 text-xs text-accent-primary"><Zap className="w-3.5 h-3.5" />Playground ↗</button>
            <button onClick={() => setNewKeySecret(null)} className={BTN_PRIMARY}>Done</button>
          </div>
        </div>
      </Modal>
    </div>
  );
};
