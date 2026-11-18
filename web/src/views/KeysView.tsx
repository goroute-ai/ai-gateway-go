import React, { useMemo, useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { adminApi } from '../api/admin';
import { useAuth } from '../context/AuthContext';
import { Modal, FormModal, Field, INPUT_CLS, MONO_INPUT_CLS, BTN_PRIMARY } from '../components/common/Modal';
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
import { Key, Plus, Pencil, RotateCw, Trash2, Copy, Check, AlertTriangle, Zap, Clock } from 'lucide-react';

type AllowMode = 'inherit' | 'deny' | 'allowlist';
type AllowState = { mode: AllowMode; text: string };
const INHERIT: AllowState = { mode: 'inherit', text: '' };
const ROLES: Role[] = ['developer', 'service_account', 'team_admin', 'org_admin', 'org_viewer', 'viewer', 'platform_admin'];
const KEY_TYPES: Array<[KeyType, string]> = [
  ['default', 'default (Custom)'],
  ['llm_api', 'llm_api (Data Plane)'],
  ['management', 'management (/admin/v1)'],
  ['read_only', 'read_only (GET Only)'],
  ['service_account', 'service_account'],
];
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
        <option value="inherit">Inherit (Org/Team)</option>
        <option value="deny">Deny All ([])</option>
        <option value="allowlist">Custom Allowlist</option>
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
  const [copied, setCopied] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);
  const [rotateTarget, setRotateTarget] = useState<VirtualKey | null>(null);
  const [gracePeriodSec, setGracePeriodSec] = useState('3600');
  const [localGraceByKeyId, setLocalGraceByKeyId] = useState<Record<string, string>>({});
  const [boostTarget, setBoostTarget] = useState<VirtualKey | null>(null);

  const [name, setName] = useState('');
  const [teamId, setTeamId] = useState('');
  const [userId, setUserId] = useState('');
  const [role, setRole] = useState<Role>('developer');
  const [keyType, setKeyType] = useState<KeyType>('default');
  const [rotationIntervalSec, setRotationIntervalSec] = useState('0');
  const [keyRotationAt, setKeyRotationAt] = useState('');
  const [expiresAt, setExpiresAt] = useState('');
  const [maxBudgetUSD, setMaxBudgetUSD] = useState('');
  const [softBudgetUSD, setSoftBudgetUSD] = useState('');
  const [throttleOnBudget, setThrottleOnBudget] = useState(false);
  const [budgetFallbacksText, setBudgetFallbacksText] = useState('');
  const [budgetResetPeriod, setBudgetResetPeriod] = useState<BudgetResetPeriod>('monthly');
  const [rpmLimit, setRpmLimit] = useState('');
  const [tpmLimit, setTpmLimit] = useState('');
  const [maxConcurrent, setMaxConcurrent] = useState('');
  const [allowedModels, setAllowedModels] = useState('');
  const [allowedEndpoints, setAllowedEndpoints] = useState('');
  const [mcpAllow, setMcpAllow] = useState<AllowState>(INHERIT);
  const [a2aAllow, setA2aAllow] = useState<AllowState>(INHERIT);
  const [clientAppAllow, setClientAppAllow] = useState<AllowState>(INHERIT);

  const { data: keysData, isLoading, isError, error, refetch } = useQuery({
    queryKey: ['admin', 'keys', adminKey, activeOrgId],
    queryFn: () => adminApi.listKeys(adminKey, activeOrgId),
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

  const rotateMutation = useMutation({
    mutationFn: ({ keyId, graceSec }: { keyId: string; graceSec: number }) =>
      adminApi.rotateKey(adminKey, keyId, { org_id: activeOrgId, grace_period_seconds: graceSec }),
    onSuccess: (rotatedKey, vars) => {
      qc.invalidateQueries({ queryKey: ['admin', 'keys', adminKey] });
      qc.invalidateQueries({ queryKey: ['admin', 'audit-logs', adminKey] });
      const graceUntil = vars.graceSec > 0 ? new Date(Date.now() + vars.graceSec * 1000).toISOString() : null;
      setLocalGraceByKeyId((p) => {
        const next = { ...p };
        if (graceUntil) next[vars.keyId] = graceUntil;
        else delete next[vars.keyId];
        return next;
      });
      setRotateTarget(null);
      if (rotatedKey.raw_key) {
        setNewKeySecret(rotatedKey.raw_key);
        setNewKeyGraceUntil(graceUntil);
        setCapturedVirtualKey(rotatedKey.raw_key);
      }
    },
  });

  const revokeMutation = useMutation({
    mutationFn: (keyId: string) => adminApi.revokeKey(adminKey, keyId),
    onSuccess: (_, keyId) => {
      qc.invalidateQueries({ queryKey: ['admin', 'keys', adminKey] });
      setLocalGraceByKeyId((p) => { const next = { ...p }; delete next[keyId]; return next; });
    },
  });

  const resetForm = () => {
    setFormError(null);
    setName(''); setTeamId(''); setUserId(''); setRole('developer'); setKeyType('default');
    setRotationIntervalSec('0'); setKeyRotationAt(''); setExpiresAt('');
    setMaxBudgetUSD(''); setSoftBudgetUSD(''); setThrottleOnBudget(false); setBudgetFallbacksText('');
    setBudgetResetPeriod('monthly'); setRpmLimit(''); setTpmLimit(''); setMaxConcurrent('');
    setAllowedModels(''); setAllowedEndpoints('');
    setMcpAllow(INHERIT); setA2aAllow(INHERIT); setClientAppAllow(INHERIT);
  };

  const openEditModal = (k: VirtualKey) => {
    issueMutation.reset();
    setFormError(null);
    setEditingKeyId(k.id);
    setName(k.name); setTeamId(k.team_id || ''); setUserId(k.user_id || '');
    setRole(k.role || 'developer'); setKeyType(k.key_type || 'default');
    setRotationIntervalSec(k.rotation_interval_sec ? String(k.rotation_interval_sec) : '0');
    setKeyRotationAt(k.key_rotation_at ? k.key_rotation_at.slice(0, 16) : '');
    setExpiresAt(k.expires_at ? k.expires_at.slice(0, 16) : '');
    setMaxBudgetUSD(microsToUsdInput(k.max_budget_micros));
    setSoftBudgetUSD(microsToUsdInput(k.soft_budget_micros));
    setThrottleOnBudget(!!k.throttle_on_budget_exceeded);
    setBudgetFallbacksText(formatBudgetFallbacks(k.budget_fallbacks));
    setBudgetResetPeriod(k.budget_reset_period || 'monthly');
    setRpmLimit(k.rpm_limit ? String(k.rpm_limit) : '');
    setTpmLimit(k.tpm_limit ? String(k.tpm_limit) : '');
    setMaxConcurrent(k.max_concurrent_requests ? String(k.max_concurrent_requests) : '');
    setAllowedModels((k.allowed_models || []).join(', '));
    setAllowedEndpoints((k.allowed_endpoints || []).join(', '));
    setMcpAllow(initAllow(k.allowed_mcp_servers));
    setA2aAllow(initAllow(k.allowed_a2a_agents));
    setClientAppAllow(initAllow(k.allowed_client_apps));
    setShowIssueModal(true);
  };

  const handleIssueSubmit = () => {
    if (!name.trim()) return;
    setFormError(null);
    let fb: Record<string, string[]> = {};
    try { fb = parseBudgetFallbacks(budgetFallbacksText); }
    catch (err: any) { setFormError(err?.message || 'Invalid fallbacks'); return; }

    const isEdit = !!editingKeyId;
    const payload: Partial<VirtualKey> = {
      org_id: activeOrgId, name: name.trim(), team_id: teamId.trim(), user_id: userId.trim(),
      role, key_type: keyType, rotation_interval_sec: Math.max(0, parseInt(rotationIntervalSec, 10) || 0),
      budget_reset_period: budgetResetPeriod, throttle_on_budget_exceeded: throttleOnBudget,
      rpm_limit: rpmLimit ? parseInt(rpmLimit, 10) : 0,
      tpm_limit: tpmLimit ? parseInt(tpmLimit, 10) : 0,
      max_concurrent_requests: maxConcurrent ? parseInt(maxConcurrent, 10) : 0,
      allowed_models: allowedModels.trim() ? parseCSV(allowedModels) : [],
    };
    if (keyRotationAt) { const d = new Date(keyRotationAt); if (!isNaN(d.getTime())) payload.key_rotation_at = d.toISOString(); }
    if (expiresAt) { const d = new Date(expiresAt); if (!isNaN(d.getTime())) payload.expires_at = d.toISOString(); }
    const maxM = usdToMicros(maxBudgetUSD);
    if (maxM !== undefined) payload.max_budget_micros = maxM; else if (isEdit) payload.max_budget_micros = 0;
    const softM = usdToMicros(softBudgetUSD);
    if (softM !== undefined) payload.soft_budget_micros = softM; else if (isEdit) payload.soft_budget_micros = 0;
    if (Object.keys(fb).length > 0 || isEdit) payload.budget_fallbacks = fb;
    if (allowedEndpoints.trim() || isEdit) payload.allowed_endpoints = allowedEndpoints.trim() ? parseCSV(allowedEndpoints) : [];
    const mcpVal = encodeAllow(mcpAllow, isEdit); if (mcpVal !== undefined) payload.allowed_mcp_servers = mcpVal;
    const a2aVal = encodeAllow(a2aAllow, isEdit); if (a2aVal !== undefined) payload.allowed_a2a_agents = a2aVal;
    const appVal = encodeAllow(clientAppAllow, isEdit); if (appVal !== undefined) payload.allowed_client_apps = appVal;
    issueMutation.mutate(payload);
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-brand-title tracking-tight">Virtual API Keys</h1>
          <p className="text-xs text-brand-muted mt-1">Manage key_type presets, scheduled &amp; grace-period rotation, soft budgets, and rate limits</p>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={() => refetch()} className="px-3 py-1.5 rounded-lg border border-border-subtle hover:border-border-strong bg-surface-elevated text-xs font-medium text-brand-body hover:text-brand-title">Refresh</button>
          <button onClick={() => { issueMutation.reset(); setEditingKeyId(null); resetForm(); setShowIssueModal(true); }} className={`${BTN_PRIMARY} flex items-center gap-1.5`}>
            <Plus className="w-3.5 h-3.5" /><span>Issue Virtual Key</span>
          </button>
        </div>
      </div>

      {isError && <ErrorAlert error={error} title="Failed to load virtual keys" onRetry={() => refetch()} />}
      {revokeMutation.isError && <ErrorAlert error={revokeMutation.error} title="Failed to revoke virtual key" />}

      <div className="rounded-xl border border-border-subtle bg-surface-base/90 overflow-x-auto">
        <table className="w-full text-left text-xs">
          <thead className="bg-surface-elevated/60 text-brand-muted uppercase text-[10px] tracking-wider border-b border-border-subtle">
            <tr>
              {['Key Name / Type', 'Prefix / Schedule', 'Spend & Budget', 'Rate Limits', 'Models', 'Status & Grace'].map((h) => (
                <th key={h} className="px-5 py-3">{h}</th>
              ))}
              <th className="px-5 py-3 text-right">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border-subtle/40">
            {isLoading ? (
              <tr><td colSpan={7} className="px-6 py-8 text-center text-brand-muted">Loading virtual keys...</td></tr>
            ) : keysData?.data?.length ? keysData.data.map((k) => {
              const isRevoked = !k.is_active;
              const graceIso = k.deprecated_key_revoke_at || graceRevokeByKeyId[k.id];
              const hasBoost = !!k.temp_budget_increase_micros && k.temp_budget_increase_micros > 0 && !!k.temp_budget_expires_at && new Date(k.temp_budget_expires_at).getTime() > Date.now();
              const softHit = !!k.soft_budget_micros && k.soft_budget_micros > 0 && (k.spent_micros ?? 0) >= k.soft_budget_micros;
              return (
                <tr key={k.id} className="hover:bg-surface-hover/30 transition-colors">
                  <td className="px-5 py-3 font-medium text-brand-title">
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
                  <td className="px-5 py-3 font-mono text-brand-body">
                    <span className="bg-surface-code px-2 py-0.5 rounded border border-border-subtle">{k.key_prefix}••••</span>
                    {(k.rotation_interval_sec || k.key_rotation_at) && (
                      <div className="text-[10px] text-brand-muted mt-1 flex items-center gap-1">
                        <Clock className="w-3 h-3 shrink-0" />
                        <span>{k.rotation_interval_sec ? `Every ${fmtDuration(k.rotation_interval_sec)}` : 'Scheduled'}{k.key_rotation_at ? ` · ${new Date(k.key_rotation_at).toLocaleDateString()}` : ''}</span>
                      </div>
                    )}
                  </td>
                  <td className="px-5 py-3 font-mono">
                    <div className="text-brand-title font-semibold">{formatUSD(k.spent_micros, 4)}</div>
                    <div className="text-[10px] text-brand-muted">{k.max_budget_micros ? `Cap: ${formatUSD(k.max_budget_micros)}` : 'No budget cap'}</div>
                    {hasBoost && <div className="text-[10px] text-accent-primary">+{formatUSD(k.temp_budget_increase_micros)} until {new Date(k.temp_budget_expires_at!).toLocaleTimeString()}</div>}
                    {softHit && <div className="mt-1"><Badge variant="warning" size="sm">Soft Cap Alert</Badge></div>}
                    {(k.throttle_on_budget_exceeded || (k.budget_fallbacks && Object.keys(k.budget_fallbacks).length > 0)) && (
                      <div className="text-[10px] text-brand-muted">{k.throttle_on_budget_exceeded ? 'Throttle ' : ''}{k.budget_fallbacks && Object.keys(k.budget_fallbacks).length > 0 ? `Fallbacks(${Object.keys(k.budget_fallbacks).length})` : ''}</div>
                    )}
                  </td>
                  <td className="px-5 py-3 font-mono text-[11px] text-brand-muted">
                    <div>RPM: {k.rpm_limit ?? '∞'}</div>
                    <div>TPM: {k.tpm_limit ? k.tpm_limit.toLocaleString() : '∞'}</div>
                  </td>
                  <td className="px-5 py-3">
                    {k.allowed_models?.length ? <div className="flex flex-wrap gap-1 max-w-xs">{k.allowed_models.map((m) => <Badge key={m} size="sm">{m}</Badge>)}</div> : <span className="text-brand-muted font-mono text-[11px]">All Models</span>}
                  </td>
                  <td className="px-5 py-3 space-y-1">
                    <Badge variant={isRevoked ? 'danger' : 'success'} size="sm">{isRevoked ? 'Revoked' : 'Active'}</Badge>
                    {!isRevoked && graceIso && (
                      <div className="text-[10px] font-mono">
                        <Badge variant="warning" size="sm">Grace Hash Active</Badge>
                        <div className="text-brand-muted mt-0.5">Revokes {new Date(graceIso).toLocaleTimeString()}</div>
                      </div>
                    )}
                  </td>
                  <td className="px-5 py-3 text-right">
                    {!isRevoked && (
                      <div className="inline-flex items-center gap-1">
                        <button onClick={() => openEditModal(k)} className="text-brand-muted hover:text-brand-title p-1.5 rounded hover:bg-surface-elevated" title="Edit key"><Pencil className="w-3.5 h-3.5" /></button>
                        <button onClick={() => setBoostTarget(k)} className="text-brand-muted hover:text-accent-primary p-1.5 rounded hover:bg-surface-elevated" title="Temporary budget boost"><Zap className="w-3.5 h-3.5" /></button>
                        <button onClick={() => { rotateMutation.reset(); setRotateTarget(k); setGracePeriodSec('3600'); }} className="text-brand-muted hover:text-status-warning p-1.5 rounded hover:bg-surface-elevated" title="Rotate key with grace period"><RotateCw className="w-3.5 h-3.5" /></button>
                        <button onClick={() => { if (confirm(`Revoke key "${k.name}"?`)) revokeMutation.mutate(k.id); }} disabled={revokeMutation.isPending} className="text-brand-muted hover:text-status-danger p-1.5 rounded hover:bg-surface-elevated" title="Revoke key"><Trash2 className="w-3.5 h-3.5" /></button>
                      </div>
                    )}
                  </td>
                </tr>
              );
            }) : (
              <tr><td colSpan={7} className="px-6 py-8 text-center text-brand-muted">No virtual keys found for {activeOrgId}.</td></tr>
            )}
          </tbody>
        </table>
      </div>

      <FormModal
        open={showIssueModal}
        onClose={() => { setShowIssueModal(false); setEditingKeyId(null); }}
        title={editingKeyId ? 'Edit Virtual Key' : 'Issue New Virtual Key'}
        maxWidth="lg"
        onSubmit={handleIssueSubmit}
        pending={issueMutation.isPending || !name.trim()}
        submitLabel={editingKeyId ? 'Save Changes' : 'Issue Key'}
      >
        {formError && <ErrorAlert error={formError} title="Validation Error" />}
        {issueMutation.isError && <ErrorAlert error={issueMutation.error} title={editingKeyId ? 'Update failed' : 'Issue failed'} />}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          <Field label="Key Name *"><input required value={name} onChange={(e) => setName(e.target.value)} placeholder="production-backend" className={INPUT_CLS} /></Field>
          <Field label="Key Type Preset">
            <select value={keyType} onChange={(e) => setKeyType(e.target.value as KeyType)} className={INPUT_CLS}>
              {KEY_TYPES.map(([v, l]) => <option key={v} value={v}>{l}</option>)}
            </select>
          </Field>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          <Field label="Team"><select value={teamId} onChange={(e) => setTeamId(e.target.value)} className={INPUT_CLS}><option value="">Org-wide</option>{(teamsData?.data || []).map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}</select></Field>
          <Field label="User"><select value={userId} onChange={(e) => setUserId(e.target.value)} className={INPUT_CLS}><option value="">Unassigned</option>{(usersData?.data || []).map((u) => <option key={u.id} value={u.id}>{u.email}</option>)}</select></Field>
          <Field label="Expires At"><input type="datetime-local" value={expiresAt} onChange={(e) => setExpiresAt(e.target.value)} className={MONO_INPUT_CLS} /></Field>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
          <Field label="Role"><select value={role} onChange={(e) => setRole(e.target.value as Role)} className={INPUT_CLS}>{ROLES.map((r) => <option key={r} value={r}>{r}</option>)}</select></Field>
          <Field label="Rotation Interval (sec)">
            <div className="flex gap-1.5">
              <input type="number" min="0" value={rotationIntervalSec} onChange={(e) => setRotationIntervalSec(e.target.value)} className={MONO_INPUT_CLS} />
              <select value="" onChange={(e) => { if (e.target.value) setRotationIntervalSec(e.target.value); }} className={`${INPUT_CLS} w-20 shrink-0`}>
                <option value="">Set</option><option value="0">Off</option><option value="86400">1d</option><option value="604800">7d</option><option value="2592000">30d</option>
              </select>
            </div>
          </Field>
          <Field label="Next Rotation At"><input type="datetime-local" value={keyRotationAt} onChange={(e) => setKeyRotationAt(e.target.value)} className={MONO_INPUT_CLS} /></Field>
        </div>
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          <Field label="Budget Cap ($)"><input type="number" step="0.01" min="0" value={maxBudgetUSD} onChange={(e) => setMaxBudgetUSD(e.target.value)} placeholder="50.00" className={MONO_INPUT_CLS} /></Field>
          <Field label="Soft Alert ($)"><input type="number" step="0.01" min="0" value={softBudgetUSD} onChange={(e) => setSoftBudgetUSD(e.target.value)} placeholder="40.00" className={MONO_INPUT_CLS} /></Field>
          <Field label="Reset"><select value={budgetResetPeriod} onChange={(e) => setBudgetResetPeriod(e.target.value as BudgetResetPeriod)} className={INPUT_CLS}>{RESET_PERIODS.map((p) => <option key={p} value={p}>{p}</option>)}</select></Field>
          <label className="flex items-end pb-2 gap-2 text-xs text-brand-body"><input type="checkbox" checked={throttleOnBudget} onChange={(e) => setThrottleOnBudget(e.target.checked)} />Throttle</label>
        </div>
        <div className="grid grid-cols-3 gap-3">
          <Field label="RPM"><input type="number" min="0" value={rpmLimit} onChange={(e) => setRpmLimit(e.target.value)} className={MONO_INPUT_CLS} /></Field>
          <Field label="TPM"><input type="number" min="0" value={tpmLimit} onChange={(e) => setTpmLimit(e.target.value)} className={MONO_INPUT_CLS} /></Field>
          <Field label="Max Conc"><input type="number" min="0" value={maxConcurrent} onChange={(e) => setMaxConcurrent(e.target.value)} className={MONO_INPUT_CLS} /></Field>
        </div>
        <Field label="Budget Fallbacks (model: fb1, fb2)">
          <textarea rows={2} value={budgetFallbacksText} onChange={(e) => setBudgetFallbacksText(e.target.value)} placeholder="gpt-4o: gpt-4o-mini" className={MONO_INPUT_CLS} />
        </Field>
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
          <Field label="Allowed Models"><input value={allowedModels} onChange={(e) => setAllowedModels(e.target.value)} placeholder="fast, openai/gpt-4o" className={MONO_INPUT_CLS} /></Field>
          <Field label="Allowed Endpoints"><input value={allowedEndpoints} onChange={(e) => setAllowedEndpoints(e.target.value)} placeholder="/v1/* (blank=preset)" className={MONO_INPUT_CLS} /></Field>
        </div>
        <AllowlistField label="Allowed MCP Servers" state={mcpAllow} onChange={setMcpAllow} placeholder="mcp_github" />
        <AllowlistField label="Allowed A2A Agents" state={a2aAllow} onChange={setA2aAllow} placeholder="agent_research" />
        <AllowlistField label="Allowed Client Apps" state={clientAppAllow} onChange={setClientAppAllow} placeholder="cursor" />
      </FormModal>

      <FormModal
        open={!!rotateTarget}
        onClose={() => setRotateTarget(null)}
        title={`Rotate Key: ${rotateTarget?.name || ''}`}
        onSubmit={() => { if (rotateTarget) rotateMutation.mutate({ keyId: rotateTarget.id, graceSec: Math.max(0, parseInt(gracePeriodSec, 10) || 0) }); }}
        pending={rotateMutation.isPending}
        submitLabel="Rotate Key"
      >
        {rotateMutation.isError && <ErrorAlert error={rotateMutation.error} title="Rotation failed" />}
        <Field label="Grace Period (seconds, 0 = immediate revocation)">
          <input type="number" min="0" value={gracePeriodSec} onChange={(e) => setGracePeriodSec(e.target.value)} className={MONO_INPUT_CLS} />
        </Field>
        <div className="flex gap-1.5">
          {[['0', '0s'], ['300', '5m'], ['3600', '1h'], ['86400', '24h']].map(([v, l]) => (
            <button key={v} type="button" onClick={() => setGracePeriodSec(v)} className={`px-2 py-1 rounded text-[11px] font-mono border ${gracePeriodSec === v ? 'bg-accent-soft text-accent-primary border-accent-primary/30' : 'bg-surface-elevated text-brand-muted border-border'}`}>{l}</button>
          ))}
        </div>
      </FormModal>

      <TempBudgetModal target={boostTarget} onClose={() => setBoostTarget(null)} />

      <Modal isOpen={!!newKeySecret} onClose={() => setNewKeySecret(null)} title="Virtual API Key Secret" description="Copy this secret now; it will not be shown again." maxWidth="md">
        <div className="space-y-4">
          <div className="p-3 rounded-lg border status-warning flex items-start gap-2.5 text-xs">
            <AlertTriangle className="w-4 h-4 shrink-0 text-status-warning mt-0.5" />
            <div>
              <p className="font-semibold">Security Warning</p>
              <p className="text-[11px] opacity-85 mt-0.5">GoRoute only stores the SHA-256 hash of this key.</p>
              {newKeyGraceUntil && <p className="text-[11px] font-mono mt-1">Grace active until {new Date(newKeyGraceUntil).toLocaleString()}.</p>}
            </div>
          </div>
          <div className="relative">
            <pre className="p-3 rounded-lg bg-surface-code border border-border-strong font-mono text-xs text-status-success break-all select-all">{newKeySecret}</pre>
            <button onClick={() => { if (newKeySecret) { navigator.clipboard.writeText(newKeySecret); setCopied(true); setTimeout(() => setCopied(false), 2000); } }} className="absolute right-2 top-2 px-2.5 py-1 rounded bg-surface-elevated border border-border-subtle text-brand-body text-xs flex items-center gap-1">
              {copied ? <Check className="w-3.5 h-3.5 text-status-success" /> : <Copy className="w-3.5 h-3.5" />}<span>{copied ? 'Copied' : 'Copy'}</span>
            </button>
          </div>
          <div className="flex items-center justify-between">
            <button onClick={() => { setNewKeySecret(null); onNavigateToPlayground(); }} className="flex items-center gap-1 text-xs text-accent-primary hover:underline"><Zap className="w-3.5 h-3.5" />Test in Playground ↗</button>
            <button onClick={() => setNewKeySecret(null)} className={BTN_PRIMARY}>Done</button>
          </div>
        </div>
      </Modal>
    </div>
  );
};
