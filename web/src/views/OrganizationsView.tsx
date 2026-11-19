import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { adminApi } from '../api/admin';
import { useAuth } from '../context/AuthContext';
import { FormModal as BaseFormModal, INPUT_CLS, MONO_INPUT_CLS, BTN_PRIMARY } from '../components/common/Modal';
import { Badge } from '../components/common/Badge';
import { ErrorAlert } from '../components/common/ErrorAlert';
import {
  formatBudgetFallbacks,
  formatUSD,
  microsToUsdInput,
  parseBudgetFallbacks,
  usdToMicros,
} from '../utils/budget';
import type {
  Organization,
  Team,
  User,
  SelfServeBudgetPolicy,
} from '../types';
import { Building2, Users, Layers, ShieldCheck, Plus, Pencil, Trash2 } from 'lucide-react';

const cell = 'px-4 py-2.5';
const panel = 'bg-surface-base border border-border-subtle rounded-xl';
const rowCard = 'flex items-center justify-between p-2 rounded-lg bg-surface-elevated border border-border-subtle text-xs';
const icoBtn = 'p-1 text-brand-muted rounded';
const g2 = 'grid grid-cols-2 gap-3';

const FormModal: React.FC<{
  open: boolean;
  onClose: () => void;
  title: string;
  onSubmit: () => void;
  pending: boolean;
  error: unknown;
  submitLabel?: string;
  children: React.ReactNode;
}> = ({ open, onClose, title, onSubmit, pending, error, submitLabel = 'Save', children }) => (
  <BaseFormModal open={open} onClose={onClose} title={title} onSubmit={onSubmit} pending={pending} submitLabel={submitLabel}>
    {!!error && <ErrorAlert error={error} title={`${title} failed`} />}
    {children}
  </BaseFormModal>
);

const SoftPolicyFields: React.FC<{
  f: Record<string, any>;
  set: (k: string, v: any) => void;
}> = ({ f, set }) => (
  <>
    <div className="grid grid-cols-2 gap-3 items-center">
      <input
        type="number"
        step="0.01"
        min="0"
        value={f.softBudget || ''}
        onChange={(e) => set('softBudget', e.target.value)}
        placeholder="Soft Alert USD"
        className={INPUT_CLS}
      />
      <label className="flex items-center gap-2 text-xs text-brand-body cursor-pointer">
        <input type="checkbox" checked={!!f.throttle} onChange={(e) => set('throttle', e.target.checked)} />
        <span>Throttle</span>
      </label>
    </div>
    <textarea
      rows={2}
      value={f.fallbacks || ''}
      onChange={(e) => set('fallbacks', e.target.value)}
      placeholder="Fallbacks (model: fb1, fb2)"
      className={MONO_INPUT_CLS}
    />
  </>
);

export const OrganizationsView: React.FC = () => {
  const { adminKey, isUnlocked, activeOrgId, setActiveOrgId } = useAuth();
  const qc = useQueryClient();
  const [tab, setTab] = useState<'orgs' | 'teams' | 'users' | 'policies'>('orgs');
  const [modal, setModal] = useState<'org' | 'team' | 'user' | 'sub' | 'policy' | 'members' | null>(null);
  const [f, setF] = useState<Record<string, any>>({
    reset: 'monthly',
    role: 'developer',
    subProv: 'openai',
    subOn: true,
    subAuto: true,
    polOn: true,
    active: true,
    selfServe: 'disabled',
  });
  const [formErr, setFormErr] = useState<string | null>(null);
  const set = (k: string, v: any) => setF((p) => ({ ...p, [k]: v }));
  const openM = (kind: typeof modal, patch: Record<string, any>) => { setFormErr(null); setF((p) => ({ ...p, ...patch })); setModal(kind); };
  const txt = (k: string, ph: string, type = 'text') => (
    <input type={type} min={type === 'number' ? '0' : undefined} step={ph.includes('USD') ? '0.01' : undefined} value={f[k] || ''} onChange={(e) => set(k, e.target.value)} placeholder={ph} className={INPUT_CLS} />
  );
  const chk = (k: string, label: string) => (
    <label className="flex items-center gap-2 text-xs text-brand-body"><input type="checkbox" checked={!!f[k]} onChange={(e) => set(k, e.target.checked)} />{label}</label>
  );

  const orgsQ = useQuery({ queryKey: ['admin', 'orgs', adminKey], queryFn: () => adminApi.listOrgs(adminKey), enabled: isUnlocked });
  const teamsQ = useQuery({ queryKey: ['admin', 'teams', adminKey, activeOrgId], queryFn: () => adminApi.listTeams(adminKey, activeOrgId), enabled: isUnlocked && !!activeOrgId });
  const usersQ = useQuery({ queryKey: ['admin', 'users', adminKey, activeOrgId], queryFn: () => adminApi.listUsers(adminKey, activeOrgId), enabled: isUnlocked && !!activeOrgId });
  const subsQ = useQuery({ queryKey: ['admin', 'org-subscriptions', adminKey, activeOrgId], queryFn: () => adminApi.getOrgSubscriptions(adminKey, activeOrgId), enabled: isUnlocked && !!activeOrgId && tab === 'policies' });
  const polsQ = useQuery({ queryKey: ['admin', 'org-model-policies', adminKey, activeOrgId], queryFn: () => adminApi.getOrgModelPolicies(adminKey, activeOrgId), enabled: isUnlocked && !!activeOrgId && tab === 'policies' });
  const membersQ = useQuery({ queryKey: ['admin', 'team-members', adminKey, f.membersTeamId], queryFn: () => adminApi.listTeamMembers(adminKey, f.membersTeamId, activeOrgId), enabled: isUnlocked && modal === 'members' && !!f.membersTeamId });

  const inv = (k: string) => qc.invalidateQueries({ queryKey: ['admin', k, adminKey] });
  const saveMut = useMutation({
    mutationFn: ({ fn }: { k: string; fn: () => Promise<any>; pick?: boolean }) => fn(),
    onSuccess: (res, vars) => { inv(vars.k); setModal(null); if (vars.pick && res?.id && !f.editOrgId) setActiveOrgId(res.id); },
  });
  const delMut = useMutation({
    mutationFn: ({ kind, id }: { kind: 'teams' | 'users'; id: string }) =>
      kind === 'teams' ? adminApi.deleteTeam(adminKey, id) : adminApi.deleteUser(adminKey, id),
    onSuccess: (_, v) => inv(v.kind),
  });

  const budgetPatch = (budgetKey: string, zeroDefault = false) => {
    setFormErr(null);
    const maxB = usdToMicros(f[budgetKey] || '');
    const softB = usdToMicros(f.softBudget || '');
    const fb = parseBudgetFallbacks(f.fallbacks || '');
    return {
      ...(maxB !== undefined ? { max_budget_micros: maxB } : zeroDefault ? { max_budget_micros: 0 } : {}),
      ...(softB !== undefined ? { soft_budget_micros: softB } : zeroDefault ? { soft_budget_micros: 0 } : {}),
      throttle_on_budget_exceeded: !!f.throttle,
      ...(Object.keys(fb).length > 0 || zeroDefault ? { budget_fallbacks: fb } : {}),
    };
  };

  const orgs = orgsQ.data?.data || [];
  const teams = teamsQ.data?.data || [];
  const users = usersQ.data?.data || [];
  const subs = subsQ.data?.data || [];
  const pols = polsQ.data?.data || [];

  const renderBudgetCell = (entity: { max_budget_micros?: number; soft_budget_micros?: number; spent_micros?: number; throttle_on_budget_exceeded?: boolean; budget_fallbacks?: Record<string, string[]> }) => {
    const softHit = !!entity.soft_budget_micros && entity.soft_budget_micros > 0 && (entity.spent_micros ?? 0) >= entity.soft_budget_micros;
    const fbCount = entity.budget_fallbacks ? Object.keys(entity.budget_fallbacks).length : 0;
    return (
      <div className="font-mono">
        <div className="text-brand-body">{entity.max_budget_micros ? formatUSD(entity.max_budget_micros) : 'Unlimited'}</div>
        {(entity.soft_budget_micros || entity.throttle_on_budget_exceeded || fbCount > 0) && (
          <div className="text-[10px] text-brand-muted space-x-1">
            {entity.soft_budget_micros ? <span>soft:{formatUSD(entity.soft_budget_micros)}</span> : null}
            {entity.throttle_on_budget_exceeded ? <span>throttle</span> : null}
            {fbCount > 0 ? <span>fb:{fbCount}</span> : null}
          </div>
        )}
        {softHit && <Badge variant="warning" size="sm">Soft Cap</Badge>}
      </div>
    );
  };

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-bold text-brand-title flex items-center gap-2"><Building2 className="w-5 h-5 text-accent-primary" />Organizations &amp; Teams</h1>
          <p className="text-xs text-brand-muted mt-0.5">Org: <code className="text-accent-primary font-mono">{activeOrgId}</code></p>
        </div>
        <div className="flex gap-2">
          {tab === 'orgs' && <button onClick={() => openM('org', { editOrgId: '', orgName: '', orgId: '', orgBudget: '', softBudget: '', throttle: false, fallbacks: '', selfServe: 'disabled', orgRpm: '', orgTpm: '', orgGuarantee: false, devSelfKeys: false, webhookUrl: '', expiryDays: '7, 1' })} className={`${BTN_PRIMARY} flex items-center gap-1`}><Plus className="w-3.5 h-3.5" />New Org</button>}
          {tab === 'teams' && <button onClick={() => openM('team', { editTeamId: '', teamName: '', teamId: '', teamBudget: '', softBudget: '', throttle: false, fallbacks: '', teamRpm: '', teamGuarantee: false, defMemBudget: '', defMemRpm: '', teamPerms: '', teamMinPrio: '', teamAllowedTags: '', active: true })} className={`${BTN_PRIMARY} flex items-center gap-1`}><Plus className="w-3.5 h-3.5" />New Team</button>}
          {tab === 'users' && <button onClick={() => openM('user', { editUserId: '', email: '', userName: '', userId: '', userTeamId: '', userBudget: '', softBudget: '', throttle: false, fallbacks: '', role: 'developer', active: true })} className={`${BTN_PRIMARY} flex items-center gap-1`}><Plus className="w-3.5 h-3.5" />New User</button>}
          {tab === 'policies' && <>
            <button onClick={() => setModal('sub')} className="px-3 py-1.5 rounded-md border border-accent-primary/30 text-accent-primary text-xs font-semibold">+ Provider Sub</button>
            <button onClick={() => setModal('policy')} className={BTN_PRIMARY}>+ Model Policy</button>
          </>}
        </div>
      </div>

      <div className="flex gap-2 border-b border-border-subtle pb-2 overflow-x-auto">
        {([['orgs', `Orgs (${orgs.length})`, Building2], ['teams', `Teams (${teams.length})`, Layers], ['users', `Users (${users.length})`, Users], ['policies', 'Subscriptions & Policies', ShieldCheck]] as const).map(([id, label, Icon]) => (
          <button key={id} onClick={() => setTab(id)} className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium whitespace-nowrap ${tab === id ? 'bg-accent-soft text-accent-primary border border-accent-primary/30' : 'text-brand-muted hover:text-brand-title'}`}>
            <Icon className="w-3.5 h-3.5" />{label}
          </button>
        ))}
      </div>

      {(orgsQ.error || teamsQ.error || delMut.error || usersQ.error || subsQ.error || polsQ.error || (!modal && saveMut.error)) && (
        <ErrorAlert error={orgsQ.error || teamsQ.error || delMut.error || usersQ.error || subsQ.error || polsQ.error || saveMut.error} title="Operation failed" />
      )}

      {tab !== 'policies' ? (
        <div className={`${panel} overflow-x-auto`}>
          <table className="w-full text-left text-xs">
            <thead className="bg-surface-elevated border-b border-border-subtle text-brand-muted font-mono uppercase text-[10px]">
              <tr>
                {tab === 'orgs' && ['Name', 'ID', 'Budget', 'Spend', 'Reset', 'Status', 'Scope'].map((h) => <th key={h} className={cell}>{h}</th>)}
                {tab === 'teams' && ['Team', 'ID', 'Budget', 'Spend', 'Status', 'Actions'].map((h) => <th key={h} className={cell}>{h}</th>)}
                {tab === 'users' && ['Email', 'Name', 'Team', 'Budget', 'Role', 'Status', 'Actions'].map((h) => <th key={h} className={cell}>{h}</th>)}
              </tr>
            </thead>
            <tbody className="divide-y divide-border-subtle">
              {tab === 'orgs' && orgs.map((o) => (
                <tr key={o.id}>
                  <td className={`${cell} font-medium text-brand-title`}>{o.name}</td>
                  <td className={`${cell} font-mono text-brand-muted`}>{o.id}</td>
                  <td className={cell}>{renderBudgetCell(o)}</td>
                  <td className={`${cell} font-mono text-status-success`}>{formatUSD(o.spent_micros)}</td>
                  <td className={`${cell} font-mono capitalize text-brand-muted`}>{o.budget_reset_period || 'monthly'}</td>
                  <td className={cell}><Badge variant={o.is_active ? 'success' : 'danger'}>{o.is_active ? 'Active' : 'Inactive'}</Badge></td>
                  <td className={cell}>
                    <div className="flex items-center gap-2">
                      {activeOrgId === o.id ? <Badge variant="info">Selected</Badge> : <button onClick={() => setActiveOrgId(o.id)} className="text-accent-primary hover:underline font-mono">Switch</button>}
                      <button onClick={() => openM('org', { editOrgId: o.id, orgName: o.name, orgBudget: microsToUsdInput(o.max_budget_micros), softBudget: microsToUsdInput(o.soft_budget_micros), throttle: !!o.throttle_on_budget_exceeded, fallbacks: formatBudgetFallbacks(o.budget_fallbacks), reset: o.budget_reset_period || 'monthly', selfServe: o.self_serve_budget_policy || 'disabled', orgRpm: o.rpm_limit ? String(o.rpm_limit) : '', orgTpm: o.tpm_limit ? String(o.tpm_limit) : '', orgGuarantee: !!o.enforce_guaranteed_throughput, devSelfKeys: !!o.developer_self_serve_keys, webhookUrl: o.lifecycle_webhook_url || '', expiryDays: (o.key_expiry_alert_days || [7, 1]).join(', '), active: o.is_active })} className={icoBtn} title="Edit"><Pencil className="w-3.5 h-3.5" /></button>
                    </div>
                  </td>
                </tr>
              ))}
              {tab === 'teams' && teams.map((t) => (
                <tr key={t.id}>
                  <td className={`${cell} font-medium text-brand-title`}>{t.name}</td>
                  <td className={`${cell} font-mono text-brand-muted`}>{t.id}</td>
                  <td className={cell}>{renderBudgetCell(t)}</td>
                  <td className={`${cell} font-mono text-status-success`}>{formatUSD(t.spent_micros)}</td>
                  <td className={cell}><Badge variant={t.is_active ? 'success' : 'danger'}>{t.is_active ? 'Active' : 'Inactive'}</Badge></td>
                  <td className={`${cell} flex items-center gap-1`}>
                    <button onClick={() => openM('members', { membersTeamId: t.id, membersTeamName: t.name, addUserIds: '', rmUserIds: '' })} className="px-1.5 py-0.5 text-[10px] font-mono text-accent-primary hover:underline" title="Sync members">Members</button>
                    <button onClick={() => openM('team', { editTeamId: t.id, teamName: t.name, teamBudget: microsToUsdInput(t.max_budget_micros), softBudget: microsToUsdInput(t.soft_budget_micros), throttle: !!t.throttle_on_budget_exceeded, fallbacks: formatBudgetFallbacks(t.budget_fallbacks), teamRpm: t.rpm_limit ? String(t.rpm_limit) : '', teamGuarantee: !!t.enforce_guaranteed_throughput, defMemBudget: microsToUsdInput(t.default_member_max_budget_micros), defMemRpm: t.default_member_rpm_limit ? String(t.default_member_rpm_limit) : '', teamPerms: (t.team_member_permissions || []).join(', '), teamMinPrio: t.min_priority_rank ? String(t.min_priority_rank) : '', teamAllowedTags: (t.allowed_routing_tags || []).join(', '), active: t.is_active })} className={icoBtn} title="Edit"><Pencil className="w-3.5 h-3.5" /></button>
                    <button onClick={() => { if (confirm(`Delete team "${t.name}"?`)) delMut.mutate({ kind: 'teams', id: t.id }); }} disabled={delMut.isPending} className={icoBtn} title="Delete"><Trash2 className="w-3.5 h-3.5" /></button>
                  </td>
                </tr>
              ))}
              {tab === 'users' && users.map((u) => (
                <tr key={u.id}>
                  <td className={`${cell} font-medium text-brand-title`}>{u.email}</td>
                  <td className={`${cell} text-brand-body`}>{u.name || '—'}</td>
                  <td className={`${cell} font-mono text-brand-muted`}>{u.team_id || '—'}</td>
                  <td className={cell}>{renderBudgetCell(u)}</td>
                  <td className={cell}><Badge variant="info">{u.role}</Badge></td>
                  <td className={cell}><Badge variant={u.is_active ? 'success' : 'danger'}>{u.is_active ? 'Active' : 'Inactive'}</Badge></td>
                  <td className={`${cell} flex items-center gap-1`}>
                    <button onClick={() => openM('user', { editUserId: u.id, email: u.email, userName: u.name || '', userTeamId: u.team_id || '', userBudget: microsToUsdInput(u.max_budget_micros), softBudget: microsToUsdInput(u.soft_budget_micros), throttle: !!u.throttle_on_budget_exceeded, fallbacks: formatBudgetFallbacks(u.budget_fallbacks), role: u.role, active: u.is_active })} className={icoBtn} title="Edit"><Pencil className="w-3.5 h-3.5" /></button>
                    <button onClick={() => { if (confirm(`Delete user "${u.email}"?`)) delMut.mutate({ kind: 'users', id: u.id }); }} disabled={delMut.isPending} className={icoBtn} title="Delete"><Trash2 className="w-3.5 h-3.5" /></button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
          <div className={`${panel} p-4 space-y-2`}>
            <h3 className="text-sm font-semibold text-brand-title">Layer 2: Provider Subscriptions</h3>
            {subs.map((s) => (
              <div key={s.provider} className={rowCard}>
                <span className="font-mono font-semibold text-brand-title uppercase">{s.provider}</span>
                <button onClick={() => saveMut.mutate({ k: 'org-subscriptions', fn: () => adminApi.setOrgSubscription(adminKey, activeOrgId, { provider: s.provider, is_enabled: !s.is_enabled, auto_enable_new: s.auto_enable_new }) })}>
                  <Badge variant={s.is_enabled ? 'success' : 'danger'}>{s.is_enabled ? 'Enabled' : 'Disabled'}</Badge>
                </button>
              </div>
            ))}
          </div>
          <div className={`${panel} p-4 space-y-2`}>
            <h3 className="text-sm font-semibold text-brand-title">Layer 3: Org Model Policies</h3>
            {pols.map((p) => (
              <div key={p.global_model_id} className={rowCard}>
                <span className="font-mono text-brand-body truncate mr-2">{p.global_model_id}</span>
                <button onClick={() => saveMut.mutate({ k: 'org-model-policies', fn: () => adminApi.setOrgModelPolicy(adminKey, activeOrgId, { global_model_id: p.global_model_id, is_enabled: !p.is_enabled }) })}>
                  <Badge variant={p.is_enabled ? 'success' : 'danger'}>{p.is_enabled ? 'Allowed' : 'Blocked'}</Badge>
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      <FormModal open={modal === 'org'} onClose={() => setModal(null)} title={f.editOrgId ? `Edit Org` : 'Create Org'} submitLabel={f.editOrgId ? 'Save' : 'Create'} pending={saveMut.isPending} error={formErr || saveMut.error} onSubmit={() => {
        try {
          const days = String(f.expiryDays || '').split(',').map((s) => parseInt(s.trim(), 10)).filter((n) => !isNaN(n) && n > 0);
          const body: Partial<Organization> = {
            ...(!f.editOrgId && f.orgId?.trim() && { id: f.orgId.trim() }),
            name: (f.orgName || '').trim(),
            budget_reset_period: f.reset,
            self_serve_budget_policy: f.selfServe as SelfServeBudgetPolicy,
            rpm_limit: f.orgRpm ? parseInt(f.orgRpm, 10) : 0,
            tpm_limit: f.orgTpm ? parseInt(f.orgTpm, 10) : 0,
            enforce_guaranteed_throughput: !!f.orgGuarantee,
            developer_self_serve_keys: !!f.devSelfKeys,
            lifecycle_webhook_url: (f.webhookUrl || '').trim(),
            key_expiry_alert_days: days,
            ...budgetPatch('orgBudget', !!f.editOrgId),
          };
          saveMut.mutate({ k: 'orgs', pick: true, fn: () => f.editOrgId ? adminApi.updateOrg(adminKey, f.editOrgId, body) : adminApi.createOrg(adminKey, body) });
        } catch (err: any) { setFormErr(err?.message || 'Invalid fallbacks'); }
      }}>
        <input required value={f.orgName || ''} onChange={(e) => set('orgName', e.target.value)} placeholder="Org Name *" className={INPUT_CLS} />
        {!f.editOrgId && txt('orgId', 'Org ID (optional)')}
        <div className="grid grid-cols-3 gap-2">
          {txt('orgBudget', 'Max USD', 'number')}
          <select value={f.reset} onChange={(e) => set('reset', e.target.value)} className={INPUT_CLS}><option value="daily">Daily</option><option value="monthly">Monthly</option><option value="never">Never</option></select>
          <select value={f.selfServe} onChange={(e) => set('selfServe', e.target.value)} className={INPUT_CLS} title="Self-serve">
            <option value="disabled">Disabled</option>
            <option value="lower_only">Lower Only</option>
            <option value="ceiling">Ceiling</option>
          </select>
        </div>
        <div className={g2}>
          {txt('orgRpm', 'RPM', 'number')}
          {txt('orgTpm', 'TPM', 'number')}
          {chk('orgGuarantee', 'Guaranteed Throughput')}
          {chk('devSelfKeys', 'Self-Serve Keys')}
          {txt('webhookUrl', 'Webhook URL')}
          {txt('expiryDays', 'Expiry Days')}
        </div>
        <SoftPolicyFields f={f} set={set} />
      </FormModal>

      <FormModal open={modal === 'team'} onClose={() => setModal(null)} title={f.editTeamId ? `Edit Team (${f.editTeamId})` : 'Create Team'} submitLabel={f.editTeamId ? 'Save' : 'Create'} pending={saveMut.isPending} error={formErr || saveMut.error} onSubmit={() => {
        try {
          const defMemM = usdToMicros(f.defMemBudget || '');
          const body: Partial<Team> = {
            org_id: activeOrgId,
            ...(!f.editTeamId && f.teamId?.trim() && { id: f.teamId.trim() }),
            name: (f.teamName || '').trim(),
            rpm_limit: f.teamRpm ? parseInt(f.teamRpm, 10) : 0,
            enforce_guaranteed_throughput: !!f.teamGuarantee,
            default_member_max_budget_micros: defMemM ?? 0,
            default_member_rpm_limit: f.defMemRpm ? parseInt(f.defMemRpm, 10) : 0,
            team_member_permissions: (f.teamPerms || '').split(',').map((s: string) => s.trim()).filter(Boolean),
            min_priority_rank: f.teamMinPrio ? Math.max(0, parseInt(f.teamMinPrio, 10) || 0) : 0,
            allowed_routing_tags: (f.teamAllowedTags || '').split(',').map((s: string) => s.trim()).filter(Boolean),
            ...budgetPatch('teamBudget', true),
            is_active: !!f.active,
          };
          saveMut.mutate({ k: 'teams', fn: () => f.editTeamId ? adminApi.updateTeam(adminKey, f.editTeamId, body) : adminApi.createTeam(adminKey, body) });
        } catch (err: any) { setFormErr(err?.message || 'Invalid'); }
      }}>
        <input required value={f.teamName || ''} onChange={(e) => set('teamName', e.target.value)} placeholder="Team Name *" className={INPUT_CLS} />
        <div className={g2}>
          {!f.editTeamId && txt('teamId', 'Team ID')}
          {txt('teamBudget', 'Max USD', 'number')}
          {txt('teamRpm', 'Team RPM', 'number')}
          {txt('defMemBudget', 'Member USD', 'number')}
          {txt('defMemRpm', 'Member RPM', 'number')}
        </div>
        {txt('teamPerms', 'Member Perms (keys:create,keys:rotate,keys:revoke)')}
        <div className={g2}>
          {txt('teamMinPrio', 'Min Priority Rank', 'number')}
          {txt('teamAllowedTags', 'Allowed Routing Tags')}
        </div>
        {chk('teamGuarantee', 'Guaranteed Throughput')}
        <SoftPolicyFields f={f} set={set} />
        {f.editTeamId && chk('active', 'Active')}
      </FormModal>

      <FormModal open={modal === 'members'} onClose={() => setModal(null)} title={`Members: ${f.membersTeamName || f.membersTeamId}`} submitLabel="Sync" pending={saveMut.isPending} error={formErr || saveMut.error} onSubmit={() => {
        const parse = (v?: string) => (v || '').split(',').map((s) => s.trim()).filter(Boolean);
        saveMut.mutate({ k: 'team-members', fn: () => adminApi.bulkSyncTeamMembers(adminKey, f.membersTeamId, { org_id: activeOrgId, members: parse(f.addUserIds).map((user_id) => ({ user_id })), remove_user_ids: parse(f.rmUserIds) }) });
      }}>
        {txt('addUserIds', 'Add User IDs')}
        {txt('rmUserIds', 'Remove User IDs')}
        <div className="max-h-40 overflow-y-auto border border-border-subtle rounded p-2 text-xs space-y-1">
          {(membersQ.data?.data || []).map((m) => (
            <div key={m.user_id} className="flex items-center justify-between font-mono">
              <span>{m.user_id} ({m.role})</span>
              <span className="flex items-center gap-2">
                <span className="text-status-success">{formatUSD(m.spent_micros || 0)}</span>
                <button type="button" onClick={() => adminApi.resetTeamMemberSpend(adminKey, f.membersTeamId, m.user_id).then(() => inv('team-members'))} className="text-accent-primary" title="Reset spend">$0</button>
              </span>
            </div>
          ))}
        </div>
      </FormModal>

      <FormModal open={modal === 'user'} onClose={() => setModal(null)} title={f.editUserId ? 'Edit User' : 'Create User'} submitLabel={f.editUserId ? 'Save' : 'Create'} pending={saveMut.isPending} error={formErr || saveMut.error} onSubmit={() => {
        try {
          const body: Partial<User> = {
            org_id: activeOrgId,
            email: (f.email || '').trim(),
            role: f.role,
            ...(!f.editUserId && f.userId?.trim() && { id: f.userId.trim() }),
            name: (f.userName || '').trim(),
            team_id: f.userTeamId || '',
            ...budgetPatch('userBudget', true),
            is_active: !!f.active,
          };
          saveMut.mutate({ k: 'users', fn: () => f.editUserId ? adminApi.updateUser(adminKey, f.editUserId, body) : adminApi.createUser(adminKey, body) });
        } catch (err: any) { setFormErr(err?.message || 'Invalid'); }
      }}>
        <input type="email" required value={f.email || ''} onChange={(e) => set('email', e.target.value)} placeholder="Email *" className={INPUT_CLS} />
        <div className={g2}>
          {txt('userName', 'Name')}
          {!f.editUserId && txt('userId', 'User ID')}
        </div>
        <div className="grid grid-cols-3 gap-2">
          <select value={f.userTeamId || ''} onChange={(e) => set('userTeamId', e.target.value)} className={INPUT_CLS}><option value="">No Team</option>{teams.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}</select>
          <select value={f.role} onChange={(e) => set('role', e.target.value)} className={INPUT_CLS}>{['developer', 'team_admin', 'org_admin', 'org_viewer', 'viewer', 'service_account'].map((r) => <option key={r} value={r}>{r}</option>)}</select>
          {txt('userBudget', 'Max USD', 'number')}
        </div>
        <SoftPolicyFields f={f} set={set} />
        {f.editUserId && chk('active', 'Active')}
      </FormModal>

      <FormModal open={modal === 'sub'} onClose={() => setModal(null)} title="Provider Sub" pending={saveMut.isPending} error={saveMut.error} onSubmit={() => saveMut.mutate({ k: 'org-subscriptions', fn: () => adminApi.setOrgSubscription(adminKey, activeOrgId, { provider: f.subProv, is_enabled: f.subOn, auto_enable_new: f.subAuto }) })}>
        <input required value={f.subProv} onChange={(e) => set('subProv', e.target.value)} placeholder="Provider" className={INPUT_CLS} />
        {chk('subOn', 'Enabled')}
        {chk('subAuto', 'Auto-enable')}
      </FormModal>

      <FormModal open={modal === 'policy'} onClose={() => setModal(null)} title="Model Policy" pending={saveMut.isPending} error={saveMut.error} onSubmit={() => saveMut.mutate({ k: 'org-model-policies', fn: () => adminApi.setOrgModelPolicy(adminKey, activeOrgId, { global_model_id: (f.polModel || '').trim(), is_enabled: f.polOn }) })}>
        {txt('polModel', 'Global Model ID')}
        {chk('polOn', 'Allow Model')}
      </FormModal>
    </div>
  );
};
