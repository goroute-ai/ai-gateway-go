import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { adminApi } from '../api/admin';
import { useAuth } from '../context/AuthContext';
import { Modal, INPUT_CLS, BTN_PRIMARY, BTN_CANCEL } from '../components/common/Modal';
import { Badge } from '../components/common/Badge';
import { ErrorAlert } from '../components/common/ErrorAlert';
import type { Organization, Team, User, OrgProviderSubscription, OrgModelPolicy } from '../types';
import { Building2, Users, Layers, ShieldCheck, Plus, Pencil, Trash2 } from 'lucide-react';

const fmtUSD = (m?: number) => (m ? `$${(m / 1e6).toFixed(2)}` : '$0.00');
const cell = 'px-4 py-2.5';

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
  <Modal isOpen={open} onClose={onClose} title={title}>
    <form onSubmit={(e) => { e.preventDefault(); onSubmit(); }} className="space-y-3">
      {!!error && <ErrorAlert error={error} title={`${title} failed`} />}
      {children}
      <div className="flex justify-end gap-2">
        <button type="button" onClick={onClose} className={BTN_CANCEL}>Cancel</button>
        <button type="submit" disabled={pending} className={BTN_PRIMARY}>{submitLabel}</button>
      </div>
    </form>
  </Modal>
);

export const OrganizationsView: React.FC = () => {
  const { adminKey, activeOrgId, setActiveOrgId } = useAuth();
  const qc = useQueryClient();
  const [tab, setTab] = useState<'orgs' | 'teams' | 'users' | 'policies'>('orgs');
  const [modal, setModal] = useState<'org' | 'team' | 'user' | 'sub' | 'policy' | null>(null);
  const [f, setF] = useState<Record<string, any>>({ reset: 'monthly', role: 'developer', subProv: 'openai', subOn: true, subAuto: true, polOn: true, active: true });
  const set = (k: string, v: any) => setF((p) => ({ ...p, [k]: v }));

  const orgsQ = useQuery({ queryKey: ['admin', 'orgs', adminKey], queryFn: () => adminApi.listOrgs(adminKey), enabled: !!adminKey });
  const teamsQ = useQuery({ queryKey: ['admin', 'teams', adminKey, activeOrgId], queryFn: () => adminApi.listTeams(adminKey, activeOrgId), enabled: !!adminKey && !!activeOrgId });
  const usersQ = useQuery({ queryKey: ['admin', 'users', adminKey, activeOrgId], queryFn: () => adminApi.listUsers(adminKey, activeOrgId), enabled: !!adminKey && !!activeOrgId });
  const subsQ = useQuery({ queryKey: ['admin', 'org-subscriptions', adminKey, activeOrgId], queryFn: () => adminApi.getOrgSubscriptions(adminKey, activeOrgId), enabled: !!adminKey && !!activeOrgId && tab === 'policies' });
  const polsQ = useQuery({ queryKey: ['admin', 'org-model-policies', adminKey, activeOrgId], queryFn: () => adminApi.getOrgModelPolicies(adminKey, activeOrgId), enabled: !!adminKey && !!activeOrgId && tab === 'policies' });

  const inv = (k: string) => qc.invalidateQueries({ queryKey: ['admin', k, adminKey] });
  const createOrg = useMutation({ mutationFn: (d: Partial<Organization>) => adminApi.createOrg(adminKey, d), onSuccess: (c) => { inv('orgs'); setModal(null); if (c?.id) setActiveOrgId(c.id); } });
  const saveTeam = useMutation({
    mutationFn: (d: Partial<Team> & { _editId?: string }) => {
      const { _editId, ...body } = d;
      return _editId ? adminApi.updateTeam(adminKey, _editId, body) : adminApi.createTeam(adminKey, body);
    },
    onSuccess: () => { inv('teams'); setModal(null); },
  });
  const deleteTeam = useMutation({ mutationFn: (id: string) => adminApi.deleteTeam(adminKey, id), onSuccess: () => inv('teams') });
  const saveUser = useMutation({
    mutationFn: (d: Partial<User> & { _editId?: string }) => {
      const { _editId, ...body } = d;
      return _editId ? adminApi.updateUser(adminKey, _editId, body) : adminApi.createUser(adminKey, body);
    },
    onSuccess: () => { inv('users'); setModal(null); },
  });
  const deleteUser = useMutation({ mutationFn: (id: string) => adminApi.deleteUser(adminKey, id), onSuccess: () => inv('users') });
  const setSub = useMutation({ mutationFn: (d: Partial<OrgProviderSubscription>) => adminApi.setOrgSubscription(adminKey, activeOrgId, d), onSuccess: () => { inv('org-subscriptions'); setModal(null); } });
  const setPol = useMutation({ mutationFn: (d: Partial<OrgModelPolicy>) => adminApi.setOrgModelPolicy(adminKey, activeOrgId, d), onSuccess: () => { inv('org-model-policies'); setModal(null); } });

  const orgs = orgsQ.data?.data || [];
  const teams = teamsQ.data?.data || [];
  const users = usersQ.data?.data || [];
  const subs = subsQ.data?.data || [];
  const pols = polsQ.data?.data || [];

  return (
    <div className="space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-bold text-white flex items-center gap-2"><Building2 className="w-5 h-5 text-accent-primary" />Organizations, Teams & Policies</h1>
          <p className="text-xs text-slate-400 mt-0.5">Active org: <code className="text-accent-primary font-mono">{activeOrgId}</code></p>
        </div>
        <div className="flex gap-2">
          {tab === 'orgs' && <button onClick={() => setModal('org')} className={`${BTN_PRIMARY} flex items-center gap-1`}><Plus className="w-3.5 h-3.5" />New Org</button>}
          {tab === 'teams' && <button onClick={() => { setF((p) => ({ ...p, editTeamId: '', teamName: '', teamId: '', teamBudget: '', active: true })); setModal('team'); }} className={`${BTN_PRIMARY} flex items-center gap-1`}><Plus className="w-3.5 h-3.5" />New Team</button>}
          {tab === 'users' && <button onClick={() => { setF((p) => ({ ...p, editUserId: '', email: '', userName: '', userId: '', userTeamId: '', role: 'developer', active: true })); setModal('user'); }} className={`${BTN_PRIMARY} flex items-center gap-1`}><Plus className="w-3.5 h-3.5" />New User</button>}
          {tab === 'policies' && <>
            <button onClick={() => setModal('sub')} className="px-3 py-1.5 rounded-md border border-accent-primary/30 text-accent-primary text-xs font-semibold">+ Provider Sub</button>
            <button onClick={() => setModal('policy')} className={BTN_PRIMARY}>+ Model Policy</button>
          </>}
        </div>
      </div>

      <div className="flex gap-2 border-b border-border-subtle pb-2 overflow-x-auto">
        {([['orgs', `Orgs (${orgs.length})`, Building2], ['teams', `Teams (${teams.length})`, Layers], ['users', `Users (${users.length})`, Users], ['policies', 'Subscriptions & Policies', ShieldCheck]] as const).map(([id, label, Icon]) => (
          <button key={id} onClick={() => setTab(id)} className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium whitespace-nowrap ${tab === id ? 'bg-accent-primary/15 text-accent-primary border border-accent-primary/30' : 'text-slate-400 hover:text-slate-200'}`}>
            <Icon className="w-3.5 h-3.5" />{label}
          </button>
        ))}
      </div>

      {orgsQ.isError && <ErrorAlert error={orgsQ.error} title="Failed to load organizations" onRetry={() => orgsQ.refetch()} />}
      {tab === 'teams' && teamsQ.isError && <ErrorAlert error={teamsQ.error} title="Failed to load teams" onRetry={() => teamsQ.refetch()} />}
      {tab === 'teams' && deleteTeam.isError && <ErrorAlert error={deleteTeam.error} title="Failed to delete team" />}
      {tab === 'users' && usersQ.isError && <ErrorAlert error={usersQ.error} title="Failed to load users" onRetry={() => usersQ.refetch()} />}
      {tab === 'users' && deleteUser.isError && <ErrorAlert error={deleteUser.error} title="Failed to delete user" />}
      {tab === 'policies' && subsQ.isError && <ErrorAlert error={subsQ.error} title="Failed to load subscriptions" onRetry={() => subsQ.refetch()} />}
      {tab === 'policies' && polsQ.isError && <ErrorAlert error={polsQ.error} title="Failed to load model policies" onRetry={() => polsQ.refetch()} />}
      {tab === 'policies' && !modal && setSub.isError && <ErrorAlert error={setSub.error} title="Failed to update provider subscription" />}
      {tab === 'policies' && !modal && setPol.isError && <ErrorAlert error={setPol.error} title="Failed to update model policy" />}

      {tab !== 'policies' ? (
        <div className="bg-surface-base border border-border-subtle rounded-xl overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-surface-elevated border-b border-border-subtle text-slate-400 font-mono uppercase text-[10px]">
              <tr>
                {tab === 'orgs' && ['Name', 'ID', 'Budget', 'Spend', 'Reset', 'Status', 'Scope'].map((h) => <th key={h} className={cell}>{h}</th>)}
                {tab === 'teams' && ['Team', 'ID', 'Budget', 'Spend', 'Status', 'Actions'].map((h) => <th key={h} className={cell}>{h}</th>)}
                {tab === 'users' && ['Email', 'Name', 'Team', 'Role', 'Status', 'Actions'].map((h) => <th key={h} className={cell}>{h}</th>)}
              </tr>
            </thead>
            <tbody className="divide-y divide-border-subtle">
              {tab === 'orgs' && orgs.map((o) => (
                <tr key={o.id}><td className={`${cell} font-medium text-white`}>{o.name}</td><td className={`${cell} font-mono text-slate-400`}>{o.id}</td><td className={`${cell} font-mono`}>{o.max_budget_micros ? fmtUSD(o.max_budget_micros) : 'Unlimited'}</td><td className={`${cell} font-mono text-emerald-400`}>{fmtUSD(o.spent_micros)}</td><td className={`${cell} font-mono capitalize text-slate-400`}>{o.budget_reset_period || 'monthly'}</td><td className={cell}><Badge variant={o.is_active ? 'success' : 'danger'}>{o.is_active ? 'Active' : 'Inactive'}</Badge></td><td className={cell}>{activeOrgId === o.id ? <Badge variant="info">Selected</Badge> : <button onClick={() => setActiveOrgId(o.id)} className="text-accent-primary hover:underline font-mono">Switch</button>}</td></tr>
              ))}
              {tab === 'teams' && teams.map((t) => (
                <tr key={t.id}>
                  <td className={`${cell} font-medium text-white`}>{t.name}</td>
                  <td className={`${cell} font-mono text-slate-400`}>{t.id}</td>
                  <td className={`${cell} font-mono`}>{t.max_budget_micros ? fmtUSD(t.max_budget_micros) : 'Unlimited'}</td>
                  <td className={`${cell} font-mono text-emerald-400`}>{fmtUSD(t.spent_micros)}</td>
                  <td className={cell}><Badge variant={t.is_active ? 'success' : 'danger'}>{t.is_active ? 'Active' : 'Inactive'}</Badge></td>
                  <td className={`${cell} flex items-center gap-1`}>
                    <button onClick={() => { setF((p) => ({ ...p, editTeamId: t.id, teamName: t.name, teamBudget: t.max_budget_micros ? String(t.max_budget_micros / 1e6) : '', active: t.is_active })); setModal('team'); }} className="p-1 text-slate-400 hover:text-white rounded" title="Edit team"><Pencil className="w-3.5 h-3.5" /></button>
                    <button onClick={() => { if (confirm(`Delete team "${t.name}"?`)) deleteTeam.mutate(t.id); }} disabled={deleteTeam.isPending} className="p-1 text-slate-400 hover:text-rose-400 rounded" title="Delete team"><Trash2 className="w-3.5 h-3.5" /></button>
                  </td>
                </tr>
              ))}
              {tab === 'users' && users.map((u) => (
                <tr key={u.id}>
                  <td className={`${cell} font-medium text-white`}>{u.email}</td>
                  <td className={`${cell} text-slate-300`}>{u.name || '—'}</td>
                  <td className={`${cell} font-mono text-slate-400`}>{u.team_id || '—'}</td>
                  <td className={cell}><Badge variant="info">{u.role}</Badge></td>
                  <td className={cell}><Badge variant={u.is_active ? 'success' : 'danger'}>{u.is_active ? 'Active' : 'Inactive'}</Badge></td>
                  <td className={`${cell} flex items-center gap-1`}>
                    <button onClick={() => { setF((p) => ({ ...p, editUserId: u.id, email: u.email, userName: u.name || '', userTeamId: u.team_id || '', role: u.role, active: u.is_active })); setModal('user'); }} className="p-1 text-slate-400 hover:text-white rounded" title="Edit user"><Pencil className="w-3.5 h-3.5" /></button>
                    <button onClick={() => { if (confirm(`Delete user "${u.email}"?`)) deleteUser.mutate(u.id); }} disabled={deleteUser.isPending} className="p-1 text-slate-400 hover:text-rose-400 rounded" title="Delete user"><Trash2 className="w-3.5 h-3.5" /></button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
          <div className="bg-surface-base border border-border-subtle rounded-xl p-4 space-y-2">
            <h3 className="text-sm font-semibold text-white">Layer 2: Provider Subscriptions</h3>
            {subs.map((s) => (
              <div key={s.provider} className="flex items-center justify-between p-2 rounded-lg bg-surface-elevated border border-border-subtle text-xs">
                <span className="font-mono font-semibold text-white uppercase">{s.provider}</span>
                <button onClick={() => setSub.mutate({ provider: s.provider, is_enabled: !s.is_enabled, auto_enable_new: s.auto_enable_new })}>
                  <Badge variant={s.is_enabled ? 'success' : 'danger'}>{s.is_enabled ? 'Enabled' : 'Disabled'}</Badge>
                </button>
              </div>
            ))}
          </div>
          <div className="bg-surface-base border border-border-subtle rounded-xl p-4 space-y-2">
            <h3 className="text-sm font-semibold text-white">Layer 3: Org Model Policies</h3>
            {pols.map((p) => (
              <div key={p.global_model_id} className="flex items-center justify-between p-2 rounded-lg bg-surface-elevated border border-border-subtle text-xs">
                <span className="font-mono text-slate-200 truncate mr-2">{p.global_model_id}</span>
                <button onClick={() => setPol.mutate({ global_model_id: p.global_model_id, is_enabled: !p.is_enabled })}>
                  <Badge variant={p.is_enabled ? 'success' : 'danger'}>{p.is_enabled ? 'Allowed' : 'Blocked'}</Badge>
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      <FormModal open={modal === 'org'} onClose={() => setModal(null)} title="Create Organization" submitLabel="Create" pending={createOrg.isPending} error={createOrg.error} onSubmit={() => { const b = parseFloat(f.orgBudget || ''); createOrg.mutate({ ...(f.orgId?.trim() && { id: f.orgId.trim() }), name: (f.orgName || '').trim(), budget_reset_period: f.reset, ...(!isNaN(b) && b > 0 && { max_budget_micros: Math.round(b * 1e6) }) }); }}>
        <input required value={f.orgName || ''} onChange={(e) => set('orgName', e.target.value)} placeholder="Organization Name *" className={INPUT_CLS} />
        <input value={f.orgId || ''} onChange={(e) => set('orgId', e.target.value)} placeholder="Organization ID (optional)" className={INPUT_CLS} />
        <div className="grid grid-cols-2 gap-3">
          <input type="number" step="0.01" value={f.orgBudget || ''} onChange={(e) => set('orgBudget', e.target.value)} placeholder="Max Budget USD" className={INPUT_CLS} />
          <select value={f.reset} onChange={(e) => set('reset', e.target.value)} className={INPUT_CLS}><option value="daily">Daily</option><option value="monthly">Monthly</option><option value="never">Never</option></select>
        </div>
      </FormModal>

      <FormModal open={modal === 'team'} onClose={() => setModal(null)} title={f.editTeamId ? `Edit Team (${f.editTeamId})` : `Create Team (${activeOrgId})`} submitLabel={f.editTeamId ? 'Save' : 'Create'} pending={saveTeam.isPending} error={saveTeam.error} onSubmit={() => { const b = parseFloat(f.teamBudget || ''); saveTeam.mutate({ _editId: f.editTeamId || undefined, org_id: activeOrgId, ...(!f.editTeamId && f.teamId?.trim() && { id: f.teamId.trim() }), name: (f.teamName || '').trim(), max_budget_micros: !isNaN(b) && b >= 0 ? Math.round(b * 1e6) : 0, is_active: !!f.active }); }}>
        <input required value={f.teamName || ''} onChange={(e) => set('teamName', e.target.value)} placeholder="Team Name *" className={INPUT_CLS} />
        <div className="grid grid-cols-2 gap-3">
          {!f.editTeamId && <input value={f.teamId || ''} onChange={(e) => set('teamId', e.target.value)} placeholder="Team ID (optional)" className={INPUT_CLS} />}
          <input type="number" step="0.01" value={f.teamBudget || ''} onChange={(e) => set('teamBudget', e.target.value)} placeholder="Max Budget USD (0=unlimited)" className={INPUT_CLS} />
        </div>
        {f.editTeamId && <label className="flex items-center gap-2 text-xs text-slate-300"><input type="checkbox" checked={!!f.active} onChange={(e) => set('active', e.target.checked)} />Active</label>}
      </FormModal>

      <FormModal open={modal === 'user'} onClose={() => setModal(null)} title={f.editUserId ? `Edit User (${f.editUserId})` : `Create User (${activeOrgId})`} submitLabel={f.editUserId ? 'Save' : 'Create'} pending={saveUser.isPending} error={saveUser.error} onSubmit={() => saveUser.mutate({ _editId: f.editUserId || undefined, org_id: activeOrgId, email: (f.email || '').trim(), role: f.role, ...(!f.editUserId && f.userId?.trim() && { id: f.userId.trim() }), name: (f.userName || '').trim(), team_id: f.userTeamId || '', is_active: !!f.active })}>
        <input type="email" required value={f.email || ''} onChange={(e) => set('email', e.target.value)} placeholder="Email *" className={INPUT_CLS} />
        <div className="grid grid-cols-2 gap-3">
          <input value={f.userName || ''} onChange={(e) => set('userName', e.target.value)} placeholder="Display Name" className={INPUT_CLS} />
          {!f.editUserId && <input value={f.userId || ''} onChange={(e) => set('userId', e.target.value)} placeholder="User ID (optional)" className={INPUT_CLS} />}
        </div>
        <div className="grid grid-cols-2 gap-3">
          <select value={f.userTeamId || ''} onChange={(e) => set('userTeamId', e.target.value)} className={INPUT_CLS}><option value="">No Team</option>{teams.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}</select>
          <select value={f.role} onChange={(e) => set('role', e.target.value)} className={INPUT_CLS}>{['developer', 'team_admin', 'org_admin', 'org_viewer', 'viewer', 'service_account'].map((r) => <option key={r} value={r}>{r}</option>)}</select>
        </div>
        {f.editUserId && <label className="flex items-center gap-2 text-xs text-slate-300"><input type="checkbox" checked={!!f.active} onChange={(e) => set('active', e.target.checked)} />Active</label>}
      </FormModal>

      <FormModal open={modal === 'sub'} onClose={() => setModal(null)} title="Set Provider Subscription" pending={setSub.isPending} error={setSub.error} onSubmit={() => setSub.mutate({ provider: f.subProv, is_enabled: f.subOn, auto_enable_new: f.subAuto })}>
        <input required value={f.subProv} onChange={(e) => set('subProv', e.target.value)} placeholder="Provider (e.g. openai)" className={INPUT_CLS} />
        <label className="flex items-center gap-2 text-xs text-slate-300"><input type="checkbox" checked={!!f.subOn} onChange={(e) => set('subOn', e.target.checked)} />Enabled</label>
        <label className="flex items-center gap-2 text-xs text-slate-300"><input type="checkbox" checked={!!f.subAuto} onChange={(e) => set('subAuto', e.target.checked)} />Auto-enable new models</label>
      </FormModal>

      <FormModal open={modal === 'policy'} onClose={() => setModal(null)} title="Set Org Model Policy" pending={setPol.isPending} error={setPol.error} onSubmit={() => setPol.mutate({ global_model_id: (f.polModel || '').trim(), is_enabled: f.polOn })}>
        <input required value={f.polModel || ''} onChange={(e) => set('polModel', e.target.value)} placeholder="Global Model ID (e.g. openai/gpt-4.1)" className={INPUT_CLS} />
        <label className="flex items-center gap-2 text-xs text-slate-300"><input type="checkbox" checked={!!f.polOn} onChange={(e) => set('polOn', e.target.checked)} />Allow Model</label>
      </FormModal>
    </div>
  );
};
