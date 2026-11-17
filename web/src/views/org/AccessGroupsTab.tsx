import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { adminApi } from '../../api/admin';
import { useAuth } from '../../context/AuthContext';
import { FormModal, INPUT_CLS, MONO_INPUT_CLS, BTN_PRIMARY } from '../../components/common/Modal';
import { Badge } from '../../components/common/Badge';
import { ErrorAlert } from '../../components/common/ErrorAlert';
import { parseCSVList } from '../../components/common/Allowlist3State';
import { formatUSD, usdToMicros } from '../../utils/budget';
import type { AccessGroup, AccessGroupMember, AccessGroupRule } from '../../types';
import { Plus, Trash2, Users } from 'lucide-react';

const cell = 'px-4 py-2.5';

export const AccessGroupsTab: React.FC = () => {
  const { adminKey, isUnlocked, activeOrgId } = useAuth();
  const qc = useQueryClient();
  const [modal, setModal] = useState<'group' | 'member' | 'rule' | null>(null);
  const [targetGroup, setTargetGroup] = useState<AccessGroup | null>(null);
  const [gf, setGf] = useState({ name: '', desc: '', budget: '', rpm: '', tpm: '', mcp: '', mcpTools: '', a2a: '' });
  const [mf, setMf] = useState<{ member_type: AccessGroupMember['member_type']; member_id: string }>({ member_type: 'model', member_id: '' });
  const [rf, setRf] = useState({
    name: '',
    attribute: 'jwt_claims.groups',
    operator: 'contains' as AccessGroupRule['operator'],
    value: '',
    models: '',
    mcp: '',
    mcpTools: '',
    a2a: '',
    groupId: '',
    priority: '10',
  });

  const groupsQ = useQuery({
    queryKey: ['admin', 'access-groups', adminKey, activeOrgId],
    queryFn: () => adminApi.listAccessGroups(adminKey, activeOrgId),
    enabled: isUnlocked && !!activeOrgId,
  });
  const rulesQ = useQuery({
    queryKey: ['admin', 'access-rules', adminKey, activeOrgId],
    queryFn: () => adminApi.listAccessGroupRules(adminKey, activeOrgId),
    enabled: isUnlocked && !!activeOrgId,
  });

  const invG = () => qc.invalidateQueries({ queryKey: ['admin', 'access-groups', adminKey] });
  const invR = () => qc.invalidateQueries({ queryKey: ['admin', 'access-rules', adminKey] });

  const saveGroupMut = useMutation({
    mutationFn: () =>
      adminApi.upsertAccessGroup(adminKey, {
        org_id: activeOrgId,
        name: gf.name.trim(),
        description: gf.desc.trim(),
        max_budget_micros: usdToMicros(gf.budget) ?? 0,
        rpm_limit: gf.rpm ? parseInt(gf.rpm, 10) : 0,
        tpm_limit: gf.tpm ? parseInt(gf.tpm, 10) : 0,
        allowed_mcp_servers: parseCSVList(gf.mcp),
        allowed_mcp_tools: parseCSVList(gf.mcpTools),
        allowed_a2a_agents: parseCSVList(gf.a2a),
        is_active: true,
      }),
    onSuccess: () => { invG(); setModal(null); },
  });

  const delGroupMut = useMutation({ mutationFn: (id: string) => adminApi.deleteAccessGroup(adminKey, id), onSuccess: invG });
  const addMemMut = useMutation({
    mutationFn: () => adminApi.addAccessGroupMember(adminKey, targetGroup!.id, { org_id: activeOrgId, ...mf }),
    onSuccess: () => { invG(); setMf({ ...mf, member_id: '' }); },
  });
  const rmMemMut = useMutation({
    mutationFn: ({ gid, mid }: { gid: string; mid: string }) => adminApi.removeAccessGroupMember(adminKey, gid, mid),
    onSuccess: invG,
  });

  const saveRuleMut = useMutation({
    mutationFn: () =>
      adminApi.createAccessGroupRule(adminKey, {
        org_id: activeOrgId,
        name: rf.name.trim(),
        attribute: rf.attribute.trim(),
        operator: rf.operator,
        value: rf.value.trim(),
        allowed_models: parseCSVList(rf.models),
        allowed_mcp_servers: parseCSVList(rf.mcp),
        allowed_mcp_tools: parseCSVList(rf.mcpTools),
        allowed_a2a_agents: parseCSVList(rf.a2a),
        access_group_id: rf.groupId.trim() || undefined,
        priority: parseInt(rf.priority, 10) || 0,
        is_active: true,
      }),
    onSuccess: () => { invR(); setModal(null); },
  });
  const delRuleMut = useMutation({ mutationFn: (id: string) => adminApi.deleteAccessGroupRule(adminKey, id), onSuccess: invR });

  const groups = groupsQ.data?.data || [];
  const rules = rulesQ.data?.data || [];
  const activeGroup = targetGroup ? groups.find((g) => g.id === targetGroup.id) || targetGroup : null;

  return (
    <div className="space-y-6">
      <div className="space-y-3">
        <div className="flex justify-between items-center">
          <div>
            <h2 className="text-sm font-semibold text-brand-title">Unified Access Groups</h2>
            <p className="text-xs text-brand-muted">Reusable permission &amp; quota pools granting models, MCP servers, MCP tools, and A2A agents.</p>
          </div>
          <button onClick={() => { setGf({ name: '', desc: '', budget: '', rpm: '', tpm: '', mcp: '', mcpTools: '', a2a: '' }); setModal('group'); }} className={`${BTN_PRIMARY} flex items-center gap-1`}>
            <Plus className="w-3.5 h-3.5" />New Access Group
          </button>
        </div>
        {(groupsQ.error || delGroupMut.error) && <ErrorAlert error={groupsQ.error || delGroupMut.error} title="Access Groups error" />}
        <div className="bg-surface-base border border-border-subtle rounded-xl overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-surface-elevated border-b border-border-subtle text-brand-muted font-mono uppercase text-[10px]">
              <tr>{['Group', 'Budget', 'MCP / A2A Grants', 'Members', 'Actions'].map((h) => <th key={h} className={cell}>{h}</th>)}</tr>
            </thead>
            <tbody className="divide-y divide-border-subtle">
              {groups.length === 0 ? (
                <tr><td colSpan={5} className="px-4 py-6 text-center text-brand-muted">No access groups yet.</td></tr>
              ) : groups.map((g) => (
                <tr key={g.id}>
                  <td className={cell}>
                    <div className="font-medium text-brand-title">{g.name}</div>
                    <div className="font-mono text-[10px] text-brand-muted">{g.id}</div>
                  </td>
                  <td className={`${cell} font-mono`}>{g.max_budget_micros ? formatUSD(g.max_budget_micros) : 'Unlimited'}</td>
                  <td className={`${cell} font-mono text-[11px]`}>
                    {g.allowed_mcp_servers?.length ? <div>mcp: {g.allowed_mcp_servers.join(', ')}</div> : null}
                    {g.allowed_mcp_tools?.length ? <div>tools: {g.allowed_mcp_tools.join(', ')}</div> : null}
                    {g.allowed_a2a_agents?.length ? <div>a2a: {g.allowed_a2a_agents.join(', ')}</div> : null}
                    {!g.allowed_mcp_servers?.length && !g.allowed_mcp_tools?.length && !g.allowed_a2a_agents?.length && <span className="text-brand-muted">Models only</span>}
                  </td>
                  <td className={cell}><Badge variant="info">{g.members?.length || 0}</Badge></td>
                  <td className={`${cell} flex items-center gap-1`}>
                    <button onClick={() => { setTargetGroup(g); setModal('member'); }} className="px-1.5 py-0.5 text-[10px] font-mono text-accent-primary flex items-center gap-1"><Users className="w-3 h-3" />Members</button>
                    <button onClick={() => { if (confirm(`Delete group "${g.name}"?`)) delGroupMut.mutate(g.id); }} className="p-1 text-brand-muted"><Trash2 className="w-3.5 h-3.5" /></button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <div className="space-y-3">
        <div className="flex justify-between items-center">
          <div>
            <h2 className="text-sm font-semibold text-brand-title">Dynamic Access Group Rules</h2>
            <p className="text-xs text-brand-muted">Attribute-based rules (e.g. <code className="font-mono">jwt_claims.groups</code>, <code className="font-mono">user_role</code>, <code className="font-mono">email</code>) granting models, MCP, A2A, or group membership.</p>
          </div>
          <button onClick={() => { setRf({ name: '', attribute: 'jwt_claims.groups', operator: 'contains', value: '', models: '', mcp: '', mcpTools: '', a2a: '', groupId: '', priority: '10' }); setModal('rule'); }} className={`${BTN_PRIMARY} flex items-center gap-1`}>
            <Plus className="w-3.5 h-3.5" />New Rule
          </button>
        </div>
        {(rulesQ.error || delRuleMut.error) && <ErrorAlert error={rulesQ.error || delRuleMut.error} title="Access Rules error" />}
        <div className="bg-surface-base border border-border-subtle rounded-xl overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-surface-elevated border-b border-border-subtle text-brand-muted font-mono uppercase text-[10px]">
              <tr>{['Rule', 'Condition', 'Grants', 'Priority', 'Actions'].map((h) => <th key={h} className={cell}>{h}</th>)}</tr>
            </thead>
            <tbody className="divide-y divide-border-subtle">
              {rules.length === 0 ? (
                <tr><td colSpan={5} className="px-4 py-6 text-center text-brand-muted">No dynamic access rules configured.</td></tr>
              ) : rules.map((r) => (
                <tr key={r.id}>
                  <td className={`${cell} font-medium text-brand-title`}>{r.name}</td>
                  <td className={`${cell} font-mono text-[11px]`}>{r.attribute} <Badge size="sm">{r.operator}</Badge> {r.value}</td>
                  <td className={`${cell} font-mono text-[11px]`}>
                    {r.allowed_models?.length ? <div>models: {r.allowed_models.join(', ')}</div> : null}
                    {r.allowed_mcp_servers?.length ? <div>mcp: {r.allowed_mcp_servers.join(', ')}</div> : null}
                    {r.allowed_mcp_tools?.length ? <div>tools: {r.allowed_mcp_tools.join(', ')}</div> : null}
                    {r.allowed_a2a_agents?.length ? <div>a2a: {r.allowed_a2a_agents.join(', ')}</div> : null}
                    {r.access_group_id ? <div>group: {r.access_group_id}</div> : null}
                  </td>
                  <td className={`${cell} font-mono`}>{r.priority}</td>
                  <td className={cell}><button onClick={() => { if (confirm(`Delete rule "${r.name}"?`)) delRuleMut.mutate(r.id); }} className="p-1 text-brand-muted"><Trash2 className="w-3.5 h-3.5" /></button></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      <FormModal open={modal === 'group'} onClose={() => setModal(null)} title="Create / Upsert Access Group" pending={saveGroupMut.isPending} onSubmit={() => saveGroupMut.mutate()}>
        {!!saveGroupMut.error && <ErrorAlert error={saveGroupMut.error} title="Save failed" />}
        <input required value={gf.name} onChange={(e) => setGf({ ...gf, name: e.target.value })} placeholder="Group Name (e.g. tier-frontier) *" className={INPUT_CLS} />
        <input value={gf.desc} onChange={(e) => setGf({ ...gf, desc: e.target.value })} placeholder="Description" className={INPUT_CLS} />
        <div className="grid grid-cols-3 gap-2">
          <input type="number" min="0" step="0.01" value={gf.budget} onChange={(e) => setGf({ ...gf, budget: e.target.value })} placeholder="Max USD" className={INPUT_CLS} />
          <input type="number" min="0" value={gf.rpm} onChange={(e) => setGf({ ...gf, rpm: e.target.value })} placeholder="RPM" className={INPUT_CLS} />
          <input type="number" min="0" value={gf.tpm} onChange={(e) => setGf({ ...gf, tpm: e.target.value })} placeholder="TPM" className={INPUT_CLS} />
        </div>
        <input value={gf.mcp} onChange={(e) => setGf({ ...gf, mcp: e.target.value })} placeholder="Allowed MCP Servers (csv)" className={MONO_INPUT_CLS} />
        <input value={gf.mcpTools} onChange={(e) => setGf({ ...gf, mcpTools: e.target.value })} placeholder="Allowed MCP Tools (e.g. github:get_issue)" className={MONO_INPUT_CLS} />
        <input value={gf.a2a} onChange={(e) => setGf({ ...gf, a2a: e.target.value })} placeholder="Allowed A2A Agents (csv)" className={MONO_INPUT_CLS} />
      </FormModal>

      <FormModal open={modal === 'member' && !!activeGroup} onClose={() => setModal(null)} title={`Members: ${activeGroup?.name || ''}`} submitLabel="Add Member" pending={addMemMut.isPending} onSubmit={() => addMemMut.mutate()}>
        {(addMemMut.error || rmMemMut.error) && <ErrorAlert error={addMemMut.error || rmMemMut.error} title="Member error" />}
        <div className="grid grid-cols-3 gap-2">
          <select value={mf.member_type} onChange={(e) => setMf({ ...mf, member_type: e.target.value as AccessGroupMember['member_type'] })} className={INPUT_CLS}>
            {(['model', 'key', 'team', 'user', 'project', 'org'] as const).map((t) => <option key={t} value={t}>{t}</option>)}
          </select>
          <input required value={mf.member_id} onChange={(e) => setMf({ ...mf, member_id: e.target.value })} placeholder="Member ID / Model Name *" className={`${MONO_INPUT_CLS} col-span-2`} />
        </div>
        <div className="max-h-48 overflow-y-auto border border-border-subtle rounded p-2 space-y-1 text-xs font-mono">
          {(activeGroup?.members || []).map((m) => (
            <div key={m.id} className="flex justify-between items-center">
              <span><Badge size="sm">{m.member_type}</Badge> {m.member_id}</span>
              <button type="button" onClick={() => rmMemMut.mutate({ gid: activeGroup!.id, mid: m.id })} className="text-status-danger"><Trash2 className="w-3 h-3" /></button>
            </div>
          ))}
        </div>
      </FormModal>

      <FormModal open={modal === 'rule'} onClose={() => setModal(null)} title="Create Dynamic Access Rule" pending={saveRuleMut.isPending} onSubmit={() => saveRuleMut.mutate()}>
        {!!saveRuleMut.error && <ErrorAlert error={saveRuleMut.error} title="Create rule failed" />}
        <div className="grid grid-cols-3 gap-2">
          <input required value={rf.name} onChange={(e) => setRf({ ...rf, name: e.target.value })} placeholder="Rule Name *" className={`${INPUT_CLS} col-span-2`} />
          <input type="number" value={rf.priority} onChange={(e) => setRf({ ...rf, priority: e.target.value })} placeholder="Priority" className={INPUT_CLS} />
        </div>
        <div className="grid grid-cols-3 gap-2">
          <input required value={rf.attribute} onChange={(e) => setRf({ ...rf, attribute: e.target.value })} placeholder="jwt_claims.groups" className={MONO_INPUT_CLS} />
          <select value={rf.operator} onChange={(e) => setRf({ ...rf, operator: e.target.value as AccessGroupRule['operator'] })} className={INPUT_CLS}>
            {(['equals', 'contains', 'prefix', 'in_list'] as const).map((o) => <option key={o} value={o}>{o}</option>)}
          </select>
          <input required value={rf.value} onChange={(e) => setRf({ ...rf, value: e.target.value })} placeholder="Match Value *" className={MONO_INPUT_CLS} />
        </div>
        <input value={rf.models} onChange={(e) => setRf({ ...rf, models: e.target.value })} placeholder="Allowed Models (csv)" className={MONO_INPUT_CLS} />
        <input value={rf.mcp} onChange={(e) => setRf({ ...rf, mcp: e.target.value })} placeholder="Allowed MCP Servers (csv)" className={MONO_INPUT_CLS} />
        <input value={rf.mcpTools} onChange={(e) => setRf({ ...rf, mcpTools: e.target.value })} placeholder="Allowed MCP Tools (csv)" className={MONO_INPUT_CLS} />
        <input value={rf.a2a} onChange={(e) => setRf({ ...rf, a2a: e.target.value })} placeholder="Allowed A2A Agents (csv)" className={MONO_INPUT_CLS} />
        <select value={rf.groupId} onChange={(e) => setRf({ ...rf, groupId: e.target.value })} className={INPUT_CLS}>
          <option value="">No linked Access Group</option>
          {groups.map((g) => <option key={g.id} value={g.id}>{g.name} ({g.id})</option>)}
        </select>
      </FormModal>
    </div>
  );
};

export default AccessGroupsTab;
