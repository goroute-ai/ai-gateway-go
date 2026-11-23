import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { adminApi } from '../../api/admin';
import { useAuth } from '../../context/AuthContext';
import { FormModal, INPUT_CLS, MONO_INPUT_CLS, BTN_PRIMARY } from '../../components/common/Modal';
import { Badge } from '../../components/common/Badge';
import { ErrorAlert } from '../../components/common/ErrorAlert';
import {
  Allowlist3StateField,
  INHERIT_ALLOW,
  encodeAllowState,
  initAllowState,
  parseCSVList,
} from '../../components/common/Allowlist3State';
import { formatUSD, microsToUsdInput, usdToMicros } from '../../utils/budget';
import type { Project, Team } from '../../types';
import { Plus, Pencil, Trash2 } from 'lucide-react';

const cell = 'px-4 py-2.5';

export const ProjectsTab: React.FC<{ teams: Team[] }> = ({ teams }) => {
  const { adminKey, isUnlocked, activeOrgId } = useAuth();
  const qc = useQueryClient();
  const [open, setOpen] = useState(false);
  const [editId, setEditId] = useState('');
  const [f, setF] = useState<Record<string, any>>({
    name: '',
    teamId: '',
    desc: '',
    budget: '',
    rpm: '',
    tpm: '',
    models: '',
    deployments: '',
    tags: '',
    mcp: INHERIT_ALLOW,
    mcpTools: INHERIT_ALLOW,
    mcpToolsets: INHERIT_ALLOW,
    a2a: INHERIT_ALLOW,
    enforceQuota: false,
    active: true,
  });
  const set = (k: string, v: any) => setF((p) => ({ ...p, [k]: v }));

  const q = useQuery({
    queryKey: ['admin', 'projects', adminKey, activeOrgId],
    queryFn: () => adminApi.listProjects(adminKey, activeOrgId),
    enabled: isUnlocked && !!activeOrgId,
  });

  const inv = () => qc.invalidateQueries({ queryKey: ['admin', 'projects', adminKey] });
  const saveMut = useMutation({
    mutationFn: (body: Partial<Project>) =>
      editId ? adminApi.updateProject(adminKey, editId, body) : adminApi.createProject(adminKey, body),
    onSuccess: () => {
      inv();
      setOpen(false);
    },
  });
  const delMut = useMutation({
    mutationFn: (id: string) => adminApi.deleteProject(adminKey, id),
    onSuccess: inv,
  });

  const openNew = () => {
    setEditId('');
    setF({
      name: '',
      teamId: teams[0]?.id || '',
      desc: '',
      budget: '',
      rpm: '',
      tpm: '',
      models: '',
      deployments: '',
      tags: '',
      mcp: INHERIT_ALLOW,
      mcpTools: INHERIT_ALLOW,
      mcpToolsets: INHERIT_ALLOW,
      a2a: INHERIT_ALLOW,
      enforceQuota: false,
      active: true,
    });
    setOpen(true);
  };

  const openEdit = (p: Project) => {
    setEditId(p.id);
    setF({
      name: p.name,
      teamId: p.team_id,
      desc: p.description || '',
      budget: microsToUsdInput(p.max_budget_micros),
      rpm: p.rpm_limit ? String(p.rpm_limit) : '',
      tpm: p.tpm_limit ? String(p.tpm_limit) : '',
      models: (p.allowed_models || []).join(', '),
      deployments: (p.allowed_deployments || []).join(', '),
      tags: (p.allowed_routing_tags || []).join(', '),
      mcp: initAllowState(p.allowed_mcp_servers),
      mcpTools: initAllowState(p.allowed_mcp_tools),
      mcpToolsets: initAllowState(p.allowed_mcp_toolsets),
      a2a: initAllowState(p.allowed_a2a_agents),
      enforceQuota: !!p.enforce_project_model_quota,
      active: p.is_active,
    });
    setOpen(true);
  };

  const projects = q.data?.data || [];

  return (
    <div className="space-y-3">
      <div className="flex justify-between items-center">
        <p className="text-xs text-brand-muted">Team-scoped workload boundaries with isolated budgets, models, deployments, MCP, and A2A access.</p>
        <button onClick={openNew} className={`${BTN_PRIMARY} flex items-center gap-1`}>
          <Plus className="w-3.5 h-3.5" />New Project
        </button>
      </div>
      {(q.error || delMut.error) && <ErrorAlert error={q.error || delMut.error} title="Projects error" />}
      <div className="bg-surface-base border border-border-subtle rounded-xl overflow-x-auto">
        <table className="w-full text-left text-xs">
          <thead className="bg-surface-elevated border-b border-border-subtle text-brand-muted font-mono uppercase text-[10px]">
            <tr>
              {['Project', 'Team', 'Budget', 'RPM / TPM', 'Models / Tags', 'Status', 'Actions'].map((h) => (
                <th key={h} className={cell}>{h}</th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-border-subtle">
            {projects.length === 0 ? (
              <tr><td colSpan={7} className="px-4 py-8 text-center text-brand-muted">No projects configured for {activeOrgId}.</td></tr>
            ) : (
              projects.map((p) => (
                <tr key={p.id}>
                  <td className={cell}>
                    <div className="font-medium text-brand-title">{p.name}</div>
                    <div className="font-mono text-[10px] text-brand-muted">{p.id}</div>
                  </td>
                  <td className={`${cell} font-mono text-brand-muted`}>{p.team_id}</td>
                  <td className={`${cell} font-mono`}>
                    {p.max_budget_micros ? formatUSD(p.max_budget_micros) : 'Unlimited'}
                    <div className="text-[10px] text-status-success">Spent: {formatUSD(p.spent_micros || 0)}</div>
                  </td>
                  <td className={`${cell} font-mono text-brand-muted`}>{p.rpm_limit || '∞'} / {p.tpm_limit || '∞'}</td>
                  <td className={`${cell} font-mono text-[11px]`}>
                    <div>{p.allowed_models?.length ? p.allowed_models.join(', ') : 'All models'}</div>
                    {p.allowed_routing_tags?.length ? <div className="text-accent-primary">tags: {p.allowed_routing_tags.join(', ')}</div> : null}
                  </td>
                  <td className={cell}><Badge variant={p.is_active ? 'success' : 'danger'}>{p.is_active ? 'Active' : 'Inactive'}</Badge></td>
                  <td className={`${cell} flex items-center gap-1`}>
                    <button onClick={() => openEdit(p)} className="p-1 text-brand-muted" title="Edit"><Pencil className="w-3.5 h-3.5" /></button>
                    <button onClick={() => { if (confirm(`Delete project "${p.name}"?`)) delMut.mutate(p.id); }} className="p-1 text-brand-muted" title="Delete"><Trash2 className="w-3.5 h-3.5" /></button>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>

      <FormModal
        open={open}
        onClose={() => setOpen(false)}
        title={editId ? 'Edit Project' : 'Create Project'}
        maxWidth="lg"
        pending={saveMut.isPending}
        submitLabel={editId ? 'Save' : 'Create'}
        onSubmit={() => {
          const isEdit = !!editId;
          const body: Partial<Project> = {
            org_id: activeOrgId,
            team_id: f.teamId,
            name: (f.name || '').trim(),
            description: (f.desc || '').trim(),
            max_budget_micros: usdToMicros(f.budget || '') ?? 0,
            rpm_limit: f.rpm ? parseInt(f.rpm, 10) : 0,
            tpm_limit: f.tpm ? parseInt(f.tpm, 10) : 0,
            allowed_models: parseCSVList(f.models),
            allowed_deployments: parseCSVList(f.deployments),
            allowed_routing_tags: parseCSVList(f.tags),
            enforce_project_model_quota: !!f.enforceQuota,
            is_active: !!f.active,
          };
          const mcp = encodeAllowState(f.mcp, isEdit); if (mcp !== undefined) body.allowed_mcp_servers = mcp;
          const tools = encodeAllowState(f.mcpTools, isEdit); if (tools !== undefined) body.allowed_mcp_tools = tools;
          const toolsets = encodeAllowState(f.mcpToolsets, isEdit); if (toolsets !== undefined) body.allowed_mcp_toolsets = toolsets;
          const a2a = encodeAllowState(f.a2a, isEdit); if (a2a !== undefined) body.allowed_a2a_agents = a2a;
          saveMut.mutate(body);
        }}
      >
        {!!saveMut.error && <ErrorAlert error={saveMut.error} title="Save project failed" />}
        <div className="grid grid-cols-2 gap-3">
          <input required value={f.name} onChange={(e) => set('name', e.target.value)} placeholder="Project Name *" className={INPUT_CLS} />
          <select required value={f.teamId} onChange={(e) => set('teamId', e.target.value)} className={INPUT_CLS}>
            <option value="">Select Team *</option>
            {teams.map((t) => <option key={t.id} value={t.id}>{t.name}</option>)}
          </select>
        </div>
        <input value={f.desc} onChange={(e) => set('desc', e.target.value)} placeholder="Description" className={INPUT_CLS} />
        <div className="grid grid-cols-3 gap-2">
          <input type="number" min="0" step="0.01" value={f.budget} onChange={(e) => set('budget', e.target.value)} placeholder="Max USD" className={INPUT_CLS} />
          <input type="number" min="0" value={f.rpm} onChange={(e) => set('rpm', e.target.value)} placeholder="RPM" className={INPUT_CLS} />
          <input type="number" min="0" value={f.tpm} onChange={(e) => set('tpm', e.target.value)} placeholder="TPM" className={INPUT_CLS} />
        </div>
        <div className="grid grid-cols-2 gap-2">
          <input value={f.models} onChange={(e) => set('models', e.target.value)} placeholder="Allowed Models (csv)" className={MONO_INPUT_CLS} />
          <input value={f.deployments} onChange={(e) => set('deployments', e.target.value)} placeholder="Allowed Deployments (csv)" className={MONO_INPUT_CLS} />
        </div>
        <input value={f.tags} onChange={(e) => set('tags', e.target.value)} placeholder="Allowed Routing Tags (e.g. eu-gdpr, tier:*)" className={MONO_INPUT_CLS} />
        <Allowlist3StateField label="MCP Servers" state={f.mcp} onChange={(v) => set('mcp', v)} placeholder="github, jira" />
        <Allowlist3StateField label="MCP Tools" state={f.mcpTools} onChange={(v) => set('mcpTools', v)} placeholder="github:get_issue, jira:*" />
        <Allowlist3StateField label="MCP Toolsets" state={f.mcpToolsets} onChange={(v) => set('mcpToolsets', v)} placeholder="gh-ops" />
        <Allowlist3StateField label="A2A Agents" state={f.a2a} onChange={(v) => set('a2a', v)} placeholder="code-reviewer" />
        <div className="flex gap-4 text-xs">
          <label className="flex items-center gap-1.5"><input type="checkbox" checked={!!f.enforceQuota} onChange={(e) => set('enforceQuota', e.target.checked)} />Enforce Model Quota</label>
          {editId && <label className="flex items-center gap-1.5"><input type="checkbox" checked={!!f.active} onChange={(e) => set('active', e.target.checked)} />Active</label>}
        </div>
      </FormModal>
    </div>
  );
};

export default ProjectsTab;
