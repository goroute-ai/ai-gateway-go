import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { adminApi } from '../../api/admin';
import { useAuth } from '../../context/AuthContext';
import { Badge } from '../../components/common/Badge';
import { ErrorAlert } from '../../components/common/ErrorAlert';
import { INPUT_CLS, BTN_PRIMARY } from '../../components/common/Modal';
import type { ToolPolicy, ToolTrustInputLevel, ToolTrustOutputLevel } from '../../types';
import { Plus, Trash2, ShieldCheck, Search } from 'lucide-react';

const INPUT_LEVELS: readonly ToolTrustInputLevel[] = ['blocked', 'untrusted', 'trusted'];
const OUTPUT_LEVELS: readonly ToolTrustOutputLevel[] = ['untrusted', 'trusted'];

const levelBtnClass = (active: boolean, level: string) => {
  if (!active) return 'bg-surface-elevated text-brand-muted border-border-subtle hover:text-brand-title';
  if (level === 'blocked') return 'status-danger font-bold';
  if (level === 'trusted') return 'status-success font-bold';
  return 'status-warning font-bold';
};

export const ToolPoliciesTab: React.FC = () => {
  const { adminKey, isUnlocked, activeOrgId } = useAuth();
  const qc = useQueryClient();

  const [filterTeam, setFilterTeam] = useState('');
  const [filterKey, setFilterKey] = useState('');
  const [searchTool, setSearchTool] = useState('');

  // Upsert form
  const [toolName, setToolName] = useState('');
  const [teamId, setTeamId] = useState('');
  const [keyId, setKeyId] = useState('');
  const [inputPolicy, setInputPolicy] = useState<ToolTrustInputLevel>('untrusted');
  const [outputPolicy, setOutputPolicy] = useState<ToolTrustOutputLevel>('untrusted');

  const policiesQuery = useQuery({
    queryKey: ['admin', 'tool-policies', adminKey, activeOrgId, filterTeam, filterKey],
    queryFn: () =>
      adminApi.listToolPolicies(adminKey, activeOrgId, {
        ...(filterTeam ? { team_id: filterTeam } : {}),
        ...(filterKey ? { virtual_key_id: filterKey } : {}),
      }),
    enabled: isUnlocked && !!activeOrgId,
  });

  const teamsQuery = useQuery({
    queryKey: ['admin', 'teams', adminKey, activeOrgId],
    queryFn: () => adminApi.listTeams(adminKey, activeOrgId),
    enabled: isUnlocked && !!activeOrgId,
  });

  const keysQuery = useQuery({
    queryKey: ['admin', 'keys', adminKey, activeOrgId],
    queryFn: () => adminApi.listKeys(adminKey, activeOrgId),
    enabled: isUnlocked && !!activeOrgId,
  });

  const invalidate = () =>
    qc.invalidateQueries({ queryKey: ['admin', 'tool-policies', adminKey, activeOrgId] });

  const upsertMut = useMutation({
    mutationFn: (payload: {
      id?: string;
      team_id?: string;
      virtual_key_id?: string;
      tool_name: string;
      input_policy: ToolTrustInputLevel;
      output_policy: ToolTrustOutputLevel;
    }) => adminApi.upsertToolPolicy(adminKey, activeOrgId, payload),
    onSuccess: () => {
      setToolName('');
      invalidate();
    },
  });

  const deleteMut = useMutation({
    mutationFn: (id: string) => adminApi.deleteToolPolicy(adminKey, activeOrgId, id),
    onSuccess: invalidate,
  });

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!toolName.trim()) return;
    upsertMut.mutate({
      tool_name: toolName.trim(),
      team_id: teamId || undefined,
      virtual_key_id: keyId || undefined,
      input_policy: inputPolicy,
      output_policy: outputPolicy,
    });
  };

  const quickUpdate = (
    p: ToolPolicy,
    nextIn: ToolTrustInputLevel,
    nextOut: ToolTrustOutputLevel
  ) => {
    upsertMut.mutate({
      id: p.id,
      team_id: p.team_id || undefined,
      virtual_key_id: p.virtual_key_id || undefined,
      tool_name: p.tool_name,
      input_policy: nextIn,
      output_policy: nextOut,
    });
  };

  const teams = teamsQuery.data?.data || [];
  const keys = keysQuery.data?.data || [];
  const policies = (policiesQuery.data?.data || []).filter((p) =>
    !searchTool.trim() ? true : p.tool_name.toLowerCase().includes(searchTool.toLowerCase())
  );

  return (
    <div className="space-y-6">
      {/* Upsert Form */}
      <form
        onSubmit={handleSubmit}
        className="bg-surface-base border border-border-subtle rounded-lg p-5 space-y-4"
      >
        <div>
          <h3 className="text-xs font-mono uppercase tracking-wider text-brand-title flex items-center gap-2">
            <ShieldCheck className="w-4 h-4 text-accent-primary" />
            Add / Update Tool Trust Policy
          </h3>
          <p className="text-[11px] text-brand-muted mt-0.5">
            Define input (`blocked` / `untrusted` / `trusted`) and output (`untrusted` / `trusted`) trust boundaries scoped by organization, team, or virtual key.
          </p>
        </div>

        {upsertMut.isError && <ErrorAlert error={upsertMut.error} title="Failed to save tool policy" />}

        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3 text-xs">
          <div>
            <label className="text-[11px] text-brand-muted font-mono block mb-1">Tool Name / Pattern *</label>
            <input
              value={toolName}
              onChange={(e) => setToolName(e.target.value)}
              placeholder="e.g. bash, sql_query, mcp:*"
              className={INPUT_CLS}
              required
            />
          </div>
          <div>
            <label className="text-[11px] text-brand-muted font-mono block mb-1">Team Scope (optional)</label>
            <select value={teamId} onChange={(e) => setTeamId(e.target.value)} className={INPUT_CLS}>
              <option value="">Organization-wide</option>
              {teams.map((t) => (
                <option key={t.id} value={t.id}>{t.name}</option>
              ))}
            </select>
          </div>
          <div>
            <label className="text-[11px] text-brand-muted font-mono block mb-1">Virtual Key Scope (optional)</label>
            <select value={keyId} onChange={(e) => setKeyId(e.target.value)} className={INPUT_CLS}>
              <option value="">All Keys in Scope</option>
              {keys.map((k) => (
                <option key={k.id} value={k.id}>{k.name} ({k.key_prefix})</option>
              ))}
            </select>
          </div>
        </div>

        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pt-1">
          <div className="flex flex-wrap items-center gap-5 text-xs font-mono">
            <div className="flex items-center gap-1.5">
              <span className="text-[11px] text-brand-muted">Input Policy:</span>
              {INPUT_LEVELS.map((lvl) => (
                <button
                  key={lvl}
                  type="button"
                  onClick={() => setInputPolicy(lvl)}
                  className={`px-2 py-0.5 rounded text-[11px] uppercase border transition ${levelBtnClass(inputPolicy === lvl, lvl)}`}
                >
                  {lvl}
                </button>
              ))}
            </div>
            <div className="flex items-center gap-1.5">
              <span className="text-[11px] text-brand-muted">Output Policy:</span>
              {OUTPUT_LEVELS.map((lvl) => (
                <button
                  key={lvl}
                  type="button"
                  onClick={() => setOutputPolicy(lvl)}
                  className={`px-2 py-0.5 rounded text-[11px] uppercase border transition ${levelBtnClass(outputPolicy === lvl, lvl)}`}
                >
                  {lvl}
                </button>
              ))}
            </div>
          </div>
          <button
            type="submit"
            disabled={upsertMut.isPending || !toolName.trim()}
            className={`${BTN_PRIMARY} flex items-center gap-1.5`}
          >
            <Plus className="w-3.5 h-3.5" />
            {upsertMut.isPending ? 'Saving...' : 'Save Tool Policy'}
          </button>
        </div>
      </form>

      {/* Matrix Table */}
      <div className="bg-surface-base border border-border-subtle rounded-lg p-5 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <h3 className="text-xs font-mono uppercase tracking-wider text-brand-title">
            Tool Trust Matrix ({policies.length})
          </h3>
          <div className="flex flex-wrap gap-2 text-xs">
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-brand-muted absolute left-2.5 top-1/2 -translate-y-1/2" />
              <input
                value={searchTool}
                onChange={(e) => setSearchTool(e.target.value)}
                placeholder="Filter tool..."
                className={`${INPUT_CLS} pl-8 w-40`}
              />
            </div>
            <select value={filterTeam} onChange={(e) => setFilterTeam(e.target.value)} className={`${INPUT_CLS} w-40`}>
              <option value="">All Teams</option>
              {teams.map((t) => (
                <option key={t.id} value={t.id}>{t.name}</option>
              ))}
            </select>
            <select value={filterKey} onChange={(e) => setFilterKey(e.target.value)} className={`${INPUT_CLS} w-40`}>
              <option value="">All Virtual Keys</option>
              {keys.map((k) => (
                <option key={k.id} value={k.id}>{k.name}</option>
              ))}
            </select>
          </div>
        </div>

        {policiesQuery.isError && (
          <ErrorAlert error={policiesQuery.error} title="Failed to load tool policies" onRetry={() => policiesQuery.refetch()} />
        )}

        {policiesQuery.isLoading ? (
          <div className="py-8 text-center text-xs font-mono text-brand-muted">Loading tool trust matrix...</div>
        ) : policies.length === 0 ? (
          <div className="py-8 text-center text-xs font-mono text-brand-muted border border-border-subtle rounded-lg">
            No tool policies configured. By default, tools without explicit trust overrides are treated as untrusted.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead>
                <tr className="border-b border-border-subtle text-brand-muted text-[11px] uppercase">
                  <th className="py-2 pr-3">Tool Name</th>
                  <th className="py-2 pr-3">Scope</th>
                  <th className="py-2 pr-3">Input Trust Level</th>
                  <th className="py-2 pr-3">Output Trust Level</th>
                  <th className="py-2 text-right">Remove</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border-subtle">
                {policies.map((p) => (
                  <tr key={p.id} className="text-brand-body">
                    <td className="py-2.5 pr-3 font-semibold text-brand-title">{p.tool_name}</td>
                    <td className="py-2.5 pr-3">
                      <div className="flex flex-wrap gap-1">
                        {!p.team_id && !p.virtual_key_id && <Badge variant="neutral" size="sm">org</Badge>}
                        {p.team_id && <Badge variant="info" size="sm">team:{p.team_id}</Badge>}
                        {p.virtual_key_id && <Badge variant="primary" size="sm">key:{p.virtual_key_id}</Badge>}
                      </div>
                    </td>
                    <td className="py-2.5 pr-3">
                      <div className="flex gap-1">
                        {INPUT_LEVELS.map((lvl) => (
                          <button
                            key={lvl}
                            type="button"
                            onClick={() => quickUpdate(p, lvl, p.output_policy)}
                            className={`px-2 py-0.5 rounded text-[10px] uppercase border transition ${levelBtnClass(p.input_policy === lvl, lvl)}`}
                          >
                            {lvl}
                          </button>
                        ))}
                      </div>
                    </td>
                    <td className="py-2.5 pr-3">
                      <div className="flex gap-1">
                        {OUTPUT_LEVELS.map((lvl) => (
                          <button
                            key={lvl}
                            type="button"
                            onClick={() => quickUpdate(p, p.input_policy, lvl)}
                            className={`px-2 py-0.5 rounded text-[10px] uppercase border transition ${levelBtnClass(p.output_policy === lvl, lvl)}`}
                          >
                            {lvl}
                          </button>
                        ))}
                      </div>
                    </td>
                    <td className="py-2.5 text-right">
                      <button
                        type="button"
                        onClick={() => deleteMut.mutate(p.id)}
                        className="p-1 text-brand-muted hover:text-status-danger"
                        title="Delete tool policy"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
};
