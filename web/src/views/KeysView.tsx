import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { adminApi } from '../api/admin';
import { useAuth } from '../context/AuthContext';
import { Modal, INPUT_CLS, BTN_CANCEL, BTN_PRIMARY } from '../components/common/Modal';
import { Badge } from '../components/common/Badge';
import { ErrorAlert } from '../components/common/ErrorAlert';
import type { VirtualKey, Role, BudgetResetPeriod } from '../types';
import {
  Key,
  Plus,
  Pencil,
  RotateCw,
  Trash2,
  Copy,
  Check,
  AlertTriangle,
  Zap,
} from 'lucide-react';

type AllowMode = 'inherit' | 'deny' | 'allowlist';
type AllowState = { mode: AllowMode; text: string };
const INHERIT: AllowState = { mode: 'inherit', text: '' };
const ROLES: Role[] = ['developer', 'service_account', 'team_admin', 'org_admin', 'org_viewer', 'viewer', 'platform_admin'];
const RESET_PERIODS: BudgetResetPeriod[] = ['daily', 'monthly', 'never'];
const parseCSV = (s: string) => s.split(',').map((x) => x.trim()).filter(Boolean);
const initAllow = (v?: string[] | null): AllowState =>
  v == null ? INHERIT : v.length === 0 ? { mode: 'deny', text: '' } : { mode: 'allowlist', text: v.join(', ') };
const encodeAllow = (s: AllowState, isEdit: boolean): string[] | null | undefined =>
  s.mode === 'inherit' ? (isEdit ? null : undefined) : s.mode === 'deny' ? [] : parseCSV(s.text);

const AllowlistField: React.FC<{
  label: string;
  state: AllowState;
  onChange: (next: AllowState) => void;
  placeholder: string;
}> = ({ label, state, onChange, placeholder }) => (
  <div>
    <label className="block text-xs font-medium text-brand-body mb-1">{label}</label>
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
        <input
          type="text"
          value={state.text}
          onChange={(e) => onChange({ ...state, text: e.target.value })}
          placeholder={placeholder}
          className={`${INPUT_CLS} font-mono`}
        />
      )}
    </div>
  </div>
);

export const KeysView: React.FC<{ onNavigateToPlayground: () => void }> = ({ onNavigateToPlayground }) => {
  const { adminKey, activeOrgId, setCapturedVirtualKey } = useAuth();
  const queryClient = useQueryClient();

  const [showIssueModal, setShowIssueModal] = useState(false);
  const [editingKeyId, setEditingKeyId] = useState<string | null>(null);
  const [newKeySecret, setNewKeySecret] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  // Form state
  const [name, setName] = useState('');
  const [teamId, setTeamId] = useState('');
  const [userId, setUserId] = useState('');
  const [role, setRole] = useState<Role>('developer');
  const [expiresAt, setExpiresAt] = useState('');
  const [maxBudgetUSD, setMaxBudgetUSD] = useState('');
  const [budgetResetPeriod, setBudgetResetPeriod] = useState<BudgetResetPeriod>('monthly');
  const [rpmLimit, setRpmLimit] = useState('');
  const [tpmLimit, setTpmLimit] = useState('');
  const [maxConcurrent, setMaxConcurrent] = useState('');
  const [allowedModels, setAllowedModels] = useState('');
  const [allowedEndpoints, setAllowedEndpoints] = useState('');
  const [mcpAllow, setMcpAllow] = useState<AllowState>(INHERIT);
  const [a2aAllow, setA2aAllow] = useState<AllowState>(INHERIT);
  const [clientAppAllow, setClientAppAllow] = useState<AllowState>(INHERIT);

  // 1. Fetch virtual keys for active org
  const {
    data: keysData,
    isLoading,
    isError,
    error,
    refetch,
  } = useQuery({
    queryKey: ['admin', 'keys', adminKey, activeOrgId],
    queryFn: () => adminApi.listKeys(adminKey, activeOrgId),
    enabled: !!adminKey,
  });

  const { data: teamsData } = useQuery({
    queryKey: ['admin', 'teams', adminKey, activeOrgId],
    queryFn: () => adminApi.listTeams(adminKey, activeOrgId),
    enabled: !!adminKey && !!activeOrgId,
  });

  const { data: usersData } = useQuery({
    queryKey: ['admin', 'users', adminKey, activeOrgId],
    queryFn: () => adminApi.listUsers(adminKey, activeOrgId),
    enabled: !!adminKey && !!activeOrgId,
  });

  // 2. Issue / Update / Rotate / Revoke key mutations
  const issueMutation = useMutation({
    mutationFn: (data: Partial<VirtualKey>) =>
      editingKeyId ? adminApi.updateKey(adminKey, editingKeyId, data) : adminApi.issueKey(adminKey, data),
    onSuccess: (resKey) => {
      queryClient.invalidateQueries({ queryKey: ['admin', 'keys', adminKey] });
      setShowIssueModal(false);
      setEditingKeyId(null);
      if (resKey.raw_key) {
        setNewKeySecret(resKey.raw_key);
        setCapturedVirtualKey(resKey.raw_key);
      }
      resetForm();
    },
  });

  const rotateMutation = useMutation({
    mutationFn: (keyId: string) => adminApi.rotateKey(adminKey, keyId),
    onSuccess: (rotatedKey) => {
      queryClient.invalidateQueries({ queryKey: ['admin', 'keys', adminKey] });
      if (rotatedKey.raw_key) {
        setNewKeySecret(rotatedKey.raw_key);
        setCapturedVirtualKey(rotatedKey.raw_key);
      }
    },
  });

  const revokeMutation = useMutation({
    mutationFn: (keyId: string) => adminApi.revokeKey(adminKey, keyId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['admin', 'keys', adminKey] });
    },
  });

  const resetForm = () => {
    setName('');
    setTeamId('');
    setUserId('');
    setRole('developer');
    setExpiresAt('');
    setMaxBudgetUSD('');
    setBudgetResetPeriod('monthly');
    setRpmLimit('');
    setTpmLimit('');
    setMaxConcurrent('');
    setAllowedModels('');
    setAllowedEndpoints('');
    setMcpAllow(INHERIT);
    setA2aAllow(INHERIT);
    setClientAppAllow(INHERIT);
  };

  const openEditModal = (k: VirtualKey) => {
    issueMutation.reset();
    setEditingKeyId(k.id);
    setName(k.name);
    setTeamId(k.team_id || '');
    setUserId(k.user_id || '');
    setRole(k.role || 'developer');
    setExpiresAt(k.expires_at ? k.expires_at.slice(0, 16) : '');
    setMaxBudgetUSD(k.max_budget_micros ? String(k.max_budget_micros / 1_000_000) : '');
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

  const handleIssueSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) return;

    const isEdit = !!editingKeyId;
    const payload: Partial<VirtualKey> = {
      org_id: activeOrgId,
      name: name.trim(),
      team_id: teamId.trim(),
      user_id: userId.trim(),
      role,
      budget_reset_period: budgetResetPeriod,
    };

    if (expiresAt) {
      const d = new Date(expiresAt);
      if (!isNaN(d.getTime())) payload.expires_at = d.toISOString();
    }
    const parsedBudget = parseFloat(maxBudgetUSD);
    if (!isNaN(parsedBudget) && parsedBudget >= 0) {
      payload.max_budget_micros = Math.round(parsedBudget * 1_000_000);
    } else if (isEdit) {
      payload.max_budget_micros = 0;
    }
    payload.rpm_limit = rpmLimit ? parseInt(rpmLimit, 10) : 0;
    payload.tpm_limit = tpmLimit ? parseInt(tpmLimit, 10) : 0;
    payload.max_concurrent_requests = maxConcurrent ? parseInt(maxConcurrent, 10) : 0;
    payload.allowed_models = allowedModels.trim() ? parseCSV(allowedModels) : [];
    if (allowedEndpoints.trim() || isEdit) {
      payload.allowed_endpoints = allowedEndpoints.trim() ? parseCSV(allowedEndpoints) : [];
    }
    const mcpVal = encodeAllow(mcpAllow, isEdit);
    if (mcpVal !== undefined) payload.allowed_mcp_servers = mcpVal;
    const a2aVal = encodeAllow(a2aAllow, isEdit);
    if (a2aVal !== undefined) payload.allowed_a2a_agents = a2aVal;
    const appVal = encodeAllow(clientAppAllow, isEdit);
    if (appVal !== undefined) payload.allowed_client_apps = appVal;

    issueMutation.mutate(payload);
  };

  const handleCopySecret = () => {
    if (newKeySecret) {
      navigator.clipboard.writeText(newKeySecret);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  return (
    <div className="space-y-6">
      {/* Header bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-brand-title tracking-tight flex items-center gap-2">
            Virtual API Keys
          </h1>
          <p className="text-xs text-brand-muted mt-1">
            Manage tenant-scoped virtual keys with budget limits, rate limiting, and model allowlists
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => refetch()}
            className="px-3 py-1.5 rounded-lg border border-border-subtle hover:border-border-strong bg-surface-elevated text-xs font-medium text-brand-body hover:text-brand-title transition-colors"
          >
            Refresh
          </button>
          <button
            onClick={() => {
              issueMutation.reset();
              setEditingKeyId(null);
              resetForm();
              setShowIssueModal(true);
            }}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-accent-primary hover:bg-accent-dark text-xs font-semibold text-accent-contrast transition-colors"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Issue Virtual Key</span>
          </button>
        </div>
      </div>

      {isError && (
        <ErrorAlert error={error} title="Failed to load virtual keys" onRetry={() => refetch()} />
      )}
      {rotateMutation.isError && (
        <ErrorAlert error={rotateMutation.error} title="Failed to rotate virtual key" />
      )}
      {revokeMutation.isError && (
        <ErrorAlert error={revokeMutation.error} title="Failed to revoke virtual key" />
      )}

      {/* Keys Table */}
      <div className="rounded-xl border border-border-subtle bg-surface-base/90 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-surface-elevated/60 text-brand-muted uppercase text-[10px] tracking-wider border-b border-border-subtle">
              <tr>
                <th className="px-6 py-3">Key Name</th>
                <th className="px-6 py-3">Prefix / ID</th>
                <th className="px-6 py-3">Spend & Budget</th>
                <th className="px-6 py-3">Rate Limits</th>
                <th className="px-6 py-3">Allowed Models</th>
                <th className="px-6 py-3">Status</th>
                <th className="px-6 py-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border-subtle/40">
              {isLoading ? (
                <tr>
                  <td colSpan={7} className="px-6 py-8 text-center text-brand-muted">
                    Loading virtual keys...
                  </td>
                </tr>
              ) : keysData?.data && keysData.data.length > 0 ? (
                keysData.data.map((k) => {
                  const spendUSD = (k.spent_micros ?? 0) / 1_000_000;
                  const budgetUSD = k.max_budget_micros ? k.max_budget_micros / 1_000_000 : null;
                  const isRevoked = !k.is_active;

                  return (
                    <tr key={k.id} className="hover:bg-surface-hover/30 transition-colors">
                      <td className="px-6 py-3 font-medium text-brand-title">
                        <div className="flex items-center gap-2">
                          <Key className="w-3.5 h-3.5 text-accent-primary shrink-0" />
                          <span>{k.name}</span>
                        </div>
                        {(k.team_id || k.user_id || k.expires_at) && (
                          <div className="text-[10px] font-mono text-brand-muted mt-0.5 space-x-2">
                            {k.team_id && <span>team:{k.team_id}</span>}
                            {k.user_id && <span>user:{k.user_id}</span>}
                            {k.expires_at && <span>exp:{new Date(k.expires_at).toLocaleDateString()}</span>}
                          </div>
                        )}
                      </td>
                      <td className="px-6 py-3 font-mono text-brand-body">
                        <span className="bg-surface-code px-2 py-0.5 rounded border border-border-subtle">
                          {k.key_prefix}••••
                        </span>
                      </td>
                      <td className="px-6 py-3 font-mono">
                        <div className="text-brand-title font-semibold">${spendUSD.toFixed(4)}</div>
                        <div className="text-[10px] text-brand-muted">
                          {budgetUSD ? `Cap: $${budgetUSD.toFixed(2)}` : 'No budget cap'}
                        </div>
                      </td>
                      <td className="px-6 py-3 font-mono text-[11px] text-brand-muted">
                        <div>RPM: {k.rpm_limit ?? '∞'}</div>
                        <div>TPM: {k.tpm_limit ? k.tpm_limit.toLocaleString() : '∞'}</div>
                      </td>
                      <td className="px-6 py-3">
                        {k.allowed_models && k.allowed_models.length > 0 ? (
                          <div className="flex flex-wrap gap-1 max-w-xs">
                            {k.allowed_models.map((m) => (
                              <Badge key={m} size="sm">
                                {m}
                              </Badge>
                            ))}
                          </div>
                        ) : (
                          <span className="text-brand-muted font-mono text-[11px]">All Models</span>
                        )}
                      </td>
                      <td className="px-6 py-3">
                        {isRevoked ? (
                          <Badge variant="danger" size="sm">
                            Revoked
                          </Badge>
                        ) : (
                          <Badge variant="success" size="sm">
                            Active
                          </Badge>
                        )}
                      </td>
                      <td className="px-6 py-3 text-right">
                        {!isRevoked && (
                          <div className="inline-flex items-center gap-1">
                            <button
                              onClick={() => openEditModal(k)}
                              className="text-brand-muted hover:text-brand-title p-1.5 rounded hover:bg-surface-elevated transition-colors"
                              title="Edit virtual key"
                            >
                              <Pencil className="w-3.5 h-3.5" />
                            </button>
                            <button
                              onClick={() => {
                                if (confirm(`Rotate key "${k.name}"? The existing key secret will stop working immediately.`)) {
                                  rotateMutation.mutate(k.id);
                                }
                              }}
                              disabled={rotateMutation.isPending}
                              className="text-brand-muted hover:text-status-warning p-1.5 rounded hover:bg-surface-elevated transition-colors"
                              title="Rotate virtual key secret"
                            >
                              <RotateCw className="w-3.5 h-3.5" />
                            </button>
                            <button
                              onClick={() => {
                                if (confirm(`Revoke key "${k.name}"? This action cannot be undone.`)) {
                                  revokeMutation.mutate(k.id);
                                }
                              }}
                              disabled={revokeMutation.isPending}
                              className="text-brand-muted hover:text-status-danger p-1.5 rounded hover:bg-surface-elevated transition-colors"
                              title="Revoke virtual key"
                            >
                              <Trash2 className="w-3.5 h-3.5" />
                            </button>
                          </div>
                        )}
                      </td>
                    </tr>
                  );
                })
              ) : (
                <tr>
                  <td colSpan={7} className="px-6 py-8 text-center text-brand-muted">
                    No virtual keys found for organization {activeOrgId}. Click "Issue Virtual Key" above.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Issue / Edit Key Modal */}
      <Modal
        isOpen={showIssueModal}
        onClose={() => {
          setShowIssueModal(false);
          setEditingKeyId(null);
        }}
        title={editingKeyId ? 'Edit Virtual Key' : 'Issue New Virtual Key'}
        description="Configure rate limits, budget caps, and model scopes for this virtual key."
        maxWidth="lg"
      >
        <form onSubmit={handleIssueSubmit} className="space-y-4">
          {issueMutation.isError && (
            <ErrorAlert error={issueMutation.error} title={editingKeyId ? 'Failed to update virtual key' : 'Failed to issue virtual key'} />
          )}
          <div>
            <label className="block text-xs font-medium text-brand-body mb-1">
              Key Name <span className="text-status-danger">*</span>
            </label>
            <input
              type="text"
              required
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. production-backend-app"
              className={INPUT_CLS}
            />
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div>
              <label className="block text-xs font-medium text-brand-body mb-1">Team (optional)</label>
              <select value={teamId} onChange={(e) => setTeamId(e.target.value)} className={INPUT_CLS}>
                <option value="">Org-wide</option>
                {(teamsData?.data || []).map((t) => <option key={t.id} value={t.id}>{t.name} ({t.id})</option>)}
              </select>
            </div>
            <div>
              <label className="block text-xs font-medium text-brand-body mb-1">User (optional)</label>
              <select value={userId} onChange={(e) => setUserId(e.target.value)} className={INPUT_CLS}>
                <option value="">Unassigned</option>
                {(usersData?.data || []).map((u) => <option key={u.id} value={u.id}>{u.email} ({u.id})</option>)}
              </select>
            </div>
            <div>
              <label className="block text-xs font-medium text-brand-body mb-1">Expires At</label>
              <input type="datetime-local" value={expiresAt} onChange={(e) => setExpiresAt(e.target.value)} className={`${INPUT_CLS} font-mono`} />
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-medium text-brand-body mb-1">Role</label>
              <select value={role} onChange={(e) => setRole(e.target.value as Role)} className={INPUT_CLS}>
                {ROLES.map((r) => <option key={r} value={r}>{r}</option>)}
              </select>
            </div>
            <div>
              <label className="block text-xs font-medium text-brand-body mb-1">Budget Reset Period</label>
              <select value={budgetResetPeriod} onChange={(e) => setBudgetResetPeriod(e.target.value as BudgetResetPeriod)} className={`${INPUT_CLS} capitalize`}>
                {RESET_PERIODS.map((p) => <option key={p} value={p}>{p}</option>)}
              </select>
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-4 gap-3">
            <div>
              <label className="block text-xs font-medium text-brand-body mb-1">Budget Cap (USD)</label>
              <input type="number" step="0.01" min="0" value={maxBudgetUSD} onChange={(e) => setMaxBudgetUSD(e.target.value)} placeholder="50.00" className={`${INPUT_CLS} font-mono`} />
            </div>
            <div>
              <label className="block text-xs font-medium text-brand-body mb-1">RPM Limit</label>
              <input type="number" min="0" value={rpmLimit} onChange={(e) => setRpmLimit(e.target.value)} placeholder="600" className={`${INPUT_CLS} font-mono`} />
            </div>
            <div>
              <label className="block text-xs font-medium text-brand-body mb-1">TPM Limit</label>
              <input type="number" min="0" value={tpmLimit} onChange={(e) => setTpmLimit(e.target.value)} placeholder="100000" className={`${INPUT_CLS} font-mono`} />
            </div>
            <div>
              <label className="block text-xs font-medium text-brand-body mb-1">Max Concurrent</label>
              <input type="number" min="0" value={maxConcurrent} onChange={(e) => setMaxConcurrent(e.target.value)} placeholder="0 (∞)" className={`${INPUT_CLS} font-mono`} />
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-medium text-brand-body mb-1">Allowed Models (Comma-separated)</label>
              <input type="text" value={allowedModels} onChange={(e) => setAllowedModels(e.target.value)} placeholder="fast, reasoning, openai/gpt-4o" className={`${INPUT_CLS} font-mono`} />
            </div>
            <div>
              <label className="block text-xs font-medium text-brand-body mb-1">Allowed Endpoints (Comma-separated)</label>
              <input type="text" value={allowedEndpoints} onChange={(e) => setAllowedEndpoints(e.target.value)} placeholder="/v1/*, /chat/* (blank=default)" className={`${INPUT_CLS} font-mono`} />
            </div>
          </div>

          <div className="space-y-2.5">
            <AllowlistField label="Allowed MCP Servers" state={mcpAllow} onChange={setMcpAllow} placeholder="mcp_github, mcp_postgres" />
            <AllowlistField label="Allowed A2A Agents" state={a2aAllow} onChange={setA2aAllow} placeholder="agent_research, agent_code" />
            <AllowlistField label="Allowed Client Apps" state={clientAppAllow} onChange={setClientAppAllow} placeholder="cursor, claude-code" />
          </div>

          <div className="flex justify-end gap-2 pt-2">
            <button
              type="button"
              onClick={() => {
                setShowIssueModal(false);
                setEditingKeyId(null);
              }}
              className={BTN_CANCEL}
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={issueMutation.isPending || !name.trim()}
              className={BTN_PRIMARY}
            >
              {issueMutation.isPending ? 'Saving...' : editingKeyId ? 'Save Changes' : 'Issue Key'}
            </button>
          </div>
        </form>
      </Modal>

      {/* Single-Reveal Secret Dialog */}
      <Modal
        isOpen={!!newKeySecret}
        onClose={() => setNewKeySecret(null)}
        title="Virtual API Key Secret"
        description="Please copy this key now. For security, it will never be displayed again."
        maxWidth="md"
      >
        <div className="space-y-4">
          <div className="p-3 rounded-lg border status-warning flex items-start gap-2.5 text-xs">
            <AlertTriangle className="w-4 h-4 shrink-0 text-status-warning mt-0.5" />
            <div>
              <p className="font-semibold">Security Warning</p>
              <p className="text-[11px] opacity-85 mt-0.5">
                GoRoute only stores the cryptographic SHA-256 hash of this key. If you lose this secret, you must issue or rotate the key.
              </p>
            </div>
          </div>

          <div className="relative">
            <pre className="p-3 rounded-lg bg-surface-code border border-border-strong font-mono text-xs text-status-success break-all select-all">
              {newKeySecret}
            </pre>
            <button
              onClick={handleCopySecret}
              className="absolute right-2 top-2 px-2.5 py-1 rounded bg-surface-elevated hover:bg-surface-hover border border-border-subtle text-brand-body text-xs flex items-center gap-1.5 transition-colors"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-status-success" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copied ? 'Copied' : 'Copy'}</span>
            </button>
          </div>

          <div className="flex items-center justify-between pt-2">
            <button
              onClick={() => {
                setNewKeySecret(null);
                onNavigateToPlayground();
              }}
              className="flex items-center gap-1.5 text-xs text-accent-primary hover:underline font-medium"
            >
              <Zap className="w-3.5 h-3.5" />
              <span>Test with this key in Playground ↗</span>
            </button>

            <button
              onClick={() => setNewKeySecret(null)}
              className={BTN_PRIMARY}
            >
              Done & Close
            </button>
          </div>
        </div>
      </Modal>
    </div>
  );
};
