import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { adminApi } from '../api/admin';
import { useAuth } from '../context/AuthContext';
import { Modal } from '../components/common/Modal';
import { Badge } from '../components/common/Badge';
import type { VirtualKey } from '../types';
import {
  Key,
  Plus,
  Trash2,
  Copy,
  Check,
  AlertOctagon,
  Sparkles,
} from 'lucide-react';

export const KeysView: React.FC<{ onNavigateToPlayground: () => void }> = ({ onNavigateToPlayground }) => {
  const { adminKey, activeOrgId, setCapturedVirtualKey } = useAuth();
  const queryClient = useQueryClient();

  const [showIssueModal, setShowIssueModal] = useState(false);
  const [newKeySecret, setNewKeySecret] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  // Form state
  const [name, setName] = useState('');
  const [maxBudgetUSD, setMaxBudgetUSD] = useState('');
  const [rpmLimit, setRpmLimit] = useState('');
  const [tpmLimit, setTpmLimit] = useState('');
  const [allowedModels, setAllowedModels] = useState('');

  // 1. Fetch virtual keys for active org
  const {
    data: keysData,
    isLoading,
    refetch,
  } = useQuery({
    queryKey: ['admin', 'keys', adminKey, activeOrgId],
    queryFn: () => adminApi.listKeys(adminKey, activeOrgId),
    enabled: !!adminKey,
  });

  // 2. Issue key mutation
  const issueMutation = useMutation({
    mutationFn: (data: Partial<VirtualKey>) => adminApi.issueKey(adminKey, data),
    onSuccess: (newKey) => {
      queryClient.invalidateQueries({ queryKey: ['admin', 'keys', adminKey] });
      setShowIssueModal(false);
      // Key secret returned only on creation
      if (newKey.raw_key) {
        setNewKeySecret(newKey.raw_key);
        setCapturedVirtualKey(newKey.raw_key);
      }
      resetForm();
    },
  });

  // 3. Revoke key mutation
  const revokeMutation = useMutation({
    mutationFn: (keyId: string) => adminApi.revokeKey(adminKey, keyId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['admin', 'keys', adminKey] });
    },
  });

  const resetForm = () => {
    setName('');
    setMaxBudgetUSD('');
    setRpmLimit('');
    setTpmLimit('');
    setAllowedModels('');
  };

  const handleIssueSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) return;

    const payload: Partial<VirtualKey> = {
      org_id: activeOrgId,
      name: name.trim(),
    };

    if (maxBudgetUSD) {
      const parsed = parseFloat(maxBudgetUSD);
      if (!isNaN(parsed) && parsed > 0) {
        payload.max_budget_micros = Math.round(parsed * 1_000_000);
      }
    }
    if (rpmLimit) payload.rpm_limit = parseInt(rpmLimit, 10);
    if (tpmLimit) payload.tpm_limit = parseInt(tpmLimit, 10);
    if (allowedModels.trim()) {
      payload.allowed_models = allowedModels.split(',').map((s) => s.trim()).filter(Boolean);
    }

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
          <h1 className="text-xl font-bold text-white tracking-tight flex items-center gap-2">
            Virtual API Keys
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Manage tenant-scoped virtual keys with budget limits, rate limiting, and model allowlists
          </p>
        </div>

        <div className="flex items-center gap-2">
          <button
            onClick={() => refetch()}
            className="px-3 py-1.5 rounded-lg border border-border-subtle hover:border-border-strong bg-surface-elevated text-xs font-medium text-slate-300 hover:text-white transition-colors"
          >
            Refresh
          </button>
          <button
            onClick={() => setShowIssueModal(true)}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-accent-primary hover:bg-accent-glow text-xs font-semibold text-black transition-colors"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Issue Virtual Key</span>
          </button>
        </div>
      </div>

      {/* Keys Table */}
      <div className="rounded-xl border border-border-subtle bg-surface-base/90 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs">
            <thead className="bg-surface-elevated/60 text-slate-400 uppercase text-[10px] tracking-wider border-b border-border-subtle">
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
                  <td colSpan={7} className="px-6 py-8 text-center text-slate-500">
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
                      <td className="px-6 py-3 font-medium text-slate-200">
                        <div className="flex items-center gap-2">
                          <Key className="w-3.5 h-3.5 text-accent-primary shrink-0" />
                          <span>{k.name}</span>
                        </div>
                      </td>
                      <td className="px-6 py-3 font-mono text-slate-300">
                        <span className="bg-black/40 px-2 py-0.5 rounded border border-border-subtle">
                          {k.key_prefix}••••
                        </span>
                      </td>
                      <td className="px-6 py-3 font-mono">
                        <div className="text-slate-200 font-semibold">${spendUSD.toFixed(4)}</div>
                        <div className="text-[10px] text-slate-500">
                          {budgetUSD ? `Cap: $${budgetUSD.toFixed(2)}` : 'No budget cap'}
                        </div>
                      </td>
                      <td className="px-6 py-3 font-mono text-[11px] text-slate-400">
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
                          <span className="text-slate-500 font-mono text-[11px]">All Models</span>
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
                          <button
                            onClick={() => {
                              if (confirm(`Revoke key "${k.name}"? This action cannot be undone.`)) {
                                revokeMutation.mutate(k.id);
                              }
                            }}
                            disabled={revokeMutation.isPending}
                            className="text-slate-400 hover:text-rose-400 p-1.5 rounded hover:bg-surface-elevated transition-colors"
                            title="Revoke virtual key"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        )}
                      </td>
                    </tr>
                  );
                })
              ) : (
                <tr>
                  <td colSpan={7} className="px-6 py-8 text-center text-slate-500">
                    No virtual keys found for organization {activeOrgId}. Click "Issue Virtual Key" above.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Issue Key Modal */}
      <Modal
        isOpen={showIssueModal}
        onClose={() => setShowIssueModal(false)}
        title="Issue New Virtual Key"
        description="Creates a hashed virtual key for callers. Set rate limits and budget caps to protect upstream spend."
        maxWidth="md"
      >
        <form onSubmit={handleIssueSubmit} className="space-y-4">
          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">
              Key Name <span className="text-rose-400">*</span>
            </label>
            <input
              type="text"
              required
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. production-backend-app"
              className="w-full bg-black/60 border border-border-strong rounded-lg px-3 py-2 text-xs text-slate-200 placeholder-slate-600 focus:outline-none focus:border-accent-primary"
            />
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                Budget Cap (USD)
              </label>
              <input
                type="number"
                step="0.01"
                min="0"
                value={maxBudgetUSD}
                onChange={(e) => setMaxBudgetUSD(e.target.value)}
                placeholder="e.g. 50.00"
                className="w-full bg-black/60 border border-border-strong rounded-lg px-3 py-2 text-xs font-mono text-slate-200 placeholder-slate-600 focus:outline-none focus:border-accent-primary"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                RPM Limit
              </label>
              <input
                type="number"
                min="1"
                value={rpmLimit}
                onChange={(e) => setRpmLimit(e.target.value)}
                placeholder="e.g. 600"
                className="w-full bg-black/60 border border-border-strong rounded-lg px-3 py-2 text-xs font-mono text-slate-200 placeholder-slate-600 focus:outline-none focus:border-accent-primary"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                TPM Limit
              </label>
              <input
                type="number"
                min="1"
                value={tpmLimit}
                onChange={(e) => setTpmLimit(e.target.value)}
                placeholder="e.g. 100000"
                className="w-full bg-black/60 border border-border-strong rounded-lg px-3 py-2 text-xs font-mono text-slate-200 placeholder-slate-600 focus:outline-none focus:border-accent-primary"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">
              Allowed Model Scope (Comma-separated, optional)
            </label>
            <input
              type="text"
              value={allowedModels}
              onChange={(e) => setAllowedModels(e.target.value)}
              placeholder="e.g. fast, reasoning, openai/gpt-4o"
              className="w-full bg-black/60 border border-border-strong rounded-lg px-3 py-2 text-xs font-mono text-slate-200 placeholder-slate-600 focus:outline-none focus:border-accent-primary"
            />
          </div>

          <div className="flex justify-end gap-2 pt-2">
            <button
              type="button"
              onClick={() => setShowIssueModal(false)}
              className="px-3 py-1.5 rounded-md text-xs text-slate-400 hover:text-slate-200 hover:bg-surface-elevated transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={issueMutation.isPending || !name.trim()}
              className="px-4 py-1.5 rounded-md text-xs font-medium bg-accent-primary hover:bg-accent-glow text-black transition-colors disabled:opacity-50"
            >
              {issueMutation.isPending ? 'Generating...' : 'Issue Key'}
            </button>
          </div>
        </form>
      </Modal>

      {/* Single-Reveal Secret Dialog */}
      <Modal
        isOpen={!!newKeySecret}
        onClose={() => setNewKeySecret(null)}
        title="Virtual API Key Generated"
        description="Please copy this key now. For security, it will never be displayed again."
        maxWidth="md"
      >
        <div className="space-y-4">
          <div className="p-3 rounded-lg bg-amber-950/40 border border-amber-500/30 flex items-start gap-2.5 text-xs text-amber-300">
            <AlertOctagon className="w-4 h-4 shrink-0 text-amber-400 mt-0.5" />
            <div>
              <p className="font-semibold">Security Warning</p>
              <p className="text-[11px] text-amber-300/80 mt-0.5">
                GoRoute only stores the cryptographic SHA-256 hash of this key. If you lose this secret, you must issue a new key.
              </p>
            </div>
          </div>

          <div className="relative">
            <pre className="p-3 rounded-lg bg-black/80 border border-border-strong font-mono text-xs text-emerald-400 break-all select-all">
              {newKeySecret}
            </pre>
            <button
              onClick={handleCopySecret}
              className="absolute right-2 top-2 px-2.5 py-1 rounded bg-surface-elevated hover:bg-surface-hover border border-border-subtle text-slate-200 text-xs flex items-center gap-1.5 transition-colors"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-emerald-400" /> : <Copy className="w-3.5 h-3.5" />}
              <span>{copied ? 'Copied' : 'Copy'}</span>
            </button>
          </div>

          <div className="flex items-center justify-between pt-2">
            <button
              onClick={() => {
                setNewKeySecret(null);
                onNavigateToPlayground();
              }}
              className="flex items-center gap-1.5 text-xs text-accent-glow hover:underline font-medium"
            >
              <Sparkles className="w-3.5 h-3.5" />
              <span>Test with this key in Playground ↗</span>
            </button>

            <button
              onClick={() => setNewKeySecret(null)}
              className="px-4 py-1.5 rounded-md text-xs font-semibold bg-accent-primary hover:bg-accent-glow text-black transition-colors"
            >
              Done & Close
            </button>
          </div>
        </div>
      </Modal>
    </div>
  );
};
