import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { adminApi } from '../api/admin';
import { useAuth } from '../context/AuthContext';
import { Modal } from '../components/common/Modal';
import { Badge } from '../components/common/Badge';
import type { ProviderType } from '../types';
import {
  Plus,
  RefreshCw,
  KeyRound,
  CheckCircle2,
  XCircle,
  Zap,
  Globe,
} from 'lucide-react';

export const CredentialsView: React.FC = () => {
  const { adminKey, activeOrgId } = useAuth();
  const queryClient = useQueryClient();

  const [showAddModal, setShowAddModal] = useState(false);
  const [provider, setProvider] = useState<ProviderType>('openai');
  const [name, setName] = useState('');
  const [apiKey, setApiKey] = useState('');
  const [baseURL, setBaseURL] = useState('');
  const [azureDeployment, setAzureDeployment] = useState('');
  const [apiVersion, setApiVersion] = useState('');

  // Preflight test state
  const [preflightTesting, setPreflightTesting] = useState(false);
  const [preflightResult, setPreflightResult] = useState<{
    valid: boolean;
    discovered_models?: number;
    latency_ms?: number;
    error?: string;
  } | null>(null);

  // 1. Fetch credentials
  const {
    data: credsData,
    isLoading,
    refetch,
  } = useQuery({
    queryKey: ['admin', 'credentials', adminKey, activeOrgId],
    queryFn: () => adminApi.listCredentials(adminKey, activeOrgId),
    enabled: !!adminKey,
  });

  // 2. Add credential mutation
  const addMutation = useMutation({
    mutationFn: (data: any) => adminApi.createCredential(adminKey, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['admin', 'credentials', adminKey] });
      setShowAddModal(false);
      resetForm();
    },
  });

  // 3. Existing credential validate mutation
  const validateMutation = useMutation({
    mutationFn: (credId: string) => adminApi.validateCredential(adminKey, credId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['admin', 'credentials', adminKey] });
    },
  });

  const resetForm = () => {
    setProvider('openai');
    setName('');
    setApiKey('');
    setBaseURL('');
    setAzureDeployment('');
    setApiVersion('');
    setPreflightResult(null);
  };

  const handlePreflightTest = async () => {
    if (!apiKey.trim() && provider !== 'ollama') return;
    setPreflightTesting(true);
    setPreflightResult(null);

    try {
      const res = await adminApi.preflightValidate(adminKey, {
        provider,
        api_key: apiKey.trim(),
        base_url: baseURL.trim() || undefined,
        azure_deployment_name: azureDeployment.trim() || undefined,
        api_version: apiVersion.trim() || undefined,
      });
      setPreflightResult(res);
    } catch (err: any) {
      setPreflightResult({
        valid: false,
        error: err.message || 'Connection test failed',
      });
    } finally {
      setPreflightTesting(false);
    }
  };

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!name.trim()) return;

    addMutation.mutate({
      org_id: activeOrgId,
      provider,
      name: name.trim(),
      api_key: apiKey.trim(),
      base_url: baseURL.trim() || undefined,
      azure_deployment_name: azureDeployment.trim() || undefined,
      api_version: apiVersion.trim() || undefined,
    });
  };

  const providersList: { id: ProviderType; label: string }[] = [
    { id: 'openai', label: 'OpenAI' },
    { id: 'anthropic', label: 'Anthropic Claude' },
    { id: 'gemini', label: 'Google Gemini' },
    { id: 'bedrock', label: 'AWS Bedrock' },
    { id: 'vertex', label: 'Google Cloud Vertex AI' },
    { id: 'azure', label: 'Azure OpenAI' },
    { id: 'cohere', label: 'Cohere' },
    { id: 'mistral', label: 'Mistral AI' },
    { id: 'groq', label: 'Groq' },
    { id: 'deepseek', label: 'DeepSeek' },
    { id: 'ollama', label: 'Ollama (Local)' },
    { id: 'cerebras', label: 'Cerebras' },
    { id: 'xai', label: 'xAI Grok' },
  ];

  return (
    <div className="space-y-6">
      {/* Header bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-white tracking-tight flex items-center gap-2">
            Provider Credentials Vault
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Boundary 2 provider credentials protected via AES-256-GCM envelope encryption with per-credential DEKs
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
            onClick={() => {
              resetForm();
              setShowAddModal(true);
            }}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-accent-primary hover:bg-accent-glow text-xs font-semibold text-black transition-colors"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Add Provider Credential</span>
          </button>
        </div>
      </div>

      {/* Credentials Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {isLoading ? (
          <div className="col-span-full py-12 text-center text-slate-500 text-xs">
            Loading encrypted credentials vault...
          </div>
        ) : credsData?.data && credsData.data.length > 0 ? (
          credsData.data.map((c) => (
            <div
              key={c.id}
              className="p-5 rounded-xl border border-border-subtle bg-surface-base/90 hover:border-border-strong transition-all space-y-3"
            >
              <div className="flex items-start justify-between">
                <div>
                  <div className="flex items-center gap-2">
                    <Badge variant="provider" provider={c.provider}>
                      {c.provider}
                    </Badge>
                    <span className="text-[10px] font-mono text-slate-500">v{c.key_version}</span>
                  </div>
                  <h3 className="text-sm font-semibold text-slate-100 mt-1.5">{c.name}</h3>
                </div>

                <button
                  onClick={() => validateMutation.mutate(c.id)}
                  disabled={validateMutation.isPending}
                  className="flex items-center gap-1 text-[11px] text-slate-400 hover:text-accent-primary p-1 rounded hover:bg-surface-elevated transition-colors"
                  title="Validate connection against upstream provider API"
                >
                  <RefreshCw className={`w-3.5 h-3.5 ${validateMutation.isPending ? 'animate-spin' : ''}`} />
                  <span>Test</span>
                </button>
              </div>

              {/* Generic Masked State */}
              <div className="flex items-center gap-2 p-2 rounded bg-black/40 border border-border-subtle font-mono text-xs text-slate-400">
                <KeyRound className="w-3.5 h-3.5 text-slate-500 shrink-0" />
                <span className="tracking-widest text-slate-500">••••••••••••••••</span>
                <span className="text-[10px] ml-auto text-emerald-400/80 bg-emerald-950/40 px-1.5 py-0.2 rounded border border-emerald-500/20">
                  AES-256-GCM
                </span>
              </div>

              {c.base_url && (
                <div className="text-[11px] text-slate-400 flex items-center gap-1.5 truncate">
                  <Globe className="w-3 h-3 text-slate-500 shrink-0" />
                  <span className="font-mono truncate">{c.base_url}</span>
                </div>
              )}

              <div className="flex items-center justify-between pt-2 border-t border-border-subtle/50 text-[10px] text-slate-500 font-mono">
                <span>ID: {c.id.slice(0, 12)}...</span>
                <span>
                  {c.last_validated_at
                    ? `Tested ${new Date(c.last_validated_at).toLocaleDateString()}`
                    : 'Not validated yet'}
                </span>
              </div>
            </div>
          ))
        ) : (
          <div className="col-span-full py-12 text-center text-slate-500 text-xs">
            No upstream provider credentials stored in vault for {activeOrgId}. Click "Add Provider Credential" to connect OpenAI, Anthropic, Gemini, Bedrock, etc.
          </div>
        )}
      </div>

      {/* Add Credential Modal with Preflight Validation */}
      <Modal
        isOpen={showAddModal}
        onClose={() => setShowAddModal(false)}
        title="Add Upstream Provider Credential"
        description="Stores an API key in the AES-256-GCM vault with automatic envelope encryption and live upstream preflight validation."
        maxWidth="lg"
      >
        <form onSubmit={handleSubmit} className="space-y-4">
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                Provider Type <span className="text-rose-400">*</span>
              </label>
              <select
                value={provider}
                onChange={(e) => {
                  setProvider(e.target.value as ProviderType);
                  setPreflightResult(null);
                }}
                className="w-full bg-black/60 border border-border-strong rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-accent-primary"
              >
                {providersList.map((p) => (
                  <option key={p.id} value={p.id} className="bg-surface-elevated text-slate-200">
                    {p.label} ({p.id})
                  </option>
                ))}
              </select>
            </div>

            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                Credential Label <span className="text-rose-400">*</span>
              </label>
              <input
                type="text"
                required
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="e.g. prod-openai-primary"
                className="w-full bg-black/60 border border-border-strong rounded-lg px-3 py-2 text-xs text-slate-200 placeholder-slate-600 focus:outline-none focus:border-accent-primary"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">
              API Key / Upstream Secret <span className="text-rose-400">*</span>
            </label>
            <input
              type="password"
              required={provider !== 'ollama'}
              value={apiKey}
              onChange={(e) => {
                setApiKey(e.target.value);
                setPreflightResult(null);
              }}
              placeholder={provider === 'ollama' ? 'Optional for local Ollama' : 'e.g. sk-ant-api03-...'}
              className="w-full bg-black/60 border border-border-strong rounded-lg px-3 py-2 text-xs font-mono text-slate-200 placeholder-slate-600 focus:outline-none focus:border-accent-primary"
            />
          </div>

          {/* Optional Base URL & Azure fields */}
          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">
              Custom Base URL (Optional)
            </label>
            <input
              type="text"
              value={baseURL}
              onChange={(e) => setBaseURL(e.target.value)}
              placeholder="e.g. https://my-vllm.internal:8000/v1 or http://localhost:11434"
              className="w-full bg-black/60 border border-border-strong rounded-lg px-3 py-2 text-xs font-mono text-slate-200 placeholder-slate-600 focus:outline-none focus:border-accent-primary"
            />
          </div>

          {provider === 'azure' && (
            <div className="grid grid-cols-2 gap-3 p-3 rounded-lg bg-surface-elevated/40 border border-border-subtle">
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">
                  Azure Deployment Name
                </label>
                <input
                  type="text"
                  value={azureDeployment}
                  onChange={(e) => setAzureDeployment(e.target.value)}
                  placeholder="e.g. gpt-4o-deployment"
                  className="w-full bg-black/60 border border-border-strong rounded-lg px-3 py-1.5 text-xs font-mono text-slate-200 focus:outline-none focus:border-accent-primary"
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-slate-300 mb-1">
                  API Version
                </label>
                <input
                  type="text"
                  value={apiVersion}
                  onChange={(e) => setApiVersion(e.target.value)}
                  placeholder="2024-08-01-preview"
                  className="w-full bg-black/60 border border-border-strong rounded-lg px-3 py-1.5 text-xs font-mono text-slate-200 focus:outline-none focus:border-accent-primary"
                />
              </div>
            </div>
          )}

          {/* Preflight Test Result */}
          {preflightResult && (
            <div
              className={`p-3 rounded-lg border text-xs font-mono flex items-start gap-2 ${
                preflightResult.valid
                  ? 'bg-emerald-950/40 border-emerald-500/30 text-emerald-300'
                  : 'bg-rose-950/40 border-rose-500/30 text-rose-300'
              }`}
            >
              {preflightResult.valid ? (
                <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
              ) : (
                <XCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />
              )}
              <div>
                <p className="font-semibold">
                  {preflightResult.valid
                    ? `Preflight Success: Verified connection in ${preflightResult.latency_ms} ms (${preflightResult.discovered_models ?? 0} models discovered)`
                    : 'Preflight Failed: Unable to verify upstream authentication'}
                </p>
                {preflightResult.error && (
                  <p className="text-[11px] text-rose-400/90 mt-0.5 break-all">
                    {preflightResult.error}
                  </p>
                )}
              </div>
            </div>
          )}

          <div className="flex items-center justify-between pt-3 border-t border-border-subtle">
            <button
              type="button"
              onClick={handlePreflightTest}
              disabled={preflightTesting || (!apiKey.trim() && provider !== 'ollama')}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-accent-primary/30 bg-[rgba(124,58,237,0.12)] hover:bg-[rgba(124,58,237,0.22)] text-xs font-medium text-accent-primary transition-colors disabled:opacity-50"
            >
              <Zap className={`w-3.5 h-3.5 ${preflightTesting ? 'animate-spin' : ''}`} />
              <span>{preflightTesting ? 'Testing connection...' : 'Test Upstream Before Saving'}</span>
            </button>

            <div className="flex gap-2">
              <button
                type="button"
                onClick={() => setShowAddModal(false)}
                className="px-3 py-1.5 rounded-md text-xs text-slate-400 hover:text-slate-200 hover:bg-surface-elevated transition-colors"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={addMutation.isPending || !name.trim()}
                className="px-4 py-1.5 rounded-md text-xs font-semibold bg-accent-primary hover:bg-accent-glow text-black transition-colors disabled:opacity-50"
              >
                {addMutation.isPending ? 'Saving to Vault...' : 'Save to Vault'}
              </button>
            </div>
          </div>
        </form>
      </Modal>
    </div>
  );
};
