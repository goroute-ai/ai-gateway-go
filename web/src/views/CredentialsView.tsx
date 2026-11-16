import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { adminApi } from '../api/admin';
import { useAuth } from '../context/AuthContext';
import { Modal, INPUT_CLS, BTN_PRIMARY, BTN_CANCEL } from '../components/common/Modal';
import { Badge } from '../components/common/Badge';
import { ErrorAlert } from '../components/common/ErrorAlert';
import type { ProviderCredential, ProviderType, CredentialValidationResult } from '../types';
import {
  Plus,
  RefreshCw,
  Key,
  CheckCircle2,
  XCircle,
  Zap,
  Layers,
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
  const [headersJSON, setHeadersJSON] = useState('');
  const [headersError, setHeadersError] = useState<string | null>(null);
  const [expiresAt, setExpiresAt] = useState('');

  // Rotate key modal state
  const [rotateCred, setRotateCred] = useState<ProviderCredential | null>(null);
  const [rotateApiKey, setRotateApiKey] = useState('');
  const [rotateBaseURL, setRotateBaseURL] = useState('');
  const [rotateExpiresAt, setRotateExpiresAt] = useState('');

  // Per-credential validation & preflight test state
  const [validationResults, setValidationResults] = useState<Record<string, CredentialValidationResult>>({});
  const [preflightTesting, setPreflightTesting] = useState(false);
  const [preflightResult, setPreflightResult] = useState<CredentialValidationResult | null>(null);

  // 1. Fetch credentials
  const {
    data: credsData,
    isLoading,
    isError,
    error,
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
    onSuccess: (res, credId) => {
      setValidationResults((prev) => ({ ...prev, [credId]: res }));
      queryClient.invalidateQueries({ queryKey: ['admin', 'credentials', adminKey] });
    },
  });

  // 4. Rotate credential mutation
  const rotateMutation = useMutation({
    mutationFn: ({ credId, data }: { credId: string; data: any }) =>
      adminApi.rotateCredential(adminKey, credId, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['admin', 'credentials', adminKey] });
      setRotateCred(null);
      setRotateApiKey('');
      setRotateBaseURL('');
      setRotateExpiresAt('');
    },
  });

  const resetForm = () => {
    setProvider('openai');
    setName('');
    setApiKey('');
    setBaseURL('');
    setAzureDeployment('');
    setApiVersion('');
    setHeadersJSON('');
    setHeadersError(null);
    setExpiresAt('');
    setPreflightResult(null);
  };

  const parseHeaders = (): Record<string, string> | undefined | false => {
    const raw = headersJSON.trim();
    if (!raw) {
      setHeadersError(null);
      return undefined;
    }
    try {
      const parsed = JSON.parse(raw);
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        setHeadersError('Headers must be a JSON object of key/value strings.');
        return false;
      }
      const out: Record<string, string> = {};
      for (const [k, v] of Object.entries(parsed)) out[k] = String(v);
      setHeadersError(null);
      return out;
    } catch {
      setHeadersError('Invalid JSON in custom headers.');
      return false;
    }
  };

  const handlePreflightTest = async () => {
    if (!apiKey.trim() && provider !== 'ollama') return;
    const headers = parseHeaders();
    if (headers === false) return;
    setPreflightTesting(true);
    setPreflightResult(null);

    try {
      const res = await adminApi.preflightValidate(adminKey, {
        provider,
        api_key: apiKey.trim(),
        base_url: baseURL.trim() || undefined,
        azure_deployment_name: azureDeployment.trim() || undefined,
        api_version: apiVersion.trim() || undefined,
        headers,
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
    const headers = parseHeaders();
    if (headers === false) return;

    const payload: Record<string, any> = {
      org_id: activeOrgId,
      provider,
      name: name.trim(),
      api_key: apiKey.trim(),
      base_url: baseURL.trim() || undefined,
      azure_deployment_name: azureDeployment.trim() || undefined,
      api_version: apiVersion.trim() || undefined,
      headers,
    };
    if (expiresAt) {
      const d = new Date(expiresAt);
      if (!isNaN(d.getTime())) payload.expires_at = d.toISOString();
    }
    addMutation.mutate(payload);
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
    { id: 'together', label: 'Together AI' },
    { id: 'sambanova', label: 'SambaNova' },
    { id: 'fireworks', label: 'Fireworks AI' },
    { id: 'perplexity', label: 'Perplexity' },
    { id: 'ollama', label: 'Ollama (Local)' },
    { id: 'cerebras', label: 'Cerebras' },
    { id: 'xai', label: 'xAI Grok' },
  ];

  return (
    <div className="space-y-6">
      {/* Header bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-brand-title tracking-tight flex items-center gap-2">
            Provider Credentials Vault
          </h1>
          <p className="text-xs text-brand-muted mt-1">
            Boundary 2 provider credentials protected via AES-256-GCM envelope encryption with per-credential DEKs
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
              addMutation.reset();
              resetForm();
              setShowAddModal(true);
            }}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-accent-primary hover:bg-accent-dark text-xs font-semibold text-accent-contrast transition-colors"
          >
            <Plus className="w-3.5 h-3.5" />
            <span>Add Provider Credential</span>
          </button>
        </div>
      </div>

      {isError && (
        <ErrorAlert error={error} title="Failed to load provider credentials" onRetry={() => refetch()} />
      )}
      {validateMutation.isError && (
        <ErrorAlert error={validateMutation.error} title="Failed to validate credential" />
      )}

      {/* Credentials Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {isLoading ? (
          <div className="col-span-full py-12 text-center text-brand-muted text-xs">
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
                    <span className="text-[10px] font-mono text-brand-muted">v{c.key_version}</span>
                  </div>
                  <h3 className="text-sm font-semibold text-brand-title mt-1.5">{c.name}</h3>
                </div>

                <div className="flex items-center gap-1">
                  <button
                    onClick={() => {
                      setRotateCred(c);
                      setRotateApiKey('');
                      setRotateBaseURL(c.base_url || '');
                      setRotateExpiresAt('');
                    }}
                    className="flex items-center gap-1 text-[11px] text-brand-muted hover:text-status-warning p-1 rounded hover:bg-surface-elevated transition-colors"
                    title="Rotate API key"
                  >
                    <Key className="w-3.5 h-3.5" />
                    <span>Rotate</span>
                  </button>
                  <button
                    onClick={() => validateMutation.mutate(c.id)}
                    disabled={validateMutation.isPending}
                    className="flex items-center gap-1 text-[11px] text-brand-muted hover:text-accent-primary p-1 rounded hover:bg-surface-elevated transition-colors"
                    title="Validate connection against upstream provider API"
                  >
                    <RefreshCw className={`w-3.5 h-3.5 ${validateMutation.isPending ? 'animate-spin' : ''}`} />
                    <span>Test</span>
                  </button>
                </div>
              </div>

              {/* Generic Masked State */}
              <div className="flex items-center gap-2 p-2 rounded bg-surface-code border border-border-subtle font-mono text-xs text-brand-muted">
                <Key className="w-3.5 h-3.5 text-brand-muted shrink-0" />
                <span className="tracking-widest text-brand-muted">••••••••••••••••</span>
                <span className="text-[10px] ml-auto status-success px-1.5 py-0.2 rounded border">
                  AES-256-GCM
                </span>
              </div>

              {c.base_url && (
                <div className="text-[11px] text-brand-muted flex items-center gap-1.5 truncate">
                  <Layers className="w-3 h-3 text-brand-muted shrink-0" />
                  <span className="font-mono truncate">{c.base_url}</span>
                </div>
              )}

              {validationResults[c.id] && (() => {
                const vr = validationResults[c.id];
                return (
                  <div
                    className={`p-2 rounded border text-[11px] font-mono flex items-start gap-1.5 ${
                      vr.valid ? 'status-success' : 'status-danger'
                    }`}
                  >
                    {vr.valid ? (
                      <CheckCircle2 className="w-3.5 h-3.5 text-status-success shrink-0 mt-0.5" />
                    ) : (
                      <XCircle className="w-3.5 h-3.5 text-status-danger shrink-0 mt-0.5" />
                    )}
                    <span className="break-words">
                      {vr.valid
                        ? `Valid${vr.latency_ms != null ? ` (${vr.latency_ms} ms)` : ''}${vr.discovered_models != null ? ` · ${vr.discovered_models} models` : ''}`
                        : `Invalid: ${vr.error || vr.reason || vr.validation_status || 'Validation failed'}`}
                    </span>
                  </div>
                );
              })()}

              <div className="flex items-center justify-between pt-2 border-t border-border-subtle/50 text-[10px] text-brand-muted font-mono">
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
          <div className="col-span-full py-12 text-center text-brand-muted text-xs">
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
          {addMutation.isError && (
            <ErrorAlert error={addMutation.error} title="Failed to save provider credential" />
          )}
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-medium text-brand-body mb-1">Provider *</label>
              <select value={provider} onChange={(e) => { setProvider(e.target.value as ProviderType); setPreflightResult(null); }} className={INPUT_CLS}>
                {providersList.map((p) => <option key={p.id} value={p.id}>{p.label} ({p.id})</option>)}
              </select>
            </div>
            <div>
              <label className="block text-xs font-medium text-brand-body mb-1">Credential Label *</label>
              <input type="text" required value={name} onChange={(e) => setName(e.target.value)} placeholder="prod-openai-primary" className={INPUT_CLS} />
            </div>
          </div>

          <div>
            <label className="block text-xs font-medium text-brand-body mb-1">API Key *</label>
            <input type="password" required={provider !== 'ollama'} value={apiKey} onChange={(e) => { setApiKey(e.target.value); setPreflightResult(null); }} placeholder={provider === 'ollama' ? 'Optional for Ollama' : 'sk-...'} className={`${INPUT_CLS} font-mono`} />
          </div>

          {/* Optional Base URL & Azure fields */}
          <div>
            <label className="block text-xs font-medium text-brand-body mb-1">
              Custom Base URL (Optional)
            </label>
            <input
              type="text"
              value={baseURL}
              onChange={(e) => setBaseURL(e.target.value)}
              placeholder="e.g. https://my-vllm.internal:8000/v1 or http://localhost:11434"
              className={`${INPUT_CLS} font-mono`}
            />
          </div>

          {provider === 'azure' && (
            <div className="grid grid-cols-2 gap-3 p-3 rounded-lg bg-surface-elevated/40 border border-border-subtle">
              <div>
                <label className="block text-xs font-medium text-brand-body mb-1">
                  Azure Deployment Name
                </label>
                <input
                  type="text"
                  value={azureDeployment}
                  onChange={(e) => setAzureDeployment(e.target.value)}
                  placeholder="e.g. gpt-4o-deployment"
                  className={`${INPUT_CLS} py-1.5 font-mono`}
                />
              </div>
              <div>
                <label className="block text-xs font-medium text-brand-body mb-1">
                  API Version
                </label>
                <input
                  type="text"
                  value={apiVersion}
                  onChange={(e) => setApiVersion(e.target.value)}
                  placeholder="2024-08-01-preview"
                  className={`${INPUT_CLS} py-1.5 font-mono`}
                />
              </div>
            </div>
          )}

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-medium text-brand-body mb-1">Custom Headers JSON (Optional)</label>
              <input
                type="text"
                value={headersJSON}
                onChange={(e) => { setHeadersJSON(e.target.value); setHeadersError(null); }}
                placeholder='{"X-Custom-Header":"value"}'
                className={`${INPUT_CLS} font-mono`}
              />
              {headersError && <p className="text-[11px] text-status-danger mt-1">{headersError}</p>}
            </div>
            <div>
              <label className="block text-xs font-medium text-brand-body mb-1">Expires At (Optional)</label>
              <input
                type="datetime-local"
                value={expiresAt}
                onChange={(e) => setExpiresAt(e.target.value)}
                className={`${INPUT_CLS} font-mono`}
              />
            </div>
          </div>

          {/* Preflight Test Result */}
          {preflightResult && (
            <div
              className={`p-3 rounded-lg border text-xs font-mono flex items-start gap-2 ${
                preflightResult.valid ? 'status-success' : 'status-danger'
              }`}
            >
              {preflightResult.valid ? (
                <CheckCircle2 className="w-4 h-4 text-status-success shrink-0 mt-0.5" />
              ) : (
                <XCircle className="w-4 h-4 text-status-danger shrink-0 mt-0.5" />
              )}
              <div>
                <p className="font-semibold">
                  {preflightResult.valid
                    ? `Preflight Success: Verified connection in ${preflightResult.latency_ms} ms (${preflightResult.discovered_models ?? 0} models discovered)`
                    : 'Preflight Failed: Unable to verify upstream authentication'}
                </p>
                {preflightResult.error && (
                  <p className="text-[11px] opacity-90 mt-0.5 break-all">
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
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-accent-primary/30 bg-accent-soft hover:bg-accent-primary/20 text-xs font-medium text-accent-primary transition-colors disabled:opacity-50"
            >
              <Zap className={`w-3.5 h-3.5 ${preflightTesting ? 'animate-spin' : ''}`} />
              <span>{preflightTesting ? 'Testing connection...' : 'Test Upstream Before Saving'}</span>
            </button>

            <div className="flex gap-2">
              <button
                type="button"
                onClick={() => setShowAddModal(false)}
                className={BTN_CANCEL}
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={addMutation.isPending || !name.trim()}
                className={BTN_PRIMARY}
              >
                {addMutation.isPending ? 'Saving to Vault...' : 'Save to Vault'}
              </button>
            </div>
          </div>
        </form>
      </Modal>

      {/* Rotate Credential Modal */}
      <Modal
        isOpen={!!rotateCred}
        onClose={() => setRotateCred(null)}
        title={`Rotate Key: ${rotateCred?.name || ''}`}
        description="Re-encrypts the upstream secret with a new key version in the AES-256-GCM vault."
        maxWidth="md"
      >
        <form
          onSubmit={(e) => {
            e.preventDefault();
            if (!rotateCred || !rotateApiKey.trim()) return;
            const payload: any = { api_key: rotateApiKey.trim() };
            if (rotateBaseURL.trim()) payload.base_url = rotateBaseURL.trim();
            if (rotateExpiresAt) {
              const d = new Date(rotateExpiresAt);
              if (!isNaN(d.getTime())) payload.expires_at = d.toISOString();
            }
            rotateMutation.mutate({ credId: rotateCred.id, data: payload });
          }}
          className="space-y-4"
        >
          {rotateMutation.isError && (
            <ErrorAlert error={rotateMutation.error} title="Failed to rotate credential" />
          )}
          <div>
            <label className="block text-xs font-medium text-brand-body mb-1">
              New API Key <span className="text-status-danger">*</span>
            </label>
            <input type="password" required value={rotateApiKey} onChange={(e) => setRotateApiKey(e.target.value)} placeholder="Enter replacement API key..." className={`${INPUT_CLS} font-mono`} />
          </div>
          <div>
            <label className="block text-xs font-medium text-brand-body mb-1">Base URL (optional)</label>
            <input type="text" value={rotateBaseURL} onChange={(e) => setRotateBaseURL(e.target.value)} placeholder="Leave blank to keep existing" className={`${INPUT_CLS} font-mono`} />
          </div>
          <div>
            <label className="block text-xs font-medium text-brand-body mb-1">Expires At (optional)</label>
            <input type="datetime-local" value={rotateExpiresAt} onChange={(e) => setRotateExpiresAt(e.target.value)} className={`${INPUT_CLS} font-mono`} />
          </div>
          <div className="flex justify-end gap-2 pt-2">
            <button type="button" onClick={() => setRotateCred(null)} className={BTN_CANCEL}>Cancel</button>
            <button type="submit" disabled={rotateMutation.isPending || !rotateApiKey.trim()} className={BTN_PRIMARY}>
              {rotateMutation.isPending ? 'Rotating...' : 'Rotate Key'}
            </button>
          </div>
        </form>
      </Modal>
    </div>
  );
};
