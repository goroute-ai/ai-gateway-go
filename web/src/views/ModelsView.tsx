import React, { useState, useMemo } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { adminApi } from '../api/admin';
import { useAuth } from '../context/AuthContext';
import { Modal, INPUT_CLS, BTN_PRIMARY, BTN_CANCEL } from '../components/common/Modal';
import { Badge } from '../components/common/Badge';
import { ErrorAlert, isPlatformAdminForbidden, ScopedRoleNotice } from '../components/common/ErrorAlert';
import type { GlobalModel, ModelGroup, Deployment } from '../types';
import {
  Search,
  RefreshCw,
  DollarSign,
  Layers,
  Plus,
  Clock,
} from 'lucide-react';

export const ModelsView: React.FC = () => {
  const { adminKey, activeOrgId } = useAuth();
  const queryClient = useQueryClient();

  const [activeTab, setActiveTab] = useState<'catalogue' | 'groups'>('catalogue');
  const [searchQuery, setSearchQuery] = useState('');
  const [providerFilter, setProviderFilter] = useState('');

  // Pricing update & history modals
  const [selectedModel, setSelectedModel] = useState<GlobalModel | null>(null);
  const [historyModel, setHistoryModel] = useState<GlobalModel | null>(null);
  const [inputCostUSD, setInputCostUSD] = useState('');
  const [outputCostUSD, setOutputCostUSD] = useState('');
  const [cachedInputUSD, setCachedInputUSD] = useState('');

  // Create Model Group modal
  const [showCreateGroupModal, setShowCreateGroupModal] = useState(false);
  const [groupAlias, setGroupAlias] = useState('');
  const [groupDesc, setGroupDesc] = useState('');
  const [routingStrategy, setRoutingStrategy] = useState('weighted-shuffle');
  const [groupMaxRetries, setGroupMaxRetries] = useState('');
  const [groupCooldown, setGroupCooldown] = useState('');
  const [groupFailureThreshold, setGroupFailureThreshold] = useState('');

  // Create Deployment modal
  const [deployGroupId, setDeployGroupId] = useState<string | null>(null);
  const [deployGlobalModelId, setDeployGlobalModelId] = useState('');
  const [deployCredentialId, setDeployCredentialId] = useState('');
  const [deployName, setDeployName] = useState('');
  const [deployRegion, setDeployRegion] = useState('');
  const [deployPriority, setDeployPriority] = useState('1');
  const [deployWeight, setDeployWeight] = useState('100');
  const [deployRpm, setDeployRpm] = useState('');
  const [deployTpm, setDeployTpm] = useState('');
  const [deployTimeoutMs, setDeployTimeoutMs] = useState('');

  // 1. Fetch Global Models Catalogue
  const {
    data: catalogueData,
    isLoading: isCatLoading,
    isError: isCatError,
    error: catError,
    refetch: refetchCat,
  } = useQuery({
    queryKey: ['admin', 'catalogue', adminKey],
    queryFn: () => adminApi.listCatalogue(adminKey),
    enabled: !!adminKey,
    retry: (count, err) => !isPlatformAdminForbidden(err) && count < 2,
  });

  // 1b. Fetch Pricing History for selected model
  const {
    data: historyData,
    isLoading: isHistLoading,
    isError: isHistError,
    error: histError,
  } = useQuery({
    queryKey: ['admin', 'pricing-history', adminKey, historyModel?.id],
    queryFn: () => adminApi.listPricingHistory(adminKey, historyModel!.id),
    enabled: !!adminKey && !!historyModel,
  });

  // 2. Fetch Model Groups
  const {
    data: groupsData,
    isLoading: isGroupsLoading,
    isError: isGroupsError,
    error: groupsError,
    refetch: refetchGroups,
  } = useQuery({
    queryKey: ['admin', 'model-groups', adminKey, activeOrgId],
    queryFn: () => adminApi.listModelGroups(adminKey, activeOrgId),
    enabled: !!adminKey,
  });

  // 3. Fetch All Deployments
  const {
    data: deploymentsData,
    isError: isDepsError,
    error: depsError,
    refetch: refetchDeps,
  } = useQuery({
    queryKey: ['admin', 'deployments', adminKey],
    queryFn: () => adminApi.listDeployments(adminKey),
    enabled: !!adminKey,
  });

  const { data: credsData } = useQuery({
    queryKey: ['admin', 'credentials', adminKey, activeOrgId],
    queryFn: () => adminApi.listCredentials(adminKey, activeOrgId),
    enabled: !!adminKey && !!activeOrgId,
  });

  // Discovery Sync mutation
  const syncMutation = useMutation({
    mutationFn: () => adminApi.syncDiscovery(adminKey),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['admin', 'catalogue', adminKey] });
    },
  });

  // Import Catalogue mutation
  const importMutation = useMutation({
    mutationFn: (prov?: string) => adminApi.importCatalogue(adminKey, prov),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['admin', 'catalogue', adminKey] });
    },
  });

  // Update Pricing mutation
  const pricingMutation = useMutation({
    mutationFn: (data: any) => adminApi.updatePricing(adminKey, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['admin', 'catalogue', adminKey] });
      setSelectedModel(null);
    },
  });

  // Create Model Group mutation
  const createGroupMutation = useMutation({
    mutationFn: (data: Partial<ModelGroup>) => adminApi.createModelGroup(adminKey, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['admin', 'model-groups', adminKey] });
      setShowCreateGroupModal(false);
      setGroupAlias('');
      setGroupDesc('');
      setGroupMaxRetries('');
      setGroupCooldown('');
      setGroupFailureThreshold('');
    },
  });

  // Create Deployment mutation
  const createDeploymentMutation = useMutation({
    mutationFn: (data: Partial<Deployment>) => adminApi.createDeployment(adminKey, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['admin', 'deployments', adminKey] });
      setDeployGroupId(null);
      setDeployGlobalModelId('');
      setDeployCredentialId('');
      setDeployName('');
      setDeployRegion('');
      setDeployPriority('1');
      setDeployWeight('100');
      setDeployRpm('');
      setDeployTpm('');
      setDeployTimeoutMs('');
    },
  });

  // Filter catalogue
  const filteredModels = useMemo(() => {
    if (!catalogueData?.data) return [];
    return catalogueData.data.filter((m) => {
      const matchSearch =
        !searchQuery ||
        m.model_name.toLowerCase().includes(searchQuery.toLowerCase()) ||
        m.display_name?.toLowerCase().includes(searchQuery.toLowerCase()) ||
        m.id.toLowerCase().includes(searchQuery.toLowerCase());
      const matchProv = !providerFilter || m.provider === providerFilter;
      return matchSearch && matchProv;
    });
  }, [catalogueData, searchQuery, providerFilter]);

  // Filter catalogue suggestions for Add Deployment datalist
  const suggestionModels = useMemo(() => {
    const all = catalogueData?.data || [];
    const q = deployGlobalModelId.trim().toLowerCase();
    return q
      ? all.filter((m) => m.id.toLowerCase().includes(q) || m.model_name.toLowerCase().includes(q))
      : all;
  }, [catalogueData, deployGlobalModelId]);

  const handleOpenPricingModal = (m: GlobalModel) => {
    setSelectedModel(m);
    setInputCostUSD((m.input_cost_micros_per_1m / 1_000_000).toString());
    setOutputCostUSD((m.output_cost_micros_per_1m / 1_000_000).toString());
    setCachedInputUSD((m.cached_input_cost_micros_per_1m / 1_000_000).toString());
  };

  const handleSavePricing = (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedModel) return;

    const inMicros = Math.round(parseFloat(inputCostUSD || '0') * 1_000_000);
    const outMicros = Math.round(parseFloat(outputCostUSD || '0') * 1_000_000);
    const cachedMicros = Math.round(parseFloat(cachedInputUSD || '0') * 1_000_000);

    pricingMutation.mutate({
      global_model_id: selectedModel.id,
      input_cost_micros_per_1m: inMicros,
      output_cost_micros_per_1m: outMicros,
      cached_input_cost_micros_per_1m: cachedMicros,
      pricing_status: 'verified',
      pricing_provenance_source: 'ui-admin-audit',
      pricing_effective_date: new Date().toISOString(),
    });
  };

  const optInt = (v: string) => {
    const n = parseInt(v, 10);
    return v.trim() && !isNaN(n) ? n : undefined;
  };

  const handleCreateGroup = (e: React.FormEvent) => {
    e.preventDefault();
    if (!groupAlias.trim()) return;

    createGroupMutation.mutate({
      org_id: activeOrgId,
      alias: groupAlias.trim(),
      description: groupDesc.trim() || undefined,
      routing_strategy: routingStrategy,
      max_retries: optInt(groupMaxRetries),
      cooldown_seconds: optInt(groupCooldown),
      failure_threshold: optInt(groupFailureThreshold),
    });
  };

  // Group deployments by model_group_id
  const deploymentsByGroup = useMemo(() => {
    const map = new Map<string, Deployment[]>();
    if (!deploymentsData?.data) return map;
    for (const d of deploymentsData.data) {
      const list = map.get(d.model_group_id) || [];
      list.push(d);
      map.set(d.model_group_id, list);
    }
    return map;
  }, [deploymentsData]);

  return (
    <div className="space-y-6">
      {/* Top Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-brand-title tracking-tight flex items-center gap-2">
            Model Catalogue & Routing Topologies
          </h1>
          <p className="text-xs text-brand-muted mt-1">
            Curated 4-layer model catalogue, tri-state capabilities, integer micro-dollar pricing, and routing topologies
          </p>
        </div>

        <div className="flex items-center gap-2">
          {activeTab === 'catalogue' ? (
            <>
              <button
                onClick={() => importMutation.mutate()}
                disabled={importMutation.isPending}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-border-subtle hover:border-border-strong bg-surface-elevated text-xs font-medium text-brand-body hover:text-brand-title transition-colors disabled:opacity-50"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${importMutation.isPending ? 'animate-spin' : ''}`} />
                <span>Import All Models</span>
              </button>
              <button
                onClick={() => syncMutation.mutate()}
                disabled={syncMutation.isPending}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-accent-primary/30 bg-accent-soft hover:bg-accent-primary/20 text-xs font-medium text-accent-primary transition-colors disabled:opacity-50"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${syncMutation.isPending ? 'animate-spin' : ''}`} />
                <span>Sync Discovery</span>
              </button>
            </>
          ) : (
            <button
              onClick={() => setShowCreateGroupModal(true)}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-accent-primary hover:bg-accent-dark text-xs font-semibold text-accent-contrast transition-colors"
            >
              <Plus className="w-3.5 h-3.5" />
              <span>New Model Group</span>
            </button>
          )}
        </div>
      </div>

      {/* Tabs */}
      <div className="flex items-center gap-1 border-b border-border-subtle">
        <button
          onClick={() => setActiveTab('catalogue')}
          className={`flex items-center gap-2 px-4 py-2 text-xs font-medium border-b-2 transition-all ${
            activeTab === 'catalogue'
              ? 'border-accent-primary text-accent-primary bg-accent-soft'
              : 'border-transparent text-brand-muted hover:text-brand-title'
          }`}
        >
          <Layers className="w-3.5 h-3.5" />
          <span>Curated Catalogue ({catalogueData?.data?.length ?? 0})</span>
        </button>

        <button
          onClick={() => setActiveTab('groups')}
          className={`flex items-center gap-2 px-4 py-2 text-xs font-medium border-b-2 transition-all ${
            activeTab === 'groups'
              ? 'border-accent-primary text-accent-primary bg-accent-soft'
              : 'border-transparent text-brand-muted hover:text-brand-title'
          }`}
        >
          <Layers className="w-3.5 h-3.5" />
          <span>Routing Topologies & Groups ({groupsData?.data?.length ?? 0})</span>
        </button>
      </div>

      {/* Error Alerts */}
      {isCatError && !isPlatformAdminForbidden(catError) && (
        <ErrorAlert error={catError} title="Failed to load global model catalogue" onRetry={() => refetchCat()} />
      )}
      {syncMutation.isError && (
        <ErrorAlert error={syncMutation.error} title="Discovery sync failed" />
      )}
      {importMutation.isError && (
        <ErrorAlert error={importMutation.error} title="Catalogue import failed" />
      )}
      {pricingMutation.isError && !selectedModel && (
        <ErrorAlert error={pricingMutation.error} title="Failed to update pricing" />
      )}
      {createGroupMutation.isError && !showCreateGroupModal && (
        <ErrorAlert error={createGroupMutation.error} title="Failed to create model group" />
      )}
      {isGroupsError && (
        <ErrorAlert error={groupsError} title="Failed to load model groups" onRetry={() => refetchGroups()} />
      )}
      {isDepsError && (
        <ErrorAlert error={depsError} title="Failed to load deployments" onRetry={() => refetchDeps()} />
      )}

      {/* Tab 1: Catalogue Explorer */}
      {activeTab === 'catalogue' && (
        isCatError && isPlatformAdminForbidden(catError) ? (
          <ScopedRoleNotice subject="the global model catalogue" />
        ) : (
        <div className="space-y-4">
          {/* Search bar & Provider Filter */}
          <div className="flex flex-col sm:flex-row gap-3">
            <div className="relative flex-1">
              <Search className="w-3.5 h-3.5 text-brand-muted absolute left-3 top-2.5" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search models by name, alias or display label..."
                className="w-full bg-surface-input border border-border-strong rounded-lg pl-9 pr-3 py-1.5 text-xs text-brand-body placeholder-brand-muted focus:outline-none focus:border-accent-primary"
              />
            </div>

            <select
              value={providerFilter}
              onChange={(e) => setProviderFilter(e.target.value)}
              className="bg-surface-input border border-border-strong rounded-lg px-3 py-1.5 text-xs text-brand-body focus:outline-none focus:border-accent-primary"
            >
              <option value="">All Providers</option>
              <option value="openai">OpenAI</option>
              <option value="anthropic">Anthropic</option>
              <option value="gemini">Google Gemini</option>
              <option value="bedrock">AWS Bedrock</option>
              <option value="vertex">Google Vertex AI</option>
              <option value="azure">Azure OpenAI</option>
              <option value="cohere">Cohere</option>
              <option value="groq">Groq</option>
              <option value="deepseek">DeepSeek</option>
              <option value="ollama">Ollama</option>
            </select>
          </div>

          {/* Table */}
          <div className="rounded-xl border border-border-subtle bg-surface-base/90 overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className="bg-surface-elevated/60 text-brand-muted uppercase text-[10px] tracking-wider border-b border-border-subtle">
                  <tr>
                    <th className="px-6 py-3">Model</th>
                    <th className="px-6 py-3">Provider</th>
                    <th className="px-6 py-3">Pricing (Per 1M Tokens)</th>
                    <th className="px-6 py-3">Capabilities</th>
                    <th className="px-6 py-3">Pricing Provenance</th>
                    <th className="px-6 py-3 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border-subtle/40">
                  {isCatLoading ? (
                    <tr>
                      <td colSpan={6} className="px-6 py-8 text-center text-brand-muted">
                        Loading model catalogue...
                      </td>
                    </tr>
                  ) : filteredModels.length > 0 ? (
                    filteredModels.slice(0, 100).map((m) => {
                      const inputUSD = (m.input_cost_micros_per_1m / 1_000_000).toFixed(4);
                      const outputUSD = (m.output_cost_micros_per_1m / 1_000_000).toFixed(4);

                      return (
                        <tr key={m.id} className="hover:bg-surface-hover/30 transition-colors">
                          <td className="px-6 py-3 font-medium text-brand-title">
                            <div>{m.display_name || m.model_name}</div>
                            <div className="text-[10px] font-mono text-brand-muted">
                              {m.id}
                              {m.max_input_tokens ? ` · ${(m.max_input_tokens / 1000).toFixed(0)}k ctx` : ''}
                            </div>
                          </td>
                          <td className="px-6 py-3">
                            <Badge variant="provider" provider={m.provider} size="sm">
                              {m.provider}
                            </Badge>
                          </td>
                          <td className="px-6 py-3 font-mono text-xs">
                            <div className="text-brand-title font-semibold">
                              In: ${inputUSD} / Out: ${outputUSD}
                            </div>
                            <div className="text-[10px] text-brand-muted">
                              Cache: ${(m.cached_input_cost_micros_per_1m / 1_000_000).toFixed(4)}
                            </div>
                          </td>
                          <td className="px-6 py-3">
                            <div className="flex flex-wrap gap-1 max-w-xs text-[10px]">
                              {(m.capabilities?.tools === 'supported' || m.supports_tools) && (
                                <span className="px-1.5 py-0.2 rounded border status-success">
                                  tools
                                </span>
                              )}
                              {(m.capabilities?.streaming === 'supported' || m.supports_streaming) && (
                                <span className="px-1.5 py-0.2 rounded border status-info">
                                  stream
                                </span>
                              )}
                              {(m.capabilities?.vision === 'supported' || m.supports_vision) && (
                                <span className="px-1.5 py-0.2 rounded border status-indigo">
                                  vision
                                </span>
                              )}
                              {(m.capabilities?.reasoning === 'supported' || m.supports_reasoning) && (
                                <span className="px-1.5 py-0.2 rounded border status-warning">
                                  reasoning
                                </span>
                              )}
                            </div>
                          </td>
                          <td className="px-6 py-3 font-mono text-[11px] text-brand-muted">
                            <div>{m.pricing_status || 'unverified'}</div>
                            <div className="text-[9px] text-brand-muted truncate max-w-[120px]">
                              {m.pricing_provenance_source || 'default'}
                            </div>
                          </td>
                          <td className="px-6 py-3 text-right">
                            <div className="inline-flex items-center gap-1">
                              <button
                                onClick={() => setHistoryModel(m)}
                                className="text-brand-muted hover:text-accent-primary p-1.5 rounded hover:bg-surface-elevated transition-colors"
                                title="View pricing history"
                              >
                                <Clock className="w-3.5 h-3.5" />
                              </button>
                              <button
                                onClick={() => handleOpenPricingModal(m)}
                                className="text-brand-muted hover:text-accent-primary p-1.5 rounded hover:bg-surface-elevated transition-colors"
                                title="Update model pricing rates"
                              >
                                <DollarSign className="w-3.5 h-3.5" />
                              </button>
                            </div>
                          </td>
                        </tr>
                      );
                    })
                  ) : (
                    <tr>
                      <td colSpan={6} className="px-6 py-8 text-center text-brand-muted">
                        No models found matching search query. Click "Import All Models" to load catalogue.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
            {filteredModels.length > 100 && (
              <div className="px-6 py-2 border-t border-border-subtle text-[11px] font-mono text-brand-muted">
                Showing 100 of {filteredModels.length} matching models — refine search or provider filter to narrow results.
              </div>
            )}
          </div>
        </div>
        )
      )}

      {/* Tab 2: Routing Topologies & Model Groups */}
      {activeTab === 'groups' && (
        <div className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {isGroupsLoading ? (
              <div className="col-span-full py-12 text-center text-brand-muted text-xs">
                Loading routing topologies...
              </div>
            ) : groupsData?.data && groupsData.data.length > 0 ? (
              groupsData.data.map((g) => {
                const deps = deploymentsByGroup.get(g.id) || [];
                return (
                  <div
                    key={g.id}
                    className="p-5 rounded-xl border border-border-subtle bg-surface-base/90 space-y-3"
                  >
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-base font-bold text-accent-primary">
                          {g.alias}
                        </span>
                        <Badge size="sm">{g.routing_strategy}</Badge>
                      </div>
                      <span className="text-[10px] font-mono text-brand-muted">ID: {g.id}</span>
                    </div>

                    <div className="space-y-1.5 pt-2 border-t border-border-subtle/50">
                      <div className="flex items-center justify-between">
                        <div className="text-[10px] uppercase font-semibold text-brand-muted tracking-wider">
                          Configured Deployments ({deps.length})
                        </div>
                        <button
                          onClick={() => setDeployGroupId(g.id)}
                          className="flex items-center gap-1 text-[11px] font-mono text-accent-primary hover:underline"
                        >
                          <Plus className="w-3 h-3" />
                          Add Deployment
                        </button>
                      </div>
                      {deps.length > 0 ? (
                        deps.map((d) => (
                          <div
                            key={d.id}
                            className="flex items-center justify-between p-2 rounded bg-surface-elevated/40 border border-border-subtle/60 text-xs font-mono"
                          >
                            <span className="text-brand-body">{d.global_model_id}</span>
                            <div className="flex items-center gap-2 text-[10px] text-brand-muted">
                              <span>P:{d.priority}</span>
                              <span>W:{d.weight}</span>
                              <span className="text-status-success">{d.status}</span>
                            </div>
                          </div>
                        ))
                      ) : (
                        <div className="text-xs text-brand-muted italic p-2">
                          No child deployments attached. Requests to this alias will resolve dynamically.
                        </div>
                      )}
                    </div>
                  </div>
                );
              })
            ) : (
              <div className="col-span-full py-12 text-center text-brand-muted text-xs">
                No model groups configured yet. Click "New Model Group" to create aliases like "fast" or "reasoning".
              </div>
            )}
          </div>
        </div>
      )}

      {/* Pricing Update Modal */}
      <Modal
        isOpen={!!selectedModel}
        onClose={() => setSelectedModel(null)}
        title={`Update Pricing: ${selectedModel?.display_name || selectedModel?.model_name}`}
        description="Updates integer micro-dollar pricing rates ($1.00 = 1,000,000 µ$) and appends an immutable provenance audit record."
        maxWidth="md"
      >
        <form onSubmit={handleSavePricing} className="space-y-4">
          {pricingMutation.isError && (
            <ErrorAlert error={pricingMutation.error} title="Failed to update pricing" />
          )}
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-medium text-brand-body mb-1">Input USD / 1M</label>
              <input type="number" step="0.0001" required value={inputCostUSD} onChange={(e) => setInputCostUSD(e.target.value)} className={`${INPUT_CLS} font-mono`} />
            </div>
            <div>
              <label className="block text-xs font-medium text-brand-body mb-1">Output USD / 1M</label>
              <input type="number" step="0.0001" required value={outputCostUSD} onChange={(e) => setOutputCostUSD(e.target.value)} className={`${INPUT_CLS} font-mono`} />
            </div>
          </div>

          <div>
            <label className="block text-xs font-medium text-brand-body mb-1">Cached Input USD / 1M</label>
            <input type="number" step="0.0001" value={cachedInputUSD} onChange={(e) => setCachedInputUSD(e.target.value)} className={`${INPUT_CLS} font-mono`} />
          </div>

          <div className="flex justify-end gap-2 pt-2">
            <button type="button" onClick={() => setSelectedModel(null)} className={BTN_CANCEL}>Cancel</button>
            <button type="submit" disabled={pricingMutation.isPending} className={BTN_PRIMARY}>
              {pricingMutation.isPending ? 'Updating...' : 'Save Pricing'}
            </button>
          </div>
        </form>
      </Modal>

      {/* Pricing History Modal */}
      <Modal
        isOpen={!!historyModel}
        onClose={() => setHistoryModel(null)}
        title={`Pricing History: ${historyModel?.display_name || historyModel?.model_name}`}
        maxWidth="xl"
      >
        <div className="space-y-3 text-xs">
          {isHistError && (
            <ErrorAlert error={histError} title="Failed to load pricing history" />
          )}
          {isHistLoading ? (
            <div className="py-6 text-center text-brand-muted font-mono">Loading pricing audit trail...</div>
          ) : (historyData?.data || []).length > 0 ? (
            <div className="overflow-x-auto border border-border-subtle rounded-lg">
              <table className="w-full text-left text-[11px] font-mono">
                <thead className="bg-surface-elevated/60 text-brand-muted uppercase text-[10px] border-b border-border-subtle">
                  <tr>
                    <th className="px-3 py-2">Ver</th>
                    <th className="px-3 py-2">In / Out / Cached (1M)</th>
                    <th className="px-3 py-2">Status</th>
                    <th className="px-3 py-2">Changed By</th>
                    <th className="px-3 py-2">Effective</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border-subtle/40">
                  {(historyData?.data || []).map((h) => (
                    <tr key={h.id}>
                      <td className="px-3 py-2 text-accent-primary">v{h.pricing_version}</td>
                      <td className="px-3 py-2 text-brand-body">
                        ${(h.input_cost_micros_per_1m / 1e6).toFixed(4)} / ${(h.output_cost_micros_per_1m / 1e6).toFixed(4)} / ${(h.cached_input_cost_micros_per_1m / 1e6).toFixed(4)}
                      </td>
                      <td className="px-3 py-2 text-brand-body">{h.pricing_status || '-'}</td>
                      <td className="px-3 py-2 text-brand-muted">{h.changed_by}</td>
                      <td className="px-3 py-2 text-brand-muted">{new Date(h.effective_from).toLocaleString()}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <div className="py-6 text-center text-brand-muted font-mono">No pricing history entries recorded.</div>
          )}
        </div>
      </Modal>

      {/* Create Model Group Modal */}
      <Modal isOpen={showCreateGroupModal} onClose={() => setShowCreateGroupModal(false)} title="Create Model Group Alias" maxWidth="md">
        <form onSubmit={handleCreateGroup} className="space-y-4">
          {createGroupMutation.isError && (
            <ErrorAlert error={createGroupMutation.error} title="Failed to create model group" />
          )}
          <div>
            <label className="block text-xs font-medium text-brand-body mb-1">Alias Name *</label>
            <input type="text" required value={groupAlias} onChange={(e) => setGroupAlias(e.target.value)} placeholder="fast, reasoning, coding" className={`${INPUT_CLS} font-mono`} />
          </div>

          <div>
            <label className="block text-xs font-medium text-brand-body mb-1">Description (optional)</label>
            <input type="text" value={groupDesc} onChange={(e) => setGroupDesc(e.target.value)} placeholder="Low-latency primary alias" className={INPUT_CLS} />
          </div>

          <div>
            <label className="block text-xs font-medium text-brand-body mb-1">Routing Strategy</label>
            <select value={routingStrategy} onChange={(e) => setRoutingStrategy(e.target.value)} className={INPUT_CLS}>
              <option value="weighted-shuffle">weighted-shuffle (Default probabilistic)</option>
              <option value="round-robin">round-robin (Cyclic distribution)</option>
              <option value="least-busy">least-busy (Lowest in-flight concurrency)</option>
              <option value="latency-based">latency-based (EWMA latency tracker)</option>
              <option value="usage-based-headroom">usage-based-headroom (TPM limit protection)</option>
              <option value="lowest-cost">lowest-cost (Cheapest micro-dollar deployment)</option>
            </select>
          </div>

          <div className="grid grid-cols-3 gap-2">
            <div><label className="block text-xs font-medium text-brand-body mb-1">Max Retries</label><input type="number" min={0} value={groupMaxRetries} onChange={(e) => setGroupMaxRetries(e.target.value)} placeholder="2" className={`${INPUT_CLS} font-mono`} /></div>
            <div><label className="block text-xs font-medium text-brand-body mb-1">Cooldown (s)</label><input type="number" min={0} value={groupCooldown} onChange={(e) => setGroupCooldown(e.target.value)} placeholder="30" className={`${INPUT_CLS} font-mono`} /></div>
            <div><label className="block text-xs font-medium text-brand-body mb-1">Failure Threshold</label><input type="number" min={0} value={groupFailureThreshold} onChange={(e) => setGroupFailureThreshold(e.target.value)} placeholder="3" className={`${INPUT_CLS} font-mono`} /></div>
          </div>

          <div className="flex justify-end gap-2 pt-2">
            <button type="button" onClick={() => setShowCreateGroupModal(false)} className={BTN_CANCEL}>
              Cancel
            </button>
            <button type="submit" disabled={createGroupMutation.isPending || !groupAlias.trim()} className={BTN_PRIMARY}>
              {createGroupMutation.isPending ? 'Creating...' : 'Create Model Group'}
            </button>
          </div>
        </form>
      </Modal>

      {/* Add Deployment Modal */}
      <Modal
        isOpen={!!deployGroupId}
        onClose={() => setDeployGroupId(null)}
        title="Add Deployment to Model Group"
        description="Attach an upstream global model and provider credential to this routing group."
        maxWidth="md"
      >
        <form
          onSubmit={(e) => {
            e.preventDefault();
            if (!deployGroupId || !deployGlobalModelId.trim()) return;
            const payload: Partial<Deployment> = {
              model_group_id: deployGroupId,
              global_model_id: deployGlobalModelId.trim(),
              priority: parseInt(deployPriority, 10) || 1,
              weight: parseInt(deployWeight, 10) || 100,
              rpm_capacity: optInt(deployRpm),
              tpm_capacity: optInt(deployTpm),
              timeout_ms: optInt(deployTimeoutMs),
            };
            if (deployCredentialId.trim()) payload.credential_id = deployCredentialId.trim();
            if (deployName.trim()) payload.deployment_name = deployName.trim();
            if (deployRegion.trim()) payload.region = deployRegion.trim();
            createDeploymentMutation.mutate(payload);
          }}
          className="space-y-4"
        >
          {createDeploymentMutation.isError && (
            <ErrorAlert error={createDeploymentMutation.error} title="Failed to create deployment" />
          )}
          <div>
            <label className="block text-xs font-medium text-brand-body mb-1">Global Model ID *</label>
            <input type="text" required list="catalogue-models-list" value={deployGlobalModelId} onChange={(e) => setDeployGlobalModelId(e.target.value)} placeholder="openai/gpt-4.1" className={`${INPUT_CLS} font-mono`} />
            <datalist id="catalogue-models-list">
              {suggestionModels.slice(0, 100).map((m) => <option key={m.id} value={m.id} />)}
            </datalist>
            {suggestionModels.length > 100 && (
              <p className="text-[10px] font-mono text-brand-muted mt-1">
                Showing 100 of {suggestionModels.length} matching models — type to narrow suggestions.
              </p>
            )}
          </div>
          <div>
            <label className="block text-xs font-medium text-brand-body mb-1">Provider Credential (optional)</label>
            <select value={deployCredentialId} onChange={(e) => setDeployCredentialId(e.target.value)} className={INPUT_CLS}>
              <option value="">Auto-resolve org credential</option>
              {(credsData?.data || []).map((c) => <option key={c.id} value={c.id}>{c.name} ({c.provider})</option>)}
            </select>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div><label className="block text-xs font-medium text-brand-body mb-1">Deployment Name</label><input type="text" value={deployName} onChange={(e) => setDeployName(e.target.value)} placeholder="primary-us-east" className={`${INPUT_CLS} font-mono`} /></div>
            <div><label className="block text-xs font-medium text-brand-body mb-1">Region</label><input type="text" value={deployRegion} onChange={(e) => setDeployRegion(e.target.value)} placeholder="us-east-1" className={`${INPUT_CLS} font-mono`} /></div>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div><label className="block text-xs font-medium text-brand-body mb-1">Priority</label><input type="number" value={deployPriority} onChange={(e) => setDeployPriority(e.target.value)} className={`${INPUT_CLS} font-mono`} /></div>
            <div><label className="block text-xs font-medium text-brand-body mb-1">Weight</label><input type="number" value={deployWeight} onChange={(e) => setDeployWeight(e.target.value)} className={`${INPUT_CLS} font-mono`} /></div>
          </div>
          <div className="grid grid-cols-3 gap-2">
            <div><label className="block text-xs font-medium text-brand-body mb-1">RPM Cap</label><input type="number" min={0} value={deployRpm} onChange={(e) => setDeployRpm(e.target.value)} placeholder="optional" className={`${INPUT_CLS} font-mono`} /></div>
            <div><label className="block text-xs font-medium text-brand-body mb-1">TPM Cap</label><input type="number" min={0} value={deployTpm} onChange={(e) => setDeployTpm(e.target.value)} placeholder="optional" className={`${INPUT_CLS} font-mono`} /></div>
            <div><label className="block text-xs font-medium text-brand-body mb-1">Timeout (ms)</label><input type="number" min={0} value={deployTimeoutMs} onChange={(e) => setDeployTimeoutMs(e.target.value)} placeholder="30000" className={`${INPUT_CLS} font-mono`} /></div>
          </div>
          <div className="flex justify-end gap-2 pt-2">
            <button type="button" onClick={() => setDeployGroupId(null)} className={BTN_CANCEL}>Cancel</button>
            <button type="submit" disabled={createDeploymentMutation.isPending || !deployGlobalModelId.trim()} className={BTN_PRIMARY}>
              {createDeploymentMutation.isPending ? 'Adding...' : 'Add Deployment'}
            </button>
          </div>
        </form>
      </Modal>
    </div>
  );
};
