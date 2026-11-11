import React, { useState, useMemo } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { adminApi } from '../api/admin';
import { useAuth } from '../context/AuthContext';
import { Modal } from '../components/common/Modal';
import { Badge } from '../components/common/Badge';
import type { GlobalModel, ModelGroup, Deployment } from '../types';
import {
  Boxes,
  Search,
  RefreshCw,
  DownloadCloud,
  DollarSign,
  Layers,
  Plus,
} from 'lucide-react';

export const ModelsView: React.FC = () => {
  const { adminKey, activeOrgId } = useAuth();
  const queryClient = useQueryClient();

  const [activeTab, setActiveTab] = useState<'catalogue' | 'groups'>('catalogue');
  const [searchQuery, setSearchQuery] = useState('');
  const [providerFilter, setProviderFilter] = useState('');

  // Pricing update modal state
  const [selectedModel, setSelectedModel] = useState<GlobalModel | null>(null);
  const [inputCostUSD, setInputCostUSD] = useState('');
  const [outputCostUSD, setOutputCostUSD] = useState('');
  const [cachedInputUSD, setCachedInputUSD] = useState('');

  // Create Model Group modal
  const [showCreateGroupModal, setShowCreateGroupModal] = useState(false);
  const [groupAlias, setGroupAlias] = useState('');
  const [routingStrategy, setRoutingStrategy] = useState('weighted-shuffle');

  // 1. Fetch Global Models Catalogue
  const {
    data: catalogueData,
    isLoading: isCatLoading,
  } = useQuery({
    queryKey: ['admin', 'catalogue', adminKey],
    queryFn: () => adminApi.listCatalogue(adminKey),
    enabled: !!adminKey,
  });

  // 2. Fetch Model Groups
  const {
    data: groupsData,
    isLoading: isGroupsLoading,
  } = useQuery({
    queryKey: ['admin', 'model-groups', adminKey, activeOrgId],
    queryFn: () => adminApi.listModelGroups(adminKey, activeOrgId),
    enabled: !!adminKey,
  });

  // 3. Fetch All Deployments
  const {
    data: deploymentsData,
  } = useQuery({
    queryKey: ['admin', 'deployments', adminKey],
    queryFn: () => adminApi.listDeployments(adminKey),
    enabled: !!adminKey,
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

  const handleCreateGroup = (e: React.FormEvent) => {
    e.preventDefault();
    if (!groupAlias.trim()) return;

    createGroupMutation.mutate({
      org_id: activeOrgId,
      alias: groupAlias.trim(),
      routing_strategy: routingStrategy,
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
          <h1 className="text-xl font-bold text-white tracking-tight flex items-center gap-2">
            Model Catalogue & Routing Topologies
          </h1>
          <p className="text-xs text-slate-400 mt-1">
            Curated 4-layer model catalogue, tri-state capabilities, integer micro-dollar pricing, and routing topologies
          </p>
        </div>

        <div className="flex items-center gap-2">
          {activeTab === 'catalogue' ? (
            <>
              <button
                onClick={() => importMutation.mutate()}
                disabled={importMutation.isPending}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-border-subtle hover:border-border-strong bg-surface-elevated text-xs font-medium text-slate-300 hover:text-white transition-colors disabled:opacity-50"
              >
                <DownloadCloud className={`w-3.5 h-3.5 ${importMutation.isPending ? 'animate-bounce' : ''}`} />
                <span>Import All Models</span>
              </button>
              <button
                onClick={() => syncMutation.mutate()}
                disabled={syncMutation.isPending}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-cyan-500/30 bg-cyan-950/40 hover:bg-cyan-900/50 text-xs font-medium text-cyan-300 transition-colors disabled:opacity-50"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${syncMutation.isPending ? 'animate-spin' : ''}`} />
                <span>Sync Discovery</span>
              </button>
            </>
          ) : (
            <button
              onClick={() => setShowCreateGroupModal(true)}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-accent-primary hover:bg-accent-glow text-xs font-semibold text-black transition-colors"
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
              ? 'border-accent-primary text-accent-glow bg-accent-primary/5'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Boxes className="w-3.5 h-3.5" />
          <span>Curated Catalogue ({catalogueData?.data?.length ?? 0})</span>
        </button>

        <button
          onClick={() => setActiveTab('groups')}
          className={`flex items-center gap-2 px-4 py-2 text-xs font-medium border-b-2 transition-all ${
            activeTab === 'groups'
              ? 'border-accent-primary text-accent-glow bg-accent-primary/5'
              : 'border-transparent text-slate-400 hover:text-slate-200'
          }`}
        >
          <Layers className="w-3.5 h-3.5" />
          <span>Routing Topologies & Groups ({groupsData?.data?.length ?? 0})</span>
        </button>
      </div>

      {/* Tab 1: Catalogue Explorer */}
      {activeTab === 'catalogue' && (
        <div className="space-y-4">
          {/* Search bar & Provider Filter */}
          <div className="flex flex-col sm:flex-row gap-3">
            <div className="relative flex-1">
              <Search className="w-3.5 h-3.5 text-slate-500 absolute left-3 top-2.5" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search models by name, alias or display label..."
                className="w-full bg-surface-base border border-border-strong rounded-lg pl-9 pr-3 py-1.5 text-xs text-slate-200 placeholder-slate-500 focus:outline-none focus:border-accent-primary"
              />
            </div>

            <select
              value={providerFilter}
              onChange={(e) => setProviderFilter(e.target.value)}
              className="bg-surface-base border border-border-strong rounded-lg px-3 py-1.5 text-xs text-slate-200 focus:outline-none focus:border-accent-primary"
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
                <thead className="bg-surface-elevated/60 text-slate-400 uppercase text-[10px] tracking-wider border-b border-border-subtle">
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
                      <td colSpan={6} className="px-6 py-8 text-center text-slate-500">
                        Loading model catalogue...
                      </td>
                    </tr>
                  ) : filteredModels.length > 0 ? (
                    filteredModels.slice(0, 100).map((m) => {
                      const inputUSD = (m.input_cost_micros_per_1m / 1_000_000).toFixed(4);
                      const outputUSD = (m.output_cost_micros_per_1m / 1_000_000).toFixed(4);

                      return (
                        <tr key={m.id} className="hover:bg-surface-hover/30 transition-colors">
                          <td className="px-6 py-3 font-medium text-slate-200">
                            <div>{m.display_name || m.model_name}</div>
                            <div className="text-[10px] font-mono text-slate-500">{m.id}</div>
                          </td>
                          <td className="px-6 py-3">
                            <Badge variant="provider" provider={m.provider} size="sm">
                              {m.provider}
                            </Badge>
                          </td>
                          <td className="px-6 py-3 font-mono text-xs">
                            <div className="text-slate-200 font-semibold">
                              In: ${inputUSD} / Out: ${outputUSD}
                            </div>
                            <div className="text-[10px] text-slate-500">
                              Cache: ${(m.cached_input_cost_micros_per_1m / 1_000_000).toFixed(4)}
                            </div>
                          </td>
                          <td className="px-6 py-3">
                            <div className="flex flex-wrap gap-1 max-w-xs text-[10px]">
                              {m.capabilities?.tools === 'supported' && (
                                <span className="px-1.5 py-0.2 rounded bg-emerald-950/60 text-emerald-400 border border-emerald-500/20">
                                  tools
                                </span>
                              )}
                              {m.capabilities?.streaming === 'supported' && (
                                <span className="px-1.5 py-0.2 rounded bg-cyan-950/60 text-cyan-400 border border-cyan-500/20">
                                  stream
                                </span>
                              )}
                              {m.capabilities?.vision === 'supported' && (
                                <span className="px-1.5 py-0.2 rounded bg-indigo-950/60 text-indigo-400 border border-indigo-500/20">
                                  vision
                                </span>
                              )}
                              {m.capabilities?.reasoning === 'supported' && (
                                <span className="px-1.5 py-0.2 rounded bg-amber-950/60 text-amber-400 border border-amber-500/20">
                                  reasoning
                                </span>
                              )}
                            </div>
                          </td>
                          <td className="px-6 py-3 font-mono text-[11px] text-slate-400">
                            <div>{m.pricing_status || 'unverified'}</div>
                            <div className="text-[9px] text-slate-500 truncate max-w-[120px]">
                              {m.pricing_provenance_source || 'default'}
                            </div>
                          </td>
                          <td className="px-6 py-3 text-right">
                            <button
                              onClick={() => handleOpenPricingModal(m)}
                              className="text-slate-400 hover:text-cyan-400 p-1.5 rounded hover:bg-surface-elevated transition-colors"
                              title="Update model pricing rates"
                            >
                              <DollarSign className="w-3.5 h-3.5" />
                            </button>
                          </td>
                        </tr>
                      );
                    })
                  ) : (
                    <tr>
                      <td colSpan={6} className="px-6 py-8 text-center text-slate-500">
                        No models found matching search query. Click "Import All Models" to load catalogue.
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* Tab 2: Routing Topologies & Model Groups */}
      {activeTab === 'groups' && (
        <div className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {isGroupsLoading ? (
              <div className="col-span-full py-12 text-center text-slate-500 text-xs">
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
                        <span className="font-mono text-base font-bold text-accent-glow">
                          {g.alias}
                        </span>
                        <Badge size="sm">{g.routing_strategy}</Badge>
                      </div>
                      <span className="text-[10px] font-mono text-slate-500">ID: {g.id}</span>
                    </div>

                    <div className="space-y-1.5 pt-2 border-t border-border-subtle/50">
                      <div className="text-[10px] uppercase font-semibold text-slate-500 tracking-wider">
                        Configured Deployments ({deps.length})
                      </div>
                      {deps.length > 0 ? (
                        deps.map((d) => (
                          <div
                            key={d.id}
                            className="flex items-center justify-between p-2 rounded bg-surface-elevated/40 border border-border-subtle/60 text-xs font-mono"
                          >
                            <span className="text-slate-300">{d.global_model_id}</span>
                            <div className="flex items-center gap-2 text-[10px] text-slate-400">
                              <span>P:{d.priority}</span>
                              <span>W:{d.weight}</span>
                              <span className="text-emerald-400">{d.status}</span>
                            </div>
                          </div>
                        ))
                      ) : (
                        <div className="text-xs text-slate-500 italic p-2">
                          No child deployments attached. Requests to this alias will resolve dynamically.
                        </div>
                      )}
                    </div>
                  </div>
                );
              })
            ) : (
              <div className="col-span-full py-12 text-center text-slate-500 text-xs">
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
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                Input USD per 1M Tokens
              </label>
              <input
                type="number"
                step="0.0001"
                required
                value={inputCostUSD}
                onChange={(e) => setInputCostUSD(e.target.value)}
                className="w-full bg-black/60 border border-border-strong rounded-lg px-3 py-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-accent-primary"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                Output USD per 1M Tokens
              </label>
              <input
                type="number"
                step="0.0001"
                required
                value={outputCostUSD}
                onChange={(e) => setOutputCostUSD(e.target.value)}
                className="w-full bg-black/60 border border-border-strong rounded-lg px-3 py-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-accent-primary"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">
              Cached Input USD per 1M Tokens
            </label>
            <input
              type="number"
              step="0.0001"
              value={cachedInputUSD}
              onChange={(e) => setCachedInputUSD(e.target.value)}
              className="w-full bg-black/60 border border-border-strong rounded-lg px-3 py-2 text-xs font-mono text-slate-200 focus:outline-none focus:border-accent-primary"
            />
          </div>

          <div className="flex justify-end gap-2 pt-2">
            <button
              type="button"
              onClick={() => setSelectedModel(null)}
              className="px-3 py-1.5 rounded-md text-xs text-slate-400 hover:text-slate-200 hover:bg-surface-elevated transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={pricingMutation.isPending}
              className="px-4 py-1.5 rounded-md text-xs font-semibold bg-accent-primary hover:bg-accent-glow text-black transition-colors disabled:opacity-50"
            >
              {pricingMutation.isPending ? 'Updating...' : 'Save & Verify Pricing'}
            </button>
          </div>
        </form>
      </Modal>

      {/* Create Model Group Modal */}
      <Modal
        isOpen={showCreateGroupModal}
        onClose={() => setShowCreateGroupModal(false)}
        title="Create Model Group Routing Alias"
        description="Defines a smart alias like 'fast', 'reasoning', or 'auto' for intelligent load balancing and failover routing."
        maxWidth="md"
      >
        <form onSubmit={handleCreateGroup} className="space-y-4">
          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">
              Alias Name <span className="text-rose-400">*</span>
            </label>
            <input
              type="text"
              required
              value={groupAlias}
              onChange={(e) => setGroupAlias(e.target.value)}
              placeholder="e.g. fast, reasoning, coding, enterprise-tier"
              className="w-full bg-black/60 border border-border-strong rounded-lg px-3 py-2 text-xs font-mono text-slate-200 placeholder-slate-600 focus:outline-none focus:border-accent-primary"
            />
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">
              Load Balancing Strategy
            </label>
            <select
              value={routingStrategy}
              onChange={(e) => setRoutingStrategy(e.target.value)}
              className="w-full bg-black/60 border border-border-strong rounded-lg px-3 py-2 text-xs text-slate-200 focus:outline-none focus:border-accent-primary"
            >
              <option value="weighted-shuffle">weighted-shuffle (Default probabilistic)</option>
              <option value="least-busy">least-busy (Lowest in-flight concurrency)</option>
              <option value="latency-based">latency-based (EWMA latency tracker)</option>
              <option value="usage-based-headroom">usage-based-headroom (TPM limit protection)</option>
              <option value="lowest-cost">lowest-cost (Cheapest micro-dollar deployment)</option>
            </select>
          </div>

          <div className="flex justify-end gap-2 pt-2">
            <button
              type="button"
              onClick={() => setShowCreateGroupModal(false)}
              className="px-3 py-1.5 rounded-md text-xs text-slate-400 hover:text-slate-200 hover:bg-surface-elevated transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={createGroupMutation.isPending || !groupAlias.trim()}
              className="px-4 py-1.5 rounded-md text-xs font-semibold bg-accent-primary hover:bg-accent-glow text-black transition-colors disabled:opacity-50"
            >
              {createGroupMutation.isPending ? 'Creating...' : 'Create Model Group'}
            </button>
          </div>
        </form>
      </Modal>
    </div>
  );
};
