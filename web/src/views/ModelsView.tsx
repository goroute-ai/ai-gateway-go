import React, { useState, useMemo } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { adminApi } from '../api/admin';
import { useAuth } from '../context/AuthContext';
import { Modal, FormModal, Field, INPUT_CLS, MONO_INPUT_CLS, BTN_ACC, THEAD_CLS } from '../components/common/Modal';
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
  Pencil,
  Trash2,
  Power,
} from 'lucide-react';

export const ModelsView: React.FC = () => {
  const { adminKey, isUnlocked, activeOrgId } = useAuth();
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

  // Create / Edit Model Group modal
  const [showCreateGroupModal, setShowCreateGroupModal] = useState(false);
  const [editingGroupId, setEditingGroupId] = useState<string | null>(null);
  const [groupAlias, setGroupAlias] = useState('');
  const [groupDesc, setGroupDesc] = useState('');
  const [routingStrategy, setRoutingStrategy] = useState('weighted-shuffle');
  const [groupMaxRetries, setGroupMaxRetries] = useState('');
  const [groupCooldown, setGroupCooldown] = useState('');
  const [groupFailureThreshold, setGroupFailureThreshold] = useState('');
  const [groupFallbacks, setGroupFallbacks] = useState('');
  const [groupCtxFallbacks, setGroupCtxFallbacks] = useState('');
  const [groupPolicyFallbacks, setGroupPolicyFallbacks] = useState('');
  const [groupSatFallbacks, setGroupSatFallbacks] = useState('');
  const [groupDropUnsupported, setGroupDropUnsupported] = useState(false);
  const [groupDisableCooldowns, setGroupDisableCooldowns] = useState(false);

  // Create / Edit Deployment modal
  const [deployGroupId, setDeployGroupId] = useState<string | null>(null);
  const [editingDeployId, setEditingDeployId] = useState<string | null>(null);
  const [deployGlobalModelId, setDeployGlobalModelId] = useState('');
  const [deployCredentialId, setDeployCredentialId] = useState('');
  const [deployName, setDeployName] = useState('');
  const [deployRegion, setDeployRegion] = useState('');
  const [deployPriority, setDeployPriority] = useState('1');
  const [deployWeight, setDeployWeight] = useState('100');
  const [deployTags, setDeployTags] = useState('');
  const [deployBudgetUSD, setDeployBudgetUSD] = useState('');
  const [deployBudgetPeriod, setDeployBudgetPeriod] = useState('');
  const [deployRpm, setDeployRpm] = useState('');
  const [deployTpm, setDeployTpm] = useState('');
  const [deployItpm, setDeployItpm] = useState('');
  const [deployOtpm, setDeployOtpm] = useState('');
  const [deployMaxParallel, setDeployMaxParallel] = useState('');
  const [deployTimeoutMs, setDeployTimeoutMs] = useState('');
  const [deployStatus, setDeployStatus] = useState('active');

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
    enabled: isUnlocked,
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
    enabled: isUnlocked && !!historyModel,
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
    enabled: isUnlocked,
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
    enabled: isUnlocked,
  });

  const { data: credsData } = useQuery({
    queryKey: ['admin', 'credentials', adminKey, activeOrgId],
    queryFn: () => adminApi.listCredentials(adminKey, activeOrgId),
    enabled: isUnlocked && !!activeOrgId,
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

  const resetGroupForm = () => {
    setShowCreateGroupModal(false);
    setEditingGroupId(null);
    setGroupAlias('');
    setGroupDesc('');
    setRoutingStrategy('weighted-shuffle');
    setGroupMaxRetries('');
    setGroupCooldown('');
    setGroupFailureThreshold('');
    setGroupFallbacks('');
    setGroupCtxFallbacks('');
    setGroupPolicyFallbacks('');
    setGroupSatFallbacks('');
    setGroupDropUnsupported(false);
    setGroupDisableCooldowns(false);
  };

  const resetDeployForm = () => {
    setDeployGroupId(null);
    setEditingDeployId(null);
    setDeployGlobalModelId('');
    setDeployCredentialId('');
    setDeployName('');
    setDeployRegion('');
    setDeployPriority('1');
    setDeployWeight('100');
    setDeployTags('');
    setDeployBudgetUSD('');
    setDeployBudgetPeriod('');
    setDeployRpm('');
    setDeployTpm('');
    setDeployItpm('');
    setDeployOtpm('');
    setDeployMaxParallel('');
    setDeployTimeoutMs('');
    setDeployStatus('active');
  };

  const openEditGroup = (g: ModelGroup) => {
    setEditingGroupId(g.id);
    setGroupAlias(g.alias);
    setGroupDesc(g.description || '');
    setRoutingStrategy(g.routing_strategy || 'weighted-shuffle');
    setGroupMaxRetries(g.max_retries != null ? String(g.max_retries) : '');
    setGroupCooldown(g.cooldown_seconds != null ? String(g.cooldown_seconds) : '');
    setGroupFailureThreshold(g.failure_threshold != null ? String(g.failure_threshold) : '');
    setGroupFallbacks((g.fallback_group_ids || []).join(', '));
    setGroupCtxFallbacks((g.context_window_fallbacks || []).map((f) => f.target).join(', '));
    setGroupPolicyFallbacks((g.content_policy_fallbacks || []).map((f) => f.target).join(', '));
    setGroupSatFallbacks((g.saturation_fallbacks || []).map((f) => f.target).join(', '));
    setGroupDropUnsupported(!!g.drop_unsupported_params);
    setGroupDisableCooldowns(!!g.disable_cooldowns);
    setShowCreateGroupModal(true);
  };

  const openEditDeploy = (d: Deployment) => {
    setEditingDeployId(d.id);
    setDeployGroupId(d.model_group_id);
    setDeployGlobalModelId(d.global_model_id);
    setDeployCredentialId(d.credential_id || '');
    setDeployName(d.deployment_name || '');
    setDeployRegion(d.region || '');
    setDeployPriority(String(d.priority));
    setDeployWeight(String(d.weight));
    setDeployTags((d.tags || []).join(', '));
    setDeployBudgetUSD(d.max_budget_micros ? (d.max_budget_micros / 1_000_000).toFixed(2) : '');
    setDeployBudgetPeriod(d.budget_reset_period || '');
    setDeployRpm(d.rpm_capacity ? String(d.rpm_capacity) : '');
    setDeployTpm(d.tpm_capacity ? String(d.tpm_capacity) : '');
    setDeployItpm(d.itpm_capacity ? String(d.itpm_capacity) : '');
    setDeployOtpm(d.otpm_capacity ? String(d.otpm_capacity) : '');
    setDeployMaxParallel(d.max_parallel_requests ? String(d.max_parallel_requests) : '');
    setDeployTimeoutMs(d.timeout_ms ? String(d.timeout_ms) : '');
    setDeployStatus(d.status || 'active');
  };

  const saveGroupMutation = useMutation({
    mutationFn: ({ id, data }: { id?: string | null; data: Partial<ModelGroup> }) =>
      id ? adminApi.updateModelGroup(adminKey, id, data) : adminApi.createModelGroup(adminKey, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['admin', 'model-groups', adminKey] });
      resetGroupForm();
    },
  });

  const deleteGroupMutation = useMutation({
    mutationFn: (id: string) => adminApi.deleteModelGroup(adminKey, id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['admin', 'model-groups', adminKey] });
      queryClient.invalidateQueries({ queryKey: ['admin', 'deployments', adminKey] });
    },
  });

  const createDeploymentMutation = useMutation({
    mutationFn: (data: Partial<Deployment>) => adminApi.createDeployment(adminKey, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['admin', 'deployments', adminKey] });
      resetDeployForm();
    },
  });

  const patchDeploymentMutation = useMutation({
    mutationFn: ({ id, data }: { id: string; data: Partial<Deployment> }) =>
      adminApi.patchDeployment(adminKey, id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['admin', 'deployments', adminKey] });
      resetDeployForm();
    },
  });

  const deleteDeploymentMutation = useMutation({
    mutationFn: (id: string) => adminApi.deleteDeployment(adminKey, id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['admin', 'deployments', adminKey] });
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

  const handleSavePricing = () => {
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

  const parseCsv = (v: string) =>
    v.split(',').map((s) => s.trim()).filter(Boolean);

  const handleCreateGroup = () => {
    if (!groupAlias.trim()) return;

    const fbIds = parseCsv(groupFallbacks);
    const ctxFbs = parseCsv(groupCtxFallbacks).map((target) => ({ target }));
    const polFbs = parseCsv(groupPolicyFallbacks).map((target) => ({ target }));
    const satFbs = parseCsv(groupSatFallbacks).map((target) => ({ target }));

    saveGroupMutation.mutate({
      id: editingGroupId,
      data: {
        org_id: activeOrgId,
        alias: groupAlias.trim(),
        description: groupDesc.trim() || undefined,
        routing_strategy: routingStrategy,
        fallback_group_ids: fbIds.length > 0 ? fbIds : (editingGroupId ? [] : undefined),
        context_window_fallbacks: ctxFbs.length > 0 ? ctxFbs : (editingGroupId ? [] : undefined),
        content_policy_fallbacks: polFbs.length > 0 ? polFbs : (editingGroupId ? [] : undefined),
        saturation_fallbacks: satFbs.length > 0 ? satFbs : (editingGroupId ? [] : undefined),
        drop_unsupported_params: groupDropUnsupported,
        disable_cooldowns: groupDisableCooldowns,
        max_retries: optInt(groupMaxRetries),
        cooldown_seconds: optInt(groupCooldown),
        failure_threshold: optInt(groupFailureThreshold),
      },
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
                className={BTN_ACC}
              >
                <RefreshCw className={`w-3.5 h-3.5 ${syncMutation.isPending ? 'animate-spin' : ''}`} />
                <span>Sync Discovery</span>
              </button>
            </>
          ) : (
            <button
              onClick={() => { resetGroupForm(); setShowCreateGroupModal(true); }}
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
      {saveGroupMutation.isError && !showCreateGroupModal && (
        <ErrorAlert error={saveGroupMutation.error} title="Failed to save model group" />
      )}
      {deleteGroupMutation.isError && (
        <ErrorAlert error={deleteGroupMutation.error} title="Failed to delete model group" />
      )}
      {patchDeploymentMutation.isError && !deployGroupId && (
        <ErrorAlert error={patchDeploymentMutation.error} title="Failed to update deployment" />
      )}
      {deleteDeploymentMutation.isError && (
        <ErrorAlert error={deleteDeploymentMutation.error} title="Failed to delete deployment" />
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
              <option value="groq">Groq</option>
              <option value="openrouter">OpenRouter</option>
              <option value="ollama">Ollama</option>
            </select>
          </div>

          {/* Table */}
          <div className="rounded-xl border border-border-subtle bg-surface-base/90 overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs">
                <thead className={THEAD_CLS}>
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
                    <div className="flex items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-base font-bold text-accent-primary">
                          {g.alias}
                        </span>
                        <Badge size="sm">{g.routing_strategy}</Badge>
                      </div>
                      <div className="flex items-center gap-1.5">
                        <button onClick={() => openEditGroup(g)} className="p-1 text-brand-muted hover:text-brand-title" title="Edit Model Group">
                          <Pencil className="w-3.5 h-3.5" />
                        </button>
                        <button
                          onClick={() => { if (confirm(`Delete model group "${g.alias}"?`)) deleteGroupMutation.mutate(g.id); }}
                          className="p-1 text-brand-muted hover:text-status-danger"
                          title="Delete Model Group"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                        <span className="text-[10px] font-mono text-brand-muted">ID: {g.id}</span>
                      </div>
                    </div>

                    {(g.fallback_group_ids?.length || g.context_window_fallbacks?.length || g.content_policy_fallbacks?.length || g.saturation_fallbacks?.length || g.drop_unsupported_params || g.disable_cooldowns) ? (
                      <div className="flex flex-wrap gap-1.5 text-[10px] font-mono">
                        {g.fallback_group_ids?.length ? (
                          <span className="px-1.5 py-0.5 rounded bg-surface-elevated border border-border-subtle text-brand-muted">
                            fb: {g.fallback_group_ids.join(' → ')}
                          </span>
                        ) : null}
                        {g.context_window_fallbacks?.length ? (
                          <span className="px-1.5 py-0.5 rounded status-info border">
                            ctx-fb: {g.context_window_fallbacks.map((f) => f.target).join(', ')}
                          </span>
                        ) : null}
                        {g.content_policy_fallbacks?.length ? (
                          <span className="px-1.5 py-0.5 rounded status-warning border">
                            policy-fb: {g.content_policy_fallbacks.map((f) => f.target).join(', ')}
                          </span>
                        ) : null}
                        {g.saturation_fallbacks?.length ? (
                          <span className="px-1.5 py-0.5 rounded bg-surface-elevated border border-border-subtle text-brand-body">
                            sat-fb: {g.saturation_fallbacks.map((f) => f.target).join(', ')}
                          </span>
                        ) : null}
                        {g.drop_unsupported_params ? (
                          <span className="px-1.5 py-0.5 rounded bg-accent-soft text-accent-primary border border-accent-primary/30">drop-params</span>
                        ) : null}
                        {g.disable_cooldowns ? (
                          <span className="px-1.5 py-0.5 rounded status-warning border">no-cooldown</span>
                        ) : null}
                      </div>
                    ) : null}

                    <div className="space-y-1.5 pt-2 border-t border-border-subtle/50">
                      <div className="flex items-center justify-between">
                        <div className="text-[10px] uppercase font-semibold text-brand-muted tracking-wider">
                          Configured Deployments ({deps.length})
                        </div>
                        <button
                          onClick={() => { resetDeployForm(); setDeployGroupId(g.id); }}
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
                            className="p-2 rounded bg-surface-elevated/40 border border-border-subtle/60 text-xs font-mono space-y-1"
                          >
                            <div className="flex items-center justify-between gap-2">
                              <span className="text-brand-body truncate">{d.deployment_name ? `${d.deployment_name} (${d.global_model_id})` : d.global_model_id}</span>
                              <div className="flex items-center gap-1.5 text-[10px] text-brand-muted shrink-0">
                                {d.region && <span>{d.region}</span>}
                                <span className="px-1 rounded bg-surface-base border border-border-subtle text-brand-title">P:{d.priority}</span>
                                <span>W:{d.weight}</span>
                                {d.max_parallel_requests ? <span>Par:{d.max_parallel_requests}</span> : null}
                                <span className={d.status === 'active' ? 'text-status-success' : 'text-status-warning'}>{d.status}</span>
                                <button
                                  onClick={() => patchDeploymentMutation.mutate({ id: d.id, data: { status: d.status === 'disabled' ? 'active' : 'disabled' } })}
                                  className="p-0.5 text-brand-muted hover:text-brand-title"
                                  title={d.status === 'disabled' ? 'Activate Deployment' : 'Drain Deployment'}
                                >
                                  <Power className="w-3 h-3" />
                                </button>
                                <button onClick={() => openEditDeploy(d)} className="p-0.5 text-brand-muted hover:text-brand-title" title="Edit Deployment">
                                  <Pencil className="w-3 h-3" />
                                </button>
                                <button
                                  onClick={() => { if (confirm(`Delete deployment "${d.deployment_name || d.global_model_id}"?`)) deleteDeploymentMutation.mutate(d.id); }}
                                  className="p-0.5 text-brand-muted hover:text-status-danger"
                                  title="Delete Deployment"
                                >
                                  <Trash2 className="w-3 h-3" />
                                </button>
                              </div>
                            </div>
                            {(d.tags?.length || (d.max_budget_micros && d.max_budget_micros > 0) || d.itpm_capacity || d.otpm_capacity) ? (
                              <div className="flex flex-wrap items-center gap-1 text-[10px]">
                                {(d.tags || []).map((tag) => (
                                  <span key={tag} className="px-1.5 py-0.2 rounded bg-accent-soft text-accent-primary border border-accent-primary/30">
                                    #{tag}
                                  </span>
                                ))}
                                {d.max_budget_micros && d.max_budget_micros > 0 ? (
                                  <span className="px-1.5 py-0.2 rounded status-success border">
                                    ${(d.max_budget_micros / 1_000_000).toFixed(2)}/{d.budget_reset_period || 'never'}
                                  </span>
                                ) : null}
                                {d.itpm_capacity ? <span className="px-1 rounded bg-surface-base border border-border-subtle">ITPM:{d.itpm_capacity}</span> : null}
                                {d.otpm_capacity ? <span className="px-1 rounded bg-surface-base border border-border-subtle">OTPM:{d.otpm_capacity}</span> : null}
                              </div>
                            ) : null}
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
      <FormModal
        open={!!selectedModel}
        onClose={() => setSelectedModel(null)}
        title={`Update Pricing: ${selectedModel?.display_name || selectedModel?.model_name}`}
        description="Updates integer micro-dollar pricing rates ($1.00 = 1,000,000 µ$) and appends an immutable provenance audit record."
        onSubmit={handleSavePricing}
        pending={pricingMutation.isPending}
        submitLabel={pricingMutation.isPending ? 'Updating...' : 'Save Pricing'}
      >
        {pricingMutation.isError && <ErrorAlert error={pricingMutation.error} title="Failed to update pricing" />}
        <div className="grid grid-cols-2 gap-3">
          <Field label="Input USD / 1M"><input type="number" step="0.0001" required value={inputCostUSD} onChange={(e) => setInputCostUSD(e.target.value)} className={MONO_INPUT_CLS} /></Field>
          <Field label="Output USD / 1M"><input type="number" step="0.0001" required value={outputCostUSD} onChange={(e) => setOutputCostUSD(e.target.value)} className={MONO_INPUT_CLS} /></Field>
        </div>
        <Field label="Cached Input USD / 1M"><input type="number" step="0.0001" value={cachedInputUSD} onChange={(e) => setCachedInputUSD(e.target.value)} className={MONO_INPUT_CLS} /></Field>
      </FormModal>

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

      {/* Create / Edit Model Group Modal */}
      <FormModal
        open={showCreateGroupModal}
        onClose={resetGroupForm}
        title={editingGroupId ? 'Edit Model Group Alias' : 'Create Model Group Alias'}
        onSubmit={handleCreateGroup}
        pending={saveGroupMutation.isPending || !groupAlias.trim()}
        submitLabel={saveGroupMutation.isPending ? 'Saving...' : (editingGroupId ? 'Save Changes' : 'Create Model Group')}
      >
        {saveGroupMutation.isError && <ErrorAlert error={saveGroupMutation.error} title="Failed to save model group" />}
        <Field label="Alias Name *"><input type="text" required value={groupAlias} onChange={(e) => setGroupAlias(e.target.value)} placeholder="fast, reasoning, coding" className={MONO_INPUT_CLS} /></Field>
        <Field label="Description (optional)"><input type="text" value={groupDesc} onChange={(e) => setGroupDesc(e.target.value)} placeholder="Low-latency primary alias" className={INPUT_CLS} /></Field>
        <Field label="Routing Strategy">
          <select value={routingStrategy} onChange={(e) => setRoutingStrategy(e.target.value)} className={INPUT_CLS}>
            <option value="weighted-shuffle">weighted-shuffle (Default probabilistic)</option>
            <option value="round-robin">round-robin (Cyclic distribution)</option>
            <option value="least-busy">least-busy (Lowest in-flight concurrency)</option>
            <option value="latency-based">latency-based (EWMA latency tracker)</option>
            <option value="fastest-response">fastest-response (Hedged latency racing)</option>
            <option value="usage-based-headroom">usage-based-headroom (TPM limit protection)</option>
            <option value="lowest-cost">lowest-cost (Cheapest micro-dollar deployment)</option>
          </select>
        </Field>
        <div className="grid grid-cols-3 gap-2">
          <Field label="Max Retries"><input type="number" min={0} value={groupMaxRetries} onChange={(e) => setGroupMaxRetries(e.target.value)} placeholder="2" className={MONO_INPUT_CLS} /></Field>
          <Field label="Cooldown (s)"><input type="number" min={0} value={groupCooldown} onChange={(e) => setGroupCooldown(e.target.value)} placeholder="30" className={MONO_INPUT_CLS} /></Field>
          <Field label="Failure Threshold"><input type="number" min={0} value={groupFailureThreshold} onChange={(e) => setGroupFailureThreshold(e.target.value)} placeholder="3" className={MONO_INPUT_CLS} /></Field>
        </div>
        <Field label="Fallback Group IDs (comma-separated)"><input type="text" value={groupFallbacks} onChange={(e) => setGroupFallbacks(e.target.value)} placeholder="reasoning, backup-fast" className={MONO_INPUT_CLS} /></Field>
        <div className="grid grid-cols-3 gap-2">
          <Field label="Context Window Fallbacks"><input type="text" value={groupCtxFallbacks} onChange={(e) => setGroupCtxFallbacks(e.target.value)} placeholder="long-context" className={MONO_INPUT_CLS} /></Field>
          <Field label="Content Policy Fallbacks"><input type="text" value={groupPolicyFallbacks} onChange={(e) => setGroupPolicyFallbacks(e.target.value)} placeholder="safe-fallback" className={MONO_INPUT_CLS} /></Field>
          <Field label="Saturation Fallbacks"><input type="text" value={groupSatFallbacks} onChange={(e) => setGroupSatFallbacks(e.target.value)} placeholder="overflow-pool" className={MONO_INPUT_CLS} /></Field>
        </div>
        <div className="flex flex-wrap gap-4 pt-1 text-xs text-brand-body">
          <label className="flex items-center gap-1.5"><input type="checkbox" checked={groupDropUnsupported} onChange={(e) => setGroupDropUnsupported(e.target.checked)} />Drop Unsupported Params</label>
          <label className="flex items-center gap-1.5"><input type="checkbox" checked={groupDisableCooldowns} onChange={(e) => setGroupDisableCooldowns(e.target.checked)} />Disable Cooldowns</label>
        </div>
      </FormModal>

      {/* Add / Edit Deployment Modal */}
      <FormModal
        open={!!deployGroupId}
        onClose={resetDeployForm}
        title={editingDeployId ? 'Edit Deployment' : 'Add Deployment to Model Group'}
        description={editingDeployId ? 'Update deployment routing capacities, priority, weight, tags, or operational status.' : 'Attach an upstream global model and provider credential to this routing group.'}
        onSubmit={() => {
          if (!deployGroupId) return;
          const parsedTags = parseCsv(deployTags);
          const parsedBudget = parseFloat(deployBudgetUSD);
          if (editingDeployId) {
            const patch: Partial<Deployment> = {
              deployment_name: deployName.trim(),
              region: deployRegion.trim(),
              priority: Math.max(0, parseInt(deployPriority, 10) || 0),
              weight: Math.max(0, parseInt(deployWeight, 10) || 100),
              rpm_capacity: optInt(deployRpm) ?? 0,
              tpm_capacity: optInt(deployTpm) ?? 0,
              itpm_capacity: optInt(deployItpm) ?? 0,
              otpm_capacity: optInt(deployOtpm) ?? 0,
              max_parallel_requests: optInt(deployMaxParallel) ?? 0,
              timeout_ms: optInt(deployTimeoutMs) ?? 0,
              tags: parsedTags,
              max_budget_micros: !isNaN(parsedBudget) && parsedBudget > 0 ? Math.round(parsedBudget * 1_000_000) : 0,
              status: deployStatus || 'active',
            };
            if (deployBudgetPeriod) patch.budget_reset_period = deployBudgetPeriod;
            patchDeploymentMutation.mutate({ id: editingDeployId, data: patch });
            return;
          }
          if (!deployGlobalModelId.trim()) return;
          const payload: Partial<Deployment> = {
            model_group_id: deployGroupId,
            global_model_id: deployGlobalModelId.trim(),
            priority: Math.max(0, parseInt(deployPriority, 10) || 0),
            weight: Math.max(0, parseInt(deployWeight, 10) || 100),
            rpm_capacity: optInt(deployRpm),
            tpm_capacity: optInt(deployTpm),
            itpm_capacity: optInt(deployItpm),
            otpm_capacity: optInt(deployOtpm),
            max_parallel_requests: optInt(deployMaxParallel),
            timeout_ms: optInt(deployTimeoutMs),
          };
          if (deployCredentialId.trim()) payload.credential_id = deployCredentialId.trim();
          if (deployName.trim()) payload.deployment_name = deployName.trim();
          if (deployRegion.trim()) payload.region = deployRegion.trim();
          if (parsedTags.length > 0) payload.tags = parsedTags;
          if (deployBudgetUSD.trim() && !isNaN(parsedBudget) && parsedBudget > 0) {
            payload.max_budget_micros = Math.round(parsedBudget * 1_000_000);
          }
          if (deployBudgetPeriod) payload.budget_reset_period = deployBudgetPeriod;
          createDeploymentMutation.mutate(payload);
        }}
        pending={createDeploymentMutation.isPending || patchDeploymentMutation.isPending || (!editingDeployId && !deployGlobalModelId.trim())}
        submitLabel={(createDeploymentMutation.isPending || patchDeploymentMutation.isPending) ? 'Saving...' : (editingDeployId ? 'Save Deployment' : 'Add Deployment')}
      >
        {(createDeploymentMutation.isError || patchDeploymentMutation.isError) && (
          <ErrorAlert error={createDeploymentMutation.error || patchDeploymentMutation.error} title="Failed to save deployment" />
        )}
        {!editingDeployId && (
          <>
            <Field label="Global Model ID *">
              <input type="text" required list="catalogue-models-list" value={deployGlobalModelId} onChange={(e) => setDeployGlobalModelId(e.target.value)} placeholder="openai/gpt-4.1" className={MONO_INPUT_CLS} />
              <datalist id="catalogue-models-list">
                {suggestionModels.slice(0, 100).map((m) => <option key={m.id} value={m.id} />)}
              </datalist>
              {suggestionModels.length > 100 && (
                <p className="text-[10px] font-mono text-brand-muted mt-1">
                  Showing 100 of {suggestionModels.length} matching models — type to narrow suggestions.
                </p>
              )}
            </Field>
            <Field label="Provider Credential (optional)">
              <select value={deployCredentialId} onChange={(e) => setDeployCredentialId(e.target.value)} className={INPUT_CLS}>
                <option value="">Auto-resolve org credential</option>
                {(credsData?.data || []).map((c) => <option key={c.id} value={c.id}>{c.name} ({c.provider})</option>)}
              </select>
              <p className="text-[10px] font-mono text-brand-muted mt-1">
                Leave as Auto-resolve only when the organization has exactly one active credential for this model&apos;s provider.
              </p>
            </Field>
          </>
        )}
        <div className="grid grid-cols-2 gap-3">
          <Field label="Deployment Name"><input type="text" value={deployName} onChange={(e) => setDeployName(e.target.value)} placeholder="primary-us-east" className={MONO_INPUT_CLS} /></Field>
          <Field label="Region"><input type="text" value={deployRegion} onChange={(e) => setDeployRegion(e.target.value)} placeholder="us-east-1" className={MONO_INPUT_CLS} /></Field>
        </div>
        <div className={`grid ${editingDeployId ? 'grid-cols-3' : 'grid-cols-2'} gap-3`}>
          <Field label="Priority Tier"><input type="number" min={0} value={deployPriority} onChange={(e) => setDeployPriority(e.target.value)} className={MONO_INPUT_CLS} /></Field>
          <Field label="Weight"><input type="number" min={0} value={deployWeight} onChange={(e) => setDeployWeight(e.target.value)} className={MONO_INPUT_CLS} /></Field>
          {editingDeployId && (
            <Field label="Status">
              <select value={deployStatus} onChange={(e) => setDeployStatus(e.target.value)} className={INPUT_CLS}>
                <option value="active">active</option>
                <option value="cooldown">cooldown</option>
                <option value="disabled">disabled (drained)</option>
              </select>
            </Field>
          )}
        </div>
        <div className="grid grid-cols-3 gap-2">
          <Field label="Tags (comma-sep)"><input type="text" value={deployTags} onChange={(e) => setDeployTags(e.target.value)} placeholder="tier:fast, eu" className={MONO_INPUT_CLS} /></Field>
          <Field label="Max Budget (USD)"><input type="number" min={0} step="0.01" value={deployBudgetUSD} onChange={(e) => setDeployBudgetUSD(e.target.value)} placeholder="unlimited" className={MONO_INPUT_CLS} /></Field>
          <Field label="Reset Period">
            <select value={deployBudgetPeriod} onChange={(e) => setDeployBudgetPeriod(e.target.value)} className={INPUT_CLS}>
              <option value="">None</option>
              <option value="daily">daily</option>
              <option value="monthly">monthly</option>
              <option value="never">never</option>
            </select>
          </Field>
        </div>
        <div className="grid grid-cols-3 gap-2">
          <Field label="RPM Cap"><input type="number" min={0} value={deployRpm} onChange={(e) => setDeployRpm(e.target.value)} placeholder="optional" className={MONO_INPUT_CLS} /></Field>
          <Field label="TPM Cap"><input type="number" min={0} value={deployTpm} onChange={(e) => setDeployTpm(e.target.value)} placeholder="optional" className={MONO_INPUT_CLS} /></Field>
          <Field label="Max Parallel"><input type="number" min={0} value={deployMaxParallel} onChange={(e) => setDeployMaxParallel(e.target.value)} placeholder="optional" className={MONO_INPUT_CLS} /></Field>
        </div>
        <div className="grid grid-cols-3 gap-2">
          <Field label="ITPM Cap"><input type="number" min={0} value={deployItpm} onChange={(e) => setDeployItpm(e.target.value)} placeholder="optional" className={MONO_INPUT_CLS} /></Field>
          <Field label="OTPM Cap"><input type="number" min={0} value={deployOtpm} onChange={(e) => setDeployOtpm(e.target.value)} placeholder="optional" className={MONO_INPUT_CLS} /></Field>
          <Field label="Timeout (ms)"><input type="number" min={0} value={deployTimeoutMs} onChange={(e) => setDeployTimeoutMs(e.target.value)} placeholder="30000" className={MONO_INPUT_CLS} /></Field>
        </div>
      </FormModal>
    </div>
  );
};
