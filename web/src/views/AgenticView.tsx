import React, { useState, useMemo, useEffect } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { adminApi } from '../api/admin';
import { useAuth } from '../context/AuthContext';
import { Badge } from '../components/common/Badge';
import { Modal, FormModal, Field, INPUT_CLS, MONO_INPUT_CLS, BTN_PRIMARY, BTN_ELEV, CARD_CLS, EMPTY_CLS } from '../components/common/Modal';
import { CodeBlock } from '../components/common/CodeBlock';
import { ErrorAlert } from '../components/common/ErrorAlert';
import type { MCPTool, MCPServer, MCPSpecInfo, MCPRuntimeSpecState, A2AAgent } from '../types';
import {
  Bot,
  Layers,
  Settings,
  Zap,
  RefreshCw,
  Activity,
  Search,
  Plus,
} from 'lucide-react';

const tr = (s: string) => s.trim() || undefined;
const MCP_TRANSPORTS = ['streamable_http', 'http_sse_2024', 'stdio', 'openapi'] as const;
const SRV_BTN_CLS = 'flex items-center gap-1.5 px-2.5 py-1 bg-surface-elevated hover:bg-surface-hover border border-border-subtle text-brand-body hover:text-brand-title rounded text-xs font-mono transition';
const INIT_SRV_FORM = {
  name: '', slug: '', endpoint: '', protocol: '2026-07-28', transport: 'streamable_http',
  authType: 'none', authSecret: '', staticHeaders: '', oauthEndpoint: '', oauthClientId: '', oauthScopes: '', pinnedHash: '', active: true,
};
const INIT_AGENT_FORM = {
  name: '',
  slug: '',
  endpoint: '',
  cardUrl: '',
  binding: 'HTTP+JSON',
  publicCard: false,
  visibility: 'key_strict',
  authType: 'none',
  authSecret: '',
  maxIter: '50',
  maxBudget: '',
  active: true,
};

const TextField: React.FC<{
  label: string; value: string; onChange: (v: string) => void; type?: string; req?: boolean; cls?: string;
}> = ({ label, value, onChange, type = 'text', req, cls = MONO_INPUT_CLS }) => (
  <Field label={label}>
    <input type={type} required={req} value={value} onChange={(e) => onChange(e.target.value)} className={cls} />
  </Field>
);

const SpecTransportFields: React.FC<{
  specs: MCPSpecInfo[];
  protocol: string;
  onProtocolChange: (v: string) => void;
  transport: string;
  onTransportChange: (v: string) => void;
}> = ({ specs, protocol, onProtocolChange, transport, onTransportChange }) => (
  <>
    <Field label="Protocol Version">
      <select
        value={protocol}
        onChange={(e) => {
          const ver = e.target.value;
          onProtocolChange(ver);
          const meta = specs.find((s) => s.version === ver);
          if (meta?.default_transport && transport !== 'stdio' && transport !== 'openapi') {
            onTransportChange(meta.default_transport);
          }
        }}
        className={INPUT_CLS}
      >
        {(specs.length ? specs : [{ version: '2026-07-28', label: '2026-07-28' }]).map((s) => (
          <option key={s.version} value={s.version}>{s.label}</option>
        ))}
      </select>
    </Field>
    <Field label="Transport">
      <select value={transport} onChange={(e) => onTransportChange(e.target.value)} className={INPUT_CLS}>
        {MCP_TRANSPORTS.map((t) => <option key={t} value={t}>{t}</option>)}
      </select>
    </Field>
  </>
);

export const AgenticView: React.FC = () => {
  const { adminKey, isUnlocked, activeOrgId } = useAuth();
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<'mcp' | 'a2a'>('mcp');
  const [selectedTool, setSelectedTool] = useState<MCPTool | null>(null);
  const [searchFilter, setSearchFilter] = useState('');

  // Modal toggles
  const [showServerModal, setShowServerModal] = useState(false);
  const [editingServer, setEditingServer] = useState<MCPServer | null>(null);
  const [showToolsetModal, setShowToolsetModal] = useState(false);
  const [showCredModal, setShowCredModal] = useState(false);
  const [showAgentModal, setShowAgentModal] = useState(false);
  const [showPushModal, setShowPushModal] = useState(false);

  // Active Gateway MCP Specification Selector state
  const [gatewaySpecVersion, setGatewaySpecVersion] = useState('2026-07-28');
  const [gatewayStrictSchema, setGatewayStrictSchema] = useState(false);

  // MCP User BYOK & A2A Push forms
  const [credForm, setCredForm] = useState({ serverId: '', userId: '', token: '' });
  const [pushForm, setPushForm] = useState({ taskId: '', targetUrl: '', authToken: '' });

  const [srvForm, setSrvForm] = useState(INIT_SRV_FORM);
  const patchSrvForm = (p: Partial<typeof INIT_SRV_FORM>) => setSrvForm((prev) => ({ ...prev, ...p }));
  const [srvFormError, setSrvFormError] = useState<string | null>(null);

  const [tsForm, setTsForm] = useState<{ name: string; slug: string; selected: string[]; manual: string }>({
    name: '', slug: '', selected: [], manual: '',
  });

  // A2A Agent form state (shared across create and edit modes)
  const [editingAgent, setEditingAgent] = useState<A2AAgent | null>(null);
  const [agentForm, setAgentForm] = useState(INIT_AGENT_FORM);
  const patchAgentForm = (patch: Partial<typeof INIT_AGENT_FORM>) =>
    setAgentForm((prev) => ({ ...prev, ...patch }));

  // Fetch Active Gateway MCP API Specification & Official Releases
  const {
    data: mcpSpecData,
    isLoading: isSpecLoading,
  } = useQuery<MCPRuntimeSpecState>({
    queryKey: ['admin', 'mcp-spec', adminKey],
    queryFn: () => adminApi.getMCPSpec(adminKey),
    enabled: isUnlocked,
  });

  useEffect(() => {
    if (mcpSpecData?.active_protocol_version) {
      setGatewaySpecVersion(mcpSpecData.active_protocol_version);
      setGatewayStrictSchema(Boolean(mcpSpecData.strict_schema_validation));
    }
  }, [mcpSpecData?.active_protocol_version, mcpSpecData?.strict_schema_validation]);

  const updateSpecMutation = useMutation({
    mutationFn: (payload: { protocol_version: string; strict_schema_validation?: boolean }) =>
      adminApi.updateMCPSpec(adminKey, payload),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['admin', 'mcp-spec'] });
      queryClient.invalidateQueries({ queryKey: ['admin', 'config'] });
    },
  });

  const mcpQ = useQuery({
    queryKey: ['admin', 'mcp-servers', adminKey, activeOrgId],
    queryFn: () => adminApi.listMCPServers(adminKey, activeOrgId),
    enabled: isUnlocked,
  });
  const tsQ = useQuery({
    queryKey: ['admin', 'mcp-toolsets', adminKey, activeOrgId],
    queryFn: () => adminApi.listMCPToolsets(adminKey, activeOrgId),
    enabled: isUnlocked && activeTab === 'mcp',
  });
  const toolsQ = useQuery({
    queryKey: ['admin', 'mcp-tools', adminKey, activeOrgId],
    queryFn: () => adminApi.listMCPTools(adminKey, activeOrgId),
    enabled: isUnlocked && activeTab === 'mcp',
  });
  const a2aQ = useQuery({
    queryKey: ['admin', 'a2a-agents', adminKey, activeOrgId],
    queryFn: () => adminApi.listA2AAgents(adminKey, activeOrgId),
    enabled: isUnlocked,
  });
  const { data: mcpServersData, isLoading: isMCPLoading, refetch: refetchMCP } = mcpQ;
  const { data: mcpToolsetsData, refetch: refetchToolsets } = tsQ;
  const { data: mcpToolsData, isLoading: isToolsLoading, refetch: refetchTools } = toolsQ;
  const { data: a2aAgentsData, isLoading: isA2ALoading, refetch: refetchA2A } = a2aQ;

  const saveServerMutation = useMutation({
    mutationFn: (arg: { id?: string; payload: Record<string, any> }) =>
      arg.id
        ? adminApi.updateMCPServer(adminKey, arg.id, arg.payload)
        : adminApi.createMCPServer(adminKey, arg.payload as Parameters<typeof adminApi.createMCPServer>[1]),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['admin', 'mcp-servers'] });
      setShowServerModal(false);
      setEditingServer(null);
      setSrvForm(INIT_SRV_FORM);
      setSrvFormError(null);
    },
  });

  // Create MCP Toolset Mutation
  const createToolsetMutation = useMutation({
    mutationFn: (payload: Parameters<typeof adminApi.createMCPToolset>[1]) =>
      adminApi.createMCPToolset(adminKey, payload),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['admin', 'mcp-toolsets'] });
      setShowToolsetModal(false);
      setTsForm({ name: '', slug: '', selected: [], manual: '' });
    },
  });

  // Save (Create / Update) A2A Agent Mutation
  const saveAgentMutation = useMutation({
    mutationFn: (arg: { id?: string; data: Record<string, any> }) =>
      arg.id
        ? adminApi.updateA2AAgent(adminKey, arg.id, arg.data)
        : adminApi.createA2AAgent(adminKey, arg.data as Parameters<typeof adminApi.createA2AAgent>[1]),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['admin', 'a2a-agents'] });
      setShowAgentModal(false);
      setEditingAgent(null);
      setAgentForm(INIT_AGENT_FORM);
    },
  });

  const a2aActionMutation = useMutation({
    mutationFn: (op: { kind: 'del' | 'sync' | 'replay' | 'kill'; id: string; killed?: boolean }): Promise<unknown> =>
      op.kind === 'del'
        ? adminApi.deleteA2AAgent(adminKey, op.id)
        : op.kind === 'sync'
        ? adminApi.syncA2AAgentCard(adminKey, op.id)
        : op.kind === 'kill'
        ? adminApi.setA2AKillSwitch(adminKey, op.id, Boolean(op.killed))
        : adminApi.replayA2AOutboxEvent(adminKey, op.id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['admin', 'a2a-agents'] });
      queryClient.invalidateQueries({ queryKey: ['admin', 'a2a-outbox'] });
    },
  });

  const { data: a2aOutboxData } = useQuery({
    queryKey: ['admin', 'a2a-outbox', activeOrgId, adminKey],
    queryFn: () => adminApi.listA2AOutboxEvents(adminKey, { org_id: activeOrgId || undefined, limit: 50 }),
    enabled: isUnlocked && activeTab === 'a2a',
  });

  const openEditAgentModal = (agent: A2AAgent) => {
    setEditingAgent(agent);
    setAgentForm({
      ...INIT_AGENT_FORM,
      name: agent.name,
      slug: agent.slug,
      endpoint: agent.endpoint_url,
      cardUrl: agent.agent_card_url || '',
      binding: agent.protocol_binding || 'HTTP+JSON',
      visibility: agent.task_visibility_mode || 'key_strict',
      authType: agent.auth_type || 'none',
      publicCard: Boolean(agent.is_public_card),
      active: Boolean(agent.is_active),
    });
    setShowAgentModal(true);
  };

  // MCP Server Sync Mutation
  const syncServerMutation = useMutation({
    mutationFn: (serverId: string) => adminApi.syncMCPServer(adminKey, serverId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['admin', 'mcp-servers'] });
      queryClient.invalidateQueries({ queryKey: ['admin', 'mcp-tools'] });
    },
  });

  // Set MCP User BYOK Credential Mutation
  const setUserCredMutation = useMutation({
    mutationFn: (payload: Parameters<typeof adminApi.setMCPUserCredential>[1]) =>
      adminApi.setMCPUserCredential(adminKey, payload),
    onSuccess: () => {
      setShowCredModal(false);
      setCredForm({ serverId: '', userId: '', token: '' });
    },
  });

  // Set A2A Push Config Mutation
  const setPushConfigMutation = useMutation({
    mutationFn: (payload: Parameters<typeof adminApi.setA2APushConfig>[1]) =>
      adminApi.setA2APushConfig(adminKey, payload),
    onSuccess: () => {
      setShowPushModal(false);
      setPushForm({ taskId: '', targetUrl: '', authToken: '' });
    },
  });

  const mcpServers = mcpServersData?.servers || mcpServersData?.data || [];
  const mcpToolsets = mcpToolsetsData?.toolsets || mcpToolsetsData?.data || [];
  const mcpTools = mcpToolsData?.tools || [];
  const a2aAgents = a2aAgentsData?.agents || a2aAgentsData?.data || [];
  const availableSpecs: MCPSpecInfo[] = mcpSpecData?.available_specs || [];
  const selectedSpecMeta = availableSpecs.find((s) => s.version === gatewaySpecVersion);

  const toolCountByServer = useMemo(() => {
    const counts = new Map<string, number>();
    for (const t of mcpTools) {
      counts.set(t.server_id, (counts.get(t.server_id) || 0) + 1);
    }
    return counts;
  }, [mcpTools]);

  const toggleToolSelection = (toolId: string) =>
    setTsForm((p) => ({
      ...p,
      selected: p.selected.includes(toolId) ? p.selected.filter((id) => id !== toolId) : [...p.selected, toolId],
    }));

  const matchesSearch = (...vals: Array<string | undefined>) => {
    const term = searchFilter.trim().toLowerCase();
    return !term || vals.some((v) => v?.toLowerCase().includes(term));
  };
  const filteredTools = mcpTools.filter((t) => matchesSearch(t.name, t.description));
  const filteredAgents = a2aAgents.filter((a) => matchesSearch(a.name, a.slug, a.endpoint_url));

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4">
        <div>
          <h2 className="text-xl font-semibold text-brand-title flex items-center gap-2">
            <Bot className="w-5 h-5 text-accent-primary" />
            Agentic Ecosystem (MCP & A2A)
          </h2>
          <p className="text-xs text-brand-muted mt-1">
            MCP runtimes & A2A agent mesh controls.
          </p>
        </div>

        <div className="flex items-center gap-2">
          {(activeTab === 'mcp'
            ? [
                ['Set User BYOK', () => setShowCredModal(true), BTN_ELEV],
                ['Create Toolset', () => setShowToolsetModal(true), BTN_ELEV],
                ['Register MCP Server', () => setShowServerModal(true), BTN_PRIMARY],
              ]
            : [
                ['Push Webhook', () => setShowPushModal(true), BTN_ELEV],
                ['Register A2A Agent', () => setShowAgentModal(true), BTN_PRIMARY],
              ]
          ).map(([lbl, fn, cls]) => (
            <button key={lbl as string} onClick={fn as () => void} className={cls as string}>
              <span className="flex items-center gap-1.5">
                <Plus className="w-3.5 h-3.5" />
                {lbl as string}
              </span>
            </button>
          ))}
          <button
            onClick={() => {
              if (activeTab === 'mcp') {
                refetchMCP();
                refetchToolsets();
                refetchTools();
              } else {
                refetchA2A();
              }
            }}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-surface-base border border-border-subtle hover:border-border-strong text-brand-body hover:text-brand-title rounded text-xs transition"
          >
            <RefreshCw className="w-3.5 h-3.5" />
            Refresh
          </button>
        </div>
      </div>

      {[
        [mcpQ.isError, mcpQ.error, 'MCP servers', mcpQ.refetch],
        [tsQ.isError, tsQ.error, 'MCP toolsets', tsQ.refetch],
        [toolsQ.isError, toolsQ.error, 'MCP tools', toolsQ.refetch],
        [a2aQ.isError, a2aQ.error, 'A2A agents', a2aQ.refetch],
        [syncServerMutation.isError, syncServerMutation.error, 'MCP sync', undefined],
        [a2aActionMutation.isError, a2aActionMutation.error, 'A2A action', undefined],
      ].map(([isErr, err, label, retry]) =>
        isErr ? <ErrorAlert key={String(label)} error={err} title={`Failed: ${label}`} onRetry={retry as any} /> : null
      )}

      {/* Tabs */}
      <div className="border-b border-border-subtle">
        <div className="flex items-center justify-between">
          <div className="flex gap-4">
            {([
              ['mcp', Layers, `Model Context Protocol (${mcpServers.length} Servers, ${mcpTools.length} Tools)`],
              ['a2a', Activity, `A2A Mesh Protocol (${a2aAgents.length} Agents)`],
            ] as const).map(([key, Icon, label]) => (
              <button
                key={key}
                onClick={() => setActiveTab(key)}
                className={`pb-3 text-xs font-medium border-b-2 flex items-center gap-2 transition ${
                  activeTab === key
                    ? 'border-accent-primary text-accent-primary font-semibold'
                    : 'border-transparent text-brand-muted hover:text-brand-title'
                }`}
              >
                <Icon className="w-4 h-4" />
                {label}
              </button>
            ))}
          </div>

          <div className="flex items-center gap-2 pb-2">
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-brand-muted absolute left-2.5 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={searchFilter}
                onChange={(e) => setSearchFilter(e.target.value)}
                placeholder={activeTab === 'mcp' ? 'Search tools...' : 'Search agents...'}
                className="pl-8 pr-3 py-1 text-xs bg-surface-input border border-border-subtle rounded text-brand-body placeholder-brand-muted focus:outline-none focus:border-accent-primary font-mono w-56"
              />
            </div>
          </div>
        </div>
      </div>

      {/* Tab 1: MCP Server Registry & Tools */}
      {activeTab === 'mcp' && (
        <div className="space-y-6">
          {/* Active Gateway MCP API Specification Selector */}
          <div className={`${CARD_CLS} p-4 space-y-3`}>
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <div className="flex items-center gap-2">
                  <Zap className="w-4 h-4 text-accent-primary" />
                  <h3 className="text-xs font-mono uppercase tracking-wider text-brand-title font-semibold">
                    Gateway MCP Specification
                  </h3>
                  <Badge variant="info">
                    Active: {mcpSpecData?.active_protocol_version || gatewaySpecVersion}
                  </Badge>
                  {selectedSpecMeta && (
                    <span className="text-xs font-mono text-brand-muted">
                      {selectedSpecMeta.schema_def_count} defs · {selectedSpecMeta.transport_mode} ·{' '}
                      {[
                        selectedSpecMeta.supports_sessions ? 'Sessions' : 'Stateless',
                        selectedSpecMeta.supports_batching && 'Batch',
                        selectedSpecMeta.supports_server_discover ? 'discover' : 'init',
                        selectedSpecMeta.supports_tasks && 'Tasks',
                        selectedSpecMeta.requires_protocol_version_header && 'ProtoHdr',
                      ]
                        .filter(Boolean)
                        .join(' · ')}
                    </span>
                  )}
                </div>
                <p className="text-xs text-brand-muted mt-1">
                  {selectedSpecMeta?.summary || 'Select active MCP schema release.'}
                </p>
              </div>

              <div className="flex items-center gap-3">
                <label className="flex items-center gap-1.5 text-xs font-mono text-brand-body cursor-pointer">
                  <input
                    type="checkbox"
                    checked={gatewayStrictSchema}
                    onChange={(e) => setGatewayStrictSchema(e.target.checked)}
                  />
                  Strict schema.yaml
                </label>
                <button
                  type="button"
                  disabled={updateSpecMutation.isPending || isSpecLoading}
                  onClick={() =>
                    updateSpecMutation.mutate({
                      protocol_version: gatewaySpecVersion,
                      strict_schema_validation: gatewayStrictSchema,
                    })
                  }
                  className={BTN_PRIMARY}
                >
                  {updateSpecMutation.isPending ? 'Applying...' : 'Apply Spec'}
                </button>
              </div>
            </div>

            {updateSpecMutation.isError && (
              <ErrorAlert error={updateSpecMutation.error} title="Failed to switch MCP spec" />
            )}

            <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-5 gap-2">
              {availableSpecs.map((specItem) => {
                const isSelected = specItem.version === gatewaySpecVersion;
                const isLive = specItem.version === mcpSpecData?.active_protocol_version;
                return (
                  <button
                    key={specItem.version}
                    type="button"
                    onClick={() => setGatewaySpecVersion(specItem.version)}
                    className={`text-left p-2.5 rounded-lg border font-mono ${
                      isSelected
                        ? 'border-accent-primary bg-accent-primary/10 text-brand-title'
                        : 'border-border-subtle bg-surface-elevated/40 text-brand-muted hover:text-brand-body'
                    }`}
                  >
                    <div className="flex items-center justify-between gap-1">
                      <span className="text-xs font-bold">{specItem.version}</span>
                      {isLive && <Badge variant="success">Live</Badge>}
                    </div>
                    <div className="text-[10px] mt-1 truncate" title={specItem.label}>
                      {specItem.transport_mode}
                    </div>
                  </button>
                );
              })}
            </div>
          </div>

          {/* MCP Servers Grid */}
          <div>
            <h3 className="text-xs font-mono uppercase tracking-wider text-brand-muted mb-3 flex items-center gap-2">
              <Layers className="w-4 h-4 text-accent-primary" />
              Registered MCP Servers ({mcpServers.length})
            </h3>

            {isMCPLoading ? (
              <div className={EMPTY_CLS}>
                Loading MCP servers...
              </div>
            ) : mcpServers.length === 0 ? (
              <div className={EMPTY_CLS}>
                No MCP servers registered.
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {mcpServers.map((srv) => (
                  <div
                    key={srv.id}
                    className={`${CARD_CLS} p-4 flex flex-col justify-between`}
                  >
                    <div>
                      <div className="flex items-start justify-between gap-2 mb-2">
                        <div>
                          <h4 className="text-sm font-semibold text-brand-title">{srv.name}</h4>
                          <span className="text-[11px] font-mono text-brand-muted">{srv.slug}</span>
                        </div>
                        <Badge variant={srv.is_active ? 'success' : 'neutral'}>
                          {srv.is_active ? 'Active' : 'Inactive'}
                        </Badge>
                      </div>

                      <div className="space-y-1.5 text-xs font-mono my-3">
                        {[
                          ['Spec Release:', srv.protocol_version || '2026-07-28', 'text-accent-primary font-semibold'],
                          ['Transport:', srv.transport_type, 'text-brand-body uppercase'],
                          srv.endpoint_url ? ['Endpoint:', srv.endpoint_url, 'text-accent-primary truncate max-w-[160px]'] : null,
                          ['Tools Registered:', toolCountByServer.get(srv.id) ?? 0, 'text-status-success font-bold'],
                        ].map((r) => r && (
                          <div key={String(r[0])} className="text-brand-muted flex justify-between">
                            <span>{r[0]}</span>
                            <span className={String(r[2])}>{r[1]}</span>
                          </div>
                        ))}
                      </div>
                    </div>

                    <div className="pt-3 border-t border-border-subtle flex flex-wrap justify-end gap-2">
                      {[
                        ['Edit Spec', () => { setEditingServer(srv); patchSrvForm({ protocol: srv.protocol_version || '2026-07-28', transport: srv.transport_type || 'streamable_http', active: srv.is_active }); setShowServerModal(true); }],
                        ['Set BYOK', () => { setCredForm((p) => ({ ...p, serverId: srv.id })); setShowCredModal(true); }],
                        ['Sync Schema', () => syncServerMutation.mutate(srv.id)],
                      ].map(([lbl, fn]) => (
                        <button key={lbl as string} onClick={fn as () => void} className={SRV_BTN_CLS}>{lbl as string}</button>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* Curated MCP Toolsets */}
          <div>
            <h3 className="text-xs font-mono uppercase tracking-wider text-brand-muted mb-3 flex items-center gap-2">
              <Layers className="w-4 h-4 text-accent-primary" />
              Curated MCP Toolsets ({mcpToolsets.length})
            </h3>
            {mcpToolsets.length === 0 ? (
              <div className={EMPTY_CLS}>No MCP toolsets.</div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {mcpToolsets.map((ts) => (
                  <div
                    key={ts.id}
                    className={`${CARD_CLS} p-4 flex items-center justify-between`}
                  >
                    <div>
                      <h4 className="text-sm font-semibold text-brand-title">{ts.name}</h4>
                      <span className="text-[11px] font-mono text-brand-muted">
                        /mcp/toolsets/{ts.slug} ({ts.tool_ids?.length ?? 0} tools)
                      </span>
                    </div>
                    <Badge variant={ts.is_active ? 'success' : 'neutral'}>
                      {ts.is_active ? 'Active' : 'Inactive'}
                    </Badge>
                  </div>
                ))}
              </div>
            )}
          </div>

          {/* MCP Tools Catalog */}
          <div>
            <h3 className="text-xs font-mono uppercase tracking-wider text-brand-muted mb-3 flex items-center gap-2">
              <Settings className="w-4 h-4 text-status-success" />
              Discovered Tool Schemas ({filteredTools.length})
            </h3>

            {isToolsLoading ? (
              <div className={EMPTY_CLS}>Loading tools...</div>
            ) : filteredTools.length === 0 ? (
        <div className="p-4 bg-surface-base border border-border-subtle rounded-lg text-xs text-brand-muted font-mono text-center">
          No tools.
        </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {filteredTools.map((tool, idx) => (
                  <div
                    key={tool.name || idx}
                    className={`${CARD_CLS} p-4 flex flex-col justify-between hover:border-border-strong transition`}
                  >
                    <div>
                      <div className="flex items-center gap-2 mb-2">
                        <Settings className="w-4 h-4 text-accent-primary shrink-0" />
                        <h4 className="text-xs font-bold font-mono text-brand-title truncate" title={tool.name}>
                          {tool.name}
                        </h4>
                      </div>
                      <p className="text-xs text-brand-muted line-clamp-2 mb-3">
                        {tool.description || '—'}
                      </p>
                    </div>

                    <div className="pt-2 border-t border-border-subtle flex justify-between items-center">
                      <span className="text-[10px] text-brand-muted font-mono">
                        {tool.input_schema?.properties ? `${Object.keys(tool.input_schema.properties).length} params` : '0 params'}
                      </span>
                      <button
                        onClick={() => setSelectedTool(tool)}
                        className={SRV_BTN_CLS}
                      >
                        Inspect Schema
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Tab 2: A2A (Agent-to-Agent) Mesh */}
      {activeTab === 'a2a' && (
        <div className="space-y-4">
          <div className={`${CARD_CLS} overflow-hidden`}>
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead className="bg-surface-elevated text-brand-muted uppercase text-[10px] tracking-wider border-b border-border-subtle">
                  <tr>
                    {['Agent', 'Slug', 'Binding', 'Endpoint', 'State'].map((h) => (
                      <th key={h} className="px-4 py-3">{h}</th>
                    ))}
                    <th className="px-4 py-3 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border-subtle">
                  {isA2ALoading || filteredAgents.length === 0 ? (
                    <tr>
                      <td colSpan={6} className="px-4 py-8 text-center text-brand-muted">
                        {isA2ALoading ? 'Loading...' : 'No A2A agents.'}
                      </td>
                    </tr>
                  ) : (
                    filteredAgents.map((agent) => (
                      <tr key={agent.id} className="hover:bg-surface-elevated/40 transition">
                        <td className="px-4 py-3 text-brand-title font-semibold flex items-center gap-2">
                          <Bot className="w-4 h-4 text-accent-primary" />
                          {agent.name}
                        </td>
                        <td className="px-4 py-3 text-brand-muted">{agent.slug}</td>
                        <td className="px-4 py-3">
                          <Badge variant={agent.is_public_card ? 'info' : 'neutral'}>
                            {agent.protocol_binding || 'HTTP+JSON'}{agent.is_public_card ? ' · Public' : ''}
                          </Badge>
                        </td>
                        <td className="px-4 py-3 text-brand-body truncate max-w-[200px]" title={agent.endpoint_url}>
                          {agent.endpoint_url}
                        </td>
                        <td className="px-4 py-3">
                          <Badge variant={agent.is_killed ? 'danger' : agent.is_active ? 'success' : 'neutral'}>
                            {agent.is_killed ? 'KILLED' : agent.is_active ? 'ACTIVE' : 'INACTIVE'}
                          </Badge>
                        </td>
                        <td className="px-4 py-3 text-right">
                          <div className="inline-flex items-center gap-1.5">
                            {[
                              agent.agent_card_url ? ['Sync', () => a2aActionMutation.mutate({ kind: 'sync', id: agent.id }), 'border-border-subtle text-brand-body'] : null,
                              ['Edit', () => openEditAgentModal(agent), 'border-border-subtle text-brand-body'],
                              [agent.is_killed ? 'Revive' : 'Kill', () => a2aActionMutation.mutate({ kind: 'kill', id: agent.id, killed: !agent.is_killed }), agent.is_killed ? 'status-success' : 'status-danger'],
                              ['Del', () => a2aActionMutation.mutate({ kind: 'del', id: agent.id }), 'border-border-subtle text-brand-muted'],
                            ].map((item) => item && (
                              <button key={item[0] as string} onClick={item[1] as () => void} className={`px-2 py-1 rounded text-xs font-mono border ${item[2]}`}>{item[0] as string}</button>
                            ))}
                          </div>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* Push Notification Outbox Table */}
          <div className={`${CARD_CLS} overflow-hidden text-xs font-mono`}>
            <div className="px-4 py-2.5 border-b border-border-subtle font-semibold text-brand-title">
              Push Outbox ({(a2aOutboxData?.events || []).length})
            </div>
            {(a2aOutboxData?.events || []).map((ev) => (
              <div key={ev.id} className="px-4 py-2 border-b border-border-subtle flex items-center justify-between gap-3">
                <span className="text-brand-muted truncate">{ev.task_id}</span>
                <span className="text-brand-body truncate flex-1">{ev.target_url}</span>
                <Badge variant={ev.status === 'sent' ? 'success' : ev.status === 'dead_letter' ? 'danger' : 'warning'}>{ev.status}</Badge>
                <span className="text-brand-muted">{ev.attempt_count}</span>
                {ev.status !== 'sent' && (
                  <button onClick={() => a2aActionMutation.mutate({ kind: 'replay', id: ev.id })} className="px-2 py-1 rounded border border-border-subtle text-brand-body">Replay</button>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {(selectedTool) && (
        <Modal title={`MCP Tool: ${selectedTool.name}`} isOpen={true} onClose={() => setSelectedTool(null)} size="lg">
          <div className="space-y-4">
            <Field label="Description">
              <p className="text-xs text-brand-body bg-surface-code border border-border-subtle rounded p-3 font-mono">
                {selectedTool.description || 'No description'}
              </p>
            </Field>
            <Field label="Input JSON Schema">
              <CodeBlock code={JSON.stringify(selectedTool.input_schema || {}, null, 2)} language="json" />
            </Field>
          </div>
        </Modal>
      )}

      {/* Register / Edit MCP Server Modal */}
      <FormModal
        open={showServerModal}
        onClose={() => { setShowServerModal(false); setEditingServer(null); setSrvForm(INIT_SRV_FORM); setSrvFormError(null); }}
        title={editingServer ? `Edit MCP Spec: ${editingServer.name}` : 'Register Upstream MCP Server'}
        maxWidth={editingServer ? undefined : 'lg'}
        onSubmit={() => {
          if (editingServer) {
            saveServerMutation.mutate({ id: editingServer.id, payload: { protocol_version: srvForm.protocol, transport_type: srvForm.transport, is_active: srvForm.active } });
            return;
          }
          if (!srvForm.name.trim() || !srvForm.slug.trim() || !srvForm.endpoint.trim()) return;
          setSrvFormError(null);
          let parsedHeaders: Record<string, string> | undefined;
          if (srvForm.staticHeaders.trim()) {
            try {
              const raw = JSON.parse(srvForm.staticHeaders);
              if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
                setSrvFormError('Static headers must be a JSON object.');
                return;
              }
              parsedHeaders = Object.fromEntries(Object.entries(raw).map(([k, v]) => [k, String(v)]));
            } catch {
              setSrvFormError('Invalid JSON syntax in Static Headers.');
              return;
            }
          }
          const scopes = srvForm.oauthScopes.split(',').map((s) => s.trim()).filter(Boolean);
          saveServerMutation.mutate({
            payload: {
              org_id: activeOrgId || undefined,
              name: srvForm.name.trim(),
              slug: srvForm.slug.trim(),
              endpoint_url: srvForm.endpoint.trim(),
              protocol_version: srvForm.protocol,
              transport_type: srvForm.transport,
              auth_type: srvForm.authType,
              auth_secret: srvForm.authSecret.trim() || undefined,
              static_headers: parsedHeaders,
              oauth2_endpoint: srvForm.authType === 'oauth2' ? srvForm.oauthEndpoint.trim() || undefined : undefined,
              oauth2_client_id: srvForm.authType === 'oauth2' ? srvForm.oauthClientId.trim() || undefined : undefined,
              oauth2_scopes: srvForm.authType === 'oauth2' && scopes.length > 0 ? scopes : undefined,
              pinned_tool_hash: srvForm.pinnedHash.trim() || undefined,
            },
          });
        }}
        pending={saveServerMutation.isPending || (!editingServer && (!srvForm.name.trim() || !srvForm.slug.trim() || !srvForm.endpoint.trim()))}
        submitLabel={editingServer ? 'Save' : saveServerMutation.isPending ? 'Registering...' : 'Register Server'}
      >
        {srvFormError && <ErrorAlert error={srvFormError} title="Invalid input" />}
        {saveServerMutation.isError && <ErrorAlert error={saveServerMutation.error} title="Failed" />}
        {!editingServer && (
          <>
            <div className="grid grid-cols-2 gap-3">
              <TextField label="Server Name *" req cls={INPUT_CLS} value={srvForm.name} onChange={(name) => patchSrvForm({ name })} />
              <TextField label="Slug *" req value={srvForm.slug} onChange={(slug) => patchSrvForm({ slug })} />
            </div>
            <TextField label="Endpoint URL *" req value={srvForm.endpoint} onChange={(endpoint) => patchSrvForm({ endpoint })} />
          </>
        )}
        <div className={editingServer ? 'space-y-4' : 'grid grid-cols-3 gap-3'}>
          <SpecTransportFields
            specs={availableSpecs}
            protocol={srvForm.protocol}
            onProtocolChange={(protocol) => patchSrvForm({ protocol })}
            transport={srvForm.transport}
            onTransportChange={(transport) => patchSrvForm({ transport })}
          />
          {editingServer ? (
            <label className="flex items-center gap-2 text-xs font-mono text-brand-body">
              <input type="checkbox" checked={srvForm.active} onChange={(e) => patchSrvForm({ active: e.target.checked })} />
              Server Active
            </label>
          ) : (
            <Field label="Auth Mode">
              <select value={srvForm.authType} onChange={(e) => patchSrvForm({ authType: e.target.value })} className={INPUT_CLS}>
                {['none', 'static', 'oauth2', 'delegation', 'vault_jwt'].map((m) => <option key={m} value={m}>{m}</option>)}
              </select>
            </Field>
          )}
        </div>
        {!editingServer && srvForm.authType !== 'none' && (
          <TextField label="Auth Secret / Token" type="password" value={srvForm.authSecret} onChange={(authSecret) => patchSrvForm({ authSecret })} />
        )}
        {!editingServer && srvForm.authType === 'oauth2' && (
          <div className="space-y-3 p-3 rounded-lg bg-surface-elevated/40 border border-border-subtle">
            <div className="grid grid-cols-2 gap-3">
              <TextField label="OAuth2 Token Endpoint" value={srvForm.oauthEndpoint} onChange={(oauthEndpoint) => patchSrvForm({ oauthEndpoint })} />
              <TextField label="OAuth2 Client ID" value={srvForm.oauthClientId} onChange={(oauthClientId) => patchSrvForm({ oauthClientId })} />
            </div>
            <TextField label="OAuth2 Scopes" value={srvForm.oauthScopes} onChange={(oauthScopes) => patchSrvForm({ oauthScopes })} />
          </div>
        )}
        {!editingServer && (
          <>
            <Field label="Static Headers JSON"><textarea rows={2} value={srvForm.staticHeaders} onChange={(e) => patchSrvForm({ staticHeaders: e.target.value })} className={MONO_INPUT_CLS} /></Field>
            <TextField label="Pinned Tool Hash" value={srvForm.pinnedHash} onChange={(pinnedHash) => patchSrvForm({ pinnedHash })} />
          </>
        )}
      </FormModal>

      {/* Create MCP Toolset Modal */}
      <FormModal
        open={showToolsetModal}
        onClose={() => setShowToolsetModal(false)}
        title="Create MCP Toolset"
        maxWidth="lg"
        onSubmit={() => {
          if (!tsForm.name.trim() || !tsForm.slug.trim()) return;
          const manual = tsForm.manual.split(',').map((s) => s.trim()).filter(Boolean);
          createToolsetMutation.mutate({
            org_id: activeOrgId || undefined,
            name: tsForm.name.trim(),
            slug: tsForm.slug.trim(),
            tool_ids: Array.from(new Set([...tsForm.selected, ...manual])),
          });
        }}
        pending={createToolsetMutation.isPending || !tsForm.name.trim() || !tsForm.slug.trim()}
        submitLabel="Create Toolset"
      >
        {createToolsetMutation.isError && <ErrorAlert error={createToolsetMutation.error} title="Failed" />}
        <div className="grid grid-cols-2 gap-3">
          <TextField label="Toolset Name *" req cls={INPUT_CLS} value={tsForm.name} onChange={(name) => setTsForm((p) => ({ ...p, name }))} />
          <TextField label="Slug *" req value={tsForm.slug} onChange={(slug) => setTsForm((p) => ({ ...p, slug }))} />
        </div>
        {mcpTools.length > 0 && (
          <Field label={`Select Tools (${tsForm.selected.length})`}>
            <div className="p-2 bg-surface-elevated/40 border border-border-subtle rounded-lg space-y-1.5">
              {mcpTools.map((tool: any, i: number) => {
                const tid = tool.id || tool.name || String(i);
                return (
                  <label key={tid} className="flex items-center gap-2 text-xs font-mono text-brand-body">
                    <input type="checkbox" checked={tsForm.selected.includes(tid)} onChange={() => toggleToolSelection(tid)} />
                    <span className="truncate">{tool.name}</span>
                  </label>
                );
              })}
            </div>
          </Field>
        )}
        <TextField label="Tool IDs" value={tsForm.manual} onChange={(manual) => setTsForm((p) => ({ ...p, manual }))} />
      </FormModal>


      {/* Register / Edit A2A Agent Modal */}
      <FormModal
        open={showAgentModal}
        onClose={() => { setShowAgentModal(false); setEditingAgent(null); setAgentForm(INIT_AGENT_FORM); }}
        title={editingAgent ? `Edit A2A Agent: ${editingAgent.name}` : 'Register A2A Agent'}
        maxWidth="lg"
        onSubmit={() => {
          if (!agentForm.name.trim() || !agentForm.endpoint.trim()) return;
          if (!editingAgent && !agentForm.slug.trim()) return;
          const maxIter = parseInt(agentForm.maxIter, 10);
          const maxBudget = parseInt(agentForm.maxBudget, 10);
          saveAgentMutation.mutate({
            id: editingAgent?.id,
            data: {
              org_id: editingAgent ? undefined : activeOrgId || undefined,
              name: agentForm.name.trim(),
              slug: editingAgent ? undefined : agentForm.slug.trim(),
              endpoint_url: agentForm.endpoint.trim(),
              agent_card_url: tr(agentForm.cardUrl),
              protocol_binding: agentForm.binding,
              is_public_card: agentForm.publicCard,
              task_visibility_mode: agentForm.visibility,
              auth_type: agentForm.authType,
              auth_secret: agentForm.authType !== 'none' ? tr(agentForm.authSecret) : undefined,
              is_active: editingAgent ? agentForm.active : undefined,
              max_task_iterations: editingAgent || isNaN(maxIter) || maxIter <= 0 ? undefined : maxIter,
              max_task_budget_micros: editingAgent || isNaN(maxBudget) || maxBudget <= 0 ? undefined : maxBudget,
            },
          });
        }}
        pending={saveAgentMutation.isPending || !agentForm.name.trim() || !agentForm.endpoint.trim() || (!editingAgent && !agentForm.slug.trim())}
        submitLabel={editingAgent ? 'Save' : 'Register Agent'}
      >
        {saveAgentMutation.isError && <ErrorAlert error={saveAgentMutation.error} title="Failed" />}
        <div className="grid grid-cols-2 gap-3">
          <TextField label="Agent Name *" req cls={INPUT_CLS} value={agentForm.name} onChange={(name) => patchAgentForm({ name })} />
          {!editingAgent && <TextField label="Mesh Slug *" req value={agentForm.slug} onChange={(slug) => patchAgentForm({ slug })} />}
        </div>
        <TextField label="Endpoint URL *" req value={agentForm.endpoint} onChange={(endpoint) => patchAgentForm({ endpoint })} />
        <TextField label="Agent Card URL" value={agentForm.cardUrl} onChange={(cardUrl) => patchAgentForm({ cardUrl })} />
        <div className="grid grid-cols-3 gap-3">
          {([
            ['Binding', 'binding', ['HTTP+JSON', 'JSONRPC', 'GRPC']],
            ['Visibility', 'visibility', ['key_strict', 'user_strict', 'team', 'org_admin']],
            ['Auth', 'authType', ['none', 'static', 'vault_jwt']],
          ] as const).map(([lbl, key, opts]) => (
            <Field key={key} label={lbl}>
              <select value={agentForm[key]} onChange={(e) => patchAgentForm({ [key]: e.target.value })} className={INPUT_CLS}>
                {opts.map((o) => <option key={o} value={o}>{o}</option>)}
              </select>
            </Field>
          ))}
        </div>
        <label className="flex items-center gap-2 text-xs font-mono text-brand-body">
          <input type="checkbox" checked={agentForm.publicCard} onChange={(e) => patchAgentForm({ publicCard: e.target.checked })} />
          Public Card Discovery
        </label>
        {editingAgent && (
          <label className="flex items-center gap-2 text-xs font-mono text-brand-body">
            <input type="checkbox" checked={agentForm.active} onChange={(e) => patchAgentForm({ active: e.target.checked })} />
            Agent Active
          </label>
        )}
        {agentForm.authType !== 'none' && (
          <TextField label="Auth Secret" type="password" value={agentForm.authSecret} onChange={(authSecret) => patchAgentForm({ authSecret })} />
        )}
        {!editingAgent && (
          <div className="grid grid-cols-2 gap-3">
            <TextField label="Max Iterations" type="number" value={agentForm.maxIter} onChange={(maxIter) => patchAgentForm({ maxIter })} />
            <TextField label="Max Budget (micros)" type="number" value={agentForm.maxBudget} onChange={(maxBudget) => patchAgentForm({ maxBudget })} />
          </div>
        )}
      </FormModal>

      {/* Set MCP User BYOK Credential Modal */}
      <FormModal
        open={showCredModal}
        onClose={() => setShowCredModal(false)}
        title="Set MCP User BYOK"
        onSubmit={() => {
          if (!credForm.serverId.trim() || !credForm.userId.trim() || !credForm.token.trim()) return;
          setUserCredMutation.mutate({ org_id: activeOrgId || undefined, server_id: credForm.serverId.trim(), user_id: credForm.userId.trim(), token: credForm.token.trim() });
        }}
        pending={setUserCredMutation.isPending || !credForm.serverId.trim() || !credForm.userId.trim() || !credForm.token.trim()}
        submitLabel="Save"
      >
        {setUserCredMutation.isError && <ErrorAlert error={setUserCredMutation.error} title="Failed" />}
        <Field label="MCP Server ID *">
          {mcpServers.length > 0 ? (
            <select required value={credForm.serverId} onChange={(e) => setCredForm((p) => ({ ...p, serverId: e.target.value }))} className={INPUT_CLS}>
              <option value="">Select Server...</option>
              {mcpServers.map((s) => <option key={s.id} value={s.id}>{s.name}</option>)}
            </select>
          ) : (
            <input type="text" required value={credForm.serverId} onChange={(e) => setCredForm((p) => ({ ...p, serverId: e.target.value }))} className={MONO_INPUT_CLS} />
          )}
        </Field>
        <TextField label="User ID *" req value={credForm.userId} onChange={(userId) => setCredForm((p) => ({ ...p, userId }))} />
        <TextField label="User Token *" req type="password" value={credForm.token} onChange={(token) => setCredForm((p) => ({ ...p, token }))} />
      </FormModal>

      {/* Configure A2A Push Notification Webhook Modal */}
      <FormModal
        open={showPushModal}
        onClose={() => setShowPushModal(false)}
        title="A2A Push Webhook"
        onSubmit={() => {
          if (!pushForm.taskId.trim() || !pushForm.targetUrl.trim()) return;
          setPushConfigMutation.mutate({ task_id: pushForm.taskId.trim(), target_url: pushForm.targetUrl.trim(), auth_token: tr(pushForm.authToken) });
        }}
        pending={setPushConfigMutation.isPending || !pushForm.taskId.trim() || !pushForm.targetUrl.trim()}
        submitLabel="Save"
      >
        {setPushConfigMutation.isError && <ErrorAlert error={setPushConfigMutation.error} title="Failed" />}
        <TextField label="Task ID *" req value={pushForm.taskId} onChange={(taskId) => setPushForm((p) => ({ ...p, taskId }))} />
        <TextField label="Target URL *" req value={pushForm.targetUrl} onChange={(targetUrl) => setPushForm((p) => ({ ...p, targetUrl }))} />
        <TextField label="Auth Token" type="password" value={pushForm.authToken} onChange={(authToken) => setPushForm((p) => ({ ...p, authToken }))} />
      </FormModal>
    </div>
  );
};
