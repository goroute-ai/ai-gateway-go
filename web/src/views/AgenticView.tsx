import React, { useState, useMemo, useEffect } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { adminApi } from '../api/admin';
import { useAuth } from '../context/AuthContext';
import { Badge } from '../components/common/Badge';
import { Modal, FormModal, Field, INPUT_CLS, MONO_INPUT_CLS, BTN_PRIMARY, BTN_ELEV, CARD_CLS, EMPTY_CLS } from '../components/common/Modal';
import { CodeBlock } from '../components/common/CodeBlock';
import { ErrorAlert } from '../components/common/ErrorAlert';
import type { MCPTool, MCPServer, MCPSpecInfo, MCPRuntimeSpecState } from '../types';
import {
  Bot,
  Layers,
  Settings,
  Zap,
  RefreshCw,
  CheckCircle2,
  AlertTriangle,
  Activity,
  Search,
  Plus,
} from 'lucide-react';

const MCP_TRANSPORTS = ['streamable_http', 'http_sse_2024', 'stdio', 'openapi'] as const;

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
  const [editSrvProtocol, setEditSrvProtocol] = useState('2026-07-28');
  const [editSrvTransport, setEditSrvTransport] = useState('streamable_http');
  const [editSrvActive, setEditSrvActive] = useState(true);
  const [showToolsetModal, setShowToolsetModal] = useState(false);
  const [showCredModal, setShowCredModal] = useState(false);
  const [showAgentModal, setShowAgentModal] = useState(false);
  const [showPushModal, setShowPushModal] = useState(false);

  // Active Gateway MCP Specification Selector state
  const [gatewaySpecVersion, setGatewaySpecVersion] = useState('2026-07-28');
  const [gatewayStrictSchema, setGatewayStrictSchema] = useState(false);

  // MCP User BYOK Credential form state
  const [credServerId, setCredServerId] = useState('');
  const [credUserId, setCredUserId] = useState('');
  const [credToken, setCredToken] = useState('');

  // A2A Push Notification Config form state
  const [pushTaskId, setPushTaskId] = useState('');
  const [pushTargetUrl, setPushTargetUrl] = useState('');
  const [pushAuthToken, setPushAuthToken] = useState('');

  // MCP Server form state
  const [srvName, setSrvName] = useState('');
  const [srvSlug, setSrvSlug] = useState('');
  const [srvEndpoint, setSrvEndpoint] = useState('');
  const [srvProtocol, setSrvProtocol] = useState('2026-07-28');
  const [srvTransport, setSrvTransport] = useState('streamable_http');
  const [srvAuthType, setSrvAuthType] = useState('none');
  const [srvAuthSecret, setSrvAuthSecret] = useState('');
  const [srvStaticHeaders, setSrvStaticHeaders] = useState('');
  const [srvOAuthEndpoint, setSrvOAuthEndpoint] = useState('');
  const [srvOAuthClientId, setSrvOAuthClientId] = useState('');
  const [srvOAuthScopes, setSrvOAuthScopes] = useState('');
  const [srvPinnedHash, setSrvPinnedHash] = useState('');
  const [srvFormError, setSrvFormError] = useState<string | null>(null);

  // MCP Toolset form state
  const [tsName, setTsName] = useState('');
  const [tsSlug, setTsSlug] = useState('');
  const [tsSelectedToolIds, setTsSelectedToolIds] = useState<string[]>([]);
  const [tsManualToolIds, setTsManualToolIds] = useState('');

  // A2A Agent form state
  const [agentName, setAgentName] = useState('');
  const [agentSlug, setAgentSlug] = useState('');
  const [agentEndpoint, setAgentEndpoint] = useState('');
  const [agentCardUrl, setAgentCardUrl] = useState('');
  const [agentVisibility, setAgentVisibility] = useState('key_strict');
  const [agentAuthType, setAgentAuthType] = useState('none');
  const [agentAuthSecret, setAgentAuthSecret] = useState('');
  const [agentMaxIter, setAgentMaxIter] = useState('50');
  const [agentMaxBudgetMicros, setAgentMaxBudgetMicros] = useState('');

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

  const updateServerMutation = useMutation({
    mutationFn: ({ serverId, payload }: { serverId: string; payload: Parameters<typeof adminApi.updateMCPServer>[2] }) =>
      adminApi.updateMCPServer(adminKey, serverId, payload),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['admin', 'mcp-servers'] });
      setEditingServer(null);
    },
  });

  // Fetch MCP Servers
  const {
    data: mcpServersData,
    isLoading: isMCPLoading,
    isError: isMCPError,
    error: mcpError,
    refetch: refetchMCP,
  } = useQuery({
    queryKey: ['admin', 'mcp-servers', adminKey, activeOrgId],
    queryFn: () => adminApi.listMCPServers(adminKey, activeOrgId),
    enabled: isUnlocked,
  });

  // Fetch MCP Toolsets
  const {
    data: mcpToolsetsData,
    isError: isToolsetsError,
    error: toolsetsError,
    refetch: refetchToolsets,
  } = useQuery({
    queryKey: ['admin', 'mcp-toolsets', adminKey, activeOrgId],
    queryFn: () => adminApi.listMCPToolsets(adminKey, activeOrgId),
    enabled: isUnlocked && activeTab === 'mcp',
  });

  // Fetch MCP Tools
  const {
    data: mcpToolsData,
    isLoading: isToolsLoading,
    isError: isToolsError,
    error: toolsError,
    refetch: refetchTools,
  } = useQuery({
    queryKey: ['admin', 'mcp-tools', adminKey, activeOrgId],
    queryFn: () => adminApi.listMCPTools(adminKey, activeOrgId),
    enabled: isUnlocked && activeTab === 'mcp',
  });

  // Fetch A2A Agents
  const {
    data: a2aAgentsData,
    isLoading: isA2ALoading,
    isError: isA2AError,
    error: a2aError,
    refetch: refetchA2A,
  } = useQuery({
    queryKey: ['admin', 'a2a-agents', adminKey, activeOrgId],
    queryFn: () => adminApi.listA2AAgents(adminKey, activeOrgId),
    enabled: isUnlocked,
  });

  // Create MCP Server Mutation
  const createServerMutation = useMutation({
    mutationFn: (payload: Parameters<typeof adminApi.createMCPServer>[1]) =>
      adminApi.createMCPServer(adminKey, payload),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['admin', 'mcp-servers'] });
      setShowServerModal(false);
      setSrvName('');
      setSrvSlug('');
      setSrvEndpoint('');
      setSrvAuthType('none');
      setSrvAuthSecret('');
      setSrvStaticHeaders('');
      setSrvOAuthEndpoint('');
      setSrvOAuthClientId('');
      setSrvOAuthScopes('');
      setSrvPinnedHash('');
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
      setTsName('');
      setTsSlug('');
      setTsSelectedToolIds([]);
      setTsManualToolIds('');
    },
  });

  // Create A2A Agent Mutation
  const createAgentMutation = useMutation({
    mutationFn: (payload: Parameters<typeof adminApi.createA2AAgent>[1]) =>
      adminApi.createA2AAgent(adminKey, payload),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['admin', 'a2a-agents'] });
      setShowAgentModal(false);
      setAgentName('');
      setAgentSlug('');
      setAgentEndpoint('');
      setAgentCardUrl('');
      setAgentVisibility('key_strict');
      setAgentAuthType('none');
      setAgentAuthSecret('');
      setAgentMaxIter('50');
      setAgentMaxBudgetMicros('');
    },
  });

  // MCP Server Sync Mutation
  const syncServerMutation = useMutation({
    mutationFn: (serverId: string) => adminApi.syncMCPServer(adminKey, serverId),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['admin', 'mcp-servers'] });
      queryClient.invalidateQueries({ queryKey: ['admin', 'mcp-tools'] });
    },
  });

  // A2A Kill-switch Mutation
  const killSwitchMutation = useMutation({
    mutationFn: ({ agentId, killed }: { agentId: string; killed: boolean }) =>
      adminApi.setA2AKillSwitch(adminKey, agentId, killed),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['admin', 'a2a-agents'] });
    },
  });

  // Set MCP User BYOK Credential Mutation
  const setUserCredMutation = useMutation({
    mutationFn: (payload: Parameters<typeof adminApi.setMCPUserCredential>[1]) =>
      adminApi.setMCPUserCredential(adminKey, payload),
    onSuccess: () => {
      setShowCredModal(false);
      setCredServerId('');
      setCredUserId('');
      setCredToken('');
    },
  });

  // Set A2A Push Config Mutation
  const setPushConfigMutation = useMutation({
    mutationFn: (payload: Parameters<typeof adminApi.setA2APushConfig>[1]) =>
      adminApi.setA2APushConfig(adminKey, payload),
    onSuccess: () => {
      setShowPushModal(false);
      setPushTaskId('');
      setPushTargetUrl('');
      setPushAuthToken('');
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

  const toggleToolSelection = (toolId: string) => {
    setTsSelectedToolIds((prev) =>
      prev.includes(toolId) ? prev.filter((id) => id !== toolId) : [...prev, toolId]
    );
  };

  const filteredTools = mcpTools.filter((t) => {
    if (!searchFilter.trim()) return true;
    const term = searchFilter.toLowerCase();
    return (
      t.name?.toLowerCase().includes(term) ||
      t.description?.toLowerCase().includes(term)
    );
  });

  const filteredAgents = a2aAgents.filter((a) => {
    if (!searchFilter.trim()) return true;
    const term = searchFilter.toLowerCase();
    return (
      a.name?.toLowerCase().includes(term) ||
      a.slug?.toLowerCase().includes(term) ||
      a.endpoint_url?.toLowerCase().includes(term)
    );
  });

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
            Standard Model Context Protocol tool runtime orchestration and Agent-to-Agent mesh with instant emergency kill-switches.
          </p>
        </div>

        <div className="flex items-center gap-2">
          {activeTab === 'mcp' ? (
            <>
              <button
                onClick={() => setShowCredModal(true)}
                className={BTN_ELEV}
              >
                <Plus className="w-3.5 h-3.5" />
                Set User BYOK
              </button>
              <button
                onClick={() => setShowToolsetModal(true)}
                className={BTN_ELEV}
              >
                <Plus className="w-3.5 h-3.5" />
                Create Toolset
              </button>
              <button
                onClick={() => setShowServerModal(true)}
                className={BTN_PRIMARY}
              >
                <span className="flex items-center gap-1.5">
                  <Plus className="w-3.5 h-3.5" />
                  Register MCP Server
                </span>
              </button>
            </>
          ) : (
            <>
              <button
                onClick={() => setShowPushModal(true)}
                className={BTN_ELEV}
              >
                <Plus className="w-3.5 h-3.5" />
                Push Webhook
              </button>
              <button
                onClick={() => setShowAgentModal(true)}
                className={BTN_PRIMARY}
              >
                <span className="flex items-center gap-1.5">
                  <Plus className="w-3.5 h-3.5" />
                  Register A2A Agent
                </span>
              </button>
            </>
          )}
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

      {/* Error Alerts */}
      {isMCPError && (
        <ErrorAlert error={mcpError} title="Failed to load MCP servers" onRetry={() => refetchMCP()} />
      )}
      {isToolsetsError && (
        <ErrorAlert error={toolsetsError} title="Failed to load MCP toolsets" onRetry={() => refetchToolsets()} />
      )}
      {isToolsError && (
        <ErrorAlert error={toolsError} title="Failed to load MCP tools" onRetry={() => refetchTools()} />
      )}
      {isA2AError && (
        <ErrorAlert error={a2aError} title="Failed to load A2A agents" onRetry={() => refetchA2A()} />
      )}
      {syncServerMutation.isError && (
        <ErrorAlert error={syncServerMutation.error} title="Failed to sync MCP server" />
      )}
      {killSwitchMutation.isError && (
        <ErrorAlert error={killSwitchMutation.error} title="Failed to toggle A2A kill-switch" />
      )}

      {/* Tabs */}
      <div className="border-b border-border-subtle">
        <div className="flex items-center justify-between">
          <div className="flex gap-4">
            <button
              onClick={() => setActiveTab('mcp')}
              className={`pb-3 text-xs font-medium border-b-2 flex items-center gap-2 transition ${
                activeTab === 'mcp'
                  ? 'border-accent-primary text-accent-primary font-semibold'
                  : 'border-transparent text-brand-muted hover:text-brand-title'
              }`}
            >
              <Layers className="w-4 h-4" />
              Model Context Protocol ({mcpServers.length} Servers, {mcpTools.length} Tools)
            </button>
            <button
              onClick={() => setActiveTab('a2a')}
              className={`pb-3 text-xs font-medium border-b-2 flex items-center gap-2 transition ${
                activeTab === 'a2a'
                  ? 'border-accent-primary text-accent-primary font-semibold'
                  : 'border-transparent text-brand-muted hover:text-brand-title'
              }`}
            >
              <Activity className="w-4 h-4" />
              A2A Mesh Protocol ({a2aAgents.length} Agents)
            </button>
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
                        <div className="text-brand-muted flex justify-between">
                          <span>Spec Release:</span>
                          <span className="text-accent-primary font-semibold">{srv.protocol_version || '2026-07-28'}</span>
                        </div>
                        <div className="text-brand-muted flex justify-between">
                          <span>Transport:</span>
                          <span className="text-brand-body uppercase">{srv.transport_type}</span>
                        </div>
                        {srv.endpoint_url && (
                          <div className="text-brand-muted flex justify-between truncate" title={srv.endpoint_url}>
                            <span>Endpoint:</span>
                            <span className="text-accent-primary truncate max-w-[160px]">{srv.endpoint_url}</span>
                          </div>
                        )}
                        <div className="text-brand-muted flex justify-between">
                          <span>Tools Registered:</span>
                          <span className="text-status-success font-bold">{toolCountByServer.get(srv.id) ?? 0}</span>
                        </div>
                      </div>
                    </div>

                    <div className="pt-3 border-t border-border-subtle flex flex-wrap justify-end gap-2">
                      <button
                        onClick={() => {
                          setEditingServer(srv);
                          setEditSrvProtocol(srv.protocol_version || '2026-07-28');
                          setEditSrvTransport(srv.transport_type || 'streamable_http');
                          setEditSrvActive(srv.is_active);
                        }}
                        className="flex items-center gap-1.5 px-2.5 py-1 bg-surface-elevated hover:bg-surface-hover border border-border-subtle text-brand-body hover:text-brand-title rounded text-xs font-mono transition"
                      >
                        <Settings className="w-3 h-3" />
                        Edit Spec
                      </button>
                      <button
                        onClick={() => {
                          setCredServerId(srv.id);
                          setShowCredModal(true);
                        }}
                        className="flex items-center gap-1.5 px-2.5 py-1 bg-surface-elevated hover:bg-surface-hover border border-border-subtle text-brand-body hover:text-brand-title rounded text-xs font-mono transition"
                      >
                        <Plus className="w-3 h-3" />
                        Set BYOK
                      </button>
                      <button
                        onClick={() => syncServerMutation.mutate(srv.id)}
                        disabled={syncServerMutation.isPending}
                        className="flex items-center gap-1.5 px-2.5 py-1 bg-surface-elevated hover:bg-surface-hover border border-border-subtle text-brand-body hover:text-brand-title rounded text-xs font-mono transition"
                      >
                        <RefreshCw className="w-3 h-3" />
                        Sync Schema
                      </button>
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
              <div className="p-4 bg-surface-base border border-border-subtle rounded-lg text-center text-xs text-brand-muted font-mono">
                No curated toolsets defined yet. Use "Create Toolset" to bundle discovered MCP tools under a dedicated `/mcp/toolsets/{'{slug}'}` endpoint.
              </div>
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
              <div className={EMPTY_CLS}>
                Discovering tools from active MCP runtimes...
              </div>
            ) : filteredTools.length === 0 ? (
              <div className="p-6 bg-surface-base border border-border-subtle rounded-lg text-center text-xs text-brand-muted font-mono">
                No tools discovered matching current search filter.
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
                        {tool.description || 'No tool description provided.'}
                      </p>
                    </div>

                    <div className="pt-2 border-t border-border-subtle flex justify-between items-center">
                      <span className="text-[10px] text-brand-muted font-mono">
                        {tool.input_schema?.properties ? `${Object.keys(tool.input_schema.properties).length} params` : '0 params'}
                      </span>
                      <button
                        onClick={() => setSelectedTool(tool)}
                        className="px-2 py-0.5 bg-surface-elevated hover:bg-surface-hover border border-border-subtle text-brand-body hover:text-brand-title rounded text-xs font-mono transition"
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
                    <th className="px-4 py-3">Agent Identity</th>
                    <th className="px-4 py-3">Mesh Slug</th>
                    <th className="px-4 py-3">Destination Endpoint</th>
                    <th className="px-4 py-3">State</th>
                    <th className="px-4 py-3 text-right">Emergency Kill-Switch</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border-subtle">
                  {isA2ALoading ? (
                    <tr>
                      <td colSpan={5} className="px-4 py-8 text-center text-brand-muted">
                        Loading registered A2A mesh agents...
                      </td>
                    </tr>
                  ) : filteredAgents.length === 0 ? (
                    <tr>
                      <td colSpan={5} className="px-4 py-8 text-center text-brand-muted">
                        No A2A agents registered in this mesh.
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
                        <td className="px-4 py-3 text-brand-body truncate max-w-[200px]" title={agent.endpoint_url}>
                          {agent.endpoint_url}
                        </td>
                        <td className="px-4 py-3">
                          {agent.is_killed ? (
                            <Badge variant="danger">
                              <span className="flex items-center gap-1">
                                <AlertTriangle className="w-3 h-3" /> KILL-SWITCHED
                              </span>
                            </Badge>
                          ) : agent.is_active ? (
                            <Badge variant="success">
                              <span className="flex items-center gap-1">
                                <CheckCircle2 className="w-3 h-3" /> ACTIVE ROUTING
                              </span>
                            </Badge>
                          ) : (
                            <Badge variant="neutral">INACTIVE</Badge>
                          )}
                        </td>
                        <td className="px-4 py-3 text-right">
                          <button
                            onClick={() =>
                              killSwitchMutation.mutate({
                                agentId: agent.id,
                                killed: !agent.is_killed,
                              })
                            }
                            disabled={killSwitchMutation.isPending}
                            className={`px-3 py-1 rounded text-xs font-mono font-medium border transition inline-flex items-center gap-1.5 hover:opacity-90 ${
                              agent.is_killed ? 'status-success' : 'status-danger'
                            }`}
                          >
                            <Zap className="w-3 h-3" />
                            {agent.is_killed ? 'Revive Agent' : 'Kill Agent'}
                          </button>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* Tool Schema Modal */}
      {selectedTool && (
        <Modal
          title={`MCP Tool: ${selectedTool.name}`}
          isOpen={!!selectedTool}
          onClose={() => setSelectedTool(null)}
          size="lg"
        >
          <div className="space-y-4">
            <div>
              <span className="text-xs text-brand-muted font-mono block mb-1">Description:</span>
              <p className="text-xs text-brand-body bg-surface-code border border-border-subtle rounded p-3 font-mono">
                {selectedTool.description || 'No description available'}
              </p>
            </div>

            <div>
              <span className="text-xs text-brand-muted font-mono block mb-1">Input JSON Schema:</span>
              <CodeBlock
                code={JSON.stringify(selectedTool.input_schema || {}, null, 2)}
                language="json"
              />
            </div>
          </div>
        </Modal>
      )}

      {/* Register MCP Server Modal */}
      <FormModal
        open={showServerModal}
        onClose={() => setShowServerModal(false)}
        title="Register Upstream MCP Server"
        description="Connect a Model Context Protocol server to discover and govern callable tools."
        maxWidth="lg"
        onSubmit={() => {
          if (!srvName.trim() || !srvSlug.trim() || !srvEndpoint.trim()) return;
          setSrvFormError(null);
          let parsedHeaders: Record<string, string> | undefined;
          if (srvStaticHeaders.trim()) {
            try {
              const raw = JSON.parse(srvStaticHeaders);
              if (!raw || typeof raw !== 'object' || Array.isArray(raw)) {
                setSrvFormError('Static headers must be a JSON object of key/value strings.');
                return;
              }
              parsedHeaders = Object.fromEntries(Object.entries(raw).map(([k, v]) => [k, String(v)]));
            } catch {
              setSrvFormError('Invalid JSON syntax in Static Headers.');
              return;
            }
          }
          const scopes = srvOAuthScopes.split(',').map((s) => s.trim()).filter(Boolean);
          createServerMutation.mutate({
            org_id: activeOrgId || undefined,
            name: srvName.trim(),
            slug: srvSlug.trim(),
            endpoint_url: srvEndpoint.trim(),
            protocol_version: srvProtocol,
            transport_type: srvTransport,
            auth_type: srvAuthType,
            auth_secret: srvAuthSecret.trim() || undefined,
            static_headers: parsedHeaders,
            oauth2_endpoint: srvAuthType === 'oauth2' ? srvOAuthEndpoint.trim() || undefined : undefined,
            oauth2_client_id: srvAuthType === 'oauth2' ? srvOAuthClientId.trim() || undefined : undefined,
            oauth2_scopes: srvAuthType === 'oauth2' && scopes.length > 0 ? scopes : undefined,
            pinned_tool_hash: srvPinnedHash.trim() || undefined,
          });
        }}
        pending={createServerMutation.isPending || !srvName.trim() || !srvSlug.trim() || !srvEndpoint.trim()}
        submitLabel={createServerMutation.isPending ? 'Registering...' : 'Register Server'}
      >
        {srvFormError && <ErrorAlert error={srvFormError} title="Invalid MCP server input" />}
        {createServerMutation.isError && <ErrorAlert error={createServerMutation.error} title="Failed to register MCP server" />}
        <div className="grid grid-cols-2 gap-3">
          <Field label="Server Name *"><input type="text" required value={srvName} onChange={(e) => setSrvName(e.target.value)} placeholder="GitHub Enterprise MCP" className={INPUT_CLS} /></Field>
          <Field label="Slug *"><input type="text" required value={srvSlug} onChange={(e) => setSrvSlug(e.target.value)} placeholder="github-mcp" className={MONO_INPUT_CLS} /></Field>
        </div>
        <Field label="Endpoint URL *"><input type="text" required value={srvEndpoint} onChange={(e) => setSrvEndpoint(e.target.value)} placeholder="https://mcp.internal.example.com/mcp" className={MONO_INPUT_CLS} /></Field>
        <div className="grid grid-cols-3 gap-3">
          <SpecTransportFields
            specs={availableSpecs}
            protocol={srvProtocol}
            onProtocolChange={setSrvProtocol}
            transport={srvTransport}
            onTransportChange={setSrvTransport}
          />
          <Field label="Auth Mode">
            <select value={srvAuthType} onChange={(e) => setSrvAuthType(e.target.value)} className={INPUT_CLS}>
              {['none', 'static', 'oauth2', 'delegation', 'vault_jwt'].map((m) => <option key={m} value={m}>{m}</option>)}
            </select>
          </Field>
        </div>
        {srvAuthType !== 'none' && (
          <Field label="Auth Secret / Token (Vault Encrypted)">
            <input type="password" value={srvAuthSecret} onChange={(e) => setSrvAuthSecret(e.target.value)} placeholder="Bearer token or client secret..." className={MONO_INPUT_CLS} />
          </Field>
        )}
        {srvAuthType === 'oauth2' && (
          <div className="space-y-3 p-3 rounded-lg bg-surface-elevated/40 border border-border-subtle">
            <div className="grid grid-cols-2 gap-3">
              <Field label="OAuth2 Token Endpoint"><input type="text" value={srvOAuthEndpoint} onChange={(e) => setSrvOAuthEndpoint(e.target.value)} placeholder="https://auth.example.com/oauth/token" className={MONO_INPUT_CLS} /></Field>
              <Field label="OAuth2 Client ID"><input type="text" value={srvOAuthClientId} onChange={(e) => setSrvOAuthClientId(e.target.value)} placeholder="mcp-client-id" className={MONO_INPUT_CLS} /></Field>
            </div>
            <Field label="OAuth2 Scopes (comma-separated)"><input type="text" value={srvOAuthScopes} onChange={(e) => setSrvOAuthScopes(e.target.value)} placeholder="tools:read, tools:execute" className={MONO_INPUT_CLS} /></Field>
          </div>
        )}
        <Field label="Static Headers JSON (Optional)"><textarea rows={2} value={srvStaticHeaders} onChange={(e) => setSrvStaticHeaders(e.target.value)} placeholder='{"X-Tenant-Env": "prod"}' className={MONO_INPUT_CLS} /></Field>
        <Field label="Pinned Tool Hash (Optional SHA-256)"><input type="text" value={srvPinnedHash} onChange={(e) => setSrvPinnedHash(e.target.value)} placeholder="sha256:..." className={MONO_INPUT_CLS} /></Field>
      </FormModal>

      {/* Create MCP Toolset Modal */}
      <FormModal
        open={showToolsetModal}
        onClose={() => setShowToolsetModal(false)}
        title="Create Curated MCP Toolset"
        description="Bundle specific MCP tools into a curated `/mcp/toolsets/{slug}` endpoint."
        maxWidth="lg"
        onSubmit={() => {
          if (!tsName.trim() || !tsSlug.trim()) return;
          const manual = tsManualToolIds.split(',').map((s) => s.trim()).filter(Boolean);
          createToolsetMutation.mutate({
            org_id: activeOrgId || undefined,
            name: tsName.trim(),
            slug: tsSlug.trim(),
            tool_ids: Array.from(new Set([...tsSelectedToolIds, ...manual])),
          });
        }}
        pending={createToolsetMutation.isPending || !tsName.trim() || !tsSlug.trim()}
        submitLabel={createToolsetMutation.isPending ? 'Creating...' : 'Create Toolset'}
      >
        {createToolsetMutation.isError && <ErrorAlert error={createToolsetMutation.error} title="Failed to create MCP toolset" />}
        <div className="grid grid-cols-2 gap-3">
          <Field label="Toolset Name *"><input type="text" required value={tsName} onChange={(e) => setTsName(e.target.value)} placeholder="Read-Only DevOps Tools" className={INPUT_CLS} /></Field>
          <Field label="Slug *"><input type="text" required value={tsSlug} onChange={(e) => setTsSlug(e.target.value)} placeholder="devops-readonly" className={MONO_INPUT_CLS} /></Field>
        </div>
        {mcpTools.length > 0 && (
          <Field label={`Select Discovered Tools (${tsSelectedToolIds.length} selected)`}>
            <div className="p-2 bg-surface-elevated/40 border border-border-subtle rounded-lg space-y-1.5">
              {mcpTools.map((tool: any, i: number) => {
                const tid = tool.id || tool.name || String(i);
                return (
                  <label key={tid} className="flex items-center gap-2 text-xs font-mono text-brand-body">
                    <input type="checkbox" checked={tsSelectedToolIds.includes(tid)} onChange={() => toggleToolSelection(tid)} />
                    <span className="truncate">{tool.name}</span>
                    {tool.id && <span className="text-[10px] text-brand-muted">({tool.id})</span>}
                  </label>
                );
              })}
            </div>
          </Field>
        )}
        <Field label="Tool IDs (comma-separated, optional)"><input type="text" value={tsManualToolIds} onChange={(e) => setTsManualToolIds(e.target.value)} placeholder="mcp_tool_1, mcp_tool_2" className={MONO_INPUT_CLS} /></Field>
      </FormModal>

      {/* Edit MCP Server Specification Modal */}
      <FormModal
        open={!!editingServer}
        onClose={() => setEditingServer(null)}
        title={editingServer ? `Edit MCP Spec: ${editingServer.name}` : 'Edit MCP Server'}
        description="Switch this upstream MCP server's protocol specification release and transport driver."
        onSubmit={() => {
          if (!editingServer) return;
          updateServerMutation.mutate({
            serverId: editingServer.id,
            payload: {
              protocol_version: editSrvProtocol,
              transport_type: editSrvTransport,
              is_active: editSrvActive,
            },
          });
        }}
        pending={updateServerMutation.isPending}
        submitLabel={updateServerMutation.isPending ? 'Saving...' : 'Save Server Spec'}
      >
        {updateServerMutation.isError && (
          <ErrorAlert error={updateServerMutation.error} title="Failed to update MCP server spec" />
        )}
        <SpecTransportFields
          specs={availableSpecs}
          protocol={editSrvProtocol}
          onProtocolChange={setEditSrvProtocol}
          transport={editSrvTransport}
          onTransportChange={setEditSrvTransport}
        />
        <label className="flex items-center gap-2 text-xs font-mono text-brand-body cursor-pointer">
          <input
            type="checkbox"
            checked={editSrvActive}
            onChange={(e) => setEditSrvActive(e.target.checked)}
          />
          Server Active
        </label>
      </FormModal>

      {/* Register A2A Agent Modal */}
      <FormModal
        open={showAgentModal}
        onClose={() => setShowAgentModal(false)}
        title="Register A2A Mesh Agent"
        description="Register an Agent-to-Agent protocol endpoint with task isolation, iteration caps, and budget controls."
        maxWidth="lg"
        onSubmit={() => {
          if (!agentName.trim() || !agentSlug.trim() || !agentEndpoint.trim()) return;
          const maxIter = parseInt(agentMaxIter, 10);
          const maxBudget = parseInt(agentMaxBudgetMicros, 10);
          createAgentMutation.mutate({
            org_id: activeOrgId || undefined,
            name: agentName.trim(),
            slug: agentSlug.trim(),
            endpoint_url: agentEndpoint.trim(),
            agent_card_url: agentCardUrl.trim() || undefined,
            task_visibility_mode: agentVisibility,
            auth_type: agentAuthType,
            auth_secret: agentAuthType !== 'none' ? agentAuthSecret.trim() || undefined : undefined,
            max_task_iterations: !isNaN(maxIter) && maxIter > 0 ? maxIter : 50,
            max_task_budget_micros: !isNaN(maxBudget) && maxBudget > 0 ? maxBudget : undefined,
          });
        }}
        pending={createAgentMutation.isPending || !agentName.trim() || !agentSlug.trim() || !agentEndpoint.trim()}
        submitLabel={createAgentMutation.isPending ? 'Registering...' : 'Register Agent'}
      >
        {createAgentMutation.isError && <ErrorAlert error={createAgentMutation.error} title="Failed to register A2A agent" />}
        <div className="grid grid-cols-2 gap-3">
          <Field label="Agent Name *"><input type="text" required value={agentName} onChange={(e) => setAgentName(e.target.value)} placeholder="Incident Triage Agent" className={INPUT_CLS} /></Field>
          <Field label="Mesh Slug *"><input type="text" required value={agentSlug} onChange={(e) => setAgentSlug(e.target.value)} placeholder="incident-triage" className={MONO_INPUT_CLS} /></Field>
        </div>
        <Field label="Endpoint URL *"><input type="text" required value={agentEndpoint} onChange={(e) => setAgentEndpoint(e.target.value)} placeholder="https://agent.internal.example.com/a2a" className={MONO_INPUT_CLS} /></Field>
        <Field label="Agent Card URL (Optional)"><input type="text" value={agentCardUrl} onChange={(e) => setAgentCardUrl(e.target.value)} placeholder="https://agent.internal.example.com/.well-known/agent-card.json" className={MONO_INPUT_CLS} /></Field>
        <div className="grid grid-cols-2 gap-3">
          <Field label="Task Visibility">
            <select value={agentVisibility} onChange={(e) => setAgentVisibility(e.target.value)} className={INPUT_CLS}>
              {['key_strict', 'user_strict', 'team', 'org_admin'].map((v) => <option key={v} value={v}>{v}</option>)}
            </select>
          </Field>
          <Field label="Upstream Auth">
            <select value={agentAuthType} onChange={(e) => setAgentAuthType(e.target.value)} className={INPUT_CLS}>
              {['none', 'static', 'vault_jwt'].map((v) => <option key={v} value={v}>{v}</option>)}
            </select>
          </Field>
        </div>
        {agentAuthType !== 'none' && (
          <Field label="Auth Secret (Vault Encrypted)"><input type="password" value={agentAuthSecret} onChange={(e) => setAgentAuthSecret(e.target.value)} placeholder="Upstream agent secret..." className={MONO_INPUT_CLS} /></Field>
        )}
        <div className="grid grid-cols-2 gap-3">
          <Field label="Max Task Iterations"><input type="number" min={1} value={agentMaxIter} onChange={(e) => setAgentMaxIter(e.target.value)} className={MONO_INPUT_CLS} /></Field>
          <Field label="Max Task Budget (micros, optional)"><input type="number" min={0} value={agentMaxBudgetMicros} onChange={(e) => setAgentMaxBudgetMicros(e.target.value)} placeholder="1000000" className={MONO_INPUT_CLS} /></Field>
        </div>
      </FormModal>

      {/* Set MCP User BYOK Credential Modal */}
      <FormModal
        open={showCredModal}
        onClose={() => setShowCredModal(false)}
        title="Set MCP User BYOK Credential"
        description="Store a Vault-encrypted per-user BYOK token for an upstream MCP server."
        onSubmit={() => {
          if (!credServerId.trim() || !credUserId.trim() || !credToken.trim()) return;
          setUserCredMutation.mutate({ org_id: activeOrgId || undefined, server_id: credServerId.trim(), user_id: credUserId.trim(), token: credToken.trim() });
        }}
        pending={setUserCredMutation.isPending || !credServerId.trim() || !credUserId.trim() || !credToken.trim()}
        submitLabel="Save Credential"
      >
        {setUserCredMutation.isError && <ErrorAlert error={setUserCredMutation.error} title="Failed to save MCP user credential" />}
        <Field label="MCP Server ID *">
          {mcpServers.length > 0 ? (
            <select required value={credServerId} onChange={(e) => setCredServerId(e.target.value)} className={INPUT_CLS}>
              <option value="">Select MCP Server...</option>
              {mcpServers.map((s) => <option key={s.id} value={s.id}>{s.name} ({s.id})</option>)}
            </select>
          ) : (
            <input type="text" required value={credServerId} onChange={(e) => setCredServerId(e.target.value)} placeholder="mcp_srv_..." className={MONO_INPUT_CLS} />
          )}
        </Field>
        <Field label="User ID *"><input type="text" required value={credUserId} onChange={(e) => setCredUserId(e.target.value)} placeholder="usr_..." className={MONO_INPUT_CLS} /></Field>
        <Field label="User Token (Vault Encrypted) *"><input type="password" required value={credToken} onChange={(e) => setCredToken(e.target.value)} placeholder="ghp_... or OAuth bearer token" className={MONO_INPUT_CLS} /></Field>
      </FormModal>

      {/* Configure A2A Push Notification Webhook Modal */}
      <FormModal
        open={showPushModal}
        onClose={() => setShowPushModal(false)}
        title="Configure A2A Push Notification Webhook"
        description="Register a webhook URL to receive asynchronous A2A task state updates."
        onSubmit={() => {
          if (!pushTaskId.trim() || !pushTargetUrl.trim()) return;
          setPushConfigMutation.mutate({ task_id: pushTaskId.trim(), target_url: pushTargetUrl.trim(), auth_token: pushAuthToken.trim() || undefined });
        }}
        pending={setPushConfigMutation.isPending || !pushTaskId.trim() || !pushTargetUrl.trim()}
        submitLabel="Save Webhook"
      >
        {setPushConfigMutation.isError && <ErrorAlert error={setPushConfigMutation.error} title="Failed to configure push webhook" />}
        <Field label="A2A Task ID *"><input type="text" required value={pushTaskId} onChange={(e) => setPushTaskId(e.target.value)} placeholder="task_..." className={MONO_INPUT_CLS} /></Field>
        <Field label="Webhook Target URL *"><input type="text" required value={pushTargetUrl} onChange={(e) => setPushTargetUrl(e.target.value)} placeholder="https://callbacks.internal.example.com/a2a/webhook" className={MONO_INPUT_CLS} /></Field>
        <Field label="Webhook Auth Token (Vault Encrypted, optional)"><input type="password" value={pushAuthToken} onChange={(e) => setPushAuthToken(e.target.value)} placeholder="Bearer secret..." className={MONO_INPUT_CLS} /></Field>
      </FormModal>
    </div>
  );
};
