import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { adminApi } from '../api/admin';
import { useAuth } from '../context/AuthContext';
import { Badge } from '../components/common/Badge';
import { Modal, INPUT_CLS, BTN_PRIMARY, BTN_CANCEL } from '../components/common/Modal';
import { CodeBlock } from '../components/common/CodeBlock';
import { ErrorAlert } from '../components/common/ErrorAlert';
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

export const AgenticView: React.FC = () => {
  const { adminKey, activeOrgId } = useAuth();
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<'mcp' | 'a2a'>('mcp');
  const [selectedTool, setSelectedTool] = useState<any | null>(null);
  const [searchFilter, setSearchFilter] = useState('');

  // Modal toggles
  const [showServerModal, setShowServerModal] = useState(false);
  const [showToolsetModal, setShowToolsetModal] = useState(false);
  const [showCredModal, setShowCredModal] = useState(false);
  const [showAgentModal, setShowAgentModal] = useState(false);
  const [showPushModal, setShowPushModal] = useState(false);

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
  const [srvPinnedHash, setSrvPinnedHash] = useState('');

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
    enabled: !!adminKey,
  });

  // Fetch MCP Toolsets
  const {
    data: mcpToolsetsData,
    refetch: refetchToolsets,
  } = useQuery({
    queryKey: ['admin', 'mcp-toolsets', adminKey, activeOrgId],
    queryFn: () => adminApi.listMCPToolsets(adminKey, activeOrgId),
    enabled: !!adminKey && activeTab === 'mcp',
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
    enabled: !!adminKey && activeTab === 'mcp',
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
    enabled: !!adminKey,
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
      setSrvPinnedHash('');
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
          <h2 className="text-xl font-semibold text-zinc-100 flex items-center gap-2">
            <Bot className="w-5 h-5 text-accent-primary" />
            Agentic Ecosystem (MCP & A2A)
          </h2>
          <p className="text-xs text-zinc-400 mt-1">
            Standard Model Context Protocol tool runtime orchestration and Agent-to-Agent mesh with instant emergency kill-switches.
          </p>
        </div>

        <div className="flex items-center gap-2">
          {activeTab === 'mcp' ? (
            <>
              <button
                onClick={() => setShowCredModal(true)}
                className="flex items-center gap-1.5 px-3 py-1.5 bg-surface-elevated hover:bg-surface-hover border border-subtle text-zinc-200 hover:text-white rounded text-xs font-medium transition"
              >
                <Plus className="w-3.5 h-3.5" />
                Set User BYOK
              </button>
              <button
                onClick={() => setShowToolsetModal(true)}
                className="flex items-center gap-1.5 px-3 py-1.5 bg-surface-elevated hover:bg-surface-hover border border-subtle text-zinc-200 hover:text-white rounded text-xs font-medium transition"
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
                className="flex items-center gap-1.5 px-3 py-1.5 bg-surface-elevated hover:bg-surface-hover border border-subtle text-zinc-200 hover:text-white rounded text-xs font-medium transition"
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
            className="flex items-center gap-1.5 px-3 py-1.5 bg-surface-base border border-subtle hover:border-strong text-zinc-300 hover:text-white rounded text-xs transition"
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
      {isToolsError && (
        <ErrorAlert error={toolsError} title="Failed to load MCP tools" onRetry={() => refetchTools()} />
      )}
      {isA2AError && (
        <ErrorAlert error={a2aError} title="Failed to load A2A agents" onRetry={() => refetchA2A()} />
      )}

      {/* Tabs */}
      <div className="border-b border-subtle">
        <div className="flex items-center justify-between">
          <div className="flex gap-4">
            <button
              onClick={() => setActiveTab('mcp')}
              className={`pb-3 text-xs font-medium border-b-2 flex items-center gap-2 transition ${
                activeTab === 'mcp'
                  ? 'border-accent-primary text-accent-primary font-semibold'
                  : 'border-transparent text-zinc-400 hover:text-zinc-200'
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
                  : 'border-transparent text-zinc-400 hover:text-zinc-200'
              }`}
            >
              <Activity className="w-4 h-4" />
              A2A Mesh Protocol ({a2aAgents.length} Agents)
            </button>
          </div>

          <div className="flex items-center gap-2 pb-2">
            <div className="relative">
              <Search className="w-3.5 h-3.5 text-zinc-500 absolute left-2.5 top-1/2 -translate-y-1/2" />
              <input
                type="text"
                value={searchFilter}
                onChange={(e) => setSearchFilter(e.target.value)}
                placeholder={activeTab === 'mcp' ? 'Search tools...' : 'Search agents...'}
                className="pl-8 pr-3 py-1 text-xs bg-surface-elevated border border-subtle rounded text-zinc-200 placeholder-zinc-500 focus:outline-none focus:border-accent-primary font-mono w-56"
              />
            </div>
          </div>
        </div>
      </div>

      {/* Tab 1: MCP Server Registry & Tools */}
      {activeTab === 'mcp' && (
        <div className="space-y-6">
          {/* MCP Servers Grid */}
          <div>
            <h3 className="text-xs font-mono uppercase tracking-wider text-zinc-400 mb-3 flex items-center gap-2">
              <Layers className="w-4 h-4 text-accent-primary" />
              Registered MCP Servers ({mcpServers.length})
            </h3>

            {isMCPLoading ? (
              <div className="py-8 text-center text-xs font-mono text-zinc-500">
                Loading MCP servers...
              </div>
            ) : mcpServers.length === 0 ? (
              <div className="p-6 bg-surface-base border border-subtle rounded-lg text-center text-xs text-zinc-400 font-mono">
                No MCP servers registered. Connect an MCP server to expose callable tools to agents.
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {mcpServers.map((srv) => (
                  <div
                    key={srv.id}
                    className="bg-surface-base border border-subtle rounded-lg p-4 flex flex-col justify-between"
                  >
                    <div>
                      <div className="flex items-start justify-between gap-2 mb-2">
                        <div>
                          <h4 className="text-sm font-semibold text-zinc-100">{srv.name}</h4>
                          <span className="text-[11px] font-mono text-zinc-500">{srv.slug}</span>
                        </div>
                        <Badge variant={srv.is_active ? 'success' : 'neutral'}>
                          {srv.is_active ? 'Active' : 'Inactive'}
                        </Badge>
                      </div>

                      <div className="space-y-1.5 text-xs font-mono my-3">
                        <div className="text-zinc-400 flex justify-between">
                          <span>Transport:</span>
                          <span className="text-zinc-200 uppercase">{srv.transport_type}</span>
                        </div>
                        {srv.endpoint_url && (
                          <div className="text-zinc-400 flex justify-between truncate" title={srv.endpoint_url}>
                            <span>Endpoint:</span>
                            <span className="text-accent-primary truncate max-w-[160px]">{srv.endpoint_url}</span>
                          </div>
                        )}
                        <div className="text-zinc-400 flex justify-between">
                          <span>Tools Registered:</span>
                          <span className="text-emerald-400 font-bold">{srv.tool_count ?? 0}</span>
                        </div>
                      </div>
                    </div>

                    <div className="pt-3 border-t border-subtle flex justify-end gap-2">
                      <button
                        onClick={() => {
                          setCredServerId(srv.id);
                          setShowCredModal(true);
                        }}
                        className="flex items-center gap-1.5 px-2.5 py-1 bg-surface-elevated hover:bg-surface-hover border border-subtle text-zinc-300 hover:text-white rounded text-xs font-mono transition"
                      >
                        <Plus className="w-3 h-3" />
                        Set BYOK
                      </button>
                      <button
                        onClick={() => syncServerMutation.mutate(srv.id)}
                        disabled={syncServerMutation.isPending}
                        className="flex items-center gap-1.5 px-2.5 py-1 bg-surface-elevated hover:bg-surface-hover border border-subtle text-zinc-300 hover:text-white rounded text-xs font-mono transition"
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
            <h3 className="text-xs font-mono uppercase tracking-wider text-zinc-400 mb-3 flex items-center gap-2">
              <Layers className="w-4 h-4 text-accent-primary" />
              Curated MCP Toolsets ({mcpToolsets.length})
            </h3>
            {mcpToolsets.length === 0 ? (
              <div className="p-4 bg-surface-base border border-subtle rounded-lg text-center text-xs text-zinc-400 font-mono">
                No curated toolsets defined yet. Use "Create Toolset" to bundle discovered MCP tools under a dedicated `/mcp/toolsets/{'{slug}'}` endpoint.
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {mcpToolsets.map((ts) => (
                  <div
                    key={ts.id}
                    className="bg-surface-base border border-subtle rounded-lg p-4 flex items-center justify-between"
                  >
                    <div>
                      <h4 className="text-sm font-semibold text-zinc-100">{ts.name}</h4>
                      <span className="text-[11px] font-mono text-zinc-500">
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
            <h3 className="text-xs font-mono uppercase tracking-wider text-zinc-400 mb-3 flex items-center gap-2">
              <Settings className="w-4 h-4 text-emerald-400" />
              Discovered Tool Schemas ({filteredTools.length})
            </h3>

            {isToolsLoading ? (
              <div className="py-8 text-center text-xs font-mono text-zinc-500">
                Discovering tools from active MCP runtimes...
              </div>
            ) : filteredTools.length === 0 ? (
              <div className="p-6 bg-surface-base border border-subtle rounded-lg text-center text-xs text-zinc-400 font-mono">
                No tools discovered matching current search filter.
              </div>
            ) : (
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {filteredTools.map((tool, idx) => (
                  <div
                    key={tool.name || idx}
                    className="bg-surface-base border border-subtle rounded-lg p-4 flex flex-col justify-between hover:border-strong transition"
                  >
                    <div>
                      <div className="flex items-center gap-2 mb-2">
                        <Settings className="w-4 h-4 text-accent-primary shrink-0" />
                        <h4 className="text-xs font-bold font-mono text-zinc-100 truncate" title={tool.name}>
                          {tool.name}
                        </h4>
                      </div>
                      <p className="text-xs text-zinc-400 line-clamp-2 mb-3">
                        {tool.description || 'No tool description provided.'}
                      </p>
                    </div>

                    <div className="pt-2 border-t border-subtle flex justify-between items-center">
                      <span className="text-[10px] text-zinc-500 font-mono">
                        {tool.inputSchema?.properties ? `${Object.keys(tool.inputSchema.properties).length} params` : '0 params'}
                      </span>
                      <button
                        onClick={() => setSelectedTool(tool)}
                        className="px-2 py-0.5 bg-surface-elevated hover:bg-surface-hover border border-subtle text-zinc-300 hover:text-white rounded text-xs font-mono transition"
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
          <div className="bg-surface-base border border-subtle rounded-lg overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-left text-xs font-mono">
                <thead className="bg-zinc-900/60 text-zinc-400 uppercase text-[10px] tracking-wider border-b border-subtle">
                  <tr>
                    <th className="px-4 py-3">Agent Identity</th>
                    <th className="px-4 py-3">Mesh Slug</th>
                    <th className="px-4 py-3">Destination Endpoint</th>
                    <th className="px-4 py-3">State</th>
                    <th className="px-4 py-3 text-right">Emergency Kill-Switch</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-subtle">
                  {isA2ALoading ? (
                    <tr>
                      <td colSpan={5} className="px-4 py-8 text-center text-zinc-500">
                        Loading registered A2A mesh agents...
                      </td>
                    </tr>
                  ) : filteredAgents.length === 0 ? (
                    <tr>
                      <td colSpan={5} className="px-4 py-8 text-center text-zinc-500">
                        No A2A agents registered in this mesh.
                      </td>
                    </tr>
                  ) : (
                    filteredAgents.map((agent) => (
                      <tr key={agent.id} className="hover:bg-surface-elevated/40 transition">
                        <td className="px-4 py-3 text-zinc-200 font-semibold flex items-center gap-2">
                          <Bot className="w-4 h-4 text-accent-primary" />
                          {agent.name}
                        </td>
                        <td className="px-4 py-3 text-zinc-400">{agent.slug}</td>
                        <td className="px-4 py-3 text-zinc-300 truncate max-w-[200px]" title={agent.endpoint_url}>
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
                            className={`px-3 py-1 rounded text-xs font-mono font-medium transition inline-flex items-center gap-1.5 ${
                              agent.is_killed
                                ? 'bg-emerald-500/20 text-emerald-300 border border-emerald-500/40 hover:bg-emerald-500/30'
                                : 'bg-red-500/20 text-red-300 border border-red-500/40 hover:bg-red-500/30'
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
              <span className="text-xs text-zinc-400 font-mono block mb-1">Description:</span>
              <p className="text-xs text-zinc-200 bg-canvas border border-subtle rounded p-3 font-mono">
                {selectedTool.description || 'No description available'}
              </p>
            </div>

            <div>
              <span className="text-xs text-zinc-400 font-mono block mb-1">Input JSON Schema:</span>
              <CodeBlock
                code={JSON.stringify(selectedTool.inputSchema || {}, null, 2)}
                language="json"
              />
            </div>
          </div>
        </Modal>
      )}

      {/* Register MCP Server Modal */}
      <Modal
        isOpen={showServerModal}
        onClose={() => setShowServerModal(false)}
        title="Register Upstream MCP Server"
        description="Connect a Model Context Protocol server to discover and govern callable tools."
        maxWidth="lg"
      >
        <form
          onSubmit={(e) => {
            e.preventDefault();
            if (!srvName.trim() || !srvSlug.trim() || !srvEndpoint.trim()) return;
            createServerMutation.mutate({
              org_id: activeOrgId || undefined,
              name: srvName.trim(),
              slug: srvSlug.trim(),
              endpoint_url: srvEndpoint.trim(),
              protocol_version: srvProtocol,
              transport_type: srvTransport,
              auth_type: srvAuthType,
              auth_secret: srvAuthSecret.trim() || undefined,
              pinned_tool_hash: srvPinnedHash.trim() || undefined,
            });
          }}
          className="space-y-4"
        >
          {createServerMutation.isError && (
            <ErrorAlert error={createServerMutation.error} title="Failed to register MCP server" />
          )}
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">Server Name *</label>
              <input
                type="text"
                required
                value={srvName}
                onChange={(e) => setSrvName(e.target.value)}
                placeholder="GitHub Enterprise MCP"
                className={INPUT_CLS}
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">Slug *</label>
              <input
                type="text"
                required
                value={srvSlug}
                onChange={(e) => setSrvSlug(e.target.value)}
                placeholder="github-mcp"
                className={`${INPUT_CLS} font-mono`}
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">Endpoint URL *</label>
            <input
              type="text"
              required
              value={srvEndpoint}
              onChange={(e) => setSrvEndpoint(e.target.value)}
              placeholder="https://mcp.internal.example.com/mcp"
              className={`${INPUT_CLS} font-mono`}
            />
          </div>

          <div className="grid grid-cols-3 gap-3">
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">Protocol Version</label>
              <select
                value={srvProtocol}
                onChange={(e) => setSrvProtocol(e.target.value)}
                className={INPUT_CLS}
              >
                <option value="2026-07-28">2026-07-28</option>
                <option value="2025-11-25">2025-11-25</option>
              </select>
            </div>
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">Transport</label>
              <select
                value={srvTransport}
                onChange={(e) => setSrvTransport(e.target.value)}
                className={INPUT_CLS}
              >
                <option value="streamable_http">streamable_http</option>
                <option value="stdio">stdio</option>
              </select>
            </div>
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">Auth Mode</label>
              <select
                value={srvAuthType}
                onChange={(e) => setSrvAuthType(e.target.value)}
                className={INPUT_CLS}
              >
                <option value="none">none</option>
                <option value="static">static</option>
                <option value="oauth2">oauth2</option>
                <option value="delegation">delegation</option>
                <option value="vault_jwt">vault_jwt</option>
              </select>
            </div>
          </div>

          {srvAuthType !== 'none' && (
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                Auth Secret / Token (Vault Encrypted)
              </label>
              <input
                type="password"
                value={srvAuthSecret}
                onChange={(e) => setSrvAuthSecret(e.target.value)}
                placeholder="Bearer token or client secret..."
                className={`${INPUT_CLS} font-mono`}
              />
            </div>
          )}

          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">
              Pinned Tool Hash (Optional SHA-256)
            </label>
            <input
              type="text"
              value={srvPinnedHash}
              onChange={(e) => setSrvPinnedHash(e.target.value)}
              placeholder="sha256:..."
              className={`${INPUT_CLS} font-mono`}
            />
          </div>

          <div className="flex justify-end gap-2 pt-2">
            <button type="button" onClick={() => setShowServerModal(false)} className={BTN_CANCEL}>
              Cancel
            </button>
            <button
              type="submit"
              disabled={createServerMutation.isPending || !srvName.trim() || !srvSlug.trim() || !srvEndpoint.trim()}
              className={BTN_PRIMARY}
            >
              {createServerMutation.isPending ? 'Registering...' : 'Register Server'}
            </button>
          </div>
        </form>
      </Modal>

      {/* Create MCP Toolset Modal */}
      <Modal
        isOpen={showToolsetModal}
        onClose={() => setShowToolsetModal(false)}
        title="Create Curated MCP Toolset"
        description="Bundle specific MCP tools into a curated `/mcp/toolsets/{slug}` endpoint."
        maxWidth="lg"
      >
        <form
          onSubmit={(e) => {
            e.preventDefault();
            if (!tsName.trim() || !tsSlug.trim()) return;
            const manual = tsManualToolIds
              .split(',')
              .map((s) => s.trim())
              .filter(Boolean);
            const combined = Array.from(new Set([...tsSelectedToolIds, ...manual]));
            createToolsetMutation.mutate({
              org_id: activeOrgId || undefined,
              name: tsName.trim(),
              slug: tsSlug.trim(),
              tool_ids: combined,
            });
          }}
          className="space-y-4"
        >
          {createToolsetMutation.isError && (
            <ErrorAlert error={createToolsetMutation.error} title="Failed to create MCP toolset" />
          )}
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">Toolset Name *</label>
              <input
                type="text"
                required
                value={tsName}
                onChange={(e) => setTsName(e.target.value)}
                placeholder="Read-Only DevOps Tools"
                className={INPUT_CLS}
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">Slug *</label>
              <input
                type="text"
                required
                value={tsSlug}
                onChange={(e) => setTsSlug(e.target.value)}
                placeholder="devops-readonly"
                className={`${INPUT_CLS} font-mono`}
              />
            </div>
          </div>

          {mcpTools.length > 0 && (
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                Select Discovered Tools ({tsSelectedToolIds.length} selected)
              </label>
              <div className="p-2 bg-surface-elevated/40 border border-subtle rounded-lg space-y-1.5">
                {mcpTools.map((tool: any, i: number) => {
                  const tid = tool.id || tool.name || String(i);
                  return (
                    <label key={tid} className="flex items-center gap-2 text-xs font-mono text-zinc-200">
                      <input
                        type="checkbox"
                        checked={tsSelectedToolIds.includes(tid)}
                        onChange={() => toggleToolSelection(tid)}
                      />
                      <span className="truncate">{tool.name}</span>
                      {tool.id && <span className="text-[10px] text-zinc-500">({tool.id})</span>}
                    </label>
                  );
                })}
              </div>
            </div>
          )}

          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">
              Tool IDs (comma-separated, optional)
            </label>
            <input
              type="text"
              value={tsManualToolIds}
              onChange={(e) => setTsManualToolIds(e.target.value)}
              placeholder="mcp_tool_1, mcp_tool_2"
              className={`${INPUT_CLS} font-mono`}
            />
          </div>

          <div className="flex justify-end gap-2 pt-2">
            <button type="button" onClick={() => setShowToolsetModal(false)} className={BTN_CANCEL}>
              Cancel
            </button>
            <button
              type="submit"
              disabled={createToolsetMutation.isPending || !tsName.trim() || !tsSlug.trim()}
              className={BTN_PRIMARY}
            >
              {createToolsetMutation.isPending ? 'Creating...' : 'Create Toolset'}
            </button>
          </div>
        </form>
      </Modal>

      {/* Register A2A Agent Modal */}
      <Modal
        isOpen={showAgentModal}
        onClose={() => setShowAgentModal(false)}
        title="Register A2A Mesh Agent"
        description="Register an Agent-to-Agent protocol endpoint with task isolation, iteration caps, and budget controls."
        maxWidth="lg"
      >
        <form
          onSubmit={(e) => {
            e.preventDefault();
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
              auth_type: agentAuthType !== 'none' ? agentAuthType : undefined,
              auth_secret: agentAuthSecret.trim() || undefined,
              max_task_iterations: !isNaN(maxIter) && maxIter > 0 ? maxIter : 50,
              max_task_budget_micros: !isNaN(maxBudget) && maxBudget > 0 ? maxBudget : undefined,
            });
          }}
          className="space-y-4"
        >
          {createAgentMutation.isError && (
            <ErrorAlert error={createAgentMutation.error} title="Failed to register A2A agent" />
          )}
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">Agent Name *</label>
              <input
                type="text"
                required
                value={agentName}
                onChange={(e) => setAgentName(e.target.value)}
                placeholder="Incident Triage Agent"
                className={INPUT_CLS}
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">Mesh Slug *</label>
              <input
                type="text"
                required
                value={agentSlug}
                onChange={(e) => setAgentSlug(e.target.value)}
                placeholder="incident-triage"
                className={`${INPUT_CLS} font-mono`}
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">Endpoint URL *</label>
            <input
              type="text"
              required
              value={agentEndpoint}
              onChange={(e) => setAgentEndpoint(e.target.value)}
              placeholder="https://agent.internal.example.com/a2a"
              className={`${INPUT_CLS} font-mono`}
            />
          </div>

          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">
              Agent Card URL (Optional)
            </label>
            <input
              type="text"
              value={agentCardUrl}
              onChange={(e) => setAgentCardUrl(e.target.value)}
              placeholder="https://agent.internal.example.com/.well-known/agent-card.json"
              className={`${INPUT_CLS} font-mono`}
            />
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">Task Visibility</label>
              <select
                value={agentVisibility}
                onChange={(e) => setAgentVisibility(e.target.value)}
                className={INPUT_CLS}
              >
                <option value="key_strict">key_strict</option>
                <option value="user_strict">user_strict</option>
                <option value="team">team</option>
                <option value="org_admin">org_admin</option>
              </select>
            </div>
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">Upstream Auth</label>
              <select
                value={agentAuthType}
                onChange={(e) => setAgentAuthType(e.target.value)}
                className={INPUT_CLS}
              >
                <option value="none">none</option>
                <option value="bearer">bearer</option>
                <option value="api_key">api_key</option>
              </select>
            </div>
          </div>

          {agentAuthType !== 'none' && (
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                Auth Secret (Vault Encrypted)
              </label>
              <input
                type="password"
                value={agentAuthSecret}
                onChange={(e) => setAgentAuthSecret(e.target.value)}
                placeholder="Upstream agent secret..."
                className={`${INPUT_CLS} font-mono`}
              />
            </div>
          )}

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">Max Task Iterations</label>
              <input
                type="number"
                min={1}
                value={agentMaxIter}
                onChange={(e) => setAgentMaxIter(e.target.value)}
                className={`${INPUT_CLS} font-mono`}
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-slate-300 mb-1">
                Max Task Budget (micros, optional)
              </label>
              <input
                type="number"
                min={0}
                value={agentMaxBudgetMicros}
                onChange={(e) => setAgentMaxBudgetMicros(e.target.value)}
                placeholder="1000000"
                className={`${INPUT_CLS} font-mono`}
              />
            </div>
          </div>

          <div className="flex justify-end gap-2 pt-2">
            <button type="button" onClick={() => setShowAgentModal(false)} className={BTN_CANCEL}>
              Cancel
            </button>
            <button
              type="submit"
              disabled={createAgentMutation.isPending || !agentName.trim() || !agentSlug.trim() || !agentEndpoint.trim()}
              className={BTN_PRIMARY}
            >
              {createAgentMutation.isPending ? 'Registering...' : 'Register Agent'}
            </button>
          </div>
        </form>
      </Modal>

      {/* Set MCP User BYOK Credential Modal */}
      <Modal
        isOpen={showCredModal}
        onClose={() => setShowCredModal(false)}
        title="Set MCP User BYOK Credential"
        description="Store a Vault-encrypted per-user BYOK token for an upstream MCP server."
        maxWidth="md"
      >
        <form
          onSubmit={(e) => {
            e.preventDefault();
            if (!credServerId.trim() || !credUserId.trim() || !credToken.trim()) return;
            setUserCredMutation.mutate({
              org_id: activeOrgId || undefined,
              server_id: credServerId.trim(),
              user_id: credUserId.trim(),
              token: credToken.trim(),
            });
          }}
          className="space-y-4"
        >
          {setUserCredMutation.isError && (
            <ErrorAlert error={setUserCredMutation.error} title="Failed to save MCP user credential" />
          )}
          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">MCP Server ID *</label>
            {mcpServers.length > 0 ? (
              <select
                required
                value={credServerId}
                onChange={(e) => setCredServerId(e.target.value)}
                className={INPUT_CLS}
              >
                <option value="">Select MCP Server...</option>
                {mcpServers.map((s) => (
                  <option key={s.id} value={s.id}>
                    {s.name} ({s.id})
                  </option>
                ))}
              </select>
            ) : (
              <input
                type="text"
                required
                value={credServerId}
                onChange={(e) => setCredServerId(e.target.value)}
                placeholder="mcp_srv_..."
                className={`${INPUT_CLS} font-mono`}
              />
            )}
          </div>
          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">User ID *</label>
            <input
              type="text"
              required
              value={credUserId}
              onChange={(e) => setCredUserId(e.target.value)}
              placeholder="usr_..."
              className={`${INPUT_CLS} font-mono`}
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">
              User Token (Vault Encrypted) *
            </label>
            <input
              type="password"
              required
              value={credToken}
              onChange={(e) => setCredToken(e.target.value)}
              placeholder="ghp_... or OAuth bearer token"
              className={`${INPUT_CLS} font-mono`}
            />
          </div>
          <div className="flex justify-end gap-2 pt-2">
            <button type="button" onClick={() => setShowCredModal(false)} className={BTN_CANCEL}>
              Cancel
            </button>
            <button
              type="submit"
              disabled={setUserCredMutation.isPending || !credServerId.trim() || !credUserId.trim() || !credToken.trim()}
              className={BTN_PRIMARY}
            >
              {setUserCredMutation.isPending ? 'Saving...' : 'Save Credential'}
            </button>
          </div>
        </form>
      </Modal>

      {/* Configure A2A Push Notification Webhook Modal */}
      <Modal
        isOpen={showPushModal}
        onClose={() => setShowPushModal(false)}
        title="Configure A2A Push Notification Webhook"
        description="Register a webhook URL to receive asynchronous A2A task state updates."
        maxWidth="md"
      >
        <form
          onSubmit={(e) => {
            e.preventDefault();
            if (!pushTaskId.trim() || !pushTargetUrl.trim()) return;
            setPushConfigMutation.mutate({
              task_id: pushTaskId.trim(),
              target_url: pushTargetUrl.trim(),
              auth_token: pushAuthToken.trim() || undefined,
            });
          }}
          className="space-y-4"
        >
          {setPushConfigMutation.isError && (
            <ErrorAlert error={setPushConfigMutation.error} title="Failed to configure push webhook" />
          )}
          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">A2A Task ID *</label>
            <input
              type="text"
              required
              value={pushTaskId}
              onChange={(e) => setPushTaskId(e.target.value)}
              placeholder="task_..."
              className={`${INPUT_CLS} font-mono`}
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">Webhook Target URL *</label>
            <input
              type="text"
              required
              value={pushTargetUrl}
              onChange={(e) => setPushTargetUrl(e.target.value)}
              placeholder="https://callbacks.internal.example.com/a2a/webhook"
              className={`${INPUT_CLS} font-mono`}
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-slate-300 mb-1">
              Webhook Auth Token (Vault Encrypted, optional)
            </label>
            <input
              type="password"
              value={pushAuthToken}
              onChange={(e) => setPushAuthToken(e.target.value)}
              placeholder="Bearer secret..."
              className={`${INPUT_CLS} font-mono`}
            />
          </div>
          <div className="flex justify-end gap-2 pt-2">
            <button type="button" onClick={() => setShowPushModal(false)} className={BTN_CANCEL}>
              Cancel
            </button>
            <button
              type="submit"
              disabled={setPushConfigMutation.isPending || !pushTaskId.trim() || !pushTargetUrl.trim()}
              className={BTN_PRIMARY}
            >
              {setPushConfigMutation.isPending ? 'Saving...' : 'Save Webhook'}
            </button>
          </div>
        </form>
      </Modal>
    </div>
  );
};
