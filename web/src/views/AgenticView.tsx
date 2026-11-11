import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { adminApi } from '../api/admin';
import { useAuth } from '../context/AuthContext';
import { Badge } from '../components/common/Badge';
import { Modal } from '../components/common/Modal';
import { CodeBlock } from '../components/common/CodeBlock';
import {
  Bot,
  Server,
  Wrench,
  Power,
  RefreshCw,
  CheckCircle2,
  AlertOctagon,
  Radio,
  Search,
} from 'lucide-react';

export const AgenticView: React.FC = () => {
  const { adminKey } = useAuth();
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<'mcp' | 'a2a'>('mcp');
  const [selectedTool, setSelectedTool] = useState<any | null>(null);
  const [searchFilter, setSearchFilter] = useState('');

  // Fetch MCP Servers
  const {
    data: mcpServersData,
    isLoading: isMCPLoading,
    refetch: refetchMCP,
  } = useQuery({
    queryKey: ['admin', 'mcp-servers', adminKey],
    queryFn: () => adminApi.listMCPServers(adminKey),
    enabled: !!adminKey,
  });

  // Fetch MCP Tools
  const {
    data: mcpToolsData,
    isLoading: isToolsLoading,
    refetch: refetchTools,
  } = useQuery({
    queryKey: ['admin', 'mcp-tools', adminKey],
    queryFn: () => adminApi.listMCPTools(adminKey),
    enabled: !!adminKey && activeTab === 'mcp',
  });

  // Fetch A2A Agents
  const {
    data: a2aAgentsData,
    isLoading: isA2ALoading,
    refetch: refetchA2A,
  } = useQuery({
    queryKey: ['admin', 'a2a-agents', adminKey],
    queryFn: () => adminApi.listA2AAgents(adminKey),
    enabled: !!adminKey,
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

  const mcpServers = mcpServersData?.data || [];
  const mcpTools = mcpToolsData?.tools || [];
  const a2aAgents = a2aAgentsData?.data || [];

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

        <div className="flex items-center gap-3">
          <button
            onClick={() => {
              if (activeTab === 'mcp') {
                refetchMCP();
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
              <Server className="w-4 h-4" />
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
              <Radio className="w-4 h-4" />
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
              <Server className="w-4 h-4 text-accent-primary" />
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

                    <div className="pt-3 border-t border-subtle flex justify-end">
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

          {/* MCP Tools Catalog */}
          <div>
            <h3 className="text-xs font-mono uppercase tracking-wider text-zinc-400 mb-3 flex items-center gap-2">
              <Wrench className="w-4 h-4 text-emerald-400" />
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
                        <Wrench className="w-4 h-4 text-accent-primary shrink-0" />
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
                                <AlertOctagon className="w-3 h-3" /> KILL-SWITCHED
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
                            <Power className="w-3 h-3" />
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
    </div>
  );
};
