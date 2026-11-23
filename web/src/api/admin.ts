import { apiFetch } from './client';
import type {
  Organization,
  OrgProviderSubscription,
  OrgModelPolicy,
  Team,
  User,
  VirtualKey,
  ProviderCredential,
  CredentialValidationResult,
  GlobalModel,
  ModelGroup,
  PricingHistoryEntry,
  Deployment,
  DeploymentHealthReport,
  TelemetrySnapshot,
  SpendSummary,
  SpendEvent,
  AuditLog,
  GuardrailPolicy,
  GuardrailStatus,
  GuardrailDefinition,
  GuardrailDefinitionWriteRequest,
  GuardrailBinding,
  GuardrailBindingCreateRequest,
  ToolPolicy,
  ToolPolicyUpsertRequest,
  GuardrailUsageSummary,
  GuardrailSimulateRequest,
  GuardrailSimulateResponse,
  GuardrailApplyRequest,
  GuardrailApplyResponse,
  MCPServer,
  MCPTool,
  MCPToolset,
  A2AAgent,
  A2AOutboxEvent,
  GatewayConfig,
  SSOProviderPublicInfo,
  AuthLoginResponse,
  AuthMeResponse,
  QuotaPolicy,
  BudgetWindowLimit,
} from '../types';

const enc = encodeURIComponent;
const qs = (params: Record<string, string | number | undefined>) => {
  const sp = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== '') sp.set(k, String(v));
  }
  const s = sp.toString();
  return s ? `?${s}` : '';
};
const get = <T>(path: string, key: string) => apiFetch<T>(path, {}, key);
const del = <T>(path: string, key: string) => apiFetch<T>(path, { method: 'DELETE' }, key);
const send = <T>(method: 'POST' | 'PUT' | 'PATCH', path: string, data: unknown, key: string) =>
  apiFetch<T>(path, data === undefined ? { method } : { method, body: JSON.stringify(data) }, key);

export const adminApi = {
  // Organizations
  listOrgs: (key: string) => get<{ data: Organization[] }>('/admin/v1/organizations', key),
  createOrg: (key: string, data: Partial<Organization>) => send<Organization>('POST', '/admin/v1/organizations', data, key),
  updateOrg: (key: string, orgId: string, data: Partial<Organization>) =>
    send<Organization>('PUT', `/admin/v1/organizations/${enc(orgId)}`, data, key),
  getOrgSubscriptions: (key: string, orgId: string) =>
    get<{ data: OrgProviderSubscription[] }>(`/admin/v1/organizations/${enc(orgId)}/subscriptions`, key),
  setOrgSubscription: (key: string, orgId: string, data: Partial<OrgProviderSubscription>) =>
    send<OrgProviderSubscription>('POST', `/admin/v1/organizations/${enc(orgId)}/subscriptions`, data, key),
  getOrgModelPolicies: (key: string, orgId: string) =>
    get<{ data: OrgModelPolicy[] }>(`/admin/v1/organizations/${enc(orgId)}/models`, key),
  setOrgModelPolicy: (key: string, orgId: string, data: Partial<OrgModelPolicy>) =>
    send<OrgModelPolicy>('POST', `/admin/v1/organizations/${enc(orgId)}/models`, data, key),

  // Teams & Users
  listTeams: (key: string, orgId?: string) => get<{ data: Team[] }>(`/admin/v1/teams${qs({ org_id: orgId })}`, key),
  createTeam: (key: string, data: Partial<Team>) => send<Team>('POST', '/admin/v1/teams', data, key),
  updateTeam: (key: string, teamId: string, data: Partial<Team>) =>
    send<Team>('PUT', `/admin/v1/teams/${enc(teamId)}`, data, key),
  deleteTeam: (key: string, teamId: string) =>
    apiFetch<{ status: string; id: string }>(`/admin/v1/teams/${enc(teamId)}`, { method: 'DELETE' }, key),
  listTeamMembers: (key: string, teamId: string, orgId?: string) =>
    get<{ data: Array<{ user_id: string; role: string; max_budget_micros?: number; spent_micros?: number }> }>(`/admin/v1/teams/${enc(teamId)}/members${qs({ org_id: orgId })}`, key),
  bulkSyncTeamMembers: (
    key: string,
    teamId: string,
    data: {
      org_id?: string;
      members?: Array<{ user_id: string; role?: string }>;
      remove_user_ids?: string[];
    }
  ) => send<{ upserted: number; removed: number }>('POST', `/admin/v1/teams/${enc(teamId)}/members/bulk`, data, key),
  resetTeamMemberSpend: (key: string, teamId: string, userId: string) =>
    apiFetch<{ status: string }>(`/admin/v1/teams/${enc(teamId)}/members/${enc(userId)}/reset-spend`, { method: 'POST' }, key),
  rotateMasterKEK: (key: string, newMasterKey: string) =>
    send<{ status: string; rewrapped: Record<string, any>; multi_pod_notice?: string }>('POST', '/admin/v1/security/rotate-kek', { new_master_key: newMasterKey }, key),
  listUsers: (key: string, orgId?: string) => get<{ data: User[] }>(`/admin/v1/users${qs({ org_id: orgId })}`, key),
  createUser: (key: string, data: Partial<User>) => send<User>('POST', '/admin/v1/users', data, key),
  updateUser: (key: string, userId: string, data: Partial<User>) =>
    send<User>('PUT', `/admin/v1/users/${enc(userId)}`, data, key),
  deleteUser: (key: string, userId: string) =>
    apiFetch<{ status: string; id: string }>(`/admin/v1/users/${enc(userId)}`, { method: 'DELETE' }, key),

  // Virtual Keys
  listKeys: (key: string, params?: string | Record<string, string | number | undefined>) =>
    get<{ data: VirtualKey[]; total?: number }>(`/admin/v1/keys${qs(typeof params === 'string' ? { org_id: params } : params || {})}`, key),
  issueKey: (key: string, data: Partial<VirtualKey>) => send<VirtualKey>('POST', '/admin/v1/keys', data, key),
  updateKey: (key: string, keyId: string, data: Partial<VirtualKey>) =>
    send<VirtualKey>('PUT', `/admin/v1/keys/${enc(keyId)}`, data, key),
  blockKey: (key: string, keyId: string, reason?: string) =>
    send<{ status: string; id: string }>('POST', `/admin/v1/keys/${enc(keyId)}/block`, { reason }, key),
  unblockKey: (key: string, keyId: string) =>
    apiFetch<VirtualKey>(`/admin/v1/keys/${enc(keyId)}/unblock`, { method: 'POST' }, key),
  resetKeySpend: (key: string, keyId: string) =>
    apiFetch<{ status: string; id: string }>(`/admin/v1/keys/${enc(keyId)}/reset-spend`, { method: 'POST' }, key),
  bulkUpdateKeys: (key: string, data: { org_id?: string; key_ids: string[]; is_active?: boolean; max_budget_micros?: number; rpm_limit?: number; tpm_limit?: number; allowed_models?: string[] }) =>
    send<{ updated: number; data: VirtualKey[] }>('POST', '/admin/v1/keys/bulk-update', data, key),
  rotateKey: (key: string, keyId: string, data?: { org_id?: string; grace_period_seconds?: number }) =>
    apiFetch<VirtualKey>(
      `/admin/v1/keys/${enc(keyId)}/rotate`,
      { method: 'POST', ...(data ? { body: JSON.stringify(data) } : {}) },
      key
    ),
  setKeyTempBudget: (
    key: string,
    keyId: string,
    data: {
      org_id?: string;
      temp_budget_increase_micros?: number;
      temp_budget_expires_at?: string;
      ttl_seconds?: number;
    }
  ) => send<VirtualKey>('POST', `/admin/v1/keys/${enc(keyId)}/temp-budget`, data, key),
  revokeKey: (key: string, keyId: string) =>
    apiFetch<{ status: string; id: string }>(`/admin/v1/keys/${enc(keyId)}/revoke`, { method: 'POST' }, key),

  // Provider Credentials
  listCredentials: (key: string, orgId?: string) =>
    get<{ data: ProviderCredential[] }>(`/admin/v1/credentials${qs({ org_id: orgId })}`, key),
  createCredential: (
    key: string,
    data: {
      org_id?: string;
      provider: string;
      name: string;
      api_key: string;
      base_url?: string;
      headers?: Record<string, string>;
      expires_at?: string;
    }
  ) => send<ProviderCredential>('POST', '/admin/v1/credentials', data, key),
  rotateCredential: (
    key: string,
    credId: string,
    data: { api_key: string; base_url?: string; expires_at?: string; headers?: Record<string, string> }
  ) => send<ProviderCredential>('POST', `/admin/v1/credentials/${enc(credId)}/rotate`, data, key),
  validateCredential: (key: string, credId: string) =>
    apiFetch<CredentialValidationResult>(`/admin/v1/credentials/${enc(credId)}/validate`, { method: 'POST' }, key),
  preflightValidate: (
    key: string,
    data: {
      org_id?: string;
      provider: string;
      api_key: string;
      base_url?: string;
      headers?: Record<string, string>;
    }
  ) => send<CredentialValidationResult>('POST', '/admin/v1/credentials/validate', data, key),

  // Model Groups & Deployments
  listModelGroups: (key: string, orgId?: string) =>
    get<{ data: ModelGroup[] }>(`/admin/v1/model-groups${qs({ org_id: orgId })}`, key),
  getModelGroup: (key: string, groupId: string) => get<ModelGroup>(`/admin/v1/model-groups/${enc(groupId)}`, key),
  createModelGroup: (key: string, data: Partial<ModelGroup>) => send<ModelGroup>('POST', '/admin/v1/model-groups', data, key),
  updateModelGroup: (key: string, groupId: string, data: Partial<ModelGroup>) =>
    send<ModelGroup>('PUT', `/admin/v1/model-groups/${enc(groupId)}`, data, key),
  deleteModelGroup: (key: string, groupId: string) =>
    apiFetch<{ status: string; id: string }>(`/admin/v1/model-groups/${enc(groupId)}`, { method: 'DELETE' }, key),
  listDeployments: (key: string, groupId?: string) =>
    get<{ data: Deployment[] }>(`/admin/v1/deployments${qs({ model_group_id: groupId })}`, key),
  getDeployment: (key: string, depId: string) => get<Deployment>(`/admin/v1/deployments/${enc(depId)}`, key),
  createDeployment: (key: string, data: Partial<Deployment>) => send<Deployment>('POST', '/admin/v1/deployments', data, key),
  patchDeployment: (key: string, depId: string, data: Partial<Deployment>) =>
    apiFetch<Deployment>(`/admin/v1/deployments/${enc(depId)}`, { method: 'PATCH', body: JSON.stringify(data) }, key),
  deleteDeployment: (key: string, depId: string) =>
    apiFetch<{ status: string; id: string }>(`/admin/v1/deployments/${enc(depId)}`, { method: 'DELETE' }, key),

  // Global Catalogue & Pricing
  listCatalogue: (key: string) => get<{ data: GlobalModel[] }>('/admin/v1/catalogue', key),
  syncDiscovery: (key: string) =>
    apiFetch<any>('/admin/v1/catalogue/sync', { method: 'POST' }, key),
  importCatalogue: (key: string, provider?: string) =>
    apiFetch<{ imported: number; provider: string; total: number }>(
      `/admin/v1/catalogue/import${qs({ provider })}`,
      { method: 'POST' },
      key
    ),
  updatePricing: (key: string, data: any) => send<any>('POST', '/admin/v1/catalogue/pricing', data, key),
  listPricingHistory: (key: string, globalModelId?: string) =>
    get<{ data: PricingHistoryEntry[] }>(`/admin/v1/catalogue/pricing${qs({ global_model_id: globalModelId })}`, key),

  // Telemetry & Health
  getTelemetryMetrics: (key: string) => get<TelemetrySnapshot>('/admin/v1/observability/metrics', key),
  listDeploymentHealth: (key: string) => get<{ data: DeploymentHealthReport[] }>('/admin/v1/health/deployments', key),
  probeHealth: (key: string) =>
    apiFetch<{ data: DeploymentHealthReport[] }>('/admin/v1/health/probe', { method: 'POST' }, key),
  invalidateCache: (key: string, data: { org_id?: string; model?: string }) =>
    send<any>('POST', '/admin/v1/cache/invalidate', data, key),

  // FinOps & Audit
  getSpendSummary: (key: string, orgId?: string) => get<SpendSummary>(`/admin/v1/spend/summary${qs({ org_id: orgId })}`, key),
  listSpendLogs: (key: string, orgId?: string, limit: number = 50) =>
    get<{ data: SpendEvent[] }>(`/admin/v1/spend/logs${qs({ limit, org_id: orgId })}`, key),
  listAuditLogs: (key: string, orgId?: string, limit: number = 50) =>
    apiFetch<{ data: AuditLog[] }>(
      `/admin/v1/audit/logs${qs({ limit, org_id: orgId })}`,
      {},
      key
    ),

  // Guardrails
  getGuardrailPolicy: (key: string, orgId: string) =>
    apiFetch<GuardrailPolicy>(`/admin/v1/organizations/${enc(orgId)}/guardrails`, {}, key),
  setGuardrailPolicy: (key: string, orgId: string, data: Partial<GuardrailPolicy>) =>
    apiFetch<GuardrailPolicy>(
      `/admin/v1/organizations/${enc(orgId)}/guardrails`,
      { method: 'POST', body: JSON.stringify(data) },
      key
    ),
  simulateGuardrails: (
    key: string,
    orgId: string,
    promptOrReq: string | GuardrailSimulateRequest,
    policy?: Partial<GuardrailPolicy>
  ) =>
    apiFetch<GuardrailSimulateResponse>(
      `/admin/v1/organizations/${enc(orgId)}/guardrails/simulate`,
      {
        method: 'POST',
        body: JSON.stringify(
          typeof promptOrReq === 'string' ? { prompt: promptOrReq, policy } : promptOrReq
        ),
      },
      key
    ),
  applyGuardrails: (dataPlaneToken: string, data: GuardrailApplyRequest) =>
    send<GuardrailApplyResponse>('POST', '/v1/guardrails/apply', data, dataPlaneToken),

  // Named Guardrail Definitions & Lifecycle
  listGuardrailDefinitions: (key: string, orgId: string, params?: { status?: string; name?: string }) =>
    get<{ data: GuardrailDefinition[] }>(`/admin/v1/organizations/${enc(orgId)}/guardrail-definitions${qs(params || {})}`, key),
  createGuardrailDefinition: (key: string, orgId: string, data: GuardrailDefinitionWriteRequest) =>
    send<GuardrailDefinition>('POST', `/admin/v1/organizations/${enc(orgId)}/guardrail-definitions`, data, key),
  getGuardrailDefinition: (key: string, guardrailId: string) =>
    get<GuardrailDefinition>(`/admin/v1/guardrail-definitions/${enc(guardrailId)}`, key),
  updateGuardrailDefinition: (key: string, guardrailId: string, data: GuardrailDefinitionWriteRequest) =>
    send<GuardrailDefinition>('PUT', `/admin/v1/guardrail-definitions/${enc(guardrailId)}`, data, key),
  patchGuardrailDefinition: (key: string, guardrailId: string, data: Partial<GuardrailDefinitionWriteRequest>) =>
    send<GuardrailDefinition>('PATCH', `/admin/v1/guardrail-definitions/${enc(guardrailId)}`, data, key),
  deleteGuardrailDefinition: (key: string, guardrailId: string) =>
    del<{ status: string; deleted: boolean; id: string }>(`/admin/v1/guardrail-definitions/${enc(guardrailId)}`, key),
  setGuardrailDefinitionStatus: (key: string, guardrailId: string, status: GuardrailStatus) =>
    send<GuardrailDefinition>('POST', `/admin/v1/guardrail-definitions/${enc(guardrailId)}/status`, { status }, key),

  // Guardrail Bindings
  listGuardrailBindings: (
    key: string,
    orgId: string,
    params?: {
      guardrail_id?: string;
      guardrail_name?: string;
      team_id?: string;
      virtual_key_id?: string;
      end_user_id?: string;
      model_group_id?: string;
      tag?: string;
    }
  ) => get<{ data: GuardrailBinding[] }>(`/admin/v1/organizations/${enc(orgId)}/guardrail-bindings${qs(params || {})}`, key),
  createGuardrailBinding: (key: string, data: GuardrailBindingCreateRequest) =>
    send<GuardrailBinding>('POST', '/admin/v1/guardrail-bindings', data, key),
  deleteGuardrailBinding: (key: string, bindingId: string) =>
    del<{ status: string; deleted: boolean; id: string }>(`/admin/v1/guardrail-bindings/${enc(bindingId)}`, key),

  // Tool Trust Policies
  listToolPolicies: (
    key: string,
    orgId: string,
    params?: { team_id?: string; virtual_key_id?: string; tool_name?: string }
  ) => get<{ data: ToolPolicy[] }>(`/admin/v1/organizations/${enc(orgId)}/tool-policies${qs(params || {})}`, key),
  upsertToolPolicy: (key: string, orgId: string, data: ToolPolicyUpsertRequest) =>
    send<ToolPolicy>('POST', `/admin/v1/organizations/${enc(orgId)}/tool-policies`, data, key),
  deleteToolPolicy: (key: string, orgId: string, policyId: string) =>
    del<{ status: string; deleted: boolean; id: string }>(`/admin/v1/organizations/${enc(orgId)}/tool-policies/${enc(policyId)}`, key),

  // Guardrail Usage & Micro-Dollar Metrics
  getGuardrailUsage: (
    key: string,
    orgId: string,
    params?: {
      guardrail_id?: string;
      team_id?: string;
      virtual_key_id?: string;
      start_date?: string;
      end_date?: string;
      top_limit?: number;
    }
  ) => get<GuardrailUsageSummary>(`/admin/v1/organizations/${enc(orgId)}/guardrail-usage${qs(params || {})}`, key),

  // MCP & A2A
  getMCPSpec: (key: string) => get<any>('/admin/v1/mcp/spec', key),
  updateMCPSpec: (key: string, data: { protocol_version: string; strict_schema_validation?: boolean }) =>
    send<any>('PUT', '/admin/v1/mcp/spec', data, key),
  listMCPServers: (key: string, orgId?: string) =>
    get<{ servers?: MCPServer[]; data?: MCPServer[] }>(`/admin/v1/mcp/servers${qs({ org_id: orgId })}`, key),
  createMCPServer: (
    key: string,
    data: {
      org_id?: string;
      name: string;
      slug: string;
      protocol_version?: string;
      transport_type?: string;
      endpoint_url: string;
      auth_type?: string;
      auth_secret?: string;
      static_headers?: Record<string, string>;
      oauth2_endpoint?: string;
      oauth2_client_id?: string;
      oauth2_scopes?: string[];
      pinned_tool_hash?: string;
    }
  ) => send<{ status: string; server: MCPServer }>('POST', '/admin/v1/mcp/servers', data, key),
  updateMCPServer: (
    key: string,
    serverId: string,
    data: {
      name?: string;
      protocol_version?: string;
      transport_type?: string;
      endpoint_url?: string;
      auth_type?: string;
      auth_secret?: string;
      pinned_tool_hash?: string;
      is_active?: boolean;
    }
  ) => send<{ status: string; server: MCPServer }>('PUT', `/admin/v1/mcp/servers/${enc(serverId)}`, data, key),
  syncMCPServer: (key: string, serverId: string) => send<any>('POST', `/admin/v1/mcp/servers/${enc(serverId)}/sync`, undefined, key),
  listMCPToolsets: (key: string, orgId?: string) =>
    get<{ toolsets?: MCPToolset[]; data?: MCPToolset[] }>(`/admin/v1/mcp/toolsets${qs({ org_id: orgId })}`, key),
  createMCPToolset: (key: string, data: { org_id?: string; name: string; slug: string; tool_ids: string[] }) =>
    send<{ status: string; toolset: MCPToolset }>('POST', '/admin/v1/mcp/toolsets', data, key),
  listMCPTools: (key: string, orgId?: string, serverSlug?: string) =>
    get<{ tools: MCPTool[] }>(`/admin/v1/mcp/tools${qs({ org_id: orgId, server_slug: serverSlug })}`, key),
  setMCPUserCredential: (key: string, data: { org_id?: string; server_id: string; user_id: string; token: string }) =>
    send<{ status: string; credential_id: string }>('POST', '/admin/v1/mcp/credentials', data, key),
  listA2AAgents: (key: string, orgId?: string) =>
    get<{ agents?: A2AAgent[]; data?: A2AAgent[] }>(`/admin/v1/a2a/agents${qs({ org_id: orgId })}`, key),
  getA2AAgent: (key: string, agentId: string) => get<{ agent: A2AAgent }>(`/admin/v1/a2a/agents/${enc(agentId)}`, key),
  createA2AAgent: (
    key: string,
    data: {
      org_id?: string;
      name: string;
      slug: string;
      endpoint_url: string;
      agent_card_url?: string;
      agent_card_json?: string;
      extended_agent_card_json?: string;
      is_public_card?: boolean;
      protocol_binding?: string;
      task_visibility_mode?: string;
      auth_type?: string;
      auth_header_name?: string;
      auth_secret?: string;
      max_task_iterations?: number;
      max_task_budget_micros?: number;
    }
  ) => send<{ status: string; agent: A2AAgent }>('POST', '/admin/v1/a2a/agents', data, key),
  updateA2AAgent: (key: string, agentId: string, data: Record<string, any>) =>
    send<{ status: string; agent: A2AAgent }>('PUT', `/admin/v1/a2a/agents/${enc(agentId)}`, data, key),
  deleteA2AAgent: (key: string, agentId: string) =>
    del<{ status: string; id: string }>(`/admin/v1/a2a/agents/${enc(agentId)}`, key),
  syncA2AAgentCard: (key: string, agentId: string, data?: { agent_card_url?: string; jwks_url?: string }) =>
    send<{ status: string; agent: A2AAgent }>('POST', `/admin/v1/a2a/agents/${enc(agentId)}/sync-card`, data || {}, key),
  setA2AKillSwitch: (key: string, agentId: string, killed: boolean) =>
    send<any>('POST', `/admin/v1/a2a/agents/${enc(agentId)}/kill-switch`, { killed }, key),
  setA2APushConfig: (key: string, data: { org_id?: string; task_id: string; target_url: string; token?: string; auth_token?: string }) =>
    send<{ status: string; push_config: any }>('POST', '/admin/v1/a2a/push-configs', data, key),
  listA2AOutboxEvents: (key: string, params?: { org_id?: string; status?: string; limit?: number }) =>
    get<{ events: A2AOutboxEvent[] }>(`/admin/v1/a2a/outbox${qs(params || {})}`, key),
  replayA2AOutboxEvent: (key: string, eventId: string) =>
    send<{ status: string; event: A2AOutboxEvent }>('POST', `/admin/v1/a2a/outbox/${enc(eventId)}/replay`, {}, key),

  // Quotas & Multi-Window Budgets
  listQuotas: (key: string, params?: { org_id?: string; scope_type?: string; scope_id?: string; model_pattern?: string; active_only?: string }) =>
    get<{ data: QuotaPolicy[] }>(`/admin/v1/quotas${qs(params || {})}`, key),
  upsertQuota: (key: string, data: Partial<QuotaPolicy>) => send<QuotaPolicy>('PUT', '/admin/v1/quotas', data, key),
  deleteQuota: (key: string, policyId: string, orgId?: string) =>
    del<{ status: string; id: string }>(`/admin/v1/quotas/${enc(policyId)}${qs({ org_id: orgId })}`, key),
  listBudgetWindows: (key: string, params?: { org_id?: string; scope_type?: string; scope_id?: string; window_type?: string }) =>
    get<{ data: BudgetWindowLimit[] }>(`/admin/v1/budget-windows${qs(params || {})}`, key),
  upsertBudgetWindow: (key: string, data: Partial<BudgetWindowLimit>) =>
    send<BudgetWindowLimit>('PUT', '/admin/v1/budget-windows', data, key),

  // Gateway Runtime Config
  getConfig: (key: string) => get<GatewayConfig>('/admin/v1/config', key),
};

export const authApi = {
  getSSOProviders: () => get<{ providers: SSOProviderPublicInfo[] }>('/auth/sso/providers', ''),
  loginPassword: (data: { email?: string; username?: string; password: string }) => send<AuthLoginResponse>('POST', '/auth/login', data, ''),
  getMe: (key?: string) => get<AuthMeResponse>('/auth/me', key || ''),
  logout: (key?: string) => send<{ status: string }>('POST', '/auth/logout', undefined, key || ''),
  updatePassword: (data: { current_password?: string; new_password: string; user_id?: string; email?: string }, key?: string) =>
    send<{ status: string; user_id: string; password_reset_required: boolean }>('POST', '/auth/password', data, key || ''),
};
