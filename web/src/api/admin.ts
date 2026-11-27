import { apiFetch } from './client';
import type {
  Organization,
  OrgProviderSubscription,
  OrgModelPolicy,
  Team,
  Project,
  AccessGroup,
  AccessGroupMember,
  AccessGroupRule,
  JWTKeyMapping,
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
  AuditLogFilter,
  GuardrailPolicy,
  GuardrailDefinition,
  GuardrailDefinitionWriteRequest,
  GuardrailSimulateRequest,
  GuardrailSimulateResponse,
  MCPServer,
  MCPTool,
  MCPToolset,
  A2AAgent,
  GatewayConfig,
  SSOProviderPublicInfo,
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

export const adminApi = {
  // Organizations
  listOrgs: (key: string) =>
    apiFetch<{ data: Organization[] }>('/admin/v1/organizations', {}, key),
  createOrg: (key: string, data: Partial<Organization>) =>
    apiFetch<Organization>('/admin/v1/organizations', { method: 'POST', body: JSON.stringify(data) }, key),
  updateOrg: (key: string, orgId: string, data: Partial<Organization>) =>
    apiFetch<Organization>(`/admin/v1/organizations/${enc(orgId)}`, { method: 'PUT', body: JSON.stringify(data) }, key),
  getOrgSubscriptions: (key: string, orgId: string) =>
    apiFetch<{ data: OrgProviderSubscription[] }>(`/admin/v1/organizations/${enc(orgId)}/subscriptions`, {}, key),
  setOrgSubscription: (key: string, orgId: string, data: Partial<OrgProviderSubscription>) =>
    apiFetch<OrgProviderSubscription>(`/admin/v1/organizations/${enc(orgId)}/subscriptions`, { method: 'POST', body: JSON.stringify(data) }, key),
  getOrgModelPolicies: (key: string, orgId: string) =>
    apiFetch<{ data: OrgModelPolicy[] }>(`/admin/v1/organizations/${enc(orgId)}/models`, {}, key),
  setOrgModelPolicy: (key: string, orgId: string, data: Partial<OrgModelPolicy>) =>
    apiFetch<OrgModelPolicy>(`/admin/v1/organizations/${enc(orgId)}/models`, { method: 'POST', body: JSON.stringify(data) }, key),

  // Teams & Users
  listTeams: (key: string, orgId?: string) =>
    apiFetch<{ data: Team[] }>(`/admin/v1/teams${qs({ org_id: orgId })}`, {}, key),
  createTeam: (key: string, data: Partial<Team>) =>
    apiFetch<Team>('/admin/v1/teams', { method: 'POST', body: JSON.stringify(data) }, key),
  updateTeam: (key: string, teamId: string, data: Partial<Team>) =>
    apiFetch<Team>(`/admin/v1/teams/${enc(teamId)}`, { method: 'PUT', body: JSON.stringify(data) }, key),
  deleteTeam: (key: string, teamId: string) =>
    apiFetch<{ status: string; id: string }>(`/admin/v1/teams/${enc(teamId)}`, { method: 'DELETE' }, key),
  listTeamMembers: (key: string, teamId: string, orgId?: string) =>
    apiFetch<{ data: Array<{ user_id: string; role: string; max_budget_micros?: number; spent_micros?: number; rpm_limit?: number; tpm_limit?: number; allowed_models?: string[] }> }>(`/admin/v1/teams/${enc(teamId)}/members${qs({ org_id: orgId })}`, {}, key),
  bulkSyncTeamMembers: (
    key: string,
    teamId: string,
    data: {
      org_id?: string;
      members?: Array<{ user_id: string; role?: string; max_budget_micros?: number; rpm_limit?: number; tpm_limit?: number; allowed_models?: string[] }>;
      remove_user_ids?: string[];
    }
  ) =>
    apiFetch<{ upserted: number; removed: number }>(`/admin/v1/teams/${enc(teamId)}/members/bulk`, { method: 'POST', body: JSON.stringify(data) }, key),
  resetTeamMemberSpend: (key: string, teamId: string, userId: string) =>
    apiFetch<{ status: string }>(`/admin/v1/teams/${enc(teamId)}/members/${enc(userId)}/reset-spend`, { method: 'POST' }, key),
  rotateMasterKEK: (key: string, newMasterKey: string) =>
    apiFetch<{ status: string; rewrapped: Record<string, any>; multi_pod_notice?: string }>('/admin/v1/security/rotate-kek', { method: 'POST', body: JSON.stringify({ new_master_key: newMasterKey }) }, key),
  listUsers: (key: string, orgId?: string) =>
    apiFetch<{ data: User[] }>(`/admin/v1/users${qs({ org_id: orgId })}`, {}, key),
  createUser: (key: string, data: Partial<User>) =>
    apiFetch<User>('/admin/v1/users', { method: 'POST', body: JSON.stringify(data) }, key),
  updateUser: (key: string, userId: string, data: Partial<User>) =>
    apiFetch<User>(`/admin/v1/users/${enc(userId)}`, { method: 'PUT', body: JSON.stringify(data) }, key),
  deleteUser: (key: string, userId: string) =>
    apiFetch<{ status: string; id: string }>(`/admin/v1/users/${enc(userId)}`, { method: 'DELETE' }, key),

  // Virtual Keys
  listKeys: (key: string, params?: string | Record<string, string | number | undefined>) =>
    apiFetch<{ data: VirtualKey[]; total?: number }>(`/admin/v1/keys${qs(typeof params === 'string' ? { org_id: params } : params || {})}`, {}, key),
  issueKey: (key: string, data: Partial<VirtualKey>) =>
    apiFetch<VirtualKey>('/admin/v1/keys', { method: 'POST', body: JSON.stringify(data) }, key),
  updateKey: (key: string, keyId: string, data: Partial<VirtualKey>) =>
    apiFetch<VirtualKey>(`/admin/v1/keys/${enc(keyId)}`, { method: 'PUT', body: JSON.stringify(data) }, key),
  blockKey: (key: string, keyId: string, reason?: string) =>
    apiFetch<{ status: string; id: string }>(`/admin/v1/keys/${enc(keyId)}/block`, { method: 'POST', body: JSON.stringify({ reason }) }, key),
  unblockKey: (key: string, keyId: string) =>
    apiFetch<VirtualKey>(`/admin/v1/keys/${enc(keyId)}/unblock`, { method: 'POST' }, key),
  resetKeySpend: (key: string, keyId: string) =>
    apiFetch<{ status: string; id: string }>(`/admin/v1/keys/${enc(keyId)}/reset-spend`, { method: 'POST' }, key),
  bulkUpdateKeys: (key: string, data: { org_id?: string; key_ids: string[]; is_active?: boolean; max_budget_micros?: number; rpm_limit?: number; tpm_limit?: number; allowed_models?: string[] }) =>
    apiFetch<{ updated: number; data: VirtualKey[] }>('/admin/v1/keys/bulk-update', { method: 'POST', body: JSON.stringify(data) }, key),
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
  ) =>
    apiFetch<VirtualKey>(
      `/admin/v1/keys/${enc(keyId)}/temp-budget`,
      { method: 'POST', body: JSON.stringify(data) },
      key
    ),
  revokeKey: (key: string, keyId: string) =>
    apiFetch<{ status: string; id: string }>(`/admin/v1/keys/${enc(keyId)}/revoke`, { method: 'POST' }, key),

  // Provider Credentials
  listCredentials: (key: string, orgId?: string) =>
    apiFetch<{ data: ProviderCredential[] }>(`/admin/v1/credentials${qs({ org_id: orgId })}`, {}, key),
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
  ) =>
    apiFetch<ProviderCredential>('/admin/v1/credentials', { method: 'POST', body: JSON.stringify(data) }, key),
  rotateCredential: (
    key: string,
    credId: string,
    data: { api_key: string; base_url?: string; expires_at?: string; headers?: Record<string, string> }
  ) =>
    apiFetch<ProviderCredential>(`/admin/v1/credentials/${enc(credId)}/rotate`, { method: 'POST', body: JSON.stringify(data) }, key),
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
  ) =>
    apiFetch<CredentialValidationResult>('/admin/v1/credentials/validate', { method: 'POST', body: JSON.stringify(data) }, key),

  // Model Groups & Deployments
  listModelGroups: (key: string, orgId?: string) =>
    apiFetch<{ data: ModelGroup[] }>(`/admin/v1/model-groups${qs({ org_id: orgId })}`, {}, key),
  getModelGroup: (key: string, groupId: string) =>
    apiFetch<ModelGroup>(`/admin/v1/model-groups/${enc(groupId)}`, {}, key),
  createModelGroup: (key: string, data: Partial<ModelGroup>) =>
    apiFetch<ModelGroup>('/admin/v1/model-groups', { method: 'POST', body: JSON.stringify(data) }, key),
  updateModelGroup: (key: string, groupId: string, data: Partial<ModelGroup>) =>
    apiFetch<ModelGroup>(`/admin/v1/model-groups/${enc(groupId)}`, { method: 'PUT', body: JSON.stringify(data) }, key),
  deleteModelGroup: (key: string, groupId: string) =>
    apiFetch<{ status: string; id: string }>(`/admin/v1/model-groups/${enc(groupId)}`, { method: 'DELETE' }, key),
  listDeployments: (key: string, groupId?: string) =>
    apiFetch<{ data: Deployment[] }>(`/admin/v1/deployments${qs({ model_group_id: groupId })}`, {}, key),
  getDeployment: (key: string, depId: string) =>
    apiFetch<Deployment>(`/admin/v1/deployments/${enc(depId)}`, {}, key),
  createDeployment: (key: string, data: Partial<Deployment>) =>
    apiFetch<Deployment>('/admin/v1/deployments', { method: 'POST', body: JSON.stringify(data) }, key),
  patchDeployment: (key: string, depId: string, data: Partial<Deployment>) =>
    apiFetch<Deployment>(`/admin/v1/deployments/${enc(depId)}`, { method: 'PATCH', body: JSON.stringify(data) }, key),
  deleteDeployment: (key: string, depId: string) =>
    apiFetch<{ status: string; id: string }>(`/admin/v1/deployments/${enc(depId)}`, { method: 'DELETE' }, key),

  // Global Catalogue & Pricing
  listCatalogue: (key: string) =>
    apiFetch<{ data: GlobalModel[] }>('/admin/v1/catalogue', {}, key),
  syncDiscovery: (key: string) =>
    apiFetch<any>('/admin/v1/catalogue/sync', { method: 'POST' }, key),
  importCatalogue: (key: string, provider?: string) =>
    apiFetch<{ imported: number; provider: string; total: number }>(
      `/admin/v1/catalogue/import${qs({ provider })}`,
      { method: 'POST' },
      key
    ),
  updatePricing: (key: string, data: any) =>
    apiFetch<any>('/admin/v1/catalogue/pricing', { method: 'POST', body: JSON.stringify(data) }, key),
  listPricingHistory: (key: string, globalModelId?: string) =>
    apiFetch<{ data: PricingHistoryEntry[] }>(
      `/admin/v1/catalogue/pricing${qs({ global_model_id: globalModelId })}`,
      {},
      key
    ),

  // Telemetry & Health
  getTelemetryMetrics: (key: string) =>
    apiFetch<TelemetrySnapshot>('/admin/v1/observability/metrics', {}, key),
  listDeploymentHealth: (key: string) =>
    apiFetch<{ data: DeploymentHealthReport[] }>('/admin/v1/health/deployments', {}, key),
  probeHealth: (key: string) =>
    apiFetch<{ data: DeploymentHealthReport[] }>('/admin/v1/health/probe', { method: 'POST' }, key),
  invalidateCache: (key: string, data: { org_id?: string; model?: string }) =>
    apiFetch<any>('/admin/v1/cache/invalidate', { method: 'POST', body: JSON.stringify(data) }, key),

  // FinOps & Audit
  getSpendSummary: (key: string, orgId?: string) =>
    apiFetch<SpendSummary>(`/admin/v1/spend/summary${qs({ org_id: orgId })}`, {}, key),
  listSpendLogs: (key: string, orgId?: string, limit: number = 50) =>
    apiFetch<{ data: SpendEvent[] }>(
      `/admin/v1/spend/logs${qs({ limit, org_id: orgId })}`,
      {},
      key
    ),
  listAuditLogs: (key: string, orgOrFilter?: string | AuditLogFilter, limit: number = 50) => {
    const params: Record<string, string | number | undefined> =
      typeof orgOrFilter === 'object' && orgOrFilter !== null
        ? { ...orgOrFilter, limit: orgOrFilter.limit ?? limit }
        : { org_id: orgOrFilter, limit };
    return apiFetch<{ data: AuditLog[]; next_cursor?: string }>(
      `/admin/v1/audit/logs${qs(params)}`,
      {},
      key
    );
  },

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

  // External Guardrail Definitions
  listGuardrailDefinitions: (
    key: string,
    orgId: string,
    params?: { enabled?: boolean }
  ) =>
    apiFetch<{ data: GuardrailDefinition[] }>(
      `/admin/v1/organizations/${enc(orgId)}/guardrail-definitions${qs(
        params?.enabled ? { enabled: 'true' } : {}
      )}`,
      {},
      key
    ),
  createGuardrailDefinition: (
    key: string,
    orgId: string,
    data: GuardrailDefinitionWriteRequest
  ) =>
    apiFetch<GuardrailDefinition>(
      `/admin/v1/organizations/${enc(orgId)}/guardrail-definitions`,
      { method: 'POST', body: JSON.stringify(data) },
      key
    ),
  getGuardrailDefinition: (key: string, guardrailId: string) =>
    apiFetch<GuardrailDefinition>(`/admin/v1/guardrail-definitions/${enc(guardrailId)}`, {}, key),
  updateGuardrailDefinition: (
    key: string,
    guardrailId: string,
    data: GuardrailDefinitionWriteRequest
  ) =>
    apiFetch<GuardrailDefinition>(
      `/admin/v1/guardrail-definitions/${enc(guardrailId)}`,
      { method: 'PUT', body: JSON.stringify(data) },
      key
    ),
  deleteGuardrailDefinition: (key: string, guardrailId: string) =>
    apiFetch<{ deleted: boolean; id: string }>(
      `/admin/v1/guardrail-definitions/${enc(guardrailId)}`,
      { method: 'DELETE' },
      key
    ),

  // MCP & A2A
  getMCPSpec: (key: string) =>
    apiFetch<any>('/admin/v1/mcp/spec', {}, key),
  updateMCPSpec: (
    key: string,
    data: { protocol_version: string; strict_schema_validation?: boolean }
  ) =>
    apiFetch<any>(
      '/admin/v1/mcp/spec',
      { method: 'PUT', body: JSON.stringify(data) },
      key
    ),
  listMCPServers: (key: string, orgId?: string) =>
    apiFetch<{ servers?: MCPServer[]; data?: MCPServer[] }>(
      `/admin/v1/mcp/servers${qs({ org_id: orgId })}`,
      {},
      key
    ),
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
  ) =>
    apiFetch<{ status: string; server: MCPServer }>(
      '/admin/v1/mcp/servers',
      { method: 'POST', body: JSON.stringify(data) },
      key
    ),
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
  ) =>
    apiFetch<{ status: string; server: MCPServer }>(
      `/admin/v1/mcp/servers/${enc(serverId)}`,
      { method: 'PUT', body: JSON.stringify(data) },
      key
    ),
  syncMCPServer: (key: string, serverId: string) =>
    apiFetch<any>(`/admin/v1/mcp/servers/${enc(serverId)}/sync`, { method: 'POST' }, key),
  listMCPToolsets: (key: string, orgId?: string) =>
    apiFetch<{ toolsets?: MCPToolset[]; data?: MCPToolset[] }>(
      `/admin/v1/mcp/toolsets${qs({ org_id: orgId })}`,
      {},
      key
    ),
  createMCPToolset: (
    key: string,
    data: { org_id?: string; name: string; slug: string; tool_ids: string[] }
  ) =>
    apiFetch<{ status: string; toolset: MCPToolset }>(
      '/admin/v1/mcp/toolsets',
      { method: 'POST', body: JSON.stringify(data) },
      key
    ),
  listMCPTools: (key: string, orgId?: string, serverSlug?: string) =>
    apiFetch<{ tools: MCPTool[] }>(
      `/admin/v1/mcp/tools${qs({ org_id: orgId, server_slug: serverSlug })}`,
      {},
      key
    ),
  setMCPUserCredential: (
    key: string,
    data: { org_id?: string; server_id: string; user_id: string; token: string }
  ) =>
    apiFetch<{ status: string; credential_id: string }>(
      '/admin/v1/mcp/credentials',
      { method: 'POST', body: JSON.stringify(data) },
      key
    ),
  listA2AAgents: (key: string, orgId?: string) =>
    apiFetch<{ agents?: A2AAgent[]; data?: A2AAgent[] }>(
      `/admin/v1/a2a/agents${qs({ org_id: orgId })}`,
      {},
      key
    ),
  getA2AAgent: (key: string, agentId: string) =>
    apiFetch<{ agent: A2AAgent }>(`/admin/v1/a2a/agents/${enc(agentId)}`, {}, key),
  createA2AAgent: (
    key: string,
    data: {
      org_id?: string;
      name: string;
      slug: string;
      endpoint_url: string;
      agent_card_url?: string;
      agent_card_json?: string;
      task_visibility_mode?: string;
      auth_type?: string;
      auth_secret?: string;
      max_task_iterations?: number;
      max_task_budget_micros?: number;
    }
  ) =>
    apiFetch<{ status: string; agent: A2AAgent }>(
      '/admin/v1/a2a/agents',
      { method: 'POST', body: JSON.stringify(data) },
      key
    ),
  setA2AKillSwitch: (key: string, agentId: string, killed: boolean) =>
    apiFetch<any>(`/admin/v1/a2a/agents/${enc(agentId)}/kill-switch`, { method: 'POST', body: JSON.stringify({ killed }) }, key),
  setA2APushConfig: (
    key: string,
    data: { task_id: string; target_url: string; auth_token?: string }
  ) =>
    apiFetch<{ status: string; push_config: any }>(
      '/admin/v1/a2a/push-configs',
      { method: 'POST', body: JSON.stringify(data) },
      key
    ),

  // Quotas & Multi-Window Budgets
  listQuotas: (
    key: string,
    params?: {
      org_id?: string;
      scope_type?: string;
      scope_id?: string;
      model_pattern?: string;
      active_only?: string;
    }
  ) => apiFetch<{ data: QuotaPolicy[] }>(`/admin/v1/quotas${qs(params || {})}`, {}, key),
  upsertQuota: (key: string, data: Partial<QuotaPolicy>) =>
    apiFetch<QuotaPolicy>('/admin/v1/quotas', { method: 'PUT', body: JSON.stringify(data) }, key),
  deleteQuota: (key: string, policyId: string, orgId?: string) =>
    apiFetch<{ status: string; id: string }>(
      `/admin/v1/quotas/${enc(policyId)}${qs({ org_id: orgId })}`,
      { method: 'DELETE' },
      key
    ),
  listBudgetWindows: (
    key: string,
    params?: { org_id?: string; scope_type?: string; scope_id?: string; window_type?: string }
  ) => apiFetch<{ data: BudgetWindowLimit[] }>(`/admin/v1/budget-windows${qs(params || {})}`, {}, key),
  upsertBudgetWindow: (key: string, data: Partial<BudgetWindowLimit>) =>
    apiFetch<BudgetWindowLimit>(
      '/admin/v1/budget-windows',
      { method: 'PUT', body: JSON.stringify(data) },
      key
    ),

  // Projects
  listProjects: (key: string, orgId?: string, teamId?: string) =>
    apiFetch<{ data: Project[] }>(`/admin/v1/projects${qs({ org_id: orgId, team_id: teamId })}`, {}, key),
  createProject: (key: string, data: Partial<Project>) =>
    apiFetch<Project>('/admin/v1/projects', { method: 'POST', body: JSON.stringify(data) }, key),
  updateProject: (key: string, projectId: string, data: Partial<Project>) =>
    apiFetch<Project>(`/admin/v1/projects/${enc(projectId)}`, { method: 'PUT', body: JSON.stringify(data) }, key),
  deleteProject: (key: string, projectId: string) =>
    apiFetch<{ status?: string; deleted?: boolean; id: string }>(`/admin/v1/projects/${enc(projectId)}`, { method: 'DELETE' }, key),

  // Unified Access Groups & Dynamic Access Rules
  listAccessGroups: (key: string, orgId?: string) =>
    apiFetch<{ data: AccessGroup[] }>(`/admin/v1/access-groups${qs({ org_id: orgId })}`, {}, key),
  upsertAccessGroup: (key: string, data: Partial<AccessGroup>) =>
    apiFetch<AccessGroup>('/admin/v1/access-groups', { method: 'PUT', body: JSON.stringify(data) }, key),
  deleteAccessGroup: (key: string, groupId: string) =>
    apiFetch<{ deleted?: boolean; id: string }>(`/admin/v1/access-groups/${enc(groupId)}`, { method: 'DELETE' }, key),
  addAccessGroupMember: (key: string, groupId: string, data: { org_id?: string; member_type: AccessGroupMember['member_type']; member_id: string }) =>
    apiFetch<AccessGroupMember>(`/admin/v1/access-groups/${enc(groupId)}/members`, { method: 'POST', body: JSON.stringify(data) }, key),
  removeAccessGroupMember: (key: string, groupId: string, memberId: string) =>
    apiFetch<{ deleted?: boolean; id: string }>(`/admin/v1/access-groups/${enc(groupId)}/members/${enc(memberId)}`, { method: 'DELETE' }, key),
  listAccessGroupRules: (key: string, orgId?: string) =>
    apiFetch<{ data: AccessGroupRule[] }>(`/admin/v1/access-group-rules${qs({ org_id: orgId })}`, {}, key),
  createAccessGroupRule: (key: string, data: Partial<AccessGroupRule>) =>
    apiFetch<AccessGroupRule>('/admin/v1/access-group-rules', { method: 'POST', body: JSON.stringify(data) }, key),
  deleteAccessGroupRule: (key: string, ruleId: string) =>
    apiFetch<{ deleted?: boolean; id: string }>(`/admin/v1/access-group-rules/${enc(ruleId)}`, { method: 'DELETE' }, key),

  // JWT Key Mappings
  listJWTMappings: (key: string, orgId?: string) =>
    apiFetch<{ data: JWTKeyMapping[] }>(`/admin/v1/jwt-mappings${qs({ org_id: orgId })}`, {}, key),
  createJWTMapping: (key: string, data: Partial<JWTKeyMapping>) =>
    apiFetch<JWTKeyMapping>('/admin/v1/jwt-mappings', { method: 'POST', body: JSON.stringify(data) }, key),
  deleteJWTMapping: (key: string, mappingId: string) =>
    apiFetch<{ deleted?: boolean; id: string }>(`/admin/v1/jwt-mappings/${enc(mappingId)}`, { method: 'DELETE' }, key),

  // Gateway Runtime Config
  getConfig: (key: string) =>
    apiFetch<GatewayConfig>('/admin/v1/config', {}, key),
};

export const authApi = {
  getSSOProviders: () =>
    apiFetch<{ providers: SSOProviderPublicInfo[] }>('/auth/sso/providers'),
  getMe: (key?: string) =>
    apiFetch<AuthMeResponse>('/auth/me', {}, key),
  logout: (key?: string) =>
    apiFetch<{ status: string; end_session_url?: string }>('/auth/logout', { method: 'POST' }, key),
  completeCLILogin: (
    loginId: string,
    data: { org_id?: string; team_id?: string; key_name?: string; ttl_seconds?: number },
    key?: string
  ) =>
    apiFetch<{
      status: string;
      login_id: string;
      org_id: string;
      team_id?: string;
      key_id: string;
      key_prefix: string;
    }>(`/auth/cli/complete/${enc(loginId)}`, { method: 'POST', body: JSON.stringify(data) }, key),
};
