import { apiFetch } from './client';
import type {
  Organization,
  OrgProviderSubscription,
  OrgModelPolicy,
  Team,
  User,
  VirtualKey,
  ProviderCredential,
  GlobalModel,
  ModelGroup,
  Deployment,
  DeploymentHealthReport,
  TelemetrySnapshot,
  SpendSummary,
  SpendEvent,
  AuditLog,
  GuardrailPolicy,
  MCPServer,
  A2AAgent,
} from '../types';

export const adminApi = {
  // Organizations
  listOrgs: (key: string) =>
    apiFetch<{ data: Organization[] }>('/admin/v1/organizations', {}, key),
  createOrg: (key: string, data: Partial<Organization>) =>
    apiFetch<Organization>('/admin/v1/organizations', { method: 'POST', body: JSON.stringify(data) }, key),
  getOrgSubscriptions: (key: string, orgId: string) =>
    apiFetch<{ data: OrgProviderSubscription[] }>(`/admin/v1/organizations/${orgId}/subscriptions`, {}, key),
  setOrgSubscription: (key: string, orgId: string, data: Partial<OrgProviderSubscription>) =>
    apiFetch<OrgProviderSubscription>(`/admin/v1/organizations/${orgId}/subscriptions`, { method: 'POST', body: JSON.stringify(data) }, key),
  getOrgModelPolicies: (key: string, orgId: string) =>
    apiFetch<{ data: OrgModelPolicy[] }>(`/admin/v1/organizations/${orgId}/models`, {}, key),
  setOrgModelPolicy: (key: string, orgId: string, data: Partial<OrgModelPolicy>) =>
    apiFetch<OrgModelPolicy>(`/admin/v1/organizations/${orgId}/models`, { method: 'POST', body: JSON.stringify(data) }, key),

  // Teams & Users
  listTeams: (key: string, orgId?: string) =>
    apiFetch<{ data: Team[] }>(`/admin/v1/teams${orgId ? `?org_id=${orgId}` : ''}`, {}, key),
  createTeam: (key: string, data: Partial<Team>) =>
    apiFetch<Team>('/admin/v1/teams', { method: 'POST', body: JSON.stringify(data) }, key),
  listUsers: (key: string, orgId?: string) =>
    apiFetch<{ data: User[] }>(`/admin/v1/users${orgId ? `?org_id=${orgId}` : ''}`, {}, key),
  createUser: (key: string, data: Partial<User>) =>
    apiFetch<User>('/admin/v1/users', { method: 'POST', body: JSON.stringify(data) }, key),

  // Virtual Keys
  listKeys: (key: string, orgId?: string) =>
    apiFetch<{ data: VirtualKey[] }>(`/admin/v1/keys${orgId ? `?org_id=${orgId}` : ''}`, {}, key),
  issueKey: (key: string, data: Partial<VirtualKey>) =>
    apiFetch<VirtualKey>('/admin/v1/keys', { method: 'POST', body: JSON.stringify(data) }, key),
  revokeKey: (key: string, keyId: string) =>
    apiFetch<{ status: string; id: string }>(`/admin/v1/keys/${keyId}/revoke`, { method: 'POST' }, key),

  // Provider Credentials
  listCredentials: (key: string, orgId?: string) =>
    apiFetch<{ data: ProviderCredential[] }>(`/admin/v1/credentials${orgId ? `?org_id=${orgId}` : ''}`, {}, key),
  createCredential: (key: string, data: any) =>
    apiFetch<ProviderCredential>('/admin/v1/credentials', { method: 'POST', body: JSON.stringify(data) }, key),
  rotateCredential: (key: string, credId: string, data: any) =>
    apiFetch<ProviderCredential>(`/admin/v1/credentials/${credId}/rotate`, { method: 'POST', body: JSON.stringify(data) }, key),
  validateCredential: (key: string, credId: string) =>
    apiFetch<any>(`/admin/v1/credentials/${credId}/validate`, { method: 'POST' }, key),
  preflightValidate: (key: string, data: any) =>
    apiFetch<any>('/admin/v1/credentials/validate', { method: 'POST', body: JSON.stringify(data) }, key),

  // Model Groups & Deployments
  listModelGroups: (key: string, orgId?: string) =>
    apiFetch<{ data: ModelGroup[] }>(`/admin/v1/model-groups${orgId ? `?org_id=${orgId}` : ''}`, {}, key),
  createModelGroup: (key: string, data: Partial<ModelGroup>) =>
    apiFetch<ModelGroup>('/admin/v1/model-groups', { method: 'POST', body: JSON.stringify(data) }, key),
  listDeployments: (key: string, groupId?: string) =>
    apiFetch<{ data: Deployment[] }>(`/admin/v1/deployments${groupId ? `?model_group_id=${groupId}` : ''}`, {}, key),
  createDeployment: (key: string, data: Partial<Deployment>) =>
    apiFetch<Deployment>('/admin/v1/deployments', { method: 'POST', body: JSON.stringify(data) }, key),

  // Global Catalogue & Pricing
  listCatalogue: (key: string) =>
    apiFetch<{ data: GlobalModel[] }>('/admin/v1/catalogue', {}, key),
  syncDiscovery: (key: string) =>
    apiFetch<any>('/admin/v1/catalogue/sync', { method: 'POST' }, key),
  importCatalogue: (key: string, provider?: string) =>
    apiFetch<{ imported: number; provider: string; total: number }>(
      `/admin/v1/catalogue/import${provider ? `?provider=${provider}` : ''}`,
      { method: 'POST' },
      key
    ),
  updatePricing: (key: string, data: any) =>
    apiFetch<any>('/admin/v1/catalogue/pricing', { method: 'POST', body: JSON.stringify(data) }, key),

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
    apiFetch<SpendSummary>(`/admin/v1/spend/summary${orgId ? `?org_id=${orgId}` : ''}`, {}, key),
  listSpendLogs: (key: string, orgId?: string, limit: number = 50) =>
    apiFetch<{ data: SpendEvent[] }>(
      `/admin/v1/spend/logs?limit=${limit}${orgId ? `&org_id=${orgId}` : ''}`,
      {},
      key
    ),
  listAuditLogs: (key: string, orgId?: string, limit: number = 50) =>
    apiFetch<{ data: AuditLog[] }>(
      `/admin/v1/audit/logs?limit=${limit}${orgId ? `&org_id=${orgId}` : ''}`,
      {},
      key
    ),

  // Guardrails
  getGuardrailPolicy: (key: string, orgId: string) =>
    apiFetch<GuardrailPolicy>(`/admin/v1/organizations/${orgId}/guardrails`, {}, key),
  setGuardrailPolicy: (key: string, orgId: string, data: Partial<GuardrailPolicy>) =>
    apiFetch<GuardrailPolicy>(
      `/admin/v1/organizations/${orgId}/guardrails`,
      { method: 'POST', body: JSON.stringify(data) },
      key
    ),
  simulateGuardrails: (key: string, orgId: string, prompt: string, policy?: Partial<GuardrailPolicy>) =>
    apiFetch<{
      allowed: boolean;
      applied_action: string;
      violations: string[];
      redacted: boolean;
      redacted_prompt: string;
      error_message?: string;
    }>(
      `/admin/v1/organizations/${orgId}/guardrails/simulate`,
      { method: 'POST', body: JSON.stringify({ prompt, policy }) },
      key
    ),

  // MCP & A2A
  listMCPServers: (key: string) =>
    apiFetch<{ data: MCPServer[] }>('/admin/v1/mcp/servers', {}, key),
  syncMCPServer: (key: string, serverId: string) =>
    apiFetch<any>(`/admin/v1/mcp/servers/${serverId}/sync`, { method: 'POST' }, key),
  listMCPTools: (key: string) =>
    apiFetch<{ tools: any[] }>('/admin/v1/mcp/tools', {}, key),
  listA2AAgents: (key: string) =>
    apiFetch<{ data: A2AAgent[] }>('/admin/v1/a2a/agents', {}, key),
  setA2AKillSwitch: (key: string, agentId: string, killed: boolean) =>
    apiFetch<any>(`/admin/v1/a2a/agents/${agentId}/kill-switch`, { method: 'POST', body: JSON.stringify({ killed }) }, key),
};
