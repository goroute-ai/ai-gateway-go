import React, { useState } from 'react';
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { adminApi } from '../../api/admin';
import { useAuth } from '../../context/AuthContext';
import { Badge } from '../../components/common/Badge';
import { ErrorAlert } from '../../components/common/ErrorAlert';
import { Modal, INPUT_CLS, BTN_PRIMARY, BTN_CANCEL } from '../../components/common/Modal';
import type {
  GuardrailDefinition,
  GuardrailDefinitionWriteRequest,
  GuardrailHook,
  GuardrailModeRule,
  GuardrailStatus,
  StreamScope,
} from '../../types';
import {
  Plus,
  Search,
  Lock,
  ShieldCheck,
  CheckCircle2,
  XCircle,
  Clock,
  Trash2,
  Settings,
  Key,
  Layers,
} from 'lucide-react';

const HOOKS: readonly GuardrailHook[] = [
  'pre_call',
  'during_call',
  'post_call',
  'logging_only',
  'pre_mcp_call',
  'during_mcp_call',
  'post_mcp_call',
];

const STREAM_SCOPES: readonly StreamScope[] = ['both', 'streaming', 'non_streaming'];

const STARLARK_SAMPLE = `def apply_guardrail(inputs, request_data, input_type):
    texts = inputs.get("texts", [])
    for t in texts:
        if "forbidden_token" in t.lower():
            return {"decision": "block", "reason": "Blocked by custom Starlark policy"}
    return {"decision": "allow"}
`;

interface ProviderPreset {
  id: string;
  label: string;
  secretsHint?: string;
  defaultConfig: Record<string, any>;
}

const PROVIDERS: readonly ProviderPreset[] = [
  { id: 'local_content_filter', label: 'Local Content Filter', defaultConfig: { action: 'block', categories: ['harm_toxic_abuse'], blocked_words: [], case_sensitive: false } },
  { id: 'custom_code', label: 'Custom Code (Starlark)', defaultConfig: { custom_code: STARLARK_SAMPLE, allow_http: false, max_execution_steps: 50000 } },
  { id: 'llm_as_a_judge', label: 'LLM as a Judge', defaultConfig: { model: 'gpt-4o-mini', threshold: 0.7, threshold_direction: 'gte', system_prompt: 'Evaluate safety from 0.0 to 1.0.' } },
  { id: 'decision_model', label: 'Decision Model', defaultConfig: { model: 'gpt-4o-mini', all_must_pass: true, checks: [{ name: 'policy_safe', prompt: 'Is the content safe?' }] } },
  { id: 'openai_moderation', label: 'OpenAI Moderation', secretsHint: 'api_key', defaultConfig: { model: 'omni-moderation-latest', threshold: 0.7 } },
  { id: 'bedrock', label: 'AWS Bedrock Guardrails', secretsHint: 'aws_region, aws_access_key_id, aws_secret_access_key', defaultConfig: { guardrail_id: '', guardrail_version: 'DRAFT', action: 'block' } },
  { id: 'azure/prompt_shield', label: 'Azure Prompt Shield', secretsHint: 'api_key', defaultConfig: { api_base: '', api_version: '2024-09-01' } },
  { id: 'azure/text_moderations', label: 'Azure Text Moderations', secretsHint: 'api_key', defaultConfig: { api_base: '', api_version: '2024-09-01', severity_threshold: 4 } },
  { id: 'model_armor', label: 'Google Model Armor', secretsHint: 'credentials or bearer_token', defaultConfig: { project_id: '', location: 'us-central1', template_id: '' } },
  { id: 'presidio', label: 'Microsoft Presidio PII', secretsHint: 'api_key', defaultConfig: { analyzer_base_url: 'http://localhost:5001', anonymizer_base_url: 'http://localhost:5002', language: 'en', score_threshold: 0.5 } },
  { id: 'lakera_v2', label: 'Lakera Guard v2', secretsHint: 'api_key', defaultConfig: { base_url: 'https://api.lakera.ai', project_id: '', payload: true, breakdown: true } },
  { id: 'guardrails_ai', label: 'Guardrails AI Server', secretsHint: 'api_key', defaultConfig: { base_url: 'http://localhost:8000', guard_name: '', num_reasks: 0 } },
  { id: 'pangea', label: 'Pangea AI Guard', secretsHint: 'api_key', defaultConfig: { domain: 'aws.us.pangea.cloud', recipe: 'pangea_prompt_guard' } },
  { id: 'generic_http', label: 'Generic HTTP Webhook', secretsHint: 'authorization or header secrets', defaultConfig: { url: 'https://guardrail.example.com/check', method: 'POST', redact_auth_headers: true } },
  { id: 'tool_permission', label: 'Tool Permission', defaultConfig: { default_policy: 'allow', rules: [] } },
  { id: 'tool_policy', label: 'Tool Trust Policy Driver', defaultConfig: { enforce_input: true, enforce_output: true } },
  { id: 'block_code_execution', label: 'Block Code Execution', defaultConfig: { action: 'block', detect_fenced_code: false, blocked_tools: ['bash', 'shell', 'python'] } },
  { id: 'mcp_security', label: 'MCP Security', defaultConfig: { action: 'block', require_registered_server: true } },
  { id: 'mcp_end_user_permission', label: 'MCP End-User RBAC', defaultConfig: { default_policy: 'deny', rules: [] } },
];

const statusVariant = (st: GuardrailStatus) =>
  st === 'active' ? 'success' : st === 'rejected' ? 'danger' : 'warning';

const parseJsonSafe = (raw: string, label: string): Record<string, any> | undefined => {
  const t = raw.trim();
  if (!t) return undefined;
  const parsed = JSON.parse(t);
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    throw new Error(`${label} must be a JSON object`);
  }
  return parsed;
};

export const RegistryTab: React.FC = () => {
  const { adminKey, activeOrgId } = useAuth();
  const qc = useQueryClient();

  const [statusFilter, setStatusFilter] = useState<string>('');
  const [search, setSearch] = useState('');
  const [formOpen, setFormOpen] = useState(false);
  const [editing, setEditing] = useState<GuardrailDefinition | null>(null);
  const [formErr, setFormErr] = useState<string | null>(null);

  // Definition form state
  const [name, setName] = useState('');
  const [provider, setProvider] = useState<string>('local_content_filter');
  const [status, setStatus] = useState<GuardrailStatus>('active');
  const [eventHooks, setEventHooks] = useState<GuardrailHook[]>(['pre_call']);
  const [streamScope, setStreamScope] = useState<StreamScope>('both');
  const [defaultOn, setDefaultOn] = useState(false);
  const [failOpen, setFailOpen] = useState(false);
  const [weight, setWeight] = useState('1');
  const [precedence, setPrecedence] = useState('0');
  const [timeoutMs, setTimeoutMs] = useState('0');
  const [enabledRolesText, setEnabledRolesText] = useState('');
  const [modeRuleDefault, setModeRuleDefault] = useState<GuardrailHook[]>([]);
  const [modeRuleTags, setModeRuleTags] = useState<Array<{ tag: string; hooks: GuardrailHook[] }>>([]);
  const [newRuleTag, setNewRuleTag] = useState('');
  const [starlarkCode, setStarlarkCode] = useState(STARLARK_SAMPLE);
  const [configJson, setConfigJson] = useState(JSON.stringify(PROVIDERS[0].defaultConfig, null, 2));
  const [secretsJson, setSecretsJson] = useState('');
  const [clearSecrets, setClearSecrets] = useState(false);
  const [infoJson, setInfoJson] = useState('');

  // Binding form state
  const [bindOpen, setBindOpen] = useState(false);
  const [bindGuardrailId, setBindGuardrailId] = useState('');
  const [bindTeamId, setBindTeamId] = useState('');
  const [bindKeyId, setBindKeyId] = useState('');
  const [bindEndUserId, setBindEndUserId] = useState('');
  const [bindModelGroupId, setBindModelGroupId] = useState('');
  const [bindTag, setBindTag] = useState('');
  const [bindLocked, setBindLocked] = useState(false);
  const [bindOverridesJson, setBindOverridesJson] = useState('');
  const [bindErr, setBindErr] = useState<string | null>(null);

  const defsQuery = useQuery({
    queryKey: ['admin', 'guardrail-definitions', adminKey, activeOrgId, statusFilter],
    queryFn: () =>
      adminApi.listGuardrailDefinitions(adminKey, activeOrgId, statusFilter ? { status: statusFilter } : undefined),
    enabled: !!adminKey && !!activeOrgId,
  });

  const bindingsQuery = useQuery({
    queryKey: ['admin', 'guardrail-bindings', adminKey, activeOrgId],
    queryFn: () => adminApi.listGuardrailBindings(adminKey, activeOrgId),
    enabled: !!adminKey && !!activeOrgId,
  });

  const teamsQuery = useQuery({
    queryKey: ['admin', 'teams', adminKey, activeOrgId],
    queryFn: () => adminApi.listTeams(adminKey, activeOrgId),
    enabled: !!adminKey && !!activeOrgId,
  });

  const keysQuery = useQuery({
    queryKey: ['admin', 'keys', adminKey, activeOrgId],
    queryFn: () => adminApi.listKeys(adminKey, activeOrgId),
    enabled: !!adminKey && !!activeOrgId,
  });

  const invalidateAll = () => {
    qc.invalidateQueries({ queryKey: ['admin', 'guardrail-definitions', adminKey, activeOrgId] });
    qc.invalidateQueries({ queryKey: ['admin', 'guardrail-bindings', adminKey, activeOrgId] });
  };

  const saveDefMut = useMutation({
    mutationFn: (payload: GuardrailDefinitionWriteRequest) =>
      editing
        ? adminApi.updateGuardrailDefinition(adminKey, editing.id, payload)
        : adminApi.createGuardrailDefinition(adminKey, activeOrgId, payload),
    onSuccess: () => {
      setFormOpen(false);
      invalidateAll();
    },
    onError: (err: any) => setFormErr(err?.message || 'Failed to save guardrail definition'),
  });

  const statusMut = useMutation({
    mutationFn: ({ id, next }: { id: string; next: GuardrailStatus }) =>
      adminApi.setGuardrailDefinitionStatus(adminKey, id, next),
    onSuccess: invalidateAll,
  });

  const deleteDefMut = useMutation({
    mutationFn: (id: string) => adminApi.deleteGuardrailDefinition(adminKey, id),
    onSuccess: invalidateAll,
  });

  const createBindMut = useMutation({
    mutationFn: (payload: any) => adminApi.createGuardrailBinding(adminKey, payload),
    onSuccess: () => {
      setBindOpen(false);
      invalidateAll();
    },
    onError: (err: any) => setBindErr(err?.message || 'Failed to create binding'),
  });

  const deleteBindMut = useMutation({
    mutationFn: (id: string) => adminApi.deleteGuardrailBinding(adminKey, id),
    onSuccess: invalidateAll,
  });

  const openCreate = () => {
    setEditing(null);
    setFormErr(null);
    setName('');
    setProvider('local_content_filter');
    setStatus('active');
    setEventHooks(['pre_call']);
    setStreamScope('both');
    setDefaultOn(false);
    setFailOpen(false);
    setWeight('1');
    setPrecedence('0');
    setTimeoutMs('0');
    setEnabledRolesText('');
    setModeRuleDefault([]);
    setModeRuleTags([]);
    setNewRuleTag('');
    setStarlarkCode(STARLARK_SAMPLE);
    setConfigJson(JSON.stringify(PROVIDERS[0].defaultConfig, null, 2));
    setSecretsJson('');
    setClearSecrets(false);
    setInfoJson('');
    setFormOpen(true);
  };

  const openEdit = (def: GuardrailDefinition) => {
    setEditing(def);
    setFormErr(null);
    setName(def.name);
    setProvider(def.provider);
    setStatus(def.status);
    setEventHooks(def.event_hooks || []);
    setStreamScope(def.stream_scope || 'both');
    setDefaultOn(def.default_on);
    setFailOpen(def.fail_open);
    setWeight(String(def.weight || 1));
    setPrecedence(String(def.precedence || 0));
    setTimeoutMs(String(def.timeout_ms || 0));
    setEnabledRolesText((def.enabled_roles || []).join(', '));
    setModeRuleDefault(def.mode_rule?.default || []);
    setModeRuleTags(
      def.mode_rule?.tags
        ? Object.entries(def.mode_rule.tags).map(([tag, hooks]) => ({ tag, hooks }))
        : []
    );
    setNewRuleTag('');
    const cfg = def.config || {};
    setStarlarkCode(cfg.custom_code || cfg.code || cfg.script || STARLARK_SAMPLE);
    setConfigJson(Object.keys(cfg).length ? JSON.stringify(cfg, null, 2) : '{}');
    setSecretsJson('');
    setClearSecrets(false);
    setInfoJson(def.guardrail_info ? JSON.stringify(def.guardrail_info, null, 2) : '');
    setFormOpen(true);
  };

  const handleProviderChange = (nextProv: string) => {
    setProvider(nextProv);
    if (!editing) {
      const preset = PROVIDERS.find((p) => p.id === nextProv);
      if (preset) {
        setConfigJson(JSON.stringify(preset.defaultConfig, null, 2));
        if (nextProv === 'custom_code') {
          setStarlarkCode(preset.defaultConfig.custom_code || STARLARK_SAMPLE);
        }
      }
    }
  };

  const toggleHook = (list: GuardrailHook[], hook: GuardrailHook): GuardrailHook[] =>
    list.includes(hook) ? list.filter((h) => h !== hook) : [...list, hook];

  const handleSaveDef = (e: React.FormEvent) => {
    e.preventDefault();
    setFormErr(null);
    if (!name.trim()) {
      setFormErr('Name is required');
      return;
    }
    try {
      const cfg = parseJsonSafe(configJson, 'Config') || {};
      if (provider === 'custom_code') {
        cfg.custom_code = starlarkCode;
      }
      const secrets = parseJsonSafe(secretsJson, 'Secrets');
      const guardrailInfo = parseJsonSafe(infoJson, 'Guardrail info');
      const roles = enabledRolesText
        .split(',')
        .map((r) => r.trim())
        .filter(Boolean);

      const tagMap: Record<string, GuardrailHook[]> = {};
      for (const row of modeRuleTags) {
        if (row.tag.trim() && row.hooks.length > 0) {
          tagMap[row.tag.trim()] = row.hooks;
        }
      }
      const modeRule: GuardrailModeRule | undefined =
        Object.keys(tagMap).length > 0 || modeRuleDefault.length > 0
          ? {
              ...(Object.keys(tagMap).length > 0 ? { tags: tagMap } : {}),
              ...(modeRuleDefault.length > 0 ? { default: modeRuleDefault } : {}),
            }
          : undefined;

      saveDefMut.mutate({
        name: name.trim(),
        provider,
        status,
        event_hooks: eventHooks,
        stream_scope: streamScope,
        mode_rule: modeRule,
        default_on: defaultOn,
        fail_open: failOpen,
        weight: Math.max(1, parseInt(weight, 10) || 1),
        precedence: parseInt(precedence, 10) || 0,
        timeout_ms: Math.max(0, parseInt(timeoutMs, 10) || 0),
        enabled_roles: roles.length > 0 ? roles : undefined,
        config: cfg,
        ...(secrets && Object.keys(secrets).length > 0 ? { secrets } : {}),
        ...(clearSecrets ? { clear_secrets: true } : {}),
        ...(guardrailInfo ? { guardrail_info: guardrailInfo } : {}),
      });
    } catch (err: any) {
      setFormErr(err?.message || 'Invalid JSON configuration');
    }
  };

  const openCreateBinding = (defId?: string) => {
    setBindErr(null);
    setBindGuardrailId(defId || defs[0]?.id || '');
    setBindTeamId('');
    setBindKeyId('');
    setBindEndUserId('');
    setBindModelGroupId('');
    setBindTag('');
    setBindLocked(false);
    setBindOverridesJson('');
    setBindOpen(true);
  };

  const handleSaveBinding = (e: React.FormEvent) => {
    e.preventDefault();
    setBindErr(null);
    if (!bindGuardrailId) {
      setBindErr('Select a guardrail definition');
      return;
    }
    try {
      const overrides = parseJsonSafe(bindOverridesJson, 'Param overrides');
      createBindMut.mutate({
        org_id: activeOrgId,
        guardrail_id: bindGuardrailId,
        ...(bindTeamId ? { team_id: bindTeamId } : {}),
        ...(bindKeyId ? { virtual_key_id: bindKeyId } : {}),
        ...(bindEndUserId.trim() ? { end_user_id: bindEndUserId.trim() } : {}),
        ...(bindModelGroupId.trim() ? { model_group_id: bindModelGroupId.trim() } : {}),
        ...(bindTag.trim() ? { tag: bindTag.trim() } : {}),
        ...(overrides ? { param_overrides: overrides } : {}),
        is_locked: bindLocked,
      });
    } catch (err: any) {
      setBindErr(err?.message || 'Invalid param overrides JSON');
    }
  };

  const defs = defsQuery.data?.data || [];
  const filteredDefs = defs.filter((d) => {
    if (!search.trim()) return true;
    const q = search.toLowerCase();
    return d.name.toLowerCase().includes(q) || d.provider.toLowerCase().includes(q);
  });
  const bindings = bindingsQuery.data?.data || [];
  const teams = teamsQuery.data?.data || [];
  const keys = keysQuery.data?.data || [];
  const activePreset = PROVIDERS.find((p) => p.id === provider);

  return (
    <div className="space-y-6">
      {/* Guardrail Definitions Header & Filter Bar */}
      <div className="bg-surface-base border border-subtle rounded-lg p-5 space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div>
            <h3 className="text-xs font-mono uppercase tracking-wider text-zinc-300 flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-accent-primary" />
              Named Guardrails & Provider Registry ({defs.length})
            </h3>
            <p className="text-[11px] text-zinc-400 mt-0.5">
              19 built-in cloud, OSS, Starlark sandbox, MCP, and LLM-judge drivers with Vault-encrypted secrets and weighted routing.
            </p>
          </div>
          <button onClick={openCreate} className={`${BTN_PRIMARY} flex items-center gap-1.5`}>
            <Plus className="w-3.5 h-3.5" />
            New Guardrail
          </button>
        </div>

        <div className="flex flex-col sm:flex-row gap-2">
          <div className="relative flex-1">
            <Search className="w-3.5 h-3.5 text-zinc-500 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Filter by guardrail name or provider..."
              className={`${INPUT_CLS} pl-8`}
            />
          </div>
          <div className="flex gap-1.5">
            {(['', 'active', 'pending_review', 'rejected'] as const).map((st) => (
              <button
                key={st || 'all'}
                type="button"
                onClick={() => setStatusFilter(st)}
                className={`px-2.5 py-1.5 rounded text-[11px] font-mono border transition ${
                  statusFilter === st
                    ? 'bg-accent-primary/20 text-accent-primary border-accent-primary/40 font-semibold'
                    : 'bg-surface-elevated text-zinc-400 border-subtle hover:text-zinc-200'
                }`}
              >
                {st || 'all'}
              </button>
            ))}
          </div>
        </div>

        {defsQuery.isError && (
          <ErrorAlert error={defsQuery.error} title="Failed to load guardrail definitions" onRetry={() => defsQuery.refetch()} />
        )}

        {defsQuery.isLoading ? (
          <div className="py-8 text-center text-xs font-mono text-zinc-500">Loading guardrail registry...</div>
        ) : filteredDefs.length === 0 ? (
          <div className="py-8 text-center text-xs font-mono text-zinc-500 border border-subtle rounded-lg">
            No named guardrails found. Create one to enable multi-driver pipelines.
          </div>
        ) : (
          <div className="space-y-3">
            {filteredDefs.map((def) => (
              <div key={def.id} className="p-4 bg-surface-elevated/40 border border-subtle rounded-lg space-y-2.5">
                <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                  <div className="flex flex-wrap items-center gap-2">
                    <span className="text-sm font-semibold text-zinc-100 font-mono">{def.name}</span>
                    <Badge variant="info" size="sm">{def.provider}</Badge>
                    <Badge variant={statusVariant(def.status)} size="sm">{def.status}</Badge>
                    {def.default_on && <Badge variant="primary" size="sm">default_on</Badge>}
                    {def.fail_open && <Badge variant="warning" size="sm">fail_open</Badge>}
                    {def.has_secrets && (
                      <Badge variant="success" size="sm">
                        <span className="flex items-center gap-1"><Key className="w-3 h-3" /> vault</span>
                      </Badge>
                    )}
                  </div>
                  <div className="flex items-center gap-1.5 text-[11px] font-mono">
                    {def.status !== 'active' && (
                      <button
                        type="button"
                        onClick={() => statusMut.mutate({ id: def.id, next: 'active' })}
                        className="px-2 py-1 rounded bg-emerald-950/60 text-emerald-400 border border-emerald-500/30 hover:text-white flex items-center gap-1"
                      >
                        <CheckCircle2 className="w-3 h-3" /> Activate
                      </button>
                    )}
                    {def.status !== 'pending_review' && (
                      <button
                        type="button"
                        onClick={() => statusMut.mutate({ id: def.id, next: 'pending_review' })}
                        className="px-2 py-1 rounded bg-amber-950/60 text-amber-400 border border-amber-500/30 flex items-center gap-1"
                      >
                        <Clock className="w-3 h-3" /> Review
                      </button>
                    )}
                    {def.status !== 'rejected' && (
                      <button
                        type="button"
                        onClick={() => statusMut.mutate({ id: def.id, next: 'rejected' })}
                        className="px-2 py-1 rounded bg-rose-500/20 text-rose-400 border border-rose-500/30 flex items-center gap-1"
                      >
                        <XCircle className="w-3 h-3" /> Reject
                      </button>
                    )}
                    <button
                      type="button"
                      onClick={() => openCreateBinding(def.id)}
                      className="px-2 py-1 rounded bg-surface-base border border-subtle text-zinc-300 hover:text-white flex items-center gap-1"
                    >
                      <Layers className="w-3 h-3" /> Bind
                    </button>
                    <button
                      type="button"
                      onClick={() => openEdit(def)}
                      className="px-2 py-1 rounded bg-surface-base border border-subtle text-zinc-300 hover:text-white flex items-center gap-1"
                    >
                      <Settings className="w-3 h-3" /> Edit
                    </button>
                    <button
                      type="button"
                      onClick={() => deleteDefMut.mutate(def.id)}
                      className="p-1.5 rounded bg-surface-base border border-subtle text-zinc-400 hover:text-rose-400"
                      title="Delete guardrail"
                    >
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                </div>

                <div className="flex flex-wrap gap-3 text-[11px] font-mono text-zinc-400">
                  <span>id: <code className="text-zinc-300">{def.id}</code></span>
                  <span>weight: <strong className="text-zinc-200">{def.weight}</strong></span>
                  <span>precedence: <strong className="text-zinc-200">{def.precedence}</strong></span>
                  <span>stream: <strong className="text-zinc-200">{def.stream_scope || 'both'}</strong></span>
                  {def.timeout_ms ? <span>timeout: <strong className="text-zinc-200">{def.timeout_ms}ms</strong></span> : null}
                  {def.enabled_roles?.length ? <span>roles: <strong className="text-zinc-200">{def.enabled_roles.join(', ')}</strong></span> : null}
                </div>

                {(def.event_hooks?.length || def.mode_rule) && (
                  <div className="flex flex-wrap gap-1.5 pt-1">
                    {(def.event_hooks || []).map((h) => (
                      <span key={h} className="px-2 py-0.5 rounded bg-zinc-800 border border-subtle text-zinc-300 text-[10px] font-mono">
                        {h}
                      </span>
                    ))}
                    {def.mode_rule?.tags &&
                      Object.entries(def.mode_rule.tags).map(([tag, th]) => (
                        <span key={tag} className="px-2 py-0.5 rounded bg-accent-soft border border-accent-primary/30 text-accent-primary text-[10px] font-mono">
                          tag:{tag} → {th.join(',')}
                        </span>
                      ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Hierarchical Guardrail Bindings */}
      <div className="bg-surface-base border border-subtle rounded-lg p-5 space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h3 className="text-xs font-mono uppercase tracking-wider text-zinc-300 flex items-center gap-2">
              <Lock className="w-4 h-4 text-accent-primary" />
              Hierarchical Guardrail Bindings ({bindings.length})
            </h3>
            <p className="text-[11px] text-zinc-400 mt-0.5">
              Attach named guardrails to Teams, Virtual Keys, End Users, Model Groups, or Tags. Locked bindings cannot be disabled per-request.
            </p>
          </div>
          <button
            type="button"
            onClick={() => openCreateBinding()}
            disabled={defs.length === 0}
            className="px-3 py-1.5 bg-surface-elevated hover:bg-surface-hover border border-subtle text-zinc-200 rounded text-xs font-mono flex items-center gap-1 disabled:opacity-40"
          >
            <Plus className="w-3.5 h-3.5" /> Add Binding
          </button>
        </div>

        {bindings.length === 0 ? (
          <div className="py-6 text-center text-xs font-mono text-zinc-500 border border-subtle rounded-lg">
            No scoped bindings configured. Guardrails with default_on apply org-wide.
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs font-mono">
              <thead>
                <tr className="border-b border-subtle text-zinc-500 text-[11px] uppercase">
                  <th className="py-2 pr-3">Guardrail</th>
                  <th className="py-2 pr-3">Scope Targets</th>
                  <th className="py-2 pr-3">Lock</th>
                  <th className="py-2 text-right">Action</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-subtle">
                {bindings.map((b) => (
                  <tr key={b.id} className="text-zinc-300">
                    <td className="py-2.5 pr-3 font-semibold text-zinc-100">{b.guardrail_name || b.guardrail_id}</td>
                    <td className="py-2.5 pr-3">
                      <div className="flex flex-wrap gap-1.5">
                        {b.team_id && <Badge variant="neutral" size="sm">team:{b.team_id}</Badge>}
                        {b.virtual_key_id && <Badge variant="info" size="sm">key:{b.virtual_key_id}</Badge>}
                        {b.end_user_id && <Badge variant="neutral" size="sm">user:{b.end_user_id}</Badge>}
                        {b.model_group_id && <Badge variant="neutral" size="sm">group:{b.model_group_id}</Badge>}
                        {b.tag && <Badge variant="primary" size="sm">tag:{b.tag}</Badge>}
                        {!b.team_id && !b.virtual_key_id && !b.end_user_id && !b.model_group_id && !b.tag && (
                          <span className="text-zinc-500">org-wide</span>
                        )}
                      </div>
                    </td>
                    <td className="py-2.5 pr-3">
                      {b.is_locked ? <Badge variant="warning" size="sm">LOCKED</Badge> : <span className="text-zinc-500">optional</span>}
                    </td>
                    <td className="py-2.5 text-right">
                      <button
                        type="button"
                        onClick={() => deleteBindMut.mutate(b.id)}
                        className="p-1 text-zinc-400 hover:text-rose-400"
                        title="Delete binding"
                      >
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Create / Edit Guardrail Definition Modal */}
      <Modal
        isOpen={formOpen}
        onClose={() => setFormOpen(false)}
        title={editing ? `Edit Guardrail: ${editing.name}` : 'Create Named Guardrail'}
        description="Configure driver provider, execution hooks, stream scope, ModeRule tag matrix, and Vault secrets."
        size="2xl"
      >
        <form onSubmit={handleSaveDef} className="space-y-4 text-xs">
          {formErr && <ErrorAlert error={formErr} title="Validation error" />}

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <label className="text-[11px] text-zinc-400 font-mono block mb-1">Guardrail Name *</label>
              <input value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. prod-pii-presidio" className={INPUT_CLS} required />
            </div>
            <div>
              <label className="text-[11px] text-zinc-400 font-mono block mb-1">Provider (19 Drivers) *</label>
              <select value={provider} onChange={(e) => handleProviderChange(e.target.value)} className={INPUT_CLS}>
                {PROVIDERS.map((p) => (
                  <option key={p.id} value={p.id}>{p.label} ({p.id})</option>
                ))}
              </select>
            </div>
          </div>

          <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
            <div>
              <label className="text-[11px] text-zinc-400 font-mono block mb-1">Status</label>
              <select value={status} onChange={(e) => setStatus(e.target.value as GuardrailStatus)} className={INPUT_CLS}>
                <option value="active">active</option>
                <option value="pending_review">pending_review</option>
                <option value="rejected">rejected</option>
              </select>
            </div>
            <div>
              <label className="text-[11px] text-zinc-400 font-mono block mb-1">Stream Scope</label>
              <select value={streamScope} onChange={(e) => setStreamScope(e.target.value as StreamScope)} className={INPUT_CLS}>
                {STREAM_SCOPES.map((sc) => (
                  <option key={sc} value={sc}>{sc}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="text-[11px] text-zinc-400 font-mono block mb-1">Weight</label>
              <input type="number" min={1} value={weight} onChange={(e) => setWeight(e.target.value)} className={INPUT_CLS} />
            </div>
            <div>
              <label className="text-[11px] text-zinc-400 font-mono block mb-1">Precedence</label>
              <input type="number" value={precedence} onChange={(e) => setPrecedence(e.target.value)} className={INPUT_CLS} />
            </div>
            <div>
              <label className="text-[11px] text-zinc-400 font-mono block mb-1">Timeout (ms)</label>
              <input type="number" min={0} value={timeoutMs} onChange={(e) => setTimeoutMs(e.target.value)} className={INPUT_CLS} />
            </div>
          </div>

          <div className="flex flex-wrap gap-5 items-center">
            <label className="flex items-center gap-2 text-zinc-300 font-mono cursor-pointer">
              <input type="checkbox" checked={defaultOn} onChange={(e) => setDefaultOn(e.target.checked)} />
              default_on (apply org-wide unless opted out)
            </label>
            <label className="flex items-center gap-2 text-zinc-300 font-mono cursor-pointer">
              <input type="checkbox" checked={failOpen} onChange={(e) => setFailOpen(e.target.checked)} />
              fail_open (flag instead of block on driver error)
            </label>
          </div>

          <div>
            <label className="text-[11px] text-zinc-400 font-mono block mb-1.5">Event Hooks</label>
            <div className="flex flex-wrap gap-1.5">
              {HOOKS.map((h) => (
                <button
                  key={h}
                  type="button"
                  onClick={() => setEventHooks(toggleHook(eventHooks, h))}
                  className={`px-2 py-1 rounded text-[11px] font-mono border transition ${
                    eventHooks.includes(h)
                      ? 'bg-accent-primary/20 text-accent-primary border-accent-primary/40 font-semibold'
                      : 'bg-surface-elevated text-zinc-400 border-subtle'
                  }`}
                >
                  {h}
                </button>
              ))}
            </div>
          </div>

          <div>
            <label className="text-[11px] text-zinc-400 font-mono block mb-1">Enabled Roles (comma-separated, empty = all roles)</label>
            <input value={enabledRolesText} onChange={(e) => setEnabledRolesText(e.target.value)} placeholder="e.g. *, org_admin, developer" className={INPUT_CLS} />
          </div>

          {/* ModeRule Tag -> Hook Matrix */}
          <div className="p-3 bg-surface-elevated/40 border border-subtle rounded-lg space-y-2.5">
            <div className="text-[11px] font-mono text-zinc-300 font-semibold">ModeRule: Tag → Hook Routing Matrix</div>
            <div>
              <span className="text-[10px] text-zinc-400 font-mono block mb-1">Default fallback hooks:</span>
              <div className="flex flex-wrap gap-1">
                {HOOKS.map((h) => (
                  <button
                    key={h}
                    type="button"
                    onClick={() => setModeRuleDefault(toggleHook(modeRuleDefault, h))}
                    className={`px-1.5 py-0.5 rounded text-[10px] font-mono border ${
                      modeRuleDefault.includes(h)
                        ? 'bg-accent-primary/20 text-accent-primary border-accent-primary/40'
                        : 'bg-surface-base text-zinc-500 border-subtle'
                    }`}
                  >
                    {h}
                  </button>
                ))}
              </div>
            </div>

            {modeRuleTags.map((row, idx) => (
              <div key={idx} className="flex flex-wrap items-center gap-1.5 pt-1 border-t border-subtle">
                <span className="px-2 py-0.5 rounded bg-zinc-800 text-zinc-200 font-mono text-[10px]">{row.tag}</span>
                {HOOKS.map((h) => (
                  <button
                    key={h}
                    type="button"
                    onClick={() =>
                      setModeRuleTags(
                        modeRuleTags.map((r, i) => (i === idx ? { ...r, hooks: toggleHook(r.hooks, h) } : r))
                      )
                    }
                    className={`px-1.5 py-0.5 rounded text-[10px] font-mono border ${
                      row.hooks.includes(h)
                        ? 'bg-emerald-950/60 text-emerald-400 border-emerald-500/30'
                        : 'bg-surface-base text-zinc-500 border-subtle'
                    }`}
                  >
                    {h}
                  </button>
                ))}
                <button
                  type="button"
                  onClick={() => setModeRuleTags(modeRuleTags.filter((_, i) => i !== idx))}
                  className="text-rose-400 text-[10px] font-mono ml-auto"
                >
                  remove
                </button>
              </div>
            ))}

            <div className="flex gap-2">
              <input
                value={newRuleTag}
                onChange={(e) => setNewRuleTag(e.target.value)}
                placeholder="Add request tag (e.g. prod, mcp-strict)..."
                className={INPUT_CLS}
              />
              <button
                type="button"
                onClick={() => {
                  const t = newRuleTag.trim();
                  if (t && !modeRuleTags.some((r) => r.tag === t)) {
                    setModeRuleTags([...modeRuleTags, { tag: t, hooks: ['pre_call'] }]);
                    setNewRuleTag('');
                  }
                }}
                className="px-3 py-1.5 bg-surface-base border border-subtle rounded text-zinc-300 hover:text-white font-mono whitespace-nowrap"
              >
                + Tag Rule
              </button>
            </div>
          </div>

          {provider === 'custom_code' && (
            <div>
              <label className="text-[11px] text-accent-primary font-mono block mb-1">
                Starlark Script Editor (`apply_guardrail(inputs, request_data, input_type)`)
              </label>
              <textarea
                rows={7}
                value={starlarkCode}
                onChange={(e) => setStarlarkCode(e.target.value)}
                className={`${INPUT_CLS} font-mono`}
              />
            </div>
          )}

          <div>
            <label className="text-[11px] text-zinc-400 font-mono block mb-1">Driver Config (JSON)</label>
            <textarea
              rows={4}
              value={configJson}
              onChange={(e) => setConfigJson(e.target.value)}
              className={`${INPUT_CLS} font-mono`}
            />
          </div>

          <div className="p-3 bg-surface-elevated/40 border border-subtle rounded-lg space-y-2">
            <div className="flex items-center justify-between">
              <label className="text-[11px] text-zinc-300 font-mono flex items-center gap-1.5">
                <Key className="w-3.5 h-3.5 text-emerald-400" />
                Vault Secrets (Write-Only JSON{activePreset?.secretsHint ? ` — keys: ${activePreset.secretsHint}` : ''})
              </label>
              {editing?.has_secrets && <Badge variant="success" size="sm">Secrets Stored</Badge>}
            </div>
            <textarea
              rows={2}
              value={secretsJson}
              onChange={(e) => setSecretsJson(e.target.value)}
              placeholder='Leave blank to keep unchanged, or enter JSON e.g. {"api_key": "..."}'
              className={`${INPUT_CLS} font-mono`}
            />
            {editing?.has_secrets && (
              <label className="flex items-center gap-2 text-[11px] text-rose-300 font-mono cursor-pointer">
                <input type="checkbox" checked={clearSecrets} onChange={(e) => setClearSecrets(e.target.checked)} />
                Clear stored Vault secrets on save
              </label>
            )}
          </div>

          <div>
            <label className="text-[11px] text-zinc-400 font-mono block mb-1">
              Billing & Info Metadata (optional JSON: usage_unit, cost_per_call_micros, cost_per_unit_micros)
            </label>
            <textarea
              rows={2}
              value={infoJson}
              onChange={(e) => setInfoJson(e.target.value)}
              placeholder='{"usage_unit": "call", "cost_per_call_micros": 100}'
              className={`${INPUT_CLS} font-mono`}
            />
          </div>

          <div className="flex justify-end gap-2 pt-2 border-t border-subtle">
            <button type="button" onClick={() => setFormOpen(false)} className={BTN_CANCEL}>Cancel</button>
            <button type="submit" disabled={saveDefMut.isPending} className={BTN_PRIMARY}>
              {saveDefMut.isPending ? 'Saving...' : editing ? 'Update Guardrail' : 'Create Guardrail'}
            </button>
          </div>
        </form>
      </Modal>

      {/* Create Guardrail Binding Modal */}
      <Modal
        isOpen={bindOpen}
        onClose={() => setBindOpen(false)}
        title="Create Guardrail Binding"
        description="Scope a named guardrail to a team, virtual key, end user, model group, or request tag."
        size="lg"
      >
        <form onSubmit={handleSaveBinding} className="space-y-3 text-xs">
          {bindErr && <ErrorAlert error={bindErr} title="Binding error" />}
          <div>
            <label className="text-[11px] text-zinc-400 font-mono block mb-1">Guardrail Definition *</label>
            <select value={bindGuardrailId} onChange={(e) => setBindGuardrailId(e.target.value)} className={INPUT_CLS} required>
              {defs.map((d) => (
                <option key={d.id} value={d.id}>{d.name} ({d.provider})</option>
              ))}
            </select>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <label className="text-[11px] text-zinc-400 font-mono block mb-1">Team Scope (optional)</label>
              <select value={bindTeamId} onChange={(e) => setBindTeamId(e.target.value)} className={INPUT_CLS}>
                <option value="">All Teams</option>
                {teams.map((t) => (
                  <option key={t.id} value={t.id}>{t.name} ({t.id})</option>
                ))}
              </select>
            </div>
            <div>
              <label className="text-[11px] text-zinc-400 font-mono block mb-1">Virtual Key Scope (optional)</label>
              <select value={bindKeyId} onChange={(e) => setBindKeyId(e.target.value)} className={INPUT_CLS}>
                <option value="">All Virtual Keys</option>
                {keys.map((k) => (
                  <option key={k.id} value={k.id}>{k.name} ({k.key_prefix})</option>
                ))}
              </select>
            </div>
          </div>

          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div>
              <label className="text-[11px] text-zinc-400 font-mono block mb-1">End User ID</label>
              <input value={bindEndUserId} onChange={(e) => setBindEndUserId(e.target.value)} placeholder="optional" className={INPUT_CLS} />
            </div>
            <div>
              <label className="text-[11px] text-zinc-400 font-mono block mb-1">Model Group ID</label>
              <input value={bindModelGroupId} onChange={(e) => setBindModelGroupId(e.target.value)} placeholder="optional" className={INPUT_CLS} />
            </div>
            <div>
              <label className="text-[11px] text-zinc-400 font-mono block mb-1">Tag</label>
              <input value={bindTag} onChange={(e) => setBindTag(e.target.value)} placeholder="e.g. prod" className={INPUT_CLS} />
            </div>
          </div>

          <div>
            <label className="text-[11px] text-zinc-400 font-mono block mb-1">Parameter Overrides (JSON, optional)</label>
            <textarea
              rows={2}
              value={bindOverridesJson}
              onChange={(e) => setBindOverridesJson(e.target.value)}
              placeholder='{"action": "block"}'
              className={`${INPUT_CLS} font-mono`}
            />
          </div>

          <label className="flex items-center gap-2 text-amber-300 font-mono cursor-pointer pt-1">
            <input type="checkbox" checked={bindLocked} onChange={(e) => setBindLocked(e.target.checked)} />
            Lock binding (`is_locked` — disallow downstream key/request opt-out)
          </label>

          <div className="flex justify-end gap-2 pt-2 border-t border-subtle">
            <button type="button" onClick={() => setBindOpen(false)} className={BTN_CANCEL}>Cancel</button>
            <button type="submit" disabled={createBindMut.isPending} className={BTN_PRIMARY}>
              {createBindMut.isPending ? 'Saving...' : 'Create Binding'}
            </button>
          </div>
        </form>
      </Modal>
    </div>
  );
};
