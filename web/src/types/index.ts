export type ProviderType =
  | 'openai'
  | 'anthropic'
  | 'groq'
  | 'openrouter'
  | string;

export type BudgetResetPeriod = 'daily' | 'monthly' | 'never';

export type KeyType = 'default' | 'llm_api' | 'management' | 'read_only' | 'service_account';

export type SelfServeBudgetPolicy = 'disabled' | 'lower_only' | 'ceiling';

export type OperatorRole = 'platform_admin' | 'org_admin' | 'org_viewer' | 'team_admin';

export interface OperatorContext {
  actor_id: string;
  impersonated_by_actor_id?: string;
  role: OperatorRole;
  org_id?: string;
  team_id?: string;
  auth_method: string;
  can_impersonate?: boolean;
  deprecated_key_revoke_at?: string;
  session_id?: string;
  csrf_token?: string;
}

export interface SSOProviderPublicInfo {
  id: string;
  display_name: string;
  type: string;
}

export interface AuthMeResponse {
  operator: OperatorContext;
  csrf_token?: string;
  user?: User;
}

export type Role =
  | 'platform_admin'
  | 'org_admin'
  | 'org_viewer'
  | 'team_admin'
  | 'developer'
  | 'service_account'
  | 'viewer';

export interface Organization {
  id: string;
  name: string;
  slug?: string;
  max_budget_micros?: number;
  temp_budget_increase_micros?: number;
  temp_budget_expires_at?: string;
  self_serve_budget_policy?: SelfServeBudgetPolicy;
  soft_budget_micros?: number;
  throttle_on_budget_exceeded?: boolean;
  budget_fallbacks?: Record<string, string[]>;
  spent_micros?: number;
  budget_reset_period?: BudgetResetPeriod;
  rpm_limit?: number;
  tpm_limit?: number;
  max_concurrent_requests?: number;
  enforce_guaranteed_throughput?: boolean;
  developer_self_serve_keys?: boolean;
  key_expiry_alert_days?: number[];
  lifecycle_webhook_url?: string;
  is_active: boolean;
  created_at?: string;
}

export interface Team {
  id: string;
  org_id: string;
  name: string;
  max_budget_micros?: number;
  temp_budget_increase_micros?: number;
  temp_budget_expires_at?: string;
  soft_budget_micros?: number;
  throttle_on_budget_exceeded?: boolean;
  budget_fallbacks?: Record<string, string[]>;
  spent_micros?: number;
  budget_reset_period?: BudgetResetPeriod;
  rpm_limit?: number;
  tpm_limit?: number;
  max_concurrent_requests?: number;
  enforce_guaranteed_throughput?: boolean;
  default_member_max_budget_micros?: number;
  default_member_rpm_limit?: number;
  default_member_tpm_limit?: number;
  default_member_allowed_models?: string[];
  team_member_permissions?: string[];
  allowed_models?: string[];
  allowed_mcp_servers?: string[] | null;
  allowed_a2a_agents?: string[] | null;
  allowed_client_apps?: string[] | null;
  min_priority_rank?: number;
  allowed_routing_tags?: string[];
  is_active: boolean;
  created_at?: string;
}

export interface OrgProviderSubscription {
  org_id: string;
  provider: ProviderType;
  is_enabled: boolean;
  auto_enable_new: boolean;
  subscribed_at: string;
}

export interface OrgModelPolicy {
  org_id: string;
  global_model_id: string;
  is_enabled: boolean;
  approved_by: string;
  approved_at: string;
}

export interface User {
  id: string;
  org_id: string;
  team_id?: string;
  email: string;
  name?: string;
  oidc_issuer?: string;
  oidc_subject?: string;
  scim_active?: boolean;
  role: Role;
  max_budget_micros?: number;
  temp_budget_increase_micros?: number;
  temp_budget_expires_at?: string;
  soft_budget_micros?: number;
  throttle_on_budget_exceeded?: boolean;
  budget_fallbacks?: Record<string, string[]>;
  spent_micros?: number;
  budget_reset_period?: BudgetResetPeriod;
  rpm_limit?: number;
  tpm_limit?: number;
  max_concurrent_requests?: number;
  is_active: boolean;
  created_at?: string;
  updated_at?: string;
}

export interface VirtualKey {
  id: string;
  org_id: string;
  team_id?: string;
  project_id?: string;
  user_id?: string;
  name: string;
  key_prefix: string;
  raw_key?: string; // Only returned on creation or rotation
  role?: Role;
  key_type?: KeyType;
  max_budget_micros?: number;
  temp_budget_increase_micros?: number;
  temp_budget_expires_at?: string;
  soft_budget_micros?: number;
  throttle_on_budget_exceeded?: boolean;
  budget_fallbacks?: Record<string, string[]>;
  spent_micros?: number;
  budget_reset_period?: BudgetResetPeriod;
  rpm_limit?: number;
  tpm_limit?: number;
  max_concurrent_requests?: number;
  min_priority_rank?: number;
  allowed_routing_tags?: string[];
  batch_enqueued_token_limit?: number;
  rotation_interval_sec?: number;
  key_rotation_at?: string;
  allowed_models?: string[];
  allowed_endpoints?: string[];
  allowed_mcp_servers?: string[] | null;
  allowed_a2a_agents?: string[] | null;
  allowed_client_apps?: string[] | null;
  expires_at?: string;
  can_impersonate?: boolean;
  deprecated_key_revoke_at?: string;
  is_active: boolean;
  created_at: string;
}

export interface ProviderCredential {
  id: string;
  org_id: string;
  provider: ProviderType;
  name: string;
  base_url?: string;
  key_version: number;
  headers?: Record<string, string>;
  is_active: boolean;
  expires_at?: string;
  last_rotated_at?: string;
  last_validated_at?: string;
  created_at: string;
}

export interface CredentialValidationResult {
  id?: string;
  provider?: ProviderType;
  valid: boolean;
  validation_status?: string;
  error?: string;
  reason?: string;
  latency_ms?: number;
  discovered_models?: number;
  last_validated_at?: string;
}

export interface ModelCapabilities {
  tools?: 'supported' | 'unsupported' | 'unknown';
  streaming?: 'supported' | 'unsupported' | 'unknown';
  vision?: 'supported' | 'unsupported' | 'unknown';
  reasoning?: 'supported' | 'unsupported' | 'unknown';
  structured_outputs?: 'supported' | 'unsupported' | 'unknown';
  embeddings?: 'supported' | 'unsupported' | 'unknown';
}

export interface GlobalModel {
  id: string;
  provider: ProviderType;
  model_name: string;
  display_name: string;
  max_input_tokens?: number;
  max_output_tokens?: number;
  input_cost_micros_per_1m: number;
  output_cost_micros_per_1m: number;
  cached_input_cost_micros_per_1m: number;
  reasoning_cost_micros_per_1m?: number;
  pricing_status?: string;
  pricing_provenance_source?: string;
  pricing_effective_date?: string;
  pricing_version?: number;
  capabilities?: ModelCapabilities;
  supports_streaming?: boolean;
  supports_tools?: boolean;
  supports_vision?: boolean;
  supports_reasoning?: boolean;
  supports_inference?: boolean;
  lifecycle_status?: string;
}

export interface FallbackTarget {
  target: string;
  overrides?: Record<string, any>;
}

export interface RetryPolicy {
  rate_limit_retries?: number;
  timeout_retries?: number;
  server_error_retries?: number;
  auth_error_retries?: number;
  not_found_retries?: number;
  bad_request_retries?: number;
  default_retries?: number;
}

export interface CooldownPolicy {
  allowed_fails?: Record<string, number>;
  failure_rate_threshold?: number;
  min_requests_per_minute?: number;
  max_cooldown_seconds?: number;
}

export interface GoRouteExtensions {
  task_id?: string;
  context_id?: string;
  guardrails?: Array<Record<string, any>>;
  tags?: string[];
  allowed_region?: string;
  session_id?: string;
  preferred_deployment_id?: string;
  priority?: number;
  hedge_after_ms?: number;
}

export interface ModelGroup {
  id: string;
  org_id: string;
  alias: string;
  description?: string;
  routing_strategy: string;
  fallback_group_ids?: string[];
  context_window_fallbacks?: FallbackTarget[];
  content_policy_fallbacks?: FallbackTarget[];
  fallback_targets?: FallbackTarget[];
  saturation_fallbacks?: FallbackTarget[];
  drop_unsupported_params?: boolean;
  disable_cooldowns?: boolean;
  retry_policy?: RetryPolicy;
  cooldown_policy?: CooldownPolicy;
  max_retries?: number;
  cooldown_seconds?: number;
  failure_threshold?: number;
  is_active: boolean;
  created_at: string;
  updated_at?: string;
}

export interface PricingHistoryEntry {
  id: string;
  global_model_id: string;
  pricing_version: number;
  input_cost_micros_per_1m: number;
  output_cost_micros_per_1m: number;
  cached_input_cost_micros_per_1m: number;
  reasoning_cost_micros_per_1m: number;
  pricing_status?: string;
  pricing_provenance_source?: string;
  changed_by: string;
  effective_from: string;
}

export interface Deployment {
  id: string;
  model_group_id: string;
  global_model_id: string;
  credential_id?: string;
  deployment_name?: string;
  region?: string;
  priority: number;
  weight: number;
  tags?: string[];
  max_budget_micros?: number;
  budget_reset_period?: BudgetResetPeriod | string;
  rpm_capacity?: number;
  tpm_capacity?: number;
  itpm_capacity?: number;
  otpm_capacity?: number;
  max_parallel_requests?: number;
  timeout_ms?: number;
  status: string;
  created_at?: string;
  updated_at?: string;
  global_model?: GlobalModel;
  credential?: ProviderCredential;
}

export interface DeploymentHealthReport {
  deployment_id: string;
  deployment_name: string;
  provider: string;
  model: string;
  status: 'healthy' | 'degraded' | 'unhealthy';
  consecutive_failures: number;
  probe_latency_ms: number;
  last_error?: string;
  last_checked_at: string;
}

export interface ProviderTelemetry {
  provider: string;
  total_requests: number;
  error_count: number;
  error_rate: number;
  avg_latency_ms: number;
  p50_latency_ms: number;
  p95_latency_ms: number;
  p99_latency_ms: number;
  avg_ttft_ms: number;
  p95_ttft_ms: number;
  total_tokens: number;
  total_cost_micros: number;
}

export interface TelemetrySnapshot {
  generated_at: string;
  total_requests: number;
  total_errors: number;
  global_error_rate: number;
  avg_latency_ms: number;
  p50_latency_ms: number;
  p95_latency_ms: number;
  p99_latency_ms: number;
  avg_ttft_ms: number;
  p95_ttft_ms: number;
  avg_routing_overhead_micros: number;
  p95_routing_overhead_micros: number;
  total_fallbacks: number;
  fallback_rate: number;
  total_retries: number;
  cache_hits: number;
  cache_misses: number;
  cache_hit_rate: number;
  providers?: Record<string, ProviderTelemetry>;
}

export interface SpendSummary {
  total_requests: number;
  total_tokens: number;
  total_cost_micros: number;
  total_cost_usd: number;
  unpriced_requests: number;
  unpriced_tokens: number;
  spend_by_provider?: Record<string, number>;
  spend_by_model?: Record<string, number>;
  spend_by_team?: Record<string, number>;
  spend_by_virtual_key?: Record<string, number>;
}

export interface TokenUsage {
  prompt_tokens: number;
  completion_tokens: number;
  total_tokens: number;
  cached_prompt_tokens?: number;
  reasoning_tokens?: number;
}

export interface SpendEvent {
  id: string;
  request_id: string;
  org_id: string;
  virtual_key_id: string;
  provider: string;
  requested_model: string;
  resolved_model: string;
  usage?: TokenUsage;
  cost_micros: number;
  cost_usd: number;
  modality?: string;
  latency_ms: number;
  created_at: string;
}

export interface AuditLog {
  id: string;
  org_id: string;
  actor_id: string;
  action: string;
  resource: string;
  resource_id: string;
  details?: Record<string, any>;
  created_at: string;
}

export type GuardrailPolicyAction = 'block' | 'redact' | 'audit' | 'route';

export interface GuardrailPolicy {
  org_id: string;
  mode?: 'enforce' | 'logging_only';
  scan_all_roles?: boolean;
  enable_prompt_injection: boolean;
  prompt_injection_action: GuardrailPolicyAction;
  enable_pii_detection: boolean;
  pii_action: GuardrailPolicyAction;
  enable_secret_detection: boolean;
  secret_action: GuardrailPolicyAction;
  redact_output_pii: boolean;
  blocked_keywords?: string[];
  enable_toxicity_filter?: boolean;
  toxicity_action?: GuardrailPolicyAction;
  toxicity_threshold?: string;
  enabled_content_categories?: string[];
  content_exceptions?: string[];
  sensitive_route_target?: string;
  updated_at?: string;
}

export type GuardrailHook =
  | 'pre_call'
  | 'during_call'
  | 'post_call'
  | 'logging_only'
  | 'pre_mcp_call'
  | 'during_mcp_call'
  | 'post_mcp_call';

export type StreamScope = 'both' | 'streaming' | 'non_streaming';

export type GuardrailStatus = 'active' | 'pending_review' | 'rejected';

export type GuardrailProviderType =
  | 'openai_moderation'
  | 'presidio'
  | 'lakera_v2'
  | 'guardrails_ai'
  | 'pangea'
  | 'local_content_filter'
  | 'generic_http'
  | 'custom_code'
  | 'tool_permission'
  | 'tool_policy'
  | 'block_code_execution'
  | 'mcp_security'
  | 'mcp_end_user_permission'
  | 'llm_as_a_judge'
  | 'decision_model'
  | string;

export interface GuardrailModeRule {
  tags?: Record<string, GuardrailHook[]>;
  default?: GuardrailHook[];
}

export interface GuardrailDefinition {
  id: string;
  org_id: string;
  name: string;
  provider: GuardrailProviderType;
  event_hooks?: GuardrailHook[];
  stream_scope?: StreamScope;
  stream_scope_by_hook?: Partial<Record<GuardrailHook, StreamScope>>;
  mode_rule?: GuardrailModeRule;
  default_on: boolean;
  enabled_roles?: string[];
  timeout_ms?: number;
  fail_open: boolean;
  precedence: number;
  config?: Record<string, any>;
  has_secrets: boolean;
  status: GuardrailStatus;
  guardrail_info?: Record<string, any>;
  weight: number;
  sensitive_route_target?: string;
  created_at: string;
  updated_at: string;
}

export interface GuardrailDefinitionWriteRequest {
  id?: string;
  name: string;
  provider: GuardrailProviderType;
  event_hooks?: GuardrailHook[];
  stream_scope?: StreamScope;
  stream_scope_by_hook?: Partial<Record<GuardrailHook, StreamScope>>;
  mode_rule?: GuardrailModeRule;
  default_on?: boolean;
  enabled_roles?: string[];
  timeout_ms?: number;
  fail_open?: boolean;
  precedence?: number;
  config?: Record<string, any>;
  secrets?: Record<string, any>;
  clear_secrets?: boolean;
  status?: GuardrailStatus;
  guardrail_info?: Record<string, any>;
  weight?: number;
  sensitive_route_target?: string;
}

export interface GuardrailBinding {
  id: string;
  org_id: string;
  guardrail_id: string;
  guardrail_name: string;
  team_id?: string;
  virtual_key_id?: string;
  end_user_id?: string;
  model_group_id?: string;
  tag?: string;
  param_overrides?: Record<string, any>;
  is_locked: boolean;
  created_at: string;
  updated_at: string;
}

export interface GuardrailBindingCreateRequest {
  id?: string;
  org_id?: string;
  guardrail_id: string;
  guardrail_name?: string;
  team_id?: string;
  virtual_key_id?: string;
  end_user_id?: string;
  model_group_id?: string;
  tag?: string;
  param_overrides?: Record<string, any>;
  is_locked?: boolean;
}

export type ToolTrustInputLevel = 'untrusted' | 'trusted' | 'blocked';
export type ToolTrustOutputLevel = 'untrusted' | 'trusted';

export interface ToolPolicy {
  id: string;
  org_id: string;
  team_id?: string;
  virtual_key_id?: string;
  tool_name: string;
  input_policy: ToolTrustInputLevel;
  output_policy: ToolTrustOutputLevel;
  created_at: string;
  updated_at: string;
}

export interface ToolPolicyUpsertRequest {
  id?: string;
  team_id?: string;
  virtual_key_id?: string;
  tool_name: string;
  input_policy: ToolTrustInputLevel;
  output_policy: ToolTrustOutputLevel;
}

export interface GuardrailUsageTotals {
  evaluations: number;
  blocks: number;
  redactions: number;
  flags: number;
  errors: number;
  latency_sum_ms: number;
  total_units: number;
  total_cost_micros: number;
}

export interface GuardrailDailyUsagePoint {
  date: string;
  guardrail_id: string;
  guardrail_name: string;
  evaluations: number;
  blocks: number;
  redactions: number;
  flags: number;
  errors: number;
  latency_sum_ms: number;
  units: number;
  cost_micros: number;
}

export interface GuardrailUsageUnitBreakdown {
  date: string;
  guardrail_id: string;
  team_id?: string;
  virtual_key_id?: string;
  usage_unit: string;
  units: number;
  cost_micros: number;
}

export interface GuardrailTopTriggered {
  guardrail_id: string;
  guardrail_name: string;
  evaluations: number;
  blocks: number;
  redactions: number;
  flags: number;
  triggered_count: number;
  errors: number;
  units: number;
  cost_micros: number;
}

export interface GuardrailUsageSummary {
  org_id: string;
  start_date: string;
  end_date: string;
  totals: GuardrailUsageTotals;
  total_cost_micros: number;
  daily_series: GuardrailDailyUsagePoint[];
  usage_units: GuardrailUsageUnitBreakdown[];
  top_triggered: GuardrailTopTriggered[];
}

export interface GuardrailViolation {
  guardrail_name: string;
  guardrail_id?: string;
  provider?: string;
  category?: string;
  rule?: string;
  severity?: string;
  message: string;
  score?: number;
  action?: string;
  decision?: string;
  details?: Record<string, any>;
}

export interface GuardrailSimulateRequest {
  prompt?: string;
  input?: string;
  text?: string;
  texts?: string[];
  messages?: Array<Record<string, any>>;
  tools?: Array<Record<string, any>>;
  tool_calls?: Array<Record<string, any>>;
  tags?: string[];
  direction?: 'input' | 'output';
  guardrail_name?: string;
  stream_chunk_size?: number;
  policy?: Partial<GuardrailPolicy>;
}

export interface GuardrailSimulateResponse {
  allowed: boolean;
  blocked?: boolean;
  decision?: string;
  action?: string;
  applied_action: string;
  violations?: Array<string | GuardrailViolation>;
  redacted: boolean;
  direction?: string;
  redacted_prompt?: string;
  texts?: string[];
  modified_texts?: string[];
  modified_messages?: Array<Record<string, any>>;
  modified_tool_calls?: Array<Record<string, any>>;
  applied_guardrails?: string[];
  stream_chunks_evaluated?: number;
  error_message?: string;
}

export interface GuardrailApplyRequest {
  guardrail_name?: string;
  input_type?: 'request' | 'input' | 'response' | 'output';
  text?: string;
  texts?: string[];
  messages?: Array<Record<string, any>>;
  tools?: Array<Record<string, any>>;
  tool_calls?: Array<Record<string, any>>;
  tags?: string[];
  metadata?: Record<string, any>;
  model?: string;
}

export interface GuardrailApplyResponse {
  decision: string;
  action: string;
  blocked: boolean;
  texts?: string[];
  modified_texts?: string[];
  modified_messages?: Array<Record<string, any>>;
  modified_tool_calls?: Array<Record<string, any>>;
  violations?: GuardrailViolation[];
  applied_guardrails?: string[];
  usage_units: number;
  latency_ms: number;
  error_message?: string;
}

export interface MCPSpecInfo {
  version: string;
  label: string;
  summary: string;
  schema_dialect: string;
  schema_def_count: number;
  transport_mode: string;
  default_transport: string;
  allowed_transports: string[];
  supports_sessions: boolean;
  requires_initialize: boolean;
  supports_batching: boolean;
  requires_protocol_version_header: boolean;
  requires_mirrored_headers: boolean;
  supports_server_discover: boolean;
  supports_subscriptions_post: boolean;
  supports_tasks: boolean;
  supports_structured_content: boolean;
  supports_elicitation: boolean;
  supports_result_type: boolean;
  client_request_methods: string[];
  client_notification_methods: string[];
  server_notification_methods: string[];
}

export interface MCPRuntimeSpecState {
  status?: string;
  active_protocol_version: string;
  strict_schema_validation: boolean;
  updated_by?: string;
  updated_at?: string;
  available_specs: MCPSpecInfo[];
}

export interface MCPServer {
  id: string;
  org_id: string;
  name: string;
  slug: string;
  protocol_version?: string;
  transport_type: string;
  endpoint_url?: string;
  auth_type?: string;
  static_headers?: Record<string, string>;
  oauth2_endpoint?: string;
  oauth2_client_id?: string;
  oauth2_scopes?: string[];
  pinned_tool_hash?: string;
  is_active: boolean;
  last_synced_at?: string;
}

export interface MCPTool {
  id: string;
  server_id: string;
  org_id: string;
  name: string;
  description?: string;
  input_schema?: Record<string, any>;
  tool_def_hash: string;
  cost_per_call_micros: number;
  is_active: boolean;
  created_at?: string;
  updated_at?: string;
}

export interface MCPToolset {
  id: string;
  org_id: string;
  name: string;
  slug: string;
  tool_ids?: string[];
  is_active: boolean;
  created_at?: string;
}

export interface A2AAgent {
  id: string;
  org_id: string;
  name: string;
  slug: string;
  endpoint_url: string;
  agent_card_url?: string;
  task_visibility_mode?: string;
  auth_type?: 'none' | 'static' | 'vault_jwt';
  max_task_iterations?: number;
  max_task_budget_micros?: number;
  is_active: boolean;
  is_killed: boolean;
  created_at: string;
}

export interface GatewayConfig {
  server?: Record<string, any>;
  rate_limit?: Record<string, any>;
  rate_limits?: Record<string, any>;
  cache?: Record<string, any>;
  guardrails?: Record<string, any>;
  router?: Record<string, any>;
  routing?: Record<string, any>;
  observability?: Record<string, any>;
  logging?: Record<string, any>;
  tracing?: Record<string, any>;
  [key: string]: any;
}

export type QuotaScopeType =
  | 'org'
  | 'team'
  | 'team_member'
  | 'project'
  | 'user'
  | 'key'
  | 'end_user'
  | 'tag'
  | 'model_access_group'
  | 'agent_session'
  | 'mcp_server'
  | 'model_per_key'
  | 'model_per_team'
  | 'model_per_project'
  | 'model_per_user'
  | 'model_per_org'
  | 'model_per_end_user';

export interface QuotaPolicy {
  id: string;
  org_id: string;
  scope_type: QuotaScopeType;
  scope_id: string;
  model_pattern: string;
  rpm_limit: number;
  tpm_limit: number;
  itpm_limit: number;
  otpm_limit: number;
  tpd_limit: number;
  rpd_limit?: number;
  max_concurrent: number;
  max_budget_micros: number;
  spent_micros: number;
  budget_reset_period: BudgetResetPeriod;
  budget_reset_at?: string;
  max_iterations: number;
  window_ttl_sec: number;
  is_active: boolean;
  created_at: string;
  updated_at: string;
}

export type BudgetWindowType = 'daily' | 'weekly' | 'monthly' | 'rolling_24h';

export interface BudgetWindowLimit {
  id: string;
  org_id: string;
  scope_type: QuotaScopeType;
  scope_id: string;
  window_type: BudgetWindowType;
  max_budget_micros: number;
  spent_micros: number;
  window_reset_at: string;
  created_at: string;
  updated_at: string;
}
