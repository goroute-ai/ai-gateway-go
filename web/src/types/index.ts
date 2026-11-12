export type ProviderType =
  | 'openai'
  | 'anthropic'
  | 'gemini'
  | 'mistral'
  | 'ollama'
  | 'groq'
  | 'deepseek'
  | 'together'
  | 'azure'
  | 'bedrock'
  | 'vertex'
  | 'cohere'
  | 'cerebras'
  | 'sambanova'
  | 'xai'
  | 'fireworks'
  | 'perplexity'
  | string;

export interface Organization {
  id: string;
  name: string;
  max_budget_micros?: number;
  current_spend_micros?: number;
  budget_reset_period?: string;
  is_active: boolean;
  created_at?: string;
}

export interface Team {
  id: string;
  org_id: string;
  name: string;
  max_budget_micros?: number;
  current_spend_micros?: number;
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
  oidc_subject?: string;
  role: string;
  is_active: boolean;
  created_at?: string;
  updated_at?: string;
}

export interface VirtualKey {
  id: string;
  org_id: string;
  team_id?: string;
  user_id?: string;
  name: string;
  key_prefix: string;
  key_secret?: string; // Only returned on creation
  role?: string;
  max_budget_micros?: number;
  current_spend_micros?: number;
  rpm_limit?: number;
  tpm_limit?: number;
  allowed_models?: string[];
  allowed_mcp_servers?: string[];
  allowed_a2a_agents?: string[];
  expires_at?: string;
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
  azure_deployment_name?: string;
  api_version?: string;
  is_active: boolean;
  expires_at?: string;
  last_rotated_at?: string;
  last_validated_at?: string;
  created_at: string;
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

export interface ModelGroup {
  id: string;
  org_id: string;
  alias: string;
  routing_strategy: string;
  is_active: boolean;
  created_at: string;
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
  rpm_capacity?: number;
  tpm_capacity?: number;
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

export interface SpendEvent {
  id: string;
  request_id: string;
  org_id: string;
  virtual_key_id: string;
  provider: string;
  requested_model: string;
  resolved_model: string;
  prompt_tokens: number;
  completion_tokens: number;
  total_tokens: number;
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

export interface GuardrailPolicy {
  org_id: string;
  enable_prompt_injection: boolean;
  prompt_injection_action: 'block' | 'redact' | 'audit';
  enable_pii_detection: boolean;
  pii_action: 'block' | 'redact' | 'audit';
  enable_secret_detection: boolean;
  secret_action: 'block' | 'redact' | 'audit';
  redact_output_pii: boolean;
  blocked_keywords?: string[];
}

export interface MCPServer {
  id: string;
  org_id: string;
  name: string;
  slug: string;
  transport_type: string;
  endpoint_url?: string;
  tool_count?: number;
  is_active: boolean;
  last_synced_at?: string;
}

export interface A2AAgent {
  id: string;
  org_id: string;
  name: string;
  slug: string;
  endpoint_url: string;
  is_active: boolean;
  is_killed: boolean;
  created_at: string;
}
