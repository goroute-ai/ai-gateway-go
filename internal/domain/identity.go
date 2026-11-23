package domain

import (
	"slices"
	"time"
)

// Role defines RBAC access levels inside an Organization.
type Role string

// Built-in data-plane RBAC roles for virtual keys and users.
const (
	RolePlatformAdmin  Role = "platform_admin"
	RoleOrgAdmin       Role = "org_admin"
	RoleOrgViewer      Role = "org_viewer"
	RoleTeamAdmin      Role = "team_admin"
	RoleDeveloper      Role = "developer"
	RoleServiceAccount Role = "service_account"
	RoleViewer         Role = "viewer"
)

// OperatorRole defines RBAC roles for Control Plane (/admin/v1/*) operators.
type OperatorRole string

// Control-plane operator RBAC roles.
const (
	OperatorRolePlatformAdmin OperatorRole = "platform_admin"
	OperatorRoleOrgAdmin      OperatorRole = "org_admin"
	OperatorRoleOrgViewer     OperatorRole = "org_viewer"
	OperatorRoleTeamAdmin     OperatorRole = "team_admin"
)

// OperatorContext represents an authenticated Control Plane operator attached to `r.Context()`.
type OperatorContext struct {
	ActorID               string       `json:"actor_id"`
	ImpersonatedByActorID string       `json:"impersonated_by_actor_id,omitempty"`
	Role                  OperatorRole `json:"role"`
	OrgID                 string       `json:"org_id,omitempty"`
	TeamID                string       `json:"team_id,omitempty"`
	AuthMethod            string       `json:"auth_method"` // "master_key", "virtual_key", "jwt", "session"
	CanImpersonate        bool         `json:"can_impersonate,omitempty"`
	DeprecatedKeyRevokeAt *time.Time   `json:"deprecated_key_revoke_at,omitempty"`
	SessionID             string       `json:"session_id,omitempty"`
	CSRFToken             string       `json:"csrf_token,omitempty"`
}

// OperatorSession represents a revocable Control Plane session stored in operator_sessions.
type OperatorSession struct {
	ID                  string     `json:"id"`
	UserID              string     `json:"user_id"`
	OrgID               string     `json:"org_id"`
	Role                string     `json:"role"`
	ProviderID          string     `json:"provider_id,omitempty"`
	CSRFToken           string     `json:"csrf_token"`
	EncryptedIDToken    string     `json:"-"`
	EncryptedIDTokenDEK string     `json:"-"`
	ExpiresAt           time.Time  `json:"expires_at"`
	RevokedAt           *time.Time `json:"revoked_at,omitempty"`
	CreatedAt           time.Time  `json:"created_at"`
}

// KeyType defines capability presets applied to Virtual API Keys.
type KeyType string

// Supported VirtualKey capability presets.
const (
	KeyTypeDefault        KeyType = "default"
	KeyTypeLLMAPI         KeyType = "llm_api"
	KeyTypeManagement     KeyType = "management"
	KeyTypeReadOnly       KeyType = "read_only"
	KeyTypeServiceAccount KeyType = "service_account"
)

// BudgetResetPeriod defines when accumulated spend counters automatically reset.
type BudgetResetPeriod string

// Supported automatic budget reset schedules.
const (
	BudgetResetDaily   BudgetResetPeriod = "daily"
	BudgetResetMonthly BudgetResetPeriod = "monthly"
	BudgetResetNever   BudgetResetPeriod = "never"
)

// Organization represents a top-level tenant in the AI Gateway.
type Organization struct {
	ID                          string                `json:"id"`
	Name                        string                `json:"name"`
	Slug                        string                `json:"slug"`
	MaxBudgetMicros             int64                 `json:"max_budget_micros"` // 0 = unlimited
	TempBudgetIncreaseMicros    int64                 `json:"temp_budget_increase_micros"`
	TempBudgetExpiresAt         *time.Time            `json:"temp_budget_expires_at,omitempty"`
	SelfServeBudgetPolicy       SelfServeBudgetPolicy `json:"self_serve_budget_policy,omitempty"`
	SoftBudgetMicros            int64                 `json:"soft_budget_micros"`
	ThrottleOnBudgetExceeded    bool                  `json:"throttle_on_budget_exceeded"`
	BudgetFallbacks             map[string][]string   `json:"budget_fallbacks,omitempty"`
	SpentMicros                 int64                 `json:"spent_micros"`
	BudgetResetPeriod           BudgetResetPeriod     `json:"budget_reset_period"`
	BudgetResetAt               *time.Time            `json:"budget_reset_at,omitempty"`
	RPMLimit                    int                   `json:"rpm_limit"`                               // 0 = unlimited
	TPMLimit                    int                   `json:"tpm_limit"`                               // 0 = unlimited
	MaxConcurrentRequests       int                   `json:"max_concurrent_requests"`                 // 0 = unlimited
	BatchEnqueuedTokenLimit     int64                 `json:"batch_enqueued_token_limit,omitempty"`    // 0 = unlimited
	MaxIterations               int                   `json:"max_iterations,omitempty"`                // 0 = unlimited per session
	MaxBudgetPerSessionMicros   int64                 `json:"max_budget_per_session_micros,omitempty"` // 0 = unlimited per session
	EnforceGuaranteedThroughput bool                  `json:"enforce_guaranteed_throughput,omitempty"`
	DeveloperSelfServeKeys      bool                  `json:"developer_self_serve_keys,omitempty"`
	KeyExpiryAlertDays          []int                 `json:"key_expiry_alert_days,omitempty"`
	LifecycleWebhookURL         string                `json:"lifecycle_webhook_url,omitempty"`
	IsActive                    bool                  `json:"is_active"`
	Metadata                    map[string]string     `json:"metadata,omitempty"`
	CreatedAt                   time.Time             `json:"created_at"`
	UpdatedAt                   time.Time             `json:"updated_at"`
}

// Team groups users and virtual keys under an Organization with dedicated budgets and model scopes.
type Team struct {
	ID                           string              `json:"id"`
	OrgID                        string              `json:"org_id"`
	Name                         string              `json:"name"`
	MaxBudgetMicros              int64               `json:"max_budget_micros"`
	TempBudgetIncreaseMicros     int64               `json:"temp_budget_increase_micros"`
	TempBudgetExpiresAt          *time.Time          `json:"temp_budget_expires_at,omitempty"`
	SoftBudgetMicros             int64               `json:"soft_budget_micros"`
	ThrottleOnBudgetExceeded     bool                `json:"throttle_on_budget_exceeded"`
	BudgetFallbacks              map[string][]string `json:"budget_fallbacks,omitempty"`
	SpentMicros                  int64               `json:"spent_micros"`
	BudgetResetPeriod            BudgetResetPeriod   `json:"budget_reset_period"`
	BudgetResetAt                *time.Time          `json:"budget_reset_at,omitempty"`
	RPMLimit                     int                 `json:"rpm_limit"`
	TPMLimit                     int                 `json:"tpm_limit"`
	MCPRPMLimit                  int                 `json:"mcp_rpm_limit,omitempty"`
	MaxConcurrentRequests        int                 `json:"max_concurrent_requests"`
	BatchEnqueuedTokenLimit      int64               `json:"batch_enqueued_token_limit,omitempty"`
	MaxIterations                int                 `json:"max_iterations,omitempty"`
	MaxBudgetPerSessionMicros    int64               `json:"max_budget_per_session_micros,omitempty"`
	EnforceGuaranteedThroughput  bool                `json:"enforce_guaranteed_throughput,omitempty"`
	DefaultMemberMaxBudgetMicros int64               `json:"default_member_max_budget_micros,omitempty"`
	DefaultMemberRPMLimit        int                 `json:"default_member_rpm_limit,omitempty"`
	DefaultMemberTPMLimit        int                 `json:"default_member_tpm_limit,omitempty"`
	DefaultMemberAllowedModels   []string            `json:"default_member_allowed_models,omitempty"`
	TeamMemberPermissions        []string            `json:"team_member_permissions,omitempty"`
	AllowedModels                []string            `json:"allowed_models,omitempty"` // Empty = inherit Org enabled models
	AllowedMCPServers            []string            `json:"allowed_mcp_servers"`      // nil = inherit, [] = DenyAll, [...] = allowlist
	AllowedA2AAgents             []string            `json:"allowed_a2a_agents"`       // nil = inherit, [] = DenyAll, [...] = allowlist
	AllowedClientApps            []string            `json:"allowed_client_apps"`      // nil = inherit, [] = DenyAll, [...] = allowlist
	MinPriorityRank              int                 `json:"min_priority_rank,omitempty"`
	AllowedRoutingTags           []string            `json:"allowed_routing_tags,omitempty"`
	IsActive                     bool                `json:"is_active"`
	CreatedAt                    time.Time           `json:"created_at"`
	UpdatedAt                    time.Time           `json:"updated_at"`
}

// User represents a human identity belonging to an Organization and optionally a Team.
type User struct {
	ID                       string              `json:"id"`
	OrgID                    string              `json:"org_id"`
	TeamID                   string              `json:"team_id,omitempty"`
	Email                    string              `json:"email"`
	Name                     string              `json:"name"`
	Role                     Role                `json:"role"`
	OIDCIssuer               string              `json:"oidc_issuer,omitempty"`
	OIDCSubject              string              `json:"oidc_subject,omitempty"`
	SCIMExternalID           string              `json:"scim_external_id,omitempty"`
	SCIMActive               bool                `json:"scim_active"`
	MaxBudgetMicros          int64               `json:"max_budget_micros"`
	TempBudgetIncreaseMicros int64               `json:"temp_budget_increase_micros"`
	TempBudgetExpiresAt      *time.Time          `json:"temp_budget_expires_at,omitempty"`
	SoftBudgetMicros         int64               `json:"soft_budget_micros"`
	ThrottleOnBudgetExceeded bool                `json:"throttle_on_budget_exceeded"`
	BudgetFallbacks          map[string][]string `json:"budget_fallbacks,omitempty"`
	SpentMicros              int64               `json:"spent_micros"`
	BudgetResetPeriod        BudgetResetPeriod   `json:"budget_reset_period"`
	BudgetResetAt            *time.Time          `json:"budget_reset_at,omitempty"`
	RPMLimit                 int                 `json:"rpm_limit"`
	TPMLimit                 int                 `json:"tpm_limit"`
	MaxConcurrentRequests    int                 `json:"max_concurrent_requests"`
	BatchEnqueuedTokenLimit  int64               `json:"batch_enqueued_token_limit,omitempty"`
	IsActive                 bool                `json:"is_active"`
	CreatedAt                time.Time           `json:"created_at"`
	UpdatedAt                time.Time           `json:"updated_at"`
}

// TeamMembership represents an M:N user-to-team membership with team-scoped role, budgets, rate limits, and model allowlists.
type TeamMembership struct {
	ID              string    `json:"id"`
	OrgID           string    `json:"org_id"`
	TeamID          string    `json:"team_id"`
	UserID          string    `json:"user_id"`
	Role            Role      `json:"role"`
	MaxBudgetMicros int64     `json:"max_budget_micros"`
	SpentMicros     int64     `json:"spent_micros"`
	RPMLimit        int       `json:"rpm_limit"`
	TPMLimit        int       `json:"tpm_limit"`
	AllowedModels   []string  `json:"allowed_models,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

// Project represents a team-scoped workload boundary under a Team with dedicated budgets, rate limits, and model scopes.
type Project struct {
	ID                       string    `json:"id"`
	OrgID                    string    `json:"org_id"`
	TeamID                   string    `json:"team_id"`
	Name                     string    `json:"name"`
	Description              string    `json:"description,omitempty"`
	MaxBudgetMicros          int64     `json:"max_budget_micros"`
	SpentMicros              int64     `json:"spent_micros"`
	RPMLimit                 int       `json:"rpm_limit"`
	TPMLimit                 int       `json:"tpm_limit"`
	AllowedModels            []string  `json:"allowed_models,omitempty"`
	EnforceProjectModelQuota bool      `json:"enforce_project_model_quota"`
	IsActive                 bool      `json:"is_active"`
	CreatedAt                time.Time `json:"created_at"`
	UpdatedAt                time.Time `json:"updated_at"`
}

// DefaultAllowedEndpoints contains the default data-plane endpoints permitted for newly issued Virtual Keys.
var DefaultAllowedEndpoints = []string{
	"/v1/*",
	"/chat/*",
	"/embeddings",
	"/models",
	"/moderations",
	"/completions",
	"/messages",
	"/anthropic/*",
	"/audio/*",
	"/images/*",
	"/files",
	"/files/*",
	"/batches",
	"/batches/*",
	"/responses",
	"/realtime",
	"/openai/*",
}

// VirtualKey represents a Gateway-issued API credential (`sk-gw-...`) for Boundary 1 authentication.
type VirtualKey struct {
	ID                        string              `json:"id"`
	KeyPrefix                 string              `json:"key_prefix"`        // e.g. "sk-gw-9f8e7d6c"
	KeyHash                   string              `json:"-"`                 // SHA-256 hex digest (never serialized in JSON responses)
	RawKey                    string              `json:"raw_key,omitempty"` // Populated ONLY once upon creation
	Name                      string              `json:"name"`
	OrgID                     string              `json:"org_id"`
	TeamID                    string              `json:"team_id,omitempty"`
	ProjectID                 string              `json:"project_id,omitempty"`
	UserID                    string              `json:"user_id,omitempty"`
	Role                      Role                `json:"role"`
	KeyType                   KeyType             `json:"key_type,omitempty"`
	AllowedModels             []string            `json:"allowed_models,omitempty"`
	AllowedEndpoints          []string            `json:"allowed_endpoints,omitempty"`
	AllowedMCPServers         []string            `json:"allowed_mcp_servers"` // nil = inherit, [] = DenyAll, [...] = allowlist
	AllowedA2AAgents          []string            `json:"allowed_a2a_agents"`  // nil = inherit, [] = DenyAll, [...] = allowlist
	AllowedClientApps         []string            `json:"allowed_client_apps"` // nil = inherit, [] = DenyAll, [...] = allowlist
	MaxBudgetMicros           int64               `json:"max_budget_micros"`
	TempBudgetIncreaseMicros  int64               `json:"temp_budget_increase_micros"`
	TempBudgetExpiresAt       *time.Time          `json:"temp_budget_expires_at,omitempty"`
	SoftBudgetMicros          int64               `json:"soft_budget_micros"`
	ThrottleOnBudgetExceeded  bool                `json:"throttle_on_budget_exceeded"`
	BudgetFallbacks           map[string][]string `json:"budget_fallbacks,omitempty"`
	SpentMicros               int64               `json:"spent_micros"`
	BudgetResetPeriod         BudgetResetPeriod   `json:"budget_reset_period"`
	BudgetResetAt             *time.Time          `json:"budget_reset_at,omitempty"`
	RPMLimit                  int                 `json:"rpm_limit"`
	TPMLimit                  int                 `json:"tpm_limit"`
	MCPRPMLimit               int                 `json:"mcp_rpm_limit,omitempty"`
	MaxConcurrentRequests     int                 `json:"max_concurrent_requests"`
	BatchEnqueuedTokenLimit   int64               `json:"batch_enqueued_token_limit,omitempty"`
	MaxIterations             int                 `json:"max_iterations,omitempty"`
	MaxBudgetPerSessionMicros int64               `json:"max_budget_per_session_micros,omitempty"`
	RotationIntervalSec       int64               `json:"rotation_interval_sec,omitempty"`
	KeyRotationAt             *time.Time          `json:"key_rotation_at,omitempty"`
	StagedKeyHash             string              `json:"-"`
	StagedKeyPrefix           string              `json:"-"`
	StagedEncryptedRawKey     string              `json:"-"`
	StagedKeyDEK              string              `json:"-"`
	StagedCreatedAt           *time.Time          `json:"-"`
	LastRotatedAt             *time.Time          `json:"last_rotated_at,omitempty"`
	RotationCount             int                 `json:"rotation_count,omitempty"`
	ExpiresAt                 *time.Time          `json:"expires_at,omitempty"`
	ExpiryAlertSentDays       []int               `json:"expiry_alert_sent_days,omitempty"`
	RevokedAt                 *time.Time          `json:"revoked_at,omitempty"`
	RevokedBy                 string              `json:"revoked_by,omitempty"`
	CanImpersonate            bool                `json:"can_impersonate"`
	IsActive                  bool                `json:"is_active"`
	MinPriorityRank           int                 `json:"min_priority_rank,omitempty"`
	AllowedRoutingTags        []string            `json:"allowed_routing_tags,omitempty"`
	Tags                      []string            `json:"tags,omitempty"`
	Metadata                  map[string]string   `json:"metadata,omitempty"`
	CreatedAt                 time.Time           `json:"created_at"`
	UpdatedAt                 time.Time           `json:"updated_at"`
}

// Principal describes the verified inbound authentication principal attached to an IdentityContext.
type Principal struct {
	AuthMethod    string         `json:"auth_method"`
	PrincipalType string         `json:"principal_type"`
	Issuer        string         `json:"issuer,omitempty"`
	Subject       string         `json:"subject,omitempty"`
	Email         string         `json:"email,omitempty"`
	RawClaims     map[string]any `json:"raw_claims,omitempty"`
}

// JWTKeyMapping binds a verified OIDC/JWT (issuer, claim_name, claim_value) tuple to a VirtualKey.
type JWTKeyMapping struct {
	ID           string    `json:"id"`
	OrgID        string    `json:"org_id"`
	Issuer       string    `json:"issuer"`
	ClaimName    string    `json:"claim_name"`
	ClaimValue   string    `json:"claim_value"`
	VirtualKeyID string    `json:"virtual_key_id"`
	CreatedAt    time.Time `json:"created_at"`
}

// AccessRuleOperator defines supported comparison operators for dynamic access group rules.
type AccessRuleOperator string

// Supported AccessRuleOperator values for dynamic attribute matching.
const (
	AccessRuleOperatorEquals   AccessRuleOperator = "equals"
	AccessRuleOperatorContains AccessRuleOperator = "contains"
	AccessRuleOperatorPrefix   AccessRuleOperator = "prefix"
	AccessRuleOperatorInList   AccessRuleOperator = "in_list"
)

// AccessGroupRule defines an organization-scoped attribute rule that dynamically grants
// model allowlists and/or access group membership to matching authenticated principals.
type AccessGroupRule struct {
	ID            string             `json:"id"`
	OrgID         string             `json:"org_id"`
	Name          string             `json:"name"`
	Attribute     string             `json:"attribute"`
	Operator      AccessRuleOperator `json:"operator"`
	Value         string             `json:"value"`
	AllowedModels []string           `json:"allowed_models"`
	AccessGroupID string             `json:"access_group_id,omitempty"`
	Priority      int                `json:"priority"`
	IsActive      bool               `json:"is_active"`
	CreatedAt     time.Time          `json:"created_at"`
	UpdatedAt     time.Time          `json:"updated_at"`
}

// IdentityContext is resolved on the hot path from L1/L2 cache and attached to `r.Context()`.
type IdentityContext struct {
	VirtualKeyID                  string              `json:"virtual_key_id"`
	KeyPrefix                     string              `json:"key_prefix"`
	OrgID                         string              `json:"org_id"`
	TeamID                        string              `json:"team_id,omitempty"`
	ProjectID                     string              `json:"project_id,omitempty"`
	UserID                        string              `json:"user_id,omitempty"`
	DelegatedUserID               string              `json:"delegated_user_id,omitempty"`
	DelegatedTeamID               string              `json:"delegated_team_id,omitempty"`
	Role                          Role                `json:"role"`
	KeyType                       KeyType             `json:"key_type,omitempty"`
	SCIMActive                    bool                `json:"scim_active"`
	CanImpersonate                bool                `json:"can_impersonate,omitempty"`
	RotationIntervalSec           int64               `json:"rotation_interval_sec,omitempty"`
	KeyRotationAt                 *time.Time          `json:"key_rotation_at,omitempty"`
	DeprecatedKeyRevokeAt         *time.Time          `json:"deprecated_key_revoke_at,omitempty"`
	Principal                     *Principal          `json:"principal,omitempty"`
	KeyAllowedModels              []string            `json:"key_allowed_models,omitempty"`
	ProjectAllowedModels          []string            `json:"project_allowed_models,omitempty"`
	TeamAllowedModels             []string            `json:"team_allowed_models,omitempty"`
	TeamMemberAllowedModels       []string            `json:"team_member_allowed_models,omitempty"`
	DynamicAllowedModels          []string            `json:"dynamic_allowed_models,omitempty"`
	AccessGroups                  []string            `json:"access_groups,omitempty"`
	AllowedEndpoints              []string            `json:"allowed_endpoints"`
	KeyAllowedMCPServers          []string            `json:"key_allowed_mcp_servers"`
	TeamAllowedMCPServers         []string            `json:"team_allowed_mcp_servers"`
	KeyAllowedA2AAgents           []string            `json:"key_allowed_a2a_agents"`
	TeamAllowedA2AAgents          []string            `json:"team_allowed_a2a_agents"`
	KeyAllowedClientApps          []string            `json:"key_allowed_client_apps"`
	TeamAllowedClientApps         []string            `json:"team_allowed_client_apps"`
	KeyRPMLimit                   int                 `json:"key_rpm_limit"`
	KeyTPMLimit                   int                 `json:"key_tpm_limit"`
	KeyMCPRPMLimit                int                 `json:"key_mcp_rpm_limit,omitempty"`
	KeyMaxConcurrent              int                 `json:"key_max_concurrent"`
	KeyBatchEnqueuedTokenLimit    int64               `json:"key_batch_enqueued_token_limit"`
	KeyMaxIterations              int                 `json:"key_max_iterations,omitempty"`
	KeyMaxBudgetPerSessionMicros  int64               `json:"key_max_budget_per_session_micros,omitempty"`
	KeyMinPriorityRank            int                 `json:"key_min_priority_rank,omitempty"`
	KeyAllowedRoutingTags         []string            `json:"key_allowed_routing_tags,omitempty"`
	TeamMinPriorityRank           int                 `json:"team_min_priority_rank,omitempty"`
	TeamAllowedRoutingTags        []string            `json:"team_allowed_routing_tags,omitempty"`
	KeyTags                       []string            `json:"key_tags,omitempty"`
	KeyMetadata                   map[string]string   `json:"key_metadata,omitempty"`
	KeyMaxBudgetMicros            int64               `json:"key_max_budget_micros"`
	KeyTempBudgetIncreaseMicros   int64               `json:"key_temp_budget_increase_micros,omitempty"`
	KeyTempBudgetExpiresAt        *time.Time          `json:"key_temp_budget_expires_at,omitempty"`
	KeySoftBudgetMicros           int64               `json:"key_soft_budget_micros"`
	KeyThrottleOnBudgetExceeded   bool                `json:"key_throttle_on_budget_exceeded"`
	KeyBudgetFallbacks            map[string][]string `json:"key_budget_fallbacks,omitempty"`
	KeySpentMicros                int64               `json:"key_spent_micros"`
	TeamRPMLimit                  int                 `json:"team_rpm_limit"`
	TeamTPMLimit                  int                 `json:"team_tpm_limit"`
	TeamMCPRPMLimit               int                 `json:"team_mcp_rpm_limit,omitempty"`
	TeamMaxConcurrent             int                 `json:"team_max_concurrent"`
	TeamBatchEnqueuedTokenLimit   int64               `json:"team_batch_enqueued_token_limit"`
	TeamMaxIterations             int                 `json:"team_max_iterations,omitempty"`
	TeamMaxBudgetPerSessionMicros int64               `json:"team_max_budget_per_session_micros,omitempty"`
	TeamMaxBudgetMicros           int64               `json:"team_max_budget_micros"`
	TeamTempBudgetIncreaseMicros  int64               `json:"team_temp_budget_increase_micros,omitempty"`
	TeamTempBudgetExpiresAt       *time.Time          `json:"team_temp_budget_expires_at,omitempty"`
	TeamSoftBudgetMicros          int64               `json:"team_soft_budget_micros"`
	TeamThrottleOnBudgetExceeded  bool                `json:"team_throttle_on_budget_exceeded"`
	TeamBudgetFallbacks           map[string][]string `json:"team_budget_fallbacks,omitempty"`
	TeamSpentMicros               int64               `json:"team_spent_micros"`
	ProjectRPMLimit               int                 `json:"project_rpm_limit"`
	ProjectTPMLimit               int                 `json:"project_tpm_limit"`
	ProjectMaxBudgetMicros        int64               `json:"project_max_budget_micros"`
	ProjectSpentMicros            int64               `json:"project_spent_micros"`
	ProjectEnforceModelQuota      bool                `json:"project_enforce_model_quota,omitempty"`
	TeamMemberRPMLimit            int                 `json:"team_member_rpm_limit"`
	TeamMemberTPMLimit            int                 `json:"team_member_tpm_limit"`
	TeamMemberMaxBudgetMicros     int64               `json:"team_member_max_budget_micros"`
	TeamMemberSpentMicros         int64               `json:"team_member_spent_micros"`
	UserRPMLimit                  int                 `json:"user_rpm_limit"`
	UserTPMLimit                  int                 `json:"user_tpm_limit"`
	UserMaxConcurrent             int                 `json:"user_max_concurrent"`
	UserBatchEnqueuedTokenLimit   int64               `json:"user_batch_enqueued_token_limit"`
	UserMaxBudgetMicros           int64               `json:"user_max_budget_micros"`
	UserTempBudgetIncreaseMicros  int64               `json:"user_temp_budget_increase_micros,omitempty"`
	UserTempBudgetExpiresAt       *time.Time          `json:"user_temp_budget_expires_at,omitempty"`
	UserSoftBudgetMicros          int64               `json:"user_soft_budget_micros"`
	UserThrottleOnBudgetExceeded  bool                `json:"user_throttle_on_budget_exceeded"`
	UserBudgetFallbacks           map[string][]string `json:"user_budget_fallbacks,omitempty"`
	UserSpentMicros               int64               `json:"user_spent_micros"`
	OrgRPMLimit                   int                 `json:"org_rpm_limit"`
	OrgTPMLimit                   int                 `json:"org_tpm_limit"`
	OrgMaxConcurrent              int                 `json:"org_max_concurrent"`
	OrgBatchEnqueuedTokenLimit    int64               `json:"org_batch_enqueued_token_limit"`
	OrgMaxIterations              int                 `json:"org_max_iterations,omitempty"`
	OrgMaxBudgetPerSessionMicros  int64               `json:"org_max_budget_per_session_micros,omitempty"`
	OrgMaxBudgetMicros            int64               `json:"org_max_budget_micros"`
	OrgTempBudgetIncreaseMicros   int64               `json:"org_temp_budget_increase_micros,omitempty"`
	OrgTempBudgetExpiresAt        *time.Time          `json:"org_temp_budget_expires_at,omitempty"`
	OrgSoftBudgetMicros           int64               `json:"org_soft_budget_micros"`
	OrgThrottleOnBudgetExceeded   bool                `json:"org_throttle_on_budget_exceeded"`
	OrgBudgetFallbacks            map[string][]string `json:"org_budget_fallbacks,omitempty"`
	OrgSpentMicros                int64               `json:"org_spent_micros"`
}

// CloneBudgetFallbacks returns a deep copy of a model-to-fallback-models mapping.
func CloneBudgetFallbacks(src map[string][]string) map[string][]string {
	if len(src) == 0 {
		return nil
	}
	dst := make(map[string][]string, len(src))
	for k, v := range src {
		dst[k] = slices.Clone(v)
	}
	return dst
}

// AuditLog records administrative or security-critical mutations.
type AuditLog struct {
	ID          string         `json:"id"`
	OrgID       string         `json:"org_id,omitempty"`
	ActorID     string         `json:"actor_id"`
	Action      string         `json:"action"`
	Resource    string         `json:"resource"`
	ResourceID  string         `json:"resource_id"`
	Details     map[string]any `json:"details,omitempty"`
	BeforeValue map[string]any `json:"before_value,omitempty"`
	AfterValue  map[string]any `json:"after_value,omitempty"`
	CreatedAt   time.Time      `json:"created_at"`
}

// CheckAllowlist3State evaluates 3-state allowlist semantics across VirtualKey and Team scopes:
// 1. If keyAllowlist is non-nil:
//   - If empty ([]string{}): DenyAll (blocks access)
//   - If non-empty: target must match keyAllowlist (or "*")
//
// 2. If keyAllowlist is nil (inherit parent):
//   - If teamAllowlist is non-nil:
//   - If empty ([]string{}): DenyAll (blocks access)
//   - If non-empty: target must match teamAllowlist (or "*")
//   - If teamAllowlist is nil: inherit Org default (permits access)
func CheckAllowlist3State(keyAllowlist, teamAllowlist []string, target string) bool {
	if keyAllowlist != nil {
		if len(keyAllowlist) == 0 {
			return false // DenyAll
		}
		for _, item := range keyAllowlist {
			if item == "*" || item == target {
				return true
			}
		}
		return false
	}

	if teamAllowlist != nil {
		if len(teamAllowlist) == 0 {
			return false // DenyAll
		}
		for _, item := range teamAllowlist {
			if item == "*" || item == target {
				return true
			}
		}
		return false
	}

	return true // Inherit parent default allow
}
