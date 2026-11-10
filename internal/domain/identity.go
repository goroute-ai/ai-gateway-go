package domain

import "time"

// Role defines RBAC access levels inside an Organization.
type Role string

const (
	RolePlatformAdmin  Role = "platform_admin"
	RoleOrgAdmin       Role = "org_admin"
	RoleTeamAdmin      Role = "team_admin"
	RoleDeveloper      Role = "developer"
	RoleServiceAccount Role = "service_account"
	RoleViewer         Role = "viewer"
)

// BudgetResetPeriod defines when accumulated spend counters automatically reset.
type BudgetResetPeriod string

const (
	BudgetResetDaily   BudgetResetPeriod = "daily"
	BudgetResetMonthly BudgetResetPeriod = "monthly"
	BudgetResetNever   BudgetResetPeriod = "never"
)

// Organization represents a top-level tenant in the AI Gateway.
type Organization struct {
	ID                string            `json:"id"`
	Name              string            `json:"name"`
	Slug              string            `json:"slug"`
	MaxBudgetMicros   int64             `json:"max_budget_micros"` // 0 = unlimited
	SpentMicros       int64             `json:"spent_micros"`
	BudgetResetPeriod BudgetResetPeriod `json:"budget_reset_period"`
	BudgetResetAt     *time.Time        `json:"budget_reset_at,omitempty"`
	RPMLimit          int               `json:"rpm_limit"` // 0 = unlimited
	TPMLimit          int               `json:"tpm_limit"` // 0 = unlimited
	IsActive          bool              `json:"is_active"`
	Metadata          map[string]string `json:"metadata,omitempty"`
	CreatedAt         time.Time         `json:"created_at"`
	UpdatedAt         time.Time         `json:"updated_at"`
}

// Team groups users and virtual keys under an Organization with dedicated budgets and model scopes.
type Team struct {
	ID                string            `json:"id"`
	OrgID             string            `json:"org_id"`
	Name              string            `json:"name"`
	MaxBudgetMicros   int64             `json:"max_budget_micros"`
	SpentMicros       int64             `json:"spent_micros"`
	BudgetResetPeriod BudgetResetPeriod `json:"budget_reset_period"`
	BudgetResetAt     *time.Time        `json:"budget_reset_at,omitempty"`
	RPMLimit          int               `json:"rpm_limit"`
	TPMLimit          int               `json:"tpm_limit"`
	AllowedModels     []string          `json:"allowed_models,omitempty"`      // Empty = inherit Org enabled models
	AllowedMCPServers []string          `json:"allowed_mcp_servers,omitempty"` // nil = inherit, [] = DenyAll, [...] = allowlist
	AllowedA2AAgents  []string          `json:"allowed_a2a_agents,omitempty"`  // nil = inherit, [] = DenyAll, [...] = allowlist
	AllowedClientApps []string          `json:"allowed_client_apps,omitempty"` // nil = inherit, [] = DenyAll, [...] = allowlist
	IsActive          bool              `json:"is_active"`
	CreatedAt         time.Time         `json:"created_at"`
	UpdatedAt         time.Time         `json:"updated_at"`
}

// User represents a human identity belonging to an Organization and optionally a Team.
type User struct {
	ID          string    `json:"id"`
	OrgID       string    `json:"org_id"`
	TeamID      string    `json:"team_id,omitempty"`
	Email       string    `json:"email"`
	Name        string    `json:"name"`
	Role        Role      `json:"role"`
	OIDCSubject string    `json:"oidc_subject,omitempty"`
	IsActive    bool      `json:"is_active"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// DefaultAllowedEndpoints contains the default data-plane endpoints permitted for newly issued Virtual Keys.
var DefaultAllowedEndpoints = []string{
	"/v1/*",
	"/chat/*",
	"/embeddings",
	"/models",
	"/rerank",
	"/v2/rerank",
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
	ID                    string            `json:"id"`
	KeyPrefix             string            `json:"key_prefix"`        // e.g. "sk-gw-9f8e7d6c"
	KeyHash               string            `json:"-"`                 // SHA-256 hex digest (never serialized in JSON responses)
	RawKey                string            `json:"raw_key,omitempty"` // Populated ONLY once upon creation
	Name                  string            `json:"name"`
	OrgID                 string            `json:"org_id"`
	TeamID                string            `json:"team_id,omitempty"`
	UserID                string            `json:"user_id,omitempty"`
	Role                  Role              `json:"role"`
	AllowedModels         []string          `json:"allowed_models,omitempty"`
	AllowedEndpoints      []string          `json:"allowed_endpoints,omitempty"`
	AllowedMCPServers     []string          `json:"allowed_mcp_servers,omitempty"` // nil = inherit, [] = DenyAll, [...] = allowlist
	AllowedA2AAgents      []string          `json:"allowed_a2a_agents,omitempty"`  // nil = inherit, [] = DenyAll, [...] = allowlist
	AllowedClientApps     []string          `json:"allowed_client_apps,omitempty"` // nil = inherit, [] = DenyAll, [...] = allowlist
	MaxBudgetMicros       int64             `json:"max_budget_micros"`
	SpentMicros           int64             `json:"spent_micros"`
	BudgetResetPeriod     BudgetResetPeriod `json:"budget_reset_period"`
	BudgetResetAt         *time.Time        `json:"budget_reset_at,omitempty"`
	RPMLimit              int               `json:"rpm_limit"`
	TPMLimit              int               `json:"tpm_limit"`
	MaxConcurrentRequests int               `json:"max_concurrent_requests"`
	ExpiresAt             *time.Time        `json:"expires_at,omitempty"`
	IsActive              bool              `json:"is_active"`
	Metadata              map[string]string `json:"metadata,omitempty"`
	CreatedAt             time.Time         `json:"created_at"`
	UpdatedAt             time.Time         `json:"updated_at"`
}

// IdentityContext is resolved on the hot path from L1/L2 cache and attached to `r.Context()`.
type IdentityContext struct {
	VirtualKeyID          string   `json:"virtual_key_id"`
	KeyPrefix             string   `json:"key_prefix"`
	OrgID                 string   `json:"org_id"`
	TeamID                string   `json:"team_id,omitempty"`
	UserID                string   `json:"user_id,omitempty"`
	Role                  Role     `json:"role"`
	KeyAllowedModels      []string `json:"key_allowed_models,omitempty"`
	TeamAllowedModels     []string `json:"team_allowed_models,omitempty"`
	AllowedEndpoints      []string `json:"allowed_endpoints,omitempty"`
	KeyAllowedMCPServers  []string `json:"key_allowed_mcp_servers,omitempty"`
	TeamAllowedMCPServers []string `json:"team_allowed_mcp_servers,omitempty"`
	KeyAllowedA2AAgents   []string `json:"key_allowed_a2a_agents,omitempty"`
	TeamAllowedA2AAgents  []string `json:"team_allowed_a2a_agents,omitempty"`
	KeyAllowedClientApps  []string `json:"key_allowed_client_apps,omitempty"`
	TeamAllowedClientApps []string `json:"team_allowed_client_apps,omitempty"`
	KeyRPMLimit           int      `json:"key_rpm_limit"`
	KeyTPMLimit           int      `json:"key_tpm_limit"`
	KeyMaxConcurrent      int      `json:"key_max_concurrent"`
	KeyMaxBudgetMicros    int64    `json:"key_max_budget_micros"`
	KeySpentMicros        int64    `json:"key_spent_micros"`
	TeamRPMLimit          int      `json:"team_rpm_limit"`
	TeamTPMLimit          int      `json:"team_tpm_limit"`
	TeamMaxBudgetMicros   int64    `json:"team_max_budget_micros"`
	TeamSpentMicros       int64    `json:"team_spent_micros"`
	OrgRPMLimit           int      `json:"org_rpm_limit"`
	OrgTPMLimit           int      `json:"org_tpm_limit"`
	OrgMaxBudgetMicros    int64    `json:"org_max_budget_micros"`
	OrgSpentMicros        int64    `json:"org_spent_micros"`
}

// AuditLog records administrative or security-critical mutations.
type AuditLog struct {
	ID         string         `json:"id"`
	OrgID      string         `json:"org_id,omitempty"`
	ActorID    string         `json:"actor_id"`
	Action     string         `json:"action"`
	Resource   string         `json:"resource"`
	ResourceID string         `json:"resource_id"`
	Details    map[string]any `json:"details,omitempty"`
	CreatedAt  time.Time      `json:"created_at"`
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
