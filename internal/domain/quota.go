package domain

import "time"

// QuotaScopeType identifies the entity or composite dimension a quota policy or
// runtime rate-limit descriptor applies to.
type QuotaScopeType string

const (
	QuotaScopeOrg              QuotaScopeType = "org"
	QuotaScopeTeam             QuotaScopeType = "team"
	QuotaScopeTeamMember       QuotaScopeType = "team_member"
	QuotaScopeProject          QuotaScopeType = "project"
	QuotaScopeUser             QuotaScopeType = "user"
	QuotaScopeKey              QuotaScopeType = "key"
	QuotaScopeEndUser          QuotaScopeType = "end_user"
	QuotaScopeTag              QuotaScopeType = "tag"
	QuotaScopeModelAccessGroup QuotaScopeType = "model_access_group"
	QuotaScopeAgentSession     QuotaScopeType = "agent_session"
	QuotaScopeMCPServer        QuotaScopeType = "mcp_server"
	QuotaScopeModelPerKey      QuotaScopeType = "model_per_key"
	QuotaScopeModelPerTeam     QuotaScopeType = "model_per_team"
	QuotaScopeModelPerProject  QuotaScopeType = "model_per_project"
	QuotaScopeModelPerUser     QuotaScopeType = "model_per_user"
	QuotaScopeModelPerOrg      QuotaScopeType = "model_per_org"
	QuotaScopeModelPerEndUser  QuotaScopeType = "model_per_end_user"
)

// IsValid reports whether s is a supported QuotaScopeType.
func (s QuotaScopeType) IsValid() bool {
	switch s {
	case QuotaScopeOrg,
		QuotaScopeTeam,
		QuotaScopeTeamMember,
		QuotaScopeProject,
		QuotaScopeUser,
		QuotaScopeKey,
		QuotaScopeEndUser,
		QuotaScopeTag,
		QuotaScopeModelAccessGroup,
		QuotaScopeAgentSession,
		QuotaScopeMCPServer,
		QuotaScopeModelPerKey,
		QuotaScopeModelPerTeam,
		QuotaScopeModelPerProject,
		QuotaScopeModelPerUser,
		QuotaScopeModelPerOrg,
		QuotaScopeModelPerEndUser:
		return true
	default:
		return false
	}
}

// QuotaPolicy is a durable, polymorphic quota configuration persisted in
// quota_policies and compiled into runtime RateLimitDescriptor entries.
type QuotaPolicy struct {
	ID                string            `json:"id"`
	OrgID             string            `json:"org_id"`
	ScopeType         QuotaScopeType    `json:"scope_type"`
	ScopeID           string            `json:"scope_id"`
	ModelPattern      string            `json:"model_pattern"`
	RPMLimit          int               `json:"rpm_limit"`
	TPMLimit          int               `json:"tpm_limit"`
	ITPMLimit         int               `json:"itpm_limit"`
	OTPMLimit         int               `json:"otpm_limit"`
	TPDLimit          int64             `json:"tpd_limit"`
	MaxConcurrent     int               `json:"max_concurrent"`
	MaxBudgetMicros   int64             `json:"max_budget_micros"`
	SpentMicros       int64             `json:"spent_micros"`
	BudgetResetPeriod BudgetResetPeriod `json:"budget_reset_period"`
	BudgetResetAt     *time.Time        `json:"budget_reset_at,omitempty"`
	MaxIterations     int               `json:"max_iterations"`
	WindowTTLSec      int               `json:"window_ttl_sec"`
	IsActive          bool              `json:"is_active"`
	CreatedAt         time.Time         `json:"created_at"`
	UpdatedAt         time.Time         `json:"updated_at"`
}

// Clone returns a deep copy of the QuotaPolicy.
func (p *QuotaPolicy) Clone() *QuotaPolicy {
	if p == nil {
		return nil
	}
	cp := *p
	if p.BudgetResetAt != nil {
		t := *p.BudgetResetAt
		cp.BudgetResetAt = &t
	}
	return &cp
}

// ToDescriptor compiles a persisted QuotaPolicy into a runtime RateLimitDescriptor.
func (p *QuotaPolicy) ToDescriptor() RateLimitDescriptor {
	if p == nil {
		return RateLimitDescriptor{}
	}
	return RateLimitDescriptor{
		PolicyID:         p.ID,
		ScopeType:        p.ScopeType,
		ScopeID:          p.ScopeID,
		ModelPattern:     p.ModelPattern,
		RPMLimit:         p.RPMLimit,
		TPMLimit:         p.TPMLimit,
		ITPMLimit:        p.ITPMLimit,
		OTPMLimit:        p.OTPMLimit,
		TPDLimit:         p.TPDLimit,
		MaxConcurrent:    p.MaxConcurrent,
		MaxBudgetMicros:  p.MaxBudgetMicros,
		SpentFloorMicros: p.SpentMicros,
		MaxIterations:    p.MaxIterations,
		WindowTTLSec:     p.WindowTTLSec,
	}
}

// RateLimitDescriptor is a single runtime quota dimension evaluated atomically
// alongside all other descriptors attached to a request.
type RateLimitDescriptor struct {
	PolicyID         string           `json:"policy_id,omitempty"`
	ScopeType        QuotaScopeType   `json:"scope_type"`
	ScopeID          string           `json:"scope_id"`
	ModelPattern     string           `json:"model_pattern,omitempty"`
	WindowType       BudgetWindowType `json:"window_type,omitempty"`
	RPMLimit         int              `json:"rpm_limit,omitempty"`
	TPMLimit         int              `json:"tpm_limit,omitempty"`
	ITPMLimit        int              `json:"itpm_limit,omitempty"`
	OTPMLimit        int              `json:"otpm_limit,omitempty"`
	TPDLimit         int64            `json:"tpd_limit,omitempty"`
	MaxConcurrent    int              `json:"max_concurrent,omitempty"`
	MaxBudgetMicros  int64            `json:"max_budget_micros,omitempty"`
	SpentFloorMicros int64            `json:"spent_floor_micros,omitempty"`
	MaxIterations    int              `json:"max_iterations,omitempty"`
	WindowTTLSec     int              `json:"window_ttl_sec,omitempty"`
}

// HasLimits reports whether the descriptor configures at least one positive quota dimension.
func (d RateLimitDescriptor) HasLimits() bool {
	return d.RPMLimit > 0 ||
		d.TPMLimit > 0 ||
		d.ITPMLimit > 0 ||
		d.OTPMLimit > 0 ||
		d.TPDLimit > 0 ||
		d.MaxConcurrent > 0 ||
		d.MaxBudgetMicros > 0 ||
		d.MaxIterations > 0
}

// BudgetWindowType identifies the time window for simultaneous multi-window spend caps.
type BudgetWindowType string

const (
	BudgetWindowDaily      BudgetWindowType = "daily"
	BudgetWindowWeekly     BudgetWindowType = "weekly"
	BudgetWindowMonthly    BudgetWindowType = "monthly"
	BudgetWindowRolling24h BudgetWindowType = "rolling_24h"
)

// IsValid reports whether w is a supported BudgetWindowType.
func (w BudgetWindowType) IsValid() bool {
	switch w {
	case BudgetWindowDaily, BudgetWindowWeekly, BudgetWindowMonthly, BudgetWindowRolling24h:
		return true
	default:
		return false
	}
}

// BudgetWindowLimit configures a simultaneous budget cap for a specific entity
// and window_type persisted in budget_window_limits.
type BudgetWindowLimit struct {
	ID              string           `json:"id"`
	OrgID           string           `json:"org_id"`
	ScopeType       QuotaScopeType   `json:"scope_type"`
	ScopeID         string           `json:"scope_id"`
	WindowType      BudgetWindowType `json:"window_type"`
	MaxBudgetMicros int64            `json:"max_budget_micros"`
	SpentMicros     int64            `json:"spent_micros"`
	WindowResetAt   time.Time        `json:"window_reset_at"`
	CreatedAt       time.Time        `json:"created_at"`
	UpdatedAt       time.Time        `json:"updated_at"`
}

// Clone returns a copy of the BudgetWindowLimit.
func (b *BudgetWindowLimit) Clone() *BudgetWindowLimit {
	if b == nil {
		return nil
	}
	cp := *b
	return &cp
}

// ToDescriptor compiles a persisted BudgetWindowLimit into a runtime RateLimitDescriptor.
func (b *BudgetWindowLimit) ToDescriptor() RateLimitDescriptor {
	if b == nil {
		return RateLimitDescriptor{}
	}
	return RateLimitDescriptor{
		PolicyID:         b.ID,
		ScopeType:        b.ScopeType,
		ScopeID:          b.ScopeID,
		ModelPattern:     "*",
		WindowType:       b.WindowType,
		MaxBudgetMicros:  b.MaxBudgetMicros,
		SpentFloorMicros: b.SpentMicros,
	}
}

// SelfServeBudgetPolicy governs whether non-org-admin operators (e.g. team_admin)
// may modify team or virtual key budgets within an organization.
type SelfServeBudgetPolicy string

const (
	SelfServeBudgetDisabled  SelfServeBudgetPolicy = "disabled"
	SelfServeBudgetLowerOnly SelfServeBudgetPolicy = "lower_only"
	SelfServeBudgetCeiling   SelfServeBudgetPolicy = "ceiling"
)

// IsValid reports whether p is a supported SelfServeBudgetPolicy.
func (p SelfServeBudgetPolicy) IsValid() bool {
	switch p {
	case SelfServeBudgetDisabled, SelfServeBudgetLowerOnly, SelfServeBudgetCeiling:
		return true
	default:
		return false
	}
}

// EffectiveMaxBudgetMicros returns baseMax plus tempIncrease when tempIncrease > 0
// and now is strictly before expiresAt. A non-positive baseMax remains 0 (unlimited).
func EffectiveMaxBudgetMicros(baseMax, tempIncrease int64, expiresAt *time.Time, now time.Time) int64 {
	if baseMax <= 0 {
		return 0
	}
	if tempIncrease > 0 && expiresAt != nil && now.Before(*expiresAt) {
		return baseMax + tempIncrease
	}
	return baseMax
}
