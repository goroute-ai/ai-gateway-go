package domain

import "time"

// GuardrailHook identifies the lifecycle stage at which a guardrail executes.
type GuardrailHook string

// Core guardrail lifecycle execution hooks.
const (
	GuardrailHookPreCall     GuardrailHook = "pre_call"
	GuardrailHookPostCall    GuardrailHook = "post_call"
	GuardrailHookLoggingOnly GuardrailHook = "logging_only"
)

// IsValid reports whether h is a recognized GuardrailHook value.
func (h GuardrailHook) IsValid() bool {
	switch h {
	case GuardrailHookPreCall,
		GuardrailHookPostCall,
		GuardrailHookLoggingOnly:
		return true
	default:
		return false
	}
}

// GuardrailDecision represents the outcome of evaluating one or more guardrails.
type GuardrailDecision string

// Guardrail evaluation decision outcomes.
const (
	GuardrailDecisionAllow  GuardrailDecision = "allow"
	GuardrailDecisionBlock  GuardrailDecision = "block"
	GuardrailDecisionFlag   GuardrailDecision = "flag"
	GuardrailDecisionModify GuardrailDecision = "modify"
)

// GuardrailDirection values for GuardrailEvalInput.Direction.
const (
	GuardrailDirectionInput  = "input"
	GuardrailDirectionOutput = "output"
)

// GuardrailDefinition defines a named, tenant-scoped external guardrail (such as a generic_http
// webhook or openai_moderation endpoint) evaluated alongside the organization's built-in policy.
type GuardrailDefinition struct {
	ID               string          `json:"id"`
	OrgID            string          `json:"org_id"`
	Name             string          `json:"name"`
	Provider         string          `json:"provider"`
	EventHooks       []GuardrailHook `json:"event_hooks,omitempty"`
	Enabled          bool            `json:"enabled"`
	TimeoutMs        int             `json:"timeout_ms,omitempty"`
	FailOpen         bool            `json:"fail_open"`
	Precedence       int             `json:"precedence"`
	Config           map[string]any  `json:"config,omitempty"`
	EncryptedSecrets string          `json:"-"` // AES-256-GCM Vault encrypted JSON secret payload
	EncryptedDEK     string          `json:"-"` // AES-256-GCM Vault encrypted DEK
	CreatedAt        time.Time       `json:"created_at"`
	UpdatedAt        time.Time       `json:"updated_at"`
}

// GuardrailEvalInput is the structured evaluation envelope passed to guardrail drivers.
type GuardrailEvalInput struct {
	Direction          string             `json:"direction,omitempty"`
	Hook               GuardrailHook      `json:"hook,omitempty"`
	RequestID          string             `json:"request_id,omitempty"`
	TraceID            string             `json:"trace_id,omitempty"`
	OrgID              string             `json:"org_id,omitempty"`
	TeamID             string             `json:"team_id,omitempty"`
	VirtualKeyID       string             `json:"virtual_key_id,omitempty"`
	EndUserID          string             `json:"end_user_id,omitempty"`
	Model              string             `json:"model,omitempty"`
	Tags               []string           `json:"tags,omitempty"`
	Texts              []string           `json:"texts,omitempty"`
	StructuredMessages []CanonicalMessage `json:"structured_messages,omitempty"`
	Images             []ImageURL         `json:"images,omitempty"`
	RequestHeaders     map[string]string  `json:"request_headers,omitempty"`
	Metadata           map[string]any     `json:"metadata,omitempty"`
}

// GuardrailViolation describes a single policy finding produced during guardrail evaluation.
type GuardrailViolation struct {
	GuardrailName string            `json:"guardrail_name"`
	GuardrailID   string            `json:"guardrail_id,omitempty"`
	Provider      string            `json:"provider,omitempty"`
	Category      string            `json:"category,omitempty"`
	Rule          string            `json:"rule,omitempty"`
	Severity      string            `json:"severity,omitempty"`
	Message       string            `json:"message"`
	Score         *float64          `json:"score,omitempty"`
	Action        GuardrailAction   `json:"action,omitempty"`
	Decision      GuardrailDecision `json:"decision,omitempty"`
	Details       map[string]any    `json:"details,omitempty"`
}

// GuardrailEvalResult carries the aggregated outcome and optional content mutations
// returned by a guardrail evaluation pass.
type GuardrailEvalResult struct {
	Decision          GuardrailDecision    `json:"decision"`
	ModifiedTexts     []string             `json:"modified_texts,omitempty"`
	ModifiedMessages  []CanonicalMessage   `json:"modified_messages,omitempty"`
	Violations        []GuardrailViolation `json:"violations,omitempty"`
	AppliedGuardrails []string             `json:"applied_guardrails,omitempty"`
	ErrorMessage      string               `json:"error_message,omitempty"`
}
