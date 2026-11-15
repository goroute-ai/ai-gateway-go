package domain

import "time"

// GuardrailHook identifies the lifecycle stage at which a guardrail executes.
type GuardrailHook string

const (
	GuardrailHookPreCall       GuardrailHook = "pre_call"
	GuardrailHookDuringCall    GuardrailHook = "during_call"
	GuardrailHookPostCall      GuardrailHook = "post_call"
	GuardrailHookLoggingOnly   GuardrailHook = "logging_only"
	GuardrailHookPreMCPCall    GuardrailHook = "pre_mcp_call"
	GuardrailHookDuringMCPCall GuardrailHook = "during_mcp_call"
	GuardrailHookPostMCPCall   GuardrailHook = "post_mcp_call"
)

// IsValid reports whether h is a recognized GuardrailHook value.
func (h GuardrailHook) IsValid() bool {
	switch h {
	case GuardrailHookPreCall,
		GuardrailHookDuringCall,
		GuardrailHookPostCall,
		GuardrailHookLoggingOnly,
		GuardrailHookPreMCPCall,
		GuardrailHookDuringMCPCall,
		GuardrailHookPostMCPCall:
		return true
	default:
		return false
	}
}

// StreamScope controls whether a guardrail evaluates streaming requests, non-streaming requests, or both.
type StreamScope string

const (
	StreamScopeBoth         StreamScope = "both"
	StreamScopeStreaming    StreamScope = "streaming"
	StreamScopeNonStreaming StreamScope = "non_streaming"
)

// IsValid reports whether s is a recognized StreamScope value.
func (s StreamScope) IsValid() bool {
	switch s {
	case StreamScopeBoth, StreamScopeStreaming, StreamScopeNonStreaming:
		return true
	default:
		return false
	}
}

// StreamScopeByHook allows overriding StreamScope on a per-hook basis.
type StreamScopeByHook map[GuardrailHook]StreamScope

// GuardrailModeRule selects execution hooks dynamically based on request tags, falling back to Default.
type GuardrailModeRule struct {
	Tags    map[string][]GuardrailHook `json:"tags,omitempty"`
	Default []GuardrailHook            `json:"default,omitempty"`
}

// GuardrailStatus tracks the approval lifecycle of a GuardrailDefinition.
type GuardrailStatus string

const (
	GuardrailStatusActive        GuardrailStatus = "active"
	GuardrailStatusPendingReview GuardrailStatus = "pending_review"
	GuardrailStatusRejected      GuardrailStatus = "rejected"
)

// IsValid reports whether st is a recognized GuardrailStatus value.
func (st GuardrailStatus) IsValid() bool {
	switch st {
	case GuardrailStatusActive, GuardrailStatusPendingReview, GuardrailStatusRejected:
		return true
	default:
		return false
	}
}

// GuardrailDecision represents the outcome of evaluating one or more guardrails.
type GuardrailDecision string

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

// GuardrailRequestOverride specifies a per-request guardrail opt-in, opt-out, or parameter override
// supplied via goroute_extensions.guardrails.
type GuardrailRequestOverride struct {
	Name    string          `json:"name"`
	Enabled *bool           `json:"enabled,omitempty"`
	Action  GuardrailAction `json:"action,omitempty"`
	Config  map[string]any  `json:"config,omitempty"`
}

// GuardrailDefinition defines a named, tenant-scoped guardrail instance in the registry.
// Multiple definitions within the same organization may share a Name to enable weighted load balancing.
type GuardrailDefinition struct {
	ID                string             `json:"id"`
	OrgID             string             `json:"org_id"`
	Name              string             `json:"name"`
	Provider          string             `json:"provider"`
	EventHooks        []GuardrailHook    `json:"event_hooks,omitempty"`
	StreamScope       StreamScope        `json:"stream_scope,omitempty"`
	StreamScopeByHook StreamScopeByHook  `json:"stream_scope_by_hook,omitempty"`
	ModeRule          *GuardrailModeRule `json:"mode_rule,omitempty"`
	DefaultOn         bool               `json:"default_on"`
	EnabledRoles      []string           `json:"enabled_roles,omitempty"`
	TimeoutMs         int                `json:"timeout_ms,omitempty"`
	FailOpen          bool               `json:"fail_open"`
	Precedence        int                `json:"precedence"`
	Config            map[string]any     `json:"config,omitempty"`
	EncryptedSecrets  string             `json:"-"` // AES-256-GCM Vault encrypted JSON/secret payload
	EncryptedDEK      string             `json:"-"` // AES-256-GCM Vault encrypted DEK
	Status            GuardrailStatus    `json:"status"`
	GuardrailInfo     map[string]any     `json:"guardrail_info,omitempty"`
	Weight            int                `json:"weight"`
	CreatedAt         time.Time          `json:"created_at"`
	UpdatedAt         time.Time          `json:"updated_at"`
}

// EffectiveStreamScope returns the StreamScope for hook, checking StreamScopeByHook first,
// then StreamScope, and defaulting to StreamScopeBoth.
func (d *GuardrailDefinition) EffectiveStreamScope(hook GuardrailHook) StreamScope {
	if d == nil {
		return StreamScopeBoth
	}
	if scope, ok := d.StreamScopeByHook[hook]; ok && scope != "" {
		return scope
	}
	if d.StreamScope != "" {
		return d.StreamScope
	}
	return StreamScopeBoth
}

// GuardrailBinding attaches a GuardrailDefinition to a hierarchical scope
// (team, virtual key, end user, model group, and/or tag) within an organization.
type GuardrailBinding struct {
	ID             string         `json:"id"`
	OrgID          string         `json:"org_id"`
	GuardrailID    string         `json:"guardrail_id"`
	GuardrailName  string         `json:"guardrail_name"`
	TeamID         string         `json:"team_id,omitempty"`
	VirtualKeyID   string         `json:"virtual_key_id,omitempty"`
	EndUserID      string         `json:"end_user_id,omitempty"`
	ModelGroupID   string         `json:"model_group_id,omitempty"`
	Tag            string         `json:"tag,omitempty"`
	ParamOverrides map[string]any `json:"param_overrides,omitempty"`
	IsLocked       bool           `json:"is_locked"`
	CreatedAt      time.Time      `json:"created_at"`
	UpdatedAt      time.Time      `json:"updated_at"`
}

// GuardrailEvalInput is the structured multimodal and tool-aware evaluation envelope
// passed to guardrail scanners and pipeline hooks.
type GuardrailEvalInput struct {
	Direction          string              `json:"direction,omitempty"`
	Hook               GuardrailHook       `json:"hook,omitempty"`
	RequestID          string              `json:"request_id,omitempty"`
	TraceID            string              `json:"trace_id,omitempty"`
	OrgID              string              `json:"org_id,omitempty"`
	TeamID             string              `json:"team_id,omitempty"`
	VirtualKeyID       string              `json:"virtual_key_id,omitempty"`
	EndUserID          string              `json:"end_user_id,omitempty"`
	Model              string              `json:"model,omitempty"`
	Tags               []string            `json:"tags,omitempty"`
	Texts              []string            `json:"texts,omitempty"`
	StructuredMessages []CanonicalMessage  `json:"structured_messages,omitempty"`
	Images             []ImageURL          `json:"images,omitempty"`
	Tools              []CanonicalTool     `json:"tools,omitempty"`
	ToolCalls          []CanonicalToolCall `json:"tool_calls,omitempty"`
	RequestHeaders     map[string]string   `json:"request_headers,omitempty"`
	Metadata           map[string]any      `json:"metadata,omitempty"`
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
	ModifiedToolCalls []CanonicalToolCall  `json:"modified_tool_calls,omitempty"`
	Violations        []GuardrailViolation `json:"violations,omitempty"`
	AppliedGuardrails []string             `json:"applied_guardrails,omitempty"`
	UsageUnits        int64                `json:"usage_units,omitempty"`
	ErrorMessage      string               `json:"error_message,omitempty"`
}
