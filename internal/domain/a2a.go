package domain

import (
	"time"
)

// A2A task visibility modes, lifecycle states, and durable outbox delivery statuses.
const (
	// TaskVisibilityKeyStrict restricts task visibility to the same org and virtual key.
	TaskVisibilityKeyStrict  = "key_strict"  // default: caller org_id && virtual_key_id
	TaskVisibilityUserStrict = "user_strict" // caller org_id && user_id
	TaskVisibilityTeam       = "team"        // caller org_id && team_id
	TaskVisibilityOrgAdmin   = "org_admin"   // all tasks within org_id

	// A2ATaskStateSubmitted and sibling constants match lf.a2a.v1.TaskState and OpenAPI TaskState.
	A2ATaskStateSubmitted     = "submitted"
	A2ATaskStateWorking       = "working"
	A2ATaskStateCompleted     = "completed"
	A2ATaskStateFailed        = "failed"
	A2ATaskStateCanceled      = "canceled"
	A2ATaskStateInputRequired = "input_required"
	A2ATaskStateRejected      = "rejected"
	A2ATaskStateAuthRequired  = "auth_required"

	// A2AProtocolBindingHTTPJSON and sibling constants represent A2A supported interface bindings.
	A2AProtocolBindingHTTPJSON = "HTTP+JSON"
	A2AProtocolBindingJSONRPC  = "JSONRPC"
	A2AProtocolBindingGRPC     = "GRPC"

	// OutboxStatusPending and sibling constants track durable webhook delivery state.
	OutboxStatusPending    = "pending"
	OutboxStatusSent       = "sent"
	OutboxStatusDeadLetter = "dead_letter"
)

// IsTerminalA2ATaskState reports whether a domain A2ATask.State (or wire TaskState) is terminal.
func IsTerminalA2ATaskState(state string) bool {
	switch state {
	case A2ATaskStateCompleted, A2ATaskStateFailed, A2ATaskStateCanceled, A2ATaskStateRejected,
		"TASK_STATE_COMPLETED", "TASK_STATE_FAILED", "TASK_STATE_CANCELED", "TASK_STATE_REJECTED":
		return true
	default:
		return false
	}
}

// A2AAgent defines an upstream Agent-to-Agent protocol service and its security policies.
type A2AAgent struct {
	ID                    string    `json:"id"`
	OrgID                 string    `json:"org_id"`
	Name                  string    `json:"name"`
	Slug                  string    `json:"slug"`
	EndpointURL           string    `json:"endpoint_url"`
	AgentCardURL          string    `json:"agent_card_url,omitempty"`
	AgentCardJSON         string    `json:"agent_card_json,omitempty"`          // Canonical agent card representation
	ExtendedAgentCardJSON string    `json:"extended_agent_card_json,omitempty"` // Authenticated extended agent card
	IsPublicCard          bool      `json:"is_public_card"`                     // Allow unauthenticated /.well-known discovery
	ProtocolBinding       string    `json:"protocol_binding,omitempty"`         // "HTTP+JSON" (default), "JSONRPC", "GRPC"
	TaskVisibilityMode    string    `json:"task_visibility_mode"`               // "key_strict" (default), "user_strict", "team", "org_admin"
	AuthType              string    `json:"auth_type"`                          // "none", "static", "vault_jwt"
	AuthHeaderName        string    `json:"auth_header_name,omitempty"`         // Default "Authorization"
	EncryptedAuthSecret   string    `json:"-"`                                  // Vault encrypted
	EncryptedAuthDEK      string    `json:"-"`                                  // Vault encrypted
	MaxTaskIterations     int       `json:"max_task_iterations"`                // Loop limit prevention (default 50)
	MaxTaskBudgetMicros   int64     `json:"max_task_budget_micros"`
	IsActive              bool      `json:"is_active"`
	IsKilled              bool      `json:"is_killed"` // Immediate kill-switch override
	CreatedAt             time.Time `json:"created_at"`
	UpdatedAt             time.Time `json:"updated_at"`
}

// A2ATask represents a stateful A2A task with durable event log sequencing.
type A2ATask struct {
	ID                string     `json:"id"`
	AgentID           string     `json:"agent_id"`
	OrgID             string     `json:"org_id"`
	TeamID            string     `json:"team_id,omitempty"`
	VirtualKeyID      string     `json:"virtual_key_id"`
	UserID            string     `json:"user_id,omitempty"`
	ClientTaskID      string     `json:"client_task_id,omitempty"`
	ContextID         string     `json:"context_id,omitempty"`
	State             string     `json:"state"`          // A2ATaskState*
	LastEventSeq      int64      `json:"last_event_seq"` // Strictly monotonic sequence counter
	InputMessageJSON  string     `json:"input_message_json,omitempty"`
	OutputMessageJSON string     `json:"output_message_json,omitempty"`
	StatusMessageJSON string     `json:"status_message_json,omitempty"`
	StatusTimestamp   *time.Time `json:"status_timestamp,omitempty"`
	HistoryJSON       string     `json:"history_json,omitempty"`
	ArtifactsJSON     string     `json:"artifacts_json,omitempty"`
	MetadataJSON      string     `json:"metadata_json,omitempty"`
	TotalCostMicros   int64      `json:"total_cost_micros"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
	CompletedAt       *time.Time `json:"completed_at,omitempty"`
}

// A2ATaskListFilter specifies storage query filters and pagination bounds for listing tasks.
type A2ATaskListFilter struct {
	AgentID      string
	OrgID        string
	VirtualKeyID string // Only set by callers under key_strict visibility
	ContextID    string
	State        string
	UpdatedAfter *time.Time
	Limit        int
	Offset       int
}

// A2ATaskEvent represents an immutable event in the task timeline.
type A2ATaskEvent struct {
	ID          string    `json:"id"`
	TaskID      string    `json:"task_id"`
	EventSeq    int64     `json:"event_seq"`
	EventType   string    `json:"event_type"` // "status", "artifact", "message"
	PayloadJSON string    `json:"payload_json"`
	CreatedAt   time.Time `json:"created_at"`
}

// A2AStreamPublication tracks real-time event broadcasts queued for Redis Pub/Sub delivery.
type A2AStreamPublication struct {
	ID            string    `json:"id"`
	TaskID        string    `json:"task_id"`
	EventSeq      int64     `json:"event_seq"`
	PayloadJSON   string    `json:"payload_json"`
	Published     bool      `json:"published"`
	AttemptCount  int       `json:"attempt_count"`
	NextAttemptAt time.Time `json:"next_attempt_at"`
	CreatedAt     time.Time `json:"created_at"`
}

// A2AOutboxEvent represents a pending webhook notification to be delivered by the outbox worker.
type A2AOutboxEvent struct {
	ID            string    `json:"id"`
	TaskID        string    `json:"task_id"`
	PushConfigID  string    `json:"push_config_id,omitempty"`
	EventType     string    `json:"event_type"`
	TargetURL     string    `json:"target_url"`
	PayloadJSON   string    `json:"payload_json"`
	Status        string    `json:"status"` // "pending", "sent", "dead_letter"
	AttemptCount  int       `json:"attempt_count"`
	LastError     string    `json:"last_error,omitempty"`
	NextAttemptAt time.Time `json:"next_attempt_at"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// A2APushNotificationConfig records a registered push destination for task updates.
type A2APushNotificationConfig struct {
	ID                 string    `json:"id"`
	TaskID             string    `json:"task_id"`
	Tenant             string    `json:"tenant,omitempty"`
	TargetURL          string    `json:"target_url"`
	Token              string    `json:"-"` // Secret verification token delivered in X-A2A-Notification-Token
	AuthToken          string    `json:"-"` // Legacy vault-encrypted token fallback
	AuthScheme         string    `json:"auth_scheme,omitempty"`
	EncryptedAuthCreds string    `json:"-"` // Vault encrypted
	EncryptedAuthDEK   string    `json:"-"` // Vault encrypted
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
}
