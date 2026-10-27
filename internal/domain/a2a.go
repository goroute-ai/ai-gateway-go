package domain

import (
	"time"
)

const (
	// TaskVisibilityMode defines multi-tenant visibility isolation for A2A tasks
	TaskVisibilityKeyStrict  = "key_strict"  // default: caller org_id && virtual_key_id
	TaskVisibilityUserStrict = "user_strict" // caller org_id && user_id
	TaskVisibilityTeam       = "team"        // caller org_id && team_id
	TaskVisibilityOrgAdmin   = "org_admin"   // all tasks within org_id

	// Task states matching lf.a2a.v1.TaskState
	A2ATaskStateSubmitted     = "submitted"
	A2ATaskStateWorking       = "working"
	A2ATaskStateCompleted     = "completed"
	A2ATaskStateFailed        = "failed"
	A2ATaskStateCanceled      = "canceled"
	A2ATaskStateInputRequired = "input_required"

	// Outbox event statuses
	OutboxStatusPending    = "pending"
	OutboxStatusSent       = "sent"
	OutboxStatusDeadLetter = "dead_letter"
)

// A2AAgent defines an upstream Agent-to-Agent protocol service and its security policies.
type A2AAgent struct {
	ID                  string    `json:"id"`
	OrgID               string    `json:"org_id"`
	Name                string    `json:"name"`
	Slug                string    `json:"slug"`
	EndpointURL         string    `json:"endpoint_url"`
	AgentCardURL        string    `json:"agent_card_url,omitempty"`
	AgentCardJSON       string    `json:"agent_card_json,omitempty"` // Canonical agent card representation
	TaskVisibilityMode  string    `json:"task_visibility_mode"`      // "key_strict" (default), "user_strict", "team", "org_admin"
	AuthType            string    `json:"auth_type"`                 // "none", "static", "vault_jwt"
	EncryptedAuthSecret string    `json:"-"`                         // Vault encrypted
	EncryptedAuthDEK    string    `json:"-"`                         // Vault encrypted
	MaxTaskIterations   int       `json:"max_task_iterations"`       // Loop limit prevention (default 50)
	MaxTaskBudgetMicros int64     `json:"max_task_budget_micros"`
	IsActive            bool      `json:"is_active"`
	IsKilled            bool      `json:"is_killed"` // Immediate kill-switch override
	CreatedAt           time.Time `json:"created_at"`
	UpdatedAt           time.Time `json:"updated_at"`
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
	State             string     `json:"state"`          // "submitted", "working", "completed", "failed", "canceled", "input_required"
	LastEventSeq      int64      `json:"last_event_seq"` // Strictly monotonic sequence counter
	InputMessageJSON  string     `json:"input_message_json,omitempty"`
	OutputMessageJSON string     `json:"output_message_json,omitempty"`
	TotalCostMicros   int64      `json:"total_cost_micros"`
	CreatedAt         time.Time  `json:"created_at"`
	UpdatedAt         time.Time  `json:"updated_at"`
	CompletedAt       *time.Time `json:"completed_at,omitempty"`
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
	EventType     string    `json:"event_type"`
	TargetURL     string    `json:"target_url"`
	PayloadJSON   string    `json:"payload_json"`
	Status        string    `json:"status"` // "pending", "sent", "dead_letter"
	AttemptCount  int       `json:"attempt_count"`
	NextAttemptAt time.Time `json:"next_attempt_at"`
	CreatedAt     time.Time `json:"created_at"`
}

// A2APushNotificationConfig records a registered push destination for task updates.
type A2APushNotificationConfig struct {
	ID        string    `json:"id"`
	TaskID    string    `json:"task_id"`
	TargetURL string    `json:"target_url"`
	AuthToken string    `json:"-"` // Vault encrypted or secret token
	CreatedAt time.Time `json:"created_at"`
}
