package gateway

import "time"

// Canonical A2A v1.0 role and task state string constants aligned with docs/openapi/a2a.openapi.yaml.
const (
	A2ARoleUser  = "ROLE_USER"
	A2ARoleAgent = "ROLE_AGENT"

	A2ATaskStateSubmitted     = "TASK_STATE_SUBMITTED"
	A2ATaskStateWorking       = "TASK_STATE_WORKING"
	A2ATaskStateCompleted     = "TASK_STATE_COMPLETED"
	A2ATaskStateFailed        = "TASK_STATE_FAILED"
	A2ATaskStateCanceled      = "TASK_STATE_CANCELED"
	A2ATaskStateInputRequired = "TASK_STATE_INPUT_REQUIRED"
	A2ATaskStateRejected      = "TASK_STATE_REJECTED"
	A2ATaskStateAuthRequired  = "TASK_STATE_AUTH_REQUIRED"
)

// A2APart represents a single union content element inside an A2A v1.0 Message or Artifact.
type A2APart struct {
	Text      string         `json:"text,omitempty"`
	Raw       string         `json:"raw,omitempty"`
	Url       string         `json:"url,omitempty"`
	Data      any            `json:"data,omitempty"`
	Filename  string         `json:"filename,omitempty"`
	MediaType string         `json:"mediaType,omitempty"`
	Metadata  map[string]any `json:"metadata,omitempty"`
}

// A2AMessage represents a single A2A v1.0 turn between user and agent.
type A2AMessage struct {
	MessageId        string         `json:"messageId"`
	Role             string         `json:"role"`
	Parts            []A2APart      `json:"parts"`
	ContextId        string         `json:"contextId,omitempty"`
	TaskId           string         `json:"taskId,omitempty"`
	Extensions       []string       `json:"extensions,omitempty"`
	ReferenceTaskIds []string       `json:"referenceTaskIds,omitempty"`
	Metadata         map[string]any `json:"metadata,omitempty"`
}

// A2AArtifact represents an agent-produced output artifact attached to an A2A task.
type A2AArtifact struct {
	ArtifactId  string         `json:"artifactId"`
	Name        string         `json:"name,omitempty"`
	Description string         `json:"description,omitempty"`
	Parts       []A2APart      `json:"parts"`
	Extensions  []string       `json:"extensions,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty"`
}

// A2ATaskStatus represents a task lifecycle state snapshot.
type A2ATaskStatus struct {
	State     string      `json:"state"`
	Message   *A2AMessage `json:"message,omitempty"`
	Timestamp string      `json:"timestamp,omitempty"`
}

// A2ATask represents a stateful A2A v1.0 task.
type A2ATask struct {
	Id        string         `json:"id"`
	ContextId string         `json:"contextId,omitempty"`
	Status    A2ATaskStatus  `json:"status"`
	History   []A2AMessage   `json:"history,omitempty"`
	Artifacts []A2AArtifact  `json:"artifacts,omitempty"`
	Metadata  map[string]any `json:"metadata,omitempty"`
}

// A2APushAuthenticationInfo describes outbound webhook authentication settings.
type A2APushAuthenticationInfo struct {
	Scheme      string `json:"scheme"`
	Credentials string `json:"credentials,omitempty"`
}

// A2ATaskPushNotificationConfig describes a registered push webhook configuration.
type A2ATaskPushNotificationConfig struct {
	Id             string                     `json:"id,omitempty"`
	TaskId         string                     `json:"taskId,omitempty"`
	Tenant         string                     `json:"tenant,omitempty"`
	Url            string                     `json:"url"`
	Token          string                     `json:"token,omitempty"`
	Authentication *A2APushAuthenticationInfo `json:"authentication,omitempty"`
}

// A2ASendMessageConfiguration configures synchronous/streaming delivery preferences on SendMessage.
type A2ASendMessageConfiguration struct {
	AcceptedOutputModes    []string                       `json:"acceptedOutputModes,omitempty"`
	HistoryLength          *int32                         `json:"historyLength,omitempty"`
	ReturnImmediately      *bool                          `json:"returnImmediately,omitempty"`
	PushNotificationConfig *A2ATaskPushNotificationConfig `json:"taskPushNotificationConfig,omitempty"`
}

// A2ASendMessageRequest represents a canonical A2A v1.0 SendMessage / SendStreamingMessage payload.
type A2ASendMessageRequest struct {
	Tenant        string                       `json:"tenant,omitempty"`
	Message       A2AMessage                   `json:"message"`
	Configuration *A2ASendMessageConfiguration `json:"configuration,omitempty"`
	Metadata      map[string]any               `json:"metadata,omitempty"`
}

// A2ASendMessageResponse holds either a Task or a Message returned synchronously from SendMessage.
type A2ASendMessageResponse struct {
	Task    *A2ATask    `json:"task,omitempty"`
	Message *A2AMessage `json:"message,omitempty"`
}

// A2ATaskStatusUpdateEvent represents an incremental task state frame emitted during streaming.
type A2ATaskStatusUpdateEvent struct {
	TaskId    string         `json:"taskId"`
	ContextId string         `json:"contextId"`
	Status    A2ATaskStatus  `json:"status"`
	Final     bool           `json:"final,omitempty"`
	Metadata  map[string]any `json:"metadata,omitempty"`
}

// A2ATaskArtifactUpdateEvent represents an incremental artifact chunk emitted during streaming.
type A2ATaskArtifactUpdateEvent struct {
	TaskId    string         `json:"taskId"`
	ContextId string         `json:"contextId"`
	Artifact  A2AArtifact    `json:"artifact"`
	Append    bool           `json:"append,omitempty"`
	LastChunk bool           `json:"lastChunk,omitempty"`
	Metadata  map[string]any `json:"metadata,omitempty"`
}

// A2AStreamResponse represents a single Server-Sent Event frame from SendStreamingMessage or SubscribeToTask.
type A2AStreamResponse struct {
	Task           *A2ATask                    `json:"task,omitempty"`
	Message        *A2AMessage                 `json:"message,omitempty"`
	StatusUpdate   *A2ATaskStatusUpdateEvent   `json:"statusUpdate,omitempty"`
	ArtifactUpdate *A2ATaskArtifactUpdateEvent `json:"artifactUpdate,omitempty"`
}

// A2AListTasksRequest specifies filters and pagination for ListA2ATasks.
type A2AListTasksRequest struct {
	ContextId            string `json:"contextId,omitempty"`
	Status               string `json:"status,omitempty"`
	PageSize             int32  `json:"pageSize,omitempty"`
	PageToken            string `json:"pageToken,omitempty"`
	HistoryLength        *int32 `json:"historyLength,omitempty"`
	StatusTimestampAfter string `json:"statusTimestampAfter,omitempty"`
	IncludeArtifacts     bool   `json:"includeArtifacts,omitempty"`
}

// A2AListTasksResponse returns paginated A2A tasks.
type A2AListTasksResponse struct {
	Tasks         []A2ATask `json:"tasks"`
	NextPageToken string    `json:"nextPageToken"`
	PageSize      int32     `json:"pageSize"`
	TotalSize     int32     `json:"totalSize"`
}

// A2AListTaskPushNotificationConfigsResponse returns paginated push notification configs for a task.
type A2AListTaskPushNotificationConfigsResponse struct {
	Configs       []A2ATaskPushNotificationConfig `json:"configs,omitempty"`
	NextPageToken string                          `json:"nextPageToken,omitempty"`
}

// A2AOutboxEvent mirrors durable push webhook delivery tracking returned by Admin APIs.
type A2AOutboxEvent struct {
	ID            string    `json:"id"`
	TaskID        string    `json:"task_id"`
	PushConfigID  string    `json:"push_config_id,omitempty"`
	EventType     string    `json:"event_type"`
	TargetURL     string    `json:"target_url"`
	PayloadJSON   string    `json:"payload_json"`
	Status        string    `json:"status"`
	AttemptCount  int       `json:"attempt_count"`
	LastError     string    `json:"last_error,omitempty"`
	NextAttemptAt time.Time `json:"next_attempt_at"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// NewA2ATextMessage constructs a user or agent text Message with a generated or supplied ID.
func NewA2ATextMessage(messageID, role, text string) A2AMessage {
	return A2AMessage{
		MessageId: messageID,
		Role:      role,
		Parts:     []A2APart{{Text: text}},
	}
}
