package a2a

import (
	"fmt"
	"strings"

	"github.com/goroute-ai/ai-gateway-go/internal/a2a/pb"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

const (
	// A2A JSON-RPC Protocol Error Codes
	CodeBudgetExceeded             = -32000 // Task has exceeded allocated budget or maximum iterations
	CodeTaskNotFound               = -32001 // Requested task ID not found or forbidden by visibility policy
	CodeTaskCancelled              = -32002 // Task was cancelled
	CodeTaskAlreadyCompleted       = -32003 // Operation cannot be performed because task is completed
	CodeTaskStateTransitionInvalid = -32004 // Illegal task state transition
	CodeInvalidTaskPayload         = -32005 // Malformed or invalid task message/artifact payload
	CodePushNotificationFailed     = -32006 // Failed to deliver or register push notification
	CodeStreamingUnsupported       = -32007 // Agent does not support streaming
	CodeExtensionNotSupported      = -32008 // Requested extension URI not supported by agent
	CodeExtensionVersionMismatch   = -32009 // Extension version incompatible
	CodeAgentKilled                = -32010 // Agent disabled via admin emergency kill-switch
)

// A2AError represents an error conforming to the A2A JSON-RPC 2.0 specification.
type A2AError struct {
	Code    int            `json:"code"`
	Message string         `json:"message"`
	Data    map[string]any `json:"data,omitempty"`
}

func (e *A2AError) Error() string {
	return fmt.Sprintf("A2A error %d: %s", e.Code, e.Message)
}

// ValidateStateTransition checks whether a proposed task state transition is legal per A2A v1.0.
func ValidateStateTransition(from, to pb.TaskState) error {
	// Identity transition (no-op) is always legal
	if from == to {
		return nil
	}

	// Terminal states CANNOT transition to any other state
	if isTerminal(from) {
		return &A2AError{
			Code:    CodeTaskStateTransitionInvalid,
			Message: fmt.Sprintf("Illegal transition: task in terminal state %s cannot transition to %s", from.String(), to.String()),
		}
	}

	switch from {
	case pb.TaskState_TASK_STATE_UNSPECIFIED, pb.TaskState_TASK_STATE_SUBMITTED:
		switch to {
		case pb.TaskState_TASK_STATE_WORKING,
			pb.TaskState_TASK_STATE_INPUT_REQUIRED,
			pb.TaskState_TASK_STATE_COMPLETED,
			pb.TaskState_TASK_STATE_FAILED,
			pb.TaskState_TASK_STATE_CANCELED:
			return nil
		}
	case pb.TaskState_TASK_STATE_WORKING:
		switch to {
		case pb.TaskState_TASK_STATE_INPUT_REQUIRED,
			pb.TaskState_TASK_STATE_COMPLETED,
			pb.TaskState_TASK_STATE_FAILED,
			pb.TaskState_TASK_STATE_CANCELED:
			return nil
		}
	case pb.TaskState_TASK_STATE_INPUT_REQUIRED:
		switch to {
		case pb.TaskState_TASK_STATE_WORKING,
			pb.TaskState_TASK_STATE_COMPLETED,
			pb.TaskState_TASK_STATE_FAILED,
			pb.TaskState_TASK_STATE_CANCELED:
			return nil
		}
	}

	return &A2AError{
		Code:    CodeTaskStateTransitionInvalid,
		Message: fmt.Sprintf("Illegal task state transition from %s to %s", from.String(), to.String()),
	}
}

func isTerminal(s pb.TaskState) bool {
	return s == pb.TaskState_TASK_STATE_COMPLETED ||
		s == pb.TaskState_TASK_STATE_FAILED ||
		s == pb.TaskState_TASK_STATE_CANCELED
}

// CheckTaskVisibility checks whether the caller identity is authorized to view or mutate the task
// under the agent's configured TaskVisibilityMode.
// Returns false if forbidden, which causes a 404 / CodeTaskNotFound to prevent information leakage.
func CheckTaskVisibility(task *domain.A2ATask, idCtx *domain.IdentityContext, mode string) bool {
	if task == nil || idCtx == nil {
		return false
	}

	// Cross-tenant protection: caller and task must belong to the exact same organization
	if task.OrgID != "" && idCtx.OrgID != "" && task.OrgID != idCtx.OrgID {
		return false
	}

	if mode == "" {
		mode = domain.TaskVisibilityKeyStrict
	}

	switch mode {
	case domain.TaskVisibilityKeyStrict:
		// Only the exact same Virtual Key that created the task can access it
		return task.VirtualKeyID != "" && idCtx.VirtualKeyID != "" && task.VirtualKeyID == idCtx.VirtualKeyID

	case domain.TaskVisibilityUserStrict:
		// Any Virtual Key belonging to the same user can access it
		if task.UserID != "" && idCtx.UserID != "" && task.UserID == idCtx.UserID {
			return true
		}
		// Fallback to key match if user ID is not set
		return task.VirtualKeyID == idCtx.VirtualKeyID

	case domain.TaskVisibilityTeam:
		// Any Virtual Key belonging to the same team can access it
		if task.TeamID != "" && idCtx.TeamID != "" && task.TeamID == idCtx.TeamID {
			return true
		}
		// Fallback to user or key match
		return (task.UserID != "" && task.UserID == idCtx.UserID) || task.VirtualKeyID == idCtx.VirtualKeyID

	case domain.TaskVisibilityOrgAdmin:
		// Any authenticated caller within the organization can view/access
		return true

	default:
		// Unknown mode fails closed to key_strict
		return task.VirtualKeyID == idCtx.VirtualKeyID
	}
}

// ValidateExtensions verifies that all requested extension URIs and versions are supported by the target agent.
func ValidateExtensions(requestedURIs []string, supportedExts []*pb.AgentExtension) error {
	if len(requestedURIs) == 0 {
		return nil
	}

	supportedMap := make(map[string]*pb.AgentExtension)
	for _, ext := range supportedExts {
		if ext != nil && ext.Uri != "" {
			supportedMap[strings.ToLower(ext.Uri)] = ext
		}
	}

	for _, uri := range requestedURIs {
		_, ok := supportedMap[strings.ToLower(uri)]
		if !ok {
			return &A2AError{
				Code:    CodeExtensionNotSupported,
				Message: fmt.Sprintf("Extension URI %q is not supported by this agent", uri),
			}
		}
	}

	return nil
}
