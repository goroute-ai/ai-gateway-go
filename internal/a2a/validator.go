package a2a

import (
	"fmt"
	"strings"

	a2aspec "github.com/goroute-ai/ai-gateway-go/internal/a2a/spec"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

// ValidateStateTransition checks whether a proposed task state transition is legal per A2A v1.0
// across all 8 non-unspecified TaskState values (including AUTH_REQUIRED and REJECTED).
func ValidateStateTransition(from, to a2aspec.TaskState) error {
	if from == to {
		return nil
	}
	if a2aspec.IsTerminalTaskState(from) {
		return ErrTaskNotCancelable(
			fmt.Sprintf("illegal transition: task in terminal state %s cannot transition to %s", from, to),
			"",
		)
	}

	switch from {
	case a2aspec.TASKSTATEUNSPECIFIED, a2aspec.TASKSTATESUBMITTED:
		switch to {
		case a2aspec.TASKSTATEWORKING,
			a2aspec.TASKSTATEINPUTREQUIRED,
			a2aspec.TASKSTATEAUTHREQUIRED,
			a2aspec.TASKSTATECOMPLETED,
			a2aspec.TASKSTATEFAILED,
			a2aspec.TASKSTATECANCELED,
			a2aspec.TASKSTATEREJECTED:
			return nil
		}
	case a2aspec.TASKSTATEWORKING:
		switch to {
		case a2aspec.TASKSTATEINPUTREQUIRED,
			a2aspec.TASKSTATEAUTHREQUIRED,
			a2aspec.TASKSTATECOMPLETED,
			a2aspec.TASKSTATEFAILED,
			a2aspec.TASKSTATECANCELED,
			a2aspec.TASKSTATEREJECTED:
			return nil
		}
	case a2aspec.TASKSTATEINPUTREQUIRED, a2aspec.TASKSTATEAUTHREQUIRED:
		switch to {
		case a2aspec.TASKSTATEWORKING,
			a2aspec.TASKSTATEINPUTREQUIRED,
			a2aspec.TASKSTATEAUTHREQUIRED,
			a2aspec.TASKSTATECOMPLETED,
			a2aspec.TASKSTATEFAILED,
			a2aspec.TASKSTATECANCELED,
			a2aspec.TASKSTATEREJECTED:
			return nil
		}
	}

	return ErrInvalidParams(fmt.Sprintf("illegal task state transition from %s to %s", from, to))
}

// CheckTaskVisibility checks that:
// 1. Both task and agent exist and belong to the caller's exact non-empty organization.
// 2. task.AgentID matches agent.ID (closing C1 cross-agent task visibility bypass).
// 3. The caller identity is permitted by agent.TaskVisibilityMode.
func CheckTaskVisibility(task *domain.A2ATask, agent *domain.A2AAgent, idCtx *domain.IdentityContext) bool {
	if task == nil || agent == nil || idCtx == nil {
		return false
	}

	if task.AgentID == "" || agent.ID == "" || task.AgentID != agent.ID {
		return false
	}

	if task.OrgID == "" || idCtx.OrgID == "" || task.OrgID != idCtx.OrgID || agent.OrgID != idCtx.OrgID {
		return false
	}

	mode := agent.TaskVisibilityMode
	if mode == "" {
		mode = domain.TaskVisibilityKeyStrict
	}

	keyMatch := task.VirtualKeyID != "" && idCtx.VirtualKeyID != "" && task.VirtualKeyID == idCtx.VirtualKeyID

	switch mode {
	case domain.TaskVisibilityKeyStrict:
		return keyMatch
	case domain.TaskVisibilityUserStrict:
		if task.UserID != "" && idCtx.UserID != "" && task.UserID == idCtx.UserID {
			return true
		}
		return keyMatch
	case domain.TaskVisibilityTeam:
		if task.TeamID != "" && idCtx.TeamID != "" && task.TeamID == idCtx.TeamID {
			return true
		}
		return (task.UserID != "" && idCtx.UserID != "" && task.UserID == idCtx.UserID) || keyMatch
	case domain.TaskVisibilityOrgAdmin:
		return idCtx.Role == domain.RolePlatformAdmin || idCtx.Role == domain.RoleOrgAdmin
	default:
		return keyMatch
	}
}

// ValidateExtensions verifies:
// 1. Every requested extension URI in A2A-Extensions / message.extensions is declared by the agent card.
// 2. Every required extension (`ext.Required == true`) on the agent card is declared by the caller.
func ValidateExtensions(requestedURIs []string, card *a2aspec.AgentCard) error {
	var supportedExts []a2aspec.AgentExtension
	if card != nil && card.Capabilities.Extensions != nil {
		supportedExts = *card.Capabilities.Extensions
	}

	supportedMap := make(map[string]a2aspec.AgentExtension, len(supportedExts))
	for _, ext := range supportedExts {
		if ext.Uri != nil && *ext.Uri != "" {
			supportedMap[strings.ToLower(*ext.Uri)] = ext
		}
	}

	requestedSet := make(map[string]struct{}, len(requestedURIs))
	for _, uri := range requestedURIs {
		norm := strings.ToLower(strings.TrimSpace(uri))
		if norm == "" {
			continue
		}
		requestedSet[norm] = struct{}{}
		if _, ok := supportedMap[norm]; !ok {
			return ErrExtensionSupportRequired(
				fmt.Sprintf("extension URI %q is not supported by this agent", uri),
				uri,
			)
		}
	}

	for normURI, ext := range supportedMap {
		if ext.Required != nil && *ext.Required {
			if _, ok := requestedSet[normURI]; !ok {
				rawURI := normURI
				if ext.Uri != nil {
					rawURI = *ext.Uri
				}
				return ErrExtensionSupportRequired(
					fmt.Sprintf("agent requires client support for extension URI %q via A2A-Extensions", rawURI),
					rawURI,
				)
			}
		}
	}

	return nil
}
