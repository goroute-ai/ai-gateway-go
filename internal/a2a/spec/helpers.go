package a2aspec

import (
	"net/mail"
	"strings"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

// SupportedA2AVersion is the canonical protocol version implemented by this package.
const SupportedA2AVersion = "1.0"

// NewTextPart creates an OpenAPI-compliant text Part.
func NewTextPart(text string) Part {
	return Part{Text: &text}
}

// PartText extracts the text value from a Part when present.
func PartText(p Part) (string, bool) {
	if p.Text == nil {
		return "", false
	}
	return *p.Text, true
}

// SetPartText replaces the text value on a Part in place.
func SetPartText(p *Part, text string) {
	if p == nil || p.Text == nil {
		return
	}
	*p.Text = text
}

// NewSendMessageResponseTask constructs a SendMessageResponse carrying a Task.
func NewSendMessageResponseTask(t *Task) *SendMessageResponse {
	return &SendMessageResponse{Task: t}
}

// NewSendMessageResponseMessage constructs a SendMessageResponse carrying a Message.
func NewSendMessageResponseMessage(m *Message) *SendMessageResponse {
	return &SendMessageResponse{Message: m}
}

// ClearUnion resets oapi-codegen's internal union raw cache on pointer targets where
// typed fields were mutated after JSON unmarshaling, ensuring MarshalJSON serializes
// the updated struct fields cleanly without stale union keys.
func (t *SendMessageResponse) ClearUnion() {
	if t != nil {
		t.union = nil
	}
}

// ClearUnion resets oapi-codegen's internal union raw cache on StreamResponse.
func (t *StreamResponse) ClearUnion() {
	if t != nil {
		t.union = nil
	}
}

// ClearUnion resets oapi-codegen's internal union raw cache on Part.
func (t *Part) ClearUnion() {
	if t != nil {
		t.union = nil
	}
}

// ClearUnion resets oapi-codegen's internal union raw cache on SecurityScheme.
func (t *SecurityScheme) ClearUnion() {
	if t != nil {
		t.union = nil
	}
}

// TaskStateToDomain converts an A2A v1.0 TaskState enum into a domain state string.
func TaskStateToDomain(s TaskState) string {
	switch s {
	case TASKSTATESUBMITTED:
		return domain.A2ATaskStateSubmitted
	case TASKSTATEWORKING:
		return domain.A2ATaskStateWorking
	case TASKSTATEINPUTREQUIRED:
		return domain.A2ATaskStateInputRequired
	case TASKSTATEAUTHREQUIRED:
		return domain.A2ATaskStateAuthRequired
	case TASKSTATECOMPLETED:
		return domain.A2ATaskStateCompleted
	case TASKSTATEFAILED:
		return domain.A2ATaskStateFailed
	case TASKSTATECANCELED:
		return domain.A2ATaskStateCanceled
	case TASKSTATEREJECTED:
		return domain.A2ATaskStateRejected
	default:
		return domain.A2ATaskStateSubmitted
	}
}

// DomainToTaskState converts a domain task state string into an A2A v1.0 TaskState enum.
func DomainToTaskState(s string) TaskState {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case domain.A2ATaskStateSubmitted:
		return TASKSTATESUBMITTED
	case domain.A2ATaskStateWorking:
		return TASKSTATEWORKING
	case domain.A2ATaskStateInputRequired:
		return TASKSTATEINPUTREQUIRED
	case domain.A2ATaskStateAuthRequired:
		return TASKSTATEAUTHREQUIRED
	case domain.A2ATaskStateCompleted:
		return TASKSTATECOMPLETED
	case domain.A2ATaskStateFailed:
		return TASKSTATEFAILED
	case domain.A2ATaskStateCanceled:
		return TASKSTATECANCELED
	case domain.A2ATaskStateRejected:
		return TASKSTATEREJECTED
	default:
		return TASKSTATEUNSPECIFIED
	}
}

// IsTerminalTaskState reports whether state is an A2A v1.0 terminal state.
func IsTerminalTaskState(state TaskState) bool {
	switch state {
	case TASKSTATECOMPLETED, TASKSTATEFAILED, TASKSTATECANCELED, TASKSTATEREJECTED:
		return true
	default:
		return false
	}
}

// IsTerminalDomainState reports whether a domain state string is terminal.
func IsTerminalDomainState(state string) bool {
	return IsTerminalTaskState(DomainToTaskState(state))
}

// IsSupportedA2AVersion validates an incoming A2A-Version header value.
// Empty header defaults to 1.0 per A2A v1.0 Section 3.3.2.
func IsSupportedA2AVersion(v string) bool {
	trimmed := strings.TrimSpace(v)
	if trimmed == "" || trimmed == SupportedA2AVersion {
		return true
	}
	return strings.HasPrefix(trimmed, "1.0.")
}

// ParseExtensionsHeader splits a comma-separated A2A-Extensions header value.
func ParseExtensionsHeader(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	seen := make(map[string]struct{}, len(parts))
	for _, p := range parts {
		uri := strings.TrimSpace(p)
		if uri == "" {
			continue
		}
		// Reject header values accidentally containing display names like "<url>"
		if addr, err := mail.ParseAddress(uri); err == nil && addr.Address != "" {
			uri = addr.Address
		}
		key := strings.ToLower(uri)
		if _, exists := seen[key]; !exists {
			seen[key] = struct{}{}
			out = append(out, uri)
		}
	}
	return out
}
