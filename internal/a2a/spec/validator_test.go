package a2aspec

import (
	"encoding/json"
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateAllCompiled(t *testing.T) {
	require.NoError(t, ValidateAllCompiled())
}

func TestDecodeStrict_SendMessageRequest(t *testing.T) {
	validPayload := []byte(`{
		"message": {
			"messageId": "msg_1",
			"role": "ROLE_USER",
			"parts": [{"text": "hello"}]
		}
	}`)
	req, err := DecodeStrict[SendMessageRequest]("SendMessageRequest", validPayload)
	require.NoError(t, err)
	require.Equal(t, "msg_1", req.Message.MessageId)
	require.Equal(t, ROLEUSER, req.Message.Role)
	require.Len(t, req.Message.Parts, 1)
	txt, ok := PartText(req.Message.Parts[0])
	require.True(t, ok)
	assert.Equal(t, "hello", txt)

	// Unknown field MUST be rejected
	unknownField := []byte(`{
		"message": {
			"messageId": "msg_2",
			"role": "ROLE_USER",
			"parts": [{"text": "hello"}]
		},
		"injectedField": true
	}`)
	_, err = DecodeStrict[SendMessageRequest]("SendMessageRequest", unknownField)
	require.Error(t, err)

	// Multiple oneOf fields in Part MUST be rejected
	multiOneOfPart := []byte(`{
		"message": {
			"messageId": "msg_3",
			"role": "ROLE_USER",
			"parts": [{"text": "hello", "url": "https://example.com/a.txt"}]
		}
	}`)
	_, err = DecodeStrict[SendMessageRequest]("SendMessageRequest", multiOneOfPart)
	require.Error(t, err)

	// Arbitrary keys inside Metadata MUST still be allowed
	withMetadata := []byte(`{
		"message": {
			"messageId": "msg_4",
			"role": "ROLE_USER",
			"parts": [{"text": "hello"}],
			"metadata": {"customKey": {"nested": 123}}
		}
	}`)
	reqMeta, err := DecodeStrict[SendMessageRequest]("SendMessageRequest", withMetadata)
	require.NoError(t, err)
	require.NotNil(t, reqMeta.Message.Metadata)
}

func TestDecodeStrict_SendMessageResponse_OneOf(t *testing.T) {
	both := []byte(`{
		"task": {"id": "t1", "status": {"state": "TASK_STATE_SUBMITTED"}},
		"message": {"messageId": "m1", "role": "ROLE_AGENT", "parts": [{"text": "hi"}]}
	}`)
	_, err := DecodeStrict[SendMessageResponse]("SendMessageResponse", both)
	require.Error(t, err)

	validTask := []byte(`{"task": {"id": "t1", "status": {"state": "TASK_STATE_COMPLETED"}}}`)
	resp, err := DecodeStrict[SendMessageResponse]("SendMessageResponse", validTask)
	require.NoError(t, err)
	require.NotNil(t, resp.Task)
	assert.Equal(t, "t1", resp.Task.Id)

	// Verify ClearUnion allows clean mutation + re-marshal
	resp.Task.Id = "t_rewritten"
	resp.ClearUnion()
	b, err := json.Marshal(resp)
	require.NoError(t, err)
	assert.Contains(t, string(b), `"t_rewritten"`)
	assert.NotContains(t, string(b), `"t1"`)
}

func TestTaskStateHelpers(t *testing.T) {
	states := []struct {
		spec     TaskState
		domain   string
		terminal bool
	}{
		{TASKSTATESUBMITTED, domain.A2ATaskStateSubmitted, false},
		{TASKSTATEWORKING, domain.A2ATaskStateWorking, false},
		{TASKSTATEINPUTREQUIRED, domain.A2ATaskStateInputRequired, false},
		{TASKSTATEAUTHREQUIRED, domain.A2ATaskStateAuthRequired, false},
		{TASKSTATECOMPLETED, domain.A2ATaskStateCompleted, true},
		{TASKSTATEFAILED, domain.A2ATaskStateFailed, true},
		{TASKSTATECANCELED, domain.A2ATaskStateCanceled, true},
		{TASKSTATEREJECTED, domain.A2ATaskStateRejected, true},
	}
	for _, tc := range states {
		d := TaskStateToDomain(tc.spec)
		assert.Equal(t, tc.domain, d)
		assert.Equal(t, tc.spec, DomainToTaskState(d))
		assert.Equal(t, tc.terminal, IsTerminalTaskState(tc.spec))
		assert.Equal(t, tc.terminal, IsTerminalDomainState(d))
	}
}
