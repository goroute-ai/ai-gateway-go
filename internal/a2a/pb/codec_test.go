package pb_test

import (
	"testing"

	"github.com/goroute-ai/ai-gateway-go/internal/a2a/pb"
	"google.golang.org/protobuf/encoding/protojson"
)

func TestProtoJSONStrictCodec(t *testing.T) {
	strictUnmarshal := protojson.UnmarshalOptions{
		DiscardUnknown: false,
	}

	marshalOpts := protojson.MarshalOptions{
		UseProtoNames:   false,
		EmitUnpopulated: false,
	}

	t.Run("SendMessageRequest round-trip", func(t *testing.T) {
		req := &pb.SendMessageRequest{
			Message: &pb.Message{
				Role: pb.Role_ROLE_USER,
				Parts: []*pb.Part{
					{
						Content: &pb.Part_Text{
							Text: "Hello, agent!",
						},
					},
				},
			},
		}

		data, err := marshalOpts.Marshal(req)
		if err != nil {
			t.Fatalf("marshal failed: %v", err)
		}

		var decoded pb.SendMessageRequest
		if err := strictUnmarshal.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("strict unmarshal failed: %v", err)
		}

		if decoded.GetMessage() == nil || len(decoded.GetMessage().GetParts()) == 0 {
			t.Fatalf("expected decoded message with parts, got %+v", &decoded)
		}
		if decoded.GetMessage().GetParts()[0].GetText() != "Hello, agent!" {
			t.Fatalf("expected text 'Hello, agent!', got %q", decoded.GetMessage().GetParts()[0].GetText())
		}
	})

	t.Run("Rejects unknown fields in strict mode", func(t *testing.T) {
		payloadWithUnknown := []byte(`{
			"message": {
				"role": "ROLE_USER",
				"parts": [
					{"text": "test"}
				],
				"unexpected_sneaky_field": "malicious_payload"
			}
		}`)

		var decoded pb.SendMessageRequest
		err := strictUnmarshal.Unmarshal(payloadWithUnknown, &decoded)
		if err == nil {
			t.Fatalf("expected strict protojson to reject unknown field 'unexpected_sneaky_field', got nil error")
		}
	})

	t.Run("Task state serialization", func(t *testing.T) {
		task := &pb.Task{
			Id: "task_12345",
			Status: &pb.TaskStatus{
				State: pb.TaskState_TASK_STATE_WORKING,
			},
		}

		data, err := marshalOpts.Marshal(task)
		if err != nil {
			t.Fatalf("marshal failed: %v", err)
		}

		var decoded pb.Task
		if err := strictUnmarshal.Unmarshal(data, &decoded); err != nil {
			t.Fatalf("strict unmarshal failed: %v", err)
		}

		if decoded.GetId() != "task_12345" || decoded.GetStatus().GetState() != pb.TaskState_TASK_STATE_WORKING {
			t.Fatalf("unexpected decoded task: %+v", &decoded)
		}
	})
}
