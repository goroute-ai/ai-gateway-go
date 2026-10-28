package a2a

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/goroute-ai/ai-gateway-go/internal/a2a/pb"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

var (
	// StrictProtoJSONUnmarshaler strictly rejects unknown fields per production gateway specification.
	StrictProtoJSONUnmarshaler = protojson.UnmarshalOptions{
		DiscardUnknown: false,
	}

	// ProtoJSONMarshaler produces standard JSON representation without emitting unpopulated fields.
	ProtoJSONMarshaler = protojson.MarshalOptions{
		EmitUnpopulated: false,
		UseProtoNames:   false,
	}
)

// JSONRPCRequest represents an A2A JSON-RPC 2.0 incoming request.
type JSONRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// JSONRPCResponse represents an A2A JSON-RPC 2.0 outgoing response.
type JSONRPCResponse struct {
	JSONRPC string        `json:"jsonrpc"`
	ID      any           `json:"id,omitempty"`
	Result  any           `json:"result,omitempty"`
	Error   *JSONRPCError `json:"error,omitempty"`
}

// JSONRPCError represents an error object in an A2A JSON-RPC response.
type JSONRPCError struct {
	Code    int            `json:"code"`
	Message string         `json:"message"`
	Data    map[string]any `json:"data,omitempty"`
}

func (e *JSONRPCError) Error() string {
	return fmt.Sprintf("A2A JSON-RPC error %d: %s", e.Code, e.Message)
}

// ParseStrictProtoJSON decodes raw bytes into a protobuf message, rejecting any unknown fields.
func ParseStrictProtoJSON(data []byte, msg proto.Message) error {
	if len(data) == 0 {
		return nil
	}
	return StrictProtoJSONUnmarshaler.Unmarshal(data, msg)
}

// FormatProtoJSON marshals a protobuf message into canonical JSON bytes.
func FormatProtoJSON(msg proto.Message) ([]byte, error) {
	if msg == nil {
		return []byte("{}"), nil
	}
	return ProtoJSONMarshaler.Marshal(msg)
}

// ReadStrictBody reads the request body and decodes it strictly into a protobuf message.
func ReadStrictBody(r *http.Request, maxBytes int64, msg proto.Message) error {
	if maxBytes <= 0 {
		maxBytes = 10 * 1024 * 1024
	}
	r.Body = http.MaxBytesReader(nil, r.Body, maxBytes)
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		return fmt.Errorf("failed to read body: %w", err)
	}
	return ParseStrictProtoJSON(bodyBytes, msg)
}

// TaskStateToString maps protobuf TaskState enum to domain string representation.
func TaskStateToString(s pb.TaskState) string {
	switch s {
	case pb.TaskState_TASK_STATE_SUBMITTED:
		return domain.A2ATaskStateSubmitted
	case pb.TaskState_TASK_STATE_WORKING:
		return domain.A2ATaskStateWorking
	case pb.TaskState_TASK_STATE_INPUT_REQUIRED:
		return domain.A2ATaskStateInputRequired
	case pb.TaskState_TASK_STATE_COMPLETED:
		return domain.A2ATaskStateCompleted
	case pb.TaskState_TASK_STATE_FAILED:
		return domain.A2ATaskStateFailed
	case pb.TaskState_TASK_STATE_CANCELED:
		return domain.A2ATaskStateCanceled
	default:
		return domain.A2ATaskStateSubmitted
	}
}

// StringToTaskState maps domain string representation to protobuf TaskState enum.
func StringToTaskState(s string) pb.TaskState {
	switch s {
	case domain.A2ATaskStateSubmitted:
		return pb.TaskState_TASK_STATE_SUBMITTED
	case domain.A2ATaskStateWorking:
		return pb.TaskState_TASK_STATE_WORKING
	case domain.A2ATaskStateInputRequired:
		return pb.TaskState_TASK_STATE_INPUT_REQUIRED
	case domain.A2ATaskStateCompleted:
		return pb.TaskState_TASK_STATE_COMPLETED
	case domain.A2ATaskStateFailed:
		return pb.TaskState_TASK_STATE_FAILED
	case domain.A2ATaskStateCanceled:
		return pb.TaskState_TASK_STATE_CANCELED
	default:
		return pb.TaskState_TASK_STATE_UNSPECIFIED
	}
}

// IsJSONRPC checks if the request is formatted as JSON-RPC 2.0.
func IsJSONRPC(body []byte) bool {
	var probe struct {
		JSONRPC string `json:"jsonrpc"`
		Method  string `json:"method"`
	}
	dec := json.NewDecoder(bytes.NewReader(body))
	if err := dec.Decode(&probe); err == nil {
		return probe.JSONRPC == "2.0" && probe.Method != ""
	}
	return false
}
