package a2a

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"

	a2aspec "github.com/goroute-ai/ai-gateway-go/internal/a2a/spec"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// A2A JSON-RPC 2.0 protocol and gateway error codes (Section 9.5 & gateway governance extensions).
const (
	CodeParseError     int32 = -32700
	CodeInvalidRequest int32 = -32600
	CodeMethodNotFound int32 = -32601
	CodeInvalidParams  int32 = -32602
	CodeInternalError  int32 = -32603

	CodeBudgetExceeded              int32 = -32000 // Gateway budget/iteration/rate limit exceeded
	CodeTaskNotFound                int32 = -32001 // TaskNotFoundError
	CodeTaskNotCancelable           int32 = -32002 // TaskNotCancelableError
	CodePushNotificationUnsupported int32 = -32003 // PushNotificationNotSupportedError
	CodeUnsupportedOperation        int32 = -32004 // UnsupportedOperationError
	CodeContentTypeNotSupported     int32 = -32005 // ContentTypeNotSupportedError
	CodeInvalidAgentResponse        int32 = -32006 // InvalidAgentResponseError
	CodeExtendedCardNotConfigured   int32 = -32007 // ExtendedAgentCardNotConfiguredError
	CodeExtensionSupportRequired    int32 = -32008 // ExtensionSupportRequiredError
	CodeVersionNotSupported         int32 = -32009 // VersionNotSupportedError
	CodeAgentKilled                 int32 = -32010 // Gateway emergency kill-switch
)

// A2AError represents a structured A2A v1.0 protocol error that serializes cleanly to
// HTTP+JSON (`google.rpc.Status`), JSON-RPC 2.0 (`JSONRPCError`), and gRPC (`status.Status`).
type A2AError struct {
	HTTPStatus  int
	RPCStatus   string
	GRPCStatus  codes.Code
	JSONRPCCode int32
	Reason      a2aspec.A2AErrorReason
	Message     string
	Metadata    map[string]string
	Details     []a2aspec.GoogleRpcErrorDetail
}

func (e *A2AError) Error() string {
	return fmt.Sprintf("a2a error (%s/%d): %s", e.Reason, e.JSONRPCCode, e.Message)
}

func makeErrorInfoDetail(reason a2aspec.A2AErrorReason, meta map[string]string) *a2aspec.GoogleRpcErrorDetail {
	if reason == "" {
		return nil
	}
	props := map[string]any{
		"reason": string(reason),
		"domain": string(a2aspec.A2aProtocolOrg),
	}
	if len(meta) > 0 {
		props["metadata"] = maps.Clone(meta)
	}
	return &a2aspec.GoogleRpcErrorDetail{
		Type:                 string(a2aspec.TypeGoogleapisComgoogleRpcErrorInfo),
		AdditionalProperties: props,
	}
}

// ToGoogleRPCStatus converts A2AError into an OpenAPI-compliant google.rpc.StatusError envelope.
func (e *A2AError) ToGoogleRPCStatus() a2aspec.GoogleRpcStatusError {
	httpCode := e.HTTPStatus
	if httpCode == 0 {
		httpCode = http.StatusBadRequest
	}
	rpcStatus := e.RPCStatus
	if rpcStatus == "" {
		rpcStatus = "INVALID_ARGUMENT"
	}
	details := make([]a2aspec.GoogleRpcErrorDetail, 0, 1+len(e.Details))
	if d := makeErrorInfoDetail(e.Reason, e.Metadata); d != nil {
		details = append(details, *d)
	}
	details = append(details, e.Details...)

	statusPayload := a2aspec.GoogleRpcStatus{
		Code:    int32(httpCode),
		Message: e.Message,
		Status:  &rpcStatus,
	}
	if len(details) > 0 {
		statusPayload.Details = &details
	}
	return a2aspec.GoogleRpcStatusError{Error: statusPayload}
}

// MarshalHTTPBody serializes ToGoogleRPCStatus including AdditionalProperties on ErrorInfo/BadRequest details.
func (e *A2AError) MarshalHTTPBody() []byte {
	st := e.ToGoogleRPCStatus()
	detailList := make([]map[string]any, 0)
	if st.Error.Details != nil {
		for _, d := range *st.Error.Details {
			m := map[string]any{"@type": d.Type}
			for k, v := range d.AdditionalProperties {
				m[k] = v
			}
			detailList = append(detailList, m)
		}
	}
	errObj := map[string]any{
		"code":    st.Error.Code,
		"message": st.Error.Message,
	}
	if st.Error.Status != nil {
		errObj["status"] = *st.Error.Status
	}
	if len(detailList) > 0 {
		errObj["details"] = detailList
	}
	b, _ := json.Marshal(map[string]any{"error": errObj})
	return b
}

// ToJSONRPCError converts A2AError into a JSON-RPC 2.0 error object.
func (e *A2AError) ToJSONRPCError() *a2aspec.JSONRPCError {
	rpcErr := &a2aspec.JSONRPCError{
		Code:    e.JSONRPCCode,
		Message: e.Message,
	}
	details := make([]a2aspec.GoogleRpcErrorDetail, 0, 1+len(e.Details))
	if d := makeErrorInfoDetail(e.Reason, e.Metadata); d != nil {
		details = append(details, *d)
	}
	details = append(details, e.Details...)
	if len(details) > 0 {
		rpcErr.Data = &details
	}
	return rpcErr
}

// ToJSONRPCErrorMap builds a JSON-serializable JSON-RPC error object preserving detail AdditionalProperties.
func (e *A2AError) ToJSONRPCErrorMap() map[string]any {
	out := map[string]any{
		"code":    e.JSONRPCCode,
		"message": e.Message,
	}
	details := make([]map[string]any, 0, 1+len(e.Details))
	if d := makeErrorInfoDetail(e.Reason, e.Metadata); d != nil {
		m := map[string]any{"@type": d.Type}
		maps.Copy(m, d.AdditionalProperties)
		details = append(details, m)
	}
	for _, d := range e.Details {
		m := map[string]any{"@type": d.Type}
		maps.Copy(m, d.AdditionalProperties)
		details = append(details, m)
	}
	if len(details) > 0 {
		out["data"] = details
	}
	return out
}

// ToGRPCStatus maps A2AError to a gRPC status error.
func (e *A2AError) ToGRPCStatus() error {
	c := e.GRPCStatus
	if c == codes.OK {
		c = codes.Internal
	}
	return status.Error(c, e.Message)
}

// WriteHTTPError writes a canonical A2A v1.0 google.rpc.StatusError response.
func WriteHTTPError(w http.ResponseWriter, err error) {
	a2aErr := NormalizeA2AError(err)
	w.Header().Set("Content-Type", MediaTypeA2AJSON)
	w.Header().Set("A2A-Version", a2aspec.SupportedA2AVersion)
	w.WriteHeader(a2aErr.HTTPStatus)
	_, _ = w.Write(a2aErr.MarshalHTTPBody())
}

// NormalizeA2AError promotes domain/standard errors into an *A2AError.
func NormalizeA2AError(err error) *A2AError {
	if err == nil {
		return ErrInternal("unexpected empty error")
	}
	var a2aErr *A2AError
	if errors.As(err, &a2aErr) {
		return a2aErr
	}
	var gwErr *domain.GatewayError
	if errors.As(err, &gwErr) {
		httpStatus := gwErr.StatusCode
		if httpStatus == 0 {
			httpStatus = http.StatusInternalServerError
		}
		rpcStatus := "INTERNAL"
		grpcCode := codes.Internal
		rpcCode := CodeInternalError
		switch httpStatus {
		case http.StatusBadRequest:
			rpcStatus = "INVALID_ARGUMENT"
			grpcCode = codes.InvalidArgument
			rpcCode = CodeInvalidParams
		case http.StatusUnauthorized:
			rpcStatus = "UNAUTHENTICATED"
			grpcCode = codes.Unauthenticated
			rpcCode = CodeInvalidRequest
		case http.StatusForbidden:
			rpcStatus = "PERMISSION_DENIED"
			grpcCode = codes.PermissionDenied
			rpcCode = CodeTaskNotFound
		case http.StatusNotFound:
			rpcStatus = "NOT_FOUND"
			grpcCode = codes.NotFound
			rpcCode = CodeTaskNotFound
		case http.StatusTooManyRequests:
			rpcStatus = "RESOURCE_EXHAUSTED"
			grpcCode = codes.ResourceExhausted
			rpcCode = CodeBudgetExceeded
		case http.StatusServiceUnavailable:
			rpcStatus = "UNAVAILABLE"
			grpcCode = codes.Unavailable
			rpcCode = CodeAgentKilled
		}
		return &A2AError{
			HTTPStatus:  httpStatus,
			RPCStatus:   rpcStatus,
			GRPCStatus:  grpcCode,
			JSONRPCCode: rpcCode,
			Message:     gwErr.Message,
		}
	}
	return ErrInternal(err.Error())
}

// Canonical A2A v1.0 error constructors.

func ErrTaskNotFound(msg string, taskID string) *A2AError {
	meta := map[string]string{}
	if taskID != "" {
		meta["taskId"] = taskID
	}
	return &A2AError{
		HTTPStatus:  http.StatusNotFound,
		RPCStatus:   "NOT_FOUND",
		GRPCStatus:  codes.NotFound,
		JSONRPCCode: CodeTaskNotFound,
		Reason:      a2aspec.TASKNOTFOUND,
		Message:     msg,
		Metadata:    meta,
	}
}

func ErrTaskNotCancelable(msg string, taskID string) *A2AError {
	meta := map[string]string{}
	if taskID != "" {
		meta["taskId"] = taskID
	}
	return &A2AError{
		HTTPStatus:  http.StatusConflict,
		RPCStatus:   "FAILED_PRECONDITION",
		GRPCStatus:  codes.FailedPrecondition,
		JSONRPCCode: CodeTaskNotCancelable,
		Reason:      a2aspec.TASKNOTCANCELABLE,
		Message:     msg,
		Metadata:    meta,
	}
}

func ErrPushNotificationNotSupported(msg string) *A2AError {
	return &A2AError{
		HTTPStatus:  http.StatusBadRequest,
		RPCStatus:   "UNIMPLEMENTED",
		GRPCStatus:  codes.Unimplemented,
		JSONRPCCode: CodePushNotificationUnsupported,
		Reason:      a2aspec.PUSHNOTIFICATIONNOTSUPPORTED,
		Message:     msg,
	}
}

func ErrUnsupportedOperation(msg string) *A2AError {
	return &A2AError{
		HTTPStatus:  http.StatusBadRequest,
		RPCStatus:   "FAILED_PRECONDITION",
		GRPCStatus:  codes.FailedPrecondition,
		JSONRPCCode: CodeUnsupportedOperation,
		Reason:      a2aspec.UNSUPPORTEDOPERATION,
		Message:     msg,
	}
}

func ErrContentTypeNotSupported(msg string) *A2AError {
	return &A2AError{
		HTTPStatus:  http.StatusUnsupportedMediaType,
		RPCStatus:   "INVALID_ARGUMENT",
		GRPCStatus:  codes.InvalidArgument,
		JSONRPCCode: CodeContentTypeNotSupported,
		Reason:      a2aspec.CONTENTTYPENOTSUPPORTED,
		Message:     msg,
	}
}

func ErrInvalidAgentResponse(msg string) *A2AError {
	return &A2AError{
		HTTPStatus:  http.StatusBadGateway,
		RPCStatus:   "INTERNAL",
		GRPCStatus:  codes.Internal,
		JSONRPCCode: CodeInvalidAgentResponse,
		Reason:      a2aspec.INVALIDAGENTRESPONSE,
		Message:     msg,
	}
}

func ErrExtendedAgentCardNotConfigured(msg string) *A2AError {
	return &A2AError{
		HTTPStatus:  http.StatusNotFound,
		RPCStatus:   "FAILED_PRECONDITION",
		GRPCStatus:  codes.FailedPrecondition,
		JSONRPCCode: CodeExtendedCardNotConfigured,
		Reason:      a2aspec.EXTENDEDAGENTCARDNOTCONFIGURED,
		Message:     msg,
	}
}

func ErrExtensionSupportRequired(msg string, uri string) *A2AError {
	meta := map[string]string{}
	if uri != "" {
		meta["extensionUri"] = uri
	}
	return &A2AError{
		HTTPStatus:  http.StatusBadRequest,
		RPCStatus:   "FAILED_PRECONDITION",
		GRPCStatus:  codes.FailedPrecondition,
		JSONRPCCode: CodeExtensionSupportRequired,
		Reason:      a2aspec.EXTENSIONSUPPORTREQUIRED,
		Message:     msg,
		Metadata:    meta,
	}
}

func ErrVersionNotSupported(msg string, version string) *A2AError {
	meta := map[string]string{}
	if version != "" {
		meta["requestedVersion"] = version
	}
	return &A2AError{
		HTTPStatus:  http.StatusBadRequest,
		RPCStatus:   "UNIMPLEMENTED",
		GRPCStatus:  codes.Unimplemented,
		JSONRPCCode: CodeVersionNotSupported,
		Reason:      a2aspec.VERSIONNOTSUPPORTED,
		Message:     msg,
		Metadata:    meta,
	}
}

func ErrAgentKilled(msg string) *A2AError {
	return &A2AError{
		HTTPStatus:  http.StatusServiceUnavailable,
		RPCStatus:   "UNAVAILABLE",
		GRPCStatus:  codes.Unavailable,
		JSONRPCCode: CodeAgentKilled,
		Message:     msg,
	}
}

func ErrBudgetExceeded(msg string) *A2AError {
	return &A2AError{
		HTTPStatus:  http.StatusTooManyRequests,
		RPCStatus:   "RESOURCE_EXHAUSTED",
		GRPCStatus:  codes.ResourceExhausted,
		JSONRPCCode: CodeBudgetExceeded,
		Message:     msg,
	}
}

func ErrInvalidParams(msg string, fieldViolations ...a2aspec.FieldViolation) *A2AError {
	var details []a2aspec.GoogleRpcErrorDetail
	if len(fieldViolations) > 0 {
		details = []a2aspec.GoogleRpcErrorDetail{
			{
				Type: string(a2aspec.TypeGoogleapisComgoogleRpcBadRequest),
				AdditionalProperties: map[string]any{
					"fieldViolations": fieldViolations,
				},
			},
		}
	}
	return &A2AError{
		HTTPStatus:  http.StatusBadRequest,
		RPCStatus:   "INVALID_ARGUMENT",
		GRPCStatus:  codes.InvalidArgument,
		JSONRPCCode: CodeInvalidParams,
		Message:     msg,
		Details:     details,
	}
}

func ErrInvalidRequest(msg string) *A2AError {
	return &A2AError{
		HTTPStatus:  http.StatusBadRequest,
		RPCStatus:   "INVALID_ARGUMENT",
		GRPCStatus:  codes.InvalidArgument,
		JSONRPCCode: CodeInvalidRequest,
		Message:     msg,
	}
}

func ErrParse(msg string) *A2AError {
	return &A2AError{
		HTTPStatus:  http.StatusBadRequest,
		RPCStatus:   "INVALID_ARGUMENT",
		GRPCStatus:  codes.InvalidArgument,
		JSONRPCCode: CodeParseError,
		Message:     msg,
	}
}

func ErrMethodNotFound(msg string) *A2AError {
	return &A2AError{
		HTTPStatus:  http.StatusNotFound,
		RPCStatus:   "UNIMPLEMENTED",
		GRPCStatus:  codes.Unimplemented,
		JSONRPCCode: CodeMethodNotFound,
		Message:     msg,
	}
}

func ErrInternal(msg string) *A2AError {
	return &A2AError{
		HTTPStatus:  http.StatusInternalServerError,
		RPCStatus:   "INTERNAL",
		GRPCStatus:  codes.Internal,
		JSONRPCCode: CodeInternalError,
		Message:     msg,
	}
}
