package domain

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// ErrorType follows the standard OpenAI error taxonomy for drop-in SDK compatibility.
type ErrorType string

const (
	ErrorTypeInvalidRequest ErrorType = "invalid_request_error"
	ErrorTypeAuthentication ErrorType = "authentication_error"
	ErrorTypePermission     ErrorType = "permission_error"
	ErrorTypeNotFound       ErrorType = "not_found_error"
	ErrorTypeRateLimit      ErrorType = "rate_limit_error"
	ErrorTypeBudgetExceeded ErrorType = "budget_exceeded_error"
	ErrorTypeUpstream       ErrorType = "upstream_provider_error"
	ErrorTypeServer         ErrorType = "server_error"
)

// GatewayError is the unified error type propagated across all gateway layers.
type GatewayError struct {
	StatusCode    int          `json:"-"`
	Type          ErrorType    `json:"type"`
	Code          string       `json:"code"`
	Message       string       `json:"message"`
	Param         string       `json:"param,omitempty"`
	Provider      ProviderType `json:"provider,omitempty"`
	RetryAfterSec int          `json:"-"`
	Retryable     bool         `json:"-"`
	AuthFailure   bool         `json:"-"`
}

func (e *GatewayError) Error() string {
	if e.Provider != "" {
		return fmt.Sprintf("[%s:%d:%s] %s", e.Provider, e.StatusCode, e.Code, e.Message)
	}
	return fmt.Sprintf("[%d:%s] %s", e.StatusCode, e.Code, e.Message)
}

// OpenAIErrorEnvelope wraps GatewayError in the exact `{ "error": { ... } }` format expected by OpenAI SDKs.
type OpenAIErrorEnvelope struct {
	Error *GatewayError `json:"error"`
}

// AnthropicErrorBody is the inner error payload expected by Anthropic SDKs.
type AnthropicErrorBody struct {
	Type    string `json:"type"`
	Message string `json:"message"`
}

// AnthropicErrorEnvelope wraps errors in the `{"type":"error","error":{"type":...,"message":...}}` format expected by Anthropic SDKs.
type AnthropicErrorEnvelope struct {
	Type  string              `json:"type"`
	Error *AnthropicErrorBody `json:"error"`
}

func normalizeGatewayError(err error) *GatewayError {
	gwErr, ok := err.(*GatewayError)
	if !ok {
		gwErr = &GatewayError{
			StatusCode: http.StatusInternalServerError,
			Type:       ErrorTypeServer,
			Code:       "internal_server_error",
			Message:    err.Error(),
		}
	}
	if gwErr.StatusCode == 0 {
		gwErr.StatusCode = http.StatusInternalServerError
	}
	return gwErr
}

func mapAnthropicErrorType(gwErr *GatewayError) string {
	if gwErr.StatusCode == 529 || gwErr.Code == "overloaded_error" {
		return "overloaded_error"
	}
	switch gwErr.Type {
	case ErrorTypeInvalidRequest, ErrorTypeAuthentication, ErrorTypePermission, ErrorTypeNotFound, ErrorTypeRateLimit:
		return string(gwErr.Type)
	case ErrorTypeBudgetExceeded:
		return string(ErrorTypeRateLimit)
	default:
		return "api_error"
	}
}

// WriteHTTPError serializes a GatewayError into an HTTP response with proper headers.
func WriteHTTPError(w http.ResponseWriter, err error) {
	gwErr := normalizeGatewayError(err)
	if gwErr.RetryAfterSec > 0 {
		w.Header().Set("Retry-After", fmt.Sprintf("%d", gwErr.RetryAfterSec))
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(gwErr.StatusCode)
	_ = json.NewEncoder(w).Encode(OpenAIErrorEnvelope{Error: gwErr})
}

// WriteAnthropicHTTPError serializes a GatewayError into an Anthropic-compatible HTTP error envelope.
func WriteAnthropicHTTPError(w http.ResponseWriter, err error) {
	gwErr := normalizeGatewayError(err)
	if gwErr.RetryAfterSec > 0 {
		w.Header().Set("Retry-After", fmt.Sprintf("%d", gwErr.RetryAfterSec))
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(gwErr.StatusCode)
	_ = json.NewEncoder(w).Encode(AnthropicErrorEnvelope{
		Type: "error",
		Error: &AnthropicErrorBody{
			Type:    mapAnthropicErrorType(gwErr),
			Message: gwErr.Message,
		},
	})
}

// ClassifyUpstreamStatus determines whether an upstream HTTP status code is retryable within the same group or requires fallback.
func ClassifyUpstreamStatus(provider ProviderType, statusCode int, body string, retryAfterSec int) *GatewayError {
	gwErr := &GatewayError{
		StatusCode:    statusCode,
		Provider:      provider,
		Message:       body,
		RetryAfterSec: retryAfterSec,
	}

	switch statusCode {
	case http.StatusBadRequest, http.StatusUnprocessableEntity:
		gwErr.Type = ErrorTypeInvalidRequest
		gwErr.Code = "upstream_bad_request"
		gwErr.Retryable = false
	case http.StatusUnauthorized, http.StatusForbidden:
		gwErr.Type = ErrorTypeAuthentication
		gwErr.Code = "upstream_auth_error"
		gwErr.StatusCode = http.StatusBadGateway // Do not leak 401 to client as if their virtual key failed
		gwErr.Retryable = false
		gwErr.AuthFailure = true
	case http.StatusNotFound:
		gwErr.Type = ErrorTypeNotFound
		gwErr.Code = "upstream_model_not_found"
		gwErr.Retryable = false
	case http.StatusRequestTimeout, http.StatusTooManyRequests:
		gwErr.Type = ErrorTypeRateLimit
		gwErr.Code = "upstream_rate_limit"
		gwErr.Retryable = true
	case http.StatusInternalServerError, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout, 529: // 529 = Anthropic Overloaded
		gwErr.Type = ErrorTypeUpstream
		gwErr.Code = "upstream_unavailable"
		gwErr.Retryable = true
		if statusCode == 529 {
			gwErr.StatusCode = http.StatusServiceUnavailable
		}
	default:
		gwErr.Type = ErrorTypeUpstream
		gwErr.Code = "upstream_error"
		gwErr.Retryable = statusCode >= 500
	}
	return gwErr
}
