package mcp

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
)

const (
	// Standard JSON-RPC 2.0 Error Codes
	CodeParseError     = -32700
	CodeInvalidRequest = -32600
	CodeMethodNotFound = -32601
	CodeInvalidParams  = -32602
	CodeInternalError  = -32603

	// MCP Protocol Error Codes (2026-07-28 & 2025 Compat)
	CodeHeaderMismatch             = -32020 // Mismatch between mirrored Mcp-* header and JSON-RPC body
	CodeCapabilityNotSupported     = -32021 // Client capability negotiation failure
	CodeUnsupportedProtocolVersion = -32022 // Requested protocol version not supported
	CodeSessionExpired             = -32025 // 2025 stateful session expired or invalidated
)

// JSONRPCRequest represents a decoded MCP JSON-RPC 2.0 request.
type JSONRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// JSONRPCResponse represents a decoded MCP JSON-RPC 2.0 response.
type JSONRPCResponse struct {
	JSONRPC string        `json:"jsonrpc"`
	ID      any           `json:"id,omitempty"`
	Result  any           `json:"result,omitempty"`
	Error   *JSONRPCError `json:"error,omitempty"`
}

// JSONRPCError represents an error object inside a JSON-RPC 2.0 response.
type JSONRPCError struct {
	Code    int            `json:"code"`
	Message string         `json:"message"`
	Data    map[string]any `json:"data,omitempty"`
}

func (e *JSONRPCError) Error() string {
	return fmt.Sprintf("MCP JSON-RPC error %d: %s", e.Code, e.Message)
}

// DecodeBase64Sentinel decodes MCP 2026-07-28 header framing:
// Either visible ASCII, or exact case-sensitive `=?base64?{Base64EncodedUTF8}?=` sentinel.
// Rejects RFC 2047 variants (e.g. `=?UTF-8?B?...?=`).
func DecodeBase64Sentinel(headerVal string) (string, error) {
	val := strings.TrimSpace(headerVal)
	if val == "" {
		return "", nil
	}

	// Check if framed with exact sentinel
	if strings.HasPrefix(val, "=?base64?") && strings.HasSuffix(val, "?=") {
		encoded := val[len("=?base64?") : len(val)-len("?=")]
		decodedBytes, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return "", fmt.Errorf("invalid base64 sentinel in header: %w", err)
		}
		return string(decodedBytes), nil
	}

	// Otherwise, must be plain ASCII without control characters (except space/tab)
	for i := 0; i < len(val); i++ {
		b := val[i]
		if b < 0x20 && b != 0x09 {
			return "", errors.New("header contains disallowed control character")
		}
		if b > 0x7E {
			return "", errors.New("non-ASCII character in header without base64 sentinel framing")
		}
	}
	return val, nil
}

// EncodeBase64Sentinel encodes a string using MCP 2026-07-28 `=?base64?...?=` sentinel
// if it contains non-ASCII or control characters.
func EncodeBase64Sentinel(raw string) string {
	needsEncoding := false
	for i := 0; i < len(raw); i++ {
		b := raw[i]
		if b < 0x20 || b > 0x7E {
			needsEncoding = true
			break
		}
	}
	if !needsEncoding {
		return raw
	}
	return "=?base64?" + base64.StdEncoding.EncodeToString([]byte(raw)) + "?="
}

// CanonicalDecimal normalizes an arbitrary-precision numeric string into canonical decimal representation.
// Uses big.Rat / big.Float to guarantee full arbitrary integer and fractional precision (> 53 bits),
// rejecting NaN, Inf, and malformed leading zeroes (like "01").
func CanonicalDecimal(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	if s == "" {
		return "", errors.New("empty numeric string")
	}

	// Reject NaN and Inf
	lower := strings.ToLower(s)
	if strings.Contains(lower, "nan") || strings.Contains(lower, "inf") {
		return "", errors.New("NaN and Infinity are forbidden numeric values")
	}

	// Reject leading zeroes in integer part (e.g. "01", "-05"), but allow "0" or "0.123"
	check := s
	if strings.HasPrefix(check, "-") || strings.HasPrefix(check, "+") {
		check = check[1:]
	}
	if len(check) > 1 && check[0] == '0' && check[1] >= '0' && check[1] <= '9' {
		return "", errors.New("disallowed leading zero in integer part")
	}

	// Parse with big.Rat to preserve arbitrary precision without float64 precision loss
	rat, ok := new(big.Rat).SetString(s)
	if !ok {
		return "", fmt.Errorf("malformed numeric format: %s", s)
	}

	// Convert to canonical decimal string representation:
	// If exact integer, return exact integer digits (e.g. 42.0 -> "42", 1e3 -> "1000")
	if rat.IsInt() {
		return rat.Num().String(), nil
	}

	// Otherwise, format with high precision and strip trailing fractional zeroes
	floatStr := rat.FloatString(100)
	if strings.Contains(floatStr, ".") {
		floatStr = strings.TrimRight(floatStr, "0")
		floatStr = strings.TrimRight(floatStr, ".")
	}
	return floatStr, nil
}

// CompareNumericValues compares two arbitrary-precision numeric strings.
// Returns true if mathematically identical (e.g. "42.0" == "42", "1e3" == "1000").
func CompareNumericValues(a, b string) bool {
	canonA, errA := CanonicalDecimal(a)
	canonB, errB := CanonicalDecimal(b)
	if errA != nil || errB != nil {
		return false
	}
	return canonA == canonB
}

// ValidateHTTPRequest validates incoming HTTP transport level constraints for MCP:
// Returns HTTP status code and error if invalid (405 Method Not Allowed, 406 Not Acceptable, 403 Forbidden).
func ValidateHTTPRequest(r *http.Request, allowedOrigins []string) (int, error) {
	// 1. Method check: POST is required for MCP Streamable HTTP RPC
	if r.Method != http.MethodPost {
		return http.StatusMethodNotAllowed, fmt.Errorf("method %s not allowed: MCP Streamable HTTP requires POST", r.Method)
	}

	// 2. Accept header check
	accept := r.Header.Get("Accept")
	if accept != "" {
		accept = strings.ToLower(accept)
		if !strings.Contains(accept, "application/json") &&
			!strings.Contains(accept, "application/mcp+json") &&
			!strings.Contains(accept, "text/event-stream") &&
			!strings.Contains(accept, "*/*") {
			return http.StatusNotAcceptable, fmt.Errorf("accept header %q not acceptable: client must accept application/json or application/mcp+json", accept)
		}
	}

	// 3. Origin check (CORS / CSRF protection)
	origin := r.Header.Get("Origin")
	if origin != "" && len(allowedOrigins) > 0 {
		matched := false
		for _, allowed := range allowedOrigins {
			if allowed == "*" || strings.EqualFold(origin, allowed) {
				matched = true
				break
			}
		}
		if !matched {
			return http.StatusForbidden, fmt.Errorf("origin %q not allowed", origin)
		}
	}

	return http.StatusOK, nil
}

// ValidateProtocolVersion validates requested MCP protocol version.
func ValidateProtocolVersion(version string) *JSONRPCError {
	version = strings.TrimSpace(version)
	if version == "" || version == "2026-07-28" || version == "2025-11-25" {
		return nil
	}
	return &JSONRPCError{
		Code:    CodeUnsupportedProtocolVersion,
		Message: fmt.Sprintf("unsupported protocol version %q; supported versions are 2026-07-28 and 2025-11-25", version),
	}
}

// ValidateClientCapabilities checks whether client capabilities fulfill the required set.
func ValidateClientCapabilities(required []string, clientCaps map[string]any) *JSONRPCError {
	if len(required) == 0 {
		return nil
	}
	if clientCaps == nil {
		return &JSONRPCError{
			Code:    CodeCapabilityNotSupported,
			Message: fmt.Sprintf("client does not support required capability %q", required[0]),
		}
	}
	for _, req := range required {
		if _, ok := clientCaps[req]; !ok {
			return &JSONRPCError{
				Code:    CodeCapabilityNotSupported,
				Message: fmt.Sprintf("client does not support required capability %q", req),
			}
		}
	}
	return nil
}

// ValidateMCPTransportHeaders checks standard HTTP transport constraints for MCP 2026-07-28.
func ValidateMCPTransportHeaders(r *http.Request) *JSONRPCError {
	// 1. Method check: POST required
	if r.Method != http.MethodPost {
		return &JSONRPCError{
			Code:    CodeInvalidRequest,
			Message: "Method Not Allowed: MCP Streamable HTTP endpoints accept POST requests only",
		}
	}

	// 2. Accept header: must accept JSON or event-stream
	accept := r.Header.Get("Accept")
	if accept != "" {
		accept = strings.ToLower(accept)
		if !strings.Contains(accept, "application/json") &&
			!strings.Contains(accept, "application/mcp+json") &&
			!strings.Contains(accept, "*/*") &&
			!strings.Contains(accept, "text/event-stream") {
			return &JSONRPCError{
				Code:    CodeInvalidRequest,
				Message: "Not Acceptable: client must accept application/json or application/mcp+json",
			}
		}
	}

	return nil
}

// ValidateMirroredHeaderParameters checks that mirrored Mcp-Param-* and Mcp-Name headers
// strictly match the JSON-RPC tool call payload arguments (MCP 2026-07-28 spec).
func ValidateMirroredHeaderParameters(r *http.Request, req *JSONRPCRequest) *JSONRPCError {
	if req.Method != "tools/call" {
		return nil
	}

	if len(req.Params) == 0 {
		return nil
	}

	var params struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
	}

	dec := json.NewDecoder(bytes.NewReader(req.Params))
	dec.UseNumber()
	if err := dec.Decode(&params); err != nil {
		return &JSONRPCError{
			Code:    CodeInvalidParams,
			Message: "Invalid tools/call params structure",
		}
	}

	// 1. Validate Mcp-Name header if present
	if mcpName := r.Header.Get("Mcp-Name"); mcpName != "" {
		decodedName, err := DecodeBase64Sentinel(mcpName)
		if err != nil || decodedName != params.Name {
			return &JSONRPCError{
				Code:    CodeHeaderMismatch,
				Message: fmt.Sprintf("Header Mcp-Name %q does not match params.name %q", decodedName, params.Name),
			}
		}
	}

	// 2. Validate mirrored Mcp-Param-{Name} headers against arguments
	if len(params.Arguments) > 0 {
		var args map[string]any
		decArgs := json.NewDecoder(bytes.NewReader(params.Arguments))
		decArgs.UseNumber()
		if err := decArgs.Decode(&args); err == nil {
			for headerName, headerVals := range r.Header {
				lower := strings.ToLower(headerName)
				if strings.HasPrefix(lower, "mcp-param-") {
					paramKey := headerName[len("Mcp-Param-"):]
					headerVal := headerVals[0]
					decodedVal, err := DecodeBase64Sentinel(headerVal)
					if err != nil {
						return &JSONRPCError{
							Code:    CodeHeaderMismatch,
							Message: fmt.Sprintf("Invalid encoding in header %s: %v", headerName, err),
						}
					}

					argVal, exists := args[paramKey]
					if !exists {
						for k, v := range args {
							if strings.EqualFold(k, paramKey) {
								argVal = v
								exists = true
								break
							}
						}
					}
					if !exists {
						return &JSONRPCError{
							Code:    CodeHeaderMismatch,
							Message: fmt.Sprintf("Mirrored header %s specifies param %q which is missing from JSON-RPC arguments", headerName, paramKey),
						}
					}

					// Value matching: string vs string, number vs number, bool vs bool
					switch v := argVal.(type) {
					case string:
						if decodedVal != v {
							return &JSONRPCError{
								Code:    CodeHeaderMismatch,
								Message: fmt.Sprintf("Header %s value %q does not match argument string %q", headerName, decodedVal, v),
							}
						}
					case json.Number:
						if !CompareNumericValues(decodedVal, v.String()) {
							return &JSONRPCError{
								Code:    CodeHeaderMismatch,
								Message: fmt.Sprintf("Header %s numeric value %q does not match argument number %s", headerName, decodedVal, v.String()),
							}
						}
					case bool:
						boolStr := fmt.Sprintf("%v", v)
						if !strings.EqualFold(decodedVal, boolStr) {
							return &JSONRPCError{
								Code:    CodeHeaderMismatch,
								Message: fmt.Sprintf("Header %s boolean value %q does not match argument bool %s", headerName, decodedVal, boolStr),
							}
						}
					}
				}
			}
		}
	}

	return nil
}
