package a2a

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"

	a2aspec "github.com/goroute-ai/ai-gateway-go/internal/a2a/spec"
)

// Canonical A2A v1.0 HTTP media types and protocol headers.
const (
	MediaTypeA2AJSON = "application/a2a+json"
	MediaTypeJSON    = "application/json"
	MediaTypeSSE     = "text/event-stream"

	HeaderA2AVersion    = "A2A-Version"
	HeaderA2AExtensions = "A2A-Extensions"
	HeaderLastEventID   = "Last-Event-ID"
)

type callOptionsContextKey struct{}

// CallOptions carries per-request A2A v1.0 protocol headers and tenant metadata into RouterService.
type CallOptions struct {
	Version    string
	Extensions []string
	Tenant     string
}

// ContextWithCallOptions attaches A2A protocol CallOptions to ctx.
func ContextWithCallOptions(ctx context.Context, opts CallOptions) context.Context {
	return context.WithValue(ctx, callOptionsContextKey{}, opts)
}

// CallOptionsFromContext retrieves A2A protocol CallOptions from ctx.
func CallOptionsFromContext(ctx context.Context) CallOptions {
	if ctx == nil {
		return CallOptions{}
	}
	opts, _ := ctx.Value(callOptionsContextKey{}).(CallOptions)
	return opts
}

// ParseAndValidateHeaders validates A2A-Version, optional A2A-Extensions, and Content-Type
// (when requireBodyMediaType is true).
func ParseAndValidateHeaders(r *http.Request, tenant string, requireBodyMediaType bool) (CallOptions, error) {
	if r == nil {
		return CallOptions{Version: a2aspec.SupportedA2AVersion, Tenant: tenant}, nil
	}
	ver := strings.TrimSpace(r.Header.Get(HeaderA2AVersion))
	if !a2aspec.IsSupportedA2AVersion(ver) {
		return CallOptions{}, ErrVersionNotSupported(fmt.Sprintf("unsupported A2A-Version %q; supported version is %s", ver, a2aspec.SupportedA2AVersion), ver)
	}
	if ver == "" {
		ver = a2aspec.SupportedA2AVersion
	}

	if requireBodyMediaType {
		if err := ValidateContentType(r); err != nil {
			return CallOptions{}, err
		}
	}

	return CallOptions{
		Version:    ver,
		Extensions: a2aspec.ParseExtensionsHeader(r.Header.Get(HeaderA2AExtensions)),
		Tenant:     tenant,
	}, nil
}

// ValidateContentType checks that Content-Type is application/a2a+json or application/json.
func ValidateContentType(r *http.Request) error {
	if r == nil {
		return nil
	}
	raw := strings.TrimSpace(r.Header.Get("Content-Type"))
	if raw == "" {
		return nil
	}
	mediaType, _, err := mime.ParseMediaType(raw)
	if err != nil {
		return ErrContentTypeNotSupported(fmt.Sprintf("malformed Content-Type header %q: %v", raw, err))
	}
	switch strings.ToLower(mediaType) {
	case MediaTypeA2AJSON, MediaTypeJSON:
		return nil
	default:
		return ErrContentTypeNotSupported(fmt.Sprintf("unsupported Content-Type %q; expected %s or %s", mediaType, MediaTypeA2AJSON, MediaTypeJSON))
	}
}

// WriteJSONResponse writes an OpenAPI JSON payload with A2A-Version and content-type headers.
func WriteJSONResponse(w http.ResponseWriter, r *http.Request, status int, payload any) error {
	b, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal a2a response: %w", err)
	}
	ct := MediaTypeA2AJSON
	if r != nil && strings.Contains(strings.ToLower(r.Header.Get("Accept")), MediaTypeJSON) &&
		!strings.Contains(strings.ToLower(r.Header.Get("Accept")), MediaTypeA2AJSON) {
		ct = MediaTypeJSON
	}
	w.Header().Set("Content-Type", ct)
	w.Header().Set(HeaderA2AVersion, a2aspec.SupportedA2AVersion)
	w.WriteHeader(status)
	_, err = w.Write(b)
	return err
}

// ReadStrictJSONBody reads an HTTP request body up to maxBytes and decodes it strictly against
// the named OpenAPI schema in a2a.openapi.yaml.
func ReadStrictJSONBody[T any](r *http.Request, maxBytes int64, schemaName string) (*T, error) {
	if maxBytes <= 0 {
		maxBytes = 10 * 1024 * 1024
	}
	bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, maxBytes+1))
	if err != nil {
		return nil, ErrInvalidRequest(fmt.Sprintf("failed to read request body: %v", err))
	}
	if int64(len(bodyBytes)) > maxBytes {
		return nil, &A2AError{
			HTTPStatus:  http.StatusRequestEntityTooLarge,
			RPCStatus:   "INVALID_ARGUMENT",
			JSONRPCCode: CodeInvalidParams,
			Message:     fmt.Sprintf("request body exceeds limit of %d bytes", maxBytes),
		}
	}
	decoded, err := a2aspec.DecodeStrict[T](schemaName, bodyBytes)
	if err != nil {
		return nil, ErrInvalidParams(fmt.Sprintf("OpenAPI schema validation failed for %s: %v", schemaName, err))
	}
	return decoded, nil
}

// JSONRPCRequest represents an incoming A2A v1.0 JSON-RPC 2.0 request envelope.
type JSONRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// JSONRPCResponse represents an outgoing A2A v1.0 JSON-RPC 2.0 response envelope.
type JSONRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  any             `json:"result,omitempty"`
	Error   map[string]any  `json:"error,omitempty"`
}
