package mcp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/mcp/spec"
)

// ParsedRPCMessage captures a decoded JSON-RPC request or notification along with its raw JSON bytes.
type ParsedRPCMessage struct {
	Raw            json.RawMessage
	Request        JSONRPCRequest
	IsNotification bool
}

// SpecProfile enforces protocol-release-specific HTTP transport, JSON-RPC envelope,
// schema validation, and result shaping rules generated from official MCP schemas.
type SpecProfile struct {
	info          spec.SpecInfo
	clientMethods map[string]struct{}
	clientNotifs  map[string]struct{}
}

// ProfileForVersion returns the SpecProfile for a supported official MCP release version.
func ProfileForVersion(version string) (SpecProfile, error) {
	v := strings.TrimSpace(version)
	if v == "" {
		v = spec.DefaultVersion
	}
	info, ok := spec.GetSpec(v)
	if !ok {
		return SpecProfile{}, fmt.Errorf("unsupported mcp specification version %q", v)
	}
	reqSet := make(map[string]struct{}, len(info.ClientRequestMethods))
	for _, m := range info.ClientRequestMethods {
		reqSet[m] = struct{}{}
	}
	notifSet := make(map[string]struct{}, len(info.ClientNotificationMethods))
	for _, m := range info.ClientNotificationMethods {
		notifSet[m] = struct{}{}
	}
	return SpecProfile{
		info:          info,
		clientMethods: reqSet,
		clientNotifs:  notifSet,
	}, nil
}

// Version returns the canonical MCP release date string (e.g. "2026-07-28").
func (p SpecProfile) Version() string { return p.info.Version }

// Info returns the generated capability metadata for this release.
func (p SpecProfile) Info() spec.SpecInfo { return p.info }

// SupportsMethod reports whether method is declared in this release's official ClientRequest or ClientNotification schema.
func (p SpecProfile) SupportsMethod(method string) bool {
	if _, ok := p.clientMethods[method]; ok {
		return true
	}
	if _, ok := p.clientNotifs[method]; ok {
		return true
	}
	return false
}

// ParseAndValidateBody parses single or batched JSON-RPC payloads and validates transport/header rules for this release.
func (p SpecProfile) ParseAndValidateBody(
	r *http.Request,
	body []byte,
	strictSchema bool,
) ([]ParsedRPCMessage, bool, *JSONRPCError) {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return nil, false, &JSONRPCError{
			Code:    CodeParseError,
			Message: "empty JSON-RPC payload",
		}
	}

	if trimmed[0] == '[' {
		if !p.info.SupportsBatching {
			return nil, true, &JSONRPCError{
				Code:    CodeInvalidRequest,
				Message: fmt.Sprintf("JSON-RPC batching is not supported in MCP specification %s", p.info.Version),
			}
		}
		var rawItems []json.RawMessage
		if err := json.Unmarshal(trimmed, &rawItems); err != nil {
			return nil, true, &JSONRPCError{
				Code:    CodeParseError,
				Message: fmt.Sprintf("invalid JSON-RPC batch array: %v", err),
			}
		}
		if len(rawItems) == 0 {
			return nil, true, &JSONRPCError{
				Code:    CodeInvalidRequest,
				Message: "empty JSON-RPC batch array",
			}
		}
		msgs := make([]ParsedRPCMessage, 0, len(rawItems))
		for _, item := range rawItems {
			parsed, rpcErr := p.parseSingleMessage(r, item, strictSchema)
			if rpcErr != nil {
				return nil, true, rpcErr
			}
			msgs = append(msgs, parsed)
		}
		return msgs, true, nil
	}

	parsed, rpcErr := p.parseSingleMessage(r, trimmed, strictSchema)
	if rpcErr != nil {
		return nil, false, rpcErr
	}
	return []ParsedRPCMessage{parsed}, false, nil
}

func (p SpecProfile) parseSingleMessage(
	r *http.Request,
	raw []byte,
	strictSchema bool,
) (ParsedRPCMessage, *JSONRPCError) {
	var rawObj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &rawObj); err != nil {
		return ParsedRPCMessage{}, &JSONRPCError{
			Code:    CodeParseError,
			Message: fmt.Sprintf("invalid json-rpc: %v", err),
		}
	}

	var req JSONRPCRequest
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	if err := dec.Decode(&req); err != nil {
		return ParsedRPCMessage{}, &JSONRPCError{
			Code:    CodeParseError,
			Message: fmt.Sprintf("invalid json-rpc: %v", err),
		}
	}
	if req.JSONRPC != "2.0" || strings.TrimSpace(req.Method) == "" {
		return ParsedRPCMessage{}, &JSONRPCError{
			Code:    CodeInvalidRequest,
			Message: "invalid json-rpc 2.0 request envelope",
		}
	}

	idRaw, hasID := rawObj["id"]
	isNotification := !hasID || len(bytes.TrimSpace(idRaw)) == 0 || bytes.Equal(bytes.TrimSpace(idRaw), []byte("null"))

	if err := p.validateHeadersAgainstMessage(r, &req); err != nil {
		return ParsedRPCMessage{}, err
	}

	if !p.SupportsMethod(req.Method) {
		return ParsedRPCMessage{}, &JSONRPCError{
			Code:    CodeMethodNotFound,
			Message: fmt.Sprintf("Method %q is not part of MCP specification %s", req.Method, p.info.Version),
		}
	}

	if strictSchema {
		defName := "ClientRequest"
		if isNotification {
			defName = "ClientNotification"
		}
		if err := spec.ValidateDefinition(p.info.Version, defName, raw); err != nil {
			code := CodeInvalidParams
			if p.info.RequiresMirroredHeaders && strings.Contains(err.Error(), "_meta") {
				code = CodeInvalidParams
			}
			return ParsedRPCMessage{}, &JSONRPCError{
				Code:    code,
				Message: err.Error(),
			}
		}
	}

	return ParsedRPCMessage{
		Raw:            raw,
		Request:        req,
		IsNotification: isNotification,
	}, nil
}

func (p SpecProfile) validateHeadersAgainstMessage(r *http.Request, req *JSONRPCRequest) *JSONRPCError {
	if r == nil {
		return nil
	}

	if protoHdr := strings.TrimSpace(r.Header.Get("MCP-Protocol-Version")); protoHdr != "" {
		if protoHdr != p.info.Version {
			return &JSONRPCError{
				Code:    CodeUnsupportedProtocolVersion,
				Message: fmt.Sprintf("unsupported protocol version %q for active specification %s", protoHdr, p.info.Version),
				Data: map[string]any{
					"requested": protoHdr,
					"supported": []string{p.info.Version},
				},
			}
		}
	}

	if p.info.RequiresMirroredHeaders {
		if mcpMethod := strings.TrimSpace(r.Header.Get("Mcp-Method")); mcpMethod != "" && mcpMethod != req.Method {
			return &JSONRPCError{
				Code:    CodeHeaderMismatch,
				Message: fmt.Sprintf("Header Mcp-Method %q does not match JSON-RPC method %q", mcpMethod, req.Method),
			}
		}
		if len(req.Params) > 0 {
			var metaHolder struct {
				Meta map[string]any `json:"_meta"`
			}
			if err := json.Unmarshal(req.Params, &metaHolder); err == nil && metaHolder.Meta != nil {
				if mv, ok := metaHolder.Meta["io.modelcontextprotocol/protocolVersion"].(string); ok && mv != "" {
					if mv != p.info.Version {
						return &JSONRPCError{
							Code:    CodeUnsupportedProtocolVersion,
							Message: fmt.Sprintf("unsupported _meta protocolVersion %q; active specification is %s", mv, p.info.Version),
							Data: map[string]any{
								"requested": mv,
								"supported": []string{p.info.Version},
							},
						}
					}
					if hdrVer := strings.TrimSpace(r.Header.Get("MCP-Protocol-Version")); hdrVer != "" && hdrVer != mv {
						return &JSONRPCError{
							Code:    CodeHeaderMismatch,
							Message: fmt.Sprintf("Header MCP-Protocol-Version %q does not match _meta.io.modelcontextprotocol/protocolVersion %q", hdrVer, mv),
						}
					}
				}
			}
		}
		if err := ValidateMirroredHeaderParameters(r, req); err != nil {
			return err
		}
	}

	return nil
}

// HTTPStatusForResponse computes the HTTP status code per the active specification.
func (p SpecProfile) HTTPStatusForResponse(isNotification bool, resp *JSONRPCResponse) int {
	if isNotification && (resp == nil || resp.Error == nil) && p.info.Version != domain.MCPProtocolVersion20241105 {
		return http.StatusAccepted
	}
	if resp != nil && resp.Error != nil && p.info.RequiresMirroredHeaders {
		switch resp.Error.Code {
		case CodeHeaderMismatch, CodeCapabilityNotSupported, CodeUnsupportedProtocolVersion:
			return http.StatusBadRequest
		}
	}
	return http.StatusOK
}

// ShapeResult normalizes result payloads so fields match the caller's selected MCP release.
func (p SpecProfile) ShapeResult(method string, result any) any {
	resMap, ok := result.(map[string]any)
	if !ok {
		return result
	}

	shaped := make(map[string]any, len(resMap)+4)
	for k, v := range resMap {
		shaped[k] = v
	}

	if p.info.SupportsResultType {
		if _, exists := shaped["resultType"]; !exists {
			shaped["resultType"] = "complete"
		}
		if isCacheableSpecMethod(method) {
			if _, exists := shaped["cacheScope"]; !exists {
				shaped["cacheScope"] = "private"
			}
			if _, exists := shaped["ttlMs"]; !exists {
				shaped["ttlMs"] = 0
			}
		}
		ensureServerInfoMeta(shaped)
		return shaped
	}

	// Pre-2026 releases do not include 2026-07-28 cacheability/resultType discriminators.
	delete(shaped, "resultType")
	delete(shaped, "cacheScope")
	delete(shaped, "ttlMs")
	if !p.info.SupportsStructuredContent {
		delete(shaped, "structuredContent")
	}
	return shaped
}

func isCacheableSpecMethod(method string) bool {
	switch method {
	case "server/discover", "tools/list", "resources/list", "resources/templates/list", "resources/read", "prompts/list":
		return true
	default:
		return false
	}
}

func ensureServerInfoMeta(resMap map[string]any) {
	meta, ok := resMap["_meta"].(map[string]any)
	if !ok || meta == nil {
		meta = make(map[string]any)
		resMap["_meta"] = meta
	}
	if _, exists := meta["io.modelcontextprotocol/serverInfo"]; !exists {
		meta["io.modelcontextprotocol/serverInfo"] = map[string]any{
			"name":    "GoRoute AI Gateway MCP Hub",
			"version": domain.MCPProtocolVersion20260728,
		}
	}
}
