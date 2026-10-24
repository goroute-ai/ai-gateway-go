package mcp

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/google/uuid"
	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

// RESTBridge exposes MCP operations over standard JSON REST endpoints.
type RESTBridge struct {
	hub *Hub
}

// NewRESTBridge creates a new RESTBridge handler instance.
func NewRESTBridge(hub *Hub) *RESTBridge {
	return &RESTBridge{hub: hub}
}

// HandleListTools serves `GET /mcp-rest/tools/list`.
// Query parameters:
//   - server_slug: (optional) filter tools to a specific registered MCP server.
func (b *RESTBridge) HandleListTools(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeRESTError(w, http.StatusMethodNotAllowed, "method_not_allowed", "GET method is required")
		return
	}

	idCtx := auth.IdentityFromContext(r.Context())
	if idCtx == nil {
		writeRESTError(w, http.StatusUnauthorized, "unauthorized", "missing identity context")
		return
	}

	serverSlug := strings.TrimSpace(r.URL.Query().Get("server_slug"))
	tools, err := b.hub.ListTools(r.Context(), idCtx, serverSlug)
	if err != nil {
		var gwErr *domain.GatewayError
		if errors.As(err, &gwErr) {
			writeRESTError(w, gwErr.StatusCode, gwErr.Code, gwErr.Message)
			return
		}
		errLower := strings.ToLower(err.Error())
		if strings.Contains(errLower, "not found") {
			writeRESTError(w, http.StatusNotFound, "server_not_found", err.Error())
			return
		}
		if strings.Contains(errLower, "forbidden") || strings.Contains(errLower, "authorized") {
			writeRESTError(w, http.StatusForbidden, "forbidden", err.Error())
			return
		}
		writeRESTError(w, http.StatusInternalServerError, "internal_error", err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"tools": tools,
	})
}

// HandleCallTool serves `POST /mcp-rest/tools/call`.
// Request JSON body:
//   - server_slug: (optional unless tool name is ambiguous across servers)
//   - tool_name: (required)
//   - arguments: (map of arguments)
func (b *RESTBridge) HandleCallTool(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeRESTError(w, http.StatusMethodNotAllowed, "method_not_allowed", "POST method is required")
		return
	}

	idCtx := auth.IdentityFromContext(r.Context())
	if idCtx == nil {
		writeRESTError(w, http.StatusUnauthorized, "unauthorized", "missing identity context")
		return
	}

	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 10*1024*1024))
	if err != nil {
		writeRESTError(w, http.StatusBadRequest, "invalid_payload", fmt.Sprintf("failed to read body: %v", err))
		return
	}

	var input ToolCallInput
	if err := json.Unmarshal(body, &input); err != nil {
		writeRESTError(w, http.StatusBadRequest, "invalid_json", fmt.Sprintf("invalid JSON payload: %v", err))
		return
	}

	if strings.TrimSpace(input.ToolName) == "" {
		writeRESTError(w, http.StatusBadRequest, "missing_tool_name", "tool_name is required")
		return
	}

	reqID := r.Header.Get("X-Request-Id")
	if reqID == "" {
		reqID = "req_" + uuid.NewString()
	}
	w.Header().Set("X-Gateway-Request-Id", reqID)

	meta := CallMetadata{
		ProtocolVersion: domain.MCPProtocolVersion2026,
		RequestID:       reqID,
		CallerMetadata:  make(map[string]string),
	}
	for k := range r.Header {
		meta.CallerMetadata[k] = r.Header.Get(k)
	}

	resp, err := b.hub.CallTool(r.Context(), idCtx, input, meta)
	if err != nil {
		var ambErr *AmbiguousToolError
		if errors.As(err, &ambErr) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error": map[string]any{
					"code":             "AmbiguousToolName",
					"message":          ambErr.Error(),
					"tool_name":        ambErr.ToolName,
					"matching_servers": ambErr.MatchingServers,
				},
			})
			return
		}

		var gwErr *domain.GatewayError
		if errors.As(err, &gwErr) {
			writeRESTError(w, gwErr.StatusCode, gwErr.Code, gwErr.Message)
			return
		}

		errLower := strings.ToLower(err.Error())
		if strings.Contains(errLower, "not found") {
			writeRESTError(w, http.StatusNotFound, "not_found", err.Error())
			return
		}
		if strings.Contains(errLower, "forbidden") || strings.Contains(errLower, "not authorized") {
			writeRESTError(w, http.StatusForbidden, "forbidden", err.Error())
			return
		}
		if strings.Contains(errLower, "guardrail") || strings.Contains(errLower, "pinning") {
			writeRESTError(w, http.StatusBadRequest, "guardrail_violation", err.Error())
			return
		}

		writeRESTError(w, http.StatusBadGateway, "upstream_error", err.Error())
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(resp)
}

func writeRESTError(w http.ResponseWriter, statusCode int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]any{
			"code":    code,
			"message": message,
		},
	})
}
