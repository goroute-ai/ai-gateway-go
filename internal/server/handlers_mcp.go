package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/goroute-ai/ai-gateway-go/internal/auth"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/mcp"
)

// handleMCPVirtualHub serves `POST /mcp` — Virtual Hub with tools/list aggregation across authorized servers.
func (s *GatewayServer) handleMCPVirtualHub(w http.ResponseWriter, r *http.Request) {
	s.handleMCPDispatch(w, r, func(idCtx *domain.IdentityContext, body []byte) (*mcp.JSONRPCResponse, http.Header, error) {
		return s.mcpHub.DispatchVirtualHub(r.Context(), idCtx, body, r.Header)
	})
}

// handleMCPSubscriptionsListen serves `GET /mcp/subscriptions/listen` — Client SSE multiplexed notifications.
func (s *GatewayServer) handleMCPSubscriptionsListen(w http.ResponseWriter, r *http.Request) {
	idCtx := auth.IdentityFromContext(r.Context())
	if idCtx == nil {
		writeJSONRPC(w, http.StatusOK, &mcp.JSONRPCResponse{
			JSONRPC: "2.0",
			Error: &mcp.JSONRPCError{
				Code:    mcp.CodeInvalidRequest,
				Message: "Unauthenticated: missing identity context",
			},
		}, nil)
		return
	}

	if s.mcpHub != nil && s.mcpHub.Subscriptions() != nil {
		s.mcpHub.Subscriptions().ServeSSEStream(w, r, idCtx)
		return
	}

	http.Error(w, "MCP subscriptions disabled", http.StatusServiceUnavailable)
}

// handleMCPScopedServer serves `POST /mcp/{serverSlug}` — Direct routing to a specific registered MCP server.
func (s *GatewayServer) handleMCPScopedServer(w http.ResponseWriter, r *http.Request) {
	serverSlug := chi.URLParam(r, "serverSlug")
	if serverSlug == "" {
		writeJSONRPC(w, http.StatusOK, &mcp.JSONRPCResponse{
			JSONRPC: "2.0",
			Error: &mcp.JSONRPCError{
				Code:    mcp.CodeInvalidRequest,
				Message: "missing server slug in URL path",
			},
		}, nil)
		return
	}

	s.handleMCPDispatch(w, r, func(idCtx *domain.IdentityContext, body []byte) (*mcp.JSONRPCResponse, http.Header, error) {
		return s.mcpHub.DispatchScopedServer(r.Context(), idCtx, serverSlug, body, r.Header)
	})
}

// handleMCPToolset serves `POST /mcp/toolsets/{toolsetSlug}` — Curated subset of tools aggregated into a single route.
func (s *GatewayServer) handleMCPToolset(w http.ResponseWriter, r *http.Request) {
	toolsetSlug := chi.URLParam(r, "toolsetSlug")
	if toolsetSlug == "" {
		writeJSONRPC(w, http.StatusOK, &mcp.JSONRPCResponse{
			JSONRPC: "2.0",
			Error: &mcp.JSONRPCError{
				Code:    mcp.CodeInvalidRequest,
				Message: "missing toolset slug in URL path",
			},
		}, nil)
		return
	}

	s.handleMCPDispatch(w, r, func(idCtx *domain.IdentityContext, body []byte) (*mcp.JSONRPCResponse, http.Header, error) {
		return s.mcpHub.DispatchToolset(r.Context(), idCtx, toolsetSlug, body, r.Header)
	})
}

// handleMCPDispatch handles common MCP request validation, reading body, executing dispatch, and rendering JSON-RPC.
func (s *GatewayServer) handleMCPDispatch(
	w http.ResponseWriter,
	r *http.Request,
	dispatchFn func(idCtx *domain.IdentityContext, body []byte) (*mcp.JSONRPCResponse, http.Header, error),
) {
	reqID := r.Header.Get("X-Request-Id")
	if reqID == "" {
		reqID = "req_" + uuid.NewString()
	}
	w.Header().Set("X-Gateway-Request-Id", reqID)

	// Validate HTTP transport layer constraints
	if status, err := mcp.ValidateHTTPRequest(r, nil); err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": map[string]any{
				"code":    status,
				"message": err.Error(),
			},
		})
		return
	}

	idCtx := auth.IdentityFromContext(r.Context())
	if idCtx == nil {
		writeJSONRPC(w, http.StatusOK, &mcp.JSONRPCResponse{
			JSONRPC: "2.0",
			Error: &mcp.JSONRPCError{
				Code:    mcp.CodeInvalidRequest,
				Message: "Unauthenticated: missing virtual key identity context",
			},
		}, nil)
		return
	}

	maxPayload := s.cfg.MCP.MaxPayloadBytes
	if maxPayload <= 0 {
		maxPayload = 10 * 1024 * 1024 // 10MB default
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxPayload)
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": map[string]any{
				"code":    http.StatusRequestEntityTooLarge,
				"message": fmt.Sprintf("payload exceeds max limit of %d bytes: %v", maxPayload, err),
			},
		})
		return
	}

	rpcResp, respHeaders, err := dispatchFn(idCtx, bodyBytes)
	if err != nil {
		writeJSONRPC(w, http.StatusOK, &mcp.JSONRPCResponse{
			JSONRPC: "2.0",
			Error: &mcp.JSONRPCError{
				Code:    mcp.CodeInternalError,
				Message: fmt.Sprintf("internal gateway error: %v", err),
			},
		}, nil)
		return
	}

	writeJSONRPC(w, http.StatusOK, rpcResp, respHeaders)
}

func writeJSONRPC(w http.ResponseWriter, status int, resp *mcp.JSONRPCResponse, extraHeaders http.Header) {
	if extraHeaders != nil {
		for k, v := range extraHeaders {
			// Don't overwrite content-type or server headers
			if stringsEqualFold(k, "Content-Type") || stringsEqualFold(k, "Content-Length") {
				continue
			}
			for _, val := range v {
				w.Header().Add(k, val)
			}
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(resp)
}

func stringsEqualFold(a, b string) bool {
	return len(a) == len(b) && (a == b || (len(a) > 0 && len(b) > 0 && (a[0]|0x20) == (b[0]|0x20)))
}

// handleMCPRegistryFeed serves `GET /v1/goroute/mcp/registry` — Enterprise catalog feed with progressive handles.
func (s *GatewayServer) handleMCPRegistryFeed(w http.ResponseWriter, r *http.Request) {
	idCtx := auth.IdentityFromContext(r.Context())
	if s.mcpHub == nil || s.mcpHub.ProgressiveDiscovery() == nil {
		writeJSON(w, http.StatusOK, map[string]any{"servers": []any{}})
		return
	}

	feed, err := s.mcpHub.ProgressiveDiscovery().BuildRegistryFeed(r.Context(), idCtx)
	if err != nil {
		domain.WriteHTTPError(w, err)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"servers": feed,
	})
}
