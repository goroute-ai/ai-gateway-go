package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/goroute-ai/ai-gateway-go/internal/domain"
	"github.com/goroute-ai/ai-gateway-go/internal/guardrails"
	"github.com/goroute-ai/ai-gateway-go/internal/mcp"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
)

// handleAdminCreateMCPServer registers a new upstream MCP server.
func (s *GatewayServer) handleAdminCreateMCPServer(w http.ResponseWriter, r *http.Request) {
	var input struct {
		OrgID           string            `json:"org_id"`
		Name            string            `json:"name"`
		Slug            string            `json:"slug"`
		ProtocolVersion string            `json:"protocol_version"` // "2026-07-28" or "2025-11-25"
		TransportType   string            `json:"transport_type"`   // "streamable_http"
		EndpointURL     string            `json:"endpoint_url"`
		AuthType        string            `json:"auth_type"` // "none", "static", "oauth2", "delegation", "vault_jwt"
		AuthSecret      string            `json:"auth_secret,omitempty"`
		StaticHeaders   map[string]string `json:"static_headers,omitempty"`
		OAuth2Endpoint  string            `json:"oauth2_endpoint,omitempty"`
		OAuth2ClientID  string            `json:"oauth2_client_id,omitempty"`
		OAuth2Scopes    []string          `json:"oauth2_scopes,omitempty"`
		PinnedToolHash  string            `json:"pinned_tool_hash,omitempty"`
	}

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_json",
			Message:    "Invalid request payload: " + err.Error(),
		})
		return
	}

	if input.Name == "" || input.Slug == "" || input.EndpointURL == "" {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "missing_required_fields",
			Message:    "name, slug, and endpoint_url are required",
		})
		return
	}

	if input.ProtocolVersion == "" {
		input.ProtocolVersion = domain.MCPProtocolVersion2026
	}
	if input.TransportType == "" {
		input.TransportType = domain.MCPTransportStreamableHTTP
	}
	if input.OrgID == "" {
		input.OrgID = resolveScopedOrgID(r, "")
	}
	if input.OrgID == "" {
		input.OrgID = s.cfg.Auth.DefaultOrgID
	}
	if _, ok := s.authorizeAdmin(w, r, input.OrgID, true); !ok {
		return
	}

	server := &domain.MCPServer{
		ID:              "mcp_srv_" + uuid.NewString(),
		OrgID:           input.OrgID,
		Name:            input.Name,
		Slug:            input.Slug,
		ProtocolVersion: input.ProtocolVersion,
		TransportType:   input.TransportType,
		EndpointURL:     input.EndpointURL,
		ConfigVersion:   1,
		AuthType:        input.AuthType,
		StaticHeaders:   input.StaticHeaders,
		OAuth2Endpoint:  input.OAuth2Endpoint,
		OAuth2ClientID:  input.OAuth2ClientID,
		OAuth2Scopes:    input.OAuth2Scopes,
		PinnedToolHash:  input.PinnedToolHash,
		IsActive:        true,
		CreatedAt:       time.Now().UTC(),
		UpdatedAt:       time.Now().UTC(),
	}

	// Encrypt auth secret if provided
	if input.AuthSecret != "" {
		cipher, dek, err := s.vault.EncryptString(input.AuthSecret)
		if err != nil {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusInternalServerError,
				Type:       domain.ErrorTypeServer,
				Code:       "vault_encryption_error",
				Message:    "Failed to encrypt auth secret: " + err.Error(),
			})
			return
		}
		server.EncryptedAuthSecret = cipher
		server.EncryptedAuthDEK = dek
	}

	if err := s.repo.CreateMCPServer(r.Context(), server); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusInternalServerError,
			Type:       domain.ErrorTypeServer,
			Code:       "storage_error",
			Message:    "Failed to store MCP server: " + err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"status": "created",
		"server": server,
	})
}

// handleAdminListMCPServers lists registered MCP servers for an organization.
func (s *GatewayServer) handleAdminListMCPServers(w http.ResponseWriter, r *http.Request) {
	orgID := resolveScopedOrgID(r, r.URL.Query().Get("org_id"))
	if orgID == "" {
		orgID = s.cfg.Auth.DefaultOrgID
	}
	if _, ok := s.authorizeAdmin(w, r, orgID, false); !ok {
		return
	}

	servers, err := s.repo.ListMCPServers(r.Context(), orgID)
	if err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusInternalServerError,
			Type:       domain.ErrorTypeServer,
			Code:       "storage_error",
			Message:    "Failed to list MCP servers: " + err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"servers": servers,
	})
}

// handleAdminSyncMCPServer queries the upstream MCP server for its tools/list,
// validates each tool against the anti-tool-poisoning scanner, computes canonical tool hashes,
// and saves the discovered tools.
func (s *GatewayServer) handleAdminSyncMCPServer(w http.ResponseWriter, r *http.Request) {
	serverID := chi.URLParam(r, "serverID")
	if serverID == "" {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "missing_server_id",
			Message:    "serverID URL parameter is required",
		})
		return
	}

	server, err := s.repo.GetMCPServer(r.Context(), serverID)
	if err != nil || server == nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusNotFound,
			Type:       domain.ErrorTypeNotFound,
			Code:       "server_not_found",
			Message:    fmt.Sprintf("MCP server %q not found", serverID),
		})
		return
	}
	if _, ok := s.authorizeAdmin(w, r, server.OrgID, true); !ok {
		return
	}

	// Build safe outbound HTTP client
	netPolicy, err := network.NewPolicy(s.cfg.Security.Network.OutboundSSRF)
	if err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusInternalServerError,
			Type:       domain.ErrorTypeServer,
			Code:       "network_policy_error",
			Message:    err.Error(),
		})
		return
	}
	// Form tools/list JSON-RPC request
	rpcReq := map[string]any{
		"jsonrpc": "2.0",
		"id":      "sync_" + uuid.NewString(),
		"method":  "tools/list",
		"params":  map[string]any{},
	}

	var jsonResp *mcp.JSONRPCResponse
	if s.mcpHub != nil && s.mcpHub.Dispatcher() != nil {
		var err error
		reqBytes, _ := json.Marshal(rpcReq)
		jsonResp, _, err = s.mcpHub.Dispatcher().Dispatch(r.Context(), server, nil, nil, reqBytes, nil)
		if err != nil {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusBadGateway,
				Type:       domain.ErrorTypeUpstream,
				Code:       "sync_network_error",
				Message:    fmt.Sprintf("Failed to reach upstream server: %v", err),
			})
			return
		}
	} else {
		httpClient := network.NewHTTPClient(netPolicy)
		httpClient.Timeout = 15 * time.Second
		reqBytes, _ := json.Marshal(rpcReq)

		httpReq, err := http.NewRequestWithContext(r.Context(), http.MethodPost, server.EndpointURL, bytes.NewReader(reqBytes))
		if err != nil {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusInternalServerError,
				Type:       domain.ErrorTypeServer,
				Code:       "request_creation_failed",
				Message:    err.Error(),
			})
			return
		}
		httpReq.Header.Set("Content-Type", "application/json")
		httpReq.Header.Set("Accept", "application/json")

		for k, v := range server.StaticHeaders {
			httpReq.Header.Set(k, v)
		}

		resp, err := httpClient.Do(httpReq)
		if err != nil {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusBadGateway,
				Type:       domain.ErrorTypeUpstream,
				Code:       "sync_network_error",
				Message:    fmt.Sprintf("Failed to reach upstream server: %v", err),
			})
			return
		}
		defer resp.Body.Close()

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusBadGateway,
				Type:       domain.ErrorTypeUpstream,
				Code:       "sync_upstream_rejected",
				Message:    fmt.Sprintf("Upstream returned HTTP %d: %s", resp.StatusCode, string(body)),
			})
			return
		}

		var parsedResp mcp.JSONRPCResponse
		if err := json.NewDecoder(resp.Body).Decode(&parsedResp); err != nil {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusBadGateway,
				Type:       domain.ErrorTypeUpstream,
				Code:       "sync_invalid_json",
				Message:    "Failed to parse upstream JSON-RPC response: " + err.Error(),
			})
			return
		}
		jsonResp = &parsedResp
	}

	if jsonResp == nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadGateway,
			Type:       domain.ErrorTypeUpstream,
			Code:       "sync_empty_response",
			Message:    "Empty response received from upstream server",
		})
		return
	}

	if jsonResp.Error != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadGateway,
			Type:       domain.ErrorTypeUpstream,
			Code:       "sync_upstream_error",
			Message:    jsonResp.Error.Message,
		})
		return
	}

	// Extract tools array
	resultMap, ok := jsonResp.Result.(map[string]any)
	if !ok {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadGateway,
			Type:       domain.ErrorTypeUpstream,
			Code:       "sync_missing_result",
			Message:    "Expected JSON-RPC result object with tools array",
		})
		return
	}

	rawTools, ok := resultMap["tools"].([]any)
	if !ok {
		if mapTools, isMapSlice := resultMap["tools"].([]map[string]any); isMapSlice {
			for _, mt := range mapTools {
				rawTools = append(rawTools, mt)
			}
		} else {
			rawTools = []any{}
		}
	}

	var discoveredTools []*domain.MCPTool
	for _, rawT := range rawTools {
		tMap, ok := rawT.(map[string]any)
		if !ok {
			continue
		}

		name, _ := tMap["name"].(string)
		desc, _ := tMap["description"].(string)
		schema, _ := tMap["inputSchema"].(map[string]any)

		tool := &domain.MCPTool{
			ID:          "mcp_tool_" + uuid.NewString(),
			ServerID:    server.ID,
			OrgID:       server.OrgID,
			Name:        name,
			Description: desc,
			InputSchema: schema,
			ToolDefHash: guardrails.ComputeToolDefinitionHash(name, desc, schema),
			IsActive:    true,
			CreatedAt:   time.Now().UTC(),
			UpdatedAt:   time.Now().UTC(),
		}

		// Security: Scan tool against Anti-Tool-Poisoning & Injection guardrails
		if s.guardrails != nil {
			if err := s.guardrails.ScanMCPToolDiscovery(tool); err != nil {
				domain.WriteHTTPError(w, &domain.GatewayError{
					StatusCode: http.StatusForbidden,
					Type:       domain.ErrorTypePermission,
					Code:       "tool_poisoning_blocked",
					Message:    fmt.Sprintf("Tool %q blocked by security scanner: %v", name, err),
				})
				return
			}

			// If server has a PinnedToolHash configured, verify integrity
			if server.PinnedToolHash != "" {
				if err := s.guardrails.VerifyToolPinning(tool, server.PinnedToolHash); err != nil {
					domain.WriteHTTPError(w, err)
					return
				}
			}
		}

		discoveredTools = append(discoveredTools, tool)
	}

	// Save tools to repository
	if err := s.repo.UpsertMCPTools(r.Context(), server.ID, server.OrgID, discoveredTools); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusInternalServerError,
			Type:       domain.ErrorTypeServer,
			Code:       "storage_error",
			Message:    "Failed to save discovered tools: " + err.Error(),
		})
		return
	}

	// Increment server config version to invalidate downstream caches
	server.ConfigVersion++
	server.UpdatedAt = time.Now().UTC()
	_ = s.repo.UpdateMCPServer(r.Context(), server)

	writeJSON(w, http.StatusOK, map[string]any{
		"status":         "synced",
		"server_id":      server.ID,
		"config_version": server.ConfigVersion,
		"tools_count":    len(discoveredTools),
		"tools":          discoveredTools,
	})
}

// handleAdminCreateMCPToolset creates a curated toolset.
func (s *GatewayServer) handleAdminCreateMCPToolset(w http.ResponseWriter, r *http.Request) {
	var input struct {
		OrgID   string   `json:"org_id"`
		Name    string   `json:"name"`
		Slug    string   `json:"slug"`
		ToolIDs []string `json:"tool_ids"`
	}

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_json",
			Message:    err.Error(),
		})
		return
	}

	if input.Name == "" || input.Slug == "" {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "missing_required_fields",
			Message:    "name and slug are required",
		})
		return
	}

	if input.OrgID == "" {
		input.OrgID = resolveScopedOrgID(r, "")
	}
	if input.OrgID == "" {
		input.OrgID = s.cfg.Auth.DefaultOrgID
	}
	if _, ok := s.authorizeAdmin(w, r, input.OrgID, true); !ok {
		return
	}

	ts := &domain.MCPToolset{
		ID:        "ts_" + uuid.NewString(),
		OrgID:     input.OrgID,
		Name:      input.Name,
		Slug:      input.Slug,
		ToolIDs:   input.ToolIDs,
		IsActive:  true,
		CreatedAt: time.Now().UTC(),
		UpdatedAt: time.Now().UTC(),
	}

	if err := s.repo.CreateMCPToolset(r.Context(), ts); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusInternalServerError,
			Type:       domain.ErrorTypeServer,
			Code:       "storage_error",
			Message:    "Failed to create toolset: " + err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusCreated, map[string]any{
		"status":  "created",
		"toolset": ts,
	})
}

// handleAdminListMCPToolsets lists toolsets for an organization.
func (s *GatewayServer) handleAdminListMCPToolsets(w http.ResponseWriter, r *http.Request) {
	orgID := resolveScopedOrgID(r, r.URL.Query().Get("org_id"))
	if orgID == "" {
		orgID = s.cfg.Auth.DefaultOrgID
	}
	if _, ok := s.authorizeAdmin(w, r, orgID, false); !ok {
		return
	}

	toolsets, err := s.repo.ListMCPToolsets(r.Context(), orgID)
	if err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusInternalServerError,
			Type:       domain.ErrorTypeServer,
			Code:       "storage_error",
			Message:    err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"toolsets": toolsets,
	})
}

// handleAdminSetMCPUserCredential stores a Vault-encrypted per-user BYOK credential.
func (s *GatewayServer) handleAdminSetMCPUserCredential(w http.ResponseWriter, r *http.Request) {
	var input struct {
		ServerID string `json:"server_id"`
		UserID   string `json:"user_id"`
		OrgID    string `json:"org_id"`
		Token    string `json:"token"`
	}

	if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_json",
			Message:    err.Error(),
		})
		return
	}

	if input.ServerID == "" || input.UserID == "" || input.Token == "" {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "missing_required_fields",
			Message:    "server_id, user_id, and token are required",
		})
		return
	}

	if input.OrgID == "" {
		input.OrgID = resolveScopedOrgID(r, "")
	}
	if input.OrgID == "" {
		input.OrgID = s.cfg.Auth.DefaultOrgID
	}
	if _, ok := s.authorizeAdmin(w, r, input.OrgID, true); !ok {
		return
	}

	cipher, dek, err := s.vault.EncryptString(strings.TrimSpace(input.Token))
	if err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusInternalServerError,
			Type:       domain.ErrorTypeServer,
			Code:       "vault_encryption_error",
			Message:    err.Error(),
		})
		return
	}

	cred := &domain.MCPUserCredential{
		ID:             "cred_" + uuid.NewString(),
		ServerID:       input.ServerID,
		UserID:         input.UserID,
		OrgID:          input.OrgID,
		EncryptedToken: cipher,
		EncryptedDEK:   dek,
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
	}

	if err := s.repo.SetMCPUserCredential(r.Context(), cred); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusInternalServerError,
			Type:       domain.ErrorTypeServer,
			Code:       "storage_error",
			Message:    err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status":        "saved",
		"credential_id": cred.ID,
	})
}

// handleAdminListMCPTools serves `GET /admin/v1/mcp/tools` for the Operator UI under Control Plane auth.
func (s *GatewayServer) handleAdminListMCPTools(w http.ResponseWriter, r *http.Request) {
	orgID := resolveScopedOrgID(r, r.URL.Query().Get("org_id"))
	if orgID == "" {
		orgID = s.cfg.Auth.DefaultOrgID
	}
	op, ok := s.authorizeAdmin(w, r, orgID, false)
	if !ok {
		return
	}

	adminIDCtx := &domain.IdentityContext{
		VirtualKeyID:         op.ActorID,
		OrgID:                orgID,
		Role:                 domain.Role(op.Role),
		KeyAllowedMCPServers: []string{"*"},
	}
	serverSlug := strings.TrimSpace(r.URL.Query().Get("server_slug"))
	tools, err := s.mcpHub.ListTools(r.Context(), adminIDCtx, serverSlug)
	if err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusInternalServerError,
			Type:       domain.ErrorTypeServer,
			Code:       "mcp_tools_error",
			Message:    err.Error(),
		})
		return
	}
	if tools == nil {
		tools = []domain.MCPTool{}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"tools": tools,
	})
}
