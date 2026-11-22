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
	"github.com/goroute-ai/ai-gateway-go/internal/mcp/spec"
	"github.com/goroute-ai/ai-gateway-go/internal/security/network"
	"github.com/goroute-ai/ai-gateway-go/internal/storage"
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
		RPMLimit        int               `json:"rpm_limit,omitempty"`
	}

	if err := decodeAdminJSON(w, r, &input); err != nil {
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
		if s.mcpHub != nil {
			input.ProtocolVersion = s.mcpHub.ActiveSpec()
		} else {
			input.ProtocolVersion = domain.MCPProtocolVersion2026
		}
	}
	if !spec.IsSupported(input.ProtocolVersion) {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "unsupported_protocol_version",
			Message:    fmt.Sprintf("unsupported protocol_version %q; supported versions are %s", input.ProtocolVersion, strings.Join(spec.SupportedVersions(), ", ")),
		})
		return
	}
	if input.TransportType == "" {
		if info, ok := spec.GetSpec(input.ProtocolVersion); ok && info.DefaultTransport != "" {
			input.TransportType = info.DefaultTransport
		} else {
			input.TransportType = domain.MCPTransportStreamableHTTP
		}
	}
	if !domain.IsSupportedMCPTransportType(input.TransportType) {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_transport_type",
			Message:    fmt.Sprintf("unsupported transport_type %q", input.TransportType),
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

	if input.RPMLimit < 0 {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_rpm_limit",
			Message:    "rpm_limit cannot be negative",
		})
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
		RPMLimit:        input.RPMLimit,
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

	if err := decodeAdminJSON(w, r, &input); err != nil {
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

	for _, toolID := range input.ToolIDs {
		tool, err := s.repo.GetMCPTool(r.Context(), toolID)
		if err != nil || tool == nil {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusNotFound,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "mcp_tool_not_found",
				Message:    fmt.Sprintf("MCP tool %q not found", toolID),
			})
			return
		}
		srv, err := s.repo.GetMCPServer(r.Context(), tool.ServerID)
		if err != nil || srv == nil || srv.OrgID != input.OrgID {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusForbidden,
				Type:       domain.ErrorTypePermission,
				Code:       "cross_tenant_mcp_tool",
				Message:    fmt.Sprintf("MCP tool %q does not belong to organization %q", toolID, input.OrgID),
			})
			return
		}
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

	if err := decodeAdminJSON(w, r, &input); err != nil {
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

	srv, err := s.repo.GetMCPServer(r.Context(), input.ServerID)
	if err != nil || srv == nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusNotFound,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "mcp_server_not_found",
			Message:    "MCP server not found",
		})
		return
	}
	if srv.OrgID != input.OrgID {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusForbidden,
			Type:       domain.ErrorTypePermission,
			Code:       "cross_tenant_mcp_server",
			Message:    "MCP server does not belong to target organization",
		})
		return
	}

	users, err := s.repo.ListUsers(r.Context(), input.OrgID)
	if err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusInternalServerError,
			Type:       domain.ErrorTypeServer,
			Code:       "storage_error",
			Message:    err.Error(),
		})
		return
	}
	foundUser := false
	for _, u := range users {
		if u != nil && u.ID == input.UserID && u.OrgID == input.OrgID {
			foundUser = true
			break
		}
	}
	if !foundUser {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusForbidden,
			Type:       domain.ErrorTypePermission,
			Code:       "cross_tenant_user",
			Message:    "User does not belong to target organization",
		})
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

// handleAdminGetMCPSpec serves `GET /admin/v1/mcp/spec` returning the active UI-selected MCP release
// and full capability descriptors for every generated official MCP release.
func (s *GatewayServer) handleAdminGetMCPSpec(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.authorizeAdmin(w, r, "", false); !ok {
		return
	}

	settings := domain.MCPRuntimeSettings{ActiveProtocolVersion: spec.DefaultVersion}
	if s.mcpHub != nil {
		settings = s.mcpHub.RuntimeSettings()
	}
	if settingsRepo, ok := s.repo.(storage.MCPRuntimeSettingsRepository); ok && settingsRepo != nil {
		if stored, err := settingsRepo.GetMCPRuntimeSettings(r.Context()); err == nil && stored != nil && !stored.UpdatedAt.IsZero() {
			settings = *stored
		}
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"active_protocol_version":  settings.ActiveProtocolVersion,
		"strict_schema_validation": settings.StrictSchemaValidation,
		"updated_by":               settings.UpdatedBy,
		"updated_at":               settings.UpdatedAt,
		"available_specs":          spec.SupportedSpecs(),
	})
}

// handleAdminUpdateMCPSpec serves `PUT /admin/v1/mcp/spec` switching the gateway-wide active MCP release from the Web UI.
func (s *GatewayServer) handleAdminUpdateMCPSpec(w http.ResponseWriter, r *http.Request) {
	op, ok := s.authorizeAdmin(w, r, "", true)
	if !ok {
		return
	}

	var input struct {
		ProtocolVersion        string `json:"protocol_version"`
		StrictSchemaValidation *bool  `json:"strict_schema_validation,omitempty"`
	}
	if err := decodeAdminJSON(w, r, &input); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_json",
			Message:    "Invalid request payload: " + err.Error(),
		})
		return
	}

	targetVersion := strings.TrimSpace(input.ProtocolVersion)
	if !spec.IsSupported(targetVersion) {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "unsupported_protocol_version",
			Message:    fmt.Sprintf("unsupported protocol_version %q; supported versions are %s", input.ProtocolVersion, strings.Join(spec.SupportedVersions(), ", ")),
		})
		return
	}

	strict := false
	if s.mcpHub != nil {
		strict = s.mcpHub.RuntimeSettings().StrictSchemaValidation
	}
	if input.StrictSchemaValidation != nil {
		strict = *input.StrictSchemaValidation
	}

	actor := "admin"
	if op != nil && op.ActorID != "" {
		actor = op.ActorID
	}
	updated := domain.MCPRuntimeSettings{
		ActiveProtocolVersion:  targetVersion,
		StrictSchemaValidation: strict,
		UpdatedBy:              actor,
		UpdatedAt:              time.Now().UTC(),
	}

	if settingsRepo, ok := s.repo.(storage.MCPRuntimeSettingsRepository); ok && settingsRepo != nil {
		if err := settingsRepo.UpdateMCPRuntimeSettings(r.Context(), &updated); err != nil {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusInternalServerError,
				Type:       domain.ErrorTypeServer,
				Code:       "storage_error",
				Message:    "Failed to persist MCP specification setting: " + err.Error(),
			})
			return
		}
	}

	if s.mcpHub != nil {
		s.mcpHub.SetRuntimeSettings(updated)
	}
	s.invalidateRoutingCaches(r.Context(), storage.InvalidationEvent{
		Type:       "mcp_spec",
		EntityType: "mcp_spec",
		EntityID:   updated.ActiveProtocolVersion,
	})

	_ = s.repo.RecordAuditLog(r.Context(), &domain.AuditLog{
		ActorID:    actor,
		Action:     "mcp.spec.updated",
		Resource:   "mcp_runtime_settings",
		ResourceID: "default",
		Details: map[string]any{
			"active_protocol_version":  updated.ActiveProtocolVersion,
			"strict_schema_validation": updated.StrictSchemaValidation,
		},
	})

	writeJSON(w, http.StatusOK, map[string]any{
		"status":                   "updated",
		"active_protocol_version":  updated.ActiveProtocolVersion,
		"strict_schema_validation": updated.StrictSchemaValidation,
		"updated_by":               updated.UpdatedBy,
		"updated_at":               updated.UpdatedAt,
		"available_specs":          spec.SupportedSpecs(),
	})
}

// handleAdminUpdateMCPServer serves `PUT /admin/v1/mcp/servers/{serverID}` allowing per-server spec/transport edits from the Web UI.
func (s *GatewayServer) handleAdminUpdateMCPServer(w http.ResponseWriter, r *http.Request) {
	serverID := strings.TrimSpace(chi.URLParam(r, "serverID"))
	if serverID == "" {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "missing_server_id",
			Message:    "serverID URL parameter is required",
		})
		return
	}

	existing, err := s.repo.GetMCPServer(r.Context(), serverID)
	if err != nil || existing == nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusNotFound,
			Type:       domain.ErrorTypeNotFound,
			Code:       "server_not_found",
			Message:    fmt.Sprintf("MCP server %q not found", serverID),
		})
		return
	}
	if _, ok := s.authorizeAdmin(w, r, existing.OrgID, true); !ok {
		return
	}

	var input struct {
		Name            *string           `json:"name,omitempty"`
		ProtocolVersion *string           `json:"protocol_version,omitempty"`
		TransportType   *string           `json:"transport_type,omitempty"`
		EndpointURL     *string           `json:"endpoint_url,omitempty"`
		AuthType        *string           `json:"auth_type,omitempty"`
		AuthSecret      *string           `json:"auth_secret,omitempty"`
		StaticHeaders   map[string]string `json:"static_headers,omitempty"`
		PinnedToolHash  *string           `json:"pinned_tool_hash,omitempty"`
		RPMLimit        *int              `json:"rpm_limit,omitempty"`
		IsActive        *bool             `json:"is_active,omitempty"`
	}
	if err := decodeAdminJSON(w, r, &input); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusBadRequest,
			Type:       domain.ErrorTypeInvalidRequest,
			Code:       "invalid_json",
			Message:    "Invalid request payload: " + err.Error(),
		})
		return
	}

	if input.ProtocolVersion != nil {
		pv := strings.TrimSpace(*input.ProtocolVersion)
		if !spec.IsSupported(pv) {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusBadRequest,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "unsupported_protocol_version",
				Message:    fmt.Sprintf("unsupported protocol_version %q", pv),
			})
			return
		}
		existing.ProtocolVersion = pv
	}
	if input.TransportType != nil {
		tt := strings.TrimSpace(*input.TransportType)
		if !domain.IsSupportedMCPTransportType(tt) {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusBadRequest,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "invalid_transport_type",
				Message:    fmt.Sprintf("unsupported transport_type %q", tt),
			})
			return
		}
		existing.TransportType = tt
	}
	if input.Name != nil && strings.TrimSpace(*input.Name) != "" {
		existing.Name = strings.TrimSpace(*input.Name)
	}
	if input.EndpointURL != nil && strings.TrimSpace(*input.EndpointURL) != "" {
		existing.EndpointURL = strings.TrimSpace(*input.EndpointURL)
	}
	if input.AuthType != nil {
		existing.AuthType = strings.TrimSpace(*input.AuthType)
	}
	if input.StaticHeaders != nil {
		existing.StaticHeaders = input.StaticHeaders
	}
	if input.PinnedToolHash != nil {
		existing.PinnedToolHash = strings.TrimSpace(*input.PinnedToolHash)
	}
	if input.RPMLimit != nil {
		if *input.RPMLimit < 0 {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusBadRequest,
				Type:       domain.ErrorTypeInvalidRequest,
				Code:       "invalid_rpm_limit",
				Message:    "rpm_limit cannot be negative",
			})
			return
		}
		existing.RPMLimit = *input.RPMLimit
	}
	if input.IsActive != nil {
		existing.IsActive = *input.IsActive
	}
	if input.AuthSecret != nil && *input.AuthSecret != "" {
		cipher, dek, encErr := s.vault.EncryptString(*input.AuthSecret)
		if encErr != nil {
			domain.WriteHTTPError(w, &domain.GatewayError{
				StatusCode: http.StatusInternalServerError,
				Type:       domain.ErrorTypeServer,
				Code:       "vault_encryption_error",
				Message:    "Failed to encrypt auth secret: " + encErr.Error(),
			})
			return
		}
		existing.EncryptedAuthSecret = cipher
		existing.EncryptedAuthDEK = dek
	}

	if err := s.repo.UpdateMCPServer(r.Context(), existing); err != nil {
		domain.WriteHTTPError(w, &domain.GatewayError{
			StatusCode: http.StatusInternalServerError,
			Type:       domain.ErrorTypeServer,
			Code:       "storage_error",
			Message:    "Failed to update MCP server: " + err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"status": "updated",
		"server": existing,
	})
}
