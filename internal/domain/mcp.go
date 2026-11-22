package domain

import (
	"time"
)

// MCP protocol versions, transport drivers, and authentication modes.
const (
	MCPProtocolVersion20241105 = "2024-11-05"
	MCPProtocolVersion20250326 = "2025-03-26"
	MCPProtocolVersion20250618 = "2025-06-18"
	MCPProtocolVersion20251125 = "2025-11-25"
	MCPProtocolVersion20260728 = "2026-07-28"

	// Legacy short aliases kept for internal callers.
	MCPProtocolVersion2026 = MCPProtocolVersion20260728
	MCPProtocolVersion2025 = MCPProtocolVersion20251125

	MCPTransportStreamableHTTP = "streamable_http"
	MCPTransportHTTPSSE2024    = "http_sse_2024"
	MCPTransportStdio          = "stdio"
	MCPTransportOpenAPI        = "openapi"

	MCPAuthNone       = "none"
	MCPAuthStatic     = "static"
	MCPAuthOAuth2     = "oauth2"
	MCPAuthDelegation = "delegation"
	MCPAuthVaultJWT   = "vault_jwt"
)

// MCPRuntimeSettings holds the gateway-wide active MCP API specification configured via Web UI/Control Plane.
type MCPRuntimeSettings struct {
	ActiveProtocolVersion  string    `json:"active_protocol_version"`
	StrictSchemaValidation bool      `json:"strict_schema_validation"`
	UpdatedBy              string    `json:"updated_by,omitempty"`
	UpdatedAt              time.Time `json:"updated_at"`
}

// IsSupportedMCPTransportType reports whether transportType is a valid MCP upstream transport identifier.
func IsSupportedMCPTransportType(transportType string) bool {
	switch transportType {
	case MCPTransportStreamableHTTP, MCPTransportHTTPSSE2024, MCPTransportStdio, MCPTransportOpenAPI:
		return true
	default:
		return false
	}
}

// MCPServer defines an upstream Model Context Protocol server definition and connection parameters.
type MCPServer struct {
	ID                  string            `json:"id"`
	OrgID               string            `json:"org_id"`
	Name                string            `json:"name"`
	Slug                string            `json:"slug"`
	ProtocolVersion     string            `json:"protocol_version"` // "2026-07-28" (stateless primary) or "2025-11-25" (compat)
	TransportType       string            `json:"transport_type"`   // "streamable_http"
	EndpointURL         string            `json:"endpoint_url"`
	ConfigVersion       int64             `json:"config_version"`
	AuthType            string            `json:"auth_type"` // "none", "static", "oauth2", "delegation", "vault_jwt"
	EncryptedAuthSecret string            `json:"-"`         // AES-256-GCM Vault encrypted
	EncryptedAuthDEK    string            `json:"-"`         // AES-256-GCM Vault encrypted
	StaticHeaders       map[string]string `json:"static_headers,omitempty"`
	OAuth2Endpoint      string            `json:"oauth2_endpoint,omitempty"`
	OAuth2ClientID      string            `json:"oauth2_client_id,omitempty"`
	OAuth2Scopes        []string          `json:"oauth2_scopes,omitempty"`
	PinnedToolHash      string            `json:"pinned_tool_hash,omitempty"` // Expected hash for tool integrity check
	RPMLimit            int               `json:"rpm_limit,omitempty"`        // 0 = unlimited
	IsActive            bool              `json:"is_active"`
	CreatedAt           time.Time         `json:"created_at"`
	UpdatedAt           time.Time         `json:"updated_at"`
}

// MCPTool defines a registered tool exposed by an MCP Server.
type MCPTool struct {
	ID                string         `json:"id"`
	ServerID          string         `json:"server_id"`
	OrgID             string         `json:"org_id"`
	Name              string         `json:"name"`
	Description       string         `json:"description,omitempty"`
	InputSchema       map[string]any `json:"input_schema,omitempty"`
	ToolDefHash       string         `json:"tool_def_hash"` // SHA-256 hash of canonical tool schema
	CostPerCallMicros int64          `json:"cost_per_call_micros"`
	IsActive          bool           `json:"is_active"`
	CreatedAt         time.Time      `json:"created_at"`
	UpdatedAt         time.Time      `json:"updated_at"`
}

// MCPToolset represents a curated group of tools spanning multiple MCP servers.
type MCPToolset struct {
	ID        string    `json:"id"`
	OrgID     string    `json:"org_id"`
	Name      string    `json:"name"`
	Slug      string    `json:"slug"`
	ToolIDs   []string  `json:"tool_ids"`
	IsActive  bool      `json:"is_active"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// MCPUserCredential stores per-user BYOK credentials for an MCP server.
type MCPUserCredential struct {
	ID             string    `json:"id"`
	ServerID       string    `json:"server_id"`
	UserID         string    `json:"user_id"`
	OrgID          string    `json:"org_id"`
	EncryptedToken string    `json:"-"` // Vault encrypted
	EncryptedDEK   string    `json:"-"` // Vault encrypted
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
}
