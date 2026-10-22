package mcp

import (
	"fmt"
	"strings"

	"github.com/goroute-ai/ai-gateway-go/internal/domain"
)

// SpendRecorder allows Hub to emit FinOps spend events for tool invocations.
type SpendRecorder interface {
	Enqueue(ev domain.SpendEvent)
}

// ToolContent represents a single content item returned by an MCP tool.
type ToolContent struct {
	Type     string         `json:"type"` // "text", "image", "resource"
	Text     string         `json:"text,omitempty"`
	Data     string         `json:"data,omitempty"`
	MimeType string         `json:"mimeType,omitempty"`
	Resource map[string]any `json:"resource,omitempty"`
}

// ToolCallInput specifies a tool call request without transport headers.
type ToolCallInput struct {
	ServerSlug string         `json:"server_slug,omitempty"` // required unless tool name is globally unique across authorized servers
	ToolName   string         `json:"tool_name"`
	Arguments  map[string]any `json:"arguments"`
}

// CallMetadata contains normalized request metadata decoupled from HTTP transport.
type CallMetadata struct {
	ProtocolVersion string            `json:"protocol_version"`
	RequestID       string            `json:"request_id"`
	CallerMetadata  map[string]string `json:"caller_metadata,omitempty"` // normalized transport metadata
}

// CallToolResponse represents the unified application-level result of a tool execution.
type CallToolResponse struct {
	Content []ToolContent  `json:"content"`
	IsError bool           `json:"is_error,omitempty"`
	Meta    map[string]any `json:"_meta,omitempty"`
}

// AmbiguousToolError is returned when a tool call does not specify server_slug
// and multiple authorized active servers expose a tool with the same name.
type AmbiguousToolError struct {
	ToolName        string   `json:"tool_name"`
	MatchingServers []string `json:"matching_servers"`
}

func (e *AmbiguousToolError) Error() string {
	return fmt.Sprintf("ambiguous tool name %q: provided by multiple servers (%s); please specify server_slug", e.ToolName, strings.Join(e.MatchingServers, ", "))
}
